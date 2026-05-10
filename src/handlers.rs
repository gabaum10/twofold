use std::sync::Arc;

use askama::Template;
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    Json,
};
use comrak::{markdown_to_html, Options};
use serde::{Deserialize, Serialize};

use crate::{
    config::ServeConfig,
    db::{Db, DocumentRecord},
    parser::{extract_title, parse_document},
};

/// URL-safe slug alphabet per spec: alphanumeric + hyphen only (no underscore,
/// which is in the default nanoid alphabet but violates the spec's literal
/// "URL-safe (alphanumeric + hyphen)").
const SLUG_ALPHABET: [char; 63] = [
    '0','1','2','3','4','5','6','7','8','9',
    'a','b','c','d','e','f','g','h','i','j','k','l','m',
    'n','o','p','q','r','s','t','u','v','w','x','y','z',
    'A','B','C','D','E','F','G','H','I','J','K','L','M',
    'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
    '-',
];

/// Shared application state injected into all handlers via axum State extractor.
///
/// Both fields are Arc-wrapped: Db has its own internal Arc<Mutex<Connection>>;
/// ServeConfig is cloned cheaply (just the Arc pointer).
#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub config: Arc<ServeConfig>,
}

/// Askama template for the human-facing document view.
///
/// `content` must be pre-rendered HTML (not raw markdown).
/// `|safe` filter in the template marks it as trusted HTML — caller is responsible.
#[derive(Template)]
#[template(path = "document.html")]
struct DocumentTemplate<'a> {
    title: &'a str,
    content: &'a str,
}

/// JSON response body for a successful POST /api/v1/documents.
#[derive(Serialize)]
pub struct CreateResponse {
    pub url: String,
    pub slug: String,
    pub api_url: String,
    pub title: String,
    pub created_at: String,
}

/// Query parameters for GET /:slug
#[derive(Deserialize)]
pub struct SlugQuery {
    pub raw: Option<String>,
}

// ---------------------------------------------------------------------------
// POST /api/v1/documents
// ---------------------------------------------------------------------------

/// Handle document creation.
///
/// Auth: validates Bearer token via constant-time comparison (subtle crate).
///
/// Body: raw bytes (Content-Type: text/markdown). Body size is enforced upstream
/// by RequestBodyLimitLayer before this handler runs.
///
/// Returns 201 with CreateResponse JSON on success.
/// Returns 400 for empty body.
/// Returns 401 for missing/invalid auth.
pub async fn post_document(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // --- Auth ---
    let provided = match extract_bearer(&headers) {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, "Missing Authorization header").into_response(),
    };
    if !constant_time_eq(provided.as_bytes(), state.config.token.as_bytes()) {
        return (StatusCode::UNAUTHORIZED, "Invalid bearer token").into_response();
    }

    // --- Body validation ---
    if body.is_empty() {
        return (StatusCode::BAD_REQUEST, "Request body must not be empty").into_response();
    }

    let raw_content = match std::str::from_utf8(&body) {
        Ok(s) => s.to_string(),
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "Request body must be valid UTF-8").into_response()
        }
    };

    // --- Build document record ---
    let slug = nanoid::nanoid!(21, &SLUG_ALPHABET);
    let title = extract_title(&raw_content, &slug);
    let now = chrono_now();

    let doc = DocumentRecord {
        id: slug.clone(),
        slug: slug.clone(),
        title: title.clone(),
        raw_content,
        created_at: now.clone(),
        updated_at: now.clone(),
    };

    // --- Persist (with slug-collision retry-once) ---
    let mut final_slug = slug;
    let mut final_doc = doc;
    match state.db.insert_document(&final_doc) {
        Ok(()) => {}
        Err(e) if is_unique_violation(&e) => {
            // Extremely rare with 21-char nanoid (~1 in 10^30) — retry once.
            let new_slug = nanoid::nanoid!(21, &SLUG_ALPHABET);
            let new_title = if final_doc.title == final_slug {
                new_slug.clone() // title was the slug-fallback — track new slug
            } else {
                final_doc.title.clone()
            };
            final_doc = DocumentRecord {
                id: new_slug.clone(),
                slug: new_slug.clone(),
                title: new_title,
                raw_content: final_doc.raw_content,
                created_at: final_doc.created_at,
                updated_at: final_doc.updated_at,
            };
            final_slug = new_slug;
            if let Err(e2) = state.db.insert_document(&final_doc) {
                tracing::error!(error = %e2, "Slug collision retry failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to allocate unique slug").into_response();
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to insert document");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
        }
    }

    // --- Response ---
    let base = state.config.base_url.trim_end_matches('/');
    let response = CreateResponse {
        url: format!("{base}/{final_slug}"),
        slug: final_slug.clone(),
        api_url: format!("{base}/api/v1/documents/{final_slug}"),
        title: final_doc.title,
        created_at: final_doc.created_at,
    };

    (StatusCode::CREATED, Json(response)).into_response()
}

// ---------------------------------------------------------------------------
// GET /:slug  (human view or raw depending on ?raw=1)
// ---------------------------------------------------------------------------

/// Handle human view and raw-shortcut view.
///
/// Without `?raw=1`: renders the human corpus as HTML via Askama template.
/// With `?raw=1`: returns the full raw source (identical to agent API endpoint).
pub async fn get_human(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Query(params): Query<SlugQuery>,
) -> Response {
    let doc = match state.db.get_by_slug(&slug) {
        Ok(Some(d)) => d,
        Ok(None) => return (StatusCode::NOT_FOUND, "Document not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, slug = %slug, "DB error fetching document");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
        }
    };

    // ?raw=1 → return full source, same as agent API
    if params.raw.as_deref() == Some("1") {
        return markdown_response(&doc.raw_content);
    }

    // Human view: parse, render, template
    let parse_result = parse_document(&doc.raw_content, &slug);
    let rendered_html = render_markdown(&parse_result.human);

    let template = DocumentTemplate {
        title: &doc.title,
        content: &rendered_html,
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Template render error");
            (StatusCode::INTERNAL_SERVER_ERROR, "Template error").into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// GET /api/v1/documents/:slug  (agent view — full raw markdown)
// ---------------------------------------------------------------------------

/// Return the full raw source markdown.
///
/// Content-Type: text/markdown; charset=utf-8
/// Body: byte-for-byte identical to what was POSTed.
pub async fn get_agent(State(state): State<AppState>, Path(slug): Path<String>) -> Response {
    let doc = match state.db.get_by_slug(&slug) {
        Ok(Some(d)) => d,
        Ok(None) => return (StatusCode::NOT_FOUND, "Document not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, slug = %slug, "DB error fetching document");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
        }
    };

    markdown_response(&doc.raw_content)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Extract the Bearer token from the Authorization header.
///
/// Returns None if the header is absent or malformed.
fn extract_bearer(headers: &HeaderMap) -> Option<&str> {
    let auth = headers.get("authorization")?.to_str().ok()?;
    auth.strip_prefix("Bearer ")
}

/// Build a `text/markdown; charset=utf-8` response from a string body.
fn markdown_response(content: &str) -> Response {
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/markdown; charset=utf-8",
        )],
        content.to_string(),
    )
        .into_response()
}

/// Render markdown to HTML using comrak with GFM extensions enabled.
///
/// Structural decision: comrak Options created per call. Cost is stack allocation
/// of a small struct — accepted because optimization would add complexity for no
/// measurable gain at this scale.
fn render_markdown(source: &str) -> String {
    let mut options = Options::default();
    // GFM extensions: tables, strikethrough, autolinks, task lists
    options.extension.table = true;
    options.extension.strikethrough = true;
    options.extension.autolink = true;
    options.extension.tasklist = true;
    // Raw HTML passthrough enabled. XSS mitigated by:
    //   (1) Bearer token auth limits publishers to trusted operators.
    //   (2) CSP header (Content-Security-Policy: script-src 'none') blocks
    //       script execution in the human view.
    // If multi-user tokens are added in a future version, re-evaluate this
    // setting — any authenticated publisher would then be able to inject
    // arbitrary HTML visible to other users.
    options.render.unsafe_ = true;
    markdown_to_html(source, &options)
}

/// Return current UTC time as ISO 8601 string.
///
/// Uses std::time::SystemTime to avoid a chrono/time dependency.
fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Format as ISO 8601 UTC: YYYY-MM-DDTHH:MM:SSZ
    // Manual formatting avoids pulling in chrono or time crate.
    let s = secs;
    let sec = s % 60;
    let min = (s / 60) % 60;
    let hour = (s / 3600) % 24;
    let days = s / 86400;

    // Days since epoch to calendar date (Gregorian proleptic)
    let (year, month, day) = days_to_ymd(days);

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Convert days-since-Unix-epoch to (year, month, day).
///
/// Algorithm: Julian Day Number arithmetic. No unsafe. No external crates.
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from https://www.researchgate.net/publication/316558298
    // Richards (2013) civil calendar algorithm — public domain
    let jdn = days + 2440588; // Unix epoch = JDN 2440588
    let f = jdn + 1401 + (((4 * jdn + 274277) / 146097) * 3) / 4 - 38;
    let e = 4 * f + 3;
    let g = (e % 1461) / 4;
    let h = 5 * g + 2;
    let day = (h % 153) / 5 + 1;
    let month = (h / 153 + 2) % 12 + 1;
    let year = e / 1461 - 4716 + (14 - month) / 12;
    (year, month, day)
}

/// Constant-time byte comparison against the configured token.
///
/// Length mismatch returns false without ct_eq (one bit leak — token length
/// is not secret). Equal-length pairs are compared via `subtle::ConstantTimeEq`,
/// which folds across all bytes regardless of where the first mismatch occurs.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Check whether a rusqlite error is a UNIQUE constraint violation.
///
/// Used for slug collision detection in post_document. Inspects the raw
/// SQLite error code without requiring a custom DbError enum.
fn is_unique_violation(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(err, _) if err.code == rusqlite::ErrorCode::ConstraintViolation
    )
}

#[cfg(test)]
mod tests {
    use super::days_to_ymd;

    #[test]
    fn days_to_ymd_epoch() {
        // Day 0 = 1970-01-01 (Unix epoch)
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
    }

    #[test]
    fn days_to_ymd_day_zero_is_epoch() {
        // Explicit alias: day 0 is the epoch, same as above.
        // Kept separate so the failure message is distinct.
        let (y, m, d) = days_to_ymd(0);
        assert_eq!((y, m, d), (1970, 1, 1), "day 0 must be 1970-01-01");
    }

    #[test]
    fn days_to_ymd_known_recent_date() {
        // 2024-03-15 = 19797 days since epoch
        // Verified: (2024 - 1970) * 365 + leap days = 19797
        assert_eq!(days_to_ymd(19797), (2024, 3, 15));
    }

    #[test]
    fn days_to_ymd_leap_year_feb29() {
        // 2024 is a leap year. Feb 29, 2024 = day 19782.
        // 2024-01-01 = 19723 days since epoch; Jan has 31 days, Feb 1 = 19754, Feb 29 = 19782.
        assert_eq!(days_to_ymd(19782), (2024, 2, 29));
    }
}
