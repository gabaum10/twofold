use std::sync::Arc;

use askama::Template;
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    Form, Json,
};
use comrak::{markdown_to_html, Options};
use serde::{Deserialize, Serialize};

use crate::{
    config::ServeConfig,
    db::{Db, DocumentRecord},
    highlight,
    parser::{extract_frontmatter, extract_title, parse_document, parse_expiry, validate_slug},
    webhook,
};

/// URL-safe slug alphabet: alphanumeric + hyphen.
const SLUG_ALPHABET: [char; 63] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    '-',
];

// ── Application Error ────────────────────────────────────────────────────────

/// Unified error type with IntoResponse impl.
/// Replaces inline error tuples throughout handlers.
#[derive(Debug)]
pub enum AppError {
    Unauthorized,
    BadRequest(String),
    NotFound,
    Conflict(String),
    Gone,
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()),
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            AppError::NotFound => (StatusCode::NOT_FOUND, "Not found".to_string()),
            AppError::Conflict(m) => (StatusCode::CONFLICT, m),
            AppError::Gone => (StatusCode::GONE, "Document has expired".to_string()),
            AppError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
        };
        (status, Json(serde_json::json!({ "error": msg }))).into_response()
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(e: rusqlite::Error) -> Self {
        tracing::error!(error = %e, "Database error");
        AppError::Internal("Database error".to_string())
    }
}

// ── State ────────────────────────────────────────────────────────────────────

/// Shared application state injected into all handlers via axum State extractor.
#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub config: Arc<ServeConfig>,
}

// ── Templates ────────────────────────────────────────────────────────────────

/// Askama template for the human-facing document view (clean theme).
#[derive(Template)]
#[template(path = "document.html")]
struct CleanTemplate<'a> {
    title: &'a str,
    content: &'a str,
    slug: &'a str,
    /// When true, toolbar shows "Summary view" instead of "Full detail".
    full_view: bool,
}

/// Dark theme template.
#[derive(Template)]
#[template(path = "dark.html")]
struct DarkTemplate<'a> {
    title: &'a str,
    content: &'a str,
    slug: &'a str,
}

/// Paper theme template.
#[derive(Template)]
#[template(path = "paper.html")]
struct PaperTemplate<'a> {
    title: &'a str,
    content: &'a str,
    slug: &'a str,
}

/// Minimal theme template.
#[derive(Template)]
#[template(path = "minimal.html")]
struct MinimalTemplate<'a> {
    title: &'a str,
    content: &'a str,
    slug: &'a str,
}

/// Hearth theme template.
#[derive(Template)]
#[template(path = "hearth.html")]
struct HearthTemplate<'a> {
    title: &'a str,
    content: &'a str,
    slug: &'a str,
    full_view: bool,
}

/// Password prompt template.
#[derive(Template)]
#[template(path = "password.html")]
struct PasswordTemplate<'a> {
    slug: &'a str,
    error: Option<&'a str>,
}

// ── Response Types ───────────────────────────────────────────────────────────

/// JSON response body for a successful POST/PUT.
#[derive(Serialize)]
pub struct CreateResponse {
    pub url: String,
    pub slug: String,
    pub api_url: String,
    pub title: String,
    pub description: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
}

/// Query parameters for GET /:slug
#[derive(Deserialize)]
pub struct SlugQuery {
    pub raw: Option<String>,
}

/// Form data for password unlock
#[derive(Deserialize)]
pub struct UnlockForm {
    pub password: String,
}

/// Query parameters for GET /api/v1/documents (list)
#[derive(Deserialize)]
pub struct ListQuery {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

/// JSON response body for the list endpoint.
#[derive(Serialize)]
pub struct ListResponse {
    pub documents: Vec<crate::db::DocumentSummary>,
    pub total: u64,
    pub limit: u32,
    pub offset: u32,
}

// ── POST /api/v1/documents ───────────────────────────────────────────────────

/// Handle document creation.
///
/// Auth: validates Bearer token via constant-time comparison FIRST (before body parsing).
/// Body: raw bytes (Content-Type: text/markdown).
///
/// v0.2: parses frontmatter for title, slug, theme, expiry, password, description.
pub async fn post_document(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    // Auth FIRST — 401 before 400/413
    check_auth(&state, &headers).await?;

    // Body validation
    if body.is_empty() {
        return Err(AppError::BadRequest("Request body must not be empty".to_string()));
    }

    let raw_content = std::str::from_utf8(&body)
        .map_err(|_| AppError::BadRequest("Request body must be valid UTF-8".to_string()))?
        .to_string();

    // Parse frontmatter
    let fm_result = extract_frontmatter(&raw_content)
        .map_err(|e| AppError::BadRequest(e))?;

    let meta = fm_result.meta.unwrap_or_default();
    let body_text = &fm_result.body;

    // Determine slug
    let slug = if let Some(ref custom_slug) = meta.slug {
        validate_slug(custom_slug)
            .map_err(|e| AppError::BadRequest(e))?;
        custom_slug.clone()
    } else {
        nanoid::nanoid!(10, &SLUG_ALPHABET)
    };

    // Determine title: frontmatter > H1 > slug
    let title = meta.title.unwrap_or_else(|| extract_title(body_text, &slug));

    // Determine theme
    let theme = meta.theme.unwrap_or_else(|| state.config.default_theme.clone());

    // Parse expiry
    let now = chrono_now();
    let expires_at = match meta.expiry.as_deref() {
        Some(exp) => {
            let seconds = parse_expiry(exp)
                .map_err(|e| AppError::BadRequest(e))?;
            Some(add_seconds_to_now(&now, seconds))
        }
        None => None,
    };

    // Hash password if provided
    let password_hash = match meta.password.as_deref() {
        Some(pw) if !pw.is_empty() => Some(hash_password(pw)?),
        _ => None,
    };

    let doc = DocumentRecord {
        id: slug.clone(),
        slug: slug.clone(),
        title: title.clone(),
        raw_content,
        theme,
        password: password_hash,
        description: meta.description.clone(),
        created_at: now.clone(),
        expires_at: expires_at.clone(),
        updated_at: now.clone(),
    };

    // Insert (handle slug collision)
    match state.db.insert_document(&doc) {
        Ok(()) => {}
        Err(e) if is_unique_violation(&e) => {
            // Custom slug collision -> 409 Conflict
            if meta.slug.is_some() {
                return Err(AppError::Conflict(
                    format!("Slug '{}' is already in use", slug),
                ));
            }
            // Random slug collision (extremely rare) -> retry once
            let new_slug = nanoid::nanoid!(10, &SLUG_ALPHABET);
            let retry_doc = DocumentRecord {
                id: new_slug.clone(),
                slug: new_slug.clone(),
                ..doc
            };
            state.db.insert_document(&retry_doc)
                .map_err(|e2| {
                    tracing::error!(error = %e2, "Slug collision retry failed");
                    AppError::Internal("Failed to allocate unique slug".to_string())
                })?;
            let base = state.config.base_url.trim_end_matches('/');
            return Ok((StatusCode::CREATED, Json(CreateResponse {
                url: format!("{base}/{new_slug}"),
                slug: new_slug.clone(),
                api_url: format!("{base}/api/v1/documents/{new_slug}"),
                title: retry_doc.title,
                description: retry_doc.description,
                created_at: retry_doc.created_at,
                expires_at: retry_doc.expires_at,
            })).into_response());
        }
        Err(e) => return Err(AppError::from(e)),
    }

    // Response
    let base = state.config.base_url.trim_end_matches('/');
    let response = CreateResponse {
        url: format!("{base}/{slug}"),
        slug: slug.clone(),
        api_url: format!("{base}/api/v1/documents/{slug}"),
        title: doc.title.clone(),
        description: doc.description.clone(),
        created_at: doc.created_at.clone(),
        expires_at: doc.expires_at.clone(),
    };

    // Dispatch webhook fire-and-forget AFTER building response.
    // Webhook failure never affects the 201 response.
    if let Some(ref wh_url) = state.config.webhook_url {
        webhook::dispatch_webhook(
            wh_url.clone(),
            state.config.webhook_secret.clone(),
            "document.created",
            now,
            webhook::WebhookDocument {
                slug: slug.clone(),
                title: doc.title.clone(),
                url: response.url.clone(),
                api_url: response.api_url.clone(),
            },
        );
    }

    Ok((StatusCode::CREATED, Json(response)).into_response())
}

// ── PUT /api/v1/documents/:slug ──────────────────────────────────────────────

/// Handle document update.
pub async fn put_document(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    // Auth first
    check_auth(&state, &headers).await?;

    // Body validation
    if body.is_empty() {
        return Err(AppError::BadRequest("Request body must not be empty".to_string()));
    }

    let raw_content = std::str::from_utf8(&body)
        .map_err(|_| AppError::BadRequest("Request body must be valid UTF-8".to_string()))?
        .to_string();

    // Check document exists and is not expired
    let existing = state.db.get_by_slug(&slug)?
        .ok_or(AppError::NotFound)?;

    if is_expired(&existing) {
        return Err(AppError::Gone);
    }

    // Parse frontmatter
    let fm_result = extract_frontmatter(&raw_content)
        .map_err(|e| AppError::BadRequest(e))?;

    let meta = fm_result.meta.unwrap_or_default();
    let body_text = &fm_result.body;

    // Title: frontmatter > H1 > slug (slug from URL, NOT frontmatter)
    let title = meta.title.unwrap_or_else(|| extract_title(body_text, &slug));

    // Theme
    let theme = meta.theme.unwrap_or_else(|| state.config.default_theme.clone());

    // Expiry (can be added, changed, or removed on PUT)
    let now = chrono_now();
    let expires_at = match meta.expiry.as_deref() {
        Some(exp) => {
            let seconds = parse_expiry(exp)
                .map_err(|e| AppError::BadRequest(e))?;
            Some(add_seconds_to_now(&now, seconds))
        }
        None => None, // Remove expiry if not in frontmatter
    };

    // Password: update or clear
    let password_hash = match meta.password.as_deref() {
        Some(pw) if !pw.is_empty() => Some(hash_password(pw)?),
        Some(_) => None, // empty password = clear
        None => None,    // no password field = clear
    };

    let updated_doc = DocumentRecord {
        id: existing.id,
        slug: slug.clone(),
        title: title.clone(),
        raw_content,
        theme,
        password: password_hash,
        description: meta.description.clone(),
        created_at: existing.created_at.clone(),
        expires_at: expires_at.clone(),
        updated_at: now.clone(),
    };

    state.db.update_document(&slug, &updated_doc)?;

    let base = state.config.base_url.trim_end_matches('/');
    let response = CreateResponse {
        url: format!("{base}/{slug}"),
        slug: slug.clone(),
        api_url: format!("{base}/api/v1/documents/{slug}"),
        title: updated_doc.title.clone(),
        description: updated_doc.description.clone(),
        created_at: existing.created_at,
        expires_at: updated_doc.expires_at.clone(),
    };

    // Webhook: document.updated
    if let Some(ref wh_url) = state.config.webhook_url {
        webhook::dispatch_webhook(
            wh_url.clone(),
            state.config.webhook_secret.clone(),
            "document.updated",
            now,
            webhook::WebhookDocument {
                slug: slug.clone(),
                title: updated_doc.title.clone(),
                url: response.url.clone(),
                api_url: response.api_url.clone(),
            },
        );
    }

    Ok((StatusCode::OK, Json(response)).into_response())
}

// ── DELETE /api/v1/documents/:slug ───────────────────────────────────────────

/// Handle document deletion.
pub async fn delete_document(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    // Auth first
    check_auth(&state, &headers).await?;

    // Check document exists — capture title/slug for webhook before delete.
    let existing = state.db.get_by_slug(&slug)?
        .ok_or(AppError::NotFound)?;

    // Expired documents: still delete them (cleanup), return 204
    // Non-expired: normal delete, return 204.
    // We delete regardless of expiry status.

    state.db.delete_by_slug(&slug)?;

    // Webhook: document.deleted — dispatched after successful delete.
    // Metadata captured from existing record before deletion.
    if let Some(ref wh_url) = state.config.webhook_url {
        let base = state.config.base_url.trim_end_matches('/');
        let now = chrono_now();
        webhook::dispatch_webhook(
            wh_url.clone(),
            state.config.webhook_secret.clone(),
            "document.deleted",
            now,
            webhook::WebhookDocument {
                slug: existing.slug.clone(),
                title: existing.title.clone(),
                url: format!("{base}/{}", existing.slug),
                api_url: format!("{base}/api/v1/documents/{}", existing.slug),
            },
        );
    }

    Ok(StatusCode::NO_CONTENT.into_response())
}

// ── GET /api/v1/documents (list) ─────────────────────────────────────────────

/// List documents with pagination.
///
/// Requires bearer auth. Does NOT return raw_content.
/// Limit capped at 100 server-side; offset must be >=0 (enforced by type u32).
/// Expired documents excluded at SQL level.
pub async fn list_documents(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<ListQuery>,
) -> Result<Response, AppError> {
    check_auth(&state, &headers).await?;

    // Default limit 20, max 100. Cap is enforced in db::list_documents.
    let limit = params.limit.unwrap_or(20);
    let offset = params.offset.unwrap_or(0);

    let (documents, total) = state.db.list_documents(limit, offset)
        .map_err(AppError::from)?;

    // Report the effective (capped) limit in the response.
    let effective_limit = limit.min(100);

    Ok(Json(ListResponse {
        documents,
        total,
        limit: effective_limit,
        offset,
    }).into_response())
}

// ── GET /api/v1/openapi.yaml ─────────────────────────────────────────────────

/// Serve the OpenAPI spec as YAML.
///
/// Content included at compile time via include_str! — no runtime file I/O,
/// no startup panic if file is missing (compile error instead).
pub async fn serve_openapi_yaml() -> impl IntoResponse {
    // include_str! embeds the file at compile time. The path is relative to src/.
    let yaml = include_str!("../docs/openapi.yaml");
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/yaml; charset=utf-8")],
        yaml,
    )
}

/// Serve the OpenAPI spec as JSON.
///
/// Converted from YAML at first call, cached via OnceLock.
/// serde_yaml → serde_json at startup eliminates repeated conversion cost.
pub async fn serve_openapi_json() -> impl IntoResponse {
    use std::sync::OnceLock;
    static OPENAPI_JSON: OnceLock<String> = OnceLock::new();

    let json = OPENAPI_JSON.get_or_init(|| {
        let yaml = include_str!("../docs/openapi.yaml");
        match serde_yaml::from_str::<serde_json::Value>(yaml) {
            Ok(val) => serde_json::to_string(&val).unwrap_or_else(|e| {
                format!("{{\"error\":\"JSON serialization failed: {e}\"}}")
            }),
            Err(e) => format!("{{\"error\":\"YAML parse failed: {e}\"}}"),
        }
    });

    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json; charset=utf-8")],
        json.as_str(),
    )
}

// ── GET /:slug (human view) ──────────────────────────────────────────────────

/// Handle human view and raw-shortcut view.
///
/// Without `?raw=1`: renders the human corpus as themed HTML.
/// With `?raw=1`: returns the full raw source.
/// Password-protected documents show a password prompt.
pub async fn get_human(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Query(params): Query<SlugQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let doc = state.db.get_by_slug(&slug)?
        .ok_or(AppError::NotFound)?;

    // Expiry check (410 takes priority over password)
    if is_expired(&doc) {
        return Err(AppError::Gone);
    }

    // Password check (if document is protected)
    if doc.password.is_some() {
        if !is_password_authed(&headers, &slug, &state.config.token) {
            let template = PasswordTemplate { slug: &slug, error: None };
            return Ok(Html(template.render().map_err(|e| {
                AppError::Internal(format!("Template error: {e}"))
            })?).into_response());
        }
    }

    // ?raw=1 -> return full source
    if params.raw.as_deref() == Some("1") {
        return Ok(markdown_response(&doc.raw_content));
    }

    // Human view: extract body (strip frontmatter), parse markers, render.
    //
    // Rendering is moved to spawn_blocking because syntect's syntax highlighting
    // can use significant stack depth during the first load (OnceLock init) and
    // during regex-based tokenization. Release builds with LTO can optimize away
    // stack frames but still require deep call chains. spawn_blocking runs on a
    // dedicated thread pool with larger stacks, avoiding stack overflow in the
    // async worker thread.
    let raw_content = doc.raw_content.clone();
    let title = doc.title.clone();
    let theme = doc.theme.clone();
    let slug_owned = slug.clone();

    let html_result = tokio::task::spawn_blocking(move || {
        let fm_result = extract_frontmatter(&raw_content)
            .unwrap_or_else(|_| crate::parser::FrontmatterResult {
                meta: None,
                body: raw_content.clone(),
            });

        let parse_result = parse_document(&fm_result.body, &slug_owned);
        let rendered_html = render_markdown(&parse_result.human);
        render_themed_sync(&title, &rendered_html, &slug_owned, &theme, false)
    })
    .await
    .map_err(|e| AppError::Internal(format!("Render task failed: {e}")))?;

    html_result
}

// ── POST /:slug/unlock ───────────────────────────────────────────────────────

/// Handle password verification and cookie setting.
pub async fn post_unlock(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Form(form): Form<UnlockForm>,
) -> Result<Response, AppError> {
    let doc = state.db.get_by_slug(&slug)?
        .ok_or(AppError::NotFound)?;

    if is_expired(&doc) {
        return Err(AppError::Gone);
    }

    let stored_hash = match &doc.password {
        Some(h) => h,
        None => {
            // No password — redirect to document
            return Ok(Redirect::to(&format!("/{slug}")).into_response());
        }
    };

    // Verify password
    if verify_password(&form.password, stored_hash) {
        // Set auth cookie and redirect
        let cookie_value = make_auth_cookie(&slug, &state.config.token);
        let cookie_header = format!(
            "twofold_auth_{}={}; Path=/{}; HttpOnly; SameSite=Strict; Max-Age=3600",
            slug, cookie_value, slug
        );
        Ok((
            StatusCode::SEE_OTHER,
            [
                (axum::http::header::LOCATION, format!("/{slug}")),
                (axum::http::header::SET_COOKIE, cookie_header),
            ],
            "",
        ).into_response())
    } else {
        // Wrong password — show form again with error
        let template = PasswordTemplate {
            slug: &slug,
            error: Some("Incorrect password"),
        };
        Ok(Html(template.render().map_err(|e| {
            AppError::Internal(format!("Template error: {e}"))
        })?).into_response())
    }
}

// ── GET /:slug/full (rendered full view) ─────────────────────────────────────

/// Render the full document (including agent sections) as themed HTML.
///
/// The marker comments themselves (`<!-- @agent -->` / `<!-- @end -->`) are stripped
/// so they don't appear as visible HTML comments, but their content is included.
/// Password-protected documents still require authentication.
pub async fn get_full(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let doc = state.db.get_by_slug(&slug)?
        .ok_or(AppError::NotFound)?;

    if is_expired(&doc) {
        return Err(AppError::Gone);
    }

    // Password check
    if doc.password.is_some() {
        if !is_password_authed(&headers, &slug, &state.config.token) {
            let template = PasswordTemplate { slug: &slug, error: None };
            return Ok(Html(template.render().map_err(|e| {
                AppError::Internal(format!("Template error: {e}"))
            })?).into_response());
        }
    }

    // Same spawn_blocking pattern as get_human — syntect needs a larger stack.
    let raw_content = doc.raw_content.clone();
    let title = doc.title.clone();
    let theme = doc.theme.clone();
    let slug_owned = slug.clone();

    let html_result = tokio::task::spawn_blocking(move || {
        let fm_result = extract_frontmatter(&raw_content)
            .unwrap_or_else(|_| crate::parser::FrontmatterResult {
                meta: None,
                body: raw_content.clone(),
            });

        let stripped = strip_marker_comments(&fm_result.body);
        let rendered_html = render_markdown(&stripped);
        render_themed_sync(&title, &rendered_html, &slug_owned, &theme, true)
    })
    .await
    .map_err(|e| AppError::Internal(format!("Render task failed: {e}")))?;

    html_result
}

// ── GET /api/v1/documents/:slug (agent view) ─────────────────────────────────

/// Return the full raw source markdown.
/// Agent view is NOT password-gated.
pub async fn get_agent(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> Result<Response, AppError> {
    let doc = state.db.get_by_slug(&slug)?
        .ok_or(AppError::NotFound)?;

    if is_expired(&doc) {
        return Err(AppError::Gone);
    }

    Ok(markdown_response(&doc.raw_content))
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Auth check: admin token (constant-time) OR managed token (argon2 verify).
async fn check_auth(state: &AppState, headers: &HeaderMap) -> Result<(), AppError> {
    let provided = extract_bearer(headers)
        .ok_or(AppError::Unauthorized)?;

    // Check admin token first (constant-time)
    if constant_time_eq(provided.as_bytes(), state.config.token.as_bytes()) {
        return Ok(());
    }

    // Check managed tokens
    let tokens = state.db.get_active_tokens()
        .map_err(|_| AppError::Internal("Failed to check tokens".to_string()))?;

    for token_record in &tokens {
        if verify_password(provided, &token_record.hash) {
            // Update last_used
            let now = chrono_now();
            let _ = state.db.touch_token(&token_record.id, &now);
            return Ok(());
        }
    }

    Err(AppError::Unauthorized)
}

/// Extract the Bearer token from the Authorization header.
fn extract_bearer(headers: &HeaderMap) -> Option<&str> {
    let auth = headers.get("authorization")?.to_str().ok()?;
    auth.strip_prefix("Bearer ")
}

/// Build a `text/markdown; charset=utf-8` response.
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

/// Strip marker comment lines and agent-instructions blocks from source.
///
/// Two stripping behaviors:
///
/// 1. `<!-- @agent -->` and `<!-- @end -->` lines are removed (their content is KEPT).
///    These delimit agent-only sections in the source but the full view still renders
///    the content between them.
///
/// 2. `<!-- @instructions -->` / `<!-- @end-instructions -->` blocks are removed
///    entirely — both the marker lines AND everything between them.
///    Use this for meta-instructions directed at agents reading raw source that
///    should never appear in any rendered view (human or full).
///
/// Uses whitespace-tolerant matching (same logic as `parser::is_marker`).
fn strip_marker_comments(source: &str) -> String {
    let mut result: Vec<&str> = Vec::new();
    let mut in_instructions = false;

    for line in source.lines() {
        let t = line.trim();
        let tag = if t.starts_with("<!--") && t.ends_with("-->") {
            let inner = &t["<!--".len()..t.len() - "-->".len()];
            Some(inner.trim())
        } else {
            None
        };

        match tag {
            // Enter instructions block — skip marker, skip all content until close
            Some("@instructions") => {
                in_instructions = true;
                // marker line itself is dropped
            }
            // Exit instructions block — skip the closing marker
            Some("@end-instructions") if in_instructions => {
                in_instructions = false;
                // marker line itself is dropped
            }
            // Strip agent/end marker lines but keep content outside them
            Some("@agent") | Some("@end") if !in_instructions => {
                // marker line dropped, surrounding content preserved
            }
            // Inside an instructions block — drop content
            _ if in_instructions => {}
            // Normal line — keep it
            _ => {
                result.push(line);
            }
        }
    }

    result.join("\n")
}

/// Render markdown to HTML using comrak with GFM extensions.
fn render_markdown(source: &str) -> String {
    let mut options = Options::default();
    options.extension.table = true;
    options.extension.strikethrough = true;
    options.extension.autolink = true;
    options.extension.tasklist = true;
    options.render.unsafe_ = true;
    markdown_to_html(source, &options)
}

/// Render a themed HTML response with syntax highlighting.
///
/// `full_view`: when true, the clean-theme toolbar shows "Summary view" instead of "Full detail".
/// Has no effect on themes that don't render a toolbar.
///
/// `content` is already-rendered HTML from comrak. Syntax highlighting post-processes
/// this HTML, finding <pre><code class="language-X"> blocks and replacing them with
/// syntect-highlighted spans. Dark theme uses dark syntax palette; all others use light.
///
/// Named `_sync` because it is called from `spawn_blocking` contexts (not directly from async).
/// This avoids stack overflow in async worker threads during syntect init/tokenization.
fn render_themed_sync(title: &str, content: &str, slug: &str, theme: &str, full_view: bool) -> Result<Response, AppError> {
    // Apply syntax highlighting to the pre-rendered HTML.
    // Dark theme gets dark syntax palette; all others get light.
    let is_dark = theme == "dark";
    let highlighted = highlight::apply_syntax_highlighting(content, is_dark);

    let html = match theme {
        "dark" => {
            let t = DarkTemplate { title, content: &highlighted, slug };
            t.render()
        }
        "paper" => {
            let t = PaperTemplate { title, content: &highlighted, slug };
            t.render()
        }
        "minimal" => {
            let t = MinimalTemplate { title, content: &highlighted, slug };
            t.render()
        }
        "hearth" => {
            let t = HearthTemplate { title, content: &highlighted, slug, full_view };
            t.render()
        }
        _ => {
            // "clean" or unknown -> default
            let t = CleanTemplate { title, content: &highlighted, slug, full_view };
            t.render()
        }
    };

    html.map(|h| Html(h).into_response())
        .map_err(|e| AppError::Internal(format!("Template render error: {e}")))
}

/// Check if a document has expired.
fn is_expired(doc: &DocumentRecord) -> bool {
    match &doc.expires_at {
        Some(exp) => {
            let now = chrono_now();
            exp.as_str() < now.as_str()
        }
        None => false,
    }
}

/// Current UTC time as ISO 8601 string.
pub fn chrono_now() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Add seconds to a timestamp string and return new ISO 8601 string.
fn add_seconds_to_now(_now: &str, seconds: u64) -> String {
    let future = chrono::Utc::now() + chrono::Duration::seconds(seconds as i64);
    future.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Constant-time byte comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Check whether a rusqlite error is a UNIQUE constraint violation.
fn is_unique_violation(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(err, _) if err.code == rusqlite::ErrorCode::ConstraintViolation
    )
}

/// Hash a password with argon2.
pub fn hash_password(password: &str) -> Result<String, AppError> {
    use argon2::{Argon2, password_hash::{SaltString, PasswordHasher, rand_core::OsRng}};

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(format!("Password hashing failed: {e}")))?;
    Ok(hash.to_string())
}

/// Verify a password against an argon2 hash.
pub fn verify_password(password: &str, hash: &str) -> bool {
    use argon2::{Argon2, PasswordHash, PasswordVerifier};

    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Generate an HMAC-based auth cookie value for a slug.
fn make_auth_cookie(slug: &str, server_secret: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use base64::Engine;

    let expiry = chrono::Utc::now() + chrono::Duration::hours(1);
    let expiry_str = expiry.format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let mut mac = Hmac::<Sha256>::new_from_slice(server_secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(slug.as_bytes());
    mac.update(expiry_str.as_bytes());
    let signature = mac.finalize().into_bytes();

    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature);
    format!("{}:{}", sig_b64, expiry_str)
}

/// Check if the request has a valid password auth cookie.
fn is_password_authed(headers: &HeaderMap, slug: &str, server_secret: &str) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use base64::Engine;

    let cookie_name = format!("twofold_auth_{}", slug);

    let cookies = match headers.get("cookie").and_then(|v| v.to_str().ok()) {
        Some(c) => c,
        None => return false,
    };

    // Find our cookie in the cookie string
    let cookie_value = cookies
        .split(';')
        .map(|s| s.trim())
        .find_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let name = parts.next()?;
            let value = parts.next()?;
            if name == cookie_name { Some(value) } else { None }
        });

    let cookie_value = match cookie_value {
        Some(v) => v,
        None => return false,
    };

    // Parse "signature:expiry"
    let mut parts = cookie_value.splitn(2, ':');
    let sig_b64 = match parts.next() {
        Some(s) => s,
        None => return false,
    };
    let expiry_str = match parts.next() {
        Some(s) => s,
        None => return false,
    };

    // Check expiry
    let now = chrono_now();
    if expiry_str < now.as_str() {
        return false; // expired cookie
    }

    // Verify HMAC
    let mut mac = match Hmac::<Sha256>::new_from_slice(server_secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(slug.as_bytes());
    mac.update(expiry_str.as_bytes());
    let expected_sig = mac.finalize().into_bytes();

    let provided_sig = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(sig_b64) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Constant-time comparison of signatures
    constant_time_eq(&provided_sig, &expected_sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_expired_none() {
        let doc = DocumentRecord {
            id: "test".to_string(),
            slug: "test".to_string(),
            title: "Test".to_string(),
            raw_content: "content".to_string(),
            theme: "clean".to_string(),
            password: None,
            description: None,
            created_at: "2024-01-01T00:00:00Z".to_string(),
            expires_at: None,
            updated_at: "2024-01-01T00:00:00Z".to_string(),
        };
        assert!(!is_expired(&doc));
    }

    #[test]
    fn test_is_expired_past() {
        let doc = DocumentRecord {
            id: "test".to_string(),
            slug: "test".to_string(),
            title: "Test".to_string(),
            raw_content: "content".to_string(),
            theme: "clean".to_string(),
            password: None,
            description: None,
            created_at: "2024-01-01T00:00:00Z".to_string(),
            expires_at: Some("2020-01-01T00:00:00Z".to_string()),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
        };
        assert!(is_expired(&doc));
    }

    #[test]
    fn test_is_expired_future() {
        let doc = DocumentRecord {
            id: "test".to_string(),
            slug: "test".to_string(),
            title: "Test".to_string(),
            raw_content: "content".to_string(),
            theme: "clean".to_string(),
            password: None,
            description: None,
            created_at: "2024-01-01T00:00:00Z".to_string(),
            expires_at: Some("2099-01-01T00:00:00Z".to_string()),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
        };
        assert!(!is_expired(&doc));
    }

    #[test]
    fn test_hash_and_verify_password() {
        let hash = hash_password("hunter2").unwrap();
        assert!(verify_password("hunter2", &hash));
        assert!(!verify_password("wrong", &hash));
    }
}
