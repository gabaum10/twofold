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
    /// Document is password-protected and no password was supplied.
    DocumentPasswordRequired,
    /// Document is password-protected and the supplied password was wrong.
    DocumentPasswordInvalid,
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
            AppError::DocumentPasswordRequired => {
                (StatusCode::UNAUTHORIZED, "Password required".to_string())
            }
            AppError::DocumentPasswordInvalid => {
                (StatusCode::UNAUTHORIZED, "Invalid password".to_string())
            }
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
    body_empty: bool,
    expires_at: Option<String>,
}

/// Dark theme template.
#[derive(Template)]
#[template(path = "dark.html")]
struct DarkTemplate<'a> {
    title: &'a str,
    content: &'a str,
    slug: &'a str,
    body_empty: bool,
    expires_at: Option<String>,
}

/// Paper theme template.
#[derive(Template)]
#[template(path = "paper.html")]
struct PaperTemplate<'a> {
    title: &'a str,
    content: &'a str,
    slug: &'a str,
    body_empty: bool,
    expires_at: Option<String>,
}

/// Minimal theme template.
#[derive(Template)]
#[template(path = "minimal.html")]
struct MinimalTemplate<'a> {
    title: &'a str,
    content: &'a str,
    slug: &'a str,
    body_empty: bool,
    expires_at: Option<String>,
}

/// Hearth theme template.
#[derive(Template)]
#[template(path = "hearth.html")]
struct HearthTemplate<'a> {
    title: &'a str,
    content: &'a str,
    slug: &'a str,
    full_view: bool,
    body_empty: bool,
    expires_at: Option<String>,
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

    // Expiry: None = keep existing, Some("") = clear, Some(value) = set new
    let now = chrono_now();
    let expires_at = match meta.expiry.as_deref() {
        Some(exp) if !exp.is_empty() => {
            let seconds = parse_expiry(exp)
                .map_err(|e| AppError::BadRequest(e))?;
            Some(add_seconds_to_now(&now, seconds))
        }
        Some(_) => None,                      // empty string = clear
        None => existing.expires_at.clone(),  // absent = preserve
    };

    // Password: None = keep existing, Some("") = clear, Some(value) = set new
    let password_hash = match meta.password.as_deref() {
        Some(pw) if !pw.is_empty() => Some(hash_password(pw)?),
        Some(_) => None,                      // empty string = clear
        None => existing.password.clone(),    // absent = preserve
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

// ── GET /health ──────────────────────────────────────────────────────────────

/// Health check endpoint. No auth required.
///
/// Returns 200 with `{"status":"ok","db":"ok"}` when the database is reachable.
/// Returns 503 with `{"status":"degraded","db":"error"}` if the db check fails.
///
/// The db check executes a trivial `SELECT 1` to verify the connection is live.
pub async fn health_check(State(state): State<AppState>) -> Response {
    let db_ok = state.db.ping().is_ok();
    if db_ok {
        (
            StatusCode::OK,
            Json(serde_json::json!({"status": "ok", "db": "ok"})),
        )
            .into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"status": "degraded", "db": "error"})),
        )
            .into_response()
    }
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
    let doc = match state.db.get_by_slug(&slug)? {
        Some(d) => d,
        None => return Ok(not_found_response()),
    };

    // Expiry check (410 takes priority over password)
    if is_expired(&doc) {
        return Ok(gone_response());
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
    let expires_at = doc.expires_at.clone();

    let html_result = tokio::task::spawn_blocking(move || {
        let fm_result = extract_frontmatter(&raw_content)
            .unwrap_or_else(|_| crate::parser::FrontmatterResult {
                meta: None,
                body: raw_content.clone(),
            });

        let parse_result = parse_document(&fm_result.body, &slug_owned);
        let rendered_html = render_markdown(&parse_result.human);
        render_themed_sync(&title, &rendered_html, &slug_owned, &theme, false, expires_at)
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
    let doc = match state.db.get_by_slug(&slug)? {
        Some(d) => d,
        None => return Ok(not_found_response()),
    };

    if is_expired(&doc) {
        return Ok(gone_response());
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
    let doc = match state.db.get_by_slug(&slug)? {
        Some(d) => d,
        None => return Ok(not_found_response()),
    };

    if is_expired(&doc) {
        return Ok(gone_response());
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
    let expires_at = doc.expires_at.clone();

    let html_result = tokio::task::spawn_blocking(move || {
        let fm_result = extract_frontmatter(&raw_content)
            .unwrap_or_else(|_| crate::parser::FrontmatterResult {
                meta: None,
                body: raw_content.clone(),
            });

        let stripped = strip_marker_comments(&fm_result.body);
        let rendered_html = render_markdown(&stripped);
        render_themed_sync(&title, &rendered_html, &slug_owned, &theme, true, expires_at)
    })
    .await
    .map_err(|e| AppError::Internal(format!("Render task failed: {e}")))?;

    html_result
}

// ── GET /api/v1/documents/:slug (agent view) ─────────────────────────────────

/// Query parameters for GET /api/v1/documents/:slug (agent view).
#[derive(Deserialize)]
pub struct AgentQuery {
    pub password: Option<String>,
}

/// Return the full raw source markdown.
///
/// Password-protected documents require the correct password as a query
/// parameter (`?password=<value>`). Returns 401 with a JSON error body if
/// the document is protected and the password is missing or incorrect.
pub async fn get_agent(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Query(params): Query<AgentQuery>,
) -> Result<Response, AppError> {
    let doc = state.db.get_by_slug(&slug)?
        .ok_or(AppError::NotFound)?;

    if is_expired(&doc) {
        return Err(AppError::Gone);
    }

    // Password gate — same argon2 check as the human view.
    if let Some(stored_hash) = &doc.password {
        match params.password.as_deref() {
            Some(provided) if verify_password(provided, stored_hash) => {
                // Correct password — fall through to serve content.
            }
            Some(_) => {
                return Err(AppError::DocumentPasswordInvalid);
            }
            None => {
                return Err(AppError::DocumentPasswordRequired);
            }
        }
    }

    Ok(markdown_response(&doc.raw_content))
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Auth check: admin token (constant-time) OR managed token (argon2 verify).
///
/// Performance contract:
/// 1. Admin token: O(1) constant-time compare, no argon2.
/// 2. Managed tokens (v0.4+): prefix lookup → O(1) indexed DB query → at most
///    1 argon2 verification per request, run in `spawn_blocking`.
/// 3. Legacy tokens (prefix IS NULL, created before v0.4): O(n) fallback with
///    argon2 per record, also in `spawn_blocking`. Degrades gracefully for
///    existing deployments; new tokens never hit this path.
async fn check_auth(state: &AppState, headers: &HeaderMap) -> Result<(), AppError> {
    let provided = extract_bearer(headers)
        .ok_or(AppError::Unauthorized)?;

    // Fast path: admin TWOFOLD_TOKEN — constant-time, no argon2.
    if constant_time_eq(provided.as_bytes(), state.config.token.as_bytes()) {
        return Ok(());
    }

    // Prefix-based O(1) lookup: use first 8 chars of the provided token
    // to look up the one candidate record, then verify with argon2.
    let prefix: String = provided.chars().take(8).collect();

    let candidate = state.db.get_token_by_prefix(&prefix)
        .map_err(|_| AppError::Internal("Failed to check tokens".to_string()))?;

    if let Some(token_record) = candidate {
        let provided_owned = provided.to_string();
        let hash_owned = token_record.hash.clone();
        let verified = tokio::task::spawn_blocking(move || {
            verify_password(&provided_owned, &hash_owned)
        })
        .await
        .map_err(|e| AppError::Internal(format!("Auth task failed: {e}")))?;

        if verified {
            let now = chrono_now();
            let _ = state.db.touch_token(&token_record.id, &now);
            return Ok(());
        }
        // Prefix matched but hash didn't — fall through to legacy check and
        // ultimately return Unauthorized (prefix collision is astronomically rare).
    }

    // Legacy fallback: tokens created before v0.4 have no prefix stored.
    // On a fresh database this query returns 0 rows immediately.
    let legacy_tokens = state.db.get_legacy_active_tokens()
        .map_err(|_| AppError::Internal("Failed to check tokens".to_string()))?;

    if !legacy_tokens.is_empty() {
        let provided_owned = provided.to_string();
        let result = tokio::task::spawn_blocking(move || {
            for token_record in &legacy_tokens {
                if verify_password(&provided_owned, &token_record.hash) {
                    return Some(token_record.id.clone());
                }
            }
            None
        })
        .await
        .map_err(|e| AppError::Internal(format!("Auth task failed: {e}")))?;

        if let Some(id) = result {
            let now = chrono_now();
            let _ = state.db.touch_token(&id, &now);
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
fn render_themed_sync(title: &str, content: &str, slug: &str, theme: &str, full_view: bool, expires_at: Option<String>) -> Result<Response, AppError> {
    // Apply syntax highlighting to the pre-rendered HTML.
    // Dark theme gets dark syntax palette; all others get light.
    let is_dark = theme == "dark";
    let highlighted = highlight::apply_syntax_highlighting(content, is_dark);

    let body_empty = highlighted.trim().is_empty();

    let html = match theme {
        "dark" => {
            let t = DarkTemplate { title, content: &highlighted, slug, body_empty, expires_at };
            t.render()
        }
        "paper" => {
            let t = PaperTemplate { title, content: &highlighted, slug, body_empty, expires_at };
            t.render()
        }
        "minimal" => {
            let t = MinimalTemplate { title, content: &highlighted, slug, body_empty, expires_at };
            t.render()
        }
        "hearth" => {
            let t = HearthTemplate { title, content: &highlighted, slug, full_view, body_empty, expires_at };
            t.render()
        }
        _ => {
            // "clean" or unknown -> default
            let t = CleanTemplate { title, content: &highlighted, slug, full_view, body_empty, expires_at };
            t.render()
        }
    };

    html.map(|h| Html(h).into_response())
        .map_err(|e| AppError::Internal(format!("Template render error: {e}")))
}

// ── Themed error page HTML ───────────────────────────────────────────────────

/// Return a themed 404 HTML response (hearth palette).
///
/// Inlined so no Askama template dependency is needed for two-page error surfaces.
/// All CSS is inline — zero external requests — matching the hearth.html contract.
fn not_found_response() -> Response {
    let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Document not found</title>
    <style>
/* twofold — error 404 page (hearth palette) */
:root {
    --bg: #F5F0EB;
    --fg: #2C2420;
    --fg-secondary: #6B5D52;
    --fg-muted: #A89888;
    --border: #E8E0D8;
    --border-strong: #D4C8B8;
    --accent: #C4762B;
    --accent-hover: #A86220;
    --font-body: Charter, 'Bitstream Charter', 'Sitka Text', Cambria, serif;
    --font-heading: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    --max-width: 850px;
}

*, *::before, *::after { box-sizing: border-box; }

html {
    font-size: 16px;
    -webkit-text-size-adjust: 100%;
    text-size-adjust: 100%;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
}

body {
    margin: 0;
    padding: 0;
    background: var(--bg);
    color: var(--fg);
    font-family: var(--font-body);
    font-size: 1.0625rem;
    line-height: 1.75;
    border-top: 4px solid var(--accent);
    min-height: 100vh;
    display: flex;
    flex-direction: column;
}

main {
    flex: 1;
    max-width: var(--max-width);
    margin: 0 auto;
    padding: 4rem 1.75rem 2.5rem;
    width: 100%;
}

.error-code {
    font-family: var(--font-heading);
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--accent);
    margin: 0 0 1rem;
}

h1 {
    font-family: var(--font-heading);
    font-size: 2rem;
    font-weight: 800;
    line-height: 1.15;
    color: var(--accent);
    margin: 0 0 1rem;
    letter-spacing: -0.02em;
    padding-bottom: 0.5rem;
    border-bottom: 3px solid var(--accent);
}

p {
    color: var(--fg-secondary);
    margin: 0;
    max-width: 36rem;
}

footer {
    max-width: var(--max-width);
    margin: 0 auto;
    padding: 1.75rem 1.75rem 2.5rem;
    text-align: center;
    border-top: 1px solid var(--border-strong);
    width: 100%;
}

footer::before {
    content: "";
    display: block;
    width: 2.5rem;
    height: 3px;
    background: var(--accent);
    margin: 0 auto 1rem;
    border-radius: 2px;
}

footer small {
    color: var(--fg-muted);
    font-size: 0.7rem;
    font-family: var(--font-heading);
    letter-spacing: 0.08em;
    text-transform: uppercase;
}

footer small a {
    color: var(--accent);
    text-decoration: underline;
    text-decoration-thickness: 1px;
    text-underline-offset: 2px;
    transition: color 0.15s ease;
}

footer small a:hover {
    color: var(--accent-hover);
}

@media (max-width: 600px) {
    main { padding: 2.5rem 1rem 1.75rem; }
    h1 { font-size: 1.625rem; }
}
    </style>
</head>
<body>
    <main>
        <p class="error-code">404</p>
        <h1>Document not found</h1>
        <p>This document doesn't exist, or the link may be incorrect.</p>
    </main>
    <footer>
        <small>SHARED VIA FLINT &middot; TWOFOLD</small>
    </footer>
</body>
</html>"#;
    (
        StatusCode::NOT_FOUND,
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response()
}

/// Return a themed 410 HTML response (hearth palette, muted/faded to signal impermanence).
///
/// Visually distinct from 404: muted heading color, reduced accent bar opacity,
/// and language that explains the document was intentionally time-limited.
fn gone_response() -> Response {
    let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Document expired</title>
    <style>
/* twofold — error 410 page (hearth palette, muted for impermanence) */
:root {
    --bg: #F5F0EB;
    --fg: #2C2420;
    --fg-secondary: #6B5D52;
    --fg-muted: #A89888;
    --border: #E8E0D8;
    --border-strong: #D4C8B8;
    --accent: #C4762B;
    --accent-hover: #A86220;
    --font-body: Charter, 'Bitstream Charter', 'Sitka Text', Cambria, serif;
    --font-heading: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    --max-width: 850px;
}

*, *::before, *::after { box-sizing: border-box; }

html {
    font-size: 16px;
    -webkit-text-size-adjust: 100%;
    text-size-adjust: 100%;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
}

body {
    margin: 0;
    padding: 0;
    background: var(--bg);
    color: var(--fg);
    font-family: var(--font-body);
    font-size: 1.0625rem;
    line-height: 1.75;
    /* Muted top bar — not gone, just quieter. Ember fading to ash. */
    border-top: 4px solid var(--fg-muted);
    min-height: 100vh;
    display: flex;
    flex-direction: column;
}

main {
    flex: 1;
    max-width: var(--max-width);
    margin: 0 auto;
    padding: 4rem 1.75rem 2.5rem;
    width: 100%;
    /* Slightly washed out — this was here but isn't anymore */
    opacity: 0.85;
}

.error-code {
    font-family: var(--font-heading);
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--fg-muted);
    margin: 0 0 1rem;
}

h1 {
    font-family: var(--font-heading);
    font-size: 2rem;
    font-weight: 800;
    line-height: 1.15;
    /* Secondary color instead of accent — the fire has gone out */
    color: var(--fg-secondary);
    margin: 0 0 1rem;
    letter-spacing: -0.02em;
    padding-bottom: 0.5rem;
    /* Muted border — a trace of what was */
    border-bottom: 3px solid var(--border-strong);
}

p {
    color: var(--fg-muted);
    margin: 0 0 1.5rem;
    max-width: 36rem;
}

.expiry-mark {
    display: inline-block;
    width: 2rem;
    height: 2px;
    background: var(--border-strong);
    border-radius: 2px;
    vertical-align: middle;
    margin-right: 0.5rem;
    opacity: 0.6;
}

footer {
    max-width: var(--max-width);
    margin: 0 auto;
    padding: 1.75rem 1.75rem 2.5rem;
    text-align: center;
    border-top: 1px solid var(--border-strong);
    width: 100%;
}

footer::before {
    content: "";
    display: block;
    width: 2.5rem;
    height: 3px;
    /* Footer ember stays warm even when document is gone */
    background: var(--accent);
    margin: 0 auto 1rem;
    border-radius: 2px;
    opacity: 0.5;
}

footer small {
    color: var(--fg-muted);
    font-size: 0.7rem;
    font-family: var(--font-heading);
    letter-spacing: 0.08em;
    text-transform: uppercase;
}

footer small a {
    color: var(--accent);
    text-decoration: underline;
    text-decoration-thickness: 1px;
    text-underline-offset: 2px;
    transition: color 0.15s ease;
}

footer small a:hover {
    color: var(--accent-hover);
}

@media (max-width: 600px) {
    main { padding: 2.5rem 1rem 1.75rem; }
    h1 { font-size: 1.625rem; }
}
    </style>
</head>
<body>
    <main>
        <p class="error-code">410</p>
        <h1>This document has expired</h1>
        <p>This document was set to expire and has been removed.</p>
        <p><span class="expiry-mark" aria-hidden="true"></span>The link is no longer valid.</p>
    </main>
    <footer>
        <small>SHARED VIA FLINT &middot; TWOFOLD</small>
    </footer>
</body>
</html>"#;
    (
        StatusCode::GONE,
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response()
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

    // ── PUT /api/v1/documents/:slug integration tests ─────────────────────────
    //
    // These tests use axum's oneshot mechanism to exercise the full handler stack
    // with an in-memory SQLite database. No network, no external process.

    use std::sync::Arc;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        Router,
        routing::{get, post},
    };
    use tower::ServiceExt;

    /// Build a minimal test router backed by an in-memory database.
    fn test_app(token: &str) -> Router {
        let db = crate::db::Db::open(":memory:").expect("in-memory db");
        let config = Arc::new(crate::config::ServeConfig {
            token: token.to_string(),
            db_path: ":memory:".to_string(),
            bind: "127.0.0.1:0".to_string(),
            base_url: "http://localhost".to_string(),
            default_theme: "clean".to_string(),
            max_size: 1_048_576,
            webhook_url: None,
            webhook_secret: None,
            reaper_interval: 3600,
        });
        let state = AppState { db, config };
        Router::new()
            .route(
                "/api/v1/documents",
                post(crate::handlers::post_document).get(crate::handlers::list_documents),
            )
            .route(
                "/api/v1/documents/:slug",
                get(crate::handlers::get_agent)
                    .put(crate::handlers::put_document)
                    .delete(crate::handlers::delete_document),
            )
            .with_state(state)
    }

    /// Build a test router that includes both API routes AND human-facing routes.
    ///
    /// Used for testing themed error pages (404/410) from the human view.
    fn test_app_full(token: &str) -> Router {
        let db = crate::db::Db::open(":memory:").expect("in-memory db");
        let config = Arc::new(crate::config::ServeConfig {
            token: token.to_string(),
            db_path: ":memory:".to_string(),
            bind: "127.0.0.1:0".to_string(),
            base_url: "http://localhost".to_string(),
            default_theme: "clean".to_string(),
            max_size: 1_048_576,
            webhook_url: None,
            webhook_secret: None,
            reaper_interval: 3600,
        });
        let state = AppState { db, config };
        Router::new()
            .route(
                "/api/v1/documents",
                post(crate::handlers::post_document).get(crate::handlers::list_documents),
            )
            .route(
                "/api/v1/documents/:slug",
                get(crate::handlers::get_agent)
                    .put(crate::handlers::put_document)
                    .delete(crate::handlers::delete_document),
            )
            .route("/:slug/unlock", post(crate::handlers::post_unlock))
            .route("/:slug/full", get(crate::handlers::get_full))
            .route("/:slug", get(crate::handlers::get_human))
            .with_state(state)
    }

    // ── Themed error page tests ───────────────────────────────────────────────

    /// GET /:nonexistent-slug → 404 with themed HTML body.
    #[tokio::test]
    async fn test_human_get_nonexistent_returns_404_with_html() {
        let token = "test-token";
        let app = test_app_full(token);

        let req = Request::builder()
            .method("GET")
            .uri("/this-slug-does-not-exist")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            content_type.contains("text/html"),
            "404 response should be HTML, got: {content_type}"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let text = std::str::from_utf8(&body).unwrap();

        assert!(
            text.contains("Document not found") || text.contains("not found"),
            "404 body should contain 'not found' text"
        );
        assert!(
            text.contains("FLINT") || text.contains("flint") || text.contains("twofold"),
            "404 body should contain footer branding"
        );
        assert!(
            text.contains("<!DOCTYPE html>"),
            "404 body should be valid HTML"
        );
    }

    /// An expired document via GET /:slug → 410 with themed HTML body.
    #[tokio::test]
    async fn test_human_get_expired_returns_410_with_html() {
        let token = "test-token";

        // We need to insert a document with a past expires_at directly — the publish
        // API only accepts future durations (e.g., "1h"). Build the app with a shared
        // DB handle so we can pre-seed the expired record.

        let db = crate::db::Db::open(":memory:").expect("in-memory db");
        let config = Arc::new(crate::config::ServeConfig {
            token: token.to_string(),
            db_path: ":memory:".to_string(),
            bind: "127.0.0.1:0".to_string(),
            base_url: "http://localhost".to_string(),
            default_theme: "clean".to_string(),
            max_size: 1_048_576,
            webhook_url: None,
            webhook_secret: None,
            reaper_interval: 3600,
        });

        // Insert an already-expired document directly.
        let expired_doc = crate::db::DocumentRecord {
            id: "expired-slug".to_string(),
            slug: "expired-slug".to_string(),
            title: "Expired Doc".to_string(),
            raw_content: "# Expired\nThis document has expired.".to_string(),
            theme: "clean".to_string(),
            password: None,
            description: None,
            created_at: "2020-01-01T00:00:00Z".to_string(),
            expires_at: Some("2020-06-01T00:00:00Z".to_string()), // firmly in the past
            updated_at: "2020-01-01T00:00:00Z".to_string(),
        };
        db.insert_document(&expired_doc).expect("insert expired doc");

        let state = AppState { db, config };
        let app = Router::new()
            .route(
                "/api/v1/documents",
                post(crate::handlers::post_document).get(crate::handlers::list_documents),
            )
            .route(
                "/api/v1/documents/:slug",
                get(crate::handlers::get_agent)
                    .put(crate::handlers::put_document)
                    .delete(crate::handlers::delete_document),
            )
            .route("/:slug/unlock", post(crate::handlers::post_unlock))
            .route("/:slug/full", get(crate::handlers::get_full))
            .route("/:slug", get(crate::handlers::get_human))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/expired-slug")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::GONE);

        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            content_type.contains("text/html"),
            "410 response should be HTML, got: {content_type}"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let text = std::str::from_utf8(&body).unwrap();

        assert!(
            text.contains("expired") || text.contains("Expired"),
            "410 body should contain 'expired' text"
        );
        assert!(
            text.contains("FLINT") || text.contains("flint") || text.contains("twofold"),
            "410 body should contain footer branding"
        );
        assert!(
            text.contains("<!DOCTYPE html>"),
            "410 body should be valid HTML"
        );
    }

    /// API (agent) route still returns JSON 404 for nonexistent slugs.
    ///
    /// This confirms the themed HTML is ONLY for human-facing routes,
    /// not for the machine API.
    #[tokio::test]
    async fn test_api_get_nonexistent_still_returns_json_404() {
        let token = "test-token";
        let app = test_app(token);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/documents/does-not-exist")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"].as_str().unwrap(), "Not found");
    }

    /// Password-protected doc that doesn't exist returns 404 (themed HTML),
    /// not a password prompt.
    #[tokio::test]
    async fn test_nonexistent_protected_slug_returns_404_not_password_prompt() {
        let token = "test-token";
        let app = test_app_full(token);

        // Request a slug that was never created — should be 404, not password form.
        let req = Request::builder()
            .method("GET")
            .uri("/nonexistent-protected-slug")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let text = std::str::from_utf8(&body).unwrap();

        // Should NOT contain password form elements
        assert!(
            !text.contains(r#"type="password""#),
            "nonexistent slug should not show password prompt"
        );
        // Should contain 404 messaging
        assert!(
            text.contains("not found") || text.contains("Not found"),
            "should contain not found message"
        );
    }

    /// POST a document and return the slug from the JSON response.
    async fn publish_doc(app: Router, token: &str, slug: &str, content: &str) -> String {
        let body = format!("---\nslug: {slug}\n---\n{content}");
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/documents")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "text/markdown")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED, "publish failed");
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        json["slug"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn test_put_updates_existing_document() {
        let token = "test-token";
        let app = test_app(token);

        // Publish a document first.
        let slug = publish_doc(app.clone(), token, "my-slug", "# Original\nOriginal content.").await;
        assert_eq!(slug, "my-slug");

        // PUT with new content.
        let req = Request::builder()
            .method("PUT")
            .uri(format!("/api/v1/documents/{slug}"))
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "text/markdown")
            .body(Body::from("# Updated\nUpdated content."))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["slug"].as_str().unwrap(), "my-slug");

        // Verify content actually changed via GET.
        let req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/documents/{slug}"))
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let raw = std::str::from_utf8(&body_bytes).unwrap();
        assert!(raw.contains("Updated content."), "content should reflect PUT body");
        assert!(!raw.contains("Original content."), "old content should be gone");
    }

    #[tokio::test]
    async fn test_put_returns_404_for_nonexistent_slug() {
        let token = "test-token";
        let app = test_app(token);

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/documents/does-not-exist")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "text/markdown")
            .body(Body::from("# Content"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_put_requires_auth() {
        let token = "test-token";
        let app = test_app(token);

        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/documents/anything")
            .header("Content-Type", "text/markdown")
            .body(Body::from("# Content"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_put_updates_title_from_frontmatter() {
        let token = "test-token";
        let app = test_app(token);

        publish_doc(app.clone(), token, "title-test", "# Old Title\nBody.").await;

        let new_content = "---\ntitle: New Title\n---\n# New Title\nBody.";
        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/documents/title-test")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "text/markdown")
            .body(Body::from(new_content))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["title"].as_str().unwrap(), "New Title");
    }

    #[tokio::test]
    async fn test_put_response_is_well_formed() {
        let token = "test-token";
        let app = test_app(token);

        // Publish, grab created_at.
        let slug = publish_doc(app.clone(), token, "ts-test", "# V1").await;

        // GET metadata via POST response is in publish step — we need another approach.
        // We'll just verify PUT responds with a valid updated_at field.
        let req = Request::builder()
            .method("PUT")
            .uri(format!("/api/v1/documents/{slug}"))
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "text/markdown")
            .body(Body::from("# V2"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // The response from PUT is CreateResponse which includes created_at but not updated_at.
        // Verify the response is well-formed and slug is correct.
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["slug"].as_str().unwrap(), slug);
        assert!(json.get("created_at").is_some(), "response should include created_at");
    }

    #[tokio::test]
    async fn test_put_does_not_change_slug() {
        // Verify the slug in the URL is the authoritative slug, not any slug in frontmatter.
        let token = "test-token";
        let app = test_app(token);

        publish_doc(app.clone(), token, "original-slug", "# Doc").await;

        // PUT with content that has a different slug in frontmatter — should be ignored.
        let content_with_different_slug = "---\nslug: different-slug\n---\n# Doc";
        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/documents/original-slug")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "text/markdown")
            .body(Body::from(content_with_different_slug))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        // Slug in response must match the URL slug, not the frontmatter slug.
        assert_eq!(json["slug"].as_str().unwrap(), "original-slug");
    }

    // ── GET /api/v1/documents/:slug password gate tests ───────────────────────

    /// Publish a password-protected document and return its slug.
    async fn publish_protected_doc(app: Router, token: &str, slug: &str, password: &str) -> String {
        let body = format!("---\nslug: {slug}\npassword: {password}\n---\nSecret content.");
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/documents")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "text/markdown")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED, "publish protected doc failed");
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        json["slug"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn test_agent_get_protected_doc_correct_password_returns_content() {
        let token = "test-token";
        let app = test_app(token);

        let slug = publish_protected_doc(app.clone(), token, "pw-correct", "hunter2").await;

        let req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/documents/{slug}?password=hunter2"))
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("Secret content."), "body should contain document content");
    }

    #[tokio::test]
    async fn test_agent_get_protected_doc_wrong_password_returns_401() {
        let token = "test-token";
        let app = test_app(token);

        let slug = publish_protected_doc(app.clone(), token, "pw-wrong", "hunter2").await;

        let req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/documents/{slug}?password=wrongpass"))
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"].as_str().unwrap(), "Invalid password");
    }

    #[tokio::test]
    async fn test_agent_get_protected_doc_no_password_returns_401() {
        let token = "test-token";
        let app = test_app(token);

        let slug = publish_protected_doc(app.clone(), token, "pw-none", "hunter2").await;

        let req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/documents/{slug}"))
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"].as_str().unwrap(), "Password required");
    }

    #[tokio::test]
    async fn test_agent_get_unprotected_doc_works_without_password() {
        let token = "test-token";
        let app = test_app(token);

        let slug = publish_doc(app.clone(), token, "no-pw-doc", "# Public\nOpen content.").await;

        let req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/documents/{slug}"))
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("Open content."), "unprotected doc should be served without password");
    }

    // ── Managed token auth tests ──────────────────────────────────────────────

    /// Build a test router that has a pre-inserted managed token in the DB.
    ///
    /// Returns (Router, plaintext_managed_token). The admin TWOFOLD_TOKEN is set
    /// to "admin-token" so both paths can be exercised separately.
    fn test_app_with_managed_token() -> (Router, String) {
        use crate::db::{Db, TokenRecord};
        use crate::config::ServeConfig;

        let db = Db::open(":memory:").expect("in-memory db");

        // Insert a managed token using the same format as `token_create` in main.rs:
        // tf_<base64url(32 bytes)>. We use a fixed value for test determinism.
        let managed_plain = "tf_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let prefix: String = managed_plain.chars().take(8).collect();
        let hash = hash_password(managed_plain).expect("hash");

        let record = TokenRecord {
            id: "test-managed-id".to_string(),
            name: "test-managed".to_string(),
            hash,
            created_at: "2024-01-01T00:00:00Z".to_string(),
            last_used: None,
            revoked: false,
            prefix: Some(prefix),
        };
        db.insert_token(&record).expect("insert managed token");

        let config = Arc::new(ServeConfig {
            token: "admin-token".to_string(),
            db_path: ":memory:".to_string(),
            bind: "127.0.0.1:0".to_string(),
            base_url: "http://localhost".to_string(),
            default_theme: "clean".to_string(),
            max_size: 1_048_576,
            webhook_url: None,
            webhook_secret: None,
            reaper_interval: 3600,
        });
        let state = AppState { db, config };
        let router = Router::new()
            .route(
                "/api/v1/documents",
                post(crate::handlers::post_document).get(crate::handlers::list_documents),
            )
            .route(
                "/api/v1/documents/:slug",
                get(crate::handlers::get_agent)
                    .put(crate::handlers::put_document)
                    .delete(crate::handlers::delete_document),
            )
            .with_state(state);
        (router, managed_plain.to_string())
    }

    /// Managed token: correct plaintext is accepted by check_auth via prefix lookup.
    #[tokio::test]
    async fn test_managed_token_auth_accepted() {
        let (app, managed_token) = test_app_with_managed_token();

        // First publish with admin token so there's a document to fetch.
        let slug = publish_doc(app.clone(), "admin-token", "managed-test", "# Hello").await;

        // Now GET with managed token.
        let req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/documents/{slug}"))
            .header("Authorization", format!("Bearer {managed_token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK,
            "managed token should be accepted by prefix lookup + argon2 verify");
    }

    /// Wrong token with same prefix: prefix matches DB record but argon2 rejects it.
    #[tokio::test]
    async fn test_managed_token_wrong_value_rejected() {
        let (app, managed_token) = test_app_with_managed_token();

        // Construct a token with the same 8-char prefix but different suffix.
        let wrong_token = format!("{}X_WRONG", &managed_token[..8]);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/documents")
            .header("Authorization", format!("Bearer {wrong_token}"))
            .header("content-type", "text/markdown")
            .body(Body::from("# Test"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED,
            "token with matching prefix but wrong value must be rejected");
    }

    /// Admin token still works independently of managed token path.
    #[tokio::test]
    async fn test_admin_token_still_works_with_managed_tokens_present() {
        let (app, _) = test_app_with_managed_token();

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/documents")
            .header("Authorization", "Bearer admin-token")
            .header("content-type", "text/markdown")
            .body(Body::from("# Admin Test"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED,
            "admin TWOFOLD_TOKEN must still work when managed tokens exist");
    }

    /// No token: 401 immediately.
    #[tokio::test]
    async fn test_no_token_returns_401() {
        let (app, _) = test_app_with_managed_token();

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/documents")
            .header("content-type", "text/markdown")
            .body(Body::from("# No Auth"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED,
            "missing token must return 401");
    }

    /// Revoked managed token: prefix lookup finds the record, but argon2 passes,
    /// yet it should be excluded by `WHERE revoked = 0`.
    #[tokio::test]
    async fn test_revoked_managed_token_rejected() {
        use crate::db::{Db, TokenRecord};
        use crate::config::ServeConfig;

        let db = Db::open(":memory:").expect("in-memory db");
        let managed_plain = "tf_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let prefix: String = managed_plain.chars().take(8).collect();
        let hash = hash_password(managed_plain).expect("hash");

        // Insert as revoked.
        let record = TokenRecord {
            id: "revoked-id".to_string(),
            name: "revoked-token".to_string(),
            hash,
            created_at: "2024-01-01T00:00:00Z".to_string(),
            last_used: None,
            revoked: true,   // already revoked
            prefix: Some(prefix),
        };
        db.insert_token(&record).expect("insert revoked token");

        let config = Arc::new(ServeConfig {
            token: "admin-token".to_string(),
            db_path: ":memory:".to_string(),
            bind: "127.0.0.1:0".to_string(),
            base_url: "http://localhost".to_string(),
            default_theme: "clean".to_string(),
            max_size: 1_048_576,
            webhook_url: None,
            webhook_secret: None,
            reaper_interval: 3600,
        });
        let state = AppState { db, config };
        let router = Router::new()
            .route(
                "/api/v1/documents",
                post(crate::handlers::post_document).get(crate::handlers::list_documents),
            )
            .with_state(state);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/documents")
            .header("Authorization", format!("Bearer {managed_plain}"))
            .header("content-type", "text/markdown")
            .body(Body::from("# Revoked Test"))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED,
            "revoked token must not authenticate");
    }
}
