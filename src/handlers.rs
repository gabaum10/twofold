use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use askama::Template;
use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    Form, Json,
};
use comrak::{markdown_to_html, Options};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::{
    config::ServeConfig,
    db::{AuditEntry, Db, DocumentRecord},
    highlight,
    parser::{extract_frontmatter, extract_title, parse_document, parse_expiry, validate_slug},
    rate_limit::{RateLimitStore, ReadRateLimit, WriteRateLimit},
    webhook,
};

/// URL-safe slug alphabet: alphanumeric + hyphen.
const SLUG_ALPHABET: [char; 63] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
    'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B',
    'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
    'V', 'W', 'X', 'Y', 'Z', '-',
];

// ── Application Error ────────────────────────────────────────────────────────

/// Unified error type with IntoResponse impl.
/// Replaces inline error tuples throughout handlers.
#[derive(Debug)]
pub enum AppError {
    Unauthorized,
    Forbidden,
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
            AppError::Forbidden => (StatusCode::FORBIDDEN, "Forbidden".to_string()),
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

/// In-flight authorization code record for the OAuth Authorization Code flow.
#[derive(Clone)]
pub struct AuthCodeRecord {
    pub client_id: String,
    pub redirect_uri: String,
    pub expires_at: String, // ISO 8601 UTC
    pub code_challenge: String,
    pub resource: Option<String>,
    pub scope: Option<String>,
}

/// In-memory access token record issued via public-client OAuth flows.
#[derive(Clone)]
#[allow(dead_code)] // fields stored for future access policy enforcement
pub struct AccessTokenRecord {
    pub client_id: String,
    pub scope: Option<String>,
    pub expires_at: String, // ISO 8601 UTC
}

/// Dynamically-registered OAuth client record (POST /oauth/register).
#[derive(Clone)]
#[allow(dead_code)] // fields stored for future access policy enforcement
pub struct OAuthClientRecord {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub token_endpoint_auth_method: String,
    /// RFC 3339 timestamp of registration — used by the 24-hour expiry sweep.
    pub created_at: String,
}

/// Active refresh token record.
#[derive(Clone)]
#[allow(dead_code)] // fields stored for future access policy enforcement
pub struct RefreshTokenRecord {
    pub client_id: String,
    pub access_token: String,
    pub scope: Option<String>,
    pub expires_at: String,
}

/// Shared application state injected into all handlers via axum State extractor.
#[derive(Clone)]
#[allow(dead_code)] // rate_limit accessed via axum Extension layer, not directly on AppState
pub struct AppState {
    pub db: Db,
    pub config: Arc<ServeConfig>,
    pub auth_codes: Arc<Mutex<HashMap<String, AuthCodeRecord>>>,
    pub oauth_clients: Arc<Mutex<HashMap<String, OAuthClientRecord>>>,
    pub refresh_tokens: Arc<Mutex<HashMap<String, RefreshTokenRecord>>>,
    pub access_tokens: Arc<Mutex<HashMap<String, AccessTokenRecord>>>,
    pub rate_limit: Arc<RateLimitStore>,
}

// ── Templates ────────────────────────────────────────────────────────────────

/// Askama template for the human-facing document view (clean theme).
#[derive(Template)]
#[template(path = "document.html")]
struct CleanTemplate<'a> {
    title: &'a str,
    content: &'a str,
    slug: &'a str,
    base_url: &'a str,
    /// When true, toolbar shows "Summary view" instead of "Full detail".
    full_view: bool,
    body_empty: bool,
    expires_at: Option<String>,
    /// First ~150 chars of plain text content for meta description / OpenGraph.
    description: String,
}

/// Dark theme template.
#[derive(Template)]
#[template(path = "dark.html")]
struct DarkTemplate<'a> {
    title: &'a str,
    content: &'a str,
    slug: &'a str,
    base_url: &'a str,
    body_empty: bool,
    expires_at: Option<String>,
    description: String,
}

/// Paper theme template.
#[derive(Template)]
#[template(path = "paper.html")]
struct PaperTemplate<'a> {
    title: &'a str,
    content: &'a str,
    slug: &'a str,
    base_url: &'a str,
    body_empty: bool,
    expires_at: Option<String>,
    description: String,
}

/// Minimal theme template.
#[derive(Template)]
#[template(path = "minimal.html")]
struct MinimalTemplate<'a> {
    title: &'a str,
    content: &'a str,
    slug: &'a str,
    base_url: &'a str,
    body_empty: bool,
    expires_at: Option<String>,
    description: String,
}

/// Hearth theme template.
#[derive(Template)]
#[template(path = "hearth.html")]
struct HearthTemplate<'a> {
    title: &'a str,
    content: &'a str,
    slug: &'a str,
    base_url: &'a str,
    full_view: bool,
    body_empty: bool,
    expires_at: Option<String>,
    description: String,
}

/// Password prompt template.
#[derive(Template)]
#[template(path = "password.html")]
struct PasswordTemplate<'a> {
    slug: &'a str,
    base_url: &'a str,
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
    /// Primary query-param password unlock for password-protected documents.
    /// Named `access_token` to avoid security heuristics in some HTTP clients
    /// (e.g. ChatGPT browsing tool refuses URLs with `?password=`).
    /// `?password=` is accepted as a backward-compatible fallback.
    /// Content negotiation still applies: bot UAs / `Accept: application/json`
    /// get the JSON response; browsers get HTML.
    pub access_token: Option<String>,
    /// Backward-compatible alias for `access_token`. `access_token` takes
    /// precedence if both are present.
    pub password: Option<String>,
}

/// JSON response body for a single document (agent/content-negotiation view).
///
/// Returned when the caller signals `Accept: application/json` or is a known
/// AI crawler, so agents can consume the full document (including agent-layer
/// content) from the same human-facing URL without hitting the API endpoint.
///
/// `content` is retained for backward compatibility (full raw markdown, password
/// stripped from frontmatter).  `human_content` and `agent_content` are parsed
/// splits: human is everything outside agent-marker blocks; agent is the content
/// inside them (None when no agent section exists).
#[derive(Serialize)]
pub struct DocumentResponse {
    pub slug: String,
    pub title: String,
    pub content: String, // full raw markdown, password stripped from frontmatter
    pub human_content: String, // content outside <!-- @agent --> blocks
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_content: Option<String>, // content inside <!-- @agent --> blocks
    pub theme: String,
    pub description: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
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

/// Query parameters for GET /api/v1/audit
#[derive(Deserialize)]
pub struct AuditQuery {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

/// JSON response body for the audit endpoint.
#[derive(Serialize)]
pub struct AuditResponse {
    pub entries: Vec<crate::db::AuditEntry>,
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
    _rl: WriteRateLimit,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    body: Bytes,
) -> Result<Response, AppError> {
    // Auth FIRST — 401 before 400/413
    let token_name = check_auth(&state, &headers).await?;
    let peer_addr = connect_info.map(|c| c.0.ip().to_string());

    // Body validation
    if body.is_empty() {
        return Err(AppError::BadRequest(
            "Request body must not be empty".to_string(),
        ));
    }

    let raw_content = std::str::from_utf8(&body)
        .map_err(|_| AppError::BadRequest("Request body must be valid UTF-8".to_string()))?
        .to_string();

    // Parse frontmatter
    let fm_result = extract_frontmatter(&raw_content).map_err(AppError::BadRequest)?;

    let meta = fm_result.meta.unwrap_or_default();
    let body_text = &fm_result.body;

    // Determine slug
    let slug = if let Some(ref custom_slug) = meta.slug {
        validate_slug(custom_slug).map_err(AppError::BadRequest)?;
        custom_slug.clone()
    } else {
        nanoid::nanoid!(10, &SLUG_ALPHABET)
    };

    // Determine title: frontmatter > H1 > slug
    let title = meta
        .title
        .unwrap_or_else(|| extract_title(body_text, &slug));

    // Determine theme
    let theme = meta
        .theme
        .unwrap_or_else(|| state.config.default_theme.clone());

    // Parse expiry
    let now = chrono_now();
    let expires_at = match meta.expiry.as_deref() {
        Some(exp) => {
            let seconds = parse_expiry(exp).map_err(AppError::BadRequest)?;
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

    // Insert (handle slug collision).
    // On a random-slug collision: retry once with a new slug and carry the final
    // slug forward so the single audit write below uses the correct value.
    let final_doc = match state.db.insert_document(&doc) {
        Ok(()) => doc,
        Err(e) if is_unique_violation(&e) => {
            // Custom slug collision -> 409 Conflict
            if meta.slug.is_some() {
                return Err(AppError::Conflict(format!(
                    "Slug '{}' is already in use",
                    slug
                )));
            }
            // Random slug collision (extremely rare) -> retry once
            let new_slug = nanoid::nanoid!(10, &SLUG_ALPHABET);
            let retry_doc = DocumentRecord {
                id: new_slug.clone(),
                slug: new_slug.clone(),
                ..doc
            };
            state.db.insert_document(&retry_doc).map_err(|e2| {
                tracing::error!(error = %e2, "Slug collision retry failed");
                AppError::Internal("Failed to allocate unique slug".to_string())
            })?;
            retry_doc
        }
        Err(e) => return Err(AppError::from(e)),
    };

    // Response — uses final_doc.slug so collision-retry path gets the correct slug.
    let base = state.config.base_url.trim_end_matches('/');
    let response = CreateResponse {
        url: format!("{base}/{}", final_doc.slug),
        slug: final_doc.slug.clone(),
        api_url: format!("{base}/api/v1/documents/{}", final_doc.slug),
        title: final_doc.title.clone(),
        description: final_doc.description.clone(),
        created_at: final_doc.created_at.clone(),
        expires_at: final_doc.expires_at.clone(),
    };

    // Dispatch webhook fire-and-forget AFTER building response.
    // Webhook failure never affects the 201 response.
    if let Some(ref wh_url) = state.config.webhook_url {
        webhook::dispatch_webhook(
            wh_url.clone(),
            state.config.webhook_secret.clone(),
            "document.created",
            now.clone(),
            webhook::WebhookDocument {
                slug: final_doc.slug.clone(),
                title: final_doc.title.clone(),
                url: response.url.clone(),
                api_url: response.api_url.clone(),
            },
        );
    }

    // Single audit write site — after slug-collision branch resolves, using the
    // final slug and a fresh timestamp. Fire-and-forget.
    let ip_address = extract_client_ip(&headers, peer_addr.as_deref());
    let audit_entry = AuditEntry {
        id: nanoid::nanoid!(10),
        timestamp: chrono_now(),
        action: "create".to_string(),
        slug: final_doc.slug.clone(),
        token_name,
        ip_address,
    };
    if let Err(e) = state.db.insert_audit_entry(&audit_entry) {
        tracing::error!(error = %e, "Failed to write audit entry");
    }

    Ok((StatusCode::CREATED, Json(response)).into_response())
}

// ── PUT /api/v1/documents/:slug ──────────────────────────────────────────────

/// Handle document update.
pub async fn put_document(
    State(state): State<AppState>,
    _rl: WriteRateLimit,
    Path(slug): Path<String>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    body: Bytes,
) -> Result<Response, AppError> {
    // Auth first
    let token_name = check_auth(&state, &headers).await?;
    let peer_addr = connect_info.map(|c| c.0.ip().to_string());

    // Body validation
    if body.is_empty() {
        return Err(AppError::BadRequest(
            "Request body must not be empty".to_string(),
        ));
    }

    let raw_content = std::str::from_utf8(&body)
        .map_err(|_| AppError::BadRequest("Request body must be valid UTF-8".to_string()))?
        .to_string();

    // Check document exists and is not expired
    let existing = state.db.get_by_slug(&slug)?.ok_or(AppError::NotFound)?;

    if is_expired(&existing) {
        return Err(AppError::Gone);
    }

    // Parse frontmatter
    let fm_result = extract_frontmatter(&raw_content).map_err(AppError::BadRequest)?;

    let meta = fm_result.meta.unwrap_or_default();
    let body_text = &fm_result.body;

    // Title: frontmatter > H1 > slug (slug from URL, NOT frontmatter)
    let title = meta
        .title
        .unwrap_or_else(|| extract_title(body_text, &slug));

    // Theme
    let theme = meta
        .theme
        .unwrap_or_else(|| state.config.default_theme.clone());

    // Expiry: None = keep existing, Some("") = clear, Some(value) = set new
    let now = chrono_now();
    let expires_at = match meta.expiry.as_deref() {
        Some(exp) if !exp.is_empty() => {
            let seconds = parse_expiry(exp).map_err(AppError::BadRequest)?;
            Some(add_seconds_to_now(&now, seconds))
        }
        Some(_) => None,                     // empty string = clear
        None => existing.expires_at.clone(), // absent = preserve
    };

    // Password: None = keep existing, Some("") = clear, Some(value) = set new
    let password_hash = match meta.password.as_deref() {
        Some(pw) if !pw.is_empty() => Some(hash_password(pw)?),
        Some(_) => None,                   // empty string = clear
        None => existing.password.clone(), // absent = preserve
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
            now.clone(),
            webhook::WebhookDocument {
                slug: slug.clone(),
                title: updated_doc.title.clone(),
                url: response.url.clone(),
                api_url: response.api_url.clone(),
            },
        );
    }

    // Audit entry — fire-and-forget.
    let ip_address = extract_client_ip(&headers, peer_addr.as_deref());
    let audit_entry = AuditEntry {
        id: nanoid::nanoid!(10),
        timestamp: now,
        action: "update".to_string(),
        slug: slug.clone(),
        token_name,
        ip_address,
    };
    if let Err(e) = state.db.insert_audit_entry(&audit_entry) {
        tracing::error!(error = %e, "Failed to write audit entry");
    }

    Ok((StatusCode::OK, Json(response)).into_response())
}

// ── DELETE /api/v1/documents/:slug ───────────────────────────────────────────

/// Handle document deletion.
pub async fn delete_document(
    State(state): State<AppState>,
    _rl: WriteRateLimit,
    Path(slug): Path<String>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
) -> Result<Response, AppError> {
    // Auth first
    let token_name = check_auth(&state, &headers).await?;
    let peer_addr = connect_info.map(|c| c.0.ip().to_string());

    // Check document exists — capture title/slug for webhook before delete.
    let existing = state.db.get_by_slug(&slug)?.ok_or(AppError::NotFound)?;

    // Expired documents: still delete them (cleanup), return 204
    // Non-expired: normal delete, return 204.
    // We delete regardless of expiry status.

    state.db.delete_by_slug(&slug)?;

    let now = chrono_now();

    // Webhook: document.deleted — dispatched after successful delete.
    // Metadata captured from existing record before deletion.
    if let Some(ref wh_url) = state.config.webhook_url {
        let base = state.config.base_url.trim_end_matches('/');
        webhook::dispatch_webhook(
            wh_url.clone(),
            state.config.webhook_secret.clone(),
            "document.deleted",
            now.clone(),
            webhook::WebhookDocument {
                slug: existing.slug.clone(),
                title: existing.title.clone(),
                url: format!("{base}/{}", existing.slug),
                api_url: format!("{base}/api/v1/documents/{}", existing.slug),
            },
        );
    }

    // Audit entry — fire-and-forget.
    let ip_address = extract_client_ip(&headers, peer_addr.as_deref());
    let audit_entry = AuditEntry {
        id: nanoid::nanoid!(10),
        timestamp: now,
        action: "delete".to_string(),
        slug: slug.clone(),
        token_name,
        ip_address,
    };
    if let Err(e) = state.db.insert_audit_entry(&audit_entry) {
        tracing::error!(error = %e, "Failed to write audit entry");
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
    _rl: WriteRateLimit,
    headers: HeaderMap,
    Query(params): Query<ListQuery>,
) -> Result<Response, AppError> {
    check_auth(&state, &headers).await?;

    // Default limit 20, max 100. Cap is enforced in db::list_documents.
    let limit = params.limit.unwrap_or(20);
    let offset = params.offset.unwrap_or(0);

    let (documents, total) = state
        .db
        .list_documents(limit, offset)
        .map_err(AppError::from)?;

    // Report the effective (capped) limit in the response.
    let effective_limit = limit.min(100);

    Ok(Json(ListResponse {
        documents,
        total,
        limit: effective_limit,
        offset,
    })
    .into_response())
}

// ── GET /api/v1/audit ────────────────────────────────────────────────────────

/// List audit log entries with pagination.
///
/// Admin-only: only the master TWOFOLD_TOKEN can read audit logs.
/// Managed tokens and OAuth tokens receive 403 Forbidden.
/// Default limit 20, max 100. Newest first.
pub async fn list_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<AuditQuery>,
) -> Result<Response, AppError> {
    let identity = check_auth(&state, &headers).await?;
    if identity != "admin" {
        return Err(AppError::Forbidden);
    }

    let limit = params.limit.unwrap_or(20);
    let offset = params.offset.unwrap_or(0);

    let (entries, total) = state
        .db
        .list_audit_entries(limit, offset)
        .map_err(AppError::from)?;

    let effective_limit = limit.min(100);

    Ok(Json(AuditResponse {
        entries,
        total,
        limit: effective_limit,
        offset,
    })
    .into_response())
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
pub async fn serve_openapi_yaml(_rl: ReadRateLimit) -> impl IntoResponse {
    // include_str! embeds the file at compile time. The path is relative to src/.
    let yaml = include_str!("../docs/openapi.yaml");
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "application/yaml; charset=utf-8",
        )],
        yaml,
    )
}

/// Serve the OpenAPI spec as JSON.
///
/// Converted from YAML at first call, cached via OnceLock.
/// serde_yaml → serde_json at startup eliminates repeated conversion cost.
pub async fn serve_openapi_json(_rl: ReadRateLimit) -> impl IntoResponse {
    use std::sync::OnceLock;
    static OPENAPI_JSON: OnceLock<String> = OnceLock::new();

    let json = OPENAPI_JSON.get_or_init(|| {
        let yaml = include_str!("../docs/openapi.yaml");
        match serde_yaml::from_str::<serde_json::Value>(yaml) {
            Ok(val) => serde_json::to_string(&val)
                .unwrap_or_else(|e| format!("{{\"error\":\"JSON serialization failed: {e}\"}}")),
            Err(e) => format!("{{\"error\":\"YAML parse failed: {e}\"}}"),
        }
    });

    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "application/json; charset=utf-8",
        )],
        json.as_str(),
    )
}

// ── GET /icon.png and GET /favicon.ico ──────────────────────────────────────

/// Serve the Twofold icon. Embedded at compile time; no runtime file I/O.
/// The file is a JPEG served under the /icon.png path for URL stability.
pub async fn serve_icon() -> impl IntoResponse {
    let bytes = include_bytes!("../assets/icon.jpg");
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "image/jpeg")],
        bytes.as_ref(),
    )
}

/// Serve favicon — redirect to /icon.png.
pub async fn serve_favicon() -> impl IntoResponse {
    Redirect::permanent("/icon.png")
}

// ── Content negotiation helpers ──────────────────────────────────────────────

/// Returns true if the Accept header expresses a preference for JSON.
///
/// Matches any Accept value that contains `application/json`, including
/// quality-factored lists such as `application/json, */*;q=0.5`.
fn accept_prefers_json(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("application/json"))
        .unwrap_or(false)
}

/// Returns true if the Accept header expresses a preference for Markdown.
///
/// Matches `text/markdown` in any position in the Accept header value.
fn accept_prefers_markdown(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("text/markdown"))
        .unwrap_or(false)
}

/// Known AI crawler User-Agent substrings (case-insensitive).
const KNOWN_BOT_AGENTS: &[&str] = &[
    "gptbot",
    "chatgpt-user",
    "claudebot",
    "claude-user",
    "google-extended",
    "googlebot",
    "bingbot",
    "perplexitybot",
    "anthropic",
    "google-agent",
];

/// Returns true if the User-Agent header matches a known AI crawler.
fn is_known_bot(headers: &HeaderMap) -> bool {
    let ua = match headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
    {
        Some(s) => s.to_lowercase(),
        None => return false,
    };
    KNOWN_BOT_AGENTS.iter().any(|bot| ua.contains(bot))
}

/// Strip the `password:` line from YAML frontmatter in raw content.
///
/// Only removes lines inside the opening `---` ... closing `---` block.
/// Does not modify content that has no frontmatter or no password field.
/// Returns a new String; the stored document is never modified.
fn strip_password_from_content(raw: &str) -> String {
    let lines: Vec<&str> = raw.lines().collect();

    // Must start with `---` to have frontmatter.
    if lines.is_empty() || lines[0].trim() != "---" {
        return raw.to_string();
    }

    // Find closing `---`.
    let close_idx = match lines
        .iter()
        .enumerate()
        .skip(1)
        .find(|(_, l)| l.trim() == "---")
    {
        Some((i, _)) => i,
        None => return raw.to_string(),
    };

    // Rebuild lines, dropping any `password: ...` line inside the fence.
    let filtered: Vec<&str> = lines
        .iter()
        .enumerate()
        .filter(|(i, line)| {
            // Only strip inside the frontmatter block (lines 1..close_idx).
            if *i >= 1 && *i < close_idx {
                let trimmed = line.trim_start();
                !trimmed.starts_with("password:")
            } else {
                true
            }
        })
        .map(|(_, line)| *line)
        .collect();

    filtered.join("\n")
}

/// Build the `DocumentResponse` JSON reply for agent/content-negotiation paths.
///
/// Used by `get_human` for JSON content-negotiation responses.
fn build_json_agent_response(doc: &crate::db::DocumentRecord) -> Response {
    // Strip password from the content that goes into the response.
    let safe_content = strip_password_from_content(&doc.raw_content);

    // Split human vs agent sections using the same parser the browser render uses.
    let parsed = parse_document(&safe_content, &doc.slug);

    let body = DocumentResponse {
        slug: doc.slug.clone(),
        title: doc.title.clone(),
        content: safe_content,
        human_content: parsed.human,
        agent_content: parsed.agent,
        theme: doc.theme.clone(),
        description: doc.description.clone(),
        created_at: doc.created_at.clone(),
        expires_at: doc.expires_at.clone(),
    };
    (StatusCode::OK, Json(body)).into_response()
}

// ── GET /:slug (human view) ──────────────────────────────────────────────────

/// Handle human view and raw-shortcut view.
///
/// Without `?raw=1`: renders the human corpus as themed HTML.
/// With `?raw=1`: returns the full raw source.
/// Password-protected documents show a password prompt.
///
/// Content negotiation (checked after expiry/password):
/// - `Accept: application/json` → full `DocumentResponse` JSON (agent layer included)
/// - `Accept: text/markdown` → raw source markdown
/// - Known AI crawler User-Agent with no Accept preference → JSON
/// - Everything else → themed HTML (existing behaviour)
pub async fn get_human(
    State(state): State<AppState>,
    _rl: ReadRateLimit,
    Path(slug): Path<String>,
    Query(params): Query<SlugQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    // .md suffix handling: `/:slug` catches `/my-doc.md` with slug = "my-doc.md".
    // Strip the suffix and serve raw markdown (same as ?raw=1).
    // This runs before the DB lookup so the bare slug is used throughout.
    let (slug, force_markdown) = if let Some(bare) = slug.strip_suffix(".md") {
        (bare.to_string(), true)
    } else {
        (slug, false)
    };

    let doc = match state.db.get_by_slug(&slug)? {
        Some(d) => d,
        None => return Ok(not_found_response()),
    };

    // Expiry check (410 takes priority over password)
    if is_expired(&doc) {
        return Ok(gone_response());
    }

    // Password check (if document is protected)
    if let Some(stored_hash) = &doc.password {
        // First: query-param unlock — ?access_token=X (or legacy ?password=X) works for agents
        // and direct links.  access_token takes precedence; password is a backward-compat fallback.
        let query_provided = params
            .access_token
            .as_deref()
            .or(params.password.as_deref());
        let query_pw_valid = if let Some(provided) = query_provided {
            let provided_owned = provided.to_string();
            let hash_owned = stored_hash.clone();
            tokio::task::spawn_blocking(move || verify_password(&provided_owned, &hash_owned))
                .await
                .map_err(|e| AppError::Internal(format!("Auth task failed: {e}")))?
        } else {
            false
        };

        // Fall back to cookie-based auth (post-form-unlock session).
        if !query_pw_valid && !is_password_authed(&headers, &slug, &state.config.token) {
            let template = PasswordTemplate {
                slug: &slug,
                base_url: state.config.base_url.trim_end_matches('/'),
                error: None,
            };
            return Ok(Html(
                template
                    .render()
                    .map_err(|e| AppError::Internal(format!("Template error: {e}")))?,
            )
            .into_response());
        }
    }

    // .md suffix → serve raw markdown immediately.
    if force_markdown {
        return Ok(markdown_response(&doc.raw_content));
    }

    // ?raw=1 -> return full source
    if params.raw.as_deref() == Some("1") {
        return Ok(markdown_response(&doc.raw_content));
    }

    // Content negotiation: Accept header wins over User-Agent.
    //
    // Priority:
    //   1. Accept: application/json  → JSON  (agent content)
    //   2. Accept: text/markdown     → raw markdown
    //   3. Accept: text/html         → HTML  (browser dev-inspect with bot UA)
    //   4. No/neutral Accept + bot User-Agent → JSON
    //   5. Everything else           → themed HTML (default)
    if accept_prefers_json(&headers) {
        return Ok(build_json_agent_response(&doc));
    }
    if accept_prefers_markdown(&headers) {
        return Ok(markdown_response(&doc.raw_content));
    }
    // Only check the bot UA when the client has NOT declared a preference for HTML.
    // A browser dev-inspecting via a bot UA will send Accept: text/html; honour it.
    let accept_explicitly_html = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("text/html"))
        .unwrap_or(false);
    if !accept_explicitly_html && is_known_bot(&headers) {
        return Ok(build_json_agent_response(&doc));
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
    let base_url = state.config.base_url.trim_end_matches('/').to_string();
    let base_url_clone = base_url.clone();

    let html_result = tokio::task::spawn_blocking(move || {
        let fm_result = extract_frontmatter(&raw_content).unwrap_or_else(|_| {
            crate::parser::FrontmatterResult {
                meta: None,
                body: raw_content.clone(),
            }
        });

        let parse_result = parse_document(&fm_result.body, &slug_owned);
        let rendered_html = render_markdown(&parse_result.human);
        render_themed_sync(
            &title,
            &rendered_html,
            &slug_owned,
            &theme,
            &base_url_clone,
            false,
            expires_at,
        )
    })
    .await
    .map_err(|e| AppError::Internal(format!("Render task failed: {e}")))?;

    // Add Link header pointing to the JSON API endpoint.
    let link_header = format!(
        "<{base_url}/api/v1/documents/{slug}>; rel=\"alternate\"; type=\"application/json\"",
    );
    let html_response = html_result?;
    let mut response = html_response.into_response();
    response.headers_mut().insert(
        axum::http::header::LINK,
        axum::http::HeaderValue::from_str(&link_header)
            .unwrap_or_else(|_| axum::http::HeaderValue::from_static("")),
    );
    Ok(response)
}

// ── POST /:slug/unlock ───────────────────────────────────────────────────────

/// Handle password verification and cookie setting.
pub async fn post_unlock(
    State(state): State<AppState>,
    _rl: ReadRateLimit,
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
        )
            .into_response())
    } else {
        // Wrong password — show form again with error
        let template = PasswordTemplate {
            slug: &slug,
            base_url: state.config.base_url.trim_end_matches('/'),
            error: Some("Incorrect password"),
        };
        Ok(Html(
            template
                .render()
                .map_err(|e| AppError::Internal(format!("Template error: {e}")))?,
        )
        .into_response())
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
    _rl: ReadRateLimit,
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
    if doc.password.is_some() && !is_password_authed(&headers, &slug, &state.config.token) {
        let template = PasswordTemplate {
            slug: &slug,
            base_url: state.config.base_url.trim_end_matches('/'),
            error: None,
        };
        return Ok(Html(
            template
                .render()
                .map_err(|e| AppError::Internal(format!("Template error: {e}")))?,
        )
        .into_response());
    }

    // Same spawn_blocking pattern as get_human — syntect needs a larger stack.
    let raw_content = doc.raw_content.clone();
    let title = doc.title.clone();
    let theme = doc.theme.clone();
    let slug_owned = slug.clone();
    let expires_at = doc.expires_at.clone();
    let base_url = state.config.base_url.trim_end_matches('/').to_string();
    let base_url_clone = base_url.clone();

    let html_result = tokio::task::spawn_blocking(move || {
        let fm_result = extract_frontmatter(&raw_content).unwrap_or_else(|_| {
            crate::parser::FrontmatterResult {
                meta: None,
                body: raw_content.clone(),
            }
        });

        let stripped = strip_marker_comments(&fm_result.body);
        let rendered_html = render_markdown(&stripped);
        render_themed_sync(
            &title,
            &rendered_html,
            &slug_owned,
            &theme,
            &base_url_clone,
            true,
            expires_at,
        )
    })
    .await
    .map_err(|e| AppError::Internal(format!("Render task failed: {e}")))?;

    // Add Link header pointing to the JSON API endpoint.
    let link_header = format!(
        "<{base_url}/api/v1/documents/{slug}>; rel=\"alternate\"; type=\"application/json\"",
    );
    let html_response = html_result?;
    let mut response = html_response.into_response();
    response.headers_mut().insert(
        axum::http::header::LINK,
        axum::http::HeaderValue::from_str(&link_header)
            .unwrap_or_else(|_| axum::http::HeaderValue::from_static("")),
    );
    Ok(response)
}

// ── GET /api/v1/documents/:slug (agent view) ─────────────────────────────────

/// Query parameters for GET /api/v1/documents/:slug (agent view).
#[derive(Deserialize)]
pub struct AgentQuery {
    /// Primary query-param password. Named `access_token` to avoid security
    /// heuristics in some HTTP clients. `?password=` accepted as fallback.
    pub access_token: Option<String>,
    /// Backward-compatible alias for `access_token`.
    pub password: Option<String>,
}

/// Return the full raw source markdown.
///
/// Password-protected documents require the correct password as a query
/// parameter (`?access_token=<value>` or legacy `?password=<value>`).
/// Returns 401 with a JSON error body if the document is protected and
/// the password is missing or incorrect.
pub async fn get_agent(
    State(state): State<AppState>,
    _rl: ReadRateLimit,
    Path(slug): Path<String>,
    Query(params): Query<AgentQuery>,
) -> Result<Response, AppError> {
    let doc = state.db.get_by_slug(&slug)?.ok_or(AppError::NotFound)?;

    if is_expired(&doc) {
        return Err(AppError::Gone);
    }

    // Password gate — same argon2 check as the human view.
    // access_token takes precedence; password is a backward-compat fallback.
    if let Some(stored_hash) = &doc.password {
        let provided = params
            .access_token
            .as_deref()
            .or(params.password.as_deref());
        match provided {
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
async fn check_auth(state: &AppState, headers: &HeaderMap) -> Result<String, AppError> {
    let provided = extract_bearer(headers).ok_or(AppError::Unauthorized)?;

    check_auth_token(state, provided).await
}

/// Validate a raw token string against the admin token and managed token store.
///
/// Extracted so that non-HTTP callers (e.g. oauth.rs) can reuse the same
/// verification logic without constructing a HeaderMap.
pub async fn check_auth_token(state: &AppState, provided: &str) -> Result<String, AppError> {
    // Fast path: admin TWOFOLD_TOKEN — constant-time, no argon2.
    if constant_time_eq(provided.as_bytes(), state.config.token.as_bytes()) {
        return Ok("admin".to_string());
    }

    // In-memory access tokens issued to public OAuth clients (UUID tokens).
    // Sweep expired entries on access, then check for a match.
    {
        let now = chrono_now();
        let mut tokens = state
            .access_tokens
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        tokens.retain(|_, v| v.expires_at.as_str() >= now.as_str());
        if tokens.contains_key(provided) {
            return Ok("oauth".to_string());
        }
    }

    // Prefix-based O(1) lookup: use first 8 chars of the provided token
    // to look up the one candidate record, then verify with argon2.
    let prefix: String = provided.chars().take(8).collect();

    let candidate = state
        .db
        .get_token_by_prefix(&prefix)
        .map_err(|_| AppError::Internal("Failed to check tokens".to_string()))?;

    if let Some(token_record) = candidate {
        let provided_owned = provided.to_string();
        let hash_owned = token_record.hash.clone();
        let verified =
            tokio::task::spawn_blocking(move || verify_password(&provided_owned, &hash_owned))
                .await
                .map_err(|e| AppError::Internal(format!("Auth task failed: {e}")))?;

        if verified {
            let now = chrono_now();
            let _ = state.db.touch_token(&token_record.id, &now);
            return Ok(token_record.name.clone());
        }
        // Prefix matched but hash didn't — fall through to legacy check and
        // ultimately return Unauthorized (prefix collision is astronomically rare).
    }

    // Legacy fallback: tokens created before v0.4 have no prefix stored.
    // On a fresh database this query returns 0 rows immediately.
    let legacy_tokens = state
        .db
        .get_legacy_active_tokens()
        .map_err(|_| AppError::Internal("Failed to check tokens".to_string()))?;

    if !legacy_tokens.is_empty() {
        let provided_owned = provided.to_string();
        let result = tokio::task::spawn_blocking(move || {
            for token_record in &legacy_tokens {
                if verify_password(&provided_owned, &token_record.hash) {
                    return Some((token_record.id.clone(), token_record.name.clone()));
                }
            }
            None
        })
        .await
        .map_err(|e| AppError::Internal(format!("Auth task failed: {e}")))?;

        if let Some((id, name)) = result {
            let now = chrono_now();
            let _ = state.db.touch_token(&id, &now);
            return Ok(name);
        }
    }

    Err(AppError::Unauthorized)
}

/// Extract the client IP address for audit logging.
///
/// Priority: X-Forwarded-For (first hop) > peer socket address > "unknown".
///
/// Both paths return bare IPs with no port suffix:
/// - XFF: the extracted value is validated as a parseable IP; if it doesn't
///   parse (e.g. contains a port or is malformed), we fall through to the
///   socket address.
/// - Socket fallback: the IP component is extracted via `.ip()`, stripping the
///   port that `SocketAddr::to_string()` would otherwise include.
pub fn extract_client_ip(headers: &HeaderMap, fallback: Option<&str>) -> String {
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next() {
            let candidate = first.trim();
            if !candidate.is_empty() {
                // Validate that the extracted value actually parses as an IP address.
                // If it doesn't (e.g. it contains a port or is malformed), fall through
                // to the socket address rather than storing a garbage string.
                if candidate.parse::<std::net::IpAddr>().is_ok() {
                    return candidate.to_string();
                }
            }
        }
    }
    // Socket address fallback: strip the port so we store a bare IP.
    if let Some(addr_str) = fallback {
        if let Ok(socket_addr) = addr_str.parse::<std::net::SocketAddr>() {
            return socket_addr.ip().to_string();
        }
        // Fallback string wasn't a valid SocketAddr — use it verbatim if non-empty.
        if !addr_str.is_empty() {
            return addr_str.to_string();
        }
    }
    "unknown".to_string()
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
fn render_themed_sync(
    title: &str,
    content: &str,
    slug: &str,
    theme: &str,
    base_url: &str,
    full_view: bool,
    expires_at: Option<String>,
) -> Result<Response, AppError> {
    // Apply syntax highlighting to the pre-rendered HTML.
    // Dark theme gets dark syntax palette; all others get light.
    let is_dark = theme == "dark";
    let highlighted = highlight::apply_syntax_highlighting(content, is_dark);

    let body_empty = highlighted.trim().is_empty();

    // Compute plain-text excerpt for meta description / OpenGraph.
    // Strip HTML tags from the rendered content, collapse whitespace, truncate at 150 chars.
    let description = plain_text_excerpt(&highlighted, 150);

    let html = match theme {
        "dark" => {
            let t = DarkTemplate {
                title,
                content: &highlighted,
                slug,
                base_url,
                body_empty,
                expires_at,
                description,
            };
            t.render()
        }
        "paper" => {
            let t = PaperTemplate {
                title,
                content: &highlighted,
                slug,
                base_url,
                body_empty,
                expires_at,
                description,
            };
            t.render()
        }
        "minimal" => {
            let t = MinimalTemplate {
                title,
                content: &highlighted,
                slug,
                base_url,
                body_empty,
                expires_at,
                description,
            };
            t.render()
        }
        "hearth" => {
            let t = HearthTemplate {
                title,
                content: &highlighted,
                slug,
                base_url,
                full_view,
                body_empty,
                expires_at,
                description,
            };
            t.render()
        }
        _ => {
            // "clean" or unknown -> default
            let t = CleanTemplate {
                title,
                content: &highlighted,
                slug,
                base_url,
                full_view,
                body_empty,
                expires_at,
                description,
            };
            t.render()
        }
    };

    html.map(|h| Html(h).into_response())
        .map_err(|e| AppError::Internal(format!("Template render error: {e}")))
}

/// Strip HTML tags and extract plain text, collapsing whitespace.
/// Returns up to `max_chars` characters, suitable for meta description tags.
fn plain_text_excerpt(html: &str, max_chars: usize) -> String {
    let mut result = String::with_capacity(html.len().min(512));
    let mut in_tag = false;
    let mut last_was_space = true; // start true so we don't lead with a space

    for ch in html.chars() {
        match ch {
            '<' => {
                in_tag = true;
            }
            '>' => {
                in_tag = false;
                // Treat closing/block tags as whitespace boundaries.
                if !last_was_space {
                    result.push(' ');
                    last_was_space = true;
                }
            }
            _ if in_tag => {}
            '\n' | '\r' | '\t' | ' ' => {
                if !last_was_space {
                    result.push(' ');
                    last_was_space = true;
                }
            }
            _ => {
                result.push(ch);
                last_was_space = false;
            }
        }
    }

    let trimmed = result.trim().to_string();

    // Truncate at max_chars on a char boundary, appending ellipsis if cut.
    if trimmed.chars().count() <= max_chars {
        trimmed
    } else {
        let cut: String = trimmed.chars().take(max_chars).collect();
        format!("{cut}...")
    }
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
    use argon2::{
        password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
        Argon2,
    };

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
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

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
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let cookie_name = format!("twofold_auth_{}", slug);

    let cookies = match headers.get("cookie").and_then(|v| v.to_str().ok()) {
        Some(c) => c,
        None => return false,
    };

    // Find our cookie in the cookie string
    let cookie_value = cookies.split(';').map(|s| s.trim()).find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        if name == cookie_name {
            Some(value)
        } else {
            None
        }
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

    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::{get, post},
        Router,
    };
    use std::sync::Arc;
    use tower::ServiceExt;

    /// Build a minimal test router backed by an in-memory database.
    fn test_app(token: &str) -> Router {
        let db = crate::db::Db::open(":memory:").expect("in-memory db");
        let config = crate::config::ServeConfig {
            token: token.to_string(),
            db_path: ":memory:".to_string(),
            bind: "127.0.0.1:0".to_string(),
            base_url: "http://localhost".to_string(),
            default_theme: "clean".to_string(),
            max_size: 1_048_576,
            webhook_url: None,
            webhook_secret: None,
            reaper_interval: 3600,
            rate_limit_read: 1000,
            rate_limit_write: 1000,
            rate_limit_window: 60,
        };
        let rate_limit = crate::rate_limit::RateLimitStore::new(&config);
        let state = AppState {
            db,
            config: Arc::new(config),
            auth_codes: Arc::new(Mutex::new(HashMap::new())),
            oauth_clients: Arc::new(Mutex::new(HashMap::new())),
            refresh_tokens: Arc::new(Mutex::new(HashMap::new())),
            access_tokens: Arc::new(Mutex::new(HashMap::new())),
            rate_limit: rate_limit.clone(),
        };
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
            .layer(axum::Extension(rate_limit))
            .with_state(state)
    }

    /// Build a test router that includes both API routes AND human-facing routes.
    ///
    /// Used for testing themed error pages (404/410) from the human view.
    fn test_app_full(token: &str) -> Router {
        let db = crate::db::Db::open(":memory:").expect("in-memory db");
        let config = crate::config::ServeConfig {
            token: token.to_string(),
            db_path: ":memory:".to_string(),
            bind: "127.0.0.1:0".to_string(),
            base_url: "http://localhost".to_string(),
            default_theme: "clean".to_string(),
            max_size: 1_048_576,
            webhook_url: None,
            webhook_secret: None,
            reaper_interval: 3600,
            rate_limit_read: 1000,
            rate_limit_write: 1000,
            rate_limit_window: 60,
        };
        let rate_limit = crate::rate_limit::RateLimitStore::new(&config);
        let state = AppState {
            db,
            config: Arc::new(config),
            auth_codes: Arc::new(Mutex::new(HashMap::new())),
            oauth_clients: Arc::new(Mutex::new(HashMap::new())),
            refresh_tokens: Arc::new(Mutex::new(HashMap::new())),
            access_tokens: Arc::new(Mutex::new(HashMap::new())),
            rate_limit: rate_limit.clone(),
        };
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
            .layer(axum::Extension(rate_limit))
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

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
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
        let config = crate::config::ServeConfig {
            token: token.to_string(),
            db_path: ":memory:".to_string(),
            bind: "127.0.0.1:0".to_string(),
            base_url: "http://localhost".to_string(),
            default_theme: "clean".to_string(),
            max_size: 1_048_576,
            webhook_url: None,
            webhook_secret: None,
            reaper_interval: 3600,
            rate_limit_read: 1000,
            rate_limit_write: 1000,
            rate_limit_window: 60,
        };

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
        db.insert_document(&expired_doc)
            .expect("insert expired doc");

        let rate_limit = crate::rate_limit::RateLimitStore::new(&config);
        let state = AppState {
            db,
            config: Arc::new(config),
            auth_codes: Arc::new(Mutex::new(HashMap::new())),
            oauth_clients: Arc::new(Mutex::new(HashMap::new())),
            refresh_tokens: Arc::new(Mutex::new(HashMap::new())),
            access_tokens: Arc::new(Mutex::new(HashMap::new())),
            rate_limit: rate_limit.clone(),
        };
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
            .layer(axum::Extension(rate_limit))
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

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
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

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
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

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
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
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        json["slug"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn test_put_updates_existing_document() {
        let token = "test-token";
        let app = test_app(token);

        // Publish a document first.
        let slug = publish_doc(
            app.clone(),
            token,
            "my-slug",
            "# Original\nOriginal content.",
        )
        .await;
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

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
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
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let raw = std::str::from_utf8(&body_bytes).unwrap();
        assert!(
            raw.contains("Updated content."),
            "content should reflect PUT body"
        );
        assert!(
            !raw.contains("Original content."),
            "old content should be gone"
        );
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

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
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
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["slug"].as_str().unwrap(), slug);
        assert!(
            json.get("created_at").is_some(),
            "response should include created_at"
        );
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

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
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
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "publish protected doc failed"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
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
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(
            text.contains("Secret content."),
            "body should contain document content"
        );
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
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
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
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
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
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(
            text.contains("Open content."),
            "unprotected doc should be served without password"
        );
    }

    // ── Managed token auth tests ──────────────────────────────────────────────

    /// Build a test router that has a pre-inserted managed token in the DB.
    ///
    /// Returns (Router, plaintext_managed_token). The admin TWOFOLD_TOKEN is set
    /// to "admin-token" so both paths can be exercised separately.
    fn test_app_with_managed_token() -> (Router, String) {
        use crate::config::ServeConfig;
        use crate::db::{Db, TokenRecord};

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

        let config = crate::config::ServeConfig {
            token: "admin-token".to_string(),
            db_path: ":memory:".to_string(),
            bind: "127.0.0.1:0".to_string(),
            base_url: "http://localhost".to_string(),
            default_theme: "clean".to_string(),
            max_size: 1_048_576,
            webhook_url: None,
            webhook_secret: None,
            reaper_interval: 3600,
            rate_limit_read: 10000,
            rate_limit_write: 10000,
            rate_limit_window: 60,
        };
        let rate_limit = crate::rate_limit::RateLimitStore::new(&config);
        let state = AppState {
            db,
            config: Arc::new(config),
            auth_codes: Arc::new(Mutex::new(HashMap::new())),
            oauth_clients: Arc::new(Mutex::new(HashMap::new())),
            refresh_tokens: Arc::new(Mutex::new(HashMap::new())),
            access_tokens: Arc::new(Mutex::new(HashMap::new())),
            rate_limit: rate_limit.clone(),
        };
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
            .layer(axum::Extension(rate_limit))
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
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "managed token should be accepted by prefix lookup + argon2 verify"
        );
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
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "token with matching prefix but wrong value must be rejected"
        );
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
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "admin TWOFOLD_TOKEN must still work when managed tokens exist"
        );
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
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "missing token must return 401"
        );
    }

    /// Revoked managed token: prefix lookup finds the record, but argon2 passes,
    /// yet it should be excluded by `WHERE revoked = 0`.
    #[tokio::test]
    async fn test_revoked_managed_token_rejected() {
        use crate::config::ServeConfig;
        use crate::db::{Db, TokenRecord};

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
            revoked: true, // already revoked
            prefix: Some(prefix),
        };
        db.insert_token(&record).expect("insert revoked token");

        let config = crate::config::ServeConfig {
            token: "admin-token".to_string(),
            db_path: ":memory:".to_string(),
            bind: "127.0.0.1:0".to_string(),
            base_url: "http://localhost".to_string(),
            default_theme: "clean".to_string(),
            max_size: 1_048_576,
            webhook_url: None,
            webhook_secret: None,
            reaper_interval: 3600,
            rate_limit_read: 10000,
            rate_limit_write: 10000,
            rate_limit_window: 60,
        };
        let rate_limit = crate::rate_limit::RateLimitStore::new(&config);
        let state = AppState {
            db,
            config: Arc::new(config),
            auth_codes: Arc::new(Mutex::new(HashMap::new())),
            oauth_clients: Arc::new(Mutex::new(HashMap::new())),
            refresh_tokens: Arc::new(Mutex::new(HashMap::new())),
            access_tokens: Arc::new(Mutex::new(HashMap::new())),
            rate_limit: rate_limit.clone(),
        };
        let router = Router::new()
            .route(
                "/api/v1/documents",
                post(crate::handlers::post_document).get(crate::handlers::list_documents),
            )
            .layer(axum::Extension(rate_limit))
            .with_state(state);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/documents")
            .header("Authorization", format!("Bearer {managed_plain}"))
            .header("content-type", "text/markdown")
            .body(Body::from("# Revoked Test"))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "revoked token must not authenticate"
        );
    }

    // ── Content negotiation tests ─────────────────────────────────────────────

    /// Helper: publish a doc through the full-app router (which includes /:slug).
    async fn publish_doc_full(app: Router, token: &str, slug: &str, content: &str) -> String {
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
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        json["slug"].as_str().unwrap().to_string()
    }

    /// Accept: text/html → returns HTML (existing behaviour unchanged).
    #[tokio::test]
    async fn test_content_neg_html_accept_returns_html() {
        let token = "test-token";
        let app = test_app_full(token);
        let slug = publish_doc_full(app.clone(), token, "cn-html", "# Hello").await;

        let req = Request::builder()
            .method("GET")
            .uri(format!("/{slug}"))
            .header("Accept", "text/html,application/xhtml+xml,*/*;q=0.9")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ct.contains("text/html"), "expected HTML, got {ct}");
    }

    /// Accept: application/json → returns JSON with document fields.
    #[tokio::test]
    async fn test_content_neg_json_accept_returns_json() {
        let token = "test-token";
        let app = test_app_full(token);
        let slug =
            publish_doc_full(app.clone(), token, "cn-json", "# Hello\n\nAgent content.").await;

        let req = Request::builder()
            .method("GET")
            .uri(format!("/{slug}"))
            .header("Accept", "application/json")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ct.contains("application/json"), "expected JSON, got {ct}");
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["slug"].as_str().unwrap(), "cn-json");
        assert!(json["content"].as_str().unwrap().contains("Hello"));
    }

    /// Accept: text/markdown → returns raw markdown source.
    #[tokio::test]
    async fn test_content_neg_markdown_accept_returns_markdown() {
        let token = "test-token";
        let app = test_app_full(token);
        let slug = publish_doc_full(app.clone(), token, "cn-md-accept", "# Markdown test").await;

        let req = Request::builder()
            .method("GET")
            .uri(format!("/{slug}"))
            .header("Accept", "text/markdown")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ct.contains("text/markdown"), "expected markdown, got {ct}");
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = std::str::from_utf8(&bytes).unwrap();
        assert!(
            body.contains("Markdown test"),
            "expected raw markdown in body"
        );
    }

    /// Bot User-Agent with no Accept → returns JSON.
    #[tokio::test]
    async fn test_content_neg_bot_ua_returns_json() {
        let token = "test-token";
        let app = test_app_full(token);
        let slug = publish_doc_full(app.clone(), token, "cn-bot", "# Bot content").await;

        let req = Request::builder()
            .method("GET")
            .uri(format!("/{slug}"))
            .header("User-Agent", "GPTBot/1.0")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            ct.contains("application/json"),
            "expected JSON for bot UA, got {ct}"
        );
    }

    /// Browser Accept + bot User-Agent → Accept wins, returns HTML.
    #[tokio::test]
    async fn test_content_neg_html_accept_beats_bot_ua() {
        let token = "test-token";
        let app = test_app_full(token);
        let slug = publish_doc_full(app.clone(), token, "cn-ua-html", "# Dev inspect").await;

        let req = Request::builder()
            .method("GET")
            .uri(format!("/{slug}"))
            .header("Accept", "text/html")
            .header("User-Agent", "ClaudeBot/1.0")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            ct.contains("text/html"),
            "Accept: text/html should beat bot UA, got {ct}"
        );
    }

    /// GET /:slug.md → returns raw markdown.
    #[tokio::test]
    async fn test_slug_md_route_returns_markdown() {
        let token = "test-token";
        let app = test_app_full(token);
        let slug = publish_doc_full(app.clone(), token, "cn-dotmd", "# Dotmd test").await;

        let req = Request::builder()
            .method("GET")
            .uri(format!("/{slug}.md"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            ct.contains("text/markdown"),
            "expected markdown content-type, got {ct}"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = std::str::from_utf8(&bytes).unwrap();
        assert!(body.contains("Dotmd test"), "expected raw markdown in body");
    }

    // ── Audit log tests ───────────────────────────────────────────────────────

    fn make_test_config(token: &str) -> crate::config::ServeConfig {
        crate::config::ServeConfig {
            token: token.to_string(),
            db_path: ":memory:".to_string(),
            bind: "127.0.0.1:0".to_string(),
            base_url: "http://localhost".to_string(),
            default_theme: "clean".to_string(),
            max_size: 1_048_576,
            webhook_url: None,
            webhook_secret: None,
            reaper_interval: 3600,
            rate_limit_read: 1000,
            rate_limit_write: 1000,
            rate_limit_window: 60,
        }
    }

    fn make_test_state(token: &str) -> (AppState, crate::db::Db) {
        let db = crate::db::Db::open(":memory:").expect("in-memory db");
        let config = make_test_config(token);
        let rate_limit = crate::rate_limit::RateLimitStore::new(&config);
        let state = AppState {
            db: db.clone(),
            config: Arc::new(config),
            auth_codes: Arc::new(Mutex::new(HashMap::new())),
            oauth_clients: Arc::new(Mutex::new(HashMap::new())),
            refresh_tokens: Arc::new(Mutex::new(HashMap::new())),
            access_tokens: Arc::new(Mutex::new(HashMap::new())),
            rate_limit: rate_limit.clone(),
        };
        (state, db)
    }

    fn test_app_with_audit(token: &str) -> Router {
        let (state, _db) = make_test_state(token);
        let rate_limit = state.rate_limit.clone();
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
            .route("/api/v1/audit", get(crate::handlers::list_audit))
            .layer(axum::Extension(rate_limit))
            .with_state(state)
    }

    fn test_app_with_db(token: &str) -> (Router, crate::db::Db) {
        let (state, db) = make_test_state(token);
        let rate_limit = state.rate_limit.clone();
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
            .route("/api/v1/audit", get(crate::handlers::list_audit))
            .layer(axum::Extension(rate_limit))
            .with_state(state);
        (router, db)
    }

    /// Test Db insert_audit_entry and list_audit_entries directly.
    #[test]
    fn test_db_insert_and_list_audit_entries() {
        let db = crate::db::Db::open(":memory:").expect("in-memory db");

        // Empty initially.
        let (entries, total) = db.list_audit_entries(20, 0).expect("list ok");
        assert_eq!(total, 0);
        assert!(entries.is_empty());

        // Insert one entry.
        let entry = crate::db::AuditEntry {
            id: "test001".to_string(),
            timestamp: "2026-05-12T14:00:00Z".to_string(),
            action: "create".to_string(),
            slug: "my-doc".to_string(),
            token_name: "admin".to_string(),
            ip_address: "127.0.0.1".to_string(),
        };
        db.insert_audit_entry(&entry).expect("insert ok");

        let (entries, total) = db.list_audit_entries(20, 0).expect("list ok");
        assert_eq!(total, 1);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, "create");
        assert_eq!(entries[0].slug, "my-doc");
        assert_eq!(entries[0].token_name, "admin");
        assert_eq!(entries[0].ip_address, "127.0.0.1");
    }

    /// check_auth returns "admin" for the master token.
    #[tokio::test]
    async fn test_check_auth_returns_admin_for_master_token() {
        let token = "master-secret-token";
        let app = test_app(token);
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/documents")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "text/markdown")
            .body(Body::from("# Test Doc\nContent."))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // 201 confirms auth passed (token_name "admin" returned internally)
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "master token should authenticate"
        );
    }

    /// check_auth returns token name for managed tokens.
    #[tokio::test]
    async fn test_check_auth_returns_token_name_for_managed_token() {
        let (app, managed_plain) = test_app_with_managed_token();
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/documents")
            .header("Authorization", format!("Bearer {managed_plain}"))
            .header("Content-Type", "text/markdown")
            .body(Body::from("# Managed Token Test\nContent."))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "managed token should authenticate"
        );
    }

    /// GET /api/v1/audit returns 200 with correct JSON shape.
    #[tokio::test]
    async fn test_list_audit_returns_200_with_correct_shape() {
        let token = "test-token";
        let app = test_app_with_audit(token);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/audit")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            json.get("entries").is_some(),
            "response must have 'entries' field"
        );
        assert!(
            json.get("total").is_some(),
            "response must have 'total' field"
        );
        assert!(
            json.get("limit").is_some(),
            "response must have 'limit' field"
        );
        assert!(
            json.get("offset").is_some(),
            "response must have 'offset' field"
        );
        assert_eq!(json["total"].as_u64().unwrap(), 0);
        assert!(json["entries"].as_array().unwrap().is_empty());
    }

    /// GET /api/v1/audit returns 401 without auth token.
    #[tokio::test]
    async fn test_list_audit_requires_auth() {
        let token = "test-token";
        let app = test_app_with_audit(token);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/audit")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "audit endpoint must require auth"
        );
    }

    /// POST /api/v1/documents writes an audit entry.
    #[tokio::test]
    async fn test_post_document_writes_audit_entry() {
        let token = "test-token";
        let (app, db) = test_app_with_db(token);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/documents")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "text/markdown")
            .body(Body::from(
                "---\nslug: audit-test-create\n---\n# Audit Test\nContent.",
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED, "publish failed");

        let (entries, total) = db.list_audit_entries(20, 0).expect("list ok");
        assert_eq!(total, 1, "should have 1 audit entry after create");
        assert_eq!(entries[0].action, "create");
        assert_eq!(entries[0].slug, "audit-test-create");
        assert_eq!(entries[0].token_name, "admin");
    }

    /// DELETE /api/v1/documents/:slug writes an audit entry.
    #[tokio::test]
    async fn test_delete_document_writes_audit_entry() {
        let token = "test-token";
        let (app, db) = test_app_with_db(token);

        // Create first.
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/documents")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "text/markdown")
            .body(Body::from("---\nslug: to-delete\n---\n# Delete Me"))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Delete it.
        let req = Request::builder()
            .method("DELETE")
            .uri("/api/v1/documents/to-delete")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let (entries, total) = db.list_audit_entries(20, 0).expect("list ok");
        assert_eq!(total, 2, "should have 2 audit entries (create + delete)");
        let delete_entry = entries
            .iter()
            .find(|e| e.action == "delete")
            .expect("delete entry");
        assert_eq!(delete_entry.slug, "to-delete");
        assert_eq!(delete_entry.token_name, "admin");
    }

    /// extract_client_ip: X-Forwarded-For takes priority.
    #[test]
    fn test_extract_client_ip_xff_priority() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "10.0.0.1, 192.168.1.1".parse().unwrap());
        let ip = extract_client_ip(&headers, Some("127.0.0.1:12345"));
        assert_eq!(ip, "10.0.0.1", "XFF first value should take priority");
    }

    /// extract_client_ip falls back to socket addr when no XFF.
    /// Port is stripped — only the bare IP is returned.
    #[test]
    fn test_extract_client_ip_fallback_to_socket() {
        let headers = HeaderMap::new();
        let ip = extract_client_ip(&headers, Some("1.2.3.4:5678"));
        assert_eq!(ip, "1.2.3.4", "should strip port and return bare IP");
    }

    /// extract_client_ip returns "unknown" when nothing is available.
    #[test]
    fn test_extract_client_ip_unknown() {
        let headers = HeaderMap::new();
        let ip = extract_client_ip(&headers, None);
        assert_eq!(ip, "unknown");
    }
}
