use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::helpers::extract_client_ip;
use crate::rate_limit::{ReadRateLimit, WriteRateLimit};

// Re-export AppError and AppState so all existing `crate::handlers::{AppError, AppState}`
// imports continue to resolve without modification.
pub use crate::error::AppError;
pub use crate::state::AppState;

// Re-export for callers that still reference this via crate::handlers.
pub use crate::views::strip_password_from_content_pub;

/// URL-safe slug alphabet: alphanumeric + hyphen.
#[allow(dead_code)]
pub const SLUG_ALPHABET: [char; 63] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
    'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B',
    'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
    'V', 'W', 'X', 'Y', 'Z', '-',
];

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
    let principal = check_auth(&state, &headers).await?;
    if !principal.can_write() {
        return Err(AppError::Forbidden);
    }
    let peer_addr = connect_info.map(|c| c.0.ip().to_string());
    let client_ip = extract_client_ip(&headers, peer_addr.as_deref());

    let raw_content = std::str::from_utf8(&body)
        .map_err(|_| AppError::BadRequest("Request body must be valid UTF-8".to_string()))?
        .to_string();

    let req = crate::service::PublishRequest {
        raw_content,
        principal,
        client_ip,
    };

    let result = crate::service::publish(&state.db, &state.config, req).await?;

    let response = CreateResponse {
        url: result.url,
        slug: result.slug,
        api_url: result.api_url,
        title: result.title,
        description: result.description,
        created_at: result.created_at,
        expires_at: result.expires_at,
    };

    Ok((StatusCode::CREATED, Json(response)).into_response())
}

// ── PUT /api/v1/documents/:slug ──────────────────────────────────────────────

/// Handle document update.
///
/// Thin wrapper: extract → auth → service::update → respond.
pub async fn put_document(
    State(state): State<AppState>,
    _rl: WriteRateLimit,
    Path(slug): Path<String>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    body: Bytes,
) -> Result<Response, AppError> {
    let principal = check_auth(&state, &headers).await?;
    if !principal.can_write() {
        return Err(AppError::Forbidden);
    }
    let peer_addr = connect_info.map(|c| c.0.ip().to_string());
    let client_ip = extract_client_ip(&headers, peer_addr.as_deref());

    let raw_content = std::str::from_utf8(&body)
        .map_err(|_| AppError::BadRequest("Request body must be valid UTF-8".to_string()))?
        .to_string();

    let req = crate::service::UpdateRequest {
        raw_content,
        principal,
        client_ip,
    };

    let result = crate::service::update(&state.db, &state.config, &slug, req).await?;

    let response = CreateResponse {
        url: result.url,
        slug: result.slug,
        api_url: result.api_url,
        title: result.title,
        description: result.description,
        created_at: result.created_at,
        expires_at: result.expires_at,
    };

    Ok((StatusCode::OK, Json(response)).into_response())
}

// ── DELETE /api/v1/documents/:slug ───────────────────────────────────────────

/// Handle document deletion.
///
/// Thin wrapper: extract → auth → service::delete → respond.
pub async fn delete_document(
    State(state): State<AppState>,
    _rl: WriteRateLimit,
    Path(slug): Path<String>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
) -> Result<Response, AppError> {
    let principal = check_auth(&state, &headers).await?;
    if !principal.can_write() {
        return Err(AppError::Forbidden);
    }
    let peer_addr = connect_info.map(|c| c.0.ip().to_string());
    let client_ip = extract_client_ip(&headers, peer_addr.as_deref());

    crate::service::delete(&state.db, &state.config, &slug, &principal, &client_ip).await?;

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
    let _principal = check_auth(&state, &headers).await?;

    let limit = params.limit.unwrap_or(20);
    let offset = params.offset.unwrap_or(0);

    let (documents, total) = crate::service::list(&state.db, limit, offset).await?;

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
    let principal = check_auth(&state, &headers).await?;
    if !principal.is_admin() {
        return Err(AppError::Forbidden);
    }

    let limit = params.limit.unwrap_or(20);
    let offset = params.offset.unwrap_or(0);

    let db_clone = state.db.clone();
    let (entries, total) =
        tokio::task::spawn_blocking(move || db_clone.list_audit_entries(limit, offset))
            .await
            .map_err(|e| AppError::Internal(format!("Task failed: {e}")))?
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
    let db_clone = state.db.clone();
    let db_ok = tokio::task::spawn_blocking(move || db_clone.ping())
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false);
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
        match serde_yml::from_str::<serde_json::Value>(yaml) {
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
    axum::response::Redirect::permanent("/icon.png")
}

// ── GET /static/twofold.js ───────────────────────────────────────────────────

/// Serve the toolbar JavaScript. Embedded at compile time; no runtime file I/O.
///
/// Deployed via `cargo install` from crates.io — no `static/` directory exists
/// at runtime, so the file must travel with the binary.
pub async fn serve_twofold_js() -> impl IntoResponse {
    let js = include_str!("../static/twofold.js");
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        js,
    )
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Auth check: delegates to [`crate::auth::check_auth`].
///
/// Kept as a thin shim so the call-sites inside this module don't need
/// to be updated to a full module path.
async fn check_auth(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<crate::auth::Principal, AppError> {
    crate::auth::check_auth(state, headers).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::hash_password;

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
            registration_limit: 5,
            registration_mode: crate::config::RegistrationMode::Open,
        };
        let rate_limit = crate::rate_limit::RateLimitStore::new(&config);
        let state = AppState {
            db,
            config: Arc::new(config),
            rate_limit: rate_limit.clone(),
        };
        Router::new()
            .route(
                "/api/v1/documents",
                post(crate::handlers::post_document).get(crate::handlers::list_documents),
            )
            .route(
                "/api/v1/documents/:slug",
                get(crate::views::get_agent)
                    .put(crate::handlers::put_document)
                    .delete(crate::handlers::delete_document),
            )
            .layer(axum::Extension(rate_limit))
            .with_state(state)
    }

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
            registration_limit: 5,
            registration_mode: crate::config::RegistrationMode::Open,
        }
    }

    fn make_test_state(token: &str) -> (AppState, crate::db::Db) {
        let db = crate::db::Db::open(":memory:").expect("in-memory db");
        let config = make_test_config(token);
        let rate_limit = crate::rate_limit::RateLimitStore::new(&config);
        let state = AppState {
            db: db.clone(),
            config: Arc::new(config),
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
                get(crate::views::get_agent)
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
                get(crate::views::get_agent)
                    .put(crate::handlers::put_document)
                    .delete(crate::handlers::delete_document),
            )
            .route("/api/v1/audit", get(crate::handlers::list_audit))
            .layer(axum::Extension(rate_limit))
            .with_state(state);
        (router, db)
    }

    /// Build a test router that has a pre-inserted managed token in the DB.
    fn test_app_with_managed_token() -> (Router, String) {
        use crate::db::{Db, TokenRecord};

        let db = Db::open(":memory:").expect("in-memory db");

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
            registration_limit: 5,
            registration_mode: crate::config::RegistrationMode::Open,
        };
        let rate_limit = crate::rate_limit::RateLimitStore::new(&config);
        let state = AppState {
            db,
            config: Arc::new(config),
            rate_limit: rate_limit.clone(),
        };
        let router = Router::new()
            .route(
                "/api/v1/documents",
                post(crate::handlers::post_document).get(crate::handlers::list_documents),
            )
            .route(
                "/api/v1/documents/:slug",
                get(crate::views::get_agent)
                    .put(crate::handlers::put_document)
                    .delete(crate::handlers::delete_document),
            )
            .layer(axum::Extension(rate_limit))
            .with_state(state);
        (router, managed_plain.to_string())
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

    /// API (agent) route still returns JSON 404 for nonexistent slugs.
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

    #[tokio::test]
    async fn test_put_updates_existing_document() {
        let token = "test-token";
        let app = test_app(token);

        let slug = publish_doc(
            app.clone(),
            token,
            "my-slug",
            "# Original\nOriginal content.",
        )
        .await;
        assert_eq!(slug, "my-slug");

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

        let slug = publish_doc(app.clone(), token, "ts-test", "# V1").await;

        let req = Request::builder()
            .method("PUT")
            .uri(format!("/api/v1/documents/{slug}"))
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "text/markdown")
            .body(Body::from("# V2"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

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
        let token = "test-token";
        let app = test_app(token);

        publish_doc(app.clone(), token, "original-slug", "# Doc").await;

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
        assert_eq!(json["slug"].as_str().unwrap(), "original-slug");
    }

    // ── Managed token auth tests ──────────────────────────────────────────────

    #[tokio::test]
    async fn test_managed_token_auth_accepted() {
        let (app, managed_token) = test_app_with_managed_token();

        let slug = publish_doc(app.clone(), "admin-token", "managed-test", "# Hello").await;

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

    #[tokio::test]
    async fn test_managed_token_wrong_value_rejected() {
        let (app, managed_token) = test_app_with_managed_token();

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

    #[tokio::test]
    async fn test_revoked_managed_token_rejected() {
        use crate::db::{Db, TokenRecord};

        let db = Db::open(":memory:").expect("in-memory db");
        let managed_plain = "tf_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let prefix: String = managed_plain.chars().take(8).collect();
        let hash = hash_password(managed_plain).expect("hash");

        let record = TokenRecord {
            id: "revoked-id".to_string(),
            name: "revoked-token".to_string(),
            hash,
            created_at: "2024-01-01T00:00:00Z".to_string(),
            last_used: None,
            revoked: true,
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
            registration_limit: 5,
            registration_mode: crate::config::RegistrationMode::Open,
        };
        let rate_limit = crate::rate_limit::RateLimitStore::new(&config);
        let state = AppState {
            db,
            config: Arc::new(config),
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

    // ── Audit log tests ───────────────────────────────────────────────────────

    #[test]
    fn test_db_insert_and_list_audit_entries() {
        let db = crate::db::Db::open(":memory:").expect("in-memory db");

        let (entries, total) = db.list_audit_entries(20, 0).expect("list ok");
        assert_eq!(total, 0);
        assert!(entries.is_empty());

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
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "master token should authenticate"
        );
    }

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

    #[tokio::test]
    async fn test_delete_document_writes_audit_entry() {
        let token = "test-token";
        let (app, db) = test_app_with_db(token);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/documents")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "text/markdown")
            .body(Body::from("---\nslug: to-delete\n---\n# Delete Me"))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

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
}
