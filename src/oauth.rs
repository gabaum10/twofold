//! OAuth 2.0 Authorization Server. Authorization Code + PKCE, dynamic client registration, refresh token rotation.

/// OAuth 2.0 implementation — full spec for Cowork (claude.ai) remote MCP.
///
/// Routes:
///   GET  /.well-known/oauth-protected-resource   — RFC 8707 resource metadata
///   GET  /.well-known/oauth-authorization-server — RFC 8414 server metadata
///   POST /oauth/register                          — RFC 7591 dynamic client registration
///   GET  /authorize                               — Authorization Code flow, PKCE required
///   POST /oauth/token                             — Token exchange (auth_code, client_credentials, refresh_token)
///
/// PKCE is MANDATORY (S256 only). Requests without code_challenge are rejected.
/// Public clients (token_endpoint_auth_method: "none") do not need a client_secret.
/// Refresh tokens are rotated on each use.
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::auth::check_auth_token;
use crate::config::RegistrationMode;
use crate::db::{AccessTokenRow, AuthCodeRow, OAuthClientRow, RefreshTokenRow};
use crate::handlers::AppState;
use crate::helpers::chrono_now;
use crate::rate_limit::{ReadRateLimit, RegistrationRateLimit};

// ── Well-known metadata handlers ─────────────────────────────────────────────

/// GET /.well-known/oauth-protected-resource — RFC 8707 resource metadata.
pub async fn handle_protected_resource_metadata(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let base = base_url(&state);
    let body = serde_json::json!({
        "resource": format!("{base}/mcp"),
        "authorization_servers": [base],
        "scopes_supported": ["mcp:tools"],
        "bearer_methods_supported": ["header"]
    });
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        axum::Json(body),
    )
}

/// GET /.well-known/oauth-authorization-server — RFC 8414 AS metadata.
///
/// When registration mode is Closed, `registration_endpoint` is omitted from the
/// metadata so clients know not to attempt dynamic registration.
pub async fn handle_authorization_server_metadata(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let base = base_url(&state);
    let mut body = serde_json::json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/oauth/token"),
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["mcp:tools", "offline_access"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"]
    });
    if state.config.registration_mode == RegistrationMode::Open {
        body["registration_endpoint"] = serde_json::json!(format!("{base}/oauth/register"));
    }
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        axum::Json(body),
    )
}

// ── Dynamic Client Registration ───────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub client_name: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
    pub grant_types: Option<Vec<String>>,
    pub response_types: Option<Vec<String>>,
    pub token_endpoint_auth_method: Option<String>,
}

#[derive(Debug, Serialize)]
struct RegisterResponse {
    client_id: String,
    client_name: String,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    response_types: Vec<String>,
    token_endpoint_auth_method: String,
}

/// POST /oauth/register — RFC 7591 dynamic client registration.
pub async fn handle_register(
    State(state): State<AppState>,
    _rl: RegistrationRateLimit,
    Json(req): Json<RegisterRequest>,
) -> Response {
    // Gate: if registration is closed, reject all dynamic registration attempts.
    if state.config.registration_mode == RegistrationMode::Closed {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "registration_disabled",
                "error_description": "Dynamic client registration is disabled. Use a pre-configured client_id."
            })),
        )
            .into_response();
    }

    let client_name = req
        .client_name
        .unwrap_or_else(|| "unnamed-client".to_string());
    let redirect_uris = req.redirect_uris.unwrap_or_default();
    if redirect_uris.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(OAuthError {
                error: "invalid_client_metadata",
                error_description: "redirect_uris is required and must not be empty",
            }),
        )
            .into_response();
    }
    let grant_types = req
        .grant_types
        .unwrap_or_else(|| vec!["authorization_code".to_string()]);
    let response_types = req
        .response_types
        .unwrap_or_else(|| vec!["code".to_string()]);
    let token_endpoint_auth_method = req
        .token_endpoint_auth_method
        .unwrap_or_else(|| "none".to_string());
    let client_id = new_uuid();
    let now = chrono_now();
    // Compute the cutoff for the 24-hour active-client window (RFC 3339, lexicographic-safe).
    // The reaper handles periodic sweeps of expired clients; we only count here.
    let cutoff_24h = {
        let cutoff = chrono::Utc::now() - chrono::Duration::hours(24);
        cutoff.format("%Y-%m-%dT%H:%M:%SZ").to_string()
    };

    // Hard cap: refuse new registrations if there are already 1,000 active entries.
    // This prevents storage exhaustion from registration spam that slips past
    // the rate limiter (e.g., distributed sources).
    let db_cap = state.db.clone();
    let cutoff_for_cap = cutoff_24h.clone();
    let cap_result =
        tokio::task::spawn_blocking(move || db_cap.count_active_oauth_clients(&cutoff_for_cap))
            .await;

    match cap_result {
        Ok(Ok(count)) if count >= 1_000 => {
            tracing::warn!(
                "OAuth client registration limit reached ({} entries)",
                count
            );
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "Registration limit reached"
                })),
            )
                .into_response();
        }
        Ok(Err(e)) => {
            tracing::error!(error = %e, "Failed to count OAuth clients");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "Database error"
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "OAuth registration count task panicked");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "Database error"
                })),
            )
                .into_response();
        }
        _ => {}
    }

    let row = OAuthClientRow {
        client_id: client_id.clone(),
        client_name: client_name.clone(),
        redirect_uris: serde_json::to_string(&redirect_uris).unwrap_or_default(),
        grant_types: serde_json::to_string(&grant_types).unwrap_or_default(),
        response_types: serde_json::to_string(&response_types).unwrap_or_default(),
        token_endpoint_auth_method: token_endpoint_auth_method.clone(),
        created_at: now,
        provisioned: false,
        client_secret: None,
    };
    let db_clone = state.db.clone();
    if let Err(e) = tokio::task::spawn_blocking(move || db_clone.insert_oauth_client(&row))
        .await
        .unwrap_or_else(|e| {
            Err(rusqlite::Error::InvalidPath(std::path::PathBuf::from(
                format!("task panicked: {e}"),
            )))
        })
    {
        tracing::error!(error = %e, "Failed to insert OAuth client");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "server_error",
                "error_description": "Database error"
            })),
        )
            .into_response();
    }
    tracing::info!(client_id = %client_id, client_name = %client_name, "OAuth dynamic client registered");
    let resp = RegisterResponse {
        client_id,
        client_name,
        redirect_uris,
        grant_types,
        response_types,
        token_endpoint_auth_method,
    };
    (StatusCode::CREATED, Json(resp)).into_response()
}

// ── Authorization endpoint ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AuthorizeParams {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub resource: Option<String>,
    #[allow(dead_code)] // parsed from registration request, reserved for future scope enforcement
    pub scope: Option<String>,
}

/// GET /authorize — PKCE (S256) required. Auto-approves, issues code, redirects.
///
/// Security: validates client_id against registered clients and validates
/// redirect_uri against the client's registered redirect_uris to prevent
/// open redirect attacks.
pub async fn handle_authorize(
    State(state): State<AppState>,
    _rl: ReadRateLimit,
    Query(params): Query<AuthorizeParams>,
) -> Response {
    match params.response_type.as_deref() {
        Some("code") => {}
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(OAuthError {
                    error: "unsupported_response_type",
                    error_description: "Only response_type=code is supported",
                }),
            )
                .into_response();
        }
    }
    let client_id = match params.client_id {
        Some(ref id) if !id.is_empty() => id.clone(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(OAuthError {
                    error: "invalid_request",
                    error_description: "client_id is required",
                }),
            )
                .into_response();
        }
    };
    let redirect_uri = match params.redirect_uri {
        Some(ref uri) if !uri.is_empty() => uri.clone(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(OAuthError {
                    error: "invalid_request",
                    error_description: "redirect_uri is required",
                }),
            )
                .into_response();
        }
    };
    // PKCE: mandatory.
    let code_challenge = match params.code_challenge {
        Some(ref c) if !c.is_empty() => c.clone(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(OAuthError {
                    error: "invalid_request",
                    error_description: "code_challenge is required (S256 PKCE mandatory)",
                }),
            )
                .into_response();
        }
    };
    match params.code_challenge_method.as_deref() {
        Some("S256") | None => {}
        Some(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(OAuthError {
                    error: "invalid_request",
                    error_description: "Only code_challenge_method=S256 is supported",
                }),
            )
                .into_response();
        }
    }

    // Validate client_id and redirect_uri against registered clients.
    // For unregistered clients (admin-token-backed), still validate redirect_uri format.
    // Runs off the async executor.
    let db_lookup = state.db.clone();
    let client_id_for_lookup = client_id.clone();
    let client_lookup =
        tokio::task::spawn_blocking(move || db_lookup.get_oauth_client(&client_id_for_lookup))
            .await;
    match client_lookup {
        Ok(Ok(Some(client))) => {
            // Registered client: redirect_uri must be in the allowed list.
            let uris: Vec<String> = serde_json::from_str(&client.redirect_uris).unwrap_or_default();
            if !uris.contains(&redirect_uri) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(OAuthError {
                        error: "invalid_request",
                        error_description: "redirect_uri does not match registered redirect URIs",
                    }),
                )
                    .into_response();
            }
        }
        Ok(Ok(None)) => {
            // Unknown client_id. In Closed mode, all clients must be provisioned — reject.
            if state.config.registration_mode == RegistrationMode::Closed {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(OAuthError {
                        error: "invalid_client",
                        error_description: "Unknown client_id. Dynamic registration is disabled.",
                    }),
                )
                    .into_response();
            }
            // Open mode: pre-registered / admin-token client — require HTTPS unless localhost.
            if !is_safe_redirect_uri(&redirect_uri) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(OAuthError {
                        error: "invalid_request",
                        error_description:
                            "redirect_uri must use HTTPS (localhost is permitted over HTTP)",
                    }),
                )
                    .into_response();
            }
        }
        Ok(Err(e)) => {
            tracing::error!(error = %e, "Failed to look up OAuth client");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(OAuthError {
                    error: "server_error",
                    error_description: "Database error",
                }),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "OAuth client lookup task panicked");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(OAuthError {
                    error: "server_error",
                    error_description: "Database error",
                }),
            )
                .into_response();
        }
    }

    let code = {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        hex_encode(&bytes)
    };
    let expires_at = {
        let future = chrono::Utc::now() + chrono::Duration::minutes(5);
        future.format("%Y-%m-%dT%H:%M:%SZ").to_string()
    };
    let auth_code_row = AuthCodeRow {
        code: code.clone(),
        client_id: client_id.clone(),
        redirect_uri: redirect_uri.clone(),
        expires_at,
        code_challenge,
        resource: params.resource.clone(),
        scope: params.scope.clone(),
    };
    let db_insert = state.db.clone();
    if let Err(e) = tokio::task::spawn_blocking(move || db_insert.insert_auth_code(&auth_code_row))
        .await
        .unwrap_or_else(|e| {
            Err(rusqlite::Error::InvalidPath(std::path::PathBuf::from(
                format!("task panicked: {e}"),
            )))
        })
    {
        tracing::error!(error = %e, "Failed to insert auth code");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(OAuthError {
                error: "server_error",
                error_description: "Database error",
            }),
        )
            .into_response();
    }
    tracing::info!(client_id = %client_id, scope = ?params.scope, "OAuth authorization_code issued");
    // URL-encode state (arbitrary client data may contain special characters).
    let redirect_url = match params.state.as_deref() {
        Some(s) if !s.is_empty() => format!(
            "{}{}code={}&state={}",
            redirect_uri,
            if redirect_uri.contains('?') { "&" } else { "?" },
            code,
            percent_encode(s),
        ),
        _ => format!(
            "{}{}code={}",
            redirect_uri,
            if redirect_uri.contains('?') { "&" } else { "?" },
            code,
        ),
    };
    Redirect::to(&redirect_url).into_response()
}

// ── Token endpoint ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct TokenRequest {
    grant_type: String,
    client_id: Option<String>,
    client_secret: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    resource: Option<String>,
    refresh_token: Option<String>,
    scope: Option<String>,
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}

/// POST /oauth/token — all grant types.
pub async fn handle_oauth_token(
    State(state): State<AppState>,
    _rl: ReadRateLimit,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let req = if content_type.starts_with("application/json") {
        match serde_json::from_slice::<TokenRequest>(&body) {
            Ok(r) => r,
            Err(_) => return invalid_request("Missing or malformed request parameters"),
        }
    } else {
        let body_str = match std::str::from_utf8(&body) {
            Ok(s) => s,
            Err(_) => return invalid_request("Request body is not valid UTF-8"),
        };
        match parse_form(body_str) {
            Some(r) => r,
            None => return invalid_request("grant_type is required"),
        }
    };
    match req.grant_type.as_str() {
        "client_credentials" => handle_client_credentials(state, req).await,
        "authorization_code" => handle_authorization_code(state, req).await,
        "refresh_token" => handle_refresh_token(state, req).await,
        _ => unsupported_grant_type(),
    }
}

async fn handle_client_credentials(state: AppState, req: TokenRequest) -> Response {
    let client_id = match req.client_id.as_deref() {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => return invalid_request("client_id is required for client_credentials grant"),
    };
    let provided_secret = match req.client_secret.as_deref() {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return invalid_request("client_secret is required for client_credentials grant"),
    };

    // Look up the client in oauth_clients (provisioned via `twofold client create`).
    let db_client = state.db.clone();
    let client_id_for_lookup = client_id.clone();
    let client_row = match tokio::task::spawn_blocking(move || {
        db_client.get_oauth_client(&client_id_for_lookup)
    })
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => {
            tracing::error!(error = %e, "Failed to look up OAuth client");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "Database error"
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "OAuth client lookup task panicked");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "Database error"
                })),
            )
                .into_response();
        }
    };

    let access_token = if let Some(ref c) = client_row {
        // Provisioned client found. It must have a stored secret (client_credentials
        // requires a confidential client).
        let stored_secret = match c.client_secret.as_deref() {
            Some(s) => s,
            None => {
                tracing::warn!(client_id = %client_id, "OAuth client_credentials denied: public client cannot use client_credentials grant");
                return invalid_client();
            }
        };
        if !constant_time_str_eq(&provided_secret, stored_secret) {
            tracing::warn!(client_id = %client_id, "OAuth client_credentials denied: wrong client_secret");
            return invalid_client();
        }
        // Secret matches — mint a short-lived access token.
        let at = new_uuid();
        let at_expires = {
            let future = chrono::Utc::now() + chrono::Duration::hours(1);
            future.format("%Y-%m-%dT%H:%M:%SZ").to_string()
        };
        let at_row = AccessTokenRow {
            token: at.clone(),
            client_id: client_id.clone(),
            scope: req.scope.clone(),
            expires_at: at_expires,
        };
        let db_at = state.db.clone();
        if let Err(e) = tokio::task::spawn_blocking(move || db_at.insert_access_token(&at_row))
            .await
            .unwrap_or_else(|e| {
                Err(rusqlite::Error::InvalidPath(std::path::PathBuf::from(
                    format!("task panicked: {e}"),
                )))
            })
        {
            tracing::error!(error = %e, "Failed to insert access token");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "Database error"
                })),
            )
                .into_response();
        }
        at
    } else {
        // Client not in oauth_clients — fall back to admin/managed token check
        // for backwards compatibility with pre-provisioning usage.
        match check_auth_token(&state, &provided_secret).await {
            Ok(_) => provided_secret,
            Err(_) => {
                tracing::warn!(client_id = %client_id, "OAuth client_credentials denied: unknown client and invalid admin token");
                return invalid_client();
            }
        }
    };

    tracing::info!(client_id = %client_id, "OAuth client_credentials grant issued");
    (
        StatusCode::OK,
        Json(TokenResponse {
            access_token,
            token_type: "bearer",
            expires_in: 3600,
            refresh_token: None,
            scope: req.scope,
        }),
    )
        .into_response()
}

async fn handle_authorization_code(state: AppState, req: TokenRequest) -> Response {
    tracing::info!(
        grant_type = %req.grant_type,
        client_id = ?req.client_id,
        has_code = req.code.is_some(),
        has_client_secret = req.client_secret.is_some(),
        has_code_verifier = req.code_verifier.is_some(),
        "OAuth token exchange request received"
    );
    let code = match req.code.as_deref() {
        Some(c) if !c.is_empty() => c.to_string(),
        _ => return invalid_request("code is required"),
    };
    let client_id = match req.client_id.as_deref() {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => return invalid_request("client_id is required"),
    };
    let redirect_uri = match req.redirect_uri.as_deref() {
        Some(uri) if !uri.is_empty() => uri.to_string(),
        _ => return invalid_request("redirect_uri is required"),
    };
    let code_verifier = match req.code_verifier.as_deref() {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => return invalid_request("code_verifier is required (PKCE mandatory)"),
    };
    let db_take = state.db.clone();
    let code_for_take = code.clone();
    let record =
        match tokio::task::spawn_blocking(move || db_take.take_auth_code(&code_for_take)).await {
            Ok(Ok(Some(r))) => r,
            Ok(Ok(None)) => {
                tracing::warn!(client_id = %client_id, "OAuth authorization_code not found");
                return invalid_grant("Authorization code not found or already used");
            }
            Ok(Err(e)) => {
                tracing::error!(error = %e, "Failed to take auth code");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "server_error",
                        "error_description": "Database error"
                    })),
                )
                    .into_response();
            }
            Err(e) => {
                tracing::error!(error = %e, "Auth code take task panicked");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "server_error",
                        "error_description": "Database error"
                    })),
                )
                    .into_response();
            }
        };
    let now = chrono_now();
    if record.expires_at.as_str() < now.as_str() {
        tracing::warn!(client_id = %client_id, "OAuth authorization_code expired");
        return invalid_grant("Authorization code has expired");
    }
    if record.client_id != client_id {
        tracing::warn!(client_id = %client_id, "OAuth authorization_code client_id mismatch");
        return invalid_grant("client_id does not match authorization request");
    }
    if record.redirect_uri != redirect_uri {
        tracing::warn!(client_id = %client_id, "OAuth authorization_code redirect_uri mismatch");
        return invalid_grant("redirect_uri does not match authorization request");
    }
    // Resource binding: if the auth code captured a resource, the token request
    // must include the same resource. If no resource on the code, that is fine.
    if let Some(ref stored_resource) = record.resource {
        match req.resource.as_deref() {
            Some(req_resource) if req_resource == stored_resource => {}
            Some(_) => {
                tracing::warn!(client_id = %client_id, "OAuth resource parameter mismatch");
                return invalid_grant("resource parameter does not match authorization request");
            }
            None => {
                // Auth code has resource, token request omits it — reject.
                tracing::warn!(client_id = %client_id, "OAuth token request missing required resource parameter");
                return invalid_grant("resource parameter is required for this authorization code");
            }
        }
    }
    if !verify_pkce_s256(&code_verifier, &record.code_challenge) {
        tracing::warn!(client_id = %client_id, "OAuth PKCE verification failed");
        return invalid_grant("code_verifier does not match code_challenge");
    }
    let db_client = state.db.clone();
    let client_id_for_lookup = client_id.clone();
    // Look up the client to determine auth method: provisioned confidential clients
    // have a client_secret in the DB and must authenticate with it. Public clients
    // (token_endpoint_auth_method=none, no DB secret) go through the standard UUID
    // access token path. The Ok(Ok(None)) fallback preserves the existing public
    // client behaviour for dynamically-registered clients not in the DB.
    let client_row = match tokio::task::spawn_blocking(move || {
        db_client.get_oauth_client(&client_id_for_lookup)
    })
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => {
            tracing::error!(error = %e, "Failed to look up OAuth client");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "Database error"
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "OAuth client lookup task panicked");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "Database error"
                })),
            )
                .into_response();
        }
    };

    // Determine if this is a confidential client (has a stored secret).
    // If so, validate the provided secret against the stored one.
    // Otherwise fall through to the public client UUID token path.
    let access_token = if let Some(ref c) = client_row {
        if let Some(ref stored_secret) = c.client_secret {
            // Confidential client: require matching client_secret.
            let provided = match req.client_secret.as_deref() {
                Some(s) if !s.is_empty() => s,
                _ => {
                    tracing::warn!(client_id = %client_id, "OAuth authorization_code denied: client_secret missing for confidential client");
                    return invalid_client();
                }
            };
            if !constant_time_str_eq(provided, stored_secret) {
                tracing::warn!(client_id = %client_id, "OAuth authorization_code denied: wrong client_secret");
                return invalid_client();
            }
            // Confidential client authenticated — issue a UUID access token.
            let at = new_uuid();
            let at_expires = {
                let future = chrono::Utc::now() + chrono::Duration::hours(1);
                future.format("%Y-%m-%dT%H:%M:%SZ").to_string()
            };
            let at_row = AccessTokenRow {
                token: at.clone(),
                client_id: client_id.clone(),
                scope: record.scope.clone(),
                expires_at: at_expires,
            };
            let db_at = state.db.clone();
            if let Err(e) = tokio::task::spawn_blocking(move || db_at.insert_access_token(&at_row))
                .await
                .unwrap_or_else(|e| {
                    Err(rusqlite::Error::InvalidPath(std::path::PathBuf::from(
                        format!("task panicked: {e}"),
                    )))
                })
            {
                tracing::error!(error = %e, "Failed to insert access token");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "server_error",
                        "error_description": "Database error"
                    })),
                )
                    .into_response();
            }
            at
        } else {
            // Registered client with no stored secret — treat as public.
            // token_endpoint_auth_method == "none" OR legacy registered client.
            let is_public = c.token_endpoint_auth_method == "none" || req.client_secret.is_none();
            if is_public {
                let at = new_uuid();
                let at_expires = {
                    let future = chrono::Utc::now() + chrono::Duration::hours(1);
                    future.format("%Y-%m-%dT%H:%M:%SZ").to_string()
                };
                let at_row = AccessTokenRow {
                    token: at.clone(),
                    client_id: client_id.clone(),
                    scope: record.scope.clone(),
                    expires_at: at_expires,
                };
                let db_at = state.db.clone();
                if let Err(e) =
                    tokio::task::spawn_blocking(move || db_at.insert_access_token(&at_row))
                        .await
                        .unwrap_or_else(|e| {
                            Err(rusqlite::Error::InvalidPath(std::path::PathBuf::from(
                                format!("task panicked: {e}"),
                            )))
                        })
                {
                    tracing::error!(error = %e, "Failed to insert access token");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({
                            "error": "server_error",
                            "error_description": "Database error"
                        })),
                    )
                        .into_response();
                }
                at
            } else {
                // client_secret_post: validate against admin token (legacy path).
                let client_secret = match req.client_secret.as_deref() {
                    Some(s) if !s.is_empty() => s.to_string(),
                    _ => {
                        tracing::warn!(client_id = %client_id, "OAuth authorization_code denied: client_secret missing or empty");
                        return invalid_client();
                    }
                };
                match check_auth_token(&state, &client_secret).await {
                    Ok(_) => client_secret,
                    Err(_) => {
                        tracing::warn!(client_id = %client_id, "OAuth authorization_code denied: invalid secret");
                        return invalid_client();
                    }
                }
            }
        }
    } else {
        // Client not in DB (Ok(Ok(None))). In Closed mode, all clients must be
        // provisioned — reject. In Open mode, fall through to public client path.
        if state.config.registration_mode == RegistrationMode::Closed {
            tracing::warn!(client_id = %client_id, "OAuth token exchange denied: unknown client_id in closed mode");
            return invalid_client();
        }
        // Open mode: public client fallback. Preserves existing behaviour for
        // Cowork when using pre-registered client_id.
        let at = new_uuid();
        let at_expires = {
            let future = chrono::Utc::now() + chrono::Duration::hours(1);
            future.format("%Y-%m-%dT%H:%M:%SZ").to_string()
        };
        let at_row = AccessTokenRow {
            token: at.clone(),
            client_id: client_id.clone(),
            scope: record.scope.clone(),
            expires_at: at_expires,
        };
        let db_at = state.db.clone();
        if let Err(e) = tokio::task::spawn_blocking(move || db_at.insert_access_token(&at_row))
            .await
            .unwrap_or_else(|e| {
                Err(rusqlite::Error::InvalidPath(std::path::PathBuf::from(
                    format!("task panicked: {e}"),
                )))
            })
        {
            tracing::error!(error = %e, "Failed to insert access token");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "Database error"
                })),
            )
                .into_response();
        }
        at
    };
    let wants_offline = record
        .scope
        .as_deref()
        .map(|s| s.split_whitespace().any(|tok| tok == "offline_access"))
        .unwrap_or(false);
    let refresh_tok = if wants_offline {
        let rt = new_uuid();
        let rt_expires = {
            let future = chrono::Utc::now() + chrono::Duration::days(30);
            future.format("%Y-%m-%dT%H:%M:%SZ").to_string()
        };
        let rt_row = RefreshTokenRow {
            token: rt.clone(),
            client_id: client_id.clone(),
            access_token: access_token.clone(),
            scope: record.scope.clone(),
            expires_at: rt_expires,
        };
        let db_rt = state.db.clone();
        if let Err(e) = tokio::task::spawn_blocking(move || db_rt.insert_refresh_token(&rt_row))
            .await
            .unwrap_or_else(|e| {
                Err(rusqlite::Error::InvalidPath(std::path::PathBuf::from(
                    format!("task panicked: {e}"),
                )))
            })
        {
            tracing::error!(error = %e, "Failed to insert refresh token");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "Database error"
                })),
            )
                .into_response();
        }
        Some(rt)
    } else {
        None
    };
    tracing::info!(client_id = %client_id, has_refresh = refresh_tok.is_some(), "OAuth authorization_code grant issued");
    (
        StatusCode::OK,
        Json(TokenResponse {
            access_token,
            token_type: "bearer",
            expires_in: 3600,
            refresh_token: refresh_tok,
            scope: record.scope,
        }),
    )
        .into_response()
}

async fn handle_refresh_token(state: AppState, req: TokenRequest) -> Response {
    let rt_value = match req.refresh_token.as_deref() {
        Some(t) if !t.is_empty() => t.to_string(),
        _ => return invalid_request("refresh_token is required"),
    };
    let client_id = match req.client_id.as_deref() {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => return invalid_request("client_id is required"),
    };
    let db_take_rt = state.db.clone();
    let rt_for_take = rt_value.clone();
    let record = match tokio::task::spawn_blocking(move || {
        db_take_rt.take_refresh_token(&rt_for_take)
    })
    .await
    {
        Ok(Ok(Some(r))) => r,
        Ok(Ok(None)) => {
            tracing::warn!(client_id = %client_id, "OAuth refresh_token not found");
            return invalid_grant("Refresh token not found or already used");
        }
        Ok(Err(e)) => {
            tracing::error!(error = %e, "Failed to take refresh token");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "Database error"
                })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "Refresh token take task panicked");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "Database error"
                })),
            )
                .into_response();
        }
    };
    let now = chrono_now();
    if record.expires_at.as_str() < now.as_str() {
        tracing::warn!(client_id = %client_id, "OAuth refresh_token expired");
        return invalid_grant("Refresh token has expired");
    }
    if record.client_id != client_id {
        tracing::warn!(client_id = %client_id, "OAuth refresh_token client_id mismatch");
        return invalid_grant("client_id does not match refresh token");
    }
    let db_client_rt = state.db.clone();
    let client_id_for_rt = client_id.clone();
    let client_row_rt =
        match tokio::task::spawn_blocking(move || db_client_rt.get_oauth_client(&client_id_for_rt))
            .await
        {
            Ok(Ok(result)) => result,
            Ok(Err(e)) => {
                tracing::error!(error = %e, "Failed to look up OAuth client");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "server_error",
                        "error_description": "Database error"
                    })),
                )
                    .into_response();
            }
            Err(e) => {
                tracing::error!(error = %e, "OAuth client lookup task panicked");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "server_error",
                        "error_description": "Database error"
                    })),
                )
                    .into_response();
            }
        };
    let access_token = if let Some(ref c) = client_row_rt {
        if let Some(ref stored_secret) = c.client_secret {
            // Confidential client: require matching client_secret.
            let provided = match req.client_secret.as_deref() {
                Some(s) if !s.is_empty() => s,
                _ => {
                    tracing::warn!(client_id = %client_id, "OAuth refresh_token denied: client_secret missing for confidential client");
                    return invalid_client();
                }
            };
            if !constant_time_str_eq(provided, stored_secret) {
                tracing::warn!(client_id = %client_id, "OAuth refresh_token denied: wrong client_secret");
                return invalid_client();
            }
            let at = new_uuid();
            let at_expires = {
                let future = chrono::Utc::now() + chrono::Duration::hours(1);
                future.format("%Y-%m-%dT%H:%M:%SZ").to_string()
            };
            let at_row_rt = AccessTokenRow {
                token: at.clone(),
                client_id: client_id.clone(),
                scope: record.scope.clone(),
                expires_at: at_expires,
            };
            let db_at_rt = state.db.clone();
            if let Err(e) =
                tokio::task::spawn_blocking(move || db_at_rt.insert_access_token(&at_row_rt))
                    .await
                    .unwrap_or_else(|e| {
                        Err(rusqlite::Error::InvalidPath(std::path::PathBuf::from(
                            format!("task panicked: {e}"),
                        )))
                    })
            {
                tracing::error!(error = %e, "Failed to insert access token");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "server_error",
                        "error_description": "Database error"
                    })),
                )
                    .into_response();
            }
            at
        } else {
            let is_public = c.token_endpoint_auth_method == "none" || req.client_secret.is_none();
            if is_public {
                let at = new_uuid();
                let at_expires = {
                    let future = chrono::Utc::now() + chrono::Duration::hours(1);
                    future.format("%Y-%m-%dT%H:%M:%SZ").to_string()
                };
                let at_row_rt = AccessTokenRow {
                    token: at.clone(),
                    client_id: client_id.clone(),
                    scope: record.scope.clone(),
                    expires_at: at_expires,
                };
                let db_at_rt = state.db.clone();
                if let Err(e) =
                    tokio::task::spawn_blocking(move || db_at_rt.insert_access_token(&at_row_rt))
                        .await
                        .unwrap_or_else(|e| {
                            Err(rusqlite::Error::InvalidPath(std::path::PathBuf::from(
                                format!("task panicked: {e}"),
                            )))
                        })
                {
                    tracing::error!(error = %e, "Failed to insert access token");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({
                            "error": "server_error",
                            "error_description": "Database error"
                        })),
                    )
                        .into_response();
                }
                at
            } else {
                let client_secret = match req.client_secret.as_deref() {
                    Some(s) if !s.is_empty() => s.to_string(),
                    _ => return invalid_client(),
                };
                match check_auth_token(&state, &client_secret).await {
                    Ok(_) => client_secret,
                    Err(_) => return invalid_client(),
                }
            }
        }
    } else {
        // Client not in DB. In Closed mode, all clients must be provisioned — reject.
        // In Open mode, fall through to public client fallback.
        if state.config.registration_mode == RegistrationMode::Closed {
            tracing::warn!(client_id = %client_id, "OAuth refresh_token denied: unknown client_id in closed mode");
            return invalid_client();
        }
        // Open mode: public client fallback.
        let at = new_uuid();
        let at_expires = {
            let future = chrono::Utc::now() + chrono::Duration::hours(1);
            future.format("%Y-%m-%dT%H:%M:%SZ").to_string()
        };
        let at_row_rt = AccessTokenRow {
            token: at.clone(),
            client_id: client_id.clone(),
            scope: record.scope.clone(),
            expires_at: at_expires,
        };
        let db_at_rt = state.db.clone();
        if let Err(e) =
            tokio::task::spawn_blocking(move || db_at_rt.insert_access_token(&at_row_rt))
                .await
                .unwrap_or_else(|e| {
                    Err(rusqlite::Error::InvalidPath(std::path::PathBuf::from(
                        format!("task panicked: {e}"),
                    )))
                })
        {
            tracing::error!(error = %e, "Failed to insert access token");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "Database error"
                })),
            )
                .into_response();
        }
        at
    };
    let new_rt = new_uuid();
    let new_rt_expires = {
        let future = chrono::Utc::now() + chrono::Duration::days(30);
        future.format("%Y-%m-%dT%H:%M:%SZ").to_string()
    };
    let new_rt_row = RefreshTokenRow {
        token: new_rt.clone(),
        client_id: client_id.clone(),
        access_token: access_token.clone(),
        scope: record.scope.clone(),
        expires_at: new_rt_expires,
    };
    let db_new_rt = state.db.clone();
    if let Err(e) = tokio::task::spawn_blocking(move || db_new_rt.insert_refresh_token(&new_rt_row))
        .await
        .unwrap_or_else(|e| {
            Err(rusqlite::Error::InvalidPath(std::path::PathBuf::from(
                format!("task panicked: {e}"),
            )))
        })
    {
        tracing::error!(error = %e, "Failed to insert refresh token");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "server_error",
                "error_description": "Database error"
            })),
        )
            .into_response();
    }
    tracing::info!(client_id = %client_id, "OAuth refresh_token grant issued (rotated)");
    (
        StatusCode::OK,
        Json(TokenResponse {
            access_token,
            token_type: "bearer",
            expires_in: 3600,
            refresh_token: Some(new_rt),
            scope: record.scope,
        }),
    )
        .into_response()
}

// ── PKCE ──────────────────────────────────────────────────────────────────────

pub(crate) fn verify_pkce_s256(code_verifier: &str, stored_challenge: &str) -> bool {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(code_verifier.as_bytes());
    let computed = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);
    constant_time_str_eq(&computed, stored_challenge)
}

fn constant_time_str_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn base_url(state: &AppState) -> String {
    state.config.base_url.trim_end_matches('/').to_string()
}

fn new_uuid() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Percent-encode a string for safe inclusion in a URL query parameter value.
/// Encodes all characters except unreserved (ALPHA / DIGIT / "-" / "." / "_" / "~").
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(char::from(*byte));
            }
            b => {
                out.push('%');
                out.push(
                    char::from_digit((*b >> 4) as u32, 16)
                        .unwrap()
                        .to_ascii_uppercase(),
                );
                out.push(
                    char::from_digit((*b & 0xf) as u32, 16)
                        .unwrap()
                        .to_ascii_uppercase(),
                );
            }
        }
    }
    out
}

/// Validate that a redirect_uri is safe for use with an unregistered client.
/// Requires HTTPS unless the host is localhost or 127.0.0.1.
fn is_safe_redirect_uri(uri: &str) -> bool {
    let parsed = match url::Url::parse(uri) {
        Ok(u) => u,
        Err(_) => return false,
    };
    if parsed.scheme() == "https" {
        return true;
    }
    if parsed.scheme() == "http" {
        matches!(
            parsed.host_str(),
            Some("localhost") | Some("127.0.0.1") | Some("[::1]")
        )
    } else {
        false
    }
}

fn url_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            out.push(' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (from_hex(bytes[i + 1]), from_hex(bytes[i + 2])) {
                out.push(char::from(h << 4 | l));
                i += 3;
                continue;
            }
            out.push('%');
            i += 1;
        } else {
            out.push(char::from(bytes[i]));
            i += 1;
        }
    }
    out
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn parse_form(body: &str) -> Option<TokenRequest> {
    let mut grant_type = None;
    let mut client_id = None;
    let mut client_secret = None;
    let mut code = None;
    let mut redirect_uri = None;
    let mut code_verifier = None;
    let mut resource = None;
    let mut refresh_token = None;
    let mut scope = None;
    for pair in body.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            let k = url_decode(k);
            let v = url_decode(v);
            match k.as_str() {
                "grant_type" => grant_type = Some(v),
                "client_id" => client_id = Some(v),
                "client_secret" => client_secret = Some(v),
                "code" => code = Some(v),
                "redirect_uri" => redirect_uri = Some(v),
                "code_verifier" => code_verifier = Some(v),
                "resource" => resource = Some(v),
                "refresh_token" => refresh_token = Some(v),
                "scope" => scope = Some(v),
                _ => {}
            }
        }
    }
    Some(TokenRequest {
        grant_type: grant_type?,
        client_id,
        client_secret,
        code,
        redirect_uri,
        code_verifier,
        resource,
        refresh_token,
        scope,
    })
}

// ── Error responses ───────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct OAuthError {
    error: &'static str,
    error_description: &'static str,
}

fn invalid_client() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(OAuthError {
            error: "invalid_client",
            error_description: "Invalid client credentials",
        }),
    )
        .into_response()
}

fn invalid_request(description: &'static str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(OAuthError {
            error: "invalid_request",
            error_description: description,
        }),
    )
        .into_response()
}

fn unsupported_grant_type() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(OAuthError {
            error: "unsupported_grant_type",
            error_description: "Supported: authorization_code, client_credentials, refresh_token",
        }),
    )
        .into_response()
}

fn invalid_grant(description: &'static str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(OAuthError {
            error: "invalid_grant",
            error_description: description,
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::{is_safe_redirect_uri, verify_pkce_s256};

    // ── P3-17: PKCE RFC 7636 Appendix B known-vector tests ───────────────────

    /// RFC 7636 Appendix B known vector: correct verifier passes.
    ///
    /// verifier: dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
    /// challenge: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
    #[test]
    fn pkce_s256_rfc7636_appendix_b_correct_verifier() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(
            verify_pkce_s256(verifier, challenge),
            "RFC 7636 Appendix B vector must verify"
        );
    }

    /// Wrong verifier is rejected.
    #[test]
    fn pkce_s256_wrong_verifier_rejected() {
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(
            !verify_pkce_s256("wrong-verifier-value", challenge),
            "incorrect verifier must not verify"
        );
    }

    /// Verifier with different length is rejected (constant_time_str_eq early-exits on length).
    #[test]
    fn pkce_s256_different_length_rejected() {
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        // Empty verifier produces a different-length base64 hash — must not match.
        assert!(
            !verify_pkce_s256("", challenge),
            "empty verifier must not match"
        );
    }

    #[test]
    fn safe_redirect_https() {
        assert!(is_safe_redirect_uri("https://example.com/callback"));
    }

    #[test]
    fn safe_redirect_localhost_with_port() {
        assert!(is_safe_redirect_uri("http://localhost:8080/callback"));
    }

    #[test]
    fn unsafe_redirect_userinfo_bypass() {
        // http://localhost@evil.com — host is evil.com, not localhost
        assert!(!is_safe_redirect_uri("http://localhost@evil.com"));
    }

    #[test]
    fn unsafe_redirect_plain_http() {
        assert!(!is_safe_redirect_uri("http://evil.com"));
    }

    #[test]
    fn unsafe_redirect_not_a_url() {
        assert!(!is_safe_redirect_uri("not-a-url"));
    }

    // ── HTTP API integration tests ────────────────────────────────────────────
    //
    // All tests go through the full axum handler stack using oneshot requests.
    // No internal storage types are accessed for assertions — tests work whether
    // OAuth state is in-memory or SQLite. The two tests that inject pre-built
    // state (token_auth_code_expired, token_refresh_expired) seed the SQLite DB
    // directly via Db methods, so they remain storage-agnostic at the HTTP level.

    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::{get, post},
        Router,
    };
    use base64::Engine;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    use tower::ServiceExt;

    // ── Test router ──────────────────────────────────────────────────────────

    /// Build a minimal OAuth router backed by an in-memory SQLite database.
    ///
    /// Mirrors the route registration in main.rs for the OAuth endpoints.
    fn oauth_app(token: &str) -> Router {
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
            // High limits so individual tests don't hit read/write caps.
            rate_limit_read: 10_000,
            rate_limit_write: 10_000,
            rate_limit_window: 60,
            registration_limit: 5,
            registration_mode: crate::config::RegistrationMode::Open,
        };
        let rate_limit = crate::rate_limit::RateLimitStore::new(&config);
        let state = crate::handlers::AppState {
            db,
            config: Arc::new(config),
            rate_limit: rate_limit.clone(),
        };
        Router::new()
            .route("/oauth/register", post(crate::oauth::handle_register))
            .route("/authorize", get(crate::oauth::handle_authorize))
            .route("/oauth/token", post(crate::oauth::handle_oauth_token))
            .layer(axum::Extension(rate_limit))
            .with_state(state)
    }

    /// Build an OAuth router for registration rate-limit testing.
    ///
    /// The registration_store bucket uses REGISTRATION_LIMIT (5) and
    /// REGISTRATION_WINDOW_SECS (60) regardless of the per-read/write config,
    /// so this is functionally identical to oauth_app. The separation makes
    /// the test intent explicit.
    fn oauth_app_tight_registration(token: &str) -> Router {
        oauth_app(token)
    }

    // ── Flow helpers ─────────────────────────────────────────────────────────

    /// POST /oauth/register with the given redirect_uris; returns the client_id.
    async fn register_client(app: Router, redirect_uris: &[&str]) -> String {
        let body = serde_json::json!({
            "client_name": "test-client",
            "redirect_uris": redirect_uris,
            "token_endpoint_auth_method": "none"
        });
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/register")
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "register_client: expected 201"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        json["client_id"].as_str().unwrap().to_string()
    }

    /// Compute a PKCE S256 code_challenge from a verifier string.
    fn pkce_challenge(verifier: &str) -> String {
        let hash = Sha256::digest(verifier.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
    }

    /// GET /authorize and extract `code` from the Location header.
    async fn authorize(
        app: Router,
        client_id: &str,
        redirect_uri: &str,
        verifier: &str,
        scope: Option<&str>,
        resource: Option<&str>,
    ) -> String {
        let challenge = pkce_challenge(verifier);
        let mut uri = format!(
            "/authorize?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}&code_challenge={challenge}&code_challenge_method=S256",
        );
        if let Some(s) = scope {
            // Percent-encode spaces so the URI is valid (scope values can contain spaces).
            let encoded = s.replace(' ', "%20");
            uri.push_str(&format!("&scope={encoded}"));
        }
        if let Some(r) = resource {
            // Percent-encode colons and slashes for safety in query parameter values.
            let encoded = r.replace(':', "%3A").replace('/', "%2F");
            uri.push_str(&format!("&resource={encoded}"));
        }
        let req = Request::builder()
            .method("GET")
            .uri(&uri)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let location = resp
            .headers()
            .get("location")
            .expect("authorize: no Location header")
            .to_str()
            .unwrap()
            .to_string();
        extract_query_param(&location, "code").expect("authorize: no code in Location")
    }

    /// POST /oauth/token with grant_type=authorization_code; returns the raw response.
    async fn exchange_code(
        app: Router,
        client_id: &str,
        code: &str,
        redirect_uri: &str,
        verifier: &str,
        resource: Option<&str>,
    ) -> axum::response::Response {
        let mut params = format!(
            "grant_type=authorization_code&client_id={client_id}&code={code}&redirect_uri={redirect_uri}&code_verifier={verifier}"
        );
        if let Some(r) = resource {
            params.push_str(&format!("&resource={r}"));
        }
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(params))
            .unwrap();
        app.oneshot(req).await.unwrap()
    }

    /// Extract a named query parameter value from a URL string.
    fn extract_query_param(url: &str, name: &str) -> Option<String> {
        let query = url.split_once('?')?.1;
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if k == name {
                    return Some(v.to_string());
                }
            }
        }
        None
    }

    // ── Registration ─────────────────────────────────────────────────────────

    /// POST /oauth/register happy path — returns 201 with a client_id.
    #[tokio::test]
    async fn register_returns_client_id() {
        let app = oauth_app("admin-token");
        let body = serde_json::json!({
            "client_name": "my-client",
            "redirect_uris": ["https://example.com/callback"],
            "token_endpoint_auth_method": "none"
        });
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/register")
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::CREATED);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert!(
            json["client_id"].as_str().is_some(),
            "response must include client_id"
        );
        assert_eq!(json["client_name"].as_str().unwrap(), "my-client");
        assert_eq!(
            json["redirect_uris"][0].as_str().unwrap(),
            "https://example.com/callback"
        );
        assert_eq!(json["token_endpoint_auth_method"].as_str().unwrap(), "none");
    }

    /// POST /oauth/register with empty redirect_uris — rejects with 400.
    #[tokio::test]
    async fn register_requires_redirect_uris() {
        let app = oauth_app("admin-token");
        let body = serde_json::json!({
            "client_name": "bad-client",
            "redirect_uris": []
        });
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/register")
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"].as_str().unwrap(), "invalid_client_metadata");
    }

    /// The 6th POST /oauth/register within 60 s from the same IP returns 429.
    ///
    /// The registration bucket is hard-coded at 5 req / 60 s per IP. The test
    /// injects a consistent X-Forwarded-For header so all requests share one bucket.
    #[tokio::test]
    async fn register_rate_limited() {
        let app = oauth_app_tight_registration("admin-token");

        let good_body = serde_json::json!({
            "client_name": "client",
            "redirect_uris": ["https://example.com/cb"]
        })
        .to_string();

        // 5 requests — all must succeed (budget is exactly 5).
        for i in 0..5u8 {
            let req = Request::builder()
                .method("POST")
                .uri("/oauth/register")
                .header("Content-Type", "application/json")
                .header("X-Forwarded-For", "10.0.0.42")
                .body(Body::from(good_body.clone()))
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::CREATED,
                "request {i} should succeed"
            );
        }

        // 6th request — bucket exhausted, must be 429.
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/register")
            .header("Content-Type", "application/json")
            .header("X-Forwarded-For", "10.0.0.42")
            .body(Body::from(good_body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    // ── Authorization ─────────────────────────────────────────────────────────

    /// /authorize without code_challenge returns 400.
    #[tokio::test]
    async fn authorize_requires_pkce() {
        let app = oauth_app("admin-token");
        let client_id = register_client(app.clone(), &["https://example.com/cb"]).await;

        let req = Request::builder()
            .method("GET")
            .uri(format!(
                "/authorize?response_type=code&client_id={client_id}&redirect_uri=https://example.com/cb"
            ))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"].as_str().unwrap(), "invalid_request");
    }

    /// Unknown client + non-HTTPS, non-localhost redirect — returns 400.
    ///
    /// The is_safe_redirect_uri guard applies to unregistered clients: plain
    /// http://evil.com must be rejected before a code is issued.
    #[tokio::test]
    async fn authorize_requires_registered_client_or_safe_redirect() {
        let app = oauth_app("admin-token");
        let challenge = pkce_challenge("some-verifier");

        let req = Request::builder()
            .method("GET")
            .uri(format!(
                "/authorize?response_type=code&client_id=unknown-id&redirect_uri=http://evil.com/cb&code_challenge={challenge}&code_challenge_method=S256"
            ))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"].as_str().unwrap(), "invalid_request");
    }

    /// Registered client with a redirect_uri not in its registered list — returns 400.
    #[tokio::test]
    async fn authorize_validates_redirect_uri_for_registered_client() {
        let app = oauth_app("admin-token");
        let client_id = register_client(app.clone(), &["https://example.com/cb"]).await;
        let challenge = pkce_challenge("verifier");

        let req = Request::builder()
            .method("GET")
            .uri(format!(
                "/authorize?response_type=code&client_id={client_id}&redirect_uri=https://other.com/cb&code_challenge={challenge}&code_challenge_method=S256"
            ))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"].as_str().unwrap(), "invalid_request");
    }

    /// /authorize happy path — redirects with a `code` query parameter.
    #[tokio::test]
    async fn authorize_happy_path() {
        let app = oauth_app("admin-token");
        let client_id = register_client(app.clone(), &["https://example.com/cb"]).await;
        let challenge = pkce_challenge("my-verifier");

        let req = Request::builder()
            .method("GET")
            .uri(format!(
                "/authorize?response_type=code&client_id={client_id}&redirect_uri=https://example.com/cb&code_challenge={challenge}&code_challenge_method=S256"
            ))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        let status = resp.status().as_u16();
        assert!(
            status == 302 || status == 303,
            "expected redirect, got {status}"
        );
        let location = resp
            .headers()
            .get("location")
            .expect("missing Location header")
            .to_str()
            .unwrap();
        let code = extract_query_param(location, "code");
        assert!(
            code.is_some(),
            "Location must contain code param: {location}"
        );
        assert!(!code.unwrap().is_empty());
    }

    // ── Token exchange ────────────────────────────────────────────────────────

    /// Full flow: register → authorize → token exchange → access_token.
    #[tokio::test]
    async fn token_auth_code_happy_path() {
        let app = oauth_app("admin-token");
        let redirect_uri = "https://example.com/cb";
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        let client_id = register_client(app.clone(), &[redirect_uri]).await;
        let code = authorize(app.clone(), &client_id, redirect_uri, verifier, None, None).await;
        let resp = exchange_code(app, &client_id, &code, redirect_uri, verifier, None).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert!(
            json["access_token"].as_str().is_some(),
            "must have access_token"
        );
        assert_eq!(json["token_type"].as_str().unwrap(), "bearer");
        assert!(json["expires_in"].as_u64().unwrap() > 0);
    }

    /// Wrong PKCE verifier at token exchange — returns invalid_grant.
    #[tokio::test]
    async fn token_auth_code_bad_verifier() {
        let app = oauth_app("admin-token");
        let redirect_uri = "https://example.com/cb";
        let verifier = "correct-verifier-string-that-is-long-enough";

        let client_id = register_client(app.clone(), &[redirect_uri]).await;
        let code = authorize(app.clone(), &client_id, redirect_uri, verifier, None, None).await;
        // Deliberately use a different verifier.
        let resp =
            exchange_code(app, &client_id, &code, redirect_uri, "wrong-verifier", None).await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"].as_str().unwrap(), "invalid_grant");
    }

    /// Expired authorization code — token exchange returns invalid_grant.
    ///
    /// An already-expired row is inserted directly via Db::insert_auth_code so the
    /// test does not need to wait for a real timeout. This is the storage-agnostic
    /// injection point: if the backing store changes, only this setup changes; the
    /// HTTP assertion is identical.
    #[tokio::test]
    async fn token_auth_code_expired() {
        let token = "admin-token";
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
            rate_limit_read: 10_000,
            rate_limit_write: 10_000,
            rate_limit_window: 60,
            registration_limit: 5,
            registration_mode: crate::config::RegistrationMode::Open,
        };
        let rate_limit = crate::rate_limit::RateLimitStore::new(&config);

        let redirect_uri = "https://example.com/cb";
        let verifier = "test-verifier-for-expired-code";
        let challenge = pkce_challenge(verifier);
        let expired_code = "expired-code-0000000000000000000000000000000000000000";

        // Seed an expired auth code directly into the database.
        db.insert_auth_code(&crate::db::AuthCodeRow {
            code: expired_code.to_string(),
            client_id: "any-client".to_string(),
            redirect_uri: redirect_uri.to_string(),
            expires_at: "2000-01-01T00:00:00Z".to_string(), // firmly in the past
            code_challenge: challenge,
            resource: None,
            scope: None,
        })
        .expect("seed expired auth code");

        let state = crate::handlers::AppState {
            db,
            config: Arc::new(config),
            rate_limit: rate_limit.clone(),
        };
        let app = Router::new()
            .route("/oauth/register", post(crate::oauth::handle_register))
            .route("/authorize", get(crate::oauth::handle_authorize))
            .route("/oauth/token", post(crate::oauth::handle_oauth_token))
            .layer(axum::Extension(rate_limit))
            .with_state(state);

        let params = format!(
            "grant_type=authorization_code&client_id=any-client&code={expired_code}&redirect_uri={redirect_uri}&code_verifier={verifier}"
        );
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(params))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"].as_str().unwrap(), "invalid_grant");
    }

    /// Reusing an authorization code returns invalid_grant (codes are single-use).
    #[tokio::test]
    async fn token_auth_code_replay() {
        let app = oauth_app("admin-token");
        let redirect_uri = "https://example.com/cb";
        let verifier = "replay-test-verifier-long-enough-to-be-valid";

        let client_id = register_client(app.clone(), &[redirect_uri]).await;
        let code = authorize(app.clone(), &client_id, redirect_uri, verifier, None, None).await;

        // First exchange — must succeed.
        let resp1 =
            exchange_code(app.clone(), &client_id, &code, redirect_uri, verifier, None).await;
        assert_eq!(
            resp1.status(),
            StatusCode::OK,
            "first exchange must succeed"
        );

        // Second exchange with the same code — must fail.
        let resp2 = exchange_code(app, &client_id, &code, redirect_uri, verifier, None).await;
        assert_eq!(resp2.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(resp2.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"].as_str().unwrap(), "invalid_grant");
    }

    // ── Refresh token ─────────────────────────────────────────────────────────

    /// Full refresh rotation: register → authorize (offline_access) → exchange → refresh.
    #[tokio::test]
    async fn token_refresh_happy_path() {
        let app = oauth_app("admin-token");
        let redirect_uri = "https://example.com/cb";
        let verifier = "refresh-verifier-long-enough-to-be-valid-here";

        let client_id = register_client(app.clone(), &[redirect_uri]).await;
        let code = authorize(
            app.clone(),
            &client_id,
            redirect_uri,
            verifier,
            Some("mcp:tools offline_access"),
            None,
        )
        .await;
        let resp =
            exchange_code(app.clone(), &client_id, &code, redirect_uri, verifier, None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let token_resp: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        let refresh_token = token_resp["refresh_token"]
            .as_str()
            .expect("must have refresh_token when scope includes offline_access");

        // Use the refresh token.
        let params =
            format!("grant_type=refresh_token&client_id={client_id}&refresh_token={refresh_token}");
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(params))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let rotated: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert!(rotated["access_token"].as_str().is_some());
        // Rotation: new refresh token must be present and different.
        let new_rt = rotated["refresh_token"]
            .as_str()
            .expect("rotated refresh_token must be present");
        assert_ne!(new_rt, refresh_token, "refresh token must rotate on use");
    }

    /// Expired refresh token returns invalid_grant.
    ///
    /// The stale row is inserted directly via Db::insert_refresh_token so the
    /// test does not wait for a real expiry. Storage-agnostic injection point.
    #[tokio::test]
    async fn token_refresh_expired() {
        let token = "admin-token";
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
            rate_limit_read: 10_000,
            rate_limit_write: 10_000,
            rate_limit_window: 60,
            registration_limit: 5,
            registration_mode: crate::config::RegistrationMode::Open,
        };
        let rate_limit = crate::rate_limit::RateLimitStore::new(&config);

        let stale_rt = "stale-refresh-token-value-00000000000000000000000000000000";
        let client_id = "test-client-for-expired-rt";

        // Seed an already-expired refresh token directly into the database.
        db.insert_refresh_token(&crate::db::RefreshTokenRow {
            token: stale_rt.to_string(),
            client_id: client_id.to_string(),
            access_token: "old-access-token".to_string(),
            scope: Some("mcp:tools offline_access".to_string()),
            expires_at: "2000-01-01T00:00:00Z".to_string(), // firmly in the past
        })
        .expect("seed stale refresh token");

        let state = crate::handlers::AppState {
            db,
            config: Arc::new(config),
            rate_limit: rate_limit.clone(),
        };
        let app = Router::new()
            .route("/oauth/register", post(crate::oauth::handle_register))
            .route("/authorize", get(crate::oauth::handle_authorize))
            .route("/oauth/token", post(crate::oauth::handle_oauth_token))
            .layer(axum::Extension(rate_limit))
            .with_state(state);

        let params =
            format!("grant_type=refresh_token&client_id={client_id}&refresh_token={stale_rt}");
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(params))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"].as_str().unwrap(), "invalid_grant");
    }

    // ── Client credentials ────────────────────────────────────────────────────

    /// client_credentials with the admin secret returns an access_token.
    #[tokio::test]
    async fn token_client_credentials_happy_path() {
        let admin_token = "super-secret-admin-token";
        let app = oauth_app(admin_token);

        let body = format!(
            "grant_type=client_credentials&client_id=my-service&client_secret={admin_token}"
        );
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(json["access_token"].as_str().is_some());
        assert_eq!(json["token_type"].as_str().unwrap(), "bearer");
    }

    /// client_credentials with a wrong secret returns 401 invalid_client.
    #[tokio::test]
    async fn token_client_credentials_bad_secret() {
        let app = oauth_app("real-admin-token");

        let body = "grant_type=client_credentials&client_id=attacker&client_secret=wrong-secret";
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"].as_str().unwrap(), "invalid_client");
    }

    // ── Scope ─────────────────────────────────────────────────────────────────

    /// scope from /authorize is preserved in the token response.
    #[tokio::test]
    async fn authorize_scope_stored() {
        let app = oauth_app("admin-token");
        let redirect_uri = "https://example.com/cb";
        let verifier = "scope-test-verifier-long-enough-to-be-valid";

        let client_id = register_client(app.clone(), &[redirect_uri]).await;
        let code = authorize(
            app.clone(),
            &client_id,
            redirect_uri,
            verifier,
            Some("mcp:tools"),
            None,
        )
        .await;
        let resp = exchange_code(app, &client_id, &code, redirect_uri, verifier, None).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let scope = json["scope"]
            .as_str()
            .expect("scope must be present in token response");
        assert!(
            scope.contains("mcp:tools"),
            "scope must round-trip: got {scope}"
        );
    }

    // ── P3-16: OAuth scope enforcement regression tests ───────────────────────
    //
    // These tests lock in the can_write() gate wired at post_document, put_document,
    // delete_document, and the MCP tool handlers. An OAuth client with no scope
    // (empty scope string) must not be able to perform write operations.
    //
    // Strategy: seed an access token directly into the DB (same pattern as the
    // token_auth_code_expired test), build a router that exposes both document
    // endpoints and OAuth routes, then assert HTTP status codes.

    /// Build a combined app with document write endpoints and OAuth routes,
    /// backed by the provided in-memory Db. Mirrors main.rs route registration.
    fn combined_app(admin_token: &str, db: crate::db::Db) -> Router {
        let config = crate::config::ServeConfig {
            token: admin_token.to_string(),
            db_path: ":memory:".to_string(),
            bind: "127.0.0.1:0".to_string(),
            base_url: "http://localhost".to_string(),
            default_theme: "clean".to_string(),
            max_size: 1_048_576,
            webhook_url: None,
            webhook_secret: None,
            reaper_interval: 3600,
            rate_limit_read: 10_000,
            rate_limit_write: 10_000,
            rate_limit_window: 60,
            registration_limit: 5,
            registration_mode: crate::config::RegistrationMode::Open,
        };
        let rate_limit = crate::rate_limit::RateLimitStore::new(&config);
        let state = crate::handlers::AppState {
            db,
            config: Arc::new(config),
            rate_limit: rate_limit.clone(),
        };
        Router::new()
            .route("/oauth/register", post(crate::oauth::handle_register))
            .route("/authorize", get(crate::oauth::handle_authorize))
            .route("/oauth/token", post(crate::oauth::handle_oauth_token))
            .route(
                "/api/v1/documents",
                post(crate::handlers::post_document).get(crate::handlers::list_documents),
            )
            .route(
                "/api/v1/documents/:slug",
                axum::routing::put(crate::handlers::put_document)
                    .delete(crate::handlers::delete_document),
            )
            .layer(axum::Extension(rate_limit))
            .with_state(state)
    }

    /// Future timestamp for token expiry — well beyond any test run.
    fn far_future() -> String {
        "2099-01-01T00:00:00Z".to_string()
    }

    /// Admin/managed token always passes can_write() — positive control.
    ///
    /// If this fails, the test harness itself is broken.
    #[tokio::test]
    async fn admin_token_can_write_post_document() {
        let admin = "admin-token";
        let db = crate::db::Db::open(":memory:").expect("in-memory db");
        let app = combined_app(admin, db);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/documents")
            .header("Authorization", format!("Bearer {admin}"))
            .header("Content-Type", "text/markdown")
            .body(Body::from("# Admin write test"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "admin token must be able to write"
        );
    }

    /// OAuth client with mcp:tools scope passes can_write() at POST /api/v1/documents.
    #[tokio::test]
    async fn oauth_with_mcp_tools_scope_can_write() {
        let admin = "admin-token";
        let db = crate::db::Db::open(":memory:").expect("in-memory db");

        // Seed an access token with mcp:tools scope directly.
        let token_value = "oauth-access-token-with-write-scope";
        db.insert_access_token(&crate::db::AccessTokenRow {
            token: token_value.to_string(),
            client_id: "test-client".to_string(),
            scope: Some("mcp:tools".to_string()),
            expires_at: far_future(),
        })
        .expect("seed access token");

        let app = combined_app(admin, db);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/documents")
            .header("Authorization", format!("Bearer {token_value}"))
            .header("Content-Type", "text/markdown")
            .body(Body::from("# OAuth write test"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "OAuth token with mcp:tools scope must be able to write"
        );
    }

    /// OAuth client with empty scope is blocked at POST /api/v1/documents — 403 Forbidden.
    ///
    /// This is the primary regression guard: an OAuth client that omits scope
    /// must not bypass the can_write() gate even though it authenticates.
    #[tokio::test]
    async fn oauth_with_empty_scope_cannot_write_post_document() {
        let admin = "admin-token";
        let db = crate::db::Db::open(":memory:").expect("in-memory db");

        // Seed an access token with NULL scope (empty scope string).
        let token_value = "oauth-access-token-no-scope";
        db.insert_access_token(&crate::db::AccessTokenRow {
            token: token_value.to_string(),
            client_id: "test-client-no-scope".to_string(),
            scope: None,
            expires_at: far_future(),
        })
        .expect("seed no-scope access token");

        let app = combined_app(admin, db);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/documents")
            .header("Authorization", format!("Bearer {token_value}"))
            .header("Content-Type", "text/markdown")
            .body(Body::from("# Should be blocked"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "OAuth token with no scope must be denied write access (403)"
        );
    }

    /// ── P3-16 MCP gate: OAuth token with empty scope is blocked at twofold_publish ──
    ///
    /// Covers the can_write() guard in mcp_http::tool_publish. The MCP handler
    /// returns a JSON-RPC result (not an HTTP error) when the principal lacks
    /// write access, so we check the JSON-RPC body for the expected error text.
    #[tokio::test]
    async fn oauth_with_empty_scope_cannot_write_mcp_publish() {
        let admin = "admin-token";
        let db = crate::db::Db::open(":memory:").expect("in-memory db");

        let token_value = "oauth-mcp-no-scope";
        db.insert_access_token(&crate::db::AccessTokenRow {
            token: token_value.to_string(),
            client_id: "mcp-client-no-scope".to_string(),
            scope: None,
            expires_at: far_future(),
        })
        .expect("seed no-scope access token for MCP");

        let config = crate::config::ServeConfig {
            token: admin.to_string(),
            db_path: ":memory:".to_string(),
            bind: "127.0.0.1:0".to_string(),
            base_url: "http://localhost".to_string(),
            default_theme: "clean".to_string(),
            max_size: 1_048_576,
            webhook_url: None,
            webhook_secret: None,
            reaper_interval: 3600,
            rate_limit_read: 10_000,
            rate_limit_write: 10_000,
            rate_limit_window: 60,
            registration_limit: 5,
            registration_mode: crate::config::RegistrationMode::Open,
        };
        let rate_limit = crate::rate_limit::RateLimitStore::new(&config);
        let state = crate::handlers::AppState {
            db,
            config: Arc::new(config),
            rate_limit: rate_limit.clone(),
        };
        let app = Router::new()
            .route("/mcp", post(crate::mcp_http::handle_mcp_post))
            .layer(axum::Extension(rate_limit))
            .with_state(state);

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "twofold_publish",
                "arguments": {
                    "content": "# Test",
                    "slug": "test-mcp"
                }
            }
        });
        let req = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("Authorization", format!("Bearer {token_value}"))
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "MCP always returns 200");
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        // tool_publish returns a JSON-RPC result containing an isError=true content block.
        let result = &json["result"];
        assert!(
            result["isError"].as_bool() == Some(true)
                || result["content"][0]["text"]
                    .as_str()
                    .map(|t| t.contains("Forbidden"))
                    .unwrap_or(false),
            "MCP twofold_publish with no-scope OAuth must be forbidden: {json}"
        );
    }

    /// resource mismatch between /authorize and /oauth/token — returns invalid_grant.
    ///
    /// RFC 8707: if the authorization code captured a resource, the token request
    /// must present the same value.
    #[tokio::test]
    async fn resource_binding() {
        let app = oauth_app("admin-token");
        let redirect_uri = "https://example.com/cb";
        let verifier = "resource-binding-verifier-long-enough";

        let client_id = register_client(app.clone(), &[redirect_uri]).await;
        // Authorize binding resource=https://api.example.com
        let code = authorize(
            app.clone(),
            &client_id,
            redirect_uri,
            verifier,
            None,
            Some("https://api.example.com"),
        )
        .await;

        // Token exchange with a different resource — must be rejected.
        let resp = exchange_code(
            app,
            &client_id,
            &code,
            redirect_uri,
            verifier,
            Some("https://other.example.com"),
        )
        .await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"].as_str().unwrap(), "invalid_grant");
    }

    // ── Closed registration mode ──────────────────────────────────────────────

    /// Build an OAuth router with TWOFOLD_REGISTRATION_MODE=closed.
    fn oauth_app_closed(token: &str) -> (Router, crate::db::Db) {
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
            rate_limit_read: 10_000,
            rate_limit_write: 10_000,
            rate_limit_window: 60,
            registration_limit: 5,
            registration_mode: crate::config::RegistrationMode::Closed,
        };
        let rate_limit = crate::rate_limit::RateLimitStore::new(&config);
        let state = crate::handlers::AppState {
            db: db.clone(),
            config: Arc::new(config),
            rate_limit: rate_limit.clone(),
        };
        let router = Router::new()
            .route(
                "/.well-known/oauth-authorization-server",
                get(crate::oauth::handle_authorization_server_metadata),
            )
            .route("/oauth/register", post(crate::oauth::handle_register))
            .route("/authorize", get(crate::oauth::handle_authorize))
            .route("/oauth/token", post(crate::oauth::handle_oauth_token))
            .layer(axum::Extension(rate_limit))
            .with_state(state);
        (router, db)
    }

    /// POST /oauth/register when mode is Closed returns 403 registration_disabled.
    #[tokio::test]
    async fn register_disabled_in_closed_mode() {
        let (app, _db) = oauth_app_closed("admin-token");
        let body = serde_json::json!({
            "client_name": "my-client",
            "redirect_uris": ["https://example.com/cb"],
            "token_endpoint_auth_method": "none"
        });
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/register")
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            json["error"].as_str().unwrap(),
            "registration_disabled",
            "closed mode must return registration_disabled"
        );
    }

    /// POST /oauth/register when mode is Open works (existing behaviour preserved).
    #[tokio::test]
    async fn register_allowed_in_open_mode() {
        let app = oauth_app("admin-token");
        let body = serde_json::json!({
            "client_name": "my-client",
            "redirect_uris": ["https://example.com/cb"],
            "token_endpoint_auth_method": "none"
        });
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/register")
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    /// Metadata omits registration_endpoint when mode is Closed.
    #[tokio::test]
    async fn metadata_omits_registration_endpoint_in_closed_mode() {
        let (app, _db) = oauth_app_closed("admin-token");
        let req = Request::builder()
            .method("GET")
            .uri("/.well-known/oauth-authorization-server")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            json["registration_endpoint"].is_null(),
            "registration_endpoint must be absent in closed mode, got: {json}"
        );
    }

    /// Metadata includes registration_endpoint when mode is Open.
    #[tokio::test]
    async fn metadata_includes_registration_endpoint_in_open_mode() {
        let db = crate::db::Db::open(":memory:").expect("in-memory db");
        let config = crate::config::ServeConfig {
            token: "tok".to_string(),
            db_path: ":memory:".to_string(),
            bind: "127.0.0.1:0".to_string(),
            base_url: "http://localhost".to_string(),
            default_theme: "clean".to_string(),
            max_size: 1_048_576,
            webhook_url: None,
            webhook_secret: None,
            reaper_interval: 3600,
            rate_limit_read: 10_000,
            rate_limit_write: 10_000,
            rate_limit_window: 60,
            registration_limit: 5,
            registration_mode: crate::config::RegistrationMode::Open,
        };
        let rate_limit = crate::rate_limit::RateLimitStore::new(&config);
        let state = crate::handlers::AppState {
            db,
            config: Arc::new(config),
            rate_limit: rate_limit.clone(),
        };
        let app = Router::new()
            .route(
                "/.well-known/oauth-authorization-server",
                get(crate::oauth::handle_authorization_server_metadata),
            )
            .layer(axum::Extension(rate_limit))
            .with_state(state);
        let req = Request::builder()
            .method("GET")
            .uri("/.well-known/oauth-authorization-server")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            json["registration_endpoint"].as_str().is_some(),
            "registration_endpoint must be present in open mode, got: {json}"
        );
    }

    // ── Confidential client (stored client_secret) auth tests ─────────────────

    /// Helper: seed a provisioned confidential client into a Db.
    fn seed_provisioned_client(
        db: &crate::db::Db,
        client_id: &str,
        redirect_uri: &str,
        secret: &str,
    ) {
        db.insert_oauth_client(&crate::db::OAuthClientRow {
            client_id: client_id.to_string(),
            client_name: "test-confidential".to_string(),
            redirect_uris: serde_json::json!([redirect_uri]).to_string(),
            grant_types: serde_json::json!(["authorization_code"]).to_string(),
            response_types: serde_json::json!(["code"]).to_string(),
            token_endpoint_auth_method: "client_secret_post".to_string(),
            created_at: "2025-01-01T00:00:00Z".to_string(),
            provisioned: true,
            client_secret: Some(secret.to_string()),
        })
        .expect("seed provisioned client");
    }

    /// Build an app that has a provisioned confidential client pre-seeded.
    fn oauth_app_with_confidential_client(
        token: &str,
        client_id: &str,
        redirect_uri: &str,
        secret: &str,
    ) -> Router {
        let db = crate::db::Db::open(":memory:").expect("in-memory db");
        seed_provisioned_client(&db, client_id, redirect_uri, secret);
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
            rate_limit_read: 10_000,
            rate_limit_write: 10_000,
            rate_limit_window: 60,
            registration_limit: 5,
            registration_mode: crate::config::RegistrationMode::Closed,
        };
        let rate_limit = crate::rate_limit::RateLimitStore::new(&config);
        let state = crate::handlers::AppState {
            db,
            config: Arc::new(config),
            rate_limit: rate_limit.clone(),
        };
        Router::new()
            .route("/oauth/register", post(crate::oauth::handle_register))
            .route("/authorize", get(crate::oauth::handle_authorize))
            .route("/oauth/token", post(crate::oauth::handle_oauth_token))
            .layer(axum::Extension(rate_limit))
            .with_state(state)
    }

    /// Token exchange succeeds with correct client_secret for a confidential client.
    #[tokio::test]
    async fn token_exchange_confidential_client_correct_secret() {
        let client_id = "conf-client-correct";
        let redirect_uri = "https://claude.ai/api/mcp/auth_callback";
        let secret = "super-secret-64-char-hex-value-0000000000000000000000000000000000";
        let app = oauth_app_with_confidential_client("admin", client_id, redirect_uri, secret);
        let verifier = "confidential-client-test-verifier-long-enough-here";

        let code = authorize(
            app.clone(),
            client_id,
            redirect_uri,
            verifier,
            Some("mcp:tools"),
            None,
        )
        .await;

        // Exchange with correct secret.
        let params = format!(
            "grant_type=authorization_code&client_id={client_id}&code={code}&redirect_uri={redirect_uri}&code_verifier={verifier}&client_secret={secret}"
        );
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(params))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK, "correct secret must succeed");
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            json["access_token"].as_str().is_some(),
            "must have access_token"
        );
    }

    /// Token exchange fails with wrong client_secret for a confidential client.
    #[tokio::test]
    async fn token_exchange_confidential_client_wrong_secret() {
        let client_id = "conf-client-wrong";
        let redirect_uri = "https://claude.ai/api/mcp/auth_callback";
        let secret = "real-secret-value-0000000000000000000000000000000000000000000000";
        let app = oauth_app_with_confidential_client("admin", client_id, redirect_uri, secret);
        let verifier = "confidential-client-wrong-verifier-long-enough";

        let code = authorize(
            app.clone(),
            client_id,
            redirect_uri,
            verifier,
            Some("mcp:tools"),
            None,
        )
        .await;

        let params = format!(
            "grant_type=authorization_code&client_id={client_id}&code={code}&redirect_uri={redirect_uri}&code_verifier={verifier}&client_secret=wrong-secret"
        );
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(params))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "wrong secret must return 401"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"].as_str().unwrap(), "invalid_client");
    }

    /// Token exchange fails when client_secret is missing for a confidential client.
    #[tokio::test]
    async fn token_exchange_confidential_client_missing_secret() {
        let client_id = "conf-client-missing";
        let redirect_uri = "https://claude.ai/api/mcp/auth_callback";
        let secret = "stored-secret-00000000000000000000000000000000000000000000000000";
        let app = oauth_app_with_confidential_client("admin", client_id, redirect_uri, secret);
        let verifier = "confidential-client-missing-verifier-long-enough-h";

        let code = authorize(
            app.clone(),
            client_id,
            redirect_uri,
            verifier,
            Some("mcp:tools"),
            None,
        )
        .await;

        // No client_secret provided.
        let params = format!(
            "grant_type=authorization_code&client_id={client_id}&code={code}&redirect_uri={redirect_uri}&code_verifier={verifier}"
        );
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(params))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "missing secret for confidential client must return 401"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"].as_str().unwrap(), "invalid_client");
    }

    /// Token exchange succeeds without a secret for a public client (no secret in DB).
    #[tokio::test]
    async fn token_exchange_public_client_no_secret_succeeds() {
        // Dynamically registered public client — no client_secret in DB.
        let app = oauth_app("admin-token");
        let redirect_uri = "https://example.com/cb";
        let verifier = "public-client-no-secret-verifier-long-enough-here";

        let client_id = register_client(app.clone(), &[redirect_uri]).await;
        let code = authorize(app.clone(), &client_id, redirect_uri, verifier, None, None).await;
        let resp = exchange_code(app, &client_id, &code, redirect_uri, verifier, None).await;

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "public client without stored secret must succeed without secret"
        );
    }

    // ── Closed mode: unknown client_id rejection ──────────────────────────────

    /// Helper: seed a provisioned public client (no client_secret) into a Db.
    fn seed_provisioned_public_client(db: &crate::db::Db, client_id: &str, redirect_uri: &str) {
        db.insert_oauth_client(&crate::db::OAuthClientRow {
            client_id: client_id.to_string(),
            client_name: "test-public-provisioned".to_string(),
            redirect_uris: serde_json::json!([redirect_uri]).to_string(),
            grant_types: serde_json::json!(["authorization_code"]).to_string(),
            response_types: serde_json::json!(["code"]).to_string(),
            token_endpoint_auth_method: "none".to_string(),
            created_at: "2025-01-01T00:00:00Z".to_string(),
            provisioned: true,
            client_secret: None,
        })
        .expect("seed provisioned public client");
    }

    /// Build a closed-mode app with a pre-seeded provisioned public client; returns (Router, Db).
    fn oauth_app_closed_with_public_client(
        token: &str,
        client_id: &str,
        redirect_uri: &str,
    ) -> (Router, crate::db::Db) {
        let db = crate::db::Db::open(":memory:").expect("in-memory db");
        seed_provisioned_public_client(&db, client_id, redirect_uri);
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
            rate_limit_read: 10_000,
            rate_limit_write: 10_000,
            rate_limit_window: 60,
            registration_limit: 5,
            registration_mode: crate::config::RegistrationMode::Closed,
        };
        let rate_limit = crate::rate_limit::RateLimitStore::new(&config);
        let state = crate::handlers::AppState {
            db: db.clone(),
            config: Arc::new(config),
            rate_limit: rate_limit.clone(),
        };
        let router = Router::new()
            .route("/oauth/register", post(crate::oauth::handle_register))
            .route("/authorize", get(crate::oauth::handle_authorize))
            .route("/oauth/token", post(crate::oauth::handle_oauth_token))
            .layer(axum::Extension(rate_limit))
            .with_state(state);
        (router, db)
    }

    /// In closed mode, /authorize with an unknown client_id returns invalid_client.
    #[tokio::test]
    async fn closed_mode_authorize_unknown_client_rejected() {
        let (app, _db) = oauth_app_closed("admin-token");
        let verifier = "closed-mode-unknown-client-verifier-long-enough";
        let challenge = pkce_challenge(verifier);
        let redirect_uri = "https://example.com/cb";

        let req = Request::builder()
            .method("GET")
            .uri(format!(
                "/authorize?response_type=code&client_id=fabricated-client-id\
                 &redirect_uri={redirect_uri}\
                 &code_challenge={challenge}&code_challenge_method=S256"
            ))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "closed mode must reject unknown client_id at /authorize"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            json["error"].as_str().unwrap(),
            "invalid_client",
            "must return invalid_client error"
        );
    }

    /// In closed mode, token exchange with an unknown client_id returns invalid_client.
    ///
    /// Scenario: an auth code exists in the DB (e.g., inserted by a provisioned client
    /// that was subsequently deleted) but the client_id is no longer registered. The token
    /// handler must reject with invalid_client rather than falling through to the public
    /// client path.
    #[tokio::test]
    async fn closed_mode_token_exchange_unknown_client_rejected() {
        let client_id = "closed-token-unknown";
        let redirect_uri = "https://example.com/cb";
        let verifier = "closed-token-exchange-verifier-long-enough-here-0";
        let challenge = pkce_challenge(verifier);

        // Build a closed-mode app. Seed an auth code directly for a client_id that
        // is NOT registered in the DB — this is the "someone bypassed /authorize" scenario.
        let (app, db) = oauth_app_closed("admin-token");

        db.insert_auth_code(&crate::db::AuthCodeRow {
            code: "fabricated-auth-code-0000000000000000000000000000000000000000000000".to_string(),
            client_id: client_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
            expires_at: "2099-01-01T00:00:00Z".to_string(),
            code_challenge: challenge,
            resource: None,
            scope: None,
        })
        .expect("seed auth code");

        let params = format!(
            "grant_type=authorization_code&client_id={client_id}\
             &code=fabricated-auth-code-0000000000000000000000000000000000000000000000\
             &redirect_uri={redirect_uri}&code_verifier={verifier}"
        );
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(params))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "closed mode must reject token exchange for unknown client_id"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"].as_str().unwrap(), "invalid_client");
    }

    /// In closed mode, a provisioned public client can still authorize and exchange tokens.
    #[tokio::test]
    async fn closed_mode_provisioned_public_client_works() {
        let client_id = "closed-provisioned-public";
        let redirect_uri = "https://example.com/cb";
        let verifier = "closed-provisioned-public-verifier-long-enough-h";
        let (app, _db) =
            oauth_app_closed_with_public_client("admin-token", client_id, redirect_uri);

        let code = authorize(app.clone(), client_id, redirect_uri, verifier, None, None).await;
        let params = format!(
            "grant_type=authorization_code&client_id={client_id}&code={code}\
             &redirect_uri={redirect_uri}&code_verifier={verifier}"
        );
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(params))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "provisioned public client must still work in closed mode"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            json["access_token"].as_str().is_some(),
            "must receive access_token"
        );
    }

    /// In closed mode, a provisioned confidential client can still authorize and exchange tokens.
    #[tokio::test]
    async fn closed_mode_provisioned_confidential_client_works() {
        let client_id = "closed-provisioned-conf";
        let redirect_uri = "https://claude.ai/api/mcp/auth_callback";
        let secret = "closed-mode-conf-secret-0000000000000000000000000000000000000000000";
        let verifier = "closed-mode-confidential-client-verifier-long-enough";
        let app =
            oauth_app_with_confidential_client("admin-token", client_id, redirect_uri, secret);

        let code = authorize(
            app.clone(),
            client_id,
            redirect_uri,
            verifier,
            Some("mcp:tools"),
            None,
        )
        .await;

        let params = format!(
            "grant_type=authorization_code&client_id={client_id}&code={code}\
             &redirect_uri={redirect_uri}&code_verifier={verifier}&client_secret={secret}"
        );
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(params))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "provisioned confidential client must still work in closed mode"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            json["access_token"].as_str().is_some(),
            "must receive access_token"
        );
    }

    /// In open mode, unknown client_ids still fall through (backward compat preserved).
    #[tokio::test]
    async fn open_mode_unknown_client_fallthrough_preserved() {
        let app = oauth_app("admin-token");
        let verifier = "open-mode-fallthrough-verifier-long-enough-here";
        let redirect_uri = "https://example.com/cb";

        // Fabricate a client_id not in the DB. In open mode this should succeed.
        let code = authorize(
            app.clone(),
            "open-fabricated-client",
            redirect_uri,
            verifier,
            None,
            None,
        )
        .await;
        let resp = exchange_code(
            app,
            "open-fabricated-client",
            &code,
            redirect_uri,
            verifier,
            None,
        )
        .await;

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "open mode must still allow unknown client fallthrough"
        );
    }

    /// Revoked provisioned client cannot re-authorize in closed mode.
    #[tokio::test]
    async fn closed_mode_revoked_client_rejected_at_authorize() {
        let client_id = "closed-revoked-client";
        let redirect_uri = "https://example.com/cb";
        let verifier = "closed-revoked-client-verifier-long-enough-here";
        let (app, db) = oauth_app_closed_with_public_client("admin-token", client_id, redirect_uri);

        // Confirm it works before revocation.
        let _code = authorize(app.clone(), client_id, redirect_uri, verifier, None, None).await;

        // Revoke.
        db.revoke_provisioned_client(client_id)
            .expect("revoke client");

        // Now /authorize should reject.
        let challenge = pkce_challenge(verifier);
        let req = Request::builder()
            .method("GET")
            .uri(format!(
                "/authorize?response_type=code&client_id={client_id}\
                 &redirect_uri={redirect_uri}\
                 &code_challenge={challenge}&code_challenge_method=S256"
            ))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "revoked client must be rejected at /authorize in closed mode"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"].as_str().unwrap(), "invalid_client");
    }

    // ── Confidential client refresh_token flow (F5) ───────────────────────────

    /// Helper: perform a full authorize + token exchange for a confidential client
    /// with offline_access scope; returns the refresh_token string.
    async fn get_refresh_token_for_confidential_client(
        app: Router,
        client_id: &str,
        redirect_uri: &str,
        verifier: &str,
        secret: &str,
    ) -> String {
        let code = authorize(
            app.clone(),
            client_id,
            redirect_uri,
            verifier,
            Some("mcp:tools offline_access"),
            None,
        )
        .await;
        let params = format!(
            "grant_type=authorization_code&client_id={client_id}&code={code}\
             &redirect_uri={redirect_uri}&code_verifier={verifier}&client_secret={secret}"
        );
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(params))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "initial token exchange failed"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        json["refresh_token"]
            .as_str()
            .expect("no refresh_token in response")
            .to_string()
    }

    /// Confidential client refresh_token succeeds with the correct client_secret.
    #[tokio::test]
    async fn refresh_token_confidential_client_correct_secret() {
        let client_id = "conf-rt-correct";
        let redirect_uri = "https://claude.ai/api/mcp/auth_callback";
        let secret = "rt-correct-secret-0000000000000000000000000000000000000000000000";
        let verifier = "rt-correct-secret-verifier-long-enough-here-00000";
        let app =
            oauth_app_with_confidential_client("admin-token", client_id, redirect_uri, secret);

        let refresh_token = get_refresh_token_for_confidential_client(
            app.clone(),
            client_id,
            redirect_uri,
            verifier,
            secret,
        )
        .await;

        let params = format!(
            "grant_type=refresh_token&client_id={client_id}\
             &refresh_token={refresh_token}&client_secret={secret}"
        );
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(params))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "refresh with correct secret must succeed"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            json["access_token"].as_str().is_some(),
            "must receive new access_token"
        );
        assert!(
            json["refresh_token"].as_str().is_some(),
            "must receive new refresh_token (rotation)"
        );
    }

    /// Confidential client refresh_token fails with the wrong client_secret.
    #[tokio::test]
    async fn refresh_token_confidential_client_wrong_secret() {
        let client_id = "conf-rt-wrong";
        let redirect_uri = "https://claude.ai/api/mcp/auth_callback";
        let secret = "rt-real-secret-000000000000000000000000000000000000000000000000";
        let verifier = "rt-wrong-secret-verifier-long-enough-here-000000000";
        let app =
            oauth_app_with_confidential_client("admin-token", client_id, redirect_uri, secret);

        let refresh_token = get_refresh_token_for_confidential_client(
            app.clone(),
            client_id,
            redirect_uri,
            verifier,
            secret,
        )
        .await;

        let params = format!(
            "grant_type=refresh_token&client_id={client_id}\
             &refresh_token={refresh_token}&client_secret=totally-wrong-secret"
        );
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(params))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "refresh with wrong secret must return 401"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"].as_str().unwrap(), "invalid_client");
    }

    /// Confidential client refresh_token fails when the secret is missing entirely.
    #[tokio::test]
    async fn refresh_token_confidential_client_missing_secret() {
        let client_id = "conf-rt-missing";
        let redirect_uri = "https://claude.ai/api/mcp/auth_callback";
        let secret = "rt-missing-secret-00000000000000000000000000000000000000000000000";
        let verifier = "rt-missing-secret-verifier-long-enough-here-00000000";
        let app =
            oauth_app_with_confidential_client("admin-token", client_id, redirect_uri, secret);

        let refresh_token = get_refresh_token_for_confidential_client(
            app.clone(),
            client_id,
            redirect_uri,
            verifier,
            secret,
        )
        .await;

        // No client_secret in the refresh request.
        let params =
            format!("grant_type=refresh_token&client_id={client_id}&refresh_token={refresh_token}");
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(params))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "refresh with missing secret for confidential client must return 401"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"].as_str().unwrap(), "invalid_client");
    }
}
