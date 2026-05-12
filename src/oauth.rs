/// OAuth 2.0 Authorization Code flow + Client Credentials grant
///
/// Routes:
///   GET  /authorize          — Authorization Code: validate, issue code, 302 redirect
///   POST /oauth/token        — Token exchange (authorization_code or client_credentials)
///
/// Authorization Code flow (used by Cowork remote connector):
///   1. Client opens browser to GET /authorize?response_type=code&client_id=...
///      &redirect_uri=...&state=...
///   2. Server auto-approves (no consent screen — trusted server). Generates a
///      random code, stores it in-memory with a 5-minute expiry, redirects to
///      redirect_uri?code=CODE&state=STATE.
///   3. Client exchanges code via POST /oauth/token with grant_type=authorization_code.
///   4. Server validates code (exists, not expired, client_id matches, redirect_uri
///      matches), then validates client_secret, and returns an access_token.
///
/// Client Credentials flow (existing, unchanged):
///   POST /oauth/token with grant_type=client_credentials.
///   Validates client_secret directly and returns it as access_token.
///
/// On failure returns RFC 6749 error response with 400/401.
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::handlers::{check_auth_token, chrono_now, AppState};

// chrono re-exported for expiry arithmetic in handle_authorize
use chrono;

// ── Request shapes ────────────────────────────────────────────────────────────

/// Query parameters for GET /authorize
#[derive(Debug, Deserialize)]
pub struct AuthorizeParams {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub state: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenRequest {
    grant_type: String,
    client_id: Option<String>,
    client_secret: Option<String>,
    /// Authorization code (authorization_code grant only)
    code: Option<String>,
    /// Must match what was sent in /authorize (authorization_code grant only)
    redirect_uri: Option<String>,
}

// ── Response shapes ───────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u32,
}

#[derive(Debug, Serialize)]
struct OAuthError {
    error: &'static str,
    error_description: &'static str,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// GET /authorize — Authorization Code flow entry point.
///
/// Auto-approves without a consent screen (trusted server). Generates a random
/// authorization code, stores it in the in-memory map with a 5-minute TTL, and
/// 302-redirects the browser to `redirect_uri?code=CODE&state=STATE`.
///
/// Required params: response_type=code, client_id, redirect_uri.
/// Optional: state (passed through unchanged).
pub async fn handle_authorize(
    State(state): State<AppState>,
    Query(params): Query<AuthorizeParams>,
) -> Response {
    // Validate response_type — only "code" is supported.
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

    // Generate a random 32-byte authorization code, hex-encoded (64 chars).
    let code = {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        hex_encode(&bytes)
    };

    // Compute 5-minute expiry.
    let expires_at = {
        let future = chrono::Utc::now() + chrono::Duration::minutes(5);
        future.format("%Y-%m-%dT%H:%M:%SZ").to_string()
    };

    // Store the code.
    {
        let mut codes = state.auth_codes.lock().unwrap();
        codes.insert(
            code.clone(),
            crate::handlers::AuthCodeRecord {
                client_id: client_id.clone(),
                redirect_uri: redirect_uri.clone(),
                expires_at,
            },
        );
    }

    tracing::info!(client_id = %client_id, "OAuth authorization_code issued");

    // Build redirect URL: redirect_uri?code=CODE[&state=STATE]
    let redirect_url = match params.state.as_deref() {
        Some(s) if !s.is_empty() => format!(
            "{}{}code={}&state={}",
            redirect_uri,
            if redirect_uri.contains('?') { "&" } else { "?" },
            code,
            s,
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

/// POST /oauth/token — token exchange for both grant types.
pub async fn handle_oauth_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // Parse the request body based on content-type.
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let req = if content_type.starts_with("application/json") {
        match serde_json::from_slice::<TokenRequest>(&body) {
            Ok(r) => r,
            Err(_) => return invalid_request(),
        }
    } else {
        // Default: treat as application/x-www-form-urlencoded.
        let body_str = match std::str::from_utf8(&body) {
            Ok(s) => s,
            Err(_) => return invalid_request(),
        };
        match parse_form(body_str) {
            Some(r) => r,
            None => return invalid_request(),
        }
    };

    match req.grant_type.as_str() {
        "client_credentials" => handle_client_credentials(state, req).await,
        "authorization_code" => handle_authorization_code(state, req).await,
        _ => unsupported_grant_type(),
    }
}

/// Handle the client_credentials grant (existing behavior).
async fn handle_client_credentials(state: AppState, req: TokenRequest) -> Response {
    let client_id = req.client_id.as_deref().unwrap_or("<unset>");

    let secret = match req.client_secret.as_deref() {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return invalid_request(),
    };

    match check_auth_token(&state, &secret).await {
        Ok(()) => {
            tracing::info!(client_id = %client_id, "OAuth client_credentials grant issued");
            let resp = TokenResponse {
                access_token: secret,
                token_type: "bearer",
                expires_in: 3600,
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(_) => {
            tracing::warn!(client_id = %client_id, "OAuth client_credentials grant denied: invalid credentials");
            invalid_client()
        }
    }
}

/// Handle the authorization_code grant.
///
/// Validates: code exists, not expired, client_id matches, redirect_uri matches,
/// then validates client_secret. On success, deletes the code (single-use) and
/// returns an access_token.
async fn handle_authorization_code(state: AppState, req: TokenRequest) -> Response {
    let code = match req.code.as_deref() {
        Some(c) if !c.is_empty() => c.to_string(),
        _ => return invalid_request(),
    };
    let client_id = match req.client_id.as_deref() {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => return invalid_request(),
    };
    let redirect_uri = match req.redirect_uri.as_deref() {
        Some(uri) if !uri.is_empty() => uri.to_string(),
        _ => return invalid_request(),
    };
    let client_secret = match req.client_secret.as_deref() {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return invalid_client(),
    };

    // Look up and validate the authorization code.
    let record = {
        let mut codes = state.auth_codes.lock().unwrap();
        match codes.remove(&code) {
            Some(r) => r,
            None => {
                tracing::warn!(client_id = %client_id, "OAuth authorization_code not found");
                return invalid_grant("Authorization code not found or already used");
            }
        }
    };

    // Check expiry.
    let now = chrono_now();
    if record.expires_at.as_str() < now.as_str() {
        tracing::warn!(client_id = %client_id, "OAuth authorization_code expired");
        return invalid_grant("Authorization code has expired");
    }

    // Check client_id matches.
    if record.client_id != client_id {
        tracing::warn!(client_id = %client_id, "OAuth authorization_code client_id mismatch");
        return invalid_grant("client_id does not match authorization request");
    }

    // Check redirect_uri matches.
    if record.redirect_uri != redirect_uri {
        tracing::warn!(client_id = %client_id, "OAuth authorization_code redirect_uri mismatch");
        return invalid_grant("redirect_uri does not match authorization request");
    }

    // Validate client_secret against the token store.
    match check_auth_token(&state, &client_secret).await {
        Ok(()) => {
            tracing::info!(client_id = %client_id, "OAuth authorization_code grant issued");
            let resp = TokenResponse {
                access_token: client_secret,
                token_type: "bearer",
                expires_in: 3600,
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(_) => {
            tracing::warn!(client_id = %client_id, "OAuth authorization_code grant denied: invalid client_secret");
            invalid_client()
        }
    }
}

// ── Parse helpers ─────────────────────────────────────────────────────────────

/// Parse a URL-encoded form body into a TokenRequest.
/// Returns None if `grant_type` is missing.
fn parse_form(body: &str) -> Option<TokenRequest> {
    let mut grant_type = None;
    let mut client_id = None;
    let mut client_secret = None;
    let mut code = None;
    let mut redirect_uri = None;

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
    })
}

/// Encode bytes as lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Minimal percent-decode for form values. Converts + to space and %XX sequences.
fn url_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            out.push(' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (
                from_hex(bytes[i + 1]),
                from_hex(bytes[i + 2]),
            ) {
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

// ── Error responses ───────────────────────────────────────────────────────────

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

fn invalid_request() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(OAuthError {
            error: "invalid_request",
            error_description: "Missing or malformed request parameters",
        }),
    )
        .into_response()
}

fn unsupported_grant_type() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(OAuthError {
            error: "unsupported_grant_type",
            error_description: "Only client_credentials and authorization_code grant types are supported",
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
