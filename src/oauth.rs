/// OAuth 2.0 Client Credentials grant — `POST /oauth/token`
///
/// Accepts either:
///   Content-Type: application/x-www-form-urlencoded
///     grant_type=client_credentials&client_id=<id>&client_secret=<secret>
///   Content-Type: application/json
///     {"grant_type": "client_credentials", "client_id": "...", "client_secret": "..."}
///
/// Validates `client_secret` against the same token store as the document API.
/// `client_id` is accepted as-is (logged, not validated against a registry).
///
/// On success returns the standard OAuth token response. `access_token` is
/// the same value that was passed as `client_secret` — we confirm it is valid
/// and return it in bearer form so the client can use it on subsequent calls.
///
/// On failure returns RFC 6749 error response with 401.
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::handlers::{check_auth_token, AppState};

// ── Request shape ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct TokenRequest {
    grant_type: String,
    client_id: Option<String>,
    client_secret: String,
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

// ── Handler ───────────────────────────────────────────────────────────────────

/// POST /oauth/token
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

    // Only client_credentials grant type is supported.
    if req.grant_type != "client_credentials" {
        return unsupported_grant_type();
    }

    let client_id = req.client_id.as_deref().unwrap_or("<unset>");

    // Validate the secret against the existing token auth.
    match check_auth_token(&state, &req.client_secret).await {
        Ok(()) => {
            tracing::info!(client_id = %client_id, "OAuth client_credentials grant issued");
            let resp = TokenResponse {
                access_token: req.client_secret,
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

// ── Parse helpers ─────────────────────────────────────────────────────────────

/// Parse a URL-encoded form body into a TokenRequest.
/// Returns None if required fields are missing.
fn parse_form(body: &str) -> Option<TokenRequest> {
    let mut grant_type = None;
    let mut client_id = None;
    let mut client_secret = None;

    for pair in body.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            let k = url_decode(k);
            let v = url_decode(v);
            match k.as_str() {
                "grant_type" => grant_type = Some(v),
                "client_id" => client_id = Some(v),
                "client_secret" => client_secret = Some(v),
                _ => {}
            }
        }
    }

    Some(TokenRequest {
        grant_type: grant_type?,
        client_id,
        client_secret: client_secret?,
    })
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
            error_description: "Only client_credentials grant type is supported",
        }),
    )
        .into_response()
}
