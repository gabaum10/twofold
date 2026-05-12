//! Authentication and authorization. `Principal` type, token validation, bearer extraction.

/// Authentication primitives for twofold.
///
/// This module owns:
/// - [`Principal`] — the identity of an authenticated caller
/// - [`PrincipalKind`] — which credential class authenticated
/// - [`check_auth`] — validates a `HeaderMap` Bearer token → `Principal`
/// - [`check_auth_token`] — validates a raw token string → `Principal`
/// - [`extract_bearer`] — strips the `Bearer ` prefix from the Authorization header
/// - [`constant_time_eq`] — constant-time byte comparison (also used for HMAC
///   signature verification in handlers.rs)
use axum::http::HeaderMap;

use crate::handlers::{AppError, AppState};

// ── Principal ────────────────────────────────────────────────────────────────

/// Which credential class authenticated this request.
#[allow(dead_code)] // variants and fields used as audit foundation; callers will expand
pub enum PrincipalKind {
    /// Master TWOFOLD_TOKEN (environment variable).
    Admin,
    /// In-memory OAuth access token issued to a public client.
    OAuth { client_id: String },
    /// Managed token stored in the database (created via `twofold token create`).
    Managed { name: String },
}

/// The authenticated identity of a caller.
///
/// `scopes` is empty for admin and managed tokens (full access).
/// OAuth tokens carry whatever scope was recorded in [`AccessTokenRecord`].
#[allow(dead_code)] // fields used as audit foundation; callers will expand
pub struct Principal {
    pub kind: PrincipalKind,
    /// Scopes granted by this credential.  Empty = full access (admin / managed).
    pub scopes: Vec<String>,
    /// Human-readable identity string for audit logging.
    /// Examples: `"admin"`, `"oauth:client-xyz"`, `"managed:deploy-bot"`.
    pub display_name: String,
}

impl Principal {
    /// Returns `true` if this principal holds the given scope OR has full access
    /// (i.e. `scopes` is empty, meaning no restriction was recorded).
    #[allow(dead_code)]
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.is_empty() || self.scopes.iter().any(|s| s == scope)
    }

    /// Returns `true` only for the master admin credential.
    pub fn is_admin(&self) -> bool {
        matches!(self.kind, PrincipalKind::Admin)
    }

    /// Returns `true` if this principal may perform write operations.
    ///
    /// Admin tokens always may.  OAuth tokens must carry the `"mcp:tools"` scope.
    /// Managed tokens (empty scopes) have full access by convention.
    #[allow(dead_code)]
    pub fn can_write(&self) -> bool {
        self.is_admin() || self.has_scope("mcp:tools")
    }
}

// ── Auth helpers ─────────────────────────────────────────────────────────────

/// Validate the Bearer token in the `Authorization` header.
///
/// Extracts the raw token then delegates to [`check_auth_token`].
pub async fn check_auth(state: &AppState, headers: &HeaderMap) -> Result<Principal, AppError> {
    let provided = extract_bearer(headers).ok_or(AppError::Unauthorized)?;
    check_auth_token(state, provided).await
}

/// Validate a raw token string and return the authenticated [`Principal`].
///
/// Verification order (mirrors the previous `check_auth_token` in handlers.rs):
///
/// 1. **Admin token** — constant-time compare against `TWOFOLD_TOKEN`.  O(1).
/// 2. **In-memory OAuth access tokens** — sweep expired entries, then look up
///    the token value and build a [`PrincipalKind::OAuth`] with the stored
///    `client_id` and `scope`.
/// 3. **Prefix-indexed managed token** — O(1) DB lookup on first 8 chars, then
///    one argon2 verify in `spawn_blocking`.
/// 4. **Legacy managed tokens** (no prefix stored, pre-v0.4) — O(n) fallback,
///    argon2 per record.  Returns immediately on first match.
///
/// Returns [`AppError::Unauthorized`] if no credential matches.
pub async fn check_auth_token(state: &AppState, provided: &str) -> Result<Principal, AppError> {
    // ── 1. Admin fast-path ───────────────────────────────────────────────────
    if constant_time_eq(provided.as_bytes(), state.config.token.as_bytes()) {
        return Ok(Principal {
            kind: PrincipalKind::Admin,
            scopes: vec![],
            display_name: "admin".to_string(),
        });
    }

    // ── 2. SQLite OAuth access tokens ───────────────────────────────────────
    // Look up the token; check expiry in-process (avoids a WHERE clause that
    // requires WAL read, at negligible overhead for one row).
    match state.db.get_access_token(provided) {
        Ok(Some(record)) => {
            let now = crate::helpers::chrono_now();
            if record.expires_at.as_str() >= now.as_str() {
                let client_id = record.client_id.clone();
                let scopes: Vec<String> = record
                    .scope
                    .as_deref()
                    .map(|s| s.split_whitespace().map(|t| t.to_string()).collect())
                    .unwrap_or_default();
                let display_name = format!("oauth:{client_id}");
                return Ok(Principal {
                    kind: PrincipalKind::OAuth { client_id },
                    scopes,
                    display_name,
                });
            }
            // Token exists but is expired — fall through to managed token check.
        }
        Ok(None) => {} // not an OAuth token — fall through
        Err(e) => {
            tracing::warn!(error = %e, "Failed to look up OAuth access token");
            // Non-fatal: fall through to managed token check.
        }
    }

    // ── 3. Prefix-indexed managed token ─────────────────────────────────────
    let prefix: String = provided.chars().take(8).collect();

    let candidate = state
        .db
        .get_token_by_prefix(&prefix)
        .map_err(|_| AppError::Internal("Failed to check tokens".to_string()))?;

    if let Some(token_record) = candidate {
        let provided_owned = provided.to_string();
        let hash_owned = token_record.hash.clone();
        let verified =
            tokio::task::spawn_blocking(move || crate::helpers::verify_password(&provided_owned, &hash_owned))
                .await
                .map_err(|e| AppError::Internal(format!("Auth task failed: {e}")))?;

        if verified {
            let now = crate::helpers::chrono_now();
            let _ = state.db.touch_token(&token_record.id, &now);
            let name = token_record.name.clone();
            return Ok(Principal {
                display_name: format!("managed:{name}"),
                kind: PrincipalKind::Managed { name },
                scopes: vec![],
            });
        }
        // Prefix matched but hash didn't — fall through to legacy check.
    }

    // ── 4. Legacy managed tokens (no prefix, pre-v0.4) ──────────────────────
    let legacy_tokens = state
        .db
        .get_legacy_active_tokens()
        .map_err(|_| AppError::Internal("Failed to check tokens".to_string()))?;

    if !legacy_tokens.is_empty() {
        let provided_owned = provided.to_string();
        let result = tokio::task::spawn_blocking(move || {
            for token_record in &legacy_tokens {
                if crate::helpers::verify_password(&provided_owned, &token_record.hash) {
                    return Some((token_record.id.clone(), token_record.name.clone()));
                }
            }
            None
        })
        .await
        .map_err(|e| AppError::Internal(format!("Auth task failed: {e}")))?;

        if let Some((id, name)) = result {
            let now = crate::helpers::chrono_now();
            let _ = state.db.touch_token(&id, &now);
            return Ok(Principal {
                display_name: format!("managed:{name}"),
                kind: PrincipalKind::Managed { name },
                scopes: vec![],
            });
        }
    }

    Err(AppError::Unauthorized)
}

/// Extract the Bearer token from the Authorization header.
pub fn extract_bearer(headers: &HeaderMap) -> Option<&str> {
    let auth = headers.get("authorization")?.to_str().ok()?;
    auth.strip_prefix("Bearer ")
}

/// Constant-time byte comparison.
///
/// Also re-exported for use in HMAC signature verification (handlers.rs).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}
