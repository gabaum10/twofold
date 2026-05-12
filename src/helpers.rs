/// Shared utility helpers used across handlers, views, auth, and service layers.
///
/// - Time utilities: `chrono_now`, `is_expired`
/// - Network: `extract_client_ip`
/// - Password: `hash_password`, `verify_password`
/// - Database: `is_unique_violation`
/// - Cookie auth: `make_auth_cookie`, `is_password_authed`
use axum::http::HeaderMap;

use crate::{db::DocumentRecord, handlers::AppError};

// ── Time utilities ────────────────────────────────────────────────────────────

/// Current UTC time as ISO 8601 string.
pub fn chrono_now() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Check if a document has expired.
pub fn is_expired(doc: &DocumentRecord) -> bool {
    match &doc.expires_at {
        Some(exp) => {
            let now = chrono_now();
            exp.as_str() < now.as_str()
        }
        None => false,
    }
}

// ── Network ───────────────────────────────────────────────────────────────────

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

// ── Password ──────────────────────────────────────────────────────────────────

/// Hash a password with argon2.
pub fn hash_password(password: &str) -> Result<String, AppError> {
    use argon2::{
        password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
        Algorithm, Argon2, Params, Version,
    };

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(19456, 2, 1, None).expect("argon2 params are valid constants"),
    );
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(format!("Password hashing failed: {e}")))?;
    Ok(hash.to_string())
}

/// Verify a password against an argon2 hash.
pub fn verify_password(password: &str, hash: &str) -> bool {
    use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordVerifier, Version};

    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(19456, 2, 1, None).expect("argon2 params are valid constants"),
    )
    .verify_password(password.as_bytes(), &parsed)
    .is_ok()
}

// ── Database helpers ──────────────────────────────────────────────────────────

/// Check whether a rusqlite error is a UNIQUE constraint violation.
#[allow(dead_code)]
pub fn is_unique_violation(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(err, _) if err.code == rusqlite::ErrorCode::ConstraintViolation
    )
}

// ── Cookie auth ───────────────────────────────────────────────────────────────

/// Generate an HMAC-based auth cookie value for a slug.
pub fn make_auth_cookie(slug: &str, server_secret: &str) -> String {
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
pub fn is_password_authed(headers: &HeaderMap, slug: &str, server_secret: &str) -> bool {
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
    crate::auth::constant_time_eq(&provided_sig, &expected_sig)
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

    /// A fresh cookie produced by make_auth_cookie is considered valid.
    #[test]
    fn is_password_authed_valid_cookie() {
        let secret = "test-secret";
        let slug = "my-doc";
        let cookie_value = make_auth_cookie(slug, secret);
        let cookie_header = format!("twofold_auth_{}={}", slug, cookie_value);

        let mut headers = HeaderMap::new();
        headers.insert("cookie", cookie_header.parse().unwrap());

        assert!(
            is_password_authed(&headers, slug, secret),
            "freshly-minted cookie should pass"
        );
    }

    /// A cookie with an expiry timestamp in the past is rejected.
    #[test]
    fn is_password_authed_expired_cookie() {
        use base64::Engine;
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let secret = "test-secret";
        let slug = "my-doc";

        // Construct a cookie with an already-expired timestamp.
        let expiry_str = "2000-01-01T00:00:00Z"; // firmly in the past
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(slug.as_bytes());
        mac.update(expiry_str.as_bytes());
        let sig_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        let cookie_value = format!("{}:{}", sig_b64, expiry_str);

        let cookie_header = format!("twofold_auth_{}={}", slug, cookie_value);
        let mut headers = HeaderMap::new();
        headers.insert("cookie", cookie_header.parse().unwrap());

        assert!(
            !is_password_authed(&headers, slug, secret),
            "expired cookie should fail"
        );
    }

    /// A cookie with a tampered HMAC signature is rejected.
    #[test]
    fn is_password_authed_tampered_cookie() {
        let secret = "test-secret";
        let slug = "my-doc";

        // Valid cookie made with the correct secret.
        let cookie_value = make_auth_cookie(slug, secret);

        // Tamper: flip the first character of the signature.
        let tampered = {
            let mut chars: Vec<char> = cookie_value.chars().collect();
            // The first char is part of the base64 signature.
            chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
            chars.iter().collect::<String>()
        };

        let cookie_header = format!("twofold_auth_{}={}", slug, tampered);
        let mut headers = HeaderMap::new();
        headers.insert("cookie", cookie_header.parse().unwrap());

        assert!(
            !is_password_authed(&headers, slug, secret),
            "tampered HMAC should fail"
        );
    }
}
