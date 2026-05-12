//! Fire-and-forget webhook dispatch on document lifecycle events. HMAC-SHA256 signing.

/// Webhook dispatch for document lifecycle events.
///
/// Fire-and-forget: dispatched via tokio::spawn, failure logs at warn level,
/// API response is never affected.
///
/// Body lifecycle: the payload is serialized to JSON exactly once before spawning.
/// The spawned closure takes ownership of the single String — no clone needed.
/// HMAC signing reads the bytes before the body is consumed by reqwest.
use std::sync::OnceLock;

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// A single webhook client, initialized once.
/// Timeout is set to 5 seconds per the spec — webhook failures must not
/// block handlers for more than this duration.
static WEBHOOK_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

fn webhook_client() -> &'static reqwest::Client {
    WEBHOOK_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("Failed to build webhook HTTP client")
    })
}

/// Document metadata included in webhook payloads.
#[derive(serde::Serialize, Clone)]
pub struct WebhookDocument {
    pub slug: String,
    pub title: String,
    pub url: String,
    pub api_url: String,
}

/// Dispatch a webhook for a document event.
///
/// # Body ownership protocol
///
/// The JSON payload is serialized exactly once before `tokio::spawn`. The
/// spawned closure takes ownership of the single `String` — no `.clone()` occurs.
/// HMAC signing reads `payload.as_bytes()` before the body is consumed by
/// `reqwest`, so only one allocation is needed for the entire dispatch path.
pub fn dispatch_webhook(
    webhook_url: String,
    webhook_secret: Option<String>,
    event: &str,
    timestamp: String,
    document: WebhookDocument,
) {
    // Serialize the payload once, before spawning.
    // The spawned closure owns the String — no borrow crosses the spawn boundary.
    let payload = match serde_json::to_string(&serde_json::json!({
        "event": event,
        "timestamp": timestamp,
        "document": {
            "slug": document.slug,
            "title": document.title,
            "url": document.url,
            "api_url": document.api_url,
        }
    })) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to serialize webhook payload — not dispatching");
            return;
        }
    };

    tokio::spawn(async move {
        let client = webhook_client();

        // HMAC-SHA256 signature if secret is configured.
        // Computed before consuming `payload` into the request body.
        // Key: UTF-8 bytes of the secret string.
        // Header: X-Twofold-Signature: sha256=<hex>
        //
        // Receivers verifying this signature SHOULD use constant-time comparison
        // (e.g., `subtle::ConstantTimeEq`) to prevent timing attacks. We send
        // the signature; verification is the receiver's responsibility.
        let signature = webhook_secret.as_deref().and_then(|secret| {
            match compute_hmac_signature(payload.as_bytes(), secret.as_bytes()) {
                Ok(sig) => Some(sig),
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to compute webhook signature — sending unsigned");
                    None
                }
            }
        });

        let mut request = client
            .post(&webhook_url)
            .header("Content-Type", "application/json")
            .body(payload);

        if let Some(sig) = signature {
            request = request.header("X-Twofold-Signature", format!("sha256={sig}"));
        }

        match request.send().await {
            Ok(resp) if resp.status().is_success() => {
                tracing::debug!(
                    url = %webhook_url,
                    status = %resp.status(),
                    "Webhook delivered"
                );
            }
            Ok(resp) => {
                tracing::warn!(
                    url = %webhook_url,
                    status = %resp.status(),
                    "Webhook delivery failed (non-2xx response)"
                );
            }
            Err(e) if e.is_timeout() => {
                tracing::warn!(url = %webhook_url, "Webhook timed out (5s)");
            }
            Err(e) => {
                tracing::warn!(url = %webhook_url, error = %e, "Webhook delivery error");
            }
        }
    });
}

/// Compute HMAC-SHA256 of `body` with `key`, return hex-encoded string.
pub(crate) fn compute_hmac_signature(body: &[u8], key: &[u8]) -> Result<String, String> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).map_err(|e| format!("HMAC key error: {e}"))?;
    mac.update(body);
    let result = mac.finalize().into_bytes();
    // Encode each byte as lowercase hex — no external hex dep needed.
    Ok(result.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::compute_hmac_signature;

    // ── P3-18: HMAC known-vector tests (RFC 4231 Test Case 1) ────────────────

    /// RFC 4231 Test Case 1: HMAC-SHA256 with a known key and message.
    ///
    /// Key:  0x0b repeated 20 bytes
    /// Data: "Hi There"
    /// Expected HMAC-SHA256 (hex): b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
    #[test]
    fn hmac_rfc4231_test_case_1() {
        let key = [0x0bu8; 20];
        let msg = b"Hi There";
        let result = compute_hmac_signature(msg, &key).expect("HMAC must not fail");
        assert_eq!(
            result, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            "HMAC-SHA256 output must match RFC 4231 TC1 vector"
        );
    }

    /// Different message with same key produces a different digest — regression guard.
    #[test]
    fn hmac_different_message_different_digest() {
        let key = [0x0bu8; 20];
        let result1 = compute_hmac_signature(b"Hi There", &key).unwrap();
        let result2 = compute_hmac_signature(b"Hi There!", &key).unwrap();
        assert_ne!(
            result1, result2,
            "different messages must produce different HMAC outputs"
        );
    }

    /// Different key with same message produces a different digest — regression guard.
    #[test]
    fn hmac_different_key_different_digest() {
        let result1 = compute_hmac_signature(b"Hi There", &[0x0bu8; 20]).unwrap();
        let result2 = compute_hmac_signature(b"Hi There", b"different-key").unwrap();
        assert_ne!(
            result1, result2,
            "different keys must produce different HMAC outputs"
        );
    }
}
