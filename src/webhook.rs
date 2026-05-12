/// Webhook dispatch for document lifecycle events.
///
/// Fire-and-forget: dispatched via tokio::spawn, failure logs at warn level,
/// API response is never affected.
///
/// Body lifecycle: body bytes are serialized to JSON, then the JSON string is
/// CLONED before spawning so the spawned task owns the bytes. No borrow crosses
/// the spawn boundary — Bytes/String are Send + 'static. This prevents any
/// use-after-move of the request body.
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
/// The JSON body is serialized BEFORE tokio::spawn. The body string is then
/// cloned (cheap — String is heap-allocated, clone is a memcpy of the bytes)
/// into the spawned closure. The spawned task owns its copy independently of
/// the calling handler. This is required: tokio::spawn requires 'static bounds,
/// and borrowing from the handler's stack frame would violate that constraint.
pub fn dispatch_webhook(
    webhook_url: String,
    webhook_secret: Option<String>,
    event: &str,
    timestamp: String,
    document: WebhookDocument,
) {
    // Serialize the payload NOW, before spawning.
    // Defensive choice: build the complete body string in the caller's frame
    // so the spawned closure owns String, not &str.
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

    // Clone payload for spawn — owned String, no borrow.
    let payload_owned = payload.clone();

    tokio::spawn(async move {
        let client = webhook_client();

        let mut request = client
            .post(&webhook_url)
            .header("Content-Type", "application/json")
            .body(payload_owned.clone());

        // HMAC-SHA256 signature if secret is configured.
        // Key: UTF-8 bytes of the secret string.
        // Header: X-Twofold-Signature: sha256=<hex>
        //
        // Receivers verifying this signature SHOULD use constant-time comparison
        // (e.g., `subtle::ConstantTimeEq`) to prevent timing attacks. We send
        // the signature; verification is the receiver's responsibility.
        if let Some(ref secret) = webhook_secret {
            match compute_hmac_signature(payload_owned.as_bytes(), secret.as_bytes()) {
                Ok(sig) => {
                    request = request.header("X-Twofold-Signature", format!("sha256={sig}"));
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to compute webhook signature — sending unsigned");
                }
            }
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
fn compute_hmac_signature(body: &[u8], key: &[u8]) -> Result<String, String> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).map_err(|e| format!("HMAC key error: {e}"))?;
    mac.update(body);
    let result = mac.finalize().into_bytes();
    // Encode each byte as lowercase hex — no external hex dep needed.
    Ok(result.iter().map(|b| format!("{b:02x}")).collect())
}
