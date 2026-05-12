/// Rate limiting module for Twofold.
///
/// Architecture: fixed-window counter per key, stored in DashMap for lock-free
/// concurrent access. Two independent stores: one keyed by client IP (read endpoints),
/// one keyed by bearer token (write endpoints).
///
/// Contract: see trace.md — RateLimitStore, ReadRateLimit extractor, WriteRateLimit extractor.
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use dashmap::DashMap;
use serde_json::json;

use crate::config::ServeConfig;

// ── Bucket ───────────────────────────────────────────────────────────────────

/// One rate limit bucket: a fixed window counter.
///
/// Invariant: `count` is the number of accepted requests in the current window.
/// The window resets when `Instant::now().duration_since(window_start).as_secs() >= window_secs`.
struct Bucket {
    count: u32,
    window_start: Instant,
}

// ── Error ────────────────────────────────────────────────────────────────────

/// Metadata returned when a bucket is exhausted.
///
/// Used by `AppError::RateLimited` to populate the required response headers.
#[derive(Debug, Clone)]
pub struct RateLimitError {
    /// Seconds until the window resets (Retry-After header value).
    pub retry_after: u64,
    /// Maximum requests allowed per window (X-RateLimit-Limit).
    pub limit: u32,
    /// Unix timestamp when the window resets (X-RateLimit-Reset).
    pub reset_at: u64,
}

// ── Store ────────────────────────────────────────────────────────────────────

/// Shared rate limit state. Held in `Arc` inside `AppState` and injected into
/// request extensions so extractors can access it without coupling to AppState.
pub struct RateLimitStore {
    read_store: DashMap<String, Bucket>,
    write_store: DashMap<String, Bucket>,
    read_limit: u32,
    write_limit: u32,
    window_secs: u64,
}

impl RateLimitStore {
    pub fn new(config: &ServeConfig) -> Arc<Self> {
        Arc::new(Self {
            read_store: DashMap::new(),
            write_store: DashMap::new(),
            read_limit: config.rate_limit_read,
            write_limit: config.rate_limit_write,
            window_secs: config.rate_limit_window,
        })
    }

    /// Check and increment the read bucket for the given IP key.
    ///
    /// Returns Ok(()) if the request is within limit, Err(RateLimitError) if exhausted.
    pub fn check_read(&self, ip: &str) -> Result<(), RateLimitError> {
        check_bucket(&self.read_store, ip, self.read_limit, self.window_secs)
    }

    /// Check and increment the write bucket for the given token key.
    ///
    /// Returns Ok(()) if the request is within limit, Err(RateLimitError) if exhausted.
    pub fn check_write(&self, token: &str) -> Result<(), RateLimitError> {
        check_bucket(&self.write_store, token, self.write_limit, self.window_secs)
    }
}

/// Shared bucket check logic for both read and write stores.
///
/// DRY seam: both buckets use identical fixed-window logic; this function
/// parameterises over the store, key, limit, and window duration.
fn check_bucket(
    store: &DashMap<String, Bucket>,
    key: &str,
    limit: u32,
    window_secs: u64,
) -> Result<(), RateLimitError> {
    let now = Instant::now();

    let mut entry = store.entry(key.to_string()).or_insert_with(|| Bucket {
        count: 0,
        window_start: now,
    });

    // Reset the window if it has expired.
    let elapsed = now.duration_since(entry.window_start).as_secs();
    if elapsed >= window_secs {
        entry.count = 0;
        entry.window_start = now;
    }

    if entry.count < limit {
        entry.count += 1;
        Ok(())
    } else {
        // Window is full. Compute reset timestamp and retry delay.
        let unix = unix_now();
        let window_start_unix = unix.saturating_sub(elapsed);
        let reset_at = window_start_unix + window_secs;
        let retry_after = reset_at.saturating_sub(unix);
        Err(RateLimitError {
            retry_after,
            limit,
            reset_at,
        })
    }
}

/// Current unix timestamp in seconds.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── IP Extraction ─────────────────────────────────────────────────────────────

/// Extract client IP from headers or socket address.
///
/// Priority:
/// 1. X-Forwarded-For (leftmost / original client)
/// 2. ConnectInfo socket peer address
///
/// Trust X-Forwarded-For unconditionally (self-hosted; proxy trust is operator responsibility).
fn extract_client_ip(parts: &Parts) -> String {
    // Try X-Forwarded-For first.
    if let Some(xff) = parts.headers.get("x-forwarded-for") {
        if let Ok(s) = xff.to_str() {
            if let Some(first) = s.split(',').next() {
                let ip = first.trim().to_string();
                if !ip.is_empty() {
                    return ip;
                }
            }
        }
    }

    // Fall back to socket peer address via ConnectInfo extension.
    if let Some(addr) = parts
        .extensions
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
    {
        return addr.0.ip().to_string();
    }

    // Absolute fallback — should not happen in normal operation.
    "unknown".to_string()
}

// ── Bearer Token Extraction ───────────────────────────────────────────────────

/// Extract bearer token from Authorization header.
///
/// Note: `extract_bearer` exists in handlers.rs but is private. We re-implement
/// here (3 lines) to avoid coupling this module to handlers internals.
fn extract_bearer_from_headers(headers: &HeaderMap) -> Option<String> {
    let auth = headers.get("authorization")?.to_str().ok()?;
    auth.strip_prefix("Bearer ").map(|s| s.to_string())
}

// ── Rate Limit Response Builder ───────────────────────────────────────────────

/// Build the HTTP 429 response with all required headers.
pub fn too_many_requests_response(err: &RateLimitError) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [
            ("Retry-After", err.retry_after.to_string()),
            ("X-RateLimit-Limit", err.limit.to_string()),
            ("X-RateLimit-Remaining", "0".to_string()),
            ("X-RateLimit-Reset", err.reset_at.to_string()),
            ("Content-Type", "application/json".to_string()),
        ],
        Json(json!({"error": "Too many requests"})).to_string(),
    )
        .into_response()
}

// ── ReadRateLimit Extractor ───────────────────────────────────────────────────

/// Axum extractor that enforces per-IP read rate limiting.
///
/// Extracts the client IP, calls `RateLimitStore::check_read`, and returns
/// HTTP 429 (short-circuiting the handler) if the bucket is exhausted.
///
/// The `Arc<RateLimitStore>` is injected into request extensions by the
/// `axum::Extension` layer applied in `main.rs`.
pub struct ReadRateLimit;

#[async_trait]
impl<S> FromRequestParts<S> for ReadRateLimit
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let store = parts
            .extensions
            .get::<Arc<RateLimitStore>>()
            .cloned()
            .ok_or_else(|| {
                (StatusCode::INTERNAL_SERVER_ERROR, "Rate limit store missing").into_response()
            })?;

        let ip = extract_client_ip(parts);

        store.check_read(&ip).map_err(|e| too_many_requests_response(&e))?;
        Ok(ReadRateLimit)
    }
}

// ── WriteRateLimit Extractor ──────────────────────────────────────────────────

/// Axum extractor that enforces per-token write rate limiting.
///
/// Extracts the bearer token from Authorization header. If absent/malformed,
/// passes through (the handler's `check_auth` will return 401). If present,
/// checks the write bucket — returns 429 if exhausted.
pub struct WriteRateLimit;

#[async_trait]
impl<S> FromRequestParts<S> for WriteRateLimit
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let store = parts
            .extensions
            .get::<Arc<RateLimitStore>>()
            .cloned()
            .ok_or_else(|| {
                (StatusCode::INTERNAL_SERVER_ERROR, "Rate limit store missing").into_response()
            })?;

        // If there's no bearer token, let the request through to the handler's
        // own auth check which will return 401. We don't rate-limit unauthenticated
        // requests on the write bucket.
        if let Some(token) = extract_bearer_from_headers(&parts.headers) {
            store.check_write(&token).map_err(|e| too_many_requests_response(&e))?;
        }

        Ok(WriteRateLimit)
    }
}
