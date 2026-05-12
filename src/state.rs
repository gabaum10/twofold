//! Shared application state injected into all handlers via axum State extractor.

use std::sync::Arc;

use crate::{config::ServeConfig, db::Db, rate_limit::RateLimitStore};

/// Shared application state injected into all handlers via axum State extractor.
#[derive(Clone)]
#[allow(dead_code)] // rate_limit accessed via axum Extension layer, not directly on AppState
pub struct AppState {
    pub db: Db,
    pub config: Arc<ServeConfig>,
    pub rate_limit: Arc<RateLimitStore>,
}
