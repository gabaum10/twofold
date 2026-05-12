//! Unified application error type with `IntoResponse` and `From` impls.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

/// Unified error type with IntoResponse impl.
/// Replaces inline error tuples throughout handlers.
#[derive(Debug)]
pub enum AppError {
    Unauthorized,
    Forbidden,
    BadRequest(String),
    NotFound,
    Conflict(String),
    Gone,
    Internal(String),
    /// Document is password-protected and no password was supplied.
    DocumentPasswordRequired,
    /// Document is password-protected and the supplied password was wrong.
    DocumentPasswordInvalid,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "Forbidden".to_string()),
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            AppError::NotFound => (StatusCode::NOT_FOUND, "Not found".to_string()),
            AppError::Conflict(m) => (StatusCode::CONFLICT, m),
            AppError::Gone => (StatusCode::GONE, "Document has expired".to_string()),
            AppError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
            AppError::DocumentPasswordRequired => {
                (StatusCode::UNAUTHORIZED, "Password required".to_string())
            }
            AppError::DocumentPasswordInvalid => {
                (StatusCode::UNAUTHORIZED, "Invalid password".to_string())
            }
        };
        (status, Json(serde_json::json!({ "error": msg }))).into_response()
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(e: rusqlite::Error) -> Self {
        tracing::error!(error = %e, "Database error");
        AppError::Internal("Database error".to_string())
    }
}
