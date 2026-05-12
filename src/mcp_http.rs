/// Remote MCP HTTP transport — `POST /mcp`
///
/// Accepts JSON-RPC messages over HTTP and dispatches to the same
/// `mcp::handle_request` logic used by the stdio transport.
///
/// Design notes:
/// - `reqwest::blocking::Client` panics when called inside a Tokio async
///   context. We use `tokio::task::spawn_blocking` to move the blocking call
///   onto a dedicated thread pool thread.
/// - JSON-RPC notifications (no `id` field) get 202 Accepted with no body,
///   per the JSON-RPC spec.
/// - No CORS headers: this endpoint is server-to-server only.
/// - No SSE: all MCP tools are quick round-trips; streaming is not needed.
/// - Auth: none. The endpoint is public. TWOFOLD_MCP_TOKEN is used internally
///   for the handler's onward calls to the document API.
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::Value;

use crate::{
    handlers::AppState,
    mcp,
};

/// POST /mcp — remote MCP JSON-RPC endpoint (unauthenticated).
pub async fn handle_mcp_post(
    State(_state): State<AppState>,
    body: axum::body::Bytes,
) -> Response {
    // Parse the JSON-RPC request.
    let request: mcp::Request = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            let resp = mcp::Response::err(
                Value::Null,
                -32700,
                format!("Parse error: {e}"),
            );
            return json_response(StatusCode::OK, &resp);
        }
    };

    // JSON-RPC notifications have no `id` — respond with 202 and no body.
    let id = match request.id.clone() {
        Some(id) => id,
        None => {
            return StatusCode::ACCEPTED.into_response();
        }
    };

    // Resolve the MCP server URL and token from environment.
    // These are the credentials the MCP layer uses for its onward HTTP calls
    // to the document API — independent of the bearer token the caller used
    // to authenticate with this endpoint.
    let server_url = std::env::var("TWOFOLD_MCP_SERVER")
        .unwrap_or_else(|_| "http://localhost:3000".to_string());
    let server_url = server_url.trim_end_matches('/').to_string();

    let token = std::env::var("TWOFOLD_MCP_TOKEN")
        .or_else(|_| std::env::var("TWOFOLD_TOKEN"))
        .unwrap_or_default();

    // reqwest::blocking panics in an async context — move to a blocking thread.
    let result = tokio::task::spawn_blocking(move || {
        let client = mcp::build_client();
        mcp::handle_request(&client, &server_url, &token, id, &request)
    })
    .await;

    match result {
        Ok(resp) => json_response(StatusCode::OK, &resp),
        Err(e) => {
            // spawn_blocking join error — task panicked.
            tracing::error!(error = %e, "MCP spawn_blocking task panicked");
            let resp = mcp::Response::err(
                Value::Null,
                -32603,
                "Internal error: handler panicked".to_string(),
            );
            json_response(StatusCode::INTERNAL_SERVER_ERROR, &resp)
        }
    }
}

/// Serialize a `mcp::Response` to a JSON HTTP response.
fn json_response(status: StatusCode, resp: &mcp::Response) -> Response {
    match serde_json::to_vec(resp) {
        Ok(body) => (
            status,
            [(
                axum::http::header::CONTENT_TYPE,
                "application/json",
            )],
            body,
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to serialize MCP response");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
