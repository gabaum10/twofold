//! MCP HTTP transport (`POST /mcp`). Bearer-auth required; dispatches directly to service layer for Cowork/remote use.

/// Remote MCP HTTP transport — `POST /mcp`
///
/// Accepts JSON-RPC messages over HTTP and dispatches tool calls directly to
/// the service layer. No reqwest loopback. The bearer token that authenticated
/// this request produces a Principal; that Principal is passed through to every
/// service call so auth is consistent and the confused-deputy path is eliminated.
///
/// The MCP stdio transport (mcp.rs) is a CLI client that legitimately makes
/// HTTP calls to a remote server and is unaffected by this change.
///
/// Design notes:
/// - JSON-RPC notifications (no `id` field) get 202 Accepted with no body,
///   per the JSON-RPC spec.
/// - No CORS headers: this endpoint is server-to-server only.
/// - No SSE: all MCP tools are quick round-trips; streaming is not needed.
/// - Auth: bearer token required. Clients obtain a token via the OAuth flow
///   (GET /authorize → POST /oauth/token). The token is validated against the
///   same token store used by the document API.
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::Value;

use crate::{
    auth::check_auth_token,
    handlers::AppState,
    mcp,
    service::{self, PublishRequest, UpdateRequest},
};

/// POST /mcp — remote MCP JSON-RPC endpoint (bearer token required).
pub async fn handle_mcp_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // Auth check — bearer token must be present and valid.
    // On 401, include WWW-Authenticate so Cowork can start OAuth discovery.
    let resource_metadata_url = {
        let base = state.config.base_url.trim_end_matches('/');
        format!("{base}/.well-known/oauth-protected-resource")
    };
    let www_auth_value = format!("Bearer resource_metadata=\"{resource_metadata_url}\"");
    let www_auth_header: axum::http::HeaderValue = www_auth_value
        .parse()
        .unwrap_or_else(|_| axum::http::HeaderValue::from_static("Bearer"));

    let provided = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let token = match provided {
        Some(t) => t.to_string(),
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                [(
                    axum::http::header::WWW_AUTHENTICATE,
                    www_auth_header.clone(),
                )],
                axum::Json(serde_json::json!({
                    "error": "unauthorized",
                    "error_description": "Bearer token required"
                })),
            )
                .into_response();
        }
    };

    let principal = match check_auth_token(&state, &token).await {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                [(axum::http::header::WWW_AUTHENTICATE, www_auth_header)],
                axum::Json(serde_json::json!({
                    "error": "unauthorized",
                    "error_description": "Invalid or expired token"
                })),
            )
                .into_response();
        }
    };

    // Parse the JSON-RPC request.
    let request: mcp::Request = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            let resp = mcp::Response::err(Value::Null, -32700, format!("Parse error: {e}"));
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

    // Dispatch tool calls directly to the service layer — no HTTP loopback.
    let resp = dispatch_tool_call(&state, principal, id, &request).await;
    json_response(StatusCode::OK, &resp)
}

/// Dispatch a JSON-RPC request to the appropriate service function.
async fn dispatch_tool_call(
    state: &AppState,
    principal: crate::auth::Principal,
    id: Value,
    req: &mcp::Request,
) -> mcp::Response {
    match req.method.as_str() {
        "initialize" => handle_initialize(id),
        "tools/list" => handle_tools_list(id),
        "tools/call" => {
            let params = match req.params.as_ref() {
                Some(p) => p,
                None => {
                    return mcp::Response::err(id, -32602, "Missing params".to_string());
                }
            };

            let tool_name = match params.get("name").and_then(|v| v.as_str()) {
                Some(n) => n,
                None => {
                    return mcp::Response::err(id, -32602, "Missing tool name".to_string());
                }
            };

            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or(Value::Object(Default::default()));

            let result = call_tool(state, principal, tool_name, &args).await;
            mcp::Response::ok(id, result)
        }
        _ => mcp::Response::err(id, -32601, format!("Method not found: {}", req.method)),
    }
}

async fn call_tool(
    state: &AppState,
    principal: crate::auth::Principal,
    tool_name: &str,
    args: &Value,
) -> Value {
    match tool_name {
        "twofold_publish" => tool_publish(state, principal, args).await,
        "twofold_get" => tool_get(state, args),
        "twofold_list" => tool_list(state, args),
        "twofold_delete" => tool_delete(state, principal, args).await,
        "twofold_update" => tool_update(state, principal, args).await,
        _ => tool_result_err(format!("Unknown tool: {tool_name}")),
    }
}

// ── Tool implementations ──────────────────────────────────────────────────────

async fn tool_publish(state: &AppState, principal: crate::auth::Principal, args: &Value) -> Value {
    let content = match args.get("content").and_then(|v| v.as_str()) {
        Some(c) => c,
        None => return tool_result_err("Missing required argument: content".to_string()),
    };

    let title = args.get("title").and_then(|v| v.as_str());
    let slug = args.get("slug").and_then(|v| v.as_str());
    let password = args.get("password").and_then(|v| v.as_str());
    let expiry = args.get("expiry").and_then(|v| v.as_str());
    let theme = args.get("theme").and_then(|v| v.as_str());
    let description = args.get("description").and_then(|v| v.as_str());
    let agent_content = args.get("agent_content").and_then(|v| v.as_str());

    // Build the raw markdown body with optional frontmatter injection.
    let body = match build_publish_body(
        content,
        title,
        slug,
        password,
        expiry,
        theme,
        description,
        agent_content,
    ) {
        Ok(b) => b,
        Err(e) => return tool_result_err(e),
    };

    let req = PublishRequest {
        raw_content: body,
        principal,
        client_ip: "mcp".to_string(),
    };

    match service::publish(&state.db, &state.config, req) {
        Ok(result) => {
            let json = serde_json::json!({
                "slug": result.slug,
                "title": result.title,
                "url": result.url,
                "api_url": result.api_url,
                "created_at": result.created_at,
                "expires_at": result.expires_at,
            });
            let text = serde_json::to_string_pretty(&json).unwrap_or_else(|_| json.to_string());
            tool_result_ok(text)
        }
        Err(e) => tool_result_err(format!("{e:?}")),
    }
}

async fn tool_update(state: &AppState, principal: crate::auth::Principal, args: &Value) -> Value {
    let slug = match args.get("slug").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return tool_result_err("Missing required argument: slug".to_string()),
    };

    let content = match args.get("content").and_then(|v| v.as_str()) {
        Some(c) => c,
        None => return tool_result_err("Missing required argument: content".to_string()),
    };

    let title = args.get("title").and_then(|v| v.as_str());
    let description = args.get("description").and_then(|v| v.as_str());
    let password = args.get("password").and_then(|v| v.as_str());
    let expiry = args.get("expiry").and_then(|v| v.as_str());
    let theme = args.get("theme").and_then(|v| v.as_str());
    let agent_content = args.get("agent_content").and_then(|v| v.as_str());

    let body = match build_publish_body(
        content,
        title,
        None,
        password,
        expiry,
        theme,
        description,
        agent_content,
    ) {
        Ok(b) => b,
        Err(e) => return tool_result_err(e),
    };

    let req = UpdateRequest {
        raw_content: body,
        principal,
        client_ip: "mcp".to_string(),
    };

    match service::update(&state.db, &state.config, slug, req) {
        Ok(result) => {
            let json = serde_json::json!({
                "slug": result.slug,
                "title": result.title,
                "url": result.url,
                "api_url": result.api_url,
                "created_at": result.created_at,
                "expires_at": result.expires_at,
            });
            let text = serde_json::to_string_pretty(&json).unwrap_or_else(|_| json.to_string());
            tool_result_ok(text)
        }
        Err(e) => match e {
            crate::handlers::AppError::NotFound => {
                tool_result_err(format!("Document not found: {slug}"))
            }
            crate::handlers::AppError::Gone => {
                tool_result_err(format!("Document has expired: {slug}"))
            }
            _ => tool_result_err(format!("{e:?}")),
        },
    }
}

async fn tool_delete(state: &AppState, principal: crate::auth::Principal, args: &Value) -> Value {
    let slug = match args.get("slug").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return tool_result_err("Missing required argument: slug".to_string()),
    };

    match service::delete(&state.db, &state.config, slug, &principal, "mcp") {
        Ok(()) => tool_result_ok(serde_json::json!({"success": true}).to_string()),
        Err(crate::handlers::AppError::NotFound) => {
            tool_result_err(format!("Document not found: {slug}"))
        }
        Err(e) => tool_result_err(format!("{e:?}")),
    }
}

fn tool_get(state: &AppState, args: &Value) -> Value {
    let slug = match args.get("slug").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return tool_result_err("Missing required argument: slug".to_string()),
    };

    match service::get(&state.db, slug) {
        Ok(doc) => {
            // Strip password from the content in the response.
            let safe_content = crate::handlers::strip_password_from_content_pub(&doc.raw_content);
            // Return the full raw source as markdown text (same as the HTTP
            // API's GET /api/v1/documents/:slug endpoint).
            tool_result_ok(safe_content)
        }
        Err(crate::handlers::AppError::NotFound) => {
            tool_result_err(format!("Document not found: {slug}"))
        }
        Err(crate::handlers::AppError::Gone) => {
            tool_result_err(format!("Document not found: {slug}"))
        }
        Err(e) => tool_result_err(format!("{e:?}")),
    }
}

fn tool_list(state: &AppState, args: &Value) -> Value {
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(20) as u32;

    match service::list(&state.db, limit, 0) {
        Ok((documents, total)) => {
            let json = serde_json::json!({
                "documents": documents,
                "total": total,
                "limit": limit.min(100),
                "offset": 0,
            });
            let text = serde_json::to_string_pretty(&json).unwrap_or_else(|_| json.to_string());
            tool_result_ok(text)
        }
        Err(e) => tool_result_err(format!("{e:?}")),
    }
}

// ── MCP protocol handlers ─────────────────────────────────────────────────────

fn handle_initialize(id: Value) -> mcp::Response {
    mcp::Response::ok(
        id,
        serde_json::json!({
            "protocolVersion": "2024-11-05",
            "serverInfo": {
                "name": "twofold",
                "version": env!("CARGO_PKG_VERSION"),
                "icons": [
                    {
                        "url": "https://share.hearth.observer/icon.png",
                        "mime_type": "image/jpeg"
                    }
                ]
            },
            "capabilities": {
                "tools": {}
            }
        }),
    )
}

fn handle_tools_list(id: Value) -> mcp::Response {
    // Delegate to the canonical tools list in mcp.rs so the two transports
    // always advertise the same schema.
    mcp::tools_list_response(id)
}

// ── Body construction helpers ─────────────────────────────────────────────────

/// Build the raw markdown body for a publish or update call.
///
/// Handles frontmatter injection/merge and agent-content block appending.
/// Returns `Err(String)` with a user-facing error message on validation failure.
#[allow(clippy::too_many_arguments)]
fn build_publish_body(
    content: &str,
    title: Option<&str>,
    slug: Option<&str>,
    password: Option<&str>,
    expiry: Option<&str>,
    theme: Option<&str>,
    description: Option<&str>,
    agent_content: Option<&str>,
) -> Result<String, String> {
    let fields = crate::frontmatter::FrontmatterFields {
        title: title.map(str::to_string),
        slug: slug.map(str::to_string),
        password: password.map(str::to_string),
        expiry: expiry.map(str::to_string),
        theme: theme.map(str::to_string),
        description: description.map(str::to_string),
    };
    let mut body = crate::frontmatter::apply_frontmatter(content, fields);

    if let Some(ac) = agent_content {
        if crate::frontmatter::contains_marker_directive(ac) {
            return Err(
                "agent_content must not contain marker directives (<!-- @agent --> or <!-- @end -->)"
                    .to_string(),
            );
        }
        body.push_str("\n\n<!-- @agent -->\n\n");
        body.push_str(ac);
        body.push_str("\n\n<!-- @end -->\n");
    }

    Ok(body)
}

// ── Response helpers ──────────────────────────────────────────────────────────

fn tool_result_ok(text: String) -> Value {
    serde_json::json!({
        "content": [{ "type": "text", "text": text }]
    })
}

fn tool_result_err(message: String) -> Value {
    serde_json::json!({
        "content": [{ "type": "text", "text": message }],
        "isError": true
    })
}

/// Serialize a `mcp::Response` to a JSON HTTP response.
fn json_response(status: StatusCode, resp: &mcp::Response) -> Response {
    match serde_json::to_vec(resp) {
        Ok(body) => (
            status,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to serialize MCP response");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
