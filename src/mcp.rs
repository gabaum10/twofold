/// MCP (Model Context Protocol) server — raw JSON-RPC over stdio.
///
/// Design choice: raw JSON-RPC, no rmcp crate dependency. The MCP handshake
/// is simple enough (initialize → initialized notification → tools/call loop)
/// that a crate adds coupling without value.
///
/// Architecture: this is a CLIENT of the twofold HTTP API. It does NOT touch
/// the database directly. All operations go through HTTP so auth and logic
/// stay consistent.
///
/// Production risks:
/// - Unreachable server: every HTTP call has connect_timeout + request_timeout.
///   Errors map to MCP error responses, never panics.
/// - Malformed JSON on stdin: parse errors produce JSON-RPC error responses.
/// - Notifications (no `id` field): we do NOT send a response (per JSON-RPC spec).
/// - The `total` in twofold_list is included in the text for agent context.
use std::io::{BufRead, Write};

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── JSON-RPC types ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct Request {
    #[allow(dead_code)]
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

#[derive(Debug, Serialize)]
struct Response {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
}

impl Response {
    fn ok(id: Value, result: Value) -> Self {
        Self { jsonrpc: "2.0", id, result: Some(result), error: None }
    }

    fn err(id: Value, code: i32, message: String) -> Self {
        Self { jsonrpc: "2.0", id, result: None, error: Some(JsonRpcError { code, message }) }
    }
}

// ── Tool result types ─────────────────────────────────────────────────────────

/// A successful tool result wraps content as a text array.
fn tool_result_ok(text: String) -> Value {
    serde_json::json!({
        "content": [{ "type": "text", "text": text }]
    })
}

/// A tool error result — non-2xx HTTP status or other failure.
/// `is_error: true` signals to MCP clients that the tool call failed.
fn tool_result_err(message: String) -> Value {
    serde_json::json!({
        "content": [{ "type": "text", "text": message }],
        "isError": true
    })
}

// ── HTTP client ───────────────────────────────────────────────────────────────

/// Build the reqwest client with conservative timeouts.
/// connect_timeout: 10s — prevents indefinite hang on unreachable server.
/// timeout: 30s — covers slow publish operations.
fn build_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("Failed to build MCP HTTP client")
}

// ── MCP server entry point ────────────────────────────────────────────────────

/// Run the MCP server on stdio. Reads JSON-RPC messages line-by-line.
/// Each line is one complete JSON-RPC message.
pub fn run_mcp_server() {
    let server_url = std::env::var("TWOFOLD_MCP_SERVER")
        .unwrap_or_else(|_| "http://localhost:3000".to_string());
    let server_url = server_url.trim_end_matches('/').to_string();

    // Token: TWOFOLD_MCP_TOKEN falls back to TWOFOLD_TOKEN
    let token = std::env::var("TWOFOLD_MCP_TOKEN")
        .or_else(|_| std::env::var("TWOFOLD_TOKEN"))
        .unwrap_or_default();

    let client = build_client();
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();

    // Process one JSON-RPC message per line.
    // Stderr is used for logging — stdout is exclusively for JSON-RPC responses.
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[mcp] stdin read error: {e}");
                break;
            }
        };

        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let request: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                // Parse error — send JSON-RPC parse error if we can determine an id.
                // Since we can't parse, use null id per spec.
                let resp = Response::err(
                    Value::Null,
                    -32700,
                    format!("Parse error: {e}"),
                );
                write_response(&stdout, &resp);
                continue;
            }
        };

        // JSON-RPC notifications have no `id` field — do NOT respond to them.
        // Notifications include: `notifications/initialized`.
        let id = match request.id.clone() {
            Some(id) => id,
            None => {
                eprintln!("[mcp] notification: {}", request.method);
                continue;
            }
        };

        let resp = handle_request(&client, &server_url, &token, id, &request);
        write_response(&stdout, &resp);
    }
}

fn write_response(stdout: &std::io::Stdout, resp: &Response) {
    let json = match serde_json::to_string(resp) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("[mcp] Failed to serialize response: {e}");
            return;
        }
    };
    // Each response is one line — MCP protocol uses newline-delimited JSON.
    let mut out = stdout.lock();
    if let Err(e) = writeln!(out, "{json}") {
        eprintln!("[mcp] stdout write error: {e}");
    }
    // Flush immediately — MCP clients may block waiting for response.
    let _ = out.flush();
}

// ── Request dispatch ──────────────────────────────────────────────────────────

fn handle_request(
    client: &reqwest::blocking::Client,
    server_url: &str,
    token: &str,
    id: Value,
    req: &Request,
) -> Response {
    match req.method.as_str() {
        "initialize" => handle_initialize(id),
        "tools/list" => handle_tools_list(id),
        "tools/call" => handle_tools_call(client, server_url, token, id, req.params.as_ref()),
        _ => Response::err(id, -32601, format!("Method not found: {}", req.method)),
    }
}

fn handle_initialize(id: Value) -> Response {
    Response::ok(id, serde_json::json!({
        "protocolVersion": "2024-11-05",
        "serverInfo": {
            "name": "twofold",
            "version": env!("CARGO_PKG_VERSION")
        },
        "capabilities": {
            "tools": {}
        }
    }))
}

fn handle_tools_list(id: Value) -> Response {
    Response::ok(id, serde_json::json!({
        "tools": [
            {
                "name": "twofold_publish",
                "description": "Publish a markdown document to twofold. Returns the URL and slug. Supports dual-layer rendering: human-readable content in the browser view, agent-only content accessible via the API endpoint.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "content": {
                            "type": "string",
                            "description": "Markdown content visible to humans in the browser view."
                        },
                        "agent_content": {
                            "type": "string",
                            "description": "Optional markdown content only visible via the API endpoint (/api/v1/documents/{slug}). Invisible in the human-readable browser view. Use for technical specs, API details, structured data meant for AI agents consuming the document."
                        },
                        "title": {
                            "type": "string",
                            "description": "Optional document title (prepended as frontmatter if content has none)."
                        },
                        "slug": {
                            "type": "string",
                            "description": "Optional custom URL slug."
                        },
                        "password": {
                            "type": "string",
                            "description": "Optional password to protect the document."
                        },
                        "expiry": {
                            "type": "string",
                            "description": "Optional expiry duration (e.g. '7d', '24h', '2w'). Document is automatically deleted after expiry."
                        },
                        "theme": {
                            "type": "string",
                            "description": "Optional theme name."
                        },
                        "description": {
                            "type": "string",
                            "description": "Optional document description."
                        }
                    },
                    "required": ["content"]
                }
            },
            {
                "name": "twofold_get",
                "description": "Retrieve raw markdown content for a slug.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "slug": { "type": "string", "description": "Document slug." },
                        "password": {
                            "type": "string",
                            "description": "Password for protected documents. Required if the document has a password set."
                        }
                    },
                    "required": ["slug"]
                }
            },
            {
                "name": "twofold_list",
                "description": "List published documents.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "integer",
                            "description": "Maximum results (default 20, max 100).",
                            "default": 20
                        }
                    }
                }
            },
            {
                "name": "twofold_delete",
                "description": "Delete a document by slug.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "slug": { "type": "string", "description": "Document slug to delete." }
                    },
                    "required": ["slug"]
                }
            },
            {
                "name": "twofold_update",
                "description": "Update an existing document. Returns 404 if the slug does not exist. Use twofold_publish to create new documents. Supports dual-layer rendering: human-readable content in the browser view, agent-only content accessible via the API endpoint.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "slug": {
                            "type": "string",
                            "description": "Slug of the document to update."
                        },
                        "content": {
                            "type": "string",
                            "description": "Markdown content visible to humans in the browser view."
                        },
                        "agent_content": {
                            "type": "string",
                            "description": "Optional markdown content only visible via the API endpoint (/api/v1/documents/{slug}). Invisible in the human-readable browser view. Use for technical specs, API details, structured data meant for AI agents consuming the document."
                        },
                        "title": {
                            "type": "string",
                            "description": "Optional new title (prepended as frontmatter if content has none)."
                        },
                        "description": {
                            "type": "string",
                            "description": "Optional document description."
                        },
                        "password": {
                            "type": "string",
                            "description": "Optional password to protect the document."
                        },
                        "expiry": {
                            "type": "string",
                            "description": "Optional expiry duration (e.g. '7d', '24h', '2w'). Document is automatically deleted after expiry."
                        },
                        "theme": {
                            "type": "string",
                            "description": "Optional theme name."
                        }
                    },
                    "required": ["slug", "content"]
                }
            }
        ]
    }))
}

fn handle_tools_call(
    client: &reqwest::blocking::Client,
    server_url: &str,
    token: &str,
    id: Value,
    params: Option<&Value>,
) -> Response {
    let params = match params {
        Some(p) => p,
        None => return Response::err(id, -32602, "Missing params".to_string()),
    };

    let tool_name = match params.get("name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return Response::err(id, -32602, "Missing tool name".to_string()),
    };

    let args = params.get("arguments").cloned().unwrap_or(Value::Object(Default::default()));

    let result = match tool_name {
        "twofold_publish" => tool_publish(client, server_url, token, &args),
        "twofold_get" => tool_get(client, server_url, token, &args),
        "twofold_list" => tool_list(client, server_url, token, &args),
        "twofold_delete" => tool_delete(client, server_url, token, &args),
        "twofold_update" => tool_update(client, server_url, token, &args),
        _ => tool_result_err(format!("Unknown tool: {tool_name}")),
    };

    Response::ok(id, result)
}

// ── Tool implementations ──────────────────────────────────────────────────────

/// twofold_publish: build body (with optional frontmatter injection), POST to API.
///
/// Frontmatter injection rule: if content does not start with `---` AND
/// title/slug are provided, prepend frontmatter. If content already has
/// frontmatter, send as-is (caller's frontmatter wins).
fn tool_publish(
    client: &reqwest::blocking::Client,
    server_url: &str,
    token: &str,
    args: &Value,
) -> Value {
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

    // Determine whether to inject frontmatter.
    // If content already starts with `---`, the caller controls frontmatter.
    let has_fm_args = title.is_some() || slug.is_some() || password.is_some()
        || expiry.is_some() || theme.is_some() || description.is_some();
    let mut body = if !content.trim_start().starts_with("---") && has_fm_args {
        // Build frontmatter block. YAML-escape values to handle special chars.
        let mut fm = String::from("---\n");
        if let Some(t) = title {
            fm.push_str(&format!("title: {}\n", yaml_escape_value(t)));
        }
        if let Some(s) = slug {
            fm.push_str(&format!("slug: {}\n", yaml_escape_value(s)));
        }
        if let Some(p) = password {
            fm.push_str(&format!("password: {}\n", yaml_escape_value(p)));
        }
        if let Some(ex) = expiry {
            fm.push_str(&format!("expiry: {}\n", yaml_escape_value(ex)));
        }
        if let Some(th) = theme {
            fm.push_str(&format!("theme: {}\n", yaml_escape_value(th)));
        }
        if let Some(d) = description {
            fm.push_str(&format!("description: {}\n", yaml_escape_value(d)));
        }
        fm.push_str("---\n");
        fm.push_str(content);
        fm
    } else {
        content.to_string()
    };

    // Append agent-only block if provided. Invisible in the browser view;
    // accessible via the raw API endpoint.
    if let Some(ac) = agent_content {
        body.push_str("\n\n<!-- @agent -->\n\n");
        body.push_str(ac);
        body.push_str("\n\n<!-- @end -->\n");
    }

    let url = format!("{server_url}/api/v1/documents");

    match client
        .post(&url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "text/markdown")
        .body(body)
        .send()
    {
        Ok(resp) => {
            let status = resp.status();
            let body_text = resp.text().unwrap_or_default();

            if status.is_success() {
                match serde_json::from_str::<Value>(&body_text) {
                    Ok(json) => {
                        let text = serde_json::to_string_pretty(&json).unwrap_or(body_text);
                        tool_result_ok(text)
                    }
                    Err(_) => tool_result_ok(body_text),
                }
            } else {
                // Propagate HTTP status in the error message for oncall debugging.
                tool_result_err(format!("HTTP {}: {}", status.as_u16(), body_text))
            }
        }
        Err(e) => {
            let msg = if e.is_connect() || e.is_timeout() {
                format!("Cannot reach twofold server at {server_url}: {e}")
            } else {
                format!("Request failed: {e}")
            };
            tool_result_err(msg)
        }
    }
}

fn tool_get(
    client: &reqwest::blocking::Client,
    server_url: &str,
    token: &str,
    args: &Value,
) -> Value {
    let slug = match args.get("slug").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return tool_result_err("Missing required argument: slug".to_string()),
    };

    let password = args.get("password").and_then(|v| v.as_str());

    // Append ?password=<value> when the caller supplies one.
    let url = if let Some(pw) = password {
        let encoded = percent_encode(pw);
        format!("{server_url}/api/v1/documents/{slug}?password={encoded}")
    } else {
        format!("{server_url}/api/v1/documents/{slug}")
    };

    match client
        .get(&url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
    {
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            if status.is_success() {
                tool_result_ok(body)
            } else if status.as_u16() == 401 {
                tool_result_err(format!("Document is password-protected: {body}"))
            } else if status.as_u16() == 404 {
                tool_result_err(format!("Document not found: {slug}"))
            } else {
                tool_result_err(format!("HTTP {}: {}", status.as_u16(), body))
            }
        }
        Err(e) => tool_result_err(format!("Request failed: {e}")),
    }
}

fn tool_list(
    client: &reqwest::blocking::Client,
    server_url: &str,
    token: &str,
    args: &Value,
) -> Value {
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(20);
    let url = format!("{server_url}/api/v1/documents?limit={limit}");

    match client
        .get(&url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
    {
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            if status.is_success() {
                // Format as readable text for agent consumption
                match serde_json::from_str::<Value>(&body) {
                    Ok(json) => {
                        let text = serde_json::to_string_pretty(&json).unwrap_or(body);
                        tool_result_ok(text)
                    }
                    Err(_) => tool_result_ok(body),
                }
            } else {
                tool_result_err(format!("HTTP {}: {}", status.as_u16(), body))
            }
        }
        Err(e) => tool_result_err(format!("Request failed: {e}")),
    }
}

fn tool_delete(
    client: &reqwest::blocking::Client,
    server_url: &str,
    token: &str,
    args: &Value,
) -> Value {
    let slug = match args.get("slug").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return tool_result_err("Missing required argument: slug".to_string()),
    };

    let url = format!("{server_url}/api/v1/documents/{slug}");

    match client
        .delete(&url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
    {
        Ok(resp) => {
            let status = resp.status();
            if status.as_u16() == 204 {
                tool_result_ok(serde_json::json!({"success": true}).to_string())
            } else if status.as_u16() == 404 {
                tool_result_err(format!("Document not found: {slug}"))
            } else {
                let body = resp.text().unwrap_or_default();
                tool_result_err(format!("HTTP {}: {}", status.as_u16(), body))
            }
        }
        Err(e) => tool_result_err(format!("Request failed: {e}")),
    }
}

/// twofold_update: PUT to /api/v1/documents/:slug.
///
/// Builds body the same way as tool_publish (optional frontmatter injection),
/// then sends a PUT request. Returns 404 if the slug does not exist.
fn tool_update(
    client: &reqwest::blocking::Client,
    server_url: &str,
    token: &str,
    args: &Value,
) -> Value {
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

    // Inject frontmatter for provided fields if content has none.
    // If content already starts with `---`, caller controls frontmatter.
    let has_fm_args = title.is_some() || description.is_some() || password.is_some()
        || expiry.is_some() || theme.is_some();
    let mut body = if !content.trim_start().starts_with("---") && has_fm_args {
        let mut fm = String::from("---\n");
        if let Some(t) = title {
            fm.push_str(&format!("title: {}\n", yaml_escape_value(t)));
        }
        if let Some(d) = description {
            fm.push_str(&format!("description: {}\n", yaml_escape_value(d)));
        }
        if let Some(p) = password {
            fm.push_str(&format!("password: {}\n", yaml_escape_value(p)));
        }
        if let Some(ex) = expiry {
            fm.push_str(&format!("expiry: {}\n", yaml_escape_value(ex)));
        }
        if let Some(th) = theme {
            fm.push_str(&format!("theme: {}\n", yaml_escape_value(th)));
        }
        fm.push_str("---\n");
        fm.push_str(content);
        fm
    } else {
        content.to_string()
    };

    // Append agent-only block if provided. Invisible in the browser view;
    // accessible via the raw API endpoint.
    if let Some(ac) = agent_content {
        body.push_str("\n\n<!-- @agent -->\n\n");
        body.push_str(ac);
        body.push_str("\n\n<!-- @end -->\n");
    }

    let url = format!("{server_url}/api/v1/documents/{slug}");

    match client
        .put(&url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "text/markdown")
        .body(body)
        .send()
    {
        Ok(resp) => {
            let status = resp.status();
            let body_text = resp.text().unwrap_or_default();

            if status.is_success() {
                match serde_json::from_str::<Value>(&body_text) {
                    Ok(json) => {
                        let text = serde_json::to_string_pretty(&json).unwrap_or(body_text);
                        tool_result_ok(text)
                    }
                    Err(_) => tool_result_ok(body_text),
                }
            } else if status.as_u16() == 404 {
                tool_result_err(format!("Document not found: {slug}"))
            } else if status.as_u16() == 410 {
                tool_result_err(format!("Document has expired: {slug}"))
            } else {
                tool_result_err(format!("HTTP {}: {}", status.as_u16(), body_text))
            }
        }
        Err(e) => {
            let msg = if e.is_connect() || e.is_timeout() {
                format!("Cannot reach twofold server at {server_url}: {e}")
            } else {
                format!("Request failed: {e}")
            };
            tool_result_err(msg)
        }
    }
}

// ── URL helpers ───────────────────────────────────────────────────────────────

/// Percent-encode a string for safe inclusion as a URL query parameter value.
///
/// Encodes all characters except unreserved ones (A-Z, a-z, 0-9, `-`, `_`,
/// `.`, `~`). This covers passwords that contain spaces, `@`, `/`, `+`, etc.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ── YAML value escaping ───────────────────────────────────────────────────────

/// Escape a string value for safe YAML injection.
///
/// Wraps the value in double quotes and escapes internal double quotes and
/// backslashes. Handles values containing colons, hashes, or other YAML
/// special characters that would break unquoted scalar parsing.
///
/// Limitation: multi-line values (containing \n) have their newlines replaced
/// with spaces. Slugs cannot contain newlines (validation prevents it).
/// Titles with newlines are unusual and the trade-off is acceptable for v0.3.
///
/// `pub` because main.rs uses this for CLI frontmatter injection.
pub fn yaml_escape_value_pub(s: &str) -> String {
    // Replace newlines with spaces to prevent multi-line YAML injection.
    let s = s.replace('\n', " ").replace('\r', "");
    // Escape backslashes first, then double quotes.
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn yaml_escape_value(s: &str) -> String {
    yaml_escape_value_pub(s)
}
