mod cli;
mod config;
mod db;
mod handlers;
mod highlight;
mod mcp;
mod parser;
mod webhook;

use std::sync::Arc;

use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post},
    Router,
};
use clap::Parser;
use axum::http::HeaderValue;
use tower_http::{set_header::SetResponseHeaderLayer, trace::TraceLayer};
use tracing_subscriber::EnvFilter;

use cli::{Cli, Commands, TokenAction};
use config::ServeConfig;
use db::Db;
use handlers::AppState;

fn main() {
    let cli = Cli::parse();

    match cli.command {
        // Publish is synchronous: parse CLI, read file, POST via reqwest blocking.
        Commands::Publish(args) => run_publish(args),

        // List documents — synchronous HTTP call.
        Commands::List(args) => run_list(args),

        // Delete a document — synchronous HTTP call.
        Commands::Delete(args) => run_delete(args),

        // Serve requires async: build the Tokio runtime here.
        Commands::Serve => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("Failed to build Tokio runtime");
            rt.block_on(run_server());
        }

        // MCP server: synchronous blocking I/O on stdio.
        Commands::Mcp => mcp::run_mcp_server(),

        // Token management — direct database access, no server needed.
        Commands::Token(args) => run_token(args),
    }
}

// ---------------------------------------------------------------------------
// `twofold serve`
// ---------------------------------------------------------------------------

async fn run_server() {
    // Initialize tracing subscriber. RUST_LOG controls filtering.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive("twofold=info".parse().unwrap()),
        )
        .init();

    // Load config — fail fast with a useful error, no panic.
    let config = match ServeConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Configuration error: {e}");
            std::process::exit(1);
        }
    };

    // Open or create the SQLite database.
    let db = match Db::open(&config.db_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to open database '{}': {e}", config.db_path);
            std::process::exit(1);
        }
    };

    let max_size = config.max_size;
    let bind_addr = config.bind.clone();
    let reaper_interval = config.reaper_interval;

    let state = AppState {
        db: db.clone(),
        config: Arc::new(config),
    };

    // Spawn the background reaper task for expired documents
    let reaper_db = db.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(
            std::time::Duration::from_secs(reaper_interval),
        );
        loop {
            interval.tick().await;
            let now = handlers::chrono_now();
            match reaper_db.delete_expired(&now) {
                Ok(count) if count > 0 => {
                    tracing::info!(count, "Reaper cleaned up expired documents");
                }
                Ok(_) => {} // nothing to reap
                Err(e) => {
                    tracing::error!(error = %e, "Reaper failed to delete expired documents");
                }
            }
        }
    });

    // Build the router.
    //
    // Route ordering matters: API routes must be registered BEFORE the
    // slug catch-all, otherwise axum would try to parse "api" as a slug.
    // XSS threat model: only trusted publishers can POST content (bearer token auth).
    // We control all HTML output, so inline scripts are safe here.
    // 'unsafe-inline' is required for our own toolbar buttons (clipboard, toast, slug derivation).
    // External script sources are still blocked by default-src 'self'.
    let csp = HeaderValue::from_static(
        "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'",
    );

    let app = Router::new()
        // Documents: POST (create) and GET (list) share the same path.
        // Axum 0.7: combine with method router chaining.
        .route("/api/v1/documents", post(handlers::post_document).get(handlers::list_documents))
        .route("/api/v1/documents/:slug", get(handlers::get_agent)
            .put(handlers::put_document)
            .delete(handlers::delete_document))
        // OpenAPI spec endpoints — no auth required.
        .route("/api/v1/openapi.yaml", get(handlers::serve_openapi_yaml))
        .route("/api/v1/openapi.json", get(handlers::serve_openapi_json))
        .route("/:slug/unlock", post(handlers::post_unlock))
        .route("/:slug/full", get(handlers::get_full))
        .route("/:slug", get(handlers::get_human))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::CONTENT_SECURITY_POLICY,
            csp,
        ))
        .layer(DefaultBodyLimit::max(max_size))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = match tokio::net::TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind to '{bind_addr}': {e}");
            std::process::exit(1);
        }
    };

    // Print bind address to stdout on start.
    println!("twofold listening on http://{bind_addr}");

    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("Server error: {e}");
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// `twofold publish <path|->`
// ---------------------------------------------------------------------------

fn run_publish(args: cli::PublishArgs) {
    // Resolve token: --token flag > TWOFOLD_TOKEN env var.
    let token = resolve_token(args.token);

    // Read content: file path or stdin.
    let content = read_publish_source(&args.path);

    // Apply frontmatter from CLI flags if any flags were provided.
    // If content already has frontmatter (starts with ---), merge flags in.
    // If no frontmatter and no flags, send as-is.
    let body = apply_publish_flags(content, args.title, args.slug, args.theme, args.expiry, args.password);

    // POST to the server.
    let url = format!("{}/api/v1/documents", args.server.trim_end_matches('/'));

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to create HTTP client: {e}");
            std::process::exit(1);
        }
    };

    let response = match client
        .post(&url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "text/markdown")
        .body(body)
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Request failed: {e}");
            std::process::exit(1);
        }
    };

    let status = response.status();

    if status == reqwest::StatusCode::CREATED {
        let body: serde_json::Value = match response.json() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Failed to parse server response: {e}");
                std::process::exit(1);
            }
        };
        if let Some(doc_url) = body.get("url").and_then(|v| v.as_str()) {
            println!("{doc_url}");
        } else {
            eprintln!("Server returned 201 but no `url` field in response.");
            std::process::exit(1);
        }
    } else {
        let body_text = response.text().unwrap_or_default();
        eprintln!("Publish failed: HTTP {status}\n{body_text}");
        std::process::exit(1);
    }
}

/// Apply CLI publish flags to content, injecting or merging frontmatter.
///
/// Rules:
/// - If content has no frontmatter AND flags provided: prepend frontmatter.
/// - If content has frontmatter AND flags provided: merge (CLI flags win on conflict).
/// - If no flags: return content unchanged.
fn apply_publish_flags(
    content: String,
    title: Option<String>,
    slug: Option<String>,
    theme: Option<String>,
    expiry: Option<String>,
    password: Option<String>,
) -> String {
    let has_flags = title.is_some() || slug.is_some() || theme.is_some()
        || expiry.is_some() || password.is_some();
    if !has_flags {
        return content;
    }

    let trimmed = content.trim_start();
    if trimmed.starts_with("---") {
        // Content has frontmatter — parse and merge CLI flags.
        merge_frontmatter_flags(content, title, slug, theme, expiry, password)
    } else {
        // No frontmatter — prepend it.
        let mut fm = String::from("---\n");
        if let Some(t) = title {
            fm.push_str(&format!("title: {}\n", crate::mcp::yaml_escape_value_pub(&t)));
        }
        if let Some(s) = slug {
            fm.push_str(&format!("slug: {}\n", crate::mcp::yaml_escape_value_pub(&s)));
        }
        if let Some(th) = theme {
            fm.push_str(&format!("theme: {}\n", crate::mcp::yaml_escape_value_pub(&th)));
        }
        if let Some(ex) = expiry {
            fm.push_str(&format!("expiry: {}\n", crate::mcp::yaml_escape_value_pub(&ex)));
        }
        if let Some(pw) = password {
            fm.push_str(&format!("password: {}\n", crate::mcp::yaml_escape_value_pub(&pw)));
        }
        fm.push_str("---\n");
        fm.push_str(&content);
        fm
    }
}

/// Merge CLI flags into existing frontmatter. CLI wins on conflict.
///
/// Strategy: parse the existing frontmatter block line-by-line. For each
/// key that a CLI flag would set, replace the existing value if present,
/// or append if absent. This is a simple line-based approach — correct for
/// the single-line scalar values twofold uses.
fn merge_frontmatter_flags(
    content: String,
    title: Option<String>,
    slug: Option<String>,
    theme: Option<String>,
    expiry: Option<String>,
    password: Option<String>,
) -> String {
    let lines: Vec<&str> = content.lines().collect();

    // Find the closing --- of the frontmatter block.
    let mut close_idx = None;
    for (i, line) in lines.iter().enumerate().skip(1) {
        if line.trim() == "---" {
            close_idx = Some(i);
            break;
        }
    }

    let close_idx = match close_idx {
        Some(i) => i,
        None => {
            // No closing fence — treat as no frontmatter, prepend new block.
            // Fallback: just prepend the flags as a new block.
            let mut fm = String::from("---\n");
            if let Some(t) = title {
                fm.push_str(&format!("title: {}\n", crate::mcp::yaml_escape_value_pub(&t)));
            }
            if let Some(s) = slug {
                fm.push_str(&format!("slug: {}\n", crate::mcp::yaml_escape_value_pub(&s)));
            }
            if let Some(th) = theme {
                fm.push_str(&format!("theme: {}\n", crate::mcp::yaml_escape_value_pub(&th)));
            }
            if let Some(ex) = expiry {
                fm.push_str(&format!("expiry: {}\n", crate::mcp::yaml_escape_value_pub(&ex)));
            }
            if let Some(pw) = password {
                fm.push_str(&format!("password: {}\n", crate::mcp::yaml_escape_value_pub(&pw)));
            }
            fm.push_str("---\n");
            fm.push_str(&content);
            return fm;
        }
    };

    // Build a set of keys to override.
    let overrides: Vec<(&str, &str)> = [
        title.as_deref().map(|v| ("title", v)),
        slug.as_deref().map(|v| ("slug", v)),
        theme.as_deref().map(|v| ("theme", v)),
        expiry.as_deref().map(|v| ("expiry", v)),
        password.as_deref().map(|v| ("password", v)),
    ]
    .into_iter()
    .flatten()
    .collect();

    let mut fm_lines: Vec<String> = lines[1..close_idx].iter().map(|s| s.to_string()).collect();

    // For each override, check if the key exists in fm_lines and replace; otherwise append.
    for (key, val) in &overrides {
        let new_line = format!("{key}: {}", crate::mcp::yaml_escape_value_pub(val));
        let prefix = format!("{key}:");
        let found = fm_lines.iter_mut().any(|line| {
            if line.trim_start().starts_with(&prefix) {
                *line = new_line.clone();
                true
            } else {
                false
            }
        });
        if !found {
            fm_lines.push(new_line);
        }
    }

    // Reconstruct the document.
    let mut result = String::from("---\n");
    for line in &fm_lines {
        result.push_str(line);
        result.push('\n');
    }
    result.push_str("---\n");
    // Body: everything after the closing ---
    if close_idx + 1 < lines.len() {
        result.push_str(&lines[close_idx + 1..].join("\n"));
    }
    result
}

/// Read content from a file path or stdin (`-`).
fn read_publish_source(path: &str) -> String {
    if path == "-" {
        use std::io::Read;
        let mut buf = String::new();
        if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
            eprintln!("Failed to read from stdin: {e}");
            std::process::exit(1);
        }
        buf
    } else {
        match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to read file '{path}': {e}");
                std::process::exit(1);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// `twofold list`
// ---------------------------------------------------------------------------

fn run_list(args: cli::ListArgs) {
    let token = resolve_token(args.token);
    let url = format!(
        "{}/api/v1/documents?limit={}",
        args.server.trim_end_matches('/'),
        args.limit
    );

    let client = make_blocking_client();

    let response = match client
        .get(&url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Request failed: {e}");
            std::process::exit(1);
        }
    };

    let status = response.status();
    if !status.is_success() {
        let body = response.text().unwrap_or_default();
        eprintln!("List failed: HTTP {status}\n{body}");
        std::process::exit(1);
    }

    let body: serde_json::Value = match response.json() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to parse server response: {e}");
            std::process::exit(1);
        }
    };

    let docs = body.get("documents").and_then(|v| v.as_array());
    let docs = match docs {
        Some(d) => d,
        None => {
            eprintln!("Unexpected response format");
            std::process::exit(1);
        }
    };

    // Print table with fixed-width columns.
    println!("{:<24} {:<32} {:<21} {}",
        "SLUG", "TITLE", "CREATED", "EXPIRES");
    println!("{}", "-".repeat(90));

    for doc in docs {
        let slug = doc.get("slug").and_then(|v| v.as_str()).unwrap_or("-");
        let title = doc.get("title").and_then(|v| v.as_str()).unwrap_or("-");
        let created = doc.get("created_at").and_then(|v| v.as_str()).unwrap_or("-");
        let expires = doc.get("expires_at").and_then(|v| v.as_str()).unwrap_or("never");

        // Truncate for display
        let slug_d = truncate(slug, 23);
        let title_d = truncate(title, 31);
        let created_d = &created[..std::cmp::min(16, created.len())];
        let expires_d = if expires == "never" {
            "never".to_string()
        } else {
            expires[..std::cmp::min(16, expires.len())].to_string()
        };

        println!("{:<24} {:<32} {:<21} {}", slug_d, title_d, created_d, expires_d);
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max - 1])
    }
}

// ---------------------------------------------------------------------------
// `twofold delete <slug>`
// ---------------------------------------------------------------------------

fn run_delete(args: cli::DeleteArgs) {
    let token = resolve_token(args.token);
    let url = format!(
        "{}/api/v1/documents/{}",
        args.server.trim_end_matches('/'),
        args.slug
    );

    let client = make_blocking_client();

    let response = match client
        .delete(&url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Request failed: {e}");
            std::process::exit(1);
        }
    };

    let status = response.status();
    match status.as_u16() {
        204 => println!("Deleted: {}", args.slug),
        401 => {
            eprintln!("Auth error: check your token");
            std::process::exit(1);
        }
        404 => {
            eprintln!("Error: document '{}' not found", args.slug);
            std::process::exit(1);
        }
        _ => {
            let body = response.text().unwrap_or_default();
            eprintln!("Delete failed: HTTP {status}\n{body}");
            std::process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// `twofold token {create|list|revoke}`
// ---------------------------------------------------------------------------

fn run_token(args: cli::TokenArgs) {
    match args.action {
        TokenAction::Create { name, db } => token_create(&name, &resolve_db_path(db)),
        TokenAction::List { db } => token_list(&resolve_db_path(db)),
        TokenAction::Revoke { name, db } => token_revoke(&name, &resolve_db_path(db)),
    }
}

fn resolve_db_path(explicit: Option<String>) -> String {
    explicit
        .or_else(|| std::env::var("TWOFOLD_DB_PATH").ok())
        .unwrap_or_else(|| "./twofold.db".to_string())
}

fn resolve_token(explicit: Option<String>) -> String {
    match explicit {
        Some(t) => t,
        None => match std::env::var("TWOFOLD_TOKEN") {
            Ok(t) => t,
            Err(_) => {
                eprintln!(
                    "Error: --token not provided and TWOFOLD_TOKEN is not set.\n\
                     Provide a token via --token <TOKEN> or set TWOFOLD_TOKEN."
                );
                std::process::exit(1);
            }
        },
    }
}

fn make_blocking_client() -> reqwest::blocking::Client {
    match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to create HTTP client: {e}");
            std::process::exit(1);
        }
    }
}

fn token_create(name: &str, db_path: &str) {
    let db = match Db::open(db_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to open database '{db_path}': {e}");
            std::process::exit(1);
        }
    };

    // Check for duplicate name
    match db.token_name_exists(name) {
        Ok(true) => {
            eprintln!("Error: Token name '{name}' already exists.");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Database error: {e}");
            std::process::exit(1);
        }
        _ => {}
    }

    // Generate a 32-byte random token, base64url-encode it
    use rand::RngCore;
    use base64::Engine;

    let mut token_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut token_bytes);
    let token_plain = format!(
        "tf_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes)
    );

    // Hash the token
    let hash = match handlers::hash_password(&token_plain) {
        Ok(h) => h,
        Err(_) => {
            eprintln!("Failed to hash token");
            std::process::exit(1);
        }
    };

    let now = handlers::chrono_now();
    let id = nanoid::nanoid!(10);

    let record = db::TokenRecord {
        id,
        name: name.to_string(),
        hash,
        created_at: now,
        last_used: None,
        revoked: false,
    };

    if let Err(e) = db.insert_token(&record) {
        eprintln!("Failed to store token: {e}");
        std::process::exit(1);
    }

    // Print the plaintext token ONCE
    println!("{token_plain}");
}

fn token_list(db_path: &str) {
    let db = match Db::open(db_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to open database '{db_path}': {e}");
            std::process::exit(1);
        }
    };

    let tokens = match db.list_tokens() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to list tokens: {e}");
            std::process::exit(1);
        }
    };

    // Print table header
    println!("{:<20} {:<22} {:<22} {}",
        "NAME", "CREATED", "LAST USED", "STATUS");

    for token in tokens {
        let status = if token.revoked { "revoked" } else { "active" };
        let last_used = token.last_used.as_deref().unwrap_or("never");
        // Truncate timestamps for display
        let created = &token.created_at[..std::cmp::min(16, token.created_at.len())];
        let used = if last_used == "never" {
            "never".to_string()
        } else {
            last_used[..std::cmp::min(16, last_used.len())].to_string()
        };
        println!("{:<20} {:<22} {:<22} {}", token.name, created, used, status);
    }
}

fn token_revoke(name: &str, db_path: &str) {
    let db = match Db::open(db_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to open database '{db_path}': {e}");
            std::process::exit(1);
        }
    };

    match db.revoke_token(name) {
        Ok(true) => println!("Token '{name}' revoked."),
        Ok(false) => {
            eprintln!("Error: Token '{name}' not found or already revoked.");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Database error: {e}");
            std::process::exit(1);
        }
    }
}
