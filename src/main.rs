//! Twofold server entry point. Route table, server setup, reaper task, and CLI dispatch.

mod auth;
mod cli;
mod config;
mod db;
mod frontmatter;
mod handlers;
mod helpers;
mod highlight;
mod mcp;
mod mcp_http;
mod oauth;
mod parser;
mod rate_limit;
mod service;
mod views;
mod webhook;

use std::sync::Arc;

use axum::http::HeaderValue;
use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post},
    Router,
};
use clap::Parser;
use tower::Layer;
use tower_http::{
    normalize_path::NormalizePathLayer, set_header::SetResponseHeaderLayer, trace::TraceLayer,
};
use tracing_subscriber::EnvFilter;

use cli::{Cli, Commands, TokenAction};
use config::ServeConfig;
use db::Db;
use handlers::AppState;
use rate_limit::RateLimitStore;

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

        // Audit log — synchronous HTTP call.
        Commands::Audit(args) => run_audit(args),
    }
}

// ---------------------------------------------------------------------------
// `twofold serve`
// ---------------------------------------------------------------------------

async fn run_server() {
    // Initialize tracing subscriber. RUST_LOG controls filtering.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("twofold=info".parse().unwrap()),
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

    // Build the rate limit store from config before moving config into Arc.
    let rate_limit = RateLimitStore::new(&config);

    let state = AppState {
        db: db.clone(),
        config: Arc::new(config),
        rate_limit: rate_limit.clone(),
    };

    // Spawn the background reaper task for expired documents and OAuth state.
    //
    // Document strategy: soft-delete tombstoning. Expired documents are NOT
    // immediately deleted — the handler's is_expired() check returns 410 for
    // them. The reaper only hard-deletes documents that expired MORE than 30
    // days ago, giving the 410 page a 30-day window before the tombstone is
    // discarded.
    //
    // OAuth strategy: hard-delete expired auth codes, access tokens, refresh
    // tokens, and registered clients on each reaper tick — they serve no
    // purpose once expired. Client sweeps previously ran per-request in the
    // registration handler; that was wasteful and has been moved here.
    let reaper_db = db.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(reaper_interval));
        loop {
            interval.tick().await;
            let now = helpers::chrono_now();
            // SQLite writes are blocking; run off the async executor.
            let db_clone = reaper_db.clone();
            let result = tokio::task::spawn_blocking(move || {
                let doc_count = db_clone.delete_expired_older_than(&now, 30)?;
                let auth_code_count = db_clone.delete_expired_auth_codes(&now)?;
                let at_count = db_clone.delete_expired_access_tokens(&now)?;
                let rt_count = db_clone.delete_expired_refresh_tokens(&now)?;
                // Sweep OAuth clients registered more than 24 hours ago.
                let client_cutoff = {
                    let cutoff = chrono::Utc::now() - chrono::Duration::hours(24);
                    cutoff.format("%Y-%m-%dT%H:%M:%SZ").to_string()
                };
                let client_count = db_clone.delete_expired_oauth_clients(&client_cutoff)?;
                Ok::<_, rusqlite::Error>((
                    doc_count,
                    auth_code_count,
                    at_count,
                    rt_count,
                    client_count,
                ))
            })
            .await;
            match result {
                Ok(Ok((docs, auth_codes, ats, rts, clients))) => {
                    if docs > 0 {
                        tracing::info!(
                            count = docs,
                            "Reaper garbage-collected tombstones older than 30 days"
                        );
                    }
                    if auth_codes + ats + rts + clients > 0 {
                        tracing::debug!(
                            auth_codes,
                            access_tokens = ats,
                            refresh_tokens = rts,
                            oauth_clients = clients,
                            "Reaper swept expired OAuth state"
                        );
                    }
                }
                Ok(Err(e)) => {
                    tracing::error!(error = %e, "Reaper failed");
                }
                Err(e) => {
                    tracing::error!(error = %e, "Reaper task panicked");
                }
            }
        }
    });

    // Spawn the background rate limit eviction task.
    //
    // Runs every 5 minutes. Removes buckets whose window started more than
    // 2× window_secs ago — these are idle IPs/tokens that will never be
    // mid-window again and would otherwise accumulate indefinitely.
    let eviction_store = rate_limit.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5 * 60));
        loop {
            interval.tick().await;
            eviction_store.evict_expired();
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
        // Health check — no auth, checked by load balancers and uptime monitors.
        .route("/health", get(handlers::health_check))
        // OAuth 2.0 well-known metadata — no auth required (RFC 8707, RFC 8414).
        .route(
            "/.well-known/oauth-protected-resource",
            get(oauth::handle_protected_resource_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth::handle_authorization_server_metadata),
        )
        // OAuth 2.0 dynamic client registration — public per RFC 7591.
        .route("/oauth/register", post(oauth::handle_register))
        // OAuth 2.0 Authorization Code flow — browser redirect, auto-approve.
        .route("/authorize", get(oauth::handle_authorize))
        // OAuth 2.0 token endpoint — client_credentials, authorization_code, refresh_token.
        .route("/oauth/token", post(oauth::handle_oauth_token))
        // Documents: POST (create) and GET (list) share the same path.
        // Axum 0.7: combine with method router chaining.
        .route(
            "/api/v1/documents",
            post(handlers::post_document).get(handlers::list_documents),
        )
        // Audit log endpoint — auth required.
        .route("/api/v1/audit", get(handlers::list_audit))
        .route(
            "/api/v1/documents/:slug",
            get(views::get_agent)
                .put(handlers::put_document)
                .delete(handlers::delete_document),
        )
        // OpenAPI spec endpoints — no auth required.
        .route("/api/v1/openapi.yaml", get(handlers::serve_openapi_yaml))
        .route("/api/v1/openapi.json", get(handlers::serve_openapi_json))
        // Icon and favicon — embedded at compile time, no auth.
        .route("/icon.png", get(handlers::serve_icon))
        .route("/favicon.ico", get(handlers::serve_favicon))
        .route("/:slug/unlock", post(views::post_unlock))
        .route("/:slug/full", get(views::get_full))
        // /:slug handles both plain slugs and /:slug.md (suffix stripped inside handler).
        .route("/:slug", get(views::get_human))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::CONTENT_SECURITY_POLICY,
            csp,
        ))
        .layer(DefaultBodyLimit::max(max_size));

    // MCP HTTP transport — 10 MB body limit to accommodate large markdown payloads
    // while preventing unbounded memory allocation. Auth is handled inside the handler.
    const MCP_MAX_BODY_BYTES: usize = 10 * 1024 * 1024;
    let mcp_router = Router::new()
        .route("/mcp", post(mcp_http::handle_mcp_post))
        .layer(DefaultBodyLimit::max(MCP_MAX_BODY_BYTES));

    let app = app
        .merge(mcp_router)
        .layer(TraceLayer::new_for_http())
        // Inject the rate limit store into request extensions so that the
        // ReadRateLimit and WriteRateLimit extractors can access it without
        // requiring the AppState — keeps the extractor module generic.
        .layer(axum::Extension(rate_limit))
        .with_state(state);

    // Wrap the entire router with NormalizePath so trailing slashes are stripped
    // before Axum's router sees the request path. NormalizePathLayer::layer()
    // produces a Service, not a MakeService, so we call into_make_service_with_connect_info()
    // on the wrapped service to expose the client socket address for IP extraction.
    let app = NormalizePathLayer::trim_trailing_slash().layer(app);
    let app = axum::ServiceExt::<axum::http::Request<axum::body::Body>>::into_make_service_with_connect_info::<std::net::SocketAddr>(app);

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
    let body = frontmatter::apply_frontmatter(
        &content,
        frontmatter::FrontmatterFields {
            title: args.title,
            slug: args.slug,
            theme: args.theme,
            expiry: args.expiry,
            password: args.password,
            description: None,
        },
    );

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
    println!("{:<24} {:<32} {:<21} EXPIRES", "SLUG", "TITLE", "CREATED");
    println!("{}", "-".repeat(90));

    for doc in docs {
        let slug = doc.get("slug").and_then(|v| v.as_str()).unwrap_or("-");
        let title = doc.get("title").and_then(|v| v.as_str()).unwrap_or("-");
        let created = doc
            .get("created_at")
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        let expires = doc
            .get("expires_at")
            .and_then(|v| v.as_str())
            .unwrap_or("never");

        // Truncate for display
        let slug_d = truncate(slug, 23);
        let title_d = truncate(title, 31);
        let created_d = &created[..std::cmp::min(16, created.len())];
        let expires_d = if expires == "never" {
            "never".to_string()
        } else {
            expires[..std::cmp::min(16, expires.len())].to_string()
        };

        println!(
            "{:<24} {:<32} {:<21} {}",
            slug_d, title_d, created_d, expires_d
        );
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
// `twofold audit`
// ---------------------------------------------------------------------------

fn run_audit(args: cli::AuditArgs) {
    let token = resolve_token(args.token);
    let url = format!(
        "{}/api/v1/audit?limit={}",
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
        eprintln!("Audit failed: HTTP {status}\n{body}");
        std::process::exit(1);
    }

    let body: serde_json::Value = match response.json() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to parse server response: {e}");
            std::process::exit(1);
        }
    };

    let entries = body.get("entries").and_then(|v| v.as_array());
    let entries = match entries {
        Some(e) => e,
        None => {
            eprintln!("Unexpected response format");
            std::process::exit(1);
        }
    };

    // Column widths: TIMESTAMP 21, ACTION 9, SLUG 25, TOKEN remainder.
    println!("{:<21} {:<9} {:<25} TOKEN", "TIMESTAMP", "ACTION", "SLUG");
    println!("{}", "-".repeat(75));

    for entry in entries {
        let timestamp = entry
            .get("timestamp")
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        let action = entry.get("action").and_then(|v| v.as_str()).unwrap_or("-");
        let slug = entry.get("slug").and_then(|v| v.as_str()).unwrap_or("-");
        let token_name = entry
            .get("token_name")
            .and_then(|v| v.as_str())
            .unwrap_or("-");

        // Truncate timestamp to 20 chars (drop sub-second noise if present)
        let ts_d = &timestamp[..std::cmp::min(20, timestamp.len())];
        let slug_d = truncate(slug, 24);

        println!("{:<21} {:<9} {:<25} {}", ts_d, action, slug_d, token_name);
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

    // Generate a 32-byte random token, base64url-encode it.
    // Retry up to 3 times on prefix collision (prefix uniqueness is enforced
    // by a UNIQUE index; collisions are astronomically unlikely but possible).
    use base64::Engine;
    use rand::RngCore;

    let now = helpers::chrono_now();

    let token_plain = 'generate: {
        for attempt in 0..3u8 {
            let mut token_bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut token_bytes);
            let plain = format!(
                "tf_{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes)
            );

            let hash = match helpers::hash_password(&plain) {
                Ok(h) => h,
                Err(_) => {
                    eprintln!("Failed to hash token");
                    std::process::exit(1);
                }
            };

            let id = nanoid::nanoid!(10);

            // Store the first 8 chars of the plaintext token as a lookup prefix.
            // This enables O(1) indexed lookup in check_auth instead of O(n × argon2).
            // The prefix is NOT a secret — it merely narrows the candidate to 1 record.
            // Argon2 verification still runs on that 1 candidate.
            let prefix = plain.chars().take(8).collect::<String>();

            let record = db::TokenRecord {
                id,
                name: name.to_string(),
                hash,
                created_at: now.clone(),
                last_used: None,
                revoked: false,
                prefix: Some(prefix),
            };

            match db.insert_token(&record) {
                Ok(()) => break 'generate plain,
                Err(e)
                    if e.to_string()
                        .contains("UNIQUE constraint failed: tokens.prefix") =>
                {
                    if attempt < 2 {
                        eprintln!(
                            "Warning: prefix collision on attempt {}; regenerating.",
                            attempt + 1
                        );
                        continue;
                    }
                    eprintln!("Failed to store token after 3 attempts (prefix collision): {e}");
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("Failed to store token: {e}");
                    std::process::exit(1);
                }
            }
        }
        // Unreachable: loop always breaks or exits, but satisfies the compiler.
        eprintln!("Failed to generate a unique token prefix.");
        std::process::exit(1);
    };

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
    println!(
        "{:<20} {:<22} {:<22} STATUS",
        "NAME", "CREATED", "LAST USED"
    );

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
