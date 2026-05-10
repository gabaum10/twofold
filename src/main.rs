mod cli;
mod config;
mod db;
mod handlers;
mod parser;

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

        // Serve requires async: build the Tokio runtime here.
        Commands::Serve => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("Failed to build Tokio runtime");
            rt.block_on(run_server());
        }

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
        .route("/api/v1/documents", post(handlers::post_document))
        .route("/api/v1/documents/:slug", get(handlers::get_agent)
            .put(handlers::put_document)
            .delete(handlers::delete_document))
        .route("/:slug/unlock", post(handlers::post_unlock))
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
    let token = match args.token {
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
    };

    // Read content: file path or stdin.
    let content = read_publish_source(&args.path);

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
        .body(content)
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
