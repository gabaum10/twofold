mod cli;
mod config;
mod db;
mod handlers;
mod parser;

use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};
use clap::Parser;
use tower_http::{limit::RequestBodyLimitLayer, trace::TraceLayer};
use tracing_subscriber::EnvFilter;

use cli::{Cli, Commands};
use config::ServeConfig;
use db::Db;
use handlers::AppState;

fn main() {
    let cli = Cli::parse();

    match cli.command {
        // Publish is synchronous: parse CLI, read file, POST via reqwest blocking.
        // It MUST run outside a Tokio runtime context to avoid the
        // "Cannot drop runtime in async context" panic with reqwest blocking.
        Commands::Publish(args) => run_publish(args),

        // Serve requires async: build the Tokio runtime here.
        Commands::Serve => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("Failed to build Tokio runtime");
            rt.block_on(run_server());
        }
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

    let state = AppState {
        db,
        config: Arc::new(config),
    };

    // Build the router.
    //
    // Route ordering matters: the API routes must be registered BEFORE the
    // slug catch-all, otherwise axum would try to parse "api" as a slug.
    //
    // RequestBodyLimitLayer is applied globally; it returns 413 automatically
    // when the body exceeds max_size bytes.
    let app = Router::new()
        .route("/api/v1/documents", post(handlers::post_document))
        .route("/api/v1/documents/:slug", get(handlers::get_agent))
        .route("/:slug", get(handlers::get_human))
        .layer(RequestBodyLimitLayer::new(max_size))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = match tokio::net::TcpListener::bind(&bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind to '{bind_addr}': {e}");
            std::process::exit(1);
        }
    };

    // Print bind address to stdout (per spec: "Prints bind address to stdout on start").
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
///
/// Does NOT use .unwrap() on user-provided paths.
/// Exits with exit code 1 and an error message on failure.
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
