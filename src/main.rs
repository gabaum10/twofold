//! Twofold server entry point. Route table, server setup, reaper task, and CLI dispatch.

mod auth;
mod cli;
mod cli_commands;
mod config;
mod db;
mod error;
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
mod state;
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
    normalize_path::NormalizePathLayer, services::ServeDir, set_header::SetResponseHeaderLayer,
    trace::TraceLayer,
};
use tracing_subscriber::EnvFilter;

use cli::{Cli, Commands};
use config::ServeConfig;
use db::Db;
use rate_limit::RateLimitStore;
use state::AppState;

fn main() {
    let cli = Cli::parse();

    match cli.command {
        // Publish is synchronous: parse CLI, read file, POST via reqwest blocking.
        Commands::Publish(args) => cli_commands::run_publish(args),

        // List documents — synchronous HTTP call.
        Commands::List(args) => cli_commands::run_list(args),

        // Delete a document — synchronous HTTP call.
        Commands::Delete(args) => cli_commands::run_delete(args),

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
        Commands::Token(args) => cli_commands::run_token(args),

        // Audit log — synchronous HTTP call.
        Commands::Audit(args) => cli_commands::run_audit(args),

        // OAuth client management — direct database access, no server needed.
        Commands::Client(args) => cli_commands::run_client(args),
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
    // We control all HTML output. script-src 'self' allows /static/twofold.js and
    // nothing else — no inline scripts, no external origins. Compatible with nginx
    // proxies that enforce their own script-src policies.
    let csp = HeaderValue::from_static(
        "default-src 'self'; script-src 'self'; style-src 'unsafe-inline'",
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
        // Static assets (twofold.js, etc.) — must be registered before /:slug catch-all.
        .nest_service("/static", ServeDir::new("static"))
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
        .route(
            "/mcp",
            get(mcp_http::handle_mcp_get).post(mcp_http::handle_mcp_post),
        )
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
