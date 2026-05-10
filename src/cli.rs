use clap::{Parser, Subcommand};

/// Dual-layer markdown share service.
///
/// Serves two views from one document: a styled human view and a full raw
/// agent view. POST markdown in, get a URL out.
#[derive(Parser, Debug)]
#[command(name = "twofold", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Start the HTTP server.
    ///
    /// Reads configuration from environment variables:
    ///   TWOFOLD_TOKEN   (required) Bearer token for publish auth
    ///   TWOFOLD_BIND    (optional) Bind address (default: 127.0.0.1:3000)
    ///   TWOFOLD_DB_PATH (optional) SQLite path (default: ./twofold.db)
    ///   TWOFOLD_BASE_URL (optional) Base URL (default: http://localhost:3000)
    ///   TWOFOLD_MAX_SIZE (optional) Max body bytes (default: 1048576)
    Serve,

    /// Publish a markdown document to a twofold server.
    ///
    /// Reads the file at PATH (or stdin if PATH is `-`) and POSTs it to the
    /// server. Prints the resulting URL to stdout on success. Exits 1 on failure.
    Publish(PublishArgs),
}

/// Arguments for the `publish` subcommand.
#[derive(clap::Args, Debug)]
pub struct PublishArgs {
    /// Path to the markdown file to publish, or `-` to read from stdin.
    pub path: String,

    /// Server base URL.
    #[arg(long, default_value = "http://localhost:3000")]
    pub server: String,

    /// Bearer token for authentication.
    /// Defaults to the TWOFOLD_TOKEN environment variable.
    #[arg(long)]
    pub token: Option<String>,
}
