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
    ///   TWOFOLD_REAPER_INTERVAL (optional) Reaper interval seconds (default: 60)
    ///   TWOFOLD_DEFAULT_THEME (optional) Default theme (default: clean)
    ///   TWOFOLD_WEBHOOK_URL (optional) Webhook endpoint URL
    ///   TWOFOLD_WEBHOOK_SECRET (optional) HMAC signing secret for webhooks
    Serve,

    /// Publish a markdown document to a twofold server.
    ///
    /// Reads the file at PATH (or stdin if PATH is `-`) and POSTs it to the
    /// server. Prints the resulting URL to stdout on success. Exits 1 on failure.
    Publish(PublishArgs),

    /// List published documents on a twofold server.
    List(ListArgs),

    /// Delete a document by slug.
    Delete(DeleteArgs),

    /// Manage API tokens.
    Token(TokenArgs),

    /// Start the MCP server (stdio JSON-RPC).
    ///
    /// Reads:
    ///   TWOFOLD_MCP_SERVER  Server URL (default: http://localhost:3000)
    ///   TWOFOLD_MCP_TOKEN   Bearer token (falls back to TWOFOLD_TOKEN)
    Mcp,
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

    /// Document title (prepended as frontmatter).
    #[arg(long)]
    pub title: Option<String>,

    /// Custom slug (prepended as frontmatter).
    #[arg(long)]
    pub slug: Option<String>,

    /// Theme (clean, dark, paper, minimal).
    #[arg(long)]
    pub theme: Option<String>,

    /// Expiry duration (e.g., 7d, 24h, 30m, 2w).
    #[arg(long)]
    pub expiry: Option<String>,
}

/// Arguments for the `list` subcommand.
#[derive(clap::Args, Debug)]
pub struct ListArgs {
    /// Server base URL.
    #[arg(long, default_value = "http://localhost:3000")]
    pub server: String,

    /// Bearer token for authentication.
    /// Defaults to the TWOFOLD_TOKEN environment variable.
    #[arg(long)]
    pub token: Option<String>,

    /// Maximum number of documents to show.
    #[arg(long, default_value = "20")]
    pub limit: u32,
}

/// Arguments for the `delete` subcommand.
#[derive(clap::Args, Debug)]
pub struct DeleteArgs {
    /// Slug of the document to delete.
    pub slug: String,

    /// Server base URL.
    #[arg(long, default_value = "http://localhost:3000")]
    pub server: String,

    /// Bearer token for authentication.
    /// Defaults to the TWOFOLD_TOKEN environment variable.
    #[arg(long)]
    pub token: Option<String>,
}

/// Arguments for the `token` subcommand.
#[derive(clap::Args, Debug)]
pub struct TokenArgs {
    #[command(subcommand)]
    pub action: TokenAction,
}

#[derive(Subcommand, Debug)]
pub enum TokenAction {
    /// Create a new API token.
    Create {
        /// Human-readable name for the token.
        #[arg(long)]
        name: String,

        /// Path to the SQLite database.
        /// Defaults to TWOFOLD_DB_PATH or ./twofold.db.
        #[arg(long)]
        db: Option<String>,
    },

    /// List all tokens.
    List {
        /// Path to the SQLite database.
        #[arg(long)]
        db: Option<String>,
    },

    /// Revoke a token by name.
    Revoke {
        /// Name of the token to revoke.
        #[arg(long)]
        name: String,

        /// Path to the SQLite database.
        #[arg(long)]
        db: Option<String>,
    },
}
