/// Configuration loaded from environment variables.
///
/// Contract: `from_env()` fails fast if TWOFOLD_TOKEN is absent.
/// All other vars have sensible defaults. Error messages are human-readable.
#[derive(Clone, Debug)]
pub struct ServeConfig {
    /// Bearer token for publish auth (TWOFOLD_TOKEN — required)
    pub token: String,
    /// Bind address (TWOFOLD_BIND — default: 127.0.0.1:3000)
    pub bind: String,
    /// SQLite database path (TWOFOLD_DB_PATH — default: ./twofold.db)
    pub db_path: String,
    /// Base URL for response URLs (TWOFOLD_BASE_URL — default: http://localhost:3000)
    pub base_url: String,
    /// Max request body size in bytes (TWOFOLD_MAX_SIZE — default: 1048576)
    pub max_size: usize,
    /// Reaper interval in seconds (TWOFOLD_REAPER_INTERVAL — default: 60)
    pub reaper_interval: u64,
    /// Default theme when none specified (TWOFOLD_DEFAULT_THEME — default: clean)
    pub default_theme: String,
    /// Webhook endpoint URL (TWOFOLD_WEBHOOK_URL — optional, no webhook if unset)
    pub webhook_url: Option<String>,
    /// HMAC-SHA256 signing secret for webhooks (TWOFOLD_WEBHOOK_SECRET — optional)
    pub webhook_secret: Option<String>,
}

impl ServeConfig {
    /// Load configuration from environment variables.
    ///
    /// Returns Err with a human-readable message if required vars are missing
    /// or if numeric vars cannot be parsed. Does NOT panic.
    pub fn from_env() -> Result<Self, String> {
        let token = std::env::var("TWOFOLD_TOKEN").map_err(|_| {
            "TWOFOLD_TOKEN is required but not set. \
             Set it to a secret bearer token before starting the server."
                .to_string()
        })?;

        if token.is_empty() {
            return Err("TWOFOLD_TOKEN must not be empty.".to_string());
        }

        let bind = std::env::var("TWOFOLD_BIND")
            .unwrap_or_else(|_| "127.0.0.1:3000".to_string());

        let db_path = std::env::var("TWOFOLD_DB_PATH")
            .unwrap_or_else(|_| "./twofold.db".to_string());

        let base_url = std::env::var("TWOFOLD_BASE_URL")
            .unwrap_or_else(|_| "http://localhost:3000".to_string());

        let max_size = match std::env::var("TWOFOLD_MAX_SIZE") {
            Ok(s) => s.parse::<usize>().map_err(|_| {
                format!("TWOFOLD_MAX_SIZE must be a positive integer, got: {s}")
            })?,
            Err(_) => 1_048_576,
        };

        let reaper_interval = match std::env::var("TWOFOLD_REAPER_INTERVAL") {
            Ok(s) => s.parse::<u64>().map_err(|_| {
                format!("TWOFOLD_REAPER_INTERVAL must be a positive integer, got: {s}")
            })?,
            Err(_) => 60,
        };

        let default_theme = std::env::var("TWOFOLD_DEFAULT_THEME")
            .unwrap_or_else(|_| "clean".to_string());

        // Webhook configuration — both are optional. No webhook fired if URL is unset.
        let webhook_url = std::env::var("TWOFOLD_WEBHOOK_URL")
            .ok()
            .and_then(|s| if s.is_empty() { None } else { Some(s) });

        let webhook_secret = std::env::var("TWOFOLD_WEBHOOK_SECRET")
            .ok()
            .and_then(|s| if s.is_empty() { None } else { Some(s) });

        Ok(ServeConfig {
            token,
            bind,
            db_path,
            base_url,
            max_size,
            reaper_interval,
            default_theme,
            webhook_url,
            webhook_secret,
        })
    }
}
