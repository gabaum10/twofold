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

        Ok(ServeConfig {
            token,
            bind,
            db_path,
            base_url,
            max_size,
        })
    }
}
