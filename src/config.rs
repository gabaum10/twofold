/// Configuration loaded from environment variables.
///
/// Contract: `from_env()` fails fast if SHARESVC_TOKEN is absent.
/// All other vars have sensible defaults. Error messages are human-readable.
#[derive(Clone, Debug)]
pub struct ServeConfig {
    /// Bearer token for publish auth (SHARESVC_TOKEN — required)
    pub token: String,
    /// Bind address (SHARESVC_BIND — default: 127.0.0.1:3000)
    pub bind: String,
    /// SQLite database path (SHARESVC_DB_PATH — default: ./sharesvc.db)
    pub db_path: String,
    /// Base URL for response URLs (SHARESVC_BASE_URL — default: http://localhost:3000)
    pub base_url: String,
    /// Max request body size in bytes (SHARESVC_MAX_SIZE — default: 1048576)
    pub max_size: usize,
}

impl ServeConfig {
    /// Load configuration from environment variables.
    ///
    /// Returns Err with a human-readable message if required vars are missing
    /// or if numeric vars cannot be parsed. Does NOT panic.
    pub fn from_env() -> Result<Self, String> {
        let token = std::env::var("SHARESVC_TOKEN").map_err(|_| {
            "SHARESVC_TOKEN is required but not set. \
             Set it to a secret bearer token before starting the server."
                .to_string()
        })?;

        if token.is_empty() {
            return Err("SHARESVC_TOKEN must not be empty.".to_string());
        }

        let bind = std::env::var("SHARESVC_BIND")
            .unwrap_or_else(|_| "127.0.0.1:3000".to_string());

        let db_path = std::env::var("SHARESVC_DB_PATH")
            .unwrap_or_else(|_| "./sharesvc.db".to_string());

        let base_url = std::env::var("SHARESVC_BASE_URL")
            .unwrap_or_else(|_| "http://localhost:3000".to_string());

        let max_size = match std::env::var("SHARESVC_MAX_SIZE") {
            Ok(s) => s.parse::<usize>().map_err(|_| {
                format!("SHARESVC_MAX_SIZE must be a positive integer, got: {s}")
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
