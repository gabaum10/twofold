//! Environment variable configuration. `ServeConfig` struct; fails fast if `TWOFOLD_TOKEN` is absent.

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
    /// Max read requests per IP per window (TWOFOLD_RATE_LIMIT_READ — default: 60)
    pub rate_limit_read: u32,
    /// Max write requests per token per window (TWOFOLD_RATE_LIMIT_WRITE — default: 30)
    pub rate_limit_write: u32,
    /// Window duration in seconds for both buckets (TWOFOLD_RATE_LIMIT_WINDOW — default: 60)
    pub rate_limit_window: u64,
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

        let bind = std::env::var("TWOFOLD_BIND").unwrap_or_else(|_| "127.0.0.1:3000".to_string());

        let db_path =
            std::env::var("TWOFOLD_DB_PATH").unwrap_or_else(|_| "./twofold.db".to_string());

        let base_url = std::env::var("TWOFOLD_BASE_URL")
            .unwrap_or_else(|_| "http://localhost:3000".to_string());
        url::Url::parse(&base_url)
            .map_err(|e| format!("TWOFOLD_BASE_URL is not a valid URL (got '{base_url}'): {e}"))?;

        let max_size = match std::env::var("TWOFOLD_MAX_SIZE") {
            Ok(s) => s
                .parse::<usize>()
                .map_err(|_| format!("TWOFOLD_MAX_SIZE must be a positive integer, got: {s}"))?,
            Err(_) => 1_048_576,
        };

        let reaper_interval = match std::env::var("TWOFOLD_REAPER_INTERVAL") {
            Ok(s) => s.parse::<u64>().map_err(|_| {
                format!("TWOFOLD_REAPER_INTERVAL must be a positive integer, got: {s}")
            })?,
            Err(_) => 60,
        };

        let default_theme =
            std::env::var("TWOFOLD_DEFAULT_THEME").unwrap_or_else(|_| "clean".to_string());

        // Webhook configuration — both are optional. No webhook fired if URL is unset.
        let webhook_url = std::env::var("TWOFOLD_WEBHOOK_URL").ok().and_then(|s| {
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        });
        if let Some(ref u) = webhook_url {
            url::Url::parse(u)
                .map_err(|e| format!("TWOFOLD_WEBHOOK_URL is not a valid URL (got '{u}'): {e}"))?;
        }

        let webhook_secret = std::env::var("TWOFOLD_WEBHOOK_SECRET").ok().and_then(|s| {
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        });

        // Rate limiting configuration — all optional with sensible defaults.
        let rate_limit_read = match std::env::var("TWOFOLD_RATE_LIMIT_READ") {
            Ok(s) => s.parse::<u32>().map_err(|_| {
                format!("TWOFOLD_RATE_LIMIT_READ must be a positive integer, got: {s}")
            })?,
            Err(_) => 60,
        };

        let rate_limit_write = match std::env::var("TWOFOLD_RATE_LIMIT_WRITE") {
            Ok(s) => s.parse::<u32>().map_err(|_| {
                format!("TWOFOLD_RATE_LIMIT_WRITE must be a positive integer, got: {s}")
            })?,
            Err(_) => 30,
        };

        let rate_limit_window = match std::env::var("TWOFOLD_RATE_LIMIT_WINDOW") {
            Ok(s) => s.parse::<u64>().map_err(|_| {
                format!("TWOFOLD_RATE_LIMIT_WINDOW must be a positive integer, got: {s}")
            })?,
            Err(_) => 60,
        };

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
            rate_limit_read,
            rate_limit_write,
            rate_limit_window,
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serialize env-var tests with a process-wide mutex.
    ///
    /// Rust test threads share a process, so concurrent tests that mutate
    /// environment variables race each other. This mutex ensures the three
    /// `from_env_*` tests run one at a time, each with a clean slate.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Clear all TWOFOLD_* vars so each test starts from a known state.
    fn clear_twofold_env() {
        for key in &[
            "TWOFOLD_TOKEN",
            "TWOFOLD_BIND",
            "TWOFOLD_DB_PATH",
            "TWOFOLD_BASE_URL",
            "TWOFOLD_MAX_SIZE",
            "TWOFOLD_REAPER_INTERVAL",
            "TWOFOLD_DEFAULT_THEME",
            "TWOFOLD_WEBHOOK_URL",
            "TWOFOLD_WEBHOOK_SECRET",
            "TWOFOLD_RATE_LIMIT_READ",
            "TWOFOLD_RATE_LIMIT_WRITE",
            "TWOFOLD_RATE_LIMIT_WINDOW",
        ] {
            std::env::remove_var(key);
        }
    }

    /// TWOFOLD_TOKEN absent → from_env returns an error.
    #[test]
    fn from_env_missing_token_errors() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_twofold_env();

        let result = ServeConfig::from_env();
        assert!(
            result.is_err(),
            "expected error when TWOFOLD_TOKEN is absent"
        );
        let msg = result.unwrap_err();
        assert!(
            msg.contains("TWOFOLD_TOKEN"),
            "error message should mention TWOFOLD_TOKEN, got: {msg}"
        );
    }

    /// Unset optional vars get their documented defaults.
    #[test]
    fn from_env_defaults() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_twofold_env();
        std::env::set_var("TWOFOLD_TOKEN", "test-secret");

        let cfg = ServeConfig::from_env().expect("from_env should succeed with token set");

        assert_eq!(cfg.token, "test-secret");
        assert_eq!(cfg.bind, "127.0.0.1:3000");
        assert_eq!(cfg.db_path, "./twofold.db");
        assert_eq!(cfg.base_url, "http://localhost:3000");
        assert_eq!(cfg.max_size, 1_048_576);
        assert_eq!(cfg.reaper_interval, 60);
        assert_eq!(cfg.default_theme, "clean");
        assert!(cfg.webhook_url.is_none());
        assert!(cfg.webhook_secret.is_none());
        assert_eq!(cfg.rate_limit_read, 60);
        assert_eq!(cfg.rate_limit_write, 30);
        assert_eq!(cfg.rate_limit_window, 60);
    }

    /// An invalid TWOFOLD_WEBHOOK_URL fails at startup with a descriptive error.
    #[test]
    fn from_env_bad_url_errors() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_twofold_env();
        std::env::set_var("TWOFOLD_TOKEN", "test-secret");
        std::env::set_var("TWOFOLD_WEBHOOK_URL", "not-a-valid-url");

        let result = ServeConfig::from_env();

        assert!(
            result.is_err(),
            "expected error for invalid TWOFOLD_WEBHOOK_URL"
        );
        let msg = result.unwrap_err();
        assert!(
            msg.contains("TWOFOLD_WEBHOOK_URL"),
            "error message should mention TWOFOLD_WEBHOOK_URL, got: {msg}"
        );
    }
}
