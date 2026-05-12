//! SQLite persistence layer. Document, token, OAuth, and audit log tables. Schema migration via PRAGMA introspection.

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Result};

/// A stored document record (maps 1:1 to the `documents` table row).
#[derive(Debug, Clone)]
pub struct DocumentRecord {
    pub id: String,
    pub slug: String,
    pub title: String,
    pub raw_content: String,
    pub theme: String,
    pub password: Option<String>, // argon2 hash, None = public
    pub description: Option<String>,
    pub created_at: String,         // ISO 8601 UTC
    pub expires_at: Option<String>, // ISO 8601 UTC, None = no expiry
    pub updated_at: String,
}

/// A stored token record.
#[derive(Debug, Clone)]
pub struct TokenRecord {
    pub id: String,
    pub name: String,
    pub hash: String, // argon2 hash of the token
    pub created_at: String,
    pub last_used: Option<String>,
    pub revoked: bool,
    /// First 8 characters of the plaintext token — stored for O(1) lookup.
    /// NULL for tokens created before v0.4 (legacy tokens).
    pub prefix: Option<String>,
}

/// An audit log entry recording a mutation event.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditEntry {
    pub id: String,
    pub timestamp: String,
    pub action: String,
    pub slug: String,
    pub token_name: String,
    pub ip_address: String,
}

/// Thread-safe database handle backed by an r2d2 connection pool.
///
/// Contract: all methods take `&self`. Pool provides thread-safe concurrent
/// access — multiple readers can run in parallel under WAL mode.
/// Errors are rusqlite::Error — callers map to HTTP status codes.
#[derive(Clone)]
pub struct Db {
    pool: Pool<SqliteConnectionManager>,
}

/// Convert an r2d2 pool error into a rusqlite error so callers keep the same
/// `rusqlite::Result<T>` return type without an API surface change.
fn pool_err(e: r2d2::Error) -> rusqlite::Error {
    rusqlite::Error::InvalidPath(std::path::PathBuf::from(format!(
        "connection pool error: {e}"
    )))
}

impl Db {
    /// Open or create the SQLite database at `path`, running schema initialization.
    ///
    /// Builds an r2d2 pool (max 8 connections) so concurrent reads can run in
    /// parallel under WAL mode instead of serializing through a single Mutex.
    /// WAL mode and busy_timeout are applied to each connection at open time.
    pub fn open(path: &str) -> Result<Self> {
        let manager = SqliteConnectionManager::file(path).with_init(|conn| {
            conn.execute_batch("PRAGMA journal_mode=WAL;")?;
            conn.busy_timeout(std::time::Duration::from_secs(5))?;
            Ok(())
        });

        let pool = Pool::builder()
            .max_size(8)
            .build(manager)
            .map_err(pool_err)?;

        let db = Db { pool };
        db.initialize_schema()?;
        db.migrate()?;
        Ok(db)
    }

    /// Create the base schema if it does not exist.
    ///
    /// For fresh databases: creates full v0.2 schema.
    /// For existing databases: creates only missing tables (documents table
    /// already exists from v0.1 — migration handles adding columns).
    fn initialize_schema(&self) -> Result<()> {
        let conn = self.pool.get().map_err(pool_err)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS documents (
                id          TEXT PRIMARY KEY,
                slug        TEXT UNIQUE NOT NULL,
                title       TEXT NOT NULL,
                raw_content TEXT NOT NULL,
                theme       TEXT NOT NULL DEFAULT 'clean',
                password    TEXT,
                description TEXT,
                created_at  TEXT NOT NULL,
                expires_at  TEXT,
                updated_at  TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_documents_slug ON documents(slug);

            CREATE TABLE IF NOT EXISTS tokens (
                id         TEXT PRIMARY KEY,
                name       TEXT UNIQUE NOT NULL,
                hash       TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_used  TEXT,
                revoked    INTEGER NOT NULL DEFAULT 0,
                prefix     TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_tokens_prefix ON tokens(prefix);

            CREATE TABLE IF NOT EXISTS audit_log (
                id          TEXT PRIMARY KEY,
                timestamp   TEXT NOT NULL,
                action      TEXT NOT NULL,
                slug        TEXT NOT NULL,
                token_name  TEXT NOT NULL,
                ip_address  TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_log_slug ON audit_log(slug);

            CREATE TABLE IF NOT EXISTS oauth_clients (
                client_id                   TEXT PRIMARY KEY,
                client_name                 TEXT NOT NULL,
                redirect_uris               TEXT NOT NULL,
                grant_types                 TEXT NOT NULL,
                response_types              TEXT NOT NULL,
                token_endpoint_auth_method  TEXT NOT NULL,
                created_at                  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS oauth_auth_codes (
                code            TEXT PRIMARY KEY,
                client_id       TEXT NOT NULL,
                redirect_uri    TEXT NOT NULL,
                expires_at      TEXT NOT NULL,
                code_challenge  TEXT NOT NULL,
                resource        TEXT,
                scope           TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_oauth_auth_codes_expires_at ON oauth_auth_codes(expires_at);

            CREATE TABLE IF NOT EXISTS oauth_access_tokens (
                token       TEXT PRIMARY KEY,
                client_id   TEXT NOT NULL,
                scope       TEXT,
                expires_at  TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_expires_at ON oauth_access_tokens(expires_at);

            CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
                token        TEXT PRIMARY KEY,
                client_id    TEXT NOT NULL,
                access_token TEXT NOT NULL,
                scope        TEXT,
                expires_at   TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_expires_at ON oauth_refresh_tokens(expires_at);",
        )?;
        Ok(())
    }

    /// Migrate v0.1 databases to v0.2 schema.
    ///
    /// Uses PRAGMA table_info to check if columns exist before altering.
    /// Safe to run on fresh databases (no-ops if columns already exist).
    fn migrate(&self) -> Result<()> {
        let conn = self.pool.get().map_err(pool_err)?;

        // Check which columns exist on documents table
        let mut stmt = conn.prepare("PRAGMA table_info(documents)")?;
        let columns: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))?
            .filter_map(|r| r.ok())
            .collect();
        drop(stmt); // Release the statement before executing DDL

        if !columns.contains(&"theme".to_string()) {
            conn.execute_batch(
                "ALTER TABLE documents ADD COLUMN theme TEXT NOT NULL DEFAULT 'clean';",
            )?;
        }
        if !columns.contains(&"password".to_string()) {
            conn.execute_batch("ALTER TABLE documents ADD COLUMN password TEXT;")?;
        }
        if !columns.contains(&"description".to_string()) {
            conn.execute_batch("ALTER TABLE documents ADD COLUMN description TEXT;")?;
        }
        if !columns.contains(&"expires_at".to_string()) {
            conn.execute_batch("ALTER TABLE documents ADD COLUMN expires_at TEXT;")?;
        }

        // Create expires_at index (safe now that column is guaranteed to exist)
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_documents_expires_at ON documents(expires_at);",
        )?;

        // v0.4: add prefix column to tokens for O(1) auth lookup.
        // Check tokens table columns separately.
        let mut token_stmt = conn.prepare("PRAGMA table_info(tokens)")?;
        let token_columns: Vec<String> = token_stmt
            .query_map([], |row| row.get::<_, String>(1))?
            .filter_map(|r| r.ok())
            .collect();
        drop(token_stmt);

        if !token_columns.contains(&"prefix".to_string()) {
            conn.execute_batch("ALTER TABLE tokens ADD COLUMN prefix TEXT;")?;
        }
        conn.execute_batch(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_tokens_prefix ON tokens(prefix);",
        )?;

        // v0.5: add audit_log table for mutation tracking.
        // IF NOT EXISTS makes this safe to run on databases that already have the table.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_log (
                id          TEXT PRIMARY KEY,
                timestamp   TEXT NOT NULL,
                action      TEXT NOT NULL,
                slug        TEXT NOT NULL,
                token_name  TEXT NOT NULL,
                ip_address  TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_log_slug ON audit_log(slug);",
        )?;

        // v0.6: OAuth tables (migrated from in-memory state to SQLite).
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS oauth_clients (
                client_id                   TEXT PRIMARY KEY,
                client_name                 TEXT NOT NULL,
                redirect_uris               TEXT NOT NULL,
                grant_types                 TEXT NOT NULL,
                response_types              TEXT NOT NULL,
                token_endpoint_auth_method  TEXT NOT NULL,
                created_at                  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS oauth_auth_codes (
                code            TEXT PRIMARY KEY,
                client_id       TEXT NOT NULL,
                redirect_uri    TEXT NOT NULL,
                expires_at      TEXT NOT NULL,
                code_challenge  TEXT NOT NULL,
                resource        TEXT,
                scope           TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_oauth_auth_codes_expires_at ON oauth_auth_codes(expires_at);

            CREATE TABLE IF NOT EXISTS oauth_access_tokens (
                token       TEXT PRIMARY KEY,
                client_id   TEXT NOT NULL,
                scope       TEXT,
                expires_at  TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_expires_at ON oauth_access_tokens(expires_at);

            CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
                token        TEXT PRIMARY KEY,
                client_id    TEXT NOT NULL,
                access_token TEXT NOT NULL,
                scope        TEXT,
                expires_at   TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_expires_at ON oauth_refresh_tokens(expires_at);",
        )?;

        Ok(())
    }

    /// Verify the database connection pool is alive with a trivial query.
    ///
    /// Used by the health endpoint. Returns Ok(()) if the pool responds,
    /// Err if pool acquisition or query fails.
    pub fn ping(&self) -> Result<()> {
        let conn = self.pool.get().map_err(pool_err)?;
        conn.execute_batch("SELECT 1;")?;
        Ok(())
    }

    /// Insert a new document into the database.
    ///
    /// Returns Err if slug already exists (UNIQUE constraint violation).
    pub fn insert_document(&self, doc: &DocumentRecord) -> Result<()> {
        let conn = self.pool.get().map_err(pool_err)?;
        conn.execute(
            "INSERT INTO documents (id, slug, title, raw_content, theme, password, description, created_at, expires_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                doc.id,
                doc.slug,
                doc.title,
                doc.raw_content,
                doc.theme,
                doc.password,
                doc.description,
                doc.created_at,
                doc.expires_at,
                doc.updated_at,
            ],
        )?;
        Ok(())
    }

    /// Update an existing document by slug.
    pub fn update_document(&self, slug: &str, doc: &DocumentRecord) -> Result<bool> {
        let conn = self.pool.get().map_err(pool_err)?;
        let rows = conn.execute(
            "UPDATE documents SET title = ?1, raw_content = ?2, theme = ?3, password = ?4,
             description = ?5, expires_at = ?6, updated_at = ?7
             WHERE slug = ?8",
            params![
                doc.title,
                doc.raw_content,
                doc.theme,
                doc.password,
                doc.description,
                doc.expires_at,
                doc.updated_at,
                slug,
            ],
        )?;
        Ok(rows > 0)
    }

    /// Delete a document by slug. Returns true if a row was deleted.
    pub fn delete_by_slug(&self, slug: &str) -> Result<bool> {
        let conn = self.pool.get().map_err(pool_err)?;
        let rows = conn.execute("DELETE FROM documents WHERE slug = ?1", params![slug])?;
        Ok(rows > 0)
    }

    /// Fetch a document by slug.
    ///
    /// Returns Ok(None) if no row matches the slug (caller maps to 404).
    pub fn get_by_slug(&self, slug: &str) -> Result<Option<DocumentRecord>> {
        let conn = self.pool.get().map_err(pool_err)?;
        let mut stmt = conn.prepare(
            "SELECT id, slug, title, raw_content, theme, password, description, created_at, expires_at, updated_at
             FROM documents WHERE slug = ?1",
        )?;

        let mut rows = stmt.query(params![slug])?;
        match rows.next()? {
            None => Ok(None),
            Some(row) => Ok(Some(DocumentRecord {
                id: row.get(0)?,
                slug: row.get(1)?,
                title: row.get(2)?,
                raw_content: row.get(3)?,
                theme: row.get(4)?,
                password: row.get(5)?,
                description: row.get(6)?,
                created_at: row.get(7)?,
                expires_at: row.get(8)?,
                updated_at: row.get(9)?,
            })),
        }
    }

    /// Delete documents that expired more than `days` days ago.
    ///
    /// Used by the reaper for tombstone garbage collection: expired docs stay
    /// in the database (returning 410) until they're old enough to discard.
    /// The cutoff is computed from `now` using SQLite's datetime arithmetic.
    pub fn delete_expired_older_than(&self, now: &str, days: u32) -> Result<usize> {
        let conn = self.pool.get().map_err(pool_err)?;
        let rows = conn.execute(
            "DELETE FROM documents \
             WHERE expires_at IS NOT NULL \
               AND expires_at < datetime(?1, printf('-%d days', ?2))",
            params![now, days],
        )?;
        Ok(rows)
    }

    // ── Token operations ─────────────────────────────────────────────────────

    /// Insert a new token record.
    pub fn insert_token(&self, token: &TokenRecord) -> Result<()> {
        let conn = self.pool.get().map_err(pool_err)?;
        conn.execute(
            "INSERT INTO tokens (id, name, hash, created_at, last_used, revoked, prefix)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                token.id,
                token.name,
                token.hash,
                token.created_at,
                token.last_used,
                token.revoked as i32,
                token.prefix,
            ],
        )?;
        Ok(())
    }

    /// Look up a single active token by its 8-character prefix for O(1) auth.
    ///
    /// Returns None if no active token has that prefix, or if the prefix is
    /// not stored (legacy token path). Callers must still verify the argon2
    /// hash of the returned record — prefix is a lookup key, not a secret.
    pub fn get_token_by_prefix(&self, prefix: &str) -> Result<Option<TokenRecord>> {
        let conn = self.pool.get().map_err(pool_err)?;
        let mut stmt = conn.prepare(
            "SELECT id, name, hash, created_at, last_used, revoked, prefix
             FROM tokens WHERE prefix = ?1 AND revoked = 0
             LIMIT 1",
        )?;
        let mut rows = stmt.query(params![prefix])?;
        match rows.next()? {
            None => Ok(None),
            Some(row) => Ok(Some(TokenRecord {
                id: row.get(0)?,
                name: row.get(1)?,
                hash: row.get(2)?,
                created_at: row.get(3)?,
                last_used: row.get(4)?,
                revoked: row.get::<_, i32>(5)? != 0,
                prefix: row.get(6)?,
            })),
        }
    }

    /// Get legacy active tokens — those without a prefix stored.
    ///
    /// Used as a fallback in `check_auth` for tokens created before v0.4.
    /// Returns empty vec on a fresh database (no legacy tokens exist).
    pub fn get_legacy_active_tokens(&self) -> Result<Vec<TokenRecord>> {
        let conn = self.pool.get().map_err(pool_err)?;
        let mut stmt = conn.prepare(
            "SELECT id, name, hash, created_at, last_used, revoked, prefix
             FROM tokens WHERE revoked = 0 AND prefix IS NULL",
        )?;
        let tokens = stmt
            .query_map([], |row| {
                Ok(TokenRecord {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    hash: row.get(2)?,
                    created_at: row.get(3)?,
                    last_used: row.get(4)?,
                    revoked: row.get::<_, i32>(5)? != 0,
                    prefix: row.get(6)?,
                })
            })?
            .filter_map(|r| {
                r.map_err(|e| tracing::warn!("Failed to deserialize token row: {}", e))
                    .ok()
            })
            .collect();
        Ok(tokens)
    }

    /// List all tokens (for CLI display).
    pub fn list_tokens(&self) -> Result<Vec<TokenRecord>> {
        let conn = self.pool.get().map_err(pool_err)?;
        let mut stmt = conn.prepare(
            "SELECT id, name, hash, created_at, last_used, revoked, prefix
             FROM tokens ORDER BY created_at DESC",
        )?;
        let tokens = stmt
            .query_map([], |row| {
                Ok(TokenRecord {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    hash: row.get(2)?,
                    created_at: row.get(3)?,
                    last_used: row.get(4)?,
                    revoked: row.get::<_, i32>(5)? != 0,
                    prefix: row.get(6)?,
                })
            })?
            .filter_map(|r| {
                r.map_err(|e| tracing::warn!("Failed to deserialize token row: {}", e))
                    .ok()
            })
            .collect();
        Ok(tokens)
    }

    /// Revoke a token by name. Returns true if a row was updated.
    pub fn revoke_token(&self, name: &str) -> Result<bool> {
        let conn = self.pool.get().map_err(pool_err)?;
        let rows = conn.execute(
            "UPDATE tokens SET revoked = 1 WHERE name = ?1 AND revoked = 0",
            params![name],
        )?;
        Ok(rows > 0)
    }

    /// Update last_used timestamp for a token.
    pub fn touch_token(&self, id: &str, now: &str) -> Result<()> {
        let conn = self.pool.get().map_err(pool_err)?;
        conn.execute(
            "UPDATE tokens SET last_used = ?1 WHERE id = ?2",
            params![now, id],
        )?;
        Ok(())
    }

    /// Check if a token name already exists.
    pub fn token_name_exists(&self, name: &str) -> Result<bool> {
        let conn = self.pool.get().map_err(pool_err)?;
        let mut stmt = conn.prepare("SELECT COUNT(*) FROM tokens WHERE name = ?1")?;
        let count: i64 = stmt.query_row(params![name], |row| row.get(0))?;
        Ok(count > 0)
    }

    /// List non-expired documents with pagination.
    ///
    /// Returns (documents, total_count).
    ///
    /// SQL-level expired filter: `expires_at IS NULL OR expires_at > now`.
    /// Using the same ISO 8601 format as the rest of the codebase.
    ///
    /// Limit is enforced server-side: callers requesting limit > 100 are silently
    /// capped at 100. Offset is u32 (cannot be negative by type).
    ///
    /// Two queries: count first, then paginated data. Each acquires its own pool
    /// connection — in theory the count could race with concurrent writes. At v0.3
    /// usage patterns this is acceptable; a window-function approach would eliminate it.
    pub fn list_documents(&self, limit: u32, offset: u32) -> Result<(Vec<DocumentSummary>, u64)> {
        // Server-side cap: callers asking for >100 get 100, no error.
        let capped_limit = limit.min(100);

        let conn = self.pool.get().map_err(pool_err)?;

        // Count all non-expired documents (for pagination total).
        // Filter: expires_at IS NULL (no expiry) OR expires_at > now (not yet expired).
        let total: u64 = {
            let mut stmt = conn.prepare(
                "SELECT COUNT(*) FROM documents \
                 WHERE expires_at IS NULL OR expires_at > strftime('%Y-%m-%dT%H:%M:%SZ', 'now')",
            )?;
            stmt.query_row([], |row| row.get::<_, i64>(0))
                .map(|n| n as u64)?
        };

        // Paginated document summaries, newest first.
        // ?1 = capped_limit, ?2 = offset — named by position, no string interpolation.
        let mut stmt = conn.prepare(
            "SELECT slug, title, description, created_at, expires_at \
             FROM documents \
             WHERE expires_at IS NULL OR expires_at > strftime('%Y-%m-%dT%H:%M:%SZ', 'now') \
             ORDER BY created_at DESC \
             LIMIT ?1 OFFSET ?2",
        )?;

        let docs = stmt
            .query_map(params![capped_limit, offset], |row| {
                Ok(DocumentSummary {
                    slug: row.get(0)?,
                    title: row.get(1)?,
                    description: row.get(2)?,
                    created_at: row.get(3)?,
                    expires_at: row.get(4)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok((docs, total))
    }

    // ── Audit log operations ──────────────────────────────────────────────────

    /// Insert an audit log entry.
    ///
    /// Fire-and-forget contract: callers log errors but do not fail the request.
    /// Audit entries are never deleted — they outlive the documents they reference.
    pub fn insert_audit_entry(&self, entry: &AuditEntry) -> Result<()> {
        let conn = self.pool.get().map_err(pool_err)?;
        conn.execute(
            "INSERT INTO audit_log (id, timestamp, action, slug, token_name, ip_address)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                entry.id,
                entry.timestamp,
                entry.action,
                entry.slug,
                entry.token_name,
                entry.ip_address,
            ],
        )?;
        Ok(())
    }

    /// List audit entries with pagination, newest first.
    ///
    /// Returns (entries, total_count).
    /// limit is capped at 100 server-side (same pattern as list_documents).
    pub fn list_audit_entries(&self, limit: u32, offset: u32) -> Result<(Vec<AuditEntry>, u64)> {
        let capped_limit = limit.min(100);
        let conn = self.pool.get().map_err(pool_err)?;

        let total: u64 = {
            let mut stmt = conn.prepare("SELECT COUNT(*) FROM audit_log")?;
            stmt.query_row([], |row| row.get::<_, i64>(0))
                .map(|n| n as u64)?
        };

        let mut stmt = conn.prepare(
            "SELECT id, timestamp, action, slug, token_name, ip_address \
             FROM audit_log \
             ORDER BY timestamp DESC \
             LIMIT ?1 OFFSET ?2",
        )?;

        let entries = stmt
            .query_map(params![capped_limit, offset], |row| {
                Ok(AuditEntry {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    action: row.get(2)?,
                    slug: row.get(3)?,
                    token_name: row.get(4)?,
                    ip_address: row.get(5)?,
                })
            })?
            .filter_map(|r| match r {
                Ok(e) => Some(e),
                Err(e) => {
                    tracing::warn!("Audit row deserialization failed: {e}");
                    None
                }
            })
            .collect();

        Ok((entries, total))
    }
}

// ── OAuth row types ───────────────────────────────────────────────────────────

/// Registered OAuth client (oauth_clients table).
#[derive(Debug, Clone)]
pub struct OAuthClientRow {
    pub client_id: String,
    pub client_name: String,
    /// JSON-encoded Vec<String>
    pub redirect_uris: String,
    /// JSON-encoded Vec<String>
    pub grant_types: String,
    /// JSON-encoded Vec<String>
    pub response_types: String,
    pub token_endpoint_auth_method: String,
    pub created_at: String,
}

/// Authorization code (oauth_auth_codes table).
#[derive(Debug, Clone)]
pub struct AuthCodeRow {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub expires_at: String,
    pub code_challenge: String,
    pub resource: Option<String>,
    pub scope: Option<String>,
}

/// Access token (oauth_access_tokens table).
#[derive(Debug, Clone)]
pub struct AccessTokenRow {
    pub token: String,
    pub client_id: String,
    pub scope: Option<String>,
    pub expires_at: String,
}

/// Refresh token (oauth_refresh_tokens table).
#[derive(Debug, Clone)]
pub struct RefreshTokenRow {
    pub token: String,
    pub client_id: String,
    pub access_token: String,
    pub scope: Option<String>,
    pub expires_at: String,
}

// ── OAuth client operations ───────────────────────────────────────────────────

impl Db {
    /// Insert a dynamically-registered OAuth client.
    pub fn insert_oauth_client(&self, row: &OAuthClientRow) -> Result<()> {
        let conn = self.pool.get().map_err(pool_err)?;
        conn.execute(
            "INSERT INTO oauth_clients
             (client_id, client_name, redirect_uris, grant_types, response_types,
              token_endpoint_auth_method, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                row.client_id,
                row.client_name,
                row.redirect_uris,
                row.grant_types,
                row.response_types,
                row.token_endpoint_auth_method,
                row.created_at,
            ],
        )?;
        Ok(())
    }

    /// Look up an OAuth client by client_id.
    pub fn get_oauth_client(&self, client_id: &str) -> Result<Option<OAuthClientRow>> {
        let conn = self.pool.get().map_err(pool_err)?;
        let mut stmt = conn.prepare(
            "SELECT client_id, client_name, redirect_uris, grant_types, response_types,
                    token_endpoint_auth_method, created_at
             FROM oauth_clients WHERE client_id = ?1",
        )?;
        let mut rows = stmt.query(params![client_id])?;
        match rows.next()? {
            None => Ok(None),
            Some(row) => Ok(Some(OAuthClientRow {
                client_id: row.get(0)?,
                client_name: row.get(1)?,
                redirect_uris: row.get(2)?,
                grant_types: row.get(3)?,
                response_types: row.get(4)?,
                token_endpoint_auth_method: row.get(5)?,
                created_at: row.get(6)?,
            })),
        }
    }

    /// Count active (non-expired) registered clients.
    ///
    /// Used to enforce the 1,000-client hard cap before inserting.
    pub fn count_active_oauth_clients(&self, cutoff: &str) -> Result<i64> {
        let conn = self.pool.get().map_err(pool_err)?;
        let mut stmt = conn.prepare("SELECT COUNT(*) FROM oauth_clients WHERE created_at >= ?1")?;
        let count: i64 = stmt.query_row(params![cutoff], |row| row.get(0))?;
        Ok(count)
    }

    /// Delete OAuth clients registered before `cutoff` (ISO 8601 string).
    pub fn delete_expired_oauth_clients(&self, cutoff: &str) -> Result<usize> {
        let conn = self.pool.get().map_err(pool_err)?;
        let rows = conn.execute(
            "DELETE FROM oauth_clients WHERE created_at < ?1",
            params![cutoff],
        )?;
        Ok(rows)
    }

    // ── Auth code operations ──────────────────────────────────────────────────

    /// Insert an authorization code.
    pub fn insert_auth_code(&self, row: &AuthCodeRow) -> Result<()> {
        let conn = self.pool.get().map_err(pool_err)?;
        conn.execute(
            "INSERT INTO oauth_auth_codes
             (code, client_id, redirect_uri, expires_at, code_challenge, resource, scope)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                row.code,
                row.client_id,
                row.redirect_uri,
                row.expires_at,
                row.code_challenge,
                row.resource,
                row.scope,
            ],
        )?;
        Ok(())
    }

    /// Atomically SELECT + DELETE an authorization code (single-use guarantee).
    ///
    /// Returns Ok(None) if the code doesn't exist (already used or never issued).
    pub fn take_auth_code(&self, code: &str) -> Result<Option<AuthCodeRow>> {
        let conn = self.pool.get().map_err(pool_err)?;
        // Use a transaction so concurrent requests can't both succeed on the same code.
        let tx = conn.unchecked_transaction()?;
        let row = {
            let mut stmt = tx.prepare(
                "SELECT code, client_id, redirect_uri, expires_at, code_challenge, resource, scope
                 FROM oauth_auth_codes WHERE code = ?1",
            )?;
            let mut rows = stmt.query(params![code])?;
            match rows.next()? {
                None => None,
                Some(r) => Some(AuthCodeRow {
                    code: r.get(0)?,
                    client_id: r.get(1)?,
                    redirect_uri: r.get(2)?,
                    expires_at: r.get(3)?,
                    code_challenge: r.get(4)?,
                    resource: r.get(5)?,
                    scope: r.get(6)?,
                }),
            }
        };
        if row.is_some() {
            tx.execute(
                "DELETE FROM oauth_auth_codes WHERE code = ?1",
                params![code],
            )?;
        }
        tx.commit()?;
        Ok(row)
    }

    /// Delete authorization codes that expired before `now`.
    pub fn delete_expired_auth_codes(&self, now: &str) -> Result<usize> {
        let conn = self.pool.get().map_err(pool_err)?;
        let rows = conn.execute(
            "DELETE FROM oauth_auth_codes WHERE expires_at < ?1",
            params![now],
        )?;
        Ok(rows)
    }

    // ── Access token operations ───────────────────────────────────────────────

    /// Insert an OAuth access token.
    pub fn insert_access_token(&self, row: &AccessTokenRow) -> Result<()> {
        let conn = self.pool.get().map_err(pool_err)?;
        conn.execute(
            "INSERT INTO oauth_access_tokens (token, client_id, scope, expires_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![row.token, row.client_id, row.scope, row.expires_at],
        )?;
        Ok(())
    }

    /// Look up an OAuth access token. Returns None if not found or expired.
    pub fn get_access_token(&self, token: &str) -> Result<Option<AccessTokenRow>> {
        let conn = self.pool.get().map_err(pool_err)?;
        let mut stmt = conn.prepare(
            "SELECT token, client_id, scope, expires_at
             FROM oauth_access_tokens WHERE token = ?1",
        )?;
        let mut rows = stmt.query(params![token])?;
        match rows.next()? {
            None => Ok(None),
            Some(row) => Ok(Some(AccessTokenRow {
                token: row.get(0)?,
                client_id: row.get(1)?,
                scope: row.get(2)?,
                expires_at: row.get(3)?,
            })),
        }
    }

    /// Delete OAuth access tokens that expired before `now`.
    pub fn delete_expired_access_tokens(&self, now: &str) -> Result<usize> {
        let conn = self.pool.get().map_err(pool_err)?;
        let rows = conn.execute(
            "DELETE FROM oauth_access_tokens WHERE expires_at < ?1",
            params![now],
        )?;
        Ok(rows)
    }

    // ── Refresh token operations ──────────────────────────────────────────────

    /// Insert an OAuth refresh token.
    pub fn insert_refresh_token(&self, row: &RefreshTokenRow) -> Result<()> {
        let conn = self.pool.get().map_err(pool_err)?;
        conn.execute(
            "INSERT INTO oauth_refresh_tokens (token, client_id, access_token, scope, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                row.token,
                row.client_id,
                row.access_token,
                row.scope,
                row.expires_at,
            ],
        )?;
        Ok(())
    }

    /// Atomically SELECT + DELETE a refresh token (rotation: single-use).
    pub fn take_refresh_token(&self, token: &str) -> Result<Option<RefreshTokenRow>> {
        let conn = self.pool.get().map_err(pool_err)?;
        let tx = conn.unchecked_transaction()?;
        let row = {
            let mut stmt = tx.prepare(
                "SELECT token, client_id, access_token, scope, expires_at
                 FROM oauth_refresh_tokens WHERE token = ?1",
            )?;
            let mut rows = stmt.query(params![token])?;
            match rows.next()? {
                None => None,
                Some(r) => Some(RefreshTokenRow {
                    token: r.get(0)?,
                    client_id: r.get(1)?,
                    access_token: r.get(2)?,
                    scope: r.get(3)?,
                    expires_at: r.get(4)?,
                }),
            }
        };
        if row.is_some() {
            tx.execute(
                "DELETE FROM oauth_refresh_tokens WHERE token = ?1",
                params![token],
            )?;
        }
        tx.commit()?;
        Ok(row)
    }

    /// Delete OAuth refresh tokens that expired before `now`.
    pub fn delete_expired_refresh_tokens(&self, now: &str) -> Result<usize> {
        let conn = self.pool.get().map_err(pool_err)?;
        let rows = conn.execute(
            "DELETE FROM oauth_refresh_tokens WHERE expires_at < ?1",
            params![now],
        )?;
        Ok(rows)
    }
}

/// Document summary for the list endpoint (no raw_content — metadata only).
#[derive(Debug, Clone, serde::Serialize)]
pub struct DocumentSummary {
    pub slug: String,
    pub title: String,
    pub description: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build an in-memory Db with schema initialized.
    fn open_test_db() -> Db {
        Db::open(":memory:").expect("in-memory db should open")
    }

    /// Helper: a minimal DocumentRecord with no expiry or password.
    fn make_doc(slug: &str, created_at: &str) -> DocumentRecord {
        DocumentRecord {
            id: slug.to_string(),
            slug: slug.to_string(),
            title: format!("Title for {slug}"),
            raw_content: format!("# {slug}\n\nContent."),
            theme: "clean".to_string(),
            password: None,
            description: Some(format!("Desc for {slug}")),
            created_at: created_at.to_string(),
            expires_at: None,
            updated_at: created_at.to_string(),
        }
    }

    /// Insert a document then fetch it back — all fields round-trip correctly.
    #[test]
    fn insert_and_get_document() {
        let db = open_test_db();
        let doc = make_doc("test-slug", "2024-01-01T00:00:00Z");

        db.insert_document(&doc).expect("insert should succeed");

        let fetched = db
            .get_by_slug("test-slug")
            .expect("query should succeed")
            .expect("document should exist");

        assert_eq!(fetched.id, doc.id);
        assert_eq!(fetched.slug, doc.slug);
        assert_eq!(fetched.title, doc.title);
        assert_eq!(fetched.raw_content, doc.raw_content);
        assert_eq!(fetched.theme, doc.theme);
        assert_eq!(fetched.password, doc.password);
        assert_eq!(fetched.description, doc.description);
        assert_eq!(fetched.created_at, doc.created_at);
        assert_eq!(fetched.expires_at, doc.expires_at);
        assert_eq!(fetched.updated_at, doc.updated_at);
    }

    /// list_documents respects limit and offset.
    #[test]
    fn list_documents_pagination() {
        let db = open_test_db();

        // Insert 5 documents with staggered created_at so ordering is stable.
        for i in 1..=5u32 {
            let slug = format!("slug-{:02}", i);
            let ts = format!("2024-01-{:02}T00:00:00Z", i);
            let doc = make_doc(&slug, &ts);
            db.insert_document(&doc).expect("insert");
        }

        // Fetch first 2 — should get the 2 newest (slug-05, slug-04).
        let (page1, total) = db.list_documents(2, 0).expect("list page 1");
        assert_eq!(total, 5, "total count should be 5");
        assert_eq!(page1.len(), 2, "page 1 should have 2 docs");
        assert_eq!(page1[0].slug, "slug-05", "newest first");
        assert_eq!(page1[1].slug, "slug-04");

        // Fetch next 2 with offset=2 — should get slug-03, slug-02.
        let (page2, _) = db.list_documents(2, 2).expect("list page 2");
        assert_eq!(page2.len(), 2);
        assert_eq!(page2[0].slug, "slug-03");
        assert_eq!(page2[1].slug, "slug-02");

        // Fetch last page (offset=4) — should get only slug-01.
        let (page3, _) = db.list_documents(2, 4).expect("list page 3");
        assert_eq!(page3.len(), 1);
        assert_eq!(page3[0].slug, "slug-01");
    }

    /// Token create → list → revoke cycle works end-to-end.
    #[test]
    fn token_crud() {
        let db = open_test_db();

        // Insert a token. Use a recognizable fake hash — we're testing CRUD,
        // not argon2 verification.
        let token = TokenRecord {
            id: "tok-id-1".to_string(),
            name: "my-token".to_string(),
            hash: "fakehash".to_string(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
            last_used: None,
            revoked: false,
            prefix: Some("tok12345".to_string()),
        };
        db.insert_token(&token).expect("insert token");

        // List — should contain exactly the one token, not revoked.
        let tokens = db.list_tokens().expect("list tokens");
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].name, "my-token");
        assert!(!tokens[0].revoked, "should not be revoked yet");

        // Revoke — should return true (row updated).
        let revoked = db.revoke_token("my-token").expect("revoke");
        assert!(revoked, "revoke should return true on first call");

        // Revoking again returns false (already revoked, no rows updated).
        let revoked_again = db.revoke_token("my-token").expect("revoke again");
        assert!(
            !revoked_again,
            "revoking an already-revoked token returns false"
        );

        // List — token is still present but marked revoked.
        let tokens_after = db.list_tokens().expect("list after revoke");
        assert_eq!(tokens_after.len(), 1);
        assert!(tokens_after[0].revoked, "should be revoked now");

        // get_token_by_prefix should not return a revoked token.
        let found = db
            .get_token_by_prefix("tok12345")
            .expect("prefix lookup should not error");
        assert!(
            found.is_none(),
            "revoked token should not be returned by prefix lookup"
        );
    }
}
