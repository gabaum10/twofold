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
///
/// Uses `SqliteFailure` with `SQLITE_CANTOPEN` (error code 14) — the most
/// accurate SQLite error class for "could not acquire a connection".
/// Previously used `InvalidPath`, which misled debuggers into thinking a file
/// path was wrong rather than the pool being exhausted or timed out.
fn pool_err(e: r2d2::Error) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CANTOPEN),
        Some(format!("connection pool error: {e}")),
    )
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
                created_at                  TEXT NOT NULL,
                provisioned                 INTEGER NOT NULL DEFAULT 0,
                client_secret               TEXT
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

        // v0.5-closed-reg: add provisioned and client_secret columns to oauth_clients.
        // provisioned=1 marks clients created via `twofold client create` — they survive
        // the reaper and require client_secret validation.
        // client_secret stores the plaintext secret for confidential clients (nullable).
        let mut client_stmt = conn.prepare("PRAGMA table_info(oauth_clients)")?;
        let client_columns: Vec<String> = client_stmt
            .query_map([], |row| row.get::<_, String>(1))?
            .filter_map(|r| r.ok())
            .collect();
        drop(client_stmt);

        if !client_columns.contains(&"provisioned".to_string()) {
            conn.execute_batch(
                "ALTER TABLE oauth_clients ADD COLUMN provisioned INTEGER NOT NULL DEFAULT 0;",
            )?;
        }
        if !client_columns.contains(&"client_secret".to_string()) {
            conn.execute_batch("ALTER TABLE oauth_clients ADD COLUMN client_secret TEXT;")?;
        }

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
    /// True if this client was pre-provisioned via `twofold client create`.
    /// Provisioned clients are exempt from the reaper and require client_secret auth.
    pub provisioned: bool,
    /// Plaintext client_secret for confidential (provisioned) clients. None for public clients.
    pub client_secret: Option<String>,
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
    /// Insert a dynamically-registered or provisioned OAuth client.
    pub fn insert_oauth_client(&self, row: &OAuthClientRow) -> Result<()> {
        let conn = self.pool.get().map_err(pool_err)?;
        conn.execute(
            "INSERT INTO oauth_clients
             (client_id, client_name, redirect_uris, grant_types, response_types,
              token_endpoint_auth_method, created_at, provisioned, client_secret)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                row.client_id,
                row.client_name,
                row.redirect_uris,
                row.grant_types,
                row.response_types,
                row.token_endpoint_auth_method,
                row.created_at,
                row.provisioned as i32,
                row.client_secret,
            ],
        )?;
        Ok(())
    }

    /// Look up an OAuth client by client_id.
    pub fn get_oauth_client(&self, client_id: &str) -> Result<Option<OAuthClientRow>> {
        let conn = self.pool.get().map_err(pool_err)?;
        let mut stmt = conn.prepare(
            "SELECT client_id, client_name, redirect_uris, grant_types, response_types,
                    token_endpoint_auth_method, created_at, provisioned, client_secret
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
                provisioned: row.get::<_, i32>(7)? != 0,
                client_secret: row.get(8)?,
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
    ///
    /// Provisioned clients (`provisioned = 1`) are always exempt — they survive indefinitely
    /// until explicitly revoked via `twofold client revoke`.
    pub fn delete_expired_oauth_clients(&self, cutoff: &str) -> Result<usize> {
        let conn = self.pool.get().map_err(pool_err)?;
        let rows = conn.execute(
            "DELETE FROM oauth_clients WHERE created_at < ?1 AND provisioned = 0",
            params![cutoff],
        )?;
        Ok(rows)
    }

    // ── Provisioned client management ─────────────────────────────────────────

    /// List all provisioned clients (created via `twofold client create`).
    pub fn list_provisioned_clients(&self) -> Result<Vec<OAuthClientRow>> {
        let conn = self.pool.get().map_err(pool_err)?;
        let mut stmt = conn.prepare(
            "SELECT client_id, client_name, redirect_uris, grant_types, response_types,
                    token_endpoint_auth_method, created_at, provisioned, client_secret
             FROM oauth_clients WHERE provisioned = 1
             ORDER BY created_at DESC",
        )?;
        let clients = stmt
            .query_map([], |row| {
                Ok(OAuthClientRow {
                    client_id: row.get(0)?,
                    client_name: row.get(1)?,
                    redirect_uris: row.get(2)?,
                    grant_types: row.get(3)?,
                    response_types: row.get(4)?,
                    token_endpoint_auth_method: row.get(5)?,
                    created_at: row.get(6)?,
                    provisioned: row.get::<_, i32>(7)? != 0,
                    client_secret: row.get(8)?,
                })
            })?
            .filter_map(|r| {
                r.map_err(|e| tracing::warn!("Failed to deserialize oauth_client row: {}", e))
                    .ok()
            })
            .collect();
        Ok(clients)
    }

    /// Delete a provisioned client and all its associated tokens by client_id.
    ///
    /// Returns true if the client existed and was deleted, false if not found.
    pub fn revoke_provisioned_client(&self, client_id: &str) -> Result<bool> {
        let conn = self.pool.get().map_err(pool_err)?;
        let tx = conn.unchecked_transaction()?;
        // Cascade: remove all tokens associated with this client.
        tx.execute(
            "DELETE FROM oauth_access_tokens WHERE client_id = ?1",
            params![client_id],
        )?;
        tx.execute(
            "DELETE FROM oauth_refresh_tokens WHERE client_id = ?1",
            params![client_id],
        )?;
        tx.execute(
            "DELETE FROM oauth_auth_codes WHERE client_id = ?1",
            params![client_id],
        )?;
        let rows = tx.execute(
            "DELETE FROM oauth_clients WHERE client_id = ?1 AND provisioned = 1",
            params![client_id],
        )?;
        tx.commit()?;
        Ok(rows > 0)
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

    // ── P3-20: reaper tests ───────────────────────────────────────────────────
    //
    // For each reaper: insert one expired row + one future row → call reaper
    // → assert expired row is gone, future row remains.

    /// delete_expired_auth_codes removes past rows and keeps future rows.
    #[test]
    fn reaper_auth_codes() {
        let db = open_test_db();
        let now = "2025-06-01T00:00:00Z";

        db.insert_auth_code(&AuthCodeRow {
            code: "expired-code".to_string(),
            client_id: "c1".to_string(),
            redirect_uri: "https://example.com/cb".to_string(),
            expires_at: "2020-01-01T00:00:00Z".to_string(), // past
            code_challenge: "challenge".to_string(),
            resource: None,
            scope: None,
        })
        .expect("insert expired auth code");
        db.insert_auth_code(&AuthCodeRow {
            code: "future-code".to_string(),
            client_id: "c1".to_string(),
            redirect_uri: "https://example.com/cb".to_string(),
            expires_at: "2099-01-01T00:00:00Z".to_string(), // future
            code_challenge: "challenge".to_string(),
            resource: None,
            scope: None,
        })
        .expect("insert future auth code");

        let deleted = db
            .delete_expired_auth_codes(now)
            .expect("reaper should succeed");
        assert_eq!(deleted, 1, "reaper should delete exactly 1 expired code");

        // Verify expired code is gone — take_auth_code returns None if absent.
        let taken_expired = db
            .take_auth_code("expired-code")
            .expect("take should not error");
        assert!(
            taken_expired.is_none(),
            "expired code must be gone after reaper"
        );

        // Verify future code is still present.
        let taken_future = db
            .take_auth_code("future-code")
            .expect("take should not error");
        assert!(taken_future.is_some(), "future code must survive reaper");
    }

    /// delete_expired_access_tokens removes past rows and keeps future rows.
    #[test]
    fn reaper_access_tokens() {
        let db = open_test_db();
        let now = "2025-06-01T00:00:00Z";

        db.insert_access_token(&AccessTokenRow {
            token: "expired-at".to_string(),
            client_id: "c1".to_string(),
            scope: None,
            expires_at: "2020-01-01T00:00:00Z".to_string(),
        })
        .expect("insert expired access token");
        db.insert_access_token(&AccessTokenRow {
            token: "future-at".to_string(),
            client_id: "c1".to_string(),
            scope: None,
            expires_at: "2099-01-01T00:00:00Z".to_string(),
        })
        .expect("insert future access token");

        let deleted = db
            .delete_expired_access_tokens(now)
            .expect("reaper should succeed");
        assert_eq!(
            deleted, 1,
            "reaper should delete exactly 1 expired access token"
        );

        let expired = db.get_access_token("expired-at").expect("lookup ok");
        assert!(
            expired.is_none(),
            "expired access token must be gone after reaper"
        );

        let future = db.get_access_token("future-at").expect("lookup ok");
        assert!(future.is_some(), "future access token must survive reaper");
    }

    /// delete_expired_refresh_tokens removes past rows and keeps future rows.
    #[test]
    fn reaper_refresh_tokens() {
        let db = open_test_db();
        let now = "2025-06-01T00:00:00Z";

        db.insert_refresh_token(&RefreshTokenRow {
            token: "expired-rt".to_string(),
            client_id: "c1".to_string(),
            access_token: "at1".to_string(),
            scope: None,
            expires_at: "2020-01-01T00:00:00Z".to_string(),
        })
        .expect("insert expired refresh token");
        db.insert_refresh_token(&RefreshTokenRow {
            token: "future-rt".to_string(),
            client_id: "c1".to_string(),
            access_token: "at2".to_string(),
            scope: None,
            expires_at: "2099-01-01T00:00:00Z".to_string(),
        })
        .expect("insert future refresh token");

        let deleted = db
            .delete_expired_refresh_tokens(now)
            .expect("reaper should succeed");
        assert_eq!(
            deleted, 1,
            "reaper should delete exactly 1 expired refresh token"
        );

        // take_refresh_token returns None if the row is gone.
        let expired = db.take_refresh_token("expired-rt").expect("take ok");
        assert!(
            expired.is_none(),
            "expired refresh token must be gone after reaper"
        );

        let future = db.take_refresh_token("future-rt").expect("take ok");
        assert!(future.is_some(), "future refresh token must survive reaper");
    }

    /// delete_expired_oauth_clients removes clients registered before cutoff,
    /// keeps those registered after.
    #[test]
    fn reaper_oauth_clients() {
        let db = open_test_db();
        let cutoff = "2025-06-01T00:00:00Z";

        db.insert_oauth_client(&OAuthClientRow {
            client_id: "old-client".to_string(),
            client_name: "old".to_string(),
            redirect_uris: "[]".to_string(),
            grant_types: "[]".to_string(),
            response_types: "[]".to_string(),
            token_endpoint_auth_method: "none".to_string(),
            created_at: "2020-01-01T00:00:00Z".to_string(), // before cutoff
            provisioned: false,
            client_secret: None,
        })
        .expect("insert old client");
        db.insert_oauth_client(&OAuthClientRow {
            client_id: "new-client".to_string(),
            client_name: "new".to_string(),
            redirect_uris: "[]".to_string(),
            grant_types: "[]".to_string(),
            response_types: "[]".to_string(),
            token_endpoint_auth_method: "none".to_string(),
            created_at: "2099-01-01T00:00:00Z".to_string(), // after cutoff
            provisioned: false,
            client_secret: None,
        })
        .expect("insert new client");

        let deleted = db
            .delete_expired_oauth_clients(cutoff)
            .expect("reaper should succeed");
        assert_eq!(deleted, 1, "reaper should delete exactly 1 expired client");

        let old = db.get_oauth_client("old-client").expect("lookup ok");
        assert!(old.is_none(), "old client must be gone after reaper");

        let new = db.get_oauth_client("new-client").expect("lookup ok");
        assert!(new.is_some(), "new client must survive reaper");
    }

    /// Provisioned clients survive the reaper even if registered before the cutoff.
    #[test]
    fn reaper_spares_provisioned_clients() {
        let db = open_test_db();
        let cutoff = "2025-06-01T00:00:00Z";

        // Provisioned client registered long before the cutoff.
        db.insert_oauth_client(&OAuthClientRow {
            client_id: "prov-client".to_string(),
            client_name: "provisioned".to_string(),
            redirect_uris: r#"["https://claude.ai/api/mcp/auth_callback"]"#.to_string(),
            grant_types: r#"["authorization_code"]"#.to_string(),
            response_types: r#"["code"]"#.to_string(),
            token_endpoint_auth_method: "client_secret_post".to_string(),
            created_at: "2020-01-01T00:00:00Z".to_string(), // before cutoff
            provisioned: true,
            client_secret: Some("secret".to_string()),
        })
        .expect("insert provisioned client");

        // Non-provisioned client also before the cutoff — should be reaped.
        db.insert_oauth_client(&OAuthClientRow {
            client_id: "dynamic-client".to_string(),
            client_name: "dynamic".to_string(),
            redirect_uris: "[]".to_string(),
            grant_types: "[]".to_string(),
            response_types: "[]".to_string(),
            token_endpoint_auth_method: "none".to_string(),
            created_at: "2020-01-01T00:00:00Z".to_string(), // before cutoff
            provisioned: false,
            client_secret: None,
        })
        .expect("insert dynamic client");

        let deleted = db
            .delete_expired_oauth_clients(cutoff)
            .expect("reaper should succeed");
        assert_eq!(
            deleted, 1,
            "reaper should delete exactly 1 (the non-provisioned client)"
        );

        let prov = db.get_oauth_client("prov-client").expect("lookup ok");
        assert!(
            prov.is_some(),
            "provisioned client must survive reaper regardless of age"
        );

        let dyn_client = db.get_oauth_client("dynamic-client").expect("lookup ok");
        assert!(
            dyn_client.is_none(),
            "non-provisioned old client must be reaped"
        );
    }

    /// list_provisioned_clients returns only provisioned clients.
    #[test]
    fn list_provisioned_clients_only_provisioned() {
        let db = open_test_db();

        db.insert_oauth_client(&OAuthClientRow {
            client_id: "prov-1".to_string(),
            client_name: "Provisioned One".to_string(),
            redirect_uris: r#"["https://claude.ai/api/mcp/auth_callback"]"#.to_string(),
            grant_types: r#"["authorization_code"]"#.to_string(),
            response_types: r#"["code"]"#.to_string(),
            token_endpoint_auth_method: "client_secret_post".to_string(),
            created_at: "2025-01-01T00:00:00Z".to_string(),
            provisioned: true,
            client_secret: Some("secret-1".to_string()),
        })
        .expect("insert prov-1");

        db.insert_oauth_client(&OAuthClientRow {
            client_id: "dyn-1".to_string(),
            client_name: "Dynamic One".to_string(),
            redirect_uris: r#"["https://example.com/cb"]"#.to_string(),
            grant_types: r#"["authorization_code"]"#.to_string(),
            response_types: r#"["code"]"#.to_string(),
            token_endpoint_auth_method: "none".to_string(),
            created_at: "2025-01-02T00:00:00Z".to_string(),
            provisioned: false,
            client_secret: None,
        })
        .expect("insert dyn-1");

        let provisioned = db.list_provisioned_clients().expect("list should succeed");
        assert_eq!(provisioned.len(), 1);
        assert_eq!(provisioned[0].client_id, "prov-1");
        assert!(provisioned[0].provisioned);
    }

    /// revoke_provisioned_client deletes client and its tokens.
    #[test]
    fn revoke_provisioned_client_cascades() {
        let db = open_test_db();

        db.insert_oauth_client(&OAuthClientRow {
            client_id: "prov-revoke".to_string(),
            client_name: "ToRevoke".to_string(),
            redirect_uris: r#"["https://claude.ai/api/mcp/auth_callback"]"#.to_string(),
            grant_types: r#"["authorization_code"]"#.to_string(),
            response_types: r#"["code"]"#.to_string(),
            token_endpoint_auth_method: "client_secret_post".to_string(),
            created_at: "2025-01-01T00:00:00Z".to_string(),
            provisioned: true,
            client_secret: Some("supersecret".to_string()),
        })
        .expect("insert client");

        // Seed an access token for this client.
        db.insert_access_token(&AccessTokenRow {
            token: "at-for-revoke".to_string(),
            client_id: "prov-revoke".to_string(),
            scope: Some("mcp:tools".to_string()),
            expires_at: "2099-01-01T00:00:00Z".to_string(),
        })
        .expect("seed access token");

        let revoked = db
            .revoke_provisioned_client("prov-revoke")
            .expect("revoke should succeed");
        assert!(revoked, "revoke should return true");

        // Client is gone.
        let client = db.get_oauth_client("prov-revoke").expect("lookup ok");
        assert!(client.is_none(), "client must be deleted after revoke");

        // Access token is also gone.
        let at = db.get_access_token("at-for-revoke").expect("lookup ok");
        assert!(
            at.is_none(),
            "access token must be deleted after client revoke"
        );
    }

    /// revoke_provisioned_client returns false for a non-existent client.
    #[test]
    fn revoke_provisioned_client_not_found() {
        let db = open_test_db();
        let result = db
            .revoke_provisioned_client("does-not-exist")
            .expect("should not error");
        assert!(!result, "should return false for non-existent client");
    }

    /// delete_expired_older_than removes documents whose expiry is before the window,
    /// keeps documents with future expiry or no expiry.
    #[test]
    fn reaper_documents() {
        let db = open_test_db();
        let now = "2025-06-01T00:00:00Z";

        // Document expired 10 days ago — should be reaped with a 5-day grace window.
        let expired_doc = DocumentRecord {
            id: "doc-expired".to_string(),
            slug: "expired-doc".to_string(),
            title: "Expired".to_string(),
            raw_content: "# Expired".to_string(),
            theme: "clean".to_string(),
            password: None,
            description: None,
            created_at: "2025-01-01T00:00:00Z".to_string(),
            expires_at: Some("2025-05-22T00:00:00Z".to_string()), // 10 days before now
            updated_at: "2025-01-01T00:00:00Z".to_string(),
        };
        // Document expiring far in the future — must survive.
        let future_doc = DocumentRecord {
            id: "doc-future".to_string(),
            slug: "future-doc".to_string(),
            title: "Future".to_string(),
            raw_content: "# Future".to_string(),
            theme: "clean".to_string(),
            password: None,
            description: None,
            created_at: "2025-01-01T00:00:00Z".to_string(),
            expires_at: Some("2099-01-01T00:00:00Z".to_string()),
            updated_at: "2025-01-01T00:00:00Z".to_string(),
        };
        db.insert_document(&expired_doc)
            .expect("insert expired doc");
        db.insert_document(&future_doc).expect("insert future doc");

        // Grace window of 5 days: only docs expired more than 5 days before `now` are reaped.
        let deleted = db
            .delete_expired_older_than(now, 5)
            .expect("reaper should succeed");
        assert_eq!(
            deleted, 1,
            "reaper should delete exactly 1 expired document"
        );

        let expired = db.get_by_slug("expired-doc").expect("lookup ok");
        assert!(expired.is_none(), "expired doc must be gone after reaper");

        let future = db.get_by_slug("future-doc").expect("lookup ok");
        assert!(future.is_some(), "future doc must survive reaper");
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
