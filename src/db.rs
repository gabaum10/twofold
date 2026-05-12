use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{Result, params};

/// A stored document record (maps 1:1 to the `documents` table row).
#[derive(Debug, Clone)]
pub struct DocumentRecord {
    pub id: String,
    pub slug: String,
    pub title: String,
    pub raw_content: String,
    pub theme: String,
    pub password: Option<String>,   // argon2 hash, None = public
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
    pub hash: String,     // argon2 hash of the token
    pub created_at: String,
    pub last_used: Option<String>,
    pub revoked: bool,
    /// First 8 characters of the plaintext token — stored for O(1) lookup.
    /// NULL for tokens created before v0.4 (legacy tokens).
    pub prefix: Option<String>,
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
    rusqlite::Error::InvalidPath(
        std::path::PathBuf::from(format!("connection pool error: {e}")),
    )
}

impl Db {
    /// Open or create the SQLite database at `path`, running schema initialization.
    ///
    /// Builds an r2d2 pool (max 8 connections) so concurrent reads can run in
    /// parallel under WAL mode instead of serializing through a single Mutex.
    /// WAL mode and busy_timeout are applied to each connection at open time.
    pub fn open(path: &str) -> Result<Self> {
        let manager = SqliteConnectionManager::file(path)
            .with_init(|conn| {
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
            CREATE INDEX IF NOT EXISTS idx_tokens_prefix ON tokens(prefix);",
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
                "ALTER TABLE documents ADD COLUMN theme TEXT NOT NULL DEFAULT 'clean';"
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
            "CREATE INDEX IF NOT EXISTS idx_documents_expires_at ON documents(expires_at);"
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
            conn.execute_batch(
                "ALTER TABLE tokens ADD COLUMN prefix TEXT;"
            )?;
        }
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_tokens_prefix ON tokens(prefix);"
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
        let rows = conn.execute(
            "DELETE FROM documents WHERE slug = ?1",
            params![slug],
        )?;
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

    /// Get all non-revoked token hashes for auth verification.
    ///
    /// Used as a fallback for legacy tokens (prefix IS NULL) and in tests.
    pub fn get_active_tokens(&self) -> Result<Vec<TokenRecord>> {
        let conn = self.pool.get().map_err(pool_err)?;
        let mut stmt = conn.prepare(
            "SELECT id, name, hash, created_at, last_used, revoked, prefix
             FROM tokens WHERE revoked = 0",
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
            .filter_map(|r| r.ok())
            .collect();
        Ok(tokens)
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
            .filter_map(|r| r.ok())
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
            .filter_map(|r| r.ok())
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
        let mut stmt = conn.prepare(
            "SELECT COUNT(*) FROM tokens WHERE name = ?1",
        )?;
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
