use rusqlite::{Connection, Result};
use std::sync::{Arc, Mutex};

/// A stored document record (maps 1:1 to the `documents` table row).
#[derive(Debug, Clone)]
pub struct DocumentRecord {
    pub id: String,
    pub slug: String,
    pub title: String,
    pub raw_content: String,
    pub created_at: String, // ISO 8601 UTC
    pub updated_at: String,
}

/// Thread-safe database handle.
///
/// Contract: all methods take `&self`; internal synchronization via Mutex.
/// Errors are rusqlite::Error — callers map to HTTP status codes.
#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

impl Db {
    /// Open or create the SQLite database at `path`, running schema initialization.
    ///
    /// Uses rusqlite "bundled" feature — no external libsqlite3 required.
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        let db = Db {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.initialize_schema()?;
        Ok(db)
    }

    /// Create the schema if it does not exist.
    ///
    /// v0.1 schema: single `documents` table + slug index.
    /// No migration system — schema is idempotent via IF NOT EXISTS.
    fn initialize_schema(&self) -> Result<()> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS documents (
                id          TEXT PRIMARY KEY,
                slug        TEXT UNIQUE NOT NULL,
                title       TEXT NOT NULL,
                raw_content TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_documents_slug ON documents(slug);",
        )?;
        Ok(())
    }

    /// Insert a new document into the database.
    ///
    /// Returns Err if slug already exists (UNIQUE constraint violation).
    pub fn insert_document(&self, doc: &DocumentRecord) -> Result<()> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.execute(
            "INSERT INTO documents (id, slug, title, raw_content, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                doc.id,
                doc.slug,
                doc.title,
                doc.raw_content,
                doc.created_at,
                doc.updated_at,
            ],
        )?;
        Ok(())
    }

    /// Fetch a document by slug.
    ///
    /// Returns Ok(None) if no row matches the slug (caller maps to 404).
    /// Returns Ok(Some(DocumentRecord)) on success.
    /// Returns Err on database error.
    pub fn get_by_slug(&self, slug: &str) -> Result<Option<DocumentRecord>> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, slug, title, raw_content, created_at, updated_at
             FROM documents WHERE slug = ?1",
        )?;

        let mut rows = stmt.query(rusqlite::params![slug])?;
        match rows.next()? {
            None => Ok(None),
            Some(row) => Ok(Some(DocumentRecord {
                id: row.get(0)?,
                slug: row.get(1)?,
                title: row.get(2)?,
                raw_content: row.get(3)?,
                created_at: row.get(4)?,
                updated_at: row.get(5)?,
            })),
        }
    }
}
