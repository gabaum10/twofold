# Twofold

One document, two views. Rust-native self-hosted markdown share service.

## What This Is

Twofold accepts markdown documents with optional `<!-- @agent -->` / `<!-- @end -->` markers. It renders two views from one source:
- **Human view** (`/:slug`) — styled HTML, markers stripped, frontmatter stripped
- **Agent view** (`/api/v1/documents/:slug`) — full content including frontmatter and marked sections
- **Raw** (`/:slug?raw=1`) — source markdown (password-gated if protected)

## Tech Stack

- **Axum 0.7.9** — HTTP framework (route params use `:param` NOT `{param}`)
- **Comrak** — Markdown to HTML (GFM extensions)
- **SQLite** (via rusqlite) — document storage, WAL mode, 5s busy_timeout
- **Askama** — HTML templates (one per theme, compiled into binary)
- **nanoid** — slug generation (10 chars, alphanumeric + hyphen)
- **serde_yaml** — frontmatter parsing
- **argon2** — password hashing and token hashing
- **chrono** — timestamp handling
- **hmac + sha2** — cookie signatures for password auth

## Architecture

- `src/main.rs` — server setup, routes, reaper task, CLI dispatch, publish client, token management
- `src/handlers.rs` — all HTTP handlers, AppError enum, auth, password flow, theme rendering
- `src/parser.rs` — frontmatter extraction, marker parsing (no-regex), slug validation, expiry parsing
- `src/db.rs` — SQLite operations (documents + tokens), schema migration
- `src/config.rs` — env-var config loading
- `src/cli.rs` — clap CLI definitions (serve, publish, token)
- `templates/document.html` — clean theme (default, Glyph's design)
- `templates/dark.html` — always-dark, monospace, terminal energy
- `templates/paper.html` — warm serif, book-like, light-only
- `templates/minimal.html` — ultra-sparse, brutalist
- `templates/password.html` — password prompt page

## Key Design Decisions (v0.2)

- **Frontmatter**: serde_yaml with a typed `Frontmatter` struct + `#[serde(flatten)]` for forward-compat unknown fields
- **Marker parser**: No-regex `is_marker()` via `strip_prefix`/`strip_suffix` (from raccoon assembly)
- **Schema migration**: PRAGMA table_info introspection, conditional ALTER TABLE
- **Password auth**: argon2 hash stored in DB, HMAC-SHA256 cookie (keyed with TWOFOLD_TOKEN), 1h TTL, slug-scoped
- **Token management**: argon2 hash, `tf_` prefix, base64url encoding, CLI direct-to-DB
- **Auth flow**: admin token (constant-time compare) checked first, then managed tokens (argon2 verify loop)
- **Expiry**: ISO 8601 timestamps in DB, checked at request time, background reaper for storage cleanup
- **Themes**: Askama compile-time templates, unknown theme falls back to clean silently
- **AppError**: enum with IntoResponse impl, JSON error bodies
- **Slug generation**: 10-char nanoid (down from 21 in v0.1), custom slugs validated at publish time

## Environment Variables

```bash
TWOFOLD_TOKEN="secret"              # Required. Admin auth token.
TWOFOLD_BIND="127.0.0.1:3000"      # Optional. Bind address.
TWOFOLD_DB_PATH="./twofold.db"     # Optional. SQLite path.
TWOFOLD_BASE_URL="http://localhost:3000"  # Optional. For response URLs.
TWOFOLD_MAX_SIZE="1048576"          # Optional. Max body bytes (1MB).
TWOFOLD_REAPER_INTERVAL="60"        # Optional. Seconds between reaper runs.
TWOFOLD_DEFAULT_THEME="clean"       # Optional. Default theme.
```

## API

```
POST   /api/v1/documents              Create (bearer auth, text/markdown body)
PUT    /api/v1/documents/:slug         Update (bearer auth)
DELETE /api/v1/documents/:slug         Delete (bearer auth) -> 204
GET    /api/v1/documents/:slug         Agent view (full raw, no password gate)
GET    /:slug                          Human view (themed, password-gated if set)
GET    /:slug?raw=1                    Raw source (password-gated if set)
POST   /:slug/unlock                   Password verification -> cookie + redirect
```

## CLI

```bash
twofold serve                          # Start HTTP server
twofold publish <path|-> [--server URL] [--token TOKEN]
twofold token create --name "name" [--db path]
twofold token list [--db path]
twofold token revoke --name "name" [--db path]
```

## Building

```bash
cargo build --release
cargo test
```

## Running

```bash
TWOFOLD_TOKEN=your-secret ./target/release/twofold serve
```

## Work Orders

- `docs/work-order.md` — v0.1 specification
- `docs/work-order-v02.md` — v0.2 specification with acceptance criteria
