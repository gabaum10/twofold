# Raccoon Work Order: Twofold v0.2

*Compete mode. Six raccoons. DJ picks the best parts.*

---

## Problem Statement

Twofold v0.1 ships a working dual-layer markdown share service: POST markdown in, get two views out. v0.2 adds the features that make it deployable for real use: frontmatter-driven document metadata, custom slugs, expiry/TTL, password protection, edit/delete operations, multiple themes, token management, and release packaging.

The codebase is clean. The module structure is clear (`cli.rs`, `config.rs`, `db.rs`, `handlers.rs`, `parser.rs`, `main.rs`). Your job: extend it without breaking what works.

**CRITICAL: Axum Version Constraint**

The project uses **Axum 0.7.9**. Route parameters use **colon prefix syntax**: `:slug`, NOT curly braces `{slug}`. The curly brace syntax is Axum 0.8 (unreleased as of this build). If you write `Router::new().route("/api/v1/documents/{slug}", ...)` it will NOT match — it treats `{slug}` as a literal path segment. Every route parameter must be `:param`.

```rust
// CORRECT (Axum 0.7):
.route("/api/v1/documents/:slug", get(handler))
.route("/:slug", get(handler))

// WRONG (Axum 0.8 syntax — DOES NOT WORK):
.route("/api/v1/documents/{slug}", get(handler))
.route("/{slug}", get(handler))
```

This bit us once already. Don't repeat it.

---

## What Already Exists (v0.1 — Do Not Break)

Read the source. These are your facts:

| File | What It Does |
|------|-------------|
| `src/main.rs` | Runtime setup, router construction, CLI dispatch, publish client |
| `src/handlers.rs` | POST/GET handlers, AppState, Askama template, comrak rendering, nanoid slug gen, constant-time auth |
| `src/db.rs` | SQLite via rusqlite, `Db` struct with Arc<Mutex<Connection>>, `DocumentRecord`, insert/get_by_slug |
| `src/parser.rs` | Line-based regex marker parser, `parse_document()` -> `ParseResult { human }`, `extract_title()` |
| `src/config.rs` | `ServeConfig::from_env()` — env-var-only config |
| `src/cli.rs` | Clap derive: `serve` and `publish` subcommands |
| `templates/document.html` | Single theme (clean), classless CSS, dark/light, inline styles |
| `Cargo.toml` | Axum 0.7, tokio, comrak 0.28, rusqlite 0.31 bundled, askama 0.12, clap 4, nanoid 0.4, reqwest blocking, regex, subtle |

**Existing env vars (keep working):** `TWOFOLD_TOKEN`, `TWOFOLD_BIND`, `TWOFOLD_DB_PATH`, `TWOFOLD_BASE_URL`, `TWOFOLD_MAX_SIZE`

**Existing endpoints (keep working):**
```
POST   /api/v1/documents              Create document (bearer auth)
GET    /api/v1/documents/:slug         Agent view (full raw markdown)
GET    /:slug                          Human view (rendered HTML, markers stripped)
GET    /:slug?raw=1                    Raw source markdown (full)
```

**Existing behavior contracts (do NOT change):**
- POST returns 201 with `{ url, slug, api_url, title, created_at }`
- Human view strips `<!-- @agent -->` / `<!-- @end -->` sections
- Agent view returns byte-for-byte what was POSTed
- `?raw=1` is identical to agent API endpoint
- Title extracted from first H1, fallback to slug
- 401 on missing/invalid token, 400 on empty body, 413 on oversize
- CSP header: `script-src 'none'`

---

## Architecture Decisions (Settled)

These are not open for divergence. The raccoons choose HOW to implement, not WHAT to use.

| Component | Choice | Why |
|-----------|--------|-----|
| Frontmatter parsing | `serde_yaml` 0.9 (or `yaml-rust2`) | YAML in `---` fences. Standard format. |
| Password hashing | `argon2` 0.5 | Memory-hard. One algorithm for both tokens and doc passwords. |
| Token hashing | `argon2` 0.5 | Same as passwords. Consistent. |
| Background reaper | `tokio::time::interval` | No external scheduler. Async task spawned at startup. |
| Themes | Askama compile-time templates | One `.html` file per theme, all baked into binary. |
| Docker base | `FROM scratch` (static musl binary) or `debian-slim` | Raccoon decides. Binary must run in Docker. |
| Release builds | `cross` or `cargo-zigbuild` for cross-compilation | linux amd64/arm64, macOS aarch64. |

### New Dependencies (add to Cargo.toml)

```toml
# Add these to [dependencies]:
argon2 = "0.5"
serde_yaml = "0.9"     # OR yaml-rust2 = "0.8" — raccoon decides
rand = "0.8"           # For token generation
base64 = "0.22"        # For token encoding
```

Remove `bcrypt` if it was listed anywhere — we use argon2 exclusively.

---

## Feature 1: Frontmatter Parsing

### Specification

Documents MAY begin with a YAML frontmatter block:

```markdown
---
title: My Custom Title
slug: quarterly-report-q1
theme: paper
expiry: 7d
password: hunter2
description: Q1 earnings summary for the board
---

# The Document Content

Everything after the closing `---` is the document body.
```

**Parsing rules:**

1. Frontmatter is OPTIONAL. Documents without frontmatter work exactly as v0.1.
2. Frontmatter MUST be the first thing in the document (no leading whitespace/newlines).
3. Frontmatter is delimited by `---` on its own line (open and close).
4. If frontmatter is present, it is STRIPPED from both human view and agent view. The agent view returns the body after frontmatter, NOT the raw source including frontmatter. **WAIT — this changes the v0.1 contract.** Decision: the agent view returns the FULL raw source including frontmatter. The frontmatter is YAML in HTML comment fences — agents can parse it themselves. The human view strips frontmatter before rendering.
5. Frontmatter fields are ALL optional. An empty frontmatter block (`---\n---`) is valid and means "use defaults for everything."

**Correction on point 4:** Agent view returns FULL raw source (byte-for-byte what was POSTed) — this maintains the v0.1 contract. The human view strips frontmatter before rendering to HTML.

**Supported fields:**

| Field | Type | Default | Effect |
|-------|------|---------|--------|
| `title` | string | First H1 / slug | Overrides H1 extraction |
| `slug` | string | nanoid | Custom URL slug (see Feature 2) |
| `theme` | string | `"clean"` | Theme selection (see Feature 6) |
| `expiry` | string | none (permanent) | TTL duration (see Feature 3) |
| `password` | string | none (public) | Document password (see Feature 4) |
| `description` | string | none | For future use (meta tags, API response) |

**Title priority (v0.2):**
1. `title` field in frontmatter
2. First H1 heading in the body (after frontmatter stripped)
3. Slug as fallback

**Parser integration:** Frontmatter parsing happens BEFORE marker parsing. The flow is:
```
raw_content → extract_frontmatter() → (metadata, body)
body → parse_document() → human corpus (markers stripped)
human corpus → render_markdown() → HTML
```

### POST Response Change

The POST response gains a `description` field (nullable):

```json
{
  "url": "http://localhost:3000/quarterly-report-q1",
  "slug": "quarterly-report-q1",
  "api_url": "http://localhost:3000/api/v1/documents/quarterly-report-q1",
  "title": "My Custom Title",
  "description": "Q1 earnings summary for the board",
  "created_at": "2026-05-10T03:22:00Z",
  "expires_at": "2026-05-17T03:22:00Z"
}
```

New fields: `description` (nullable string), `expires_at` (nullable ISO 8601 string).

---

## Feature 2: Custom Slugs

### Specification

Users may specify a slug via frontmatter:

```yaml
---
slug: my-quarterly-report
---
```

**Slug validation rules:**

1. Allowed characters: `[a-zA-Z0-9-]` (alphanumeric + hyphen). Same charset as nanoid slugs.
2. Min length: 3 characters. Max length: 128 characters.
3. Must not start or end with a hyphen.
4. Must not be a reserved path: `api`, `health`, `status`, `favicon.ico`, `robots.txt`. (These could collide with future routes.)
5. Case-sensitive: `MyReport` and `myreport` are different slugs.

**Collision handling:**

1. Check if slug already exists in the database.
2. If collision: return HTTP 409 Conflict with body `{"error": "Slug 'my-slug' is already in use"}`.
3. Do NOT auto-append a suffix or fall back to nanoid. The user chose this slug — tell them it's taken.

**Fallback:** If no `slug` field in frontmatter (or no frontmatter at all), generate a 10-character nanoid (shorter than v0.1's 21 — custom slugs make discoverability less important, and shorter nanoids are more practical for sharing). Alphabet stays: `[a-zA-Z0-9-]`.

**Slug change on update (PUT):** Slugs are immutable. Once created, a document's slug cannot change via PUT. If the frontmatter in a PUT request contains a different slug value, ignore it (the URL path slug wins).

---

## Feature 3: Expiry / TTL

### Specification

Documents may declare a TTL via frontmatter:

```yaml
---
expiry: 7d
---
```

**Duration format:** A positive integer followed by a unit suffix:

| Suffix | Meaning | Example |
|--------|---------|---------|
| `m` | minutes | `30m` |
| `h` | hours | `24h` |
| `d` | days | `7d` |
| `w` | weeks | `2w` |

No combined durations (no `1d12h`). One value, one unit. Parse with a simple regex: `^(\d+)(m|h|d|w)$`.

**Minimum TTL:** 5 minutes. Anything less is rejected (400: "Expiry must be at least 5 minutes").
**Maximum TTL:** 365 days. Anything more is rejected (400: "Expiry must not exceed 365 days").

**Storage:** The `expires_at` column stores the computed expiration timestamp (ISO 8601 UTC). `created_at + duration = expires_at`. The duration string is NOT stored — only the absolute expiry time.

**Behavior of expired documents:**

- `GET /:slug` → 410 Gone (not 404 — the slug existed, it's gone now)
- `GET /api/v1/documents/:slug` → 410 Gone
- `GET /:slug?raw=1` → 410 Gone
- `PUT /api/v1/documents/:slug` → 410 Gone
- `DELETE /api/v1/documents/:slug` → 410 Gone (already expired, but confirm deletion)

410 response body: `{"error": "Document has expired"}` with Content-Type `application/json`.

**Background reaper:**

A tokio task runs on an interval (configurable, default: 60 seconds):

```rust
// Pseudo-code:
tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(reaper_interval));
    loop {
        interval.tick().await;
        db.delete_expired().await;
    }
});
```

The reaper runs `DELETE FROM documents WHERE expires_at IS NOT NULL AND expires_at < ?` with the current UTC time.

**Important:** The 410 check happens at request time (compare `expires_at` against `now()`). The reaper is a cleanup mechanism — it reclaims storage. A document is "expired" when its `expires_at` has passed, regardless of whether the reaper has run yet.

---

## Feature 4: Password Protection

### Specification

Documents may require a password to view:

```yaml
---
password: hunter2
---
```

**How it works:**

1. The plaintext password from frontmatter is hashed with argon2 at publish time. Only the hash is stored. The raw password is NEVER stored.
2. When a viewer requests the human view (`GET /:slug`), the server returns a password prompt page (simple HTML form) instead of the document.
3. The viewer submits the password via POST to a verification endpoint.
4. On correct password: set a cookie (`twofold_auth_{slug}`) with a short-lived HMAC token (1 hour TTL). Redirect to `GET /:slug`. The slug-specific cookie scopes auth to one document.
5. On incorrect password: re-render the prompt with an error message.

**Password-protected endpoints:**

| Endpoint | Behavior |
|----------|----------|
| `GET /:slug` | Requires password (or valid cookie) |
| `GET /:slug?raw=1` | Requires password (or valid cookie) |
| `GET /api/v1/documents/:slug` | **NO password required** — agent view is unrestricted |

Decision: The agent view bypasses password protection. Rationale: the slug is already a 10+ character unguessable secret. Password protection is a UX feature for human-facing links that might be shared broadly (e.g., in an email). Agent consumers already have the slug — requiring them to handle cookie-based auth would break programmatic consumption.

**Password prompt page:**

A separate Askama template (`password.html`). Minimal form:

```html
<form method="POST" action="/:slug/unlock">
  <label>This document is protected.</label>
  <input type="password" name="password" autofocus>
  <button type="submit">Unlock</button>
</form>
```

**New endpoint:**

```
POST   /:slug/unlock                   Verify password, set auth cookie
```

This endpoint:
- Accepts `application/x-www-form-urlencoded` with field `password`
- Verifies against stored argon2 hash
- On success: sets cookie, 303 redirect to `GET /:slug`
- On failure: re-renders password form with error

**Cookie format:** `twofold_auth_{slug}=<HMAC(slug + expiry_timestamp, server_secret)>:<expiry_timestamp>`

The server secret is derived from `TWOFOLD_TOKEN` (HMAC key). This avoids needing a second secret env var.

**Password update on PUT:** If a PUT request includes a different password in frontmatter, hash the new password and replace the stored hash. If password is removed from frontmatter on PUT, clear the password (document becomes public).

---

## Feature 5: PUT/DELETE Endpoints

### Specification

```
PUT    /api/v1/documents/:slug         Update document (bearer auth)
DELETE /api/v1/documents/:slug         Delete document (bearer auth)
```

**PUT /api/v1/documents/:slug**

Updates the document content. Same auth as POST (bearer token).

Request:
```
PUT /api/v1/documents/:slug
Authorization: Bearer <token>
Content-Type: text/markdown

---
title: Updated Title
theme: dark
---

# Updated Content

New body here.
```

Behavior:
- Re-parses frontmatter (title, theme, expiry, password, description all update)
- `slug` field in frontmatter is IGNORED on PUT (slug is immutable — the URL path is canonical)
- `updated_at` is set to current time
- `created_at` is preserved (unchanged)
- If document doesn't exist: 404
- If document is expired: 410
- Returns 200 with same JSON shape as POST response (updated fields)

**DELETE /api/v1/documents/:slug**

Permanently removes the document.

Request:
```
DELETE /api/v1/documents/:slug
Authorization: Bearer <token>
```

Behavior:
- Deletes the row from the database
- If document doesn't exist: 404
- If document is expired: 204 (delete the expired row anyway, clean up)
- Returns 204 No Content on success

---

## Feature 6: Multiple Built-In Themes

### Specification

v0.1 ships one theme (clean). v0.2 adds three more. Theme is selected via frontmatter:

```yaml
---
theme: paper
---
```

**Available themes:**

| Theme | Description | Default |
|-------|-------------|---------|
| `clean` | v0.1 theme. System fonts, neutral colors, dark/light auto. | YES |
| `dark` | Always dark. Higher contrast. Monospace headings. Terminal energy. | |
| `paper` | Warm. Serif body text. Book-like. Light-only (no dark mode). | |
| `minimal` | Ultra-sparse. No borders. Maximum whitespace. Almost brutalist. | |

**Implementation:** One Askama template per theme:
- `templates/clean.html` (existing `document.html` renamed)
- `templates/dark.html`
- `templates/paper.html`
- `templates/minimal.html`

Each template is a complete standalone HTML file (CSS inlined, zero external requests). All templates share the same Askama variables: `{{ title }}` and `{{ content|safe }}`.

**Template selection in handler:**

```rust
// Pseudo-code:
match theme {
    "clean" => CleanTemplate { title, content }.render(),
    "dark" => DarkTemplate { title, content }.render(),
    "paper" => PaperTemplate { title, content }.render(),
    "minimal" => MinimalTemplate { title, content }.render(),
    _ => CleanTemplate { title, content }.render(), // unknown theme falls back to clean
}
```

**Validation:** Unknown theme names are NOT errors. They fall back to `clean` silently. This allows forward-compatibility — a document authored with a future theme name renders in `clean` until that theme ships.

**Theme requirements (all themes must satisfy):**
- Responsive (mobile + desktop)
- CSS inlined (no external requests)
- `<title>` set to document title
- `{{ content|safe }}` renders the HTML body
- Code blocks styled (monospace, background, padding)
- Tables styled
- Footer: `<small>shared via twofold</small>`

---

## Feature 7: Token Management CLI

### Specification

v0.1 uses a single env var token. v0.2 adds a `tokens` table and CLI management.

**The transition:** The `TWOFOLD_TOKEN` env var becomes the **admin token**. It is NOT stored in the database. It has full access (publish, update, delete, manage tokens). Managed tokens are stored (hashed) in the `tokens` table and can be scoped or revoked.

For v0.2, all tokens (admin + managed) have the same permissions: full publish/update/delete access. Scoped permissions (read-only tokens, per-document tokens) are a future feature.

**CLI subcommands:**

```bash
# Create a new token (outputs the token ONCE — it's never shown again)
twofold token create --name "ci-publish"

# List all tokens (shows name, created, last_used, status — NOT the token value)
twofold token list

# Revoke a token by name
twofold token revoke --name "ci-publish"
```

**`twofold token create --name <name>`**

1. Generate a 32-byte random token, base64url-encode it (43 chars).
2. Hash the token with argon2.
3. Store `{ id: nanoid, name, hash, created_at, last_used: null, revoked: false }` in the `tokens` table.
4. Print the plaintext token to stdout ONCE: `Token created: tf_aBcDeFgH...` (prefix `tf_` for identification).
5. The plaintext is never stored. If lost, revoke and create a new one.

**`twofold token list`**

Output (table format to stdout):
```
NAME            CREATED              LAST USED            STATUS
ci-publish      2026-05-10 03:22     2026-05-10 14:30     active
old-deploy      2026-04-01 12:00     never                revoked
```

This reads the database directly. The `--db` flag (or `TWOFOLD_DB_PATH` env var) tells it which database to query.

**`twofold token revoke --name <name>`**

1. Sets `revoked = true` in the tokens table.
2. Prints confirmation: `Token 'ci-publish' revoked.`
3. If name not found: exit 1 with error.

**Auth flow change:**

When a request arrives with `Authorization: Bearer <token>`:

1. Check if it matches the admin token (`TWOFOLD_TOKEN` env var) — constant-time compare. If yes: authorized.
2. If not the admin token: hash the provided token with argon2 and check against all non-revoked entries in the `tokens` table. If any match: authorized. Update `last_used`.
3. If no match: 401.

**Performance note:** Argon2 verification is intentionally slow (~100ms). For v0.2 with a handful of tokens, iterating all non-revoked tokens is acceptable. If token count grows past ~50, a future version should add a token prefix index for lookup before hashing. Document this as a known scaling limit.

**Database access for CLI:** The token management commands need direct SQLite access. They use `TWOFOLD_DB_PATH` (same env var as the server) to find the database. The commands work whether or not the server is running (SQLite supports concurrent readers).

---

## Feature 8: Docker Image + Binary Releases

### Specification

**Dockerfile:**

```dockerfile
# Multi-stage build
FROM rust:1-slim AS builder
WORKDIR /src
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/twofold /usr/local/bin/twofold
EXPOSE 3000
ENTRYPOINT ["twofold", "serve"]
```

Raccoon decides: `debian-slim` vs `scratch` (musl static) vs `distroless`. All are valid. The binary must start and serve.

**Environment in Docker:**
- `TWOFOLD_TOKEN` — required (no default)
- `TWOFOLD_BIND=0.0.0.0:3000` — override default to bind all interfaces in container
- `TWOFOLD_DB_PATH=/data/twofold.db` — volume mount target
- `TWOFOLD_BASE_URL` — required for correct URL generation

**Binary releases (GitHub Actions):**

CI builds on tag push (`v*`):
- `twofold-linux-amd64` (x86_64-unknown-linux-musl)
- `twofold-linux-arm64` (aarch64-unknown-linux-musl)
- `twofold-macos-arm64` (aarch64-apple-darwin)

Upload as GitHub Release assets. Raccoons provide the GitHub Actions workflow file (`.github/workflows/release.yml`).

**Acceptance:** The Dockerfile builds. The image runs. `docker run -e TWOFOLD_TOKEN=test -p 3000:3000 twofold` starts the server and responds to requests.

---

## Storage Schema (v0.2)

```sql
-- Migration from v0.1: add columns to documents, create tokens table.
-- The server checks on startup and runs migrations if needed.

-- Updated documents table
CREATE TABLE IF NOT EXISTS documents (
    id          TEXT PRIMARY KEY,
    slug        TEXT UNIQUE NOT NULL,
    title       TEXT NOT NULL,
    raw_content TEXT NOT NULL,
    theme       TEXT NOT NULL DEFAULT 'clean',
    password    TEXT,              -- argon2 hash, nullable (null = public)
    description TEXT,             -- nullable
    created_at  TEXT NOT NULL,
    expires_at  TEXT,             -- nullable (null = no expiry), ISO 8601 UTC
    updated_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_documents_slug ON documents(slug);
CREATE INDEX IF NOT EXISTS idx_documents_expires_at ON documents(expires_at);

-- Tokens table (new in v0.2)
CREATE TABLE IF NOT EXISTS tokens (
    id         TEXT PRIMARY KEY,
    name       TEXT UNIQUE NOT NULL,
    hash       TEXT NOT NULL,      -- argon2 hash of the token
    created_at TEXT NOT NULL,
    last_used  TEXT,               -- nullable, updated on each successful auth
    revoked    INTEGER NOT NULL DEFAULT 0   -- 0 = active, 1 = revoked
);
```

**Migration strategy:** On startup, the server checks if the `tokens` table exists and if the `documents` table has the new columns. If not, it runs ALTER TABLE / CREATE TABLE statements. No migration framework — just idempotent DDL.

```sql
-- Idempotent migration statements (run on every startup, safe if already applied):
ALTER TABLE documents ADD COLUMN theme TEXT NOT NULL DEFAULT 'clean';
ALTER TABLE documents ADD COLUMN password TEXT;
ALTER TABLE documents ADD COLUMN description TEXT;
ALTER TABLE documents ADD COLUMN expires_at TEXT;
-- (SQLite ignores ALTER TABLE ADD COLUMN if column already exists? No — it errors.
--  So: wrap in a check. The raccoon handles this. Options: try/catch the error,
--  or query pragma table_info and conditionally alter.)
```

The raccoon figures out the migration approach. Options: `PRAGMA table_info` introspection, or catch the "duplicate column" error and continue. Either is fine. The schema MUST be correct after startup regardless of whether this is a fresh database or a v0.1 database being upgraded.

---

## Configuration (v0.2)

v0.2 still uses environment variables. Config TOML was originally planned but is deferred — env vars work fine for Docker deployment.

### Environment Variables

```bash
# Existing (unchanged):
TWOFOLD_TOKEN="admin-token"           # Required. Admin auth.
TWOFOLD_BIND="127.0.0.1:3000"        # Optional. Default: 127.0.0.1:3000
TWOFOLD_DB_PATH="./twofold.db"       # Optional. Default: ./twofold.db
TWOFOLD_BASE_URL="http://localhost:3000"  # Optional. For response URLs.
TWOFOLD_MAX_SIZE="1048576"            # Optional. Max body bytes. Default: 1MB.

# New in v0.2:
TWOFOLD_REAPER_INTERVAL="60"          # Optional. Seconds between reaper runs. Default: 60.
TWOFOLD_DEFAULT_THEME="clean"         # Optional. Theme when none specified. Default: clean.
```

---

## API Shape (v0.2 — Complete)

```
POST   /api/v1/documents              Create document (bearer auth)
PUT    /api/v1/documents/:slug         Update document (bearer auth)
DELETE /api/v1/documents/:slug         Delete document (bearer auth)
GET    /api/v1/documents/:slug         Agent view (full raw markdown, no password gate)
GET    /:slug                          Human view (themed HTML, password-gated if set)
GET    /:slug?raw=1                    Raw source (password-gated if set)
POST   /:slug/unlock                   Password verification
```

**Reminder: Axum 0.7.9 uses `:slug` syntax. NOT `{slug}`.**

---

## Acceptance Criteria (v0.2)

Binary pass/fail. All must pass for GREEN.

### Frontmatter Parsing
- [ ] Document with frontmatter: title extracted from `title:` field
- [ ] Document with frontmatter but no `title:`: falls back to first H1
- [ ] Document without frontmatter: works exactly as v0.1
- [ ] Empty frontmatter block (`---\n---\n`) is valid, uses all defaults
- [ ] Frontmatter is stripped from human view HTML
- [ ] Agent view returns full raw source INCLUDING frontmatter
- [ ] Invalid YAML in frontmatter: 400 with descriptive error
- [ ] Unknown frontmatter fields are silently ignored (forward-compatible)

### Custom Slugs
- [ ] `slug: my-report` in frontmatter creates document at `/my-report`
- [ ] Invalid slug chars (spaces, underscores, unicode): 400
- [ ] Slug too short (<3): 400
- [ ] Slug too long (>128): 400
- [ ] Slug starts/ends with hyphen: 400
- [ ] Reserved slug (`api`): 400
- [ ] Duplicate slug: 409 Conflict
- [ ] No slug in frontmatter: nanoid generated (10 chars)
- [ ] Custom slug appears correctly in response `url` and `api_url`

### Expiry / TTL
- [ ] `expiry: 7d` sets `expires_at` 7 days from now
- [ ] `expiry: 30m` sets `expires_at` 30 minutes from now
- [ ] `expiry: 2w` sets `expires_at` 14 days from now
- [ ] Expired document returns 410 on all GET endpoints
- [ ] Expired document returns 410 on PUT
- [ ] `expires_at` field present in POST/PUT response
- [ ] No `expiry` field: document never expires (`expires_at` is null in response)
- [ ] Background reaper deletes expired documents from database
- [ ] Expiry below 5m: 400
- [ ] Expiry above 365d: 400
- [ ] Invalid expiry format: 400

### Password Protection
- [ ] Document with `password:` field shows password prompt on `GET /:slug`
- [ ] Correct password submission sets cookie and shows document
- [ ] Incorrect password re-shows prompt with error
- [ ] Agent view (`/api/v1/documents/:slug`) is NOT password-gated
- [ ] `?raw=1` IS password-gated (same as human view)
- [ ] Password cookie expires after 1 hour
- [ ] Different documents have different cookies (slug-scoped)
- [ ] PUT with new password updates the hash
- [ ] PUT with password removed makes document public

### PUT Endpoint
- [ ] PUT with valid token and existing slug: 200 with updated response
- [ ] PUT updates `raw_content`, `title`, `theme`, `updated_at`
- [ ] PUT preserves `created_at`
- [ ] PUT ignores `slug` field in frontmatter (slug is immutable)
- [ ] PUT to nonexistent slug: 404
- [ ] PUT to expired slug: 410
- [ ] PUT without auth: 401
- [ ] PUT with empty body: 400
- [ ] PUT updates `expires_at` if expiry changes in frontmatter

### DELETE Endpoint
- [ ] DELETE with valid token and existing slug: 204
- [ ] DELETE removes document from database
- [ ] Subsequent GET returns 404 (not 410 — it's gone, not expired)
- [ ] DELETE nonexistent slug: 404
- [ ] DELETE expired slug: 204 (cleanup)
- [ ] DELETE without auth: 401

### Themes
- [ ] `theme: clean` renders with clean theme (same as v0.1)
- [ ] `theme: dark` renders with dark theme
- [ ] `theme: paper` renders with paper theme
- [ ] `theme: minimal` renders with minimal theme
- [ ] Unknown theme name: falls back to clean (no error)
- [ ] All themes are responsive (mobile-friendly)
- [ ] All themes render code blocks, tables, lists correctly
- [ ] No theme makes external network requests

### Token Management
- [ ] `twofold token create --name "test"` outputs a token prefixed with `tf_`
- [ ] Created token can authenticate POST/PUT/DELETE requests
- [ ] `twofold token list` shows name, created, last_used, status
- [ ] `twofold token revoke --name "test"` makes token stop working
- [ ] Revoked token returns 401 on next use
- [ ] Admin token (env var) still works after managed tokens are created
- [ ] Token name must be unique (error on duplicate)
- [ ] `last_used` updates on successful auth

### Docker
- [ ] `docker build .` succeeds
- [ ] Container starts with `docker run -e TWOFOLD_TOKEN=test -p 3000:3000`
- [ ] Server responds to requests from host machine
- [ ] Database persists across container restarts with volume mount

### Migration
- [ ] Fresh database (no existing data): full schema created, server starts
- [ ] v0.1 database (existing documents): new columns added, existing documents accessible, server starts
- [ ] v0.1 documents after migration: serve correctly with default theme, no password, no expiry

---

## Test Cases (v0.2) — Curl Commands

Run against:
```bash
TWOFOLD_TOKEN="test-token-123" TWOFOLD_BIND="127.0.0.1:3000" twofold serve
```

### Test 1: Publish with frontmatter

```bash
curl -s -X POST http://localhost:3000/api/v1/documents \
  -H "Authorization: Bearer test-token-123" \
  -H "Content-Type: text/markdown" \
  -d '---
title: Board Report Q1
slug: board-q1
theme: paper
description: Q1 summary for the board
---

# Quarterly Results

Revenue up 23%.

<!-- @agent -->
## Full Data
Revenue: $4.2M, Churn: 3.1%, NRR: 112%
<!-- @end -->

Looking forward to Q2.'
```

**Expected:** HTTP 201. Response contains `"slug": "board-q1"`, `"title": "Board Report Q1"`, `"description": "Q1 summary for the board"`, URL is `http://localhost:3000/board-q1`.

### Test 2: Custom slug collision

```bash
curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:3000/api/v1/documents \
  -H "Authorization: Bearer test-token-123" \
  -H "Content-Type: text/markdown" \
  -d '---
slug: board-q1
---

# Duplicate slug attempt.'
```

**Expected:** HTTP 409.

### Test 3: Invalid slug

```bash
curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:3000/api/v1/documents \
  -H "Authorization: Bearer test-token-123" \
  -H "Content-Type: text/markdown" \
  -d '---
slug: has spaces and_underscores!
---

# Bad slug.'
```

**Expected:** HTTP 400.

### Test 4: Expiry sets future timestamp

```bash
RESPONSE=$(curl -s -X POST http://localhost:3000/api/v1/documents \
  -H "Authorization: Bearer test-token-123" \
  -H "Content-Type: text/markdown" \
  -d '---
expiry: 1h
slug: expires-soon
---

# Short-lived document.')

echo $RESPONSE | jq '.expires_at'
```

**Expected:** HTTP 201. `expires_at` is approximately 1 hour from now (ISO 8601).

### Test 5: Theme selection

```bash
SLUG=$(curl -s -X POST http://localhost:3000/api/v1/documents \
  -H "Authorization: Bearer test-token-123" \
  -H "Content-Type: text/markdown" \
  -d '---
theme: dark
slug: dark-themed
---

# Dark Theme Test

Content here.' | jq -r '.slug')

curl -s http://localhost:3000/$SLUG | grep -c "dark"
```

**Expected:** HTTP 201. The human view HTML contains dark-theme-specific CSS (the exact match depends on the raccoon's implementation — but it MUST be visually distinct from clean).

### Test 6: PUT updates document

```bash
curl -s -X PUT http://localhost:3000/api/v1/documents/board-q1 \
  -H "Authorization: Bearer test-token-123" \
  -H "Content-Type: text/markdown" \
  -d '---
title: Board Report Q1 (Updated)
theme: clean
---

# Updated Content

Revenue up 25% (revised).'
```

**Expected:** HTTP 200. Response contains `"title": "Board Report Q1 (Updated)"`. Theme changed to clean.

### Test 7: PUT preserves slug

```bash
curl -s -X PUT http://localhost:3000/api/v1/documents/board-q1 \
  -H "Authorization: Bearer test-token-123" \
  -H "Content-Type: text/markdown" \
  -d '---
slug: totally-different-slug
title: Slug Should Not Change
---

# Content.' | jq -r '.slug'
```

**Expected:** Response slug is still `"board-q1"` (frontmatter slug ignored on PUT).

### Test 8: DELETE

```bash
# Create a document to delete
curl -s -X POST http://localhost:3000/api/v1/documents \
  -H "Authorization: Bearer test-token-123" \
  -H "Content-Type: text/markdown" \
  -d '---
slug: delete-me
---

# To be deleted.' > /dev/null

# Delete it
curl -s -o /dev/null -w "%{http_code}" -X DELETE http://localhost:3000/api/v1/documents/delete-me \
  -H "Authorization: Bearer test-token-123"
```

**Expected:** HTTP 204.

### Test 9: GET after DELETE returns 404

```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/delete-me
```

**Expected:** HTTP 404 (not 410 — document was deleted, not expired).

### Test 10: Expired document returns 410

```bash
# Create a document that expires in 5 minutes
curl -s -X POST http://localhost:3000/api/v1/documents \
  -H "Authorization: Bearer test-token-123" \
  -H "Content-Type: text/markdown" \
  -d '---
expiry: 5m
slug: ttl-test
---

# Will expire.' > /dev/null

# Wait... (or manually set expires_at to the past in the database for testing)
# For real testing: use sqlite3 to backdate the expires_at, then:
sqlite3 ./twofold.db "UPDATE documents SET expires_at = '2020-01-01T00:00:00Z' WHERE slug = 'ttl-test'"

curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/ttl-test
```

**Expected:** HTTP 410.

### Test 11: Agent view bypasses password

```bash
curl -s -X POST http://localhost:3000/api/v1/documents \
  -H "Authorization: Bearer test-token-123" \
  -H "Content-Type: text/markdown" \
  -d '---
slug: secret-doc
password: s3cret
---

# Protected Content

This should be behind a password for humans.' > /dev/null

# Human view — should get password prompt, not content
curl -s http://localhost:3000/secret-doc | grep -c "password"

# Agent view — should get full raw markdown
curl -s http://localhost:3000/api/v1/documents/secret-doc | grep -c "Protected Content"
```

**Expected:** Human view contains a password form. Agent view contains "Protected Content".

### Test 12: Password unlock flow

```bash
# Submit correct password (follow redirects)
curl -s -L -c /tmp/twofold-cookies -X POST http://localhost:3000/secret-doc/unlock \
  -d "password=s3cret"

# Now fetch with the cookie — should get the document
curl -s -b /tmp/twofold-cookies http://localhost:3000/secret-doc | grep -c "Protected Content"
```

**Expected:** After unlock, human view contains "Protected Content".

### Test 13: Token management

```bash
# Create a token
TOKEN=$(twofold token create --name "test-managed" --db ./twofold.db 2>/dev/null)

# Use the new token to publish
curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:3000/api/v1/documents \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: text/markdown" \
  -d '# Published with managed token.'
```

**Expected:** Token create outputs `tf_...`. POST with that token returns 201.

### Test 14: Revoke token

```bash
twofold token revoke --name "test-managed" --db ./twofold.db

# Try to use revoked token
curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:3000/api/v1/documents \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: text/markdown" \
  -d '# Should fail.'
```

**Expected:** Revoke prints confirmation. POST with revoked token returns 401.

### Test 15: v0.1 backward compatibility

```bash
# No frontmatter, no custom slug — should work exactly like v0.1
curl -s -X POST http://localhost:3000/api/v1/documents \
  -H "Authorization: Bearer test-token-123" \
  -H "Content-Type: text/markdown" \
  -d '# Simple Document

No frontmatter. Just markdown.

<!-- @agent -->
Hidden agent data.
<!-- @end -->

Visible ending.'
```

**Expected:** HTTP 201. Slug is auto-generated (10-char nanoid). Title is "Simple Document". Human view strips agent section. Agent view returns full source. Identical to v0.1 behavior.

### Test 16: Frontmatter in agent view

```bash
SLUG=$(curl -s -X POST http://localhost:3000/api/v1/documents \
  -H "Authorization: Bearer test-token-123" \
  -H "Content-Type: text/markdown" \
  -d '---
title: Agent Sees All
theme: dark
---

# Body content.' | jq -r '.slug')

curl -s http://localhost:3000/api/v1/documents/$SLUG | head -3
```

**Expected:** First line of agent view is `---` (frontmatter is present in agent view).

---

## What Is NOT in Scope (v0.2)

Do NOT build any of these. They are explicitly deferred.

- **Config TOML file** — env vars only. TOML is deferred to a future version.
- **AST-aware marker parsing** — the line-based regex parser stays. Known code-block limitation is documented, not fixed.
- **Rate limiting** — handled at reverse proxy layer.
- **Access logging / view counters** — no analytics. Deferred to v0.3.
- **MCP integration** — v0.3.
- **Webhooks** — v0.3.
- **Document listing endpoint** — no index. You need the slug.
- **Syntax highlighting** — plain code blocks. No syntect.
- **OpenAPI spec** — v0.3.
- **Graceful shutdown** — nice-to-have, not required.
- **Custom theme directory** — only built-in themes. No user-uploaded CSS.
- **Token scoping/permissions** — all tokens are full-access in v0.2.
- **Accept header negotiation** — URL path determines view. No content negotiation via headers.
- **HTTPS / TLS** — reverse proxy handles this.
- **Nix package** — v1.0.
- **Tests** — raccoons MAY write tests. Not required for GREEN. The curl commands are acceptance tests.
- **`twofold ls` / `twofold rm` CLI commands** — v0.3.

---

## Constraints

- **Language:** Rust, edition 2021
- **Minimum Rust version:** stable
- **Binary name:** `twofold`
- **Axum version:** 0.7.9. Route params use `:param` (colon prefix). NOT `{param}`.
- **No unsafe code** unless justified in a comment
- **No `.unwrap()` on user input paths** — proper error handling. `.unwrap()` on infallible operations is fine.
- **Startup must not panic on missing env vars** — print useful error, exit
- **Single crate** — no workspace, no sub-crates. One `Cargo.toml`, one `src/` directory.
- **Module structure is open** — raccoons organize `src/` however they want
- **Backward compatible** — all v0.1 curl tests must still pass against v0.2

---

## Notes for DJ

The raccoons compete on the FULL v0.2. Each raccoon builds all 8 features independently.

**What to evaluate divergence on:**
- Frontmatter parsing approach (serde_yaml vs manual parse, struct vs HashMap)
- Schema migration strategy (PRAGMA introspection vs error catch)
- Password auth UX (cookie approach, HMAC implementation, prompt template)
- Theme CSS quality (are they visually distinct? do they look good?)
- Token management CLI ergonomics
- Background reaper implementation (error handling, graceful shutdown)
- Dockerfile quality (image size, layer caching, security)
- How they handle the POST handler complexity growth (one big function vs decomposed)

**Assembly priority:**
1. Does it compile? (`cargo build`)
2. Do the v0.1 curl tests still pass? (backward compatibility)
3. Do the v0.2 curl tests pass? (tests 1-16)
4. Code clarity — can this be extended in v0.3 without rewriting?
5. Theme quality — do they look good?
6. Migration safety — does a v0.1 database upgrade cleanly?

**GREEN = compiles + v0.1 tests pass + tests 1-9 pass.** Tests 10-16 (expiry timing, password flow, token management, Docker) are bonus.

**IMPORTANT for DJ: Update CLAUDE.md as architecture decisions are made during assembly.** When you pick an approach (e.g., "we're using serde_yaml with a typed struct," "migration uses PRAGMA table_info," "password cookies use HMAC-SHA256"), add those decisions to the project's CLAUDE.md so future sessions start with settled context. The CLAUDE.md is the living architecture record — don't let decisions evaporate.

---

## Edge Cases the Raccoons Must Handle

| Case | Expected Behavior |
|------|-------------------|
| Frontmatter with only `---` openers (no close) | Treat entire document as body (no frontmatter detected) |
| Frontmatter YAML parse error | 400 with message: "Invalid frontmatter: {yaml error}" |
| Custom slug that looks like a nanoid | Valid — no special treatment. First-come-first-served. |
| PUT that adds expiry to a permanent document | Set `expires_at` going forward. Document now has TTL. |
| PUT that removes expiry from an expiring document | Clear `expires_at`. Document becomes permanent. |
| PUT that changes password | Hash new password, replace old hash. Existing cookies invalidated (new HMAC). |
| Password-protected + expired | 410 takes priority over password prompt. Dead is dead. |
| DELETE an already-expired document | 204. Clean it up. |
| Publish with both custom slug AND expiry AND password AND theme | All four features compose. No conflicts. |
| Empty password field (`password: ""`) | Treated as no password (empty string = no protection). |
| Reaper runs while server is handling a request for same doc | SQLite serializes. Request either succeeds (doc still exists) or gets 410/404. No crash. |
| Token create with duplicate name | Error, exit 1: "Token name 'foo' already exists." |
| Token list with empty database | Shows header row only, no tokens. |
| Very long frontmatter (>64KB of YAML) | Falls under max body size limit. If total body > 1MB, rejected by layer. |

---

*The v0.1 bones are solid. Eight features, all composable, all backward-compatible. Build it.*
