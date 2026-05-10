# Raccoon Work Order: Twofold v0.3

*Compete mode. Six raccoons. DJ picks the best parts.*

---

## Problem Statement

Twofold v0.2 ships a solid self-hosted markdown share service: publish, update, delete, frontmatter, custom slugs, expiry, passwords, themes, token management. It works. v0.3 makes it useful as infrastructure — the layer that agents and pipelines publish through without thinking about it.

Three integration vectors: MCP (agents call twofold natively as a tool), CLI (humans pipe into it from scripts), and webhooks (downstream systems react to publishes). Plus two quality-of-life features: syntax highlighting for code-heavy documents and an OpenAPI spec for machine-readable API documentation.

**This is the "other systems talk to twofold" release.**

**CRITICAL: Build directly in the twofold repo using `--repo ~/projects/twofold`.** Do not build in the scrapyard. The code lives here; the work goes here.

---

## What Already Exists (v0.2 — Do Not Break)

Read the source. These are your facts:

| File | What It Does |
|------|-------------|
| `src/main.rs` | Server setup, routes, reaper task, CLI dispatch (serve/publish/token) |
| `src/handlers.rs` | POST/PUT/DELETE/GET handlers, AppError enum, auth (admin + managed tokens), password flow, theme rendering, comrak markdown |
| `src/parser.rs` | Frontmatter extraction (serde_yaml), marker parsing (no-regex `is_marker()`), slug validation, expiry parsing |
| `src/db.rs` | SQLite via rusqlite, Arc<Mutex<Connection>>, documents + tokens tables, PRAGMA migration |
| `src/config.rs` | `ServeConfig::from_env()` — env vars only |
| `src/cli.rs` | Clap derive: `serve`, `publish`, `token {create,list,revoke}` |
| `templates/document.html` | Clean theme (default) |
| `templates/dark.html` | Always-dark, monospace |
| `templates/paper.html` | Warm serif, book-like |
| `templates/minimal.html` | Ultra-sparse |
| `templates/password.html` | Password prompt page |

**Existing env vars (keep working):** `TWOFOLD_TOKEN`, `TWOFOLD_BIND`, `TWOFOLD_DB_PATH`, `TWOFOLD_BASE_URL`, `TWOFOLD_MAX_SIZE`, `TWOFOLD_REAPER_INTERVAL`, `TWOFOLD_DEFAULT_THEME`

**Existing endpoints (keep working):**
```
POST   /api/v1/documents              Create document (bearer auth)
PUT    /api/v1/documents/:slug         Update document (bearer auth)
DELETE /api/v1/documents/:slug         Delete document (bearer auth)
GET    /api/v1/documents/:slug         Agent view (full raw markdown, no password gate)
GET    /:slug                          Human view (themed HTML, password-gated if set)
GET    /:slug?raw=1                    Raw source (password-gated if set)
POST   /:slug/unlock                   Password verification
GET    /:slug/full                     Full rendered view (markers stripped, content kept)
```

**Reminder: Axum 0.7.9 uses `:slug` syntax (colon prefix). NOT `{slug}`. This applies to ALL route parameters.**

**Existing behavior contracts (do NOT change):**
- POST returns 201 with `{ url, slug, api_url, title, description, created_at, expires_at }`
- Human view strips `<!-- @agent -->` / `<!-- @end -->` sections
- Agent view returns byte-for-byte what was POSTed
- `?raw=1` is identical to agent API endpoint (password-gated)
- Title priority: frontmatter > first H1 > slug
- Auth: admin token (constant-time) checked first, then managed tokens (argon2 verify)
- AppError enum with JSON error bodies
- CSP header: `script-src 'unsafe-inline'; style-src 'unsafe-inline'`

---

## Architecture Decisions (Settled)

These are not open for divergence. The raccoons choose HOW to implement, not WHAT to use.

| Component | Choice | Why |
|-----------|--------|-----|
| MCP server | Separate binary in the same crate (`[[bin]]`) OR feature-gated module — raccoon decides | Same repo, shared types. Must be deployable independently. |
| MCP protocol | `rmcp` crate (Rust MCP SDK) or raw JSON-RPC over stdio | MCP servers communicate via stdio JSON-RPC. Use a crate if one exists and is stable; raw impl if not. |
| Syntax highlighting | `syntect` 5.x with compiled theme sets | Battle-tested. Integrates with comrak's AST for code block detection. |
| OpenAPI spec | Hand-written YAML file in `docs/openapi.yaml` | Not generated from code. The spec IS documentation. Raccoons write it to match the actual API. |
| Webhooks | Stored in config (env var), fired async via `reqwest` | No webhook table in v0.3. One global webhook URL. Simple. |
| CLI commands | Extend existing clap derive in `cli.rs` | Same pattern as v0.2 token subcommands. |

### New Dependencies (add to Cargo.toml)

```toml
# Add these to [dependencies]:
syntect = "5"              # Syntax highlighting
```

The MCP dependency depends on approach:
- If using `rmcp`: add it
- If raw JSON-RPC: no additional dep (serde_json already present)

The raccoon decides. Document the choice.

---

## Feature 1: MCP Server Wrapper

### Problem

Claude Code agents (and other MCP-compatible clients) should be able to publish and retrieve documents via native MCP tool calls. Today they have to shell out to `curl` or the CLI binary. An MCP server wrapping twofold's API gives agents first-class access:

```
twofold.publish(markdown) -> { url, slug }
twofold.get(slug) -> markdown
twofold.list() -> [{ slug, title, created_at }]
twofold.delete(slug) -> success
```

### Specification

**MCP server is a separate binary entry point** in the same Cargo workspace. Two options (raccoon picks one):

**Option A: Separate `[[bin]]` in Cargo.toml**
```toml
[[bin]]
name = "twofold-mcp"
path = "src/mcp.rs"
```

**Option B: Subcommand of the existing binary**
```bash
twofold mcp   # starts the MCP server on stdio
```

Either is acceptable. Option B keeps a single binary (simpler deployment). Option A isolates the MCP concern.

**Transport:** stdio (stdin/stdout JSON-RPC). This is how Claude Code discovers and communicates with MCP servers. No HTTP needed — the MCP server is a LOCAL process that speaks to the twofold HTTP server.

**The MCP server is a CLIENT of the twofold HTTP API.** It does NOT access the database directly. It calls the same REST endpoints that `curl` would. This means:

1. The MCP server needs: server URL + bearer token (configured via env vars or MCP server config)
2. The MCP server is stateless — it's a translation layer between MCP tool calls and HTTP requests
3. The twofold HTTP server does NOT need to be modified to support MCP (existing API is sufficient)

**MCP Tools Exposed:**

| Tool | Parameters | Returns | Maps to |
|------|-----------|---------|---------|
| `twofold_publish` | `content` (string, required), `title` (string, optional), `slug` (string, optional) | `{ url, slug, api_url, title }` | POST /api/v1/documents |
| `twofold_get` | `slug` (string, required) | Raw markdown content | GET /api/v1/documents/:slug |
| `twofold_list` | `limit` (int, optional, default 20) | `[{ slug, title, created_at }]` | GET /api/v1/documents (new endpoint) |
| `twofold_delete` | `slug` (string, required) | `{ success: true }` | DELETE /api/v1/documents/:slug |

**New endpoint required for MCP list:**

```
GET /api/v1/documents                  List documents (bearer auth)
```

Returns JSON array of document summaries:
```json
{
  "documents": [
    { "slug": "abc123", "title": "My Report", "created_at": "2026-05-10T03:22:00Z", "expires_at": null },
    ...
  ],
  "total": 42
}
```

Query params: `?limit=20&offset=0` (pagination). Default limit: 20. Max limit: 100.

This endpoint requires bearer auth (same as POST/PUT/DELETE). It does NOT expose document content — just metadata for listing.

**MCP Server Configuration:**

```bash
# Environment variables for the MCP server process:
TWOFOLD_MCP_SERVER="http://localhost:3000"   # Twofold HTTP server URL
TWOFOLD_MCP_TOKEN="your-token"              # Bearer token for API calls
```

**MCP Server Manifest (for Claude Code `settings.json`):**

```json
{
  "mcpServers": {
    "twofold": {
      "command": "twofold",
      "args": ["mcp"],
      "env": {
        "TWOFOLD_MCP_SERVER": "http://localhost:3000",
        "TWOFOLD_MCP_TOKEN": "your-token-here"
      }
    }
  }
}
```

**`twofold_publish` tool behavior:**

1. Accept `content` parameter (the markdown body). If `title` or `slug` provided, prepend as frontmatter.
2. POST to the twofold API with the constructed markdown body.
3. Return the response JSON (url, slug, api_url, title).
4. On error: return MCP error response with the HTTP status and error message.

**Frontmatter construction in publish tool:**

If the caller provides `title` or `slug` as separate params AND the content does not already start with `---`:
```
---
title: <provided title>
slug: <provided slug>
---
<content>
```

If content already starts with `---` (has its own frontmatter), the tool does NOT inject additional frontmatter — it sends the content as-is. The caller's frontmatter wins.

---

## Feature 2: CLI Tool Improvements

### Specification

v0.2 has: `twofold serve`, `twofold publish <path|->`, `twofold token {create,list,revoke}`.

v0.3 adds:

```bash
# List published documents
twofold list [--server URL] [--token TOKEN] [--limit N]

# Delete a document by slug
twofold delete <slug> [--server URL] [--token TOKEN]

# Publish with frontmatter support from CLI flags
twofold publish <path|-> [--server URL] [--token TOKEN] [--title TITLE] [--slug SLUG] [--theme THEME] [--expiry EXPIRY]
```

**`twofold list`**

- Calls `GET /api/v1/documents` on the server (the new list endpoint from Feature 1)
- Prints a table to stdout:

```
SLUG                 TITLE                          CREATED              EXPIRES
board-q1             Board Report Q1                2026-05-10 03:22     never
expires-soon         Short-lived document           2026-05-10 04:00     2026-05-10 05:00
abc12def34           Untitled                       2026-05-09 12:15     never
```

- `--limit N`: how many to show (default: 20)
- `--server`: override default URL
- `--token`: override env var
- Exit 0 on success, 1 on failure (error to stderr)

**`twofold delete <slug>`**

- Calls `DELETE /api/v1/documents/:slug` on the server
- On 204: prints `Deleted: <slug>` to stdout
- On 404: prints error to stderr, exit 1
- On 401: prints auth error to stderr, exit 1
- `--server`: override default URL
- `--token`: override env var

**`twofold publish` improvements (frontmatter from flags):**

When `--title`, `--slug`, `--theme`, or `--expiry` flags are provided, the CLI prepends frontmatter to the content before POSTing:

```bash
echo "# My Report" | twofold publish - --title "Custom Title" --slug "my-report" --expiry "7d"
```

Becomes:
```markdown
---
title: Custom Title
slug: my-report
expiry: 7d
---
# My Report
```

Rules:
- If the source content already starts with `---` (has frontmatter), CLI flags are MERGED into the existing frontmatter (CLI flags win on conflict).
- If no flags provided, content is sent as-is (existing behavior).

---

## Feature 3: Webhooks on Publish

### Specification

When a document is created, updated, or deleted, fire a webhook to a configured URL.

**Configuration:**

```bash
TWOFOLD_WEBHOOK_URL="https://hooks.example.com/twofold"   # Optional. No webhook if unset.
TWOFOLD_WEBHOOK_SECRET="optional-hmac-secret"             # Optional. Signs payloads if set.
```

**Payload:**

```json
{
  "event": "document.created",
  "timestamp": "2026-05-10T03:22:00Z",
  "document": {
    "slug": "board-q1",
    "title": "Board Report Q1",
    "url": "http://localhost:3000/board-q1",
    "api_url": "http://localhost:3000/api/v1/documents/board-q1"
  }
}
```

**Events:**

| Event | Fires when |
|-------|-----------|
| `document.created` | POST /api/v1/documents succeeds (201) |
| `document.updated` | PUT /api/v1/documents/:slug succeeds (200) |
| `document.deleted` | DELETE /api/v1/documents/:slug succeeds (204) |

**Delivery:**

- HTTP POST to `TWOFOLD_WEBHOOK_URL`
- Content-Type: `application/json`
- If `TWOFOLD_WEBHOOK_SECRET` is set: include `X-Twofold-Signature` header with HMAC-SHA256 of the request body (hex-encoded), keyed with the secret.
- Timeout: 5 seconds
- Fire-and-forget: the webhook is dispatched asynchronously (tokio::spawn). Webhook failure does NOT fail the API response. Log errors at warn level.
- No retries in v0.3. If the webhook endpoint is down, the event is lost. Retries are a future feature.

**Signature verification (for receivers):**

```
X-Twofold-Signature: sha256=<hex(HMAC-SHA256(body, secret))>
```

The receiver computes HMAC-SHA256 of the raw body using the shared secret and compares. Standard webhook signature pattern (same as GitHub).

**Implementation location:** Add webhook dispatch as a helper in handlers.rs (or a new `webhook.rs` module). Call it after successful POST/PUT/DELETE, passing the event type and document metadata.

---

## Feature 4: Syntax Highlighting

### Specification

Code blocks in the human view should render with syntax-highlighted colors instead of plain monospace text.

**How it works:**

1. Comrak renders markdown to HTML, producing `<pre><code class="language-rust">...</code></pre>` blocks.
2. After comrak renders, post-process the HTML: find code blocks with a language class, run them through syntect, replace the content with highlighted spans.
3. Inject the syntect theme CSS into the template (once, at the top).

**OR (simpler approach):**

Use comrak's built-in syntax highlighting support via its `plugins` system or its HTML formatter hooks. Comrak 0.28+ supports custom code block rendering. Check if this exists — if so, use it. If not, post-process.

**Theme:**

- Light mode: a light syntax theme (e.g., InspiredGitHub, Solarized Light)
- Dark mode: a dark syntax theme (e.g., base16-ocean.dark, Monokai)
- The syntax theme should complement the document theme. At minimum: one light and one dark syntax palette, switched via `prefers-color-scheme` in CSS.

**Syntect integration:**

```rust
use syntect::highlighting::ThemeSet;
use syntect::html::highlighted_html_for_string;
use syntect::parsing::SyntaxSet;

// Load at startup (these are compiled into the binary):
lazy_static! {
    static ref SYNTAX_SET: SyntaxSet = SyntaxSet::load_defaults_newlines();
    static ref THEME_SET: ThemeSet = ThemeSet::load_defaults();
}
```

**Language detection:**

- From the code fence info string: ````rust`, ````python`, ````js`, etc.
- If no language specified: no highlighting (render as plain `<code>` — don't guess)
- Unknown language: fall back to plain (no error)

**Impact on templates:**

- All four themes (clean, dark, paper, minimal) gain syntax highlighting CSS
- The CSS can be a shared block injected by the renderer, or inlined per-theme
- All highlighting CSS must be inlined (no external requests — same constraint as v0.1)

**Performance:**

- Syntect loads syntax definitions and themes at process startup (one-time cost)
- Highlighting per code block is fast (~microseconds for typical blocks)
- The `SyntaxSet::load_defaults_newlines()` gives 50+ languages out of the box
- No lazy_static needed if using `once_cell` or `std::sync::OnceLock` (Rust 1.70+)

---

## Feature 5: OpenAPI Spec

### Specification

A machine-readable API description at `docs/openapi.yaml` in the repo AND served by the running server.

**File location:** `docs/openapi.yaml`

**Served at:** `GET /api/v1/openapi.yaml` — returns the YAML file with `Content-Type: application/yaml`.

Also: `GET /api/v1/openapi.json` — returns a JSON conversion of the same spec (serde_yaml -> serde_json at startup or build time). This is a convenience — some tools prefer JSON.

**The spec must document:**

- All endpoints (POST, PUT, DELETE, GET) with request/response schemas
- Authentication (Bearer token)
- Error responses (400, 401, 404, 409, 410, 413)
- Frontmatter fields (described in the POST body documentation)
- Query parameters (`?raw=1`, `?limit=`, `?offset=`)
- The list endpoint (new in v0.3)

**OpenAPI version:** 3.1.0

**The spec is hand-authored, not generated.** Write it to accurately reflect the actual API behavior. It's documentation, not code.

**New endpoint in the router:**

```rust
.route("/api/v1/openapi.yaml", get(serve_openapi_yaml))
.route("/api/v1/openapi.json", get(serve_openapi_json))
```

The YAML content can be included via `include_str!("../docs/openapi.yaml")` at compile time.

---

## New Endpoint: Document Listing

Required by Features 1 and 2.

```
GET /api/v1/documents          List documents (bearer auth)
```

**Request:**
```
GET /api/v1/documents?limit=20&offset=0
Authorization: Bearer <token>
```

**Response (200 OK):**
```json
{
  "documents": [
    {
      "slug": "board-q1",
      "title": "Board Report Q1",
      "description": "Q1 summary for the board",
      "created_at": "2026-05-10T03:22:00Z",
      "expires_at": "2026-05-17T03:22:00Z"
    }
  ],
  "total": 1,
  "limit": 20,
  "offset": 0
}
```

**Behavior:**
- Requires bearer auth (same as POST/PUT/DELETE)
- Does NOT return `raw_content` (listing is metadata only)
- Excludes expired documents from the listing
- Ordered by `created_at DESC` (newest first)
- `total` is the count of all non-expired documents (for pagination)
- Limit capped at 100; offset must be >= 0

**Database addition:**

```rust
// In db.rs:
pub fn list_documents(&self, limit: u32, offset: u32) -> Result<(Vec<DocumentSummary>, u64)> { ... }
```

```rust
pub struct DocumentSummary {
    pub slug: String,
    pub title: String,
    pub description: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
}
```

**Route registration note:** This is a GET on the same path as the POST (`/api/v1/documents`). In Axum 0.7, combine them:

```rust
.route("/api/v1/documents", post(post_document).get(list_documents))
```

---

## Storage Schema (v0.3)

**No schema changes required.** The existing v0.2 schema supports all v0.3 features. The list endpoint queries existing columns. Webhooks are stateless (config only). Syntax highlighting is render-time. The MCP server is a client.

---

## Configuration (v0.3)

### New Environment Variables

```bash
# Existing (unchanged):
TWOFOLD_TOKEN="admin-token"
TWOFOLD_BIND="127.0.0.1:3000"
TWOFOLD_DB_PATH="./twofold.db"
TWOFOLD_BASE_URL="http://localhost:3000"
TWOFOLD_MAX_SIZE="1048576"
TWOFOLD_REAPER_INTERVAL="60"
TWOFOLD_DEFAULT_THEME="clean"

# New in v0.3:
TWOFOLD_WEBHOOK_URL=""                # Optional. Webhook endpoint. No webhook if unset.
TWOFOLD_WEBHOOK_SECRET=""             # Optional. HMAC-SHA256 signing key for webhooks.

# MCP server env vars (only needed when running `twofold mcp`):
TWOFOLD_MCP_SERVER="http://localhost:3000"   # Twofold server URL
TWOFOLD_MCP_TOKEN=""                         # Bearer token (defaults to TWOFOLD_TOKEN)
```

---

## API Shape (v0.3 — Complete)

```
POST   /api/v1/documents              Create document (bearer auth, fires webhook)
GET    /api/v1/documents              List documents (bearer auth)
PUT    /api/v1/documents/:slug         Update document (bearer auth, fires webhook)
DELETE /api/v1/documents/:slug         Delete document (bearer auth, fires webhook)
GET    /api/v1/documents/:slug         Agent view (full raw markdown, no password gate)
GET    /api/v1/openapi.yaml            OpenAPI spec (YAML)
GET    /api/v1/openapi.json            OpenAPI spec (JSON)
GET    /:slug                          Human view (themed HTML, syntax-highlighted, password-gated)
GET    /:slug?raw=1                    Raw source (password-gated)
POST   /:slug/unlock                   Password verification
GET    /:slug/full                     Full rendered view
```

**Reminder: Axum 0.7.9 uses `:slug` syntax. NOT `{slug}`.**

---

## Acceptance Criteria (v0.3)

Binary pass/fail. All must pass for GREEN.

### MCP Server
- [ ] MCP server starts on stdio when invoked (`twofold mcp` or `twofold-mcp`)
- [ ] `twofold_publish` tool: accepts content, returns url + slug
- [ ] `twofold_publish` with title/slug params: prepends frontmatter correctly
- [ ] `twofold_publish` with content that already has frontmatter: sends as-is
- [ ] `twofold_get` tool: returns raw markdown for a valid slug
- [ ] `twofold_get` tool: returns error for nonexistent slug
- [ ] `twofold_list` tool: returns array of document summaries
- [ ] `twofold_delete` tool: deletes document, returns success
- [ ] MCP server handles tool errors gracefully (returns MCP error, doesn't crash)

### Document Listing Endpoint
- [ ] `GET /api/v1/documents` with auth returns JSON with documents array
- [ ] Response includes `total`, `limit`, `offset` fields
- [ ] `?limit=5` limits results to 5
- [ ] `?offset=5` skips first 5 results
- [ ] Expired documents are NOT included in listing
- [ ] Documents ordered by created_at DESC
- [ ] No `raw_content` field in listing response
- [ ] Without auth: 401

### CLI Improvements
- [ ] `twofold list` prints document table to stdout
- [ ] `twofold list --limit 5` limits output
- [ ] `twofold delete <slug>` deletes and prints confirmation
- [ ] `twofold delete <nonexistent>` exits 1 with error
- [ ] `twofold publish --title "X" --slug "y"` prepends frontmatter
- [ ] `twofold publish` with existing frontmatter + flags: flags merged into frontmatter
- [ ] All CLI commands respect `--server` and `--token` overrides

### Webhooks
- [ ] With `TWOFOLD_WEBHOOK_URL` set: POST fires webhook on document create
- [ ] PUT fires webhook with `document.updated` event
- [ ] DELETE fires webhook with `document.deleted` event
- [ ] Webhook payload contains event, timestamp, document metadata
- [ ] With `TWOFOLD_WEBHOOK_SECRET` set: `X-Twofold-Signature` header present and correct
- [ ] Without secret: no signature header
- [ ] Webhook failure does NOT fail the API response (fire-and-forget)
- [ ] Without `TWOFOLD_WEBHOOK_URL`: no webhook fired, no error
- [ ] Webhook timeout: does not block handler for more than 5 seconds

### Syntax Highlighting
- [ ] Code block with language (````rust`) renders with colored syntax spans
- [ ] Code block without language renders as plain monospace (no guessing)
- [ ] Unknown language renders as plain (no error)
- [ ] Highlighting works in all four themes (clean, dark, paper, minimal)
- [ ] Dark theme uses a dark syntax palette
- [ ] Light themes use a light syntax palette
- [ ] All highlighting CSS is inlined (no external requests)
- [ ] Documents without code blocks render identically to v0.2

### OpenAPI Spec
- [ ] `GET /api/v1/openapi.yaml` returns valid OpenAPI 3.1 YAML
- [ ] `GET /api/v1/openapi.json` returns valid OpenAPI 3.1 JSON
- [ ] Spec documents all endpoints with request/response schemas
- [ ] Spec documents auth (Bearer token)
- [ ] Spec documents error responses
- [ ] `docs/openapi.yaml` exists in the repo

### Backward Compatibility
- [ ] All v0.1 curl tests still pass
- [ ] All v0.2 curl tests still pass
- [ ] Documents published without v0.3 features render correctly
- [ ] Existing env vars work unchanged

---

## Test Cases (v0.3) — Curl Commands

Run against:
```bash
TWOFOLD_TOKEN="test-token-123" TWOFOLD_BIND="127.0.0.1:3000" TWOFOLD_WEBHOOK_URL="http://localhost:9999/hook" twofold serve
```

### Test 1: List documents (empty)

```bash
curl -s -X GET http://localhost:3000/api/v1/documents \
  -H "Authorization: Bearer test-token-123"
```

**Expected:** HTTP 200. `{ "documents": [], "total": 0, "limit": 20, "offset": 0 }`

### Test 2: List documents (with content)

```bash
# Publish two documents first
curl -s -X POST http://localhost:3000/api/v1/documents \
  -H "Authorization: Bearer test-token-123" \
  -H "Content-Type: text/markdown" \
  -d '---
slug: list-test-one
---
# First Document' > /dev/null

curl -s -X POST http://localhost:3000/api/v1/documents \
  -H "Authorization: Bearer test-token-123" \
  -H "Content-Type: text/markdown" \
  -d '---
slug: list-test-two
---
# Second Document' > /dev/null

# List
curl -s -X GET http://localhost:3000/api/v1/documents \
  -H "Authorization: Bearer test-token-123" | jq '.total'
```

**Expected:** `total` >= 2. Documents array contains entries with slug, title, created_at. No raw_content field.

### Test 3: List with pagination

```bash
curl -s -X GET "http://localhost:3000/api/v1/documents?limit=1&offset=0" \
  -H "Authorization: Bearer test-token-123" | jq '.documents | length'
```

**Expected:** 1 (limited to 1 result).

### Test 4: List requires auth

```bash
curl -s -o /dev/null -w "%{http_code}" -X GET http://localhost:3000/api/v1/documents
```

**Expected:** HTTP 401.

### Test 5: CLI list

```bash
twofold list --server http://localhost:3000 --token test-token-123
```

**Expected:** Prints table with SLUG, TITLE, CREATED, EXPIRES columns. Contains "list-test-one" and "list-test-two".

### Test 6: CLI delete

```bash
twofold delete list-test-one --server http://localhost:3000 --token test-token-123
echo $?
```

**Expected:** Prints "Deleted: list-test-one". Exit code 0.

### Test 7: CLI delete nonexistent

```bash
twofold delete nonexistent-slug-xyz --server http://localhost:3000 --token test-token-123
echo $?
```

**Expected:** Error to stderr. Exit code 1.

### Test 8: CLI publish with frontmatter flags

```bash
echo "Content without frontmatter." | twofold publish - \
  --server http://localhost:3000 \
  --token test-token-123 \
  --title "Flag Title" \
  --slug "flag-test"
```

**Expected:** Prints URL. The URL contains "flag-test". Fetching agent view shows frontmatter with `title: Flag Title` and `slug: flag-test`.

### Test 9: Syntax highlighting renders

```bash
SLUG=$(curl -s -X POST http://localhost:3000/api/v1/documents \
  -H "Authorization: Bearer test-token-123" \
  -H "Content-Type: text/markdown" \
  -d '# Code Example

```rust
fn main() {
    println!("Hello, world!");
}
```

Regular text after.' | jq -r '.slug')

curl -s http://localhost:3000/$SLUG | grep -c "span"
```

**Expected:** HTTP 201. The human view HTML contains `<span` elements (syntax highlighting spans). The grep count should be > 0.

### Test 10: No highlighting without language

```bash
SLUG=$(curl -s -X POST http://localhost:3000/api/v1/documents \
  -H "Authorization: Bearer test-token-123" \
  -H "Content-Type: text/markdown" \
  -d '# Plain Code

```
just plain text in a code block
no language specified
```

Done.' | jq -r '.slug')

curl -s http://localhost:3000/$SLUG
```

**Expected:** Code block renders as `<pre><code>` without syntect highlight spans (no `style=` attributes on spans inside the code block, or no inner spans at all).

### Test 11: Webhook fires on create

```bash
# Start a webhook listener (in another terminal):
# nc -l 9999 > /tmp/webhook-payload.txt &
# OR use a request bin

curl -s -X POST http://localhost:3000/api/v1/documents \
  -H "Authorization: Bearer test-token-123" \
  -H "Content-Type: text/markdown" \
  -d '---
slug: webhook-test
---
# Webhook Test Document'
```

**Expected:** The webhook URL receives a POST with JSON body containing `"event": "document.created"`, `"document": { "slug": "webhook-test", ... }`.

### Test 12: Webhook fires on delete

```bash
curl -s -X DELETE http://localhost:3000/api/v1/documents/webhook-test \
  -H "Authorization: Bearer test-token-123"
```

**Expected:** HTTP 204. Webhook URL receives POST with `"event": "document.deleted"`.

### Test 13: Webhook signature

```bash
# With TWOFOLD_WEBHOOK_SECRET="test-secret" set on the server:
# The webhook POST should include:
# X-Twofold-Signature: sha256=<hex(HMAC-SHA256(body, "test-secret"))>
```

**Expected:** Header present. Signature matches when verified with the shared secret.

### Test 14: OpenAPI YAML endpoint

```bash
curl -s http://localhost:3000/api/v1/openapi.yaml | head -5
```

**Expected:** Returns YAML starting with `openapi: "3.1.0"` or similar. Content-Type includes `yaml`.

### Test 15: OpenAPI JSON endpoint

```bash
curl -s http://localhost:3000/api/v1/openapi.json | jq '.openapi'
```

**Expected:** Returns `"3.1.0"`. Valid JSON.

### Test 16: MCP server starts

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | twofold mcp 2>/dev/null | head -1 | jq '.result.serverInfo.name'
```

**Expected:** Returns `"twofold"` (or similar). The MCP server responds to the initialize handshake.

### Test 17: MCP publish tool

```bash
# After initialize + initialized handshake:
echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"twofold_publish","arguments":{"content":"# MCP Test\n\nPublished via MCP."}}}' | twofold mcp 2>/dev/null | jq '.result'
```

**Expected:** Response contains `url` and `slug` in the tool result.

### Test 18: Backward compatibility — v0.2 document

```bash
# Publish a basic v0.1-style document (no frontmatter, no v0.3 features)
curl -s -X POST http://localhost:3000/api/v1/documents \
  -H "Authorization: Bearer test-token-123" \
  -H "Content-Type: text/markdown" \
  -d '# Old School

Human-visible content.

<!-- @agent -->
Agent-only data here.
<!-- @end -->

Still human-visible.'
```

**Expected:** HTTP 201. Human view shows "Human-visible content." and "Still human-visible." Does NOT show "Agent-only data here." All v0.1/v0.2 behavior preserved.

---

## What Is NOT in Scope (v0.3)

Do NOT build any of these. They are explicitly deferred.

- **View counters / analytics** — originally planned for v0.3 but deferred to v1.0. Not enough value yet.
- **Webhook retry / dead letter queue** — fire-and-forget only. Retries are a v1.0 concern.
- **Webhook per-document configuration** — one global webhook URL via env var. Per-document webhooks are future.
- **Multiple webhook URLs** — one URL only in v0.3.
- **MCP resources / prompts** — only MCP tools. Resources and prompts are future.
- **AST-aware marker parsing** — still line-based. Still a known limitation.
- **Config TOML file** — env vars only.
- **Custom theme directory** — built-in themes only.
- **Rate limiting** — reverse proxy layer.
- **Encryption at rest** — v1.0.
- **Nix package** — v1.0.
- **GitHub Actions CI** — v1.0.
- **Documentation / README rewrite** — v1.0.
- **Token scoping / permissions** — all tokens are full-access.
- **Accept header content negotiation** — URL path determines view.
- **HTTPS / TLS** — reverse proxy handles this.
- **Graceful shutdown** — nice-to-have, not required.

---

## Constraints

- **Language:** Rust, edition 2021
- **Minimum Rust version:** stable
- **Binary name:** `twofold` (MCP may be a subcommand OR separate `twofold-mcp` binary — raccoon decides)
- **Axum version:** 0.7.9. Route params use `:param` (colon prefix). NOT `{param}`.
- **No unsafe code** unless justified in a comment
- **No `.unwrap()` on user input paths** — proper error handling
- **Startup must not panic on missing optional env vars** — defaults or skip
- **Single crate** — no workspace, no sub-crates. One `Cargo.toml`, one `src/` directory. Multiple `[[bin]]` entries are fine.
- **Module structure is open** — raccoons organize `src/` however they want. New modules (e.g., `webhook.rs`, `mcp.rs`, `highlight.rs`) are encouraged.
- **Backward compatible** — all v0.1 and v0.2 curl tests must still pass

---

## Notes for DJ

The raccoons compete on the FULL v0.3. Each raccoon builds all 5 features independently.

**IMPORTANT: Raccoons work directly in the twofold repo using `--repo ~/projects/twofold`.** Do not build in the scrapyard task directory.

**What to evaluate divergence on:**
- MCP implementation approach (subcommand vs separate binary, rmcp crate vs raw JSON-RPC)
- Syntect integration strategy (post-process HTML vs comrak plugin hooks vs custom renderer)
- Webhook module design (inline in handlers vs separate module, how they handle async fire-and-forget)
- OpenAPI spec quality (completeness, accuracy, readability)
- CLI ergonomics (table formatting, error messages, flag composition)
- How they handle the GET/POST same-path routing for `/api/v1/documents`
- Whether the list endpoint filters expired docs at query level (SQL WHERE) or application level

**Assembly priority:**
1. Does it compile? (`cargo build`)
2. Do the v0.1 and v0.2 curl tests still pass? (backward compatibility)
3. Do the v0.3 curl tests pass? (tests 1-18)
4. Code clarity — can Kade extend this to v1.0 without rewriting?
5. MCP server correctness — does it actually work with Claude Code?
6. Syntax highlighting quality — does code look good?

**GREEN = compiles + backward compat + tests 1-10 pass.** Tests 11-18 (webhooks, OpenAPI, MCP) are bonus.

**IMPORTANT for DJ: Update CLAUDE.md as architecture decisions are made during assembly.** When you pick an approach (e.g., "MCP is a subcommand not a separate binary," "syntect uses post-process strategy," "webhooks are in a separate module"), add those decisions to the project's CLAUDE.md. The CLAUDE.md is the living architecture record — don't let decisions evaporate.

---

## Edge Cases the Raccoons Must Handle

| Case | Expected Behavior |
|------|-------------------|
| List endpoint with zero documents | Returns `{ "documents": [], "total": 0, "limit": 20, "offset": 0 }` |
| List endpoint with offset > total | Returns empty documents array, total still accurate |
| List endpoint with limit > 100 | Cap at 100, don't error |
| List endpoint with negative offset | Treat as 0 |
| CLI `--title` flag with quotes/special chars | YAML-safe escaping in generated frontmatter |
| CLI publish with flags + existing frontmatter | Merge: CLI flags override conflicting frontmatter fields |
| Webhook URL that returns 500 | Log warning, don't retry, API response unaffected |
| Webhook URL that times out | 5s timeout, log warning, API response unaffected |
| Webhook URL unset | No webhook behavior at all, no error logs |
| MCP server with unreachable twofold server | Return MCP error response, don't crash |
| MCP publish with empty content | Return MCP error (maps to 400 from API) |
| Syntect with extremely long code block | Should still render (syntect handles large inputs). If somehow too slow, consider a size cap. |
| Code fence with language alias (`js` vs `javascript`) | Syntect handles common aliases. If not found, render plain. |
| OpenAPI endpoint with no auth | Return the spec (OpenAPI is public documentation) |
| Multiple code blocks with different languages | Each highlighted independently with correct syntax |
| Syntax highlighting in password-protected documents | Highlighting applies after password verification (same as all rendering) |

---

*Five features, all composable, all backward-compatible. The MCP server makes twofold a first-class tool for agents. The webhooks make it a node in a pipeline. The CLI makes it scriptable. The highlighting makes it pretty. The OpenAPI makes it discoverable. Build it.*
