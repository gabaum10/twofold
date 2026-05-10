# Raccoon Work Order: Dual-Layer Share Service v0.1

*Compete mode. Six raccoons. DJ picks the best parts.*

---

## Problem Statement

Build a self-hosted markdown share service that renders two views from one document. The author writes markdown with HTML comment markers (`<!-- @agent -->` / `<!-- @end -->`). The service stores the full document and serves two views:

- **Human view:** Themed HTML page with agent-only sections stripped out. Pretty. Readable. Something you'd send to a non-technical person.
- **Agent view:** Full raw markdown including all agent sections. What you'd pipe into another model.

One binary. Rust. No runtime dependencies. POST markdown in, get a URL out. That URL serves humans styled HTML. The API endpoint serves agents raw markdown.

This is not a paste bin. It is a render target for models that already write both layers but have nowhere to serve them separately. The difference from Cloudflare/Vercel content negotiation: they convert FORMAT (same content, HTML vs markdown). We serve DIFFERENT CONTENT to different consumers (authored summary vs full corpus).

---

## Architecture Decisions (Settled)

These are not open for divergence. The raccoons choose HOW to implement, not WHAT to use.

| Component | Choice | Why |
|-----------|--------|-----|
| HTTP framework | Axum 0.7 | Tokio-native, composable |
| Markdown rendering | Comrak 0.28 | CommonMark + GFM, battle-tested |
| Storage | SQLite via rusqlite 0.31 (bundled) | Single file, no external deps |
| Templating | Askama 0.12 | Compile-time, zero-alloc, templates baked into binary |
| CLI | Clap 4 (derive) | Standard Rust CLI |
| IDs | nanoid 0.4 | URL-safe, short slugs |
| Auth | Single bearer token via env var | No token management in v0.1 |
| Hashing | argon2 0.5 | For future token hashing. NOT needed in v0.1 (env var compare). |

### Cargo.toml (v0.1 minimal)

```toml
[package]
name = "sharesvc"
version = "0.1.0"
edition = "2021"

[dependencies]
axum = "0.7"
tokio = { version = "1", features = ["full"] }
comrak = "0.28"
rusqlite = { version = "0.31", features = ["bundled"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
clap = { version = "4", features = ["derive"] }
askama = "0.12"
tower-http = { version = "0.5", features = ["cors", "trace"] }
tracing = "0.1"
tracing-subscriber = "0.3"
nanoid = "0.4"
```

---

## API Shape (v0.1)

### Endpoints

```
POST   /api/v1/documents              Create document
GET    /:slug                          Human view (rendered HTML, markers stripped)
GET    /api/v1/documents/:slug         Agent view (full raw markdown)
GET    /:slug?raw=1                    Raw source markdown (full, including markers)
```

### POST /api/v1/documents

**Request:**
```
POST /api/v1/documents
Authorization: Bearer <token>
Content-Type: text/markdown

# My Document

Human-visible summary.

<!-- @agent -->
## Agent Detail
Full analysis here.
<!-- @end -->
```

**Response (201 Created):**
```json
{
  "url": "http://localhost:3000/abc123",
  "slug": "abc123",
  "api_url": "http://localhost:3000/api/v1/documents/abc123",
  "title": "My Document",
  "created_at": "2026-05-10T03:22:00Z"
}
```

**Errors:**
- 401: Missing or invalid bearer token
- 413: Body exceeds max size (default 1MB, configurable)
- 400: Empty body

### GET /:slug (Human View)

Returns HTML page. Themed. Agent sections stripped. Content-Type: `text/html`.

**Errors:**
- 404: Slug not found

### GET /api/v1/documents/:slug (Agent View)

Returns full raw markdown (the entire source document as stored, NOT rendered to HTML). Content-Type: `text/markdown; charset=utf-8`.

This is the agent consumption path. Full fidelity. Markers included.

**Errors:**
- 404: Slug not found

### GET /:slug?raw=1 (Raw Source)

**Semantics (decided):** Returns the FULL source markdown, identical to `/api/v1/documents/:slug`. This is a convenience shortcut on the human URL for people who want to `curl` the raw source without constructing the API path.

Content-Type: `text/markdown; charset=utf-8`.

`?raw=1` is NOT "human-view-as-markdown." It is the same full source that the agent API returns.

---

## Title Extraction (Decided)

v0.1 has no frontmatter parsing. Title is extracted by this priority:

1. **First H1 heading** in the document (first line matching `^# .+`). Strip the `# ` prefix.
2. **Fallback:** Use the generated slug as the title.

The H1 extraction is a simple regex on the raw source (before splitting). It does NOT need to be AST-aware. First match wins.

```
^# (.+)$    (multiline, first match)
```

If the first H1 is inside an agent section, it's still the title. Title extraction happens BEFORE the split.

---

## Marker Format and Parser Specification

### The Markers

```
<!-- @agent -->
```
Opens an agent-only section. Everything after this line (exclusive) is hidden from the human view.

```
<!-- @end -->
```
Closes the agent-only section. Content after this line is visible to humans again.

Whitespace tolerance: the parser must handle `<!--@agent-->`, `<!-- @agent -->`, `<!--  @agent  -->` (variable internal spacing). Regex: `^\s*<!--\s*@agent\s*-->\s*$` and `^\s*<!--\s*@end\s*-->\s*$` (line-level match).

### Parser Strategy (Decided): Line-Based Regex

NOT AST-aware. The parser operates on lines of text, not on a parsed markdown tree. This is deliberate: it's simpler (~20 lines), faster, and the edge cases are documented rather than handled.

**Algorithm:**
```
1. Split source into lines
2. Walk lines. Track boolean `in_agent_section = false`
3. If line matches open marker: set in_agent_section = true, skip line
4. If line matches close marker: set in_agent_section = false, skip line
5. If in_agent_section: include in agent corpus only
6. If not in_agent_section: include in both corpora
7. Human corpus = lines from step 6, joined
8. Agent corpus = ALL original lines (the raw source, unmodified)
```

Wait — important distinction. The agent view returns the RAW SOURCE. It does NOT strip markers. It returns exactly what was POSTed. The human view strips markers AND agent-only content.

So the splitter only needs to produce the HUMAN corpus. The agent path just returns `raw_content` from the database verbatim.

### Edge Cases (Defined Behavior)

| Case | Behavior | Rationale |
|------|----------|-----------|
| **Nested markers** (`@agent` inside `@agent`) | Ignored. The inner `<!-- @agent -->` is treated as content inside the already-open section. Only the FIRST `<!-- @end -->` after an open closes it. | No nesting. Flat structure. Simple parser. |
| **Markers inside fenced code blocks** | Stripped anyway. The parser is line-based, not AST-aware. A marker inside a code block WILL be treated as a real marker. | Known limitation. Document it. The fix (AST-aware parsing) is a v0.2 concern. Workaround: authors indent markers in code blocks with a leading space (breaks the `^\s*` regex... actually no it doesn't). Real workaround: use a different comment format in examples, e.g., `<!-- @@agent -->` or escape it. |
| **Markers inside HTML blocks** | Same as code blocks — parser doesn't know the difference. Line-level regex fires regardless. | Known limitation. Same v0.2 fix. |
| **Unclosed `<!-- @agent -->`** | Everything from the open marker to EOF is agent-only. The human view loses all content after the unclosed marker. Server logs a warning: `"Unclosed @agent marker in document {slug}"`. | Fail-safe: when in doubt, hide from humans rather than leak agent content to them. Log the warning so the author can fix it. |
| **`<!-- @end -->` without preceding open** | Ignored. Treated as a regular HTML comment (invisible in rendered markdown anyway). No error. | Defensive: orphan close markers are harmless. |
| **Empty agent section** (`@agent` immediately followed by `@end`) | Valid. Produces no additional agent content. Human view unaffected. | Don't special-case emptiness. |
| **Multiple agent sections** | Fully supported. Each open/close pair is independent. Content between pairs is human-visible. | The format is designed for interleaved content. |

### Important: Code Block Limitation Workaround

If an author needs to SHOW the marker format in a document (e.g., documentation about the service itself), they cannot use the literal markers inside fenced code blocks without them being parsed. Workaround for v0.1: authors escape by using a zero-width space or by not placing literal markers on their own line:

```
The marker format is: `<!-- @agent -->` (inline code, not on its own line — safe)
```

A line-level regex that requires the marker to be the ONLY content on the line (after stripping whitespace) naturally protects inline code references like `` `<!-- @agent -->` `` because those have surrounding backticks on the same line.

**Refined regex:** `^\s*<!--\s*@agent\s*-->\s*$` — the `^` and `$` anchors plus no other content requirement means `` `<!-- @agent -->` `` on a line does NOT match (the backticks are additional content).

For fenced code blocks where the marker IS alone on a line — that's the known limitation. v0.2 fixes it with AST-aware parsing.

---

## Storage Schema (v0.1)

```sql
CREATE TABLE IF NOT EXISTS documents (
    id          TEXT PRIMARY KEY,       -- nanoid, same as slug in v0.1
    slug        TEXT UNIQUE NOT NULL,   -- URL path component
    title       TEXT NOT NULL,          -- extracted from first H1 or slug
    raw_content TEXT NOT NULL,          -- full source markdown as received
    created_at  TEXT NOT NULL,          -- ISO 8601 UTC
    updated_at  TEXT NOT NULL           -- ISO 8601 UTC
);

CREATE INDEX IF NOT EXISTS idx_documents_slug ON documents(slug);
```

v0.1 does NOT have: theme column, password column, unlisted column, expires_at column, tokens table. Single bearer token is compared against an env var, not stored.

---

## Configuration

### Environment Variables (v0.1)

```bash
SHARESVC_TOKEN="your-secret-bearer-token"   # Required. Publish auth.
SHARESVC_BIND="127.0.0.1:3000"              # Optional. Default: 127.0.0.1:3000
SHARESVC_DB_PATH="./sharesvc.db"            # Optional. Default: ./sharesvc.db
SHARESVC_BASE_URL="http://localhost:3000"   # Optional. Used in POST response URLs.
SHARESVC_MAX_SIZE="1048576"                 # Optional. Max body bytes. Default: 1MB.
```

No config file in v0.1. Env vars only. Config TOML is a v0.2 feature.

---

## CLI Interface (v0.1)

```bash
# Start the server
sharesvc serve

# Publish from file
sharesvc publish ./report.md

# Publish from stdin
cat report.md | sharesvc publish -

# Publish with explicit server
sharesvc publish ./report.md --server https://share.example.com --token $TOKEN
```

### CLI Subcommands

**`sharesvc serve`**
- Starts the HTTP server
- Reads env vars for configuration
- Creates SQLite database if not exists
- Prints bind address to stdout on start

**`sharesvc publish <path|->`**
- `<path>`: Read file at path
- `-`: Read from stdin
- `--server <url>`: Target server URL (default: `http://localhost:3000`)
- `--token <token>`: Bearer token (default: reads `SHARESVC_TOKEN` env var)
- Prints the resulting URL to stdout on success
- Exit code 0 on success, 1 on failure (with error to stderr)

---

## Template (v0.1 — Single Theme)

One HTML template compiled into the binary via Askama. The theme is "clean" — Pico CSS (classless) with minor overrides for readability.

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ title }}</title>
    <style>
    /* Pico CSS (minimal subset or full, raccoon decides) */
    /* OR: a hand-rolled classless stylesheet */
    /* Requirement: readable, responsive, dark/light via prefers-color-scheme */
    </style>
</head>
<body>
    <main>
        <article>
            {{ content }}
        </article>
    </main>
    <footer>
        <small>shared via sharesvc</small>
    </footer>
</body>
</html>
```

Requirements for the template:
- Responsive (mobile + desktop)
- Respects `prefers-color-scheme` (dark/light)
- Readable typography (sensible line length, font size, spacing)
- CSS is inlined in the template (no external requests)
- The rendered page makes zero external network requests

---

## Phased Build Plan (Full Context)

### v0.1 — This Work Order (Raccoon Build)

Everything above. The raccoons compete on this. One weekend of focused Rust.

**Ships:** POST to publish, GET human view, GET agent view, GET raw, CLI serve + publish, SQLite storage, single theme, single bearer token.

### v0.2 — Polish (Kade)

- Frontmatter parsing (title, slug, theme, expiry override H1 extraction)
- Custom slugs via frontmatter `slug:` field
- Expiry / TTL support (background reaper, tokio interval)
- Password protection per document (argon2)
- 3-4 built-in themes + theme selection via frontmatter
- Token management CLI (create, list, revoke) with tokens table
- PUT /api/v1/documents/:slug (update)
- DELETE /api/v1/documents/:slug
- Config TOML file support
- Docker image + binary releases (linux amd64/arm64, macOS aarch64)
- AST-aware marker parsing (fixes the code-block limitation)

### v0.3 — Integration (Kade)

- MCP server wrapper (publish/retrieve as MCP tools)
- CLI tool improvements (sharesvc ls, sharesvc rm)
- Webhook on publish (POST to configured URL)
- Syntax highlighting (syntect, compiled themes)
- OpenAPI spec
- View counters (human_views, agent_views, raw_views per document)

### v1.0 — Release

- Documentation, examples, screenshots
- Nix package
- GitHub Actions CI
- Custom theme directory (bring your own CSS)
- Encryption at rest
- Analytics dashboard
- Signed documents (Ed25519)

---

## Acceptance Criteria (v0.1)

Binary pass/fail. If any of these fail, the build is RED.

### Server Startup
- [ ] `sharesvc serve` starts and binds to configured address
- [ ] Server creates SQLite database file if not present
- [ ] Server prints bind address to stdout
- [ ] Server responds to requests within 1 second of startup

### Publish (POST)
- [ ] POST with valid token returns 201 with JSON body containing `url`, `slug`, `api_url`, `title`, `created_at`
- [ ] POST without token returns 401
- [ ] POST with wrong token returns 401
- [ ] POST with empty body returns 400
- [ ] POST with body exceeding max size returns 413
- [ ] Generated slug is URL-safe (alphanumeric + hyphen)
- [ ] Title is extracted from first H1 heading
- [ ] Title falls back to slug when no H1 present
- [ ] Returned `url` is valid and serves the human view
- [ ] Returned `api_url` is valid and serves the agent view

### Human View (GET /:slug)
- [ ] Returns HTML with Content-Type `text/html`
- [ ] Agent-only sections (`<!-- @agent -->` to `<!-- @end -->`) are NOT present in the HTML
- [ ] Human-visible content IS rendered as HTML (markdown converted)
- [ ] The title appears in the `<title>` element
- [ ] The page is styled (not raw unstyled HTML)
- [ ] Returns 404 for nonexistent slugs

### Agent View (GET /api/v1/documents/:slug)
- [ ] Returns raw markdown with Content-Type containing `text/markdown`
- [ ] Response body is the EXACT source markdown that was POSTed (byte-for-byte)
- [ ] Agent sections and markers are present in the response
- [ ] Returns 404 for nonexistent slugs

### Raw View (GET /:slug?raw=1)
- [ ] Returns raw markdown with Content-Type containing `text/markdown`
- [ ] Response body is identical to the agent view endpoint
- [ ] Returns 404 for nonexistent slugs

### CLI Publish
- [ ] `sharesvc publish ./file.md` publishes the file and prints the URL
- [ ] `cat file.md | sharesvc publish -` publishes from stdin and prints the URL
- [ ] `sharesvc publish` with invalid token exits with code 1 and error message to stderr
- [ ] `--server` flag overrides default URL
- [ ] `--token` flag overrides env var

### Marker Parsing
- [ ] Single agent section is stripped from human view
- [ ] Multiple agent sections are independently stripped
- [ ] Content between agent sections is human-visible
- [ ] Unclosed marker hides everything after it from human view
- [ ] Orphan `<!-- @end -->` is ignored (no error)
- [ ] Nested `<!-- @agent -->` inside an open section is treated as content
- [ ] Markers with varied spacing (`<!--@agent-->`, `<!--  @agent  -->`) are recognized
- [ ] Markers that are not alone on their line (e.g., `` `<!-- @agent -->` ``) are NOT parsed as markers

---

## Test Cases (v0.1) — Curl Commands

These are the literal commands that prove the build works. Run against a server started with:

```bash
SHARESVC_TOKEN="test-token-123" SHARESVC_BIND="127.0.0.1:3000" sharesvc serve
```

### Test 1: Publish a basic document

```bash
curl -s -X POST http://localhost:3000/api/v1/documents \
  -H "Authorization: Bearer test-token-123" \
  -H "Content-Type: text/markdown" \
  -d '# Hello World

This is visible to humans.

<!-- @agent -->
## Secret Agent Data
This is only for agents.
<!-- @end -->

Back to human-visible content.'
```

**Expected:** HTTP 201. JSON response with `url`, `slug`, `api_url`, `title` (= "Hello World"), `created_at`.

### Test 2: Publish without auth

```bash
curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:3000/api/v1/documents \
  -H "Content-Type: text/markdown" \
  -d '# No Auth'
```

**Expected:** HTTP 401.

### Test 3: Publish with wrong token

```bash
curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:3000/api/v1/documents \
  -H "Authorization: Bearer wrong-token" \
  -H "Content-Type: text/markdown" \
  -d '# Wrong Token'
```

**Expected:** HTTP 401.

### Test 4: Publish empty body

```bash
curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:3000/api/v1/documents \
  -H "Authorization: Bearer test-token-123" \
  -H "Content-Type: text/markdown" \
  -d ''
```

**Expected:** HTTP 400.

### Test 5: Human view strips agent sections

```bash
# First, publish (capture slug from response)
SLUG=$(curl -s -X POST http://localhost:3000/api/v1/documents \
  -H "Authorization: Bearer test-token-123" \
  -H "Content-Type: text/markdown" \
  -d '# Report

Summary for humans.

<!-- @agent -->
## Detailed Numbers
Revenue: $4.2M
Churn: 3.1%
<!-- @end -->

Closing paragraph.' | jq -r '.slug')

# Then, fetch human view
curl -s http://localhost:3000/$SLUG
```

**Expected:** HTML response. Contains "Summary for humans." and "Closing paragraph." Does NOT contain "Detailed Numbers", "Revenue: $4.2M", or "Churn: 3.1%". Does NOT contain `<!-- @agent -->` or `<!-- @end -->`.

### Test 6: Agent view returns full source

```bash
curl -s http://localhost:3000/api/v1/documents/$SLUG
```

**Expected:** Raw markdown. Contains ALL content: "Summary for humans.", the markers, "Detailed Numbers", "Revenue: $4.2M", "Closing paragraph." Content-Type header contains `text/markdown`.

### Test 7: Raw view equals agent view

```bash
# These two should be byte-identical
diff <(curl -s http://localhost:3000/$SLUG?raw=1) \
     <(curl -s http://localhost:3000/api/v1/documents/$SLUG)
```

**Expected:** No diff. Exit code 0.

### Test 8: 404 on nonexistent slug

```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/nonexistent-slug-xyz
```

**Expected:** HTTP 404.

### Test 9: Multiple agent sections

```bash
SLUG=$(curl -s -X POST http://localhost:3000/api/v1/documents \
  -H "Authorization: Bearer test-token-123" \
  -H "Content-Type: text/markdown" \
  -d '# Multi Section

Intro.

<!-- @agent -->
Agent block 1.
<!-- @end -->

Middle human content.

<!-- @agent -->
Agent block 2.
<!-- @end -->

Outro.' | jq -r '.slug')

curl -s http://localhost:3000/$SLUG
```

**Expected:** HTML contains "Intro.", "Middle human content.", "Outro." Does NOT contain "Agent block 1." or "Agent block 2."

### Test 10: Unclosed marker hides remainder

```bash
SLUG=$(curl -s -X POST http://localhost:3000/api/v1/documents \
  -H "Authorization: Bearer test-token-123" \
  -H "Content-Type: text/markdown" \
  -d '# Unclosed

Visible part.

<!-- @agent -->
This and everything below is agent-only.
No end marker ever comes.' | jq -r '.slug')

curl -s http://localhost:3000/$SLUG
```

**Expected:** HTML contains "Visible part." Does NOT contain "This and everything below" or "No end marker ever comes."

### Test 11: Title extraction from H1

```bash
RESPONSE=$(curl -s -X POST http://localhost:3000/api/v1/documents \
  -H "Authorization: Bearer test-token-123" \
  -H "Content-Type: text/markdown" \
  -d '# My Excellent Report

Content here.')

echo $RESPONSE | jq -r '.title'
```

**Expected:** "My Excellent Report"

### Test 12: Title fallback when no H1

```bash
RESPONSE=$(curl -s -X POST http://localhost:3000/api/v1/documents \
  -H "Authorization: Bearer test-token-123" \
  -H "Content-Type: text/markdown" \
  -d 'No heading in this document. Just paragraphs.')

TITLE=$(echo $RESPONSE | jq -r '.title')
SLUG=$(echo $RESPONSE | jq -r '.slug')

# Title should equal slug (the fallback)
[ "$TITLE" = "$SLUG" ] && echo "PASS" || echo "FAIL"
```

**Expected:** PASS (title equals slug).

### Test 13: Marker spacing tolerance

```bash
SLUG=$(curl -s -X POST http://localhost:3000/api/v1/documents \
  -H "Authorization: Bearer test-token-123" \
  -H "Content-Type: text/markdown" \
  -d '# Spacing Test

Before.

<!--@agent-->
Tight spacing hidden.
<!--@end-->

Middle.

<!--  @agent  -->
Loose spacing hidden.
<!--  @end  -->

After.' | jq -r '.slug')

curl -s http://localhost:3000/$SLUG
```

**Expected:** HTML contains "Before.", "Middle.", "After." Does NOT contain "Tight spacing hidden." or "Loose spacing hidden."

### Test 14: Inline marker references NOT parsed

```bash
SLUG=$(curl -s -X POST http://localhost:3000/api/v1/documents \
  -H "Authorization: Bearer test-token-123" \
  -H "Content-Type: text/markdown" \
  -d '# Documentation

Use the marker format: `<!-- @agent -->` to start a section.

This line should remain visible.' | jq -r '.slug')

curl -s http://localhost:3000/$SLUG
```

**Expected:** HTML contains BOTH "Use the marker format:" AND "This line should remain visible." The inline code reference does not trigger the parser.

### Test 15: CLI publish from stdin

```bash
echo '# Stdin Test

Published via pipe.' | sharesvc publish - --server http://localhost:3000 --token test-token-123
```

**Expected:** Prints a URL to stdout. That URL serves the human view when fetched.

---

## What Is NOT in Scope (v0.1)

Do NOT build any of these. They are explicitly deferred.

- **Frontmatter parsing** — no YAML frontmatter handling. Title comes from H1 only.
- **Custom slugs** — all slugs are auto-generated (nanoid). No user-chosen slugs.
- **Themes / theme selection** — one hardcoded theme. No config for choosing themes.
- **Expiry / TTL** — documents persist forever. No reaper.
- **Password protection** — all documents are public once created.
- **PUT / DELETE endpoints** — create-only. No updates, no deletes.
- **Token management** — one token via env var. No create/list/revoke.
- **Rate limiting** — none.
- **Access logging / view counters** — no analytics.
- **Docker image / cross-compilation** — raccoons build for their own platform only.
- **Config file (TOML)** — env vars only.
- **Syntax highlighting** — plain code blocks, no syntect.
- **Accept header negotiation** — the URL path determines the view. No content negotiation via headers.
- **OpenAPI spec** — not in v0.1.
- **MCP integration** — not in v0.1.
- **Webhooks** — not in v0.1.
- **Document listing** — no index endpoint. You need the slug to access a document.
- **AST-aware marker parsing** — line-based regex only. Code block limitation is documented, not fixed.
- **HTTPS / TLS** — the binary serves plain HTTP. TLS is the reverse proxy's job.
- **Graceful shutdown** — nice to have but not required. Ctrl-C kills it.
- **Database migrations** — the schema is created on first run. No migration system.
- **Tests** — raccoons MAY write tests. Not required for GREEN status. The curl commands above are the acceptance tests.

---

## Constraints

- **Language:** Rust, edition 2021
- **Minimum Rust version:** stable (whatever current stable is)
- **Binary name:** `sharesvc`
- **No unsafe code** unless justified in a comment
- **No `.unwrap()` on user input paths** — use proper error handling. `.unwrap()` on infallible operations (like compile-time templates) is fine.
- **Startup must not panic on missing env vars** — print a useful error and exit
- **The binary must be a SINGLE crate** — no workspace, no sub-crates. One `Cargo.toml`, one `src/` directory.
- **Module structure is open** — raccoons can organize `src/` however they want. Flat file, modules, whatever works.

---

## Notes for DJ

The raccoons compete on the FULL v0.1. No decomposition. Each raccoon builds the complete service independently.

**What to evaluate divergence on:**
- Module structure (flat vs layered)
- Parser implementation (regex flavor, iterator approach)
- Error handling strategy (anyhow vs custom types vs status codes)
- Template/CSS approach (which classless framework, how much CSS)
- How they handle the Axum router setup and state management
- Whether the CLI publish command shares code with the server or is a separate HTTP client

**Assembly priority:**
1. Does it compile? (`cargo build`)
2. Do the curl tests pass? (run all 15)
3. Code clarity — can Kade extend this in v0.2 without rewriting?
4. Template quality — does the human view actually look good?

GREEN = compiles + tests 1-14 pass. Test 15 (CLI) is bonus.

---

*The thinking is done. The markers are defined. The edge cases are named. Build it.*
