# twofold

**One document, two views.**

Your agent wrote 15 pages. Humans see what matters. Agents see everything.

---

## The Problem

AI generates cathedrals of content. A quarterly report becomes 15 pages of structured data, citations, methodology notes. Humans can't process that. But the next agent in your pipeline needs all of it.

There is no format that serves both audiences from one source. You either dumb it down for humans or bury them in detail meant for machines. Twofold is one markdown file that renders two views: a human gets the executive summary, an agent gets the full corpus. Same URL. Same document. Two layers, authored intentionally.

## How It Works

Write markdown. Mark the agent-only sections with HTML comments:

```markdown
---
title: Q1 Revenue Report
slug: q1-revenue
theme: clean
expiry: 30d
---

# Q1 Revenue Report

Revenue grew 23% YoY driven by enterprise expansion.
Key risk: churn in mid-market segment accelerating.

Recommendation: shift acquisition spend to retention for Q2.

<!-- @agent -->

## Detailed Breakdown

| Segment | ARR | Growth | Churn |
|---------|-----|--------|-------|
| Enterprise | $4.2M | +31% | 2.1% |
| Mid-market | $1.8M | +12% | 8.7% |
| SMB | $0.6M | -3% | 14.2% |

## Methodology

Growth figures are trailing-twelve-month calculations normalized against...
[12 more pages of tables, analysis, source citations]

<!-- @end -->
```

**Human visits** `share.example.com/q1-revenue` -- sees a styled page with the summary. Three paragraphs. Done.

**Agent hits** `share.example.com/api/v1/documents/q1-revenue` -- gets everything. All 15 pages. Raw markdown with frontmatter intact.

The markers are HTML comments. They're invisible in any standard markdown renderer. Any LLM can emit them. Without twofold, the document degrades gracefully to normal markdown with some comments in it.

## Quick Start

```bash
# Install from crates.io
cargo install twofold

# Run it
export TWOFOLD_TOKEN="your-secret-token"
twofold serve

# Publish a document
curl -X POST http://localhost:3000/api/v1/documents \
  -H "Authorization: Bearer $TWOFOLD_TOKEN" \
  -H "Content-Type: text/markdown" \
  --data-binary @report.md

# Response:
# {"slug":"q1-revenue","url":"http://localhost:3000/q1-revenue"}
```

Or pipe from stdin:

```bash
cat report.md | twofold publish --server http://localhost:3000 --token $TWOFOLD_TOKEN
```

**Build from source:**

```bash
git clone https://github.com/gabaum10/twofold.git
cd twofold
cargo build --release
./target/release/twofold serve
```

## Features

- **Frontmatter** -- title, slug, theme, expiry, description (YAML in `---` fences)
- **Custom slugs** -- choose your URL or let nanoid generate one
- **Expiry** -- documents self-destruct (`30m`, `24h`, `7d`, `2w`) with background reaper; live countdown timer on the human view
- **Themes** -- clean (default), dark, paper, minimal, hearth; wider content layout (850px) with enhanced print CSS across all five themes
- **PDF download** -- toolbar button triggers browser print-to-PDF
- **Syntax highlighting** -- syntect-powered, theme-aware (light/dark palettes)
- **Full CRUD** -- create, read, update, delete via REST
- **MCP server** -- agents publish and retrieve natively via JSON-RPC over stdio
- **Webhooks** -- fire on create/update/delete, HMAC-signed
- **Agent discovery** -- `<link rel="alternate" type="text/markdown">` in every HTML page
- **OpenAPI spec** -- served live at `/api/v1/openapi.yaml` and `/api/v1/openapi.json`
- **Token management** -- create/list/revoke API tokens via CLI
- **Single binary** -- no runtime dependencies, SQLite embedded

## API

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/v1/documents` | Bearer | Create document (body: `text/markdown`) |
| `GET` | `/api/v1/documents` | Bearer | List documents (paginated, metadata only) |
| `GET` | `/api/v1/documents/:slug` | -- | Agent view (full raw markdown + frontmatter) |
| `PUT` | `/api/v1/documents/:slug` | Bearer | Update document |
| `DELETE` | `/api/v1/documents/:slug` | Bearer | Delete document (returns 204) |
| `GET` | `/api/v1/openapi.yaml` | -- | OpenAPI spec (YAML) |
| `GET` | `/api/v1/openapi.json` | -- | OpenAPI spec (JSON) |
| `GET` | `/:slug` | -- | Human view (styled HTML, agent sections stripped) |
| `GET` | `/:slug?raw=1` | -- | Raw markdown source |
| `GET` | `/:slug/full` | -- | Full rendered view (all content, markers stripped) |

## MCP Server

Twofold ships an MCP (Model Context Protocol) server for direct agent integration. Agents publish, retrieve, list, and delete documents without shelling out to curl.

```bash
twofold mcp
```

Runs on stdio (JSON-RPC, newline-delimited). Wire it into Claude Code or any MCP-compatible tool:

```json
{
  "mcpServers": {
    "twofold": {
      "command": "/path/to/twofold",
      "args": ["mcp"],
      "env": {
        "TWOFOLD_MCP_SERVER": "http://localhost:3000",
        "TWOFOLD_MCP_TOKEN": "your-token"
      }
    }
  }
}
```

### MCP Tools

| Tool | Description |
|------|-------------|
| `twofold_publish` | Publish markdown. Accepts `content` (required), `title`, `slug`, `expiry`, `theme`, `description`. Returns URL and slug. |
| `twofold_update` | Update a document by slug. Accepts `slug` (required), `content` (required), `title`, `description`, `expiry`, `theme`. |
| `twofold_get` | Retrieve raw markdown by slug. |
| `twofold_list` | List published documents. Optional `limit` (default 20, max 100). |
| `twofold_delete` | Delete a document by slug. |

Environment: `TWOFOLD_MCP_SERVER` (default `http://localhost:3000`), `TWOFOLD_MCP_TOKEN` (falls back to `TWOFOLD_TOKEN`).

## Authoring Format

Two markers. That's it.

```
<!-- @agent -->
Content only agents see.
<!-- @end -->
```

Everything outside markers is visible to both humans and agents. Everything inside is agent-only.

A third marker pair hides content from ALL rendered views (human, full, and agent HTML) while keeping it in the raw source:

```
<!-- @instructions -->
Meta-instructions for agents reading raw source. Never rendered.
<!-- @end-instructions -->
```

**Why HTML comments?**

- Invisible in every markdown renderer that exists
- Any LLM can emit them without special tooling
- Graceful degradation: without twofold, it's just a markdown file
- No new syntax to learn, no preprocessing step

Markers must be on their own line. Inline `<!-- @agent -->` in a paragraph is not parsed as a marker. Whitespace inside is tolerated: `<!--  @agent  -->` works.

## Themes

Select via frontmatter:

```yaml
---
theme: dark
---
```

| Theme | Character |
|-------|-----------|
| `clean` | Warm serif, dark/light auto, Tufte-informed (default) |
| `dark` | Always dark, monospace, terminal energy |
| `paper` | Warm serif, book-like, light only |
| `minimal` | Ultra-sparse, brutalist |
| `hearth` | Warm, interior, campfire tone |

Unknown theme names fall back to `clean` silently.

## Webhooks

Configure a URL; twofold fires JSON on document lifecycle events.

```bash
export TWOFOLD_WEBHOOK_URL="https://your-service.com/hook"
export TWOFOLD_WEBHOOK_SECRET="your-hmac-secret"  # optional
```

Events: `document.created`, `document.updated`, `document.deleted`.

Payload:

```json
{
  "event": "document.created",
  "timestamp": "2026-05-10T03:22:00Z",
  "document": {
    "slug": "q1-revenue",
    "title": "Q1 Revenue Report",
    "url": "http://localhost:3000/q1-revenue",
    "api_url": "http://localhost:3000/api/v1/documents/q1-revenue"
  }
}
```

When `TWOFOLD_WEBHOOK_SECRET` is set, requests include an `X-Twofold-Signature: sha256=<hex>` header (HMAC-SHA256 of the JSON body). Fire-and-forget: webhook failure never affects API responses.

## Configuration

All config is via environment variables. No config files.

| Variable | Default | Description |
|----------|---------|-------------|
| `TWOFOLD_TOKEN` | *required* | Admin bearer token for publish/update/delete |
| `TWOFOLD_BIND` | `127.0.0.1:3000` | Server bind address |
| `TWOFOLD_DB_PATH` | `./twofold.db` | SQLite database path |
| `TWOFOLD_BASE_URL` | `http://localhost:3000` | Base URL for response payloads |
| `TWOFOLD_MAX_SIZE` | `1048576` | Max request body in bytes (1MB) |
| `TWOFOLD_REAPER_INTERVAL` | `60` | Seconds between expired document cleanup |
| `TWOFOLD_DEFAULT_THEME` | `clean` | Default theme when none specified |
| `TWOFOLD_WEBHOOK_URL` | -- | Webhook endpoint (no webhook if unset) |
| `TWOFOLD_WEBHOOK_SECRET` | -- | HMAC-SHA256 signing secret for webhooks |

## CLI

```bash
twofold serve                                              # Start server
twofold publish <file|-> --server URL --token T            # Publish document
twofold publish <file> --title "..." --slug X              # Publish with frontmatter flags
twofold publish <file> --theme dark --expiry 7d            # Set theme and expiry
twofold list --server URL --token T                        # List documents
twofold delete <slug> --server URL --token T               # Delete a document
twofold token create --name "deploy-bot"                   # Create API token
twofold token list                                         # List tokens
twofold token revoke --name "deploy-bot"                   # Revoke token
twofold mcp                                                # Start MCP server (stdio)
```

## Agent Discovery

Every HTML page includes a `<link>` tag pointing to the raw markdown API endpoint:

```html
<link rel="alternate" type="text/markdown" href="/api/v1/documents/{slug}" title="Full document (markdown)">
```

Agents that parse HTML can find the full document without knowing the API URL structure.

## What This Is NOT

**Not a paste bin.** Paste bins store text. Twofold renders authored dual-layer documents with theming, expiry, and access control.

**Not a CMS.** No user accounts. No editing UI. No database migrations to babysit. Publish via API, done.

**Not content negotiation.** Cloudflare and Vercel convert the same content between formats (HTML vs markdown vs plain text). Twofold serves *different content* to different consumers. The author writes both layers. The service routes them.

## License

MIT
