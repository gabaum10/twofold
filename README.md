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
# Build from source
git clone https://github.com/gabaum10/twofold.git
cd twofold
cargo build --release

# Run it
export TWOFOLD_TOKEN="your-secret-token"
./target/release/twofold serve

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
cat report.md | ./target/release/twofold publish --server http://localhost:3000 --token $TWOFOLD_TOKEN
```

## Features

- **Frontmatter** -- title, slug, theme, expiry, password, description
- **Custom slugs** -- choose your URL or let nanoid generate one
- **Expiry** -- documents self-destruct (`30m`, `24h`, `7d`, `2w`)
- **Password protection** -- per-document, argon2-hashed
- **Themes** -- clean (default), dark, paper, minimal
- **Full CRUD** -- create, read, update, delete via REST
- **Token management** -- create/list/revoke API tokens via CLI
- **Single binary** -- no runtime dependencies, SQLite embedded

## API

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/v1/documents` | Bearer | Create document (body: `text/markdown`) |
| `GET` | `/:slug` | -- | Human view (styled HTML, agent sections stripped) |
| `GET` | `/:slug/full` | -- | Full rendered view (all sections visible) |
| `GET` | `/:slug?raw=1` | -- | Raw markdown source |
| `GET` | `/api/v1/documents/:slug` | -- | Agent API (full raw markdown + frontmatter) |
| `PUT` | `/api/v1/documents/:slug` | Bearer | Update document |
| `DELETE` | `/api/v1/documents/:slug` | Bearer | Delete document (returns 204) |

Password-protected documents gate the human view and raw view. The agent API endpoint is not gated.

## Authoring Format

Two markers. That's it.

```
<!-- @agent -->
Content only agents see.
<!-- @end -->
```

Everything outside markers is visible to both humans and agents. Everything inside is agent-only.

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

Unknown theme names fall back to `clean` silently.

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

## CLI

```bash
twofold serve                                    # Start server
twofold publish <file|-> --server URL --token T  # Publish document
twofold token create --name "deploy-bot"         # Create API token
twofold token list                               # List tokens
twofold token revoke --name "deploy-bot"         # Revoke token
```

## What This Is NOT

**Not a paste bin.** Paste bins store text. Twofold renders authored dual-layer documents with theming, expiry, and access control.

**Not a CMS.** No user accounts. No editing UI. No database migrations to babysit. Publish via API, done.

**Not content negotiation.** Cloudflare and Vercel convert the same content between formats (HTML vs markdown vs plain text). Twofold serves *different content* to different consumers. The author writes both layers. The service routes them.

## License

MIT
