# Twofold

One document, two views. Rust-native self-hosted markdown share service.

## What This Is

Twofold accepts markdown documents with optional `<!-- @agent -->` / `<!-- @end -->` markers. It renders two views from one source:
- **Human view** (`/:slug`) — styled HTML, markers stripped, summary only
- **Agent view** (`/api/v1/documents/:slug`) — full content including marked sections
- **Raw** (`/:slug?raw=1`) — source markdown

## Tech Stack

- **Axum** — HTTP framework
- **Comrak** — Markdown → HTML (GFM extensions)
- **SQLite** (via rusqlite) — document storage
- **Askama** — HTML templates
- **nanoid** — slug generation

## Architecture

- `src/main.rs` — server setup, routes
- `src/parser.rs` — marker parsing, dual-corpus generation
- `src/db.rs` — SQLite operations
- `templates/` — Askama HTML templates (CSS inlined in template)

## Key Design Decisions

- Marker format is `<!-- @agent -->` / `<!-- @end -->` — HTML comments, invisible in standard renderers
- Line-based regex parsing, not AST-aware (v0.1)
- Title extraction: first H1 via regex, falls back to slug
- URL path routing for view selection (not Accept headers)
- Single bearer token auth via `TWOFOLD_TOKEN` env var

## Building

```bash
cargo build --release
```

## Running

```bash
TWOFOLD_TOKEN=your-secret ./target/release/twofold
```

## Work Order

See `docs/work-order.md` for the full raccoon build specification with acceptance criteria and test cases.

## DJ Note

Update this CLAUDE.md as architecture decisions are made during the build. This file is the onboarding doc for anyone working on the project — keep it current.
