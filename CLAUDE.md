# Twofold

One document, two views. Rust-native self-hosted markdown share service.

## What This Is

Twofold accepts markdown documents with optional `<!-- @agent -->` / `<!-- @end -->` markers. It renders two views from one source:
- **Human view** (`/:slug`) — styled HTML, agent-only sections stripped, frontmatter stripped
- **Agent view** (`/api/v1/documents/:slug`) — full raw content including frontmatter and marked sections
- **Raw** (`/:slug?raw=1`) — source markdown (password-gated if protected)
- **Full** (`/:slug/full`) — all content rendered, markers stripped, for authenticated previews

## Tech Stack

- **Axum 0.7.9** — HTTP framework (route params use `:param` NOT `{param}`)
- **Comrak** — Markdown to HTML (GFM extensions)
- **SQLite** (via r2d2 + rusqlite) — document storage, WAL mode, 8-connection pool, 5s busy_timeout
- **Askama** — HTML templates (one per theme, compiled into binary)
- **nanoid** — slug generation (10 chars, alphanumeric + hyphen)
- **serde_yaml** — frontmatter parsing
- **argon2** — password hashing and token hashing
- **chrono** — timestamp handling
- **hmac + sha2** — cookie signatures for password auth, webhook signing
- **DashMap** — lock-free concurrent rate limit counters
- **syntect** — syntax highlighting (lazy-loaded via OnceLock)

## Module Map

| File | Responsibility |
|------|---------------|
| `src/main.rs` | Entry point, route table, server setup, reaper task, CLI dispatch |
| `src/auth.rs` | `Principal` type, `PrincipalKind` (Admin/OAuth/Managed), bearer extraction, constant-time comparison, `check_auth` / `check_auth_token` |
| `src/service.rs` | Document CRUD business logic — pure functions over `&Db` + `&ServeConfig`, no axum extractors; shared by HTTP handlers and MCP HTTP transport |
| `src/handlers.rs` | HTTP handlers, `AppState`, `AppError`, password flow, theme rendering, audit log endpoint |
| `src/views.rs` | Read and render handlers (split from handlers.rs — may be in progress) |
| `src/helpers.rs` | Shared handler utilities (split from handlers.rs — may be in progress) |
| `src/oauth.rs` | OAuth 2.0 server: Authorization Code + PKCE, dynamic client registration, refresh rotation, SQLite-backed token store |
| `src/mcp.rs` | MCP stdio transport — raw JSON-RPC over stdin/stdout; acts as HTTP client to the running server |
| `src/mcp_http.rs` | MCP HTTP transport — `POST /mcp`; dispatches tool calls directly to the service layer; no loopback |
| `src/frontmatter.rs` | YAML frontmatter parsing, merging, and injection — canonical source used by parser.rs and mcp.rs |
| `src/rate_limit.rs` | Fixed-window rate limiting via DashMap; `ReadRateLimit` extractor (per-IP), `WriteRateLimit` extractor (per-token), `RegistrationRateLimit` |
| `src/db.rs` | SQLite operations — documents, tokens, OAuth tables, audit log; schema migration via PRAGMA introspection |
| `src/parser.rs` | Markdown marker parsing (`@agent`/`@end`/`@instructions`), slug validation, expiry parsing; re-exports frontmatter types |
| `src/config.rs` | Environment variable config (`ServeConfig`); fails fast if `TWOFOLD_TOKEN` is absent |
| `src/cli.rs` | Clap CLI definitions: `serve`, `publish`, `list`, `delete`, `token`, `mcp`, `audit` |
| `src/highlight.rs` | Syntect syntax highlighting, lazy-initialized via `OnceLock` |
| `src/webhook.rs` | Fire-and-forget webhook dispatch on document lifecycle events; HMAC-SHA256 signing |

## Auth Model

Every authenticated request resolves to a `Principal`:

```rust
pub struct Principal {
    pub kind: PrincipalKind,  // Admin | OAuth { client_id } | Managed { name }
    pub display_name: String,
    pub scopes: Vec<String>,  // empty = full access (admin/managed); OAuth tokens carry explicit scopes
}
```

- **Admin** — master `TWOFOLD_TOKEN` env var, constant-time compare
- **Managed** — database-backed tokens created via `twofold token create`, argon2-hashed, prefix-accelerated O(1) lookup
- **OAuth** — short-lived access tokens issued by the built-in OAuth server; carry explicit scopes; refresh tokens rotate on use

Auth check order: Admin (constant-time) → Managed (prefix lookup + argon2 verify). OAuth tokens flow through the same `check_auth_token` path.

## MCP: Two Transports, One Service Layer

| Transport | File | How it works |
|-----------|------|-------------|
| **stdio** | `mcp.rs` | CLI subcommand (`twofold mcp`); raw JSON-RPC over stdin/stdout; HTTP client to a remote server |
| **HTTP** | `mcp_http.rs` | `POST /mcp`; bearer-auth required; dispatches directly to `service.rs`; no loopback |

The stdio transport is for local CLI use (Claude Code, etc.). The HTTP transport is for Cowork (claude.ai remote MCP) — it goes through the OAuth flow to obtain a bearer token, then POSTs JSON-RPC to `/mcp`.

Both transports expose the same tools: `twofold_publish`, `twofold_update`, `twofold_get`, `twofold_list`, `twofold_delete`.

## Content Negotiation

Bot UA detection and `Accept` header inspection determine the response format for `GET /:slug`:

- Bot user-agent or `Accept: text/markdown` → redirect to `/api/v1/documents/:slug` (raw agent view)
- `.md` extension on the slug → same redirect
- Browser request → themed HTML (human view, agent sections stripped)

## Dual-Layer Rendering

Each document has two content representations:

- **`content`** — human view: agent-only blocks (between `<!-- @agent -->` / `<!-- @end -->`) stripped; `<!-- @instructions -->` blocks stripped
- **`agent_content`** — full source including all marked sections; delivered via the API endpoint

Marker rules:
- Markers must be on their own line
- `<!-- @agent -->` ... `<!-- @end -->` — agent-only content (stripped from human view)
- `<!-- @instructions -->` ... `<!-- @end-instructions -->` — never rendered anywhere; raw source only

## Rate Limiting

Three independent stores, all fixed-window via DashMap:

| Extractor | Key | Applies to |
|-----------|-----|-----------|
| `ReadRateLimit` | Client IP | `GET /:slug`, `GET /api/v1/documents/:slug` |
| `WriteRateLimit` | Bearer token | `POST`, `PUT`, `DELETE` on `/api/v1/documents` |
| `RegistrationRateLimit` | Client IP | `POST /oauth/register` |

Limits configurable via env vars (see Configuration section). Exceeded limits return `429 Too Many Requests` with a JSON body.

## Audit Logging

Write operations (create, update, delete) produce `AuditEntry` records written fire-and-forget to the `audit_log` table in SQLite.

- **Admin-only endpoint:** `GET /api/v1/audit` — requires Admin `Principal`
- Fields: `id`, `timestamp`, `action`, `slug`, `token_name`, `ip_address`
- Failure never affects the main response path

## OAuth

Full OAuth 2.0 Authorization Server implementation targeting Cowork (claude.ai remote MCP):

| Endpoint | Purpose |
|----------|---------|
| `GET /.well-known/oauth-protected-resource` | RFC 8707 resource metadata |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 server metadata |
| `POST /oauth/register` | RFC 7591 dynamic client registration |
| `GET /authorize` | Authorization Code flow with mandatory PKCE (S256 only) |
| `POST /oauth/token` | Token exchange: `authorization_code`, `client_credentials`, `refresh_token` |

- PKCE is **required** — requests without `code_challenge` are rejected
- Public clients (`token_endpoint_auth_method: "none"`) need no client secret
- Refresh tokens rotate on each use
- All state (clients, auth codes, access tokens, refresh tokens) stored in SQLite

## CI

GitHub Actions gate on every push:

1. `cargo fmt --check` — formatting must be clean
2. `cargo clippy -- -D warnings` — no warnings allowed
3. `cargo test` — all tests pass

## Environment Variables

```bash
# Required
TWOFOLD_TOKEN="secret"               # Admin bearer token

# Server
TWOFOLD_BIND="127.0.0.1:3000"       # Bind address (default: 127.0.0.1:3000)
TWOFOLD_DB_PATH="./twofold.db"      # SQLite path (default: ./twofold.db)
TWOFOLD_BASE_URL="http://localhost:3000"  # For response URLs
TWOFOLD_MAX_SIZE="1048576"           # Max body bytes (default: 1MB)
TWOFOLD_REAPER_INTERVAL="60"         # Seconds between reaper runs (default: 60)
TWOFOLD_DEFAULT_THEME="clean"        # Default theme (default: clean)

# Webhooks
TWOFOLD_WEBHOOK_URL="https://..."    # Webhook endpoint (disabled if unset)
TWOFOLD_WEBHOOK_SECRET="secret"      # HMAC-SHA256 signing secret (optional)

# Rate limiting
TWOFOLD_READ_RATE_LIMIT="60"         # Reads per IP per window (default: 60)
TWOFOLD_WRITE_RATE_LIMIT="30"        # Writes per token per window (default: 30)
TWOFOLD_RATE_LIMIT_WINDOW="60"       # Window size in seconds (default: 60)
TWOFOLD_REGISTRATION_LIMIT="5"       # OAuth registrations per IP per window (default: 5)

# MCP (when running as MCP client)
TWOFOLD_MCP_SERVER="http://localhost:3000"  # Target server URL
TWOFOLD_MCP_TOKEN="..."              # Falls back to TWOFOLD_TOKEN
```

## API

```
POST   /api/v1/documents              Create (bearer auth, text/markdown body)
PUT    /api/v1/documents/:slug        Update (bearer auth)
DELETE /api/v1/documents/:slug        Delete (bearer auth) -> 204
GET    /api/v1/documents              List (bearer auth, paginated)
GET    /api/v1/documents/:slug        Agent view (full raw)
GET    /api/v1/audit                  Audit log (admin only)
GET    /api/v1/openapi.yaml           OpenAPI spec
GET    /api/v1/openapi.json           OpenAPI spec (JSON)
POST   /mcp                           MCP HTTP transport (bearer auth)
GET    /:slug                         Human view (themed HTML)
GET    /:slug?raw=1                   Raw source (password-gated)
GET    /:slug/full                    Full rendered view
POST   /:slug/unlock                  Password verification -> cookie + redirect
```

## CLI

```bash
twofold serve                          # Start HTTP server
twofold publish <path|-> [--server URL] [--token TOKEN] [--title T] [--slug S] [--theme THEME] [--expiry EXP]
twofold list [--server URL] [--token TOKEN]
twofold delete <slug> [--server URL] [--token TOKEN]
twofold token create --name "name" [--db path]
twofold token list [--db path]
twofold token revoke --name "name" [--db path]
twofold mcp                            # Start MCP server (stdio)
twofold audit [--server URL] [--token TOKEN]
```

## Building

```bash
cargo build --release
cargo test
cargo fmt
cargo clippy
```

## Templates

| File | Theme |
|------|-------|
| `templates/document.html` | `clean` — warm serif, dark/light auto (default) |
| `templates/dark.html` | `dark` — always dark, monospace, terminal energy |
| `templates/paper.html` | `paper` — warm serif, book-like, light only |
| `templates/minimal.html` | `minimal` — ultra-sparse, brutalist |
| `templates/hearth.html` | `hearth` — warm, interior, campfire tone |
| `templates/password.html` | password prompt page |

Unknown theme names fall back to `clean` silently.

## Work Orders

- `docs/work-order.md` — v0.1 specification
- `docs/work-order-v02.md` — v0.2 specification with acceptance criteria
