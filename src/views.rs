/// Read/render handlers and all supporting helpers for human-facing document views.
///
/// Includes:
/// - Template structs (CleanTemplate, DarkTemplate, etc.)
/// - Content negotiation helpers (accept_prefers_json, is_known_bot, etc.)
/// - Rendering helpers (render_markdown, render_themed_sync, strip_marker_comments, etc.)
/// - Response helpers (not_found_response, gone_response, markdown_response)
/// - Handler functions: get_human, get_full, get_agent, post_unlock
use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    Form, Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    handlers::{AppError, AppState},
    helpers::{is_expired, is_password_authed, make_auth_cookie, verify_password},
    parser::{extract_frontmatter, parse_document},
    rate_limit::ReadRateLimit,
};

// ── Templates ─────────────────────────────────────────────────────────────────

/// Askama template for the human-facing document view (clean theme).
#[derive(Template)]
#[template(path = "document.html")]
struct CleanTemplate<'a> {
    title: &'a str,
    content: &'a str,
    slug: &'a str,
    base_url: &'a str,
    /// When true, toolbar shows "Summary view" instead of "Full detail".
    full_view: bool,
    expires_at: Option<String>,
    /// First ~150 chars of plain text content for meta description / OpenGraph.
    description: String,
}

/// Dark theme template.
#[derive(Template)]
#[template(path = "dark.html")]
struct DarkTemplate<'a> {
    title: &'a str,
    content: &'a str,
    slug: &'a str,
    base_url: &'a str,
    full_view: bool,
    expires_at: Option<String>,
    description: String,
}

/// Paper theme template.
#[derive(Template)]
#[template(path = "paper.html")]
struct PaperTemplate<'a> {
    title: &'a str,
    content: &'a str,
    slug: &'a str,
    base_url: &'a str,
    expires_at: Option<String>,
    description: String,
}

/// Minimal theme template.
#[derive(Template)]
#[template(path = "minimal.html")]
struct MinimalTemplate<'a> {
    title: &'a str,
    content: &'a str,
    slug: &'a str,
    base_url: &'a str,
    expires_at: Option<String>,
    description: String,
}

/// Hearth theme template.
#[derive(Template)]
#[template(path = "hearth.html")]
struct HearthTemplate<'a> {
    title: &'a str,
    content: &'a str,
    slug: &'a str,
    base_url: &'a str,
    full_view: bool,
    expires_at: Option<String>,
    description: String,
}

/// Password prompt template.
#[derive(Template)]
#[template(path = "password.html")]
struct PasswordTemplate<'a> {
    slug: &'a str,
    base_url: &'a str,
    error: Option<&'a str>,
}

/// 404 Not Found error template.
/// `theme` is passed through to the template for CSS comment identification;
/// the hearth palette CSS variables are always used for error pages so the
/// look is consistent regardless of the document's own theme.
#[derive(Template)]
#[template(path = "404.html")]
struct NotFoundTemplate<'a> {
    theme: &'a str,
}

/// 410 Gone error template.
/// `theme` is passed through to the template for CSS comment identification.
/// The 30-day tombstone window explanation is rendered in the template body.
#[derive(Template)]
#[template(path = "410.html")]
struct GoneTemplate<'a> {
    theme: &'a str,
}

// ── Query / form types used only by view handlers ────────────────────────────

/// Query parameters for GET /:slug
#[derive(Deserialize)]
pub struct SlugQuery {
    pub raw: Option<String>,
    /// Primary query-param password unlock for password-protected documents.
    /// Named `access_token` to avoid security heuristics in some HTTP clients
    /// (e.g. ChatGPT browsing tool refuses URLs with `?password=`).
    /// `?password=` is accepted as a backward-compatible fallback.
    /// Content negotiation still applies: bot UAs / `Accept: application/json`
    /// get the JSON response; browsers get HTML.
    pub access_token: Option<String>,
    /// Backward-compatible alias for `access_token`. `access_token` takes
    /// precedence if both are present.
    pub password: Option<String>,
}

/// Query parameters for GET /api/v1/documents/:slug (agent view).
#[derive(Deserialize)]
pub struct AgentQuery {
    /// Primary query-param password. Named `access_token` to avoid security
    /// heuristics in some HTTP clients. `?password=` accepted as fallback.
    pub access_token: Option<String>,
    /// Backward-compatible alias for `access_token`.
    pub password: Option<String>,
}

/// Form data for password unlock
#[derive(Deserialize)]
pub struct UnlockForm {
    pub password: String,
}

/// JSON response body for a single document (agent/content-negotiation view).
///
/// Returned when the caller signals `Accept: application/json` or is a known
/// AI crawler, so agents can consume the full document (including agent-layer
/// content) from the same human-facing URL without hitting the API endpoint.
///
/// `content` is retained for backward compatibility (full raw markdown, password
/// stripped from frontmatter).  `human_content` and `agent_content` are parsed
/// splits: human is everything outside agent-marker blocks; agent is the content
/// inside them (None when no agent section exists).
#[derive(Serialize)]
pub struct DocumentResponse {
    pub slug: String,
    pub title: String,
    pub content: String, // full raw markdown, password stripped from frontmatter
    pub human_content: String, // content outside <!-- @agent --> blocks
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_content: Option<String>, // content inside <!-- @agent --> blocks
    pub theme: String,
    pub description: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
}

// ── Content negotiation helpers ───────────────────────────────────────────────

/// Returns true if the Accept header expresses a preference for JSON.
///
/// Matches any Accept value that contains `application/json`, including
/// quality-factored lists such as `application/json, */*;q=0.5`.
pub fn accept_prefers_json(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("application/json"))
        .unwrap_or(false)
}

/// Returns true if the Accept header expresses a preference for Markdown.
///
/// Matches `text/markdown` in any position in the Accept header value.
pub fn accept_prefers_markdown(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("text/markdown"))
        .unwrap_or(false)
}

/// Known AI crawler User-Agent substrings (case-insensitive).
const KNOWN_BOT_AGENTS: &[&str] = &[
    "gptbot",
    "chatgpt-user",
    "claudebot",
    "claude-user",
    "google-extended",
    "googlebot",
    "bingbot",
    "perplexitybot",
    "anthropic",
    "google-agent",
];

/// Returns true if the User-Agent header matches a known AI crawler.
pub fn is_known_bot(headers: &HeaderMap) -> bool {
    let ua = match headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
    {
        Some(s) => s.to_lowercase(),
        None => return false,
    };
    KNOWN_BOT_AGENTS.iter().any(|bot| ua.contains(bot))
}

// ── Rendering helpers ─────────────────────────────────────────────────────────

/// Strip the `password:` line from YAML frontmatter in raw content.
///
/// Only removes lines inside the opening `---` ... closing `---` block.
/// Does not modify content that has no frontmatter or no password field.
/// Returns a new String; the stored document is never modified.
pub fn strip_password_from_content_pub(raw: &str) -> String {
    strip_password_from_content(raw)
}

pub(crate) fn strip_password_from_content(raw: &str) -> String {
    let lines: Vec<&str> = raw.lines().collect();

    // Must start with `---` to have frontmatter.
    if lines.is_empty() || lines[0].trim() != "---" {
        return raw.to_string();
    }

    // Find closing `---`.
    let close_idx = match lines
        .iter()
        .enumerate()
        .skip(1)
        .find(|(_, l)| l.trim() == "---")
    {
        Some((i, _)) => i,
        None => return raw.to_string(),
    };

    // Rebuild lines, dropping any `password: ...` line inside the fence.
    let filtered: Vec<&str> = lines
        .iter()
        .enumerate()
        .filter(|(i, line)| {
            // Only strip inside the frontmatter block (lines 1..close_idx).
            if *i >= 1 && *i < close_idx {
                let trimmed = line.trim_start();
                !trimmed.starts_with("password:")
            } else {
                true
            }
        })
        .map(|(_, line)| *line)
        .collect();

    filtered.join("\n")
}

/// Build the `DocumentResponse` JSON reply for agent/content-negotiation paths.
///
/// Used by `get_human` for JSON content-negotiation responses.
fn build_json_agent_response(doc: &crate::db::DocumentRecord) -> Response {
    // Strip password from the content that goes into the response.
    let safe_content = strip_password_from_content(&doc.raw_content);

    // Split human vs agent sections using the same parser the browser render uses.
    let parsed = parse_document(&safe_content, &doc.slug);

    let body = DocumentResponse {
        slug: doc.slug.clone(),
        title: doc.title.clone(),
        content: safe_content,
        human_content: parsed.human,
        agent_content: parsed.agent,
        theme: doc.theme.clone(),
        description: doc.description.clone(),
        created_at: doc.created_at.clone(),
        expires_at: doc.expires_at.clone(),
    };
    (StatusCode::OK, Json(body)).into_response()
}

/// Strip marker comment lines and agent-instructions blocks from source.
///
/// Two stripping behaviors:
///
/// 1. `<!-- @agent -->` and `<!-- @end -->` lines are removed (their content is KEPT).
///    These delimit agent-only sections in the source but the full view still renders
///    the content between them.
///
/// 2. `<!-- @instructions -->` / `<!-- @end-instructions -->` blocks are removed
///    entirely — both the marker lines AND everything between them.
///    Use this for meta-instructions directed at agents reading raw source that
///    should never appear in any rendered view (human or full).
///
/// Uses whitespace-tolerant matching (same logic as `parser::is_marker`).
fn strip_marker_comments(source: &str) -> String {
    let mut result: Vec<&str> = Vec::new();
    let mut in_instructions = false;

    for line in source.lines() {
        let t = line.trim();
        let tag = if t.starts_with("<!--") && t.ends_with("-->") {
            let inner = &t["<!--".len()..t.len() - "-->".len()];
            Some(inner.trim())
        } else {
            None
        };

        match tag {
            // Enter instructions block — skip marker, skip all content until close
            Some("@instructions") => {
                in_instructions = true;
                // marker line itself is dropped
            }
            // Exit instructions block — skip the closing marker
            Some("@end-instructions") if in_instructions => {
                in_instructions = false;
                // marker line itself is dropped
            }
            // Strip agent/end marker lines but keep content outside them
            Some("@agent") | Some("@end") if !in_instructions => {
                // marker line dropped, surrounding content preserved
            }
            // Inside an instructions block — drop content
            _ if in_instructions => {}
            // Normal line — keep it
            _ => {
                result.push(line);
            }
        }
    }

    result.join("\n")
}

/// Render markdown to HTML using comrak with GFM extensions.
///
/// `render.unsafe_` is intentionally false — raw HTML in document content is
/// NOT passed through to the output. ammonia then sanitizes the rendered HTML
/// as a second layer, stripping any script tags, event handlers, iframes, or
/// other XSS vectors that comrak's own sanitization might miss.
///
/// Note: comrak 0.28's `Options<'c>` type contains `ParseOptions<'c>` which
/// holds `Option<Arc<Mutex<BrokenLinkCallback<'c>>>>`. The `dyn FnMut` inside
/// the callback is not `Sync`, so `Options` cannot be stored in a `static OnceLock`.
/// Construction is O(1) bool-field assignment with no heap allocation, so the
/// per-call cost is negligible.
fn render_markdown(source: &str) -> String {
    use comrak::{markdown_to_html, Options};

    let mut options = Options::default();
    options.extension.table = true;
    options.extension.strikethrough = true;
    options.extension.autolink = true;
    options.extension.tasklist = true;
    options.render.unsafe_ = false;
    let rendered = markdown_to_html(source, &options);
    // Second layer: ammonia removes script tags, event handlers, iframes, and
    // any other XSS-capable constructs while preserving safe formatting HTML.
    ammonia::clean(&rendered)
}

/// Render a themed HTML response with syntax highlighting.
///
/// `full_view`: when true, the clean-theme toolbar shows "Summary view" instead of "Full detail".
/// Has no effect on themes that don't render a toolbar.
///
/// `content` is already-rendered HTML from comrak. Syntax highlighting post-processes
/// this HTML, finding <pre><code class="language-X"> blocks and replacing them with
/// syntect-highlighted spans. Dark theme uses dark syntax palette; all others use light.
///
/// Named `_sync` because it is called from `spawn_blocking` contexts (not directly from async).
/// This avoids stack overflow in async worker threads during syntect init/tokenization.
fn render_themed_sync(
    title: &str,
    content: &str,
    slug: &str,
    theme: &str,
    base_url: &str,
    full_view: bool,
    expires_at: Option<String>,
) -> Result<Response, AppError> {
    // Apply syntax highlighting to the pre-rendered HTML.
    // Dark theme gets dark syntax palette; all others get light.
    let is_dark = theme == "dark";
    let highlighted = crate::highlight::apply_syntax_highlighting(content, is_dark);

    // Compute plain-text excerpt for meta description / OpenGraph.
    // Strip HTML tags from the rendered content, collapse whitespace, truncate at 150 chars.
    let description = plain_text_excerpt(&highlighted, 150);

    let html = match theme {
        "dark" => {
            let t = DarkTemplate {
                title,
                content: &highlighted,
                slug,
                base_url,
                full_view,
                expires_at,
                description,
            };
            t.render()
        }
        "paper" => {
            let t = PaperTemplate {
                title,
                content: &highlighted,
                slug,
                base_url,
                expires_at,
                description,
            };
            t.render()
        }
        "minimal" => {
            let t = MinimalTemplate {
                title,
                content: &highlighted,
                slug,
                base_url,
                expires_at,
                description,
            };
            t.render()
        }
        "hearth" => {
            let t = HearthTemplate {
                title,
                content: &highlighted,
                slug,
                base_url,
                full_view,
                expires_at,
                description,
            };
            t.render()
        }
        _ => {
            // "clean" or unknown -> default
            let t = CleanTemplate {
                title,
                content: &highlighted,
                slug,
                base_url,
                full_view,
                expires_at,
                description,
            };
            t.render()
        }
    };

    html.map(|h| Html(h).into_response())
        .map_err(|e| AppError::Internal(format!("Template render error: {e}")))
}

/// Strip HTML tags and extract plain text, collapsing whitespace.
/// Returns up to `max_chars` characters, suitable for meta description tags.
fn plain_text_excerpt(html: &str, max_chars: usize) -> String {
    let mut result = String::with_capacity(html.len().min(512));
    let mut in_tag = false;
    let mut last_was_space = true; // start true so we don't lead with a space

    for ch in html.chars() {
        match ch {
            '<' => {
                in_tag = true;
            }
            '>' => {
                in_tag = false;
                // Treat closing/block tags as whitespace boundaries.
                if !last_was_space {
                    result.push(' ');
                    last_was_space = true;
                }
            }
            _ if in_tag => {}
            '\n' | '\r' | '\t' | ' ' => {
                if !last_was_space {
                    result.push(' ');
                    last_was_space = true;
                }
            }
            _ => {
                result.push(ch);
                last_was_space = false;
            }
        }
    }

    let trimmed = result.trim().to_string();

    // Truncate at max_chars on a char boundary, appending ellipsis if cut.
    if trimmed.chars().count() <= max_chars {
        trimmed
    } else {
        let cut: String = trimmed.chars().take(max_chars).collect();
        format!("{cut}...")
    }
}

// ── Response helpers ──────────────────────────────────────────────────────────

/// Build a `text/markdown; charset=utf-8` response.
pub fn markdown_response(content: &str) -> Response {
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/markdown; charset=utf-8",
        )],
        content.to_string(),
    )
        .into_response()
}

/// Return a themed 404 HTML response via Askama template.
///
/// Uses the hearth palette (the default error theme). The `theme` field in
/// the template is passed through for CSS comment identification but does not
/// change the palette — error pages use hearth regardless of document theme.
pub fn not_found_response() -> Response {
    let t = NotFoundTemplate { theme: "hearth" };
    match t.render() {
        Ok(html) => (
            StatusCode::NOT_FOUND,
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            html,
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to render 404 template");
            StatusCode::NOT_FOUND.into_response()
        }
    }
}

/// Return a themed 410 HTML response via Askama template.
///
/// Visually distinct from 404: muted heading color, reduced accent bar opacity,
/// and language that explains the document was intentionally time-limited.
/// The 30-day tombstone window is explained in the template body.
pub fn gone_response() -> Response {
    let t = GoneTemplate { theme: "hearth" };
    match t.render() {
        Ok(html) => (
            StatusCode::GONE,
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            html,
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to render 410 template");
            StatusCode::GONE.into_response()
        }
    }
}

// ── GET /:slug (human view) ───────────────────────────────────────────────────

/// Handle human view and raw-shortcut view.
///
/// Without `?raw=1`: renders the human corpus as themed HTML.
/// With `?raw=1`: returns the full raw source.
/// Password-protected documents show a password prompt.
///
/// Content negotiation (checked after expiry/password):
/// - `Accept: application/json` → full `DocumentResponse` JSON (agent layer included)
/// - `Accept: text/markdown` → raw source markdown
/// - Known AI crawler User-Agent with no Accept preference → JSON
/// - Everything else → themed HTML (existing behaviour)
pub async fn get_human(
    State(state): State<AppState>,
    _rl: ReadRateLimit,
    Path(slug): Path<String>,
    Query(params): Query<SlugQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    // .md suffix handling: `/:slug` catches `/my-doc.md` with slug = "my-doc.md".
    // Strip the suffix and serve raw markdown (same as ?raw=1).
    // This runs before the DB lookup so the bare slug is used throughout.
    let (slug, force_markdown) = if let Some(bare) = slug.strip_suffix(".md") {
        (bare.to_string(), true)
    } else {
        (slug, false)
    };

    let slug_for_lookup = slug.clone();
    let db_lookup = state.db.clone();
    let doc = match tokio::task::spawn_blocking(move || db_lookup.get_by_slug(&slug_for_lookup))
        .await
        .map_err(|e| AppError::Internal(format!("Task failed: {e}")))?
        .map_err(AppError::from)?
    {
        Some(d) => d,
        None => return Ok(not_found_response()),
    };

    // Expiry check (410 takes priority over password)
    if is_expired(&doc) {
        return Ok(gone_response());
    }

    // Password check (if document is protected)
    if let Some(stored_hash) = &doc.password {
        // First: query-param unlock — ?access_token=X (or legacy ?password=X) works for agents
        // and direct links.  access_token takes precedence; password is a backward-compat fallback.
        let query_provided = params
            .access_token
            .as_deref()
            .or(params.password.as_deref());
        let query_pw_valid = if let Some(provided) = query_provided {
            let provided_owned = provided.to_string();
            let hash_owned = stored_hash.clone();
            tokio::task::spawn_blocking(move || verify_password(&provided_owned, &hash_owned))
                .await
                .map_err(|e| AppError::Internal(format!("Auth task failed: {e}")))?
        } else {
            false
        };

        // Fall back to cookie-based auth (post-form-unlock session).
        if !query_pw_valid && !is_password_authed(&headers, &slug, &state.config.token) {
            let template = PasswordTemplate {
                slug: &slug,
                base_url: state.config.base_url.trim_end_matches('/'),
                error: None,
            };
            return Ok(Html(
                template
                    .render()
                    .map_err(|e| AppError::Internal(format!("Template error: {e}")))?,
            )
            .into_response());
        }
    }

    // .md suffix → serve raw markdown immediately.
    if force_markdown {
        return Ok(markdown_response(&strip_password_from_content(
            &doc.raw_content,
        )));
    }

    // ?raw=1 -> return full source
    if params.raw.as_deref() == Some("1") {
        return Ok(markdown_response(&strip_password_from_content(
            &doc.raw_content,
        )));
    }

    // Content negotiation: Accept header wins over User-Agent.
    //
    // Priority:
    //   1. Accept: application/json  → JSON  (agent content)
    //   2. Accept: text/markdown     → raw markdown
    //   3. Accept: text/html         → HTML  (browser dev-inspect with bot UA)
    //   4. No/neutral Accept + bot User-Agent → JSON
    //   5. Everything else           → themed HTML (default)
    if accept_prefers_json(&headers) {
        return Ok(build_json_agent_response(&doc));
    }
    if accept_prefers_markdown(&headers) {
        return Ok(markdown_response(&strip_password_from_content(
            &doc.raw_content,
        )));
    }
    // Only check the bot UA when the client has NOT declared a preference for HTML.
    // A browser dev-inspecting via a bot UA will send Accept: text/html; honour it.
    let accept_explicitly_html = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("text/html"))
        .unwrap_or(false);
    if !accept_explicitly_html && is_known_bot(&headers) {
        return Ok(build_json_agent_response(&doc));
    }

    // Human view: extract body (strip frontmatter), parse markers, render.
    //
    // Rendering is moved to spawn_blocking because syntect's syntax highlighting
    // can use significant stack depth during the first load (OnceLock init) and
    // during regex-based tokenization. Release builds with LTO can optimize away
    // stack frames but still require deep call chains. spawn_blocking runs on a
    // dedicated thread pool with larger stacks, avoiding stack overflow in the
    // async worker thread.
    let raw_content = doc.raw_content.clone();
    let title = doc.title.clone();
    let theme = doc.theme.clone();
    let slug_owned = slug.clone();
    let expires_at = doc.expires_at.clone();
    let base_url = state.config.base_url.trim_end_matches('/').to_string();
    let base_url_clone = base_url.clone();

    let html_result = tokio::task::spawn_blocking(move || {
        let fm_result = extract_frontmatter(&raw_content).unwrap_or_else(|_| {
            crate::parser::FrontmatterResult {
                meta: None,
                body: raw_content.clone(),
                close_end_byte: None,
            }
        });

        let parse_result = parse_document(&fm_result.body, &slug_owned);
        let rendered_html = render_markdown(&parse_result.human);
        render_themed_sync(
            &title,
            &rendered_html,
            &slug_owned,
            &theme,
            &base_url_clone,
            false,
            expires_at,
        )
    })
    .await
    .map_err(|e| AppError::Internal(format!("Render task failed: {e}")))?;

    // Add Link header pointing to the JSON API endpoint.
    let link_header = format!(
        "<{base_url}/api/v1/documents/{slug}>; rel=\"alternate\"; type=\"application/json\"",
    );
    let html_response = html_result?;
    let mut response = html_response.into_response();
    response.headers_mut().insert(
        axum::http::header::LINK,
        axum::http::HeaderValue::from_str(&link_header)
            .unwrap_or_else(|_| axum::http::HeaderValue::from_static("")),
    );
    Ok(response)
}

// ── POST /:slug/unlock ────────────────────────────────────────────────────────

/// Handle password verification and cookie setting.
pub async fn post_unlock(
    State(state): State<AppState>,
    _rl: ReadRateLimit,
    Path(slug): Path<String>,
    Form(form): Form<UnlockForm>,
) -> Result<Response, AppError> {
    let slug_for_unlock = slug.clone();
    let db_unlock = state.db.clone();
    let doc = match tokio::task::spawn_blocking(move || db_unlock.get_by_slug(&slug_for_unlock))
        .await
        .map_err(|e| AppError::Internal(format!("Task failed: {e}")))?
        .map_err(AppError::from)?
    {
        Some(d) => d,
        None => return Ok(not_found_response()),
    };

    if is_expired(&doc) {
        return Ok(gone_response());
    }

    let stored_hash = match &doc.password {
        Some(h) => h,
        None => {
            // No password — redirect to document
            return Ok(Redirect::to(&format!("/{slug}")).into_response());
        }
    };

    // Verify password (argon2 is CPU-heavy; run off the async executor).
    let pw_owned = form.password.clone();
    let hash_owned = stored_hash.clone();
    let verified = tokio::task::spawn_blocking(move || verify_password(&pw_owned, &hash_owned))
        .await
        .map_err(|e| AppError::Internal(format!("Task failed: {e}")))?;

    if verified {
        // Set auth cookie and redirect
        let cookie_value = make_auth_cookie(&slug, &state.config.token);
        let secure_flag = if state.config.base_url.starts_with("https://") {
            "; Secure"
        } else {
            ""
        };
        let cookie_header = format!(
            "twofold_auth_{}={}; Path=/{}; HttpOnly; SameSite=Strict; Max-Age=3600{}",
            slug, cookie_value, slug, secure_flag
        );
        Ok((
            StatusCode::SEE_OTHER,
            [
                (axum::http::header::LOCATION, format!("/{slug}")),
                (axum::http::header::SET_COOKIE, cookie_header),
            ],
            "",
        )
            .into_response())
    } else {
        // Wrong password — show form again with error
        let template = PasswordTemplate {
            slug: &slug,
            base_url: state.config.base_url.trim_end_matches('/'),
            error: Some("Incorrect password"),
        };
        Ok(Html(
            template
                .render()
                .map_err(|e| AppError::Internal(format!("Template error: {e}")))?,
        )
        .into_response())
    }
}

// ── GET /:slug/full (rendered full view) ──────────────────────────────────────

/// Render the full document (including agent sections) as themed HTML.
///
/// The marker comments themselves (`<!-- @agent -->` / `<!-- @end -->`) are stripped
/// so they don't appear as visible HTML comments, but their content is included.
/// Password-protected documents still require authentication.
pub async fn get_full(
    State(state): State<AppState>,
    _rl: ReadRateLimit,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let slug_for_full = slug.clone();
    let db_full = state.db.clone();
    let doc = match tokio::task::spawn_blocking(move || db_full.get_by_slug(&slug_for_full))
        .await
        .map_err(|e| AppError::Internal(format!("Task failed: {e}")))?
        .map_err(AppError::from)?
    {
        Some(d) => d,
        None => return Ok(not_found_response()),
    };

    if is_expired(&doc) {
        return Ok(gone_response());
    }

    // Password check
    if doc.password.is_some() && !is_password_authed(&headers, &slug, &state.config.token) {
        let template = PasswordTemplate {
            slug: &slug,
            base_url: state.config.base_url.trim_end_matches('/'),
            error: None,
        };
        return Ok(Html(
            template
                .render()
                .map_err(|e| AppError::Internal(format!("Template error: {e}")))?,
        )
        .into_response());
    }

    // Same spawn_blocking pattern as get_human — syntect needs a larger stack.
    let raw_content = doc.raw_content.clone();
    let title = doc.title.clone();
    let theme = doc.theme.clone();
    let slug_owned = slug.clone();
    let expires_at = doc.expires_at.clone();
    let base_url = state.config.base_url.trim_end_matches('/').to_string();
    let base_url_clone = base_url.clone();

    let html_result = tokio::task::spawn_blocking(move || {
        let fm_result = extract_frontmatter(&raw_content).unwrap_or_else(|_| {
            crate::parser::FrontmatterResult {
                meta: None,
                body: raw_content.clone(),
                close_end_byte: None,
            }
        });

        let stripped = strip_marker_comments(&fm_result.body);
        let rendered_html = render_markdown(&stripped);
        render_themed_sync(
            &title,
            &rendered_html,
            &slug_owned,
            &theme,
            &base_url_clone,
            true,
            expires_at,
        )
    })
    .await
    .map_err(|e| AppError::Internal(format!("Render task failed: {e}")))?;

    // Add Link header pointing to the JSON API endpoint.
    let link_header = format!(
        "<{base_url}/api/v1/documents/{slug}>; rel=\"alternate\"; type=\"application/json\"",
    );
    let html_response = html_result?;
    let mut response = html_response.into_response();
    response.headers_mut().insert(
        axum::http::header::LINK,
        axum::http::HeaderValue::from_str(&link_header)
            .unwrap_or_else(|_| axum::http::HeaderValue::from_static("")),
    );
    Ok(response)
}

// ── GET /api/v1/documents/:slug (agent view) ──────────────────────────────────

/// Return the full raw source markdown.
///
/// Password-protected documents require the correct password as a query
/// parameter (`?access_token=<value>` or legacy `?password=<value>`).
/// Returns 401 with a JSON error body if the document is protected and
/// the password is missing or incorrect.
pub async fn get_agent(
    State(state): State<AppState>,
    _rl: ReadRateLimit,
    Path(slug): Path<String>,
    Query(params): Query<AgentQuery>,
) -> Result<Response, AppError> {
    let slug_for_agent = slug.clone();
    let db_agent = state.db.clone();
    let doc = tokio::task::spawn_blocking(move || db_agent.get_by_slug(&slug_for_agent))
        .await
        .map_err(|e| AppError::Internal(format!("Task failed: {e}")))?
        .map_err(AppError::from)?
        .ok_or(AppError::NotFound)?;

    if is_expired(&doc) {
        return Err(AppError::Gone);
    }

    // Password gate — same argon2 check as the human view.
    // access_token takes precedence; password is a backward-compat fallback.
    // argon2 is CPU-heavy; run off the async executor.
    if let Some(stored_hash) = &doc.password {
        let provided = params
            .access_token
            .as_deref()
            .or(params.password.as_deref());
        match provided {
            None => {
                return Err(AppError::DocumentPasswordRequired);
            }
            Some(pw) => {
                let pw_owned = pw.to_string();
                let hash_owned = stored_hash.clone();
                let verified =
                    tokio::task::spawn_blocking(move || verify_password(&pw_owned, &hash_owned))
                        .await
                        .map_err(|e| AppError::Internal(format!("Task failed: {e}")))?;
                if !verified {
                    return Err(AppError::DocumentPasswordInvalid);
                }
                // Correct password — fall through to serve content.
            }
        }
    }

    Ok(markdown_response(&strip_password_from_content(
        &doc.raw_content,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::{get, post},
        Router,
    };
    use std::sync::Arc;
    use tower::ServiceExt;

    use crate::handlers::AppState;

    fn make_test_config(token: &str) -> crate::config::ServeConfig {
        crate::config::ServeConfig {
            token: token.to_string(),
            db_path: ":memory:".to_string(),
            bind: "127.0.0.1:0".to_string(),
            base_url: "http://localhost".to_string(),
            default_theme: "clean".to_string(),
            max_size: 1_048_576,
            webhook_url: None,
            webhook_secret: None,
            reaper_interval: 3600,
            rate_limit_read: 1000,
            rate_limit_write: 1000,
            rate_limit_window: 60,
            registration_limit: 5,
            registration_mode: crate::config::RegistrationMode::Open,
        }
    }

    fn make_test_state(token: &str) -> (AppState, crate::db::Db) {
        let db = crate::db::Db::open(":memory:").expect("in-memory db");
        let config = make_test_config(token);
        let rate_limit = crate::rate_limit::RateLimitStore::new(&config);
        let state = AppState {
            db: db.clone(),
            config: Arc::new(config),
            rate_limit: rate_limit.clone(),
        };
        (state, db)
    }

    fn test_app_full(token: &str) -> Router {
        let db = crate::db::Db::open(":memory:").expect("in-memory db");
        let config = make_test_config(token);
        let rate_limit = crate::rate_limit::RateLimitStore::new(&config);
        let state = AppState {
            db,
            config: Arc::new(config),
            rate_limit: rate_limit.clone(),
        };
        Router::new()
            .route(
                "/api/v1/documents",
                post(crate::handlers::post_document).get(crate::handlers::list_documents),
            )
            .route(
                "/api/v1/documents/:slug",
                get(crate::views::get_agent)
                    .put(crate::handlers::put_document)
                    .delete(crate::handlers::delete_document),
            )
            .route("/:slug/unlock", post(crate::views::post_unlock))
            .route("/:slug/full", get(crate::views::get_full))
            .route("/:slug", get(crate::views::get_human))
            .layer(axum::Extension(rate_limit))
            .with_state(state)
    }

    /// POST a document via the full-app router and return its slug.
    async fn publish_doc_full(app: Router, token: &str, slug: &str, content: &str) -> String {
        let body = format!("---\nslug: {slug}\n---\n{content}");
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/documents")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "text/markdown")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED, "publish failed");
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        json["slug"].as_str().unwrap().to_string()
    }

    // ── Themed error page tests ───────────────────────────────────────────────

    /// GET /:nonexistent-slug → 404 with themed HTML body.
    #[tokio::test]
    async fn test_human_get_nonexistent_returns_404_with_html() {
        let token = "test-token";
        let app = test_app_full(token);

        let req = Request::builder()
            .method("GET")
            .uri("/this-slug-does-not-exist")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            content_type.contains("text/html"),
            "404 response should be HTML, got: {content_type}"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();

        assert!(
            text.contains("Document not found") || text.contains("not found"),
            "404 body should contain 'not found' text"
        );
        assert!(
            text.contains("FLINT") || text.contains("flint") || text.contains("twofold"),
            "404 body should contain footer branding"
        );
        assert!(
            text.contains("<!DOCTYPE html>"),
            "404 body should be valid HTML"
        );
    }

    /// An expired document via GET /:slug → 410 with themed HTML body.
    #[tokio::test]
    async fn test_human_get_expired_returns_410_with_html() {
        let token = "test-token";

        let db = crate::db::Db::open(":memory:").expect("in-memory db");
        let config = make_test_config(token);

        // Insert an already-expired document directly.
        let expired_doc = crate::db::DocumentRecord {
            id: "expired-slug".to_string(),
            slug: "expired-slug".to_string(),
            title: "Expired Doc".to_string(),
            raw_content: "# Expired\nThis document has expired.".to_string(),
            theme: "clean".to_string(),
            password: None,
            description: None,
            created_at: "2020-01-01T00:00:00Z".to_string(),
            expires_at: Some("2020-06-01T00:00:00Z".to_string()), // firmly in the past
            updated_at: "2020-01-01T00:00:00Z".to_string(),
        };
        db.insert_document(&expired_doc)
            .expect("insert expired doc");

        let rate_limit = crate::rate_limit::RateLimitStore::new(&config);
        let state = AppState {
            db,
            config: Arc::new(config),
            rate_limit: rate_limit.clone(),
        };
        let app = Router::new()
            .route(
                "/api/v1/documents",
                post(crate::handlers::post_document).get(crate::handlers::list_documents),
            )
            .route(
                "/api/v1/documents/:slug",
                get(crate::views::get_agent)
                    .put(crate::handlers::put_document)
                    .delete(crate::handlers::delete_document),
            )
            .route("/:slug/unlock", post(crate::views::post_unlock))
            .route("/:slug/full", get(crate::views::get_full))
            .route("/:slug", get(crate::views::get_human))
            .layer(axum::Extension(rate_limit))
            .with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/expired-slug")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::GONE);

        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            content_type.contains("text/html"),
            "410 response should be HTML, got: {content_type}"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();

        assert!(
            text.contains("expired") || text.contains("Expired"),
            "410 body should contain 'expired' text"
        );
        assert!(
            text.contains("FLINT") || text.contains("flint") || text.contains("twofold"),
            "410 body should contain footer branding"
        );
        assert!(
            text.contains("<!DOCTYPE html>"),
            "410 body should be valid HTML"
        );
    }

    /// Password-protected doc that doesn't exist returns 404, not a password prompt.
    #[tokio::test]
    async fn test_nonexistent_protected_slug_returns_404_not_password_prompt() {
        let token = "test-token";
        let app = test_app_full(token);

        let req = Request::builder()
            .method("GET")
            .uri("/nonexistent-protected-slug")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();

        assert!(
            !text.contains(r#"type="password""#),
            "nonexistent slug should not show password prompt"
        );
        assert!(
            text.contains("not found") || text.contains("Not found"),
            "should contain not found message"
        );
    }

    // ── Content negotiation tests ─────────────────────────────────────────────

    /// Accept: text/html → returns HTML (existing behaviour unchanged).
    #[tokio::test]
    async fn test_content_neg_html_accept_returns_html() {
        let token = "test-token";
        let app = test_app_full(token);
        let slug = publish_doc_full(app.clone(), token, "cn-html", "# Hello").await;

        let req = Request::builder()
            .method("GET")
            .uri(format!("/{slug}"))
            .header("Accept", "text/html,application/xhtml+xml,*/*;q=0.9")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ct.contains("text/html"), "expected HTML, got {ct}");
    }

    /// Accept: application/json → returns JSON with document fields.
    #[tokio::test]
    async fn test_content_neg_json_accept_returns_json() {
        let token = "test-token";
        let app = test_app_full(token);
        let slug =
            publish_doc_full(app.clone(), token, "cn-json", "# Hello\n\nAgent content.").await;

        let req = Request::builder()
            .method("GET")
            .uri(format!("/{slug}"))
            .header("Accept", "application/json")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ct.contains("application/json"), "expected JSON, got {ct}");
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["slug"].as_str().unwrap(), "cn-json");
        assert!(json["content"].as_str().unwrap().contains("Hello"));
    }

    /// Accept: text/markdown → returns raw markdown source.
    #[tokio::test]
    async fn test_content_neg_markdown_accept_returns_markdown() {
        let token = "test-token";
        let app = test_app_full(token);
        let slug = publish_doc_full(app.clone(), token, "cn-md-accept", "# Markdown test").await;

        let req = Request::builder()
            .method("GET")
            .uri(format!("/{slug}"))
            .header("Accept", "text/markdown")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ct.contains("text/markdown"), "expected markdown, got {ct}");
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = std::str::from_utf8(&bytes).unwrap();
        assert!(
            body.contains("Markdown test"),
            "expected raw markdown in body"
        );
    }

    /// Bot User-Agent with no Accept → returns JSON.
    #[tokio::test]
    async fn test_content_neg_bot_ua_returns_json() {
        let token = "test-token";
        let app = test_app_full(token);
        let slug = publish_doc_full(app.clone(), token, "cn-bot", "# Bot content").await;

        let req = Request::builder()
            .method("GET")
            .uri(format!("/{slug}"))
            .header("User-Agent", "GPTBot/1.0")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            ct.contains("application/json"),
            "expected JSON for bot UA, got {ct}"
        );
    }

    /// Browser Accept + bot User-Agent → Accept wins, returns HTML.
    #[tokio::test]
    async fn test_content_neg_html_accept_beats_bot_ua() {
        let token = "test-token";
        let app = test_app_full(token);
        let slug = publish_doc_full(app.clone(), token, "cn-ua-html", "# Dev inspect").await;

        let req = Request::builder()
            .method("GET")
            .uri(format!("/{slug}"))
            .header("Accept", "text/html")
            .header("User-Agent", "ClaudeBot/1.0")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            ct.contains("text/html"),
            "Accept: text/html should beat bot UA, got {ct}"
        );
    }

    /// GET /:slug.md → returns raw markdown.
    #[tokio::test]
    async fn test_slug_md_route_returns_markdown() {
        let token = "test-token";
        let app = test_app_full(token);
        let slug = publish_doc_full(app.clone(), token, "cn-dotmd", "# Dotmd test").await;

        let req = Request::builder()
            .method("GET")
            .uri(format!("/{slug}.md"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            ct.contains("text/markdown"),
            "expected markdown content-type, got {ct}"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = std::str::from_utf8(&bytes).unwrap();
        assert!(body.contains("Dotmd test"), "expected raw markdown in body");
    }

    // ── Password cookie / unlock tests ────────────────────────────────────────

    /// Correct password → 303 redirect with Set-Cookie header.
    #[tokio::test]
    async fn post_unlock_happy_path() {
        let token = "test-token";
        let password = "correct-horse";
        let slug = "locked-doc";

        let db = crate::db::Db::open(":memory:").expect("in-memory db");
        let hash = crate::helpers::hash_password(password).expect("hash");
        let doc = crate::db::DocumentRecord {
            id: slug.to_string(),
            slug: slug.to_string(),
            title: "Locked".to_string(),
            raw_content: format!("---\npassword: {hash}\n---\n# Secret"),
            theme: "clean".to_string(),
            password: Some(hash),
            description: None,
            created_at: "2024-01-01T00:00:00Z".to_string(),
            expires_at: None,
            updated_at: "2024-01-01T00:00:00Z".to_string(),
        };
        db.insert_document(&doc).expect("insert");

        let config = make_test_config(token);
        let rate_limit = crate::rate_limit::RateLimitStore::new(&config);
        let state = AppState {
            db,
            config: Arc::new(config),
            rate_limit: rate_limit.clone(),
        };
        let app = Router::new()
            .route("/:slug/unlock", post(crate::views::post_unlock))
            .layer(axum::Extension(rate_limit))
            .with_state(state);

        let body = format!("password={password}");
        let req = Request::builder()
            .method("POST")
            .uri(format!("/{slug}/unlock"))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(
            resp.status(),
            StatusCode::SEE_OTHER,
            "correct password should redirect"
        );
        let set_cookie = resp
            .headers()
            .get("set-cookie")
            .expect("Set-Cookie header should be present");
        let cookie_str = set_cookie.to_str().unwrap();
        assert!(
            cookie_str.contains(&format!("twofold_auth_{}", slug)),
            "cookie name should include slug, got: {cookie_str}"
        );
    }

    /// Wrong password → 200 with password form and error message.
    #[tokio::test]
    async fn post_unlock_wrong_password() {
        let token = "test-token";
        let password = "correct-horse";
        let slug = "locked-doc-2";

        let db = crate::db::Db::open(":memory:").expect("in-memory db");
        let hash = crate::helpers::hash_password(password).expect("hash");
        let doc = crate::db::DocumentRecord {
            id: slug.to_string(),
            slug: slug.to_string(),
            title: "Locked".to_string(),
            raw_content: format!("---\npassword: {hash}\n---\n# Secret"),
            theme: "clean".to_string(),
            password: Some(hash),
            description: None,
            created_at: "2024-01-01T00:00:00Z".to_string(),
            expires_at: None,
            updated_at: "2024-01-01T00:00:00Z".to_string(),
        };
        db.insert_document(&doc).expect("insert");

        let config = make_test_config(token);
        let rate_limit = crate::rate_limit::RateLimitStore::new(&config);
        let state = AppState {
            db,
            config: Arc::new(config),
            rate_limit: rate_limit.clone(),
        };
        let app = Router::new()
            .route("/:slug/unlock", post(crate::views::post_unlock))
            .layer(axum::Extension(rate_limit))
            .with_state(state);

        let req = Request::builder()
            .method("POST")
            .uri(format!("/{slug}/unlock"))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(Body::from("password=wrong-password"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_ne!(
            resp.status(),
            StatusCode::SEE_OTHER,
            "wrong password should not redirect"
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(
            text.contains("Incorrect password"),
            "should show error message, got: {text}"
        );
    }

    /// strip_password_from_content removes only the password line, not others.
    #[test]
    fn strip_password_preserves_other_frontmatter() {
        let raw = "---\ntitle: My Doc\npassword: secret123\ntheme: clean\n---\n# Body";
        let stripped = strip_password_from_content(raw);

        assert!(
            !stripped.contains("password:"),
            "password line should be removed"
        );
        assert!(
            stripped.contains("title: My Doc"),
            "title should be preserved"
        );
        assert!(
            stripped.contains("theme: clean"),
            "theme should be preserved"
        );
        assert!(
            stripped.contains("# Body"),
            "body content should be preserved"
        );
        assert!(stripped.starts_with("---"), "opening fence should remain");
    }

    /// GET /api/v1/documents/:slug with password-protected doc, correct password.
    #[tokio::test]
    async fn test_agent_get_protected_doc_correct_password_returns_content() {
        let token = "test-token";
        let (state, _db) = make_test_state(token);
        let rate_limit = state.rate_limit.clone();
        let app = Router::new()
            .route(
                "/api/v1/documents",
                post(crate::handlers::post_document).get(crate::handlers::list_documents),
            )
            .route(
                "/api/v1/documents/:slug",
                get(crate::views::get_agent)
                    .put(crate::handlers::put_document)
                    .delete(crate::handlers::delete_document),
            )
            .layer(axum::Extension(rate_limit))
            .with_state(state);

        // Publish a password-protected doc.
        let body = "---\nslug: pw-correct\npassword: hunter2\n---\nSecret content.";
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/documents")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "text/markdown")
            .body(Body::from(body))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/documents/pw-correct?password=hunter2")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("Secret content."));
    }

    /// GET /api/v1/documents/:slug with wrong password → 401.
    #[tokio::test]
    async fn test_agent_get_protected_doc_wrong_password_returns_401() {
        let token = "test-token";
        let (state, _db) = make_test_state(token);
        let rate_limit = state.rate_limit.clone();
        let app = Router::new()
            .route(
                "/api/v1/documents",
                post(crate::handlers::post_document).get(crate::handlers::list_documents),
            )
            .route(
                "/api/v1/documents/:slug",
                get(crate::views::get_agent)
                    .put(crate::handlers::put_document)
                    .delete(crate::handlers::delete_document),
            )
            .layer(axum::Extension(rate_limit))
            .with_state(state);

        let body = "---\nslug: pw-wrong\npassword: hunter2\n---\nSecret.";
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/documents")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "text/markdown")
            .body(Body::from(body))
            .unwrap();
        app.clone().oneshot(req).await.unwrap();

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/documents/pw-wrong?password=wrongpass")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"].as_str().unwrap(), "Invalid password");
    }

    /// GET /api/v1/documents/:slug with no password → 401.
    #[tokio::test]
    async fn test_agent_get_protected_doc_no_password_returns_401() {
        let token = "test-token";
        let (state, _db) = make_test_state(token);
        let rate_limit = state.rate_limit.clone();
        let app = Router::new()
            .route(
                "/api/v1/documents",
                post(crate::handlers::post_document).get(crate::handlers::list_documents),
            )
            .route(
                "/api/v1/documents/:slug",
                get(crate::views::get_agent)
                    .put(crate::handlers::put_document)
                    .delete(crate::handlers::delete_document),
            )
            .layer(axum::Extension(rate_limit))
            .with_state(state);

        let body = "---\nslug: pw-none\npassword: hunter2\n---\nSecret.";
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/documents")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "text/markdown")
            .body(Body::from(body))
            .unwrap();
        app.clone().oneshot(req).await.unwrap();

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/documents/pw-none")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"].as_str().unwrap(), "Password required");
    }

    /// GET /api/v1/documents/:slug unprotected doc works without password.
    #[tokio::test]
    async fn test_agent_get_unprotected_doc_works_without_password() {
        let token = "test-token";
        let (state, _db) = make_test_state(token);
        let rate_limit = state.rate_limit.clone();
        let app = Router::new()
            .route(
                "/api/v1/documents",
                post(crate::handlers::post_document).get(crate::handlers::list_documents),
            )
            .route(
                "/api/v1/documents/:slug",
                get(crate::views::get_agent)
                    .put(crate::handlers::put_document)
                    .delete(crate::handlers::delete_document),
            )
            .layer(axum::Extension(rate_limit))
            .with_state(state);

        let body = "---\nslug: no-pw-doc\n---\n# Public\nOpen content.";
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/documents")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "text/markdown")
            .body(Body::from(body))
            .unwrap();
        app.clone().oneshot(req).await.unwrap();

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/documents/no-pw-doc")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("Open content."));
    }
}
