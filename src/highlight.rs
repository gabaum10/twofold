//! Syntax highlighting via syntect. Lazy-initialized via `OnceLock`; theme-aware light/dark palettes.

/// Syntax highlighting via syntect.
///
/// Loaded once at first use via OnceLock (Rust 1.70+, no lazy_static dep).
/// `SyntaxSet::load_defaults_newlines()` takes ~10ms on first call — this
/// happens on the first human view render, not at server startup, which keeps
/// startup fast. All subsequent calls hit the initialized OnceLock instantly.
use std::sync::OnceLock;
use syntect::highlighting::ThemeSet;
use syntect::html::highlighted_html_for_string;
use syntect::parsing::SyntaxSet;

static SYNTAX_SET: OnceLock<SyntaxSet> = OnceLock::new();
static THEME_SET: OnceLock<ThemeSet> = OnceLock::new();

fn syntax_set() -> &'static SyntaxSet {
    SYNTAX_SET.get_or_init(SyntaxSet::load_defaults_newlines)
}

fn theme_set() -> &'static ThemeSet {
    THEME_SET.get_or_init(ThemeSet::load_defaults)
}

/// Highlight a code block. Returns highlighted HTML or None if the language
/// is unknown/unspecified (caller renders as plain <pre><code>).
///
/// Production note: syntect is O(n) on input. For extremely large code blocks
/// (>100KB) this is still fast but measurable. No cap implemented — syntect
/// handles large inputs safely.
pub fn highlight_code(code: &str, lang: &str) -> Option<String> {
    if lang.is_empty() {
        return None;
    }

    let ss = syntax_set();
    let ts = theme_set();

    // find_syntax_by_token handles common aliases (js → javascript, etc.)
    let syntax = ss.find_syntax_by_token(lang)?;

    // InspiredGitHub is a clean light theme. Falls back to first available if missing.
    let theme = ts
        .themes
        .get("InspiredGitHub")
        .or_else(|| ts.themes.values().next())?;

    // highlighted_html_for_string returns Ok always for valid syntax refs.
    // Err path is documented as unreachable for bundled themes, but we handle it.
    highlighted_html_for_string(code, ss, syntax, theme).ok()
}

/// Highlight a code block for dark themes.
pub fn highlight_code_dark(code: &str, lang: &str) -> Option<String> {
    if lang.is_empty() {
        return None;
    }

    let ss = syntax_set();
    let ts = theme_set();

    let syntax = ss.find_syntax_by_token(lang)?;

    // base16-ocean.dark is a solid dark theme bundled with syntect defaults.
    let theme = ts
        .themes
        .get("base16-ocean.dark")
        .or_else(|| ts.themes.values().next())?;

    highlighted_html_for_string(code, ss, syntax, theme).ok()
}

/// Post-process comrak HTML: replace plain code blocks with syntect-highlighted HTML.
///
/// Comrak produces: <pre><code class="language-rust">...</code></pre>
/// We find these blocks and replace the inner content with highlighted spans.
/// Code blocks without a language class are left untouched.
///
/// This is a string-based post-processor (not AST-level) — simple and sufficient
/// for the twofold use case. The main risk is malformed HTML from comrak, but
/// comrak's output is well-formed by contract.
///
/// `dark`: if true, use dark syntax theme; if false, use light theme.
pub fn apply_syntax_highlighting(html: &str, dark: bool) -> String {
    let mut result = String::with_capacity(html.len() + 512);
    let mut remaining = html;

    loop {
        // Find the next <pre><code ...> block.
        // comrak emits: <pre><code class="language-rust">...</code></pre>
        let pre_start = match remaining.find("<pre><code") {
            Some(i) => i,
            None => {
                result.push_str(remaining);
                break;
            }
        };

        // Emit everything before this block
        result.push_str(&remaining[..pre_start]);
        remaining = &remaining[pre_start..];

        // Find end of opening <code ...> tag.
        // We must skip past the <pre> tag to find the end of the <code> tag.
        // The string starts with "<pre><code", so we look for '>' after the
        // "<code" part (which starts at offset 5).
        let code_tag_start = 5; // "<pre>" is 5 chars, then "<code" starts
        let tag_end = match remaining[code_tag_start..].find('>') {
            Some(i) => code_tag_start + i,
            None => {
                result.push_str(remaining);
                break;
            }
        };

        let open_tag = &remaining[..=tag_end]; // e.g. <pre><code class="language-rust">

        // Extract language from class="language-{lang}"
        let lang = extract_language(open_tag);

        // Find the closing </code></pre>
        let close = "</code></pre>";
        let code_start = tag_end + 1;
        let close_pos = match remaining[code_start..].find(close) {
            Some(i) => code_start + i,
            None => {
                // Malformed HTML from comrak — emit as-is
                result.push_str(remaining);
                break;
            }
        };

        let raw_code = &remaining[code_start..close_pos];

        // Decode HTML entities in the code content (comrak escapes < > & in code blocks)
        let decoded = decode_html_entities(raw_code);

        // Try to highlight
        let highlighted = if let Some(ref l) = lang {
            if dark {
                highlight_code_dark(&decoded, l)
            } else {
                highlight_code(&decoded, l)
            }
        } else {
            None
        };

        match highlighted {
            Some(hl) => {
                // syntect produces a full <pre ...>...</pre> block
                result.push_str(&hl);
            }
            None => {
                // No language or unknown language — emit original unchanged
                result.push_str(&remaining[..close_pos + close.len()]);
            }
        }

        remaining = &remaining[close_pos + close.len()..];
    }

    result
}

/// Extract the language token from a <pre><code ...> opening tag.
/// Looks for class="language-{lang}" or class='language-{lang}'.
fn extract_language(tag: &str) -> Option<String> {
    // Look for 'language-' prefix in the class attribute
    let prefix = "language-";
    let pos = tag.find(prefix)?;
    let after = &tag[pos + prefix.len()..];

    // Language ends at the next '"', '\'', or whitespace
    let end = after
        .find(|c: char| c == '"' || c == '\'' || c.is_whitespace())
        .unwrap_or(after.len());

    let lang = &after[..end];
    if lang.is_empty() {
        None
    } else {
        Some(lang.to_string())
    }
}

/// Minimal HTML entity decoder for code block content.
/// Comrak escapes exactly these four in code blocks.
fn decode_html_entities(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
}

// Note: syntect's highlighted_html_for_string generates inline styles on each
// span element. No separate CSS injection is needed — all styling is self-contained
// in the generated HTML. This means highlighting works with any template and
// all highlighting CSS is inlined by design.
