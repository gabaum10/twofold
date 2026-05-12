//! Markdown marker parsing (`@agent`/`@end`/`@instructions`), slug validation, expiry parsing. Re-exports frontmatter types.

// Re-export frontmatter types and extraction from the canonical module.
// handlers.rs and service.rs import these from parser — keep the path stable.
#[allow(unused_imports)]
pub use crate::frontmatter::Frontmatter;
pub use crate::frontmatter::{extract_frontmatter, FrontmatterResult}; // re-exported for callers that may reference parser::Frontmatter

// ── Marker Parsing ───────────────────────────────────────────────────────────
// No-regex approach from the raccoon assembly. Whitespace tolerance via trim.
// Matches: <!--\s*@agent\s*--> and <!--\s*@end\s*--> (line must be ONLY the marker).

/// Check if a line is a marker comment (e.g., `@agent` or `@end`).
///
/// The line must consist of ONLY `<!-- {tag} -->` with optional whitespace.
/// No regex needed: strip the HTML comment delimiters, trim, compare.
fn is_marker(line: &str, tag: &str) -> bool {
    let t = line.trim();
    if !t.starts_with("<!--") || !t.ends_with("-->") {
        return false;
    }
    let inner = &t["<!--".len()..t.len() - "-->".len()];
    inner.trim() == tag
}

/// Result of parsing a document's marker sections.
///
/// Contract: `human` contains only the lines visible to human readers,
/// with marker lines removed and agent-only content excluded.
/// `agent` contains only the lines inside `<!-- @agent -->` ... `<!-- @end -->`
/// blocks, or `None` if no agent section exists.
pub struct ParseResult {
    /// Human-visible markdown (markers stripped, agent sections excluded).
    pub human: String,
    /// Agent-only markdown (content between marker pairs), or None if absent.
    pub agent: Option<String>,
}

/// Parse a markdown document, splitting out agent-only sections.
///
/// Algorithm (line-based, no regex):
/// 1. Split source into lines
/// 2. Walk lines, tracking `in_agent_section`
/// 3. Open marker -> set in_agent_section = true, skip line
/// 4. Close marker -> set in_agent_section = false, skip line
/// 5. In agent section -> exclude from human corpus, include in agent corpus
/// 6. Not in agent section -> include in human corpus
/// 7. Join corpora with newline; agent is None if the corpus is empty
///
/// Logs a tracing::warn if EOF is reached while in_agent_section is true.
pub fn parse_document(source: &str, slug: &str) -> ParseResult {
    let mut human_lines: Vec<&str> = Vec::new();
    let mut agent_lines: Vec<&str> = Vec::new();
    let mut in_agent_section = false;

    for line in source.lines() {
        if !in_agent_section && is_marker(line, "@agent") {
            in_agent_section = true;
        } else if in_agent_section && is_marker(line, "@end") {
            in_agent_section = false;
        } else if in_agent_section {
            agent_lines.push(line);
        } else {
            human_lines.push(line);
        }
    }

    if in_agent_section {
        tracing::warn!(
            slug = %slug,
            "Unclosed @agent marker in document — all content after the open marker \
             is hidden from human view"
        );
    }

    ParseResult {
        human: human_lines.join("\n"),
        agent: if agent_lines.is_empty() {
            None
        } else {
            Some(agent_lines.join("\n"))
        },
    }
}

/// Extract the title from the first H1 heading in the source.
///
/// Searches line-by-line for `^# <content>` (first match wins).
/// Title extraction happens on the body (after frontmatter stripped).
///
/// Returns the slug as a fallback if no H1 is found.
pub fn extract_title(source: &str, slug: &str) -> String {
    for line in source.lines() {
        if let Some(rest) = line.strip_prefix("# ") {
            let title = rest.trim();
            if !title.is_empty() {
                return title.to_string();
            }
        }
    }
    slug.to_string()
}

/// Parse an expiry duration string (e.g., "7d", "24h", "30m", "2w").
///
/// Returns the duration in seconds, or an error message.
pub fn parse_expiry(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("Expiry must not be empty".to_string());
    }

    let (num_str, unit) = s.split_at(s.len() - 1);
    let num: u64 = num_str
        .parse()
        .map_err(|_| format!("Invalid expiry format: '{s}' (expected e.g., 7d, 24h, 30m, 2w)"))?;

    let seconds = match unit {
        "m" => num * 60,
        "h" => num * 3600,
        "d" => num * 86400,
        "w" => num * 604800,
        _ => {
            return Err(format!(
                "Invalid expiry unit: '{unit}' (expected m, h, d, or w)"
            ))
        }
    };

    let min_seconds = 5 * 60; // 5 minutes
    let max_seconds = 365 * 86400; // 365 days

    if seconds < min_seconds {
        return Err("Expiry must be at least 5 minutes".to_string());
    }
    if seconds > max_seconds {
        return Err("Expiry must not exceed 365 days".to_string());
    }

    Ok(seconds)
}

/// Validate a custom slug.
///
/// Rules:
/// 1. Allowed characters: [a-zA-Z0-9-]
/// 2. Length: 3-128 characters
/// 3. Must not start or end with hyphen
/// 4. Must not be a reserved path
pub fn validate_slug(slug: &str) -> Result<(), String> {
    if slug.len() < 3 {
        return Err("Slug must be at least 3 characters".to_string());
    }
    if slug.len() > 128 {
        return Err("Slug must not exceed 128 characters".to_string());
    }
    if slug.starts_with('-') || slug.ends_with('-') {
        return Err("Slug must not start or end with a hyphen".to_string());
    }

    for ch in slug.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '-' {
            return Err(format!(
                "Slug contains invalid character '{ch}' (only alphanumeric and hyphen allowed)"
            ));
        }
    }

    let reserved = [
        "api",
        "health",
        "status",
        "favicon.ico",
        "robots.txt",
        "authorize",
        "oauth",
        "mcp",
        "icon.png",
        ".well-known",
    ];
    if reserved.contains(&slug) {
        return Err(format!("Slug '{slug}' is reserved"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_single_agent_section() {
        let src = "Before.\n<!-- @agent -->\nHidden.\n<!-- @end -->\nAfter.";
        let r = parse_document(src, "test");
        assert!(r.human.contains("Before."));
        assert!(r.human.contains("After."));
        assert!(!r.human.contains("Hidden."));
        assert!(!r.human.contains("@agent"));
    }

    #[test]
    fn strips_multiple_sections() {
        let src =
            "A.\n<!-- @agent -->\nH1.\n<!-- @end -->\nB.\n<!-- @agent -->\nH2.\n<!-- @end -->\nC.";
        let r = parse_document(src, "test");
        assert!(r.human.contains("A.") && r.human.contains("B.") && r.human.contains("C."));
        assert!(!r.human.contains("H1.") && !r.human.contains("H2."));
    }

    #[test]
    fn tight_spacing_markers() {
        let src = "X.\n<!--@agent-->\nHidden.\n<!--@end-->\nY.";
        let r = parse_document(src, "test");
        assert!(r.human.contains("X.") && r.human.contains("Y."));
        assert!(!r.human.contains("Hidden."));
    }

    #[test]
    fn loose_spacing_markers() {
        let src = "X.\n<!--  @agent  -->\nHidden.\n<!--  @end  -->\nY.";
        let r = parse_document(src, "test");
        assert!(r.human.contains("X.") && r.human.contains("Y."));
        assert!(!r.human.contains("Hidden."));
    }

    #[test]
    fn inline_marker_not_parsed() {
        let src = "Use `<!-- @agent -->` inline.\nStill visible.";
        let r = parse_document(src, "test");
        assert!(r.human.contains("Use"));
        assert!(r.human.contains("Still visible."));
    }

    #[test]
    fn orphan_close_ignored() {
        let src = "A.\n<!-- @end -->\nB.";
        let r = parse_document(src, "test");
        assert!(r.human.contains("A.") && r.human.contains("B."));
    }

    #[test]
    fn unclosed_hides_remainder() {
        let src = "Visible.\n<!-- @agent -->\nHidden forever.";
        let r = parse_document(src, "test");
        assert!(r.human.contains("Visible."));
        assert!(!r.human.contains("Hidden forever."));
    }

    #[test]
    fn nested_agent_marker_treated_as_content() {
        let src = "Before.\n<!-- @agent -->\nAgent line 1.\n<!-- @agent -->\nAgent line 2.\n<!-- @end -->\nAfter.";
        let r = parse_document(src, "test");
        assert!(r.human.contains("Before."));
        assert!(r.human.contains("After."));
        assert!(!r.human.contains("Agent line 1."));
        assert!(!r.human.contains("Agent line 2."));
    }

    #[test]
    fn extract_title_basic() {
        assert_eq!(
            extract_title("# Hello World\n\nContent.", "fallback"),
            "Hello World"
        );
    }

    #[test]
    fn extract_title_falls_back_to_slug() {
        assert_eq!(extract_title("No heading here.", "my-slug"), "my-slug");
    }

    #[test]
    fn extract_title_in_agent_section() {
        let src = "<!-- @agent -->\n# Hidden Title\n<!-- @end -->\nContent.";
        // extract_title works on raw source, finds H1 regardless of markers
        assert_eq!(extract_title(src, "fallback"), "Hidden Title");
    }

    // Expiry parsing tests

    #[test]
    fn parse_expiry_valid() {
        assert_eq!(parse_expiry("30m").unwrap(), 1800);
        assert_eq!(parse_expiry("1h").unwrap(), 3600);
        assert_eq!(parse_expiry("7d").unwrap(), 604800);
        assert_eq!(parse_expiry("2w").unwrap(), 1209600);
    }

    #[test]
    fn parse_expiry_too_short() {
        assert!(parse_expiry("4m").is_err());
    }

    #[test]
    fn parse_expiry_too_long() {
        assert!(parse_expiry("366d").is_err());
    }

    #[test]
    fn parse_expiry_invalid_unit() {
        assert!(parse_expiry("7x").is_err());
    }

    // Slug validation tests

    #[test]
    fn validate_slug_valid() {
        assert!(validate_slug("hello-world").is_ok());
        assert!(validate_slug("abc").is_ok());
        assert!(validate_slug("MyReport2024").is_ok());
    }

    #[test]
    fn validate_slug_too_short() {
        assert!(validate_slug("ab").is_err());
    }

    #[test]
    fn validate_slug_invalid_chars() {
        assert!(validate_slug("has spaces").is_err());
        assert!(validate_slug("under_score").is_err());
    }

    #[test]
    fn validate_slug_hyphen_start_end() {
        assert!(validate_slug("-starts").is_err());
        assert!(validate_slug("ends-").is_err());
    }

    #[test]
    fn validate_slug_reserved() {
        assert!(validate_slug("api").is_err());
    }

    #[test]
    fn validate_slug_reserved_oauth_routes() {
        assert!(validate_slug("authorize").is_err());
        assert!(validate_slug("oauth").is_err());
        assert!(validate_slug("mcp").is_err());
        assert!(validate_slug("icon.png").is_err());
        assert!(validate_slug(".well-known").is_err());
    }
}
