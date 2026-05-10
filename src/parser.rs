use regex::Regex;
use std::sync::OnceLock;

/// Compiled open-marker regex, initialized once at first use.
static OPEN_RE: OnceLock<Regex> = OnceLock::new();
/// Compiled close-marker regex, initialized once at first use.
static CLOSE_RE: OnceLock<Regex> = OnceLock::new();

fn open_re() -> &'static Regex {
    // Pattern is a compile-time constant; unwrap is infallible.
    OPEN_RE.get_or_init(|| Regex::new(r"^\s*<!--\s*@agent\s*-->\s*$").unwrap())
}

fn close_re() -> &'static Regex {
    CLOSE_RE.get_or_init(|| Regex::new(r"^\s*<!--\s*@end\s*-->\s*$").unwrap())
}

/// Result of parsing a document's marker sections.
///
/// Contract: `human` contains only the lines visible to human readers,
/// with marker lines removed and agent-only content excluded.
/// The agent corpus is NOT stored here — the raw source is returned directly
/// from the database for agent/raw endpoints.
pub struct ParseResult {
    /// Human-visible markdown (markers stripped, agent sections excluded).
    pub human: String,
}

/// Parse a markdown document, splitting out agent-only sections.
///
/// Algorithm (line-based regex per spec):
/// 1. Split source into lines
/// 2. Walk lines, tracking `in_agent_section`
/// 3. Open marker → set in_agent_section = true, skip line
/// 4. Close marker → set in_agent_section = false, skip line
/// 5. In agent section → exclude from human corpus
/// 6. Not in agent section → include in human corpus
/// 7. Join human lines with newline
///
/// Logs a tracing::warn if EOF is reached while in_agent_section is true.
///
/// Structural note: regexes are compiled once via OnceLock, not per call.
pub fn parse_document(source: &str, slug: &str) -> ParseResult {
    let open = open_re();
    let close = close_re();

    let mut human_lines: Vec<&str> = Vec::new();
    let mut in_agent_section = false;

    for line in source.lines() {
        if !in_agent_section && open.is_match(line) {
            // Opening marker: enter agent section, skip the marker line
            in_agent_section = true;
        } else if in_agent_section && close.is_match(line) {
            // Closing marker: exit agent section, skip the marker line
            in_agent_section = false;
        } else if !in_agent_section {
            // Human-visible line (includes orphan @end markers, which comrak
            // renders as invisible HTML comments — correct per spec)
            human_lines.push(line);
        }
        // else: inside agent section, non-marker line → excluded from human corpus
    }

    if in_agent_section {
        tracing::warn!(
            slug = %slug,
            "Unclosed @agent marker in document — all content after the open marker \
             is hidden from human view"
        );
    }

    // source.lines() strips trailing newlines; rejoin with \n.
    // A trailing \n difference vs the original is acceptable for rendered output.
    ParseResult {
        human: human_lines.join("\n"),
    }
}

/// Extract the title from the first H1 heading in the source.
///
/// Searches line-by-line for `^# <content>` (first match wins).
/// Title extraction happens on the raw source BEFORE splitting — an H1 inside
/// an agent section is still a valid title (per spec).
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
        let src = "A.\n<!-- @agent -->\nH1.\n<!-- @end -->\nB.\n<!-- @agent -->\nH2.\n<!-- @end -->\nC.";
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
    fn extract_title_basic() {
        assert_eq!(extract_title("# Hello World\n\nContent.", "fallback"), "Hello World");
    }

    #[test]
    fn extract_title_falls_back_to_slug() {
        assert_eq!(extract_title("No heading here.", "my-slug"), "my-slug");
    }

    #[test]
    fn extract_title_in_agent_section() {
        let src = "<!-- @agent -->\n# Hidden Title\n<!-- @end -->\nContent.";
        assert_eq!(extract_title(src, "fallback"), "Hidden Title");
    }
}
