//! YAML frontmatter parsing, merging, and injection. Consolidated from parser.rs, mcp.rs, and main.rs.

/// Frontmatter parsing, merging, and injection — single source of truth.
///
/// Previously scattered across parser.rs (extract_frontmatter),
/// mcp.rs (merge_fm_args, yaml_escape_value), and main.rs
/// (apply_publish_flags, merge_frontmatter_flags). Consolidated here.
use serde::Deserialize;
use std::collections::HashMap;

// ── Types ─────────────────────────────────────────────────────────────────────

/// Parsed frontmatter metadata from YAML block.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Frontmatter {
    pub title: Option<String>,
    pub slug: Option<String>,
    pub theme: Option<String>,
    pub expiry: Option<String>,
    pub password: Option<String>,
    pub description: Option<String>,
    /// Catch-all for unknown fields (forward-compatible).
    #[serde(flatten)]
    pub _extra: HashMap<String, serde_yml::Value>,
}

/// Result of extracting frontmatter from raw content.
#[derive(Debug)]
pub struct FrontmatterResult {
    /// Parsed frontmatter (None if no frontmatter block present).
    pub meta: Option<Frontmatter>,
    /// Document body (everything after the closing `---`, or the full content if no frontmatter).
    pub body: String,
}

/// Fields to inject or merge into a document's frontmatter.
///
/// Only `Some` fields are written. `None` fields are left untouched (merge)
/// or omitted (prepend). All fields are escaped via `yaml_escape_value`.
#[derive(Debug, Default)]
pub struct FrontmatterFields {
    pub title: Option<String>,
    pub slug: Option<String>,
    pub password: Option<String>,
    pub expiry: Option<String>,
    pub theme: Option<String>,
    pub description: Option<String>,
}

// ── Extraction ────────────────────────────────────────────────────────────────

/// Extract YAML frontmatter from the beginning of a document.
///
/// Frontmatter rules:
/// 1. Must be the very first thing in the document (line 1 starts with `---`).
/// 2. Closed by a second `---` on its own line.
/// 3. If no closing `---` found, treat entire document as body (no frontmatter).
/// 4. Empty frontmatter (`---\n---`) is valid — returns default Frontmatter.
///
/// Returns Err with a descriptive message if YAML parsing fails.
pub fn extract_frontmatter(source: &str) -> Result<FrontmatterResult, String> {
    let lines: Vec<&str> = source.lines().collect();

    // Must start with `---` on the first line
    if lines.is_empty() || lines[0].trim() != "---" {
        return Ok(FrontmatterResult {
            meta: None,
            body: source.to_string(),
        });
    }

    // Find closing `---`
    let mut close_idx = None;
    for (i, line) in lines.iter().enumerate().skip(1) {
        if line.trim() == "---" {
            close_idx = Some(i);
            break;
        }
    }

    let close_idx = match close_idx {
        Some(i) => i,
        None => {
            // No closing fence — treat as no frontmatter
            return Ok(FrontmatterResult {
                meta: None,
                body: source.to_string(),
            });
        }
    };

    // Extract YAML content between fences
    let yaml_content = lines[1..close_idx].join("\n");

    // Parse YAML (empty string parses to None in serde_yaml, handle explicitly)
    let meta: Frontmatter = if yaml_content.trim().is_empty() {
        Frontmatter::default()
    } else {
        serde_yml::from_str(&yaml_content).map_err(|e| format!("Invalid frontmatter: {e}"))?
    };

    // Body is everything after the closing `---`
    let body = if close_idx + 1 < lines.len() {
        let remaining = &lines[close_idx + 1..];
        remaining.join("\n")
    } else {
        String::new()
    };

    Ok(FrontmatterResult {
        meta: Some(meta),
        body,
    })
}

// ── Injection / Merge ─────────────────────────────────────────────────────────

/// Apply frontmatter fields to a document.
///
/// - If no fields are set: return content unchanged.
/// - If content has existing frontmatter: merge fields in (supplied fields win on conflict).
/// - If content has no frontmatter: prepend a new frontmatter block.
pub fn apply_frontmatter(content: &str, fields: FrontmatterFields) -> String {
    let has_any = fields.title.is_some()
        || fields.slug.is_some()
        || fields.password.is_some()
        || fields.expiry.is_some()
        || fields.theme.is_some()
        || fields.description.is_some();

    if !has_any {
        return content.to_string();
    }

    if content.trim_start().starts_with("---") {
        merge_into_existing(content, &fields)
    } else {
        prepend_new_block(content, &fields)
    }
}

/// Prepend a fresh frontmatter block to content that has none.
fn prepend_new_block(content: &str, fields: &FrontmatterFields) -> String {
    let mut fm = String::from("---\n");
    if let Some(ref t) = fields.title {
        fm.push_str(&format!("title: {}\n", yaml_escape_value(t)));
    }
    if let Some(ref s) = fields.slug {
        fm.push_str(&format!("slug: {}\n", yaml_escape_value(s)));
    }
    if let Some(ref p) = fields.password {
        fm.push_str(&format!("password: {}\n", yaml_escape_value(p)));
    }
    if let Some(ref ex) = fields.expiry {
        fm.push_str(&format!("expiry: {}\n", yaml_escape_value(ex)));
    }
    if let Some(ref th) = fields.theme {
        fm.push_str(&format!("theme: {}\n", yaml_escape_value(th)));
    }
    if let Some(ref d) = fields.description {
        fm.push_str(&format!("description: {}\n", yaml_escape_value(d)));
    }
    fm.push_str("---\n");
    fm.push_str(content);
    fm
}

/// Merge supplied fields into an existing frontmatter block. Supplied fields win on conflict.
///
/// Strategy: parse the existing block line-by-line, replace matching keys, append any absent.
/// Only operates on the simple single-line scalar values twofold uses.
fn merge_into_existing(content: &str, fields: &FrontmatterFields) -> String {
    let lines: Vec<&str> = content.lines().collect();

    // Find closing `---` of the frontmatter block.
    let mut close_idx = None;
    for (i, line) in lines.iter().enumerate().skip(1) {
        if line.trim() == "---" {
            close_idx = Some(i);
            break;
        }
    }

    let close_idx = match close_idx {
        Some(i) => i,
        None => {
            // No closing fence — fall back to prepend.
            return prepend_new_block(content, fields);
        }
    };

    // Build override map: key -> value.
    let mut overrides: HashMap<&str, &str> = HashMap::new();
    if let Some(ref t) = fields.title {
        overrides.insert("title", t.as_str());
    }
    if let Some(ref s) = fields.slug {
        overrides.insert("slug", s.as_str());
    }
    if let Some(ref p) = fields.password {
        overrides.insert("password", p.as_str());
    }
    if let Some(ref ex) = fields.expiry {
        overrides.insert("expiry", ex.as_str());
    }
    if let Some(ref th) = fields.theme {
        overrides.insert("theme", th.as_str());
    }
    if let Some(ref d) = fields.description {
        overrides.insert("description", d.as_str());
    }

    let mut written_keys: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut fm_lines: Vec<String> = Vec::new();

    // First line is always `---`.
    fm_lines.push(lines[0].to_string());

    // Process existing frontmatter lines (1..close_idx).
    for line in &lines[1..close_idx] {
        let mut replaced = false;
        for &key in overrides.keys() {
            let prefix = format!("{}:", key);
            if line.trim_start().starts_with(&prefix) {
                fm_lines.push(format!("{}: {}", key, yaml_escape_value(overrides[key])));
                written_keys.insert(key);
                replaced = true;
                break;
            }
        }
        if !replaced {
            fm_lines.push(line.to_string());
        }
    }

    // Append any fields not already in the frontmatter.
    for &key in overrides.keys() {
        if !written_keys.contains(key) {
            fm_lines.push(format!("{}: {}", key, yaml_escape_value(overrides[key])));
        }
    }

    // Closing `---`.
    fm_lines.push("---".to_string());

    // Append the body (everything after close_idx).
    let body_lines = &lines[close_idx + 1..];
    let mut result = fm_lines.join("\n");
    if !body_lines.is_empty() {
        result.push('\n');
        result.push_str(&body_lines.join("\n"));
    }
    result
}

// ── YAML value escaping ───────────────────────────────────────────────────────

/// Escape a string value for safe YAML injection.
///
/// Wraps the value in double quotes and escapes internal double quotes and
/// backslashes. Handles values containing colons, hashes, or other YAML
/// special characters that would break unquoted scalar parsing.
///
/// Limitation: multi-line values (containing \n) have their newlines replaced
/// with spaces. Slugs cannot contain newlines (validation prevents it).
/// Titles with newlines are unusual and the trade-off is acceptable.
pub fn yaml_escape_value(s: &str) -> String {
    let s = s.replace('\n', " ").replace('\r', "");
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

// ── Marker directive check ────────────────────────────────────────────────────

/// Returns true if the string contains a marker directive on its own line.
///
/// Matches `<!-- @agent -->` or `<!-- @end -->` appearing as a complete line
/// (possibly with surrounding whitespace), to prevent breaking out of the
/// agent layer containment.
pub fn contains_marker_directive(s: &str) -> bool {
    s.lines().any(|line| {
        let t = line.trim();
        t == "<!-- @agent -->" || t == "<!-- @end -->"
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // extract_frontmatter

    #[test]
    fn frontmatter_basic() {
        let src = "---\ntitle: Hello\nslug: hello-world\n---\n\n# Body";
        let result = extract_frontmatter(src).unwrap();
        let meta = result.meta.unwrap();
        assert_eq!(meta.title.as_deref(), Some("Hello"));
        assert_eq!(meta.slug.as_deref(), Some("hello-world"));
        assert!(result.body.contains("# Body"));
        assert!(!result.body.contains("---"));
    }

    #[test]
    fn frontmatter_empty_block() {
        let src = "---\n---\n\n# Just body";
        let result = extract_frontmatter(src).unwrap();
        assert!(result.meta.is_some());
        assert!(result.body.contains("# Just body"));
    }

    #[test]
    fn no_frontmatter() {
        let src = "# No frontmatter\n\nJust content.";
        let result = extract_frontmatter(src).unwrap();
        assert!(result.meta.is_none());
        assert_eq!(result.body, src);
    }

    #[test]
    fn frontmatter_unclosed() {
        let src = "---\ntitle: Broken\nNo closing fence.";
        let result = extract_frontmatter(src).unwrap();
        assert!(result.meta.is_none());
        assert_eq!(result.body, src);
    }

    #[test]
    fn frontmatter_invalid_yaml() {
        let src = "---\n[invalid: yaml: broken\n---\n\nBody.";
        let result = extract_frontmatter(src);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid frontmatter"));
    }

    // apply_frontmatter — no fields

    #[test]
    fn apply_no_fields_returns_unchanged() {
        let content = "# Hello\n\nContent.";
        let result = apply_frontmatter(content, FrontmatterFields::default());
        assert_eq!(result, content);
    }

    // apply_frontmatter — prepend (no existing frontmatter)

    #[test]
    fn apply_prepends_when_no_existing_fm() {
        let content = "# Hello\n\nContent.";
        let fields = FrontmatterFields {
            title: Some("My Title".to_string()),
            slug: Some("my-slug".to_string()),
            ..Default::default()
        };
        let result = apply_frontmatter(content, fields);
        assert!(result.starts_with("---\n"));
        assert!(result.contains("title: \"My Title\""));
        assert!(result.contains("slug: \"my-slug\""));
        assert!(result.contains("# Hello"));
    }

    // apply_frontmatter — merge (existing frontmatter, field overrides)

    #[test]
    fn apply_merges_into_existing_fm() {
        let content = "---\ntitle: Old Title\nslug: old-slug\n---\n# Body";
        let fields = FrontmatterFields {
            title: Some("New Title".to_string()),
            ..Default::default()
        };
        let result = apply_frontmatter(content, fields);
        // Overridden field gets quoted; untouched field is kept verbatim from source.
        assert!(result.contains("title: \"New Title\""));
        assert!(result.contains("slug: old-slug"));
        assert!(result.contains("# Body"));
    }

    #[test]
    fn apply_appends_missing_field_to_existing_fm() {
        let content = "---\ntitle: Existing\n---\n# Body";
        let fields = FrontmatterFields {
            expiry: Some("7d".to_string()),
            ..Default::default()
        };
        let result = apply_frontmatter(content, fields);
        // Untouched field kept verbatim; new field gets quoted.
        assert!(result.contains("title: Existing"));
        assert!(result.contains("expiry: \"7d\""));
        assert!(result.contains("# Body"));
    }

    // yaml_escape_value

    #[test]
    fn yaml_escape_basic() {
        assert_eq!(yaml_escape_value("hello"), "\"hello\"");
    }

    #[test]
    fn yaml_escape_quotes() {
        assert_eq!(yaml_escape_value("say \"hi\""), "\"say \\\"hi\\\"\"");
    }

    #[test]
    fn yaml_escape_backslash() {
        assert_eq!(yaml_escape_value("a\\b"), "\"a\\\\b\"");
    }

    #[test]
    fn yaml_escape_newline_flattened() {
        assert_eq!(yaml_escape_value("line1\nline2"), "\"line1 line2\"");
    }

    #[test]
    fn yaml_escape_colon() {
        // Colon in a value would break unquoted YAML; verify it's safely wrapped.
        assert_eq!(yaml_escape_value("key: val"), "\"key: val\"");
    }

    // contains_marker_directive

    #[test]
    fn marker_directive_detected() {
        assert!(contains_marker_directive(
            "some text\n<!-- @agent -->\nmore"
        ));
        assert!(contains_marker_directive("<!-- @end -->"));
    }

    #[test]
    fn marker_directive_inline_not_detected() {
        assert!(!contains_marker_directive("Use `<!-- @agent -->` inline."));
    }

    #[test]
    fn marker_directive_absent() {
        assert!(!contains_marker_directive(
            "# Plain markdown\n\nNo markers."
        ));
    }
}
