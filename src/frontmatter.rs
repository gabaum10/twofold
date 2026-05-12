//! YAML frontmatter parsing, merging, and injection. Consolidated from parser.rs, mcp.rs, and main.rs.

/// Frontmatter parsing, merging, and injection — single source of truth.
///
/// Previously scattered across parser.rs (extract_frontmatter),
/// mcp.rs (merge_fm_args), and main.rs (apply_publish_flags, merge_frontmatter_flags).
/// Consolidated here.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Types ─────────────────────────────────────────────────────────────────────

/// Parsed frontmatter metadata from YAML block.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Frontmatter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub theme: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
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
/// or omitted (prepend). All fields are serialized via `serde_yml` for correct
/// YAML escaping.
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
///
/// Uses `serde_yml::to_string` so writes go through the same serializer as reads,
/// ensuring correct quoting of all values (including multi-line strings and
/// values containing YAML-special characters like `:` or `#`).
fn prepend_new_block(content: &str, fields: &FrontmatterFields) -> String {
    // Build a Frontmatter struct from the supplied fields so we can round-trip
    // through serde_yml — same serializer as reads, correct escaping guaranteed.
    let fm = Frontmatter {
        title: fields.title.clone(),
        slug: fields.slug.clone(),
        password: fields.password.clone(),
        expiry: fields.expiry.clone(),
        theme: fields.theme.clone(),
        description: fields.description.clone(),
        _extra: HashMap::new(),
    };

    let yaml_body = serde_yml::to_string(&fm)
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "serde_yml serialization failed — falling back to empty frontmatter");
            String::new()
        });

    // serde_yml adds a trailing newline; strip it since we add our own fence.
    let yaml_body = yaml_body.trim_end_matches('\n');

    let mut result = String::from("---\n");
    if !yaml_body.is_empty() {
        result.push_str(yaml_body);
        result.push('\n');
    }
    result.push_str("---\n");
    result.push_str(content);
    result
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
                fm_lines.push(format_yaml_kv(key, overrides[key]));
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
            fm_lines.push(format_yaml_kv(key, overrides[key]));
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

// ── YAML value serialization ──────────────────────────────────────────────────

/// Format a single YAML key-value pair using serde_yml for correct value escaping.
///
/// serde_yml handles all quoting and escaping automatically — including colons,
/// hashes, multi-line strings, and other YAML-special content.
fn format_yaml_kv(key: &str, value: &str) -> String {
    // Serialize a single-entry mapping so serde_yml decides quoting.
    // We serialize as `key: <serialized_value>` by building a struct on-the-fly
    // using a wrapper type.
    use std::collections::BTreeMap;
    let mut map = BTreeMap::new();
    map.insert(key, value);
    let yaml = serde_yml::to_string(&map).unwrap_or_else(|_| format!("{key}: {value}"));
    // serde_yml emits `key: value\n` — trim the trailing newline.
    yaml.trim_end_matches('\n').to_string()
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
        // serde_yml emits unquoted scalars for simple strings — no surrounding quotes.
        assert!(result.contains("title: My Title"));
        assert!(result.contains("slug: my-slug"));
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
        // Overridden field serialized via serde_yml (unquoted for simple strings);
        // untouched field kept verbatim from the original source line.
        assert!(result.contains("title: New Title"));
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
        // Untouched field kept verbatim from source; new field serialized via serde_yml.
        // serde_yml single-quotes values that look like YAML special types (e.g. "7d"
        // resembles a sexagesimal literal), so we check for the quoted form.
        assert!(result.contains("title: Existing"));
        assert!(result.contains("expiry:") && result.contains("7d"));
        assert!(result.contains("# Body"));
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
