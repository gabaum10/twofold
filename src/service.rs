//! Document CRUD business logic. Async functions over `Db` + `ServeConfig`. Shared by HTTP handlers and MCP HTTP transport.

/// Service layer — async document CRUD over `Db` and `ServeConfig`.
///
/// No axum extractors. No HTTP. No Principal in the function signatures where
/// it is not needed for logic — callers supply the principal fields they need
/// (display_name, ip_address) for audit entries.
///
/// All blocking SQLite work is offloaded to `tokio::task::spawn_blocking` so
/// callers in async handler contexts do not block a Tokio worker thread.
///
/// This is the single place where document business logic lives. Both the HTTP
/// handlers and the MCP HTTP transport call into this layer. The confused-deputy
/// path where mcp_http.rs looped back through the HTTP API is eliminated here.
use crate::{
    auth::Principal,
    config::ServeConfig,
    db::{AuditEntry, Db, DocumentRecord, DocumentSummary},
    handlers::AppError,
    helpers::hash_password,
    parser::{
        compose_document, extract_frontmatter, extract_title, parse_document, parse_expiry,
        validate_slug,
    },
    webhook,
};

/// URL-safe slug alphabet (mirrors handlers.rs — kept in sync).
const SLUG_ALPHABET: [char; 63] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
    'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B',
    'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
    'V', 'W', 'X', 'Y', 'Z', '-',
];

// ── Request / Result types ────────────────────────────────────────────────────

/// Input to [`publish`].
pub struct PublishRequest {
    pub raw_content: String,
    pub principal: Principal,
    pub client_ip: String,
}

/// Input to [`update`].
pub struct UpdateRequest {
    pub raw_content: String,
    pub principal: Principal,
    pub client_ip: String,
}

/// Output from [`publish`] and [`update`].
pub struct PublishResult {
    pub slug: String,
    pub title: String,
    pub url: String,
    pub api_url: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub description: Option<String>,
}

// ── publish ───────────────────────────────────────────────────────────────────

/// Create a new document. Handles slug collision retry.
///
/// Returns `AppError::Conflict` if a custom slug is already in use.
/// Returns `AppError::BadRequest` for malformed frontmatter or invalid slug.
pub async fn publish(
    db: &Db,
    config: &ServeConfig,
    req: PublishRequest,
) -> Result<PublishResult, AppError> {
    if req.raw_content.trim().is_empty() {
        return Err(AppError::BadRequest(
            "Request body must not be empty".to_string(),
        ));
    }

    let fm_result = extract_frontmatter(&req.raw_content).map_err(AppError::BadRequest)?;
    let meta = fm_result.meta.unwrap_or_default();
    let body_text = &fm_result.body;

    // Slug: custom (validated) or random nanoid.
    let slug = if let Some(ref custom_slug) = meta.slug {
        validate_slug(custom_slug).map_err(AppError::BadRequest)?;
        custom_slug.clone()
    } else {
        nanoid::nanoid!(10, &SLUG_ALPHABET)
    };

    let title = meta
        .title
        .unwrap_or_else(|| extract_title(body_text).unwrap_or_else(|| slug.clone()));

    let theme = meta.theme.unwrap_or_else(|| config.default_theme.clone());

    let now = crate::helpers::chrono_now();

    let expires_at = match meta.expiry.as_deref() {
        Some(exp) => {
            let seconds = parse_expiry(exp).map_err(AppError::BadRequest)?;
            Some(add_seconds_to_now(seconds))
        }
        None => None,
    };

    let password_hash = match meta.password.as_deref() {
        Some(pw) if !pw.is_empty() => Some(hash_password(pw)?),
        _ => None,
    };

    let doc = DocumentRecord {
        id: slug.clone(),
        slug: slug.clone(),
        title: title.clone(),
        raw_content: req.raw_content,
        theme,
        password: password_hash,
        description: meta.description.clone(),
        created_at: now.clone(),
        expires_at: expires_at.clone(),
        updated_at: now.clone(),
    };

    // Insert with slug-collision retry. Blocking SQLite work runs off the async executor.
    let db_clone = db.clone();
    let custom_slug = meta.slug.clone();
    let final_doc = tokio::task::spawn_blocking(move || -> Result<DocumentRecord, AppError> {
        match db_clone.insert_document(&doc) {
            Ok(()) => Ok(doc),
            Err(e) if crate::helpers::is_unique_violation(&e) => {
                if custom_slug.is_some() {
                    return Err(AppError::Conflict(format!(
                        "Slug '{}' is already in use",
                        doc.slug
                    )));
                }
                let new_slug = nanoid::nanoid!(10, &SLUG_ALPHABET);
                let retry_doc = DocumentRecord {
                    id: new_slug.clone(),
                    slug: new_slug.clone(),
                    ..doc
                };
                db_clone.insert_document(&retry_doc).map_err(|e2| {
                    tracing::error!(error = %e2, "Slug collision retry failed");
                    AppError::Internal("Failed to allocate unique slug".to_string())
                })?;
                Ok(retry_doc)
            }
            Err(e) => Err(AppError::from(e)),
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("Task failed: {e}")))??;

    let base = config.base_url.trim_end_matches('/');
    let url = format!("{base}/{}", final_doc.slug);
    let api_url = format!("{base}/api/v1/documents/{}", final_doc.slug);

    // Webhook — fire-and-forget.
    if let Some(ref wh_url) = config.webhook_url {
        webhook::dispatch_webhook(
            wh_url.clone(),
            config.webhook_secret.clone(),
            "document.created",
            now.clone(),
            webhook::WebhookDocument {
                slug: final_doc.slug.clone(),
                title: final_doc.title.clone(),
                url: url.clone(),
                api_url: api_url.clone(),
            },
        );
    }

    // Audit — single write site.
    let audit_entry = AuditEntry {
        id: nanoid::nanoid!(10),
        timestamp: crate::helpers::chrono_now(),
        action: "create".to_string(),
        slug: final_doc.slug.clone(),
        token_name: req.principal.display_name,
        ip_address: req.client_ip,
    };
    let db_clone2 = db.clone();
    // Fire-and-forget: errors are logged in the map_err closures; the Result is intentionally discarded.
    tokio::task::spawn_blocking(move || db_clone2.insert_audit_entry(&audit_entry))
        .await
        .map_err(|e| tracing::error!(error = %e, "Audit task panicked"))
        .and_then(|r| r.map_err(|e| tracing::error!(error = %e, "Failed to write audit entry")))
        .ok();

    Ok(PublishResult {
        slug: final_doc.slug,
        title: final_doc.title,
        url,
        api_url,
        created_at: final_doc.created_at,
        expires_at: final_doc.expires_at,
        description: final_doc.description,
    })
}

// ── update ────────────────────────────────────────────────────────────────────

/// Update an existing document by slug.
///
/// Returns `AppError::NotFound` if the slug does not exist.
/// Returns `AppError::Gone` if the document has expired.
pub async fn update(
    db: &Db,
    config: &ServeConfig,
    slug: &str,
    req: UpdateRequest,
) -> Result<PublishResult, AppError> {
    if req.raw_content.trim().is_empty() {
        return Err(AppError::BadRequest(
            "Request body must not be empty".to_string(),
        ));
    }

    // Fetch the existing document off the executor.
    let slug_owned = slug.to_string();
    let db_clone = db.clone();
    let existing = tokio::task::spawn_blocking(move || db_clone.get_by_slug(&slug_owned))
        .await
        .map_err(|e| AppError::Internal(format!("Task failed: {e}")))?
        .map_err(AppError::from)?
        .ok_or(AppError::NotFound)?;

    if crate::helpers::is_expired(&existing) {
        return Err(AppError::Gone);
    }

    let fm_result = extract_frontmatter(&req.raw_content).map_err(AppError::BadRequest)?;
    let frontmatter_close_byte = fm_result.close_end_byte;
    let meta = fm_result.meta.unwrap_or_default();
    let body_text = &fm_result.body;

    // Merge with existing for fields absent from the incoming payload.
    // Re-parses existing.raw_content so agent-block preservation is symmetric
    // with the new payload.
    let existing_fm = extract_frontmatter(&existing.raw_content).map_err(AppError::BadRequest)?;
    let existing_body = &existing_fm.body;
    let existing_parsed = parse_document(existing_body, slug);
    let incoming_parsed = parse_document(body_text, slug);

    // Three-way agent merge:
    //   None        => preserve existing (the bug fix)
    //   Some("")    => intentional clear
    //   Some(x)     => use incoming
    //
    // Agent content is trimmed before storage to prevent blank-line accumulation
    // on round-trips: parse_document captures blank lines adjacent to markers as
    // part of the agent content, so composing without trimming would prepend and
    // append extra blank lines each update cycle.
    let final_agent: Option<String> = match incoming_parsed.agent.as_deref() {
        None => existing_parsed
            .agent
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        Some(s) if s.trim().is_empty() => None,
        Some(s) => Some(s.trim().to_string()),
    };

    // Recompose body (sans frontmatter) with merged agent layer.
    let merged_body = compose_document(&incoming_parsed.human, final_agent.as_deref());

    // Recover the leading frontmatter portion of req.raw_content byte-exactly,
    // so user's original YAML formatting is preserved. Use the byte offset that
    // extract_frontmatter already computed — this avoids re-scanning and cannot
    // miscount YAML values that happen to trim to "---".
    let frontmatter_prefix = frontmatter_close_byte
        .map(|end| &req.raw_content[..end])
        .unwrap_or("");
    let raw_to_store = format!("{frontmatter_prefix}{merged_body}");

    let title = meta
        .title
        .unwrap_or_else(|| extract_title(body_text).unwrap_or_else(|| existing.title.clone()));

    let theme = meta.theme.unwrap_or_else(|| existing.theme.clone());

    let now = crate::helpers::chrono_now();

    let expires_at = match meta.expiry.as_deref() {
        Some(exp) if !exp.is_empty() => {
            let seconds = parse_expiry(exp).map_err(AppError::BadRequest)?;
            Some(add_seconds_to_now(seconds))
        }
        Some(_) => None,
        None => existing.expires_at.clone(),
    };

    let password_hash = match meta.password.as_deref() {
        Some(pw) if !pw.is_empty() => Some(hash_password(pw)?),
        Some(_) => None,
        None => existing.password.clone(),
    };

    let updated_doc = DocumentRecord {
        id: existing.id.clone(),
        slug: slug.to_string(),
        title: title.clone(),
        raw_content: raw_to_store,
        theme,
        password: password_hash,
        description: meta.description.clone().or(existing.description.clone()),
        created_at: existing.created_at.clone(),
        expires_at: expires_at.clone(),
        updated_at: now.clone(),
    };

    // Write the update off the executor.
    let db_clone2 = db.clone();
    let slug_owned2 = slug.to_string();
    let updated_doc_clone = updated_doc.clone();
    tokio::task::spawn_blocking(move || {
        db_clone2.update_document(&slug_owned2, &updated_doc_clone)
    })
    .await
    .map_err(|e| AppError::Internal(format!("Task failed: {e}")))?
    .map_err(AppError::from)?;

    let base = config.base_url.trim_end_matches('/');
    let url = format!("{base}/{slug}");
    let api_url = format!("{base}/api/v1/documents/{slug}");

    // Webhook — fire-and-forget.
    if let Some(ref wh_url) = config.webhook_url {
        webhook::dispatch_webhook(
            wh_url.clone(),
            config.webhook_secret.clone(),
            "document.updated",
            now.clone(),
            webhook::WebhookDocument {
                slug: slug.to_string(),
                title: updated_doc.title.clone(),
                url: url.clone(),
                api_url: api_url.clone(),
            },
        );
    }

    // Audit — single write site.
    let audit_entry = AuditEntry {
        id: nanoid::nanoid!(10),
        timestamp: now,
        action: "update".to_string(),
        slug: slug.to_string(),
        token_name: req.principal.display_name,
        ip_address: req.client_ip,
    };
    let db_clone3 = db.clone();
    // Fire-and-forget: errors are logged in the map_err closures; the Result is intentionally discarded.
    tokio::task::spawn_blocking(move || db_clone3.insert_audit_entry(&audit_entry))
        .await
        .map_err(|e| tracing::error!(error = %e, "Audit task panicked"))
        .and_then(|r| r.map_err(|e| tracing::error!(error = %e, "Failed to write audit entry")))
        .ok();

    Ok(PublishResult {
        slug: slug.to_string(),
        title: updated_doc.title,
        url,
        api_url,
        created_at: existing.created_at,
        expires_at: updated_doc.expires_at,
        description: updated_doc.description,
    })
}

// ── delete ────────────────────────────────────────────────────────────────────

/// Delete a document by slug.
///
/// Returns `AppError::NotFound` if the slug does not exist.
/// Expired documents are deleted regardless of expiry status.
pub async fn delete(
    db: &Db,
    config: &ServeConfig,
    slug: &str,
    principal: &Principal,
    client_ip: &str,
) -> Result<(), AppError> {
    // Fetch + delete off the executor in one spawn_blocking.
    let slug_owned = slug.to_string();
    let db_clone = db.clone();
    let existing = tokio::task::spawn_blocking(move || {
        let existing = db_clone
            .get_by_slug(&slug_owned)?
            .ok_or(AppError::NotFound)?;
        db_clone
            .delete_by_slug(&slug_owned)
            .map_err(AppError::from)?;
        Ok::<_, AppError>(existing)
    })
    .await
    .map_err(|e| AppError::Internal(format!("Task failed: {e}")))??;

    let now = crate::helpers::chrono_now();

    // Webhook — fire-and-forget.
    if let Some(ref wh_url) = config.webhook_url {
        let base = config.base_url.trim_end_matches('/');
        webhook::dispatch_webhook(
            wh_url.clone(),
            config.webhook_secret.clone(),
            "document.deleted",
            now.clone(),
            webhook::WebhookDocument {
                slug: existing.slug.clone(),
                title: existing.title.clone(),
                url: format!("{base}/{}", existing.slug),
                api_url: format!("{base}/api/v1/documents/{}", existing.slug),
            },
        );
    }

    // Audit — single write site.
    let audit_entry = AuditEntry {
        id: nanoid::nanoid!(10),
        timestamp: now,
        action: "delete".to_string(),
        slug: slug.to_string(),
        token_name: principal.display_name.clone(),
        ip_address: client_ip.to_string(),
    };
    let db_clone2 = db.clone();
    // Fire-and-forget: errors are logged in the map_err closures; the Result is intentionally discarded.
    tokio::task::spawn_blocking(move || db_clone2.insert_audit_entry(&audit_entry))
        .await
        .map_err(|e| tracing::error!(error = %e, "Audit task panicked"))
        .and_then(|r| r.map_err(|e| tracing::error!(error = %e, "Failed to write audit entry")))
        .ok();

    Ok(())
}

// ── get ───────────────────────────────────────────────────────────────────────

/// Retrieve a document record by slug.
///
/// Returns `AppError::NotFound` if the slug does not exist.
/// Returns `AppError::Gone` if the document has expired.
pub async fn get(db: &Db, slug: &str) -> Result<DocumentRecord, AppError> {
    let slug_owned = slug.to_string();
    let db_clone = db.clone();
    let doc = tokio::task::spawn_blocking(move || db_clone.get_by_slug(&slug_owned))
        .await
        .map_err(|e| AppError::Internal(format!("Task failed: {e}")))?
        .map_err(AppError::from)?
        .ok_or(AppError::NotFound)?;
    if crate::helpers::is_expired(&doc) {
        return Err(AppError::Gone);
    }
    Ok(doc)
}

// ── list ──────────────────────────────────────────────────────────────────────

/// List documents with pagination.
///
/// Limit is capped at 100 server-side by the db layer.
pub async fn list(
    db: &Db,
    limit: u32,
    offset: u32,
) -> Result<(Vec<DocumentSummary>, u64), AppError> {
    let db_clone = db.clone();
    tokio::task::spawn_blocking(move || db_clone.list_documents(limit, offset))
        .await
        .map_err(|e| AppError::Internal(format!("Task failed: {e}")))?
        .map_err(AppError::from)
}

// ── internal helpers ──────────────────────────────────────────────────────────

fn add_seconds_to_now(seconds: u64) -> String {
    let future = chrono::Utc::now() + chrono::Duration::seconds(seconds as i64);
    future.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{Principal, PrincipalKind};
    use crate::config::ServeConfig;
    use crate::db::Db;

    /// Minimal `ServeConfig` for tests — no webhook, no auth required in service layer.
    fn test_config() -> ServeConfig {
        ServeConfig {
            token: "test-token".to_string(),
            bind: "127.0.0.1:3000".to_string(),
            db_path: ":memory:".to_string(),
            base_url: "http://localhost:3000".to_string(),
            max_size: 1_048_576,
            reaper_interval: 60,
            default_theme: "clean".to_string(),
            webhook_url: None,
            webhook_secret: None,
            rate_limit_read: 60,
            rate_limit_write: 30,
            rate_limit_window: 60,
            registration_limit: 5,
            registration_mode: crate::config::RegistrationMode::Open,
        }
    }

    fn test_principal() -> Principal {
        Principal {
            kind: PrincipalKind::Admin,
            scopes: vec![],
            display_name: "test".to_string(),
        }
    }

    /// Publish a document and return its slug.
    async fn do_publish(db: &Db, config: &ServeConfig, body: &str) -> String {
        let req = PublishRequest {
            raw_content: body.to_string(),
            principal: test_principal(),
            client_ip: "127.0.0.1".to_string(),
        };
        publish(db, config, req)
            .await
            .expect("publish should succeed")
            .slug
    }

    /// Update a document by slug.
    async fn do_update(db: &Db, config: &ServeConfig, slug: &str, body: &str) {
        let req = UpdateRequest {
            raw_content: body.to_string(),
            principal: test_principal(),
            client_ip: "127.0.0.1".to_string(),
        };
        update(db, config, slug, req)
            .await
            .expect("update should succeed");
    }

    // ── Agent preservation tests ──────────────────────────────────────────────

    /// Core bug fix: updating with a body that has no agent block must preserve
    /// the existing agent layer.
    #[tokio::test]
    async fn update_preserves_agent_when_absent() {
        let db = Db::open(":memory:").expect("in-memory db");
        let config = test_config();

        let initial = "# Doc\n\nHuman content.\n\n<!-- @agent -->\n\nold agent\n\n<!-- @end -->\n";
        let slug = do_publish(&db, &config, initial).await;

        // Update with body that has no agent block.
        do_update(&db, &config, &slug, "# Doc\n\nUpdated human content.").await;

        let doc = get(&db, &slug).await.expect("doc should exist");
        let fm_result = crate::parser::extract_frontmatter(&doc.raw_content).unwrap();
        let parsed = crate::parser::parse_document(&fm_result.body, &slug);

        // parse_document captures blank lines adjacent to markers as part of the
        // agent content; trim before asserting.
        assert_eq!(
            parsed.agent.as_deref().map(str::trim),
            Some("old agent"),
            "agent layer must be preserved when incoming body has no marker block"
        );
    }

    /// Explicit clear: an empty agent block (only whitespace inside) should clear
    /// the agent layer.
    #[tokio::test]
    async fn update_clears_agent_when_empty_block() {
        let db = Db::open(":memory:").expect("in-memory db");
        let config = test_config();

        let initial = "# Doc\n\n<!-- @agent -->\n\nold agent\n\n<!-- @end -->\n";
        let slug = do_publish(&db, &config, initial).await;

        // Update with an empty agent block.
        let clear_body = "# Doc\n\nHuman content.\n\n<!-- @agent -->\n\n   \n\n<!-- @end -->\n";
        do_update(&db, &config, &slug, clear_body).await;

        let doc = get(&db, &slug).await.expect("doc should exist");
        let fm_result = crate::parser::extract_frontmatter(&doc.raw_content).unwrap();
        let parsed = crate::parser::parse_document(&fm_result.body, &slug);

        assert!(
            parsed.agent.is_none(),
            "agent layer must be cleared when incoming body has empty marker block"
        );
    }

    /// No regression: when the incoming body has a real agent block, it replaces
    /// the existing one.
    #[tokio::test]
    async fn update_replaces_agent_when_present() {
        let db = Db::open(":memory:").expect("in-memory db");
        let config = test_config();

        let initial = "# Doc\n\n<!-- @agent -->\n\nold agent\n\n<!-- @end -->\n";
        let slug = do_publish(&db, &config, initial).await;

        let new_body = "# Doc\n\nHuman.\n\n<!-- @agent -->\n\nnew agent\n\n<!-- @end -->\n";
        do_update(&db, &config, &slug, new_body).await;

        let doc = get(&db, &slug).await.expect("doc should exist");
        let fm_result = crate::parser::extract_frontmatter(&doc.raw_content).unwrap();
        let parsed = crate::parser::parse_document(&fm_result.body, &slug);

        // parse_document captures blank lines adjacent to markers; trim before asserting.
        assert_eq!(
            parsed.agent.as_deref().map(str::trim),
            Some("new agent"),
            "agent layer must be replaced when incoming body has a non-empty marker block"
        );
    }

    // ── Description preservation tests ───────────────────────────────────────

    /// Updating without a description in frontmatter must preserve the existing description.
    #[tokio::test]
    async fn update_preserves_description_when_absent() {
        let db = Db::open(":memory:").expect("in-memory db");
        let config = test_config();

        let initial = "---\ndescription: foo\n---\n# Doc\n\nContent.";
        let slug = do_publish(&db, &config, initial).await;

        // Update with frontmatter missing description.
        do_update(&db, &config, &slug, "# Doc\n\nUpdated content.").await;

        let doc = get(&db, &slug).await.expect("doc should exist");
        assert_eq!(
            doc.description.as_deref(),
            Some("foo"),
            "description must be preserved when incoming frontmatter omits it"
        );
    }

    // ── Title preservation tests ──────────────────────────────────────────────

    /// Updating with a body that has no H1 and no title in frontmatter must
    /// preserve the existing title (not overwrite it with the slug).
    #[tokio::test]
    async fn update_preserves_title_when_no_h1_and_no_fm_title() {
        let db = Db::open(":memory:").expect("in-memory db");
        let config = test_config();

        // Publish with a custom title in frontmatter.
        let initial = "---\ntitle: Cool Title\n---\n\nContent without H1.";
        let slug = do_publish(&db, &config, initial).await;

        // Verify it was stored.
        let doc = get(&db, &slug).await.unwrap();
        assert_eq!(doc.title, "Cool Title");

        // Update with body that has no H1 and no title in frontmatter.
        do_update(&db, &config, &slug, "Updated content without H1.").await;

        let doc = get(&db, &slug).await.expect("doc should exist");
        assert_eq!(
            doc.title, "Cool Title",
            "title must be preserved when no H1 in body and no title in frontmatter"
        );
    }

    // ── Theme preservation tests ──────────────────────────────────────────────

    /// Updating without a theme in frontmatter must preserve the existing theme,
    /// not fall back to the config default.
    #[tokio::test]
    async fn update_preserves_theme_when_absent() {
        let db = Db::open(":memory:").expect("in-memory db");
        let config = test_config(); // default_theme is "clean"

        let initial = "---\ntheme: dark\n---\n# Doc\n\nContent.";
        let slug = do_publish(&db, &config, initial).await;

        // Update with frontmatter missing theme.
        do_update(&db, &config, &slug, "# Doc\n\nUpdated content.").await;

        let doc = get(&db, &slug).await.expect("doc should exist");
        assert_eq!(
            doc.theme, "dark",
            "theme must be preserved when incoming frontmatter omits it"
        );
    }

    // ── No-regression tests ───────────────────────────────────────────────────

    /// A body with an H1 must update the title (existing title overridden).
    #[tokio::test]
    async fn update_overrides_title_when_new_h1() {
        let db = Db::open(":memory:").expect("in-memory db");
        let config = test_config();

        let initial = "---\ntitle: Old\n---\n# Old\n\nContent.";
        let slug = do_publish(&db, &config, initial).await;

        do_update(&db, &config, &slug, "# New\n\nContent.").await;

        let doc = get(&db, &slug).await.expect("doc should exist");
        assert_eq!(
            doc.title, "New",
            "title must be updated when incoming body has an H1"
        );
    }

    /// A frontmatter `theme` field must override the existing theme.
    #[tokio::test]
    async fn update_overrides_theme_when_in_fm() {
        let db = Db::open(":memory:").expect("in-memory db");
        let config = test_config();

        let initial = "---\ntheme: clean\n---\n# Doc\n\nContent.";
        let slug = do_publish(&db, &config, initial).await;

        do_update(
            &db,
            &config,
            &slug,
            "---\ntheme: dark\n---\n# Doc\n\nContent.",
        )
        .await;

        let doc = get(&db, &slug).await.expect("doc should exist");
        assert_eq!(
            doc.theme, "dark",
            "theme must be updated when incoming frontmatter includes a theme"
        );
    }

    // ── Adversarial / pressure-test cases ────────────────────────────────────

    /// Regression: H1 whose text equals the slug must update the title from the H1,
    /// not fall back to existing.title. This was broken when extract_title returned the
    /// slug as a fallback String, making the "no H1" case ambiguous. Fixed by returning
    /// Option<String> where None means "no H1 found."
    ///
    /// Scenario: existing title = "Old Custom Title", user PUTs body with H1 "# test-slug-x"
    /// where "test-slug-x" equals the actual slug. Expected: title = "test-slug-x" (from H1).
    #[tokio::test]
    async fn adversarial_h1_text_equal_to_slug_bypasses_title_update() {
        let db = Db::open(":memory:").expect("in-memory db");
        let config = test_config();

        // Publish with a custom slug so we know its value, and set a distinct title.
        let initial = "---\nslug: test-slug-x\ntitle: Old Custom Title\n---\n\nContent without H1.";
        let slug = do_publish(&db, &config, initial).await;
        assert_eq!(slug, "test-slug-x");

        // Verify stored title is "Old Custom Title".
        let doc = get(&db, &slug).await.unwrap();
        assert_eq!(doc.title, "Old Custom Title");

        // Update with an H1 whose text equals the slug: "# test-slug-x"
        // Expected: title should update to "test-slug-x" (the H1 content).
        // Fixed: extract_title returns Some("test-slug-x"), existing.title is never consulted.
        do_update(&db, &config, &slug, "# test-slug-x\n\nNew content.").await;

        let doc = get(&db, &slug).await.expect("doc should exist");
        assert_eq!(
            doc.title, "test-slug-x",
            "H1 text == slug should update title from H1, not fall back to existing.title"
        );
    }

    /// Round-trip stability: three successive identical PUTs should converge to
    /// the same stored content and produce idempotent results.
    #[tokio::test]
    async fn adversarial_round_trip_three_puts_idempotent() {
        let db = Db::open(":memory:").expect("in-memory db");
        let config = test_config();

        let initial =
            "---\ntheme: dark\ndescription: test desc\n---\n# My Doc\n\nHuman content.\n\n<!-- @agent -->\n\nagent stuff\n\n<!-- @end -->\n";
        let slug = do_publish(&db, &config, initial).await;

        // PUT #1 with body containing no agent block (agent should be preserved)
        let update_body =
            "---\ntheme: dark\ndescription: test desc\n---\n# My Doc\n\nHuman content.";
        do_update(&db, &config, &slug, update_body).await;
        let doc1 = get(&db, &slug).await.unwrap();

        // PUT #2 with the same body
        do_update(&db, &config, &slug, update_body).await;
        let doc2 = get(&db, &slug).await.unwrap();

        // PUT #3
        do_update(&db, &config, &slug, update_body).await;
        let doc3 = get(&db, &slug).await.unwrap();

        // All three should have the same raw_content (stable round-trip)
        assert_eq!(
            doc1.raw_content, doc2.raw_content,
            "round-trip: PUT#1 and PUT#2 must produce identical stored content"
        );
        assert_eq!(
            doc2.raw_content, doc3.raw_content,
            "round-trip: PUT#2 and PUT#3 must produce identical stored content (idempotent)"
        );

        // Agent should be preserved across all PUTs
        let fm = crate::parser::extract_frontmatter(&doc3.raw_content).unwrap();
        let parsed = crate::parser::parse_document(&fm.body, &slug);
        assert_eq!(
            parsed.agent.as_deref().map(str::trim),
            Some("agent stuff"),
            "agent must survive three successive PUTs without the agent block"
        );
    }

    /// Whitespace-only body must be rejected with 400 BadRequest.
    /// The is_empty() guard has been replaced with trim().is_empty() so that
    /// "   \n\n   " is caught before it can silently overwrite human-visible content.
    #[tokio::test]
    async fn update_rejects_whitespace_only_body() {
        let db = Db::open(":memory:").expect("in-memory db");
        let config = test_config();

        let initial =
            "# My Doc\n\nImportant content.\n\n<!-- @agent -->\n\nold agent\n\n<!-- @end -->\n";
        let slug = do_publish(&db, &config, initial).await;

        let req = UpdateRequest {
            raw_content: "   \n\n   ".to_string(),
            principal: test_principal(),
            client_ip: "127.0.0.1".to_string(),
        };
        let result = update(&db, &config, &slug, req).await;

        assert!(
            matches!(result, Err(AppError::BadRequest(_))),
            "whitespace-only PUT body must return 400 BadRequest, got: {:?}",
            result.map(|_| "Ok")
        );
    }

    /// publish must also reject whitespace-only body with 400 BadRequest.
    #[tokio::test]
    async fn publish_rejects_whitespace_only_body() {
        let db = Db::open(":memory:").expect("in-memory db");
        let config = test_config();

        let req = PublishRequest {
            raw_content: "   \n\n   ".to_string(),
            principal: test_principal(),
            client_ip: "127.0.0.1".to_string(),
        };
        let result = publish(&db, &config, req).await;

        assert!(
            matches!(result, Err(AppError::BadRequest(_))),
            "whitespace-only POST body must return 400 BadRequest, got: {:?}",
            result.map(|_| "Ok")
        );
    }

    /// Unclosed @agent marker in the EXISTING document: update should preserve
    /// the dangling agent content and the stored result should have a proper @end.
    #[tokio::test]
    async fn adversarial_unclosed_agent_in_existing_healed_on_update() {
        let db = Db::open(":memory:").expect("in-memory db");
        let config = test_config();

        // Publish a doc where the agent marker is not closed (simulates a corrupt/old doc).
        // We bypass the normal publish path by publishing a well-formed doc and
        // directly verifying the update behavior preserves the unclosed content.
        let initial =
            "# Doc\n\nHuman.\n\n<!-- @agent -->\n\nUnclosed agent content - no @end marker";
        let slug = do_publish(&db, &config, initial).await;

        // Update with a body that has no agent block — should preserve the existing agent.
        do_update(&db, &config, &slug, "# Doc\n\nUpdated human.").await;

        let doc = get(&db, &slug).await.unwrap();
        let fm = crate::parser::extract_frontmatter(&doc.raw_content).unwrap();
        let parsed = crate::parser::parse_document(&fm.body, &slug);

        // The unclosed agent content should be preserved (and now properly closed).
        assert_eq!(
            parsed.agent.as_deref().map(str::trim),
            Some("Unclosed agent content - no @end marker"),
            "unclosed @agent content in existing doc must be preserved and healed on update"
        );

        // The stored raw_content should now have a proper @end marker (healed).
        assert!(
            doc.raw_content.contains("<!-- @end -->"),
            "stored content after update should have a proper @end marker (unclosed marker healed)"
        );
    }

    /// Body starting with --- (horizontal rule) immediately after frontmatter
    /// closing fence should not confuse frontmatter_prefix_of.
    #[tokio::test]
    async fn adversarial_body_hr_after_frontmatter_preserved() {
        let db = Db::open(":memory:").expect("in-memory db");
        let config = test_config();

        // Publish: frontmatter, then a markdown HR (---), then content.
        let initial = "---\ntheme: dark\n---\n---\n# Below the HR\n\nContent.";
        let slug = do_publish(&db, &config, initial).await;

        // Update with same body — frontmatter_prefix_of must stop at the second ---
        // (the real closing fence), not the HR.
        do_update(
            &db,
            &config,
            &slug,
            "---\ntheme: dark\n---\n---\n# Below the HR\n\nUpdated.",
        )
        .await;

        let doc = get(&db, &slug).await.unwrap();

        // Theme should be preserved — frontmatter was parsed correctly.
        assert_eq!(
            doc.theme, "dark",
            "theme must survive update with body-leading HR"
        );

        // The body should still contain the HR.
        let fm = crate::parser::extract_frontmatter(&doc.raw_content).unwrap();
        assert!(
            fm.body.starts_with("---"),
            "body-leading HR (---) must be preserved in stored raw_content"
        );
    }

    /// Incoming body is ONLY an agent block with no human content.
    /// This is the "agent_content passed, content omitted" reverse case.
    /// The spec notes this is partially out of scope but we verify it doesn't corrupt data.
    #[tokio::test]
    async fn adversarial_incoming_body_is_only_agent_block() {
        let db = Db::open(":memory:").expect("in-memory db");
        let config = test_config();

        // Existing doc has both human content and agent layer.
        let initial =
            "# My Doc\n\nHuman content here.\n\n<!-- @agent -->\n\nold agent\n\n<!-- @end -->\n";
        let slug = do_publish(&db, &config, initial).await;

        // PUT a body that is only an agent block with no human content.
        // incoming_parsed.human = "" (empty)
        // incoming_parsed.agent = Some("new agent from update")
        // This REPLACES the agent (Some arm) and CLEARS human content.
        // Semantics: "clear human" — the user explicitly sent empty human content.
        let agent_only_body = "<!-- @agent -->\n\nnew agent from update\n\n<!-- @end -->\n";
        do_update(&db, &config, &slug, agent_only_body).await;

        let doc = get(&db, &slug).await.unwrap();
        let fm = crate::parser::extract_frontmatter(&doc.raw_content).unwrap();
        let parsed = crate::parser::parse_document(&fm.body, &slug);

        // Agent should be the new value.
        assert_eq!(
            parsed.agent.as_deref().map(str::trim),
            Some("new agent from update"),
            "agent should be replaced when incoming body contains only an agent block"
        );

        // Human content is empty (clear semantics — user sent no human content).
        assert!(
            parsed.human.trim().is_empty(),
            "human content should be empty when incoming body has no human text"
        );

        // Critical: no data corruption — the document should be retrievable.
        assert!(
            !doc.raw_content.is_empty(),
            "raw_content must not be empty after agent-only PUT"
        );
    }

    /// CRLF line endings in frontmatter must survive a round-trip through update.
    /// frontmatter_prefix_of uses split('\n') which preserves \r in chunks,
    /// so the prefix is returned with CRLF intact.
    #[tokio::test]
    async fn adversarial_crlf_frontmatter_survives_round_trip() {
        let db = Db::open(":memory:").expect("in-memory db");
        let config = test_config();

        // Initial publish without CRLF (normal).
        let initial = "---\ntheme: dark\n---\n# My Doc\n\nContent.";
        let slug = do_publish(&db, &config, initial).await;

        // Update with CRLF frontmatter (Windows-style line endings).
        let crlf_body = "---\r\ntheme: dark\r\n---\r\n# My Doc\r\n\r\nUpdated content.";
        do_update(&db, &config, &slug, crlf_body).await;

        let doc = get(&db, &slug).await.unwrap();

        // Theme must be parsed and preserved correctly despite CRLF.
        assert_eq!(
            doc.theme, "dark",
            "theme must be preserved from CRLF frontmatter"
        );

        // A second update with no frontmatter must still preserve the theme.
        do_update(&db, &config, &slug, "# My Doc\n\nSecond update.").await;
        let doc2 = get(&db, &slug).await.unwrap();
        assert_eq!(
            doc2.theme, "dark",
            "theme must survive a second update after CRLF frontmatter was stored"
        );
    }

    /// Title preserved when existing.title was itself the slug (published with no H1).
    /// This is the exact case spec mentions: "what if existing.title was itself the slug?"
    #[tokio::test]
    async fn adversarial_title_preserved_when_existing_title_was_slug() {
        let db = Db::open(":memory:").expect("in-memory db");
        let config = test_config();

        // Publish with no H1 and no title in frontmatter.
        // extract_title returns slug → title stored AS the slug.
        let initial = "---\nslug: the-slug-doc\n---\n\nJust content, no H1.";
        let slug = do_publish(&db, &config, initial).await;
        assert_eq!(slug, "the-slug-doc");

        let doc = get(&db, &slug).await.unwrap();
        // Title should be the slug itself (fallback behavior).
        assert_eq!(
            doc.title, "the-slug-doc",
            "initial publish with no H1 should store slug as title"
        );

        // Update with no H1 and no fm title.
        do_update(&db, &config, &slug, "No H1 in this update either.").await;

        let doc2 = get(&db, &slug).await.unwrap();
        // extract_title returns None (no H1), so existing.title is used as fallback.
        // existing.title == "the-slug-doc" (the slug) — result: title stays as slug.
        assert_eq!(
            doc2.title, "the-slug-doc",
            "title should remain as slug when no H1 and existing title was the slug"
        );
    }

    /// Multiple agent blocks: parse_document captures ALL agent sections and merges
    /// their content into a single agent string. After an update that omits agent blocks,
    /// the merged agent is preserved. The second @agent block is NOT human content —
    /// it is captured by the parser as part of the combined agent corpus.
    /// This test verifies no data corruption occurs and the combined agent survives.
    #[tokio::test]
    async fn adversarial_multiple_agent_blocks_combined_and_preserved() {
        let db = Db::open(":memory:").expect("in-memory db");
        let config = test_config();

        // Doc with two agent blocks — parser merges both into one agent corpus.
        let initial = "# Doc\n\nHuman.\n\n<!-- @agent -->\n\nfirst agent\n\n<!-- @end -->\n\n<!-- @agent -->\n\nsecond agent\n\n<!-- @end -->\n";
        let slug = do_publish(&db, &config, initial).await;

        // Verify the initial parse combines both agent blocks.
        let initial_doc = get(&db, &slug).await.unwrap();
        let initial_fm = crate::parser::extract_frontmatter(&initial_doc.raw_content).unwrap();
        let initial_parsed = crate::parser::parse_document(&initial_fm.body, &slug);
        // Both blocks combined into one agent string.
        let initial_agent = initial_parsed.agent.as_deref().unwrap_or("");
        assert!(
            initial_agent.contains("first agent") && initial_agent.contains("second agent"),
            "parser should combine both agent blocks: got {:?}",
            initial_agent
        );

        // Update with a body that has no agent block — combined agent must be preserved.
        do_update(&db, &config, &slug, "# Doc\n\nUpdated human.").await;

        let doc = get(&db, &slug).await.unwrap();
        let fm = crate::parser::extract_frontmatter(&doc.raw_content).unwrap();
        let parsed = crate::parser::parse_document(&fm.body, &slug);

        // Combined agent preserved (stored as single block by compose_document).
        let preserved_agent = parsed.agent.as_deref().map(str::trim).unwrap_or("");
        assert!(
            preserved_agent.contains("first agent") && preserved_agent.contains("second agent"),
            "combined agent from multiple blocks must be preserved on update: got {:?}",
            preserved_agent
        );

        // After update, content is stored as a single @agent block (normalized).
        let block_count = doc.raw_content.matches("<!-- @agent -->").count();
        assert_eq!(
            block_count, 1,
            "multiple @agent blocks should be normalized to one after update, got {}",
            block_count
        );

        // No data corruption.
        assert!(!doc.raw_content.is_empty());
    }

    /// Marker with extreme whitespace: "<!--   @agent   -->" (extra spaces inside).
    /// is_marker handles this via inner.trim() == tag. Verify through full update cycle.
    #[tokio::test]
    async fn adversarial_marker_extreme_whitespace_preserved() {
        let db = Db::open(":memory:").expect("in-memory db");
        let config = test_config();

        // Publish with loosely-spaced markers.
        let initial = "# Doc\n\nHuman.\n\n<!--  @agent  -->\n\nloose agent\n\n<!--  @end  -->\n";
        let slug = do_publish(&db, &config, initial).await;

        // Update with no agent block — loose-marker agent must be preserved.
        do_update(&db, &config, &slug, "# Doc\n\nUpdated.").await;

        let doc = get(&db, &slug).await.unwrap();
        let fm = crate::parser::extract_frontmatter(&doc.raw_content).unwrap();
        let parsed = crate::parser::parse_document(&fm.body, &slug);

        assert_eq!(
            parsed.agent.as_deref().map(str::trim),
            Some("loose agent"),
            "agent captured with loose-whitespace markers must be preserved on update"
        );

        // The stored content uses standard markers (compose_document normalizes them).
        assert!(
            doc.raw_content.contains("<!-- @agent -->"),
            "stored content should use normalized standard markers after compose_document"
        );
    }

    /// Regression (F-2): frontmatter containing a YAML value of `"---"` must survive
    /// a round-trip through update without losing any frontmatter fields.
    ///
    /// The old `frontmatter_prefix_of` helper re-scanned for the closing fence and
    /// would miscount when a YAML value line trimmed to "---", cutting the prefix
    /// mid-frontmatter. The fix: `extract_frontmatter` now returns the byte offset of
    /// the closing fence directly, which is used verbatim for slicing.
    #[tokio::test]
    async fn update_preserves_frontmatter_with_yaml_triple_dash_value() {
        let db = Db::open(":memory:").expect("in-memory db");
        let config = test_config();

        // Frontmatter with a field whose value is exactly "---" (a valid YAML scalar
        // when quoted). serde_yml parses this fine; old frontmatter_prefix_of would not.
        let initial = "---\ntheme: dark\nseparator: \"---\"\n---\n# My Doc\n\nContent.";
        let slug = do_publish(&db, &config, initial).await;

        // Verify initial parse stored the theme correctly.
        let doc = get(&db, &slug).await.unwrap();
        assert_eq!(doc.theme, "dark");

        // Update with the same frontmatter. The prefix must be recovered byte-exactly.
        do_update(&db, &config, &slug, initial).await;

        let doc2 = get(&db, &slug).await.unwrap();

        // Theme must survive the update (frontmatter prefix was not truncated).
        assert_eq!(
            doc2.theme, "dark",
            "theme must be preserved when frontmatter contains a 'separator: \"---\"' field"
        );

        // The stored raw_content must include the separator field (prefix not truncated).
        assert!(
            doc2.raw_content.contains("separator:"),
            "frontmatter field after '---' value must be present in stored raw_content"
        );
    }
}
