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
    if req.raw_content.is_empty() {
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
        .unwrap_or_else(|| extract_title(body_text, &slug));

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
    if req.raw_content.is_empty() {
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
    let has_frontmatter = fm_result.meta.is_some();
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
    // so user's original YAML formatting is preserved.
    let frontmatter_prefix = if has_frontmatter {
        frontmatter_prefix_of(&req.raw_content)
    } else {
        ""
    };
    let raw_to_store = format!("{frontmatter_prefix}{merged_body}");

    let title = meta.title.unwrap_or_else(|| {
        let t = extract_title(body_text, slug);
        if t == slug {
            existing.title.clone()
        } else {
            t
        }
    });

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
}

/// Extract the frontmatter prefix from a raw document string byte-exactly.
///
/// Returns the slice of `raw` from the start through the closing `---` fence line
/// (including its trailing newline if present). Returns `""` if no valid frontmatter
/// block is found.
///
/// This preserves the user's original YAML formatting and line endings without
/// re-serializing through serde_yml.
fn frontmatter_prefix_of(raw: &str) -> &str {
    // Must start with a `---` fence.
    if !raw.starts_with("---") {
        return "";
    }
    let mut fence_count = 0usize;
    let mut pos = 0usize;
    for line in raw.split('\n') {
        let end = pos + line.len();
        if line.trim() == "---" {
            fence_count += 1;
            if fence_count == 2 {
                // Include the closing `---` and the following newline if present.
                let after = end + 1; // +1 for the '\n' we split on
                if after <= raw.len() {
                    return &raw[..after];
                }
                return &raw[..end];
            }
        }
        pos = end + 1; // +1 for the '\n'
    }
    ""
}
