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
    parser::{extract_frontmatter, extract_title, parse_expiry, validate_slug},
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
    let meta = fm_result.meta.unwrap_or_default();
    let body_text = &fm_result.body;

    let title = meta.title.unwrap_or_else(|| extract_title(body_text, slug));

    let theme = meta.theme.unwrap_or_else(|| config.default_theme.clone());

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
        raw_content: req.raw_content,
        theme,
        password: password_hash,
        description: meta.description.clone(),
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
