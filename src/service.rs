//! Document CRUD business logic. Pure functions over `&Db` + `&ServeConfig`. Shared by HTTP handlers and MCP HTTP transport.

// In-progress scaffolding: not yet wired into handlers or mcp_http.
#![allow(dead_code)]

/// Service layer — pure document CRUD over `&Db` and `&ServeConfig`.
///
/// No axum extractors. No HTTP. No Principal in the function signatures where
/// it is not needed for logic — callers supply the principal fields they need
/// (display_name, ip_address) for audit entries.
///
/// This is the single place where document business logic lives. Both the HTTP
/// handlers and the MCP HTTP transport call into this layer. The confused-deputy
/// path where mcp_http.rs looped back through the HTTP API is eliminated here.
use crate::{
    auth::Principal,
    config::ServeConfig,
    db::{AuditEntry, Db, DocumentRecord, DocumentSummary},
    handlers::{hash_password, AppError},
    parser::{extract_frontmatter, extract_title, parse_expiry, validate_slug},
    webhook,
};

/// URL-safe slug alphabet (mirrors handlers.rs — kept in sync).
const SLUG_ALPHABET: [char; 63] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
    'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
    'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '-',
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
pub fn publish(
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

    let theme = meta
        .theme
        .unwrap_or_else(|| config.default_theme.clone());

    let now = crate::handlers::chrono_now();

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

    // Insert with slug-collision retry.
    let final_doc = match db.insert_document(&doc) {
        Ok(()) => doc,
        Err(e) if is_unique_violation(&e) => {
            if meta.slug.is_some() {
                return Err(AppError::Conflict(format!(
                    "Slug '{}' is already in use",
                    slug
                )));
            }
            let new_slug = nanoid::nanoid!(10, &SLUG_ALPHABET);
            let retry_doc = DocumentRecord {
                id: new_slug.clone(),
                slug: new_slug.clone(),
                ..doc
            };
            db.insert_document(&retry_doc).map_err(|e2| {
                tracing::error!(error = %e2, "Slug collision retry failed");
                AppError::Internal("Failed to allocate unique slug".to_string())
            })?;
            retry_doc
        }
        Err(e) => return Err(AppError::from(e)),
    };

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
        timestamp: crate::handlers::chrono_now(),
        action: "create".to_string(),
        slug: final_doc.slug.clone(),
        token_name: req.principal.display_name,
        ip_address: req.client_ip,
    };
    if let Err(e) = db.insert_audit_entry(&audit_entry) {
        tracing::error!(error = %e, "Failed to write audit entry");
    }

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
pub fn update(
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

    let existing = db.get_by_slug(slug)?.ok_or(AppError::NotFound)?;

    if is_expired_doc(&existing) {
        return Err(AppError::Gone);
    }

    let fm_result = extract_frontmatter(&req.raw_content).map_err(AppError::BadRequest)?;
    let meta = fm_result.meta.unwrap_or_default();
    let body_text = &fm_result.body;

    let title = meta
        .title
        .unwrap_or_else(|| extract_title(body_text, slug));

    let theme = meta
        .theme
        .unwrap_or_else(|| config.default_theme.clone());

    let now = crate::handlers::chrono_now();

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
        id: existing.id,
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

    db.update_document(slug, &updated_doc)?;

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
    if let Err(e) = db.insert_audit_entry(&audit_entry) {
        tracing::error!(error = %e, "Failed to write audit entry");
    }

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
pub fn delete(
    db: &Db,
    config: &ServeConfig,
    slug: &str,
    principal: &Principal,
    client_ip: &str,
) -> Result<(), AppError> {
    let existing = db.get_by_slug(slug)?.ok_or(AppError::NotFound)?;

    db.delete_by_slug(slug)?;

    let now = crate::handlers::chrono_now();

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
    if let Err(e) = db.insert_audit_entry(&audit_entry) {
        tracing::error!(error = %e, "Failed to write audit entry");
    }

    Ok(())
}

// ── get ───────────────────────────────────────────────────────────────────────

/// Retrieve a document record by slug.
///
/// Returns `AppError::NotFound` if the slug does not exist.
/// Returns `AppError::Gone` if the document has expired.
pub fn get(db: &Db, slug: &str) -> Result<DocumentRecord, AppError> {
    let doc = db.get_by_slug(slug)?.ok_or(AppError::NotFound)?;
    if is_expired_doc(&doc) {
        return Err(AppError::Gone);
    }
    Ok(doc)
}

// ── list ──────────────────────────────────────────────────────────────────────

/// List documents with pagination.
///
/// Limit is capped at 100 server-side by the db layer.
pub fn list(
    db: &Db,
    limit: u32,
    offset: u32,
) -> Result<(Vec<DocumentSummary>, u64), AppError> {
    db.list_documents(limit, offset).map_err(AppError::from)
}

// ── internal helpers ──────────────────────────────────────────────────────────

fn is_expired_doc(doc: &DocumentRecord) -> bool {
    match &doc.expires_at {
        Some(exp) => exp.as_str() < crate::handlers::chrono_now().as_str(),
        None => false,
    }
}

fn add_seconds_to_now(seconds: u64) -> String {
    let future = chrono::Utc::now() + chrono::Duration::seconds(seconds as i64);
    future.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn is_unique_violation(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(err, _) if err.code == rusqlite::ErrorCode::ConstraintViolation
    )
}
