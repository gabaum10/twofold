//! CLI command implementations. Each `run_*` function is the body for a Clap subcommand.
//!
//! `main.rs` dispatches here after parsing. This module owns the actual logic;
//! `cli.rs` owns only the Clap struct definitions.

use crate::{cli, db, frontmatter, helpers};

// ── Shared helpers ────────────────────────────────────────────────────────────

pub fn resolve_token(explicit: Option<String>) -> String {
    match explicit {
        Some(t) => t,
        None => match std::env::var("TWOFOLD_TOKEN") {
            Ok(t) => t,
            Err(_) => {
                eprintln!(
                    "Error: --token not provided and TWOFOLD_TOKEN is not set.\n\
                     Provide a token via --token <TOKEN> or set TWOFOLD_TOKEN."
                );
                std::process::exit(1);
            }
        },
    }
}

pub fn resolve_db_path(explicit: Option<String>) -> String {
    explicit
        .or_else(|| std::env::var("TWOFOLD_DB_PATH").ok())
        .unwrap_or_else(|| "./twofold.db".to_string())
}

pub fn make_blocking_client() -> reqwest::blocking::Client {
    match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to create HTTP client: {e}");
            std::process::exit(1);
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max - 1])
    }
}

// ── `twofold publish <path|->` ────────────────────────────────────────────────

pub fn run_publish(args: cli::PublishArgs) {
    // Resolve token: --token flag > TWOFOLD_TOKEN env var.
    let token = resolve_token(args.token);

    // Read content: file path or stdin.
    let content = read_publish_source(&args.path);

    // Apply frontmatter from CLI flags if any flags were provided.
    // If content already has frontmatter (starts with ---), merge flags in.
    // If no frontmatter and no flags, send as-is.
    let body = frontmatter::apply_frontmatter(
        &content,
        frontmatter::FrontmatterFields {
            title: args.title,
            slug: args.slug,
            theme: args.theme,
            expiry: args.expiry,
            password: args.password,
            description: None,
        },
    );

    // POST to the server.
    let url = format!("{}/api/v1/documents", args.server.trim_end_matches('/'));

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to create HTTP client: {e}");
            std::process::exit(1);
        }
    };

    let response = match client
        .post(&url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "text/markdown")
        .body(body)
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Request failed: {e}");
            std::process::exit(1);
        }
    };

    let status = response.status();

    if status == reqwest::StatusCode::CREATED {
        let body: serde_json::Value = match response.json() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Failed to parse server response: {e}");
                std::process::exit(1);
            }
        };
        if let Some(doc_url) = body.get("url").and_then(|v| v.as_str()) {
            println!("{doc_url}");
        } else {
            eprintln!("Server returned 201 but no `url` field in response.");
            std::process::exit(1);
        }
    } else {
        let body_text = response.text().unwrap_or_default();
        eprintln!("Publish failed: HTTP {status}\n{body_text}");
        std::process::exit(1);
    }
}

/// Read content from a file path or stdin (`-`).
fn read_publish_source(path: &str) -> String {
    if path == "-" {
        use std::io::Read;
        let mut buf = String::new();
        if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
            eprintln!("Failed to read from stdin: {e}");
            std::process::exit(1);
        }
        buf
    } else {
        match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to read file '{path}': {e}");
                std::process::exit(1);
            }
        }
    }
}

// ── `twofold list` ────────────────────────────────────────────────────────────

pub fn run_list(args: cli::ListArgs) {
    let token = resolve_token(args.token);
    let url = format!(
        "{}/api/v1/documents?limit={}",
        args.server.trim_end_matches('/'),
        args.limit
    );

    let client = make_blocking_client();

    let response = match client
        .get(&url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Request failed: {e}");
            std::process::exit(1);
        }
    };

    let status = response.status();
    if !status.is_success() {
        let body = response.text().unwrap_or_default();
        eprintln!("List failed: HTTP {status}\n{body}");
        std::process::exit(1);
    }

    let body: serde_json::Value = match response.json() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to parse server response: {e}");
            std::process::exit(1);
        }
    };

    let docs = body.get("documents").and_then(|v| v.as_array());
    let docs = match docs {
        Some(d) => d,
        None => {
            eprintln!("Unexpected response format");
            std::process::exit(1);
        }
    };

    // Print table with fixed-width columns.
    println!("{:<24} {:<32} {:<21} EXPIRES", "SLUG", "TITLE", "CREATED");
    println!("{}", "-".repeat(90));

    for doc in docs {
        let slug = doc.get("slug").and_then(|v| v.as_str()).unwrap_or("-");
        let title = doc.get("title").and_then(|v| v.as_str()).unwrap_or("-");
        let created = doc
            .get("created_at")
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        let expires = doc
            .get("expires_at")
            .and_then(|v| v.as_str())
            .unwrap_or("never");

        // Truncate for display
        let slug_d = truncate(slug, 23);
        let title_d = truncate(title, 31);
        let created_d = &created[..std::cmp::min(16, created.len())];
        let expires_d = if expires == "never" {
            "never".to_string()
        } else {
            expires[..std::cmp::min(16, expires.len())].to_string()
        };

        println!(
            "{:<24} {:<32} {:<21} {}",
            slug_d, title_d, created_d, expires_d
        );
    }
}

// ── `twofold delete <slug>` ───────────────────────────────────────────────────

pub fn run_delete(args: cli::DeleteArgs) {
    let token = resolve_token(args.token);
    let url = format!(
        "{}/api/v1/documents/{}",
        args.server.trim_end_matches('/'),
        args.slug
    );

    let client = make_blocking_client();

    let response = match client
        .delete(&url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Request failed: {e}");
            std::process::exit(1);
        }
    };

    let status = response.status();
    match status.as_u16() {
        204 => println!("Deleted: {}", args.slug),
        401 => {
            eprintln!("Auth error: check your token");
            std::process::exit(1);
        }
        404 => {
            eprintln!("Error: document '{}' not found", args.slug);
            std::process::exit(1);
        }
        _ => {
            let body = response.text().unwrap_or_default();
            eprintln!("Delete failed: HTTP {status}\n{body}");
            std::process::exit(1);
        }
    }
}

// ── `twofold audit` ───────────────────────────────────────────────────────────

pub fn run_audit(args: cli::AuditArgs) {
    let token = resolve_token(args.token);
    let url = format!(
        "{}/api/v1/audit?limit={}",
        args.server.trim_end_matches('/'),
        args.limit
    );

    let client = make_blocking_client();

    let response = match client
        .get(&url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Request failed: {e}");
            std::process::exit(1);
        }
    };

    let status = response.status();
    if !status.is_success() {
        let body = response.text().unwrap_or_default();
        eprintln!("Audit failed: HTTP {status}\n{body}");
        std::process::exit(1);
    }

    let body: serde_json::Value = match response.json() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to parse server response: {e}");
            std::process::exit(1);
        }
    };

    let entries = body.get("entries").and_then(|v| v.as_array());
    let entries = match entries {
        Some(e) => e,
        None => {
            eprintln!("Unexpected response format");
            std::process::exit(1);
        }
    };

    // Column widths: TIMESTAMP 21, ACTION 9, SLUG 25, TOKEN remainder.
    println!("{:<21} {:<9} {:<25} TOKEN", "TIMESTAMP", "ACTION", "SLUG");
    println!("{}", "-".repeat(75));

    for entry in entries {
        let timestamp = entry
            .get("timestamp")
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        let action = entry.get("action").and_then(|v| v.as_str()).unwrap_or("-");
        let slug = entry.get("slug").and_then(|v| v.as_str()).unwrap_or("-");
        let token_name = entry
            .get("token_name")
            .and_then(|v| v.as_str())
            .unwrap_or("-");

        // Truncate timestamp to 20 chars (drop sub-second noise if present)
        let ts_d = &timestamp[..std::cmp::min(20, timestamp.len())];
        let slug_d = truncate(slug, 24);

        println!("{:<21} {:<9} {:<25} {}", ts_d, action, slug_d, token_name);
    }
}

// ── `twofold token {create|list|revoke}` ─────────────────────────────────────

pub fn run_token(args: cli::TokenArgs) {
    match args.action {
        cli::TokenAction::Create { name, db } => token_create(&name, &resolve_db_path(db)),
        cli::TokenAction::List { db } => token_list(&resolve_db_path(db)),
        cli::TokenAction::Revoke { name, db } => token_revoke(&name, &resolve_db_path(db)),
    }
}

fn token_create(name: &str, db_path: &str) {
    let database = match db::Db::open(db_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to open database '{db_path}': {e}");
            std::process::exit(1);
        }
    };

    // Check for duplicate name
    match database.token_name_exists(name) {
        Ok(true) => {
            eprintln!("Error: Token name '{name}' already exists.");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Database error: {e}");
            std::process::exit(1);
        }
        _ => {}
    }

    // Generate a 32-byte random token, base64url-encode it.
    // Retry up to 3 times on prefix collision (prefix uniqueness is enforced
    // by a UNIQUE index; collisions are astronomically unlikely but possible).
    use base64::Engine;
    use rand::RngCore;

    let now = helpers::chrono_now();

    let token_plain = 'generate: {
        for attempt in 0..3u8 {
            let mut token_bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut token_bytes);
            let plain = format!(
                "tf_{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes)
            );

            let hash = match helpers::hash_password(&plain) {
                Ok(h) => h,
                Err(_) => {
                    eprintln!("Failed to hash token");
                    std::process::exit(1);
                }
            };

            let id = nanoid::nanoid!(10);

            // Store the first 8 chars of the plaintext token as a lookup prefix.
            // This enables O(1) indexed lookup in check_auth instead of O(n × argon2).
            // The prefix is NOT a secret — it merely narrows the candidate to 1 record.
            // Argon2 verification still runs on that 1 candidate.
            let prefix = plain.chars().take(8).collect::<String>();

            let record = db::TokenRecord {
                id,
                name: name.to_string(),
                hash,
                created_at: now.clone(),
                last_used: None,
                revoked: false,
                prefix: Some(prefix),
            };

            match database.insert_token(&record) {
                Ok(()) => break 'generate plain,
                Err(e)
                    if e.to_string()
                        .contains("UNIQUE constraint failed: tokens.prefix") =>
                {
                    if attempt < 2 {
                        eprintln!(
                            "Warning: prefix collision on attempt {}; regenerating.",
                            attempt + 1
                        );
                        continue;
                    }
                    eprintln!("Failed to store token after 3 attempts (prefix collision): {e}");
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("Failed to store token: {e}");
                    std::process::exit(1);
                }
            }
        }
        // Unreachable: loop always breaks or exits, but satisfies the compiler.
        eprintln!("Failed to generate a unique token prefix.");
        std::process::exit(1);
    };

    // Print the plaintext token ONCE
    println!("{token_plain}");
}

fn token_list(db_path: &str) {
    let database = match db::Db::open(db_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to open database '{db_path}': {e}");
            std::process::exit(1);
        }
    };

    let tokens = match database.list_tokens() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to list tokens: {e}");
            std::process::exit(1);
        }
    };

    // Print table header
    println!(
        "{:<20} {:<22} {:<22} STATUS",
        "NAME", "CREATED", "LAST USED"
    );

    for token in tokens {
        let status = if token.revoked { "revoked" } else { "active" };
        let last_used = token.last_used.as_deref().unwrap_or("never");
        // Truncate timestamps for display
        let created = &token.created_at[..std::cmp::min(16, token.created_at.len())];
        let used = if last_used == "never" {
            "never".to_string()
        } else {
            last_used[..std::cmp::min(16, last_used.len())].to_string()
        };
        println!("{:<20} {:<22} {:<22} {}", token.name, created, used, status);
    }
}

fn token_revoke(name: &str, db_path: &str) {
    let database = match db::Db::open(db_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to open database '{db_path}': {e}");
            std::process::exit(1);
        }
    };

    match database.revoke_token(name) {
        Ok(true) => println!("Token '{name}' revoked."),
        Ok(false) => {
            eprintln!("Error: Token '{name}' not found or already revoked.");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Database error: {e}");
            std::process::exit(1);
        }
    }
}
