//! `neoth keys` — HMAC key management + scope-gated API token management.
//!
//! Phase 33b SP-2 follow-up: HMAC key rotation (show / rotate / archives).
//! GOLD-ADAPT-ODY-31: API token lifecycle (api-token create / list / revoke).
//!
//! HMAC subcommands:
//!   `show`    — print path, byte length, mode. **Never prints key bytes.**
//!   `rotate`  — archive the current key, generate a new one (OS-RNG)
//!   `archives` — list archived keys with their timestamps
//!
//! API-token subcommands:
//!   `api-token create --label NAME --scope S1 [--scope S2] [--expires-in SECS]`
//!                     — mint token, print plaintext ONCE, store hash.
//!   `api-token list`  — list tokens (label / id / scopes / status). No plaintext.
//!   `api-token revoke <ID>` — mark a token revoked by its id.
//!
//! Token bytes are shown once at create time and never appear in list output
//! or on disk.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::security::api_tokens;
use crate::wal::compaction;

// ── top-level args ───────────────────────────────────────────────────────────

#[derive(Args, Debug, Clone)]
pub struct KeysArgs {
    #[command(subcommand)]
    pub action: KeysAction,
    /// Override the HMAC key path (mostly for tests). Default
    /// `~/.neoth/wal/hmac.key`.
    #[arg(long, value_name = "PATH", global = true)]
    pub key: Option<PathBuf>,
    /// Override the neoth home directory (for tests / custom installs).
    /// Default: `~/.neoth`.
    #[arg(long, value_name = "PATH", global = true)]
    pub home: Option<PathBuf>,
    /// Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

// ── action enum ──────────────────────────────────────────────────────────────

#[derive(Subcommand, Debug, Clone)]
pub enum KeysAction {
    /// Show HMAC key path, byte length, mode. Does NOT print the key bytes.
    Show,
    /// Archive the current HMAC key and generate a new one. Old key kept at
    /// `<path>.<unix-ts>.archive` for verifying historical markers.
    Rotate {
        /// Print what would happen without changing any files.
        #[arg(long)]
        dry_run: bool,
    },
    /// List archived HMAC keys with their timestamps.
    Archives,
    /// Manage scope-gated API tokens (GOLD-ADAPT-ODY-31).
    #[command(name = "api-token", subcommand)]
    ApiToken(ApiTokenAction),
}

// ── api-token subcommands ─────────────────────────────────────────────────────

#[derive(Subcommand, Debug, Clone)]
pub enum ApiTokenAction {
    /// Mint a new scope-gated API token. Prints the plaintext ONCE — store it
    /// securely. The hash is stored in `~/.neoth/api_tokens.json`.
    Create {
        /// Human-readable label (not unique).
        #[arg(long, short = 'l')]
        label: String,
        /// Scope(s) to grant. Repeat for multiple.
        /// Valid: api:health, recall:read, stats:read, memory:write,
        ///        provider:call, channel:send
        /// (memory:write auto-includes recall:read)
        #[arg(long, short = 's', required = true, num_args = 1..)]
        scope: Vec<String>,
        /// Token lifetime in seconds from now. Omit for no expiry.
        #[arg(long)]
        expires_in: Option<u64>,
    },
    /// List all tokens (label / id / scopes / status). Never shows token bytes.
    List,
    /// Revoke a token by its id (shown in `list` output).
    Revoke {
        /// Token id to revoke.
        id: String,
    },
}

// ── dispatch ──────────────────────────────────────────────────────────────────

pub async fn run_keys(args: KeysArgs) -> Result<()> {
    let key_path = args
        .key
        .clone()
        .unwrap_or_else(compaction::default_key_path);
    let home = args
        .home
        .clone()
        .unwrap_or_else(FreedomConfig::default_neoth_home);
    match args.action {
        KeysAction::Show => show(&key_path, args.output),
        KeysAction::Rotate { dry_run } => rotate(&home, &key_path, dry_run, args.output).await,
        KeysAction::Archives => archives(&key_path, args.output),
        KeysAction::ApiToken(sub) => api_token(sub, &home, args.output),
    }
}

// ── api-token handlers ────────────────────────────────────────────────────────

fn api_token(action: ApiTokenAction, home: &std::path::Path, output: OutputFormat) -> Result<()> {
    match action {
        ApiTokenAction::Create {
            label,
            scope,
            expires_in,
        } => api_token_create(label, scope, expires_in, home, output),
        ApiTokenAction::List => api_token_list(home, output),
        ApiTokenAction::Revoke { id } => api_token_revoke(&id, home, output),
    }
}

fn api_token_create(
    label: String,
    scopes: Vec<String>,
    expires_in: Option<u64>,
    home: &std::path::Path,
    output: OutputFormat,
) -> Result<()> {
    let expires_at = expires_in.map(|secs| crate::time::now_unix_i64().saturating_add(secs as i64));
    let (record, plaintext) =
        api_tokens::create_token(label, scopes, expires_at).context("create API token")?;

    api_tokens::mutate_store(home, |records| {
        records.push(record.clone());
        Ok(())
    })
    .context("append to api_tokens.json")?;

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "id": record.id,
                    "label": record.label,
                    "scopes": record.scopes,
                    "created_at": record.created_at,
                    "expires_at": record.expires_at,
                    // plaintext shown once in the JSON response.
                    "token": plaintext,
                })
            );
        }
        OutputFormat::Table => {
            println!("API token created:");
            println!("  id:      {}", record.id);
            println!("  label:   {}", record.label);
            println!("  scopes:  {}", record.scopes.join(", "));
            if let Some(exp) = record.expires_at {
                println!("  expires: {exp} (unix)");
            } else {
                println!("  expires: never");
            }
            println!();
            println!("  TOKEN (copy now — shown ONCE, not stored):");
            println!("  {plaintext}");
            println!();
            println!("  Use:  Authorization: Bearer {plaintext}");
        }
    }
    Ok(())
}

fn api_token_list(home: &std::path::Path, output: OutputFormat) -> Result<()> {
    let records = api_tokens::load_store(home).context("load api_tokens.json")?;
    let now = crate::time::now_unix_i64();

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let rows: Vec<_> = records
                .iter()
                .map(|r| {
                    let status = if r.revoked_at.is_some() {
                        "revoked"
                    } else if r.expires_at.is_some_and(|e| now >= e) {
                        "expired"
                    } else {
                        "active"
                    };
                    serde_json::json!({
                        "id": r.id,
                        "label": r.label,
                        "scopes": r.scopes,
                        "status": status,
                        "created_at": r.created_at,
                        "expires_at": r.expires_at,
                        "last_used": r.last_used,
                        "revoked_at": r.revoked_at,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::json!({ "count": rows.len(), "tokens": rows })
            );
        }
        OutputFormat::Table => {
            if records.is_empty() {
                println!("(no API tokens)");
                return Ok(());
            }
            println!("{:<38}  {:<24}  {:<10}  SCOPES", "ID", "LABEL", "STATUS");
            println!("{}", "-".repeat(100));
            for r in &records {
                let status = if r.revoked_at.is_some() {
                    "revoked"
                } else if r.expires_at.is_some_and(|e| now >= e) {
                    "expired"
                } else {
                    "active"
                };
                let label = if r.label.len() > 24 {
                    format!("{}…", &r.label[..23])
                } else {
                    r.label.clone()
                };
                println!(
                    "{:<38}  {:<24}  {:<10}  {}",
                    r.id,
                    label,
                    status,
                    r.scopes.join(", ")
                );
            }
        }
    }
    Ok(())
}

fn api_token_revoke(id: &str, home: &std::path::Path, output: OutputFormat) -> Result<()> {
    let found = api_tokens::mutate_store(home, |records| Ok(api_tokens::revoke_token(records, id)))
        .context("update api_tokens.json")?;
    if !found {
        anyhow::bail!("no token with id {id:?} found");
    }
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::json!({ "revoked": true, "id": id }));
        }
        OutputFormat::Table => {
            println!("token {id} revoked");
        }
    }
    Ok(())
}

fn show(path: &std::path::Path, output: OutputFormat) -> Result<()> {
    if !path.exists() {
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!(
                    "{}",
                    serde_json::json!({
                        "exists": false,
                        "path": path.display().to_string(),
                    })
                );
            }
            OutputFormat::Table => {
                println!("hmac key: absent at {}", path.display());
                println!("(it will be generated on the first `neoth serve` boot)");
            }
        }
        return Ok(());
    }
    let meta = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    let size = meta.len();
    let mode_str = format_mode(path);
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "exists": true,
                    "path": path.display().to_string(),
                    "size_bytes": size,
                    "mode": mode_str,
                })
            );
        }
        OutputFormat::Table => {
            println!("hmac key:");
            println!("  path:  {}", path.display());
            println!("  size:  {size} bytes");
            println!("  mode:  {mode_str}");
            println!("(key bytes intentionally not shown — they live on disk only)");
        }
    }
    Ok(())
}

async fn rotate(
    home: &std::path::Path,
    path: &std::path::Path,
    dry_run: bool,
    output: OutputFormat,
) -> Result<()> {
    let ts = crate::time::now_unix_secs();
    let mut archive_ts = ts;
    let archive_for = |archive_ts| {
        let mut name = path
            .file_name()
            .map(|name| name.to_os_string())
            .unwrap_or_else(|| "hmac.key".into());
        name.push(format!(".{archive_ts}.archive"));
        path.with_file_name(name)
    };
    let mut archive_path = archive_for(archive_ts);
    while archive_path.exists() {
        archive_ts = archive_ts.saturating_add(1);
        archive_path = archive_for(archive_ts);
    }

    if dry_run {
        let exists = path.exists();
        match output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!(
                    "{}",
                    serde_json::json!({
                        "dry_run": true,
                        "current_exists": exists,
                        "would_archive_to": archive_path.display().to_string(),
                        "would_generate_at": path.display().to_string(),
                    })
                );
            }
            OutputFormat::Table => {
                if exists {
                    println!(
                        "dry-run: would archive {} -> {}",
                        path.display(),
                        archive_path.display()
                    );
                } else {
                    println!(
                        "dry-run: no existing key; would generate at {}",
                        path.display()
                    );
                }
            }
        }
        return Ok(());
    }

    let had_current = path.exists();
    let mut new_key = zeroize::Zeroizing::new([0u8; 32]);
    getrandom::getrandom(new_key.as_mut())
        .context("OS RNG unavailable — refusing to generate a weak HMAC key")?;
    let rotation = crate::cli::security::rotate_hmac_key_with_audit(
        home,
        path,
        new_key.as_ref(),
        "rotate",
        had_current.then_some(archive_path),
    )
    .await?;
    let archived_at = rotation
        .archive_path
        .as_ref()
        .map(|path| path.display().to_string());

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "rotated": true,
                    "recovered": rotation.recovered,
                    "new_key_path": path.display().to_string(),
                    "archived_at": archived_at,
                    "ts_unix": rotation.ts_unix(),
                })
            );
        }
        OutputFormat::Table => {
            println!("rotated HMAC key:");
            if let Some(archive) = &rotation.archive_path {
                println!("  archived old → {}", archive.display());
            } else {
                println!("  archived old → (no previous key)");
            }
            println!("  new key      → {}", path.display());
            if rotation.recovered {
                println!("  state        → recovered interrupted audited rotation");
            }
            println!(
                "(historical compaction markers still verify via the archived \
                 key — pass it to `neoth verify --key <path>`)"
            );
        }
    }
    Ok(())
}

fn archives(path: &std::path::Path, output: OutputFormat) -> Result<()> {
    let Some(parent) = path.parent() else {
        anyhow::bail!("key path has no parent directory: {}", path.display());
    };
    let stem = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("hmac.key");

    let mut found = Vec::new();
    if let Ok(rd) = std::fs::read_dir(parent) {
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            // Pattern: `<stem>.<ts>.archive` — extract ts.
            if !name.starts_with(&format!("{stem}.")) || !name.ends_with(".archive") {
                continue;
            }
            // Strip prefix + suffix to extract the timestamp.
            let stripped = &name[stem.len() + 1..name.len() - ".archive".len()];
            let Ok(ts) = stripped.parse::<u64>() else {
                continue;
            };
            found.push((ts, entry.path()));
        }
    }
    found.sort_by_key(|(ts, _)| *ts);

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let rows: Vec<_> = found
                .iter()
                .map(|(ts, p)| {
                    serde_json::json!({
                        "ts_unix": ts,
                        "path": p.display().to_string(),
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::json!({
                    "count": rows.len(),
                    "archives": rows,
                })
            );
        }
        OutputFormat::Table => {
            if found.is_empty() {
                println!("(no archived keys at {})", parent.display());
                return Ok(());
            }
            println!("# {} archived key(s):", found.len());
            for (ts, p) in &found {
                println!("  ts={ts}  {}", p.display());
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn format_mode(path: &std::path::Path) -> String {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(m) => format!("0o{:o}", m.permissions().mode() & 0o777),
        Err(_) => "<unknown>".into(),
    }
}

#[cfg(not(unix))]
fn format_mode(_path: &std::path::Path) -> String {
    "<windows DACL>".into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn show_handles_missing_key_gracefully() {
        let dir = tempdir().unwrap();
        let args = KeysArgs {
            home: None,
            action: KeysAction::Show,
            key: Some(dir.path().join("absent.key")),
            output: OutputFormat::Table,
        };
        run_keys(args).await.unwrap();
    }

    #[tokio::test]
    async fn rotate_archives_existing_key_and_generates_new() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("hmac.key");
        // Seed an existing 32-byte key.
        std::fs::write(&key_path, vec![0x42u8; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let args = KeysArgs {
            home: Some(dir.path().to_path_buf()),
            action: KeysAction::Rotate { dry_run: false },
            key: Some(key_path.clone()),
            output: OutputFormat::Table,
        };
        run_keys(args).await.unwrap();

        // New key written at the same path, with different bytes.
        // K-Sec-4 (2026-05-22): on Windows the new key is DPAPI-wrapped
        // on disk, so `read(path)` returns the wrapped envelope (>= 32B,
        // typically ~280B). The LOGICAL key bytes are recovered via
        // `compaction::load_or_init_key`. On unix the on-disk size
        // stays exactly 32. Pin both shapes.
        assert!(key_path.exists(), "new key must exist at original path");
        let on_disk = std::fs::read(&key_path).unwrap();
        #[cfg(unix)]
        assert_eq!(on_disk.len(), 32, "unix on-disk key stays plaintext 32B");
        #[cfg(windows)]
        assert!(
            on_disk.len() >= 32,
            "windows on-disk key is DPAPI-wrapped or plaintext fallback; got {} bytes",
            on_disk.len()
        );
        // The logical key (after DPAPI unwrap on Windows) must differ
        // from the seeded legacy 32 bytes — that's the rotation contract.
        let logical = crate::wal::compaction::load_or_init_key(&key_path).unwrap();
        assert_eq!(logical.len(), 32, "logical key length must be 32 bytes");
        assert!(
            logical != vec![0x42u8; 32],
            "rotation must change the logical key bytes",
        );

        // Exactly one archive file present.
        let mut archives = Vec::new();
        for entry in std::fs::read_dir(dir.path()).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.contains(".archive") {
                archives.push(name);
            }
        }
        assert_eq!(archives.len(), 1, "expected one archive, got {archives:?}");
        let archive_bytes = std::fs::read(dir.path().join(&archives[0])).unwrap();
        assert_eq!(
            archive_bytes,
            vec![0x42u8; 32],
            "archived bytes must match original"
        );
    }

    #[tokio::test]
    async fn rotate_dry_run_does_not_modify_files() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("hmac.key");
        std::fs::write(&key_path, vec![0x77u8; 32]).unwrap();
        let args = KeysArgs {
            home: Some(dir.path().to_path_buf()),
            action: KeysAction::Rotate { dry_run: true },
            key: Some(key_path.clone()),
            output: OutputFormat::Table,
        };
        run_keys(args).await.unwrap();
        let bytes = std::fs::read(&key_path).unwrap();
        assert_eq!(bytes, vec![0x77u8; 32], "dry-run must not touch the key");
    }

    #[tokio::test]
    async fn rotate_works_when_no_existing_key() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("hmac.key");
        assert!(!key_path.exists());
        let args = KeysArgs {
            home: Some(dir.path().to_path_buf()),
            action: KeysAction::Rotate { dry_run: false },
            key: Some(key_path.clone()),
            output: OutputFormat::Table,
        };
        run_keys(args).await.unwrap();
        assert!(
            key_path.exists(),
            "rotate with no prior key should still generate one"
        );
    }

    #[tokio::test]
    async fn archives_command_lists_only_matching_files() {
        let dir = tempdir().unwrap();
        let stem = dir.path().join("hmac.key");
        // Two matching archives + one non-matching file.
        std::fs::write(dir.path().join("hmac.key.1700000000.archive"), b"k1").unwrap();
        std::fs::write(dir.path().join("hmac.key.1800000000.archive"), b"k2").unwrap();
        std::fs::write(dir.path().join("unrelated.txt"), b"x").unwrap();
        std::fs::write(dir.path().join("hmac.key"), b"current").unwrap();

        let args = KeysArgs {
            home: None,
            action: KeysAction::Archives,
            key: Some(stem),
            output: OutputFormat::Table,
        };
        // Just ensure it doesn't error; capturing stdout would need a wrapper.
        run_keys(args).await.unwrap();
    }
}
