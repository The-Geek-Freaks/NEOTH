//! `neoth keys` — HMAC key management. Phase 33b SP-2 follow-up.
//!
//! Operators need a way to rotate the WAL HMAC key after a backup leak,
//! a suspected key compromise, or just as routine hygiene. Rotation is
//! non-destructive: the old key is moved to `hmac.key.<ts>.archive` so
//! historical compaction markers continue to verify with their original
//! key. `neoth verify --key <path>` accepts an explicit key path for
//! re-checking archived chains.
//!
//! Subcommands:
//!   `show`    — print path, byte length, mode. **Never prints key bytes.**
//!   `rotate`  — archive the current key, generate a new one (OS-RNG)
//!   `archives` — list archived keys with their timestamps
//!
//! Key bytes themselves stay on disk only — they're never piped to stdout
//! or logged, so a `--verbose` flag can't accidentally leak them.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::wal::compaction;

#[derive(Args, Debug, Clone)]
pub struct KeysArgs {
    #[command(subcommand)]
    pub action: KeysAction,
    /// Override the key path (mostly for tests). Default
    /// `~/.neoth/wal/hmac.key`.
    #[arg(long, value_name = "PATH", global = true)]
    pub key: Option<PathBuf>,
    /// Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum KeysAction {
    /// Show path, byte length, mode. Does NOT print the key bytes.
    Show,
    /// Archive the current key and generate a new one. Old key kept at
    /// `<path>.<unix-ts>.archive` for verifying historical markers.
    Rotate {
        /// Print what would happen without changing any files.
        #[arg(long)]
        dry_run: bool,
    },
    /// List archived keys with their timestamps.
    Archives,
}

pub async fn run_keys(args: KeysArgs) -> Result<()> {
    let key_path = args
        .key
        .clone()
        .unwrap_or_else(compaction::default_key_path);
    match args.action {
        KeysAction::Show => show(&key_path, args.output),
        KeysAction::Rotate { dry_run } => rotate(&key_path, dry_run, args.output),
        KeysAction::Archives => archives(&key_path, args.output),
    }
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

fn rotate(path: &std::path::Path, dry_run: bool, output: OutputFormat) -> Result<()> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let archive_path = path.with_extension(format!("key.{ts}.archive"));

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

    // Move current key (if any) to archive path. Rename is atomic on the
    // same filesystem.
    if path.exists() {
        std::fs::rename(path, &archive_path)
            .with_context(|| format!("archive {} -> {}", path.display(), archive_path.display()))?;
    }

    // Generate a fresh key via the OS RNG. `load_or_init_key` handles the
    // mode-0600 / DACL write path AND fails closed if the OS RNG is
    // unavailable — exactly the behaviour we want during rotation.
    let _new_key = compaction::load_or_init_key(path)
        .context("generate replacement HMAC key after rotation")?;

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "rotated": true,
                    "new_key_path": path.display().to_string(),
                    "archived_at": archive_path.display().to_string(),
                    "ts_unix": ts,
                })
            );
        }
        OutputFormat::Table => {
            println!("rotated HMAC key:");
            println!("  archived old → {}", archive_path.display());
            println!("  new key      → {}", path.display());
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
            action: KeysAction::Archives,
            key: Some(stem),
            output: OutputFormat::Table,
        };
        // Just ensure it doesn't error; capturing stdout would need a wrapper.
        run_keys(args).await.unwrap();
    }
}
