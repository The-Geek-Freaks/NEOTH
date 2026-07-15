//! `neoth reload` — operator-facing hot-reload trigger (Pick #37,
//! Session 14).
//!
//! Writes a sentinel file at `~/.neoth/.reload-requested` containing
//! a wall-clock timestamp. The running `neoth serve` daemon polls
//! for the sentinel on every channel-ingress tick; on present it
//! re-reads `freedom.yaml`, validates against the immutable-field
//! set, atomically swaps the `Arc<FreedomConfig>` via `arc-swap`,
//! emits a `CONFIG_RELOADED` (or `CONFIG_RELOAD_REJECTED`) WAL
//! audit frame, and deletes the sentinel.
//!
//! When no daemon is running, the sentinel just sits there — the
//! next `neoth serve` startup will see it, perform the reload at
//! boot, and clean it up. That's intentional: an operator who
//! edits freedom.yaml on a stopped daemon + types `neoth reload`
//! gets the reload applied when the daemon next starts, not
//! silently ignored.
//!
//! Not a network call; not an IPC socket; just a filesystem flag.
//! Works identically on every OS NEOTH targets (Linux/macOS/Windows
//! — all supported). No SIGHUP dependency, no `notify` crate
//! background thread.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Args;

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::config::reload::RELOAD_SENTINEL_NAME;

#[derive(Args, Debug, Clone)]
pub struct ReloadArgs {
    /// Override `~/.neoth/` (mostly for tests).
    #[arg(long, value_name = "DIR")]
    pub home: Option<PathBuf>,

    /// Output format. Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

/// Write the canonical reload sentinel for any CLI mutation that changes
/// `freedom.yaml`. Returning the timestamp keeps the operator-facing command
/// and non-interactive callers on the same filesystem contract.
pub(crate) fn request_reload_at(home: &Path) -> Result<(PathBuf, u64)> {
    let sentinel = home.join(RELOAD_SENTINEL_NAME);
    let ts = crate::time::now_unix_secs();
    std::fs::create_dir_all(home)
        .with_context(|| format!("create {} for sentinel", home.display()))?;
    std::fs::write(&sentinel, format!("ts_unix={ts}\n"))
        .with_context(|| format!("write reload sentinel at {}", sentinel.display()))?;
    Ok((sentinel, ts))
}

pub async fn run_reload(args: ReloadArgs) -> Result<()> {
    let home = args.home.unwrap_or_else(FreedomConfig::default_neoth_home);
    // Content is diagnostic only; the file's existence is the signal.
    let (sentinel, ts) = request_reload_at(&home)?;

    match args.output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "sentinel": sentinel.display().to_string(),
                    "ts_unix": ts,
                    "note": "running daemon picks this up on next ingress tick; stopped daemon picks it up at next `neoth serve` start",
                })
            );
        }
        OutputFormat::Table => {
            println!("reload requested: {}", sentinel.display());
            println!(
                "(running daemon picks this up on next ingress tick; \
                 stopped daemon picks it up at next `neoth serve` start)"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn run_reload_writes_sentinel() {
        let dir = tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let args = ReloadArgs {
            home: Some(home.clone()),
            output: OutputFormat::Json,
        };
        run_reload(args).await.expect("reload must Ok");
        let sentinel = home.join(RELOAD_SENTINEL_NAME);
        assert!(sentinel.exists(), "sentinel file must exist after reload");
        let body = std::fs::read_to_string(&sentinel).unwrap();
        assert!(body.starts_with("ts_unix="));
    }

    #[tokio::test]
    async fn run_reload_creates_home_dir_if_missing() {
        // Operator may run `neoth reload` before `neoth init` has
        // created ~/.neoth/. The CLI should create the dir + sentinel
        // rather than failing with "no such dir".
        let dir = tempdir().unwrap();
        let home = dir.path().join("nested").join(".neoth");
        assert!(!home.exists());
        let args = ReloadArgs {
            home: Some(home.clone()),
            output: OutputFormat::Json,
        };
        run_reload(args)
            .await
            .expect("reload must Ok even on fresh dir");
        assert!(home.exists());
        assert!(home.join(RELOAD_SENTINEL_NAME).exists());
    }
}
