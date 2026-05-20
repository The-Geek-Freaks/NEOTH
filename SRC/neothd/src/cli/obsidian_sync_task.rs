//! Background Obsidian-vault auto-sync — R-5 follow-up.
//!
//! `neoth obsidian sync` runs `sync_archive(archive_root, vault, subdir)`
//! once. This module wraps the same call in a tokio interval task so the
//! daemon keeps the operator's vault current without manual invocation.
//!
//! Off by default — operator opts in via `freedom.yaml::obsidian_vault`
//! (plus optional `obsidian_subdir` + `obsidian_auto_sync_secs`).
//! Errors log + retry next tick; never crash the daemon.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::cli::obsidian::sync_archive;
use crate::memory::archive::default_archive_root;

/// 1 hour default cadence — matches the daily archive write rhythm but
/// frequent enough that an operator who edited a session note doesn't
/// wait 24h to see it round-trip.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Spawn the auto-sync task. Returns the `JoinHandle` so the caller can
/// `.abort()` on shutdown.
///
/// `interval = None` => use [`DEFAULT_INTERVAL`]. `subdir = None` =>
/// "NEOTH" (matches the wizard's default).
pub fn spawn(
    archive_root: Option<PathBuf>,
    vault: PathBuf,
    subdir: Option<String>,
    interval: Option<Duration>,
) -> JoinHandle<Result<()>> {
    let archive_root = archive_root.unwrap_or_else(default_archive_root);
    let subdir = PathBuf::from(subdir.unwrap_or_else(|| "NEOTH".to_string()));
    let interval = interval.unwrap_or(DEFAULT_INTERVAL);
    tokio::spawn(async move { run(archive_root, vault, subdir, interval).await })
}

async fn run(
    archive_root: PathBuf,
    vault: PathBuf,
    subdir: PathBuf,
    interval: Duration,
) -> Result<()> {
    info!(
        vault = %vault.display(),
        subdir = %subdir.display(),
        interval_secs = interval.as_secs(),
        "obsidian auto-sync task started",
    );
    let mut ticker = tokio::time::interval(interval);
    // Burn the immediate tick — fresh boot already has either an empty
    // archive (nothing to sync) or a recent state from the prior daemon.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        match sync_archive(&archive_root, &vault, &subdir, false).await {
            Ok(stats) => {
                if stats.copied > 0 {
                    info!(
                        copied = stats.copied,
                        considered = stats.considered,
                        "obsidian auto-sync run",
                    );
                }
            }
            Err(e) => {
                warn!(error = %e, "obsidian auto-sync failed (will retry next tick)");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn task_aborts_cleanly() {
        // No real archive/vault setup needed — the task should enter the
        // ticker loop and respond to abort regardless.
        let archive_dir = tempdir().unwrap();
        let vault_dir = tempdir().unwrap();
        let task = spawn(
            Some(archive_dir.path().to_path_buf()),
            vault_dir.path().to_path_buf(),
            Some("NEOTH-test".into()),
            Some(Duration::from_millis(50)),
        );
        // Let the task enter the loop.
        tokio::time::sleep(Duration::from_millis(20)).await;
        task.abort();
        let _ = task.await; // JoinError on abort is expected
    }

    #[tokio::test]
    async fn one_tick_runs_sync_and_copies_session_md() {
        let archive_dir = tempdir().unwrap();
        let vault_dir = tempdir().unwrap();

        // Seed one session file under <archive>/sessions/<day>/<file>.md
        let day_dir = archive_dir.path().join("sessions").join("2026-05-14");
        std::fs::create_dir_all(&day_dir).unwrap();
        std::fs::write(day_dir.join("session-a.md"), "# session a\n").unwrap();

        let task = spawn(
            Some(archive_dir.path().to_path_buf()),
            vault_dir.path().to_path_buf(),
            Some("NEOTH-test".into()),
            // Very tight interval so the second tick fires within the test
            // window — first tick is burned per `run`.
            Some(Duration::from_millis(30)),
        );

        let copied = vault_dir
            .path()
            .join("NEOTH-test")
            .join("2026-05-14")
            .join("session-a.md");
        // Poll-with-deadline up to 2s. Under heavy parallel CI load the
        // 150ms fixed sleep is sometimes not enough — same flake fix the
        // cloud_sync_task test already received.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !copied.exists() && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        task.abort();
        let _ = task.await;

        assert!(
            copied.exists(),
            "auto-sync should have copied the session md within 2s"
        );
        let body = std::fs::read_to_string(&copied).unwrap();
        assert!(body.contains("# session a"));
    }
}
