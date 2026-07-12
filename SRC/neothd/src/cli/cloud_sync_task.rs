//! Background cloud-archive mirror task — R-8.
//!
//! Same shape as `obsidian_sync_task` but pointed at the operator's
//! cloud client folder (Dropbox / GDrive / OneDrive / iCloud). The
//! cloud client itself takes care of uploading; NEOTH only writes new
//! / changed session-archive files into the local sync folder.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::cli::obsidian::sync_archive;
use crate::memory::archive::default_archive_root;

/// 1 hour default cadence — matches the daily archive write rhythm
/// while still letting the operator see today's notes appear in their
/// cloud folder within the hour.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Spawn the auto-mirror task. Returns the `JoinHandle` so the daemon
/// can `.abort()` on shutdown.
pub fn spawn(
    archive_root: Option<PathBuf>,
    dest: PathBuf,
    subdir: Option<String>,
    interval: Option<Duration>,
) -> JoinHandle<Result<()>> {
    let archive_root = archive_root.unwrap_or_else(default_archive_root);
    let subdir = PathBuf::from(subdir.unwrap_or_else(|| "NEOTH".to_string()));
    let interval = interval.unwrap_or(DEFAULT_INTERVAL);
    tokio::spawn(async move { run(archive_root, dest, subdir, interval).await })
}

async fn run(
    archive_root: PathBuf,
    dest: PathBuf,
    subdir: PathBuf,
    interval: Duration,
) -> Result<()> {
    info!(
        dest = %dest.display(),
        subdir = %subdir.display(),
        interval_secs = interval.as_secs(),
        "cloud auto-mirror task started",
    );
    let mut ticker = tokio::time::interval(interval);
    // Burn the immediate tick — fresh boot already has either an empty
    // archive (nothing to sync) or recent state from the prior daemon.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        match sync_archive(&archive_root, &dest, &subdir, false, None).await {
            Ok(stats) => {
                if stats.copied > 0 {
                    info!(
                        copied = stats.copied,
                        considered = stats.considered,
                        "cloud auto-mirror run",
                    );
                }
            }
            Err(e) => {
                warn!(error = %e, "cloud auto-mirror failed (will retry next tick)");
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
        let archive_dir = tempdir().unwrap();
        let cloud_dir = tempdir().unwrap();
        let task = spawn(
            Some(archive_dir.path().to_path_buf()),
            cloud_dir.path().to_path_buf(),
            Some("NEOTH-test".into()),
            Some(Duration::from_millis(50)),
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn one_tick_mirrors_session_md() {
        let archive_dir = tempdir().unwrap();
        let cloud_dir = tempdir().unwrap();
        let day = archive_dir.path().join("sessions").join("2026-05-15");
        std::fs::create_dir_all(&day).unwrap();
        std::fs::write(day.join("note.md"), "# note\n").unwrap();

        let task = spawn(
            Some(archive_dir.path().to_path_buf()),
            cloud_dir.path().to_path_buf(),
            Some("NEOTH-test".into()),
            Some(Duration::from_millis(30)),
        );
        // Poll for the mirrored file instead of a single fixed sleep —
        // under heavy parallel CI load a 150 ms window was racy. Up to
        // 2 s gives the ticker plenty of chances to fire its second
        // tick (first is burned in `run`).
        let mirrored = cloud_dir
            .path()
            .join("NEOTH-test")
            .join("2026-05-15")
            .join("note.md");
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            if mirrored.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        task.abort();
        let _ = task.await;

        assert!(mirrored.exists(), "auto-mirror must have copied the note");
    }
}
