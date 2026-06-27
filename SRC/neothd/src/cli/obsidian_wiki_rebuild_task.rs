//! OH-14 — periodic NEOTH self-wiki rebuild cron.
//!
//! When `freedom.yaml::obsidian_vault` AND a source directory (either
//! `freedom.yaml::obsidian_wiki_source_dir` or env `NEOTH_PLAN_DIR`) are
//! configured, this task rebuilds the NEOTH self-wiki on a schedule by:
//!
//!   1. Calling [`crate::wiki::build_wiki`] to render the PLAN/ design corpus
//!      into interlinked Obsidian pages under `<vault>/<subdir>/`.
//!   2. Calling [`crate::wiki::discover_sources`] + [`crate::wiki::ingest_sources`]
//!      to refresh ground-truth pointers in `idx_groundtruth` (scope
//!      `neoth-self-wiki`) so the design corpus surfaces on recall.
//!   3. Emitting a `0xFA OBSIDIAN_WIKI_REBUILD_COMPLETE` WAL frame with
//!      counters so operators can track cron health via `neoth wal show`.
//!
//! Off by default — requires `obsidian_vault` AND a reachable source dir.
//! Errors log + continue on next tick; never crash the daemon.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::wal::HeaderBuilder;
use crate::wal::events::EVENT_TYPE_OBSIDIAN_WIKI_REBUILD_COMPLETE;
use crate::wal::writer::WalWriterHandle;

/// Default rebuild cadence: every 24 hours. The design corpus changes
/// infrequently; a daily rebuild keeps the vault fresh without burning I/O.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Spawn the wiki-rebuild cron task. Returns the `JoinHandle` so
/// `serve_tasks` can `.abort()` on shutdown.
///
/// `interval = None` → [`DEFAULT_INTERVAL`].
/// `subdir = None` → `"NEOTH-Wiki"` (matches the `neoth obsidian wiki-build`
/// CLI default).
pub fn spawn(
    vault: PathBuf,
    source_dir: PathBuf,
    subdir: Option<String>,
    interval: Option<Duration>,
    writer: WalWriterHandle,
) -> JoinHandle<anyhow::Result<()>> {
    let subdir = subdir.unwrap_or_else(|| "NEOTH-Wiki".to_string());
    let interval = interval.unwrap_or(DEFAULT_INTERVAL);
    tokio::spawn(async move { run(vault, source_dir, subdir, interval, writer).await })
}

async fn run(
    vault: PathBuf,
    source_dir: PathBuf,
    subdir: String,
    interval: Duration,
    writer: WalWriterHandle,
) -> anyhow::Result<()> {
    info!(
        vault = %vault.display(),
        source_dir = %source_dir.display(),
        subdir = %subdir,
        interval_secs = interval.as_secs(),
        "obsidian wiki-rebuild cron started",
    );
    let mut ticker = tokio::time::interval(interval);
    // Burn the immediate tick — on a fresh boot the daemon is still
    // initialising and the PLAN/ directory may not be fully visible yet.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        if let Err(e) = run_one_tick(&vault, &source_dir, &subdir, &writer).await {
            warn!(error = %e, "obsidian wiki-rebuild tick failed (will retry next interval)");
        }
    }
}

/// One rebuild tick: build → ingest → emit WAL frame.
async fn run_one_tick(
    vault: &Path,
    source_dir: &Path,
    subdir: &str,
    writer: &WalWriterHandle,
) -> anyhow::Result<()> {
    // Guard: source directory must exist or the wiki builder produces nothing
    // useful. Treat absence as a warn+skip rather than a daemon-level error.
    if !source_dir.exists() {
        warn!(
            source_dir = %source_dir.display(),
            "obsidian wiki-rebuild: source_dir does not exist, skipping tick"
        );
        return Ok(());
    }

    let out_dir = vault.join(subdir);
    // Convert to owned PathBuf before spawn_blocking (closures require 'static).
    let source_dir_buf = source_dir.to_path_buf();

    // Step 1: build wiki pages from source_dir into vault/subdir/.
    // `dry_run = false` — we write for real.
    let (stats, _slugs) = tokio::task::spawn_blocking({
        let source_dir = source_dir_buf.clone();
        let out_dir = out_dir.clone();
        move || crate::wiki::build_wiki(&source_dir, &out_dir, false)
    })
    .await
    .context("obsidian wiki-rebuild: spawn_blocking panicked")?
    .context("obsidian wiki-rebuild: build_wiki failed")?;

    // Step 2: refresh ground-truth pointers in idx_groundtruth.
    // Open a fresh connection per tick (safe under SQLite WAL mode).
    let sources = tokio::task::spawn_blocking({
        let source_dir = source_dir_buf;
        move || crate::wiki::discover_sources(&source_dir)
    })
    .await
    .context("obsidian wiki-rebuild: spawn_blocking panicked (discover)")?
    .context("obsidian wiki-rebuild: discover_sources failed")?;

    let now_ns = crate::time::now_unix_ns_i64();

    // Step 3: emit 0xFA WAL frame BEFORE ingest so a task abort during the
    // blocking ingest cannot suppress the audit frame.
    //
    // Rationale: `spawn_blocking` tasks run to completion even when the parent
    // async task is cancelled (Tokio guarantee), but the `await` on the join
    // handle IS a cancellation point. If the task is aborted while awaiting
    // ingest, control never reaches a WAL emit that follows. Moving the emit
    // here (after pages are on disk) makes the frame unconditional for any tick
    // that actually wrote wiki pages. Ingest stats are not yet known; the frame
    // records 0 for them (acceptable — the ingest runs best-effort after).
    let payload = serde_json::json!({
        "pages_written": stats.pages_written,
        "sources": stats.sources,
        "ground_truth_inserted": 0_u64,
        "ground_truth_revoked": 0_u64,
        "ts_unix": now_ns / 1_000_000_000,
    });
    let body = serde_json::to_vec(&payload).unwrap_or_default();
    let header = HeaderBuilder::new(EVENT_TYPE_OBSIDIAN_WIKI_REBUILD_COMPLETE, &body).build();
    if let Err(e) = writer.append(header, body).await {
        warn!(error = %e, "obsidian wiki-rebuild: WAL append failed (non-fatal)");
    }

    // Step 4: refresh ground-truth pointers in idx_groundtruth (best-effort).
    let ingest_result = tokio::task::spawn_blocking(move || {
        let conn = crate::memory::store::open(&crate::memory::store::default_path())
            .context("obsidian wiki-rebuild: open views.db")?;
        crate::wiki::ingest_sources(&conn, &sources, now_ns)
            .context("obsidian wiki-rebuild: ingest_sources failed")
    })
    .await
    .context("obsidian wiki-rebuild: spawn_blocking panicked (ingest)");

    let ingest_stats = match ingest_result {
        Ok(Ok(s)) => s,
        Ok(Err(e)) | Err(e) => {
            warn!(error = %e, "obsidian wiki-rebuild: ground-truth ingest failed (non-fatal)");
            crate::wiki::IngestStats::default()
        }
    };

    info!(
        pages_written = stats.pages_written,
        sources = stats.sources,
        gt_inserted = ingest_stats.inserted,
        gt_revoked = ingest_stats.revoked,
        "obsidian wiki-rebuild cron tick complete",
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn task_aborts_cleanly() {
        // No real vault/source setup needed — the task should burn
        // the first tick and block on the second; abort must be clean.
        let vault_dir = tempfile::tempdir().unwrap();
        let source_dir = tempfile::tempdir().unwrap();
        let wal_dir = tempfile::tempdir().unwrap();
        let (writer, _writer_join) =
            crate::wal::writer::spawn(wal_dir.path().join("neoth.wal")).unwrap();

        let task = spawn(
            vault_dir.path().to_path_buf(),
            source_dir.path().to_path_buf(),
            Some("NEOTH-Wiki".into()),
            Some(Duration::from_millis(50)),
            writer,
        );
        // Let the task burn the first tick and enter the loop.
        tokio::time::sleep(Duration::from_millis(20)).await;
        task.abort();
        let _ = task.await; // JoinError on abort is expected
    }

    #[tokio::test]
    async fn one_tick_rebuilds_wiki_pages_in_vault() {
        // PLAN/ fixture with two source docs.
        let plan_dir = tempfile::tempdir().unwrap();
        std::fs::write(plan_dir.path().join("SPEC_a.md"), "# Spec A\n\nbody").unwrap();
        std::fs::write(plan_dir.path().join("CHORUS_x.md"), "# Chorus X\n\nbody").unwrap();

        let vault_dir = tempfile::tempdir().unwrap();
        let wal_dir = tempfile::tempdir().unwrap();
        let (writer, writer_join) =
            crate::wal::writer::spawn(wal_dir.path().join("neoth.wal")).unwrap();

        let task = spawn(
            vault_dir.path().to_path_buf(),
            plan_dir.path().to_path_buf(),
            Some("NEOTH-Wiki".into()),
            // Very tight interval so the second tick fires inside the test
            // window — first tick is burned per cron pattern.
            Some(Duration::from_millis(30)),
            writer.clone(),
        );

        // Wait for the first real (non-burned) tick to write wiki pages.
        let wiki_index = vault_dir
            .path()
            .join("NEOTH-Wiki")
            .join("NEOTH-Wiki-Index.md");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !wiki_index.exists() && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        task.abort();
        let _ = task.await;
        drop(writer);
        let _ = writer_join.await;

        // Pages must be on disk.
        assert!(
            wiki_index.exists(),
            "index page must exist after cron tick"
        );
        assert!(
            vault_dir
                .path()
                .join("NEOTH-Wiki")
                .join("SPEC_a.md")
                .exists(),
            "SPEC_a.md wiki page must exist"
        );

        // WAL frame 0xFA must have been emitted — scan the segment bytes directly.
        let wal_path = wal_dir.path().join("neoth.wal");
        let bytes = std::fs::read(&wal_path).unwrap();
        let mut cur = crate::wal::segment_header::SEGMENT_HEADER_LEN;
        let mut found_fa = false;
        while cur < bytes.len() {
            let Ok(f) = crate::wal::frame::decode_frame(&bytes[cur..]) else {
                break;
            };
            if f.header.event_type == EVENT_TYPE_OBSIDIAN_WIKI_REBUILD_COMPLETE {
                found_fa = true;
            }
            let t = f.header.total_len as usize;
            if t == 0 {
                break;
            }
            cur += t;
        }
        assert!(
            found_fa,
            "WAL must carry a rebuild-complete (0xFA) frame after a successful tick"
        );
    }
}
