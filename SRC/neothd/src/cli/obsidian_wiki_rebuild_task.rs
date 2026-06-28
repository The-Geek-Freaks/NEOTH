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
/// `views_db = None` → [`crate::memory::store::default_path`] (production
/// default). Pass `Some(path)` in tests to isolate the SQLite DB from the
/// real `~/.neoth/views.db` and prevent parallel-test races.
pub fn spawn(
    vault: PathBuf,
    source_dir: PathBuf,
    subdir: Option<String>,
    interval: Option<Duration>,
    writer: WalWriterHandle,
    views_db: Option<PathBuf>,
) -> JoinHandle<anyhow::Result<()>> {
    let subdir = subdir.unwrap_or_else(|| "NEOTH-Wiki".to_string());
    let interval = interval.unwrap_or(DEFAULT_INTERVAL);
    tokio::spawn(async move { run(vault, source_dir, subdir, interval, writer, views_db).await })
}

async fn run(
    vault: PathBuf,
    source_dir: PathBuf,
    subdir: String,
    interval: Duration,
    writer: WalWriterHandle,
    views_db: Option<PathBuf>,
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
        if let Err(e) = run_one_tick(&vault, &source_dir, &subdir, &writer, views_db.clone()).await
        {
            warn!(error = %e, "obsidian wiki-rebuild tick failed (will retry next interval)");
        }
    }
}

/// One rebuild tick: build → ingest → emit WAL frame.
///
/// `views_db` overrides the path used to open the ground-truth SQLite
/// database. Production callers pass `None` → resolves via
/// [`crate::memory::store::default_path`]. Tests pass `Some(isolated_path)`
/// to prevent parallel-test races on the real `~/.neoth/views.db`.
async fn run_one_tick(
    vault: &Path,
    source_dir: &Path,
    subdir: &str,
    writer: &WalWriterHandle,
    views_db: Option<PathBuf>,
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
    // `db_path` is resolved now (on the async task) so the spawn_blocking
    // closure captures an owned PathBuf rather than calling default_path()
    // inside the blocking thread — avoids any HOME env-var read inside a
    // thread that could race with other concurrent tests.
    let db_path = views_db.unwrap_or_else(crate::memory::store::default_path);
    let ingest_result = tokio::task::spawn_blocking(move || {
        let conn = crate::memory::store::open(&db_path)
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
            None,
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
        // Isolated views.db: each test gets its own tempdir so concurrent tests
        // never contend on the real ~/.neoth/views.db (parallel-suite flake fix).
        let views_db_dir = tempfile::tempdir().unwrap();
        let views_db_path = views_db_dir.path().join(".neoth").join("views.db");
        let (writer, writer_join) =
            crate::wal::writer::spawn(wal_dir.path().join("neoth.wal")).unwrap();

        // Drive ONE full tick to completion directly instead of spawn()+abort().
        // The old spawn/abort path raced under the parallel suite: it waited for
        // the wiki INDEX file (written in build step 1) and then aborted, which
        // under CPU contention could cancel the task BEFORE the ingest + WAL
        // append (final step) emitted the 0xFA frame → `found_fa` flaked false.
        // run_one_tick runs build → ingest → WAL-append synchronously, so the
        // 0xFA frame is always emitted before we scan for it; `views_db` is an
        // isolated tempdir so the ingest never reads HOME (the other race).
        run_one_tick(
            vault_dir.path(),
            plan_dir.path(),
            "NEOTH-Wiki",
            &writer,
            Some(views_db_path),
        )
        .await
        .expect("one rebuild tick must succeed");

        // Flush the WAL writer so the 0xFA frame is durable before we scan.
        drop(writer);
        let _ = writer_join.await;

        // Pages must be on disk.
        let wiki_index = vault_dir
            .path()
            .join("NEOTH-Wiki")
            .join("NEOTH-Wiki-Index.md");
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
