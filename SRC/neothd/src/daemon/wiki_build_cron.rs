//! GOLD-FEAT-03b — self-wiki background rebuild cron.
//!
//! Each tick re-renders NEOTH's self-wiki into the operator's Obsidian
//! vault:
//! 1. **Capability pages** — always (generated from the in-binary
//!    `memory::self_wiki` map; this is the release-binary corpus).
//! 2. **Design-doc pages** — when `self_wiki.source_dir` points at an
//!    existing directory (dev checkouts: the repo `PLAN/`), via the same
//!    `wiki::build_wiki` path the CLI uses.
//! 3. **Ground-truth pointers** — when `self_wiki.ingest` (idempotent
//!    revoke-then-insert, scope `neoth-self-wiki`).
//!
//! ## Audit
//!
//! tracing only — the WAL event-type byte space is exhausted (255/256
//! at build time; the plan's 0x4E/0x4F were taken by RSS long ago), so
//! there is deliberately NO dedicated WAL frame. The tick outcome is
//! visible via `tracing` and the vault mtime.

use std::path::PathBuf;

use crate::config::automation::SelfWikiConfig;

/// Outcome of one rebuild tick — for the cron log line.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SelfWikiTickReport {
    /// Capability pages written (index + per-kind).
    pub capability_pages: usize,
    /// Design-doc pages written by `build_wiki` (0 when no source_dir).
    pub plan_pages: usize,
    /// Ground-truth pointers inserted (0 when ingest off / no sources).
    pub ingested: usize,
    /// At least one step failed (details in the log).
    pub had_errors: bool,
}

/// Run one self-wiki rebuild tick. Blocking work (fs + rusqlite) runs in
/// `spawn_blocking`; errors are logged, never propagated (a broken vault
/// path must not kill the daemon).
pub async fn run_self_wiki_tick(cfg: SelfWikiConfig) -> SelfWikiTickReport {
    tokio::task::spawn_blocking(move || run_tick_blocking(&cfg))
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "self-wiki cron: tick task panicked");
            SelfWikiTickReport {
                had_errors: true,
                ..Default::default()
            }
        })
}

fn run_tick_blocking(cfg: &SelfWikiConfig) -> SelfWikiTickReport {
    let mut report = SelfWikiTickReport::default();

    let vault = cfg
        .vault
        .clone()
        .unwrap_or_else(crate::cli::obsidian::default_vault_path);
    let subdir = PathBuf::from(&cfg.subdir);
    if let Err(e) = crate::cli::obsidian::validate_subdir(&subdir) {
        tracing::error!(error = %e, subdir = %cfg.subdir, "self-wiki cron: invalid subdir — tick skipped");
        report.had_errors = true;
        return report;
    }
    let out_dir = vault.join(&subdir);
    if let Err(e) = std::fs::create_dir_all(&out_dir) {
        tracing::error!(error = %e, dir = %out_dir.display(), "self-wiki cron: create out dir failed");
        report.had_errors = true;
        return report;
    }

    // 1. Capability pages — the in-binary corpus, always written.
    for (file, body) in crate::wiki::capabilities::render_capability_pages() {
        match std::fs::write(out_dir.join(&file), body) {
            Ok(()) => report.capability_pages += 1,
            Err(e) => {
                tracing::error!(error = %e, file, "self-wiki cron: capability page write failed");
                report.had_errors = true;
            }
        }
    }

    // 2. Design-doc pages — dev checkouts only.
    let source_dir = cfg.source_dir.as_ref().filter(|d| d.is_dir());
    if let Some(src) = source_dir {
        match crate::wiki::build_wiki(src, &out_dir, false) {
            Ok((stats, _slugs)) => report.plan_pages = stats.pages_written,
            Err(e) => {
                tracing::error!(error = %e, src = %src.display(), "self-wiki cron: build_wiki failed");
                report.had_errors = true;
            }
        }
        // 3. Ground-truth pointers for the design docs.
        if cfg.ingest {
            match ingest_blocking(src) {
                Ok(n) => report.ingested = n,
                Err(e) => {
                    tracing::error!(error = %e, "self-wiki cron: ground-truth ingest failed");
                    report.had_errors = true;
                }
            }
        }
    }

    report
}

fn ingest_blocking(src: &std::path::Path) -> anyhow::Result<usize> {
    let sources = crate::wiki::discover_sources(src)?;
    let conn = crate::memory::store::open(&crate::memory::store::default_path())?;
    let now_ns = crate::time::now_unix_ns_i64();
    let stats = crate::wiki::ingest_sources(&conn, &sources, now_ns)?;
    Ok(stats.inserted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_are_off_and_daily() {
        let cfg = SelfWikiConfig::default();
        assert!(!cfg.enabled, "self-wiki cron must be opt-in");
        assert_eq!(cfg.subdir, "NEOTH-Wiki");
        assert!(cfg.ingest);
        assert_eq!(
            cfg.interval_duration(),
            std::time::Duration::from_secs(
                crate::config::automation::DEFAULT_SELF_WIKI_INTERVAL_SECS
            )
        );
    }

    #[test]
    fn interval_floor_clamps_to_one_hour() {
        let cfg = SelfWikiConfig {
            interval_secs: 5,
            ..Default::default()
        };
        assert_eq!(
            cfg.interval_duration(),
            std::time::Duration::from_secs(3_600)
        );
    }

    #[tokio::test]
    async fn tick_writes_capability_pages_into_vault() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = SelfWikiConfig {
            enabled: true,
            vault: Some(dir.path().to_path_buf()),
            source_dir: None, // release-binary case: capability pages only
            ingest: false,
            ..Default::default()
        };
        let report = run_self_wiki_tick(cfg).await;
        assert!(!report.had_errors, "clean vault write must not error");
        assert_eq!(report.capability_pages, 5, "index + 4 kind pages");
        assert_eq!(report.plan_pages, 0);
        let index = dir
            .path()
            .join("NEOTH-Wiki")
            .join(crate::wiki::capabilities::CAPABILITIES_INDEX_FILE);
        assert!(index.is_file(), "index page written to vault/subdir");
    }

    #[tokio::test]
    async fn tick_with_source_dir_renders_plan_pages_too() {
        let vault = tempfile::tempdir().unwrap();
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("00_DESIGN_TEST.md"), "# design\nbody\n").unwrap();
        let cfg = SelfWikiConfig {
            enabled: true,
            vault: Some(vault.path().to_path_buf()),
            source_dir: Some(src.path().to_path_buf()),
            ingest: false, // ingest hits the real default views.db — not in tests
            ..Default::default()
        };
        let report = run_self_wiki_tick(cfg).await;
        assert!(!report.had_errors);
        assert!(report.plan_pages >= 1, "at least the design page + index");
    }

    #[tokio::test]
    async fn tick_rejects_traversal_subdir() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = SelfWikiConfig {
            enabled: true,
            vault: Some(dir.path().to_path_buf()),
            subdir: "../evil".to_string(),
            ..Default::default()
        };
        let report = run_self_wiki_tick(cfg).await;
        assert!(report.had_errors, "traversal subdir must be refused");
        assert_eq!(report.capability_pages, 0);
    }
}
