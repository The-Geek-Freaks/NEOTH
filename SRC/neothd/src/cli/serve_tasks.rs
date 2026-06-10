//! GOLD-ARCH-01 (decomposition of `cli/serve.rs`) — background-task spawn helpers.
//!
//! `run_serve` is a ~2800-line function dominated by ~30 optional background-task
//! spawn blocks. This module relocates the *construction* of those tasks out of
//! `run_serve` into focused `spawn_*` helpers, one per task.
//!
//! **Behaviour-preserving by construction:** each helper returns the SAME handle
//! type to the SAME binding name at the SAME call site in `run_serve`, so the
//! spawn ORDER, the shutdown abort sequence, and the `worker_watch` liveness
//! registrations are all UNCHANGED — this is a pure relocation of per-task setup
//! logic, not a lifecycle change. The first increment covers WAL-FREE tasks
//! (they capture no [`crate::wal::writer::WalWriterHandle`]), which keeps the
//! helper signatures small and sidesteps the WAL-ordering-sensitive shutdown
//! drain entirely (a WAL-free task's abort order relative to `drop(writer)` is
//! irrelevant). WAL-emitting tasks can adopt the same pattern later by taking a
//! `&WalWriterHandle` parameter.

use std::sync::Arc;

use tokio::task::JoinHandle;
use tracing::info;

use crate::config::FreedomConfig;
use crate::providers::Provider;

/// R-5 — Obsidian vault auto-sync. Spawned only when `freedom.yaml::obsidian_vault`
/// is set; mirrors the session archive into the operator's vault on a schedule.
/// `None` (no vault configured) ⇒ no task. WAL-free.
pub(crate) fn spawn_obsidian_sync(
    config: &FreedomConfig,
) -> Option<JoinHandle<anyhow::Result<()>>> {
    let vault_str = config.obsidian_vault.as_deref()?;
    let vault = std::path::PathBuf::from(vault_str);
    let subdir = config.obsidian_subdir.clone();
    let interval = config
        .obsidian_auto_sync_secs
        .map(std::time::Duration::from_secs);
    Some(crate::cli::obsidian_sync_task::spawn(
        None, vault, subdir, interval,
    ))
}

/// R-8 — cloud archive auto-mirror. Spawned only when `freedom.yaml::cloud_archive_dest`
/// is set; periodically mirrors the session archive into a subdir of that folder
/// so the operator's cloud-vendor desktop client picks up the delta. `None`
/// (no dest configured) ⇒ no task. WAL-free.
pub(crate) fn spawn_cloud_archive(
    config: &FreedomConfig,
) -> Option<JoinHandle<anyhow::Result<()>>> {
    let dest_str = config.cloud_archive_dest.as_deref()?;
    let dest = std::path::PathBuf::from(dest_str);
    let subdir = config.cloud_archive_subdir.clone();
    let interval = config
        .cloud_archive_auto_sync_secs
        .map(std::time::Duration::from_secs);
    Some(crate::cli::cloud_sync_task::spawn(None, dest, subdir, interval))
}

/// EL-02 — arXiv topic-feed ingest. Spawned when `freedom.yaml::arxiv.enabled` is
/// true AND `arxiv.topics` is non-empty; runs each topic query on a cadence,
/// optionally LLM-summarises each abstract via the shared provider, and lands the
/// result in the ctx knowledge store. `None` (disabled / no topics) ⇒ no task.
/// WAL-free (writes to the ctx store, not the WAL).
pub(crate) fn spawn_arxiv_ingest(
    config: &FreedomConfig,
    shared_provider: &Option<Arc<dyn Provider>>,
) -> Option<JoinHandle<anyhow::Result<()>>> {
    if config.arxiv.enabled && !config.arxiv.topics.is_empty() {
        info!(topics = config.arxiv.topics.len(), "arxiv ingest task enabled");
        Some(crate::cli::arxiv_ingest_task::spawn(
            FreedomConfig::default_neoth_home(),
            config.arxiv.topics.clone(),
            shared_provider.as_ref().map(Arc::clone),
            config
                .arxiv
                .interval_secs
                .map(std::time::Duration::from_secs),
            config.arxiv.max_per_topic,
            config.arxiv.source_category.clone(),
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A default config leaves obsidian_vault/cloud_archive_dest unset and arxiv
    // disabled, so every helper returns None WITHOUT spawning a task — provable
    // without a tokio runtime (a fired spawn would panic "no reactor" here).
    #[test]
    fn all_wal_free_spawns_are_none_for_default_config() {
        let cfg = FreedomConfig::default();
        assert!(spawn_obsidian_sync(&cfg).is_none(), "no obsidian_vault → None");
        assert!(spawn_cloud_archive(&cfg).is_none(), "no cloud_archive_dest → None");
        assert!(
            spawn_arxiv_ingest(&cfg, &None).is_none(),
            "arxiv disabled → None"
        );
    }
}
