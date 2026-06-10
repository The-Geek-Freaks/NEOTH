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
use tracing::{info, warn};

use crate::config::FreedomConfig;
use crate::providers::Provider;
use crate::wal::writer::WalWriterHandle;

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

/// C-05c — installer_ran sidecar ingester. `neoth install` drops
/// `~/.neoth/installer_ran_<ts>.json` after a successful install. Polls every
/// 5s, appends a `0x12 INSTALLER_RAN` WAL frame per sidecar, removes the file.
/// At-least-once: a crash between append + remove leaves the file for the next
/// tick (the WAL writer dedupes by event_id). Verbatim relocation of the inline
/// run_serve block — the caller passes `writer.clone()` and the returned handle
/// keeps its name + shutdown-abort site, so abort-before-`drop(writer)` ordering
/// is unchanged.
pub(crate) fn spawn_installer_audit_ingester(writer: WalWriterHandle) -> JoinHandle<()> {
    let home = FreedomConfig::default_neoth_home();
    let handle = tokio::spawn(async move {
        const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
        loop {
            tokio::time::sleep(POLL_INTERVAL).await;
            let pending = match crate::daemon::installer_audit_sidecar::list_pending(&home) {
                Ok(v) => v,
                Err(e) => {
                    warn!(error = %e, "installer_ran sidecar list failed");
                    continue;
                }
            };
            for (path, payload) in pending {
                let body = crate::daemon::installer_audit_sidecar::build_wal_frame_body(&payload);
                let header = crate::wal::HeaderBuilder::new(
                    crate::wal::events::EVENT_TYPE_INSTALLER_RAN,
                    &body,
                )
                .build();
                match writer.append(header, body).await {
                    Ok(_) => {
                        if let Err(e) =
                            crate::daemon::installer_audit_sidecar::remove_sidecar(&path)
                        {
                            warn!(
                                error = %e,
                                path = %path.display(),
                                "installer_ran sidecar remove failed after WAL append"
                            );
                        } else {
                            info!(
                                cli_name = payload.cli_name.as_str(),
                                version = payload.version.as_str(),
                                pkg_mgr = payload.pkg_mgr.as_str(),
                                "installer_ran frame appended to WAL"
                            );
                        }
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            path = %path.display(),
                            "installer_ran WAL append failed; sidecar retained for next tick"
                        );
                    }
                }
            }
        }
    });
    info!("installer_ran sidecar ingester spawned (5s tick)");
    handle
}

/// C-05d — credentials_import sidecar ingester. `neoth init` step 6g drops
/// `~/.neoth/credentials_import_<ts>.json` after the SC-17 redactor produced its
/// payload. Polls every 5s, appends a `0xD6 CREDENTIAL_IMPORT` WAL frame per
/// sidecar, removes the file. The payload is already redacted on disk — this
/// loop never touches raw secret material. Verbatim relocation (see
/// [`spawn_installer_audit_ingester`] for the ordering contract).
pub(crate) fn spawn_credentials_import_ingester(writer: WalWriterHandle) -> JoinHandle<()> {
    let home = FreedomConfig::default_neoth_home();
    let handle = tokio::spawn(async move {
        const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
        loop {
            tokio::time::sleep(POLL_INTERVAL).await;
            let pending = match crate::daemon::credentials_import_sidecar::list_pending(&home) {
                Ok(v) => v,
                Err(e) => {
                    warn!(error = %e, "credentials_import sidecar list failed");
                    continue;
                }
            };
            for (path, payload) in pending {
                let body =
                    crate::daemon::credentials_import_sidecar::build_wal_frame_body(&payload);
                let header = crate::wal::HeaderBuilder::new(
                    crate::wal::events::EVENT_TYPE_CREDENTIAL_IMPORT,
                    &body,
                )
                .build();
                match writer.append(header, body).await {
                    Ok(_) => {
                        if let Err(e) =
                            crate::daemon::credentials_import_sidecar::remove_sidecar(&path)
                        {
                            warn!(
                                error = %e,
                                path = %path.display(),
                                "credentials_import sidecar remove failed after WAL append"
                            );
                        } else {
                            info!(
                                source = payload.source.as_str(),
                                entry_count = payload.entry_count,
                                target_vault_id = payload.target_vault_id.as_str(),
                                "credentials_import frame appended to WAL"
                            );
                        }
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            path = %path.display(),
                            "credentials_import WAL append failed; sidecar retained for next tick"
                        );
                    }
                }
            }
        }
    });
    info!("credentials_import sidecar ingester spawned (5s tick)");
    handle
}

/// W-04 follow-up — detect_complete sidecar ingester. The wizard's step1b drops
/// `~/.neoth/detect_complete_<ts>.json` after a fresh probe pass. Same 5s poll +
/// at-least-once contract as the installer + credentials ingesters above; appends
/// a `0x?? DETECT_COMPLETE` WAL frame per sidecar. Verbatim relocation.
pub(crate) fn spawn_detect_complete_ingester(writer: WalWriterHandle) -> JoinHandle<()> {
    let home = FreedomConfig::default_neoth_home();
    let handle = tokio::spawn(async move {
        const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
        loop {
            tokio::time::sleep(POLL_INTERVAL).await;
            let pending = match crate::daemon::detect_complete_sidecar::list_pending(&home) {
                Ok(v) => v,
                Err(e) => {
                    warn!(error = %e, "detect_complete sidecar list failed");
                    continue;
                }
            };
            for (path, payload) in pending {
                let body = crate::daemon::detect_complete_sidecar::build_wal_frame_body(&payload);
                let header = crate::wal::HeaderBuilder::new(
                    crate::wal::events::EVENT_TYPE_DETECT_COMPLETE,
                    &body,
                )
                .build();
                match writer.append(header, body).await {
                    Ok(_) => {
                        if let Err(e) =
                            crate::daemon::detect_complete_sidecar::remove_sidecar(&path)
                        {
                            warn!(
                                error = %e,
                                path = %path.display(),
                                "detect_complete sidecar remove failed after WAL append"
                            );
                        } else {
                            info!(
                                probed_at_unix = payload.probed_at_unix,
                                has_accelerator = payload.has_accelerator(),
                                "detect_complete frame appended to WAL"
                            );
                        }
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            path = %path.display(),
                            "detect_complete WAL append failed; sidecar retained for next tick"
                        );
                    }
                }
            }
        }
    });
    info!("detect_complete sidecar ingester spawned (5s tick)");
    handle
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
