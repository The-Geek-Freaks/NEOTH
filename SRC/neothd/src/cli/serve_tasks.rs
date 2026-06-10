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

use anyhow::Context;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::channels::{Channel, PipelineHandler};
use crate::cli::serve_pipeline::{PipelineHandlerDeps, build_pipeline_handler};
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

// ── Region-8 alerting/adaptation crons. Each is a thin delegate to its own
// `crate::daemon::*::spawn_*_cron_loop` fn that returns `None` when the feature
// is disabled (so opt-out operators carry no idle task). WAL-emitting, but the
// per-site mechanism keeps each handle's name + shutdown-abort site (before
// `drop(writer)`) UNCHANGED, so the WAL-ordering invariant holds. `&config`
// works for every one: the `Copy` config slices (recall_latency / profile_adapt)
// copy out of the borrow, the rest `.clone()`. ────────────────────────────────

/// MONITOR-03 / RECALL-METER-01 — recall-latency p95 alert cron (`0x4B`).
pub(crate) fn spawn_recall_latency_cron(
    config: &FreedomConfig,
    writer: WalWriterHandle,
) -> Option<JoinHandle<()>> {
    let handle = crate::daemon::recall_latency_cron::spawn_recall_latency_cron_loop(
        config.recall_latency,
        FreedomConfig::default_neoth_home(),
        writer,
    );
    if handle.is_some() {
        info!(
            interval_secs = config.recall_latency.interval_secs,
            p95_threshold_ms = config.recall_latency.p95_threshold_ms,
            "recall-latency cron loop spawned (MONITOR-03)"
        );
    }
    handle
}

/// SL-03 — ResourcePressureWatcher cron; emits `0x47 RESOURCE_PRESSURE_ALERT`.
pub(crate) fn spawn_resource_watch(
    config: &FreedomConfig,
    writer: WalWriterHandle,
) -> Option<JoinHandle<()>> {
    let handle =
        crate::daemon::resource_watch::spawn_resource_watch_loop(config.resource_watch.clone(), writer);
    if handle.is_some() {
        info!(
            interval_secs = config.resource_watch.interval_secs,
            vram_threshold_pct = config.resource_watch.vram_threshold_pct,
            "resource-watch cron loop spawned (SL-03)"
        );
    }
    handle
}

/// HO-07 — monitor alerting cron (`0x48`/`0x49`/`0x4A`).
pub(crate) fn spawn_monitor_cron(
    config: &FreedomConfig,
    wal_dir: &std::path::Path,
    writer: WalWriterHandle,
) -> Option<JoinHandle<()>> {
    let handle = crate::daemon::monitor_cron::spawn_monitor_cron_loop(
        config.monitor.clone(),
        FreedomConfig::default_neoth_home(),
        wal_dir.to_path_buf(),
        writer,
    );
    if handle.is_some() {
        info!(
            interval_secs = config.monitor.interval_secs,
            "monitor cron loop spawned (HO-07)"
        );
    }
    handle
}

/// OM-01 — local OMI transcript ingest. `None` when `omi.enabled = false`.
pub(crate) fn spawn_omi_ingest(
    config: &FreedomConfig,
    writer: WalWriterHandle,
) -> Option<JoinHandle<()>> {
    if !config.omi.enabled {
        return None;
    }
    let handle = crate::daemon::omi_ingest_task::spawn_omi_ingest_task(
        config.omi.clone(),
        crate::memory::store::default_path(),
        writer,
    );
    info!(endpoint = %config.omi.endpoint, "OMI ingest task spawned (OM-01)");
    Some(handle)
}

/// SPEC-05 — passive user-adaptation cron (queues self-dev PROPOSALS, never auto-applies).
pub(crate) fn spawn_profile_adapt_cron(
    config: &FreedomConfig,
    wal_dir: &std::path::Path,
    writer: WalWriterHandle,
) -> Option<JoinHandle<()>> {
    let handle = crate::daemon::profile_adapt_cron::spawn_profile_adapt_cron_loop(
        config.profile_adapt,
        FreedomConfig::default_neoth_home(),
        wal_dir.to_path_buf(),
        writer,
    );
    if handle.is_some() {
        info!(
            interval_secs = config.profile_adapt.interval_secs,
            "passive user-adaptation cron loop spawned (SPEC-05)"
        );
    }
    handle
}

/// F4-01 — ecology auto-scheduler (STAGES review-gated self-dev proposals, emits `0x4C`).
pub(crate) fn spawn_ecology_cron(
    config: &FreedomConfig,
    wal_dir: &std::path::Path,
    writer: WalWriterHandle,
) -> Option<JoinHandle<()>> {
    let handle = crate::ecology::scheduler::spawn_ecology_cron_loop(
        FreedomConfig::default_neoth_home(),
        wal_dir.to_path_buf(),
        config.ecology.clone(),
        writer,
    );
    if handle.is_some() {
        info!(
            interval_secs = config.ecology.scheduler_interval_secs,
            min_streak = config.ecology.correlation_min_streak,
            "ecology auto-scheduler cron loop spawned (F4-01 — proposals review-gated)"
        );
    }
    handle
}

// ── Region-7 updater lanes (U-04 + MV-01b). The three probe crons share one
// `UpdaterCronConfig` (built once in run_serve + cloned into each) and differ
// only by their ComponentSpec builder closure + UpdaterTaskKind. The two
// auto_update lanes (cli-apply / self-stage) gate internally on autonomy. All
// WAL-emitting; per-site keeps each handle/abort-site/worker_watch unchanged. ──

/// Shared type of the `ComponentSpec` builder closure each updater probe cron
/// hands to `spawn_updater_cron_loop`.
type UpdaterSpecBuilder =
    Arc<dyn Fn() -> Vec<crate::updater::pipeline::ComponentSpec> + Send + Sync + 'static>;

/// U-01 — neoth-self GitHub-Releases update probe cron (`0x44`/`0x45`).
pub(crate) fn spawn_updater_self_cron(
    cfg: crate::daemon::updater_cron::UpdaterCronConfig,
    writer: WalWriterHandle,
) -> Option<JoinHandle<()>> {
    let builder: UpdaterSpecBuilder = Arc::new(|| {
        crate::updater::probes::neoth_self_specs_blocking(
            crate::updater::pipeline::GateDecision::Allow,
        )
    });
    let handle = crate::daemon::updater_cron::spawn_updater_cron_loop(
        cfg,
        crate::wal::payloads_u04::UpdaterTaskKind::NeothSelf,
        builder,
        writer,
    );
    if handle.is_some() {
        info!("updater cron loop spawned: neoth_self (U-01)");
    }
    handle
}

/// U-03 — CLI-version npm-registry update probe cron (claude/codex/gemini).
pub(crate) fn spawn_updater_cli_cron(
    cfg: crate::daemon::updater_cron::UpdaterCronConfig,
    writer: WalWriterHandle,
) -> Option<JoinHandle<()>> {
    let builder: UpdaterSpecBuilder = Arc::new(|| {
        crate::updater::probes::cli_version_specs_blocking(
            crate::updater::pipeline::GateDecision::Allow,
        )
    });
    let handle = crate::daemon::updater_cron::spawn_updater_cron_loop(
        cfg,
        crate::wal::payloads_u04::UpdaterTaskKind::CliVersions,
        builder,
        writer,
    );
    if handle.is_some() {
        info!("updater cron loop spawned: cli_version (U-03)");
    }
    handle
}

/// U-02 — skill/plugin update probe cron (captures `home` for the spec scan).
pub(crate) fn spawn_updater_skill_cron(
    cfg: crate::daemon::updater_cron::UpdaterCronConfig,
    writer: WalWriterHandle,
) -> Option<JoinHandle<()>> {
    let home_for_skills = FreedomConfig::default_neoth_home();
    let builder: UpdaterSpecBuilder = Arc::new(move || {
        crate::updater::probes::skill_plugin_specs_blocking(
            home_for_skills.clone(),
            crate::updater::pipeline::GateDecision::Allow,
        )
    });
    let handle = crate::daemon::updater_cron::spawn_updater_cron_loop(
        cfg,
        crate::wal::payloads_u04::UpdaterTaskKind::SkillPlugin,
        builder,
        writer,
    );
    if handle.is_some() {
        info!("updater cron loop spawned: skill_plugin (U-02)");
    }
    handle
}

/// MV-01b — CLI auto-apply loop. Internally `None` at autonomy below
/// elevated/full (notify-only); emits `0x13 UPDATE_RAN` per applied CLI.
pub(crate) fn spawn_cli_autoupdate(
    config: &FreedomConfig,
    writer: WalWriterHandle,
) -> Option<JoinHandle<()>> {
    let handle = crate::daemon::auto_update::spawn(
        config.autonomy,
        config.updater.enabled,
        config.updater.interval_secs,
        writer,
    );
    if handle.is_some() {
        info!("CLI auto-apply loop spawned (MV-01b; autonomy elevated/full)");
    }
    handle
}

/// MV-01b #5 — neoth-self STAGING loop (stage-only — downloads + verifies +
/// stages newer releases; the operator applies via `neoth update --self --apply`).
pub(crate) fn spawn_self_stage(
    config: &FreedomConfig,
    writer: WalWriterHandle,
) -> Option<JoinHandle<()>> {
    let handle = crate::daemon::auto_update::spawn_self_stage(
        config.autonomy,
        config.updater.enabled,
        config.updater.interval_secs,
        "The-Geek-Freaks/NEOTH".to_string(),
        FreedomConfig::default_neoth_home(),
        writer,
    );
    if handle.is_some() {
        info!("neoth-self staging loop spawned (MV-01b #5; stage-only)");
    }
    handle
}

/// G-01 — weekly reflection cron (enqueues proactive items; per-week dedup key
/// in the producer keeps emissions to one/ISO-week regardless of tick rate).
/// WAL-free, home-only. Bare `JoinHandle<()>` (always spawns).
pub(crate) fn spawn_reflection_cron() -> JoinHandle<()> {
    let handle = crate::daemon::reflection_cron::spawn_reflection_cron_loop(
        FreedomConfig::default_neoth_home(),
        crate::daemon::reflection_cron::DEFAULT_CRON_INTERVAL_SECS,
    );
    info!(
        interval_secs = crate::daemon::reflection_cron::DEFAULT_CRON_INTERVAL_SECS,
        "reflection cron loop spawned (G-01 wiring — Round-3 v0.4)"
    );
    handle
}

/// G-02 — "knows things about you you don't know" surfacing cron; scans
/// idx_profile for high-confidence claims + enqueues them. WAL-free, home-only.
pub(crate) fn spawn_g02_surfacing_cron() -> JoinHandle<()> {
    let handle = crate::daemon::g02_surfacing_cron::spawn_g02_surfacing_cron_loop(
        FreedomConfig::default_neoth_home(),
        crate::daemon::g02_surfacing_cron::G02_CRON_INTERVAL_SECS,
    );
    info!(
        interval_secs = crate::daemon::g02_surfacing_cron::G02_CRON_INTERVAL_SECS,
        "G-02 surfacing cron loop spawned (Round-3 v0.4)"
    );
    handle
}

/// EL-01 — periodic `neoth doctor` cron (`0x46 DOCTOR_TICK`) + a sidecar
/// notification sink under `~/.neoth/notifications/`. `None` when disabled.
pub(crate) fn spawn_doctor_cron(
    config: &FreedomConfig,
    writer: WalWriterHandle,
) -> Option<JoinHandle<()>> {
    let home = FreedomConfig::default_neoth_home();
    let sink: Arc<dyn crate::daemon::doctor_cron::DoctorNotificationSink> = Arc::new(
        crate::daemon::doctor_cron::SidecarNotificationSink::new(home.join("notifications")),
    );
    let cfg = crate::daemon::doctor_cron::DoctorCronConfig {
        enabled: config.doctor.enabled,
        interval_secs: config.doctor.interval_secs,
        notify_channel: "cli".to_string(),
    };
    let interval_secs = cfg.interval_secs;
    let enabled = cfg.enabled;
    let handle = crate::daemon::doctor_cron::spawn_doctor_cron_loop(cfg, home, writer, sink);
    if handle.is_some() {
        info!(interval_secs, "doctor cron loop spawned (EL-01)");
    } else if !enabled {
        info!("doctor cron disabled via freedom.yaml::doctor.enabled = false");
    }
    handle
}

/// G-01 detector suite — behaviour-pattern cron (inactivity / query-repeat /
/// topic-burst / time-of-day-shift detectors → proactive nudges). WAL-free,
/// `config.pattern_cron` + home only. `None` when disabled.
pub(crate) fn spawn_pattern_cron(config: &FreedomConfig) -> Option<JoinHandle<()>> {
    let handle = crate::daemon::pattern_cron::spawn_pattern_cron_loop(
        config.pattern_cron,
        FreedomConfig::default_neoth_home(),
    );
    if handle.is_some() {
        info!(
            interval_secs = config.pattern_cron.interval_secs,
            inactivity_gap_secs = config.pattern_cron.inactivity_gap_secs,
            "pattern-detection cron loop spawned (G-01 detector suite)"
        );
    }
    handle
}

/// K-Models-Discovery — daily `~/.neoth/models_catalog.json` refresh. WAL-free;
/// ticks but does nothing when no cloud provider is configured (no outbound
/// traffic). Bare `JoinHandle<()>` (always spawns).
pub(crate) fn spawn_catalog_refresh(config: &FreedomConfig) -> JoinHandle<()> {
    let handle = crate::models::refresh_task::spawn_periodic_refresh(
        FreedomConfig::default_neoth_home(),
        config.clone(),
    );
    info!(
        tick_secs = crate::models::refresh_task::REFRESH_TICK_INTERVAL.as_secs(),
        "models catalog refresh task spawned (K-Models-Discovery)"
    );
    handle
}

/// HO-02 — kanban stale-planning reaper (startup, not spawned). Cerebellum
/// opens a session row + decomposes via LLM before flipping it to Running; a
/// dispatcher crash / daemon restart mid-decompose strands the row in Planning
/// forever (visible on `neoth kanban list`, never picked up). Sweep rows past a
/// 1-hour cut-off on each daemon startup so the operator sees a clean slate.
/// Best-effort + synchronous (own short-lived views.db connection, no WAL
/// writer): a views.db open failure is logged + skipped — hygiene, not
/// load-bearing on liveness.
pub(crate) fn run_stale_planning_reaper_on_startup() {
    const STALE_CUTOFF_NS: u64 = 3_600 * 1_000_000_000;
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    match crate::memory::store::open(&crate::memory::store::default_path()) {
        Ok(conn) => {
            // ensure_schema is idempotent + cheap; covers the fresh-install
            // case where the kanban tables haven't been created yet.
            if let Err(e) = crate::coding::store::ensure_schema(&conn) {
                warn!(error = %e, "kanban schema ensure failed at reaper; skipping sweep");
            } else {
                match crate::coding::store::reap_stale_planning_sessions(
                    &conn,
                    now_ns,
                    STALE_CUTOFF_NS,
                ) {
                    Ok(0) => {
                        tracing::debug!("kanban stale-planning reaper: nothing to abandon")
                    }
                    Ok(n) => {
                        info!(
                            reaped = n,
                            "kanban stale-planning reaper abandoned {n} session(s)"
                        )
                    }
                    Err(e) => {
                        warn!(error = %e, "kanban stale-planning reaper failed; non-fatal")
                    }
                }
            }
        }
        Err(e) => {
            warn!(error = %e, "stale-planning reaper: cannot open views.db; skipping");
        }
    }
}

/// n8n localhost API (`freedom.yaml::n8n_api.enabled`). Loopback hyper server
/// on 127.0.0.1; `n8n_api_shutdown` (a shared `Notify`) lets the daemon stop the
/// accept loop cleanly at shutdown. `None` when disabled or the token load
/// fails (API simply absent that session). WAL-emitting (the API state holds a
/// writer clone) — but a pure construction relocation, so the handle stays bound
/// to the same site + drained at the same shutdown point.
pub(crate) fn spawn_n8n_api(
    config: &FreedomConfig,
    writer: &WalWriterHandle,
    n8n_api_shutdown: &Arc<tokio::sync::Notify>,
) -> Option<JoinHandle<()>> {
    if !config.n8n_api.enabled {
        tracing::debug!("freedom.yaml::n8n_api.enabled = false; skipping localhost API spawn");
        return None;
    }
    let home = FreedomConfig::default_neoth_home();
    let token_path = config
        .n8n_api
        .token_path
        .clone()
        .unwrap_or_else(|| home.clone());
    match crate::n8n_api::server::load_or_init_token(&token_path) {
        Ok(token) => {
            let state = std::sync::Arc::new(crate::n8n_api::server::ApiState {
                writer: writer.clone(),
                config: std::sync::Arc::new(config.clone()),
                home: home.clone(),
                token,
                cooldown: std::sync::Arc::new(crate::n8n_api::auth::AuthCooldown::new()),
                boot_instant: std::time::Instant::now(),
            });
            info!(
                port = config.n8n_api.port,
                "n8n localhost API enabled — spawning hyper task on 127.0.0.1"
            );
            Some(crate::n8n_api::server::spawn_server(
                state,
                std::sync::Arc::clone(n8n_api_shutdown),
            ))
        }
        Err(e) => {
            warn!(
                error = %e,
                path = %token_path.display(),
                "n8n_api token load/init failed — API will NOT be available this session"
            );
            None
        }
    }
}

/// `/healthz` + `/metrics` listener (Phase 33c BS-1). Off by default; opt in via
/// `freedom.yaml::observability_listen: "127.0.0.1:PORT"`. Loopback by design.
/// `None` when unset or the host:port is invalid. WAL-free.
pub(crate) fn spawn_healthz(
    config: &FreedomConfig,
    provider_meter: &crate::providers::meter::Meter,
) -> Option<JoinHandle<anyhow::Result<()>>> {
    match config.observability_listen.as_deref() {
        None => None,
        Some(addr_str) => match addr_str.parse::<std::net::SocketAddr>() {
            Ok(addr) => {
                let cfg = crate::daemon::healthz::HealthzConfig {
                    home: FreedomConfig::default_neoth_home(),
                    config: Some(Arc::new(config.clone())),
                    // Daemon path: feed the live provider meter so
                    // `/healthz` + `/metrics` show tps + p50/p95.
                    meter: Some(provider_meter.clone()),
                };
                info!(addr = %addr, "spawning /healthz + /metrics listener");
                Some(crate::daemon::healthz::spawn(addr, cfg))
            }
            Err(e) => {
                warn!(addr = %addr_str, error = %e, "observability_listen has invalid host:port; listener not started");
                None
            }
        },
    }
}

/// Audit-RPC loopback listener (AUDIT-RPC-01). Off by default. When
/// `freedom.yaml::audit_rpc.enabled`, one-shot CLIs forward their `0xA5..=0xAD`
/// audit frames to this (the WAL-owning) daemon. Returns BOTH the listener task
/// AND the `SidecarGuard` — the guard MUST be bound for the daemon lifetime in
/// `run_serve` (its `Drop` removes the sidecar + token), so it is returned, not
/// dropped here. `(None, None)` when disabled or bind/token-mint fails. Async
/// (binds the socket). WAL-emitting via the listener's writer clone.
pub(crate) async fn spawn_audit_rpc(
    config: &FreedomConfig,
    writer: &WalWriterHandle,
) -> (
    Option<JoinHandle<anyhow::Result<()>>>,
    Option<crate::daemon::audit_rpc::SidecarGuard>,
) {
    if !config.audit_rpc.enabled {
        return (None, None);
    }
    let home = FreedomConfig::default_neoth_home();
    // Clear any sidecar+token a PRIOR daemon left behind on a crash (no clean
    // SidecarGuard drop) BEFORE minting fresh ones — closes the
    // stale-token-disclosure window (recycled port).
    crate::daemon::audit_rpc::remove_sidecar(&home);
    match crate::daemon::audit_rpc::init_rpc_token(&home) {
        Ok(token) => {
            let state = crate::daemon::audit_rpc::AuditRpcState {
                token: token.clone(),
                writer: writer.clone(),
                cooldown: std::sync::Arc::new(crate::n8n_api::auth::AuthCooldown::new()),
            };
            match crate::daemon::audit_rpc::bind_and_serve(state).await {
                Ok((addr, task)) => {
                    if let Err(e) = crate::daemon::audit_rpc::write_sidecar(
                        &home,
                        addr.port(),
                        std::process::id(),
                        &token,
                    ) {
                        warn!(error = %e, "audit-RPC sidecar write failed; one-shots can't find the port");
                    }
                    info!(port = addr.port(), "audit-RPC listener up (127.0.0.1)");
                    (
                        Some(task),
                        Some(crate::daemon::audit_rpc::SidecarGuard::new(home.clone())),
                    )
                }
                Err(e) => {
                    warn!(error = %e, "audit-RPC listener failed to bind; one-shot audit forwarding disabled");
                    (None, None)
                }
            }
        }
        Err(e) => {
            warn!(error = %e, "audit-RPC token mint failed; listener not started");
            (None, None)
        }
    }
}

/// R-02 Phase 4c dreaming nightly task. Off by default (`dreaming.enabled`);
/// composes one batch of dreams per interval over a window, using
/// `compose_dreams_with_embeddings` when an embedding provider is buildable
/// (falls back to deterministic compose otherwise). Hands the chat provider in
/// only when `dreaming.summarize_themes` is on (cost gate). WAL-emitting (0xF4
/// DREAM_COMPOSED via the writer clone). `None` when disabled. Async — it builds
/// the embedding provider at spawn time.
pub(crate) async fn spawn_dreaming(
    config: &FreedomConfig,
    shared_provider: &Option<Arc<dyn Provider>>,
    writer: &WalWriterHandle,
) -> Option<JoinHandle<anyhow::Result<()>>> {
    if !config.dreaming.enabled {
        return None;
    }
    let embed_provider = crate::providers::embed_provider_from_config(config).await;
    // SPEC-12 Phase 4b — only hand the chat provider to the dreaming task when
    // `dreaming.summarize_themes` is on (cost-safe gate: it adds one LLM call
    // per cluster). Reuses the already-built shared provider chain; `None` keeps
    // deterministic cluster labels.
    let dream_chat = if config.dreaming.summarize_themes {
        shared_provider.as_ref().map(Arc::clone)
    } else {
        None
    };
    Some(crate::cli::dreaming_task::spawn(
        FreedomConfig::default_neoth_home(),
        embed_provider,
        dream_chat,
        config
            .dreaming
            .interval_secs
            .map(std::time::Duration::from_secs),
        config
            .dreaming
            .window_secs
            .map(std::time::Duration::from_secs),
        config.dreaming.max_events,
        // SPEC-12 daemon-side audit: the daemon owns the WAL writer, so each
        // non-empty nightly pass emits a `0xF4 DREAM_COMPOSED` frame.
        Some(writer.clone()),
    ))
}

/// Cron scheduler (Phase 33a AU-B5). Loads `~/.neoth/jobs.yaml` if present and
/// spawns the tick loop; a missing jobs file is NOT an error (returns
/// `Ok(None)`), but bad YAML IS — it propagates `Err` so the daemon fails loudly
/// at startup rather than silently never firing. Requires a provider. Async
/// (reads + parses jobs.yaml); WAL-emitting via the scheduler's writer clone.
pub(crate) async fn spawn_cron_scheduler(
    config: &FreedomConfig,
    shared_provider: &Option<Arc<dyn Provider>>,
    writer: &WalWriterHandle,
) -> anyhow::Result<Option<JoinHandle<()>>> {
    match (shared_provider.as_ref(), config.jobs_file_path()) {
        (Some(provider), Some(jobs_path)) if jobs_path.exists() => {
            match crate::cron::JobsFile::load_from_path(&jobs_path).await {
                Ok(jobs) => {
                    let writer_for_cron = writer.clone();
                    let provider_for_cron = provider.clone();
                    let count = jobs.jobs.len();
                    let handle = tokio::spawn(async move {
                        if let Err(e) = crate::cron::scheduler::run_scheduler(
                            jobs,
                            provider_for_cron,
                            writer_for_cron,
                        )
                        .await
                        {
                            tracing::error!(error = %e, "cron scheduler exited with error");
                        }
                    });
                    info!(jobs = count, path = %jobs_path.display(), "cron scheduler spawned");
                    Ok(Some(handle))
                }
                Err(e) => Err(anyhow::anyhow!(
                    "failed to load {}: {e:#}",
                    jobs_path.display(),
                )),
            }
        }
        (Some(_), Some(jobs_path)) => {
            info!(path = %jobs_path.display(), "no jobs.yaml; cron scheduler idle");
            Ok(None)
        }
        (None, _) => Ok(None),
        (_, None) => Ok(None),
    }
}

/// Memory indexer — tails the WAL into the SQLite views db so `neoth recall` is
/// near-real-time. Opens its own `views.db` connection; `None` (logged) when the
/// open fails (recall then runs a per-query index pass). WAL-free (reads the WAL,
/// writes SQLite).
pub(crate) fn spawn_indexer(segment_path: &std::path::Path) -> Option<JoinHandle<()>> {
    let conn_path = crate::memory::store::default_path();
    let seg = segment_path.to_path_buf();
    match crate::memory::store::open(&conn_path) {
        Ok(conn) => Some(tokio::spawn(async move {
            if let Err(e) =
                crate::memory::indexer::tail(conn, seg, std::time::Duration::from_millis(500)).await
            {
                tracing::error!(error = %e, "indexer tail task exited with error");
            }
        })),
        Err(e) => {
            warn!(error = %e, "failed to open views.db; recall queries will run an index pass each time");
            None
        }
    }
}

/// Hot-reload sentinel poller (Pick #37). Polls `~/.neoth/.reload-requested`
/// every 2s; on presence, re-reads freedom.yaml + swaps the ArcSwap (or rejects)
/// via the shared `crate::cli::serve::handle_reload_sentinel`. Bare
/// `JoinHandle<()>` (always spawns). WAL-emitting (the reload handler writes a
/// CONFIG_RELOADED / CONFIG_RELOAD_REJECTED frame via the writer clone).
pub(crate) fn spawn_reload_poller(
    reload_controller: &Arc<crate::config::reload::ReloadController>,
    writer: &WalWriterHandle,
) -> JoinHandle<()> {
    let ctrl = Arc::clone(reload_controller);
    let writer_for_reload = writer.clone();
    let home = FreedomConfig::default_neoth_home();
    let sentinel = home.join(crate::config::reload::RELOAD_SENTINEL_NAME);
    tokio::spawn(async move {
        // 2s polling interval — cheap stat call; the sentinel is usually absent.
        // Tight enough that a manual `neoth reload` feels responsive (P95 ~1s).
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if sentinel.exists() {
                crate::cli::serve::handle_reload_sentinel(&ctrl, &sentinel, &writer_for_reload)
                    .await;
            }
        }
    })
}

/// G-01 consumer half — proactive drain loop (Round-3 v0.4). Drains the
/// ProactiveQueue + appends to the JSONL sidecar on a cadence. Bare
/// `JoinHandle<()>` (always spawns). WAL-emitting via the writer clone.
pub(crate) fn spawn_proactive_dispatcher(writer: &WalWriterHandle) -> JoinHandle<()> {
    let handle = crate::daemon::proactive_dispatcher::spawn_proactive_drain_loop(
        FreedomConfig::default_neoth_home(),
        crate::daemon::proactive_dispatcher::PROACTIVE_DRAIN_INTERVAL_SECS,
        writer.clone(),
    );
    info!(
        interval_secs = crate::daemon::proactive_dispatcher::PROACTIVE_DRAIN_INTERVAL_SECS,
        "proactive drain loop spawned (G-01 consumer half — Round-3 v0.4)"
    );
    handle
}

/// HO-09b profile drift-alert cron. Emits `0xBA PROFILE_DRIFT_ALERT` on a 6h
/// schedule when the profile drifts past `drift_alert.threshold`. Off by default
/// (`None` when `drift_alert.enabled = false`). WAL-emitting via the writer clone.
pub(crate) fn spawn_drift_alert_cron(
    config: &FreedomConfig,
    writer: &WalWriterHandle,
) -> Option<JoinHandle<()>> {
    let handle = crate::daemon::drift_alert_cron::spawn_drift_alert_cron_loop(
        config.drift_alert,
        FreedomConfig::default_neoth_home(),
        writer.clone(),
    );
    if handle.is_some() {
        info!(
            interval_secs = config.drift_alert.interval_secs,
            threshold = config.drift_alert.threshold,
            "profile drift-alert cron loop spawned (HO-09b)"
        );
    }
    handle
}

/// ADV-14 regression-anchor cron. Weekly re-asks the anchor queries, re-embeds,
/// emits `0x3F REGRESSION_ALERT` on a cosine drop. Off by default; needs BOTH a
/// chat provider AND a configured embed provider — `None` (with a warn) when
/// enabled-but-unconfigured. Async (builds the embed provider). WAL-emitting.
pub(crate) async fn spawn_regression_cron(
    config: &FreedomConfig,
    shared_provider: &Option<Arc<dyn Provider>>,
    writer: &WalWriterHandle,
) -> Option<JoinHandle<()>> {
    if !config.regression_anchor.enabled {
        return None;
    }
    match (
        shared_provider.as_ref(),
        crate::providers::embed_provider_from_config(config).await,
    ) {
        (Some(provider), Some(embed)) => {
            let handle = crate::daemon::regression_cron::spawn_regression_cron_loop(
                config.regression_anchor,
                FreedomConfig::default_neoth_home(),
                Arc::clone(provider),
                embed,
                writer.clone(),
            );
            if handle.is_some() {
                info!(
                    interval_secs = config.regression_anchor.interval_secs,
                    threshold = config.regression_anchor.threshold,
                    "regression-anchor cron loop spawned (ADV-14)"
                );
            }
            handle
        }
        _ => {
            tracing::warn!(
                "regression_anchor.enabled but no chat/embed provider configured — \
                 cron not started (set inference.embedding_provider + a provider)"
            );
            None
        }
    }
}

/// GOLD-WIRE-07b daemon HNSW snapshot auto-freshness. Every 30 min, rebuilds the
/// on-disk HNSW snapshot FROM SQLite (the source of truth shared with the
/// separate `neoth ingest` CLI) when stale — first tick at boot. Off entirely
/// unless `memory.vector_index.backend == Hnsw` (`None`). WAL-free (only SQLite
/// reads + an atomic snapshot rename), so order-independent at shutdown. The
/// blocking rebuild runs via `spawn_blocking`.
pub(crate) fn spawn_snapshot_refresh(config: &FreedomConfig) -> Option<JoinHandle<()>> {
    if config.memory.vector_index.backend != crate::config::VectorBackend::Hnsw {
        return None;
    }
    const REFRESH_INTERVAL_SECS: u64 = 1800; // 30 min
    let home = FreedomConfig::default_neoth_home();
    let handle = tokio::spawn(async move {
        let mut tick =
            tokio::time::interval(std::time::Duration::from_secs(REFRESH_INTERVAL_SECS));
        // A slow rebuild must not bunch up missed ticks into a burst.
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            // First tick fires immediately → a boot-time freshness pass.
            tick.tick().await;
            let home = home.clone();
            // Blocking SQLite + a full O(N log N) index rebuild → off the reactor.
            match tokio::task::spawn_blocking(move || {
                crate::memory::snapshot_refresh::refresh_snapshot_once(&home, true)
            })
            .await
            {
                Ok(Ok(Some(n))) => info!(
                    vectors = n,
                    "GOLD-WIRE-07b: HNSW snapshot refreshed from SQLite"
                ),
                Ok(Ok(None)) => {} // fresh / below-ceiling — nothing to do
                Ok(Err(e)) => {
                    warn!(error = %e, "GOLD-WIRE-07b snapshot refresh failed (non-fatal)")
                }
                Err(e) => {
                    warn!(error = %e, "GOLD-WIRE-07b snapshot refresh task join error")
                }
            }
        }
    });
    info!(
        interval_secs = REFRESH_INTERVAL_SECS,
        "HNSW snapshot auto-refresh cron spawned (GOLD-WIRE-07b)"
    );
    Some(handle)
}

/// Self-dev outbox drain (P-04 follow-on). The `neoth self-dev
/// accept/decline/propose` CLI runs without a WAL writer (the daemon owns the
/// segment), so it enqueues pending events in
/// `~/.neoth/self_dev/pending_events.jsonl`; this task drains them every
/// `DRAIN_INTERVAL` and emits the real SELF_DEV_* frames. Bare `JoinHandle<()>`
/// (always spawns). WAL-emitting via the writer clone.
pub(crate) fn spawn_self_dev_outbox(writer: &WalWriterHandle) -> JoinHandle<()> {
    let handle = crate::cli::self_dev_outbox::spawn_drain_task(
        FreedomConfig::default_neoth_home(),
        writer.clone(),
    );
    info!(
        tick_secs = crate::cli::self_dev_outbox::DRAIN_INTERVAL.as_secs(),
        "self-dev outbox drain task spawned"
    );
    handle
}

/// Cluster audit-sidecar ingester (cluster feature only). Polls
/// `~/.neoth/pending_audit/cluster_*.json` every 5s, appends the WAL 0xE6/0xE7
/// frame, removes the consumed file. Bare `JoinHandle<()>` (always spawns under
/// the feature). WAL-emitting via the writer clone.
#[cfg(feature = "cluster")]
pub(crate) fn spawn_cluster_audit_ingester(writer: &WalWriterHandle) -> JoinHandle<()> {
    let writer_for_audit = writer.clone();
    let home = FreedomConfig::default_neoth_home();
    tokio::spawn(async move {
        const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
        loop {
            tokio::time::sleep(POLL_INTERVAL).await;
            let pending = match crate::cluster::audit_sidecar::list_pending(&home) {
                Ok(v) => v,
                Err(e) => {
                    warn!(error = %e, "cluster audit sidecar list failed");
                    continue;
                }
            };
            for (path, sidecar) in pending {
                let event_type = sidecar.kind.wal_event_type();
                let body = crate::cluster::audit_sidecar::build_wal_frame_body(&sidecar);
                let header = crate::wal::HeaderBuilder::new(event_type, &body).build();
                match writer_for_audit.append(header, body).await {
                    Ok(_) => {
                        if let Err(e) = crate::cluster::audit_sidecar::remove_sidecar(&path) {
                            warn!(
                                error = %e,
                                path = %path.display(),
                                "cluster audit sidecar remove failed after WAL append"
                            );
                        } else {
                            info!(
                                kind = sidecar.kind.as_str(),
                                pub_key_prefix =
                                    &sidecar.pub_key_hex[..16.min(sidecar.pub_key_hex.len())],
                                "cluster audit frame appended to WAL"
                            );
                        }
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            path = %path.display(),
                            "cluster audit WAL append failed; sidecar retained for next tick"
                        );
                    }
                }
            }
        }
    })
}

/// Spawn a `Channel::run` adapter loop into `channel_tasks` (Telegram / Slack
/// socket-mode — every adapter whose receive loop is `Channel::run`, NOT the
/// WhatsApp webhook listener which uses `webhook_listener::serve`). `label` is
/// the channel name for the exit-error log. `Channel: Send + Sync` (the trait's
/// `#[async_trait]` boxes a `Send` future), so the generic spawn is sound.
/// Pure relocation of the identical `tokio::spawn(channel.run(handler))` +
/// `channel_tasks.push(task)` block the adapters inlined.
pub(crate) fn spawn_channel_run<C: Channel + 'static>(
    channel: C,
    handler: PipelineHandler,
    label: &'static str,
    channel_tasks: &mut Vec<JoinHandle<()>>,
) {
    let task = tokio::spawn(async move {
        if let Err(e) = channel.run(handler).await {
            tracing::error!(error = %e, "{label} channel task exited with error");
        }
    });
    channel_tasks.push(task);
}

/// Build the per-message channel pipeline handler shared by every configured
/// channel adapter (Telegram / Slack socket-mode / WhatsApp webhook). The three
/// adapters previously inlined an identical 11-field [`PipelineHandlerDeps`]
/// literal; this is the single construction site so the field mapping lives in
/// one place. `provider` is the adapter-specific provider clone; everything else
/// is borrowed from the shared daemon locals and cloned into the deps exactly as
/// before (behaviour-identical to the inline literals).
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_channel_handler(
    provider: Arc<dyn Provider>,
    config: &FreedomConfig,
    writer: &WalWriterHandle,
    provider_meter: &crate::providers::meter::Meter,
    rate_limiter: &Arc<crate::channels::rate_limit::RateLimiter>,
    segment_path: &std::path::Path,
    shared_views_conn: &Option<Arc<tokio::sync::Mutex<rusqlite::Connection>>>,
    reload_controller: &Arc<crate::config::reload::ReloadController>,
) -> PipelineHandler {
    build_pipeline_handler(PipelineHandlerDeps {
        provider,
        writer: writer.clone(),
        operator_id: config.operator_id.clone(),
        autonomy: config.autonomy,
        goal_max_turns: config.goal.max_turns,
        meter: provider_meter.clone(),
        rate_limiter: Arc::clone(rate_limiter),
        segment_path: segment_path.to_path_buf(),
        profile_config: config.profile.clone(),
        reload_controller: Arc::clone(reload_controller),
        views_conn: shared_views_conn.clone(),
    })
}

/// Abort an optional background task and await its termination, swallowing the
/// `JoinError` from the cancel. No-op when `None`. This is the standard daemon
/// shutdown teardown for every cancel-safe background task — `abort` + `await`
/// stops the task from emitting new WAL frames BEFORE `drop(writer)` drains the
/// writer. Behaviour-identical to the inline `if let Some(task) = X { task.abort();
/// let _ = task.await; }` it replaces.
pub(crate) async fn abort_optional<T>(task: Option<JoinHandle<T>>) {
    if let Some(task) = task {
        task.abort();
        let _ = task.await;
    }
}

/// Abort a (non-optional) background task and await its termination. The
/// always-spawned sibling of [`abort_optional`]; behaviour-identical to the
/// inline `task.abort(); let _ = task.await;` it replaces.
pub(crate) async fn abort_join<T>(task: JoinHandle<T>) {
    task.abort();
    let _ = task.await;
}

/// GOLD-ARCH-01: post-config runtime-service priming, run after config load and
/// before WAL setup. Enforces the OM-01 SC-14 OMI-local-endpoint hard rule
/// (bail on a cloud OMI backend), runs the V03-08 + A-2 consent gate (bails with
/// an actionable error if any cloud provider is unconsented), primes the
/// process-wide `SkillRegistry` + its filesystem watcher, and installs the
/// GOLD-WIRE-10 domain-event bus. Returns the `WatcherHandle` (bound by the
/// caller for the daemon lifetime). Async (the skill registry loads off disk).
pub(crate) async fn prime_runtime_services(
    config: &FreedomConfig,
) -> anyhow::Result<Option<crate::skills::registry::WatcherHandle>> {
    // OM-01 SC-14 hard rule: if OMI ingest is enabled, the endpoint MUST be a
    // self-hosted/local address — refuse to start against a cloud OMI backend
    // (api.omi.me) so operator transcripts never leave the machine.
    if config.omi.enabled {
        if let Err(reason) = crate::installers::omi::is_local_endpoint(&config.omi.endpoint) {
            anyhow::bail!(
                "SC-14 OMI hard rule: {reason}. Set freedom.yaml::omi.endpoint to a local \
                 address (e.g. http://127.0.0.1:8002) or disable it (omi.enabled: false)."
            );
        }
    }

    // V03-08 + A-2 preflight: daemon has no TTY so `ensure_all_granted_or_prompt`
    // bails with an actionable error if any cloud provider in the operator's
    // freedom.yaml is not yet consented (covers single-mode `provider_kind` AND
    // the per-hemisphere providers). `NEOTH_CONSENT_BYPASS=1` skips it for CI.
    {
        let home = FreedomConfig::default_neoth_home();
        crate::consent::ensure_all_granted_or_prompt(&home, config)
            .context("consent gate (V03-08 + A-2)")?;
    }

    // E-22 chat-route: prime the process-wide SkillRegistry + start its
    // filesystem watcher BEFORE any request-handling task spawns, so operator
    // edits to `~/.neoth/skills/<id>/skill.yaml` propagate to the next chat turn
    // (250ms debounce). The watcher handle is owned by the daemon lifetime.
    let skill_watcher = {
        let home = FreedomConfig::default_neoth_home();
        let skills_dir = home.join("skills");
        match crate::skills::SkillRegistry::load(&skills_dir).await {
            Ok(reg) => {
                let watcher = reg.watch();
                let inited = crate::skills::registry::init_global(std::sync::Arc::clone(&reg));
                if !inited {
                    warn!(
                        "global skill registry already initialised earlier in this process — \
                         keeping the existing instance + spawning a redundant watcher (cheap)"
                    );
                }
                info!(
                    skill_count = reg.snapshot().len(),
                    dir = %skills_dir.display(),
                    watcher_active = watcher.is_some(),
                    "skill registry primed for daemon"
                );
                watcher
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "skill registry load failed; chat paths will fall back to per-call load"
                );
                None
            }
        }
    };

    // GOLD-WIRE-10: install the process-wide domain-event bus + spawn its meter
    // drainer BEFORE any request-handling task can produce events (council
    // hemisphere calls fire `ProviderResponded`; the UsageMeter folds token
    // counts into the running KF-08 budget total).
    if !crate::domain_events::init_global() {
        warn!("domain-event bus already installed earlier in this process");
    }

    Ok(skill_watcher)
}

/// GOLD-ARCH-01: the pre-config startup guards — home-dir isolation (BS-9),
/// clock-rollback guard (BS-5), and the single-instance PID lock (BS-12). These
/// run at the very top of `run_serve` BEFORE config load and produce only the
/// `PidGuard` (returned so the caller binds it for the daemon lifetime — its
/// `Drop` releases the lock). `--one-shot` skips isolation + the PID lock
/// (ephemeral tempdirs / shared CI runners). Synchronous; bails on a tripped
/// guard. Behaviour-identical to the prior inline `run_serve` prelude.
pub(crate) fn run_preflight_guards(
    one_shot: bool,
    allow_clock_rollback: bool,
) -> anyhow::Result<Option<crate::daemon::pidfile::PidGuard>> {
    // ── 0. Home-dir isolation (Phase 33c BS-9) ──────────────────────────────
    // Refuse to start if `~/.neoth/` is readable by other users. One-shot mode
    // (smoke checks + integration tests) skips this guard — those run against
    // ephemeral tempdirs / shared CI runners where home perms are out of scope.
    if !one_shot {
        crate::daemon::isolation::check_home_isolation(&FreedomConfig::default_neoth_home())?;
    }

    // ── 0a. Clock rollback guard (Phase 33c BS-5) ───────────────────────────
    // Bail before any WAL write if the system clock is far behind the last
    // observed timestamp. `--allow-clock-rollback` skips it (intentional rewind).
    if !allow_clock_rollback {
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        crate::daemon::clock_floor::check(
            &crate::daemon::clock_floor::default_floor_path(),
            now_ns,
        )?;
    } else {
        warn!("--allow-clock-rollback: skipping monotonic clock guard");
    }

    // ── 0b. Single-instance lock (Phase 33c BS-12) ──────────────────────────
    // Acquire `~/.neoth/neothd.pid` BEFORE touching the WAL — a second daemon
    // writing the same segment would corrupt the byte stream. Skipped under
    // `--one-shot` so integration tests can run in parallel.
    let pid_guard = if one_shot {
        None
    } else {
        match crate::daemon::pidfile::acquire(&crate::daemon::pidfile::default_pidfile()) {
            Ok(g) => Some(g),
            Err(e) => {
                anyhow::bail!("{e}");
            }
        }
    };
    Ok(pid_guard)
}

/// GOLD-ARCH-01: every background-task handle + teardown-only local produced
/// between WAL setup and the idle-wait, grouped so the ~230-LOC shutdown
/// sequence can move out of `run_serve` into [`shutdown_background_tasks`].
/// RAII guards (`_pid_guard` / `_skill_watcher` / `_audit_rpc_guard`) are
/// deliberately NOT here — they stay bound in `run_serve` so their `Drop` fires
/// at fn-end AFTER the writer drain. `writer` + `writer_join` are passed
/// separately (the idle-wait `select!` borrows `&mut writer_join` before the call).
pub(crate) struct BackgroundHandles {
    pub worker_watch_handle: Option<JoinHandle<()>>,
    pub channel_tasks: Vec<JoinHandle<()>>,
    pub dispatch_join: Arc<tokio::sync::Mutex<tokio::task::JoinSet<()>>>,
    pub cron_task: Option<JoinHandle<()>>,
    pub doctor_cron_task: Option<JoinHandle<()>>,
    pub resource_watch_handle: Option<JoinHandle<()>>,
    pub monitor_cron_handle: Option<JoinHandle<()>>,
    pub snapshot_refresh_handle: Option<JoinHandle<()>>,
    pub omi_handle: Option<JoinHandle<()>>,
    pub updater_self_task: Option<JoinHandle<()>>,
    pub updater_cli_task: Option<JoinHandle<()>>,
    pub updater_skill_task: Option<JoinHandle<()>>,
    pub cli_autoupdate_task: Option<JoinHandle<()>>,
    pub self_stage_task: Option<JoinHandle<()>>,
    pub catalog_task: JoinHandle<()>,
    #[cfg(feature = "cluster")]
    pub cluster_audit_task: JoinHandle<()>,
    #[cfg(feature = "cluster")]
    pub cluster_gossip_task: Option<JoinHandle<()>>,
    #[cfg(feature = "cluster")]
    pub cluster_swarm: Option<crate::cluster::hyperswarm::SwarmHandle>,
    pub installer_audit_task: JoinHandle<()>,
    pub credentials_import_task: JoinHandle<()>,
    pub detect_complete_task: JoinHandle<()>,
    pub self_dev_outbox_task: JoinHandle<()>,
    pub indexer_task: Option<JoinHandle<()>>,
    pub reload_task: JoinHandle<()>,
    pub audit_rpc_task: Option<JoinHandle<anyhow::Result<()>>>,
    pub healthz_task: Option<JoinHandle<anyhow::Result<()>>>,
    pub decay_task: Option<JoinHandle<()>>,
    pub gc_task: Option<JoinHandle<anyhow::Result<()>>>,
    pub reflection_cron_handle: JoinHandle<()>,
    pub proactive_dispatcher_handle: JoinHandle<()>,
    pub g02_surfacing_cron_handle: JoinHandle<()>,
    pub drift_alert_cron_handle: Option<JoinHandle<()>>,
    pub regression_cron_handle: Option<JoinHandle<()>>,
    pub recall_latency_cron_handle: Option<JoinHandle<()>>,
    pub profile_adapt_cron_handle: Option<JoinHandle<()>>,
    pub ecology_cron_handle: Option<JoinHandle<()>>,
    pub pattern_cron_handle: Option<JoinHandle<()>>,
    pub dreaming_task: Option<JoinHandle<anyhow::Result<()>>>,
    pub arxiv_ingest_task: Option<JoinHandle<anyhow::Result<()>>>,
    pub rss_feed_task: Option<JoinHandle<anyhow::Result<()>>>,
    pub tmux_sweeper_task: Option<JoinHandle<anyhow::Result<()>>>,
    pub n8n_api_shutdown: Arc<tokio::sync::Notify>,
    pub n8n_api_task: Option<JoinHandle<()>>,
    pub obsidian_task: Option<JoinHandle<anyhow::Result<()>>>,
    pub cloud_task: Option<JoinHandle<anyhow::Result<()>>>,
    pub hysteria_supervisor: Option<crate::transport::hysteria::HysteriaSupervisor>,
}

/// GOLD-ARCH-01: the full ordered daemon shutdown sequence, moved VERBATIM out
/// of `run_serve`. Aborts/drains every background task in the exact prior order
/// (worker_watch FIRST per MONITOR-02; WAL-emitting tasks before `drop(writer)`;
/// the self-dev outbox final-drained via `&writer`; n8n notify-then-await;
/// cluster teardown; hysteria drop), then `drop(writer)` + `writer_join.await`.
/// The destructure restores the original local names so the body below is
/// byte-identical to the prior inline sequence.
pub(crate) async fn shutdown_background_tasks(
    handles: BackgroundHandles,
    writer: WalWriterHandle,
    writer_join: JoinHandle<()>,
) {
    let BackgroundHandles {
        worker_watch_handle,
        channel_tasks,
        dispatch_join,
        cron_task,
        doctor_cron_task,
        resource_watch_handle,
        monitor_cron_handle,
        snapshot_refresh_handle,
        omi_handle,
        updater_self_task,
        updater_cli_task,
        updater_skill_task,
        cli_autoupdate_task,
        self_stage_task,
        catalog_task,
        #[cfg(feature = "cluster")]
        cluster_audit_task,
        #[cfg(feature = "cluster")]
        cluster_gossip_task,
        #[cfg(feature = "cluster")]
        cluster_swarm,
        installer_audit_task,
        credentials_import_task,
        detect_complete_task,
        self_dev_outbox_task,
        indexer_task,
        reload_task,
        audit_rpc_task,
        healthz_task,
        decay_task,
        gc_task,
        reflection_cron_handle,
        proactive_dispatcher_handle,
        g02_surfacing_cron_handle,
        drift_alert_cron_handle,
        regression_cron_handle,
        recall_latency_cron_handle,
        profile_adapt_cron_handle,
        ecology_cron_handle,
        pattern_cron_handle,
        dreaming_task,
        arxiv_ingest_task,
        rss_feed_task,
        tmux_sweeper_task,
        n8n_api_shutdown,
        n8n_api_task,
        obsidian_task,
        cloud_task,
        hysteria_supervisor,
    } = handles;

    // MONITOR-02: abort the worker-watch FIRST — so the deliberate abort of the
    // watched workers (below) is never mistaken for an unexpected death + alerted.
    crate::cli::serve_tasks::abort_optional(worker_watch_handle).await;

    // Abort channel tasks first so they stop generating new WAL frames.
    for task in &channel_tasks {
        task.abort();
    }
    for task in channel_tasks {
        let _ = task.await; // ignore JoinError on aborted tasks
    }

    // COR-34: drain in-flight Meta webhook fan-out tasks (DISPATCH_GATE-bounded,
    // <=64) BEFORE drop(writer) so their pipeline WAL frames (RAW_TEXT,
    // CHANNEL_INGRESS/EGRESS, HOOK_FIRED) land. The channel tasks are already
    // aborted above so no new dispatches are added; these tasks live in the
    // shared JoinSet (not the listener task) so the abort above didn't cancel
    // them. Bounded: a slow/stuck turn (e.g. a hung provider holding a
    // WalWriterHandle clone) is abandoned via JoinSet::shutdown after the
    // timeout so the daemon can't hang on exit — those tasks' in-flight frames
    // are then dropped (same trade-off as the webhook HTTP drain).
    {
        const DISPATCH_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
        let drain = async {
            let mut js = dispatch_join.lock().await;
            while js.join_next().await.is_some() {}
        };
        if tokio::time::timeout(DISPATCH_DRAIN_TIMEOUT, drain).await.is_err() {
            warn!(
                timeout_s = DISPATCH_DRAIN_TIMEOUT.as_secs(),
                "COR-34: webhook dispatch drain timed out — aborting remaining \
                 fan-out tasks; their in-flight WAL frames may be lost"
            );
            dispatch_join.lock().await.shutdown().await;
        }
    }

    // Abort the cron scheduler — same reasoning as channels: stop emitting
    // new WAL frames before the writer drains.
    crate::cli::serve_tasks::abort_optional(cron_task).await;

    // Abort the EL-01 doctor cron loop. Same drain-before-writer-close
    // discipline as the regular cron scheduler.
    crate::cli::serve_tasks::abort_optional(doctor_cron_task).await;

    // Abort the SL-03 resource-watch cron loop (drain before writer close).
    crate::cli::serve_tasks::abort_optional(resource_watch_handle).await;

    // Abort the HO-07 monitor alerting cron loop (drain before writer close).
    crate::cli::serve_tasks::abort_optional(monitor_cron_handle).await;
    // GOLD-WIRE-07b: abort the HNSW snapshot auto-refresh cron. It writes no WAL
    // frames (only SQLite reads + an atomic snapshot rename), so its ordering vs
    // the writer drain is irrelevant — but abort it cleanly like the others.
    crate::cli::serve_tasks::abort_optional(snapshot_refresh_handle).await;
    crate::cli::serve_tasks::abort_optional(omi_handle).await;

    // Abort the U-04 updater cron loops (neoth_self + cli_version).
    // Drain before the WAL writer closes so any in-flight tick's
    // result-frame doesn't get dropped mid-append.
    crate::cli::serve_tasks::abort_optional(updater_self_task).await;
    crate::cli::serve_tasks::abort_optional(updater_cli_task).await;
    crate::cli::serve_tasks::abort_optional(updater_skill_task).await;
    // MV-01b CLI auto-apply loop. A mid-pass abort at worst drops one
    // component's UPDATE_RAN frame; the install itself already completed.
    crate::cli::serve_tasks::abort_optional(cli_autoupdate_task).await;
    // MV-01b #5 neoth-self staging loop. Mid-pass abort at worst drops a
    // partial staged archive (re-staged next boot); never swaps.
    crate::cli::serve_tasks::abort_optional(self_stage_task).await;

    // Abort the catalog refresh task. May be in the middle of an HTTPS
    // round-trip; aborting drops the connection, which is fine — the
    // next daemon start will re-run discovery on its first tick.
    crate::cli::serve_tasks::abort_join(catalog_task).await;

    // Abort the cluster audit sidecar ingester. Pending sidecars
    // on disk are retained — the next daemon start picks them up
    // on its first tick (at-least-once semantics are fine for an
    // audit frame, the WAL writer dedupes by frame hash).
    // GOLD-SEC-16: cluster task teardown only exists with the `cluster` feature.
    #[cfg(feature = "cluster")]
    {
        crate::cli::serve_tasks::abort_join(cluster_audit_task).await;

        // SL-01b: stop the gossip send-tick before tearing the transport down.
        crate::cli::serve_tasks::abort_optional(cluster_gossip_task).await;

        // SL-00(1b): tear down the cluster transport. `shutdown()` aborts the
        // discovery task + awaits it so we leave the DHT cleanly (no lingering
        // announce). `None` when the transport never came up — no-op.
        if let Some(swarm) = cluster_swarm {
            if let Err(e) = swarm.shutdown().await {
                warn!(error = %e, "cluster transport shutdown error (non-fatal)");
            } else {
                info!("cluster transport shut down");
            }
        }
    }

    // Abort the installer_ran + credentials_import sidecar ingesters.
    // Same at-least-once contract — any sidecars still on disk get
    // ingested on the next daemon start.
    crate::cli::serve_tasks::abort_join(installer_audit_task).await;
    crate::cli::serve_tasks::abort_join(credentials_import_task).await;
    crate::cli::serve_tasks::abort_join(detect_complete_task).await;

    // Final-drain the self-dev outbox BEFORE aborting the task so
    // CLI events queued in the last 5s land in the WAL instead of
    // waiting for the next daemon start.
    {
        let home = FreedomConfig::default_neoth_home();
        match crate::cli::self_dev_outbox::drain_once(&home, &writer).await {
            Ok(0) => {}
            Ok(n) => info!(emitted = n, "self-dev outbox final-drained on shutdown"),
            Err(e) => {
                warn!(error = %e, "self-dev outbox final-drain failed (events retained for next start)")
            }
        }
    }
    crate::cli::serve_tasks::abort_join(self_dev_outbox_task).await;

    // Abort the indexer next. It may have been mid-pass; the next `neoth serve`
    // start picks up from `wal_cursor`.
    crate::cli::serve_tasks::abort_optional(indexer_task).await;

    // Pick #37 (Session 14): abort the hot-reload poll task. The
    // controller is dropped along with `reload_controller`. A
    // pending sentinel on disk survives + the next `neoth serve`
    // boot picks it up via the at-boot one-shot check.
    crate::cli::serve_tasks::abort_join(reload_task).await;

    // Abort the /healthz listener — it never writes WAL so it can be cancelled
    // freely. In-flight connections finish on their own.
    // COR-34: await the abort so the handle isn't dropped mid-run.
    crate::cli::serve_tasks::abort_optional(audit_rpc_task).await;
    // _audit_rpc_guard drops here at fn end → removes the sidecar + token.
    crate::cli::serve_tasks::abort_optional(healthz_task).await;

    // Abort the Hebbian decay task. It runs against the SQLite views db, so
    // aborting mid-pass leaves an open transaction at worst — SQLite rolls
    // it back automatically on connection close.
    crate::cli::serve_tasks::abort_optional(decay_task).await;

    // Abort the sources GC task — same reasoning as decay above.
    crate::cli::serve_tasks::abort_optional(gc_task).await;

    // Round-3 v0.4 G-01 — reflection cron loop. Reads views.db +
    // writes proactive_queue.json; mid-tick abort leaves the queue
    // file untouched (writer is atomic .tmp + rename) so the next
    // boot sees a consistent state.
    crate::cli::serve_tasks::abort_join(reflection_cron_handle).await;

    // Round-3 v0.4 G-01 consumer half — proactive drain loop.
    // Drains queue + appends to JSONL sidecar; the JSONL sidecar
    // is append-only so a mid-tick abort either landed the line
    // (delivered) or didn't (next tick re-picks the item). Worst
    // case: one item is dropped from a tick that aborted mid-flight
    // — operator sees it on next drain cycle.
    crate::cli::serve_tasks::abort_join(proactive_dispatcher_handle).await;

    // Round-3 v0.4 G-02 — surfacing cron loop. Reads idx_profile +
    // writes proactive_queue.json (atomic .tmp + rename). Mid-tick
    // abort leaves the queue file untouched + per-claim dedup_key
    // means the next boot's first tick re-finds the same novel
    // claims + re-enqueues are no-ops.
    crate::cli::serve_tasks::abort_join(g02_surfacing_cron_handle).await;

    // Abort the HO-09b drift-alert cron. Same drain-before-writer-close
    // discipline as the doctor cron: abort + await BEFORE the WAL writer
    // is dropped so an in-flight 0xBA frame isn't lost.
    crate::cli::serve_tasks::abort_optional(drift_alert_cron_handle).await;
    // Abort the ADV-14 regression-anchor cron (same drain-before-close order
    // so an in-flight 0x3F frame isn't lost).
    crate::cli::serve_tasks::abort_optional(regression_cron_handle).await;
    // Abort the MONITOR-03 recall-latency cron (drain before writer close).
    crate::cli::serve_tasks::abort_optional(recall_latency_cron_handle).await;
    crate::cli::serve_tasks::abort_optional(profile_adapt_cron_handle).await;
    // Abort the F4-01 ecology auto-scheduler (drain before writer close).
    crate::cli::serve_tasks::abort_optional(ecology_cron_handle).await;
    crate::cli::serve_tasks::abort_optional(pattern_cron_handle).await;

    // Abort the R-02 Phase 4c dreaming task. Embed-path callers
    // hit `spawn_blocking` for OuroModel/local_qwen forward;
    // aborting cancels the JoinHandle but the blocking task
    // may run to completion (acceptable — drains naturally,
    // never strands the model load).
    crate::cli::serve_tasks::abort_optional(dreaming_task).await;

    // EL-02 arXiv ingest task — abort on shutdown. Mid-pass abort at
    // worst drops one topic's fetch, which the next boot re-runs.
    crate::cli::serve_tasks::abort_optional(arxiv_ingest_task).await;

    // GOLD-ADOPT-26 RSS feed poller — abort BEFORE the WAL writer drains
    // (it emits 0x4E/0x4F). Mid-pass abort drops one feed's fetch, which the
    // next tick re-runs.
    crate::cli::serve_tasks::abort_optional(rss_feed_task).await;

    // Abort the tmux sweeper. Sweeper runs `tmux kill-session` calls;
    // aborting mid-pass at worst leaves one session unkilled, which the
    // next interval picks up — safe to drop.
    crate::cli::serve_tasks::abort_optional(tmux_sweeper_task).await;

    // Drain the n8n localhost API. Notify the accept loop first so it
    // breaks cleanly between accepts (in-flight handler tasks finish
    // their existing response), then drop the JoinHandle.
    n8n_api_shutdown.notify_waiters();
    if let Some(task) = n8n_api_task {
        let _ = task.await;
    }

    // Abort the Obsidian auto-sync task. Pure file IO — aborting mid-copy
    // is safe; the next start runs a fresh full sync from `wal_cursor=0`.
    crate::cli::serve_tasks::abort_optional(obsidian_task).await;

    // Same drill for the cloud auto-mirror task. The cloud client
    // upstream gets the final delta on its own schedule once the
    // file lands on disk.
    crate::cli::serve_tasks::abort_optional(cloud_task).await;

    // Tear down the Hysteria subprocess. `Drop` does the cleanup; the
    // explicit drop here just makes the order obvious in shutdown logs.
    if let Some(sup) = hysteria_supervisor {
        info!("stopping Hysteria subprocess");
        drop(sup);
    }

    drop(writer);
    match writer_join.await {
        Ok(()) => info!("WAL writer task drained cleanly"),
        Err(e) => warn!(error = %e, "WAL writer task panicked during drain"),
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
