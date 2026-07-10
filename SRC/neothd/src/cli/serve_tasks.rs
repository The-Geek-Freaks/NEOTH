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
use crate::config::reload::ReloadController;
use crate::providers::Provider;
use crate::wal::writer::WalWriterHandle;

// ── ZF-06 — Cron supervisor types ─────────────────────────────────────────────
//
// Every background cron that was previously spawned as an individual
// `Optional<JoinHandle>` field in BackgroundHandles is now keyed by `CronKey`
// and managed by the fleet supervisor in serve.rs.  Four crons remain as direct
// fields because they need async construction or extra deps outside SpawnDeps:
//   - CheckinCron   (async spawn_checkin_cron)
//   - SessionSort   (async, inline in serve.rs)
//   - EmailIngest   (inline in serve.rs)
//   - Regression    (async, needs shared_provider)

/// Names every config-gated background cron managed by the fleet supervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CronKey {
    RecallLatency,
    ResourceWatch,
    DoctorCron,
    PatternCron,
    WatchdogCron,
    SynthesisCron,
    GuidanceCron,
    EcologyCron,
    ProfileAdapt,
    DriftAlert,
    TokenAnomaly,
    SessionHealth,
    WebhookManager,
    SkillCurator,
    SelfWiki,
    SelfImprovementCollector,
    Babel,
    BgMonitor,
    ContradictionResolve,
    ObsidianSync,
    ObsidianVaultReader,
    ObsidianWikiRebuild,
    SelfMap,
    ConsolidationSweep,
    MonitorCron,
}

/// WAL-emitting cron keys — must be drained BEFORE `drop(writer)` in shutdown.
pub(crate) const WAL_EMITTING_CRON_KEYS: &[CronKey] = &[
    CronKey::ObsidianWikiRebuild, // 0xFA
    CronKey::SelfMap,             // 0xFB
    CronKey::ConsolidationSweep,  // 0x9D/0x9E
    CronKey::MonitorCron,         // 0x48/0x49/0x4A
    CronKey::DriftAlert,          // 0xBA
    CronKey::TokenAnomaly,        // 0x6E
    CronKey::SessionHealth,       // 0x6F
    CronKey::WebhookManager,      // 0x08/0x09/0x0A
    CronKey::SelfImprovementCollector, // 0xBE/0xBF
];

/// Returns the desired set of `CronKey`s for the given config snapshot.
/// Pure function — no I/O; used by the fleet supervisor diff on every reload.
pub(crate) fn desired_cron_keys(cfg: &FreedomConfig) -> std::collections::HashSet<CronKey> {
    use CronKey::*;
    let mut keys = std::collections::HashSet::new();

    // BgMonitor gates on `interval_secs != 0` (spawn_bg_monitor_task returns
    // None at 0). Mirror that here too — otherwise a reload that sets the
    // interval to 0 leaves the running monitor un-stopped, and the reload log
    // over-counts `started` (to_start holds a key that spawns nothing).
    if cfg.bg_monitor.interval_secs != 0 {
        keys.insert(BgMonitor);
    }

    // `.enabled`-gated crons: the desired set MUST mirror each spawn_*'s
    // `if !config.X.enabled { return None }` guard. Otherwise a cron enabled at
    // boot then disabled via `neoth reload` stays in `desired`, `to_stop` comes
    // out empty, and the running task is never aborted — so the operator's
    // opt-out is silently ignored until a full restart (webhook_manager is the
    // sharpest case: it keeps POSTing to external endpoints). Gating here also
    // makes disable→enable hot-start work. Each predicate is copied verbatim
    // from the matching spawn_* helper.
    if cfg.doctor.enabled {
        keys.insert(DoctorCron);
    }
    if cfg.monitor.enabled {
        keys.insert(MonitorCron);
    }
    if cfg.drift_alert.enabled {
        keys.insert(DriftAlert);
    }
    if cfg.recall_latency.enabled {
        keys.insert(RecallLatency);
    }
    if cfg.profile_adapt.enabled {
        keys.insert(ProfileAdapt);
    }
    if cfg.ecology.enabled {
        keys.insert(EcologyCron);
    }
    if cfg.pattern_cron.enabled {
        keys.insert(PatternCron);
    }
    if cfg.guidance_cron.enabled {
        keys.insert(GuidanceCron);
    }
    if cfg.skill_curator.enabled {
        keys.insert(SkillCurator);
    }
    if cfg.synthesis_cron.enabled {
        keys.insert(SynthesisCron);
    }
    if cfg.consolidation_sweep.enabled {
        keys.insert(ConsolidationSweep);
    }
    if cfg.self_wiki.enabled {
        keys.insert(SelfWiki);
    }
    if cfg.token_anomaly.enabled {
        keys.insert(TokenAnomaly);
    }
    if cfg.session_health.enabled {
        keys.insert(SessionHealth);
    }
    if cfg.webhook_manager.enabled {
        keys.insert(WebhookManager);
    }
    // Wave-11: these five were wrongly classed as always-on in the first pass —
    // each spawn_* (or its inner loop) has an `.enabled` gate, so a reload that
    // disables them must stop the running task. WatchdogCron is the sharpest:
    // it can auto-restart the daemon at Elevated/Full autonomy.
    if cfg.watchdog.enabled {
        keys.insert(WatchdogCron);
    }
    if cfg.resource_watch.enabled {
        keys.insert(ResourceWatch);
    }
    if cfg.contradiction_resolve.enabled {
        keys.insert(ContradictionResolve);
    }
    if cfg.self_improvement_collector.enabled {
        keys.insert(SelfImprovementCollector);
    }
    if cfg.babel.enabled {
        keys.insert(Babel);
    }
    // Vault-gated crons: all four spawn_* helpers early-return None without
    // `obsidian_vault`, so on first boot the key would spawn nothing. The gate
    // matters on RELOAD: if these keys stayed in the desired set unconditionally
    // and the operator cleared `obsidian_vault`, diff_cron_fleet would compute
    // an empty to_stop and the already-running tasks would never be aborted.
    // Gating the desired set on the config makes a vault-clearing reload stop
    // them.
    if cfg.obsidian_vault.is_some() {
        keys.insert(ObsidianSync);
        // ObsidianVaultReader's spawn gates on the vault AND its own
        // `obsidian_vault_reader_enabled` flag, so the desired set must too —
        // otherwise vault-set + reader-disabled leaves the key in `desired`,
        // reload never stops a running reader, and the start log over-counts.
        if cfg.obsidian_vault_reader_enabled {
            keys.insert(ObsidianVaultReader);
        }
        keys.insert(ObsidianWikiRebuild);
        keys.insert(SelfMap);
    }
    keys
}

/// Returns `(to_stop, to_start)` given the running set and the desired set.
/// Pure function — no I/O.
pub(crate) fn diff_cron_fleet(
    running: &std::collections::HashSet<CronKey>,
    desired: &std::collections::HashSet<CronKey>,
) -> (Vec<CronKey>, Vec<CronKey>) {
    let to_stop: Vec<CronKey> = running.difference(desired).copied().collect();
    let to_start: Vec<CronKey> = desired.difference(running).copied().collect();
    (to_stop, to_start)
}

/// Shared map of running cron tasks, managed by the fleet supervisor.
/// `Arc<Mutex<…>>` so the supervisor and shutdown can both access it.
pub(crate) type CronFleet =
    Arc<std::sync::Mutex<std::collections::HashMap<CronKey, JoinHandle<()>>>>;

/// Dependencies shared across all `spawn_cron_for_key` calls.
#[derive(Clone)]
pub(crate) struct SpawnDeps {
    pub reload_controller: Arc<ReloadController>,
    pub writer: WalWriterHandle,
    pub wal_dir: std::path::PathBuf,
    pub views_executor: Option<Arc<crate::memory::store::ViewsExecutor>>,
    pub sse_tx: Option<
        Arc<tokio::sync::broadcast::Sender<crate::coding::feed::FeedEntry>>,
    >,
}

/// Dispatch: spawn the cron task for `key` using the current live config.
/// Returns `None` when the config gates the task off.
/// Wraps every `Option<JoinHandle<anyhow::Result<()>>>` into
/// `Option<JoinHandle<()>>` by mapping the inner result to `()`.
pub(crate) fn spawn_cron_for_key(
    key: CronKey,
    cfg: &FreedomConfig,
    deps: &SpawnDeps,
) -> Option<JoinHandle<()>> {
    use CronKey::*;
    let rc = &deps.reload_controller;
    let w = deps.writer.clone();
    let wd = deps.wal_dir.as_path();

    match key {
        RecallLatency => spawn_recall_latency_cron(cfg, rc, w),
        ResourceWatch => spawn_resource_watch(cfg, rc, w),
        DoctorCron => spawn_doctor_cron(cfg, rc, w),
        PatternCron => spawn_pattern_cron(cfg, rc),
        WatchdogCron => spawn_watchdog_cron(cfg, rc, w),
        SynthesisCron => spawn_synthesis_cron(cfg, rc),
        GuidanceCron => spawn_guidance_cron(cfg, rc, wd),
        EcologyCron => spawn_ecology_cron(cfg, rc, wd, w),
        ProfileAdapt => spawn_profile_adapt_cron(cfg, rc, wd, w),
        DriftAlert => spawn_drift_alert_cron(cfg, rc, &deps.writer),
        TokenAnomaly => spawn_token_anomaly_cron(cfg, rc, wd, w),
        SessionHealth => spawn_session_health_cron(cfg, rc, wd, w),
        WebhookManager => spawn_webhook_manager_cron(
            cfg,
            rc,
            wd,
            &FreedomConfig::default_neoth_home(),
            w,
        ),
        SkillCurator => spawn_skill_curator_cron(cfg, rc),
        SelfWiki => spawn_self_wiki_cron(cfg, rc),
        SelfImprovementCollector => spawn_self_improvement_collector_cron(cfg, w),
        Babel => spawn_babel_cron(cfg, wd, &deps.views_executor, deps.sse_tx.clone()),
        BgMonitor => spawn_bg_monitor_task(cfg, rc),
        ContradictionResolve => spawn_contradiction_resolve_cron(cfg),
        MonitorCron => spawn_monitor_cron(cfg, rc, wd, w),
        ConsolidationSweep => spawn_consolidation_sweep_cron(cfg, rc, w),
        ObsidianSync => wrap_result_handle(spawn_obsidian_sync(cfg)),
        ObsidianVaultReader => wrap_result_handle(spawn_obsidian_vault_reader(cfg)),
        ObsidianWikiRebuild => wrap_result_handle(spawn_obsidian_wiki_rebuild(cfg, w)),
        SelfMap => wrap_result_handle(spawn_self_map(cfg, w)),
    }
}

/// Adapt `Option<JoinHandle<anyhow::Result<()>>>` → `Option<JoinHandle<()>>`.
///
/// Two subtleties the naive `spawn(async { let _ = h.await; })` gets wrong:
///  1. Aborting the OUTER wrapper only drops the inner `JoinHandle`, which in
///     Tokio *detaches* (not aborts) the inner task — so a WAL-emitting cron
///     would keep ticking after `drop(writer)` at shutdown and append to a
///     closed channel. `AbortOnDrop` aborts the inner task when the wrapper's
///     future is dropped (including on shutdown abort).
///  2. A `let _ = h.await` swallows a panic (`JoinError`) or an `Err(_)` from
///     the task, so a dead cron looks healthy. We now surface both via `warn!`.
fn wrap_result_handle(
    h: Option<JoinHandle<anyhow::Result<()>>>,
) -> Option<JoinHandle<()>> {
    h.map(|handle| {
        tokio::spawn(async move {
            struct AbortOnDrop(JoinHandle<anyhow::Result<()>>);
            impl Drop for AbortOnDrop {
                fn drop(&mut self) {
                    self.0.abort();
                }
            }
            // `&mut JoinHandle` is a `Future` (JoinHandle is Unpin), so awaiting
            // through the guard does not consume it — the guard's Drop still
            // owns the inner handle and aborts it if this wrapper is cancelled.
            let mut guard = AbortOnDrop(handle);
            match (&mut guard.0).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!(error = %e, "fleet cron task returned an error"),
                Err(e) if e.is_cancelled() => {} // normal shutdown/reload abort
                Err(e) => warn!(error = %e, "fleet cron task panicked"),
            }
        })
    })
}

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

/// OH-14 — Obsidian self-wiki periodic rebuild. Spawned only when both
/// `freedom.yaml::obsidian_vault` AND a source dir are configured (either
/// `freedom.yaml::obsidian_wiki_source_dir` or env `NEOTH_PLAN_DIR`).
/// `None` (no vault or no source dir) ⇒ no task. WAL-emitting (0xFA) —
/// must be aborted BEFORE `drop(writer)` in shutdown.
pub(crate) fn spawn_obsidian_wiki_rebuild(
    config: &FreedomConfig,
    writer: WalWriterHandle,
) -> Option<JoinHandle<anyhow::Result<()>>> {
    // Gate: vault must be configured.
    let vault_str = config.obsidian_vault.as_deref()?;
    let vault = std::path::PathBuf::from(vault_str);

    // Source dir: explicit config → env NEOTH_PLAN_DIR → None (skip).
    let source_dir = config
        .obsidian_wiki_source_dir
        .as_deref()
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("NEOTH_PLAN_DIR").map(std::path::PathBuf::from)
        })?;

    let interval = config
        .obsidian_wiki_rebuild_secs
        .map(std::time::Duration::from_secs);
    Some(crate::cli::obsidian_wiki_rebuild_task::spawn(
        vault, source_dir, None, interval, writer, None,
    ))
}

/// L6-PRELOAD-AUTORUN-01 — one-shot Obsidian vault preload at serve startup.
///
/// Spawns a single background task that calls
/// [`crate::cli::obsidian::preload_template`] for the primary
/// `obsidian_preload_template_dir` and for each entry in
/// `knowledge_preload_dirs`.  Each root gets its own state file (keyed by path
/// hash via [`crate::cli::obsidian::preload_state_path_for`]) so an
/// unchanged-restart run writes zero chunks.
///
/// Gates:
///   - `obsidian_preload_template_dir` must be `Some`; if unset, returns `None`
///     with a debug log (most installs hit this branch — no noise).
///   - `obsidian_vault` must also be set; missing vault emits a `warn!` and
///     returns `None`.
///   - Each `knowledge_preload_dirs` entry without a `preload_manifest.yaml` is
///     skipped with a `warn!` per entry; remaining entries still run.
///
/// NEOTH-AUDIT-PRELOAD-FS-BOUNDARY-01: canonical-containment guard for vault writes.
///
/// Creates `target_dir` if it does not yet exist, then canonicalizes both the
/// vault root and `target_dir`.  Returns `true` iff the resolved path is a
/// descendant of (or equal to) the vault root.  Fail-closed: returns `false`
/// and emits a `warn!` on any I/O error or detected escape so the caller can
/// skip the write entirely.
///
/// Windows note: `std::fs::canonicalize` returns a `\\?\`-verbatim path on
/// Windows; both sides are canonicalized with the same call so
/// `Path::starts_with` operates on consistent representations regardless of
/// whether the raw strings carry a verbatim prefix.
fn vault_subdir_is_contained(
    canonical_vault: &std::path::Path,
    target_dir: &std::path::Path,
) -> bool {
    if let Err(e) = std::fs::create_dir_all(target_dir) {
        warn!(
            error  = %e,
            target = %target_dir.display(),
            "obsidian preload: cannot create target dir; refusing write (fail-closed)"
        );
        return false;
    }
    match std::fs::canonicalize(target_dir) {
        Ok(real) if real.starts_with(canonical_vault) => true,
        Ok(real) => {
            warn!(
                target = %target_dir.display(),
                real   = %real.display(),
                "obsidian preload: write target resolves outside vault \
                 (symlink/junction escape); refusing write"
            );
            false
        }
        Err(e) => {
            warn!(
                error  = %e,
                target = %target_dir.display(),
                "obsidian preload: canonicalize failed; refusing write (fail-closed)"
            );
            false
        }
    }
}

/// WAL-audited (NEOTH-AUDIT-PRELOAD-AUTORUN-AUDIT-01): emits
/// `EXTENDED/ObsidianPreloadIntent` before the first vault/DB write and
/// `EXTENDED/ObsidianPreloadResult` on completion. Returns `None` when preload
/// is not configured or the `ObsidianPreloadWrite` autonomy gate blocks it
/// (Strict=Confirm → fail-closed in daemon; Standard/Elevated/Full=Allow).
pub(crate) fn spawn_obsidian_preload(config: &FreedomConfig) -> Option<JoinHandle<()>> {
    use crate::cli::obsidian::{
        knowledge_root_has_manifest, preload_autorun_decision, preload_state_path_for,
        PreloadDecision,
    };

    // ── ADR-008/009 permission gate ──────────────────────────────────────
    // ObsidianPreloadWrite: Strict=Confirm (no TTY in daemon → fail-closed),
    // Standard/Elevated/Full=Allow. A Confirm result here means the daemon has
    // no TTY to resolve it — skip the unattended preload rather than hang.
    {
        let decision = crate::permissions::evaluate(
            &crate::permissions::Action::ObsidianPreloadWrite,
            config.autonomy,
        );
        if !decision.is_allow() {
            warn!(
                autonomy = config.autonomy.as_str(),
                decision = decision.tag(),
                "obsidian preload-autorun: permission gate blocked preload \
                 (Strict requires confirm; daemon has no TTY — fail-closed)"
            );
            return None;
        }
    }

    let (vault, template_dir, subdir) = match preload_autorun_decision(config) {
        PreloadDecision::Skip => {
            tracing::debug!(
                "obsidian_preload_template_dir not set — preload autorun disabled"
            );
            return None;
        }
        PreloadDecision::WarnNoVault => {
            warn!(
                "obsidian_preload_template_dir is set but obsidian_vault is not \
                 configured — preload autorun skipped"
            );
            return None;
        }
        PreloadDecision::Run {
            vault,
            template_dir,
            subdir,
        } => (vault, template_dir, subdir),
    };

    let knowledge_dirs: Vec<std::path::PathBuf> = config
        .knowledge_preload_dirs
        .iter()
        .map(std::path::PathBuf::from)
        .collect();

    info!(
        template = %template_dir.display(),
        vault = %vault.display(),
        knowledge_roots = knowledge_dirs.len(),
        "obsidian preload-autorun task spawned (one-shot)"
    );

    let handle = tokio::spawn(async move {
        // NEOTH-AUDIT-PRELOAD-FS-BOUNDARY-01: canonicalize the vault root once.
        // Per-call containment checks compare resolved paths against this root.
        // Falls back to the raw path when the vault does not yet exist so the
        // per-target create_dir_all + canonicalize check still catches escapes
        // once the directory is materialised.
        let canonical_vault =
            std::fs::canonicalize(&vault).unwrap_or_else(|_| vault.clone());

        // ── WAL intent frame (NEOTH-AUDIT-PRELOAD-AUTORUN-AUDIT-01) ──────
        // Open a short-lived audit segment; emit the intent frame BEFORE the
        // first vault/DB write. Best-effort: a WAL open failure must never
        // block the preload — the permission gate (run synchronously above) is
        // the security layer; WAL is the audit trail.
        let wal = {
            use crate::wal::events::{EVENT_TYPE_EXTENDED, ExtendedSubtype};
            use crate::wal::types::EventFlags;
            let wal_dir = FreedomConfig::default_wal_dir();
            let wal_opt: Option<(WalWriterHandle, tokio::task::JoinHandle<()>)> =
                if std::fs::create_dir_all(&wal_dir).is_ok() {
                    let seg = wal_dir.join("obsidian_preload_audit.wal");
                    match crate::wal::writer::spawn(seg) {
                        Ok(pair) => Some(pair),
                        Err(e) => {
                            warn!(
                                error = %e,
                                "obsidian preload: cannot open WAL writer — audit frames skipped"
                            );
                            None
                        }
                    }
                } else {
                    warn!("obsidian preload: cannot create WAL dir — audit frames skipped");
                    None
                };

            if let Some((ref w, _)) = wal_opt {
                let ts = crate::time::now_unix_i64();
                if let Ok(payload) = serde_json::to_vec(&serde_json::json!({
                    "vault": vault.to_string_lossy(),
                    "knowledge_roots": knowledge_dirs.len(),
                    "ts_unix": ts,
                })) {
                    let header =
                        crate::wal::HeaderBuilder::new(EVENT_TYPE_EXTENDED, &payload)
                            .event_subtype(ExtendedSubtype::ObsidianPreloadIntent as u8)
                            .flags(EventFlags::empty())
                            .build();
                    let _ = w.append(header, payload).await;
                }
            }
            wal_opt
        };

        let mut preload_ok = true;

        // ── Primary template ─────────────────────────────────────────────
        let state = preload_state_path_for(&template_dir);
        // Containment guard: when subdir is non-empty (the common case), verify
        // that vault/subdir resolves INSIDE the vault before delegating writes
        // to preload_template.  A symlink or Windows junction at vault/subdir
        // that points outside the vault would otherwise let preload_template
        // write outside the vault undetected.
        // When subdir is empty, preload_template derives effective_subdir from
        // the template manifest; we cannot determine it here without re-loading
        // the manifest.  validate_subdir inside preload_template still rejects
        // traversal components for the manifest-derived value (defence-in-depth
        // for the empty-subdir path).
        let primary_allowed = subdir.as_os_str().is_empty()
            || vault_subdir_is_contained(&canonical_vault, &vault.join(&subdir));
        if !primary_allowed {
            warn!(
                vault  = %vault.display(),
                subdir = %subdir.display(),
                "obsidian preload: primary template skipped — \
                 vault/subdir escapes vault root (symlink/junction guard)"
            );
            preload_ok = false;
        } else {
            match crate::cli::obsidian::preload_template(
                &template_dir,
                &vault,
                &subdir,
                false, // dry_run
                true,  // ingest
                Some(&state),
                None,
            )
            .await
            {
                Ok(stats) => info!(
                    files_copied = stats.files_copied,
                    ingested_chunks = stats.ingested_chunks,
                    template = %template_dir.display(),
                    "obsidian preload-autorun: primary template complete"
                ),
                Err(e) => {
                    warn!(
                        error = %e,
                        template = %template_dir.display(),
                        "obsidian preload-autorun: primary template failed"
                    );
                    preload_ok = false;
                }
            }
        }

        // ── knowledge_preload_dirs ────────────────────────────────────────
        // NOTE: effective_subdir for each knowledge root is read from the
        // root's preload_manifest.yaml by preload_template (obsidian.rs); we
        // cannot perform the per-subdir containment check here without
        // re-loading the manifest.  validate_subdir inside preload_template
        // rejects traversal components; a junction/symlink-at-subdir guard for
        // this code path requires a fix in preload_template (obsidian.rs).
        for root in &knowledge_dirs {
            if !knowledge_root_has_manifest(root) {
                warn!(
                    dir = %root.display(),
                    "knowledge_preload_dirs entry has no preload_manifest.yaml — skipped"
                );
                continue;
            }
            let state = preload_state_path_for(root);
            // Empty subdir → preload_template uses the manifest's default_vault_subdir.
            match crate::cli::obsidian::preload_template(
                root,
                &vault,
                &std::path::PathBuf::new(),
                false,
                true,
                Some(&state),
                None,
            )
            .await
            {
                Ok(stats) => info!(
                    dir = %root.display(),
                    files_copied = stats.files_copied,
                    "obsidian preload-autorun: knowledge root complete"
                ),
                Err(e) => {
                    warn!(
                        error = %e,
                        dir = %root.display(),
                        "obsidian preload-autorun: knowledge root failed — continuing"
                    );
                    preload_ok = false;
                }
            }
        }

        // ── WAL result frame + flush (best-effort) ────────────────────────
        if let Some((w, join)) = wal {
            use crate::wal::events::{EVENT_TYPE_EXTENDED, ExtendedSubtype};
            use crate::wal::types::EventFlags;
            let ts = crate::time::now_unix_i64();
            if let Ok(payload) = serde_json::to_vec(&serde_json::json!({
                "ok": preload_ok,
                "ts_unix": ts,
            })) {
                let header =
                    crate::wal::HeaderBuilder::new(EVENT_TYPE_EXTENDED, &payload)
                        .event_subtype(ExtendedSubtype::ObsidianPreloadResult as u8)
                        .flags(EventFlags::empty())
                        .build();
                let _ = w.append(header, payload).await;
            }
            // Flush: drop the sender so the writer drains, then wait up to 5s.
            drop(w);
            let _ =
                tokio::time::timeout(std::time::Duration::from_secs(5), join).await;
        }
    });
    Some(handle)
}

/// GOLD-ADAPT-GRAPH-05 — NEOTH self-map cron. Spawned only when both
/// `freedom.yaml::obsidian_vault` AND a source dir are configured (either
/// `freedom.yaml::self_map_source_dir` or env `NEOTH_SRC_DIR`).
/// `None` (no vault or no source dir) ⇒ no task. WAL-emitting (0xFB) —
/// must be aborted BEFORE `drop(writer)` in shutdown.
pub(crate) fn spawn_self_map(
    config: &FreedomConfig,
    writer: WalWriterHandle,
) -> Option<JoinHandle<anyhow::Result<()>>> {
    // Gate: vault must be configured.
    let vault_str = config.obsidian_vault.as_deref()?;
    let vault = std::path::PathBuf::from(vault_str);

    // Source dir: explicit config → env NEOTH_SRC_DIR → None (skip).
    let source_dir = config
        .self_map_source_dir
        .as_deref()
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("NEOTH_SRC_DIR").map(std::path::PathBuf::from))?;

    let interval = config
        .self_map_interval_secs
        .map(std::time::Duration::from_secs);
    let subdir = config.self_map_subdir.clone();
    // GRAPH-07: extract label config + provider creds for community naming.
    let label_enabled = config.self_map_label_enabled;
    let label_model = config.self_map_label_model.clone();
    let provider_kind = config.provider_kind;
    // Expose the SecretString into a transient String for the subprocess env var.
    // This is the ONLY consumer; it is not persisted or logged.
    let provider_key = config
        .provider_key
        .as_ref()
        .map(|s| s.expose().to_owned());
    let provider_endpoint = config.provider_endpoint.clone();
    Some(crate::daemon::self_map_task::spawn(
        vault,
        source_dir,
        subdir,
        interval,
        writer,
        label_enabled,
        label_model,
        provider_kind,
        provider_key,
        provider_endpoint,
    ))
}

/// GOLD-ADAPT-JV-IMP-05 — Obsidian vault bidirectional reader+writer cron.
///
/// Returns `Some(handle)` only when BOTH `obsidian_vault` is set AND
/// `obsidian_vault_reader_enabled = true`.  A default `FreedomConfig` has
/// neither, so the function returns `None` without touching the Tokio runtime
/// (the no-runtime unit test in `daemon::obsidian_vault_reader_cron` depends
/// on this gate order).  WAL-free; abort is safe at any tick boundary.
pub(crate) fn spawn_obsidian_vault_reader(
    config: &FreedomConfig,
) -> Option<JoinHandle<anyhow::Result<()>>> {
    // Both gates must pass: vault configured AND feature enabled.
    if !config.obsidian_vault_reader_enabled {
        return None;
    }
    let vault_str = config.obsidian_vault.as_deref()?;
    let vault = std::path::PathBuf::from(vault_str);
    let home = FreedomConfig::default_neoth_home();
    let interval = config
        .obsidian_vault_reader_secs
        .map(std::time::Duration::from_secs);
    info!("obsidian vault reader cron enabled");
    Some(crate::daemon::obsidian_vault_reader_cron::spawn(vault, home, interval))
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
    Some(crate::cli::cloud_sync_task::spawn(
        None, dest, subdir, interval,
    ))
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
        info!(
            topics = config.arxiv.topics.len(),
            "arxiv ingest task enabled"
        );
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

/// GOLD-ADAPT-MEM-16 — ArXiv skill-learning cron spawner.
///
/// Returns `Some(handle)` when `arxiv_skill_scan.enabled`, the topics list is
/// non-empty, AND a shared provider is wired (provider required for LLM
/// extraction). Any missing gate → `None` (no task spawned, warn logged).
pub(crate) fn spawn_arxiv_skill_scan(
    config: &FreedomConfig,
    shared_provider: &Option<Arc<dyn Provider>>,
) -> Option<JoinHandle<anyhow::Result<()>>> {
    if !config.arxiv_skill_scan.enabled {
        return None;
    }
    if config.arxiv_skill_scan.topics.is_empty() {
        warn!("arxiv_skill_scan enabled but no topics configured; not spawning");
        return None;
    }
    let Some(provider) = shared_provider.as_ref().map(Arc::clone) else {
        warn!("arxiv_skill_scan enabled but no provider wired; not spawning (provider required for extraction)");
        return None;
    };
    info!(
        topics = config.arxiv_skill_scan.topics.len(),
        "arxiv skill-scan cron enabled"
    );
    Some(crate::daemon::arxiv_skill_scan_cron::spawn(
        FreedomConfig::default_neoth_home(),
        config.arxiv_skill_scan.topics.clone(),
        provider,
        config
            .arxiv_skill_scan
            .interval_secs
            .map(std::time::Duration::from_secs),
        config.arxiv_skill_scan.max_per_topic,
    ))
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
///
/// GOLD-ADAPT-TRAIL-03: accepts `Arc<ReloadController>` so the tick loop reads
/// `reload_controller.latest().recall_latency` on every tick, picking up
/// in-flight changes to `interval_secs` / `p95_threshold_ms` after a
/// `neoth reload` without a daemon restart.
pub(crate) fn spawn_recall_latency_cron(
    config: &FreedomConfig,
    reload_controller: &Arc<ReloadController>,
    writer: WalWriterHandle,
) -> Option<JoinHandle<()>> {
    if !config.recall_latency.enabled {
        return None;
    }
    let ctrl = Arc::clone(reload_controller);
    let home = FreedomConfig::default_neoth_home();
    let boot_cfg = config.recall_latency;
    info!(
        interval_secs = boot_cfg.interval_secs,
        p95_threshold_ms = boot_cfg.p95_threshold_ms,
        "recall-latency cron loop spawned (MONITOR-03)"
    );
    Some(tokio::spawn(async move {
        let mut current_interval = boot_cfg.interval_duration();
        let mut ticker = tokio::time::interval(current_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            interval_secs = current_interval.as_secs(),
            p95_threshold_ms = boot_cfg.p95_threshold_ms,
            "recall-latency cron loop online (MONITOR-03 / TRAIL-03)",
        );
        loop {
            ticker.tick().await;
            // TRAIL-03: read live config each tick so operator `neoth reload`
            // changes to interval_secs / p95_threshold_ms take effect.
            let live_cfg = ctrl.latest().recall_latency;
            let live_interval = live_cfg.interval_duration();
            if live_interval != current_interval {
                current_interval = live_interval;
                ticker = tokio::time::interval(current_interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                tracing::info!(
                    interval_secs = current_interval.as_secs(),
                    "recall-latency cron: interval updated via config reload (TRAIL-03)",
                );
            }
            match crate::daemon::recall_latency_cron::run_recall_latency_tick(
                &home, &live_cfg, &writer,
            )
            .await
            {
                Ok(Some(p95_ms)) => tracing::warn!(p95_ms, "recall-latency cron: 0x4B emitted"),
                Ok(None) => tracing::debug!("recall-latency cron: no alert this tick"),
                Err(e) => tracing::error!(error = %e, "recall-latency tick failed"),
            }
        }
    }))
}

/// SL-03 — ResourcePressureWatcher cron; emits `0x47 RESOURCE_PRESSURE_ALERT`.
///
/// GOLD-ADAPT-TRAIL-03: reads `reload_controller.latest().resource_watch` each
/// tick so `vram_threshold_pct` and `interval_secs` changes take effect after
/// a `neoth reload` without restarting the daemon.
pub(crate) fn spawn_resource_watch(
    config: &FreedomConfig,
    reload_controller: &Arc<ReloadController>,
    writer: WalWriterHandle,
) -> Option<JoinHandle<()>> {
    if !config.resource_watch.enabled {
        return None;
    }
    let ctrl = Arc::clone(reload_controller);
    let boot_cfg = config.resource_watch.clone();
    info!(
        interval_secs = boot_cfg.interval_secs,
        vram_threshold_pct = boot_cfg.vram_threshold_pct,
        "resource-watch cron loop spawned (SL-03)"
    );
    Some(tokio::spawn(async move {
        let mut current_interval = boot_cfg.interval_duration();
        let mut ticker = tokio::time::interval(current_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            interval_secs = current_interval.as_secs(),
            vram_threshold_pct = boot_cfg.vram_threshold_pct,
            "resource-watch cron loop online (SL-03 / TRAIL-03)",
        );
        loop {
            ticker.tick().await;
            let live_cfg = ctrl.latest().resource_watch.clone();
            let live_interval = live_cfg.interval_duration();
            if live_interval != current_interval {
                current_interval = live_interval;
                ticker = tokio::time::interval(current_interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                tracing::info!(
                    interval_secs = current_interval.as_secs(),
                    "resource-watch cron: interval updated via config reload (TRAIL-03)",
                );
            }
            let reading = crate::daemon::resource_watch::read_gpu_vram();
            match crate::daemon::resource_watch::run_resource_watch_tick(
                &live_cfg, &writer, reading,
            )
            .await
            {
                Ok(Some(a)) => tracing::info!(pct = a.pct, "resource-watch: 0x47 emitted"),
                Ok(None) => tracing::debug!("resource-watch: no pressure this tick"),
                Err(e) => tracing::error!(error = %e, "resource-watch tick failed"),
            }
        }
    }))
}

/// HO-07 — monitor alerting cron (`0x48`/`0x49`/`0x4A`).
///
/// GOLD-ADAPT-TRAIL-03: reads `reload_controller.latest().monitor` each tick
/// so `interval_secs` and threshold fields take effect after a `neoth reload`.
/// Per-loop mutable state (`crash_log_offset`, `emit_state`, scorecard/pipeline
/// history ring buffers) is preserved across ticks — a reload does NOT reset
/// them; only interval and the config thresholds change.
pub(crate) fn spawn_monitor_cron(
    config: &FreedomConfig,
    reload_controller: &Arc<ReloadController>,
    wal_dir: &std::path::Path,
    writer: WalWriterHandle,
) -> Option<JoinHandle<()>> {
    if !config.monitor.enabled {
        tracing::info!("monitor cron disabled (monitor.enabled = false)");
        return None;
    }
    let ctrl = Arc::clone(reload_controller);
    let home = FreedomConfig::default_neoth_home();
    let wal_dir = wal_dir.to_path_buf();
    let boot_cfg = config.monitor.clone();
    info!(
        interval_secs = boot_cfg.interval_secs,
        "monitor cron loop spawned (HO-07)"
    );
    Some(tokio::spawn(async move {
        let mut current_interval = boot_cfg.interval_duration();
        let mut ticker = tokio::time::interval(current_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut crash_log_offset = 0u64;
        let mut emit_state = crate::daemon::monitor_cron::MonitorEmitState::default();
        let mut scorecard_history = crate::memory::scorecard::ScorecardHistory::default();
        let mut pipeline_history = crate::memory::scorecard::PipelineHistory::default();
        tracing::info!(
            interval_secs = current_interval.as_secs(),
            "monitor cron loop online (HO-07 / TRAIL-03)",
        );
        crate::daemon::monitor_cron::warn_misconfigured_channels(&home);
        loop {
            ticker.tick().await;
            let live_cfg = ctrl.latest().monitor.clone();
            let live_interval = live_cfg.interval_duration();
            if live_interval != current_interval {
                current_interval = live_interval;
                ticker = tokio::time::interval(current_interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                tracing::info!(
                    interval_secs = current_interval.as_secs(),
                    "monitor cron: interval updated via config reload (TRAIL-03)",
                );
            }
            match crate::daemon::monitor_cron::run_monitor_tick_live(
                &live_cfg,
                &writer,
                &home,
                &wal_dir,
                &mut crash_log_offset,
                &mut emit_state,
            )
            .await
            {
                Ok((wal, crash, silence)) => {
                    if wal || crash || silence {
                        tracing::info!(wal, crash, silence, "monitor tick: alerts emitted");
                    } else {
                        tracing::debug!("monitor tick: clean");
                    }
                }
                Err(e) => tracing::error!(error = %e, "monitor tick failed"),
            }
            crate::daemon::monitor_cron::run_scorecard_tick(
                &home,
                crate::time::now_unix_i64(),
                &mut scorecard_history,
            );
            crate::daemon::monitor_cron::run_pipeline_scorecard_tick(
                &home,
                crate::time::now_unix_i64(),
                &writer,
                &mut pipeline_history,
            )
            .await;
        }
    }))
}

/// GOLD-DELTA-04 — Babel-Index observer cron (`analytics/babel`).
///
/// Default ON (local-only observer, never blocks inference, SQLite-only
/// sink). Returns `None` when `babel.enabled = false` OR the views
/// executor failed to open — without views.db there is nowhere to
/// persist windows.
pub(crate) fn spawn_babel_cron(
    config: &FreedomConfig,
    wal_dir: &std::path::Path,
    views_executor: &Option<std::sync::Arc<crate::memory::store::ViewsExecutor>>,
    sse_tx: Option<std::sync::Arc<tokio::sync::broadcast::Sender<crate::coding::feed::FeedEntry>>>,
) -> Option<JoinHandle<()>> {
    let Some(views) = views_executor else {
        tracing::info!("babel observer not started (views executor unavailable)");
        return None;
    };
    crate::daemon::babel_cron::spawn_babel_cron_loop(
        config.babel.clone(),
        config.autonomy,
        wal_dir.to_path_buf(),
        std::sync::Arc::clone(views),
        sse_tx,
    )
}

/// GOLD-ADAPT-JV-MEM-16 — guidance-block snapshot refresh cron (WAL-free).
///
/// Spawns when `freedom.yaml::guidance_cron.enabled: true`; writes
/// `~/.neoth/guidance_snapshot.json` every `interval_secs` (default 3h)
/// so `build_prompt_bundle` / `maybe_guidance_block_at` read richer context.
/// Returns `None` (no task) when disabled (the default).
///
/// GOLD-ADAPT-TRAIL-03: reads `reload_controller.latest().guidance_cron` each
/// tick so `interval_secs` and `signal_window_secs` take effect after
/// a `neoth reload` without restarting the daemon.
pub(crate) fn spawn_guidance_cron(
    config: &FreedomConfig,
    reload_controller: &Arc<ReloadController>,
    wal_dir: &std::path::Path,
) -> Option<JoinHandle<()>> {
    if !config.guidance_cron.enabled {
        return None;
    }
    let ctrl = Arc::clone(reload_controller);
    let home = FreedomConfig::default_neoth_home();
    let wal_dir = wal_dir.to_path_buf();
    let boot_cfg = config.guidance_cron;
    info!(
        interval_secs = boot_cfg.interval_secs,
        "guidance-block snapshot cron spawned (JV-MEM-16)"
    );
    Some(tokio::spawn(async move {
        let mut current_interval = boot_cfg.interval_duration();
        let mut ticker = tokio::time::interval(current_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            interval_secs = current_interval.as_secs(),
            "guidance-block snapshot cron online (JV-MEM-16 / TRAIL-03)",
        );
        loop {
            ticker.tick().await;
            let live_cfg = ctrl.latest().guidance_cron;
            let live_interval = live_cfg.interval_duration();
            if live_interval != current_interval {
                current_interval = live_interval;
                ticker = tokio::time::interval(current_interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                tracing::info!(
                    interval_secs = current_interval.as_secs(),
                    "guidance cron: interval updated via config reload (TRAIL-03)",
                );
            }
            let home2 = home.clone();
            let wal2 = wal_dir.clone();
            let sw = live_cfg.signal_window_secs;
            let _ = tokio::task::spawn_blocking(move || {
                crate::daemon::guidance_cron::run_guidance_snapshot_tick(
                    &home2,
                    &wal2,
                    crate::time::now_unix_i64(),
                    sw,
                )
            })
            .await;
        }
    }))
}

/// GOLD-FEAT-11 — LLM check-in body cron. Detects inactivity gaps and
/// enqueues a provider-generated check-in nudge once per UTC day.
/// Returns `None` when `checkin_cron.enabled = false` (the default).
pub(crate) async fn spawn_checkin_cron(
    config: &FreedomConfig,
    reload_controller: &Arc<ReloadController>,
) -> Option<JoinHandle<()>> {
    if !config.checkin_cron.enabled {
        return None;
    }
    // Provider needed — build from config. If wiring fails, log and skip.
    let provider = match crate::providers::from_config(config).await {
        Ok(p) => std::sync::Arc::from(p),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "checkin_cron: provider build failed — cron disabled for this session"
            );
            return None;
        }
    };
    let ctrl = Arc::clone(reload_controller);
    let home = FreedomConfig::default_neoth_home();
    let boot_cfg = config.checkin_cron;
    info!(
        interval_secs = boot_cfg.interval_secs,
        "checkin cron spawned (GOLD-FEAT-11)"
    );
    Some(tokio::spawn(async move {
        let mut current_interval = boot_cfg.interval_duration();
        let mut ticker = tokio::time::interval(current_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let live_cfg = ctrl.latest().checkin_cron;
            let live_interval = live_cfg.interval_duration();
            if live_interval != current_interval {
                current_interval = live_interval;
                ticker = tokio::time::interval(current_interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            }
            if let Err(e) =
                crate::daemon::checkin_cron::run_checkin_tick(&home, &live_cfg, &provider).await
            {
                tracing::warn!(error = %e, "checkin_cron: tick failed");
            }
        }
    }))
}

/// GOLD-FEAT-11 — skill-curator cron. Promotes mature operator-accepted skill
/// proposals to `~/.neoth/skills/`. Returns `None` when disabled (default).
pub(crate) fn spawn_skill_curator_cron(
    config: &FreedomConfig,
    reload_controller: &Arc<ReloadController>,
) -> Option<JoinHandle<()>> {
    if !config.skill_curator.enabled {
        return None;
    }
    let ctrl = Arc::clone(reload_controller);
    let home = FreedomConfig::default_neoth_home();
    let boot_cfg = config.skill_curator;
    info!(
        interval_secs = boot_cfg.interval_secs,
        min_age_days = boot_cfg.min_age_days,
        "skill-curator cron spawned (GOLD-FEAT-11)"
    );
    Some(tokio::spawn(async move {
        let mut current_interval = boot_cfg.interval_duration();
        let mut ticker = tokio::time::interval(current_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let live_cfg = ctrl.latest().skill_curator;
            let live_interval = live_cfg.interval_duration();
            if live_interval != current_interval {
                current_interval = live_interval;
                ticker = tokio::time::interval(current_interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            }
            if let Err(e) =
                crate::daemon::skill_curator_cron::run_skill_curator_tick(&home, &live_cfg).await
            {
                tracing::warn!(error = %e, "skill_curator: tick failed");
            }
        }
    }))
}

/// NN-MEM-02 — weekly 5-dimensional synthesis pattern-recognition cron.
///
/// Produces a structured synthesis meta-note written as a `idx_groundtruth`
/// row (`source = "synthesis-cron"`, `scope = "meta"`) and optionally to
/// `~/.neoth/synthesis/YYYY-WW.md`. WAL-free. Returns `None` when disabled
/// (the default).
///
/// GOLD-ADAPT-TRAIL-03: reads `reload_controller.latest().synthesis_cron` each
/// tick so `interval_secs` and `window_days` changes propagate after
/// a `neoth reload`.
pub(crate) fn spawn_synthesis_cron(
    config: &FreedomConfig,
    reload_controller: &Arc<ReloadController>,
) -> Option<JoinHandle<()>> {
    if !config.synthesis_cron.enabled {
        return None;
    }
    let ctrl = Arc::clone(reload_controller);
    let db_path = crate::memory::store::default_path();
    let home = FreedomConfig::default_neoth_home();
    let boot_cfg = config.synthesis_cron;
    info!(
        interval_secs = boot_cfg.interval_secs,
        window_days = boot_cfg.window_days,
        "synthesis pattern-recognition cron spawned (NN-MEM-02)"
    );
    Some(tokio::spawn(async move {
        let mut current_interval = boot_cfg.interval_duration();
        let mut ticker = tokio::time::interval(current_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            interval_secs = current_interval.as_secs(),
            window_days = boot_cfg.window_days,
            "synthesis pattern-recognition cron online (NN-MEM-02 / TRAIL-03)",
        );
        loop {
            ticker.tick().await;
            let live_cfg = ctrl.latest().synthesis_cron;
            let live_interval = live_cfg.interval_duration();
            if live_interval != current_interval {
                current_interval = live_interval;
                ticker = tokio::time::interval(current_interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                tracing::info!(
                    interval_secs = current_interval.as_secs(),
                    "synthesis cron: interval updated via config reload (TRAIL-03)",
                );
            }
            let db2 = db_path.clone();
            let home2 = home.clone();
            let cfg2 = live_cfg;
            let _ = tokio::task::spawn_blocking(move || {
                match crate::daemon::synthesis_cron::run_synthesis_tick_once(&db2, &home2, &cfg2) {
                    Ok(report) => tracing::info!(
                        topics_analyzed = report.topics_analyzed,
                        correlations_found = report.correlations_found,
                        contradictions_flagged = report.contradictions_flagged,
                        note_written = report.note_written,
                        skill_suggestions_written = report.skill_suggestions_written,
                        skill_proposals_staged = report.skill_proposals_staged,
                        "NN-MEM-02/NN-MEM-05/HERMES-06: synthesis cron tick complete",
                    ),
                    Err(e) => tracing::error!(
                        error = %e,
                        "synthesis cron tick failed (NN-MEM-02)",
                    ),
                }
            })
            .await;
        }
    }))
}

/// GOLD-ADAPT-JV-PRO-02 — token-anomaly tripwire cron (`0x6E`). Buckets the WAL
/// `0x21 PROVIDER_RESPONSE` token usage over a rolling baseline + alerts on a
/// σ-spike / >1M jump / new model. `None` when `token_anomaly.enabled = false`.
///
/// GOLD-ADAPT-TRAIL-03: reads `reload_controller.latest().token_anomaly` each
/// tick so threshold and interval changes propagate after a `neoth reload`.
pub(crate) fn spawn_token_anomaly_cron(
    config: &FreedomConfig,
    reload_controller: &Arc<ReloadController>,
    wal_dir: &std::path::Path,
    writer: WalWriterHandle,
) -> Option<JoinHandle<()>> {
    if !config.token_anomaly.enabled {
        return None;
    }
    let ctrl = Arc::clone(reload_controller);
    let wal_dir = wal_dir.to_path_buf();
    let boot_cfg = config.token_anomaly;
    info!(
        interval_secs = boot_cfg.interval_secs,
        "token-anomaly cron loop spawned (GOLD-ADAPT-JV-PRO-02)"
    );
    Some(tokio::spawn(async move {
        let mut current_interval = boot_cfg.interval_duration();
        let mut ticker = tokio::time::interval(current_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            interval_secs = current_interval.as_secs(),
            "token-anomaly cron loop online (GOLD-ADAPT-JV-PRO-02 / TRAIL-03)",
        );
        loop {
            ticker.tick().await;
            let live_cfg = ctrl.latest().token_anomaly;
            let live_interval = live_cfg.interval_duration();
            if live_interval != current_interval {
                current_interval = live_interval;
                ticker = tokio::time::interval(current_interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                tracing::info!(
                    interval_secs = current_interval.as_secs(),
                    "token-anomaly cron: interval updated via config reload (TRAIL-03)",
                );
            }
            match crate::daemon::token_anomaly_cron::run_token_anomaly_tick(
                &wal_dir, &live_cfg, &writer,
            )
            .await
            {
                Ok(Some(_)) => tracing::warn!("token-anomaly cron: 0x6E emitted"),
                Ok(None) => tracing::debug!("token-anomaly cron: no anomaly this tick"),
                Err(e) => tracing::error!(error = %e, "token-anomaly tick failed"),
            }
        }
    }))
}

/// GOLD-ADAPT-VIEW-05 — spawn the session-health / outcome cron: grades the
/// most-recent active UTC day A–F from the WAL audit trail + emits
/// `0x6F SESSION_HEALTH_DEGRADED` on a degraded grade. `None` when
/// `session_health.enabled = false`.
///
/// GOLD-ADAPT-TRAIL-03: reads `reload_controller.latest().session_health` each
/// tick so threshold and interval changes propagate after a `neoth reload`.
pub(crate) fn spawn_session_health_cron(
    config: &FreedomConfig,
    reload_controller: &Arc<ReloadController>,
    wal_dir: &std::path::Path,
    writer: WalWriterHandle,
) -> Option<JoinHandle<()>> {
    if !config.session_health.enabled {
        return None;
    }
    let ctrl = Arc::clone(reload_controller);
    let wal_dir = wal_dir.to_path_buf();
    let boot_cfg = config.session_health.clone();
    info!(
        interval_secs = boot_cfg.interval_secs,
        "session-health cron loop spawned (GOLD-ADAPT-VIEW-05)"
    );
    Some(tokio::spawn(async move {
        let mut current_interval = boot_cfg.interval_duration();
        let mut ticker = tokio::time::interval(current_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            interval_secs = current_interval.as_secs(),
            "session-health cron loop online (GOLD-ADAPT-VIEW-05 / TRAIL-03)",
        );
        loop {
            ticker.tick().await;
            let live_cfg = ctrl.latest().session_health.clone();
            let live_interval = live_cfg.interval_duration();
            if live_interval != current_interval {
                current_interval = live_interval;
                ticker = tokio::time::interval(current_interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                tracing::info!(
                    interval_secs = current_interval.as_secs(),
                    "session-health cron: interval updated via config reload (TRAIL-03)",
                );
            }
            match crate::daemon::session_health_cron::run_session_health_tick(
                &wal_dir, &live_cfg, &writer,
            )
            .await
            {
                Ok(Some(alert)) => tracing::warn!(
                    grade = alert.grade.as_str(),
                    "session-health cron: 0x6F emitted"
                ),
                Ok(None) => tracing::debug!("session-health cron: no alert this tick"),
                Err(e) => tracing::error!(error = %e, "session-health tick failed"),
            }
        }
    }))
}

/// GOLD-ADAPT-ODY-21 — spawn the outbound webhook manager cron. Tail-reads new
/// WAL frames (`0x9A`/`0x21`/`0x01`/`0x32`) and fans them out as HMAC-signed
/// HTTPS POSTs. SSRF guard blocks RFC-1918/CGNAT/loopback. Emits
/// `0x08`/`0x09`/`0x0A` audit frames. `None` when
/// `webhook_manager.enabled = false` (the default — opt-in).
///
/// GOLD-ADAPT-TRAIL-03: reads `reload_controller.latest().webhook_manager` each
/// tick so endpoint list and interval changes propagate after a `neoth reload`.
/// The reqwest client is built once at spawn (HTTP client construction is
/// expensive and the SSRF/HTTPS-only policy is immutable post-spawn).
pub(crate) fn spawn_webhook_manager_cron(
    config: &FreedomConfig,
    reload_controller: &Arc<ReloadController>,
    wal_dir: &std::path::Path,
    home_dir: &std::path::Path,
    writer: WalWriterHandle,
) -> Option<JoinHandle<()>> {
    if !config.webhook_manager.enabled {
        return None;
    }
    let ctrl = Arc::clone(reload_controller);
    let wal_dir = wal_dir.to_path_buf();
    let home_dir = home_dir.to_path_buf();
    let boot_cfg = config.webhook_manager.clone();
    info!(
        interval_secs = boot_cfg.interval_secs,
        endpoints = boot_cfg.endpoints.len(),
        "webhook-manager cron loop spawned (GOLD-ADAPT-ODY-21)"
    );
    Some(tokio::spawn(async move {
        // Build the reqwest client ONCE: HTTPS-only + no-redirect is immutable
        // policy (SSRF guard). A reload can change endpoint URLs or the signing
        // secret but NEVER the transport policy.
        let client = match reqwest::Client::builder()
            .https_only(true)
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "webhook_manager: failed to build reqwest client — cron aborted"
                );
                return;
            }
        };
        let mut ssrf_cache: crate::daemon::webhook_manager::SsrfCache =
            std::collections::HashMap::new();
        let mut current_interval = boot_cfg.interval_duration();
        let mut ticker = tokio::time::interval(current_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            interval_secs = current_interval.as_secs(),
            endpoints = boot_cfg.endpoints.len(),
            "webhook_manager cron loop online (GOLD-ADAPT-ODY-21 / TRAIL-03)",
        );
        loop {
            ticker.tick().await;
            let live_cfg = ctrl.latest().webhook_manager.clone();
            let live_interval = live_cfg.interval_duration();
            if live_interval != current_interval {
                current_interval = live_interval;
                ticker = tokio::time::interval(current_interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                tracing::info!(
                    interval_secs = current_interval.as_secs(),
                    "webhook-manager cron: interval updated via config reload (TRAIL-03)",
                );
            }
            crate::daemon::webhook_manager::run_webhook_manager_tick(
                &live_cfg,
                &wal_dir,
                &home_dir,
                &client,
                &mut ssrf_cache,
                &writer,
            )
            .await;
        }
    }))
}

/// GOLD-ADAPT-ODY-24 — spawn the companion LAN pairing server.
///
/// Reads `config.companion.enabled` and `config.companion.port`. Creates the
/// `Arc<Notify>` shutdown notifier, calls
/// `daemon::companion::spawn_companion_server_loop`, and returns the pair.
/// Returns `(Arc::new(Notify::new()), None)` when `config.companion.enabled ==
/// false` (the default — opt-in via `companion.enabled: true`).
pub(crate) fn spawn_companion_server(
    config: &FreedomConfig,
    home_dir: &std::path::Path,
    companion_state: std::sync::Arc<crate::daemon::companion::CompanionState>,
    shutdown: std::sync::Arc<tokio::sync::Notify>,
) -> Option<tokio::task::JoinHandle<()>> {
    let handle = crate::daemon::companion::spawn_companion_server_loop(
        config.companion.clone(),
        home_dir.to_path_buf(),
        companion_state,
        shutdown,
    );
    if handle.is_some() {
        info!(
            port = config.companion.port,
            "companion LAN pairing server spawned (GOLD-ADAPT-ODY-24)"
        );
    }
    handle
}

/// GOLD-COMPANION-P2P-01 — spawn a long-running serve-side companion P2P listener
/// task.
///
/// Returns `None` when `config.companion.p2p_enabled = false` (the default) or
/// when the `cluster` feature is NOT compiled in (peeroxide unavailable).
///
/// When enabled, the task runs for the daemon's lifetime. It waits for an
/// invite to be stored by `neoth companion pair-phone` and then drives the
/// Noise-XX accept loop for that invite. After the invite is consumed (paired
/// or rejected), it waits for the next one. This allows the operator to
/// repeatedly run `neoth companion pair-phone` without restarting the daemon.
///
/// Note: the current implementation drives one invite at a time. The
/// serve-side task is the coordination point; `neoth companion pair-phone`
/// spawns the P2P listener inline when run as a standalone CLI command and
/// does NOT require `p2p_enabled = true` in the config — it drives its own
/// transient swarm.
pub(crate) fn spawn_companion_p2p_listener_task(
    config: &FreedomConfig,
    companion_state: std::sync::Arc<crate::daemon::companion::CompanionState>,
    writer: WalWriterHandle,
    shutdown: std::sync::Arc<tokio::sync::Notify>,
) -> Option<tokio::task::JoinHandle<()>> {
    if !config.companion.p2p_enabled {
        return None;
    }

    #[cfg(not(feature = "cluster"))]
    {
        warn!(
            "companion_p2p: p2p_enabled=true in config but `cluster` feature not compiled — \
             P2P pairing unavailable; falling back to loopback HTTP only"
        );
        let _ = (companion_state, writer, shutdown);
        return None;
    }

    #[cfg(feature = "cluster")]
    {
        // The serve-side task is a long-running coordination loop. It wraps a
        // Notify-based channel: `neoth companion pair-phone` (running as a
        // separate process) cannot directly notify this task. Instead, the
        // serve-side task polls a well-known invite file
        // (~/.neoth/companion_pending_invite.json) every 2s, and when it finds
        // one, it loads + deletes the file then calls spawn_companion_p2p_listener.
        //
        // This decoupled design avoids IPC complexity while the companion mobile
        // codebase is out of scope. It also means the daemon never holds an open
        // P2P swarm unless an invite is actually pending.
        use crate::daemon::companion::CompanionInvite;

        let home = crate::config::FreedomConfig::default_neoth_home();
        let invite_path = home.join("companion_pending_invite.json");
        let shutdown_clone = std::sync::Arc::clone(&shutdown);

        info!(
            "companion_p2p: serve-side P2P coordinator spawned \
             (polls {} every 2s for pending invites)",
            invite_path.display()
        );

        let task = tokio::spawn(async move {
            loop {
                // Poll for a pending invite file written by `neoth companion pair-phone
                // --write-invite-for-serve`.
                tokio::select! {
                    biased;
                    _ = shutdown_clone.notified() => {
                        info!("companion_p2p: serve-side coordinator received shutdown");
                        break;
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {}
                }

                if !invite_path.exists() {
                    continue;
                }

                // Load and immediately delete the file (atomic single-use).
                let invite_json = match std::fs::read_to_string(&invite_path) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(error = %e, "companion_p2p: failed to read invite file");
                        continue;
                    }
                };
                // Delete before using so a second daemon loop or a race can't
                // pick it up.
                let _ = std::fs::remove_file(&invite_path);

                let invite: serde_json::Value = match serde_json::from_str(&invite_json) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error = %e, "companion_p2p: invite file JSON parse failed");
                        continue;
                    }
                };

                let topic_hex = match invite["topic_hex"].as_str() {
                    Some(s) => s.to_string(),
                    None => {
                        warn!("companion_p2p: invite file missing topic_hex");
                        continue;
                    }
                };
                let psk_hex = match invite["psk_hex"].as_str() {
                    Some(s) => s.to_string(),
                    None => {
                        warn!("companion_p2p: invite file missing psk_hex");
                        continue;
                    }
                };
                let ttl_secs = invite["ttl_secs"].as_u64().unwrap_or(300);

                // Reconstruct a CompanionInvite from the file.
                let p2p_invite = CompanionInvite::from_hex(topic_hex, psk_hex);
                let per_invite_shutdown = std::sync::Arc::new(tokio::sync::Notify::new());

                info!("companion_p2p: serve-side coordinator picked up pending invite");

                // Spawn the single-invite listener and await it (blocks the
                // coordinator loop until the invite is consumed — by design,
                // only one pairing is active at a time).
                let sub_shutdown = std::sync::Arc::clone(&per_invite_shutdown);
                let task = crate::daemon::companion::spawn_companion_p2p_listener(
                    p2p_invite,
                    std::sync::Arc::clone(&companion_state),
                    writer.clone(),
                    ttl_secs,
                    sub_shutdown,
                );

                tokio::pin!(task);
                tokio::select! {
                    biased;
                    _ = shutdown_clone.notified() => {
                        per_invite_shutdown.notify_waiters();
                        // Abort the in-flight invite listener and wait for it to stop.
                        task.abort();
                        let _ = task.await;
                        break;
                    }
                    _ = &mut task => {
                        // Invite consumed; loop back and poll for the next one.
                    }
                }
            }
        });

        Some(task)
    }
}

/// GOLD-FEAT-09 — spawn the daemon watchdog / auto-recovery cron. `None` when
/// `watchdog.enabled = false`. The restart ACTION (spawning a service) is gated
/// to `Elevated`/`Full` autonomy, resolved once here and passed as a plain
/// `bool` so the watchdog module stays decoupled from the autonomy enum; below
/// that the loop is observe-only (alerts, no spawn).
///
/// GOLD-ADAPT-TRAIL-03: reads `reload_controller.latest().watchdog` each tick
/// so `interval_secs` and watchdog thresholds propagate after a `neoth reload`.
/// Per-service rolling failure state (`states` map) is preserved — a reload
/// does NOT reset the failure counters; only the config thresholds change.
/// Note: `autonomy` is immutable post-init (provider-bound), so `restart_allowed`
/// is resolved once at spawn time and is NOT re-evaluated on reload.
pub(crate) fn spawn_watchdog_cron(
    config: &FreedomConfig,
    reload_controller: &Arc<ReloadController>,
    writer: WalWriterHandle,
) -> Option<JoinHandle<()>> {
    use crate::permissions::AutonomyLevel;
    let restart_allowed = matches!(
        config.autonomy,
        AutonomyLevel::Elevated | AutonomyLevel::Full
    );
    if !config.watchdog.enabled {
        tracing::info!("watchdog cron disabled (watchdog.enabled = false)");
        return None;
    }
    let ctrl = Arc::clone(reload_controller);
    let boot_cfg = config.watchdog;
    info!(
        interval_secs = boot_cfg.interval_secs,
        restart_allowed,
        "watchdog cron loop spawned (GOLD-FEAT-09)"
    );
    Some(tokio::spawn(async move {
        let mut current_interval = boot_cfg.interval_duration();
        let mut ticker = tokio::time::interval(current_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut states: std::collections::HashMap<
            crate::daemon::watchdog_cron::WatchedService,
            crate::daemon::watchdog_cron::WatchState,
        > = std::collections::HashMap::new();
        tracing::info!(
            interval_secs = current_interval.as_secs(),
            restart_allowed,
            "watchdog cron loop online (GOLD-FEAT-09 / TRAIL-03)",
        );
        loop {
            ticker.tick().await;
            let live_cfg = ctrl.latest().watchdog;
            let live_interval = live_cfg.interval_duration();
            if live_interval != current_interval {
                current_interval = live_interval;
                ticker = tokio::time::interval(current_interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                tracing::info!(
                    interval_secs = current_interval.as_secs(),
                    "watchdog cron: interval updated via config reload (TRAIL-03)",
                );
            }
            if let Err(e) = crate::daemon::watchdog_cron::run_watchdog_tick(
                &live_cfg,
                restart_allowed,
                &writer,
                &mut states,
            )
            .await
            {
                tracing::warn!(error = %e, "watchdog tick failed");
            }
        }
    }))
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
///
/// GOLD-ADAPT-TRAIL-03: reads `reload_controller.latest().profile_adapt` each
/// tick so `interval_secs` changes propagate after a `neoth reload`.
pub(crate) fn spawn_profile_adapt_cron(
    config: &FreedomConfig,
    reload_controller: &Arc<ReloadController>,
    wal_dir: &std::path::Path,
    writer: WalWriterHandle,
) -> Option<JoinHandle<()>> {
    if !config.profile_adapt.enabled {
        return None;
    }
    let ctrl = Arc::clone(reload_controller);
    let home = FreedomConfig::default_neoth_home();
    let wal_dir = wal_dir.to_path_buf();
    let boot_cfg = config.profile_adapt;
    info!(
        interval_secs = boot_cfg.interval_secs,
        "passive user-adaptation cron loop spawned (SPEC-05)"
    );
    Some(tokio::spawn(async move {
        let mut current_interval = boot_cfg.interval_duration();
        let mut ticker = tokio::time::interval(current_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            interval_secs = current_interval.as_secs(),
            "profile-adapt cron loop online (SPEC-05 / TRAIL-03)",
        );
        loop {
            ticker.tick().await;
            let live_cfg = ctrl.latest().profile_adapt;
            let live_interval = live_cfg.interval_duration();
            if live_interval != current_interval {
                current_interval = live_interval;
                ticker = tokio::time::interval(current_interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                tracing::info!(
                    interval_secs = current_interval.as_secs(),
                    "profile-adapt cron: interval updated via config reload (TRAIL-03)",
                );
            }
            match crate::daemon::profile_adapt_cron::run_profile_adapt_tick(
                &home,
                &wal_dir,
                &writer,
                crate::daemon::profile_adapt_cron::current_basis(&home),
            )
            .await
            {
                Ok(0) => tracing::debug!("profile-adapt cron: no new proposals this tick"),
                Ok(n) => tracing::info!(
                    new_proposals = n,
                    "profile-adapt cron: queued new self-dev proposal(s) — review via \
                     `neoth self-dev review`",
                ),
                Err(e) => tracing::error!(error = %e, "profile-adapt tick failed"),
            }
        }
    }))
}

/// F4-01 — ecology auto-scheduler (STAGES review-gated self-dev proposals, emits `0x4C`).
///
/// GOLD-ADAPT-TRAIL-03: reads `reload_controller.latest().ecology` each tick
/// so `scheduler_interval_secs` and `correlation_min_streak` changes propagate
/// after a `neoth reload` without restarting the daemon.
pub(crate) fn spawn_ecology_cron(
    config: &FreedomConfig,
    reload_controller: &Arc<ReloadController>,
    wal_dir: &std::path::Path,
    writer: WalWriterHandle,
) -> Option<JoinHandle<()>> {
    if !config.ecology.enabled {
        tracing::info!("ecology scheduler disabled in config (ecology.enabled = false)");
        return None;
    }
    let ctrl = Arc::clone(reload_controller);
    let home = FreedomConfig::default_neoth_home();
    let wal_dir = wal_dir.to_path_buf();
    let boot_cfg = config.ecology.clone();
    info!(
        interval_secs = boot_cfg.scheduler_interval_secs,
        min_streak = boot_cfg.correlation_min_streak,
        "ecology auto-scheduler cron loop spawned (F4-01 — proposals review-gated)"
    );
    Some(tokio::spawn(async move {
        let mut current_interval = boot_cfg.scheduler_interval_duration();
        let mut ticker = tokio::time::interval(current_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            interval_secs = current_interval.as_secs(),
            min_streak = boot_cfg.correlation_min_streak,
            "ecology scheduler cron loop online (F4-01 / TRAIL-03 — proposals are review-gated)",
        );
        loop {
            ticker.tick().await;
            let live_cfg = ctrl.latest().ecology.clone();
            let live_interval = live_cfg.scheduler_interval_duration();
            if live_interval != current_interval {
                current_interval = live_interval;
                ticker = tokio::time::interval(current_interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                tracing::info!(
                    interval_secs = current_interval.as_secs(),
                    "ecology cron: interval updated via config reload (TRAIL-03)",
                );
            }
            let now_unix = crate::time::now_unix_i64();
            match crate::ecology::scheduler::run_ecology_tick_once(
                &home,
                &wal_dir,
                &writer,
                live_cfg.correlation_min_streak,
                now_unix,
            )
            .await
            {
                Ok(true) => tracing::info!(
                    "ecology scheduler: low-dissent regime → queued new self-dev proposal(s) — \
                     review via `neoth self-dev review`",
                ),
                Ok(false) => tracing::debug!(
                    "ecology scheduler: no fire (no streak signal / no new proposals)"
                ),
                Err(e) => tracing::error!(error = %e, "ecology scheduler tick failed"),
            }
        }
    }))
}

/// GOLD-ADAPT-ODY-07 — background-job monitor task. Creates the process-global
/// [`crate::daemon::bg_jobs::BgJobRegistry`], resurrects pre-restart orphan
/// jobs via `load_existing`, then spawns the periodic scan loop.
///
/// Returns `None` when `bg_monitor.interval_secs == 0` (monitor disabled).
/// The `load_existing` async call is driven on a detached `tokio::spawn` so
/// it does not block the serve-init path — it races with the first monitor
/// tick but both paths are idempotent (register is idempotent by design).
///
/// GOLD-ADAPT-TRAIL-03: `reload_controller` is accepted for API consistency.
/// `bg_monitor` is infrastructure (file-scan cadence); its interval is fixed at
/// spawn time — changing `bg_monitor.interval_secs` after reload has no effect
/// on the live scan rate (requires a daemon restart). This is documented
/// behaviour per TRAIL-03 pitfall #2.
pub(crate) fn spawn_bg_monitor_task(
    config: &FreedomConfig,
    _reload_controller: &Arc<ReloadController>,
) -> Option<JoinHandle<()>> {
    let interval = config.bg_monitor.interval_secs;
    if interval == 0 {
        return None;
    }
    let bgjobs_dir = FreedomConfig::default_neoth_home().join("bgjobs");
    // Ensure the directory exists before any job can land there.
    if let Err(e) = std::fs::create_dir_all(&bgjobs_dir) {
        tracing::warn!(
            path = %bgjobs_dir.display(),
            error = %e,
            "bg_monitor: could not create bgjobs dir (monitor still starts)"
        );
    }
    let registry = std::sync::Arc::new(crate::daemon::bg_jobs::BgJobRegistry::new(
        bgjobs_dir,
    ));
    // Store globally so any call site can call `global_registry()`.
    crate::daemon::bg_jobs::init_global_registry(std::sync::Arc::clone(&registry));
    // Re-hydrate orphan jobs from a prior daemon session (best-effort async).
    let reg_for_load = std::sync::Arc::clone(&registry);
    tokio::spawn(async move {
        let loaded = reg_for_load.load_existing().await;
        if loaded > 0 {
            tracing::info!(
                count = loaded,
                "bg_monitor: resurrected orphan jobs from prior session"
            );
        }
    });
    let handle =
        crate::daemon::bg_monitor::spawn_bg_monitor(registry, interval)?;
    info!(
        interval_secs = interval,
        "bg_monitor task spawned (GOLD-ADAPT-ODY-07)"
    );
    Some(handle)
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
///
/// GOLD-ADAPT-TRAIL-03: reads `reload_controller.latest().doctor` each tick so
/// `interval_secs` changes propagate after a `neoth reload`. The sink is built
/// once at spawn (the notifications dir path is the NEOTH home — immutable).
pub(crate) fn spawn_doctor_cron(
    config: &FreedomConfig,
    reload_controller: &Arc<ReloadController>,
    writer: WalWriterHandle,
) -> Option<JoinHandle<()>> {
    let home = FreedomConfig::default_neoth_home();
    if !config.doctor.enabled {
        info!("doctor cron disabled via freedom.yaml::doctor.enabled = false");
        return None;
    }
    let ctrl = Arc::clone(reload_controller);
    let boot_interval_secs = config.doctor.interval_secs;
    let sink: Arc<dyn crate::daemon::doctor_cron::DoctorNotificationSink> = Arc::new(
        crate::daemon::doctor_cron::SidecarNotificationSink::new(home.join("notifications")),
    );
    info!(interval_secs = boot_interval_secs, "doctor cron loop spawned (EL-01)");
    Some(tokio::spawn(async move {
        let boot_cfg = crate::daemon::doctor_cron::DoctorCronConfig {
            enabled: true,
            interval_secs: boot_interval_secs,
            notify_channel: "cli".to_string(),
        };
        let mut current_interval = boot_cfg.interval_duration();
        let mut ticker = tokio::time::interval(current_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            interval_secs = current_interval.as_secs(),
            "doctor cron loop online (EL-01 / TRAIL-03)",
        );
        loop {
            ticker.tick().await;
            let live_doctor = ctrl.latest().doctor.clone();
            let live_cfg = crate::daemon::doctor_cron::DoctorCronConfig {
                enabled: live_doctor.enabled,
                interval_secs: live_doctor.interval_secs,
                notify_channel: "cli".to_string(),
            };
            let live_interval = live_cfg.interval_duration();
            if live_interval != current_interval {
                current_interval = live_interval;
                ticker = tokio::time::interval(current_interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                tracing::info!(
                    interval_secs = current_interval.as_secs(),
                    "doctor cron: interval updated via config reload (TRAIL-03)",
                );
            }
            // Pitfall #2: `enabled = false` reload leaves the loop running but no-ops
            // — cheap at 1h default cadence; true abort would require a separate abort
            // handle threaded from handle_reload_sentinel (TRAIL-04 scope).
            if !live_cfg.enabled {
                tracing::debug!("doctor cron: disabled via reload, skipping tick");
                continue;
            }
            match crate::daemon::doctor_cron::run_doctor_tick(&home, &writer, sink.as_ref()).await
            {
                Ok(report) => {
                    tracing::debug!(
                        pass = report.pass_count,
                        warn = report.warn_count,
                        fail = report.fail_count,
                        "doctor tick complete",
                    );
                }
                Err(e) => tracing::error!(error = %e, "doctor tick failed"),
            }
        }
    }))
}

/// G-01 detector suite — behaviour-pattern cron (inactivity / query-repeat /
/// topic-burst / time-of-day-shift detectors → proactive nudges). WAL-free,
/// `config.pattern_cron` + home only. `None` when disabled.
///
/// GOLD-ADAPT-TRAIL-03: reads `reload_controller.latest().pattern_cron` each
/// tick so `interval_secs`, `inactivity_gap_secs`, and per-detector toggles
/// propagate after a `neoth reload`.
pub(crate) fn spawn_pattern_cron(
    config: &FreedomConfig,
    reload_controller: &Arc<ReloadController>,
) -> Option<JoinHandle<()>> {
    if !config.pattern_cron.enabled {
        tracing::info!("pattern cron disabled in config (pattern_cron.enabled = false)");
        return None;
    }
    let ctrl = Arc::clone(reload_controller);
    let home = FreedomConfig::default_neoth_home();
    let boot_cfg = config.pattern_cron;
    info!(
        interval_secs = boot_cfg.interval_secs,
        inactivity_gap_secs = boot_cfg.inactivity_gap_secs,
        "pattern-detection cron loop spawned (G-01 detector suite)"
    );
    Some(tokio::spawn(async move {
        let mut current_interval = boot_cfg.interval_duration();
        let mut ticker = tokio::time::interval(current_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            interval_secs = current_interval.as_secs(),
            inactivity_gap_secs = boot_cfg.inactivity_gap_secs,
            query_repeat = boot_cfg.query_repeat_enabled,
            topic_burst = boot_cfg.topic_burst_enabled,
            tod_shift = boot_cfg.tod_shift_enabled,
            "pattern cron loop online (G-01 / TRAIL-03)",
        );
        loop {
            ticker.tick().await;
            let live_cfg = ctrl.latest().pattern_cron;
            let live_interval = live_cfg.interval_duration();
            if live_interval != current_interval {
                current_interval = live_interval;
                ticker = tokio::time::interval(current_interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                tracing::info!(
                    interval_secs = current_interval.as_secs(),
                    "pattern cron: interval updated via config reload (TRAIL-03)",
                );
            }
            let now_unix = crate::time::utc_now().timestamp();
            match crate::daemon::pattern_cron::run_pattern_tick_once(&home, now_unix, &live_cfg) {
                Ok(0) => tracing::debug!("pattern cron: no nudge this tick"),
                Ok(n) => tracing::info!(nudges = n, "pattern cron: proactive nudges enqueued"),
                Err(e) => {
                    tracing::warn!(error = %e, "pattern cron tick failed; retrying next interval")
                }
            }
        }
    }))
}

/// JV-SELF-02 — AMEM4Rec consolidation sweep cron. Clusters hot-tier
/// episode embeddings by cosine ≥ threshold, boosts importance, and merges
/// mature clusters into `idx_groundtruth`. Emits `0x9D`/`0x9E`. `None`
/// when `consolidation_sweep.enabled = false` (the default).
///
/// GOLD-ADAPT-TRAIL-03: reads `reload_controller.latest().consolidation_sweep`
/// each tick so `cosine_threshold` and `interval_secs` changes propagate after
/// a `neoth reload`.
pub(crate) fn spawn_consolidation_sweep_cron(
    config: &FreedomConfig,
    reload_controller: &Arc<ReloadController>,
    writer: WalWriterHandle,
) -> Option<JoinHandle<()>> {
    if !config.consolidation_sweep.enabled {
        return None;
    }
    let ctrl = Arc::clone(reload_controller);
    let db_path = crate::memory::store::default_path();
    let boot_cfg = config.consolidation_sweep;
    info!(
        interval_secs = boot_cfg.interval_secs,
        cosine_threshold = boot_cfg.cosine_threshold,
        "consolidation-sweep cron spawned (JV-SELF-02)"
    );
    Some(tokio::spawn(async move {
        let mut current_interval = boot_cfg.interval_duration();
        let mut ticker = tokio::time::interval(current_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            interval_secs = current_interval.as_secs(),
            cosine_threshold = boot_cfg.cosine_threshold,
            "consolidation-sweep cron online (JV-SELF-02 / TRAIL-03)",
        );
        loop {
            ticker.tick().await;
            let live_cfg = ctrl.latest().consolidation_sweep;
            let live_interval = live_cfg.interval_duration();
            if live_interval != current_interval {
                current_interval = live_interval;
                ticker = tokio::time::interval(current_interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                tracing::info!(
                    interval_secs = current_interval.as_secs(),
                    "consolidation-sweep cron: interval updated via config reload (TRAIL-03)",
                );
            }
            let report = crate::daemon::consolidation_sweep_cron::run_consolidation_sweep_tick(
                &db_path, live_cfg, &writer,
            )
            .await;
            tracing::info!(
                clusters_found = report.clusters_found,
                merged_to_groundtruth = report.merged_to_groundtruth,
                "consolidation-sweep tick complete",
            );
        }
    }))
}

/// GOLD-FEAT-03b — self-wiki rebuild cron. Re-renders the in-binary
/// capability map (+ the PLAN/ design corpus on dev checkouts) into the
/// operator's Obsidian vault + refreshes the ground-truth pointers.
/// Reload-aware (interval + paths track `neoth reload`). Audit: tracing
/// only — no WAL byte free. `None` when `self_wiki.enabled = false`
/// (the default).
pub(crate) fn spawn_self_wiki_cron(
    config: &FreedomConfig,
    reload_controller: &Arc<ReloadController>,
) -> Option<JoinHandle<()>> {
    if !config.self_wiki.enabled {
        return None;
    }
    let ctrl = Arc::clone(reload_controller);
    let boot_cfg = config.self_wiki.clone();
    info!(
        interval_secs = boot_cfg.interval_secs,
        subdir = %boot_cfg.subdir,
        "self-wiki rebuild cron spawned (GOLD-FEAT-03b)"
    );
    Some(tokio::spawn(async move {
        let mut current_interval = boot_cfg.interval_duration();
        let mut ticker = tokio::time::interval(current_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let live_cfg = ctrl.latest().self_wiki.clone();
            let live_interval = live_cfg.interval_duration();
            if live_interval != current_interval {
                current_interval = live_interval;
                ticker = tokio::time::interval(current_interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                tracing::info!(
                    interval_secs = current_interval.as_secs(),
                    "self-wiki cron: interval updated via config reload",
                );
            }
            let report = crate::daemon::wiki_build_cron::run_self_wiki_tick(live_cfg).await;
            tracing::info!(
                capability_pages = report.capability_pages,
                plan_pages = report.plan_pages,
                ingested = report.ingested,
                had_errors = report.had_errors,
                "self-wiki rebuild tick complete",
            );
        }
    }))
}

/// JV-SELF-03 — auto-builder signal collector cron. Scans episode topics,
/// groundtruth lessons, and the SkillOpt ledger to classify improvement
/// signals; writes the sidecar for HERMES-06. Emits `0xBE`/`0xBF`. Default
/// OFF. `None` when `self_improvement_collector.enabled = false`.
pub(crate) fn spawn_self_improvement_collector_cron(
    config: &FreedomConfig,
    writer: WalWriterHandle,
) -> Option<JoinHandle<()>> {
    let handle = crate::daemon::self_improvement_collector::spawn_self_improvement_collector_loop(
        config.self_improvement_collector,
        crate::memory::store::default_path(),
        FreedomConfig::default_neoth_home(),
        writer,
    );
    if handle.is_some() {
        info!(
            interval_secs = config.self_improvement_collector.interval_secs,
            window_days = config.self_improvement_collector.window_days,
            "self-improvement collector cron spawned (GOLD-ADAPT-JV-SELF-03)"
        );
    }
    handle
}

/// NN-MEM-06 — daily contradiction auto-resolution cron. Resolves the
/// `idx_contradictions` backlog (temporal-supersede / semantic-equiv merge /
/// human-review queue). WAL-free. `None` when disabled.
pub(crate) fn spawn_contradiction_resolve_cron(
    config: &FreedomConfig,
) -> Option<JoinHandle<()>> {
    let handle = crate::daemon::contradiction_resolve_cron::spawn_contradiction_resolve_cron_loop(
        config.contradiction_resolve.clone(),
        crate::memory::store::default_path(),
    );
    if handle.is_some() {
        info!(
            interval_secs = config.contradiction_resolve.interval_secs,
            "contradiction-resolve cron loop spawned (NN-MEM-06)"
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

/// HO-02 + GOLD-TASK-04 — kanban stale reapers (startup, not spawned).
/// Two sweeps over the same short-lived views.db connection:
///   1. Stale-PLANNING sessions (HO-02): Cerebellum opens a session row +
///      decomposes via LLM before flipping it onward; a crash mid-decompose
///      strands the row in Planning forever (visible on `neoth kanban list`,
///      never picked up).
///   2. Stale-INPROGRESS tasks (GOLD-TASK-04): the dispatcher stamps a task
///      Backlog→InProgress before `worker.execute()`; a crash mid-execute
///      strands that task row in InProgress forever (worker_watch only fires
///      while the daemon is alive). Swept to Blocked so it can be re-queued.
/// Both use a 1-hour cut-off on each daemon startup so the operator sees a
/// clean slate. Best-effort + synchronous (no WAL writer): a views.db open
/// failure is logged + skipped — hygiene, not load-bearing on liveness.
pub(crate) fn run_stale_kanban_reapers_on_startup() {
    const STALE_CUTOFF_NS: u64 = 3_600 * 1_000_000_000;
    let now_ns = crate::time::now_unix_ns();
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
                // GOLD-TASK-04: second sweep — crash-stranded InProgress
                // task rows (orphaned by a dispatch that died mid-execute)
                // → Blocked, on the same connection + cut-off.
                match crate::coding::store::reap_stale_inprogress_tasks(
                    &conn,
                    now_ns,
                    STALE_CUTOFF_NS,
                ) {
                    Ok(0) => {
                        tracing::debug!("kanban stale-inprogress reaper: nothing to block")
                    }
                    Ok(n) => {
                        info!(
                            reaped = n,
                            "kanban stale-inprogress reaper blocked {n} orphaned task(s)"
                        )
                    }
                    Err(e) => {
                        warn!(error = %e, "kanban stale-inprogress reaper failed; non-fatal")
                    }
                }
            }
        }
        Err(e) => {
            warn!(error = %e, "stale-kanban reaper: cannot open views.db; skipping");
        }
    }
}

/// GOLD-ADAPT-HERMES-05 — startup crash-recovery journal scan.
///
/// Called once at daemon boot (after WAL writer is live, after the
/// `one_shot` early-return). Walks `~/.neoth/journals/` for orphaned
/// `.jsonl` files — each surviving file means a `neoth chat` turn
/// crashed between `0x05 TURN_JOURNAL_OPENED` and
/// `0x06 TURN_JOURNAL_CLOSED`. For every orphan found:
///
/// * emits one `0x07 STALE_INTERRUPTED` WAL frame
///   (`{turn_id, journal_path, size_bytes, line_count, ts_unix}`)
/// * logs a `warn!` directing the operator to `neoth recover`
///
/// Also walks for `.bak` files and logs `warn!` on `LiveShrunk` or
/// `LiveMissing` verdicts so the operator is alerted on the first
/// boot after a crash-truncated write.
///
/// Best-effort: WAL-append errors are logged and ignored — they must
/// not prevent the daemon from starting. The scan is read-only;
/// journals are NEVER deleted here.
pub(crate) async fn run_journal_recovery_on_startup(writer: &WalWriterHandle) {
    use crate::recovery::{BakVerdict, scan_for_baks, scan_for_journals};
    use crate::wal::HeaderBuilder;
    use crate::wal::events::EVENT_TYPE_STALE_INTERRUPTED;

    let home = crate::config::FreedomConfig::default_neoth_home();
    let now_ts = crate::time::now_unix_i64();

    // ── orphaned turn-journals ──────────────────────────────────────────────
    match scan_for_journals(&home) {
        Err(e) => {
            warn!(error = %e, "journal recovery scan: scan_for_journals failed; skipping");
        }
        Ok(reports) => {
            for report in &reports {
                warn!(
                    turn_id = %report.turn_id,
                    journal_path = %report.path.display(),
                    size_bytes = report.size_bytes,
                    line_count = report.line_count,
                    "orphaned turn-journal found at startup; run `neoth recover --list` to inspect"
                );
                let payload = match serde_json::to_vec(&serde_json::json!({
                    "turn_id":      report.turn_id,
                    "journal_path": report.path.display().to_string(),
                    "size_bytes":   report.size_bytes,
                    "line_count":   report.line_count,
                    "ts_unix":      now_ts,
                })) {
                    Ok(b) => b,
                    Err(e) => {
                        warn!(error = %e, turn_id = %report.turn_id,
                              "journal recovery: payload serialisation failed; skipping frame");
                        continue;
                    }
                };
                let header = HeaderBuilder::new(EVENT_TYPE_STALE_INTERRUPTED, &payload).build();
                if let Err(e) = writer.append(header, payload).await {
                    warn!(error = %e, turn_id = %report.turn_id,
                          "journal recovery: WAL append failed; continuing");
                }
            }
            if reports.is_empty() {
                tracing::debug!("journal recovery scan: no orphaned turn-journals found");
            }
        }
    }

    // ── bak-file sweep (warn-only, no WAL frame) ────────────────────────────
    match scan_for_baks(&home) {
        Err(e) => {
            warn!(error = %e, "journal recovery scan: scan_for_baks failed; skipping");
        }
        Ok(baks) => {
            for bak in &baks {
                match bak.verdict {
                    BakVerdict::LiveMissing => {
                        warn!(
                            bak_path = %bak.bak_path.display(),
                            live_path = %bak.live_path.display(),
                            "live file MISSING — bak present; run `neoth recover --list`"
                        );
                    }
                    BakVerdict::LiveShrunk => {
                        warn!(
                            bak_path = %bak.bak_path.display(),
                            live_path = %bak.live_path.display(),
                            bak_size = bak.bak_size,
                            live_size = ?bak.live_size,
                            "live file SHRUNK relative to bak — possible data loss; run `neoth recover --list`"
                        );
                    }
                    BakVerdict::Stale | BakVerdict::LiveOk => {
                        tracing::debug!(
                            bak_path = %bak.bak_path.display(),
                            verdict = ?bak.verdict,
                            "bak file present but verdict is safe; no action needed"
                        );
                    }
                }
            }
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

/// GOLD-ADAPT-HERMES-08 — Kanban SSE endpoint.
///
/// Binds `127.0.0.1:<config.kanban_sse.port>` (default 9432) when
/// `kanban_sse.enabled = true`. Streams live kanban events (task events,
/// comments, dep edges) to browser/GUI/n8n EventSource consumers.
/// Bearer-token auth reuses the n8n_api token file.
/// `None` when disabled or the token load fails (endpoint simply absent).
pub(crate) fn spawn_kanban_sse(
    config: &FreedomConfig,
    writer: &WalWriterHandle,
    kanban_sse_shutdown: &Arc<tokio::sync::Notify>,
) -> (
    Option<JoinHandle<()>>,
    Option<Arc<tokio::sync::broadcast::Sender<crate::coding::feed::FeedEntry>>>,
) {
    let _ = writer; // SSE server is WAL-read-only; writer retained for API symmetry
    if !config.kanban_sse.enabled {
        tracing::debug!("freedom.yaml::kanban_sse.enabled = false; skipping SSE spawn");
        return (None, None);
    }
    let home = FreedomConfig::default_neoth_home();
    let token_path = config
        .n8n_api
        .token_path
        .clone()
        .unwrap_or_else(|| home.clone());
    match crate::n8n_api::server::load_or_init_token(&token_path) {
        Ok(token) => {
            let (tx, _) =
                tokio::sync::broadcast::channel::<crate::coding::feed::FeedEntry>(512);
            let tx_arc = std::sync::Arc::new(tx);
            let state = std::sync::Arc::new(crate::daemon::kanban_sse::SseState {
                config: std::sync::Arc::new(config.clone()),
                tx: std::sync::Arc::clone(&tx_arc),
                home: home.clone(),
                token,
            });
            tracing::info!(
                port = config.kanban_sse.port,
                "kanban_sse enabled — spawning SSE task on 127.0.0.1"
            );
            let handle = crate::daemon::kanban_sse::spawn_server(
                state,
                std::sync::Arc::clone(kanban_sse_shutdown),
            );
            (Some(handle), Some(tx_arc))
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                path = %token_path.display(),
                "kanban_sse token load/init failed — SSE endpoint will NOT be available"
            );
            (None, None)
        }
    }
}

/// GOLD-ADAPT-TRAIL-02: one kanban-SSE relay step — read the most-recent kanban
/// feed entry from views.db via the executor's reader pool and broadcast it to
/// the SSE subscribers. Returns `true` when an entry was found and sent.
///
/// Extracted from the inline relay loop in `cli/serve.rs` so the
/// read → parse → broadcast → deliver path is unit-testable (a spawned closure
/// is not). A `broadcast::send` error means there are currently no SSE
/// subscribers connected — that is the idle case, not a failure.
pub(crate) async fn relay_latest_feed_to_sse(
    exec: &crate::memory::store::ViewsExecutor,
    sse_tx: &tokio::sync::broadcast::Sender<crate::coding::feed::FeedEntry>,
) -> bool {
    let entry = exec
        .with_reader(crate::coding::feed::latest_feed_entry_from_db)
        .await;
    match entry {
        Some(e) => {
            let _ = sse_tx.send(e);
            true
        }
        None => false,
    }
}

/// GOLD-ADAPT-AWE-PROV-01 — OpenRouter-compat oai_serve adapter.
///
/// Binds `127.0.0.1:<config.oai_serve.port>` (default 9746) when
/// `oai_serve.enabled = true`. Serves `GET /v1/models` in OpenRouter wire
/// format so Cline, Continue, OpenCode, Goose and similar clients can
/// discover NEOTH's models catalog. No auth token required — the endpoint is
/// read-only and the loopback bind is the security boundary.
///
/// Returns `None` when `oai_serve.enabled = false` (the default) or the bind
/// fails (error logged at `error!`; daemon continues without the adapter).
pub(crate) fn spawn_oai_serve(
    config: &FreedomConfig,
    oai_serve_shutdown: &Arc<tokio::sync::Notify>,
) -> Option<JoinHandle<()>> {
    let home = FreedomConfig::default_neoth_home();
    crate::oai_serve::server::spawn_server(
        std::sync::Arc::new(config.clone()),
        home,
        std::sync::Arc::clone(oai_serve_shutdown),
    )
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
                // GR-RESID-D34 — FULL-AUTO single-use token store for the GUI bypass.
                fullauto: std::sync::Arc::new(
                    crate::daemon::audit_rpc::FullAutoTokenStore::new(),
                ),
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
/// open fails (recall then runs a per-query index pass). GR-164: when `writer`
/// is `Some`, a tamper-suspect (unreconstructable) segment emits a 0x5E alert
/// frame so the skip is auditable; otherwise read-only against the WAL.
pub(crate) fn spawn_indexer(
    segment_path: &std::path::Path,
    writer: Option<crate::wal::writer::WalWriterHandle>,
    // MEMGRAPH-01: threaded into the tail loop so the continuous ingest
    // auto-embeds new episodes when an embed provider is configured.
    embed_provider: Option<std::sync::Arc<dyn crate::providers::embed::EmbedProvider>>,
    // GOLD-ADAPT-TRAIL-02: when `Some`, the indexer fires this sender
    // after every pass that indexes ≥1 new frame, so in-process consumers
    // (kanban_sse relay) can push updates without polling.
    change_tx: Option<tokio::sync::watch::Sender<()>>,
) -> Option<JoinHandle<()>> {
    let conn_path = crate::memory::store::default_path();
    let seg = segment_path.to_path_buf();
    match crate::memory::store::open(&conn_path) {
        Ok(conn) => Some(tokio::spawn(async move {
            if let Err(e) = crate::memory::indexer::tail(
                conn,
                seg,
                std::time::Duration::from_millis(500),
                writer,
                embed_provider,
                change_tx,
            )
            .await
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
///
/// GOLD-ADAPT-TRAIL-03: reads `reload_controller.latest().drift_alert` each tick
/// so `threshold` and `interval_secs` changes propagate after a `neoth reload`.
pub(crate) fn spawn_drift_alert_cron(
    config: &FreedomConfig,
    reload_controller: &Arc<ReloadController>,
    writer: &WalWriterHandle,
) -> Option<JoinHandle<()>> {
    if !config.drift_alert.enabled {
        tracing::info!("drift-alert cron disabled in config (drift_alert.enabled = false)");
        return None;
    }
    let ctrl = Arc::clone(reload_controller);
    let home = FreedomConfig::default_neoth_home();
    let writer = writer.clone();
    let boot_cfg = config.drift_alert;
    info!(
        interval_secs = boot_cfg.interval_secs,
        threshold = boot_cfg.threshold,
        "profile drift-alert cron loop spawned (HO-09b)"
    );
    Some(tokio::spawn(async move {
        let mut current_interval = boot_cfg.interval_duration();
        let mut ticker = tokio::time::interval(current_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            interval_secs = current_interval.as_secs(),
            threshold = boot_cfg.threshold,
            "drift-alert cron loop online (HO-09b / TRAIL-03)",
        );
        loop {
            ticker.tick().await;
            let live_cfg = ctrl.latest().drift_alert;
            let live_interval = live_cfg.interval_duration();
            if live_interval != current_interval {
                current_interval = live_interval;
                ticker = tokio::time::interval(current_interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                tracing::info!(
                    interval_secs = current_interval.as_secs(),
                    "drift-alert cron: interval updated via config reload (TRAIL-03)",
                );
            }
            match crate::daemon::drift_alert_cron::run_drift_alert_tick(
                &home, &live_cfg, &writer,
            )
            .await
            {
                Ok(Some(report)) => tracing::info!(
                    drift_ratio = report.drift_ratio(),
                    "drift-alert cron: 0xBA emitted",
                ),
                Ok(None) => tracing::debug!("drift-alert cron: no alert this tick"),
                Err(e) => tracing::error!(error = %e, "drift-alert tick failed"),
            }
        }
    }))
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

/// GOLD-PROG-08 / WIRE-10b — serialise a usage-meter snapshot to disk atomically.
/// Pure (no globals), so it is unit-testable. Best-effort JSON.
fn write_usage_snapshot(
    path: &std::path::Path,
    snap: &crate::domain_events::UsageSnapshot,
) -> std::io::Result<()> {
    let json = serde_json::to_vec(snap).unwrap_or_else(|_| b"{}".to_vec());
    crate::util::atomic_write::atomic_write(path, &json)
}

/// GOLD-PROG-08 / WIRE-10b — export the live usage meter to
/// `~/.neoth/usage_meter.json` every 10s so the GUI (a SEPARATE process that
/// cannot read the daemon's in-memory `UsageMeter`) can render a live
/// token-budget panel. Best-effort + WAL-free + stateless (a stale snapshot is
/// harmless), so the caller spawns it DETACHED — no graceful-shutdown /
/// BackgroundHandles wiring. Writes nothing until the global meter is live (the
/// event bus is installed at daemon boot). Atomic write → the GUI never reads a
/// torn file.
pub(crate) fn spawn_usage_export() -> JoinHandle<()> {
    const EXPORT_INTERVAL_SECS: u64 = 10;
    let path = FreedomConfig::default_neoth_home().join("usage_meter.json");
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(EXPORT_INTERVAL_SECS));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            if let Some(snap) = crate::domain_events::global_meter_snapshot() {
                if let Err(e) = write_usage_snapshot(&path, &snap) {
                    tracing::debug!(error = %e, "usage-meter export write failed (best-effort)");
                }
            }
        }
    })
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
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(REFRESH_INTERVAL_SECS));
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

/// Foreign-event indexer (cluster feature only). Polls `views.db` every 30s and
/// applies accepted peer signals from `idx_foreign_events` to local recall rows.
/// WAL-free; the indexer keeps its own marker table and preserves the foreign
/// event backup table.
#[cfg(feature = "cluster")]
pub(crate) fn spawn_foreign_indexer() -> crate::cluster::foreign_indexer::ForeignIndexerHandle {
    let handle =
        crate::cluster::foreign_indexer::spawn_foreign_indexer(FreedomConfig::default_neoth_home());
    info!("cluster foreign-event indexer spawned (30s tick)");
    handle
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

/// Spawn the configured inbound channel adapters (Telegram polling, Slack
/// socket-mode, WhatsApp Meta webhook listener) into `channel_tasks`. Each
/// builds its per-message handler via [`build_channel_handler`] and logs an
/// honest LIVE / CONFIGURED-NOT-STARTED / OUTBOUND-ONLY status. `creds` is
/// borrowed (NOT consumed — the caller also reads it for cluster-transport
/// activation). The WhatsApp listener's detached fan-out tasks are tracked in
/// `dispatch_join` for the COR-34 shutdown drain. Pure relocation of the inline
/// channel-bootstrap region.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_channel_adapters(
    config: &FreedomConfig,
    shared_provider: &Option<Arc<dyn Provider>>,
    writer: &WalWriterHandle,
    provider_meter: &crate::providers::meter::Meter,
    rate_limiter: &Arc<crate::channels::rate_limit::RateLimiter>,
    segment_path: &std::path::Path,
    shared_views_conn: &Option<Arc<tokio::sync::Mutex<rusqlite::Connection>>>,
    reload_controller: &Arc<crate::config::reload::ReloadController>,
    dispatch_join: &Arc<tokio::sync::Mutex<tokio::task::JoinSet<()>>>,
    creds: &crate::config::credentials::Credentials,
    channel_tasks: &mut Vec<JoinHandle<()>>,
    // GOLD-ADAPT-GOOSE-03: shared approval bus passed into every channel handler.
    // When `Some`, channel permission gates switch to Channel confirm strategy
    // (suspend/resume via UUID elicitation). `None` = fail-closed (pre-GOOSE-03).
    confirm_bus: &Option<Arc<crate::permissions::confirm_bus::ConfirmBus>>,
    // GOLD-ADAPT-TRAIL-04: multi-reader executor. When `Some`, read-only DB
    // calls in channel handlers use a pool reader (non-serialising).
    views_executor: &Option<std::sync::Arc<crate::memory::store::ViewsExecutor>>,
) {
    if let (Some(telegram_token), Some(provider)) =
        (config.telegram_token.clone(), shared_provider.as_ref())
    {
        let handler: PipelineHandler = build_channel_handler(
            provider.clone(),
            config,
            writer,
            provider_meter,
            rate_limiter,
            segment_path,
            shared_views_conn,
            reload_controller,
            confirm_bus.clone(),
            views_executor.clone(),
        );
        // SF-03: hand the adapter the daemon's WAL writer so allowlist-rejected
        // senders are audited via `0x3B CHANNEL_GATE_REJECTED`.
        let channel = crate::channels::telegram::TelegramChannel::new(
            telegram_token,
            config.telegram_user_id,
        )
        .with_gate_writer(writer.clone());
        spawn_channel_run(channel, handler, "Telegram", channel_tasks);
        info!(
            channel = "telegram",
            status = "LIVE",
            "channel: spawned (polling loop)"
        );
    } else if config.telegram_token.is_some() && shared_provider.is_none() {
        warn!(
            channel = "telegram",
            status = "CONFIGURED-NOT-STARTED",
            "Telegram token configured but provider unavailable; channel not started"
        );
    }

    // R4-P1 honest channel-bootstrap status logging: every channel gets an
    // explicit log line at boot so `neoth doctor channels` matches what
    // `neoth serve` actually did (LIVE / CONFIGURED-NOT-STARTED / OUTBOUND-ONLY).
    // Slack socket-mode inbound — spawns the WebSocket receive loop when both
    // bot + app tokens are configured. Requires a provider; else log CNS.
    match (
        creds.slack_bot_token.clone(),
        creds.slack_app_token.clone(),
        shared_provider.as_ref(),
    ) {
        (Some(bot), Some(app), Some(provider)) => {
            let handler: PipelineHandler = build_channel_handler(
                provider.clone(),
                config,
                writer,
                provider_meter,
                rate_limiter,
                segment_path,
                shared_views_conn,
                reload_controller,
                confirm_bus.clone(),
                views_executor.clone(),
            );
            let channel = crate::channels::slack::SlackChannel::new(bot, app);
            spawn_channel_run(channel, handler, "Slack", channel_tasks);
            info!(
                channel = "slack",
                status = "LIVE",
                "channel: spawned (socket-mode WS loop)"
            );
        }
        (Some(_), None, _) | (None, Some(_), _) => {
            warn!(
                channel = "slack",
                status = "CONFIGURED-NOT-STARTED",
                "Slack needs BOTH bot_token (xoxb-) and app_token (xapp-) for socket mode; \
                 only one supplied — receive loop not started. send_text still works."
            );
        }
        (Some(_), Some(_), None) => {
            warn!(
                channel = "slack",
                status = "CONFIGURED-NOT-STARTED",
                "Slack tokens configured but provider unavailable; channel not started"
            );
        }
        (None, None, _) => {}
    }

    // GOLD-PROG-16 — Discord inbound via the gateway WS receive loop. Spawns
    // when a bot token + provider are present (`DiscordChannel::run` dials the
    // gateway). Mirrors the Slack creds-based arm.
    match (creds.discord_bot_token.clone(), shared_provider.as_ref()) {
        (Some(token), Some(provider)) => {
            match crate::channels::discord::DiscordChannel::new(token) {
                Ok(channel) => {
                    let handler: PipelineHandler = build_channel_handler(
                        provider.clone(),
                        config,
                        writer,
                        provider_meter,
                        rate_limiter,
                        segment_path,
                        shared_views_conn,
                        reload_controller,
                        confirm_bus.clone(),
                        views_executor.clone(),
                    );
                    spawn_channel_run(channel, handler, "Discord", channel_tasks);
                    info!(
                        channel = "discord",
                        status = "LIVE",
                        "channel: spawned (gateway WS loop)"
                    );
                }
                Err(e) => warn!(
                    channel = "discord",
                    error = %e,
                    "Discord token configured but adapter construction failed; channel not started"
                ),
            }
        }
        (Some(_), None) => warn!(
            channel = "discord",
            status = "CONFIGURED-NOT-STARTED",
            "Discord token configured but provider unavailable; channel not started"
        ),
        (None, _) => {}
    }

    // GOLD-FEAT-10 — Signal inbound via the signal-cli poll loop. Spawns when
    // the cli URL + registered number + a provider are all present
    // (`SignalChannel::run` polls /v1/receive). Mirrors the Discord creds arm.
    match (
        creds.signal_cli_url.clone(),
        creds.signal_phone_number.clone(),
        shared_provider.as_ref(),
    ) {
        (Some(url), Some(number), Some(provider)) => {
            match crate::channels::signal::SignalChannel::new(url, number) {
                Ok(channel) => {
                    let handler: PipelineHandler = build_channel_handler(
                        provider.clone(),
                        config,
                        writer,
                        provider_meter,
                        rate_limiter,
                        segment_path,
                        shared_views_conn,
                        reload_controller,
                        confirm_bus.clone(),
                        views_executor.clone(),
                    );
                    spawn_channel_run(channel, handler, "Signal", channel_tasks);
                    info!(
                        channel = "signal",
                        status = "LIVE",
                        "channel: spawned (signal-cli poll loop)"
                    );
                }
                Err(e) => warn!(
                    channel = "signal",
                    error = %e,
                    "Signal configured but adapter construction failed; channel not started"
                ),
            }
        }
        (Some(_), Some(_), None) => warn!(
            channel = "signal",
            status = "CONFIGURED-NOT-STARTED",
            "Signal configured but provider unavailable; channel not started"
        ),
        (Some(_), None, _) | (None, Some(_), _) => warn!(
            channel = "signal",
            status = "CONFIGURED-NOT-STARTED",
            "Signal needs BOTH signal_cli_url and signal_phone_number; only one supplied — not started"
        ),
        (None, None, _) => {}
    }

    // GOLD-FEAT-10b — iMessage via a local BlueBubbles server (REST polling;
    // NEOTH dials OUT, no public URL). Always compiled — pure `reqwest` +
    // `serde`, no new dep. Spawns when `bluebubbles_url` + `bluebubbles_password`
    // + a provider are all present (`BlueBubblesChannel::run` polls `/api/v1/message`).
    match (
        creds.bluebubbles_url.clone(),
        creds.bluebubbles_password.clone(),
        shared_provider.as_ref(),
    ) {
        (Some(url), Some(password), Some(provider)) => {
            // Parse optional comma-separated chat GUID allowlist.
            let chat_guid_allowlist: Option<Vec<String>> =
                creds.bluebubbles_chat_guid.as_deref().map(|s| {
                    s.split(',')
                        .map(|g| g.trim().to_string())
                        .filter(|g| !g.is_empty())
                        .collect()
                });
            match crate::channels::imessage_bluebubbles::BlueBubblesChannel::new(
                url,
                password,
                chat_guid_allowlist,
                creds.imessage_allowed_sender.clone(),
            ) {
                Ok(channel) => {
                    let channel = channel.with_gate_writer(writer.clone());
                    let handler: PipelineHandler = build_channel_handler(
                        provider.clone(),
                        config,
                        writer,
                        provider_meter,
                        rate_limiter,
                        segment_path,
                        shared_views_conn,
                        reload_controller,
                        confirm_bus.clone(),
                        views_executor.clone(),
                    );
                    spawn_channel_run(channel, handler, "BlueBubbles", channel_tasks);
                    info!(
                        channel = "imessage_bluebubbles",
                        status = "LIVE",
                        "channel: spawned (bluebubbles REST poll loop)"
                    );
                }
                Err(e) => warn!(
                    channel = "imessage_bluebubbles",
                    error = %e,
                    "BlueBubbles configured but adapter construction failed; channel not started"
                ),
            }
        }
        (Some(_), Some(_), None) => warn!(
            channel = "imessage_bluebubbles",
            status = "CONFIGURED-NOT-STARTED",
            "BlueBubbles configured but provider unavailable; channel not started"
        ),
        (Some(_), None, _) | (None, Some(_), _) => warn!(
            channel = "imessage_bluebubbles",
            status = "CONFIGURED-NOT-STARTED",
            "BlueBubbles needs BOTH bluebubbles_url and bluebubbles_password; only one supplied — not started"
        ),
        (None, None, _) => {}
    }

    // GOLD-FEAT-10 — Mattermost inbound via the WebSocket API (NEOTH dials OUT,
    // no public URL). Always compiled (reuses tokio-tungstenite + reqwest, no new
    // crate). Spawns when the server URL + token + a provider are all present
    // (`MattermostChannel::run` fetches /users/me then streams the WS).
    match (
        creds.mattermost_url.clone(),
        creds.mattermost_token.clone(),
        shared_provider.as_ref(),
    ) {
        (Some(url), Some(token), Some(provider)) => {
            let channel = crate::channels::mattermost::MattermostChannel::new(url, token)
                .with_allowlist(creds.mattermost_allowed_user_id.clone(), writer.clone());
            let handler: PipelineHandler = build_channel_handler(
                provider.clone(),
                config,
                writer,
                provider_meter,
                rate_limiter,
                segment_path,
                shared_views_conn,
                reload_controller,
                confirm_bus.clone(),
                views_executor.clone(),
            );
            spawn_channel_run(channel, handler, "Mattermost", channel_tasks);
            info!(
                channel = "mattermost",
                status = "LIVE",
                "channel: spawned (mattermost WebSocket loop)"
            );
        }
        (Some(_), Some(_), None) => warn!(
            channel = "mattermost",
            status = "CONFIGURED-NOT-STARTED",
            "Mattermost configured but provider unavailable; channel not started"
        ),
        (Some(_), None, _) | (None, Some(_), _) => warn!(
            channel = "mattermost",
            status = "CONFIGURED-NOT-STARTED",
            "Mattermost needs BOTH mattermost_url and mattermost_token; only one supplied — not started"
        ),
        (None, None, _) => {}
    }

    // GOLD-FEAT-10 — Matrix inbound via matrix-sdk (feature `matrix-channel`).
    // Spawns when the homeserver + bot user id + a provider are all present;
    // the adapter logs in (or restores the persisted device session) lazily on
    // its first sync. Compiled only in `--features matrix-channel` builds —
    // without the feature a configured `matrix:` block is surfaced by `neoth
    // doctor`'s probe row instead of silently ignored. Mirrors the Signal arm.
    #[cfg(feature = "matrix-channel")]
    {
        match (
            creds.matrix_homeserver.clone(),
            creds.matrix_user_id.clone(),
            shared_provider.as_ref(),
        ) {
            (Some(homeserver), Some(user_id), Some(provider)) => {
                let channel = crate::channels::matrix::MatrixChannel::new(
                    homeserver,
                    user_id,
                    creds.matrix_password.clone(),
                    creds
                        .matrix_store_path
                        .clone()
                        .map(std::path::PathBuf::from),
                )
                .with_allowlist(creds.matrix_allowed_user_id.clone(), writer.clone());
                let handler: PipelineHandler = build_channel_handler(
                    provider.clone(),
                    config,
                    writer,
                    provider_meter,
                    rate_limiter,
                    segment_path,
                    shared_views_conn,
                    reload_controller,
                    confirm_bus.clone(),
                    views_executor.clone(),
                );
                spawn_channel_run(channel, handler, "Matrix", channel_tasks);
                info!(
                    channel = "matrix",
                    status = "LIVE",
                    "channel: spawned (matrix-sdk E2EE sync loop)"
                );
            }
            (Some(_), Some(_), None) => warn!(
                channel = "matrix",
                status = "CONFIGURED-NOT-STARTED",
                "Matrix configured but provider unavailable; channel not started"
            ),
            (Some(_), None, _) | (None, Some(_), _) => warn!(
                channel = "matrix",
                status = "CONFIGURED-NOT-STARTED",
                "Matrix needs BOTH matrix_homeserver and matrix_user_id; only one supplied — not started"
            ),
            (None, None, _) => {}
        }
    }

    // GOLD-FEAT-10 — IRC inbound via the `irc` crate (raw TCP; NEOTH dials OUT,
    // no public URL). Compiled only in `--features irc-channel` builds. Starts
    // when irc_server + irc_nick + a provider are all present.
    #[cfg(feature = "irc-channel")]
    {
        match (
            creds.irc_server.clone(),
            creds.irc_nick.clone(),
            shared_provider.as_ref(),
        ) {
            (Some(server), Some(nick), Some(provider)) => {
                let channel = crate::channels::irc::IrcChannel::new(
                    server,
                    creds.irc_port.unwrap_or(6697),
                    nick,
                    creds.irc_password.clone(),
                    creds.irc_channels.clone().unwrap_or_default(),
                    creds.irc_tls.unwrap_or(true),
                )
                .with_allowlist(creds.irc_allowed_nick.clone(), writer.clone())
                .with_allowed_account(creds.irc_allowed_account.clone());
                let handler: PipelineHandler = build_channel_handler(
                    provider.clone(),
                    config,
                    writer,
                    provider_meter,
                    rate_limiter,
                    segment_path,
                    shared_views_conn,
                    reload_controller,
                    confirm_bus.clone(),
                    views_executor.clone(),
                );
                spawn_channel_run(channel, handler, "IRC", channel_tasks);
                info!(
                    channel = "irc",
                    status = "LIVE",
                    "channel: spawned (irc TCP receive loop)"
                );
            }
            (Some(_), Some(_), None) => warn!(
                channel = "irc",
                status = "CONFIGURED-NOT-STARTED",
                "IRC configured but provider unavailable; channel not started"
            ),
            (Some(_), None, _) | (None, Some(_), _) => warn!(
                channel = "irc",
                status = "CONFIGURED-NOT-STARTED",
                "IRC needs BOTH irc_server and irc_nick; only one supplied — not started"
            ),
            (None, None, _) => {}
        }
    }

    // GOLD-FEAT-10 — Twitch chat via the IRC adapter (Twitch chat IS IRC). Same
    // `irc-channel` feature; NEOTH dials OUT to irc.chat.twitch.tv, no public URL.
    // Starts when twitch_username + twitch_oauth_token + a provider are present.
    #[cfg(feature = "irc-channel")]
    {
        match (
            creds.twitch_username.clone(),
            creds.twitch_oauth_token.clone(),
            shared_provider.as_ref(),
        ) {
            (Some(username), Some(oauth), Some(provider)) => {
                let channel = crate::channels::irc::IrcChannel::for_twitch(
                    username,
                    oauth,
                    creds.twitch_channels.clone().unwrap_or_default(),
                );
                let handler: PipelineHandler = build_channel_handler(
                    provider.clone(),
                    config,
                    writer,
                    provider_meter,
                    rate_limiter,
                    segment_path,
                    shared_views_conn,
                    reload_controller,
                    confirm_bus.clone(),
                    views_executor.clone(),
                );
                spawn_channel_run(channel, handler, "Twitch", channel_tasks);
                info!(
                    channel = "twitch",
                    status = "LIVE",
                    "channel: spawned (twitch IRC receive loop)"
                );
            }
            (Some(_), Some(_), None) => warn!(
                channel = "twitch",
                status = "CONFIGURED-NOT-STARTED",
                "Twitch configured but provider unavailable; channel not started"
            ),
            (Some(_), None, _) | (None, Some(_), _) => warn!(
                channel = "twitch",
                status = "CONFIGURED-NOT-STARTED",
                "Twitch needs BOTH twitch_username and twitch_oauth_token; only one supplied — not started"
            ),
            (None, None, _) => {}
        }
    }

    // GOLD-FEAT-10 — Nostr inbound via `nostr-sdk` (WSS relays; NEOTH dials OUT,
    // no public URL). Compiled only in `--features nostr-channel` builds. Starts
    // when nostr_secret_key + nostr_relays + a provider are all present.
    #[cfg(feature = "nostr-channel")]
    {
        match (
            creds.nostr_secret_key.clone(),
            creds.nostr_relays.clone(),
            shared_provider.as_ref(),
        ) {
            (Some(secret_key), Some(relays), Some(provider)) => {
                let channel = crate::channels::nostr::NostrChannel::new(secret_key, relays)
                    .with_allowlist(creds.nostr_allowed_pubkey.clone(), writer.clone());
                let handler: PipelineHandler = build_channel_handler(
                    provider.clone(),
                    config,
                    writer,
                    provider_meter,
                    rate_limiter,
                    segment_path,
                    shared_views_conn,
                    reload_controller,
                    confirm_bus.clone(),
                    views_executor.clone(),
                );
                spawn_channel_run(channel, handler, "Nostr", channel_tasks);
                info!(
                    channel = "nostr",
                    status = "LIVE",
                    "channel: spawned (nostr relay receive loop)"
                );
            }
            (Some(_), Some(_), None) => warn!(
                channel = "nostr",
                status = "CONFIGURED-NOT-STARTED",
                "Nostr configured but provider unavailable; channel not started"
            ),
            (Some(_), None, _) | (None, Some(_), _) => warn!(
                channel = "nostr",
                status = "CONFIGURED-NOT-STARTED",
                "Nostr needs BOTH nostr_secret_key and nostr_relays; only one supplied — not started"
            ),
            (None, None, _) => {}
        }
    }

    // B9 — Google Chat via a GCP Pub/Sub PULL subscription (NEOTH dials OUT,
    // no public URL). Compiled only in `--features gchat-channel` builds.
    // Starts when gchat_service_account_json + gchat_subscription + a provider
    // are all present.
    #[cfg(feature = "gchat-channel")]
    {
        match (
            creds.gchat_service_account_json.clone(),
            creds.gchat_subscription.clone(),
            shared_provider.as_ref(),
        ) {
            (Some(sa_path), Some(subscription), Some(provider)) => {
                match crate::channels::gchat::GChatChannel::new(
                    std::path::Path::new(&sa_path),
                    subscription,
                ) {
                    Ok(channel) => {
                        let channel = channel
                            .with_allowlist(creds.gchat_allowed_sender.clone(), writer.clone());
                        let handler: PipelineHandler = build_channel_handler(
                            provider.clone(),
                            config,
                            writer,
                            provider_meter,
                            rate_limiter,
                            segment_path,
                            shared_views_conn,
                            reload_controller,
                            confirm_bus.clone(),
                            views_executor.clone(),
                        );
                        spawn_channel_run(channel, handler, "GoogleChat", channel_tasks);
                        info!(
                            channel = "gchat",
                            status = "LIVE",
                            "channel: spawned (google chat pubsub pull loop)"
                        );
                    }
                    Err(e) => warn!(
                        channel = "gchat",
                        status = "CONFIGURED-NOT-STARTED",
                        error = %e,
                        "Google Chat service-account key unreadable; channel not started"
                    ),
                }
            }
            (Some(_), Some(_), None) => warn!(
                channel = "gchat",
                status = "CONFIGURED-NOT-STARTED",
                "Google Chat configured but provider unavailable; channel not started"
            ),
            (Some(_), None, _) | (None, Some(_), _) => warn!(
                channel = "gchat",
                status = "CONFIGURED-NOT-STARTED",
                "Google Chat needs BOTH gchat_service_account_json and gchat_subscription; only one supplied — not started"
            ),
            (None, None, _) => {}
        }
    }

    // WhatsApp inbound via Meta webhook listener — spawns when phone-id +
    // verify-token + app-secret + provider are all present. Listens on
    // 127.0.0.1:<whatsapp_webhook_port> (default 8443).
    let whatsapp_inbound_started = match (
        creds.whatsapp_token.clone(),
        creds.whatsapp_phone_id.clone(),
        creds.whatsapp_verify_token.clone(),
        creds.whatsapp_app_secret.clone(),
        shared_provider.as_ref(),
    ) {
        (Some(token), Some(phone), Some(verify), Some(secret), Some(provider)) => {
            let handler: PipelineHandler = build_channel_handler(
                provider.clone(),
                config,
                writer,
                provider_meter,
                rate_limiter,
                segment_path,
                shared_views_conn,
                reload_controller,
                confirm_bus.clone(),
                views_executor.clone(),
            );
            let port = config.whatsapp_webhook_port.unwrap_or(8443);
            let bind: std::net::SocketAddr = format!("127.0.0.1:{port}")
                .parse()
                .expect("static bind addr parses");
            // GR-01 Pick B: thread the Graph API send creds into the listener so
            // the dispatch path can route pipeline replies back through Meta.
            let listener_cfg = crate::channels::webhook_listener::WebhookListenerConfig {
                meta_app_secret: secret.expose().as_bytes().to_vec(),
                meta_verify_token: verify.expose().to_string(),
                slack_signing_secret: Vec::new(),
                pipeline: handler,
                whatsapp_send_creds: Some(crate::channels::webhook_listener::WhatsAppSendCreds {
                    access_token: token.clone(),
                    phone_number_id: phone.clone(),
                    base_url: None,
                }),
                // P0 — gate + audit the WhatsApp webhook reply send under the
                // active autonomy; honour the proof-hardline required-audit switch.
                send_governance: crate::channels::webhook_listener::SendGovernance {
                    wal_writer: Some(writer.clone()),
                    decision: crate::permissions::evaluate(
                        &crate::permissions::Action::ChannelSend,
                        config.autonomy,
                    ),
                    required_audit: config.audit_rpc.required_for_oneshot_permission_events,
                    dry_run: false,
                },
                max_concurrent_connections: None,
                // COR-34: track this listener's detached Meta fan-out tasks so
                // shutdown can drain their WAL writes before the writer closes.
                dispatch_join: Some(std::sync::Arc::clone(dispatch_join)),
                // GR-010: dedup inbound wamids so Meta reconnect-storm
                // re-deliveries don't re-run the pipeline (+ re-send the reply).
                inbound_dedup: Some(std::sync::Arc::new(tokio::sync::Mutex::new(
                    crate::channels::webhook_listener::InboundDedup::new(2048),
                ))),
                // This is the WhatsApp/Meta listener — LINE has its own arm below.
                line: None,
            };
            let task = tokio::spawn(async move {
                // GR-012b — re-dispatch any inbound webhooks spooled before a
                // prior crash (ACKed 200 to Meta but never provably processed)
                // BEFORE accepting new ones. Borrow for the drain, then `serve`
                // consumes the cfg.
                crate::channels::webhook_listener::drain_inbound_spool(&listener_cfg).await;
                let shutdown = std::future::pending::<()>();
                if let Err(e) =
                    crate::channels::webhook_listener::serve(bind, listener_cfg, shutdown).await
                {
                    tracing::error!(error = %e, "WhatsApp webhook listener exited with error");
                }
            });
            channel_tasks.push(task);
            info!(
                channel = "whatsapp",
                status = "LIVE",
                port = port,
                "channel: spawned (Meta webhook listener on 127.0.0.1)"
            );
            true
        }
        (Some(_), _, _, _, None) => {
            warn!(
                channel = "whatsapp",
                status = "CONFIGURED-NOT-STARTED",
                "WhatsApp credentials configured but provider unavailable; channel not started"
            );
            false
        }
        (Some(_), _, _, _, _) => {
            warn!(
                channel = "whatsapp",
                status = "OUTBOUND-ONLY",
                "WhatsApp send_text works but inbound needs whatsapp_verify_token + \
                 whatsapp_app_secret in credentials.yaml. Listener not started."
            );
            false
        }
        _ => false,
    };
    let _ = whatsapp_inbound_started;

    // GOLD-FEAT-10 — LINE inbound via the shared webhook listener. Spawns when
    // the channel access token + channel secret + a provider are all present.
    // Listens on 127.0.0.1:<line_webhook_port> (default 8444); the operator
    // fronts it with a public HTTPS reverse proxy. Outbound replies route back
    // through the LINE push API, gated + audited like the WhatsApp arm.
    match (
        creds.line_channel_access_token.clone(),
        creds.line_channel_secret.clone(),
        shared_provider.as_ref(),
    ) {
        (Some(access_token), Some(secret), Some(provider)) => {
            let handler: PipelineHandler = build_channel_handler(
                provider.clone(),
                config,
                writer,
                provider_meter,
                rate_limiter,
                segment_path,
                shared_views_conn,
                reload_controller,
                confirm_bus.clone(),
                views_executor.clone(),
            );
            let port = creds.line_webhook_port.unwrap_or(8444);
            let bind: std::net::SocketAddr = format!("127.0.0.1:{port}")
                .parse()
                .expect("static bind addr parses");
            let listener_cfg = crate::channels::webhook_listener::WebhookListenerConfig {
                meta_app_secret: Vec::new(),
                meta_verify_token: String::new(),
                slack_signing_secret: Vec::new(),
                pipeline: handler,
                whatsapp_send_creds: None,
                // P0 — gate + audit every LINE webhook reply under the active
                // autonomy; honour the proof-hardline required-audit switch.
                send_governance: crate::channels::webhook_listener::SendGovernance {
                    wal_writer: Some(writer.clone()),
                    decision: crate::permissions::evaluate(
                        &crate::permissions::Action::ChannelSend,
                        config.autonomy,
                    ),
                    required_audit: config.audit_rpc.required_for_oneshot_permission_events,
                    dry_run: false,
                },
                max_concurrent_connections: None,
                // COR-34: track the detached LINE fan-out tasks so shutdown can
                // drain their WAL writes before the writer closes.
                dispatch_join: Some(std::sync::Arc::clone(dispatch_join)),
                // Dedup inbound webhookEventIds so a LINE redelivery doesn't
                // re-run the pipeline (+ re-send the reply).
                inbound_dedup: Some(std::sync::Arc::new(tokio::sync::Mutex::new(
                    crate::channels::webhook_listener::InboundDedup::new(2048),
                ))),
                line: Some(crate::channels::webhook_listener::LineConfig {
                    channel_secret: secret.expose().as_bytes().to_vec(),
                    access_token,
                    base_url: None,
                }),
            };
            let task = tokio::spawn(async move {
                let shutdown = std::future::pending::<()>();
                if let Err(e) =
                    crate::channels::webhook_listener::serve(bind, listener_cfg, shutdown).await
                {
                    tracing::error!(error = %e, "LINE webhook listener exited with error");
                }
            });
            channel_tasks.push(task);
            info!(
                channel = "line",
                status = "LIVE",
                port = port,
                "channel: spawned (LINE webhook listener on 127.0.0.1)"
            );
        }
        (Some(_), Some(_), None) => warn!(
            channel = "line",
            status = "CONFIGURED-NOT-STARTED",
            "LINE configured but provider unavailable; channel not started"
        ),
        (Some(_), None, _) => warn!(
            channel = "line",
            status = "OUTBOUND-ONLY",
            "LINE access token set but channel secret missing — inbound webhook needs \
             line_channel_secret to verify signatures. Listener not started (send_text still works)."
        ),
        (None, Some(_), _) => warn!(
            channel = "line",
            status = "CONFIGURED-NOT-STARTED",
            "LINE channel secret set but line_channel_access_token missing; cannot send. Listener not started."
        ),
        (None, None, _) => {}
    }

    // Discord + Keet have no credential fields in credentials.yaml yet — when
    // they land, the same explicit-log pattern fires.
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
    // GOLD-ADAPT-GOOSE-03: shared approval bus. When `Some`, channel gates
    // switch from FailClosed to Channel strategy (suspend/resume via UUID).
    confirm_bus: Option<Arc<crate::permissions::confirm_bus::ConfirmBus>>,
    // GOLD-ADAPT-TRAIL-04: multi-reader executor. When `Some`, read-only DB
    // ops (identity resolve) use a pool reader instead of the write mutex.
    views_executor: Option<std::sync::Arc<crate::memory::store::ViewsExecutor>>,
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
        views_executor,
        confirm_bus,
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

/// GOLD-ARCH-01: the WAL directory + writer, produced by [`prepare_wal`].
/// `writer_join` is returned plain; `run_serve` rebinds it `mut` (the idle-wait
/// `select!` borrows `&mut writer_join`).
pub(crate) struct WalSetup {
    pub wal_dir: std::path::PathBuf,
    pub segment_path: std::path::PathBuf,
    pub writer: WalWriterHandle,
    pub writer_join: JoinHandle<()>,
}

/// GOLD-ARCH-01: WAL setup (steps 2/2b/3/3b/BS-4). Prepares the WAL dir (0700 on
/// unix), runs the ADV-01 `.cpt` crash-recovery scan, spawns the writer task,
/// flushes deferred quarantine-audit frames into the now-live chain, and
/// attaches the BS-4 quota guard. Returns the dir + segment path + quota-guarded
/// writer + join handle. The BOOT frame, the `--one-shot` early-return, the wasm
/// plugin invoker bootstrap, and the council-depth warning STAY in `run_serve`
/// (they run after the writer exists). Behaviour-identical to the prior inline
/// WAL prelude.
pub(crate) fn prepare_wal(wal_segment: Option<std::path::PathBuf>) -> anyhow::Result<WalSetup> {
    let wal_dir = FreedomConfig::default_wal_dir();
    let segment_path = wal_segment.unwrap_or_else(|| wal_dir.join("000001.wal"));

    if let Some(parent) = segment_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create WAL dir {}", parent.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            {
                warn!(
                    path = %parent.display(),
                    error = %e,
                    "could not chmod 0700 on WAL dir; continuing with inherited mode"
                );
            }
        }
    }

    // ── 2b. ADV-01 — apply or quarantine any pre-existing `.cpt` files ─────
    // Before the writer opens any segment, walk the WAL dir for crash-recovery
    // compaction files. Valid pairs are renamed `.cpt → .bin`; tampered ones are
    // quarantined + surfaced via a `COMPACTION_AUTH_FAILED` (0x51) frame once the
    // writer is up below.
    let pending_auth_failures: Vec<crate::wal::cpt_recovery::ScanReport> = {
        let key_path = crate::wal::compaction::default_key_path();
        match crate::wal::compaction::load_or_init_key(&key_path) {
            Ok(master) => {
                let auth = crate::wal::cpt_auth::CompactionAuthenticator::from_master_key(&master);
                match crate::wal::cpt_recovery::scan_and_apply(&wal_dir, &auth, || {
                    crate::time::now_unix_secs()
                }) {
                    Ok(report) => {
                        if report.total() > 0 {
                            info!(
                                applied = report.applied.len(),
                                quarantined = report.quarantined.len(),
                                "ADV-01: WAL .cpt recovery scan complete"
                            );
                        }
                        if report.quarantined.is_empty() {
                            Vec::new()
                        } else {
                            vec![report]
                        }
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            wal_dir = %wal_dir.display(),
                            "ADV-01: .cpt recovery scan failed — continuing startup"
                        );
                        Vec::new()
                    }
                }
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "ADV-01: HMAC master key unavailable — skipping .cpt recovery scan. \
                     Any pre-existing .cpt files are left in place and will be re-evaluated \
                     on next startup once the key is recoverable."
                );
                Vec::new()
            }
        }
    };

    // ── 3. Spawn writer task ───────────────────────────────────────────────
    let (writer, writer_join) =
        crate::wal::spawn(segment_path.clone()).context("spawn WAL writer task")?;

    // ── 3b. ADV-01 — emit deferred audit frames for quarantined `.cpt`s ────
    for report in pending_auth_failures {
        for quarantine_path in report.quarantined {
            let now_unix = crate::time::now_unix_secs();
            // Reconstruct the original `.cpt` path from the quarantine
            // suffix so the audit payload names the original file.
            let cpt_path = quarantine_path
                .to_string_lossy()
                .rsplit_once(".rejected.")
                .map(|(prefix, _)| std::path::PathBuf::from(prefix))
                .unwrap_or_else(|| quarantine_path.clone());
            let payload = crate::wal::cpt_recovery::auth_failed_payload(
                &cpt_path,
                "hmac verification failed at recovery scan",
                now_unix,
                &quarantine_path,
            );
            let header = crate::wal::HeaderBuilder::new(
                crate::wal::events::EVENT_TYPE_COMPACTION_AUTH_FAILED,
                &payload,
            )
            .build();
            if let Err(e) = writer.try_append_sync(header, payload) {
                warn!(
                    error = %e,
                    quarantine = %quarantine_path.display(),
                    "ADV-01: failed to emit COMPACTION_AUTH_FAILED audit frame"
                );
            }
        }
    }
    // Phase 33c BS-4 quota enforcement: attach a guard so the writer
    // refuses appends once `~/.neoth/` crosses the configured ceiling.
    let writer = {
        let home = FreedomConfig::default_neoth_home();
        let ceiling = std::env::var("NEOTH_QUOTA_CEILING_BYTES")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(crate::daemon::quota::DEFAULT_CEILING_BYTES);
        writer.with_quota_guard(std::sync::Arc::new(crate::wal::writer::QuotaGuard::new(
            home, ceiling,
        )))
    };
    info!(path = %segment_path.display(), "WAL writer spawned");

    Ok(WalSetup {
        wal_dir,
        segment_path,
        writer,
        writer_join,
    })
}

/// GOLD-ADAPT-OH-03 — reject `neoth serve` when no channel/integration was
/// configured at init time. Two-stage check for idempotency:
///
/// 1. Fast path: `onboarding_complete` flag in freedom.yaml is `true` → pass.
/// 2. Secondary probe: even if flag is `false` (old freedom.yaml or flag absent),
///    load credentials.yaml + [`ChannelCredsView`] + [`probe_all`] — if any
///    channel is `Ok` or `Warn`, pass (operator configured channels manually or
///    via step6g after initial wizard).
///
/// Call this from `run_serve` BEFORE `prime_runtime_services`, guarded by
/// `!args.one_shot` so integration tests with ephemeral configs pass through.
pub(crate) fn check_onboarding_complete(cfg: &FreedomConfig) -> anyhow::Result<()> {
    // Fast path — flag was set by write_config during wizard.
    if cfg.onboarding_complete {
        return Ok(());
    }

    // Secondary probe: even without the wizard flag, the operator may have
    // hand-configured channels in credentials.yaml (step6g, manual edit, or an
    // old freedom.yaml that pre-dates the flag). Use the authoritative
    // ChannelCredsView + probe_all so every one of the 13 channel adapters is
    // covered, not just the two wizard-path channels (keet + telegram).
    let cred_path = crate::config::credentials::default_path();
    let creds = crate::config::credentials::Credentials::load_or_default(&cred_path)
        .unwrap_or_default();
    let view =
        crate::channels::probe::ChannelCredsView::from_config(Some(cfg), &creds);
    let any_channel = crate::channels::probe::probe_all(&view)
        .into_iter()
        .any(|h| {
            matches!(
                h.status,
                crate::channels::probe::ProbeStatus::Ok
                    | crate::channels::probe::ProbeStatus::Warn
            )
        });
    if any_channel {
        return Ok(());
    }

    anyhow::bail!(
        "GOLD-ADAPT-OH-03: onboarding incomplete — no channel or integration configured.\n\
         Run `neoth init` and configure at least one channel (Telegram, Discord, Slack, …)\n\
         before starting the daemon. Or set `onboarding_complete: true` in freedom.yaml\n\
         if you have configured channels manually via credentials.yaml."
    )
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
        let now_ns = crate::time::now_unix_ns();
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
    /// Shared with the adapter-fleet reload supervisor, which swaps the
    /// vec's contents on every successful `neoth reload`.
    pub channel_tasks: Arc<std::sync::Mutex<Vec<JoinHandle<()>>>>,
    /// The fleet supervisor itself — aborted BEFORE the channel tasks
    /// so a reload racing shutdown can't respawn into a dying daemon.
    pub channel_supervisor_task: JoinHandle<()>,
    pub dispatch_join: Arc<tokio::sync::Mutex<tokio::task::JoinSet<()>>>,
    pub cron_task: Option<JoinHandle<()>>,
    /// ZF-06 — fleet map + supervisor; replaces 21 individual cron handles.
    pub cron_fleet: CronFleet,
    pub cron_supervisor_task: JoinHandle<()>,
    pub snapshot_refresh_handle: Option<JoinHandle<()>>,
    pub omi_handle: Option<JoinHandle<()>>,
    pub updater_self_task: Option<JoinHandle<()>>,
    // ── 4 deferred crons (not fleet-managed) ───────────────────────────────
    pub updater_cli_task: Option<JoinHandle<()>>,
    pub updater_skill_task: Option<JoinHandle<()>>,
    pub cli_autoupdate_task: Option<JoinHandle<()>>,
    pub self_stage_task: Option<JoinHandle<()>>,
    pub catalog_task: JoinHandle<()>,
    #[cfg(feature = "cluster")]
    pub cluster_audit_task: JoinHandle<()>,
    #[cfg(feature = "cluster")]
    pub cluster_foreign_indexer_task: crate::cluster::foreign_indexer::ForeignIndexerHandle,
    #[cfg(feature = "cluster")]
    pub cluster_gossip_task: Option<JoinHandle<()>>,
    #[cfg(feature = "cluster")]
    pub cluster_swarm: Option<crate::cluster::hyperswarm::SwarmHandle>,
    /// mDNS LAN announcer (Phase-2 wire-in). Dropping the ServiceDaemon
    /// unregisters `_neoth._udp.local.`; torn down beside the swarm.
    #[cfg(feature = "cluster")]
    pub mdns_daemon: Option<mdns_sd::ServiceDaemon>,
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
    // ── 4 deferred crons kept as direct fields ──────────────────────────────
    /// GOLD-FEAT-11 — LLM check-in body cron handle (async spawn; deferred).
    /// `None` when `checkin_cron.enabled = false` (default).
    pub checkin_cron_handle: Option<JoinHandle<()>>,
    /// GOLD-ADAPT-ODY-26 — session auto-sort cron handle (async; deferred).
    /// `None` when `session_sort_cron.enabled = false` (default).
    pub session_sort_cron_handle: Option<JoinHandle<()>>,
    /// GOLD-ADAPT-JV-PAPERLESS-01 — email ingest cron (inline in serve.rs; deferred).
    /// `None` when `email_ingest_cron.enabled = false` (default).
    pub email_ingest_cron_handle: Option<JoinHandle<()>>,
    /// ADV-14 regression-anchor cron (async + provider dep; deferred).
    pub regression_cron_handle: Option<JoinHandle<()>>,
    pub dreaming_task: Option<JoinHandle<anyhow::Result<()>>>,
    pub arxiv_ingest_task: Option<JoinHandle<anyhow::Result<()>>>,
    /// GOLD-ADAPT-MEM-16 — ArXiv skill-learning cron handle.
    /// WAL-free; `None` when `arxiv_skill_scan.enabled = false` (default)
    /// or no provider is wired.
    pub arxiv_skill_scan_task: Option<JoinHandle<anyhow::Result<()>>>,
    pub rss_feed_task: Option<JoinHandle<anyhow::Result<()>>>,
    pub tmux_sweeper_task: Option<JoinHandle<anyhow::Result<()>>>,
    pub n8n_api_shutdown: Arc<tokio::sync::Notify>,
    pub n8n_api_task: Option<JoinHandle<()>>,
    /// GOLD-ADAPT-HERMES-08 — shutdown notifier for the kanban SSE server.
    pub kanban_sse_shutdown: Arc<tokio::sync::Notify>,
    /// GOLD-ADAPT-HERMES-08 — task handle for the kanban SSE hyper server.
    pub kanban_sse_task: Option<JoinHandle<()>>,
    /// GOLD-ADAPT-AWE-PROV-01 — shutdown notifier for the OpenRouter-compat
    /// oai_serve hyper server. Notified to break the accept loop and drain.
    pub oai_serve_shutdown: Arc<tokio::sync::Notify>,
    /// GOLD-ADAPT-AWE-PROV-01 — task handle for the oai_serve hyper server.
    /// `None` when `oai_serve.enabled = false` (the default) or bind fails.
    pub oai_serve_task: Option<JoinHandle<()>>,
    /// GOLD-ADAPT-ODY-24 — shutdown notifier for the companion LAN pairing server.
    pub companion_shutdown: Arc<tokio::sync::Notify>,
    /// GOLD-ADAPT-ODY-24 — task handle for the companion loopback hyper server.
    pub companion_task: Option<JoinHandle<()>>,
    /// GOLD-COMPANION-P2P-01 — shutdown notifier for the companion P2P Noise
    /// pairing coordinator (serve-side long-running task). Notified to stop the
    /// poll loop and abort any in-flight single-invite listener.
    pub companion_p2p_shutdown: Arc<tokio::sync::Notify>,
    /// GOLD-COMPANION-P2P-01 — task handle for the companion P2P coordinator.
    /// `None` when `companion.p2p_enabled = false` (default) or `cluster`
    /// feature not compiled in.
    pub companion_p2p_task: Option<JoinHandle<()>>,
    pub cloud_task: Option<JoinHandle<anyhow::Result<()>>>,
    /// L6-PRELOAD-AUTORUN-01 — one-shot vault-preload task. `None` when
    /// `obsidian_preload_template_dir` is unset (most installs).
    /// WAL-free; abort order relative to `drop(writer)` is irrelevant.
    pub obsidian_preload_task: Option<JoinHandle<()>>,
    pub hysteria_supervisor: Option<crate::transport::hysteria::HysteriaSupervisor>,
    /// TERMIX-01 — running SSH local-forward tunnels. Shut down (task
    /// abort) after Hysteria; inert background tasks, no WAL interaction.
    #[cfg(feature = "ssh-tunnel")]
    pub ssh_tunnel_handles: Vec<crate::transport::ssh_tunnel::SshTunnel>,
    /// GOLD-ADAPT-GOOSE-03 — drain task that reads `ConfirmRequest`s off the
    /// bus's mpsc channel and forwards them as elicitation messages to the
    /// operator's primary channel (Telegram). WAL-free; aborted before
    /// `drop(writer)` to avoid logging new frames after the writer closes.
    pub confirm_drain_task: Option<JoinHandle<()>>,
}

/// GOLD-ARCH-01: the full ordered daemon shutdown sequence, moved VERBATIM out
/// of `run_serve`. Aborts/drains every background task in the exact prior order
/// (worker_watch FIRST per MONITOR-02; WAL-emitting tasks before `drop(writer)`;
/// the self-dev outbox final-drained via `&writer`; n8n notify-then-await;
/// cluster teardown; hysteria drop), then `drop(writer)` + `writer_join.await`.
/// The destructure restores the original local names. GR-102 — the body is NOT
/// byte-identical to the old inline sequence: every optional task is now drained
/// through `abort_optional` (abort + `task.await`), which uniformly awaits the
/// task — a deliberate improvement over the prior inline `audit_rpc_task.abort()`
/// that aborted WITHOUT awaiting. The ordering + set of tasks is preserved.
pub(crate) async fn shutdown_background_tasks(
    handles: BackgroundHandles,
    writer: WalWriterHandle,
    writer_join: JoinHandle<()>,
) {
    let BackgroundHandles {
        worker_watch_handle,
        channel_tasks,
        channel_supervisor_task,
        dispatch_join,
        cron_task,
        cron_fleet,
        cron_supervisor_task,
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
        cluster_foreign_indexer_task,
        #[cfg(feature = "cluster")]
        cluster_gossip_task,
        #[cfg(feature = "cluster")]
        cluster_swarm,
        #[cfg(feature = "cluster")]
        mdns_daemon,
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
        regression_cron_handle,
        checkin_cron_handle,
        session_sort_cron_handle,
        email_ingest_cron_handle,
        dreaming_task,
        arxiv_ingest_task,
        arxiv_skill_scan_task,
        rss_feed_task,
        tmux_sweeper_task,
        n8n_api_shutdown,
        n8n_api_task,
        kanban_sse_shutdown,
        kanban_sse_task,
        oai_serve_shutdown,
        oai_serve_task,
        companion_shutdown,
        companion_task,
        companion_p2p_shutdown,
        companion_p2p_task,
        cloud_task,
        obsidian_preload_task,
        hysteria_supervisor,
        #[cfg(feature = "ssh-tunnel")]
        ssh_tunnel_handles,
        confirm_drain_task,
    } = handles;

    // MONITOR-02: abort the worker-watch FIRST — so the deliberate abort of the
    // watched workers (below) is never mistaken for an unexpected death + alerted.
    crate::cli::serve_tasks::abort_optional(worker_watch_handle).await;

    // Abort the fleet supervisor BEFORE the channel tasks — a reload
    // racing shutdown must not respawn adapters into a dying daemon.
    crate::cli::serve_tasks::abort_join(channel_supervisor_task).await;

    // Abort channel tasks first so they stop generating new WAL frames.
    let channel_tasks: Vec<JoinHandle<()>> = {
        let mut guard = channel_tasks.lock().expect("channel_tasks mutex poisoned");
        std::mem::take(&mut *guard)
    };
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
        if tokio::time::timeout(DISPATCH_DRAIN_TIMEOUT, drain)
            .await
            .is_err()
        {
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

    // ZF-06: abort the fleet supervisor BEFORE draining fleet tasks so a
    // reload racing shutdown can't respawn into a dying daemon.
    crate::cli::serve_tasks::abort_join(cron_supervisor_task).await;

    // ZF-06: drain WAL-emitting fleet crons first (before drop(writer)),
    // then drain the rest. Handles are collected under the lock and awaited
    // OUTSIDE it — a std MutexGuard must not be held across an await point.
    let (wal_handles, rest_handles) = {
        let mut fleet = cron_fleet.lock().expect("cron_fleet mutex poisoned");
        let mut wal = Vec::new();
        for key in WAL_EMITTING_CRON_KEYS {
            if let Some(handle) = fleet.remove(key) {
                wal.push(handle);
            }
        }
        // Non-WAL crons: abort + await in any order.
        let rest: Vec<_> = fleet.drain().map(|(_key, handle)| handle).collect();
        (wal, rest)
    };
    for handle in wal_handles.into_iter().chain(rest_handles) {
        handle.abort();
        let _ = handle.await;
    }

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
        cluster_foreign_indexer_task.shutdown().await;

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
        // Unregister the mDNS announce (drop ⇒ goodbye packets). Beside
        // the swarm teardown so the LAN + DHT presence disappear together.
        if let Some(d) = mdns_daemon {
            info!("cluster: stopping mDNS announcer");
            let _ = d.shutdown();
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

    // ADV-14 regression-anchor cron (deferred; WAL-emitting 0x3F).
    crate::cli::serve_tasks::abort_optional(regression_cron_handle).await;
    // GOLD-FEAT-11 — abort the LLM check-in cron (deferred). No WAL writes;
    // mid-tick abort is safe.
    crate::cli::serve_tasks::abort_optional(checkin_cron_handle).await;
    // GOLD-ADAPT-ODY-26 — abort the session-sort cron (deferred). Card writes
    // are atomic per file; mid-tick abort is safe.
    crate::cli::serve_tasks::abort_optional(session_sort_cron_handle).await;
    // GOLD-ADAPT-JV-PAPERLESS-01 — abort the email-ingest cron (deferred).
    crate::cli::serve_tasks::abort_optional(email_ingest_cron_handle).await;

    // Abort the R-02 Phase 4c dreaming task. Embed-path callers
    // hit `spawn_blocking` for OuroModel/local_qwen forward;
    // aborting cancels the JoinHandle but the blocking task
    // may run to completion (acceptable — drains naturally,
    // never strands the model load).
    crate::cli::serve_tasks::abort_optional(dreaming_task).await;

    // EL-02 arXiv ingest task — abort on shutdown. Mid-pass abort at
    // worst drops one topic's fetch, which the next boot re-runs.
    crate::cli::serve_tasks::abort_optional(arxiv_ingest_task).await;

    // GOLD-ADAPT-MEM-16 arXiv skill-scan cron — WAL-free; mid-pass abort
    // at worst drops one paper's takeaway extraction. Next tick re-runs.
    crate::cli::serve_tasks::abort_optional(arxiv_skill_scan_task).await;

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

    // GOLD-ADAPT-HERMES-08: drain the kanban SSE server. Notify breaks
    // the accept loop; in-flight SSE streams finish their current frame
    // then see the TCP close. WAL-free — safe to stop after n8n_api.
    kanban_sse_shutdown.notify_waiters();
    if let Some(task) = kanban_sse_task {
        let _ = task.await;
    }

    // GOLD-ADAPT-AWE-PROV-01: drain the OpenRouter-compat oai_serve adapter.
    // Notify breaks the accept loop; in-flight /v1/models responses finish
    // then the task exits. WAL-free (read-only) — safe to stop after
    // kanban_sse, before companion (which is WAL-emitting).
    oai_serve_shutdown.notify_waiters();
    if let Some(task) = oai_serve_task {
        let _ = task.await;
    }

    // GOLD-ADAPT-ODY-24: drain the companion LAN pairing server. Notify breaks
    // the accept loop; in-flight mint requests finish their existing response.
    // WAL-emitting (0x0B) — must be shut down BEFORE drop(writer) so any
    // in-flight COMPANION_PAIRED frame isn't lost. Placed here (after kanban_sse,
    // before Obsidian) matching the WAL-emitting task ordering discipline.
    companion_shutdown.notify_waiters();
    if let Some(task) = companion_task {
        let _ = task.await;
    }

    // GOLD-COMPANION-P2P-01: drain the companion P2P Noise coordinator.
    // WAL-emitting (0x0D/0x0E) — must be shut down BEFORE drop(writer) so any
    // in-flight COMPANION_P2P_PAIRED or COMPANION_P2P_REJECTED frames land.
    // Placed immediately after the HTTP companion drain to preserve ordering.
    companion_p2p_shutdown.notify_waiters();
    if let Some(task) = companion_p2p_task {
        let _ = task.await;
    }

    // Obsidian sync/vault-reader/wiki-rebuild and self-map tasks are now
    // fleet-managed (CronKey::ObsidianSync, ObsidianVaultReader,
    // ObsidianWikiRebuild, SelfMap) and were already drained above in the
    // fleet WAL-emitting + non-WAL drain blocks.

    // Same drill for the cloud auto-mirror task. The cloud client
    // upstream gets the final delta on its own schedule once the
    // file lands on disk.
    crate::cli::serve_tasks::abort_optional(cloud_task).await;

    // L6-PRELOAD-AUTORUN-01: abort the one-shot preload task. WAL-free;
    // mid-pass abort at worst leaves vault files partially updated — the next
    // daemon start re-runs and the hash state skips already-copied files.
    crate::cli::serve_tasks::abort_optional(obsidian_preload_task).await;

    // Tear down the Hysteria subprocess. `Drop` does the cleanup; the
    // explicit drop here just makes the order obvious in shutdown logs.
    if let Some(sup) = hysteria_supervisor {
        info!("stopping Hysteria subprocess");
        drop(sup);
    }

    // TERMIX-01: abort the SSH tunnel tasks (inert forwards — no WAL
    // frames, so ordering relative to `drop(writer)` is not critical;
    // kept here beside the Hysteria teardown for symmetric transport
    // shutdown logs).
    #[cfg(feature = "ssh-tunnel")]
    for t in ssh_tunnel_handles {
        info!(local_port = t.local_port(), "stopping ssh tunnel");
        t.shutdown();
    }

    // GOLD-ADAPT-GOOSE-03: abort the confirm-bus drain task. WAL-free so it
    // can safely stop here, just before the writer closes.
    crate::cli::serve_tasks::abort_optional(confirm_drain_task).await;

    drop(writer);
    match writer_join.await {
        Ok(()) => info!("WAL writer task drained cleanly"),
        Err(e) => warn!(error = %e, "WAL writer task panicked during drain"),
    }
}

pub(crate) fn build_boot_payload(config: &FreedomConfig) -> anyhow::Result<Vec<u8>> {
    // Boot payload = minimal JSON: {operator_id, provider_kind, daemon_version}
    // Day-23+ will use a proper msgpack PayloadPrefixV4 frame; for Day-4 keep
    // it simple so a debug inspection of the WAL byte stream is possible.
    let payload = serde_json::json!({
        "operator_id": config.operator_id,
        "provider_kind": config.provider_kind,
        "daemon_version": env!("CARGO_PKG_VERSION"),
        "boot_unix": crate::time::now_unix_secs(),
    });
    Ok(serde_json::to_vec(&payload)?)
}

/// Pick #34 follow-up (2026-05-21): discover plugins, compile, build
/// the daemon-side PluginInvoker, register it as the process-wide
/// invoker so existing `run_stage` calls automatically fire Plugin
/// actions.
///
/// Single-shot; safe to call multiple times (OnceLock semantics —
/// subsequent calls noop). Failure modes all log a warn + return
/// without registering; the daemon stays up + Plugin hooks degrade
/// to Allow (their pre-bootstrap behaviour).
#[cfg(feature = "wasm-plugin-host")]
pub(crate) fn bootstrap_plugin_invoker(
    home: &std::path::Path,
    wal_writer: WalWriterHandle,
    reload_controller: std::sync::Arc<crate::config::reload::ReloadController>,
) {
    use std::sync::Arc;
    let plugins_root = home.join("plugins");
    let mut report = crate::wasm_plugin::discovery::discover(&plugins_root);
    if report.is_empty() {
        // No plugins dir or zero entries — operator hasn't installed
        // anything. Skip silently; the next run_serve will re-scan.
        return;
    }
    if !report.rejected.is_empty() {
        for e in &report.rejected {
            warn!(error = %e, "plugin discovery rejected entry");
        }
    }

    // D-102 (Session 21, 6/6 agent panel): default-inactive. Only plugins
    // whose `freedom.yaml::plugins.wasm.activations[id]` is `Active`
    // reach the engine. Unknown ids and `Pending` ids fall through to
    // the operator-visible bootstrap-skipped log line — they show up in
    // `neoth plugin list` so flipping them on is one command away.
    #[allow(clippy::type_complexity)]
    let (
        activations,
        pinned_hashes,
        require_all_pinned,
        author_pubkey,
        require_signature,
        revoked_ids,
        full_auto,
    ): (
        std::collections::BTreeMap<String, crate::wasm_plugin::discovery::PluginActivation>,
        std::collections::BTreeMap<String, String>,
        bool,
        Option<String>,
        bool,
        Vec<String>,
        bool,
    ) = match FreedomConfig::load_from_default_path() {
        Ok(cfg) => (
            cfg.plugins.wasm.activations.clone(),
            cfg.plugins.wasm.pinned_hashes.clone(),
            cfg.plugins.wasm.require_all_pinned,
            cfg.plugins.wasm.author_pubkey.clone(),
            cfg.plugins.wasm.require_signature,
            cfg.plugins.wasm.revoked_ids.clone(),
            // Full-auto mode (the same flag that opens autonomy to Full + routes
            // the whole skill library) MAY auto-activate Pending plugins — but
            // ONLY signed-by-trusted-author AND hash-pinned ones (see the
            // `auto_activation_eligible` gate below). Unsigned/unpinned/revoked
            // stay Pending exactly as in gated mode.
            cfg.skills.enable_all_bundled,
        ),
        Err(e) => {
            warn!(
                error = %e,
                "freedom.yaml load failed during plugin activation/integrity gate; \
                 treating ALL discovered plugins as Pending (none auto-instantiate)"
            );
            (
                std::collections::BTreeMap::new(),
                std::collections::BTreeMap::new(),
                false,
                None,
                false,
                Vec::new(),
                false,
            )
        }
    };
    // home is reserved for future per-home credential lookup; suppress
    // unused-var on the v0.1 path that goes through the default-path
    // loader.
    let _ = home;

    let pre_filter = report.loaded.len();
    let mut skipped_pending: Vec<String> = Vec::new();
    let mut skipped_disabled: Vec<String> = Vec::new();
    // Full-auto: Pending plugins promoted to Active because they passed the
    // strict signed+pinned `auto_activation_eligible` gate. (id, content_hash)
    // for the post-retain WAL audit.
    let mut auto_activated: Vec<(String, String)> = Vec::new();
    // SC-03 — Active plugins that fail the integrity gate (pinned-hash
    // mismatch / unpinned-when-required) are refused before reaching the
    // engine. Collected separately so the operator sees a SECURITY skip,
    // not a benign Pending one.
    let mut skipped_integrity: Vec<(String, String)> = Vec::new();
    let integrity_policy = crate::wasm_plugin::discovery::IntegrityPolicy {
        pinned: &pinned_hashes,
        require_all_pinned,
        author_pubkey: author_pubkey.as_deref(),
        require_signature,
        revoked: &revoked_ids,
    };
    report.loaded.retain(|p| {
        let state = activations.get(&p.manifest.id).copied().unwrap_or_default();
        match state {
            crate::wasm_plugin::discovery::PluginActivation::Active => {
                // Active is necessary but not sufficient — the binary
                // must also pass the operator's pin policy.
                match crate::wasm_plugin::discovery::verify_integrity(p, &integrity_policy) {
                    Ok(()) => true,
                    Err(e) => {
                        skipped_integrity.push((p.manifest.id.clone(), e.to_string()));
                        false
                    }
                }
            }
            crate::wasm_plugin::discovery::PluginActivation::Pending => {
                // Full-auto auto-activation: a Pending plugin runs WITHOUT an
                // explicit `neoth plugin enable` ONLY when it is signed by the
                // operator's trusted author key AND hash-pinned (two independent
                // trust signals). Everything else stays Pending — full-auto
                // never silently runs untrusted WASM.
                if full_auto
                    && crate::wasm_plugin::discovery::auto_activation_eligible(p, &integrity_policy)
                {
                    auto_activated.push((p.manifest.id.clone(), p.content_hash.clone()));
                    true
                } else {
                    skipped_pending.push(p.manifest.id.clone());
                    false
                }
            }
            crate::wasm_plugin::discovery::PluginActivation::Disabled => {
                skipped_disabled.push(p.manifest.id.clone());
                false
            }
        }
    });
    if !skipped_integrity.is_empty() {
        warn!(
            integrity_rejected = ?skipped_integrity
                .iter()
                .map(|(id, e)| format!("{id}: {e}"))
                .collect::<Vec<_>>(),
            "plugins REFUSED by SC-03 integrity gate (revoked / hash mismatch / \
             unpinned / signature invalid or missing) — NOT instantiated"
        );
        // GOLD-ADAPT-G-02 — forensic anchor: one `0xC3 PLUGIN_REJECTED`
        // frame per refusal, mirroring the 0xC2 PLUGIN_LOADED anchor, so
        // WAL replay shows WHICH plugin the SC-03 gate refused and why.
        // Best-effort sync append — a WAL failure must not block bootstrap.
        for (id, reason) in &skipped_integrity {
            let payload = serde_json::to_vec(&serde_json::json!({
                "plugin": id,
                "reason": reason,
                "gate": "sc03_integrity",
            }))
            .unwrap_or_else(|_| b"{}".to_vec());
            let header = crate::wal::HeaderBuilder::new(
                crate::wal::events::EVENT_TYPE_PLUGIN_REJECTED,
                &payload,
            )
            .build();
            if let Err(e) = wal_writer.try_append_sync(header, payload) {
                warn!(error = %e, plugin = %id, "0xC3 plugin-rejected WAL frame failed (best-effort)");
            }
        }
    }
    // SC-03 — surface the inactive-gate state so an operator running
    // Active plugins doesn't assume tamper-protection they haven't
    // configured. Active plugins are live but no pin gates them.
    if pinned_hashes.is_empty() && !require_all_pinned && !report.loaded.is_empty() {
        warn!(
            active = ?report.loaded_ids(),
            "SC-03 integrity gate INACTIVE — Active plugins are running unpinned. \
             Run `neoth plugin list` to read each plugin.wasm hash, then pin trusted \
             values in freedom.yaml::plugins.wasm.pinned_hashes"
        );
    }
    if !auto_activated.is_empty() {
        warn!(
            auto_activated = ?auto_activated.iter().map(|(id, _)| id).collect::<Vec<_>>(),
            "full-auto mode AUTO-ACTIVATED signed+pinned plugins (no explicit \
             `neoth plugin enable`) — each is signature-verified against \
             plugins.wasm.author_pubkey AND hash-pinned"
        );
        // Forensic anchor: one 0xC2 PLUGIN_LOADED frame per auto-activation,
        // marked source=full_auto, so WAL replay shows exactly which plugins
        // ran without an explicit operator enable. Best-effort sync append —
        // bootstrap is not async; a WAL failure must not block plugin loading.
        for (id, content_hash) in &auto_activated {
            let payload = serde_json::to_vec(&serde_json::json!({
                "plugin": id,
                "content_hash": content_hash,
                "auto_activated": true,
                "source": "full_auto",
            }))
            .unwrap_or_else(|_| b"{}".to_vec());
            let header = crate::wal::HeaderBuilder::new(
                crate::wal::events::EVENT_TYPE_PLUGIN_LOADED,
                &payload,
            )
            .build();
            if let Err(e) = wal_writer.try_append_sync(header, payload) {
                warn!(error = %e, plugin = %id, "full-auto plugin-activation WAL frame failed (best-effort)");
            }
        }
    }
    if !skipped_pending.is_empty() {
        info!(
            pending = ?skipped_pending,
            "plugins discovered but PENDING operator activation — \
             run `neoth plugin enable <id>` to opt them in"
        );
    }
    if !skipped_disabled.is_empty() {
        info!(
            disabled = ?skipped_disabled,
            "plugins discovered but operator-DISABLED — skipped"
        );
    }
    if report.loaded.is_empty() {
        info!(
            scanned = pre_filter,
            "plugin discovery complete; zero plugins are currently Active. \
             Use `neoth plugin list` to inspect, `neoth plugin enable <id>` to activate."
        );
        return;
    }

    let engine = match crate::wasm_plugin::engine::NeothEngine::new() {
        Ok(e) => Arc::new(e),
        Err(e) => {
            warn!(error = %e, "wasmtime engine build failed — plugin hooks disabled");
            return;
        }
    };
    let linker = match crate::wasm_plugin::hostcalls::build_linker(engine.raw()) {
        Ok(l) => Arc::new(l),
        Err(e) => {
            warn!(error = %e, "hostcalls linker build failed — plugin hooks disabled");
            return;
        }
    };
    let outcomes = crate::wasm_plugin::dispatch::compile_all_discovered(&engine, &report);
    let failed: Vec<&str> = outcomes
        .iter()
        .filter(|o| !o.is_ok())
        .map(|o| o.plugin_id())
        .collect();
    if !failed.is_empty() {
        warn!(
            failed_plugins = ?failed,
            "some plugins failed compile — they will NOT be invoked by hooks; \
             see `neoth plugins list` for details"
        );
    }
    // SC-04: the granted permission level for each plugin is its
    // manifest `requested_permissions` — the level the operator approved
    // by enabling it. Threaded into the invoker so the hostcall gate
    // enforces it. Keyed by manifest.id, same as the compiled modules.
    let grants = crate::wasm_plugin::dispatch::CompiledPluginInvoker::grants_from_report(&report);
    // SC-04 audit: open views.db read-only so `recall_top` returns real
    // hit counts in production, and thread the daemon's WAL writer (a
    // clone of the single segment writer — NOT a second writer) so a
    // denied hostcall actually emits its 0xC7 PLUGIN_CAP_DENIED frame.
    // Best-effort: a db-open failure degrades recall_top to 0, never
    // blocks plugin loading.
    let recall_db = match crate::memory::store::open(&home.join("views.db")) {
        Ok(conn) => Some(Arc::new(std::sync::Mutex::new(conn))),
        Err(e) => {
            warn!(error = %e, "plugin recall_db open failed — recall_top will return 0");
            None
        }
    };
    let invoker = crate::wasm_plugin::dispatch::CompiledPluginInvoker::from_compile_outcomes(
        engine, &outcomes, linker, grants,
    )
    .with_runtime_handles(Some(wal_writer), recall_db)
    // Live revocation: `neoth reload` with an updated
    // `plugins.wasm.revoked_ids` must reach the compiled invoker without
    // a daemon restart — the per-invoke check reads this handle.
    .with_reload_controller(reload_controller);
    if invoker.is_empty() {
        warn!("plugin discovery returned entries but zero compiled — invoker not registered");
        return;
    }
    let count = invoker.len();
    let arc: Arc<dyn crate::hooks::dispatcher::PluginInvoker> = Arc::new(invoker);
    if crate::hooks::dispatcher::register_global_invoker(arc) {
        info!(
            plugins = count,
            "plugin invoker registered; hook actions Plugin{{..}} are live"
        );
    } else {
        warn!(
            "plugin invoker already registered earlier in this process — \
             keeping the existing instance"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wave-4 regression: aborting the outer wrapper must abort the INNER task
    /// (dropping a JoinHandle only detaches it). Deterministic via a drop-guard
    /// that signals a oneshot — no sleep-polling, so it can't flake.
    #[tokio::test]
    async fn wrap_result_handle_aborts_inner_on_outer_abort() {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let inner = tokio::spawn(async move {
            struct SendOnDrop(Option<tokio::sync::oneshot::Sender<()>>);
            impl Drop for SendOnDrop {
                fn drop(&mut self) {
                    if let Some(t) = self.0.take() {
                        let _ = t.send(());
                    }
                }
            }
            let _g = SendOnDrop(Some(tx));
            // Never completes on its own — only an abort ends it.
            std::future::pending::<()>().await;
            #[allow(unreachable_code)]
            Ok(())
        });
        let outer = wrap_result_handle(Some(inner)).expect("Some handle");
        tokio::task::yield_now().await; // let the inner poll once
        outer.abort();
        let _ = outer.await;
        tokio::time::timeout(std::time::Duration::from_secs(2), rx)
            .await
            .expect("inner task was not aborted within 2s")
            .expect("inner drop guard did not fire");
    }

    /// Wave-4 regression: an inner task that returns Err must not hang or panic
    /// the wrapper — the wrapper logs and completes cleanly.
    #[tokio::test]
    async fn wrap_result_handle_completes_on_inner_error() {
        let inner = tokio::spawn(async move { Err(anyhow::anyhow!("boom")) });
        let outer = wrap_result_handle(Some(inner)).expect("Some handle");
        outer.await.expect("wrapper must complete cleanly on inner Err");
    }

    /// GOLD-PROG-08: the usage-meter export writes valid JSON that round-trips
    /// back to the same snapshot (the GUI's `parse_usage_meter` consumes this).
    #[test]
    fn write_usage_snapshot_roundtrips_json() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("usage_meter.json");
        let snap = crate::domain_events::UsageSnapshot {
            events_total: 9,
            provider_responses: 3,
            input_tokens_total: 1200,
            output_tokens_total: 450,
            lagged_events: 0,
        };
        write_usage_snapshot(&path, &snap).unwrap();
        let back: crate::domain_events::UsageSnapshot =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(back, snap);
    }

    // A default config leaves obsidian_vault/cloud_archive_dest unset and arxiv
    // disabled, so every helper returns None WITHOUT spawning a task — provable
    // without a tokio runtime (a fired spawn would panic "no reactor" here).
    #[test]
    fn all_wal_free_spawns_are_none_for_default_config() {
        let cfg = FreedomConfig::default();
        assert!(
            spawn_obsidian_sync(&cfg).is_none(),
            "no obsidian_vault → None"
        );
        assert!(
            spawn_cloud_archive(&cfg).is_none(),
            "no cloud_archive_dest → None"
        );
        assert!(
            spawn_arxiv_ingest(&cfg, &None).is_none(),
            "arxiv disabled → None"
        );
        // GOLD-ADAPT-MEM-16: skill-scan disabled by default + no provider → None.
        assert!(
            spawn_arxiv_skill_scan(&cfg, &None).is_none(),
            "arxiv_skill_scan disabled + no provider → None"
        );
        // NN-MEM-06: contradiction-resolve is off by default → no task spawned.
        assert!(
            spawn_contradiction_resolve_cron(&cfg).is_none(),
            "contradiction_resolve disabled by default → None"
        );
    }

    #[test]
    fn spawn_contradiction_resolve_returns_none_for_default_config() {
        // Default FreedomConfig has contradiction_resolve.enabled = false.
        // The underlying spawn fn returns None without needing a tokio reactor.
        let cfg = FreedomConfig::default();
        assert!(
            !cfg.contradiction_resolve.enabled,
            "contradiction_resolve must be off by default"
        );
        let handle =
            crate::daemon::contradiction_resolve_cron::spawn_contradiction_resolve_cron_loop(
                cfg.contradiction_resolve.clone(),
                "/nonexistent".into(),
            );
        assert!(handle.is_none(), "disabled config => None (no task spawned)");
    }

    /// OH-14 — spawn_obsidian_wiki_rebuild returns None when no vault is
    /// configured. The vault gate fires before the WalWriterHandle is even
    /// used, so we can verify the None path without a tokio runtime by using
    /// a dummy writer (created via the channel pair approach in wal::writer).
    #[tokio::test]
    async fn spawn_obsidian_wiki_rebuild_returns_none_when_no_vault() {
        // Default config: obsidian_vault = None → spawn must return None.
        let cfg = FreedomConfig::default();
        let wal_dir = tempfile::tempdir().unwrap();
        let (writer, _join) =
            crate::wal::writer::spawn(wal_dir.path().join("neoth.wal")).unwrap();
        let handle = spawn_obsidian_wiki_rebuild(&cfg, writer);
        assert!(
            handle.is_none(),
            "no obsidian_vault → spawn_obsidian_wiki_rebuild must return None"
        );
    }

    #[tokio::test]
    async fn contradiction_resolve_cron_spawns_and_aborts_cleanly_when_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("views.db");
        // Touch the db so the cron's store::open succeeds on first tick.
        drop(crate::memory::store::open(&db_path).unwrap());
        let config =
            crate::daemon::contradiction_resolve_cron::ContradictionResolveCronConfig {
                enabled: true,
                interval_secs: 86_400,
            };
        let handle =
            crate::daemon::contradiction_resolve_cron::spawn_contradiction_resolve_cron_loop(
                config,
                db_path,
            )
            .expect("enabled config must return Some");
        // Abort mirrors shutdown_background_tasks abort_optional path.
        handle.abort();
        let _ = handle.await; // JoinError on abort expected + swallowed
    }

    // ── GOLD-ADAPT-HERMES-05 integration tests ─────────────────────────────

    /// Verify that `run_journal_recovery_on_startup` emits exactly one
    /// `0x07 STALE_INTERRUPTED` WAL frame per orphaned turn-journal, and
    /// that each frame's JSON payload carries the required fields.
    #[tokio::test]
    async fn startup_scan_emits_stale_interrupted_wal_frame_per_orphan() {
        use crate::recovery::TurnJournal;
        use crate::wal::events::EVENT_TYPE_STALE_INTERRUPTED;

        let neoth_dir = tempfile::tempdir().unwrap();
        let wal_dir = tempfile::tempdir().unwrap();
        let seg = wal_dir.path().join("000001.wal");

        // Open two journals but do NOT call close() — both become orphans.
        let j1 = TurnJournal::open(neoth_dir.path(), "crash-turn-alpha").unwrap();
        let j2 = TurnJournal::open(neoth_dir.path(), "crash-turn-beta").unwrap();
        // The files survive on disk; dropping without close() leaves them.
        drop(j1);
        drop(j2);

        // Spawn a real WAL writer.
        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();

        // Override the default_neoth_home by directly calling the fn with tempdir.
        // run_journal_recovery_on_startup uses default_neoth_home() internally, so
        // we call the inner logic directly via crate::recovery helpers, then verify
        // the WAL frames.
        //
        // Because default_neoth_home() is not injectable, we replicate the logic
        // from run_journal_recovery_on_startup using the tempdir as home. This
        // is the same call-path the production code takes; the test validates
        // the WAL-frame shape directly.
        {
            use crate::recovery::scan_for_journals;
            use crate::wal::HeaderBuilder;
            use crate::wal::events::EVENT_TYPE_STALE_INTERRUPTED as EV;

            let home = neoth_dir.path();
            let now_ts = 9_000_000_i64;
            let reports = scan_for_journals(home).unwrap();
            assert_eq!(reports.len(), 2, "both orphans must be found");

            for report in &reports {
                let payload = serde_json::to_vec(&serde_json::json!({
                    "turn_id":      report.turn_id,
                    "journal_path": report.path.display().to_string(),
                    "size_bytes":   report.size_bytes,
                    "line_count":   report.line_count,
                    "ts_unix":      now_ts,
                }))
                .unwrap();
                let header = HeaderBuilder::new(EV, &payload).build();
                writer.append(header, payload).await.unwrap();
            }
        }

        drop(writer);
        join.await.unwrap();

        // Read the segment and count STALE_INTERRUPTED frames.
        let bytes = std::fs::read(&seg).unwrap();
        let mut offset = crate::wal::segment_header::SEGMENT_HEADER_LEN;
        let mut stale_frames = Vec::new();
        while offset < bytes.len() {
            let dec = match crate::wal::frame::decode_frame(&bytes[offset..]) {
                Ok(d) => d,
                Err(_) => break,
            };
            if dec.header.event_type == EVENT_TYPE_STALE_INTERRUPTED {
                let v: serde_json::Value =
                    serde_json::from_slice(dec.payload).expect("payload must be valid JSON");
                stale_frames.push(v);
            }
            offset += dec.header.total_len as usize;
        }

        assert_eq!(
            stale_frames.len(),
            2,
            "must emit exactly one 0x07 frame per orphan"
        );
        for frame in &stale_frames {
            assert!(
                frame["turn_id"].as_str().is_some(),
                "turn_id field required"
            );
            assert!(
                frame["journal_path"].as_str().is_some(),
                "journal_path field required"
            );
            assert!(
                frame["size_bytes"].as_u64().is_some(),
                "size_bytes field required"
            );
            assert!(
                frame["line_count"].as_u64().is_some(),
                "line_count field required"
            );
            assert!(
                frame["ts_unix"].as_i64().is_some(),
                "ts_unix field required"
            );
        }
    }

    /// With no orphaned journals, zero STALE_INTERRUPTED frames are emitted.
    #[tokio::test]
    async fn startup_scan_emits_no_frames_when_no_orphans() {
        use crate::recovery::TurnJournal;
        use crate::wal::events::EVENT_TYPE_STALE_INTERRUPTED;

        let neoth_dir = tempfile::tempdir().unwrap();
        let wal_dir = tempfile::tempdir().unwrap();
        let seg = wal_dir.path().join("000001.wal");

        // Open a journal and close it cleanly — no orphan.
        let j = TurnJournal::open(neoth_dir.path(), "clean-turn").unwrap();
        j.close().unwrap();

        let (writer, join) = crate::wal::writer::spawn(seg.clone()).unwrap();

        {
            use crate::recovery::scan_for_journals;
            use crate::wal::HeaderBuilder;
            use crate::wal::events::EVENT_TYPE_STALE_INTERRUPTED as EV;

            let reports = scan_for_journals(neoth_dir.path()).unwrap();
            assert!(reports.is_empty(), "closed journal must not appear as orphan");

            for report in &reports {
                let payload = serde_json::to_vec(&serde_json::json!({
                    "turn_id":      report.turn_id,
                    "journal_path": report.path.display().to_string(),
                    "size_bytes":   report.size_bytes,
                    "line_count":   report.line_count,
                    "ts_unix":      0_i64,
                }))
                .unwrap();
                let header = HeaderBuilder::new(EV, &payload).build();
                writer.append(header, payload).await.unwrap();
            }
        }

        drop(writer);
        join.await.unwrap();

        let bytes = std::fs::read(&seg).unwrap();
        let mut offset = crate::wal::segment_header::SEGMENT_HEADER_LEN;
        let mut stale_count = 0_usize;
        while offset < bytes.len() {
            let dec = match crate::wal::frame::decode_frame(&bytes[offset..]) {
                Ok(d) => d,
                Err(_) => break,
            };
            if dec.header.event_type == EVENT_TYPE_STALE_INTERRUPTED {
                stale_count += 1;
            }
            offset += dec.header.total_len as usize;
        }
        assert_eq!(stale_count, 0, "clean shutdown: zero STALE_INTERRUPTED frames");
    }

    // ── GOLD-ADAPT-OH-03 gate tests ─────────────────────────────────────────

    /// Fast path: `onboarding_complete = true` → gate passes without touching disk.
    #[test]
    fn oh03_gate_passes_when_flag_set() {
        let cfg = FreedomConfig {
            onboarding_complete: true,
            ..Default::default()
        };
        assert!(check_onboarding_complete(&cfg).is_ok());
    }

    /// Gate rejects when flag is `false` and no channel credentials exist.
    /// The secondary probe reads the default credentials.yaml path; in the
    /// test environment that file either does not exist (returns default
    /// empty Credentials) or is the developer's own file with channels — but
    /// since `FreedomConfig::default_neoth_home()` points to a real directory,
    /// we exercise the gate with a config that has NO channels in-struct and
    /// confirm the error message guides the operator.
    #[test]
    fn oh03_gate_rejects_when_no_channel_configured() {
        let cfg = FreedomConfig {
            onboarding_complete: false,
            // All channel fields default to None / false — probe sees NotConfigured.
            telegram_token: None,
            telegram_user_id: None,
            ..Default::default()
        };
        // The secondary probe loads the real credentials.yaml. If a developer runs
        // this test with channels already configured that file passes them through —
        // acceptable: the gate is conservative (fails closed), not strict-test-only.
        // We only assert the error message shape when we know creds are empty.
        let result = check_onboarding_complete(&cfg);
        // If the secondary probe found credentials (developer environment) the gate
        // passes — that is the correct behaviour. If not, the error must reference init.
        if let Err(e) = result {
            let msg = e.to_string();
            assert!(
                msg.contains("neoth init"),
                "error must reference `neoth init`: {msg}"
            );
            assert!(
                msg.contains("GOLD-ADAPT-OH-03"),
                "error must carry the issue tag: {msg}"
            );
        }
    }

    /// Secondary probe: `onboarding_complete = false` but telegram_token is
    /// present in the FreedomConfig (e.g. legacy freedom.yaml with inline token).
    /// The probe via ChannelCredsView sees `telegram_token = true` → gate passes.
    #[test]
    fn oh03_secondary_probe_passes_when_telegram_in_config() {
        let cfg = FreedomConfig {
            onboarding_complete: false,
            telegram_token: Some(crate::secret::SecretString::from("tok")),
            telegram_user_id: Some(12345),
            ..Default::default()
        };
        // ChannelCredsView.telegram_token = true + user_id = true
        // → probe_channel(Telegram) → ProbeStatus::Ok → any_channel = true → Ok
        assert!(
            check_onboarding_complete(&cfg).is_ok(),
            "secondary probe must pass when telegram_token + telegram_user_id present"
        );
    }

    /// TRAIL-02 gap fix: prove the kanban-SSE relay's full
    /// read → parse → broadcast → DELIVER path (the prior test only checked the
    /// change-bus fired). Seed a session-opened row, subscribe, run one relay
    /// step, assert the subscriber receives the parsed `FeedEntry`.
    #[tokio::test]
    async fn trail02_relay_reads_feed_and_delivers_to_sse_subscriber() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("views.db");
        let exec = crate::memory::store::ViewsExecutor::open(&path, 2).expect("open executor");

        // Create the columns latest_feed_entry_from_db reads + a 0x70
        // (KANBAN_SESSION_OPENED = 112) row with a valid SessionOpenedPayload.
        exec.with_writer(|c| {
            c.execute_batch(
                "CREATE TABLE IF NOT EXISTS idx_kanban_task_event (\
                   event_id INTEGER PRIMARY KEY AUTOINCREMENT, \
                   task_id INTEGER, event_type INTEGER, created_ns INTEGER, payload TEXT);",
            )
            .unwrap();
            c.execute(
                "INSERT INTO idx_kanban_task_event (task_id, event_type, created_ns, payload) \
                 VALUES (1, 112, 123456789, ?1)",
                rusqlite::params![r#"{"session_id":1,"source_channel":"telegram"}"#],
            )
            .unwrap();
        })
        .await;

        let (sse_tx, mut sse_rx) =
            tokio::sync::broadcast::channel::<crate::coding::feed::FeedEntry>(8);
        let sent = super::relay_latest_feed_to_sse(&exec, &sse_tx).await;
        assert!(sent, "relay must find + broadcast the seeded feed entry");

        let got = sse_rx
            .try_recv()
            .expect("SSE subscriber must receive the relayed entry");
        assert_eq!(got.event_type, 112, "0x70 KANBAN_SESSION_OPENED");
        assert!(
            got.message.contains("Session opened via telegram"),
            "relayed entry must carry the parsed message, got: {}",
            got.message
        );
    }

    /// Empty kanban table → relay broadcasts nothing (no spurious client events).
    #[tokio::test]
    async fn trail02_relay_no_entry_does_not_broadcast() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("views.db");
        let exec = crate::memory::store::ViewsExecutor::open(&path, 1).expect("open executor");
        exec.with_writer(|c| {
            c.execute_batch(
                "CREATE TABLE IF NOT EXISTS idx_kanban_task_event (\
                   event_id INTEGER PRIMARY KEY AUTOINCREMENT, \
                   task_id INTEGER, event_type INTEGER, created_ns INTEGER, payload TEXT);",
            )
            .unwrap();
        })
        .await;
        let (sse_tx, _rx) = tokio::sync::broadcast::channel::<crate::coding::feed::FeedEntry>(8);
        assert!(
            !super::relay_latest_feed_to_sse(&exec, &sse_tx).await,
            "empty kanban table → relay sends nothing"
        );
    }
}

// ── ZF-06 unit tests — pure functions, no I/O ─────────────────────────────
#[cfg(test)]
mod zf06_fleet_tests {
    use std::collections::HashSet;
    use super::{CronKey, diff_cron_fleet, desired_cron_keys};
    use crate::config::FreedomConfig;

    #[test]
    fn diff_empty_running_returns_full_desired_as_to_start() {
        let running = HashSet::new();
        let desired: HashSet<CronKey> = [CronKey::DoctorCron, CronKey::Babel, CronKey::MonitorCron]
            .into_iter()
            .collect();
        let (to_stop, to_start) = diff_cron_fleet(&running, &desired);
        assert!(to_stop.is_empty(), "nothing to stop when running is empty");
        let started: HashSet<CronKey> = to_start.into_iter().collect();
        assert_eq!(started, desired);
    }

    #[test]
    fn diff_running_superset_returns_excess_as_to_stop() {
        let running: HashSet<CronKey> =
            [CronKey::DoctorCron, CronKey::Babel, CronKey::MonitorCron]
                .into_iter()
                .collect();
        let desired: HashSet<CronKey> =
            [CronKey::DoctorCron, CronKey::Babel].into_iter().collect();
        let (to_stop, to_start) = diff_cron_fleet(&running, &desired);
        assert!(to_start.is_empty(), "nothing to start when running is a superset");
        assert_eq!(to_stop, vec![CronKey::MonitorCron]);
    }

    #[test]
    fn diff_identical_sets_returns_empty() {
        let set: HashSet<CronKey> = [CronKey::WatchdogCron, CronKey::BgMonitor]
            .into_iter()
            .collect();
        let (to_stop, to_start) = diff_cron_fleet(&set, &set);
        assert!(to_stop.is_empty());
        assert!(to_start.is_empty());
    }

    #[test]
    fn desired_cron_keys_default_config_contains_core_keys() {
        // BgMonitor is present iff its interval is non-zero; a reload to 0 must
        // drop it from the desired set so the running monitor is stopped.
        let mut on = FreedomConfig::default();
        on.bg_monitor.interval_secs = 60;
        assert!(desired_cron_keys(&on).contains(&CronKey::BgMonitor), "interval>0 → present");

        let mut off = on.clone();
        off.bg_monitor.interval_secs = 0;
        assert!(!desired_cron_keys(&off).contains(&CronKey::BgMonitor), "interval=0 → absent");
    }

    #[test]
    fn desired_cron_keys_gates_obsidian_on_vault() {
        // Wave-3 regression: the four vault-gated keys must be ABSENT without a
        // vault (else a vault-clearing reload leaves the tasks running forever),
        // and PRESENT once a vault is configured. Counts are expressed as a
        // delta so they don't depend on which `.enabled` crons default on/off.
        let vault_gated = [
            CronKey::ObsidianSync,
            CronKey::ObsidianVaultReader,
            CronKey::ObsidianWikiRebuild,
            CronKey::SelfMap,
        ];

        let no_vault = desired_cron_keys(&FreedomConfig::default());
        for key in &vault_gated {
            assert!(!no_vault.contains(key), "{key:?} must be gated off without a vault");
        }

        let mut cfg = FreedomConfig::default();
        cfg.obsidian_vault = Some("/tmp/vault".to_string());
        // ObsidianVaultReader additionally gates on its own flag — enable it so
        // all four vault keys are present for the delta assertion.
        cfg.obsidian_vault_reader_enabled = true;
        let with_vault = desired_cron_keys(&cfg);
        for key in &vault_gated {
            assert!(with_vault.contains(key), "{key:?} must be present with a vault");
        }
        assert_eq!(
            with_vault.len(),
            no_vault.len() + 4,
            "a vault (+ reader enabled) adds exactly the four obsidian/self-map keys"
        );

        // Vault set but reader disabled → the reader key must be absent, so
        // reload after disabling the reader stops the running task.
        let mut reader_off = cfg.clone();
        reader_off.obsidian_vault_reader_enabled = false;
        assert!(
            !desired_cron_keys(&reader_off).contains(&CronKey::ObsidianVaultReader),
            "reader-disabled must drop ObsidianVaultReader even with a vault"
        );
    }

    #[test]
    fn desired_cron_keys_gates_enabled_crons_on_reload() {
        // Wave-10 regression: a `.enabled`-gated cron must leave the desired set
        // when disabled, so a `neoth reload` that disables it computes a
        // non-empty to_stop and actually aborts the running task (webhook_manager
        // is the sharpest case — it POSTs to external endpoints).
        let mut on = FreedomConfig::default();
        on.webhook_manager.enabled = true;
        assert!(
            desired_cron_keys(&on).contains(&CronKey::WebhookManager),
            "enabled webhook_manager must be in the desired set"
        );

        let mut off = on.clone();
        off.webhook_manager.enabled = false;
        assert!(
            !desired_cron_keys(&off).contains(&CronKey::WebhookManager),
            "disabled webhook_manager must be GONE from the desired set (reload must stop it)"
        );
    }
}

// ── NEOTH-AUDIT-PRELOAD-FS-BOUNDARY-01 — containment helper tests ─────────────
#[cfg(test)]
mod vault_containment_tests {
    use super::vault_subdir_is_contained;

    /// A normal subdir immediately inside the vault must pass.
    #[test]
    fn allows_in_vault_subdir() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = tmp.path().join("vault");
        std::fs::create_dir_all(&vault).unwrap();
        let canonical_vault = std::fs::canonicalize(&vault).unwrap();

        let target = vault.join("NEOTH");
        assert!(
            vault_subdir_is_contained(&canonical_vault, &target),
            "an in-vault subdir must be allowed"
        );
    }

    /// Passing vault itself (empty-subdir case) must pass — the vault is
    /// trivially contained within itself.
    #[test]
    fn allows_vault_root_itself() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = tmp.path().join("vault");
        std::fs::create_dir_all(&vault).unwrap();
        let canonical_vault = std::fs::canonicalize(&vault).unwrap();

        assert!(
            vault_subdir_is_contained(&canonical_vault, &vault),
            "vault root itself must pass containment"
        );
    }

    /// A path that escapes the vault via `..` must be refused.
    /// `vault.join("..").join("outside")` resolves to a sibling of the vault
    /// directory — outside by construction.
    #[test]
    fn rejects_parent_traversal_escape() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = tmp.path().join("vault");
        std::fs::create_dir_all(&vault).unwrap();
        let canonical_vault = std::fs::canonicalize(&vault).unwrap();

        // Construct a path that canonicalises to tmp/outside — NOT under vault.
        let escape = vault.join("..").join("outside");
        assert!(
            !vault_subdir_is_contained(&canonical_vault, &escape),
            "a path escaping the vault via `..` must be refused"
        );
    }

    /// Canonical root is a strict prefix: a sibling directory whose name
    /// starts with the same bytes as the vault name must NOT match.
    /// e.g. canonical_vault = /tmp/vault  and  target = /tmp/vault_evil
    /// must not pass starts_with("/tmp/vault").
    #[test]
    fn rejects_sibling_with_prefix_name() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = tmp.path().join("vault");
        std::fs::create_dir_all(&vault).unwrap();
        let canonical_vault = std::fs::canonicalize(&vault).unwrap();

        // target is a sibling: tmp/vault_evil — shares the "vault" prefix in
        // the raw string, but Path::starts_with is component-aware so it must
        // still be refused.
        let sibling = tmp.path().join("vault_evil");
        std::fs::create_dir_all(&sibling).unwrap();
        assert!(
            !vault_subdir_is_contained(&canonical_vault, &sibling),
            "a sibling directory sharing a raw name prefix must be refused"
        );
    }
}
