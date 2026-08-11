//! `neoth serve` — daemon entry. Reads freedom.yaml, opens WAL, awaits shutdown.
//!
//! D-1..D-4 acceptance:
//!   - reads the selected freedom.yaml (`~/.neoth` by default) (D-2)
//!   - owns WAL/state below that config file's parent directory (D-3)
//!   - emits a BOOT event (event_type 0x10) on startup
//!   - blocks until SIGTERM / Ctrl+C, then drains and exits 0 (D-4)
//!
//! Day-5+ pipelines (channel adapters, LLM provider calls) plug into this
//! same task. For Day-4 the daemon is intentionally minimal: open WAL, write
//! BOOT, idle until shutdown.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Args;
use tracing::{debug, error, info, warn};

use crate::config::FreedomConfig;
use crate::memory::store;
use crate::providers::{self, Provider};
use crate::shutdown;
use crate::wal::EventFlags;
use crate::wal::events::{EVENT_TYPE_BOOT, EVENT_TYPE_ONBOARDING_COMPLETE_CONFIRMED};
use crate::wal::writer::WalWriterHandle;

// ── ZF-07 Boot-Stagger constants ──────────────────────────────────────────────
//
// At daemon boot the full cron fleet (≤ 28 tasks) whose schedules are
// already-due fire their first tick simultaneously — thundering herd on
// CPU, IO, and the provider API rate-limit.  A shared `Semaphore` with
// `START_STAGGER_PERMITS` permits bounds cold-start concurrency: each cron
// seed acquires one permit before spawning; the permit is released after
// `CRON_FIRST_TICK_WINDOW`, letting the next batch start.  Steady-state
// ticks (all subsequent interval firings) run completely unthrottled.

/// Maximum concurrent cron cold-starts during daemon boot (ZF-07 ceiling).
///
/// With 28 fleet crons at 4 permits the burst is ≤ 4-wide; the full fleet
/// seeds in ≈ 28/4 × 500 ms ≈ 3.5 s instead of an instantaneous spike.
const START_STAGGER_PERMITS: usize = 4;

/// How long a boot-stagger permit is held after a cron is spawned.
///
/// Conservative upper bound on a typical first-tick wall-time including any
/// cold-path provider latency.  Releasing too early would let a slow first
/// tick overlap with the next batch; releasing too late would delay seeding
/// unnecessarily.  500 ms covers the common cases without notable boot delay.
const CRON_FIRST_TICK_WINDOW: std::time::Duration = std::time::Duration::from_millis(500);

/// Reconcile liveness even when no config reload occurs.
///
/// A completed/panicked fleet child must not remain dead until the operator
/// happens to edit freedom.yaml.
const CRON_HEALTH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CronSupervisorWake {
    Reload,
    Health,
}

impl CronSupervisorWake {
    fn label(self) -> &'static str {
        match self {
            Self::Reload => "reload",
            Self::Health => "health",
        }
    }
}

async fn next_cron_supervisor_wake(
    generation: &mut tokio::sync::watch::Receiver<u64>,
    health: &mut tokio::time::Interval,
) -> Option<CronSupervisorWake> {
    tokio::select! {
        changed = generation.changed() => changed.ok().map(|()| CronSupervisorWake::Reload),
        _ = health.tick() => Some(CronSupervisorWake::Health),
    }
}

fn dream_needs_generation_restart(
    wake: CronSupervisorWake,
    is_running: bool,
    is_desired: bool,
) -> bool {
    wake == CronSupervisorWake::Reload && is_running && is_desired
}

/// A reload must rebuild the email-ingest ticker when its cadence changes.
/// Enabling a previously dormant supervisor also resets it so the first poll
/// happens immediately instead of waiting for the old/default interval.
fn email_ingest_schedule_change(
    was_enabled: bool,
    current_interval: std::time::Duration,
    live: &crate::config::EmailIngestCronConfig,
) -> Option<std::time::Duration> {
    let live_interval = live.interval_duration();
    (live_interval != current_interval || (!was_enabled && live.enabled)).then_some(live_interval)
}

// GOLD-ARCH-01: the channel-side inbound pipeline now lives in `serve_pipeline`.

#[derive(Args, Debug, Clone)]
pub struct ServeArgs {
    /// Override the path to freedom.yaml. Defaults to ~/.neoth/freedom.yaml.
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Override the WAL chain-base path. It must be the canonical sequence-1
    /// direct child (`000001.wal`) of the selected config home's `wal`
    /// directory. Defaults to `<config-home>/wal/000001.wal`.
    #[arg(long, value_name = "PATH")]
    pub wal_segment: Option<PathBuf>,

    /// Emit one BOOT frame, drain, exit. Used by integration tests; equivalent
    /// to a graceful shutdown immediately after the first frame is durable.
    #[arg(long, hide = true)]
    pub one_shot: bool,

    /// Override the clock-rollback guard. Use only when restoring from a
    /// backup or recovering from a VM snapshot rewind — operator promises
    /// the timestamps in the WAL are intentional. Phase 33c BS-5.
    #[arg(long)]
    pub allow_clock_rollback: bool,
}

pub async fn run_serve(args: ServeArgs) -> Result<()> {
    // Derive the instance home before every startup guard. A custom --config
    // owns its PID, clock floor, isolation boundary, WAL, DB, and sidecars;
    // process-global defaults must never leak into that instance.
    let config_path = args
        .config
        .clone()
        .unwrap_or_else(FreedomConfig::default_path);
    let neoth_home = config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    // ── 0/0a/0b. Pre-config startup guards (GOLD-ARCH-01: relocated to
    // serve_tasks). Home-dir isolation (BS-9) + clock-rollback guard (BS-5) +
    // single-instance PID lock (BS-12). `--one-shot` skips isolation + PID.
    // The PidGuard is bound HERE for the
    // daemon lifetime — its Drop releases the lock at run_serve fn-end.
    let mut pid_guard = crate::cli::serve_tasks::run_preflight_guards(
        &neoth_home,
        args.one_shot,
        args.allow_clock_rollback,
    )?;

    // ── 1. Load config ──────────────────────────────────────────────────────
    let credentials_path = neoth_home.join("credentials.yaml");
    // Load the complete secret contract before any runtime service is primed.
    // This keeps custom --config homes and the OS-keychain backend aligned with
    // the exact freedom.yaml generation later passed to channel, cluster, and
    // OMI workers. The pair loader also recovers any interrupted dual-file
    // publication before exposing either half.
    let runtime_config = crate::config::load_runtime_config_pair_from_path(&config_path)
        .with_context(|| {
            format!(
                "runtime config pair at {} cannot be loaded; repair freedom.yaml and its credential file/keychain before starting",
                config_path.display()
            )
        })?;
    let config = runtime_config.config;
    let creds = runtime_config.credentials;
    #[cfg(feature = "cluster")]
    if config.cluster.enabled
        && crate::cluster::identity::cluster_transport_activation(&config, &creds).is_none()
    {
        anyhow::bail!(
            "cluster.enabled is true, but the identity is incomplete; set both cluster.name in {} and cluster_passphrase in {}",
            config_path.display(),
            credentials_path.display()
        );
    }
    #[cfg(all(feature = "cluster", not(feature = "cluster-iroh")))]
    if config.cluster.enabled && config.cluster.transport == crate::config::ClusterTransport::Iroh {
        anyhow::bail!(
            "cluster.transport is `iroh`, but this binary was built without the `cluster-iroh` feature; install a native desktop release or switch the complete cluster config to `peeroxide`"
        );
    }
    // Hooks are operator policy. Validate and retain one known-good snapshot
    // before any provider, channel, cron, listener, or plugin task is started.
    // A malformed/unreadable configured hook must not degrade startup into an
    // empty policy set. A missing `hooks/` directory remains valid.
    let hook_dir = neoth_home.join("hooks");
    let startup_hooks = crate::hooks::load_all_strict(&hook_dir)
        .await
        .with_context(|| {
            format!(
                "operator hooks at {} are invalid; daemon startup refused",
                hook_dir.display()
            )
        })?;
    info!(
        operator = config.operator_id.as_deref().unwrap_or("(unset)"),
        provider = ?config.provider_kind,
        "loaded freedom.yaml"
    );

    // GOLD-ADAPT-OH-03: onboarding completion gate — bail before touching the WAL
    // if no channel/integration has been configured. Bypassed for --one-shot
    // (integration-test path that runs against ephemeral configs with no channels).
    // The secondary credential probe inside check_onboarding_complete handles old
    // freedom.yaml files that pre-date the `onboarding_complete` flag.
    if !args.one_shot {
        crate::cli::serve_tasks::check_onboarding_complete(&config, &creds)?;
    }

    // ── 2/2b/3/3b/BS-4. WAL setup (GOLD-ARCH-01: relocated to
    // serve_tasks::prepare_wal — dir prep + ADV-01 .cpt recovery scan + writer
    // spawn + deferred quarantine-audit frames + BS-4 quota guard). `writer_join`
    // is rebound `mut` because the idle-wait `select!` borrows `&mut writer_join`.
    let crate::cli::serve_tasks::WalSetup {
        wal_dir,
        segment_chain_base_path,
        segment_path,
        writer,
        mut writer_join,
    } = crate::cli::serve_tasks::prepare_wal(&neoth_home, args.wal_segment.clone()).await?;

    // GOLD-R3-18: a daemon may have died after durably admitting an updater
    // leaf but before recording its terminal result. Reconcile those exact
    // request bindings before BOOT or any runtime producer can append new
    // updater work. One-shot diagnostics must never race a live daemon's WAL.
    if !args.one_shot
        && let Err(error) = crate::updater::reconcile::reconcile_unfinished_updater_leaves(
            &neoth_home,
            &segment_chain_base_path,
            &writer,
            crate::updater::reconcile::UpdaterReconcilePhase::Startup,
        )
        .await
    {
        drop(writer);
        let _ = writer_join.await;
        return Err(error).context("reconcile interrupted updater leaves at daemon startup");
    }

    // ── 3b'. Hot-reload controller (construction only) ─────────────────────
    // Built HERE (before the plugin bootstrap) so the compiled plugin
    // invoker can hold a live-config handle for its per-invoke
    // revocation check. Construction is side-effect-free; the at-boot
    // sentinel one-shot + the polling task stay in step 5b below.
    let reload_controller = std::sync::Arc::new(crate::config::reload::ReloadController::new(
        config.clone(),
        config_path.clone(),
    ));

    // ── 3c. Plugin invoker bootstrap (SC-04) ───────────────────────────────
    // Deferred from step 1a so the invoker carries a clone of the live
    // WAL writer: a denied plugin hostcall must emit its 0xC7
    // PLUGIN_CAP_DENIED audit frame, and a used capability its 0xC4/0xC6
    // frame, into the SAME segment the daemon writes. Reusing the writer
    // handle (not spawning a second one) keeps the single-writer
    // invariant that the WAL segment depends on.
    #[cfg(feature = "wasm-plugin-host")]
    let plugin_invoker_registration = {
        if config.plugins.wasm.enabled {
            crate::cli::serve_tasks::bootstrap_plugin_invoker(
                &neoth_home,
                writer.clone(),
                reload_controller.clone(),
            )
        } else {
            info!(
                "freedom.yaml::plugins.wasm.enabled = false; skipping plugin discovery + invoker bootstrap"
            );
            None
        }
    };
    #[cfg(not(feature = "wasm-plugin-host"))]
    let plugin_invoker_registration: Option<
        crate::hooks::dispatcher::GlobalInvokerRegistration,
    > = None;

    // Resolve OnSessionStart after the optional plugin invoker exists, but
    // before any runtime service is primed. A Block is a real startup veto,
    // not a warning emitted after channels and cron have already started. The
    // decision is durably audited before it takes effect.
    let startup_hook_outcome = crate::hooks::run_stage(
        crate::hooks::HookStage::OnSessionStart,
        "session-start",
        &startup_hooks,
    )
    .context("evaluate on_session_start hooks before daemon side effects")?;
    match startup_hook_outcome {
        crate::hooks::StageOutcome::Continue { hits, .. } => {
            for name in hits {
                let payload = serde_json::to_vec(&serde_json::json!({
                    "name": &name,
                    "stage": "on_session_start",
                    "ts_unix": crate::time::now_unix_secs(),
                }))
                .context("serialize OnSessionStart HOOK_FIRED")?;
                let header = crate::wal::HeaderBuilder::new(
                    crate::wal::events::EVENT_TYPE_HOOK_FIRED,
                    &payload,
                )
                .build();
                writer
                    .append(header, payload)
                    .await
                    .with_context(|| format!("append OnSessionStart HOOK_FIRED for `{name}`"))?;
                info!(hook = %name, "on_session_start hook fired");
            }
        }
        crate::hooks::StageOutcome::Block { name, reason } => {
            let payload = serde_json::to_vec(&serde_json::json!({
                "name": &name,
                "stage": "on_session_start",
                "reason": &reason,
                "ts_unix": crate::time::now_unix_secs(),
            }))
            .context("serialize OnSessionStart HOOK_BLOCKED")?;
            let header = crate::wal::HeaderBuilder::new(
                crate::wal::events::EVENT_TYPE_HOOK_BLOCKED,
                &payload,
            )
            .build();
            writer
                .append(header, payload)
                .await
                .with_context(|| format!("append OnSessionStart HOOK_BLOCKED for `{name}`"))?;
            drop(plugin_invoker_registration);
            drop(writer);
            if let Err(join_error) = writer_join.await {
                warn!(
                    error = %join_error,
                    "WAL writer join failed while honoring OnSessionStart Block"
                );
            }
            anyhow::bail!("on_session_start hook `{name}` blocked daemon startup: {reason}");
        }
    }

    // E-2 Phase 4 (Session 14 Pick #23) — log a depth-cost warning at
    // boot when the operator's freedom.yaml has
    // `hemisphere_council_depth > 1`. Catches the operator who hand-
    // edited the config without going through the wizard's cost-warning
    // screen. Best-effort: pure stderr — never blocks the daemon.
    let council_depth = config.inference.hemisphere_council_depth.get();
    if council_depth > 1 {
        warn!(
            council_depth = council_depth,
            "{}",
            crate::cli::init::render_council_depth_cost_warning(council_depth),
        );
    }

    // ── 4. Emit BOOT event ─────────────────────────────────────────────────
    let boot_payload = crate::cli::serve_tasks::build_boot_payload(&config)?;
    let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_BOOT, &boot_payload)
        .flags(EventFlags::SYNTHETIC)
        .build();
    let offset = writer
        .append(header, boot_payload)
        .await
        .context("write BOOT WAL frame")?;
    info!(offset, "BOOT event written and fsynced");

    // Persist the boot-time wall-clock as the new clock floor. Cheap on
    // disk (one small write) — captures the "last alive moment" so the
    // next start can detect a rollback even if we crash mid-run.
    let now_ns = crate::time::now_unix_ns();
    // The floor is security-bearing persistent state: a daemon that cannot
    // update it must not continue writing an audit chain whose next startup
    // cannot detect rollback. The selected config's parent is authoritative.
    let clock_floor_path = neoth_home.join("clock.floor");
    crate::daemon::clock_floor::persist_floor(&clock_floor_path, now_ns).with_context(|| {
        format!(
            "persist instance clock floor at {}",
            clock_floor_path.display()
        )
    })?;

    // GOLD-ADAPT-OH-03 audit frame — best-effort, non-blocking. Emitted after
    // the BOOT frame so the WAL writer is live; the gate itself fires before WAL
    // is open (in run_serve) and cannot write. Skipped for --one-shot (gate was
    // already bypassed; no point auditing a non-daemon start).
    if !args.one_shot {
        let oh03_payload = serde_json::json!({
            "operator_id": config.operator_id.as_deref().unwrap_or(""),
            "onboarding_complete": config.onboarding_complete,
            // GOLD-ADAPT-OH-11: richer boot-audit snapshot — chat flag included
            // in the existing 0xFD frame (additive JSON; backward-compatible).
            "chat_onboarding_completed": config.chat_onboarding_completed,
            "ts_unix": now_ns / 1_000_000_000u64,
        })
        .to_string()
        .into_bytes();
        let oh03_header =
            crate::wal::HeaderBuilder::new(EVENT_TYPE_ONBOARDING_COMPLETE_CONFIRMED, &oh03_payload)
                .flags(EventFlags::SYNTHETIC)
                .build();
        if let Err(e) = writer.append(oh03_header, oh03_payload).await {
            warn!(error = %e, "OH-03 audit frame write failed (non-fatal)");
        }
    }

    if args.one_shot {
        info!("--one-shot: closing writer and exiting");
        drop(plugin_invoker_registration);
        drop(writer);
        writer_join
            .await
            .context("join one-shot WAL writer")?
            .map_err(anyhow::Error::msg)?;
        return Ok(());
    }

    // Publish the mandatory daemon-owned mutation-audit endpoint before any
    // recovery or registry consumer can observe installed Skills. Public
    // `/audit` and token routes still follow `audit_rpc.enabled`; `/health`,
    // Skill mutation auditing, and cluster authority remain internal runtime
    // contracts whenever this process owns the PID lock and WAL writer.
    #[cfg(feature = "cluster")]
    let cluster_live_sessions =
        std::sync::Arc::new(crate::cluster::membership::LiveSessionRegistry::new());
    #[cfg(feature = "cluster")]
    let membership_store = crate::cluster::membership::MembershipStore::open(&neoth_home)
        .context("open daemon membership authority")?;
    #[cfg(feature = "cluster")]
    let membership_controller = std::sync::Arc::new(
        crate::cluster::membership::MembershipController::with_audit_writer(
            membership_store,
            std::sync::Arc::clone(&cluster_live_sessions),
            writer.clone(),
        ),
    );
    #[cfg(feature = "cluster")]
    let startup_membership = std::sync::Arc::clone(&membership_controller);
    #[cfg(feature = "cluster")]
    tokio::task::spawn_blocking(move || {
        startup_membership.drain_outbox(crate::time::now_unix_i64())
    })
    .await
    .context("join membership outbox startup replay")?
    .context("replay membership outbox before carrier startup")?;
    // The listener is a required authority boundary even without cluster:
    // Skill mutations cannot safely bypass the daemon-owned WAL.
    let membership_listener_required = true;
    let daemon_pid_guard = pid_guard
        .as_mut()
        .context("normal daemon startup must retain its PID lock")?;
    #[cfg(feature = "cluster")]
    let (audit_rpc_task, mut audit_rpc_guard) = crate::cli::serve_tasks::spawn_audit_rpc(
        &config,
        &neoth_home,
        &writer,
        daemon_pid_guard,
        std::sync::Arc::clone(&membership_controller),
    )
    .await
    .context("start daemon membership/audit RPC")?;
    #[cfg(not(feature = "cluster"))]
    let (audit_rpc_task, mut audit_rpc_guard) =
        crate::cli::serve_tasks::spawn_audit_rpc(&config, &neoth_home, &writer, daemon_pid_guard)
            .await
            .context("start mandatory daemon audit RPC")?;

    // Recover consent authority before any runtime-service preflight constructs
    // a provider. A prepared or required-audit journal deliberately blocks
    // live use; placing recovery after priming would make restart recovery
    // self-blocking.
    match crate::cli::consent_outbox::recover_pending_with_writer(&neoth_home, &writer)
        .await
        .context("recover pending consent mutation before provider startup")?
    {
        crate::cli::consent_outbox::RecoveryOutcome::None => {}
        crate::cli::consent_outbox::RecoveryOutcome::Recovered {
            operation_id,
            phase,
            delivery,
        } => {
            if delivery.is_pending() {
                warn!(
                    %operation_id,
                    phase = phase.as_str(),
                    "consent mutation recovered but its audit remains queued"
                );
            } else {
                info!(
                    %operation_id,
                    phase = phase.as_str(),
                    "consent mutation recovered before provider startup"
                );
            }
        }
    }

    // Runtime-service priming follows the validated startup-hook, published
    // internal audit endpoint, and recovered consent boundary. The
    // SkillRegistry watcher remains bound for the daemon lifetime.
    let _skill_watcher = crate::cli::serve_tasks::prime_runtime_services(
        &config,
        &creds,
        &neoth_home,
        &writer,
        std::sync::Arc::clone(&reload_controller),
    )
    .await?;

    // ── 4b. Replay any stranded profile-outbox rows ───────────────────────
    //
    // Pick #12 (Session 14, ADR-002 Option A) — `profile::apply::apply_delta`
    // commits idx_profile rows in one SQLite transaction with a parallel
    // INSERT into `idx_profile_outbox`, then drains the outbox to the WAL
    // post-commit. A crash between tx.commit() and drain-finished leaves
    // outbox rows whose owning idx_profile rows already exist — the WAL
    // never recorded the corresponding PROFILE_DELTA / REINFORCED /
    // SUPERSEDED frames. Sweep them here before the indexer starts
    // tailing, so the indexer + recall queries see a consistent
    // SQLite ⇔ WAL pair.
    //
    // Fail closed: views.db and its durable outbox are authoritative state.
    // Continuing without either would expose a live channel fleet backed by
    // incomplete memory/profile state.
    //
    // Pick #38 (Session 14, Agent #4 design-consensus, Perf #11 fix):
    // hold the post-drain connection alive in an `Arc<tokio::sync::
    // Mutex<Connection>>` so the per-message profile pipeline at
    // line ~1700 can reuse it instead of re-opening views.db every
    // inbound. Each open hits the WAL pragma stack + integrity_check
    // (Pick #34 fix M) — ~10ms blocking overhead × every Telegram /
    // WhatsApp / Slack message at the channel's hot path.
    //
    let views_path = neoth_home.join("views.db");
    let shared_views_conn: Option<Arc<tokio::sync::Mutex<rusqlite::Connection>>> = {
        let mut conn = store::open(&views_path)
            .with_context(|| format!("open instance views database at {}", views_path.display()))?;
        let replayed = crate::profile::apply::drain_outbox_all(&mut conn, &writer)
            .await
            .context("replay durable profile outbox before starting runtime services")?;
        if replayed > 0 {
            info!(
                replayed,
                "profile.outbox: startup drain replayed stranded rows"
            );
        }
        Some(Arc::new(tokio::sync::Mutex::new(conn)))
    };

    // ── GOLD-ADAPT-TRAIL-04: multi-reader SQLite executor ─────────────────
    //
    // Opens 1 write + 4 read connections to views.db so concurrent inbound
    // channel messages can resolve identities via pool readers without
    // serialising behind the single write mutex. Under SQLite WAL mode,
    // N readers run concurrently with no lock contention against the writer.
    //
    // Opening the executor is part of the same fail-closed state boundary as
    // the shared connection above; all readers must target this instance DB.
    let views_executor: Option<std::sync::Arc<crate::memory::store::ViewsExecutor>> = {
        let exec = crate::memory::store::ViewsExecutor::open(&views_path, 4)
            .with_context(|| format!("open instance views executor at {}", views_path.display()))?;
        info!(
            readers = 4,
            "TRAIL-04: ViewsExecutor ready (writer:1 + readers:4)"
        );
        Some(exec)
    };

    // ── 5a. Spawn memory indexer (tail-the-WAL into SQLite views) ─────────
    //
    // Runs alongside the writer. Each iteration: replay_once(...) reads
    // any new WAL bytes and INSERTs them into `idx_episode` / `idx_provider`,
    // advancing the cursor in `wal_cursor`. With this running, `neoth recall`
    // in another terminal is always near-real-time without a pre-query pass.
    // ── 5b. Hot-reload controller + sentinel polling task ─────────────
    //
    // Pick #37 (Session 14, Agent #4 design-consensus): operator
    // edits freedom.yaml + runs `neoth reload` → CLI writes a
    // sentinel file at `<instance-home>/.reload-requested` → this daemon-
    // side task polls for the sentinel every 2s. On present:
    // re-read freedom.yaml, validate against immutable fields, swap
    // the ArcSwap atomically (or reject), emit a CONFIG_RELOADED /
    // CONFIG_RELOAD_REJECTED WAL audit frame, delete the sentinel.
    //
    // Pick #39 wired the controller into `PipelineHandlerDeps`, so
    // tunable config fields ARE re-read per inbound message
    // (serve_pipeline.rs `reload_controller.latest()`); the controller
    // itself is constructed in step 3b' above so the plugin invoker's
    // per-invoke revocation check can hold it.
    // At-boot one-shot: if a sentinel is already on disk (operator
    // ran `neoth reload` against a stopped daemon), process it now
    // before the indexer + handler-spawn use the controller.
    {
        let sentinel = neoth_home.join(crate::config::reload::RELOAD_SENTINEL_NAME);
        handle_reload_sentinel(&reload_controller, &sentinel, &writer).await;
    }
    // GOLD-ARCH-01: construction relocated to serve_tasks (same handle, same site).
    let reload_task =
        crate::cli::serve_tasks::spawn_reload_poller(&reload_controller, &writer, &neoth_home);

    // GOLD-ARCH-01: construction relocated to serve_tasks (same handle, same site).
    // GR-164: hand the indexer the WAL writer so a tamper-suspect segment emits
    // an auditable 0x5E alert frame instead of a warn-only silent skip.
    // MEMGRAPH-01 — build the embed provider once (when configured) so the
    // indexer tail auto-embeds newly-ingested episodes into the vector lane.
    let indexer_embed_provider = crate::providers::embed_provider_from_config(&config).await;
    // GOLD-ADAPT-TRAIL-02: create the views.db change-bus before spawning the
    // indexer so in-process consumers can subscribe before the first change fires.
    let (views_change_tx, views_change_rx) = crate::memory::change_bus::channel();
    let indexer_task = Some(crate::cli::serve_tasks::spawn_indexer(
        &neoth_home,
        &segment_path,
        Some(writer.clone()),
        indexer_embed_provider,
        Some(views_change_tx), // TRAIL-02: fires on every indexer pass with n>0
    )?);

    // ── 5a-kanban. Stale-kanban reapers — HO-02 + GOLD-TASK-04. Best-effort
    // startup sweep of sessions stranded in Planning (crash mid-decompose) and
    // task rows stranded in InProgress (crash mid-execute).
    crate::cli::serve_tasks::run_stale_kanban_reapers_on_startup(&neoth_home)?;

    // ── 5a-journal. GOLD-ADAPT-HERMES-05 startup journal recovery scan.
    // Walks the selected instance home's journals/ for orphaned .jsonl files left by a crash
    // mid-turn; emits one 0x07 STALE_INTERRUPTED WAL frame per orphan.
    // Also warns on LiveShrunk / LiveMissing .bak verdicts. Read-only;
    // never deletes journals. Scan or audit failures abort startup so evidence
    // cannot be silently omitted from the live WAL chain.
    crate::cli::serve_tasks::run_journal_recovery_on_startup(&neoth_home, &writer).await?;

    // ── 5a-creds. Startup credential-pattern audit (HO-06) ─────────────────
    //
    // Walks `<instance-home>/policy.yaml::startup_audit_scan_paths` for
    // `ghp_` / `sk-` / `AKIA` / Bearer shapes + (when
    // `forbid_inline_tokens_in_remotes`) `git remote -v` for inline
    // `user:token@host` URLs. Warn-only — never fails boot. Empty
    // scan-paths + flag-off → silent no-op.
    //
    // Policy parsing is fail-closed: a malformed operator policy must never be
    // replaced by defaults. Scanner execution remains advisory once the exact
    // policy has loaded successfully.
    let policy_path = neoth_home.join("policy.yaml");
    let policy = crate::policy::PolicyConfig::load_or_default(&policy_path)
        .with_context(|| format!("load instance policy at {}", policy_path.display()))?;
    if !policy.startup_audit_scan_paths.is_empty() || policy.forbid_inline_tokens_in_remotes {
        match crate::daemon::startup_credential_audit::run_credential_scan(
            &policy.startup_audit_scan_paths,
            policy.forbid_inline_tokens_in_remotes,
        ) {
            Ok(findings) if findings.is_empty() => {
                info!("startup credential audit: clean (0 findings)");
            }
            Ok(findings) => {
                warn!(
                    count = findings.len(),
                    "startup credential audit: {} finding(s); rotate or move to keychain",
                    findings.len()
                );
                for f in &findings {
                    warn!(
                        finding = %crate::daemon::startup_credential_audit::format_finding(f),
                        "credential pattern detected"
                    );
                }
            }
            Err(e) => {
                warn!(error = %e, "startup credential audit failed; non-fatal");
            }
        }
    }

    // ── 5a-hysteria. Hysteria encrypted egress (R-3) ───────────────────────
    //
    // MUST run BEFORE provider construction below. The providers'
    // reqwest::Client reads `NEOTH_HTTP_PROXY` at build time only — if
    // we spawned Hysteria after `providers::from_config`, the already-
    // built clients would talk to the world directly while later code
    // thinks they're proxied. The supervisor is dropped on shutdown
    // further down to kill the subprocess + clear the temp config.
    // Session 24 fix #3: when autonomy=Strict AND Hysteria IS
    // configured, treat encrypted egress as a hard requirement —
    // spawn / probe failure must bail the daemon, NOT silently fall
    // back to direct egress. Pre-fix the warn-and-continue path
    // exfiltrated provider traffic through the operator's clear
    // network exactly when they had explicitly set up Hysteria to
    // avoid that. Standard / Elevated / Full operators keep the
    // permissive "warn + direct egress" fallback (they implicitly
    // accept it by not picking Strict).
    let strict_egress = matches!(config.autonomy, crate::permissions::AutonomyLevel::Strict);
    let hysteria_supervisor: Option<crate::transport::hysteria::HysteriaSupervisor> = match config
        .hysteria
        .as_ref()
    {
        Some(hcfg) if !hcfg.server.is_empty() => {
            match crate::transport::hysteria::HysteriaSupervisor::spawn(hcfg) {
                Ok(mut sup) => {
                    let port = sup.socks_port;
                    // Give the subprocess a beat to bind.
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                    match crate::transport::hysteria::probe_socks_port(port).await {
                        Ok(()) => {
                            // R-3 Phase 3b helper — single source of truth
                            // for the SOCKS5 URL. Installs the process-proxy
                            // slot in providers::http_client (OnceLock, no
                            // env write). No provider client built yet (next
                            // block constructs them) so the install beats
                            // every reqwest::Client::builder call.
                            let proxy_url = sup.install_as_process_proxy();
                            info!(
                                proxy = %proxy_url,
                                "Hysteria SOCKS5 up; routing provider HTTP through it",
                            );
                            // Respawn-with-backoff watchdog: a crashed
                            // child must not silently drop egress to
                            // direct.
                            sup.start_watchdog();
                            Some(sup)
                        }
                        Err(e) if strict_egress => {
                            error!(
                                error = %e,
                                "Hysteria SOCKS5 probe failed under autonomy=strict; refusing to fall back to direct egress",
                            );
                            drop(sup);
                            anyhow::bail!(
                                "autonomy=strict requires encrypted egress but Hysteria SOCKS5 probe failed: {e}. \
                                 Fix the Hysteria config OR lower autonomy to standard/elevated/full to allow \
                                 direct-egress fallback."
                            );
                        }
                        Err(e) => {
                            warn!(
                                error = %e,
                                "Hysteria spawned but SOCKS5 probe failed; falling back to direct egress (autonomy != strict)",
                            );
                            drop(sup); // kills the subprocess
                            None
                        }
                    }
                }
                Err(e) if strict_egress => {
                    error!(
                        error = %e,
                        "Hysteria supervisor spawn failed under autonomy=strict; refusing to fall back to direct egress",
                    );
                    anyhow::bail!(
                        "autonomy=strict requires encrypted egress but Hysteria supervisor failed to spawn: {e}. \
                         Fix the Hysteria config OR lower autonomy to standard/elevated/full to allow \
                         direct-egress fallback."
                    );
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        "Hysteria supervisor spawn failed; continuing with direct egress (autonomy != strict)"
                    );
                    None
                }
            }
        }
        _ => None,
    };

    // ── 5a-ssh. SSH local-forward tunnels (TERMIX-01) ──────────────────────
    //
    // Spawned before provider construction for the same reason as
    // Hysteria: a provider endpoint pointed at `127.0.0.1:<local_port>`
    // must find the listener bound. `spawn_tunnel` returns once the
    // local port is bound; the SSH connect itself retries in the
    // background with exponential backoff. A configured tunnel set is an
    // explicit runtime contract: TOFU-store or listener setup failure aborts
    // startup, and dropping `handles` rolls back listeners already bound in
    // this block.
    #[cfg(feature = "ssh-tunnel")]
    let ssh_tunnel_handles: Vec<crate::transport::ssh_tunnel::SshTunnel> = {
        let mut handles = Vec::new();
        if !config.ssh_tunnels.is_empty() {
            let tofu_path = neoth_home.join("ssh_known_hosts.db");
            let tofu_path_for_error = tofu_path.clone();
            let store = tokio::task::spawn_blocking(move || {
                crate::transport::ssh_tofu::TofuStore::open(&tofu_path)
            })
            .await
            .context("SSH TOFU store initialization worker failed")?
            .with_context(|| format!("open SSH TOFU store at {}", tofu_path_for_error.display()))?;
            let tofu = Arc::new(tokio::sync::Mutex::new(store));
            for tcfg in &config.ssh_tunnels {
                let tunnel =
                    crate::transport::ssh_tunnel::spawn_tunnel(tcfg.clone(), Arc::clone(&tofu))
                        .await
                        .with_context(|| {
                            format!(
                                "bind SSH tunnel listener for {} -> {}:{}",
                                tcfg.endpoint.host_key(),
                                tcfg.remote_host,
                                tcfg.remote_port
                            )
                        })?;
                info!(
                    local_port = tunnel.local_port(),
                    host = %tcfg.endpoint.host_key(),
                    remote = %format!("{}:{}", tcfg.remote_host, tcfg.remote_port),
                    "ssh tunnel listener bound; connecting in background"
                );
                handles.push(tunnel);
            }
        }
        handles
    };
    #[cfg(not(feature = "ssh-tunnel"))]
    if !config.ssh_tunnels.is_empty() {
        warn!(
            configured = config.ssh_tunnels.len(),
            "credentials.yaml::ssh_tunnels is configured but this binary was built without \
             the `ssh-tunnel` feature — tunnels NOT started"
        );
    }

    // ── 5b. Provider — shared by channels + cron scheduler ─────────────────
    //
    // Built once so the scheduler can dispatch jobs even when no channel
    // is configured, and so two consumers don't pay the construction cost
    // twice. None if construction fails — channels + scheduler then skip
    // gracefully rather than crash the daemon.
    //
    // SPEC-03b: use `fallback_chain_from_config` (NOT bare `from_config`) so
    // channel-driven messages get the same 429 fallback chain the CLI does,
    // and so the consent gate runs on this construction path too. Empty
    // `fallback.chain` ⇒ the bare primary (zero overhead, no behaviour change).
    // Thread the live daemon WAL writer so a 429 failover on the unattended
    // channel/cron path emits a durable `0x25 PROVIDER_FALLBACK_ATTEMPTED`
    // audit frame (SPEC-03b trust claim — a prompt that "wanders" A→B must
    // be auditable). The writer (spawned ~line 272) serializes concurrent
    // channel turns, so per-hop frames stay correct under concurrency.
    let shared_provider: Option<Arc<dyn Provider>> =
        match providers::fallback_chain_from_config(&config, &neoth_home, Some(writer.clone()))
            .await
        {
            Ok(p) => {
                // GOLD-ADAPT-HARNESS-03: wrap with history-compaction middleware when enabled.
                // Daemon path threads the WAL writer so every compaction event is auditable.
                let arc: Arc<dyn Provider> = if config.tokens.history_compaction_enabled {
                    let utility = providers::from_config_for_utility_at(&config, &neoth_home)
                        .await
                        .ok();
                    providers::compactor::arc_from_config(
                        Arc::from(p),
                        utility,
                        providers::utility_model_for_config(&config),
                        &config.tokens,
                        Some(writer.clone()),
                    )
                } else {
                    Arc::from(p)
                };
                Some(arc)
            }
            Err(e) => {
                warn!(error = %e, "provider not available — channels + cron skipped");
                None
            }
        };

    // ── 5c-meter. Shared provider-call Meter (Q-3). One per daemon —
    // every channel pipeline records into the same rolling window so
    // `/metrics` aggregates across adapters.
    let provider_meter = crate::providers::meter::Meter::with_default_window();

    // ── 5c-ratelimit. Shared per-sender token-bucket (BS-11). Defaults to
    // 30 msg/min, burst 30. Every channel pipeline consults this before
    // touching the WAL so a runaway upstream cannot drown the daemon.
    let rate_limiter = crate::channels::shared_rate_limiter();

    // ── 5c. Spawn configured channel adapters ──────────────────────────────
    //
    // Each configured channel runs in its own tokio task. The pipeline
    // handler is an Arc-cloned closure that the channel calls per incoming
    // message: emit WAL CHANNEL_INGRESS → call provider → emit CHANNEL_EGRESS
    // → return reply for the channel to send.
    let mut channel_tasks: crate::cli::serve_tasks::ChannelFleet = std::collections::HashMap::new();
    // COR-34: shared JoinSet tracking the detached, DISPATCH_GATE-bounded Meta
    // webhook fan-out tasks. The WhatsApp listener spawns each dispatch into it
    // (via WebhookListenerConfig::dispatch_join); the shutdown sequence drains it
    // — with a bounded timeout, then abort — BEFORE drop(writer), so in-flight
    // pipeline turns flush their WAL frames deterministically instead of relying
    // on the dispatch task's accidental WalWriterHandle-clone refcount (which
    // could otherwise hang shutdown on a slow turn).
    let dispatch_join: std::sync::Arc<tokio::sync::Mutex<tokio::task::JoinSet<()>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(tokio::task::JoinSet::new()));
    // GOLD-ADAPT-GOOSE-03: construct the approval bus + drain task BEFORE
    // spawning channel adapters. The drain task reads ConfirmRequests and
    // forwards them as elicitation messages on the operator's primary channel
    // (Telegram, if configured). The bus Arc is threaded into every channel
    // handler so gates can switch to Channel confirm strategy.
    let (confirm_bus, mut confirm_rx) = crate::permissions::confirm_bus::ConfirmBus::new();
    // Late-read Telegram config + the effective credential backend per request.
    // This keeps confirmation delivery on the same hot-rotated token and user
    // binding as the reconciled Telegram adapter.
    let drain_reload_controller = std::sync::Arc::clone(&reload_controller);
    let drain_neoth_home = neoth_home.clone();
    let confirm_drain_task: Option<tokio::task::JoinHandle<()>> = Some(tokio::spawn(async move {
        let confirm_client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
        {
            Ok(client) => client,
            Err(error) => {
                tracing::error!(%error, "approval delivery client could not be constructed");
                return;
            }
        };
        while let Some(req) = confirm_rx.recv().await {
            let drain_config = drain_reload_controller.latest();
            let drain_credentials = crate::config::credentials::Credentials::load_effective(
                &drain_neoth_home.join("credentials.yaml"),
                drain_config.secrets_backend,
            );
            let drain_telegram_token = drain_config.telegram_token.clone().or_else(|| {
                drain_credentials
                    .as_ref()
                    .ok()
                    .and_then(|credentials| credentials.telegram_token.clone())
            });
            let drain_telegram_user_id = drain_config.telegram_user_id;
            // Format a human-readable elicitation message with the UUID
            // the operator must echo back as "yes <uuid>" or "no <uuid>".
            let msg = format!(
                "\u{26a0}\u{fe0f} NEOTH needs your approval\n\
                     Action: {}\n\
                     Reply: `yes {}` to allow or `no {}` to deny",
                req.description, req.uuid, req.uuid
            );
            // Best-effort: send via Telegram if credentials are present.
            if let (Some(token), Some(user_id)) = (&drain_telegram_token, drain_telegram_user_id) {
                let url = format!("https://api.telegram.org/bot{}/sendMessage", token.expose());
                // A failed or timed-out delivery leaves the permission gate
                // fail-closed, but is surfaced so the operator can diagnose it.
                if let Err(error) = confirm_client
                    .post(&url)
                    .json(&serde_json::json!({
                        "chat_id": user_id,
                        "text": msg,
                        "parse_mode": "Markdown"
                    }))
                    .send()
                    .await
                {
                    tracing::warn!(
                        uuid = %req.uuid,
                        %error,
                        "approval notification delivery failed"
                    );
                }
            } else if let Err(load_error) = drain_credentials {
                tracing::error!(
                    uuid = %req.uuid,
                    error = %load_error,
                    "approval delivery blocked: effective credential store is unreadable"
                );
            } else {
                // No Telegram configured — log so the operator can see
                // the pending approval in daemon logs.
                tracing::warn!(
                    uuid = %req.uuid,
                    description = %req.description,
                    "GOOSE-03: approval requested but no Telegram configured; \
                     reply via `neoth channel confirm {}`",
                    req.uuid
                );
            }
        }
    }));

    // GOLD-ARCH-01: the channel-adapter bootstrap (Telegram polling + Slack
    // socket-mode + WhatsApp Meta webhook listener) is relocated to serve_tasks.
    let confirm_bus = Some(confirm_bus);
    crate::cli::serve_tasks::spawn_channel_adapters(
        &config,
        &shared_provider,
        &writer,
        &provider_meter,
        &rate_limiter,
        &segment_path,
        &neoth_home,
        &shared_views_conn,
        &reload_controller,
        &dispatch_join,
        &creds,
        &mut channel_tasks,
        None,
        &confirm_bus,
        &views_executor, // GOLD-ADAPT-TRAIL-04: multi-reader executor
    );

    // ── 5b-bis. Credential-aware adapter fleet reconciler ─────────────────
    //
    // Channel credentials are immutable inside an adapter instance. Watch the
    // effective file/keychain values as well as freedom.yaml generations,
    // debounce atomic replacements, fingerprint each channel independently,
    // and restart only adapters whose inputs changed. Stop-before-start avoids
    // duplicate pollers and webhook port collisions. A corrupt credential store
    // is fail-closed: the old fleet is stopped instead of retaining stale keys.
    let initial_channel_fingerprints =
        crate::cli::serve_tasks::channel_credential_fingerprints(&config, &creds, &neoth_home);
    let channel_tasks = std::sync::Arc::new(std::sync::Mutex::new(channel_tasks));
    let channel_supervisor_task: tokio::task::JoinHandle<()> = {
        let mut gen_rx = reload_controller.subscribe_generation();
        let tasks = std::sync::Arc::clone(&channel_tasks);
        let shared_provider = shared_provider.clone();
        let writer = writer.clone();
        let provider_meter = provider_meter.clone();
        let rate_limiter = std::sync::Arc::clone(&rate_limiter);
        let segment_path = segment_path.clone();
        let channel_neoth_home = neoth_home.clone();
        let shared_views_conn = shared_views_conn.clone();
        let reload_controller = std::sync::Arc::clone(&reload_controller);
        let dispatch_join = std::sync::Arc::clone(&dispatch_join);
        let confirm_bus = confirm_bus.clone();
        let views_executor = views_executor.clone();
        tokio::spawn(async move {
            const CREDENTIAL_POLL: std::time::Duration = std::time::Duration::from_millis(750);
            const RELOAD_DEBOUNCE: std::time::Duration = std::time::Duration::from_millis(300);

            let credentials_path = channel_neoth_home.join("credentials.yaml");
            let mut tick = tokio::time::interval(CREDENTIAL_POLL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut known_fingerprints = initial_channel_fingerprints;
            let mut credentials_valid = true;
            let mut failed_channels = std::collections::HashSet::new();
            let mut channel_generations: std::collections::HashMap<
                crate::channels::ChannelKind,
                u64,
            > = crate::channels::registry::channel_ids()
                .map(|kind| (kind, 0))
                .collect();
            type PendingChannelReload = (
                std::time::Instant,
                std::collections::HashMap<crate::channels::ChannelKind, u64>,
                std::sync::Arc<FreedomConfig>,
                crate::config::credentials::Credentials,
                bool,
            );
            let mut pending: Option<PendingChannelReload> = None;

            loop {
                let explicit_retry = tokio::select! {
                    _ = tick.tick() => false,
                    changed = gen_rx.changed() => {
                        if changed.is_err() {
                            break;
                        }
                        let _ = gen_rx.borrow_and_update();
                        true
                    }
                };

                // A completed adapter is not healthy. Reap it once and leave it
                // stopped until its credential changes or an explicit reload
                // requests a retry; never create a hot failure/restart loop.
                let finished: Vec<crate::channels::ChannelKind> = {
                    let guard = tasks.lock().expect("channel_tasks mutex poisoned");
                    guard
                        .iter()
                        .filter(|(_, handles)| handles.iter().any(|handle| handle.is_finished()))
                        .map(|(kind, _)| *kind)
                        .collect()
                };
                for kind in finished {
                    let handles = tasks
                        .lock()
                        .expect("channel_tasks mutex poisoned")
                        .remove(&kind)
                        .unwrap_or_default();
                    for handle in &handles {
                        handle.abort();
                    }
                    for handle in handles {
                        let _ = handle.await;
                    }
                    failed_channels.insert(kind);
                    error!(
                        channel = kind.as_str(),
                        "channel adapter stopped unexpectedly; it remains unhealthy until credentials change or `neoth reload` retries it"
                    );
                }

                let fresh_config = reload_controller.latest();
                let fresh_creds = match crate::config::credentials::Credentials::load_effective(
                    &credentials_path,
                    fresh_config.secrets_backend,
                ) {
                    Ok(credentials) => credentials,
                    Err(load_error) => {
                        pending = None;
                        if credentials_valid {
                            let old: Vec<tokio::task::JoinHandle<()>> = {
                                let mut guard = tasks.lock().expect("channel_tasks mutex poisoned");
                                std::mem::take(&mut *guard)
                                    .into_values()
                                    .flatten()
                                    .collect()
                            };
                            for handle in &old {
                                handle.abort();
                            }
                            for handle in old {
                                let _ = handle.await;
                            }
                            failed_channels.extend(crate::channels::registry::channel_ids());
                            error!(
                                error = %load_error,
                                "effective credential store became unreadable; all channel adapters stopped fail-closed"
                            );
                        }
                        credentials_valid = false;
                        continue;
                    }
                };
                if shared_provider.is_some() {
                    let running: std::collections::HashSet<_> = tasks
                        .lock()
                        .expect("channel_tasks mutex poisoned")
                        .keys()
                        .copied()
                        .collect();
                    for kind in crate::channels::registry::channel_ids() {
                        if crate::cli::serve_tasks::channel_runtime_expected(
                            &fresh_config,
                            &fresh_creds,
                            kind,
                        ) && !running.contains(&kind)
                        {
                            failed_channels.insert(kind);
                        }
                    }
                }
                let fresh_fingerprints = crate::cli::serve_tasks::channel_credential_fingerprints(
                    &fresh_config,
                    &fresh_creds,
                    &channel_neoth_home,
                );
                let retry_latched = pending.as_ref().is_some_and(|(_, _, _, _, retry)| *retry);
                let retry_failed = (explicit_retry || retry_latched) && !failed_channels.is_empty();
                if credentials_valid && fresh_fingerprints == known_fingerprints && !retry_failed {
                    pending = None;
                    continue;
                }

                let same_candidate =
                    pending
                        .as_ref()
                        .is_some_and(|(_, fingerprints, _, _, retry)| {
                            *fingerprints == fresh_fingerprints && *retry == retry_failed
                        });
                if !same_candidate {
                    pending = Some((
                        std::time::Instant::now(),
                        fresh_fingerprints,
                        fresh_config,
                        fresh_creds,
                        retry_failed,
                    ));
                    continue;
                }
                if pending
                    .as_ref()
                    .is_some_and(|(since, _, _, _, _)| since.elapsed() < RELOAD_DEBOUNCE)
                {
                    continue;
                }
                let (_, new_fingerprints, fresh_config, fresh_creds, retry_failed) =
                    pending.take().expect("candidate checked above");
                let mut changed = if credentials_valid {
                    crate::cli::serve_tasks::changed_channel_credentials(
                        &known_fingerprints,
                        &new_fingerprints,
                    )
                } else {
                    crate::channels::registry::channel_ids().collect()
                };
                if retry_failed {
                    changed.extend(failed_channels.iter().copied());
                    changed.sort_unstable_by_key(|kind| kind.as_str());
                    changed.dedup();
                }

                for kind in changed {
                    let old = tasks
                        .lock()
                        .expect("channel_tasks mutex poisoned")
                        .remove(&kind)
                        .unwrap_or_default();
                    for handle in &old {
                        handle.abort();
                    }
                    for handle in old {
                        let _ = handle.await;
                    }

                    let mut replacement = crate::cli::serve_tasks::ChannelFleet::new();
                    crate::cli::serve_tasks::spawn_channel_adapters(
                        &fresh_config,
                        &shared_provider,
                        &writer,
                        &provider_meter,
                        &rate_limiter,
                        &segment_path,
                        &channel_neoth_home,
                        &shared_views_conn,
                        &reload_controller,
                        &dispatch_join,
                        &fresh_creds,
                        &mut replacement,
                        Some(kind),
                        &confirm_bus,
                        &views_executor,
                    );
                    let replacement = replacement.remove(&kind).unwrap_or_default();
                    let task_count = replacement.len();
                    if replacement.is_empty() {
                        if shared_provider.is_some()
                            && crate::cli::serve_tasks::channel_runtime_expected(
                                &fresh_config,
                                &fresh_creds,
                                kind,
                            )
                        {
                            failed_channels.insert(kind);
                            warn!(
                                channel = kind.as_str(),
                                "channel reconciliation produced no running adapter; runtime status remains unhealthy"
                            );
                        } else {
                            failed_channels.remove(&kind);
                            info!(
                                channel = kind.as_str(),
                                "channel reconciliation left adapter inactive by configuration"
                            );
                        }
                    } else {
                        tasks
                            .lock()
                            .expect("channel_tasks mutex poisoned")
                            .insert(kind, replacement);
                        failed_channels.remove(&kind);
                    }
                    let generation = channel_generations.entry(kind).or_default();
                    *generation = generation.saturating_add(1);
                    info!(
                        channel = kind.as_str(),
                        generation = *generation,
                        tasks = task_count,
                        "channel credential generation reconciled"
                    );
                }
                known_fingerprints = new_fingerprints;
                credentials_valid = true;
            }
        })
    };

    // ── 5b-tris / 5b-tris-a2 / 5b-tris-b / 5b-tris-c ─────────────────────
    // ObsidianSync, ObsidianVaultReader, ObsidianWikiRebuild, SelfMap are now
    // fleet-managed (ZF-06 CronFleet). Seeded by the cron supervisor below.

    // ── 5b-quad. Cloud archive auto-mirror (R-8) ───────────────────────────
    //
    // Off by default. When freedom.yaml::cloud_archive_dest is set,
    // periodically mirror the session archive into a subdir of that
    // folder. The operator's cloud vendor desktop client picks the
    // delta up + uploads.
    // GOLD-ARCH-01: construction relocated to serve_tasks (same handle, same site).
    let cloud_task = crate::cli::serve_tasks::spawn_cloud_archive(&config, &neoth_home);

    // ── L6-PRELOAD-AUTORUN-01 — one-shot Obsidian vault preload ────────────
    //
    // Fires once at serve startup when `obsidian_preload_template_dir` AND
    // `obsidian_vault` are both set in freedom.yaml.  Idempotent: unchanged
    // files are skipped via hash state kept in ~/.neoth/obsidian_preload_state_*.json.
    // Errors are logged (warn) but never crash the daemon.  WAL-free.
    // GOLD-ARCH-01: body in serve_tasks (same handle pattern as cloud_task).
    let obsidian_preload_task =
        crate::cli::serve_tasks::spawn_obsidian_preload(&config, &neoth_home, writer.clone());

    // ADR-003 Dream calendar runtime is fleet-managed below. It is seeded from
    // the accepted generation and restarted on schedule/effect-policy reloads.

    // ── 5b-arxiv. EL-02 arXiv topic-feed ingest task ───────────────────────
    //
    // Off by default. When freedom.yaml::arxiv.enabled = true AND
    // arxiv.topics is non-empty, runs each topic query on a cadence
    // (default 6h), optionally LLM-summarises each abstract via the
    // shared provider, and lands the result in the ctx knowledge store.
    // A topic fetch failure logs + skips; a pass failure logs + retries
    // next tick — never crashes the daemon.
    // GOLD-ARCH-01: construction relocated to serve_tasks (same handle, same site).
    let arxiv_ingest_task = crate::cli::serve_tasks::spawn_arxiv_ingest(
        &config,
        &neoth_home,
        &shared_provider,
        &reload_controller,
        &writer,
    );

    // ── 5b-quart. ArXiv skill-scan cron — GOLD-ADAPT-MEM-16 ────────────────
    //
    // Scans cs.AI/cs.LG on a 6h cadence, extracts 1-3 actionable takeaways
    // per paper via the shared provider, and writes each to `idx_groundtruth`
    // (source = "arxiv-skill-scan", scope = "arxiv-learning", Candidate).
    // Facts surface into recall/council automatically via surface_for_recall.
    // Off by default; requires both `arxiv_skill_scan.enabled: true` AND a
    // wired provider. WAL-free.
    let arxiv_skill_scan_task = crate::cli::serve_tasks::spawn_arxiv_skill_scan(
        &config,
        &neoth_home,
        &shared_provider,
        &reload_controller,
        &writer,
    );

    // ── 5b-ter. RSS / Atom / JSON-Feed poller — GOLD-ADOPT-26 ──────────────
    //
    // Polls `config.feeds.entries` on a cadence (default 1h), SSRF-validates
    // each URL, parses via feed-rs, lands new entries in the ctx store. Off
    // unless the operator set `feeds.enabled = true` with non-empty entries.
    // Same fail-soft cron discipline as the arXiv task; writes 0x4E/0x4F so it
    // is aborted BEFORE the WAL writer drains (see shutdown below).
    let rss_feed_task: Option<tokio::task::JoinHandle<anyhow::Result<()>>> =
        if config.feeds.enabled && !config.feeds.entries.is_empty() {
            info!(
                feeds = config.feeds.entries.len(),
                "rss feed poller enabled"
            );
            Some(crate::cli::rss_feed_task::spawn(
                neoth_home.clone(),
                config.feeds.entries.clone(),
                config
                    .feeds
                    .interval_secs
                    .map(std::time::Duration::from_secs),
                writer.clone(),
            ))
        } else {
            None
        };

    // ── 5b-bis. Hebbian decay task — QUELLEN Q-8 adoption ──────────────────
    //
    // Runs `memory::consolidate::run_consolidation_pass` every 2h. Math
    // primitives (decay 0.97/0.99/0.997, FORGET_FLOOR 0.10, PROMOTION 0.65)
    // are math-validated in `memory::tiers`. Task aborts on shutdown.
    // KF-10: when the operator configured an Obsidian vault, the decay
    // pass drafts a frontmatter-markdown summary of each hot memory it is
    // about to FORGET (below FORGET_FLOOR) into `<vault>/PreDecay/` — a
    // last-chance, reviewable record before the sweep. `None` = no export
    // (the pre-KF-10 behaviour, unchanged).
    let pre_decay_vault = config.obsidian_vault.clone().map(PathBuf::from);
    let decay_task = Some(crate::memory::decay_task::spawn(
        neoth_home.clone(),
        neoth_home.join("views.db"),
        crate::memory::decay_task::DEFAULT_INTERVAL,
        pre_decay_vault.clone(),
        // KF-10: the daemon owns the WAL writer, so each pass that touches rows
        // emits a `0x94 CONSOLIDATION_PASS` audit frame.
        Some(writer.clone()),
        // GOLD-FEAT-12 (b): pass the daemon provider so a LOCAL one can roll each
        // consolidated day up into a `kind='summary'` row (the pass's
        // is_local_provider guard skips cloud providers — no background billing).
        shared_provider.clone(),
    ));
    info!(
        interval_secs = crate::memory::decay_task::DEFAULT_INTERVAL.as_secs(),
        pre_decay_export = pre_decay_vault.is_some(),
        "Hebbian decay task spawned"
    );

    // ── 5b-quart. Sources-table GC scheduler (BS-3 wired). 24h cadence
    // sweeps transient `sources` rows + their chunks once a day.
    let gc_task = Some(crate::memory::gc_task::spawn(
        Some(neoth_home.join("views.db")),
        crate::memory::gc_task::DEFAULT_INTERVAL,
    ));
    info!(
        interval_secs = crate::memory::gc_task::DEFAULT_INTERVAL.as_secs(),
        "sources GC task spawned"
    );

    // ── 5b-sext. GOLD-PROG-08 — usage-meter export. Writes the live token
    // budget to <instance-home>/usage_meter.json every 10s so the GUI (a separate
    // process) can render it. Best-effort + WAL-free + stateless (a stale
    // snapshot is harmless), so it is a DETACHED daemon-lifetime task — no
    // BackgroundHandles / graceful-shutdown wiring. The handle is held (not
    // `let _ =`, which clippy flags as a dropped future) and detaches at
    // run_serve exit → the runtime stops it at daemon shutdown.
    let _usage_export = crate::cli::serve_tasks::spawn_usage_export(&neoth_home);

    // ── 5b-quint. Tmux sweeper (B-10 wired). 5-min cadence walks every
    // session whose name starts with `neoth-cc-`, kills entries idle
    // for > 10 min. No-op on Windows / hosts without tmux. Companion
    // to the B-6 TmuxSession primitive; integration of warm sessions
    // into ClaudeCliAdapter is the B-6 follow-up.
    let tmux_sweeper_task = Some(crate::providers::tmux_sweeper_task::spawn(None, None, None));
    info!(
        interval_secs = crate::providers::tmux_sweeper_task::DEFAULT_INTERVAL.as_secs(),
        "tmux sweeper task spawned"
    );

    // ── 5b-sext. n8n localhost API server (N-3 Workstream D) ──────────────
    //
    // Binds 127.0.0.1:<config.n8n_api.port> when
    // `freedom.yaml::n8n_api.enabled = true`. Hyper 1.x service with
    // bearer auth (5-strike cooldown), per-request 0x39 WAL audit
    // frame, loopback-only enforcement (bind + accept-time check),
    // 256 KiB body cap. Default OFF — operator opts in + runs
    // `neoth n8n token` first to generate the bearer.
    let n8n_api_shutdown = std::sync::Arc::new(tokio::sync::Notify::new());
    let n8n_api_task = crate::cli::serve_tasks::spawn_n8n_api(
        &config,
        &neoth_home,
        &writer,
        &reload_controller,
        &n8n_api_shutdown,
    );

    // ── 5c-quad. Spawn Kanban SSE endpoint — GOLD-ADAPT-HERMES-08 ────────────
    //
    // Binds 127.0.0.1:<config.kanban_sse.port> (default 9432) when
    // `freedom.yaml::kanban_sse.enabled = true`. Streams live kanban
    // events (task events, comments, dep edges) to browser/GUI/n8n
    // clients via `text/event-stream`. Bearer-token auth (same token
    // file as n8n_api). Default OFF — operator opts in.
    let kanban_sse_shutdown = std::sync::Arc::new(tokio::sync::Notify::new());
    let (kanban_sse_task, kanban_sse_tx) = crate::cli::serve_tasks::spawn_kanban_sse(
        &config,
        &neoth_home,
        &writer,
        &kanban_sse_shutdown,
    );

    // GOLD-ADAPT-TRAIL-02: relay task — wakes on views_change_rx (watch
    // coalesces bursts → 1 wakeup per indexer pass), reads the latest FeedEntry
    // from views.db via the shared ViewsExecutor reader pool, and fans out to
    // kanban_sse broadcast subscribers (one step = `relay_latest_feed_to_sse`).
    //
    // No early-delta loss: `views_change_rx` is created at boot (above) and is
    // NEVER consumed before this clone, so the clone inherits last-seen = the
    // initial version. Any indexer `send` since boot — even one that fired before
    // this task spawned — leaves the current version ahead of the clone's
    // baseline, so the first `changed().await` returns immediately for it. watch
    // coalescing then collapses a burst into a single wakeup.
    if let Some(sse_tx) = kanban_sse_tx.clone() {
        let mut change_rx = views_change_rx.clone();
        let exec_for_relay = views_executor.clone();
        tokio::spawn(async move {
            loop {
                // Block until the indexer signals a new commit to views.db.
                if change_rx.changed().await.is_err() {
                    // Sender dropped (daemon shutting down) — exit cleanly.
                    break;
                }
                let Some(exec) = exec_for_relay.as_ref() else {
                    continue;
                };
                crate::cli::serve_tasks::relay_latest_feed_to_sse(exec, &sse_tx).await;
            }
        });
    }

    // ── 5c-ter-bis. Spawn OpenRouter-compat /v1/models serve adapter — GOLD-ADAPT-AWE-PROV-01
    //
    // Loopback-only (127.0.0.1:9746 default). Serves GET /v1/models in
    // OpenRouter wire format so Cline/Continue/OpenCode/Goose can discover
    // NEOTH's models catalog. No auth required — read-only; loopback is the
    // security boundary. Default OFF — operator opts in via
    // `oai_serve.enabled: true` in freedom.yaml.
    let oai_serve_shutdown = std::sync::Arc::new(tokio::sync::Notify::new());
    let oai_serve_task =
        crate::cli::serve_tasks::spawn_oai_serve(&config, &neoth_home, &oai_serve_shutdown);

    // ── 5c-bis. Spawn /healthz + /metrics listener — Phase 33c BS-1 ────────
    //
    // Optional, off by default. Operator opts in by setting
    // `observability_listen: "127.0.0.1:43117"` (or similar) in freedom.yaml.
    // Localhost-only by design — public exposure is the operator's choice
    // via a reverse proxy if they want one.
    let healthz_task =
        crate::cli::serve_tasks::spawn_healthz(&config, &neoth_home, &provider_meter);

    // ── 5d. Cron scheduler — Phase 33a AU-B5 ───────────────────────────────
    //
    // Loads `<instance-home>/jobs.yaml` if present and spawns the tick loop.
    // Missing jobs file is not an error — operators without recurring jobs
    // simply see no scheduler task. Bad YAML *is* an error: configuration
    // problems must fail loudly at startup, not silently never fire.
    // GOLD-ARCH-01: construction relocated to serve_tasks (same handle, same site).
    let cron_task = crate::cli::serve_tasks::spawn_cron_scheduler(
        &config,
        &neoth_home,
        &shared_provider,
        &writer,
        &reload_controller,
    )
    .await?;

    // ── 5d.b  ZF-06 Cron Fleet supervisor ────────────────────────────────
    //
    // All config-gated fleet crons (DoctorCron, ResourceWatch, MonitorCron,
    // Babel, WatchdogCron, DriftAlert, RecallLatency, ProfileAdapt,
    // EcologyCron, PatternCron, BgMonitor, ContradictionResolve,
    // GuidanceCron, SkillCurator, SynthesisCron, ConsolidationSweep,
    // SelfWiki, SelfImprovementCollector, TokenAnomaly, SessionHealth,
    // WebhookManager, ObsidianSync, ObsidianVaultReader,
    // ObsidianWikiRebuild, SelfMap, and cluster ResourceSnapshot) are seeded here and hot-reloaded by
    // the supervisor on every `neoth reload`.  Four crons remain as direct
    // fields (CheckinCron, SessionSort, EmailIngest, Regression) because
    // they need async construction or extra deps (shared_provider).
    let spawn_deps = crate::cli::serve_tasks::SpawnDeps {
        reload_controller: reload_controller.clone(),
        writer: writer.clone(),
        home: neoth_home.clone(),
        wal_dir: wal_dir.clone(),
        views_executor: views_executor.clone(),
        sse_tx: kanban_sse_tx.clone(),
        shared_provider: shared_provider.clone(),
    };
    let cron_fleet: crate::cli::serve_tasks::CronFleet =
        std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let cron_supervisor_task: tokio::task::JoinHandle<()> = {
        use crate::cli::serve_tasks::{
            desired_cron_keys, plan_cron_fleet_reload, spawn_cron_for_key,
        };
        let mut gen_rx = reload_controller.subscribe_generation();
        let fleet = std::sync::Arc::clone(&cron_fleet);
        let deps = spawn_deps;
        let ctrl = reload_controller.clone();
        tokio::spawn(async move {
            // NEOTH-AUDIT-CRON-FLEET-LIFECYCLE-01 fix:
            // Local fingerprint map: tracks a config-spec hash per running key
            // so a changed interval/path triggers a restart even when the
            // CronKey itself stays in the desired set.
            let mut fp_map: std::collections::HashMap<crate::cli::serve_tasks::CronKey, u64> =
                std::collections::HashMap::new();

            // ZF-07 Boot-Stagger: create the first-tick semaphore once for the
            // boot seed phase.  Each cron acquires one permit before spawning;
            // the permit is released after CRON_FIRST_TICK_WINDOW via a tiny
            // detached timer task.  The semaphore is not used after seeding —
            // steady-state hot-reload restarts bypass it entirely.
            let boot_stagger_sem =
                std::sync::Arc::new(tokio::sync::Semaphore::new(START_STAGGER_PERMITS));

            // Seed: spawn all desired crons for the boot config.
            {
                let boot_accepted = ctrl.accepted_snapshot();
                let boot_cfg = boot_accepted.config();
                let desired = desired_cron_keys(&boot_cfg);
                let mut seeded = 0usize;
                for key in &desired {
                    // ZF-07: acquire before spawn — at most START_STAGGER_PERMITS
                    // crons execute their first tick concurrently.  Blocks until a
                    // slot opens; runtime continues scheduling other tasks meanwhile.
                    let stagger_permit = boot_stagger_sem
                        .clone()
                        .acquire_owned()
                        .await
                        .expect("boot_stagger_sem closed");
                    if let Some(handle) =
                        spawn_cron_for_key(*key, Arc::clone(&boot_accepted), &deps).await
                    {
                        fleet
                            .lock()
                            .expect("cron_fleet mutex poisoned")
                            .insert(*key, handle);
                        fp_map.insert(*key, cron_spec_fingerprint(*key, &boot_cfg));
                        seeded += 1;
                        // Hold the permit for CRON_FIRST_TICK_WINDOW so the cron's
                        // first tick finishes before the next batch is released.
                        // Detached: daemon-lifetime task; no handle needed.
                        tokio::spawn(async move {
                            tokio::time::sleep(CRON_FIRST_TICK_WINDOW).await;
                            drop(stagger_permit); // explicit: release the slot
                        });
                    }
                    // None branch: stagger_permit drops here, releasing immediately.
                }
                // Count tasks actually spawned, not the desired-set size: a
                // desired key whose spawn_* returns None (e.g. a vault is set but
                // no source_dir) never enters the fleet and must not be counted.
                tracing::info!(seeded, "ZF-06 cron fleet seeded");
            }
            let mut health = tokio::time::interval(CRON_HEALTH_INTERVAL);
            health.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            health.tick().await;
            // Reload + health loop: config changes rebuild affected tasks;
            // health ticks independently reap and respawn dead children.
            loop {
                let Some(wake) = next_cron_supervisor_wake(&mut gen_rx, &mut health).await else {
                    break;
                };
                let wake_label = wake.label();

                // ── NEOTH-AUDIT-CRON-FLEET-LIFECYCLE-01: is_finished() sweep ──
                // Reap handles for crons that completed or panicked without
                // being explicitly stopped. Removing them from the fleet lets
                // diff_cron_fleet include them in to_start on this pass, so
                // they are immediately respawned.
                let finished_tasks = crate::cli::serve_tasks::take_finished_cron_tasks(&fleet);
                if !finished_tasks.is_empty() {
                    let finished_keys: Vec<_> =
                        finished_tasks.iter().map(|(key, _)| *key).collect();
                    tracing::warn!(
                        count = finished_keys.len(),
                        keys = ?finished_keys,
                        wake = wake_label,
                        "ZF-06 cron fleet: reaping finished/panicked handles; will respawn",
                    );
                    for (key, handle) in finished_tasks {
                        fp_map.remove(&key);
                        handle.reap_finished().await;
                    }
                }

                let live_accepted = ctrl.accepted_snapshot();
                let live_cfg = live_accepted.config();
                let desired = desired_cron_keys(&live_cfg);

                // ── NEOTH-AUDIT-CRON-FLEET-LIFECYCLE-01: fingerprint-change
                // detection — keys still present in both running and desired but
                // whose effective spec (interval, path, flags) changed since they
                // were last spawned need a restart, not just an enable/disable.
                let mut fp_changed: std::collections::HashSet<crate::cli::serve_tasks::CronKey> = {
                    let guard = fleet.lock().expect("cron_fleet mutex poisoned");
                    guard
                        .keys()
                        .filter(|k| desired.contains(*k))
                        .filter(|k| {
                            fp_map.get(*k).copied().unwrap_or(0)
                                != cron_spec_fingerprint(**k, &live_cfg)
                        })
                        .copied()
                        .collect()
                };
                // Dream's authority is bound to the exact accepted snapshot,
                // not merely to its Dream sub-config fingerprint. Every
                // successful reload retires the old snapshot's commit gate, so
                // the owner must replace a still-desired Dream task immediately
                // even when an unrelated config field changed.
                let dream_is_desired = desired.contains(&crate::cli::serve_tasks::CronKey::Dream);
                let dream_is_running = fleet
                    .lock()
                    .expect("cron_fleet mutex poisoned")
                    .contains_key(&crate::cli::serve_tasks::CronKey::Dream);
                if dream_needs_generation_restart(wake, dream_is_running, dream_is_desired) {
                    fp_changed.insert(crate::cli::serve_tasks::CronKey::Dream);
                }

                let (to_stop, to_start) = {
                    let guard = fleet.lock().expect("cron_fleet mutex poisoned");
                    let running: std::collections::HashSet<_> = guard.keys().copied().collect();
                    plan_cron_fleet_reload(&running, &desired, &fp_changed)
                };

                // Stop tasks that are no longer desired (or whose spec changed).
                // SelfMap is deliberately cooperative: if a blocking phase is
                // still draining, the owner is put back and the replacement is
                // suppressed until a later reconciliation can prove terminal
                // quiescence.
                let mut stopped = 0usize;
                for key in &to_stop {
                    let handle = fleet.lock().expect("cron_fleet mutex poisoned").remove(key);
                    if let Some(handle) = handle {
                        match handle.stop().await {
                            crate::cli::serve_tasks::CronTaskStopOutcome::Stopped => {
                                fp_map.remove(key);
                                stopped += 1;
                            }
                            crate::cli::serve_tasks::CronTaskStopOutcome::TimedOut(handle) => {
                                fleet
                                    .lock()
                                    .expect("cron_fleet mutex poisoned")
                                    .insert(*key, handle);
                                tracing::warn!(
                                    key = ?key,
                                    "cron replacement suppressed until prior SelfMap owner quiesces"
                                );
                            }
                        }
                    }
                }
                // Start newly desired tasks (including spec-change restarts),
                // counting only those that actually spawned — a desired key
                // whose spawn_* returns None (vault set but no source_dir)
                // would otherwise be logged as "started" on every reload
                // forever without ever entering the fleet.
                let mut started = 0usize;
                for key in &to_start {
                    if fleet
                        .lock()
                        .expect("cron_fleet mutex poisoned")
                        .contains_key(key)
                    {
                        tracing::debug!(
                            key = ?key,
                            "cron start suppressed because prior owner remains live"
                        );
                        continue;
                    }
                    if let Some(handle) =
                        spawn_cron_for_key(*key, Arc::clone(&live_accepted), &deps).await
                    {
                        fleet
                            .lock()
                            .expect("cron_fleet mutex poisoned")
                            .insert(*key, handle);
                        fp_map.insert(*key, cron_spec_fingerprint(*key, &live_cfg));
                        started += 1;
                    }
                }
                if !to_stop.is_empty() || started > 0 {
                    tracing::info!(
                        stopped,
                        started,
                        wake = wake_label,
                        "ZF-06 cron fleet reconciled"
                    );
                }
            }
        })
    };

    // ── 5d-bis. Reflection cron — G-01 (Round-3 v0.4 cron wiring) ────
    //
    // Weekly Day-7 reflection: glues `crate::reflection`
    // (G-01-mini producer) + `crate::proactive::ProactiveQueue`
    // (G-01a substrate). Ticks every 24h by default — the per-week
    // dedup_key in the built item keeps actual emissions to one per
    // ISO week regardless of tick frequency, so daily ticks just
    // provide recovery if a daemon restart misses Sunday's tick.
    //
    // No freedom.yaml gate yet (planned config: `reflection.cron_
    // interval_secs`); ships always-on at 24h. Operators who don't
    // want proactive reflections can drain the proactive_queue.json
    // before the consumer-side reads it.
    // GOLD-ARCH-01: relocated to serve_tasks (same handle, same site).
    let reflection_cron_handle =
        crate::cli::serve_tasks::spawn_reflection_cron(&neoth_home, &reload_controller, &writer);

    // ── 5d-tris. Durable proactive egress — G-01 consumer half ───────────
    //
    // Claims ready items, WAL-binds the exact intent, persists an Armed proof
    // before a live transport can run, then records the terminal result and
    // idempotently projects it to Cron state, queue settlement, and the private
    // CLI/GUI history. Ticks every 5min; a per-tick cap of 3 smooths bursts.
    // GOLD-ARCH-01: construction relocated to serve_tasks (same handle, same site).
    let proactive_dispatcher_handle = crate::cli::serve_tasks::spawn_proactive_dispatcher(
        &neoth_home,
        &segment_chain_base_path,
        &writer,
    );

    // ── 5d-quartus. G-02 surfacing cron — "Knows things about you you
    //               don't know" producer (Round-3 v0.4) ──
    //
    // Daily scan of `idx_profile` for high-confidence claims newer
    // than the novelty window; each gets rendered as a bilingual
    // ProactiveItem + enqueued into the same ProactiveQueue the
    // proactive_dispatcher (above) drains. Per-claim dedup_key
    // (`g02:<field>:<value_hash>`) prevents re-enqueue churn even
    // if the cron fires more frequently than the default 24h.
    //
    // Quiet no-op on fresh installs (no views.db yet) so first-week
    // wizard logs stay clean.
    // GOLD-ARCH-01: relocated to serve_tasks (same handle, same site).
    let g02_surfacing_cron_handle = crate::cli::serve_tasks::spawn_g02_surfacing_cron(&neoth_home);

    // ── 5d-sextus. Regression-anchor cron — ADV-14 (deferred: async + provider dep)
    let regression_cron_handle = crate::cli::serve_tasks::spawn_regression_cron(
        &config,
        &neoth_home,
        &shared_provider,
        &writer,
        &reload_controller,
    )
    .await;

    // GOLD-ADAPT-ODY-24 — Companion server-side pairing surface. Default OFF —
    // opt-in via `companion.enabled: true`. Its loopback browser endpoint and QR
    // preview can mint chat-scoped bearer tokens for a compatible client; NEOTH
    // does not ship a phone client. Emits `0x0B COMPANION_PAIRED` WAL audit frames.
    // ONE shared CompanionState (token store) wired into BOTH the loopback HTTP
    // server AND the v2 HyperDHT/authenticated Noise-IK coordinator below. A bearer
    // token minted over either path is therefore valid on the other — a compatible
    // client pairs over P2P
    // and then talks to the daemon over loopback HTTP with the SAME token.
    // (Previously the two paths each built their own CompanionState, so a
    // P2P-minted token was unknown to the HTTP auth check and vice-versa.)
    let companion_state = std::sync::Arc::new(crate::daemon::companion::CompanionState::new(
        writer.clone(),
        config.companion.port,
    ));
    let companion_shutdown = std::sync::Arc::new(tokio::sync::Notify::new());
    let companion_task = crate::cli::serve_tasks::spawn_companion_server(
        &config,
        &neoth_home,
        std::sync::Arc::clone(&companion_state),
        std::sync::Arc::clone(&companion_shutdown),
    );

    // GOLD-COMPANION-P2P-01 — Companion v2 HyperDHT / authenticated Noise-IK
    // pairing coordinator.
    // Default OFF — opt-in via `companion.p2p_enabled: true`. When enabled,
    // runs a long-lived poll loop that picks up pending invites written by
    // `neoth companion pair-phone --write-invite-for-serve` and drives the
    // HyperDHT / authenticated Noise-IK accept loop for each one. It admits the
    // topic-and-PSK-HKDF-derived expected client static key before allocation and
    // retains the encrypted application PSK as defense in depth. Shares `companion_state`
    // above so P2P-minted tokens are valid on the loopback HTTP path. Emits
    // `0x0D COMPANION_P2P_PAIRED` / `0x0E COMPANION_P2P_REJECTED` WAL audit
    // frames. Requires the `cluster` feature.
    let companion_p2p_shutdown = std::sync::Arc::new(tokio::sync::Notify::new());
    let companion_p2p_task = crate::cli::serve_tasks::spawn_companion_p2p_listener_task(
        &config,
        &neoth_home,
        std::sync::Arc::clone(&companion_state),
        writer.clone(),
        std::sync::Arc::clone(&companion_p2p_shutdown),
    );

    // WatchdogCron is now fleet-managed (ZF-06).

    // ── GOLD-WIRE-07b — daemon HNSW snapshot auto-freshness ────────────────────
    // WIRE-07 made `neoth recall` cold-load the on-disk HNSW snapshot, but it
    // only refreshed on the manual `neoth memory --rebuild-index`. This task
    // periodically REBUILDS the snapshot FROM SQLite — the source of truth shared
    // with the SEPARATE `neoth ingest` CLI process — when it has gone stale, so
    // the cross-process cold-load stays fresh without operator action. An
    // in-memory daemon warm index would be WRONG here (it would miss every
    // CLI-ingested vector and could clobber a good snapshot); reading SQLite
    // captures every writer. Gated to backend=hnsw + corpus past the brute-force
    // ceiling; idempotent + best-effort; writes NO WAL frames (only SQLite reads
    // + an atomic snapshot rename) so it is order-independent at shutdown. Off
    // entirely when the backend is brute-force.
    // GOLD-ARCH-01: construction relocated to serve_tasks (same handle, same site).
    let snapshot_refresh_handle =
        crate::cli::serve_tasks::spawn_snapshot_refresh(&config, &neoth_home);

    // ── OMI-MULTIMODAL-01 full runtime supervisor ──────────────────────────
    // Owns official Developer API sync, authenticated native audio/caption/
    // frame ingestion, retention, credential rotation, and config reload.
    // The supervisor itself stays alive while disabled so reload can enable it.
    let omi_handle = crate::cli::serve_tasks::spawn_omi_ingest(
        &reload_controller,
        credentials_path.clone(),
        neoth_home.clone(),
        writer.clone(),
        provider_meter.clone(),
    );

    // ProfileAdapt, EcologyCron, PatternCron, BgMonitor, ContradictionResolve,
    // GuidanceCron are now fleet-managed (ZF-06).

    // ── GOLD-FEAT-11 post-init healthcheck (one-shot) ─────────────────────
    // Checks onboarding gaps and enqueues a ProactiveItem when incomplete.
    // Detached — no handle; errors are logged best-effort.
    {
        let home_for_init = neoth_home.clone();
        // run_post_init_check borrows home as &Path — passing &PathBuf coerces fine.
        // The PathBuf is moved into the spawned async block which owns it.
        tokio::spawn(async move {
            crate::daemon::post_init_cron::run_post_init_check(&home_for_init).await;
        });
    }

    // ── GOLD-FEAT-11 LLM check-in cron (default OFF) ─────────────────────
    let checkin_cron_handle = crate::cli::serve_tasks::spawn_checkin_cron(
        &config,
        &reload_controller,
        &neoth_home,
        &writer,
    )
    .await;

    // ── GOLD-ADAPT-ODY-26 session auto-sort cron (default OFF) ───────────
    let session_sort_cron_handle = crate::daemon::session_sort_cron::spawn_session_sort_cron(
        &config,
        &reload_controller,
        &neoth_home,
        &writer,
    )
    .await;

    // ── GOLD-ADAPT-JV-PAPERLESS-01 email-ingest cron (default OFF) ───────
    // Keep a dormant supervisor alive while disabled so `neoth reload` can
    // enable it without a daemon restart. Generation notifications reset the
    // ticker immediately on both interval changes and disabled→enabled edges.
    let email_ingest_cron_handle = {
        let ctrl = reload_controller.clone();
        let home = neoth_home.clone();
        info!("email ingest cron supervisor spawned (GOLD-ADAPT-JV-PAPERLESS-01)");
        Some(tokio::spawn(async move {
            let mut generation = ctrl.subscribe_generation();
            let (mut current_enabled, mut current_interval) = {
                let initial = ctrl.latest();
                (
                    initial.email_ingest_cron.enabled,
                    initial.email_ingest_cron.interval_duration(),
                )
            };
            let mut ticker = tokio::time::interval(current_interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let current = ctrl.latest();
                        if !current.email_ingest_cron.enabled {
                            continue;
                        }
                        if let Err(e) =
                            crate::daemon::email_ingest_cron::run_email_ingest_tick(&home).await
                        {
                            warn!(error = %e, "email_ingest_cron tick error");
                        }
                    }
                    changed = generation.changed() => {
                        if changed.is_err() {
                            break;
                        }
                        let current = ctrl.latest();
                        if let Some(live_interval) = email_ingest_schedule_change(
                            current_enabled,
                            current_interval,
                            &current.email_ingest_cron,
                        ) {
                            current_interval = live_interval;
                            ticker = tokio::time::interval_at(
                                tokio::time::Instant::now(),
                                current_interval,
                            );
                            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                            info!(
                                enabled = current.email_ingest_cron.enabled,
                                interval_secs = current_interval.as_secs(),
                                "email ingest cron schedule updated via config reload"
                            );
                        }
                        current_enabled = current.email_ingest_cron.enabled;
                    }
                }
            }
        }))
    };

    // SkillCurator, SynthesisCron, ConsolidationSweep, SelfWiki,
    // SelfImprovementCollector are now fleet-managed (ZF-06).

    // ── 5e. Models catalog refresh task — K-Models-Discovery (Session 14) ──
    //
    // Daemon-internal background task that refreshes
    // `~/.neoth/models_catalog.json` once per day. Provider model
    // names rot fast (Claude went 4.5→4.6→4.7 in seven weeks during
    // 2026; Gemini 3 Pro Preview was sunset 2026-03-26 with three
    // weeks notice). Without proactive discovery the wizard's
    // select-list goes stale and operators land on retired model
    // ids.
    //
    // Honours the operator's freedom.yaml: when no cloud provider is
    // configured (LocalQwen-only deployments), the task ticks but
    // does nothing — no outbound traffic.
    // GOLD-ARCH-01: relocated to serve_tasks (same handle, same site).
    let catalog_task = crate::cli::serve_tasks::spawn_catalog_refresh(&config, &neoth_home);

    // ── Cluster audit-sidecar ingester ─────────────────────────────────────
    // CLI commands (`neoth cluster confirm` / `revoke`) drop JSON
    // sidecars at `~/.neoth/pending_audit/cluster_*.json`. This
    // task polls every 5s, reads pending sidecars, appends WAL
    // 0xE6/0xE7 frames, removes the consumed file.
    // GOLD-SEC-16: cluster transport + its sidecar/gossip tasks compile in only
    // with the `cluster` feature.
    // GOLD-ARCH-01: construction relocated to serve_tasks (same handle, same site).
    #[cfg(feature = "cluster")]
    let cluster_audit_task =
        crate::cli::serve_tasks::spawn_cluster_audit_ingester(&neoth_home, &writer);
    #[cfg(feature = "cluster")]
    info!("cluster audit sidecar ingester spawned (5s tick)");
    #[cfg(feature = "cluster")]
    let cluster_foreign_indexer_task = crate::cli::serve_tasks::spawn_foreign_indexer(&neoth_home);

    // ── R4-13 shared live cluster runtime supervisor ──────────────────────
    // One generation-bound owner serializes carrier, mDNS, gossip, durable
    // request-consumer and executor lifetimes. Config and credential changes
    // stop+await the old unit before starting the replacement; failed switches
    // remain fully stopped and never restore revoked auth/privacy generations.
    #[cfg(feature = "cluster")]
    let cluster_runtime_supervisor = crate::cluster::runtime_supervisor::spawn_runtime_supervisor(
        neoth_home.clone(),
        segment_path.clone(),
        writer.clone(),
        std::sync::Arc::clone(&reload_controller),
        shared_provider.clone(),
        std::sync::Arc::clone(&cluster_live_sessions),
    )
    .await?;

    // ── 5d.c. Reload-owned recurring updater supervisor — GOLD-R3-18 ──────
    //
    // Spawn only after the last fallible startup constructor above. This keeps
    // an early cluster-start failure from dropping a JoinHandle and detaching a
    // recurring updater generation. Normal shutdown signals the supervisor and
    // joins every admitted lane. An unexpected owner drop sends the same
    // shutdown signal and leaves the supervisor attached to the runtime long
    // enough to drain, because aborting it could manufacture an audit orphan.
    let mut updater_supervisor = crate::cli::serve_tasks::spawn_updater_supervisor(
        &neoth_home,
        std::sync::Arc::clone(&reload_controller),
        writer.clone(),
    );

    // ── MONITOR-02 worker-watch ───────────────────────────────────────────
    // Real-time death detection for the long-running cron/worker loops: hold a
    // cheap `AbortHandle` clone of each + poll `is_finished()`, emitting
    // `0x4D WORKER_DIED` (naming the task) the moment one panics/exits.
    let worker_watch_handle: Option<tokio::task::JoinHandle<()>> = if config.monitor.enabled {
        use crate::daemon::worker_watch::WatchedWorker;
        let watched: Vec<WatchedWorker> = [
            cron_task
                .as_ref()
                .map(|h| WatchedWorker::new("cron_scheduler", h.abort_handle())),
            Some(WatchedWorker::new(
                "updater_supervisor",
                updater_supervisor.abort_handle(),
            )),
            omi_handle
                .as_ref()
                .map(|h| WatchedWorker::new("omi_ingest", h.abort_handle())),
            snapshot_refresh_handle
                .as_ref()
                .map(|h| WatchedWorker::new("snapshot_refresh", h.abort_handle())),
        ]
        .into_iter()
        .flatten()
        .collect();
        let watched_count = watched.len();
        let handle = crate::daemon::worker_watch::spawn_worker_watch(
            watched,
            writer.clone(),
            config.monitor.interval_secs,
        );
        if handle.is_some() {
            info!(watched = watched_count, "MONITOR-02 worker-watch spawned");
        }
        handle
    } else {
        None
    };

    // ── W-05d installer_ran sidecar ingester (Session 26) ─────────────────
    // `neoth installer apply --yes` drops `~/.neoth/installer_ran_<ts>.json`
    // after a successful install. This task polls every 5s, reads
    // pending sidecars, appends a `0x12 INSTALLER_RAN` WAL frame per
    // sidecar, and removes the file. At-least-once semantics: a crash
    // between WAL append + file remove leaves the file for the next
    // tick to retry; the WAL writer dedupes by event_id.
    // GOLD-ARCH-01: body relocated to serve_tasks (same handle, same site).
    let installer_audit_task =
        crate::cli::serve_tasks::spawn_installer_audit_ingester(&neoth_home, writer.clone());

    // ── C-05d credentials_import sidecar ingester (Session 26) ────────────
    // `neoth init` wizard step 6g drops
    // `~/.neoth/credentials_import_<ts>.json` after the SC-17 redactor
    // produced its payload. This task polls every 5s, reads pending
    // sidecars, appends a `0xD6 CREDENTIAL_IMPORT` WAL frame per
    // sidecar, and removes the file. The payload is already redacted
    // by the time it lands on disk — this loop never touches raw
    // secret material.
    // GOLD-ARCH-01: body relocated to serve_tasks (same handle, same site).
    let credentials_import_task =
        crate::cli::serve_tasks::spawn_credentials_import_ingester(&neoth_home, writer.clone());

    // ── W-04 follow-up: detect_complete sidecar ingester (Session 26) ─────
    // The wizard's step1b drops `~/.neoth/detect_complete_<ts>.json`
    // after a fresh probe pass produced a `DetectCompletePayload`.
    // Same 5s poll + at-least-once contract as the installer +
    // credentials ingesters above.
    // GOLD-ARCH-01: body relocated to serve_tasks (same handle, same site).
    let detect_complete_task =
        crate::cli::serve_tasks::spawn_detect_complete_ingester(&neoth_home, writer.clone());

    // ── Self-dev outbox drain (P-04 follow-on, Session 21) ────────────────
    // CLI commands `neoth self-dev accept/decline/propose` run
    // without an in-process WAL writer (daemon owns the segment
    // exclusively). They enqueue pending events in
    // `~/.neoth/self_dev/pending_events.jsonl`; this task drains
    // every DRAIN_INTERVAL (5s default) + emits real
    // EVENT_TYPE_SELF_DEV_{PROPOSED,ACCEPTED,DECLINED} frames into
    // the WAL. Closes the public-blocker gap "CLI without writer
    // warns 'no WAL frame'" — the WAL frames now DO land,
    // asynchronously through the daemon.
    // GOLD-ARCH-01: construction relocated to serve_tasks (same handle, same site).
    let self_dev_outbox_task = crate::cli::serve_tasks::spawn_self_dev_outbox(&neoth_home, &writer);
    let consent_outbox_task =
        crate::cli::serve_tasks::spawn_consent_outbox_recovery(&neoth_home, &writer);

    // ── QM-10 Phase 3 breaker state restore ────────────────────────────────
    // Replay the failure counters from the prior daemon run so a
    // flapping provider that built up failure history before
    // shutdown doesn't get a clean slate after restart. Open
    // state is intentionally NOT restored — a fresh boot should
    // retry every provider once. Stale rows (older than 7 days)
    // are skipped.
    {
        match crate::providers::circuit_breaker::persist::restore_from_disk(
            &neoth_home,
            &crate::providers::circuit_breaker::GLOBAL,
            7 * 86_400,
        ) {
            Ok(0) => {}
            Ok(n) => info!(
                providers = n,
                "QM-10 Phase 3: restored circuit-breaker failure counters from prior run"
            ),
            Err(e) => warn!(error = %e, "breaker state restore failed (non-fatal)"),
        }
    }

    // ── 6. Idle until shutdown signal arrives ──────────────────────────────
    {
        let live_channels = channel_tasks
            .lock()
            .expect("channel_tasks mutex poisoned")
            .len();
        if live_channels == 0 {
            info!("no channels configured; idling until shutdown signal");
        } else {
            info!(
                channels = live_channels,
                "channels running; idling until shutdown signal (SIGTERM / Ctrl+C)"
            );
        }
    }
    // Supervision fix (Agent 4 audit 2026-05-16): race the shutdown
    // signal against the WAL writer's join handle. Without this race,
    // a writer task that dies mid-run (disk full / fsync error / panic
    // after N days of rotation) leaves the daemon limping — channels
    // keep accepting messages, the pipeline keeps trying to append,
    // every WAL write returns `WriterClosed`, replies silently fail,
    // and the operator only notices when their next `neoth wal show`
    // turns up a stale tail. Treating writer death as fatal lets a
    // process supervisor (systemd / Windows Service Manager / a bash
    // `while true; do neothd serve; done` loop) restart cleanly.
    // ── MV-01b restart contract ────────────────────────────────────────
    // After an operator-confirmed self-update swaps the binary on disk,
    // the apply path drops `~/.neoth/restart.request`. This watcher polls
    // for it + signals a graceful drain+exit so the supervisor relaunches
    // onto the NEW binary. No-op without a supervisor (the daemon would
    // just exit + not come back, so the apply path only writes the marker
    // when `config.supervisor.enabled`). Stop (vs restart) is the
    // supervisor's own command, not this path.
    let restart_notify = std::sync::Arc::new(tokio::sync::Notify::new());
    let restart_watcher = {
        let notify = std::sync::Arc::clone(&restart_notify);
        let restart_home = neoth_home.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(5));
            ticker.tick().await; // burn immediate
            loop {
                ticker.tick().await;
                if crate::daemon::supervisor::take_restart_request(&restart_home).await {
                    notify.notify_one();
                    break;
                }
            }
        })
    };

    let mut audit_rpc_task = audit_rpc_task;
    let mut writer_join_result: Option<
        std::result::Result<Result<(), String>, tokio::task::JoinError>,
    > = None;
    let required_boundary_died = tokio::select! {
        biased;
        _ = shutdown::wait_for_signal() => false,
        _ = restart_notify.notified() => {
            info!(
                "restart requested (self-update binary swap); draining + exiting for supervisor relaunch"
            );
            false
        }
        result = &mut writer_join => {
            writer_join_result = Some(result);
            match writer_join_result.as_ref().expect("writer result just stored") {
                Ok(Ok(())) => warn!(
                    "WAL writer task exited unexpectedly without error — daemon cannot persist events; treating as fatal"
                ),
                Ok(Err(e)) => error!(
                    error = %e,
                    "WAL writer task failed — daemon cannot persist events; treating as fatal"
                ),
                Err(e) => error!(
                    error = %e,
                    "WAL writer task panicked — daemon cannot persist events; treating as fatal"
                ),
            }
            true
        }
        reason = updater_supervisor.wait_for_failure() => {
            error!(
                %reason,
                "required updater supervisor boundary failed — treating recurring-update lifecycle loss as fatal"
            );
            true
        }
        result = async {
            audit_rpc_task
                .as_mut()
                .expect("required membership/audit listener task missing after startup")
                .await
        }, if membership_listener_required => {
            match result {
                Ok(Ok(())) => error!(
                    "required membership/audit listener exited unexpectedly — authority mutations can no longer be served safely"
                ),
                Ok(Err(error)) => error!(
                    %error,
                    "required membership/audit listener failed — treating authority boundary loss as fatal"
                ),
                Err(error) => error!(
                    %error,
                    "required membership/audit listener panicked — treating authority boundary loss as fatal"
                ),
            }
            audit_rpc_guard.take();
            crate::daemon::audit_rpc::remove_sidecar(&neoth_home);
            true
        }
    };
    // Withdraw endpoint discovery at the shutdown decision, before hooks or
    // background drains can take time and before the OS endpoint can be
    // substituted. The guard also aborts the listener; its JoinHandle remains
    // in `BackgroundHandles` solely for ordered task collection.
    audit_rpc_guard.take();
    restart_watcher.abort();
    let _ = restart_watcher.await;
    // Linearize generation-bound effect shutdown at the signal/fatal-boundary
    // decision, before breaker persistence and operator hooks can extend
    // teardown. Existing Dream commits and updater leaves drain; no new
    // generation lease can start after this returns.
    crate::cli::serve_tasks::retire_generation_effect_runtime(&reload_controller).await;
    if required_boundary_died {
        info!("required daemon persistence/authority boundary died; aborting channels + exiting");
    } else {
        info!("shutdown signal received; aborting channels + draining WAL writer");
    }

    // ── QM-10 Phase 3 breaker state snapshot ───────────────────────────────
    // Persist the current failure counters BEFORE the shutdown hooks
    // fire so a restart-grace path sees the same state. Best-effort —
    // a stuck disk doesn't block the shutdown sequence.
    {
        match crate::providers::circuit_breaker::persist::snapshot_to_disk(
            &neoth_home,
            &crate::providers::circuit_breaker::GLOBAL,
        ) {
            Ok(0) => {}
            Ok(n) => info!(
                providers = n,
                "QM-10 Phase 3: snapshotted circuit-breaker failure counters to disk"
            ),
            Err(e) => warn!(error = %e, "breaker state snapshot failed (non-fatal)"),
        }
    }

    // ── OnShutdown hooks (Phase 29 R-15) ──────────────────────────────────
    // Fire operator-defined hooks at the `on_shutdown` stage BEFORE we
    // abort channel/cron/indexer tasks. Each fired hook writes a
    // HOOK_FIRED WAL frame so the audit log shows that the configured
    // shutdown actions ran. Block actions at this stage are best-effort
    // — we're already shutting down, so a Block just gets logged + skipped
    // rather than aborting the drain.
    {
        // Re-read valid operator edits. If the live set became malformed,
        // retain the startup-validated policy instead of silently erasing all
        // shutdown hooks at the lifecycle boundary.
        let hooks = match crate::hooks::load_all_strict(&hook_dir).await {
            Ok(hooks) => hooks,
            Err(error) => {
                warn!(
                    error = %error,
                    dir = %hook_dir.display(),
                    "shutdown hook reload rejected; using startup-validated hook snapshot"
                );
                startup_hooks.clone()
            }
        };
        match crate::hooks::run_stage(crate::hooks::HookStage::OnShutdown, "shutdown", &hooks) {
            Ok(crate::hooks::StageOutcome::Continue { hits, .. }) => {
                for name in &hits {
                    let payload = match serde_json::to_vec(&serde_json::json!({
                        "name": name,
                        "stage": "on_shutdown",
                        "ts_unix": crate::time::now_unix_secs(),
                    })) {
                        Ok(p) => p,
                        Err(e) => {
                            warn!(error = %e, "serialize OnShutdown hook frame failed");
                            continue;
                        }
                    };
                    let header = crate::wal::HeaderBuilder::new(
                        crate::wal::events::EVENT_TYPE_HOOK_FIRED,
                        &payload,
                    )
                    .build();
                    if let Err(e) = writer.append(header, payload).await {
                        warn!(error = %e, "WAL append OnShutdown HOOK_FIRED failed");
                    } else {
                        info!(hook = name, "on_shutdown hook fired");
                    }
                }
            }
            Ok(crate::hooks::StageOutcome::Block { name, reason }) => {
                warn!(
                    hook = %name,
                    reason = %reason,
                    "on_shutdown hook returned Block; ignored (daemon is already shutting down)"
                );
            }
            Err(e) => warn!(error = %e, "OnShutdown hook dispatch failed"),
        }
    }

    // GOLD-ARCH-01: the full ordered shutdown sequence is now
    // serve_tasks::shutdown_background_tasks. Gather every background handle into
    // BackgroundHandles. The PID + Skill watcher remain bound here; audit-RPC
    // discovery was deliberately withdrawn at the shutdown decision above so
    // a dead listener can never remain advertised during the longer drain.
    let bg = crate::cli::serve_tasks::BackgroundHandles {
        plugin_invoker_registration,
        shared_provider,
        companion_state,
        worker_watch_handle,
        channel_tasks,
        channel_supervisor_task,
        dispatch_join,
        cron_task,
        cron_fleet,
        cron_supervisor_task,
        reload_controller,
        snapshot_refresh_handle,
        omi_handle,
        updater_supervisor,
        catalog_task,
        #[cfg(feature = "cluster")]
        cluster_audit_task,
        #[cfg(feature = "cluster")]
        cluster_foreign_indexer_task,
        #[cfg(feature = "cluster")]
        cluster_runtime_supervisor,
        installer_audit_task,
        credentials_import_task,
        detect_complete_task,
        self_dev_outbox_task,
        consent_outbox_task,
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
    };
    crate::cli::serve_tasks::shutdown_background_tasks(
        &neoth_home,
        &segment_chain_base_path,
        bg,
        writer,
        writer_join,
        writer_join_result,
    )
    .await?;
    anyhow::ensure!(
        !required_boundary_died,
        "required daemon persistence/authority/update boundary exited unexpectedly"
    );
    Ok(())
}

/// GOLD-COR-04 / A-11: append a SECURITY-BEARING audit frame
/// (CHANNEL_PRIVILEGE_BLOCKED, HOOK_BLOCKED, INGEST_EXTRACTED,
/// EMBED_PERSISTED, CONFIG_RELOADED). Unlike a plain best-effort
/// `writer.append`, a write failure here is NOT swallowed at `warn` level: it
/// is logged at `error!` with a uniform, greppable `audit_loss = true` + the
/// frame's `event` name, so `neoth monitor`'s rule engine can alert on a lost
/// security record instead of it vanishing into the log noise.
///
/// This is deliberately NOT hard fail-closed (operator decision 2026-06-06,
/// GOLD-COR-04): at every one of these call sites the guarded action — the
/// block / reject / drop, or the embedding persist / config reload — has
/// ALREADY completed by the time the frame is written, so aborting the
/// operation could not undo it; it would only leave incoherent post-side-effect
/// state. And because `append` fails on a full WAL quota, propagating the error
/// would turn a disk-cap into a DoS amplifier on exactly the security-relevant
/// paths. The durable fix is non-silent, monitorable audit loss — not a louder
/// failure mode for the operation itself.
///
/// GOLD-ARCH-01: `pub(crate)` so the extracted `serve_pipeline` module can reach
/// the shared helper; it stays here because `handle_reload_sentinel` (daemon
/// side) also calls it.
pub(crate) async fn emit_required_audit(
    writer: &WalWriterHandle,
    event_type: u8,
    event_name: &'static str,
    payload: Vec<u8>,
) {
    let header = crate::wal::make_header(event_type, &payload);
    if let Err(e) = writer.append(header, payload).await {
        error!(
            audit_loss = true,
            event = event_name,
            error = %e,
            "security audit frame lost — durable WAL record could not be written"
        );
    }
}

// build_pipeline_header / boot_header migrated to wal::make_header /
// wal::HeaderBuilder — Phase 33a AU-B3. Local defaults that drifted from the
// 0.5 baseline (chat=0.6, pipeline=0.6) are now uniform at builder default.

/// NEOTH-AUDIT-CRON-FLEET-LIFECYCLE-01: compute a config-spec fingerprint for
/// a fleet cron key.
///
/// Returns a `u64` that changes whenever the config fields driving that cron's
/// effective behaviour (interval, paths, flags) change, allowing the fleet
/// supervisor to restart a task whose spec changed even though its `CronKey`
/// is still in the desired set.
///
/// No locking and no side effects. Hashes only the inputs that the corresponding
/// `spawn_cron_for_key` branch captures, so an unrelated config change (e.g.
/// rotating the Telegram token) does NOT trigger spurious restarts of unrelated
/// crons. SelfMap additionally observes `NEOTH_SRC_DIR`, matching its effective
/// config-field-first source-directory resolution at spawn time.
pub(crate) fn cron_spec_fingerprint(
    key: crate::cli::serve_tasks::CronKey,
    cfg: &crate::config::FreedomConfig,
) -> u64 {
    use crate::cli::serve_tasks::CronKey::*;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut h = DefaultHasher::new();

    // For sub-structs that derive Serialize we hash their JSON representation.
    // The macro silently skips the hash contribution if serialisation fails
    // (should never happen in practice — all configs derive Serialize).
    macro_rules! jh {
        ($val:expr) => {
            if let Ok(s) = serde_json::to_string(&$val) {
                s.hash(&mut h);
            }
        };
    }

    match key {
        BgMonitor => jh!(cfg.bg_monitor),
        DoctorCron => jh!(cfg.doctor),
        Babel => jh!(cfg.babel),
        WatchdogCron => jh!(cfg.watchdog),
        DriftAlert => jh!(cfg.drift_alert),
        RecallLatency => jh!(cfg.recall_latency),
        ResourceWatch => jh!(cfg.resource_watch),
        MonitorCron => jh!(cfg.monitor),
        TokenAnomaly => jh!(cfg.token_anomaly),
        SessionHealth => jh!(cfg.session_health),
        WebhookManager => jh!(cfg.webhook_manager),
        SkillCurator => jh!(cfg.skill_curator),
        SynthesisCron => jh!(cfg.synthesis_cron),
        ConsolidationSweep => jh!(cfg.consolidation_sweep),
        SelfWiki => jh!(cfg.self_wiki),
        SelfImprovementCollector => jh!(cfg.self_improvement_collector),
        Dream => {
            jh!(cfg.dreaming);
            cfg.user_tz.hash(&mut h);
            cfg.autonomy.as_str().hash(&mut h);
            cfg.skills.auto_distill.hash(&mut h);
            cfg.obsidian_vault.hash(&mut h);
            cfg.obsidian_subdir.hash(&mut h);
            cfg.provider_model.hash(&mut h);
            jh!(cfg.inference);
        }
        EcologyCron => jh!(cfg.ecology),
        PatternCron => jh!(cfg.pattern_cron),
        ContradictionResolve => jh!(cfg.contradiction_resolve),
        GuidanceCron => jh!(cfg.guidance_cron),
        ProfileAdapt => jh!(cfg.profile_adapt),
        #[cfg(feature = "cluster")]
        ResourceSnapshot => cfg.swarm.interval_secs.hash(&mut h),
        // Obsidian crons: relevant config is scattered across individual
        // primitive fields rather than a single sub-struct — hash each directly.
        ObsidianSync => {
            cfg.obsidian_vault.hash(&mut h);
            cfg.obsidian_auto_sync_secs.hash(&mut h);
            cfg.obsidian_subdir.hash(&mut h);
        }
        ObsidianVaultReader => {
            cfg.obsidian_vault.hash(&mut h);
            cfg.obsidian_vault_reader_enabled.hash(&mut h);
            cfg.obsidian_vault_reader_secs.hash(&mut h);
        }
        ObsidianWikiRebuild => {
            cfg.obsidian_vault.hash(&mut h);
            cfg.obsidian_wiki_rebuild_secs.hash(&mut h);
            cfg.obsidian_wiki_source_dir.hash(&mut h);
        }
        SelfMap => {
            cfg.obsidian_vault.hash(&mut h);
            crate::cli::serve_tasks::effective_self_map_source_dir(cfg).hash(&mut h);
            cfg.self_map_interval_secs.hash(&mut h);
            cfg.self_map_subdir.hash(&mut h);
            cfg.self_map_label_enabled.hash(&mut h);
            cfg.self_map_label_model.hash(&mut h);
            jh!(cfg.provider_kind);
            cfg.provider_endpoint.hash(&mut h);

            // Bind credential rotation without formatting, logging, or
            // persisting the secret. `SecretString::expose()` is borrowed only
            // for the in-memory hash operation and never leaves this function.
            cfg.provider_key.is_some().hash(&mut h);
            if let Some(provider_key) = cfg.provider_key.as_ref() {
                provider_key.expose().hash(&mut h);
            }
        }
    }

    h.finish()
}

#[cfg(test)]
mod self_map_cron_fingerprint_tests {
    use super::cron_spec_fingerprint;
    use crate::cli::serve_tasks::CronKey;
    use crate::config::FreedomConfig;
    use crate::secret::SecretString;

    fn fingerprint(config: &FreedomConfig) -> u64 {
        cron_spec_fingerprint(CronKey::SelfMap, config)
    }

    fn configured_self_map() -> FreedomConfig {
        let mut config = FreedomConfig::default();
        config.obsidian_vault = Some("vault-a".to_owned());
        config.self_map_source_dir = Some("source-a".to_owned());
        config.self_map_interval_secs = Some(3_600);
        config.self_map_subdir = Some("NEOTH-Self".to_owned());
        config.self_map_label_enabled = true;
        config.self_map_label_model = Some("label-model".to_owned());
        config.provider_kind = Some(crate::cli::init::ProviderKind::OpenaiApi);
        config.provider_endpoint = Some("https://provider-a.invalid/v1".to_owned());
        config.provider_key = Some(SecretString::from("credential-a"));
        config
    }

    type ConfigChange = fn(&mut FreedomConfig);

    struct FingerprintChange {
        name: &'static str,
        prepare: ConfigChange,
        change: ConfigChange,
        env_before: &'static str,
        env_after: &'static str,
    }

    fn unchanged(_: &mut FreedomConfig) {}

    fn use_environment_source(config: &mut FreedomConfig) {
        config.self_map_source_dir = None;
    }

    fn change_configured_source(config: &mut FreedomConfig) {
        config.self_map_source_dir = Some("source-b".to_owned());
    }

    fn change_interval(config: &mut FreedomConfig) {
        config.self_map_interval_secs = Some(60);
    }

    fn change_subdir(config: &mut FreedomConfig) {
        config.self_map_subdir = Some("NEOTH-Other".to_owned());
    }

    fn disable_labeling(config: &mut FreedomConfig) {
        config.self_map_label_enabled = false;
    }

    fn change_label_model(config: &mut FreedomConfig) {
        config.self_map_label_model = Some("other-label-model".to_owned());
    }

    fn change_provider_kind(config: &mut FreedomConfig) {
        config.provider_kind = Some(crate::cli::init::ProviderKind::AnthropicApi);
    }

    fn change_provider_key(config: &mut FreedomConfig) {
        config.provider_key = Some(SecretString::from("credential-b"));
    }

    fn change_provider_endpoint(config: &mut FreedomConfig) {
        config.provider_endpoint = Some("https://provider-b.invalid/v1".to_owned());
    }

    fn change_vault(config: &mut FreedomConfig) {
        config.obsidian_vault = Some("vault-b".to_owned());
    }

    /// Restores NEOTH_SRC_DIR even when an assertion fails. Tests holding this
    /// guard must take crate::test_env::lock() before mutating the environment.
    struct EnvVarGuard {
        previous: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set(value: &str) -> Self {
            let previous = std::env::var_os("NEOTH_SRC_DIR");
            // SAFETY: the enclosing test holds crate::test_env::lock(), which
            // serializes all process-global environment mutation in this crate.
            unsafe { std::env::set_var("NEOTH_SRC_DIR", value) };
            Self { previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            // SAFETY: the guard is dropped before the enclosing test releases
            // crate::test_env::lock(), so this restoration cannot race a peer.
            unsafe {
                if let Some(value) = self.previous.as_ref() {
                    std::env::set_var("NEOTH_SRC_DIR", value);
                } else {
                    std::env::remove_var("NEOTH_SRC_DIR");
                }
            }
        }
    }

    #[test]
    fn self_map_fingerprint_binds_every_spawn_input() {
        let _env = crate::test_env::lock();
        let _source_env = EnvVarGuard::set("ambient-source");
        let cases = [
            FingerprintChange {
                name: "configured source directory",
                prepare: unchanged,
                change: change_configured_source,
                env_before: "ignored-env-source-a",
                env_after: "ignored-env-source-b",
            },
            FingerprintChange {
                name: "environment source-directory fallback",
                prepare: use_environment_source,
                change: unchanged,
                env_before: "env-source-a",
                env_after: "env-source-b",
            },
            FingerprintChange {
                name: "interval",
                prepare: unchanged,
                change: change_interval,
                env_before: "ignored-env-source-a",
                env_after: "ignored-env-source-a",
            },
            FingerprintChange {
                name: "subdirectory",
                prepare: unchanged,
                change: change_subdir,
                env_before: "ignored-env-source-a",
                env_after: "ignored-env-source-a",
            },
            FingerprintChange {
                name: "label-enabled flag",
                prepare: unchanged,
                change: disable_labeling,
                env_before: "ignored-env-source-a",
                env_after: "ignored-env-source-a",
            },
            FingerprintChange {
                name: "label model",
                prepare: unchanged,
                change: change_label_model,
                env_before: "ignored-env-source-a",
                env_after: "ignored-env-source-a",
            },
            FingerprintChange {
                name: "provider kind",
                prepare: unchanged,
                change: change_provider_kind,
                env_before: "ignored-env-source-a",
                env_after: "ignored-env-source-a",
            },
            FingerprintChange {
                name: "provider key",
                prepare: unchanged,
                change: change_provider_key,
                env_before: "ignored-env-source-a",
                env_after: "ignored-env-source-a",
            },
            FingerprintChange {
                name: "provider endpoint",
                prepare: unchanged,
                change: change_provider_endpoint,
                env_before: "ignored-env-source-a",
                env_after: "ignored-env-source-a",
            },
            FingerprintChange {
                name: "vault",
                prepare: unchanged,
                change: change_vault,
                env_before: "ignored-env-source-a",
                env_after: "ignored-env-source-a",
            },
        ];

        for case in cases {
            let mut baseline = configured_self_map();
            (case.prepare)(&mut baseline);
            // SAFETY: this whole test holds crate::test_env::lock().
            unsafe { std::env::set_var("NEOTH_SRC_DIR", case.env_before) };
            let baseline_fingerprint = fingerprint(&baseline);

            let mut changed = baseline;
            (case.change)(&mut changed);
            // SAFETY: this whole test holds crate::test_env::lock().
            unsafe { std::env::set_var("NEOTH_SRC_DIR", case.env_after) };

            assert_ne!(
                baseline_fingerprint,
                fingerprint(&changed),
                "SelfMap fingerprint must change when its {} changes",
                case.name
            );
        }
    }
}

/// Pick #37 (Session 14, Agent #4 design-consensus): process a
/// `~/.neoth/.reload-requested` sentinel. Calls `try_reload` on the
/// supplied `ReloadController`, emits one of two WAL audit frames
/// (`CONFIG_RELOADED` / `CONFIG_RELOAD_REJECTED`), and deletes the
/// sentinel regardless of outcome — so the operator's next
/// `neoth reload` is a fresh request, not a duplicate.
///
/// Best-effort: every failure path (read, parse, WAL append,
/// sentinel delete) logs at warn level + continues. The daemon's
/// receive loop must keep running even when the reload mechanism
/// itself misbehaves.
async fn claim_reload_sentinel(
    sentinel_path: &std::path::Path,
) -> std::io::Result<Option<std::path::PathBuf>> {
    let claimed_path = sentinel_path.with_file_name(format!(
        "{}.processing",
        crate::config::reload::RELOAD_SENTINEL_NAME
    ));
    // A crash after the rename leaves the claim behind. Resume that durable
    // request before consuming a newer public sentinel.
    if tokio::fs::try_exists(&claimed_path).await? {
        return Ok(Some(claimed_path));
    }
    match tokio::fs::rename(sentinel_path, &claimed_path).await {
        Ok(()) => Ok(Some(claimed_path)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub(crate) async fn handle_reload_sentinel(
    controller: &std::sync::Arc<crate::config::reload::ReloadController>,
    sentinel_path: &std::path::Path,
    writer: &crate::wal::writer::WalWriterHandle,
) {
    // Claim by atomic rename before doing any parse or audit work. A second
    // `neoth reload` can then create the public sentinel again and cannot be
    // erased by completion of this request.
    let claimed_path = match claim_reload_sentinel(sentinel_path).await {
        Ok(Some(path)) => path,
        Ok(None) => return,
        Err(error) => {
            warn!(
                %error,
                path = %sentinel_path.display(),
                "reload: could not claim sentinel"
            );
            return;
        }
    };
    // Loading and parsing freedom.yaml uses synchronous filesystem APIs. Keep
    // that work off the Tokio runtime: instance homes can live on slow or
    // temporarily unavailable network filesystems.
    let controller_for_reload = std::sync::Arc::clone(controller);
    let result = match tokio::task::spawn_blocking(move || controller_for_reload.try_reload()).await
    {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => {
            warn!(
                error = %e,
                path = %controller.source_path().display(),
                "reload: re-read freedom.yaml failed; sentinel will be deleted to prevent loop"
            );
            // Still delete the sentinel — otherwise the poll task
            // re-tries the same broken file every 2s + spams logs.
            if let Err(remove_error) = tokio::fs::remove_file(&claimed_path).await
                && remove_error.kind() != std::io::ErrorKind::NotFound
            {
                warn!(
                    error = %remove_error,
                    path = %claimed_path.display(),
                    "reload sentinel delete failed after reload read error"
                );
            }
            return;
        }
        Err(e) => {
            warn!(
                error = %e,
                path = %controller.source_path().display(),
                "reload: config reload worker failed; sentinel will be deleted to prevent loop"
            );
            if let Err(remove_error) = tokio::fs::remove_file(&claimed_path).await
                && remove_error.kind() != std::io::ErrorKind::NotFound
            {
                warn!(
                    error = %remove_error,
                    path = %claimed_path.display(),
                    "reload sentinel delete failed after reload worker failure"
                );
            }
            return;
        }
    };
    let ts_unix = crate::time::now_unix_secs();
    match result {
        crate::config::reload::ReloadResult::Reloaded { changed_fields } => {
            info!(
                changed = ?changed_fields,
                source = %controller.source_path().display(),
                "config hot-reloaded"
            );
            let payload = serde_json::json!({
                "changed_fields": changed_fields,
                "source_path": controller.source_path().display().to_string(),
                "ts_unix": ts_unix,
            });
            if let Ok(bytes) = serde_json::to_vec(&payload) {
                emit_required_audit(
                    writer,
                    crate::wal::events::EVENT_TYPE_CONFIG_RELOADED,
                    "CONFIG_RELOADED",
                    bytes,
                )
                .await;
            }
            // GOLD-FEAT-07b — dedicated moral-core kill-switch audit. The generic
            // CONFIG_RELOADED above already lists "moral_core" in changed_fields, but
            // the moral core is the sovereign position-0 directive layer, so its
            // enable/disable gets its own greppable WAL anchor carrying the resulting
            // on/off state (read from the just-swapped live config).
            if changed_fields.iter().any(|f| f == "moral_core") {
                let enabled = controller.latest().moral_core.enabled;
                let mc_payload = serde_json::json!({ "enabled": enabled, "ts_unix": ts_unix });
                if let Ok(bytes) = serde_json::to_vec(&mc_payload) {
                    emit_required_audit(
                        writer,
                        crate::wal::events::EVENT_TYPE_MORAL_CORE_TOGGLED,
                        "MORAL_CORE_TOGGLED",
                        bytes,
                    )
                    .await;
                }
            }
        }
        crate::config::reload::ReloadResult::Rejected { rejection } => {
            let reason = rejection.to_string();
            let restart_required = rejection.restart_required();
            let reason_codes = rejection.reason_codes();
            warn!(
                reason = %reason,
                restart_required,
                source = %controller.source_path().display(),
                "config reload REJECTED — immutable field changed; daemon stays on prior config"
            );
            let payload = serde_json::json!({
                "reason": reason,
                "reason_codes": reason_codes,
                "restart_required": restart_required,
                "source_path": controller.source_path().display().to_string(),
                "ts_unix": ts_unix,
            });
            if let Ok(bytes) = serde_json::to_vec(&payload) {
                let header = crate::wal::HeaderBuilder::new(
                    crate::wal::events::EVENT_TYPE_CONFIG_RELOAD_REJECTED,
                    &bytes,
                )
                .build();
                if let Err(e) = writer.append(header, bytes).await {
                    warn!(error = %e, "CONFIG_RELOAD_REJECTED WAL append failed (best-effort audit)");
                }
            }
        }
        crate::config::reload::ReloadResult::Unchanged => {
            debug!(
                source = %controller.source_path().display(),
                "config reload triggered but file content matches live config — no-op"
            );
            // No WAL frame for the no-op case. Operator triggered a
            // reload but didn't actually edit anything; spamming the
            // audit log would dilute the signal.
        }
    }
    if let Err(e) = tokio::fs::remove_file(&claimed_path).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        warn!(
            error = %e,
            path = %claimed_path.display(),
            "reload sentinel delete failed; next poll tick may double-fire"
        );
    }
}

#[cfg(test)]
mod reload_sentinel_claim_tests {
    use super::claim_reload_sentinel;

    #[tokio::test]
    async fn a_new_reload_request_survives_completion_of_the_claimed_request() {
        let home = tempfile::tempdir().unwrap();
        let sentinel = home
            .path()
            .join(crate::config::reload::RELOAD_SENTINEL_NAME);
        tokio::fs::write(&sentinel, b"request-one").await.unwrap();

        let claimed = claim_reload_sentinel(&sentinel)
            .await
            .unwrap()
            .expect("first request claimed");
        assert!(!tokio::fs::try_exists(&sentinel).await.unwrap());
        tokio::fs::write(&sentinel, b"request-two").await.unwrap();

        tokio::fs::remove_file(&claimed).await.unwrap();
        assert!(
            tokio::fs::try_exists(&sentinel).await.unwrap(),
            "finishing request one must not delete request two"
        );
        assert_eq!(
            claim_reload_sentinel(&sentinel)
                .await
                .unwrap()
                .expect("second request claimed"),
            claimed
        );
    }

    #[tokio::test]
    async fn an_interrupted_claim_is_resumed_after_restart() {
        let home = tempfile::tempdir().unwrap();
        let sentinel = home
            .path()
            .join(crate::config::reload::RELOAD_SENTINEL_NAME);
        tokio::fs::write(&sentinel, b"request").await.unwrap();
        let claimed = claim_reload_sentinel(&sentinel).await.unwrap().unwrap();

        assert_eq!(
            claim_reload_sentinel(&sentinel).await.unwrap(),
            Some(claimed),
            "a crash-retained processing marker remains a durable request"
        );
    }
}

// ── Reload schedule unit tests ─────────────────────────────────────────────────
#[cfg(test)]
mod email_ingest_schedule_tests {
    use super::email_ingest_schedule_change;
    use crate::config::EmailIngestCronConfig;
    use std::time::Duration;

    #[test]
    fn reload_resets_ticker_for_cadence_changes_and_enable_edges() {
        let mut live = EmailIngestCronConfig::default();
        live.interval_secs = 60;
        assert_eq!(
            email_ingest_schedule_change(false, Duration::from_secs(300), &live),
            Some(Duration::from_secs(60)),
            "a shorter disabled cadence must be remembered before enable"
        );

        live.interval_secs = 300;
        live.enabled = true;
        assert_eq!(
            email_ingest_schedule_change(false, Duration::from_secs(300), &live),
            Some(Duration::from_secs(300)),
            "enabling must schedule an immediate first poll"
        );
        assert_eq!(
            email_ingest_schedule_change(true, Duration::from_secs(300), &live),
            None,
            "an unchanged live schedule must not churn the ticker"
        );
    }
}

// ── ZF-07 boot-stagger unit tests ─────────────────────────────────────────────
#[cfg(test)]
mod boot_stagger_tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::{CRON_FIRST_TICK_WINDOW, START_STAGGER_PERMITS};

    /// Proves that the boot-stagger semaphore bounds concurrent cron cold-starts
    /// to at most `START_STAGGER_PERMITS` (ZF-07 correctness).
    ///
    /// Spawns `START_STAGGER_PERMITS * 3` tasks (three full batches).  Each task
    /// mirrors the seed-loop pattern: acquire an owned permit, record peak
    /// concurrency, do brief "first-tick" work, then release.  The observed peak
    /// must never exceed the ceiling.
    #[tokio::test]
    async fn boot_stagger_bounds_concurrent_first_ticks() {
        let sem = Arc::new(tokio::sync::Semaphore::new(START_STAGGER_PERMITS));
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let n_tasks = START_STAGGER_PERMITS * 3;
        let mut handles = Vec::with_capacity(n_tasks);
        for _ in 0..n_tasks {
            let sem = Arc::clone(&sem);
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            handles.push(tokio::spawn(async move {
                // Mirror the seed loop: acquire one permit before "first tick".
                let _permit = sem.acquire_owned().await.expect("semaphore closed");
                let cur = active.fetch_add(1, Ordering::AcqRel) + 1;
                // Track peak via CAS loop (avoids a separate mutex).
                let mut p = peak.load(Ordering::Acquire);
                while p < cur {
                    match peak.compare_exchange_weak(p, cur, Ordering::AcqRel, Ordering::Acquire) {
                        Ok(_) => break,
                        Err(actual) => p = actual,
                    }
                }
                // Simulate first-tick work (much shorter than CRON_FIRST_TICK_WINDOW
                // so the test finishes quickly while still proving concurrency).
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                active.fetch_sub(1, Ordering::AcqRel);
                // _permit drops here — releases the semaphore slot.
            }));
        }
        for h in handles {
            h.await.expect("task panicked");
        }
        let observed = peak.load(Ordering::Acquire);
        // The semaphore ceiling must hold.
        assert!(
            observed <= START_STAGGER_PERMITS,
            "peak concurrent first-ticks {observed} must not exceed \
             START_STAGGER_PERMITS={START_STAGGER_PERMITS}",
        );
    }

    /// Sanity: CRON_FIRST_TICK_WINDOW is non-zero (a zero window would release
    /// the permit immediately, making the stagger a no-op).
    #[test]
    fn cron_first_tick_window_is_positive() {
        assert!(
            !CRON_FIRST_TICK_WINDOW.is_zero(),
            "CRON_FIRST_TICK_WINDOW must be > 0 or the stagger is a no-op",
        );
    }
}

#[cfg(test)]
mod cron_supervisor_health_tests {
    use super::{CronSupervisorWake, dream_needs_generation_restart, next_cron_supervisor_wake};

    #[tokio::test]
    async fn health_wake_occurs_without_reload_generation_change() {
        let (_generation_tx, mut generation_rx) = tokio::sync::watch::channel(0u64);
        let mut health = tokio::time::interval(std::time::Duration::from_millis(1));
        health.tick().await; // consume Interval's immediate first tick

        let wake = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            next_cron_supervisor_wake(&mut generation_rx, &mut health),
        )
        .await
        .expect("health wake timed out");
        assert_eq!(wake, Some(CronSupervisorWake::Health));
    }

    #[test]
    fn dream_restarts_only_for_an_accepted_generation_change() {
        assert!(dream_needs_generation_restart(
            CronSupervisorWake::Reload,
            true,
            true
        ));
        assert!(!dream_needs_generation_restart(
            CronSupervisorWake::Health,
            true,
            true
        ));
        assert!(!dream_needs_generation_restart(
            CronSupervisorWake::Reload,
            false,
            true
        ));
        assert!(!dream_needs_generation_restart(
            CronSupervisorWake::Reload,
            true,
            false
        ));
    }
}

#[cfg(test)]
#[path = "serve_tests.rs"]
mod tests;
