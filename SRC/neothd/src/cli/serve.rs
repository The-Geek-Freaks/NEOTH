//! `neoth serve` — daemon entry. Reads freedom.yaml, opens WAL, awaits shutdown.
//!
//! D-1..D-4 acceptance:
//!   - reads ~/.neoth/freedom.yaml (D-2)
//!   - spawns the WAL writer task on ~/.neoth/wal/000001.wal (D-3)
//!   - emits a BOOT event (event_type 0x10) on startup
//!   - blocks until SIGTERM / Ctrl+C, then drains and exits 0 (D-4)
//!
//! Day-5+ pipelines (channel adapters, LLM provider calls) plug into this
//! same task. For Day-4 the daemon is intentionally minimal: open WAL, write
//! BOOT, idle until shutdown.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Args;
use tracing::{debug, error, info, warn};

use crate::channels::{Channel, PipelineHandler, telegram::TelegramChannel};
use crate::config::FreedomConfig;
use crate::memory::{indexer, store};
use crate::providers::{self, Provider};
use crate::shutdown;
use crate::wal::events::EVENT_TYPE_BOOT;
use crate::wal::writer::WalWriterHandle;
use crate::wal::{EventFlags, spawn as wal_spawn};

// GOLD-ARCH-01: the channel-side inbound pipeline now lives in `serve_pipeline`.
use crate::cli::serve_pipeline::{PipelineHandlerDeps, build_pipeline_handler};

#[derive(Args, Debug, Clone)]
pub struct ServeArgs {
    /// Override the path to freedom.yaml. Defaults to ~/.neoth/freedom.yaml.
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Override the WAL segment path. Defaults to ~/.neoth/wal/000001.wal.
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
    // ── 0. Home-dir isolation (Phase 33c BS-9) ──────────────────────────────
    // Refuse to start if `~/.neoth/` is readable by other users on this
    // host. WAL frames + ground-truth rows are operator-private.
    //
    // One-shot mode (smoke checks + integration tests) skips this guard
    // for the same reason it skips the PID lock at line 84: those run
    // against ephemeral tempdirs or shared CI runners where the home
    // dir's permissions are out of NEOTH's control. The long-lived
    // daemon path is the only place the invariant matters.
    if !args.one_shot {
        crate::daemon::isolation::check_home_isolation(&FreedomConfig::default_neoth_home())?;
    }

    // ── 0a. Clock rollback guard (Phase 33c BS-5) ───────────────────────────
    // Bail before any WAL write if the system clock is far behind the
    // last observed timestamp. Operator can pass --allow-clock-rollback
    // when intentional (backup restore, snapshot rewind).
    if !args.allow_clock_rollback {
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
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
    // Acquire ~/.neoth/neothd.pid BEFORE touching the WAL — a second daemon
    // writing the same segment would corrupt the byte stream. Stale-PID
    // (process gone) is taken over silently; live-PID aborts startup.
    // Skipped under --one-shot so integration tests can run in parallel.
    let _pid_guard = if args.one_shot {
        None
    } else {
        match crate::daemon::pidfile::acquire(&crate::daemon::pidfile::default_pidfile()) {
            Ok(g) => Some(g),
            Err(e) => {
                anyhow::bail!("{e}");
            }
        }
    };

    // ── 1. Load config ──────────────────────────────────────────────────────
    let config = match &args.config {
        Some(p) => FreedomConfig::load_from_path(p)?,
        None => FreedomConfig::load_from_default_path()?,
    };
    info!(
        operator = config.operator_id.as_deref().unwrap_or("(unset)"),
        provider = ?config.provider_kind,
        "loaded freedom.yaml"
    );

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

    // ── 1a. Plugin discovery + invoker registration (Pick #34 follow-up) ───
    //
    // Discover `~/.neoth/plugins/<id>/`, compile each .wasm, register the
    // resulting CompiledPluginInvoker as the process-wide hook invoker.
    // Failure on any individual plugin logs a warn + continues (operator
    // sees the cause in `neoth plugins list` separately); a missing
    // plugin dir is silently fine.
    //
    // Feature-gated so the slim daemon (no wasm-plugin-host) skips the
    // whole block without an `unused_imports` warning. Runtime gate
    // via `config.plugins.wasm.enabled` (NOOB-UX-3) — operator on a
    // wasm-plugin-host-compiled release can still disable plugins
    // via freedom.yaml without recompiling.
    //
    // SC-04: the actual `bootstrap_plugin_invoker` call moved DOWN to
    // after the WAL writer is spawned (step 3) — the invoker needs a
    // clone of the daemon's single writer so a denied plugin hostcall
    // emits its 0xC7 PLUGIN_CAP_DENIED audit frame. Bootstrapping here
    // (before the writer existed) left the production audit hollow.

    // V03-08 + A-2 preflight: daemon has no TTY so `ensure_all_granted_or_prompt`
    // bails with an actionable error if any cloud provider in the
    // operator's freedom.yaml is not yet consented. Covers both the
    // legacy single-mode `provider_kind` AND the per-hemisphere
    // providers in `inference.{left,right,cerebellum}` (A-2 closes the
    // bypass). Operator runs `neoth consent grant <provider>` once per
    // missing provider + re-launches `neoth serve`. `NEOTH_CONSENT_BYPASS=1`
    // skips the gate for CI / scripted bring-up. LocalQwen + Skip never gate.
    {
        let home = FreedomConfig::default_neoth_home();
        crate::consent::ensure_all_granted_or_prompt(&home, &config)
            .context("consent gate (V03-08 + A-2)")?;
    }

    // E-22 chat-route (Session 21, 2026-05-23): prime the process-wide
    // SkillRegistry + start its filesystem watcher BEFORE any
    // request-handling tasks spawn. Every in-daemon chat path reads
    // through `crate::skills::registry::global()`, so once this fires
    // operator edits to `~/.neoth/skills/<id>/skill.yaml` propagate to
    // the next chat turn without a daemon restart (250ms debounce).
    // Watcher handle is intentionally leaked: daemon lifetime owns it,
    // tear-down on process exit is fine.
    let _skill_watcher = {
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
    // drainer BEFORE any request-handling task can produce events. Council
    // hemisphere calls fire `ProviderResponded` into it; the UsageMeter folds the
    // token counts into the running KF-08 budget total (read via
    // `domain_events::global_meter_snapshot()`; the GUI display is WIRE-10b).
    if !crate::domain_events::init_global() {
        warn!("domain-event bus already installed earlier in this process");
    }

    // ── 2. Prepare WAL directory + segment ──────────────────────────────────
    let wal_dir = FreedomConfig::default_wal_dir();
    let segment_path = args
        .wal_segment
        .clone()
        .unwrap_or_else(|| wal_dir.join("000001.wal"));

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
    // SPEC §4.3: before the writer opens any segment, walk the WAL dir for
    // crash-recovery compaction files left behind by the previous run.
    // Valid pairs are renamed `.cpt → .bin` (with `.cpt.hmac` deleted);
    // tampered / unauthenticated pairs are quarantined to `.cpt.rejected.<ts>`
    // and surfaced via an `EVENT_TYPE_COMPACTION_AUTH_FAILED` (0x51) frame
    // once the writer is up below. Closes the pre-ADV-01 attack window
    // where local file-write access let an attacker inject crafted
    // `PROFILE_DELTA` / tombstone frames into the recovered segment.
    let pending_auth_failures: Vec<crate::wal::cpt_recovery::ScanReport> = {
        let key_path = crate::wal::compaction::default_key_path();
        match crate::wal::compaction::load_or_init_key(&key_path) {
            Ok(master) => {
                let auth = crate::wal::cpt_auth::CompactionAuthenticator::from_master_key(&master);
                match crate::wal::cpt_recovery::scan_and_apply(&wal_dir, &auth, || {
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0)
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
    let (writer, mut writer_join) =
        wal_spawn(segment_path.clone()).context("spawn WAL writer task")?;

    // ── 3b. ADV-01 — emit deferred audit frames for quarantined `.cpt`s ────
    // Scan ran in step 2b before the writer existed; flush each
    // quarantine event into the now-live WAL chain so operators see the
    // rejection in `neoth wal show`. Best-effort: a writer hiccup here
    // never blocks the daemon — startup is operator-visible enough.
    for report in pending_auth_failures {
        for quarantine_path in report.quarantined {
            let now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
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
    // Ceiling defaults to 5 GiB; operator can lower via env override
    // `NEOTH_QUOTA_CEILING_BYTES` (Phase 3 will surface a YAML field).
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

    // ── 3c. Plugin invoker bootstrap (SC-04) ───────────────────────────────
    // Deferred from step 1a so the invoker carries a clone of the live
    // WAL writer: a denied plugin hostcall must emit its 0xC7
    // PLUGIN_CAP_DENIED audit frame, and a used capability its 0xC4/0xC6
    // frame, into the SAME segment the daemon writes. Reusing the writer
    // handle (not spawning a second one) keeps the single-writer
    // invariant that the WAL segment depends on.
    #[cfg(feature = "wasm-plugin-host")]
    {
        if config.plugins.wasm.enabled {
            bootstrap_plugin_invoker(&FreedomConfig::default_neoth_home(), writer.clone());
        } else {
            info!(
                "freedom.yaml::plugins.wasm.enabled = false; skipping plugin discovery + invoker bootstrap"
            );
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
    let boot_payload = build_boot_payload(&config)?;
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
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    // Pick #35 (Session 14, silent-failure audit-fix #4): clock-floor
    // is the anti-rollback mechanism that protects WAL replay ordering
    // on the next daemon start. Prior `let _ = ...` swallowed write
    // failures silently — operator would never know the floor wasn't
    // persisted, and a subsequent power loss could let replayed events
    // from before the current epoch slip through undetected. Surface
    // the failure at warn level so it shows up in journald / event
    // log, while still letting the daemon proceed (the in-memory
    // clock is correct for the current run).
    if let Err(e) = crate::daemon::clock_floor::persist_floor(
        &crate::daemon::clock_floor::default_floor_path(),
        now_ns,
    ) {
        warn!(
            error = %e,
            now_ns,
            "persist clock_floor failed at startup — next start cannot detect a \
             pre-this-run rollback; check disk permissions on ~/.neoth/clock.floor",
        );
    }

    if args.one_shot {
        info!("--one-shot: closing writer and exiting");
        drop(writer);
        writer_join.await.ok();
        return Ok(());
    }

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
    // Best-effort: failure to open views.db or to drain leaves the
    // surviving rows for the next startup. The daemon proceeds either
    // way — a stuck drain must not block boot.
    //
    // Pick #38 (Session 14, Agent #4 design-consensus, Perf #11 fix):
    // hold the post-drain connection alive in an `Arc<tokio::sync::
    // Mutex<Connection>>` so the per-message profile pipeline at
    // line ~1700 can reuse it instead of re-opening views.db every
    // inbound. Each open hits the WAL pragma stack + integrity_check
    // (Pick #34 fix M) — ~10ms blocking overhead × every Telegram /
    // WhatsApp / Slack message at the channel's hot path.
    //
    // None = open or drain failed at startup; per-message handler
    // falls back to per-message open so the channel path still works
    // even when the shared connection couldn't be established.
    let shared_views_conn: Option<Arc<tokio::sync::Mutex<rusqlite::Connection>>> = {
        let views_path = store::default_path();
        match store::open(&views_path) {
            Ok(mut conn) => {
                match crate::profile::apply::drain_outbox_all(&mut conn, &writer).await {
                    Ok(0) => {}
                    Ok(n) => {
                        info!(
                            replayed = n,
                            "profile.outbox: startup drain replayed stranded rows"
                        );
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            "profile.outbox: startup drain failed; rows will replay on next start",
                        );
                    }
                }
                // Drain succeeded (or partial) — promote to shared
                // mutex for the per-message handler's reuse.
                Some(Arc::new(tokio::sync::Mutex::new(conn)))
            }
            Err(e) => {
                warn!(
                    error = %e,
                    path = %views_path.display(),
                    "profile.outbox: cannot open views.db for startup drain (non-fatal); per-message handler will fall back to per-call open",
                );
                None
            }
        }
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
    // sentinel file at `~/.neoth/.reload-requested` → this daemon-
    // side task polls for the sentinel every 2s. On present:
    // re-read freedom.yaml, validate against immutable fields, swap
    // the ArcSwap atomically (or reject), emit a CONFIG_RELOADED /
    // CONFIG_RELOAD_REJECTED WAL audit frame, delete the sentinel.
    //
    // The ArcSwap doesn't propagate to live channel-pipeline closures
    // yet — they still capture the original `Arc<FreedomConfig>`.
    // That follow-up swaps `PipelineHandlerDeps` to hold the
    // `ReloadController` so each ingress message reads the latest
    // snapshot. For now the value is: audit-evidence + at-boot
    // pickup when an operator runs `neoth reload` against a stopped
    // daemon and the sentinel waits for the next `neoth serve`.
    let reload_controller = std::sync::Arc::new(crate::config::reload::ReloadController::new(
        config.clone(),
        match &args.config {
            Some(p) => p.clone(),
            None => FreedomConfig::default_path(),
        },
    ));
    // At-boot one-shot: if a sentinel is already on disk (operator
    // ran `neoth reload` against a stopped daemon), process it now
    // before the indexer + handler-spawn use the controller.
    {
        let sentinel =
            FreedomConfig::default_neoth_home().join(crate::config::reload::RELOAD_SENTINEL_NAME);
        if sentinel.exists() {
            handle_reload_sentinel(&reload_controller, &sentinel, &writer).await;
        }
    }
    let reload_task = {
        let ctrl = std::sync::Arc::clone(&reload_controller);
        let writer_for_reload = writer.clone();
        let home = FreedomConfig::default_neoth_home();
        let sentinel = home.join(crate::config::reload::RELOAD_SENTINEL_NAME);
        tokio::spawn(async move {
            // 2s polling interval — cheap stat call; the sentinel is
            // usually absent. Tight enough that a manual `neoth reload`
            // feels responsive (P95 latency ~1s).
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                if sentinel.exists() {
                    handle_reload_sentinel(&ctrl, &sentinel, &writer_for_reload).await;
                }
            }
        })
    };

    let indexer_task = {
        let conn_path = store::default_path();
        let seg = segment_path.clone();
        match store::open(&conn_path) {
            Ok(conn) => Some(tokio::spawn(async move {
                if let Err(e) =
                    indexer::tail(conn, seg, std::time::Duration::from_millis(500)).await
                {
                    tracing::error!(error = %e, "indexer tail task exited with error");
                }
            })),
            Err(e) => {
                warn!(error = %e, "failed to open views.db; recall queries will run an index pass each time");
                None
            }
        }
    };

    // ── 5a-kanban. Stale-planning reaper — HO-02 (Session 28) ──────────────
    //
    // Cerebellum opens a session row + decomposes via LLM before
    // flipping to Running. A dispatcher crash / daemon restart
    // mid-decompose leaves the row stuck in Planning forever — the
    // operator sees it on `neoth kanban list` but no worker will
    // ever pick it up. Sweep on each daemon startup so the operator
    // sees a clean slate.
    //
    // 1-hour cut-off is well past the longest legitimate decompose
    // (Cerebellum LLM call + JSON parse + per-task insert; ~90s on
    // cold local Qwen). Best-effort: failure to open views.db here
    // is logged and continues — the reaper is hygiene, not load-
    // bearing on liveness.
    {
        const STALE_CUTOFF_NS: u64 = 3_600 * 1_000_000_000;
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        match store::open(&store::default_path()) {
            Ok(conn) => {
                // ensure_schema is idempotent + cheap; covers the
                // fresh-install case where the kanban tables haven't
                // been created yet.
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

    // ── 5a-creds. Startup credential-pattern audit (HO-06) ─────────────────
    //
    // Walks `~/.neoth/policy.yaml::startup_audit_scan_paths` for
    // `ghp_` / `sk-` / `AKIA` / Bearer shapes + (when
    // `forbid_inline_tokens_in_remotes`) `git remote -v` for inline
    // `user:token@host` URLs. Warn-only — never fails boot. Empty
    // scan-paths + flag-off → silent no-op.
    //
    // Best-effort: policy.yaml load failure or scanner errors log
    // warn + continue. This is hygiene + recommendation, not load-
    // bearing on liveness.
    match crate::policy::PolicyConfig::load() {
        Ok(policy) => {
            if !policy.startup_audit_scan_paths.is_empty() || policy.forbid_inline_tokens_in_remotes
            {
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
        }
        Err(e) => {
            warn!(error = %e, "policy.yaml load failed; skipping startup credential audit");
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
                Ok(sup) => {
                    let port = sup.socks_port;
                    // Give the subprocess a beat to bind.
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                    match crate::transport::hysteria::probe_socks_port(port).await {
                        Ok(()) => {
                            // R-3 Phase 3b helper — single source of truth
                            // for the SOCKS5 URL + NEOTH_HTTP_PROXY env
                            // write. No provider client built yet (next
                            // block constructs them) so the env-write
                            // beats every reqwest::Client::builder call.
                            let proxy_url = sup.install_as_process_proxy();
                            info!(
                                proxy = %proxy_url,
                                "Hysteria SOCKS5 up; routing provider HTTP through it",
                            );
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
        match providers::fallback_chain_from_config(&config, Some(writer.clone())).await {
            Ok(p) => Some(Arc::from(p)),
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
    let mut channel_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    // COR-34: shared JoinSet tracking the detached, DISPATCH_GATE-bounded Meta
    // webhook fan-out tasks. The WhatsApp listener spawns each dispatch into it
    // (via WebhookListenerConfig::dispatch_join); the shutdown sequence drains it
    // — with a bounded timeout, then abort — BEFORE drop(writer), so in-flight
    // pipeline turns flush their WAL frames deterministically instead of relying
    // on the dispatch task's accidental WalWriterHandle-clone refcount (which
    // could otherwise hang shutdown on a slow turn).
    let dispatch_join: std::sync::Arc<tokio::sync::Mutex<tokio::task::JoinSet<()>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(tokio::task::JoinSet::new()));
    if let (Some(telegram_token), Some(provider)) =
        (config.telegram_token.clone(), shared_provider.as_ref())
    {
        let writer_for_handler = writer.clone();
        let operator_id = config.operator_id.clone();
        let handler: PipelineHandler = build_pipeline_handler(PipelineHandlerDeps {
            provider: provider.clone(),
            writer: writer_for_handler,
            operator_id,
            autonomy: config.autonomy,
            goal_max_turns: config.goal.max_turns,
            meter: provider_meter.clone(),
            rate_limiter: Arc::clone(&rate_limiter),
            segment_path: segment_path.clone(),
            profile_config: config.profile.clone(),
            reload_controller: Arc::clone(&reload_controller),
            views_conn: shared_views_conn.clone(),
        });
        // SF-03: hand the adapter the daemon's WAL writer so allowlist-
        // rejected senders are audited via `0x3B CHANNEL_GATE_REJECTED`
        // (the daemon is the single writer; this is a cheap handle clone).
        let channel = TelegramChannel::new(telegram_token, config.telegram_user_id)
            .with_gate_writer(writer.clone());
        let task = tokio::spawn(async move {
            if let Err(e) = channel.run(handler).await {
                tracing::error!(error = %e, "Telegram channel task exited with error");
            }
        });
        channel_tasks.push(task);
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

    // ── R4-P1 honest channel-bootstrap status logging ─────────────────────
    //
    // Per `PLAN/REEVALUATION_GESAMT_2026-05-22_R4.md` P1: every channel
    // gets an explicit log line at boot so `neoth doctor channels`'s
    // honest classification matches what `neoth serve` actually did.
    // No silent failures, no "looks like everything started but
    // half the channels are scaffolds".
    //
    // Implementation matches the R2-P0-2 doctor classification:
    //   LIVE = adapter has live inbound + serve spawns it
    //   OUTBOUND-ONLY = send_text works, no inbound receive loop
    //   CONFIGURED-NOT-STARTED = full inbound code exists but serve
    //                            does not yet bootstrap it
    //   absent = no credentials configured (silent)
    let creds = crate::config::credentials::Credentials::load_or_default(
        &crate::config::credentials::default_path(),
    )
    .unwrap_or_default();
    // Slack socket-mode inbound — spawns the WebSocket receive loop when
    // both bot + app tokens are configured. Requires a provider so the
    // pipeline can answer; otherwise log CONFIGURED-NOT-STARTED.
    match (
        creds.slack_bot_token.clone(),
        creds.slack_app_token.clone(),
        shared_provider.as_ref(),
    ) {
        (Some(bot), Some(app), Some(provider)) => {
            let handler: PipelineHandler = build_pipeline_handler(PipelineHandlerDeps {
                provider: provider.clone(),
                writer: writer.clone(),
                operator_id: config.operator_id.clone(),
                autonomy: config.autonomy,
                goal_max_turns: config.goal.max_turns,
                meter: provider_meter.clone(),
                rate_limiter: Arc::clone(&rate_limiter),
                segment_path: segment_path.clone(),
                profile_config: config.profile.clone(),
                reload_controller: Arc::clone(&reload_controller),
                views_conn: shared_views_conn.clone(),
            });
            let channel = crate::channels::slack::SlackChannel::new(bot, app);
            let task = tokio::spawn(async move {
                if let Err(e) = channel.run(handler).await {
                    tracing::error!(error = %e, "Slack channel task exited with error");
                }
            });
            channel_tasks.push(task);
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

    // WhatsApp inbound via Meta webhook listener — spawns when phone-id +
    // verify-token + app-secret + provider are all present. Listens on
    // 127.0.0.1:<whatsapp_webhook_port> (default 8443); the operator's
    // reverse proxy terminates TLS and forwards `/webhook` here.
    let whatsapp_inbound_started = match (
        creds.whatsapp_token.clone(),
        creds.whatsapp_phone_id.clone(),
        creds.whatsapp_verify_token.clone(),
        creds.whatsapp_app_secret.clone(),
        shared_provider.as_ref(),
    ) {
        (Some(token), Some(phone), Some(verify), Some(secret), Some(provider)) => {
            let handler: PipelineHandler = build_pipeline_handler(PipelineHandlerDeps {
                provider: provider.clone(),
                writer: writer.clone(),
                operator_id: config.operator_id.clone(),
                autonomy: config.autonomy,
                goal_max_turns: config.goal.max_turns,
                meter: provider_meter.clone(),
                rate_limiter: Arc::clone(&rate_limiter),
                segment_path: segment_path.clone(),
                profile_config: config.profile.clone(),
                reload_controller: Arc::clone(&reload_controller),
                views_conn: shared_views_conn.clone(),
            });
            let port = config.whatsapp_webhook_port.unwrap_or(8443);
            let bind: std::net::SocketAddr = format!("127.0.0.1:{port}")
                .parse()
                .expect("static bind addr parses");
            // GR-01 Pick B: thread the Graph API send creds into the
            // listener so the dispatch path can route pipeline replies
            // back through Meta instead of logging+dropping them.
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
                // P0 — gate + audit the WhatsApp webhook reply send. The daemon
                // owns the WAL writer; evaluate the channel-send permission once
                // under the active autonomy; honour the proof-hardline
                // required-audit switch (a send that can't be audited is then
                // refused fail-closed).
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
                dispatch_join: Some(std::sync::Arc::clone(&dispatch_join)),
            };
            let task = tokio::spawn(async move {
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
    // Discord + Keet have no credential fields in credentials.yaml yet
    // — when they land, the same explicit-log pattern fires.

    // ── 5b-tris. Obsidian vault auto-sync (R-5 follow-up) ──────────────────
    //
    // Spawned only when freedom.yaml has `obsidian_vault` set. Mirrors the
    // archive into the operator's vault on a schedule. Off by default.
    let obsidian_task: Option<tokio::task::JoinHandle<anyhow::Result<()>>> =
        if let Some(vault_str) = config.obsidian_vault.as_deref() {
            let vault = std::path::PathBuf::from(vault_str);
            let subdir = config.obsidian_subdir.clone();
            let interval = config
                .obsidian_auto_sync_secs
                .map(std::time::Duration::from_secs);
            Some(crate::cli::obsidian_sync_task::spawn(
                None, vault, subdir, interval,
            ))
        } else {
            None
        };

    // ── 5b-quad. Cloud archive auto-mirror (R-8) ───────────────────────────
    //
    // Off by default. When freedom.yaml::cloud_archive_dest is set,
    // periodically mirror the session archive into a subdir of that
    // folder. The operator's cloud vendor desktop client picks the
    // delta up + uploads.
    let cloud_task: Option<tokio::task::JoinHandle<anyhow::Result<()>>> =
        if let Some(dest_str) = config.cloud_archive_dest.as_deref() {
            let dest = std::path::PathBuf::from(dest_str);
            let subdir = config.cloud_archive_subdir.clone();
            let interval = config
                .cloud_archive_auto_sync_secs
                .map(std::time::Duration::from_secs);
            Some(crate::cli::cloud_sync_task::spawn(
                None, dest, subdir, interval,
            ))
        } else {
            None
        };

    // ── 5b-pent. R-02 Phase 4c — dreaming nightly task ─────────────────────
    //
    // Off by default. When freedom.yaml::dreaming.enabled = true,
    // composes one batch of dreams per interval (default 24h) over a
    // 24h window. Uses `compose_dreams_with_embeddings` when an
    // `inference.embedding_provider` is wired + buildable; falls back
    // to deterministic `compose_dream` per L-07 safe-default when
    // not. Errors log + retry next tick; never crashes the daemon.
    let dreaming_task: Option<tokio::task::JoinHandle<anyhow::Result<()>>> =
        if config.dreaming.enabled {
            let embed_provider = crate::providers::embed_provider_from_config(&config).await;
            // SPEC-12 Phase 4b — only hand the chat provider to the dreaming
            // task when `dreaming.summarize_themes` is on (cost-safe gate: it
            // adds one LLM call per cluster). Reuses the already-built shared
            // provider chain; `None` keeps deterministic cluster labels.
            let dream_chat = if config.dreaming.summarize_themes {
                shared_provider.as_ref().map(Arc::clone)
            } else {
                None
            };
            Some(crate::cli::dreaming_task::spawn(
                crate::config::FreedomConfig::default_neoth_home(),
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
                // SPEC-12 daemon-side audit: the daemon owns the WAL writer, so
                // each non-empty nightly pass emits a `0xF4 DREAM_COMPOSED` frame.
                Some(writer.clone()),
            ))
        } else {
            None
        };

    // ── 5b-arxiv. EL-02 arXiv topic-feed ingest task ───────────────────────
    //
    // Off by default. When freedom.yaml::arxiv.enabled = true AND
    // arxiv.topics is non-empty, runs each topic query on a cadence
    // (default 6h), optionally LLM-summarises each abstract via the
    // shared provider, and lands the result in the ctx knowledge store.
    // A topic fetch failure logs + skips; a pass failure logs + retries
    // next tick — never crashes the daemon.
    let arxiv_ingest_task: Option<tokio::task::JoinHandle<anyhow::Result<()>>> =
        if config.arxiv.enabled && !config.arxiv.topics.is_empty() {
            info!(
                topics = config.arxiv.topics.len(),
                "arxiv ingest task enabled"
            );
            Some(crate::cli::arxiv_ingest_task::spawn(
                crate::config::FreedomConfig::default_neoth_home(),
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
        store::default_path(),
        crate::memory::decay_task::DEFAULT_INTERVAL,
        pre_decay_vault.clone(),
        // KF-10: the daemon owns the WAL writer, so each pass that touches rows
        // emits a `0x94 CONSOLIDATION_PASS` audit frame.
        Some(writer.clone()),
    ));
    info!(
        interval_secs = crate::memory::decay_task::DEFAULT_INTERVAL.as_secs(),
        pre_decay_export = pre_decay_vault.is_some(),
        "Hebbian decay task spawned"
    );

    // ── 5b-quart. Sources-table GC scheduler (BS-3 wired). 24h cadence
    // sweeps transient `sources` rows + their chunks once a day.
    let gc_task = Some(crate::memory::gc_task::spawn(
        None,
        crate::memory::gc_task::DEFAULT_INTERVAL,
    ));
    info!(
        interval_secs = crate::memory::gc_task::DEFAULT_INTERVAL.as_secs(),
        "sources GC task spawned"
    );

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
    let n8n_api_task: Option<tokio::task::JoinHandle<()>> = if config.n8n_api.enabled {
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
                    std::sync::Arc::clone(&n8n_api_shutdown),
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
    } else {
        debug!("freedom.yaml::n8n_api.enabled = false; skipping localhost API spawn");
        None
    };

    // ── 5c-bis. Spawn /healthz + /metrics listener — Phase 33c BS-1 ────────
    //
    // Optional, off by default. Operator opts in by setting
    // `observability_listen: "127.0.0.1:43117"` (or similar) in freedom.yaml.
    // Localhost-only by design — public exposure is the operator's choice
    // via a reverse proxy if they want one.
    let healthz_task: Option<tokio::task::JoinHandle<anyhow::Result<()>>> = match config
        .observability_listen
        .as_deref()
    {
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
    };

    // ── 5c-ter. Spawn the audit-RPC listener — AUDIT-RPC-01 ────────────────
    //
    // Off by default. When `freedom.yaml::audit_rpc.enabled = true`, a loopback
    // listener lets one-shot CLIs forward their audit frames to this (the
    // WAL-owning) daemon so a `neoth os launch` / `fs` / `lease` run while the
    // daemon is up still lands its `0xA5..=0xAD` audit frames. Bearer-token +
    // loopback-only + a compile-time event-type allowlist (anti-poisoning).
    let mut _audit_rpc_guard: Option<crate::daemon::audit_rpc::SidecarGuard> = None;
    let audit_rpc_task: Option<tokio::task::JoinHandle<anyhow::Result<()>>> =
        if config.audit_rpc.enabled {
            let home = FreedomConfig::default_neoth_home();
            // Clear any sidecar+token a PRIOR daemon left behind on a crash
            // (no clean SidecarGuard drop) BEFORE minting fresh ones — closes
            // the stale-token-disclosure window (recycled port).
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
                            _audit_rpc_guard =
                                Some(crate::daemon::audit_rpc::SidecarGuard::new(home.clone()));
                            info!(port = addr.port(), "audit-RPC listener up (127.0.0.1)");
                            Some(task)
                        }
                        Err(e) => {
                            warn!(error = %e, "audit-RPC listener failed to bind; one-shot audit forwarding disabled");
                            None
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "audit-RPC token mint failed; listener not started");
                    None
                }
            }
        } else {
            None
        };

    // ── 5d. Cron scheduler — Phase 33a AU-B5 ───────────────────────────────
    //
    // Loads `~/.neoth/jobs.yaml` if present and spawns the tick loop.
    // Missing jobs file is not an error — operators without recurring jobs
    // simply see no scheduler task. Bad YAML *is* an error: configuration
    // problems must fail loudly at startup, not silently never fire.
    let cron_task: Option<tokio::task::JoinHandle<()>> =
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
                        Some(handle)
                    }
                    Err(e) => {
                        return Err(anyhow::anyhow!(
                            "failed to load {}: {e:#}",
                            jobs_path.display(),
                        ));
                    }
                }
            }
            (Some(_), Some(jobs_path)) => {
                info!(path = %jobs_path.display(), "no jobs.yaml; cron scheduler idle");
                None
            }
            (None, _) => None,
            (_, None) => None,
        };

    // ── 5d.c. Updater cron loops — U-04 + probes (Session 25) ────────────
    //
    // Two parallel updater lanes: NeothSelf (GitHub Releases probe via
    // `self_update::check_for_update`) + CliVersion (npm registry probe
    // for claude/codex/gemini via `updater::check_all`). Each lane runs
    // on its own UpdaterCronConfig with the same 6h default interval.
    // 0x44 UPDATER_TASK_FIRED + 0x45 UPDATER_TASK_RESULT WAL frames
    // fire per tick — operators audit via `neoth updater status`.
    // U-04 follow-up (Session 26): operator-tunable updater interval
    // via freedom.yaml::updater.{enabled,interval_secs}. All three
    // lanes share the same knob today; per-lane override is a future
    // schema bump. Build the shared cron config once + clone into
    // each spawn site so the lanes stay independent join-handles.
    let updater_cron_cfg = crate::daemon::updater_cron::UpdaterCronConfig {
        enabled: config.updater.enabled,
        interval_secs: config.updater.interval_secs,
    };

    let updater_self_task: Option<tokio::task::JoinHandle<()>> = {
        let writer_for_updater = writer.clone();
        let cfg = updater_cron_cfg.clone();
        let builder: std::sync::Arc<
            dyn Fn() -> Vec<crate::updater::pipeline::ComponentSpec> + Send + Sync + 'static,
        > = std::sync::Arc::new(|| {
            crate::updater::probes::neoth_self_specs_blocking(
                crate::updater::pipeline::GateDecision::Allow,
            )
        });
        let handle = crate::daemon::updater_cron::spawn_updater_cron_loop(
            cfg,
            crate::wal::payloads_u04::UpdaterTaskKind::NeothSelf,
            builder,
            writer_for_updater,
        );
        if handle.is_some() {
            info!("updater cron loop spawned: neoth_self (U-01)");
        }
        handle
    };

    let updater_cli_task: Option<tokio::task::JoinHandle<()>> = {
        let writer_for_updater = writer.clone();
        let cfg = updater_cron_cfg.clone();
        let builder: std::sync::Arc<
            dyn Fn() -> Vec<crate::updater::pipeline::ComponentSpec> + Send + Sync + 'static,
        > = std::sync::Arc::new(|| {
            crate::updater::probes::cli_version_specs_blocking(
                crate::updater::pipeline::GateDecision::Allow,
            )
        });
        let handle = crate::daemon::updater_cron::spawn_updater_cron_loop(
            cfg,
            crate::wal::payloads_u04::UpdaterTaskKind::CliVersions,
            builder,
            writer_for_updater,
        );
        if handle.is_some() {
            info!("updater cron loop spawned: cli_version (U-03)");
        }
        handle
    };

    let updater_skill_task: Option<tokio::task::JoinHandle<()>> = {
        let writer_for_updater = writer.clone();
        let home_for_skills = FreedomConfig::default_neoth_home();
        let cfg = updater_cron_cfg.clone();
        let builder: std::sync::Arc<
            dyn Fn() -> Vec<crate::updater::pipeline::ComponentSpec> + Send + Sync + 'static,
        > = std::sync::Arc::new(move || {
            crate::updater::probes::skill_plugin_specs_blocking(
                home_for_skills.clone(),
                crate::updater::pipeline::GateDecision::Allow,
            )
        });
        let handle = crate::daemon::updater_cron::spawn_updater_cron_loop(
            cfg,
            crate::wal::payloads_u04::UpdaterTaskKind::SkillPlugin,
            builder,
            writer_for_updater,
        );
        if handle.is_some() {
            info!("updater cron loop spawned: skill_plugin (U-02)");
        }
        handle
    };

    // ── 5d.c. CLI auto-apply loop — MV-01b (Session 28c) ─────────────────
    //
    // Operator policy "Option A": auto-apply CLI updates (claude-cli /
    // antigravity-cli / codex) when autonomy is elevated/full. At standard
    // or below this returns None (notify-only — the probe crons above
    // already surface availability). Emits `0x13 UPDATE_RAN` per applied
    // CLI. The `neoth` daemon's own self-replacement stays manual
    // (`neoth update --self --apply`).
    let cli_autoupdate_task: Option<tokio::task::JoinHandle<()>> =
        crate::daemon::auto_update::spawn(
            config.autonomy,
            config.updater.enabled,
            config.updater.interval_secs,
            writer.clone(),
        );
    if cli_autoupdate_task.is_some() {
        info!("CLI auto-apply loop spawned (MV-01b; autonomy elevated/full)");
    }

    // ── 5d.d. neoth-self STAGING loop — MV-01b #5 (Session 28c) ──────────
    //
    // Stage-only (never swaps — the SelfBinaryReplace gate is
    // Confirm-always): at elevated/full it downloads + verifies (sha256 +
    // minisig) + stages newer releases to ~/.neoth/staged/ + notifies.
    // The operator applies via `neoth update --self --apply`.
    let self_stage_task: Option<tokio::task::JoinHandle<()>> =
        crate::daemon::auto_update::spawn_self_stage(
            config.autonomy,
            config.updater.enabled,
            config.updater.interval_secs,
            "The-Geek-Freaks/NEOTH".to_string(),
            FreedomConfig::default_neoth_home(),
            writer.clone(),
        );
    if self_stage_task.is_some() {
        info!("neoth-self staging loop spawned (MV-01b #5; stage-only)");
    }

    // ── 5d.b. Doctor cron loop — EL-01 (Session 25) ──────────────────────
    //
    // Periodic `neoth doctor` ticks → WAL 0x46 DOCTOR_TICK frame per pass +
    // SidecarNotificationSink dropping a JSON file under
    // `~/.neoth/notifications/doctor_<ts>.json` whenever the report carries
    // Warn / Fail findings. GUI notifications panel polls the directory;
    // future channel-push subscribers can subscribe similarly without
    // re-running the diagnostic suite.
    let doctor_cron_task: Option<tokio::task::JoinHandle<()>> = {
        let home = FreedomConfig::default_neoth_home();
        let writer_for_doctor = writer.clone();
        let sink: std::sync::Arc<dyn crate::daemon::doctor_cron::DoctorNotificationSink> =
            std::sync::Arc::new(crate::daemon::doctor_cron::SidecarNotificationSink::new(
                home.join("notifications"),
            ));
        // EL-01 follow-up (Session 26): read the operator's tunable
        // doctor knobs from freedom.yaml. Missing fields default per
        // `DoctorConfig::default()` so pre-EL-01 configs still load.
        let cfg = crate::daemon::doctor_cron::DoctorCronConfig {
            enabled: config.doctor.enabled,
            interval_secs: config.doctor.interval_secs,
            notify_channel: "cli".to_string(),
        };
        let interval_secs = cfg.interval_secs;
        let enabled = cfg.enabled;
        let handle =
            crate::daemon::doctor_cron::spawn_doctor_cron_loop(cfg, home, writer_for_doctor, sink);
        if handle.is_some() {
            info!(interval_secs, "doctor cron loop spawned (EL-01)");
        } else if !enabled {
            info!("doctor cron disabled via freedom.yaml::doctor.enabled = false");
        }
        handle
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
    let reflection_cron_handle = {
        let home = crate::config::FreedomConfig::default_neoth_home();
        crate::daemon::reflection_cron::spawn_reflection_cron_loop(
            home,
            crate::daemon::reflection_cron::DEFAULT_CRON_INTERVAL_SECS,
        )
    };
    info!(
        interval_secs = crate::daemon::reflection_cron::DEFAULT_CRON_INTERVAL_SECS,
        "reflection cron loop spawned (G-01 wiring — Round-3 v0.4)"
    );

    // ── 5d-tris. Proactive drain cron — G-01 consumer half (Round-3 v0.4) ──
    //
    // Drains items the reflection_cron (above) enqueued into the
    // ProactiveQueue + appends each to `~/.neoth/proactive_delivered.jsonl`
    // for operator inspection. Ticks every 5min; per-tick cap of 3
    // smooths bursty producers. Future channel adapters (Telegram /
    // Slack / Keet) consume the same sidecar for at-least-once
    // delivery semantics — the daemon-side drain stays channel-
    // agnostic.
    let proactive_dispatcher_handle = {
        let home = crate::config::FreedomConfig::default_neoth_home();
        crate::daemon::proactive_dispatcher::spawn_proactive_drain_loop(
            home,
            crate::daemon::proactive_dispatcher::PROACTIVE_DRAIN_INTERVAL_SECS,
            writer.clone(),
        )
    };
    info!(
        interval_secs = crate::daemon::proactive_dispatcher::PROACTIVE_DRAIN_INTERVAL_SECS,
        "proactive drain loop spawned (G-01 consumer half — Round-3 v0.4)"
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
    let g02_surfacing_cron_handle = {
        let home = crate::config::FreedomConfig::default_neoth_home();
        crate::daemon::g02_surfacing_cron::spawn_g02_surfacing_cron_loop(
            home,
            crate::daemon::g02_surfacing_cron::G02_CRON_INTERVAL_SECS,
        )
    };
    info!(
        interval_secs = crate::daemon::g02_surfacing_cron::G02_CRON_INTERVAL_SECS,
        "G-02 surfacing cron loop spawned (Round-3 v0.4)"
    );

    // ── 5d-quintus. Profile drift-alert cron — HO-09b. Runs the same
    // drift evaluation as `neoth profile drift report` on a 6h schedule
    // and emits a `0xBA PROFILE_DRIFT_ALERT` WAL frame when the operator's
    // profile drifts past `freedom.yaml::drift_alert.threshold`. Off by
    // default — `spawn_*` returns None when `drift_alert.enabled = false`
    // so opt-out operators carry no idle tokio task.
    let drift_alert_cron_handle: Option<tokio::task::JoinHandle<()>> = {
        let home = FreedomConfig::default_neoth_home();
        let writer_for_drift = writer.clone();
        let handle = crate::daemon::drift_alert_cron::spawn_drift_alert_cron_loop(
            config.drift_alert,
            home,
            writer_for_drift,
        );
        if handle.is_some() {
            info!(
                interval_secs = config.drift_alert.interval_secs,
                threshold = config.drift_alert.threshold,
                "profile drift-alert cron loop spawned (HO-09b)"
            );
        }
        handle
    };

    // ── 5d-sextus. Regression-anchor cron — ADV-14. Weekly re-asks the
    // anchor queries, re-embeds the fresh answers, and emits `0x3F
    // REGRESSION_ALERT` when cosine to the cutover anchor drops below
    // `freedom.yaml::regression_anchor.threshold`. Off by default; needs BOTH a
    // chat provider AND a configured embed provider — only then is it built.
    let regression_cron_handle: Option<tokio::task::JoinHandle<()>> = if config
        .regression_anchor
        .enabled
    {
        match (
            shared_provider.as_ref(),
            crate::providers::embed_provider_from_config(&config).await,
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
    } else {
        None
    };

    // ── 5d-septimus. Recall-latency cron — MONITOR-03 / RECALL-METER-01.
    // Reads the `idx_recall_latency` window (samples recorded by each one-shot
    // `neoth recall`) + emits `0x4B RECALL_LATENCY_ALERT` when p95 exceeds
    // `recall_latency.p95_threshold_ms`. Off by default → no idle task.
    let recall_latency_cron_handle: Option<tokio::task::JoinHandle<()>> = {
        let handle = crate::daemon::recall_latency_cron::spawn_recall_latency_cron_loop(
            config.recall_latency,
            FreedomConfig::default_neoth_home(),
            writer.clone(),
        );
        if handle.is_some() {
            info!(
                interval_secs = config.recall_latency.interval_secs,
                p95_threshold_ms = config.recall_latency.p95_threshold_ms,
                "recall-latency cron loop spawned (MONITOR-03)"
            );
        }
        handle
    };

    // ── SL-03 ResourcePressureWatcher cron ────────────────────────────────
    // Polls live GPU VRAM; emits `0x47 RESOURCE_PRESSURE_ALERT` on a breach
    // of `resource_watch.vram_threshold_pct`. Default OFF → no idle task; a
    // no-op on non-GPU / non-NVIDIA hosts even when enabled.
    let resource_watch_handle: Option<tokio::task::JoinHandle<()>> = {
        let writer_for_rw = writer.clone();
        let handle = crate::daemon::resource_watch::spawn_resource_watch_loop(
            config.resource_watch.clone(),
            writer_for_rw,
        );
        if handle.is_some() {
            info!(
                interval_secs = config.resource_watch.interval_secs,
                vram_threshold_pct = config.resource_watch.vram_threshold_pct,
                "resource-watch cron loop spawned (SL-03)"
            );
        }
        handle
    };

    // ── HO-07 monitor alerting cron ──────────────────────────────────────────
    // Polls WAL integrity + crash.log + channel activity; emits
    // `0x48 WAL_CRC_ALERT` / `0x49 CRASH_LOG_ALERT` / `0x4A CHANNEL_SILENCE_ALERT`.
    // Default OFF → no idle task; opt-in via `monitor.enabled = true`.
    let monitor_cron_handle: Option<tokio::task::JoinHandle<()>> = {
        let home = FreedomConfig::default_neoth_home();
        let wal_dir_for_monitor = wal_dir.clone();
        let writer_for_monitor = writer.clone();
        let handle = crate::daemon::monitor_cron::spawn_monitor_cron_loop(
            config.monitor.clone(),
            home,
            wal_dir_for_monitor,
            writer_for_monitor,
        );
        if handle.is_some() {
            info!(
                interval_secs = config.monitor.interval_secs,
                "monitor cron loop spawned (HO-07)"
            );
        }
        handle
    };

    // ── OM-01 local OMI transcript ingest ─────────────────────────────────────
    // Polls the operator's self-hosted OMI backend (SC-14 already confirmed the
    // endpoint is local above), promotes high-confidence items to ground-truth
    // (`0x9C`) + extracts action items to kanban. Default OFF → no task.
    let omi_handle: Option<tokio::task::JoinHandle<()>> = if config.omi.enabled {
        let handle = crate::daemon::omi_ingest_task::spawn_omi_ingest_task(
            config.omi.clone(),
            store::default_path(),
            writer.clone(),
        );
        info!(endpoint = %config.omi.endpoint, "OMI ingest task spawned (OM-01)");
        Some(handle)
    } else {
        None
    };

    // ── Passive user-adaptation cron (SPEC-05) ────────────────────────────
    // Re-aggregates the behavioural snapshot from the WAL every
    // `profile_adapt.interval_secs` (daily default) + queues new self-dev
    // adaptation PROPOSALS for operator review (nothing auto-applied). Off
    // by default — `spawn_*` returns None when `profile_adapt.enabled =
    // false` so opt-out operators carry no idle tokio task.
    let profile_adapt_cron_handle: Option<tokio::task::JoinHandle<()>> = {
        let home = FreedomConfig::default_neoth_home();
        let wal_dir_for_adapt = wal_dir.clone();
        let writer_for_adapt = writer.clone();
        let handle = crate::daemon::profile_adapt_cron::spawn_profile_adapt_cron_loop(
            config.profile_adapt,
            home,
            wal_dir_for_adapt,
            writer_for_adapt,
        );
        if handle.is_some() {
            info!(
                interval_secs = config.profile_adapt.interval_secs,
                "passive user-adaptation cron loop spawned (SPEC-05)"
            );
        }
        handle
    };

    // ── Ecology auto-scheduler (F4-01 Phase 1) ────────────────────────────
    // Decides WHEN to adapt: on a low-dissent council regime (winner streak ≥
    // `ecology.correlation_min_streak`) it STAGES P-04 self-dev proposals for
    // `neoth self-dev review` and emits 0x4C. NEVER auto-applies — the
    // DESIGN_CH13 P2 review-gate. Off by default → `spawn_*` returns None.
    let ecology_cron_handle: Option<tokio::task::JoinHandle<()>> = {
        let home = FreedomConfig::default_neoth_home();
        let wal_dir_for_ecology = wal_dir.clone();
        let writer_for_ecology = writer.clone();
        let handle = crate::ecology::scheduler::spawn_ecology_cron_loop(
            home,
            wal_dir_for_ecology,
            config.ecology.clone(),
            writer_for_ecology,
        );
        if handle.is_some() {
            info!(
                interval_secs = config.ecology.scheduler_interval_secs,
                min_streak = config.ecology.correlation_min_streak,
                "ecology auto-scheduler cron loop spawned (F4-01 — proposals review-gated)"
            );
        }
        handle
    };

    // ── Behaviour-pattern cron (G-01 full detector suite) ─────────────────
    // Each tick runs the inactivity / query-repeat / topic-burst /
    // time-of-day-shift detectors and enqueues their nudges (per-detector
    // toggled, per-UTC-day deduped, per-tick capped). Delivered by the
    // existing proactive_dispatcher drain loop. Off by default — a
    // proactive ping is intrusive — so `spawn_*` returns None when
    // `pattern_cron.enabled = false`.
    let pattern_cron_handle: Option<tokio::task::JoinHandle<()>> = {
        let home = FreedomConfig::default_neoth_home();
        let handle =
            crate::daemon::pattern_cron::spawn_pattern_cron_loop(config.pattern_cron, home);
        if handle.is_some() {
            info!(
                interval_secs = config.pattern_cron.interval_secs,
                inactivity_gap_secs = config.pattern_cron.inactivity_gap_secs,
                "pattern-detection cron loop spawned (G-01 detector suite)"
            );
        }
        handle
    };

    // ── MONITOR-02 worker-watch ───────────────────────────────────────────
    // Real-time death detection for the long-running cron/worker loops: hold a
    // cheap `AbortHandle` clone of each + poll `is_finished()`, emitting
    // `0x4D WORKER_DIED` (naming the task) the moment one panics/exits — lower
    // latency + attribution than the HO-07 crash.log scan. Gated on the same
    // `monitor.enabled` as the HO-07 cron. Holds only abort-handle clones, so the
    // shutdown-abort of the original handles (below) is entirely unaffected.
    let worker_watch_handle: Option<tokio::task::JoinHandle<()>> = if config.monitor.enabled {
        use crate::daemon::worker_watch::WatchedWorker;
        let watched: Vec<WatchedWorker> = [
            cron_task.as_ref().map(|h| WatchedWorker::new("cron_scheduler", h.abort_handle())),
            updater_self_task.as_ref().map(|h| WatchedWorker::new("updater_self", h.abort_handle())),
            updater_cli_task.as_ref().map(|h| WatchedWorker::new("updater_cli", h.abort_handle())),
            updater_skill_task.as_ref().map(|h| WatchedWorker::new("updater_skill", h.abort_handle())),
            cli_autoupdate_task.as_ref().map(|h| WatchedWorker::new("cli_autoupdate", h.abort_handle())),
            self_stage_task.as_ref().map(|h| WatchedWorker::new("self_stage", h.abort_handle())),
            doctor_cron_task.as_ref().map(|h| WatchedWorker::new("doctor_cron", h.abort_handle())),
            resource_watch_handle.as_ref().map(|h| WatchedWorker::new("resource_watch", h.abort_handle())),
            monitor_cron_handle.as_ref().map(|h| WatchedWorker::new("monitor_cron", h.abort_handle())),
            omi_handle.as_ref().map(|h| WatchedWorker::new("omi_ingest", h.abort_handle())),
            profile_adapt_cron_handle.as_ref().map(|h| WatchedWorker::new("profile_adapt_cron", h.abort_handle())),
            ecology_cron_handle.as_ref().map(|h| WatchedWorker::new("ecology_scheduler", h.abort_handle())),
            pattern_cron_handle.as_ref().map(|h| WatchedWorker::new("pattern_cron", h.abort_handle())),
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
    let catalog_task: tokio::task::JoinHandle<()> = {
        let home = FreedomConfig::default_neoth_home();
        let config_for_catalog = config.clone();
        crate::models::refresh_task::spawn_periodic_refresh(home, config_for_catalog)
    };
    info!(
        tick_secs = crate::models::refresh_task::REFRESH_TICK_INTERVAL.as_secs(),
        "models catalog refresh task spawned (K-Models-Discovery)"
    );

    // ── Cluster audit-sidecar ingester ─────────────────────────────────────
    // CLI commands (`neoth cluster confirm` / `revoke`) drop JSON
    // sidecars at `~/.neoth/pending_audit/cluster_*.json`. This
    // task polls every 5s, reads pending sidecars, appends WAL
    // 0xE6/0xE7 frames, removes the consumed file.
    // GOLD-SEC-16: cluster transport + its sidecar/gossip tasks compile in only
    // with the `cluster` feature.
    #[cfg(feature = "cluster")]
    let cluster_audit_task: tokio::task::JoinHandle<()> = {
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
    };
    #[cfg(feature = "cluster")]
    info!("cluster audit sidecar ingester spawned (5s tick)");

    // ── SL-00(1b) Cluster transport activation (Hyperswarm DHT) ────────────
    // The live-network flip. Brought up ONLY when BOTH gates are open:
    //   1. operator flipped `cluster.enabled: true`  (transport master-switch)
    //   2. a full identity resolves — public `cluster.name` AND secret
    //      `cluster_passphrase` (fail-closed `resolve_cluster_identity`).
    // Either missing ⇒ no spawn ⇒ the daemon NEVER announces on the public
    // DHT. A fresh install (enabled=false, no name, no passphrase) is
    // triple-gated OFF. When it does come up, every peer handshake enforces
    // the cluster_key proof (SL-00(1b)-handshake) so the transport is
    // authenticated from the first byte.
    // SL-01b: gossip anti-entropy send-tick handle (spawned only when the
    // transport actually comes up), aborted on shutdown alongside the swarm.
    #[cfg(feature = "cluster")]
    let mut cluster_gossip_task: Option<tokio::task::JoinHandle<()>> = None;
    #[cfg(feature = "cluster")]
    let cluster_swarm: Option<crate::cluster::hyperswarm::SwarmHandle> =
        match crate::cluster::identity::cluster_transport_activation(&config, &creds) {
            Some(identity) => {
                let registry = std::sync::Arc::new(std::sync::Mutex::new(
                    crate::cluster::PeerLoadRegistry::new(),
                ));
                let cluster_key = std::sync::Arc::new(identity.key);
                let cluster_wal = Some(std::sync::Arc::new(writer.clone()));
                // SL-00(1c): the outbound peer-stream registry, shared between
                // the transport (drains it to write), the SL-01 executor
                // (queues TaskResult replies), and the SL-01b gossip tick.
                let peer_streams =
                    std::sync::Arc::new(crate::cluster::peer_streams::PeerStreamRegistry::new());
                // SL-01: spawn the single task executor (holds the provider +
                // a clone of peer_streams) and thread its bounded dispatch
                // sender into the transport's accept gate.
                let dispatch_tx = crate::cluster::executor::spawn_cluster_executor(
                    shared_provider.clone(),
                    std::sync::Arc::clone(&peer_streams),
                );
                // SL-01b: the gossip send-tick reads the active WAL segment tail
                // + broadcasts replicable frames to paired peers.
                let gossip_streams = std::sync::Arc::clone(&peer_streams);
                let gossip_segment = segment_path.clone();
                let gossip_writer = std::sync::Arc::new(writer.clone());
                match crate::cluster::hyperswarm::spawn_discovery_with_wal(
                    &identity.name,
                    Some(cluster_key),
                    registry,
                    cluster_wal,
                    peer_streams,
                    config.autonomy,
                    crate::config::FreedomConfig::default_neoth_home(),
                    Some(dispatch_tx),
                )
                .await
                {
                    Ok(handle) => {
                        info!(
                            cluster = %identity.name,
                            "SL-00(1b): cluster transport ACTIVE — authenticated Hyperswarm discovery joined"
                        );
                        cluster_gossip_task = Some(crate::cluster::wal_sync::spawn_gossip_tick(
                            gossip_streams,
                            gossip_segment,
                            gossip_writer,
                        ));
                        Some(handle)
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            "cluster transport failed to start; continuing without clustering"
                        );
                        None
                    }
                }
            }
            None => {
                // Default path: gate closed (enabled=false OR identity
                // incomplete). Emit a one-line diagnostic only when the
                // operator flipped the switch but left identity incomplete,
                // so a misconfig is visible without noise on every boot.
                if config.cluster.enabled {
                    warn!(
                        "cluster.enabled=true but no identity resolved (need both cluster.name and cluster_passphrase); transport stays OFF"
                    );
                }
                None
            }
        };

    // ── W-05d installer_ran sidecar ingester (Session 26) ─────────────────
    // `neoth installer apply --yes` drops `~/.neoth/installer_ran_<ts>.json`
    // after a successful install. This task polls every 5s, reads
    // pending sidecars, appends a `0x12 INSTALLER_RAN` WAL frame per
    // sidecar, and removes the file. At-least-once semantics: a crash
    // between WAL append + file remove leaves the file for the next
    // tick to retry; the WAL writer dedupes by event_id.
    let installer_audit_task: tokio::task::JoinHandle<()> = {
        let writer_for_installer = writer.clone();
        let home = FreedomConfig::default_neoth_home();
        tokio::spawn(async move {
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
                    let body =
                        crate::daemon::installer_audit_sidecar::build_wal_frame_body(&payload);
                    let header = crate::wal::HeaderBuilder::new(
                        crate::wal::events::EVENT_TYPE_INSTALLER_RAN,
                        &body,
                    )
                    .build();
                    match writer_for_installer.append(header, body).await {
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
        })
    };
    info!("installer_ran sidecar ingester spawned (5s tick)");

    // ── C-05d credentials_import sidecar ingester (Session 26) ────────────
    // `neoth init` wizard step 6g drops
    // `~/.neoth/credentials_import_<ts>.json` after the SC-17 redactor
    // produced its payload. This task polls every 5s, reads pending
    // sidecars, appends a `0xD6 CREDENTIAL_IMPORT` WAL frame per
    // sidecar, and removes the file. The payload is already redacted
    // by the time it lands on disk — this loop never touches raw
    // secret material.
    let credentials_import_task: tokio::task::JoinHandle<()> = {
        let writer_for_credentials = writer.clone();
        let home = FreedomConfig::default_neoth_home();
        tokio::spawn(async move {
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
                    match writer_for_credentials.append(header, body).await {
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
        })
    };
    info!("credentials_import sidecar ingester spawned (5s tick)");

    // ── W-04 follow-up: detect_complete sidecar ingester (Session 26) ─────
    // The wizard's step1b drops `~/.neoth/detect_complete_<ts>.json`
    // after a fresh probe pass produced a `DetectCompletePayload`.
    // Same 5s poll + at-least-once contract as the installer +
    // credentials ingesters above.
    let detect_complete_task: tokio::task::JoinHandle<()> = {
        let writer_for_detect = writer.clone();
        let home = FreedomConfig::default_neoth_home();
        tokio::spawn(async move {
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
                    let body =
                        crate::daemon::detect_complete_sidecar::build_wal_frame_body(&payload);
                    let header = crate::wal::HeaderBuilder::new(
                        crate::wal::events::EVENT_TYPE_DETECT_COMPLETE,
                        &body,
                    )
                    .build();
                    match writer_for_detect.append(header, body).await {
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
        })
    };
    info!("detect_complete sidecar ingester spawned (5s tick)");

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
    let self_dev_outbox_task: tokio::task::JoinHandle<()> = {
        let writer_for_self_dev = writer.clone();
        let home = FreedomConfig::default_neoth_home();
        crate::cli::self_dev_outbox::spawn_drain_task(home, writer_for_self_dev)
    };
    info!(
        tick_secs = crate::cli::self_dev_outbox::DRAIN_INTERVAL.as_secs(),
        "self-dev outbox drain task spawned"
    );

    // ── QM-10 Phase 3 breaker state restore ────────────────────────────────
    // Replay the failure counters from the prior daemon run so a
    // flapping provider that built up failure history before
    // shutdown doesn't get a clean slate after restart. Open
    // state is intentionally NOT restored — a fresh boot should
    // retry every provider once. Stale rows (older than 7 days)
    // are skipped.
    {
        let home = crate::config::FreedomConfig::default_neoth_home();
        match crate::providers::circuit_breaker::persist::restore_from_disk(
            &home,
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

    // ── OnSessionStart hooks (QM-15 follow-on) ─────────────────────────────
    // Fire operator-defined hooks at the `on_session_start` stage AFTER
    // all subsystems (WAL writer, indexer, channels, cron, models catalog
    // refresh) have spawned. Mirrors the OnShutdown firing on the other
    // side of the wait loop. Each fired hook writes a HOOK_FIRED WAL
    // frame so the audit log shows that configured boot actions ran.
    //
    // GR-06 (Session 27): `Block` outcome semantics pinned. A
    // `StageOutcome::Block` at this stage is LOGGED via warn! and
    // ignored — the daemon stays booted. This is intentional: at
    // the `on_session_start` stage the daemon has already opened
    // every channel + spawned cron tasks + bound its HTTP listener;
    // tearing those down because a single operator-defined hook
    // returned Block would surface as a half-booted daemon that
    // never gets to its idle wait loop. Hooks that need to abort
    // boot belong at an earlier stage (no such stage exists today —
    // operator escalation deferred until v0.4 or a real ask). The
    // warn! message names the hook + the reason so the operator
    // sees the intent without it being load-bearing on the
    // daemon's liveness.
    {
        let hook_dir = crate::config::FreedomConfig::default_neoth_home().join("hooks");
        let hooks = crate::hooks::load_all(&hook_dir).await.unwrap_or_else(|e| {
            warn!(
                error = %e,
                dir = %hook_dir.display(),
                "hook load failed at session-start — proceeding with empty hook set"
            );
            Default::default()
        });
        match crate::hooks::run_stage(
            crate::hooks::HookStage::OnSessionStart,
            "session-start",
            &hooks,
        ) {
            Ok(crate::hooks::StageOutcome::Continue { hits, .. }) => {
                for name in &hits {
                    let payload = match serde_json::to_vec(&serde_json::json!({
                        "name": name,
                        "stage": "on_session_start",
                        "ts_unix": std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0),
                    })) {
                        Ok(p) => p,
                        Err(e) => {
                            warn!(error = %e, "serialize OnSessionStart hook frame failed");
                            continue;
                        }
                    };
                    let header = crate::wal::HeaderBuilder::new(
                        crate::wal::events::EVENT_TYPE_HOOK_FIRED,
                        &payload,
                    )
                    .build();
                    if let Err(e) = writer.append(header, payload).await {
                        warn!(error = %e, "WAL append OnSessionStart HOOK_FIRED failed");
                    } else {
                        info!(hook = name, "on_session_start hook fired");
                    }
                }
            }
            Ok(crate::hooks::StageOutcome::Block { name, reason }) => {
                // Documented Block semantics: daemon continues. See the
                // module-doc above the hook block for the rationale.
                warn!(
                    hook = %name,
                    reason = %reason,
                    "on_session_start hook returned Block; ignored — daemon continues (subsystems already spawned)"
                );
            }
            Err(e) => warn!(error = %e, "OnSessionStart hook dispatch failed"),
        }
    }

    // ── 6. Idle until shutdown signal arrives ──────────────────────────────
    if channel_tasks.is_empty() {
        info!("no channels configured; idling until shutdown signal");
    } else {
        info!(
            channels = channel_tasks.len(),
            "channels running; idling until shutdown signal (SIGTERM / Ctrl+C)"
        );
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
        tokio::spawn(async move {
            let home = crate::config::FreedomConfig::default_neoth_home();
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(5));
            ticker.tick().await; // burn immediate
            loop {
                ticker.tick().await;
                if crate::daemon::supervisor::take_restart_request(&home) {
                    notify.notify_one();
                    break;
                }
            }
        })
    };

    let writer_died = tokio::select! {
        biased;
        _ = shutdown::wait_for_signal() => false,
        _ = restart_notify.notified() => {
            info!(
                "restart requested (self-update binary swap); draining + exiting for supervisor relaunch"
            );
            false
        }
        result = &mut writer_join => {
            match result {
                Ok(()) => warn!(
                    "WAL writer task exited unexpectedly without error — daemon cannot persist events; treating as fatal"
                ),
                Err(e) => error!(
                    error = %e,
                    "WAL writer task panicked — daemon cannot persist events; treating as fatal"
                ),
            }
            true
        }
    };
    restart_watcher.abort();
    let _ = restart_watcher.await;
    if writer_died {
        info!("WAL writer death detected; aborting channels + exiting");
    } else {
        info!("shutdown signal received; aborting channels + draining WAL writer");
    }

    // ── QM-10 Phase 3 breaker state snapshot ───────────────────────────────
    // Persist the current failure counters BEFORE the shutdown hooks
    // fire so a restart-grace path sees the same state. Best-effort —
    // a stuck disk doesn't block the shutdown sequence.
    {
        let home = crate::config::FreedomConfig::default_neoth_home();
        match crate::providers::circuit_breaker::persist::snapshot_to_disk(
            &home,
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
        let hook_dir = crate::config::FreedomConfig::default_neoth_home().join("hooks");
        // Pick #34 (Session 14, silent-failure audit-fix): hook load
        // failures now surface at warn level. Prior `unwrap_or_default()`
        // silently disabled every hook on a single bad TOML file.
        let hooks = crate::hooks::load_all(&hook_dir).await.unwrap_or_else(|e| {
            warn!(
                error = %e,
                dir = %hook_dir.display(),
                "hook load failed — proceeding with empty hook set"
            );
            Default::default()
        });
        match crate::hooks::run_stage(crate::hooks::HookStage::OnShutdown, "shutdown", &hooks) {
            Ok(crate::hooks::StageOutcome::Continue { hits, .. }) => {
                for name in &hits {
                    let payload = match serde_json::to_vec(&serde_json::json!({
                        "name": name,
                        "stage": "on_shutdown",
                        "ts_unix": std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0),
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

    // MONITOR-02: abort the worker-watch FIRST — so the deliberate abort of the
    // watched workers (below) is never mistaken for an unexpected death + alerted.
    if let Some(task) = worker_watch_handle {
        task.abort();
        let _ = task.await;
    }

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
    if let Some(task) = cron_task {
        task.abort();
        let _ = task.await;
    }

    // Abort the EL-01 doctor cron loop. Same drain-before-writer-close
    // discipline as the regular cron scheduler.
    if let Some(task) = doctor_cron_task {
        task.abort();
        let _ = task.await;
    }

    // Abort the SL-03 resource-watch cron loop (drain before writer close).
    if let Some(task) = resource_watch_handle {
        task.abort();
        let _ = task.await;
    }

    // Abort the HO-07 monitor alerting cron loop (drain before writer close).
    if let Some(task) = monitor_cron_handle {
        task.abort();
        let _ = task.await;
    }
    if let Some(task) = omi_handle {
        task.abort();
        let _ = task.await;
    }

    // Abort the U-04 updater cron loops (neoth_self + cli_version).
    // Drain before the WAL writer closes so any in-flight tick's
    // result-frame doesn't get dropped mid-append.
    if let Some(task) = updater_self_task {
        task.abort();
        let _ = task.await;
    }
    if let Some(task) = updater_cli_task {
        task.abort();
        let _ = task.await;
    }
    if let Some(task) = updater_skill_task {
        task.abort();
        let _ = task.await;
    }
    // MV-01b CLI auto-apply loop. A mid-pass abort at worst drops one
    // component's UPDATE_RAN frame; the install itself already completed.
    if let Some(task) = cli_autoupdate_task {
        task.abort();
        let _ = task.await;
    }
    // MV-01b #5 neoth-self staging loop. Mid-pass abort at worst drops a
    // partial staged archive (re-staged next boot); never swaps.
    if let Some(task) = self_stage_task {
        task.abort();
        let _ = task.await;
    }

    // Abort the catalog refresh task. May be in the middle of an HTTPS
    // round-trip; aborting drops the connection, which is fine — the
    // next daemon start will re-run discovery on its first tick.
    catalog_task.abort();
    let _ = catalog_task.await;

    // Abort the cluster audit sidecar ingester. Pending sidecars
    // on disk are retained — the next daemon start picks them up
    // on its first tick (at-least-once semantics are fine for an
    // audit frame, the WAL writer dedupes by frame hash).
    // GOLD-SEC-16: cluster task teardown only exists with the `cluster` feature.
    #[cfg(feature = "cluster")]
    {
        cluster_audit_task.abort();
        let _ = cluster_audit_task.await;

        // SL-01b: stop the gossip send-tick before tearing the transport down.
        if let Some(task) = cluster_gossip_task {
            task.abort();
            let _ = task.await;
        }

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
    installer_audit_task.abort();
    let _ = installer_audit_task.await;
    credentials_import_task.abort();
    let _ = credentials_import_task.await;
    detect_complete_task.abort();
    let _ = detect_complete_task.await;

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
    self_dev_outbox_task.abort();
    let _ = self_dev_outbox_task.await;

    // Abort the indexer next. It may have been mid-pass; the next `neoth serve`
    // start picks up from `wal_cursor`.
    if let Some(task) = indexer_task {
        task.abort();
        let _ = task.await;
    }

    // Pick #37 (Session 14): abort the hot-reload poll task. The
    // controller is dropped along with `reload_controller`. A
    // pending sentinel on disk survives + the next `neoth serve`
    // boot picks it up via the at-boot one-shot check.
    reload_task.abort();
    let _ = reload_task.await;

    // Abort the /healthz listener — it never writes WAL so it can be cancelled
    // freely. In-flight connections finish on their own.
    if let Some(task) = audit_rpc_task {
        task.abort();
        let _ = task.await; // COR-34: await the abort so the handle isn't dropped mid-run
    }
    // _audit_rpc_guard drops here at fn end → removes the sidecar + token.
    if let Some(task) = healthz_task {
        task.abort();
        let _ = task.await;
    }

    // Abort the Hebbian decay task. It runs against the SQLite views db, so
    // aborting mid-pass leaves an open transaction at worst — SQLite rolls
    // it back automatically on connection close.
    if let Some(task) = decay_task {
        task.abort();
        let _ = task.await;
    }

    // Abort the sources GC task — same reasoning as decay above.
    if let Some(task) = gc_task {
        task.abort();
        let _ = task.await;
    }

    // Round-3 v0.4 G-01 — reflection cron loop. Reads views.db +
    // writes proactive_queue.json; mid-tick abort leaves the queue
    // file untouched (writer is atomic .tmp + rename) so the next
    // boot sees a consistent state.
    reflection_cron_handle.abort();
    let _ = reflection_cron_handle.await;

    // Round-3 v0.4 G-01 consumer half — proactive drain loop.
    // Drains queue + appends to JSONL sidecar; the JSONL sidecar
    // is append-only so a mid-tick abort either landed the line
    // (delivered) or didn't (next tick re-picks the item). Worst
    // case: one item is dropped from a tick that aborted mid-flight
    // — operator sees it on next drain cycle.
    proactive_dispatcher_handle.abort();
    let _ = proactive_dispatcher_handle.await;

    // Round-3 v0.4 G-02 — surfacing cron loop. Reads idx_profile +
    // writes proactive_queue.json (atomic .tmp + rename). Mid-tick
    // abort leaves the queue file untouched + per-claim dedup_key
    // means the next boot's first tick re-finds the same novel
    // claims + re-enqueues are no-ops.
    g02_surfacing_cron_handle.abort();
    let _ = g02_surfacing_cron_handle.await;

    // Abort the HO-09b drift-alert cron. Same drain-before-writer-close
    // discipline as the doctor cron: abort + await BEFORE the WAL writer
    // is dropped so an in-flight 0xBA frame isn't lost.
    if let Some(task) = drift_alert_cron_handle {
        task.abort();
        let _ = task.await;
    }
    // Abort the ADV-14 regression-anchor cron (same drain-before-close order
    // so an in-flight 0x3F frame isn't lost).
    if let Some(task) = regression_cron_handle {
        task.abort();
        let _ = task.await;
    }
    // Abort the MONITOR-03 recall-latency cron (drain before writer close).
    if let Some(task) = recall_latency_cron_handle {
        task.abort();
        let _ = task.await;
    }
    if let Some(task) = profile_adapt_cron_handle {
        task.abort();
        let _ = task.await;
    }
    // Abort the F4-01 ecology auto-scheduler (drain before writer close).
    if let Some(task) = ecology_cron_handle {
        task.abort();
        let _ = task.await;
    }
    if let Some(task) = pattern_cron_handle {
        task.abort();
        let _ = task.await;
    }

    // Abort the R-02 Phase 4c dreaming task. Embed-path callers
    // hit `spawn_blocking` for OuroModel/local_qwen forward;
    // aborting cancels the JoinHandle but the blocking task
    // may run to completion (acceptable — drains naturally,
    // never strands the model load).
    if let Some(task) = dreaming_task {
        task.abort();
        let _ = task.await;
    }

    // EL-02 arXiv ingest task — abort on shutdown. Mid-pass abort at
    // worst drops one topic's fetch, which the next boot re-runs.
    if let Some(task) = arxiv_ingest_task {
        task.abort();
        let _ = task.await;
    }

    // Abort the tmux sweeper. Sweeper runs `tmux kill-session` calls;
    // aborting mid-pass at worst leaves one session unkilled, which the
    // next interval picks up — safe to drop.
    if let Some(task) = tmux_sweeper_task {
        task.abort();
        let _ = task.await;
    }

    // Drain the n8n localhost API. Notify the accept loop first so it
    // breaks cleanly between accepts (in-flight handler tasks finish
    // their existing response), then drop the JoinHandle.
    n8n_api_shutdown.notify_waiters();
    if let Some(task) = n8n_api_task {
        let _ = task.await;
    }

    // Abort the Obsidian auto-sync task. Pure file IO — aborting mid-copy
    // is safe; the next start runs a fresh full sync from `wal_cursor=0`.
    if let Some(task) = obsidian_task {
        task.abort();
        let _ = task.await;
    }

    // Same drill for the cloud auto-mirror task. The cloud client
    // upstream gets the final delta on its own schedule once the
    // file lands on disk.
    if let Some(task) = cloud_task {
        task.abort();
        let _ = task.await;
    }

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
pub(crate) async fn handle_reload_sentinel(
    controller: &crate::config::reload::ReloadController,
    sentinel_path: &std::path::Path,
    writer: &crate::wal::writer::WalWriterHandle,
) {
    let result = match controller.try_reload() {
        Ok(r) => r,
        Err(e) => {
            warn!(
                error = %e,
                path = %controller.source_path().display(),
                "reload: re-read freedom.yaml failed; sentinel will be deleted to prevent loop"
            );
            // Still delete the sentinel — otherwise the poll task
            // re-tries the same broken file every 2s + spams logs.
            let _ = std::fs::remove_file(sentinel_path);
            return;
        }
    };
    let ts_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
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
        }
        crate::config::reload::ReloadResult::Rejected { reason } => {
            warn!(
                reason = %reason,
                source = %controller.source_path().display(),
                "config reload REJECTED — immutable field changed; daemon stays on prior config"
            );
            let payload = serde_json::json!({
                "reason": reason,
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
    if let Err(e) = std::fs::remove_file(sentinel_path) {
        warn!(
            error = %e,
            path = %sentinel_path.display(),
            "reload sentinel delete failed; next poll tick may double-fire"
        );
    }
}

fn build_boot_payload(config: &FreedomConfig) -> Result<Vec<u8>> {
    // Boot payload = minimal JSON: {operator_id, provider_kind, daemon_version}
    // Day-23+ will use a proper msgpack PayloadPrefixV4 frame; for Day-4 keep
    // it simple so a debug inspection of the WAL byte stream is possible.
    let payload = serde_json::json!({
        "operator_id": config.operator_id,
        "provider_kind": config.provider_kind,
        "daemon_version": env!("CARGO_PKG_VERSION"),
        "boot_unix": SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
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
fn bootstrap_plugin_invoker(home: &std::path::Path, wal_writer: WalWriterHandle) {
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
    ): (
        std::collections::BTreeMap<String, crate::wasm_plugin::discovery::PluginActivation>,
        std::collections::BTreeMap<String, String>,
        bool,
        Option<String>,
        bool,
        Vec<String>,
    ) = match FreedomConfig::load_from_default_path() {
        Ok(cfg) => (
            cfg.plugins.wasm.activations.clone(),
            cfg.plugins.wasm.pinned_hashes.clone(),
            cfg.plugins.wasm.require_all_pinned,
            cfg.plugins.wasm.author_pubkey.clone(),
            cfg.plugins.wasm.require_signature,
            cfg.plugins.wasm.revoked_ids.clone(),
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
    // SC-03 — Active plugins that fail the integrity gate (pinned-hash
    // mismatch / unpinned-when-required) are refused before reaching the
    // engine. Collected separately so the operator sees a SECURITY skip,
    // not a benign Pending one.
    let mut skipped_integrity: Vec<String> = Vec::new();
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
                        skipped_integrity.push(format!("{}: {e}", p.manifest.id));
                        false
                    }
                }
            }
            crate::wasm_plugin::discovery::PluginActivation::Pending => {
                skipped_pending.push(p.manifest.id.clone());
                false
            }
            crate::wasm_plugin::discovery::PluginActivation::Disabled => {
                skipped_disabled.push(p.manifest.id.clone());
                false
            }
        }
    });
    if !skipped_integrity.is_empty() {
        warn!(
            integrity_rejected = ?skipped_integrity,
            "plugins REFUSED by SC-03 integrity gate (revoked / hash mismatch / \
             unpinned / signature invalid or missing) — NOT instantiated"
        );
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
    .with_runtime_handles(Some(wal_writer), recall_db);
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
    // GOLD-ARCH-01: these pipeline helpers moved to `serve_pipeline`.
    use crate::cli::serve_pipeline::{channel_skill_allowlist, emit_channel_privilege_blocked};
    use crate::wal::frame::decode_frame;
    use std::io::Write;
    use tempfile::tempdir;
    use tokio::fs::read;

    // Sets NEOTH_CONSENT_BYPASS (process-global) — hold the crate-wide
    // env lock across the run_serve().await so it can't race another env
    // test. The awaited serve path never re-locks it (bounded hold).
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn serve_one_shot_writes_boot_frame() {
        let _env = crate::test_env::lock();
        // Arrange: freedom.yaml + segment paths in temp dir
        let dir = tempdir().unwrap();
        let cfg_path = dir.path().join("freedom.yaml");
        let mut f = std::fs::File::create(&cfg_path).unwrap();
        f.write_all(b"operator_id: alice\nrole: developer\nprovider_kind: claude_cli\n")
            .unwrap();

        let seg_path = dir.path().join("000001.wal");

        let args = ServeArgs {
            config: Some(cfg_path),
            wal_segment: Some(seg_path.clone()),
            one_shot: true,
            allow_clock_rollback: false,
        };

        // V03-08 consent gate would block this test against the real
        // `~/.neoth/consent/claude_cli.granted` marker. Bypass via env var
        // — this test pins WAL writer + BOOT frame shape, not consent.
        // SAFETY: tests run single-threaded under `cargo test` only on the
        // serve module so no other test races this var; restored below.
        unsafe {
            std::env::set_var("NEOTH_CONSENT_BYPASS", "1");
        }
        let result = run_serve(args).await;
        unsafe {
            std::env::remove_var("NEOTH_CONSENT_BYPASS");
        }
        result.expect("serve one-shot");

        // Assert: file exists; has SegmentHeader at offset 0; boot frame after.
        let bytes = read(&seg_path).await.unwrap();
        use crate::wal::segment_header::{SEGMENT_HEADER_LEN, SegmentHeader};
        assert!(
            bytes.len() > SEGMENT_HEADER_LEN + 104,
            "WAL must hold SegmentHeader + at least one frame"
        );
        let sh =
            SegmentHeader::from_le_bytes(bytes[..SEGMENT_HEADER_LEN].try_into().expect("60 bytes"))
                .expect("SegmentHeader CRC must pass");
        assert_eq!(&sh.magic, b"NEOT-SEG");
        let dec = decode_frame(&bytes[SEGMENT_HEADER_LEN..]).expect("decode boot frame");
        assert_eq!(dec.header.event_type, EVENT_TYPE_BOOT);
        let payload_str = std::str::from_utf8(dec.payload).unwrap();
        assert!(payload_str.contains("\"operator_id\":\"alice\""));
        assert!(payload_str.contains("\"daemon_version\""));
    }

    #[tokio::test]
    async fn serve_fails_with_helpful_error_when_freedom_yaml_missing() {
        let dir = tempdir().unwrap();
        let cfg_path = dir.path().join("nope.yaml");
        let seg_path = dir.path().join("000001.wal");
        let args = ServeArgs {
            config: Some(cfg_path),
            wal_segment: Some(seg_path),
            one_shot: true,
            allow_clock_rollback: false,
        };
        let err = run_serve(args).await.unwrap_err();
        assert!(err.to_string().contains("neoth init"));
    }

    // ── SC-11 channel-path tool_allowlist threading (Session 28d) ─────────
    fn skill_with_allowlist(
        id: &str,
        kws: &[&str],
        allow: &[&str],
    ) -> crate::skills::schema::Skill {
        crate::skills::schema::Skill {
            manifest: crate::skills::schema::SkillManifest {
                id: id.to_string(),
                description: format!("test skill {id}"),
                version: "1.0.0".to_string(),
                trigger_keywords: kws.iter().map(|s| (*s).to_string()).collect(),
                system_prompt: format!("you are {id}"),
                tool_allowlist: allow.iter().map(|s| (*s).to_string()).collect(),
                author: None,
                tags: vec![],
                homepage: None,
                source: None,
                modes: vec![],
                enabled: true,
            },
            path: std::path::PathBuf::from(format!("/tmp/{id}/skill.yaml")),
            content_hash: String::new(),
        }
    }

    #[test]
    fn channel_skill_allowlist_none_when_no_skill_matched() {
        // No skill matched this inbound ⇒ gate allows every tool.
        assert_eq!(channel_skill_allowlist(None), None);
    }

    #[test]
    fn channel_skill_allowlist_some_empty_for_default_manifest() {
        // A matched skill with the default (empty) allowlist ⇒ Some(empty),
        // which the gate also treats as "allow all" — distinct from None
        // but behaviourally equivalent at the gate.
        let s = skill_with_allowlist("news", &["news"], &[]);
        assert_eq!(channel_skill_allowlist(Some(&s)), Some(vec![]));
    }

    #[test]
    fn channel_skill_allowlist_carries_restrictive_list() {
        // The SC-11 regression guard: a matched skill's NON-EMPTY allowlist
        // must survive to the dispatch loop, not be dropped to None like the
        // pre-fix channel path did.
        let s = skill_with_allowlist("ops", &["deploy"], &["fs.read", "shell.run"]);
        assert_eq!(
            channel_skill_allowlist(Some(&s)),
            Some(vec!["fs.read".to_string(), "shell.run".to_string()])
        );
    }

    #[test]
    fn channel_route_then_allowlist_preserves_restriction_end_to_end() {
        // Compose the exact channel derivation: route() picks the skill,
        // channel_skill_allowlist() extracts its allowlist. A restrictive
        // allowlist must reach the gate — proving the channel path no longer
        // bypasses skill-scoped tool restriction.
        let skills = vec![skill_with_allowlist("ops", &["deploy"], &["fs.read"])];
        let m = crate::skills::route("please deploy the service", &skills)
            .expect("skill should match 'deploy'");
        let allow = channel_skill_allowlist(Some(m.skill));
        assert_eq!(allow, Some(vec!["fs.read".to_string()]));
    }

    // ── ADV-09: channel privilege-block audit frame (0x3C) ────────────

    #[tokio::test]
    async fn emit_channel_privilege_blocked_writes_0x3c_frame() {
        // The privilege ceiling itself (destructive action from a channel →
        // ChannelPrivilegeBlocked) is unit-tested in slash::action_dispatch;
        // this pins the AUDIT frame the serve.rs channel path emits when it
        // rejects such an action — exactly one 0x3C frame carrying the
        // channel + numeric sender + action wire-name, NO message text.
        let dir = tempdir().unwrap();
        let seg = dir.path().join("priv.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg.clone()).unwrap();
        emit_channel_privilege_blocked(&writer, "telegram", "4242", "autonomy_level").await;

        let bytes = std::fs::read(&seg).unwrap();
        let hdr = crate::wal::segment_header::parse_segment_header(&bytes).unwrap();
        let mut cursor = hdr.header_len();
        let mut found = 0usize;
        while cursor < bytes.len() {
            let dec = match decode_frame(&bytes[cursor..]) {
                Ok(d) => d,
                Err(_) => break,
            };
            if dec.header.event_type == crate::wal::events::EVENT_TYPE_CHANNEL_PRIVILEGE_BLOCKED {
                let v: serde_json::Value = serde_json::from_slice(dec.payload).unwrap();
                assert_eq!(v["channel"], "telegram");
                assert_eq!(v["sender_id"], "4242");
                assert_eq!(v["action"], "autonomy_level");
                assert!(
                    v.get("text").is_none(),
                    "audit frame must carry no message text"
                );
                found += 1;
            }
            let total = dec.header.total_len as usize;
            if total == 0 {
                break;
            }
            cursor = cursor.saturating_add(total);
        }
        assert_eq!(
            found, 1,
            "expected exactly one 0x3C CHANNEL_PRIVILEGE_BLOCKED frame"
        );
    }

    #[tokio::test]
    async fn emit_required_audit_survives_append_failure_without_aborting() {
        // GOLD-COR-04 / A-11: when a security audit frame CANNOT be written
        // (here: an oversize payload makes `append` reject synchronously, the
        // same failure class as a quota-full WAL), the helper must NOT panic
        // and must NOT propagate — the guarded action already happened, so the
        // operation continues; the loss is surfaced loud at error level
        // (audit_loss=true) instead. We assert the no-panic + no-frame outcome;
        // the error-level log is the documented side effect.
        let dir = tempdir().unwrap();
        let seg = dir.path().join("audit.wal");
        let (writer, _join) = crate::wal::writer::spawn(seg.clone()).unwrap();

        // First a VALID frame, so the segment + its header exist on disk and we
        // have a known-good baseline of exactly one HOOK_BLOCKED frame.
        emit_required_audit(
            &writer,
            crate::wal::events::EVENT_TYPE_HOOK_BLOCKED,
            "HOOK_BLOCKED",
            b"{\"ok\":1}".to_vec(),
        )
        .await;

        let oversize = vec![0u8; crate::wal::writer::MAX_PAYLOAD_BYTES + 1];
        // Returns normally (no panic, no Err to unwrap) despite the failed write.
        emit_required_audit(
            &writer,
            crate::wal::events::EVENT_TYPE_HOOK_BLOCKED,
            "HOOK_BLOCKED",
            oversize,
        )
        .await;

        // The rejected oversize frame must NOT have landed — only the valid one.
        let bytes = std::fs::read(&seg).unwrap();
        let hdr = crate::wal::segment_header::parse_segment_header(&bytes).unwrap();
        let mut cursor = hdr.header_len();
        let mut hook_frames = 0usize;
        while cursor < bytes.len() {
            let dec = match decode_frame(&bytes[cursor..]) {
                Ok(d) => d,
                Err(_) => break,
            };
            if dec.header.event_type == crate::wal::events::EVENT_TYPE_HOOK_BLOCKED {
                hook_frames += 1;
            }
            let total = dec.header.total_len as usize;
            if total == 0 {
                break;
            }
            cursor = cursor.saturating_add(total);
        }
        assert_eq!(
            hook_frames, 1,
            "exactly the one valid frame must land; the oversize one must be dropped"
        );
    }
}
