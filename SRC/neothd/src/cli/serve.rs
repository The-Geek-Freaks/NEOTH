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
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Args;
use tracing::{debug, error, info, warn};

use crate::channels::{
    Channel, InboundMessage, OutboundMessage, PipelineHandler, telegram::TelegramChannel,
};
use crate::config::FreedomConfig;
use crate::memory::{indexer, store};
use crate::providers::{self, Provider, Request};
use crate::shutdown;
use crate::wal::events::{
    EVENT_TYPE_BOOT, EVENT_TYPE_CHANNEL_EGRESS, EVENT_TYPE_CHANNEL_INGRESS, EVENT_TYPE_RAW_TEXT,
};
use crate::wal::writer::WalWriterHandle;
use crate::wal::{EventFlags, spawn as wal_spawn};

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
    #[cfg(feature = "wasm-plugin-host")]
    {
        if config.plugins.wasm.enabled {
            bootstrap_plugin_invoker(&FreedomConfig::default_neoth_home());
        } else {
            info!(
                "freedom.yaml::plugins.wasm.enabled = false; skipping plugin discovery + invoker bootstrap"
            );
        }
    }

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
    // twice. None if `from_config` fails — channels + scheduler then skip
    // gracefully rather than crash the daemon.
    let shared_provider: Option<Arc<dyn Provider>> = match providers::from_config(&config).await {
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
    let rate_limiter = Arc::new(crate::channels::rate_limit::RateLimiter::with_defaults());

    // ── 5c. Spawn configured channel adapters ──────────────────────────────
    //
    // Each configured channel runs in its own tokio task. The pipeline
    // handler is an Arc-cloned closure that the channel calls per incoming
    // message: emit WAL CHANNEL_INGRESS → call provider → emit CHANNEL_EGRESS
    // → return reply for the channel to send.
    let mut channel_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
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
            meter: provider_meter.clone(),
            rate_limiter: Arc::clone(&rate_limiter),
            segment_path: segment_path.clone(),
            profile_config: config.profile.clone(),
            reload_controller: Arc::clone(&reload_controller),
            views_conn: shared_views_conn.clone(),
        });
        let channel = TelegramChannel::new(telegram_token, config.telegram_user_id);
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
                }),
                max_concurrent_connections: None,
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
            Some(crate::cli::dreaming_task::spawn(
                crate::config::FreedomConfig::default_neoth_home(),
                embed_provider,
                config
                    .dreaming
                    .interval_secs
                    .map(std::time::Duration::from_secs),
                config
                    .dreaming
                    .window_secs
                    .map(std::time::Duration::from_secs),
                config.dreaming.max_events,
            ))
        } else {
            None
        };

    // ── 5b-bis. Hebbian decay task — QUELLEN Q-8 adoption ──────────────────
    //
    // Runs `memory::consolidate::run_consolidation_pass` every 2h. Math
    // primitives (decay 0.97/0.99/0.997, FORGET_FLOOR 0.10, PROMOTION 0.65)
    // are math-validated in `memory::tiers`. Task aborts on shutdown.
    let decay_task = Some(crate::memory::decay_task::spawn(
        store::default_path(),
        crate::memory::decay_task::DEFAULT_INTERVAL,
    ));
    info!(
        interval_secs = crate::memory::decay_task::DEFAULT_INTERVAL.as_secs(),
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
    let updater_self_task: Option<tokio::task::JoinHandle<()>> = {
        let writer_for_updater = writer.clone();
        let cfg = crate::daemon::updater_cron::UpdaterCronConfig::default();
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
        let cfg = crate::daemon::updater_cron::UpdaterCronConfig::default();
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
        let cfg = crate::daemon::updater_cron::UpdaterCronConfig::default();
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
        let cfg = crate::daemon::doctor_cron::DoctorCronConfig::default();
        let handle =
            crate::daemon::doctor_cron::spawn_doctor_cron_loop(cfg, home, writer_for_doctor, sink);
        if handle.is_some() {
            info!("doctor cron loop spawned (EL-01)");
        }
        handle
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
    info!("cluster audit sidecar ingester spawned (5s tick)");

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
    // Block at this stage logs + skips (a hook that hard-stops boot would
    // need explicit operator escalation — defer to v0.4).
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
                warn!(
                    hook = %name,
                    reason = %reason,
                    "on_session_start hook returned Block; ignored (daemon already booted)"
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
    let writer_died = tokio::select! {
        biased;
        _ = shutdown::wait_for_signal() => false,
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

    // Abort channel tasks first so they stop generating new WAL frames.
    for task in &channel_tasks {
        task.abort();
    }
    for task in channel_tasks {
        let _ = task.await; // ignore JoinError on aborted tasks
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

    // Abort the catalog refresh task. May be in the middle of an HTTPS
    // round-trip; aborting drops the connection, which is fine — the
    // next daemon start will re-run discovery on its first tick.
    catalog_task.abort();
    let _ = catalog_task.await;

    // Abort the cluster audit sidecar ingester. Pending sidecars
    // on disk are retained — the next daemon start picks them up
    // on its first tick (at-least-once semantics are fine for an
    // audit frame, the WAL writer dedupes by frame hash).
    cluster_audit_task.abort();
    let _ = cluster_audit_task.await;

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

    // Abort the R-02 Phase 4c dreaming task. Embed-path callers
    // hit `spawn_blocking` for OuroModel/local_qwen forward;
    // aborting cancels the JoinHandle but the blocking task
    // may run to completion (acceptable — drains naturally,
    // never strands the model load).
    if let Some(task) = dreaming_task {
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

/// Captured dependencies for `build_pipeline_handler`. K-Wire-3 v0
/// (Session 13): replaces a 9-argument signature that previously needed
/// `#[allow(clippy::too_many_arguments)]`. Construct at the call site,
/// then pass once. Fields stay `pub(crate)` so future channel adapters
/// (Slack, WhatsApp, Discord) can build the same closure without
/// re-listing every captured value.
pub(crate) struct PipelineHandlerDeps {
    pub(crate) provider: Arc<dyn Provider>,
    pub(crate) writer: WalWriterHandle,
    pub(crate) operator_id: Option<String>,
    pub(crate) autonomy: crate::permissions::AutonomyLevel,
    pub(crate) meter: crate::providers::meter::Meter,
    pub(crate) rate_limiter: Arc<crate::channels::rate_limit::RateLimiter>,
    /// Segment path the channel-side profile pipeline replays before
    /// reading idx_episode. Same path the daemon's tail-indexer uses;
    /// `indexer::replay_once` is cursor-based + idempotent.
    pub(crate) segment_path: std::path::PathBuf,
    /// Opt-in profile-learning policy. When `learn_enabled: true`,
    /// channels (Telegram / WhatsApp / Slack) grow the operator-profile
    /// passively the same way `neoth chat` does. Default off — paid-
    /// cloud operators don't get a surprise 2× token bill per inbound
    /// message.
    pub(crate) profile_config: crate::config::ProfileConfig,
    /// Pick #39 (Session 14, hot-reload live-propagation): instead of
    /// capturing a frozen `Arc<FreedomConfig>` at handler-build time,
    /// the handler now carries the `ReloadController`. Every inbound
    /// message calls `reload_controller.latest()` once at the top of
    /// the closure body — that snapshot is then used for the whole
    /// turn, so tunable fields (`council.selection_mode`,
    /// `code_map.auto_context_max_files`, autonomy level, etc.)
    /// reflect any operator-triggered `neoth reload` since the prior
    /// message. Immutable fields stay rejected at validate-time per
    /// Pick #37 (which is why the provider Arc + channel adapters
    /// are still safe to use without rebuild).
    pub(crate) reload_controller: Arc<crate::config::reload::ReloadController>,
    /// Pick #38 (Session 14, Perf #11 fix): shared `views.db`
    /// connection that survives across inbound messages, eliminating
    /// the ~10ms per-message `store::open` overhead. `None` when
    /// startup couldn't open or drain views.db — handler falls back
    /// to per-call open so the channel path still works.
    pub(crate) views_conn: Option<Arc<tokio::sync::Mutex<rusqlite::Connection>>>,
}

/// Build the per-channel pipeline handler closure. Captured: provider trait
/// object (shared Arc) + WAL writer handle (cheap Clone of an mpsc sender).
/// Each inbound message: WAL INGRESS → provider.complete → WAL EGRESS →
/// reply.
fn build_pipeline_handler(deps: PipelineHandlerDeps) -> PipelineHandler {
    let PipelineHandlerDeps {
        provider,
        writer,
        operator_id,
        autonomy,
        meter,
        rate_limiter,
        segment_path,
        profile_config,
        reload_controller,
        views_conn,
    } = deps;
    Box::new(move |inbound: InboundMessage| {
        let provider = Arc::clone(&provider);
        let writer = writer.clone();
        let operator_id = operator_id.clone();
        let meter = meter.clone();
        let rate_limiter = Arc::clone(&rate_limiter);
        let segment_path = segment_path.clone();
        let profile_config = profile_config.clone();
        // Pick #39 (Session 14, hot-reload live-propagation): snapshot
        // the live config ONCE at the top of the handler. Tunables
        // reflect any `neoth reload` since the previous message;
        // immutable fields are guaranteed stable by the validator at
        // reload-time. Single `latest()` call per inbound means
        // mid-message config-flip is impossible.
        let config_for_handler = reload_controller.latest();
        let views_conn = views_conn.clone();
        Box::pin(async move {
            // R-9 multimodal: if the inbound message carries a media
            // attachment, run it through the extraction pipeline first.
            // The result either replaces `text` (audio → transcript) or
            // surfaces as an operator-facing acknowledgement (image →
            // "embedding cached"). Text-bearing messages with no media
            // skip this branch entirely. Audit frames
            // (INGEST_EXTRACTED + EMBED_PERSISTED) are emitted via the
            // daemon's primary writer so the channel-side pipeline
            // stays consistent with `neoth ingest`.
            let effective_text: Option<String> = if let Some(media) = inbound.media.clone() {
                match crate::cli::serve::handle_media_attachment(&inbound, &media, Some(&writer))
                    .await
                {
                    Ok(text) => Some(text),
                    Err(e) => {
                        tracing::warn!(error = %e, "media attachment pipeline failed");
                        Some(format!("[NEOTH] media pipeline error: {e}"))
                    }
                }
            } else {
                inbound.text.clone()
            };

            let Some(raw_text) = effective_text.as_deref() else {
                info!(
                    channel = inbound.channel.as_str(),
                    sender = %inbound.sender_id,
                    "inbound message has no text payload + no media; dropping silently"
                );
                return Ok(::std::option::Option::None);
            };
            let channel_str = inbound.channel.as_str();

            // ── PreChannelIngress hooks (Phase 29 R-15) ───────────────────
            // Fire operator-defined hooks before the sanitizer + WAL
            // ingress frame. A Replace rewrites the inbound text (e.g.
            // redact secrets that the operator typo'd into a channel);
            // a Block silently drops the turn (no reply, no WAL ingress
            // frame). Empty hook set → no-op.
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
            let hooked_text: String = match crate::hooks::run_stage(
                crate::hooks::HookStage::PreChannelIngress,
                raw_text,
                &hooks,
            ) {
                Ok(crate::hooks::StageOutcome::Continue { body, hits }) => {
                    for name in &hits {
                        let payload = match serde_json::to_vec(&serde_json::json!({
                            "name": name,
                            "stage": "pre_channel_ingress",
                            "channel": channel_str,
                            "sender_id": inbound.sender_id,
                            "ts_unix": std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0),
                        })) {
                            Ok(p) => p,
                            Err(e) => {
                                warn!(error = %e, "serialize PreChannelIngress frame failed");
                                continue;
                            }
                        };
                        let header = crate::wal::HeaderBuilder::new(
                            crate::wal::events::EVENT_TYPE_HOOK_FIRED,
                            &payload,
                        )
                        .build();
                        if let Err(e) = writer.append(header, payload).await {
                            warn!(error = %e, "WAL append PreChannelIngress hook frame failed");
                        }
                    }
                    body
                }
                Ok(crate::hooks::StageOutcome::Block { name, reason }) => {
                    info!(
                        channel = channel_str,
                        sender = %inbound.sender_id,
                        hook = %name,
                        reason = %reason,
                        "inbound dropped by pre_channel_ingress hook"
                    );
                    let payload = match serde_json::to_vec(&serde_json::json!({
                        "name": name,
                        "stage": "pre_channel_ingress",
                        "channel": channel_str,
                        "sender_id": inbound.sender_id,
                        "reason": reason,
                        "ts_unix": std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0),
                    })) {
                        Ok(p) => p,
                        Err(e) => {
                            warn!(error = %e, "serialize PreChannelIngress block frame failed");
                            return Ok(::std::option::Option::None);
                        }
                    };
                    let header = crate::wal::HeaderBuilder::new(
                        crate::wal::events::EVENT_TYPE_HOOK_BLOCKED,
                        &payload,
                    )
                    .build();
                    if let Err(e) = writer.append(header, payload).await {
                        warn!(error = %e, "WAL append PreChannelIngress block frame failed");
                    }
                    return Ok(::std::option::Option::None);
                }
                Err(e) => {
                    warn!(error = %e, "PreChannelIngress hook dispatch failed");
                    raw_text.to_string()
                }
            };
            let raw_text = hooked_text.as_str();

            // BS-11: per-sender rate limit BEFORE any WAL write. Drops
            // are silent (no reply) — a misbehaving upstream learns from
            // its own retry backoff, not from NEOTH explaining itself.
            // Hits are logged + a CHANNEL_ERROR WAL frame records the
            // drop for the audit trail.
            match rate_limiter.try_consume(channel_str, &inbound.sender_id) {
                crate::channels::rate_limit::Decision::Allowed => {}
                crate::channels::rate_limit::Decision::RateLimited { retry_after_ms } => {
                    info!(
                        channel = channel_str,
                        sender = %inbound.sender_id,
                        retry_after_ms,
                        "inbound rate-limited; dropping",
                    );
                    // Never emit a zero-byte WAL frame — a corrupted
                    // payload misparses the rest of the segment. If
                    // serialisation fails (it cannot here — all fields
                    // are primitives — but the pattern stays defensive)
                    // drop the audit frame entirely.
                    let payload = match serde_json::to_vec(&serde_json::json!({
                        "channel": channel_str,
                        "sender_id": inbound.sender_id,
                        "reason": "rate_limited",
                        "retry_after_ms": retry_after_ms,
                    })) {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "rate-limit audit payload serialisation failed; frame skipped"
                            );
                            return Ok(::std::option::Option::None);
                        }
                    };
                    let header = crate::wal::HeaderBuilder::new(
                        crate::wal::events::EVENT_TYPE_CHANNEL_ERROR,
                        &payload,
                    )
                    .build();
                    if let Err(e) = writer.append(header, payload).await {
                        tracing::warn!(error = %e, "WAL append failed (best-effort audit frame)");
                    }
                    return Ok(::std::option::Option::None);
                }
            }
            // ── Phase 11a gate: sanitize before ANY downstream effect ─────
            // Per memory/neoth-research-synthesis.md anti-pattern #4:
            // skipping this gate = highest-risk shortcut. Quarantined
            // messages are dropped silently (no reply, no provider call)
            // and only logged to the JSONL audit trail.
            let report = crate::security::ingress_sanitizer::sanitize(raw_text, channel_str);
            let audit_dir = crate::config::FreedomConfig::default_neoth_home().join("audit");
            if let Err(e) =
                crate::security::ingress_sanitizer::audit_append(&report, &audit_dir).await
            {
                warn!(error = %e, "ingress audit append failed; continuing");
            }
            if report.quarantined {
                info!(
                    channel = channel_str,
                    sender = %inbound.sender_id,
                    findings = ?report.findings,
                    input_hash = %report.input_hash,
                    "inbound message quarantined; dropping silently"
                );
                return Ok(::std::option::Option::None);
            }
            // Use the sanitized text from here on. The raw input never
            // touches the WAL or the provider.
            let sanitized_text = report.text;

            // ── Emit RAW_TEXT for the inbound message (recallable body) ───
            let raw_header =
                crate::wal::make_header(EVENT_TYPE_RAW_TEXT, sanitized_text.as_bytes());
            writer
                .append(raw_header, sanitized_text.as_bytes().to_vec())
                .await
                .context("write RAW_TEXT WAL frame for inbound")?;

            // ── P-08 briefing-gate marker (Workstream C, Session 22) ──────
            // Channel ingress is the operator engaging via any wired
            // surface (Telegram / Discord / Keet / …). Refresh the
            // last-active marker so the briefing-gate's inactivity check
            // treats this as a real engagement signal. Best-effort: a
            // permission failure on the marker file MUST NOT fail the
            // inbound handler — recording is an audit signal, not an
            // ingress-correctness invariant.
            let _ = crate::profile::briefing_gate::record_last_active(
                &crate::config::FreedomConfig::default_neoth_home(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0),
            );

            // ── Emit CHANNEL_INGRESS (hashed metadata) ────────────────────
            let ingress_payload = serde_json::to_vec(&serde_json::json!({
                "channel": inbound.channel,
                "sender_id": inbound.sender_id,
                "sender_display": inbound.sender_display,
                "text_hash_xxh3": xxhash_rust::xxh3::xxh3_64(sanitized_text.as_bytes()),
                "text_bytes": sanitized_text.len(),
                "operator_id": operator_id,
                "channel_ts_unix": inbound.channel_ts_unix,
                "sanitizer_input_hash": report.input_hash,
                "sanitizer_findings": report.findings,
            }))?;
            let ingress_header =
                crate::wal::make_header(EVENT_TYPE_CHANNEL_INGRESS, &ingress_payload);
            // K-Wire-3 v3 2026-05-17: capture the event_id BEFORE the
            // header moves into append. The post-reply profile pipeline
            // (added below the SESSION_ARCHIVE block) uses this as the
            // trigger anchor for `extract_window` — analog to chat.rs's
            // `raw_event_id` capture on the RAW_TEXT frame.
            let ingress_event_id = ingress_header.event_id.0 as i64;
            writer
                .append(ingress_header, ingress_payload)
                .await
                .context("write CHANNEL_INGRESS WAL frame")?;

            // ── Permission gate (Phase 28b AU-4 + Pick #10 fix) ──────────
            // Daemon path has no TTY — use FailClosed strategy. Channel-driven
            // confirm (AU-4-part-2) wires here once the channel callback is
            // ready: switch to `ConfirmStrategy::Channel` and provide the
            // adapter hook.
            //
            // Pick #10 (Session 14, 2026-05-18 Codex feedback): the prior
            // `eur_estimate: 0.0` hardcode silently bypassed Standard +
            // Elevated cost thresholds (€0.50 / €5.00). Now uses
            // `cost::predict` over the configured provider+model so the
            // channel path enforces the same cost contract as `chat.rs`.
            {
                use crate::permissions::{Action, ConfirmStrategy, Gate};
                use crate::providers::cost::predict as predict_cost;
                use crate::providers::meter::Meter;
                let provider_id = config_for_handler
                    .provider_kind
                    .as_ref()
                    .map(|k| match k {
                        crate::cli::init::ProviderKind::ClaudeCli => "claude_cli",
                        crate::cli::init::ProviderKind::OpenaiApi => "openai_api",
                        crate::cli::init::ProviderKind::OpenaiCompat => "openai_compat",
                        crate::cli::init::ProviderKind::GeminiApi => "gemini_api",
                        crate::cli::init::ProviderKind::LocalQwen => "local_qwen",
                        crate::cli::init::ProviderKind::LocalOuro => "local_ouro",
                        crate::cli::init::ProviderKind::AwsBedrock => "aws_bedrock",
                        crate::cli::init::ProviderKind::AzureOpenAi => "azure_openai",
                        crate::cli::init::ProviderKind::Skip => "unknown",
                    })
                    .unwrap_or("unknown");
                let model_str = config_for_handler
                    .provider_model
                    .as_deref()
                    .unwrap_or("unknown");
                let meter = Meter::with_default_window();
                let cost = predict_cost(provider_id, model_str, &sanitized_text, &meter);
                let action = Action::PaidProviderCall {
                    eur_estimate: cost.total_eur,
                };
                let gate = Gate::for_level(autonomy).with_confirm(ConfirmStrategy::FailClosed);
                if let Err(e) = gate.check(&action, Some(&writer)).await {
                    warn!(
                        channel = channel_str,
                        provider = provider_id,
                        model = model_str,
                        eur_estimate = cost.total_eur,
                        error = %e,
                        "channel pipeline blocked by autonomy gate (PaidProviderCall)"
                    );
                    return Ok(::std::option::Option::None);
                }
            }

            // ── K-Wire-3 (Session 23) — channel-side enrichment via helper ─
            // Channel inbounds now reach CLI parity on every layer the
            // `pipeline::build_enriched_request` helper composes:
            // operator_md + skills + MCP catalogue + persona + repo
            // context. Prior channel path skipped all of these and sent
            // the bare prompt to the provider. Slash command dispatch
            // (below) overrides the enriched system when a `/cmd`
            // matches — preserving the original slash semantics.
            //
            // Note: this adds 5 FS reads per inbound (operator_md +
            // skills dir + mcp_servers.yaml + tweaks.toml + code_map
            // sqlite probe). Matches `chat.rs::run_chat_with` cost; on
            // a healthy filesystem the combined latency is sub-30ms.
            let channel_home = crate::config::FreedomConfig::default_neoth_home();
            let channel_cwd = std::env::current_dir().unwrap_or_else(|_| channel_home.clone());
            let operator_blocks = crate::memory::operator_md::assemble(&channel_home, &channel_cwd)
                .await
                .unwrap_or_default();
            let operator_context = if operator_blocks.is_empty() {
                None
            } else {
                Some(crate::memory::operator_md::render(&operator_blocks))
            };

            // Prefer the daemon's global SkillRegistry (built once at
            // startup + hot-reloaded by the file watcher); fall back to
            // per-call load when the global wasn't initialised.
            let installed_skills = match crate::skills::registry::global() {
                Some(reg) => reg.snapshot_owned(),
                None => {
                    match crate::skills::SkillRegistry::load(&channel_home.join("skills")).await {
                        Ok(reg) => reg.snapshot_owned(),
                        Err(e) => {
                            warn!(
                                error = %e,
                                "skill registry load failed on channel path; empty set"
                            );
                            std::sync::Arc::new(Vec::new())
                        }
                    }
                }
            };
            let mode_registry =
                crate::skills::mode_registry::ModeRegistry::from_skills(&installed_skills)
                    .unwrap_or_default();
            let mode_hit = mode_registry.match_trigger(&sanitized_text);
            let (skill_layer, used_skill_id): (Option<String>, Option<String>) =
                if let Some(resolved) = mode_hit {
                    let parent = installed_skills
                        .iter()
                        .find(|s| s.id() == resolved.skill_id);
                    info!(
                        channel = channel_str,
                        mode = %resolved.mode.id,
                        skill = %resolved.skill_id,
                        "mode activated via ModeRegistry (channel path)"
                    );
                    let layer = match parent {
                        Some(p) if !resolved.mode.system_prompt_delta.is_empty() => Some(format!(
                            "{}\n\n{}",
                            p.system_prompt(),
                            resolved.mode.system_prompt_delta
                        )),
                        Some(p) => Some(p.system_prompt().to_string()),
                        None if !resolved.mode.system_prompt_delta.is_empty() => {
                            Some(resolved.mode.system_prompt_delta.clone())
                        }
                        None => None,
                    };
                    (layer, None)
                } else {
                    let skill_match = crate::skills::route(&sanitized_text, &installed_skills);
                    if let Some(m) = &skill_match {
                        info!(
                            channel = channel_str,
                            skill = m.skill.id(),
                            matched_keywords = ?m.matched_keywords,
                            "skill activated (channel path)"
                        );
                    }
                    let layer = skill_match
                        .as_ref()
                        .map(|m| m.skill.system_prompt().to_string());
                    let id = skill_match.as_ref().map(|m| m.skill.id().to_string());
                    (layer, id)
                };

            let channel_mcp_servers = crate::mcp::McpServers::load().unwrap_or_else(|e| {
                warn!(
                    error = %e,
                    "mcp_servers.yaml load failed on channel path — proceeding without MCP tools"
                );
                Default::default()
            });
            let channel_mcp_catalogue: Option<String> = if channel_mcp_servers.enabled().is_empty()
            {
                None
            } else {
                crate::mcp::catalogue::assemble_catalogue(&channel_mcp_servers).await
            };

            let channel_tweaks_path = crate::tweaks::Tweaks::default_path();
            let channel_persona = crate::tweaks::Tweaks::load_or_default(&channel_tweaks_path)
                .ok()
                .and_then(|t| t.persona_override.clone());

            // AR-01 (Session 24) — channel path must read the live
            // active preset on every inbound so a mid-day
            // `neoth profile preset apply` flips the channel-side
            // system prompt without restarting the daemon.
            let channel_preset_home = crate::config::FreedomConfig::default_neoth_home();
            let channel_preset_addendum =
                crate::cli::profile::load_active_preset(&channel_preset_home)
                    .map(|p| crate::profile::presets::apply_preset(p).system_addendum)
                    .filter(|s| !s.is_empty());

            let channel_repo_context = crate::cli::chat::maybe_repo_context_block(
                config_for_handler.as_ref(),
                &sanitized_text,
            );

            let channel_enriched =
                crate::pipeline::build_enriched_request(crate::pipeline::EnrichmentInputs {
                    prompt: &sanitized_text,
                    operator_context: operator_context.as_deref(),
                    preset_addendum: channel_preset_addendum.as_deref(),
                    explicit_system: None,
                    repo_context_block: channel_repo_context.as_deref(),
                    skill_system_prompt: skill_layer.as_deref(),
                    used_skill_id: used_skill_id.as_deref(),
                    mcp_catalogue: channel_mcp_catalogue.as_deref(),
                    persona_override: channel_persona.as_deref(),
                });
            let channel_enriched_system = channel_enriched.system;
            let _channel_used_skill_id = channel_enriched.used_skill_id;

            // ── Slash command dispatch (Phase 28 R-17 SC-2) ───────────────
            // If the operator opens with `/<name> args`, route through the
            // slash registry. Built-ins (`/help`, `/recall`, `/status`,
            // `/jobs`) + `~/.neoth/commands/*.toml` overrides. The matched
            // command's prompt template REPLACES the enriched system
            // prompt (slash semantics preserved); non-matches fall back
            // to the layered enrichment from the helper above.
            let (final_prompt, system_override) =
                match crate::slash::parse_invocation(&sanitized_text) {
                    crate::slash::Invocation::Command { name, args } => {
                        let slash_dir =
                            crate::config::FreedomConfig::default_neoth_home().join("commands");
                        let commands = crate::slash::load_all(&slash_dir).await.unwrap_or_default();
                        if let Some(cmd) = commands.iter().find(|c| c.name == name) {
                            let rendered = cmd.render(&args, operator_id.as_deref());
                            info!(slash_command = %name, "slash dispatch");
                            (args, Some(rendered))
                        } else {
                            // Unknown command — pass through with the
                            // enriched system so the model can still
                            // respond with "unknown command, try /help".
                            (sanitized_text.clone(), channel_enriched_system)
                        }
                    }
                    crate::slash::Invocation::Escaped { text } => (text, channel_enriched_system),
                    crate::slash::Invocation::NotACommand => {
                        (sanitized_text.clone(), channel_enriched_system)
                    }
                };

            // ── Operator hooks at PreProviderCall (Phase 29 R-15 H-3) ─────
            // Loaded fresh per turn so operator edits to `~/.neoth/hooks/`
            // take effect without daemon restart. Block-action stops the
            // turn (no provider call, no reply); replace mutates the
            // outbound prompt. Empty hook set is the common case.
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
            let (final_prompt, hook_hits) = match crate::hooks::run_stage(
                crate::hooks::HookStage::PreProviderCall,
                &final_prompt,
                &hooks,
            ) {
                Ok(crate::hooks::StageOutcome::Continue { body, hits }) => (body, hits),
                Ok(crate::hooks::StageOutcome::Block { name, reason }) => {
                    info!(hook = %name, reason = %reason, "PreProviderCall hook blocked turn");
                    let payload = match serde_json::to_vec(&serde_json::json!({
                        "name": name,
                        "stage": crate::hooks::HookStage::PreProviderCall.as_str(),
                        "reason": reason,
                    })) {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "HOOK_BLOCKED audit payload serialisation failed; frame skipped"
                            );
                            return Ok(::std::option::Option::None);
                        }
                    };
                    let header = crate::wal::make_header(
                        crate::wal::events::EVENT_TYPE_HOOK_BLOCKED,
                        &payload,
                    );
                    if let Err(e) = writer.append(header, payload).await {
                        tracing::warn!(error = %e, "WAL append failed (best-effort audit frame)");
                    }
                    return Ok(::std::option::Option::None);
                }
                Err(e) => {
                    warn!(error = %e, "hook dispatcher errored — continuing without hooks");
                    (final_prompt, Vec::new())
                }
            };
            for name in &hook_hits {
                let payload = match serde_json::to_vec(&serde_json::json!({
                    "name": name,
                    "stage": crate::hooks::HookStage::PreProviderCall.as_str(),
                })) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            hook = %name,
                            "HOOK_FIRED audit payload serialisation failed; frame skipped"
                        );
                        continue;
                    }
                };
                let header =
                    crate::wal::make_header(crate::wal::events::EVENT_TYPE_HOOK_FIRED, &payload);
                if let Err(e) = writer.append(header, payload).await {
                    tracing::warn!(error = %e, "WAL append failed (best-effort audit frame)");
                }
            }

            // ── Provider call (with MCP autoroute — K-Wire-3 v1) ──────────
            //
            // 2026-05-17: channels now share the same MCP-autoroute path
            // as `neoth chat`. Tri-state env override per A8:
            //   `NEOTH_MCP_AUTOROUTE=1` → forced ON
            //   `NEOTH_MCP_AUTOROUTE=0` → forced OFF
            //   unset / any other value → AUTO (on when `mcp_servers.yaml`
            //                                   has ≥1 enabled server)
            // Operators with no MCP servers configured see zero behaviour
            // change. Operators who pinned `mcp_servers.yaml` get tool-use
            // on every Telegram / WhatsApp / Slack inbound the same way
            // they get it on `neoth chat`.
            //
            // Failure mode: an MCP loop error falls back to the direct
            // provider.complete path with a WARN log — channels are
            // async-delivery (no operator-retry surface), so silent
            // fallback is the right UX trade-off vs CLI's fail-loud.
            // Operators grep logs to detect MCP-loop regressions.
            //
            // Council debate for channels is K-Wire-3 v2 (deferred —
            // callosum-recovery branch is 130+ LOC of complex logic
            // intertwined with CLI-specific paths).
            let started = Instant::now();
            // R-04 2026-05-17: clone final_prompt + system_override so
            // the LOWKEY refusal-recovery path post-reply can reissue
            // the same (prompt, system) pair under a reframing. See
            // `cli/chat.rs` for the matching pattern.
            let req = Request {
                prompt: final_prompt.clone(),
                system: system_override.clone(),
                model: None,
                ..Default::default()
            };
            // K-Wire-3 v2 2026-05-17: council smart-trigger for channels.
            // Same evaluation logic as `cli/chat.rs::run_chat_with` —
            // promoted via `chat::evaluate_council_trigger`. Operators
            // on `inference.mode = triplet` or `custom` get a
            // 3-hemisphere debate on every substantive Telegram /
            // WhatsApp / Slack message; operators on `single` mode see
            // no behaviour change because all three hemispheres resolve
            // to the same provider via `from_config_for_role`.
            //
            // Mutually exclusive with MCP autoroute (council debates
            // many providers, autoroute wraps one). Council wins when
            // the trigger fires; otherwise the dispatch falls through
            // to the existing MCP-autoroute / direct branches.
            //
            // Channels pass a flat 0.01 EUR estimate to the budget
            // gate — they don't pre-compute a per-prompt cost like the
            // CLI's `cost_estimate` path. Operators wanting tighter
            // budget control raise `policy.budget_multiplier` in
            // freedom.yaml.
            let council_decision = crate::cli::chat::evaluate_council_trigger(&req.prompt, 0.01);
            let council_enable = council_decision.should_convene();
            // B-1 (Session 13) — channel-side COUNCIL_SKIP audit. Same
            // contract as the CLI path: every Skip decision lands in
            // the WAL so the operator can reconstruct why a channel
            // message was answered by the single Left hemisphere.
            if !council_enable {
                let prompt_hash_skip = xxhash_rust::xxh3::xxh3_64(req.prompt.as_bytes());
                let _ = crate::cli::chat::emit_council_skip(
                    &writer,
                    prompt_hash_skip,
                    council_decision.reason(),
                )
                .await;
            }
            // Finding 5 (Session 13) — runtime consent re-check per channel
            // message so a mid-run `neoth consent revoke <provider>` is
            // honoured WITHOUT daemon restart. Closes the TOCTOU gap
            // where V03-08 + A-2 only gate at startup. Bail surfaces an
            // operator-actionable error back through the channel adapter
            // rather than silently fanning out to the no-longer-consented
            // provider.
            {
                let home_revoke = crate::config::FreedomConfig::default_neoth_home();
                if let Err(e) = crate::consent::ensure_all_still_granted(
                    &home_revoke,
                    config_for_handler.as_ref(),
                ) {
                    warn!(
                        channel = channel_str,
                        sender = %inbound.sender_id,
                        error = %e,
                        "consent revoked mid-run; dropping inbound"
                    );
                    return Ok(::std::option::Option::Some(OutboundMessage {
                        recipient_id: inbound.sender_id.clone(),
                        text: format!("[NEOTH] {e}"),
                    }));
                }
            }
            let autoroute_env = std::env::var("NEOTH_MCP_AUTOROUTE").ok();
            let mcp_servers_for_loop = if council_enable {
                crate::mcp::McpServers::default()
            } else {
                // Pick #34 (Session 14, silent-failure audit-fix):
                // surface YAML parse errors so operators discover broken
                // mcp_servers.yaml instead of silently losing tools on
                // every channel message.
                crate::mcp::McpServers::load().unwrap_or_else(|e| {
                    warn!(error = %e, "mcp_servers.yaml load failed in channel autoroute — proceeding without MCP tools");
                    Default::default()
                })
            };
            let autoroute_decision =
                mcp_servers_for_loop.autoroute_decision(autoroute_env.as_deref());
            let use_loop = !council_enable && autoroute_decision.is_on();
            let mut completion = if council_enable {
                info!(
                    channel = channel_str,
                    decision = ?council_decision,
                    "channel council convened — running 3-hemisphere debate",
                );
                match crate::cli::chat::dispatch_council_with_recovery(
                    &req,
                    config_for_handler.as_ref(),
                    &writer,
                )
                .await
                {
                    Ok(text) => crate::providers::Completion {
                        text,
                        model: "council".to_string(),
                        latency: started.elapsed(),
                        input_tokens: None,
                        output_tokens: None,
                    },
                    Err(e) => {
                        warn!(
                            error = %e,
                            "channel council debate failed — falling back to direct provider call",
                        );
                        provider.complete(req).await?
                    }
                }
            } else if use_loop {
                info!(
                    reason = %autoroute_decision.reason(),
                    "channel MCP autoroute enabled — running dispatch loop",
                );
                let loop_req = req.clone();
                match crate::cli::chat::run_mcp_dispatch_loop(
                    &*provider,
                    loop_req,
                    &mcp_servers_for_loop,
                    autonomy,
                    &writer,
                    None,
                )
                .await
                {
                    Ok(outcome) => {
                        info!(
                            iterations = outcome.iterations,
                            successful_calls = outcome.successful_calls,
                            failed_calls = outcome.failed_calls,
                            hit_cap = outcome.hit_cap,
                            "channel MCP dispatch loop complete",
                        );
                        crate::providers::Completion {
                            text: outcome.final_text,
                            model: String::new(),
                            latency: started.elapsed(),
                            input_tokens: None,
                            output_tokens: None,
                        }
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            "channel MCP dispatch loop failed — falling back to direct provider call",
                        );
                        provider.complete(req).await?
                    }
                }
            } else {
                provider.complete(req).await?
            };
            let latency = started.elapsed();

            // Q-3: record into the rolling-window meter so `/metrics` reflects
            // the call's tokens + latency. Cheap: one mutex lock + a push.
            meter.record(
                completion.input_tokens.unwrap_or(0),
                completion.output_tokens.unwrap_or(0),
                latency,
            );

            // ── Mirror-refusal Schicht-0 detection + R-09 cause classifier ─
            // Channels previously skipped both signals (only chat.rs ran
            // them). R-09 wire 2026-05-17: emit `0x16 REFUSAL_OBSERVED`
            // with the cause classification bundled so operator audit +
            // future R-01 recovery state machine see the same signals on
            // any ingress surface. Best-effort: serialise failure logs +
            // continues; never blocks the channel reply.
            {
                let report = crate::security::refusal_detect::classify(&completion.text);
                if report.is_refusal() {
                    let cause = crate::security::refusal_cause::classify_cause(&completion.text);
                    let payload = serde_json::to_vec(&serde_json::json!({
                        "operator_id": operator_id,
                        "channel": inbound.channel,
                        "sender_id": inbound.sender_id,
                        "provider": provider.name(),
                        "model": completion.model,
                        "refusal_class": report.class.as_str(),
                        "confidence": report.confidence,
                        "matched_patterns": report.matched_patterns,
                        "cause": cause.cause.as_str(),
                        "cause_confidence": cause.confidence,
                        "cause_matched_patterns": cause.matched_patterns,
                        "response_hash_xxh3": xxhash_rust::xxh3::xxh3_64(
                            completion.text.as_bytes(),
                        ),
                        "ts_unix": std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0),
                    }));
                    match payload {
                        Ok(bytes) => {
                            let header = crate::wal::HeaderBuilder::new(
                                crate::wal::events::EVENT_TYPE_REFUSAL_OBSERVED,
                                &bytes,
                            )
                            .build();
                            if let Err(e) = writer.append(header, bytes).await {
                                tracing::warn!(error = %e,
                                    "WAL append REFUSAL_OBSERVED failed (best-effort audit)");
                            } else {
                                info!(
                                    channel = channel_str,
                                    refusal_class = report.class.as_str(),
                                    cause = cause.cause.as_str(),
                                    cause_confidence = cause.confidence,
                                    "channel mirror-refusal detector + cause classifier fired"
                                );
                            }
                        }
                        Err(e) => tracing::warn!(error = %e,
                            "serialize channel REFUSAL_OBSERVED payload failed"),
                    }
                }
            }

            // ── R-04 LOWKEY refusal recovery (channel path) ──────────────
            // Same shape as `cli/chat.rs::run_chat_with`'s recovery wire:
            // when the Schicht-0 detector found a refusal + the operator
            // opted in (default ON), call try_recover once, replace
            // completion.text on success so downstream egress sees the
            // recovered reply. Per-call escape via
            // `NEOTH_REFUSAL_RECOVERY_DISABLE=1`.
            if config_for_handler.refusal_recovery.enabled
                && std::env::var("NEOTH_REFUSAL_RECOVERY_DISABLE")
                    .map(|v| !(v == "1" || v.eq_ignore_ascii_case("true")))
                    .unwrap_or(true)
            {
                let report = crate::security::refusal_detect::classify(&completion.text);
                if report.is_refusal() {
                    let recovery_req = crate::providers::Request {
                        prompt: final_prompt.clone(),
                        system: system_override.clone(),
                        model: None,
                        ..Default::default()
                    };
                    let now_unix = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    match crate::security::refusal_recovery::try_recover_multi(
                        &*provider,
                        &recovery_req,
                        &completion.text,
                        &config_for_handler.refusal_recovery.disabled_reframings,
                        Some(&writer),
                        now_unix,
                        config_for_handler.refusal_recovery.max_attempts,
                    )
                    .await
                    {
                        Ok(crate::security::refusal_recovery::RecoveryOutcome::Recovered {
                            completion: recovered,
                            reframing_id,
                        }) => {
                            info!(
                                channel = channel_str,
                                reframing = reframing_id,
                                original_bytes = completion.text.len(),
                                recovered_bytes = recovered.text.len(),
                                "channel refusal recovery succeeded — replacing completion.text",
                            );
                            completion.text = recovered.text;
                        }
                        Ok(crate::security::refusal_recovery::RecoveryOutcome::RefusedAgain {
                            reframing_id,
                            ..
                        }) => {
                            info!(
                                channel = channel_str,
                                reframing = reframing_id,
                                "channel refusal recovery attempted but model refused again",
                            );
                        }
                        Ok(
                            crate::security::refusal_recovery::RecoveryOutcome::NotRecoverable {
                                cause,
                            },
                        ) => {
                            tracing::debug!(
                                channel = channel_str,
                                cause = cause.as_str(),
                                "channel refusal not recoverable",
                            );
                        }
                        Ok(crate::security::refusal_recovery::RecoveryOutcome::ProviderError {
                            reframing_id,
                            error,
                        }) => {
                            warn!(
                                channel = channel_str,
                                reframing = reframing_id,
                                error = %error,
                                "channel refusal recovery retry hit provider error",
                            );
                        }
                        Err(e) => {
                            warn!(error = %e, "channel refusal recovery failed (non-fatal)");
                        }
                    }
                }
            }

            // ── ADR auto-extraction (Phase 31 R-21 ADR-1) ─────────────────
            // Scan the reply for `DECISION:` / `Beschluss:` / `ADR:` markers
            // and write any detected blocks to ~/.neoth/adr/NNNN-<slug>.md.
            // Best-effort: never blocks the egress on disk failure.
            {
                let decisions = crate::adr::extract_decisions(&completion.text);
                if !decisions.is_empty() {
                    let adr_dir = crate::adr::default_adr_dir();
                    for d in &decisions {
                        match crate::adr::write_adr(&adr_dir, d) {
                            Ok(path) => {
                                info!(adr = %path.display(), title = %d.title, "ADR captured")
                            }
                            Err(e) => warn!(error = %e, "failed to write ADR"),
                        }
                    }
                }
            }

            // ── Emit CHANNEL_EGRESS ───────────────────────────────────────
            let egress_payload = serde_json::to_vec(&serde_json::json!({
                "channel": inbound.channel,
                "recipient_id": inbound.sender_id,
                "reply_hash_xxh3": xxhash_rust::xxh3::xxh3_64(completion.text.as_bytes()),
                "reply_bytes": completion.text.len(),
                "provider": provider.name(),
                "model": completion.model,
                "latency_ns": u64::try_from(latency.as_nanos()).unwrap_or(u64::MAX),
                "input_tokens": completion.input_tokens,
                "output_tokens": completion.output_tokens,
            }))?;
            let egress_header = crate::wal::make_header(EVENT_TYPE_CHANNEL_EGRESS, &egress_payload);
            writer
                .append(egress_header, egress_payload)
                .await
                .context("write CHANNEL_EGRESS WAL frame")?;

            // ── SESSION ARCHIVE (Phase 28a MT-4) ──────────────────────────
            // Append the turn pair to the operator-readable MD archive.
            // Session id = `<channel>-<sender>`: stable per-correspondent
            // file per UTC day. Failure logs but never blocks egress —
            // the WAL is the source of truth.
            {
                let session_id = format!("{}-{}", channel_str, inbound.sender_id);
                let now = chrono::Utc::now();
                let archive = crate::memory::archive::SessionArchive::new(
                    crate::memory::archive::default_archive_root(),
                    session_id,
                    now,
                );
                if let Err(e) = archive
                    .append_turn(&sanitized_text, &completion.text, now)
                    .await
                {
                    warn!(error = %e, "session archive append failed");
                }
            }

            // ── Profile pipeline post-reply (K-Wire-3 v3 2026-05-17) ──────
            // Mirrors `cli/chat.rs::run_chat_with`'s post-reply learning
            // block: when the operator opts in via
            // `freedom.yaml::profile.learn_enabled: true`, channels grow
            // the operator-profile passively from every Telegram /
            // WhatsApp / Slack message. Same gate, same timeout cap,
            // same env overrides (`NEOTH_PROFILE_LEARN_DISABLE` /
            // `NEOTH_PROFILE_LEARN_FORCE`).
            //
            // Trigger anchor: `ingress_event_id` captured above from the
            // CHANNEL_INGRESS frame. The indexer's `replay_once` pass
            // ensures that frame is in idx_episode before the pipeline
            // reads the conversation window.
            //
            // Best-effort: any failure (views.db open, indexer, extract,
            // guard, timeout) logs at warn/debug and never blocks the
            // channel reply. Channels are async-delivery — a hung
            // extract LLM call would otherwise pin the entire ingress
            // task and starve other channel messages.
            let env_disable = std::env::var("NEOTH_PROFILE_LEARN_DISABLE")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            let env_force = std::env::var("NEOTH_PROFILE_LEARN_FORCE")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            let learn_on = !env_disable && (env_force || profile_config.learn_enabled);
            if learn_on {
                let timeout = std::time::Duration::from_secs(profile_config.timeout_secs.max(1));
                let views_path = crate::memory::store::default_path();
                // K-Wire-3 v3 Send-escape: `rusqlite::Transaction` is
                // !Send. The channel handler's outer future must be
                // Send (PipelineHandler = Pin<Box<dyn Future + Send>>),
                // so we cannot hold a Transaction across an await on
                // the main task path. `block_in_place` moves the
                // current task to a blocking-pool thread; we then
                // `block_on` a !Send future on that same thread. The
                // multi-threaded tokio runtime keeps making progress
                // on other channel messages because the blocking task
                // is moved off the worker pool.
                let writer_for_pipeline = writer.clone();
                let provider_for_pipeline = Arc::clone(&provider);
                let segment_path_for_pipeline = segment_path.clone();
                let channel_str_for_pipeline = channel_str.to_string();
                let sender_id_for_pipeline = inbound.sender_id.clone();
                let views_conn_for_pipeline = views_conn.clone();
                tokio::task::block_in_place(|| {
                    let handle = tokio::runtime::Handle::current();
                    handle.block_on(async move {
                        // Pick #38 (Session 14, Perf #11 fix): prefer the
                        // shared `views.db` connection from startup; fall
                        // back to per-call open if startup couldn't open
                        // it (so the channel path stays functional).
                        // `ConnBorrow` keeps both variants matchable
                        // through one local `as_mut()` interface so the
                        // rest of the inner async block stays unchanged.
                        enum ConnBorrow<'a> {
                            Shared(tokio::sync::MutexGuard<'a, rusqlite::Connection>),
                            Owned(rusqlite::Connection),
                        }
                        impl<'a> ConnBorrow<'a> {
                            fn as_mut(&mut self) -> &mut rusqlite::Connection {
                                match self {
                                    ConnBorrow::Shared(g) => g,
                                    ConnBorrow::Owned(c) => c,
                                }
                            }
                        }
                        let mut conn_holder = if let Some(shared) = &views_conn_for_pipeline {
                            ConnBorrow::Shared(shared.lock().await)
                        } else {
                            match crate::memory::store::open(&views_path) {
                                Ok(c) => ConnBorrow::Owned(c),
                                Err(e) => {
                                    tracing::warn!(
                                        error = %e,
                                        path = %views_path.display(),
                                        "open views.db failed for channel profile pipeline (non-fatal)"
                                    );
                                    return;
                                }
                            }
                        };
                        let conn = conn_holder.as_mut();
                        let pipeline_fut = async {
                            if let Err(e) = crate::memory::indexer::replay_once(
                                conn,
                                &segment_path_for_pipeline,
                            )
                            .await
                            {
                                tracing::warn!(
                                    error = %e,
                                    "indexer replay_once failed before channel profile pipeline"
                                );
                                return;
                            }
                            let guard =
                                crate::profile::claim_guard::ProfileClaimGuard::default();
                            let extensions =
                                crate::profile::extension_registry::TypedExtensionRegistry::load()
                                    .unwrap_or_default();
                            let now_unix = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            match crate::profile::run_pipeline(
                                conn,
                                &writer_for_pipeline,
                                &*provider_for_pipeline,
                                ingress_event_id,
                                2,
                                &guard,
                                &extensions,
                                now_unix,
                                // ADV-03 Phase 5 (Session 24): None
                                // preserves pre-gate behaviour for the
                                // serve-mode channel ingress pipeline.
                                // Phase 6+ wires the daemon-mode gate
                                // context (autonomy + is_tty=false +
                                // queue-pending closure) once the CLI
                                // `neoth profile pending` surface is
                                // shipped.
                                None,
                            )
                            .await
                            {
                                Ok(crate::profile::PipelineRun::Applied {
                                    outcome, ..
                                }) => {
                                    tracing::info!(
                                        channel = %channel_str_for_pipeline,
                                        sender = %sender_id_for_pipeline,
                                        claims_applied = outcome.claims_applied,
                                        claims_reinforced = outcome.claims_reinforced,
                                        claims_superseded = outcome.claims_superseded,
                                        idempotent_skip = outcome.idempotent_skip,
                                        "channel profile pipeline applied post-reply"
                                    );
                                }
                                Ok(crate::profile::PipelineRun::Skipped(reason)) => {
                                    tracing::debug!(
                                        channel = %channel_str_for_pipeline,
                                        reason = %reason,
                                        "channel profile pipeline skipped post-reply"
                                    );
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        error = %e,
                                        "channel profile pipeline failed post-reply (non-fatal)"
                                    );
                                }
                            }
                        };
                        match tokio::time::timeout(timeout, pipeline_fut).await {
                            Ok(()) => {}
                            Err(_elapsed) => {
                                tracing::warn!(
                                    channel = %channel_str_for_pipeline,
                                    timeout_secs = timeout.as_secs(),
                                    "channel profile pipeline timed out post-reply; learning abandoned"
                                );
                            }
                        }
                    });
                });
            }

            // ── PreEgress hooks (Phase 29 R-15) ───────────────────────────
            // Last filter before the channel adapter sends the reply. A
            // Replace rewrites the outbound text (per-messenger formatting
            // rules, link unfurling, profanity scrub); a Block silently
            // drops the reply with a HOOK_BLOCKED audit frame.
            let reply_text = match crate::hooks::run_stage(
                crate::hooks::HookStage::PreEgress,
                &completion.text,
                &hooks,
            ) {
                Ok(crate::hooks::StageOutcome::Continue { body, hits }) => {
                    for name in &hits {
                        if let Ok(payload) = serde_json::to_vec(&serde_json::json!({
                            "name": name,
                            "stage": "pre_egress",
                            "channel": channel_str,
                            "recipient_id": inbound.sender_id,
                            "ts_unix": std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0),
                        })) {
                            let header = crate::wal::HeaderBuilder::new(
                                crate::wal::events::EVENT_TYPE_HOOK_FIRED,
                                &payload,
                            )
                            .build();
                            if let Err(e) = writer.append(header, payload).await {
                                warn!(error = %e, "WAL append PreEgress hook frame failed");
                            }
                        }
                    }
                    body
                }
                Ok(crate::hooks::StageOutcome::Block { name, reason }) => {
                    info!(
                        channel = channel_str,
                        recipient = %inbound.sender_id,
                        hook = %name,
                        reason = %reason,
                        "outbound dropped by pre_egress hook"
                    );
                    if let Ok(payload) = serde_json::to_vec(&serde_json::json!({
                        "name": name,
                        "stage": "pre_egress",
                        "channel": channel_str,
                        "recipient_id": inbound.sender_id,
                        "reason": reason,
                        "ts_unix": std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0),
                    })) {
                        let header = crate::wal::HeaderBuilder::new(
                            crate::wal::events::EVENT_TYPE_HOOK_BLOCKED,
                            &payload,
                        )
                        .build();
                        if let Err(e) = writer.append(header, payload).await {
                            warn!(error = %e, "WAL append PreEgress block frame failed");
                        }
                    }
                    return Ok(::std::option::Option::None);
                }
                Err(e) => {
                    warn!(error = %e, "PreEgress hook dispatch failed");
                    completion.text.clone()
                }
            };

            // ── Permission gate: ChannelSend (Pick #10, Session 14) ─────
            // Codex feedback 2026-05-18: before the channel adapter
            // ships the reply outbound, gate it through the autonomy
            // ladder. Mirrors what `chat.rs` does for the CLI surface
            // (no gate needed there — TTY local print, not network
            // egress). Strict level: denies + emits WAL audit frame.
            {
                use crate::permissions::{Action, ConfirmStrategy, Gate};
                let action = Action::ChannelSend;
                let gate = Gate::for_level(autonomy).with_confirm(ConfirmStrategy::FailClosed);
                if let Err(e) = gate.check(&action, Some(&writer)).await {
                    warn!(
                        channel = channel_str,
                        error = %e,
                        "channel outbound blocked by autonomy gate (ChannelSend)"
                    );
                    return Ok(::std::option::Option::None);
                }
            }

            Ok(Some(OutboundMessage {
                recipient_id: inbound.sender_id,
                text: reply_text,
            }))
        })
    })
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
                let header = crate::wal::HeaderBuilder::new(
                    crate::wal::events::EVENT_TYPE_CONFIG_RELOADED,
                    &bytes,
                )
                .build();
                if let Err(e) = writer.append(header, bytes).await {
                    warn!(error = %e, "CONFIG_RELOADED WAL append failed (best-effort audit)");
                }
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

/// Run an inbound media attachment through the multimodal extraction
/// pipeline and synthesise the text payload the rest of the inbound
/// flow expects. Behaviour by `MediaKind`:
///
/// - `Image`: extract via vision backend, persist 512-dim CLIP embedding
///   into `idx_embedding`, return a short operator-facing acknowledgement.
/// - `Audio`: extract via audio backend (decode → whisper transcript when
///   the model is cached), return the transcript text. Caption (if any)
///   prepends.
/// - `Video`: extract via video backend (audio track → whisper), return
///   the transcript.
/// - `Document` / `Sticker`: bail with a "kind not supported" string.
///
/// Errors propagate to the caller, which logs + surfaces a generic
/// "media pipeline error" reply to the operator.
pub(crate) async fn handle_media_attachment(
    inbound: &InboundMessage,
    media: &crate::channels::MediaPayload,
    writer: Option<&WalWriterHandle>,
) -> Result<String> {
    use crate::channels::MediaKind;
    use crate::media::{Asset, AssetKind, route_to_first_match};
    use crate::memory::embeddings;
    use crate::providers::clip_engine;
    use crate::wal::events::{EVENT_TYPE_EMBED_PERSISTED, EVENT_TYPE_INGEST_EXTRACTED};
    use std::sync::Arc;

    // Explicit exhaustive match — adding a new MediaKind variant
    // becomes a compile error here instead of silently routing into
    // the wrong extractor (the previous nested match would have hit
    // an `_ => AssetKind::Audio` fallback).
    let asset_kind = match media.kind {
        MediaKind::Image => AssetKind::Image,
        MediaKind::Audio => AssetKind::Audio,
        MediaKind::Video => AssetKind::Video,
        MediaKind::Document => {
            return Ok(format!(
                "[NEOTH] document attachments not supported in v0.1.x \
                 (filename={:?}, mime={})",
                media.filename, media.mime
            ));
        }
        MediaKind::Sticker => {
            return Ok("[NEOTH] sticker received; v0.1.x ignores sticker payloads.".into());
        }
    };

    let asset = Asset::Bytes {
        kind: asset_kind,
        mime: media.mime.clone(),
        data: media.data.clone(),
    };
    let backends: Vec<Arc<dyn crate::media::MediaExtractor>> = vec![
        Arc::new(crate::media::pdf::PdfExtractor),
        Arc::new(crate::media::vision::VisionExtractor),
        Arc::new(crate::media::audio::AudioExtractor),
        Arc::new(crate::media::video::VideoExtractor),
    ];
    let extraction = route_to_first_match(&backends, &asset)
        .await
        .map_err(|e| anyhow::anyhow!("extractor: {e}"))?;

    // Persist embedding (image today; future audio/video variants).
    let source_kind = match asset_kind {
        AssetKind::Image => "image",
        AssetKind::Audio => "audio_segment",
        AssetKind::Video => "video_frame",
        AssetKind::Pdf => "pdf_page",
        AssetKind::Other => "asset",
    };
    let source_ref = format!(
        "{}:{}:{}:{}",
        inbound.channel.as_str(),
        inbound.chat_id,
        inbound.sender_id,
        inbound.channel_ts_unix,
    );

    // Always emit INGEST_EXTRACTED — mirrors `neoth ingest`'s audit
    // shape so a `neoth wal show` operator sees the same frames for
    // CLI-side and channel-side ingestion.
    let model_name = extraction.metadata["extractor"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    if let Some(w) = writer {
        match serde_json::to_vec(&serde_json::json!({
            "source_ref": source_ref,
            "asset_kind": format!("{asset_kind:?}").to_lowercase(),
            "text_bytes": extraction.text.len(),
            "model": model_name,
            "channel": inbound.channel.as_str(),
            "ts_unix": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        })) {
            Ok(payload) => {
                let header =
                    crate::wal::HeaderBuilder::new(EVENT_TYPE_INGEST_EXTRACTED, &payload).build();
                if let Err(e) = w.append(header, payload).await {
                    tracing::warn!(error = %e, "WAL append INGEST_EXTRACTED failed (best-effort)");
                }
            }
            Err(e) => tracing::warn!(
                error = %e,
                "INGEST_EXTRACTED audit payload serialisation failed; frame skipped"
            ),
        }
    }

    let mut embed_msg = String::new();
    if let Some(arr) = extraction.metadata["embedding"].as_array() {
        let embedding: Vec<f32> = arr
            .iter()
            .filter_map(|v| v.as_f64().map(|f| f as f32))
            .collect();
        if !embedding.is_empty() {
            let db_path = store::default_path();
            let conn = store::open(&db_path).context("open views.db")?;
            let model = clip_engine::DEFAULT_CLIP_REPO.to_string();
            let dim = embedding.len();
            embeddings::upsert(&conn, source_kind, &source_ref, &model, &embedding)
                .context("persist channel-side embedding")?;
            embed_msg = " 512-dim CLIP embedding cached.".to_string();
            if let Some(w) = writer {
                match serde_json::to_vec(&serde_json::json!({
                    "source_kind": source_kind,
                    "source_ref": source_ref,
                    "model": model,
                    "dim": dim,
                    "channel": inbound.channel.as_str(),
                    "ts_unix": SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                })) {
                    Ok(payload) => {
                        let header =
                            crate::wal::HeaderBuilder::new(EVENT_TYPE_EMBED_PERSISTED, &payload)
                                .build();
                        if let Err(e) = w.append(header, payload).await {
                            tracing::warn!(
                                error = %e,
                                "WAL append EMBED_PERSISTED failed (best-effort)"
                            );
                        }
                    }
                    Err(e) => tracing::warn!(
                        error = %e,
                        "EMBED_PERSISTED audit payload serialisation failed; frame skipped"
                    ),
                }
            }
        }
    }

    // Synthesise the text payload to hand to the LLM pipeline.
    let synthesised = match asset_kind {
        AssetKind::Image => {
            let caption = inbound.text.clone().unwrap_or_default();
            if caption.trim().is_empty() {
                format!(
                    "[NEOTH] Image received ({}×{} px).{}",
                    extraction.metadata["width"].as_u64().unwrap_or(0),
                    extraction.metadata["height"].as_u64().unwrap_or(0),
                    embed_msg,
                )
            } else {
                format!(
                    "{caption}\n\n[NEOTH] Image attached ({}×{} px).{}",
                    extraction.metadata["width"].as_u64().unwrap_or(0),
                    extraction.metadata["height"].as_u64().unwrap_or(0),
                    embed_msg,
                )
            }
        }
        AssetKind::Audio | AssetKind::Video => {
            let transcript = extraction.text.trim();
            if transcript.is_empty() {
                format!(
                    "[NEOTH] {} received but transcription returned empty text. \
                     Whisper model cached? Run `neoth models pull whisper`.",
                    if matches!(asset_kind, AssetKind::Audio) {
                        "Voice note"
                    } else {
                        "Video"
                    }
                )
            } else {
                let prefix = inbound.text.clone().unwrap_or_default();
                if prefix.trim().is_empty() {
                    transcript.to_string()
                } else {
                    format!("{prefix}\n\n[transcript]\n{transcript}")
                }
            }
        }
        AssetKind::Pdf | AssetKind::Other => extraction.text,
    };
    Ok(synthesised)
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
fn bootstrap_plugin_invoker(home: &std::path::Path) {
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
    let activations: std::collections::BTreeMap<
        String,
        crate::wasm_plugin::discovery::PluginActivation,
    > = match FreedomConfig::load_from_default_path() {
        Ok(cfg) => cfg.plugins.wasm.activations.clone(),
        Err(e) => {
            warn!(
                error = %e,
                "freedom.yaml load failed during plugin activation gate; \
                 treating ALL discovered plugins as Pending (none auto-instantiate)"
            );
            std::collections::BTreeMap::new()
        }
    };
    // home is reserved for future per-home credential lookup; suppress
    // unused-var on the v0.1 path that goes through the default-path
    // loader.
    let _ = home;

    let pre_filter = report.loaded.len();
    let mut skipped_pending: Vec<String> = Vec::new();
    let mut skipped_disabled: Vec<String> = Vec::new();
    report.loaded.retain(|p| {
        let state = activations.get(&p.manifest.id).copied().unwrap_or_default();
        match state {
            crate::wasm_plugin::discovery::PluginActivation::Active => true,
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
    let invoker = crate::wasm_plugin::dispatch::CompiledPluginInvoker::from_compile_outcomes(
        engine, &outcomes, linker,
    );
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
    use crate::wal::frame::decode_frame;
    use std::io::Write;
    use tempfile::tempdir;
    use tokio::fs::read;

    #[tokio::test]
    async fn serve_one_shot_writes_boot_frame() {
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
}
