//! `neoth serve` â€” daemon entry. Reads freedom.yaml, opens WAL, awaits shutdown.
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

// â”€â”€ ZF-07 Boot-Stagger constants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
//
// At daemon boot the full cron fleet (â‰¤ 28 tasks) whose schedules are
// already-due fire their first tick simultaneously â€” thundering herd on
// CPU, IO, and the provider API rate-limit.  A shared `Semaphore` with
// `START_STAGGER_PERMITS` permits bounds cold-start concurrency: each cron
// seed acquires one permit before spawning; the permit is released after
// `CRON_FIRST_TICK_WINDOW`, letting the next batch start.  Steady-state
// ticks (all subsequent interval firings) run completely unthrottled.

/// Maximum concurrent cron cold-starts during daemon boot (ZF-07 ceiling).
///
/// With 28 fleet crons at 4 permits the burst is â‰¤ 4-wide; the full fleet
/// seeds in â‰ˆ 28/4 Ã— 500 ms â‰ˆ 3.5 s instead of an instantaneous spike.
const START_STAGGER_PERMITS: usize = 4;

/// How long a boot-stagger permit is held after a cron is spawned.
///
/// Conservative upper bound on a typical first-tick wall-time including any
/// cold-path provider latency.  Releasing too early would let a slow first
/// tick overlap with the next batch; releasing too late would delay seeding
/// unnecessarily.  500 ms covers the common cases without notable boot delay.
const CRON_FIRST_TICK_WINDOW: std::time::Duration = std::time::Duration::from_millis(500);

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

    /// Override the WAL segment path. Defaults to ~/.neoth/wal/000001.wal.
    #[arg(long, value_name = "PATH")]
    pub wal_segment: Option<PathBuf>,

    /// Emit one BOOT frame, drain, exit. Used by integration tests; equivalent
    /// to a graceful shutdown immediately after the first frame is durable.
    #[arg(long, hide = true)]
    pub one_shot: bool,

    /// Override the clock-rollback guard. Use only when restoring from a
    /// backup or recovering from a VM snapshot rewind â€” operator promises
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

    // â”€â”€ 0/0a/0b. Pre-config startup guards (GOLD-ARCH-01: relocated to
    // serve_tasks). Home-dir isolation (BS-9) + clock-rollback guard (BS-5) +
    // single-instance PID lock (BS-12). `--one-shot` skips isolation + PID.
    // The PidGuard is bound HERE (named `_pid_guard`, not bare `_`) for the
    // daemon lifetime â€” its Drop releases the lock at run_serve fn-end.
    let _pid_guard = crate::cli::serve_tasks::run_preflight_guards(
        &neoth_home,
        args.one_shot,
        args.allow_clock_rollback,
    )?;

    // Recover a crash-interrupted self-improvement accept/rollback while the
    // instance lock is held and before any daemon consumer can read proposals,
    // the ledger, or a partially-written skill. Corrupt/ambiguous state blocks
    // startup for operator repair instead of racing a second daemon process.
    if !args.one_shot {
        crate::self_improve::recover_pending_journal(&neoth_home).with_context(|| {
            format!(
                "recover self-improvement journal under {} before daemon startup",
                neoth_home.display()
            )
        })?;
    }

    // â”€â”€ 1. Load config â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    let config = FreedomConfig::load_from_path(&config_path)?;
    let credentials_path = neoth_home.join("credentials.yaml");
    // Load the complete secret contract before any runtime service is primed.
    // This keeps custom --config homes and the OS-keychain backend aligned with
    // the exact credentials later passed to channel and OMI workers.
    let creds = crate::config::credentials::Credentials::load_effective(
        &credentials_path,
        config.secrets_backend,
    )
    .with_context(|| {
        format!(
            "credentials at {} cannot be loaded; repair the file/keychain before starting",
            credentials_path.display()
        )
    })?;
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

    // GOLD-ADAPT-OH-03: onboarding completion gate â€” bail before touching the WAL
    // if no channel/integration has been configured. Bypassed for --one-shot
    // (integration-test path that runs against ephemeral configs with no channels).
    // The secondary credential probe inside check_onboarding_complete handles old
    // freedom.yaml files that pre-date the `onboarding_complete` flag.
    if !args.one_shot {
        crate::cli::serve_tasks::check_onboarding_complete(&config, &creds)?;
    }

    // â”€â”€ 2/2b/3/3b/BS-4. WAL setup (GOLD-ARCH-01: relocated to
    // serve_tasks::prepare_wal â€” dir prep + ADV-01 .cpt recovery scan + writer
    // spawn + deferred quarantine-audit frames + BS-4 quota guard). `writer_join`
    // is rebound `mut` because the idle-wait `select!` borrows `&mut writer_join`.
    let crate::cli::serve_tasks::WalSetup {
        wal_dir,
        segment_path,
        writer,
        mut writer_join,
    } = crate::cli::serve_tasks::prepare_wal(&neoth_home, args.wal_segment.clone())?;

    // â”€â”€ 3b'. Hot-reload controller (construction only) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Built HERE (before the plugin bootstrap) so the compiled plugin
    // invoker can hold a live-config handle for its per-invoke
    // revocation check. Construction is side-effect-free; the at-boot
    // sentinel one-shot + the polling task stay in step 5b below.
    let reload_controller = std::sync::Arc::new(crate::config::reload::ReloadController::new(
        config.clone(),
        config_path.clone(),
    ));

    // â”€â”€ 3c. Plugin invoker bootstrap (SC-04) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Deferred from step 1a so the invoker carries a clone of the live
    // WAL writer: a denied plugin hostcall must emit its 0xC7
    // PLUGIN_CAP_DENIED audit frame, and a used capability its 0xC4/0xC6
    // frame, into the SAME segment the daemon writes. Reusing the writer
    // handle (not spawning a second one) keeps the single-writer
    // invariant that the WAL segment depends on.
    #[cfg(feature = "wasm-plugin-host")]
    {
        if config.plugins.wasm.enabled {
            crate::cli::serve_tasks::bootstrap_plugin_invoker(
                &neoth_home,
                writer.clone(),
                reload_controller.clone(),
            );
        } else {
            info!(
                "freedom.yaml::plugins.wasm.enabled = false; skipping plugin discovery + invoker bootstrap"
            );
        }
    }

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

    // Runtime-service priming follows the validated startup-hook boundary.
    // The SkillRegistry watcher handle remains bound for the daemon lifetime.
    let _skill_watcher =
        crate::cli::serve_tasks::prime_runtime_services(&config, &creds, &neoth_home).await?;

    // E-2 Phase 4 (Session 14 Pick #23) â€” log a depth-cost warning at
    // boot when the operator's freedom.yaml has
    // `hemisphere_council_depth > 1`. Catches the operator who hand-
    // edited the config without going through the wizard's cost-warning
    // screen. Best-effort: pure stderr â€” never blocks the daemon.
    let council_depth = config.inference.hemisphere_council_depth.get();
    if council_depth > 1 {
        warn!(
            council_depth = council_depth,
            "{}",
            crate::cli::init::render_council_depth_cost_warning(council_depth),
        );
    }

    // â”€â”€ 4. Emit BOOT event â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
    // disk (one small write) â€” captures the "last alive moment" so the
    // next start can detect a rollback even if we crash mid-run.
    let now_ns = crate::time::now_unix_ns();
    // The floor is security-bearing persistent state: a daemon that cannot
    // update it must not continue writing an audit chain whose next startup
    // cannot detect rollback. The selected config's parent is authoritative.
    let clock_floor_path = neoth_home.join("clock.floor");
    crate::daemon::clock_floor::persist_floor(&clock_floor_path, now_ns).with_context(|| {
        format!(
            "persist instance clock floor at {}",
           ßo6ÒÚ$z{-®éÜj×6·2‚fæV÷F…ö†öÖRÂ&rÂw&—FW"Âw&—FW%ö¦ö–â’æv—C°¢ö²‚‚’§Ð ¢òòòtôÄBÔ4õ"ÓBòÓ¢VæB4T5U$•E’Ô$T$”ärVF—Bg&ÖP¢òòò„4„ääTÅõ$•d”ÄTtUô$Äô4´TBÂ„ôôµô$Äô4´TBÂ”ätU5EôU…E$5DTBÀ¢òòòTÔ$TEõU%4•5DTBÂ4ôäd”uõ$TÄôDTB’âVæÆ–¶RÆ–â&W7BÖVff÷'@¢òòòw&—FW"æVæFÂw&—FRf–ÇW&R†W&R—2äõB7vÆÆ÷vVBBv&æÆWfVÃ¢—@¢òòò—2ÆövvVBBW'&÷"v—F‚Væ–f÷&ÒÂw&W&ÆRVF—EöÆ÷72ÒG'VV²F†P¢òòòg&ÖRw2WfVçFæÖRÂ6òæV÷F‚Ööæ—F÷&w2'VÆRVæv–æR6âÆW'BöâÆ÷7@¢òòò6V7W&—G’&V6÷&B–ç7FVBöb—Bfæ—6†–ær–çFòF†RÆöræö—6Rà¢òòð¢òòòF†—2—2FVÆ–&W&FVÇ’äõB†&Bf–ÂÖ6Æ÷6VB†÷W&F÷"FV6—6–öâ##bÓbÓbÀ¢òòòtôÄBÔ4õ"ÓB“¢BWfW'’öæRöbF†W6R6ÆÂ6—FW2F†RwV&FVB7F–öâ(	BF†P¢òòò&Æö6²ò&V¦V7BòG&÷Â÷"F†RVÖ&VFF–ærW'6—7Bò6öæf–r&VÆöB(	B†0¢òòòÅ$TE’6ö×ÆWFVB'’F†RF–ÖRF†Rg&ÖR—2w&—GFVâÂ6ò&÷'F–ærF†P¢òòò÷W&F–öâ6÷VÆBæ÷BVæFò—C²—Bv÷VÆBöæÇ’ÆVfR–æ6ö†W&VçB÷7B×6–FRÖVffV7@¢òòò7FFRâæB&V6W6RVæFf–Ç2öâgVÆÂtÂV÷FÂ&÷vF–ærF†RW'&÷ ¢òòòv÷VÆBGW&âF—6²Ö6–çFòFõ2×Æ–f–W"öâW†7FÇ’F†R6V7W&—G’×&VÆWfç@¢òòòF‡2âF†RGW&&ÆRf—‚—2æöâ×6–ÆVçBÂÖöæ—F÷&&ÆRVF—BÆ÷72(	Bæ÷BÆ÷VFW ¢òòòf–ÇW&RÖöFRf÷"F†R÷W&F–öâ—G6VÆbà¢òòð¢òòòtôÄBÔ$4‚Ó¢V"†7&FR–6òF†RW‡G&7FVB6W'fU÷—VÆ–æVÖöGVÆR6â&V6€¢òòòF†R6†&VB†VÇW#²—B7F—2†W&R&V6W6R†æFÆU÷&VÆöE÷6VçF–æVÆ†FVÖöà¢òòò6–FR’Ç6ò6ÆÇ2—Bà§V"†7&FR’7–æ2fâVÖ—E÷&WV—&VEöVF—B€¢w&—FW#¢evÅw&—FW$†æFÆRÀ¢WfVçE÷G—S¢S‚À¢WfVçEöæÖS¢bw7FF–27G"À¢–ÆöC¢fV3ÇSƒâÀ¢’°¢ÆWB†VFW"Ò7&FS£§vÃ£¦Ö¶Uö†VFW"†WfVçE÷G—RÂg–ÆöB“°¢–bÆWBW'"†R’Òw&—FW"æVæB††VFW"Â–ÆöB’æv—B°¢W'&÷"€¢VF—EöÆ÷72ÒG'VRÀ¢WfVçBÒWfVçEöæÖRÀ¢W'&÷"ÒVRÀ¢'6V7W&—G’VF—Bg&ÖRÆ÷7B(	BGW&&ÆRtÂ&V6÷&B6÷VÆBæ÷B&Rw&—GFVâ ¢“°¢Ð§Ð ¢òò'V–ÆE÷—VÆ–æUö†VFW"ò&ö÷Eö†VFW"Ö–w&FVBFòvÃ£¦Ö¶Uö†VFW"ð¢òòvÃ£¤†VFW$'V–ÆFW"(	B†6R36RÔ#2âÆö6ÂFVfVÇG2F†BG&–gFVBg&öÒF†P¢òòãR&6VÆ–æR†6†CÓãbÂ—VÆ–æSÓãb’&Ræ÷rVæ–f÷&ÒB'V–ÆFW"FVfVÇBà ¢òòòäTõD‚ÔTD•BÔ5$ôâÔdÄTUBÔÄ”dT5”4ÄRÓ¢6ö×WFR6öæf–r×7V2f–ævW'&–çBf÷ ¢òòòfÆVWB7&öâ¶W’à¢òòð¢òòò&WGW&ç2ScFF†B6†ævW2v†VæWfW"F†R6öæf–rf–VÆG2G&—f–ærF†B7&öâw0¢òòòVffV7F—fR&V†f–÷W"†–çFW'fÂÂF‡2ÂfÆw2’6†ævRÂÆÆ÷v–ærF†RfÆVW@¢òòò7WW'f—6÷"Fò&W7F'BF6²v†÷6R7V26†ævVBWfVâF†÷Vv‚—G27&öä¶W– ¢òòò—27F–ÆÂ–âF†RFW6—&VB6WBà¢òòð¢òòòW&S¢æò’ôòÂæòÆö6¶–ærÂæò6–FRVffV7G2â†6†W2öæÇ’F†R7V"×7G'V7BF†@¢òòòF†R6÷'&W7öæF–ær7våö7&öåöf÷%ö¶W–'&æ6‚&VG2Â6òâVç&VÆFVB6öæf–p¢òòò6†ævR†Rærâ&÷FF–ærF†RFVÆVw&ÒFö¶Vâ’FöW2äõBG&–vvW"7W&–÷W2&W7F'G0¢òòòöbVç&VÆFVB7&öç2à§V"†7&FR’fâ7&öå÷7V5öf–ævW'&–çB€¢¶W“¢7&FS£¦6Æ“£§6W'fU÷F6·3£¤7&öä¶W’À¢6fs¢f7&FS£¦6öæf–s£¤g&VVFöÔ6öæf–rÀ¢’ÓâScB°¢W6R7&FS£¦6Æ“£§6W'fU÷F6·3£¤7&öä¶W“£¢£°¢W6R7FC£¦6öÆÆV7F–öç3£¦†6…öÖ£¤FVfVÇD†6†W#°¢W6R7FC£¦†6ƒ£§´†6‚Â†6†W'Ó° ¢ÆWB×WB‚ÒFVfVÇD†6†W#£¦æWr‚“° ¢òòf÷"7V"×7G'V7G2F†BFW&—fR6W&–Æ—¦RvR†6‚F†V—"¥4ôâ&W&W6VçFF–öâà¢òòF†RÖ7&ò6–ÆVçFÇ’6¶—2F†R†6‚6öçG&–'WF–öâ–b6W&–Æ—6F–öâf–Ç0¢òò‡6†÷VÆBæWfW"†Vâ–â&7F–6R(	BÆÂ6öæf–w2FW&—fR6W&–Æ—¦R’à¢Ö7&õ÷'VÆW2¦‚°¢‚GfÃ¦W‡"’Óâ°¢–bÆWBö²‡2’Ò6W&FUö§6öã£§Fõ÷7G&–ær‚bGfÂ’°¢2æ†6‚‚f×WB‚“°¢Ð¢Ó°¢Ð ¢ÖF6‚¶W’°¢&tÖöæ—F÷"Óâ¦‚†6fræ&uöÖöæ—F÷"’À¢Fö7F÷$7&öâÓâ¦‚†6fræFö7F÷"’À¢&&VÂÓâ¦‚†6fræ&&VÂ’À¢vF6†Föt7&öâÓâ¦‚†6frçvF6†För’À¢G&–gDÆW'BÓâ¦‚†6fræG&–gEöÆW'B’À¢&V6ÆÄÆFVæ7’Óâ¦‚†6frç&V6ÆÅöÆFVæ7’’À¢&W6÷W&6UvF6‚Óâ¦‚†6frç&W6÷W&6U÷vF6‚’À¢Ööæ—F÷$7&öâÓâ¦‚†6fræÖöæ—F÷"’À¢Fö¶VäæöÖÇ’Óâ¦‚†6frçFö¶VåöæöÖÇ’’À¢6W76–öä†VÇF‚Óâ¦‚†6frç6W76–öåö†VÇF‚’À¢vV&†öö´ÖævW"Óâ¦‚†6frçvV&†ööµöÖævW"’À¢6¶–ÆÄ7W&F÷"Óâ¦‚†6frç6¶–ÆÅö7W&F÷"’À¢7–çF†W6—47&öâÓâ¦‚†6frç7–çF†W6—5ö7&öâ’À¢6öç6öÆ–FF–öå7vVWÓâ¦‚†6fræ6öç6öÆ–FF–öå÷7vVW’À¢6VÆev–¶’Óâ¦‚†6frç6VÆe÷v–¶’’À¢6VÆd–×&÷fVÖVçD6öÆÆV7F÷"Óâ¦‚†6frç6VÆeö–×&÷fVÖVçEö6öÆÆV7F÷"’À¢V6öÆöw”7&öâÓâ¦‚†6fræV6öÆöw’’À¢GFW&ä7&öâÓâ¦‚†6frçGFW&åö7&öâ’À¢6öçG&F–7F–öå&W6öÇfRÓâ¦‚†6fræ6öçG&F–7F–öå÷&W6öÇfR’À¢wV–Fæ6T7&öâÓâ¦‚†6fræwV–Fæ6Uö7&öâ’À¢&öf–ÆTFBÓâ¦‚†6frç&öf–ÆUöFB’À¢5¶6fr†fVGW&RÒ&6ÇW7FW""•Ð¢&W6÷W&6U6æ6†÷BÓâ6frç7v&Òæ–çFW'fÅ÷6V72æ†6‚‚f×WB‚’À¢òòö'6–F–â7&öç3¢&VÆWfçB6öæf–r—266GFW&VB7&÷72–æF—f–GVÀ¢òò&–Ö—F—fRf–VÆG2&F†W"F†â6–ævÆR7V"×7G'V7B(	B†6‚V6‚F—&V7FÇ’à¢ö'6–F–å7–æ2Óâ°¢6fræö'6–F–å÷fVÇBæ†6‚‚f×WB‚“°¢6fræö'6–F–åöWFõ÷7–æ5÷6V72æ†6‚‚f×WB‚“°¢6fræö'6–F–å÷7V&F—"æ†6‚‚f×WB‚“°¢Ð¢ö'6–F–åfVÇE&VFW"Óâ°¢6fræö'6–F–å÷fVÇBæ†6‚‚f×WB‚“°¢6fræö'6–F–å÷fVÇE÷&VFW%öVæ&ÆVBæ†6‚‚f×WB‚“°¢6fræö'6–F–å÷fVÇE÷&VFW%÷6V72æ†6‚‚f×WB‚“°¢Ð¢ö'6–F–åv–¶•&V'V–ÆBÓâ°¢6fræö'6–F–å÷fVÇBæ†6‚‚f×WB‚“°¢6fræö'6–F–å÷v–¶•÷&V'V–ÆE÷6V72æ†6‚‚f×WB‚“°¢6fræö'6–F–å÷v–¶•÷6÷W&6UöF—"æ†6‚‚f×WB‚“°¢Ð¢6VÆdÖÓâ°¢6frç6VÆeöÖ÷6÷W&6UöF—"æ†6‚‚f×WB‚“°¢6frç6VÆeöÖö–çFW'fÅ÷6V72æ†6‚‚f×WB‚“°¢6frç6VÆeöÖ÷7V&F—"æ†6‚‚f×WB‚“°¢6frç6VÆeöÖöÆ&VÅöVæ&ÆVBæ†6‚‚f×WB‚“°¢6frç6VÆeöÖöÆ&VÅöÖöFVÂæ†6‚‚f×WB‚“°¢Ð¢Ð ¢‚æf–æ—6‚‚§Ð ¢òòò–6²33r…6W76–öâBÂvVçB3BFW6–vâÖ6öç6Vç7W2“¢&ö6W72¢òòòâòææV÷F‚òç&VÆöB×&WVW7FVF6VçF–æVÂâ6ÆÇ2G'•÷&VÆöFöâF†P¢òòò7WÆ–VB&VÆöD6öçG&öÆÆW&ÂVÖ—G2öæRöbGvòtÂVF—Bg&ÖW0¢òòò†4ôäd”uõ$TÄôDTFò4ôäd”uõ$TÄôEõ$T¤T5DTF’ÂæBFVÆWFW2F†P¢òòò6VçF–æVÂ&Vv&FÆW72öb÷WF6öÖR(	B6òF†R÷W&F÷"w2æW‡@¢òòòæV÷F‚&VÆöF—2g&W6‚&WVW7BÂæ÷BGWÆ–6FRà¢òòð¢òòò&W7BÖVff÷'C¢WfW'’f–ÇW&RF‚‡&VBÂ'6RÂtÂVæBÀ¢òòò6VçF–æVÂFVÆWFR’Æöw2Bv&âÆWfVÂ²6öçF–çVW2âF†RFVÖöâw0¢òòò&V6V—fRÆö÷×W7B¶VW'Vææ–ærWfVâv†VâF†R&VÆöBÖV6†æ—6Ð¢òòò—G6VÆbÖ—6&V†fW2à§V"†7&FR’7–æ2fâ†æFÆU÷&VÆöE÷6VçF–æVÂ€¢6öçG&öÆÆW#¢f7&FS£¦6öæf–s£§&VÆöC£¥&VÆöD6öçG&öÆÆW"À¢6VçF–æVÅ÷Fƒ¢g7FC£§Fƒ£¥F‚À¢w&—FW#¢f7&FS£§vÃ£§w&—FW#£¥vÅw&—FW$†æFÆRÀ¢’°¢ÆWB&W7VÇBÒÖF6‚6öçG&öÆÆW"çG'•÷&VÆöB‚’°¢ö²‡"’Óâ"À¢W'"†R’Óâ°¢v&â€¢W'&÷"ÒVRÀ¢F‚ÒV6öçG&öÆÆW"ç6÷W&6U÷F‚‚’æF—7Æ’‚’À¢'&VÆöC¢&R×&VBg&VVFöÒç–ÖÂf–ÆVC²6VçF–æVÂv–ÆÂ&RFVÆWFVBFò&WfVçBÆö÷ ¢“°¢òò7F–ÆÂFVÆWFRF†R6VçF–æVÂ(	B÷F†W'v—6RF†RöÆÂF6°¢òò&R×G&–W2F†R6ÖR'&ö¶Vâf–ÆRWfW'’'2²7×2Æöw2à¢ÆWBòÒ7FC£¦g3£§&VÖ÷fUöf–ÆR‡6VçF–æVÅ÷F‚“°¢&WGW&ã°¢Ð¢Ó°¢ÆWBG5÷Væ—‚Ò7&FS£§F–ÖS£¦æ÷u÷Væ—…÷6V72‚“°¢ÖF6‚&W7VÇB°¢7&FS£¦6öæf–s£§&VÆöC£¥&VÆöE&W7VÇC£¥&VÆöFVB²6†ævVEöf–VÆG2ÒÓâ°¢–æfò€¢6†ævVBÒö6†ævVEöf–VÆG2À¢6÷W&6RÒV6öçG&öÆÆW"ç6÷W&6U÷F‚‚’æF—7Æ’‚’À¢&6öæf–r†÷B×&VÆöFVB ¢“°¢ÆWB–ÆöBÒ6W&FUö§6öã£¦§6öâ‡°¢&6†ævVEöf–VÆG2#¢6†ævVEöf–VÆG2À¢'6÷W&6U÷F‚#¢6öçG&öÆÆW"ç6÷W&6U÷F‚‚’æF—7Æ’‚’çFõ÷7G&–ær‚’À¢'G5÷Væ—‚#¢G5÷Væ—‚À¢Ò“°¢–bÆWBö²†'—FW2’Ò6W&FUö§6öã£§Fõ÷fV2‚g–ÆöB’°¢VÖ—E÷&WV—&VEöVF—B€¢w&—FW"À¢7&FS£§vÃ£¦WfVçG3£¤UdTåEõE•Uô4ôäd”uõ$TÄôDTBÀ¢$4ôäd”uõ$TÄôDTB"À¢'—FW2À¢¢æv—C°¢Ð¢òòtôÄBÔdTBÓv"(	BFVF–6FVBÖ÷&ÂÖ6÷&R¶–ÆÂ×7v—F6‚VF—BâF†RvVæW&–0¢òò4ôäd”uõ$TÄôDTB&÷fRÇ&VG’Æ—7G2&Ö÷&Åö6÷&R"–â6†ævVEöf–VÆG2Â'W@¢òòF†RÖ÷&Â6÷&R—2F†R6÷fW&V–vâ÷6—F–öâÓF—&V7F—fRÆ–W"Â6ò—G0¢òòVæ&ÆRöF—6&ÆRvWG2—G2÷vâw&W&ÆRtÂæ6†÷"6''––ærF†R&W7VÇF–æp¢òòöâööfb7FFR‡&VBg&öÒF†R§W7B×7vVBÆ—fR6öæf–r’à¢–b6†ævVEöf–VÆG2æ—FW"‚’æç’‡ÆgÂbÓÒ&Ö÷&Åö6÷&R"’°¢ÆWBVæ&ÆVBÒ6öçG&öÆÆW"æÆFW7B‚’æÖ÷&Åö6÷&RæVæ&ÆVC°¢ÆWBÖ5÷–ÆöBÒ6W&FUö§6öã£¦§6öâ‡²&Væ&ÆVB#¢Væ&ÆVBÂ'G5÷Væ—‚#¢G5÷Væ—‚Ò“°¢–bÆWBö²†'—FW2’Ò6W&FUö§6öã£§Fõ÷fV2‚fÖ5÷–ÆöB’°¢VÖ—E÷&WV—&VEöVF—B€¢w&—FW"À¢7&FS£§vÃ£¦WfVçG3£¤UdTåEõE•UôÔõ$Åô4õ$UõDôttÄTBÀ¢$Ôõ$Åô4õ$UõDôttÄTB"À¢'—FW2À¢¢æv—C°¢Ð¢Ð¢Ð¢7&FS£¦6öæf–s£§&VÆöC£¥&VÆöE&W7VÇC£¥&V¦V7FVB²&V6öâÒÓâ°¢v&â€¢&V6öâÒW&V6öâÀ¢6÷W&6RÒV6öçG&öÆÆW"ç6÷W&6U÷F‚‚’æF—7Æ’‚’À¢&6öæf–r&VÆöB$T¤T5DTB(	B–Ö×WF&ÆRf–VÆB6†ævVC²FVÖöâ7F—2öâ&–÷"6öæf–r ¢“°¢ÆWB–ÆöBÒ6W&FUö§6öã£¦§6öâ‡°¢'&V6öâ#¢&V6öâÀ¢'6÷W&6U÷F‚#¢6öçG&öÆÆW"ç6÷W&6U÷F‚‚’æF—7Æ’‚’çFõ÷7G&–ær‚’À¢'G5÷Væ—‚#¢G5÷Væ—‚À¢Ò“°¢–bÆWBö²†'—FW2’Ò6W&FUö§6öã£§Fõ÷fV2‚g–ÆöB’°¢ÆWB†VFW"Ò7&FS£§vÃ£¤†VFW$'V–ÆFW#£¦æWr€¢7&FS£§vÃ£¦WfVçG3£¤UdTåEõE•Uô4ôäd”uõ$TÄôEõ$T¤T5DTBÀ¢f'—FW2À¢¢æ'V–ÆB‚“°¢–bÆWBW'"†R’Òw&—FW"æVæB††VFW"Â'—FW2’æv—B°¢v&â†W'&÷"ÒVRÂ$4ôäd”uõ$TÄôEõ$T¤T5DTBtÂVæBf–ÆVB†&W7BÖVff÷'BVF—B’"“°¢Ð¢Ð¢Ð¢7&FS£¦6öæf–s£§&VÆöC£¥&VÆöE&W7VÇC£¥Væ6†ævVBÓâ°¢FV'Vr€¢6÷W&6RÒV6öçG&öÆÆW"ç6÷W&6U÷F‚‚’æF—7Æ’‚’À¢&6öæf–r&VÆöBG&–vvW&VB'WBf–ÆR6öçFVçBÖF6†W2Æ—fR6öæf–r(	BæòÖ÷ ¢“°¢òòæòtÂg&ÖRf÷"F†RæòÖ÷66Râ÷W&F÷"G&–vvW&VB¢òò&VÆöB'WBF–FâwB7GVÆÇ’VF—Bç—F†–æs²7ÖÖ–ærF†P¢òòVF—BÆörv÷VÆBF–ÇWFRF†R6–væÂà¢Ð¢Ð¢–bÆWBW'"†R’Ò7FC£¦g3£§&VÖ÷fUöf–ÆR‡6VçF–æVÅ÷F‚’°¢v&â€¢W'&÷"ÒVRÀ¢F‚ÒW6VçF–æVÅ÷F‚æF—7Æ’‚’À¢'&VÆöB6VçF–æVÂFVÆWFRf–ÆVC²æW‡BöÆÂF–6²Ö’F÷V&ÆRÖf—&R ¢“°¢Ð§Ð ¢òò)H)H&VÆöB66†VGVÆRVæ—BFW7G2)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H ¢5¶6fr‡FW7B•Ð¦ÖöBVÖ–Åö–ævW7E÷66†VGVÆU÷FW7G2°¢W6R7WW#£¦VÖ–Åö–ævW7E÷66†VGVÆUö6†ævS°¢W6R7&FS£¦6öæf–s£¤VÖ–Ä–ævW7D7&öä6öæf–s°¢W6R7FC£§F–ÖS£¤GW&F–öã° ¢5·FW7EÐ¢fâ&VÆöE÷&W6WG5÷F–6¶W%öf÷%ö6FVæ6Uö6†ævW5öæEöVæ&ÆUöVFvW2‚’°¢ÆWB×WBÆ—fRÒVÖ–Ä–ævW7D7&öä6öæf–s£¦FVfVÇB‚“°¢Æ—fRæ–çFW'fÅ÷6V72Òc°¢76W'EöW€¢VÖ–Åö–ævW7E÷66†VGVÆUö6†ævR†fÇ6RÂGW&F–öã£¦g&öÕ÷6V72ƒ3’ÂfÆ—fR’À¢6öÖR„GW&F–öã£¦g&öÕ÷6V72ƒc’’À¢&6†÷'FW"F—6&ÆVB6FVæ6R×W7B&R&VÖVÖ&W&VB&Vf÷&RVæ&ÆR ¢“° ¢Æ—fRæ–çFW'fÅ÷6V72Ò3°¢Æ—fRæVæ&ÆVBÒG'VS°¢76W'EöW€¢VÖ–Åö–ævW7E÷66†VGVÆUö6†ævR†fÇ6RÂGW&F–öã£¦g&öÕ÷6V72ƒ3’ÂfÆ—fR’À¢6öÖR„GW&F–öã£¦g&öÕ÷6V72ƒ3’’À¢&Væ&Æ–ær×W7B66†VGVÆRâ–ÖÖVF–FRf—'7BöÆÂ ¢“°¢76W'EöW€¢VÖ–Åö–ævW7E÷66†VGVÆUö6†ævR‡G'VRÂGW&F–öã£¦g&öÕ÷6V72ƒ3’ÂfÆ—fR’À¢æöæRÀ¢&âVæ6†ævVBÆ—fR66†VGVÆR×W7Bæ÷B6‡W&âF†RF–6¶W" ¢“°¢Ð§Ð ¢òò)H)H¤bÓr&ö÷B×7FvvW"Væ—BFW7G2)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H)H ¢5¶6fr‡FW7B•Ð¦ÖöB&ö÷E÷7FvvW%÷FW7G2°¢W6R7FC£§7–æ3£¤&3°¢W6R7FC£§7–æ3£¦FöÖ–3£§´FöÖ–5W6—¦RÂ÷&FW&–æwÓ° ¢W6R7WW#£§´5$ôåôd•%5EõD”4µõt”äDõrÂ5D%Eõ5DttU%õU$Ô•E7Ó° ¢òòò&÷fW2F†BF†R&ö÷B×7FvvW"6VÖ†÷&R&÷VæG26öæ7W'&VçB7&öâ6öÆB×7F'G0¢òòòFòBÖ÷7B5D%Eõ5DttU%õU$Ô•E6…¤bÓr6÷'&V7FæW72’à¢òòð¢òòò7vç25D%Eõ5DttU%õU$Ô•E2¢6F6·2‡F‡&VRgVÆÂ&F6†W2’âV6‚F6°¢òòòÖ—'&÷'2F†R6VVBÖÆö÷GFW&ã¢7V—&Râ÷væVBW&Ö—BÂ&V6÷&BV°¢òòò6öæ7W'&Væ7’ÂFò'&–Vb&f—'7B×F–6²"v÷&²ÂF†Vâ&VÆV6RâF†Rö'6W'fVBV°¢òòò×W7BæWfW"W†6VVBF†R6V–Æ–ærà¢5·Fö¶–ó£§FW7EÐ¢7–æ2fâ&ö÷E÷7FvvW%ö&÷VæG5ö6öæ7W'&VçEöf—'7E÷F–6·2‚’°¢ÆWB6VÒÒ&3£¦æWr‡Fö¶–ó£§7–æ3£¥6VÖ†÷&S£¦æWr…5D%Eõ5DttU%õU$Ô•E2’“°¢ÆWB7F—fRÒ&3£¦æWr„FöÖ–5W6—¦S£¦æWrƒ’“°¢ÆWBV²Ò&3£¦æWr„FöÖ–5W6—¦S£¦æWrƒ’“° ¢ÆWBå÷F6·2Ò5D%Eõ5DttU%õU$Ô•E2¢3°¢ÆWB×WB†æFÆW2ÒfV3£§v—F…ö66—G’†å÷F6·2“°¢f÷"ò–ââæå÷F6·2°¢ÆWB6VÒÒ&3£¦6ÆöæR‚g6VÒ“°¢ÆWB7F—fRÒ&3£¦6ÆöæR‚f7F—fR“°¢ÆWBV²Ò&3£¦6ÆöæR‚gV²“°¢†æFÆW2çW6‚‡Fö¶–ó£§7vâ†7–æ2Ö÷fR°¢òòÖ—'&÷"F†R6VVBÆö÷¢7V—&RöæRW&Ö—B&Vf÷&R&f—'7BF–6²"à¢ÆWB÷W&Ö—BÒ6VÒæ7V—&Uö÷væVB‚’æv—BæW‡V7B‚'6VÖ†÷&R6Æ÷6VB"“°¢ÆWB7W"Ò7F—fRæfWF6…öFBƒÂ÷&FW&–æs£¤7&VÂ’²°¢òòG&6²V²f–42Æö÷†fö–G26W&FR×WFW‚’à¢ÆWB×WBÒV²æÆöB„÷&FW&–æs£¤7V—&R“°¢v†–ÆRÂ7W"°¢ÖF6‚V²æ6ö×&UöW†6†ævU÷vV²‡Â7W"Â÷&FW&–æs£¤7&VÂÂ÷&FW&–æs£¤7V—&R’°¢ö²…ò’Óâ'&V²À¢W'"†7GVÂ’ÓâÒ7GVÂÀ¢Ð¢Ð¢òò6–×VÆFRf—'7B×F–6²v÷&²†×V6‚6†÷'FW"F†â5$ôåôd•%5EõD”4µõt”äDõp¢òò6òF†RFW7Bf–æ—6†W2V–6¶Ç’v†–ÆR7F–ÆÂ&÷f–ær6öæ7W'&Væ7’’à¢Fö¶–ó£§F–ÖS£§6ÆVW‡7FC£§F–ÖS£¤GW&F–öã£¦g&öÕöÖ–ÆÆ—2ƒR’’æv—C°¢7F—fRæfWF6…÷7V"ƒÂ÷&FW&–æs£¤7&VÂ“°¢òò÷W&Ö—BG&÷2†W&R(	B&VÆV6W2F†R6VÖ†÷&R6Æ÷Bà¢Ò’“°¢Ð¢f÷"‚–â†æFÆW2°¢‚æv—BæW‡V7B‚'F6²æ–6¶VB"“°¢Ð¢ÆWBö'6W'fVBÒV²æÆöB„÷&FW&–æs£¤7V—&R“°¢òòF†R6VÖ†÷&R6V–Æ–ær×W7B†öÆBà¢76W'B€¢ö'6W'fVBÃÒ5D%Eõ5DttU%õU$Ô•E2À¢'V²6öæ7W'&VçBf—'7B×F–6·2¶ö'6W'fVGÒ×W7Bæ÷BW†6VVBÀ¢5D%Eõ5DttU%õU$Ô•E3×µ5D%Eõ5DttU%õU$Ô•E7Ò"À¢“°¢Ð ¢òòò6æ—G“¢5$ôåôd•%5EõD”4µõt”äDõr—2æöâ×¦W&ò†¦W&òv–æF÷rv÷VÆB&VÆV6P¢òòòF†RW&Ö—B–ÖÖVF–FVÇ’ÂÖ¶–ærF†R7FvvW"æòÖ÷’à¢5·FW7EÐ¢fâ7&öåöf—'7E÷F–6µ÷v–æF÷uö—5÷÷6—F—fR‚’°¢76W'B€¢5$ôåôd•%5EõD”4µõt”äDõræ—5÷¦W&ò‚’À¢$5$ôåôd•%5EõD”4µõt”äDõr×W7B&Râ÷"F†R7FvvW"—2æòÖ÷"À¢“°¢Ð§Ð ¢5¶6fr‡FW7B•Ð¢5·F‚Ò'6W'fU÷FW7G2ç'2%Ð¦ÖöBFW7G3° 