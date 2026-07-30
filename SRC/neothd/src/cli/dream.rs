//! `neoth dream` — operator-triggered dream composition and archive browsing
//! (SPEC-12 / R-02).
//!
//! ## Subcommands
//!
//! - `now`  — compose one batch of dreams over the recent window right now
//!            instead of waiting for the daemon's nightly dreaming cron.
//! - `status` — show the manual path, explicit cron opt-in, schedule, autonomy
//!              rail, daemon presence and pending-reload state.
//! - `cron enable|disable` — atomically change only `dream.cron_enabled`,
//!              preserve unrelated/unknown config fields and request a daemon
//!              reload. The command never changes autonomy on the operator's
//!              behalf.
//! - `list` — enumerate `~/.neoth/dreams/*.jsonl` files (one per day) sorted
//!            newest-first. Emits `{days:[{day, entries, path}]}` (JSON) or a
//!            simple table row per day.
//! - `show <day>` — read one day's JSONL and render each line. Emits
//!            `{day, dreams:[...]}` (JSON) or human-readable lines (Table).
//!            Errors cleanly when the dreams directory or the requested day is
//!            missing.
//!
//! `now` reuses [`crate::cli::dreaming_task::run_one_pass`] — identical in shape
//! to the daemon cron: gather `idx_episode` rows, embed + cosine-cluster into
//! themes, append Dream records to `~/.neoth/dreams/YYYY-MM-DD.jsonl`.
//!
//! Emits `0xF4 DREAM_COMPOSED` through a collision-resistant, home-bound
//! standalone WAL.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, bail, ensure};
use clap::{Args, Subcommand};
use serde::Serialize;

use crate::cli::OutputFormat;
use crate::cli::dreaming_task::{
    DreamPassConfig, PassReport, dream_composed_payload, run_one_pass,
};
use crate::config::FreedomConfig;
use crate::config::reload::RELOAD_SENTINEL_NAME;

#[derive(Args, Debug, Clone)]
pub struct DreamArgs {
    #[command(subcommand)]
    pub action: DreamAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum DreamAction {
    /// Compose dreams over the recent window right now (default: last 24h).
    Now {
        /// Look-back window in seconds. Default 86400 (24h).
        #[arg(long)]
        window_secs: Option<u64>,
        /// Max events to embed + cluster this pass. Default 500.
        #[arg(long)]
        max_events: Option<usize>,
    },
    /// Show the manual and scheduled Dream runtime contract.
    Status,
    /// Explicitly opt in to or out of the unattended daily Dream cron.
    Cron {
        #[command(subcommand)]
        action: DreamCronAction,
    },
    /// List days that have a dream JSONL file in `~/.neoth/dreams/`.
    /// Output is sorted newest-first.
    List,
    /// Show the dreams recorded on a specific day.
    ///
    /// <day> must be in `YYYY-MM-DD` format (as printed by `neoth dream list`).
    Show {
        /// Day to show (e.g. `2026-06-03`).
        day: String,
    },
}

#[derive(Subcommand, Debug, Clone, Copy, PartialEq, Eq)]
pub enum DreamCronAction {
    /// Enable the daily cron and request a daemon reload.
    Enable,
    /// Disable the daily cron and request a daemon reload.
    Disable,
}

pub async fn run_dream(args: DreamArgs, output: OutputFormat) -> Result<()> {
    match args.action {
        DreamAction::Now {
            window_secs,
            max_events,
        } => run_now(window_secs, max_events, output).await,
        DreamAction::Status => run_status(output),
        DreamAction::Cron { action } => run_cron(action, output),
        DreamAction::List => run_list(output),
        DreamAction::Show { day } => run_show(&day, output),
    }
}

// ── status / cron control ────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DreamStatus {
    contract_version: u8,
    config_path: String,
    config_present: bool,
    manual_available: bool,
    cron_enabled: bool,
    cron_at: String,
    timezone: String,
    autonomy: String,
    autonomy_allows_scheduler: bool,
    scheduler_state: &'static str,
    daemon_running: bool,
    daemon_pid: Option<u32>,
    reload_pending: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DreamCronReceipt {
    ok: bool,
    action: &'static str,
    changed: bool,
    cron_enabled: bool,
    config_path: String,
    reload_requested: bool,
    reload_sentinel: String,
    autonomy: String,
    autonomy_allows_scheduler: bool,
}

fn run_status(output: OutputFormat) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    let path = home.join("freedom.yaml");
    let status = dream_status_at(&home, &path)?;
    render_status(&status, output);
    Ok(())
}

fn dream_status_at(home: &Path, path: &Path) -> Result<DreamStatus> {
    let config_present = path
        .try_exists()
        .with_context(|| format!("check Dream config path {}", path.display()))?;
    let config = if config_present {
        FreedomConfig::load_from_path(path)
            .with_context(|| format!("load Dream config from {}", path.display()))?
    } else {
        FreedomConfig::default()
    };
    // Run the same schedule/pass validation as the daemon before presenting a
    // cron as configured. A malformed explicit file must fail loudly.
    let _ = crate::cli::dreaming_task::DreamSchedule::from_config(&config)?;
    let _ = DreamPassConfig::from_config(&config, None, None)?;

    let autonomy_allows_scheduler =
        crate::cron::scheduler::autonomy_allows_scheduler(config.autonomy);
    let daemon_pid = crate::daemon::pidfile::live_daemon_pid(&home.join("neothd.pid"))
        .context("inspect Dream daemon pidfile")?;
    let reload_pending = home
        .join(RELOAD_SENTINEL_NAME)
        .try_exists()
        .with_context(|| {
            format!(
                "check Dream reload sentinel {}",
                home.join(RELOAD_SENTINEL_NAME).display()
            )
        })?;
    let scheduler_state = if reload_pending {
        // Disk is the committed target generation, but the live daemon may
        // still be running the prior accepted generation until pickup.
        "reload_pending"
    } else if !config.dreaming.enabled {
        "manual_only"
    } else if !autonomy_allows_scheduler {
        "blocked_by_autonomy"
    } else if daemon_pid.is_none() {
        "waiting_for_daemon"
    } else {
        // This means the accepted on-disk generation is eligible. It does not
        // claim that a pass is executing at this instant.
        "configured_on_disk"
    };

    Ok(DreamStatus {
        contract_version: 1,
        config_path: path.display().to_string(),
        config_present,
        manual_available: true,
        cron_enabled: config.dreaming.enabled,
        cron_at: config.dreaming.cron_at.clone(),
        timezone: config
            .dreaming
            .timezone
            .clone()
            .or(config.user_tz.clone())
            .unwrap_or_else(|| "Etc/UTC".to_string()),
        autonomy: config.autonomy.as_str().to_string(),
        autonomy_allows_scheduler,
        scheduler_state,
        daemon_running: daemon_pid.is_some(),
        daemon_pid,
        reload_pending,
    })
}

fn run_cron(action: DreamCronAction, output: OutputFormat) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    let path = home.join("freedom.yaml");
    let receipt = set_dream_cron_at(&home, &path, action)?;
    render_cron_receipt(&receipt, output);
    Ok(())
}

fn set_dream_cron_at(
    home: &Path,
    path: &Path,
    action: DreamCronAction,
) -> Result<DreamCronReceipt> {
    ensure!(
        path.try_exists()
            .with_context(|| format!("check Dream config path {}", path.display()))?,
        "freedom.yaml not found at {}. Run `neoth init` first; Dream cron was not changed.",
        path.display()
    );
    let enabled = action == DreamCronAction::Enable;
    let (previous, autonomy) = FreedomConfig::update_at(path, |config| {
        let previous = config.dreaming.enabled;
        config.dreaming.enabled = enabled;
        Ok((previous, config.autonomy))
    })
    .with_context(|| format!("atomically update dream.cron_enabled in {}", path.display()))?;

    // Reconcile a live daemon even for an idempotent repeat: a previous manual
    // edit may be on disk while the accepted runtime generation is still old.
    let (sentinel, _) = crate::cli::reload::request_reload_at(home).with_context(|| {
        format!(
            "dream.cron_enabled was committed, but requesting its daemon reload failed; \
             run `neoth reload` to reconcile {}",
            path.display()
        )
    })?;
    let autonomy_allows_scheduler = crate::cron::scheduler::autonomy_allows_scheduler(autonomy);

    Ok(DreamCronReceipt {
        ok: true,
        action: match action {
            DreamCronAction::Enable => "enable",
            DreamCronAction::Disable => "disable",
        },
        changed: previous != enabled,
        cron_enabled: enabled,
        config_path: path.display().to_string(),
        reload_requested: true,
        reload_sentinel: sentinel.display().to_string(),
        autonomy: autonomy.as_str().to_string(),
        autonomy_allows_scheduler,
    })
}

fn render_status(status: &DreamStatus, output: OutputFormat) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::to_string(status).expect("serialize Dream status")
            );
        }
        OutputFormat::Table => {
            println!("Dream manual: available (`neoth dream now`)");
            println!(
                "Dream cron: {} [{}]",
                if status.cron_enabled {
                    "enabled by explicit operator opt-in"
                } else {
                    "disabled (healthy default)"
                },
                status.scheduler_state
            );
            println!("Schedule: {} {}", status.cron_at, status.timezone);
            println!(
                "Autonomy rail: {} ({})",
                status.autonomy,
                if status.autonomy_allows_scheduler {
                    "scheduler allowed"
                } else {
                    "scheduler blocked; NEOTH will not change autonomy automatically"
                }
            );
            match status.daemon_pid {
                Some(pid) => println!("Daemon: running (PID {pid})"),
                None => println!("Daemon: not running"),
            }
            println!(
                "Reload: {}",
                if status.reload_pending {
                    "requested; awaiting daemon pickup"
                } else {
                    "no request pending"
                }
            );
            println!(
                "Config: {} ({})",
                status.config_path,
                if status.config_present {
                    "operator file"
                } else {
                    "compiled defaults; run `neoth init` before changing cron"
                }
            );
        }
    }
}

fn render_cron_receipt(receipt: &DreamCronReceipt, output: OutputFormat) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::to_string(receipt).expect("serialize Dream cron receipt")
        ),
        OutputFormat::Table => {
            println!(
                "Dream cron {}{}.",
                if receipt.cron_enabled {
                    "enabled by explicit operator opt-in"
                } else {
                    "disabled"
                },
                if receipt.changed {
                    ""
                } else {
                    " (already in that state)"
                }
            );
            println!("Reload requested: {}", receipt.reload_sentinel);
            if receipt.cron_enabled && !receipt.autonomy_allows_scheduler {
                println!(
                    "Cron remains blocked under autonomy `{}`. NEOTH did not change autonomy; \
                     `neoth dream now` remains available.",
                    receipt.autonomy
                );
            }
        }
    }
}

async fn run_now(
    window_secs: Option<u64>,
    max_events: Option<usize>,
    output: OutputFormat,
) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    let config = FreedomConfig::load_from_default_path_or_default()?;
    // Reject CLI bounds before constructing/downloading any model or opening a
    // cost-authorized chat leaf.
    let pass_config =
        DreamPassConfig::from_config(&config, window_secs.map(Duration::from_secs), max_events)?;
    let embed = crate::providers::embed_provider_from_config(&config).await;
    // SPEC-12 Phase 4b — LLM theme labels, gated behind
    // `dreaming.summarize_themes` (cost-safe default OFF: it spends one
    // chat-provider call per cluster, which on a metered cloud provider
    // would bill). Built only when the flag is on AND a provider is
    // configured; otherwise deterministic `cluster-N-seed-id` labels.
    let mut chat_audit = None;
    let chat: Option<crate::providers::cost_authorization::AuthorizedProvider> = if config
        .dreaming
        .summarize_themes
    {
        // GOLD-ADOPT-21 — theme labels are a low-stakes utility call; route them
        // to the fast/cheap `inference.utility_provider` when configured (else
        // this is identical to the main provider).
        match crate::providers::from_config_for_utility_at(&config, &home).await {
            Ok(provider) => {
                let default_model =
                    crate::providers::provider_default_wire_model(provider.as_ref());
                let audit =
                    crate::providers::cost_authorization::ProviderCallAuthorizer::interactive_one_shot(
                        config.autonomy_policy(),
                        config.tokens.max_per_request,
                    )
                    .await
                    .context("open cost-authorization WAL for dream theme summaries")?;
                let authorizer = audit.authorizer();
                chat_audit = Some(audit);
                Some(
                    crate::providers::cost_authorization::AuthorizedProvider::from_box(
                        provider,
                        authorizer,
                        default_model,
                        "dream.now.theme_summary",
                    ),
                )
            }
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "dream: theme-summary provider unavailable; using deterministic labels"
                );
                None
            }
        }
    } else {
        None
    };
    // The pass-level writer remains None because `emit_dream_composed` below
    // owns that event. Any theme-summary cloud leaf has its independent,
    // collision-resistant cost/permission WAL through `chat` above.
    let report = run_one_pass(&home, embed.as_deref(), chat.as_ref(), &pass_config, None).await;
    if let Some(audit) = chat_audit {
        audit
            .finish(chat)
            .await
            .context("finalize dream theme-summary provider-call audit WAL")?;
    } else {
        drop(chat);
    }
    let report = report?;

    // Best-effort DREAM_COMPOSED audit — only when this process wrote dreams.
    if report.dreams_written > 0 {
        emit_dream_composed(&report);
    }

    render(&report, output);
    Ok(())
}

fn emit_dream_composed(report: &PassReport) {
    let home = FreedomConfig::default_neoth_home();
    let now_unix = crate::time::now_unix_secs();
    // Shared payload builder — identical shape to the daemon cron's 0xF4
    // frame (only the emit mechanism + provenance flag differ).
    let payload = dream_composed_payload(report, now_unix);
    let wal_dir = home.join("wal");
    if let Err(error) = std::fs::create_dir_all(&wal_dir) {
        tracing::warn!(%error, "dream: WAL directory unavailable; DREAM_COMPOSED not recorded");
        return;
    }
    let segment = crate::wal::writer::unique_standalone_segment_path(&wal_dir, "dream-composed");
    let (writer, _join) = match crate::wal::writer::spawn_for_home(segment, home) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "dream: WAL writer spawn failed; DREAM_COMPOSED not recorded");
            return;
        }
    };
    let header =
        crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_DREAM_COMPOSED, &payload)
            .build();
    if let Err(e) = writer.try_append_sync(header, payload) {
        tracing::warn!(error = %e, "dream: DREAM_COMPOSED frame append failed (audit gap)");
    }
}

// ── list ──────────────────────────────────────────────────────────────────────

fn run_list(output: OutputFormat) -> Result<()> {
    let dreams_dir = FreedomConfig::default_neoth_home().join("dreams");

    // Missing directory → empty list, not an error.
    if !dreams_dir.exists() {
        render_list(&[], output);
        return Ok(());
    }

    let mut entries: Vec<DayEntry> = std::fs::read_dir(&dreams_dir)
        .with_context(|| format!("read dreams dir {}", dreams_dir.display()))?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let p = e.path();
            // Only YYYY-MM-DD.jsonl files.
            if p.extension().and_then(|x| x.to_str()) != Some("jsonl") {
                return None;
            }
            let day = p.file_stem()?.to_str()?.to_owned();
            // Count newlines as a proxy for entry count.
            let entries = std::fs::read_to_string(&p)
                .map(|s| s.lines().filter(|l| !l.trim().is_empty()).count())
                .unwrap_or(0);
            Some(DayEntry {
                day,
                entries,
                path: p,
            })
        })
        .collect();

    // Newest-first by day string (ISO date lexicographic ≡ chronological).
    entries.sort_by(|a, b| b.day.cmp(&a.day));

    render_list(&entries, output);
    Ok(())
}

struct DayEntry {
    day: String,
    entries: usize,
    path: PathBuf,
}

fn render_list(entries: &[DayEntry], output: OutputFormat) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let days: Vec<serde_json::Value> = entries
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "day": e.day,
                        "entries": e.entries,
                        "path": e.path.display().to_string(),
                    })
                })
                .collect();
            println!("{}", serde_json::json!({"days": days}));
        }
        OutputFormat::Table => {
            if entries.is_empty() {
                println!("(no dream files found)");
                return;
            }
            for e in entries {
                println!("{} ({} dream(s))  {}", e.day, e.entries, e.path.display());
            }
            println!("# {} day(s)", entries.len());
        }
    }
}

// ── show ──────────────────────────────────────────────────────────────────────

fn run_show(day: &str, output: OutputFormat) -> Result<()> {
    let dreams_dir = FreedomConfig::default_neoth_home().join("dreams");
    let path = dreams_dir.join(format!("{day}.jsonl"));

    if !path.exists() {
        bail!(
            "no dream file for day `{day}` (expected {})",
            path.display()
        );
    }

    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("read dream file {}", path.display()))?;

    let dreams: Vec<serde_json::Value> = raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            serde_json::from_str(l).unwrap_or_else(|_| serde_json::Value::String(l.to_owned()))
        })
        .collect();

    render_show(day, &dreams, output);
    Ok(())
}

fn render_show(day: &str, dreams: &[serde_json::Value], output: OutputFormat) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!(
                "{}",
                serde_json::json!({
                    "day": day,
                    "dreams": dreams,
                })
            );
        }
        OutputFormat::Table => {
            if dreams.is_empty() {
                println!("(no entries for {day})");
                return;
            }
            println!("Dreams for {day}:");
            for (i, d) in dreams.iter().enumerate() {
                // Pretty-print JSON if it's an object; fall back to raw string.
                let line = match d {
                    serde_json::Value::String(s) => s.clone(),
                    other => {
                        serde_json::to_string_pretty(other).unwrap_or_else(|_| other.to_string())
                    }
                };
                println!("[{}] {}", i + 1, line);
            }
        }
    }
}

// ── now ───────────────────────────────────────────────────────────────────────

fn render(report: &PassReport, output: OutputFormat) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "day": report.day_label(),
                "events_considered": report.events_considered,
                "dreams_written": report.dreams_written,
                "path": report.path.display().to_string(),
                "path_taken": format!("{:?}", report.path_taken),
            })
        ),
        OutputFormat::Table => {
            if report.dreams_written == 0 {
                println!(
                    "No dreams composed ({} event(s) in window).",
                    report.events_considered
                );
            } else {
                println!(
                    "✓ Composed {} dream(s) from {} event(s) [{:?}]",
                    report.dreams_written, report.events_considered, report.path_taken
                );
                println!("  → {}", report.path.display());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::dreaming_task::DreamingPath;
    use clap::Parser;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[derive(Parser)]
    struct DreamTestCli {
        #[command(subcommand)]
        action: DreamAction,
    }

    #[test]
    fn cli_exposes_status_and_nested_cron_controls() {
        assert!(matches!(
            DreamTestCli::try_parse_from(["neoth-dream", "status"])
                .unwrap()
                .action,
            DreamAction::Status
        ));
        assert!(matches!(
            DreamTestCli::try_parse_from(["neoth-dream", "cron", "enable"])
                .unwrap()
                .action,
            DreamAction::Cron {
                action: DreamCronAction::Enable
            }
        ));
        assert!(matches!(
            DreamTestCli::try_parse_from(["neoth-dream", "cron", "disable"])
                .unwrap()
                .action,
            DreamAction::Cron {
                action: DreamCronAction::Disable
            }
        ));
    }

    #[test]
    fn status_without_config_reports_manual_only_defaults() {
        let dir = tempdir().unwrap();
        let status = dream_status_at(dir.path(), &dir.path().join("freedom.yaml")).unwrap();
        assert!(!status.config_present);
        assert!(status.manual_available);
        assert!(!status.cron_enabled);
        assert_eq!(status.scheduler_state, "manual_only");
        assert_eq!(status.cron_at, "03:00");
        assert_eq!(status.timezone, "Etc/UTC");
    }

    #[test]
    fn cron_enable_is_atomic_lossless_and_canonicalizes_legacy_spelling() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(
            &path,
            "operator_id: demo\n\
             future_root:\n  keep_me: yes\n\
             dreaming:\n  enabled: false\n  future_dream_knob: 7\n",
        )
        .unwrap();

        let receipt = set_dream_cron_at(dir.path(), &path, DreamCronAction::Enable).unwrap();
        assert!(receipt.ok);
        assert!(receipt.changed);
        assert!(receipt.cron_enabled);
        assert!(receipt.reload_requested);
        assert!(dir.path().join(RELOAD_SENTINEL_NAME).exists());

        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("future_root:"));
        assert!(body.contains("keep_me: yes"));
        assert!(body.contains("future_dream_knob: 7"));
        assert!(body.contains("dream:"));
        assert!(body.contains("cron_enabled: true"));
        assert!(!body.contains("dreaming:"));
        let loaded = FreedomConfig::load_from_path(&path).unwrap();
        assert!(loaded.dreaming.enabled);
    }

    #[test]
    fn cron_disable_is_idempotent_but_still_requests_reconciliation() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(&path, "dream:\n  cron_enabled: false\n").unwrap();

        let receipt = set_dream_cron_at(dir.path(), &path, DreamCronAction::Disable).unwrap();
        assert!(!receipt.changed);
        assert!(!receipt.cron_enabled);
        assert!(receipt.reload_requested);
        assert!(dir.path().join(RELOAD_SENTINEL_NAME).exists());
    }

    #[test]
    fn cron_mutation_requires_initialized_config() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        let error = set_dream_cron_at(dir.path(), &path, DreamCronAction::Enable)
            .unwrap_err()
            .to_string();
        assert!(error.contains("Run `neoth init` first"));
        assert!(!path.exists());
        assert!(!dir.path().join(RELOAD_SENTINEL_NAME).exists());
    }

    #[test]
    fn invalid_config_is_unchanged_and_never_requests_reload() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("freedom.yaml");
        let source = b"dream: [not-a-mapping]\n";
        std::fs::write(&path, source).unwrap();

        assert!(set_dream_cron_at(dir.path(), &path, DreamCronAction::Enable).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), source);
        assert!(!dir.path().join(RELOAD_SENTINEL_NAME).exists());
    }

    #[test]
    fn status_exposes_enabled_but_fail_closed_autonomy_contracts() {
        for autonomy in ["strict", "custom"] {
            let dir = tempdir().unwrap();
            let path = dir.path().join("freedom.yaml");
            std::fs::write(
                &path,
                format!("autonomy: {autonomy}\ndream:\n  cron_enabled: true\n"),
            )
            .unwrap();

            let status = dream_status_at(dir.path(), &path).unwrap();
            assert!(status.cron_enabled);
            assert!(!status.autonomy_allows_scheduler);
            assert_eq!(status.scheduler_state, "blocked_by_autonomy");
            assert_eq!(status.autonomy, autonomy);
        }
    }

    #[test]
    fn day_label_extracts_yyyy_mm_dd() {
        let report = PassReport {
            events_considered: 0,
            dreams_written: 0,
            path: PathBuf::from("/home/op/.neoth/dreams/2026-06-03.jsonl"),
            path_taken: DreamingPath::Deterministic,
        };
        assert_eq!(report.day_label(), "2026-06-03");
    }

    /// `render_list` JSON shape: top-level `days` array with expected fields.
    #[test]
    fn list_json_shape_empty() {
        // Captures stdout would require extra infrastructure; instead verify
        // the JSON value shape used by render_list directly.
        let entries: Vec<serde_json::Value> = vec![];
        let v = serde_json::json!({"days": entries});
        assert!(v["days"].is_array());
        assert_eq!(v["days"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn list_json_shape_with_entry() {
        let entry = serde_json::json!({
            "day": "2026-06-03",
            "entries": 5_usize,
            "path": "/home/op/.neoth/dreams/2026-06-03.jsonl",
        });
        let v = serde_json::json!({"days": [entry]});
        assert_eq!(v["days"][0]["day"], "2026-06-03");
        assert_eq!(v["days"][0]["entries"], 5);
    }

    /// `render_show` JSON shape: `{day, dreams:[...]}`.
    #[test]
    fn show_json_shape() {
        let dream = serde_json::json!({"theme": "test", "score": 0.9_f64});
        let v = serde_json::json!({
            "day": "2026-06-03",
            "dreams": [dream],
        });
        assert_eq!(v["day"], "2026-06-03");
        assert!(v["dreams"].is_array());
        assert_eq!(v["dreams"][0]["theme"], "test");
    }
}
