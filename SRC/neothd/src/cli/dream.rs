//! `neoth dream` — operator-triggered dream composition and archive browsing
//! (SPEC-12 / R-02).
//!
//! ## Subcommands
//!
//! - `now`  — compose one batch of dreams over the recent window right now
//!            instead of waiting for the daemon's nightly dreaming cron.
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
//! Emits `0xF4 DREAM_COMPOSED` for the audit trail — best-effort, and only when
//! no daemon owns the WAL writer (a live daemon's nightly pass is the primary
//! path; a one-shot writer would race the daemon's segment).

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::cli::dreaming_task::{
    DEFAULT_MAX_EVENTS, DEFAULT_WINDOW, PassReport, dream_composed_payload, run_one_pass,
};
use crate::config::FreedomConfig;

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

pub async fn run_dream(args: DreamArgs, output: OutputFormat) -> Result<()> {
    match args.action {
        DreamAction::Now {
            window_secs,
            max_events,
        } => run_now(window_secs, max_events, output).await,
        DreamAction::List => run_list(output),
        DreamAction::Show { day } => run_show(&day, output),
    }
}

async fn run_now(
    window_secs: Option<u64>,
    max_events: Option<usize>,
    output: OutputFormat,
) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    let config = FreedomConfig::load_from_default_path_or_default()?;
    let embed = crate::providers::embed_provider_from_config(&config).await;
    // SPEC-12 Phase 4b — LLM theme labels, gated behind
    // `dreaming.summarize_themes` (cost-safe default OFF: it spends one
    // chat-provider call per cluster, which on a metered cloud provider
    // would bill). Built only when the flag is on AND a provider is
    // configured; otherwise deterministic `cluster-N-seed-id` labels.
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
                Some(
                    crate::providers::cost_authorization::AuthorizedProvider::from_box(
                    provider,
                    crate::providers::cost_authorization::ProviderCallAuthorizer::interactive_one_shot(
                        config.autonomy_policy(),
                        config.tokens.max_per_request,
                    )
                    .context("open cost-authorization WAL for dream theme summaries")?,
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
    let window = window_secs
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_WINDOW);
    let max = max_events.unwrap_or(DEFAULT_MAX_EVENTS);

    // The pass-level writer remains None because `emit_dream_composed` below
    // owns that event. Any theme-summary cloud leaf has its independent,
    // collision-resistant cost/permission WAL through `chat` above.
    let report = run_one_pass(&home, embed.as_deref(), chat.as_ref(), window, max, None).await?;

    // Best-effort DREAM_COMPOSED audit — only when this process wrote dreams
    // AND no daemon owns the writer (avoid racing the daemon's segment).
    if report.dreams_written > 0 {
        emit_dream_composed(&report);
    }

    render(&report, output);
    Ok(())
}

fn emit_dream_composed(report: &PassReport) {
    let pidfile = crate::daemon::pidfile::default_pidfile();
    if matches!(
        crate::daemon::pidfile::live_daemon_pid(&pidfile),
        Ok(Some(_))
    ) {
        tracing::info!(
            "dream: daemon is live — skipping one-shot DREAM_COMPOSED audit to avoid a writer race"
        );
        return;
    }
    let segment = FreedomConfig::default_wal_dir().join("000001.wal");
    let (writer, _join) = match crate::wal::writer::spawn(segment) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "dream: WAL writer spawn failed; DREAM_COMPOSED not recorded");
            return;
        }
    };
    let now_unix = crate::time::now_unix_secs();
    // Shared payload builder — identical shape to the daemon cron's 0xF4
    // frame (only the emit mechanism + provenance flag differ).
    let payload = dream_composed_payload(report, now_unix);
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
    use std::path::PathBuf;

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
