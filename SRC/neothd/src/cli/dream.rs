//! `neoth dream now` — operator-triggered dream composition (SPEC-12 / R-02).
//!
//! Composes one batch of dreams over a recent window RIGHT NOW instead of
//! waiting for the daemon's nightly dreaming cron. It reuses
//! [`crate::cli::dreaming_task::run_one_pass`] — the exact orchestrator the cron
//! uses — so a manually-triggered dream is identical in shape to an automatic
//! one: gather the window's `idx_episode` rows, embed + cosine-cluster them into
//! themes (when an embed provider is configured; deterministic fallback
//! otherwise), and append a Dream per cluster to `~/.neoth/dreams/YYYY-MM-DD.jsonl`.
//!
//! Emits `0xF4 DREAM_COMPOSED` for the audit trail — best-effort, and only when
//! no daemon owns the WAL writer (a live daemon's nightly pass is the primary
//! path; a one-shot writer would race the daemon's segment).

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::cli::dreaming_task::{DEFAULT_MAX_EVENTS, DEFAULT_WINDOW, PassReport, run_one_pass};
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
}

pub async fn run_dream(args: DreamArgs, output: OutputFormat) -> Result<()> {
    match args.action {
        DreamAction::Now {
            window_secs,
            max_events,
        } => run_now(window_secs, max_events, output).await,
    }
}

async fn run_now(
    window_secs: Option<u64>,
    max_events: Option<usize>,
    output: OutputFormat,
) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    let config = FreedomConfig::load_from_default_path().unwrap_or_default();
    let embed = crate::providers::embed_provider_from_config(&config).await;
    let window = window_secs.map(Duration::from_secs).unwrap_or(DEFAULT_WINDOW);
    let max = max_events.unwrap_or(DEFAULT_MAX_EVENTS);

    let report = run_one_pass(&home, embed.as_deref(), window, max).await?;

    // Best-effort DREAM_COMPOSED audit — only when this process wrote dreams
    // AND no daemon owns the writer (avoid racing the daemon's segment).
    if report.dreams_written > 0 {
        emit_dream_composed(&report);
    }

    render(&report, output);
    Ok(())
}

/// `YYYY-MM-DD` from the report's JSONL path stem (the file the dreams landed
/// in, e.g. `~/.neoth/dreams/2026-06-03.jsonl` → `2026-06-03`). Falls back to
/// the empty string if the path has no stem — the audit frame still emits.
fn day_from_path(path: &Path) -> String {
    path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string()
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
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let payload = serde_json::to_vec(&serde_json::json!({
        "day": day_from_path(&report.path),
        "dreams": report.dreams_written,
        "events_considered": report.events_considered,
        "path_taken": format!("{:?}", report.path_taken),
        "ts_unix": now_unix,
    }))
    .unwrap_or_default();
    let header =
        crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_DREAM_COMPOSED, &payload)
            .build();
    if let Err(e) = writer.try_append_sync(header, payload) {
        tracing::warn!(error = %e, "dream: DREAM_COMPOSED frame append failed (audit gap)");
    }
}

fn render(report: &PassReport, output: OutputFormat) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "day": day_from_path(&report.path),
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
    use std::path::PathBuf;

    #[test]
    fn day_from_path_extracts_yyyy_mm_dd() {
        let p = PathBuf::from("/home/op/.neoth/dreams/2026-06-03.jsonl");
        assert_eq!(day_from_path(&p), "2026-06-03");
    }

    #[test]
    fn day_from_path_empty_when_no_stem() {
        assert_eq!(day_from_path(Path::new("/")), "");
    }
}
