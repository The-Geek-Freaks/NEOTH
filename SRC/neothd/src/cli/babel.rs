//! GOLD-DELTA-08/09 — `neoth babel` CLI surface.
//!
//! Operator window into the Babel-Index observer: status, recent windows,
//! manual collapse labelling (`human_confirmed = 1`), enable/disable (the
//! `babel.enabled` flag in `freedom.yaml`), and the JSONL export the
//! delta-kosmologie theorem-test tooling consumes. All reads/writes go to
//! `views.db` — the observer has no WAL surface (byte space exhausted).

use std::path::PathBuf;
use std::str::FromStr as _;

use anyhow::{bail, Context as _, Result};
use clap::{Args, Subcommand};

use crate::analytics::babel::collapse::{persist_label, post_hoc_label_pass, CollapseLabel};
use crate::analytics::babel::export::export_batch;
use crate::cli::OutputFormat;

#[derive(Args, Debug, Clone)]
pub struct BabelArgs {
    #[command(subcommand)]
    pub action: BabelAction,

    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum BabelAction {
    /// Observer status: enabled flag, threshold, epsilon, window counts,
    /// latest scores per granularity.
    Status,
    /// Show the most recent closed windows.
    Windows {
        /// How many windows to show (newest first).
        #[arg(long, default_value = "10")]
        n: usize,
    },
    /// Attach an operator-confirmed collapse label to a window.
    ///
    /// Labels: agent_loop, retry_storm, tool_timeout_cascade,
    /// context_limit_failure, semantic_degradation, fallback_failure,
    /// objective_failure, tool_selection_failure.
    Label {
        /// The window id (`neoth babel windows` lists them).
        window_id: String,
        /// The collapse label to attach.
        label: String,
    },
    /// Enable the observer (`babel.enabled = true` in freedom.yaml).
    Enable,
    /// Disable the observer (`babel.enabled = false` in freedom.yaml).
    Disable,
    /// Export windows + labels as JSONL for the theorem-test tooling.
    /// Runs the post-hoc horizon pass first so every ripe window carries
    /// its collapse_30m stamp.
    Export {
        /// Output file path.
        #[arg(long)]
        out: PathBuf,
        /// Only windows with ts_end >= this unix timestamp (default: all).
        #[arg(long, default_value = "0")]
        since: i64,
    },
}

fn open_views() -> Result<rusqlite::Connection> {
    let path = crate::memory::store::default_path();
    let conn = crate::memory::store::open(&path)
        .with_context(|| format!("open views db {}", path.display()))?;
    crate::analytics::babel::store::ensure_schema(&conn)?;
    Ok(conn)
}

fn set_enabled(enabled: bool) -> Result<()> {
    let path = crate::config::FreedomConfig::default_path();
    let mut fc = crate::config::FreedomConfig::load_from_path(&path)
        .with_context(|| format!("load {}", path.display()))?;
    if fc.babel.enabled == enabled {
        println!("babel observer already {}", if enabled { "enabled" } else { "disabled" });
        return Ok(());
    }
    fc.babel.enabled = enabled;
    fc.save_public_to_default_path()?;
    println!(
        "babel observer {} (takes effect on the next daemon start / reload)",
        if enabled { "enabled" } else { "disabled" }
    );
    Ok(())
}

pub async fn run_babel(args: BabelArgs) -> Result<()> {
    match args.action {
        BabelAction::Status => {
            let cfg = crate::config::FreedomConfig::load_from_path(
                &crate::config::FreedomConfig::default_path(),
            )
            .map(|fc| fc.babel)
            .unwrap_or_default();
            let conn = open_views()?;
            let total: i64 = conn
                .query_row("SELECT COUNT(*) FROM idx_babel_windows", [], |r| r.get(0))?;
            println!("babel observer: {}", if cfg.enabled { "enabled" } else { "disabled" });
            println!("threshold (15-min b_mult): {}", cfg.threshold);
            match cfg.epsilon_calibrated {
                Some(e) => println!("epsilon: {e} (frozen)"),
                None => println!("epsilon: not yet calibrated (b_mult inactive)"),
            }
            if total == 0 {
                println!("no windows recorded yet");
                return Ok(());
            }
            println!("windows: {total}");
            let mut stmt = conn.prepare(
                "SELECT window_secs, COUNT(*), MAX(ts_end) FROM idx_babel_windows
                 GROUP BY window_secs ORDER BY window_secs",
            )?;
            let rows: Vec<(i64, i64, i64)> = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            for (secs, count, last) in rows {
                println!("  {secs:>5}s: {count} windows, last ts_end {last}");
            }
            let collapses: i64 = conn.query_row(
                "SELECT COUNT(*) FROM idx_babel_windows WHERE collapse_5m = 1",
                [],
                |r| r.get(0),
            )?;
            println!("collapse-flagged windows: {collapses}");
        }
        BabelAction::Windows { n } => {
            let conn = open_views()?;
            let mut stmt = conn.prepare(
                "SELECT id, window_secs, ts_start, ts_end, b_log, b_mult, b_bottleneck,
                        collapse_5m, collapse_30m, collapse_kind
                 FROM idx_babel_windows ORDER BY ts_end DESC LIMIT ?1",
            )?;
            #[allow(clippy::type_complexity)]
            let rows: Vec<(
                String,
                i64,
                i64,
                i64,
                Option<f64>,
                Option<f64>,
                f64,
                Option<i64>,
                Option<i64>,
                Option<String>,
            )> = stmt
                .query_map(rusqlite::params![n as i64], |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                        r.get(9)?,
                    ))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if rows.is_empty() {
                println!("no windows");
                return Ok(());
            }
            for (id, secs, ts_start, ts_end, b_log, b_mult, b_bot, c5, c30, kind) in rows {
                let fmt_opt = |v: Option<f64>| {
                    v.map(|x| format!("{x:.4}")).unwrap_or_else(|| "-".to_string())
                };
                let fmt_flag = |v: Option<i64>| match v {
                    Some(1) => "1",
                    Some(_) => "0",
                    None => "?",
                };
                println!(
                    "{id}  {secs:>5}s  [{ts_start}..{ts_end}]  b_log={} b_mult={} b_bneck={:.4}  c5={} c30={} kind={}",
                    fmt_opt(b_log),
                    fmt_opt(b_mult),
                    b_bot,
                    fmt_flag(c5),
                    fmt_flag(c30),
                    kind.as_deref().unwrap_or("-"),
                );
            }
        }
        BabelAction::Label { window_id, label } => {
            let parsed = CollapseLabel::from_str(&label)?;
            let conn = open_views()?;
            let exists: i64 = conn.query_row(
                "SELECT COUNT(*) FROM idx_babel_windows WHERE id = ?1",
                rusqlite::params![window_id],
                |r| r.get(0),
            )?;
            if exists == 0 {
                bail!("window `{window_id}` not found (`neoth babel windows` lists ids)");
            }
            persist_label(&conn, &window_id, parsed, true, crate::time::now_unix_i64())?;
            println!("labeled {window_id} as {} (operator-confirmed)", parsed.as_str());
        }
        BabelAction::Enable => set_enabled(true)?,
        BabelAction::Disable => set_enabled(false)?,
        BabelAction::Export { out, since } => {
            let conn = open_views()?;
            let stamped = post_hoc_label_pass(&conn, 1800, crate::time::now_unix_i64())?;
            let stats = export_batch(&conn, &out, "jsonl", since)?;
            println!(
                "exported {} windows ({} labels, {} horizons stamped) -> {}",
                stats.windows,
                stats.labels,
                stamped,
                out.display()
            );
        }
    }
    Ok(())
}
