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
    /// Federation opt-in/out (`babel.federate`). Sharing anonymized window
    /// records is OFF by default; enabling additionally requires
    /// AutonomyLevel >= Elevated and calibration maturity at runtime.
    /// Without flags, prints the current federation state.
    Federate {
        /// Opt IN to the shared research pool.
        #[arg(long, conflicts_with = "disable")]
        enable: bool,
        /// Opt OUT (stops future submissions immediately; already-submitted
        /// pseudonymous windows cannot be recalled).
        #[arg(long)]
        disable: bool,
    },
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
            // A diagnostic that silently shows defaults on a config load
            // failure lies to the operator — fail loudly instead.
            let cfg = crate::config::FreedomConfig::load_from_path(
                &crate::config::FreedomConfig::default_path(),
            )
            .context("load freedom.yaml for babel status")?
            .babel;
            let conn = open_views()?;
            let total: i64 = conn
                .query_row("SELECT COUNT(*) FROM idx_babel_windows", [], |r| r.get(0))?;

            // Per-granularity summary: (window_secs, count, last_ts_end)
            let mut stmt = conn.prepare(
                "SELECT window_secs, COUNT(*), MAX(ts_end) FROM idx_babel_windows
                 GROUP BY window_secs ORDER BY window_secs",
            )?;
            let gran_rows: Vec<(i64, i64, i64)> = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<std::result::Result<Vec<_>, _>>()?;

            let collapses: i64 = conn.query_row(
                "SELECT COUNT(*) FROM idx_babel_windows WHERE collapse_5m = 1",
                [],
                |r| r.get(0),
            )?;

            match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    let windows_by_granularity: Vec<serde_json::Value> = gran_rows
                        .iter()
                        .map(|(secs, count, last)| {
                            serde_json::json!({
                                "window_secs": secs,
                                "count": count,
                                "last_ts_end": last,
                            })
                        })
                        .collect();
                    println!(
                        "{}",
                        serde_json::json!({
                            "enabled": cfg.enabled,
                            "threshold": cfg.threshold,
                            "epsilon_calibrated": cfg.epsilon_calibrated,
                            "federate": cfg.federate,
                            "total_windows": total,
                            "collapse_flagged": collapses,
                            "windows_by_granularity": windows_by_granularity,
                        })
                    );
                }
                OutputFormat::Table => {
                    println!("babel observer: {}", if cfg.enabled { "enabled" } else { "disabled" });
                    println!("threshold (15-min b_mult): {}", cfg.threshold);
                    match cfg.epsilon_calibrated {
                        Some(e) => println!("epsilon: {e} (frozen)"),
                        None => println!("epsilon: not yet calibrated (b_mult inactive)"),
                    }
                    println!(
                        "federation: {}",
                        if cfg.federate { "ENABLED (consent-gated at runtime)" } else { "disabled" }
                    );
                    if total == 0 {
                        println!("no windows recorded yet");
                        return Ok(());
                    }
                    println!("windows: {total}");
                    for (secs, count, last) in &gran_rows {
                        println!("  {secs:>5}s: {count} windows, last ts_end {last}");
                    }
                    println!("collapse-flagged windows: {collapses}");
                }
            }
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

            match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    let windows: Vec<serde_json::Value> = rows
                        .iter()
                        .map(|(id, secs, ts_start, ts_end, b_log, b_mult, b_bot, c5, c30, kind)| {
                            serde_json::json!({
                                "id": id,
                                "window_secs": secs,
                                "ts_start": ts_start,
                                "ts_end": ts_end,
                                "b_log": b_log,
                                "b_mult": b_mult,
                                "b_bottleneck": b_bot,
                                "collapse_5m": c5,
                                "collapse_30m": c30,
                                "collapse_kind": kind,
                            })
                        })
                        .collect();
                    println!("{}", serde_json::json!({"windows": windows}));
                }
                OutputFormat::Table => {
                    if rows.is_empty() {
                        println!("no windows");
                        return Ok(());
                    }
                    for (id, secs, ts_start, ts_end, b_log, b_mult, b_bot, c5, c30, kind) in &rows {
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
                            fmt_opt(*b_log),
                            fmt_opt(*b_mult),
                            b_bot,
                            fmt_flag(*c5),
                            fmt_flag(*c30),
                            kind.as_deref().unwrap_or("-"),
                        );
                    }
                }
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
        BabelAction::Federate { enable, disable } => {
            let path = crate::config::FreedomConfig::default_path();
            let mut fc = crate::config::FreedomConfig::load_from_path(&path)
                .with_context(|| format!("load {}", path.display()))?;
            if !enable && !disable {
                println!(
                    "federation: {}",
                    if fc.babel.federate { "ENABLED (consent-gated at runtime)" } else { "disabled" }
                );
                println!(
                    "transport endpoint: {}",
                    fc.babel.federation_endpoint.as_deref().unwrap_or("none (batches queue as pending files)")
                );
                return Ok(());
            }
            let target = enable;
            if fc.babel.federate == target {
                println!(
                    "federation already {}",
                    if target { "enabled" } else { "disabled" }
                );
                return Ok(());
            }
            fc.babel.federate = target;
            fc.save_public_to_default_path()?;
            if target {
                println!(
                    "federation ENABLED. Submissions additionally require AutonomyLevel >= \
                     Elevated and >= 50 calibrated windows; only anonymized, signed window \
                     records leave this machine (10% sample, 1:1 collapse ratio)."
                );
            } else {
                println!(
                    "federation disabled — submissions stop immediately \
                     (already-submitted pseudonymous windows cannot be recalled)."
                );
            }
        }
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

#[cfg(test)]
mod tests {

    /// JSON shape for `status` must contain the expected top-level keys.
    #[test]
    fn status_json_shape() {
        let v = serde_json::json!({
            "enabled": true,
            "threshold": 1.5_f64,
            "epsilon_calibrated": null,
            "federate": false,
            "total_windows": 42_i64,
            "collapse_flagged": 3_i64,
            "windows_by_granularity": [
                {"window_secs": 900_i64, "count": 42_i64, "last_ts_end": 1_700_000_000_i64}
            ],
        });
        assert_eq!(v["enabled"], true);
        assert_eq!(v["total_windows"], 42);
        assert_eq!(v["windows_by_granularity"][0]["window_secs"], 900);
        assert_eq!(v["windows_by_granularity"][0]["count"], 42);
    }

    /// JSON shape for `windows` must wrap rows under a `windows` array.
    #[test]
    fn windows_json_shape() {
        let row = serde_json::json!({
            "id": "abc-123",
            "window_secs": 900_i64,
            "ts_start": 1_700_000_000_i64,
            "ts_end": 1_700_000_900_i64,
            "b_log": 0.1234_f64,
            "b_mult": null,
            "b_bottleneck": 0.5678_f64,
            "collapse_5m": null,
            "collapse_30m": 1_i64,
            "collapse_kind": "agent_loop",
        });
        let envelope = serde_json::json!({"windows": [row]});
        assert!(envelope["windows"].is_array());
        assert_eq!(envelope["windows"][0]["id"], "abc-123");
        assert_eq!(envelope["windows"][0]["collapse_kind"], "agent_loop");
    }
}
