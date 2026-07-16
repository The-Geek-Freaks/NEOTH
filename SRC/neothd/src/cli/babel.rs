//! GOLD-DELTA-08/09 — `neoth babel` CLI surface.
//!
//! Operator window into the Babel-Index observer: status, recent windows,
//! manual collapse labelling (`human_confirmed = 1`), enable/disable (the
//! `babel.enabled` flag in `freedom.yaml`), and the JSONL export the
//! delta-kosmologie theorem-test tooling consumes. All reads/writes go to
//! `views.db` — the observer has no WAL surface (byte space exhausted).

use std::path::PathBuf;
use std::str::FromStr as _;

use anyhow::{Context as _, Result, bail};
use clap::{Args, Subcommand};
use rusqlite::OptionalExtension as _;

use crate::analytics::babel::collapse::{
    CollapseLabel, NegativeControlType, persist_label, post_hoc_label_pass,
};
use crate::analytics::babel::export::export_batch;
use crate::analytics::babel::store::persist_negative_control;
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
    /// Tag or untag a deliberately stable window used as a negative control.
    NegativeControl {
        #[command(subcommand)]
        action: NegativeControlAction,
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
        /// Export format override. Precedence: --format > babel.export_format
        /// in freedom.yaml > default ("jsonl"). Only "jsonl" is currently
        /// implemented; any other value is a loud error before any file write.
        #[arg(long)]
        format: Option<String>,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum NegativeControlAction {
    /// Mark a window as an operator-declared negative control.
    Set {
        /// The window id (`neoth babel windows` lists them).
        window_id: String,
        /// One of: synthetic_stable, isolated_run, replay_deterministic.
        control_type: String,
    },
    /// Remove a negative-control tag from a window.
    Clear {
        /// The window id (`neoth babel windows` lists them).
        window_id: String,
    },
}

fn open_views() -> Result<rusqlite::Connection> {
    let path = crate::memory::store::default_path();
    let conn = crate::memory::store::open(&path)
        .with_context(|| format!("open views db {}", path.display()))?;
    crate::analytics::babel::store::ensure_schema(&conn)?;
    Ok(conn)
}

fn set_enabled(enabled: bool, output: OutputFormat) -> Result<()> {
    let path = crate::config::FreedomConfig::default_path();
    let unchanged = crate::config::FreedomConfig::update_at(&path, |config| {
        let unchanged = config.babel.enabled == enabled;
        config.babel.enabled = enabled;
        Ok(unchanged)
    })
    .with_context(|| format!("update {}", path.display()))?;
    render_enabled(enabled, output, unchanged);
    Ok(())
}

fn render_enabled(enabled: bool, output: OutputFormat, unchanged: bool) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "action": if enabled { "enable" } else { "disable" },
                "enabled": enabled,
            })
        ),
        OutputFormat::Table if unchanged => println!(
            "babel observer already {}",
            if enabled { "enabled" } else { "disabled" }
        ),
        OutputFormat::Table => println!(
            "babel observer {} (takes effect on the next daemon start / reload)",
            if enabled { "enabled" } else { "disabled" }
        ),
    }
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
            let total: i64 =
                conn.query_row("SELECT COUNT(*) FROM idx_babel_windows", [], |r| r.get(0))?;

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
            let negative_controls: i64 = conn.query_row(
                "SELECT COUNT(*) FROM idx_babel_windows WHERE negative_ctrl = 1",
                [],
                |r| r.get(0),
            )?;
            let last_variables: Option<String> = conn
                .query_row(
                    "SELECT variables FROM idx_babel_windows ORDER BY ts_end DESC LIMIT 1",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            let last_variables = last_variables
                .as_deref()
                .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());
            let last_k_d_posture = last_variables
                .as_ref()
                .and_then(|v| v.get("k_d_posture"))
                .cloned();

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
                            "negative_controls": negative_controls,
                            "windows_by_granularity": windows_by_granularity,
                            "memory_signals": {
                                "enabled": cfg.memory_signals,
                                "mapping_version": crate::analytics::babel::signals::SIGNAL_MAPPING_VERSION,
                                "sources": ["new_contradiction", "true_recall_miss"],
                            },
                            "skill_signals": {
                                "enabled": cfg.skill_signals,
                                "mapping_version": crate::analytics::babel::signals::SIGNAL_MAPPING_VERSION,
                                "outcomes": ["mode", "keyword", "embedding", "no_match", "suppressed"],
                            },
                            "k_d": {
                                "mode": if cfg.k_d_embedding_model.is_some() { "embedding_v1" } else { "histogram_v0" },
                                "requested_model": cfg.k_d_embedding_model.as_deref(),
                                "last_window_posture": last_k_d_posture,
                            },
                        })
                    );
                }
                OutputFormat::Table => {
                    println!(
                        "babel observer: {}",
                        if cfg.enabled { "enabled" } else { "disabled" }
                    );
                    println!("threshold (15-min b_mult): {}", cfg.threshold);
                    match cfg.epsilon_calibrated {
                        Some(e) => println!("epsilon: {e} (frozen)"),
                        None => println!("epsilon: not yet calibrated (b_mult inactive)"),
                    }
                    println!(
                        "federation: {}",
                        if cfg.federate {
                            "ENABLED (consent-gated at runtime)"
                        } else {
                            "disabled"
                        }
                    );
                    println!(
                        "memory_signals: {} ({})",
                        if cfg.memory_signals {
                            "enabled"
                        } else {
                            "disabled"
                        },
                        crate::analytics::babel::signals::SIGNAL_MAPPING_VERSION,
                    );
                    println!(
                        "skill_signals: {} ({})",
                        if cfg.skill_signals {
                            "enabled"
                        } else {
                            "disabled"
                        },
                        crate::analytics::babel::signals::SIGNAL_MAPPING_VERSION,
                    );
                    match cfg.k_d_embedding_model.as_deref() {
                        Some(model) => println!(
                            "K_d: embedding_v1, requested local model {model}, last posture {}",
                            last_k_d_posture
                                .as_ref()
                                .map(serde_json::Value::to_string)
                                .unwrap_or_else(|| "not recorded yet".to_string())
                        ),
                        None => println!("K_d: histogram_v0"),
                    }
                    if total == 0 {
                        println!("no windows recorded yet");
                        return Ok(());
                    }
                    println!("windows: {total}");
                    for (secs, count, last) in &gran_rows {
                        println!("  {secs:>5}s: {count} windows, last ts_end {last}");
                    }
                    println!("collapse-flagged windows: {collapses}");
                    println!("negative-control windows: {negative_controls}");
                }
            }
        }
        BabelAction::Windows { n } => {
            let conn = open_views()?;
            let mut stmt = conn.prepare(
                "SELECT id, window_secs, ts_start, ts_end, b_log, b_mult, b_bottleneck,
                        collapse_5m, collapse_30m, collapse_kind, negative_control_type
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
                        r.get(10)?,
                    ))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;

            match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    let windows: Vec<serde_json::Value> = rows
                        .iter()
                        .map(
                            |(
                                id,
                                secs,
                                ts_start,
                                ts_end,
                                b_log,
                                b_mult,
                                b_bot,
                                c5,
                                c30,
                                kind,
                                negative_control_type,
                            )| {
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
                                    "negative_control": negative_control_type.is_some(),
                                    "negative_control_type": negative_control_type,
                                })
                            },
                        )
                        .collect();
                    println!("{}", serde_json::json!({"windows": windows}));
                }
                OutputFormat::Table => {
                    if rows.is_empty() {
                        println!("no windows");
                        return Ok(());
                    }
                    for (
                        id,
                        secs,
                        ts_start,
                        ts_end,
                        b_log,
                        b_mult,
                        b_bot,
                        c5,
                        c30,
                        kind,
                        negative_control_type,
                    ) in &rows
                    {
                        let fmt_opt = |v: Option<f64>| {
                            v.map(|x| format!("{x:.4}"))
                                .unwrap_or_else(|| "-".to_string())
                        };
                        let fmt_flag = |v: Option<i64>| match v {
                            Some(1) => "1",
                            Some(_) => "0",
                            None => "?",
                        };
                        println!(
                            "{id}  {secs:>5}s  [{ts_start}..{ts_end}]  b_log={} b_mult={} b_bneck={:.4}  c5={} c30={} kind={} negative_control={}",
                            fmt_opt(*b_log),
                            fmt_opt(*b_mult),
                            b_bot,
                            fmt_flag(*c5),
                            fmt_flag(*c30),
                            kind.as_deref().unwrap_or("-"),
                            negative_control_type.as_deref().unwrap_or("-"),
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
            println!(
                "labeled {window_id} as {} (operator-confirmed)",
                parsed.as_str()
            );
        }
        BabelAction::NegativeControl { action } => {
            let conn = open_views()?;
            let (window_id, control_type) = match action {
                NegativeControlAction::Set {
                    window_id,
                    control_type,
                } => (
                    window_id,
                    Some(NegativeControlType::from_str(&control_type)?),
                ),
                NegativeControlAction::Clear { window_id } => (window_id, None),
            };
            if !persist_negative_control(&conn, &window_id, control_type)? {
                bail!("window `{window_id}` not found (`neoth babel windows` lists ids)");
            }
            match control_type {
                Some(value) => println!(
                    "tagged {window_id} as negative control ({})",
                    value.as_str()
                ),
                None => println!("cleared negative-control tag from {window_id}"),
            }
        }
        BabelAction::Enable => set_enabled(true, args.output)?,
        BabelAction::Disable => set_enabled(false, args.output)?,
        BabelAction::Federate { enable, disable } => {
            let path = crate::config::FreedomConfig::default_path();
            if !enable && !disable {
                let fc = crate::config::FreedomConfig::load_from_path(&path)
                    .with_context(|| format!("load {}", path.display()))?;
                println!(
                    "federation: {}",
                    if fc.babel.federate {
                        "ENABLED (consent-gated at runtime)"
                    } else {
                        "disabled"
                    }
                );
                println!(
                    "transport endpoint: {}",
                    fc.babel
                        .federation_endpoint
                        .as_deref()
                        .unwrap_or("none (batches queue as pending files)")
                );
                return Ok(());
            }
            let target = enable;
            let unchanged = crate::config::FreedomConfig::update_at(&path, |config| {
                let unchanged = config.babel.federate == target;
                config.babel.federate = target;
                Ok(unchanged)
            })
            .with_context(|| format!("update {}", path.display()))?;
            if unchanged {
                println!(
                    "federation already {}",
                    if target { "enabled" } else { "disabled" }
                );
                return Ok(());
            }
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
        BabelAction::Export { out, since, format } => {
            // Load config fail-loud: a silent fallback to "jsonl" would hide
            // a misconfigured export_format (e.g. "csv") that the operator
            // set expecting a loud error. Precedence: --format > config > default.
            let cfg = crate::config::FreedomConfig::load_from_path(
                &crate::config::FreedomConfig::default_path(),
            )
            .context("load freedom.yaml for babel export")?
            .babel;
            let effective_format = format.unwrap_or(cfg.export_format);
            let conn = open_views()?;
            let stamped = post_hoc_label_pass(&conn, 1800, crate::time::now_unix_i64())?;
            let stats = export_batch(&conn, &out, &effective_format, since)?;
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
    use crate::analytics::babel::export::export_batch;
    use crate::analytics::babel::store::ensure_schema;

    /// Minimal seeded in-memory connection with one window row for export tests.
    fn seeded_conn() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().expect("mem db");
        ensure_schema(&conn).expect("schema");
        let vars = serde_json::json!({
            "C": 0.5, "K": 0.4, "M": 0.3, "A": 0.5, "V": 0.2, "D": 1.0, "H": 1.0,
            "algo": {"c": "C_d_v0", "k": "K_d_v0", "m": "M_d_v0", "a": "A_d_v0",
                      "v": "V_d_v0", "d": "D_d_v0", "h": "H_d_v0"},
            "k_d_posture": {"mode": "histogram_v0", "requested_model": null,
                "effective_model": null, "sample_count": 3, "failure_count": 0,
                "failure_reasons": [], "degraded_reason": null},
            "signal_posture": {"mapping_version": "BabelSignalMap_v1",
                "memory_enabled": false, "skill_enabled": false,
                "memory_contradictions": 0, "memory_recall_misses": 0,
                "skill_mode": 0, "skill_keyword": 0, "skill_embedding": 0,
                "skill_no_match": 0, "skill_suppressed": 0},
            "schema": "neoth-babel-window/0.4.0",
        });
        conn.execute(
            "INSERT INTO idx_babel_windows
             (id, session_id, window_secs, ts_start, ts_end, b_log, b_bottleneck, variables)
             VALUES (?1, 'a1b2c3d4e5f60718', 900, 0, 900, -1.5, 0.2, ?2)",
            rusqlite::params!["w0", vars.to_string()],
        )
        .expect("seed");
        conn
    }

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

    /// Status JSON reports live source gates and mapping version (B24).
    #[test]
    fn status_json_shape_includes_live_signal_keys() {
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
            "memory_signals": {"enabled": true, "mapping_version": "BabelSignalMap_v1"},
            "skill_signals": {"enabled": false, "mapping_version": "BabelSignalMap_v1"},
            "k_d": {"mode": "histogram_v0", "requested_model": null},
        });
        assert_eq!(v["memory_signals"]["enabled"], true);
        assert_eq!(v["skill_signals"]["enabled"], false);
        assert_eq!(v["k_d"]["mode"], "histogram_v0");
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

    /// A configured export_format of "csv" must produce a loud error before
    /// any file is written at the target path (B24 truth-slice).
    #[test]
    fn export_arm_errors_on_configured_csv_before_write() {
        let conn = seeded_conn();
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("babel.jsonl");
        // Simulate: config has export_format = "csv", no CLI --format flag →
        // config value is the effective format (precedence: CLI > config > default).
        let effective = "csv".to_string();
        let result = export_batch(&conn, &out, &effective, 0);
        assert!(result.is_err(), "csv format must produce an error");
        let msg = format!("{:?}", result.unwrap_err());
        assert!(
            msg.contains("unsupported babel export format"),
            "error must name the unsupported format; got: {msg}"
        );
        assert!(
            !out.exists(),
            "target file must not exist after a format error"
        );
    }

    /// export_format = "jsonl" from config (no CLI flag) must succeed and write
    /// the output file with at least one window (B24 truth-slice).
    #[test]
    fn export_arm_passes_format_from_config() {
        let conn = seeded_conn();
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("babel.jsonl");
        // Simulate: config has export_format = "jsonl", no CLI --format flag →
        // config value is the effective format.
        let effective = "jsonl".to_string();
        let stats = export_batch(&conn, &out, &effective, 0)
            .expect("jsonl export via config format must succeed");
        assert!(stats.windows > 0, "at least one window must be exported");
        assert!(
            out.exists(),
            "output file must exist after a successful export"
        );
    }

    /// CLI --format flag wins over babel.export_format in config (B24 truth-slice).
    /// Case A: --format jsonl + config csv → success.
    /// Case B: --format csv + config jsonl → error (CLI override is enforced).
    #[test]
    fn export_cli_format_flag_overrides_config() {
        let conn = seeded_conn();
        let dir = tempfile::tempdir().expect("tempdir");

        // Case A: CLI jsonl beats config csv → export must succeed.
        let out_ok = dir.path().join("ok.jsonl");
        let effective_a = "jsonl".to_string(); // CLI --format jsonl overrides config csv
        let result_a = export_batch(&conn, &out_ok, &effective_a, 0);
        assert!(
            result_a.is_ok(),
            "CLI --format jsonl must beat config csv and succeed"
        );
        assert!(out_ok.exists(), "output file must exist on success");

        // Case B: CLI csv beats config jsonl → export must error.
        let out_bad = dir.path().join("bad.jsonl");
        let effective_b = "csv".to_string(); // CLI --format csv overrides config jsonl
        let result_b = export_batch(&conn, &out_bad, &effective_b, 0);
        assert!(
            result_b.is_err(),
            "CLI --format csv must beat config jsonl and error"
        );
        assert!(
            !out_bad.exists(),
            "no file written when CLI format is unsupported"
        );
    }
}
