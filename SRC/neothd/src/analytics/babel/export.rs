//! GOLD-DELTA-08 — Babel window export pipeline.
//!
//! Serialises closed windows (+ their labels) from `views.db` into a JSONL
//! file the delta-kosmologie theorem-test tooling ingests. The stored
//! `session_id` is ALREADY the HMAC pseudonym (16 hex — the cron never
//! persists a raw id), so export passes it through as
//! `pseudonymised_session_id`. No WAL output — the event byte space is
//! exhausted. Callers run [`super::collapse::post_hoc_label_pass`] first so
//! every ripe horizon is stamped before rows leave the machine.
//!
//! Windows whose 30-minute horizon has NOT yet ripened are included with
//! `collapse_30m = null` — the honest value. Theorem-test tooling must
//! filter `collapse_30m IS NOT NULL` before training any h=30m model;
//! the rows remain valid for feature analysis and the h=5m label.
//!
//! The file is written `.tmp`-then-rename: a failed export never leaves a
//! partial file at the target path for a polling consumer to ingest.

use std::io::Write as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use rusqlite::Connection;

/// What an export produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExportStats {
    /// Window rows written.
    pub windows: usize,
    /// Label rows attached across all windows.
    pub labels: usize,
}

/// Export every window with `ts_end >= since_ts` as JSONL. `format` accepts
/// only `"jsonl"` (the `babel.export_format` config value) — anything else
/// is a loud error, not a silent fallback.
pub fn export_batch(
    conn: &Connection,
    out_path: &Path,
    format: &str,
    since_ts: i64,
) -> Result<ExportStats> {
    if format != "jsonl" {
        bail!("unsupported babel export format `{format}` (only `jsonl` is implemented)");
    }
    let mut stmt = conn.prepare(
        "SELECT id, session_id, window_secs, ts_start, ts_end,
                b_log, b_mult, b_bottleneck, variables,
                collapse_5m, collapse_30m, collapse_kind, negative_ctrl,
                negative_control_type, submitted
         FROM idx_babel_windows
         WHERE ts_end >= ?1
         ORDER BY ts_end ASC",
    )?;
    struct Row {
        id: String,
        session_id: String,
        window_secs: i64,
        ts_start: i64,
        ts_end: i64,
        b_log: Option<f64>,
        b_mult: Option<f64>,
        b_bottleneck: f64,
        variables: String,
        collapse_5m: Option<i64>,
        collapse_30m: Option<i64>,
        collapse_kind: Option<String>,
        negative_ctrl: i64,
        negative_control_type: Option<String>,
        submitted: i64,
    }
    let rows: Vec<Row> = stmt
        .query_map(rusqlite::params![since_ts], |r| {
            Ok(Row {
                id: r.get(0)?,
                session_id: r.get(1)?,
                window_secs: r.get(2)?,
                ts_start: r.get(3)?,
                ts_end: r.get(4)?,
                b_log: r.get(5)?,
                b_mult: r.get(6)?,
                b_bottleneck: r.get(7)?,
                variables: r.get(8)?,
                collapse_5m: r.get(9)?,
                collapse_30m: r.get(10)?,
                collapse_kind: r.get(11)?,
                negative_ctrl: r.get(12)?,
                negative_control_type: r.get(13)?,
                submitted: r.get(14)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let mut label_stmt = conn.prepare(
        "SELECT label, human_confirmed, labeled_at FROM idx_babel_labels
         WHERE window_id = ?1 ORDER BY labeled_at ASC",
    )?;

    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create export dir {}", parent.display()))?;
    }
    let tmp_path = out_path.with_extension("jsonl.tmp");
    let file = std::fs::File::create(&tmp_path)
        .with_context(|| format!("create export temp file {}", tmp_path.display()))?;
    let mut w = std::io::BufWriter::new(file);

    let mut stats = ExportStats {
        windows: 0,
        labels: 0,
    };
    for row in rows {
        let labels: Vec<serde_json::Value> = label_stmt
            .query_map(rusqlite::params![row.id], |r| {
                Ok(serde_json::json!({
                    "label": r.get::<_, String>(0)?,
                    "human_confirmed": r.get::<_, i64>(1)? == 1,
                    "labeled_at": r.get::<_, i64>(2)?,
                }))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        stats.labels += labels.len();
        // The stored variables blob carries the 7 features + `algo` version
        // map + `schema` (see store::insert_window) — split it back apart so
        // the export schema has them as explicit top-level fields. A corrupt
        // blob is a hard error: silently exporting an all-null record would
        // poison the theorem-test dataset undetectably.
        let vars: serde_json::Value = serde_json::from_str(&row.variables)
            .with_context(|| format!("decode variables blob for window {}", row.id))?;
        let algorithm_versions = vars.get("algo").cloned().unwrap_or(serde_json::Value::Null);
        let schema_version = vars
            .get("schema")
            .and_then(|s| s.as_str())
            .unwrap_or(super::window::BabelWindow::SCHEMA_VERSION)
            .to_string();
        let has_all_fields = |key: &str, fields: &[&str]| {
            vars.get(key)
                .and_then(serde_json::Value::as_object)
                .is_some_and(|object| fields.iter().all(|field| object.contains_key(*field)))
        };
        let k_d_posture_valid = vars
            .get("k_d_posture")
            .cloned()
            .and_then(|value| serde_json::from_value::<super::feature::KdPosture>(value).ok())
            .is_some();
        let signal_posture_valid = vars
            .get("signal_posture")
            .cloned()
            .and_then(|value| serde_json::from_value::<super::signals::SignalPosture>(value).ok())
            .is_some();
        let current_posture_complete = has_all_fields(
            "k_d_posture",
            &[
                "mode",
                "requested_model",
                "effective_model",
                "sample_count",
                "failure_count",
                "failure_reasons",
                "degraded_reason",
            ],
        ) && has_all_fields(
            "signal_posture",
            &[
                "mapping_version",
                "memory_enabled",
                "skill_enabled",
                "memory_contradictions",
                "memory_recall_misses",
                "skill_mode",
                "skill_keyword",
                "skill_embedding",
                "skill_no_match",
                "skill_suppressed",
            ],
        );
        if schema_version == super::window::BabelWindow::SCHEMA_VERSION
            && (!current_posture_complete || !k_d_posture_valid || !signal_posture_valid)
        {
            anyhow::bail!(
                "current-schema Babel window {} has incomplete/invalid K_d or signal posture",
                row.id
            );
        }
        let negative_control_type = match (row.negative_ctrl, row.negative_control_type.as_deref())
        {
            (0, None) => None,
            (1, Some(value)) => Some(
                value
                    .parse::<super::collapse::NegativeControlType>()
                    .with_context(|| {
                        format!("invalid negative-control type for window {}", row.id)
                    })?,
            ),
            _ => anyhow::bail!(
                "inconsistent negative-control state for Babel window {}",
                row.id
            ),
        };
        let line = serde_json::json!({
            "record_version": "neoth-babel-export/0.3.0",
            "schema_version": schema_version,
            "id": row.id,
            "pseudonymised_session_id": row.session_id,
            "window_secs": row.window_secs,
            "ts_start": row.ts_start,
            "ts_end": row.ts_end,
            "b_log": row.b_log,
            "b_mult": row.b_mult,
            "b_bottleneck": row.b_bottleneck,
            "variables": {
                "C": vars.get("C"), "K": vars.get("K"), "M": vars.get("M"),
                "A": vars.get("A"), "V": vars.get("V"), "D": vars.get("D"),
                "H": vars.get("H"),
            },
            "algorithm_versions": algorithm_versions,
            "k_d_posture": vars.get("k_d_posture"),
            "signal_posture": vars.get("signal_posture"),
            "collapse_5m": row.collapse_5m,
            "collapse_30m": row.collapse_30m,
            "collapse_kind": row.collapse_kind,
            "labels": labels,
            "negative_control": row.negative_ctrl == 1,
            "negative_control_type": negative_control_type.map(|value| value.as_str()),
            "submitted": row.submitted == 1,
        });
        writeln!(w, "{line}").context("write export line")?;
        stats.windows += 1;
    }
    w.flush().context("flush export file")?;
    drop(w);
    std::fs::rename(&tmp_path, out_path)
        .with_context(|| format!("rename {} -> {}", tmp_path.display(), out_path.display()))?;
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analytics::babel::collapse::{CollapseLabel, NegativeControlType, persist_label};
    use crate::analytics::babel::store::{ensure_schema, persist_negative_control};

    const T: i64 = 1_800_000_000;

    fn seeded() -> Connection {
        let conn = Connection::open_in_memory().expect("mem db");
        ensure_schema(&conn).expect("schema");
        for i in 0..3i64 {
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
                 VALUES (?1, 'a1b2c3d4e5f60718', 900, ?2, ?3, -1.5, 0.2, ?4)",
                rusqlite::params![
                    format!("w{i}"),
                    T + i * 900 - 900,
                    T + i * 900,
                    vars.to_string()
                ],
            )
            .expect("seed");
        }
        persist_label(&conn, "w1", CollapseLabel::RetryStorm, true, T).expect("label");
        persist_negative_control(&conn, "w2", Some(NegativeControlType::IsolatedRun))
            .expect("negative control");
        conn
    }

    #[test]
    fn export_writes_valid_jsonl_with_required_fields() {
        let conn = seeded();
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("babel.jsonl");
        let stats = export_batch(&conn, &out, "jsonl", 0).expect("export");
        assert_eq!(
            stats,
            ExportStats {
                windows: 3,
                labels: 1
            }
        );
        let body = std::fs::read_to_string(&out).expect("read back");
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 3);
        for line in &lines {
            let v: serde_json::Value = serde_json::from_str(line).expect("valid JSON line");
            assert_eq!(v["pseudonymised_session_id"], "a1b2c3d4e5f60718");
            assert_eq!(v["record_version"], "neoth-babel-export/0.3.0");
            assert_eq!(v["schema_version"], "neoth-babel-window/0.4.0");
            assert_eq!(v["algorithm_versions"]["k"], "K_d_v0");
            assert!(v["variables"]["C"].is_number());
            assert!(
                v.get("session_id").is_none(),
                "no raw session_id key in export"
            );
        }
        let labeled: Vec<serde_json::Value> = lines
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .filter(|v: &serde_json::Value| !v["labels"].as_array().unwrap().is_empty())
            .collect();
        assert_eq!(labeled.len(), 1);
        assert_eq!(labeled[0]["labels"][0]["label"], "retry_storm");
        assert_eq!(labeled[0]["labels"][0]["human_confirmed"], true);
        let control: serde_json::Value = lines
            .iter()
            .map(|line| serde_json::from_str(line).unwrap())
            .find(|value: &serde_json::Value| value["negative_control"] == true)
            .expect("negative-control row exported");
        assert_eq!(control["negative_control_type"], "isolated_run");
    }

    #[test]
    fn export_respects_since_ts_and_rejects_unknown_format() {
        let conn = seeded();
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("since.jsonl");
        let stats = export_batch(&conn, &out, "jsonl", T + 1).expect("export");
        assert_eq!(stats.windows, 2, "w0 (ts_end = T) filtered out by since_ts");
        assert!(
            export_batch(&conn, &out, "csv", 0).is_err(),
            "unknown format is loud"
        );
    }
}
