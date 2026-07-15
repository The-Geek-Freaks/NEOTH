//! GOLD-DELTA-02 — SQLite persistence schema for the Babel-Index observer.
//!
//! Babel output lives in SQLite ONLY (the WAL event byte space is exhausted,
//! 255/256 — verified 2026-07-02; see the WS-DELTA tracker section). Three
//! tables on the operator's `views.db`:
//!
//! - `idx_babel_windows` — one row per closed window (canonical DDL mirrors
//!   the doc block in `window.rs`).
//! - `idx_babel_norm`    — p1/p99 snapshots of the consumed `b_raw`
//!   distribution per window size, swept every 5 min (doc block in `norm.rs`).
//! - `idx_babel_labels`  — collapse labels per window, from the post-hoc
//!   detector pass or operator CLI labelling (`human_confirmed = 1`).
//!
//! `ensure_schema` is idempotent (CREATE TABLE IF NOT EXISTS) and is called
//! once by the daemon cron at spawn (GOLD-DELTA-04).

use anyhow::Result;
use rusqlite::Connection;

use super::collapse::NegativeControlType;
use super::window::BabelWindow;

/// Create the three Babel tables + query-path indexes. Idempotent.
pub fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS idx_babel_windows (
            id            TEXT PRIMARY KEY,
            session_id    TEXT NOT NULL,
            window_secs   INTEGER NOT NULL,
            ts_start      INTEGER NOT NULL,
            ts_end        INTEGER NOT NULL,
            b_log         REAL,
            b_mult        REAL,
            b_bottleneck  REAL NOT NULL,
            variables     TEXT NOT NULL,
            collapse_5m   INTEGER,
            collapse_30m  INTEGER,
            collapse_kind TEXT,
            negative_ctrl INTEGER NOT NULL DEFAULT 0,
            negative_control_type TEXT CHECK (
                negative_control_type IS NULL OR negative_control_type IN (
                    'synthetic_stable', 'isolated_run', 'replay_deterministic'
                )
            ),
            submitted     INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_babel_windows_ts_end
            ON idx_babel_windows (ts_end);
        CREATE INDEX IF NOT EXISTS idx_babel_windows_submitted
            ON idx_babel_windows (submitted) WHERE submitted = 0;

        CREATE TABLE IF NOT EXISTS idx_babel_norm (
            variable     TEXT NOT NULL,
            window_secs  INTEGER NOT NULL,
            p1           REAL NOT NULL,
            p99          REAL NOT NULL,
            sample_count INTEGER NOT NULL,
            updated_at   INTEGER NOT NULL,
            PRIMARY KEY (variable, window_secs)
        );

        CREATE TABLE IF NOT EXISTS idx_babel_labels (
            window_id       TEXT NOT NULL,
            label           TEXT NOT NULL,
            human_confirmed INTEGER NOT NULL DEFAULT 0,
            labeled_at      INTEGER NOT NULL,
            PRIMARY KEY (window_id, label)
        );
        "#,
    )?;

    // `CREATE TABLE IF NOT EXISTS` cannot evolve an existing installation.
    // Add the v0.4 negative-control discriminator in place; old rows remain
    // valid because the operator-tagged control bit never had a producer.
    let mut columns = conn.prepare("PRAGMA table_info(idx_babel_windows)")?;
    let has_negative_control_type = columns
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<std::result::Result<Vec<_>, _>>()?
        .iter()
        .any(|name| name == "negative_control_type");
    drop(columns);
    if !has_negative_control_type {
        conn.execute(
            "ALTER TABLE idx_babel_windows ADD COLUMN negative_control_type TEXT \
             CHECK (negative_control_type IS NULL OR negative_control_type IN (\
               'synthetic_stable', 'isolated_run', 'replay_deterministic'))",
            [],
        )?;
    }
    Ok(())
}

/// Persist one closed window. `collapse_30m` stays NULL until the post-hoc
/// label pass (GOLD-DELTA-07) fills it; `submitted` defaults to 0.
///
/// The `variables` JSON carries the seven raw features PLUS the per-feature
/// algorithm versions and the record schema version — the export pipeline
/// (GOLD-DELTA-08) and cross-contributor sensitivity analysis need them
/// per-row, and the table has no dedicated columns for them.
pub fn insert_window(conn: &Connection, w: &BabelWindow) -> Result<()> {
    let variables = serde_json::json!({
        "C": w.features.c, "K": w.features.k, "M": w.features.m,
        "A": w.features.a, "V": w.features.v, "D": w.features.d, "H": w.features.h,
        "algo": {
            "c": w.algorithm_version_c, "k": w.algorithm_version_k,
            "m": w.algorithm_version_m, "a": w.algorithm_version_a,
            "v": w.algorithm_version_v, "d": w.algorithm_version_d,
            "h": w.algorithm_version_h,
        },
        "k_d_posture": w.features.k_d_posture,
        "signal_posture": w.signal_posture,
        "schema": w.schema_version,
    });
    conn.execute(
        "INSERT INTO idx_babel_windows
         (id, session_id, window_secs, ts_start, ts_end,
          b_log, b_mult, b_bottleneck, variables,
          collapse_5m, collapse_30m, collapse_kind, negative_ctrl, negative_control_type)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        rusqlite::params![
            w.id,
            w.session_id_pseudo,
            w.granularity.secs() as i64,
            w.ts_start,
            w.ts_end,
            w.scores.b_log,
            w.scores.b_mult,
            w.scores.b_bottleneck,
            variables.to_string(),
            i64::from(w.collapse.collapse_within_5m),
            w.collapse.collapse_within_30m.map(i64::from),
            w.collapse
                .collapse_kind
                .map(super::collapse::CollapseLabel::as_str),
            i64::from(w.collapse.negative_control),
            w.collapse
                .negative_control_type
                .map(NegativeControlType::as_str),
        ],
    )?;
    Ok(())
}

/// Set or clear an operator-declared negative control on an existing window.
/// The boolean and discriminator are updated together so exports and
/// federation can never observe a half-tagged control.
pub fn persist_negative_control(
    conn: &Connection,
    window_id: &str,
    control_type: Option<NegativeControlType>,
) -> Result<bool> {
    let changed = conn.execute(
        "UPDATE idx_babel_windows
         SET negative_ctrl = ?2, negative_control_type = ?3
         WHERE id = ?1",
        rusqlite::params![
            window_id,
            i64::from(control_type.is_some()),
            control_type.map(NegativeControlType::as_str),
        ],
    )?;
    Ok(changed == 1)
}

// ── GOLD-DELTA-10 — federation read/mark path ────────────────────────────────

/// Pool-level submission counters for the mandatory sampling rule.
#[derive(Clone, Copy, Debug, Default)]
pub struct SubmissionCounts {
    pub total_windows: u64,
    pub submitted_windows: u64,
    pub submitted_collapse: u64,
    pub submitted_non_collapse: u64,
}

/// Read the counters `federation::SamplingDecision` needs (primary 15-min
/// windows only — the falsification ladder's canonical granularity).
pub fn submission_counts(conn: &Connection) -> Result<SubmissionCounts> {
    conn.query_row(
        "SELECT COUNT(*),
                COALESCE(SUM(submitted), 0),
                COALESCE(SUM(CASE WHEN submitted = 1
                    AND (collapse_5m = 1 OR collapse_30m = 1) THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN submitted = 1
                    AND NOT (collapse_5m = 1 OR collapse_30m = 1) THEN 1 ELSE 0 END), 0)
         FROM idx_babel_windows WHERE window_secs = 900",
        [],
        |r| {
            Ok(SubmissionCounts {
                total_windows: r.get::<_, i64>(0)? as u64,
                submitted_windows: r.get::<_, i64>(1)? as u64,
                submitted_collapse: r.get::<_, i64>(2)? as u64,
                submitted_non_collapse: r.get::<_, i64>(3)? as u64,
            })
        },
    )
    .map_err(Into::into)
}

/// Reconstruct unsubmitted primary windows from their rows for the
/// federation batch. Returns `(window, is_collapse)` pairs oldest-first.
/// Only fully-stamped rows qualify (`collapse_30m IS NOT NULL`) — the pool
/// needs the 30-min label, and unripe rows would federate as unlabeled
/// noise. `b_mult_epsilon` is not stored per-row; the caller passes the
/// frozen config value so reconstructed scores carry it.
pub fn load_unsubmitted_windows(
    conn: &Connection,
    limit: usize,
    epsilon: Option<f64>,
) -> Result<Vec<(BabelWindow, bool)>> {
    use super::collapse::CollapseDetection;
    use super::feature::{BabelFeatures, FeatureAlgorithmVersions, KdPosture};
    use super::score::BabelScores;
    use super::signals::SignalPosture;
    use super::window::WindowGranularity;

    let mut stmt = conn.prepare(
        "SELECT id, session_id, window_secs, ts_start, ts_end,
                b_log, b_mult, b_bottleneck, variables,
                collapse_5m, collapse_30m, collapse_kind, negative_ctrl,
                negative_control_type
         FROM idx_babel_windows
         WHERE window_secs = 900 AND submitted = 0 AND collapse_30m IS NOT NULL
         ORDER BY ts_end ASC LIMIT ?1",
    )?;
    let rows = stmt.query_map(rusqlite::params![limit as i64], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, i64>(3)?,
            r.get::<_, i64>(4)?,
            r.get::<_, Option<f64>>(5)?,
            r.get::<_, Option<f64>>(6)?,
            r.get::<_, f64>(7)?,
            r.get::<_, String>(8)?,
            r.get::<_, Option<i64>>(9)?,
            r.get::<_, Option<i64>>(10)?,
            r.get::<_, Option<String>>(11)?,
            r.get::<_, i64>(12)?,
            r.get::<_, Option<String>>(13)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (
            id,
            session_id,
            window_secs,
            ts_start,
            ts_end,
            b_log,
            b_mult,
            b_bottleneck,
            variables,
            collapse_5m,
            collapse_30m,
            collapse_kind,
            negative_ctrl,
            negative_control_type,
        ) = row?;
        let Some(granularity) = WindowGranularity::from_secs(window_secs as u64) else {
            continue; // unknown granularity row — never ours, skip
        };
        let vars: serde_json::Value = match serde_json::from_str(&variables) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(window_id = %id, error = %e,
                    "babel federation: corrupt variables blob, window skipped");
                continue;
            }
        };
        let get = |k: &str| vars.get(k).and_then(|x| x.as_f64()).unwrap_or(0.0);
        let row_schema = vars
            .get("schema")
            .and_then(|s| s.as_str())
            .unwrap_or(BabelWindow::SCHEMA_VERSION)
            .to_string();
        let has_all_fields = |key: &str, fields: &[&str]| {
            vars.get(key)
                .and_then(serde_json::Value::as_object)
                .is_some_and(|object| fields.iter().all(|field| object.contains_key(*field)))
        };
        let k_d_posture = vars
            .get("k_d_posture")
            .cloned()
            .and_then(|value| serde_json::from_value::<KdPosture>(value).ok());
        let signal_posture = vars
            .get("signal_posture")
            .cloned()
            .and_then(|value| serde_json::from_value::<SignalPosture>(value).ok());
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
        if row_schema == BabelWindow::SCHEMA_VERSION
            && (!current_posture_complete || k_d_posture.is_none() || signal_posture.is_none())
        {
            tracing::warn!(
                window_id = %id,
                "babel federation: current-schema row has incomplete/invalid posture, skipped"
            );
            continue;
        }
        let algo = |k: &str| {
            vars.get("algo")
                .and_then(|a| a.get(k))
                .and_then(|s| s.as_str())
                .unwrap_or("unknown")
                .to_string()
        };
        let features = BabelFeatures {
            c: get("C"),
            k: get("K"),
            m: get("M"),
            a: get("A"),
            v: get("V"),
            d: get("D").max(1e-9),
            h: get("H").max(1e-9),
            k_d_posture: k_d_posture.unwrap_or_default(),
            algorithm_versions: FeatureAlgorithmVersions {
                c: algo("c"),
                k: algo("k"),
                m: algo("m"),
                a: algo("a"),
                v: algo("v"),
                d: algo("d"),
                h: algo("h"),
            },
        };
        let negative_control_type = match (negative_ctrl, negative_control_type.as_deref()) {
            (0, None) => None,
            (1, Some(value)) => match value.parse::<NegativeControlType>() {
                Ok(value) => Some(value),
                Err(error) => {
                    tracing::warn!(window_id = %id, %error,
                        "babel federation: invalid negative-control type, window skipped");
                    continue;
                }
            },
            _ => {
                tracing::warn!(window_id = %id,
                    "babel federation: inconsistent negative-control state, window skipped");
                continue;
            }
        };
        let is_collapse = collapse_5m == Some(1) || collapse_30m == Some(1);
        let window = BabelWindow {
            id,
            session_id_pseudo: session_id,
            granularity,
            ts_start,
            ts_end,
            scores: BabelScores {
                b_log,
                b_mult,
                b_mult_epsilon: b_mult.and(epsilon),
                b_mult_epsilon_rule: "0.01_median_buffer_ratio_calibration".to_string(),
                b_bottleneck,
            },
            collapse: CollapseDetection {
                collapse_within_5m: collapse_5m == Some(1),
                collapse_within_30m: collapse_30m.map(|v| v == 1),
                collapse_kind: collapse_kind.and_then(|s| s.parse().ok()),
                negative_control: negative_ctrl == 1,
                negative_control_type,
            },
            signal_posture: signal_posture.unwrap_or_default(),
            schema_version: row_schema,
            algorithm_version_c: features.algorithm_versions.c.clone(),
            algorithm_version_k: features.algorithm_versions.k.clone(),
            algorithm_version_m: features.algorithm_versions.m.clone(),
            algorithm_version_a: features.algorithm_versions.a.clone(),
            algorithm_version_v: features.algorithm_versions.v.clone(),
            algorithm_version_d: features.algorithm_versions.d.clone(),
            algorithm_version_h: features.algorithm_versions.h.clone(),
            features,
        };
        out.push((window, is_collapse));
    }
    Ok(out)
}

/// Mark a set of windows as submitted (after their batch is durably on
/// disk as a pending file — the pending file IS the submission record).
pub fn mark_submitted(conn: &Connection, ids: &[String]) -> Result<usize> {
    let mut n = 0usize;
    for id in ids {
        n += conn.execute(
            "UPDATE idx_babel_windows SET submitted = 1 WHERE id = ?1",
            rusqlite::params![id],
        )?;
    }
    Ok(n)
}

// ── GOLD-DELTA-13 — fitness read path ────────────────────────────────────────

/// Advisory verdict on a change, derived from the B_d trend around it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FitnessVerdict {
    /// Sustained lower B_d after the change, no collapse in the horizon.
    Reinforce,
    /// Higher B_d after the change OR a collapse inside the horizon.
    Flag,
    /// No decisive movement either way.
    Neutral,
}

impl FitnessVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reinforce => "reinforce",
            Self::Flag => "flag",
            Self::Neutral => "neutral",
        }
    }
}

/// B_d comparison around one change timestamp.
#[derive(Clone, Copy, Debug)]
pub struct BabelFitness {
    pub before_median: f64,
    pub after_median: f64,
    pub collapses_after: u32,
    pub windows_before: usize,
    pub windows_after: usize,
}

impl BabelFitness {
    /// ±10% median movement is the decisive band; any collapse in the
    /// horizon flags regardless of the median (a collapse is never noise).
    pub fn verdict(&self) -> FitnessVerdict {
        if self.collapses_after > 0 || self.after_median > self.before_median * 1.1 {
            FitnessVerdict::Flag
        } else if self.after_median < self.before_median * 0.9 {
            FitnessVerdict::Reinforce
        } else {
            FitnessVerdict::Neutral
        }
    }
}

fn median(values: &mut [f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mid = values.len() / 2;
    Some(if values.len().is_multiple_of(2) {
        (values[mid - 1] + values[mid]) / 2.0
    } else {
        values[mid]
    })
}

/// Compare the PRIMARY (15-min) windows around `change_ts`: median
/// `b_bottleneck` of `[change_ts - horizon, change_ts]` (by ts_end) vs
/// `[change_ts, change_ts + horizon]` (fully inside), plus the collapse
/// count after. `b_bottleneck` is the v0 fitness score — it always exists
/// (`b_log` is NULL until the K_d feed warms up, `b_mult` until epsilon
/// freezes). `Ok(None)` below 2 windows on either side — an unobservable
/// change must not produce a verdict.
pub fn babel_fitness(
    conn: &Connection,
    change_ts: i64,
    horizon_secs: i64,
) -> Result<Option<BabelFitness>> {
    let fetch = |lo: i64, hi: i64| -> Result<Vec<f64>> {
        let mut stmt = conn.prepare(
            "SELECT b_bottleneck FROM idx_babel_windows
             WHERE window_secs = 900 AND ts_end > ?1 AND ts_end <= ?2",
        )?;
        Ok(stmt
            .query_map(rusqlite::params![lo, hi], |r| r.get(0))?
            .collect::<std::result::Result<Vec<f64>, _>>()?)
    };
    let mut before = fetch(change_ts - horizon_secs, change_ts)?;
    let mut after = fetch(change_ts, change_ts + horizon_secs)?;
    if before.len() < 2 || after.len() < 2 {
        return Ok(None);
    }
    let collapses_after: u32 = conn.query_row(
        "SELECT COUNT(*) FROM idx_babel_windows
         WHERE window_secs = 900 AND ts_end > ?1 AND ts_end <= ?2
           AND (collapse_5m = 1 OR collapse_30m = 1)",
        rusqlite::params![change_ts, change_ts + horizon_secs],
        |r| r.get(0),
    )?;
    let (windows_before, windows_after) = (before.len(), after.len());
    Ok(Some(BabelFitness {
        before_median: median(&mut before).expect("len >= 2"),
        after_median: median(&mut after).expect("len >= 2"),
        collapses_after,
        windows_before,
        windows_after,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table_names(conn: &Connection) -> Vec<String> {
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'idx_babel%' ORDER BY name")
            .expect("prepare");
        stmt.query_map([], |r| r.get::<_, String>(0))
            .expect("query")
            .collect::<std::result::Result<Vec<_>, _>>()
            .expect("rows")
    }

    #[test]
    fn ensure_schema_creates_all_three_tables_and_is_idempotent() {
        let conn = Connection::open_in_memory().expect("mem db");
        ensure_schema(&conn).expect("first run");
        ensure_schema(&conn).expect("second run is a no-op");
        assert_eq!(
            table_names(&conn),
            vec!["idx_babel_labels", "idx_babel_norm", "idx_babel_windows"]
        );
    }

    #[test]
    fn ensure_schema_migrates_existing_windows_table() {
        let conn = Connection::open_in_memory().expect("mem db");
        conn.execute_batch(
            "CREATE TABLE idx_babel_windows (
                id TEXT PRIMARY KEY,
                negative_ctrl INTEGER NOT NULL DEFAULT 0
             );",
        )
        .expect("legacy table");
        ensure_schema(&conn).expect("migration");
        ensure_schema(&conn).expect("migration is idempotent");
        let mut stmt = conn
            .prepare("PRAGMA table_info(idx_babel_windows)")
            .expect("pragma");
        let columns: Vec<String> = stmt
            .query_map([], |row| row.get(1))
            .expect("query")
            .collect::<std::result::Result<_, _>>()
            .expect("columns");
        assert!(columns.iter().any(|name| name == "negative_control_type"));
    }

    #[test]
    fn windows_table_accepts_a_canonical_row() {
        let conn = Connection::open_in_memory().expect("mem db");
        ensure_schema(&conn).expect("schema");
        conn.execute(
            "INSERT INTO idx_babel_windows
             (id, session_id, window_secs, ts_start, ts_end, b_bottleneck, variables)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                "018f0000-0000-7000-8000-000000000001",
                "a1b2c3d4e5f60718",
                900_i64,
                1_800_000_000_i64,
                1_800_000_900_i64,
                0.42_f64,
                r#"{"C":0.1,"K":0.2,"M":0.3,"A":0.4,"V":0.5,"D":0.6,"H":0.7}"#,
            ],
        )
        .expect("insert");
        let submitted: i64 = conn
            .query_row("SELECT submitted FROM idx_babel_windows", [], |r| r.get(0))
            .expect("select");
        assert_eq!(submitted, 0, "federation flag defaults to not-submitted");
    }

    #[test]
    fn negative_control_tag_is_atomic_typed_and_clearable() {
        let conn = Connection::open_in_memory().expect("mem db");
        ensure_schema(&conn).expect("schema");
        conn.execute(
            "INSERT INTO idx_babel_windows
             (id, session_id, window_secs, ts_start, ts_end, b_bottleneck, variables)
             VALUES ('w1', 'a1b2c3d4e5f60718', 900, 0, 900, 0.4, '{}')",
            [],
        )
        .expect("window");

        assert!(
            persist_negative_control(&conn, "w1", Some(NegativeControlType::SyntheticStable))
                .expect("tag")
        );
        let tagged: (i64, Option<String>) = conn
            .query_row(
                "SELECT negative_ctrl, negative_control_type FROM idx_babel_windows WHERE id='w1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("tagged row");
        assert_eq!(tagged, (1, Some("synthetic_stable".to_string())));

        assert!(persist_negative_control(&conn, "w1", None).expect("clear"));
        let cleared: (i64, Option<String>) = conn
            .query_row(
                "SELECT negative_ctrl, negative_control_type FROM idx_babel_windows WHERE id='w1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("cleared row");
        assert_eq!(cleared, (0, None));
        assert!(!persist_negative_control(&conn, "missing", None).expect("missing"));
    }

    const CT: i64 = 1_800_100_000;

    fn seed_fitness_window(conn: &Connection, id: &str, ts_end: i64, b: f64, collapse: bool) {
        conn.execute(
            "INSERT INTO idx_babel_windows
             (id, session_id, window_secs, ts_start, ts_end, b_bottleneck, variables, collapse_5m)
             VALUES (?1, 'a1b2c3d4e5f60718', 900, ?2, ?3, ?4, '{}', ?5)",
            rusqlite::params![id, ts_end - 900, ts_end, b, i64::from(collapse)],
        )
        .expect("seed");
    }

    fn fitness_db(before_b: f64, after_b: f64, after_collapse: bool) -> Connection {
        let conn = Connection::open_in_memory().expect("mem db");
        ensure_schema(&conn).expect("schema");
        for i in 0..4i64 {
            seed_fitness_window(&conn, &format!("b{i}"), CT - i * 900, before_b, false);
            seed_fitness_window(
                &conn,
                &format!("a{i}"),
                CT + 900 + i * 900,
                after_b,
                after_collapse && i == 0,
            );
        }
        conn
    }

    #[test]
    fn fitness_reinforce_on_sustained_lower_b() {
        let conn = fitness_db(1.0, 0.5, false);
        let f = babel_fitness(&conn, CT, 7200)
            .expect("query")
            .expect("both sides observable");
        assert_eq!(f.verdict(), FitnessVerdict::Reinforce);
        assert!(f.after_median < f.before_median);
        assert_eq!(f.collapses_after, 0);
    }

    #[test]
    fn fitness_flag_on_higher_b_or_collapse() {
        let higher = fitness_db(0.5, 1.0, false);
        let f = babel_fitness(&higher, CT, 7200)
            .expect("query")
            .expect("observable");
        assert_eq!(f.verdict(), FitnessVerdict::Flag, "higher B_d flags");

        let collapsed = fitness_db(1.0, 0.5, true);
        let f = babel_fitness(&collapsed, CT, 7200)
            .expect("query")
            .expect("observable");
        assert_eq!(
            f.verdict(),
            FitnessVerdict::Flag,
            "a collapse flags even with lower B_d"
        );
        assert_eq!(f.collapses_after, 1);
    }

    #[test]
    fn fitness_neutral_inside_the_band_and_none_when_unobservable() {
        let flat = fitness_db(1.0, 1.0, false);
        let f = babel_fitness(&flat, CT, 7200)
            .expect("query")
            .expect("observable");
        assert_eq!(f.verdict(), FitnessVerdict::Neutral);

        let thin = Connection::open_in_memory().expect("mem db");
        ensure_schema(&thin).expect("schema");
        seed_fitness_window(&thin, "only", CT - 900, 1.0, false);
        assert!(
            babel_fitness(&thin, CT, 7200).expect("query").is_none(),
            "fewer than 2 windows per side → no verdict"
        );
    }

    #[test]
    fn labels_pk_rejects_duplicate_label_per_window() {
        let conn = Connection::open_in_memory().expect("mem db");
        ensure_schema(&conn).expect("schema");
        let ins = "INSERT INTO idx_babel_labels (window_id, label, labeled_at) VALUES (?1, ?2, ?3)";
        conn.execute(ins, rusqlite::params!["w1", "agent_loop", 1_i64])
            .expect("first");
        let dup = conn.execute(ins, rusqlite::params!["w1", "agent_loop", 2_i64]);
        assert!(dup.is_err(), "PK (window_id,label) must reject duplicates");
    }
}
