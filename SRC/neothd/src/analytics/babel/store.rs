//! GOLD-DELTA-02 — SQLite persistence schema for the Babel-Index observer.
//!
//! Babel output lives in SQLite ONLY (the WAL event byte space is exhausted,
//! 255/256 — verified 2026-07-02; see the WS-DELTA tracker section). Three
//! tables on the operator's `views.db`:
//!
//! - `idx_babel_windows` — one row per closed window (canonical DDL mirrors
//!   the doc block in `window.rs`).
//! - `idx_babel_norm`    — p1/p99 normalisation snapshots per (variable,
//!   window_secs), swept every 5 min (doc block in `norm.rs`).
//! - `idx_babel_labels`  — collapse labels per window, from the post-hoc
//!   detector pass or operator CLI labelling (`human_confirmed = 1`).
//!
//! `ensure_schema` is idempotent (CREATE TABLE IF NOT EXISTS) and is called
//! once by the daemon cron at spawn (GOLD-DELTA-04).

use anyhow::Result;
use rusqlite::Connection;

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
        "schema": w.schema_version,
    });
    conn.execute(
        "INSERT INTO idx_babel_windows
         (id, session_id, window_secs, ts_start, ts_end,
          b_log, b_mult, b_bottleneck, variables,
          collapse_5m, collapse_30m, collapse_kind, negative_ctrl)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
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
            w.collapse.collapse_kind.map(super::collapse::CollapseLabel::as_str),
            i64::from(w.collapse.negative_control),
        ],
    )?;
    Ok(())
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
    fn labels_pk_rejects_duplicate_label_per_window() {
        let conn = Connection::open_in_memory().expect("mem db");
        ensure_schema(&conn).expect("schema");
        let ins = "INSERT INTO idx_babel_labels (window_id, label, labeled_at) VALUES (?1, ?2, ?3)";
        conn.execute(ins, rusqlite::params!["w1", "agent_loop", 1_i64]).expect("first");
        let dup = conn.execute(ins, rusqlite::params!["w1", "agent_loop", 2_i64]);
        assert!(dup.is_err(), "PK (window_id,label) must reject duplicates");
    }
}
