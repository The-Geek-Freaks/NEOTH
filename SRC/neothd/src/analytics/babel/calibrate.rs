//! GOLD-DELTA-15 — prediction self-calibration.
//!
//! Tracks whether `b_mult >= threshold` actually preceded a collapse
//! within the 30-minute horizon, and nudges the WORKING threshold with a
//! simple online rule: a false positive raises it one step, a false
//! negative lowers it one step (correct predictions leave it alone). The
//! Brier score of each round is reported so the improvement is
//! measurable, not just claimed.
//!
//! Firewall: the adjustment is applied to the daemon's IN-MEMORY working
//! threshold only and every change is logged. `babel.threshold` in
//! `freedom.yaml` stays the operator's anchor — auto-rewriting an
//! operator-tunable would cross the advisory line. A restart returns to
//! the anchor and re-learns from fresh stamped windows.

use anyhow::Result;
use rusqlite::Connection;

/// Per-step threshold movement. Small on purpose: the signal arrives one
/// stamped window at a time and the rule must not oscillate.
pub const CALIBRATION_STEP: f64 = 0.01;
/// Working-threshold clamp — the rule may never walk the threshold into
/// "always fire" or "never fire" territory.
pub const THRESHOLD_MIN: f64 = 0.05;
pub const THRESHOLD_MAX: f64 = 0.95;

/// Outcome of one calibration round.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CalibrationRound {
    /// Stamped windows evaluated this round.
    pub evaluated: usize,
    /// Predicted collapse, none occurred.
    pub false_positives: usize,
    /// Collapse occurred, not predicted.
    pub false_negatives: usize,
    /// Brier score of `b_mult` as a collapse probability over the round
    /// (lower is better; 0.25 = coin flip on a balanced set).
    pub brier: f64,
    /// The adjusted working threshold.
    pub new_threshold: f64,
    /// Highest `ts_end` evaluated — the caller's next `since_ts` cursor.
    pub cursor_ts: i64,
}

/// Evaluate every 15-min window stamped since `since_ts` that carries a
/// `b_mult` score, against the current working `threshold`. Returns
/// `Ok(None)` when there is nothing new to evaluate.
pub fn calibrate_round(
    conn: &Connection,
    threshold: f64,
    since_ts: i64,
) -> Result<Option<CalibrationRound>> {
    let mut stmt = conn.prepare(
        "SELECT b_mult, collapse_30m, ts_end FROM idx_babel_windows
         WHERE window_secs = 900 AND collapse_30m IS NOT NULL
           AND b_mult IS NOT NULL AND ts_end > ?1
         ORDER BY ts_end ASC",
    )?;
    let rows: Vec<(f64, i64, i64)> = stmt
        .query_map(rusqlite::params![since_ts], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if rows.is_empty() {
        return Ok(None);
    }

    let mut t = threshold;
    let (mut fp, mut fn_) = (0usize, 0usize);
    let mut brier_sum = 0.0f64;
    let mut cursor_ts = since_ts;
    for (b_mult, collapse, ts_end) in &rows {
        let outcome = *collapse == 1;
        let predicted = *b_mult >= t;
        match (predicted, outcome) {
            (true, false) => {
                fp += 1;
                t = (t + CALIBRATION_STEP).min(THRESHOLD_MAX);
            }
            (false, true) => {
                fn_ += 1;
                t = (t - CALIBRATION_STEP).max(THRESHOLD_MIN);
            }
            _ => {}
        }
        let outcome_f = if outcome { 1.0 } else { 0.0 };
        brier_sum += (b_mult - outcome_f).powi(2);
        cursor_ts = cursor_ts.max(*ts_end);
    }

    Ok(Some(CalibrationRound {
        evaluated: rows.len(),
        false_positives: fp,
        false_negatives: fn_,
        brier: brier_sum / rows.len() as f64,
        new_threshold: t,
        cursor_ts,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analytics::babel::store::ensure_schema;

    const T: i64 = 1_800_200_000;

    fn seed(conn: &Connection, id: &str, ts_end: i64, b_mult: f64, collapse_30m: i64) {
        conn.execute(
            "INSERT INTO idx_babel_windows
             (id, session_id, window_secs, ts_start, ts_end, b_mult, b_bottleneck,
              variables, collapse_30m)
             VALUES (?1, 'a1b2c3d4e5f60718', 900, ?2, ?3, ?4, 0.5, '{}', ?5)",
            rusqlite::params![id, ts_end - 900, ts_end, b_mult, collapse_30m],
        )
        .expect("seed");
    }

    fn db() -> Connection {
        let conn = Connection::open_in_memory().expect("mem db");
        ensure_schema(&conn).expect("schema");
        conn
    }

    #[test]
    fn false_positives_raise_and_false_negatives_lower_the_threshold() {
        // Two loud false positives: high b_mult, no collapse.
        let conn = db();
        seed(&conn, "w1", T, 0.9, 0);
        seed(&conn, "w2", T + 900, 0.9, 0);
        let r = calibrate_round(&conn, 0.8, 0).expect("query").expect("rows");
        assert_eq!(r.false_positives, 2);
        assert_eq!(r.false_negatives, 0);
        assert!((r.new_threshold - 0.82).abs() < 1e-9, "0.8 + 2 steps up");
        assert_eq!(r.cursor_ts, T + 900);

        // Two misses: collapse with b_mult below the threshold.
        let conn = db();
        seed(&conn, "w1", T, 0.2, 1);
        seed(&conn, "w2", T + 900, 0.2, 1);
        let r = calibrate_round(&conn, 0.8, 0).expect("query").expect("rows");
        assert_eq!(r.false_negatives, 2);
        assert!((r.new_threshold - 0.78).abs() < 1e-9, "0.8 - 2 steps down");
    }

    #[test]
    fn correct_predictions_leave_threshold_alone_and_brier_is_computed() {
        let conn = db();
        seed(&conn, "hit", T, 0.9, 1); // predicted + collapsed
        seed(&conn, "pass", T + 900, 0.1, 0); // not predicted + clean
        let r = calibrate_round(&conn, 0.8, 0).expect("query").expect("rows");
        assert_eq!(r.false_positives, 0);
        assert_eq!(r.false_negatives, 0);
        assert!((r.new_threshold - 0.8).abs() < 1e-9, "no movement");
        // Brier: ((0.9-1)^2 + (0.1-0)^2) / 2 = 0.01
        assert!((r.brier - 0.01).abs() < 1e-9);
    }

    #[test]
    fn round_is_none_without_new_stamped_windows_and_clamps_hold() {
        let conn = db();
        assert!(calibrate_round(&conn, 0.8, 0).expect("query").is_none(), "empty db");
        seed(&conn, "w1", T, 0.9, 0);
        assert!(
            calibrate_round(&conn, 0.8, T).expect("query").is_none(),
            "cursor at ts_end excludes the row"
        );
        // Clamp: threshold near the ceiling can't exceed THRESHOLD_MAX.
        let conn = db();
        for i in 0..10i64 {
            seed(&conn, &format!("w{i}"), T + i * 900, 0.99, 0);
        }
        let r = calibrate_round(&conn, 0.94, 0).expect("query").expect("rows");
        assert!(r.new_threshold <= THRESHOLD_MAX + 1e-12);
    }
}
