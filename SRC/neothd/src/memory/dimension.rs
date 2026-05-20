//! Memory dimension estimator — EXP-FD-0 from `PLAN/FRACTAL_DIMENSION.md`.
//!
//! Operator question: is NEOTH's 4-tier memory actually self-similar
//! (D_mem measurable as a stable log-log slope), or is it just a
//! plain 4-level hierarchy where the "fractal" framing would be
//! marketing?
//!
//! This module computes the box-count signal: total byte count per
//! tier, log-log regressed against the tier index. If the residual is
//! small (`R² > 0.95`), the slope is the operator's `D_mem`. If the
//! residual is high, the tiers don't show measurable self-similarity
//! — the operator gets that finding back instead of a misleading
//! number, so the broader fractal-experiment chain (EXP-FD-1..5)
//! stays gated on real evidence.

use anyhow::{Context, Result};
use rusqlite::Connection;

/// One row of the per-tier measurement table.
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct TierMeasurement {
    pub tier: &'static str,
    pub row_count: i64,
    pub total_bytes: i64,
}

/// Full output of the estimator. `d_mem` is meaningful only when
/// `r_squared >= 0.95`; otherwise the operator should treat the
/// memory as plain-hierarchical, not fractal.
#[derive(Clone, Debug, serde::Serialize)]
pub struct DimensionReport {
    pub tiers: Vec<TierMeasurement>,
    pub d_mem: Option<f64>,
    pub r_squared: Option<f64>,
    pub honest_verdict: &'static str,
}

/// Compute `D_mem` from the four SQLite-backed memory tiers. Returns
/// the table + the regressed slope when at least three tiers carry
/// non-zero bytes (two-point regression is degenerate by definition).
pub fn estimate(conn: &Connection) -> Result<DimensionReport> {
    let tiers = vec![
        measure_tier(conn, "hot", "idx_episode")?,
        measure_tier(conn, "warm", "idx_consolidated")?,
        measure_tier(conn, "long", "idx_longterm")?,
        measure_tier(conn, "ground", "idx_groundtruth")?,
    ];

    // Collect the (index, log(bytes)) points where bytes > 0. Tiers
    // with zero bytes can't contribute to a log-log fit — we'd be
    // taking log(0). At least 3 non-zero points needed for a
    // meaningful slope.
    let mut xs: Vec<f64> = Vec::new();
    let mut ys: Vec<f64> = Vec::new();
    for (i, t) in tiers.iter().enumerate() {
        if t.total_bytes > 0 {
            xs.push(i as f64);
            ys.push((t.total_bytes as f64).ln());
        }
    }
    if xs.len() < 3 {
        return Ok(DimensionReport {
            tiers,
            d_mem: None,
            r_squared: None,
            honest_verdict: "Not enough non-empty tiers to fit a slope. Seed more conversations + run \
                 a consolidation pass first.",
        });
    }
    let (slope, r_squared) = linear_regression(&xs, &ys);
    let verdict = if r_squared >= 0.95 {
        "Slope is stable — D_mem is meaningful. EXP-FD-1..5 may proceed against this value."
    } else if r_squared >= 0.80 {
        "Slope is approximate. Treat D_mem as a hint, not a measurement. Re-run after \
         the next consolidation pass."
    } else {
        "Slope is unstable — the tiers don't show self-similarity. Treat memory as plain \
         hierarchical, NOT fractal. Do NOT ship features that depend on D_mem."
    };
    Ok(DimensionReport {
        tiers,
        d_mem: Some(-slope),
        r_squared: Some(r_squared),
        honest_verdict: verdict,
    })
}

fn measure_tier(conn: &Connection, label: &'static str, table: &str) -> Result<TierMeasurement> {
    // SQLite `LENGTH(text)` counts UTF-8 bytes for TEXT columns.
    // Sum across rows is the proxy for "total bytes the tier holds".
    let text_col = match table {
        "idx_groundtruth" => "statement",
        _ => "text",
    };
    let sql = format!("SELECT COUNT(*), COALESCE(SUM(LENGTH({text_col})), 0) FROM {table}");
    let (row_count, total_bytes): (i64, i64) = conn
        .query_row(&sql, [], |r| Ok((r.get(0)?, r.get(1)?)))
        .with_context(|| format!("measure tier {label}"))?;
    Ok(TierMeasurement {
        tier: label,
        row_count,
        total_bytes,
    })
}

/// Two-pass least-squares linear regression. Returns `(slope, R²)`.
/// We log the byte counts before passing in, so a stable slope on a
/// log-log scale corresponds to a power-law relationship between
/// tier index and content size — i.e., self-similarity.
fn linear_regression(xs: &[f64], ys: &[f64]) -> (f64, f64) {
    let n = xs.len() as f64;
    if n == 0.0 {
        return (0.0, 0.0);
    }
    let sum_x: f64 = xs.iter().sum();
    let sum_y: f64 = ys.iter().sum();
    let mean_x = sum_x / n;
    let mean_y = sum_y / n;
    let mut num = 0.0;
    let mut denom = 0.0;
    for i in 0..xs.len() {
        let dx = xs[i] - mean_x;
        num += dx * (ys[i] - mean_y);
        denom += dx * dx;
    }
    if denom == 0.0 {
        return (0.0, 0.0);
    }
    let slope = num / denom;
    let intercept = mean_y - slope * mean_x;
    // R² = 1 - SSres/SStot.
    let mut ss_res = 0.0;
    let mut ss_tot = 0.0;
    for i in 0..xs.len() {
        let predicted = slope * xs[i] + intercept;
        let residual = ys[i] - predicted;
        ss_res += residual * residual;
        let dy = ys[i] - mean_y;
        ss_tot += dy * dy;
    }
    let r_squared = if ss_tot == 0.0 {
        1.0
    } else {
        1.0 - ss_res / ss_tot
    };
    (slope, r_squared)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::store;

    fn seed_db() -> Connection {
        let temp = tempfile::tempdir().unwrap();
        let temp_db = temp.path().join("seed.db");
        let conn = store::open(&temp_db).unwrap();
        std::mem::forget(temp);
        conn
    }

    #[test]
    fn linear_regression_perfect_slope_returns_r_squared_one() {
        let xs = vec![0.0, 1.0, 2.0, 3.0];
        let ys = vec![1.0, 2.0, 3.0, 4.0];
        let (slope, r2) = linear_regression(&xs, &ys);
        assert!((slope - 1.0).abs() < 1e-9);
        assert!((r2 - 1.0).abs() < 1e-9);
    }

    #[test]
    fn linear_regression_constant_y_returns_zero_slope() {
        let xs = vec![0.0, 1.0, 2.0];
        let ys = vec![5.0, 5.0, 5.0];
        let (slope, _) = linear_regression(&xs, &ys);
        assert!(slope.abs() < 1e-9);
    }

    #[test]
    fn estimate_empty_db_reports_insufficient_data() {
        let conn = seed_db();
        let report = estimate(&conn).expect("estimate ok");
        assert!(report.d_mem.is_none());
        assert!(report.honest_verdict.contains("Not enough"));
    }

    #[test]
    fn estimate_three_tiers_with_data_produces_slope() {
        let conn = seed_db();
        // Plant rows with decreasing total bytes per tier so the
        // regression has something to chew on. Hot >> warm >> long.
        conn.execute(
            "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash, importance, last_access_ts) \
             VALUES (1, 1, 1, ?1, 'h', 0.5, 0), (2, 1, 2, ?2, 'h', 0.5, 0), (3, 1, 3, ?3, 'h', 0.5, 0)",
            rusqlite::params!["x".repeat(1000), "x".repeat(1000), "x".repeat(1000)],
        ).unwrap();
        conn.execute(
            "INSERT INTO idx_consolidated (kind, day, text, text_hash, importance, consolidated_ts, last_access_ts) \
             VALUES ('summary', '2026-05-01', ?1, 'h', 0.5, 1, 0), ('retained', '2026-05-01', ?2, 'h', 0.5, 1, 0)",
            rusqlite::params!["y".repeat(400), "y".repeat(400)],
        ).unwrap();
        conn.execute(
            "INSERT INTO idx_longterm (event_id, text, text_hash, importance, promoted_ts, last_access_ts) \
             VALUES (10, ?1, 'h', 0.9, 0, 0)",
            rusqlite::params!["z".repeat(80)],
        ).unwrap();
        let report = estimate(&conn).expect("estimate ok");
        // Three tiers with data — slope should be defined.
        assert!(report.d_mem.is_some());
        let d = report.d_mem.unwrap();
        // Bytes decrease across tiers (hot > warm > long), so log decreases
        // → slope is negative → reported D_mem (= -slope) is positive.
        assert!(d > 0.0, "expected positive D_mem, got {d}");
    }
}
