//! Per-instance normaliser for the multiplicative B_d form.
//!
//! Populated by a background task that sweeps `idx_babel_windows` every 5 min
//! (see `window::spawn_norm_refresh`).  On cold-start (fewer than 50 raw
//! samples) returns `None` from `BabelWindow::b_mult` so downstream code
//! never emits a normalised score it cannot trust.
//!
//! ## Storage
//!
//! SQLite table:
//! ```sql
//! CREATE TABLE IF NOT EXISTS idx_babel_norm (
//!     variable     TEXT NOT NULL,
//!     window_secs  INTEGER NOT NULL,
//!     p1           REAL NOT NULL,
//!     p99          REAL NOT NULL,
//!     sample_count INTEGER NOT NULL,
//!     updated_at   INTEGER NOT NULL,
//!     PRIMARY KEY (variable, window_secs)
//! );
//! ```
//!
//! ## norm_d formula
//!
//! `norm_d(x) = clamp((x - p1) / (p99 - p1 + 1e-9), 0.0, 1.0)`
//!
//! Cold-start guard: emit `b_mult = null` when `sample_count < MIN_SAMPLES`.

use anyhow::Result;
use rusqlite::Connection;

/// Minimum samples before normalisation is considered reliable.
pub const MIN_SAMPLES: u32 = 50;

/// Pseudo-variable name for the RAW multiplicative score in
/// `idx_babel_norm`. The windows table stores the NORMALISED `b_mult`, so
/// the sweep recomputes the raw ratio form from the stored feature JSON
/// (+ frozen epsilon) — that raw distribution is what the [`Normaliser`]
/// calibrates against.
pub const B_RAW_VARIABLE: &str = "b_raw";

/// A snapshot of the normalisation parameters for the multiplicative B_d form.
/// Updated by the background refresh task; read by the score computation path.
#[derive(Clone, Debug)]
pub struct Normaliser {
    pub p1: f64,
    pub p99: f64,
    pub sample_count: u32,
}

impl Normaliser {
    /// Cold-start sentinel — used when no calibration data is available yet.
    /// Score computation returns None for b_mult when this is the active state.
    pub fn cold_start() -> Self {
        Self { p1: 0.0, p99: 1.0, sample_count: 0 }
    }

    /// Whether we have enough samples to trust normalisation.
    pub fn is_calibrated(&self) -> bool {
        self.sample_count >= MIN_SAMPLES
    }

    /// Normalise a raw B_d value into [0,1].
    /// When not calibrated, the output is still computed (identity-ish stretch)
    /// but callers MUST check `is_calibrated()` before emitting to federation.
    pub fn normalise(&self, raw: f64) -> f64 {
        let range = self.p99 - self.p1 + 1e-9;
        ((raw - self.p1) / range).clamp(0.0, 1.0)
    }
}

/// Compute the epsilon value for the multiplicative form from a slice of
/// buffer-ratio products `(D/A) * (H/V)` (the calibration batch — the
/// simplified ratio form's actual denominator; upstream fix `a4bd367`).
/// Pinned rule: `0.01 * median((D/A)*(H/V))`, tag
/// `0.01_median_buffer_ratio_calibration`. Returns None when empty.
pub fn compute_calibration_epsilon(buffer_ratio_products: &[f64]) -> Option<f64> {
    if buffer_ratio_products.is_empty() { return None; }
    let mut sorted = buffer_ratio_products.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mid = sorted.len() / 2;
    let median = if sorted.len() % 2 == 0 {
        (sorted[mid - 1] + sorted[mid]) / 2.0
    } else {
        sorted[mid]
    };
    Some(0.01 * median)
}

/// Nearest-rank percentile over an unsorted slice. Empty → None.
fn percentile(values: &[f64], q: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = ((sorted.len() - 1) as f64 * q).round() as usize;
    Some(sorted[idx.min(sorted.len() - 1)])
}

/// GOLD-DELTA-05 — 7-day p1/p99 sweep for one window granularity.
///
/// Reads every window row of the last 7 days for `window_secs`, extracts the
/// seven variables from the stored JSON, and upserts one `idx_babel_norm`
/// row per variable. When `epsilon` is frozen, additionally recomputes the
/// RAW ratio-form score per row and upserts it as [`B_RAW_VARIABLE`] — the
/// calibration source for [`load_normaliser`]. Returns the number of rows
/// upserted.
pub fn sweep_norm(
    conn: &Connection,
    window_secs: u64,
    now_unix: i64,
    epsilon: Option<f64>,
) -> Result<usize> {
    const SEVEN_DAYS_SECS: i64 = 7 * 24 * 3600;
    let mut stmt = conn.prepare(
        "SELECT variables FROM idx_babel_windows
         WHERE window_secs = ?1 AND ts_end >= ?2",
    )?;
    let rows: Vec<String> = stmt
        .query_map(
            rusqlite::params![window_secs as i64, now_unix - SEVEN_DAYS_SECS],
            |r| r.get(0),
        )?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    const VARS: [&str; 7] = ["C", "K", "M", "A", "V", "D", "H"];
    let mut series: [Vec<f64>; 7] = Default::default();
    let mut b_raw: Vec<f64> = Vec::new();
    let mut parse_failures = 0usize;
    for raw in &rows {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) else {
            parse_failures += 1;
            continue;
        };
        let mut vals = [0.0f64; 7];
        let mut complete = true;
        for (i, name) in VARS.iter().enumerate() {
            match v.get(*name).and_then(|x| x.as_f64()) {
                Some(x) if x.is_finite() => {
                    vals[i] = x;
                    series[i].push(x);
                }
                _ => complete = false,
            }
        }
        if let (Some(eps), true) = (epsilon, complete) {
            // vals order mirrors VARS: C K M A V D H.
            let (c, k, m, a, vv, d, h) =
                (vals[0], vals[1], vals[2], vals[3], vals[4], vals[5], vals[6]);
            // Same preconditions as score.rs::compute — including eps > 0,
            // or a hand-edited epsilon of 0.0 pushes +Inf into the series.
            if a > 0.0 && vv > 0.0 && eps > 0.0 {
                b_raw.push((c * k * m) / ((d / a) * (h / vv) + eps));
            }
        }
    }
    if parse_failures > 0 {
        tracing::warn!(
            skipped = parse_failures,
            window_secs,
            "babel sweep: rows skipped due to variables-JSON parse failure"
        );
    }

    let mut upserts = 0usize;
    let mut upsert = |variable: &str, values: &[f64]| -> Result<()> {
        let (Some(p1), Some(p99)) = (percentile(values, 0.01), percentile(values, 0.99)) else {
            // Empty 7-day series: a stale row from an earlier sweep would keep
            // passing is_calibrated() forever — delete it so readers fall back
            // to cold-start semantics.
            conn.execute(
                "DELETE FROM idx_babel_norm WHERE variable = ?1 AND window_secs = ?2",
                rusqlite::params![variable, window_secs as i64],
            )?;
            return Ok(());
        };
        conn.execute(
            "INSERT INTO idx_babel_norm (variable, window_secs, p1, p99, sample_count, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (variable, window_secs) DO UPDATE SET
               p1 = excluded.p1, p99 = excluded.p99,
               sample_count = excluded.sample_count, updated_at = excluded.updated_at",
            rusqlite::params![variable, window_secs as i64, p1, p99, values.len() as i64, now_unix],
        )?;
        upserts += 1;
        Ok(())
    };
    for (i, name) in VARS.iter().enumerate() {
        upsert(name, &series[i])?;
    }
    upsert(B_RAW_VARIABLE, &b_raw)?;
    Ok(upserts)
}

/// GOLD-DELTA-06 — compute the calibration epsilon from stored windows.
///
/// Reads every window of `window_secs`, computes the buffer-ratio product
/// `(D/A) * (H/V)` per row and applies the pre-registered rule
/// `0.01 * median` ([`compute_calibration_epsilon`]). Returns `None` until
/// at least `min_samples` usable rows exist — the freeze must not happen on
/// a cold instance. Deterministic over the same row set (idempotent).
pub fn calibration_epsilon_from_db(
    conn: &Connection,
    window_secs: u64,
    min_samples: u32,
) -> Result<Option<f64>> {
    let mut stmt = conn.prepare(
        "SELECT variables FROM idx_babel_windows WHERE window_secs = ?1 ORDER BY ts_end ASC",
    )?;
    let rows: Vec<String> = stmt
        .query_map(rusqlite::params![window_secs as i64], |r| r.get(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let products: Vec<f64> = rows
        .iter()
        .filter_map(|raw| {
            let v = serde_json::from_str::<serde_json::Value>(raw).ok()?;
            let get = |k: &str| v.get(k).and_then(|x| x.as_f64()).filter(|x| x.is_finite());
            let (a, vv, d, h) = (get("A")?, get("V")?, get("D")?, get("H")?);
            (a > 0.0 && vv > 0.0).then(|| (d / a) * (h / vv))
        })
        .filter(|p| p.is_finite())
        .collect();
    if products.len() < min_samples as usize {
        return Ok(None);
    }
    Ok(compute_calibration_epsilon(&products))
}

/// Load the [`B_RAW_VARIABLE`] snapshot for a granularity as a
/// [`Normaliser`]. `Ok(None)` when the sweep hasn't produced one yet;
/// a real read failure is an `Err` — conflating it with "not yet
/// calibrated" would freeze the caller's normaliser silently.
pub fn load_normaliser(conn: &Connection, window_secs: u64) -> Result<Option<Normaliser>> {
    match conn.query_row(
        "SELECT p1, p99, sample_count FROM idx_babel_norm
         WHERE variable = ?1 AND window_secs = ?2",
        rusqlite::params![B_RAW_VARIABLE, window_secs as i64],
        |r| {
            Ok(Normaliser {
                p1: r.get(0)?,
                p99: r.get(1)?,
                sample_count: r.get::<_, i64>(2)? as u32,
            })
        },
    ) {
        Ok(n) => Ok(Some(n)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cold_start_is_not_calibrated() {
        let n = Normaliser::cold_start();
        assert!(!n.is_calibrated());
    }

    #[test]
    fn normalise_clamps_to_unit_interval() {
        let n = Normaliser { p1: 1.0, p99: 10.0, sample_count: 100 };
        assert_eq!(n.normalise(-5.0), 0.0);
        assert_eq!(n.normalise(100.0), 1.0);
        let mid = n.normalise(5.5);
        assert!(mid > 0.0 && mid < 1.0);
    }

    #[test]
    fn epsilon_is_one_percent_of_median() {
        let dh = vec![0.1, 0.2, 0.3, 0.4, 0.5];
        // median = 0.3
        let eps = compute_calibration_epsilon(&dh).unwrap();
        assert!((eps - 0.003).abs() < 1e-9);
    }

    #[test]
    fn epsilon_returns_none_for_empty_slice() {
        assert!(compute_calibration_epsilon(&[]).is_none());
    }

    const NOW: i64 = 1_800_000_000;

    fn seeded_db(n: usize) -> Connection {
        let conn = Connection::open_in_memory().expect("mem db");
        super::super::store::ensure_schema(&conn).expect("schema");
        for i in 0..n {
            // V climbs 0.01, 0.02, … — the p99 of 60 rows (nearest rank,
            // idx round(59*0.99)=58) is the 59th value = 0.59.
            let v = (i + 1) as f64 / 100.0;
            let vars = serde_json::json!({
                "C": 0.5, "K": 0.5, "M": 0.5, "A": 0.5, "V": v, "D": 1.0, "H": 1.0,
            });
            conn.execute(
                "INSERT INTO idx_babel_windows
                 (id, session_id, window_secs, ts_start, ts_end, b_bottleneck, variables)
                 VALUES (?1, ?2, 900, ?3, ?4, 0.5, ?5)",
                rusqlite::params![
                    format!("w{i}"),
                    "a1b2c3d4e5f60718",
                    NOW - 1000 - i as i64,
                    NOW - 900 - i as i64,
                    vars.to_string(),
                ],
            )
            .expect("insert");
        }
        conn
    }

    #[test]
    fn sweep_p99_within_two_percent_for_variable_v() {
        let conn = seeded_db(60);
        let n = sweep_norm(&conn, 900, NOW, None).expect("sweep");
        assert_eq!(n, 7, "7 variables upserted, no b_raw without epsilon");
        let (p1, p99, count): (f64, f64, i64) = conn
            .query_row(
                "SELECT p1, p99, sample_count FROM idx_babel_norm
                 WHERE variable = 'V' AND window_secs = 900",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .expect("row");
        assert_eq!(count, 60);
        assert!((p99 - 0.59).abs() / 0.59 < 0.02, "p99 {p99} within 2% of 0.59");
        assert!(p1 <= 0.02, "p1 {p1} near the bottom of the series");
    }

    #[test]
    fn sweep_with_epsilon_produces_loadable_normaliser() {
        let conn = seeded_db(60);
        let n = sweep_norm(&conn, 900, NOW, Some(0.01)).expect("sweep");
        assert_eq!(n, 8, "7 variables + b_raw");
        let norm = load_normaliser(&conn, 900).expect("query ok").expect("b_raw row present");
        assert_eq!(norm.sample_count, 60);
        assert!(norm.is_calibrated());
        assert!(norm.p99 > norm.p1);
        // Sweep twice — upsert, not duplicate.
        sweep_norm(&conn, 900, NOW, Some(0.01)).expect("second sweep");
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM idx_babel_norm", [], |r| r.get(0))
            .expect("count");
        assert_eq!(rows, 8);
    }

    #[test]
    fn sweep_ignores_windows_older_than_seven_days() {
        let conn = seeded_db(10);
        // One ancient row that must not enter the percentile series.
        conn.execute(
            "INSERT INTO idx_babel_windows
             (id, session_id, window_secs, ts_start, ts_end, b_bottleneck, variables)
             VALUES ('old', 'a1b2c3d4e5f60718', 900, 0, 1000, 0.5, ?1)",
            rusqlite::params![
                serde_json::json!({"C":0.5,"K":0.5,"M":0.5,"A":0.5,"V":99.0,"D":1.0,"H":1.0})
                    .to_string()
            ],
        )
        .expect("insert old");
        sweep_norm(&conn, 900, NOW, None).expect("sweep");
        let p99: f64 = conn
            .query_row(
                "SELECT p99 FROM idx_babel_norm WHERE variable = 'V' AND window_secs = 900",
                [],
                |r| r.get(0),
            )
            .expect("row");
        assert!(p99 < 1.0, "stale 99.0 outlier excluded, got {p99}");
    }

    #[test]
    fn load_normaliser_none_before_any_sweep() {
        let conn = Connection::open_in_memory().expect("mem db");
        super::super::store::ensure_schema(&conn).expect("schema");
        assert!(load_normaliser(&conn, 900).expect("query ok").is_none());
    }

    #[test]
    fn calibration_epsilon_none_below_min_samples_then_freezes_idempotently() {
        let conn = seeded_db(10);
        assert!(
            calibration_epsilon_from_db(&conn, 900, MIN_SAMPLES)
                .expect("query ok")
                .is_none(),
            "10 rows < MIN_SAMPLES → no freeze"
        );
        let conn = seeded_db(60);
        let eps = calibration_epsilon_from_db(&conn, 900, MIN_SAMPLES)
            .expect("query ok")
            .expect("60 rows → calibrated");
        assert!(eps > 0.0 && eps < 0.1, "eps {eps} in (0, 0.1)");
        let again = calibration_epsilon_from_db(&conn, 900, MIN_SAMPLES)
            .expect("query ok")
            .expect("still calibrated");
        assert_eq!(eps, again, "same rows → same epsilon (idempotent)");
    }
}
