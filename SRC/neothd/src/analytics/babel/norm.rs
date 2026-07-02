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

/// Minimum samples before normalisation is considered reliable.
pub const MIN_SAMPLES: u32 = 50;

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

/// Compute the epsilon value for the multiplicative form from a slice of D*H
/// products (the calibration batch).  Pinned rule: `0.01 * median(D*H)`.
/// Returns None when the slice is empty.
pub fn compute_calibration_epsilon(dh_products: &[f64]) -> Option<f64> {
    if dh_products.is_empty() { return None; }
    let mut sorted = dh_products.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mid = sorted.len() / 2;
    let median = if sorted.len() % 2 == 0 {
        (sorted[mid - 1] + sorted[mid]) / 2.0
    } else {
        sorted[mid]
    };
    Some(0.01 * median)
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
}
