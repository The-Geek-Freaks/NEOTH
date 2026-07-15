//! Rolling-window aggregation for the Babel Index.
//!
//! Three parallel window granularities run simultaneously:
//!   - 5 min  (300 s)  — real-time alert, high FP tolerance
//!   - 15 min (900 s)  — action trigger, lower FP, PRIMARY for M1 rule and ML label
//!   - 60 min (3600 s) — trend / report
//!   - 30 min (1800 s) — secondary horizon for multi-horizon label schema
//!
//! The 15-minute window is the canonical falsification horizon (primary label).
//! The 5-minute window is the secondary operational alert.
//!
//! ## SQLite persistence
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS idx_babel_windows (
//!     id           TEXT PRIMARY KEY,        -- UUID v7
//!     session_id   TEXT NOT NULL,           -- pseudonymised (16 hex)
//!     window_secs  INTEGER NOT NULL,        -- 300 / 900 / 1800 / 3600
//!     ts_start     INTEGER NOT NULL,        -- unix epoch seconds
//!     ts_end       INTEGER NOT NULL,
//!     b_log        REAL,                    -- NULL when any numerator = 0
//!     b_mult       REAL,                    -- NULL when not calibrated
//!     b_bottleneck REAL NOT NULL,
//!     variables    TEXT NOT NULL,           -- JSON: {C,K,M,A,V,D,H}
//!     collapse_5m  INTEGER,                 -- 0/1/NULL
//!     collapse_30m INTEGER,                 -- 0/1/NULL
//!     collapse_kind TEXT,
//!     negative_ctrl INTEGER NOT NULL DEFAULT 0,
//!     submitted    INTEGER NOT NULL DEFAULT 0  -- federation submission flag
//! );
//! ```
//!
//! ## Norm refresh
//!
//! A background task calls `spawn_norm_refresh` every 5 min; it recomputes the
//! raw multiplicative score from `idx_babel_windows` and updates the consumed
//! `b_raw` distribution in `idx_babel_norm`.

use serde::{Deserialize, Serialize};

use super::collapse::CollapseDetection;
use super::feature::BabelFeatures;
use super::score::BabelScores;
use super::signals::SignalPosture;

/// Canonical window granularities.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowGranularity {
    /// 300 s — real-time alert.
    FiveMin,
    /// 900 s — primary falsification horizon.
    FifteenMin,
    /// 1800 s — multi-horizon secondary label.
    ThirtyMin,
    /// 3600 s — trend / report.
    SixtyMin,
}

impl WindowGranularity {
    pub fn secs(self) -> u64 {
        match self {
            Self::FiveMin => 300,
            Self::FifteenMin => 900,
            Self::ThirtyMin => 1800,
            Self::SixtyMin => 3600,
        }
    }

    /// Inverse of [`Self::secs`] — used when reconstructing windows from
    /// their SQLite rows (GOLD-DELTA-10 federation path).
    pub fn from_secs(secs: u64) -> Option<Self> {
        match secs {
            300 => Some(Self::FiveMin),
            900 => Some(Self::FifteenMin),
            1800 => Some(Self::ThirtyMin),
            3600 => Some(Self::SixtyMin),
            _ => None,
        }
    }

    pub fn all() -> &'static [WindowGranularity] {
        &[
            WindowGranularity::FiveMin,
            WindowGranularity::FifteenMin,
            WindowGranularity::ThirtyMin,
            WindowGranularity::SixtyMin,
        ]
    }
}

/// One complete, closed rolling window ready for storage and optionally
/// for federation submission.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BabelWindow {
    /// UUID v7 — globally unique window identifier (pseudonymised before federation).
    pub id: String,
    /// Pseudonymised session id (16 hex chars).
    pub session_id_pseudo: String,
    pub granularity: WindowGranularity,
    pub ts_start: i64,
    pub ts_end: i64,
    pub features: BabelFeatures,
    pub scores: BabelScores,
    pub collapse: CollapseDetection,
    /// Optional-source posture and content-free counts. This is intentionally
    /// outside the seven score variables.
    pub signal_posture: SignalPosture,
    /// Schema version of this record format — pin for compatibility checks.
    pub schema_version: String,
    /// Algorithm version map so sensitivity analysis is possible.
    pub algorithm_version_c: String,
    pub algorithm_version_k: String,
    pub algorithm_version_m: String,
    pub algorithm_version_a: String,
    pub algorithm_version_v: String,
    pub algorithm_version_d: String,
    pub algorithm_version_h: String,
}

impl BabelWindow {
    pub const SCHEMA_VERSION: &'static str = "neoth-babel-window/0.4.0";

    pub fn duration_secs(&self) -> i64 {
        self.ts_end.saturating_sub(self.ts_start)
    }
}

/// Pending window accumulator — collects events until the window closes.
pub struct WindowAccumulator {
    pub granularity: WindowGranularity,
    pub ts_start: i64,
    pub event_count: usize,
}

impl WindowAccumulator {
    pub fn new(granularity: WindowGranularity, ts_start: i64) -> Self {
        Self {
            granularity,
            ts_start,
            event_count: 0,
        }
    }

    pub fn deadline(&self) -> i64 {
        self.ts_start + self.granularity.secs() as i64
    }

    pub fn is_expired(&self, now: i64) -> bool {
        now >= self.deadline()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn granularity_secs_correct() {
        assert_eq!(WindowGranularity::FiveMin.secs(), 300);
        assert_eq!(WindowGranularity::FifteenMin.secs(), 900);
        assert_eq!(WindowGranularity::ThirtyMin.secs(), 1800);
        assert_eq!(WindowGranularity::SixtyMin.secs(), 3600);
    }

    #[test]
    fn all_granularities_have_four_entries() {
        assert_eq!(WindowGranularity::all().len(), 4);
    }

    #[test]
    fn accumulator_deadline_matches_granularity() {
        let acc = WindowAccumulator::new(WindowGranularity::FiveMin, 1000);
        assert_eq!(acc.deadline(), 1300);
        assert!(!acc.is_expired(1299));
        assert!(acc.is_expired(1300));
    }
}
