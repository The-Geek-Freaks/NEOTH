//! REPOW-03 — Change-risk model combining ownership and churn.
//!
//! ## Risk formula
//!
//! `change_risk(ownership, churn_commits)` returns a logistic score
//! in [0, 1] computed as:
//!
//! ```text
//! ownership_risk  = (1.0 - primary_share) * (1.0 / bus_factor.max(1) as f64)
//! churn_raw       = ln(churn_commits as f64 + 1.0) / ln(CHURN_CAP + 1.0)
//! churn_risk      = churn_raw.clamp(0.0, 1.0)
//! combined        = WEIGHT_OWN * ownership_risk + WEIGHT_CHURN * churn_risk
//! score           = 1.0 / (1.0 + exp(-STEEPNESS * (combined - MIDPOINT)))
//! ```
//!
//! ### Coefficient rationale
//!
//! * `WEIGHT_OWN = 0.55` — ownership risk is the primary signal: a file
//!   known only to one person (bus_factor=1, primary_share≈1) is
//!   paradoxically low-ownership-risk on the primary_share axis but
//!   very high bus-factor risk.  The combined term `(1 - share) *
//!   (1 / bus_factor)` is highest when a single author owns a large
//!   share AND bus_factor is 1 (sole owner). We weight it slightly
//!   more than churn because team knowledge gaps outlive file churn.
//! * `WEIGHT_CHURN = 0.45` — churn is log-dampened (a 1000-commit file
//!   is not 1000× riskier than a 10-commit file) so a lower weight
//!   keeps the signal proportional.
//! * `CHURN_CAP = 200.0` — normalises ln-churn to [0, 1] for a 200-
//!   commit ceiling; files beyond that saturate at 1.0.
//! * `STEEPNESS = 6.0`, `MIDPOINT = 0.5` — centres the logistic curve
//!   so a "perfectly risky" combined input (1.0) maps to ≈0.98 and a
//!   "no risk" input (0.0) maps to ≈0.02.

use serde::{Deserialize, Serialize};

use super::ownership::FileOwnership;

// ---------------------------------------------------------------------------
// Tuning constants (see module-level comment for rationale)
// ---------------------------------------------------------------------------

const WEIGHT_OWN: f64 = 0.55;
const WEIGHT_CHURN: f64 = 0.45;
const CHURN_CAP: f64 = 200.0;
const STEEPNESS: f64 = 6.0;
const MIDPOINT: f64 = 0.5;

/// A file path paired with its risk score.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FileRisk {
    pub path: String,
    pub score: f64,
}

/// Compute a change-risk score in `[0, 1]` for a single file.
///
/// * `ownership` — the `FileOwnership` produced by `ownership::file_ownership`.
/// * `churn_commits` — total commit count for the file (can be
///   `ownership.total_commits` or an independently computed window).
pub fn change_risk(ownership: &FileOwnership, churn_commits: u32) -> f64 {
    // Ownership risk: (1 - primary_share) * (1 / bus_factor).
    // A sole owner (primary_share≈1, bus_factor=1) → ownership_risk≈0.
    // A shared but fragile file (primary_share=0.3, bus_factor=1) → 0.7.
    // A well-distributed file (primary_share=0.3, bus_factor=4) → 0.175.
    let bus = ownership.bus_factor.max(1) as f64;
    let ownership_risk = (1.0 - ownership.primary_share) * (1.0 / bus);

    // Churn risk: log-dampened, capped at CHURN_CAP.
    let churn_norm =
        (churn_commits as f64 + 1.0).ln() / (CHURN_CAP + 1.0).ln();
    let churn_risk = churn_norm.clamp(0.0, 1.0);

    // Weighted sum → logistic squash.
    let combined = WEIGHT_OWN * ownership_risk + WEIGHT_CHURN * churn_risk;
    logistic(combined)
}

/// Rank files by descending risk score.
///
/// Input: `(path, ownership, churn_commits)` tuples.
/// Output: `Vec<FileRisk>` sorted by score desc, then path asc for
/// determinism.
pub fn rank_files(files: &[(String, FileOwnership, u32)]) -> Vec<FileRisk> {
    let mut scored: Vec<FileRisk> = files
        .iter()
        .map(|(path, ow, churn)| FileRisk {
            path: path.clone(),
            score: change_risk(ow, *churn),
        })
        .collect();
    scored.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.path.cmp(&b.path))
    });
    scored
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

#[inline]
fn logistic(x: f64) -> f64 {
    1.0 / (1.0 + (-STEEPNESS * (x - MIDPOINT)).exp())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_map::ownership::FileOwnership;

    fn ownership(total: u32, primary_share: f64, bus_factor: u32) -> FileOwnership {
        FileOwnership {
            total_commits: total,
            authors: vec![("a@x.com".to_string(), (total as f64 * primary_share) as u32)],
            primary_owner: "a@x.com".to_string(),
            primary_share,
            bus_factor,
            recent_owner: "a@x.com".to_string(),
        }
    }

    // --- score is in [0, 1] for any input ---------------------------------

    #[test]
    fn score_bounded_within_unit_interval() {
        for &churn in &[0u32, 1, 10, 50, 200, 1000] {
            for &share in &[0.0f64, 0.25, 0.5, 0.75, 1.0] {
                for &bus in &[1u32, 2, 4, 8] {
                    let ow = ownership(churn, share, bus);
                    let s = change_risk(&ow, churn);
                    assert!(
                        (0.0..=1.0).contains(&s),
                        "score {s} out of [0,1] for churn={churn} share={share} bus={bus}"
                    );
                }
            }
        }
    }

    // --- high-risk file scores higher than low-risk file ------------------

    #[test]
    fn high_risk_file_scores_above_low_risk_file() {
        // Risky: bus_factor=1, primary_share=0.3 (fragile sole-area), high churn.
        let risky_ow = ownership(150, 0.3, 1);
        let risky = change_risk(&risky_ow, 150);

        // Safe: bus_factor=4, primary_share=0.5, low churn.
        let safe_ow = ownership(5, 0.5, 4);
        let safe = change_risk(&safe_ow, 5);

        assert!(
            risky > safe,
            "risky={risky:.4} should be > safe={safe:.4}"
        );
    }

    // --- rank_files returns deterministic descending order ----------------

    #[test]
    fn rank_files_returns_descending_order() {
        let files = vec![
            ("safe.rs".to_string(), ownership(2, 0.9, 3), 2u32),
            ("risky.rs".to_string(), ownership(180, 0.2, 1), 180u32),
            ("mid.rs".to_string(), ownership(30, 0.5, 2), 30u32),
        ];

        let ranked = rank_files(&files);

        assert_eq!(ranked.len(), 3);
        // Scores must be descending.
        for w in ranked.windows(2) {
            assert!(
                w[0].score >= w[1].score,
                "scores not descending: {ranked:?}"
            );
        }
        // Most risky file should be first.
        assert_eq!(ranked[0].path, "risky.rs", "expected risky.rs first, got {ranked:?}");
    }

    // --- determinism: same input → same output ---------------------------

    #[test]
    fn change_risk_is_deterministic() {
        let ow = ownership(42, 0.6, 2);
        let s1 = change_risk(&ow, 42);
        let s2 = change_risk(&ow, 42);
        assert_eq!(s1.to_bits(), s2.to_bits(), "non-deterministic result");
    }
}
