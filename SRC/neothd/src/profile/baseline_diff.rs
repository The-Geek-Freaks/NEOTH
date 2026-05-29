//! HO-09 / V1x-03 — profile baseline DRIFT detection.
//!
//! Companion to [`super::baseline_snapshot`]. Where `baseline_snapshot`
//! captures the immutable Phase-3 migration anchor (the exactly-once
//! `0xB3 PROFILE_BASELINE_SNAPSHOT` WAL frame), this module provides:
//!
//!   1. A pure set-difference [`compute_drift`] over claim-hash sets,
//!      producing a [`DriftReport`] with added / removed / retained +
//!      a drift ratio.
//!   2. An operator-resettable WORKING baseline ([`DriftBaseline`]) stored
//!      as `~/.neoth/profile_drift_baseline.json`. The migration `0xB3`
//!      anchor is immutable; this working baseline is what `neoth profile
//!      drift baseline` (re)captures and `neoth profile drift reset`
//!      clears, so the operator can re-anchor drift to "now" without
//!      touching the append-only WAL.
//!
//! All functions here are pure / filesystem-only — the WAL fallback (read
//! the `0xB3` anchor when no working baseline file exists) lives in the
//! `cli::profile` drift handler where the frame-decode helpers already are.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Filename of the operator-resettable working drift baseline inside
/// `~/.neoth/`.
pub const DRIFT_BASELINE_FILE: &str = "profile_drift_baseline.json";

/// The result of comparing a baseline claim-hash set against the current
/// active claim set. Set-membership semantics (per the `0xB3` doc): a
/// claim is identified by its SHA-256 hash; ordering is irrelevant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DriftReport {
    /// Distinct claim hashes in the baseline.
    pub baseline_count: usize,
    /// Distinct claim hashes in the current active profile.
    pub current_count: usize,
    /// Hashes present now but absent at baseline (new self-knowledge).
    pub added: Vec<String>,
    /// Hashes present at baseline but absent now (forgotten / superseded).
    pub removed: Vec<String>,
    /// Count of hashes present in both.
    pub retained: usize,
}

impl DriftReport {
    /// Fraction of the profile that changed since the baseline:
    /// `(added + removed) / max(baseline_count, current_count)`.
    /// `0.0` = identical sets; `1.0` = full one-sided replacement (every
    /// claim either added or removed, but not both); up to `2.0` when the
    /// sets are completely disjoint (every baseline claim replaced by a
    /// new one — both an add AND a remove per slot). So `threshold` in
    /// `DriftAlertConfig` is meaningful across `0.0..=2.0`. Empty-vs-empty
    /// is `0.0` (no baseline, no drift).
    pub fn drift_ratio(&self) -> f64 {
        let denom = self.baseline_count.max(self.current_count);
        if denom == 0 {
            return 0.0;
        }
        (self.added.len() + self.removed.len()) as f64 / denom as f64
    }

    /// True when the drift ratio strictly exceeds `threshold`.
    pub fn is_over(&self, threshold: f64) -> bool {
        self.drift_ratio() > threshold
    }
}

/// Pure set-difference between a baseline claim-hash set and the current
/// active claim-hash set. Deduplicates both sides (set membership) and
/// returns `added` / `removed` sorted for stable output.
pub fn compute_drift(baseline_hashes: &[String], current_hashes: &[String]) -> DriftReport {
    use std::collections::BTreeSet;
    let base: BTreeSet<&str> = baseline_hashes.iter().map(|s| s.as_str()).collect();
    let cur: BTreeSet<&str> = current_hashes.iter().map(|s| s.as_str()).collect();

    let added: Vec<String> = cur.difference(&base).map(|s| (*s).to_string()).collect();
    let removed: Vec<String> = base.difference(&cur).map(|s| (*s).to_string()).collect();
    let retained = base.intersection(&cur).count();

    DriftReport {
        baseline_count: base.len(),
        current_count: cur.len(),
        added,
        removed,
        retained,
    }
}

/// Operator-resettable working baseline. Distinct from the immutable
/// `0xB3` migration anchor — this one can be re-captured and cleared.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftBaseline {
    /// `"manual"` for an operator-captured baseline, or the `0xB3`
    /// snapshot_id when the working baseline was seeded from the anchor.
    pub source: String,
    /// Per-claim SHA-256 hex digests of the active claim set at capture.
    pub claim_hashes: Vec<String>,
    /// NEOTH version that captured the working baseline.
    pub neoth_version: String,
    pub captured_at_ts_unix: i64,
}

impl DriftBaseline {
    pub fn new(
        source: impl Into<String>,
        claim_hashes: Vec<String>,
        neoth_version: impl Into<String>,
        captured_at_ts_unix: i64,
    ) -> Self {
        Self {
            source: source.into(),
            claim_hashes,
            neoth_version: neoth_version.into(),
            captured_at_ts_unix,
        }
    }
}

/// Path to the working drift baseline file inside `home`.
pub fn drift_baseline_path(home: &Path) -> PathBuf {
    home.join(DRIFT_BASELINE_FILE)
}

/// Persist the working baseline atomically (`.tmp` sibling + rename) so a
/// crash mid-write never leaves a torn JSON file. Both fallible steps
/// carry the offending path in their error context (matches the
/// `audit_sidecar` / `briefing_gate` atomic-write convention).
pub fn save_drift_baseline(home: &Path, baseline: &DriftBaseline) -> Result<()> {
    let path = drift_baseline_path(home);
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_string_pretty(baseline).context("serialize drift baseline")?;
    std::fs::write(&tmp, json).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))
}

/// Load the working baseline. `Ok(None)` when no file exists (the caller
/// then falls back to the `0xB3` anchor). A malformed file is an error so
/// the operator notices rather than silently re-anchoring. Uses
/// attempt-then-match-on-NotFound (no `exists()` TOCTOU window).
pub fn load_drift_baseline(home: &Path) -> Result<Option<DriftBaseline>> {
    let path = drift_baseline_path(home);
    let body = match std::fs::read_to_string(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow::Error::from(e).context(format!("read {}", path.display()))),
    };
    let baseline: DriftBaseline = serde_json::from_str(&body)
        .with_context(|| format!("parse drift baseline {}", path.display()))?;
    Ok(Some(baseline))
}

/// Delete the working baseline file. Idempotent — absent file is
/// `Ok(false)`. Attempt-then-match-on-NotFound (no `exists()` TOCTOU).
pub fn reset_drift_baseline(home: &Path) -> Result<bool> {
    let path = drift_baseline_path(home);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(anyhow::Error::from(e).context(format!("remove {}", path.display()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn h(s: &str) -> String {
        s.to_string()
    }

    #[test]
    fn compute_drift_identical_sets_is_zero() {
        let base = vec![h("a"), h("b"), h("c")];
        let report = compute_drift(&base, &base);
        assert!(report.added.is_empty());
        assert!(report.removed.is_empty());
        assert_eq!(report.retained, 3);
        assert_eq!(report.drift_ratio(), 0.0);
        assert!(!report.is_over(0.0));
    }

    #[test]
    fn compute_drift_detects_added_and_removed() {
        let base = vec![h("a"), h("b"), h("c")];
        let cur = vec![h("b"), h("c"), h("d")]; // -a, +d
        let report = compute_drift(&base, &cur);
        assert_eq!(report.added, vec!["d"]);
        assert_eq!(report.removed, vec!["a"]);
        assert_eq!(report.retained, 2);
        assert_eq!(report.baseline_count, 3);
        assert_eq!(report.current_count, 3);
        // (1 added + 1 removed) / max(3,3) = 0.666…
        assert!((report.drift_ratio() - 2.0 / 3.0).abs() < 1e-9);
        assert!(report.is_over(0.5));
        assert!(!report.is_over(0.7));
        // At-boundary must NOT trigger — pins the strict `>` contract
        // against a `>` → `>=` regression.
        assert!(
            !report.is_over(2.0 / 3.0),
            "at-boundary should not trigger (strict >)"
        );
    }

    #[test]
    fn compute_drift_empty_vs_empty_is_zero_not_nan() {
        let report = compute_drift(&[], &[]);
        assert_eq!(report.drift_ratio(), 0.0);
    }

    #[test]
    fn compute_drift_total_turnover_reaches_two() {
        // Fully disjoint equal-size sets: every baseline claim removed +
        // every current claim added ⇒ ratio 2.0 (the max), NOT 1.0.
        let base = vec![h("a"), h("b")];
        let cur = vec![h("x"), h("y")];
        let report = compute_drift(&base, &cur);
        assert_eq!(report.retained, 0);
        assert_eq!(report.drift_ratio(), 2.0); // (added=2 + removed=2) / max(2,2)
    }

    #[test]
    fn compute_drift_dedups_each_side() {
        let base = vec![h("a"), h("a"), h("b")];
        let cur = vec![h("a"), h("b"), h("b")];
        let report = compute_drift(&base, &cur);
        assert_eq!(report.baseline_count, 2);
        assert_eq!(report.current_count, 2);
        assert_eq!(report.retained, 2);
        assert_eq!(report.drift_ratio(), 0.0);
    }

    #[test]
    fn drift_baseline_round_trips_through_file() {
        let dir = TempDir::new().unwrap();
        let baseline = DriftBaseline::new("manual", vec![h("h1"), h("h2")], "0.2.1", 1_700_000_000);
        assert!(load_drift_baseline(dir.path()).unwrap().is_none());
        save_drift_baseline(dir.path(), &baseline).unwrap();
        let back = load_drift_baseline(dir.path()).unwrap().unwrap();
        assert_eq!(back, baseline);
    }

    #[test]
    fn save_drift_baseline_leaves_no_tmp() {
        let dir = TempDir::new().unwrap();
        let baseline = DriftBaseline::new("manual", vec![h("h1")], "0.2.1", 0);
        save_drift_baseline(dir.path(), &baseline).unwrap();
        assert!(!dir.path().join("profile_drift_baseline.json.tmp").exists());
        assert!(drift_baseline_path(dir.path()).exists());
    }

    #[test]
    fn reset_drift_baseline_is_idempotent() {
        let dir = TempDir::new().unwrap();
        // Absent → Ok(false).
        assert!(!reset_drift_baseline(dir.path()).unwrap());
        save_drift_baseline(
            dir.path(),
            &DriftBaseline::new("manual", vec![], "0.2.1", 0),
        )
        .unwrap();
        // Present → Ok(true), then gone.
        assert!(reset_drift_baseline(dir.path()).unwrap());
        assert!(load_drift_baseline(dir.path()).unwrap().is_none());
    }

    #[test]
    fn load_malformed_baseline_is_error_not_silent_none() {
        let dir = TempDir::new().unwrap();
        std::fs::write(drift_baseline_path(dir.path()), "{ not valid json").unwrap();
        assert!(load_drift_baseline(dir.path()).is_err());
    }
}
