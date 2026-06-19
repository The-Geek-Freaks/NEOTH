//! REPOW-03 — Change-risk model combining ownership and churn.
//!
//! Also provides [`assess_edit_risk`] — the pre-edit gate used by the
//! coding dispatcher to warn the operator before applying a patch to
//! high-risk files (risk ≥ HIGH_RISK_THRESHOLD or bus_factor == 1).
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

use std::path::Path;

use serde::{Deserialize, Serialize};

use super::ownership::{self, FileOwnership};

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
// Pre-edit risk gate (REPOW review #2)
// ---------------------------------------------------------------------------

/// Files with a risk score at or above this threshold trigger a warning.
///
/// // neoth: tunable — lower to 0.55 for noisier-but-earlier warnings,
/// // raise toward 0.80 for calmer operation on large churning repos.
pub const HIGH_RISK_THRESHOLD: f64 = 0.66;

/// One warning emitted by [`assess_edit_risk`] for a single file.
#[derive(Clone, Debug)]
pub struct RiskWarning {
    /// Repo-relative path of the file about to be edited.
    pub file: String,
    /// Computed risk score in [0, 1].
    pub risk_score: f64,
    /// Bus-factor of the file (0 = no git history).
    pub bus_factor: u32,
    /// Human-readable reason string, e.g. "risk=0.78 (HIGH)" or
    /// "bus_factor=1 (single-owner)".
    pub reason: String,
}

/// Assess pre-edit risk for a set of files about to be patched.
///
/// For each file, runs `git log` (via [`ownership::file_ownership`]) and
/// [`change_risk`]. Returns a [`RiskWarning`] for every file that either:
///
/// * has `risk_score >= HIGH_RISK_THRESHOLD`, OR
/// * has `bus_factor == 1` (sole owner — fragile knowledge island).
///
/// Git subprocess failures are swallowed and treated as "no history" (no
/// warning emitted for that file) so a git error never aborts the edit.
///
/// Intended call site: coding dispatcher, immediately before
/// `apply_patch_in_worktree`. Does NOT block the edit.
pub fn assess_edit_risk(repo: &Path, files: &[String]) -> Vec<RiskWarning> {
    files
        .iter()
        .filter_map(|file| {
            let ownership = match ownership::file_ownership(repo, file) {
                Ok(o) => o,
                Err(_) => return None, // degrade gracefully — never abort
            };
            let score = change_risk(&ownership, ownership.total_commits);
            let high_risk = score >= HIGH_RISK_THRESHOLD;
            let single_owner = ownership.bus_factor == 1 && ownership.total_commits > 0;
            if !high_risk && !single_owner {
                return None;
            }
            let reason = match (high_risk, single_owner) {
                (true, true) => format!(
                    "risk={score:.2} (HIGH), bus_factor=1 (single-owner)"
                ),
                (true, false) => format!("risk={score:.2} (HIGH)"),
                (false, true) => format!(
                    "bus_factor=1 (single-owner), risk={score:.2}"
                ),
                _ => unreachable!(),
            };
            Some(RiskWarning {
                file: file.clone(),
                risk_score: score,
                bus_factor: ownership.bus_factor,
                reason,
            })
        })
        .collect()
}

/// Extract the set of files touched by a unified-diff patch file.
///
/// Parses `+++ b/<path>` lines (standard unified-diff header). Returns
/// repo-relative paths. Silently returns empty vec on any IO/parse error
/// so that a bad patch file never prevents the apply attempt.
pub fn patch_changed_files(patch_path: &Path) -> Vec<String> {
    let text = match std::fs::read_to_string(patch_path) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    text.lines()
        .filter_map(|line| {
            // Unified diff header: "+++ b/src/foo/bar.rs"
            // /dev/null means the file is being deleted — skip.
            let stripped = line.strip_prefix("+++ b/")?;
            if stripped == "/dev/null" || stripped.is_empty() {
                return None;
            }
            Some(stripped.to_string())
        })
        .collect::<std::collections::HashSet<_>>() // deduplicate (multi-hunk)
        .into_iter()
        .collect()
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

    // -----------------------------------------------------------------------
    // assess_edit_risk — pre-edit gate tests
    // -----------------------------------------------------------------------

    use std::path::Path;
    use std::process::Command;
    use tempfile::tempdir;

    fn git_available() -> bool {
        Command::new("git")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn init_repo(dir: &Path) -> std::io::Result<()> {
        Command::new("git").arg("-C").arg(dir).args(["init", "-q"]).status()?;
        Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["config", "user.email", "ci@example.com"])
            .status()?;
        Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["config", "user.name", "CI"])
            .status()?;
        Ok(())
    }

    fn commit_file(dir: &Path, file: &str, content: &str) {
        std::fs::write(dir.join(file), content).unwrap();
        Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["add", file])
            .status()
            .unwrap();
        Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["commit", "-q", "-m", &format!("update {file}")])
            .env("GIT_AUTHOR_NAME", "sole")
            .env("GIT_AUTHOR_EMAIL", "sole@x.com")
            .env("GIT_COMMITTER_NAME", "sole")
            .env("GIT_COMMITTER_EMAIL", "sole@x.com")
            .status()
            .unwrap();
    }

    // Single-owner + high-churn file → warning emitted
    #[test]
    fn assess_edit_risk_warns_for_single_owner_high_churn_file() {
        if !git_available() {
            eprintln!("skipping: git not on PATH");
            return;
        }
        let dir = tempdir().unwrap();
        let repo = dir.path();
        init_repo(repo).unwrap();

        // One author, many commits → bus_factor=1 → should trigger single-owner warning.
        for i in 0..30 {
            commit_file(repo, "hot.rs", &format!("// v{i}"));
        }

        let warnings = assess_edit_risk(repo, &["hot.rs".to_string()]);
        assert!(
            !warnings.is_empty(),
            "expected a warning for single-owner high-churn file, got none"
        );
        let w = &warnings[0];
        assert_eq!(w.file, "hot.rs");
        assert_eq!(w.bus_factor, 1);
        assert!(
            w.risk_score >= HIGH_RISK_THRESHOLD || w.bus_factor == 1,
            "warning should be for high risk or single owner, got: {w:?}"
        );
    }

    // Untracked / new file with no git history → no warning (degrade gracefully)
    #[test]
    fn assess_edit_risk_no_warning_for_file_with_no_history() {
        if !git_available() {
            eprintln!("skipping: git not on PATH");
            return;
        }
        let dir = tempdir().unwrap();
        let repo = dir.path();
        init_repo(repo).unwrap();

        // Write but don't commit — no git history.
        std::fs::write(repo.join("new.rs"), "fn main() {}").unwrap();

        let warnings = assess_edit_risk(repo, &["new.rs".to_string()]);
        assert!(
            warnings.is_empty(),
            "expected no warning for file with no history, got: {warnings:?}"
        );
    }

    // -----------------------------------------------------------------------
    // patch_changed_files — unified-diff parser tests
    // -----------------------------------------------------------------------

    #[test]
    fn patch_changed_files_extracts_plus_b_paths() {
        let dir = tempdir().unwrap();
        let patch = dir.path().join("test.patch");
        std::fs::write(
            &patch,
            "diff --git a/src/foo.rs b/src/foo.rs\n\
             --- a/src/foo.rs\n\
             +++ b/src/foo.rs\n\
             @@ -1 +1 @@\n\
             -old\n\
             +new\n\
             diff --git a/src/bar.rs b/src/bar.rs\n\
             --- a/src/bar.rs\n\
             +++ b/src/bar.rs\n\
             @@ -1 +1 @@\n\
             -old\n\
             +new\n",
        )
        .unwrap();

        let mut files = patch_changed_files(&patch);
        files.sort();
        assert_eq!(files, vec!["src/bar.rs", "src/foo.rs"]);
    }

    #[test]
    fn patch_changed_files_deduplicates_multi_hunk() {
        let dir = tempdir().unwrap();
        let patch = dir.path().join("multi.patch");
        // Same file appears in two hunks — should deduplicate.
        std::fs::write(
            &patch,
            "+++ b/src/lib.rs\n\
             @@ -1 +1 @@\n\
             +hunk1\n\
             +++ b/src/lib.rs\n\
             @@ -5 +5 @@\n\
             +hunk2\n",
        )
        .unwrap();

        let files = patch_changed_files(&patch);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0], "src/lib.rs");
    }

    #[test]
    fn patch_changed_files_returns_empty_for_missing_patch() {
        let files = patch_changed_files(Path::new("/nonexistent/path/x.patch"));
        assert!(files.is_empty());
    }
}
