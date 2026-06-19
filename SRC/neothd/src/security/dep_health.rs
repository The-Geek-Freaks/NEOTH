//! GOLD-ADAPT-SNYK-03 — dependency-health heuristics gate.
//!
//! Provides a fast, offline typosquatting detector for packages about to be
//! installed via `npm install -g`. The check runs BEFORE the install alongside
//! the OSV malware gate (GOLD-ADAPT-GOOSE-01): that gate catches known-bad
//! packages by advisory ID; this one catches *look-alike* names that attackers
//! register to ride on popular packages' typos (e.g. `expres` → `express`).
//!
//! ## What is NOT here (network follow-up)
//!
//! Archived/abandoned-package detection requires querying the npm registry
//! metadata API (`registry.npmjs.org/<name>`) for `time.unpublished` or a
//! very old `modified` date, plus download-count signals. That is intentionally
//! OUT OF SCOPE for this slice — it needs a network call and a decay heuristic.
//! neoth: GOLD-ADAPT-SNYK-03b — add `check_abandoned(name) -> Option<AbandonHit>`
//!   using `GET https://registry.npmjs.org/<name>` + `last_modified` + weekly
//!   download count via `https://api.npmjs.org/downloads/point/last-week/<name>`.
//!
//! ## Distance thresholds
//!
//! | name length | max edit distance |
//! |-------------|-------------------|
//! | < 4 chars   | 0 (exact match only, too short to be informative) |
//! | 4–7 chars   | 1 |
//! | ≥ 8 chars   | 2 |
//!
//! Rationale: short names (`vue`, `npm`) have almost no Levenshtein headroom
//! before every other 3-letter word matches. At 4+ chars, distance 1 is a
//! strong single-transposition/deletion signal. Distance 2 becomes safe to
//! surface only when the name is long enough that two edits leave an
//! unambiguous resemblance.

use serde::Serialize;

/// High-traffic npm packages that are frequent typosquatting targets.
/// Curated to cover the AI-agent-install vector (tools NEOTH auto-installs
/// or that users commonly ask agents to install). Keep sorted for readability;
/// the runtime check is O(n) Levenshtein so order does not affect correctness.
const POPULAR_NPM: &[&str] = &[
    "@angular/cli",
    "@vue/cli",
    "axios",
    "babel-cli",
    "bcrypt",
    "chalk",
    "commander",
    "create-react-app",
    "debug",
    "dotenv",
    "eslint",
    "express",
    "http-server",
    "jest",
    "jsonwebtoken",
    "lodash",
    "minimist",
    "mocha",
    "moment",
    "next",
    "nodemon",
    "npm",
    "prettier",
    "react",
    "react-dom",
    "react-scripts",
    "semver",
    "ts-node",
    "typescript",
    "uuid",
    "vite",
    "vue",
    "webpack",
    "webpack-cli",
    "yarn",
    "zod",
];

// ── Public types ─────────────────────────────────────────────────────────────

/// A package name that appears to be a typosquat of a popular package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TyposquatHit {
    /// The name being installed.
    pub suspect: String,
    /// The popular package it closely resembles.
    pub resembles: String,
    /// Levenshtein edit distance between `suspect` and `resembles`.
    pub distance: usize,
}

impl TyposquatHit {
    /// Human-readable operator warning suitable for a `warn!` log field.
    pub fn describe(&self) -> String {
        format!(
            "`{}` looks like a typosquat of `{}` (edit distance {}) — \
             verify the package name before installing",
            self.suspect, self.resembles, self.distance
        )
    }
}

// ── Core heuristic ───────────────────────────────────────────────────────────

/// Return the maximum Levenshtein distance threshold for a name of a given
/// length. Returns `0` for names shorter than 4 characters, meaning only an
/// exact match would fire — but exact matches are explicitly excluded, so
/// effectively disabled for very short names.
fn threshold(name_len: usize) -> usize {
    if name_len < 4 {
        0
    } else if name_len < 8 {
        1
    } else {
        2
    }
}

/// Check whether `name` looks like a typosquat of a popular `ecosystem`
/// package.
///
/// Returns `Some(TyposquatHit)` iff:
/// - `ecosystem` is `"npm"` (no list exists for other ecosystems yet),
/// - `name` is NOT itself in the popular list (exact matches are legitimate),
/// - there exists a popular name within the Levenshtein distance threshold for
///   `name`'s length.
///
/// The first (shortest-distance, then alphabetically-first) hit is returned.
/// Callers should surface this as a WARNING — typosquatting is a heuristic and
/// must not hard-block installs unilaterally.
pub fn typosquat_risk(name: &str, ecosystem: &str) -> Option<TyposquatHit> {
    if !ecosystem.eq_ignore_ascii_case("npm") {
        // No curated list for this ecosystem yet.
        return None;
    }

    // Exact membership → legitimate popular package, no hit.
    if POPULAR_NPM.contains(&name) {
        return None;
    }

    let max_dist = threshold(name.len());
    if max_dist == 0 {
        // Name too short; any hit would be noise.
        return None;
    }

    // Find the closest popular name within the threshold.
    let mut best: Option<(&str, usize)> = None;
    for &popular in POPULAR_NPM {
        let d = strsim::levenshtein(name, popular);
        if d <= max_dist {
            let take = match best {
                None => true,
                Some((prev_name, prev_d)) => d < prev_d || (d == prev_d && popular < prev_name),
            };
            if take {
                best = Some((popular, d));
            }
        }
    }

    best.map(|(resembles, distance)| TyposquatHit {
        suspect: name.to_string(),
        resembles: resembles.to_string(),
        distance,
    })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// "expres" is one deletion from "express" — must fire.
    #[test]
    fn typosquat_expres_flags_express() {
        let hit = typosquat_risk("expres", "npm").expect("expres must flag express");
        assert_eq!(hit.resembles, "express");
        assert_eq!(hit.distance, 1);
        assert!(hit.describe().contains("express"));
        assert!(hit.describe().contains("expres"));
    }

    /// An exact popular name is itself — must return None (not a typosquat).
    #[test]
    fn exact_popular_name_is_not_a_typosquat() {
        assert!(
            typosquat_risk("react", "npm").is_none(),
            "react is in the popular list, should not flag itself"
        );
        assert!(
            typosquat_risk("express", "npm").is_none(),
            "express is in the popular list, should not flag itself"
        );
    }

    /// A clearly-unrelated package name must not fire.
    #[test]
    fn bespoke_internal_package_is_clean() {
        assert!(
            typosquat_risk("my-bespoke-internal-pkg", "npm").is_none(),
            "unrelated name must not flag as typosquat"
        );
    }

    /// A short name (< 4 chars) with distance 1 must NOT fire — threshold is 0.
    #[test]
    fn short_name_distance_1_is_suppressed() {
        // "vuw" is distance 1 from "vue" (3 chars → threshold 0 → no hit).
        assert!(
            typosquat_risk("vuw", "npm").is_none(),
            "names shorter than 4 chars must not trigger the heuristic"
        );
        // "npm" is in the list; "nmp" (distance 1, 3 chars) must also be clean.
        assert!(
            typosquat_risk("nmp", "npm").is_none(),
            "3-char names must not trigger (threshold 0)"
        );
    }

    /// An unknown ecosystem with no curated list must always return None.
    #[test]
    fn non_npm_ecosystem_returns_none() {
        // "serde" is a crate name; no crates list, so must be None.
        assert!(
            typosquat_risk("serde", "crates").is_none(),
            "crates ecosystem has no list, must return None"
        );
        assert!(
            typosquat_risk("expres", "pypi").is_none(),
            "pypi ecosystem has no list, must return None"
        );
    }

    /// Distance-2 on a short (4–7 char) name must NOT fire — threshold is 1.
    #[test]
    fn distance_2_on_short_name_is_suppressed() {
        // "loadsh" (6 chars, threshold 1) is distance 2 from "lodash"
        // (the a/d pair is swapped = two substitutions) — must not flag.
        assert_eq!(strsim::levenshtein("loadsh", "lodash"), 2);
        assert!(
            typosquat_risk("loadsh", "npm").is_none(),
            "distance 2 must not fire for a 6-char name (threshold 1)"
        );
    }

    /// Verify describe() output contains suspect, resembles, and distance wording.
    #[test]
    fn describe_contains_expected_tokens() {
        let hit = TyposquatHit {
            suspect: "expres".to_string(),
            resembles: "express".to_string(),
            distance: 1,
        };
        let d = hit.describe();
        assert!(d.contains("expres"), "describe missing suspect: {d}");
        assert!(d.contains("express"), "describe missing resembles: {d}");
        assert!(d.contains('1'), "describe missing distance: {d}");
        assert!(d.contains("verify"), "describe missing action hint: {d}");
    }
}
