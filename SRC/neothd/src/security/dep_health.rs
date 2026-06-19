//! GOLD-ADAPT-SNYK-03 / GOLD-ADAPT-SNYK-03b — dependency-health heuristics gate.
//!
//! Provides a fast, offline typosquatting detector for packages about to be
//! installed via `npm install -g`. The check runs BEFORE the install alongside
//! the OSV malware gate (GOLD-ADAPT-GOOSE-01): that gate catches known-bad
//! packages by advisory ID; this one catches *look-alike* names that attackers
//! register to ride on popular packages' typos (e.g. `expres` → `express`).
//!
//! ## Registry-metadata health check (GOLD-ADAPT-SNYK-03b)
//!
//! `check_registry_health` queries `registry.npmjs.org/<name>` for two signals:
//! - **Deprecated**: the latest-version `deprecated` field is non-empty → the
//!   package maintainer explicitly marked it deprecated (warn, don't block).
//! - **Abandoned**: the latest-version publish time is older than
//!   `ABANDONED_SECS` → likely unmaintained (warn, don't block).
//!
//! Both signals are WARN-only — the same posture as the typosquat heuristic.
//! A registry hiccup (network error / 404 / timeout) fails OPEN so an offline
//! install is never bricked. The pure `parse_registry_health` function is
//! testable without any I/O.
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

use std::time::Duration;

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

// ── Registry-metadata health (GOLD-ADAPT-SNYK-03b) ───────────────────────────

/// How long without a new release before we consider a package abandoned.
/// Operator can tune by recompiling; surfaced as a warn, never a hard block.
// neoth: tunable — 2 years felt right for npm CLI toolchain packages (they tend
// to release at least once a year when actively maintained).
const ABANDONED_SECS: i64 = 2 * 365 * 24 * 60 * 60; // 2 years

/// Network timeout for the npm registry GET — fail open past this.
const REGISTRY_TIMEOUT: Duration = Duration::from_secs(6);

/// Health signal derived from the npm registry document for a package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegistryHealth {
    /// The latest version carries a non-empty `deprecated` field.
    pub deprecated: bool,
    /// The deprecation message left by the maintainer, if any.
    pub deprecation_msg: Option<String>,
    /// Unix-second timestamp of the latest-version publish, if parseable.
    pub last_publish_unix: Option<i64>,
    /// True when `last_publish_unix` is older than [`ABANDONED_SECS`].
    pub abandoned: bool,
    /// Human-readable reason for the `abandoned` flag, if set.
    pub reason: Option<String>,
}

impl RegistryHealth {
    /// Returns `true` when neither flag is set — package looks healthy.
    pub fn is_healthy(&self) -> bool {
        !self.deprecated && !self.abandoned
    }

    /// Single-line operator warning. Returns `None` when nothing to warn about.
    pub fn describe(&self) -> Option<String> {
        match (self.deprecated, self.abandoned) {
            (false, false) => None,
            (true, _) => Some(format!(
                "npm package is deprecated{}",
                self.deprecation_msg
                    .as_deref()
                    .map(|m| format!(": {m}"))
                    .unwrap_or_default()
            )),
            (false, true) => Some(
                self.reason
                    .clone()
                    .unwrap_or_else(|| "npm package appears abandoned".to_string()),
            ),
        }
    }
}

/// Parse an ISO-8601 / RFC 3339 timestamp string to a Unix second.
///
/// The npm registry emits timestamps like `"2021-03-14T10:00:00.000Z"`.
/// chrono's `parse_from_rfc3339` handles fractional seconds natively but
/// requires the timezone expressed as `+00:00` rather than the `Z` shorthand
/// accepted by some parsers. We normalise `Z` → `+00:00` first.
fn parse_iso8601_to_unix(s: &str) -> Option<i64> {
    // Normalise trailing 'Z' (with or without fractional seconds) → '+00:00'.
    let normalised: std::borrow::Cow<str> = if let Some(stem) = s.strip_suffix('Z') {
        std::borrow::Cow::Owned(format!("{stem}+00:00"))
    } else {
        std::borrow::Cow::Borrowed(s)
    };
    chrono::DateTime::parse_from_rfc3339(&normalised)
        .ok()
        .map(|dt| dt.timestamp())
}

/// Parse a raw npm registry document into a [`RegistryHealth`] verdict.
///
/// Pure — no I/O, injected `now_unix` makes it unit-testable. Any missing or
/// malformed field is treated as healthy (defensive / fail-open for unknown
/// registry shapes). Never panics.
pub fn parse_registry_health(body: &serde_json::Value, now_unix: i64) -> RegistryHealth {
    // Locate the dist-tags.latest version string.
    let latest_ver = body
        .get("dist-tags")
        .and_then(|dt| dt.get("latest"))
        .and_then(|v| v.as_str());

    // ── Deprecation ──────────────────────────────────────────────────────────
    // `versions.<latest>.deprecated` is a non-empty string when set.
    let (deprecated, deprecation_msg) = latest_ver
        .and_then(|v| body.get("versions").and_then(|vs| vs.get(v)))
        .and_then(|ver_obj| ver_obj.get("deprecated"))
        .and_then(|d| d.as_str())
        .filter(|s| !s.is_empty())
        .map(|msg| (true, Some(msg.to_string())))
        .unwrap_or((false, None));

    // ── Abandon heuristic ─────────────────────────────────────────────────────
    // `time.<latest>` is an ISO-8601 string like "2021-03-14T10:00:00.000Z".
    let last_publish_unix: Option<i64> = latest_ver
        .and_then(|v| body.get("time").and_then(|t| t.get(v)))
        .and_then(|ts| ts.as_str())
        .and_then(parse_iso8601_to_unix)
        // Fall back: try `time.modified` (top-level registry modified date).
        .or_else(|| {
            body.get("time")
                .and_then(|t| t.get("modified"))
                .and_then(|ts| ts.as_str())
                .and_then(parse_iso8601_to_unix)
        });

    let (abandoned, reason) = match last_publish_unix {
        Some(ts) if (now_unix - ts) > ABANDONED_SECS => {
            let years = (now_unix - ts) / (365 * 24 * 60 * 60);
            (
                true,
                Some(format!(
                    "npm package last published ~{years} year(s) ago — may be abandoned"
                )),
            )
        }
        _ => (false, None),
    };

    RegistryHealth {
        deprecated,
        deprecation_msg,
        last_publish_unix,
        abandoned,
        reason,
    }
}

/// Query the npm registry for health metadata on `pkg`.
///
/// Mirrors the OSV-check client pattern exactly: same timeout, same fail-open
/// posture — a registry hiccup must never block an install.
///
/// `now_unix` is the current wall-clock second (use `crate::time::now_unix_i64()`
/// at the call site).
pub async fn check_registry_health(pkg: &str, now_unix: i64) -> RegistryHealth {
    // Healthy sentinel — returned on any error so the caller is never blocked.
    let healthy = RegistryHealth {
        deprecated: false,
        deprecation_msg: None,
        last_publish_unix: None,
        abandoned: false,
        reason: None,
    };

    // Percent-encode the package name (handles scoped packages like @anthropic-ai/claude-code).
    let encoded = percent_encode_pkg(pkg);
    let url = format!("https://registry.npmjs.org/{encoded}");

    let client = match reqwest::Client::builder()
        .timeout(REGISTRY_TIMEOUT)
        .build()
    {
        Ok(c) => c,
        Err(_) => return healthy,
    };
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(_) => return healthy,
    };
    if !resp.status().is_success() {
        return healthy;
    }
    match resp.json::<serde_json::Value>().await {
        Ok(body) => parse_registry_health(&body, now_unix),
        Err(_) => healthy,
    }
}

/// Minimal percent-encoding for npm package names.
///
/// Scoped packages like `@anthropic-ai/claude-code` need the `@` and `/` encoded
/// when used as a URL path segment: → `%40anthropic-ai%2Fclaude-code`.
fn percent_encode_pkg(pkg: &str) -> String {
    // The npm registry accepts the literal `@scope/name` form in the URL path
    // (it's how the registry CLI itself calls it), BUT the slash must be encoded
    // to avoid being interpreted as a path separator by HTTP routers. The `@`
    // is safe in path position but some proxies reject it — encode both to be safe.
    pkg.replace('@', "%40").replace('/', "%2F")
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

    // ── RegistryHealth / parse_registry_health tests (pure, no network) ───────

    /// A registry doc with a non-empty `deprecated` field on the latest version
    /// must be flagged deprecated=true and carry the message.
    #[test]
    fn registry_health_deprecated_latest_version() {
        let body = serde_json::json!({
            "dist-tags": { "latest": "1.2.3" },
            "versions": {
                "1.2.3": {
                    "deprecated": "use `new-pkg` instead"
                }
            },
            "time": {
                "1.2.3": "2024-01-15T10:00:00.000Z"
            }
        });
        // now_unix: 2025-06-19 ≈ 1 year after publish — NOT abandoned
        let now = 1_750_000_000_i64;
        let health = parse_registry_health(&body, now);
        assert!(health.deprecated, "expected deprecated=true");
        assert_eq!(
            health.deprecation_msg.as_deref(),
            Some("use `new-pkg` instead")
        );
        assert!(!health.abandoned, "only 1 year old — should not be abandoned");
        assert!(health.describe().is_some());
        assert!(health.describe().unwrap().contains("new-pkg"));
    }

    /// A doc whose latest publish time is 3 years before `now_unix` must be
    /// flagged abandoned=true.
    #[test]
    fn registry_health_abandoned_old_publish() {
        // Publish date: 2020-01-01 ≈ unix 1_577_836_800
        let body = serde_json::json!({
            "dist-tags": { "latest": "0.1.0" },
            "versions": { "0.1.0": {} },
            "time": {
                "0.1.0": "2020-01-01T00:00:00.000Z"
            }
        });
        // now_unix: 2023-06-01 ≈ 1_685_577_600 (~3.5 years later)
        let now = 1_685_577_600_i64;
        let health = parse_registry_health(&body, now);
        assert!(!health.deprecated, "no deprecated field");
        assert!(health.abandoned, "3+ years old — should be abandoned");
        assert!(health.reason.is_some());
        let reason = health.reason.as_deref().unwrap();
        assert!(reason.contains("year"), "reason should mention years: {reason}");
        assert!(health.describe().is_some());
    }

    /// A fresh, non-deprecated doc must yield all-false (healthy).
    #[test]
    fn registry_health_fresh_healthy_doc() {
        // Published "recently" (now - 6 months)
        let recent_ts = 1_750_000_000_i64 - 6 * 30 * 24 * 60 * 60;
        // Build an ISO-8601 string from the timestamp (approximate — good enough
        // for a round-trip unit test of the parse path).
        let ts_str = chrono::DateTime::from_timestamp(recent_ts, 0)
            .map(|dt| dt.format("%Y-%m-%dT%H:%M:%S+00:00").to_string())
            .unwrap_or_else(|| "2025-01-01T00:00:00+00:00".to_string());
        let body = serde_json::json!({
            "dist-tags": { "latest": "3.0.0" },
            "versions": { "3.0.0": {} },
            "time": { "3.0.0": ts_str }
        });
        let health = parse_registry_health(&body, 1_750_000_000);
        assert!(!health.deprecated);
        assert!(!health.abandoned);
        assert!(health.is_healthy());
        assert!(health.describe().is_none());
    }

    /// A malformed / empty doc must yield healthy (no panic, no false positive).
    #[test]
    fn registry_health_malformed_doc_is_healthy() {
        // Completely empty object
        let health = parse_registry_health(&serde_json::json!({}), 1_750_000_000);
        assert!(!health.deprecated);
        assert!(!health.abandoned);
        assert!(health.is_healthy());

        // Null body
        let health2 = parse_registry_health(&serde_json::Value::Null, 1_750_000_000);
        assert!(health2.is_healthy());

        // dist-tags present but no versions block
        let health3 = parse_registry_health(
            &serde_json::json!({ "dist-tags": { "latest": "1.0.0" } }),
            1_750_000_000,
        );
        assert!(health3.is_healthy());
    }

    /// percent_encode_pkg must encode scoped package names correctly.
    #[test]
    fn percent_encode_pkg_scoped() {
        assert_eq!(
            percent_encode_pkg("@anthropic-ai/claude-code"),
            "%40anthropic-ai%2Fclaude-code"
        );
        assert_eq!(percent_encode_pkg("lodash"), "lodash");
        assert_eq!(percent_encode_pkg("@openai/codex"), "%40openai%2Fcodex");
    }
}
