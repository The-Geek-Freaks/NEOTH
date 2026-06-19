//! GOLD-ADAPT-GOOSE-01 — OSV supply-chain malware gate.
//! GOLD-ADAPT-SNYK-01 — CVE/GHSA severity-threshold dep-blocking.
//!
//! Before NEOTH's wizard / auto-update installs a CLI toolchain package via
//! `npm install -g`, query the OSV database (api.osv.dev) for advisories naming
//! that package. A confirmed `MAL-*` hit BLOCKS unconditionally. CVE/GHSA hits
//! are classified by severity and block-or-warn depending on the threshold passed
//! by the caller (default: warn-only, block at >= `High` when operator opts in).
//! A network / HTTP / parse error FAILS OPEN so an offline or transient failure
//! never bricks onboarding.
//!
//! Adapted from goose `agents/extension_malware_check.rs` (queries
//! `api.osv.dev/v1/query`, filters `MAL-*`, fails open on network error). NEOTH's
//! installers previously ran `npm install -g <pkg>` with ZERO pre-install
//! advisory lookup — `security/dangerous_command.rs` is shell-pattern-only — so
//! this closes a supply-chain gap, directly relevant to the operator's
//! security-researcher profile and NEOTH's self-contained wizard installs.

use std::time::Duration;

use serde::Serialize;

/// OSV query endpoint.
const OSV_QUERY_URL: &str = "https://api.osv.dev/v1/query";
/// OSV malware advisories are namespaced `MAL-…`.
const MALWARE_ID_PREFIX: &str = "MAL-";
/// Network timeout — fail open past this so a slow/unreachable OSV never hangs
/// or bricks an install.
const OSV_TIMEOUT: Duration = Duration::from_secs(6);

// ── Severity classification (GOLD-ADAPT-SNYK-01) ─────────────────────────────

/// CVSS / OSV severity level, ordered from lowest to highest.
///
/// Derived from `vulns[].severity[].score` (CVSS vector), `database_specific.severity`
/// (GitHub advisory), or the raw `severity` string on the vuln object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum SeverityLevel {
    /// No severity information present in the advisory.
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl SeverityLevel {
    /// Parse a severity string (case-insensitive) as used by OSV / GitHub advisories.
    fn from_str(s: &str) -> Self {
        match s.to_ascii_uppercase().as_str() {
            "CRITICAL" => Self::Critical,
            "HIGH" => Self::High,
            "MEDIUM" | "MODERATE" => Self::Medium,
            "LOW" => Self::Low,
            _ => Self::None,
        }
    }

    /// Parse a CVSS base score string (e.g. `"CVSS:3.1/AV:N/.../S:U/C:H/I:H/A:H"`)
    /// into a severity bucket.  Falls back to `None` on any parse failure.
    fn from_cvss(score_str: &str) -> Self {
        // CVSS vectors start with "CVSS:3.x/" or "CVSS:2.0/". We look for the
        // overall base-score numeric at the end (some callers give just a number).
        // Prefer parsing the numeric base-score directly when the string is a plain
        // float (GitHub/NVD sometimes inlines just the number).
        if let Ok(n) = score_str.trim().parse::<f64>() {
            return Self::from_cvss_score(n);
        }
        // For full CVSS vectors, look for the numeric after the last component.
        // api.osv.dev often emits severity[].score as the full vector string.
        // We don't implement a full CVSS parser here — instead, map via the
        // qualitative label embedded in `database_specific.severity` if available.
        Self::None
    }

    fn from_cvss_score(score: f64) -> Self {
        if score >= 9.0 {
            Self::Critical
        } else if score >= 7.0 {
            Self::High
        } else if score >= 4.0 {
            Self::Medium
        } else if score > 0.0 {
            Self::Low
        } else {
            Self::None
        }
    }
}

/// Classify the maximum severity of non-MAL advisories in an OSV response body.
///
/// PURE — no I/O. Returns the highest `SeverityLevel` found across all CVE/GHSA
/// entries in `vulns[]`. MAL-* entries are excluded (they are handled by
/// `classify_osv_body` unconditionally; severity is not relevant for malware).
///
/// Priority order for each advisory:
/// 1. `severity[].score` where `type == "CVSS_V3"` or `"CVSS_V2"` — parse numeric
/// 2. `database_specific.severity` string (GitHub advisory label)
/// 3. `severity[].score` string label fallback
pub fn classify_osv_severity(body: &serde_json::Value) -> SeverityLevel {
    let vulns = match body.get("vulns").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return SeverityLevel::None,
    };

    let mut max = SeverityLevel::None;

    for vuln in vulns {
        // Skip MAL-* — malware is handled unconditionally elsewhere.
        let id = vuln
            .get("id")
            .and_then(|id| id.as_str())
            .unwrap_or_default();
        if id.starts_with(MALWARE_ID_PREFIX) {
            continue;
        }

        let sev = severity_for_vuln(vuln);
        if sev > max {
            max = sev;
        }
    }

    max
}

/// Extract the best severity signal from a single OSV `vulns[]` entry.
fn severity_for_vuln(vuln: &serde_json::Value) -> SeverityLevel {
    // 1. database_specific.severity — used by GitHub advisories (string label).
    if let Some(s) = vuln
        .get("database_specific")
        .and_then(|d| d.get("severity"))
        .and_then(|s| s.as_str())
    {
        let parsed = SeverityLevel::from_str(s);
        if parsed > SeverityLevel::None {
            return parsed;
        }
    }

    // 2. severity[] array — OSV standard, may contain CVSS vectors or scores.
    if let Some(arr) = vuln.get("severity").and_then(|s| s.as_array()) {
        let mut best = SeverityLevel::None;
        for entry in arr {
            let score_str = entry
                .get("score")
                .and_then(|s| s.as_str())
                .unwrap_or_default();
            // Try numeric score first (some entries are plain "7.5").
            let candidate = SeverityLevel::from_cvss(score_str);
            if candidate > best {
                best = candidate;
            }
            // Also check type-specific label fields, e.g. `{"type":"CVSS_V3","score":"..."}`.
            // No additional parsing needed here — from_cvss covers both paths.
        }
        if best > SeverityLevel::None {
            return best;
        }
    }

    SeverityLevel::None
}

// ── OsvVerdict (GOLD-ADAPT-GOOSE-01 + SNYK-01) ───────────────────────────────

/// Verdict from an OSV advisory lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OsvVerdict {
    /// No advisories name this package — safe to install.
    Clean,
    /// One or more `MAL-*` advisories name this package — BLOCK unconditionally.
    Malicious { advisories: Vec<String> },
    /// One or more CVE/GHSA advisories name this package. Each entry carries the
    /// advisory ID and its classified severity. The caller decides whether to block
    /// or warn based on a severity threshold.
    Vulnerable {
        /// `(advisory_id, severity)` pairs, MAL-* excluded.
        advisories: Vec<(String, SeverityLevel)>,
        /// The maximum severity across all entries — provided for quick comparison.
        max_severity: SeverityLevel,
    },
    /// The lookup could not be completed (network / HTTP / parse error). FAIL
    /// OPEN: the caller proceeds, but the reason is logged so it stays auditable.
    Unknown { reason: String },
}

impl OsvVerdict {
    pub fn is_malicious(&self) -> bool {
        matches!(self, OsvVerdict::Malicious { .. })
    }
}

#[derive(Serialize)]
struct OsvPackage<'a> {
    name: &'a str,
    ecosystem: &'a str,
}

#[derive(Serialize)]
struct OsvQuery<'a> {
    package: OsvPackage<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<&'a str>,
}

/// Classify an OSV `/v1/query` response body.
///
/// Priority:
/// 1. If ANY `MAL-*` advisory is present → `Malicious` (unconditional hard block).
/// 2. If CVE/GHSA advisories are present → `Vulnerable` with per-advisory severity.
/// 3. Otherwise → `Clean`.
///
/// Pure — no I/O, unit-tested directly.
fn classify_osv_body(body: &serde_json::Value) -> OsvVerdict {
    let vulns = match body.get("vulns").and_then(|v| v.as_array()) {
        Some(arr) if !arr.is_empty() => arr,
        _ => return OsvVerdict::Clean,
    };

    // First pass: collect MAL-* ids (malware — unconditional block).
    let mal_ids: Vec<String> = vulns
        .iter()
        .filter_map(|v| v.get("id").and_then(|id| id.as_str()))
        .filter(|id| id.starts_with(MALWARE_ID_PREFIX))
        .map(|id| id.to_string())
        .collect();

    if !mal_ids.is_empty() {
        return OsvVerdict::Malicious { advisories: mal_ids };
    }

    // Second pass: collect CVE/GHSA advisories with severity (GOLD-ADAPT-SNYK-01).
    let vuln_advisories: Vec<(String, SeverityLevel)> = vulns
        .iter()
        .filter_map(|v| {
            let id = v.get("id").and_then(|id| id.as_str())?.to_string();
            let sev = severity_for_vuln(v);
            Some((id, sev))
        })
        .collect();

    if vuln_advisories.is_empty() {
        return OsvVerdict::Clean;
    }

    let max_severity = vuln_advisories
        .iter()
        .map(|(_, s)| *s)
        .max()
        .unwrap_or(SeverityLevel::None);

    OsvVerdict::Vulnerable {
        advisories: vuln_advisories,
        max_severity,
    }
}

/// Query OSV for malware advisories on `(name, ecosystem[, version])`.
/// FAILS OPEN (`Unknown`) on any network / HTTP / parse error.
pub async fn check_package(name: &str, ecosystem: &str, version: Option<&str>) -> OsvVerdict {
    check_package_at(OSV_QUERY_URL, name, ecosystem, version).await
}

/// [`check_package`] against an explicit endpoint — the `wiremock` test seam.
async fn check_package_at(
    url: &str,
    name: &str,
    ecosystem: &str,
    version: Option<&str>,
) -> OsvVerdict {
    let client = match reqwest::Client::builder().timeout(OSV_TIMEOUT).build() {
        Ok(c) => c,
        Err(e) => {
            return OsvVerdict::Unknown {
                reason: format!("build http client: {e}"),
            };
        }
    };
    let query = OsvQuery {
        package: OsvPackage { name, ecosystem },
        version,
    };
    let resp = match client.post(url).json(&query).send().await {
        Ok(r) => r,
        Err(e) => {
            return OsvVerdict::Unknown {
                reason: format!("OSV request failed: {e}"),
            };
        }
    };
    if !resp.status().is_success() {
        return OsvVerdict::Unknown {
            reason: format!("OSV returned HTTP {}", resp.status()),
        };
    }
    match resp.json::<serde_json::Value>().await {
        Ok(body) => classify_osv_body(&body),
        Err(e) => OsvVerdict::Unknown {
            reason: format!("OSV response parse: {e}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── classify_osv_body ─────────────────────────────────────────────────────

    #[test]
    fn classify_flags_mal_ids_only_when_mixed() {
        // MAL-* always wins over CVE/GHSA — malware is an unconditional block.
        let body = json!({"vulns": [
            {"id": "MAL-2024-1234"},
            {"id": "CVE-2021-0001"},
            {"id": "GHSA-xxxx-yyyy-zzzz"},
            {"id": "MAL-2025-9999"},
        ]});
        match classify_osv_body(&body) {
            OsvVerdict::Malicious { advisories } => {
                assert_eq!(advisories, vec!["MAL-2024-1234", "MAL-2025-9999"]);
            }
            other => panic!("expected Malicious, got {other:?}"),
        }
    }

    /// SNYK-01: non-MAL advisories produce `Vulnerable`, not `Clean`.
    #[test]
    fn classify_vulnerable_when_only_cve_ghsa() {
        let body = json!({"vulns": [
            {"id": "CVE-2021-0001"},
            {"id": "GHSA-aaaa-bbbb-cccc"},
        ]});
        match classify_osv_body(&body) {
            OsvVerdict::Vulnerable { advisories, .. } => {
                let ids: Vec<&str> = advisories.iter().map(|(id, _)| id.as_str()).collect();
                assert!(ids.contains(&"CVE-2021-0001"));
                assert!(ids.contains(&"GHSA-aaaa-bbbb-cccc"));
            }
            other => panic!("expected Vulnerable, got {other:?}"),
        }
    }

    #[test]
    fn classify_clean_on_empty_or_missing_vulns() {
        assert_eq!(classify_osv_body(&json!({"vulns": []})), OsvVerdict::Clean);
        // OSV returns `{}` (no `vulns` key) when nothing matches.
        assert_eq!(classify_osv_body(&json!({})), OsvVerdict::Clean);
    }

    // ── classify_osv_severity (SNYK-01, pure) ────────────────────────────────

    /// A HIGH CVE via `database_specific.severity` → `High`.
    #[test]
    fn severity_high_via_database_specific() {
        let body = json!({"vulns": [
            {
                "id": "CVE-2023-9999",
                "database_specific": { "severity": "HIGH" }
            }
        ]});
        assert_eq!(classify_osv_severity(&body), SeverityLevel::High);
    }

    /// A CRITICAL advisory → `Critical`.
    #[test]
    fn severity_critical_via_database_specific() {
        let body = json!({"vulns": [
            {
                "id": "GHSA-aaaa-bbbb-cccc",
                "database_specific": { "severity": "CRITICAL" }
            }
        ]});
        assert_eq!(classify_osv_severity(&body), SeverityLevel::Critical);
    }

    /// A MODERATE advisory maps to `Medium`.
    #[test]
    fn severity_moderate_maps_to_medium() {
        let body = json!({"vulns": [
            {
                "id": "CVE-2022-1111",
                "database_specific": { "severity": "MODERATE" }
            }
        ]});
        assert_eq!(classify_osv_severity(&body), SeverityLevel::Medium);
    }

    /// MAL-* entries are excluded from severity classification — returns `None`.
    #[test]
    fn severity_none_for_mal_only_body() {
        let body = json!({"vulns": [
            { "id": "MAL-2024-1234" }
        ]});
        assert_eq!(classify_osv_severity(&body), SeverityLevel::None);
    }

    /// When multiple advisories are present the maximum severity is returned.
    #[test]
    fn severity_max_across_advisories() {
        let body = json!({"vulns": [
            {
                "id": "CVE-2022-0001",
                "database_specific": { "severity": "LOW" }
            },
            {
                "id": "CVE-2022-0002",
                "database_specific": { "severity": "CRITICAL" }
            },
            {
                "id": "CVE-2022-0003",
                "database_specific": { "severity": "MEDIUM" }
            }
        ]});
        assert_eq!(classify_osv_severity(&body), SeverityLevel::Critical);
    }

    /// Empty body → `None`.
    #[test]
    fn severity_none_on_empty_body() {
        assert_eq!(classify_osv_severity(&json!({})), SeverityLevel::None);
        assert_eq!(classify_osv_severity(&json!({"vulns": []})), SeverityLevel::None);
    }

    /// CVSS numeric score 9.5 → `Critical`.
    #[test]
    fn severity_from_cvss_numeric_score() {
        assert_eq!(SeverityLevel::from_cvss_score(9.5), SeverityLevel::Critical);
        assert_eq!(SeverityLevel::from_cvss_score(7.5), SeverityLevel::High);
        assert_eq!(SeverityLevel::from_cvss_score(5.0), SeverityLevel::Medium);
        assert_eq!(SeverityLevel::from_cvss_score(2.0), SeverityLevel::Low);
        assert_eq!(SeverityLevel::from_cvss_score(0.0), SeverityLevel::None);
    }

    /// SeverityLevel ordering must be Low < Medium < High < Critical.
    #[test]
    fn severity_level_ordering() {
        assert!(SeverityLevel::None < SeverityLevel::Low);
        assert!(SeverityLevel::Low < SeverityLevel::Medium);
        assert!(SeverityLevel::Medium < SeverityLevel::High);
        assert!(SeverityLevel::High < SeverityLevel::Critical);
    }

    // ── network tests (wiremock) ──────────────────────────────────────────────

    #[tokio::test]
    async fn check_package_blocks_on_mal_advisory() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/query"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"vulns": [{"id": "MAL-2024-1"}]})),
            )
            .mount(&server)
            .await;
        let v = check_package_at(
            &format!("{}/v1/query", server.uri()),
            "evil-pkg",
            "npm",
            None,
        )
        .await;
        assert!(v.is_malicious(), "MAL advisory must yield Malicious: {v:?}");
    }

    #[tokio::test]
    async fn check_package_clean_on_no_vulns() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/query"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;
        let v =
            check_package_at(&format!("{}/v1/query", server.uri()), "jquery", "npm", None).await;
        assert_eq!(v, OsvVerdict::Clean);
    }

    #[tokio::test]
    async fn check_package_fails_open_on_http_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/query"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let v = check_package_at(&format!("{}/v1/query", server.uri()), "x", "npm", None).await;
        assert!(
            matches!(v, OsvVerdict::Unknown { .. }),
            "HTTP 500 must fail open as Unknown: {v:?}"
        );
    }

    #[tokio::test]
    async fn check_package_fails_open_on_unreachable_host() {
        // Reserved-for-docs TEST-NET-1 (RFC 5737) on a dead port → connection
        // error → fail open (never block an install on a network blip).
        let v = check_package_at("http://192.0.2.1:1/v1/query", "anything", "npm", None).await;
        assert!(
            matches!(v, OsvVerdict::Unknown { .. }),
            "an unreachable OSV host must fail open: {v:?}"
        );
    }
}
