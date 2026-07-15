//! GOLD-ADAPT-GOOSE-01 — OSV supply-chain malware gate.
//! GOLD-ADAPT-SNYK-01 — CVE/GHSA severity-threshold dep-blocking.
//!
//! Before NEOTH's wizard / auto-update installs a CLI toolchain package via
//! `npm install -g`, query the OSV database (api.osv.dev) for advisories naming
//! that package. A confirmed `MAL-*` hit BLOCKS unconditionally. CVE/GHSA hits
//! are classified by severity and block-or-warn depending on the threshold passed
//! by the caller. Production `SecurityPolicy` defaults to `High`; an explicit
//! `None` threshold is the opt-in warn-only mode.
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
/// OSV batch endpoint. The batch response is intentionally used only to
/// identify clean packages; positive non-malware rows are re-queried through
/// `OSV_QUERY_URL` because batch rows may omit advisory severity details.
const OSV_QUERY_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
/// OSV malware advisories are namespaced `MAL-…`.
const MALWARE_ID_PREFIX: &str = "MAL-";
/// Network timeout — fail open past this so a slow/unreachable OSV never hangs
/// or bricks an install.
const OSV_TIMEOUT: Duration = Duration::from_secs(6);

/// A parsed OSV endpoint whose transport policy has already been checked.
///
/// Production builds accept HTTPS only. Unit tests additionally accept plain
/// HTTP on the loopback interface so `wiremock` can exercise the real request
/// path without weakening the runtime boundary.
#[derive(Clone, Debug)]
struct OsvEndpoint(reqwest::Url);

impl OsvEndpoint {
    fn parse(raw: &str) -> Result<Self, String> {
        let endpoint =
            reqwest::Url::parse(raw).map_err(|error| format!("invalid OSV endpoint: {error}"))?;
        if !osv_transport_allowed(&endpoint) {
            return Err("OSV endpoint must use HTTPS".to_string());
        }
        Ok(Self(endpoint))
    }

    fn url(&self) -> reqwest::Url {
        self.0.clone()
    }
}

fn osv_transport_allowed(endpoint: &reqwest::Url) -> bool {
    if endpoint.scheme() == "https" {
        return true;
    }

    #[cfg(test)]
    {
        endpoint.scheme() == "http"
            && crate::providers::http_client::url_has_loopback_host(endpoint)
    }

    #[cfg(not(test))]
    {
        false
    }
}

// ── Severity classification (GOLD-ADAPT-SNYK-01) ─────────────────────────────

/// CVSS / OSV severity level, ordered from lowest to highest.
///
/// Derived from `vulns[].severity[].score` (CVSS vector), `database_specific.severity`
/// (GitHub advisory), or the raw `severity` string on the vuln object.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, serde::Deserialize,
)]
pub enum SeverityLevel {
    /// No severity information present in the advisory.
    None,
    Low,
    Medium,
    /// GOLD-ADAPT-SNYK-01 — default for `SecurityPolicy::dep_vuln_threshold`:
    /// blocks both High and Critical advisories on CLI installs.
    #[default]
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
        // F39 — api.osv.dev emits `severity[].score` as the full CVSS v3 VECTOR
        // string (not a number), so a High/Critical CVE expressed only as a
        // vector previously bucketed to `None` and never blocked. Compute the
        // CVSS v3.0/3.1 base score from the vector per the spec formula.
        if let Some(score) = cvss_base_score_from_vector(score_str.trim()) {
            return Self::from_cvss_score(score);
        }
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

/// F39 — CVSS v3.0/3.1 base-score impact sub-metric weight (C/I/A).
fn cvss_impact_weight(v: &str) -> Option<f64> {
    match v {
        "H" => Some(0.56),
        "L" => Some(0.22),
        "N" => Some(0.0),
        _ => None,
    }
}

/// F39 — compute the CVSS v3.0/3.1 base score from a vector string per the
/// first.org spec formula. Returns `None` if it isn't a v3 vector or a required
/// base metric is missing/invalid. (v2 vectors are not scored — rare in OSV's
/// CVE/GHSA feed; they fall back to `SeverityLevel::None`.)
fn cvss_base_score_from_vector(vector: &str) -> Option<f64> {
    if !(vector.starts_with("CVSS:3.0/") || vector.starts_with("CVSS:3.1/")) {
        return None;
    }
    let (mut av, mut ac, mut ui, mut scope_changed) = (None, None, None, None);
    let (mut c, mut i, mut a, mut pr_raw) = (None, None, None, None);
    for part in vector.split('/').skip(1) {
        let (k, v) = part.split_once(':')?;
        match k {
            "AV" => {
                av = Some(match v {
                    "N" => 0.85,
                    "A" => 0.62,
                    "L" => 0.55,
                    "P" => 0.2,
                    _ => return None,
                })
            }
            "AC" => {
                ac = Some(match v {
                    "L" => 0.77,
                    "H" => 0.44,
                    _ => return None,
                })
            }
            "UI" => {
                ui = Some(match v {
                    "N" => 0.85,
                    "R" => 0.62,
                    _ => return None,
                })
            }
            "S" => {
                scope_changed = Some(match v {
                    "U" => false,
                    "C" => true,
                    _ => return None,
                })
            }
            "C" => c = Some(cvss_impact_weight(v)?),
            "I" => i = Some(cvss_impact_weight(v)?),
            "A" => a = Some(cvss_impact_weight(v)?),
            "PR" => pr_raw = Some(v.to_string()),
            _ => {} // temporal / environmental / unknown metrics: ignored
        }
    }
    let (av, ac, ui, scope_changed) = (av?, ac?, ui?, scope_changed?);
    let (c, i, a) = (c?, i?, a?);
    // Privileges-Required weight depends on Scope (changed scope raises L/H).
    let pr = match (pr_raw?.as_str(), scope_changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let exploitability = 8.22 * av * ac * pr * ui;
    let raw = if scope_changed {
        (1.08 * (impact + exploitability)).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };
    // CVSS "roundup": smallest one-decimal value >= raw.
    Some((raw * 10.0).ceil() / 10.0)
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

#[derive(Serialize)]
struct OsvBatchRequest<'a> {
    queries: Vec<OsvQuery<'a>>,
}

fn has_next_page_token(body: &serde_json::Value) -> bool {
    match body.get("next_page_token") {
        None | Some(serde_json::Value::Null) => false,
        Some(serde_json::Value::String(token)) => !token.is_empty(),
        Some(_) => true,
    }
}

/// Borrowed package coordinates for one OSV query.
#[derive(Debug, Clone, Copy)]
pub struct PackageQuery<'a> {
    pub name: &'a str,
    pub ecosystem: &'a str,
    pub version: Option<&'a str>,
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
    if has_next_page_token(body) {
        return OsvVerdict::Unknown {
            reason: "OSV response requires pagination".to_string(),
        };
    }
    let vulns = match body.get("vulns") {
        None => return OsvVerdict::Clean,
        Some(serde_json::Value::Array(arr)) if arr.is_empty() => return OsvVerdict::Clean,
        Some(serde_json::Value::Array(arr)) => arr,
        Some(_) => {
            return OsvVerdict::Unknown {
                reason: "OSV response `vulns` field is not an array".to_string(),
            };
        }
    };

    // First pass: collect MAL-* ids (malware — unconditional block).
    let mal_ids: Vec<String> = vulns
        .iter()
        .filter_map(|v| v.get("id").and_then(|id| id.as_str()))
        .filter(|id| id.starts_with(MALWARE_ID_PREFIX))
        .map(|id| id.to_string())
        .collect();

    if !mal_ids.is_empty() {
        return OsvVerdict::Malicious {
            advisories: mal_ids,
        };
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

/// Query OSV for a complete manifest without one HTTP round-trip per clean
/// dependency. Batch rows that contain no vulnerabilities are conclusive.
/// Malware IDs are also conclusive from the batch row. Other positive rows are
/// queried once more via `/v1/query` so severity policy never runs on the
/// intentionally minimal batch representation.
///
/// The returned vector always has the same order and length as `queries`.
/// Any malformed/failed batch chunk becomes `Unknown` for that whole chunk;
/// strict callers therefore remain fail-closed.
pub async fn check_packages_batch(queries: &[PackageQuery<'_>]) -> Vec<OsvVerdict> {
    check_packages_batch_at(OSV_QUERY_BATCH_URL, OSV_QUERY_URL, queries).await
}

/// [`check_package`] against an explicit endpoint — the `wiremock` test seam.
async fn check_package_at(
    url: &str,
    name: &str,
    ecosystem: &str,
    version: Option<&str>,
) -> OsvVerdict {
    let endpoint = match OsvEndpoint::parse(url) {
        Ok(endpoint) => endpoint,
        Err(reason) => return OsvVerdict::Unknown { reason },
    };
    let client = match reqwest::Client::builder().timeout(OSV_TIMEOUT).build() {
        Ok(c) => c,
        Err(e) => {
            return OsvVerdict::Unknown {
                reason: format!("build http client: {e}"),
            };
        }
    };
    check_package_with_client(&client, &endpoint, name, ecosystem, version).await
}

async fn check_package_with_client(
    client: &reqwest::Client,
    endpoint: &OsvEndpoint,
    name: &str,
    ecosystem: &str,
    version: Option<&str>,
) -> OsvVerdict {
    let query = OsvQuery {
        package: OsvPackage { name, ecosystem },
        version,
    };
    let resp = match client.post(endpoint.url()).json(&query).send().await {
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

async fn check_packages_batch_at(
    batch_url: &str,
    query_url: &str,
    queries: &[PackageQuery<'_>],
) -> Vec<OsvVerdict> {
    if queries.is_empty() {
        return Vec::new();
    }
    let (batch_endpoint, query_endpoint) =
        match (OsvEndpoint::parse(batch_url), OsvEndpoint::parse(query_url)) {
            (Ok(batch_endpoint), Ok(query_endpoint)) => (batch_endpoint, query_endpoint),
            (batch, query) => {
                let reason = batch
                    .err()
                    .or_else(|| query.err())
                    .unwrap_or_else(|| "invalid OSV endpoint".to_string());
                return queries
                    .iter()
                    .map(|_| OsvVerdict::Unknown {
                        reason: reason.clone(),
                    })
                    .collect();
            }
        };
    let client = match reqwest::Client::builder().timeout(OSV_TIMEOUT).build() {
        Ok(client) => client,
        Err(e) => {
            let reason = format!("build http client: {e}");
            return queries
                .iter()
                .map(|_| OsvVerdict::Unknown {
                    reason: reason.clone(),
                })
                .collect();
        }
    };

    // OSV documents a finite batch size; keeping chunks comfortably below it
    // also bounds request bodies for very large generated lockfiles.
    const BATCH_SIZE: usize = 500;
    let mut verdicts = Vec::with_capacity(queries.len());
    for chunk in queries.chunks(BATCH_SIZE) {
        let request = OsvBatchRequest {
            queries: chunk
                .iter()
                .map(|query| OsvQuery {
                    package: OsvPackage {
                        name: query.name,
                        ecosystem: query.ecosystem,
                    },
                    version: query.version,
                })
                .collect(),
        };
        let response = match client
            .post(batch_endpoint.url())
            .json(&request)
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => response,
            Ok(response) => {
                let reason = format!("OSV batch returned HTTP {}", response.status());
                verdicts.extend(chunk.iter().map(|_| OsvVerdict::Unknown {
                    reason: reason.clone(),
                }));
                continue;
            }
            Err(e) => {
                let reason = format!("OSV batch request failed: {e}");
                verdicts.extend(chunk.iter().map(|_| OsvVerdict::Unknown {
                    reason: reason.clone(),
                }));
                continue;
            }
        };
        let body = match response.json::<serde_json::Value>().await {
            Ok(body) => body,
            Err(e) => {
                let reason = format!("OSV batch response parse: {e}");
                verdicts.extend(chunk.iter().map(|_| OsvVerdict::Unknown {
                    reason: reason.clone(),
                }));
                continue;
            }
        };
        if has_next_page_token(&body) {
            let reason = "OSV batch response requires pagination".to_string();
            verdicts.extend(chunk.iter().map(|_| OsvVerdict::Unknown {
                reason: reason.clone(),
            }));
            continue;
        }
        let Some(results) = body.get("results").and_then(serde_json::Value::as_array) else {
            let reason = "OSV batch response omitted `results`".to_string();
            verdicts.extend(chunk.iter().map(|_| OsvVerdict::Unknown {
                reason: reason.clone(),
            }));
            continue;
        };
        if results.len() != chunk.len() {
            let reason = format!(
                "OSV batch response count mismatch: expected {}, received {}",
                chunk.len(),
                results.len()
            );
            verdicts.extend(chunk.iter().map(|_| OsvVerdict::Unknown {
                reason: reason.clone(),
            }));
            continue;
        }

        for (query, row) in chunk.iter().zip(results) {
            if has_next_page_token(row) {
                verdicts.push(OsvVerdict::Unknown {
                    reason: "OSV batch row requires pagination".to_string(),
                });
                continue;
            }
            let vulnerabilities = match row.get("vulns") {
                None => {
                    verdicts.push(OsvVerdict::Clean);
                    continue;
                }
                Some(serde_json::Value::Array(vulns)) if vulns.is_empty() => {
                    verdicts.push(OsvVerdict::Clean);
                    continue;
                }
                Some(serde_json::Value::Array(vulns)) => vulns,
                Some(_) => {
                    verdicts.push(OsvVerdict::Unknown {
                        reason: "OSV batch row `vulns` field is not an array".to_string(),
                    });
                    continue;
                }
            };
            debug_assert!(!vulnerabilities.is_empty());
            let batch_verdict = classify_osv_body(row);
            if batch_verdict.is_malicious() {
                verdicts.push(batch_verdict);
                continue;
            }
            verdicts.push(
                check_package_with_client(
                    &client,
                    &query_endpoint,
                    query.name,
                    query.ecosystem,
                    query.version,
                )
                .await,
            );
        }
    }
    verdicts
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

    #[test]
    fn classify_pagination_as_unknown_instead_of_partial_clean() {
        assert!(matches!(
            classify_osv_body(&json!({
                "vulns": [],
                "next_page_token": "more-results"
            })),
            OsvVerdict::Unknown { .. }
        ));
        assert!(matches!(
            classify_osv_body(&json!({
                "vulns": [],
                "next_page_token": 1
            })),
            OsvVerdict::Unknown { .. }
        ));
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
        assert_eq!(
            classify_osv_severity(&json!({"vulns": []})),
            SeverityLevel::None
        );
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

    #[test]
    fn severity_from_cvss_vector_string_computes_base_score() {
        // F39 — a full CVSS v3 vector (what OSV emits) must score, not return None.
        // AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 (Critical, the classic RCE).
        assert_eq!(
            (cvss_base_score_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").unwrap()
                * 10.0)
                .round(),
            98.0
        );
        assert_eq!(
            SeverityLevel::from_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            SeverityLevel::Critical,
            "a vector-string High/Critical CVE must NOT fall through to None"
        );
        // AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N = low-end → Low/None bucket.
        assert!(
            SeverityLevel::from_cvss("CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")
                <= SeverityLevel::Medium
        );
        // Scope-changed raises the score (S:C path exercised).
        assert_eq!(
            SeverityLevel::from_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
            SeverityLevel::Critical
        );
        // Garbage / non-v3 → None (graceful).
        assert!(cvss_base_score_from_vector("not-a-vector").is_none());
        assert!(cvss_base_score_from_vector("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P").is_none());
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

    #[test]
    fn endpoint_transport_policy_is_https_except_for_test_loopback() {
        assert!(OsvEndpoint::parse("https://api.osv.dev/v1/query").is_ok());
        assert!(OsvEndpoint::parse("http://api.osv.dev/v1/query").is_err());
        assert!(OsvEndpoint::parse("http://192.0.2.1/v1/query").is_err());
        assert!(OsvEndpoint::parse("http://127.0.0.1:1234/v1/query").is_ok());
        assert!(OsvEndpoint::parse("http://[::1]:1234/v1/query").is_ok());
    }

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
    async fn batch_keeps_order_and_resolves_minimal_positive_rows() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [
                    {},
                    {"vulns": [{"id": "CVE-2026-1", "modified": "2026-01-01T00:00:00Z"}]},
                    {"vulns": [{"id": "MAL-2026-2", "modified": "2026-01-01T00:00:00Z"}]}
                ]
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/query"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "vulns": [{
                    "id": "CVE-2026-1",
                    "database_specific": {"severity": "HIGH"}
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let queries = [
            PackageQuery {
                name: "clean",
                ecosystem: "npm",
                version: Some("1.0.0"),
            },
            PackageQuery {
                name: "vulnerable",
                ecosystem: "npm",
                version: Some("2.0.0"),
            },
            PackageQuery {
                name: "malware",
                ecosystem: "npm",
                version: None,
            },
        ];
        let verdicts = check_packages_batch_at(
            &format!("{}/v1/querybatch", server.uri()),
            &format!("{}/v1/query", server.uri()),
            &queries,
        )
        .await;
        assert_eq!(verdicts.len(), queries.len());
        assert_eq!(verdicts[0], OsvVerdict::Clean);
        assert!(matches!(
            verdicts[1],
            OsvVerdict::Vulnerable {
                max_severity: SeverityLevel::High,
                ..
            }
        ));
        assert!(verdicts[2].is_malicious());
    }

    #[tokio::test]
    async fn batch_pagination_is_unknown_instead_of_partial_clean() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{"vulns": [], "next_page_token": "more"}]
            })))
            .mount(&server)
            .await;
        let verdicts = check_packages_batch_at(
            &format!("{}/v1/querybatch", server.uri()),
            &format!("{}/v1/query", server.uri()),
            &[PackageQuery {
                name: "paged",
                ecosystem: "npm",
                version: Some("1.0.0"),
            }],
        )
        .await;
        assert!(matches!(verdicts.as_slice(), [OsvVerdict::Unknown { .. }]));
    }

    #[tokio::test]
    async fn malformed_batch_shape_is_unknown_for_every_query() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"results": [{}]})))
            .mount(&server)
            .await;
        let queries = [
            PackageQuery {
                name: "one",
                ecosystem: "npm",
                version: None,
            },
            PackageQuery {
                name: "two",
                ecosystem: "npm",
                version: None,
            },
        ];
        let verdicts = check_packages_batch_at(
            &format!("{}/v1/querybatch", server.uri()),
            &format!("{}/v1/query", server.uri()),
            &queries,
        )
        .await;
        assert_eq!(verdicts.len(), queries.len());
        assert!(
            verdicts
                .iter()
                .all(|verdict| matches!(verdict, OsvVerdict::Unknown { .. }))
        );
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
        // Loopback port 1 is expected to be closed. HTTPS keeps the production
        // transport contract intact while exercising the connection-error path.
        let v = check_package_at("https://127.0.0.1:1/v1/query", "anything", "npm", None).await;
        assert!(
            matches!(v, OsvVerdict::Unknown { .. }),
            "an unreachable OSV host must fail open: {v:?}"
        );
    }
}
