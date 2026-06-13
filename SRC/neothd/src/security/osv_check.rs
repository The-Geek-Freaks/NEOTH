//! GOLD-ADAPT-GOOSE-01 — OSV supply-chain malware gate.
//!
//! Before NEOTH's wizard / auto-update installs a CLI toolchain package via
//! `npm install -g`, query the OSV database (api.osv.dev) for MALWARE advisories
//! (`MAL-*` IDs) naming that package. A confirmed hit BLOCKS the install; a
//! network / HTTP / parse error FAILS OPEN (proceeds with a loud warning) so an
//! offline or transient failure never bricks onboarding.
//!
//! Adapted from goose `agents/extension_malware_check.rs` (queries
//! `api.osv.dev/v1/query`, filters `MAL-*`, fails open on network error). NEOTH's
//! installers previously ran `npm install -g <pkg>` with ZERO pre-install
//! advisory lookup — `security/dangerous_command.rs` is shell-pattern-only — so
//! this closes a supply-chain gap, directly relevant to the operator's
//! security-researcher profile and NEOTH's self-contained wizard installs.
//!
//! Only confirmed MALWARE (`MAL-*`) blocks. Regular vulnerability classes
//! (`CVE-*` / `GHSA-*`) are NOT install-blockers here — they would create
//! constant false-positive friction on legitimate toolchain packages, whereas a
//! `MAL-*` advisory means OSV's curators flagged the package itself as malicious.

use std::time::Duration;

use serde::Serialize;

/// OSV query endpoint.
const OSV_QUERY_URL: &str = "https://api.osv.dev/v1/query";
/// OSV malware advisories are namespaced `MAL-…`.
const MALWARE_ID_PREFIX: &str = "MAL-";
/// Network timeout — fail open past this so a slow/unreachable OSV never hangs
/// or bricks an install.
const OSV_TIMEOUT: Duration = Duration::from_secs(6);

/// Verdict from an OSV malware lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OsvVerdict {
    /// No malware advisory names this package — safe to install.
    Clean,
    /// One or more `MAL-*` advisories name this package — BLOCK the install.
    Malicious { advisories: Vec<String> },
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

/// Classify an OSV `/v1/query` response body: collect every `vulns[].id` that
/// begins with `MAL-`. Pure — no I/O, so it is unit-tested directly.
fn classify_osv_body(body: &serde_json::Value) -> OsvVerdict {
    let advisories: Vec<String> = body
        .get("vulns")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.get("id").and_then(|id| id.as_str()))
                .filter(|id| id.starts_with(MALWARE_ID_PREFIX))
                .map(|id| id.to_string())
                .collect()
        })
        .unwrap_or_default();
    if advisories.is_empty() {
        OsvVerdict::Clean
    } else {
        OsvVerdict::Malicious { advisories }
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

    #[test]
    fn classify_flags_mal_ids_only() {
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

    #[test]
    fn classify_clean_when_only_non_malware_vulns() {
        let body = json!({"vulns": [{"id": "CVE-2021-0001"}, {"id": "GHSA-aaaa"}]});
        assert_eq!(classify_osv_body(&body), OsvVerdict::Clean);
    }

    #[test]
    fn classify_clean_on_empty_or_missing_vulns() {
        assert_eq!(classify_osv_body(&json!({"vulns": []})), OsvVerdict::Clean);
        // OSV returns `{}` (no `vulns` key) when nothing matches.
        assert_eq!(classify_osv_body(&json!({})), OsvVerdict::Clean);
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
        let v = check_package_at(
            "http://192.0.2.1:1/v1/query",
            "anything",
            "npm",
            None,
        )
        .await;
        assert!(
            matches!(v, OsvVerdict::Unknown { .. }),
            "an unreachable OSV host must fail open: {v:?}"
        );
    }
}
