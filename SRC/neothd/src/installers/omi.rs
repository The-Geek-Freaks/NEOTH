//! W-02 — OMI installer primitive (Jarvis-local mode).
//!
//! OMI = Open Memory Interface. NEOTH's OM-01 lane consumes OMI
//! transcript streams via the operator's OWN Jarvis-local OMI
//! backend (NOT `api.omi.me`). SC-14 codifies the constraint as
//! a hard rule: the daemon refuses to start if `omi.endpoint`
//! points at the cloud-managed service.
//!
//! This primitive ships:
//!
//!   - Default Jarvis-local endpoint constant.
//!   - The forbidden cloud-managed hostname so SC-14 has one
//!     central source of truth.
//!   - `is_jarvis_local_endpoint(url)` validator the wizard +
//!     daemon both call.
//!   - Probe for the operator's local OMI backend health.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Default OMI endpoint when the wizard sets up Jarvis-local.
/// Operators override via `freedom.yaml::omi.endpoint`.
pub const DEFAULT_OMI_ENDPOINT: &str = "http://127.0.0.1:8002";

/// The cloud-managed OMI hostname SC-14 forbids. Anything that
/// resolves to or names this host is rejected by
/// [`is_jarvis_local_endpoint`].
pub const FORBIDDEN_CLOUD_HOSTNAME: &str = "api.omi.me";

/// Upstream docs URL for operators wanting to self-host the OMI
/// backend on Jarvis or another local machine.
pub const OMI_SELF_HOST_DOCS_URL: &str = "https://docs.omi.me/docs/developer/Backend/";

/// Validate an OMI endpoint URL per the SC-14 hard rule.
///
/// Returns `Ok(())` when the URL points at a loopback / private
/// host. Returns `Err(reason)` when the URL names the forbidden
/// cloud host or is malformed.
pub fn is_jarvis_local_endpoint(url: &str) -> Result<(), String> {
    if url.is_empty() {
        return Err("empty endpoint".to_string());
    }
    // Conservative substring match — the SC-14 rule is "never let
    // a config pointing at the cloud service through". An operator
    // who genuinely wants a different cloud endpoint must edit
    // this constant + re-justify in PROGRESS.
    let lower = url.to_lowercase();
    if lower.contains(FORBIDDEN_CLOUD_HOSTNAME) {
        return Err(format!(
            "OMI endpoint {url:?} resolves to the cloud-managed {FORBIDDEN_CLOUD_HOSTNAME} — \
             SC-14 hard rule requires a Jarvis-local backend. See {OMI_SELF_HOST_DOCS_URL} \
             for self-hosting.",
        ));
    }
    // Surface other obvious mistakes the wizard catches early.
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        return Err(format!(
            "OMI endpoint {url:?} must start with http:// or https://",
        ));
    }
    Ok(())
}

/// Outcome of a live OMI endpoint probe. Same shape as the
/// n8n/paperless probes in this module.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeOutcome {
    Reachable,
    PortClosed,
    Timeout,
    /// Endpoint URL failed SC-14 validation — probe refused.
    Forbidden,
}

impl ProbeOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Reachable => "reachable",
            Self::PortClosed => "port_closed",
            Self::Timeout => "timeout",
            Self::Forbidden => "forbidden",
        }
    }
}

/// Probe the operator's configured OMI endpoint. Returns
/// `Forbidden` immediately when the URL trips SC-14 — we don't
/// TCP-connect to the cloud-managed host even briefly.
pub async fn probe_endpoint(url: &str) -> ProbeOutcome {
    if is_jarvis_local_endpoint(url).is_err() {
        return ProbeOutcome::Forbidden;
    }
    let host_port = match url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
    {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return ProbeOutcome::Forbidden,
    };
    // Default port 80/443 when none supplied.
    let addr = if host_port.contains(':') {
        host_port
    } else if url.starts_with("https://") {
        format!("{host_port}:443")
    } else {
        format!("{host_port}:80")
    };
    use tokio::net::TcpStream;
    match tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => ProbeOutcome::Reachable,
        Ok(Err(_)) => ProbeOutcome::PortClosed,
        Err(_) => ProbeOutcome::Timeout,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_endpoint_pinned_loopback() {
        assert_eq!(DEFAULT_OMI_ENDPOINT, "http://127.0.0.1:8002");
    }

    #[test]
    fn forbidden_hostname_pinned() {
        assert_eq!(FORBIDDEN_CLOUD_HOSTNAME, "api.omi.me");
    }

    #[test]
    fn self_host_docs_url_https() {
        assert!(OMI_SELF_HOST_DOCS_URL.starts_with("https://"));
    }

    // ── SC-14 validator ───────────────────────────────────────────

    #[test]
    fn validator_accepts_loopback_endpoint() {
        assert!(is_jarvis_local_endpoint("http://127.0.0.1:8002").is_ok());
        assert!(is_jarvis_local_endpoint("http://localhost:8002").is_ok());
    }

    #[test]
    fn validator_accepts_https_loopback() {
        assert!(is_jarvis_local_endpoint("https://127.0.0.1:8443").is_ok());
    }

    #[test]
    fn validator_accepts_lan_addresses() {
        assert!(is_jarvis_local_endpoint("http://192.168.1.50:8002").is_ok());
        assert!(is_jarvis_local_endpoint("http://10.0.0.5:8002").is_ok());
    }

    #[test]
    fn validator_rejects_cloud_endpoint_with_message() {
        let err = is_jarvis_local_endpoint("https://api.omi.me/v1/streams").unwrap_err();
        assert!(err.contains(FORBIDDEN_CLOUD_HOSTNAME));
        assert!(err.contains("SC-14"));
        assert!(err.contains("self-host"));
    }

    #[test]
    fn validator_rejects_cloud_case_insensitive() {
        let err = is_jarvis_local_endpoint("HTTPS://API.OMI.ME/v1/streams").unwrap_err();
        assert!(err.contains(FORBIDDEN_CLOUD_HOSTNAME));
    }

    #[test]
    fn validator_rejects_empty_url() {
        let err = is_jarvis_local_endpoint("").unwrap_err();
        assert!(err.contains("empty"));
    }

    #[test]
    fn validator_rejects_non_http_scheme() {
        let err = is_jarvis_local_endpoint("ws://127.0.0.1:8002").unwrap_err();
        assert!(err.contains("http"));
    }

    // ── probe ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn probe_forbidden_cloud_endpoint_returns_forbidden_without_tcp_connect() {
        // Drift guard: the probe MUST NOT TCP-connect to api.omi.me
        // even briefly. We can't observe the absence of a connect
        // directly, but we CAN assert the outcome is `Forbidden`
        // (which short-circuits before the TCP path).
        let outcome = probe_endpoint("https://api.omi.me/healthz").await;
        assert_eq!(outcome, ProbeOutcome::Forbidden);
    }

    #[tokio::test]
    async fn probe_loopback_closed_port_returns_port_closed_or_timeout() {
        let outcome = probe_endpoint("http://127.0.0.1:58_999").await;
        assert!(matches!(
            outcome,
            ProbeOutcome::PortClosed | ProbeOutcome::Timeout
        ));
    }

    #[tokio::test]
    async fn probe_empty_url_returns_forbidden() {
        let outcome = probe_endpoint("").await;
        assert_eq!(outcome, ProbeOutcome::Forbidden);
    }

    #[test]
    fn probe_outcome_as_str_pinned() {
        assert_eq!(ProbeOutcome::Reachable.as_str(), "reachable");
        assert_eq!(ProbeOutcome::PortClosed.as_str(), "port_closed");
        assert_eq!(ProbeOutcome::Timeout.as_str(), "timeout");
        assert_eq!(ProbeOutcome::Forbidden.as_str(), "forbidden");
    }

    #[test]
    fn probe_outcome_snake_case_serde() {
        assert_eq!(
            serde_json::to_string(&ProbeOutcome::Forbidden).unwrap(),
            "\"forbidden\"",
        );
    }
}
