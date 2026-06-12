//! W-02 — OMI installer primitive (self-hosted local mode).
//!
//! OMI = Open Memory Interface. NEOTH's OM-01 lane consumes OMI
//! transcript streams via the operator's OWN self-hosted local OMI
//! backend (NOT `api.omi.me`). SC-14 codifies the constraint as
//! a hard rule: the daemon refuses to start if `omi.endpoint`
//! points at the cloud-managed service.
//!
//! This primitive ships:
//!
//!   - Default self-hosted local endpoint constant.
//!   - The forbidden cloud-managed hostname so SC-14 has one
//!     central source of truth.
//!   - `is_local_endpoint(url)` validator the wizard +
//!     daemon both call.
//!   - Probe for the operator's local OMI backend health.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Default OMI endpoint when the wizard sets up a self-hosted local backend.
/// Operators override via `freedom.yaml::omi.endpoint`.
pub const DEFAULT_OMI_ENDPOINT: &str = "http://127.0.0.1:8002";

/// The cloud-managed OMI hostname SC-14 forbids. Anything that
/// resolves to or names this host is rejected by
/// [`is_local_endpoint`].
pub const FORBIDDEN_CLOUD_HOSTNAME: &str = "api.omi.me";

/// Upstream docs URL for operators wanting to self-host the OMI
/// backend on a local machine.
pub const OMI_SELF_HOST_DOCS_URL: &str = "https://docs.omi.me/docs/developer/Backend/";

/// Validate an OMI endpoint URL per the SC-14 hard rule.
///
/// Returns `Ok(())` when the URL points at a loopback / private
/// host. Returns `Err(reason)` when the URL names the forbidden
/// cloud host or is malformed.
pub fn is_local_endpoint(url: &str) -> Result<(), String> {
    if url.is_empty() {
        return Err("empty endpoint".to_string());
    }
    let lower = url.to_lowercase();
    // Surface obvious scheme mistakes first.
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        return Err(format!(
            "OMI endpoint {url:?} must start with http:// or https://",
        ));
    }
    // Keep the explicit cloud-host denylist for a friendly, specific error.
    if lower.contains(FORBIDDEN_CLOUD_HOSTNAME) {
        return Err(format!(
            "OMI endpoint {url:?} resolves to the cloud-managed {FORBIDDEN_CLOUD_HOSTNAME} — \
             SC-14 hard rule requires a self-hosted local backend. See {OMI_SELF_HOST_DOCS_URL} \
             for self-hosting.",
        ));
    }
    // SC-14 / GOLD-SEC-07: real allowlist. The host must be loopback,
    // `localhost`, or an RFC-1918 / IPv6-ULA private address — NOT just
    // "anything except api.omi.me". This is the SSRF guard: a config that
    // bypasses the wizard (hand-edited YAML, future loader) still cannot
    // point the daemon's polled GET at an arbitrary public host.
    let host =
        extract_host(url).ok_or_else(|| format!("OMI endpoint {url:?} has no parseable host"))?;
    if !is_local_host(&host) {
        return Err(format!(
            "OMI endpoint {url:?} host {host:?} is not loopback or a private address — SC-14 \
             requires a self-hosted LOCAL backend. Use localhost, 127.0.0.1, ::1, or a private \
             10./172.16-31./192.168./fc00:: address. See {OMI_SELF_HOST_DOCS_URL}.",
        ));
    }
    Ok(())
}

/// Extract the host (no scheme, userinfo, or port) from a URL. Handles
/// `scheme://user@[ipv6]:port/path`. Returns `None` when there is no host.
fn extract_host(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return None;
    }
    // Strip userinfo (everything up to and including the last '@').
    let hostport = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);
    let host = if let Some(rest) = hostport.strip_prefix('[') {
        // Bracketed IPv6: [::1]:443 → ::1
        rest.split(']').next().unwrap_or("").to_string()
    } else {
        // Strip a trailing :port (only when it is all digits).
        match hostport.rsplit_once(':') {
            Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => h.to_string(),
            _ => hostport.to_string(),
        }
    };
    if host.is_empty() { None } else { Some(host) }
}

/// True iff `host` is `localhost`, a loopback IP, or a private
/// (RFC-1918 v4 / fc00::/7 ULA v6) address. Non-IP hostnames other than
/// `localhost` are rejected — they could resolve (or DNS-rebind) to a
/// public address, defeating the SSRF guard.
fn is_local_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        // GR-085 — also accept RFC-6598 CGNAT 100.64.0.0/10: Tailscale draws node
        // IPs from that range and NEOTH's wizard recommends Tailscale, so a
        // Tailscale-reachable OMI endpoint is legitimately local (private mesh),
        // not a public host the SSRF guard should reject.
        Ok(std::net::IpAddr::V4(v4)) => v4.is_loopback() || v4.is_private() || is_cgnat_v4(v4),
        // Loopback ::1 or Unique-Local-Address fc00::/7.
        Ok(std::net::IpAddr::V6(v6)) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
        Err(_) => false,
    }
}

/// RFC-6598 carrier-grade-NAT shared range `100.64.0.0/10` (100.64.0.0 –
/// 100.127.255.255) — the range Tailscale assigns node IPs from.
fn is_cgnat_v4(v4: std::net::Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 100 && (64..=127).contains(&o[1])
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
    if is_local_endpoint(url).is_err() {
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
        assert!(is_local_endpoint("http://127.0.0.1:8002").is_ok());
        assert!(is_local_endpoint("http://localhost:8002").is_ok());
    }

    #[test]
    fn validator_accepts_https_loopback() {
        assert!(is_local_endpoint("https://127.0.0.1:8443").is_ok());
    }

    #[test]
    fn validator_accepts_lan_addresses() {
        assert!(is_local_endpoint("http://192.168.1.50:8002").is_ok());
        assert!(is_local_endpoint("http://10.0.0.5:8002").is_ok());
    }

    #[test]
    fn validator_accepts_tailscale_cgnat_range_gr085() {
        // GR-085 — RFC-6598 100.64.0.0/10 (Tailscale) is local.
        assert!(is_local_endpoint("http://100.64.0.5:8002").is_ok());
        assert!(is_local_endpoint("http://100.127.255.254:8002").is_ok());
        // Boundaries: 100.63.x and 100.128.x are NOT in the /10.
        assert!(is_local_endpoint("http://100.63.0.1:8002").is_err());
        assert!(is_local_endpoint("http://100.128.0.1:8002").is_err());
    }

    #[test]
    fn validator_rejects_cloud_endpoint_with_message() {
        let err = is_local_endpoint("https://api.omi.me/v1/streams").unwrap_err();
        assert!(err.contains(FORBIDDEN_CLOUD_HOSTNAME));
        assert!(err.contains("SC-14"));
        assert!(err.contains("self-host"));
    }

    #[test]
    fn validator_rejects_cloud_case_insensitive() {
        let err = is_local_endpoint("HTTPS://API.OMI.ME/v1/streams").unwrap_err();
        assert!(err.contains(FORBIDDEN_CLOUD_HOSTNAME));
    }

    #[test]
    fn validator_rejects_empty_url() {
        let err = is_local_endpoint("").unwrap_err();
        assert!(err.contains("empty"));
    }

    #[test]
    fn validator_rejects_arbitrary_public_host() {
        // GOLD-SEC-07 / A-19: the old denylist accepted any host except
        // api.omi.me. The allowlist now rejects public hosts outright.
        assert!(is_local_endpoint("http://evil.example.com/v1/memories").is_err());
        assert!(is_local_endpoint("https://8.8.8.8/v1/memories").is_err());
        assert!(is_local_endpoint("http://169.254.169.254/latest/meta-data").is_err());
    }

    #[test]
    fn validator_rejects_userinfo_smuggling() {
        // The real host is evil.com, not localhost — must be rejected.
        let err = is_local_endpoint("http://localhost@evil.com/v1/memories").unwrap_err();
        assert!(err.contains("evil.com") || err.contains("not loopback"));
    }

    #[test]
    fn validator_accepts_ipv6_loopback_and_ula() {
        assert!(is_local_endpoint("http://[::1]:8002/").is_ok());
        assert!(is_local_endpoint("http://[fc00::1]:8002/").is_ok());
        // Public IPv6 is rejected.
        assert!(is_local_endpoint("http://[2001:4860:4860::8888]:8002/").is_err());
    }

    #[test]
    fn validator_accepts_172_16_private_range() {
        assert!(is_local_endpoint("http://172.16.0.1:8002").is_ok());
        // 172.32 is NOT private.
        assert!(is_local_endpoint("http://172.32.0.1:8002").is_err());
    }

    #[test]
    fn extract_host_strips_scheme_userinfo_port() {
        assert_eq!(extract_host("http://127.0.0.1:8002/v1").as_deref(), Some("127.0.0.1"));
        assert_eq!(extract_host("https://u:p@host.tld/x").as_deref(), Some("host.tld"));
        assert_eq!(extract_host("http://[::1]:443/").as_deref(), Some("::1"));
        assert_eq!(extract_host("http://localhost").as_deref(), Some("localhost"));
    }

    #[test]
    fn validator_rejects_non_http_scheme() {
        let err = is_local_endpoint("ws://127.0.0.1:8002").unwrap_err();
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
        let outcome = probe_endpoint("http://127.0.0.1:58999").await;
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
