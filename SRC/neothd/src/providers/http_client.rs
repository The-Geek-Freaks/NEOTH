//! Shared `reqwest::Client` builder for every cloud provider. Phase 3b
//! wires in optional SOCKS5 routing through the local Hysteria proxy when
//! `NEOTH_HTTP_PROXY` is set (e.g. `socks5://127.0.0.1:1080`).
//!
//! Operators who run Hysteria for encrypted egress pin the daemon to it
//! by exporting `NEOTH_HTTP_PROXY` before `neothd serve`. Adapters that
//! call [`build_client`] inherit the proxy automatically; tests + one-shot
//! CLIs hit it without realising.
//!
//! Self-contained-rule note: NEOTH never hardcodes a remote proxy. The
//! env var ALWAYS points at a localhost endpoint (the local Hysteria
//! listener); routing the final hop to the operator's upstream server is
//! Hysteria's concern, not ours.

use std::sync::RwLock;
use std::time::Duration;

use anyhow::{Context, Result};

/// Process-wide proxy override installed at daemon startup by the Hysteria
/// supervisor (`transport::hysteria::install_as_process_proxy`). Consulted
/// BEFORE the `NEOTH_HTTP_PROXY` env var so the daemon can wire the proxy
/// at runtime without `std::env::set_var` — which is unsound once the
/// multi-threaded Tokio runtime is up (daemon startup runs inside it).
/// RwLock (not OnceLock): a re-provisioned supervisor on a new SOCKS5
/// port must be able to re-install — last-write-wins, matching the old
/// env-write semantics. Never written from tests (would leak a proxy
/// into every parallel `build_client` test in the process).
static PROCESS_PROXY: RwLock<Option<String>> = RwLock::new(None);

/// Install (or replace) the process-wide proxy URL for every subsequent
/// `build_client*` call. Last write wins.
pub(crate) fn set_process_proxy(url: &str) {
    *PROCESS_PROXY
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(url.to_string());
}

/// Parse a candidate proxy URL — pure function so the parser can be
/// unit-tested without setting the process-global `NEOTH_HTTP_PROXY`
/// env var. `Ok(Some(_))` = a proxy is configured, `Ok(None)` = unset
/// or empty, `Err(_)` = malformed URL.
pub fn parse_proxy_setting(value: Option<&str>) -> Result<Option<reqwest::Proxy>> {
    let Some(raw) = value else { return Ok(None) };
    if raw.is_empty() {
        return Ok(None);
    }
    let proxy = reqwest::Proxy::all(raw).context("parse NEOTH_HTTP_PROXY")?;
    Ok(Some(proxy))
}

/// Build a reqwest client with the project's default timeout + the
/// optional SOCKS5 proxy from `NEOTH_HTTP_PROXY`. Defaults to a direct
/// client when the env var is unset.
pub fn build_client() -> Result<reqwest::Client> {
    build_client_with(reqwest::redirect::Policy::default())
}

/// Build a reqwest client that follows the operator's proxy configuration
/// but never follows HTTP redirects. Used by `tools::web_fetch` (SX-01):
/// blocking redirects closes the bypass where an attacker controls a
/// public URL that 302s into a private network after the initial
/// `validate_url` host check has passed.
pub fn build_client_no_redirect() -> Result<reqwest::Client> {
    build_client_with(reqwest::redirect::Policy::none())
}

/// Build a direct, no-redirect client for a loopback-only provider endpoint.
/// Loopback traffic must never be sent through an operator/environment proxy:
/// that would disclose local prompts and let a proxy impersonate the trusted
/// local service. Redirects are disabled so a local endpoint cannot bounce a
/// request onto a different origin after locality was classified.
pub fn build_direct_client_no_redirect() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .context("build direct no-redirect reqwest client")
}

/// Return whether a parsed URL names the local loopback interface.
///
/// Match the typed host instead of reparsing `host_str()`: the `url` crate
/// renders IPv6 host strings with brackets (`[::1]`), which `IpAddr::from_str`
/// intentionally rejects. Keeping this in the shared HTTP boundary prevents
/// provider, channel, tool, and security clients from drifting on IPv6.
pub(crate) fn url_has_loopback_host(url: &reqwest::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(host)) => {
            host.trim_end_matches('.').eq_ignore_ascii_case("localhost")
        }
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

fn build_client_with(redirect_policy: reqwest::redirect::Policy) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .redirect(redirect_policy);
    let raw = PROCESS_PROXY
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
        .or_else(|| std::env::var("NEOTH_HTTP_PROXY").ok());
    if let Some(proxy) = parse_proxy_setting(raw.as_deref())? {
        builder = builder.proxy(proxy);
        if let Some(url) = raw.as_deref() {
            tracing::info!(proxy = %url, "provider HTTP routed through proxy");
        }
    }
    builder.build().context("build reqwest client")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests exercise the pure `parse_proxy_setting` function rather than
    // mutating the process-global `NEOTH_HTTP_PROXY` env var. Avoids the
    // long-standing flake where this test serialised the env mutation
    // under a private mutex while parallel tests in other modules (the
    // OpenAI adapter constructor, for example) called `build_client` and
    // observed the torn state without holding the lock.

    #[test]
    fn parse_unset_returns_none() {
        let proxy = parse_proxy_setting(None).unwrap();
        assert!(proxy.is_none());
    }

    #[test]
    fn parse_empty_string_treats_as_unset() {
        let proxy = parse_proxy_setting(Some("")).unwrap();
        assert!(proxy.is_none());
    }

    #[test]
    fn parse_valid_socks5_url_returns_proxy() {
        let proxy = parse_proxy_setting(Some("socks5://127.0.0.1:1080")).unwrap();
        assert!(proxy.is_some());
    }

    #[test]
    fn parse_invalid_url_returns_error() {
        let err = parse_proxy_setting(Some("not a url")).unwrap_err();
        assert!(err.to_string().contains("NEOTH_HTTP_PROXY"));
    }

    #[test]
    fn build_client_works_without_proxy() {
        // Serialize the NEOTH_HTTP_PROXY removal against other env tests
        // (crate::test_env) so a concurrent setter can't reintroduce it.
        let _env = crate::test_env::lock();
        unsafe { std::env::remove_var("NEOTH_HTTP_PROXY") };
        let client = build_client();
        assert!(client.is_ok());
    }

    #[test]
    fn direct_client_ignores_malformed_proxy_environment() {
        let _env = crate::test_env::lock();
        let previous = std::env::var_os("NEOTH_HTTP_PROXY");
        unsafe { std::env::set_var("NEOTH_HTTP_PROXY", "not a url") };
        assert!(build_direct_client_no_redirect().is_ok());
        match previous {
            Some(value) => unsafe { std::env::set_var("NEOTH_HTTP_PROXY", value) },
            None => unsafe { std::env::remove_var("NEOTH_HTTP_PROXY") },
        }
    }

    #[test]
    fn loopback_host_detection_handles_typed_ipv4_ipv6_and_localhost() {
        for endpoint in [
            "http://localhost:8080",
            "http://localhost.:8080",
            "http://127.0.0.1:8080",
            "http://127.42.0.9:8080",
            "http://[::1]:8080",
            "https://[0:0:0:0:0:0:0:1]:8443",
        ] {
            let parsed = reqwest::Url::parse(endpoint).unwrap();
            assert!(url_has_loopback_host(&parsed), "not loopback: {endpoint}");
        }
        for endpoint in [
            "https://localhost.evil.test",
            "https://192.168.1.4",
            "https://[fc00::1]",
        ] {
            let parsed = reqwest::Url::parse(endpoint).unwrap();
            assert!(!url_has_loopback_host(&parsed), "loopback: {endpoint}");
        }
    }
}
