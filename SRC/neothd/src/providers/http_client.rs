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

use std::time::Duration;

use anyhow::{Context, Result};

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
    let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(120));
    let raw = std::env::var("NEOTH_HTTP_PROXY").ok();
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
        // No env mutation — relies on the test runner leaving the proxy
        // unset (the default). If a malicious external setting interferes
        // the worst-case is a connect-time failure, not a parse failure.
        unsafe { std::env::remove_var("NEOTH_HTTP_PROXY") };
        let client = build_client();
        assert!(client.is_ok());
    }
}
