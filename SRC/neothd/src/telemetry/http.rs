//! E-18 Workstream N (Session 22) — real HTTPS POST for the
//! opt-in telemetry surface. Consumes the privacy-pinned primitives
//! shipped Session 21 (parent `mod.rs`).
//!
//! Failure posture: telemetry NEVER fails the daemon. Every error
//! path is encoded as an `Ok(SendOutcome::…)` variant so the
//! caller's only `Err` surface is the upstream `reqwest` builder
//! failing to construct a client (which itself is a programmer-
//! error path, not an operator-runtime path).
//!
//! Endpoint validation:
//!   - The URL MUST be HTTPS. An `http://` URL fails fast with
//!     `SendOutcome::EndpointRejected { reason: "insecure scheme" }`
//!     so a misconfigured `freedom.yaml::telemetry.endpoint` can't
//!     silently downgrade an opt-in operator from TLS.
//!   - URL parsing errors surface as
//!     `SendOutcome::EndpointRejected { reason: <parse err> }`.
//!
//! No extra headers beyond `content-type: application/json`. The
//! request body is `serde_json::to_vec(payload)`. TLS is delegated
//! to the platform-default trust store via `reqwest::Client`.

use std::time::Duration;

use super::TelemetryPayload;

/// Per-request timeout. 5s = comfortably above realistic upstream
/// latency, well under a reasonable daemon-boot blocker.
pub const DEFAULT_SEND_TIMEOUT: Duration = Duration::from_secs(5);

/// One send-attempt outcome. Every variant is `Ok(…)` from the
/// caller's perspective — telemetry never bubbles errors that
/// would fail the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendOutcome {
    /// Endpoint accepted with a 2xx status code.
    Sent { status: u16 },
    /// Endpoint returned a non-2xx status. Telemetry treats this as
    /// graceful — the operator-side log shows the status; the
    /// daemon's posture is unchanged.
    UpstreamError { status: u16 },
    /// DNS / connect / TLS / read failure before any HTTP status
    /// came back. `detail` is the operator-readable error message.
    NetworkError { detail: String },
    /// Request didn't complete inside [`DEFAULT_SEND_TIMEOUT`].
    Timeout,
    /// Endpoint URL was rejected at validation time — non-HTTPS
    /// scheme, malformed URL, etc. Never reached the network.
    EndpointRejected { reason: String },
}

impl SendOutcome {
    /// True when the payload landed at the endpoint with a 2xx.
    /// Operators run `neoth telemetry send-now` + read this flag
    /// to confirm their opt-in is wired.
    pub fn is_sent(&self) -> bool {
        matches!(self, Self::Sent { .. })
    }

    /// Operator-readable one-line summary for CLI output.
    pub fn summary(&self) -> String {
        match self {
            Self::Sent { status } => format!("sent (HTTP {status})"),
            Self::UpstreamError { status } => format!("endpoint returned HTTP {status}"),
            Self::NetworkError { detail } => format!("network error: {detail}"),
            Self::Timeout => format!(
                "request timed out after {}s",
                DEFAULT_SEND_TIMEOUT.as_secs()
            ),
            Self::EndpointRejected { reason } => format!("endpoint rejected: {reason}"),
        }
    }
}

/// Validate the endpoint URL is HTTPS + well-formed. Pure-fn so
/// callers can re-use the check from CLI surfaces (`neoth telemetry
/// status` shows the resolved endpoint + whether it passes the
/// HTTPS gate).
///
/// Returns the parsed URL on success, `Err(reason)` operator-readable
/// otherwise. Caller treats `Err` as `SendOutcome::EndpointRejected`.
pub fn validate_endpoint(endpoint: &str) -> Result<reqwest::Url, String> {
    let parsed = reqwest::Url::parse(endpoint).map_err(|e| e.to_string())?;
    if parsed.scheme() != "https" {
        return Err(format!(
            "insecure scheme: {} (telemetry requires https)",
            parsed.scheme()
        ));
    }
    Ok(parsed)
}

/// Send the payload to `endpoint`. Returns an outcome, never panics,
/// never bubbles errors to the daemon.
///
/// Timeout pinned to [`DEFAULT_SEND_TIMEOUT`]. Use
/// [`send_payload_with_timeout`] for explicit-timeout call sites
/// (tests, operator `--timeout` override).
pub async fn send_payload(endpoint: &str, payload: &TelemetryPayload) -> SendOutcome {
    send_payload_with_timeout(endpoint, payload, DEFAULT_SEND_TIMEOUT).await
}

/// As [`send_payload`] but with an explicit timeout. Test sites
/// pass a short timeout (e.g. 100ms) so the test runner doesn't
/// stall on a hung endpoint.
pub async fn send_payload_with_timeout(
    endpoint: &str,
    payload: &TelemetryPayload,
    timeout: Duration,
) -> SendOutcome {
    let url = match validate_endpoint(endpoint) {
        Ok(u) => u,
        Err(reason) => return SendOutcome::EndpointRejected { reason },
    };

    let client = match reqwest::Client::builder().timeout(timeout).build() {
        Ok(c) => c,
        Err(e) => {
            return SendOutcome::NetworkError {
                detail: format!("client build failed: {e}"),
            };
        }
    };

    let body = match serde_json::to_vec(payload) {
        Ok(b) => b,
        Err(e) => {
            return SendOutcome::NetworkError {
                detail: format!("payload encode failed: {e}"),
            };
        }
    };

    let result = client
        .post(url)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await;

    match result {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if (200..300).contains(&status) {
                SendOutcome::Sent { status }
            } else {
                SendOutcome::UpstreamError { status }
            }
        }
        Err(e) if e.is_timeout() => SendOutcome::Timeout,
        Err(e) => SendOutcome::NetworkError {
            detail: e.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::build_payload;

    #[test]
    fn default_send_timeout_is_reasonable() {
        // Drift guard — a future tightening below 1s would break
        // slow ISPs; loosening above 30s would stall daemon boot.
        let secs = DEFAULT_SEND_TIMEOUT.as_secs();
        assert!((1..=30).contains(&secs));
    }

    #[test]
    fn validate_endpoint_accepts_https() {
        let url = validate_endpoint("https://example.com/path").unwrap();
        assert_eq!(url.scheme(), "https");
    }

    #[test]
    fn validate_endpoint_rejects_http() {
        let err = validate_endpoint("http://example.com").unwrap_err();
        assert!(
            err.contains("insecure scheme"),
            "must explain insecure scheme: {err}"
        );
    }

    #[test]
    fn validate_endpoint_rejects_file_scheme() {
        let err = validate_endpoint("file:///etc/passwd").unwrap_err();
        assert!(err.contains("insecure scheme"));
    }

    #[test]
    fn validate_endpoint_rejects_malformed_url() {
        assert!(validate_endpoint("not a url at all").is_err());
    }

    #[tokio::test]
    async fn send_payload_to_invalid_url_returns_endpoint_rejected() {
        let payload = build_payload("0.1.0", "alex");
        let outcome = send_payload("not a url", &payload).await;
        assert!(
            matches!(outcome, SendOutcome::EndpointRejected { .. }),
            "got {outcome:?}",
        );
    }

    #[tokio::test]
    async fn send_payload_to_http_url_rejected_without_network_call() {
        // Defence-in-depth: an http:// endpoint must NEVER be
        // dialled. The validation gate short-circuits before any
        // TLS connect attempt.
        let payload = build_payload("0.1.0", "alex");
        let outcome = send_payload("http://127.0.0.1:1/insecure", &payload).await;
        assert!(matches!(outcome, SendOutcome::EndpointRejected { .. }));
    }

    #[tokio::test]
    async fn send_payload_to_unreachable_host_returns_network_error_or_timeout() {
        // Hit a port that's almost certainly closed on loopback +
        // a short timeout so the test runner doesn't stall.
        let payload = build_payload("0.1.0", "alex");
        let outcome = send_payload_with_timeout(
            "https://127.0.0.1:1/no-server-here",
            &payload,
            Duration::from_millis(500),
        )
        .await;
        assert!(
            matches!(
                outcome,
                SendOutcome::NetworkError { .. } | SendOutcome::Timeout
            ),
            "unreachable host must surface as NetworkError or Timeout, got {outcome:?}",
        );
    }

    #[test]
    fn outcome_summary_carries_status_or_reason() {
        assert!(SendOutcome::Sent { status: 200 }.summary().contains("200"));
        assert!(
            SendOutcome::UpstreamError { status: 503 }
                .summary()
                .contains("503")
        );
        assert!(
            SendOutcome::NetworkError {
                detail: "dns lookup failed".into(),
            }
            .summary()
            .contains("dns")
        );
        assert!(SendOutcome::Timeout.summary().contains("timed out"));
        assert!(
            SendOutcome::EndpointRejected {
                reason: "insecure scheme: http".into(),
            }
            .summary()
            .contains("insecure")
        );
    }

    #[test]
    fn outcome_is_sent_only_for_two_xx() {
        assert!(SendOutcome::Sent { status: 200 }.is_sent());
        assert!(SendOutcome::Sent { status: 204 }.is_sent());
        assert!(!SendOutcome::UpstreamError { status: 500 }.is_sent());
        assert!(!SendOutcome::Timeout.is_sent());
        assert!(
            !SendOutcome::NetworkError {
                detail: String::new()
            }
            .is_sent()
        );
    }
}
