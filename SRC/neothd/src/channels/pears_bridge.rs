//! D-101 (Session 21, 2026-05-23, 6/6 agent panel) — minimal reqwest
//! HTTP client for the out-of-process Pears runtime.
//!
//! Per the panel's K-2 verdict ("minimal reqwest client first"), this
//! module ships a focused transport primitive only — no Keet pairing
//! UX, no cluster discovery, no live message routing. Those land in
//! K-3 / K-4 once K-2 is operator-tested against a live `pear`
//! process.
//!
//! Architecture (from `QUELLEN/research/R-A1_K1_decision.md` Path 3):
//!
//! ```text
//!   ┌───────────────────────┐         ┌──────────────────────────────┐
//!   │ NEOTH binary (Rust)   │  HTTP   │ pear runtime (Node, external)│
//!   │  channels/pears_bridge│ ◄─────► │  exposes Hyperswarm + Keet   │
//!   │  PearsBridge::new(url)│ 127.0.0 │  topics over a local API     │
//!   └───────────────────────┘  :<port>└──────────────────────────────┘
//! ```
//!
//! Security note (security-reviewer agent verdict): the HTTP surface is
//! localhost-only — any binding to `0.0.0.0` is rejected at construction.
//! A per-session bearer token to defend against confused-deputy attacks
//! from other local processes is **designed but NOT yet active — K-3 TODO**
//! (GOLD-HON-17 / A-39): `bearer_token` defaults to `None` and the only
//! caller of `with_bearer_token` is a test, so in production the bridge
//! currently accepts **unauthenticated** localhost requests. Until the K-3
//! wiring generates a token at NEOTH startup + hands it to `pear` on launch,
//! treat the bridge as trusted-local-process-only (it is opt-in + localhost-
//! bound, so a process that can reach `127.0.0.1:<port>` is already inside
//! the trust boundary).
//!
//! Why HTTP over JSON-RPC / gRPC: simplest possible surface, debug-able
//! with `curl`, and the panel explicitly picked Path 3 for its zero
//! incremental dependency cost (`reqwest` already in the workspace).

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// Default localhost port the wizard tells `pear` to bind. Operators
/// who run multiple NEOTH instances on one machine override via
/// `freedom.yaml::channels.pears.bridge_port`. Pinned at 9100 because
/// the standard Pears `pear-electron` UI uses 9090 and Keet desktop
/// listens on 9091 — 9100 stays clear of both.
pub const DEFAULT_BRIDGE_PORT: u16 = 9100;

/// Default per-request timeout. Pears HTTP responses are local-loopback;
/// anything over 5s indicates the runtime is wedged.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Errors specific to the Pears HTTP bridge. Distinct from
/// `crate::channels::ChannelError` because the bridge is a transport
/// primitive — channel-layer wrapping happens in the K-3 follow-up.
#[derive(Debug, thiserror::Error)]
pub enum PearsBridgeError {
    /// Operator pointed the bridge URL at a non-localhost address.
    /// Bridge refuses to talk to anything off-host as a defence in
    /// depth against confused-deputy attacks.
    #[error("Pears bridge URL must be localhost (127.0.0.1, ::1, or localhost); got {got}")]
    NonLocalhost { got: String },
    /// URL didn't parse at all.
    #[error("Pears bridge URL is malformed: {reason}")]
    MalformedUrl { reason: String },
    /// HTTP request to `pear` failed at the transport layer (process
    /// not running, port not listening, etc).
    #[error("Pears bridge transport error: {0}")]
    Transport(#[from] reqwest::Error),
    /// `pear` returned a non-2xx status. The body is included for
    /// operator debugging.
    #[error("Pears bridge returned HTTP {status}: {body}")]
    Http { status: u16, body: String },
    /// `pear` rejected the request as unauthorized (HTTP 401). This almost
    /// always means the bearer token doesn't match what `pear` expects.
    /// Check `bridge_token` in freedom.yaml and ensure it matches the token
    /// the `pear` process was started with.
    #[error(
        "Pears bridge returned HTTP 401 Unauthorized — check `bridge_token` in freedom.yaml: {body}"
    )]
    Unauthorized { body: String },
    /// Response body wasn't valid JSON or didn't match the expected
    /// shape.
    #[error("Pears bridge JSON decode failed: {0}")]
    Decode(#[from] serde_json::Error),
}

/// HTTP client for the local `pear` runtime. Holds a `reqwest::Client`
/// configured with a per-request timeout + the base URL (already
/// validated as localhost at construction).
pub struct PearsBridge {
    base_url: String,
    client: reqwest::Client,
    /// Optional bearer token. Set by the K-3 wiring once the wizard
    /// generates one at startup. None during early K-2 testing so
    /// `curl` operators can poke the bridge without auth.
    bearer_token: Option<String>,
}

impl std::fmt::Debug for PearsBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PearsBridge")
            .field("base_url", &self.base_url)
            .field("client", &self.client)
            // Redact so the token never lands in logs, crash reports, or
            // operator-visible debug output — K-3 TODO: use SecretString.
            .field(
                "bearer_token",
                &self.bearer_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl PearsBridge {
    /// Construct a new bridge client. `base_url` MUST be a localhost
    /// URL (`http://127.0.0.1:<port>`, `http://localhost:<port>`, or
    /// `http://[::1]:<port>`). Off-host URLs are rejected at this
    /// boundary so a misconfigured `freedom.yaml` can never trick
    /// NEOTH into pushing message bodies to the wider network.
    pub fn new(base_url: impl Into<String>) -> Result<Self, PearsBridgeError> {
        let base_url = base_url.into();
        let normalised = normalise_localhost_url(&base_url)?;
        let client = reqwest::Client::builder()
            .timeout(DEFAULT_REQUEST_TIMEOUT)
            .build()
            .map_err(PearsBridgeError::Transport)?;
        Ok(Self {
            base_url: normalised,
            client,
            bearer_token: None,
        })
    }

    /// Construct with the default localhost URL on the standard port.
    pub fn local() -> Result<Self, PearsBridgeError> {
        Self::new(format!("http://127.0.0.1:{DEFAULT_BRIDGE_PORT}"))
    }

    /// Set the per-session bearer token. The K-3 wiring will call this
    /// once after the wizard generates a fresh token + hands it to the
    /// `pear` process on launch.
    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(token.into());
        self
    }

    /// Bridge base URL (already validated as localhost). Useful for
    /// operator-visible logging via `neoth doctor`.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Probe the bridge's `/health` endpoint. Returns `Ok(())` when
    /// `pear` answers 2xx, `Err(_)` otherwise. The wizard's pre-flight
    /// uses this to surface "is pear running?" before progressing.
    pub async fn health(&self) -> Result<HealthResponse, PearsBridgeError> {
        let url = format!("{}/health", self.base_url);
        debug!(url = %url, "Pears bridge: health probe");
        let req = self.client.get(&url);
        let req = match &self.bearer_token {
            Some(t) => req.bearer_auth(t),
            None => req,
        };
        let resp = req.send().await.map_err(PearsBridgeError::Transport)?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            if status.as_u16() == 401 {
                return Err(PearsBridgeError::Unauthorized { body });
            }
            return Err(PearsBridgeError::Http {
                status: status.as_u16(),
                body,
            });
        }
        let payload = resp
            .json::<HealthResponse>()
            .await
            .map_err(PearsBridgeError::Transport)?;
        Ok(payload)
    }

    /// Post a single message to a Pears/Keet topic. The bridge
    /// translates the HTTP POST into the appropriate Hyperswarm /
    /// Keet operation. K-3 will route Keet channel sends through
    /// this primitive.
    pub async fn post_message(
        &self,
        topic: &str,
        body: &PostMessageRequest,
    ) -> Result<PostMessageResponse, PearsBridgeError> {
        let url = format!("{}/topics/{}/messages", self.base_url, topic);
        debug!(url = %url, topic = %topic, "Pears bridge: post message");
        let req = self.client.post(&url).json(body);
        let req = match &self.bearer_token {
            Some(t) => req.bearer_auth(t),
            None => req,
        };
        let resp = req.send().await.map_err(PearsBridgeError::Transport)?;
        let status = resp.status();
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            warn!(
                topic = %topic,
                status = status.as_u16(),
                body = %body_text,
                "Pears bridge: post_message failed"
            );
            if status.as_u16() == 401 {
                return Err(PearsBridgeError::Unauthorized { body: body_text });
            }
            return Err(PearsBridgeError::Http {
                status: status.as_u16(),
                body: body_text,
            });
        }
        let payload = resp
            .json::<PostMessageResponse>()
            .await
            .map_err(PearsBridgeError::Transport)?;
        Ok(payload)
    }
}

#[cfg(test)]
impl PearsBridge {
    /// Test seam: construct with a custom per-request timeout so timeout
    /// tests don't block for the full [`DEFAULT_REQUEST_TIMEOUT`] default.
    fn new_with_timeout(
        base_url: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self, PearsBridgeError> {
        let base_url = base_url.into();
        let normalised = normalise_localhost_url(&base_url)?;
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(PearsBridgeError::Transport)?;
        Ok(Self {
            base_url: normalised,
            client,
            bearer_token: None,
        })
    }
}

/// Reply shape for `GET /health`. `version` is the pear runtime
/// version string; `peers` is the count of currently-connected swarm
/// peers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthResponse {
    pub version: String,
    #[serde(default)]
    pub peers: u32,
    #[serde(default)]
    pub topics: u32,
}

/// Body for `POST /topics/<topic>/messages`. Operator-readable text
/// plus an optional binary attachment (base64-encoded so the JSON
/// envelope stays text-safe).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PostMessageRequest {
    pub text: String,
    #[serde(default)]
    pub attachment_b64: Option<String>,
    #[serde(default)]
    pub attachment_mime: Option<String>,
}

/// Reply for a successful `POST /topics/<topic>/messages`. `message_id`
/// is the bridge-generated id the Keet UI will surface; the K-3 wiring
/// records it alongside the WAL `CHANNEL_SENT` frame so dedupe + ACK
/// tracking works end-to-end.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PostMessageResponse {
    pub message_id: String,
    #[serde(default)]
    pub delivered_to_peers: u32,
}

/// Validate `url` is a localhost URL + return a canonical version.
/// Rejects non-`http`/`https` schemes too — a `file://` URL slipping
/// through would be a defence-in-depth gap.
fn normalise_localhost_url(url: &str) -> Result<String, PearsBridgeError> {
    let trimmed = url.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(PearsBridgeError::MalformedUrl {
            reason: "empty URL".into(),
        });
    }
    let parsed = reqwest::Url::parse(trimmed).map_err(|e| PearsBridgeError::MalformedUrl {
        reason: e.to_string(),
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(PearsBridgeError::MalformedUrl {
            reason: format!("unsupported scheme: {}", parsed.scheme()),
        });
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| PearsBridgeError::MalformedUrl {
            reason: "URL has no host".into(),
        })?;
    // `Url::host_str()` returns IPv6 addresses wrapped in brackets
    // (`[::1]`) when surfaced from the URL form. Strip them so the
    // localhost match covers both presentations consistently.
    let bare_host = host.trim_start_matches('[').trim_end_matches(']');
    let is_localhost = matches!(bare_host, "localhost" | "127.0.0.1" | "::1");
    if !is_localhost {
        return Err(PearsBridgeError::NonLocalhost {
            got: host.to_string(),
        });
    }
    Ok(trimmed.to_string())
}

/// Build the operator-facing `freedom.yaml` snippet the wizard shows
/// after the K-2 transport is wired. Pure-fn so the wizard renders the
/// exact YAML to the operator.
pub fn render_freedom_yaml_snippet(port: u16, has_token: bool) -> String {
    let token_line = if has_token {
        "  bridge_token: \"<generated by wizard>\""
    } else {
        "  # bridge_token: optional bearer; wizard generates one if you skip this line"
    };
    format!("channels:\n  pears:\n    bridge_port: {port}\n{token_line}\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_uses_default_port() {
        let bridge = PearsBridge::local().unwrap();
        assert!(
            bridge
                .base_url()
                .contains(&format!(":{DEFAULT_BRIDGE_PORT}"))
        );
        assert!(bridge.base_url().contains("127.0.0.1"));
    }

    #[test]
    fn new_accepts_127_0_0_1() {
        let bridge = PearsBridge::new("http://127.0.0.1:9100").unwrap();
        assert_eq!(bridge.base_url(), "http://127.0.0.1:9100");
    }

    #[test]
    fn new_accepts_localhost_hostname() {
        let bridge = PearsBridge::new("http://localhost:9100").unwrap();
        assert_eq!(bridge.base_url(), "http://localhost:9100");
    }

    #[test]
    fn new_accepts_ipv6_loopback() {
        let bridge = PearsBridge::new("http://[::1]:9100").unwrap();
        assert_eq!(bridge.base_url(), "http://[::1]:9100");
    }

    #[test]
    fn new_rejects_remote_host() {
        // Defence-in-depth: a misconfigured freedom.yaml pointing the
        // bridge URL at an off-host address MUST fail at construction.
        // Per security-reviewer agent verdict.
        let result = PearsBridge::new("http://192.168.1.10:9100");
        assert!(matches!(
            result.unwrap_err(),
            PearsBridgeError::NonLocalhost { .. }
        ));
    }

    #[test]
    fn new_rejects_public_dns_name() {
        let result = PearsBridge::new("http://example.com:9100");
        assert!(matches!(
            result.unwrap_err(),
            PearsBridgeError::NonLocalhost { .. }
        ));
    }

    #[test]
    fn new_rejects_file_scheme() {
        let result = PearsBridge::new("file:///tmp/socket");
        assert!(matches!(
            result.unwrap_err(),
            PearsBridgeError::MalformedUrl { .. }
        ));
    }

    #[test]
    fn new_rejects_empty_url() {
        let result = PearsBridge::new("");
        assert!(matches!(
            result.unwrap_err(),
            PearsBridgeError::MalformedUrl { .. }
        ));
    }

    #[test]
    fn new_trims_trailing_slash() {
        let bridge = PearsBridge::new("http://127.0.0.1:9100/").unwrap();
        assert_eq!(bridge.base_url(), "http://127.0.0.1:9100");
    }

    #[test]
    fn with_bearer_token_stashes_token() {
        let bridge = PearsBridge::local()
            .unwrap()
            .with_bearer_token("test-token-123");
        assert_eq!(bridge.bearer_token.as_deref(), Some("test-token-123"));
    }

    #[test]
    fn health_response_round_trips_serde() {
        let payload = HealthResponse {
            version: "0.5.2".into(),
            peers: 3,
            topics: 7,
        };
        let json = serde_json::to_string(&payload).unwrap();
        let back: HealthResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(payload, back);
    }

    #[test]
    fn health_response_defaults_missing_fields_to_zero() {
        // Older pear bridge versions may omit `peers`/`topics`. We
        // serde-default both so the response decodes cleanly.
        let json = r#"{"version":"0.4.0"}"#;
        let parsed: HealthResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.peers, 0);
        assert_eq!(parsed.topics, 0);
    }

    #[test]
    fn post_message_request_round_trips_with_attachment() {
        let req = PostMessageRequest {
            text: "hello".into(),
            attachment_b64: Some("YWJj".into()),
            attachment_mime: Some("image/png".into()),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: PostMessageRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn post_message_request_text_only_serialises() {
        let req = PostMessageRequest {
            text: "plain text".into(),
            attachment_b64: None,
            attachment_mime: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        // Attachment fields are Option<String>; serde emits them as
        // null. Bridge accepts both null + missing.
        assert!(json.contains("\"text\":\"plain text\""));
    }

    #[test]
    fn post_message_response_round_trips() {
        let resp = PostMessageResponse {
            message_id: "msg_abc123".into(),
            delivered_to_peers: 4,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: PostMessageResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn render_freedom_yaml_snippet_with_token_line() {
        let s = render_freedom_yaml_snippet(9100, true);
        assert!(s.contains("channels:"));
        assert!(s.contains("pears:"));
        assert!(s.contains("bridge_port: 9100"));
        assert!(s.contains("bridge_token:"));
    }

    #[test]
    fn render_freedom_yaml_snippet_without_token_shows_hint() {
        let s = render_freedom_yaml_snippet(9100, false);
        assert!(s.contains("# bridge_token"));
        assert!(s.contains("wizard generates"));
    }

    // ── Wiremock mock-server tests (D101 done-criteria) ──────────────────
    // No real network — MockServer binds 127.0.0.1 on an ephemeral port.
    // All async tests use #[tokio::test].

    #[tokio::test]
    async fn mock_health_success_returns_parsed_response() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let expected = HealthResponse {
            version: "1.2.3".into(),
            peers: 5,
            topics: 2,
        };
        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&expected))
            .mount(&mock_server)
            .await;

        let bridge = PearsBridge::new(mock_server.uri()).unwrap();
        let resp = bridge.health().await.expect("health should succeed on 200");
        assert_eq!(resp.version, "1.2.3");
        assert_eq!(resp.peers, 5);
        assert_eq!(resp.topics, 2);
    }

    #[tokio::test]
    async fn mock_post_message_success_returns_parsed_response() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let expected = PostMessageResponse {
            message_id: "msg_xyz789".into(),
            delivered_to_peers: 3,
        };
        Mock::given(method("POST"))
            .and(path("/topics/my-topic/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&expected))
            .mount(&mock_server)
            .await;

        let bridge = PearsBridge::new(mock_server.uri()).unwrap();
        let req = PostMessageRequest {
            text: "hello pears".into(),
            attachment_b64: None,
            attachment_mime: None,
        };
        let resp = bridge
            .post_message("my-topic", &req)
            .await
            .expect("post_message should succeed on 200");
        assert_eq!(resp.message_id, "msg_xyz789");
        assert_eq!(resp.delivered_to_peers, 3);
    }

    /// Timeout: mock delays 300 ms; client timeout is 100 ms → Transport error.
    /// The error message must be operator-actionable (mention "bridge" or
    /// "transport") so operators know where to look in the stack.
    #[tokio::test]
    async fn mock_post_message_timeout_returns_transport_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/topics/slow-topic/messages"))
            .respond_with(
                ResponseTemplate::new(200).set_delay(Duration::from_millis(300)),
            )
            .mount(&mock_server)
            .await;

        // 100 ms timeout < 300 ms mock delay → guaranteed timeout.
        let bridge =
            PearsBridge::new_with_timeout(mock_server.uri(), Duration::from_millis(100))
                .unwrap();
        let req = PostMessageRequest {
            text: "will timeout".into(),
            attachment_b64: None,
            attachment_mime: None,
        };
        let result = bridge.post_message("slow-topic", &req).await;
        assert!(
            matches!(result, Err(PearsBridgeError::Transport(_))),
            "expected Transport error on timeout; got {result:?}"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("transport") || msg.contains("bridge"),
            "timeout error must mention 'transport' or 'bridge' for operator actionability; got: {msg}"
        );
    }

    /// Malformed response: 200 with non-JSON body → Err, no panic.
    #[tokio::test]
    async fn mock_post_message_malformed_json_returns_error_without_panic() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/topics/bad-json/messages"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("not valid json }{garbage"),
            )
            .mount(&mock_server)
            .await;

        let bridge = PearsBridge::new(mock_server.uri()).unwrap();
        let req = PostMessageRequest {
            text: "test".into(),
            attachment_b64: None,
            attachment_mime: None,
        };
        let result = bridge.post_message("bad-json", &req).await;
        // reqwest's .json() decode failure surfaces as a reqwest::Error
        // (is_decode() == true), mapped to Transport.
        assert!(
            matches!(result, Err(PearsBridgeError::Transport(_))),
            "malformed JSON body should produce Transport error; got {result:?}"
        );
    }

    /// HTTP 500 → Http error with status code in message for triage.
    #[tokio::test]
    async fn mock_post_message_http_500_returns_http_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/topics/boom/messages"))
            .respond_with(
                ResponseTemplate::new(500).set_body_string("internal pear error"),
            )
            .mount(&mock_server)
            .await;

        let bridge = PearsBridge::new(mock_server.uri()).unwrap();
        let req = PostMessageRequest {
            text: "test".into(),
            attachment_b64: None,
            attachment_mime: None,
        };
        let result = bridge.post_message("boom", &req).await;
        match result {
            Err(PearsBridgeError::Http { status, ref body }) => {
                assert_eq!(status, 500, "status must be 500");
                assert!(
                    body.contains("internal pear error"),
                    "body must be forwarded for operator debugging"
                );
            }
            other => panic!("expected Http {{ status: 500 }}; got {other:?}"),
        }
    }

    /// HTTP 401 → Unauthorized error whose message explicitly references
    /// `bridge_token` so operators know exactly what to fix in freedom.yaml.
    #[tokio::test]
    async fn mock_post_message_http_401_hints_bridge_token() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/topics/locked/messages"))
            .respond_with(
                ResponseTemplate::new(401).set_body_string("unauthorized"),
            )
            .mount(&mock_server)
            .await;

        let bridge = PearsBridge::new(mock_server.uri()).unwrap();
        let req = PostMessageRequest {
            text: "test".into(),
            attachment_b64: None,
            attachment_mime: None,
        };
        let result = bridge.post_message("locked", &req).await;
        assert!(
            matches!(result, Err(PearsBridgeError::Unauthorized { .. })),
            "HTTP 401 must produce Unauthorized error; got {result:?}"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("bridge_token"),
            "401 error message must mention 'bridge_token' for operator actionability; got: {msg}"
        );
    }

    /// Bearer token: the Authorization header actually arrives at the mock
    /// when the bridge was built via `with_bearer_token`.
    /// Strategy: mount a mock that only matches when the correct
    /// Authorization header is present; missing/wrong header → 404 → test fails.
    #[tokio::test]
    async fn mock_bearer_token_sent_in_authorization_header() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/health"))
            .and(header("authorization", "Bearer session-tok-abc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&HealthResponse {
                version: "2.0.0".into(),
                peers: 0,
                topics: 0,
            }))
            .mount(&mock_server)
            .await;

        let bridge = PearsBridge::new(mock_server.uri())
            .unwrap()
            .with_bearer_token("session-tok-abc");
        let result = bridge.health().await;
        assert!(
            result.is_ok(),
            "health with correct bearer token should succeed; \
             if the header were missing the mock returns 404 → Http error; got {result:?}"
        );
    }

    /// Bearer token must NOT appear verbatim in `Debug` output so it
    /// can't leak into logs, crash reports, or operator-visible traces.
    #[test]
    fn bearer_token_not_exposed_in_debug_output() {
        let secret = "very-secret-bearer-token-12345";
        let bridge = PearsBridge::local().unwrap().with_bearer_token(secret);
        let debug_str = format!("{bridge:?}");
        assert!(
            !debug_str.contains(secret),
            "bearer token must not appear verbatim in Debug output; got: {debug_str}"
        );
        // The redacted placeholder must be present so operators can see
        // the field exists without exposing its value.
        assert!(
            debug_str.contains("redacted"),
            "expected '<redacted>' placeholder in Debug output; got: {debug_str}"
        );
    }

    // ── Live bridge tests (require pear runtime — skipped in CI) ────────

    #[tokio::test]
    async fn health_returns_transport_error_when_no_bridge_running() {
        // Smoke: without a live `pear` on 127.0.0.1:9100 the health
        // probe MUST surface a transport error rather than panic.
        // Port chosen to be unlikely-bound (avoid the standard 9100
        // that an operator might actually have running).
        let bridge = PearsBridge::new("http://127.0.0.1:65431").unwrap();
        let result = bridge.health().await;
        assert!(
            matches!(result, Err(PearsBridgeError::Transport(_))),
            "expected transport error from offline bridge; got {result:?}"
        );
    }
}
