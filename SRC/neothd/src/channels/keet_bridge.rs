//! Hardened client contract for the repository-owned Keet companion.
//!
//! Keet does not expose a supported public room/message automation API. NEOTH
//! therefore talks only to its own versioned local companion, which provides a
//! separate Keet-identity Pear/Hyperswarm channel rather than reading existing
//! Keet application rooms. The companion is considered usable only after an
//! authenticated capability handshake proves that both text send and text
//! receive are ready. An outbound-only process is rejected: it must never make
//! the channel appear live.

use std::time::Duration;

use base64::Engine as _;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};

use crate::secret::SecretString;

pub const BRIDGE_PROTOCOL: &str = "neoth-keet-bridge";
pub const BRIDGE_PROTOCOL_VERSION: u16 = 1;
pub const DEFAULT_BRIDGE_URL: &str = "http://127.0.0.1:9130";

const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_TIMEOUT: Duration = Duration::from_secs(35);
const POLL_WAIT_MS: u32 = 25_000;
const POLL_LIMIT: u8 = 50;
const POST_ATTEMPTS: usize = 2;
const POST_RETRY_DELAY: Duration = Duration::from_millis(100);
const MAX_CONTROL_BODY: usize = 64 * 1024;
const MAX_MESSAGES_BODY: usize = 1024 * 1024;
const MAX_SAFE_CURSOR_SEQUENCE: u64 = 9_007_199_254_740_991;

#[derive(Debug, thiserror::Error)]
pub enum KeetBridgeError {
    #[error("Keet bridge URL must be an HTTP(S) loopback origin")]
    InvalidUrl,
    #[error("Keet bridge bearer token is missing or invalid")]
    InvalidToken,
    #[error(
        "Keet topic must be the canonical `nk1_…` capability printed by `neoth-keet-bridge setup`"
    )]
    InvalidTopic,
    #[error("Keet sender ID must be a canonical 32-byte unpadded base64url identity")]
    InvalidSenderId,
    #[error("Keet idempotency key must contain 1..128 URL-safe ASCII characters")]
    InvalidIdempotencyKey,
    #[error("Keet bridge request failed during {operation}")]
    Transport { operation: &'static str },
    #[error("Keet bridge authentication failed")]
    Unauthorized,
    #[error("Keet bridge returned HTTP {status} during {operation}")]
    Http {
        operation: &'static str,
        status: u16,
    },
    #[error("Keet bridge response exceeded the {limit}-byte safety limit")]
    ResponseTooLarge { limit: usize },
    #[error("Keet bridge returned invalid JSON during {operation}")]
    InvalidJson { operation: &'static str },
    #[error("Keet bridge protocol rejected: {0}")]
    Protocol(&'static str),
}

#[derive(Clone)]
pub struct KeetBridge {
    base_url: reqwest::Url,
    token: SecretString,
    http: reqwest::Client,
}

impl std::fmt::Debug for KeetBridge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KeetBridge")
            .field("base_url", &self.base_url.as_str())
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl KeetBridge {
    pub fn new(base_url: &str, token: SecretString) -> Result<Self, KeetBridgeError> {
        let base_url = normalize_loopback_origin(base_url)?;
        validate_bearer_token(token.expose())?;
        let http = reqwest::Client::builder()
            .connect_timeout(CONTROL_TIMEOUT)
            // A loopback-only trust boundary must stay loopback-only. Do not
            // let a compromised companion redirect an authenticated request
            // to a different origin or silently substitute another endpoint.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| KeetBridgeError::Transport {
                operation: "client setup",
            })?;
        Ok(Self {
            base_url,
            token,
            http,
        })
    }

    pub fn base_url(&self) -> &str {
        self.base_url.as_str().trim_end_matches('/')
    }

    /// Authenticate and require the exact v1 full-duplex capability contract.
    pub async fn health(&self) -> Result<BridgeHealth, KeetBridgeError> {
        let url = self.endpoint(&["v1", "health"])?;
        let response = self
            .http
            .get(url)
            .timeout(CONTROL_TIMEOUT)
            .bearer_auth(self.token.expose())
            .send()
            .await
            .map_err(|_| KeetBridgeError::Transport {
                operation: "health check",
            })?;
        let health: BridgeHealth = decode_json(response, MAX_CONTROL_BODY, "health check").await?;
        validate_health(&health)?;
        Ok(health)
    }

    /// Full preflight for one room: full-duplex health plus an explicit joined
    /// topic state. The returned latest cursor is the safe first-run baseline.
    pub async fn probe_topic(&self, topic: &str) -> Result<KeetBridgeProbe, KeetBridgeError> {
        validate_topic(topic)?;
        let health = self.health().await?;
        let url = self.endpoint(&["v1", "topics", topic])?;
        let response = self
            .http
            .get(url)
            .timeout(CONTROL_TIMEOUT)
            .bearer_auth(self.token.expose())
            .send()
            .await
            .map_err(|_| KeetBridgeError::Transport {
                operation: "topic check",
            })?;
        let topic_state: TopicState =
            decode_json(response, MAX_CONTROL_BODY, "topic check").await?;
        validate_topic_state(&topic_state)?;
        Ok(KeetBridgeProbe {
            health,
            topic: topic_state,
        })
    }

    pub async fn poll_messages(
        &self,
        topic: &str,
        after: &str,
    ) -> Result<MessagesPage, KeetBridgeError> {
        validate_topic(topic)?;
        parse_cursor(after)?;
        // Revalidate capabilities on every long-poll. A companion that loses
        // receive support is immediately fail-closed instead of degrading to
        // an outbound-only channel behind the daemon's back.
        self.health().await?;
        let mut url = self.endpoint(&["v1", "topics", topic, "messages"])?;
        url.query_pairs_mut()
            .append_pair("after", after)
            .append_pair("wait_ms", &POLL_WAIT_MS.to_string())
            .append_pair("limit", &POLL_LIMIT.to_string());
        let response = self
            .http
            .get(url)
            .timeout(POLL_TIMEOUT)
            .bearer_auth(self.token.expose())
            .send()
            .await
            .map_err(|_| KeetBridgeError::Transport {
                operation: "receive poll",
            })?;
        let page: MessagesPage = decode_json(response, MAX_MESSAGES_BODY, "receive poll").await?;
        validate_messages_page(&page, after)?;
        Ok(page)
    }

    pub async fn post_message(
        &self,
        topic: &str,
        text: &str,
        reply_to: Option<&str>,
    ) -> Result<PostMessageResponse, KeetBridgeError> {
        let idempotency_key = uuid::Uuid::new_v4().to_string();
        self.post_message_idempotent(topic, text, reply_to, &idempotency_key)
            .await
    }

    /// Send with a caller-owned durable operation key. Transport/response-loss
    /// failures receive one bounded retry with the exact same key; callers with
    /// a persisted outbox may safely reuse it again after process restart.
    pub async fn post_message_idempotent(
        &self,
        topic: &str,
        text: &str,
        reply_to: Option<&str>,
        idempotency_key: &str,
    ) -> Result<PostMessageResponse, KeetBridgeError> {
        validate_topic(topic)?;
        validate_idempotency_key(idempotency_key)?;
        if text.trim().is_empty() || text.len() > 64 * 1024 {
            return Err(KeetBridgeError::Protocol(
                "outbound text must contain 1..65536 bytes",
            ));
        }
        if reply_to.is_some_and(|message_id| {
            message_id.is_empty()
                || message_id.len() > 1024
                || message_id.chars().any(char::is_control)
        }) {
            return Err(KeetBridgeError::Protocol("invalid reply target"));
        }
        // Sending is permitted only while the companion still proves BOTH
        // capabilities and confirms that this exact topic is joined.
        self.probe_topic(topic).await?;
        let url = self.endpoint(&["v1", "topics", topic, "messages"])?;
        let body = PostMessageRequest {
            text,
            reply_to,
            idempotency_key,
        };

        for attempt in 0..POST_ATTEMPTS {
            let sent = match self
                .http
                .post(url.clone())
                .timeout(CONTROL_TIMEOUT)
                .bearer_auth(self.token.expose())
                .json(&body)
                .send()
                .await
            {
                Ok(response) => {
                    decode_json::<PostMessageResponse>(response, MAX_CONTROL_BODY, "message send")
                        .await
                }
                Err(_) => Err(KeetBridgeError::Transport {
                    operation: "message send",
                }),
            };
            match sent {
                Ok(sent) => {
                    if sent.message_id.trim().is_empty()
                        || sent.message_id.len() > 1024
                        || sent.message_id.chars().any(char::is_control)
                    {
                        return Err(KeetBridgeError::Protocol(
                            "companion returned an invalid message id",
                        ));
                    }
                    return Ok(sent);
                }
                Err(KeetBridgeError::Transport { .. }) if attempt + 1 < POST_ATTEMPTS => {
                    tokio::time::sleep(POST_RETRY_DELAY).await;
                }
                Err(KeetBridgeError::Http { status, .. })
                    if status >= 500 && attempt + 1 < POST_ATTEMPTS =>
                {
                    tokio::time::sleep(POST_RETRY_DELAY).await;
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("POST_ATTEMPTS is non-zero")
    }

    fn endpoint(&self, segments: &[&str]) -> Result<reqwest::Url, KeetBridgeError> {
        let mut url = self.base_url.clone();
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|_| KeetBridgeError::InvalidUrl)?;
            path.clear();
            for segment in segments {
                path.push(segment);
            }
        }
        Ok(url)
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct BridgeHealth {
    pub protocol: String,
    pub protocol_version: u16,
    pub bridge_version: String,
    pub ready: bool,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct TopicState {
    pub joined: bool,
    pub latest_cursor: String,
    pub self_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeetBridgeProbe {
    pub health: BridgeHealth,
    pub topic: TopicState,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct MessagesPage {
    #[serde(default)]
    pub messages: Vec<BridgeMessage>,
    pub next_cursor: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct BridgeMessage {
    pub cursor: String,
    pub message_id: String,
    pub sender_id: String,
    #[serde(default)]
    pub sender_display: Option<String>,
    pub text: String,
    pub sent_at_ms: i64,
    #[serde(default)]
    pub reply_to: Option<String>,
}

#[derive(Debug, Serialize)]
struct PostMessageRequest<'a> {
    text: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reply_to: Option<&'a str>,
    idempotency_key: &'a str,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct PostMessageResponse {
    pub message_id: String,
}

pub fn validate_bearer_token(token: &str) -> Result<(), KeetBridgeError> {
    if token.trim() != token
        || token.len() < 32
        || token.len() > 4096
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-'))
    {
        return Err(KeetBridgeError::InvalidToken);
    }
    Ok(())
}

pub fn validate_topic(topic: &str) -> Result<(), KeetBridgeError> {
    let Some(encoded) = topic.strip_prefix("nk1_") else {
        return Err(KeetBridgeError::InvalidTopic);
    };
    if !is_canonical_base64url_32(encoded) {
        return Err(KeetBridgeError::InvalidTopic);
    }
    Ok(())
}

pub fn validate_sender_id(sender_id: &str) -> Result<(), KeetBridgeError> {
    if !is_canonical_base64url_32(sender_id) {
        return Err(KeetBridgeError::InvalidSenderId);
    }
    Ok(())
}

pub fn validate_idempotency_key(value: &str) -> Result<(), KeetBridgeError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-'))
    {
        return Err(KeetBridgeError::InvalidIdempotencyKey);
    }
    Ok(())
}

pub fn parse_cursor(value: &str) -> Result<u64, KeetBridgeError> {
    let Some(digits) = value.strip_prefix("c:") else {
        return Err(KeetBridgeError::Protocol("invalid canonical cursor"));
    };
    if digits.is_empty()
        || digits.len() > 16
        || (digits.len() > 1 && digits.starts_with('0'))
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(KeetBridgeError::Protocol("invalid canonical cursor"));
    }
    let sequence = digits
        .parse::<u64>()
        .map_err(|_| KeetBridgeError::Protocol("invalid canonical cursor"))?;
    if sequence > MAX_SAFE_CURSOR_SEQUENCE {
        return Err(KeetBridgeError::Protocol("cursor is outside the v1 range"));
    }
    Ok(sequence)
}

fn is_canonical_base64url_32(value: &str) -> bool {
    if value.len() != 43
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return false;
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .ok()
        .filter(|decoded| decoded.len() == 32)
        .is_some_and(|decoded| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(decoded) == value
        })
}

fn normalize_loopback_origin(value: &str) -> Result<reqwest::Url, KeetBridgeError> {
    let mut url = reqwest::Url::parse(value.trim()).map_err(|_| KeetBridgeError::InvalidUrl)?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(KeetBridgeError::InvalidUrl);
    }
    let is_loopback = match url.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        Some(url::Host::Domain(_)) | None => false,
    };
    if !is_loopback {
        return Err(KeetBridgeError::InvalidUrl);
    }
    if !matches!(url.path(), "" | "/") {
        return Err(KeetBridgeError::InvalidUrl);
    }
    url.set_path("");
    Ok(url)
}

fn validate_health(health: &BridgeHealth) -> Result<(), KeetBridgeError> {
    if health.protocol != BRIDGE_PROTOCOL {
        return Err(KeetBridgeError::Protocol("wrong companion protocol id"));
    }
    if health.protocol_version != BRIDGE_PROTOCOL_VERSION {
        return Err(KeetBridgeError::Protocol(
            "unsupported companion protocol version",
        ));
    }
    if health.bridge_version.trim().is_empty()
        || health.bridge_version.len() > 128
        || health.bridge_version.chars().any(char::is_control)
    {
        return Err(KeetBridgeError::Protocol(
            "companion omitted its bridge version",
        ));
    }
    if !health.ready {
        return Err(KeetBridgeError::Protocol("companion is not ready"));
    }
    let send = health.capabilities.iter().any(|value| value == "send_text");
    let receive = health
        .capabilities
        .iter()
        .any(|value| value == "receive_text");
    if !send || !receive {
        return Err(KeetBridgeError::Protocol(
            "companion must declare both send_text and receive_text",
        ));
    }
    Ok(())
}

fn validate_topic_state(topic: &TopicState) -> Result<(), KeetBridgeError> {
    if !topic.joined {
        return Err(KeetBridgeError::Protocol(
            "companion is not joined to the configured topic",
        ));
    }
    if parse_cursor(&topic.latest_cursor).is_err() {
        return Err(KeetBridgeError::Protocol(
            "companion returned an invalid latest cursor",
        ));
    }
    if validate_sender_id(&topic.self_id).is_err() {
        return Err(KeetBridgeError::Protocol(
            "companion returned an invalid local identity",
        ));
    }
    Ok(())
}

fn validate_messages_page(page: &MessagesPage, after: &str) -> Result<(), KeetBridgeError> {
    if page.messages.len() > POLL_LIMIT as usize {
        return Err(KeetBridgeError::Protocol(
            "companion returned too many messages",
        ));
    }
    let mut expected_sequence = parse_cursor(after)?;
    for message in &page.messages {
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or(KeetBridgeError::Protocol(
                "message cursor sequence overflowed",
            ))?;
        if message.cursor != format!("c:{expected_sequence}") {
            return Err(KeetBridgeError::Protocol(
                "companion returned a non-contiguous message cursor",
            ));
        }
        if message.message_id.trim().is_empty()
            || message.message_id.len() > 1024
            || message.message_id.chars().any(char::is_control)
            || validate_sender_id(&message.sender_id).is_err()
            || message
                .sender_display
                .as_deref()
                .is_some_and(|display| display.len() > 512 || display.chars().any(char::is_control))
            || message.text.trim().is_empty()
            || message.text.len() > 64 * 1024
            || message.sent_at_ms < 0
            || message.reply_to.as_deref().is_some_and(|reply_to| {
                reply_to.trim().is_empty()
                    || reply_to.len() > 1024
                    || reply_to.chars().any(char::is_control)
            })
        {
            return Err(KeetBridgeError::Protocol(
                "companion returned an invalid message envelope",
            ));
        }
    }
    if page.next_cursor != format!("c:{expected_sequence}") {
        return Err(KeetBridgeError::Protocol(
            "page cursor does not match the contiguous message sequence",
        ));
    }
    Ok(())
}

async fn decode_json<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
    limit: usize,
    operation: &'static str,
) -> Result<T, KeetBridgeError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(KeetBridgeError::ResponseTooLarge { limit });
    }
    let status = response.status();
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| KeetBridgeError::Transport { operation })?;
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(KeetBridgeError::ResponseTooLarge { limit });
        }
        body.extend_from_slice(&chunk);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(KeetBridgeError::Unauthorized);
    }
    if !status.is_success() {
        return Err(KeetBridgeError::Http {
            operation,
            status: status.as_u16(),
        });
    }
    serde_json::from_slice(&body).map_err(|_| KeetBridgeError::InvalidJson { operation })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_TOPIC: &str = "nk1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const TEST_SENDER: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn token() -> SecretString {
        SecretString::from("0123456789abcdef0123456789abcdef")
    }

    #[test]
    fn bridge_requires_loopback_origin_and_strong_token() {
        assert!(KeetBridge::new(DEFAULT_BRIDGE_URL, token()).is_ok());
        assert!(KeetBridge::new("http://127.42.0.7:9130/", token()).is_ok());
        assert!(KeetBridge::new("http://[::1]:9130", token()).is_ok());
        assert!(matches!(
            KeetBridge::new("http://localhost:9130/", token()),
            Err(KeetBridgeError::InvalidUrl)
        ));
        assert!(matches!(
            KeetBridge::new("http://192.168.1.5:9130/", token()),
            Err(KeetBridgeError::InvalidUrl)
        ));
        assert!(matches!(
            KeetBridge::new("https://example.com", token()),
            Err(KeetBridgeError::InvalidUrl)
        ));
        assert!(matches!(
            KeetBridge::new("http://127.0.0.1:9130/base", token()),
            Err(KeetBridgeError::InvalidUrl)
        ));
        assert!(matches!(
            KeetBridge::new(DEFAULT_BRIDGE_URL, SecretString::from("short")),
            Err(KeetBridgeError::InvalidToken)
        ));
    }

    #[test]
    fn debug_never_exposes_bearer() {
        let bridge = KeetBridge::new(DEFAULT_BRIDGE_URL, token()).unwrap();
        let rendered = format!("{bridge:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("0123456789abcdef"));
    }

    #[test]
    fn health_rejects_outbound_only_companion() {
        let outbound_only = BridgeHealth {
            protocol: BRIDGE_PROTOCOL.into(),
            protocol_version: BRIDGE_PROTOCOL_VERSION,
            bridge_version: "1.0.0".into(),
            ready: true,
            capabilities: vec!["send_text".into()],
        };
        assert!(matches!(
            validate_health(&outbound_only),
            Err(KeetBridgeError::Protocol(_))
        ));
        let full_duplex = BridgeHealth {
            capabilities: vec!["send_text".into(), "receive_text".into()],
            ..outbound_only
        };
        assert!(validate_health(&full_duplex).is_ok());
    }

    #[test]
    fn topic_requires_canonical_32_byte_capability() {
        validate_topic(TEST_TOPIC).unwrap();
        assert!(validate_topic("topic").is_err());
        assert!(validate_topic("nk1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!").is_err());
        assert!(validate_topic("nk1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB").is_err());
        let bridge = KeetBridge::new(DEFAULT_BRIDGE_URL, token()).unwrap();
        let url = bridge
            .endpoint(&["v1", "topics", TEST_TOPIC, "messages"])
            .unwrap();
        assert!(url.as_str().contains(TEST_TOPIC));
    }

    #[test]
    fn message_page_requires_advancing_exact_cursor() {
        let good = MessagesPage {
            messages: vec![BridgeMessage {
                cursor: "c:2".into(),
                message_id: "m1".into(),
                sender_id: TEST_SENDER.into(),
                sender_display: None,
                text: "hello".into(),
                sent_at_ms: 1_700_000_000_000,
                reply_to: None,
            }],
            next_cursor: "c:2".into(),
        };
        validate_messages_page(&good, "c:1").unwrap();
        let stale = MessagesPage {
            next_cursor: "c:1".into(),
            ..good
        };
        assert!(validate_messages_page(&stale, "c:1").is_err());
        let skipped = MessagesPage {
            messages: vec![],
            next_cursor: "c:2".into(),
        };
        assert!(validate_messages_page(&skipped, "c:1").is_err());
        let idle = MessagesPage {
            messages: vec![],
            next_cursor: "c:1".into(),
        };
        validate_messages_page(&idle, "c:1").unwrap();

        let out_of_order = MessagesPage {
            messages: vec![BridgeMessage {
                cursor: "c:3".into(),
                message_id: "m2".into(),
                sender_id: TEST_SENDER.into(),
                sender_display: None,
                text: "skipped c:2".into(),
                sent_at_ms: 1_700_000_000_001,
                reply_to: None,
            }],
            next_cursor: "c:3".into(),
        };
        assert!(validate_messages_page(&out_of_order, "c:1").is_err());
    }

    #[test]
    fn cursor_sender_and_idempotency_contracts_are_canonical() {
        assert_eq!(parse_cursor("c:0").unwrap(), 0);
        assert_eq!(parse_cursor("c:42").unwrap(), 42);
        for bad in ["0", "c:", "c:00", "c:+1", "c:9007199254740992"] {
            assert!(parse_cursor(bad).is_err(), "accepted {bad}");
        }
        validate_sender_id(TEST_SENDER).unwrap();
        assert!(validate_sender_id("alice").is_err());
        validate_idempotency_key("reply.01234567-89ab-4def-8123-456789abcdef").unwrap();
        assert!(validate_idempotency_key("contains space").is_err());
    }

    #[tokio::test]
    async fn health_does_not_follow_companion_redirects() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/health"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", "/substitute"))
            .mount(&server)
            .await;

        let bridge = KeetBridge::new(&server.uri(), token()).unwrap();
        assert!(matches!(
            bridge.health().await,
            Err(KeetBridgeError::Http { status: 302, .. })
        ));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn live_probe_requires_authenticated_full_duplex_and_joined_topic() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let auth = format!("Bearer {}", token().expose());
        Mock::given(method("GET"))
            .and(path("/v1/health"))
            .and(header("authorization", auth.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "protocol": BRIDGE_PROTOCOL,
                "protocol_version": BRIDGE_PROTOCOL_VERSION,
                "bridge_version": "1.0.0",
                "ready": true,
                "capabilities": ["send_text", "receive_text"]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/topics/{TEST_TOPIC}")))
            .and(header("authorization", auth))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "joined": true,
                "latest_cursor": "c:42",
                "self_id": TEST_SENDER
            })))
            .mount(&server)
            .await;

        let bridge = KeetBridge::new(&server.uri(), token()).unwrap();
        let probe = bridge.probe_topic(TEST_TOPIC).await.unwrap();
        assert_eq!(probe.topic.latest_cursor, "c:42");
        assert_eq!(probe.topic.self_id, TEST_SENDER);
    }

    #[tokio::test]
    async fn live_probe_rejects_outbound_only_before_topic_request() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/health"))
            .and(header(
                "authorization",
                format!("Bearer {}", token().expose()),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "protocol": BRIDGE_PROTOCOL,
                "protocol_version": BRIDGE_PROTOCOL_VERSION,
                "bridge_version": "1.0.0",
                "ready": true,
                "capabilities": ["send_text"]
            })))
            .mount(&server)
            .await;

        let bridge = KeetBridge::new(&server.uri(), token()).unwrap();
        assert!(matches!(
            bridge.probe_topic(TEST_TOPIC).await,
            Err(KeetBridgeError::Protocol(_))
        ));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn send_reproves_health_and_topic_and_preserves_operation_keys() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

        #[derive(Clone)]
        struct FailFirstPost {
            calls: Arc<AtomicUsize>,
        }

        impl Respond for FailFirstPost {
            fn respond(&self, _request: &Request) -> ResponseTemplate {
                if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(503)
                } else {
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "message_id": "sent-1"
                    }))
                }
            }
        }

        let server = MockServer::start().await;
        let auth = format!("Bearer {}", token().expose());
        Mock::given(method("GET"))
            .and(path("/v1/health"))
            .and(header("authorization", auth.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "protocol": BRIDGE_PROTOCOL,
                "protocol_version": BRIDGE_PROTOCOL_VERSION,
                "bridge_version": "1.0.0",
                "ready": true,
                "capabilities": ["send_text", "receive_text"]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/topics/{TEST_TOPIC}")))
            .and(header("authorization", auth.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "joined": true,
                "latest_cursor": "c:42",
                "self_id": TEST_SENDER
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("/v1/topics/{TEST_TOPIC}/messages")))
            .and(header("authorization", auth))
            .respond_with(FailFirstPost {
                calls: Arc::new(AtomicUsize::new(0)),
            })
            .mount(&server)
            .await;

        let bridge = KeetBridge::new(&server.uri(), token()).unwrap();
        let sent = bridge
            .post_message(TEST_TOPIC, "hello", Some("in-1"))
            .await
            .unwrap();
        assert_eq!(sent.message_id, "sent-1");
        bridge
            .post_message_idempotent(TEST_TOPIC, "retry-safe", None, "durable.request-1")
            .await
            .unwrap();
        let requests = server.received_requests().await.unwrap();
        let posts: Vec<_> = requests
            .iter()
            .filter(|request| request.method.as_str() == "POST")
            .collect();
        assert_eq!(posts.len(), 3);
        let body: serde_json::Value = serde_json::from_slice(&posts[0].body).unwrap();
        let retry: serde_json::Value = serde_json::from_slice(&posts[1].body).unwrap();
        assert_eq!(body["text"], "hello");
        assert_eq!(body["reply_to"], "in-1");
        assert_eq!(
            body["idempotency_key"], retry["idempotency_key"],
            "bounded retry must reuse the exact operation key"
        );
        let idempotency = body["idempotency_key"].as_str().unwrap();
        assert_eq!(
            uuid::Uuid::parse_str(idempotency)
                .unwrap()
                .get_version_num(),
            4
        );
        let durable: serde_json::Value = serde_json::from_slice(&posts[2].body).unwrap();
        assert_eq!(durable["text"], "retry-safe");
        assert_eq!(durable["idempotency_key"], "durable.request-1");
    }
}
