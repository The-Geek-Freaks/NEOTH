//! GOLD-FEAT-10 — Mattermost protocol surface: the pure WebSocket-frame decode
//! + the REST send/identity calls. Mattermost is self-hosted, Slack-style team
//! chat; NEOTH connects OUT to the server's WebSocket API (`/api/v4/websocket`),
//! so — like IRC — it needs no public URL. It reuses the always-present
//! `tokio-tungstenite` (Slack socket-mode) + `reqwest` deps: no new crate, no
//! feature gate.
//!
//! The wire shapes are unit-testable without a live server: [`decode_frame`]
//! turns a raw WS text frame into a [`MmFrame`] verdict, and [`mm_ws_url`] +
//! [`auth_challenge_frame`] are pure string builders. The live receive loop
//! lives in [`super::mattermost`].

use anyhow::Context;
use serde::Deserialize;

use super::{ChannelError, ChannelKind, InboundMessage};
use crate::providers::http_client;
use crate::secret::SecretString;

/// A parsed inbound WebSocket frame. Mattermost multiplexes two frame shapes on
/// one socket: asynchronous *events* (`{"event": "...", "data": {...}, ...}`)
/// and *responses* to our actions (`{"status": "OK", "seq_reply": N}`). Every
/// field is optional so one struct parses both without branching first.
#[derive(Debug, Default, Deserialize)]
pub struct MmEvent {
    #[serde(default)]
    pub event: Option<String>,
    #[serde(default)]
    pub data: Option<MmEventData>,
    #[serde(default)]
    pub broadcast: Option<MmBroadcast>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub seq_reply: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
pub struct MmEventData {
    /// The `posted` event carries the new post as a JSON-ENCODED STRING (not a
    /// nested object) — Mattermost serialises the post once on the server.
    #[serde(default)]
    pub post: Option<String>,
    #[serde(default)]
    pub channel_type: Option<String>,
    #[serde(default)]
    pub sender_name: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct MmBroadcast {
    #[serde(default)]
    pub channel_id: Option<String>,
}

/// The inner post (the parsed `data.post` string).
#[derive(Debug, Default, Deserialize)]
pub struct MmPost {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub channel_id: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub user_id: String,
    /// Epoch MILLIseconds (Mattermost is millisecond-based throughout).
    #[serde(default)]
    pub create_at: i64,
    /// Empty for a normal user message; `system_*` for join/leave/header/etc.
    #[serde(rename = "type", default)]
    pub post_type: String,
    #[serde(default)]
    pub props: Option<serde_json::Value>,
}

/// Minimal `/api/v4/users/me` shape — we only need our own id for echo-drop.
#[derive(Debug, Default, Deserialize)]
struct MmMe {
    #[serde(default)]
    id: String,
    #[serde(default)]
    username: String,
}

/// Verdict from decoding one inbound WS frame.
#[derive(Debug)]
pub enum MmFrame {
    /// A `posted` event we should run through the pipeline.
    Posted(Box<InboundMessage>),
    /// Any other event / a response / a self-or-bot echo — no dispatch.
    Ignored,
    /// The frame (or its inner post) was not JSON we recognise.
    ParseError(String),
}

/// Build the `wss://…/api/v4/websocket` URL from the operator's base URL.
/// `https` → `wss`, `http` → `ws`; an explicit `ws(s)` base is honoured, and a
/// bare host defaults to TLS. A trailing slash is trimmed so we never emit
/// `//api`.
pub fn mm_ws_url(base: &str) -> String {
    let base = base.trim_end_matches('/');
    let (host_and_path, ws_scheme) = if let Some(rest) = base.strip_prefix("https://") {
        (rest, "wss://")
    } else if let Some(rest) = base.strip_prefix("http://") {
        (rest, "ws://")
    } else if let Some(rest) = base.strip_prefix("wss://") {
        (rest, "wss://")
    } else if let Some(rest) = base.strip_prefix("ws://") {
        (rest, "ws://")
    } else {
        (base, "wss://")
    };
    format!("{ws_scheme}{host_and_path}/api/v4/websocket")
}

/// The authentication-challenge frame sent immediately after the socket opens.
/// Mattermost streams no events until it sees this.
pub fn auth_challenge_frame(token: &str) -> String {
    serde_json::json!({
        "seq": 1,
        "action": "authentication_challenge",
        "data": { "token": token }
    })
    .to_string()
}

/// Decode one raw WS text frame. `bot_user_id` is our own user id (from
/// [`fetch_me_user_id`]) — posts we authored echo back over the socket and must
/// be dropped to avoid a reply loop.
pub fn decode_frame(raw: &str, bot_user_id: &str) -> MmFrame {
    let event: MmEvent = match serde_json::from_str(raw) {
        Ok(e) => e,
        Err(e) => return MmFrame::ParseError(e.to_string()),
    };
    // Only `posted` events carry a message; everything else (typing, presence,
    // status responses) is ignored.
    if event.event.as_deref() != Some("posted") {
        return MmFrame::Ignored;
    }
    let Some(post_str) = event.data.as_ref().and_then(|d| d.post.as_deref()) else {
        return MmFrame::Ignored;
    };
    let post: MmPost = match serde_json::from_str(post_str) {
        Ok(p) => p,
        Err(e) => return MmFrame::ParseError(format!("inner post: {e}")),
    };
    match decode_post(&post, event.data.as_ref(), bot_user_id) {
        Some(inbound) => MmFrame::Posted(Box::new(inbound)),
        None => MmFrame::Ignored,
    }
}

/// Map a parsed [`MmPost`] to an [`InboundMessage`], or `None` if it must not
/// reach the pipeline: our own echo, a bot author (loop guard), a `system_*`
/// post, an empty body, or a post with no channel to reply to.
pub fn decode_post(
    post: &MmPost,
    data: Option<&MmEventData>,
    bot_user_id: &str,
) -> Option<InboundMessage> {
    if !bot_user_id.is_empty() && post.user_id == bot_user_id {
        return None; // our own message echoed back — never loop on it
    }
    if post.post_type.starts_with("system_") {
        return None; // join/leave/header-change/etc.
    }
    // Loop guard: drop messages authored by ANY bot, not just our own. Mattermost
    // has historically encoded `props.from_bot` as the string "true"; accept a
    // real JSON bool too so the guard is robust across server versions.
    if let Some(props) = &post.props {
        let from_bot = props
            .get("from_bot")
            .is_some_and(|v| v.as_str() == Some("true") || v.as_bool() == Some(true));
        if from_bot {
            return None;
        }
    }
    let message = post.message.trim();
    if message.is_empty() || post.channel_id.is_empty() {
        return None;
    }
    Some(InboundMessage {
        channel: ChannelKind::Mattermost,
        chat_id: post.channel_id.clone(),
        thread_id: None,
        sender_id: post.user_id.clone(),
        sender_display: data.and_then(|d| d.sender_name.clone()),
        text: Some(message.to_string()),
        media: None,
        reply_to: None,
        message_id: if post.id.is_empty() {
            None
        } else {
            Some(post.id.clone())
        },
        edit_unix: None,
        mention_kind: None,
        channel_ts_unix: (post.create_at / 1000).max(0) as u64,
        raw_ts_ms: if post.create_at > 0 {
            Some(post.create_at)
        } else {
            None
        },
        human_uuid: None,
    })
}

/// POST a reply via `/api/v4/posts`. Returns the created post's id on success.
/// HTTP status is classified so the caller can distinguish a rate-limit /
/// auth-rejection from a generic transport failure.
pub async fn send_post(
    base: &str,
    token: &SecretString,
    channel_id: &str,
    message: &str,
) -> std::result::Result<String, ChannelError> {
    let base = base.trim_end_matches('/');
    let url = format!("{base}/api/v4/posts");
    let client = http_client::build_client()
        .map_err(|e| ChannelError::Transport(format!("http client: {e}")))?;
    let payload = serde_json::to_vec(&serde_json::json!({
        "channel_id": channel_id,
        "message": message,
    }))
    .map_err(|e| ChannelError::Transport(format!("serialize post: {e}")))?;
    let resp = client
        .post(&url)
        .bearer_auth(token.expose())
        .header("Content-Type", "application/json")
        .body(payload)
        .send()
        .await
        .map_err(|e| ChannelError::Transport(format!("mattermost POST /posts: {e}")))?;
    let status = resp.status();
    match status.as_u16() {
        429 => {
            let retry = resp
                .headers()
                .get("Retry-After")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(5);
            Err(ChannelError::RateLimited {
                retry_after_secs: retry,
            })
        }
        401 | 403 => Err(ChannelError::Auth(format!(
            "mattermost rejected the token (HTTP {status})"
        ))),
        code if !(200..300).contains(&code) => {
            let body = resp
                .text()
                .await
                .unwrap_or_else(|error| format!("<response body unreadable: {error}>"));
            Err(ChannelError::Transport(format!(
                "mattermost /posts HTTP {status}: {}",
                body.chars().take(200).collect::<String>()
            )))
        }
        _ => {
            let created: MmPost = resp
                .json()
                .await
                .map_err(|e| ChannelError::Transport(format!("decode created post: {e}")))?;
            Ok(created.id)
        }
    }
}

/// Fetch our own user id via `/api/v4/users/me`. Called once at startup so the
/// receive loop can drop our own echoed posts. A failure here is fatal to the
/// run loop — without our id we cannot safely dedup the echo.
pub async fn fetch_me_user_id(base: &str, token: &SecretString) -> anyhow::Result<String> {
    Ok(probe_identity(base, token).await?.0)
}

/// Read-only token/identity probe shared by daemon startup and
/// `neoth channel test mattermost`.
pub async fn probe_identity(base: &str, token: &SecretString) -> anyhow::Result<(String, String)> {
    let base = super::readiness::parse_base_url(base, "Mattermost")?;
    let url = super::readiness::append_path(base, "/api/v4/users/me");
    let client = super::readiness::probe_client(&url)?;
    let resp = client
        .get(url)
        .bearer_auth(token.expose())
        .timeout(super::readiness::PROBE_TIMEOUT)
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("mattermost GET /users/me request failed"))?;
    let (status, body) = super::readiness::bounded_body(resp, "Mattermost /users/me").await?;
    if matches!(status.as_u16(), 401 | 403) {
        anyhow::bail!("Mattermost rejected the token");
    }
    if !status.is_success() {
        anyhow::bail!("mattermost /users/me HTTP {}", status.as_u16());
    }
    let me: MmMe = serde_json::from_slice(&body).context("decode Mattermost /users/me")?;
    if me.id.is_empty() {
        anyhow::bail!("mattermost /users/me returned an empty id");
    }
    Ok((me.id, me.username))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_url_maps_https_to_wss_and_appends_path() {
        assert_eq!(
            mm_ws_url("https://mm.example.com"),
            "wss://mm.example.com/api/v4/websocket"
        );
    }

    #[test]
    fn ws_url_maps_http_to_ws_and_trims_trailing_slash() {
        assert_eq!(
            mm_ws_url("http://localhost:8065/"),
            "ws://localhost:8065/api/v4/websocket"
        );
    }

    #[test]
    fn ws_url_bare_host_defaults_to_tls() {
        assert_eq!(
            mm_ws_url("mm.example.com"),
            "wss://mm.example.com/api/v4/websocket"
        );
        assert_eq!(mm_ws_url("wss://x.io"), "wss://x.io/api/v4/websocket");
    }

    #[tokio::test]
    async fn identity_probe_is_read_only_bounded_and_token_safe() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let token = SecretString::from("mm-super-secret");
        Mock::given(method("GET"))
            .and(path("/api/v4/users/me"))
            .and(header("authorization", "Bearer mm-super-secret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "bot-id",
                "username": "neoth"
            })))
            .mount(&server)
            .await;
        let identity = probe_identity(&server.uri(), &token).await.unwrap();
        assert_eq!(identity, ("bot-id".to_string(), "neoth".to_string()));

        let error = probe_identity("http://127.0.0.1:1", &token)
            .await
            .unwrap_err()
            .to_string();
        assert!(!error.contains(token.expose()));
    }

    #[test]
    fn auth_challenge_carries_token_and_action() {
        let f = auth_challenge_frame("secret-tok");
        assert!(f.contains("authentication_challenge"));
        assert!(f.contains("secret-tok"));
        // Must be valid JSON the server can parse.
        let v: serde_json::Value = serde_json::from_str(&f).unwrap();
        assert_eq!(v["data"]["token"], "secret-tok");
        assert_eq!(v["seq"], 1);
    }

    fn posted_frame(user_id: &str, message: &str, post_type: &str) -> String {
        let post = serde_json::json!({
            "id": "p1",
            "channel_id": "chan1",
            "message": message,
            "user_id": user_id,
            "create_at": 1_700_000_000_000i64,
            "type": post_type,
        })
        .to_string();
        serde_json::json!({
            "event": "posted",
            "data": { "post": post, "channel_type": "O", "sender_name": "@alice" },
            "broadcast": { "channel_id": "chan1" },
            "seq": 7
        })
        .to_string()
    }

    #[test]
    fn posted_event_decodes_to_inbound() {
        match decode_frame(&posted_frame("u_alice", "hi neoth", ""), "u_bot") {
            MmFrame::Posted(inbound) => {
                assert_eq!(inbound.channel, ChannelKind::Mattermost);
                assert_eq!(inbound.chat_id, "chan1");
                assert_eq!(inbound.sender_id, "u_alice");
                assert_eq!(inbound.sender_display.as_deref(), Some("@alice"));
                assert_eq!(inbound.text.as_deref(), Some("hi neoth"));
                assert_eq!(inbound.message_id.as_deref(), Some("p1"));
                assert_eq!(inbound.channel_ts_unix, 1_700_000_000);
                assert_eq!(inbound.raw_ts_ms, Some(1_700_000_000_000));
            }
            other => panic!("expected Posted, got {other:?}"),
        }
    }

    #[test]
    fn own_echo_is_ignored() {
        // user_id == bot_user_id → our own post echoed back.
        assert!(matches!(
            decode_frame(&posted_frame("u_bot", "my own reply", ""), "u_bot"),
            MmFrame::Ignored
        ));
    }

    #[test]
    fn system_post_is_ignored() {
        assert!(matches!(
            decode_frame(
                &posted_frame("u_alice", "alice joined", "system_join_channel"),
                "u_bot"
            ),
            MmFrame::Ignored
        ));
    }

    #[test]
    fn bot_authored_post_is_ignored_loop_guard() {
        let post = serde_json::json!({
            "id": "p9", "channel_id": "c", "message": "from another bot",
            "user_id": "u_otherbot", "create_at": 1i64, "type": "",
            "props": { "from_bot": "true" }
        })
        .to_string();
        let frame = serde_json::json!({
            "event": "posted",
            "data": { "post": post }
        })
        .to_string();
        assert!(matches!(decode_frame(&frame, "u_bot"), MmFrame::Ignored));
    }

    #[test]
    fn bot_authored_post_bool_form_is_ignored() {
        // Some Mattermost versions emit a real JSON bool, not the string "true".
        let post = serde_json::json!({
            "id": "p9", "channel_id": "c", "message": "from a bot",
            "user_id": "u_otherbot", "create_at": 1i64, "type": "",
            "props": { "from_bot": true }
        })
        .to_string();
        let frame = serde_json::json!({ "event": "posted", "data": { "post": post } }).to_string();
        assert!(matches!(decode_frame(&frame, "u_bot"), MmFrame::Ignored));
    }

    #[test]
    fn non_posted_event_is_ignored() {
        let frame = r#"{"event":"typing","data":{"user_id":"u1"},"seq":3}"#;
        assert!(matches!(decode_frame(frame, "u_bot"), MmFrame::Ignored));
    }

    #[test]
    fn auth_response_frame_is_ignored() {
        let frame = r#"{"status":"OK","seq_reply":1}"#;
        assert!(matches!(decode_frame(frame, "u_bot"), MmFrame::Ignored));
    }

    #[test]
    fn empty_message_is_ignored() {
        assert!(matches!(
            decode_frame(&posted_frame("u_alice", "   ", ""), "u_bot"),
            MmFrame::Ignored
        ));
    }

    #[test]
    fn garbage_frame_is_parse_error() {
        assert!(matches!(
            decode_frame("not json", "u_bot"),
            MmFrame::ParseError(_)
        ));
    }

    #[test]
    fn empty_bot_id_does_not_drop_everyone() {
        // A startup that somehow has an empty bot id must still deliver real
        // posts (the empty-id guard only skips the self-echo compare).
        assert!(matches!(
            decode_frame(&posted_frame("u_alice", "hi", ""), ""),
            MmFrame::Posted(_)
        ));
    }
}
