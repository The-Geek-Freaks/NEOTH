//! Slack Web/API surface used by the live socket-mode adapter.
//!
//! Operator workflow today:
//!   1. Configure `xoxb-` bot token + `xapp-` app-level token via
//!      `neoth init` or `credentials.yaml`.
//!   2. Run `neoth slack test` — calls Slack's `apps.connections.open`
//!      with the app token; on success Slack returns a WSS URL that
//!      proves the operator's app credentials are valid + scoped.
//!   3. `neoth serve` opens that WSS URL via `tokio-tungstenite`, decodes
//!      `events_api` envelopes, and forwards them to `PipelineHandler`.
//!
//! This module owns the HTTP calls (`auth.test`, socket URL, post/update);
//! `slack_socket` owns the reconnecting WebSocket receive/ACK loop.

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::providers::http_client;
use crate::secret::SecretString;

#[derive(Clone, Debug, serde::Serialize)]
pub struct AuthTestResult {
    pub ok: bool,
    pub bot_id: Option<String>,
    pub team: Option<String>,
    pub team_id: Option<String>,
    pub user: Option<String>,
    pub url: Option<String>,
    pub error: Option<String>,
}

/// Call `auth.test` with the bot token. Returns the team + bot info
/// when valid; `ok=false` + error string when Slack rejects the token.
pub async fn auth_test(bot_token: &SecretString) -> Result<AuthTestResult> {
    let client = http_client::build_client()?;
    let resp = client
        .get("https://slack.com/api/auth.test")
        .bearer_auth(bot_token.expose())
        .send()
        .await
        .context("slack auth.test request")?;
    let body: SlackAuthBody = resp.json().await.context("slack auth.test decode")?;
    Ok(AuthTestResult {
        ok: body.ok,
        bot_id: body.bot_id,
        team: body.team,
        team_id: body.team_id,
        user: body.user,
        url: body.url,
        error: body.error,
    })
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct SocketOpenResult {
    pub ok: bool,
    pub url: Option<String>,
    pub error: Option<String>,
}

/// Call `apps.connections.open` with the app-level token. Returns the
/// WSS URL on success — that's the URL the live event loop dials.
/// Failing to fetch a URL is an actionable pre-flight error before the
/// daemon starts the Slack channel.
pub async fn socket_mode_open(app_token: &SecretString) -> Result<SocketOpenResult> {
    let client = http_client::build_client()?;
    let resp = client
        .post("https://slack.com/api/apps.connections.open")
        .bearer_auth(app_token.expose())
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send()
        .await
        .context("slack apps.connections.open request")?;
    let body: SocketOpenBody = resp
        .json()
        .await
        .context("slack apps.connections.open decode")?;
    Ok(SocketOpenResult {
        ok: body.ok,
        url: body.url,
        error: body.error,
    })
}

#[derive(Deserialize)]
struct SlackAuthBody {
    ok: bool,
    #[serde(default)]
    bot_id: Option<String>,
    #[serde(default)]
    team: Option<String>,
    #[serde(default)]
    team_id: Option<String>,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
struct SocketOpenBody {
    ok: bool,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// Result of a `chat.postMessage` call. `ts` is Slack's message id
/// (a numeric string like `"1700000000.000100"`) — operators can use
/// it for edits / reactions / threading in future iterations.
#[derive(Clone, Debug, serde::Serialize)]
pub struct PostMessageResult {
    pub ok: bool,
    pub ts: Option<String>,
    pub channel: Option<String>,
    pub error: Option<String>,
}

/// POST `chat.postMessage`. `channel` accepts a channel id (`Cxxxxxx`),
/// a channel name with the `#` prefix, or a DM id (`Dxxxxxx`). Slack
/// resolves the addressing server-side.
///
/// Returns the parsed envelope so the caller can decide policy on
/// `ok=false` — operators may want to surface invalid_auth differently
/// from channel_not_found.
pub async fn post_message(
    bot_token: &SecretString,
    channel: &str,
    text: &str,
) -> Result<PostMessageResult> {
    let client = http_client::build_client()?;
    let resp = client
        .post("https://slack.com/api/chat.postMessage")
        .bearer_auth(bot_token.expose())
        .header("Content-Type", "application/json; charset=utf-8")
        .body(
            serde_json::to_vec(&serde_json::json!({
                "channel": channel,
                "text": text,
            }))
            .context("serialize chat.postMessage payload")?,
        )
        .send()
        .await
        .context("slack chat.postMessage request")?;
    let body: PostMessageBody = resp.json().await.context("slack chat.postMessage decode")?;
    Ok(PostMessageResult {
        ok: body.ok,
        ts: body.ts,
        channel: body.channel,
        error: body.error,
    })
}

#[derive(Deserialize)]
struct PostMessageBody {
    ok: bool,
    #[serde(default)]
    ts: Option<String>,
    #[serde(default)]
    channel: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// Result of a `chat.update` call (SPEC-11 edit path). Slack echoes the same
/// `ts` (a message's id never changes across edits) + the channel.
#[derive(Clone, Debug, serde::Serialize)]
pub struct UpdateMessageResult {
    pub ok: bool,
    pub ts: Option<String>,
    pub channel: Option<String>,
    pub error: Option<String>,
}

/// POST `chat.update` — edit an existing message in place. `ts` is the message
/// id returned by [`post_message`] (Slack uses the post timestamp as the id).
/// Returns the parsed envelope so the caller can branch on `ok=false`
/// (`message_not_found`, `cant_update_message`, …).
pub async fn update_message(
    bot_token: &SecretString,
    channel: &str,
    ts: &str,
    text: &str,
) -> Result<UpdateMessageResult> {
    let client = http_client::build_client()?;
    let resp = client
        .post("https://slack.com/api/chat.update")
        .bearer_auth(bot_token.expose())
        .header("Content-Type", "application/json; charset=utf-8")
        .body(
            serde_json::to_vec(&serde_json::json!({
                "channel": channel,
                "ts": ts,
                "text": text,
            }))
            .context("serialize chat.update payload")?,
        )
        .send()
        .await
        .context("slack chat.update request")?;
    let body: PostMessageBody = resp.json().await.context("slack chat.update decode")?;
    Ok(UpdateMessageResult {
        ok: body.ok,
        ts: body.ts,
        channel: body.channel,
        error: body.error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_test_result_serializes_to_expected_shape() {
        let r = AuthTestResult {
            ok: true,
            bot_id: Some("B123".into()),
            team: Some("acme".into()),
            team_id: Some("T123".into()),
            user: Some("neoth-bot".into()),
            url: Some("https://acme.slack.com/".into()),
            error: None,
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"ok\":true"));
        assert!(s.contains("\"team\":\"acme\""));
    }

    #[test]
    fn socket_open_result_serializes_with_failure_path() {
        let r = SocketOpenResult {
            ok: false,
            url: None,
            error: Some("invalid_auth".into()),
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"ok\":false"));
        assert!(s.contains("\"error\":\"invalid_auth\""));
    }

    #[test]
    fn post_message_result_serializes_success_shape() {
        let r = PostMessageResult {
            ok: true,
            ts: Some("1700000000.000100".into()),
            channel: Some("C12345".into()),
            error: None,
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"ok\":true"));
        assert!(s.contains("\"ts\":\"1700000000.000100\""));
        assert!(s.contains("\"channel\":\"C12345\""));
    }

    #[test]
    fn post_message_result_serializes_failure_shape() {
        let r = PostMessageResult {
            ok: false,
            ts: None,
            channel: None,
            error: Some("channel_not_found".into()),
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"ok\":false"));
        assert!(s.contains("\"error\":\"channel_not_found\""));
    }

    #[test]
    fn post_message_body_deserialises_minimal_payload() {
        // Slack returns extra fields we ignore — serde(default) keeps
        // forward-compat across API revisions.
        let raw = r#"{"ok":true,"channel":"C12345","ts":"1700000000.000100","extra":"ignored"}"#;
        let parsed: PostMessageBody = serde_json::from_str(raw).unwrap();
        assert!(parsed.ok);
        assert_eq!(parsed.channel.as_deref(), Some("C12345"));
        assert_eq!(parsed.ts.as_deref(), Some("1700000000.000100"));
    }

    #[test]
    fn post_message_body_deserialises_error_payload() {
        let raw = r#"{"ok":false,"error":"not_in_channel"}"#;
        let parsed: PostMessageBody = serde_json::from_str(raw).unwrap();
        assert!(!parsed.ok);
        assert_eq!(parsed.error.as_deref(), Some("not_in_channel"));
        assert!(parsed.ts.is_none());
    }

    #[test]
    fn update_message_result_serializes_success_shape() {
        // SPEC-11: chat.update echoes the same ts (id stable across edits).
        let r = UpdateMessageResult {
            ok: true,
            ts: Some("1700000000.000100".into()),
            channel: Some("C12345".into()),
            error: None,
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"ok\":true"));
        assert!(s.contains("\"ts\":\"1700000000.000100\""));
    }

    #[test]
    fn update_message_result_serializes_failure_shape() {
        let r = UpdateMessageResult {
            ok: false,
            ts: None,
            channel: None,
            error: Some("message_not_found".into()),
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"ok\":false"));
        assert!(s.contains("\"error\":\"message_not_found\""));
    }
}
