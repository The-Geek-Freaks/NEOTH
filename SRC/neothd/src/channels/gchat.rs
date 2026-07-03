//! B9 — Google Chat channel adapter (RECEIVE via GCP Pub/Sub PULL, SEND via
//! the Chat REST API), behind the `gchat-channel` cargo feature.
//!
//! Transport (Hermes pattern, `channels_hermes_2026-06-13.md`): the Chat app
//! is configured in GCP to publish events to a Pub/Sub topic; NEOTH pulls a
//! subscription on that topic — **no public URL**, NEOTH dials out, works
//! behind NAT. Wire types + event mapping live in the always-compiled
//! [`super::gchat_api`]; this module owns auth + the pull loop + sends.
//!
//! ## Auth
//!
//! A GCP **service-account JSON key** (path in `credentials.yaml::
//! gchat_service_account_json`). Access tokens are minted on demand via the
//! RS256 JWT-bearer grant (`jsonwebtoken`, ring-backed) with the combined
//! `pubsub` + `chat.bot` scopes and cached until ~60s before expiry. The
//! private key never leaves this struct; error strings carry neither key nor
//! token material (static messages + status codes only).
//!
//! ## Operator prerequisite
//!
//! GCP project with the Chat API enabled, a Chat app publishing to a Pub/Sub
//! topic, a pull subscription on it, and a service account holding
//! `roles/pubsub.subscriber` + Chat-app credentials. `credentials.yaml`:
//! `gchat_service_account_json` (path), `gchat_subscription`
//! (`projects/<p>/subscriptions/<s>`), optional `gchat_allowed_sender`
//! (`users/<id>`, the D2 allowlist).

use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use async_trait::async_trait;
use serde::Deserialize;
use tracing::{info, warn};

use super::gchat_api::{PullResponse, decode_chat_event, event_to_inbound, sa_jwt_claims};
use super::{Channel, ChannelError, ChannelKind, MessageId, PipelineHandler};
use crate::secret::SecretString;

/// Combined scope for one token: pull/ack the subscription + send as the app.
const SCOPES: &str = "https://www.googleapis.com/auth/pubsub https://www.googleapis.com/auth/chat.bot";
/// Refresh the cached token when less than this much lifetime remains.
const TOKEN_SLACK: Duration = Duration::from_secs(60);
/// Messages per pull request.
const PULL_BATCH: u32 = 10;
/// Backoff after a transient pull/transport error.
const ERROR_BACKOFF: Duration = Duration::from_secs(5);

/// Subset of the service-account JSON key NEOTH needs.
#[derive(Debug, Deserialize)]
struct ServiceAccountKey {
    client_email: String,
    private_key: String,
    #[serde(default = "default_token_uri")]
    token_uri: String,
}

fn default_token_uri() -> String {
    "https://oauth2.googleapis.com/token".to_string()
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

/// Google Chat adapter. Construction parses the key file (fail fast on a bad
/// path/JSON); the network work happens in [`Self::run`] / the send methods.
pub struct GChatChannel {
    client_email: String,
    /// PEM private key from the SA JSON — held as a secret, Debug-redacted.
    private_key: SecretString,
    token_uri: String,
    /// `projects/<p>/subscriptions/<s>`.
    subscription: String,
    http: reqwest::Client,
    /// Cached bearer token + its refresh deadline.
    token: tokio::sync::Mutex<Option<(String, Instant)>>,
    /// D2 — operator sender allowlist (`users/<id>`). `None` ⇒ open.
    allowed_sender: Option<String>,
    /// D2 — WAL writer for the `0x3B CHANNEL_GATE_REJECTED` audit on a drop.
    gate_writer: Option<crate::wal::writer::WalWriterHandle>,
}

impl GChatChannel {
    /// Parse the service-account key at `sa_json_path` and build the adapter.
    pub fn new(sa_json_path: &std::path::Path, subscription: impl Into<String>) -> Result<Self> {
        let raw = std::fs::read_to_string(sa_json_path).with_context(|| {
            format!(
                "read gchat service-account key at {}",
                sa_json_path.display()
            )
        })?;
        let key: ServiceAccountKey =
            serde_json::from_str(&raw).context("parse gchat service-account JSON key")?;
        // The signed JWT assertion is POSTed to token_uri — never let a
        // tampered key file point that at a plaintext/internal endpoint.
        if !key.token_uri.starts_with("https://") {
            anyhow::bail!(
                "gchat: token_uri in the service-account key must be an https:// URL \
                 (got a non-https value)"
            );
        }
        // Security: never follow redirects — a redirect would forward the
        // Authorization bearer header to the redirect target.
        let http = crate::providers::http_client::build_client_no_redirect()
            .context("build reqwest client for gchat adapter")?;
        Ok(Self {
            client_email: key.client_email,
            private_key: SecretString::from(key.private_key.as_str()),
            token_uri: key.token_uri,
            subscription: subscription.into(),
            http,
            token: tokio::sync::Mutex::new(None),
            allowed_sender: None,
            gate_writer: None,
        })
    }

    /// D2 — bind the operator sender allowlist + the gate's audit writer.
    pub fn with_allowlist(
        mut self,
        allowed_sender: Option<String>,
        gate_writer: crate::wal::writer::WalWriterHandle,
    ) -> Self {
        self.allowed_sender = allowed_sender;
        self.gate_writer = Some(gate_writer);
        self
    }

    /// Current bearer token, minting a fresh one via the RS256 JWT-bearer
    /// grant when the cache is empty or near expiry.
    async fn bearer(&self) -> Result<String, ChannelError> {
        let mut guard = self.token.lock().await;
        if let Some((tok, deadline)) = guard.as_ref() {
            if Instant::now() < *deadline {
                return Ok(tok.clone());
            }
        }
        let claims = sa_jwt_claims(
            &self.client_email,
            SCOPES,
            &self.token_uri,
            crate::time::now_unix_secs(),
        );
        let claims_value: serde_json::Value = serde_json::from_str(&claims)
            .map_err(|_| ChannelError::Transport("gchat: claims serialization".to_string()))?;
        let jwt = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
            &claims_value,
            &jsonwebtoken::EncodingKey::from_rsa_pem(self.private_key.expose().as_bytes())
                // Static message — never echo key material or parser detail.
                .map_err(|_| {
                    ChannelError::Auth(
                        "gchat: service-account private_key is not a valid RSA PEM".to_string(),
                    )
                })?,
        )
        .map_err(|_| ChannelError::Auth("gchat: JWT signing failed".to_string()))?;
        let resp = self
            .http
            .post(&self.token_uri)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", jwt.as_str()),
            ])
            .send()
            .await
            .map_err(|e| ChannelError::Transport(format!("gchat token POST: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            // Body may echo the assertion — log status only.
            return Err(ChannelError::Auth(format!(
                "gchat token grant rejected (HTTP {status}) — check the service account key + \
                 clock skew"
            )));
        }
        let tok: TokenResponse = resp
            .json()
            .await
            .map_err(|_| ChannelError::Transport("gchat token response parse".to_string()))?;
        let ttl = Duration::from_secs(tok.expires_in.unwrap_or(3600));
        let deadline = Instant::now() + ttl.saturating_sub(TOKEN_SLACK);
        *guard = Some((tok.access_token.clone(), deadline));
        Ok(tok.access_token)
    }

    /// One `:pull` round trip. Empty vec on no traffic. Without the
    /// deprecated `returnImmediately` flag the server long-polls ("may wait
    /// for a bounded amount of time until at least one message is available"
    /// — REST v1 `subscriptions.pull` docs), so an idle subscription costs
    /// one request per server hold period, well inside the 120s client
    /// timeout.
    async fn pull(&self) -> Result<PullResponse, ChannelError> {
        let bearer = self.bearer().await?;
        let url = format!(
            "https://pubsub.googleapis.com/v1/{}:pull",
            self.subscription
        );
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&bearer)
            .json(&serde_json::json!({ "maxMessages": PULL_BATCH }))
            .send()
            .await
            .map_err(|e| ChannelError::Transport(format!("gchat pubsub pull: {e}")))?;
        let status = resp.status();
        if status.as_u16() == 401 || status.as_u16() == 403 {
            // Invalidate the cache; the next loop iteration re-mints.
            *self.token.lock().await = None;
            return Err(ChannelError::Auth(format!(
                "gchat pubsub pull unauthorized (HTTP {status}) — check roles/pubsub.subscriber"
            )));
        }
        if !status.is_success() {
            return Err(ChannelError::Transport(format!(
                "gchat pubsub pull failed (HTTP {status})"
            )));
        }
        resp.json()
            .await
            .map_err(|_| ChannelError::Transport("gchat pull response parse".to_string()))
    }

    /// Ack processed messages so Pub/Sub stops redelivering them.
    async fn ack(&self, ack_ids: &[String]) -> Result<(), ChannelError> {
        if ack_ids.is_empty() {
            return Ok(());
        }
        let bearer = self.bearer().await?;
        let url = format!(
            "https://pubsub.googleapis.com/v1/{}:acknowledge",
            self.subscription
        );
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&bearer)
            .json(&serde_json::json!({ "ackIds": ack_ids }))
            .send()
            .await
            .map_err(|e| ChannelError::Transport(format!("gchat pubsub ack: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(ChannelError::Transport(format!(
                "gchat pubsub ack failed (HTTP {status})"
            )));
        }
        Ok(())
    }

    /// `POST /v1/{space}/messages` — plain-text send.
    async fn post_text(&self, space: &str, text: &str) -> Result<MessageId, ChannelError> {
        let bearer = self.bearer().await?;
        let url = format!("https://chat.googleapis.com/v1/{space}/messages");
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&bearer)
            .json(&serde_json::json!({ "text": text }))
            .send()
            .await
            .map_err(|e| ChannelError::Transport(format!("gchat message POST: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(ChannelError::Transport(format!(
                "gchat message send failed (HTTP {status})"
            )));
        }
        let val: serde_json::Value = resp.json().await.unwrap_or_default();
        let name = val
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("sent")
            .to_string();
        Ok(MessageId(name))
    }
}

#[async_trait]
impl Channel for GChatChannel {
    fn name(&self) -> &'static str {
        ChannelKind::GoogleChat.as_str()
    }

    /// Pull loop: `:pull` → map `MESSAGE` events through the pipeline →
    /// reply into the originating space → `:acknowledge` EVERYTHING that
    /// was pulled (poison payloads + non-message events included — a
    /// message that can't be parsed must never wedge the subscription).
    /// Auth errors abort the adapter (broken config, no restart-spin);
    /// transient transport errors back off and retry.
    async fn run(&self, handler: PipelineHandler) -> Result<()> {
        info!(subscription = %self.subscription, "gchat adapter live (pubsub pull)");
        loop {
            let pulled = match self.pull().await {
                Ok(p) => p,
                Err(ChannelError::Auth(msg)) => anyhow::bail!("gchat auth: {msg}"),
                Err(e) => {
                    warn!(error = %e, "gchat pull failed; backing off");
                    tokio::time::sleep(ERROR_BACKOFF).await;
                    continue;
                }
            };
            // The server MAY return early with an empty batch; a short pause
            // keeps a fast-returning idle server from turning the long-poll
            // loop into a hot spin (quota + billing guard).
            if pulled.received_messages.is_empty() {
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
            let mut ack_ids: Vec<String> = Vec::with_capacity(pulled.received_messages.len());
            for received in pulled.received_messages {
                ack_ids.push(received.ack_id.clone());
                let Some(event) = received
                    .message
                    .as_ref()
                    .and_then(|m| m.data.as_deref())
                    .and_then(decode_chat_event)
                else {
                    continue; // non-JSON / empty payload — ack + skip
                };
                let Some(inbound) = event_to_inbound(&event, crate::time::now_unix_secs()) else {
                    continue; // bot echo / non-MESSAGE / missing fields
                };
                // D2 — drop + audit a sender not on the operator allowlist
                // before the pipeline sees the message (open when None).
                if super::sender_blocked_by_allowlist(
                    self.allowed_sender.as_deref(),
                    &inbound.sender_id,
                    self.gate_writer.as_ref(),
                    ChannelKind::GoogleChat.as_str(),
                )
                .await
                {
                    continue;
                }
                let reply_to = inbound.chat_id.clone();
                match handler(inbound).await {
                    Ok(Some(out)) => {
                        if let Err(e) = self.post_text(&reply_to, &out.text).await {
                            warn!(error = %e, "gchat reply send failed (dropped)");
                        }
                    }
                    Ok(None) => {} // pipeline chose to stay silent
                    Err(e) => {
                        warn!(error = %e, "gchat pipeline handler errored; skipping message")
                    }
                }
            }
            if let Err(e) = self.ack(&ack_ids).await {
                // Unacked messages redeliver — log loudly, keep pulling.
                warn!(error = %e, "gchat ack failed; messages will redeliver");
            }
        }
    }

    /// Send plain text to `chat_id` (a `spaces/<id>` resource name).
    async fn send_text(
        &self,
        chat_id: &str,
        text: &str,
    ) -> std::result::Result<MessageId, ChannelError> {
        self.post_text(chat_id, text).await
    }

    /// Proactive = same app-credential send path; `chat_id` is the operator's
    /// configured space, never item-influenced.
    async fn send_proactive(
        &self,
        chat_id: &str,
        text: &str,
    ) -> std::result::Result<MessageId, ChannelError> {
        self.post_text(chat_id, text).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sa_key_parse_defaults_token_uri() {
        let key: ServiceAccountKey = serde_json::from_str(
            r#"{"client_email":"bot@p.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nX\n-----END PRIVATE KEY-----\n"}"#,
        )
        .unwrap();
        assert_eq!(key.token_uri, "https://oauth2.googleapis.com/token");
        assert_eq!(key.client_email, "bot@p.iam.gserviceaccount.com");
    }

    #[test]
    fn new_fails_fast_on_missing_or_invalid_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.json");
        assert!(GChatChannel::new(&missing, "projects/p/subscriptions/s").is_err());
        let bad = dir.path().join("bad.json");
        std::fs::write(&bad, "{not json").unwrap();
        assert!(GChatChannel::new(&bad, "projects/p/subscriptions/s").is_err());
    }

    #[tokio::test]
    async fn bearer_rejects_invalid_pem_without_leaking_key() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("sa.json");
        // PEM check fires BEFORE any network I/O — the https token_uri is
        // never contacted.
        std::fs::write(
            &key,
            r#"{"client_email":"bot@p.iam.gserviceaccount.com","private_key":"not-a-pem","token_uri":"https://127.0.0.1:1/token"}"#,
        )
        .unwrap();
        let ch = GChatChannel::new(&key, "projects/p/subscriptions/s").unwrap();
        let err = ch.bearer().await.unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("not a valid RSA PEM"), "clear diagnosis: {msg}");
        assert!(!msg.contains("not-a-pem"), "key material never echoed");
    }

    #[test]
    fn new_rejects_non_https_token_uri() {
        // Security review: a tampered key file must not point the signed JWT
        // assertion at a plaintext/internal endpoint.
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("sa.json");
        std::fs::write(
            &key,
            r#"{"client_email":"b@p","private_key":"x","token_uri":"http://169.254.169.254/token"}"#,
        )
        .unwrap();
        let Err(err) = GChatChannel::new(&key, "projects/p/subscriptions/s") else {
            panic!("non-https token_uri must be rejected");
        };
        assert!(err.to_string().contains("https://"), "{err}");
    }
}
