//! Keet channel adapter backed by the authenticated local NEOTH companion.
//!
//! The adapter deliberately contains no guessed proprietary Keet-room protocol.
//! The companion owns NEOTH's separate Keet-identity Pear/Hyperswarm transport;
//! this module owns the strict local IPC boundary, cursor durability, sender
//! policy, and canonical Channel wiring. Existing Keet application rooms are
//! not claimed as interoperable.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use super::keet_bridge::{KeetBridge, KeetBridgeProbe};
use super::{Channel, ChannelError, ChannelKind, InboundMessage, MessageId, PipelineHandler};
use crate::secret::SecretString;

pub const DEFAULT_CURSOR_FILE: &str = "channel-state/keet-cursor.json";

pub struct KeetChannel {
    bridge: KeetBridge,
    topic: String,
    allowed_senders: BTreeSet<String>,
    cursor_path: PathBuf,
    gate_writer: Option<crate::wal::writer::WalWriterHandle>,
}

impl std::fmt::Debug for KeetChannel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KeetChannel")
            .field("bridge", &self.bridge)
            .field("topic", &"<redacted>")
            .field(
                "allowed_senders",
                &format_args!("{} entries", self.allowed_senders.len()),
            )
            .field("cursor_path", &self.cursor_path)
            .finish_non_exhaustive()
    }
}

impl KeetChannel {
    pub fn new(
        bridge_url: &str,
        bearer_token: SecretString,
        topic: &str,
        allowed_senders: &str,
        cursor_path: PathBuf,
    ) -> Result<Self> {
        super::keet_bridge::validate_topic(topic).context("validate Keet topic")?;
        let normalized = normalize_allowed_senders(allowed_senders)?;
        let bridge = KeetBridge::new(bridge_url, bearer_token).context("build Keet bridge")?;
        Ok(Self {
            bridge,
            topic: topic.to_string(),
            allowed_senders: normalized.split(',').map(str::to_string).collect(),
            cursor_path,
            gate_writer: None,
        })
    }

    pub fn with_gate_writer(mut self, writer: crate::wal::writer::WalWriterHandle) -> Self {
        self.gate_writer = Some(writer);
        self
    }

    pub async fn probe(&self) -> Result<KeetBridgeProbe> {
        self.bridge
            .probe_topic(&self.topic)
            .await
            .context("Keet companion full-duplex probe failed")
    }

    async fn deliver_pending_reply(&self, pending: &PendingReply) {
        let mut backoff_seconds = 1_u64;
        loop {
            // Keep the typed variant: `reply` flattens every bridge error into
            // `ChannelError::Transport(String)`, which erases exactly the
            // permanent-vs-retryable distinction `post_message_idempotent`
            // makes. This delivery is awaited inline by `run`, so retrying a
            // permanently-rejected reply forever stalls the WHOLE channel — the
            // cursor never advances and every later inbound message is silently
            // dropped until a restart, which resumes the same reply into the
            // same loop.
            match self
                .bridge
                .post_message_idempotent(
                    &self.topic,
                    &pending.text,
                    Some(&pending.message_id),
                    &pending.idempotency_key,
                )
                .await
            {
                Ok(_) => return,
                Err(error) if error.is_permanent() => {
                    // Dead-letter: the caller clears the pending reply and
                    // advances the cursor, so the channel keeps serving.
                    warn!(
                        channel = "keet",
                        error = %error,
                        "Keet reply was permanently rejected and is being DROPPED so the channel \
                         can make progress; the operator's message was not delivered"
                    );
                    return;
                }
                Err(error) => {
                    warn!(
                        channel = "keet",
                        error = %error,
                        "Keet reply remains in the durable outbox; retrying without rerunning the handler"
                    );
                    tokio::time::sleep(Duration::from_secs(backoff_seconds)).await;
                    backoff_seconds = (backoff_seconds * 2).min(30);
                }
            }
        }
    }
}

/// Live capability probe shared by `channel test` and future GUI callers.
pub async fn probe_bridge(
    bridge_url: &str,
    bearer_token: SecretString,
    topic: &str,
) -> Result<KeetBridgeProbe> {
    let bridge = KeetBridge::new(bridge_url, bearer_token).context("build Keet bridge")?;
    bridge
        .probe_topic(topic)
        .await
        .context("Keet companion full-duplex probe failed")
}

/// Normalize an exact sender-id allowlist. IDs are canonical 32-byte base64url
/// Keet identities and case-sensitive; delimiter ambiguity is rejected.
pub fn normalize_allowed_senders(value: &str) -> Result<String> {
    let mut senders = BTreeSet::new();
    for sender in value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        if super::keet_bridge::validate_sender_id(sender).is_err() {
            anyhow::bail!(
                "invalid Keet sender id; use comma-separated canonical 32-byte base64url IDs printed by the companion"
            );
        }
        senders.insert(sender.to_string());
    }
    if senders.is_empty() {
        anyhow::bail!("Keet sender allowlist must contain at least one exact sender ID");
    }
    Ok(senders.into_iter().collect::<Vec<_>>().join(","))
}

#[async_trait]
impl Channel for KeetChannel {
    fn name(&self) -> &'static str {
        "keet"
    }

    async fn run(&self, handler: PipelineHandler) -> Result<()> {
        // Keep the daemon task alive when the companion starts later or is
        // temporarily restarting. The channel remains fail-closed and does not
        // claim LIVE until the authenticated full-duplex + joined-topic proof
        // succeeds.
        let mut startup_backoff_seconds = 1_u64;
        let initial = loop {
            match self.probe().await {
                Ok(probe) => {
                    info!(
                        channel = "keet",
                        status = "LIVE",
                        "authenticated companion is full-duplex and joined to the configured topic"
                    );
                    break probe;
                }
                Err(error) => {
                    warn!(
                        channel = "keet",
                        status = "WAITING",
                        error = %error,
                        "Keet companion proof failed; channel remains closed and will retry"
                    );
                    tokio::time::sleep(Duration::from_secs(startup_backoff_seconds)).await;
                    startup_backoff_seconds = (startup_backoff_seconds * 2).min(30);
                }
            }
        };
        let self_id = initial.topic.self_id;
        let chat_alias = topic_alias(&self.topic)?;
        let mut state = match load_cursor_state(&self.cursor_path, &self.topic, &self_id)? {
            Some(state) => state,
            None => {
                // First enable, legacy state, or a topic/identity namespace
                // change starts at the companion's current edge. Never import
                // arbitrary room history or reuse another topic's `c:N`.
                let state = baseline_state(&self.topic, &self_id, &initial.topic.latest_cursor)?;
                save_cursor_state(&self.cursor_path, &state)?;
                state
            }
        };

        // A crash or response loss can leave a reply durably pending while the
        // sidecar already accepted it. Reuse the stored operation key; its
        // idempotency journal returns the original message instead of sending a
        // duplicate. The model handler is never rerun for an outboxed reply.
        if let Some(pending) = state.pending_reply.clone() {
            info!(
                channel = "keet",
                "resuming durable pending reply before polling new messages"
            );
            self.deliver_pending_reply(&pending).await;
            complete_pending_reply(&mut state, &pending)?;
            save_cursor_state(&self.cursor_path, &state)?;
        }

        let mut poll_backoff_seconds = 1_u64;
        let mut handler_backoff_seconds = 1_u64;

        loop {
            let page = match self.bridge.poll_messages(&self.topic, &state.cursor).await {
                Ok(page) => {
                    poll_backoff_seconds = 1;
                    page
                }
                Err(error) => {
                    warn!(
                        channel = "keet",
                        error = %error,
                        "Keet companion receive poll failed; retrying"
                    );
                    tokio::time::sleep(Duration::from_secs(poll_backoff_seconds)).await;
                    poll_backoff_seconds = (poll_backoff_seconds * 2).min(30);
                    continue;
                }
            };

            if page.messages.is_empty() {
                continue;
            }

            let mut retry_current_message = false;
            for message in page.messages {
                let message_cursor = message.cursor.clone();
                if message.sender_id == self_id {
                    advance_without_reply(&mut state, &message_cursor)?;
                    save_cursor_state(&self.cursor_path, &state)?;
                    continue;
                }
                if !self.allowed_senders.contains(&message.sender_id) {
                    super::emit_gate_rejected(
                        self.gate_writer.as_ref(),
                        &message.sender_id,
                        "keet",
                    )
                    .await;
                    advance_without_reply(&mut state, &message_cursor)?;
                    save_cursor_state(&self.cursor_path, &state)?;
                    continue;
                }

                let channel_ts_unix = u64::try_from(message.sent_at_ms.max(0) / 1000)
                    .unwrap_or_else(|_| crate::time::now_unix_secs());
                let message_id = message.message_id.clone();
                let inbound = InboundMessage {
                    channel: ChannelKind::Keet,
                    // Generic pipeline/session/audit surfaces receive only a
                    // stable one-way alias. The real topic is a possession
                    // capability and stays inside this transport boundary.
                    chat_id: chat_alias.clone(),
                    thread_id: None,
                    sender_id: message.sender_id,
                    sender_display: message
                        .sender_display
                        .filter(|display| !display.trim().is_empty()),
                    text: Some(message.text),
                    media: None,
                    reply_to: message.reply_to.map(MessageId),
                    message_id: Some(message_id.clone()),
                    edit_unix: None,
                    mention_kind: None,
                    channel_ts_unix,
                    raw_ts_ms: Some(message.sent_at_ms),
                    human_uuid: None,
                };

                match handler(inbound).await {
                    Ok(Some(outbound)) => {
                        // The model/pipeline cannot redirect a Keet reply: the
                        // configured operator topic is the only destination.
                        // Persist before network I/O so response loss or a crash
                        // cannot rerun the handler or duplicate the reply.
                        let pending = stage_pending_reply(
                            &mut state,
                            &message_cursor,
                            message_id,
                            outbound.text,
                        )?;
                        save_cursor_state(&self.cursor_path, &state)?;
                        self.deliver_pending_reply(&pending).await;
                        complete_pending_reply(&mut state, &pending)?;
                        save_cursor_state(&self.cursor_path, &state)?;
                        handler_backoff_seconds = 1;
                    }
                    Ok(None) => {
                        advance_without_reply(&mut state, &message_cursor)?;
                        save_cursor_state(&self.cursor_path, &state)?;
                        handler_backoff_seconds = 1;
                    }
                    Err(error) => {
                        warn!(
                            channel = "keet",
                            error = %error,
                            "Keet pipeline handler failed; cursor remains unchanged and the message will retry"
                        );
                        tokio::time::sleep(Duration::from_secs(handler_backoff_seconds)).await;
                        handler_backoff_seconds = (handler_backoff_seconds * 2).min(30);
                        retry_current_message = true;
                        break;
                    }
                }
            }
            if retry_current_message {
                continue;
            }
        }
    }

    async fn send_text(
        &self,
        chat_id: &str,
        text: &str,
    ) -> std::result::Result<MessageId, ChannelError> {
        // Callers may send to another operator-configured Keet topic (proactive
        // routing). The bridge validates the canonical capability and encodes
        // it as one path segment.
        self.bridge
            .post_message(chat_id, text, None)
            .await
            .map(|response| MessageId(response.message_id))
            .map_err(|error| ChannelError::Transport(error.to_string()))
    }

    async fn send_proactive(
        &self,
        chat_id: &str,
        text: &str,
    ) -> std::result::Result<MessageId, ChannelError> {
        self.send_text(chat_id, text).await
    }
}

const CURSOR_STATE_VERSION: u8 = 1;
// JSON escaping can expand a valid 64 KiB reply (for example control
// characters) several-fold. Keep a hard bound while accommodating the full
// bridge text contract plus metadata.
const MAX_CURSOR_STATE_BYTES: u64 = 512 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CursorState {
    #[serde(default)]
    version: u8,
    #[serde(default)]
    topic_fingerprint: String,
    #[serde(default)]
    self_id: String,
    cursor: String,
    #[serde(default)]
    pending_reply: Option<PendingReply>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PendingReply {
    cursor: String,
    message_id: String,
    text: String,
    idempotency_key: String,
}

fn baseline_state(topic: &str, self_id: &str, cursor: &str) -> Result<CursorState> {
    super::keet_bridge::validate_topic(topic).context("validate Keet state topic")?;
    super::keet_bridge::validate_sender_id(self_id).context("validate Keet state identity")?;
    super::keet_bridge::parse_cursor(cursor).context("validate Keet state baseline cursor")?;
    Ok(CursorState {
        version: CURSOR_STATE_VERSION,
        topic_fingerprint: topic_fingerprint(topic),
        self_id: self_id.to_string(),
        cursor: cursor.to_string(),
        pending_reply: None,
    })
}

fn load_cursor_state(path: &Path, topic: &str, self_id: &str) -> Result<Option<CursorState>> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("inspect {}", path.display())),
    };
    if metadata.len() > MAX_CURSOR_STATE_BYTES {
        anyhow::bail!("Keet channel state file is oversized: {}", path.display());
    }
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let state: CursorState = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse Keet channel state at {}", path.display()))?;
    super::keet_bridge::parse_cursor(&state.cursor)
        .with_context(|| format!("invalid Keet cursor at {}", path.display()))?;

    // Legacy `{cursor}` state has no namespace. Re-baseline at the companion's
    // current edge instead of applying an unrelated cursor to a topic.
    if state.version == 0 && state.topic_fingerprint.is_empty() && state.self_id.is_empty() {
        return Ok(None);
    }
    if state.version != CURSOR_STATE_VERSION {
        anyhow::bail!(
            "unsupported Keet channel state version {} at {}",
            state.version,
            path.display()
        );
    }
    if state.topic_fingerprint != topic_fingerprint(topic) || state.self_id != self_id {
        return Ok(None);
    }
    validate_cursor_state(&state)
        .with_context(|| format!("invalid Keet channel state at {}", path.display()))?;
    Ok(Some(state))
}

fn save_cursor_state(path: &Path, state: &CursorState) -> Result<()> {
    validate_cursor_state(state).context("refusing to persist invalid Keet channel state")?;
    let bytes = serde_json::to_vec(state)?;
    if bytes.len() as u64 > MAX_CURSOR_STATE_BYTES {
        anyhow::bail!("refusing to persist oversized Keet channel state");
    }
    crate::util::atomic_write::atomic_write_private(path, &bytes)
        .with_context(|| format!("persist Keet channel state at {}", path.display()))
}

fn advance_without_reply(state: &mut CursorState, cursor: &str) -> Result<()> {
    if state.pending_reply.is_some() {
        anyhow::bail!("cannot advance Keet cursor while a reply is pending");
    }
    let mut next = state.clone();
    next.cursor = cursor.to_string();
    validate_cursor_state(&next)?;
    let previous = super::keet_bridge::parse_cursor(&state.cursor)?;
    let advanced = super::keet_bridge::parse_cursor(cursor)?;
    if previous.checked_add(1) != Some(advanced) {
        anyhow::bail!("Keet cursor advance is not contiguous");
    }
    *state = next;
    Ok(())
}

fn stage_pending_reply(
    state: &mut CursorState,
    cursor: &str,
    message_id: String,
    text: String,
) -> Result<PendingReply> {
    if state.pending_reply.is_some() {
        anyhow::bail!("a Keet reply is already pending");
    }
    let pending = PendingReply {
        cursor: cursor.to_string(),
        message_id,
        text,
        idempotency_key: uuid::Uuid::new_v4().to_string(),
    };
    let mut next = state.clone();
    next.pending_reply = Some(pending.clone());
    validate_cursor_state(&next)?;
    *state = next;
    Ok(pending)
}

fn complete_pending_reply(state: &mut CursorState, pending: &PendingReply) -> Result<()> {
    if state.pending_reply.as_ref() != Some(pending) {
        anyhow::bail!("Keet outbox completion does not match the pending reply");
    }
    let mut next = state.clone();
    next.cursor = pending.cursor.clone();
    next.pending_reply = None;
    validate_cursor_state(&next)?;
    *state = next;
    Ok(())
}

fn validate_cursor_state(state: &CursorState) -> Result<()> {
    if state.version != CURSOR_STATE_VERSION
        || state.topic_fingerprint.len() != 64
        || !state
            .topic_fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        anyhow::bail!("invalid Keet state namespace");
    }
    super::keet_bridge::validate_sender_id(&state.self_id)?;
    let cursor_sequence = super::keet_bridge::parse_cursor(&state.cursor)?;
    if let Some(pending) = &state.pending_reply {
        let pending_sequence = super::keet_bridge::parse_cursor(&pending.cursor)?;
        if cursor_sequence.checked_add(1) != Some(pending_sequence) {
            anyhow::bail!("pending Keet reply is not the next receive cursor");
        }
        if pending.message_id.trim().is_empty()
            || pending.message_id.len() > 1024
            || pending.message_id.chars().any(char::is_control)
            || pending.text.trim().is_empty()
            || pending.text.len() > 64 * 1024
        {
            anyhow::bail!("invalid pending Keet reply envelope");
        }
        super::keet_bridge::validate_idempotency_key(&pending.idempotency_key)?;
    }
    Ok(())
}

fn topic_fingerprint(topic: &str) -> String {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(topic.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Stable non-secret identifier for generic pipeline/session/audit surfaces.
/// The Keet topic itself is a possession capability and must never be used as
/// a generic chat id where Debug or event serialization could expose it.
pub fn topic_alias(topic: &str) -> Result<String> {
    super::keet_bridge::validate_topic(topic).context("validate Keet topic capability")?;
    Ok(format!("keet:sha256:{}", topic_fingerprint(topic)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_TOPIC: &str = "nk1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const TEST_TOPIC_TWO: &str = "nk1_AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
    const TEST_SENDER: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const TEST_SENDER_TWO: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

    fn token() -> SecretString {
        SecretString::from("0123456789abcdef0123456789abcdef")
    }

    #[test]
    fn allowed_senders_are_exact_deduplicated_and_sorted() {
        let input = format!("{TEST_SENDER_TWO},{TEST_SENDER},{TEST_SENDER_TWO}");
        assert_eq!(
            normalize_allowed_senders(&input).unwrap(),
            format!("{TEST_SENDER},{TEST_SENDER_TWO}")
        );
        assert!(normalize_allowed_senders("  ").is_err());
        assert!(normalize_allowed_senders("alice").is_err());
    }

    #[test]
    fn constructor_rejects_remote_bridge_and_missing_policy() {
        let cursor = PathBuf::from("cursor.json");
        assert!(
            KeetChannel::new(
                "https://example.com",
                token(),
                TEST_TOPIC,
                TEST_SENDER,
                cursor.clone()
            )
            .is_err()
        );
        assert!(
            KeetChannel::new(
                super::super::keet_bridge::DEFAULT_BRIDGE_URL,
                token(),
                TEST_TOPIC,
                " ",
                cursor,
            )
            .is_err()
        );
    }

    #[test]
    fn cursor_state_is_namespaced_crash_safe_and_carries_a_durable_outbox() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keet-cursor.json");
        assert_eq!(
            load_cursor_state(&path, TEST_TOPIC, TEST_SENDER).unwrap(),
            None
        );
        let mut state = baseline_state(TEST_TOPIC, TEST_SENDER, "c:7").unwrap();
        let unchanged = state.clone();
        assert!(advance_without_reply(&mut state, "c:9").is_err());
        assert_eq!(state, unchanged, "failed transition must not mutate state");
        let pending = stage_pending_reply(
            &mut state,
            "c:8",
            "message-8".into(),
            "durable reply".into(),
        )
        .unwrap();
        assert_eq!(state.cursor, "c:7", "staging must not consume the inbound");
        assert_eq!(state.pending_reply.as_ref(), Some(&pending));
        save_cursor_state(&path, &state).unwrap();
        assert_eq!(
            load_cursor_state(&path, TEST_TOPIC, TEST_SENDER)
                .unwrap()
                .unwrap(),
            state
        );
        assert!(
            !std::fs::read_to_string(&path).unwrap().contains(TEST_TOPIC),
            "topic capability must be persisted only as a fingerprint"
        );

        let mut completed = state.clone();
        complete_pending_reply(&mut completed, &pending).unwrap();
        assert_eq!(completed.cursor, "c:8");
        assert!(completed.pending_reply.is_none());

        assert_eq!(
            load_cursor_state(&path, TEST_TOPIC_TWO, TEST_SENDER).unwrap(),
            None,
            "topic mismatch must force a fresh probed baseline"
        );
        assert_eq!(
            load_cursor_state(&path, TEST_TOPIC, TEST_SENDER_TWO).unwrap(),
            None,
            "companion identity mismatch must force a fresh probed baseline"
        );

        std::fs::write(&path, br#"{"cursor":"c:9"}"#).unwrap();
        assert_eq!(
            load_cursor_state(&path, TEST_TOPIC, TEST_SENDER).unwrap(),
            None,
            "legacy unbound cursor must never cross a topic namespace"
        );
        std::fs::write(&path, b"not-json").unwrap();
        assert!(load_cursor_state(&path, TEST_TOPIC, TEST_SENDER).is_err());

        let mut invalid = baseline_state(TEST_TOPIC, TEST_SENDER, "c:7").unwrap();
        invalid.pending_reply = Some(PendingReply {
            cursor: "c:9".into(),
            message_id: "skipped".into(),
            text: "must fail".into(),
            idempotency_key: "request-1".into(),
        });
        assert!(save_cursor_state(&path, &invalid).is_err());
    }

    #[test]
    fn debug_redacts_topic_token_and_sender_ids() {
        let channel = KeetChannel::new(
            super::super::keet_bridge::DEFAULT_BRIDGE_URL,
            token(),
            TEST_TOPIC,
            TEST_SENDER_TWO,
            PathBuf::from("cursor.json"),
        )
        .unwrap();
        let rendered = format!("{channel:?}");
        assert!(!rendered.contains(TEST_TOPIC));
        assert!(!rendered.contains(TEST_SENDER_TWO));
        assert!(!rendered.contains("0123456789abcdef"));
    }

    #[test]
    fn topic_alias_is_stable_and_never_contains_the_capability() {
        let first = topic_alias(TEST_TOPIC).unwrap();
        let second = topic_alias(TEST_TOPIC).unwrap();
        assert_eq!(first, second);
        assert!(first.starts_with("keet:sha256:"));
        assert_eq!(first.len(), "keet:sha256:".len() + 64);
        assert!(!first.contains(TEST_TOPIC));
        assert!(topic_alias("nk1_not-canonical").is_err());
    }
}
