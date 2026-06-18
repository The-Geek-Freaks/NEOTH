//! SPEC-11 — `LiveDelivery`: a stateful send-then-edit wrapper.
//!
//! Abstracts the "first call sends a new message, subsequent calls edit that
//! same message" protocol used by streaming previews + post-reply corrections.
//!
//! The first [`LiveDelivery::send_or_edit`] calls [`Channel::send_text`] and
//! remembers the returned [`MessageId`]; later calls route to
//! [`Channel::edit_message`] against that id and emit a `0x38 CHANNEL_EDIT`
//! audit frame — the OUTBOUND mirror of the SD-03 inbound-edit frame, so
//! `neoth wal show --type channel_edit` aggregates edits in both directions
//! (the `direction` field disambiguates). No raw text is logged — only an
//! xxh3-64 hash + byte length, matching the inbound-edit PII contract.
//!
//! On [`ChannelError::NotSupported`] from `edit_message` (an adapter without an
//! edit API — most webhooks) `send_or_edit` degrades to a fresh `send_text`,
//! so the wrapper stays usable on every channel. No WAL event is minted: `0x38`
//! already exists + is wired.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{Channel, ChannelError, ChannelKind, MessageId};
use crate::config::LiveDeliveryConfig;
use crate::wal::writer::WalWriterHandle;

/// What one `send_or_edit` did. `Coalesced` = the edit was DROPPED by the
/// rate limiter (too soon after the last edit, or past the per-message cap) —
/// no API call was made. The final edit (when `final_edit_always_allowed`) is
/// never coalesced, so the operator never sees a truncated draft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendOutcome {
    /// A new message was sent (first send, or a degraded fresh-send).
    Sent(MessageId),
    /// The live message was edited in place.
    Edited(MessageId),
    /// The edit was rate-limited away (no network call).
    Coalesced,
}

/// Stateful wrapper that sends a message once, then edits it in place on
/// subsequent updates — bounded by [`LiveDeliveryConfig`] so it can't trip a
/// channel's edit rate limit. NOT `Clone` — the send/edit state is
/// per-delivery; share via the owning task, not by copying.
pub struct LiveDelivery {
    channel: Arc<dyn Channel>,
    chat_id: String,
    kind: ChannelKind,
    config: LiveDeliveryConfig,
    /// `None` until the first `send_or_edit` succeeds; then the platform id of
    /// the live message every subsequent edit targets.
    sent_message_id: Option<MessageId>,
    /// Wall-clock (ms) of the last edit/send that actually hit the wire — the
    /// rate-limit reference point.
    last_edit_ms: Option<u64>,
    /// Edits that have hit the wire for this message (the per-message cap).
    edit_count: u32,
}

/// SPEC-11 rate-limit decision — PURE so it is unit-testable with an explicit
/// clock. `true` ⇒ the edit may hit the wire; `false` ⇒ coalesce (drop) it.
/// The final edit always passes when `final_edit_always_allowed`.
fn should_send_edit(
    config: &LiveDeliveryConfig,
    now_ms: u64,
    last_edit_ms: Option<u64>,
    edit_count: u32,
    is_final: bool,
) -> bool {
    if is_final && config.final_edit_always_allowed {
        return true;
    }
    if edit_count >= config.max_edits_per_message {
        return false;
    }
    // Coalesce when the previous edit was within the min interval.
    !matches!(
        last_edit_ms,
        Some(last) if now_ms.saturating_sub(last) < config.min_edit_interval_ms
    )
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl LiveDelivery {
    /// New delivery bound to `chat_id` on `channel` (of family `kind`), governed
    /// by `config`. Nothing is sent until the first [`LiveDelivery::send_or_edit`].
    pub fn new(
        channel: Arc<dyn Channel>,
        chat_id: String,
        kind: ChannelKind,
        config: LiveDeliveryConfig,
    ) -> Self {
        Self {
            channel,
            chat_id,
            kind,
            config,
            sent_message_id: None,
            last_edit_ms: None,
            edit_count: 0,
        }
    }

    /// `true` once the first send has landed (a `MessageId` is held).
    pub fn has_sent(&self) -> bool {
        self.sent_message_id.is_some()
    }

    /// Send (first call) or edit-in-place (subsequent calls), wall-clock-bounded.
    /// `is_final = true` marks the completed reply — it bypasses the rate limits
    /// (when `final_edit_always_allowed`) so the last edit always lands. See
    /// [`LiveDelivery::send_or_edit_at`] for the testable, explicit-clock core.
    pub async fn send_or_edit(
        &mut self,
        writer: &WalWriterHandle,
        text: &str,
        is_final: bool,
    ) -> std::result::Result<SendOutcome, ChannelError> {
        self.send_or_edit_at(writer, now_ms(), text, is_final).await
    }

    /// Explicit-clock core of [`LiveDelivery::send_or_edit`] (the `now_ms` seam
    /// makes the rate limiter deterministically testable).
    ///
    /// - First call: `send_text` → store + return `Sent`.
    /// - Subsequent call, rate-limited away: `Coalesced` (no API call).
    /// - Subsequent call that passes: `edit_message` → emit `0x38` → `Edited`
    ///   (same id). If edits are disabled OR the adapter reports `NotSupported`,
    ///   degrade to a fresh `send_text` → `Sent` (no `0x38` — a new message is
    ///   not an edit).
    pub async fn send_or_edit_at(
        &mut self,
        writer: &WalWriterHandle,
        now_ms: u64,
        text: &str,
        is_final: bool,
    ) -> std::result::Result<SendOutcome, ChannelError> {
        match self.sent_message_id.clone() {
            None => {
                let id = self.channel.send_text(&self.chat_id, text).await?;
                self.sent_message_id = Some(id.clone());
                self.last_edit_ms = Some(now_ms);
                Ok(SendOutcome::Sent(id))
            }
            Some(existing) => {
                // Rate limit: drop intermediate edits that arrive too fast or
                // past the per-message cap (the final edit always passes).
                if !should_send_edit(
                    &self.config,
                    now_ms,
                    self.last_edit_ms,
                    self.edit_count,
                    is_final,
                ) {
                    return Ok(SendOutcome::Coalesced);
                }
                // Edits disabled → send-only: a fresh message instead of editing.
                if !self.config.edits_enabled {
                    let id = self.channel.send_text(&self.chat_id, text).await?;
                    self.sent_message_id = Some(id.clone());
                    self.last_edit_ms = Some(now_ms);
                    return Ok(SendOutcome::Sent(id));
                }
                match self
                    .channel
                    .edit_message(&self.chat_id, &existing, text)
                    .await
                {
                    Ok(()) => {
                        self.emit_edit(writer, &existing, text).await;
                        self.last_edit_ms = Some(now_ms);
                        self.edit_count = self.edit_count.saturating_add(1);
                        Ok(SendOutcome::Edited(existing))
                    }
                    Err(ChannelError::NotSupported { .. }) => {
                        let id = self.channel.send_text(&self.chat_id, text).await?;
                        self.sent_message_id = Some(id.clone());
                        self.last_edit_ms = Some(now_ms);
                        Ok(SendOutcome::Sent(id))
                    }
                    Err(e) => Err(e),
                }
            }
        }
    }

    /// Finalize the live delivery. No-op today — a placeholder for streaming
    /// finalize semantics (e.g. stripping a "typing…" marker on the last edit).
    pub async fn finalize(&self) -> std::result::Result<(), ChannelError> {
        Ok(())
    }

    /// Emit the outbound `0x38 CHANNEL_EDIT` audit frame. Best-effort: a WAL
    /// error is logged + dropped (the edit already happened on the wire; the
    /// frame is the audit nicety). Mirrors the inbound-edit payload shape +
    /// adds `direction: "outbound"`.
    async fn emit_edit(&self, writer: &WalWriterHandle, message_id: &MessageId, new_text: &str) {
        let ts_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let payload = match serde_json::to_vec(&serde_json::json!({
            "channel": self.kind.as_str(),
            "direction": "outbound",
            "message_id": message_id.0,
            "new_text_hash_xxh3": xxhash_rust::xxh3::xxh3_64(new_text.as_bytes()),
            "new_text_bytes": new_text.len(),
            "ts_unix": ts_unix,
        })) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "serialize outbound CHANNEL_EDIT (0x38) failed");
                return;
            }
        };
        let header = crate::wal::make_header(crate::wal::events::EVENT_TYPE_CHANNEL_EDIT, &payload);
        if let Err(e) = writer.append(header, payload).await {
            tracing::warn!(error = %e, "WAL append outbound CHANNEL_EDIT (0x38) failed (non-fatal)");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channels::PipelineHandler;
    use anyhow::Result;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Configurable mock channel: counts send_text / edit_message calls, can be
    /// told to report `NotSupported` on edit, and records the last edit text.
    struct MockChannel {
        sends: AtomicUsize,
        edits: AtomicUsize,
        edit_not_supported: bool,
        last_edit_text: std::sync::Mutex<Option<String>>,
    }

    impl MockChannel {
        fn new(edit_not_supported: bool) -> Self {
            Self {
                sends: AtomicUsize::new(0),
                edits: AtomicUsize::new(0),
                edit_not_supported,
                last_edit_text: std::sync::Mutex::new(None),
            }
        }
    }

    #[async_trait]
    impl Channel for MockChannel {
        fn name(&self) -> &'static str {
            "mock"
        }
        async fn run(&self, _handler: PipelineHandler) -> Result<()> {
            Ok(())
        }
        async fn send_text(
            &self,
            _chat_id: &str,
            _text: &str,
        ) -> std::result::Result<MessageId, ChannelError> {
            let n = self.sends.fetch_add(1, Ordering::SeqCst);
            // A new id per send so the degrade path is observable.
            Ok(MessageId(format!("msg-{n}")))
        }
        async fn edit_message(
            &self,
            _chat_id: &str,
            _message_id: &MessageId,
            new_text: &str,
        ) -> std::result::Result<(), ChannelError> {
            if self.edit_not_supported {
                return Err(ChannelError::NotSupported {
                    feature: "edit_message",
                });
            }
            self.edits.fetch_add(1, Ordering::SeqCst);
            *self.last_edit_text.lock().unwrap() = Some(new_text.to_string());
            Ok(())
        }
    }

    fn test_writer() -> (
        WalWriterHandle,
        tokio::task::JoinHandle<()>,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let (writer, join) = crate::wal::writer::spawn(dir.path().join("ld.wal")).unwrap();
        (writer, join, dir)
    }

    fn count_channel_edit_frames(seg: &std::path::Path) -> usize {
        let Ok(bytes) = std::fs::read(seg) else {
            return 0;
        };
        let Ok(hdr) = crate::wal::segment_header::parse_segment_header(&bytes) else {
            return 0;
        };
        let mut cursor = hdr.header_len();
        let mut count = 0usize;
        while cursor < bytes.len() {
            let dec = match crate::wal::frame::decode_frame(&bytes[cursor..]) {
                Ok(d) => d,
                Err(_) => break,
            };
            if dec.header.event_type == crate::wal::events::EVENT_TYPE_CHANNEL_EDIT {
                count += 1;
            }
            let total = dec.header.total_len as usize;
            if total == 0 {
                break;
            }
            cursor = cursor.saturating_add(total);
        }
        count
    }

    /// Edits never rate-limited away — for the behavioural (non-rate-limit) tests.
    fn fast_config() -> LiveDeliveryConfig {
        LiveDeliveryConfig {
            edits_enabled: true,
            min_edit_interval_ms: 0,
            max_edits_per_message: 1000,
            final_edit_always_allowed: true,
        }
    }

    #[tokio::test]
    async fn first_call_sends_text() {
        let ch = Arc::new(MockChannel::new(false));
        let mut live = LiveDelivery::new(
            ch.clone(),
            "c1".into(),
            ChannelKind::Telegram,
            fast_config(),
        );
        let (writer, join, _dir) = test_writer();

        assert!(!live.has_sent());
        let out = live.send_or_edit(&writer, "hello", false).await.unwrap();
        assert_eq!(out, SendOutcome::Sent(MessageId("msg-0".into())));
        assert!(live.has_sent());
        assert_eq!(ch.sends.load(Ordering::SeqCst), 1);
        assert_eq!(ch.edits.load(Ordering::SeqCst), 0);

        drop(writer);
        let _ = join.await;
    }

    #[tokio::test]
    async fn second_call_edits_and_emits_0x38() {
        let ch = Arc::new(MockChannel::new(false));
        let mut live =
            LiveDelivery::new(ch.clone(), "c1".into(), ChannelKind::Slack, fast_config());
        let (writer, join, dir) = test_writer();
        let seg = dir.path().join("ld.wal");

        let first = live.send_or_edit(&writer, "draft", false).await.unwrap();
        let second = live.send_or_edit(&writer, "final", true).await.unwrap();
        assert_eq!(first, SendOutcome::Sent(MessageId("msg-0".into())));
        // Edit keeps the SAME id; no new send.
        assert_eq!(second, SendOutcome::Edited(MessageId("msg-0".into())));
        assert_eq!(ch.sends.load(Ordering::SeqCst), 1);
        assert_eq!(ch.edits.load(Ordering::SeqCst), 1);
        assert_eq!(ch.last_edit_text.lock().unwrap().as_deref(), Some("final"));

        drop(writer);
        let _ = join.await;
        assert_eq!(
            count_channel_edit_frames(&seg),
            1,
            "the edit path must emit exactly one outbound 0x38 frame"
        );
    }

    #[tokio::test]
    async fn degrades_to_send_when_edit_not_supported() {
        let ch = Arc::new(MockChannel::new(true)); // edit → NotSupported
        let mut live =
            LiveDelivery::new(ch.clone(), "c1".into(), ChannelKind::Discord, fast_config());
        let (writer, join, dir) = test_writer();
        let seg = dir.path().join("ld.wal");

        let first = live.send_or_edit(&writer, "one", false).await.unwrap();
        let second = live.send_or_edit(&writer, "two", false).await.unwrap();
        // Degrade path = a fresh send with a NEW id, no panic.
        assert_eq!(first, SendOutcome::Sent(MessageId("msg-0".into())));
        assert_eq!(second, SendOutcome::Sent(MessageId("msg-1".into())));
        assert_eq!(
            ch.sends.load(Ordering::SeqCst),
            2,
            "edit degraded to a 2nd send"
        );

        drop(writer);
        let _ = join.await;
        assert_eq!(
            count_channel_edit_frames(&seg),
            0,
            "a degraded fresh-send is NOT an edit — no 0x38 frame"
        );
    }

    #[tokio::test]
    async fn finalize_is_noop() {
        let ch = Arc::new(MockChannel::new(false));
        let mut live = LiveDelivery::new(ch, "c1".into(), ChannelKind::Telegram, fast_config());
        let (writer, join, _dir) = test_writer();
        let _ = live.send_or_edit(&writer, "x", false).await.unwrap();
        assert!(live.finalize().await.is_ok());
        drop(writer);
        let _ = join.await;
    }

    // ── SPEC-11 rate limiting (P1) ──────────────────────────────────────────

    #[test]
    fn should_send_edit_respects_interval() {
        let cfg = LiveDeliveryConfig {
            min_edit_interval_ms: 1000,
            ..fast_config()
        };
        // Too soon after the last edit → coalesce.
        assert!(!should_send_edit(&cfg, 900, Some(500), 0, false));
        // Past the interval → send.
        assert!(should_send_edit(&cfg, 1600, Some(500), 0, false));
        // No prior edit → send.
        assert!(should_send_edit(&cfg, 100, None, 0, false));
    }

    #[test]
    fn should_send_edit_respects_count_cap() {
        let cfg = LiveDeliveryConfig {
            max_edits_per_message: 3,
            min_edit_interval_ms: 0,
            ..fast_config()
        };
        assert!(should_send_edit(&cfg, 10, Some(0), 2, false));
        assert!(
            !should_send_edit(&cfg, 10, Some(0), 3, false),
            "at the cap → coalesce"
        );
    }

    #[test]
    fn should_send_edit_final_bypasses_limits() {
        let cfg = LiveDeliveryConfig {
            min_edit_interval_ms: 10_000,
            max_edits_per_message: 1,
            final_edit_always_allowed: true,
            ..fast_config()
        };
        // Past BOTH limits, but the final edit always lands.
        assert!(should_send_edit(&cfg, 0, Some(0), 99, true));
        // …unless the operator turned that off.
        let cfg_off = LiveDeliveryConfig {
            final_edit_always_allowed: false,
            ..cfg
        };
        assert!(!should_send_edit(&cfg_off, 0, Some(0), 99, true));
    }

    #[tokio::test]
    async fn rate_limit_coalesces_fast_intermediate_edit_then_final_lands() {
        let ch = Arc::new(MockChannel::new(false));
        let cfg = LiveDeliveryConfig {
            min_edit_interval_ms: 1000,
            ..fast_config()
        };
        let mut live = LiveDelivery::new(ch.clone(), "c1".into(), ChannelKind::Telegram, cfg);
        let (writer, join, _dir) = test_writer();

        // t=0: first send.
        let s = live
            .send_or_edit_at(&writer, 0, "draft", false)
            .await
            .unwrap();
        assert_eq!(s, SendOutcome::Sent(MessageId("msg-0".into())));
        // t=100: too soon → coalesced (no edit hits the wire).
        let c = live
            .send_or_edit_at(&writer, 100, "partial", false)
            .await
            .unwrap();
        assert_eq!(c, SendOutcome::Coalesced);
        assert_eq!(ch.edits.load(Ordering::SeqCst), 0, "fast edit dropped");
        // t=200: still too soon, but FINAL → always lands.
        let f = live
            .send_or_edit_at(&writer, 200, "final", true)
            .await
            .unwrap();
        assert_eq!(f, SendOutcome::Edited(MessageId("msg-0".into())));
        assert_eq!(ch.edits.load(Ordering::SeqCst), 1, "final edit landed");

        drop(writer);
        let _ = join.await;
    }

    #[tokio::test]
    async fn edits_disabled_sends_fresh_each_time() {
        let ch = Arc::new(MockChannel::new(false));
        let cfg = LiveDeliveryConfig {
            edits_enabled: false,
            min_edit_interval_ms: 0,
            ..fast_config()
        };
        let mut live = LiveDelivery::new(ch.clone(), "c1".into(), ChannelKind::Slack, cfg);
        let (writer, join, _dir) = test_writer();

        let a = live.send_or_edit_at(&writer, 0, "a", false).await.unwrap();
        let b = live.send_or_edit_at(&writer, 1, "b", false).await.unwrap();
        assert_eq!(a, SendOutcome::Sent(MessageId("msg-0".into())));
        assert_eq!(
            b,
            SendOutcome::Sent(MessageId("msg-1".into())),
            "send-only: never edits"
        );
        assert_eq!(
            ch.edits.load(Ordering::SeqCst),
            0,
            "edits disabled → 0 edits"
        );

        drop(writer);
        let _ = join.await;
    }

    #[tokio::test]
    async fn outbound_0x38_payload_shape() {
        let ch = Arc::new(MockChannel::new(false));
        let mut live = LiveDelivery::new(ch, "c1".into(), ChannelKind::Telegram, fast_config());
        let (writer, join, dir) = test_writer();
        let seg = dir.path().join("ld.wal");

        live.send_or_edit(&writer, "draft", false).await.unwrap();
        live.send_or_edit(&writer, "final", true).await.unwrap();
        drop(writer);
        let _ = join.await;

        // Decode the 0x38 frame + assert the field set matches the inbound-edit
        // contract (+ direction discriminator), text never present verbatim.
        let bytes = std::fs::read(&seg).unwrap();
        let hdr = crate::wal::segment_header::parse_segment_header(&bytes).unwrap();
        let mut cursor = hdr.header_len();
        let mut checked = false;
        while cursor < bytes.len() {
            let dec = match crate::wal::frame::decode_frame(&bytes[cursor..]) {
                Ok(d) => d,
                Err(_) => break,
            };
            if dec.header.event_type == crate::wal::events::EVENT_TYPE_CHANNEL_EDIT {
                let v: serde_json::Value = serde_json::from_slice(dec.payload).unwrap();
                assert_eq!(v["channel"], "telegram");
                assert_eq!(v["direction"], "outbound");
                assert_eq!(v["message_id"], "msg-0");
                assert_eq!(v["new_text_bytes"], 5); // "final"
                assert!(v.get("new_text_hash_xxh3").is_some());
                assert!(v.get("ts_unix").is_some());
                assert!(
                    v.get("new_text").is_none(),
                    "raw edit text must never be in the frame (PII)"
                );
                checked = true;
            }
            let total = dec.header.total_len as usize;
            if total == 0 {
                break;
            }
            cursor = cursor.saturating_add(total);
        }
        assert!(checked, "expected a 0x38 frame to inspect");
    }
}
