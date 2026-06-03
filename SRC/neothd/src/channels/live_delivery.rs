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
use crate::wal::writer::WalWriterHandle;

/// Stateful wrapper that sends a message once, then edits it in place on
/// subsequent updates. NOT `Clone` — the `sent_message_id` is per-delivery
/// state; share via the owning task, not by copying.
pub struct LiveDelivery {
    channel: Arc<dyn Channel>,
    chat_id: String,
    kind: ChannelKind,
    /// `None` until the first `send_or_edit` succeeds; then the platform id of
    /// the live message every subsequent edit targets.
    sent_message_id: Option<MessageId>,
}

impl LiveDelivery {
    /// New delivery bound to `chat_id` on `channel` (of family `kind`). Nothing
    /// is sent until the first [`LiveDelivery::send_or_edit`].
    pub fn new(channel: Arc<dyn Channel>, chat_id: String, kind: ChannelKind) -> Self {
        Self {
            channel,
            chat_id,
            kind,
            sent_message_id: None,
        }
    }

    /// `true` once the first send has landed (a `MessageId` is held).
    pub fn has_sent(&self) -> bool {
        self.sent_message_id.is_some()
    }

    /// Send (first call) or edit-in-place (subsequent calls).
    ///
    /// - First call: `send_text` → store + return the new `MessageId`.
    /// - Subsequent calls: `edit_message` against the stored id → emit
    ///   `0x38 CHANNEL_EDIT` + return the SAME id.
    /// - If `edit_message` reports `NotSupported`: degrade to a fresh
    ///   `send_text`, update the stored id, return the NEW id (no 0x38 — a
    ///   brand-new message is not an edit).
    ///
    /// Any other `edit_message` / `send_text` error propagates unchanged.
    pub async fn send_or_edit(
        &mut self,
        writer: &WalWriterHandle,
        text: &str,
    ) -> std::result::Result<MessageId, ChannelError> {
        match self.sent_message_id.clone() {
            None => {
                let id = self.channel.send_text(&self.chat_id, text).await?;
                self.sent_message_id = Some(id.clone());
                Ok(id)
            }
            Some(existing) => match self.channel.edit_message(&self.chat_id, &existing, text).await {
                Ok(()) => {
                    self.emit_edit(writer, &existing, text).await;
                    Ok(existing)
                }
                Err(ChannelError::NotSupported { .. }) => {
                    // Adapter has no edit API → send a fresh message instead.
                    let id = self.channel.send_text(&self.chat_id, text).await?;
                    self.sent_message_id = Some(id.clone());
                    Ok(id)
                }
                Err(e) => Err(e),
            },
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

    fn test_writer() -> (WalWriterHandle, tokio::task::JoinHandle<()>, tempfile::TempDir) {
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

    #[tokio::test]
    async fn first_call_sends_text() {
        let ch = Arc::new(MockChannel::new(false));
        let mut live = LiveDelivery::new(ch.clone(), "c1".into(), ChannelKind::Telegram);
        let (writer, join, _dir) = test_writer();

        assert!(!live.has_sent());
        let id = live.send_or_edit(&writer, "hello").await.unwrap();
        assert_eq!(id, MessageId("msg-0".into()));
        assert!(live.has_sent());
        assert_eq!(ch.sends.load(Ordering::SeqCst), 1);
        assert_eq!(ch.edits.load(Ordering::SeqCst), 0);

        drop(writer);
        let _ = join.await;
    }

    #[tokio::test]
    async fn second_call_edits_and_emits_0x38() {
        let ch = Arc::new(MockChannel::new(false));
        let mut live = LiveDelivery::new(ch.clone(), "c1".into(), ChannelKind::Slack);
        let (writer, join, dir) = test_writer();
        let seg = dir.path().join("ld.wal");

        let first = live.send_or_edit(&writer, "draft").await.unwrap();
        let second = live.send_or_edit(&writer, "final").await.unwrap();
        // Edit keeps the SAME id; no new send.
        assert_eq!(first, second, "edit must reuse the original message id");
        assert_eq!(ch.sends.load(Ordering::SeqCst), 1);
        assert_eq!(ch.edits.load(Ordering::SeqCst), 1);
        assert_eq!(
            ch.last_edit_text.lock().unwrap().as_deref(),
            Some("final")
        );

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
        let mut live = LiveDelivery::new(ch.clone(), "c1".into(), ChannelKind::Discord);
        let (writer, join, dir) = test_writer();
        let seg = dir.path().join("ld.wal");

        let first = live.send_or_edit(&writer, "one").await.unwrap();
        let second = live.send_or_edit(&writer, "two").await.unwrap();
        // Degrade path = a fresh send with a NEW id, no panic.
        assert_eq!(first, MessageId("msg-0".into()));
        assert_eq!(second, MessageId("msg-1".into()));
        assert_eq!(ch.sends.load(Ordering::SeqCst), 2, "edit degraded to a 2nd send");

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
        let mut live = LiveDelivery::new(ch, "c1".into(), ChannelKind::Telegram);
        let (writer, join, _dir) = test_writer();
        let _ = live.send_or_edit(&writer, "x").await.unwrap();
        assert!(live.finalize().await.is_ok());
        drop(writer);
        let _ = join.await;
    }

    #[tokio::test]
    async fn outbound_0x38_payload_shape() {
        let ch = Arc::new(MockChannel::new(false));
        let mut live = LiveDelivery::new(ch, "c1".into(), ChannelKind::Telegram);
        let (writer, join, dir) = test_writer();
        let seg = dir.path().join("ld.wal");

        live.send_or_edit(&writer, "draft").await.unwrap();
        live.send_or_edit(&writer, "final").await.unwrap();
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
