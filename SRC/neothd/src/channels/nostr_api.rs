//! GOLD-FEAT-10 — Nostr protocol mapping: the pure inbound NIP-17 DM →
//! [`InboundMessage`] conversion + the outbound chunker. The [`super::nostr`]
//! adapter (behind the `nostr-channel` feature) extracts the
//! `(sender_pubkey_hex, content, created_at)` primitives from an unwrapped
//! gift-wrap rumor and calls in here, so the mapping + chunk logic are
//! unit-testable without `nostr-sdk` or a live relay. This module is always
//! compiled (it carries no `nostr-sdk` dependency).

use super::{ChannelKind, InboundMessage};

/// Nostr has no hard protocol-level content cap, but relays commonly reject
/// very large events. 8000 chars is a comfortable per-message payload that
/// stays well under typical relay limits; long replies split across several
/// DMs. Matches the formatter's `NOSTR_MAX_CHARS`.
pub const NOSTR_MAX_TEXT_CHARS: usize = 8_000;

/// Map one inbound NIP-17 direct message (an already-unwrapped gift-wrap rumor)
/// to an [`InboundMessage`]. Returns `None` for an empty body or a sourceless
/// rumor we cannot attribute.
///
/// `sender_pubkey_hex` is the rumor author's public key (hex). Because NIP-17
/// gift wraps are addressed TO us, the sender is never ourselves, so the reply
/// `chat_id` is always the sender's pubkey — a reply DM routes straight back to
/// them.
pub fn map_nostr_dm(
    sender_pubkey_hex: &str,
    content: &str,
    ts_unix: u64,
) -> Option<InboundMessage> {
    let content = content.trim();
    if content.is_empty() {
        return None;
    }
    let sender = sender_pubkey_hex.trim();
    if sender.is_empty() {
        return None;
    }
    Some(InboundMessage {
        channel: ChannelKind::Nostr,
        chat_id: sender.to_string(),
        thread_id: None,
        sender_id: sender.to_string(),
        sender_display: None,
        text: Some(content.to_string()),
        media: None,
        reply_to: None,
        message_id: None, // the inner rumor id is not surfaced to the pipeline
        edit_unix: None,
        mention_kind: None,
        channel_ts_unix: ts_unix,
        raw_ts_ms: None,
        human_uuid: None,
    })
}

/// Split an outbound reply into Nostr-safe DM chunks, each capped at
/// [`NOSTR_MAX_TEXT_CHARS`] characters. Unlike IRC, newlines are preserved (a
/// Nostr event content is free-form text), so a multi-line reply stays one chunk
/// until it exceeds the cap. An empty/whitespace reply yields no chunks (a blank
/// DM is meaningless).
pub fn nostr_text_chunks(text: &str) -> Vec<String> {
    if text.trim().is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut count = 0usize;
    for c in text.chars() {
        buf.push(c);
        count += 1;
        if count >= NOSTR_MAX_TEXT_CHARS {
            out.push(std::mem::take(&mut buf));
            count = 0;
        }
    }
    if !buf.is_empty() {
        out.push(buf);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dm_maps_to_inbound_replying_to_sender() {
        let m = map_nostr_dm("abcd1234pubkeyhex", "gm nostr", 1000).unwrap();
        assert_eq!(m.channel, ChannelKind::Nostr);
        assert_eq!(
            m.chat_id, "abcd1234pubkeyhex",
            "a DM replies to the sender's pubkey"
        );
        assert_eq!(m.sender_id, "abcd1234pubkeyhex");
        assert_eq!(m.text.as_deref(), Some("gm nostr"));
        assert_eq!(m.channel_ts_unix, 1000);
        assert!(m.message_id.is_none());
    }

    #[test]
    fn empty_or_whitespace_content_is_skipped() {
        assert!(map_nostr_dm("pk", "   ", 1).is_none());
        assert!(map_nostr_dm("pk", "", 1).is_none());
    }

    #[test]
    fn empty_sender_is_skipped() {
        assert!(map_nostr_dm("   ", "hi", 1).is_none());
    }

    #[test]
    fn content_is_trimmed() {
        let m = map_nostr_dm("pk", "  hello  ", 1).unwrap();
        assert_eq!(m.text.as_deref(), Some("hello"));
    }

    #[test]
    fn short_reply_is_one_chunk_preserving_newlines() {
        let out = nostr_text_chunks("line one\nline two");
        assert_eq!(
            out,
            vec!["line one\nline two"],
            "newlines stay inside one DM chunk"
        );
    }

    #[test]
    fn long_reply_splits_at_the_char_cap() {
        let long = "x".repeat(NOSTR_MAX_TEXT_CHARS + 25);
        let out = nostr_text_chunks(&long);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].chars().count(), NOSTR_MAX_TEXT_CHARS);
        assert_eq!(out[1].chars().count(), 25);
    }

    #[test]
    fn blank_reply_yields_no_chunks() {
        assert!(nostr_text_chunks("   \n  ").is_empty());
    }
}
