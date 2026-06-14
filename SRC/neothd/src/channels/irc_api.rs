//! GOLD-FEAT-10 — IRC protocol mapping: the pure inbound `PRIVMSG` →
//! [`InboundMessage`] conversion + the outbound line-splitter. The
//! [`super::irc`] adapter (behind the `irc-channel` feature) extracts the
//! `(target, text, source-nick)` primitives from the `irc` crate's `Message`
//! and calls in here, so the mapping + split logic are unit-testable without
//! the irc crate or a live connection. This module is always compiled (it
//! carries no `irc` dependency).

use super::{ChannelKind, InboundMessage};

/// IRC payload split point. A full PRIVMSG line is capped at 512 BYTES
/// including the `:nick!user@host PRIVMSG target :` envelope + CRLF, so 400
/// chars of payload is the safe boundary (the formatter's `IRC_MAX_CHARS`).
pub const IRC_MAX_TEXT_CHARS: usize = 400;

/// Map one inbound IRC PRIVMSG to an [`InboundMessage`]. Returns `None` for our
/// own echo (`source_nick == our_nick`), an empty body, or a sourceless line we
/// cannot attribute.
///
/// `target` is the PRIVMSG target: a channel (`#room` / `&local`) for a channel
/// message, or our own nick for a private message. The reply `chat_id` is the
/// channel for a channel message, or the SENDER's nick for a DM (so the reply
/// goes back to them, never to ourselves).
pub fn map_irc_privmsg(
    target: &str,
    text: &str,
    source_nick: Option<&str>,
    our_nick: &str,
    ts_unix: u64,
) -> Option<InboundMessage> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let sender = source_nick.map(str::trim).filter(|s| !s.is_empty())?;
    if sender.eq_ignore_ascii_case(our_nick) {
        return None; // our own message echoed back — never loop on it
    }
    // A channel message (`#`/`&`) replies to the channel; a DM (target is our
    // own nick) replies to the sender.
    let is_channel = target.starts_with('#') || target.starts_with('&');
    let chat_id = if is_channel {
        target.to_string()
    } else {
        sender.to_string()
    };
    Some(InboundMessage {
        channel: ChannelKind::Irc,
        chat_id,
        thread_id: None,
        sender_id: sender.to_string(),
        sender_display: None,
        text: Some(text.to_string()),
        media: None,
        reply_to: None,
        message_id: None, // IRC carries no per-message id
        edit_unix: None,
        mention_kind: None,
        channel_ts_unix: ts_unix,
        raw_ts_ms: None,
        human_uuid: None,
    })
}

/// Split an outbound reply into IRC-safe PRIVMSG lines: one PRIVMSG per source
/// line (IRC has no in-message newlines — a `\n` ends the command), each chunked
/// to [`IRC_MAX_TEXT_CHARS`] characters. Blank lines are dropped (a blank
/// PRIVMSG is meaningless and some servers reject it).
pub fn irc_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in text.split('\n') {
        let line = raw.trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }
        let mut buf = String::new();
        let mut count = 0usize;
        for c in line.chars() {
            buf.push(c);
            count += 1;
            if count >= IRC_MAX_TEXT_CHARS {
                out.push(std::mem::take(&mut buf));
                count = 0;
            }
        }
        if !buf.is_empty() {
            out.push(buf);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_message_replies_to_channel() {
        let m = map_irc_privmsg("#dev", "hi team", Some("alice"), "neoth", 100).unwrap();
        assert_eq!(m.channel, ChannelKind::Irc);
        assert_eq!(m.chat_id, "#dev", "a channel message replies to the channel");
        assert_eq!(m.sender_id, "alice");
        assert_eq!(m.text.as_deref(), Some("hi team"));
        assert_eq!(m.channel_ts_unix, 100);
    }

    #[test]
    fn dm_replies_to_sender_not_self() {
        // target == our own nick → a private message; reply goes to the sender.
        let m = map_irc_privmsg("neoth", "ping", Some("bob"), "neoth", 5).unwrap();
        assert_eq!(m.chat_id, "bob", "a DM replies to the sender, never to ourselves");
        assert_eq!(m.sender_id, "bob");
    }

    #[test]
    fn ampersand_local_channel_is_a_channel() {
        let m = map_irc_privmsg("&local", "x", Some("carol"), "neoth", 1).unwrap();
        assert_eq!(m.chat_id, "&local");
    }

    #[test]
    fn own_echo_is_skipped() {
        // Case-insensitive: IRC nicks are case-insensitive per RFC.
        assert!(map_irc_privmsg("#dev", "hi", Some("NeoTH"), "neoth", 1).is_none());
    }

    #[test]
    fn empty_text_and_sourceless_are_skipped() {
        assert!(map_irc_privmsg("#dev", "   ", Some("alice"), "neoth", 1).is_none());
        assert!(map_irc_privmsg("#dev", "hi", None, "neoth", 1).is_none());
        assert!(map_irc_privmsg("#dev", "hi", Some("  "), "neoth", 1).is_none());
    }

    #[test]
    fn irc_lines_splits_one_privmsg_per_source_line() {
        let out = irc_lines("first\nsecond\nthird");
        assert_eq!(out, vec!["first", "second", "third"]);
    }

    #[test]
    fn irc_lines_chunks_a_long_line_at_the_char_cap() {
        let long = "x".repeat(IRC_MAX_TEXT_CHARS + 50);
        let out = irc_lines(&long);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].chars().count(), IRC_MAX_TEXT_CHARS);
        assert_eq!(out[1].chars().count(), 50);
    }

    #[test]
    fn irc_lines_drops_blank_lines_and_strips_cr() {
        let out = irc_lines("a\r\n\r\n\nb");
        assert_eq!(out, vec!["a", "b"]);
    }
}
