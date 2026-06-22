//! GOLD-ADAPT-HERMES-03b — out-of-band clarification answer-routing store.
//!
//! The CLI clarification path ([`crate::cli::clarify_chat`]) PARKS the worker on
//! a [`crate::daemon::clarify::ClarificationGate`] and reads the answer from
//! stdin. On a channel / autonomous surface there is no stdin and no place to
//! park across an `.await` inside the per-message handler closure (its future
//! must stay `Send` and short-lived) — the answer arrives OUT OF BAND as the
//! operator's NEXT inbound message.
//!
//! This module is that bridge. When a channel reply asks for clarification the
//! handler records the original (already-enriched) prompt keyed on
//! `(channel, sender)`; the operator's next message is then re-issued as
//! `"<original>\n\n[operator clarification]: <answer>"`. No parking, no held
//! await — the state lives here between two independent handler invocations.
//!
//! Process-global + best-effort: a poisoned lock degrades to "no pending"
//! (the message is treated as a fresh request) rather than panicking the
//! channel loop.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

static PENDING: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

fn store_map() -> &'static Mutex<HashMap<String, String>> {
    PENDING.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Compose the per-conversation key. The sender component should already be the
/// PII-hashed id the channel pipeline uses elsewhere (never the plaintext id).
fn key(channel: &str, sender: &str) -> String {
    format!("{channel}:{sender}")
}

/// Record a pending clarification. `original_prompt` is the (already-enriched)
/// prompt whose reply asked a clarifying question. Overwrites any prior pending
/// for the same `(channel, sender)` — the latest unanswered question wins.
pub fn store(channel: &str, sender: &str, original_prompt: &str) {
    if let Ok(mut m) = store_map().lock() {
        m.insert(key(channel, sender), original_prompt.to_string());
    }
}

/// If a clarification is pending for `(channel, sender)`, CONSUME it and return
/// the combined re-issue prompt
/// (`"<original>\n\n[operator clarification]: <answer>"`). Returns `None` when
/// nothing is pending — the caller then treats `answer` as a fresh request.
pub fn take_combined(channel: &str, sender: &str, answer: &str) -> Option<String> {
    let original = store_map().lock().ok()?.remove(&key(channel, sender))?;
    Some(format!("{original}\n\n[operator clarification]: {answer}"))
}

/// True when a clarification is currently pending (diagnostic / test helper).
pub fn is_pending(channel: &str, sender: &str) -> bool {
    store_map()
        .lock()
        .map(|m| m.contains_key(&key(channel, sender)))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_then_take_combines_and_clears() {
        // Distinct keys per test — the store is process-global (OnceLock).
        store("hermes03b-telegram", "u1", "deploy the cluster");
        assert!(is_pending("hermes03b-telegram", "u1"));
        let combined = take_combined("hermes03b-telegram", "u1", "staging").unwrap();
        assert!(combined.contains("deploy the cluster"), "keeps original: {combined}");
        assert!(
            combined.contains("[operator clarification]: staging"),
            "appends the answer: {combined}"
        );
        // Consumed → gone (single round-trip per stored question).
        assert!(!is_pending("hermes03b-telegram", "u1"));
        assert!(take_combined("hermes03b-telegram", "u1", "x").is_none());
    }

    #[test]
    fn take_without_pending_is_none() {
        assert!(take_combined("hermes03b-slack", "no-such-sender", "ans").is_none());
    }

    #[test]
    fn keys_isolated_per_channel_and_sender() {
        store("hermes03b-iso", "a", "Pa");
        store("hermes03b-iso", "b", "Pb");
        assert!(take_combined("hermes03b-iso", "a", "x").unwrap().contains("Pa"));
        assert!(take_combined("hermes03b-iso", "b", "y").unwrap().contains("Pb"));
    }
}
