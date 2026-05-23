//! Keet channel adapter — R-2 stub.
//!
//! Keet rides on Holepunch's Hyperswarm + Hypercore stack (JS / Node).
//! A native-Rust port is multi-week work — see the research note
//! `QUELLEN/research/` (Phase 11 R-A1, pending). v0.1.x ships this
//! stub so the wizard's per-hemisphere picker + `freedom.yaml`
//! configuration round-trip cleanly without a "dispatching to a
//! nonexistent adapter" panic.
//!
//! What the stub provides:
//!   - `KeetChannel::new(seed_phrase)` — accepts the 24-word seed the
//!     operator paired with on their phone.
//!   - `Channel::name()` → `"keet"`.
//!   - `Channel::run(handler)` → returns a clear "deferred" error.
//!   - `send_text` / `send_media` inherit the trait's `NotSupported`
//!     default.
//!
//! Why this shape: the channel adapter trait + dispatch path are already
//! solid (`SP-5 C-prime`). What's missing is the Hyperswarm transport,
//! and that decision is captured separately. When the transport lands,
//! only `run()` + `send_text` + `send_media` need to be filled in.

use anyhow::Result;
use async_trait::async_trait;

use super::{Channel, PipelineHandler};
use crate::secret::SecretString;

pub struct KeetChannel {
    /// Operator's 24-word pairing phrase. Stored as `SecretString` so
    /// mlock + zeroize protect it the same way provider keys do.
    seed_phrase: SecretString,
}

impl KeetChannel {
    pub fn new(seed_phrase: SecretString) -> Self {
        Self { seed_phrase }
    }

    /// Operator-visible hint for the pairing flow. Exposed so the wizard
    /// can render the same line in both the seed-prompt and the post-
    /// install confirmation.
    pub const PAIRING_HINT: &'static str =
        "Paste the 24-word seed phrase Keet generated on your phone.";

    /// R-2 Phase 1 pairing-anchor preview: derive the 32-byte topic
    /// key + discovery key from the configured seed phrase. Returns
    /// the deterministic hex prefix the operator can match against
    /// their phone (the JS Keet side will surface the SAME hex
    /// prefix in the pairing UI once both sides upgrade to the
    /// same derivation). Empty phrase returns None.
    pub fn pairing_anchor_preview(&self) -> Option<String> {
        let topic = super::keet_crypto::topic_key(self.seed_phrase.expose()).ok()?;
        let discovery = super::keet_crypto::discovery_key(topic);
        // Render 16 hex chars from each so the operator can scan
        // both anchors at a glance.
        let topic_hex: String = topic.0[..8].iter().map(|b| format!("{b:02x}")).collect();
        let disc_hex: String = discovery.0[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        Some(format!("topic:{topic_hex}… disc:{disc_hex}…"))
    }
}

/// What a seed-phrase validation pass concluded. Operator-readable
/// enough that the wizard can render the variant directly without
/// translation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeedValidation {
    /// Phrase is the right shape (24 lowercase words, 3-8 chars each,
    /// only [a-z]). Doesn't BIP39-checksum-verify — Keet uses its own
    /// dictionary + checksum we can't recompute without the JS lib.
    Valid,
    /// Wrong word count. `expected = 24`, `got` is what we found.
    WrongWordCount { got: usize },
    /// One or more words contain characters outside `[a-z]`. The
    /// `bad_word_index` is 0-based so the wizard can highlight it.
    InvalidCharacter { bad_word_index: usize },
    /// One or more words are too short / too long for a plausible
    /// BIP39-style entry (3-8 chars). Likely an operator typo.
    SuspiciousWordLength {
        bad_word_index: usize,
        length: usize,
    },
}

impl SeedValidation {
    pub fn is_valid(&self) -> bool {
        matches!(self, SeedValidation::Valid)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SeedValidation::Valid => "valid",
            SeedValidation::WrongWordCount { .. } => "wrong_word_count",
            SeedValidation::InvalidCharacter { .. } => "invalid_character",
            SeedValidation::SuspiciousWordLength { .. } => "suspicious_word_length",
        }
    }
}

/// R-2 (2026-05-21): shape-check a Keet seed phrase before persisting.
/// Catches the common operator mistakes (truncated paste, extra
/// whitespace, typos) at wizard time rather than at first connect
/// when the diagnostic would surface as "Hyperswarm handshake failed
/// — bad keypair".
///
/// Does NOT verify the checksum — that requires Keet's own wordlist
/// and algorithm which live in the JS Holepunch stack. The transport
/// will reject a checksum-failing phrase at pairing time; this
/// function catches the 90% of operator typos.
pub fn validate_seed_phrase(s: &str) -> SeedValidation {
    let words: Vec<&str> = s.split_whitespace().collect();
    if words.len() != 24 {
        return SeedValidation::WrongWordCount { got: words.len() };
    }
    for (i, w) in words.iter().enumerate() {
        if w.len() < 3 || w.len() > 8 {
            return SeedValidation::SuspiciousWordLength {
                bad_word_index: i,
                length: w.len(),
            };
        }
        if !w.chars().all(|c| c.is_ascii_lowercase()) {
            return SeedValidation::InvalidCharacter { bad_word_index: i };
        }
    }
    SeedValidation::Valid
}

#[async_trait]
impl Channel for KeetChannel {
    fn name(&self) -> &'static str {
        "keet"
    }

    async fn run(&self, _handler: PipelineHandler) -> Result<()> {
        // Hyperswarm + Hypercore transport is multi-week work. The trait
        // path stays clean — when the transport lands, replace this body
        // with the actual swarm join + topic subscription. Until then,
        // dispatching to Keet bails fast with an actionable message.
        anyhow::bail!(
            "keet channel: receive loop is deferred until the Hyperswarm \
             transport lands. Use Telegram for v0.1.x. The seed phrase \
             you configured ({} chars) is persisted unchanged so the \
             upgrade requires no re-pairing.",
            self.seed_phrase.expose().len(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_reports_keet_name() {
        let c = KeetChannel::new(SecretString::from(
            "word ".repeat(24).trim_end().to_string(),
        ));
        assert_eq!(c.name(), "keet");
    }

    #[test]
    fn pairing_anchor_preview_renders_topic_and_discovery_hex() {
        let phrase = "alpha bravo charlie delta echo foxtrot golf hotel india juliet \
                      kilo lima mike november oscar papa quebec romeo sierra tango \
                      uniform victor whiskey xray";
        let c = KeetChannel::new(SecretString::from(phrase.to_string()));
        let preview = c.pairing_anchor_preview().expect("non-empty phrase");
        assert!(preview.contains("topic:"));
        assert!(preview.contains("disc:"));
        // Hex prefixes should be deterministic across calls.
        let again = c.pairing_anchor_preview().unwrap();
        assert_eq!(preview, again);
    }

    #[test]
    fn pairing_anchor_preview_returns_none_for_empty_phrase() {
        let c = KeetChannel::new(SecretString::from("   \t\n  ".to_string()));
        assert!(c.pairing_anchor_preview().is_none());
    }

    #[tokio::test]
    async fn run_bails_with_actionable_message() {
        let c = KeetChannel::new(SecretString::from("seed".to_string()));
        let handler: PipelineHandler = Box::new(|_inbound| Box::pin(async move { Ok(None) }));
        let err = c.run(handler).await.unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("deferred"), "msg: {msg}");
        assert!(msg.contains("Telegram"), "msg: {msg}");
    }

    /// Trait defaults must surface as `NotSupported` so callers can
    /// distinguish "stub, will land later" from "transport error".
    #[tokio::test]
    async fn send_text_inherits_not_supported_default() {
        use crate::channels::ChannelError;
        let c = KeetChannel::new(SecretString::from("x".to_string()));
        let err = c.send_text("chat", "hi").await.unwrap_err();
        assert!(matches!(
            err,
            ChannelError::NotSupported {
                feature: "send_text"
            }
        ));
    }

    #[test]
    fn pairing_hint_is_non_empty_and_single_line() {
        assert!(!KeetChannel::PAIRING_HINT.is_empty());
        assert!(!KeetChannel::PAIRING_HINT.contains('\n'));
    }

    // ── R-2 seed-phrase validation (2026-05-21) ──────────────────────

    fn good_phrase() -> String {
        // 24 lowercase 4-6 letter words. Not a real Keet phrase
        // (no checksum guarantee) but shape-valid for the validator.
        let words = [
            "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
            "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
            "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
        ];
        words.join(" ")
    }

    #[test]
    fn validate_seed_accepts_well_formed_24_word_phrase() {
        let v = validate_seed_phrase(&good_phrase());
        assert_eq!(v, SeedValidation::Valid);
        assert!(v.is_valid());
    }

    #[test]
    fn validate_seed_rejects_truncated_paste() {
        // Operator hit Enter mid-paste — 12 words instead of 24.
        let full = good_phrase();
        let words: Vec<&str> = full.split_whitespace().take(12).collect();
        let v = validate_seed_phrase(&words.join(" "));
        assert_eq!(v, SeedValidation::WrongWordCount { got: 12 });
        assert!(!v.is_valid());
    }

    #[test]
    fn validate_seed_rejects_extra_words() {
        let mut phrase = good_phrase();
        phrase.push_str(" extra");
        assert_eq!(
            validate_seed_phrase(&phrase),
            SeedValidation::WrongWordCount { got: 25 }
        );
    }

    #[test]
    fn validate_seed_rejects_uppercase_letters() {
        // Operator copied from a doc that title-cased the phrase.
        let mut words: Vec<String> = good_phrase().split_whitespace().map(String::from).collect();
        words[5] = "AbSORB".into();
        let v = validate_seed_phrase(&words.join(" "));
        assert_eq!(v, SeedValidation::InvalidCharacter { bad_word_index: 5 });
    }

    #[test]
    fn validate_seed_rejects_digits_or_punctuation() {
        let mut words: Vec<String> = good_phrase().split_whitespace().map(String::from).collect();
        words[10] = "acc3ss".into();
        let v = validate_seed_phrase(&words.join(" "));
        assert_eq!(v, SeedValidation::InvalidCharacter { bad_word_index: 10 });
    }

    #[test]
    fn validate_seed_rejects_too_short_word() {
        let mut words: Vec<String> = good_phrase().split_whitespace().map(String::from).collect();
        words[3] = "ab".into(); // 2 chars — implausible
        let v = validate_seed_phrase(&words.join(" "));
        assert_eq!(
            v,
            SeedValidation::SuspiciousWordLength {
                bad_word_index: 3,
                length: 2
            }
        );
    }

    #[test]
    fn validate_seed_rejects_too_long_word() {
        let mut words: Vec<String> = good_phrase().split_whitespace().map(String::from).collect();
        words[7] = "supercalifragilistic".into();
        let v = validate_seed_phrase(&words.join(" "));
        assert!(matches!(
            v,
            SeedValidation::SuspiciousWordLength {
                bad_word_index: 7,
                ..
            }
        ));
    }

    #[test]
    fn validate_seed_handles_extra_whitespace() {
        // split_whitespace collapses runs — tab + double-space input
        // still passes shape validation.
        let normal = good_phrase();
        let messy = normal.replace(' ', "  \t  ");
        assert!(validate_seed_phrase(&messy).is_valid());
    }

    #[test]
    fn seed_validation_wire_form_is_stable() {
        // The wizard uses these strings in JSON output + WAL frames.
        // Pin so a refactor surfaces here.
        assert_eq!(SeedValidation::Valid.as_str(), "valid");
        assert_eq!(
            SeedValidation::WrongWordCount { got: 0 }.as_str(),
            "wrong_word_count"
        );
        assert_eq!(
            SeedValidation::InvalidCharacter { bad_word_index: 0 }.as_str(),
            "invalid_character"
        );
        assert_eq!(
            SeedValidation::SuspiciousWordLength {
                bad_word_index: 0,
                length: 0
            }
            .as_str(),
            "suspicious_word_length"
        );
    }
}
