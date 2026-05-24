//! K-3 (Session 21, 2026-05-23) — Keet pairing UX primitives.
//!
//! Builds on:
//!   - `channels::pears_bridge::PearsBridge::with_bearer_token` —
//!     the API the bearer-token generator targets.
//!   - `channels::keet::KeetChannel::pairing_anchor_preview` —
//!     the deterministic hex anchor the operator scans on their phone.
//!   - `channels::keet::validate_seed_phrase` — shape-check on the
//!     pasted 24-word phrase.
//!
//! Per the 6/6 senior-dev panel verdict D-101b ("minimal first"), this
//! module ships the pairing primitives only — wizard wire-up (the
//! actual interactive prompt + `pear` process launch) lands in a
//! cli/init.rs follow-up so each ship stays reviewable on its own.
//!
//! ## Bearer-token security model
//!
//! Per the security-reviewer agent verdict on D-101: the Pears HTTP
//! bridge is localhost-only but any process running as the same user
//! can sniff or spoof it without auth. The bearer-token is the
//! defence-in-depth layer.
//!
//! Lifecycle:
//!   - Generated once per NEOTH session (wizard runs `generate_bearer_token()`)
//!   - Handed to the `pear` runtime on launch (via env-var or stdin)
//!   - Stored in `freedom.yaml::channels.pears.bridge_token` (mode 0600)
//!   - Every `PearsBridge::post_message` / `.health()` attaches it via
//!     `bearer_auth` header so the bridge can verify the caller
//!
//! Rotation: operators run `neoth plugin disable / re-enable` style
//! flows for K-3.5 (deferred). For v0.1 the token persists for the
//! freedom.yaml lifetime; rotation = `neoth init --reconfigure`.

use anyhow::{Context, Result};

use super::keet::validate_seed_phrase;
use crate::secret::SecretString;

/// Bearer-token byte length. 32 bytes / 256 bits — same strength as
/// the project's HMAC keys (per `wal/hmac.rs`). 64 hex chars when
/// rendered, fits a single freedom.yaml line.
pub const BEARER_TOKEN_BYTES: usize = 32;

/// Generated bearer token wrapped in `SecretString` so the same
/// mlock+zeroize protections that apply to provider keys + seed
/// phrases cover the Pears auth secret too.
///
/// Display impl intentionally redacts — operator-facing log lines
/// MUST NOT leak the token. Use `expose()` only at the boundary that
/// hands the token to `pear` or attaches it to a request.
pub struct BearerToken(SecretString);

impl BearerToken {
    /// Generate a fresh 32-byte token via `getrandom`. The OS RNG is
    /// the right source — `getrandom::getrandom` is the same primitive
    /// `rand::random` would use under the hood.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; BEARER_TOKEN_BYTES];
        getrandom::getrandom(&mut bytes).context("OS RNG failed during bearer token generation")?;
        let hex_str = hex::encode(bytes);
        Ok(Self(SecretString::from(hex_str)))
    }

    /// Construct from an existing hex string (e.g. read from
    /// freedom.yaml at daemon boot). Returns Err if the input isn't
    /// 64 hex chars — defence against a half-pasted token surviving
    /// to runtime.
    pub fn from_hex(s: impl Into<String>) -> Result<Self> {
        let s = s.into();
        if s.len() != BEARER_TOKEN_BYTES * 2 {
            anyhow::bail!(
                "bearer token must be {} hex chars (got {})",
                BEARER_TOKEN_BYTES * 2,
                s.len()
            );
        }
        if !s.chars().all(|c| c.is_ascii_hexdigit()) {
            anyhow::bail!("bearer token must be hex-only");
        }
        Ok(Self(SecretString::from(s)))
    }

    /// Expose the raw token. Boundary-only — pass to `pear` or
    /// `PearsBridge::with_bearer_token`. Never log.
    pub fn expose(&self) -> &str {
        self.0.expose()
    }

    /// Hex-encoded length, for shape assertions without exposing the
    /// bytes themselves.
    pub fn len(&self) -> usize {
        self.0.expose().len()
    }

    /// Returns `true` when the token is empty (degenerate guard for
    /// future from_hex callers that might pass "").
    pub fn is_empty(&self) -> bool {
        self.0.expose().is_empty()
    }
}

impl std::fmt::Debug for BearerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BearerToken")
            .field("hex_len", &self.len())
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Operator-facing pairing info — output of `prepare_pairing()`. The
/// wizard renders these fields one-per-line; the operator types the
/// hex anchor into their phone's Keet pairing screen and confirms
/// they match.
#[derive(Debug)]
pub struct PairingInfo {
    /// Same as `KeetChannel::pairing_anchor_preview` — deterministic
    /// hex prefix the operator's phone will show.
    pub pairing_anchor: String,
    /// Fresh bearer token generated for THIS pairing session. Operator
    /// never sees the value (display is redacted); the wizard writes it
    /// to freedom.yaml + hands it to the `pear` process.
    pub bearer_token: BearerToken,
    /// freedom.yaml snippet ready to print to the operator after
    /// confirmation. Builds on
    /// `channels::pears_bridge::render_freedom_yaml_snippet`.
    pub freedom_yaml_snippet: String,
}

/// Prepare a Keet pairing session: validate the seed phrase, derive
/// the deterministic anchor, generate a fresh bearer token, render
/// the freedom.yaml snippet. Pure-fn-ish — no I/O, no network. The
/// wizard runs this BEFORE prompting the operator so any seed-phrase
/// error surfaces immediately.
pub fn prepare_pairing(seed_phrase: &str, bridge_port: u16) -> Result<PairingInfo> {
    let validation = validate_seed_phrase(seed_phrase);
    if !validation.is_valid() {
        anyhow::bail!(
            "Keet seed phrase rejected: {}. Re-paste the 24-word phrase \
             your phone showed exactly, lowercase, single-spaced.",
            validation.as_str()
        );
    }
    let secret = SecretString::from(seed_phrase.trim().to_string());
    let channel = super::keet::KeetChannel::new(secret);
    let pairing_anchor = channel
        .pairing_anchor_preview()
        .ok_or_else(|| anyhow::anyhow!("seed phrase produced no anchor — empty after trim?"))?;
    let bearer_token = BearerToken::generate()?;
    let freedom_yaml_snippet = super::pears_bridge::render_freedom_yaml_snippet(bridge_port, true);
    Ok(PairingInfo {
        pairing_anchor,
        bearer_token,
        freedom_yaml_snippet,
    })
}

/// Operator-facing instructional text the wizard prints alongside the
/// pairing anchor. Single source of truth so the GUI + CLI render the
/// same step list.
pub const PAIRING_INSTRUCTIONS: &[&str] = &[
    "1. Open Keet on your phone. Tap 'Add device' → 'Scan QR' or 'Enter code'.",
    "2. Match the hex anchor shown below against the one your phone displays.",
    "3. If they match, tap 'Confirm pairing' on your phone.",
    "4. NEOTH writes the bearer token to ~/.neoth/freedom.yaml (mode 0600).",
    "5. Restart `neoth serve` so the daemon picks up the new bridge config.",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn good_phrase() -> String {
        // Same shape-valid 24-word phrase used in channels::keet::tests.
        // Not a real Keet phrase (no checksum guarantee).
        let words = [
            "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
            "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
            "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
        ];
        words.join(" ")
    }

    // ── BearerToken ──────────────────────────────────────────────────

    #[test]
    fn generate_returns_64_hex_chars() {
        let tok = BearerToken::generate().expect("OS rng works");
        assert_eq!(tok.len(), BEARER_TOKEN_BYTES * 2);
        assert!(tok.expose().chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!tok.is_empty());
    }

    #[test]
    fn two_generates_produce_distinct_tokens() {
        // Pin that the RNG isn't degenerate — collision in 256 bits is
        // astronomically unlikely so this acts as a smoke test for the
        // getrandom wiring.
        let a = BearerToken::generate().unwrap();
        let b = BearerToken::generate().unwrap();
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn debug_redacts_token_value() {
        // Operator-safety: the Debug impl MUST NOT print the secret
        // because tracing macros + panic messages run Debug. Pin so a
        // future derive(Debug) drop-in surfaces here at test time.
        let tok = BearerToken::generate().unwrap();
        let s = format!("{tok:?}");
        assert!(s.contains("<redacted>"));
        assert!(!s.contains(tok.expose()));
    }

    #[test]
    fn from_hex_accepts_exact_length_hex_string() {
        let s = "a".repeat(BEARER_TOKEN_BYTES * 2);
        let tok = BearerToken::from_hex(s.clone()).unwrap();
        assert_eq!(tok.expose(), s);
    }

    #[test]
    fn from_hex_rejects_wrong_length() {
        let too_short = BearerToken::from_hex("abc");
        assert!(too_short.is_err());
        assert!(too_short.unwrap_err().to_string().contains("hex chars"));

        let too_long = BearerToken::from_hex("a".repeat(BEARER_TOKEN_BYTES * 2 + 1));
        assert!(too_long.is_err());
    }

    #[test]
    fn from_hex_rejects_non_hex_characters() {
        let bad = BearerToken::from_hex("Z".repeat(BEARER_TOKEN_BYTES * 2));
        assert!(bad.is_err());
        assert!(bad.unwrap_err().to_string().contains("hex"));
    }

    // ── prepare_pairing ─────────────────────────────────────────────

    #[test]
    fn prepare_pairing_returns_anchor_token_and_snippet_for_valid_phrase() {
        let info = prepare_pairing(&good_phrase(), 9100).unwrap();
        assert!(info.pairing_anchor.contains("topic:"));
        assert!(info.pairing_anchor.contains("disc:"));
        assert_eq!(info.bearer_token.len(), BEARER_TOKEN_BYTES * 2);
        assert!(info.freedom_yaml_snippet.contains("bridge_port: 9100"));
        assert!(info.freedom_yaml_snippet.contains("bridge_token:"));
    }

    #[test]
    fn prepare_pairing_returns_deterministic_anchor_across_calls() {
        // Anchor is derived from seed alone — must match on re-prepare
        // so an operator who re-runs the wizard sees the SAME anchor
        // their phone is showing. (Bearer token re-rolls; anchor does
        // not.)
        let a = prepare_pairing(&good_phrase(), 9100).unwrap();
        let b = prepare_pairing(&good_phrase(), 9100).unwrap();
        assert_eq!(a.pairing_anchor, b.pairing_anchor);
        assert_ne!(a.bearer_token.expose(), b.bearer_token.expose());
    }

    #[test]
    fn prepare_pairing_bails_on_truncated_phrase() {
        // Operator hit Enter mid-paste. Must error with a clear
        // diagnostic that points at the validation kind so the wizard
        // can re-prompt.
        let short: String = good_phrase()
            .split_whitespace()
            .take(12)
            .collect::<Vec<_>>()
            .join(" ");
        let err = prepare_pairing(&short, 9100).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("wrong_word_count"), "msg: {msg}");
        assert!(msg.contains("Re-paste"), "msg: {msg}");
    }

    #[test]
    fn prepare_pairing_bails_on_uppercase_word() {
        let mut words: Vec<String> = good_phrase().split_whitespace().map(String::from).collect();
        words[2] = "AbLE".into();
        let err = prepare_pairing(&words.join(" "), 9100).unwrap_err();
        assert!(err.to_string().contains("invalid_character"));
    }

    #[test]
    fn prepare_pairing_carries_bridge_port_into_snippet() {
        // Pin the port-through so a future signature change doesn't
        // silently swap arg positions.
        let info = prepare_pairing(&good_phrase(), 12345).unwrap();
        assert!(info.freedom_yaml_snippet.contains("bridge_port: 12345"));
    }

    #[test]
    fn pairing_instructions_are_non_empty_and_numbered() {
        assert!(!PAIRING_INSTRUCTIONS.is_empty());
        for (i, line) in PAIRING_INSTRUCTIONS.iter().enumerate() {
            let expected_prefix = format!("{}.", i + 1);
            assert!(
                line.starts_with(&expected_prefix),
                "instruction {i} should start with `{expected_prefix}`: {line}"
            );
        }
    }

    /// Pin the SeedValidation re-export path so the public surface
    /// stays stable. K-3 callers (wizard) import via this module —
    /// renaming the source location would break wizard wiring.
    #[test]
    fn seed_validation_reachable_via_pairing_module() {
        let v = validate_seed_phrase(&good_phrase());
        assert!(v.is_valid());
    }
}
