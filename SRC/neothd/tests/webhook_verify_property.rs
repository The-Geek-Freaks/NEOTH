//! Round-3 v0.4 GR-11 — property/fuzz tests for the webhook signature
//! canonicalization + timestamp-window logic in `channels::webhook_verify`.
//!
//! Why property tests, not more example-based tests: the existing
//! inline `#[cfg(test)] mod tests` covers the canonical happy path +
//! a handful of named negative cases. Property tests probe the input
//! space `proptest` generates — random body bytes, random secrets,
//! random timestamps, random header strings — to catch the classes of
//! bug example-based tests miss:
//!
//! - HMAC round-trip on body bytes the operator didn't think to test
//!   (UTF-8 invalid, embedded NULs, huge bodies).
//! - Header parsing that accepts almost-right shapes (e.g. accidental
//!   accept of `sha256 = abc` because of stray whitespace).
//! - Timestamp window arithmetic that under-/overflows at i64
//!   boundaries.
//!
//! `proptest` shrinks failing inputs to the minimal counter-example,
//! which makes regression diagnosis cheap. Failures land with the
//! exact failing seed so a re-run reproduces deterministically.

use neothd::channels::webhook_verify::{
    MAX_TIMESTAMP_SKEW_SECS, MetaChallengeOutcome, SlackVerifyError, meta_challenge_response,
    sign_meta, sign_slack, verify_meta_signature, verify_slack_signature,
};
use proptest::prelude::*;

// ── Meta (X-Hub-Signature-256) properties ────────────────────────────

proptest! {
    /// Round-trip: any body + any secret signed by `sign_meta` is
    /// accepted by `verify_meta_signature` with the same secret.
    #[test]
    fn meta_sign_verify_round_trip(body: Vec<u8>, secret in prop::collection::vec(any::<u8>(), 1..256)) {
        let sig = sign_meta(&body, &secret);
        prop_assert!(
            verify_meta_signature(&body, &sig, &secret),
            "verify must accept signature produced by sign with same secret",
        );
    }

    /// Cross-secret rejection: two non-equal secrets produce signatures
    /// that don't verify against each other. (Catches a class of
    /// implementation bug where the HMAC key was accidentally ignored.)
    #[test]
    fn meta_verify_rejects_wrong_secret(
        body: Vec<u8>,
        secret_a in prop::collection::vec(any::<u8>(), 1..64),
        secret_b in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        prop_assume!(secret_a != secret_b);
        let sig_with_a = sign_meta(&body, &secret_a);
        prop_assert!(
            !verify_meta_signature(&body, &sig_with_a, &secret_b),
            "signature with secret_a MUST be rejected by verify with secret_b",
        );
    }

    /// Tampered-ciphertext defence: flipping any single bit of the
    /// hex-encoded signature breaks verification. HMAC's avalanche
    /// property guarantees this; the test pins the property at the
    /// caller boundary so a future header-rewriter doesn't silently
    /// "normalise" away the tamper.
    #[test]
    fn meta_verify_rejects_single_bit_tamper(
        body: Vec<u8>,
        secret in prop::collection::vec(any::<u8>(), 1..64),
        flip_offset in 0usize..64,
    ) {
        let sig = sign_meta(&body, &secret);
        // sig is "sha256=" + 64 hex chars. Flip one char in the hex part.
        let prefix = "sha256=";
        prop_assume!(sig.starts_with(prefix));
        let hex_part = &sig[prefix.len()..];
        prop_assume!(hex_part.len() == 64);
        let off = flip_offset % 64;
        let mut bytes: Vec<u8> = hex_part.bytes().collect();
        // Replace the byte at `off` with a different hex char.
        let original = bytes[off];
        let replacement = if original == b'a' { b'b' } else { b'a' };
        bytes[off] = replacement;
        let tampered_hex = std::str::from_utf8(&bytes).expect("ASCII hex");
        let tampered = format!("{prefix}{tampered_hex}");
        prop_assert!(
            !verify_meta_signature(&body, &tampered, &secret),
            "tampered signature MUST be rejected",
        );
    }

    /// Arbitrary header strings (random ASCII) MUST NOT panic. Any
    /// non-`sha256=`-prefixed input returns false cleanly; any invalid
    /// hex returns false cleanly. The HTTP listener exposes this
    /// function to whatever the network hands it.
    #[test]
    fn meta_verify_no_panic_on_arbitrary_header(
        body: Vec<u8>,
        secret in prop::collection::vec(any::<u8>(), 0..64),
        header in "\\PC{0,256}", // any printable-character string up to 256 chars
    ) {
        // We don't care about the return value — only that the call
        // doesn't panic on operator-controlled (read: attacker-
        // controlled) input.
        let _ = verify_meta_signature(&body, &header, &secret);
    }

    /// Empty body + empty secret round-trip — degenerate edge that
    /// must still work without panic.
    #[test]
    fn meta_sign_verify_empty_body_any_secret(secret in prop::collection::vec(any::<u8>(), 0..64)) {
        let sig = sign_meta(&[], &secret);
        prop_assert!(verify_meta_signature(&[], &sig, &secret));
    }
}

// ── Meta challenge handshake properties ──────────────────────────────

proptest! {
    /// Canonical handshake — `hub.mode=subscribe&hub.verify_token=X
    /// &hub.challenge=Y` with the correct operator token echoes Y.
    /// Property over arbitrary tokens + challenges (URL-safe ASCII so
    /// we don't fight URL decoding).
    #[test]
    fn meta_challenge_canonical_echoes_challenge(
        token in "[A-Za-z0-9_-]{1,32}",
        challenge in "[A-Za-z0-9_-]{1,32}",
    ) {
        let query = format!(
            "hub.mode=subscribe&hub.verify_token={token}&hub.challenge={challenge}"
        );
        match meta_challenge_response(&query, &token) {
            MetaChallengeOutcome::Echo(c) => prop_assert_eq!(c, challenge),
            other => prop_assert!(false, "expected Echo, got {:?}", other),
        }
    }

    /// Token mismatch — same canonical shape but the operator's token
    /// differs from the one in the query → TokenMismatch (NOT Echo
    /// + NOT BadRequest).
    #[test]
    fn meta_challenge_wrong_token_surfaces_token_mismatch(
        sent_token in "[A-Za-z0-9_-]{1,32}",
        operator_token in "[A-Za-z0-9_-]{1,32}",
        challenge in "[A-Za-z0-9_-]{1,32}",
    ) {
        prop_assume!(sent_token != operator_token);
        let query = format!(
            "hub.mode=subscribe&hub.verify_token={sent_token}&hub.challenge={challenge}"
        );
        prop_assert_eq!(
            meta_challenge_response(&query, &operator_token),
            MetaChallengeOutcome::TokenMismatch,
        );
    }
}

// ── Slack (X-Slack-Signature) properties ─────────────────────────────

proptest! {
    /// Round-trip within the timestamp window: `sign_slack(body, ts,
    /// secret)` verifies for `now ∈ [ts - 300, ts + 300]`.
    #[test]
    fn slack_sign_verify_round_trip_within_window(
        body: Vec<u8>,
        secret in prop::collection::vec(any::<u8>(), 1..64),
        ts in 1_000_000_000i64..3_000_000_000i64, // year 2001..2065 range
        // skew within ±MAX_TIMESTAMP_SKEW_SECS
        skew in -MAX_TIMESTAMP_SKEW_SECS..=MAX_TIMESTAMP_SKEW_SECS,
    ) {
        let ts_header = ts.to_string();
        let sig = sign_slack(&body, &ts_header, &secret);
        let now = ts + skew;
        let result = verify_slack_signature(&body, &ts_header, &sig, &secret, now);
        prop_assert!(
            result.is_ok(),
            "within-window verify must succeed, got {:?} (ts={ts}, skew={skew}, now={now})",
            result,
        );
    }

    /// Outside-window rejection: `now > ts + 300` (or below) MUST
    /// surface as `TimestampOutOfWindow`. Catches off-by-one at the
    /// boundary + over-tolerant comparisons.
    #[test]
    fn slack_verify_rejects_outside_window(
        body: Vec<u8>,
        secret in prop::collection::vec(any::<u8>(), 1..64),
        ts in 1_000_000_000i64..3_000_000_000i64,
        // Skew strictly outside the window: at least 301s away.
        excess in (MAX_TIMESTAMP_SKEW_SECS + 1)..=(MAX_TIMESTAMP_SKEW_SECS + 10_000),
        sign_flip in any::<bool>(),
    ) {
        let ts_header = ts.to_string();
        let sig = sign_slack(&body, &ts_header, &secret);
        let now = if sign_flip { ts + excess } else { ts - excess };
        let result = verify_slack_signature(&body, &ts_header, &sig, &secret, now);
        match result {
            Err(SlackVerifyError::TimestampOutOfWindow { skew_secs }) => {
                prop_assert_eq!(skew_secs, excess, "reported skew must match");
            }
            other => prop_assert!(
                false,
                "expected TimestampOutOfWindow, got {:?} (excess={excess})",
                other,
            ),
        }
    }

    /// Cross-secret rejection on Slack path. Distinct from
    /// timestamp-window rejection — must surface as
    /// `SignatureMismatch`, not the other variants.
    #[test]
    fn slack_verify_rejects_wrong_secret(
        body: Vec<u8>,
        secret_a in prop::collection::vec(any::<u8>(), 1..64),
        secret_b in prop::collection::vec(any::<u8>(), 1..64),
        ts in 1_000_000_000i64..3_000_000_000i64,
    ) {
        prop_assume!(secret_a != secret_b);
        let ts_header = ts.to_string();
        let sig = sign_slack(&body, &ts_header, &secret_a);
        // now == ts so window is satisfied; only the secret differs.
        let result = verify_slack_signature(&body, &ts_header, &sig, &secret_b, ts);
        prop_assert_eq!(result, Err(SlackVerifyError::SignatureMismatch));
    }

    /// Malformed timestamp header: any non-integer string surfaces
    /// as `MalformedTimestamp` (NOT panic, NOT a default-zero parse).
    #[test]
    fn slack_verify_malformed_timestamp(
        body: Vec<u8>,
        secret in prop::collection::vec(any::<u8>(), 1..64),
        bad_ts in "[A-Za-z][A-Za-z0-9 ]{0,32}", // starts with letter so it can't be a valid i64
    ) {
        let sig = "v0=ignored";
        let now = 1_700_000_000i64;
        let result = verify_slack_signature(&body, &bad_ts, sig, &secret, now);
        prop_assert_eq!(result, Err(SlackVerifyError::MalformedTimestamp));
    }

    /// Malformed signature header: missing `v0=` prefix or non-hex
    /// body surfaces as `MalformedSignatureHeader`, NOT panic.
    #[test]
    fn slack_verify_malformed_signature_header(
        body: Vec<u8>,
        secret in prop::collection::vec(any::<u8>(), 1..64),
        ts in 1_000_000_000i64..3_000_000_000i64,
        sig in "[^v].{0,64}", // anything not starting with 'v'
    ) {
        let result = verify_slack_signature(&body, &ts.to_string(), &sig, &secret, ts);
        prop_assert_eq!(result, Err(SlackVerifyError::MalformedSignatureHeader));
    }

    /// No-panic on arbitrary inputs: every combination of arbitrary
    /// bytes for body / secret / headers MUST surface as Ok or one of
    /// the named SlackVerifyError variants — never panic.
    #[test]
    fn slack_verify_no_panic_on_arbitrary_inputs(
        body: Vec<u8>,
        secret in prop::collection::vec(any::<u8>(), 0..64),
        ts_header in "\\PC{0,32}",
        sig_header in "\\PC{0,128}",
        now in any::<i64>(),
    ) {
        let _ = verify_slack_signature(&body, &ts_header, &sig_header, &secret, now);
    }
}
