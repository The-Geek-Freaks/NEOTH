//! Inbound-webhook signature verification + handshake helpers (A7).
//!
//! Pure-crypto + pure-string-parsing primitives that any future HTTP
//! listener (hyper, axum, the operator's reverse-proxy bridge) MUST
//! call before trusting a request. Today no HTTP server is wired in
//! NEOTH — the operator-facing channel adapters either long-poll
//! (Telegram) or use Socket Mode (Slack scaffold). When the inbound
//! TLS path lands (Konsens-decision A7), these are the load-bearing
//! security primitives.
//!
//! Why pure functions: keeping HMAC + handshake logic out of the
//! transport layer means we can unit-test the security-critical bits
//! exhaustively without spinning up hyper, and the transport layer
//! can swap (hyper / axum / reverse-proxy bridge) without rewriting
//! the verification.
//!
//! ## Meta / WhatsApp Cloud API
//!
//! - **Signature header**: `X-Hub-Signature-256: sha256=<hexdigest>`,
//!   where `<hexdigest>` is HMAC-SHA256 over the raw POST body using
//!   the App Secret. Compare with constant-time equality.
//! - **Verify challenge**: Meta sends a GET on the same callback URL
//!   with `?hub.mode=subscribe&hub.verify_token=<TOKEN>&hub.challenge=<NONCE>`.
//!   When `mode == "subscribe"` AND `verify_token` matches the operator's
//!   configured token, the listener must echo `<NONCE>` back as the
//!   response body. Any mismatch → 403.
//!
//! ## Slack Events API
//!
//! - **Signature header**: `X-Slack-Signature: v0=<hexdigest>`, where
//!   `<hexdigest>` is HMAC-SHA256 over the byte-sequence
//!   `"v0:" + X-Slack-Request-Timestamp + ":" + raw_body` using the
//!   signing secret. Constant-time compare.
//! - **Timestamp skew**: Slack docs recommend rejecting requests with
//!   a timestamp more than ±5 minutes from now (replay defence).
//!   `MAX_TIMESTAMP_SKEW_SECS = 300`.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Slack replay-defence window: 5 minutes either side of now.
pub const MAX_TIMESTAMP_SKEW_SECS: i64 = 300;

/// Verify a Meta-style `X-Hub-Signature-256` header against a raw body
/// and the operator's App Secret. Constant-time comparison so a timing
///   attack can't distinguish "right prefix, wrong suffix" from
///   fully-wrong signatures.
///
/// Returns `true` only on full match. Empty body + empty secret +
/// header without the `sha256=` prefix → `false`.
pub fn verify_meta_signature(body: &[u8], signature_header: &str, app_secret: &[u8]) -> bool {
    let Some(hex_part) = signature_header.strip_prefix("sha256=") else {
        return false;
    };
    let Ok(provided) = decode_hex(hex_part) else {
        return false;
    };
    let mut mac = HmacSha256::new_from_slice(app_secret).expect("HMAC-SHA256 accepts any key");
    mac.update(body);
    mac.verify_slice(&provided).is_ok()
}

/// Render the `X-Hub-Signature-256` header value for a body + secret.
/// Used by tests + by any future synthetic-replay tooling.
pub fn sign_meta(body: &[u8], app_secret: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(app_secret).expect("HMAC-SHA256 accepts any key");
    mac.update(body);
    let tag = mac.finalize().into_bytes();
    format!("sha256={}", hex_encode(&tag))
}

/// Outcome of a Meta GET-handshake (`hub.mode=subscribe`).
#[derive(Debug, PartialEq, Eq)]
pub enum MetaChallengeOutcome {
    /// Token matched + mode == "subscribe". Echo this string as the
    /// 200 OK response body.
    Echo(String),
    /// Operator misconfigured the verify_token; reject with 403.
    TokenMismatch,
    /// hub.mode wasn't "subscribe" or required params missing — Meta
    /// won't accept this as a valid handshake. Reject with 400.
    BadRequest { reason: String },
}

/// Parse a Meta verify-handshake query-string + decide the response.
///
/// `query` is the raw querystring (without the leading `?`). The
/// expected three keys are `hub.mode`, `hub.verify_token`, and
/// `hub.challenge`. Missing-key tolerant: any missing key → BadRequest.
///
/// `operator_verify_token` is the secret value the operator pinned
/// in their Meta App configuration; we constant-time compare against it.
pub fn meta_challenge_response(query: &str, operator_verify_token: &str) -> MetaChallengeOutcome {
    let mut mode = None;
    let mut token = None;
    let mut challenge = None;
    // Reviewer-2 P2 (2026-05-20): duplicate-key semantics pinned.
    // Last-write-wins matches URL Standard / URLSearchParams + the
    // Meta verify handshake spec, but is explicit-documented here so
    // future maintainers don't accidentally swap it for first-wins.
    // A duplicate key in a real handshake is anomalous — log a warn
    // so the operator notices misbehaving proxies / Meta config drift.
    let mut duplicate_seen: Vec<&str> = Vec::new();
    for pair in query.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        let v = url_decode(v);
        match k {
            "hub.mode" => {
                if mode.is_some() && !duplicate_seen.contains(&"hub.mode") {
                    duplicate_seen.push("hub.mode");
                }
                mode = Some(v);
            }
            "hub.verify_token" => {
                if token.is_some() && !duplicate_seen.contains(&"hub.verify_token") {
                    duplicate_seen.push("hub.verify_token");
                }
                token = Some(v);
            }
            "hub.challenge" => {
                if challenge.is_some() && !duplicate_seen.contains(&"hub.challenge") {
                    duplicate_seen.push("hub.challenge");
                }
                challenge = Some(v);
            }
            _ => {}
        }
    }
    if !duplicate_seen.is_empty() {
        tracing::warn!(
            duplicate_keys = ?duplicate_seen,
            "Meta verify handshake had duplicate query keys — last value wins. \
             Investigate proxy / Meta config if this recurs."
        );
    }
    let mode = match mode {
        Some(m) => m,
        None => {
            return MetaChallengeOutcome::BadRequest {
                reason: "missing hub.mode".into(),
            };
        }
    };
    if mode != "subscribe" {
        return MetaChallengeOutcome::BadRequest {
            reason: format!("hub.mode `{mode}` (expected `subscribe`)"),
        };
    }
    let token = match token {
        Some(t) => t,
        None => {
            return MetaChallengeOutcome::BadRequest {
                reason: "missing hub.verify_token".into(),
            };
        }
    };
    let challenge = match challenge {
        Some(c) => c,
        None => {
            return MetaChallengeOutcome::BadRequest {
                reason: "missing hub.challenge".into(),
            };
        }
    };
    if !constant_time_eq(token.as_bytes(), operator_verify_token.as_bytes()) {
        return MetaChallengeOutcome::TokenMismatch;
    }
    MetaChallengeOutcome::Echo(challenge)
}

/// Verify a Slack `X-Slack-Signature` header against a raw body +
/// `X-Slack-Request-Timestamp` + the operator's signing secret.
///
/// Returns `Ok(())` on success, `Err(SlackVerifyError)` with the
/// specific reason on failure. The reason taxonomy lets the HTTP
/// listener log/respond differently per failure mode without leaking
/// timing or content information to the attacker.
pub fn verify_slack_signature(
    body: &[u8],
    timestamp_header: &str,
    signature_header: &str,
    signing_secret: &[u8],
    now_unix: i64,
) -> Result<(), SlackVerifyError> {
    let Ok(ts) = timestamp_header.parse::<i64>() else {
        return Err(SlackVerifyError::MalformedTimestamp);
    };
    if (now_unix - ts).abs() > MAX_TIMESTAMP_SKEW_SECS {
        return Err(SlackVerifyError::TimestampOutOfWindow {
            skew_secs: (now_unix - ts).abs(),
        });
    }
    let Some(hex_part) = signature_header.strip_prefix("v0=") else {
        return Err(SlackVerifyError::MalformedSignatureHeader);
    };
    let Ok(provided) = decode_hex(hex_part) else {
        return Err(SlackVerifyError::MalformedSignatureHeader);
    };
    let mut mac = HmacSha256::new_from_slice(signing_secret).expect("HMAC-SHA256 accepts any key");
    mac.update(b"v0:");
    mac.update(timestamp_header.as_bytes());
    mac.update(b":");
    mac.update(body);
    mac.verify_slice(&provided)
        .map_err(|_| SlackVerifyError::SignatureMismatch)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlackVerifyError {
    MalformedTimestamp,
    MalformedSignatureHeader,
    TimestampOutOfWindow { skew_secs: i64 },
    SignatureMismatch,
}

impl std::fmt::Display for SlackVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SlackVerifyError::MalformedTimestamp => {
                write!(f, "malformed X-Slack-Request-Timestamp")
            }
            SlackVerifyError::MalformedSignatureHeader => {
                write!(f, "malformed X-Slack-Signature header")
            }
            SlackVerifyError::TimestampOutOfWindow { skew_secs } => write!(
                f,
                "timestamp skew {skew_secs}s outside ±{MAX_TIMESTAMP_SKEW_SECS}s window"
            ),
            SlackVerifyError::SignatureMismatch => write!(f, "signature mismatch"),
        }
    }
}

impl std::error::Error for SlackVerifyError {}

/// Render the `X-Slack-Signature` header value for a body + timestamp
/// + secret. Used by tests + replay tooling.
pub fn sign_slack(body: &[u8], timestamp_header: &str, signing_secret: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(signing_secret).expect("HMAC-SHA256 accepts any key");
    mac.update(b"v0:");
    mac.update(timestamp_header.as_bytes());
    mac.update(b":");
    mac.update(body);
    let tag = mac.finalize().into_bytes();
    format!("v0={}", hex_encode(&tag))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn decode_hex(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 {
        return Err(());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(()),
    }
}

/// Minimal percent-decoder for Meta-handshake querystring values.
/// Handles `%XX` escapes + `+` → space (form-encoding convention).
/// Returns the input unchanged on malformed escapes — Meta sends
/// well-formed URLs, but we don't bail on edge cases that would
/// just produce a TokenMismatch downstream.
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let (Ok(hi), Ok(lo)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2])) {
                    out.push((hi << 4) | lo);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Meta signature ---

    #[test]
    fn meta_sig_roundtrip_verifies() {
        let body = br#"{"object":"whatsapp_business_account","entry":[]}"#;
        let secret = b"app-secret-abc";
        let header = sign_meta(body, secret);
        assert!(header.starts_with("sha256="));
        assert!(verify_meta_signature(body, &header, secret));
    }

    #[test]
    fn meta_sig_rejects_wrong_secret() {
        let body = b"{}";
        let header = sign_meta(body, b"right-secret");
        assert!(!verify_meta_signature(body, &header, b"wrong-secret"));
    }

    #[test]
    fn meta_sig_rejects_tampered_body() {
        let header = sign_meta(b"original-body", b"k");
        assert!(!verify_meta_signature(b"tampered-body", &header, b"k"));
    }

    #[test]
    fn meta_sig_rejects_missing_prefix() {
        let body = b"x";
        let unprefixed = sign_meta(body, b"k")
            .trim_start_matches("sha256=")
            .to_string();
        assert!(!verify_meta_signature(body, &unprefixed, b"k"));
    }

    #[test]
    fn meta_sig_rejects_malformed_hex() {
        assert!(!verify_meta_signature(b"x", "sha256=NOT_HEX", b"k"));
        assert!(!verify_meta_signature(b"x", "sha256=abc", b"k")); // odd-length
    }

    // --- Meta hub.challenge handshake ---

    #[test]
    fn meta_challenge_happy_path_echoes() {
        let q = "hub.mode=subscribe&hub.verify_token=mytoken&hub.challenge=NONCE123";
        let outcome = meta_challenge_response(q, "mytoken");
        assert_eq!(outcome, MetaChallengeOutcome::Echo("NONCE123".to_string()));
    }

    #[test]
    fn meta_challenge_duplicate_keys_last_write_wins() {
        // Reviewer-2 P2 regression guard (2026-05-20): duplicate query
        // keys MUST follow last-write-wins semantics to match the
        // URL Standard / URLSearchParams contract. A proxy that
        // accidentally doubles a key must not subtly invert the
        // verifier's view of the request.
        let q = "hub.mode=subscribe&hub.verify_token=oldtoken\
                 &hub.verify_token=newtoken&hub.challenge=NONCE";
        let outcome = meta_challenge_response(q, "newtoken");
        assert_eq!(
            outcome,
            MetaChallengeOutcome::Echo("NONCE".to_string()),
            "duplicate hub.verify_token: last value (`newtoken`) must win"
        );

        // Inverse: the first value loses, so the gate rejects it.
        let outcome = meta_challenge_response(q, "oldtoken");
        assert!(
            matches!(outcome, MetaChallengeOutcome::TokenMismatch),
            "an attacker prepending a key with a stale value CANNOT \
             revive it via duplication"
        );
    }

    #[test]
    fn meta_challenge_token_mismatch() {
        let q = "hub.mode=subscribe&hub.verify_token=wrong&hub.challenge=N";
        assert_eq!(
            meta_challenge_response(q, "right"),
            MetaChallengeOutcome::TokenMismatch
        );
    }

    #[test]
    fn meta_challenge_bad_mode_rejected() {
        let q = "hub.mode=unsubscribe&hub.verify_token=t&hub.challenge=N";
        match meta_challenge_response(q, "t") {
            MetaChallengeOutcome::BadRequest { reason } => {
                assert!(reason.contains("unsubscribe"));
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn meta_challenge_missing_keys_rejected() {
        assert!(matches!(
            meta_challenge_response("hub.mode=subscribe&hub.challenge=x", "t"),
            MetaChallengeOutcome::BadRequest { .. }
        ));
        assert!(matches!(
            meta_challenge_response("hub.verify_token=t&hub.challenge=x", "t"),
            MetaChallengeOutcome::BadRequest { .. }
        ));
        assert!(matches!(
            meta_challenge_response("hub.mode=subscribe&hub.verify_token=t", "t"),
            MetaChallengeOutcome::BadRequest { .. }
        ));
    }

    #[test]
    fn meta_challenge_url_decoded_values() {
        // Meta percent-encodes spaces + special chars in tokens.
        let q = "hub.mode=subscribe&hub.verify_token=my%20token&hub.challenge=N%2BO%2FE";
        let outcome = meta_challenge_response(q, "my token");
        assert_eq!(outcome, MetaChallengeOutcome::Echo("N+O/E".to_string()));
    }

    // --- Slack signature ---

    #[test]
    fn slack_sig_roundtrip_verifies() {
        let body = br#"{"type":"event_callback"}"#;
        let secret = b"slack-signing-secret";
        let ts = "1700000000";
        let now: i64 = 1_700_000_000;
        let header = sign_slack(body, ts, secret);
        assert!(header.starts_with("v0="));
        assert_eq!(
            verify_slack_signature(body, ts, &header, secret, now),
            Ok(())
        );
    }

    #[test]
    fn slack_sig_rejects_skew_outside_window() {
        let body = b"x";
        let ts = "1700000000";
        let header = sign_slack(body, ts, b"k");
        // 301s skew -- one second past the 5-min cliff.
        let too_late: i64 = 1_700_000_000 + MAX_TIMESTAMP_SKEW_SECS + 1;
        match verify_slack_signature(body, ts, &header, b"k", too_late) {
            Err(SlackVerifyError::TimestampOutOfWindow { skew_secs }) => {
                assert_eq!(skew_secs, MAX_TIMESTAMP_SKEW_SECS + 1);
            }
            other => panic!("expected TimestampOutOfWindow, got {other:?}"),
        }
    }

    #[test]
    fn slack_sig_accepts_just_within_window() {
        let body = b"x";
        let ts = "1700000000";
        let header = sign_slack(body, ts, b"k");
        let edge: i64 = 1_700_000_000 + MAX_TIMESTAMP_SKEW_SECS;
        assert_eq!(
            verify_slack_signature(body, ts, &header, b"k", edge),
            Ok(())
        );
    }

    #[test]
    fn slack_sig_rejects_wrong_secret() {
        let body = b"x";
        let ts = "1700000000";
        let header = sign_slack(body, ts, b"right");
        assert_eq!(
            verify_slack_signature(body, ts, &header, b"wrong", 1_700_000_000),
            Err(SlackVerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn slack_sig_rejects_malformed_timestamp() {
        let header = sign_slack(b"x", "1700000000", b"k");
        assert_eq!(
            verify_slack_signature(b"x", "not-an-int", &header, b"k", 1_700_000_000),
            Err(SlackVerifyError::MalformedTimestamp)
        );
    }

    #[test]
    fn slack_sig_rejects_missing_v0_prefix() {
        let body = b"x";
        let ts = "1700000000";
        let header = sign_slack(body, ts, b"k");
        let stripped = header.trim_start_matches("v0=").to_string();
        assert_eq!(
            verify_slack_signature(body, ts, &stripped, b"k", 1_700_000_000),
            Err(SlackVerifyError::MalformedSignatureHeader)
        );
    }

    #[test]
    fn slack_sig_rejects_tampered_body() {
        let ts = "1700000000";
        let header = sign_slack(b"original", ts, b"k");
        assert_eq!(
            verify_slack_signature(b"tampered", ts, &header, b"k", 1_700_000_000),
            Err(SlackVerifyError::SignatureMismatch)
        );
    }

    // --- helpers ---

    #[test]
    fn constant_time_eq_distinguishes_only_full_match() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd")); // different lengths
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn hex_roundtrip() {
        assert_eq!(hex_encode(&[0x00, 0xff, 0x10]), "00ff10");
        assert_eq!(decode_hex("00ff10").unwrap(), vec![0x00, 0xff, 0x10]);
        assert_eq!(decode_hex("00FF10").unwrap(), vec![0x00, 0xff, 0x10]);
        assert!(decode_hex("0").is_err());
        assert!(decode_hex("zz").is_err());
    }
}
