//! RFC 7636 PKCE (Proof Key for Code Exchange) helpers — E-15.
//!
//! Today the wizard delegates Anthropic login by shelling out to
//! `claude /login` (which IS the OAuth PKCE flow Anthropic ships in
//! its own CLI). NEOTH-native PKCE — popping a browser ourselves and
//! exchanging the auth code for an Anthropic token — is gated on
//! Anthropic publishing a public OAuth client_id NEOTH can register
//! against. Until then, this module ships the spec-compliant
//! primitive (verifier + S256 challenge) so the day Anthropic opens
//! that door, the wizard just adds the redirect/exchange step on top.
//!
//! Tested vectors come from RFC 7636 Appendix B (the canonical
//! example the spec uses to pin the BASE64URL-NOPAD encoding).
//!
//! References:
//!   - RFC 7636 §4.1  code_verifier requirements (43-128 chars, the
//!     URL-safe alphabet `[A-Z][a-z][0-9]-._~`).
//!   - RFC 7636 §4.2  code_challenge = BASE64URL(SHA256(verifier)).
//!   - RFC 7636 App B  test vector
//!     `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk` is the S256
//!     challenge of
//!     `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk` (sic — the
//!     verifier itself), pinning our BASE64URL impl + SHA-256 pipe.

use rand::RngCore;
use sha2::{Digest, Sha256};

/// PKCE verifier length in bytes — RFC 7636 says 43..=128 characters
/// in the URL-safe alphabet. 43 chars = 32 raw bytes encoded with
/// BASE64URL-NOPAD; 32 bytes is also the SHA-256 output length so
/// the verifier carries 256 bits of entropy.
const PKCE_VERIFIER_RAW_BYTES: usize = 32;

/// One PKCE verifier+challenge pair, ready for the OAuth start URL.
/// Generated together so the verifier never leaves NEOTH (only its
/// challenge does); the verifier comes back into play at the token-
/// exchange step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PkcePair {
    /// 43-char URL-safe verifier kept private to NEOTH for the
    /// token-exchange call.
    pub verifier: String,
    /// 43-char BASE64URL-NOPAD(SHA256(verifier)) — sent as the
    /// `code_challenge` query parameter in the authorise URL.
    pub challenge: String,
    /// Always `"S256"` per RFC 7636 §4.3. NEOTH refuses the
    /// `"plain"` method even though the spec permits it — Anthropic
    /// rejects it anyway and plain weakens the flow to a no-op.
    pub method: &'static str,
}

impl PkcePair {
    /// Generate a fresh verifier + S256 challenge using the OS CSPRNG.
    /// The verifier carries 256 bits of entropy; that's the same
    /// strength as the SHA-256 hash and matches Anthropic's
    /// recommendation in the public OAuth flow docs.
    pub fn generate() -> Self {
        let mut raw = [0u8; PKCE_VERIFIER_RAW_BYTES];
        rand::rng().fill_bytes(&mut raw);
        Self::from_random_bytes(&raw)
    }

    /// Build a pair from caller-supplied raw entropy. Exposed so the
    /// RFC test vectors can pin the deterministic encoding output.
    pub fn from_random_bytes(raw: &[u8]) -> Self {
        let verifier = base64url_nopad_encode(raw);
        let challenge_hash = Sha256::digest(verifier.as_bytes());
        let challenge = base64url_nopad_encode(&challenge_hash);
        Self {
            verifier,
            challenge,
            method: "S256",
        }
    }
}

/// BASE64URL encoder without padding (RFC 4648 §5), the alphabet
/// PKCE mandates. Implemented inline so NEOTH avoids pulling the
/// `base64` crate just for one OAuth helper.
pub fn base64url_nopad_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut chunks = input.chunks_exact(3);
    for chunk in &mut chunks {
        let n = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32);
        out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        out.push(ALPHABET[(n & 0x3F) as usize] as char);
    }
    let remainder = chunks.remainder();
    match remainder.len() {
        1 => {
            let n = (remainder[0] as u32) << 16;
            out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        }
        2 => {
            let n = ((remainder[0] as u32) << 16) | ((remainder[1] as u32) << 8);
            out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
            out.push(ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        }
        _ => {}
    }
    out
}

/// True ⇔ the verifier matches RFC 7636 §4.1 constraints:
/// 43-128 chars, alphabet `[A-Z][a-z][0-9]-._~`. NEOTH validates
/// this before sending it to the token endpoint so a corrupted
/// verifier surfaces locally rather than as a server-side error.
pub fn is_valid_verifier(s: &str) -> bool {
    if !(43..=128).contains(&s.len()) {
        return false;
    }
    s.bytes().all(|b| {
        b.is_ascii_uppercase()
            || b.is_ascii_lowercase()
            || b.is_ascii_digit()
            || b == b'-'
            || b == b'.'
            || b == b'_'
            || b == b'~'
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_verifier_is_43_chars_url_safe() {
        let pair = PkcePair::generate();
        assert_eq!(pair.verifier.len(), 43);
        assert!(is_valid_verifier(&pair.verifier));
    }

    #[test]
    fn generated_challenge_is_43_chars_url_safe() {
        let pair = PkcePair::generate();
        assert_eq!(pair.challenge.len(), 43);
        assert!(is_valid_verifier(&pair.challenge));
    }

    #[test]
    fn method_is_always_s256() {
        let pair = PkcePair::generate();
        assert_eq!(pair.method, "S256");
    }

    #[test]
    fn two_generated_pairs_differ() {
        // CSPRNG must not return the same verifier twice in a row;
        // if this ever fires investigate the entropy source.
        let a = PkcePair::generate();
        let b = PkcePair::generate();
        assert_ne!(a.verifier, b.verifier);
        assert_ne!(a.challenge, b.challenge);
    }

    #[test]
    fn rfc_7636_appendix_b_test_vector_pins_encoder_and_hash() {
        // RFC 7636 Appendix B test vector. The 32-byte verifier
        // source (decimal): 116,24,223,180,151,153,224,37,79,250,
        // 96,125,216,173,187,186,22,212,37,77,105,214,191,240,91,
        // 88,5,88,83,132,141,121.
        let raw: [u8; 32] = [
            116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22, 212,
            37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121,
        ];
        let pair = PkcePair::from_random_bytes(&raw);
        assert_eq!(pair.verifier, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        assert_eq!(
            pair.challenge,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert_eq!(pair.method, "S256");
    }

    #[test]
    fn base64url_nopad_encode_no_remainder() {
        // 3-byte input encodes to 4 chars, no padding.
        assert_eq!(base64url_nopad_encode(b"abc"), "YWJj");
    }

    #[test]
    fn base64url_nopad_encode_one_byte_remainder() {
        // 1-byte input encodes to 2 chars (RFC 4648 §5 no-pad).
        assert_eq!(base64url_nopad_encode(b"f"), "Zg");
    }

    #[test]
    fn base64url_nopad_encode_two_byte_remainder() {
        // 2-byte input encodes to 3 chars (RFC 4648 §5 no-pad).
        assert_eq!(base64url_nopad_encode(b"fo"), "Zm8");
    }

    #[test]
    fn base64url_nopad_encode_url_safe_alphabet() {
        // Bytes 0xFB,0xFF,0xFE encode with both `-` and `_`,
        // confirming we use the URL-safe alphabet (not standard).
        let s = base64url_nopad_encode(&[0xFB, 0xFF, 0xFE]);
        // Standard alphabet would give "+__-" or similar; URL-safe
        // never produces `+` or `/`. Confirm absence.
        assert!(!s.contains('+'));
        assert!(!s.contains('/'));
        // Specific vector: 0xFB,0xFF,0xFE → "-__-" pattern check.
        assert!(s.contains('-') || s.contains('_'));
    }

    #[test]
    fn is_valid_verifier_accepts_43_char_url_safe() {
        let pair = PkcePair::generate();
        assert!(is_valid_verifier(&pair.verifier));
    }

    #[test]
    fn is_valid_verifier_rejects_too_short() {
        assert!(!is_valid_verifier("short"));
        assert!(!is_valid_verifier(&"a".repeat(42)));
    }

    #[test]
    fn is_valid_verifier_rejects_too_long() {
        assert!(!is_valid_verifier(&"a".repeat(129)));
    }

    #[test]
    fn is_valid_verifier_rejects_disallowed_chars() {
        // Spaces, slashes, plus signs MUST fail — they're not in
        // the unreserved-character set RFC 7636 §4.1 allows.
        assert!(!is_valid_verifier(&format!("{}{}", "a".repeat(42), " ")));
        assert!(!is_valid_verifier(&format!("{}{}", "a".repeat(42), "/")));
        assert!(!is_valid_verifier(&format!("{}{}", "a".repeat(42), "+")));
    }

    #[test]
    fn challenge_changes_when_verifier_changes() {
        let pair_a = PkcePair::from_random_bytes(&[0u8; 32]);
        let pair_b = PkcePair::from_random_bytes(&[1u8; 32]);
        assert_ne!(pair_a.challenge, pair_b.challenge);
    }
}
