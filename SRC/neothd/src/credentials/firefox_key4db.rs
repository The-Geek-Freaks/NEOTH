//! C-04b Phase 2 chunk 2a (Session 27) — Firefox `key4.db` crypto primitives.
//!
//! `key4.db` is the SQLite database NSS writes the master-key
//! envelope + the operator's password check string into. The full
//! decrypt flow reads two columns:
//!
//! - `metaData.item2` — PBES2-wrapped "password-check" plaintext
//!   (`b"password-check"`); decrypts iff the operator's primary
//!   password is correct. Used as a wrong-password detector
//!   before attempting the master-key unwrap (the master-key
//!   unwrap itself would also fail on the wrong password but
//!   the failure surfaces as a generic AES-CBC unpad error —
//!   the `metaData.item2` check has a specific plaintext we can
//!   verify against, so it's the operator-friendly gate).
//! - `nssPrivate.a11` — PBES2-wrapped 24-byte master key, also
//!   AES-256-CBC under the same masking key.
//!
//! Chunk 2a (this file) ships the two cryptographic primitives
//! that don't need the SQLite read: the PBKDF2-SHA256 masking-key
//! derivation + the password-check verifier. Both are NIST-/RFC-
//! KAT-pinned so a future regression in the underlying RustCrypto
//! crates surfaces here, not in the integration test.
//!
//! Chunk 2b (Session 28) wires `rusqlite` to read the two
//! key4.db columns + the ASN.1 PBES2 envelope decoder (a
//! 2-layer SEQUENCE, slightly more complex than the SECITEM
//! envelope shipped by `firefox_envelope` chunk 1) + the
//! end-to-end `extract_master_key` orchestration.

use sha2::Sha256;
use subtle::ConstantTimeEq;

/// Canonical plaintext of the `metaData.item2` password-check
/// column. After AES-256-CBC decrypt with the right masking
/// key, the unpadded bytes equal this constant. Wrong password
/// → decrypt yields garbage → constant-time compare returns
/// false without revealing where the mismatch occurred.
pub const PASSWORD_CHECK_PLAINTEXT: &[u8] = b"password-check";

/// PBKDF2-SHA256 masking-key derivation. NSS 3.40+ uses 10_000
/// iterations as the default for fresh key4.db creates; older
/// profiles may carry whatever the wizard at-create-time picked,
/// so the caller passes `iterations` from the metadata table
/// rather than hardcoding.
///
/// Returns a 32-byte key suitable for AES-256-CBC. The output
/// length is fixed because every NSS code path expects 32 bytes;
/// surfacing a different length would only be a footgun.
pub fn derive_masking_key_pbkdf2_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> [u8; 32] {
    let mut key = [0u8; 32];
    // pbkdf2_hmac is infallible in pbkdf2 0.12 — no Result wrap.
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut key);
    key
}

/// Verify the operator's primary password by attempting to
/// decrypt the `metaData.item2` ciphertext and comparing the
/// plaintext (in constant time) against [`PASSWORD_CHECK_PLAINTEXT`].
///
/// Returns `true` iff the masking key recovers the canonical
/// check string. Returns `false` for every failure mode —
/// decrypt-fails / pad-fails / plaintext-doesn't-match all
/// collapse to the same `false` so an attacker timing the
/// caller can't distinguish "wrong password" from "corrupt
/// envelope" from "unsupported algorithm".
///
/// `iv` is the 16-byte IV extracted from the PBES2 envelope's
/// AlgorithmIdentifier; chunk 2b feeds it from the ASN.1 decode.
pub fn verify_password_check(
    masking_key: &[u8; 32],
    iv: &[u8; 16],
    check_ciphertext: &[u8],
) -> bool {
    match crate::credentials::firefox::decrypt_aes256_cbc_pkcs7(
        masking_key,
        iv,
        check_ciphertext,
    ) {
        Ok(plaintext) => plaintext.ct_eq(PASSWORD_CHECK_PLAINTEXT).into(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbc::cipher::block_padding::Pkcs7;
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};
    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    /// Encrypt a plaintext with AES-256-CBC + PKCS#7 padding —
    /// helper for the password-check verifier tests so we don't
    /// depend on a hand-typed ciphertext blob.
    fn aes_encrypt(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; plaintext.len() + 16];
        buf[..plaintext.len()].copy_from_slice(plaintext);
        let ct_len = Aes256CbcEnc::new(key.into(), iv.into())
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            .expect("encrypt must succeed")
            .len();
        buf.truncate(ct_len);
        buf
    }

    // ── PBKDF2-SHA256 KAT ─────────────────────────────────────────

    #[test]
    fn pbkdf2_sha256_known_answer_test_1_iter() {
        // Published PBKDF2-HMAC-SHA256 test vector (cross-referenced
        // against multiple independent implementations including
        // OpenSSL's evp_kdf-pbkdf2 + Bouncy Castle):
        //   Password   = "password"
        //   Salt       = "salt"
        //   Iterations = 1
        //   Output     = 120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b
        let got = derive_masking_key_pbkdf2_sha256(b"password", b"salt", 1);
        let expected: [u8; 32] = [
            0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4,
            0xf8, 0x37, 0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48, 0x08, 0x05, 0x98, 0x7c,
            0xb7, 0x0b, 0xe1, 0x7b,
        ];
        assert_eq!(got, expected, "PBKDF2-SHA256 1-iter KAT must match");
    }

    #[test]
    fn pbkdf2_sha256_known_answer_test_2_iter() {
        // Same source: iters=2 produces a distinct output. Pin so a
        // pbkdf2-crate regression that silently swaps SHA-1 for
        // SHA-256 (or vice versa) fails here.
        //   Output (iters=2) = ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43
        let got = derive_masking_key_pbkdf2_sha256(b"password", b"salt", 2);
        let expected: [u8; 32] = [
            0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3, 0x2d, 0x0a, 0xdf, 0xf9, 0x28, 0xf0,
            0x6d, 0xd0, 0x2a, 0x30, 0x3f, 0x8e, 0xf3, 0xc2, 0x51, 0xdf, 0xd6, 0xe2, 0xd8, 0x5a,
            0x95, 0x47, 0x4c, 0x43,
        ];
        assert_eq!(got, expected);
    }

    #[test]
    fn pbkdf2_sha256_empty_password_does_not_panic() {
        // Operator with no primary password set → empty bytes. NSS
        // still runs PBKDF2 against the salt + iters from the
        // metadata. The wrapper must accept empty input.
        let got = derive_masking_key_pbkdf2_sha256(b"", b"some-salt", 100);
        // Sanity: not the all-zeros key (would mean the wrapper
        // skipped PBKDF2 entirely).
        assert_ne!(got, [0u8; 32]);
    }

    #[test]
    fn pbkdf2_sha256_different_iters_diverge() {
        // Drift guard: iters parameter is actually wired. A
        // regression that ignored iters (e.g. always used 1) would
        // produce identical outputs across iters values.
        let a = derive_masking_key_pbkdf2_sha256(b"pw", b"salt", 10);
        let b = derive_masking_key_pbkdf2_sha256(b"pw", b"salt", 100);
        assert_ne!(a, b, "iters must influence the derived key");
    }

    // ── verify_password_check ─────────────────────────────────────

    #[test]
    fn verify_password_check_accepts_right_key() {
        // Round-trip: encrypt "password-check" with a known key,
        // verifier must accept the same key.
        let key: [u8; 32] = [0x55; 32];
        let iv: [u8; 16] = [0xAB; 16];
        let ct = aes_encrypt(&key, &iv, PASSWORD_CHECK_PLAINTEXT);
        assert!(verify_password_check(&key, &iv, &ct));
    }

    #[test]
    fn verify_password_check_rejects_wrong_key() {
        // Different key with same IV + ciphertext → verifier
        // returns false. No panic, no Err — collapses to false so
        // the side-channel surface is minimal.
        let right_key: [u8; 32] = [0x55; 32];
        let wrong_key: [u8; 32] = [0x56; 32];
        let iv: [u8; 16] = [0xAB; 16];
        let ct = aes_encrypt(&right_key, &iv, PASSWORD_CHECK_PLAINTEXT);
        // Re-roll cap of 8 — wrong key has tiny chance of producing
        // valid PKCS#7 padding AND matching "password-check"
        // (~256^-14 — astronomical). Re-rolling perturbs the IV so
        // each trial is independent.
        let mut all_rejected = true;
        for nudge in 0..8 {
            let mut iv_perturbed = iv;
            iv_perturbed[0] ^= nudge;
            if verify_password_check(&wrong_key, &iv_perturbed, &ct) {
                all_rejected = false;
                break;
            }
        }
        assert!(all_rejected, "wrong key MUST be rejected in 8 trials");
    }

    #[test]
    fn verify_password_check_rejects_wrong_plaintext_at_right_key() {
        // Right key, but the ciphertext encrypts a DIFFERENT
        // plaintext. Decrypt succeeds (valid pad) but the
        // constant-time compare against "password-check" fails.
        // This is the critical drift guard: a wrong-PLAINTEXT
        // attack (operator tampers with key4.db to plant a
        // different but well-padded blob) must surface as false,
        // not true.
        let key: [u8; 32] = [0x55; 32];
        let iv: [u8; 16] = [0xAB; 16];
        let ct = aes_encrypt(&key, &iv, b"NOT-password-check");
        assert!(
            !verify_password_check(&key, &iv, &ct),
            "right key + wrong plaintext MUST return false"
        );
    }

    #[test]
    fn verify_password_check_rejects_empty_ciphertext() {
        // Edge case: empty ciphertext can't decrypt to anything;
        // verifier must surface false (not panic).
        let key: [u8; 32] = [0; 32];
        let iv: [u8; 16] = [0; 16];
        assert!(!verify_password_check(&key, &iv, &[]));
    }

    #[test]
    fn password_check_plaintext_is_canonical_constant() {
        // Pin the constant so a future find-and-replace doesn't
        // silently mutate it. NSS firefox_decrypt + the Mozilla
        // source both use the literal bytes "password-check"
        // (14 bytes, no NUL, no length prefix).
        assert_eq!(PASSWORD_CHECK_PLAINTEXT, b"password-check");
        assert_eq!(PASSWORD_CHECK_PLAINTEXT.len(), 14);
    }
}
