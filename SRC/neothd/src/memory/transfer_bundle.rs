//! A3-01 — `neoth transfer` recipient-encrypted, operator-signed memory bundle.
//!
//! Exports a slice of the operator's memory to ANOTHER NEOTH instance without
//! exposing it to anyone but the named recipient. Hybrid crypto:
//!   1. **Confidentiality** — ephemeral X25519 ECDH against the recipient's
//!      public key → HKDF-SHA256 → a one-shot AES-256-GCM key. Only the holder
//!      of the recipient's X25519 secret can derive the key + decrypt.
//!   2. **Authenticity** — the bundle is signed with the operator's existing
//!      ed25519 WAL signing key (`wal::signing`), so the recipient verifies WHO
//!      sent it (against an out-of-band-pinned pubkey).
//!
//! The plaintext payload BYTES never touch disk or the WAL — only the
//! ciphertext + the public ephemeral key + the nonce are persisted.
//!
//! Pure crypto core (no I/O) so the round-trip is fully unit-testable.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// Schema tag — bumped if the wire format changes.
pub const TRANSFER_SCHEMA_VERSION: u32 = 1;
/// HKDF info string — domain-separates this KDF from any other use of the same
/// ECDH output.
const HKDF_INFO: &[u8] = b"neoth-transfer-v1";

/// One sealed, signed memory bundle. All binary fields are base64 (STANDARD) so
/// the whole thing round-trips through JSON. The plaintext payload is NOT
/// present — only `ciphertext_b64`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct TransferBundle {
    pub schema_version: u32,
    /// Recipient's X25519 public key (echoed for operator-visible routing; the
    /// recipient confirms it matches their own key before decrypting).
    pub dest_pubkey_b64: String,
    /// Ephemeral X25519 public key — the recipient ECDHs their secret against
    /// this to recover the shared secret.
    pub ephemeral_pubkey_b64: String,
    /// 12-byte AES-GCM nonce.
    pub nonce_b64: String,
    /// AES-256-GCM ciphertext (includes the 16-byte tag).
    pub ciphertext_b64: String,
    /// ed25519 signature over `canonical_bytes()`.
    pub signature_b64: String,
    /// Sender's ed25519 public key, embedded so a verifier with no pinned key
    /// can confirm self-consistency (no post-sign tamper). True attribution
    /// requires checking against an out-of-band-pinned pubkey.
    pub signer_pubkey_b64: String,
    pub ts_unix: u64,
}

impl TransferBundle {
    /// Stable, signature-free byte encoding (everything EXCEPT `signature_b64`),
    /// used both to sign and to verify. Field order is fixed — a drift here
    /// would silently break every prior bundle's verification. Length-prefixed
    /// so two adjacent fields can't be slid across the boundary.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.schema_version.to_le_bytes());
        for field in [
            &self.dest_pubkey_b64,
            &self.ephemeral_pubkey_b64,
            &self.nonce_b64,
            &self.ciphertext_b64,
            &self.signer_pubkey_b64,
        ] {
            out.extend_from_slice(&(field.len() as u32).to_le_bytes());
            out.extend_from_slice(field.as_bytes());
        }
        out.extend_from_slice(&self.ts_unix.to_le_bytes());
        out
    }
}

/// Result of [`verify_signature`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureCheck {
    /// Verified against the EMBEDDED signer pubkey only — proves no post-sign
    /// tamper, NOT identity (an attacker could re-sign with their own key +
    /// embed it).
    SelfConsistent,
    /// Verified against an operator-pinned expected pubkey — true attribution.
    VerifiedAgainstExpected,
}

/// 32 fresh random bytes via getrandom (fail-closed).
fn random_32() -> Result<[u8; 32]> {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
    Ok(b)
}

/// Decode a base64 string into exactly 32 bytes (an X25519 pubkey).
pub fn parse_b64_32(s: &str, what: &str) -> Result<[u8; 32]> {
    let v = B64.decode(s).with_context(|| format!("decode {what} base64"))?;
    let arr: [u8; 32] = v
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("{what} must be 32 bytes, got {}", v.len()))?;
    Ok(arr)
}

/// Derive the one-shot AES-256 key from the ECDH shared secret. Salt = the
/// ephemeral pubkey (binds the key to this exact exchange).
fn derive_key(shared: &[u8; 32], ephemeral_pub: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(ephemeral_pub), shared);
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm)
        .expect("HKDF-SHA256 expand of 32 bytes is always valid");
    okm
}

/// Encrypt `payload` FOR the recipient's X25519 public key + sign with the
/// operator's ed25519 key. Returns a sealed [`TransferBundle`].
pub fn encrypt_for(
    payload: &[u8],
    dest_pubkey: &[u8; 32],
    signing_key: &SigningKey,
    ts_unix: u64,
) -> Result<TransferBundle> {
    // Ephemeral X25519 keypair (fresh per export — forward secrecy of the bundle).
    let eph_secret = StaticSecret::from(random_32()?);
    let eph_public = PublicKey::from(&eph_secret);
    // ECDH → shared secret.
    let dest = PublicKey::from(*dest_pubkey);
    let shared = eph_secret.diffie_hellman(&dest);
    let aes_key = derive_key(shared.as_bytes(), eph_public.as_bytes());
    // AES-256-GCM encrypt under a random 12-byte nonce.
    let nonce_bytes = {
        let r = random_32()?;
        let mut n = [0u8; 12];
        n.copy_from_slice(&r[..12]);
        n
    };
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), payload)
        .map_err(|e| anyhow::anyhow!("AES-256-GCM encrypt: {e}"))?;

    let mut bundle = TransferBundle {
        schema_version: TRANSFER_SCHEMA_VERSION,
        dest_pubkey_b64: B64.encode(dest_pubkey),
        ephemeral_pubkey_b64: B64.encode(eph_public.as_bytes()),
        nonce_b64: B64.encode(nonce_bytes),
        ciphertext_b64: B64.encode(&ciphertext),
        signature_b64: String::new(),
        signer_pubkey_b64: B64.encode(signing_key.verifying_key().to_bytes()),
        ts_unix,
    };
    let sig: Signature = signing_key.sign(&bundle.canonical_bytes());
    bundle.signature_b64 = B64.encode(sig.to_bytes());
    Ok(bundle)
}

/// Verify the bundle signature. With `expected_signer = Some`, the signature
/// must verify against THAT key (true attribution → `VerifiedAgainstExpected`)
/// AND the embedded key must match it; otherwise it verifies against the
/// embedded key (`SelfConsistent`). `Err` on invalid signature / key mismatch.
pub fn verify_signature(
    bundle: &TransferBundle,
    expected_signer: Option<&[u8; 32]>,
) -> Result<SignatureCheck> {
    let embedded = parse_b64_32(&bundle.signer_pubkey_b64, "signer_pubkey")?;
    let (verify_key_bytes, outcome) = match expected_signer {
        Some(exp) => {
            if exp != &embedded {
                bail!("embedded signer pubkey does not match the pinned --pubkey");
            }
            (*exp, SignatureCheck::VerifiedAgainstExpected)
        }
        None => (embedded, SignatureCheck::SelfConsistent),
    };
    let vk = VerifyingKey::from_bytes(&verify_key_bytes).context("parse signer pubkey")?;
    let sig_bytes = B64.decode(&bundle.signature_b64).context("decode signature")?;
    let sig = Signature::from_slice(&sig_bytes).context("parse signature")?;
    vk.verify(&bundle.canonical_bytes(), &sig)
        .context("signature verification failed")?;
    Ok(outcome)
}

/// Decrypt a bundle with the recipient's X25519 secret. Verifies the signature
/// (self-consistent) first, then ECDHs + AES-GCM-decrypts. `Err` on any
/// signature/parse/decrypt failure (a tampered ciphertext fails the GCM tag).
pub fn decrypt_with(bundle: &TransferBundle, recipient_secret: &[u8; 32]) -> Result<Vec<u8>> {
    verify_signature(bundle, None)?;
    let eph_pub = parse_b64_32(&bundle.ephemeral_pubkey_b64, "ephemeral_pubkey")?;
    let nonce_bytes = B64.decode(&bundle.nonce_b64).context("decode nonce")?;
    if nonce_bytes.len() != 12 {
        bail!("nonce must be 12 bytes, got {}", nonce_bytes.len());
    }
    let ciphertext = B64.decode(&bundle.ciphertext_b64).context("decode ciphertext")?;
    let secret = StaticSecret::from(*recipient_secret);
    let shared = secret.diffie_hellman(&PublicKey::from(eph_pub));
    let aes_key = derive_key(shared.as_bytes(), &eph_pub);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));
    cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
        .map_err(|e| anyhow::anyhow!("AES-256-GCM decrypt (wrong key or tampered): {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a recipient X25519 keypair from fixed bytes → (secret, pubkey).
    fn recipient(seed: u8) -> ([u8; 32], [u8; 32]) {
        let secret_bytes = [seed; 32];
        let pubkey = PublicKey::from(&StaticSecret::from(secret_bytes));
        (secret_bytes, pubkey.to_bytes())
    }

    fn signer(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn round_trip_encrypt_decrypt() {
        let (rx_secret, rx_pub) = recipient(7);
        let sk = signer(3);
        let payload = b"top secret memory bundle \xff\x00 contents";
        let bundle = encrypt_for(payload, &rx_pub, &sk, 1_700_000_000).unwrap();
        // Plaintext never appears in the bundle.
        assert!(!bundle.ciphertext_b64.is_empty());
        assert_ne!(bundle.ciphertext_b64.as_bytes(), payload);
        let out = decrypt_with(&bundle, &rx_secret).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn wrong_recipient_key_fails() {
        let (_rx_secret, rx_pub) = recipient(7);
        let (wrong_secret, _wrong_pub) = recipient(9);
        let bundle = encrypt_for(b"hello", &rx_pub, &signer(1), 1).unwrap();
        assert!(decrypt_with(&bundle, &wrong_secret).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails_gcm_tag() {
        let (rx_secret, rx_pub) = recipient(7);
        let mut bundle = encrypt_for(b"hello world", &rx_pub, &signer(1), 1).unwrap();
        // Flip a ciphertext byte (decode → mutate → re-encode) AND re-sign so
        // the signature passes but the GCM tag must catch the tamper.
        let mut ct = B64.decode(&bundle.ciphertext_b64).unwrap();
        ct[0] ^= 0x01;
        bundle.ciphertext_b64 = B64.encode(&ct);
        let sk = signer(1);
        let sig = sk.sign(&bundle.canonical_bytes());
        bundle.signature_b64 = B64.encode(sig.to_bytes());
        assert!(decrypt_with(&bundle, &rx_secret).is_err());
    }

    #[test]
    fn post_sign_tamper_fails_signature() {
        let (_rx_secret, rx_pub) = recipient(7);
        let mut bundle = encrypt_for(b"hello", &rx_pub, &signer(1), 1).unwrap();
        // Mutate a signed field WITHOUT re-signing → signature must fail.
        bundle.ts_unix += 1;
        assert!(verify_signature(&bundle, None).is_err());
    }

    #[test]
    fn verify_against_expected_pubkey() {
        let (_rx_secret, rx_pub) = recipient(7);
        let sk = signer(5);
        let signer_pub = sk.verifying_key().to_bytes();
        let bundle = encrypt_for(b"hi", &rx_pub, &sk, 1).unwrap();
        assert_eq!(
            verify_signature(&bundle, Some(&signer_pub)).unwrap(),
            SignatureCheck::VerifiedAgainstExpected
        );
        // No pin → self-consistent.
        assert_eq!(
            verify_signature(&bundle, None).unwrap(),
            SignatureCheck::SelfConsistent
        );
    }

    #[test]
    fn wrong_expected_pubkey_rejected() {
        let (_rx_secret, rx_pub) = recipient(7);
        let bundle = encrypt_for(b"hi", &rx_pub, &signer(5), 1).unwrap();
        let other_pub = signer(6).verifying_key().to_bytes();
        assert!(verify_signature(&bundle, Some(&other_pub)).is_err());
    }

    #[test]
    fn parse_b64_32_rejects_wrong_length() {
        assert!(parse_b64_32(&B64.encode([0u8; 31]), "k").is_err());
        assert!(parse_b64_32(&B64.encode([0u8; 33]), "k").is_err());
        assert!(parse_b64_32("not base64 ~~~", "k").is_err());
        assert!(parse_b64_32(&B64.encode([0u8; 32]), "k").is_ok());
    }

    #[test]
    fn canonical_bytes_stable_and_excludes_signature() {
        let (_s, rx_pub) = recipient(7);
        let bundle = encrypt_for(b"x", &rx_pub, &signer(1), 42).unwrap();
        let a = bundle.canonical_bytes();
        // Changing only the signature must NOT change canonical_bytes.
        let mut b2 = bundle.clone();
        b2.signature_b64 = "different".into();
        assert_eq!(a, b2.canonical_bytes());
        // Changing a signed field MUST change it.
        let mut b3 = bundle.clone();
        b3.ts_unix = 43;
        assert_ne!(a, b3.canonical_bytes());
    }

    #[test]
    fn json_round_trip() {
        let (_s, rx_pub) = recipient(2);
        let bundle = encrypt_for(b"payload", &rx_pub, &signer(8), 9).unwrap();
        let json = serde_json::to_string(&bundle).unwrap();
        let back: TransferBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle, back);
    }
}
