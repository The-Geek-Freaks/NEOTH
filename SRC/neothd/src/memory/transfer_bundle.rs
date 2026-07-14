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
use zeroize::Zeroizing;

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
    let v = B64
        .decode(s)
        .with_context(|| format!("decode {what} base64"))?;
    let arr: [u8; 32] = v
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("{what} must be 32 bytes, got {}", v.len()))?;
    Ok(arr)
}

/// Derive the one-shot AES-256 key from the ECDH shared secret. Salt = the
/// ephemeral pubkey (binds the key to this exact exchange).
///
/// Returns a `Zeroizing` wrapper so the 32-byte OKM is wiped on drop on
/// every exit path (including caller early returns). The wrapper derefs to
/// `[u8; 32]` so `Key::<Aes256Gcm>::from_slice(&aes_key)` requires no
/// call-site changes.
fn derive_key(shared: &[u8; 32], ephemeral_pub: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(ephemeral_pub), shared);
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm)
        .expect("HKDF-SHA256 expand of 32 bytes is always valid");
    // neoth: hkdf 0.12 has no Zeroize impl — the PRK copy inside `hk`'s
    // internal HmacCore is released (not cleared) when the frame unwinds.
    // Explicit drop here marks the intent and bounds the lifetime; the
    // intermediate T(1) expansion block on expand's stack frame is also
    // released without clearing (upstream papercut). The Zeroizing wrapper
    // on `okm` is the layer we CAN control. Upgrade path: enable a zeroize
    // feature on hkdf when upstream provides one; the `drop(hk)` comment
    // is the re-test marker.
    // Hkdf has no Drop impl so clippy warns about drop-non-drop; the call is
    // intentional: it documents lifetime intent, not destructor invocation.
    #[allow(clippy::drop_non_drop)]
    drop(hk);
    Zeroizing::new(okm)
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
    // `from_slice` expects `&[u8]`; deref Zeroizing<[u8;32]> → [u8;32] → &[u8].
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(aes_key.as_ref()));
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
    let sig_bytes = B64
        .decode(&bundle.signature_b64)
        .context("decode signature")?;
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
    let ciphertext = B64
        .decode(&bundle.ciphertext_b64)
        .context("decode ciphertext")?;
    let secret = StaticSecret::from(*recipient_secret);
    let shared = secret.diffie_hellman(&PublicKey::from(eph_pub));
    let aes_key = derive_key(shared.as_bytes(), &eph_pub);
    // `from_slice` expects `&[u8]`; deref Zeroizing<[u8;32]> → [u8;32] → &[u8].
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(aes_key.as_ref()));
    cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
        .map_err(|e| anyhow::anyhow!("AES-256-GCM decrypt (wrong key or tampered): {e}"))
}

// ── A3-01 hardening: managed recipient keypair + full verify verdict ──────────

use std::path::{Path, PathBuf};

/// Default path for the operator's persistent X25519 transfer secret:
/// `~/.neoth/wal/transfer.key`. Sits next to the ed25519 signing key under the
/// same protected dir (0600 / DPAPI-wrapped on Windows).
pub fn default_transfer_key_path() -> PathBuf {
    crate::config::FreedomConfig::default_wal_dir().join("transfer.key")
}

/// Load the operator's X25519 transfer SECRET, generating + persisting a fresh
/// one on first use. DAU-safe: zero interaction — the same auto-managed pattern
/// as `wal::signing::load_or_init_signing_key`. Fail-closed if the OS RNG is
/// unavailable. The public half (what senders use as `--dest`) is derived via
/// [`transfer_pubkey_b64`].
///
/// Returns a [`Zeroizing`] wrapper so the 32-byte secret is wiped from memory
/// when it drops, preventing the raw X25519 seed from outliving its use-site.
/// Callers pass `&*secret` where `&[u8; 32]` is expected (Deref coercion).
pub fn load_or_init_transfer_key(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    if path.exists() {
        let body =
            std::fs::read(path).with_context(|| format!("read transfer key {}", path.display()))?;
        let seed = crate::wal::compaction::maybe_unwrap_dpapi(&body, path)?;
        let seed: [u8; 32] = seed.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!(
                "transfer key at {} is not 32 bytes ({} given) — refusing a malformed key",
                path.display(),
                seed.len(),
            )
        })?;
        return Ok(Zeroizing::new(seed));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create transfer key parent {}", parent.display()))?;
    }
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .context("OS RNG unavailable — refusing to generate a weak transfer key")?;
    crate::wal::compaction::write_key_securely(path, &seed)?;
    Ok(Zeroizing::new(seed))
}

/// Base64 (standard) of the X25519 PUBLIC key derived from a transfer secret —
/// what the operator shares so others can `neoth transfer export --dest <this>`.
pub fn transfer_pubkey_b64(secret: &[u8; 32]) -> String {
    let pk = PublicKey::from(&StaticSecret::from(*secret));
    B64.encode(pk.to_bytes())
}

/// The full verification verdict for a received bundle — the five operator-
/// distinguishable outcomes A3-01-hardening requires. NEVER collapse
/// `WrongRecipient` / `UnsupportedSchema` into a generic error: the operator
/// must know WHY a bundle won't open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyVerdict {
    /// Schema is supported, the recipient matches (when checked), and the
    /// signature verifies against the EMBEDDED key only — proves no post-sign
    /// tamper, NOT sender identity.
    SelfConsistent,
    /// As above, and the signature also verifies against the operator-pinned
    /// expected sender pubkey — true attribution.
    VerifiedAgainstExpected,
    /// The signature does not verify (tampered, or signed by a different key
    /// than the embedded one claims).
    SignatureMismatch,
    /// The bundle is addressed to a different X25519 public key than the
    /// recipient's — they cannot decrypt it (and shouldn't try).
    WrongRecipient,
    /// `schema_version` is not one this build understands.
    UnsupportedSchema(u32),
}

/// Verify a received bundle, returning the precise [`VerifyVerdict`]. Checks (in
/// order): schema support → recipient match (when `my_pubkey` is given) →
/// signature (against `expected_sender` when pinned, else the embedded key).
/// This NEVER decrypts — it's safe to run on an untrusted bundle.
pub fn verify_bundle(
    bundle: &TransferBundle,
    my_pubkey: Option<&[u8; 32]>,
    expected_sender: Option<&[u8; 32]>,
) -> VerifyVerdict {
    if bundle.schema_version != TRANSFER_SCHEMA_VERSION {
        return VerifyVerdict::UnsupportedSchema(bundle.schema_version);
    }
    if let Some(mine) = my_pubkey {
        match parse_b64_32(&bundle.dest_pubkey_b64, "dest_pubkey") {
            Ok(dest) if &dest != mine => return VerifyVerdict::WrongRecipient,
            Ok(_) => {}
            Err(_) => return VerifyVerdict::SignatureMismatch, // malformed dest
        }
    }
    match verify_signature(bundle, expected_sender) {
        Ok(SignatureCheck::SelfConsistent) => VerifyVerdict::SelfConsistent,
        Ok(SignatureCheck::VerifiedAgainstExpected) => VerifyVerdict::VerifiedAgainstExpected,
        Err(_) => VerifyVerdict::SignatureMismatch,
    }
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

    // ── CRYPTO-02 zeroize ────────────────────────────────────────────────

    #[test]
    fn derive_key_returns_zeroizing_wrapper() {
        // Compile-time proof: derive_key must return Zeroizing<[u8; 32]>.
        // If the return type reverts to [u8; 32] this test fails to compile.
        let shared = [0xABu8; 32];
        let eph = [0xCDu8; 32];
        let key: Zeroizing<[u8; 32]> = derive_key(&shared, &eph);
        // Must be non-zero (HKDF of non-zero inputs produces non-zero OKM).
        assert_ne!(*key, [0u8; 32]);
        // Must be deterministic.
        let key2: Zeroizing<[u8; 32]> = derive_key(&shared, &eph);
        assert_eq!(*key, *key2);
    }

    // ── A3-01 hardening ──────────────────────────────────────────────────

    #[test]
    fn verify_verdict_self_consistent_then_verified() {
        let (_rx_secret, rx_pub) = recipient(7);
        let sk = signer(5);
        let signer_pub = sk.verifying_key().to_bytes();
        let bundle = encrypt_for(b"hi", &rx_pub, &sk, 1).unwrap();
        // No recipient check, no pin → self-consistent.
        assert_eq!(
            verify_bundle(&bundle, None, None),
            VerifyVerdict::SelfConsistent
        );
        // Recipient matches + pinned sender → verified.
        assert_eq!(
            verify_bundle(&bundle, Some(&rx_pub), Some(&signer_pub)),
            VerifyVerdict::VerifiedAgainstExpected
        );
    }

    #[test]
    fn verify_verdict_wrong_recipient() {
        let (_rx_secret, rx_pub) = recipient(7);
        let (_other_s, other_pub) = recipient(9);
        let bundle = encrypt_for(b"hi", &rx_pub, &signer(1), 1).unwrap();
        assert_eq!(
            verify_bundle(&bundle, Some(&other_pub), None),
            VerifyVerdict::WrongRecipient
        );
    }

    #[test]
    fn verify_verdict_unsupported_schema() {
        let (_s, rx_pub) = recipient(7);
        let mut bundle = encrypt_for(b"hi", &rx_pub, &signer(1), 1).unwrap();
        bundle.schema_version = 99;
        assert_eq!(
            verify_bundle(&bundle, None, None),
            VerifyVerdict::UnsupportedSchema(99)
        );
    }

    #[test]
    fn verify_verdict_signature_mismatch_on_tamper() {
        let (_s, rx_pub) = recipient(7);
        let mut bundle = encrypt_for(b"hi", &rx_pub, &signer(1), 1).unwrap();
        bundle.ts_unix += 1; // signed field changed, signature not refreshed
        assert_eq!(
            verify_bundle(&bundle, None, None),
            VerifyVerdict::SignatureMismatch
        );
    }

    #[test]
    fn transfer_keypair_generates_persists_and_derives_pubkey() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wal").join("transfer.key");
        let s1: Zeroizing<[u8; 32]> = load_or_init_transfer_key(&path).expect("first gen");
        assert!(path.exists());
        let s2: Zeroizing<[u8; 32]> = load_or_init_transfer_key(&path).expect("second read");
        assert_eq!(*s1, *s2, "the persisted key is stable across loads");
        // The derived pubkey is what a sender would use as --dest; round-trips.
        let pub_b64 = transfer_pubkey_b64(&s1);
        let parsed = parse_b64_32(&pub_b64, "transfer pubkey").unwrap();
        // A bundle sealed to this pubkey decrypts with the secret.
        let bundle = encrypt_for(b"to me", &parsed, &signer(1), 1).unwrap();
        assert_eq!(decrypt_with(&bundle, &s1).unwrap(), b"to me");
    }

    #[test]
    fn transfer_key_load_returns_zeroizing_wrapper() {
        // Prove: (1) load_or_init_transfer_key returns Zeroizing<[u8;32]> (compile-time),
        // (2) fresh key is non-zero, (3) reload returns the identical bytes.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transfer.key");
        let k1: Zeroizing<[u8; 32]> = load_or_init_transfer_key(&path).unwrap();
        assert!(k1.iter().any(|&b| b != 0), "fresh key must be non-zero");
        let k2: Zeroizing<[u8; 32]> = load_or_init_transfer_key(&path).unwrap();
        assert_eq!(*k1, *k2, "reload returns the same key");
        // Full encrypt → pubkey derive → decrypt round-trip with the Zeroizing key.
        let pub_b64 = transfer_pubkey_b64(&k1);
        let recipient_pub = parse_b64_32(&pub_b64, "pub").unwrap();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let bundle = encrypt_for(
            b"crypto-03 zeroizing integration",
            &recipient_pub,
            &signing_key,
            1_700_000_000,
        )
        .expect("encrypt succeeds");
        let plaintext = decrypt_with(&bundle, &k1).expect("decrypt with Zeroizing-wrapped key");
        assert_eq!(plaintext, b"crypto-03 zeroizing integration");
    }
}
