//! GOLD-ADAPT-CRYPTO-01..04 — WAL/config AEAD-at-rest primitives.
//!
//! The foundation slice for confidentiality-at-rest: typed keys, HKDF subkey
//! derivation, a resume-safe nonce counter, and an AES-256-GCM-SIV blob
//! encrypt/decrypt. No file I/O, no WAL-core wiring — those land in later
//! slices (master-key lifecycle, encrypt-on-seal, reader threading).
//!
//! ## Why AES-256-GCM-SIV (CRYPTO-04)
//! The WAL is **at-rest storage that resumes across restarts**, not a transport
//! session. With plain AES-GCM a nonce-counter that desyncs on a crash reuses a
//! `(key, nonce)` pair over different plaintexts → full GCM authentication
//! bypass + key recovery, silently. AES-256-GCM-SIV is nonce-MISUSE-resistant:
//! a collision degrades only to IND-CPA (the two colliding frames lose
//! confidentiality), never to key recovery. For the offline-exfiltration threat
//! model (stolen disk / same-user rogue process — the threat `dpapi.rs` targets)
//! that residual is acceptable; a GCM auth bypass is not.
//!
//! ## CRYPTO-01/02/03
//! - **CRYPTO-01** [`NonceCounter`]: non-`Clone`, `prefix || counter` (LE),
//!   capped at 2⁴⁸ so the counter space can never wrap into reuse.
//! - **CRYPTO-02** [`derive_subkey`]: HKDF-SHA256 with the intermediate output
//!   buffer zeroized before return (the upstream `hkdf` papercut).
//! - **CRYPTO-03** [`WalMasterKey`] / [`WalSegmentKey`]: typed `[u8; 32]`
//!   newtypes that zeroize on drop and redact their `Debug` — a raw key never
//!   reaches a log line or a clone.

use aes_gcm_siv::aead::{Aead, KeyInit, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Nonce};
use anyhow::{anyhow, Context, Result};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 12-byte magic prefix that marks an encrypted WAL blob — mirrors the
/// `dpapi.rs` `NEOTH_DPAPIv1\n` convention. The first two bytes (`NE`) differ
/// from the segment-header magic (`NTHW`), so detection is unambiguous.
pub const ENC_MAGIC: &[u8] = b"NEOTH_ENCv1\n";

/// HKDF `info` for the per-segment WAL encryption subkey (domain separation).
pub const INFO_WAL_SEGMENT: &[u8] = b"neoth-wal-segment-enc-v1";
/// HKDF `info` for the credentials-at-rest subkey.
pub const INFO_CONFIG: &[u8] = b"neoth-config-enc-v1";

/// Hard cap on the nonce counter (2⁴⁸). Reaching it forces segment rotation
/// long before the counter could wrap and reuse a value.
const NONCE_COUNTER_MAX: u64 = 1 << 48;

/// CRYPTO-03 — the 32-byte root key. Zeroizes on drop; `Debug` is redacted.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct WalMasterKey([u8; 32]);

impl WalMasterKey {
    /// Generate a fresh random master key (fail-closed on RNG failure).
    pub fn generate() -> Result<Self> {
        let mut k = [0u8; 32];
        getrandom::getrandom(&mut k).map_err(|e| anyhow!("getrandom master key: {e}"))?;
        Ok(Self(k))
    }

    /// Construct from raw bytes (e.g. an unwrapped key file). Rejects the wrong length.
    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        let arr: [u8; 32] = raw
            .try_into()
            .map_err(|_| anyhow!("WAL master key must be exactly 32 bytes, got {}", raw.len()))?;
        Ok(Self(arr))
    }

    /// Borrow the raw key bytes (CRYPTO-03 `expose_secret` — call sites are auditable).
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for WalMasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WalMasterKey(***)")
    }
}

/// CRYPTO-03 — a derived per-purpose subkey. Same zeroize + redact posture.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct WalSegmentKey([u8; 32]);

impl WalSegmentKey {
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for WalSegmentKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WalSegmentKey(***)")
    }
}

/// CRYPTO-02 — derive a domain-separated subkey via HKDF-SHA256. The
/// intermediate output buffer is zeroized before return so the only surviving
/// copy is the one owned by the returned (zeroize-on-drop) key.
pub fn derive_subkey(master: &WalMasterKey, info: &[u8]) -> Result<WalSegmentKey> {
    let hk = Hkdf::<Sha256>::new(None, master.expose());
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|_| anyhow!("HKDF expand (invalid output length)"))?;
    let key = WalSegmentKey(okm); // copies okm into the owned, zeroizing struct
    okm.zeroize(); // CRYPTO-02: scrub the intermediate buffer
    Ok(key)
}

/// CRYPTO-01 — resume-safe nonce source. Non-`Clone` (a clone would let two
/// writers issue the same nonce). The 12-byte nonce is `prefix(4) || counter(8)`
/// little-endian; `prefix` is the segment id so two segments never share a
/// nonce space even at the same counter.
#[derive(Debug)]
pub struct NonceCounter {
    prefix: [u8; 4],
    counter: u64,
}

impl NonceCounter {
    /// Start a counter for a segment. `start` lets a resuming writer continue
    /// from the segment's existing frame count (the authoritative source).
    pub fn new(segment_prefix: [u8; 4], start: u64) -> Self {
        Self {
            prefix: segment_prefix,
            counter: start,
        }
    }

    /// Yield the next nonce and advance. `Err` once the 2⁴⁸ cap is reached so a
    /// caller rotates the segment instead of ever wrapping into reuse.
    pub fn next_nonce(&mut self) -> Result<[u8; 12]> {
        if self.counter >= NONCE_COUNTER_MAX {
            return Err(anyhow!(
                "nonce counter exhausted (2^48) — segment must rotate"
            ));
        }
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&self.prefix);
        nonce[4..12].copy_from_slice(&self.counter.to_le_bytes());
        self.counter += 1;
        Ok(nonce)
    }

    /// The current counter value (frames issued so far).
    pub fn position(&self) -> u64 {
        self.counter
    }
}

/// CRYPTO-04 — AES-256-GCM-SIV encrypt. `aad` is authenticated-but-not-encrypted
/// (the plaintext segment header binds the ciphertext to its metadata). Returns
/// `ciphertext || tag`.
pub fn encrypt_blob(
    key: &WalSegmentKey,
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256GcmSiv::new_from_slice(key.expose())
        .map_err(|e| anyhow!("AES-256-GCM-SIV key init: {e}"))?;
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|e| anyhow!("AES-256-GCM-SIV encrypt: {e}"))
}

/// CRYPTO-04 — AES-256-GCM-SIV decrypt. `Err` on a wrong key, wrong nonce,
/// wrong `aad`, or any tampered byte (the GCM-SIV tag fails closed).
pub fn decrypt_blob(
    key: &WalSegmentKey,
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256GcmSiv::new_from_slice(key.expose())
        .map_err(|e| anyhow!("AES-256-GCM-SIV key init: {e}"))?;
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|e| anyhow!("AES-256-GCM-SIV decrypt (wrong key / nonce / aad, or tampered): {e}"))
}

/// True when `bytes` begins with the [`ENC_MAGIC`] prefix.
pub fn is_encrypted(bytes: &[u8]) -> bool {
    bytes.starts_with(ENC_MAGIC)
}

/// Build the on-disk encrypted blob: `ENC_MAGIC || nonce(12) || ciphertext`.
pub fn frame_encrypted(nonce: &[u8; 12], ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ENC_MAGIC.len() + 12 + ciphertext.len());
    out.extend_from_slice(ENC_MAGIC);
    out.extend_from_slice(nonce);
    out.extend_from_slice(ciphertext);
    out
}

/// Split an on-disk encrypted blob into `(nonce, ciphertext)`. `Err` if the
/// magic is absent or the buffer is too short to hold magic + nonce.
pub fn split_encrypted(bytes: &[u8]) -> Result<([u8; 12], &[u8])> {
    if !is_encrypted(bytes) {
        return Err(anyhow!("not an encrypted blob (missing ENC magic)"));
    }
    let after_magic = &bytes[ENC_MAGIC.len()..];
    if after_magic.len() < 12 {
        return Err(anyhow!("encrypted blob truncated (no nonce)"));
    }
    let nonce: [u8; 12] = after_magic[..12]
        .try_into()
        .context("read 12-byte nonce")?;
    Ok((nonce, &after_magic[12..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> WalSegmentKey {
        let master = WalMasterKey::from_bytes(&[7u8; 32]).unwrap();
        derive_subkey(&master, INFO_WAL_SEGMENT).unwrap()
    }

    #[test]
    fn encrypt_decrypt_round_trips() {
        let key = test_key();
        let nonce = [1u8; 12];
        let aad = b"segment-header-as-aad";
        let pt = b"the quick brown fox jumps over the lazy dog";
        let ct = encrypt_blob(&key, &nonce, aad, pt).unwrap();
        assert_ne!(&ct[..], &pt[..], "ciphertext must differ from plaintext");
        let back = decrypt_blob(&key, &nonce, aad, &ct).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn tampered_ciphertext_fails_closed() {
        let key = test_key();
        let nonce = [2u8; 12];
        let mut ct = encrypt_blob(&key, &nonce, b"", b"secret payload").unwrap();
        ct[0] ^= 0xFF;
        assert!(decrypt_blob(&key, &nonce, b"", &ct).is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let key = test_key();
        let nonce = [3u8; 12];
        let ct = encrypt_blob(&key, &nonce, b"header-A", b"payload").unwrap();
        assert!(
            decrypt_blob(&key, &nonce, b"header-B", &ct).is_err(),
            "AAD is authenticated — a changed header must fail decrypt"
        );
    }

    #[test]
    fn subkeys_are_domain_separated() {
        let master = WalMasterKey::from_bytes(&[9u8; 32]).unwrap();
        let seg = derive_subkey(&master, INFO_WAL_SEGMENT).unwrap();
        let cfg = derive_subkey(&master, INFO_CONFIG).unwrap();
        assert_ne!(seg.expose(), cfg.expose(), "different info → different keys");
    }

    #[test]
    fn nonce_counter_increments_and_caps() {
        let mut nc = NonceCounter::new([0xAB; 4], 0);
        let n0 = nc.next_nonce().unwrap();
        let n1 = nc.next_nonce().unwrap();
        assert_ne!(n0, n1);
        assert_eq!(&n0[0..4], &[0xAB; 4], "prefix preserved");
        assert_eq!(&n0[4..12], &0u64.to_le_bytes());
        assert_eq!(&n1[4..12], &1u64.to_le_bytes());
        // At the cap, refuse rather than wrap into reuse.
        let mut maxed = NonceCounter::new([0; 4], NONCE_COUNTER_MAX);
        assert!(maxed.next_nonce().is_err());
    }

    #[test]
    fn nonce_prefix_separates_segments() {
        // Same counter, different segment prefix → different nonce space.
        let mut a = NonceCounter::new([1, 0, 0, 0], 5);
        let mut b = NonceCounter::new([2, 0, 0, 0], 5);
        assert_ne!(a.next_nonce().unwrap(), b.next_nonce().unwrap());
    }

    #[test]
    fn frame_split_round_trips() {
        let key = test_key();
        let nonce = [4u8; 12];
        let ct = encrypt_blob(&key, &nonce, b"", b"hello").unwrap();
        let blob = frame_encrypted(&nonce, &ct);
        assert!(is_encrypted(&blob));
        let (got_nonce, got_ct) = split_encrypted(&blob).unwrap();
        assert_eq!(got_nonce, nonce);
        assert_eq!(decrypt_blob(&key, &got_nonce, b"", got_ct).unwrap(), b"hello");
        // A plaintext segment header (magic NTHW) is not mistaken for encrypted.
        assert!(!is_encrypted(b"NTHW\x00\x00"));
    }

    #[test]
    fn master_key_debug_is_redacted() {
        let k = WalMasterKey::from_bytes(&[0x42; 32]).unwrap();
        assert_eq!(format!("{k:?}"), "WalMasterKey(***)");
        assert!(!format!("{k:?}").contains("42"));
    }

    #[test]
    fn from_bytes_rejects_wrong_length() {
        assert!(WalMasterKey::from_bytes(&[0u8; 31]).is_err());
        assert!(WalMasterKey::from_bytes(&[0u8; 33]).is_err());
        assert!(WalMasterKey::from_bytes(&[0u8; 32]).is_ok());
    }
}
