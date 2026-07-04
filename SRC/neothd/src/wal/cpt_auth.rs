//! ADV-01 — HMAC-SHA256 authenticator for WAL compaction (`.cpt`) files.
//!
//! Per [`SPEC_wal_lifecycle.md`] §4.3. Compaction produces a `.cpt`
//! replacement segment that the crash-recovery path will atomically
//! rename to `.bin` on next startup. Pre-ADV-01 the recovery applied
//! `.cpt` files using only CRC32c + xxh3-64 (non-cryptographic).
//! An attacker with local file-write access could pre-place a crafted
//! `.cpt` carrying injected `PROFILE_DELTA` or tombstone frames; the
//! next NEOTH restart would apply it unconditionally and bypass the
//! single-writer Hypothalamus invariant on the recovery path.
//!
//! ## Design
//!
//! Every `.cpt` write is paired with a `.cpt.hmac` file containing a
//! 32-byte HMAC-SHA256 over the `.cpt` content. The crash-recovery
//! reader recomputes the HMAC, constant-time-compares against the
//! `.cpt.hmac`, and refuses to apply on mismatch.
//!
//! The HMAC key is derived from NEOTH's existing per-installation
//! WAL HMAC key (see [`super::compaction::load_or_init_key`]) via a
//! single-step HMAC-SHA256 with the label `b"neoth.wal.cpt.v1"`. That
//! gives us domain separation between the in-frame
//! `COMPACTION_MARKER` HMAC and the `.cpt` file HMAC — compromising
//! one tag does not let an attacker forge the other — without
//! depending on the vault key surface that is not yet wired for this
//! purpose. When vault-derived keys land, swap [`from_master_key`] for
//! a vault-key variant.
//!
//! ## Why not HKDF
//!
//! HKDF-Extract degenerates to `HMAC(salt, master_key)` when the
//! master is already uniformly random (which our 32-byte CSPRNG key
//! is). We use a single HMAC pass with the label as key + master as
//! input data — same security property, zero extra deps.
//!
//! ## Threat model
//!
//! Defends against: attacker with local file-write access who pre-
//! places `.cpt` files. After ADV-01 they cannot forge a valid
//! `.cpt.hmac` without also stealing `~/.neoth/wal/hmac.key`
//! (which on Windows is DPAPI-wrapped per K-Sec-4).
//!
//! Does NOT defend against: an attacker who *already* has the HMAC
//! key. At that point the operator's broader audit chain is already
//! compromised; ADV-01 raises the bar for crash-recovery injection
//! to the same level as the existing marker-forgery bar.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::error::WalError;

type HmacSha256 = Hmac<Sha256>;

/// Domain-separation label for `.cpt` file HMACs. The `v1` suffix
/// reserves space for a future key-rotation path that produces
/// `v2`-tagged sub-keys without invalidating in-flight `.cpt` files.
pub const WAL_CPT_HMAC_KEY_LABEL: &[u8] = b"neoth.wal.cpt.v1";

/// Length of the HMAC-SHA256 tag persisted in `.cpt.hmac`. Fixed at
/// 32 bytes by the SHA-256 output size.
pub const CPT_HMAC_TAG_LEN: usize = 32;

/// 32-byte sub-key derived from the WAL master HMAC key. Held in
/// memory only; never written to disk. Cleared on drop via the
/// `zeroize`-free manual reset below (no dep added — manual fill is
/// sufficient for an in-process key that never leaves the address
/// space).
pub struct CompactionAuthenticator {
    sub_key: [u8; CPT_HMAC_TAG_LEN],
}

impl CompactionAuthenticator {
    /// Derive a `.cpt` sub-key from the per-installation WAL master
    /// HMAC key. `master_key` must be ≥16 bytes — `compaction::
    /// load_or_init_key` enforces this on disk read.
    pub fn from_master_key(master_key: &[u8]) -> Self {
        assert!(
            master_key.len() >= 16,
            "master HMAC key shorter than 16 bytes — caller guarantees ≥16"
        );
        let mut mac = HmacSha256::new_from_slice(WAL_CPT_HMAC_KEY_LABEL)
            .expect("HMAC-SHA256 accepts any non-empty key");
        mac.update(master_key);
        let tag = mac.finalize().into_bytes();
        let mut sub_key = [0u8; CPT_HMAC_TAG_LEN];
        sub_key.copy_from_slice(&tag);
        Self { sub_key }
    }

    /// Compute HMAC-SHA256 over `cpt_content`. Caller persists the
    /// returned bytes alongside the `.cpt` file as `.cpt.hmac`.
    pub fn sign(&self, cpt_content: &[u8]) -> [u8; CPT_HMAC_TAG_LEN] {
        let mut mac = HmacSha256::new_from_slice(&self.sub_key)
            .expect("HMAC-SHA256 accepts any non-empty key");
        mac.update(cpt_content);
        let tag = mac.finalize().into_bytes();
        let mut out = [0u8; CPT_HMAC_TAG_LEN];
        out.copy_from_slice(&tag);
        out
    }

    /// Constant-time verify `expected_hmac` against the HMAC of
    /// `cpt_content`. Returns `WalError::CompactionAuthFailed` on
    /// mismatch.
    pub fn verify(&self, cpt_content: &[u8], expected_hmac: &[u8]) -> Result<(), WalError> {
        if expected_hmac.len() != CPT_HMAC_TAG_LEN {
            return Err(WalError::CompactionAuthFailed {
                reason: format!(
                    "HMAC tag length {} does not match expected {}",
                    expected_hmac.len(),
                    CPT_HMAC_TAG_LEN
                ),
            });
        }
        let mut mac = HmacSha256::new_from_slice(&self.sub_key)
            .expect("HMAC-SHA256 accepts any non-empty key");
        mac.update(cpt_content);
        mac.verify_slice(expected_hmac)
            .map_err(|_| WalError::CompactionAuthFailed {
                reason: "HMAC tag does not match content — possible tamper".into(),
            })
    }
}

impl Drop for CompactionAuthenticator {
    fn drop(&mut self) {
        // Wipe the sub-key bytes on drop. Not crypto-grade scrubbing
        // (the compiler could elide this in theory), but it makes
        // post-drop heap dumps from the same process cleaner.
        self.sub_key.fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_master() -> Vec<u8> {
        // 32 bytes — fixed test pattern, NOT a real key.
        (0u8..32).collect()
    }

    #[test]
    fn label_constant_pins_wire_form() {
        // ADV-01 contract: the label is the wire form of the
        // domain-separation tag. A future refactor that renames the
        // label silently invalidates every previously-signed .cpt.hmac
        // on disk — pin to make the impact loud.
        assert_eq!(WAL_CPT_HMAC_KEY_LABEL, b"neoth.wal.cpt.v1");
    }

    #[test]
    fn tag_len_matches_sha256_output() {
        assert_eq!(CPT_HMAC_TAG_LEN, 32);
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = CompactionAuthenticator::from_master_key(&fixture_master());
        let b = CompactionAuthenticator::from_master_key(&fixture_master());
        assert_eq!(a.sub_key, b.sub_key);
    }

    #[test]
    fn different_master_keys_produce_different_sub_keys() {
        let a = CompactionAuthenticator::from_master_key(&fixture_master());
        let mut other = fixture_master();
        other[0] ^= 0xFF;
        let b = CompactionAuthenticator::from_master_key(&other);
        assert_ne!(a.sub_key, b.sub_key);
    }

    #[test]
    fn sub_key_differs_from_master_key() {
        // Domain separation contract — the .cpt sub-key MUST NOT equal
        // the master key. If a future change accidentally removes the
        // HMAC pass and copies the master bytes verbatim, this test
        // catches the regression before it ships.
        let master = fixture_master();
        let auth = CompactionAuthenticator::from_master_key(&master);
        assert_ne!(&auth.sub_key[..], &master[..32]);
    }

    #[test]
    fn sign_roundtrip_verifies() {
        let auth = CompactionAuthenticator::from_master_key(&fixture_master());
        let content = b"compacted segment bytes";
        let tag = auth.sign(content);
        auth.verify(content, &tag)
            .expect("matching content + tag verifies");
    }

    #[test]
    fn sign_is_deterministic_for_same_content() {
        let auth = CompactionAuthenticator::from_master_key(&fixture_master());
        let content = b"deterministic check";
        let a = auth.sign(content);
        let b = auth.sign(content);
        assert_eq!(a, b);
    }

    #[test]
    fn verify_rejects_tampered_content() {
        let auth = CompactionAuthenticator::from_master_key(&fixture_master());
        let original = b"compacted segment bytes";
        let tag = auth.sign(original);
        let tampered = b"compacted segment BYTES";
        let err = auth.verify(tampered, &tag).expect_err("tamper must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("HMAC tag does not match"),
            "expected tamper-detect message, got: {msg}"
        );
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let alice = CompactionAuthenticator::from_master_key(&fixture_master());
        let mut bob_master = fixture_master();
        bob_master[0] ^= 0xFF;
        let bob = CompactionAuthenticator::from_master_key(&bob_master);
        let content = b"alice signed this";
        let tag_from_alice = alice.sign(content);
        let r = bob.verify(content, &tag_from_alice);
        assert!(r.is_err(), "Bob's key MUST NOT verify Alice's signature");
    }

    #[test]
    fn verify_rejects_short_tag() {
        let auth = CompactionAuthenticator::from_master_key(&fixture_master());
        let short = [0u8; 16];
        let err = auth
            .verify(b"x", &short)
            .expect_err("short tag must be rejected");
        assert!(format!("{err}").contains("length"));
    }

    #[test]
    fn verify_rejects_long_tag() {
        let auth = CompactionAuthenticator::from_master_key(&fixture_master());
        let long = [0u8; 64];
        let err = auth
            .verify(b"x", &long)
            .expect_err("over-long tag must be rejected");
        assert!(format!("{err}").contains("length"));
    }

    #[test]
    fn verify_rejects_all_zero_tag() {
        // Defence against accidental "uninitialised buffer" persists —
        // an all-zero HMAC tag must never verify against any content
        // (probability of HMAC-SHA256 producing all-zeros is ~2^-256).
        let auth = CompactionAuthenticator::from_master_key(&fixture_master());
        let zeros = [0u8; CPT_HMAC_TAG_LEN];
        let r = auth.verify(b"any content here", &zeros);
        assert!(r.is_err());
    }

    #[test]
    fn drop_runs_without_panic() {
        // The `Drop` impl wipes the sub-key bytes with `fill(0)`. We
        // can't observe the memory after drop in safe Rust, so the
        // wipe correctness is by code inspection. Exercise the Drop
        // body once to surface any future panic in the wipe path.
        let auth = CompactionAuthenticator::from_master_key(&fixture_master());
        drop(auth);
    }

    #[test]
    #[should_panic(expected = "shorter than 16 bytes")]
    fn from_master_key_panics_on_short_key() {
        let _ = CompactionAuthenticator::from_master_key(&[0u8; 8]);
    }
}
