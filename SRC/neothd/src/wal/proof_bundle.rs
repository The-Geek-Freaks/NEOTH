//! `.neoth-proof` tamper-evidence bundle — KF-03.
//!
//! `neoth wal export --window <w>` walks the WAL, collects every frame in a
//! time window plus the HMAC compaction marker(s) that seal those bytes, and
//! writes a self-describing JSON envelope. A third party (auditor, backup
//! validator, disaster-recovery operator) re-checks tamper-evidence by:
//!   1. recomputing the envelope's SHA-256 over the bundle's canonical bytes
//!      ([`ProofEnvelope::digest_matches`]) — detects bundle tampering;
//!   2. recomputing each marker's HMAC over the original segment bytes via
//!      the same [`crate::wal::compaction::verify_marker`] the daemon uses —
//!      detects WAL tampering.
//!
//! The bundle is SIGN-READY: [`ProofBundle::canonical_bytes`] is the stable
//! byte form the future `--sign` (KF-03 signed slice, blocked on the
//! operator's minisign keypair) signs verbatim into [`ProofEnvelope::signature`].

use serde::{Deserialize, Serialize};

/// Bumped only on a breaking format change. Verifiers reject unknown majors.
/// v2 (KF-03 signed slice): the envelope gained `signer_pubkey` +
/// `sig_algorithm` alongside the now-populated `signature`. Unsigned v2
/// bundles leave all three `None` (back-compatible with the v1 shape via
/// `#[serde(default)]`), so the bump is conservative.
pub const PROOF_SCHEMA_VERSION: u8 = 2;

/// One WAL frame captured into the proof, metadata + the frame's own
/// `payload_hash` (the per-frame integrity anchor). Payload BYTES are
/// deliberately NOT included — the bundle proves chain + frame integrity
/// without exfiltrating message content (no PII leakage from a proof file).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProofFrame {
    /// Segment basename the frame came from (e.g. `000001.wal`).
    pub segment: String,
    /// Logical byte offset within the (decompressed) frame stream. For a
    /// compressed segment this is the offset in the inflated body, not the
    /// on-disk offset — it locates the frame; integrity is via `payload_hash`.
    pub offset: u64,
    pub event_type: u8,
    pub event_id: u64,
    pub ts_ns: u64,
    pub payload_hash: u64,
    pub payload_len: u32,
    pub importance: f32,
}

/// A `0x15 COMPACTION_MARKER` copied verbatim so a verifier with the original
/// segment + the operator's HMAC key can re-run `verify_marker` over the
/// sealed byte range — the cryptographic tamper-evidence anchor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProofMarker {
    pub segment: String,
    pub from_offset: u64,
    pub to_offset: u64,
    pub frame_count: u32,
    pub hmac_hex: String,
    /// Re-verified against the local HMAC key at export time when
    /// `--verify-chain` was set AND the key was available; `None` means the
    /// verifier must check it themselves (no key at export, or flag off).
    pub verified_at_export: Option<bool>,
}

/// The proof body. Sealed into a [`ProofEnvelope`] before writing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProofBundle {
    pub schema_version: u8,
    pub neoth_version: String,
    /// Inclusive lower bound (unix nanoseconds).
    pub window_start_ts_ns: u64,
    /// Exclusive upper bound (unix nanoseconds).
    pub window_end_ts_ns: u64,
    pub generated_unix: i64,
    pub frames: Vec<ProofFrame>,
    pub markers: Vec<ProofMarker>,
    /// `true` only when at least one marker was present AND every included
    /// marker re-verified at export time. `false` when the window is not yet
    /// sealed by any marker OR a marker failed — a verifier must re-check.
    pub chain_verified: bool,
}

impl ProofBundle {
    /// Stable, compact canonical bytes — what the future `--sign` signs and
    /// what the envelope digest covers. `serde_json` with struct field order
    /// (stable in Rust) gives a deterministic encoding.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// SHA-256 (lowercase hex) over [`Self::canonical_bytes`].
    pub fn digest_hex(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(self.canonical_bytes());
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// The file written to disk: the bundle + a self-integrity digest + a
/// signature slot. The digest covers the bundle's canonical bytes (NOT the
/// envelope — avoids circularity), so a verifier checks the digest before
/// trusting `frames`. `signature` stays `None` until the signed slice.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProofEnvelope {
    pub bundle: ProofBundle,
    /// SHA-256 hex over `bundle.canonical_bytes()`.
    pub digest_sha256: String,
    /// KF-03: base64 (standard) of the raw 64-byte ed25519 signature over
    /// `bundle.canonical_bytes()`, produced by `neoth wal export --sign` with
    /// the operator's auto-managed signing key. `None` for an unsigned export.
    pub signature: Option<String>,
    /// KF-03: base64 (standard) of the 32-byte ed25519 PUBLIC key that signed
    /// this bundle, embedded so `neoth wal verify-proof` is self-contained.
    /// **Self-consistency only** — on an untrusted channel an attacker could
    /// replace both the bundle AND this key + re-sign; true operator
    /// attribution requires pinning the key out-of-band (`--pubkey`). `None`
    /// when unsigned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_pubkey: Option<String>,
    /// KF-03: signature scheme tag (`"ed25519-raw"`); lets a future scheme
    /// change be unambiguous to a verifier. `None` when unsigned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig_algorithm: Option<String>,
}

/// Outcome of [`ProofEnvelope::check_signature`]. Deliberately distinguishes
/// "self-consistent" (signed by the embedded key — proves no post-sign
/// tamper, but NOT who) from "verified against the operator's expected key"
/// (true attribution) so a verifier never mistakes one for the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureCheck {
    /// No signature present (unsigned bundle).
    Unsigned,
    /// Signature valid against the EMBEDDED pubkey only. Proves the bundle was
    /// not altered after signing; does NOT prove the signer's identity (the
    /// embedded key is attacker-replaceable on an untrusted channel). The
    /// operator should pin `signer_pubkey` out-of-band + re-verify with it.
    SelfConsistent { signer_pubkey: String },
    /// Signature valid AND the embedded key matches the operator's pinned
    /// (out-of-band) `--pubkey` — true attribution.
    VerifiedAgainstExpected,
    /// Signature present but does not verify (tampered bundle / wrong key /
    /// malformed signature / embedded key ≠ expected key).
    Invalid { reason: String },
}

impl ProofEnvelope {
    /// Seal a bundle: compute the self-integrity digest, leave unsigned.
    pub fn seal(bundle: ProofBundle) -> Self {
        let digest_sha256 = bundle.digest_hex();
        Self {
            bundle,
            digest_sha256,
            signature: None,
            signer_pubkey: None,
            sig_algorithm: None,
        }
    }

    /// Re-check the self-integrity digest. A verifier calls this FIRST; a
    /// mismatch means the bundle's frame list was altered after export.
    pub fn digest_matches(&self) -> bool {
        self.bundle.digest_hex() == self.digest_sha256
    }

    /// KF-03: sign the sealed bundle with the operator's ed25519 key,
    /// populating `signature` (over `bundle.canonical_bytes()`),
    /// `signer_pubkey`, and `sig_algorithm`. Idempotent — re-signing
    /// overwrites all three. The digest covers `canonical_bytes()` and the
    /// signature covers the SAME bytes, so a verifier's digest + signature
    /// checks are consistent.
    pub fn sign(&mut self, key: &ed25519_dalek::SigningKey) {
        let msg = self.bundle.canonical_bytes();
        self.signature = Some(crate::wal::signing::sign_b64(key, &msg));
        self.signer_pubkey = Some(crate::wal::signing::pubkey_b64(key));
        self.sig_algorithm = Some(crate::wal::signing::SIG_ALGORITHM.to_string());
    }

    /// KF-03: check the signature. `expected_pubkey` is the operator's pinned
    /// (out-of-band) public key; pass `Some` for TRUE attribution, `None` for
    /// a self-consistency-only check against the embedded key. See
    /// [`SignatureCheck`] for the verdict semantics. Always verifies over
    /// `bundle.canonical_bytes()` — call [`Self::digest_matches`] FIRST so a
    /// digest mismatch is reported as tamper before reaching here.
    pub fn check_signature(&self, expected_pubkey: Option<&str>) -> SignatureCheck {
        let Some(sig) = self.signature.as_ref() else {
            return SignatureCheck::Unsigned;
        };
        let Some(embedded_pk) = self.signer_pubkey.as_ref() else {
            return SignatureCheck::Invalid {
                reason: "signature present but signer_pubkey missing — not verifiable".to_string(),
            };
        };
        let msg = self.bundle.canonical_bytes();
        match expected_pubkey {
            // Operator pinned a key out-of-band: it is the trust anchor. The
            // embedded key must EQUAL it (else the file claims a different
            // signer) AND the signature must verify under it.
            Some(expected) => {
                if expected.trim() != embedded_pk.trim() {
                    return SignatureCheck::Invalid {
                        reason: "embedded signer_pubkey does not match the expected --pubkey \
                                 (the proof was signed by a different key)"
                            .to_string(),
                    };
                }
                match crate::wal::signing::verify_b64(expected.trim(), sig, &msg) {
                    Ok(()) => SignatureCheck::VerifiedAgainstExpected,
                    Err(e) => SignatureCheck::Invalid { reason: e.to_string() },
                }
            }
            // No pinned key: self-consistency only (proves no post-sign tamper,
            // not identity).
            None => match crate::wal::signing::verify_b64(embedded_pk, sig, &msg) {
                Ok(()) => SignatureCheck::SelfConsistent {
                    signer_pubkey: embedded_pk.clone(),
                },
                Err(e) => SignatureCheck::Invalid { reason: e.to_string() },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_bundle() -> ProofBundle {
        ProofBundle {
            schema_version: PROOF_SCHEMA_VERSION,
            neoth_version: "0.0.0-test".into(),
            window_start_ts_ns: 1_000,
            window_end_ts_ns: 2_000,
            generated_unix: 1_700_000_000,
            frames: vec![ProofFrame {
                segment: "000001.wal".into(),
                offset: 64,
                event_type: 0x01,
                event_id: 7,
                ts_ns: 1_500,
                payload_hash: 0xdead_beef,
                payload_len: 12,
                importance: 0.5,
            }],
            markers: vec![],
            chain_verified: false,
        }
    }

    #[test]
    fn canonical_bytes_is_deterministic() {
        let a = sample_bundle();
        let b = sample_bundle();
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
    }

    #[test]
    fn canonical_bytes_round_trips() {
        let a = sample_bundle();
        let back: ProofBundle = serde_json::from_slice(&a.canonical_bytes()).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn envelope_digest_detects_tamper() {
        let env = ProofEnvelope::seal(sample_bundle());
        assert!(env.digest_matches(), "freshly sealed envelope must verify");

        // Tamper the frame list after sealing → digest no longer matches.
        let mut tampered = env.clone();
        tampered.bundle.frames[0].payload_hash = 0x0000_0000;
        assert!(
            !tampered.digest_matches(),
            "altering a frame after seal must break the digest"
        );

        // Tamper the digest itself → also caught.
        let mut bad_digest = env.clone();
        bad_digest.digest_sha256 = "0".repeat(64);
        assert!(!bad_digest.digest_matches());
    }

    #[test]
    fn fresh_envelope_is_unsigned() {
        let env = ProofEnvelope::seal(sample_bundle());
        assert!(
            env.signature.is_none(),
            "unsigned slice leaves signature None"
        );
        assert_eq!(env.check_signature(None), SignatureCheck::Unsigned);
    }

    // ── KF-03 signing ─────────────────────────────────────────────────────

    fn test_key(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn sign_populates_all_three_fields() {
        let mut env = ProofEnvelope::seal(sample_bundle());
        env.sign(&test_key(11));
        assert!(env.signature.is_some());
        assert!(env.signer_pubkey.is_some());
        assert_eq!(env.sig_algorithm.as_deref(), Some("ed25519-raw"));
    }

    #[test]
    fn signed_envelope_is_self_consistent() {
        let mut env = ProofEnvelope::seal(sample_bundle());
        env.sign(&test_key(11));
        match env.check_signature(None) {
            SignatureCheck::SelfConsistent { signer_pubkey } => {
                assert_eq!(Some(signer_pubkey), env.signer_pubkey);
            }
            other => panic!("expected SelfConsistent, got {other:?}"),
        }
    }

    #[test]
    fn signed_envelope_verifies_against_matching_expected_key() {
        let key = test_key(11);
        let mut env = ProofEnvelope::seal(sample_bundle());
        env.sign(&key);
        let expected = crate::wal::signing::pubkey_b64(&key);
        assert_eq!(
            env.check_signature(Some(&expected)),
            SignatureCheck::VerifiedAgainstExpected,
            "the operator's pinned key gives TRUE attribution",
        );
    }

    #[test]
    fn signed_envelope_rejects_wrong_expected_key() {
        let mut env = ProofEnvelope::seal(sample_bundle());
        env.sign(&test_key(11));
        // An attacker can't make the proof verify against the operator's REAL
        // pinned key (which differs from the embedded one).
        let other = crate::wal::signing::pubkey_b64(&test_key(99));
        assert!(matches!(
            env.check_signature(Some(&other)),
            SignatureCheck::Invalid { .. }
        ));
    }

    #[test]
    fn tampering_a_frame_after_signing_breaks_the_signature() {
        let mut env = ProofEnvelope::seal(sample_bundle());
        env.sign(&test_key(11));
        // Alter a frame AFTER signing → canonical_bytes change → the sig (over
        // the original bytes) no longer verifies. (digest_matches() also
        // catches this; the signature is the second, key-bound layer.)
        env.bundle.frames[0].payload_hash = 0x0000_0000;
        assert!(matches!(
            env.check_signature(None),
            SignatureCheck::Invalid { .. }
        ));
    }

    #[test]
    fn unsigned_v2_envelope_round_trips_through_json() {
        // Back-compat: an unsigned envelope omits the new fields (skip_if None)
        // and re-parses cleanly.
        let env = ProofEnvelope::seal(sample_bundle());
        let json = serde_json::to_string(&env).unwrap();
        assert!(!json.contains("signer_pubkey"), "unsigned omits the field");
        let back: ProofEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back, env);
    }
}
