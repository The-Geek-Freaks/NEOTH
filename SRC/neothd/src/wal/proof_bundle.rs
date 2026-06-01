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
pub const PROOF_SCHEMA_VERSION: u8 = 1;

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
    /// minisign signature (base64) over `bundle.canonical_bytes()`. `None`
    /// until the `--sign` slice + operator keypair land.
    pub signature: Option<String>,
}

impl ProofEnvelope {
    /// Seal a bundle: compute the self-integrity digest, leave unsigned.
    pub fn seal(bundle: ProofBundle) -> Self {
        let digest_sha256 = bundle.digest_hex();
        Self {
            bundle,
            digest_sha256,
            signature: None,
        }
    }

    /// Re-check the self-integrity digest. A verifier calls this FIRST; a
    /// mismatch means the bundle's frame list was altered after export.
    pub fn digest_matches(&self) -> bool {
        self.bundle.digest_hex() == self.digest_sha256
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
    }
}
