//! P-10 — PROFILE_BASELINE_SNAPSHOT (0xB3) emitter primitive.
//!
//! v1.1 §A3 Phase-3 drift anchor. Emitted ONCE during the Phase-3
//! Day-65 seed-migration pass after the operator's first stable
//! claim set lands. Captures the full snapshot in a single frame
//! so a later drift-detection pass (Phase-4) can compare any
//! future profile state against the seed without walking the
//! entire delta chain.
//!
//! This module ships the **payload primitive** + **exactly-once
//! enforcement helper**. The wire-up site (`neoth-migrate` Phase-3
//! seed pass) calls into here to produce the JSON byte vec the WAL
//! writer appends.
//!
//! Invariants from `wal::events.rs` doc-comment on
//! `EVENT_TYPE_PROFILE_BASELINE_SNAPSHOT`:
//!   - `importance=1.0` at write
//!   - never compacted, never tombstoned
//!   - SYNC_ON_WRITE
//!   - exactly-once: caller checks for existing snapshot before
//!     emit; second write is a hard error
//!
//! Wire shape (matches the doc-comment promise):
//! `{snapshot_id, claim_count, claim_hashes, embedding_b64,
//!  neoth_version, seeded_at_ts_unix}`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Maximum bytes of `embedding_b64` we accept. Keeps the WAL frame
/// under the 1 MiB payload ceiling even on extreme embedding sizes.
/// 2048 dims × 4 bytes × base64 1.33 expansion = ~10.9 KiB; this
/// cap is comfortable headroom.
pub const MAX_EMBEDDING_B64_BYTES: usize = 64 * 1024;

/// One baseline snapshot. Serializes to the JSON the 0xB3 WAL
/// frame payload carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineSnapshot {
    /// UUID v7 — time-ordered so Phase-4 drift queries sort
    /// snapshots chronologically without re-deriving from
    /// `seeded_at_ts_unix`.
    pub snapshot_id: String,
    pub claim_count: u32,
    /// Per-claim SHA-256 hex digests in claim-id order. Phase-4
    /// drift compares set membership; ordering is preserved for
    /// audit replay.
    pub claim_hashes: Vec<String>,
    /// Optional embedding payload (base64 of the f32 vector bytes).
    /// `None` when no `EmbedProvider` is wired (Phase-4 follow-up
    /// per the events.rs doc).
    pub embedding_b64: Option<String>,
    /// NEOTH version that wrote the snapshot. Format: semver
    /// (e.g. `"0.1.0"`).
    pub neoth_version: String,
    pub seeded_at_ts_unix: i64,
}

impl BaselineSnapshot {
    /// Hash one claim into the 64-char lowercase-hex SHA-256
    /// digest the snapshot stores. Used by the migration pass to
    /// build `claim_hashes` from the seed claim set.
    pub fn hash_claim(claim_text: &str) -> String {
        let digest = Sha256::digest(claim_text.as_bytes());
        let mut out = String::with_capacity(64);
        for b in digest {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }

    /// Build the JSON byte vec for the 0xB3 WAL frame payload.
    /// Validates that `embedding_b64` (when present) does not
    /// exceed `MAX_EMBEDDING_B64_BYTES` so the frame stays under
    /// the WAL payload ceiling.
    pub fn to_payload(&self) -> Result<Vec<u8>, BaselineError> {
        if let Some(b64) = &self.embedding_b64 {
            if b64.len() > MAX_EMBEDDING_B64_BYTES {
                return Err(BaselineError::EmbeddingTooLarge {
                    actual: b64.len(),
                    cap: MAX_EMBEDDING_B64_BYTES,
                });
            }
        }
        if self.claim_count as usize != self.claim_hashes.len() {
            return Err(BaselineError::ClaimCountMismatch {
                count_field: self.claim_count as usize,
                actual_hashes: self.claim_hashes.len(),
            });
        }
        serde_json::to_vec(self).map_err(|e| BaselineError::Serialise(e.to_string()))
    }

    /// Convenience constructor — auto-derives `claim_count` from
    /// `claim_hashes.len()` so the two cannot drift.
    pub fn new(
        snapshot_id: impl Into<String>,
        claim_hashes: Vec<String>,
        embedding_b64: Option<String>,
        neoth_version: impl Into<String>,
        seeded_at_ts_unix: i64,
    ) -> Self {
        let claim_count = claim_hashes.len() as u32;
        Self {
            snapshot_id: snapshot_id.into(),
            claim_count,
            claim_hashes,
            embedding_b64,
            neoth_version: neoth_version.into(),
            seeded_at_ts_unix,
        }
    }
}

/// Operator-facing error from the exactly-once + size invariants.
#[derive(Debug, thiserror::Error)]
pub enum BaselineError {
    #[error(
        "embedding_b64 exceeds size cap ({actual} bytes > {cap}); reduce dimensions \
         or drop the embedding from this snapshot"
    )]
    EmbeddingTooLarge { actual: usize, cap: usize },
    #[error(
        "claim_count={count_field} drifted from claim_hashes.len()={actual_hashes} \
         — use BaselineSnapshot::new() to keep them in lockstep"
    )]
    ClaimCountMismatch {
        count_field: usize,
        actual_hashes: usize,
    },
    #[error("snapshot already emitted ({snapshot_id}); 0xB3 frames are exactly-once")]
    AlreadyEmitted { snapshot_id: String },
    #[error("serialise: {0}")]
    Serialise(String),
}

/// Exactly-once gate. Caller passes in the snapshot id they
/// observed in the WAL replay (if any). If `Some`, this is a
/// second-write attempt and we bail with the dedicated error so
/// the operator sees WHICH prior snapshot is blocking.
///
/// Returns Ok(()) when the gate passes (caller may now emit).
pub fn ensure_exactly_once(existing_snapshot_id: Option<&str>) -> Result<(), BaselineError> {
    if let Some(id) = existing_snapshot_id {
        return Err(BaselineError::AlreadyEmitted {
            snapshot_id: id.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(id: &str, hashes: Vec<String>) -> BaselineSnapshot {
        BaselineSnapshot::new(id, hashes, None, "0.1.0", 1_700_000_000)
    }

    #[test]
    fn hash_claim_returns_64_char_lowercase_hex() {
        let h = BaselineSnapshot::hash_claim("operator likes Rust");
        assert_eq!(h.len(), 64);
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && (c.is_ascii_digit() || c.is_ascii_lowercase()))
        );
    }

    #[test]
    fn hash_claim_deterministic() {
        let a = BaselineSnapshot::hash_claim("x");
        let b = BaselineSnapshot::hash_claim("x");
        assert_eq!(a, b);
    }

    #[test]
    fn hash_claim_differs_per_input() {
        let a = BaselineSnapshot::hash_claim("alpha");
        let b = BaselineSnapshot::hash_claim("beta");
        assert_ne!(a, b);
    }

    #[test]
    fn constructor_auto_derives_claim_count() {
        let s = fixture("snap-1", vec!["h1".into(), "h2".into(), "h3".into()]);
        assert_eq!(s.claim_count, 3);
    }

    #[test]
    fn payload_round_trips_through_serde() {
        let s = fixture("snap-1", vec!["aa".into(), "bb".into()]);
        let bytes = s.to_payload().unwrap();
        let back: BaselineSnapshot = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn payload_carries_required_fields() {
        let s = fixture("snap-7f3a", vec!["h1".into()]);
        let v: serde_json::Value = serde_json::from_slice(&s.to_payload().unwrap()).unwrap();
        assert_eq!(v["snapshot_id"], "snap-7f3a");
        assert_eq!(v["claim_count"], 1);
        assert_eq!(v["neoth_version"], "0.1.0");
        assert_eq!(v["seeded_at_ts_unix"], 1_700_000_000);
        assert!(v["claim_hashes"].is_array());
    }

    #[test]
    fn payload_rejects_drifted_claim_count() {
        // Construct via struct-literal to bypass the auto-derive.
        let drifted = BaselineSnapshot {
            snapshot_id: "x".into(),
            claim_count: 5,
            claim_hashes: vec!["only-one".into()],
            embedding_b64: None,
            neoth_version: "0.1.0".into(),
            seeded_at_ts_unix: 0,
        };
        match drifted.to_payload() {
            Err(BaselineError::ClaimCountMismatch {
                count_field,
                actual_hashes,
            }) => {
                assert_eq!(count_field, 5);
                assert_eq!(actual_hashes, 1);
            }
            other => panic!("expected ClaimCountMismatch, got {other:?}"),
        }
    }

    #[test]
    fn payload_rejects_oversized_embedding() {
        let oversized = "x".repeat(MAX_EMBEDDING_B64_BYTES + 1);
        let s = BaselineSnapshot::new("x", vec![], Some(oversized), "0.1.0", 0);
        match s.to_payload() {
            Err(BaselineError::EmbeddingTooLarge { actual, cap }) => {
                assert_eq!(actual, MAX_EMBEDDING_B64_BYTES + 1);
                assert_eq!(cap, MAX_EMBEDDING_B64_BYTES);
            }
            other => panic!("expected EmbeddingTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn payload_accepts_embedding_at_exact_cap() {
        let at_cap = "x".repeat(MAX_EMBEDDING_B64_BYTES);
        let s = BaselineSnapshot::new("x", vec![], Some(at_cap), "0.1.0", 0);
        assert!(s.to_payload().is_ok());
    }

    #[test]
    fn ensure_exactly_once_passes_when_no_prior_snapshot() {
        assert!(ensure_exactly_once(None).is_ok());
    }

    #[test]
    fn ensure_exactly_once_bails_with_prior_snapshot_id() {
        match ensure_exactly_once(Some("snap-prior-7f3a")) {
            Err(BaselineError::AlreadyEmitted { snapshot_id }) => {
                assert_eq!(snapshot_id, "snap-prior-7f3a");
            }
            other => panic!("expected AlreadyEmitted, got {other:?}"),
        }
    }

    #[test]
    fn embedding_optional_field_omitted_when_none() {
        let s = fixture("x", vec![]);
        let v: serde_json::Value = serde_json::from_slice(&s.to_payload().unwrap()).unwrap();
        // `embedding_b64: null` is fine; the field stays present.
        assert!(v.get("embedding_b64").is_some());
        assert!(v["embedding_b64"].is_null());
    }

    #[test]
    fn embedding_round_trips_when_present() {
        let s = BaselineSnapshot::new("x", vec![], Some("base64-payload".into()), "0.1.0", 0);
        let bytes = s.to_payload().unwrap();
        let back: BaselineSnapshot = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.embedding_b64.as_deref(), Some("base64-payload"));
    }
}
