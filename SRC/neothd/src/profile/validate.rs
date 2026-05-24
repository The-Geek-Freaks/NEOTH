//! Stage 4 — `profile.validate`. Pure schema validation + provenance
//! check on the LLM-produced [`ProfileDelta`]. No LLM, no I/O.
//!
//! What this stage rejects:
//!   - Empty `extraction_id` (idempotency key cannot be blank).
//!   - Empty `conversation_hash` (audit trail breaks otherwise).
//!   - Claims with empty `field` path.
//!   - Claims with `confidence` outside `[0.0, 1.0]` or NaN.
//!   - Claims whose `evidence_event_ids` reference segments outside the
//!     attributed window (the LLM cited a row that doesn't exist).
//!   - Claims whose ONLY evidence is `QuotedExternal`, `ToolOutput`, or
//!     `Ambiguous` segments (H1 fix — provenance must include at least
//!     one `UserSpeech` segment).
//!
//! What it does NOT do — those belong to stage 5 (`profile_claim_guard`):
//!   - Redaction registry lookup.
//!   - Daily-LLM-cost cap enforcement.
//!   - Timestamp normalisation.
//!   - Novel-category extension registry check.

use std::collections::HashSet;

use crate::profile::delta::{ProfileDelta, RawClaim};
use crate::profile::types::AttributedWindow;

/// One validation error. The dispatcher folds these into a per-claim
/// drop list; whole-delta errors abort the validation pass.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ValidateError {
    #[error("empty extraction_id")]
    EmptyExtractionId,
    #[error("empty conversation_hash")]
    EmptyConversationHash,
    #[error("claim has empty field path")]
    EmptyField,
    #[error("claim confidence {0} outside [0.0, 1.0]")]
    ConfidenceOutOfRange(String),
    #[error("claim cites event_id {0} not present in attributed window")]
    UnknownEvidence(i64),
    #[error("claim has no UserSpeech provenance (H1)")]
    NoFirstPersonProvenance,
}

/// Result of a validation pass. `accepted_claims` survived every check;
/// `dropped` records the per-claim reasons so the audit trail captures
/// what the LLM proposed vs. what made it through.
#[derive(Clone, Debug, Default)]
pub struct ValidatedDelta {
    pub delta: ProfileDelta,
    pub dropped: Vec<DroppedClaim>,
}

/// One rejected claim plus the reason it failed.
#[derive(Clone, Debug, PartialEq)]
pub struct DroppedClaim {
    pub claim: RawClaim,
    pub reason: ValidateError,
}

/// Validate `delta` against `attributed_window`. Returns a
/// `ValidatedDelta` with the surviving claims. Whole-delta errors
/// (empty extraction_id, empty conversation_hash) return `Err` so the
/// caller can short-circuit.
pub fn validate(
    delta: ProfileDelta,
    attributed_window: &AttributedWindow,
) -> Result<ValidatedDelta, ValidateError> {
    if delta.extraction_id.trim().is_empty() {
        return Err(ValidateError::EmptyExtractionId);
    }
    if delta.conversation_hash.trim().is_empty() {
        return Err(ValidateError::EmptyConversationHash);
    }

    // Index of every event_id in the window so evidence lookups are O(1).
    let window_ids: HashSet<i64> = attributed_window
        .segments
        .iter()
        .map(|s| s.segment.event_id)
        .collect();
    let user_speech_ids: HashSet<i64> = attributed_window
        .segments
        .iter()
        .filter(|s| s.is_extraction_eligible())
        .map(|s| s.segment.event_id)
        .collect();

    let mut accepted = Vec::with_capacity(delta.claims.len());
    let mut dropped = Vec::new();

    for claim in delta.claims.iter() {
        if let Err(reason) = check_claim(claim, &window_ids, &user_speech_ids) {
            dropped.push(DroppedClaim {
                claim: claim.clone(),
                reason,
            });
        } else {
            accepted.push(claim.clone());
        }
    }

    Ok(ValidatedDelta {
        delta: ProfileDelta {
            claims: accepted,
            ..delta
        },
        dropped,
    })
}

fn check_claim(
    claim: &RawClaim,
    window_ids: &HashSet<i64>,
    user_speech_ids: &HashSet<i64>,
) -> Result<(), ValidateError> {
    if claim.field.trim().is_empty() {
        return Err(ValidateError::EmptyField);
    }
    if !claim.confidence.is_finite() || claim.confidence < 0.0 || claim.confidence > 1.0 {
        return Err(ValidateError::ConfidenceOutOfRange(format!(
            "{}",
            claim.confidence
        )));
    }
    // Evidence-event-id check.
    //
    // K-Validate-ZeroEv hardening (Session 22, 2026-05-23): previously
    // the empty-citation path was a silent bypass — claims with NO
    // `evidence_event_ids` short-circuited Ok(()) before the H1 check
    // could run. An attacker injecting a ProfileDelta with empty
    // evidence on every claim slipped past the validator entirely.
    //
    // Fixed semantics:
    //   - When the claim HAS citations: every cited id must be in the
    //     window AND at least one must be UserSpeech-eligible (H1).
    //   - When the claim has NO citations: the WINDOW itself must
    //     contain at least one UserSpeech-eligible segment. That's the
    //     "require_first_person_window" property that the prior
    //     comment claimed without enforcing. Without it, an empty-
    //     evidence claim could land against a window of pure
    //     ToolOutput / QuotedExternal segments — the exact privacy
    //     leak vector this check exists to close.
    if claim.evidence_event_ids.is_empty() {
        if user_speech_ids.is_empty() {
            return Err(ValidateError::NoFirstPersonProvenance);
        }
        return Ok(());
    }
    for ev in &claim.evidence_event_ids {
        if !window_ids.contains(ev) {
            return Err(ValidateError::UnknownEvidence(*ev));
        }
    }
    // H1: at least one cited event must be UserSpeech-eligible.
    if !claim
        .evidence_event_ids
        .iter()
        .any(|e| user_speech_ids.contains(e))
    {
        return Err(ValidateError::NoFirstPersonProvenance);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::types::{
        AttributedSegment, Attribution, ConversationSegment, SegmentOrigin,
    };

    fn att(event_id: i64, a: Attribution) -> AttributedSegment {
        AttributedSegment {
            segment: ConversationSegment {
                event_id,
                ts_ns: 0,
                origin: SegmentOrigin::OperatorInbound,
                text: format!("text {event_id}"),
            },
            attribution: a,
            confidence: 0.9,
            matched_signals: vec![],
        }
    }

    fn window() -> AttributedWindow {
        AttributedWindow {
            trigger_event_id: 100,
            segments: vec![
                att(10, Attribution::UserSpeech),
                att(11, Attribution::ToolOutput),
                att(12, Attribution::QuotedExternal),
            ],
        }
    }

    fn claim(field: &str, confidence: f32, evidence: Vec<i64>) -> RawClaim {
        RawClaim {
            field: field.into(),
            value_json: serde_json::json!("v"),
            confidence,
            reasoning: "".into(),
            evidence_event_ids: evidence,
        }
    }

    fn delta(claims: Vec<RawClaim>) -> ProfileDelta {
        ProfileDelta {
            extraction_id: "ext-1".into(),
            conversation_hash: "hash".into(),
            claims,
            ..Default::default()
        }
    }

    #[test]
    fn empty_extraction_id_returns_error() {
        let d = ProfileDelta {
            extraction_id: "".into(),
            conversation_hash: "hash".into(),
            ..Default::default()
        };
        let err = validate(d, &window()).unwrap_err();
        assert_eq!(err, ValidateError::EmptyExtractionId);
    }

    #[test]
    fn empty_conversation_hash_returns_error() {
        let d = ProfileDelta {
            extraction_id: "ext".into(),
            conversation_hash: "".into(),
            ..Default::default()
        };
        let err = validate(d, &window()).unwrap_err();
        assert_eq!(err, ValidateError::EmptyConversationHash);
    }

    #[test]
    fn confidence_out_of_range_drops_claim() {
        let d = delta(vec![claim("a.b", 1.5, vec![])]);
        let v = validate(d, &window()).unwrap();
        assert!(v.delta.claims.is_empty());
        assert_eq!(v.dropped.len(), 1);
        assert!(matches!(
            v.dropped[0].reason,
            ValidateError::ConfidenceOutOfRange(_)
        ));
    }

    #[test]
    fn nan_confidence_drops_claim() {
        let d = delta(vec![claim("a.b", f32::NAN, vec![])]);
        let v = validate(d, &window()).unwrap();
        assert_eq!(v.dropped.len(), 1);
    }

    #[test]
    fn empty_field_drops_claim() {
        let d = delta(vec![claim("", 0.5, vec![])]);
        let v = validate(d, &window()).unwrap();
        assert!(v.delta.claims.is_empty());
        assert_eq!(v.dropped[0].reason, ValidateError::EmptyField);
    }

    #[test]
    fn unknown_evidence_event_drops_claim() {
        let d = delta(vec![claim("identity.x", 0.7, vec![999])]);
        let v = validate(d, &window()).unwrap();
        assert!(v.delta.claims.is_empty());
        assert_eq!(v.dropped[0].reason, ValidateError::UnknownEvidence(999));
    }

    #[test]
    fn evidence_referencing_only_quoted_external_drops_claim() {
        // event_id 12 is QuotedExternal in the fixture window.
        let d = delta(vec![claim("identity.x", 0.7, vec![12])]);
        let v = validate(d, &window()).unwrap();
        assert!(v.delta.claims.is_empty());
        assert_eq!(v.dropped[0].reason, ValidateError::NoFirstPersonProvenance);
    }

    #[test]
    fn evidence_referencing_user_speech_keeps_claim() {
        // event_id 10 is UserSpeech.
        let d = delta(vec![claim("identity.x", 0.85, vec![10])]);
        let v = validate(d, &window()).unwrap();
        assert_eq!(v.delta.claims.len(), 1);
        assert!(v.dropped.is_empty());
    }

    #[test]
    fn claim_with_no_evidence_passes_when_window_has_user_speech() {
        // K-Validate-ZeroEv: evidence-less claims pass ONLY when the
        // window itself has at least one UserSpeech segment. The
        // `window()` fixture includes event_id=10 with `is_extraction_eligible()=true`,
        // so the window-level user-speech check passes.
        let d = delta(vec![claim("identity.x", 0.5, vec![])]);
        let v = validate(d, &window()).unwrap();
        assert_eq!(v.delta.claims.len(), 1);
        assert!(v.dropped.is_empty());
    }

    /// K-Validate-ZeroEv contract pin: an evidence-less claim against
    /// a window with ZERO UserSpeech segments MUST be dropped with
    /// `NoFirstPersonProvenance`. Closes the silent-bypass vector
    /// where the previous validator would accept the claim because
    /// the empty-evidence short-circuit skipped every H1 check.
    #[test]
    fn claim_with_no_evidence_drops_when_window_has_no_user_speech() {
        use crate::profile::types::Attribution;
        // Build a window where every segment is QuotedExternal (NOT
        // extraction-eligible) — mimics an attacker context with
        // pure tool-output / quoted-other-person content.
        let segments = vec![
            att(20, Attribution::QuotedExternal),
            att(21, Attribution::QuotedExternal),
        ];
        let win = AttributedWindow {
            trigger_event_id: 1,
            segments,
        };
        let d = delta(vec![claim("identity.x", 0.5, vec![])]);
        let v = validate(d, &win).unwrap();
        assert_eq!(
            v.delta.claims.len(),
            0,
            "must drop the bypass-attempt claim"
        );
        assert_eq!(v.dropped.len(), 1);
        assert!(
            matches!(v.dropped[0].reason, ValidateError::NoFirstPersonProvenance),
            "expected NoFirstPersonProvenance, got {:?}",
            v.dropped[0].reason,
        );
    }

    /// K-Validate-ZeroEv mass-bypass pin: even WITH the patch, a
    /// delta with N empty-evidence claims against a UserSpeech-free
    /// window must drop ALL N. Catches a partial-fix regression that
    /// would let SOME bypass claims through.
    #[test]
    fn many_empty_evidence_claims_all_dropped_when_window_unsafe() {
        use crate::profile::types::Attribution;
        let segments = vec![att(20, Attribution::QuotedExternal)];
        let win = AttributedWindow {
            trigger_event_id: 1,
            segments,
        };
        let d = delta(vec![
            claim("identity.a", 0.5, vec![]),
            claim("identity.b", 0.6, vec![]),
            claim("identity.c", 0.7, vec![]),
            claim("identity.d", 0.8, vec![]),
        ]);
        let v = validate(d, &win).unwrap();
        assert_eq!(v.delta.claims.len(), 0);
        assert_eq!(v.dropped.len(), 4);
        assert!(
            v.dropped
                .iter()
                .all(|d| matches!(d.reason, ValidateError::NoFirstPersonProvenance)),
            "every empty-evidence claim must drop with NoFirstPersonProvenance"
        );
    }

    #[test]
    fn mixed_claims_partition_correctly() {
        let d = delta(vec![
            claim("a.b", 0.5, vec![10]), // user_speech evidence — ok
            claim("a.c", 2.0, vec![10]), // bad confidence — drop
            claim("a.d", 0.5, vec![12]), // quoted evidence — drop
            claim("", 0.5, vec![]),      // empty field — drop
        ]);
        let v = validate(d, &window()).unwrap();
        assert_eq!(v.delta.claims.len(), 1);
        assert_eq!(v.delta.claims[0].field, "a.b");
        assert_eq!(v.dropped.len(), 3);
    }
}
