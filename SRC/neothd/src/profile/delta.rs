//! `ProfileDelta` / `RawClaim` typed structs — the contract the extractor
//! LLM (stage 3 of `profile_learn.yaml`) produces and the validator
//! (stage 4) + claim guard (stage 5) consume.
//!
//! This module owns the wire schema. Stage 3 (`profile.extract`) emits
//! JSON matching `ProfileDelta`; stage 4 deserialises + schema-checks it;
//! stage 5 runs the H1/H2/H5/M1/M2 guards; stage 6 applies it as a
//! Hypothalamus WAL event. None of those downstream stages exist yet —
//! shipping the types first locks the contract so when each stage lands
//! it just plugs in.

use serde::{Deserialize, Serialize};

/// Field path the claim asserts against, e.g. `identity.name`,
/// `preferences.food`, `skills.rust`. Dot-segmented; first segment is
/// the top-level category (`identity` / `preferences` / `skills` /
/// `goals` / `health` / `schedule` / `emotional_baseline` /
/// `operator_preferences` / `relationships`). Novel categories must be
/// registered in the operator's `typed_extension_registry` or be
/// rejected by stage 5 (M2 fix).
pub type FieldPath = String;

/// Confidence in the [0.0..=1.0] range. Out-of-band values are
/// rejected by the validator.
pub type Confidence = f32;

/// One claim the LLM extracted. `value_json` carries the operator-fact
/// payload (string for identity.name, struct for relationships, …).
/// `reasoning` is the LLM's free-text explanation — the validator uses
/// it for provenance matching (which conversation segment did this
/// claim come from?).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RawClaim {
    pub field: FieldPath,
    /// Value payload — opaque to the validator at this level, schema-
    /// shaped by the field path.
    pub value_json: serde_json::Value,
    pub confidence: Confidence,
    /// Free-text reasoning the LLM produced. The validator looks for
    /// substrings from this in the attributed window's user-speech
    /// segments to enforce the H1 provenance rule.
    #[serde(default)]
    pub reasoning: String,
    /// Optional citation pointing the validator at a specific segment
    /// by event_id. Stronger evidence than reasoning-substring match
    /// because it eliminates ambiguity when multiple segments look
    /// similar.
    #[serde(default)]
    pub evidence_event_ids: Vec<i64>,
}

/// Detected contradiction with an existing profile claim. The extractor
/// surfaces these so the apply stage can mark the old claim
/// `SUPERSEDED` rather than just appending a new one.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Contradiction {
    pub field: FieldPath,
    /// Brief explanation suitable for an audit row.
    pub note: String,
    /// Event id of the existing claim being contradicted, when the
    /// extractor knows it.
    #[serde(default)]
    pub existing_event_id: Option<i64>,
}

/// What the extractor LLM emits in one batch. Stage 4 deserialises this
/// from the LLM's JSON output and gates it.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ProfileDelta {
    /// Stable id for this extraction pass. Used for idempotency on the
    /// `profile.apply` Effect Adapter (spec §profile_apply).
    pub extraction_id: String,
    /// Hash of the conversation window the extractor saw. Stage 5's
    /// `blocked_delta_hash` echoes this when it rejects.
    pub conversation_hash: String,
    /// Every claim the LLM derived. Empty is valid (no extractable
    /// facts) — `primary_kpi_threshold: 0` in the spec.
    pub claims: Vec<RawClaim>,
    /// Detected contradictions with existing profile state.
    #[serde(default)]
    pub contradictions: Vec<Contradiction>,
    /// Behavioral-style embedding (per-turn). Phase-3 parity substrate.
    /// `None` until the embedder is wired into stage 5.
    #[serde(default)]
    pub style_embedding: Option<Vec<f32>>,
    /// Version of the guard that produced this delta. Stamped by stage
    /// 5 so audit can track which guard ruleset gated it. Empty when
    /// the delta hasn't passed the guard yet.
    #[serde(default)]
    pub guard_version: String,
}

impl ProfileDelta {
    /// Number of distinct fields claimed. Useful for the primary KPI.
    pub fn claim_count(&self) -> usize {
        self.claims.len()
    }

    /// Returns true iff no claims were extracted. The spec says this is
    /// valid — recall windows often have no extractable user facts.
    pub fn is_empty(&self) -> bool {
        self.claims.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delta_serde_roundtrip_preserves_every_field() {
        let d = ProfileDelta {
            extraction_id: "ext-1".into(),
            conversation_hash: "abc123".into(),
            claims: vec![RawClaim {
                field: "identity.location".into(),
                value_json: serde_json::json!("Berlin"),
                confidence: 0.85,
                reasoning: "Alex said he works in Berlin".into(),
                evidence_event_ids: vec![100, 102],
            }],
            contradictions: vec![Contradiction {
                field: "identity.location".into(),
                note: "previously claimed Hamburg".into(),
                existing_event_id: Some(50),
            }],
            style_embedding: Some(vec![0.1, 0.2, 0.3]),
            guard_version: "0.1.0".into(),
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: ProfileDelta = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn raw_claim_with_minimal_fields_deserialises() {
        let json = r#"{
            "field": "skills.rust",
            "value_json": true,
            "confidence": 0.9
        }"#;
        let c: RawClaim = serde_json::from_str(json).unwrap();
        assert_eq!(c.field, "skills.rust");
        assert_eq!(c.confidence, 0.9);
        // Defaults applied
        assert_eq!(c.reasoning, "");
        assert!(c.evidence_event_ids.is_empty());
    }

    #[test]
    fn delta_is_empty_when_no_claims() {
        let d = ProfileDelta::default();
        assert!(d.is_empty());
        assert_eq!(d.claim_count(), 0);
    }

    #[test]
    fn delta_claim_count_matches_vec_len() {
        let d = ProfileDelta {
            claims: vec![
                RawClaim {
                    field: "a.b".into(),
                    value_json: serde_json::json!(1),
                    confidence: 0.5,
                    reasoning: "".into(),
                    evidence_event_ids: vec![],
                },
                RawClaim {
                    field: "a.c".into(),
                    value_json: serde_json::json!(2),
                    confidence: 0.5,
                    reasoning: "".into(),
                    evidence_event_ids: vec![],
                },
            ],
            ..Default::default()
        };
        assert_eq!(d.claim_count(), 2);
    }
}
