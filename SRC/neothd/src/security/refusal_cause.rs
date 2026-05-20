//! R-09 RefusalCause classifier — Phase 2 of the refusal-recovery
//! pipeline (per `PLAN/SPEC_refusal_recovery.md`).
//!
//! Orthogonal to [`crate::security::refusal_detect`]:
//!   - `refusal_detect::RefusalClass` answers **how** a refusal looks
//!     (hard / partial / soft / redirect / safety-warning).
//!   - `refusal_cause::RefusalCause` answers **why** the model
//!     refused (safety policy / capability gap / privacy / operator
//!     policy / unknown).
//!
//! Both classifiers run independently; the recovery pipeline (R-01
//! state machine) needs **both** signals to pick the right LOWKEY
//! reframing strategy:
//!
//!   ```text
//!   HardRefusal × SafetyPolicy   → reframe as research / hypothesis
//!   HardRefusal × CapabilityGap  → suggest tool-use or external lookup
//!   PartialRefusal × Privacy     → respect + offer scoped alternative
//!   SoftRefusal × OperatorPolicy → confirm the prior instruction
//!   * × Unknown                  → ask the operator for clarification
//!   ```
//!
//! Pure-deterministic. No LLM call, no meta-decision-making.
//! Framework v4.1 Anti-Pattern G.4 conformant.

/// Five orthogonal cause categories. `Unknown` is the fallback when no
/// pattern fires — the pipeline routes these to operator-clarification
/// rather than guessing a reframing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalCause {
    /// Provider-side safety guardrails (Anthropic, OpenAI, Google
    /// content policies). Cue phrases: "violates safety", "harmful
    /// content", "against my guidelines", "cannot provide harmful".
    SafetyPolicy,
    /// Model said it can't do something due to training cutoff,
    /// missing tool, or architectural limitation. Cue phrases:
    /// "I cannot browse", "I don't have access to", "outside my
    /// training data", "as of my knowledge cutoff", "I lack the
    /// capability to".
    CapabilityGap,
    /// Privacy / confidentiality boundary. Cue phrases: "personal
    /// information", "cannot share that", "private data", "would be
    /// a privacy violation", "respect confidentiality".
    Privacy,
    /// Operator-set policy (the operator earlier told the model not
    /// to do X). Cue phrases: "you said earlier", "your instructions
    /// were", "per your earlier message", "as you mentioned".
    /// Distinguishes the operator's OWN constraints from provider
    /// safety policy.
    OperatorPolicy,
    /// No cue pattern matched. The classifier deliberately bails
    /// rather than guessing — the recovery pipeline asks the
    /// operator for context instead of mis-reframing.
    Unknown,
}

impl RefusalCause {
    /// Snake-case wire name for WAL payloads + JSON output.
    pub fn as_str(&self) -> &'static str {
        match self {
            RefusalCause::SafetyPolicy => "safety_policy",
            RefusalCause::CapabilityGap => "capability_gap",
            RefusalCause::Privacy => "privacy",
            RefusalCause::OperatorPolicy => "operator_policy",
            RefusalCause::Unknown => "unknown",
        }
    }
}

/// Classification + matched patterns + confidence proxy. Returned
/// for the WAL `0x17 REFUSAL_CLASSIFIED` payload (band 0x17 reserved
/// in `wal/events.rs::EVENT_TYPE_REFUSAL_CLASSIFIED`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CauseReport {
    pub cause: RefusalCause,
    pub matched_patterns: Vec<String>,
    /// 0-100, deterministic from pattern weights. Lower than 30
    /// means the classifier saw weak signals — pipeline should
    /// surface a "low confidence" hint to the operator.
    pub confidence: u8,
}

impl CauseReport {
    pub fn unknown() -> Self {
        Self {
            cause: RefusalCause::Unknown,
            matched_patterns: Vec::new(),
            confidence: 0,
        }
    }
}

/// Safety-policy markers. Strong signals — Anthropic / OpenAI /
/// Google all phrase their content-policy refusals with these.
const SAFETY_PATTERNS: &[&str] = &[
    "violates safety",
    "violate safety",
    "against my guidelines",
    "against safety guidelines",
    "against my values",
    "harmful content",
    "harmful instructions",
    "promotes harm",
    "cannot provide harmful",
    "content policy",
    "usage policies",
    "safety policy",
    "verstoße gegen die richtlinien",
    "gegen meine richtlinien",
    "schädliche inhalte",
    "ethical guidelines",
    "moral guidelines",
];

/// Capability-gap markers. Model is telling the operator it CAN'T
/// (not won't) — missing tool, training cutoff, architectural limit.
const CAPABILITY_PATTERNS: &[&str] = &[
    "i cannot browse",
    "cannot access the internet",
    "don't have internet access",
    "do not have access to",
    "i don't have access",
    "outside my training",
    "beyond my training",
    "knowledge cutoff",
    "training cutoff",
    "as of my last update",
    "i lack the capability",
    "i'm not able to access",
    "real-time data",
    "live data",
    "i don't have the ability",
    "ich habe keinen zugriff",
    "außerhalb meines wissens",
];

/// Privacy / confidentiality markers.
const PRIVACY_PATTERNS: &[&str] = &[
    "personal information",
    "private information",
    "confidential information",
    "share personal",
    "share private",
    "privacy violation",
    "respect confidentiality",
    "confidentiality concerns",
    "data protection",
    "gdpr",
    "personenbezogene daten",
    "persönliche informationen",
    "datenschutz",
];

/// Operator-policy markers — references back to operator's own
/// earlier instructions. Distinguishes operator-set from provider-set
/// constraints.
const OPERATOR_PATTERNS: &[&str] = &[
    "you said earlier",
    "you mentioned earlier",
    "your instructions were",
    "per your earlier",
    "as you mentioned",
    "you previously told me",
    "you asked me to avoid",
    "you instructed me",
    "wie du sagtest",
    "wie du erwähnt hast",
    "deine anweisung war",
];

/// Score the response against each cause's pattern list. Pure
/// substring match (case-insensitive). The cause with the most
/// matches wins; ties break in the order Safety > Capability >
/// Privacy > Operator > Unknown (i.e. the SPEC §1.2 priority list).
pub fn classify_cause(response: &str) -> CauseReport {
    if response.trim().is_empty() {
        return CauseReport::unknown();
    }
    let lowered = response.to_ascii_lowercase();
    let mut safety_hits: Vec<String> = Vec::new();
    let mut capability_hits: Vec<String> = Vec::new();
    let mut privacy_hits: Vec<String> = Vec::new();
    let mut operator_hits: Vec<String> = Vec::new();

    for p in SAFETY_PATTERNS {
        if lowered.contains(p) {
            safety_hits.push((*p).to_string());
        }
    }
    for p in CAPABILITY_PATTERNS {
        if lowered.contains(p) {
            capability_hits.push((*p).to_string());
        }
    }
    for p in PRIVACY_PATTERNS {
        if lowered.contains(p) {
            privacy_hits.push((*p).to_string());
        }
    }
    for p in OPERATOR_PATTERNS {
        if lowered.contains(p) {
            operator_hits.push((*p).to_string());
        }
    }

    // Pick the cause with the highest hit count; SPEC §1.2 tie-break
    // order: Safety > Capability > Privacy > Operator.
    let counts = [
        (RefusalCause::SafetyPolicy, safety_hits.len()),
        (RefusalCause::CapabilityGap, capability_hits.len()),
        (RefusalCause::Privacy, privacy_hits.len()),
        (RefusalCause::OperatorPolicy, operator_hits.len()),
    ];
    let max_hits = counts.iter().map(|(_, n)| *n).max().unwrap_or(0);
    if max_hits == 0 {
        return CauseReport::unknown();
    }
    // First-priority cause with max_hits wins the tie-break.
    let (winning_cause, _) = counts
        .iter()
        .find(|(_, n)| *n == max_hits)
        .copied()
        .unwrap_or((RefusalCause::Unknown, 0));
    let matched_patterns = match winning_cause {
        RefusalCause::SafetyPolicy => safety_hits,
        RefusalCause::CapabilityGap => capability_hits,
        RefusalCause::Privacy => privacy_hits,
        RefusalCause::OperatorPolicy => operator_hits,
        RefusalCause::Unknown => Vec::new(),
    };
    // Confidence proxy: 40 + 15 per match, capped at 100. Single
    // hit = 55 (medium); two hits = 70 (strong); three+ = 85+
    // (high). The recovery pipeline (R-05 LOWKEY retry) uses
    // confidence ≥ 50 as the "auto-retry" threshold; lower
    // confidence routes to operator-clarification.
    let confidence = (40 + 15 * matched_patterns.len() as u8).min(100);
    CauseReport {
        cause: winning_cause,
        matched_patterns,
        confidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_response_is_unknown() {
        let r = classify_cause("");
        assert_eq!(r.cause, RefusalCause::Unknown);
        assert!(r.matched_patterns.is_empty());
        assert_eq!(r.confidence, 0);
    }

    #[test]
    fn safety_policy_caught_via_violates_safety() {
        let r = classify_cause("I can't help — this violates safety guidelines.");
        assert_eq!(r.cause, RefusalCause::SafetyPolicy);
        assert!(r.matched_patterns.iter().any(|p| p == "violates safety"));
        assert!(r.confidence >= 50);
    }

    #[test]
    fn capability_gap_caught_via_cannot_browse() {
        let r = classify_cause("I cannot browse the web for real-time data.");
        assert_eq!(r.cause, RefusalCause::CapabilityGap);
        assert!(r.matched_patterns.iter().any(|p| p == "i cannot browse"));
    }

    #[test]
    fn privacy_caught_via_personal_information() {
        let r = classify_cause(
            "I can't share that — it would expose personal information about a third party.",
        );
        assert_eq!(r.cause, RefusalCause::Privacy);
    }

    #[test]
    fn operator_policy_caught_via_you_said_earlier() {
        let r = classify_cause("You said earlier to avoid that topic, so I'll skip it.");
        assert_eq!(r.cause, RefusalCause::OperatorPolicy);
    }

    #[test]
    fn unknown_when_no_pattern_matches() {
        let r = classify_cause("Sure, here's the answer: 42.");
        assert_eq!(r.cause, RefusalCause::Unknown);
        assert_eq!(r.confidence, 0);
    }

    #[test]
    fn case_insensitive_match() {
        let r = classify_cause("VIOLATES SAFETY guidelines!");
        assert_eq!(r.cause, RefusalCause::SafetyPolicy);
    }

    #[test]
    fn german_patterns_recognised() {
        let r = classify_cause("Ich kann das nicht — verstoße gegen die richtlinien.");
        assert_eq!(r.cause, RefusalCause::SafetyPolicy);
        let r2 = classify_cause("Ich habe keinen zugriff auf das internet.");
        assert_eq!(r2.cause, RefusalCause::CapabilityGap);
    }

    #[test]
    fn tie_break_prioritises_safety_over_capability() {
        // One hit each → safety wins per SPEC §1.2 priority order.
        let r = classify_cause("harmful content noted — and I cannot browse to verify.");
        assert_eq!(r.cause, RefusalCause::SafetyPolicy);
    }

    #[test]
    fn multi_hit_in_one_category_raises_confidence() {
        let r =
            classify_cause("Against my guidelines — harmful content — content policy violation.");
        assert_eq!(r.cause, RefusalCause::SafetyPolicy);
        assert!(r.confidence >= 70, "got {}", r.confidence);
        assert!(r.matched_patterns.len() >= 2);
    }

    #[test]
    fn highest_hit_count_beats_priority_order() {
        // Two capability hits + one safety hit → capability wins
        // because max_hits=2 > max_hits=1.
        let r = classify_cause(
            "I don't have internet access. Real-time data is outside my training. \
             Also, this violates safety guidelines.",
        );
        assert_eq!(r.cause, RefusalCause::CapabilityGap);
        assert!(r.matched_patterns.len() >= 2);
    }

    #[test]
    fn as_str_round_trips_through_serde() {
        let causes = [
            RefusalCause::SafetyPolicy,
            RefusalCause::CapabilityGap,
            RefusalCause::Privacy,
            RefusalCause::OperatorPolicy,
            RefusalCause::Unknown,
        ];
        for c in causes {
            let serialized = serde_json::to_string(&c).unwrap();
            // Should be the snake_case wire name in quotes.
            assert!(
                serialized.contains(c.as_str()),
                "serde {serialized} does not contain {}",
                c.as_str()
            );
        }
    }

    #[test]
    fn confidence_caps_at_100() {
        // Build a response with 5+ safety hits to push toward the cap.
        let resp = "violates safety, against my guidelines, harmful content, \
                    content policy, safety policy, against my values, usage policies";
        let r = classify_cause(resp);
        assert!(r.confidence <= 100);
        assert!(r.confidence >= 85);
    }
}
