//! Mirror-refusal classifier — Schicht-0 from `PLAN/SPEC_mirror_refusal.md`.
//!
//! Pure-deterministic refusal classifier. NO LLM call, NO meta-decision-
//! making. Returns one of six `RefusalClass` variants based on regex +
//! keyword + length-ratio analysis of the assistant's response.
//!
//! Operator workflow:
//!   - Daemon emits `0x16 REFUSAL_OBSERVED` whenever this classifier
//!     returns anything other than `None`.
//!   - The mirror-refusal pipeline (Phase 2) consumes that event +
//!     dispatches the appropriate `TMPL_*` reply template.
//!
//! Why pure deterministic: Framework v4.1 Anti-Pattern G.4 forbids
//! classifier tools from making meta-decisions. This module's only
//! job is to classify; selecting the response template is the
//! pipeline's concern.

/// Six refusal categories. `None` is the "no refusal detected" case
/// — emitted from the classifier so downstream consumers can route
/// uniformly without a separate "did we even classify?" check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalClass {
    None,
    HardRefusal,
    PartialRefusal,
    SoftRefusal,
    RedirectSuggestion,
    SafetyWarning,
}

impl RefusalClass {
    /// Snake-case wire name used in WAL payloads + the YAML spec.
    pub fn as_str(&self) -> &'static str {
        match self {
            RefusalClass::None => "none",
            RefusalClass::HardRefusal => "hard_refusal",
            RefusalClass::PartialRefusal => "partial_refusal",
            RefusalClass::SoftRefusal => "soft_refusal",
            RefusalClass::RedirectSuggestion => "redirect_suggestion",
            RefusalClass::SafetyWarning => "safety_warning",
        }
    }
}

/// Classification + matched patterns + confidence proxy. Returned
/// for the WAL `0x16 REFUSAL_OBSERVED` payload.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RefusalReport {
    pub class: RefusalClass,
    pub matched_patterns: Vec<String>,
    pub confidence: u8, // 0-100, deterministic from pattern weights
}

impl RefusalReport {
    pub fn none() -> Self {
        Self {
            class: RefusalClass::None,
            matched_patterns: Vec::new(),
            confidence: 0,
        }
    }
    pub fn is_refusal(&self) -> bool {
        !matches!(self.class, RefusalClass::None)
    }
}

/// Hard-refusal patterns (weight 0.9-1.0). One of these matched →
/// `HardRefusal` unless soft + redirect patterns also matched.
const HARD_PATTERNS: &[&str] = &[
    "i cannot",
    "i'm unable to",
    "i am unable to",
    "i won't",
    "i will not",
    "kann ich nicht",
    "ich bin nicht in der lage",
    "verstoße gegen",
    "ist nicht möglich",
    "i refuse",
    "ich weigere mich",
];

/// Soft-refusal patterns (hedging, partial compliance).
const SOFT_PATTERNS: &[&str] = &[
    "i'd rather not",
    "i would prefer not",
    "i'm hesitant to",
    "ich würde lieber nicht",
    "i'm not comfortable",
    "ich bin nicht überzeugt",
];

/// Redirect patterns — refusal + alternative offered.
const REDIRECT_PATTERNS: &[&str] = &[
    "however, i can",
    "instead, i can",
    "but i can",
    "stattdessen kann ich",
    "ich könnte stattdessen",
    "what i can do is",
];

/// Safety-warning patterns — output produced + safety addendum.
const SAFETY_PATTERNS: &[&str] = &[
    "please note that",
    "be careful when",
    "this is potentially",
    "be advised that",
    "bitte beachte dass",
    "achtung:",
    "warning:",
    "this could be dangerous",
];

/// Read-only view of every static pattern dictionary the classifier
/// uses. Operator-facing tools (`neoth refusal patterns`) expose these
/// so the operator can see exactly which strings fire each class.
/// Order matches the spec's per-class introduction order.
pub fn pattern_dictionaries() -> (
    &'static [&'static str],
    &'static [&'static str],
    &'static [&'static str],
    &'static [&'static str],
) {
    (
        HARD_PATTERNS,
        SOFT_PATTERNS,
        REDIRECT_PATTERNS,
        SAFETY_PATTERNS,
    )
}

/// Classify the assistant's response text.
///
/// Algorithm (deterministic, no LLM):
///   1. Lowercase the input + the patterns; substring search each.
///   2. Compute counts per category.
///   3. Priority resolution per spec §1:
///      - hard pattern present + no redirect → HardRefusal
///      - hard + soft both present → PartialRefusal
///      - redirect pattern (with or without hard) → RedirectSuggestion
///      - soft pattern only → SoftRefusal
///      - safety pattern only (no refusal pattern) → SafetyWarning
///      - nothing matched → None
///   4. Confidence = clamp((hard_count*100 + soft_count*60 + redirect_count*70 + safety_count*40), 0..100)
pub fn classify(response: &str) -> RefusalReport {
    let lowered = response.to_lowercase();
    let mut matched: Vec<String> = Vec::new();

    let hard: Vec<&&str> = HARD_PATTERNS
        .iter()
        .filter(|p| lowered.contains(**p))
        .collect();
    let soft: Vec<&&str> = SOFT_PATTERNS
        .iter()
        .filter(|p| lowered.contains(**p))
        .collect();
    let redirect: Vec<&&str> = REDIRECT_PATTERNS
        .iter()
        .filter(|p| lowered.contains(**p))
        .collect();
    let safety: Vec<&&str> = SAFETY_PATTERNS
        .iter()
        .filter(|p| lowered.contains(**p))
        .collect();

    matched.extend(hard.iter().map(|s| (**s).to_string()));
    matched.extend(soft.iter().map(|s| (**s).to_string()));
    matched.extend(redirect.iter().map(|s| (**s).to_string()));
    matched.extend(safety.iter().map(|s| (**s).to_string()));

    let confidence_raw =
        hard.len() * 100 + soft.len() * 60 + redirect.len() * 70 + safety.len() * 40;
    let confidence = confidence_raw.min(100) as u8;

    let class = if !redirect.is_empty() && (!hard.is_empty() || !soft.is_empty()) {
        // Refusal + alternative offered.
        RefusalClass::RedirectSuggestion
    } else if !redirect.is_empty() {
        // Operator-friendly redirect without a hard refusal upstream
        // is still a soft refusal in spirit.
        RefusalClass::RedirectSuggestion
    } else if !hard.is_empty() && !soft.is_empty() {
        RefusalClass::PartialRefusal
    } else if !hard.is_empty() {
        RefusalClass::HardRefusal
    } else if !soft.is_empty() {
        RefusalClass::SoftRefusal
    } else if !safety.is_empty() {
        RefusalClass::SafetyWarning
    } else {
        RefusalClass::None
    };

    RefusalReport {
        class,
        matched_patterns: matched,
        confidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_clean_response_is_none() {
        let r = classify("Sure, here's the answer: 4");
        assert_eq!(r.class, RefusalClass::None);
        assert!(!r.is_refusal());
        assert!(r.matched_patterns.is_empty());
    }

    #[test]
    fn classify_hard_refusal_english() {
        let r = classify("I cannot help with that request.");
        assert_eq!(r.class, RefusalClass::HardRefusal);
        assert!(r.is_refusal());
        assert!(r.confidence >= 80);
    }

    #[test]
    fn classify_hard_refusal_german() {
        let r = classify("Das kann ich nicht tun, das verstoße gegen die Richtlinien.");
        assert_eq!(r.class, RefusalClass::HardRefusal);
    }

    #[test]
    fn classify_partial_refusal_hard_plus_soft() {
        let r = classify("I cannot do the first part, and I'd rather not attempt the second.");
        assert_eq!(r.class, RefusalClass::PartialRefusal);
    }

    #[test]
    fn classify_redirect_suggestion_offers_alternative() {
        let r = classify("I cannot fetch that URL directly, however, I can summarise it.");
        assert_eq!(r.class, RefusalClass::RedirectSuggestion);
    }

    #[test]
    fn classify_soft_refusal_hedging_only() {
        let r = classify("I'd rather not get into that topic too deeply.");
        assert_eq!(r.class, RefusalClass::SoftRefusal);
    }

    #[test]
    fn classify_safety_warning_with_content() {
        let r = classify(
            "Here's how the system works. Please note that this is potentially \
             a sensitive operation in production.",
        );
        assert_eq!(r.class, RefusalClass::SafetyWarning);
    }

    #[test]
    fn classify_confidence_clamps_at_100() {
        let r = classify("I cannot, I will not, I refuse, ich weigere mich, kann ich nicht.");
        assert_eq!(r.confidence, 100);
    }

    #[test]
    fn classify_round_trips_via_serde() {
        let r = classify("I cannot help");
        let s = serde_json::to_string(&r).expect("serialize");
        assert!(s.contains("\"hard_refusal\""));
        let r2: RefusalReport = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(r, r2);
    }

    #[test]
    fn refusal_class_as_str_matches_spec_wire_names() {
        assert_eq!(RefusalClass::None.as_str(), "none");
        assert_eq!(RefusalClass::HardRefusal.as_str(), "hard_refusal");
        assert_eq!(RefusalClass::PartialRefusal.as_str(), "partial_refusal");
        assert_eq!(RefusalClass::SoftRefusal.as_str(), "soft_refusal");
        assert_eq!(
            RefusalClass::RedirectSuggestion.as_str(),
            "redirect_suggestion"
        );
        assert_eq!(RefusalClass::SafetyWarning.as_str(), "safety_warning");
    }
}
