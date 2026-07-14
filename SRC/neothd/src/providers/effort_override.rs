//! GOLD-CCPARITY-EFFORT-03 — operator- and skill-selected reasoning budgets.
//!
//! `EffortBudget` is the serialized policy surface used by skills and chat
//! dispatch. `effort_to_tokens` resolves that policy to the exact provider
//! thinking-token budget before the request is authorized and dispatched.

/// One operator-facing effort budget. Mirrors the skill/chat policy
/// knob; ordered Low < Medium < High < Max for stable comparisons.
///
/// GOLD-CCPARITY-EFFORT-03: `Serialize`/`Deserialize` added so
/// `effort: high` in a skill's `skill.yaml` round-trips cleanly.
/// `serde(rename_all = "lowercase")` maps `Low` → `"low"`, etc.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum EffortBudget {
    Low,
    Medium,
    High,
    Max,
}

impl EffortBudget {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Max => "max",
        }
    }
}

/// GOLD-CCPARITY-EFFORT-03 — map an `EffortBudget` variant to a concrete
/// `MAX_THINKING_TOKENS` value. These are the pinned values from the tracker
/// spec; tests in this module assert them so a refactor can't drift silently.
///
/// | Variant | Tokens |
/// |---------|--------|
/// | Low     |  1 024 |
/// | Medium  |  4 096 |
/// | High    | 16 384 |
/// | Max     | 32 000 |
pub fn effort_to_tokens(b: EffortBudget) -> u32 {
    match b {
        EffortBudget::Low => 1_024,
        EffortBudget::Medium => 4_096,
        EffortBudget::High => 16_384,
        EffortBudget::Max => 32_000,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_as_str_pinned() {
        assert_eq!(EffortBudget::Low.as_str(), "low");
        assert_eq!(EffortBudget::Medium.as_str(), "medium");
        assert_eq!(EffortBudget::High.as_str(), "high");
        assert_eq!(EffortBudget::Max.as_str(), "max");
    }

    #[test]
    fn budget_ordering_explicit() {
        assert!(EffortBudget::Low < EffortBudget::Medium);
        assert!(EffortBudget::High < EffortBudget::Max);
    }

    // ── GOLD-CCPARITY-EFFORT-03: effort_to_tokens pinned ───────────────

    #[test]
    fn effort_low_maps_to_1024_tokens() {
        assert_eq!(effort_to_tokens(EffortBudget::Low), 1_024);
    }

    #[test]
    fn effort_medium_maps_to_4096_tokens() {
        assert_eq!(effort_to_tokens(EffortBudget::Medium), 4_096);
    }

    #[test]
    fn effort_high_maps_to_16384_tokens() {
        assert_eq!(effort_to_tokens(EffortBudget::High), 16_384);
    }

    #[test]
    fn effort_max_maps_to_32000_tokens() {
        assert_eq!(effort_to_tokens(EffortBudget::Max), 32_000);
    }

    // ── GOLD-CCPARITY-EFFORT-03: serde round-trip ──────────────────────

    #[test]
    fn effort_budget_serde_round_trip() {
        // Deserialise from the lowercase string that appears in skill.yaml.
        let high: EffortBudget = serde_json::from_str("\"high\"").unwrap();
        assert_eq!(high, EffortBudget::High);
        let low: EffortBudget = serde_json::from_str("\"low\"").unwrap();
        assert_eq!(low, EffortBudget::Low);
        let medium: EffortBudget = serde_json::from_str("\"medium\"").unwrap();
        assert_eq!(medium, EffortBudget::Medium);
        let max: EffortBudget = serde_json::from_str("\"max\"").unwrap();
        assert_eq!(max, EffortBudget::Max);
    }

    #[test]
    fn effort_budget_serialises_lowercase() {
        assert_eq!(
            serde_json::to_string(&EffortBudget::High).unwrap(),
            "\"high\""
        );
        assert_eq!(
            serde_json::to_string(&EffortBudget::Low).unwrap(),
            "\"low\""
        );
    }
}
