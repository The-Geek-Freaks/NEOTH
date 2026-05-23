//! B-6 Item 4f — error-pattern effort-override.
//!
//! bridge.py monitors model responses for refusal / soft-fail phrases
//! ("I can't help with that", "I'm not able to") and, on the next
//! retry, downgrades the effort budget so the operator stops paying
//! premium-tier tokens for an answer the model isn't going to give.
//!
//! This module ports the detection + override surface as a pure
//! pipeline:
//!   1. `RefusalPattern` enum — distinct categories so operator-
//!      facing diagnostics can show "rate-limit refusal" vs
//!      "policy refusal" vs "ambiguity bailout".
//!   2. `detect_refusal(text)` scans response text + classifies.
//!   3. `EffortBudget` newtype mirrors the operator-facing
//!      effort knob (`low` / `medium` / `high` / `max`).
//!   4. `override_effort(current, pattern)` decides whether to
//!      downgrade + by how much.
//!
//! Wiring (deferred): the council router consults `detect_refusal`
//! on each completion + tags the operator's next message with the
//! downgraded budget. v0.2 lands the wire-up; this commit ships the
//! detection surface + the override policy.

/// Distinct categories of model refusals. Pinned exhaustively —
/// adding a new category needs an `override_effort` policy entry +
/// a test pin so we never silently route a known refusal to the
/// fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RefusalPattern {
    /// Hard policy refusal — "I cannot help with that".
    /// Downgrade hard: max → low so the operator pays for the
    /// rephrase, not the premium-tier debate.
    Policy,
    /// Soft ambiguity — "I'm not sure I understand your question".
    /// Keep tier but flag for clarifying-question routing.
    Ambiguity,
    /// Provider-side capacity error — "system is currently
    /// overloaded". Drop one tier; transient.
    Capacity,
    /// No refusal detected.
    None,
}

impl RefusalPattern {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Ambiguity => "ambiguity",
            Self::Capacity => "capacity",
            Self::None => "none",
        }
    }
}

/// One operator-facing effort budget. Mirrors the freedom.yaml
/// knob; ordered Low < Medium < High < Max so downgrade math
/// stays explicit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

    /// Step down by one tier; saturates at Low.
    pub fn step_down(self) -> Self {
        match self {
            Self::Max => Self::High,
            Self::High => Self::Medium,
            Self::Medium => Self::Low,
            Self::Low => Self::Low,
        }
    }
}

/// Phrase fragments that signal a hard policy refusal. Match is
/// case-insensitive substring — operator-visible signal so a future
/// rephrase by the model carries forward via test maintenance.
const POLICY_REFUSAL_FRAGMENTS: &[&str] = &[
    "i cannot help",
    "i can't help with that",
    "i'm unable to assist",
    "i am not able to help",
    "i won't provide",
    "against my guidelines",
    "violates my policies",
];

/// Phrase fragments that signal soft ambiguity bailout — model
/// didn't understand the question well enough to commit.
const AMBIGUITY_FRAGMENTS: &[&str] = &[
    "i'm not sure i understand",
    "could you clarify",
    "i'm not certain what you mean",
    "ambiguous request",
];

/// Phrase fragments that signal provider-side capacity issues.
const CAPACITY_FRAGMENTS: &[&str] = &[
    "currently overloaded",
    "service is busy",
    "try again later",
    "rate limit exceeded",
    "capacity exceeded",
];

/// Scan `text` for known refusal patterns. Priority order (most
/// specific first): Policy → Ambiguity → Capacity → None.
pub fn detect_refusal(text: &str) -> RefusalPattern {
    let lower = text.to_lowercase();
    if POLICY_REFUSAL_FRAGMENTS.iter().any(|p| lower.contains(p)) {
        return RefusalPattern::Policy;
    }
    if AMBIGUITY_FRAGMENTS.iter().any(|p| lower.contains(p)) {
        return RefusalPattern::Ambiguity;
    }
    if CAPACITY_FRAGMENTS.iter().any(|p| lower.contains(p)) {
        return RefusalPattern::Capacity;
    }
    RefusalPattern::None
}

/// Decide the next-call effort budget given the current budget +
/// observed refusal pattern. Pinned per-pattern:
///   - Policy   → step down two tiers (Max → Medium, High → Low).
///     Operator pays cheap-tier tokens for the rephrase prompt.
///   - Ambiguity → no change (rephrase needs same depth, model
///     wasn't refusing capability-wise).
///   - Capacity → step down one tier (drains rate-limit window
///     more cheaply).
///   - None     → no change.
pub fn override_effort(current: EffortBudget, pattern: RefusalPattern) -> EffortBudget {
    match pattern {
        RefusalPattern::Policy => current.step_down().step_down(),
        RefusalPattern::Ambiguity => current,
        RefusalPattern::Capacity => current.step_down(),
        RefusalPattern::None => current,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── detect_refusal ──────────────────────────────────────────

    #[test]
    fn detect_policy_refusal() {
        let p = detect_refusal("I cannot help with that request.");
        assert_eq!(p, RefusalPattern::Policy);
    }

    #[test]
    fn detect_policy_case_insensitive() {
        let p = detect_refusal("AGAINST MY GUIDELINES, this is not allowed.");
        assert_eq!(p, RefusalPattern::Policy);
    }

    #[test]
    fn detect_ambiguity() {
        let p = detect_refusal("I'm not sure I understand what you're asking.");
        assert_eq!(p, RefusalPattern::Ambiguity);
    }

    #[test]
    fn detect_capacity() {
        let p = detect_refusal("Service is currently overloaded — try again later.");
        assert_eq!(p, RefusalPattern::Capacity);
    }

    #[test]
    fn detect_none_on_normal_response() {
        let p = detect_refusal("Here is the answer: 42.");
        assert_eq!(p, RefusalPattern::None);
    }

    #[test]
    fn policy_takes_priority_over_capacity_signals() {
        // A response that says BOTH "I cannot help" + "try again
        // later" classifies as Policy — the policy refusal is the
        // operator-actionable signal.
        let p = detect_refusal("I cannot help with that; please try again later.");
        assert_eq!(p, RefusalPattern::Policy);
    }

    // ── EffortBudget step_down ──────────────────────────────────

    #[test]
    fn step_down_walks_tiers() {
        assert_eq!(EffortBudget::Max.step_down(), EffortBudget::High);
        assert_eq!(EffortBudget::High.step_down(), EffortBudget::Medium);
        assert_eq!(EffortBudget::Medium.step_down(), EffortBudget::Low);
    }

    #[test]
    fn step_down_saturates_at_low() {
        assert_eq!(EffortBudget::Low.step_down(), EffortBudget::Low);
    }

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

    // ── override_effort policy ──────────────────────────────────

    #[test]
    fn policy_refusal_downgrades_two_tiers() {
        let next = override_effort(EffortBudget::Max, RefusalPattern::Policy);
        assert_eq!(next, EffortBudget::Medium);
        let next = override_effort(EffortBudget::High, RefusalPattern::Policy);
        assert_eq!(next, EffortBudget::Low);
    }

    #[test]
    fn ambiguity_does_not_change_budget() {
        for b in [
            EffortBudget::Low,
            EffortBudget::Medium,
            EffortBudget::High,
            EffortBudget::Max,
        ] {
            assert_eq!(override_effort(b, RefusalPattern::Ambiguity), b);
        }
    }

    #[test]
    fn capacity_downgrades_one_tier() {
        let next = override_effort(EffortBudget::High, RefusalPattern::Capacity);
        assert_eq!(next, EffortBudget::Medium);
    }

    #[test]
    fn no_refusal_preserves_budget() {
        for b in [
            EffortBudget::Low,
            EffortBudget::Medium,
            EffortBudget::High,
            EffortBudget::Max,
        ] {
            assert_eq!(override_effort(b, RefusalPattern::None), b);
        }
    }

    #[test]
    fn policy_at_low_stays_at_low() {
        // Operator already at minimum spend; step_down saturates.
        let next = override_effort(EffortBudget::Low, RefusalPattern::Policy);
        assert_eq!(next, EffortBudget::Low);
    }

    #[test]
    fn refusal_pattern_as_str_pinned() {
        assert_eq!(RefusalPattern::Policy.as_str(), "policy");
        assert_eq!(RefusalPattern::Ambiguity.as_str(), "ambiguity");
        assert_eq!(RefusalPattern::Capacity.as_str(), "capacity");
        assert_eq!(RefusalPattern::None.as_str(), "none");
    }
}
