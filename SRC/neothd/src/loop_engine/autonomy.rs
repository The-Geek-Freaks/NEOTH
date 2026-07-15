//! GOLD-LOOP-04 — the named L1/L2/L3 loop-autonomy ladder.
//!
//! The loop-engineering source material names three loop levels; NEOTH's
//! engine already gates behaviour on [`AutonomyLevel`] (verifier judge at
//! Elevated+, refine pass at Elevated+). This module gives the operator the
//! named ladder as a CLI surface (`neoth loop run --level l1|l2|l3`) and
//! maps it onto the ONE autonomy enum the rest of the daemon speaks:
//!
//! | Level | Maps to    | Behaviour                                          |
//! |-------|------------|----------------------------------------------------|
//! | L1    | Standard   | no verifier gate, no refine — bounded iterate only |
//! | L2    | Elevated   | StopConditionVerifier judges + self-reflect refine |
//! | L3    | Full       | everything, and a tool-call budget is MANDATORY    |
//!
//! The L3-requires-budget rule is the safety inversion: the most autonomous
//! mode is the one that must carry a hard resource cap.

use crate::permissions::AutonomyLevel;

/// Named loop-autonomy level (see module doc for the mapping table).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoopAutonomyLevel {
    L1,
    L2,
    L3,
}

impl LoopAutonomyLevel {
    /// Parse the operator's `--level` argument. Accepts `l1`/`L1`/`1` forms.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "l1" | "1" => Some(Self::L1),
            "l2" | "2" => Some(Self::L2),
            "l3" | "3" => Some(Self::L3),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::L1 => "l1",
            Self::L2 => "l2",
            Self::L3 => "l3",
        }
    }

    /// The [`AutonomyLevel`] the engine actually gates on.
    pub fn to_autonomy_level(self) -> AutonomyLevel {
        match self {
            Self::L1 => AutonomyLevel::Standard,
            Self::L2 => AutonomyLevel::Elevated,
            Self::L3 => AutonomyLevel::Full,
        }
    }

    /// L3 refuses to run uncapped (GOLD-LOOP-05 gate).
    pub fn requires_budget(self) -> bool {
        matches!(self, Self::L3)
    }

    /// Validate the level/budget pairing BEFORE the loop starts — the gate
    /// belongs at argument time, not round N.
    pub fn validate_budget(self, tool_call_budget: Option<u64>) -> Result<(), String> {
        if self.requires_budget() && tool_call_budget.is_none_or(|budget| budget == 0) {
            return Err(
                "loop level l3 (full autonomy) requires --budget <N> — the most \
                 autonomous mode must carry a hard tool-call cap"
                    .to_string(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_all_operator_spellings() {
        for (input, want) in [
            ("l1", LoopAutonomyLevel::L1),
            ("L2", LoopAutonomyLevel::L2),
            ("3", LoopAutonomyLevel::L3),
            (" l3 ", LoopAutonomyLevel::L3),
        ] {
            assert_eq!(LoopAutonomyLevel::parse(input), Some(want), "{input}");
        }
        assert_eq!(LoopAutonomyLevel::parse("l4"), None);
        assert_eq!(LoopAutonomyLevel::parse(""), None);
    }

    #[test]
    fn ladder_maps_per_spec() {
        assert_eq!(
            LoopAutonomyLevel::L1.to_autonomy_level(),
            AutonomyLevel::Standard
        );
        assert_eq!(
            LoopAutonomyLevel::L2.to_autonomy_level(),
            AutonomyLevel::Elevated
        );
        assert_eq!(
            LoopAutonomyLevel::L3.to_autonomy_level(),
            AutonomyLevel::Full
        );
    }

    #[test]
    fn l3_without_budget_is_refused() {
        assert!(LoopAutonomyLevel::L3.validate_budget(None).is_err());
        assert!(LoopAutonomyLevel::L3.validate_budget(Some(0)).is_err());
        assert!(LoopAutonomyLevel::L3.validate_budget(Some(50)).is_ok());
        assert!(LoopAutonomyLevel::L1.validate_budget(None).is_ok());
        assert!(LoopAutonomyLevel::L2.validate_budget(None).is_ok());
    }
}
