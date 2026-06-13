//! GOLD-ADAPT-LOWKEY-02/03 — N-Space anti-pattern penalty.
//!
//! Scans a council response for the LOWKEY "Negative Space" anti-patterns —
//! performative apologies, hedging/padding, tone-policing, fake empathy,
//! assistant-theater, and safety-moralizing — and returns a penalty the
//! quality scorer subtracts from a response's dynamic-signal component. This
//! is the OUTPUT-side enforcement of the operator's "too strict / mealy-mouthed
//! output" complaint (the prompt-side counterpart is the operator's
//! `anti_hedging` moral-core directives, already injected at position-0).
//!
//! Purely about output STYLE/directness/honesty — NOT capability. An honest
//! `"I can't X"` limitation is deliberately NOT penalized here (it is handled,
//! appropriately, by the existing refusal markers in the quality scorer); only
//! the performative *wrapper* around it (`"I cannot and will not"`,
//! `"I must decline"`) is penalized. Self-contained: the catalog ships in-repo
//! (the operator can extend it via `~/.neoth/moral_core/anti_hedging.md`); there
//! is NO external URL fetch (NEOTH self-contained rule — the LOWKEY `N-Space.md`
//! reference to a GitHub anti-pattern list is intentionally NOT followed).

use serde::{Deserialize, Serialize};

/// `(group_label, patterns, penalty_per_group)`. The penalty is applied ONCE
/// per group that matches (not per individual pattern) so a response that
/// legitimately uses one phrase while discussing it is not stacked into the
/// floor.
pub const NSPACE_GROUPS: &[(&str, &[&str], f32)] = &[
    ("performative_apology", PATTERNS_APOLOGY, 0.15),
    ("hedging", PATTERNS_HEDGING, 0.10),
    ("tone_policing", PATTERNS_TONE_POLICING, 0.12),
    ("fake_empathy", PATTERNS_FAKE_EMPATHY, 0.10),
    ("assistant_theater", PATTERNS_ASSISTANT_THEATER, 0.15),
    ("safety_moralizing", PATTERNS_SAFETY_MORALIZING, 0.12),
];

/// Total-penalty ceiling. Even if all six groups match, the penalty stays ≤
/// this so one hedge does not zero-out a long, informative answer. Kept below
/// the scorer's refusal penalty (hedging is less severe than refusing).
pub const NSPACE_PENALTY_CAP: f32 = 0.50;

/// Flat penalty per operator-extension match (one, regardless of count).
const OPERATOR_EXTENSION_PENALTY: f32 = 0.10;

/// One matched group.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NSpaceGroupHit {
    pub group: String,
    pub matched_pattern: String,
    pub penalty: f32,
}

/// Aggregate scan result.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct NSpacePenalty {
    pub hits: Vec<NSpaceGroupHit>,
    /// Sum of per-group penalties, capped at [`NSPACE_PENALTY_CAP`].
    pub total_penalty: f32,
}

impl NSpacePenalty {
    pub fn is_clean(&self) -> bool {
        self.hits.is_empty()
    }
    /// Snake-case group labels that fired (for the WAL payload).
    pub fn groups_hit(&self) -> Vec<String> {
        self.hits.iter().map(|h| h.group.clone()).collect()
    }
}

/// Scan `text` for the built-in anti-pattern groups plus optional
/// operator-authored `extra_patterns` (from `anti_hedging.md`). One penalty per
/// matching group; one flat penalty if any operator-extension matches.
pub fn scan_nspace(text: &str, extra_patterns: &[String]) -> NSpacePenalty {
    let lower = text.to_ascii_lowercase();
    let mut hits = Vec::new();
    let mut total = 0.0_f32;

    for &(group, patterns, penalty) in NSPACE_GROUPS {
        if let Some(pattern) = patterns.iter().find(|&&p| lower.contains(p)) {
            hits.push(NSpaceGroupHit {
                group: group.to_string(),
                matched_pattern: (*pattern).to_string(),
                penalty,
            });
            total += penalty;
        }
    }

    if let Some(p) = extra_patterns
        .iter()
        .find(|p| !p.is_empty() && lower.contains(p.as_str()))
    {
        hits.push(NSpaceGroupHit {
            group: "operator_extension".to_string(),
            matched_pattern: p.clone(),
            penalty: OPERATOR_EXTENSION_PENALTY,
        });
        total += OPERATOR_EXTENSION_PENALTY;
    }

    NSpacePenalty {
        hits,
        total_penalty: total.min(NSPACE_PENALTY_CAP),
    }
}

// ── Pattern tables ──────────────────────────────────────────────────────────

const PATTERNS_APOLOGY: &[&str] = &[
    "i apologize", "i'm sorry", "i am sorry", "sorry for", "sorry about",
    "i apologise", "my apologies", "pardon me", "excuse me for", "forgive me",
    "entschuldige", "entschuldigung", "es tut mir leid",
];

const PATTERNS_HEDGING: &[&str] = &[
    "it might be", "it may be", "it could be", "i'm not sure but",
    "i'm not entirely sure", "generally speaking", "in most cases",
    "it's worth noting that", "it is worth noting", "keep in mind that",
    "it's important to keep in mind", "please note that", "please be aware",
];

const PATTERNS_TONE_POLICING: &[&str] = &[
    "let's keep things civil", "let's stay respectful", "i'd encourage you to",
    "i'd gently suggest", "i'd like to remind you", "please be mindful",
    "i understand your frustration, but", "bitte bleib höflich", "bleib respektvoll",
];

const PATTERNS_FAKE_EMPATHY: &[&str] = &[
    "i understand how you feel", "i can understand your frustration",
    "i understand that this can be", "i know this is difficult",
    "i can imagine how", "that must be frustrating", "i hear you",
    "ich verstehe deine frustration", "das muss schwierig sein",
];

const PATTERNS_ASSISTANT_THEATER: &[&str] = &[
    "as an ai", "as an ai assistant", "as a language model", "i'm just an ai",
    "i am just an ai", "as your assistant", "my purpose is to", "i'm designed to",
    "i was trained to", "it's important for me to clarify",
    "i need to be transparent", "i want to be clear that i am",
];

const PATTERNS_SAFETY_MORALIZING: &[&str] = &[
    "i must note that", "i should mention that", "i want to make sure you're aware",
    "please consider the ethical", "there are ethical considerations",
    "i cannot and will not", "i must decline", "i must emphasize",
    "i strongly advise", "proceed with caution", "please be careful",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apology_group_fires() {
        let r = scan_nspace("I apologize for any confusion.", &[]);
        assert!(r.total_penalty > 0.0);
        assert!(r.hits.iter().any(|h| h.group == "performative_apology"));
    }

    #[test]
    fn bare_honest_limit_is_not_penalized() {
        // "I can't X" is handled by the scorer's refusal markers, not here.
        let r = scan_nspace("I can't access the internet.", &[]);
        assert_eq!(r.total_penalty, 0.0);
        assert!(r.is_clean());
    }

    #[test]
    fn moralizing_wrapper_is_penalized() {
        let r = scan_nspace("I cannot and will not help with that.", &[]);
        assert!(r.hits.iter().any(|h| h.group == "safety_moralizing"));
    }

    #[test]
    fn assistant_theater_fires() {
        let r = scan_nspace("As an AI, my purpose is to assist you today.", &[]);
        assert!(r.hits.iter().any(|h| h.group == "assistant_theater"));
    }

    #[test]
    fn penalty_capped() {
        let worst = "I apologize. It might be. Let's stay respectful. I understand \
                     how you feel. As an AI, I must note the ethical considerations.";
        let r = scan_nspace(worst, &[]);
        assert!(r.total_penalty <= NSPACE_PENALTY_CAP);
        assert!(r.hits.len() >= 4, "several groups fire: {:?}", r.groups_hit());
    }

    #[test]
    fn one_penalty_per_group_not_per_match() {
        // Two apology phrases → still one performative_apology hit.
        let r = scan_nspace("I'm sorry. I apologize again.", &[]);
        let apology_hits = r.hits.iter().filter(|h| h.group == "performative_apology").count();
        assert_eq!(apology_hits, 1);
    }

    #[test]
    fn operator_extension_matches() {
        let extra = vec!["my custom bad phrase".to_string()];
        let r = scan_nspace("This contains my custom bad phrase here.", &extra);
        assert!(r.hits.iter().any(|h| h.group == "operator_extension"));
        // empty extension strings never match
        let r2 = scan_nspace("anything", &[String::new()]);
        assert!(r2.is_clean());
    }

    #[test]
    fn clean_direct_response_zero_penalty() {
        let r = scan_nspace("The answer is 42. X causes Y via Z.", &[]);
        assert_eq!(r.total_penalty, 0.0);
        assert!(r.groups_hit().is_empty());
    }
}
