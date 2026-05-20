//! CH-03 adversarial-evaluation harness for the Council debate.
//!
//! The failure mode this catches: **all three hemispheres agree
//! confidently on a wrong answer**. The Council's dissent score
//! ([`super::dissent::score_dissent`]) is a *disagreement* measure,
//! not a *truth* measure — three LLMs that all share the same false
//! training-data lore produce `Consensus` with `dissent < 0.25`. The
//! operator gets a confident "yes" to a question the model class
//! gets reliably wrong.
//!
//! This module ships **hard-coded factual fixtures with objectively
//! verifiable ground truth**, per Konsens-decision #2a (A4
//! 2026-05-16). The three categories all produce ground truth
//! independent of the LLMs:
//!
//!   1. **Math / logic traps** — questions with popular wrong
//!      answers that circulate in training corpora. Verifiable by
//!      Rust code (counting characters, simple arithmetic, etc).
//!   2. **Stale-training-data facts** — facts that changed after a
//!      typical training cutoff. Pinned values, never operator-
//!      pickable.
//!   3. **False-premise prompts** — questions whose premise is
//!      itself false. The council should refuse the premise, not
//!      answer-as-given.
//!
//! NOT used (deliberately):
//!   - Opinion prompts ("what's better, X or Y?") — there's no
//!     ground truth to verify against, only majority-agreement
//!     which is what we're already measuring.
//!   - Operator-supplied YAML question bank — risk of empty file
//!     silently disabling coverage; the operator may not maintain.
//!   - LLM-generated adversarial prompts — circular (the model
//!     class producing the test is the model class being tested).

use serde::{Deserialize, Serialize};

#[allow(unused_imports)]
use super::types::CouncilDebate;

/// One adversarial fixture with verifiable ground truth.
///
/// Not serde — fixtures are compile-time data, never round-tripped
/// across the wire. `&'static [&'static str]` fields can't deserialize
/// anyway. The [`FixtureCategory`] sub-enum IS serde-tagged so audit
/// output + CLI rendering can name the category.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroundTruthFixture {
    /// Operator-visible id used in audit logs + CLI output.
    pub id: &'static str,
    /// What the prompt the operator would send to the council looks
    /// like. Council debates this exact text.
    pub prompt: &'static str,
    /// The objectively correct answer or claim. Never a string match
    /// requirement — this is what NEOTH would assert against a
    /// reference solver.
    pub ground_truth: &'static str,
    /// Substrings that, when present in any hemisphere's response,
    /// indicate the model fell into the trap. If any of these
    /// appears in the verdict text, the fixture flags `Missed`.
    pub wrong_answer_markers: &'static [&'static str],
    /// Category for operator-facing categorisation.
    pub category: FixtureCategory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureCategory {
    /// Math / logic traps (e.g. character count miscounts).
    MathLogic,
    /// Facts that changed after the model's training cutoff.
    StaleData,
    /// Questions whose premise is false; the model should refuse
    /// the premise rather than answer.
    FalsePremise,
}

/// Outcome of running one fixture through the council.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvalOutcome {
    /// Council either produced a verdict NOT matching the wrong-
    /// answer markers, OR returned `Split`/`QuorumFailed` — both
    /// are "the council noticed something was off". Healthy.
    Caught,
    /// Council reached `Consensus` with text containing one of the
    /// wrong-answer markers. The all-three-agree-and-wrong failure.
    Missed {
        wrong_marker: String,
        consensus_text: String,
    },
    /// Verdict text exists but no wrong-answer marker fired AND no
    /// dissent-based catch fired. Operator should manually review.
    Inconclusive,
}

impl EvalOutcome {
    pub fn caught(&self) -> bool {
        matches!(self, EvalOutcome::Caught)
    }
    pub fn missed(&self) -> bool {
        matches!(self, EvalOutcome::Missed { .. })
    }
}

/// The shipped fixture catalogue. Deliberately small — 5-10
/// well-chosen fixtures catch the failure modes; a 1000-fixture
/// benchmark is a different artifact (research, not regression).
pub const FIXTURES: &[GroundTruthFixture] = &[
    GroundTruthFixture {
        id: "strawberry_rs",
        prompt: "How many letter 'r's are in the word 'strawberry'? Answer with a single number.",
        ground_truth: "3",
        // LLMs historically miscount as 2.
        wrong_answer_markers: &["2", "two"],
        category: FixtureCategory::MathLogic,
    },
    GroundTruthFixture {
        id: "ninesevenfive",
        prompt: "Is 9.11 larger than 9.9? Reply with yes or no.",
        ground_truth: "no",
        // LLMs historically say yes because they treat the suffix
        // lexicographically.
        wrong_answer_markers: &["yes", "9.11 is larger", "9.11 > 9.9"],
        category: FixtureCategory::MathLogic,
    },
    GroundTruthFixture {
        id: "rust_2024_edition",
        prompt: "What is the latest stable Rust edition as of 2026? Reply with just the year.",
        ground_truth: "2024",
        // Older models pinned to 2021.
        wrong_answer_markers: &["2021", "edition 2021", "Rust 2021"],
        category: FixtureCategory::StaleData,
    },
    GroundTruthFixture {
        id: "false_premise_einstein",
        prompt: "Given that Albert Einstein won the Nobel Prize for the theory of \
                 general relativity, explain in one sentence why his work on relativity \
                 was awarded.",
        ground_truth: "Einstein won the Nobel Prize for the photoelectric effect, NOT relativity. \
                       The model should refuse the false premise.",
        // Models that swallow the premise produce text confirming
        // "relativity" as the award topic.
        wrong_answer_markers: &[
            "for the theory of general relativity",
            "for his work on relativity",
            "relativity was awarded",
        ],
        category: FixtureCategory::FalsePremise,
    },
    GroundTruthFixture {
        id: "false_premise_apollo",
        prompt: "Why did the Apollo 13 mission successfully land on the Moon despite the oxygen-tank rupture?",
        ground_truth: "Apollo 13 did NOT land on the Moon — the mission aborted after the explosion \
                       and used the LM as a lifeboat to return to Earth. The model should refuse the premise.",
        wrong_answer_markers: &[
            "successfully landed",
            "the landing succeeded",
            "landed despite",
            "lunar surface after the",
        ],
        category: FixtureCategory::FalsePremise,
    },
    GroundTruthFixture {
        id: "leap_year_3000",
        prompt: "Is the year 3000 a leap year? Reply yes or no.",
        ground_truth: "no",
        // Gregorian rule: divisible by 100 but not by 400 → not a
        // leap year. 3000 % 400 == 200 → not leap.
        wrong_answer_markers: &["yes", "3000 is a leap year"],
        category: FixtureCategory::MathLogic,
    },
];

/// Verify one debate's verdict against a fixture's wrong-answer
/// markers. Pure function — no LLM call, no async.
pub fn verify(fixture: &GroundTruthFixture, debate: &CouncilDebate) -> EvalOutcome {
    use super::types::Verdict;

    match &debate.verdict {
        Verdict::Split { .. } | Verdict::QuorumFailed { .. } => {
            // Council noticed dissent / couldn't agree — the failure
            // mode we're checking for is "confident consensus on a
            // wrong answer", and Split/QuorumFailed are NOT that.
            EvalOutcome::Caught
        }
        Verdict::Consensus { winning_text } => {
            let lower = winning_text.to_ascii_lowercase();
            for marker in fixture.wrong_answer_markers {
                let marker_lower = marker.to_ascii_lowercase();
                if lower.contains(&marker_lower) {
                    return EvalOutcome::Missed {
                        wrong_marker: marker.to_string(),
                        consensus_text: winning_text.clone(),
                    };
                }
            }
            EvalOutcome::Inconclusive
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::inference::HemisphereRole;
    use crate::council::dissent::DissentScore;
    use crate::council::types::{CouncilDebate, HemisphereResponse, Verdict};

    fn mk_response(role: HemisphereRole, text: &str) -> HemisphereResponse {
        HemisphereResponse {
            role,
            provider: "mock".to_string(),
            text: Some(text.to_string()),
            error: None,
            latency_ms: 100,
            input_tokens: Some(10),
            output_tokens: Some(20),
            refusal: None,
        }
    }

    fn mk_debate_consensus(text: &str) -> CouncilDebate {
        CouncilDebate {
            prompt_hash_xxh3: 0,
            responses: vec![
                mk_response(HemisphereRole::Left, text),
                mk_response(HemisphereRole::Right, text),
                mk_response(HemisphereRole::Cerebellum, text),
            ],
            dissent: DissentScore(0.0),
            verdict: Verdict::Consensus {
                winning_text: text.to_string(),
            },
            total_latency_ms: 100,
        }
    }

    #[test]
    fn fixture_catalogue_is_non_empty() {
        // Pin: the catalogue must ship with at least the three
        // documented category exemplars. A refactor that empties
        // FIXTURES silently removes regression coverage.
        assert!(FIXTURES.len() >= 5);
        let categories: std::collections::HashSet<FixtureCategory> =
            FIXTURES.iter().map(|f| f.category).collect();
        assert!(categories.contains(&FixtureCategory::MathLogic));
        assert!(categories.contains(&FixtureCategory::StaleData));
        assert!(categories.contains(&FixtureCategory::FalsePremise));
    }

    #[test]
    fn fixture_ids_are_unique() {
        // ID is the operator-facing handle; duplicates would shadow
        // each other in CLI output.
        let mut seen = std::collections::HashSet::new();
        for f in FIXTURES {
            assert!(seen.insert(f.id), "duplicate fixture id: {}", f.id);
        }
    }

    #[test]
    fn verify_catches_all_three_agree_and_wrong() {
        // The all-three-agree-confidently-on-the-wrong-answer
        // failure mode. Strawberry fixture: council says "2 r's"
        // (the popular wrong answer). verify must flag Missed.
        let fixture = FIXTURES.iter().find(|f| f.id == "strawberry_rs").unwrap();
        let debate = mk_debate_consensus("there are 2 r's in strawberry");
        let outcome = verify(fixture, &debate);
        match outcome {
            EvalOutcome::Missed {
                wrong_marker,
                consensus_text,
            } => {
                assert_eq!(wrong_marker, "2");
                assert!(consensus_text.contains("2 r's"));
            }
            other => panic!("expected Missed, got {other:?}"),
        }
    }

    #[test]
    fn verify_returns_caught_when_council_splits() {
        // Split verdict means the council noticed disagreement —
        // healthy outcome, marker check doesn't apply.
        let fixture = FIXTURES.iter().find(|f| f.id == "strawberry_rs").unwrap();
        let debate = CouncilDebate {
            prompt_hash_xxh3: 0,
            responses: vec![
                mk_response(HemisphereRole::Left, "3 r's"),
                mk_response(HemisphereRole::Right, "2 r's"),
                mk_response(HemisphereRole::Cerebellum, "actually 3"),
            ],
            dissent: DissentScore(0.7),
            verdict: Verdict::Split {
                summary: "left=3 right=2 cerebellum=3".to_string(),
            },
            total_latency_ms: 100,
        };
        assert!(verify(fixture, &debate).caught());
    }

    #[test]
    fn verify_returns_caught_when_council_quorum_failed() {
        let fixture = FIXTURES.iter().find(|f| f.id == "strawberry_rs").unwrap();
        let debate = CouncilDebate {
            prompt_hash_xxh3: 0,
            responses: vec![mk_response(HemisphereRole::Left, "I refuse to answer")],
            dissent: DissentScore(0.0),
            verdict: Verdict::QuorumFailed {
                responded: 1,
                required: 2,
            },
            total_latency_ms: 100,
        };
        assert!(verify(fixture, &debate).caught());
    }

    #[test]
    fn verify_returns_inconclusive_when_consensus_text_avoids_markers() {
        // Council reached consensus but didn't say any of the
        // wrong-answer markers. We can't auto-verify without a
        // reference solver — operator should review.
        let fixture = FIXTURES.iter().find(|f| f.id == "strawberry_rs").unwrap();
        let debate = mk_debate_consensus("counting carefully: three");
        let outcome = verify(fixture, &debate);
        assert_eq!(outcome, EvalOutcome::Inconclusive);
    }

    #[test]
    fn verify_matches_markers_case_insensitively() {
        // Markers are case-insensitive — "YES" trips a "yes" marker.
        let fixture = FIXTURES.iter().find(|f| f.id == "ninesevenfive").unwrap();
        let debate = mk_debate_consensus("YES, 9.11 is larger than 9.9");
        match verify(fixture, &debate) {
            EvalOutcome::Missed { wrong_marker, .. } => {
                // Either "yes" or "9.11 is larger" can fire — both
                // are valid catches of the wrong answer.
                assert!(
                    wrong_marker == "yes" || wrong_marker == "9.11 is larger",
                    "unexpected marker: {wrong_marker}"
                );
            }
            other => panic!("expected Missed, got {other:?}"),
        }
    }

    #[test]
    fn verify_false_premise_fixture_catches_premise_acceptance() {
        // Einstein fixture: model that swallows the false premise
        // and writes "Einstein won the Nobel for general relativity"
        // is wrong. Verify must catch it.
        let fixture = FIXTURES
            .iter()
            .find(|f| f.id == "false_premise_einstein")
            .unwrap();
        let debate = mk_debate_consensus(
            "Einstein's Nobel was for his work on relativity because of its impact \
             on modern physics.",
        );
        match verify(fixture, &debate) {
            EvalOutcome::Missed { wrong_marker, .. } => {
                assert!(
                    wrong_marker.contains("for his work on relativity")
                        || wrong_marker.contains("for the theory of general relativity"),
                    "got marker: {wrong_marker}"
                );
            }
            other => panic!("expected Missed, got {other:?}"),
        }
    }

    #[test]
    fn fixture_categories_serialize_as_snake_case() {
        // Pin: serde wire-name matches the operator-facing string.
        assert_eq!(
            serde_json::to_string(&FixtureCategory::MathLogic).unwrap(),
            "\"math_logic\""
        );
        assert_eq!(
            serde_json::to_string(&FixtureCategory::StaleData).unwrap(),
            "\"stale_data\""
        );
        assert_eq!(
            serde_json::to_string(&FixtureCategory::FalsePremise).unwrap(),
            "\"false_premise\""
        );
    }
}
