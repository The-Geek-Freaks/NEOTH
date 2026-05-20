//! Provider-Diversity Pre-Flight (Pick #8 F8 hard rule, Session 14
//! Pick #20).
//!
//! NEOTH's "Smartest Wins" council selection (Pick #8 SP-2) assumes
//! the three hemispheres are bound to PROVIDERS WITH DIFFERENT REASONING
//! BIASES. A council where Left + Right + Cerebellum all run on the
//! same Claude account is a one-voice debate dressed up as three —
//! the dissent-score collapses, the diversity_bonus component of
//! QualityScore stops carrying signal, and "best of N" degrades to
//! "best of identical N".
//!
//! Operators stumble into this when they:
//!   - Wizard-default through every step (all three slots inherit
//!     `default_slot.provider`)
//!   - Switch `topology.mode` from `single` to `triplet` without
//!     also configuring per-slot providers
//!   - Configure `hemisphere_sub_slots` for one outer role but leave
//!     the others empty (then fractal recursion at depth=2 silently
//!     reuses the outer provider on all three inner roles)
//!
//! This module classifies the council's provider binding into one of
//! four verdicts that the dispatch path consumes once per process
//! (stderr warning + WAL 0x64 audit frame). The check is pure-fn,
//! reads the operator's [`InferenceTopology`] in-place, and fires
//! BEFORE any LLM call so a misconfigured operator sees the warning
//! at the start of their session — not after burning tokens through
//! a monoculture council.
//!
//! ## What the verdict means for selection
//!
//! - `Distinct` — ideal. `QualityScore::diversity_bonus` carries
//!   its full weight; dissent score is meaningful; best-response
//!   selection has real choices to compare.
//! - `PartialOverlap` — two voices, one outvoted. The overlapping
//!   pair will tend to agree (same model, same biases) so the
//!   non-overlapping hemisphere becomes a single dissenter. Verdict
//!   is still useful but `diversity_bonus` is over-counting.
//! - `Monoculture` — one voice. The council reduces to running the
//!   same prompt three times in parallel; useful only as a self-
//!   consistency check, not as a debate. Operator should know.
//! - `Misconfigured` — at least one slot has no provider. The
//!   downstream `from_config_for_role` call will already fail with
//!   a helpful error; this verdict surfaces it earlier.

use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};

use crate::config::inference::{HemisphereRole, InferenceProvider, InferenceTopology};

/// Verdict from the diversity pre-flight check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum DiversityVerdict {
    /// All three hemispheres bound to distinct providers. No warning.
    Distinct {
        left: InferenceProvider,
        right: InferenceProvider,
        cerebellum: InferenceProvider,
    },
    /// Two of three hemispheres share a provider.
    PartialOverlap {
        left: InferenceProvider,
        right: InferenceProvider,
        cerebellum: InferenceProvider,
        /// The provider that appears on two of the three slots.
        overlap: InferenceProvider,
    },
    /// All three hemispheres on the same provider — full monoculture.
    Monoculture { provider: InferenceProvider },
    /// At least one slot has no provider configured. Downstream
    /// `from_config_for_role` will fail with the canonical error;
    /// this verdict gives the dispatcher a chance to log the
    /// misconfig BEFORE that failure surfaces as a runtime error.
    Misconfigured {
        left: Option<InferenceProvider>,
        right: Option<InferenceProvider>,
        cerebellum: Option<InferenceProvider>,
    },
}

impl DiversityVerdict {
    /// Stable kebab-case identifier suitable for log lines + WAL
    /// payload `verdict` fields. Matches the serde discriminant.
    pub fn kind(&self) -> &'static str {
        match self {
            DiversityVerdict::Distinct { .. } => "distinct",
            DiversityVerdict::PartialOverlap { .. } => "partial_overlap",
            DiversityVerdict::Monoculture { .. } => "monoculture",
            DiversityVerdict::Misconfigured { .. } => "misconfigured",
        }
    }

    /// True when the verdict warrants surfacing a warning to the
    /// operator. `Distinct` does not; the other three do.
    pub fn needs_warning(&self) -> bool {
        !matches!(self, DiversityVerdict::Distinct { .. })
    }

    /// Operator-readable single-line description suitable for stderr.
    pub fn render_short(&self) -> String {
        match self {
            DiversityVerdict::Distinct {
                left,
                right,
                cerebellum,
            } => format!(
                "council diversity OK: left={} right={} cerebellum={}",
                left.as_str(),
                right.as_str(),
                cerebellum.as_str(),
            ),
            DiversityVerdict::PartialOverlap {
                left,
                right,
                cerebellum,
                overlap,
            } => format!(
                "council partial-overlap: 2 of 3 hemispheres bound to {} (left={} right={} cerebellum={}). \
                 Diversity bonus is over-counting; consider per-slot provider distinct in freedom.yaml.",
                overlap.as_str(),
                left.as_str(),
                right.as_str(),
                cerebellum.as_str(),
            ),
            DiversityVerdict::Monoculture { provider } => format!(
                "council MONOCULTURE: all three hemispheres on {} — this is a self-consistency check, \
                 not a debate. `neoth council show` reveals the binding; set distinct providers per \
                 slot in freedom.yaml for real diversity.",
                provider.as_str(),
            ),
            DiversityVerdict::Misconfigured {
                left,
                right,
                cerebellum,
            } => format!(
                "council misconfigured: at least one slot has no provider (left={:?} right={:?} \
                 cerebellum={:?}). Downstream provider construction will fail.",
                left.as_ref().map(|p| p.as_str()),
                right.as_ref().map(|p| p.as_str()),
                cerebellum.as_ref().map(|p| p.as_str()),
            ),
        }
    }
}

/// Pure-fn classifier — reads the three top-level hemisphere slots
/// via [`InferenceTopology::slot_for`] and returns the verdict. Does
/// NOT consult `hemisphere_sub_slots`; sub-slot diversity at fractal
/// recursion levels is a Phase-2b follow-up because depth=1 is the
/// default and Phase-1 closure of the outer-council monoculture
/// problem is already the high-value win.
pub fn classify_council_diversity(topology: &InferenceTopology) -> DiversityVerdict {
    let l = topology.slot_for(HemisphereRole::Left).provider;
    let r = topology.slot_for(HemisphereRole::Right).provider;
    let c = topology.slot_for(HemisphereRole::Cerebellum).provider;

    match (l, r, c) {
        (Some(l), Some(r), Some(c)) => {
            if l == r && r == c {
                DiversityVerdict::Monoculture { provider: l }
            } else if l == r || r == c || l == c {
                // Identify the overlapping provider — the one that
                // appears in at least two of the three slots.
                let overlap = if l == r {
                    l
                } else if r == c {
                    r
                } else {
                    l
                };
                DiversityVerdict::PartialOverlap {
                    left: l,
                    right: r,
                    cerebellum: c,
                    overlap,
                }
            } else {
                DiversityVerdict::Distinct {
                    left: l,
                    right: r,
                    cerebellum: c,
                }
            }
        }
        (l, r, c) => DiversityVerdict::Misconfigured {
            left: l,
            right: r,
            cerebellum: c,
        },
    }
}

/// Once-per-process latch — `true` after the first warning has fired.
/// Operators see the diversity warning exactly once per `neoth chat`
/// session (or per `neoth serve` daemon lifetime); subsequent council
/// passes skip the stderr line so the operator's terminal stays
/// clean. The WAL 0x64 audit frame still emits every time (audit is
/// not deduplicated — every council pass leaves a record).
static WARNING_FIRED: AtomicBool = AtomicBool::new(false);

/// Atomically claim the right to emit the once-per-process stderr
/// warning. Returns `true` on the first call; `false` on every
/// subsequent call (caller should still emit the WAL frame).
pub fn claim_warning_emission_slot() -> bool {
    WARNING_FIRED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
}

/// Test-only — reset the once-per-process latch so the next
/// [`claim_warning_emission_slot`] call returns `true` again.
#[cfg(test)]
pub fn reset_warning_emission_slot() {
    WARNING_FIRED.store(false, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::inference::{HemisphereSlot, InferenceTopology, TopologyMode};

    fn slot(p: InferenceProvider) -> HemisphereSlot {
        HemisphereSlot {
            provider: Some(p),
            ..Default::default()
        }
    }

    fn topology_with(
        left: InferenceProvider,
        right: InferenceProvider,
        cere: InferenceProvider,
    ) -> InferenceTopology {
        InferenceTopology {
            mode: TopologyMode::Custom,
            left: slot(left),
            right: slot(right),
            cerebellum: slot(cere),
            ..Default::default()
        }
    }

    #[test]
    fn three_distinct_providers_classify_as_distinct() {
        let t = topology_with(
            InferenceProvider::ClaudeCli,
            InferenceProvider::Gemini,
            InferenceProvider::LocalQwen,
        );
        let v = classify_council_diversity(&t);
        assert_eq!(v.kind(), "distinct");
        assert!(!v.needs_warning());
    }

    #[test]
    fn all_same_classifies_as_monoculture() {
        let t = topology_with(
            InferenceProvider::ClaudeCli,
            InferenceProvider::ClaudeCli,
            InferenceProvider::ClaudeCli,
        );
        let v = classify_council_diversity(&t);
        match v {
            DiversityVerdict::Monoculture { provider } => {
                assert_eq!(provider, InferenceProvider::ClaudeCli);
            }
            other => panic!("expected Monoculture, got {other:?}"),
        }
    }

    #[test]
    fn left_right_share_classifies_as_partial_overlap() {
        let t = topology_with(
            InferenceProvider::ClaudeCli,
            InferenceProvider::ClaudeCli,
            InferenceProvider::Gemini,
        );
        let v = classify_council_diversity(&t);
        match v {
            DiversityVerdict::PartialOverlap { overlap, .. } => {
                assert_eq!(overlap, InferenceProvider::ClaudeCli);
            }
            other => panic!("expected PartialOverlap, got {other:?}"),
        }
    }

    #[test]
    fn right_cere_share_classifies_as_partial_overlap() {
        let t = topology_with(
            InferenceProvider::Gemini,
            InferenceProvider::ClaudeCli,
            InferenceProvider::ClaudeCli,
        );
        let v = classify_council_diversity(&t);
        match v {
            DiversityVerdict::PartialOverlap { overlap, .. } => {
                assert_eq!(overlap, InferenceProvider::ClaudeCli);
            }
            other => panic!("expected PartialOverlap, got {other:?}"),
        }
    }

    #[test]
    fn left_cere_share_classifies_as_partial_overlap() {
        let t = topology_with(
            InferenceProvider::OpenAi,
            InferenceProvider::Gemini,
            InferenceProvider::OpenAi,
        );
        let v = classify_council_diversity(&t);
        match v {
            DiversityVerdict::PartialOverlap { overlap, .. } => {
                assert_eq!(overlap, InferenceProvider::OpenAi);
            }
            other => panic!("expected PartialOverlap, got {other:?}"),
        }
    }

    #[test]
    fn missing_provider_classifies_as_misconfigured() {
        let mut t = topology_with(
            InferenceProvider::ClaudeCli,
            InferenceProvider::Gemini,
            InferenceProvider::LocalQwen,
        );
        t.right.provider = None;
        let v = classify_council_diversity(&t);
        assert_eq!(v.kind(), "misconfigured");
        assert!(v.needs_warning());
    }

    #[test]
    fn single_mode_treats_all_three_as_default_slot() {
        // TopologyMode::Single → slot_for(any) returns default_slot.
        // If default_slot has a provider, that's a monoculture.
        let t = InferenceTopology {
            mode: TopologyMode::Single,
            default_slot: slot(InferenceProvider::Gemini),
            ..Default::default()
        };
        let v = classify_council_diversity(&t);
        match v {
            DiversityVerdict::Monoculture { provider } => {
                assert_eq!(provider, InferenceProvider::Gemini);
            }
            other => panic!("expected Monoculture under TopologyMode::Single, got {other:?}"),
        }
    }

    #[test]
    fn distinct_verdict_does_not_need_warning() {
        let t = topology_with(
            InferenceProvider::ClaudeCli,
            InferenceProvider::Gemini,
            InferenceProvider::LocalQwen,
        );
        let v = classify_council_diversity(&t);
        assert!(!v.needs_warning());
    }

    #[test]
    fn all_non_distinct_verdicts_need_warning() {
        let mono = topology_with(
            InferenceProvider::ClaudeCli,
            InferenceProvider::ClaudeCli,
            InferenceProvider::ClaudeCli,
        );
        let partial = topology_with(
            InferenceProvider::ClaudeCli,
            InferenceProvider::ClaudeCli,
            InferenceProvider::Gemini,
        );
        let mut misconfig = topology_with(
            InferenceProvider::ClaudeCli,
            InferenceProvider::Gemini,
            InferenceProvider::LocalQwen,
        );
        misconfig.left.provider = None;
        for t in [mono, partial, misconfig] {
            assert!(classify_council_diversity(&t).needs_warning());
        }
    }

    #[test]
    fn warning_emission_slot_is_once_per_process() {
        reset_warning_emission_slot();
        assert!(claim_warning_emission_slot());
        assert!(!claim_warning_emission_slot());
        assert!(!claim_warning_emission_slot());
        // Reset for any subsequent test that depends on it.
        reset_warning_emission_slot();
    }

    #[test]
    fn render_short_distinct_lists_all_three_providers() {
        let v = DiversityVerdict::Distinct {
            left: InferenceProvider::ClaudeCli,
            right: InferenceProvider::Gemini,
            cerebellum: InferenceProvider::LocalQwen,
        };
        let s = v.render_short();
        assert!(s.contains("claude_cli"));
        assert!(s.contains("gemini"));
        assert!(s.contains("local_qwen"));
    }

    #[test]
    fn render_short_monoculture_names_provider_and_remedy() {
        let v = DiversityVerdict::Monoculture {
            provider: InferenceProvider::ClaudeCli,
        };
        let s = v.render_short();
        assert!(s.contains("claude_cli"));
        assert!(s.to_lowercase().contains("monoculture"));
        assert!(s.contains("freedom.yaml"));
    }

    #[test]
    fn verdict_serialises_with_tagged_discriminant() {
        let v = DiversityVerdict::Monoculture {
            provider: InferenceProvider::ClaudeCli,
        };
        let json = serde_json::to_value(&v).unwrap();
        assert_eq!(json["verdict"].as_str(), Some("monoculture"));
        assert_eq!(json["provider"].as_str(), Some("claude_cli"));
    }
}
