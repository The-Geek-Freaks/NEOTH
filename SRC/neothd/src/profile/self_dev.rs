//! P-04 — proactive self-development proposal engine.
//!
//! Looks at the operator's [`BehaviouralProfile`] (P-01 estimators)
//! + their current applied [`PresetData`] (P-02) and emits proposals
//! for profile adjustments the operator can accept / decline via
//! `neoth self-dev review` / `accept <id>` / `decline <id>`.
//!
//! Pure-fn surface: `propose_adjustments(profile, current_preset)`
//! returns `Vec<SelfDevProposal>`. Each proposal carries an id +
//! kind + reason + confidence (0.0..=1.0) the operator can use to
//! filter ("only show me ≥0.7 confidence" surface).
//!
//! Acceptance / decline emits the WAL events shipped in P-05
//! (`EVENT_TYPE_SELF_DEV_ACCEPTED` 0x1D / `..._DECLINED` 0x1E).
//! This module ships ONLY the proposal generation — accept/decline
//! storage + WAL emit live in the focused P-04 impl session that
//! wires the CLI surface.

use serde::{Deserialize, Serialize};

use super::estimators::BehaviouralProfile;
use super::presets::{PresetData, ProfilePreset};

/// Kind of adjustment a proposal recommends. Pinned exhaustively —
/// adding a kind needs a `propose_*` function + operator-facing
/// description in `as_str`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalKind {
    /// Switch to a different profile preset (e.g. Lowkey → Formal
    /// because tone signal flipped formal).
    SwitchPreset,
    /// Adjust verbosity tier independent of preset.
    AdjustVerbosity,
    /// Adjust briefing schedule based on temporal pattern.
    AdjustBriefingSchedule,
    /// Surface that operator's usage spans a new topic area NEOTH
    /// could learn an extension for.
    LearnExtension,
}

impl ProposalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SwitchPreset => "switch_preset",
            Self::AdjustVerbosity => "adjust_verbosity",
            Self::AdjustBriefingSchedule => "adjust_briefing_schedule",
            Self::LearnExtension => "learn_extension",
        }
    }
}

/// One concrete proposal the operator reviews. `confidence` is the
/// engine's own estimate (0.0..=1.0); operator filters by it via
/// `neoth self-dev review --min-confidence 0.7`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SelfDevProposal {
    /// Stable id for the operator-facing accept/decline command.
    /// Format: `{kind}-{short_hash}` (kind for readability +
    /// hash for uniqueness). Caller generates the hash from a
    /// stable signature over the proposal contents.
    pub id: String,
    pub kind: ProposalKind,
    /// Operator-readable one-line explanation of WHY the engine
    /// thinks this adjustment fits the recent activity.
    pub reason: String,
    /// 0.0..=1.0. Engine's own estimate of how confident it is.
    pub confidence: f64,
    /// Machine-readable target — e.g. for SwitchPreset this is
    /// the target preset name (`"formal"`); for AdjustVerbosity
    /// it's `"terse"` / `"detailed"`; for AdjustBriefingSchedule
    /// it's an ISO time `"08:30"`. Empty allowed for kinds that
    /// don't have a single-string target.
    pub target: String,
}

impl SelfDevProposal {
    /// Build the WAL payload for `EVENT_TYPE_SELF_DEV_PROPOSED`
    /// (0x1C). The accepted/declined events use just the id.
    pub fn to_proposed_payload(&self, ts_unix: i64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "proposal_id": self.id,
            "kind": self.kind.as_str(),
            "reason": self.reason,
            "confidence": self.confidence,
            "target": self.target,
            "ts_unix": ts_unix,
        }))
        .unwrap_or_default()
    }
}

/// Generate proposals from the operator's behavioural profile +
/// current preset. Returns proposals in confidence-descending
/// order so `neoth self-dev review` shows the most defensible
/// adjustments first.
pub fn propose_adjustments(
    profile: &BehaviouralProfile,
    current_preset: &PresetData,
) -> Vec<SelfDevProposal> {
    let mut out = Vec::new();

    // ── tone-driven preset switch ──────────────────────────────
    // Strong tone signal in the OPPOSITE direction of the current
    // preset's formality → propose the matching switch.
    if profile.tone.sample_count >= 20 {
        let suggest_formal = profile.tone.casual_score < -0.4
            && !matches!(current_preset.preset, ProfilePreset::Formal);
        let suggest_casual = profile.tone.casual_score > 0.4
            && matches!(current_preset.preset, ProfilePreset::Formal);

        if suggest_formal {
            out.push(SelfDevProposal {
                id: stable_id("switch_preset", "formal-from-tone"),
                kind: ProposalKind::SwitchPreset,
                reason: format!(
                    "your recent writing shifted formal (tone score {:.2}); preset Formal would match",
                    profile.tone.casual_score
                ),
                confidence: (-profile.tone.casual_score).min(1.0),
                target: "formal".into(),
            });
        } else if suggest_casual {
            out.push(SelfDevProposal {
                id: stable_id("switch_preset", "lowkey-from-tone"),
                kind: ProposalKind::SwitchPreset,
                reason: format!(
                    "your recent writing shifted casual (tone score {:.2}); preset Lowkey would match",
                    profile.tone.casual_score
                ),
                confidence: profile.tone.casual_score.min(1.0),
                target: "lowkey".into(),
            });
        }
    }

    // ── length-driven verbosity adjustment ──────────────────────
    if profile.length.sample_count >= 20 {
        // Operator writes long prompts → expect detailed replies.
        if profile.length.median_chars >= 200
            && current_preset.verbosity != super::presets::Verbosity::Detailed
        {
            out.push(SelfDevProposal {
                id: stable_id("adjust_verbosity", "detailed-from-length"),
                kind: ProposalKind::AdjustVerbosity,
                reason: format!(
                    "your median prompt is {} chars; Detailed verbosity would match the depth",
                    profile.length.median_chars
                ),
                confidence: ((profile.length.median_chars as f64) / 500.0).min(1.0),
                target: "detailed".into(),
            });
        }
        // Operator writes terse prompts → terse replies.
        if profile.length.median_chars <= 30
            && current_preset.verbosity != super::presets::Verbosity::Terse
        {
            out.push(SelfDevProposal {
                id: stable_id("adjust_verbosity", "terse-from-length"),
                kind: ProposalKind::AdjustVerbosity,
                reason: format!(
                    "your median prompt is only {} chars; Terse verbosity would respect the brevity",
                    profile.length.median_chars
                ),
                confidence: (30.0 - profile.length.median_chars as f64).max(0.0) / 30.0,
                target: "terse".into(),
            });
        }
    }

    // ── temporal-driven briefing schedule ──────────────────────
    if let Some(peak_hour) = profile.temporal.peak_hour {
        let total: u32 = profile.temporal.hour_buckets.iter().sum();
        if total >= 50 {
            // Suggest briefing 30min before peak activity hour.
            let brief_hour = (peak_hour as i32 - 1).rem_euclid(24);
            out.push(SelfDevProposal {
                id: stable_id("adjust_briefing_schedule", &format!("brief-{brief_hour:02}")),
                kind: ProposalKind::AdjustBriefingSchedule,
                reason: format!(
                    "your peak activity is hour {peak_hour:02}; briefing at {brief_hour:02}:30 would land in your warmup window"
                ),
                confidence: (total as f64 / 200.0).min(0.9),
                target: format!("{brief_hour:02}:30"),
            });
        }
    }

    // ── topic-driven extension learning ──────────────────────
    // Top topic accounting for substantial activity → propose
    // pulling in a related extension.
    if let Some((top_topic, hits)) = profile.topic.top_topics.first() {
        if *hits >= 30 {
            out.push(SelfDevProposal {
                id: stable_id("learn_extension", top_topic),
                kind: ProposalKind::LearnExtension,
                reason: format!(
                    "you used {hits} prompts in the `{top_topic}` topic — NEOTH could load the matching extension"
                ),
                confidence: (*hits as f64 / 100.0).min(0.85),
                target: top_topic.clone(),
            });
        }
    }

    out.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out
}

/// Build a stable proposal id from (kind, distinguishing_text).
/// Uses xxh3-style hash for a short hex prefix the operator can
/// type. We use the FNV-1a 32-bit mixer inline (no extra dep needed
/// — sha2 would be overkill for an operator-readable short id).
fn stable_id(kind: &str, distinguishing: &str) -> String {
    let mut hash: u32 = 2_166_136_261;
    for byte in kind.bytes().chain([b':']).chain(distinguishing.bytes()) {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(16_777_619);
    }
    format!("{kind}-{hash:08x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::estimators::{
        CadenceEstimate, LengthEstimate, TemporalEstimate, ToneEstimate, TopicEstimate,
    };
    use crate::profile::presets::{Verbosity, apply_preset};

    fn empty_profile() -> BehaviouralProfile {
        BehaviouralProfile::default()
    }

    fn profile_with_tone(casual_score: f64, samples: u32) -> BehaviouralProfile {
        BehaviouralProfile {
            tone: ToneEstimate {
                sample_count: samples,
                casual_hits: if casual_score > 0.0 { samples } else { 0 },
                formal_hits: if casual_score < 0.0 { samples } else { 0 },
                casual_score,
            },
            ..Default::default()
        }
    }

    fn profile_with_length(median: u32, samples: u32) -> BehaviouralProfile {
        BehaviouralProfile {
            length: LengthEstimate {
                sample_count: samples,
                mean_chars: median as f64,
                median_chars: median,
                p10_chars: median,
                p90_chars: median,
            },
            ..Default::default()
        }
    }

    // ── ProposalKind ────────────────────────────────────────────

    #[test]
    fn proposal_kind_as_str_pinned() {
        assert_eq!(ProposalKind::SwitchPreset.as_str(), "switch_preset");
        assert_eq!(ProposalKind::AdjustVerbosity.as_str(), "adjust_verbosity");
        assert_eq!(
            ProposalKind::AdjustBriefingSchedule.as_str(),
            "adjust_briefing_schedule"
        );
        assert_eq!(ProposalKind::LearnExtension.as_str(), "learn_extension");
    }

    #[test]
    fn proposal_kind_serialises_snake_case() {
        let s = serde_json::to_string(&ProposalKind::AdjustBriefingSchedule).unwrap();
        assert_eq!(s, "\"adjust_briefing_schedule\"");
    }

    // ── stable_id ───────────────────────────────────────────────

    #[test]
    fn stable_id_deterministic_for_same_inputs() {
        assert_eq!(
            stable_id("switch_preset", "x"),
            stable_id("switch_preset", "x")
        );
    }

    #[test]
    fn stable_id_differs_for_different_inputs() {
        assert_ne!(
            stable_id("switch_preset", "x"),
            stable_id("switch_preset", "y")
        );
        assert_ne!(stable_id("a", "x"), stable_id("b", "x"));
    }

    #[test]
    fn stable_id_has_kind_prefix() {
        let id = stable_id("learn_extension", "code");
        assert!(id.starts_with("learn_extension-"));
    }

    // ── empty profile + empty current preset ────────────────────

    #[test]
    fn empty_profile_produces_no_proposals() {
        let current = apply_preset(ProfilePreset::Lowkey);
        assert!(propose_adjustments(&empty_profile(), &current).is_empty());
    }

    // ── tone-driven switch ──────────────────────────────────────

    #[test]
    fn strong_formal_tone_proposes_formal_when_current_is_lowkey() {
        let profile = profile_with_tone(-0.8, 50);
        let current = apply_preset(ProfilePreset::Lowkey);
        let props = propose_adjustments(&profile, &current);
        assert!(!props.is_empty());
        let switch = props
            .iter()
            .find(|p| p.kind == ProposalKind::SwitchPreset)
            .unwrap();
        assert_eq!(switch.target, "formal");
        assert!(switch.confidence > 0.5);
    }

    #[test]
    fn strong_casual_tone_proposes_lowkey_when_current_is_formal() {
        let profile = profile_with_tone(0.9, 50);
        let current = apply_preset(ProfilePreset::Formal);
        let props = propose_adjustments(&profile, &current);
        let switch = props
            .iter()
            .find(|p| p.kind == ProposalKind::SwitchPreset)
            .unwrap();
        assert_eq!(switch.target, "lowkey");
    }

    #[test]
    fn tone_below_sample_threshold_does_not_propose() {
        // Strong score but only 5 samples → engine doesn't trust it.
        let profile = profile_with_tone(-0.9, 5);
        let current = apply_preset(ProfilePreset::Lowkey);
        let props = propose_adjustments(&profile, &current);
        assert!(props.iter().all(|p| p.kind != ProposalKind::SwitchPreset));
    }

    #[test]
    fn tone_does_not_propose_switch_to_current_preset() {
        // Already on Formal + strong formal tone → no SwitchPreset.
        let profile = profile_with_tone(-0.8, 50);
        let current = apply_preset(ProfilePreset::Formal);
        let props = propose_adjustments(&profile, &current);
        assert!(props.iter().all(|p| p.kind != ProposalKind::SwitchPreset));
    }

    // ── length-driven verbosity ─────────────────────────────────

    #[test]
    fn long_prompts_propose_detailed_verbosity() {
        let profile = profile_with_length(300, 50);
        let current = apply_preset(ProfilePreset::Lowkey); // Terse default
        let props = propose_adjustments(&profile, &current);
        let v = props
            .iter()
            .find(|p| p.kind == ProposalKind::AdjustVerbosity)
            .unwrap();
        assert_eq!(v.target, "detailed");
    }

    #[test]
    fn short_prompts_propose_terse_verbosity() {
        let profile = profile_with_length(10, 50);
        let current = apply_preset(ProfilePreset::Deepdive); // Detailed default
        let props = propose_adjustments(&profile, &current);
        let v = props
            .iter()
            .find(|p| p.kind == ProposalKind::AdjustVerbosity)
            .unwrap();
        assert_eq!(v.target, "terse");
    }

    #[test]
    fn verbosity_skip_when_already_matching() {
        let profile = profile_with_length(10, 50);
        // Lowkey is already Terse — no need to propose.
        let current = apply_preset(ProfilePreset::Lowkey);
        let props = propose_adjustments(&profile, &current);
        assert!(
            props
                .iter()
                .all(|p| p.kind != ProposalKind::AdjustVerbosity)
        );
    }

    // ── temporal-driven briefing ────────────────────────────────

    #[test]
    fn temporal_peak_proposes_briefing_30min_earlier() {
        let mut buckets = [0u32; 24];
        buckets[9] = 80; // peak at 9am
        let profile = BehaviouralProfile {
            temporal: TemporalEstimate {
                hour_buckets: buckets,
                peak_hour: Some(9),
            },
            ..Default::default()
        };
        let current = apply_preset(ProfilePreset::Lowkey);
        let props = propose_adjustments(&profile, &current);
        let b = props
            .iter()
            .find(|p| p.kind == ProposalKind::AdjustBriefingSchedule)
            .unwrap();
        assert_eq!(b.target, "08:30");
    }

    #[test]
    fn temporal_below_sample_threshold_no_briefing_proposal() {
        let profile = empty_profile();
        let current = apply_preset(ProfilePreset::Lowkey);
        let props = propose_adjustments(&profile, &current);
        assert!(
            props
                .iter()
                .all(|p| p.kind != ProposalKind::AdjustBriefingSchedule)
        );
    }

    // ── topic-driven extension ──────────────────────────────────

    #[test]
    fn high_topic_count_proposes_learn_extension() {
        let profile = BehaviouralProfile {
            topic: TopicEstimate {
                top_topics: vec![("code".to_string(), 60)],
            },
            ..Default::default()
        };
        let current = apply_preset(ProfilePreset::Lowkey);
        let props = propose_adjustments(&profile, &current);
        let l = props
            .iter()
            .find(|p| p.kind == ProposalKind::LearnExtension)
            .unwrap();
        assert_eq!(l.target, "code");
    }

    // ── sort + payload ──────────────────────────────────────────

    #[test]
    fn proposals_sorted_by_confidence_descending() {
        // Build a profile that triggers 3 proposals with distinct
        // confidences + assert sort order.
        let mut buckets = [0u32; 24];
        buckets[10] = 200; // very high confidence on briefing
        let profile = BehaviouralProfile {
            tone: ToneEstimate {
                sample_count: 50,
                casual_hits: 0,
                formal_hits: 50,
                casual_score: -0.5, // medium confidence
            },
            length: LengthEstimate {
                sample_count: 50,
                mean_chars: 5.0,
                median_chars: 5, // high confidence on terse
                p10_chars: 5,
                p90_chars: 5,
            },
            topic: TopicEstimate {
                top_topics: vec![("code".to_string(), 60)],
            },
            cadence: CadenceEstimate::default(),
            temporal: TemporalEstimate {
                hour_buckets: buckets,
                peak_hour: Some(10),
            },
        };
        let current = apply_preset(ProfilePreset::Deepdive); // Detailed
        let props = propose_adjustments(&profile, &current);
        assert!(props.len() >= 2);
        for w in props.windows(2) {
            assert!(
                w[0].confidence >= w[1].confidence,
                "proposals not in descending order: {:?}",
                props
            );
        }
    }

    #[test]
    fn proposal_payload_carries_all_fields() {
        let p = SelfDevProposal {
            id: "x-deadbeef".into(),
            kind: ProposalKind::SwitchPreset,
            reason: "test".into(),
            confidence: 0.75,
            target: "formal".into(),
        };
        let v: serde_json::Value =
            serde_json::from_slice(&p.to_proposed_payload(1_700_000_000)).unwrap();
        assert_eq!(v["proposal_id"], "x-deadbeef");
        assert_eq!(v["kind"], "switch_preset");
        assert_eq!(v["reason"], "test");
        assert_eq!(v["confidence"], 0.75);
        assert_eq!(v["target"], "formal");
        assert_eq!(v["ts_unix"], 1_700_000_000);
    }

    // Use Verbosity in the test scope so the import isn't unused.
    #[test]
    fn verbosity_default_for_lowkey_is_terse() {
        let lk = apply_preset(ProfilePreset::Lowkey);
        assert_eq!(lk.verbosity, Verbosity::Terse);
    }
}
