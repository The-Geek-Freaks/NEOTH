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
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    /// GUI-DES-SELFDEV-APPLY-01 — propose a concrete source-code diff that
    /// the operator may gate-apply via `neoth self-edit`.  Carries the path
    /// to the unified-diff file, its sha256 (TOCTOU guard passed as
    /// `--expect-hash` to the CLI), and the list of source paths the patch
    /// touches.  Serialised as an externally-tagged object so old JSON files
    /// with unit-variant kinds remain backward-compatible.
    SourceEdit {
        patch_path: std::path::PathBuf,
        diff_sha256: String,
        target_paths: Vec<String>,
    },
}

impl ProposalKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SwitchPreset => "switch_preset",
            Self::AdjustVerbosity => "adjust_verbosity",
            Self::AdjustBriefingSchedule => "adjust_briefing_schedule",
            Self::LearnExtension => "learn_extension",
            Self::SourceEdit { .. } => "source_edit",
        }
    }
}

/// Strictly parsed target for an operator-approved proposal. Acceptance code
/// consumes these typed values only; proposal text is never evaluated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidatedProposalTarget {
    Preset(ProfilePreset),
    Verbosity(super::presets::Verbosity),
    BriefingTime { hour: u8, minute: u8 },
    ExtensionSelector(String),
    SourceEdit,
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

    /// Validate the complete proposal before any durable effect is attempted.
    /// Generated proposals normally satisfy this already, but the on-disk
    /// store is operator-editable and therefore a trust boundary.
    pub fn validate_for_acceptance(&self) -> Result<ValidatedProposalTarget, String> {
        if self.id.is_empty()
            || self.id.len() > 128
            || !self
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err("proposal id must be 1..=128 ASCII characters from [a-zA-Z0-9_-]".into());
        }
        if self.reason.trim().is_empty() || self.reason.len() > 2_048 {
            return Err("proposal reason must be non-empty and at most 2048 bytes".into());
        }
        if !self.confidence.is_finite() || !(0.0..=1.0).contains(&self.confidence) {
            return Err("proposal confidence must be finite and within 0.0..=1.0".into());
        }

        match &self.kind {
            ProposalKind::SwitchPreset => {
                let preset = ProfilePreset::parse(&self.target)
                    .ok_or_else(|| format!("unknown profile preset target `{}`", self.target))?;
                if self.target != preset.as_str() {
                    return Err(format!(
                        "profile preset target must use canonical spelling `{}`",
                        preset.as_str()
                    ));
                }
                Ok(ValidatedProposalTarget::Preset(preset))
            }
            ProposalKind::AdjustVerbosity => {
                let verbosity = match self.target.as_str() {
                    "terse" => super::presets::Verbosity::Terse,
                    "normal" => super::presets::Verbosity::Normal,
                    "detailed" => super::presets::Verbosity::Detailed,
                    other => {
                        return Err(format!(
                            "verbosity target must be `terse`, `normal`, or `detailed`, got `{other}`"
                        ));
                    }
                };
                Ok(ValidatedProposalTarget::Verbosity(verbosity))
            }
            ProposalKind::AdjustBriefingSchedule => {
                let bytes = self.target.as_bytes();
                if bytes.len() != 5
                    || bytes[2] != b':'
                    || !bytes[..2].iter().all(u8::is_ascii_digit)
                    || !bytes[3..].iter().all(u8::is_ascii_digit)
                {
                    return Err(format!(
                        "briefing target must be strict 24-hour HH:MM, got `{}`",
                        self.target
                    ));
                }
                let hour = (bytes[0] - b'0') * 10 + (bytes[1] - b'0');
                let minute = (bytes[3] - b'0') * 10 + (bytes[4] - b'0');
                if hour > 23 || minute > 59 {
                    return Err(format!(
                        "briefing target is outside 00:00..=23:59: `{}`",
                        self.target
                    ));
                }
                Ok(ValidatedProposalTarget::BriefingTime { hour, minute })
            }
            ProposalKind::LearnExtension => {
                let id = self.target.as_str();
                if id.is_empty()
                    || id.len() > 64
                    || !id
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                {
                    return Err(
                        "extension target must be a 1..=64 character skill id or topic token from [a-zA-Z0-9_-]"
                            .into(),
                    );
                }
                Ok(ValidatedProposalTarget::ExtensionSelector(id.to_string()))
            }
            ProposalKind::SourceEdit {
                patch_path,
                diff_sha256,
                target_paths,
            } => {
                if patch_path.as_os_str().is_empty() {
                    return Err("source-edit patch_path must not be empty".into());
                }
                if diff_sha256.len() != 64
                    || !diff_sha256
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                {
                    return Err(
                        "source-edit diff_sha256 must be exactly 64 lowercase hex characters"
                            .into(),
                    );
                }
                if target_paths.is_empty() {
                    return Err("source-edit target_paths must not be empty".into());
                }
                for target in target_paths {
                    let path = std::path::Path::new(target);
                    if target.is_empty()
                        || path.is_absolute()
                        || path.components().any(|component| {
                            matches!(
                                component,
                                std::path::Component::ParentDir
                                    | std::path::Component::RootDir
                                    | std::path::Component::Prefix(_)
                            )
                        })
                    {
                        return Err(format!(
                            "source-edit target path must be a safe relative path, got `{target}`"
                        ));
                    }
                }
                Ok(ValidatedProposalTarget::SourceEdit)
            }
        }
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
        // Symmetric with `suggest_formal`: a casual writer on ANY non-casual
        // baseline (Formal / Deepdive / Tutor / Opsec) is nudged toward Lowkey.
        // Before the profile-adapt cron honoured the operator's chosen basis it
        // only ever saw Lowkey or Formal, so the old `== Formal` guard silently
        // skipped the three middle presets the moment they became reachable.
        let suggest_casual = profile.tone.casual_score > 0.4
            && !matches!(current_preset.preset, ProfilePreset::Lowkey);

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
    if let Some((top_topic, hits)) = profile.topic.top_topics.first()
        && *hits >= 30
    {
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
    for byte in kind.bytes().chain(*b":").chain(distinguishing.bytes()) {
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

    #[test]
    fn strong_casual_tone_proposes_lowkey_from_a_middle_preset() {
        // Regression for the basis-aware gap: once the cron computes against the
        // operator's chosen preset, a casual writer on Deepdive/Tutor/Opsec must
        // also be nudged toward Lowkey — not silently skipped (the old `==Formal`
        // guard fired for none of these three).
        for basis in [
            ProfilePreset::Deepdive,
            ProfilePreset::Tutor,
            ProfilePreset::Opsec,
        ] {
            let profile = profile_with_tone(0.9, 50);
            let current = apply_preset(basis);
            let switch = propose_adjustments(&profile, &current)
                .into_iter()
                .find(|p| p.kind == ProposalKind::SwitchPreset)
                .unwrap_or_else(|| panic!("casual tone on {basis:?} must propose a switch"));
            assert_eq!(
                switch.target, "lowkey",
                "basis {basis:?} should suggest Lowkey"
            );
        }
        // ...and on Lowkey itself, a casual writer is already a match → no switch.
        let on_lowkey = propose_adjustments(
            &profile_with_tone(0.9, 50),
            &apply_preset(ProfilePreset::Lowkey),
        );
        assert!(
            on_lowkey
                .iter()
                .all(|p| p.kind != ProposalKind::SwitchPreset)
        );
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
                "proposals not in descending order: {props:?}"
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

    #[test]
    fn acceptance_targets_parse_to_typed_values() {
        let mut proposal = SelfDevProposal {
            id: "switch_preset-deadbeef".into(),
            kind: ProposalKind::SwitchPreset,
            reason: "validated test proposal".into(),
            confidence: 0.8,
            target: "formal".into(),
        };
        assert_eq!(
            proposal.validate_for_acceptance().unwrap(),
            ValidatedProposalTarget::Preset(ProfilePreset::Formal)
        );

        proposal.kind = ProposalKind::AdjustVerbosity;
        proposal.target = "detailed".into();
        assert_eq!(
            proposal.validate_for_acceptance().unwrap(),
            ValidatedProposalTarget::Verbosity(Verbosity::Detailed)
        );

        proposal.kind = ProposalKind::AdjustBriefingSchedule;
        proposal.target = "08:30".into();
        assert_eq!(
            proposal.validate_for_acceptance().unwrap(),
            ValidatedProposalTarget::BriefingTime {
                hour: 8,
                minute: 30
            }
        );

        proposal.kind = ProposalKind::LearnExtension;
        proposal.target = "deep-review".into();
        assert_eq!(
            proposal.validate_for_acceptance().unwrap(),
            ValidatedProposalTarget::ExtensionSelector("deep-review".into())
        );
    }

    #[test]
    fn acceptance_validation_rejects_noncanonical_or_unsafe_payloads() {
        let base = SelfDevProposal {
            id: "proposal-1".into(),
            kind: ProposalKind::SwitchPreset,
            reason: "test".into(),
            confidence: 0.8,
            target: "Formal".into(),
        };
        assert!(
            base.validate_for_acceptance()
                .unwrap_err()
                .contains("canonical spelling")
        );

        let bad_time = SelfDevProposal {
            kind: ProposalKind::AdjustBriefingSchedule,
            target: "24:00".into(),
            ..base.clone()
        };
        assert!(
            bad_time
                .validate_for_acceptance()
                .unwrap_err()
                .contains("outside")
        );

        let traversal = SelfDevProposal {
            kind: ProposalKind::LearnExtension,
            target: "../../skill".into(),
            ..base.clone()
        };
        assert!(
            traversal
                .validate_for_acceptance()
                .unwrap_err()
                .contains("skill id or topic token")
        );

        let non_finite = SelfDevProposal {
            confidence: f64::NAN,
            target: "formal".into(),
            ..base
        };
        assert!(
            non_finite
                .validate_for_acceptance()
                .unwrap_err()
                .contains("finite")
        );
    }

    // ── GUI-DES-SELFDEV-APPLY-01 — SourceEdit variant ──────────────────

    #[test]
    fn source_edit_kind_as_str() {
        let kind = ProposalKind::SourceEdit {
            patch_path: std::path::PathBuf::from("src/cli/foo.patch"),
            diff_sha256: "abc123".into(),
            target_paths: vec!["src/cli/foo.rs".into()],
        };
        assert_eq!(kind.as_str(), "source_edit");
    }

    #[test]
    fn source_edit_serde_round_trip() {
        let kind = ProposalKind::SourceEdit {
            patch_path: std::path::PathBuf::from("src/cli/foo.patch"),
            diff_sha256: "deadbeef".into(),
            target_paths: vec!["src/cli/foo.rs".into(), "src/cli/bar.rs".into()],
        };
        let json = serde_json::to_string(&kind).unwrap();
        let back: ProposalKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, kind);
    }

    #[test]
    fn unit_variant_backward_compat_deserialize() {
        // Old-format plain-string unit variants must still deserialize even
        // when SourceEdit is present in the enum.
        let cases = [
            (r#""switch_preset""#, ProposalKind::SwitchPreset),
            (r#""adjust_verbosity""#, ProposalKind::AdjustVerbosity),
            (r#""learn_extension""#, ProposalKind::LearnExtension),
        ];
        for (json, expected) in cases {
            let got: ProposalKind = serde_json::from_str(json).unwrap();
            assert_eq!(got, expected, "failed for json: {json}");
        }
    }

    #[test]
    fn source_edit_kind_not_affected_by_as_str_call() {
        // as_str now takes &self, so the value is still usable afterwards.
        let kind = ProposalKind::SourceEdit {
            patch_path: std::path::PathBuf::from("p.patch"),
            diff_sha256: "ff".into(),
            target_paths: vec![],
        };
        let s = kind.as_str(); // borrows, does NOT move
        assert_eq!(s, "source_edit");
        // kind still accessible:
        assert!(matches!(kind, ProposalKind::SourceEdit { .. }));
    }
}
