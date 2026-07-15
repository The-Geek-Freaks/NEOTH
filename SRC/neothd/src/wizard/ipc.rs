//! W-07 — wizard IPC channel primitive.
//!
//! GUI + CLI wizard surfaces both consume the same data shapes
//! so the operator's pick on one side reaches the other without
//! a re-prompt. The GUI's Slint view and the CLI's clap dialogs
//! both serialise into [`WizardIpcMessage`] flowing over a
//! shared MPSC channel inside the daemon.
//!
//! ## What ships here
//!
//! - [`WizardIpcMessage`] — every message type the protocol
//!   carries. Tagged-enum snake_case wire form.
//! - [`WizardStepId`] — pinned enum of every wizard step both
//!   surfaces support.
//! - Constructors + accessors so producer + consumer side never
//!   reach into the inner variant data directly.
//!
//! ## What's NOT here
//!
//! - The Slint GUI itself (separate crate; landed when the
//!   `neothd-gui` workspace member adds the bindings).
//! - The actual MPSC wire-up (lands when `cli::serve` opens the
//!   channel + the GUI process connects).

use serde::{Deserialize, Serialize};

use crate::installers::detect::DetectReport;
use crate::wizard::recommend::{
    ChannelRecommendation, ComplexityLevel, ExperienceLevel, Recommendation, VpnRecommendation,
};

/// One wizard step. Pinned snake_case wire form so the GUI's
/// step-progress bar + the CLI's progress messages stay synced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WizardStepId {
    /// 0 — welcome screen, mode pick (GUI vs CLI).
    Welcome,
    /// 1 — operator experience-level pick + privacy posture.
    ExperienceLevel,
    /// 2 — system detection (W-04 detect_step).
    Detect,
    /// 3 — review recommendations (W-03 recommend).
    Recommend,
    /// 4 — optional installer chain (W-05 install_step).
    Install,
    /// 5 — provider + CLI picker.
    Provider,
    /// 6 — credential import (C-05 wizard_step).
    Credentials,
    /// 7 — Obsidian vault setup.
    Vault,
    /// 8 — finalise + persist WizardStateV2.
    Finish,
}

impl WizardStepId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Welcome => "welcome",
            Self::ExperienceLevel => "experience_level",
            Self::Detect => "detect",
            Self::Recommend => "recommend",
            Self::Install => "install",
            Self::Provider => "provider",
            Self::Credentials => "credentials",
            Self::Vault => "vault",
            Self::Finish => "finish",
        }
    }

    /// Numeric step index (1-based for the operator-facing
    /// "Step N of M" banner). Welcome = 1.
    pub fn step_number(self) -> u8 {
        match self {
            Self::Welcome => 1,
            Self::ExperienceLevel => 2,
            Self::Detect => 3,
            Self::Recommend => 4,
            Self::Install => 5,
            Self::Provider => 6,
            Self::Credentials => 7,
            Self::Vault => 8,
            Self::Finish => 9,
        }
    }

    pub const TOTAL_STEPS: u8 = 9;
}

/// Operator's progress through the wizard. Both surfaces tick
/// the same shape so a CLI session can hand off to a GUI session
/// mid-wizard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WizardProgress {
    pub current_step: WizardStepId,
    pub completed_steps: Vec<WizardStepId>,
}

impl WizardProgress {
    pub fn at(current_step: WizardStepId) -> Self {
        Self {
            current_step,
            completed_steps: Vec::new(),
        }
    }

    pub fn completed_step_count(&self) -> usize {
        self.completed_steps.len()
    }

    /// Mark `step` as complete if it isn't already, then advance
    /// `current_step` to the supplied next step.
    pub fn complete_and_advance(&mut self, just_finished: WizardStepId, next: WizardStepId) {
        if !self.completed_steps.contains(&just_finished) {
            self.completed_steps.push(just_finished);
        }
        self.current_step = next;
    }
}

/// Every message type that flows between the GUI + CLI wizards.
/// Tagged enum so the wire form carries an explicit `"kind"`
/// discriminator — easy to dispatch in Slint + clap callbacks
/// alike.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WizardIpcMessage {
    /// Producer signals the operator started a wizard step. The
    /// receiving surface focuses its UI on the matching panel.
    StepStarted { step: WizardStepId },

    /// Operator picked an experience level (Beginner /
    /// Intermediate / Advanced) + privacy posture.
    ExperienceLevelSelected {
        experience: ExperienceLevel,
        privacy_first: bool,
    },

    /// W-04 detect-step published a DetectReport snapshot.
    DetectReportReady { report: DetectReport },

    /// W-03 recommendation engine published a Recommendation.
    /// The receiving surface renders + lets the operator override.
    RecommendationReady { recommendation: Recommendation },

    /// Operator overrode the recommended channel (CLI → Telegram
    /// → Telegram → Slack).
    ChannelOverride { channel: ChannelRecommendation },

    /// Operator overrode the recommended VPN posture.
    VpnOverride { vpn: VpnRecommendation },

    /// Operator overrode the recommended complexity level
    /// (controls collapsed-panel decisions in the GUI).
    ComplexityOverride { complexity: ComplexityLevel },

    /// Operator finished a step. Receiving surface advances its
    /// progress + focuses the next panel.
    StepCompleted { step: WizardStepId },

    /// Operator cancelled the wizard. The daemon drops to the
    /// previous-good WizardStateV2 (no partial commit).
    Cancelled { from_step: WizardStepId },

    /// Wizard finished — last step committed WizardStateV2.
    Finished,
}

impl WizardIpcMessage {
    /// The `"kind"` discriminator value (matches the tag serde
    /// emits). Pinned for audit + GUI dispatch.
    pub fn kind_tag(&self) -> &'static str {
        match self {
            Self::StepStarted { .. } => "step_started",
            Self::ExperienceLevelSelected { .. } => "experience_level_selected",
            Self::DetectReportReady { .. } => "detect_report_ready",
            Self::RecommendationReady { .. } => "recommendation_ready",
            Self::ChannelOverride { .. } => "channel_override",
            Self::VpnOverride { .. } => "vpn_override",
            Self::ComplexityOverride { .. } => "complexity_override",
            Self::StepCompleted { .. } => "step_completed",
            Self::Cancelled { .. } => "cancelled",
            Self::Finished => "finished",
        }
    }

    /// True when this message represents operator-pick input
    /// (the receiving surface should treat it as a state mutation
    /// to fold into its WizardStateV2 staging area).
    pub fn is_operator_input(&self) -> bool {
        matches!(
            self,
            Self::ExperienceLevelSelected { .. }
                | Self::ChannelOverride { .. }
                | Self::VpnOverride { .. }
                | Self::ComplexityOverride { .. }
                | Self::Cancelled { .. }
        )
    }

    /// True when this message is a daemon-produced status update
    /// (no operator decision required).
    pub fn is_daemon_status(&self) -> bool {
        matches!(
            self,
            Self::StepStarted { .. }
                | Self::DetectReportReady { .. }
                | Self::RecommendationReady { .. }
                | Self::StepCompleted { .. }
                | Self::Finished
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installers::gpu::{GpuKind, GpuReport};

    fn fresh_detect() -> DetectReport {
        DetectReport {
            probed_at_unix: 1_700_000_000,
            docker_version: Some("25.0.0".into()),
            docker_compose_version: None,
            docker_compose_legacy_version: None,
            npm_version: None,
            node_version: None,
            git_version: None,
            ffmpeg_version: None,
            gpu: Some(GpuReport {
                kind: GpuKind::Cuda,
                vram_mib: Some(24_000),
                vendor: Some("NVIDIA".into()),
                name: None,
            }),
            disk_free_bytes: None,
        }
    }

    fn fresh_recommendation() -> Recommendation {
        Recommendation {
            model_tier: "qwen2.5-7b".into(),
            offer_gpu_toggles: true,
            default_channel: ChannelRecommendation::Telegram,
            vpn: VpnRecommendation::Tailscale,
            complexity: ComplexityLevel::Standard,
            skip_optional_installers: false,
            reasoning: vec!["GPU detected".into()],
        }
    }

    // ── WizardStepId ──────────────────────────────────────────────

    #[test]
    fn step_id_as_str_pinned() {
        assert_eq!(WizardStepId::Welcome.as_str(), "welcome");
        assert_eq!(WizardStepId::ExperienceLevel.as_str(), "experience_level");
        assert_eq!(WizardStepId::Detect.as_str(), "detect");
        assert_eq!(WizardStepId::Recommend.as_str(), "recommend");
        assert_eq!(WizardStepId::Install.as_str(), "install");
        assert_eq!(WizardStepId::Provider.as_str(), "provider");
        assert_eq!(WizardStepId::Credentials.as_str(), "credentials");
        assert_eq!(WizardStepId::Vault.as_str(), "vault");
        assert_eq!(WizardStepId::Finish.as_str(), "finish");
    }

    #[test]
    fn step_number_increasing_and_total_pinned() {
        let order = [
            WizardStepId::Welcome,
            WizardStepId::ExperienceLevel,
            WizardStepId::Detect,
            WizardStepId::Recommend,
            WizardStepId::Install,
            WizardStepId::Provider,
            WizardStepId::Credentials,
            WizardStepId::Vault,
            WizardStepId::Finish,
        ];
        let mut prev: u8 = 0;
        for s in order {
            let n = s.step_number();
            assert!(n > prev, "step {s:?} number not increasing");
            prev = n;
        }
        assert_eq!(WizardStepId::TOTAL_STEPS, 9);
        assert_eq!(WizardStepId::Finish.step_number(), 9);
    }

    #[test]
    fn step_id_snake_case_serde() {
        assert_eq!(
            serde_json::to_string(&WizardStepId::ExperienceLevel).unwrap(),
            "\"experience_level\"",
        );
    }

    // ── WizardProgress ────────────────────────────────────────────

    #[test]
    fn progress_at_initialises_empty_completed_list() {
        let p = WizardProgress::at(WizardStepId::Welcome);
        assert_eq!(p.current_step, WizardStepId::Welcome);
        assert_eq!(p.completed_step_count(), 0);
    }

    #[test]
    fn complete_and_advance_appends_unique() {
        let mut p = WizardProgress::at(WizardStepId::Welcome);
        p.complete_and_advance(WizardStepId::Welcome, WizardStepId::ExperienceLevel);
        assert_eq!(p.current_step, WizardStepId::ExperienceLevel);
        assert_eq!(p.completed_step_count(), 1);
        // Re-complete same step → no duplicate.
        p.complete_and_advance(WizardStepId::Welcome, WizardStepId::Detect);
        assert_eq!(p.completed_step_count(), 1);
        assert_eq!(p.current_step, WizardStepId::Detect);
    }

    #[test]
    fn complete_and_advance_tracks_distinct_steps() {
        let mut p = WizardProgress::at(WizardStepId::Welcome);
        p.complete_and_advance(WizardStepId::Welcome, WizardStepId::ExperienceLevel);
        p.complete_and_advance(WizardStepId::ExperienceLevel, WizardStepId::Detect);
        assert_eq!(p.completed_step_count(), 2);
        assert!(p.completed_steps.contains(&WizardStepId::Welcome));
        assert!(p.completed_steps.contains(&WizardStepId::ExperienceLevel));
    }

    // ── WizardIpcMessage ──────────────────────────────────────────

    #[test]
    fn kind_tag_pinned_for_audit_dispatch() {
        let m = WizardIpcMessage::StepStarted {
            step: WizardStepId::Detect,
        };
        assert_eq!(m.kind_tag(), "step_started");

        assert_eq!(WizardIpcMessage::Finished.kind_tag(), "finished",);
        assert_eq!(
            WizardIpcMessage::Cancelled {
                from_step: WizardStepId::Detect,
            }
            .kind_tag(),
            "cancelled",
        );
    }

    #[test]
    fn message_classifier_operator_input_vs_daemon_status() {
        // Operator input.
        let op_msgs = [
            WizardIpcMessage::ExperienceLevelSelected {
                experience: ExperienceLevel::Intermediate,
                privacy_first: false,
            },
            WizardIpcMessage::ChannelOverride {
                channel: ChannelRecommendation::Cli,
            },
            WizardIpcMessage::VpnOverride {
                vpn: VpnRecommendation::None,
            },
            WizardIpcMessage::ComplexityOverride {
                complexity: ComplexityLevel::Minimal,
            },
            WizardIpcMessage::Cancelled {
                from_step: WizardStepId::Detect,
            },
        ];
        for m in &op_msgs {
            assert!(m.is_operator_input(), "{m:?} should be operator input");
            assert!(!m.is_daemon_status());
        }

        // Daemon status.
        let daemon_msgs = [
            WizardIpcMessage::StepStarted {
                step: WizardStepId::Welcome,
            },
            WizardIpcMessage::DetectReportReady {
                report: fresh_detect(),
            },
            WizardIpcMessage::RecommendationReady {
                recommendation: fresh_recommendation(),
            },
            WizardIpcMessage::StepCompleted {
                step: WizardStepId::Welcome,
            },
            WizardIpcMessage::Finished,
        ];
        for m in &daemon_msgs {
            assert!(m.is_daemon_status(), "{m:?} should be daemon status");
            assert!(!m.is_operator_input());
        }
    }

    #[test]
    fn message_serde_tagged_kind_field_present() {
        let m = WizardIpcMessage::DetectReportReady {
            report: fresh_detect(),
        };
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("\"kind\":\"detect_report_ready\""));
        assert!(json.contains("\"report\""));
    }

    #[test]
    fn message_serde_roundtrip_recommendation_ready() {
        let m = WizardIpcMessage::RecommendationReady {
            recommendation: fresh_recommendation(),
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: WizardIpcMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn message_serde_roundtrip_experience_selected() {
        let m = WizardIpcMessage::ExperienceLevelSelected {
            experience: ExperienceLevel::Beginner,
            privacy_first: true,
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: WizardIpcMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn message_serde_finished_has_no_payload_field() {
        let m = WizardIpcMessage::Finished;
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("\"kind\":\"finished\""));
    }

    #[test]
    fn channel_override_round_trip() {
        let m = WizardIpcMessage::ChannelOverride {
            channel: ChannelRecommendation::Telegram,
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: WizardIpcMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn cancelled_message_carries_from_step() {
        let m = WizardIpcMessage::Cancelled {
            from_step: WizardStepId::Credentials,
        };
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("\"from_step\":\"credentials\""));
    }

    #[test]
    fn step_id_total_steps_matches_finish_step_number() {
        // Drift guard — adding a step requires bumping TOTAL_STEPS.
        assert_eq!(
            WizardStepId::TOTAL_STEPS,
            WizardStepId::Finish.step_number()
        );
    }
}
