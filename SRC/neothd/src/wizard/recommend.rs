//! W-03 — RecommendationEngine.
//!
//! Pure-fn engine that consumes a [`crate::installers::detect::
//! DetectReport`] + operator preferences + produces a
//! [`Recommendation`] the wizard surfaces as "here's what we
//! suggest; override anything you want".
//!
//! All decisions are based on already-detected facts; the engine
//! itself does NO I/O so the wizard can re-run it cheaply when
//! the operator toggles a preference.
//!
//! ## W-03a sub-item
//!
//! Exposes [`operator_complexity_level`] — same signature for both
//! W-03 (wizard recommendation) and GU-03 (GUI panel-collapse rule
//! engine at v1.0). Single source of truth so the GUI's "show
//! advanced toggles?" decision doesn't drift from the wizard's
//! "auto-select model tier?" decision.

use serde::{Deserialize, Serialize};

use crate::installers::detect::DetectReport;

/// Operator's self-declared experience level. Passed in from the
/// wizard's first-screen prompt (or `freedom.yaml::operator.
/// experience_level` for non-wizard reloads).
///
/// `Default == Beginner` — when an aborted wizard or a missing field
/// lands here, the safest first-run flow is the most hand-holding
/// one. Power operators explicitly pick `Advanced` in step 1c.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExperienceLevel {
    /// "Alex's mom" — never touched a CLI; needs every default
    /// chosen for her + most toggles hidden.
    #[default]
    Beginner,
    /// Comfortable with a terminal; will edit `freedom.yaml`; wants
    /// recommended defaults but visible toggles.
    Intermediate,
    /// Power user; treats defaults as a starting point + wants
    /// every advanced surface visible from day one.
    Advanced,
}

impl ExperienceLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Beginner => "beginner",
            Self::Intermediate => "intermediate",
            Self::Advanced => "advanced",
        }
    }
}

/// W-03a output. GU-03 reads this to decide which advanced
/// panels are collapsed by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplexityLevel {
    /// Collapse every advanced panel; show beginner-summary view.
    Minimal,
    /// Show common operator panels expanded, advanced collapsed.
    Standard,
    /// Show everything expanded.
    Full,
}

impl ComplexityLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Standard => "standard",
            Self::Full => "full",
        }
    }
}

/// W-03a entry point. Stable mapping between experience + system
/// capability:
///
///   - Advanced operator → Full regardless of system.
///   - Intermediate → Standard.
///   - Beginner → Minimal.
///
/// The engine intentionally does NOT down-tune Advanced to
/// Minimal even on a low-spec machine — power users on slow
/// hardware still want to see every knob.
pub fn operator_complexity_level(experience: ExperienceLevel) -> ComplexityLevel {
    match experience {
        ExperienceLevel::Beginner => ComplexityLevel::Minimal,
        ExperienceLevel::Intermediate => ComplexityLevel::Standard,
        ExperienceLevel::Advanced => ComplexityLevel::Full,
    }
}

/// Channel recommendation. The wizard picks one as the default
/// channel + offers the others as opt-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelRecommendation {
    Cli,
    Telegram,
    Keet,
    Slack,
}

impl ChannelRecommendation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Telegram => "telegram",
            Self::Keet => "keet",
            Self::Slack => "slack",
        }
    }
}

/// VPN/transport recommendation. Beginner gets `None` (skip the
/// VPN step entirely); advanced operators see all options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VpnRecommendation {
    None,
    Tailscale,
    Hysteria2,
}

impl VpnRecommendation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Tailscale => "tailscale",
            Self::Hysteria2 => "hysteria2",
        }
    }
}

/// One full wizard recommendation. Operator overrides any field;
/// the wizard recomputes the rest if needed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recommendation {
    /// `"qwen2.5-72b"` / `"qwen2.5-7b"` / `"cloud"` — same string
    /// the GpuReport tier accessor produces, so downstream model-
    /// fetch logic deduplicates on it.
    pub model_tier: String,
    /// Whether the wizard should offer GPU acceleration toggles.
    /// False on Cpu-only systems.
    pub offer_gpu_toggles: bool,
    pub default_channel: ChannelRecommendation,
    pub vpn: VpnRecommendation,
    pub complexity: ComplexityLevel,
    /// True when the wizard should skip the "optional installer"
    /// chain (paperless / n8n / OBS) entirely — Beginner default
    /// is to focus on the chat surface.
    pub skip_optional_installers: bool,
    /// Operator-readable explanation of why these picks were made.
    /// Shown in the wizard summary screen so the operator sees the
    /// reasoning + can override with intent.
    pub reasoning: Vec<String>,
}

/// Compute a recommendation from the detected system + operator
/// experience level + a hint about whether the operator has
/// declared they want a "private-by-default" posture.
pub fn recommend(
    report: &DetectReport,
    experience: ExperienceLevel,
    privacy_first: bool,
) -> Recommendation {
    let mut reasoning: Vec<String> = Vec::new();

    // Model tier — VRAM driven (W-03 spec).
    let (model_tier, offer_gpu_toggles) = match &report.gpu {
        Some(g) => {
            let tier = g.recommended_model_tier();
            reasoning.push(format!(
                "GPU {} with {} MiB VRAM → tier '{}'",
                g.kind.as_str(),
                g.vram_mib.unwrap_or(0),
                tier,
            ));
            (tier.to_string(), g.kind.can_accelerate())
        }
        None => {
            reasoning.push("No GPU detected → cloud tier with CPU fallback".to_string());
            ("cloud".to_string(), false)
        }
    };

    // Channel — start with CLI for beginner (single surface, no
    // bot tokens to manage); intermediate keeps Telegram default
    // because that's the broadest operator install base.
    let default_channel = match experience {
        ExperienceLevel::Beginner => {
            reasoning.push("Beginner → CLI-only first surface".to_string());
            ChannelRecommendation::Cli
        }
        ExperienceLevel::Intermediate => {
            reasoning.push("Intermediate → Telegram (broadest install base)".to_string());
            ChannelRecommendation::Telegram
        }
        ExperienceLevel::Advanced => {
            reasoning.push("Advanced → Keet (best privacy default for power users)".to_string());
            ChannelRecommendation::Keet
        }
    };

    // VPN — beginner skips, intermediate picks Tailscale (easiest),
    // advanced + privacy_first picks Hysteria2.
    let vpn = match (experience, privacy_first) {
        (ExperienceLevel::Beginner, _) => {
            reasoning.push("Beginner → no VPN step".to_string());
            VpnRecommendation::None
        }
        (ExperienceLevel::Intermediate, false) => {
            reasoning.push("Intermediate → Tailscale (easy install)".to_string());
            VpnRecommendation::Tailscale
        }
        (ExperienceLevel::Intermediate, true) => {
            reasoning.push("Intermediate + privacy_first → Hysteria2".to_string());
            VpnRecommendation::Hysteria2
        }
        (ExperienceLevel::Advanced, true) => {
            reasoning.push("Advanced + privacy_first → Hysteria2".to_string());
            VpnRecommendation::Hysteria2
        }
        (ExperienceLevel::Advanced, false) => {
            reasoning.push("Advanced → Tailscale (mesh by default)".to_string());
            VpnRecommendation::Tailscale
        }
    };

    let complexity = operator_complexity_level(experience);
    let skip_optional_installers = matches!(experience, ExperienceLevel::Beginner);
    if skip_optional_installers {
        reasoning.push("Beginner → skip optional installers (focus on chat surface)".to_string());
    }

    Recommendation {
        model_tier,
        offer_gpu_toggles,
        default_channel,
        vpn,
        complexity,
        skip_optional_installers,
        reasoning,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installers::detect::DetectReport;
    use crate::installers::gpu::{GpuKind, GpuReport};

    fn report_with_gpu(gpu: Option<GpuReport>) -> DetectReport {
        DetectReport {
            probed_at_unix: 0,
            docker_version: None,
            docker_compose_version: None,
            docker_compose_legacy_version: None,
            npm_version: None,
            node_version: None,
            git_version: None,
            ffmpeg_version: None,
            gpu,
            disk_free_bytes: None,
        }
    }

    fn gpu(kind: GpuKind, vram_mib: u32) -> GpuReport {
        GpuReport {
            kind,
            vram_mib: Some(vram_mib),
            vendor: None,
            name: None,
        }
    }

    // ── enum surface ──────────────────────────────────────────────

    #[test]
    fn experience_as_str_pinned() {
        assert_eq!(ExperienceLevel::Beginner.as_str(), "beginner");
        assert_eq!(ExperienceLevel::Intermediate.as_str(), "intermediate");
        assert_eq!(ExperienceLevel::Advanced.as_str(), "advanced");
    }

    #[test]
    fn complexity_as_str_pinned() {
        assert_eq!(ComplexityLevel::Minimal.as_str(), "minimal");
        assert_eq!(ComplexityLevel::Standard.as_str(), "standard");
        assert_eq!(ComplexityLevel::Full.as_str(), "full");
    }

    #[test]
    fn channel_as_str_pinned() {
        assert_eq!(ChannelRecommendation::Cli.as_str(), "cli");
        assert_eq!(ChannelRecommendation::Telegram.as_str(), "telegram");
        assert_eq!(ChannelRecommendation::Keet.as_str(), "keet");
        assert_eq!(ChannelRecommendation::Slack.as_str(), "slack");
    }

    #[test]
    fn vpn_as_str_pinned() {
        assert_eq!(VpnRecommendation::None.as_str(), "none");
        assert_eq!(VpnRecommendation::Tailscale.as_str(), "tailscale");
        assert_eq!(VpnRecommendation::Hysteria2.as_str(), "hysteria2");
    }

    // ── W-03a ─────────────────────────────────────────────────────

    #[test]
    fn complexity_level_beginner_minimal() {
        assert_eq!(
            operator_complexity_level(ExperienceLevel::Beginner),
            ComplexityLevel::Minimal,
        );
    }

    #[test]
    fn complexity_level_intermediate_standard() {
        assert_eq!(
            operator_complexity_level(ExperienceLevel::Intermediate),
            ComplexityLevel::Standard,
        );
    }

    #[test]
    fn complexity_level_advanced_full() {
        assert_eq!(
            operator_complexity_level(ExperienceLevel::Advanced),
            ComplexityLevel::Full,
        );
    }

    // ── model tier ────────────────────────────────────────────────

    #[test]
    fn recommend_72b_for_24gib_cuda() {
        let r = recommend(
            &report_with_gpu(Some(gpu(GpuKind::Cuda, 24 * 1024))),
            ExperienceLevel::Intermediate,
            false,
        );
        assert_eq!(r.model_tier, "qwen2.5-72b");
        assert!(r.offer_gpu_toggles);
    }

    #[test]
    fn recommend_7b_for_16gib_cuda() {
        let r = recommend(
            &report_with_gpu(Some(gpu(GpuKind::Cuda, 16 * 1024))),
            ExperienceLevel::Intermediate,
            false,
        );
        assert_eq!(r.model_tier, "qwen2.5-7b");
    }

    #[test]
    fn recommend_cloud_for_low_vram() {
        let r = recommend(
            &report_with_gpu(Some(gpu(GpuKind::Cuda, 4 * 1024))),
            ExperienceLevel::Intermediate,
            false,
        );
        assert_eq!(r.model_tier, "cloud");
        // Still offers GPU toggles (operator has a GPU even if VRAM
        // is too small for local model).
        assert!(r.offer_gpu_toggles);
    }

    #[test]
    fn recommend_cloud_for_cpu_only_no_gpu_toggles() {
        let r = recommend(&report_with_gpu(None), ExperienceLevel::Intermediate, false);
        assert_eq!(r.model_tier, "cloud");
        assert!(!r.offer_gpu_toggles);
    }

    #[test]
    fn recommend_cloud_for_cpu_kind_no_gpu_toggles() {
        let r = recommend(
            &report_with_gpu(Some(GpuReport::cpu())),
            ExperienceLevel::Intermediate,
            false,
        );
        assert_eq!(r.model_tier, "cloud");
        assert!(!r.offer_gpu_toggles);
    }

    // ── channel ───────────────────────────────────────────────────

    #[test]
    fn recommend_beginner_default_channel_is_cli() {
        let r = recommend(&report_with_gpu(None), ExperienceLevel::Beginner, false);
        assert_eq!(r.default_channel, ChannelRecommendation::Cli);
    }

    #[test]
    fn recommend_intermediate_default_channel_is_telegram() {
        let r = recommend(&report_with_gpu(None), ExperienceLevel::Intermediate, false);
        assert_eq!(r.default_channel, ChannelRecommendation::Telegram);
    }

    #[test]
    fn recommend_advanced_default_channel_is_keet() {
        let r = recommend(&report_with_gpu(None), ExperienceLevel::Advanced, false);
        assert_eq!(r.default_channel, ChannelRecommendation::Keet);
    }

    // ── vpn ───────────────────────────────────────────────────────

    #[test]
    fn recommend_beginner_no_vpn() {
        let r = recommend(&report_with_gpu(None), ExperienceLevel::Beginner, true);
        assert_eq!(r.vpn, VpnRecommendation::None);
    }

    #[test]
    fn recommend_intermediate_default_tailscale() {
        let r = recommend(&report_with_gpu(None), ExperienceLevel::Intermediate, false);
        assert_eq!(r.vpn, VpnRecommendation::Tailscale);
    }

    #[test]
    fn recommend_intermediate_privacy_first_hysteria2() {
        let r = recommend(&report_with_gpu(None), ExperienceLevel::Intermediate, true);
        assert_eq!(r.vpn, VpnRecommendation::Hysteria2);
    }

    #[test]
    fn recommend_advanced_default_tailscale() {
        let r = recommend(&report_with_gpu(None), ExperienceLevel::Advanced, false);
        assert_eq!(r.vpn, VpnRecommendation::Tailscale);
    }

    #[test]
    fn recommend_advanced_privacy_first_hysteria2() {
        let r = recommend(&report_with_gpu(None), ExperienceLevel::Advanced, true);
        assert_eq!(r.vpn, VpnRecommendation::Hysteria2);
    }

    // ── complexity flow-through ───────────────────────────────────

    #[test]
    fn recommend_complexity_matches_w03a() {
        for exp in [
            ExperienceLevel::Beginner,
            ExperienceLevel::Intermediate,
            ExperienceLevel::Advanced,
        ] {
            let r = recommend(&report_with_gpu(None), exp, false);
            assert_eq!(r.complexity, operator_complexity_level(exp));
        }
    }

    // ── skip_optional_installers ──────────────────────────────────

    #[test]
    fn recommend_beginner_skips_optional_installers() {
        let r = recommend(&report_with_gpu(None), ExperienceLevel::Beginner, false);
        assert!(r.skip_optional_installers);
    }

    #[test]
    fn recommend_intermediate_keeps_optional_installers() {
        let r = recommend(&report_with_gpu(None), ExperienceLevel::Intermediate, false);
        assert!(!r.skip_optional_installers);
    }

    #[test]
    fn recommend_advanced_keeps_optional_installers() {
        let r = recommend(&report_with_gpu(None), ExperienceLevel::Advanced, false);
        assert!(!r.skip_optional_installers);
    }

    // ── reasoning ─────────────────────────────────────────────────

    #[test]
    fn reasoning_lines_are_non_empty_for_any_input() {
        for exp in [
            ExperienceLevel::Beginner,
            ExperienceLevel::Intermediate,
            ExperienceLevel::Advanced,
        ] {
            for privacy in [false, true] {
                let r = recommend(&report_with_gpu(None), exp, privacy);
                assert!(!r.reasoning.is_empty(), "{exp:?}+{privacy}");
            }
        }
    }

    #[test]
    fn reasoning_mentions_gpu_when_present() {
        let r = recommend(
            &report_with_gpu(Some(gpu(GpuKind::Cuda, 24 * 1024))),
            ExperienceLevel::Intermediate,
            false,
        );
        let joined = r.reasoning.join(" ");
        assert!(joined.contains("GPU"));
        assert!(joined.contains("cuda"));
    }

    #[test]
    fn recommendation_serde_roundtrip() {
        let r = recommend(
            &report_with_gpu(Some(gpu(GpuKind::Cuda, 24 * 1024))),
            ExperienceLevel::Advanced,
            true,
        );
        let json = serde_json::to_string(&r).unwrap();
        let back: Recommendation = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn experience_snake_case_serde() {
        assert_eq!(
            serde_json::to_string(&ExperienceLevel::Intermediate).unwrap(),
            "\"intermediate\"",
        );
    }
}
