//! W-06 — `WizardStateV2`.
//!
//! Operators who started NEOTH on v0.2 ran the wizard once + their
//! `~/.neoth/freedom.yaml` carries the v0.2 fields verbatim
//! (`operator_id`, `role`, `provider_kind`, `steps_completed`, …).
//! v0.3+ wizard adds new fields (detect-report snapshot, GPU
//! recommendation, experience level, privacy posture, completed-
//! step set v2). v0.2 fields MUST NOT silently drop on a re-save
//! — operators expect their existing config to round-trip.
//!
//! `WizardStateV2` solves this via `#[serde(flatten)] base:
//! BaseFields` so v0.2 keys land at the top of the YAML
//! unchanged + v0.3 keys live alongside under their own names.
//! Loading a v0.2 file via serde produces `WizardStateV2 { base:
//! <v0.2 fields>, v2: defaults }`; saving it back preserves
//! every key the operator typed.
//!
//! ## What's NOT here
//!
//! - The full `FreedomConfig` shape. `WizardStateV2` is the
//!   wizard's intermediate persistence — it owns ONLY the fields
//!   the wizard wrote. The daemon's `FreedomConfig` reads its own
//!   YAML; both formats overlap on operator_id/role/provider_kind
//!   but the wizard state file lives at
//!   `~/.neoth/wizard_state_v2.yaml` to avoid two-writer drift.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::installers::detect::DetectReport;
use crate::wizard::recommend::{
    ChannelRecommendation, ComplexityLevel, ExperienceLevel, VpnRecommendation,
};

/// v0.2-shape fields the wizard wrote before W-06 landed.
/// Pinned exhaustively — adding a new v0.2-era field needs an
/// upgrade migration not a silent default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaseFields {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_kind: Option<String>,
    /// v0.2 wizard's step tracker — kept verbatim so v0.2 wizard
    /// behaviour stays identical for un-upgraded operators.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps_completed: Vec<u32>,
}

/// v2-only fields. Each is `#[serde(default)]` so a v0.2 file
/// without them parses cleanly into `Default::default()` values.
///
/// Note: `Default` is hand-rolled (not `#[derive(Default)]`)
/// because `state_version` defaults to 1 — `u32::default()` would
/// give 0 which the `is_pre_v2()` check disagrees with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct V2Fields {
    /// Operator's self-declared experience level (Beginner /
    /// Intermediate / Advanced). Drives the W-03
    /// RecommendationEngine + W-03a complexity-level decisions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub experience_level: Option<ExperienceLevel>,
    /// True when the operator picked the "privacy-first" branch
    /// (Hysteria2 VPN, no cloud fallback, paperless-only-local).
    /// Skips on serialize when false so v0.2 round-trip stays
    /// byte-clean.
    #[serde(default, skip_serializing_if = "is_false")]
    pub privacy_first: bool,
    /// Snapshot of the W-01 DetectReport at wizard time. Kept so
    /// the wizard's "what we found" page can render the same data
    /// without re-probing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detect_snapshot: Option<DetectReport>,
    /// Default channel the W-03 engine picked for this operator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommended_channel: Option<ChannelRecommendation>,
    /// VPN posture the W-03 engine picked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommended_vpn: Option<VpnRecommendation>,
    /// Complexity level operator-facing UIs default to (collapsed-
    /// panel decisions etc). Read by GU-03.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub complexity_level: Option<ComplexityLevel>,
    /// v2 wizard's step tracker — separate from the v0.2
    /// `steps_completed` so re-running a v0.2 step doesn't bump
    /// the v2 counter and vice-versa.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps_completed_v2: Vec<String>,
    /// Schema version. v0.2 files have no `state_version`, which
    /// defaults to 1; v2 saves write 2. Drift-guard so a future
    /// v3 wizard can detect "stale v2 state" without re-parsing.
    /// Skipped on serialize when equal to the default (1) so
    /// v0.2 round-trip stays byte-clean — wizard upgrade bumps
    /// to 2 which then appears.
    #[serde(
        default = "default_version",
        skip_serializing_if = "is_default_version"
    )]
    pub state_version: u32,
}

fn default_version() -> u32 {
    1
}

fn is_default_version(v: &u32) -> bool {
    *v == default_version()
}

fn is_false(v: &bool) -> bool {
    !*v
}

impl Default for V2Fields {
    fn default() -> Self {
        Self {
            experience_level: None,
            privacy_first: false,
            detect_snapshot: None,
            recommended_channel: None,
            recommended_vpn: None,
            complexity_level: None,
            steps_completed_v2: Vec::new(),
            state_version: default_version(),
        }
    }
}

/// Full operator wizard state. v0.2 fields land at the top of
/// the YAML via flatten + v2 fields under their own keys.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WizardStateV2 {
    #[serde(flatten)]
    pub base: BaseFields,
    #[serde(flatten)]
    pub v2: V2Fields,
}

impl WizardStateV2 {
    /// Conventional path under the NEOTH home dir.
    pub fn default_path(home: &Path) -> PathBuf {
        home.join("wizard_state_v2.yaml")
    }

    /// True when the loaded YAML didn't carry any v2-specific key
    /// — an operator on v0.2 whose state hasn't been upgraded yet.
    /// The wizard's first v2 prompt consults this to decide
    /// whether to show "welcome back" vs "first run".
    pub fn is_pre_v2(&self) -> bool {
        self.v2.experience_level.is_none()
            && !self.v2.privacy_first
            && self.v2.detect_snapshot.is_none()
            && self.v2.recommended_channel.is_none()
            && self.v2.recommended_vpn.is_none()
            && self.v2.complexity_level.is_none()
            && self.v2.steps_completed_v2.is_empty()
            && self.v2.state_version == 1
    }

    /// Stamp the state as "this run finished a v2 upgrade" —
    /// bumps `state_version` to 2 + zeroes the v2-completion
    /// vector so subsequent runs see a clean slate. Idempotent.
    pub fn mark_v2_upgraded(&mut self) {
        self.v2.state_version = 2;
        if self.v2.steps_completed_v2.is_empty() {
            self.v2.steps_completed_v2 = vec!["welcome_v2".to_string()];
        }
    }

    /// Atomic save — `.tmp` + rename, Windows-safe. Same pattern
    /// as every other vault/state writer this session.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let body = serde_yaml::to_string(self).map_err(std::io::Error::other)?;
        let tmp = path.with_extension("yaml.tmp");
        std::fs::write(&tmp, body)?;
        // GOLD-HON-22: `rename` replaces an existing file atomically on BOTH
        // Unix and Windows (std uses MoveFileExW + MOVEFILE_REPLACE_EXISTING),
        // so we do NOT remove the target first — a remove-then-rename would
        // open a window where a concurrent reader observes NO file, which
        // would contradict the "Atomic save" guarantee in the doc above.
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Load — missing file returns the default state. Malformed
    /// YAML surfaces as an Err (operator must intervene; silently
    /// resetting would lose their config).
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let body = match std::fs::read_to_string(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(e) => return Err(e),
        };
        serde_yaml::from_str(&body).map_err(std::io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::installers::gpu::{GpuKind, GpuReport};

    fn fixture_detect() -> DetectReport {
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
                name: Some("RTX 4090".into()),
            }),
            disk_free_bytes: None,
        }
    }

    // ── default + pre-v2 detection ────────────────────────────────

    #[test]
    fn default_state_is_pre_v2() {
        let s = WizardStateV2::default();
        assert!(s.is_pre_v2());
        assert_eq!(s.v2.state_version, 1);
    }

    #[test]
    fn state_with_experience_level_is_not_pre_v2() {
        let mut s = WizardStateV2::default();
        s.v2.experience_level = Some(ExperienceLevel::Beginner);
        assert!(!s.is_pre_v2());
    }

    #[test]
    fn state_with_privacy_first_is_not_pre_v2() {
        let mut s = WizardStateV2::default();
        s.v2.privacy_first = true;
        assert!(!s.is_pre_v2());
    }

    #[test]
    fn state_with_v2_step_completion_is_not_pre_v2() {
        let mut s = WizardStateV2::default();
        s.v2.steps_completed_v2.push("welcome_v2".into());
        assert!(!s.is_pre_v2());
    }

    // ── mark_v2_upgraded ──────────────────────────────────────────

    #[test]
    fn mark_v2_upgraded_bumps_version_and_seeds_step() {
        let mut s = WizardStateV2::default();
        assert_eq!(s.v2.state_version, 1);
        assert!(s.v2.steps_completed_v2.is_empty());
        s.mark_v2_upgraded();
        assert_eq!(s.v2.state_version, 2);
        assert_eq!(s.v2.steps_completed_v2, vec!["welcome_v2"]);
    }

    #[test]
    fn mark_v2_upgraded_is_idempotent() {
        let mut s = WizardStateV2::default();
        s.mark_v2_upgraded();
        s.mark_v2_upgraded();
        assert_eq!(s.v2.state_version, 2);
        // Step list not duplicated — second call sees non-empty so leaves alone.
        assert_eq!(s.v2.steps_completed_v2.len(), 1);
    }

    // ── serde: v0.2 file round-trip ───────────────────────────────

    #[test]
    fn v02_yaml_parses_into_base_fields_with_default_v2() {
        // Real-world v0.2 freedom-yaml subset operators have on
        // disk. NEOTH v0.3 wizard must parse this cleanly.
        let yaml = r#"
operator_id: sam
role: developer
provider_kind: claude_cli
steps_completed:
- 1
- 2
- 3
- 4
"#;
        let s: WizardStateV2 = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(s.base.operator_id.as_deref(), Some("sam"));
        assert_eq!(s.base.role.as_deref(), Some("developer"));
        assert_eq!(s.base.provider_kind.as_deref(), Some("claude_cli"));
        assert_eq!(s.base.steps_completed, vec![1, 2, 3, 4]);
        // v2 fields default cleanly.
        assert!(s.is_pre_v2());
    }

    #[test]
    fn v2_save_preserves_v02_keys_at_top_level() {
        // Operator's v0.2 fields land at the top of the YAML
        // unchanged — flatten contract.
        let s = WizardStateV2 {
            base: BaseFields {
                operator_id: Some("sam".into()),
                role: Some("developer".into()),
                provider_kind: Some("claude_cli".into()),
                steps_completed: vec![1, 2, 3, 4],
            },
            v2: V2Fields::default(),
        };
        let yaml = serde_yaml::to_string(&s).unwrap();
        assert!(yaml.contains("operator_id: sam"));
        assert!(yaml.contains("role: developer"));
        assert!(yaml.contains("provider_kind: claude_cli"));
        assert!(yaml.contains("steps_completed:"));
    }

    #[test]
    fn v2_save_omits_empty_v2_fields_via_skip_serializing_if() {
        // Default V2Fields → no v2 keys appear in the YAML so a
        // v0.2 operator's file remains byte-identical until they
        // touch a v2 setting. Even state_version (which has a
        // default fn) skips on save when it equals 1 — preserves
        // v0.2 byte-clean round-trip.
        let s = WizardStateV2 {
            base: BaseFields {
                operator_id: Some("sam".into()),
                ..Default::default()
            },
            v2: V2Fields::default(),
        };
        let yaml = serde_yaml::to_string(&s).unwrap();
        assert!(!yaml.contains("experience_level"));
        assert!(!yaml.contains("privacy_first"));
        assert!(!yaml.contains("detect_snapshot"));
        assert!(!yaml.contains("steps_completed_v2"));
        assert!(!yaml.contains("state_version"));
    }

    #[test]
    fn state_version_emitted_after_upgrade() {
        // After `mark_v2_upgraded` bumps to version 2, the key
        // appears in the YAML so audit tooling can detect "this
        // operator has run a v2 wizard".
        let mut s = WizardStateV2::default();
        s.mark_v2_upgraded();
        let yaml = serde_yaml::to_string(&s).unwrap();
        assert!(yaml.contains("state_version: 2"));
    }

    #[test]
    fn v2_roundtrip_after_upgrade_preserves_every_field() {
        let mut s = WizardStateV2 {
            base: BaseFields {
                operator_id: Some("sam".into()),
                role: Some("developer".into()),
                provider_kind: Some("claude_cli".into()),
                steps_completed: vec![1, 2, 3, 4],
            },
            v2: V2Fields {
                experience_level: Some(ExperienceLevel::Intermediate),
                privacy_first: true,
                detect_snapshot: Some(fixture_detect()),
                recommended_channel: Some(ChannelRecommendation::Telegram),
                recommended_vpn: Some(VpnRecommendation::Hysteria2),
                complexity_level: Some(ComplexityLevel::Standard),
                steps_completed_v2: vec!["welcome_v2".into(), "channels".into()],
                state_version: 2,
            },
        };
        s.mark_v2_upgraded();
        let yaml = serde_yaml::to_string(&s).unwrap();
        let back: WizardStateV2 = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn v02_file_loaded_and_resaved_unchanged_above_below_flatten_boundary() {
        // Operator on v0.2 → NEOTH v0.3 daemon reads the file +
        // writes it back without touching the wizard. The v0.2
        // fields MUST survive verbatim (no silent default-fill).
        let v02 = "operator_id: sam\nrole: developer\n";
        let parsed: WizardStateV2 = serde_yaml::from_str(v02).unwrap();
        let resaved = serde_yaml::to_string(&parsed).unwrap();
        assert!(resaved.contains("operator_id: sam"));
        assert!(resaved.contains("role: developer"));
        // No v2 keys leaked into a passive read+write cycle (other
        // than state_version which is always present).
        for unwelcome in [
            "experience_level",
            "privacy_first",
            "detect_snapshot",
            "recommended_channel",
            "recommended_vpn",
            "complexity_level",
            "steps_completed_v2",
        ] {
            assert!(
                !resaved.contains(unwelcome),
                "v0.2 round-trip leaked v2 key {unwelcome}: {resaved}",
            );
        }
    }

    // ── load / save ───────────────────────────────────────────────

    #[test]
    fn save_load_roundtrip() {
        let home = tempfile::tempdir().unwrap();
        let path = WizardStateV2::default_path(home.path());
        let mut s = WizardStateV2::default();
        s.base.operator_id = Some("sam".into());
        s.v2.experience_level = Some(ExperienceLevel::Advanced);
        s.v2.privacy_first = true;
        s.mark_v2_upgraded();
        s.save(&path).unwrap();

        let loaded = WizardStateV2::load(&path).unwrap();
        assert_eq!(loaded, s);
    }

    #[test]
    fn load_missing_returns_default() {
        let home = tempfile::tempdir().unwrap();
        let path = WizardStateV2::default_path(home.path());
        let s = WizardStateV2::load(&path).unwrap();
        assert!(s.is_pre_v2());
    }

    #[test]
    fn load_malformed_yaml_returns_err() {
        let home = tempfile::tempdir().unwrap();
        let path = WizardStateV2::default_path(home.path());
        std::fs::write(&path, "this :: is :: not :: yaml :: ").unwrap();
        let result = WizardStateV2::load(&path);
        assert!(result.is_err(), "must error so operator notices");
    }

    #[test]
    fn save_atomic_no_tmp_file_lingers() {
        let home = tempfile::tempdir().unwrap();
        let path = WizardStateV2::default_path(home.path());
        WizardStateV2::default().save(&path).unwrap();
        let tmp = path.with_extension("yaml.tmp");
        assert!(!tmp.exists(), "tmp leaked: {tmp:?}");
    }

    #[test]
    fn save_overwrites_existing_atomically() {
        let home = tempfile::tempdir().unwrap();
        let path = WizardStateV2::default_path(home.path());
        let mut a = WizardStateV2::default();
        a.base.operator_id = Some("sam".into());
        a.save(&path).unwrap();
        let mut b = WizardStateV2::default();
        b.base.operator_id = Some("bob".into());
        b.save(&path).unwrap();
        let loaded = WizardStateV2::load(&path).unwrap();
        assert_eq!(loaded.base.operator_id.as_deref(), Some("bob"));
    }

    #[test]
    fn default_path_under_home() {
        let home = std::path::Path::new("/some/neoth/home");
        let p = WizardStateV2::default_path(home);
        assert!(p.starts_with(home));
        assert_eq!(
            p.file_name().unwrap().to_string_lossy(),
            "wizard_state_v2.yaml",
        );
    }
}
