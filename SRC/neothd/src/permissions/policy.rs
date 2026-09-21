//! Immutable autonomy-policy snapshots and stable action identifiers.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use super::{Action, AutonomyLevel, Decision};

pub const MAX_SKILL_AUTONOMY_OVERRIDES: usize = 128;

/// Canonical operator-facing Skill identity.  This is shared with skill
/// creation so config keys cannot name a package the runtime would reject.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct SkillId(String);

impl SkillId {
    pub fn parse(value: impl AsRef<str>) -> anyhow::Result<Self> {
        let value = value.as_ref();
        if value.is_empty() {
            anyhow::bail!("skill id must not be empty");
        }
        if value.len() > 64 {
            anyhow::bail!("skill id must be <= 64 chars (got {})", value.len());
        }
        if !value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
        {
            anyhow::bail!("skill id may only contain lowercase [a-z0-9_-]: {value}");
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str { &self.0 }
}

impl std::fmt::Display for SkillId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SkillId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

/// Stable, payload-free identifier for every runtime [`Action`] variant.
///
/// The exhaustive matches in [`Action::kind`] and [`Action::representative`]
/// deliberately make a new `Action` variant a compile error until its public
/// policy name and CLI representative are defined.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    Read,
    WriteNeothHome,
    WriteOutsideHome,
    ExecScripts,
    ExecArbitrary,
    PaidProviderCall,
    UnboundedPaidProviderCall,
    ExternalTtsSynthesis,
    ExternalHttpRequest,
    ChannelSend,
    DangerousTarget,
    McpToolInvocation,
    PatchApplyToRepo,
    ClusterPeerPairing,
    SelfBinaryReplace,
    ProactiveChannelSend,
    OsFileRead,
    OsFileWrite,
    OsAppLaunch,
    OsClipboardRead,
    OsClipboardWrite,
    ClusterTaskAccept,
    ExternalTaskWrite,
    SelfSkillToggle,
    SelfCronRegister,
    SelfSourceEdit,
    ObsidianPreloadWrite,
}

impl ActionKind {
    pub const ALL: [Self; 27] = [
        Self::Read,
        Self::WriteNeothHome,
        Self::WriteOutsideHome,
        Self::ExecScripts,
        Self::ExecArbitrary,
        Self::PaidProviderCall,
        Self::UnboundedPaidProviderCall,
        Self::ExternalTtsSynthesis,
        Self::ExternalHttpRequest,
        Self::ChannelSend,
        Self::DangerousTarget,
        Self::McpToolInvocation,
        Self::PatchApplyToRepo,
        Self::ClusterPeerPairing,
        Self::SelfBinaryReplace,
        Self::ProactiveChannelSend,
        Self::OsFileRead,
        Self::OsFileWrite,
        Self::OsAppLaunch,
        Self::OsClipboardRead,
        Self::OsClipboardWrite,
        Self::ClusterTaskAccept,
        Self::ExternalTaskWrite,
        Self::SelfSkillToggle,
        Self::SelfCronRegister,
        Self::SelfSourceEdit,
        Self::ObsidianPreloadWrite,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::WriteNeothHome => "write_neoth_home",
            Self::WriteOutsideHome => "write_outside_home",
            Self::ExecScripts => "exec_scripts",
            Self::ExecArbitrary => "exec_arbitrary",
            Self::PaidProviderCall => "paid_provider_call",
            Self::UnboundedPaidProviderCall => "unbounded_paid_provider_call",
            Self::ExternalTtsSynthesis => "external_tts_synthesis",
            Self::ExternalHttpRequest => "external_http_request",
            Self::ChannelSend => "channel_send",
            Self::DangerousTarget => "dangerous_target",
            Self::McpToolInvocation => "mcp_tool_invocation",
            Self::PatchApplyToRepo => "patch_apply_to_repo",
            Self::ClusterPeerPairing => "cluster_peer_pairing",
            Self::SelfBinaryReplace => "self_binary_replace",
            Self::ProactiveChannelSend => "proactive_channel_send",
            Self::OsFileRead => "os_file_read",
            Self::OsFileWrite => "os_file_write",
            Self::OsAppLaunch => "os_app_launch",
            Self::OsClipboardRead => "os_clipboard_read",
            Self::OsClipboardWrite => "os_clipboard_write",
            Self::ClusterTaskAccept => "cluster_task_accept",
            Self::ExternalTaskWrite => "external_task_write",
            Self::SelfSkillToggle => "self_skill_toggle",
            Self::SelfCronRegister => "self_cron_register",
            Self::SelfSourceEdit => "self_source_edit",
            Self::ObsidianPreloadWrite => "obsidian_preload_write",
        }
    }
}

impl fmt::Display for ActionKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ActionKind {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        Self::ALL
            .into_iter()
            .find(|kind| kind.as_str() == value)
            .ok_or_else(|| {
                format!(
                    "unknown action `{value}`; valid: {}",
                    Self::ALL.map(Self::as_str).join(", ")
                )
            })
    }
}

impl Action {
    pub const fn kind(&self) -> ActionKind {
        match self {
            Self::Read => ActionKind::Read,
            Self::WriteNeothHome => ActionKind::WriteNeothHome,
            Self::WriteOutsideHome => ActionKind::WriteOutsideHome,
            Self::ExecScripts => ActionKind::ExecScripts,
            Self::ExecArbitrary => ActionKind::ExecArbitrary,
            Self::PaidProviderCall { .. } => ActionKind::PaidProviderCall,
            Self::UnboundedPaidProviderCall { .. } => ActionKind::UnboundedPaidProviderCall,
            Self::ExternalTtsSynthesis { .. } => ActionKind::ExternalTtsSynthesis,
            Self::ExternalHttpRequest { .. } => ActionKind::ExternalHttpRequest,
            Self::ChannelSend => ActionKind::ChannelSend,
            Self::DangerousTarget(_) => ActionKind::DangerousTarget,
            Self::McpToolInvocation { .. } => ActionKind::McpToolInvocation,
            Self::PatchApplyToRepo { .. } => ActionKind::PatchApplyToRepo,
            Self::ClusterPeerPairing { .. } => ActionKind::ClusterPeerPairing,
            Self::SelfBinaryReplace { .. } => ActionKind::SelfBinaryReplace,
            Self::ProactiveChannelSend { .. } => ActionKind::ProactiveChannelSend,
            Self::OsFileRead { .. } => ActionKind::OsFileRead,
            Self::OsFileWrite { .. } => ActionKind::OsFileWrite,
            Self::OsAppLaunch { .. } => ActionKind::OsAppLaunch,
            Self::OsClipboardRead => ActionKind::OsClipboardRead,
            Self::OsClipboardWrite => ActionKind::OsClipboardWrite,
            Self::ClusterTaskAccept => ActionKind::ClusterTaskAccept,
            Self::ExternalTaskWrite { .. } => ActionKind::ExternalTaskWrite,
            Self::SelfSkillToggle { .. } => ActionKind::SelfSkillToggle,
            Self::SelfCronRegister { .. } => ActionKind::SelfCronRegister,
            Self::SelfSourceEdit { .. } => ActionKind::SelfSourceEdit,
            Self::ObsidianPreloadWrite => ActionKind::ObsidianPreloadWrite,
        }
    }

    /// Payload-safe representative used by permission previews and CLI checks.
    pub fn representative(kind: ActionKind) -> Self {
        match kind {
            ActionKind::Read => Self::Read,
            ActionKind::WriteNeothHome => Self::WriteNeothHome,
            ActionKind::WriteOutsideHome => Self::WriteOutsideHome,
            ActionKind::ExecScripts => Self::ExecScripts,
            ActionKind::ExecArbitrary => Self::ExecArbitrary,
            ActionKind::PaidProviderCall => Self::PaidProviderCall {
                provider: "policy_preview".into(),
                model: "policy_preview".into(),
                authorization_id: "not-a-dispatch-authorization".into(),
                request_binding_sha256: "not-a-dispatch-binding".into(),
                eur_estimate: 0.10,
            },
            ActionKind::UnboundedPaidProviderCall => Self::UnboundedPaidProviderCall {
                provider: "policy_preview".into(),
                model: "unbounded".into(),
                authorization_id: "not-a-dispatch-authorization".into(),
                request_binding_sha256: "not-a-dispatch-binding".into(),
            },
            ActionKind::ExternalTtsSynthesis => Self::ExternalTtsSynthesis {
                provider: "external_preview".into(),
                destination: "https://tts.example".into(),
                sends_reference_audio: false,
                request_binding_sha256: "not-a-dispatch-binding".into(),
            },
            ActionKind::ExternalHttpRequest => Self::ExternalHttpRequest {
                method: "GET".into(),
                destination: "https://example.invalid".into(),
                surface: "policy_preview".into(),
                request_id: "not-a-dispatch-request".into(),
                request_binding_sha256: "not-a-dispatch-binding".into(),
            },
            ActionKind::ChannelSend => Self::ChannelSend,
            ActionKind::DangerousTarget => Self::DangerousTarget("example".into()),
            ActionKind::McpToolInvocation => Self::McpToolInvocation {
                server_id: "example".into(),
                tool: "example".into(),
            },
            ActionKind::PatchApplyToRepo => Self::PatchApplyToRepo {
                repo_root: std::path::PathBuf::from("example-repo"),
                task_id: 1,
            },
            ActionKind::ClusterPeerPairing => Self::ClusterPeerPairing {
                pub_key_hex: "00".repeat(32),
                discovered_via: "policy_preview".into(),
            },
            ActionKind::SelfBinaryReplace => Self::SelfBinaryReplace {
                from: "current".into(),
                to: "next".into(),
                repo: "owner/repo".into(),
            },
            ActionKind::ProactiveChannelSend => Self::ProactiveChannelSend {
                channel: "example".into(),
            },
            ActionKind::OsFileRead => Self::OsFileRead {
                path: std::path::PathBuf::from("example-read.txt"),
            },
            ActionKind::OsFileWrite => Self::OsFileWrite {
                path: std::path::PathBuf::from("example-write.txt"),
            },
            ActionKind::OsAppLaunch => Self::OsAppLaunch {
                program: std::path::PathBuf::from("example-program"),
            },
            ActionKind::OsClipboardRead => Self::OsClipboardRead,
            ActionKind::OsClipboardWrite => Self::OsClipboardWrite,
            ActionKind::ClusterTaskAccept => Self::ClusterTaskAccept,
            ActionKind::ExternalTaskWrite => Self::ExternalTaskWrite {
                provider: "example".into(),
                action: "add".into(),
            },
            ActionKind::SelfSkillToggle => Self::SelfSkillToggle {
                skill_id: "example".into(),
                enable: true,
            },
            ActionKind::SelfCronRegister => Self::SelfCronRegister {
                job_id: "example".into(),
            },
            ActionKind::SelfSourceEdit => Self::SelfSourceEdit {
                target_paths: vec!["src/example.rs".into()],
            },
            ActionKind::ObsidianPreloadWrite => Self::ObsidianPreloadWrite,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CustomDecision {
    Allow,
    Confirm,
    Deny,
}

impl fmt::Display for CustomDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Allow => "allow",
            Self::Confirm => "confirm",
            Self::Deny => "deny",
        })
    }
}

impl FromStr for CustomDecision {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "allow" => Ok(Self::Allow),
            "confirm" => Ok(Self::Confirm),
            "deny" => Ok(Self::Deny),
            other => Err(format!(
                "unknown custom decision `{other}`; valid: allow, confirm, deny"
            )),
        }
    }
}

/// Operator-owned custom autonomy rules stored under
/// `freedom.yaml::custom_autonomy.overrides`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CustomAutonomyConfig {
    pub overrides: BTreeMap<ActionKind, CustomDecision>,
    pub skill_overrides: BTreeMap<SkillId, SkillAutonomyOverride>,
}

/// Operator-owned cap for one admitted selected skill. It never belongs in a
/// skill package and therefore cannot grant package-supplied authority.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SkillAutonomyOverride {
    pub level: AutonomyLevel,
    pub overrides: BTreeMap<ActionKind, CustomDecision>,
}

impl Default for SkillAutonomyOverride {
    fn default() -> Self {
        Self { level: AutonomyLevel::Standard, overrides: BTreeMap::new() }
    }
}

impl SkillAutonomyOverride {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.level == AutonomyLevel::Custom || self.overrides.is_empty(),
            "skill autonomy action overrides require level custom"
        );
        anyhow::ensure!(
            self.overrides.len() <= ActionKind::ALL.len(),
            "skill autonomy overrides exceed supported action kinds"
        );
        Ok(())
    }
}

impl CustomAutonomyConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.skill_overrides.len() <= MAX_SKILL_AUTONOMY_OVERRIDES,
            "skill autonomy overrides exceed the {MAX_SKILL_AUTONOMY_OVERRIDES}-skill limit"
        );
        for override_policy in self.skill_overrides.values() {
            override_policy.validate()?;
        }
        Ok(())
    }
}

/// Immutable point-in-time policy used for one permission decision.
///
/// Callers obtain this from `FreedomConfig::autonomy_policy()` or a reload
/// controller. It owns the override map, so no config lock or mutable global is
/// held across confirmation or WAL awaits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutonomyPolicySnapshot {
    level: AutonomyLevel,
    overrides: BTreeMap<ActionKind, CustomDecision>,
    skill_overrides: BTreeMap<SkillId, SkillAutonomyOverride>,
}

impl AutonomyPolicySnapshot {
    pub fn new(level: AutonomyLevel, custom: &CustomAutonomyConfig) -> Self {
        Self {
            level,
            overrides: custom.overrides.clone(),
            skill_overrides: custom.skill_overrides.clone(),
        }
    }

    /// Built-in policy preview. `Custom` needs an operator map and therefore
    /// cannot be represented by this constructor.
    pub fn builtin(level: AutonomyLevel) -> Option<Self> {
        if level == AutonomyLevel::Custom {
            return None;
        }
        Some(Self {
            level,
            overrides: BTreeMap::new(),
            skill_overrides: BTreeMap::new(),
        })
    }

    pub const fn level(&self) -> AutonomyLevel {
        self.level
    }

    pub fn overrides(&self) -> &BTreeMap<ActionKind, CustomDecision> {
        &self.overrides
    }

    /// Build the restrictive per-action policy intersection for a selected,
    /// already-admitted route. Callers must never supply a free-form manifest
    /// id or use this to revive a stale route.
    pub fn effective_for_selected_skill(&self, skill_id: &SkillId) -> EffectiveAutonomyPolicy {
        let skill_cap = self.skill_overrides.get(skill_id).map(|override_policy| {
            AutonomyPolicySnapshot {
                level: override_policy.level,
                overrides: override_policy.overrides.clone(),
                skill_overrides: BTreeMap::new(),
            }
        });
        EffectiveAutonomyPolicy { skill_cap }
    }

    /// Stable digest of the exact snapshot used for one durable admission.
    /// The field order is domain-separated and length-delimited; overrides are
    /// a `BTreeMap`, so their canonical order does not depend on YAML input
    /// order or hash-map iteration. This is an identity of policy *content*,
    /// not a config reload epoch.
    pub(crate) fn trust_fingerprint_sha256(&self) -> String {
        fn add_part(hasher: &mut Sha256, value: &str) {
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value.as_bytes());
        }

        let mut hasher = Sha256::new();
        hasher.update(b"neoth.autonomy-policy.trust-fingerprint.v1\0");
        add_part(&mut hasher, self.level.as_str());
        hasher.update((self.overrides.len() as u64).to_be_bytes());
        for (action, decision) in &self.overrides {
            add_part(&mut hasher, action.as_str());
            add_part(&mut hasher, &decision.to_string());
        }
        // Preserve the v1 fingerprint byte-for-byte for legacy/default
        // configurations. Only a configured per-skill map carries the
        // domain-separated extension.
        if !self.skill_overrides.is_empty() {
            hasher.update(b"neoth.autonomy-policy.skill-overrides.v1\0");
            hasher.update((self.skill_overrides.len() as u64).to_be_bytes());
            for (skill_id, override_policy) in &self.skill_overrides {
                add_part(&mut hasher, skill_id.as_str());
                add_part(&mut hasher, override_policy.level.as_str());
                hasher.update((override_policy.overrides.len() as u64).to_be_bytes());
                for (action, decision) in &override_policy.overrides {
                    add_part(&mut hasher, action.as_str());
                    add_part(&mut hasher, &decision.to_string());
                }
            }
        }
        hex::encode(hasher.finalize())
    }

    pub(crate) fn custom_override(&self, kind: ActionKind) -> Option<CustomDecision> {
        self.overrides.get(&kind).copied()
    }

    #[cfg(test)]
    pub(crate) fn test_level(level: AutonomyLevel) -> Self {
        Self {
            level,
            overrides: BTreeMap::new(),
            skill_overrides: BTreeMap::new(),
        }
    }
}

/// Immutable action-by-action intersection of the current global policy and
/// one selected skill's operator-owned cap. Missing caps preserve legacy
/// global behavior; a present cap can only restrict it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectiveAutonomyPolicy {
    skill_cap: Option<AutonomyPolicySnapshot>,
}

impl EffectiveAutonomyPolicy {
    pub(crate) fn cap_requires_confirmation(&self, action: &Action) -> bool {
        self.skill_cap
            .as_ref()
            .is_some_and(|cap| matches!(super::evaluate_snapshot(action, cap), Decision::Confirm(_)))
    }
    /// Evaluate against the global snapshot read at the effect leaf while
    /// retaining the admitted route's skill cap. A config reload may tighten
    /// the global side but must never substitute a later skill cap for this
    /// route-owned value.
    pub fn evaluate_with_current_global(
        &self,
        action: &Action,
        current_global: &AutonomyPolicySnapshot,
    ) -> Decision {
        let global = super::evaluate_snapshot(action, current_global);
        let Some(skill_cap) = &self.skill_cap else { return global; };
        let cap = super::evaluate_snapshot(action, skill_cap);
        match (&global, &cap) {
            (Decision::Deny(_), _) => global,
            (_, Decision::Deny(_)) => cap,
            (Decision::Confirm(_), _) => global,
            (_, Decision::Confirm(_)) => cap,
            (Decision::Allow, Decision::Allow) => Decision::Allow,
        }
    }

    pub fn has_skill_cap(&self) -> bool { self.skill_cap.is_some() }
}

pub(crate) fn custom_requested_decision(
    action: &Action,
    configured: Option<CustomDecision>,
    standard: Decision,
    full: Decision,
) -> Decision {
    let Some(configured) = configured else {
        return standard;
    };
    let kind = action.kind();
    let requested = match configured {
        CustomDecision::Allow => Decision::Allow,
        CustomDecision::Confirm => {
            Decision::Confirm(format!("custom override: {kind} requires confirm"))
        }
        CustomDecision::Deny => Decision::Deny(format!("custom override: {kind} denied")),
    };

    // An explicit custom Deny is always final.
    if requested.is_deny() {
        return requested;
    }

    // Full is the irreducible upper safety boundary. Custom may tighten it but
    // can never turn a Full Confirm/Deny into a weaker decision.
    match full {
        Decision::Deny(reason) => {
            return Decision::Deny(format!("custom safety floor: {reason}"));
        }
        Decision::Confirm(reason) if requested.is_allow() => {
            return Decision::Confirm(format!("custom safety floor: {reason}"));
        }
        Decision::Allow | Decision::Confirm(_) => {}
    }

    // Full historically allows paid calls without inspecting the estimate.
    // Custom still may not auto-allow malformed cost data.
    if let Action::PaidProviderCall { eur_estimate, .. } = action
        && (!eur_estimate.is_finite() || *eur_estimate < 0.0)
    {
        return Decision::Confirm(format!(
            "custom safety floor: invalid paid-provider EUR estimate ({eur_estimate}) requires confirm"
        ));
    }

    requested
}

mod sealed {
    pub trait Sealed {}

    impl Sealed for &super::AutonomyPolicySnapshot {}

    #[cfg(test)]
    impl Sealed for super::AutonomyLevel {}
}

/// Sealed argument accepted by [`super::evaluate`]. Production builds expose
/// only `&AutonomyPolicySnapshot`; unit tests also accept a built-in level to
/// keep the exhaustive historical matrix compact.
#[doc(hidden)]
pub trait PolicyArgument: sealed::Sealed {
    fn evaluate_action(self, action: &Action) -> Decision;
    fn policy_snapshot(&self) -> AutonomyPolicySnapshot;
}

impl PolicyArgument for &AutonomyPolicySnapshot {
    fn evaluate_action(self, action: &Action) -> Decision {
        super::evaluate_snapshot(action, self)
    }

    fn policy_snapshot(&self) -> AutonomyPolicySnapshot {
        (*self).clone()
    }
}

#[cfg(test)]
impl PolicyArgument for AutonomyLevel {
    fn evaluate_action(self, action: &Action) -> Decision {
        super::evaluate_snapshot(action, &AutonomyPolicySnapshot::test_level(self))
    }

    fn policy_snapshot(&self) -> AutonomyPolicySnapshot {
        AutonomyPolicySnapshot::test_level(*self)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use sha2::{Digest, Sha256};

    use super::*;

    fn custom_snapshot(
        overrides: impl IntoIterator<Item = (ActionKind, CustomDecision)>,
    ) -> AutonomyPolicySnapshot {
        let custom = CustomAutonomyConfig {
            overrides: overrides.into_iter().collect(),
            skill_overrides: BTreeMap::new(),
        };
        AutonomyPolicySnapshot::new(AutonomyLevel::Custom, &custom)
    }

    fn decision_class(decision: Decision) -> &'static str {
        match decision {
            Decision::Allow => "allow",
            Decision::Confirm(_) => "confirm",
            Decision::Deny(_) => "deny",
        }
    }

    #[test]
    fn action_kind_names_are_exhaustive_unique_and_round_trip() {
        assert_eq!(ActionKind::ALL.len(), 27);
        let names: BTreeSet<_> = ActionKind::ALL
            .map(ActionKind::as_str)
            .into_iter()
            .collect();
        assert_eq!(names.len(), ActionKind::ALL.len());
        for kind in ActionKind::ALL {
            assert_eq!(kind.to_string().parse::<ActionKind>().unwrap(), kind);
            assert_eq!(Action::representative(kind).kind(), kind);
            assert_eq!(
                serde_yaml::from_str::<ActionKind>(kind.as_str()).unwrap(),
                kind
            );
        }
    }

    #[test]
    fn trust_fingerprint_is_stable_sorted_and_policy_sensitive() {
        let first = custom_snapshot([
            (ActionKind::ChannelSend, CustomDecision::Confirm),
            (ActionKind::Read, CustomDecision::Deny),
        ]);
        let reordered = custom_snapshot([
            (ActionKind::Read, CustomDecision::Deny),
            (ActionKind::ChannelSend, CustomDecision::Confirm),
        ]);
        let changed = custom_snapshot([
            (ActionKind::ChannelSend, CustomDecision::Allow),
            (ActionKind::Read, CustomDecision::Deny),
        ]);
        let first_fingerprint = first.trust_fingerprint_sha256();
        assert_eq!(first_fingerprint.len(), 64);
        assert_eq!(first_fingerprint, reordered.trust_fingerprint_sha256());
        assert_ne!(first_fingerprint, changed.trust_fingerprint_sha256());
        assert_ne!(
            first_fingerprint,
            AutonomyPolicySnapshot::builtin(AutonomyLevel::Standard)
                .unwrap()
                .trust_fingerprint_sha256()
        );
    }

    fn legacy_v1_trust_fingerprint_sha256(policy: &AutonomyPolicySnapshot) -> String {
        fn add_part(hasher: &mut Sha256, value: &str) {
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value.as_bytes());
        }

        let mut hasher = Sha256::new();
        hasher.update(b"neoth.autonomy-policy.trust-fingerprint.v1\0");
        add_part(&mut hasher, policy.level.as_str());
        hasher.update((policy.overrides.len() as u64).to_be_bytes());
        for (action, decision) in &policy.overrides {
            add_part(&mut hasher, action.as_str());
            add_part(&mut hasher, &decision.to_string());
        }
        hex::encode(hasher.finalize())
    }

    #[test]
    fn empty_skill_overrides_preserve_legacy_v1_trust_fingerprint() {
        let legacy_compatible = custom_snapshot([
            (ActionKind::ChannelSend, CustomDecision::Confirm),
            (ActionKind::Read, CustomDecision::Deny),
        ]);
        assert_eq!(
            legacy_compatible.trust_fingerprint_sha256(),
            legacy_v1_trust_fingerprint_sha256(&legacy_compatible),
            "an empty per-skill map must retain the exact v1 byte algorithm"
        );

        let with_skill_override = AutonomyPolicySnapshot::new(
            AutonomyLevel::Custom,
            &CustomAutonomyConfig {
                overrides: legacy_compatible.overrides.clone(),
                skill_overrides: BTreeMap::from([(
                    SkillId::parse("bounded-skill").unwrap(),
                    SkillAutonomyOverride {
                        level: AutonomyLevel::Standard,
                        overrides: BTreeMap::new(),
                    },
                )]),
            },
        );
        assert_ne!(
            with_skill_override.trust_fingerprint_sha256(),
            legacy_v1_trust_fingerprint_sha256(&with_skill_override),
            "configured per-skill caps must extend the legacy fingerprint domain"
        );
    }

    #[test]
    fn custom_config_rejects_unknown_action_and_decision() {
        assert!(
            serde_yaml::from_str::<CustomAutonomyConfig>(
                "overrides:\n  action_that_does_not_exist: allow\n"
            )
            .is_err()
        );
        assert!(
            serde_yaml::from_str::<CustomAutonomyConfig>("overrides:\n  read: allow_everything\n")
                .is_err()
        );
    }

    #[test]
    fn custom_without_override_is_exactly_standard_for_every_action() {
        let custom = custom_snapshot([]);
        let standard = AutonomyPolicySnapshot::test_level(AutonomyLevel::Standard);
        for kind in ActionKind::ALL {
            let action = Action::representative(kind);
            assert_eq!(
                decision_class(super::super::evaluate(&action, &custom)),
                decision_class(super::super::evaluate(&action, &standard)),
                "missing custom override must inherit Standard for {kind}"
            );
        }
    }

    #[test]
    fn custom_allow_confirm_and_deny_overrides_are_applied() {
        let policy = custom_snapshot([
            (ActionKind::ExecArbitrary, CustomDecision::Allow),
            (ActionKind::Read, CustomDecision::Confirm),
            (ActionKind::ChannelSend, CustomDecision::Deny),
        ]);
        assert!(super::super::evaluate(&Action::ExecArbitrary, &policy).is_allow());
        assert!(matches!(
            super::super::evaluate(&Action::Read, &policy),
            Decision::Confirm(_)
        ));
        assert!(super::super::evaluate(&Action::ChannelSend, &policy).is_deny());
    }

    #[test]
    fn custom_cannot_loosen_full_confirm_or_deny() {
        let policy = custom_snapshot([
            (ActionKind::SelfSourceEdit, CustomDecision::Allow),
            (ActionKind::Read, CustomDecision::Allow),
        ]);
        let source_edit = Action::representative(ActionKind::SelfSourceEdit);
        assert!(matches!(
            super::super::evaluate(&source_edit, &policy),
            Decision::Confirm(_)
        ));

        let synthetic_full_deny = custom_requested_decision(
            &Action::Read,
            Some(CustomDecision::Allow),
            Decision::Allow,
            Decision::Deny("future full hard-deny".into()),
        );
        assert!(synthetic_full_deny.is_deny());
    }

    #[test]
    fn malformed_paid_allow_clamps_to_confirm_but_explicit_deny_stays_deny() {
        for estimate in [f32::NAN, f32::INFINITY, -0.01] {
            let action = match Action::representative(ActionKind::PaidProviderCall) {
                Action::PaidProviderCall {
                    provider,
                    model,
                    authorization_id,
                    request_binding_sha256,
                    ..
                } => Action::PaidProviderCall {
                    provider,
                    model,
                    authorization_id,
                    request_binding_sha256,
                    eur_estimate: estimate,
                },
                _ => unreachable!(),
            };
            let allow = custom_snapshot([(ActionKind::PaidProviderCall, CustomDecision::Allow)]);
            assert!(matches!(
                super::super::evaluate(&action, &allow),
                Decision::Confirm(_)
            ));

            let deny = custom_snapshot([(ActionKind::PaidProviderCall, CustomDecision::Deny)]);
            assert!(super::super::evaluate(&action, &deny).is_deny());
        }
    }

    #[test]
    fn selected_skill_cap_intersects_each_action_restrictively() {
        let skill_id = SkillId::parse("bounded-skill").unwrap();
        let custom = CustomAutonomyConfig {
            overrides: BTreeMap::new(),
            skill_overrides: BTreeMap::from([(
                skill_id.clone(),
                SkillAutonomyOverride {
                    level: AutonomyLevel::Custom,
                    overrides: BTreeMap::from([
                        (ActionKind::ExecArbitrary, CustomDecision::Deny),
                        (ActionKind::WriteOutsideHome, CustomDecision::Confirm),
                    ]),
                },
            )]),
        };
        custom.validate().unwrap();
        let global = AutonomyPolicySnapshot::new(AutonomyLevel::Full, &custom);
        let effective = global.effective_for_selected_skill(&skill_id);
        assert!(effective.has_skill_cap());
        assert!(
            effective
                .evaluate_with_current_global(&Action::ExecArbitrary, &global)
                .is_deny()
        );
        assert!(matches!(
            effective.evaluate_with_current_global(&Action::WriteOutsideHome, &global),
            Decision::Confirm(_)
        ));
        assert!(
            effective
                .evaluate_with_current_global(&Action::Read, &global)
                .is_allow()
        );
        assert!(
            global
                .effective_for_selected_skill(&SkillId::parse("no-override").unwrap())
                .evaluate_with_current_global(&Action::ExecArbitrary, &global)
                .is_allow(),
            "missing override preserves the established global policy"
        );
    }

    #[test]
    fn skill_override_rejects_actions_without_custom_level() {
        let override_policy = SkillAutonomyOverride {
            level: AutonomyLevel::Standard,
            overrides: BTreeMap::from([(ActionKind::ExecArbitrary, CustomDecision::Deny)]),
        };
        assert!(override_policy.validate().is_err());
        assert!(SkillId::parse("Uppercase").is_err());
        assert!(SkillId::parse("valid_skill-1").is_ok());
    }

    #[test]
    fn retained_skill_cap_uses_current_global_effect_leaf_policy() {
        let skill_id = SkillId::parse("reload-bound-skill").unwrap();
        let configured = CustomAutonomyConfig {
            overrides: BTreeMap::new(),
            skill_overrides: BTreeMap::from([(
                skill_id.clone(),
                SkillAutonomyOverride {
                    level: AutonomyLevel::Full,
                    overrides: BTreeMap::new(),
                },
            )]),
        };
        let admitted_global = AutonomyPolicySnapshot::new(AutonomyLevel::Full, &configured);
        let retained = admitted_global.effective_for_selected_skill(&skill_id);
        let tightened_global = AutonomyPolicySnapshot::builtin(AutonomyLevel::Strict).unwrap();
        assert!(
            retained
                .evaluate_with_current_global(&Action::ExecArbitrary, &tightened_global)
                .is_deny(),
            "a later global tightening must still win over the retained route cap"
        );
    }
}
