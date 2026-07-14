//! Immutable autonomy-policy snapshots and stable action identifiers.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use super::{Action, AutonomyLevel, Decision};

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
}

impl AutonomyPolicySnapshot {
    pub fn new(level: AutonomyLevel, custom: &CustomAutonomyConfig) -> Self {
        Self {
            level,
            overrides: custom.overrides.clone(),
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
        })
    }

    pub const fn level(&self) -> AutonomyLevel {
        self.level
    }

    pub fn overrides(&self) -> &BTreeMap<ActionKind, CustomDecision> {
        &self.overrides
    }

    pub(crate) fn custom_override(&self, kind: ActionKind) -> Option<CustomDecision> {
        self.overrides.get(&kind).copied()
    }

    #[cfg(test)]
    pub(crate) fn test_level(level: AutonomyLevel) -> Self {
        Self {
            level,
            overrides: BTreeMap::new(),
        }
    }
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
    if let Action::PaidProviderCall { eur_estimate, .. } = action {
        if !eur_estimate.is_finite() || *eur_estimate < 0.0 {
            return Decision::Confirm(format!(
                "custom safety floor: invalid paid-provider EUR estimate ({eur_estimate}) requires confirm"
            ));
        }
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

    use super::*;

    fn custom_snapshot(
        overrides: impl IntoIterator<Item = (ActionKind, CustomDecision)>,
    ) -> AutonomyPolicySnapshot {
        let custom = CustomAutonomyConfig {
            overrides: overrides.into_iter().collect(),
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
}
