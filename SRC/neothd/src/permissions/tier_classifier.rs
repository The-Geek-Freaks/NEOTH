//! P-01 — 7-tier approval classifier (openclaw-adopted).
//!
//! Every tool call NEOTH ever makes maps into exactly one of
//! seven [`ApprovalTier`]s. The dispatcher consults
//! [`auto_approve_decision`] to decide whether the call goes
//! through immediately, prompts the operator first, or gets
//! refused outright.
//!
//! The point: at `Standard` autonomy a `readonly_scoped` GET on
//! `/health` should not pop a confirm dialog — that's the
//! "confirm fatigue" v0.5 surfaces multiply. Conversely a
//! `control_plane` action (cron schedule edit, plugin enable/
//! disable) ALWAYS prompts regardless of autonomy.
//!
//! ## The 7 tiers (least → most dangerous)
//!
//! 1. `ReadonlyScoped` — bounded reads (recall, list, status).
//!    No side effects, no exfil channel.
//! 2. `ReadonlySearch` — broader reads (web search, code grep
//!    over operator-allowed paths). Still no side effects but
//!    surface is larger.
//! 3. `Mutating` — writes operator-owned state (memory write,
//!    note edit, draft save). Reversible.
//! 4. `ExecCapable` — runs subprocess (shell, python script).
//!    Side effects on the host OS.
//! 5. `ControlPlane` — changes NEOTH's own config (autonomy,
//!    cron schedules, plugin enable/disable, channel registration).
//!    Always prompts.
//! 6. `Interactive` — drives a real human (send to Telegram,
//!    schedule a calendar invite). Side effect outside the agent
//!    boundary.
//! 7. `Unknown` — classifier couldn't decide. Defaults to prompt.
//!
//! ## Decision matrix (Tier × AutonomyLevel → Decision)
//!
//! |               | Strict  | Standard | Elevated | Full   |
//! |---------------|---------|----------|----------|--------|
//! | ReadonlyScoped| Prompt  | Auto     | Auto     | Auto   |
//! | ReadonlySearch| Prompt  | Auto     | Auto     | Auto   |
//! | Mutating      | Prompt  | Prompt   | Auto     | Auto   |
//! | ExecCapable   | Prompt  | Prompt   | Prompt   | Auto   |
//! | ControlPlane  | Prompt  | Prompt   | Prompt   | Prompt |
//! | Interactive   | Prompt  | Prompt   | Prompt   | Prompt |
//! | Unknown       | Prompt  | Prompt   | Prompt   | Prompt |
//!
//! `Strict` operators see every confirm (locked-down env);
//! `Full` is "trust the agent except for control-plane +
//! interactive" — the two classes where wrong action is
//! externally visible.

use serde::{Deserialize, Serialize};

/// One of the 7 approval tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalTier {
    ReadonlyScoped,
    ReadonlySearch,
    Mutating,
    ExecCapable,
    ControlPlane,
    Interactive,
    Unknown,
}

impl ApprovalTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadonlyScoped => "readonly_scoped",
            Self::ReadonlySearch => "readonly_search",
            Self::Mutating => "mutating",
            Self::ExecCapable => "exec_capable",
            Self::ControlPlane => "control_plane",
            Self::Interactive => "interactive",
            Self::Unknown => "unknown",
        }
    }
}

/// Operator's chosen autonomy level. Mirrors
/// [`super::AutonomyLevel`] (Custom = the "Strict" row for
/// safety until a per-tier override lands).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomyForTier {
    Strict,
    Standard,
    Elevated,
    Full,
}

impl AutonomyForTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Standard => "standard",
            Self::Elevated => "elevated",
            Self::Full => "full",
        }
    }
}

/// Dispatcher decision for a tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TierDecision {
    /// Run without prompting.
    AutoApprove,
    /// Stop + ask the operator before running.
    Prompt,
}

/// The matrix above as a pure-fn lookup. Operator UIs render the
/// full grid via repeated calls — no need to expose the table
/// directly (decisions stay encapsulated).
pub fn auto_approve_decision(tier: ApprovalTier, autonomy: AutonomyForTier) -> TierDecision {
    use ApprovalTier::*;
    use AutonomyForTier::*;
    match (tier, autonomy) {
        // Always prompt — control plane + interactive + unknown
        // never auto-approve regardless of autonomy.
        (ControlPlane, _) | (Interactive, _) | (Unknown, _) => TierDecision::Prompt,
        // Strict: prompts everything.
        (_, Strict) => TierDecision::Prompt,
        // Standard: auto-approves readonly tiers only.
        (ReadonlyScoped | ReadonlySearch, Standard) => TierDecision::AutoApprove,
        (Mutating | ExecCapable, Standard) => TierDecision::Prompt,
        // Elevated: adds Mutating.
        (ReadonlyScoped | ReadonlySearch | Mutating, Elevated) => TierDecision::AutoApprove,
        (ExecCapable, Elevated) => TierDecision::Prompt,
        // Full: adds ExecCapable. (ControlPlane/Interactive caught above.)
        (ReadonlyScoped | ReadonlySearch | Mutating | ExecCapable, Full) => {
            TierDecision::AutoApprove
        }
    }
}

/// Classifier from a tool name (the canonical `noun.verb` form
/// the dispatcher uses) to an [`ApprovalTier`]. Conservative — any
/// unrecognised tool returns `Unknown` so it prompts the operator.
///
/// Verbs convention (pinned for matching):
///   - `read.*` / `list.*` / `search.*` / `recall.*` / `status.*`
///     / `show.*` / `find.*` → readonly
///   - `write.*` / `edit.*` / `create.*` / `save.*` / `mark.*` /
///     `delete.*` → mutating
///   - `exec.*` / `shell.*` / `run.*` / `spawn.*` → exec_capable
///   - `config.*` / `enable.*` / `disable.*` / `schedule.*` /
///     `revoke.*` / `set_autonomy.*` → control_plane
///   - `send.*` / `notify.*` / `invite.*` / `post.*` →
///     interactive
pub fn classify_tool(tool_name: &str) -> ApprovalTier {
    let name = tool_name.trim();
    if name.is_empty() {
        return ApprovalTier::Unknown;
    }
    let (verb, target) = match name.split_once('.') {
        Some((v, t)) => (v, t),
        None => (name, ""),
    };

    // Interactive — external boundary crossings. Checked FIRST so
    // a `send.email` doesn't accidentally match a "send" mutating
    // verb elsewhere.
    if matches!(verb, "send" | "notify" | "invite" | "post" | "reply") {
        return ApprovalTier::Interactive;
    }
    // Control plane.
    if matches!(
        verb,
        "config" | "enable" | "disable" | "schedule" | "revoke" | "grant" | "set_autonomy"
    ) {
        return ApprovalTier::ControlPlane;
    }
    // Special-case `permissions.*` — every action under the
    // permissions tool is control-plane regardless of verb form.
    if name.starts_with("permissions.") {
        return ApprovalTier::ControlPlane;
    }
    // Exec.
    if matches!(verb, "exec" | "shell" | "run" | "spawn" | "bash") {
        return ApprovalTier::ExecCapable;
    }
    // Mutating.
    if matches!(
        verb,
        "write" | "edit" | "create" | "save" | "mark" | "delete" | "import" | "store"
    ) {
        return ApprovalTier::Mutating;
    }
    // ReadonlySearch — broader read surface (web, code-grep).
    if matches!(verb, "search" | "grep" | "scan" | "fetch") {
        // `search.web` and `fetch.url` go into the broader band.
        // `search.memory` is still readonly_scoped per below.
        if target == "memory" || target == "kanban" || target == "audit" {
            return ApprovalTier::ReadonlyScoped;
        }
        return ApprovalTier::ReadonlySearch;
    }
    // ReadonlyScoped.
    if matches!(
        verb,
        "read" | "list" | "recall" | "status" | "show" | "find" | "describe"
    ) {
        return ApprovalTier::ReadonlyScoped;
    }
    ApprovalTier::Unknown
}

/// Combined classify + decide entry point — what the dispatcher
/// calls per tool invocation.
pub fn classify_and_decide(
    tool_name: &str,
    autonomy: AutonomyForTier,
) -> (ApprovalTier, TierDecision) {
    let tier = classify_tool(tool_name);
    let decision = auto_approve_decision(tier, autonomy);
    (tier, decision)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── enum surface ──────────────────────────────────────────────

    #[test]
    fn approval_tier_as_str_pinned() {
        assert_eq!(ApprovalTier::ReadonlyScoped.as_str(), "readonly_scoped");
        assert_eq!(ApprovalTier::ReadonlySearch.as_str(), "readonly_search");
        assert_eq!(ApprovalTier::Mutating.as_str(), "mutating");
        assert_eq!(ApprovalTier::ExecCapable.as_str(), "exec_capable");
        assert_eq!(ApprovalTier::ControlPlane.as_str(), "control_plane");
        assert_eq!(ApprovalTier::Interactive.as_str(), "interactive");
        assert_eq!(ApprovalTier::Unknown.as_str(), "unknown");
    }

    #[test]
    fn autonomy_as_str_pinned() {
        assert_eq!(AutonomyForTier::Strict.as_str(), "strict");
        assert_eq!(AutonomyForTier::Standard.as_str(), "standard");
        assert_eq!(AutonomyForTier::Elevated.as_str(), "elevated");
        assert_eq!(AutonomyForTier::Full.as_str(), "full");
    }

    #[test]
    fn decision_snake_case_serde() {
        assert_eq!(
            serde_json::to_string(&TierDecision::AutoApprove).unwrap(),
            "\"auto_approve\""
        );
        assert_eq!(
            serde_json::to_string(&TierDecision::Prompt).unwrap(),
            "\"prompt\""
        );
    }

    // ── decision matrix — full grid ───────────────────────────────

    #[test]
    fn control_plane_always_prompts_regardless_of_autonomy() {
        for autonomy in [
            AutonomyForTier::Strict,
            AutonomyForTier::Standard,
            AutonomyForTier::Elevated,
            AutonomyForTier::Full,
        ] {
            assert_eq!(
                auto_approve_decision(ApprovalTier::ControlPlane, autonomy),
                TierDecision::Prompt,
                "ControlPlane must always prompt (autonomy={autonomy:?})",
            );
        }
    }

    #[test]
    fn interactive_always_prompts_regardless_of_autonomy() {
        for autonomy in [
            AutonomyForTier::Strict,
            AutonomyForTier::Standard,
            AutonomyForTier::Elevated,
            AutonomyForTier::Full,
        ] {
            assert_eq!(
                auto_approve_decision(ApprovalTier::Interactive, autonomy),
                TierDecision::Prompt,
            );
        }
    }

    #[test]
    fn unknown_always_prompts() {
        for autonomy in [
            AutonomyForTier::Strict,
            AutonomyForTier::Standard,
            AutonomyForTier::Elevated,
            AutonomyForTier::Full,
        ] {
            assert_eq!(
                auto_approve_decision(ApprovalTier::Unknown, autonomy),
                TierDecision::Prompt,
            );
        }
    }

    #[test]
    fn strict_prompts_every_tier() {
        for tier in [
            ApprovalTier::ReadonlyScoped,
            ApprovalTier::ReadonlySearch,
            ApprovalTier::Mutating,
            ApprovalTier::ExecCapable,
            ApprovalTier::ControlPlane,
            ApprovalTier::Interactive,
            ApprovalTier::Unknown,
        ] {
            assert_eq!(
                auto_approve_decision(tier, AutonomyForTier::Strict),
                TierDecision::Prompt,
                "Strict must always prompt (tier={tier:?})",
            );
        }
    }

    #[test]
    fn standard_auto_approves_readonly_only() {
        assert_eq!(
            auto_approve_decision(ApprovalTier::ReadonlyScoped, AutonomyForTier::Standard),
            TierDecision::AutoApprove,
        );
        assert_eq!(
            auto_approve_decision(ApprovalTier::ReadonlySearch, AutonomyForTier::Standard),
            TierDecision::AutoApprove,
        );
        assert_eq!(
            auto_approve_decision(ApprovalTier::Mutating, AutonomyForTier::Standard),
            TierDecision::Prompt,
        );
        assert_eq!(
            auto_approve_decision(ApprovalTier::ExecCapable, AutonomyForTier::Standard),
            TierDecision::Prompt,
        );
    }

    #[test]
    fn elevated_adds_mutating_auto_approve() {
        assert_eq!(
            auto_approve_decision(ApprovalTier::Mutating, AutonomyForTier::Elevated),
            TierDecision::AutoApprove,
        );
        assert_eq!(
            auto_approve_decision(ApprovalTier::ExecCapable, AutonomyForTier::Elevated),
            TierDecision::Prompt,
        );
    }

    #[test]
    fn full_adds_exec_capable_auto_approve() {
        assert_eq!(
            auto_approve_decision(ApprovalTier::ExecCapable, AutonomyForTier::Full),
            TierDecision::AutoApprove,
        );
    }

    // ── classifier ────────────────────────────────────────────────

    #[test]
    fn classify_empty_is_unknown() {
        assert_eq!(classify_tool(""), ApprovalTier::Unknown);
        assert_eq!(classify_tool("   "), ApprovalTier::Unknown);
    }

    #[test]
    fn classify_unrecognised_verb_is_unknown() {
        assert_eq!(classify_tool("teleport.user"), ApprovalTier::Unknown);
    }

    #[test]
    fn classify_readonly_scoped_verbs() {
        for tool in [
            "read.file",
            "list.tasks",
            "recall.memory",
            "status.daemon",
            "show.config",
            "find.contact",
            "describe.tool",
        ] {
            assert_eq!(
                classify_tool(tool),
                ApprovalTier::ReadonlyScoped,
                "{tool} should be ReadonlyScoped",
            );
        }
    }

    #[test]
    fn classify_readonly_search_for_broad_targets() {
        assert_eq!(classify_tool("search.web"), ApprovalTier::ReadonlySearch);
        assert_eq!(classify_tool("grep.code"), ApprovalTier::ReadonlySearch);
        assert_eq!(classify_tool("fetch.url"), ApprovalTier::ReadonlySearch);
        assert_eq!(classify_tool("scan.files"), ApprovalTier::ReadonlySearch);
    }

    #[test]
    fn classify_search_memory_stays_scoped() {
        // Internal-only memory search is the cheap recall path —
        // doesn't widen to ReadonlySearch (which would prompt at
        // tighter autonomy levels by default).
        assert_eq!(classify_tool("search.memory"), ApprovalTier::ReadonlyScoped);
        assert_eq!(classify_tool("search.kanban"), ApprovalTier::ReadonlyScoped);
        assert_eq!(classify_tool("search.audit"), ApprovalTier::ReadonlyScoped);
    }

    #[test]
    fn classify_mutating_verbs() {
        for tool in [
            "write.memory",
            "edit.note",
            "create.task",
            "save.draft",
            "mark.read",
            "delete.proposal",
            "import.credentials",
            "store.fact",
        ] {
            assert_eq!(
                classify_tool(tool),
                ApprovalTier::Mutating,
                "{tool} should be Mutating",
            );
        }
    }

    #[test]
    fn classify_exec_capable_verbs() {
        for tool in [
            "exec.shell",
            "shell.run",
            "run.script",
            "spawn.process",
            "bash.command",
        ] {
            assert_eq!(classify_tool(tool), ApprovalTier::ExecCapable);
        }
    }

    #[test]
    fn classify_control_plane_verbs() {
        for tool in [
            "config.update",
            "enable.plugin",
            "disable.skill",
            "schedule.cron",
            "revoke.lease",
            "grant.capability",
            "set_autonomy.standard",
        ] {
            assert_eq!(
                classify_tool(tool),
                ApprovalTier::ControlPlane,
                "{tool} should be ControlPlane",
            );
        }
    }

    #[test]
    fn classify_permissions_namespace_always_control_plane() {
        // Even `permissions.show` (readonly verb under control-
        // plane namespace) is ControlPlane — operators must see
        // every permissions action they're not invoking themselves.
        assert_eq!(
            classify_tool("permissions.show"),
            ApprovalTier::ControlPlane,
        );
        assert_eq!(
            classify_tool("permissions.list"),
            ApprovalTier::ControlPlane,
        );
    }

    #[test]
    fn classify_interactive_verbs() {
        for tool in [
            "send.telegram",
            "notify.operator",
            "invite.attendee",
            "post.slack",
            "reply.email",
        ] {
            assert_eq!(
                classify_tool(tool),
                ApprovalTier::Interactive,
                "{tool} should be Interactive",
            );
        }
    }

    #[test]
    fn classify_no_verb_separator_uses_full_string() {
        assert_eq!(classify_tool("status"), ApprovalTier::ReadonlyScoped);
        assert_eq!(classify_tool("shell"), ApprovalTier::ExecCapable);
        assert_eq!(classify_tool("send"), ApprovalTier::Interactive);
    }

    // ── combined entry point ──────────────────────────────────────

    #[test]
    fn classify_and_decide_returns_pair() {
        let (tier, decision) = classify_and_decide("read.file", AutonomyForTier::Standard);
        assert_eq!(tier, ApprovalTier::ReadonlyScoped);
        assert_eq!(decision, TierDecision::AutoApprove);

        let (tier, decision) = classify_and_decide("send.telegram", AutonomyForTier::Full);
        assert_eq!(tier, ApprovalTier::Interactive);
        // Interactive ALWAYS prompts even at Full.
        assert_eq!(decision, TierDecision::Prompt);
    }

    #[test]
    fn classify_and_decide_unknown_tool_prompts_at_every_autonomy() {
        for autonomy in [
            AutonomyForTier::Strict,
            AutonomyForTier::Standard,
            AutonomyForTier::Elevated,
            AutonomyForTier::Full,
        ] {
            let (tier, decision) = classify_and_decide("totally.new", autonomy);
            assert_eq!(tier, ApprovalTier::Unknown);
            assert_eq!(decision, TierDecision::Prompt);
        }
    }

    // ── serde ─────────────────────────────────────────────────────

    #[test]
    fn approval_tier_snake_case_serde() {
        assert_eq!(
            serde_json::to_string(&ApprovalTier::ControlPlane).unwrap(),
            "\"control_plane\"",
        );
        assert_eq!(
            serde_json::to_string(&ApprovalTier::ReadonlyScoped).unwrap(),
            "\"readonly_scoped\"",
        );
    }

    #[test]
    fn autonomy_snake_case_serde() {
        assert_eq!(
            serde_json::to_string(&AutonomyForTier::Elevated).unwrap(),
            "\"elevated\"",
        );
    }
}
