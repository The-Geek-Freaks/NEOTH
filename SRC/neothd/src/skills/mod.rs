//! Skills — Phase 27 R-16.
//!
//! Proactive skill activation per `memory/neoth_round3_synthesis.md`.
//!
//! A skill is a YAML manifest in `~/.neoth/skills/<id>/skill.yaml` declaring:
//!   - `id` / `description` (required)
//!   - `trigger_keywords` (optional but recommended — Stage-1 router input)
//!   - `system_prompt` (injected into provider call when activated)
//!   - `tool_allowlist` (optional — restricts which tools the skill may call;
//!      omitted/empty means this skill may call no MCP tools)
//!
//! Router is a two-stage hybrid:
//!   Stage 1 — O(1) keyword scan on `trigger_keywords`. Pure-Rust, no model.
//!   Stage 2 — Qwen3-Q8 embedding re-rank on Stage-1 candidates (cosine ≥ 0.72).
//!             Activates when D14b lands; for now Stage 1 alone runs.
//!
//! Activation point in pipeline: AFTER operator_md.assemble (R-14), BEFORE
//! provider.complete(). Skill system_prompt is appended to the assembled
//! operator context so per-turn skill instructions win over global rules.

pub mod authority;
/// GOLD-ADAPT-ODY-20 — auto-skill extraction from MCP-loop agent runs.
/// After ≥ 2 tool-calls an LLM distils {title,steps,tags,confidence} from the
/// turn; skills above the 0.6 confidence threshold that are computer-executable
/// are staged in the proactive review queue for operator review.
pub mod auto_extract;
pub mod bundled;
pub mod creator;
pub mod generated_scan;
pub mod installer;
pub mod loader;
pub mod mode_registry;
pub(crate) mod mutation_lifecycle;
/// GOLD-ADAPT-PWF-01 — plan-attestation prompt-injection guard for
/// `writing_plans` / `executing_plans` skills. Fences `task_plan.md`
/// into the skill layer and verifies the SHA-256 hash before every
/// provider call so a tampered plan file is blocked with `[PLAN TAMPERED]`.
pub mod plan_attestation;
pub mod registry;
pub mod resolver;
pub mod route_ownership;
pub mod router;
pub mod schema;
pub(crate) mod store;
pub mod teacher;
pub mod test_harness;
/// Round-3 v0.4 ARCH-07 — LOWKEY skill versioning + prompt-bundle
/// hashing primitives. SHA-256(yaml||template) per-skill fingerprint
/// + SHA-256(BlockA..E) per-PROVIDER_REQUEST bundle hash + the
/// SkillSkipReason enum the WAL `0x29 SKILL_INJECT_SKIPPED` payload
/// carries. Prerequisite for ARCH-02 replay-determinism test.
pub mod versioning;

pub use loader::load_all;
pub use registry::SkillRegistry;
pub use router::route;

pub(crate) const WARNING_RECOVERY_RETAINED: &str =
    "W_SKILL_RECOVERY_RETAINED: a private recovery artifact remains available";
pub(crate) const WARNING_CLEANUP_PENDING: &str =
    "W_SKILL_CLEANUP_PENDING: private transaction cleanup remains pending";
pub(crate) const WARNING_DURABILITY_UNCONFIRMED: &str = "W_SKILL_DURABILITY_UNCONFIRMED: the state change committed, but durable storage was not confirmed";
pub(crate) const WARNING_POST_COMMIT_REDACTED: &str =
    "W_SKILL_POST_COMMIT: the state change committed with a redacted follow-up warning";

/// Stable operator-facing class for a post-commit skill warning.
///
/// Raw warnings intentionally remain available to the transaction owner for
/// recovery decisions, but they can contain private paths, transaction names,
/// and chained OS errors. Every CLI, GUI, log, WAL, or propagated-error
/// boundary must emit only this class's fixed message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OperatorSkillWarningClass {
    RecoveryRetained,
    CleanupPending,
    DurabilityUnconfirmed,
    PostCommit,
}

impl OperatorSkillWarningClass {
    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::RecoveryRetained => WARNING_RECOVERY_RETAINED,
            Self::CleanupPending => WARNING_CLEANUP_PENDING,
            Self::DurabilityUnconfirmed => WARNING_DURABILITY_UNCONFIRMED,
            Self::PostCommit => WARNING_POST_COMMIT_REDACTED,
        }
    }
}

pub(crate) fn classify_operator_skill_warning(warning: &str) -> OperatorSkillWarningClass {
    if warning.contains("retained") || warning.contains("recoverable backup") {
        OperatorSkillWarningClass::RecoveryRetained
    } else if warning.contains("cleanup") {
        OperatorSkillWarningClass::CleanupPending
    } else if warning.contains("durab") || warning.contains("sync") {
        OperatorSkillWarningClass::DurabilityUnconfirmed
    } else {
        OperatorSkillWarningClass::PostCommit
    }
}

/// Reduce post-commit diagnostics to stable operator classes before they cross
/// a process, log, error, GUI, receipt, or audit boundary.
pub(crate) fn operator_skill_warnings(warnings: &[String]) -> Vec<&'static str> {
    warnings
        .iter()
        .map(|warning| classify_operator_skill_warning(warning).message())
        .collect()
}
