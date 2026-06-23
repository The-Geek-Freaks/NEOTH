//! Skills — Phase 27 R-16.
//!
//! Proactive skill activation per `memory/neoth_round3_synthesis.md`.
//!
//! A skill is a YAML manifest in `~/.neoth/skills/<id>/skill.yaml` declaring:
//!   - `id` / `description` (required)
//!   - `trigger_keywords` (optional but recommended — Stage-1 router input)
//!   - `system_prompt` (injected into provider call when activated)
//!   - `tool_allowlist` (optional — restricts which tools the skill may call;
//!      NEOTH-specific, Claude Code has no per-skill allowlist)
//!
//! Router is a two-stage hybrid:
//!   Stage 1 — O(1) keyword scan on `trigger_keywords`. Pure-Rust, no model.
//!   Stage 2 — Qwen3-Q8 embedding re-rank on Stage-1 candidates (cosine ≥ 0.72).
//!             Activates when D14b lands; for now Stage 1 alone runs.
//!
//! Activation point in pipeline: AFTER operator_md.assemble (R-14), BEFORE
//! provider.complete(). Skill system_prompt is appended to the assembled
//! operator context so per-turn skill instructions win over global rules.

pub mod bundled;
pub mod creator;
pub mod installer;
pub mod loader;
pub mod mode_registry;
/// GOLD-ADAPT-PWF-01 — plan-attestation prompt-injection guard for
/// `writing_plans` / `executing_plans` skills. Fences `task_plan.md`
/// into the skill layer and verifies the SHA-256 hash before every
/// provider call so a tampered plan file is blocked with `[PLAN TAMPERED]`.
pub mod plan_attestation;
pub mod registry;
pub mod router;
pub mod schema;
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
