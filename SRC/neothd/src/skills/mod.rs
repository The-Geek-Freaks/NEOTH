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

pub mod loader;
pub mod router;
pub mod schema;
pub mod test_harness;

pub use loader::load_all;
pub use router::route;
