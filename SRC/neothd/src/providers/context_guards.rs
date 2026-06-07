//! Q1 — Karpathy-style metacognitive context guards.
//!
//! Per `PLAN/QUELLEN_ADOPT_karpathy_2026-05-21.md` +
//! `PLAN/QUELLEN_ADOPT_MASTER_2026-05-21.md` cross-cut Finding
//! C. Three principles from
//! `QUELLEN/andrej-karpathy-skills/CLAUDE.md` are NOT skill-
//! router targets (keyword routing would miss them when the
//! operator's message doesn't trigger a keyword) but always-
//! on preambles every code-leaning provider call should see:
//!
//!   - **P-1 Think Before Coding** — surface assumptions
//!     before writing. Catches "I'll just implement what
//!     you said" hallucinations that skip the contract.
//!   - **P-2 Simplicity First** — bias toward the smallest
//!     change that solves the request. Counters the
//!     model's tendency to over-abstract.
//!   - **P-3 Surgical Changes** — minimise blast radius;
//!     keep unrelated files untouched. Especially valuable
//!     in NEOTH's multi-file `--apply` flow.
//!
//! P-4 (Goal-Driven Execution) is intentionally NOT here —
//! NEOTH's existing `assets/skills/verification_before_completion/skill.yaml`
//! already covers that surface AND is stronger (demands
//! command + output line + file:line citation).
//!
//! ## Architecture
//!
//! Pure function: `code_discipline_preamble() -> &'static str`
//! returns a fixed string. Callers prepend it to the
//! `system` block of `providers::Request`. Adopter is the
//! `cli::chat::run_chat_with` pipeline (any path that
//! resolves a Provider and calls `complete()`).
//!
//! ## Why a const string, not a config knob
//!
//! Per Karpathy report §4 (KP-1), these three principles
//! are unconditional — making them runtime-tunable would
//! invite operators to disable them via freedom.yaml as a
//! "quieter prompt", which is exactly the failure mode
//! Karpathy's repo exists to prevent. The preamble stays
//! `&'static str` so it cannot be silently turned off.
//!
//! ## What this module is NOT
//!
//! - Not a skill — skill router (`skills::router`) would
//!   miss this when the operator's message doesn't trigger
//!   a keyword. Preamble fires UNCONDITIONALLY.
//! - Not part of the system prompt operators write — it
//!   prepends; the operator-supplied system block follows.
//! - Not provider-conditional — Karpathy principles apply
//!   to local Qwen + cloud providers + everything else.
//!   The caller decides whether to inject (e.g. `neoth chat`
//!   does; a one-off `neoth providers test-call` probe
//!   doesn't because it's not a code task).

/// Karpathy metacognitive preamble. Fixed string —
/// callers prepend to the `system` block of
/// [`crate::providers::Request`].
///
/// Three principles compressed into the smallest text
/// that conveys the contract without bloating the prompt:
/// every code-leaning call gets these three sentences
/// BEFORE the operator-supplied system block. For a 5k-
/// token system prompt this adds ~120 tokens — negligible.
pub fn code_discipline_preamble() -> &'static str {
    "## Core principles (always apply)\n\
     \n\
     - **Think before coding.** Surface the assumptions you are about to make. If the request is ambiguous, name the ambiguity instead of picking silently.\n\
     - **Simplicity first.** Make the smallest change that solves the request. Resist new abstractions, new dependencies, and new files unless the request requires them.\n\
     - **Surgical changes.** Touch only what the request requires. Unrelated files, unrelated functions, unrelated formatting stay untouched.\n"
}

/// Merge the Karpathy preamble onto an operator-supplied
/// system block. When the operator passes `None`, returns
/// the preamble alone. When they pass `Some(sys)`, returns
/// `<preamble>\n\n<sys>`. Idempotent — re-applying skips
/// when the preamble is already present (avoids double-
/// injection if the chat pipeline calls this twice along a
/// re-entry path).
pub fn apply_code_discipline_preamble(system: Option<&str>) -> String {
    let preamble = code_discipline_preamble();
    match system {
        None => preamble.to_string(),
        Some(s) if s.contains("## Core principles (always apply)") => s.to_string(),
        Some(s) => format!("{preamble}\n{s}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preamble_is_non_empty_and_pins_principle_titles() {
        // Pin the three principle titles so a future refactor
        // that drops one surfaces immediately. KP-2 from the
        // karpathy report (3 tests: non-empty, principle
        // titles, no double-injection) — this covers the
        // first two.
        let p = code_discipline_preamble();
        assert!(!p.is_empty());
        assert!(p.contains("Think before coding"));
        assert!(p.contains("Simplicity first"));
        assert!(p.contains("Surgical changes"));
    }

    #[test]
    fn preamble_does_not_include_p4_goal_driven_execution() {
        // P-4 is intentionally excluded — NEOTH's existing
        // verification_before_completion skill covers it
        // with a stronger contract. Pin so a future
        // refactor doesn't silently re-add P-4 + create a
        // duplicate prompt with subtly different shape.
        let p = code_discipline_preamble();
        assert!(!p.contains("Goal-Driven"));
        assert!(!p.contains("goal-driven"));
    }

    #[test]
    fn apply_to_none_returns_bare_preamble() {
        let result = apply_code_discipline_preamble(None);
        assert_eq!(result, code_discipline_preamble());
    }

    #[test]
    fn apply_to_some_prepends_with_separator() {
        let operator_sys = "You are NEOTH's coding assistant.";
        let merged = apply_code_discipline_preamble(Some(operator_sys));
        assert!(merged.starts_with("## Core principles"));
        assert!(merged.contains(operator_sys));
        // The operator's block MUST appear AFTER the preamble.
        let preamble_pos = merged.find("## Core principles").unwrap();
        let sys_pos = merged.find(operator_sys).unwrap();
        assert!(
            preamble_pos < sys_pos,
            "preamble must precede operator system"
        );
    }

    #[test]
    fn apply_is_idempotent_when_preamble_already_present() {
        // Re-applying on an already-prefixed system block is
        // a no-op. Prevents double-injection in re-entrant
        // chat paths (e.g. council debate hands back to
        // chat::run_chat_with which calls this again).
        let once = apply_code_discipline_preamble(Some("operator block"));
        let twice = apply_code_discipline_preamble(Some(once.as_str()));
        assert_eq!(once, twice);
    }

    #[test]
    fn preamble_token_budget_is_under_200() {
        // 4 chars per token rough heuristic — the preamble
        // should stay under 200 tokens (~800 chars) so it
        // remains a tiny fraction of any reasonable system
        // prompt budget.
        let p = code_discipline_preamble();
        assert!(
            p.len() < 800,
            "preamble crept above 800 chars ({}); trim before merging",
            p.len()
        );
    }
}
