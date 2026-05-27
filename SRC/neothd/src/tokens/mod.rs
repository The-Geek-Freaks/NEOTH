//! Round-3 v0.4 ARCH-04 — block-layer hard token caps + graceful
//! degradation primitive.
//!
//! Prompt assembly composes 5 named blocks (A..E) into the final
//! system+user payload sent to the provider. Without a cap, a
//! pathological recall window (operator with 10k episodes in the
//! 7-day Hippocampus view) can blow the provider's context limit
//! mid-flight + waste the round-trip cost. ARCH-04 enforces a
//! pre-flight cap + a deterministic degradation policy:
//!
//! ## Block taxonomy
//!
//! | Block | Source                                                       |
//! |-------|--------------------------------------------------------------|
//! | A     | Operator-explicit system prompt (`--system` / freedom.yaml)  |
//! | B     | Active LOWKEY skill prompts                                  |
//! | C     | Profile context (operator-claims from `idx_profile`)         |
//! | D     | Episode / recall context (idx_episode hits, dream summaries) |
//! | E     | Current message (operator's prompt text this turn)           |
//!
//! ## Degradation policy
//!
//! When `count_total > cap`, drop in this strict order until under:
//!
//! 1. **D oldest 50%** — episode context is the most reconstructible
//!    (recall can re-fetch on next turn); oldest items are the
//!    farthest from operator intent.
//! 2. **C lowest-importance 50%** — profile claims are
//!    confidence-ranked; low-importance claims surface in fewer
//!    downstream paths so losing them costs less.
//! 3. **Conductor.plan/spec truncation** — the orchestrator's
//!    internal plan/spec metadata block. Truncation rather than
//!    drop so the orchestrator still has structure.
//!
//! **NEVER touch A/B/E.** A is the operator's explicit intent. B is
//! the active skill's behavioural prompt — losing it breaks the
//! skill contract. E is the current turn — losing it makes the
//! response nonsensical.
//!
//! ## Token counting
//!
//! [`count_tokens`] uses a coarse `chars / 4` heuristic — matches the
//! OpenAI tokenizer's average ratio for English+German mixed text.
//! Precise token counts would require the provider-specific tokeniser
//! (tiktoken / gemma-tokenizer / etc.) which is too heavy for a
//! per-turn pre-flight check. The estimator's purpose is "trigger
//! degradation when the cap is plausibly exceeded"; a small over-
//! count is benign (slight aggressive degradation), a small under-
//! count just means the provider truncates instead. The audit chain
//! captures both `prompt_token_estimate` (this fn) +
//! `prompt_token_actual` (returned by the provider) so drift is
//! observable.
//!
//! ## Why not the provider's tokeniser
//!
//! - **Cross-provider portability** — operators swap providers; a
//!   tokeniser-per-provider chain breaks when the active provider's
//!   tokeniser isn't installed.
//! - **Cold-path cost** — the prompt-assembly call site runs once
//!   per turn; a 3 ms estimator beats a 50 ms tokeniser when the
//!   downstream provider call is going to take 500-5000 ms anyway.
//! - **No false security** — operators see `prompt_token_estimate`
//!   in the audit log as a clearly-labelled estimate; they don't
//!   mistake it for a precise count.

pub mod budget;
