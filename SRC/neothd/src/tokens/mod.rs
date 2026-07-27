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
//! **Never remove A/B/E independently.** A is the operator's explicit intent,
//! B is the active skill's behavioural prompt, and E is the current turn. The
//! sole typed exception is a validated optional atomic group: its A protocol
//! is removed together with the degradable data it describes, never by itself.
//!
//! ## Token counting
//!
//! [`count_tokens`] remains the coarse `chars / 4` display/compaction
//! heuristic. Hard-cap enforcement does not trust it: typed A-E items use
//! [`budget::count_tokens_upper_bound`], and the final provider leaf adds a
//! conservative UTF-8/model/message-envelope upper bound before dispatch.
//! This is deliberately stricter than ordinary English tokenisation, but it
//! also covers CJK, emoji and minified/adversarial input without assuming the
//! provider will truncate a paid request safely.
//!
//! ## Why not the provider's tokeniser
//!
//! - **Cross-provider portability** — operators swap providers; a
//!   tokeniser-per-provider chain breaks when the active provider's
//!   tokeniser isn't installed.
//! - **Cold-path cost** — the prompt-assembly call site runs once
//!   per turn; a 3 ms estimator beats a 50 ms tokeniser when the
//!   downstream provider call is going to take 500-5000 ms anyway.
//! - **No false security** — audit keeps the provider's returned
//!   `prompt_token_actual`, while the pre-dispatch value is a conservative
//!   upper bound rather than a tokenizer-precision claim.

pub mod budget;
