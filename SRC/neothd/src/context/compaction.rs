//! GOLD-ADOPT-19 — threshold-triggered context compaction for the agentic
//! tool-dispatch loop.
//!
//! The loop (`mcp::dispatch_loop::run_tool_loop_with_cap`) feeds the model one
//! flat, ever-growing prompt: each iteration appends the assistant reply, the
//! tool-result blocks, and any subdir hints. On a long chain that string can
//! approach the model's context window. When it crosses the operator's
//! threshold this module replaces the bulk of it with a single dense
//! `[CONTEXT SUMMARY]` produced by one extra LLM call — preserving the latest
//! exchange while collapsing the older history.
//!
//! Design notes:
//! - The summarization call reuses the loop's own `CompletionDriver` (no second
//!   provider is threaded in) — see the loop hook. The retention instructions
//!   live IN the prompt (the driver prepends its own system prompt; the inline
//!   instruction dominates), so a bad chat system prompt can't silently turn the
//!   summary into narrative fluff.
//! - The token estimate reuses [`crate::tokens::budget::count_tokens`]
//!   (chars/4) — the same heuristic the pre-flight budget gate uses, so the
//!   threshold is consistent with what the operator already tunes via
//!   `freedom.yaml::tokens.max_per_request`.
//! - There is NO per-model context-window value anywhere in the catalog, so the
//!   threshold is derived from `tokens.max_per_request` (NEOTH's pre-flight cap)
//!   × a fraction. An operator on a 1M-context model who left the 100k cap will
//!   compact early; the fix is to raise `tokens.max_per_request` to match their
//!   real window. This is documented on [`CompactionPolicy`].

/// Marker prefixing a compacted prompt so the model (and a human reading the
/// WAL/transcript) can tell the older history was summarized, not lost.
pub const SUMMARY_MARKER: &str = "[CONTEXT SUMMARY]";

/// In-prompt instruction for the summarization pass. Deliberately demands the
/// model keep the load-bearing facts a coding/agent loop needs to keep
/// working — unresolved tool outputs, file paths, identifiers, pending tasks —
/// not a narrative recap. A summary that drops an unresolved result would make
/// the agent re-issue the tool call or loop (correctness risk).
pub const COMPACTION_INSTRUCTION: &str = "\
You are compacting the transcript of an in-progress AI agent's tool-using \
session so it fits the context window. Produce a DENSE summary that the agent \
can keep working from. You MUST preserve, verbatim where they matter: every \
UNRESOLVED tool result and its value; all file paths, identifiers, URLs, error \
messages, and command outputs still relevant to the task; the original \
objective; and every pending/in-flight task. Drop only resolved chit-chat and \
superseded intermediate reasoning. Do NOT add new facts, do NOT solve the task \
further, do NOT editorialize. Output ONLY the summary.";

/// Policy controlling whether + when the loop compacts. Built by the caller
/// from `freedom.yaml::compaction` (+ `tokens.max_per_request`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompactionPolicy {
    /// Master switch. `false` → the loop never compacts (zero extra LLM calls).
    pub enabled: bool,
    /// Compact when the accumulated prompt's estimated token count reaches this.
    /// Derived as `tokens.max_per_request × compaction.threshold_fraction`.
    pub threshold_tokens: u32,
    /// When `true`, also run a compaction pass after EVERY tool-pair once a
    /// lower (progressive) threshold is crossed — not only at the main
    /// threshold. Opt-in (more LLM calls); default off.
    pub progressive: bool,
}

impl CompactionPolicy {
    /// Compaction off — the historical behaviour (no extra calls, prompt grows
    /// unbounded up to the iteration cap). Used by tests + non-chat callers.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            threshold_tokens: u32::MAX,
            progressive: false,
        }
    }

    /// Build a policy from the operator's compaction config + the request token
    /// cap. `threshold_fraction` is clamped to (0.0, 1.0]; a non-positive or
    /// NaN fraction disables compaction (fail-safe — never compact on garbage
    /// config). Returns [`disabled`](Self::disabled) when `enabled` is false.
    pub fn from_config(enabled: bool, progressive: bool, max_per_request: u32, fraction: f32) -> Self {
        // Fail-safe: a disabled flag, a non-finite fraction (incl. NaN), or a
        // fraction outside (0.0, 1.0] all disable compaction rather than
        // compacting on garbage config. `is_finite()` rejects NaN cleanly
        // (avoids a clippy-flagged negated float comparison).
        if !enabled || !fraction.is_finite() || fraction <= 0.0 || fraction > 1.0 {
            return Self::disabled();
        }
        let threshold = ((max_per_request as f64) * (fraction as f64)).round();
        let threshold_tokens = if threshold >= u32::MAX as f64 {
            u32::MAX
        } else {
            threshold as u32
        };
        Self {
            enabled: true,
            threshold_tokens: threshold_tokens.max(1),
            progressive,
        }
    }
}

impl Default for CompactionPolicy {
    /// Default = ENABLED at an 80k-token threshold (0.8 × the 100k default
    /// `tokens.max_per_request`). Honors the features-default-on rule; only
    /// fires on genuinely long chains, so the cost is near-zero in practice.
    fn default() -> Self {
        Self {
            enabled: true,
            threshold_tokens: 80_000,
            progressive: false,
        }
    }
}

/// Does the prompt's estimated token count meet/exceed the policy threshold?
/// `false` immediately when the policy is disabled (no token count computed).
pub fn needs_compaction(prompt: &str, policy: &CompactionPolicy) -> bool {
    if !policy.enabled {
        return false;
    }
    crate::tokens::budget::count_tokens(prompt) >= policy.threshold_tokens
}

/// Wrap raw history in the summarization instruction. The driver prepends its
/// own system prompt; the explicit instruction here dominates the request.
pub fn build_compaction_prompt(history: &str) -> String {
    format!("{COMPACTION_INSTRUCTION}\n\n--- TRANSCRIPT START ---\n{history}\n--- TRANSCRIPT END ---\n\nDENSE SUMMARY:")
}

/// Prefix a model-produced summary with [`SUMMARY_MARKER`] so it slots back in
/// as the loop's new prompt base, legible as compacted history.
pub fn wrap_summary(summary: &str) -> String {
    format!("{SUMMARY_MARKER}\n{}", summary.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_policy_never_needs_compaction() {
        let big = "x".repeat(10_000_000); // way over any real threshold
        assert!(!needs_compaction(&big, &CompactionPolicy::disabled()));
    }

    #[test]
    fn needs_compaction_respects_threshold() {
        let policy = CompactionPolicy {
            enabled: true,
            threshold_tokens: 100,
            progressive: false,
        };
        // count_tokens = chars/4 (+1). 200 chars ≈ 50 tokens < 100 → no.
        assert!(!needs_compaction(&"a".repeat(200), &policy));
        // 1000 chars ≈ 250 tokens ≥ 100 → yes.
        assert!(needs_compaction(&"a".repeat(1000), &policy));
    }

    #[test]
    fn from_config_disables_on_bad_fraction() {
        assert!(!CompactionPolicy::from_config(true, false, 100_000, 0.0).enabled);
        assert!(!CompactionPolicy::from_config(true, false, 100_000, -1.0).enabled);
        assert!(!CompactionPolicy::from_config(true, false, 100_000, 1.5).enabled);
        assert!(!CompactionPolicy::from_config(true, false, 100_000, f32::NAN).enabled);
        // disabled flag wins regardless of a valid fraction.
        assert!(!CompactionPolicy::from_config(false, false, 100_000, 0.8).enabled);
    }

    #[test]
    fn from_config_computes_threshold() {
        let p = CompactionPolicy::from_config(true, true, 100_000, 0.8);
        assert!(p.enabled);
        assert_eq!(p.threshold_tokens, 80_000);
        assert!(p.progressive);
    }

    #[test]
    fn build_compaction_prompt_embeds_retention_instruction_and_history() {
        let p = build_compaction_prompt("TOOL_RESULT: /etc/hosts had 3 lines");
        assert!(p.contains("UNRESOLVED tool result"), "must demand retention");
        assert!(p.contains("/etc/hosts had 3 lines"), "must include the history");
        assert!(p.contains("DENSE SUMMARY:"), "must cue the model to summarize");
    }

    #[test]
    fn wrap_summary_prefixes_marker() {
        let w = wrap_summary("  did X, pending Y  ");
        assert!(w.starts_with(SUMMARY_MARKER));
        assert!(w.contains("did X, pending Y"));
        assert!(!w.contains("  did X")); // trimmed
    }

    #[test]
    fn default_policy_is_enabled_at_80k() {
        let d = CompactionPolicy::default();
        assert!(d.enabled);
        assert_eq!(d.threshold_tokens, 80_000);
        assert!(!d.progressive);
    }
}
