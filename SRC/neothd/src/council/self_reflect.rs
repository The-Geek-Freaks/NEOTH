//! Optional self-reflection refinement pass (Pick #8 SP-5, Session 14).
//!
//! After the council picks a winner, the operator can opt-in to an
//! ADDITIONAL provider call where the WINNING hemisphere reviews its
//! own response and either confirms it or revises it. The intent
//! mirrors the chain-of-verification literature: a single self-
//! review pass catches obvious factual errors + tightens phrasing,
//! at the cost of one extra LLM call.
//!
//! ## Hard rules (from Pick #8 fractal synthesis)
//!
//! - **Depth-0 only** (F3). Self-reflect fires only at the outer
//!   council. Inner recursive councils never reflect — would cost
//!   `3^N` extra calls.
//! - **Threshold-gated**. Fires only when the composite quality
//!   score is BELOW `effective_refine_threshold()` (default 0.90).
//!   Confident answers skip the reflect pass.
//! - **Kill-switch**. `config.council.self_reflect_enabled = false`
//!   disables the threshold gate entirely. Both must agree for a
//!   reflect call to fire.
//! - **Fail-safe**. ANY error during the reflect call returns the
//!   original text. Self-reflect can NEVER make the user-visible
//!   answer worse than the council winner already produced.
//! - **Info-amplification guard** (Security #5). The reflect prompt
//!   explicitly instructs the model to NOT add information not
//!   present in the original. Post-check rejects responses whose
//!   length grew by >50% — prevents leakage of operator-context
//!   facts that the model "helpfully" hallucinated into the refined
//!   version.
//!
//! ## When to defer to v0.3.1
//!
//! BudgetToken integration (cost-cap propagation through recursion)
//! lives in a parallel sub-pick. For SP-5 minimum-viable, the
//! function takes a `&dyn HemisphereProvider` directly and trusts
//! the caller to budget-check before invoking.

use crate::council::orchestrator::{CompletionRecord, HemisphereProvider};

/// Pick #8 SP-5 (Session 14) — outcome of one refinement pass.
/// Returned by [`refine`] so callers can audit `refined` vs.
/// `original` + see whether the rejection-on-bloat guard fired.
#[derive(Clone, Debug, PartialEq)]
pub struct RefinedResponse {
    /// The original winning text (verbatim copy).
    pub original: String,
    /// The text the dispatch path SHOULD print to the operator.
    /// Equals `original` when the reflect call failed, was rejected
    /// by the bloat guard, or returned an empty string.
    pub refined: String,
    /// Whether the refined text actually came from the LLM (true)
    /// or from the fail-safe fallback to original (false).
    pub did_refine: bool,
    /// When `did_refine = false`, this carries the reason the
    /// fallback fired — useful for WAL audit + operator debugging.
    pub fallback_reason: Option<&'static str>,
}

impl RefinedResponse {
    /// The text dispatch should surface to the operator.
    pub fn final_text(&self) -> &str {
        &self.refined
    }
}

/// Maximum allowed growth ratio between the refined response and
/// the original — bloated responses get rejected as a defence
/// against info-amplification (Security threat #5).
pub const MAX_GROWTH_RATIO: f32 = 1.50;

/// System prompt prepended to the refine call. Explicit anti-
/// amplification instruction.
pub const REFINE_SYSTEM_PROMPT: &str = "You are reviewing your own prior answer. If it is already correct \
     and complete, repeat it verbatim. If you can improve clarity or \
     fix a factual error WITHOUT adding new information or context \
     not present in your prior answer, do so. Do not add hedging, \
     preamble, or new facts. Do not reference this review process.";

/// Pick #8 SP-5 (Session 14) — apply the self-reflection gate.
///
/// Returns `true` when self-reflect SHOULD fire for this debate:
///   - kill-switch ON (`config.council.self_reflect_enabled`)
///   - composite quality score < `effective_refine_threshold()`
///   - depth == 0 (F3 fractal rule)
pub fn should_refine(
    config: &crate::config::FreedomConfig,
    composite_quality_score: f32,
    depth: u8,
) -> bool {
    if !config.council.self_reflect_enabled {
        return false;
    }
    if depth > 0 {
        return false;
    }
    composite_quality_score < config.council.effective_refine_threshold()
}

/// Pick #8 SP-5 (Session 14) — fire ONE self-reflection pass.
///
/// `provider` is the winning hemisphere's provider, built by the
/// dispatch path via `build_hemisphere` or equivalent. The function
/// makes exactly one `ask` call and applies the bloat-guard to its
/// output.
///
/// Fail-safe: on ANY error or rejected output, returns
/// `RefinedResponse { refined: original.into(), did_refine: false,
/// fallback_reason: Some(reason) }`. Never propagates errors to the
/// caller — the original answer is always served to the operator.
pub async fn refine(
    original_prompt: &str,
    original_text: &str,
    provider: &dyn HemisphereProvider,
) -> RefinedResponse {
    let reflect_prompt = build_reflect_prompt(original_prompt, original_text);
    let llm_result = provider.ask(&reflect_prompt).await;
    classify_refine_output(original_text, llm_result)
}

fn build_reflect_prompt(original_prompt: &str, original_text: &str) -> String {
    // System instructions land inline because the HemisphereProvider
    // trait's `ask(prompt: &str)` doesn't expose a system-prompt
    // slot — the inline-prompt approach is the simplest contract.
    format!(
        "{REFINE_SYSTEM_PROMPT}\n\n\
         === ORIGINAL QUESTION ===\n{original_prompt}\n\n\
         === YOUR PRIOR ANSWER ===\n{original_text}\n\n\
         === REVIEWED ANSWER ===\n"
    )
}

/// Pure function — extracted so tests can drive the classifier
/// without spawning a provider.
pub(crate) fn classify_refine_output(
    original_text: &str,
    llm_result: std::result::Result<CompletionRecord, String>,
) -> RefinedResponse {
    let original_len = original_text.chars().count();

    match llm_result {
        Err(reason) => RefinedResponse {
            original: original_text.to_string(),
            refined: original_text.to_string(),
            did_refine: false,
            fallback_reason: Some(classify_error_reason(&reason)),
        },
        Ok(record) => {
            let refined_text = record.text.trim().to_string();
            if refined_text.is_empty() {
                return RefinedResponse {
                    original: original_text.to_string(),
                    refined: original_text.to_string(),
                    did_refine: false,
                    fallback_reason: Some("empty_refinement"),
                };
            }
            let refined_len = refined_text.chars().count();
            if original_len > 0 && (refined_len as f32) > MAX_GROWTH_RATIO * (original_len as f32) {
                // Info-amplification guard — refined text grew too
                // much, probably hallucinated context.
                return RefinedResponse {
                    original: original_text.to_string(),
                    refined: original_text.to_string(),
                    did_refine: false,
                    fallback_reason: Some("bloat_rejected"),
                };
            }
            RefinedResponse {
                original: original_text.to_string(),
                refined: refined_text,
                did_refine: true,
                fallback_reason: None,
            }
        }
    }
}

/// Map a provider error string into a short categorical reason for
/// WAL audit. Errors are arbitrary strings from `provider.ask`; this
/// extracts a fixed-vocabulary tag.
fn classify_error_reason(err: &str) -> &'static str {
    let lower = err.to_ascii_lowercase();
    if lower.contains("timeout") {
        "timeout"
    } else if lower.contains("quota") || lower.contains("rate") || lower.contains("429") {
        "rate_limited"
    } else if lower.contains("auth") || lower.contains("401") || lower.contains("403") {
        "auth_failed"
    } else {
        "provider_error"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FreedomConfig;
    use crate::config::inference::CouncilConfig;

    fn cfg_with(enabled: bool, threshold: f32) -> FreedomConfig {
        let mut cfg = FreedomConfig::default();
        cfg.council = CouncilConfig {
            self_reflect_enabled: enabled,
            refine_threshold: Some(threshold),
            ..Default::default()
        };
        cfg
    }

    #[test]
    fn should_refine_disabled_by_kill_switch() {
        let cfg = cfg_with(false, 0.90);
        // Even with very low quality, kill-switch prevents refinement.
        assert!(!should_refine(&cfg, 0.10, 0));
    }

    #[test]
    fn should_refine_skipped_at_depth_above_zero() {
        let cfg = cfg_with(true, 0.90);
        // F3 fractal rule: depth > 0 NEVER reflects.
        assert!(!should_refine(&cfg, 0.10, 1));
        assert!(!should_refine(&cfg, 0.10, 2));
        assert!(!should_refine(&cfg, 0.10, 4));
    }

    #[test]
    fn should_refine_fires_when_below_threshold_and_depth_zero() {
        let cfg = cfg_with(true, 0.90);
        assert!(should_refine(&cfg, 0.85, 0));
        assert!(should_refine(&cfg, 0.50, 0));
    }

    #[test]
    fn should_refine_skips_above_threshold() {
        let cfg = cfg_with(true, 0.90);
        // Confident answers skip the reflect pass.
        assert!(!should_refine(&cfg, 0.95, 0));
        assert!(!should_refine(&cfg, 0.90, 0));
        assert!(!should_refine(&cfg, 1.00, 0));
    }

    #[test]
    fn should_refine_honours_operator_threshold_override() {
        let cfg = cfg_with(true, 0.50);
        // Operator dialled down threshold — only very low scores fire.
        assert!(should_refine(&cfg, 0.40, 0));
        assert!(!should_refine(&cfg, 0.60, 0));
    }

    #[test]
    fn classify_refine_output_provider_error_returns_original() {
        let result = classify_refine_output("answer text", Err("timeout after 30s".to_string()));
        assert!(!result.did_refine);
        assert_eq!(result.refined, "answer text");
        assert_eq!(result.fallback_reason, Some("timeout"));
    }

    #[test]
    fn classify_refine_output_categorises_rate_limit_error() {
        let r = classify_refine_output("x", Err("HTTP 429 rate limit exceeded".to_string()));
        assert_eq!(r.fallback_reason, Some("rate_limited"));
    }

    #[test]
    fn classify_refine_output_categorises_auth_error() {
        let r = classify_refine_output("x", Err("HTTP 401 unauthorized".to_string()));
        assert_eq!(r.fallback_reason, Some("auth_failed"));
    }

    #[test]
    fn classify_refine_output_empty_text_returns_original() {
        let record = CompletionRecord {
            text: "   ".to_string(),
            input_tokens: None,
            output_tokens: None,
        };
        let r = classify_refine_output("original answer", Ok(record));
        assert!(!r.did_refine);
        assert_eq!(r.refined, "original answer");
        assert_eq!(r.fallback_reason, Some("empty_refinement"));
    }

    #[test]
    fn classify_refine_output_accepts_genuine_improvement() {
        let record = CompletionRecord {
            text: "Better wording of the same idea.".to_string(),
            input_tokens: None,
            output_tokens: None,
        };
        let r = classify_refine_output("Worse wording of an idea.", Ok(record));
        assert!(r.did_refine);
        assert_eq!(r.refined, "Better wording of the same idea.");
        assert_eq!(r.fallback_reason, None);
    }

    #[test]
    fn classify_refine_output_rejects_bloated_response() {
        let original = "Short answer.";
        // refined text is 5× longer than original — way beyond
        // MAX_GROWTH_RATIO=1.5.
        let huge = "x".repeat(original.len() * 5);
        let record = CompletionRecord {
            text: huge,
            input_tokens: None,
            output_tokens: None,
        };
        let r = classify_refine_output(original, Ok(record));
        assert!(!r.did_refine, "bloat guard must reject");
        assert_eq!(r.refined, original);
        assert_eq!(r.fallback_reason, Some("bloat_rejected"));
    }

    #[test]
    fn classify_refine_output_accepts_within_growth_ratio() {
        let original = "x".repeat(100);
        // 1.4× growth — within bounds.
        let acceptable = "y".repeat(140);
        let record = CompletionRecord {
            text: acceptable.clone(),
            input_tokens: None,
            output_tokens: None,
        };
        let r = classify_refine_output(&original, Ok(record));
        assert!(r.did_refine);
        assert_eq!(r.refined, acceptable);
    }

    #[test]
    fn build_reflect_prompt_includes_explicit_anti_amplification_directive() {
        let p = build_reflect_prompt("what is 2+2?", "4");
        assert!(
            p.contains("not present in your prior answer"),
            "prompt missing anti-amplification directive: {p}"
        );
        assert!(p.contains("what is 2+2?"));
        assert!(p.contains("4"));
    }

    #[test]
    fn max_growth_ratio_is_set_to_1_5() {
        // Hard rule pin from Security threat #5 mitigation: bloat
        // guard at 1.5×. Future PRs touching this trip the test.
        assert!((MAX_GROWTH_RATIO - 1.5).abs() < 1e-6);
    }

    #[test]
    fn refine_system_prompt_says_do_not_add_facts() {
        // Pin the anti-amplification instruction is in the prompt.
        assert!(REFINE_SYSTEM_PROMPT.to_lowercase().contains("do not add"));
    }
}
