//! Council smart-trigger logic (CH-14).
//!
//! Convening a 3-hemisphere debate costs ~3× the spend + latency of a
//! single-hemisphere chat. Firing it on every prompt is wasteful — and
//! firing it on a 5-word small-talk message is comical. This module
//! decides WHEN the council should automatically convene, gated on
//! four orthogonal signals per the `SPEC_council_governance.md §1`
//! smart-trigger table:
//!
//!   1. **Complexity gate** — short, simple prompts (no questions,
//!      no code blocks, no multi-clause structure) skip the council.
//!      Council is for genuinely consequential calls.
//!   2. **Rate gate** — if a council ran in the last `min_interval`,
//!      skip. Cooldown prevents back-to-back chained debates from
//!      thrashing the operator's spend.
//!   3. **Budget gate** — if the operator's remaining daily provider
//!      budget is below the threshold (default: 3× a single chat's
//!      estimated cost), skip. Operator can lift via the autonomy
//!      level (full / elevated bypass the budget check).
//!   4. **Dissent gate** — pattern-match on prompt for markers that
//!      historically benefit from multi-hemisphere review (opinion
//!      questions, multi-step reasoning, value judgments, contested
//!      domains). If any fires, convene.
//!
//! The four gates are evaluated in order; the first one whose verdict
//! is `Skip` wins. `Convene` only fires if every gate either passed or
//! the dissent gate explicitly demanded a debate.
//!
//! Pure-function deterministic. No I/O, no LLM, no async. Caller
//! threads in the recent-debate-history + budget snapshot.

use std::time::Duration;

/// Outcome of one trigger evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TriggerDecision {
    /// Council should convene. `reason` is operator-facing diagnostic
    /// ("dissent_marker: opinion_question").
    Convene { reason: String },
    /// Council should skip this prompt. `reason` is operator-facing.
    Skip { reason: String },
}

impl TriggerDecision {
    pub fn should_convene(&self) -> bool {
        matches!(self, TriggerDecision::Convene { .. })
    }
    pub fn reason(&self) -> &str {
        match self {
            TriggerDecision::Convene { reason } | TriggerDecision::Skip { reason } => {
                reason.as_str()
            }
        }
    }
}

/// Context the trigger evaluator needs per call. Keep it lean — every
/// field is required so adding new ones is a deliberate spec move,
/// not a silent default-changes-behaviour drift.
#[derive(Debug, Clone, PartialEq)]
pub struct TriggerContext {
    /// Seconds since the operator's last council debate. `u64::MAX`
    /// means "no prior debate this session".
    pub seconds_since_last_council: u64,
    /// Remaining daily provider budget in USD — operator's quota
    /// minus what's been spent. `None` means "no budget tracking"
    /// (single-provider free local-qwen path, or autonomy lifted).
    pub remaining_budget_usd: Option<f32>,
    /// Estimated cost of one single-hemisphere call for this prompt
    /// (USD). Council convene needs ~3× this to stay within budget.
    pub estimated_single_call_usd: f32,
    /// Conservative bound for the complete reachable Council tree. Production
    /// callers populate this from the exact provider/model topology; the
    /// single-call multiplier remains an operator-controlled additional floor.
    pub estimated_council_cost_usd: Option<f32>,
}

/// Policy values for the four gates. Operator overrides land here via
/// `freedom.yaml::council.trigger` once the config surface exists; for
/// now operators stick with the defaults.
#[derive(Debug, Clone, PartialEq)]
pub struct TriggerPolicy {
    /// Minimum prompt length (chars) to even consider the complexity
    /// gate. Below this we always skip — small-talk doesn't deserve
    /// 3-hemisphere debate. Lowered from 120 → 80 (2026-05-17
    /// B-Konsens, Code-Explorer wedge): operators' real technical
    /// prompts often land in the 80-120 range; the prior threshold
    /// kept the council from firing on most genuine asks.
    pub min_complex_prompt_chars: usize,
    /// Minimum seconds between consecutive council convenes. Cooldown.
    pub min_interval: Duration,
    /// Council needs at least this many USD of remaining budget to
    /// fire — pinned as multiplier on the single-call cost so the
    /// policy scales with provider pricing changes.
    pub budget_multiplier: f32,
    /// Pattern markers that DEMAND a council convene regardless of
    /// the other gates (still subject to rate cooldown). Operator can
    /// extend; defaults pin the common "needs review" cases.
    pub dissent_markers: Vec<&'static str>,
    /// Convene the council on technically-deep prompts even when no
    /// explicit dissent marker fires. Triggers when the prompt carries
    /// a fenced code block AND a question mark AND clears the
    /// `min_complex_prompt_chars * 2` length bar. Default `true`
    /// (2026-05-17 B-Konsens): the prior default-skip semantic meant
    /// the council convened on ~0% of real operator prompts — only
    /// explicit "what's better" / "step by step" / "ethical" matches
    /// triggered. Operators who want the strict opt-in-only behaviour
    /// can flip this to `false`.
    pub convene_on_high_complexity: bool,
    /// Operator-supplied EXTRA dissent markers (SPEC-03b trigger config
    /// surface), appended to — never replacing — the built-in
    /// `dissent_markers`. Owned `String`s (the config is operator-typed at
    /// runtime, not `&'static`); matched lowercased exactly like the
    /// built-ins. Empty by default. Populated from
    /// `freedom.yaml::council.trigger.extra_dissent_markers`.
    pub extra_markers: Vec<String>,
}

impl Default for TriggerPolicy {
    fn default() -> Self {
        Self {
            min_complex_prompt_chars: 80,
            min_interval: Duration::from_secs(60),
            budget_multiplier: 3.0,
            dissent_markers: vec![
                // Opinion / judgment questions — multi-hemisphere
                // helps surface alternative framings.
                "should i",
                "what's better",
                "which is better",
                "what do you think",
                "your opinion",
                // Value-laden domains where consensus matters.
                "ethical",
                "morally",
                "is it ok to",
                "is it okay to",
                // Multi-step reasoning markers.
                "step by step",
                "walk me through",
                "reason through",
                // Disagreement-likely topics.
                "controversial",
                "debate",
                "pros and cons",
                // Technical-depth markers (2026-05-17 B-Konsens) —
                // operators' real prompts to NEOTH overwhelmingly
                // touch design / refactor / architecture decisions
                // where multi-hemisphere review is the whole point.
                "best way",
                "best approach",
                "design",
                "architect",
                "tradeoff",
                "trade-off",
                "trade off",
                "refactor",
                "review this",
                "critique",
                "compare",
                " vs ",
                "explain why",
                "root cause",
                "diagnose",
            ],
            convene_on_high_complexity: true,
            extra_markers: Vec::new(),
        }
    }
}

/// Evaluate every gate in the documented order and return the first
/// `Skip` verdict OR a `Convene` if the dissent gate fired or all
/// other gates passed.
pub fn should_convene(
    prompt: &str,
    ctx: &TriggerContext,
    policy: &TriggerPolicy,
) -> TriggerDecision {
    // Gate 1 — complexity. Cheap heuristic; short prompts skip.
    if !is_complex_prompt(prompt, policy.min_complex_prompt_chars) {
        return TriggerDecision::Skip {
            reason: format!(
                "complexity: prompt below {}-char threshold",
                policy.min_complex_prompt_chars
            ),
        };
    }

    // Gate 2 — rate cooldown. Prevents back-to-back debates.
    if ctx.seconds_since_last_council < policy.min_interval.as_secs() {
        return TriggerDecision::Skip {
            reason: format!(
                "rate: last council {}s ago, cooldown {}s",
                ctx.seconds_since_last_council,
                policy.min_interval.as_secs()
            ),
        };
    }

    // Gate 3 — budget. Only checked when tracking is enabled.
    if let Some(remaining) = ctx.remaining_budget_usd {
        let needed = (ctx.estimated_single_call_usd * policy.budget_multiplier)
            .max(ctx.estimated_council_cost_usd.unwrap_or(0.0));
        if remaining < needed {
            return TriggerDecision::Skip {
                reason: format!(
                    "budget: remaining ${remaining:.2} below council threshold ${needed:.2}",
                ),
            };
        }
    }

    // Gate 4 — dissent markers. Lowercase scan against the prompt.
    let lowered = prompt.to_ascii_lowercase();
    for marker in &policy.dissent_markers {
        if lowered.contains(marker) {
            return TriggerDecision::Convene {
                reason: format!("dissent_marker: {marker}"),
            };
        }
    }
    // Gate 4b — operator-supplied extra markers (SPEC-03b). Same scan,
    // appended to the built-ins; an empty operator list is a no-op.
    for marker in &policy.extra_markers {
        if !marker.is_empty() && lowered.contains(marker.as_str()) {
            return TriggerDecision::Convene {
                reason: format!("dissent_marker: {marker}"),
            };
        }
    }

    // Gate 5 — high-complexity convene (2026-05-17 B-Konsens, Code-Explorer
    // wedge). Code-fence + question mark + length ≥ 2× the min threshold
    // signals a substantive technical ask that benefits from multi-
    // hemisphere review even when no explicit dissent marker fires.
    // Operators who want strict opt-in-only behaviour set
    // `convene_on_high_complexity = false` in their policy override.
    if policy.convene_on_high_complexity
        && prompt.contains("```")
        && prompt.contains('?')
        && prompt.len() >= policy.min_complex_prompt_chars.saturating_mul(2)
    {
        return TriggerDecision::Convene {
            reason: "high_complexity: code_fence + question + length".into(),
        };
    }

    // Every gate either passed or skipped without an explicit
    // convene demand. Default: skip — council is opt-in by signal.
    TriggerDecision::Skip {
        reason: "no dissent marker matched + no explicit convene signal".into(),
    }
}

/// Heuristic complexity check. Cheap + deterministic; LLM-judge style
/// "is this complex" can layer on top later via the embedding path
/// (CH-12 adaptive thresholds).
fn is_complex_prompt(prompt: &str, min_chars: usize) -> bool {
    if prompt.len() < min_chars {
        return false;
    }
    // Multi-clause / code-block / question-laden prompts are complex.
    let has_question_mark = prompt.contains('?');
    let has_code_fence = prompt.contains("```");
    let multi_clause = prompt.matches('.').count() >= 2 || prompt.contains(';');
    has_question_mark || has_code_fence || multi_clause
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_default() -> TriggerContext {
        TriggerContext {
            seconds_since_last_council: u64::MAX,
            remaining_budget_usd: None,
            estimated_single_call_usd: 0.10,
            estimated_council_cost_usd: None,
        }
    }

    // SPEC-03b: operator-supplied extra dissent markers convene the council
    // even when no BUILT-IN marker fires — without changing default behaviour.
    #[test]
    fn extra_markers_convene_and_default_skips() {
        // Long + question ⇒ passes the complexity gate; contains NO built-in
        // marker and no code fence ⇒ defaults take it to Skip.
        let prompt =
            "Please carefully evaluate the threat model for this subsystem boundary, yes or no?";

        let default_policy = TriggerPolicy::default();
        let r = should_convene(prompt, &ctx_default(), &default_policy);
        assert!(
            !r.should_convene(),
            "default policy must NOT convene on this prompt (no built-in marker), got {r:?}"
        );

        let mut p = TriggerPolicy::default();
        p.extra_markers = vec!["threat model".to_string()];
        let r2 = should_convene(prompt, &ctx_default(), &p);
        match r2 {
            TriggerDecision::Convene { reason } => {
                assert!(
                    reason.contains("threat model"),
                    "extra marker must attribute the convene, got: {reason}"
                );
            }
            other => panic!("extra marker must convene, got {other:?}"),
        }
    }

    #[test]
    fn short_prompt_skips_via_complexity_gate() {
        let p = TriggerPolicy::default();
        let r = should_convene("yes", &ctx_default(), &p);
        assert!(!r.should_convene());
        assert!(r.reason().contains("complexity"));
    }

    #[test]
    fn long_chatty_prompt_without_dissent_marker_skips() {
        // Long enough to pass complexity (>120 chars + multi-clause)
        // but no dissent markers → default is skip rather than always-
        // convene. Multi-clause via two sentence-ending periods.
        let prompt = "Hello, I'm just describing a long but mundane day at work. There was \
                      typing involved. A few cups of coffee. Nothing particularly contentious \
                      happened in the conversation.";
        let p = TriggerPolicy::default();
        let r = should_convene(prompt, &ctx_default(), &p);
        assert!(!r.should_convene(), "expected Skip, got {r:?}");
        assert!(r.reason().contains("no dissent marker matched"));
    }

    #[test]
    fn opinion_question_triggers_convene_via_dissent_gate() {
        let prompt = "I'm trying to choose between Rust and Go for this CLI tool that needs \
                      cross-platform builds, fast startup, and a good async story — \
                      what do you think is better given my constraints?";
        let p = TriggerPolicy::default();
        let r = should_convene(prompt, &ctx_default(), &p);
        assert!(r.should_convene(), "expected Convene, got {r:?}");
        assert!(r.reason().contains("dissent_marker"));
        assert!(r.reason().contains("what do you think"));
    }

    #[test]
    fn rate_gate_blocks_repeat_convene_within_cooldown() {
        // Multi-clause + question mark → passes complexity.
        let prompt = "Walk me through whether I should refactor this entire authentication \
                      module given the dependency rot in the JWT library? Step by step please \
                      — also covering the migration risks.";
        let ctx = TriggerContext {
            seconds_since_last_council: 10, // well under 60s default
            ..ctx_default()
        };
        let p = TriggerPolicy::default();
        let r = should_convene(prompt, &ctx, &p);
        assert!(!r.should_convene());
        assert!(r.reason().contains("rate"));
        assert!(r.reason().contains("cooldown"));
    }

    #[test]
    fn budget_gate_skips_when_remaining_too_low() {
        // Single call = $0.10; council multiplier = 3.0 → need $0.30.
        // Remaining $0.15 → skip.
        let prompt = "Should I switch to a Postgres backend or stay with SQLite given the \
                      cross-platform deployment constraint? Please walk me through the tradeoffs.";
        let ctx = TriggerContext {
            seconds_since_last_council: u64::MAX,
            remaining_budget_usd: Some(0.15),
            estimated_single_call_usd: 0.10,
            estimated_council_cost_usd: None,
        };
        let p = TriggerPolicy::default();
        let r = should_convene(prompt, &ctx, &p);
        assert!(!r.should_convene());
        assert!(r.reason().contains("budget"));
        assert!(r.reason().contains("0.30"));
    }

    #[test]
    fn budget_gate_passes_when_remaining_exceeds_threshold() {
        let prompt = "Should I switch to a Postgres backend now or stay with SQLite \
                      a bit longer? Walk me through the cross-platform deployment tradeoffs \
                      step by step please.";
        let ctx = TriggerContext {
            seconds_since_last_council: u64::MAX,
            remaining_budget_usd: Some(5.00),
            estimated_single_call_usd: 0.10,
            estimated_council_cost_usd: None,
        };
        let p = TriggerPolicy::default();
        let r = should_convene(prompt, &ctx, &p);
        assert!(r.should_convene(), "expected Convene: {r:?}");
    }

    #[test]
    fn budget_gate_never_drops_below_complete_tree_bound() {
        let prompt = "Should I choose this recursive Council architecture? Please walk me through the tradeoffs across every provider and sub-slot.";
        let ctx = TriggerContext {
            seconds_since_last_council: u64::MAX,
            remaining_budget_usd: Some(0.50),
            estimated_single_call_usd: 0.10,
            estimated_council_cost_usd: Some(0.75),
        };
        let decision = should_convene(prompt, &ctx, &TriggerPolicy::default());
        assert!(
            matches!(
                decision,
                TriggerDecision::Skip { ref reason }
                    if reason.contains("budget") && reason.contains("0.75")
            ),
            "full tree bound must override the 3x single-leaf floor: {decision:?}"
        );
    }

    #[test]
    fn no_budget_tracking_skips_the_budget_gate() {
        // remaining_budget_usd = None → budget gate skipped entirely.
        // Dissent marker still fires.
        let prompt = "What's better for this particular case — async or sync IO when the \
                      latency budget is sub-millisecond and the workload is bursty? \
                      Walk me through the tradeoffs please.";
        let ctx = TriggerContext {
            seconds_since_last_council: u64::MAX,
            remaining_budget_usd: None,
            estimated_single_call_usd: 100.0,
            estimated_council_cost_usd: None,
        };
        let p = TriggerPolicy::default();
        let r = should_convene(prompt, &ctx, &p);
        assert!(r.should_convene());
    }

    #[test]
    fn ethical_question_triggers_convene() {
        let prompt = "Is it ethical to scrape this public Wikipedia article for my dataset \
                      given that the license technically allows it but the maintainers seem \
                      unhappy about it?";
        let r = should_convene(prompt, &ctx_default(), &TriggerPolicy::default());
        assert!(r.should_convene());
        assert!(r.reason().contains("ethical"));
    }

    #[test]
    fn code_block_prompt_passes_complexity_gate() {
        let prompt = "Here is a snippet:\n```rust\nfn foo() { unsafe { *ptr } }\n```\n\
                      what do you think about this approach for the lockless ring buffer?";
        let r = should_convene(prompt, &ctx_default(), &TriggerPolicy::default());
        // Has code fence (complexity), has "what do you think" (dissent)
        // → convene.
        assert!(r.should_convene());
    }

    #[test]
    fn gate_order_complexity_before_rate() {
        // A SHORT prompt with rate cooldown still active should skip
        // via complexity (the first gate), not rate. Verifies the
        // documented evaluation order.
        let ctx = TriggerContext {
            seconds_since_last_council: 5,
            ..ctx_default()
        };
        let p = TriggerPolicy::default();
        let r = should_convene("hi", &ctx, &p);
        assert!(!r.should_convene());
        // Complexity wins first.
        assert!(r.reason().contains("complexity"));
    }

    #[test]
    fn gate_order_rate_before_budget() {
        // Complex prompt (question + multi-clause), rate still active,
        // budget also low — rate gate wins because it runs first.
        let prompt = "I'd like a detailed walkthrough of every aspect of this design choice? \
                      Please consider the tradeoffs across all dimensions. Step by step \
                      please — also covering the long-term maintenance implications.";
        let ctx = TriggerContext {
            seconds_since_last_council: 5,
            remaining_budget_usd: Some(0.01),
            estimated_single_call_usd: 0.10,
            estimated_council_cost_usd: None,
        };
        let p = TriggerPolicy::default();
        let r = should_convene(prompt, &ctx, &p);
        assert!(!r.should_convene());
        assert!(r.reason().contains("rate"));
    }

    #[test]
    fn is_complex_prompt_short_circuits_on_length() {
        assert!(!is_complex_prompt("short", 120));
        // Long enough but only declarative sentence, no markers.
        let p = "a".repeat(200);
        assert!(!is_complex_prompt(&p, 120));
    }

    #[test]
    fn is_complex_prompt_recognises_question_mark() {
        let p = format!("{}?", "a".repeat(200));
        assert!(is_complex_prompt(&p, 120));
    }

    #[test]
    fn is_complex_prompt_recognises_multi_clause_via_periods() {
        let p = format!("{}. then. another.", "x".repeat(150));
        assert!(is_complex_prompt(&p, 120));
    }

    #[test]
    fn default_policy_pins_documented_baselines() {
        // Pin the operator-visible defaults — refactors that drift
        // these break this test loudly rather than silently changing
        // the council's trigger behaviour.
        // Lowered min_complex_prompt_chars 120 → 80 (2026-05-17
        // B-Konsens, Code-Explorer wedge); convene_on_high_complexity
        // = true is the new default-fire-on-substantive-tech-ask flag.
        let p = TriggerPolicy::default();
        assert_eq!(p.min_complex_prompt_chars, 80);
        assert_eq!(p.min_interval, Duration::from_secs(60));
        assert!((p.budget_multiplier - 3.0).abs() < f32::EPSILON);
        assert!(p.convene_on_high_complexity);
        // Sanity: dissent markers cover the documented categories.
        assert!(p.dissent_markers.iter().any(|m| m.contains("opinion")));
        assert!(p.dissent_markers.iter().any(|m| m.contains("ethical")));
        assert!(p.dissent_markers.iter().any(|m| m.contains("step by step")));
        // Sanity: B-Konsens 2026-05-17 technical-depth markers present.
        assert!(p.dissent_markers.iter().any(|m| m.contains("design")));
        assert!(p.dissent_markers.iter().any(|m| m.contains("refactor")));
        assert!(p.dissent_markers.iter().any(|m| m.contains("tradeoff")));
        assert!(p.dissent_markers.iter().any(|m| m.contains("diagnose")));
    }

    #[test]
    fn high_complexity_branch_convenes_on_code_fence_plus_question_plus_length() {
        // Pure-complexity convene without any dissent marker: a code
        // block + question mark + length ≥ 2 × min_complex_prompt_chars.
        // Default min = 80 → threshold = 160. The prompt below has 7
        // lines of code and a clear question, no opinion words.
        let prompt = "Here's my implementation:\n\
                      ```rust\n\
                      fn handle(req: Request) -> Response {\n\
                          let parsed = parse_input(req.body);\n\
                          let validated = validate(parsed);\n\
                          render(validated)\n\
                      }\n\
                      ```\n\
                      Will this implementation deadlock under concurrent load?";
        assert!(prompt.len() >= 160, "test setup: prompt long enough");
        let p = TriggerPolicy::default();
        let r = should_convene(prompt, &ctx_default(), &p);
        assert!(r.should_convene(), "expected Convene, got {r:?}");
        assert!(r.reason().contains("high_complexity"));
    }

    #[test]
    fn high_complexity_branch_respects_opt_out_flag() {
        // Operator sets `convene_on_high_complexity = false` → revert
        // to the prior strict opt-in-only behaviour. Prompt that would
        // have fired via the new branch now Skips.
        let prompt = "Here's my implementation:\n\
                      ```rust\n\
                      fn handle(req: Request) -> Response { todo!() }\n\
                      ```\n\
                      Will this implementation deadlock under concurrent load \
                      when the executor pool is saturated and the channel back-\
                      pressures?";
        let mut p = TriggerPolicy::default();
        p.convene_on_high_complexity = false;
        let r = should_convene(prompt, &ctx_default(), &p);
        assert!(!r.should_convene(), "expected Skip with opt-out, got {r:?}");
    }

    #[test]
    fn high_complexity_branch_requires_all_three_signals() {
        let p = TriggerPolicy::default();
        // Only code fence + question, but too short (under 160 chars).
        let short = "```rust\nlet x = 1;\n```\nbug?";
        let r1 = should_convene(short, &ctx_default(), &p);
        // Even shorter than the complexity gate's min length →
        // fails Gate 1 before reaching the high-complexity check.
        assert!(!r1.should_convene());
        // Long + question but no code fence — must miss the branch.
        // Carefully avoid every dissent marker so this isolates the
        // "high-complexity needs code fence" assertion. Avoids: design,
        // refactor, architect, review, critique, compare, vs, tradeoff,
        // explain why, root cause, diagnose, best way/approach, should i.
        let no_fence = "I'm currently writing some chatty filler text that simply \
                        describes a long mundane scenario without any technical \
                        signal markers in it whatsoever, ending in a question?";
        let r2 = should_convene(no_fence, &ctx_default(), &p);
        // No dissent marker + no code fence → still skips even at length.
        assert!(!r2.should_convene(), "expected Skip, got {r2:?}");
    }

    #[test]
    fn technical_depth_markers_trigger_convene() {
        // B-Konsens 2026-05-17 markers — pin each new entry against a
        // realistic prompt so a future drop is caught immediately.
        let p = TriggerPolicy::default();
        let cases = [
            (
                "the best way to handle async errors in this design",
                "best way",
            ),
            ("what's the best approach for caching here", "best approach"),
            ("we need to design a clean abstraction over this", "design"),
            (
                "review this implementation and tell me what's wrong",
                "review this",
            ),
            (
                "compare option A and option B for our use case here",
                "compare",
            ),
            (
                "which one is faster — Vec vs SmallVec for our pattern",
                " vs ",
            ),
            (
                "can you critique this approach and find weak spots",
                "critique",
            ),
            (
                "explain why we hit a deadlock here under contention",
                "explain why",
            ),
            (
                "the root cause is unclear — help me diagnose this",
                "root cause",
            ),
            (
                "any tradeoff between latency and throughput here",
                "tradeoff",
            ),
            (
                "we should refactor this module before adding features",
                "refactor",
            ),
            (
                "the architect should sign off before we proceed",
                "architect",
            ),
        ];
        for (prompt, marker) in cases {
            // Pad with filler to clear the 80-char complexity threshold.
            let padded = format!("{prompt}. Some additional context for this question.");
            let r = should_convene(&padded, &ctx_default(), &p);
            assert!(
                r.should_convene(),
                "expected Convene for marker {marker:?}, got {r:?}"
            );
            assert!(
                r.reason().contains(marker),
                "reason should cite marker {marker:?}, got {}",
                r.reason()
            );
        }
    }
}
