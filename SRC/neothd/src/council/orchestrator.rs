//! Council orchestrator: fires the three hemispheres in parallel,
//! collects responses, scores dissent, produces a verdict.
//!
//! The orchestrator is generic over a `HemisphereProvider` trait so:
//!   - production code passes per-role `Box<dyn Provider>` adapters
//!     built via `providers::from_config_for_role`;
//!   - tests pass mock implementations with deterministic responses.
//!
//! All three hemispheres run concurrently via `FuturesUnordered`.
//! K-Perf-1 (2026-05-17 B-Konsens): the orchestrator EARLY-EXITS as
//! soon as quorum (≥ QUORUM_THRESHOLD present responses) is reached
//! AND those responses agree (DissentScore::is_consensus()). The
//! remaining slow hemisphere(s) have their futures dropped → providers
//! receive cancellation (HTTP request aborted mid-stream). The
//! resulting `CouncilDebate.responses` Vec is missing the cancelled
//! hemisphere(s), and the verdict is `Consensus` because the quorum
//! agreed.
//!
//! Trade-off: operators on metered providers (OpenAI / Anthropic API /
//! OpenRouter) may pay for partially-completed cancelled calls. The
//! latency win is dominated by the slowest hemisphere on a council
//! call — typically claude_cli tmux at 10-30s vs Gemini API at 2-5s.
//! Saving 8-25s when 2 hemispheres agree quickly is a meaningful daily
//! UX improvement; the cost is a partial token bill on the cancelled
//! call which most operator plans amortise.
//!
//! Errors don't short-circuit — a failed hemisphere becomes an error
//! variant in its `HemisphereResponse` so the verdict step sees the
//! full picture (the QuorumFailed variant fires when too few present
//! responses arrived even after every future settled).

use std::time::Instant;

use futures_util::stream::{FuturesUnordered, StreamExt};

use crate::config::inference::HemisphereRole;

use super::budget::BudgetToken;
use super::dissent::{DissentScore, score_dissent};
use super::types::{CouncilDebate, HemisphereRefusal, HemisphereResponse, Verdict, dur_to_ms};
use crate::security::refusal_cause::classify_cause;
use crate::security::refusal_detect::classify as classify_refusal;

/// Marker string written into `HemisphereResponse::error` when a
/// hemisphere is skipped because the shared [`BudgetToken`] is already
/// exhausted. The chat dispatcher's `responses[i].error` audit path
/// surfaces this verbatim so operators see exactly which hemispheres
/// got cut off and which ones consumed the cap.
pub const BUDGET_EXHAUSTED_ERROR: &str = "budget-exhausted";

/// Minimum hemispheres required for a verdict. Below this threshold
/// the orchestrator returns `Verdict::QuorumFailed` rather than
/// inventing consensus from one voice.
pub const QUORUM_THRESHOLD: u32 = 2;

/// Trait every hemisphere participant implements. Production wraps a
/// `Box<dyn Provider>`; tests use deterministic mocks.
#[async_trait::async_trait]
pub trait HemisphereProvider: Send + Sync {
    /// Stable id for the underlying provider (matches
    /// `InferenceProvider::as_str` in production).
    fn provider_id(&self) -> String;
    /// Run a completion. Returns the text on success, or an error
    /// reason string the orchestrator stores into
    /// `HemisphereResponse::error`.
    async fn ask(&self, prompt: &str) -> Result<CompletionRecord, String>;
    /// E-2 Phase 1 (Session 13) — recursion-aware variant of `ask`.
    /// Default impl ignores `depth` and falls through to `ask` so every
    /// existing implementor keeps working without changes. Adapters
    /// that want fractal-hemisphere behaviour ("each hemisphere can
    /// spawn its own inner council on hard sub-questions") override
    /// this to inspect `depth`: when `depth > 1` they may convene
    /// `run_debate_with_depth(depth - 1, ...)` against sub-providers
    /// before returning; when `depth <= 1` they MUST behave as a flat
    /// completion (no inner council).
    ///
    /// Actual recursion wiring is the E-2 Phase 2 follow-up; Phase 1
    /// lands the trait surface + plumbing so the future override has a
    /// pinned shape.
    async fn ask_with_depth(&self, prompt: &str, depth: u8) -> Result<CompletionRecord, String> {
        let _ = depth;
        self.ask(prompt).await
    }

    /// Pick #19 (Session 14 F6 fractal rule) — budget-aware variant of
    /// `ask_with_depth`. The shared [`BudgetToken`] tracks total LLM
    /// calls across the entire council recursion tree; an adapter that
    /// internally recurses (calls `run_debate_with_depth_budget`)
    /// MUST clone + pass the same token so the cap is honoured.
    ///
    /// Default impl ignores the budget and forwards to `ask_with_depth`
    /// — that's safe because [`run_one`] charges against the budget
    /// BEFORE invoking this method, so adapters that don't recurse
    /// internally are already accounted for. Only adapters that fan
    /// out to additional LLM calls (inner council, multi-shot
    /// self-reflect, judge passes) need to override.
    async fn ask_with_depth_budget(
        &self,
        prompt: &str,
        depth: u8,
        budget: BudgetToken,
    ) -> Result<CompletionRecord, String> {
        let _ = budget;
        self.ask_with_depth(prompt, depth).await
    }
}

/// Minimal record returned by a hemisphere; matches the shape needed
/// to populate `HemisphereResponse` without depending on
/// `providers::Completion` directly (keeps the council module
/// dependency-free for test purposes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletionRecord {
    pub text: String,
    pub input_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
}

/// Run a full council debate against the three configured hemispheres.
/// Returns the aggregate debate record including dissent + verdict.
///
/// The orchestrator does not emit WAL frames — the caller (chat
/// dispatch) owns the audit emission so the WAL band allocation can
/// stay centralised. Caller passes `prompt_hash_xxh3` so debate audit
/// frames correlate with the upstream `PROVIDER_REQUEST` frame.
/// Backwards-compatible entry point. Threads
/// `HemisphereCouncilDepth::default()` (= 1, flat) through to
/// `run_debate_with_depth`. Callers that read the operator's topology
/// (`config.inference.hemisphere_council_depth`) should call
/// `run_debate_with_depth` directly so future inner-council recursion
/// fires when the operator opted in.
pub async fn run_debate(
    prompt: &str,
    prompt_hash_xxh3: u64,
    left: &dyn HemisphereProvider,
    right: &dyn HemisphereProvider,
    cerebellum: &dyn HemisphereProvider,
) -> CouncilDebate {
    run_debate_with_depth(
        prompt,
        prompt_hash_xxh3,
        crate::config::inference::HemisphereCouncilDepth::default().get(),
        left,
        right,
        cerebellum,
    )
    .await
}

/// E-2 Phase 1 (Session 13) — recursion-aware orchestrator entry.
/// `depth` is passed through to every hemisphere's `ask_with_depth`
/// invocation. Default-impl hemispheres ignore the value (flat
/// behaviour). Adapters that override `ask_with_depth` may convene an
/// inner council on hard sub-questions as long as the depth budget
/// permits.
pub async fn run_debate_with_depth(
    prompt: &str,
    prompt_hash_xxh3: u64,
    depth: u8,
    left: &dyn HemisphereProvider,
    right: &dyn HemisphereProvider,
    cerebellum: &dyn HemisphereProvider,
) -> CouncilDebate {
    // Backwards-compat entry: creates a fresh BudgetToken with the
    // default cap so callers that don't yet know about budget
    // propagation still get the F6 protection (15 calls total).
    let budget = BudgetToken::new(crate::config::inference::DEFAULT_MAX_CALLS_PER_USER_MESSAGE);
    run_debate_with_depth_budget(
        prompt,
        prompt_hash_xxh3,
        depth,
        budget,
        left,
        right,
        cerebellum,
    )
    .await
}

/// Pick #19 (Session 14 F6 fractal rule) — budget-aware orchestrator
/// entry. Threads a shared [`BudgetToken`] through every hemisphere's
/// `ask_with_depth_budget` invocation. The orchestrator charges the
/// token BEFORE spawning each hemisphere's future — if the cap is
/// already exhausted, the hemisphere is replaced with a synthetic
/// `HemisphereResponse { error: Some("budget-exhausted"), .. }` and
/// no provider call is made.
///
/// Adapters that internally recurse (override `ask_with_depth_budget`
/// to call this function with a smaller `depth`) MUST clone the same
/// token so the cap stays shared across the entire recursion tree.
pub async fn run_debate_with_depth_budget(
    prompt: &str,
    prompt_hash_xxh3: u64,
    depth: u8,
    budget: BudgetToken,
    left: &dyn HemisphereProvider,
    right: &dyn HemisphereProvider,
    cerebellum: &dyn HemisphereProvider,
) -> CouncilDebate {
    let overall_start = Instant::now();

    // K-Perf-1 2026-05-17: FuturesUnordered + early-exit on quorum-
    // with-consensus. Three concurrent tasks; first 2-3 to settle
    // drive the verdict.
    let mut tasks: FuturesUnordered<_> = FuturesUnordered::new();
    tasks.push(Box::pin(run_one(
        HemisphereRole::Left,
        left,
        prompt,
        depth,
        budget.clone(),
    ))
        as std::pin::Pin<
            Box<dyn std::future::Future<Output = HemisphereResponse> + Send>,
        >);
    tasks.push(Box::pin(run_one(
        HemisphereRole::Right,
        right,
        prompt,
        depth,
        budget.clone(),
    ))
        as std::pin::Pin<
            Box<dyn std::future::Future<Output = HemisphereResponse> + Send>,
        >);
    tasks.push(Box::pin(run_one(
        HemisphereRole::Cerebellum,
        cerebellum,
        prompt,
        depth,
        budget.clone(),
    ))
        as std::pin::Pin<
            Box<dyn std::future::Future<Output = HemisphereResponse> + Send>,
        >);

    let mut responses: Vec<HemisphereResponse> = Vec::with_capacity(3);
    while let Some(resp) = tasks.next().await {
        responses.push(resp);
        // Early-exit check: quorum reached + present responses agree.
        // Audit 2026-05-19 Type #13 Phase 2: route both `is_present` and
        // text extraction through the typed `outcome()` so the state
        // machine is the single source of truth.
        let present_count = responses
            .iter()
            .filter(|r| r.outcome().is_present())
            .count() as u32;
        if present_count >= QUORUM_THRESHOLD {
            let texts: Vec<&str> = responses
                .iter()
                .filter_map(|r| r.outcome().text())
                .collect();
            let early_dissent = score_dissent(&texts);
            if early_dissent.is_consensus() {
                // Quorum + consensus → verdict locked. Drop the
                // FuturesUnordered to cancel remaining hemispheres.
                break;
            }
        }
    }
    // Drop tasks explicitly — cancels any in-flight provider HTTP
    // requests for hemispheres we early-exited past.
    drop(tasks);

    // Preserve the legacy L/R/C indexing in the responses Vec so
    // callers using `responses[0/1/2]` (e.g. cli/chat.rs callosum
    // branch) keep working. Sort by role's int discriminant.
    responses.sort_by_key(|r| role_index(r.role));

    let texts: Vec<&str> = responses
        .iter()
        .filter_map(|r| r.outcome().text())
        .collect();
    let dissent = score_dissent(&texts);
    let verdict = decide_verdict(&responses, dissent, &texts);
    CouncilDebate {
        prompt_hash_xxh3,
        responses,
        dissent,
        verdict,
        total_latency_ms: dur_to_ms(overall_start.elapsed()),
    }
}

/// Stable sort key for `HemisphereResponse` so the response Vec keeps
/// the operator-expected L/R/C order even when FuturesUnordered
/// settles them out-of-order.
fn role_index(role: HemisphereRole) -> u8 {
    match role {
        HemisphereRole::Left => 0,
        HemisphereRole::Right => 1,
        HemisphereRole::Cerebellum => 2,
    }
}

async fn run_one(
    role: HemisphereRole,
    h: &dyn HemisphereProvider,
    prompt: &str,
    depth: u8,
    budget: BudgetToken,
) -> HemisphereResponse {
    let started = Instant::now();
    let provider = h.provider_id();
    // Pick #19 F6 fractal rule — charge BEFORE the LLM call. The shared
    // counter spans every hemisphere in this debate AND any nested
    // `run_debate_with_depth_budget` an adapter recurses into. When
    // the cap is hit we synthesise a skipped-response (mirrors the
    // shape of a timeout-cancelled hemisphere) so the verdict step
    // sees a uniform `HemisphereResponse` regardless of cause.
    if let Err(_exhausted) = budget.charge() {
        return HemisphereResponse {
            role,
            provider,
            text: None,
            error: Some(BUDGET_EXHAUSTED_ERROR.to_string()),
            latency_ms: dur_to_ms(started.elapsed()),
            input_tokens: None,
            output_tokens: None,
            refusal: None,
        };
    }
    match h.ask_with_depth_budget(prompt, depth, budget).await {
        Ok(rec) => {
            // R-03: per-hemisphere refusal classification. The orchestrator
            // runs the deterministic Schicht-0 classifier + cause taxonomy
            // on every successful text so the chat dispatcher can detect
            // "1-2 hemispheres refused while others succeeded" and route
            // around the refusal instead of treating the whole debate as
            // blocked. Classifier is pure-function pattern matching — fast
            // enough to run on every council reply without an escape hatch.
            let refusal = classify_per_hemisphere(&rec.text);
            HemisphereResponse {
                role,
                provider,
                text: Some(rec.text),
                error: None,
                latency_ms: dur_to_ms(started.elapsed()),
                input_tokens: rec.input_tokens,
                output_tokens: rec.output_tokens,
                refusal,
            }
        }
        Err(reason) => HemisphereResponse {
            role,
            provider,
            text: None,
            error: Some(reason),
            latency_ms: dur_to_ms(started.elapsed()),
            input_tokens: None,
            output_tokens: None,
            refusal: None,
        },
    }
}

/// R-03 helper. Returns `Some(HemisphereRefusal)` when the deterministic
/// classifier flagged the text as a refusal; `None` for normal completions.
/// Couples the council orchestrator to the security classifier — the
/// classifier is pure-function + has no I/O so this is fine for both
/// production code and unit tests.
fn classify_per_hemisphere(text: &str) -> Option<HemisphereRefusal> {
    let report = classify_refusal(text);
    if !report.is_refusal() {
        return None;
    }
    let cause = classify_cause(text);
    Some(HemisphereRefusal {
        class: report.class,
        class_confidence: report.confidence,
        cause: cause.cause,
        cause_confidence: cause.confidence,
    })
}

fn decide_verdict(
    responses: &[HemisphereResponse],
    dissent: DissentScore,
    texts: &[&str],
) -> Verdict {
    let responded = responses
        .iter()
        .filter(|r| r.outcome().is_present())
        .count() as u32;
    if responded < QUORUM_THRESHOLD {
        return Verdict::QuorumFailed {
            responded,
            required: QUORUM_THRESHOLD,
        };
    }
    if dissent.is_consensus() {
        // Pick the response whose token length is the median — proxy
        // for "most representative" without an LLM judge. With 2 or 3
        // present responses this is deterministic.
        let winning = pick_median(texts);
        Verdict::Consensus {
            winning_text: winning.to_string(),
        }
    } else {
        Verdict::Split {
            summary: build_split_summary(responses),
        }
    }
}

fn pick_median<'a>(texts: &[&'a str]) -> &'a str {
    let mut indexed: Vec<(usize, usize)> = texts
        .iter()
        .enumerate()
        .map(|(i, t)| (i, t.len()))
        .collect();
    indexed.sort_by_key(|(_, len)| *len);
    let middle = indexed.len() / 2;
    let (idx, _) = indexed[middle];
    texts[idx]
}

fn build_split_summary(responses: &[HemisphereResponse]) -> String {
    let mut parts = Vec::with_capacity(responses.len());
    for r in responses {
        let role = r.role.as_str();
        let head = r
            .text
            .as_deref()
            .map(|t| t.chars().take(40).collect::<String>())
            .unwrap_or_else(|| "(no response)".into());
        parts.push(format!("{role}={head}"));
    }
    parts.join(" | ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock hemisphere that returns a fixed string. Tests construct
    /// these to drive deterministic debates without touching real
    /// providers.
    struct MockHemisphere {
        id: &'static str,
        response: Result<&'static str, &'static str>,
    }

    #[async_trait::async_trait]
    impl HemisphereProvider for MockHemisphere {
        fn provider_id(&self) -> String {
            self.id.to_string()
        }
        async fn ask(&self, _prompt: &str) -> Result<CompletionRecord, String> {
            match self.response {
                Ok(text) => Ok(CompletionRecord {
                    text: text.to_string(),
                    input_tokens: Some(10),
                    output_tokens: Some(20),
                }),
                Err(err) => Err(err.to_string()),
            }
        }
    }

    fn mk(id: &'static str, text: &'static str) -> MockHemisphere {
        MockHemisphere {
            id,
            response: Ok(text),
        }
    }

    fn mk_err(id: &'static str, err: &'static str) -> MockHemisphere {
        MockHemisphere {
            id,
            response: Err(err),
        }
    }

    #[tokio::test]
    async fn consensus_when_all_hemispheres_agree() {
        // K-Perf-1 (2026-05-17): with FuturesUnordered + early-exit
        // on quorum-with-consensus, the 3rd hemisphere's future MAY
        // get cancelled when the first two agree. responses.len() is
        // therefore in 2..=3 depending on tokio task scheduling. The
        // winning_text + verdict must still be Consensus on the
        // agreed text.
        let l = mk("claude", "the answer is forty two");
        let r = mk("gemini", "the answer is forty two");
        let c = mk("local_qwen", "the answer is forty two");
        let d = run_debate("what is the answer?", 0xabcd, &l, &r, &c).await;
        assert!(matches!(d.verdict, Verdict::Consensus { .. }));
        assert!(d.dissent.is_consensus());
        assert!(
            (2..=3).contains(&d.responses.len()),
            "early-exit may settle 2 or 3; got {}",
            d.responses.len()
        );
        assert_eq!(d.winning_text(), Some("the answer is forty two"));
    }

    #[tokio::test]
    async fn split_when_hemispheres_disagree_strongly() {
        let l = mk("claude", "alpha beta gamma delta");
        let r = mk("gemini", "epsilon zeta eta theta");
        let c = mk("local_qwen", "iota kappa lambda mu");
        let d = run_debate("polysemic prompt", 0, &l, &r, &c).await;
        assert!(matches!(d.verdict, Verdict::Split { .. }));
        assert!(d.dissent.is_strong_dissent());
        assert!(d.winning_text().is_none());
    }

    #[tokio::test]
    async fn quorum_failed_when_two_hemispheres_error() {
        let l = mk("claude", "the only voice");
        let r = mk_err("gemini", "timeout");
        let c = mk_err("local_qwen", "model not loaded");
        let d = run_debate("alone", 0, &l, &r, &c).await;
        match d.verdict {
            Verdict::QuorumFailed {
                responded,
                required,
            } => {
                assert_eq!(responded, 1);
                assert_eq!(required, QUORUM_THRESHOLD);
            }
            other => panic!("expected QuorumFailed, got {other:?}"),
        }
        // Error reasons captured for the operator audit.
        assert_eq!(d.responses[1].error.as_deref(), Some("timeout"));
        assert_eq!(d.responses[2].error.as_deref(), Some("model not loaded"));
    }

    #[tokio::test]
    async fn debate_records_per_role_provider_id() {
        // K-Perf-1 update: identical "x" responses trip early-exit
        // when the first 2 settle. Use distinct responses so the
        // verdict is Split (no early-exit) and all 3 provider ids
        // appear in the responses Vec.
        let l = mk("claude_cli", "alpha beta");
        let r = mk("gemini_api", "gamma delta");
        let c = mk("local_qwen", "epsilon zeta");
        let d = run_debate("p", 0, &l, &r, &c).await;
        let left = d.response_for(HemisphereRole::Left).unwrap();
        let right = d.response_for(HemisphereRole::Right).unwrap();
        let cere = d.response_for(HemisphereRole::Cerebellum).unwrap();
        assert_eq!(left.provider, "claude_cli");
        assert_eq!(right.provider, "gemini_api");
        assert_eq!(cere.provider, "local_qwen");
    }

    #[tokio::test]
    async fn one_error_two_consensus_still_produces_consensus() {
        let l = mk("claude", "the answer is yes");
        let r = mk("gemini", "the answer is yes");
        let c = mk_err("local_qwen", "model not loaded");
        let d = run_debate("p", 0, &l, &r, &c).await;
        assert!(matches!(d.verdict, Verdict::Consensus { .. }));
        // Quorum threshold = 2, responded = 2, dissent ≈ 0.
        assert!(d.dissent.is_consensus());
    }

    #[tokio::test]
    async fn split_summary_includes_each_role_with_text_head() {
        let l = mk("claude", "alpha beta gamma delta");
        let r = mk("gemini", "epsilon zeta eta theta");
        let c = mk("local_qwen", "iota kappa lambda mu");
        let d = run_debate("p", 0, &l, &r, &c).await;
        let summary = match &d.verdict {
            Verdict::Split { summary } => summary.clone(),
            other => panic!("expected Split, got {other:?}"),
        };
        assert!(summary.contains("left=alpha"));
        assert!(summary.contains("right=epsilon"));
        assert!(summary.contains("cerebellum=iota"));
    }

    #[test]
    fn pick_median_returns_middle_length_text() {
        // Lengths 3 / 5 / 7 → median is the 5-char text.
        let texts = ["abc", "abcde", "abcdefg"];
        let picked = pick_median(&texts);
        assert_eq!(picked, "abcde");
    }

    #[test]
    fn quorum_threshold_pinned_at_two_thirds() {
        // 2/3 majority — operators reading this default see the
        // baseline without source-diving.
        assert_eq!(QUORUM_THRESHOLD, 2);
    }

    // ── K-Perf-1 2026-05-17: early-exit verification ──────────────────

    /// Mock hemisphere that sleeps for a controlled duration before
    /// returning. Used to verify the early-exit path: when 2 fast
    /// hemispheres agree, the slow 3rd should be cancelled and
    /// `run_debate` should return well before the slow one would
    /// have completed.
    struct SlowMock {
        id: &'static str,
        response: &'static str,
        delay_ms: u64,
    }
    #[async_trait::async_trait]
    impl HemisphereProvider for SlowMock {
        fn provider_id(&self) -> String {
            self.id.to_string()
        }
        async fn ask(&self, _prompt: &str) -> Result<CompletionRecord, String> {
            tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
            Ok(CompletionRecord {
                text: self.response.to_string(),
                input_tokens: Some(10),
                output_tokens: Some(20),
            })
        }
    }

    #[tokio::test]
    async fn early_exit_returns_before_slow_hemisphere_completes() {
        // Left + Right are fast (10ms) and agree exactly → quorum +
        // consensus reached at ~10ms. Cerebellum is slow (3000ms).
        // run_debate should return well under 3000ms.
        let l = SlowMock {
            id: "claude",
            response: "answer is 42",
            delay_ms: 10,
        };
        let r = SlowMock {
            id: "gemini",
            response: "answer is 42",
            delay_ms: 10,
        };
        let c = SlowMock {
            id: "local_qwen",
            response: "different answer",
            delay_ms: 3000,
        };
        let started = std::time::Instant::now();
        let d = run_debate("p", 0, &l, &r, &c).await;
        let elapsed = started.elapsed();
        // Must complete well before the slow hemisphere — generous
        // 1500ms cap leaves headroom for CI scheduler jitter while
        // still catching the regression where we wait for slow.
        assert!(
            elapsed.as_millis() < 1500,
            "early-exit must beat slow hemisphere; took {elapsed:?}"
        );
        // Verdict is Consensus because L+R agreed before C settled.
        assert!(matches!(d.verdict, Verdict::Consensus { .. }));
        // Cerebellum response is absent (its future was cancelled).
        let cere = d.response_for(HemisphereRole::Cerebellum);
        assert!(
            cere.is_none(),
            "cancelled hemisphere must not appear in responses"
        );
    }

    #[tokio::test]
    async fn no_early_exit_when_quorum_pair_disagrees() {
        // L + R disagree → we must wait for C to break the tie.
        let l = SlowMock {
            id: "claude",
            response: "alpha beta gamma delta",
            delay_ms: 10,
        };
        let r = SlowMock {
            id: "gemini",
            response: "epsilon zeta eta theta",
            delay_ms: 10,
        };
        let c = SlowMock {
            id: "local_qwen",
            response: "iota kappa lambda mu",
            delay_ms: 50,
        };
        let d = run_debate("p", 0, &l, &r, &c).await;
        // All 3 should be present (no early-exit fired).
        assert_eq!(d.responses.len(), 3);
        assert!(d.response_for(HemisphereRole::Left).is_some());
        assert!(d.response_for(HemisphereRole::Right).is_some());
        assert!(d.response_for(HemisphereRole::Cerebellum).is_some());
    }

    #[tokio::test]
    async fn responses_stay_ordered_l_r_c_even_under_unordered_settle() {
        // Cerebellum settles first (fastest), then Right, then Left.
        // Verify the response Vec is still [Left, Right, Cerebellum]
        // so legacy callers using responses[0/1/2] keep working.
        let l = SlowMock {
            id: "claude",
            response: "L",
            delay_ms: 80,
        };
        let r = SlowMock {
            id: "gemini",
            response: "R",
            delay_ms: 40,
        };
        let c = SlowMock {
            id: "local_qwen",
            response: "C",
            delay_ms: 10,
        };
        // Distinct responses + short → likely Split (no early-exit).
        let d = run_debate("p", 0, &l, &r, &c).await;
        assert_eq!(d.responses.len(), 3);
        assert_eq!(d.responses[0].role, HemisphereRole::Left);
        assert_eq!(d.responses[1].role, HemisphereRole::Right);
        assert_eq!(d.responses[2].role, HemisphereRole::Cerebellum);
    }

    // ── E-2 Phase 1 (Session 13) depth-threading scaffold ─────────────

    /// Mock that records the `depth` it was called with. Used to pin
    /// the depth-threading contract from `run_debate_with_depth`
    /// through `run_one` to the trait method.
    struct DepthRecordingMock {
        id: &'static str,
        recorded: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    }
    #[async_trait::async_trait]
    impl HemisphereProvider for DepthRecordingMock {
        fn provider_id(&self) -> String {
            self.id.to_string()
        }
        async fn ask(&self, _prompt: &str) -> Result<CompletionRecord, String> {
            // Should not be called when ask_with_depth is overridden, but
            // present for trait completeness.
            Ok(CompletionRecord {
                text: "fallback".into(),
                input_tokens: None,
                output_tokens: None,
            })
        }
        async fn ask_with_depth(
            &self,
            _prompt: &str,
            depth: u8,
        ) -> Result<CompletionRecord, String> {
            self.recorded.lock().unwrap().push(depth);
            Ok(CompletionRecord {
                text: format!("depth={depth}"),
                input_tokens: None,
                output_tokens: None,
            })
        }
    }

    #[tokio::test]
    async fn run_debate_with_depth_threads_depth_to_every_hemisphere() {
        let recorded = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let l = DepthRecordingMock {
            id: "left",
            recorded: recorded.clone(),
        };
        let r = DepthRecordingMock {
            id: "right",
            recorded: recorded.clone(),
        };
        let c = DepthRecordingMock {
            id: "cere",
            recorded: recorded.clone(),
        };
        let _ = run_debate_with_depth("p", 0, 3, &l, &r, &c).await;
        let depths = recorded.lock().unwrap().clone();
        assert!(
            !depths.is_empty(),
            "at least one hemisphere should have recorded"
        );
        assert!(
            depths.iter().all(|&d| d == 3),
            "every hemisphere should receive depth=3 got {depths:?}",
        );
    }

    #[tokio::test]
    async fn run_debate_default_uses_flat_depth_one() {
        // Backwards-compat: the legacy `run_debate(…)` entry point
        // threads `HemisphereCouncilDepth::default()` (= 1) so existing
        // callers see exactly the v0.1 behaviour.
        let recorded = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let l = DepthRecordingMock {
            id: "left",
            recorded: recorded.clone(),
        };
        let r = DepthRecordingMock {
            id: "right",
            recorded: recorded.clone(),
        };
        let c = DepthRecordingMock {
            id: "cere",
            recorded: recorded.clone(),
        };
        let _ = run_debate("p", 0, &l, &r, &c).await;
        let depths = recorded.lock().unwrap().clone();
        assert!(
            depths.iter().all(|&d| d == 1),
            "default run_debate should thread depth=1, got {depths:?}",
        );
    }

    /// Mock that does NOT override `ask_with_depth` — exercises the
    /// trait's default fallback path (delegate to `ask`, ignore depth).
    struct AskOnlyMock {
        id: &'static str,
        ask_calls: std::sync::Arc<std::sync::atomic::AtomicU32>,
    }
    #[async_trait::async_trait]
    impl HemisphereProvider for AskOnlyMock {
        fn provider_id(&self) -> String {
            self.id.to_string()
        }
        async fn ask(&self, _prompt: &str) -> Result<CompletionRecord, String> {
            self.ask_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(CompletionRecord {
                text: "ok".into(),
                input_tokens: None,
                output_tokens: None,
            })
        }
    }

    #[tokio::test]
    async fn ask_with_depth_default_falls_back_to_ask() {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let l = AskOnlyMock {
            id: "left",
            ask_calls: calls.clone(),
        };
        let r = AskOnlyMock {
            id: "right",
            ask_calls: calls.clone(),
        };
        let c = AskOnlyMock {
            id: "cere",
            ask_calls: calls.clone(),
        };
        // Pass depth=4 even though mocks don't read it — the trait's
        // default impl must delegate to ask() so legacy hemispheres
        // keep working without re-implementing.
        let _ = run_debate_with_depth("p", 0, 4, &l, &r, &c).await;
        let n = calls.load(std::sync::atomic::Ordering::SeqCst);
        assert!(n >= 2, "at least 2 hemispheres must have settled; got {n}");
    }

    // ── R-03 2026-05-18: per-hemisphere refusal classification ────────

    #[tokio::test]
    async fn refusal_per_hemisphere_flags_only_refusing_hemisphere() {
        // L answers normally, R refuses (HardRefusal pattern), C agrees.
        let l = mk("claude", "the answer is forty two");
        let r = mk(
            "gemini",
            "I cannot help with that — it violates safety guidelines.",
        );
        let c = mk("local_qwen", "the answer is forty two");
        let d = run_debate("p", 0, &l, &r, &c).await;
        // Per-hemisphere refusal lookup — only Right is flagged.
        let left = d.response_for(HemisphereRole::Left);
        let right = d.response_for(HemisphereRole::Right);
        // Cerebellum may have been cancelled via early-exit when L+C agreed.
        if let Some(left) = left {
            assert!(left.refusal.is_none(), "left should not be flagged");
        }
        if let Some(right) = right {
            let refusal = right.refusal.as_ref().expect("right must be flagged");
            assert_eq!(
                refusal.class,
                crate::security::refusal_detect::RefusalClass::HardRefusal
            );
            assert!(refusal.class_confidence > 0);
            // Cause should classify to SafetyPolicy on this phrasing.
            assert_eq!(
                refusal.cause,
                crate::security::refusal_cause::RefusalCause::SafetyPolicy
            );
        }
    }

    #[tokio::test]
    async fn refusal_none_when_all_hemispheres_normal() {
        let l = mk("claude", "the answer is forty two");
        let r = mk("gemini", "the answer is forty two");
        let c = mk("local_qwen", "the answer is forty two");
        let d = run_debate("p", 0, &l, &r, &c).await;
        // No hemisphere should have a refusal flagged.
        for resp in &d.responses {
            assert!(
                resp.refusal.is_none(),
                "{:?} unexpectedly flagged as refusal",
                resp.role
            );
        }
        assert_eq!(d.refused_count(), 0);
        assert!(!d.is_partial_refusal());
    }

    #[tokio::test]
    async fn refusal_partial_signal_fires_when_one_refuses() {
        // Use the slow mock with distinct strings to PREVENT the early-exit
        // path from cancelling the refusing hemisphere — distinct strings
        // → dissent above consensus threshold → orchestrator waits for all
        // three.
        let l = SlowMock {
            id: "claude",
            response: "alpha beta gamma",
            delay_ms: 10,
        };
        let r = SlowMock {
            id: "gemini",
            response: "I cannot help with that request — content policy.",
            delay_ms: 10,
        };
        let c = SlowMock {
            id: "local_qwen",
            response: "epsilon zeta eta",
            delay_ms: 10,
        };
        let d = run_debate("p", 0, &l, &r, &c).await;
        assert_eq!(d.responses.len(), 3, "all three must settle");
        assert_eq!(d.refused_count(), 1);
        assert!(d.is_partial_refusal());
        let usable: Vec<HemisphereRole> = d.usable_responses().map(|r| r.role).collect();
        assert_eq!(usable.len(), 2);
        assert!(usable.contains(&HemisphereRole::Left));
        assert!(usable.contains(&HemisphereRole::Cerebellum));
    }

    #[tokio::test]
    async fn refusal_errored_hemisphere_has_no_refusal_field() {
        let l = mk_err("claude", "network timeout");
        let r = mk("gemini", "the answer is forty two");
        let c = mk("local_qwen", "the answer is forty two");
        let d = run_debate("p", 0, &l, &r, &c).await;
        let left = d.response_for(HemisphereRole::Left).expect("left present");
        assert!(left.text.is_none(), "errored left must have no text");
        assert!(left.error.is_some(), "errored left must have error reason");
        assert!(
            left.refusal.is_none(),
            "errored left must not carry refusal"
        );
    }

    // ── Pick #19 (Session 14 F6) — BudgetToken propagation ────────────

    #[tokio::test]
    async fn budget_cap_below_council_size_skips_late_hemispheres() {
        // Cap=2 means at most two of the three hemispheres charge
        // successfully; the third hits BudgetExhausted and is
        // synthesised as a skipped response (text=None, error=
        // "budget-exhausted"). Counts charged + skipped must sum to
        // exactly 3.
        let l = mk("claude", "alpha");
        let r = mk("gemini", "beta");
        let c = mk("local_qwen", "gamma");
        let budget = BudgetToken::new(2);
        let d = run_debate_with_depth_budget("p", 0, 1, budget.clone(), &l, &r, &c).await;
        assert_eq!(d.responses.len(), 3, "all three slots present");
        let skipped: Vec<_> = d
            .responses
            .iter()
            .filter(|r| r.error.as_deref() == Some(BUDGET_EXHAUSTED_ERROR))
            .collect();
        assert_eq!(
            skipped.len(),
            1,
            "exactly one hemisphere should be budget-skipped with cap=2; got: {:?}",
            d.responses
                .iter()
                .map(|r| (r.role, r.text.as_deref(), r.error.as_deref()))
                .collect::<Vec<_>>(),
        );
        // Cap was honoured — at most 2 charges landed.
        assert!(
            budget.used() <= 2,
            "budget.used must not exceed cap; got {}",
            budget.used()
        );
    }

    #[tokio::test]
    async fn budget_cap_zero_skips_every_hemisphere() {
        let l = mk("claude", "x");
        let r = mk("gemini", "y");
        let c = mk("local_qwen", "z");
        let budget = BudgetToken::new(0);
        let d = run_debate_with_depth_budget("p", 0, 1, budget, &l, &r, &c).await;
        assert_eq!(d.responses.len(), 3);
        for r in &d.responses {
            assert!(r.text.is_none(), "no LLM text should reach the verdict");
            assert_eq!(
                r.error.as_deref(),
                Some(BUDGET_EXHAUSTED_ERROR),
                "every hemisphere must report budget-exhausted; got: {r:?}"
            );
        }
    }

    #[tokio::test]
    async fn budget_default_cap_allows_full_council() {
        // Default cap is 15 — far above the 3 calls a single debate
        // makes. No hemisphere should be budget-skipped.
        let l = mk("claude", "p");
        let r = mk("gemini", "q");
        let c = mk("local_qwen", "r");
        let budget = BudgetToken::new(crate::config::inference::DEFAULT_MAX_CALLS_PER_USER_MESSAGE);
        let d = run_debate_with_depth_budget("p", 0, 1, budget.clone(), &l, &r, &c).await;
        let any_skipped = d
            .responses
            .iter()
            .any(|r| r.error.as_deref() == Some(BUDGET_EXHAUSTED_ERROR));
        assert!(!any_skipped, "default cap must allow all three hemispheres");
        // At most 3 charges should have landed.
        assert!(budget.used() <= 3, "used={} should be ≤ 3", budget.used());
    }

    #[tokio::test]
    async fn budget_shared_across_two_back_to_back_debates() {
        // Same token threaded into two sequential debates — the
        // second debate inherits whatever the first one left. Cap=4
        // means debate 1 charges 3, debate 2 charges 1 then 2 of
        // its hemispheres see budget-exhausted.
        let l = mk("claude", "a");
        let r = mk("gemini", "b");
        let c = mk("local_qwen", "c");
        let budget = BudgetToken::new(4);
        let d1 = run_debate_with_depth_budget("p1", 0, 1, budget.clone(), &l, &r, &c).await;
        let skipped1 = d1
            .responses
            .iter()
            .filter(|r| r.error.as_deref() == Some(BUDGET_EXHAUSTED_ERROR))
            .count();
        assert_eq!(skipped1, 0, "first debate must complete fully");
        let d2 = run_debate_with_depth_budget("p2", 0, 1, budget.clone(), &l, &r, &c).await;
        let skipped2 = d2
            .responses
            .iter()
            .filter(|r| r.error.as_deref() == Some(BUDGET_EXHAUSTED_ERROR))
            .count();
        assert_eq!(skipped2, 2, "second debate must show 2 budget-skipped");
        // Cap respected end-to-end.
        assert!(budget.used() <= 4);
    }

    /// Mock that recurses internally — invokes another
    /// `run_debate_with_depth_budget` from within its
    /// `ask_with_depth_budget`. Pins the contract that adapter-side
    /// recursion shares the SAME budget token, so the cap spans the
    /// outer + inner council together (not 2× cap).
    struct RecursingMock {
        id: &'static str,
    }
    #[async_trait::async_trait]
    impl HemisphereProvider for RecursingMock {
        fn provider_id(&self) -> String {
            self.id.to_string()
        }
        async fn ask(&self, _prompt: &str) -> Result<CompletionRecord, String> {
            Ok(CompletionRecord {
                text: "flat-fallback".into(),
                input_tokens: None,
                output_tokens: None,
            })
        }
        async fn ask_with_depth_budget(
            &self,
            prompt: &str,
            depth: u8,
            budget: BudgetToken,
        ) -> Result<CompletionRecord, String> {
            // Recurse: each outer hemisphere fires its own inner
            // 3-hemisphere debate against fresh leaf mocks, threading
            // the SAME budget so the cap is shared.
            let inner_l = mk("inner-l", "x");
            let inner_r = mk("inner-r", "y");
            let inner_c = mk("inner-c", "z");
            let _ = run_debate_with_depth_budget(
                prompt,
                0,
                depth.saturating_sub(1),
                budget,
                &inner_l,
                &inner_r,
                &inner_c,
            )
            .await;
            Ok(CompletionRecord {
                text: "outer-after-inner".into(),
                input_tokens: None,
                output_tokens: None,
            })
        }
    }

    #[tokio::test]
    async fn budget_propagates_through_adapter_side_recursion() {
        // Cap=5: outer hemispheres charge 3 (1 each), and from EACH
        // outer the adapter recurses into an inner 3-hemisphere
        // debate that charges against the same budget. Only 2 of
        // the 9 inner charges fit before exhaustion. Final used
        // must equal cap exactly — no over-grant, no under-count.
        let l = RecursingMock { id: "outer-l" };
        let r = RecursingMock { id: "outer-r" };
        let c = RecursingMock { id: "outer-c" };
        let budget = BudgetToken::new(5);
        let _ = run_debate_with_depth_budget("p", 0, 2, budget.clone(), &l, &r, &c).await;
        assert_eq!(
            budget.used(),
            5,
            "shared budget must converge to cap exactly across outer+inner"
        );
    }
}
