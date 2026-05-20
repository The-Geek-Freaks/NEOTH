//! CH-08 Corpus Callosum — structured Split-verdict resolution.
//!
//! When `council::run_debate` returns [`Verdict::Split`], the Left and
//! Right hemispheres produced incompatible answers and the operator
//! either picks one manually or the system escalates. This module is
//! the **automated** escalation path: ask the Cerebellum hemisphere
//! to synthesise the two positions into one coherent reply.
//!
//! Per Konsens-decision #2b (A5 2026-05-16): **standalone module with
//! recursion-cap = 1**. The cap matters because:
//!   - A `run_debate` that ends `Split` cost 3 hemisphere calls.
//!   - Calling `callosum::resolve` adds exactly 1 Cerebellum call.
//!   - Total: 4 calls — hard ceiling, no loop risk.
//!   - The alternative — recursive `run_debate` — could chain
//!     debates without termination guarantee and easily reach 6× /
//!     9× single-call cost.
//!
//! Design contract:
//!   - INPUT: the two disagreeing hemisphere texts (Left, Right) +
//!     a Cerebellum provider.
//!   - PROMPT: a structured "Left says A, Right says B — synthesize"
//!     framing. The Cerebellum gets a well-defined task rather than
//!     "resolve the disagreement" ambiguity.
//!   - OUTPUT: `CorticalVerdict::{Synthesis(String),
//!     IrreconcilableConflict}`. If Cerebellum errors or refuses,
//!     surface IrreconcilableConflict — do not retry, do not chain.
//!
//! Pure-function deterministic at the prompt-building level; the
//! actual hemisphere call goes via the `HemisphereProvider` trait
//! that `orchestrator.rs` already defines.

use super::orchestrator::{CompletionRecord, HemisphereProvider};

/// What the Callosum decided after seeing both Split responses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CorticalVerdict {
    /// Cerebellum produced a synthesis text bridging Left and Right.
    /// The caller (chat dispatch) uses this as the final reply.
    Synthesis(String),
    /// Cerebellum errored, refused, or produced empty text. The
    /// operator must pick manually — we do NOT retry.
    IrreconcilableConflict { reason: String },
}

impl CorticalVerdict {
    pub fn is_resolved(&self) -> bool {
        matches!(self, CorticalVerdict::Synthesis(_))
    }
    pub fn text(&self) -> Option<&str> {
        match self {
            CorticalVerdict::Synthesis(s) => Some(s.as_str()),
            CorticalVerdict::IrreconcilableConflict { .. } => None,
        }
    }
}

/// Resolve a `Verdict::Split` by asking the Cerebellum hemisphere to
/// synthesise the two disagreeing positions.
///
/// `original_prompt` is the user's original question — needed so the
/// Cerebellum has the framing context, not just the two positions.
/// Recursion-cap is **structural**: this function makes exactly ONE
/// Cerebellum call. There is no path that loops back into `run_debate`.
pub async fn resolve(
    original_prompt: &str,
    left_text: &str,
    right_text: &str,
    cerebellum: &dyn HemisphereProvider,
) -> CorticalVerdict {
    resolve_with_profile(original_prompt, left_text, right_text, None, cerebellum).await
}

/// CH-11: Same as [`resolve`] but with an optional operator-profile
/// context block injected into the synthesis prompt. When `Some(block)`
/// is supplied, the Cerebellum sees a "OPERATOR PROFILE (high-confidence
/// claims, weight these when synthesising)" section before the LEFT /
/// RIGHT positions — biasing the synthesis toward operator-known
/// preferences. The chat dispatch fills this from
/// `profile::lookup::top_claims_for_chat` + `render_for_synthesis_prompt`.
///
/// Empty / whitespace-only blocks are treated as `None` so callers
/// don't need to pre-check.
pub async fn resolve_with_profile(
    original_prompt: &str,
    left_text: &str,
    right_text: &str,
    profile_block: Option<&str>,
    cerebellum: &dyn HemisphereProvider,
) -> CorticalVerdict {
    let synthesis_prompt =
        build_synthesis_prompt_with_profile(original_prompt, left_text, right_text, profile_block);
    match cerebellum.ask(&synthesis_prompt).await {
        Ok(CompletionRecord { text, .. }) if !text.trim().is_empty() => {
            CorticalVerdict::Synthesis(text)
        }
        Ok(_) => CorticalVerdict::IrreconcilableConflict {
            reason: "cerebellum returned empty synthesis text".to_string(),
        },
        Err(e) => CorticalVerdict::IrreconcilableConflict {
            reason: format!("cerebellum call failed: {e}"),
        },
    }
}

/// Build the structured synthesis prompt. Pinned format so the
/// Cerebellum's expectation stays stable across refactors. Operators
/// reading WAL audit can correlate the synthesis call back to this
/// exact framing.
fn build_synthesis_prompt(original_prompt: &str, left_text: &str, right_text: &str) -> String {
    build_synthesis_prompt_with_profile(original_prompt, left_text, right_text, None)
}

/// CH-11: synthesis prompt builder with optional operator-profile
/// context. Pinned format: when a non-empty `profile_block` is supplied,
/// the OPERATOR PROFILE section appears between the council framing and
/// QUESTION. Operators reading WAL audit can correlate the synthesis
/// call back to this exact framing including the profile injection.
fn build_synthesis_prompt_with_profile(
    original_prompt: &str,
    left_text: &str,
    right_text: &str,
    profile_block: Option<&str>,
) -> String {
    let profile_section = match profile_block {
        Some(block) if !block.trim().is_empty() => format!(
            "OPERATOR PROFILE (high-confidence claims, weight these when synthesising):\n\
             {block}\n"
        ),
        _ => String::new(),
    };
    format!(
        "Two hemispheres of a debate council reached different conclusions on the \
         following question:\n\n\
         {profile_section}\
         QUESTION: {original_prompt}\n\n\
         LEFT (analytic) said:\n{left_text}\n\n\
         RIGHT (creative) said:\n{right_text}\n\n\
         Synthesise a single coherent answer. If the two positions are \
         compatible, integrate them. If they are contradictory, state which \
         is more likely correct and why. Avoid hedging — produce a single \
         actionable response."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Mock that captures the prompt + returns scripted answers.
    struct MockCerebellum {
        responses: Vec<String>,
        call_count: Arc<AtomicUsize>,
        last_prompt: std::sync::Mutex<Option<String>>,
    }

    impl MockCerebellum {
        fn returning(text: &str) -> Self {
            Self {
                responses: vec![text.to_string()],
                call_count: Arc::new(AtomicUsize::new(0)),
                last_prompt: std::sync::Mutex::new(None),
            }
        }
        fn erroring() -> ErrorMock {
            ErrorMock {
                call_count: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    #[async_trait::async_trait]
    impl HemisphereProvider for MockCerebellum {
        fn provider_id(&self) -> String {
            "mock_cerebellum".to_string()
        }
        async fn ask(&self, prompt: &str) -> Result<CompletionRecord, String> {
            *self.last_prompt.lock().unwrap() = Some(prompt.to_string());
            let idx = self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(CompletionRecord {
                text: self.responses.get(idx).cloned().unwrap_or_default(),
                input_tokens: Some(10),
                output_tokens: Some(20),
            })
        }
    }

    struct ErrorMock {
        call_count: Arc<AtomicUsize>,
    }
    #[async_trait::async_trait]
    impl HemisphereProvider for ErrorMock {
        fn provider_id(&self) -> String {
            "error_mock".to_string()
        }
        async fn ask(&self, _prompt: &str) -> Result<CompletionRecord, String> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Err("upstream unreachable".to_string())
        }
    }

    #[tokio::test]
    async fn resolve_returns_synthesis_when_cerebellum_responds() {
        let cere = MockCerebellum::returning(
            "Both views capture part of the truth: the answer is a hybrid approach.",
        );
        let verdict = resolve(
            "Should we use Rust or Go for this CLI?",
            "Rust — type safety + perf",
            "Go — simpler tooling + concurrency",
            &cere,
        )
        .await;
        match verdict {
            CorticalVerdict::Synthesis(text) => {
                assert!(text.contains("hybrid approach"));
            }
            other => panic!("expected Synthesis, got {other:?}"),
        }
        // Exactly ONE cerebellum call — the recursion cap.
        assert_eq!(cere.call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn resolve_returns_irreconcilable_when_cerebellum_errors() {
        let cere = MockCerebellum::erroring();
        let verdict = resolve("What is X?", "A", "B", &cere).await;
        match verdict {
            CorticalVerdict::IrreconcilableConflict { reason } => {
                assert!(reason.contains("cerebellum call failed"));
                assert!(reason.contains("upstream unreachable"));
            }
            other => panic!("expected IrreconcilableConflict, got {other:?}"),
        }
        // Even on error, ONE call only — no retry.
        assert_eq!(cere.call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn resolve_returns_irreconcilable_when_cerebellum_returns_empty() {
        let cere = MockCerebellum::returning("   "); // whitespace only
        let verdict = resolve("What is X?", "A", "B", &cere).await;
        match verdict {
            CorticalVerdict::IrreconcilableConflict { reason } => {
                assert!(reason.contains("empty synthesis text"));
            }
            other => panic!("expected IrreconcilableConflict, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn synthesis_prompt_includes_both_positions_and_original_question() {
        let cere = MockCerebellum::returning("synthesized");
        let _ = resolve(
            "Original question text",
            "Left position text",
            "Right position text",
            &cere,
        )
        .await;
        let captured = cere.last_prompt.lock().unwrap().clone().unwrap();
        assert!(captured.contains("Original question text"));
        assert!(captured.contains("Left position text"));
        assert!(captured.contains("Right position text"));
        assert!(captured.contains("LEFT (analytic)"));
        assert!(captured.contains("RIGHT (creative)"));
        // The framing must instruct synthesis, not pick-one.
        assert!(captured.contains("Synthesise"));
    }

    #[test]
    fn build_synthesis_prompt_with_profile_injects_block_when_supplied() {
        let prompt = build_synthesis_prompt_with_profile(
            "Q?",
            "L",
            "R",
            Some("- role: developer (conf 0.92)\n- lang: de (conf 0.88)\n"),
        );
        assert!(prompt.contains("OPERATOR PROFILE"));
        assert!(prompt.contains("role: developer (conf 0.92)"));
        assert!(prompt.contains("lang: de (conf 0.88)"));
        // Section sits BEFORE the QUESTION marker.
        let profile_at = prompt.find("OPERATOR PROFILE").unwrap();
        let question_at = prompt.find("QUESTION: Q?").unwrap();
        assert!(profile_at < question_at);
    }

    #[test]
    fn build_synthesis_prompt_with_profile_none_matches_no_profile_form() {
        let with_none = build_synthesis_prompt_with_profile("Q", "L", "R", None);
        let without = build_synthesis_prompt("Q", "L", "R");
        assert_eq!(with_none, without);
        assert!(!with_none.contains("OPERATOR PROFILE"));
    }

    #[test]
    fn build_synthesis_prompt_with_profile_empty_or_whitespace_skips_section() {
        let with_empty = build_synthesis_prompt_with_profile("Q", "L", "R", Some(""));
        let with_ws = build_synthesis_prompt_with_profile("Q", "L", "R", Some("   \n  "));
        let without = build_synthesis_prompt("Q", "L", "R");
        assert_eq!(with_empty, without);
        assert_eq!(with_ws, without);
    }

    #[tokio::test]
    async fn resolve_with_profile_threads_block_into_cerebellum_prompt() {
        let cere = MockCerebellum::returning("integrated");
        let _ = resolve_with_profile(
            "Q",
            "left position",
            "right position",
            Some("- role: developer (conf 0.92)\n"),
            &cere,
        )
        .await;
        let captured = cere.last_prompt.lock().unwrap().clone().unwrap();
        assert!(captured.contains("OPERATOR PROFILE"));
        assert!(captured.contains("role: developer (conf 0.92)"));
        assert!(captured.contains("QUESTION: Q"));
    }

    #[tokio::test]
    async fn resolve_falls_through_to_resolve_with_profile_none() {
        // The legacy `resolve` (no profile) must not inject any
        // OPERATOR PROFILE section.
        let cere = MockCerebellum::returning("x");
        let _ = resolve("Q", "L", "R", &cere).await;
        let captured = cere.last_prompt.lock().unwrap().clone().unwrap();
        assert!(!captured.contains("OPERATOR PROFILE"));
    }

    #[test]
    fn build_synthesis_prompt_format_is_stable() {
        // Pin the prompt shape so a refactor doesn't silently drift
        // it (would invalidate cached audit traces).
        let prompt = build_synthesis_prompt("Q", "L", "R");
        assert!(prompt.starts_with("Two hemispheres of a debate council"));
        assert!(prompt.contains("QUESTION: Q"));
        assert!(prompt.contains("LEFT (analytic) said:\nL"));
        assert!(prompt.contains("RIGHT (creative) said:\nR"));
        assert!(prompt.contains("Avoid hedging"));
    }

    #[test]
    fn cortical_verdict_is_resolved_distinguishes_synthesis_from_conflict() {
        assert!(CorticalVerdict::Synthesis("x".into()).is_resolved());
        assert!(
            !CorticalVerdict::IrreconcilableConflict {
                reason: "fail".into()
            }
            .is_resolved()
        );
    }

    #[test]
    fn cortical_verdict_text_returns_some_only_on_synthesis() {
        assert_eq!(
            CorticalVerdict::Synthesis("answer".into()).text(),
            Some("answer")
        );
        assert!(
            CorticalVerdict::IrreconcilableConflict { reason: "x".into() }
                .text()
                .is_none()
        );
    }

    // ── CH-08 integration test ────────────────────────────────────────────
    // Full pipeline: 3 distinct hemispheres → `run_debate` returns
    // `Verdict::Split` → `callosum::resolve` against a separately
    // configured Cerebellum → `CorticalVerdict::Synthesis` lands. This
    // is the end-to-end happy path the chat dispatch relies on.

    /// Mock that returns a different scripted text on each call. The
    /// first call goes to `run_debate` (as the Cerebellum hemisphere);
    /// the second goes to `callosum::resolve` (the synthesis call).
    /// Splitting them lets us verify the recursion-cap = 1 contract
    /// from outside the orchestrator.
    struct ScriptedCallosumProvider {
        call_count: std::sync::Mutex<usize>,
        responses: Vec<String>,
    }

    impl ScriptedCallosumProvider {
        fn new(responses: Vec<&str>) -> Self {
            Self {
                call_count: std::sync::Mutex::new(0),
                responses: responses.into_iter().map(String::from).collect(),
            }
        }
        fn calls(&self) -> usize {
            *self.call_count.lock().unwrap()
        }
    }

    #[async_trait::async_trait]
    impl HemisphereProvider for ScriptedCallosumProvider {
        fn provider_id(&self) -> String {
            "scripted_cerebellum".to_string()
        }
        async fn ask(&self, _prompt: &str) -> Result<CompletionRecord, String> {
            let mut n = self.call_count.lock().unwrap();
            let idx = *n;
            *n += 1;
            let text = self
                .responses
                .get(idx)
                .cloned()
                .unwrap_or_else(|| "(out of scripted responses)".to_string());
            Ok(CompletionRecord {
                text,
                input_tokens: Some(10),
                output_tokens: Some(20),
            })
        }
    }

    /// Minimal stand-in for the orchestrator's `mk` helper so we don't
    /// reach across module boundaries. Returns a fresh anonymous mock
    /// per call so the orchestrator tests can drop their static state.
    struct FixedHemisphere {
        id: &'static str,
        text: &'static str,
    }
    #[async_trait::async_trait]
    impl HemisphereProvider for FixedHemisphere {
        fn provider_id(&self) -> String {
            self.id.to_string()
        }
        async fn ask(&self, _prompt: &str) -> Result<CompletionRecord, String> {
            Ok(CompletionRecord {
                text: self.text.to_string(),
                input_tokens: Some(10),
                output_tokens: Some(20),
            })
        }
    }

    #[tokio::test]
    async fn full_pipeline_split_then_callosum_produces_synthesis() {
        // 3 distinct hemispheres → dissent score crosses 0.6 → Split.
        let left = FixedHemisphere {
            id: "claude",
            text: "alpha beta gamma delta epsilon",
        };
        let right = FixedHemisphere {
            id: "gemini",
            text: "zeta eta theta iota kappa",
        };
        // The Cerebellum in run_debate returns a third disagreeing
        // text; the SAME provider then gets called again by callosum
        // to synthesise (recursion-cap = 1).
        let cerebellum = ScriptedCallosumProvider::new(vec![
            "lambda mu nu xi omicron", // run_debate Cerebellum response
            "Both perspectives carry weight; the integrated answer is X.",
        ]);

        let debate = crate::council::run_debate(
            "Which framework should we use?",
            0xdeadbeef,
            &left,
            &right,
            &cerebellum,
        )
        .await;

        // Verdict must be Split (3 disagreeing texts → high dissent).
        match &debate.verdict {
            crate::council::Verdict::Split { .. } => {}
            other => panic!("expected Split, got {other:?}"),
        }
        assert_eq!(cerebellum.calls(), 1, "run_debate makes 1 cerebellum call");

        // Now run callosum::resolve on the same cerebellum. Role-keyed
        // access (`response_for`) is safer than raw indexing — a future
        // test that exercises the K-Perf-1 early-exit path could see
        // `responses` with fewer than 3 entries.
        let left_text = debate
            .response_for(crate::config::inference::HemisphereRole::Left)
            .and_then(|r| r.text.as_deref())
            .expect("left hemisphere must be present in this fixture")
            .to_string();
        let right_text = debate
            .response_for(crate::config::inference::HemisphereRole::Right)
            .and_then(|r| r.text.as_deref())
            .expect("right hemisphere must be present in this fixture")
            .to_string();
        let verdict = resolve(
            "Which framework should we use?",
            &left_text,
            &right_text,
            &cerebellum,
        )
        .await;

        match verdict {
            CorticalVerdict::Synthesis(s) => {
                assert!(
                    s.contains("integrated answer"),
                    "synthesis text should land verbatim: {s}"
                );
            }
            other => panic!("expected Synthesis, got {other:?}"),
        }
        // run_debate (1) + callosum::resolve (1) = 2 total cerebellum
        // calls. Recursion-cap = 1 means callosum NEVER chains further.
        assert_eq!(
            cerebellum.calls(),
            2,
            "callosum must add exactly ONE call on top of run_debate's one"
        );
    }

    #[tokio::test]
    async fn full_pipeline_split_then_callosum_failure_falls_back() {
        let left = FixedHemisphere {
            id: "claude",
            text: "alpha beta gamma delta epsilon",
        };
        let right = FixedHemisphere {
            id: "gemini",
            text: "zeta eta theta iota kappa",
        };

        // Cerebellum that errors on the SECOND call (callosum's call).
        struct FailingCallosum {
            calls: std::sync::Mutex<usize>,
        }
        #[async_trait::async_trait]
        impl HemisphereProvider for FailingCallosum {
            fn provider_id(&self) -> String {
                "failing".into()
            }
            async fn ask(&self, _: &str) -> Result<CompletionRecord, String> {
                let mut n = self.calls.lock().unwrap();
                let idx = *n;
                *n += 1;
                if idx == 0 {
                    Ok(CompletionRecord {
                        text: "first call ok".into(),
                        input_tokens: Some(1),
                        output_tokens: Some(1),
                    })
                } else {
                    Err("synthesis call upstream timeout".into())
                }
            }
        }
        let cere = FailingCallosum {
            calls: std::sync::Mutex::new(0),
        };

        let debate = crate::council::run_debate("Q", 0xfeed, &left, &right, &cere).await;
        match &debate.verdict {
            crate::council::Verdict::Split { .. } => {}
            other => panic!("expected Split, got {other:?}"),
        }

        // Role-keyed access — see comment in the prior test for why
        // raw indexing is dispreferred even when the fixture guarantees
        // 3 entries.
        let left_text = debate
            .response_for(crate::config::inference::HemisphereRole::Left)
            .and_then(|r| r.text.as_deref())
            .expect("left present in FixedHemisphere fixture");
        let right_text = debate
            .response_for(crate::config::inference::HemisphereRole::Right)
            .and_then(|r| r.text.as_deref())
            .expect("right present in FixedHemisphere fixture");
        let verdict = resolve("Q", left_text, right_text, &cere).await;

        match verdict {
            CorticalVerdict::IrreconcilableConflict { reason } => {
                assert!(
                    reason.contains("upstream timeout"),
                    "reason should surface the cerebellum error: {reason}"
                );
            }
            other => panic!("expected IrreconcilableConflict, got {other:?}"),
        }
    }
}
