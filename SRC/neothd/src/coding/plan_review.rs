//! GRILL-02 — adversarial plan-review loop.
//!
//! Runs an adversarial review cycle over a plan text using any
//! provider that implements the [`DecomposerLlm`] trait (same
//! abstraction re-used by the decomposer, second-opinion classifier,
//! and cerebellum provider — no second binding needed).
//!
//! ## Loop contract
//!
//! 1. Build a critique prompt from the current plan text.
//! 2. Ask the reviewer (via `llm.complete()`) to analyse the plan for
//!    security holes, race conditions, missing error handling, and
//!    scope creep.
//! 3. Parse the reviewer's reply for `APPROVED` or `REVISE`.
//! 4. On `REVISE`: record the critique + feed it back as an addendum to
//!    the plan text for the next round.
//! 5. On `APPROVED` or after [`MAX_REVIEW_ROUNDS`]: exit.
//! 6. At round ceiling without `APPROVED`: return
//!    [`ReviewOutcome::Deadlock`].
//!
//! Every round is appended to a [`PlanReviewLog`] for operator
//! transparency and audit trail.
//!
//! ## Design notes
//!
//! - **Provider-agnostic**: takes `&dyn DecomposerLlm` so any
//!   configured hemisphere provider can drive the review without
//!   extra bindings.
//! - **Testable**: the trait is a simple `async fn complete` closure,
//!   so tests pass a mock via a thin wrapper.
//! - **No WAL, no DB, no config**: pure I/O through the trait.

use anyhow::Result;

use crate::coding::decomposer::DecomposerLlm;
use crate::coding::plan_writer::{PlanReviewLog, PlanReviewRound};

/// Maximum review rounds before declaring a deadlock. Mirrors the
/// `MAX_BRAINSTORM_ROUNDS` philosophy: bound the loop so a disagreeing
/// reviewer cannot block the operator indefinitely.
pub const MAX_REVIEW_ROUNDS: u32 = 5;

/// Outcome of a completed [`review_plan`] run.
#[derive(Debug)]
pub enum ReviewOutcome {
    /// Reviewer returned `APPROVED` within the round budget. The log
    /// records all rounds including the approving one.
    Approved { log: PlanReviewLog },
    /// [`MAX_REVIEW_ROUNDS`] exhausted without `APPROVED`. The log
    /// records every round attempted; `unresolved` lists the
    /// reviewer's outstanding critiques.
    Deadlock {
        log: PlanReviewLog,
        unresolved: Vec<String>,
    },
}

impl ReviewOutcome {
    /// True when the reviewer approved the plan.
    pub fn is_approved(&self) -> bool {
        matches!(self, ReviewOutcome::Approved { .. })
    }

    /// True when the loop hit the round ceiling.
    pub fn is_deadlock(&self) -> bool {
        matches!(self, ReviewOutcome::Deadlock { .. })
    }

    /// Borrow the review log regardless of outcome.
    pub fn log(&self) -> &PlanReviewLog {
        match self {
            ReviewOutcome::Approved { log } | ReviewOutcome::Deadlock { log, .. } => log,
        }
    }
}

/// Build the reviewer prompt for one round.
///
/// The reviewer is instructed to output either:
/// - `APPROVED` — plan is ready (followed by an optional brief comment)
/// - `REVISE: <reason>` — one or more specific issues found
///
/// The `critique_so_far` string is empty on round 1 and non-empty on
/// subsequent rounds (it contains the cumulative REVISE reasons so
/// the reviewer can track what was already flagged).
fn build_review_prompt(plan_text: &str, critique_so_far: &str) -> String {
    let prior = if critique_so_far.is_empty() {
        String::new()
    } else {
        format!(
            "\n\n<prior_critiques>\n{critique_so_far}\n</prior_critiques>\n\
             The author claims to have addressed these. Verify and re-evaluate.\n"
        )
    };

    format!(
        "You are an adversarial plan reviewer. Analyse the plan below for:\n\
         1. Security holes or missing authentication / authorisation gates\n\
         2. Race conditions or missing concurrency guards\n\
         3. Missing error handling or silent failure paths\n\
         4. Scope creep or unscoped dependencies\n\
         \n\
         Reply with EXACTLY one of:\n\
         - `APPROVED` — followed by an optional one-line note (plan is production-ready)\n\
         - `REVISE: <specific issues, one per line>` — when any of the above apply\n\
         \n\
         Do NOT output anything else before the verdict token.\n\
         {prior}\n\
         <plan>\n\
         {plan_text}\n\
         </plan>"
    )
}

/// Parse the reviewer's reply into a verdict string (`APPROVED` or
/// `REVISE`) and the critique body.
///
/// Looks for the first occurrence of `APPROVED` or `REVISE` (case-
/// insensitive). Defaults to `REVISE` on parse failure — safer than
/// approving an unreadable reply.
fn parse_verdict(reply: &str) -> (&'static str, String) {
    // Bound the scan — 4 KB is generous for a structured verdict reply.
    // char-safe: a raw `&reply[..4096]` byte slice panics on a multibyte
    // codepoint straddling byte 4096.
    let scan = match reply.char_indices().nth(4096) {
        Some((idx, _)) => &reply[..idx],
        None => reply,
    };
    let lower = scan.to_lowercase();
    // REVISE wins whenever it appears: a genuine APPROVED reply never
    // contains "revise", but a "this is NOT approved, REVISE: …" reply
    // does — so a plain `contains("approved")` would mis-read a *negated*
    // approval as APPROVED. The prompt requires the verdict token FIRST
    // with nothing before it, so a real approval LEADS with "approved".
    let revises = lower.contains("revise");
    let leads_approved = lower.trim_start().starts_with("approved");
    if leads_approved && !revises {
        ("APPROVED", reply.trim().to_string())
    } else if revises {
        // Extract everything after "REVISE:" if present (ASCII token →
        // the byte offset from `lower` is valid in `scan`).
        let critique = if let Some(pos) = lower.find("revise:") {
            scan[pos + "revise:".len()..].trim().to_string()
        } else if let Some(pos) = lower.find("revise") {
            scan[pos + "revise".len()..].trim().to_string()
        } else {
            scan.trim().to_string()
        };
        ("REVISE", critique)
    } else {
        // No clear leading verdict — default REVISE: never approve an
        // unreadable / non-leading reply (fail-safe toward revising).
        ("REVISE", reply.trim().to_string())
    }
}

/// GRILL-02 — adversarial plan-review loop.
///
/// Runs up to [`MAX_REVIEW_ROUNDS`] review rounds. On each round the
/// reviewer (via `llm`) critiques the plan; the critique is appended to
/// a [`PlanReviewLog`] and fed back into the next round's prompt.
///
/// Returns [`ReviewOutcome::Approved`] as soon as the reviewer says
/// `APPROVED`, or [`ReviewOutcome::Deadlock`] after the round ceiling
/// with the accumulated unresolved critiques.
///
/// # Arguments
///
/// * `llm`       — any provider implementing [`DecomposerLlm`]
/// * `plan_text` — the plan text to review (markdown, free-form, etc.)
pub async fn review_plan(
    llm: &dyn DecomposerLlm,
    plan_text: &str,
) -> Result<ReviewOutcome> {
    let mut log = PlanReviewLog::new();
    let mut critique_so_far = String::new();
    let mut unresolved: Vec<String> = Vec::new();

    for round in 1..=MAX_REVIEW_ROUNDS {
        let prompt = build_review_prompt(plan_text, &critique_so_far);
        let reply = llm
            .complete(&prompt)
            .await
            .map_err(|e| anyhow::anyhow!("plan reviewer LLM call failed (round {round}): {e}"))?;

        let (verdict, critique) = parse_verdict(&reply);
        let response = if verdict == "APPROVED" {
            "Plan accepted without requested changes.".to_string()
        } else {
            format!("Round {round} critique acknowledged; plan will be revised.")
        };

        log.append(PlanReviewRound {
            round,
            critique: critique.clone(),
            response: response.clone(),
            verdict: verdict.to_string(),
        });

        if verdict == "APPROVED" {
            return Ok(ReviewOutcome::Approved { log });
        }

        // Accumulate critique for the next round.
        if !critique.is_empty() {
            if !critique_so_far.is_empty() {
                critique_so_far.push('\n');
            }
            critique_so_far.push_str(&format!("Round {round}: {critique}"));
            unresolved.push(critique);
        }
    }

    Ok(ReviewOutcome::Deadlock { log, unresolved })
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};

    /// Mock provider that returns pre-canned replies in order.
    struct MockLlm {
        replies: Arc<Mutex<Vec<String>>>,
        call_count: Arc<Mutex<u32>>,
    }

    impl MockLlm {
        fn new(replies: Vec<&str>) -> Self {
            Self {
                replies: Arc::new(Mutex::new(
                    replies.into_iter().map(str::to_string).collect(),
                )),
                call_count: Arc::new(Mutex::new(0)),
            }
        }

        fn calls(&self) -> u32 {
            *self.call_count.lock().unwrap()
        }
    }

    #[async_trait]
    impl DecomposerLlm for MockLlm {
        async fn complete(&self, _prompt: &str) -> Result<String> {
            let mut count = self.call_count.lock().unwrap();
            let mut replies = self.replies.lock().unwrap();
            let idx = *count as usize;
            *count += 1;
            if idx < replies.len() {
                Ok(replies[idx].clone())
            } else {
                // If we run out of replies, return a REVISE so the
                // deadlock path is exercisable.
                Ok("REVISE: no more canned replies".to_string())
            }
        }
    }

    /// One REVISE then APPROVED — loop must exit after exactly 2 rounds
    /// and the log must have 2 entries.
    #[tokio::test]
    async fn review_plan_two_rounds_revise_then_approved() {
        let mock = MockLlm::new(vec![
            "REVISE: tighten the scope of the auth slice",
            "APPROVED looks solid now",
        ]);

        let outcome = review_plan(&mock, "## Plan\nDo stuff.").await.unwrap();

        assert!(
            outcome.is_approved(),
            "outcome must be Approved; got {:?}",
            outcome.is_deadlock()
        );
        assert_eq!(mock.calls(), 2, "exactly 2 LLM calls expected");

        let log = outcome.log();
        assert_eq!(log.len(), 2, "log must have exactly 2 entries");

        let rounds = log.rounds();
        assert_eq!(rounds[0].round, 1);
        assert_eq!(rounds[0].verdict, "REVISE");
        assert!(rounds[0].critique.contains("tighten"));

        assert_eq!(rounds[1].round, 2);
        assert_eq!(rounds[1].verdict, "APPROVED");
    }

    /// MAX_REVIEW_ROUNDS all returning REVISE must produce Deadlock.
    #[tokio::test]
    async fn review_plan_deadlock_at_max_rounds_without_approval() {
        // Supply enough REVISE replies to fill MAX_REVIEW_ROUNDS.
        let replies: Vec<&str> = (0..MAX_REVIEW_ROUNDS)
            .map(|_| "REVISE: still not good enough")
            .collect();
        let mock = MockLlm::new(replies);

        let outcome = review_plan(&mock, "## Plan\nDo stuff.").await.unwrap();

        assert!(
            outcome.is_deadlock(),
            "MAX_REVIEW_ROUNDS without APPROVED must be Deadlock"
        );
        assert_eq!(
            mock.calls(),
            MAX_REVIEW_ROUNDS,
            "must call LLM exactly MAX_REVIEW_ROUNDS times"
        );

        let log = outcome.log();
        assert_eq!(
            log.len(),
            MAX_REVIEW_ROUNDS as usize,
            "log must record every round"
        );

        if let ReviewOutcome::Deadlock { unresolved, .. } = &outcome {
            assert!(
                !unresolved.is_empty(),
                "Deadlock must carry unresolved critiques"
            );
        }
    }

    /// Immediate APPROVED — only 1 LLM call, log has 1 entry.
    #[tokio::test]
    async fn review_plan_immediate_approval() {
        let mock = MockLlm::new(vec!["APPROVED great plan"]);
        let outcome = review_plan(&mock, "## Plan\nTiny thing.").await.unwrap();
        assert!(outcome.is_approved());
        assert_eq!(mock.calls(), 1);
        assert_eq!(outcome.log().len(), 1);
    }

    /// A *negated* approval ("NOT approved, REVISE …") must parse as REVISE,
    /// never APPROVED — the old `contains("approved")` read it as APPROVED.
    #[test]
    fn parse_verdict_rejects_negated_approval() {
        let (v, _) = parse_verdict("This is NOT approved, REVISE: fix the auth gate");
        assert_eq!(v, "REVISE", "negated approval must be REVISE");

        let (v2, _) = parse_verdict("APPROVED looks good");
        assert_eq!(v2, "APPROVED", "a leading APPROVED token is the only accepted approval");

        let (v3, _) = parse_verdict("honestly this looks approved to me");
        assert_eq!(v3, "REVISE", "a non-leading 'approved' falls back to REVISE (fail-safe)");

        let (v4, c4) = parse_verdict("REVISE: race in the writer");
        assert_eq!(v4, "REVISE");
        assert!(c4.contains("race"));
    }
}
