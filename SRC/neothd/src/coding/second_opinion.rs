//! Pick #9 — LLM second-opinion classifier for `Ambiguous` tasks.
//!
//! When `classify_heuristic` returns `Complexity::Ambiguous` (no
//! signal list fires), the dispatcher escalates here. The Cerebellum
//! LLM gets a focused yes-or-no prompt + we parse a `FAST`/`DEEP`
//! token from the reply. On parse failure we default to `Deep` — the
//! Right hemisphere can handle anything Left can, but not vice versa,
//! so erring deep is the safer escalation.
//!
//! Re-uses the [`DecomposerLlm`] trait so the production wire-up
//! happens through the same Cerebellum provider that runs `Pick #4`
//! decomposition — no second provider binding needed.

use anyhow::Result;

use crate::coding::classifier::Complexity;
use crate::coding::decomposer::DecomposerLlm;
use crate::coding::types::KanbanTask;

/// Cap on reply length the parser tolerates. Long ramble-replies that
/// don't echo a single FAST/DEEP token within this window get the
/// default `Deep` verdict. Cerebellum should be returning ≤30 chars
/// for this classify role — anything longer is misuse.
pub const MAX_REPLY_LEN: usize = 256;

/// Build the focused classify prompt. The LLM must reply with exactly
/// one of `FAST` or `DEEP` followed by an optional one-line reason.
/// Operator description is delimited as DATA (same anti-injection
/// pattern as `decomposer::build_prompt`).
pub fn build_classify_prompt(task: &KanbanTask) -> String {
    let title = task.title.as_str();
    let description = task.description.as_deref().unwrap_or("(no description)");
    format!(
        "You classify one engineering task into FAST or DEEP.\n\
         \n\
         FAST = single-file change, UI scaffold, CRUD, test stub, rename, typo.\n\
         DEEP = architecture, multi-file refactor, design decision, ambiguous spec.\n\
         \n\
         Reply with exactly one word on the first line: FAST or DEEP.\n\
         You may add one short explanation line after.\n\
         \n\
         <<<TASK_TITLE\n{title}\n>>>TASK_TITLE\n\
         <<<TASK_DESCRIPTION\n{description}\n>>>TASK_DESCRIPTION\n"
    )
}

/// Parse the LLM reply into a `Complexity`. Looks for the first
/// FAST / DEEP token (case-insensitive). Defaults to `Deep` on
/// failure — Right hemisphere is the safer escalation for ambiguous
/// requirements.
pub fn parse_classify_reply(reply: &str) -> Complexity {
    // Bound the scan to MAX_REPLY_LEN so a chatty model can't waste
    // our cycles on a 10k-char poem.
    let scan = if reply.len() <= MAX_REPLY_LEN {
        reply
    } else {
        // GOLD-COR-02 / A-04: char-boundary-safe slice — `reply` is raw LLM
        // output (multibyte), so a raw `[..MAX_REPLY_LEN]` could panic.
        let mut end = MAX_REPLY_LEN;
        while end > 0 && !reply.is_char_boundary(end) {
            end -= 1;
        }
        &reply[..end]
    };
    let upper = scan.to_ascii_uppercase();
    // First-token-wins: FAST anywhere in the prefix wins unless DEEP
    // appears earlier. Mirrors the operator's reading-order expectation
    // ("I see FAST in line 1, the task IS fast").
    let fast_pos = upper.find("FAST");
    let deep_pos = upper.find("DEEP");
    match (fast_pos, deep_pos) {
        (Some(f), Some(d)) => {
            if f < d {
                Complexity::Fast
            } else {
                Complexity::Deep
            }
        }
        (Some(_), None) => Complexity::Fast,
        (None, Some(_)) => Complexity::Deep,
        (None, None) => Complexity::Deep, // safe default
    }
}

/// Run the second-opinion classify against the Cerebellum LLM.
/// Failed LLM calls collapse to `Complexity::Deep` so the dispatcher
/// keeps moving — the operator sees the task in Right hemisphere
/// with a `tracing::warn` line, not a stuck Ambiguous bucket.
pub async fn second_opinion_classify(llm: &dyn DecomposerLlm, task: &KanbanTask) -> Complexity {
    let prompt = build_classify_prompt(task);
    let reply = match llm.complete(&prompt).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                task_id = task.task_id.raw(),
                error = %e,
                "second-opinion LLM call failed; defaulting to Deep"
            );
            return Complexity::Deep;
        }
    };
    parse_classify_reply(&reply)
}

/// Convenience wrapper used by the dispatcher and tests when callers
/// want a `Result` (so an outer `?` keeps the error chain intact even
/// though the LLM-failure path here is already collapsed to a
/// default).
pub async fn second_opinion_classify_result(
    llm: &dyn DecomposerLlm,
    task: &KanbanTask,
) -> Result<Complexity> {
    Ok(second_opinion_classify(llm, task).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coding::types::{Hemisphere, KanbanSessionId, KanbanTaskId, TaskStatus};
    use async_trait::async_trait;

    fn sample_task(title: &str, desc: Option<&str>) -> KanbanTask {
        KanbanTask {
            task_id: KanbanTaskId(7),
            session_id: KanbanSessionId(1),
            status: TaskStatus::Backlog,
            title: title.into(),
            description: desc.map(String::from),
            task_type: "ui".into(),
            hemisphere: Hemisphere::Unassigned,
            worker: None,
            parent_task_id: None,
            created_ns: 0,
            started_ns: None,
            eta_ns: None,
            completed_ns: None,
            patch_path: None,
            test_summary: None,
        }
    }

    /// Canned LLM — replies with a static string. Sufficient to pin
    /// the parser contract end-to-end.
    struct CannedLlm {
        reply: String,
    }

    #[async_trait]
    impl DecomposerLlm for CannedLlm {
        async fn complete(&self, _prompt: &str) -> Result<String> {
            Ok(self.reply.clone())
        }
    }

    /// LLM that always errors. Lets us assert the safe-default path.
    struct FailingLlm;

    #[async_trait]
    impl DecomposerLlm for FailingLlm {
        async fn complete(&self, _prompt: &str) -> Result<String> {
            anyhow::bail!("simulated LLM outage")
        }
    }

    #[test]
    fn parse_reply_fast_first_wins() {
        // A reply that starts with FAST + later mentions deep MUST
        // classify as Fast (first-token-wins, mirrors operator reading
        // order).
        assert_eq!(
            parse_classify_reply("FAST\nIt's a one-line typo fix, not deep work."),
            Complexity::Fast
        );
    }

    #[test]
    fn parse_reply_deep_first_wins() {
        assert_eq!(
            parse_classify_reply("DEEP\nRefactor spans 12 files, not fast at all."),
            Complexity::Deep
        );
    }

    #[test]
    fn parse_reply_case_insensitive() {
        // Some models lowercase tokens; our parser MUST handle that.
        assert_eq!(parse_classify_reply("fast — typo"), Complexity::Fast);
        assert_eq!(parse_classify_reply("Deep refactor"), Complexity::Deep);
    }

    #[test]
    fn parse_reply_defaults_deep_when_unrecognised() {
        // Garbage / verbose ramble / empty → Deep (safer escalation).
        assert_eq!(parse_classify_reply(""), Complexity::Deep);
        assert_eq!(
            parse_classify_reply("I'm not sure, could go either way..."),
            Complexity::Deep
        );
        assert_eq!(parse_classify_reply("OK"), Complexity::Deep);
    }

    #[test]
    fn parse_reply_truncates_overlong_input() {
        // 10 KB of "X" then a FAST token — the parser should never
        // see the FAST because it's past MAX_REPLY_LEN. Defaults Deep.
        let mut blob = "X".repeat(MAX_REPLY_LEN + 10);
        blob.push_str("FAST");
        assert_eq!(parse_classify_reply(&blob), Complexity::Deep);
    }

    #[test]
    fn build_prompt_includes_title_and_description_delimited() {
        let task = sample_task("Add dark mode", Some("only the toggle component"));
        let prompt = build_classify_prompt(&task);
        assert!(prompt.contains("<<<TASK_TITLE"));
        assert!(prompt.contains("Add dark mode"));
        assert!(prompt.contains("<<<TASK_DESCRIPTION"));
        assert!(prompt.contains("only the toggle component"));
        assert!(prompt.contains("FAST"));
        assert!(prompt.contains("DEEP"));
    }

    #[test]
    fn build_prompt_handles_missing_description() {
        let task = sample_task("Rename a fn", None);
        let prompt = build_classify_prompt(&task);
        assert!(prompt.contains("(no description)"));
    }

    #[tokio::test]
    async fn second_opinion_returns_fast_from_canned_reply() {
        let llm = CannedLlm {
            reply: "FAST\nit's a one-liner".into(),
        };
        let task = sample_task("typo", None);
        assert_eq!(second_opinion_classify(&llm, &task).await, Complexity::Fast);
    }

    #[tokio::test]
    async fn second_opinion_returns_deep_when_llm_fails() {
        // Pick #9 safety: LLM outage MUST NOT stall the dispatcher.
        // The Ambiguous task escalates to Deep (Right hemisphere)
        // and the operator sees a warn log.
        let llm = FailingLlm;
        let task = sample_task("unclear", None);
        assert_eq!(second_opinion_classify(&llm, &task).await, Complexity::Deep);
    }

    #[tokio::test]
    async fn second_opinion_result_wrapper_round_trips() {
        let llm = CannedLlm {
            reply: "DEEP".into(),
        };
        let task = sample_task("x", None);
        let result = second_opinion_classify_result(&llm, &task).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Complexity::Deep);
    }
}
