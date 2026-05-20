//! Two-stage sub-agent review gate — ported from obra/superpowers Item #2.
//!
//! After a sub-agent produces a reply, the operator can opt in to a quality
//! gate that chains two more provider calls:
//!
//!   1. **Stage 1 — Spec compliance.** Does the reply actually answer what
//!      the operator asked? Catches off-topic / partial / fabricated work.
//!   2. **Stage 2 — Code quality.** When the reply contains code, is the
//!      code idiomatic, safe, and well-tested?
//!
//! Both stages return a typed `ReviewVerdict` with a pass/fail flag + free-
//! form feedback. The dispatcher (caller in `cli/chat.rs` follow-up) emits
//! a WAL `0x84 SUBAGENT_REVIEW_STAGE` frame per stage so the audit trail
//! captures the chain. v0.1 ships the module + tests; chat-pipeline wiring
//! is the follow-up step.
//!
//! Cost note: each invocation triples the provider spend. Operators opt in
//! via `FreedomConfig.review_gate_enabled` (default `false`) — sensible for
//! `/agent code-reviewer` type calls, overkill for casual chat.

use anyhow::Result;

use crate::providers::{Provider, Request};

/// Which review pass produced this verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReviewStage {
    SpecCompliance,
    CodeQuality,
}

impl ReviewStage {
    pub fn as_str(self) -> &'static str {
        match self {
            ReviewStage::SpecCompliance => "spec_compliance",
            ReviewStage::CodeQuality => "code_quality",
        }
    }
}

/// One stage's outcome. `passed = false` does not abort the chain — the
/// caller decides whether a stage-1 fail blocks stage-2 (default: continue
/// both stages so the operator sees the full picture in one call).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewVerdict {
    pub stage: ReviewStage,
    pub passed: bool,
    pub feedback: String,
}

/// Build the system prompt for the spec-compliance pass. The operator's
/// original prompt + the primary reply are interpolated so the reviewer
/// has both sides of the conversation in front of it.
pub fn spec_compliance_system_prompt() -> &'static str {
    "You are a strict spec-compliance reviewer. The operator sent a prompt \
     to a sub-agent. The sub-agent produced a reply. Your job: decide \
     whether the reply actually addresses what the operator asked. \
     Issues to flag: off-topic, partial coverage, fabricated facts, \
     missing requirements, vague closure (\"should work\"). \
     \
     End your review with exactly one line: \
     `VERDICT: PASS` or `VERDICT: FAIL` (no other text on that line). \
     Before the verdict line, give a concise (<200 words) justification."
}

/// System prompt for stage 2 — code quality. Triggered only when the reply
/// contains code blocks; otherwise the dispatcher records a synthetic PASS
/// without calling the provider (saves cost when the reply is pure prose).
pub fn code_quality_system_prompt() -> &'static str {
    "You are a senior code reviewer. Read the sub-agent's reply, focus on \
     any code it contains. Flag: unsafe patterns, missing error handling, \
     un-idiomatic constructs for the language, lack of test coverage, \
     security holes. \
     \
     End your review with exactly one line: \
     `VERDICT: PASS` or `VERDICT: FAIL` (no other text on that line). \
     Before the verdict line, give a concise (<200 words) justification."
}

/// Build the user message handed to the reviewer. Same shape for both
/// stages so the dispatcher can construct it uniformly.
pub fn build_reviewer_user_message(operator_prompt: &str, primary_reply: &str) -> String {
    format!(
        "Operator prompt:\n```\n{}\n```\n\nSub-agent reply:\n```\n{}\n```\n",
        operator_prompt, primary_reply
    )
}

/// Parse a reviewer's output into a typed verdict. Looks for the literal
/// `VERDICT: PASS` / `VERDICT: FAIL` marker on its own line (case-
/// insensitive, trailing whitespace tolerated). Anything before the marker
/// is the feedback body; missing marker = `passed: false` with a note.
pub fn parse_verdict(stage: ReviewStage, reviewer_output: &str) -> ReviewVerdict {
    // Materialise once — `Lines` is forward-only, can't be reversed in place.
    let lines: Vec<&str> = reviewer_output.lines().collect();
    let mut passed: Option<bool> = None;
    let mut verdict_line_idx: Option<usize> = None;
    for (i, line) in lines.iter().enumerate().rev() {
        let upper = line.trim().to_ascii_uppercase();
        if upper == "VERDICT: PASS" || upper == "VERDICT:PASS" {
            passed = Some(true);
            verdict_line_idx = Some(i);
            break;
        }
        if upper == "VERDICT: FAIL" || upper == "VERDICT:FAIL" {
            passed = Some(false);
            verdict_line_idx = Some(i);
            break;
        }
    }
    let feedback = match verdict_line_idx {
        Some(idx) => lines[..idx].join("\n").trim().to_string(),
        None => reviewer_output.trim().to_string(),
    };
    ReviewVerdict {
        stage,
        passed: passed.unwrap_or(false),
        feedback: if feedback.is_empty() {
            "(reviewer returned no body)".to_string()
        } else {
            feedback
        },
    }
}

/// Heuristic: does the reply contain code worth a stage-2 pass? Looks for
/// fenced code blocks (\`\`\`) or 4-space-indented runs. Pure prose skips
/// the second call to save the provider spend.
pub fn reply_has_code(reply: &str) -> bool {
    if reply.contains("```") {
        return true;
    }
    // Indent-block heuristic: ≥ 3 consecutive lines starting with 4+ spaces
    // (or a tab). Trims false positives from accidentally-indented prose.
    let mut run = 0usize;
    for line in reply.lines() {
        if line.starts_with("    ") || line.starts_with('\t') {
            run += 1;
            if run >= 3 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// Run both review stages against a provider. Returns the verdicts in
/// order [SpecCompliance, CodeQuality]. Stage 2 is skipped (synthetic
/// PASS with "no code in reply" feedback) when `reply_has_code` is false.
pub async fn two_stage_review(
    provider: &dyn Provider,
    operator_prompt: &str,
    primary_reply: &str,
) -> Result<Vec<ReviewVerdict>> {
    let user_msg = build_reviewer_user_message(operator_prompt, primary_reply);

    let v1 = run_one_stage(
        provider,
        ReviewStage::SpecCompliance,
        spec_compliance_system_prompt(),
        &user_msg,
    )
    .await?;

    let v2 = if reply_has_code(primary_reply) {
        run_one_stage(
            provider,
            ReviewStage::CodeQuality,
            code_quality_system_prompt(),
            &user_msg,
        )
        .await?
    } else {
        ReviewVerdict {
            stage: ReviewStage::CodeQuality,
            passed: true,
            feedback: "(stage 2 skipped — reply contains no code)".into(),
        }
    };

    Ok(vec![v1, v2])
}

async fn run_one_stage(
    provider: &dyn Provider,
    stage: ReviewStage,
    system: &str,
    user_msg: &str,
) -> Result<ReviewVerdict> {
    let req = Request {
        prompt: user_msg.to_string(),
        system: Some(system.to_string()),
        model: None,
        ..Default::default()
    };
    let completion = provider.complete(req).await?;
    Ok(parse_verdict(stage, &completion.text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::Completion;

    #[test]
    fn parse_verdict_pass() {
        let v = parse_verdict(
            ReviewStage::SpecCompliance,
            "Reply addresses the prompt clearly.\nNo missing requirements.\nVERDICT: PASS",
        );
        assert!(v.passed);
        assert_eq!(v.stage, ReviewStage::SpecCompliance);
        assert!(v.feedback.contains("addresses the prompt"));
    }

    #[test]
    fn parse_verdict_fail() {
        let v = parse_verdict(
            ReviewStage::CodeQuality,
            "Missing error handling at line 42.\nVERDICT: FAIL",
        );
        assert!(!v.passed);
        assert_eq!(v.stage, ReviewStage::CodeQuality);
        assert!(v.feedback.contains("Missing error handling"));
    }

    #[test]
    fn parse_verdict_no_marker_fails_with_full_body_as_feedback() {
        let v = parse_verdict(ReviewStage::SpecCompliance, "Looks fine to me.");
        assert!(!v.passed, "missing marker must default to fail");
        assert!(v.feedback.contains("Looks fine"));
    }

    #[test]
    fn parse_verdict_handles_no_space_variant() {
        let v = parse_verdict(ReviewStage::CodeQuality, "ok\nVERDICT:PASS");
        assert!(v.passed);
    }

    #[test]
    fn parse_verdict_case_insensitive() {
        let v = parse_verdict(ReviewStage::SpecCompliance, "body\nverdict: pass");
        assert!(v.passed);
    }

    #[test]
    fn parse_verdict_uses_last_marker_when_multiple_present() {
        let v = parse_verdict(
            ReviewStage::SpecCompliance,
            "The previous review said VERDICT: PASS but I disagree.\n\
             Actually the reply is partial.\n\
             VERDICT: FAIL",
        );
        assert!(!v.passed, "last marker wins");
    }

    #[test]
    fn reply_has_code_detects_fenced_block() {
        assert!(reply_has_code("Here is code:\n```rust\nfn main() {}\n```"));
    }

    #[test]
    fn reply_has_code_detects_indented_run() {
        let s = "Look:\n\n    let x = 1;\n    let y = 2;\n    println!(\"{}\", x + y);";
        assert!(reply_has_code(s));
    }

    #[test]
    fn reply_has_code_returns_false_for_prose() {
        assert!(!reply_has_code("Just plain English with no code."));
        assert!(!reply_has_code(
            "A single indented line\n    is not enough,\nnor two."
        ));
    }

    #[test]
    fn build_reviewer_user_message_includes_both_sides() {
        let m = build_reviewer_user_message("do X", "I did Y");
        assert!(m.contains("do X"));
        assert!(m.contains("I did Y"));
        assert!(m.contains("Operator prompt"));
        assert!(m.contains("Sub-agent reply"));
    }

    /// Stand-in provider that returns canned reviewer outputs in sequence.
    /// Used to verify `two_stage_review` chains correctly without touching
    /// the real provider stack.
    struct ScriptedProvider {
        scripts: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl Provider for ScriptedProvider {
        fn name(&self) -> &'static str {
            "scripted"
        }
        async fn complete(&self, _req: Request) -> Result<Completion> {
            let mut g = self.scripts.lock().unwrap();
            let text = g
                .pop()
                .ok_or_else(|| anyhow::anyhow!("scripted provider ran out of canned replies"))?;
            Ok(Completion {
                text,
                model: "scripted-1".into(),
                latency: std::time::Duration::from_millis(1),
                input_tokens: Some(10),
                output_tokens: Some(20),
            })
        }
    }

    #[tokio::test]
    async fn two_stage_review_chains_both_stages_when_code_present() {
        // Order: pop() = LIFO. Push stage2 first then stage1 so first call
        // returns stage1's canned reply.
        let provider = ScriptedProvider {
            scripts: std::sync::Mutex::new(vec![
                "code-quality body\nVERDICT: FAIL".into(),
                "spec-compliance body\nVERDICT: PASS".into(),
            ]),
        };
        let verdicts = two_stage_review(
            &provider,
            "operator prompt",
            "primary reply\n```rust\nfn x() {}\n```",
        )
        .await
        .expect("review");
        assert_eq!(verdicts.len(), 2);
        assert_eq!(verdicts[0].stage, ReviewStage::SpecCompliance);
        assert!(verdicts[0].passed);
        assert_eq!(verdicts[1].stage, ReviewStage::CodeQuality);
        assert!(!verdicts[1].passed);
        assert!(verdicts[1].feedback.contains("code-quality body"));
    }

    #[tokio::test]
    async fn two_stage_review_skips_stage2_when_no_code() {
        // Only one canned reply: stage 1. Stage 2 must short-circuit to
        // synthetic PASS without calling provider.complete.
        let provider = ScriptedProvider {
            scripts: std::sync::Mutex::new(vec!["spec body\nVERDICT: PASS".into()]),
        };
        let verdicts = two_stage_review(&provider, "operator prompt", "pure prose reply")
            .await
            .expect("review");
        assert_eq!(verdicts.len(), 2);
        assert!(verdicts[0].passed);
        assert!(verdicts[1].passed, "synthetic stage-2 PASS");
        assert!(verdicts[1].feedback.contains("skipped"));
    }
}
