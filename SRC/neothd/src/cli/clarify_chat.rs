//! GOLD-ADAPT-HERMES-03 (consumer) — mid-run clarification in `neoth chat`.
//!
//! The first real production CALLER of [`crate::daemon::clarify::ClarificationGate`]
//! (the engine landed earlier with tests but no caller — review verdict
//! 2026-06-20 flagged it engine-only). When the model's reply carries an
//! ambiguity marker (see [`crate::daemon::clarify::is_ambiguous`]) and the
//! operator is at an interactive TTY, NEOTH pauses the turn, surfaces the
//! clarifying question, **parks on the gate**, reads the operator's answer from
//! stdin (the operator answer surface), resumes the parked worker via
//! [`crate::daemon::clarify::ClarificationGate::answer`], and re-issues the
//! provider call with the answer appended.
//!
//! Opt-in (`NEOTH_CLARIFICATION=1`); default off → zero behaviour change. A
//! no-op when stdin is not a TTY (piped / `--stream` / automation never block).
//!
//! The gate is single-use per run (engine contract): one park→answer round-trip
//! per turn. A second ambiguity in the re-issued reply is returned verbatim —
//! the channel/autonomous path (out-of-band answer surface) is a follow-up.

use std::io::IsTerminal;
use std::sync::Arc;

use crate::daemon::clarify::{self, ClarificationGate, ParkOutcome};
use crate::providers::{Provider, Request};

/// Env opt-in. Default off so the common path is byte-for-byte unchanged.
/// `pub(crate)` so the channel path (HERMES-03b, serve_pipeline) gates its
/// out-of-band answer-routing on the same opt-in.
pub(crate) fn enabled() -> bool {
    std::env::var("NEOTH_CLARIFICATION")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// One-line protocol injected into the system prompt (only when opted-in) so
/// the model knows it may request a clarification. Without this the marker
/// would never appear in practice and the gate would stay dormant.
const CLARIFY_PROTOCOL: &str = "\n\nClarification protocol: if — and only if — \
the operator's request is genuinely ambiguous and you cannot proceed without \
one missing detail, reply with exactly `[[clarify]] <one concise question>` and \
nothing else. Otherwise answer normally; never use this for rhetorical questions.";

/// Append the clarification protocol to the assembled system prompt when the
/// feature is opted-in. A no-op (returns `base` unchanged) by default, so the
/// common path's system prompt is byte-for-byte identical.
pub fn augment_system(base: String) -> String {
    if enabled() {
        format!("{base}{CLARIFY_PROTOCOL}")
    } else {
        base
    }
}

/// Markers `clarify::is_ambiguous` recognises — stripped so the operator sees a
/// clean question instead of the raw signal token.
const MARKERS: &[&str] = &[
    "[[ambiguous]]",
    "[[clarify]]",
    "[[needs-clarification]]",
    "AMBIGUOUS:",
    "CLARIFY:",
];

/// Remove the (first) ambiguity marker from the model reply. `pub(crate)` so the
/// channel path (HERMES-03b) surfaces the same clean question the CLI does.
pub(crate) fn strip_marker(reply: &str) -> String {
    let mut out = reply.trim().to_string();
    let lower = out.to_lowercase();
    for m in MARKERS {
        if let Some(pos) = lower.find(&m.to_lowercase()) {
            out.replace_range(pos..pos + m.len(), "");
            break;
        }
    }
    out.trim().to_string()
}

/// If `reply` asks for clarification (and we're enabled + on a TTY), run one
/// clarification round-trip and return the resolved reply. Returns `None` when
/// no clarification happened — the caller then prints the original reply
/// unchanged, so the default path is untouched.
pub async fn maybe_clarify(
    provider: &dyn Provider,
    original_prompt: &str,
    system: Option<&str>,
    reply: &str,
) -> Option<String> {
    if !enabled() || !clarify::is_ambiguous(reply) {
        return None;
    }
    // Non-interactive stdin (pipe / automation) → never block: the marker reply
    // flows through unchanged (the caller prints it).
    if !std::io::stdin().is_terminal() {
        return None;
    }

    let question = strip_marker(reply);
    println!("\n[neoth needs clarification] {question}");
    print!("> your answer: ");
    use std::io::Write as _;
    let _ = std::io::stdout().flush();

    // Operator answer surface: a blocking stdin read on its own task feeds the
    // gate, so `park` (worker half) and `answer` (operator half) rendezvous
    // across two tasks exactly as the engine is designed.
    let gate = Arc::new(ClarificationGate::default());
    let gate_answer = Arc::clone(&gate);
    // ponytail: spawn_blocking can't be force-cancelled — if the operator walks
    // away the gate times out (DEFAULT_TIMEOUT) but this thread stays parked on
    // stdin until the process exits. Fine for a one-shot CLI; revisit if reused.
    let answer_task = tokio::task::spawn_blocking(move || -> Option<()> {
        let mut line = String::new();
        let n = std::io::stdin().read_line(&mut line).ok()?;
        if n == 0 {
            return None; // EOF (Ctrl-D)
        }
        // `park` has set Waiting by now: the operator had to type a line first.
        let req = gate_answer.pending_request()?;
        gate_answer.answer(&req.id, line.trim().to_string()).ok()
    });

    match gate.park(question).await {
        Ok(ParkOutcome::Answered(answer)) => {
            let _ = answer_task.await;
            let req = Request {
                prompt: format!("{original_prompt}\n\n[operator clarification]: {answer}"),
                system: system.map(str::to_string),
                model: None,
                ..Default::default()
            };
            match provider.complete(req).await {
                Ok(c) => Some(c.text),
                Err(e) => {
                    tracing::warn!(error = %e, "clarification re-issue failed; keeping original reply");
                    None
                }
            }
        }
        Ok(ParkOutcome::TimedOut) => {
            answer_task.abort();
            println!("[neoth] clarification timed out — proceeding with the original reply.");
            None
        }
        Err(e) => {
            tracing::warn!(error = %e, "clarification gate park errored; keeping original reply");
            answer_task.abort();
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_marker_removes_known_signal_tokens() {
        assert_eq!(
            strip_marker("[[clarify]] staging or production?"),
            "staging or production?"
        );
        assert_eq!(
            strip_marker("CLARIFY: which branch do you mean?"),
            "which branch do you mean?"
        );
        // Case-insensitive, mid-string.
        assert_eq!(strip_marker("[[AMBIGUOUS]] two targets"), "two targets");
        // No marker → trimmed verbatim.
        assert_eq!(strip_marker("  just a normal reply  "), "just a normal reply");
    }

    #[test]
    fn enabled_defaults_off() {
        // The opt-in is env-driven; with the var unset the feature is inert.
        // (We don't mutate the process env here to avoid cross-test races; the
        // contract under test is that the default branch returns false.)
        if std::env::var("NEOTH_CLARIFICATION").is_err() {
            assert!(!enabled(), "feature must be off without the opt-in env");
        }
    }

    #[tokio::test]
    async fn non_ambiguous_reply_is_a_noop() {
        // No marker → returns None regardless of enabled/TTY state, so the
        // caller prints the original reply unchanged.
        struct Dummy;
        #[async_trait::async_trait]
        impl Provider for Dummy {
            fn name(&self) -> &'static str {
                "dummy"
            }
            async fn complete(
                &self,
                _req: Request,
            ) -> anyhow::Result<crate::providers::Completion> {
                unreachable!("must not be called for a non-ambiguous reply")
            }
        }
        let out = maybe_clarify(&Dummy, "deploy it", None, "done, deployed staging").await;
        assert!(out.is_none(), "a clean reply triggers no clarification");
    }
}
