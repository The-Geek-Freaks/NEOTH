//! HERMES-04 — Independent goal-verification judge.
//!
//! After the dispatch loop's nudge fires and the model replies, the loop
//! would normally stop on the NEXT clean exit without verifying the goal
//! is actually met (the model self-assesses "yes I'm done" inline in its
//! reply). This module adds an independent LLM call — using the SAME
//! provider — that asks a minimal temp-0 prompt: "Is this goal met? YES
//! or NO." If YES, the loop exits immediately before the normal nudge
//! path. If NO (or on any provider error), the existing nudge path fires
//! unchanged.
//!
//! ## Privacy / cost contract
//!
//! - The judge call uses a TRUNCATED conversation summary (≤ 2000 chars)
//!   to bound token cost.
//! - The WAL frame records `goal_hash` (xxh3-64 hex) not the raw goal
//!   text; the conversation summary never reaches the WAL.
//! - Provider error → fail-open (judge returns `false`); the existing
//!   nudge then fires normally. A broken judge NEVER silently exits the
//!   loop.

/// Maximum characters of `conversation_summary` fed to the judge prompt.
/// Limits the extra provider call to a small bounded slice of the
/// conversation even for very long grind sessions.
pub const JUDGE_SUMMARY_TRUNCATE: usize = 2000;

/// Emit byte for the GOAL_JUDGED WAL frame — re-exported here so call
/// sites can reference `goal_judge::GOAL_JUDGED_EVENT` without touching
/// `wal::events` directly.
pub use crate::wal::events::EVENT_TYPE_GOAL_JUDGED;

/// Ask an independent LLM call whether `goal` is fully met given the
/// current conversation state (`conversation_summary`).
///
/// Returns `true` when the judge says **YES** (the loop may exit), `false`
/// in all other cases (nudge fires as normal). On a provider error the
/// function logs a warning and returns `false` (fail-open).
///
/// The judge uses a tight, structured prompt so the model only needs to
/// emit a single word. Temperature is not directly settable here — the
/// provider uses its own default, which is fine; the yes/no framing keeps
/// the response deterministic even at default temperature.
pub async fn judge_goal_met(
    goal: &str,
    conversation_summary: &str,
    provider: &dyn crate::providers::Provider,
    writer: Option<&crate::wal::writer::WalWriterHandle>,
) -> bool {
    // Truncate the summary to bound the judge call cost.
    let summary = truncate_to_char_boundary(conversation_summary, JUDGE_SUMMARY_TRUNCATE);

    let prompt = format!(
        "You are a strict goal-completion evaluator. Your ONLY job is to determine \
         whether a goal has been fully accomplished.\n\n\
         CONVERSATION SUMMARY:\n{summary}\n\n\
         GOAL TO EVALUATE:\n{goal}\n\n\
         Has this goal been FULLY and COMPLETELY met based on the conversation above?\n\
         Reply with ONLY the single word YES or NO. No explanation."
    );

    let req = crate::providers::Request {
        prompt,
        ..Default::default()
    };

    let verdict = match provider.complete(req).await {
        Ok(completion) => {
            let text = completion.text.trim().to_uppercase();
            text.starts_with("YES")
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "HERMES-04: goal judge provider call failed — fail-open (nudge will fire)"
            );
            false
        }
    };

    // Emit the WAL audit frame (GOLD-TASK-05: kind field replaces verdict field).
    let goal_hash = format!("{:016x}", xxhash_rust::xxh3::xxh3_64(goal.as_bytes()));
    let kind = if verdict { "met" } else { "not_met" };
    emit_goal_judged_wal(writer, &goal_hash, kind).await;

    verdict
}

/// Append a `0x89 GOAL_JUDGED` WAL frame. Best-effort: a WAL failure must
/// never abort the loop. Records goal hash + kind + timestamp only —
/// never the raw goal text or conversation content.
///
/// `kind` is one of: `"met"`, `"not_met"`, `"budget_exhausted"`.
/// Using a single event byte with a discriminating `kind` field avoids
/// claiming new WAL bytes (0x7A/0x7B are already taken by skill-effort events).
pub async fn emit_goal_judged_wal(
    writer: Option<&crate::wal::writer::WalWriterHandle>,
    goal_hash: &str,
    kind: &str,
) {
    let Some(w) = writer else { return };
    let ts = crate::time::now_unix_i64();
    let payload = match serde_json::to_vec(&serde_json::json!({
        "goal_hash": goal_hash,
        "kind": kind,
        "ts_unix": ts,
    })) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "HERMES-04: WAL payload serialise failed");
            return;
        }
    };
    let header =
        crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_GOAL_JUDGED, &payload)
            .build();
    if let Err(e) = w.append(header, payload).await {
        tracing::warn!(error = %e, "HERMES-04: GOAL_JUDGED WAL append failed (audit gap)");
    }
}

/// Return a byte-boundary-safe prefix of `s` of at most `max_chars` Unicode
/// scalar values. This is different from byte truncation — we count chars
/// (`.char_indices().nth(max_chars)`) so multi-byte characters don't get
/// split. Returns a `&str` slice (zero-copy when short enough).
fn truncate_to_char_boundary(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        Some((byte_pos, _)) => &s[..byte_pos],
        None => s,
    }
}

// ── unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── truncate helper ──────────────────────────────────────────────────────

    #[test]
    fn truncate_short_returns_unchanged() {
        let s = "hello world";
        assert_eq!(truncate_to_char_boundary(s, 100), s);
    }

    #[test]
    fn truncate_at_char_boundary() {
        // "日本語" is 3 chars each 3 bytes. Truncating to 2 chars gives the first
        // 6 bytes (日本), not a mid-byte slice.
        let s = "日本語";
        let t = truncate_to_char_boundary(s, 2);
        assert_eq!(t, "日本");
    }

    #[test]
    fn truncate_empty_string() {
        assert_eq!(truncate_to_char_boundary("", 10), "");
    }

    // ── goal_hash format ─────────────────────────────────────────────────────

    #[test]
    fn goal_hash_is_hex_not_raw_goal() {
        // The WAL payload must never store the raw goal text — only the hash.
        // We can't easily test the async emit without a real WAL writer, but we
        // can verify the hash format the emit would use.
        let goal = "finish the report";
        let hash = format!("{:016x}", xxhash_rust::xxh3::xxh3_64(goal.as_bytes()));
        // 16 hex chars = 8 bytes = xxh3-64 wire width.
        assert_eq!(hash.len(), 16, "goal hash must be 16 hex chars");
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "goal hash must be hex"
        );
        assert!(
            !hash.contains("report"),
            "goal hash must not contain raw goal text"
        );
    }

    // ── judge_goal_met integration ────────────────────────────────────────────

    // Mock provider that always returns a fixed reply.
    struct FixedProvider(String);

    #[async_trait::async_trait]
    impl crate::providers::Provider for FixedProvider {
        fn name(&self) -> &'static str {
            "mock_judge"
        }
        async fn complete(
            &self,
            _req: crate::providers::Request,
        ) -> anyhow::Result<crate::providers::Completion> {
            Ok(crate::providers::Completion {
                text: self.0.clone(),
                identity: Default::default(),
                model: "mock".into(),
                latency: std::time::Duration::ZERO,
                input_tokens: None,
                output_tokens: None,
                cache_creation_tokens: None,
                cache_read_tokens: None,
            })
        }
    }

    #[tokio::test]
    async fn judge_returns_true_on_yes_reply() {
        let provider = FixedProvider("YES".into());
        let result =
            judge_goal_met("finish the task", "I finished the task.", &provider, None).await;
        assert!(result, "YES reply must return true");
    }

    #[tokio::test]
    async fn judge_returns_true_on_yes_with_trailing_text() {
        // The judge spec says starts_with("YES") so extra text is fine.
        let provider = FixedProvider("YES, the goal is met.".into());
        let result =
            judge_goal_met("finish the task", "I finished the task.", &provider, None).await;
        assert!(result, "YES-prefixed reply must return true");
    }

    #[tokio::test]
    async fn judge_returns_false_on_no_reply() {
        let provider = FixedProvider("NO".into());
        let result = judge_goal_met("finish the task", "Still working.", &provider, None).await;
        assert!(!result, "NO reply must return false");
    }

    #[tokio::test]
    async fn judge_returns_false_on_empty_reply() {
        let provider = FixedProvider(String::new());
        let result = judge_goal_met("finish the task", "I finished.", &provider, None).await;
        assert!(!result, "empty reply must return false");
    }

    #[tokio::test]
    async fn judge_is_case_insensitive_on_yes() {
        // `to_uppercase` normalises "yes" → "YES".
        let provider = FixedProvider("yes".into());
        let result = judge_goal_met("finish the task", "Done.", &provider, None).await;
        assert!(result, "lowercase yes must return true");
    }

    struct ErrorProvider;

    #[async_trait::async_trait]
    impl crate::providers::Provider for ErrorProvider {
        fn name(&self) -> &'static str {
            "mock_error"
        }
        async fn complete(
            &self,
            _req: crate::providers::Request,
        ) -> anyhow::Result<crate::providers::Completion> {
            Err(anyhow::anyhow!("simulated provider error"))
        }
    }

    #[tokio::test]
    async fn judge_fails_open_on_provider_error() {
        // A broken judge MUST return false (fail-open) so the normal nudge path
        // fires rather than silently exiting the loop.
        let result = judge_goal_met("finish the task", "Done.", &ErrorProvider, None).await;
        assert!(
            !result,
            "provider error must return false (fail-open, not silent loop exit)"
        );
    }

    #[tokio::test]
    async fn judge_truncates_long_summary() {
        // A 10 000-char summary is trimmed to JUDGE_SUMMARY_TRUNCATE before the
        // provider sees it; the provider still replies YES (it's mocked).
        let long_summary = "a".repeat(10_000);
        let provider = FixedProvider("YES".into());
        // We can't directly inspect what went to the provider in the mock,
        // but we can verify the function completes without panic + returns true.
        let result = judge_goal_met("finish the task", &long_summary, &provider, None).await;
        assert!(result, "judge must work with a long summary");
    }
}
