//! Pick #6 Phase 3 — concrete provider-backed Worker.
//!
//! `ProviderWorker` wraps any `providers::Provider` (claude_cli,
//! openai_api, openai_compat, gemini_api, local_qwen, local_ouro)
//! into an `async` `Worker` impl that the dispatcher calls
//! one task at a time. QU-10d (Session 30): `Worker::execute` is now
//! `async`, so this awaits `provider.complete` directly on the ambient
//! runtime — the prior `tokio::runtime::Handle` + `block_on` hack is
//! gone (block_on inside an async context risked a nested-runtime
//! panic; awaiting is correct + lets the executor parallelise).
//!
//! Left vs Right is just a name label — the hemisphere binding lives
//! in `HemisphereWorkerSet`, not here. The constructor takes the name
//! ("left/local_qwen", "right/claude_cli") and the operator's bound
//! provider; the dispatcher decides which hemisphere this worker
//! serves.
//!
//! Phase 3 scope:
//!   - Build a prompt from the kanban task (title + description + role
//!     hint + repo context placeholder)
//!   - Call provider.complete()
//!   - Parse the completion: extract a unified-diff patch block if
//!     present, otherwise treat as a no-op outcome with summary only
//!   - Write the patch to `<wal_dir>/coding-sessions/<session-id>/
//!     task-<task-id>.patch` so audit consumers can re-apply
//!
//! Q1 patch-safety placeholder: this commit stores the patch without
//! applying. `git apply --check` + real apply land once Chorus settles
//! Q1 (direct vs worktree vs stash-revert).

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;

use crate::coding::tool_router::{self, RoutingMode, ToolCategory};
use crate::coding::types::{KanbanTask, TestSummary};
use crate::coding::worker::{Worker, WorkerOutcome};
use crate::providers::{Provider, Request};

/// Provider-backed worker. One instance per (hemisphere, provider)
/// binding; held by `HemisphereWorkerSet`.
pub struct ProviderWorker {
    name: &'static str,
    provider: Arc<dyn Provider>,
    /// Operator-configured model name for the bound provider (e.g.
    /// `"deepseek-coder"`, `"qwen3"`). Drives the GOLD-WIRE-01 two-stage
    /// tool-router decision: small-context models (`≤ 16 384`) get a
    /// Stage-1 category-selector turn before the task. Empty when the
    /// slot left the model unset — that resolves to the unknown-default
    /// profile (32 k context → Direct, no extra call).
    model_name: String,
    /// Where task patches land. `<wal_dir>/coding-sessions/<session-id>/
    /// task-<task-id>.patch`. The dispatcher provides the parent dir;
    /// this struct only knows the operator's home root.
    patch_root: PathBuf,
}

impl ProviderWorker {
    /// Build a worker. `name` is operator-readable and surfaces in
    /// the WAL + activity feed; pin it to a stable string per
    /// hemisphere ("left/local_qwen", "right/claude_cli") so audit
    /// chain readability survives renames. `model_name` is the
    /// operator-configured model for this provider — it selects the
    /// tool-router profile (GOLD-WIRE-01); pass `""` when unknown.
    /// QU-10d: no longer takes a `runtime` Handle — `execute` is async
    /// and awaits the provider on the ambient runtime.
    pub fn new(
        name: &'static str,
        provider: Arc<dyn Provider>,
        model_name: impl Into<String>,
        patch_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            name,
            provider,
            model_name: model_name.into(),
            patch_root: patch_root.into(),
        }
    }

    /// Stage 1 of the two-stage tool router (GOLD-WIRE-01): ask the model
    /// which tool category its next action falls in, so Stage 2 can prime
    /// the task prompt with just that category's vocabulary instead of the
    /// full set. A failed call OR an unparseable reply yields `None` —
    /// the caller then proceeds with the plain (Direct) task prompt.
    async fn select_tool_category(&self) -> Option<ToolCategory> {
        let selector = Request {
            prompt: tool_router::build_selector_prompt(),
            ..Default::default()
        };
        match self.provider.complete(selector).await {
            Ok(c) => parse_category_reply(&c.text),
            Err(e) => {
                tracing::warn!(
                    worker = self.name,
                    error = %e,
                    "tool-router Stage-1 selector failed; falling back to Direct"
                );
                None
            }
        }
    }
}

/// Lenient parse of the Stage-1 selector reply. The prompt asks for the
/// bare category name; tolerate surrounding whitespace + case + a short
/// trailing clause by also trying the first whitespace token. `None`
/// when nothing matches → the caller falls back to Direct (no hint).
fn parse_category_reply(reply: &str) -> Option<ToolCategory> {
    let lower = reply.trim().to_ascii_lowercase();
    ToolCategory::from_str(&lower)
        .or_else(|| lower.split_whitespace().next().and_then(ToolCategory::from_str))
}

#[async_trait]
impl Worker for ProviderWorker {
    async fn execute(&self, task: &KanbanTask) -> Result<WorkerOutcome> {
        // GOLD-WIRE-01: two-stage tool routing. Small-context models
        // (≤ 16 384, e.g. local Qwen/deepseek) first pick ONE tool
        // category so the task prompt can be primed with just that
        // category's vocabulary; larger models skip the extra turn.
        // `detected_context_window = 0` — no live endpoint-side context
        // probe is wired yet, so the static `model_profile::KNOWN_PROFILES`
        // table is used as-is (`0` never overrides). Pass a real detected
        // value here once an endpoint context-window probe exists.
        let profile = crate::coding::model_profile::get_profile(&self.model_name, 0);
        let tool_hint = match tool_router::routing_mode_for_profile(&profile) {
            RoutingMode::TwoStage => self.select_tool_category().await,
            RoutingMode::Direct => None,
        };
        let prompt = build_task_prompt(task, tool_hint);
        let req = Request {
            prompt,
            ..Default::default()
        };
        let completion = self
            .provider
            .complete(req)
            .await
            .with_context(|| format!("worker {} provider.complete", self.name))?;
        let parsed = parse_completion_text(&completion.text);
        let patch_path = patch_path_for(&self.patch_root, task);
        if !parsed.patch.is_empty() {
            // Ensure the parent dir exists. Best-effort — we still
            // record the patch_path in the outcome even if disk
            // write fails so the operator sees what we tried.
            if let Some(parent) = patch_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Err(e) = std::fs::write(&patch_path, parsed.patch.as_bytes()) {
                tracing::warn!(
                    path = %patch_path.display(),
                    error = %e,
                    "ProviderWorker: failed to persist patch — audit copy missing"
                );
            }
        }
        Ok(WorkerOutcome {
            patch_text: parsed.patch,
            patch_path,
            tests: parsed.tests,
            summary: parsed.summary,
        })
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

/// Where on disk a task's patch is persisted. Layout:
///   `<patch_root>/coding-sessions/<session-id>/task-<task-id>.patch`
pub fn patch_path_for(patch_root: &std::path::Path, task: &KanbanTask) -> PathBuf {
    patch_root
        .join("coding-sessions")
        .join(format!("{}", task.session_id.raw()))
        .join(format!("task-{}.patch", task.task_id.raw()))
}

/// Build the prompt the worker hands the provider. Plain template:
///   - Operator's task title
///   - Optional description
///   - Role hint based on the task's hemisphere
///   - Explicit "respond with a unified diff" instruction
///
/// Repo context (which files to read, project layout) lands in
/// Phase 3 follow-up — the LLM gets a `repo_context: &str` parameter
/// once the dispatcher decides how much to feed.
///
/// `tool_hint` is the GOLD-WIRE-01 Stage-1 result: when `Some`, the
/// prompt is primed with that tool category's description + member
/// vocabulary so a small-context model focuses its next action; `None`
/// (Direct mode, or an unparseable Stage-1 reply) leaves the prompt
/// plain.
fn build_task_prompt(task: &KanbanTask, tool_hint: Option<ToolCategory>) -> String {
    let role_hint = match task.hemisphere {
        crate::coding::types::Hemisphere::Left => {
            "You are a fast, focused engineer. Make the smallest change \
             that solves the task. Always include tests."
        }
        crate::coding::types::Hemisphere::Right => {
            "You are a senior engineer. Think through the design \
             implications, then make the change. Always include tests."
        }
        crate::coding::types::Hemisphere::Cerebellum => {
            "You are an orchestrator. Decompose ambiguous tasks; \
             write directly only when the change is mechanical."
        }
        crate::coding::types::Hemisphere::Unassigned => {
            "You are an engineer. Decide the appropriate scope, then \
             make the change. Always include tests."
        }
    };
    let mut out = String::with_capacity(512);
    out.push_str(role_hint);
    if let Some(cat) = tool_hint {
        // GOLD-WIRE-01 Stage-2 priming: focus the small model on the
        // category it picked in Stage 1.
        out.push_str("\n\nLikely tool category for this task: ");
        out.push_str(cat.as_str());
        out.push_str(" — ");
        out.push_str(tool_router::category_description(cat));
        out.push_str(".\nRelevant operations: ");
        out.push_str(&tool_router::category_member_hint(cat).join(", "));
        out.push('.');
    }
    out.push_str("\n\n---\n");
    out.push_str("TASK\n");
    out.push_str("Title: ");
    out.push_str(&task.title);
    if let Some(desc) = task.description.as_ref() {
        out.push_str("\nDescription: ");
        out.push_str(desc);
    }
    out.push_str("\nType: ");
    out.push_str(&task.task_type);
    out.push_str("\nHemisphere: ");
    out.push_str(task.hemisphere.as_str());
    out.push_str("\n---\n");
    out.push_str("\nRespond in two parts:\n");
    out.push_str("1. A unified-diff patch in a ```diff fenced block.\n");
    out.push_str("2. A one-line summary on a line that starts with `SUMMARY:`.\n");
    out.push_str(
        "\nIf the task does not require a code change, omit the diff block \
                  and write `SUMMARY: no change required — <reason>` on its own line.\n",
    );
    out
}

/// Pure parse step extracted so unit tests can exercise the response
/// format without a real Provider. Looks for:
///   - The first ```diff (case-insensitive) fenced block — its body
///     is the patch_text. Closing ``` on its own line ends the block.
///   - A line starting with `SUMMARY:` (case-insensitive) — the rest
///     of that line becomes the summary string (trimmed, capped at
///     120 chars per the WorkerOutcome contract).
///   - A line starting with `TESTS:` (case-insensitive) — parsed as
///     `added=N total=N passing=N failing=N skipped=N` (any order,
///     missing keys default to 0). Phase-3-late: workers that don't
///     report tests yet leave this block out and tests = ZERO.
pub fn parse_completion_text(text: &str) -> ParsedCompletion {
    ParsedCompletion {
        patch: extract_diff_block(text),
        summary: extract_summary_line(text),
        tests: extract_tests_line(text),
    }
}

/// What `parse_completion_text` returns. Public so the dispatcher
/// can serialise it for the activity feed when needed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedCompletion {
    pub patch: String,
    pub summary: String,
    pub tests: TestSummary,
}

fn extract_diff_block(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let Some(open_at) = lower.find("```diff") else {
        return String::new();
    };
    // Skip the fence + the rest of the opening line.
    let after_fence = &text[open_at + "```diff".len()..];
    let body_start = after_fence
        .find('\n')
        .map(|n| n + 1)
        .unwrap_or(after_fence.len());
    let body_view = &after_fence[body_start..];
    let close = body_view.find("\n```").unwrap_or(body_view.len());
    body_view[..close].trim_end_matches('\n').to_string()
}

fn extract_summary_line(text: &str) -> String {
    for line in text.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed
            .strip_prefix("SUMMARY:")
            .or_else(|| trimmed.strip_prefix("Summary:"))
            .or_else(|| trimmed.strip_prefix("summary:"))
        {
            let summary = rest.trim();
            return summary.chars().take(120).collect();
        }
    }
    String::new()
}

fn extract_tests_line(text: &str) -> TestSummary {
    for line in text.lines() {
        let trimmed = line.trim_start();
        let rest = match trimmed
            .strip_prefix("TESTS:")
            .or_else(|| trimmed.strip_prefix("Tests:"))
            .or_else(|| trimmed.strip_prefix("tests:"))
        {
            Some(r) => r,
            None => continue,
        };
        let mut s = TestSummary::ZERO;
        for kv in rest.split_whitespace() {
            if let Some((k, v)) = kv.split_once('=') {
                if let Ok(n) = v.parse::<u32>() {
                    match k {
                        "added" => s.added = n,
                        "total" => s.total = n,
                        "passing" => s.passing = n,
                        "failing" => s.failing = n,
                        "skipped" => s.skipped = n,
                        _ => {}
                    }
                }
            }
        }
        return s;
    }
    TestSummary::ZERO
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coding::types::{Hemisphere, KanbanSessionId, KanbanTaskId, TaskStatus};

    fn sample_task() -> KanbanTask {
        KanbanTask {
            task_id: KanbanTaskId(42),
            session_id: KanbanSessionId(7),
            status: TaskStatus::Todo,
            title: "Add dark-mode toggle".into(),
            description: Some("UI-only — wire to existing settings store.".into()),
            task_type: "ui".into(),
            hemisphere: Hemisphere::Left,
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

    #[test]
    fn build_prompt_includes_task_title_and_description() {
        let p = build_task_prompt(&sample_task(), None);
        assert!(p.contains("Add dark-mode toggle"));
        assert!(p.contains("UI-only"));
        assert!(p.contains("Type: ui"));
        assert!(p.contains("Hemisphere: left"));
    }

    #[test]
    fn build_prompt_role_hint_matches_hemisphere() {
        // Left = fast/focused; Right = senior/design.
        let mut t = sample_task();
        let l = build_task_prompt(&t, None);
        assert!(l.contains("fast, focused"), "left role hint missing");

        t.hemisphere = Hemisphere::Right;
        let r = build_task_prompt(&t, None);
        assert!(r.contains("senior engineer"), "right role hint missing");

        t.hemisphere = Hemisphere::Cerebellum;
        let c = build_task_prompt(&t, None);
        assert!(c.contains("orchestrator"), "cerebellum role hint missing");
    }

    #[test]
    fn parse_extracts_diff_block_when_present() {
        let raw = "Here you go:\n\n\
            ```diff\n\
            --- a/x\n\
            +++ b/x\n\
            @@ -1,1 +1,1 @@\n\
            -old line\n\
            +new line\n\
            ```\n\
            SUMMARY: replaced one line\n";
        let parsed = parse_completion_text(raw);
        assert!(parsed.patch.contains("--- a/x"));
        assert!(parsed.patch.contains("+new line"));
        assert!(!parsed.patch.contains("```"), "fences must be stripped");
        assert_eq!(parsed.summary, "replaced one line");
    }

    #[test]
    fn parse_empty_patch_when_no_diff_block() {
        let raw = "I didn't need to change anything.\n\
                   SUMMARY: no change required — already correct\n";
        let parsed = parse_completion_text(raw);
        assert!(parsed.patch.is_empty());
        assert!(parsed.summary.contains("no change required"));
    }

    #[test]
    fn parse_diff_block_case_insensitive_open_fence() {
        let raw = "```DIFF\n--- a/y\n+++ b/y\n+ok\n```\n";
        let parsed = parse_completion_text(raw);
        assert!(parsed.patch.contains("--- a/y"));
    }

    #[test]
    fn parse_summary_truncates_to_120_chars() {
        // Pin the 120-char cap from WorkerOutcome.summary contract.
        let long = "x".repeat(300);
        let raw = format!("SUMMARY: {long}\n");
        let parsed = parse_completion_text(&raw);
        assert_eq!(parsed.summary.len(), 120);
        assert!(parsed.summary.chars().all(|c| c == 'x'));
    }

    #[test]
    fn parse_tests_line_pulls_added_total_passing_failing_skipped() {
        let raw = "```diff\n+x\n```\n\
                   TESTS: added=3 total=5 passing=4 failing=1 skipped=0\n\
                   SUMMARY: changed one file";
        let parsed = parse_completion_text(raw);
        assert_eq!(parsed.tests.added, 3);
        assert_eq!(parsed.tests.total, 5);
        assert_eq!(parsed.tests.passing, 4);
        assert_eq!(parsed.tests.failing, 1);
        assert_eq!(parsed.tests.skipped, 0);
    }

    #[test]
    fn parse_tests_line_missing_keys_default_to_zero() {
        // Worker that only reports the count of tests added without
        // running them. ZERO defaults keep the WorkerOutcome
        // `all_green()` check honest — no tests in summary == not
        // auto-promotable.
        let raw = "TESTS: added=2\n";
        let parsed = parse_completion_text(raw);
        assert_eq!(parsed.tests.added, 2);
        assert_eq!(parsed.tests.total, 0);
        assert_eq!(parsed.tests.passing, 0);
    }

    #[test]
    fn parse_tests_line_absent_returns_zero_summary() {
        let raw = "```diff\n+x\n```\nSUMMARY: no tests\n";
        let parsed = parse_completion_text(raw);
        assert_eq!(parsed.tests, TestSummary::ZERO);
    }

    #[test]
    fn patch_path_for_uses_session_and_task_ids() {
        let t = sample_task();
        let p = patch_path_for(std::path::Path::new("/tmp/neoth"), &t);
        let s = p.to_string_lossy();
        assert!(s.contains("coding-sessions"));
        assert!(s.contains("/7/") || s.contains("\\7\\"));
        assert!(s.ends_with("task-42.patch"));
    }

    #[test]
    fn parse_no_diff_block_lower_or_upper_case_fence() {
        // Defensive: the diff fence must match `diff` token, NOT
        // `differential` or anything that just starts with `diff`.
        // Today's lazy `.find("```diff")` accepts both — the closing
        // fence stops the body. Pin behaviour.
        let raw = "```diff\n+ok\n```\n";
        assert!(!parse_completion_text(raw).patch.is_empty());

        let raw2 = "```rust\nfn x() {}\n```\n";
        assert!(parse_completion_text(raw2).patch.is_empty());
    }

    // ── GOLD-WIRE-01: two-stage tool routing ────────────────────────────

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use crate::providers::Completion;

    /// Provider that counts `complete` calls + returns a scripted reply
    /// per call (last reply repeats once the script runs out).
    struct CountingProvider {
        calls: AtomicUsize,
        replies: Vec<String>,
    }

    impl CountingProvider {
        fn new(replies: &[&str]) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                replies: replies.iter().map(|s| s.to_string()).collect(),
            }
        }
        fn count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl Provider for CountingProvider {
        fn name(&self) -> &'static str {
            "counting"
        }
        async fn complete(&self, _req: Request) -> Result<Completion> {
            let i = self.calls.fetch_add(1, Ordering::SeqCst);
            let text = self
                .replies
                .get(i)
                .or_else(|| self.replies.last())
                .cloned()
                .unwrap_or_default();
            Ok(Completion {
                text,
                model: "test".into(),
                latency: Duration::from_millis(1),
                input_tokens: Some(0),
                output_tokens: Some(0),
            })
        }
    }

    fn worker_with(model: &str, provider: Arc<CountingProvider>) -> ProviderWorker {
        ProviderWorker::new("test/counting", provider, model, std::env::temp_dir())
    }

    #[tokio::test]
    async fn two_stage_model_fires_selector_then_task() {
        // deepseek-coder = 16 384 ctx → TwoStage. Stage-1 selector reply
        // "write" + Stage-2 task reply → exactly TWO complete calls.
        let provider = Arc::new(CountingProvider::new(&[
            "write",
            "```diff\n+x\n```\nSUMMARY: done",
        ]));
        let worker = worker_with("deepseek-coder", provider.clone());
        let out = worker.execute(&sample_task()).await.unwrap();
        assert_eq!(provider.count(), 2, "TwoStage must fire selector + task");
        assert_eq!(out.summary, "done");
    }

    #[tokio::test]
    async fn direct_model_skips_selector() {
        // Unknown model → unknown_default (32 768 ctx) → Direct → ONE call.
        let provider = Arc::new(CountingProvider::new(&["```diff\n+x\n```\nSUMMARY: done"]));
        let worker = worker_with("", provider.clone());
        let _ = worker.execute(&sample_task()).await.unwrap();
        assert_eq!(provider.count(), 1, "Direct must skip the selector call");
    }

    #[tokio::test]
    async fn unknown_category_reply_falls_back_to_direct_task() {
        // TwoStage model but Stage-1 returns garbage → still completes the
        // task (selector + task = 2 calls); no category hint is injected.
        let provider = Arc::new(CountingProvider::new(&[
            "bananas",
            "SUMMARY: no change required — nothing to do",
        ]));
        let worker = worker_with("deepseek-coder", provider.clone());
        let out = worker.execute(&sample_task()).await.unwrap();
        assert_eq!(provider.count(), 2);
        assert!(out.summary.contains("no change required"));
    }

    #[test]
    fn build_task_prompt_injects_category_hint_when_present() {
        let t = sample_task();
        let primed = build_task_prompt(&t, Some(ToolCategory::Write));
        assert!(primed.contains("write"), "category name missing");
        assert!(primed.contains("patch"), "member-hint vocabulary missing");
        assert!(!build_task_prompt(&t, None).contains("Likely tool category"));
    }

    #[test]
    fn parse_category_reply_handles_clean_firstword_and_unknown() {
        assert_eq!(parse_category_reply("write"), Some(ToolCategory::Write));
        assert_eq!(parse_category_reply("  READ \n"), Some(ToolCategory::Read));
        assert_eq!(
            parse_category_reply("search the codebase"),
            Some(ToolCategory::Search)
        );
        assert_eq!(parse_category_reply("bananas"), None);
        assert_eq!(parse_category_reply(""), None);
    }
}
