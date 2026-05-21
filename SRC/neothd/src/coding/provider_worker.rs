//! Pick #6 Phase 3 — concrete provider-backed Worker.
//!
//! `ProviderWorker` wraps any `providers::Provider` (claude_cli,
//! openai_api, openai_compat, gemini_api, local_qwen, hermes,
//! openclaw) into a synchronous `Worker` impl that the dispatcher
//! calls one task at a time. The provider is async; we hold a
//! `tokio::runtime::Handle` and `block_on` inside execute so the
//! sync `Worker` trait stays.
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
use tokio::runtime::Handle;

use crate::coding::types::{KanbanTask, TestSummary};
use crate::coding::worker::{Worker, WorkerOutcome};
use crate::providers::{Provider, Request};

/// Provider-backed worker. One instance per (hemisphere, provider)
/// binding; held by `HemisphereWorkerSet`.
pub struct ProviderWorker {
    name: &'static str,
    provider: Arc<dyn Provider>,
    /// Where task patches land. `<wal_dir>/coding-sessions/<session-id>/
    /// task-<task-id>.patch`. The dispatcher provides the parent dir;
    /// this struct only knows the operator's home root.
    patch_root: PathBuf,
    /// Tokio runtime the sync execute() blocks on. The daemon
    /// already runs inside #[tokio::main]; tests construct a
    /// `Runtime::new().handle().clone()` per test.
    runtime: Handle,
}

impl ProviderWorker {
    /// Build a worker. `name` is operator-readable and surfaces in
    /// the WAL + activity feed; pin it to a stable string per
    /// hemisphere ("left/local_qwen", "right/claude_cli") so audit
    /// chain readability survives renames.
    pub fn new(
        name: &'static str,
        provider: Arc<dyn Provider>,
        patch_root: impl Into<PathBuf>,
        runtime: Handle,
    ) -> Self {
        Self {
            name,
            provider,
            patch_root: patch_root.into(),
            runtime,
        }
    }
}

impl Worker for ProviderWorker {
    fn execute(&self, task: &KanbanTask) -> Result<WorkerOutcome> {
        let prompt = build_task_prompt(task);
        let req = Request {
            prompt,
            ..Default::default()
        };
        let completion = self
            .runtime
            .block_on(self.provider.complete(req))
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
fn build_task_prompt(task: &KanbanTask) -> String {
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
    out.push_str("\nIf the task does not require a code change, omit the diff block \
                  and write `SUMMARY: no change required — <reason>` on its own line.\n");
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
        let p = build_task_prompt(&sample_task());
        assert!(p.contains("Add dark-mode toggle"));
        assert!(p.contains("UI-only"));
        assert!(p.contains("Type: ui"));
        assert!(p.contains("Hemisphere: left"));
    }

    #[test]
    fn build_prompt_role_hint_matches_hemisphere() {
        // Left = fast/focused; Right = senior/design.
        let mut t = sample_task();
        let l = build_task_prompt(&t);
        assert!(l.contains("fast, focused"), "left role hint missing");

        t.hemisphere = Hemisphere::Right;
        let r = build_task_prompt(&t);
        assert!(r.contains("senior engineer"), "right role hint missing");

        t.hemisphere = Hemisphere::Cerebellum;
        let c = build_task_prompt(&t);
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
}
