# Smallcode Integration Plan — 2026-05-21

## §Target

Port smallcode's **per-file failure taxonomy + adaptive decompose strategy** (`pickDecomposeStrategy`) into `coding::dispatcher` as a `WorkerRetryPolicy` that converts a raw `Err` or `failed()` outcome into one of three typed recovery actions before transitioning to `Blocked`.

---

## §Why This One

The dispatcher's current `worker.execute` error path is a single-statement `Blocked` transition — every failure mode (transient provider timeout, corrupted patch, multi-error file, oversized diff) lands identically in `Blocked` with no corrective signal. Smallcode's governor solves exactly this problem for small LLMs: it reads the error shape, classifies it into one of three strategies (split-file / one-error-at-a-time / rewrite-section), and injects a corrective prompt injection before the next attempt. The pattern translates directly to NEOTH because NEOTH's Left worker *is* a small local LLM (Qwen 7B-20B), which exhibits the same failure modes smallcode was designed for. Porting this is a 1:1 match between the pain point and the solution, with no architectural mismatch.

---

## §Smallcode Source

| File | Lines | What to port |
|------|-------|--------------|
| `QUELLEN/smallcode/src/governor/early_stop.js` | 1-137 | `recordPatchResult` failure counter + no-op detection; `checkRepetition` tail-scan loop |
| `QUELLEN/smallcode/bin/governor.js` | 130-226 | `checkAndEnforceHardFail` attempt history + `pickDecomposeStrategy` (split_file / one_error_at_a_time / rewrite_section) |

Key line references:
- `governor.js:155-177` — retry vs. decompose branch on `MAX_VERIFICATION_RETRIES`
- `governor.js:181-226` — `pickDecomposeStrategy` with three strategy arms keyed on line count + error count
- `early_stop.js:61-98` — `recordPatchResult` no-op detection (`oldStr === newStr` → failure) + attempt ceiling

---

## §NEOTH Integration

**Primary site**: `SRC/neothd/src/coding/dispatcher.rs` — `apply_outcome()` (line 238) and the `Err(e)` arm of the `exec_result` match (line 188).

**New module**: `SRC/neothd/src/coding/retry_policy.rs`

`apply_outcome` currently makes a binary `review_ready()` → `Review | Blocked` decision. The change introduces a `WorkerRetryPolicy` consulted *before* `apply_outcome` fires, which classifies the failure and either re-queues the task with an injected correction hint or lets it fall through to `Blocked` if the per-task attempt budget is exhausted.

---

## §Algorithm Sketch

```rust
// coding/retry_policy.rs

pub const MAX_TASK_ATTEMPTS: u32 = 3;

#[derive(Debug, Clone)]
pub enum RecoveryAction {
    /// Re-enqueue with a corrective context injection appended to the
    /// task description.  Dispatcher moves task back to Backlog.
    Requeue { hint: String },
    /// Attempt budget exhausted — let dispatcher transition to Blocked.
    Blocked { reason: String },
}

#[derive(Debug, Default)]
pub struct WorkerRetryPolicy {
    /// task_id → attempt count
    attempts: HashMap<KanbanTaskId, u32>,
}

impl WorkerRetryPolicy {
    pub fn evaluate(
        &mut self,
        task: &KanbanTask,
        outcome: &WorkerOutcome,
        worker_err: Option<&anyhow::Error>,
    ) -> RecoveryAction {
        let count = self.attempts.entry(task.task_id).or_insert(0);
        *count += 1;

        if *count >= MAX_TASK_ATTEMPTS {
            return RecoveryAction::Blocked {
                reason: format!("task {} exhausted {MAX_TASK_ATTEMPTS} attempts", task.task_id.raw()),
            };
        }

        let hint = pick_strategy(task, outcome, worker_err);
        RecoveryAction::Requeue { hint }
    }
}

fn pick_strategy(
    task: &KanbanTask,
    outcome: &WorkerOutcome,
    worker_err: Option<&anyhow::Error>,
) -> String {
    let err_text = worker_err.map(|e| e.to_string()).unwrap_or_default();
    let patch_lines = outcome.patch_text.lines().count();

    // Mirror smallcode governor.js:181 — large patch = worker overreached
    if patch_lines > 80 || outcome.patch_text.is_empty() && err_text.contains("context") {
        return format!(
            "[NEOTH-RETRY] The previous attempt produced a patch that was too large \
             or empty. Split the work: pick the SMALLEST change that makes progress \
             on task '{}'. One function or one type at a time.",
            task.title
        );
    }

    // Multiple distinct errors reported in the summary
    let error_count = outcome.summary.matches("error").count()
        + outcome.summary.matches("failed").count();
    if error_count > 1 {
        return format!(
            "[NEOTH-RETRY] Multiple errors detected. Fix ONE error only. \
             Ignore everything else. Task: '{}'.",
            task.title
        );
    }

    // Single persistent error — force rewrite-section strategy
    format!(
        "[NEOTH-RETRY] Previous approach failed for task '{}'. \
         Start from scratch with a simpler implementation. \
         Error hint: {}",
        task.title,
        err_text.chars().take(200).collect::<String>()
    )
}
```

In `dispatcher.rs`, the `exec_result` match becomes:

```rust
Err(e) => {
    match retry_policy.evaluate(&task, &WorkerOutcome::empty(), Some(&e)) {
        RecoveryAction::Requeue { hint } => {
            store::append_task_description(conn, task.task_id, &hint)?;
            store::patch_task_status(conn, task.task_id, TaskStatus::Backlog, now_unix_ns())?;
        }
        RecoveryAction::Blocked { reason } => {
            warn!(task_id = task.task_id.raw(), %reason, "retry budget exhausted");
            outcome.tasks_blocked += 1;
            store::patch_task_status(conn, task.task_id, TaskStatus::Blocked, now_unix_ns())?;
        }
    }
}
```

---

## §Test Plan

```
retry_policy_first_failure_requeues()
  — attempt 1 on an empty-patch outcome → RecoveryAction::Requeue

retry_policy_exhaustion_blocks()
  — attempt MAX_TASK_ATTEMPTS on same task_id → RecoveryAction::Blocked

pick_strategy_large_patch_returns_split_hint()
  — patch_text with 100 lines → hint contains "SMALLEST change"

pick_strategy_multi_error_returns_one_error_hint()
  — summary with "error: X, error: Y" → hint contains "ONE error only"

pick_strategy_single_error_returns_rewrite_hint()
  — summary with one error → hint contains "Start from scratch"

dispatcher_requeues_task_on_worker_error()
  — integration: CannedWorker returns Err, task status is Backlog after dispatch,
    task description contains the injected hint

dispatcher_blocks_after_max_attempts()
  — integration: CannedWorker always errors, run dispatch 3x, task ends in Blocked
```

---

## §Risk

**Risk 1 — Infinite requeue loop.** Mitigated: `MAX_TASK_ATTEMPTS` is a hard ceiling enforced per `task_id` in `WorkerRetryPolicy.attempts`. Once exhausted, the task goes to `Blocked` regardless of error type.

**Risk 2 — `append_task_description` does not exist yet in `store.rs`.** The store currently has `patch_task_status` and `attach_task_artifact`. A new `append_task_description(conn, task_id, hint)` SQL UPDATE is needed — ~10 LOC. Low-risk addition.

**Risk 3 — Hint injection inflates context for small LLMs.** Cap hint at 400 chars in `pick_strategy` to stay within 8k-context Left hemisphere workers. Already sketched as `.chars().take(200)` above — raise to 400 in the full impl.

---

## §Effort

- `coding/retry_policy.rs` (new file): ~120 LOC + 60 LOC tests = 180 LOC
- `coding/dispatcher.rs` patch (match arm rewrite + `WorkerRetryPolicy` injection): ~25 LOC
- `coding/store.rs` (`append_task_description`): ~15 LOC
- Total: ~220 LOC
- Rust-experience hours: **3-4 h** (all pure logic, no async, no new dependencies)
