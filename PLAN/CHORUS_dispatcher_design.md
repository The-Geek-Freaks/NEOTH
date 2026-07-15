# Chorus design artifact — Pick #6 Worker Dispatcher

**Date:** 2026-05-20
**Status:** DRAFT — awaiting Chorus gremium verdict before implementation
**Predecessor:** `PLAN/CHORUS_decomposer_design.md` (Pick #4 artifact, shipped Session 17)
**Scope reference:** `PLAN/SPEC_coding_workflow.md` §"Open questions" items 2, 3, 4

---

## 1. Context — why the dispatcher is the missing link

After Pick #4 + Pick #5 shipped, `neoth code "..."` runs end-to-end up
to **task creation**: Cerebellum decomposes the prompt, the heuristic
classifier sorts tasks into Left/Right/Ambiguous, rows land in
`idx_kanban_task` with status `BACKLOG`. Then they sit.

The dispatcher is what closes the loop: it picks BACKLOG tasks, calls
the bound provider (Left = fast / Right = deep), captures the patch +
test outcome, transitions through IN_PROGRESS → REVIEW, and lets
Pick #10's auto-promote flow drop a green task into DONE.

Without it, the operator must `neoth kanban move <id> <status>` by
hand for every task. With it, `neoth code "..."` is the operator's
single command for a multi-task work session.

## 2. Architecture sketch (skeleton — not yet shipped)

```rust
// SRC/neothd/src/coding/worker.rs  (new file)

/// One worker run against a single kanban task. Each hemisphere has
/// its own concrete impl (Left → LocalQwenWorker / Right → ClaudeCli
/// or OpenaiCompatWorker / Cerebellum → orchestrator-only, no exec).
pub trait Worker: Send + Sync {
    fn execute(&self, task: &KanbanTask) -> impl Future<Output = Result<WorkerOutcome>> + Send;
}

/// What a worker reports back. Patch bytes + test summary land in
/// `idx_kanban_task` via store::patch_task_result. Tests-summary all-
/// green + non-empty patch → REVIEW status; tests failing → BLOCKED.
pub struct WorkerOutcome {
    pub patch_text: String,
    pub patch_path: PathBuf,            // where the patch was saved
    pub tests_added: u32,
    pub tests_passing: u32,
    pub tests_failing: u32,
    pub tests_skipped: u32,
    pub summary: String,                // one-line operator-facing note
}

// SRC/neothd/src/coding/dispatcher.rs  (new file)

/// Drives the dispatch loop. Per session: scan BACKLOG tasks, pick
/// the next one whose hemisphere has capacity, transition to
/// IN_PROGRESS, fire the worker, write the outcome, transition to
/// REVIEW (or BLOCKED on failure). Loop until the session is empty
/// or the operator cancels.
pub async fn dispatch_session(
    conn: &Connection,
    session_id: KanbanSessionId,
    workers: &HemisphereWorkerSet,  // Left + Right + Cerebellum bindings
    writer: &WalWriterHandle,
) -> Result<DispatchOutcome>;
```

## 3. Open architecture questions (Chorus-worthy)

### Q1 — Patch safety: direct apply vs git worktree vs stash+revert?

**SPEC reference:** §Open questions item 2.

**Options:**

- **(A) Direct apply** to the operator's working tree. Hermes does
  this. Fastest, but a bad patch contaminates the operator's repo
  state immediately — recovery means `git restore .` or similar.
- **(B) Git worktree branch** per dispatch session. `git worktree add
  ../neoth-session-<id>` + apply there + run tests + only after green
  REVIEW does the operator pull the branch back. Cleanest audit; +
  expensive (~50-500 MiB per worktree depending on repo size).
- **(C) Stash + apply + revert-on-fail** in the operator's working
  tree. Stash current changes, apply patch, run tests, on failure
  `git stash pop`. Cheaper than (B), but races against operator
  edits during dispatch + breaks if the operator has uncommitted
  conflicts.

**Recommendation pre-Chorus:** (B) worktree by default, (A) direct
behind explicit `freedom.yaml::coding.patch_apply_mode: direct` opt-in
for operators who know what they're doing. Reasoning: NEOTH's audit
model and policy.yaml strict-mode argue for isolation; (B) gives
operator-in-loop pull moment.

### Q2 — Streaming worker output: live to WAL or batched on completion?

**SPEC reference:** §Open questions item 4.

**Options:**

- **(A) Live stream** — emit one `EVENT_TYPE_KANBAN_TASK_PROGRESS`
  frame per ~500ms of worker output. Operator can `kanban watch` in
  another shell and see real-time progress. Audit chain grows ~10x
  per task.
- **(B) Batched** — only emit `EVENT_TYPE_KANBAN_TASK_COMPLETED` when
  the worker returns. Single frame per task. Operator has no live
  visibility during the worker run.
- **(C) Heartbeat** — emit one progress frame every 30s with current
  byte count; final completion frame at end. Trade-off middle ground.

**Recommendation pre-Chorus:** (C) heartbeat at 30s. Operator sees
"still working" signal in `neoth kanban watch` without the audit
chain bloating proportional to output size. Reserves a new event
code `EVENT_TYPE_KANBAN_TASK_PROGRESS = 0x77` (currently free in the
0x70-0x7F coding band).

### Q3 — REVIEW gating: operator-in-loop or Right-hemisphere auto-promote?

**SPEC reference:** §Open questions item 3.

**Options:**

- **(A) Always operator-in-loop** — every REVIEW task requires
  `neoth kanban review <id> --promote` or the GUI button before it
  moves to DONE. Pick #10 already implements this auto-promote check
  path; here we'd just NOT auto-fire it from the dispatcher.
- **(B) Right-hemisphere self-approve** — the Right worker reviews
  Left's output, posts a comment, and if green calls
  `auto_promote_session` itself. Hermes does this between SmallCode
  and Claude. NEOTH's stricter audit model probably wants operator
  trust signal first.
- **(C) Per-autonomy-level gate** — autonomy `strict` / `standard` →
  (A) operator-in-loop. Autonomy `elevated` / `full` → (B) Right
  self-approves with `EVENT_TYPE_KANBAN_AUTO_PROMOTED` audit. Matches
  NEOTH's 5-level autonomy ladder.

**Recommendation pre-Chorus:** (C) autonomy-bound. Re-uses the
existing `permissions::evaluate(action, &policy_snapshot)` gate from R-23;
operator's choice on first-launch wizard step 5c determines REVIEW
behaviour. Lowest-friction for trusting operators, safest for new
ones.

### Q4 — Cycle prevention: what stops the dispatcher from looping forever?

**SPEC reference:** implicit — not explicitly listed but architectural.

**Options:**

- **(A) Time budget** per session. Default 30 min. After budget,
  remaining BACKLOG tasks transition to BLOCKED with reason "session
  budget exhausted".
- **(B) Task-count budget**. Default 20 tasks per session. Hard cap
  on how many tasks can run regardless of time.
- **(C) Both** — whichever hits first. Conservative.

**Recommendation pre-Chorus:** (C). Two indpendent escape hatches
match NEOTH's defense-in-depth pattern (fuel cap + memory cap on
plugins; rate limit + timeout on webhooks).

## 4. Test plan (sketch)

- Unit: `Worker` trait mock + `dispatch_session` runs single task
  end-to-end against fake worker, asserts status transitions.
- Unit: time budget exceeds → BLOCKED with correct reason.
- Unit: task-count budget exceeds → BLOCKED.
- Unit: worker error → BLOCKED, no IN_PROGRESS → REVIEW leak.
- Unit: cycle (worker returns "subtask spawned") → max-depth cap.
- Integration (feature-gated): real LocalQwenWorker against
  `examples/coding/sample-decomposed-task.json` → patch applies
  cleanly to `examples/coding/sample-repo/`.
- Property test: dispatch loop is reentrant (calling twice on same
  session is a no-op).

## 5. Implementation order after Chorus verdict

1. Define `Worker` trait + `WorkerOutcome` struct (~50 LOC, types only)
2. `HemisphereWorkerSet` builder that maps hemisphere → bound provider
3. `dispatch_session()` orchestrator (~200 LOC)
4. `LeftWorker` / `RightWorker` concrete impls (~150 LOC each)
5. WAL event codes for progress + auto-promoted frames
6. `neoth code` CLI invokes `dispatch_session` after decomposition
7. Test suite: unit + integration + property
8. GUI integration: live tail picks up dispatcher frames automatically
   (no GUI changes needed thanks to Pick #8 Step 4)

Total estimated LOC: ~600-800 across new files + small touches to
`cli/code.rs` + `coding/mod.rs`.

## 6. What the dispatcher does NOT do (out-of-scope for Pick #6)

- LLM second-opinion classification on Ambiguous tasks (that's Pick #9,
  depends on this picking up Cerebellum-routed tasks first).
- Multi-session orchestration. One dispatcher run handles one session.
- Cross-session worker pool sharing. Each session opens fresh workers.
- Operator-facing approval UI for individual patches. Pick #8's
  detail-pane already shows status; explicit per-patch approve/reject
  buttons land in v0.2 with the comment + assign callbacks.

---

**Next action:** fire Chorus 2-reviewer review with this artifact as
`work`, verdicts on Q1-Q4, then implement per recommendation.
