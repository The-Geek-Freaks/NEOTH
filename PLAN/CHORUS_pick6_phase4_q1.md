# Pick #6 Phase 4 — Q1 patch-apply safety design (2026-05-21)

## Context

NEOTH ships the coding workflow (Picks #1-3 + #5-10). Pick #6
Phase 1-3 are live: `Worker` trait, `HemisphereWorkerSet`,
`DispatchBudget`, `dispatch_session()` orchestrator,
`ProviderWorker` (wraps any `providers::Provider` into a sync
Worker), `WorkerRetryPolicy` (smallcode-ported failure
classifier with strategy-hint re-queue), `coding::validate`
(patch-shape sanity gate before promotion).

Today the worker writes the patch to
`<wal_dir>/coding-sessions/<sid>/task-<tid>.patch` and **does
NOT apply it**. Operators inspect via `neoth kanban task <id>`
and manually run `git apply` if they accept the change.

Phase 4 closes this gap: the dispatcher applies the patch
automatically (gated by autonomy level + operator confirm) so
the kanban → green-test → done flow lands working code, not
just artefact files.

## Q1 — Patch-apply strategy

Three plausible strategies. Each has security + UX + recovery
tradeoffs.

### Strategy A: direct `git apply` in the operator's repo

```rust
fn apply(patch_path: &Path, repo_root: &Path) -> Result<()> {
    std::process::Command::new("git")
        .arg("apply")
        .arg("--check")        // dry-run first
        .arg(patch_path)
        .current_dir(repo_root)
        .status()?;
    std::process::Command::new("git")
        .arg("apply")
        .arg(patch_path)
        .current_dir(repo_root)
        .status()?;
    Ok(())
}
```

Pros: simplest. Operator sees the change in their working tree
immediately, can review with `git diff` + commit when happy.

Cons:
- Pollutes uncommitted operator changes (a worker patch landing
  during an in-progress edit creates a mess).
- No automatic rollback if tests fail post-apply.
- Race condition: two parallel dispatcher workers can fight
  for the index.

### Strategy B: git worktree per task

```rust
fn apply(patch_path: &Path, repo_root: &Path, task_id: u64) -> Result<PathBuf> {
    let worktree = repo_root.parent().unwrap().join(format!(".neoth-task-{task_id}"));
    git("worktree", &["add", worktree.to_str().unwrap(), "HEAD"])?;
    git_in(&worktree, "apply", &[patch_path.to_str().unwrap()])?;
    Ok(worktree)
}
```

Pros: each task lives in its own checkout. No collisions. Tests
run isolated. Cleanup = `git worktree remove`.

Cons:
- Disk overhead (full repo copy per task; for a 500 MB repo
  with 10 tasks = 5 GB).
- Operator can't see the changes in their main checkout
  until manual merge.
- Cross-task dependencies (Task 2 depends on Task 1's patch)
  need explicit coordination.

### Strategy C: stash + apply + revert-on-fail

```rust
fn apply(patch_path: &Path, repo_root: &Path) -> Result<StashId> {
    let stash = git_in(repo_root, "stash", &["push", "-u", "-m", "neoth-pre-apply"])?;
    if let Err(e) = git_in(repo_root, "apply", &[patch_path.to_str().unwrap()]) {
        git_in(repo_root, "stash", &["pop"])?;
        return Err(e);
    }
    Ok(stash)
}
```

Pros: protects uncommitted operator changes (stashed first),
deterministic recovery path (`stash pop` on test failure).

Cons:
- Operator's stash gets polluted with neoth-managed entries.
- Stash collisions if the operator runs concurrent `git stash`.
- `--include-untracked` interaction with `.gitignore` is
  surprising.

## Cross-cutting concerns

1. **Permission gate**: every apply MUST pass through
   `permissions::evaluate(action: WriteToRepo, level)`. Strict
   autonomy denies; Standard prompts; Elevated+Full apply
   without ask.
2. **Path safety**: the patch text MUST be validated against
   path traversal (`../` segments to escape `repo_root`). NEOTH
   already has `path_safety::ensure_within(root, target)`;
   re-use.
3. **Rollback anchor**: a `0xF2 PRE_MUTATION_SNAPSHOT` WAL
   frame MUST land before the apply so `neoth rollback` can
   restore. The existing `wal::snapshot::emit_snapshot` helper
   handles this.
4. **Test loop**: after apply, the worker runs
   `cargo check --message-format=json` (or the project's
   declared test command from `freedom.yaml::coding.test_cmd`)
   and feeds diagnostics back to a fix-loop, OR transitions to
   Blocked if tests fail.
5. **Cycle prevention**: dispatcher budget cap
   (`DispatchBudget::max_tasks`) already prevents runaway loops.

## Operator-facing surface

```
neoth code "add dark mode toggle to settings"
  → session 42 opens
  → decomposer produces 3 tasks
  → dispatcher picks task 1 → worker writes patch → applies →
    tests pass → promotes to DONE
  → dispatcher picks task 2 → worker writes patch → applies →
    tests FAIL → retry with strategy hint
  → retry fails → transitions to Blocked
  → operator runs `neoth kanban task 2` to inspect
  → operator runs `neoth rollback apply <event_id>` to restore
```

## Verdict requested

Which strategy is safest for the v0.2 ship target?

- **A** (direct apply) — fast iteration, risky if operator has
  uncommitted changes
- **B** (worktree) — most isolated, highest disk cost
- **C** (stash + revert) — middle ground, stash pollution risk

Plus the cross-cutting Qs:
- Q1a: Should the apply path require an explicit operator
  confirm even at Elevated+Full, OR only at Strict+Standard?
- Q1b: Should NEOTH refuse to apply when the operator's
  working tree is dirty (uncommitted changes)?
- Q1c: For Strategy C, should the stash include untracked
  files (`-u`)?
- Q1d: What's the right test-loop ceiling — 1 retry then
  Blocked, or 3 retries via WorkerRetryPolicy?
