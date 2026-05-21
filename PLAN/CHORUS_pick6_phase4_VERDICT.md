# Pick #6 Phase 4 — Q1 patch-apply Chorus verdict (2026-05-21)

Chat ID: `019E49EAC4EACB805644D020B8F74A03`
Template: `codex-gemini-review`
Reviewers: codex-cli, gemini-cli

## Consensus

**Strategy B — git worktree per task.** Both reviewers picked B
unanimously. A is too risky (mutates operator checkout, parallel
race). C is operationally brittle (global stash state, hard
under concurrency, `-u` interacts badly with `.gitignore`).

B's disk-overhead cost (~500 MB × 10 tasks = 5 GB) is acceptable
for the safety + isolation + parallel-safety guarantees.

## Verdict per question

| Q | Codex | Gemini | NEOTH adopts |
|---|-------|--------|--------------|
| Q1 strategy | B | B | **B (worktree)** |
| Q1a confirm at Elevated+Full | YES | only at Elevated (for merge-back) | **YES at both** (conservative for v0.2) |
| Q1b refuse on dirty | YES (worktree dirty) | YES (on merge-back) | **YES on the task worktree before apply** |
| Q1c stash -u | NO | NO | **No stash at all — refuse dirty instead** |
| Q1d retry count | 1 then Blocked | 3 via WorkerRetryPolicy | **1 then Blocked** for v0.2 (raise to 3 in v0.3 once failure taxonomy proven) |

Conservative choice on Q1a + Q1d because v0.2 is the operator's
first taste of autonomous code-apply; better surface-area
tightness up front, relax later.

## Required design changes (Codex)

Implemented in Phase 4 commit:

- [ ] B is the primary + only v0.2 apply strategy
- [ ] Apply patches only inside task-scoped worktrees
  (`<repo_parent>/.neoth-task-<task_id>/`)
- [ ] Refuse if the task worktree is dirty before apply
- [ ] Require explicit confirm for Elevated + Full autonomy
- [ ] Do NOT touch operator stash, ever
- [ ] Cap test repair at 1 retry, then Blocked with diagnostics
- [ ] WAL frame records: worktree path, base commit, patch
      hash, apply result, test result

## Implementation order

1. **`coding::worktree`** module — pure helpers (path computation,
   dirty check via `git status --porcelain`) + side-effect helpers
   (`create_task_worktree`, `apply_patch_in_worktree`, `cleanup_worktree`).
2. **WAL event reservation** — `0xD3 PATCH_APPLIED` (and maybe
   `0xD4 PATCH_APPLY_FAILED`) in the config-lifecycle band.
3. **`dispatcher`** integration — `dispatch_session` calls
   `worktree::apply_patch_in_worktree` after the worker returns
   a non-empty patch + runs the test command + transitions on
   the outcome.
4. **Permission gate** — `permissions::evaluate(action: WriteToRepo, ...)`
   variant for the autonomy guard.
5. **CLI surface** — `neoth code "..."` already runs the
   dispatcher; the Phase 4 patch-apply happens inside the
   existing flow without operator action. Add
   `neoth code --no-apply` for operators who want the Phase 3
   "patch-stored-only" behaviour.

Phase 4 follow-ups (v0.3):
- Raise retry count to 3 via WorkerRetryPolicy
- Worktree merge-back to operator's checkout (today the operator
  manually `git cherry-pick`s)
- Multi-task DAG worktree coordination
