# NEOTH v1.0 GOLD execution handoff for Claude Opus 5

**Created:** 2026-07-31  **Refreshed:** 2026-08-01
**Repository:** `C:\Users\Shadow-PC\CascadeProjects\AGENTER`
**Remote:** `https://github.com/The-Geek-Freaks/NEOTH.git`
**Branch:** `main`
**Pushed parent before the exact-egress checkpoint:**
`2c8e435e14bbd2c9830f39ae7026ec69780b27ac`

The pushed B10 catalog baseline is:

- `351dc6a6` — eliminate built-in routing collisions;
- `2c8e435e` — satisfy strict router lint without changing match semantics.

This file lands with the exact proactive-egress checkpoint. Do not trust a hash
written in prose as the current head: fetch, inspect and start from the newest
exact `origin/main`.

## 1. Mission and completion standard

The authoritative backlog is `PLAN/ROAD_TO_1_0_GOLD.md`. Everything in that
document is v1.0 scope. Do not silently defer work to 1.1, remove findings,
convert unfinished runtime work into prose-only completion or mark a task done
because a helper, module or isolated test exists.

A task is complete only when every applicable part is true:

1. The implementation exists and all failure paths are explicit.
2. Every intended production caller is wired.
3. Searches prove no stale bypass, duplicate implementation or dead partial
   remains.
4. Config, safe/default behavior, migrations, wizard/onboarding, Doctor/probe,
   CLI, GUI, Buddy, channels and release packaging are updated where relevant.
5. CLI/GUI/channel behavior is genuinely parity-safe.
6. Tests exercise the real boundary and a production-shaped path, including
   negative, recovery and adversarial cases.
7. Public docs, roadmap and progress state tell the truth.
8. Independent code review and, for trust boundaries, security review have no
   unresolved blocker.
9. The checkpoint is committed, pushed and verified with
   `HEAD == origin/main`.

The v1.0 product target remains zero-friction install and first run, complete
release artifacts, GUI included where supported, easy CLI/GUI switching, useful
Buddy behavior, provider/channel parity, clean migration, no hidden manual
prerequisite and no advertised partial or unwired feature.

## 2. Start every resumed session safely

Run before editing:

```powershell
Set-Location C:\Users\Shadow-PC\CascadeProjects\AGENTER
git status --short --branch
git fetch --prune origin
git rev-parse HEAD
git rev-parse origin/main
git rev-list --left-right --count HEAD...origin/main
git log -8 --oneline --decorate
git merge-base --is-ancestor 2c8e435e14bbd2c9830f39ae7026ec69780b27ac origin/main
```

Do not pull or rebase blindly over a dirty shared worktree. Inspect the
provenance of every changed file and integrate around concurrent work. Never use
`git reset --hard`, `git clean`, broad checkout/revert or `git add -A`.

Do not start a new slice unless the ancestry check succeeds and
`HEAD == origin/main`. If heads differ, inspect every foreign commit and dirty
file before changing or committing anything. Resume an unfinished shared slice
only after its ownership, callers and test state are understood.

These local items are unrelated to the exact-egress checkpoint. Do not stage,
delete, reformat or claim them:

- modified `.gitignore`;
- untracked `.kilo/`;
- untracked `SRC/_autoupdate.py`;
- untracked `SRC/_*.bat` helper scripts;
- untracked `SRC/.freedom-credentials.transaction.lock`;
- untracked `SRC/credentials.lock` and `SRC/freedom.yaml.lock`;
- untracked `SRC/neothd/unused/`.

The list can drift. Re-read `git status`; never assume it is exhaustive.

## 3. Required continuous delivery loop

For each bounded roadmap slice:

1. Re-read the exact ROAD entry and nearby corrections.
2. Perform a deep source/caller/data-flow analysis before editing.
3. Query an existing Graphify graph if present, but treat `INFERRED` edges as
   hypotheses and filter generated/legacy/upload/backup noise.
4. Search all definitions, callers, config fields, migrations, tests, GUI/CLI
   surfaces, channel consumers and release/docs references.
5. Assign one worker clear file ownership. Other agents are read-only
   explorers, reviewers or security auditors.
6. Implement the smallest coherent vertical slice. Do not land a foundation
   whose consumers are still unwired.
7. Run cheap focused checks while iterating.
8. Freeze source before expensive Cargo gates.
9. Run independent final code review; fix every blocker and re-review.
10. Update ROAD and PROGRESS additively. Preserve historical findings and mark
    stale statements `HISTORICAL — SUPERSEDED`.
11. Stage only an explicit file allowlist, inspect the cached diff, commit,
    push and prove exact remote equality.
12. Continue with the next open task. A checkpoint is not full v1.0 closure.

Use parallel agents only for independent work. Never let two workers own
overlapping files. Reviewers do not run Cargo while the worker is active.

## 4. Build and test strategy

### Inner loop

Use source search, targeted unit tests, `rustfmt --check`, source-contract
tests and `git diff --check`. Do not run full workspace Clippy or all platform
suites after every edit.

### Checkpoint gate

After source freeze:

- run strict Clippy for the changed crate/surface;
- run the exact affected unit and integration groups;
- run feature-specific checks only where the slice changed those features;
- run one Cargo process at a time with `CARGO_BUILD_JOBS=1`;
- retain exact pass counts and any environment limitation;
- do not call a skipped platform or physical external-delivery test green.

On this Windows host, use the repository MSVC environment:

```powershell
Set-Location C:\Users\Shadow-PC\CascadeProjects\AGENTER\SRC
& cmd.exe /d /s /c 'call "_msvc_env.bat" && set "CARGO_BUILD_JOBS=1" && cargo <command>'
```

The pushed workspace currently contains rustfmt drift in unrelated source
files. Do not sweep it into a feature commit. Use targeted
`rustfmt --edition 2024 --config skip_children=true --check <owned files>`
and record the workspace-wide drift separately.

### Release-candidate gate

Only after roadmap implementation freezes, run the complete workspace, feature
matrix, security, CodeQL, packaging, clean-machine installer and supported
platform/distro matrix. Release-candidate gates must execute against one exact
commit. A local Windows pass does not prove Linux, macOS, musl or installer
behavior.

## 5. Historical provider-boundary checkpoint

OpenAI-compatible and native Ollama response-envelope work landed on
2026-07-31. Detailed notes remain in git history and PROGRESS. Do not derive
current task ownership, current blocker counts or next work from that historical
snapshot. `PLAN/ROAD_TO_1_0_GOLD.md` is authoritative.

## 6. Current pushed B10 baseline and open resolver contract

The pushed catalog baseline contains 182 bundled skill manifests, 99 enabled by
default, zero normalized cross-owner collisions and no exception allowlist.
Every raw alias is checked. Literal routing is Unicode- and token-boundary-aware,
including punctuation triggers such as `fact-check`, `node.js`, `/ship` and
`max++`.

Focused B10 evidence before the exact-egress landing:

- bundled tests 22/22;
- router tests 53/53;
- targeted Rustfmt and `git diff --check` green;
- independent Rust review green.

This is a partial B10 delivery, not closure. The next owned slice is one shared,
authority-bound typed resolver returning `Match`, `NoMatch`, `Conflict` or
`Rejected`. Required precedence:

1. explicit `/skill-id` before automatic routing;
2. Parent before Mode;
3. embedding only after `NoMatch`.

Bind resolved skill generation and authority to execution. Apply Custom owner
and reload policy. Preflight install/create/enable/self-activate mutations.
Make chat, channels, CLI probe, GUI and Buddy consume the same route report.
Add parity and no-bypass source gates before marking B10 complete.

## 7. Exact proactive-egress checkpoint

Every terminal proactive item now follows one recoverable transaction:

`Prepared → Intent WAL ACK → Armed WAL ACK → one transport invocation through`
`the sole seam → authenticated Result WAL ACK → idempotent history/Cron/queue`
`projection`.

Recovery runs before config, enable, quiet-hours, idle and routing gates. One
immutable tick context feeds one production `execute_claimed_once` seam; all
eleven constructible live route arms use it.

The live set is Telegram, Slack, Discord, WhatsApp Cloud, WhatsApp/Baileys,
Keet, Signal, LINE, Mattermost, iMessage and feature-gated Matrix. IRC, Twitch,
Nostr and Google Chat remain connection-bound `SidecarOnly`, so
`GOLD-LF-P1-14` remains open.

The private projection is bound to the canonical authenticated WAL chain,
recipient digest and exact Intent/Armed/Result frame hashes. Modern unverified
or forged projections fail closed. Migrated legacy rows stay visibly
`legacy_unverified`. CLI `neoth proactive list --history`, GUI feed and Buddy
use the same verified reader.

Windows claim/history operations pin no-follow handles, private DACLs,
volume/File-ID identity, exact rotation bytes, torn tails and monotonic archive
IDs across clock rollback.

Observed evidence on the frozen combined tree:

- strict `cargo clippy -p neoth --lib -- -D warnings`: green;
- proactive egress 35/35;
- proactive queue and CLI admission 45/45;
- proactive dispatcher 26/26;
- cron state 10/10;
- GUI stream 20/20;
- bound Windows file/directory DACL bridges 7/7;
- private create/replace/atomic-write regressions 8/8;
- authenticated WAL marker/DACL groups 7/7;
- proactive source contract 17/17;
- GUI channel feed 6/6;
- GUI all-features check green;
- final independent review: 0 Critical, 0 High, 0 Medium, 0 Low.

Do not overclaim physical exactly-once external effects across a crash window.
`Armed` without `Result` becomes visible `CrashUnknown` and is not blindly
replayed.

`GOLD-LF-P1-14` also remains open for canonical `ChannelAccountId`, a
claim-bound typed one-shot permit, uniform intent-bound retry/attempt budgets
and exact-head platform/channel-contract evidence.

## 8. Immediate continuation after this push

1. Fetch and prove `HEAD == origin/main`; inspect dirty provenance.
2. Continue B10 only through the shared resolver slice in section 6.
3. Keep explorer/research lanes read-only; give one worker exact file ownership.
4. Reuse the existing B10 caller map before broad source traversal.
5. Wire every resolver consumer in the same coherent checkpoint; do not leave a
   second legacy decision path.
6. Run focused tests during implementation, then one coherent frozen
   Clippy/test/review gate.
7. Update ROAD/PROGRESS, stage an explicit allowlist, inspect, commit, push and
   verify the remote hash.

## 9. Adoption and wiring audit rules

For every later adoption:

- deep-read source code and record actual algorithm/data-flow findings;
- verify the source license before copying; reimplement behavior when needed;
- compare upstream behavior with NEOTH's real architecture and defaults;
- map every intended consumer before implementation;
- include config/schema/default/migration/wizard/Doctor/CLI/GUI/Buddy/channel/
  release/docs effects;
- expose model/artifact downloads with readiness, progress, error and
  cancellation in both CLI and GUI;
- prove install and migration paths on production-shaped fixtures;
- verify feature flags and release packaging actually include the adoption;
- search for partials, stubs, duplicate legacy paths and dead tests;
- never close an adoption from file presence alone.

## 10. Git landing protocol

Before every commit:

```powershell
git diff --check
git fetch --prune origin
git rev-list --left-right --count HEAD...origin/main
```

Require `0 0` before landing. Stage only the intended files:

```powershell
git add -- <explicit files only>
git diff --cached --name-only
git diff --cached --stat
git diff --cached --check
git status --short
```

If any unrelated path is staged, unstage only that path without reverting its
worktree contents. Re-run the focused evidence after any code fix made during
review.

Then:

```powershell
git commit -m "<type(scope): exact checkpoint>"
git push origin main
git fetch --prune origin
git rev-parse HEAD
git rev-parse origin/main
```

Report separately:

- what is implemented and wired;
- exact tests/reviews passed;
- known open roadmap contracts;
- workspace-wide or platform verification not run;
- local commit hash;
- whether push succeeded and `HEAD == origin/main`.

Never describe a dirty tree as committed, a local commit as pushed, a focused
test as a full release gate or a partial checkpoint as v1.0 Gold completion.
