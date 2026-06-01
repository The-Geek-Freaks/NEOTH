# Session 18 Handoff — GUI Code Sessions Tab + Pick #6 dispatcher prep

**Predecessor**: `PLAN/HANDOFF_2026-05-19_SESSION16.md` + Session 17
(11 picks shipped, see `PROGRESS.md` Session 17 entry).
**Date**: 2026-05-20 onward.
**Workspace state at handoff**: neothd test suite **2298 passed / 0 failed**.
clippy `-D warnings` + fmt clean. Builds via
`scripts/cargo-msvc.ps1` (Windows MSVC wrapper).

## Session 17 outcome

V11 coding workflow chain is **v1.0 ship-ready** end-to-end. Operator
runs `neoth code "..."`, NEOTH decomposes via Cerebellum hemisphere,
heuristic-classifies each task, persists in `views.db::idx_kanban_*`,
shows the result. Operator inspects via `neoth kanban {list, show,
task, move, assign, comment, archive, watch, review}`. Auto-promote
flow ships so REVIEW tasks with green tests land in DONE without
operator intervention.

11 picks shipped in Session 17:

| # | Pick | Status | Notes |
|---|------|--------|-------|
| #34 voll | WAL writer sync API + hostcalls emit_event | ✅ | V10-04 unrelated to coding workflow |
| #37 hygiene | SEQ_TEST_LOCK Mutex fix | ✅ | Flaky test eliminated |
| #34c | recall_top views.db wiring | ✅ | V10-04, feature-gated tests |
| #38 scaffold | Coding Pick #1 — types + schema + WAL codes | ✅ | 0x70..=0x76 reserved |
| #38b store CRUD | Coding Pick #2 — full session/task/comment CRUD | ✅ | SQL injection regression pinned |
| #38c classifier | Coding Pick #3 — heuristic Fast/Deep/Ambiguous | ✅ | 23+24 signal lists |
| #38d feed | Coding Pick #7 — pure WAL→activity-feed parser | ✅ | 7 event-type schemas |
| #38e decomposer | Coding Pick #4 — Chorus-gated | ✅ | All 7 verdicts + 4 blocking changes |
| #38f kanban CLI | Coding Pick #5a | ✅ | 8 operator subcommands |
| #38g code CLI + cerebellum adapter | Coding Pick #5b | ✅ | End-to-end `neoth code` works |
| #38h review + auto-promote | Coding Pick #10 | ✅ | REVIEW → DONE auto-transition |

## What's still open

Per `PLAN/SPEC_coding_workflow.md` build order:

- ⏸️ **Pick #6 worker dispatcher** — Chorus-gated. SPEC §Open
  questions flags "patch safety: worktree vs direct apply" as the
  central architectural decision. Without dispatcher, tasks sit in
  Backlog/Unassigned (after `neoth code`) until an operator manually
  moves them via `neoth kanban move/assign`. v1.1 work.
- ⏸️ **Pick #8 GUI Code Sessions tab** — Slint UI panel, ~400 LOC.
  **This is Session 18's primary focus** — operator wants to test the GUI
  visually together.
- ⏸️ **Pick #9 LLM second-opinion classify** — Ambiguous-bucket gets
  re-classified via Cerebellum LLM. Sits in the dispatcher (Pick #6)
  path so it's gated on #6 for the polished version.

## Session 18 plan — GUI Code Sessions tab (Pick #8)

### Scope per SPEC

A 9th tab in the Slint Settings panel ([neothd-gui/ui/settings.slint](SRC/neothd-gui/ui/settings.slint))
that mirrors the Twitter image layout:

```
┌─Settings─────────────────────────────────────────────────────────┐
│  Chat │ Hemispheres │ Channels │ Skills │ Plugins │ Memory │     │
│  Privacy │ Config │ Code Sessions [NEW]                          │
├──────────────────────────────────────────────────────────────────┤
│  Code Sessions                                                   │
│  ────────────────────────                                        │
│  ┌──────────┬───────┬─────────────┬────────┬───────┐             │
│  │ BACKLOG  │ TODO  │ IN PROGRESS │ REVIEW │ DONE  │             │
│  ├──────────┼───────┼─────────────┼────────┼───────┤             │
│  │ task 1   │ task2 │ task 3      │ task 4 │ task5 │             │
│  │ task ... │ ...   │ ...         │ ...    │ ...   │             │
│  └──────────┴───────┴─────────────┴────────┴───────┘             │
│  Activity feed (right rail)                                      │
│  ────────────────────────                                        │
│  23:55  left      Patch generated for toggle component           │
│  23:56  left      Tests added (5 new)                            │
│  23:57  right     Code review started                            │
│  23:58 cerebellum All checks passing                             │
└──────────────────────────────────────────────────────────────────┘
```

### Pre-wired ingredients (all in `neothd` crate, ready to bind)

- **Data**: `coding::store::list_tasks_for_session(conn, session_id)`
  returns `Vec<KanbanTask>` with full lifecycle state.
- **Session list**: copy `cli::kanban::select_sessions` pattern.
- **Activity feed**: `coding::feed::parse_kanban_payload(et, ts, payload)`
  returns `FeedEntry { ts_ns, event_type, actor, message }`; just
  needs WAL segment walking which `cli::kanban::scan_wal_dir_for_kanban_feed`
  already does (copy / refactor into a shared helper).
- **Live updates**: the existing GUI subscribes to the in-process WAL
  tail; Pick #8 binds those frames to Slint property updates. Don't
  add SSE — use the same direct WAL → property binding the chat tab
  uses.

### Recommended implementation order

1. **Static board layout** — render 5 columns side-by-side with a
   hardcoded fixture task list. Verify column widths + bubble styling.
2. **Wire to `views.db`** — load real sessions on tab open, populate
   columns from `list_tasks_for_session`. Add session-switcher
   dropdown at the top.
3. **Activity feed right rail** — walk WAL via the existing parser,
   stream entries into a ListView.
4. **Live updates** — bind to WAL tail; refresh on new kanban frames.
5. **Click-to-detail** — clicking a task card opens a detail pane
   mirroring `neoth kanban task <id>` (description, comments,
   patch/test summary, status transition buttons).
6. **Operator actions in GUI** — `move` / `assign` / `comment` /
   `archive` / `review --promote` buttons calling into `coding::store::*`
   directly (same path as the CLI). Per the hard rule "GUI + CLI
   parity": every CLI subcommand must have a GUI control.

### Test surface

- Slint UI tests aren't easy on Windows headlessly. Pin instead:
  - Unit tests on any new pure functions (data formatting, status
    column grouping).
  - Visual review with the operator — fire up the GUI binary, click through
    the workflow against a real `neoth code "..."` session.
- `coding::store::*` is already test-covered (Pick #38b).

## Session 18 plan — Pick #6 dispatcher prep (after GUI is stable)

The dispatcher is the missing link between Pick #4 (decomposer) +
Pick #5 (CLI entry) on one side, and Pick #10 (auto-promote) on the
other. Today `neoth code` lands tasks in BACKLOG with hemisphere
assigned via classifier but no worker actually runs. Pick #6 fires
the bound provider for each Left/Right task, captures the patch +
test outcome, transitions through IN_PROGRESS → REVIEW.

**Chorus-gated** per SPEC §Open questions:

1. Patch safety: worktree (git worktree branch + apply in isolation)
   vs direct apply (operate on current working tree) vs stash+apply+
   revert-on-fail?
2. Streaming: should worker output stream live into the WAL
   (one frame per token), or only after the worker completes?
3. Per-tier autonomy gates: strict tier confirms every patch apply
   before it lands?
4. Cycle prevention if the dispatcher itself loops?

**Prep work to land before firing Chorus** (does not require
architectural decisions):

- Define `Worker` trait sibling to `DecomposerLlm` — `async fn execute(task: &KanbanTask) -> Result<WorkerOutcome>`.
- `WorkerOutcome { patch_text, tests_added, tests_passing, tests_failing, summary }`.
- Workspace dispatch loop skeleton — fetch BACKLOG tasks, hand to
  hemisphere worker, record outcome.

After Chorus verdicts come in, this skeleton becomes the dispatcher
implementation in ~600 LOC.

## Critical files map (Session 17 deltas)

| File | What it carries | Pick |
|------|-----------------|------|
| `SRC/neothd/src/coding/types.rs` | KanbanSessionId/TaskId newtypes, TaskStatus, Hemisphere, KanbanTask/Session/Comment, TestSummary, SessionStatus | #38 + #38b |
| `SRC/neothd/src/coding/store.rs` | Schema + 9 CRUD functions, 3 row decoders | #38 + #38b |
| `SRC/neothd/src/coding/classifier.rs` | `classify_heuristic` + DEEP/FAST signal lists + Complexity enum | #38c |
| `SRC/neothd/src/coding/feed.rs` | `parse_kanban_payload` + `FeedEntry::format` | #38d |
| `SRC/neothd/src/coding/decomposer.rs` | `decompose` orchestrator + delimited prompt + 12k token cap + validate_tasks + cycle detection | #38e |
| `SRC/neothd/src/coding/cerebellum_provider.rs` | `CerebellumDecomposer` (Provider → DecomposerLlm bridge) | #38g |
| `SRC/neothd/src/coding/review.rs` | `check_auto_promotable` + `auto_promote_if_green` + `auto_promote_session` | #38h |
| `SRC/neothd/src/cli/kanban.rs` | 9 operator subcommands + WAL feed scan | #38f + #38h |
| `SRC/neothd/src/cli/code.rs` | `neoth code <prompt>` orchestrator | #38g |
| `SRC/neothd/src/wal/events.rs` | EVENT_TYPE_KANBAN_* 0x70..=0x76 | #38 |
| `PLAN/SPEC_coding_workflow.md` | Full 10-pick contract | #38 |
| `PLAN/CHORUS_decomposer_design.md` | Pick #4 stress-test artifact | #38e |
| `RECON/hermes_coding_workflow.md` | Workflow analysis + image breakdown | #38 |

## Verify commands (Session 18 startup checklist)

```powershell
# From repo root
cd <your-workspace>/AGENTER

# Full neothd suite — must show 2298 passed / 0 failed at start
.\scripts\cargo-msvc.ps1 test -p neothd --bin neothd

# clippy + fmt
.\scripts\cargo-msvc.ps1 clippy -p neothd --bin neothd --tests -- -D warnings
.\scripts\cargo-msvc.ps1 fmt -p neothd -- --check

# Visual demo (requires a configured cerebellum provider)
.\scripts\cargo-msvc.ps1 run -p neothd --bin neothd -- code "Add dark mode toggle to settings"
.\scripts\cargo-msvc.ps1 run -p neothd --bin neothd -- kanban list
.\scripts\cargo-msvc.ps1 run -p neothd --bin neothd -- kanban show 1
.\scripts\cargo-msvc.ps1 run -p neothd --bin neothd -- kanban watch
```

## Memory rules in effect (carry forward)

- **[HARD RULE: v1.1 is the norm](memory/neoth_design_v11_is_norm.md)** —
  PLAN/00_DESIGN_v1.1_FINAL.md + SPEC_*.md authoritative
- **[NEOTH coding workflow](memory/coding_workflow_spec.md)** —
  3-hemisphere routing, kanban tasks in `views.db::idx_kanban_*`,
  WAL 0x70..=0x76, 10-pick build order
- **[HARD RULE: features default-ON in release](memory/neoth_features_default_on_runtime_toggle.md)** —
  Code workflow is operator-facing; wizard needs plain-language
  intro page when v1.0 release lands
- **[HARD RULE: GUI mode-selection first + settings parity](memory/neoth_gui_first_screen_and_settings_parity.md)** —
  GUI Code Sessions tab MUST mirror every CLI kanban subcommand
- **[HARD RULE: slash commands + GUI settings parity](memory/neoth_slash_commands_and_settings_parity.md)** —
  `/code` slash command needs adding when slash registry is touched next
- **[HARD RULE: PROGRESS.md update](memory/neoth_progress_md_update_rule.md)** —
  Every shipped pick updates PROGRESS in the same turn
- **[HARD RULE: claude-cli requires tmux](memory/neoth_claude_cli_tmux_mandatory.md)** —
  cerebellum bound to claude_cli will need tmux warm session for
  decomposer LLM calls to work in practice

## Communication template (carry forward)

- German register, direct, blunt
- Diff > description; no trailing summaries
- NEVER use SendUserMessage (it renders unreadably in some UIs) — reply
  directly in chat text
- Match the operator's register: "ja weiter" / "los!" → ship + report
- Risky / destructive ops: state consequence + ask before executing

## Session 18 communication points

- **Before starting Pick #8 GUI**: announce "starte GUI Pick #8 now",
  operator will be at the keyboard ready to visually review
- **Before firing dispatcher Chorus (Pick #6)**: draft the
  `PLAN/CHORUS_dispatcher_design.md` mirror of Pick #4's artifact;
  ask for verdicts on the 4 architectural questions

## Open lurking concerns

- **GUI testability on Windows**: Slint headless rendering is not
  trivial. Plan for "operator runs the binary, I drive via screenshots"
  rather than fully automated visual diff tests.
- **`neoth code` without a configured cerebellum**: surfaces as
  `from_config_for_role` error. Pick #5b's CLI prints the resolver
  error verbatim; that's fine for v1.0 but Pick #8 GUI should show a
  friendly "no Cerebellum bound — run wizard step 5d" state.
- **Operator session continuity**: if `neoth code` is interrupted
  mid-decompose, the session row sits in Planning forever. Pick #6
  dispatcher should reap stale Planning sessions on startup.
