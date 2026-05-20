# SPEC — NEOTH Coding Workflow (Hermes-adapted, hemisphere-routed)

**Status**: Draft v0.1, 2026-05-19 Session 17
**Adapts**: Hermes-Agent Autonomous Software Engineering Workflow
([RECON/hermes_coding_workflow.md](../RECON/hermes_coding_workflow.md))
**Hard rule alignment**: v1.1 norm ([[neoth-design-v11-is-norm]]),
features default-ON ([[neoth-features-default-on-runtime-toggle]]),
GUI/CLI parity ([[neoth-slash-commands-and-settings-parity]])

## Goal

Operator types `neoth code "Add dark mode toggle to settings page and
persist preference"` (or slash `/code` in the chat surface, or messenger
DM). NEOTH:

1. Decomposes the prompt into atomic tasks.
2. Classifies each task by complexity → routes to Left (Fast) or Right
   (Deep) hemisphere; Cerebellum orchestrates.
3. Tracks every task on a Kanban board with the 5-column shape Hermes
   pinned (BACKLOG → TODO → IN_PROGRESS → REVIEW → DONE), persisted in
   `views.db`.
4. Streams per-worker activity to the WAL audit trail; the GUI + CLI
   render a live feed.
5. Emits a final patch + test summary + merge verdict.

## Non-goals (explicit out-of-scope)

- **Multi-board management** (Hermes has multi-board switching; NEOTH
  v0.1 ships a single default board per session).
- **Task dependency graphs** (Hermes has explicit dep links; NEOTH v0.1
  ships parent → child only, no DAG).
- **Drag-drop GUI reordering** (status changes go through `neoth kanban
  move`; v0.2+ adds drag-drop).
- **Third-party worker marketplace** — NEOTH has no equivalent of
  ClawHub. Workers are the bound hemisphere providers, period.

## Architecture

```
                  ┌─────────────────────────────────────┐
                  │  Operator entry                     │
                  │    neoth code "..." (CLI)           │
                  │    /code in chat surface (GUI)      │
                  │    DM to bound messenger (channels) │
                  └────────────────┬────────────────────┘
                                   │
                                   ▼
                  ┌─────────────────────────────────────┐
                  │  CEREBELLUM (orchestrator)          │
                  │  • Resolves the bound provider for  │
                  │    role=cerebellum from             │
                  │    InferenceTopology                │
                  │  • Runs decomposer prompt → list of │
                  │    KanbanTask rows                  │
                  │  • Classifies each task by          │
                  │    complexity (heuristic + LLM      │
                  │    second-opinion when ambiguous)   │
                  └────────────────┬────────────────────┘
                                   │
                       ┌───────────┴───────────┐
                       ▼                       ▼
        ┌───────────────────────┐  ┌───────────────────────┐
        │  LEFT (analytic)      │  │  RIGHT (creative)     │
        │  Fast worker          │  │  Deep worker          │
        │  Best for:            │  │  Best for:            │
        │   • UI scaffolds      │  │   • Architecture      │
        │   • Test stubs        │  │   • Design decisions  │
        │   • Well-scoped CRUD  │  │   • Code review       │
        │   • Single-file edits │  │   • Ambiguous specs   │
        └───────────┬───────────┘  └───────────┬───────────┘
                    │                          │
                    ▼                          ▼
        ┌───────────────────────────────────────────────┐
        │  Kanban store (views.db::idx_kanban)          │
        │  Per-task lifecycle WAL events                │
        │   0x70 KANBAN_TASK_CREATED                    │
        │   0x71 KANBAN_TASK_STATUS_CHANGED             │
        │   0x72 KANBAN_TASK_ASSIGNED                   │
        │   0x73 KANBAN_TASK_COMMENT                    │
        │   0x74 KANBAN_TASK_COMPLETED                  │
        │   0x75 KANBAN_SESSION_OPENED                  │
        │   0x76 KANBAN_SESSION_CLOSED                  │
        └────────────────┬──────────────────────────────┘
                         │
                         ▼
        ┌───────────────────────────────────────────────┐
        │  Activity feed view                           │
        │   neoth kanban watch  (CLI tail)              │
        │   GUI "Code Sessions" tab live SSE            │
        │   Channel echo: DM with summary on completion │
        └───────────────────────────────────────────────┘
```

## Data model

### Sqlite schema (`views.db`)

```sql
CREATE TABLE IF NOT EXISTS idx_kanban_session (
    session_id     INTEGER PRIMARY KEY,
    -- HLC physical_ns of creation; sorts naturally
    created_ns     INTEGER NOT NULL,
    -- Original operator prompt verbatim
    prompt         TEXT NOT NULL,
    -- xxh3 of prompt; matches WAL frame payload_hash format
    prompt_hash    TEXT NOT NULL,
    -- Channel the request arrived on: cli / chat / telegram / discord / ...
    source_channel TEXT NOT NULL,
    -- Operator identifier (resolves to FreedomConfig operator_id)
    operator_id    TEXT,
    -- Status: planning / running / review / done / abandoned
    status         TEXT NOT NULL,
    -- Final artifact path when status=done (relative to ~/.neoth/sessions/<id>/)
    artifact_path  TEXT,
    -- One-line summary written by Cerebellum on completion
    summary        TEXT
);
CREATE INDEX IF NOT EXISTS idx_kanban_session_created
    ON idx_kanban_session (created_ns DESC);
CREATE INDEX IF NOT EXISTS idx_kanban_session_status
    ON idx_kanban_session (status);

CREATE TABLE IF NOT EXISTS idx_kanban_task (
    task_id        INTEGER PRIMARY KEY,
    session_id     INTEGER NOT NULL REFERENCES idx_kanban_session(session_id),
    -- Status column (Hermes-compatible): backlog / todo / in_progress / review / done / blocked / archived
    status         TEXT NOT NULL,
    -- Operator-visible task title (1-2 lines)
    title          TEXT NOT NULL,
    -- Free-text description Cerebellum produced during decomposition
    description    TEXT,
    -- Task type tag: ui / store / theme / tests / refactor / docs / build / ...
    task_type      TEXT NOT NULL,
    -- Hemisphere assignment: left / right / cerebellum / unassigned
    hemisphere     TEXT NOT NULL DEFAULT 'unassigned',
    -- Provider name resolved at dispatch (e.g. "local_qwen" / "claude_cli")
    worker         TEXT,
    -- Parent task for sub-decomposition (e.g. "Add tests" parent of "Add unit test for X")
    parent_task_id INTEGER REFERENCES idx_kanban_task(task_id),
    -- Lifecycle timestamps
    created_ns     INTEGER NOT NULL,
    started_ns     INTEGER,
    -- ETA in nanoseconds from started_ns (Cerebellum estimates; refined by worker)
    eta_ns         INTEGER,
    completed_ns   INTEGER,
    -- Final patch (when worker produced one) relative to session artifact dir
    patch_path     TEXT,
    -- Test summary in JSON: {added, total, passing, failing, skipped}
    test_summary   TEXT
);
CREATE INDEX IF NOT EXISTS idx_kanban_task_session
    ON idx_kanban_task (session_id);
CREATE INDEX IF NOT EXISTS idx_kanban_task_status
    ON idx_kanban_task (status);
CREATE INDEX IF NOT EXISTS idx_kanban_task_hemisphere
    ON idx_kanban_task (hemisphere);

CREATE TABLE IF NOT EXISTS idx_kanban_comment (
    comment_id   INTEGER PRIMARY KEY,
    task_id      INTEGER NOT NULL REFERENCES idx_kanban_task(task_id),
    -- Who left the comment: cerebellum / left / right / operator
    author       TEXT NOT NULL,
    body         TEXT NOT NULL,
    created_ns   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_kanban_comment_task
    ON idx_kanban_comment (task_id, created_ns ASC);
```

### Rust types

```rust
// src/coding/types.rs
pub struct KanbanSessionId(pub i64);
pub struct KanbanTaskId(pub i64);

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TaskStatus {
    Backlog,
    Todo,
    InProgress,
    Review,
    Done,
    Blocked,
    Archived,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Hemisphere {
    Left,        // analytic / fast worker
    Right,       // creative / deep worker
    Cerebellum,  // orchestrator (rare assignment — meta-tasks only)
    Unassigned,
}

pub struct KanbanTask {
    pub task_id: KanbanTaskId,
    pub session_id: KanbanSessionId,
    pub status: TaskStatus,
    pub title: String,
    pub description: Option<String>,
    pub task_type: String,
    pub hemisphere: Hemisphere,
    pub worker: Option<String>,
    pub parent_task_id: Option<KanbanTaskId>,
    pub created_ns: u64,
    pub started_ns: Option<u64>,
    pub eta_ns: Option<u64>,
    pub completed_ns: Option<u64>,
    pub patch_path: Option<std::path::PathBuf>,
    pub test_summary: Option<TestSummary>,
}

pub struct TestSummary {
    pub added: u32,
    pub total: u32,
    pub passing: u32,
    pub failing: u32,
    pub skipped: u32,
}
```

## Complexity classifier

The classifier decides Left vs Right per task. Heuristic-first (no LLM
round-trip), LLM second-opinion only when the heuristic abstains.

```rust
// src/coding/classifier.rs
pub enum Complexity {
    Fast,       // → Left
    Deep,       // → Right
    Ambiguous,  // → escalate to Cerebellum for LLM classify
}

pub fn classify_heuristic(task: &KanbanTask) -> Complexity {
    let title_lower = task.title.to_lowercase();
    let desc_lower = task.description.as_deref().unwrap_or("").to_lowercase();
    let combined = format!("{} {}", title_lower, desc_lower);

    // Hard signals for Deep:
    if FAST_BLOCKERS.iter().any(|kw| combined.contains(kw)) {
        return Complexity::Deep;
    }
    // Hard signals for Fast:
    if FAST_KEYWORDS.iter().any(|kw| combined.contains(kw)) {
        return Complexity::Fast;
    }
    Complexity::Ambiguous
}

const FAST_BLOCKERS: &[&str] = &[
    "architecture", "design decision", "refactor", "review",
    "consider", "evaluate", "trade-off", "tradeoff", "should we",
    "edge case", "security", "race", "deadlock", "migration",
];
const FAST_KEYWORDS: &[&str] = &[
    "add toggle", "add button", "add input", "add field",
    "save preference", "store value", "load setting",
    "write test", "add test", "fix typo", "rename",
    "add validation", "add error message",
];
```

The lists are CHOSEN, not learned — they encode the operator's
intuition. They live in [`coding/classifier.rs`](../SRC/neothd/src/coding/classifier.rs)
so operators can tune them without recompiling logic.

LLM second-opinion (for `Ambiguous`) goes through the **Cerebellum**
hemisphere with a tiny classifier prompt:

```
You classify a coding task into Fast or Deep. Return ONLY the word
"fast" or "deep". A Fast task is well-scoped, < 50 LOC, no design
decision, no review-needed. A Deep task involves architecture, design,
ambiguity, or judgment calls.

Task title: {title}
Task description: {description}
```

## WAL events (band 0x70..=0x7F reserved)

Aligned with the existing tool-band convention (`wal/events.rs`
already pins 0x00..=0xCF). The 0x70..=0x7F slot is unused today.

```rust
// wal/events.rs additions (Session 17 Pick #38 scaffold; concrete codes land with implementation)
pub const EVENT_TYPE_KANBAN_SESSION_OPENED: u8 = 0x70;
pub const EVENT_TYPE_KANBAN_TASK_CREATED:   u8 = 0x71;
pub const EVENT_TYPE_KANBAN_TASK_ASSIGNED:  u8 = 0x72;
pub const EVENT_TYPE_KANBAN_STATUS_CHANGED: u8 = 0x73;
pub const EVENT_TYPE_KANBAN_TASK_COMMENT:   u8 = 0x74;
pub const EVENT_TYPE_KANBAN_TASK_COMPLETED: u8 = 0x75;
pub const EVENT_TYPE_KANBAN_SESSION_CLOSED: u8 = 0x76;
```

All seven need `needs_immediate_sync = true` (audit chain MUST survive
crash). The CLI registry (`cli/events.rs::REGISTRY`) gets matching rows
so `neoth events --grep kanban` surfaces them.

## CLI surface

```text
neoth code <PROMPT>            # one-shot: decompose + dispatch + watch
neoth code --watch SESSION_ID  # re-attach to a running session
neoth kanban list              # show open sessions
neoth kanban show TASK_ID      # task detail (title / status / worker / comments)
neoth kanban move TASK_ID <STATUS>     # manual status nudge (backlog→todo→...)
neoth kanban assign TASK_ID <HEMI>     # manual hemisphere reassignment
neoth kanban comment TASK_ID "..."     # operator-side comment
neoth kanban archive SESSION_ID        # close + archive session
neoth kanban watch              # tail activity feed
```

Slash commands (chat surface) MUST mirror — per the slash + GUI parity
hard rule:

```text
/code <prompt>     — equivalent to `neoth code`
/kanban            — opens GUI Code Sessions panel
/kanban <task_id>  — shows task detail inline
```

## GUI surface

The Slint GUI gains a 9th tab in the Settings panel:

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
│  23:58  cerebellum All checks passing                            │
└──────────────────────────────────────────────────────────────────┘
```

Live updates flow from the WAL event stream (already exists) into the
GUI via Slint property bindings. No SSE — the GUI subscribes to the
in-process WAL tail directly.

## Worker dispatch contract

When Cerebellum hands a task to Left or Right, the prompt template is:

```
You are an autonomous coding worker on the {hemisphere} hemisphere.
Your job: {task_title}

Description: {task_description}
Task type: {task_type}
Session context: {session_prompt}

Produce:
1. A unified diff patch (one file or multi-file) applying the change.
2. Tests covering the change (≥80% line coverage where applicable).
3. A one-paragraph summary of what you did + any caveats.

Output as JSON:
{
  "patch": "<unified diff>",
  "tests_added": <int>,
  "tests_passing": <int>,
  "tests_failing": <int>,
  "summary": "<one paragraph>"
}
```

The worker's reply is parsed; on success the task moves to REVIEW. The
Right hemisphere (or Cerebellum, configurable) reviews REVIEW tasks
and moves to DONE.

## Module layout

```text
SRC/neothd/src/coding/
├── mod.rs              — public surface, type re-exports
├── types.rs            — KanbanTask, TaskStatus, Hemisphere, TestSummary
├── store.rs            — sqlite CRUD over views.db::idx_kanban_*
├── decomposer.rs       — prompt → list<KanbanTask> via Cerebellum LLM
├── classifier.rs       — complexity classifier (heuristic + LLM second-opinion)
├── dispatcher.rs       — worker dispatch + lifecycle
├── feed.rs             — derived activity-feed view from WAL events
└── tests/
    ├── classifier_test.rs   — heuristic edge cases
    ├── decomposer_test.rs   — golden fixtures of prompt → task list
    └── store_test.rs        — sqlite round-trip
```

```text
SRC/neothd/src/cli/
├── code.rs             — `neoth code <prompt>`
└── kanban.rs           — `neoth kanban {list,show,move,assign,comment,archive,watch}`
```

```text
SRC/neothd-gui/ui/
└── code_sessions.slint  — 9th settings tab
```

## Build order (incremental picks)

| # | Pick | LOC | Chorus gate | Notes |
|---|------|-----|-------------|-------|
| 1 | **Scaffold + schema** | ~250 | no | data types + sqlite migrations + WAL event codes |
| 2 | **Store CRUD + tests** | ~300 | no | session + task + comment round-trip |
| 3 | **Heuristic classifier** | ~200 | no | pure-function `classify_heuristic` + golden tests |
| 4 | **Decomposer** | ~400 | **yes** — prompt design | Cerebellum LLM call + JSON parse + fallback for malformed |
| 5 | **CLI entry `neoth code` + `kanban`** | ~500 | no | wires #1..#4 into operator-visible commands |
| 6 | **Worker dispatcher** | ~500 | **yes** — patch parse + apply safety | hands tasks to bound hemisphere, parses worker JSON reply, writes patch to session artifact dir |
| 7 | **Activity feed CLI + WAL view** | ~250 | no | tails WAL 0x70..0x76 frames, formats per the image |
| 8 | **GUI Code Sessions tab** | ~400 | no | Slint panel mirroring the 5-column layout |
| 9 | **LLM second-opinion classify** | ~200 | no | Cerebellum-routed `Ambiguous` resolution |
| 10 | **Comments + review flow** | ~300 | no | inter-hemisphere comments; auto-promote to DONE on review pass |

**Total**: ~3,300 LOC across 10 picks. v1.0 ship-blocker scope is
**Picks 1-5** (~1,650 LOC) — enough for `neoth code "..."` to
decompose + dispatch + complete a real task end-to-end. Picks 6-10 are
v1.1 polish + GUI.

## Open questions (Chorus-worthy)

1. **Decomposer prompt design** (Pick #4) — Hermes' actual decomposer
   prompt isn't public; we have to design ours. Chorus gremium to
   compare two candidate prompts before committing.
2. **Patch safety** (Pick #6) — should the worker's patch apply directly
   to the working tree, or to a git worktree branch, or stash + apply +
   revert-on-fail? Hermes appears to apply directly. NEOTH's stricter
   audit model probably wants worktree.
3. **REVIEW gating** — does REVIEW always require human approval, or
   can Right hemisphere self-approve? Hermes shows Claude reviewing
   SmallCode's work autonomously; NEOTH defaults probably want
   operator-in-loop until trust is built.
4. **Streaming**: should worker output stream live into the WAL (one
   frame per token), or only after the worker completes? K-Perf-2's
   `append_no_ack` pattern says live-streaming is cheap; the question is
   whether the audit chain benefits or just grows huge.

## Memory rule integration

This SPEC is added to `MEMORY.md` after Pick #1 lands so the next
session knows the coding workflow exists + where to find the SPEC.
Naming pin: memory entry name `coding-workflow-spec` with description
"Hermes-adapted coding workflow: 3-hemisphere routing, kanban tasks in
views.db, WAL 0x70..0x76, CLI+GUI surfaces. v1.0 ship: Picks 1-5."

## References

- [RECON/hermes_coding_workflow.md](../RECON/hermes_coding_workflow.md) — the upstream analysis
- [QUELLEN/hermes-webui/api/kanban_bridge.py](../QUELLEN/hermes-webui/api/kanban_bridge.py) — HTTP+SSE bridge reference
- [SRC/neothd/src/cli/hemispheres.rs](../SRC/neothd/src/cli/hemispheres.rs) — existing hemisphere CLI
- [SRC/neothd/src/config/inference.rs](../SRC/neothd/src/config/inference.rs) — `InferenceTopology`
- [SRC/neothd/src/memory/store.rs](../SRC/neothd/src/memory/store.rs) — views.db schema (where `idx_kanban_*` lives)
- [SRC/neothd/src/wal/events.rs](../SRC/neothd/src/wal/events.rs) — event code register
