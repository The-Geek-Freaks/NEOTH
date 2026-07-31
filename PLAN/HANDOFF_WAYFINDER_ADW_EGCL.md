# HANDOFF — Wayfinder → ADW Design → Evidence-Gated Coding Loop

**For:** the Claude session implementing this in NEOTH.
**From:** the 2026-07-31 adoption session (`PLAN/ADOPT_2026_07_31/`).
**Tracker:** `PLAN/ROAD_TO_1_0_GOLD.md` → `## WS-ADOPT31` → *Lane I*.
**Read this whole file before touching code.** It is self-contained: architecture, verified
ground truth, build order, and the traps that will otherwise cost you hours.

---

## 0. Operator's framing (verbatim intent)

> *Wayfinder → ADW Design → Evidence-Gated Coding Loop. Damit trenne ich Zielklärung,
> wiederholbares Prozessdesign und konkrete verifizierte Umsetzung sauber voneinander.*

Three stages, deliberately separated:

| Stage | Owns | Refuses to own |
|---|---|---|
| **Wayfinder** | *What are we actually trying to achieve, and how will we know?* — **an existing agent-side skill, not something NEOTH builds** | how the work gets done |
| **ADW Design** | *What repeatable process produces that, and who does each step?* | this particular task's content |
| **Evidence-Gated Coding Loop** | *Execute it, and prove each step happened.* | deciding the goal or the shape |

The separation is the feature. Today NEOTH smears all three across
`coding/dispatcher.rs` (3281 lines) — intent inference, a hardcoded topology, and validation
all in one file with no seam between them.

---

## 1. The load-bearing idea

The three stages are not three documents. They are **one typed pipeline**, joined by a single
invariant:

```
Wayfinder  →  Goal { intent, constraints, acceptance: Vec<AcceptanceCriterion> }
                     └─ every criterion names the EVIDENCE that will prove it
                              │
                              │  COVERAGE CHECK — the thing that makes this a system:
                              │  an AdwSpec may not run unless every AcceptanceCriterion
                              │  maps to ≥1 node that emits that evidence kind.
                              │  Unmapped criterion ⇒ reject the run. Not a warning.
                              ▼
ADW Design →  AdwSpec { nodes(code|agent|human), edges(on_pass/on_fail), isolation, budgets }
                              │
                              ▼
Evidence-  →  AdwRun — every node transition writes an Evidence record to the WAL.
Gated Loop    The run reaches Complete ONLY when every AcceptanceCriterion has a
              satisfied Evidence record. **"The agent said it's done" is not a state.**
```

That coverage check is what turns *"never claim done without proof"* from a discipline
someone has to remember into a **structural property of the runtime**. It is the reason to
build all three rather than just the middle one.

If you implement only one thing from this document, implement the coverage check.

---

## 2. Verified NEOTH ground truth

Every line below was produced by a command that was actually run on 2026-07-31. Do not
re-derive; do verify anything you intend to change.

```
rg -n 'enum (NodeKind|StepKind|WorkflowNode|PipelineNode|StageKind)' --type rust SRC/neothd/src
  → ZERO hits
rg -rin 'evidence.gated|evidence_gate'  → ZERO hits   (new concept, free namespace)
```

### ⚠ Wayfinder ALREADY EXISTS — do not rebuild it

`~/.claude/skills/wayfinder/` is an installed agent-side skill the operator already uses, and
the Codex line opened a live map for exactly this repo at
`.scratch/wayfinder-map-gold-finish.md` (commit `bc5de90b`, referenced from
`PLAN/PROGRESS_v1_0.md`). Its model:

- The **map** is one artifact (`wayfinder:map`) with `## Destination`, `## Notes`,
  `## Decisions so far`, `## Not yet specified` (fog), `## Out of scope`.
- **Tickets** are child issues, each labelled `wayfinder:{research,prototype,grilling,task}`,
  each a *question whose resolution is a decision*, sized to one ~100K-token session.
- It is **"plan, don't do"** by default. Its own words: *"The pull to just do the work is
  usually the signal you've reached the edge of the map and it's time to hand off."*
- The **frontier** is the open + unblocked + unclaimed tickets.

**That handoff moment is the seam.** Wayfinder stops where execution begins; the ADW pipeline
starts there. NEOTH's job in stage 1 is *not* to plan — it is to **ingest a cleared way** and
turn it into a typed `Goal` whose acceptance criteria are machine-checkable. Building a
`/wayfinder` command inside NEOTH would duplicate a working tool and split the operator's
planning surface in two. Do not do it.

*(An earlier draft of this document claimed the `wayfinder` namespace was free. It was, at the
moment that grep ran; the Codex line committed the map later the same day. Corrected here.)*

**Live-map note for whoever picks this up:** that map's ticket **T4** asks which of the
"233 pre-tag blockers" are genuinely v1.0 — those figures predate this session. The roadmap
now counts **1,289 boxes / 298 pre-tag blockers** after WS-ADOPT31. T4's split must be made
against the current number, not the one written in the map body.

### What already exists and must be reused, not rebuilt

| Need | Existing NEOTH surface | LOC |
|---|---|---|
| Intent classification | `coding/intent.rs`, `coding/general_task_intent.rs`, `coding/classifier.rs` | 506 / 461 / — |
| Goal exploration | `coding/brainstorm.rs` | 651 |
| Plan writing / board | `coding/plan_writer.rs`, `coding/decomposer.rs`, `coding/store.rs` | 573 / 1059 / 1382 |
| Kanban identity | `coding/types.rs::{KanbanSessionId, KanbanTaskId}` | 462 |
| Worktree isolation | `coding/worktree.rs` — `create_task_worktree`, `apply_patch_in_worktree`, `cleanup_worktree`, `is_worktree_dirty` | 987 |
| Validation nodes | `coding/validate.rs`, `cargo_check.rs`, `tdd_preflight.rs`, `review.rs`, `second_opinion.rs`, `plan_review.rs` | 481 / 402 / — / 631 / — / — |
| Loop control | `coding/retry.rs`, `coding/early_stop.rs`, `council/stop_verifier.rs` | — / — / 398 |
| Adversarial check | `council/orchestrator.rs`, `council/factual_check.rs`, `council/quality_score.rs`, `council/dissent.rs` | 1547 / 486 / 961 / 371 |
| Parallel agents | `sub_agents/parallel.rs`, `sub_agents/runtime.rs` | 602 / 728 |
| Model tiering | `providers/model_roles.rs::ModelRole{Flagship,Balanced,Fast,Vision,Embedding}` (line 66), `coding/model_profile.rs`, `models/hemisphere_preset.rs` | 490 / 493 / 155 |
| Consent gates | `permissions/mod.rs`, `permissions/gate.rs`, `permissions/lease.rs`, `permissions/tier_classifier.rs` | 2132 / 1421 / 525 / 555 |
| Self-edit safety | `coding/self_source_gate.rs` | 1980 |
| Durable audit | `wal/` (Extended-Subtype band), `daemon/audit_rpc/server.rs` | — |
| Declarative schema **without an executor** | `recipes/schema.rs` (`RecipeSpec`, `SubRecipe`, `RetryPolicy`), `recipes/render.rs` | 285 / 314 |

### What is genuinely absent

- Typed workflow node — no `NodeKind`, anywhere.
- Topology as data — `dispatcher.rs` hardcodes exactly one shape.
- Per-work-class routing — `intent.rs`/`classifier.rs` classify *intent* and *hemisphere*, never *which pipeline shape*.
- A `Goal` artifact with machine-checkable acceptance criteria.
- An `Evidence` record type and the coverage check over it.
- Agent sandboxes beyond git worktrees; racing lanes.

**Read this correctly:** NEOTH already *implements* a good AI Developer Workflow. It just
cannot *express* one. Almost everything you need exists as a function; what is missing is the
data model that lets those functions be arranged declaratively and proven afterwards.

---

## 3. The types

Put the whole pipeline under `SRC/neothd/src/adw/`. It spans coding, council and permissions,
so it does not belong inside `coding/`.

```rust
// adw/goal.rs  — STAGE 1 output
pub struct Goal {
    pub id: GoalId,
    pub intent: String,                        // operator's own words, defanged before any prompt use
    pub constraints: Vec<Constraint>,          // budget, deadline, forbidden areas, invariants to hold
    pub acceptance: Vec<AcceptanceCriterion>,  // MUST be non-empty — a Goal with no criteria is rejected
    pub non_goals: Vec<String>,                // explicit scope fence
    pub open_questions: Vec<String>,           // non-empty ⇒ Goal is Draft, not Ready
}

pub struct AcceptanceCriterion {
    pub id: CriterionId,
    pub statement: String,                     // "the new gate rejects an unmapped criterion"
    pub evidence: EvidenceKind,                // HOW it will be proven — the crux
    pub required: bool,                        // false = nice-to-have, does not block Complete
}

pub enum EvidenceKind {
    TestPasses { filter: String },             // a named test actually ran and passed
    CommandExits { cmd: CommandSpec, code: i32 },
    FileContains { path: PathBuf, pattern: String },
    DiffTouches { path_glob: String },
    HumanConfirms { prompt: String },          // routed through permissions::ActionKind
    CouncilVerdict { min_score: u8 },          // council/quality_score.rs
    Absent { pattern: String, scope: PathBuf }, // proves a removal
}
```

```rust
// adw/spec.rs  — STAGE 2 output
pub enum NodeKind {
    Code(CodeOp),      // Lint | Format | Typecheck | Test | Build | Status | Git | Shell(allowlisted)
    Agent(AgentSpec),  // { role: ModelRole, sub_agent: SubAgentId, budget: TokenBudget }
    Human(GateSpec),   // { prompt, action: permissions::ActionKind }
}

pub struct Node {
    pub id: NodeId,
    pub kind: NodeKind,
    pub on_pass: EdgeTarget,          // NOT Option — a node without a success path is a bug
    pub on_fail: EdgeTarget,          // NOT Option — a node without a failure path is THE bug
    pub emits: Vec<EvidenceKind>,     // what this node can prove. Drives the coverage check.
}

pub enum EdgeTarget { Node(NodeId), Terminal(Outcome), GiveUp }   // no implicit fallthrough

pub struct AdwSpec {
    pub id: AdwId,
    pub work_class: WorkClass,        // Chore | Bug | Feature | Hotfix | Custom(String)
    pub isolation: Isolation,         // Shared | Worktree | Sandbox
    pub lanes: u8,
    pub race: bool,
    pub max_iterations: u16,          // hard loop bound
    pub max_spend: TokenBudget,       // hard cap; exceeding is a Terminal, never a warning
    pub nodes: Vec<Node>,
}
```

```rust
// adw/evidence.rs  — STAGE 3
pub struct Evidence {
    pub criterion: CriterionId,
    pub node: NodeId,
    pub kind: EvidenceKind,
    pub verdict: Verdict,             // Satisfied | Refuted | Inconclusive
    pub proof: ProofBlob,             // command output / test name+result / diff hash / gate id
    pub at: UnixNanos,
}

/// THE GATE. Call before a run starts and again before it may report Complete.
pub fn check_coverage(goal: &Goal, spec: &AdwSpec) -> Result<(), Vec<CriterionId>>;
pub fn is_complete(goal: &Goal, ledger: &[Evidence]) -> bool;   // all required criteria Satisfied
```

### Four invariants that must hold at the type level, not by convention

1. **`on_pass` / `on_fail` are not `Option`.** A node lacking a failure path must not compile.
   This kills the silent-failure class structurally.
2. **`Goal.acceptance` non-empty**, enforced in the constructor. No goal without a definition
   of done.
3. **`AgentSpec.role: ModelRole`, never a model name string.** Satisfies the
   model-version-agnostic hard rule for free.
4. **`Human` nodes carry a `permissions::ActionKind`.** Reuse the existing consent engine —
   do not invent a second approval path, or autonomy levels and leases silently stop applying.

---

## 4. Build order

Ship in this order. Each slice is independently valuable and independently revertible.

| # | Slice | Effort | Gate before commit |
|---|---|---|---|
| **I1** ✅ | Bundled skill `adw_design` — **DONE 2026-07-31**, gate green | S | done |
| **W1** | `adw/goal.rs` — `Goal`, `AcceptanceCriterion`, `EvidenceKind`; `open_questions` non-empty ⇒ `Draft`. This is the **handoff artifact from a cleared wayfinder map**, not a rival planner. | S | fmt + check + `adw::` tests |
| **W2** | `neoth goal from-map <path>` — ingest a wayfinder map: `## Destination` → `Goal.intent`, `## Out of scope` → `non_goals`, `## Not yet specified` → `open_questions`, a resolved `wayfinder:task` ticket → the acceptance criteria. **Refuse** to emit a `Ready` goal while any criterion lacks a concrete `EvidenceKind`. Map text is untrusted-ish operator input → `defang_prompt_delimiters`. Plus a bundled skill teaching the *handoff discipline* (turning a resolved decision into a falsifiable criterion) — **not** a second mapping tool. | M | + skills tests |
| **I2** | `adw/spec.rs` + `adw/exec.rs` — encode NEOTH's **current** topology as the built-in `feature` spec; existing coding lane behaves **identically**. No new capability. This is the seam. | M | full `coding::` + `adw::` |
| **V1** | `adw/evidence.rs` — `Evidence`, `check_coverage`, `is_complete` | M | `adw::` |
| **V2** | Wire the coverage check: `check_coverage` before a run may start; `is_complete` before it may report success | M | `coding::` + `adw::` |
| **I3** | `adw/builtin.rs` — `chore` / `bug` / `feature` / `hotfix` specs with genuinely different shapes; deterministic router, agent only when the class must be inferred | M | `coding::` |
| **V3** | WAL evidence ledger — `ExtendedSubtype::{AdwNodeTransition, AdwEvidence}` | S | ⚠ see §5 |
| **I5** | Operator-authored specs from `~/.neoth/adw/<id>.yaml` + GUI panel | M | + `cargo check -p neothd-gui` |
| **V4** | `neoth adw explain <run-id>` — reconstruct the run from the WAL: node order, verdicts, spend, which criterion each piece of evidence satisfied | S | — |
| **I6** | Parallel lanes + racing over `coding/worktree.rs` | L | — |
| **I7** | *(v1.1)* `Isolation::Sandbox` — **design doc first** | L | — |

**Do I2 before V1.** The coverage check needs a spec to check against; building evidence
first leaves it with no consumer, which violates the no-primitive-ahead-of-its-consumer rule.

---

## 5. Traps — read before you build

### WAL opcodes are exhausted
Top-level opcodes are **255/255**. Every new event goes in the `ExtendedSubtype` band in
`wal/events.rs`, **and** the daemon allowlist in `daemon/audit_rpc/server.rs`, **and** its
exhaustive `allowlist_contains_exactly_*` test. Miss the test and it passes locally and
fails in CI. Mirror the existing `PluginRemovalIntent(0x12)` / `PluginRemovalResult(0x13)`
pair — it is the worked example.

### `cargo check --tests` compiles tests, it does not run them
Exhaustive-list tests, allowlist tests and schema-version pins only fail when tests actually
*run*. Before pushing anything that touches an enum, an allowlist or a schema version:
```bash
rg "contains exactly|== &\[|ALLOWED_|schema_version"
```

### Six `skills::` tests are ALREADY RED on this machine — not yours
Verified 2026-07-31 by A/B (stash the change, re-run, identical result):
`448 passed / 9 failed` both with and without the `adw_design` skill.
```
skills::creator::tests::create_recovers_interrupted_install_before_refusing_replacement
skills::installer::tests::mutation_journal_accepts_legacy_ids_only_for_removal
skills::loader::tests::authorized_quarantine_never_swallows_manifest_work_budget_exhaustion
skills::loader::tests::oversized_read_errors_are_charged_to_authorized_work_budget
skills::registry::tests::initial_load_propagates_existing_malformed_manifest
skills::registry::tests::watcher_rebind_failure_still_drops_installed_runtime_skills
```
Do not chase them as a regression from your work. **Do** re-run the A/B if you touch
`skills/` — the two `work_budget` ones are load-sensitive and could plausibly react to a
change in the bundled set.

### Local gates
```bash
MSYS_NO_PATHCONV=1 cmd /c "C:\Users\Shadow-PC\CascadeProjects\AGENTER\SRC\_gate_neoth.bat"
```
`cargo fmt --check` + `cargo check -p neoth --tests -j1`, ~4 min, `GATE_EXIT=0` on success.
Clippy is **not** in that gate and has caught real bugs the gate missed — run
`cargo clippy -p neoth --all-targets -- -D warnings` before any push. `-D warnings` applies
per target, so scope it with `--all-targets` or dead-code acks will surprise you.

### Do not run `cargo fmt` on the whole tree
`rustfmt` version skew against CI's older version. `skills/registry.rs:95` in particular:
CI's rustfmt wraps a line the local one collapses. CI is the authority — leave it alone.

### No parallel agents, no Workflow tool on this host
Parallel local subagents BSOD this machine. One sequential agent at a time is safe and
verified. Builds must not run concurrently with agents.

### Adding a bundled skill
Drop `assets/skills/<id>/skill.yaml`, add the `(id, include_str!(...))` tuple to
`BUNDLED_SKILLS` in `skills/bundled.rs` **alpha-sorted**. Both guard tests are
directory-driven, so no pinned id list needs editing — verified. Note some existing entries
are one-line (`("pme", include_str!(...)),`) so a line-anchored grep undercounts the array.

---

## 6. Scope fence

**In scope:** the three stages as typed artifacts, the coverage check, the executor over
NEOTH's existing node implementations, WAL evidence, CLI + GUI surfaces.

**Out of scope — do not build:**
- A visual workflow editor, a distributed scheduler, cron-per-node.
- A new agent runtime. Nodes call the existing `sub_agents/`, `coding/worker.rs`,
  `coding/provider_worker.rs`. **Zero new provider code.**
- Cloud sandboxes. NEOTH is local-first; `Isolation::Sandbox` is a locally-supervised
  environment and it is v1.1, behind its own design doc.
- Dropping engineering review once the system "feels trusted". For a daemon that can rewrite
  its own source, review is a safety boundary — `coding/self_source_gate.rs` (1980 lines)
  exists precisely because that gate must never become optional. This was proposed by the
  source talk and is **explicitly rejected**; do not re-litigate it.
- Racing as a default. N× spend for one result is for incidents only, behind an explicit
  spend confirmation.

---

## 7. Definition of done for the pipeline

The three stages are integrated when all of these hold:

1. `neoth wayfinder "<intent>"` produces a `Goal` whose every acceptance criterion carries a
   concrete `EvidenceKind`, and **refuses** to emit one while any criterion is unfalsifiable.
2. `check_coverage(goal, spec)` **rejects** a spec that cannot prove some required criterion,
   naming the unmapped criterion ids — and there is a test that asserts the rejection.
3. A coding run cannot report success while any required criterion lacks a `Satisfied`
   `Evidence` record — asserted by a test that fabricates a "the agent says it's done" run
   and watches it be refused.
4. `neoth adw explain <run-id>` reconstructs the whole run from the WAL alone.
5. GUI parity: goal view, spec list, run trace.
6. The built-in `chore` and `feature` specs have visibly different topologies, and a chore
   does not pay for the feature pipeline.

Item 3 is the one that matters. Everything else is scaffolding around it.

---

## 8. Provenance

Stage 2 (`ADW Design`) derives from a source-level analysis of IndyDevDan's talk
*"FORGET Loop Engineering. Agentic Engineering is about THIS"*
(`youtube.com/watch?v=VQy50fuxI34`, 2026-07-13, 34:18), watched with the `watch` skill —
full transcript plus ten diagram frames. Analysis: `PLAN/ADOPT_2026_07_31/G_indydevdan_adw.md`.
The ADW vocabulary is his and is credited in the skill manifest. **Nothing is vendored** — a
talk has no repository and no licence; the Rust types, invariants, the coverage check and the
Wayfinder and Evidence-Gated stages are NEOTH's own. No `THIRD_PARTY_LICENSES` entry is owed.
