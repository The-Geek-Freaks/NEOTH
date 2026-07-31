# G — AI Developer Workflows (IndyDevDan) → NEOTH integration plan

**Source.** IndyDevDan, *"FORGET Loop Engineering. Agentic Engineering is about THIS"*,
`youtube.com/watch?v=VQy50fuxI34`, published 2026-07-13, 34:18.
**Method.** Watched with the `watch` skill (bradautomates/claude-video, MIT), installed
2026-07-31 to `~/.claude/skills/watch` with `yt-dlp 2026.07.04` + `ffmpeg 8.1.2`.
Two passes: full caption transcript (941 segments → 36 KB de-rolled), then ten
transcript-cue frames at 1024 px on the diagram beats
(5:33, 7:35, 9:37, 10:58, 13:42, 16:25, 17:46, 19:46, 20:26, 29:16).
Every architectural claim below was read off an actual frame, not inferred from speech.

**Nothing is vendored.** The video is a talk; there is no repository and no licence to
inherit. What follows is our own design, using the author's vocabulary with credit.

---

## 1. What the talk actually argues

Thesis: *"loop engineering"* is a bad rebrand of the software development life cycle. The
loop is one control-flow construct inside a much larger object — an **AI Developer Workflow
(ADW)**: an explicit graph whose nodes are typed as **code**, **agent**, or **human**, with
pass/fail edges routing between them.

### The three actors of value creation

Engineers, agents, and code. Reliability ranking stated explicitly: **code > engineers >
agents**. Code is the "unsung hero" — zero token cost, no hallucination, identical result
every run, runs at light speed. The failure mode he keeps naming is over-indexing on agents
because agents are the exciting actor.

### The two constraints of agentic engineering

The engineer appears at exactly two points: **prompting/planning** at the front and
**reviewing/validation** at the back. "If you're agentic engineering at scale properly,
you're showing up at the beginning and the end with a few exceptions."

### The progression ladder (each rung verified from a frame)

| # | Frame | Shape |
|---|---|---|
| 1 | — | `[Engineer Prompt] → (Build Agent) → [Engineer Review]` |
| 2 | 5:33 | `+ <Lint Code>` diamond; `fail →` back to Build Agent, `pass →` Review. **This edge is the entire "loop".** |
| 3 | 7:35 | `+ <Format Code> + <Test Code>` — three sequential code diamonds, each failing back to the same Build Agent |
| 4 | — | Collapse the validation diamonds into a single **Test Agent** ("scaling compute to scale impact / adding compute to add confidence") |
| 5 | — | `+ Planner Agent` at the front |
| 6 | 9:37 | **Worktrees.** `</> Build Worktree Code` fans out to N lanes, each `Planner → Build → Test → Engineer Review`, converging on `Merge → Ship` |
| 7 | 10:58 | **Agent sandboxes** replace worktrees — identical lane topology, full isolation, operator can step into a lane mid-run. *"Worktrees are a great place to start, not a great place to end."* |
| 8 | 13:42 | **Kanban intake.** `Support/Product/Engineer → </> Kanban Ticket → </> Status: Planning → Scout Agent → Plan Agent → </> Status: Building → Build Agent → …` — note the *code* nodes doing status transitions, and that advanced teams skip the human `Engineer Prompt` node entirely |
| 9 | 16:25 | **Hotfix ADW.** `Engineer Prompt → Scout Agent → Hot Fix Agent → [Approve/Reject]` (human in the middle, deliberately) `→ approve → </> Build Sandboxes →` N racing sandboxes; first passing solution wins → Review → Ship |
| 10 | 19:46 / 20:26 | **Software factory.** `</> Start Factory → </> Status: In Progress → Factory Router Agent → </> Setup Sandbox →` branches by work class into **Hotfix Sandbox / Feature Sandbox / Bug Sandbox / Chore Sandbox / "Any specialized ADW you need"** — each with a *different node topology* |

The chore lane is visibly the cheapest (`Build Agent → <Lint> → <CI/CD> → Review`); the
feature lane is the richest (`Planner → Build → Test → <CI/CD> → Review`). That asymmetry is
the point: you do not run the feature pipeline for a chore.

### Model tiering per node

Stated at 20:26: the build agent can be a **workhorse** model, but planner and scout should
be **state-of-the-art** "so nothing gets missed"; a chore gets "a single agent with a
workhorse model, maybe even a lightweight model". Routing criterion: *best price, best
performance, right speed*.

### The seven recommendations (26:33 – 31:57)

1. **KISS.** Start with the simplest workflow that does something.
2. **Separate code from agents — the load-bearing advice.** Verbatim: *"I'm not saying write
   a skill, have your agent build, and then at the bottom of the skill, run lint. Separate
   this out. Use an agent SDK, run a build agent, do work, and then run a linter. And when
   the linter fails, pass that back into the build agent with the same session ID… Otherwise
   you just have an agent calling code. That's not what we want."* One mega-skill with a
   hundred nodes has *"massive testing, massive validation problems"*.
3. **Design by doing the work yourself first.** Run the workflow end to end manually,
   step into every node, watch each condition fire — then write it as code+agents. He
   recommends drawing it in **mermaid** (mermaid.live).
4. **Use agents AND code.** Moving skill work into code is not about token cost — it is
   about performance, reliability and speed.
5. **Information orchestration.** You need a defined place for the artifact between every
   pair of steps. "That is what context engineering is."
6. **Classic engineering patterns matter more, not less** — isolatable, decoupled, single
   interface — because the workflow gets multiplied hundreds of times.
7. **Specialisation beats out-of-the-box agents.** Template your expertise into the workflow.

Closing distinction, worth keeping: *"Vibe coding is not knowing how the system works and
not looking at how the system works. Agentic engineering is knowing your system works so
well you don't have to look."*

---

## 2. NEOTH ground truth — verified, not assumed

```
rg -n 'enum (NodeKind|StepKind|WorkflowNode|PipelineNode|StageKind)' --type rust SRC/neothd/src
  → ZERO hits
```

| Capability | NEOTH today | Verdict |
|---|---|---|
| Kanban board | `coding/types.rs::{KanbanSessionId,KanbanTaskId}`, `coding/store.rs` (1382), `coding/decomposer.rs` (1059) turns a prompt into atomic kanban tasks, `coding/plan_writer.rs` owns the board write | **Have it.** Rung 8's intake exists. |
| Worktree isolation | `coding/worktree.rs` (987): `worktree_path_for`, `create_task_worktree`, `apply_patch_in_worktree`, `cleanup_worktree`, `is_worktree_dirty`; consumed by `coding/dispatcher.rs::apply_patch_via_worktree` + `run_worktree_tests` | **Have it.** Rung 6. |
| Validation nodes | `coding/validate.rs` (481), `cargo_check.rs` (402), `tdd_preflight.rs`, `review.rs` (631), `second_opinion.rs`, `plan_review.rs` | **Have them** — as hardcoded stages |
| Retry / stop | `coding/retry.rs`, `coding/early_stop.rs`, `council/stop_verifier.rs` | **Have it** |
| Parallel agents | `sub_agents/parallel.rs` (602), `sub_agents/runtime.rs` (728) | **Have it** |
| Model tiering | `providers/model_roles.rs::ModelRole{Flagship,Balanced,Fast,Vision,Embedding}` (490), `coding/model_profile.rs` (493), `models/hemisphere_preset.rs`, `coding/classifier.rs` routes a kanban task Left(Fast)/Right | **Have it** — but bound to hemisphere classification, not to a workflow node |
| Declarative spec | `recipes/schema.rs` (285): `RecipeSpec`, `SubRecipe`, `RetryPolicy`, `RecipeParameter`; `recipes/render.rs` (314) renders it | **Partial — schema only, no executor.** This is a prompt-recipe renderer, not a workflow engine. |
| **Typed workflow node** | — | **ABSENT** (grep above) |
| **Declarative multi-topology graph** | — | **ABSENT.** `coding/dispatcher.rs` (3281) is one hardcoded topology. |
| **Work-class router** | `coding/intent.rs`, `general_task_intent.rs`, `classifier.rs` classify *intent* and *hemisphere* | **ABSENT as a topology selector** — nothing picks a different pipeline shape per work class |
| **Agent sandbox** (beyond git worktree) | — | **ABSENT.** Rung 7 not reached. |
| **Racing lanes** | — | **ABSENT** |

**Honest summary: NEOTH already implements one good ADW — hardcoded in Rust.** What it
cannot do is let the operator *declare a different one*. Every rung up to 6 exists inside
`coding/dispatcher.rs`; rungs 7–10 (sandboxes, per-class topologies, factory router,
racing) do not exist at all, and none of the existing rungs are addressable as data.

---

## 3. The integration: an ADW engine

### Design

A small, typed, declarative graph executor. NEOTH's existing stages become node
*implementations*; the graph becomes data the operator can read, edit and version.

```rust
// coding/adw/spec.rs  — the data
pub enum NodeKind {
    Code(CodeOp),        // deterministic, zero tokens: Lint, Format, Typecheck,
                         // Test, Build, Status(transition), Git(op), Shell(allowlisted)
    Agent(AgentSpec),    // { role: ModelRole, sub_agent: SubAgentId, budget: TokenBudget }
    Human(GateSpec),     // { prompt, permissions::ActionKind } — the consent gate
}

pub struct Node { id: NodeId, kind: NodeKind, on_pass: EdgeTarget, on_fail: EdgeTarget }
pub enum EdgeTarget { Node(NodeId), Terminal(Outcome), GiveUp }   // no implicit fallthrough

pub struct AdwSpec {
    id: AdwId,
    work_class: WorkClass,          // Chore | Bug | Feature | Hotfix | Custom(String)
    isolation: Isolation,           // Shared | Worktree | Sandbox
    lanes: u8,                      // >1 = fan-out; race: bool decides first-wins vs all-must-pass
    max_iterations: u16,            // hard loop bound — no unbounded retry
    max_spend: TokenBudget,         // hard cap; exceeding it is a Terminal, not a warning
    nodes: Vec<Node>,
}
```

Four properties are non-negotiable and follow directly from the talk plus NEOTH's own rules:

1. **Both edges are mandatory.** `on_pass` and `on_fail` are not `Option`. A node without a
   failure path does not compile. This is what kills the silent-failure class.
2. **Loops are bounded by construction.** `max_iterations` and `max_spend` live on the spec,
   not in a node's prose. Hitting either is a `Terminal(Outcome::Exhausted)` that surfaces —
   never a silent stop.
3. **Model roles, never model names.** `AgentSpec.role: ModelRole` resolves through the
   existing catalog. Satisfies the model-version-agnostic hard rule for free.
4. **`Human` nodes are `permissions::ActionKind` gates.** They reuse the existing consent
   engine rather than inventing a second approval path, so autonomy level and lease rules
   apply unchanged.

### Why this is the right shape for NEOTH specifically

- It is **subtractive, not additive**: `coding/dispatcher.rs` (3281 lines) currently encodes
  the topology *and* the node behaviour in one file. Extracting the topology as data makes
  the dispatcher smaller and each node independently testable — the file is well past the
  800-line house limit and this is the natural seam.
- It gives `recipes/schema.rs` the executor it has been missing since it was written.
- It makes the ADW auditable: every node transition is a WAL event, so the operator can
  reconstruct what each node decided after the fact. That is exactly the "know your system"
  standard the talk closes on, and NEOTH already has the durable log to do it.

### Explicit non-goals

- **Not a general-purpose workflow product.** No visual editor, no cron-per-node, no
  distributed scheduler. This orchestrates NEOTH's own coding lane.
- **Not a new agent runtime.** Nodes call existing `sub_agents/`, `coding/worker.rs`,
  `provider_worker.rs`. Zero new provider code.
- **No hosted sandboxes.** The talk assumes cloud sandbox infrastructure. NEOTH is
  local-first; `Isolation::Sandbox` means a locally-supervised isolated environment, and it
  is v1.1 scope. `Worktree` covers v1.0 and already exists.

---

## 4. Build order — staged slices

**Slice I-1 — the skill (SHIPPED 2026-07-31).** `assets/skills/adw_design/skill.yaml` +
`skills/bundled.rs` entry. Teaches the discipline: type every node, push work down the
reliability ladder, both edges mandatory, bound every loop, one topology per work class.
Zero engine dependency; useful the moment it routes. *Needs `_gate_neoth.bat` before commit.*

**Slice I-2 — `AdwSpec` + executor over the existing pipeline (M).**
`coding/adw/{spec,exec}.rs`. Encode NEOTH's *current* coding topology as the built-in
`feature` spec and run it through the executor. Success criterion: the existing coding lane
behaves identically, but the topology is now data. No new capability, no user-visible change
— this is the seam, and it must land before anything else.

**Slice I-3 — work-class topologies + router (M).** Built-in `chore`, `bug`, `feature`
specs with genuinely different shapes (chore = one agent + lint + review; feature = the
current full pipeline). Router is **deterministic code** when the class is already known
(kanban label, CLI flag), and only escalates to `coding/classifier.rs` when it must be
inferred. Consumer: `cli/code.rs`.

**Slice I-4 — WAL node-transition audit (S).** One `ExtendedSubtype::AdwNodeTransition`
carrying `{adw_id, run_id, node_id, verdict, iteration, spend}`. Top-level opcodes are
255/255 exhausted, so the Extended band plus the daemon allowlist plus its exhaustive
`allowlist_contains_exactly_*` test. Consumer: `neoth code run --explain`, GUI run view.

**Slice I-5 — operator-authored specs (M).** Load `AdwSpec` from
`~/.neoth/adw/<id>.yaml`, validated at load: unknown node id → reject; missing `on_fail` →
reject; unreachable node → reject; absent `max_iterations`/`max_spend` → reject. Untrusted
content path: a spec is operator-authored config, but any string it injects into a prompt
goes through `defang_prompt_delimiters` like everything else. GUI panel for the spec list +
per-run node trace (Rule 3 parity).

**Slice I-6 — parallel lanes and racing (L).** `lanes > 1` fans out over the existing
`coding/worktree.rs`; `race: true` takes the first lane that passes validation and cancels
the rest. Hard requirement: cancellation must actually reclaim the token budget, otherwise
racing silently costs N× forever. Gate behind an explicit spend confirmation.

**Slice I-7 (v1.1) — `Isolation::Sandbox`.** A locally-supervised isolated environment per
lane, following the `media/docling.rs` owned-supervisor precedent. Needs its own design
doc — process isolation, filesystem scoping and network policy are each a real decision.

### Files per slice

| Slice | New | Modified |
|---|---|---|
| I-1 ✅ | `assets/skills/adw_design/skill.yaml` | `skills/bundled.rs` |
| I-2 | `coding/adw/{mod,spec,exec}.rs` | `coding/dispatcher.rs` (topology extracted out) |
| I-3 | `coding/adw/builtin.rs` | `cli/code.rs`, `coding/classifier.rs` |
| I-4 | — | `wal/events.rs`, `daemon/audit_rpc/server.rs` (+ exhaustive allowlist test) |
| I-5 | `coding/adw/load.rs` | `config/`, GUI panel + `neothd-gui/ui/` |
| I-6 | — | `coding/adw/exec.rs`, `coding/worktree.rs`, `providers/quota.rs` |
| I-7 | `coding/adw/sandbox.rs` | design doc first |

---

## 5. Where the talk is wrong for us, and where it is right

**Right, and we should act on it:**
- Code/agent separation as a *node boundary*, not a code-style preference. NEOTH's existing
  validation logic is already separate — the gap is that it is not addressable.
- One topology per work class. NEOTH currently runs one pipeline for everything.
- Bounded loops and named artifacts between nodes.
- Model role per node rather than per session.

**Wrong or inapplicable for NEOTH:**
- **Cloud sandboxes as the end state.** The talk assumes rented compute and predicts agent
  sandboxes will be "the majority of computers out there". NEOTH is local-first and
  single-operator; a per-lane sandbox on Alex's own machine is the ceiling, and worktrees
  cover most of the value.
- **"The best teams never touch the product themselves"** and dropping engineering review.
  For a self-editing daemon that can rewrite its own source, review is a safety boundary,
  not a productivity tax — `coding/self_source_gate.rs` (1980 lines) exists precisely
  because that gate must not be optional.
- **Racing as a habit.** N× spend for one result is defensible for a production incident and
  indefensible as a default. Gate it behind explicit spend confirmation.
- **The org/kanban framing** assumes a team with support and product filing tickets. NEOTH's
  operator is one person; the intake half of rung 8 matters much less than the topology half.

---

## 6. Attribution

No code, text or diagram from the video is reproduced. The ADW vocabulary (AI Developer
Workflow, three actors of value creation, software factory) is IndyDevDan's and is credited
in the skill manifest and here. The engine design, the Rust types, the invariants and the
slice plan are NEOTH's own. Nothing is added to `THIRD_PARTY_LICENSES` because nothing of
his ships.
