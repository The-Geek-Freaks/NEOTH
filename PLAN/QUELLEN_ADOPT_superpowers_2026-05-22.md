# QUELLEN Adoption — obra/superpowers
> Date: 2026-05-22 | Source: `QUELLEN/superpowers/` | Target: `SRC/neothd/`

## Canonical Skill Inventory (14 total)

From `QUELLEN/superpowers/skills/`:

| # | Skill dir | Category |
|---|-----------|----------|
| 1 | `verification-before-completion` | Debugging |
| 2 | `systematic-debugging` | Debugging |
| 3 | `test-driven-development` | Testing |
| 4 | `brainstorming` | Collaboration/Structural |
| 5 | `writing-plans` | Collaboration/Structural |
| 6 | `executing-plans` | Collaboration/Structural |
| 7 | `dispatching-parallel-agents` | Collaboration/Structural |
| 8 | `requesting-code-review` | Collaboration |
| 9 | `receiving-code-review` | Collaboration |
| 10 | `using-git-worktrees` | Collaboration |
| 11 | `finishing-a-development-branch` | Collaboration |
| 12 | `subagent-driven-development` | Collaboration/Sub-agent |
| 13 | `writing-skills` | Meta |
| 14 | `using-superpowers` | Meta |

---

## Already Shipped

| # | Skill | Status |
|---|-------|--------|
| 1 | `verification-before-completion` | ✅ `assets/skills/verification_before_completion/skill.yaml` (2026-05-14) |
| — | Two-stage review gate | ✅ `sub_agents/review.rs` shipped; chat-pipeline wiring still open (~1h) |
| — | Skill-testing harness | ✅ `skills/test_harness.rs` + `neoth skills --run-tests <id>` (2026-05-14) |

---

## Classification of Unshipped Skills

### ADOPT-AS-SKILL (drop YAML into `assets/skills/`)

These encode operator-facing workflows the skill router should surface on demand. No daemon-wide enforcement needed — the operator invokes them explicitly.

#### SP-S1 — `systematic-debugging`
- **Why:** 4-phase root-cause discipline (Investigate → Pattern → Hypothesis → Implement). Complements `verification-before-completion`. No overlap with existing NEOTH primitives.
- **NEOTH hook:** Also register a `post_provider_call` TOML hook that auto-suggests this skill when a reply contains "exception", "panic", "error:" tokens — mirror of superpowers' auto-trigger logic.
- **Effort:** 1-2h (port SKILL.md + supporting technique files → skill.yaml, write trigger hook snippet)
- **Supporting files:** `root-cause-tracing.md`, `defense-in-depth.md`, `condition-based-waiting.md` — embed as `auxiliary:` entries in skill.yaml

#### SP-S2 — `test-driven-development`
- **Why:** RED-GREEN-REFACTOR discipline with rationalization table + red-flags. Superpowers version is more complete than NEOTH's current CLAUDE.md rule (includes anti-patterns list and "Iron Law").
- **Note:** NEOTH's `test_harness.rs` handles skill-level TDD; this skill covers code-level TDD — different layer.
- **Effort:** 1h (port SKILL.md; testing anti-patterns as auxiliary file)

#### SP-S3 — `requesting-code-review`
- **Why:** Pre-review checklist + template for reviewer sub-agent invocation. NEOTH has `sub_agents/review.rs` but no operator-facing skill that explains *when* and *how* to request review.
- **Effort:** 1h (port SKILL.md + `code-reviewer.md` as auxiliary)

#### SP-S4 — `receiving-code-review`
- **Why:** Forbidden-responses list + pushback protocol. Prevents the AI from silently accepting wrong feedback or rationalizing away valid criticism. Unique content, nothing in NEOTH covers this.
- **Effort:** 1h

#### SP-S5 — `writing-skills`
- **Why:** NEOTH ships `skills/test_harness.rs` — operators will write custom skills. This skill provides TDD-adapted skill-authoring methodology (RED = baseline scenario, GREEN = compliance, REFACTOR = close loopholes). Directly feeds the test harness.
- **Effort:** 1h (port SKILL.md; flowchart diagrams optional)

---

### ADOPT-AS-CORE (promote to Rust / daemon-wide primitive)

These encode invariants that must hold for every task, not just when the operator invokes a skill.

#### SP-C1 — `brainstorming`
- **Why:** The canonical NEOTH pre-code gate. obra's skill mandates: "Always brainstorm before entering plan mode. If operator says 'let's build X', trigger brainstorming first." This maps directly to NEOTH's `PreProviderCall` or `PreChannelIngress` hook — but the *logic* (Socratic Q&A → spec document → self-review) should live in a Rust module so it cannot be skipped by a mis-configured hook.
- **Concrete target:** `src/workflows/brainstorm.rs` — a `BrainstormGate` struct that the coding workflow (`src/cli/code.rs`, SPEC_coding_workflow.md) calls before dispatching to Left/Right hemispheres. Gate runs only when `request_type == FeatureRequest` (heuristic: no "fix", "debug", "list" verbs). Output: a markdown spec saved to `views.db::idx_kanban_spec` before any code tasks are created.
- **Config:** `freedom.yaml::brainstorm_gate.enabled` (default true).
- **Effort:** 2-3d

#### SP-C2 — `writing-plans`
- **Why:** Superpowers' plan format (header template, bite-sized checkbox tasks, "no placeholders" rule, self-review pass) is structurally what NEOTH's kanban task creation should produce. The plan format should be a Rust constant / template, not a skill the operator has to invoke.
- **Concrete target:** Fold into `src/workflows/plan_writer.rs` — called by `BrainstormGate` after spec is approved. Emits tasks to `idx_kanban_*`. Header template and "no placeholders" invariant enforced at write time (returns error if task description contains placeholder text).
- **Effort:** 1d (mostly integrating with existing kanban schema)

---

### ADOPT-AS-HOOK (TOML hook, not a skill invocation)

These are lifecycle events that should fire automatically, not on-demand.

#### SP-H1 — `using-superpowers` bootstrap
- **What it does in obra:** On `SessionStart`, injects the `using-superpowers` skill as system context so the AI always knows the skill library exists.
- **NEOTH equivalent:** `OnSessionStart` → load `~/.neoth/skills/` index → prepend skill manifest to system prompt. This is already planned for Phase 30 (`OnSessionStart` hook stage is defined in `hooks/stages.rs` but not yet wired).
- **Action:** When Phase 30 lands, emit a built-in `session-start` TOML hook entry in `assets/hooks/builtin.toml` that injects the skill registry summary (skill names + descriptions, not full content) into the system context.
- **Effort:** included in Phase 30 scope

#### SP-H2 — `finishing-a-development-branch` (partial)
- **Why:** The "verify tests before merge" check and "cleanup worktree after merge" steps are safety invariants. The operator-choice menu (merge/PR/keep/discard) belongs in a skill, but the *guard* (refuse to merge if tests fail) belongs in a `pre_egress` hook or the `neoth finish` CLI command.
- **Action:** Add `--verify-tests` flag to `neoth finish` / `neoth branch` CLI commands when those land. The full skill also becomes SP-S6 (see below).
- **Effort:** 0.5d

---

### ADOPT-AS-SUB-AGENT (multi-stage workflow needing own sub-agent)

#### SP-A1 — `subagent-driven-development` (partial — core already shipped)
- **Status:** `sub_agents/review.rs` ships the two-stage review gate (spec compliance → code quality). The missing piece is the **controller loop**: dispatch fresh sub-agent per kanban task → await result → run two-stage review → gate next task on review verdict.
- **Concrete target:** `src/sub_agents/task_executor.rs` — controller that iterates `idx_kanban_pending`, dispatches `AgentTask` per item, pipes result through `two_stage_review()`, writes verdict + WAL `0x84`. Wired into `neoth code` flow after SP-C1+SP-C2.
- **Effort:** 1-2d (chat-pipeline wiring for review gate is already the open 1h item from memory)

#### SP-A2 — `dispatching-parallel-agents`
- **Why:** fanout pattern (identify independent domains → create focused tasks → dispatch in parallel → integrate) is more complex than a skill doc. NEOTH already has sub-agent infrastructure. This skill's decision tree (when to fan out vs sequential) should be encoded in `task_executor.rs` as a `ParallelDispatch` mode alongside `SequentialDispatch`.
- **Effort:** 1d (extend SP-A1 controller with fan-out scheduling)

---

### ADOPT-AS-SKILL (secondary, lower priority)

#### SP-S6 — `finishing-a-development-branch`
- **Why:** Operator-facing guide (options menu: merge/PR/keep/discard + cleanup steps). The safety guard is SP-H2; this is the UX layer.
- **Effort:** 0.5h (port SKILL.md)

#### SP-S7 — `executing-plans`
- **Why:** Fallback execution mode when subagent dispatch is not used (inline, checkpoint-based). Operators running NEOTH in solo-CLI mode will want this.
- **Effort:** 0.5h (port SKILL.md)

#### SP-S8 — `using-git-worktrees`
- **Why:** NEOTH operators on worktree-based workflows. Not critical path — include in next skill-pack batch.
- **Effort:** 0.5h (port SKILL.md + quick-reference)

---

### SKIP-DUPLICATE

None. NEOTH has no exact duplicates in the shipped skill set. `verification-before-completion` is the only previously ported item.

---

### SKIP-OUT-OF-SCOPE

| Skill | Reason |
|-------|--------|
| `using-superpowers` (full) | obra bootstrap is harness-specific (Claude Code plugin injection). NEOTH replaces it with SP-H1 session-start hook above. |
| Cross-harness packaging (`.claude-plugin/`, `.codex-plugin/`, `.cursor-plugin/`) | NEOTH is its own harness; no plugin manifest needed. |

---

## Structural Observation — "Brainstorm-First" as NEOTH Core Primitive

obra's canonical acceptance test: *"Let's make a react todo list" must auto-trigger `brainstorming` before any code is written.*

This is architecturally the same as NEOTH's existing `PermissionToken` gate pattern. The right NEOTH implementation is **not** a skill-router match — it is a `BrainstormGate` in `src/workflows/` that fires unconditionally for feature-request intents, upstream of the Left/Right hemisphere dispatch. Classifying this as a skill would allow it to be skipped by routing miss.

Same logic applies to `writing-plans`: the plan format is a structural invariant of every kanban task, not an on-demand operator tool.

---

## Build Order (priority-sequenced)

| Priority | Item | Classification | Effort | Depends On |
|----------|------|---------------|--------|-----------|
| P1 | SP-S1 `systematic-debugging` | ADOPT-AS-SKILL | 1-2h | — |
| P1 | SP-S2 `test-driven-development` | ADOPT-AS-SKILL | 1h | — |
| P1 | SP-S3 `requesting-code-review` | ADOPT-AS-SKILL | 1h | — |
| P1 | SP-S4 `receiving-code-review` | ADOPT-AS-SKILL | 1h | — |
| P1 | SP-S5 `writing-skills` | ADOPT-AS-SKILL | 1h | test_harness.rs (shipped) |
| P2 | SP-A1 chat-pipeline wiring for two-stage review | ADOPT-AS-SUB-AGENT | 1h | review.rs (shipped) |
| P2 | SP-H2 `finishing-a-development-branch` guard | ADOPT-AS-HOOK | 0.5d | neoth finish CLI |
| P3 | SP-C1 `BrainstormGate` | ADOPT-AS-CORE | 2-3d | SPEC_coding_workflow |
| P3 | SP-C2 `PlanWriter` | ADOPT-AS-CORE | 1d | SP-C1 |
| P3 | SP-A1 full task-executor controller | ADOPT-AS-SUB-AGENT | 1-2d | SP-C1, SP-C2 |
| P3 | SP-A2 parallel dispatch mode | ADOPT-AS-SUB-AGENT | 1d | SP-A1 |
| P4 | SP-H1 session-start skill-registry injection | ADOPT-AS-HOOK | Phase 30 | hooks Phase 30 |
| P4 | SP-S6/S7/S8 remaining skill docs | ADOPT-AS-SKILL | 1.5h total | — |

**Total P1 (skill drops): ~5h**
**Total P2 (wiring + guard): ~1.5d**
**Total P3 (core workflow): ~5-7d**
