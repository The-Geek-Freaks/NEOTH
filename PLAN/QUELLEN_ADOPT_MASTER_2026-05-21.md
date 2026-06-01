# QUELLEN Adoption Master Plan — 2026-05-21

Synthesis of 7 parallel agent reports analysing
QUELLEN/cc-switch, codegraph, andrej-karpathy-skills,
academic-research-skills, skills (mattpocock), superpowers
(obra), and agency-agents for NEOTH adoption.

Each individual report sits next to this file as
`QUELLEN_ADOPT_<name>_2026-05-21.md`. This master synthesises
across them: cross-cuts that surface in multiple reports,
the deduped pick list, the build order.

## §1 Cross-cutting findings

### Finding A — NEOTH's biggest STRUCTURAL gap: code graph edges

`codegraph` agent flagged this most clearly. NEOTH's
`code_map` indexes symbols (`name + kind + line`) but stores
NO edge data. It cannot answer:
- "What functions call `fn X`?" (`calls` edges)
- "Which files import `module M`?" (`imports` edges)
- "What types extend `trait T`?" (`extends`/`implements`)

This is the single biggest data-model win — every other repo
INCLUDING `superpowers` indirectly assumes the agent can do
this kind of structural query. Path: new
`SRC/neothd/src/code_map/edges.rs` + schema migration on
`code_map.db` with `code_map_edges` table + BFS traversal
helpers + recall integration that boosts files reachable via
edges from already-selected files.

**Estimated effort: 3-4 commits, ~600 LOC**.

### Finding B — `MODE_REGISTRY` is a more general primitive than skills

Both `academic-research-skills` and `agency-agents` reports
flagged this. A **mode** is a higher-order construct than a
skill:

- A **skill** = `(trigger_keywords, system_prompt, tool_allowlist)`. Activated per message.
- A **mode** = `(name, spectrum, oversight_level, output_contract, agent_composition, system_prompt_addenda, trigger_phrases)`. Active across an entire session until the operator flips it.

NEOTH today has skills but no mode-as-state-machine. Adding
this gives operators `/mode research` / `/mode review` /
`/mode debug` / `/mode code` — and the daemon's per-turn
behaviour flips coherently in one lookup.

**Estimated effort: 2-3 commits, ~400 LOC** (extends
`SkillManifest` with a `modes` sibling + new
`/mode <id>` slash command + WAL band reservation).

### Finding C — Karpathy + superpowers + mattpocock all agree on META-skills

Five different reports independently flagged the same
pattern: certain skills should NOT route via keywords — they
should fire UNCONDITIONALLY as core preambles.

- **Karpathy P-1/P-2/P-3**: think-before-coding, simplicity-first, surgical-changes (~3 sentences each)
- **Superpowers brainstorming + writing-plans**: pre-code gates that enforce alignment before implementation
- **Mattpocock tdd**: vertical-slice tracer-bullet doctrine before any code task

The right architectural home: a `context_guards` /
`workflows` module that injects an always-on preamble into
every provider call BEFORE skill-specific prompts. NEOTH's
existing `permissions::evaluate` gate is the prior art —
same shape, different layer.

**Estimated effort: 1-2 commits, ~200 LOC**.

### Finding D — agency-agents gives the missing sub-agent CONTRACT

NEOTH has `sub_agents::` but the data shape passed between
caller + sub-agent is implicit (untyped JSON). agency-agents'
NEXUS protocol formalises `{from, to, context, acceptance_criteria, evidence_required, next_agent}`. Plus a `QaVerdict::{Pass, Fail(Vec<FailureItem>), Blocked(String)}` enum that NEOTH's review path could adopt for explicit structured handoff.

**Estimated effort: 1-2 commits, ~250 LOC** (extends
`SubAgentRequest`/`SubAgentResult` + adds `QaVerdict`).

### Finding E — cc-switch ports cherry-pick, not wholesale

The hope was to fork cc-switch wholesale. The cc-switch
agent's verdict: NO — cc-switch is Tauri 2 (React frontend)
which doesn't map to NEOTH's Slint GUI; the Rust backend has
extractable pieces but its core architecture (multi-CLI
config write-through) is antithetical to NEOTH's
self-contained rule. **Cherry-pick 5 pieces, skip the rest.**

The 5 picks (descending priority): provider preset catalog
+ GUI panel (~750 LOC), request-log + usage dashboard
(~650), local proxy + circuit-breaker (~600), skills
installer (~300), role-based model mapping (~150).

## §2 Master adoption table

| # | Item | Source | Category | Effort | NEOTH path |
|---|------|--------|----------|--------|------------|
| Q1 | Karpathy `context_guards` | karpathy | CORE | 0.5d | `src/providers/context_guards.rs` |
| Q2 | Code graph edges + BFS | codegraph | CORE | 3-4d | `src/code_map/edges.rs` |
| Q3 | MODE_REGISTRY pattern | academic + agency | CORE | 2-3d | `src/skills/modes.rs` + `/mode` slash |
| Q4 | Brainstorming + PlanWriter gates | superpowers | CORE | 1-2d | `src/workflows/brainstorm.rs` + `plan_writer.rs` |
| Q5 | NEXUS sub-agent handoff schema | agency | CORE | 1d | `src/sub_agents/schema.rs` extend |
| Q6 | `QaVerdict` enum | agency | CORE | 0.5d | `src/council/quality_score.rs` |
| Q7 | TDD pre-flight in cli/code | mattpocock | CORE | 1d | `src/cli/code.rs` (vertical-slice doctrine) |
| Q8 | Provider preset catalog + Slint panel | cc-switch | GUI+CORE | 2d | `src/providers/presets.rs` + `ui/providers.slint` |
| Q9 | Request-log + usage dashboard | cc-switch | GUI+CORE | 2d | `src/meter/request_log.rs` + `ui/usage.slint` |
| Q10 | Local proxy + circuit-breaker | cc-switch | CORE | 3d | `src/proxy/` (new module) |
| Q11 | Skills installer (GitHub ZIP/symlink) | cc-switch | CORE | 1d | `src/skills/installer.rs` |
| Q12 | Role-based model mapping | cc-switch | CORE | 0.5d | `src/providers/model_roles.rs` |
| Q13 | 6 new Council voices | agency | CORE | 1d | `src/council/voices.rs` extend |
| Q14 | SessionSummarizer Stop-hook | agency | HOOK | 0.5d | `src/sub_agents/session_summarizer.rs` |
| Q15 | Brainstorming hook (bootstrap) | superpowers | HOOK | 0.5d | `src/hooks/builtin/` (`session_start.toml`) |
| Q16 | Parallel-agents dispatcher | superpowers | SUB-AGENT | 1d | `src/sub_agents/parallel.rs` |
| Q17 | Two-stage review gate | superpowers | SUB-AGENT | 1d | `src/sub_agents/review.rs` extend |
| Q18 | Citation-check helper | academic | CORE | 1d | `src/recall/citation_check.rs` |
| Q19 | Fact-check claim_guard wire | academic | CORE | 0.5d | `src/profile/claim_guard.rs` extend |
| Q20 | Temporal-integrity verifier | academic | CORE | 1d | `src/profile/temporal_guard.rs` |
| Q21 | 5 superpowers P1 skill YAMLs | superpowers | SKILL | 0.5d | `assets/skills/` drops |
| Q22 | 9 mattpocock skill YAMLs | mattpocock | SKILL | 1d | `assets/skills/` drops |
| Q23 | 15 academic mode entries | academic | SKILL+MODE | 1d | Depends on Q3 |
| Q24 | 8 superpowers P4 skill YAMLs | superpowers | SKILL | 0.5d | `assets/skills/` drops |

**Total: 24 picks across 7 repos.**

## §3 Build order

### Sprint 1 — Quick wins + foundation (this session)

- **Q1 Karpathy context_guards** (0.5d) — proof of concept for the always-on preamble layer.

### Sprint 2 — Core data model (next 1-2 sessions)

- **Q2 Code graph edges + BFS** — biggest data-model gap.
- **Q3 MODE_REGISTRY** — biggest UX leap.

### Sprint 3 — Structural workflows (3-4 sessions)

- **Q4 Brainstorming + PlanWriter** — pre-code gates.
- **Q5 NEXUS handoff schema** — formal sub-agent protocol.
- **Q6 QaVerdict** — structured review outcome.
- **Q7 TDD pre-flight** — vertical-slice doctrine in cli/code.
- **Q13 Council voices** — 6 new perspectives.

### Sprint 4 — cc-switch cherry-pick (4-5 sessions)

- **Q12 Role-based model mapping** (0.5d) — smallest first.
- **Q11 Skills installer** (1d).
- **Q8 Provider preset catalog + Slint panel** (2d).
- **Q9 Request-log + usage dashboard** (2d).
- **Q10 Proxy + circuit-breaker** (3d).

### Sprint 5 — Skill library shipping (parallel, 2-3 sessions)

- **Q21-Q24** all skill YAML drops. Parallelisable — independent files.

### Sprint 6 — Specialised verifiers (1-2 sessions)

- **Q18 Citation-check** + **Q19 Fact-check** + **Q20 Temporal-integrity** — research-grade verification chain.

### Sprint 7 — Hooks + dispatchers (1 session)

- **Q14 SessionSummarizer** + **Q15 Brainstorming hook** + **Q16 Parallel-agents** + **Q17 Two-stage review**.

## §4 What we explicitly skip

- **Tauri AppHandle + React frontend (cc-switch)** — NEOTH's Slint GUI is the target.
- **Multi-CLI config write-through (cc-switch)** — antithetical to NEOTH's self-contained rule.
- **WebDAV provider (cc-switch)** — OpenDAL R-8 path already covers.
- **UsageScript JS eval (cc-switch)** — unsafe execution surface.
- **Chinese-only comments + zh-TW citation rules (cc-switch, academic)** — i18n later.
- **Claude Code marketplace packaging (karpathy)** — not portable.
- **Cursor IDE format (karpathy)** — wrong target IDE.
- **Karpathy P-4 (goal-driven execution)** — already shipped as verification-before-completion.
- **80+ agency-agents personas** — marketing/sales/design/game/finance divisions, out of scope.
- **Mattpocock TS-specific skills** (`migrate-to-shoehorn`, `setup-pre-commit`) — language-specific, not generalisable.
- **Web tree-sitter WASM runtime (codegraph)** — NEOTH uses Rust regex-based symbol extraction; not switching to tree-sitter.
- **MCP server process model (codegraph)** — NEOTH is in-process.

## §5 Memory rule additions

Update `[[neoth-research-synthesis]]` with the cross-cuts:

- **MODE_REGISTRY > skill router** for session-scoped behaviour flips.
- **Meta-skills are CORE** — Karpathy P-1/P-2/P-3 + superpowers brainstorming + plan-writing + mattpocock tdd are all context-guard preambles, NOT skill-router targets.
- **Code graph edges** are mandatory for any "what calls X / what imports Y / what extends Z" agent question. Symbol-name FTS5 (shipped) is necessary but not sufficient.
- **NEXUS handoff schema** is the formal sub-agent contract.
