# QUELLEN Adoption Report — mattpocock/skills

Date: 2026-05-21
Source: `QUELLEN/skills/` (mattpocock/skills, "Skills For Real Engineers")
Analyst: senior-ai-engineer agent

---

## 1. Project Philosophy

Matt Pocock's repo is explicitly anti-vibe-coding. The organizing principle is
**communication-gap engineering**: every skill either (a) closes the gap between
operator intent and agent action before coding starts, or (b) enforces a
practice so mechanically sound that agents can't skip it. Key intellectual debt:
John Ousterhout's *A Philosophy of Software Design* (deep modules, seams,
deletion test) + classic TDD (Kent Beck's tracer bullets, one-cycle-at-a-time).

Skills are small, composable, and deliberately not owning your whole process —
contrast to BMAD/Spec-Kit. Every skill has a YAML `name/description/argument-hint`
header which maps 1:1 to NEOTH's `SkillManifest.{id, description, trigger_keywords}`.

Buckets: `engineering/` (daily code), `productivity/` (non-code workflow),
`misc/` (personal/toolchain), `deprecated/` (superseded). An `.out-of-scope/`
dir holds writing/editing skills with no engineering relevance.

---

## 2. Skill Inventory and Classification

### 2.1 engineering/ — 10 skills

| Skill | Classification | Rationale |
|---|---|---|
| `tdd` | **ADOPT-AS-CORE** | Language-agnostic. The vertical-slice tracer-bullet loop + "never refactor while RED" + behavior-through-public-interface doctrine are unconditional quality gates that belong in NEOTH's `neoth code` workflow, not as an opt-in skill. Ports directly to `src/cli/code.rs` as a pre-implementation checklist enforced by the coding workflow. |
| `diagnose` | **ADOPT-AS-SKILL** | Meta-engineering. Phase loop (reproduce→minimise→hypothesise→instrument→fix→regression-test) is language-agnostic. Worth as `/diagnose` or auto-triggered on "debug"/"broken"/"failing" keywords. |
| `grill-with-docs` | **ADOPT-AS-SKILL** | Meta-engineering. Pre-commit grilling against domain model (CONTEXT.md + ADRs) prevents spec drift. NEOTH already has `CONTEXT.md` convention and `docs/adr/`. Maps cleanly to `/grill` trigger. |
| `improve-codebase-architecture` | **ADOPT-AS-SKILL** | Meta-engineering. Deep-module/seam vocabulary is language-agnostic and directly improves NEOTH's own Rust codebase. Trigger on "refactor"/"architecture"/"improve codebase". |
| `triage` | **ADOPT-AS-SKILL** | Meta-engineering. State-machine-driven issue lifecycle (needs-triage→needs-info→ready-for-agent→ready-for-human→wontfix). NEOTH kanban (`idx_kanban_*` in `views.db`, WAL 0x70..=0x76) is the storage backend; this skill becomes the editorial layer over it. |
| `to-prd` | **ADOPT-AS-SKILL** | Meta-engineering. PRD template (Problem/Solution/User Stories/Implementation Decisions/Testing Decisions/Out-of-Scope) is tool-agnostic. Plugs into NEOTH's kanban as a "describe and publish" flow. |
| `to-issues` | **ADOPT-AS-SKILL** | Meta-engineering. Tracer-bullet vertical slice decomposition is agnostic. Writes to `idx_kanban_*`; replaces manual `neoth code plan` drafts. |
| `zoom-out` | **ADOPT-AS-SKILL** | Meta-engineering. Zero model invocation — pure context-enrichment directive. Trigger: "zoom out", "how does this fit", "big picture". Trivial to port (system_prompt = one paragraph). |
| `prototype` | **ADOPT-AS-SKILL** | Meta-engineering. Two-branch router (state-machine/business-logic terminal app vs UI variation toggle). Language-agnostic concept; concrete scaffold will be Rust/CLI or Slint. Trigger: "prototype"/"spike"/"try a few designs". |
| `setup-matt-pocock-skills` | **SKIP-DUPLICATE** | NEOTH already has `/wizard` + `neoth init` for per-repo configuration. The three config sections (issue tracker, triage label vocabulary, domain docs) are subsets of what `neoth init` covers. |

### 2.2 productivity/ — 4 skills

| Skill | Classification | Rationale |
|---|---|---|
| `grill-me` | **ADOPT-AS-SKILL** | Meta-engineering. Non-code grilling (stress-test a plan, resolve decision tree). Distinct from `grill-with-docs` (no codebase exploration). Trigger: "grill me"/"stress-test my plan"/"challenge this". |
| `handoff` | **SKIP-DUPLICATE** | NEOTH `save-session` / `HANDOFF_*.md` pattern already covers compact context transfer between sessions. `/handoff` would be redundant unless integrated with NEOTH's WAL memory archive, which is a future item. |
| `write-a-skill` | **ADOPT-AS-SKILL** | Meta-engineering. Skill authoring harness (progressive disclosure, YAML header, bundled resources) informs NEOTH's own `neoth skill new` wizard. Port as documentation + skill-creation template rather than runtime skill. |
| `caveman` | **SKIP-OUT-OF-SCOPE** | Token-compression communication mode. Useful for Claude Code sessions but NEOTH operators are not token-budget-aware; operator-facing output style is governed by `freedom.yaml::output.verbosity`. |

### 2.3 misc/ — 4 skills

| Skill | Classification | Rationale |
|---|---|---|
| `git-guardrails-claude-code` | **SKIP-DUPLICATE** | NEOTH's `src/cli/hooks.rs` + `freedom.yaml::git.*` gates already block dangerous git ops via the TOML hooks engine. The Claude Code hook JSON format this skill emits is irrelevant to NEOTH's hook system. |
| `migrate-to-shoehorn` | **SKIP-LANGUAGE-SPECIFIC** | Migrates TS `as` type assertions to `@total-typescript/shoehorn`. No Rust equivalent; shoehorn is a TS-only library. |
| `scaffold-exercises` | **SKIP-OUT-OF-SCOPE** | Creates TypeScript course exercise directories with sections/problems/solutions/explainers. NEOTH is not a course-authoring tool. |
| `setup-pre-commit` | **SKIP-LANGUAGE-SPECIFIC** | Installs Husky + lint-staged + Prettier + tsc. Node.js/TS toolchain specific. NEOTH's pre-commit is `cargo fmt --check && cargo clippy && cargo test`. |

### 2.4 deprecated/ — 4 skills

All deprecated: `design-an-interface`, `qa`, `request-refactor-plan`,
`ubiquitous-language`. **SKIP** — superseded by `grill-with-docs` +
`improve-codebase-architecture` + `triage` in the active buckets.

---

## 3. Meta-Engineering vs Language-Specific Axis

```
META-ENGINEERING (port universally)          LANGUAGE-SPECIFIC (TS-only or skip)
─────────────────────────────────────────    ─────────────────────────────────
tdd                 → ADOPT-AS-CORE          migrate-to-shoehorn  → SKIP-TS
diagnose            → ADOPT-AS-SKILL         setup-pre-commit     → SKIP-TS
grill-with-docs     → ADOPT-AS-SKILL         scaffold-exercises   → SKIP-OOS
grill-me            → ADOPT-AS-SKILL         caveman              → SKIP-OOS
improve-codebase-architecture → ADOPT        git-guardrails       → SKIP-DUP
triage              → ADOPT-AS-SKILL         setup-matt-pocock-   → SKIP-DUP
to-prd              → ADOPT-AS-SKILL         handoff              → SKIP-DUP
to-issues           → ADOPT-AS-SKILL
zoom-out            → ADOPT-AS-SKILL
prototype           → ADOPT-AS-SKILL
write-a-skill       → ADOPT-AS-SKILL
```

Key insight: every skill in `engineering/` except `setup-matt-pocock-skills`
is meta-engineering practice. Matt's TS expertise shows up only in the `misc/`
toolchain skills; the engineering process skills are language-agnostic by design.

---

## 4. NEOTH Paths and Integration Notes

### 4.1 ADOPT-AS-CORE: tdd

Port the red-green-refactor discipline into `src/cli/code.rs` as a pre-flight
checklist injected before the coding-workflow hemispheres fire:

```
SRC/neothd/src/cli/code.rs
  → tdd_preflight::confirm_interface_changes()
  → tdd_preflight::confirm_behaviors_to_test()
  → tdd_preflight::identify_deep_module_opportunities()
```

WAL events: reuse `0x70..=0x76` coding-workflow band. No new YAML skill file
needed — bake into the Cerebellum orchestrator prompt in `SPEC_coding_workflow.md`.

### 4.2 ADOPT-AS-SKILL (8 skills)

Install to: `SRC/neothd/assets/skills/<id>/skill.yaml`
(loader auto-installs to `~/.neoth/skills/<id>/` on first run)

Target paths:

```
assets/skills/diagnose/skill.yaml
assets/skills/grill-with-docs/skill.yaml
assets/skills/improve-codebase-architecture/skill.yaml
assets/skills/triage/skill.yaml
assets/skills/to-prd/skill.yaml
assets/skills/to-issues/skill.yaml
assets/skills/zoom-out/skill.yaml
assets/skills/prototype/skill.yaml
assets/skills/grill-me/skill.yaml
assets/skills/write-a-skill/skill.yaml   ← doc/template, not runtime
```

Each `skill.yaml` maps:
- `id`: kebab-case name from SKILL.md header
- `description`: one-line from SKILL.md `description:` field
- `trigger_keywords`: derived from the SKILL.md `Use when…` clause
- `system_prompt`: full SKILL.md body (minus YAML frontmatter)
- `author`: "mattpocock"
- `homepage`: "https://github.com/mattpocock/skills"
- `tags`: ["meta-engineering", "workflow"] (+ language tag where applicable)

### 4.3 Stage-1 router keyword seeds

Quick reference for `trigger_keywords` population:

| skill id | keywords |
|---|---|
| diagnose | debug, diagnose, broken, failing, throwing, regression, performance regression |
| grill-with-docs | grill with docs, stress-test plan, challenge design, sharpen terminology |
| improve-codebase-architecture | improve architecture, refactor opportunities, deep module, testability, AI-navigable |
| triage | triage, create issue, review bug, feature request, AFK agent, issue workflow |
| to-prd | write prd, create prd, document feature, spec feature |
| to-issues | break into issues, create tickets, decompose plan, vertical slices |
| zoom-out | zoom out, big picture, how does this fit, broader context |
| prototype | prototype, spike, try a few designs, sanity-check data model, mock up |
| grill-me | grill me, stress-test my plan, challenge this, relentless questions |

### 4.4 CONTEXT.md / ADR convention

`grill-with-docs`, `improve-codebase-architecture`, `diagnose`, and `tdd`
all reference `CONTEXT.md` + `docs/adr/`. NEOTH already has this layout
(confirmed in `QUELLEN/skills/CONTEXT.md` structure mirrors NEOTH's own
`PLAN/` + `docs/adr/` directories). Operator-facing: wizard step should
document `CONTEXT.md` path during `neoth init`. Surface as `NOOB-UX-*` item.

---

## 5. Build Order

Priority: meta-engineering practices that immediately improve NEOTH's own code
quality first, then issue-workflow skills.

```
Pick 1 (CORE):  tdd preflight in code.rs                 — ~1 day
Pick 2:         diagnose + grill-me skill.yaml            — ~0.5 day
Pick 3:         grill-with-docs + improve-codebase-arch   — ~1 day
Pick 4:         triage + to-prd + to-issues               — ~1 day (requires kanban writes confirmed)
Pick 5:         zoom-out + prototype                      — ~0.5 day
Pick 6:         write-a-skill (template only)             — ~0.5 day
```

Total: ~4.5 days, all parallelisable with ongoing coding-workflow work (SPEC_coding_workflow.md Pick 2+).

---

## 6. What NEOTH Gains

- **Unconditional TDD gate** in every `neoth code` invocation (no operator config required, HARD RULE from `neoth_features_default_on_runtime_toggle.md`: default-ON, runtime-toggleable).
- **Diagnose skill** gives operators a structured debug loop that works in Rust, Python, shell, any language.
- **Grilling skills** close the intent-action gap before code is written — the #1 failure mode the author identified.
- **Deep-module vocabulary** (`improve-codebase-architecture`) gives NEOTH's Cerebellum orchestrator the language to identify refactor candidates in the operator's codebase and its own.
- **Issue lifecycle** (`triage`/`to-prd`/`to-issues`) wires cleanly into NEOTH's kanban WAL band, giving operators a full planning→execution pipeline from inside the chat interface.
