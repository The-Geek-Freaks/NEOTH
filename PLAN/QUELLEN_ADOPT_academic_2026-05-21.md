# QUELLEN Adoption: academic-research-skills → NEOTH
*Analyzed: 2026-05-21. Source: `QUELLEN/academic-research-skills/` v3.9.4.2*

---

## 1. Repository Character

**Meta-framework, not a simple skill library.**

ARS is a 4-skill suite (deep-research, academic-paper, academic-paper-reviewer, academic-pipeline) backed by a 25-mode registry, multi-agent pipelines (13 agents per skill), YAML schema contracts, deterministic lint scripts, and a Material Passport system for cross-session state. The operator does not edit YAML — they phrase a natural-language request; the skill's CLAUDE.md does intent-based mode dispatch.

Layout:
```
QUELLEN/academic-research-skills/
├── MODE_REGISTRY.md          ← single-source-of-truth: 25 modes × 4 skills
├── deep-research/            ← 7 modes, 13-agent pipeline
│   └── SKILL.md
├── academic-paper/           ← 10 modes, 12-agent pipeline
│   └── SKILL.md
├── academic-paper-reviewer/  ← 6 modes
│   └── SKILL.md
├── academic-pipeline/        ← orchestrator (1 mode + resume_from_passport)
│   ├── SKILL.md
│   └── agents/               ← claim_ref_alignment_audit_agent + others
├── shared/
│   ├── contracts/passport/   ← YAML schemas (claim_audit_result, etc.)
│   ├── mode_spectrum.md
│   └── references/           ← intent_clarification_protocol, etc.
└── scripts/                  ← deterministic lints + migration tools
```

---

## 2. MODE_REGISTRY Pattern — CORE NEOTH PRIMITIVE ★

**This is the most important finding. Flag: ADOPT-MODE-REGISTRY.**

### What ARS does

`MODE_REGISTRY.md` is a table-driven registry with one row per mode. Each row carries:
- `Mode` id (e.g., `lit-review`, `fact-check`, `socratic`)
- `Spectrum` — `fidelity | balanced | originality` (controls how template-heavy the output is)
- `Output` shape (format + length contract)
- `Oversight` level — `Low / Medium / High / Very High` (how much operator confirmation is required)
- `Triggers` — keyword phrases that activate the mode

When the operator says "do a systematic review on X", the skill matches `systematic-review`, flips to its agent composition, output contract, and oversight level — in a single declarative lookup. The orchestrator (academic-pipeline) uses the registry as the routing table for multi-skill dispatch.

### Why this is a NEOTH core primitive

NEOTH's skill system already has `trigger_keywords + system_prompt + tool_allowlist` per manifest. That is a **mode**. The gap is: NEOTH has no registry layer above the skill — no concept of a named mode that an operator can address by name (`/mode lit-review`), no `spectrum` or `oversight` metadata, and no orchestrator that can switch between modes within one skill session.

**The MODE_REGISTRY pattern maps cleanly onto NEOTH architecture:**

```
Current NEOTH skill.yaml            Proposed NEOTH mode entry
─────────────────────────────       ─────────────────────────────────────
trigger_keywords: [...]             trigger_phrases: [...]
system_prompt: ...                  system_prompt: ...
tool_allowlist: [...]               tool_allowlist: [...]
                                    spectrum: fidelity|balanced|originality
                                    oversight: low|medium|high|very_high
                                    output_contract: {format, length_hint}
```

Concrete implementation path:
1. Extend `SRC/neothd/src/skills/manifest.rs` `SkillManifest` with optional `modes: Vec<ModeEntry>` field (additive, non-breaking — skills without modes behave identically).
2. Add `ModeRegistry` struct in `SRC/neothd/src/skills/mode_registry.rs` — flat lookup table built at daemon start from all loaded skills.
3. Slash command `/mode <id>` and CLI `neoth mode <id>` write `freedom.yaml::active_mode` and reload the active `system_prompt + tool_allowlist` without restarting.
4. Operator message "fact-check these claims" → Stage-1 keyword scan hits `mode:fact-check` before hitting a full skill match → injects mode's system_prompt delta on top of the skill base prompt.

This unifies NEOTH's skill router, proactive activation, and operator `/mode` command under one data model. Every skill can declare 1..N modes; the registry is the operator-visible surface.

**WAL event: reserve `0xB0..=0xBF` for mode-lifecycle events** (`0xB0 MODE_ACTIVATE`, `0xB1 MODE_SWITCH`, `0xB2 MODE_DEACTIVATE`).

---

## 3. Mode Enumeration and Classification

### 3.1 deep-research (7 modes)

| Mode | Classification | Rationale |
|------|---------------|-----------|
| `full` | **ADOPT-AS-SKILL** | Port as `~/.neoth/skills/research-full/skill.yaml`. Maps to existing NEOTH recall + provider pipeline. |
| `quick` | **ADOPT-AS-SKILL** | `~/.neoth/skills/research-quick/skill.yaml`. Brief synthesis mode, recall-lite path. |
| `lit-review` | **ADOPT-AS-SKILL** | `~/.neoth/skills/research-lit-review/skill.yaml`. Annotated bibliography output contract. |
| `fact-check` | **ADOPT-AS-CORE** | Claim-by-claim verification maps to `SRC/neothd/src/profile/claim_guard.rs` + `validate.rs`. Port the ARS fact-check agent prompt into a new `SRC/neothd/src/profile/fact_check.rs` that chains through the existing `ProfileClaimGuard` (H1+H2+H5+M1+M2) and emits WAL frames. |
| `socratic` | **ADOPT-AS-SKILL** | `~/.neoth/skills/research-socratic/skill.yaml`. Intent-based activation (not keyword) — add `intent_activation: true` flag to manifest to tell the Stage-2 Qwen re-ranker to use semantic match, not keyword hit. |
| `review` | **ADOPT-AS-SKILL** | `~/.neoth/skills/research-review/skill.yaml`. Source evaluation mode; overlaps with `academic-paper-reviewer`. |
| `systematic-review` | **ADOPT-AS-SKILL** | `~/.neoth/skills/research-systematic/skill.yaml`. PRISMA output contract; long-form, high oversight. |

### 3.2 academic-paper (10 modes)

| Mode | Classification | Rationale |
|------|---------------|-----------|
| `full` | **ADOPT-AS-SKILL** | `~/.neoth/skills/paper-full/skill.yaml`. Heavy multi-agent pipeline — adapt as a skill system_prompt that orchestrates NEOTH hemispheres (Cerebellum→Left→Right from coding-workflow spec). |
| `plan` | **ADOPT-AS-SKILL** | `~/.neoth/skills/paper-plan/skill.yaml`. Socratic guided writing; same intent-activation flag as `socratic` above. |
| `outline-only` | **ADOPT-AS-SKILL** | `~/.neoth/skills/paper-outline/skill.yaml`. Low complexity. |
| `revision` | **ADOPT-AS-SKILL** | `~/.neoth/skills/paper-revision/skill.yaml`. Requires ingesting reviewer comments as context. |
| `revision-coach` | **ADOPT-AS-SKILL** | `~/.neoth/skills/paper-revision-coach/skill.yaml`. |
| `abstract-only` | **ADOPT-AS-SKILL** | `~/.neoth/skills/paper-abstract/skill.yaml`. Bilingual output contract. |
| `lit-review` | **SKIP-DUPLICATE** | Covered by `deep-research/lit-review`. Same annotated-bibliography output. |
| `format-convert` | **SKIP-OUT-OF-SCOPE** | LaTeX/Pandoc/PDF toolchain — not a NEOTH operator concern. |
| `citation-check` | **ADOPT-AS-CORE** | ARS's citation contamination detection (`contamination_signals`, Semantic Scholar + OpenAlex + Crossref triangulation) maps to a new `SRC/neothd/src/recall/citation_check.rs`. Operator says "check citations" → daemon fetches against live APIs, emits `CITATION_VERIFIED/CONTAMINATED` WAL frames. |
| `disclosure` | **SKIP-OUT-OF-SCOPE** | Venue-specific AI disclosure — academic publishing workflow, not NEOTH domain. |

### 3.3 academic-paper-reviewer (6 modes)

| Mode | Classification | Rationale |
|------|---------------|-----------|
| `full` | **ADOPT-AS-SKILL** | `~/.neoth/skills/reviewer-full/skill.yaml`. 5-dimension scoring (EIC + R1/R2/R3 + Devil's Advocate) — excellent as a general document-review skill, not just academic. Rename: `~/.neoth/skills/review-document/skill.yaml`. |
| `quick` | **ADOPT-AS-SKILL** | `~/.neoth/skills/review-quick/skill.yaml`. Low-overhead assessment. |
| `methodology-focus` | **ADOPT-AS-SKILL** | `~/.neoth/skills/review-methodology/skill.yaml`. Deep logic/method critique — applicable to NEOTH design docs + specs too. |
| `guided` | **ADOPT-AS-SKILL** | `~/.neoth/skills/review-guided/skill.yaml`. Interactive improvement coaching. |
| `re-review` | **ADOPT-AS-SKILL** | `~/.neoth/skills/review-recheck/skill.yaml`. Revision verification — maps to NEOTH's verification-before-completion superpower already in `assets/skills/`. |
| `calibration` | **SKIP-OUT-OF-SCOPE** | Reviewer calibration against gold sets — academic publishing UX only. |

### 3.4 academic-pipeline (orchestrator)

| Mode | Classification | Rationale |
|------|---------------|-----------|
| `(pipeline)` | **ADOPT-MODE-REGISTRY** | The 10-stage orchestrator IS the mode-registry pattern in action. Don't port it as a skill — port its architectural concept as the NEOTH mode-registry core (see §2). |
| `resume_from_passport` | **ADOPT-AS-CORE** | The Material Passport (hash-addressed session checkpoint with `kind: boundary/resume`) maps directly to NEOTH's WAL + recall. Port as: on any pipeline skill completing a stage, emit a `MODE_CHECKPOINT` WAL frame (`0xB3`) carrying a SHA-256 of the session context. Operator can say "resume from [hash]" and NEOTH reconstructs context from the WAL frame + groundtruth snapshot. No separate "passport" file needed — WAL is the ledger. |

---

## 4. Cross-Cutting Concepts to ADOPT-AS-CORE

### 4.1 Spectrum taxonomy (fidelity / balanced / originality)
Add `spectrum` field to `SkillManifest` in `SRC/neothd/src/skills/manifest.rs`. Controls how the skill's system_prompt instructs the provider: fidelity = template-heavy + low creativity, originality = exploratory + high latitude. The operator can override per-session via `neoth config set skill.spectrum=fidelity`.

### 4.2 Oversight levels (Low / Medium / High / Very High)
Maps to NEOTH's existing `PermissionToken<L>` autonomy gate (`SRC/neothd/src/permissions/`). A skill with `oversight: very_high` requires operator confirmation at each stage even when autonomy is `elevated`. Add a `required_oversight: OversightLevel` field to `SkillManifest`; the skill dispatcher in `SRC/neothd/src/cli/chat.rs` gates on it before injecting the skill's system_prompt.

### 4.3 Intent-based activation (Socratic/Plan modes)
ARS's Socratic mode activates on **intent signals**, not keyword hits. NEOTH's Stage-1 router is keyword-only today. Stage-2 Qwen embedding re-rank (D14b, spec'd but not yet shipped) handles this naturally — the `intent_activation: true` manifest flag should bypass Stage-1 entirely and go straight to Stage-2 cosine match. Add `intent_activation: bool` to `SkillManifest`.

### 4.4 Temporal integrity verifier (v3.9.4)
ARS ships a deterministic verifier for 5 temporal failure modes (retrospective arithmetic, anachronistic citation, comparator unmaterialized, causal inversion, deictic present). Port as `SRC/neothd/src/profile/temporal_guard.rs` — runs as an advisory pass after `claim_guard` (H1+H2+H5+M1+M2), emits WAL `TEMPORAL_ADVISORY` frames (`0xB4`). SKIP the full Crossref/Semantic Scholar lookup in v1 — implement passes P1 (retrospective arithmetic) + P4 (causal inversion) deterministically; defer P2/P3/P5 to after citation_check lands.

---

## 5. SKIP Summary

| Item | Reason |
|------|--------|
| `format-convert` (LaTeX/Pandoc) | Out-of-scope toolchain |
| `disclosure` (AI venue statement) | Academic publishing, not NEOTH operator domain |
| `calibration` (reviewer gold-set) | Academic publishing UX |
| `lit-review` (paper duplicate) | Covered by `deep-research/lit-review` |
| Chinese-only citation rules (APA 7.0 zh-TW) | Domain-specific, not operator-relevant |
| Scripts (migrate_literature_corpus_*.py, semantic_scholar_client.py) | ARS runtime tooling; citation_check.rs replaces the essential parts |

---

## 6. Build Order

Priority: core primitives first, skills second.

1. **`mode_registry.rs`** — extend `SkillManifest` with `modes`, `spectrum`, `required_oversight`, `intent_activation`; build `ModeRegistry`; `/mode` slash command; WAL `0xB0-0xBF` band. Blocker for everything else.
2. **`fact_check.rs`** in `src/profile/` — chains `claim_guard` + new fact-check prompt; WAL frames.
3. **`citation_check.rs`** in `src/recall/` — OpenAlex + Crossref lookup; `CITATION_CONTAMINATED` WAL frame.
4. **`temporal_guard.rs`** in `src/profile/` — advisory P1+P4 passes.
5. **Skill YAMLs** (`~/.neoth/skills/`) — 15 skills from §3 (10 ADOPT-AS-SKILL + 5 renames). Write manifests using the extended schema from step 1.
6. **`resume_from_passport`** logic — `MODE_CHECKPOINT` WAL frame (`0xB3`) + recall reconstruction in `cli/chat.rs`.

---

## 7. PROGRESS.md Hook

Add to `PLAN/PROGRESS.md` under a new `ARS-*` item band:

```
[ ] ARS-1  mode_registry.rs + SkillManifest extensions + WAL 0xB0-0xBF
[ ] ARS-2  fact_check.rs (chain through claim_guard)
[ ] ARS-3  citation_check.rs (OpenAlex + Crossref advisory)
[ ] ARS-4  temporal_guard.rs (P1+P4 advisory passes)
[ ] ARS-5  15 skill YAML manifests (research-* + paper-* + review-*)
[ ] ARS-6  resume_from_passport WAL checkpoint + recall reconstruct
```
