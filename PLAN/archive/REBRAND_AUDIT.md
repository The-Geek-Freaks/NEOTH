# REBRAND_AUDIT — AGENTER → NEOTH (Operator-Agnostic)

Status: Applied 2026-05-13. Recorded for transparency and rollback reference.

## Scope

NEOTH is built as a public OSS daemon. Pre-1.0 naming, paths, and operator-identity references were swept from the active spec set so any operator can install and run their own deployment without inheriting the original author's environment.

## What changed (active specs only)

| Pattern | Before | After | Count |
|---------|--------|-------|-------|
| CLI binary | `agenterctl` | `neothctl` | 23 |
| Config dir | `~/.agenter/` | `~/.neoth/` | 8 |
| Env var prefix | `AGENTER_*` | `NEOTH_*` | 4 |
| Standalone uppercase | `AGENTER` | `NEOTH` | 240+ |
| MCP namespace | `mcp__agenter__*` | `mcp__neoth__*` | 2 |
| WAL event prefix | `SHADOW_AGENTER_*` | `SHADOW_NEOTH_*` | 3 |
| Test/log filenames | `agenter-response.jsonl`, `agenter-monitor`, `agenter-wa-shim` | `neoth-*` | 3 |
| Scoring variable | `agenter_score` | `neoth_score` | 4 |
| Endpoint flag | `--agenter-endpoint` | `--neoth-endpoint` | 1 |
| Operator example | `--operator <name>`, `id: "<name>"`, `author = "<name>"` | `<your-operator-id>`, `"yourname"` | 4 |
| Day-1 prep section | "Decide directory rename" operator-specific path | Generic 3-item OSS operator checklist | 1 |

Total: 293 individual edits across 15 active spec files. Verified: zero residual hits via `grep -rEn "agenterctl\|~/\.agenter\|AGENTER_\|\bAGENTER\b\|\bagenter\b\|agenter-\|agenter_"`.

## What deliberately did NOT change

These references stay because they're either historical context, third-party docs, or legitimately about the predecessor system:

- **`PLAN/archive/`** — 19 archived design docs (v0.1 to v1.0). Kept as-is for audit history. Header banner already says "archived".
- **`PLAN/tool_framework_v4_1.md`** — third-party foundation document. Python pseudocode blocks are the original framework material; NEOTH implements them in Rust. KEEP-AS-IS.
- **`PLAN/CHORUS_v06_*.md`, `CLAUDE_v07_review.md`** — historical adversarial reviews. KEEP-AS-IS.
- **`PLAN/BLUEPRINT_v06_synthesis.md` / `CHERRY_PICK_RANKING.md` references to `*.py` files in QUELLEN/** — these are Source-FROM pointers (predecessor's Python implementations that we port to Rust). Filename references are appropriate.
- **`Jarvis` references** — Jarvis is the predecessor system NEOTH is migrating from. `RUNBOOK_phase3_cutover.md` Days 66-79 describe shadow-run against Jarvis. Predecessor name stays.
- **Operator-name mentions in eval-query examples** (RUNBOOK Z.21, Z.23) and "original operator calibration anchor" — these are clearly contextual. Anyone running their own eval substitutes their own operator name.

## What was tagged but not yet swept

- **`PLAN/02_MEMORY_LAYER_MAPPING.md`**, **`PLAN/CHORUS_v06_codex.md`**, **`PLAN/CLAUDE_v07_review.md`**, **`PLAN/CHERRY_PICK_RANKING.md`**, **`PLAN/BLUEPRINT_v06_synthesis.md`** — these are "reference snapshots" (analysis docs taken at a point in time). They received AGENTER→NEOTH replacements where appropriate, but the OSS-release decision is to add a one-line banner at the top of each marking them as historical reference rather than rewriting them in full. See banner template below.

## Banner template for REFERENCE-only documents

```markdown
> **Reference document.** Captures analysis or synthesis at a specific point in time.
> The normative current state lives in `00_DESIGN_v1.1_FINAL.md` plus the `SPEC_*.md`
> files. Use this for context; do not treat it as build instructions.
```

## Files getting banners

1. `PLAN/02_MEMORY_LAYER_MAPPING.md`
2. `PLAN/CHERRY_PICK_RANKING.md`
3. `PLAN/BLUEPRINT_v06_synthesis.md`
4. `PLAN/NEW_SOURCES_INTEGRATION.md`
5. `PLAN/CHORUS_v06_codex.md`
6. `PLAN/CHORUS_v06_gemini.md`
7. `PLAN/CLAUDE_v07_review.md`
8. `PLAN/S10_PAT_REVOCATION.md` (operator-specific historical action)
9. `PLAN/ADVERSARIAL/00_SUMMARY.md` (reference summary; the 10 reports themselves stay as adversarial findings)
10. `PLAN/tool_framework_v4_1.md` (third-party foundation; banner clarifies "Reference-only, NEOTH implements in Rust")

## Verification commands

```bash
# Active-spec residual check (must return zero results)
cd PLAN
grep -rEn "agenterctl|~/\.agenter|AGENTER_|\bAGENTER\b|\bagenter\b|agenter-|agenter_" \
  $(ls *.md ADVERSARIAL/*.md | grep -v "^archive/")

# Operator-hardcoding residual check (must return zero results)
grep -rEn '"<your-operator-id>"|operator_id.*<your-id>|author = "<your-id>"' \
  *.md ADVERSARIAL/*.md
```

## Rollback

This sweep was applied by sed-based bulk replacement. To roll back: revert the relevant commits, or run the inverse sed on the affected files. The archive/ folder preserves pre-sweep originals if you need pattern reference.

---

Companion document: `REFERENCE_DEPLOYMENT.md` — describes the original development deployment (the author's setup) as one example reference architecture, not as a required configuration.
