# NEOTH PLAN — Normative Index

_Last updated: 2026-05-14. v1.1 = post-adversarial-fixes. All build-relevant files at top level. See `archive/` for historical snapshots._

## Current Normative Design

| File | Purpose |
|------|---------|
| **`00_DESIGN_v1.1_FINAL.md`** | **CURRENT normative design.** Post-adversarial fixes (10 S-class + 8 H-class + 3 A-class). Build-ready pending S10 operator action. |
| `tool_framework_v4_1.md` | Framework v4.1 "Pflegbarer Garten" — foundational constraint set (3 Schichten, 5 Zutaten, 13 Anti-Patterns). |
| `S10_PAT_REVOCATION.md` | Operator action — revoke GitHub PAT before Day 1. |

## Wire + Storage Specs

| File | Purpose | v1.1 fixes |
|------|---------|------------|
| `SPEC_wire_header_v2_slim.md` | 96-byte EventHeader, byte-by-byte LE wire format, PayloadPrefixV4 | S1 (ts_ns→Hlc layout), S4 (originator enum), S8 (no repr(C, packed), explicit `from_le_bytes`) |
| `SPEC_multinode_clock.md` | Hybrid Logical Clock (Kulkarni 2014) | S2 (Kulkarni-conformance audit), S9 (Result<(), HlcError> instead of panic) |
| `SPEC_wal_lifecycle.md` | Segment rotation, compaction, vector blobs, disk pressure | S5 (HMAC on .cpt), S6 (no MmapMut on active), S7 (fdatasync not msync) |

## Skill + Plugin + Auth

| File | Purpose | v1.1 fixes |
|------|---------|------------|
| `SPEC_skill_plugin_system.md` | Skills (YAML) + Plugins (compiled-in Phase 1, WASM Phase 2). Capability-API. | S3 (`PermissionToken<T>` fully implemented) |

## Profile + Memory

| File | Purpose | v1.1 fixes |
|------|---------|------------|
| `SPEC_proactive_learning.md` | Continuous user-profile learning, Hebbian dynamics, idx_profile, freedom.yaml gates | H1 (first-person attribution), H2 (redaction registry), H4 (nightly batch decay), H8 (refusal feedback exclusion), A3 (PROFILE_BASELINE_SNAPSHOT 0x37) |
| `SPEC_profile_claim_guard.md` | NEW v1.1 — Schicht-0 guard between extract+apply | H1 + H2 + H5 + M1 + M2 unified |
| `SPEC_local_inference.md` | NEW v1.1 — Qwen3-4B-INT4 locally on Cube | H3 (privacy theater) + A1 (local model) |

## Channels + Council + Refusal

| File | Purpose | v1.1 fixes |
|------|---------|------------|
| `SPEC_channels.md` | Telegram/WhatsApp/Slack adapters, Channel trait | A2 (`send_proactive()` reserved on trait) |
| `SPEC_council_governance.md` | NEW v1.1 — quota, 429 cascade, smart trigger | H5 (council quota exhaustion) |
| `SPEC_mirror_refusal.md` | Mirror-refusal pipeline (6 classes, 4 WAL events) | unchanged from v1.0 |

## Eval + Migration

| File | Purpose | v1.1 fixes |
|------|---------|------------|
| `SPEC_recall_parity_methodology.md` | Phase-3 cutover gate: parity + grader bias detection | H6 (GROUND_TRUTH_TAG for council adversarial test), H7 (4-grader + operator anchor) |
| `RUNBOOK_phase3_cutover.md` | Day 61-90 tag-genau cutover + rollback | unchanged from v1.0 |
| `02_MEMORY_LAYER_MAPPING.md` | 12-store Jarvis → NEOTH WAL migration map | unchanged |

## Reference + History

| File | Purpose |
|------|---------|
| `BLUEPRINT_v06_synthesis.md` | Multi-source synthesis: openclaw + openhuman + hermes-webui + jarvis-live + veronica + Framework v4.1 |
| `CHERRY_PICK_RANKING.md` | Source-by-source top-5 must-adopt + top-3 do-not-copy |
| `NEW_SOURCES_INTEGRATION.md` | needle, agentmemory, skills, CloakBrowser, react-doctor, oh-my-{gemini,claudecode,codex}, tweakcc + LOWKEY 16 modules + claude-cli bridge |
| `CHORUS_v06_codex.md` / `CHORUS_v06_gemini.md` | Drove v0.7 changes (Codex: NOT approve; Gemini: approve) |
| `CLAUDE_v07_review.md` | Drove v0.8 sofort-aktionen (header slim, WAL lifecycle, Phase-3 runbook) |

## Adversarial Review (drove v1.1)

| File | Purpose |
|------|---------|
| `ADVERSARIAL/00_SUMMARY.md` | Synthesis of 10 agents × 3 rounds — 10 S-class + 8 H-class + 3 A-class findings |
| `ADVERSARIAL/01_security_attack_surface.md` | 30 attack vectors |
| `ADVERSARIAL/02_silent_failures.md` | 19 failure modes |
| `ADVERSARIAL/03_type_design_holes.md` | 15 type-system holes |
| `ADVERSARIAL/04_architecture_alternatives.md` | 8 design decisions challenged |
| `ADVERSARIAL/05_cost_reality.md` | $320-600/month + 900-1050 operator-hours |
| `ADVERSARIAL/06_operator_abuse.md` | 5 operator-self-pwn vectors |
| `ADVERSARIAL/07_eval_methodology.md` | 5 eval gaps |
| `ADVERSARIAL/08_schedule_reality.md` | Day-30 → realistic Day-60 |
| `ADVERSARIAL/09_implementation_hotpaths.md` | 8 Rust hot-path gotchas |
| `ADVERSARIAL/10_comparative_product.md` | 5 known-failure modes from peer products |

## Sources Cloned Locally

`../QUELLEN/` — 14 repos, ~5.4 MB. openclaw + openhuman + hermes-webui + tailslayer + tailslayer-rs + needle + agentmemory + mattpocock/skills + CloakBrowser + react-doctor + oh-my-gemini + tweakcc + oh-my-claudecode + oh-my-codex + JARVIS_FILES + VERONICA_FILES + CLAUDE_CLI_BRIDGE + LOWKEY + CLAUDE_SETTINGS.

## Layout

```
PLAN/
├── INDEX.md                                ← you are here
├── 00_DESIGN_v1.1_FINAL.md                 ← normative design
├── tool_framework_v4_1.md                  ← foundation
├── S10_PAT_REVOCATION.md                   ← operator gate before Day 1
├── SPEC_wire_header_v2_slim.md             (S1, S4, S8 fixed)
├── SPEC_multinode_clock.md                 (S2 audit, S9 fixed)
├── SPEC_wal_lifecycle.md                   (S5, S6, S7 fixed)
├── SPEC_skill_plugin_system.md             (S3 fixed)
├── SPEC_proactive_learning.md              (H1, H2, H4, H8, A3 fixed)
├── SPEC_profile_claim_guard.md             ← NEW (one-change fix)
├── SPEC_local_inference.md                 ← NEW (H3 + A1)
├── SPEC_council_governance.md              ← NEW (H5)
├── SPEC_channels.md                        (A2 fixed)
├── SPEC_recall_parity_methodology.md       (H6, H7 fixed)
├── SPEC_mirror_refusal.md                  (unchanged v1.0)
├── RUNBOOK_phase3_cutover.md
├── 02_MEMORY_LAYER_MAPPING.md
├── BLUEPRINT_v06_synthesis.md
├── CHERRY_PICK_RANKING.md
├── NEW_SOURCES_INTEGRATION.md
├── CHORUS_v06_codex.md / CHORUS_v06_gemini.md
├── CLAUDE_v07_review.md
├── ADVERSARIAL/                            ← 10 adversarial agents, drove v1.1
└── archive/                                ← v0.1 — v1.0 + older Chorus reviews
```
