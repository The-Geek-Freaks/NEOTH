# Handoff — Ecology-Schicht (E-19 / V1x-01 / CH-13)

**Date opened:** 2026-05-24
**Author:** Session 22 (Claude Opus 4.7)
**Status:** Stub — multi-week v1.x track. Not started in Session 22; closed at this stub level pending dedicated v1.x phase opening.
**Design note:** `PLAN/DESIGN_CH13_ecology_schicht_2026-05-23.md` (Session 21 — read first)

---

## Scope

Three converging items, all the same workstream:

| ID | Source line | Description |
|----|-------------|-------------|
| **E-19** | 1875 | Ecology-Schicht full — self-improvement loop, Council-adaptation, Tool-genealogy |
| **V1x-01** | 2490 | (same — v1.x umbrella ID) |
| **CH-13** | (cross-ref) | Design started Session 21 |

---

## Why v1.x, not v0.x

Per existing PROGRESS line (1875): "P4 milestone, 10-12 focused days per the design note. `[~]` deferred until P4 phase opens." v0.x scope-completion (the goal of Sessions 20–22) intentionally does not include the Ecology-Schicht. v0.2 ships first; v1.x phase opens after the operator-feedback loop on v0.2 stabilises.

---

## Components

The design note covers three sub-systems:

1. **Self-improvement loop** — operator-feedback signal → profile tuning → council weight adjustment. Builds on `profile/self_dev.rs` (P-04, already shipped) + `cron/runner::run_briefing_gated` (Session 22 Workstream C) as the trigger surface.
2. **Council-adaptation** — adjust per-hemisphere weights based on per-decision audit signal. Touches `council/callosum.rs` (already shipped pure-fn voting) + new `council/adaptation.rs` (NEW) for the weight-mutation loop.
3. **Tool-genealogy** — track which skills/plugins/tools the operator uses + which produced good outcomes + retire / promote based on signal. Touches `skills/registry.rs` (already shipped) + new `skills/genealogy.rs` (NEW).

---

## Pickup steps for the v1.x phase opener

1. Read `PLAN/DESIGN_CH13_ecology_schicht_2026-05-23.md` end-to-end.
2. Audit the current state of `profile/self_dev.rs` + `council/callosum.rs` + `skills/registry.rs` — these are the surface the Ecology-Schicht consumes.
3. Decompose the 10-12 focused days into per-day pickups (the design note has a phase breakdown).
4. Each day ships under a dedicated commit so v1.x history is per-component reviewable.

---

This file is a **stub**. v0.x ships first; Ecology-Schicht is the first big v1.x deliverable.
