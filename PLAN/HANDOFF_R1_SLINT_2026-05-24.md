# Handoff — R-1 Slint GUI (Workstream P)

**Date opened:** 2026-05-24
**Author:** Session 22 (Claude Opus 4.7)
**Status:** Stub — not started; multi-week scope deliberately deferred from the Session 22 deferred sweep.
**Predecessor:** `PLAN/HANDOFF_DEFERRED_SWEEP_2026-05-24.md` Workstream P section.

---

## Scope

13 GUI items consolidated under one workstream:

| ID | Description | Source line in PROGRESS.md |
|----|-------------|-----------------------------|
| **G-01** | Full R-1 Slint GUI wizard scope | 1840 |
| **G-02** | GUI profile preset selector | 1841 |
| **G-03** | GUI hemisphere post-onboarding panel | 1842 |
| **G-04** | GUI autonomy picker | 1843 |
| **G-05** | Hysteria walkthrough wizard screen | 1844 |
| **G-06** | Keet QR/seed pairing UX | 1845 |
| **G-07** | Slack + Keet activation in GUI channel step | 1846 |
| **G-08** | FacCam plugin wizard screen | 1847 |
| **G-09** | Cross-platform FacCam family GUI consumption | 1848 |
| **G-10** | ADR viewer in GUI | 1849 |
| **G-11** | Obsidian vault auto-sync timer in GUI | 1850 |
| **V10-05** | Full terminal-free Slint onboarding | 2481 |
| **CH-07** | GUI Slint hemisphere panel post-wizard switcher | 1781 (dup of G-03) |

Plus the GUI dups already pointed here from PROGRESS via the Session 22 cleanup pass:
- `G-4` (line 337) → dup of G-06
- `AU-7` (line 493) → dup of G-04
- `P-03` (line 1794) → dup of G-02

---

## Why a separate handoff

The Session 22 deferred-sweep handoff (`PLAN/HANDOFF_DEFERRED_SWEEP_2026-05-24.md` Workstream P section) explicitly defers this:

> Don't ship in deferred-sweep session. Create separate `PLAN/HANDOFF_R1_SLINT_2026-XX-XX.md` for the multi-week R-1 workstream — too big to interleave with bounded sweeps.

Slint GUI ships under a separate `SRC/neothd-gui/` crate (already scaffolded in workspace). The wizard step / panel work touches 13 distinct screens + the daemon-side reads via `freedom.yaml` + `~/.neoth/profile/active_preset.txt` etc. — all of which Session 22 stabilised. The CLI-side primitives every GUI screen consumes are already shipped (see PROGRESS.md status for each item's "[x] primitive" entry).

---

## Tech pins (from Round-3 research synthesis `[[neoth-research-synthesis]]`)

- **Slint** as the GUI framework (no Tauri, no Electron, no Qt).
- **Cross-platform:** Windows + Linux + macOS targeted; iOS / Android later.
- **Cargo:** `slint = "1"` already in workspace (`SRC/neothd-gui/Cargo.toml`).
- **Theming:** `tweaks.toml` ~30 keys for runtime operator tuning (Round-3 R-21 deliverable).

---

## Recommended phasing (~6 weeks)

| Phase | Items | Estimate |
|-------|-------|----------|
| **P-1 Foundation** | G-01 wizard shell + nav + theme load + `tweaks.toml` parser | 1.5 weeks |
| **P-2 Wizard screens** | G-02 preset selector + G-03 hemisphere + G-04 autonomy + G-05 Hysteria + G-06 Keet pairing + G-07 Slack/Keet + G-08 FacCam + V10-05 terminal-free flow | 2.5 weeks |
| **P-3 Post-wizard panels** | CH-07 hemisphere switcher + G-10 ADR viewer + G-11 Obsidian sync timer + main chat surface | 1.5 weeks |
| **P-4 Cross-platform polish** | G-09 FacCam family + Windows / macOS / Linux build matrix + cargo-dist GUI bundles | 0.5 week |

---

## Pickup steps

1. Open `SRC/neothd-gui/` and survey what's already scaffolded.
2. Pick the highest-impact wizard screen that has CLI parity: **G-04 autonomy picker** is a good starter — autonomy levels are pinned at `permissions::AutonomyLevel::{Strict, Standard, Elevated, Full, Custom}` and the CLI already exposes them.
3. For each screen, the pattern is:
   - Read the corresponding wizard-step fn in `SRC/neothd/src/cli/init.rs` (step5, step5b, step6, step6b, step6c, step6d, step6e, step6f, step7, step7b, step7c) — every wizard step has a working non-interactive path that the GUI mirrors.
   - The GUI panel calls the same primitive (e.g. `record_active_preset`, `record_last_active`) that the CLI uses, so freedom.yaml + marker files stay in sync.

---

## Hard rules (carry over from CLAUDE.md + project rules)

- **Mode-selection first screen** (per `[[neoth-gui-first-screen-and-settings-parity]]`): the daemon's first GUI start shows a CLI-vs-GUI card picker with SVG glyphs. Operator can flip later via settings.
- **Settings panel parity:** every operator-tweakable setting MUST be available in BOTH GUI and CLI. Both write the same `FreedomConfig`. Tests pin parity.
- **Default operator post-onboarding view = chat:** GUI lands the operator on a chat surface, not a dashboard.
- **No SendUserMessage** etc. — same global CLAUDE.md rules apply.

---

This file is a **stub**. When Session 23 (or later) picks up R-1, it can scope down to per-phase handoffs.
