# NEOTH Design System

This directory is the durable GUI-work contract for NEOTH's native Slint
application. Before reviewing or changing `.slint` UI, read these documents in
order:

1. [`PRODUCT.md`](PRODUCT.md) — operator, surface map, states, and interaction
   truthfulness.
2. [`DESIGN.md`](DESIGN.md) — Theme authority, semantic signals, type, layout,
   shape, motion, and review path.
3. [`../SRC/neothd-gui/ui/COMPONENT_API.md`](../SRC/neothd-gui/ui/COMPONENT_API.md)
   — the real component property names and Slint constraints.

The nearest GUI instruction file at
[`../SRC/neothd-gui/AGENTS.md`](../SRC/neothd-gui/AGENTS.md) makes this pre-read
mandatory for work in that subtree. The docs are a workflow guard, not compiled
runtime and not release proof.

## Review contracts

- [`lint_rules.md`](lint_rules.md) contains the 59 stable design-lint identifiers
  and their honest Slint portability class. Only the four G2 token-drift rules
  (`design-system-font`, `design-system-color`, `design-system-radius`, and
  `design-system-font-size`) are automated.
- [`AUDIT_CHECKLIST.md`](AUDIT_CHECKLIST.md) is the evidence-first scorecard for
  accessibility, performance, theming, responsive behavior, and implementation
  integrity.

Neither document replaces rendered-platform evidence, exact-head remote CI,
Security/CodeQL, or the wider Road acceptance requirements.

## Production implementation

The production visual-token authority is
[`SRC/neothd-gui/ui/theme.slint`](../SRC/neothd-gui/ui/theme.slint). Its Slint
`Theme` global owns the live dark/light tokens, semantic colors, typography,
spacing, radii, density, overrides, and reduced-motion behavior. The reactive
Buddy is implemented by
[`SRC/neothd-gui/ui/buddy.slint`](../SRC/neothd-gui/ui/buddy.slint), and Rust
drives its live mood from
[`SRC/neothd-gui/src/main.rs`](../SRC/neothd-gui/src/main.rs).

## This folder (reference, not built)

- `HANDOFF-README.md` — the original Claude Design handoff instructions.
- `SKILL.md` — the design skill description (colours, type, components, Buddy).
- `manifest.json` — the full token + component + screen index from the handoff
  (319 design tokens with values, dark + light themes, the 28 Buddy moods with
  per-mood hue / spin / breath timing, the desktop/onboarding/mobile screen kits).
- `design-chat-transcript.md` — the design conversation; **the intent lives here**
  (what the operator asked for, where the iterations landed).
- `assets/brand/` — the real brand SVGs (the three "acts", the 6-region brain).

The original handoff also shipped React/HTML prototypes (`components/*.jsx`,
`ui_kits/{desktop,onboarding,mobile}`) as a bundled runtime; those are prototypes
to read for visual intent, not production code. The production target is Slint —
recreate the visual output there (as done in `SRC/neothd-gui/`), don't port the
prototype's internal structure.

Source repo input: `The-Geek-Freaks/NEOTH`.
