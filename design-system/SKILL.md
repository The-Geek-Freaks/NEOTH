---
name: neoth-design
description: Use this skill to generate well-branded interfaces and assets for NEOTH (the local-first private AI buddy by The Geek Freaks), either for production or throwaway prototypes/mocks/decks. Contains essential design guidelines, colors, type, fonts, assets, the reactive Buddy companion, and UI kit components for prototyping.
user-invocable: true
---

Read `README.md`, `lint_rules.md`, and `AUDIT_CHECKLIST.md` in this folder before
reviewing or changing production `.slint` UI. They establish the actual Slint
source-of-truth boundary, rule portability, and required evidence format.

NEOTH is a local-first, fail-closed personal AI. Its design language is neon-on-near-black,
organized around three signal colours that carry meaning everywhere: **green = memory**
(primary/live), **pink = consent** (boundaries/alert), **cyan = audit** (proof/info). Type is
an elegant grotesk (Space Grotesk) for all UI + display, the serif **NEOTH wordmark** in Bodoni Moda (logo only), and JetBrains Mono. The
signature element is the **Buddy** — a glowing neural-core orb that reflects what NEOTH is
doing right now.

Key files:
- `README.md` — production/source-of-truth boundary and brand language.
- `lint_rules.md` — ADOPT31-G1's 59 stable rule identifiers. Only the four
  `gate-now` G2 token-drift rules are automated today; do not call the rest
  checked or passing without their stated review evidence.
- `AUDIT_CHECKLIST.md` — ADOPT31-G4's five-dimension Slint review scorecard.
  Record Pass/Fail/N/A plus evidence for every applicable row.
- `styles.css` — link this one file to get all tokens, fonts, base, component styles.
- `tokens/` — colours (dark default + `[data-theme="light"]`), type, spacing/motion/glow.
- `components/` — React primitives (`Button`, `Card`, `Badge`, `Switch`, `Meter`, `Input`,
  `StatusDot`, `IconButton`, `Tooltip`) and **`Buddy`** (8 moods). See each `.prompt.md`.
- `ui_kits/desktop/` — a full interactive recreation of the NEOTH GUI to copy patterns from.
- `assets/brand/` + `assets/icons/` — real logos, illustrations, demo GIFs, glyphs.

If creating visual artifacts (slides, mocks, throwaway prototypes), copy assets out and create
static HTML files for the user to view — link `styles.css` and use the CSS custom properties.
If working on production code, copy assets and read the rules here to become an expert in
designing with this brand.

For production Slint work, this skill is guidance rather than gate evidence. Do
not claim ADOPT31-G1/G4, another GUI Road item, or release readiness is complete
until the exact pushed head has the separately required remote checks and review
artifacts.

If the user invokes this skill without other guidance, ask them what they want to build or
design, ask a few questions, and act as an expert designer who outputs HTML artifacts _or_
production code, depending on the need. Hold the product promise in every screen: simple for
normal users, serious for operators, **loyal to the user** — calm, trustworthy, never noisy.
