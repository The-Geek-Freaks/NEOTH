# NEOTH Design System

Canonical visual language for NEOTH — the local-first private AI buddy.
Originated as a Claude Design handoff (claude.ai/design, 2026-06-15) generated
by reading NEOTH's real Slint GUI, then adopted as the source of truth for the
app's look.

## The language

Neon-on-near-black. Three **signal colours carry meaning everywhere**:

| Signal | Colour | Meaning |
|--------|--------|---------|
| green  | `#00ff80` | **memory** — primary / live / accent |
| pink   | `#ff2a6d` | **consent** — boundaries / alert / danger |
| cyan   | `#05d5ff` | **audit** — proof / info / network |
| amber  | `#ffb627` | in-progress / caution |

Type: **Space Grotesk** (all UI + display), **Bodoni Moda** (the NEOTH wordmark
only), **JetBrains Mono** (ids, audit frames, eyebrows, status lines).

Signature element: the **Buddy** — a glowing neural-core orb that reflects what
NEOTH is doing right now (idle, thinking, working, remembering, verifying,
hitting a consent boundary, finishing).

> **Palette decision (2026-06-15):** the saturated neon signal palette above is
> **canonical** — it supersedes the earlier desaturated emerald (`#3ecf8e`)
> experiment. Operator call during the design-system adoption.

## Where it lives in the codebase (the real implementation)

The design tokens + Buddy are implemented natively in the Slint GUI — these are
the production files, not this folder:

- **`SRC/neothd-gui/ui/theme.slint`** — every token (ink scale, signal neons +
  glow/tint, semantic surfaces, text hierarchy, spacing 4px grid, radii xs..pill,
  type, motion) as a Slint `Theme` global. Change a value here → it propagates to
  every screen. **This is the live single source of truth.**
- **`SRC/neothd-gui/ui/buddy.slint`** — the reactive Buddy orb (`Buddy` +
  `BuddyDock`), driven by `animation-tick()`. `mood` → hue / orbit speed / breath
  speed + per-mood overlays (thinking dots, working scan, success check, memory
  inflow, alert badge, secure lock, …).
- **`SRC/neothd-gui/src/main.rs`** — drives `buddy-mood` from live activity
  (chat: thinking → working → success/error).

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
