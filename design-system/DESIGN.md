# NEOTH GUI Design Contract

Read this document together with [`PRODUCT.md`](PRODUCT.md) before reviewing
or changing any Slint surface. This document describes how the product contract
appears in the native GUI. It does not replace the compiled source of truth:
[`SRC/neothd-gui/ui/theme.slint`](../SRC/neothd-gui/ui/theme.slint).

## Authority and implementation boundary

`theme.slint` owns production token values, dark/light behavior, runtime
appearance overrides, density, and reduced-motion behavior. Use `Theme.*` at
call sites; do not recreate visual constants in a view. The reference assets
under `design-system/` provide visual intent only and are never a second UI
runtime.

For component property names and known Slint constraints, read
[`SRC/neothd-gui/ui/COMPONENT_API.md`](../SRC/neothd-gui/ui/COMPONENT_API.md)
before writing a new view or changing a component invocation.

## Visual language

NEOTH is neon-on-near-black: restrained dark surfaces carry dense operational
information, while vivid signals have stable meanings.

| Signal | Meaning | Use |
|---|---|---|
| Green / `Theme.memory` or `Theme.accent` | Memory, live/primary, affirmative action. | A real live state, primary action, memory-related information. |
| Cyan / `Theme.audit` | Audit, proof, information, network. | Receipts, provenance, inspectable evidence, neutral information. |
| Pink / `Theme.consent` | Consent, boundary, alert, danger. | Egress/authority decisions and genuinely dangerous or failed states. |
| Amber / `Theme.warning` | In progress or caution. | Pending, constrained, degraded, or requires-attention states. |

Use semantic aliases when the meaning is known; raw signal colors are reserved
for the token module. Signal color is supplementary: text, iconography, labels,
and state-specific behavior must carry the same meaning.

## Type ramp and text roles

Use the Theme font roles rather than host-dependent literals:

| Role | Token family | Intended use |
|---|---|---|
| UI and display | `Theme.font-sans` / `Theme.font-display` | Controls, headings, ordinary operator text. |
| Wordmark only | `Theme.font-wordmark` | NEOTH brand mark, not body or arbitrary decorative text. |
| Machine truth | `Theme.font-mono` | IDs, timestamps, audit frames, compact status values. |
| Body and caption | `Theme.font-size-body`, `Theme.font-size-caption` | Readable operational text and supporting context. |
| Heading | `Theme.font-size-h2`, `Theme.font-size-h1` | A clear hierarchy, sized for the target window. |
| Display | `Theme.font-size-display-*`, `Theme.font-size-hero` | Exceptional, space-rich product moments; never a substitute for hierarchy. |

Letter spacing uses the named `Theme.letter-spacing-*` tokens. Avoid
all-caps body copy, decorative kickers, and slogan-like status prose. Text that
conveys an operation must name its real state and scope.

## Layout, spacing, and shape

The layout scale is a 4px grid through `Theme.space-1` to
`Theme.space-10`, with compatibility aliases for common spacing. Use those
tokens to establish hierarchy; do not apply one uniform gap to every surface.

Use `Theme.radius-*` for ordinary controls and cards. The visual baseline is a
"noble curve": sharp zero-radius UI is not a default. The limited pixel-scale
exceptions in `theme.slint` are for tiny rails/indicators where a large semantic
radius is geometrically invalid, not a general escape hatch.

Cards, borders, halo, and shadow must show information hierarchy or state. Do
not add nested-card stacks, generic icon tiles, ornamental grids, repeated
stripes, or visual glow that has no product meaning. Reserve enough outer
padding for small windows and ensure long text has an intentional overflow
behavior.

## Motion and reduced motion

Use motion to explain a real state change, not to decorate idle content. All
durations come from `Theme.duration-*` and honor `Theme.animation-mode`:

| Mode | Contract |
|---|---|
| `0` | No motion; duration tokens resolve safely to zero. |
| `1` | Reduced motion. |
| `2` | Full motion. |

Never divide by a duration or drive an ambient animation without the existing
`animation-mode` guard. Avoid bounce/spring easing, decorative pulsing dots,
marquees, blinking text, layout-property animation, and image hover-lift.
Rendered behavior still needs review; source inspection alone is not a motion
or accessibility pass.

## Required review path

1. Read [`PRODUCT.md`](PRODUCT.md), this document, and the component API.
2. Keep production visual values in `theme.slint` and consume them through
   `Theme.*` in views.
3. Use [`lint_rules.md`](lint_rules.md) to classify source, text, screenshot,
   and DOM-not-applicable evidence honestly.
4. Complete the applicable rows in
   [`AUDIT_CHECKLIST.md`](AUDIT_CHECKLIST.md); a missing render, accessibility,
   or remote exact-head gate is incomplete, not a pass.

The current automated GUI lint covers the four G2 token-drift checks plus the
bounded G5a motion source checks backed by the exact reviewed baseline. It does
not prove visual quality, accessibility, responsiveness, runtime motion
behavior, or a functional UI action.
