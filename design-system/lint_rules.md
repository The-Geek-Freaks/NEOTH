# NEOTH Slint Design-Lint Taxonomy

ADOPT31-G1 preserves all 59 stable design-lint identifiers as a Slint review
vocabulary. It does not assert that a browser/DOM detector works on a native
Slint application. Production tokens remain in
[`SRC/neothd-gui/ui/theme.slint`](../SRC/neothd-gui/ui/theme.slint).

## Portability contract

Every rule is assigned exactly one class. `gate-now` is the only class that
means checked-in automation exists: it covers the four G2 token rules and the
bounded ADOPT31-G5a motion source checks documented below.
All other rows need the stated reviewer evidence; they are not automated passes.

| Class | Meaning | Automated now |
|---|---|---|
| `gate-now` | Deterministic source gate. | Yes: rules 51-54 and bounded G5a motion checks. |
| `source-review` | Inspect the indicated Slint source/property pattern. | No. |
| `text-review` | Inspect operator-visible UI copy and its structure. | No. |
| `screenshot-required` | Inspect a target-platform render/runtime observation. | No. |
| `DOM-not-applicable` | Requires browser DOM/JS/HTML/ARIA semantics absent from Slint. This is not a pass. | No. |

`SRC/_gui_lint.ps1` and `SRC/_gui_lint.bat` provide the four G2 checks and the
bounded G5a source checks listed as `gate-now`, including narrow fixture
self-tests. They do not validate this full taxonomy or close ADOPT31-G1,
ADOPT31-G4, the remainder of G5-G7, or broader GUI/accessibility Road work.
Release readiness still needs manual evidence and the separately required
remote exact-head gates.

## Rule catalog

The review actions below are NEOTH Slint adaptations. They do not claim that
impeccable's browser engine can execute against Slint.

| # | Stable rule ID | Slint review action | Class |
|---:|---|---|---|
| 1 | `side-tab` | Inspect cards for thick single-side accent-border decoration. | `screenshot-required` |
| 2 | `border-accent-on-rounded` | Inspect accent borders on rounded elements for visual noise. | `screenshot-required` |
| 3 | `overused-font` | Review font roles and `font-family` against Theme. | `source-review` |
| 4 | `flat-type-hierarchy` | Review heading text roles and meaningful scale contrast. | `source-review` |
| 5 | `gradient-text` | Inspect rendered text legibility and contrast. | `screenshot-required` |
| 6 | `ai-color-palette` | Inspect unintended purple/violet heading palette drift. | `screenshot-required` |
| 7 | `cream-palette` | Inspect unintended warm cream/brown surface drift. | `screenshot-required` |
| 8 | `nested-cards` | Review nested `Rectangle`/border containment depth. | `source-review` |
| 9 | `monotonous-spacing` | Review spacing hierarchy rather than one gap everywhere. | `source-review` |
| 10 | `bounce-easing` | Review animation easing and safe duration guards. | `source-review` |
| 11 | `pulsing-dot` | Review status-indicator motion; reject decorative pulse. | `source-review` |
| 12 | `blinking-cursor` | Review text/motion declarations; reject decorative blink. | `source-review` |
| 13 | `shape-assembled-illustration` | Inspect artwork for generic assembled-shape illustration. | `screenshot-required` |
| 14 | `dark-glow` | Inspect dark-surface glow extent and state meaning. | `screenshot-required` |
| 15 | `radial-halo` | Review radial fill/gradient usage for semantic purpose. | `source-review` |
| 16 | `radial-spotlight-glow` | Review oversized radial spotlight overlays. | `source-review` |
| 17 | `marquee` | Review repeated x-offset animation; reject infinite decorative scroll. | `source-review` |
| 18 | `icon-tile-stack` | Inspect generic colored icon-tile feature art. | `screenshot-required` |
| 19 | `italic-serif-display` | Review italic serif use; Bodoni Moda is wordmark-only. | `source-review` |
| 20 | `hero-eyebrow-chip` | Review headline chips; require real status meaning. | `source-review` |
| 21 | `kicker-above-heading` | Review decorative all-caps heading kickers. | `source-review` |
| 22 | `numbered-section-labels` | Review changed UI strings for decorative `01.` labels. | `text-review` |
| 23 | `em-dash-overuse` | Review changed UI copy for decorative em-dash use. | `text-review` |
| 24 | `marketing-buzzword` | Review UI claims against shipped behavior. | `text-review` |
| 25 | `aphoristic-cadence` | Review operational UI copy for slogan-like cadence. | `text-review` |
| 26 | `oversized-h1` | Review heading scale against target window constraints. | `source-review` |
| 27 | `extreme-negative-tracking` | Review letter-spacing declarations for excessive compression. | `source-review` |
| 28 | `broken-image` | Browser image-load/alt behavior has no direct Slint DOM equivalent. Use native asset review separately; do not mark this Pass. | `DOM-not-applicable` |
| 29 | `script-error` | Browser JS-console errors have no Slint equivalent. Use native diagnostics separately; do not mark this Pass. | `DOM-not-applicable` |
| 30 | `content-hidden-at-rest` | Review `visible`/opacity state conditions and keyboard path. | `source-review` |
| 31 | `edge-flush-cards` | Review root/container padding at small windows. | `source-review` |
| 32 | `text-occlusion` | Inspect target-size render for text/control overlap. | `screenshot-required` |
| 33 | `first-viewport-column-overflow` | Inspect initial target-size render for clipping/overflow. | `screenshot-required` |
| 34 | `gray-on-color` | Inspect signal-state render for washed-out neutral gray. | `screenshot-required` |
| 35 | `low-contrast` | Render and measure or record justified contrast assessment. | `screenshot-required` |
| 36 | `layout-transition` | Review `animate` declarations for width/height/padding changes. | `source-review` |
| 37 | `line-length` | Inspect rendered body-text measure at target width. | `screenshot-required` |
| 38 | `cramped-padding` | Review interactive-control geometry and target padding. | `source-review` |
| 39 | `body-text-viewport-edge` | Review outer text padding and request target-size render. | `source-review` |
| 40 | `tight-leading` | Review body-text line-height/text metrics. | `source-review` |
| 41 | `skipped-heading` | Review visible heading labels and surface order. | `text-review` |
| 42 | `heading-rhythm` | Inspect rendered heading-space rhythm. | `screenshot-required` |
| 43 | `justified-text` | Review horizontal-alignment declarations. | `source-review` |
| 44 | `tiny-text` | Review text roles/sizes against supported scaling. | `source-review` |
| 45 | `undersized-ui-text` | Review interactive-text roles and sizes. | `source-review` |
| 46 | `all-caps-body` | Review changed body copy in context. | `text-review` |
| 47 | `wide-tracking` | Review body-text tracking declarations. | `source-review` |
| 48 | `text-overflow` | Review clipping/ellipsis declarations and state. | `source-review` |
| 49 | `repeated-container-text` | Review ownership of repeated visible strings. | `text-review` |
| 50 | `clipped-overflow-container` | Review clipping/overflow behavior around meaningful content. | `source-review` |
| 51 | `design-system-font` | Font family must be Theme-derived. G2 emits `design-system-font`. | `gate-now` |
| 52 | `design-system-color` | Checked direct color literals must be Theme-derived, except documented compatibility behavior. G2 emits `design-system-color`. | `gate-now` |
| 53 | `design-system-radius` | Border-radius literals must stay within the initial checked ramp or Theme-derived path. G2 emits `design-system-radius`. | `gate-now` |
| 54 | `design-system-font-size` | Font-size literals must stay within the initial checked ramp or Theme-derived path. G2 emits `design-system-font-size`. | `gate-now` |
| 55 | `gpt-thin-border-wide-shadow` | Inspect thin-border plus oversized-shadow card treatment. | `screenshot-required` |
| 56 | `repeating-stripes-gradient` | Review gradient/fill declarations for repeating stripes. | `source-review` |
| 57 | `codex-grid-background` | Inspect generic dot-grid/line-grid background decoration. | `screenshot-required` |
| 58 | `theater-slop-phrase` | Review UI strings for theatre-style future/tomorrow claims. | `text-review` |
| 59 | `image-hover-transform` | Review hover/animation declarations for image scale/lift. | `source-review` |

## ADOPT31-G5a bounded motion source gate

G5a is deliberately a small executable-source gate, not a visual-motion
certification. It runs after the same nested comment and string-literal masking
used by the G2 source lint; words in comments or UI text cannot create or
approve a motion finding.

The gate emits only these motion rule identifiers:

| Rule | Detects | Fail-closed allowance condition |
|---|---|---|
| `motion-bounce-spring` | An executable `animate` block containing `spring` or `bounce`. | A source-local exact baseline entry hashes the complete canonical animate block. |
| `motion-layout-animation` | `animate width`, `height`, `x`, `y`, `padding`, or `spacing`. | A source-local exact baseline entry hashes the complete canonical animate block. |
| `motion-marquee` | A direct `x` or `y` assignment driven by `animation-tick()`. | A source-local exact baseline entry hashes the canonical assignment. |
| `motion-pulse-guard` | A direct `opacity` or `scale` assignment driven by `animation-tick()`. | The expression must contain `Theme.animation-mode == 0` before the tick path and match an exact baseline entry. |

The checked-in production baseline is
[`gui_motion_allowlist.json`](gui_motion_allowlist.json). It is intentionally
not a glob list. Each entry binds a normalized GUI-relative `.slint` path, rule,
property, SHA-256 fingerprint of the whitespace-canonical executable expression,
reason, and its required reduced-motion contract. JSON schema, duplicate keys,
unsafe paths, unknown rules/properties, malformed fingerprints, absent source
files, and stale entries are fatal. Any executable expression change therefore
creates an unallowlisted finding instead of silently inheriting an approval.

The baseline is limited to transitions and semantic status pulses found in the
scoped G5a audit. It does not allow a new spring/bounce effect, marquee, or
continuous pulse by category. `Theme.animation-mode == 0` is the required
static-safe branch for a continuous opacity/scale expression; duration-based
layout entries separately document the existing theme duration-to-0ms contract.

`SRC/gui_lint_fixtures/` contains positive and negative static self-test cases:
an exact allowed transition; one failure each for bounce/spring, layout,
marquee, and missing pulse guard; comment/string decoys; and a changed approved
expression. These fixtures are source-gate evidence only. They are not a Slint
compiler, runtime, accessibility, or reduced-motion rendering proof.

## Attribution and adaptation boundary

**Pinned source baseline:** the 59 stable IDs in this table were compared with
[`pbakaus/impeccable` commit `f88b2837a7d7c3182e46307bbbb091a1ed547571`](https://github.com/pbakaus/impeccable/tree/f88b2837a7d7c3182e46307bbbb091a1ed547571)
at `cli/engine/registry/antipatterns.mjs` on 2026-08-20. This documentation has
no dependency on the mutable `main`/`HEAD` name.

Copyright 2025 Paul Bakaus. The source baseline is licensed under the Apache
License 2.0; see NEOTH's local [LICENSE-APACHE](../LICENSE-APACHE). **NEOTH
modification notice:** this file is an independently written, modified
adaptation of the stable identifier taxonomy for Slint review. It does not copy,
bundle, or execute impeccable's JavaScript/DOM/browser engine.

The upstream [`NOTICE.md` at the pinned revision](https://github.com/pbakaus/impeccable/blob/f88b2837a7d7c3182e46307bbbb091a1ed547571/NOTICE.md)
was reviewed and exists; it describes third-party platform-design-skill material
that NEOTH does not copy here. This document is not a replacement for upstream
license or NOTICE material. Any future import of upstream code, assets, or
notice-bearing material must retain the required Apache-2.0 license and NOTICE
material with that import.

This taxonomy is a review aid, not a release approval, accessibility
certification, or evidence that a Road item is complete.
