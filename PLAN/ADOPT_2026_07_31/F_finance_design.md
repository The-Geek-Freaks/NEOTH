# F — Finance & Design Adoption Report
**Agent:** F of 6 | **Date:** 2026-07-31 | **Repos:** free-stockdb · ECC · awesome-systematic-trading · impeccable

---

## Repo 1 — free-stockdb (hello245m, MIT, 1.6k★)

### 1. What it actually is

A Chinese A-share stock market data sync+query system, NOT a library. Ships:

- **Windows pre-built binaries** (`数据更新.exe` = updater, `stockdb.exe` = SSDB/LevelDB server on port 7899)
- **C++ client SDK** (`cpp/`) — libcurl + LevelDB reader; queries via a simple SSDB-like TCP protocol; exports OHLCV k-line data + cumulative adjustment factors; vectorized C++ MA/EMA/MACD helpers
- **Python SDK** (`pybao/stock_sdk.py`) — wraps the `stockdb` Python binding to an SSDB client; async-capable; synthetic weekly/monthly OHLCV built from daily data in memory; optional pandas DataFrame output
- **MCP native interface** (`pybao/native_mcp.py`) — JSON-RPC MCP server exposing `get_stock_list`, `get_kdata`, `get_factors`, `get_sector`, `get_market_overview`
- **No bundled data** — `data/` directory is populated only after the user runs the updater

The updater reads `sync_url.txt` (EMPTY in the repo — user must supply a URL), fetches `<mirror>/manifest.txt` (sha256 + file size + relative path per entry), verifies checksums, and syncs binary LevelDB data files to `./data/`.

### 2. Data source: legitimacy and licence

`sync_url.txt` contains only placeholder comments — the repo ships no pre-configured data source URL. The user must point it at a trusted mirror. **Consequence:**

- Chinese A-share OHLCV data originates from the Shanghai Stock Exchange (SSE) and Shenzhen Stock Exchange (SZSE). Both exchanges license data commercially; redistribution to third parties is prohibited under exchange data agreements without an explicit license.
- The **MIT license covers only the C++/Python client code**. It cannot grant any rights over market data, which the repo does not bundle and does not own.
- Any mirror the user configures carries the terms of *that* provider. NEOTH cannot ship or mandate a data source that is commercially restricted exchange data.
- `rg -i 'ohlcv|stock_price|market_data|backtest|yfinance' SRC/neothd/src/` → **0 results** (run, confirmed). NEOTH has zero finance domain code today.

### 3. Licence obligations (code side)

MIT. If any SDK code were ported, the MIT notice must be preserved. No obligation beyond that.

### 4. Architecture compatibility with NEOTH

| Dimension | Assessment |
|-----------|-----------|
| Self-contained (Rule 1) | FAILS — requires SSDB C++ server process external to NEOTH; Python runtime not NEOTH-installed |
| Cross-platform (Rule 8) | PARTIAL — pre-built binaries are Windows-only; C++ source is portable but needs a full build pipeline |
| Consumer exists (Rule 9) | NO — NEOTH has zero finance scope; no user-visible feature to attach this to |
| Data licence | FATAL — market data cannot be bundled or shipped by NEOTH |

### 5. Platform rule boundary

NEOTH's operator (per `PLAN/00_DESIGN_v1.1_FINAL.md`) and the Claude platform both bar personalized investment advice and trade execution. What technically remains on the safe side: passive data display, summarization, indicator computation from user-supplied data. This is too narrow a scope to justify adopting an entire stock-database system.

### 6. Steal-list

**Nothing.** No steal warranted. The C++ technical debt (build chain, SSDB protocol, libcurl) does not port cleanly to Rust with less effort than using an existing Rust crate (`polars`, `ta-lib-rs`). The MCP native interface pattern is already solved by NEOTH's MCP layer.

### 7. Verdict

**SKIP entirely.** Data licence is fatal. Platform rule bars the consumer. Zero NEOTH finance domain = Rule 9 (no primitive ahead of its consumer) fires. Code architecture requires external supervisor. If a future NEOTH feature ever needs market data, the right path is a user-configured REST feed (not a forked Chinese OHLCV binary database), gated by `freedom.yaml` + WAL consent + operator-sovereignty assertion.

---

## Repo 2 — ECC (affaan-m, MIT, 236k★)

### 1. What it actually is

"Everything Claude Code" — a cross-harness AI *coding configuration* ecosystem: 67 specialized subagent `.md` files (language reviewers, build-error resolvers, TDD guides), 281 skill workflow definitions, 94 slash commands, and automated hook workflows. The 236k stars reflect Claude Code's viral growth, not ECC's novelty; ECC is the canonical config layer that ships alongside Claude Code installations. The architecture is JavaScript/TypeScript config, not an executable binary.

Key dirs: `agents/` (CC-subagent .md specs), `skills/` (workflow definitions), `commands/` (slash command .md), `hooks/` (session/PreToolUse/PostToolUse hooks in Node.js), `contexts/`, `rules/`, `mcp-configs/`.

### 2. ALREADY EVALUATED — GOLD-ADOPT-05 (CLOSED)

The tracker `PLAN/ROAD_TO_1_0_GOLD.md` at GOLD-ADOPT-05 records:

> **✅DONE** (deep read per global repo-eval rule: gh tree of 64 agents + 261 skills, not just README).
> **Verdict: GROUND-TRUTH.** ECC = the "Everything Claude Code" cross-harness CONFIG ecosystem
> (literally the skills installed in this session) — agents are CC-subagent .md (language
> reviewers/build-resolvers), skills target a coding harness. NEOTH is a standalone Rust daemon
> with its OWN 98+ bundled skills / sub_agents / hooks — the infrastructure is fully redundant +
> format-mismatched. Steal-list is THIN: mine individual skill CONTENT on demand for future
> bundled ports; no concrete port warranted now.

The full verdict document is at `REVIEWS/_gold_audit/gremium_eval_ecc.md`.

### 3. NEOTH-side verification (run, confirmed)

NEOTH has its own complete equivalent infrastructure:
- `src/sub_agents/` — `review.rs` (spec-compliance reviewer), `parallel.rs` (fan-out dispatcher), `runtime.rs`, `schema.rs`, `builtins.rs`
- `src/skills/` — `bundled.rs` (98+ skills compiled into binary), `router.rs`, `creator.rs`, `authority.rs`, `store.rs`, `teacher.rs`, `test_harness.rs`
- `src/hooks/` — NEOTH hook engine
- `src/slash/` — slash command builtins, parser, dispatcher
- `src/council/` — QA verdict, factual-check, multi-model council

ECC's 67 reviewer agents = CC-harness subagent configs. NEOTH's Rust sub-agents implement the same patterns natively. Format mismatch is fundamental: ECC `.md` files are CC-harness prompts; NEOTH's equivalent is `skill.yaml` + Rust dispatch.

### 4. Steal-list

Near-zero. The only future mining path: individual skill *content* (e.g., a new domain NEOTH lacks) ported verbatim-adapted into a `skill.yaml` — same path as the engineering/cybersec/pm bundled skills already completed. No framework adoption warranted.

### 5. ECC Verdict (authoritative, tracker is closed)

**GROUND-TRUTH / SKIP. No action needed. Tracker item GOLD-ADOPT-05 is DONE.**

> One unambiguous sentence: ECC is a Claude Code harness config layer that is fully redundant with NEOTH's own Rust-native sub_agents/skills/hooks/slash infrastructure and format-incompatible with it — no adoption warranted now or in the foreseeable future.

---

## Repo 3 — awesome-systematic-trading (paperswithbacktest, NO LICENCE, 11.3k★)

### 1. What it actually is

A pure curated link list / bibliography. The entire repo is:
- `README.md` (578 lines) — links to 97 libraries, 40+ academic strategy papers, 55 books, 23 videos, blogs, courses
- `README_zh.md` — Chinese translation
- `static/` — a single JPEG hero image

Zero executable code. Zero data. Zero implementation. The companion site `paperswithbacktest.com` is where actual implementations live (behind a paywall, not in this repo).

### 2. Licence status — no rights granted

**NO LICENSE FILE in the repository.** Default copyright under the Berne Convention applies to all original expressive content — the specific selection, arrangement, and annotation of links. No reader has any right to copy, reproduce, modify, or distribute the list's selection/arrangement without explicit permission.

Copyright law corner cases:
- Individual **facts** (a paper title, a library name, a URL, a star count) are not copyrightable.
- The **selection and arrangement** of those facts — which libraries to include, how to categorize them, which to annotate — is copyrightable when it reflects creative judgment.
- The README's prose annotations ("implementing trading bots, backtesting...") are copyrightable text.

**What NEOTH can lawfully reference:**
- The *fact* that a library named "backtrader" exists (not copyrightable)
- The *taxonomy of strategy classes* as a vocabulary list (factual categorization — not copyrightable)
- Individual library names and GitHub URLs (facts)

**What NEOTH cannot copy:**
- The curated list as a whole
- Prose descriptions
- The selection of "which 97 libraries matter"

### 3. Taxonomy structure (extractable without copying)

The strategy taxonomy (as *vocabulary*, not as copied text):

| Tier | Categories |
|------|-----------|
| Infrastructure | Backtesting frameworks (event-driven / vector-based), trading bots, analytics (indicators / metrics / optimization / pricing / risk), broker APIs, data sources |
| Strategy classes | Cross-sectional momentum, fixed income arbitrage, macro / multi-asset, crypto-specific, currency carry, equity factor |
| Knowledge | Books (beginner / biography / coding / HFT / ML), videos, blogs, courses |

This vocabulary could inform trigger_keywords in a hypothetical future NEOTH finance skill — but see scope argument below.

### 4. Finance scope argument for NEOTH

NEOTH is a personal AI daemon. Platform rule bars financial advice and trade execution. The analysis-only zone that remains:
- Passive market data display (summarize a data feed the user already subscribes to)
- Technical indicator computation from user-provided CSV data
- Fetching and parsing publicly available earnings reports for context

The awesome-systematic-trading list is a bibliography of academic strategies and research tools for **practitioners building trading systems**. NEOTH is not that product. The list has no implementation value for the narrow data-display scope that survives the platform rule.

### 5. Verdict

**SKIP.** No rights granted. Nothing ports to NEOTH. The taxonomy vocabulary (not copyrightable) could be noted in a planning document if a future NEOTH finance-data feature ever reaches the planning stage, but that feature has no confirmed consumer today (Rule 9).

---

## Repo 4 — impeccable (pbakaus, Apache-2.0, 53k★)

### 1. What it actually is

impeccable is a design-quality CLI + skill system for frontend interfaces. Its distinguishing architecture:

- **Durable context anchors:** `PRODUCT.md` (business context, modes, surfaces) + `DESIGN.md` (full token system: colors in OKLCH, type ramp at 16px root, spacing scale, radius, motion easing) — persisted per-project so the LLM always has brand truth
- **23 design commands:** `/audit`, `/critique`, `/craft`, `/bolder`, `/clarify`, `/colorize`, `/layout`, `/animate`, `/harden`, `/distill`, `/adapt`, `/live`, `/live-setup`, `/new-work`, `/onboard`, `/polish`, `/delight`, `/extract`, `/document`, `/doctor`, `/init`, `/ios`, `/android`
- **Deterministic detector:** exactly **59 antipattern rules** across 6 engines (regex text scan, static HTML CSS-cascade analysis, browser DOM inspection, screenshot contrast, design-system token drift, live browser injection)
- **Browser iteration:** Playwright-injected WebSocket overlay (`cli/engine/browser/injected/index.mjs`) reads computed styles + emits feedback — live iteration without file edits
- **5 audit dimensions scored 0–4:** A11y, Performance, Theming, Responsive Design, Implementation Integrity

### 2. The 59 Detector Rules — Complete Enumerated List with Slint Portability

**Source files:** `cli/engine/registry/antipatterns.mjs` (rule registry, 59 entries), `cli/engine/rules/checks.mjs` (detection logic, ~1700 lines), `cli/engine/engines/` (per-engine runners).

Portability legend: **S** = greppable in Slint `.slint` source | **SS** = screenshot/rendered only | **T** = text/copy scan | **DOM** = browser DOM only, skip for Slint

#### AI-Slop Visual Patterns (category: `slop`)

| # | Rule ID | Description | Slint Portability |
|---|---------|-------------|------------------|
| 1 | `side-tab` | Thick colored border on one side of a card | SS |
| 2 | `border-accent-on-rounded` | Accent border on rounded-corner element | SS |
| 3 | `overused-font` | Inter/Roboto/Poppins/Plus Jakarta Sans as display face | **S** — grep `font-family` or `font:` in `.slint` vs Theme token |
| 4 | `flat-type-hierarchy` | No meaningful size delta between heading levels | **S** — grep font-size ratios in `.slint` |
| 5 | `gradient-text` | `background-clip: text` with gradient fill | SS |
| 6 | `ai-color-palette` | Purple/violet heading text (sRGB hue 260–310) | SS |
| 7 | `cream-palette` | Warm off-white + warm brown = "recipe blog" palette | SS |
| 8 | `nested-cards` | Card inside card inside card (3+ depth) | **S** — grep nested `Rectangle` with border |
| 9 | `monotonous-spacing` | Same gap value on all spacing axes throughout page | **S** — grep `spacing:` values |
| 10 | `bounce-easing` | Spring/overshoot easing cubic-bezier or `animate-bounce` | **S** — grep `easing:` in animations |
| 11 | `pulsing-dot` | Decorative pulse keyframe on status dot | **S** — grep `animate` + keyframe pattern |
| 12 | `blinking-cursor` | Decorative blinking text cursor in hero | **S** — grep `blink` animation |
| 13 | `shape-assembled-illustration` | SVG triangles/shapes assembled as fake illustration | SS |
| 14 | `dark-glow` | Zero-offset colored box-shadow glow on dark background | SS |
| 15 | `radial-halo` | Radial gradient behind element as atmospheric halo | **S** — grep `radial-gradient` or equivalent |
| 16 | `radial-spotlight-glow` | Large radial overlay for hero "spotlight" effect | **S** — grep `radial` overlay |
| 17 | `marquee` | Infinite horizontal scroll animation | **S** — grep infinite x-offset animation |
| 18 | `icon-tile-stack` | 2×2 grid of colored icon tiles as generic feature visual | SS |
| 19 | `italic-serif-display` | Italic serif face in hero against sans body | **S** — grep `italic` + `font:` |
| 20 | `hero-eyebrow-chip` | Pill/chip label above hero headline | **S** — grep chip/badge above heading |
| 21 | `kicker-above-heading` | Small all-caps kicker text above heading | **S** — grep kicker / all-uppercase tiny text |
| 22 | `numbered-section-labels` | "01. 02. 03." section label numbering | **T** — text scan |
| 23 | `em-dash-overuse` | Em-dash as stylistic connector in UI copy | **T** — text scan |
| 24 | `marketing-buzzword` | "powerful", "seamless", "revolutionary", "game-changing" | **T** — text scan |
| 25 | `aphoristic-cadence` | Short punchy rhetorical cadence as prose style | **T** — text scan |
| 26 | `oversized-h1` | Hero headline > 96px at standard viewport | **S** — grep `font-size` on title/heading |
| 27 | `extreme-negative-tracking` | `letter-spacing` < −0.05em | **S** — grep `letter-spacing:` vs threshold |

#### Technical/Structural Defects

| # | Rule ID | Description | Slint Portability |
|---|---------|-------------|------------------|
| 28 | `broken-image` | `<img>` 404 or missing `alt` | DOM — skip |
| 29 | `script-error` | JS error on page load | DOM — skip |
| 30 | `content-hidden-at-rest` | Content visible only on hover/focus | **S** — grep `visible:` / `opacity:` conditional on hover |
| 31 | `edge-flush-cards` | Cards flush to viewport edge on mobile | **S** — grep `padding` on outer containers |
| 32 | `text-occlusion` | Text overlapping another element | SS |
| 33 | `first-viewport-column-overflow` | Content overflows on initial load | SS |

#### Accessibility Rules (medium-independent)

| # | Rule ID | Description | Slint Portability |
|---|---------|-------------|------------------|
| 34 | `gray-on-color` | Gray text on saturated color background | SS (contrast screenshot) |
| 35 | `low-contrast` | Text contrast < 4.5:1 WCAG AA (< 3:1 for large text) | SS (screenshot contrast analysis) |
| 36 | `layout-transition` | Transitioning `width`/`height`/`padding` (layout thrash) | **S** — grep `animate` on layout properties |
| 37 | `line-length` | Line > 80ch at body font size | Layout analysis |
| 38 | `cramped-padding` | Interactive element padding below minimum threshold | **S** — grep `padding:` on `TouchArea` / `Button` |
| 39 | `body-text-viewport-edge` | Body text within 12px of viewport edge | **S** — structural padding check |
| 40 | `tight-leading` | `line-height` < 1.4 for body text | **S** — grep `line-height:` |
| 41 | `skipped-heading` | h1→h3 without h2 (broken hierarchy) | **T** — heading structure scan |
| 42 | `heading-rhythm` | Inconsistent spacing above/below headings | SS |
| 43 | `justified-text` | `text-align: justify` on body text | **S** — grep `horizontal-alignment:` justify |
| 44 | `tiny-text` | Text < 11px | **S** — grep `font-size:` literals |
| 45 | `undersized-ui-text` | Button/label text < 13px | **S** — grep `font-size:` on `Button`/`TouchArea` |
| 46 | `all-caps-body` | Body text in all-caps | **S** — grep `text-transform` or manual uppercase |
| 47 | `wide-tracking` | `letter-spacing` > 0.12em on body text | **S** — grep `letter-spacing:` |
| 48 | `text-overflow` | Text overflows its container | **S** — grep `overflow:` / `clip:` |
| 49 | `repeated-container-text` | Same string in parent and child element | **T** — text scan |
| 50 | `clipped-overflow-container` | `overflow: hidden` clips meaningful content | **S** — grep `clip:` patterns |

#### Design-System Drift (highest value for NEOTH)

| # | Rule ID | Description | Slint Portability |
|---|---------|-------------|------------------|
| 51 | `design-system-font` | Font face not declared in design system | **S** — grep `font:` literals vs `Theme.font-*` |
| 52 | `design-system-color` | Hardcoded color not in design system tokens | **S** — grep color literals vs `Theme.color-*` |
| 53 | `design-system-radius` | Border radius not in design system token | **S** — grep `border-radius:` literals vs `Theme.radius-*` |
| 54 | `design-system-font-size` | Font size not on the enumerated type ramp | **S** — grep `font-size:` literals vs `Theme.font-size-*` |

#### Recent-Model Slop Patterns (batch 2)

| # | Rule ID | Description | Slint Portability |
|---|---------|-------------|------------------|
| 55 | `gpt-thin-border-wide-shadow` | 1px border + 40px+ shadow blur "GPT card" | SS |
| 56 | `repeating-stripes-gradient` | Repeating diagonal/linear stripes background | **S** — grep gradient pattern |
| 57 | `codex-grid-background` | Dot-grid or line-grid SVG background | SS |
| 58 | `theater-slop-phrase` | "The future of X is here" / "Building for tomorrow" | **T** — text scan |
| 59 | `image-hover-transform` | Scale/lift `transform` on hover of image element | **S** — grep hover animate scale |

**Portability summary:** 34 rules are greppable in Slint `.slint` source, 5 are text/copy scans, 13 require screenshot/rendered output, 7 are DOM-only (skip).

### 3. Audit Passes

The `/audit` command scores across 5 dimensions (0–4 each, 20 total):

1. **A11y** — contrast ratios, `prefers-reduced-motion` (flag 0.01ms global kill, not full disable), ARIA, keyboard nav, semantic hierarchy
2. **Performance** — layout thrash, unbounded blur/filter/shadow, lazy-loading, image optimization
3. **Theming** — hardcoded colors, dark-mode completeness, token consistency, theme-switch correctness
4. **Responsive Design** — fixed widths, touch targets < 44×44px, horizontal scroll, text scaling, breakpoints
5. **Implementation Integrity** — deterministic detector findings, design-system drift, product-specific coherence vs. generic/interchangeable design

Rating bands: 18–20 = Excellent | 14–17 = Good | 10–13 = Acceptable | 6–9 = Poor | 0–5 = Critical.

### 4. Browser Iteration Mechanism

The `/live` command:
1. Runs `node scripts/live-setup.mjs` to detect the dev server framework (Vite/Next/Webpack) and open a Playwright browser
2. Injects `cli/engine/browser/injected/index.mjs` into the page — a WebSocket overlay that:
   - Draws a red `<div id="impeccable-overlay">` banner for detected issues
   - Provides `window.__impeccable.detect()` to re-run checks after edits
   - Reports computed styles back via postMessage/WebSocket
3. The agent edits source files; the injected overlay re-runs detection and reports changes

**This mechanism is entirely DOM/browser-specific. There is no equivalent path for Slint.**

### 5. NEOTH-side gap assessment

**Verification runs (confirmed):**
- `rg -i 'ohlcv|stock_price|market_data|backtest|yfinance' SRC/neothd/src/` → 0 results
- NEOTH GUI uses `Theme.duration-entrance`, `Theme.duration-fast`, `Theme.duration-breathe`, `Theme.letter-spacing-*` — token system exists
- `animation-mode == 0` guard before `animation-tick() / Theme.duration-breathe` is already in `activity.slint:178` — div-by-zero protection is already shipped
- `design-system/` directory exists with `manifest.json` + `README.md` — design token definitions exist
- `_gate_gui_check.bat` runs only `cargo fmt --check` + `cargo check -p neothd-gui` — **zero design quality checks today**

**What NEOTH has:**
- Token system in `SRC/neothd-gui/ui/` with `Theme.*` properties (fonts, sizes, spacing, durations)
- Slint-specific motion guards already implemented
- No antipattern detection for design drift

**What NEOTH lacks:**
- Any automated check that `.slint` files respect the Theme token system (no `design-system-color` / `design-system-font` / `design-system-font-size` / `design-system-radius` equivalent)
- Any motion-pattern check (no `bounce-easing`, `marquee`, `layout-transition` detection)
- Any prose quality check (no `marketing-buzzword`, `theater-slop-phrase`, `em-dash-overuse`)
- The `PRODUCT.md`/`DESIGN.md` durable-context pattern as a formal gate (the `design-system/` README exists but is not formally loaded into every GUI work session)

### 6. What to steal

The value is **not** the JavaScript detector engine (DOM-bound, incompatible). The value is:
1. **The 59-rule taxonomy** — medium-independent vocabulary of what to check, adapted to Slint
2. **The `PRODUCT.md`/`DESIGN.md` workflow contract** — durable context that anchors every GUI work session to brand truth
3. **The 5-dimension audit scorecard** — structured QA pass instead of ad-hoc review

### 7. Licence obligations

Apache 2.0. Required when redistributing:
- Preserve `LICENSE` (Apache 2.0)
- Preserve `NOTICE.md` — attributes `ehmo/platform-design-skills` (MIT, used in `ios.md`/`android.md`)

If NEOTH ports the skill reference content into a bundled `design_lint` skill or `design-system/lint_rules.md`, the NOTICE attribution must be included in that file or in the design-system directory.

---

## Summary Steal-List (Ranked)

| # | Item | Source | Target NEOTH file | Effort | Real consumer |
|---|------|---------|-------------------|--------|---------------|
| 1 | 54 Slint-greppable rules from the 59-rule taxonomy (excludes DOM-only rules) | `impeccable/cli/engine/registry/antipatterns.mjs` rules 1–59 | `design-system/lint_rules.md` (new) — adapt IDs + Slint-specific patterns | M | `_gate_gui_check.bat` extended with `_gui_lint.bat` |
| 2 | Design-system-drift rule set (rules 51–54: font, color, radius, font-size) | `impeccable/cli/engine/registry/antipatterns.mjs` + `design-system.mjs` | `SRC/_gui_lint.bat` (new script) — grep `.slint` files for literal colors/fonts vs `Theme.*` | S | Pre-commit GUI gate; catches token drift immediately |
| 3 | `PRODUCT.md`/`DESIGN.md` durable-context workflow pattern | `impeccable/skill/SKILL.src.md` — context.mjs setup + PRODUCT.md/DESIGN.md | `design-system/PRODUCT.md` (new) + `design-system/DESIGN.md` (expand from current README) | S | Every GUI PR: mandate reading PRODUCT+DESIGN before touching `.slint` |
| 4 | 5-dimension audit scorecard (A11y / Performance / Theming / Responsive / Integrity) | `impeccable/skill/reference/audit.md` | `design-system/AUDIT_CHECKLIST.md` (new) adapted for Slint dimensions | S | Code-reviewer agent running on GUI PRs |
| 5 | Motion antipattern rules (bounce-easing, layout-transition, marquee, pulsing-dot) | `impeccable/cli/engine/rules/checks.mjs` — `checkElementMotion` function | `SRC/_gui_lint.bat` — grep `.slint` for bounce/spring easing, `animate` on layout props | S | `_gate_gui_check.bat` extension |
| 6 | Prose quality rules (marketing-buzzword, theater-slop-phrase, em-dash-overuse) adapted for UI copy | `impeccable/cli/engine/registry/antipatterns.mjs` + `cli/engine/engines/regex/detect-text.mjs` | `skills/bundled.rs` → new bundled skill `gui_copy_lint` (trigger: "review UI copy", "proofread interface text") | S | NEOTH's existing anti-slop prose skill extended to GUI text |
| 7 | Screenshot contrast check (low-contrast, gray-on-color rules) | `impeccable/cli/engine/engines/visual/screenshot-contrast.mjs` | `SRC/_gui_lint.bat` + screenshot via `cargo run --example screenshot` if Slint supports headless render | L | CI gate (Linux runner has headless); local = manual |
| 8 | `design-system-font`/`design-system-color`/`design-system-radius`/`design-system-font-size` token-drift detection logic | `impeccable/cli/engine/design-system.mjs` — `collectStaticDesignSystemFindings` | `SRC/_gui_lint.bat` — extract Theme token names from Slint theme file, grep for hardcoded literals | M | Every GUI change gate |

**Not stealing:**
- JavaScript detector engine (DOM-bound, incompatible with Slint)
- Browser live-iteration mechanism (Playwright + WebSocket overlay, browser-specific)
- `skill/reference/ios.md` / `android.md` (native platform — different target)
- Any finance repo content (free-stockdb, awesome-systematic-trading) — see verdicts above
- ECC framework — already evaluated GROUND-TRUTH, tracker closed

---

## Build Order — Staged Slices

**Slice 1 (~2 days): Design-drift gate**
- New file: `design-system/lint_rules.md` — the 59-rule taxonomy adapted to Slint, with portability column
- New file: `SRC/_gui_lint.bat` — grep `.slint` source for: literal color values not in `Theme.*`, literal font names not via Theme, font-size literals not on type ramp, `border-radius:` literals not via Theme
- Add call to `_gate_gui_check.bat`: run `_gui_lint.bat` and fail on findings
- Apache NOTICE attribution in `design-system/lint_rules.md`
- Consumer: next GUI PR immediately catches token drift (rules 51–54)

**Slice 2 (~1 day): Motion + spacing checks**
- Extend `_gui_lint.bat` with: bounce easing grep, layout-transition grep, marquee grep, monotonous-spacing heuristic, cramped-padding check on `TouchArea` / `Button`
- Consumer: catches motion antipatterns before code review (rules 9–12, 36, 38)

**Slice 3 (~1 day): PRODUCT.md / DESIGN.md formal context**
- Expand `design-system/README.md` → split into proper `PRODUCT.md` (surface map, modes, target user) + `DESIGN.md` (current Slint `Theme.*` token export, type ramp, spacing scale)
- Add to CLAUDE.md project instructions: load `design-system/PRODUCT.md` + `design-system/DESIGN.md` before any GUI work session
- Consumer: GUI PR reviews have brand context instead of ad-hoc inspection

**Slice 4 (v1.1 scope): Screenshot contrast**
- Add `_gui_lint.bat` screenshot pass using Slint headless render (investigate `slint-viewer --screenshot`) → feed PNG to contrast checker script
- Consumer: CI validates contrast ratios without a running app (Linux runner, no display needed)

---

## Files That Change Per Slice

| Slice | Files |
|-------|-------|
| 1 | `design-system/lint_rules.md` (new), `SRC/_gui_lint.bat` (new), `SRC/_gate_gui_check.bat` (extend) |
| 2 | `SRC/_gui_lint.bat` (extend) |
| 3 | `design-system/PRODUCT.md` (new), `design-system/DESIGN.md` (expand from README) |
| 4 | `SRC/_gui_lint.bat` (extend screenshot pass) |

---

## Items that contradict the brief's baseline

1. **free-stockdb's sync_url.txt is empty** — the repo ships NO pre-configured data source URL. The brief says "sync_url.txt is a strong hint that this pulls from a remote." It does — but from a *user-supplied* remote only. The binary pulls from wherever the user points it. There is no built-in data provider to evaluate for legitimacy; the legitimacy question applies to whatever *the user configures*.

2. **The 59 impeccable detector rules are confirmed exactly** — the brief calls them "~59 deterministic detector rules." The actual count from `registry/antipatterns.mjs` is exactly **59**. The check functions in `rules/checks.mjs` reference 47 unique rule IDs (the other 12 appear only in the registry with browser-engine support; they are defined but not yet implemented in the text/static-HTML engines).

3. **ECC's star count is misleading in the finance cluster** — 236k stars do not indicate a finance project. ECC is entirely a software-development coding harness. It has zero finance domain content. It ended up in this cluster likely due to folder proximity in the adoption batch, not domain relevance.

4. **impeccable's browser iteration is entirely browser-specific** — the brief suggests live browser iteration as a valuable feature. It is, but the mechanism is Playwright + injected DOM inspector, giving zero portability to Slint. The *workflow* concept (edit → detect → iterate) ports; the *mechanism* does not. The only live-iteration path for Slint is screenshot-based comparison, which requires separate implementation.

5. **NEOTH already has motion div-by-zero protection** — the brief's memory documents this as a Slint gotcha to watch for. `activity.slint:178` already contains `animation-mode == 0 ? 0.9 : 0.55 + 0.45 * sin(... / Theme.duration-breathe)`. This guard is in production. Any new animations added from impeccable rule study must follow this existing pattern (check `animation-mode` before dividing by a duration token).

6. **awesome-systematic-trading has NO LICENSE** — this is harder than just "no explicit open-source license." Under the Berne Convention, the work is under exclusive copyright from the moment of creation. There is no implied permission, no viral open-source condition to worry about, and no ability to "use it commercially." Facts (library names, URLs) are free; the arrangement is not. This is a cleaner block than a restrictive license — it simply means: do not copy the list.
