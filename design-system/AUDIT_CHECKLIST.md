# NEOTH Slint GUI Audit Checklist

Use this scorecard for a GUI PR, focused GUI repair, or release-candidate
review. It adapts five audit dimensions to Slint's native GUI model. It is
evidence-first: an unchecked or unrun item is **not** a pass.

This is a review artifact, not a closure claim. ADOPT31-G1 and ADOPT31-G4 stay
Road-open until their separately required exact-head remote gates and evidence
exist. This checklist cannot close G2, G3, G5-G7, GOLD-R4-09, or any broader GUI
Road item.

## Record the review

For every row, use exactly **Pass**, **Fail**, or **N/A** and add an evidence
link, command/result, screenshot path, or concise manual observation. `N/A`
requires its reason in Evidence. A blank evidence cell is incomplete, not Pass.

| Review metadata | Value |
|---|---|
| Commit / exact ref | |
| Reviewer | |
| Date | |
| Platform, window sizes, DPI/scaling | |
| Changed Slint/Rust/UI-copy files | |
| Remote exact-head gate references | |
| Screenshot/runtime artifact locations | |

## 1. Accessibility

| Check | Status (Pass/Fail/N/A) | Evidence |
|---|---|---|
| Keyboard path reaches and visibly focuses every changed interactive control. | | |
| Focus order follows task order; no required content is hover-only. | | |
| Labels, current state, errors, progress, cancel, retry, and disabled/unavailable states are understandable without color alone. | | |
| Rendered signal colors and text have recorded contrast assessment (`gray-on-color`, `low-contrast`). | | |
| Text roles, leading, and control labels remain readable at tested scaling (`tiny-text`, `undersized-ui-text`, `tight-leading`). | | |
| Small-window view preserves text, padding, and no clipped meaningful content. | | |
| Platform accessibility-tree/screen-reader evidence is recorded where the changed surface exposes it, or N/A names the platform reason. | | |

## 2. Performance

| Check | Status (Pass/Fail/N/A) | Evidence |
|---|---|---|
| No changed animation affects layout width, height, or padding (`layout-transition`). | | |
| Motion has state purpose; no decorative bounce, pulse, blink, marquee, or image-hover lift (`bounce-easing`, `pulsing-dot`, `blinking-cursor`, `marquee`, `image-hover-transform`). | | |
| New animation follows the existing safe duration/animation-mode guard pattern; zero/disabled animation cannot divide by zero or loop unchecked. | | |
| The changed screen has no observed startup/interact jank, unbounded repaint loop, or avoidable heavy effect at the tested target. | | |
| Long text, busy state, cancellation, and error state remain responsive in the reviewed flow. | | |

## 3. Theming

| Check | Status (Pass/Fail/N/A) | Evidence |
|---|---|---|
| G2 token gate result is recorded for the exact reviewed ref. It covers only `design-system-font`, `design-system-color`, `design-system-radius`, and `design-system-font-size`. | | |
| Changed source has no unreviewed non-Theme font/color/radius/type-ramp drift outside documented G2 compatibility behavior. | | |
| Signal meaning remains coherent: green memory/live, pink consent/boundary, cyan audit/proof, amber in-progress/caution. | | |
| The change avoids unintended purple/cream palette drift, unreadable gradient text, generic grid/stripe background, or excessive glow. | | |
| Card, halo, border, and shadow treatments convey hierarchy rather than generic AI-card decoration. | | |
| Buddy/visual state, if changed, corresponds to live state and does not imply an action or approval that did not occur. | | |

## 4. Responsive

| Check | Status (Pass/Fail/N/A) | Evidence |
|---|---|---|
| Rendered initial viewport has no horizontal overflow, text occlusion, or required-content clipping. | | |
| Small-window layout preserves outer padding; cards and body text are not edge-flush. | | |
| Heading/body hierarchy, measure, tracking, and rhythm remain readable at tested sizes. | | |
| Interactive areas retain adequate padding and task flow at tested window sizes. | | |
| The change does not add unnecessary nested cards, decorative chips/kickers, numbered labels, or generic icon-tile stacks. | | |
| Any visual assertion needing a render has a screenshot/runtime artifact, not a source-only Pass. | | |

## 5. Implementation integrity

| Check | Status (Pass/Fail/N/A) | Evidence |
|---|---|---|
| Source ownership is clear: no duplicate visible strings, hidden-at-rest requirement, accidental all-caps/marketing/theatre copy, or skipped heading hierarchy. | | |
| Changed UI actions have real enabled, disabled, unavailable, loading, error, cancel, and retry behavior appropriate to the action; no dead or misleading control exists. | | |
| No raw stack trace, secret, or fabricated readiness/success claim reaches the operator surface. | | |
| Production token authority remains `SRC/neothd-gui/ui/theme.slint`; this folder was not treated as compiled runtime. | | |
| `lint_rules.md` classes were honored: only `gate-now` is automated; source/text/screenshot rows have stated evidence; DOM-not-applicable is not scored Pass. | | |
| Required remote CI/Security/CodeQL evidence exists for the exact reviewed head, or the review remains incomplete with the missing gate named. | | |

## Scores and verdict

Score each dimension 0-4 only after its table is complete. Do not calculate a
release-style total when a required row is blank, failed, or awaiting an
exact-head gate. A number is triage information, never a substitute for a
required Pass.

| Dimension | Score (0-4) | Blocking finding / evidence summary |
|---|---:|---|
| Accessibility | | |
| Performance | | |
| Theming | | |
| Responsive | | |
| Implementation integrity | | |
| **Total** | **/20** | |

| Audit verdict | Value |
|---|---|
| Required-row state | Complete / Incomplete |
| Blocking failures | |
| Follow-up owner and Road item(s) | |
| Exact-head remote evidence state | Verified / Pending / Failed |
| Release/closure claim | None unless separately proven |

## Finding record

Do not downgrade a missing test or unavailable platform into a pass.

| ID | Severity (P0-P3) | Rule/check | Location | User impact | Required fix or evidence | Status |
|---|---|---|---|---|---|---|
| | | | | | | |
