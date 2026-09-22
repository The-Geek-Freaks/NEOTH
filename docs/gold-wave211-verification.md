# Wave 211 embedding model selection and operator lifecycle

W211 connects the W210 local BGE-M3 adapter to a dedicated embedding-model
surface. The closed model selection remains `qwen3_q8 | bge_m3`; chat model
routing and the existing Ollama lifecycle keep their own controls.

`neoth models embedding --config PATH list|status|select|probe|pull|repair|prune`
provides a strict versioned JSON envelope with two ordered model rows, selected
model, observation time, cache state, readiness, immutable BGE repository and
revision, and supported actions. Selection uses the canonical locked lossless
config update and exact readback, including custom config filenames. Lifecycle
JSON has no human stdout prefix. The existing fixed-target `models bge-m3`
commands retain their direct semantics.

Periodic GUI status only examines the cache. A selected BGE `probe` explicitly
verifies pinned artifacts and performs a native model load, then rejects a
changed configuration before returning fresh Ready. Qwen currently has no
read-only native-load probe or standalone CLI lifecycle; its controls remain
unavailable. A constructor or download cache is never a Ready claim.

The Settings selector and Resources card call the real core CLI. Typed parsing
rejects unknown fields/states, wrong model order, wrong pins, impossible clocks,
and actions for unselected/Qwen rows. UI operation generations reject stale
completion; the selected model remains at its confirmed readback until the core
transaction completes. Buddy verifies only a fresh selected BGE probe; successful
cache lifecycle actions complete neutrally and errors remain failures. Status,
select, probe, and lifecycle commands have separate bounded timeouts with
concurrent capped stdout/stderr draining and kill/reap on failure. Resources
scrolls as model cards grow.

## Evidence and remaining gates

Five core regressions cover closed commands, cheap status, selected actions,
custom-config lossless selection and strict JSON. Five GUI contract regressions
cover valid and invalid envelopes, fresh selected readiness, actions, cache-only
rejection, immutable pins and observation clocks. The grouped core lane now
selects 205 exact tests. Inventory: 524 source paths, 752 universal native and
92 GUI identities, plus unchanged platform-specific, audio and macOS harness
identities. Source checks and independent static review are separate from the
pending GitHub build, behavior and GUI rendering gates.

W210 source-bound results are confirmed: Grouped200 run `35759964957` on
`ab2902ec` ran all 200 cases, with 199 passing and only W205 failing. W207 passed
17/17 and W210 13/13. BGE run `35760067844` on `db27a66c` passed the product CLI
pull and both exact official-model/native-load and retained-Ready recovery tests.
W205 was corrected at `ff9fe8e2` to query the actual full `leaf_delegated`
identifier and establish injected context before WAL custody assertions.

The applicable GUI source review uses `design-system/PRODUCT.md`, `DESIGN.md`,
`lint_rules.md`, `AUDIT_CHECKLIST.md` and the component API. New visual values
use Theme tokens and existing card strokes. Text carries working/unavailable/
verified state independently of color; no new animation was introduced.
Required GUI audit state remains **Incomplete**: hosted token/motion lint,
compiled callbacks, screenshots, small-window/keyboard/accessibility behavior,
and native-platform runtime results are still pending. No total GUI score or
release closure is claimed from source. GOLD-LF-P2-24 remains open, including
model-switch isolation addressed by W212 and remaining native acceptance.

The workstation stays under the absolute BSOD hold. No local compiler, Cargo,
formatter, code/model parser, tests, fixtures, product/GUI/audio probes or model
weight downloads ran.
