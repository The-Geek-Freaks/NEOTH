# W185 — daemon-owned local model operations

**Functional acceptance (2026-09-23):** W495 verifies33 unique identities and65 exact macOS/Windows test-class terminals with15-path scoped carry. See `docs/gold-wave495-local-model-acceptance.md`. The original source-only W185 notes below are retained as history; P1-19 is now accepted.

GOLD-LF-P1-19 is implemented across the Ollama controller, private same-user
IPC, daemon lifecycle, `models ollama`, Buddy status and Resources UI. This is
an independently reviewed implementation with passing Hosted core compilation;
native and GUI behavior acceptance remains pending.
It does not close the Road item.

The active native LocalOllama provider supplies the endpoint and selected
model. Only loopback origins are managed. Readiness requires a successful
bounded model-specific chat and fresh matching tags and loaded digest; fresh
loaded-use data accompanies the Ready state. Persisted readiness never returns
after restart without new observation. The daemon owns all mutable HTTP work;
CLI and GUI use the private daemon endpoint.

A single operation/observation permit serializes probes and mutations. The
mutation worker is parked until its exact intent is durably written. Pull and
update require terminal success and fresh exact inventory; prune refuses loaded
or absent targets and requires fresh absence. Explicit rejection is Failed;
a lost response, cancellation or restart after an uncertain effect remains
InterruptedUnknown. Retry binds an exact retained Failed receipt and never
replays an unknown operation. Worker ownership extends through terminal
reconciliation; shutdown must drain it while preserving any durable terminal.

GUI actions require typed acknowledgement, exact action/model/operation binding
and a separate fresh readback. Pulling a not-yet-installed model has a visible
operation row. Invalid or unavailable status clears prior Ready presentation.
Resource rows distinguish installed size, loaded total footprint and VRAM; RAM
is unknown without an authoritative RAM measurement.

Required Hosted evidence includes real bounded loopback HTTP controller tests,
private native socket/pipe discovery and roundtrip, concurrent status/cancel,
failed persistence before mutation, terminal persistence failure, drain during
blocked terminal reconciliation, restart, exact readiness and selector checks,
and the actual GUI callback fixture. The macOS custom harness includes W185.
These tests are source until their exact-source runner results are retained.

The 15 implementation paths and operator guide are admitted separately from
W186 live audio. Source freeze and final review are retained in
`work/gold-20260906/wave185-next-batch/`; the canonical source manifest and test
matrix bind the published test inputs. Generated CLI reference must be imported
from the matching successful Hosted exporter after these commands compile.

No local compiler, parser, formatter, fixture, product/GUI/audio runtime or test
is permitted under the workstation BSOD hold. All executable gates run on GitHub.

The final source review covers all 15 frozen implementation paths. Thirty new
native test identities (18 controller, nine IPC, two CLI and one lifecycle),
two common GUI parser tests and one Linux/macOS callback fixture are registered.
Custom CLI instances use the config-parent IPC home via "--config"; GUI children
inherit the selected NEOTH_HOME. The publication also includes the five narrow
A130 headless-harness/unused-receipt Clippy repairs. No runtime pass is claimed.

## Hosted follow-up on 2e7de3f6

Code Quality35693421727 passed. Preflight35693422094 requested 150 unique
formatting hunks in ten files (168 with native GUI aliases). The exact Hosted
changes are imported; one masked Authorization format-string context was kept
verbatim from the frozen input. No local formatter or parser was executed.
Core check35693435347 failed with four compiler errors: a mutable IPC guard,
two reqwest-to-anyhow conversions, and a shadowed fixture constructor. The
repairs preserve operation outcomes, shutdown ownership and test assertions.
The format and compiler receipts are retained in the W185 working directory.
Fresh Hosted checks and native/GUI behavior are still required; no Gold item
is closed by this repair publication.

Repair source87c18246 passed Code Quality35694661630. One final formatting
hunk from Preflight35694662282 is imported without a semantic change. Its core
check35694693234 remains in progress; native behavior is not accepted.

Hosted35694693234 on87c18246 completed SUCCESS: core test-target typecheck,
public CLI build and generated reference export. The exact reference is imported
with40 new Ollama help lines; SHA256
A7D8E0BA60CF9909AC2DC9250D2463E0C76DF14BCA06668CD4243AF4D8759A07.
Preflight35695206750 passed on4e9c0718. These do not prove native model operations
or GUI callbacks; GOLD-LF-P1-19 stays open.
