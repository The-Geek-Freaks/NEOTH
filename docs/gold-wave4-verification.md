# GOLD Wave 4 verification

**Status date:** 2026-09-07
**Scope:** bounded local implementation checkpoint for required trust decisions.
All checks listed below are complete. This report does not close
GOLD-LF-P1-05 or any roadmap checkbox.

## Source and runtime provenance

The [source manifest](verification/gold-wave4-source-manifest.json) records
**19 changed compiled source inputs** against base
`89c21dd3256408102f73de3bb7eeaa16a1361602`. It is not an inventory of every
transitive dependency or a release artifact manifest. The
[test matrix](verification/gold-wave4-test-matrix.json) records the exact binary,
selected filters and completed gates. Post-gate readback at
`2026-09-07T08:37:25Z` confirmed all 19 source hashes and both executable hashes.
The publication target is GitHub `main`; the manifest's branch field records
the historical branch at the time the inputs were frozen.

The fresh library test binary contains **14,129 tests**, is **271,911,936 bytes**,
and has SHA-256
`303A46117041066DA180DC947B92C5B6B7883D394C4027C00DB9E64358A1E5C4`.
Its final compile passed in **3m43s** (`TEST_EXIT=0`).

The public debug executable is **181,779,456 bytes**, reports `neoth 1.0.0`,
and has SHA-256
`3156B1FE3C5E9B687E17BBFC13B5EBA3D26A73E1B7B48365F4D15C6839E14413`.
These are locally built debug binaries from the recorded source inputs,
not signed release artifacts.

## Completed checks

| Check | Result |
|---|---|
| Selected runtime matrix | **15/15 groups, 1,605 passing parent-harness test executions**, no failed group or zero-test filter. Counts are executions, not a deduplicated full suite. |
| Strict core Clippy | `--lib --tests --no-deps -- -D warnings` passed in **6m08s**, `CLIPPY_EXIT=0`. An existing peeroxide-dht dependency warning is outside the no-deps lint scope. |
| Core package check | `_check.bat` passed in **1m31s**, `BUILD_EXIT=0`. |
| GUI package/test check | Default-feature `check -p neothd-gui --tests` passed in **6m03s**, `GUI_GATE_EXIT=0`. It retains 13 existing probe-supervisor dead-code warnings. |
| Production GUI controllers | The Code Map and Coding integration harnesses passed **6/0 + 6/0** in **4m05s**, `GUI_GATE_EXIT=0`. |
| Public CLI build and startup | `_build.bat --locked --offline -j1` passed in **4m16s**, `BUILD_EXIT=0`. Version and seven affected help pages each exited **0**; the matrix records all eight probes. |
| Workspace metadata | Locked metadata parsed successfully: **5 packages, 5 workspace members**, `GUI_GATE_EXIT=0`. |
| Workspace formatting and GUI static guard | `_gui_check.bat fmt --all -- --check` passed, `GUI_GATE_EXIT=0`; its GUI-lint fixtures and production token/motion guard also passed. |
| Static release contracts | Arrayref provenance, cadence, manifest generation, provider parity, roadmap, assets, capabilities, release gate, isolation, bootstrap verifier and lost-feature integrity passed. |

Two entries are marked ignored in the parent harness. The RPC health-probe
helper is deliberately invoked and passes as a child process of its parent
test; the existing WAL latency measurement is an opt-in benchmark and was not
run. The 1,605 total uses the final parent-harness summaries, rather than
accidentally counting an intermediate child summary as the group result.

## Verified implementation boundaries

The production contract is documented in
[required trust decisions](trust-decision-boundaries.md).

| Area | Behavior and final focused evidence |
|---|---|
| Coding apply and self-source | Canonical policy and authenticated audit precede worktree/live-source effects. Private consumed admission binds physical root, task and accepted patch. Cancellation before and after admission has distinct truthful history and no premature worktree effect. Self-source records an early terminal denial or a final allow after integrity fences. **Coding 574/0, Coding CLI 29/0**. |
| Windows Git transport | Verbatim disk/UNC paths are converted only for Git arguments, with lossless UTF-16 and physical target/parent revalidation. The real Unicode Windows worktree create/cleanup fixture passes. Device namespaces remain unchanged; UNC transport has unit coverage, not a live network-share acceptance claim. |
| Local CLI writes | Todo/Calendar use a shared production admission-to-effect seam and retain the exact captured request, destination and account. Skill/cron writes revalidate under coherent config authority; a canceled outer await cannot drop the audit owner while the actual blocking mutation continues. **Audit owner 3/0, self-activation 19/0, Todo 6/0, Calendar 6/0, config 462/0**. |
| External HTTP and released research | Required canonical decision uses the same audit owner and precedes intent/permit/transport. Released research still confirms the real request but persists fixed provider-neutral labels and random correlation, including the denial digest. **External HTTP 25/0, web-fetch 53/0**. |
| One-shot MCP | Exact-home writer/RPC ownership spans canonical server/tool/argument admission and spawn/effect; a live daemon failure cannot create a fallback writer. Fixed exact historic Codegraph v6/v7/v8 catalogues migrate to nine tools without trusting unknown names, duplicates or lookalikes. **CLI MCP 34/0, MCP gate 31/0, audit RPC 56/0 plus its child helper**. |
| Shared audit consumers | Canonical permissions/replay **194/0**, WAL writer **86/0** plus the ignored benchmark, OS gate **27/0**. |

The GUI source comparison also verified that the old editable source label
`cli` could suppress the final policy check. The private CLI confirmation
marker and always-present policy close that bypass. Normal GUI/Buddy apply
already refused Confirm at the baseline; this batch does not implement their
separate user-confirmation flow.

## Repairs retained in the evidence

The first test compile exposed two MCP type/ownership errors. The first
runtime matrix then exposed a real Windows verbatim-path Git failure, stale
Codegraph migration assumptions and legacy total-frame/subtype expectations.
These were repaired and independently re-reviewed before the final compile.
The Strict assertion now proves complete denied semantic decisions and no
worktree, without treating retry count as an invariant.

Static checks found older dashboard count drift and Windows autocrlf changes
to three arrayref metadata files. Published ROAD/PROGRESS counts now match the
existing checkboxes; no checkbox changed. The three vendor files again match
their original Git/upstream bytes, and `.gitattributes` disables conversion
only for that certified archive. No dependency hash, allowlist or test gate was
relaxed. Intermediate logs are retained under `work/gold-20260906`.

## Evidence limits and remaining work

This is a selected suite supporting a bounded implementation commit under
`PLAN/BUILD_AND_RELEASE_CADENCE.md`. It is not an unfiltered execution of all
14,129 library tests or a full workspace, release, live-provider, peer,
interactive GUI, package or clean-machine qualification. The Windows recovery
rule keeps the linked GUI test monolith out of local runs; that gate belongs
to CI.

P1-05 remains open for durable proactive/webhook decision reconciliation,
authenticated cluster-task admission, required upstream channel-reply audit,
and Obsidian preload admission. GUI-local apply confirmation is also separate
remaining product work. Full affected-feature/workspace and exact-candidate
CI/Security/CodeQL evidence remains required before Gold.
