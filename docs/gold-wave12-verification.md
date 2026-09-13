# Gold Wave 12 — Windows nextest repair

**Receipt status:** **LOCAL REPAIR ACCEPTED** on 2026-09-13. The focused
regressions from CI run `34753681098` pass on the final Windows test executable.
The build, selected runtime tests, strict Clippy, Core check, formatting and
independent review pass. Full CI and cross-platform acceptance remain pending;
this repair closes no roadmap item and does not change P1-08 status.

## Published baseline

Wave 11 was committed and pushed as
`970f819155b95bf61eeec86989e11ea5f69ca4e5`. Its Preflight run `34757107740`
and Code Quality run `34757107575` succeeded. Wave 12 is a new, focused repair
after the earlier Windows nextest evidence; it is not evidence that the prior
full CI has been repaired.

## Applied source scope

Eight Wave 12 source files are changed. The intended corrections are:

- SQLite fixture paths use the transcript store factory so required SQL
  functions are registered.
- On Windows, inherited DACLs are tightened before an identity-bound verifier
  accepts the object.
- The history/schema assertion expects schema 38, and the CLI parity inventory
  includes `context`.
- The MCP catalogue assertion covers its nine actual tools; the diff-impact
  fixture supplies real newlines for parser-backed input.
- Provider/chat tests assert typed `TrustDecision` behavior and exact ordering;
  the decomposer assertion retains its audited fingerprint.
- The Windows hygiene regression uses the existing test-only unsupported-volume
  scope to require recovery deterministically. Qualified NTFS publication may
  legitimately confirm its write-through rename; production durability logic
  remains unchanged.

These are narrowly scoped fixes for the failure inventory. They do not create
new transcript provenance, provider, release, or cross-platform authority.

## Acceptance gates

The first diagnostic build passed. Its selected run executed 359 tests:
356 passed and three failed. Two new chat assertions used `authorization_id`
where provider lifecycle frames name the same value `invocation_id`; the
permission and trust records retain `authorization_id`. The third failure was
the stale Windows durability assumption described above. These assertions were
corrected and independently reviewed before the final passing runtime gates.

| Gate | State | Note |
| --- | --- | --- |
| TestBuild02 | PASS — 3m18s | Minimum free RAM 215.98 GiB; peak build working set 10.20 GiB. |
| Selected Windows-repair tests02 | PASS — 359 / 0 failed / 0 ignored, 15.73s | Seven affected modules, including every reported CI failure with its current test name. |
| Qualified / unsupported Windows commit regressions01 | PASS — 2 / 0 failed / 0 ignored, 0.03s | Both native durability outcomes verified separately. |
| Strict Clippy01, library and tests, no-deps, warnings denied | PASS — 2m43s | Minimum free RAM 219.45 GiB; peak working set 6.61 GiB. |
| Core check01, library | PASS — 36.17s | Minimum free RAM 221.34 GiB; peak working set 4.38 GiB. |
| Workspace formatting check | PASS | `_gui_check.bat fmt --all -- --check`, including GUI static lint. |
| Independent review and final diagnostic delta | CLEAR | Typed audit linkage, bounded storage identity and test-only durability scope. |
| Lost-feature / roadmap release checks | PASS — 19 / 11 | Existing count and release restrictions retained. |
| Full CI / Windows nextest | **PENDING** | No repaired CI result recorded yet. |

The [source manifest](verification/gold-wave12-source-manifest.json) binds eight
Rust inputs plus `Cargo.toml` and `Cargo.lock`. The [test matrix](verification/gold-wave12-test-matrix.json)
records 359 selected names and the two supplemental tests against the same
14,247-test executable. Its SHA-256 is
`1FEAD25A3C2BF6EB586424557758652D06D6BA6183FEBF87576CC7F34542D44D`.
These are 361 unique passing tests, not a complete library/workspace run.

All compile gates use one job, debug info zero, locked/offline dependencies,
Idle priority and four logical CPUs (affinity 61440). The process-tree monitor
stops owned build processes if free physical or virtual memory falls below
32 GiB. The existing vendored `peeroxide-dht` dead-code warning does not fail
the no-deps Clippy gate. No GUI monolith or installer was linked locally.

`GOLD-LF-P1-08` remains **OPEN**. Roadmap counts and checkboxes are unchanged
at 1,324 total, 1,009 complete, 313 open and two partial: 315 raw blockers and
314 pre-tag blockers. A full CI run on the published repair commit is the
next integration gate; no source-only or selected-test result substitutes for it.
