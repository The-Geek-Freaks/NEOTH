# Gold Wave 11 — local transcript candidate evidence

**Receipt status:** Stage 4 component accepted on 2026-09-13 from baseline
`716ad564496333eadc933d8454002ea7f6c358aa`. The final source and runtime gates
below pass. This component does not close P1-08.

## Implemented boundary

Stage 4 adds explicit local candidate list/export support to
`recall-parity-harness`. The operator supplies an existing local evidence home,
then selects active, unexpired `provenance_id` values and UTF-8-aligned spans in
JSONL. Export reads the home and transcript database read-only, authenticates
the selected current RAW/Bound proof, and writes only the selected text copy
(`source.evidence`), candidate vector, signed manifest/receipt, and bounded
local custody sidecar.

The signed artifact has durable identity but no durable permission. Every
local-evidence consumer dynamically revalidates custody against the supplied
existing home before accepting it: candidate validation, operator-anchor
intake, and later run reopen paths. Deletion, revocation, expiry, changed text
or frame custody, absent/altered custody, or concurrent state change rejects
consumption. Stage 4 does not mint transcript birth/recovery/WAL authority,
does not label candidates, and does not run providers or decide release
eligibility. It makes no automatic-purge claim for the copied source text.

The export's artifact parent must already exist. The target is absolute and
has no `.` or `..` navigation component. Its one-attempt lock reports busy for
concurrent export; the caller retries later. A retry reuses only byte-identical
children.

The operator contract and examples are in
[local transcript provenance](transcript-provenance-v1.md).

## Source and executable identity

The [source manifest](verification/gold-wave11-source-manifest.json) has 18 inputs: 16 Rust files plus `Cargo.lock`
and `Cargo.toml`. The selected-test binary is SHA-256
`C7D5E87B2F314CD413DD1DC77FC77300DE3C05C70123902B912B2CFB60024090` and
catalogues 14,247 tests. This receipt covers the selected 443 executions and
the separately owned child invocation; it is not a complete library or
workspace test receipt. The [test matrix](verification/gold-wave11-test-matrix.json)
records the exact selected names, binary size/hash, and result.

## Current gates

| Gate | Current result | Evidence boundary |
| --- | --- | --- |
| Selected02 | PASS — 443 passed, 0 failed, 0 ignored, 53.07s | Plus one parent-owned cross-process child, recorded separately. |
| TestBuild04 | PASS — 3m08s | One job; minimum free physical memory 216.95 GiB; peak 10.09 GiB; Idle priority and affinity 61440. |
| Contract03 | PASS — 10 | Contract checks only. |
| Strict Clippy02, library and tests, no-deps, warnings denied | PASS — 4m59s | Minimum free physical memory 215.72 GiB; peak process-tree working set 10.78 GiB. |
| Core check02, library | PASS — 1m38s | Minimum free physical memory 218.60 GiB; peak process-tree working set 7.33 GiB. |
| Workspace formatting check | PASS | `_gui_check.bat fmt --all -- --check`, including GUI static lint. |
| Independent source and final delta review | CLEAR | Includes existing-only key loading, mutation boundaries, partial-anchor recovery and Windows state publication. |
| Roadmap release / lost-feature integrity checks | PASS — 11 / 19 | Counts and existing release restrictions remain intact. |

All compile gates use `--locked --offline -j1`, debug info zero, Idle priority,
four logical CPUs (affinity 61440), and monitored process-tree termination if
free physical or virtual memory falls below 32 GiB. The load measurements
describe this run's constrained Windows build, not a general hardware guarantee.
The existing vendored `peeroxide-dht` dead-code warning does not fail the
no-deps Clippy gate.

The real local fixture covers signed export and exact retry, UTF-8 and duplicate
selection refusal, missing keys without initialization, foreign homes, legacy
rows, deleted sources, custody tampering and revocation. A separate concurrent
delete regression prevents returning text from a stale SQLite snapshot. The
full fixture runs all nine downstream consumers before revocation, then requires
custody-specific refusal and unchanged derived artifacts after revocation.
Offline signed grader fixtures prove the software transitions; they are not
evidence of real provider execution or operator judgments.

Diagnostic runtime failures exposed a partial-anchor resume regression and a
Windows self-pinned mutable STATE handle. The repaired publisher releases only
that handle immediately before exact-old-bytes replacement while retaining
immutable proof handles, the run lock and fresh readback validation. Both
repairs passed the final 443-test run and independent review.

## CI and acceptance boundary

GitHub Actions [run 34753681098](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/34753681098)
on the preceding Wave 10 commit is **FAILED**. Wave 11 includes three
baseline compile fixes found by that run, but 20 Windows failures remain for
Wave 12. This receipt makes no full-CI or cross-platform acceptance claim.

`GOLD-LF-P1-08` remains **OPEN**. Candidate export is only one prerequisite:
real operator labels, a shadow run, live four-grader evidence, and methodology
acceptance remain outstanding. The roadmap count remains 1,324 total items:
1,009 done, 313 open, and 2 partial.
