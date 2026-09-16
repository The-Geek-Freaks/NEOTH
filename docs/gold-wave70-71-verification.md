# W70/W71 — accepted coding results and worker provenance

Status on 2026-09-16: **reviewed source, partial local validation; remote CI
still required**. This report does not claim complete GUI, release, installed
package, visual/accessibility, or delivery acceptance.

## Implemented behavior

The decomposer binds accepted plans to the exact retained request attempt.
A repair request retains its own context before calling the provider; rejected,
malformed, failed or cancelled attempts do not acquire an accepted-result claim.

Accepted worker output carries a sealed context/output commitment, including
task identity, prepared-context bytes and hash, root/index/graph generation,
patch bytes/hash, test counts and summary hash. The commitment is validated and
persisted atomically before optional application. Legacy/custom workers retain
an explicit absent provenance value. Invalid internal commitments are rejected
before output materialization. Kanban detail decoding preserves valid stored
provenance and rejects malformed JSON or semantically invalid records.

The GUI coding-controller fixture now checks the selected-home service route,
provider requests, valid nonempty diff and persisted context/output commitment.
Its new source has compiled through Rust type checking, but the local link failed;
its runtime assertions remain unexecuted for this batch.

## Verified local scope

Admission09 owns 15 source paths. The retained proof contains 276 pre-docgen and
277 post-docgen inputs. All current source bytes were rechecked against those
snapshots after the host restart. The evidence is deliberately marked
`PARTIAL_LOCAL_PENDING_REMOTE_CI` in both the
[source manifest](verification/gold-wave70-71-source-manifest.json) and
[test matrix](verification/gold-wave70-71-test-matrix.json).

| Gate | Recorded outcome |
| --- | --- |
| Native Clippy11, library and tests | PASS, 4m33s |
| Native test build02 | PASS, 6m46s |
| Native selected01 | 2925 passed, 0 failed, 1 ignored; 2926 selected from 14750; 186.96s |
| Required native fixtures | All 35 passed across the 25-filter selection |
| Integration contracts01 | Seven targets; 750 passed, 0 failed, 0 ignored |
| CLI documentation fixture | 1 passed, 0 failed; 0.05s; existing binary, no compilation |
| Python contracts and CI matrix | 45 tests passed; Windows/macOS matrix assertions passed |
| GUI source lint | PASS; no visual or runtime claim |
| GUI build01 | Interrupted; no completion receipt |
| GUI build02 | FAILED at local link: LNK1127, damaged `libneothd-ddac4ec8c56e3249.rlib` |
| New GUI runtime/catalogue and GUI Clippy | Pending remote execution |
| Full platform/workspace CI | Pending remote execution |

The native executable is `SRC/target/debug/deps/neothd-7119ee327a8a7e9e.exe`,
294478848 bytes, SHA-256
`F2197810F851F7CB0CAB2ED84AF45CDA04B6180FB3B8399A4704952C38C73CFF`.
Its identity, exact catalogue/selected-test equality, all required fixture source
hashes and the source snapshots were verified before recording the partial proof.
The older W66 GUI binary is not evidence for W70/W71.

## Remaining execution and host constraint

The user reported repeated bluescreens. Windows recorded an unexpected shutdown
at 08:24:54 and a restart at 08:25:59 on 2026-09-16 local time. No compiler remains
running. The exact cause has not been established; free RAM telemetry alone does
not establish host stability. GUI build02 recorded at least 211.61 GiB free RAM,
a peak build working set of 18.67 GiB and no memory-guard termination.

Further heavy local Rust compilation is suspended. The remaining build, GUI
runtime/Clippy and full integration gates move to GitHub-hosted CI from reviewed
source on `main`. Lightweight source, formatting, Python and documentation checks
may continue locally. No full-pass result is manufactured from the interrupted
or failed GUI attempts, and no roadmap acceptance box is closed by this handoff.

The roadmap remains 1324 total / 1015 checked / 307 open / 2 partial
(raw unchecked 309, pre-tag open 308). Local installer, delivery and visual
acceptance remain separate obligations.
