# Gold Waves 35, 36 and 38 — shared chat turns and graph confidence

**Receipt status: LOCALLY VERIFIED.** The admitted scope contains sixteen
source files and retains 197 source inputs. Strict Clippy passes in 2m57s;
the final unit build passes in 3m41s. The selected runtime suite passes
**888 tests, zero failures, zero ignored** in 70.46s, using ten filters from
14,501 catalogued tests. All thirteen integration targets pass **157 tests,
zero failures, zero ignored**; their compile took 2m39s. The GUI compile check
passes in 6m25s without a GUI link. Its thirteen existing
`trusted_probe_supervisor` warnings are unchanged. The Python suites pass
19 document-integrity, 11 roadmap, and 8 release-contract tests.

The [source manifest](verification/gold-wave35-38-source-manifest.json) and
[test matrix](verification/gold-wave35-38-test-matrix.json) retain 197 source
inputs, fourteen executables, and every selected test name. The final catalogue
check caught a misspelled default-invocation filter; the corrected selection
includes all fourteen intended launcher tests on the same final executable.

The unit executable has 284878848 bytes and SHA-256
`775FD96D695A8C74FDD3C35E0FD91A95529980EF49D775DBD2C9B281D1A2BEC0`.
All local build gates use one Cargo job, Idle priority, four selected logical
CPUs, disabled debug information, and an enforced 32-GiB free-memory reserve.
The final unit build retained at least 216.10 GiB free RAM and peaked at
10.45 GiB of observed process-tree working set. No GUI monolith was linked.

## Chat ownership and completion

W35 extracts the existing after-WAL turn into `cli::chat_turn_pipeline`.
The CLI adapter retains preparation, request admission, and creation of its
home-bound writer. It passes the exact selected segment path and closes the
request cancellation gate after the engine returns. It then drops the writer,
awaits the completion channel, and invokes the presentation finalizer.
An actual WAL shutdown-marker failure suppresses both deferred done output
and the success terminal; an engine error remains the primary failure when
writer completion also fails.

W38 makes this engine available to another in-process caller with its own
admitted configuration, provider, writer, segment path, and typed sink. The
engine does not construct or drain the caller's writer and leaves the terminal
result for its caller. Runtime coverage exercises that ownership with a real
WAL and controlled provider. A separate custom-config regression executes
`/skill disable academic_research`, changes the selected YAML, keeps the
sibling default `freedom.yaml` byte-identical, and makes zero provider calls.
Incognito, refusal, attachment, cancellation, and output compatibility tests
remain in the selected suite.

## Graph confidence and migration

W36 adds `confidence` and `confidence_tier` to graph edges. The valid ordinal
pairs are `inferred` / 50 and `resolved` / 100. Schema 8 migrates to schema 9
with conservative inferred defaults, and endpoint resolution does not upgrade
regex-derived evidence. Invalid persisted pairs fail before traversal.

The migration tests also retain the competing-opener race: a reader that saw
schema 3 rechecks under its write lock after another opener has migrated.
They verify both new columns and the 50 / inferred defaults on a retained
legacy edge. Bounded traversal prefers stronger same-depth paths while
preserving shortest-hop ordering, depth-only scores, deterministic ties,
and existing root, generation, stale-state, and cycle guards.

## Verification repairs and CI boundary

The extraction required source-contract assertions to follow their actual
owners. The Incognito test bounds both source views before their test modules
and normalizes whitespace only for its alternate-ingress ordering check.
The attachment contract follows preparation, caller-owned WAL completion,
and the finalizer; its raw-prepend prohibitions still cover both modules.
MCP catalogue assembly remains zero calls in the CLI adapter and exactly one
in the typed engine. The corrupt-confidence and real-WAL regressions inspect
the complete anyhow error chain and retain the exact expected root cause.

An intermediate contract run executed an older cached binary because copying
the candidate had retained its timestamp. That run is excluded. Admission
now advances changed source timestamps after hash verification, and final
evidence must use the subsequently built executables.

Full CI `34820034751` on published `ff101c05` passed Linux, Windows, and its
other independent jobs, but macOS reported 16,126 passes, two failures, and
23 skipped tests. Both failures received `Deadline` instead of their required
missing-store/query-error outcome. The admitted repair adds one private
budget parameter used by those two semantic fixtures with five seconds.
The public recall entry, normal worker construction, and existing deadline
tests retain the 250-ms production budget. The local selected suite covers
the repaired fixtures and deadline cases; a new macOS CI run is still required.

## Remaining scope

ADOPT31-E1 is locally complete for typed edge confidence, conservative migration,
and bounded same-depth traversal. Roadmap totals are 1,324 items: 1,012 done,
310 open, and two partial (312 raw and 311 pre-tag blockers).
P2-26, P1-16, P1-17, R3-18B, and their parent rollups remain open.
This receipt does not establish daemon
RPC, GUI/Buddy ownership, native packaged operation, live-provider delivery,
cross-platform acceptance, or a completed Gold release. Publication identity
is the Git commit containing this receipt.
