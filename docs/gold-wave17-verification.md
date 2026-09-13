# Gold Wave 17 — account CLI, runtime health and CI repairs

**Receipt status: LOCALLY VERIFIED; full CI pending.** Source and focused
repairs are independently reviewed. Fresh unit/integration behavior, final
Clippy, formatting and the relevant integrity/release checks pass.

## Account behavior

The existing channel inventory retains one root row per registered channel.
Valid mapped Telegram accounts add sorted, secret-free child rows containing
their exact ChannelRef, configuration readiness and an optional runtime state.
Legacy scalar Telegram keeps its prior shape. Invalid or partial account maps
do not produce usable children.

`neoth channel test telegram --account <id>` selects exactly one authenticated
mapped bundle. Missing, unknown, partial, legacy-flag and non-Telegram-flag
requests fail before transport invocation. The legacy no-account entrypoint
and two-argument home-scoped API remain available. A credential probe never
claims that an inbound daemon adapter is running.

The existing adapter supervisor publishes a private, atomic runtime projection
for its owned fleet. It preserves old tags while old handles remain alive
through reload debounce, changes tags after replacement, reaps finished handles,
and publishes stopping/stopped lifecycle state. The CLI accepts only a bounded
regular file, a current same-home snapshot, the exact authenticated live daemon
instance, and matching tags from its current coherent account bundles.
A rotated or removed A row cannot erase a still-matching B observation.
Unknown runtime is omitted from JSON and rendered as unknown in the table.

The file is observational; it is not a credential store or authorization input.
Opaque secret-derived comparison tags never appear in operator output.

## CI repairs included

- An absent default account map serialized as a non-null empty object. CLI
  credential field reporting now excludes it, and an import omitting the map
  preserves existing mapped credentials. An explicitly populated incoming map
  still replaces the map through the established import path.
- Two legacy Telegram recovery fixtures now use the existing injected-store
  coherent recovery loader, eliminating real Linux Secret Service access.
- Fresh private History creation rejects every preexisting SQLite sidecar
  before creating the main database, including dangling symlinks. Portable
  regressions retain the original sidecar bytes and prove the main file absent.
- Two watcher acceptance tests now allow their configured 30-second periodic
  reconciliation plus five seconds for the final post-write observation.
  Other short waits and production watcher policy remain unchanged.
- Wave15 macOS CI spent 74m30 compiling and exhausted its 75-minute nextest
  step after test startup. The macOS budget is now 90 minutes for nextest and
  105 minutes for the job. Windows retains 50/90; resource and test settings
  are unchanged.

## Verification and retained corrections

Clippy01 rejected the new runtime reader's Option collection. The reviewed
correction explicitly wraps the matching-row subset in Some and fixes a
test-only helper-name shadow. Clippy02 found three newly unused compatibility
wrappers and an equivalent question-mark simplification. CLI dispatch again
uses the legacy wrappers for no-account requests; the old audit health wrapper
is test-only while production uses the authenticated instance result.

The Unix file reader uses nonblocking open before regular-file validation so
a FIFO cannot block channel listing. An initial proposed regression cleanup
could wait indefinitely; the reviewed final test bounds cleanup and always
fails the initial timeout, even when cleanup successfully wakes the reader.

Clippy03 then found an ambiguous lifetime in the account lookup test helper;
Clippy04 found a keys-only map iteration in that helper's tests. Both minimal
corrections are reviewed. The final strict Clippy05 run passes.

TestBuild01 passed in 7m12 (189.13 GiB minimum free, 15.48 GiB peak). Its fresh
14,358-test catalogue supplied 405 selected cases: 403 passed, one failed and
one existing child-process helper was ignored, in 19.82s. The failure was a
Windows sharing violation while the private atomic writer was publishing.
Production already treats a transient read failure as unknown. The reviewed
fixture now permits only Windows OS32 during concurrent writes, fails every
other read error or missing file, and requires the exact final Running row and
binding after all writes complete. TestBuild02 and the repaired selection pass.

## Final local evidence

| Gate | Result |
| --- | --- |
| TestBuild02 | **PASS** — 3m45; 193.86 GiB minimum free; 10.45 GiB peak |
| Selected02 | **PASS** — 404 passed, 0 failed, 1 ignored in 19.52s; catalogue 14,358 |
| AccountConfigContracts, all 13 targets in one invocation | **PASS** — 157/0/0; compile 4m58; 193.92 GiB minimum free; 10.49 GiB peak |
| Final strict Clippy05 | **PASS** — 4m33; 192.86 GiB minimum free; 10.80 GiB peak |
| Formatting, GUI lint and GUI self-test | **PASS**; GUI source unchanged in this batch |
| Generated CLI reference | **PASS** against the fresh TestBuild02 executable |
| Python integrity, roadmap release, release-gate and CI-cadence contracts | **PASS** — 19 + 11 + 8 + 6 |

The one ignored selected entry is the existing audit-RPC subprocess helper,
which the live-listener parent test invokes explicitly. It is not a silently
skipped new account behavior. The final unit executable is 279,425,024 bytes,
SHA-256 `33A44427494AFE3A1B4AC7232AF22D2F45A9BB2732A78EB79B5716FD1CD1F8D2`.
The failed Selected01 source, binary metadata and output remain retained as
separate failed-run artifacts. Earlier binaries and CI15 results are not
Wave17 runtime proof.

The exact 107-input and 14-executable receipts are
[`gold-wave17-source-manifest.json`](verification/gold-wave17-source-manifest.json)
and [`gold-wave17-test-matrix.json`](verification/gold-wave17-test-matrix.json).
They validate current source bytes, catalogue-selected case names, every
terminal result and each executable hash. The audit child report is accepted
only with its complete passing summary and the enclosing parent's terminal
success; failed, partial, mismatched and duplicate child proofs are rejected.
The final commit additionally requires exact working-tree/index agreement.

All local compiler/test gates ran serially with one Cargo job, debug info off,
Idle priority, CPU mask 61440 and the 32 GiB free-memory guard. This batch did
not link the GUI test monolith. Wave15 CI is terminal; a fresh full CI must run
after publication and cannot be replaced by these local receipts.

## Scope remaining

GOLD-LF-P1-16 stays OPEN. GUI/Buddy presentation and onboarding, pairing,
importer binding, migration surfaces and other transports remain separate
work. This batch makes no live Telegram or local GUI-link claim.
Roadmap counts remain 1,324 total / 1,010 complete / 312 open / 2 partial
(314 raw; 313 pre-tag blockers).
