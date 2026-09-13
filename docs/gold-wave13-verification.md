# Gold Wave 13 — session-start recall preload

**Receipt status:** local component accepted; documentation checks pass.
P1-11 supplies bounded, local session-start recall for
the first provider prompt; it does not change P1-08 or certify cross-platform
CI.

## Implemented contract

`memory/session_start_recall.rs` starts after this turn's authenticated RAW
delivery and before prompt assembly. It opens only an existing bound home and
existing `views.db`, using read-only/no-follow SQLite plus `query_only`; it
creates no home, database, WAL frame, or mining authority. The generic reader
checks namespace/file identity and rechecks `data_version` before and after
the query, including an empty result. A prompt/session/subject fingerprint
binds a preload to one consumption attempt, and stale or failed preparation
cannot trigger a second unbounded read.

The preload uses the normal fresh recall policy and is recall-only. The first
provider request consumes the prepared canonical envelope when it is valid;
normal chat journaling and audit behavior remain in place. Incognito constructs
neither the preloader nor a preload status notice. Normal chat emits only a
loading/ready/no-data/stale/failed status notice; stale or unavailable local
recall continues without the prepared block.

The pre-copy prompt limit is 4 KiB, each SQLite value is capped at 64 KiB, and
the final canonical recall envelope is capped at 8 KiB. Query and revalidation
have a monotonic 250 ms deadline with a 25 ms interrupt grace. A global
capacity of two remains occupied until the actual blocking worker exits, even
if an OS open outlives the caller. These are preload-operation limits, not a
whole-prompt-assembly latency guarantee.

## Source and selected-runtime evidence

The implementation is in `SRC/neothd/src/memory/session_start_recall.rs`,
`cli/chat.rs`, `memory/mod.rs`, and `SRC/neothd/Cargo.toml`. Independent final
source and focused-test review is **APPROVE**. TestBuild04 passed in 7m34s with
one job, Idle priority and four logical CPUs; free physical memory reached at
least 208.33 GiB and peak use was 12.11 GiB. The selected binary is
`neothd-dcf7f8d5ad97854d.exe`; its catalogue contains 14,265 tests.

Selected03 passed **265 / 0 / 0** in 8.67s. It covers the existing-only
reader, read-only/no-follow/query-only boundary, first-provider consumption,
Incognito exclusion, notice states, monotonic deadline/progress handling, and
the capacity/worker-lifetime guard. The source manifest and exact selected
matrix are recorded in `verification/gold-wave13-source-manifest.json` and
`verification/gold-wave13-test-matrix.json`: fourteen exact source inputs,
the selected test names and all five integration executables. Selected binary
SHA-256: `9EA0E43DC5866CAC43CB5FB9FB0D2FFE3C125B15868C54353342CC8218F60E18`.

## Final local gates

| Gate | Exact result |
| --- | --- |
| Clippy04 | `PASS 2m43s; min 214.65 GiB free / peak 6.18 GiB` |
| Core check | `PASS 2m12s; min 214.33 GiB free / peak 6.46 GiB` |
| Workspace formatting check | `PASS; workspace formatting plus GUI lint/self-test` |
| 30 Python checks | `PASS: lost-feature integrity 19; roadmap release gate 11` |

Full CI `34758135622` on base commit `990080844a3cdd8d23ec312a37a48d3c61aeb7c9`
failed with eight Windows test failures, Linux dead-code errors, and a GUI
Read-trait import error shared by macOS and Ubuntu. This batch repairs those
compile paths and all five affected test targets: **30/0/0**, fresh Cargo
SourceContracts02 in 9.31s, at least 218.10 GiB free RAM / 1.00 GiB peak.
The final test changes assert actual Windows VFS binding/handle operations,
both factual preflight modes before scheduling, and current Stage-3b SQL
attestor denial. Independent delta review is APPROVE. Published exact-SHA
cross-platform CI remains a separate gate; no green CI claim is made.
