# GOLD Wave 3 verification

**Status date:** 2026-09-07
**Scope:** bounded local implementation checkpoint for the Wave 3 change set. This report
does not change a roadmap checkbox; the exact roadmap dispositions remain in
`PLAN/ROAD_TO_1_0_GOLD.md`.

## Final provenance

The canonical proof artifacts are:

- [final source manifest](verification/gold-wave3-source-manifest.json) — the
  complete **82-input** hash inventory and post-gate hash readback;
- [final selected test matrix](verification/gold-wave3-test-matrix.json) — all
  binary identity plus selected runtime filters and compiler, package, GUI, and controller gates;
- [HLC replay design](wal-hlc-replay-design.md) — EventHeaderV2 compatibility,
  canonical replay order, and the authenticated post-commit receive merge.

The final test binary has SHA-256
`360FD5F14C431306B6C344944AE8BC16DC25EE72E2F59221AF8FD193CD2DABB9` and
contains **14,091 tests**. Test compilation passed in **1m32s**
(`TEST_EXIT=0`). All **82** manifest inputs read back equal after the final
gates. The inventory completion added the already-unchanged
`SRC/neothd/Cargo.toml` to the proof record; it was unchanged since 20:48:40
local, before every final gate. No compiled source changed during that
inventory completion.

## Final checks

| Check | Result |
|---|---|
| Selected runtime matrix | **31/31 groups**, **2,174 passing test executions**. |
| Ignored case | One existing D008 `wal_sync_latency_measurement` benchmark was ignored; it is an opt-in latency benchmark, not a failed test. |
| Strict core Clippy | `--lib --tests --no-deps -- -D warnings` passed in **2m33s** (`CLIPPY_EXIT=0`). |
| Core package check | Passed in **1m46s** (`BUILD_EXIT=0`). |
| Default-feature GUI check | `check --tests` passed in **4m57s** (`GUI_GATE_EXIT=0`). It emitted 13 existing probe-supervisor dead-code warnings; the Wave 3 GUI change there was only an import. |
| Production GUI controllers | Code-map controller **6/0** and Coding controller **6/0**, completed in **4m31s**. |
| Public CLI build | `_build.bat --locked --offline -j1` passed in **5m15s** (`BUILD_EXIT=0`). |
| Public CLI startup | `--version`, `code --help`, `code-map diff-impact --help`, `context --help`, `permissions --help`, and `wal --help` each exited **0**. This checks startup and command registration, not their effectful workflows. |

The public default-feature debug executable is **181,485,056 bytes**, SHA-256
`EC2FC675141B8E107C0986A12C31CE201EB68DB9C45A22772A6E27E4156E5DC8`.
After these startup probes, all **82** source hashes and the library test
binary hash still matched the recorded values.

## Verified implementation slices

| Area | Final local evidence | Remaining boundary |
|---|---|---|
| CRG-01 incremental lifecycle | The selected-root first-index/refresh lifecycle is bounded, cancellable, watcher-invalidated, restart-aware, receipt-bound, and retains unchanged file/symbol data and valid edges behind a final source fence. The final `code_map::` filter passed **347/0**. | Other CRG-01 rows remain open: cross-surface truth, GUI/Buddy parity, clean-install/package, and consumer adoption. |
| CRG-03 diff parser and extents | Native Git acquisition is authority-bound and capped; it parses zero-context diffs, normalizes paths, handles add/modify/delete/rename/quoted/binary cases, and maps conservative seeds. Schema v8 persists nullable parser-certified `line_end` extents and exact intersection falls back when no extent is certified. | The broader CRG-03 consumer, configuration, Doctor, GUI/Buddy, package, and release rows remain open. |
| Coding service and controllers | CodingService lifecycle/reload/refusal, owned joins, result/receipt behavior, and shared production controller paths have final focused evidence: `coding::` **562/0**, `cli::code::` **29/0**, plus the two **6/0** controller harnesses. | These checks are not an interactive desktop, Buddy, provider, package, or release journey. |
| Windows Context, IPC, Skills, History | Final matrix passes include ContextStore **16/0**, Context CLI **1/0**, native delete **1/0**, private IPC **2/0**, audit transport **7/0**, History **25/0**, Skill installer **84/0**, and Skill store **49/0**. | This does not close the full Context/connector cards: cipher/key lifecycle, retention/erasure, account sync, supervisor, shared surfaces, and platform qualification remain separate. |
| Typed Trust and HLC | Permissions **194/0**, MCP gate **29/0**, OS gate **27/0**, WAL scan **36/0**, HLC **14/0**, WAL CLI **27/0**, foreign persist **1/0**, WAL sync **28/0**, and WAL writer **86/0** passed. The documented HLC path orders EventHeaderV2 headers canonically and merges a received clock only after authenticated durable commit or bound duplicate. | P1-05 remains open: its all-decision-boundary inventory contains further direct decision sites. HLC proof is local source/test evidence, not remote or live-peer acceptance. |
| Updater receipts and budgets | Updater **321/0** and updater-cron **19/0** cover the ordered leaf receipt, outer run identity, and inherited-budget binding slice. | R3-18 remains open. `SelfProbe` and `SelfStage` stay denied, and bounded owned terminal ACK drain still needs its named proof. |

## Evidence limits

The 31/31 matrix is a selected focused suite, not execution of the entire
14,091-test binary without filters. Under
`PLAN/BUILD_AND_RELEASE_CADENCE.md`, this evidence supports a bounded
implementation commit. It does not complete the source-frozen package/GUI
wave: complete affected-crate/feature tests and the linked GUI test binary
remain required at that gate. The host-specific recovery rule in
`PLAN/ROAD_TO_1_0_GOLD.md` requires avoiding the GUI test monolith link on this
Windows workstation; its full test execution belongs to CI. Nothing here proves an interactive GUI
journey, packaged artifact, release, remote peer, real provider, clean-machine,
or external CI acceptance. No broader parent card is implied by the four
literal leaf closures in the roadmap.
