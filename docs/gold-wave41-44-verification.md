# Gold Wave 41–44 verification receipt

**Status:** W41 and W44 are locally verified on 2026-09-14. The source manifest
and test matrix below bind the admitted source and retained executables to the
completed local checks. Full cross-platform CI and release acceptance remain
separate gates; no parent roadmap item closes from this batch.

## W41 product boundary

Main and Buddy consume one daemon-owned chat stream. The GUI presents bounded
state but cannot create a capability, consent proof, route, endpoint, or
transport identity. The daemon owns admission, provider and configuration
selection, turn and WAL custody, and conversion of a request-bound decision into
an effect.

Preflight exposes Ready or a bounded safe-route confirmation. Main and Buddy
keep Deny, AllowOnce, and AllowAlways; sensitive prompt material stays out of
the UI prompt. Deny clears staged state before provider effect. Stream handoff
generations bind Stop and reopen so a detached Buddy error cannot settle a newer
Main turn. Attachments stay typed, untrusted and bounded; captions stay separate,
and required material that exceeds the effective provider budget fails visibly.

## Current local proof

| Gate | Result |
| --- | --- |
| NativeTestBuild02 | **PASS** — 3m51s; 210.30 GiB minimum free; 10.62 GiB peak |
| Selected native run | **2,108 pass / 0 fail / 12 ignored** in 73.85s; catalog 14,586, selected 2,120 |
| Native binary | 289,073,152 bytes; SHA-256 `BEBDDED1D810A55277165AFF8BE43CC6C38D56C022CDA2A37D6CDB36C18F61DC` |
| NativeClippy01 | **PASS** — 7m08s; 208.44 GiB minimum free; 10.05 GiB peak |
| Final contracts | six targets: **29 pass / 0 fail**; 5m39s; 209.66 GiB minimum free; 8.62 GiB peak |
| Final GUIClippy02 | **PASS** — 4m47s; 212.12 GiB minimum free; 6.41 GiB peak; no GUI link |
| Final WasmCheck02 | **PASS** — 1m52s; 210.44 GiB minimum free; 7.85 GiB peak |
| Python integrity/release checks | **38 pass / 0 fail** across the existing 19, 11 and 8 test suites |
| Dependency and notice checks | cargo-audit, cargo-deny and generated Rust notices **PASS** |

## Source and executable proof

The [source manifest](verification/gold-wave41-44-source-manifest.json) records
230 inputs. The [test matrix](verification/gold-wave41-44-test-matrix.json)
records the exact selected test names, seven executable hashes, and retained
gate artifacts. The core snapshot matches 227 inputs. Exactly
`gui_chat_bridge_controller.rs`, `chat_stream_phase.rs` and
`chat_child_supervisor.rs` are outside that core executable and checked by the
final GUI snapshot covering all 230 inputs. Other GUI text embedded by CLI
parity tests remains included and unchanged.

Five GUI lint diagnostics were repaired before GUIClippy02. Its 13 remaining
Windows GUI dead-code warnings belong to the existing probe supervisor; the
existing vendor `admission_permit` warning is also disclosed. This is no claim
of globally warning-free Windows GUI compilation. No local GUI executable was
linked. The 12 ignored unit outcomes are one explicit subprocess helper
exercised by its parent and 11 tests requiring local Qwen/Ouro model weights.
The recorded serial test parser accounts for direct stdout and the nested
helper harness without counting the helper as an extra top-level pass.

## W44 dependency boundary

Cargo.lock, license snapshots, and THIRD_PARTY_LICENSES are updated. Audit,
deny, notice generation/check, independent review, and final-source WasmCheck02
passed. Wasmtime is 36.0.14 with its required Cranelift/Pulley closure; der is
0.8.2 and wnaf is 0.14.1. No advisory/yanked-package exception was added. Local
cargo-audit 0.22.1 evidence is distinct from CI's pinned 0.22.2 tool version.

W43/W45 composed01 remains approved work-only across 19 paths. W47's real SQLite
tests exposed a bounded-loader target-file gap being repaired. W46's real MCP
stdio tests and hook policy are under review after call-site type repairs.
These candidates are not part of this source manifest or runtime proof.

## Release boundary

The older e4b4 CI `34857514849` failed on all three operating systems: Linux
16,174 pass / 5 fail, Windows 16,111 pass / 1 fail, and macOS 16,164 pass / 5
fail, from the same updater causes. The current updater selection passed locally.
This is not a native cross-OS, full-CI, release, native-GUI, or live-provider
claim.

Counts remain **1,324 total / 1,012 done / 310 open / 2 partial**. P1-14 and
P1-16 remain open; P1-17 remains partial. No checkbox or parent closes here.
