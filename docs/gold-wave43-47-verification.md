# Gold Waves 43–47 codegraph and tool-boundary verification

**Status:** locally verified; 46 publication paths include the reviewed source,
integration/dependency repairs, documentation and retained evidence.
NativeTestBuild04 passed in 4m07; TestBuild05 confirmed the final 247-input
snapshot after the CI cadence fixture update. Selected runtime04 passed
1,913 / 0 / 0 in 104.17 seconds. Strict Clippy05, CLI docgen, four contracts
(15 tests), Python integrity/cadence (45 tests), CI matrix assertions, audit,
deny and notices passed. The first two CRG-04 kernel leaves are verified;
their parent and remaining consumers stay open. The generated CLI reference
joins the final 248-input manifest.

## Published W41/W44 boundary

W41/W44 are published directly on main at
`2bf6c0fe298cdd1e1146a7c8279ab68fd92c25bb`, with 56 verified paths. The
published evidence contains 230 source inputs, native unit selection
**2,108 / 0 / 12**, contracts **29 / 0**, Python **38**, and passing GUIClippy02
and WasmCheck02. It does not establish native GUI interaction, live-provider
delivery, cross-platform CI, release acceptance, or roadmap-parent closure.

Wave 42 remains published at `cb717ee54e40f9e27583a8534b8bc25130e773e4`.
Its typed v5 proactive-health reader separates exact channel references even for
equal-text Telegram/default and Slack/default accounts, without changing
outbound behavior. P1-14 and P1-16 remain open; P1-17 remains partial.

## Current CI boundary

Full CI [34881450745](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/34881450745)
completed with Linux quality and Windows/macOS compilation failures. The macOS
compile step hit its 100-minute deadline, with no compiler/OOM error or test
result; its last named starts were Slint and the GUI. Security [34881453920](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/34881453920)
completed with the two Rustls failures; both CodeQL languages and the
unresolved-high/critical gate passed. [Preflight 34881430046](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/34881430046)
and [Quality 34881430782](https://github.com/The-Geek-Freaks/NEOTH/actions/runs/34881430782)
succeeded. Security's cargo-audit and cargo-deny jobs failed on new
RUSTSEC-2026-0285. The worktree now uses rustls 0.23.45, rustls-webpki 0.103.15,
aws-lc-rs 1.18.1 and aws-lc-sys 0.45.0. Fresh local audit, deny and notices
passed; audit's advisory DB commit is the same as the failing CI and reports
zero vulnerabilities. The local compilation gates passed; new-head CI remains
required for the affected platform and dependency boundaries.
[Upstream advisory](https://github.com/rustls/rustls/security/advisories/GHSA-2mjx-qc3c-rqvc).

Linux quality failed on a Unix helper whose only caller requires `recursive-mas`;
the helper now has the same feature gate. Windows failed during compilation with
`rustc-LLVM ERROR: out of memory`, before any test result. The workflow now uses
one Windows compiler job and retains four on macOS. Local YAML/matrix checks
passed; new-head CI must verify the runner outcome. The macOS job retains its
existing build parallelism and deadline; the old timeout is not a passing test
receipt.

## W43–47 composition boundary

The batch adds these production paths:

- W43 resolves explicit working-tree, staged, committed base/target, or stdin
  diffs against the selected canonical repository. The bounded original bytes
  supply the diff digest; root identity and index/graph generations fence the
  result. Coding receives the same structural citation in its provider prompt
  and both durable pre-provider attempt receipts. Raw diff text is not retained
  in those receipts.
- W45 identifies supported Rust/Python framework tests and emits deterministic,
  root-scoped `TestedBy` edges only for unique production targets. Schema v10
  persists target-file identity; migration preserves legacy null identities and
  rejects unknown edge kinds rather than interpreting them as calls.
- W47 queries direct/transitive test evidence for the full CRG-02 impacted-node
  identity. Root/generation/stale/cap rejection is typed, and one global work
  budget bounds traversal, database work and output. Legacy or inferred evidence
  remains uncertain; no observed test does not mean that no test exists.
- W46 introduces a real typed `PreToolUse` boundary for MCP, provider-emitted
  tools and direct CLI MCP calls. Hooks may allow, add bounded context or block;
  they do not rewrite tool arguments. The invocation permit retains argument
  and authorization identity, including SmartApprove's pre-catalog hook path.

| Slice | Admitted review state |
| --- | --- |
| W43/W45 composed01 | **APPROVE**, 19 paths |
| W47 repair06 | **APPROVE**, three target overlays |
| W46 repair06 | **APPROVE**, 13 paths |
| Composition | 31 paths, independently approved and admitted; native unit/Clippy/docgen/contracts passed |

W46 covers the MCP, provider, and direct-CLI boundary. It does not claim every
native surface or establish release acceptance.

## Retained final evidence

The [source manifest](verification/gold-wave43-47-source-manifest.json) binds
248 inputs. The [test matrix](verification/gold-wave43-47-test-matrix.json)
retains the exact 1,913-name selection from the 14,629-test catalog, five
executable hashes, source snapshots, gate summaries and log hashes. The native
unit executable is SHA-256
`69C7E67118BC5FF7DC86755626BFF3B2705883F28E61CFC8F76A696AA58976CC`.

All native gates ran serially with one Cargo job, Idle priority and CPU mask
61440. TestBuild04 took 4m07 (206.74 GiB minimum free; 10.88 GiB peak build
working set), followed by cached TestBuild05 after the Python CI-fixture edit.
Strict Clippy05 took 5m33 (207.48 GiB minimum; 10.03 GiB peak). The four contracts
compiled in 6m16 (208.33 GiB minimum; 8.80 GiB peak) and passed 4+3+3+5 tests.
No memory guard stopped a final gate.

## CRG boundaries

The first two CRG-04 leaves are verified by root-owned native tests and strict
Clippy: stable test identity, deterministic root-scoped `TestedBy` persistence,
migration behavior, and bounded direct/transitive impact-bound test discovery.
The CRG-04 parent and its consumer/config/lifecycle/GUI/Doctor/release leaves
remain open, as do CRG-03's third leaf and the remaining CRG-05 work.

Counts are **1,324 total / 1,014 done / 308 open / 2 partial**: 310 raw blockers,
309 before the release tag. Older failures and initial fixture repairs are
retained locally; only the final passing runs establish this boundary.
