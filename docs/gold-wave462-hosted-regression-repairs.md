# W448/W459/W460 hosted regression repairs

Core run `35886288492` at `5bace4f0` passed slim production Clippy, then
failed the default-feature test-target check with 16 library diagnostics and
19 test-build diagnostics. The complete retained log is
`work/gold-20260906/wave459-core5bace/run35886288492.log`.

## Raft integration compatibility

The repairs match the pinned OpenRaft 0.9.25 API: its own async-trait macro
for network implementations, `error::RaftError`, `AnyError::new`, the bounded
snapshot's consuming accessor and the snapshot-builder trait import. The
membership validator uses the existing authenticated-peer accessors; the
transport compares the epoch's value. Budget frames reaching the synchronous
handler fail closed because the authenticated asynchronous session owns them.
Invalid documentation comments on function parameters become ordinary comments.

Cluster configuration and runtime fixtures initialize the new budget field.
The generic CLI configuration command preserves the existing budget policy,
checks for concurrent policy drift inside the actual configuration transaction,
and includes it in the complete receipt and runtime snapshot. The GUI retains
strict typed receipt decoding for that additional field. Regression coverage
checks preservation, concurrent policy changes and the corresponding GUI wire
contract. This does not add a second budget configuration authority.

## Windows private publication

The four Windows WAL/redaction failures in FullCI `35871801240` identify the
legacy native rename operation returning access denied. The bound read/write
target already shares DELETE; closing that handle was not a justified repair.

Only private stages now use `FileRenameInformationEx` with POSIX replacement
semantics. The source handle remains open and the destination stays relative
to the retained parent-directory handle. Non-private replacement stages keep
the existing legacy path. The two Windows regressions cover an open,
DELETE-sharing destination and an ambient-parent swap immediately before
publication. They verify that the retained directory receives the new object
while the replacement ambient path remains untouched.

## Real post-provider producer regression

W458 executes the actual prepared three-chunk chat producer, filesystem-loaded
post-provider hooks, WAL drain and presentation sink. Block must fail for the
specific hook and release no provider delta or completion; Replace must release
one accepted body whose count, content hash and finalization receipt agree.
This is a producer-to-sink regression. It does not establish integrated
producer-to-Main/Buddy delivery, so P2-26a remains open. An unrelated synthetic
GUI reducer test was removed; the existing framing helper tests remain explicitly
classified as lower-layer contracts.

## Focused hosted execution

`windows-storage-regressions.yml` builds only the native library and selects
exactly 16 regressions: eight managed-browser cases, two Windows path-prefix
cases, four WAL/redaction publication cases and the two private-stage cases.
Each selected name must exist exactly once before execution. The artifact
records source identity, source/input hashes, ordered individual logs and
captured success/failure counts. It uses Rust 1.91, one compiler job, serial
tests and the existing low-debug-info cache profile.

All repairs have static review and text-diff validation only until the new
hosted runs return. This document does not close P2-19 or claim Windows runtime,
complete workspace or release success. The absolute local BSOD hold remains.

## W467 hosted follow-up

Core run `35889966328` at `a96eeba5ad380cd60ee2d6f3a98fd42e3fccf054`
passed slim production Clippy, then reported two OpenRaft attribute panics,
an `anyhow::Error: StdError` conversion failure and three cascading missing
factory trait diagnostics. The earlier static review did not establish API
compatibility. The impls now express the network futures directly, without
applying OpenRaft's trait-definition macro to impl blocks. The store conversion
uses the supported dynamic-error conversion in pinned AnyError0.1.13; it retains
the source chain without adding an anyhow feature.

These are repairs to actual compiler output; fresh hosted compilation and
behavioral execution remain required. Pending live-assignment, runtime-stream
and wizard regressions are separate uncommitted batches at this checkpoint.
