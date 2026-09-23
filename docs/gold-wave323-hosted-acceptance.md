# Wave 323: hosted result admission and parent coverage

## Frozen results

GitHub run `35833333444` at `750d162b075d01c9155f00291d207180dacc3341`
executed all 643 selected native tests: 624 passed and 19 failed. Admission
verified all 138 fixture-source hashes against Git blobs, matrix/lock inputs,
the exact ordered selection, and each named one-test terminal in the raw
`cargo-research-lifecycle.log`. The run remains failed; its passing individual
results are usable only for their tested source and covered criteria.

GUI run `35831827281` at `d6da730098d792a758e1b01fb9ea7049aaad8564`
executed 129 selected tests: 125 passed and four failed. Its 23 source/input
bindings and ordered terminal receipts were checked. W153, W164, manager-stop
and parent-death containment remain failed pending the W319 hosted rerun.

Core run `35835186407` at `5bf88622ff8005c08722e0c1a2bca948635e543c`
passed slim production Clippy, test-target type checking, CLI build and reference
export. The exported CLI reference matches committed SHA-256
`F7E3604A1789839F87DD6A574E3D4987A98E4F4E599CB71179DC32C7ED2D6CFA`.
Preflight `35835139699` requested formatting only; its patch SHA-256
`B505744E589F229B7D69D7DC07D8D55303E44BDCAEDBE1CBCBF984647D303E51`
was imported after verifying every affected Git preimage and postimage.

## P2-22 acceptance

All 22 required ceremony, origin, revocation, embedding and clustering tests
passed at `750d162b`. The ten relevant implementation/test source files are
unchanged in the publication worktree. The structured record is
`docs/verification/gold-wave323-p222-acceptance.json`.

This completes `GOLD-LF-P2-22`: unknown or revoked channel episodes remain
ineligible, exact counterparty scopes cannot cluster together, grant requires
durable authenticated audit evidence, and revocation plus interrupted audit
recovery preserve denial. The 19 unrelated failures do not change those 22
actual passing results. This is neither an overall green native suite nor a
release acceptance claim.

## Remaining parent coverage

P2-08 has all 51 historical passing terminals at `750d162b`; later direct-retry
changes affect chat/provider files, so it remains open for the selected full
family on the new source.

P2-11 remains open. The four W299 witness tests passed, but 25 mapped
ImportGraph, TypeHierarchy, CallGraph, persistence/freshness, MCP, CLI and daemon
completion/recovery tests were absent from the grouped selection. W323 adds
those exact existing fixtures to the next hosted group and registers the 12
previously uncatalogued identities. The matrix stores the complete 29-test
parent set and the 25 newly selected names.

W318 adds two universal and one Unix retention-inventory regression. Together
with the W323 selection, the next group contains 684 tests. Native inventory
is 1022 universal plus Windows19/Linux32/macOS31; GUI remains Linux129/macOS125.
No local compiler, formatter, parser, fixture or runtime verification ran.
