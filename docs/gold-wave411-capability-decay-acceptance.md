# Gold Wave 411 — P2-06 capability-decay acceptance

## Decision

`GOLD-LF-P2-06` is **selection pending**, not accepted yet. The product source
already contains the expected bounded capability-quality, snapshot-history, and
operator-diagnostic behavior. Its remaining condition is focused hosted evidence
for 17 exact P2-06 terminals on a source that includes the changed terminal
producer and WAL writer dependencies.

## Evidence boundary

W188/W189 hosted run `35712523037` passed all 18 P2-06 terminals on
`2cef8239`. Group810 run `35866133454` at `bdb50ac2` is a source-admitted
810-test result with three unrelated retained failures, and it passes one
current P2-06 terminal:

`cli::doctor::tests::check_docs_listed_count_matches_runtime_contract`.

The P2-06 scanner, history and operator files are Git-identical from Group810
to current HEAD `8f6ef116`. That only carries the Doctor runtime-document test.
It does not carry the other old terminals: since `2cef8239`, the actual
provider-terminal producer `SRC/neothd/src/providers/cost_authorization.rs` and
its WAL writer dependency `SRC/neothd/src/wal/writer.rs` changed materially.
The old producer/scanner/history terminal receipts cannot prove their behavior
through that dependency drift without another focused execution.

## Required grouped selection

`work/gold-20260906/W411-additional-grouped.json` lists the 17 missing,
non-overlapping `[test, sourcePath]` entries. Add exactly those entries to the
already planned grouped run; do not schedule a separate compile or invent a
full-head, all-OS, GUI, or release gate. The existing Group810 Doctor contract
terminal remains credited.

The grouped receipt must bind the selected fixtures to its tested source and
record individual PASS terminals. A passing 17/17 result plus the already
admitted Doctor contract terminal closes this parent.

No local compiler, formatter, parser, test, runtime, GUI, or network action was
run for W411.
