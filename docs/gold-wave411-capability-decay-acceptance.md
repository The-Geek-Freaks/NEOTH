# Gold Wave 411 — P2-06 capability-decay acceptance

## Decision

`GOLD-LF-P2-06` is **accepted** at current HEAD `010d535c`. The Road contract
is met by source-bound evidence for all 18 exact terminals: Group841 provides
the 17 former W411 gaps, and Group810 provides the remaining Doctor contract
overlap. No source batch, GUI/Slint change, platform matrix, or release gate is
needed for this native parent.

## Source-bound evidence

- Group841 admission `35871794576` ran on `bc9db76c`, required/executed
  `841/841`, passed `834`, and has matching source hashes, matrix, lock and
  exact fixture identities. Its seven failures are all Cluster membership /
  outbound / Audit-RPC fixtures, not P2-06.
- Group841 includes and therefore passed every W411 selected terminal: six
  authenticated-terminal/scanner tests, two read-only Doctor tests, seven
  snapshot-history tests, the capabilities CLI parser contract, and Doctor’s
  `run_all_checks` contract.
- Group810 admission `35866133454` supplies the remaining
  `cli::doctor::tests::check_docs_listed_count_matches_runtime_contract` pass.
- The direct P2-06 files plus the actual terminal producer
  `SRC/neothd/src/providers/cost_authorization.rs` and authenticated writer
  `SRC/neothd/src/wal/writer.rs` have no Git diff from Group841 head to current
  Head `010d535c`; the working tree is clean for this dependency set. The
  uncommitted W422 `cli/serve.rs` work is outside this path.

This is dependency-specific carry-forward, rather than an all-HEAD acceptance
claim.

## Contract covered

The accepted terminals prove complete authenticated provider-terminal WAL
input, bounded scanner refusal of incomplete tails, provider/wire-model/closed-
workflow isolation, independent 8/12 sample floors, advisory
stable/degrading/recovering classification, non-mutating Doctor behavior,
explicit bounded private snapshots, corrupt/missing/locked-history refusal, and
operator CLI wiring. Quality observations do not measure answer correctness or
silently alter routing, availability, retry, or disable decisions.

Every terminal, direct source hash and producer/writer dependency hash is in
`docs/verification/gold-wave411-p206-acceptance.json`.

No local compiler, formatter, parser, test, runtime, GUI, or network action was
run for W425.
