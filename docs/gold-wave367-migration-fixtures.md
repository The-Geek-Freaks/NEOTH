# W367 Group721 migration-fixture repair

Date: 2026-09-23. This repair is based on the source-bound Group721 log
`work/gold-20260906/wave357-publication/group721954/w190-research-lifecycle-log-954f838afd1ddef8a7781913218cbb189f7659bd/cargo-research-lifecycle.log`.
No local executable validation ran under the workstation BSOD hold.

## Observed failures

Three Group721 fixtures failed at the same W331 boundary:

- `memory::counterparty_consent::tests::v41_to_v42_migration_preserves_history_and_default_denies_without_backfill`
  at `counterparty_consent.rs:851`;
- `memory::migrations::tests::v42_to_v43_preserves_w208_state_without_backfilling_challenges_and_reopens`
  at `migrations/mod.rs:5237`;
- `memory::migrations::tests::v44_to_v45_rolls_back_tier_columns_when_dream_schema_cannot_be_created`
  at `migrations/mod.rs:5308`.

The first two called `store::open` after creating a supposed v41/v42 database
from a current fresh schema. They removed the v42-v44 objects, but left W331's
v45 Dream tables and `trust` columns in place while resetting `meta` to an old
version. Reopening correctly reached v44→v45 and attempted to add `trust`
again, producing `duplicate column name: trust`. These were invalid old-schema
fixtures, not a policy that permits silently ignoring duplicate tier columns.

The third fixture exposed a production migration defect. SQLite accepts
`CREATE TABLE IF NOT EXISTS dream_phase_run` when a view of that name already
exists, so the old migration could stamp v45 after an incompatible object hid
the intended Dream table. Its test therefore observed an unexpected success.

## Repair

- The v41 and v42 historical fixtures now remove all v45-only Dream tables and
  both v45 tier `trust` columns before the older schema version is stamped.
  The restart checks now model actual predecessors.
- `migration_v44_to_v45` now rejects every pre-existing Dream object. A real
  v44 predecessor has none; accepting a same-named table or view would hide a
  malformed/partially versioned database behind `CREATE TABLE IF NOT EXISTS`.
  The lookup uses SQLite `NOCASE` matching, the same identifier boundary used
  by schema creation, so mixed-case collisions are refused too. This precheck
  runs before either tier `ALTER TABLE`; a blocked Dream schema therefore
  leaves v44 with neither added `trust` column.
- The migration still treats an existing `trust` column as an error. A valid
  v44 predecessor has neither tier column; swallowing that error would hide a
  partially or incorrectly versioned database.

The repair is limited to
`SRC/neothd/src/memory/counterparty_consent.rs` and
`SRC/neothd/src/memory/migrations/mod.rs`. It does not change migration
registry order, schema version, Road/index/dispatch state, or Dream runtime
behavior.

## Required hosted readback

Re-run the three named Group721 identities on one frozen source head and bind
the result to the exact changed source hashes. The rollback fixture must report
an error and retain v44 with no tier `trust` columns; the two historical
reopen fixtures must reach the current schema while preserving their asserted
pre-v42/v43 state.
