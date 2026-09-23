# W318 retention inventory repair

## Hosted failure set

Hosted group 643, run `35833333444` (`750d`) reported these nine failures with
`DailyRetentionError { reason: "managed note inventory is invalid" }` at
`retention_v2_tests.rs:106`:

1. `v2_prepared_before_rename_is_abandoned_then_next_batch_is_safe`
2. `v2_post_archive_rename_before_transition_reconciles_source_identity`
3. `v2_post_note_rename_before_transition_reconciles_deterministic_destination`
4. `v2_receipt_before_committed_ordering_is_idempotent_after_restart`
5. `v2_purge_prepared_before_unlink_restarts_from_both_quarantined_leaves`
6. `v2_unlink_attempted_after_partial_unlink_is_reconciled_truthfully`
7. `v2_completed_purge_is_idempotent_after_the_effect_receipt_is_timestamped`
8. `v2_purged_completed_journal_finalizes_a_missing_effect_receipt_timestamp`
9. `v2_completed_purge_rejects_a_foreign_receipt_binding_without_changing_evidence`

## Root cause and repair

A successful receipt-owned note quarantine creates the product-reserved direct
child `NEOTH/Daily/.neoth-retention-v2`. The next inventory pass classified
that directory as an unknown note leaf before retention recovery could inspect
the V2 journal and receipts.

`periodic.rs` now excludes that name only after `open_existing_read_only_child`
has opened it as a direct no-follow real directory. A vanished child, regular
file, symlink, junction/reparse object, or metadata failure remains a managed
note inventory error. The behavior mirrors archive-side handling of the
product-reserved `.retention-v2` child without creating a namespace during
inventory.

The regression matrix adds three targeted fixture cases:

- a real reserved directory is accepted by inventory;
- a foreign regular file at the reserved path is rejected;
- on Unix, a symlink at the reserved path is rejected.

The V2 quarantine open/create/revalidation, journal, receipt, and identity
guards are unchanged, subject to coordinating review.

## Evidence boundary

This is a source-only repair pending hosted rerun. Under the BSOD hold, no
local Cargo command, compiler, formatter, parser, test, runtime operation, or
Git mutation was performed.
