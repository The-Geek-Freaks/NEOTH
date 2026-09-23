# W344 — Dream v45 migration and ordinary-trust fixtures

This change adds static regression fixtures only. No local compiler, formatter, parser, SQLite runtime, test, GUI, or application runtime was run.

## Covered contracts

Schema v45 adds `trust` to the warm (`idx_consolidated`) and cold (`idx_longterm`) tiers and creates the Dream phase journal. The new fixtures make the upgrade and fresh-schema contracts explicit:

- `memory::migrations::tests::v44_to_v45_preserves_existing_tier_rows_defaults_trust_and_creates_dream_schema` starts with real v44-shaped tier rows, migrates to v45, verifies that both retained rows remain and default to `trust=1`, confirms all four Dream tables, and checks `meta.schema_version=45`.
- `memory::migrations::tests::v44_to_v45_rolls_back_tier_columns_when_dream_schema_cannot_be_created` poisons the Dream run-table name with a view. The migration must fail atomically: neither tier gains `trust` and `meta.schema_version` remains 44.
- `memory::store::tests::fresh_v45_schema_has_tier_trust_defaults_and_dream_phase_tables` verifies fresh-schema parity: both tier schemas expose `trust`, fresh warm and cold rows default to 1, and all four Dream tables exist.
- `memory::store::tests::legacy_history_migration_never_reopens_a_swapped_views_path` now constructs an actual v42 predecessor when the current store is v45: it removes the v45 Dream tables and tier-trust columns before the existing v44 embedding and v43 consent rollback. This prevents duplicate-column/table migration failure from masking the no-follow rebind assertion.
- `memory::consolidate::tests::ordinary_untrusted_trust_survives_hot_warm_cold_consolidation` uses an ordinary `trust=0` hot row, then verifies the exact value after the hot-to-warm and warm-to-cold transitions.

## Source boundary

Only these implementation/test files changed:

- `SRC/neothd/src/memory/migrations/mod.rs`
- `SRC/neothd/src/memory/store.rs`
- `SRC/neothd/src/memory/consolidate.rs`

No production logic changed. The existing `migration_v44_to_v45` already adds the two tier columns transactionally through the migration dispatcher and installs the canonical Dream schema SQL; the new tests bind preservation, defaulting, parity, and rollback behavior.

## Cold-reader integration

The existing `cli::recall::tests::recall_cold_like_surfaces_cold_tier_rows_with_correct_tier_label`
now inserts a Cold row with trust 0 and asserts the real `RecallHit.trust` is 0.
This companion change in `cli/recall.rs` verifies the reader in addition to the
ordinary-consolidation writer. Nine Dream fixtures include separate revoke-only
and revoke/regrant cases. Hosted compilation and exact execution remain required.
