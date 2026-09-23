# W337 retention restart recovery

## Hosted evidence

Group 684, run `35838862993` (`b609`), admitted 679 fixtures and left five
unrelated failures. Its only retention failure was
`reflection::periodic::retention_v2_tests::v2_post_archive_rename_before_transition_reconciles_source_identity`, which stopped at
`retention_v2_tests.rs:106` with `managed note inventory is invalid`.

The prior W318 restart cases passed in this run.

## Cause and repair

The fixture models the exact crash boundary after the archive was moved to its
journal-bound quarantine but before its journal transition. It restores the
receipt-owned note to its original Daily path so recovery must re-quarantine
that exact bound object. The V1 inventory ran before journal recovery, saw the
valid restored note without a live archive, and rejected it before the
identity-bound recovery could restore the paired state.

`enforce_daily_retention_with_execution` now runs its existing effect recovery
before invoking the complete V1 inventory. Recovery remains bound to the
durable journal, archive digest, object identities, no-follow directories, and
note receipt. Once it re-establishes the namespace, the unchanged full
inventory validates it before purge recovery or a new candidate.

No new fixture was required: the hosted failing test already creates this
precise archive-quarantined/note-restored state and asserts successful recovery
to the committed journal state. W318's foreign regular-file, Unix symlink, and
reserved-real-directory inventory fixtures remain unchanged.

## Evidence boundary

This is source-only pending a hosted rerun. Under the BSOD hold, no local
Cargo command, compiler, formatter, parser, test, runtime operation, or Git
mutation was performed.
