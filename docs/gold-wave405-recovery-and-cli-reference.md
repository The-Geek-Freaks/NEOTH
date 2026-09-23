# W405 — recovered hosted state and outbound CLI reference

Core run 35866308409 on ed979ed5522a9da13aec929ded4eaa32f5540c3f
passed production slim Clippy, core test-target typecheck, public CLI build,
and source-bound reference export. The generated reference was checked against
the exported source head and SHA-256 before import:
`D9C6E38C851CCD2E1F4C451851DFFE3FB0F6011123CD5D5C6EF2C27850D6C82E`.
Its 44 added lines describe only the four outbound TaskDelegate commands.
Receipt: `work/gold-20260906/wave392400-publication/coreed979/ADMISSION.json`.

Full CI 35867787236 on 8f6ef116 was cancelled before acceptance because that
commit still contained the older CLI reference. GitHub now confirms cancelled.
Its replacement must include this import and the newly observed Group810 fixes.
GUI143 run 35867782202 is independent and continues on its frozen source.

Group810 run 35866133454 on bdb50ac2acc4583345b61eb620ae7d08ecac5307
executed all 810 selected tests: 807 passed and three failed. Admission checked
all 163 source-path hashes, matrix and lock inputs, ordered test selection,
and each actual passing or failing terminal. The failures are retained:

- `cli::parity_drift::operation_inventory_tracks_live_nested_cli_leaves`
- `cli::memory::tests::physical_redaction_refuses_journal_target_that_is_not_the_bound_leaf`
- `wal::redact::tests::staged_authenticated_leaf_refuses_matched_structural_frame_byte_identically`

Receipt: `work/gold-20260906/wave405-recovery/group810bdb/ADMISSION.json`.
W406 and W407 address these concrete failures. Passing functional subsets can
be accepted independently after their relevant source and requirement checks,
as specified in the build cadence evidence ladder. This recovery entry itself
closes no parent Road item and does not claim a green aggregate or release.

The workstation still reports boot time 2026-09-22 22:33:06. No active Cargo,
Rust compiler, or NEOTH process was observed during recovery; the BSOD cause
remains unproven. No local compiler, formatter, parser, test, product runtime,
browser, audio process, or model archive download was started.
