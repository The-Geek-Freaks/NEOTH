# W270 — Hippocampus importance cron validation

GOLD-LF-P2-02 is implemented and independently source-reviewed; focused hosted
validation is pending. This selection does not close the Road item.

## Production path

WAL header importance is indexed into durable `idx_episode.importance`.
The daemon starts the two-hour decay task, which reads the accepted reload
snapshot at each tick. Explicit opt-in plus permitted autonomy enables selection;
Custom forbids membership mutation while ordinary decay remains available.
The consolidation transaction reconciles durable Hippocampus membership using
an inclusive `importance >= 0.75` threshold and atomic retention/rollback rules.
The v40-to-v41 migration adds membership without rewriting existing importance.
`neoth memory --hippocampus` supplies bounded read-only inspection.

## Focused hosted contract

Eleven existing identities cover default-off config, inclusive/idempotent
selection, removal of decayed or missing entries, read-only query ordering,
accepted policy versus rejected reload, Custom refusal, the real WAL-indexed
importance through accepted task tick to CLI view, retention rollback, valid
migration, incompatible-schema rollback, and CLI argument parsing.
The exact names and ten caller/consumer source paths are recorded in
`wave270HippocampusAcceptance` in the canonical test matrix.

The end-to-end tick fixture is part of this set; a passing helper alone is not
sufficient. Admission must verify selected Git source identities, matrix and
lock inputs, every actual test terminal, and the production dependency closure.
No additional GUI or Buddy surface is required by this Road row.
No local executable validation ran under the BSOD hold.
