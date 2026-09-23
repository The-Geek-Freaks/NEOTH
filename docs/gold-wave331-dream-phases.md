# W331 — durable Dream Light, REM and Repair

The existing opt-in Dream scheduler uses its accepted-generation effect rail.
`views.db` owns phase state and restart decisions. Eligible inputs are prepared
before the legacy calendar claim; that claim still precedes the composer so
its JSONL/Forge/Obsidian/DREAM_COMPOSED effects are never blindly replayed.
Both post-claim paths resume existing phase inputs only. A day without eligible
input intentionally remains legacy-only.

A run binds its local date, accepted generation, sorted/deduplicated positive
Dream event IDs, text hashes, origin/consent-revision hashes, source tier and
trust. At most 32 Hot rows and 32 independent Warm anchors participate. Pinned,
missing-origin, revoked and unconsented rows are excluded. Revoke then regrant
with a new revision cannot reactivate an old prepared binding.

Light moves only bound, still-matching unpinned Hot episodes into retained Warm
rows. Ordinary and Dream tier movement preserve source trust; legacy schema
rows default to trust 1. Real Warm/Cold recall readers consume the persisted
trust. No global decay sweep runs as a Dream effect.

REM records each canonical pair once per run. A pair reaches the existing
recall-consumed `idx_memory_links` graph only after two distinct completed runs.
Warm anchors allow later runs to observe a pair after Light consumed its Hot
rows. Repair validates declared Light outputs and repairs only missing pairs
from the current run; unrelated globally qualified pairs remain untouched.

Light has a separately durable Prepared receipt. For REM and Repair, receipt
preparation, effect, Completed transition and pending audit state are one
Immediate SQLite transaction: a crash before commit rolls all of them back,
and a committed effect already has its Completed receipt. Each effect and its
outbox state commit atomically. A missing or changed binding blocks effects.

W332 delivers an authenticated append-once WAL receipt before acknowledging the
outbox. Lost acknowledgements leave the same transition pending for exact
retry. Phase preparation, legacy claim and phase-effect commit leases end at
their synchronous DB operations. Only the dedicated audit lease spans WAL
await; composer and Obsidian work retain their established generation rails.
Resume failures stay visible in diagnostics and do not reselect current data.

The exact fixture identities are registered in the canonical test matrix.
They cover selected-only promotion, real-reader trust 0, two-run REM and replay,
bounded IDs, consent revocation/regrant, generation/hash refusal, resume-only
selection, declared-pair repair, and rollback when the second Light write fails.
W344 adds v44-to-v45 migration/defaults/rollback and ordinary tier-trust cases.
Independent static review passed. Hosted formatting, lint, compilation and
behavioral checks remain required; no local executable validation ran.
