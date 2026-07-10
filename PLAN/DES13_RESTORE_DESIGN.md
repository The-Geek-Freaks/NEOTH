# DES-13: Foreign-to-Local Merge Restore Design
<!-- Source of truth for DES-13-AUTO-RESTORE-01 implementation wave (designed 2026-07-10) -->

## 1. Restore Model

"Import a peer backup" = parse a JSONL export (`neoth cluster export-foreign`,
cluster.rs:1168-1179) and apply eligible rows to the recovering node's
`idx_episode` / `idx_groundtruth`. Export line shape (ForeignEventRow wal_sync.rs:549-555):
  `{ origin_peer_pk, origin_seq, event_type:"0xNN", payload_b64, received_at }`

Restorable event types (Replicate-class; wal_sync.rs:76-84):

| Code | Name                 | Local effect                                   |
|------|----------------------|------------------------------------------------|
| 0x90 | EPISODE_CONSOLIDATED | MAX(local, peer) importance on idx_episode row |
| 0x91 | EPISODE_PROMOTED     | Same boost rule                                |
| 0x92 | EPISODE_ARCHIVED     | Soft-decay; DECAY_FLOOR=0.10 (foreign_indexer.rs:303-306) |
| 0x98 | GROUNDTRUTH_REVOKED  | Set revoked_at if NULL on idx_groundtruth row  |

Noise — skip silently (count in rows_skipped):
- 0x94 CONSOLIDATION_PASS — aggregate counts only, no addressable row.
- 0x13 UPDATE_RAN — version metadata, no recall effect.
- Any DoNotGossip code (0x97, 0x93, 0x12, …) in file = tamper/buggy peer signal.
  Log WARN + skip. NEVER act (wal_sync.rs:97-99).

## 2. Stable-Key Mapping

`idx_episode.event_id` is a local SQLite AUTOINCREMENT (store.rs:454), not peer-stable.
Gossip payloads carry the origin node's local `event_id` (foreign_indexer.rs:34-48).

Primary failover scenario: node A crashes; peer B stored A's frames in idx_foreign_events;
operator runs `neoth cluster export-foreign --peer <A_pk>` on B, then
`neoth cluster restore <file>` on recovered A. The `origin_peer_pk` in every frame = A's
own pubkey, so the exported event_ids ARE local to A — direct match is safe.

Mapping rule (no schema change to idx_episode):

```
if row.origin_peer_pk == local_node_pubkey:
    apply payload.event_id directly against local idx_episode.event_id
else:
    SKIP — no cross-peer content bridge exists (payload carries id+importance, not text_hash)
    log WARN("cross-peer episode mapping unsupported; origin={pk}")
```

Same rule for 0x98: `origin_peer_pk != local_pk` → skip. `local_node_pubkey` is read from
the cluster identity in freedom.yaml / the paired-peer registry.

## 3. Conflict Policy Matrix

Trust ceiling: curated-reference only. idx_groundtruth rows are NEVER CREATED by restore
(foreign_indexer.rs:15; store.rs:690-694). Operator-attested / groundtruth-privileged status
can never be asserted from peer data.

| Case                           | 0x90/0x91 (boost)        | 0x92 (decay)        | 0x98 (GT revoke)               |
|-------------------------------|--------------------------|---------------------|-------------------------------|
| local row missing              | SKIP                     | SKIP                | SKIP                          |
| local importance >= peer       | MAX → no-op (idempotent) | Apply; floor=0.10   | If revoked_at set: SKIP       |
| local importance < peer        | Boost to peer value      | Apply; floor=0.10   | Set revoked_at = received_at  |
| fact_state='contradicted'      | N/A                      | N/A                 | SKIP (already closed)         |

Each row is its own SQLite transaction; failure rolls back that row only.

## 4. Audit Trail

WAL opcode space is EXHAUSTED — events.rs SCHEMA_VERSION 24 occupies all 255 slots
(0x01-0xFF). Verified 2026-07-10 by scanning every `pub const EVENT_TYPE_*: u8` constant.
DO NOT reuse 0xDB (CONSENT_GRANTED) or 0xDC (CONSENT_REVOKED).

Restore audit uses a dedicated append-only log: `~/.neoth/restore-audit.jsonl`.
Mode 0600 (same ACL pattern as views.db; store.rs:65). Two records per run:

```json
{"kind":"RESTORE_STARTED","source_file":"...","peer_pk":"...","dry_run":bool,"ts_unix":N}
{"kind":"RESTORE_COMPLETED","source_file":"...","peer_pk":"...","rows_scanned":N,
 "rows_applied":N,"rows_skipped":N,"dry_run":bool,"ts_unix":N}
```

Future: when WAL event-type is extended to u16, migrate to a cluster-restore band. The
opcode-exhaustion blocker goes into OPEN_DECISIONS.md as a new D-entry.

## 5. CLI Surface

```
neoth cluster restore <peer-export> [--dry-run] [--peer <pk>] [--yes]
```

- Registered as `ClusterAction::Restore` in cluster.rs alongside `ExportForeign` (line 49
  pattern). One-shot, synchronous, operator-invoked only.
- Consent gate: prints "Restore will modify local recall from peer <pk>. Confirm [y/N]:";
  `--yes` skips for scripted use; must be explicit.
- Skips `#`-prefixed comment lines from export file (the EXPORT_FOREIGN_WARNING header).
- `--dry-run`: evaluates conflict logic, prints per-row outcome to stderr, writes ZERO SQL,
  writes ZERO audit log, exits 0.
- NO background auto-merge. Tracker deliberately deferred auto-merge; this design is
  operator-invoked only, not a daemon path.
- Aborts with guidance if views.db is locked by the running daemon.

## 6. Test Plan

1. Idempotent re-restore: second run on same file → rows_applied=0, rows_skipped=N.
2. Conflict matrix fixtures: one test per matrix row (missing/boost/decay/revoke/contradicted).
3. Trust ceiling: file with hand-crafted 0x97 GROUNDTRUTH_ADDED line; assert zero
   idx_groundtruth rows created; that line counted in rows_skipped.
4. Dry-run parity: dry-run rows_scanned == real-run rows_scanned; DB checksum unchanged
   after dry-run.
5. Cross-peer skip: origin_peer_pk != local_pk in all rows → rows_applied=0, WARN emitted.
6. DoNotGossip tamper: 0x93/0x12 in file → all in rows_skipped, no SQL written.
7. Audit log ACL: restore-audit.jsonl created with mode 0600; RESTORE_STARTED line
   precedes any row-level write.

## 7. Size Estimate and File Touch-List

Estimate: M (3-5 days: consent gate + dry-run parity + cross-peer detection + ACL)

| File | Change |
|------|--------|
| `SRC/neothd/src/cli/cluster.rs` | ClusterAction::Restore + run_restore() ~150 LoC + 7 tests |
| `SRC/neothd/src/cluster/wal_sync.rs` | apply_restore_frame() + local_node_pubkey() helper |
| `SRC/neothd/src/cluster/foreign_indexer.rs` | Extract conflict helpers as pub fns for reuse |
| `PLAN/OPEN_DECISIONS.md` | New D-entry: WAL opcode exhaustion; propose u16 extension track |
