# SPEC — Cluster Phase 6 (gossip state-sync)

**Status**: scope acknowledged. Multi-week effort — single-session
ship structurally impossible.

**Parent SPEC**: `PLAN/SPEC_cluster_auto_discovery_2026-05-22.md`
Phase 6 (state-sync gossip protocol).

## Use case

After Phase 4 confirm, two NEOTH instances are paired but
isolated — each has its own WAL, memory tiers, kanban,
usage_log, dreams. Phase 6 makes them act as one logical unit:
WAL frames gossip between peers + the memory layers stay in
sync without operator intervention.

## What gossips

Per the parent SPEC's "Cluster state sync" section, scope is:

1. **WAL frames** via vector-clock-tagged gossip. Each peer's
   WAL writer adds a `peer_id` + `lamport_ts` to every frame;
   the gossiper replays remote frames it hasn't seen yet.
   Conflict resolution: last-writer-wins per frame; the
   per-frame HMAC chain in the existing WAL design defends
   against tampering.

2. **Memory tier sync** (`idx_episode` / `idx_consolidated` /
   `idx_longterm`). Per-event-id replication piggybacks on
   the WAL gossip — every reinforcement / consolidation /
   long-term promotion already emits a WAL frame, so the
   tier-table state is derivable from WAL replay.

3. **Append-only JSONL files** (`kanban.jsonl`,
   `usage_log/*.jsonl`, `dreams/*.jsonl`). Trivially gossipable
   — peer sees a higher-numbered line + appends locally.
   Conflict resolution: sort by ts_unix on read.

4. **Council debate budget** (Pick #8 `BudgetToken`). Either
   leader-elected or distributed-token across the cluster.
   The latter is multi-week in its own right (Raft-style
   consensus for budget decrement).

## Why this is multi-week

- **Vector clocks**: every peer maintains a per-cluster
  Lamport-clock map. Implementation + tests + edge cases
  (clock skew, peer addition/removal) is 1-2 weeks of
  careful work.
- **Replay-on-reconnect**: a peer offline for a week must
  catch up on all frames the cluster wrote during its
  downtime. Bounded retransmit + the new frames during
  catchup → another 1-2 weeks.
- **Conflict detection**: even with LWW per frame, the
  memory layers can diverge in subtle ways (peer A
  reinforces an event peer B just consolidated). Resolution
  table + tests → 1-2 weeks.
- **Budget consensus**: shared `BudgetToken` across peers
  needs Raft or similar — Lamport clocks alone don't
  prevent two peers from each draining the daily_usd_cap
  in parallel. Quorum-based decrement → 2-3 weeks.

Total: ~6-10 weeks of focused work.

## Phase 6.1 (1 session) — GOSSIP-PROTOCOL SPEC

Single-session deliverable: write the gossip wire-protocol spec
covering vector-clock representation + replay envelope + LWW
conflict resolution rules. No implementation. Single-instance
operators pay zero cost.

## Phase 6.2..6.5 (multi-week)

1. **Phase 6.2** — WAL frame gossip (1-2 sessions for the
   primitive; multi-week for production-readiness)
2. **Phase 6.3** — Memory tier sync derived from WAL replay
3. **Phase 6.4** — JSONL append-stream gossip (kanban / usage /
   dreams)
4. **Phase 6.5** — BudgetToken Raft consensus across peers

## Open questions

1. Replay frame budget on reconnect — what's the upper bound
   before a peer that's been offline >30 days should refuse to
   catch up + force a clean re-pair?
2. Per-channel filter: do Telegram / Slack / WhatsApp ingress
   frames replicate to every peer (so any peer can answer) OR
   only to the peer that owns the channel adapter (no
   replication, just visibility)?
3. Privacy: an operator's memory tiers contain conversations
   with friends. Gossiping those to every paired peer is the
   default — should there be a per-event "do not gossip" tag?
