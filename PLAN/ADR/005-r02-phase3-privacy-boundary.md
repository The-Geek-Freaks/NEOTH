# ADR-005 — R-02 Phase 3 channel-ingress privacy boundary

**Status**: Accepted (backfilled 2026-05-27 from Session 21
[[open-decisions-verdicts]] verdict — 4 architect agents
unanimously ratified episodes-only in Session 21 2026-05-23).

## Context

R-02 Phase 3 LLM-based theme clustering runs over the operator's
prior-day events to compose "dreams" (see [[ADR-003]] for cadence
+ [[ADR-004]] for embedding model). The unresolved question
post-Session 20: which event types feed into the cluster?

Two scopes:

1. **Episodes-only** — only `idx_episode` (Hippocampus brain region
   — RAW_TEXT + memory-op events 0x01..0x0F + 0x90..0x9F) feeds
   clustering. Channel-ingress events (Telegram inbound, Slack
   inbound, WhatsApp inbound, Discord inbound — 0x30..0x3F band)
   do NOT feed clustering.
2. **All-tier** — every region (Hippocampus + Insula channel
   ingress + Hypothalamus lifecycle + Cerebellum provider +
   BasalGanglia cron/hooks + Amygdala salience overlay) feeds
   clustering.

The choice affects:
- Privacy footprint: channel-ingress events contain other
  humans' words (counterparties on the operator's chats). Feeding
  them through an embedding + LLM theme-summarisation pass creates
  derived data about people who never consented to NEOTH's
  processing.
- Cluster quality: more event types = richer themes, but also
  more noise (cron firings, hook outputs, lifecycle events) that
  drown out the operator's actual cognitive content.
- Downstream surfacing: dreams composed from channel ingress
  could surface in the operator's recall as "you talked about X
  with Bob last Tuesday" — which leaks Bob's words back through
  the proactive-surfacing path.

## Decision

**Episodes-only.** R-02 Phase 3 clustering reads exclusively from
`idx_episode` (Hippocampus). Channel-ingress events (Insula band
0x30..0x3F) are explicitly excluded from the embedding + LLM
clustering pipeline.

Per Session 21 architect-panel verdict ([[open-decisions-verdicts]]):
> "R-02 episodes-only privacy."

Rationale anchors on the no-counterparty-leak rule: the operator
opted into NEOTH's processing; counterparties on channels did not.
Clustering counterparty words + surfacing them back via proactive
recall would silently widen the dataset NEOTH processes beyond the
operator's own cognitive footprint.

## Consequences

**Positive**
- Dreams reflect the operator's own thinking, not the cross-
  product of every conversation they had. Recall surfacing stays
  honest ("you wrote X yesterday") rather than aliasing ("Bob
  said X to you last week").
- Counterparty words never enter the embedding model + clustering
  pass. No derived data about non-consenting third parties.
- Smaller dataset per nightly pass → faster compute + lower
  cost-to-default (matters when paired with the [[ADR-003]]
  opt-in cron cadence).

**Negative**
- Operators who want "dreams over every interaction including
  channels" must explicitly enable it. Future opt-in could be
  gated on a per-counterparty consent layer (matches the
  [[neoth-arch-v2]] cluster-mode + cloud-connector matrix
  philosophy of per-source explicit toggles).
- Insula brain region stays absent from the clustering brain
  view — could feel "incomplete" to operators familiar with the
  6-region model.

**Operator-facing**
- Wizard step at R-02 setup explains: "we cluster your own
  notes + episodes, never your chat partners' words."
- `freedom.yaml::dream.regions = ["hippocampus"]` is the default
  + the only supported value at this lane; future opt-in widens
  to `["hippocampus", "insula", ...]` once per-source consent
  ships.

## Alternatives considered

- **All-tier (Insula + Cerebellum + everything)** — rejected for
  the no-counterparty-leak privacy reason above. Even with the
  Amygdala salience overlay turned off, the embedding pass alone
  derives data about counterparty content.
- **Insula-included with per-counterparty consent gate** —
  deferred. The infrastructure for per-counterparty consent
  doesn't exist yet (would need a `consent_per_sender_id` view +
  wizard surface). Episodes-only is the safe default until that
  ships.

## Implementation note

The `wal::views::episode` module shipped in Session 28 ([[neoth-
session28-burndown]] QU-08) provides the temporal-window grouping
that R-02 Phase 3 will consume. The episode view is naturally
scoped to `idx_episode` only, so this ADR's privacy boundary is
already enforced by the view-layer plumbing — there is no separate
filter to implement; R-02 Phase 3 simply reads from
`wal::views::episode::fetch_episodes` rather than a region-
broadened equivalent.

## References

- Memory: [[open-decisions-verdicts]] — Session 21 unanimous
  panel verdict.
- Memory: [[neoth-arch-v2]] — cluster + cloud-connector
  per-source consent philosophy.
- Memory: [[neoth-session28-burndown]] — QU-08 wal::views::episode
  ships the Hippocampus-only view this ADR formalises.
- `PLAN/HANDOFF_2026-05-22.md` §"Operator decisions pending" #4
  ("R-02 Phase 3 privacy boundary").
- `PLAN/PROGRESS_v1_0.md` SPEC-12 (R-02 Phase 3 implementation).
- HO-04 stub set: [[ADR-002]] / [[ADR-003]] / [[ADR-004]] /
  **[[ADR-005]]**.
