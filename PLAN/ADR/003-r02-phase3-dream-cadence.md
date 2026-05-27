# ADR-003 — R-02 Phase 3 dream-composition cadence

**Status**: Proposed (HO-04 stub registered 2026-05-27 Session 28;
final decision waits on Day-14b forward-pass unstuck — embedding
model selection [[ADR-004]] is the dependency edge).

## Context

R-02 Phase 3 ships LLM-based theme clustering over the operator's
prior-day episodes ([[neoth-d101-d102-d103-verdicts]] + SPEC-12 in
PROGRESS_v1_0.md). The clustering produces "dreams" — semantic
compressions of the day's interactions that feed proactive recall +
G-02 wrong-self-knowledge surfacing.

The clustering pass is non-cheap: it runs embeddings over every
episode + agglomerative clustering + LLM theme-summarisation. Two
cadence shapes presented themselves:

1. **Cron 03:00 nightly** — the dream pass runs automatically at the
   operator's local 03:00 (low-activity window). Operators wake to
   yesterday's dreams already composed.
2. **Operator-triggered (`neoth dream now`)** — no cron; operator
   runs the pass on demand. Compute happens when the operator asks.

The decision affects:
- Quota cost: nightly cron consumes a measurable LLM-call budget
  every day regardless of whether the operator queries dreams the
  next day. Operator-triggered consumes only on demand.
- Proactive surfacing latency: G-02 ("you said X last week but the
  current chat suggests Y") needs the cluster pre-computed to fire
  in-conversation; nightly cron makes it always-ready, on-demand
  introduces a "computing dreams…" delay.
- Privacy ([[ADR-005]]): nightly cron means embeddings run over
  every episode every night, regardless of operator awareness;
  operator-triggered keeps the operator in the explicit loop.

## Decision

**Pending.** The recommended shape per Session 21 architect-panel
direction is a hybrid:

- **Default:** opt-in `neoth dream now` (no cron until the operator
  enables it). Operator runs the pass when they want dream-derived
  recall surfacing.
- **Operator opt-in:** `freedom.yaml::dream.cron_enabled = true`
  with `freedom.yaml::dream.cron_at = "03:00"` lights up the nightly
  pass. Wizard step explains the trade-off
  (always-ready proactive surfacing vs LLM-quota cost vs every-night
  embedding run over your episodes) + recommends default-off.

This pairs with the no-deferred-LLM-calls hard rule
([[feedback-no-deferring-roadblocks]]): the operator owns the
explicit "compute dreams now" gesture in the default flow.

## Consequences

**Positive (default off + opt-in cron)**
- Zero ambient LLM cost until the operator opts in.
- Embedding pass over episodes happens only when the operator
  explicitly chooses, preserving the AIO "operator controls every
  outbound call" stance.
- G-02 wrong-self-knowledge surfacing latency is "first turn after
  the operator triggers dreams" — acceptable for an opt-in feature.

**Negative**
- First-use friction: until the operator runs `neoth dream now`,
  there are no clusters → no proactive surfacing. We need a
  wizard-time + first-recall-time UX nudge.
- The opt-in cron path is essentially the cron-default path with
  more steps; some operators will opt in immediately + then
  wonder why we didn't default-on.

**Operator-facing**
- Default install: `neoth dream now` is a single command, runs on
  demand.
- Opt-in toggle: `freedom.yaml::dream.cron_enabled = true` + GUI
  settings parity (per the slash-commands-and-settings-parity hard
  rule [[neoth-slash-commands-and-settings-parity]]).

## Alternatives considered

- **Nightly cron always-on default** — rejected for the privacy +
  quota-cost reasons above + the no-ambient-LLM-default policy.
- **Per-message synchronous dream compose** — rejected: clustering
  needs ≥1 day of episodes to be useful; per-message would just be
  expensive noise.

## Open questions

- Hour-of-day for opt-in cron: defaults to operator's local 03:00,
  but timezone detection on first wizard run is fragile; consider
  asking the operator at opt-in time.
- Dream-composition retry on cron-tick clock skew: ARCH-06 HLC
  integration is the upstream dep ([[neoth-open-decisions-verdicts]]
  Round-3 v0.9 ARCH-06).

## References

- Memory: [[open-decisions-verdicts]] — Session 21 panel ratified
  R-02 episodes-only privacy; cadence remained "operator pick".
- Memory: [[neoth-d101-d102-d103-verdicts]] — D-103 wasmtime
  baseline (Day-14b forward-pass dependency).
- `PLAN/HANDOFF_2026-05-22.md` §"Operator decisions pending" #2.
- `PLAN/PROGRESS_v1_0.md` SPEC-12 (R-02 Phase 3 implementation).
- This ADR is one of four HO-04 stubs:
  - [[ADR-002]] R-2 port strategy (Accepted).
  - **[[ADR-003]] R-02 Phase 3 cadence** (this doc, Proposed).
  - [[ADR-004]] R-02 Phase 3 embedding model (Proposed).
  - [[ADR-005]] R-02 Phase 3 privacy boundary (Accepted).
