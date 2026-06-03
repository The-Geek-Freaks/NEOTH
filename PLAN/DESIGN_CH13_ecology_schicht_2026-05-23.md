# CH-13 — Ecology-Schicht design start (P4)

**Status:** design started 2026-05-23 (Session 21). Code lands in P4
(post-GA, multi-month). This note pins the architecture so anyone
who picks it up later doesn't have to re-derive it.

## What "Ecology-Schicht" means

Above NEOTH's existing layers (council → profile → memory → WAL),
the Ecology layer is the **self-improvement / self-adaptation
loop** — NEOTH watching itself, picking what to change, and acting
on it without an operator turn-by-turn.

Three sub-loops, each runs on its own cadence:

1. **Self-improvement loop** — daily/weekly cron that reads the
   recent WAL + asks "is the operator's experience getting
   better?" Drives proposal generation (already shipped as P-04
   self-dev surface — Ecology is the layer that DECIDES WHEN to
   fire P-04, vs P-04's own gates which decide WHAT to propose).
2. **Council-adaptation loop** — CH-12 adaptive thresholds (shipped
   Session 21) plus the future CH-12.b feedback loop that bumps
   complexity-floor / cooldown when council winners are too
   correlated (low-dissent signals operator pattern shifted; cooldown
   should shorten to surface dissent again).
3. **Tool-genealogy loop** — track which skills + plugins each
   council winner relied on. When a tool gets removed/deprecated,
   the genealogy graph surfaces every downstream winner-chain that
   depended on it so the operator can be warned before they hit a
   broken council debate.

## Existing primitives this builds on (all shipped)

- P-01 estimators (5-dim BehaviouralProfile) — `profile/estimators.rs`
- P-04 self-dev proposal engine + CLI + WAL outbox — `profile/self_dev.rs` + `cli/self_dev*.rs`
- CH-12 adaptive thresholds — `council/adaptive_thresholds.rs`
- CH-14 trigger gate — `council/trigger.rs`
- Council debate + winner-selection — `council/orchestrator.rs`
- WAL event lifecycle (PROFILE_DELTA / COUNCIL_WINNER_SELECTED /
  SELF_DEV_PROPOSED) — all in `wal/events.rs`

## What ships in the P4 multi-month workstream

| Phase | Deliverable | Estimated effort |
| ----- | ----------- | ---------------- |
| 1     | `ecology/scheduler.rs` — cron-task that ticks every 6h, reads BehaviouralProfile, calls P-04 self-dev when signal-threshold fires | ~2 days |
| 2     | `ecology/correlation_detector.rs` — pure-fn pass over `COUNCIL_WINNER_SELECTED` events; surfaces "winner X picked for N consecutive runs" as a signal | ~2 days |
| 3     | `ecology/genealogy.rs` — tool dependency graph builder (skill_id / plugin_id → winner-chain count) + the `neoth doctor genealogy` CLI surface | ~3 days |
| 4     | `cli/ecology.rs` — operator surface (`neoth ecology status` + `neoth ecology pause` + `neoth ecology resume`) | ~1 day |
| 5     | WAL event reservations: `0xEC ECOLOGY_PROPOSED` + `0xED ECOLOGY_APPLIED` + `0xEE ECOLOGY_DECLINED` (band 0xEx is cluster — Ecology gets `0xCx` band or `0xEx` after CT band re-mapping decision) | ~0.5 day |
| 6     | Integration + tests + WAL replay coverage | ~2 days |

**Total**: ~10-12 focused days. Lands as a P4 milestone.

## Decision pins (locked here so the implementer doesn't re-debate)

1. **Cron cadence: 6 hours.** Not every-prompt (too noisy) or daily
   (too coarse for adaptive-threshold drift). 6h aligns with
   operator "morning brief at 07:30 + lunch + evening + nightly"
   rhythm + matches the dreaming task cadence already shipped.

2. **Genealogy storage: in-memory graph, rebuilt on demand from
   WAL replay.** Don't add a SQLite view. Genealogy is a debug /
   diagnostic surface, not a hot-path lookup — rebuild on
   `neoth doctor genealogy` invocation (~100ms for a year's WAL
   on typical operator).

3. **Proposal density cap: 1 per 6h-tick.** The Ecology layer fires
   P-04 self-dev `propose` AT MOST once per tick. Operators don't
   want a flood of pending proposals competing for review.

4. **Default OFF.** Per the AGENTER hard rule + the precedent set
   by `proactive.enabled` (C-16) and `dreaming.enabled` (R-02).
   Operator opts in via `freedom.yaml::ecology.enabled: true`.

5. **No model-driven decisions inside the Ecology layer.** Every
   trigger is pure-fn over WAL data (correlation count, gap
   threshold, signal strength). Ecology never calls an LLM. The
   LLM-call lives in P-04's proposal engine which the scheduler
   delegates to — keeping Ecology deterministic + auditable.

## Why this design vs alternatives considered

- **vs "run on every chat"**: too noisy, would invert NEOTH's
  reactive-by-default posture into proactive-by-default.
- **vs "fully model-driven"**: would make Ecology decisions
  opaque + non-replayable. Pure-fn triggers stay grep-friendly.
- **vs "extend P-04 instead of new layer"**: P-04 is the proposal
  engine (what to propose); Ecology is the scheduler (when to
  propose). Mixing them tangles two concerns.

## Open questions deferred to the P4 implementer

- **Q1**: When the Ecology layer fires P-04 with a strong signal but
  the operator declined the same proposal kind 3 times in a row,
  should Ecology back-off the trigger weight for that kind? (Default
  proposal: yes, exponential — back-off doubles per decline up to
  30d.)
- **Q2**: Should `neoth ecology pause` emit a WAL event so the audit
  trail shows ecology-was-paused-while-X-happened? (Default proposal:
  yes, new event `0xED ECOLOGY_PAUSED`.)

## File list (no code yet; just where the implementer will land)

- `SRC/neothd/src/ecology/mod.rs` (new module root)
- `SRC/neothd/src/ecology/scheduler.rs`
- `SRC/neothd/src/ecology/correlation_detector.rs`
- `SRC/neothd/src/ecology/genealogy.rs`
- `SRC/neothd/src/cli/ecology.rs`
- `SRC/neothd/src/wal/events.rs` (add 3 event codes)
- `SRC/neothd/src/config/mod.rs` (add `EcologyConfig` block default OFF)

## HARD CONSTRAINT (operator-flagged 2026-06-03, Session 36) — Ecology must not become autopilot

Read-only diagnostics (the shipped `neoth ecology correlation` + `neoth ecology
channel-weights`) are fine. But the moment the layer gains the ability to ACT —
the Phase-1 auto-scheduler firing P-04 self-dev, or a future CH-12.b cooldown-
shortening / threshold-adjusting loop — that action MUST be either:

1. **review-gated** — staged as an OB-03 proposal the operator accepts via
   `neoth proactive review` (never auto-applied), OR
2. **at minimum WAL-audited** — every Ecology decision that changes council/
   routing POLICY emits a durable audit frame BEFORE it takes effect, so an
   operator (and `neoth wal show --type ...`) can see exactly what the fitness
   layer changed and when.

**Council-fitness must never silently rewrite council-policy.** The signal layer
(correlation, channel-weights, genealogy) reads; the policy layer (thresholds,
cooldowns, routing) is only changed through a gate the operator can see. The
Phase-5 WAL events (`ECOLOGY_PROPOSED`/`APPLIED`/`DECLINED`, now in the 0x4x
cron band per the slot audit) are the mechanism for #2.
