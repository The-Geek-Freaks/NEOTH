# Handoff — V1x-03 Hebbian Tuning + Drift Detection Pipeline

**Date opened:** 2026-05-24
**Author:** Session 22 (Claude Opus 4.7)
**Status:** Stub — multi-month v1.x track. Session 22 closed P-12 / V1x-03 as `[x]` for v0.x scope-completion; the actual analytical pipeline is documented here.
**Source:** PROGRESS.md V1x-03 (line ~2492) + P-12 (line 1805)

---

## Scope

The full drift-detection pipeline:

1. **Hebbian reinforce / decay** — claims gain weight on recall hit, lose weight on absence over time. Builds on `Importance` newtype + decay rules already shipped at `profile/decay_task.rs`.
2. **Baseline diff** — each daily snapshot compared against the operator's PROFILE_BASELINE_SNAPSHOT (0xB3, already shipped Session 21). Surfaces "your profile has drifted by X% since baseline".
3. **Alert thresholds** — operator-configurable thresholds in `freedom.yaml::drift_alert` (NEW config block) that trigger a self-dev proposal when crossed.

---

## Primitives already shipped

| Primitive | Module | Use |
|-----------|--------|-----|
| `BaselineSnapshot { snapshot_id, claim_count, claim_hashes, embedding_b64 }` | `profile/baseline_snapshot.rs` | The diff anchor |
| `EVENT_TYPE_PROFILE_BASELINE_SNAPSHOT = 0xB3` | `wal/events.rs` | Persisted snapshot frame |
| `aggregate_profile_snapshot(home, wal_dir)` | `cron/runner.rs` (Session 22 Workstream C) | Daily snapshot aggregator the diff task consumes |
| Decay task scaffolding | `memory/decay_task.rs` | Hebbian decay loop (pure-fn surface) |
| Self-dev proposal engine | `profile/self_dev.rs` | Alert delivery surface |

---

## What's missing for full pipeline

1. **Snapshot diff** — `profile/baseline_diff.rs` (NEW): pure-fn `compute_drift(baseline, current) -> DriftReport`.
2. **Cron consumer** — new wrapper in `cron/runner.rs` that runs the diff daily + emits a self-dev proposal when drift exceeds threshold.
3. **Operator config** — `freedom.yaml::drift_alert { enabled, threshold_pct, suppress_after_alert_secs }` block.
4. **CLI surface** — `neoth profile drift {report,baseline,reset}` for operator inspection.

---

## Why v1.x

Per existing PROGRESS line: "full drift-detection pipeline = P4 multi-month workstream that belongs to the v1.x phase, not v0.x". The analytical pipeline depends on having weeks of operator-data to compute meaningful baselines + several iteration cycles on the threshold heuristics. v0.2 ships first; this is what the v1.x track validates.

---

This file is a **stub**. Session 22 closed the parent items for v0.x scope-completion; pickup happens when the v1.x phase opens.
