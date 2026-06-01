# NEOTH Fractal Dimension — brain / memory / agent architecture extension

**Status**: design + concrete experiments queued. Not built v0.1.x. Tracked here so when an experiment is run, the math is rigorous from the start and not a Twitter-grade buzzword pose.

**Origin**: Operator note 2026-05-15 connecting Mandelbrot's coastline-paradox (smaller ruler → longer measured length → measurable fractal dimension `D`) to NEOTH's memory + reasoning + skill + trust architecture.

**Core insight**: NEOTH's existing primitives (4-tier memory, sub-agents, skills, autonomy gates) already exhibit *partial* self-similarity but are coded as if they were strict hierarchies. If self-similarity across scales is **measurable** and **utilisable**, the architecture compresses, the cost model improves, and the reasoning-depth knob becomes adaptive instead of binary.

This document distinguishes **where the fractal lens is real** (measurable D, falsifiable claims) from **where it's metaphor** (hierarchy with a fancy name). The five real lenses get an experiment that produces a number; the metaphors get explicitly skipped.

---

## The honesty test (must pass before any "fractal" claim ships)

A NEOTH feature qualifies as "fractal" only if:

1. **Self-similarity is measurable across ≥ 3 scales.** Box-counting / size-distribution / branching-factor across at least three levels must yield a slope that is stable (low variance) and non-trivial (D ≠ 1.0, D ≠ 2.0).
2. **The dimension `D` is a concrete number per operator.** Not "feels recursive". `D = 1.42 ± 0.03` measured on the operator's actual data.
3. **Behaviour at D=1.0 vs D=1.4 vs D=1.9 is observably different and benchmarkable.** The feature must do something different at different D values, and that difference must move a metric the operator cares about (cost / latency / hit-rate / correctness).

Any claim that fails the test gets renamed to its honest description ("hierarchy", "recursion") and shipped without fractal-dimension framing.

---

## Five places where the fractal lens is real

### 1. Memory tree dimension `D_mem`

**Hypothesis**: NEOTH's 4-tier memory (`idx_episode` hot → `idx_consolidated` warm → `idx_longterm` cold → `idx_groundtruth` immutable) is approximately self-similar. Each tier holds the same shape (text + hash + importance + ts) at a different summarisation scale. The compression ratio between tiers (raw → summary → meta-summary) is the box-count signal.

**Measurement**: Log-log plot of `total_bytes(tier_n)` against `n` for tiers 0..3. If the slope is stable, the tree is fractal and `D_mem` = slope. NEOTH-side: `memory::dimension::estimate_d_mem(conn) -> f32` walks the tiers + emits the slope.

**Utility once measured**:
- **Per-operator summariser aggressiveness**: high `D_mem` (≈1.9, verbose operator with redundancy) → consolidator can compress harder without losing signal. Low `D_mem` (≈1.1, dense operator) → consolidator must be gentle.
- **Predictive token budget**: knowing `D_mem` lets the cost predictor estimate how much a recall query will cost across tiers (currently flat 4-tier scan).
- **Anomaly detection**: a sudden `D_mem` drift indicates the operator's communication style changed or the consolidator regressed.

**Experiment 0**: ship `neoth memory dimension` CLI that prints the current `D_mem` + the underlying log-log table. Pure read, no behaviour change. Cost: ~150 LOC + 3 tests.

**Phase 2 follow-up**: wire `D_mem` into `memory::consolidate::run_consolidation_pass` so the summariser prompt + the importance-decay rate depend on the measured value.

### 2. Reasoning-depth dimension `D_think` (adaptive auflösung)

**Hypothesis**: every operator turn has an inherent "stakes × reversibility × uncertainty" triplet that determines how much reasoning is appropriate. Today's agents are binary: greedy fast (`D ≈ 1.0`, "ja mach das") or Extended Thinking (`D ≈ 2.0`, 30k tokens for a pizza order). The right answer for most turns lives between, at `D ≈ 1.3..1.6`.

**Measurement**: Pre-call classifier (50-token Qwen3-Q8 forward pass against the prompt) returns `(stakes ∈ [0,1], reversibility ∈ [0,1], uncertainty ∈ [0,1])`. `D_think = 1.0 + (stakes × (2 - reversibility) × uncertainty)`. Bound to `[1.0, 2.0]`.

**Utility**:
- **Cost-shape transparency**: the existing `providers::cost::predict` gains a `D_think` input that scales `output_tokens_est`. At `D=1.0`, output_est = ~150 tokens. At `D=1.9`, output_est = ~3000 tokens.
- **Provider routing**: low-`D` turns route to `local_qwen` (free); high-`D` turns route to Claude Opus. Operator sees the routing decision in the cost preview.
- **Adversarial pair**: a `D=1.2` answer + a `D=1.6` critique by the `critic` sub-agent runs in parallel — the operator sees both. Implementable as a hook on `PreProviderCall` (existing primitive).

**Experiment 1**: ship `neoth reasoning estimate "<prompt>"` CLI that returns the `(stakes, reversibility, uncertainty, D_think)` triplet without dispatching the provider. Operator can manually inspect.

**Experiment 2**: extend the `permissions::PaidProviderCall { eur_estimate }` action with a `d_think` field; the existing confirm gate shows both the euro cost AND the reasoning-depth so operator sees over-provisioning (`D=1.9` for a yes/no question) before committing.

### 3. Skill composition dimension `D_skill`

**Hypothesis**: a skill that calls skills (which call skills) — if every level has the same shape (`SKILL.md` + trigger + procedure + rollback), it's self-similar. The dimension is the branching factor (avg sub-skills per skill) across composition depth.

**Measurement**: `skills::dimension::estimate_d_skill(skill_registry)` walks the skill registry's invocation graph (each `skill.toml` declares which other skills it calls). Box-count: for each depth `n`, count the unique skills reachable. Log-log slope = `D_skill`.

**Utility**:
- **Skill-Factory pruning**: when `D_skill > 1.5`, the operator's skill graph is dense — Skill Workshop should propose **consolidation** (merge skills that always co-invoke). When `D_skill < 1.2`, the graph is sparse — Skill Workshop should propose **decomposition** (split a fat skill into reusable pieces).
- **Trust audit cost**: skill execution cost scales with `D_skill` (more sub-invocations per top-level call). The `permissions::evaluate` gate can preview this BEFORE the skill runs ("this skill will trigger 12 sub-skills, est. €0.14").

**Phase 2**: skill-graph rendering + `neoth skill graph --format dot` to visualise the structure. The visual is more useful than the number for most operators.

### 4. Conversation topology dimension `D_conv`

**Hypothesis**: the operator's conversation across sessions is not a linear chain (D=1) nor a fully-connected graph (D=2). It's a sparse, branching topic graph with occasional cross-references — empirically ≈ D=1.3..1.5 on real chat data.

**Measurement**: build the topic-link graph from `idx_episode` + `idx_consolidated` (FTS5 + embedding edges). `memory::dimension::estimate_d_conv(conn)` log-log-counts reachable topics at distance 1, 2, 3 from any given starting episode. Stable slope → `D_conv`.

**Utility**:
- **Recall ranking**: today recall is BM25 + tier-weight + recency. Adding a `D_conv`-aware traversal lets queries jump across cross-references the operator made themselves. "What did I say about X three weeks ago that connects to today's Y" becomes a graph-walk, not a flat search.
- **Memory replay**: at high `D_conv`, the daily-summary cron job has fertile cross-reference soil — emit "you connected X to Y on Tuesday, the same theme came up Friday".
- **Anti-rambling signal**: a sudden drop in `D_conv` means the operator's sessions stopped cross-referencing — could indicate session amnesia or topic shift. Surface as a gentle warning.

### 5. Trust / verification dimension `D_trust` (the fractal trust spec)

**Hypothesis**: the same trust question — "darf das passieren?" — applies at every scale: user input → skill input → LLM call → sub-agent → file write. Today NEOTH writes the gate logic *separately* per layer (`security::ingress_sanitizer`, `permissions::evaluate`, `hooks::dispatcher::run_stage`). A truly fractal trust spec writes the logic once and applies it at every depth.

**Measurement**: not a number — it's a coverage check. `D_trust = 1.0` when every action uses the same trust trait; `D_trust = 0.0` when each layer has its own bespoke check. Today NEOTH is ~`D_trust = 0.4` (two layers use `evaluate`, two use bespoke regex).

**Utility**:
- **One trust trait, all layers**: introduce `Trustable::evaluate(&self, ctx: &TrustCtx) -> TrustDecision`. Every layer implements it once. The hook dispatcher, the permission gate, the skill runner, the sub-agent dispatch all call the same function.
- **Audit completeness**: a single WAL band records every `Trustable::evaluate` outcome. `neoth verify --trust-completeness` checks every gate-passage emitted a WAL event in the last 24h.

**Phase 0 prerequisite**: this needs the existing permission + hook + sanitizer modules audited for overlap before refactoring. Not a v0.1 item.

---

## Where it would be marketing (DO NOT ship under fractal framing)

These are valid features but DO NOT have measurable `D`:

- **"Sub-agents calling sub-agents calling sub-agents"** — that's recursion, not self-similarity. Call it recursion.
- **"Hierarchical memory"** — strict hierarchy with three levels is just three levels. The fractal claim requires log-log linearity.
- **"Adaptive complexity"** — vague. Pick a specific dimension (`D_think`, `D_skill`) and name it.
- **"Mandelbrot-inspired agent architecture"** — if there's no Hausdorff dimension being computed, this is a t-shirt slogan.

---

## Concrete buildable experiments (in order, smallest first)

### EXP-FD-0 — Memory dimension reporter (Phase 0, ~1 day)

`neoth memory dimension` CLI. Reads `idx_episode`/`idx_consolidated`/`idx_longterm`/`idx_groundtruth`. Computes total-bytes-per-tier + row-count-per-tier. Log-log plot the byte counts; slope is `D_mem`. Pure read, no behaviour change. JSON + table output.

**Acceptance**: prints `D_mem ≈ 1.4` (or whatever the operator's value is) with the underlying table. Slope-stability metric (`R²`) shown so operator knows whether the value is meaningful.

### EXP-FD-1 — Reasoning-depth classifier (Phase 1, ~3 days)

`neoth reasoning estimate "<prompt>"` returns `(stakes, reversibility, uncertainty, D_think)`. Two implementations:
- v1: hand-coded heuristics (length × question-mark count × keyword matches for "delete", "permanent", "irreversible"). 50 LOC.
- v2: local Qwen3-Q8 classifier prompt. Reuses the existing local-inference path.

**Acceptance**: 10 manual test prompts produce defensible `D_think` values. "Order pizza" → ≈1.1. "Should I sign this contract" → ≈1.7. "Delete my last 6 months of data" → ≈1.9.

### EXP-FD-2 — Cost-aware reasoning-depth gate (Phase 1, ~2 days, depends on EXP-FD-1)

Extend `providers::cost::predict` to accept `D_think` as a multiplier on `output_tokens_est`. Extend `permissions::PaidProviderCall { eur_estimate, d_think }`. Confirm prompt shows both numbers: "**€0.14** for this turn at `D_think=1.6` — proceed?". Operator sees over-provisioning before committing.

**Acceptance**: a turn at `D=1.9` vs `D=1.1` produces different `eur_estimate` values in `neoth cost estimate`. WAL `0xA4 COST_ESTIMATE_SHOWN` payload gains a `d_think` field.

### EXP-FD-3 — Adversarial-pair routing (Phase 2, ~1 week, depends on EXP-FD-1 + existing `critic` sub-agent)

When `D_think > 1.4`, the daemon dispatches the operator's turn AT `D=1.2` to the primary provider AND `D=1.6` to the `critic` sub-agent in parallel. Operator sees both. Useful for high-stakes decisions where you want speed + verification simultaneously.

**Acceptance**: a single high-stakes prompt produces two WAL events (`0x20 PROVIDER_REQUEST` at low `D`, `0x84 SUBAGENT_REVIEW_STAGE` at high `D`). Latency does not double — the calls run concurrently.

### EXP-FD-4 — Adaptive summariser aggressiveness (Phase 2, ~1 week, depends on EXP-FD-0)

`memory::consolidate::run_consolidation_pass` reads the current `D_mem` and scales the summariser prompt: at `D_mem ≥ 1.7`, use the "compress hard, drop redundancy" prompt; at `D_mem ≤ 1.2`, use the "preserve every claim" prompt. Token savings measurable via the meter.

**Acceptance**: per-operator `D_mem` is logged at consolidation time as `0x94 CONSOLIDATION_PASS` payload extension. Operator can `neoth events --code 0x94` to see the dimension trend over time.

### EXP-FD-5 — Conversation topology recall (Phase 3, ~2 weeks)

Recall extension: at `D_conv > 1.3`, the BM25 + tier-rank score gets an additional graph-walk bonus for episodes that cross-reference each other. Operator can ask "what did I say three weeks ago that connects to today's question" and get walk-by-walk hits, not just keyword matches.

**Acceptance**: a hand-curated test set of 20 cross-referenced episodes scores higher under `D_conv`-aware recall than under flat BM25+tier.

---

## Why this matters for NEOTH specifically

NEOTH already has the primitives: 4-tier memory, sub-agents, hooks, WAL audit, autonomy gates. The fractal lens is not a new system — it's a measurement framework on top of what's shipped.

The unique NEOTH advantage:
- **WAL gives ground-truth data**: every consolidation pass, every skill call, every reasoning turn is already journaled. The dimension can be measured offline from the WAL alone, no instrumentation needed.
- **Self-contained**: the dimension lives on the operator's machine, never leaks. Compare to OpenHuman where the cloud sees everything.
- **Personalised D values**: each operator's memory shape is different. NEOTH's per-operator install means `D_mem`, `D_think`, `D_conv` are tuned to *this* operator, not a global average.

Mandelbrot would respect this only if we publish the log-log slopes per operator + show that adaptive behaviour at the measured `D` beats binary fast/slow. The bar is real, but reachable.

---

## Risk register

- **Premature optimisation**: ship EXP-FD-0 first; verify the slope is actually stable (`R² > 0.95`) before building anything that depends on it.
- **Buzzword regression**: every PR that touches `D_*` must include the log-log measurement in the commit body. If the slope isn't shown, the term "fractal" gets stripped from the diff.
- **D drift over time**: operator's communication style may shift. The dimension should be re-measured weekly via the existing cron scheduler, not assumed constant.
- **Cross-operator dimension comparison**: never do it. Each `D` is operator-local. Federation across operators (Block C #8) would need a fundamentally different model.

---

## Decision required from operator

Before EXP-FD-0 ships, operator confirms:
1. **Measurement target**: should `D_mem` be computed from byte counts, row counts, token counts, or embedding-cluster radii? Each gives a slightly different slope. Recommend byte counts as the simplest.
2. **Trigger cadence**: weekly (via cron) or on-demand (via CLI)? Recommend on-demand for v0.1, cron later.
3. **Failure mode if slope unstable**: `R² < 0.95` means the tiers aren't actually self-similar. Skip the feature for that operator, or fall back to a "hierarchical mode" without fractal claims? Recommend fall back, document the result.

---

**Bottom line**: the fractal lens is real where the slope is measurable and falsifiable. Five experiments queued — EXP-FD-0 first, the rest gated on its result. If the slope holds, NEOTH gets adaptive auflösung at every layer. If the slope doesn't hold, the framework is honest hierarchy and we don't ship marketing.
