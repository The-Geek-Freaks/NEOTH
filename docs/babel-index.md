# Babel-Index — collapse prediction on NEOTH's own runtime

NEOTH ships an instrument that measures whether NEOTH itself is degrading.

Agent systems fail in recognizable shapes: retry storms, agent loops, context
death spirals, tool-timeout cascades, semantic drift. Most frameworks let you
discover these in the post-mortem. NEOTH watches its own WAL event stream,
scores every rolling window with seven collapse variables, and warns you
**before** the failure — then lets you (optionally, off by default) contribute
anonymised measurements to an open research pool that tests whether the
underlying collapse model holds across instances.

The model comes from
[delta-kosmologie](https://github.com/The-Geek-Freaks/delta-kosmologie), an
open RDelta/Babel-Index framework for collapse dynamics in LLM agents and
world-systems. NEOTH implements the agent-side half of the
NEOTH ↔ delta-kosmologie federation protocol.

Quick taste:

```bash
neoth babel status        # enabled flag, threshold, epsilon, latest scores
neoth babel windows --n 10
neoth babel label <window_id> agent_loop
neoth babel export --out babel.jsonl
neoth babel federate      # prints federation state (OFF by default)
```

## Design constraints

The observer is deliberately boring where it must be:

- **Async-only.** It never blocks inference, tool calls, or routing. Feature
  extraction happens off the hot path; the in-process response histogram feed
  drops on backpressure rather than waiting.
- **Content-free.** Only derived metrics leave the extractors — never prompts,
  never responses. Session ids are HMAC pseudonyms keyed by your local WAL
  key; no raw id exists in the stored rows to leak.
- **Consent-first.** Observation is local. Federation is a separate, explicit
  opt-in (`babel.federate = true`) that additionally requires
  `AutonomyLevel >= Elevated` and calibration maturity at runtime.
- **Pre-registered.** Collapse label definitions are deterministic functions
  of the event stream, frozen before data collection. Changing them after the
  fact must be declared as exploratory analysis. Every federated record
  carries its `algorithm_versions` so between-version sensitivity analysis is
  possible.

## The seven variables

Each 5/15/60-minute window gets seven normalised features, extracted from WAL
band codes:

| Variable | Meaning | Source events |
| :-- | :-- | :-- |
| `C_d` | Tool/agent coupling density | `0xC0 MCP_TOOL_CALLED`, `0xFC AGENT_DISPATCHED` |
| `K_d` | Semantic convergence pressure (are outputs collapsing toward sameness?) | `0x20/0x21` output-token histograms |
| `M_d` | Resource/context pressure | context-used ratio, VRAM %, budget caps |
| `A_d` | Autonomous agent density | distinct dispatched agents × autonomy scalar |
| `V_d` | Throughput headroom | tokens/sec vs. p99 norm |
| `D_d` | Diversity/schema divergence (buffer) | tool schema conflict events |
| `H_d` | Redundancy of fallback routes (buffer) | fallback attempt/result events |

`C/K/M/A/V` are **amplifiers** — pressure toward collapse. `D/H` are
**buffers** — slack that absorbs it.

## The score

Three candidate forms are computed and stored per window; the log form is the
primary discriminator for pooled falsification:

| Form | Definition | Notes |
| :-- | :-- | :-- |
| `B_log` | `Σ log(C,K,M,A,V) − log(D) − log(H)` | Primary. No epsilon. Undefined (NULL) until all amplifiers are warm. |
| `B_mult` | `norm((C·K·M) / ((D/A)·(H/V) + ε))` | ε = `0.01 · median((D/A)·(H/V))`, frozen at the first 50-window calibration batch. Value **and** governance rule ship in every federated record. |
| `B_bottleneck` | `min(C,K,M,A,V) / max(D,H)` | Weakest amplifier over strongest buffer; used for local fitness verdicts. |

A 15-minute threshold breach raises a warning in the daemon log and on the
GUI SSE feed — an operator-visible signal, not a silent metric.

## Collapse labels

Eight canonical labels, each a deterministic rule over the window's events
(v0, frozen 2026-07-02):

| Label | Detection rule (v0) |
| :-- | :-- |
| `agent_loop` | ≥3 identical (tool, agent) retries within 60 s |
| `retry_storm` | >5 retries per 30 s across all agents |
| `tool_timeout_cascade` | timeouts across >3 distinct tools in the window |
| `context_limit_failure` | context ≥95 % followed by a context/truncation error |
| `semantic_degradation` | `K_d > 0.90` for 3 consecutive 5-minute windows |
| `fallback_failure` | fallback attempted, no success within 60 s |
| `objective_failure` | operator-labelled via `neoth babel label` |
| `tool_selection_failure` | schema-conflict variant (subsumed by cascade in v0) |

A post-hoc pass stamps every window with "did a collapse start within the next
30 minutes?" once the horizon is fully observed — that stamped history is what
the predictor trains against. Operator confirmations ratchet **up** only: a
machine re-pass never demotes a human label.

## Self-calibration

The prediction threshold tunes itself against its own stamped history: false
positives raise it by 0.01, false negatives lower it, clamped to
`[0.05, 0.95]`, with a Brier score reported per round so the accuracy claim is
measurable rather than asserted.

Firewall: calibration adjusts an **in-memory working threshold only**.
`babel.threshold` in `freedom.yaml` remains the operator's anchor; a restart
returns to it. The system never rewrites an operator-tunable.

Babel also feeds NEOTH's self-improvement loop locally: every accepted
capability change is assessed by comparing median `B_bottleneck` two hours
before vs. after the change. A regression flags the change for operator
attention — advisory only, nothing auto-reverts.

## Federation (opt-in, fail-closed)

Sharing is **off by default** and stays off until three conditions hold at
runtime: `babel.federate = true`, `AutonomyLevel >= Elevated`, and calibration
maturity. Then, and only then:

- Only windows with a fully-observed collapse horizon are eligible (no
  unlabeled noise), downsampled with a documented sampling rule.
- Records are anonymised (HMAC-pseudonymised session ids, content-free
  derived metrics, algorithm versions attached).
- Each batch is gzip JSONL, Ed25519-signed with your node key over the
  payload hash, and written durably to a local pending directory **before**
  being marked submitted — crash-safe, no double-submit.
- Delivery runs async off the hot path; failures stay pending locally.

The reverse direction is firewalled harder. A pooled predictor downloaded
from the aggregator is:

1. **Advisory by construction** — no code path exists from pool data to the
   local threshold; it can only produce a log/SSE note.
2. Gated by the **same consent gate** as submitting — a non-opted-in instance
   never even parses pool data.
3. **Domain-checked** — anything not `neoth` is rejected outright.
4. **Signature-pinned** — verified against the operator-pinned aggregator
   public key; no pin, no parse, fail-closed. The cache stores the signed
   envelope and re-verifies on every load.

Inspect everything:

```bash
neoth babel status                 # includes federation state
neoth babel export --out out.jsonl # exactly what a federated record contains
neoth babel federate --disable     # one command out
```

Or turn the whole observer off: `neoth babel disable`
(`babel.enabled = false` in `freedom.yaml`).

## Why this matters

Two reasons, one practical, one bigger:

**Practical:** an assistant that runs unattended jobs, agents, and channels
needs a health instrument for its own cognition. "The agent got stuck in a
loop overnight" should be a warning you received, not a log you excavate.

**Bigger:** whether one scalar family can predict collapse across very
different complex systems is a real, falsifiable research question. NEOTH
instances that opt in become measurement points for it — with pre-registered
definitions, versioned algorithms, signed records, and an open protocol.
That is the delta-kosmologie bet, and NEOTH is its first production
instrument.

## Related

- [delta-kosmologie](https://github.com/The-Geek-Freaks/delta-kosmologie) — the upstream framework and falsification protocol
- [privacy.md](privacy.md) — the wider privacy model Babel operates under
- [cli-commands.md](cli-commands.md) — generated `neoth babel` reference
- [architecture.md](architecture.md) — where the observer sits in the daemon
