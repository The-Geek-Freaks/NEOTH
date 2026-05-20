# AGENTER Design v0.4 — Independent Architecture Review

Date: 2026-05-12 | Reviewer: claude-sonnet-4-6 (architect agent)
Sources: 00_DESIGN_v0.4.md · tool_framework_v4_1.md · 00_JARVIS_LIVE_TRUTH.md · 03_CHORUS_SYNTHESE.md

---

## 1. Framework Conformance (G.1–G.13)

| Anti-Pattern | Verdict | Finding |
|---|---|---|
| G.1 Stateful Tool | Compliant | All state externalized to WAL. Tool schema is stateless per call. |
| G.2 Self-Modifying Tool | Compliant | No runtime YAML mutation mechanism. |
| G.3 Goal-Seeking Tool | Compliant | Goals in `idx_goal` WAL view, not in tools. |
| G.4 Meta-Decision-Making Tool | **Borderline** | `brain_metadata.invoked_by: [left_hemisphere]` implies hemisphere-enforcement with unspecified location. Tool-side = G.4 violation. Router-side = compliant. Must be resolved before code. |
| G.5 Emergente Tool-Komposition | Compliant | All composition explicit in Pipeline YAML. |
| G.6 Refusal-Umgehung | Compliant | `refusal_handling.mode: mirror` enforced at tool level. |
| G.7 Scope-Inflation | Compliant | Single-responsibility visible in tool definitions. |
| G.8 Starke Emergenz | Compliant | No adaptive state in tools. |
| G.9 Black-Box | Compliant | `introspection:` block present in tool spec. |
| G.10 Magic Scale | Compliant | No emergent-from-scale claims. |
| G.11 Closed-Loop Ecology | Compliant | Schicht 2 deferred to Phase 4. Dreaming writes WAL via Schicht-1 pipeline — correct. |
| G.12 Level-Confusion | **Borderline** | (1) `corpus_callosum_check` uses inline `if_dissent_score > 0.4: trigger:` — not a Framework Teil-C valid stage construct. (2) `council_debate.yaml` introduces `execution_model: parallel_per_round` and `loop_while:` — neither is Framework-defined. Schicht-1 logic embedded as non-standard YAML is Level-Confusion. |
| G.13 Bateson-III-Claims | Compliant | No autonomy claims. Hemispheres are role-bound. |

---

## 2. Brain-Anatomy Coherence

**Enforces real constraints (3 of 13 regions):**

- Left hemisphere = output monopoly. Testable. Prevents conflicting user responses — the root cause of Jarvis's multi-service divergence.
- Amygdala = importance decay heap. Clear contract: importance-scoring lives here. Maps to Jarvis hippocampus-threshold model.
- Insula = council-rounds view. Council state isolated; prevents metadata leaking into episodic recall.

**Require policy to enforce (2 regions):** Cerebellum (provider stats) needs a single-writer policy; Basal Ganglia (tool-router cache) needs promotion/demotion policy tied to WAL events — otherwise it is a frequency table with no Selektion mechanic.

**Cosmetic (8 regions):** BrainStem, Pineal, MirrorNeurons, MedialTemporal, DefaultMode, Thalamus, PrefrontalCortex, Cortex — correctly named but the metaphor adds no constraint beyond what the underlying implementation would have. The `brain_region: u8` WAL tag is dead metadata without a Query-Planner routing policy that uses it. Either spec region-aware recall routing or drop the tag. Minor inconsistency: header says "12 memory layers," table has 13 regions.

---

## 3. Schicht-Discipline: Council

Council at Schicht 1 (Pipeline) is correct. Council holds round-state across multiple LLM calls — Framework A.1 transient session state. Council-as-Tool violates G.1 + G.3. Council-as-Ecology violates the read-only rule. `council.score_responses` + `council.synthesize` are pure functions — G.4 compliant.

---

## 4. Hard-to-Vary Core: Verdict

| Item | Verdict | Reasoning |
|---|---|---|
| 1. WAL as single truth | Hard-to-vary | Removing means no reproducible views — Jarvis 12-store drift returns. |
| 2. Tools stateless + deterministic | Hard-to-vary | Re-introduces the exact problem AGENTER solves. |
| 3. Pipelines declarative + budget-bound | Hard-to-vary | Without declarativity = procedural + untestable. |
| 4. Left hemisphere = sole output channel | Hard-to-vary | Breaks conflict-prevention guarantee. |
| 5. Refusal = Mirror not Transform | Soft | Policy choice. |
| 6. Schicht-Disziplin | Hard-to-vary (redundant) | Framework F.8 Kern-Element 2 restated. |
| 7. CRC32c + Magic + Schema-Version | Soft | WAL format detail. |
| 8. Konzept-First > Spec-First | Soft | Process rule. |

4 of 8 genuinely hard-to-vary.

---

## 5. Phase-1 Realism — Underestimated Steps

| Step | Claimed | Realistic | Why |
|---|---|---|---|
| 1.0 Skeleton + YAML loaders + WAL | 2d | 5d | Framework YAML schema (populations/introspection/health-check/locality) non-trivial Rust deserialization. |
| 1.1 Brain topology + 3 LLM CLI-OAuth adapters | 3d | 8–10d | claude-code/codex-cli/gemini-cli each have different auth flows. |
| 1.4 WAL + 13 views + Tailslayer | 5d | 12d | 13 index structures. tailslayer-rs v0.1.0 needs integration testing. |
| 1.6 Context-Engine / Query-Planner | 4d | 10d | Hybrid query (vec_sim + category + ts + importance) is the most drift-prone Jarvis component. |

**Dependency inversion:** Dreaming (1.3) before Memory Engine (1.4). Dreaming writes to views that do not exist yet. `idx_council` (Insula) depends on Council (1.7).

**Deferrable to Phase 2:** Dreaming-Pipeline, full Council, vault_sync, 9 of 13 brain-region views.

**Minimum MVP:** WAL + `idx_episodic` + `idx_semantic` + left-hemisphere response via Claude CLI + Telegram channel.

---

## 6. Cherry-Pick Verification

| Source | Verdict | Finding |
|---|---|---|
| openclaw memory-host-sdk, dreaming, context-engine | Correctly borrowed | Structurally aligned. |
| hermes-webui compression-anchor, goals, session-recovery | Correctly borrowed | Patterns map. |
| openhuman OAuth-vault, typed-tools | Correctly borrowed | YAML-spec tool format maps to Framework B.5 without distortion. |
| Framework v4.1 3 Schichten, patterns | Mostly correct, one gap | Tool populations + pipeline budget ported. **Gap:** Framework Teil-C `conditions:` block bypassed by inline `if_dissent_score > 0.4:`. `execution_model` extended informally by `parallel_per_round` / `loop_while:` without updating framework spec. |

---

## 7. Top-5 Must-Fix Before Code

**1. Specify hemisphere-binding enforcement location.** Move to Pipeline-Router at dispatch time. Tool must be unaware of caller identity. Add to spec: "Router checks hemisphere binding before dispatching; tool has no caller context."

**2. Fix dependency inversion in Phase-1 ordering.** Required: Memory Engine (1.4) → Dreaming-Pipeline (1.3). Document `idx_council` depends on Council (1.7).

**3. Fix non-conformant Pipeline YAML syntax.** Move `if_dissent_score > 0.4:` into proper `conditions:` block. Either extend Framework spec for `parallel_per_round`/`loop_while:` or restructure council rounds as tick-gated stages with loop-controller tool.

**4. Define region-aware recall routing policy or drop the WAL brain-region tag.** Spec which recall query types filter by region, or remove the tag (view-membership encodes region implicitly).

**5. Define 30-day hard MVP cutoff.** "By Day 30: daemon receives Telegram message, recalls from 2 WAL views, generates left-hemisphere response via Claude CLI-OAuth, sends it back." Everything else explicitly Phase 2.

---

*End of review.*
