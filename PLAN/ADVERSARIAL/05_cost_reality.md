# ADVERSARIAL-05: Cost Reality Check — NEOTH v1.0
**Date:** 2026-05-13  
**Analyst:** Claude Sonnet 4.6 (adversarial sub-agent)  
**Source data:** `00_DESIGN_v1.0_FINAL.md`, `SPEC_proactive_learning.md`, `SPEC_channels.md`, `SPEC_skill_plugin_system.md`, `SPEC_wal_lifecycle.md`, `tool_framework_v4_1.md`, `00_JARVIS_LIVE_TRUTH.md`

---

## Methodology

All numbers derived from spec files + observed Jarvis live state. Where specs state costs explicitly (e.g., `cost_budget_usd: 0.027` in `profile_learn.yaml`), those are used verbatim. Public API pricing used for overage estimates (Gemini 3.1 Pro: $1.25/1M in, $5.00/1M out; Claude Opus 4.7: $15/1M in, $75/1M out; GPT-5.5: ~$10/1M in, ~$30/1M out as proxy). Subscription pricing: Claude MAX $100/mo, ChatGPT Pro $200/mo, Google One AI Premium $19.99/mo.

**Jarvis baseline load:** 100 turns/day. Corroborated by 58 active cron jobs (avg 1.5 fires/day each) + interactive turns from JARVIS_LIVE_TRUTH cron listing.

---

## ROUND 1 — Concrete Daily/Monthly Cost Estimates

### 1.1 Subscription Floor

NEOTH uses CLI-OAuth-first across all three providers:

| Provider | Product | Cost/month |
|---|---|---|
| Claude Opus 4.7 | Claude MAX | $100 |
| GPT-5.5 (Callosum) | ChatGPT Pro | $200 |
| Gemini 3.1 Pro (Right) | Google One AI Premium | $19.99 |
| **Total floor** | | **$319.99/month** |

**Confidence: high.** These are public 2025/2026 prices. No volume discounts apply at single-user scale.

**What makes it lower:** Alex may already have Claude MAX. If so, subtract $100 — floor drops to $220.  
**What makes it higher:** GPT-5.5 may not be on ChatGPT Pro tier; could require API-only → add $0 in subscription but pay-as-you-go on every Council call.

---

### 1.2 Per-Turn Provider Cost (on-quota, CLI-OAuth)

At 100 turns/day on subscription: **$0 marginal per turn** — it's a flat-rate subscription.  
Effective per-turn "cost" = subscription amortized = **$319.99 / (100 × 30) ≈ $0.107/turn**.

Token load per main turn (Left hemisphere = Claude):
- Block A (SOUL.md + freedom.yaml): ~2k tokens
- Block B (profile inject): ~1k tokens  
- Block C (recall results): ~5k tokens
- Block D (session history): ~3k tokens
- Block E (user message): ~1k tokens
- **Total in: ~12k tokens | out: ~1k tokens**

This is within Claude MAX's flat-rate envelope for normal conversational cadence.

---

### 1.3 Profile Extraction (SPEC_proactive_learning.md)

**Trigger:** every `PROVIDER_RESPONSE` WAL event (0x0E). No sampling. No condition except `scope != SESSION_LEDGER_INTERNAL`.

**Model:** Right hemisphere = Gemini 3.1 Pro  
**Tokens:** ~2,500 in (conversation window + existing profile summary) + ~800 out  
**Stated cost:** $0.027/call (spec says "~800 tokens at Gemini 3.1 Pro")  
**Actual API cost calc:** (2500/1M × $1.25) + (800/1M × $5.00) = **$0.00713/call**

The spec overstates cost by ~4×, which means the `cost_budget_usd: 0.027` daily cap per Cerebellum is actually a *per-call cap*, not a per-day figure. This ambiguity is a spec defect.

| Metric | Value |
|---|---|
| Extractions/day (100 turns) | 100 |
| Daily Gemini calls for extraction | 100 |
| Daily cost (API fallback) | $0.71 |
| Monthly cost (API fallback) | $21.38 |
| On-quota (Gemini Advanced) | $0 marginal |

**Quota status:** 100 extraction calls + ~45 Council Gemini calls = **145 Gemini calls/day**. Gemini Advanced (AI Premium) has no published hard RPD cap but rate-limits exist per RPM. At 145/day spread across waking hours ≈ 1 call/6 min — should stay under rate limits. **However: no hard published guarantee.** If quota enforcement tightens (Google has done this before), all extractions fail simultaneously.

**Confidence: medium.** Quota is opaque on Google's side.

---

### 1.4 Council Debate

**Trigger:** keywords `[architecture, security, refactor, destructive, breaking]` OR complexity > 800 tokens OR dissent_score > 0.4.

**Critical observation:** Alex is a security researcher. The word "security" alone will trigger Council on nearly every security-research turn. At minimum 15% trigger rate, realistically 25-35% for Alex's workload.

| Metric | Conservative (15%) | Realistic (25%) |
|---|---|---|
| Council events/day | 15 | 25 |
| Rounds default | 3 | 3 |
| Participants | 3 | 3 |
| Total LLM calls/council | 9 | 9 |
| Tokens in/participant/round | ~14k (grows with rounds) | ~14k |
| Tokens out/participant/round | ~2k | ~2k |
| **Cost/event (API pricing)** | **$1.76** | **$1.76** |
| **Daily (API)** | **$26.44** | **$44.07** |
| **Monthly (API)** | **$793** | **$1,322** |

**On-subscription:** Council hits Claude MAX (claude-opus-4-7) for 15 events × 3 rounds = 45 additional heavy Claude calls/day, on top of 100 main turns = **145 Claude calls/day**. Claude MAX's 5-hour rolling window allows ~300 messages/window by current enforcement. 145 calls spread across ~16 waking hours = ~9 calls/hour = fine during normal cadence.

**During dev/test:** anti-pattern test stubs (spec Day 28-37), Day-30 acceptance test, adversarial runs → calls spike 3-5×. At 4× = 580 Claude calls/day → **Claude MAX quota wall hit by 14:00**.

**Cost at quota wall:** fallback currently undefined for quota exhaustion (see Round 2). Assume API fallback kicks in.

**Confidence: medium-high** for trigger rate; **low** for exact API pricing of GPT-5.5 (no public rate confirmed).

**What lowers it:** `early_stop_on_consensus: true` + `agreement_threshold: 0.66` means many councils resolve in 2 rounds, not 3. If 60% of councils early-stop: cost × 0.73.

---

### 1.5 Embedding (Qwen3-Embedding-0.6B-Q8, candle, CPU-local)

**Cost:** compute-only, no API. At ~80ms/embed × 100 embeds/day = 8 seconds CPU/day.  
**Power cost:** debian VM idle draw ~30W, 8 sec active = 0.00007 kWh = **$0.00002/day**. Negligible.

---

### 1.6 Disk Growth

| Source | Daily | Per Year raw | Per Year compressed (zstd_3 4:1) |
|---|---|---|---|
| WAL events (~750/day × ~2KB avg) | 1.6 MB | 0.57 GB | 0.14 GB |
| Vector blobs (1024d × 4B × 100/day) | 0.41 MB | 0.15 GB | — (uncompressed) |
| **Total** | **2 MB/day** | **0.72 GB/year** | **~0.29 GB/year** |

Assumption: 750 WAL events/day = 100 USER_MSG + 100 PROVIDER_RESPONSE + 100 profile_learn + ~300 profile delta events + ~150 council/session events.

**Confidence: medium.** Profile delta rate (3 fields/extraction) is speculative. Could be 10× if profile is dense.

---

### 1.7 Tailslayer Hugepages

Default in tailslayer-rs: `HugePageSize::Size1GiB`. For smaller setups: `HugePageSize::Size2MiB`.

**For NEOTH's use case (embedding/routing lookup table):**

| Use case | Per replica | 2 replicas |
|---|---|---|
| Routing/skill table (10k entries × 64B) | ~1 MB | ~2 MB |
| Embedding table (100k × 1024d × 4B) | ~400 MB | ~800 MB |

**Debian VM context:** openclaw-gateway currently uses 1.1 GB RSS. 2 context-mode Node processes at 100% CPU (stuck in `Rl`/`Sl`). If Tailslayer is used for embedding lookup with 2 replicas at 2 MiB page size: **+~800 MB locked RAM**, non-swappable (hugepages are locked by kernel). Total RSS after: ~2 GB for NEOTH stack alone, on top of existing Jarvis load.

Gemini reviewer already flagged: `"default-ON will hard-crash or fail to allocate on virtualized hosts that explicitly disable hugepages."` Debian VM on Tailscale — hugepage availability depends on hypervisor config. **No verification in spec.**

**Confidence: medium.** If hugepages fail silently, Tailslayer falls back or crashes — spec doesn't say which.

---

### 1.8 Monthly Total Summary

| Component | Low estimate | High estimate |
|---|---|---|
| Subscriptions (all 3 providers) | $220 (Alex has MAX) | $320 |
| API overage (10 heavy quota-hit days/mo) | $0 (quota never hit) | $272 |
| API overage (20 heavy days) | — | $543 |
| **Monthly total** | **$220** | **$863** |

**Realistic for Alex's usage pattern: $320–$600/month.**  
Annual: **$3,840–$7,200/year** in subscription costs alone, excluding API overages.

**RAM:** +800 MB locked hugepages (Tailslayer) + neothd baseline ~200 MB = **~1 GB new RAM on debian VM**.  
**Disk:** ~0.3 GB/year compressed.

---

## ROUND 2 — CLI-OAuth Quota Mechanics Under Stress

### 2.1 Gemini Quota Exhaustion Path

Profile extraction fires on every PROVIDER_RESPONSE. At 100 turns/day, Gemini sees 100 extraction calls + 15-25 Council (right-hemisphere) calls = **115-125 Gemini calls/day**.

Gemini Advanced (Google One AI Premium, $19.99/mo): quota is unpublished. Google's public documentation states "higher limits" than free tier but gives no numbers. Free tier: 1,500 RPD for Gemini 1.5 Flash (not 3.1 Pro). Gemini 3.1 Pro limits are not publicly documented.

**Known risk:** Google's RPM limits (requests per minute) are stricter than RPD. During a Council event, 3 rounds × right-hemisphere = 3 Gemini calls in ~60 seconds. If RPM = 60 for Gemini Advanced, 3 calls in 60 sec = fine. But during a dev sprint with 5 concurrent test runs → 15 calls/minute → likely RPM-throttled.

**What happens at quota exhaustion?** The spec's cascade (`claude → codex → gemini → qwen-local`) is defined for **refusal/error**, not explicitly for **429 RateLimitError / quota exhaustion**. The `on_refusal: mirror_pipeline` path in `profile_learn.yaml` triggers on refusal — a 429 is not a refusal. **There is no documented handler for HTTP 429 on the extraction pipeline.** This means profile extraction silently fails or crashes the pipeline on quota hit.

**Confidence: high** that this gap exists. **Confidence: medium** on when quota actually triggers.

---

### 2.2 Council Quota Drain — All 3 Providers Simultaneously

Council runs `execution_model: parallel_per_round` — all 3 providers fire in parallel per round. So one council event drains:
- 3 Claude calls (left × 3 rounds)
- 3 Gemini calls (right × 3 rounds)  
- 3 GPT-5.5 calls (callosum × 3 rounds)

All three subscription quotas drain **simultaneously** on every council event. At 15 council events/day × 3 rounds: **45 calls from each provider's quota per day**, on top of normal usage.

**Day-28-37 anti-pattern test stubs:** spec calls for real LLM calls to verify determinism. If test suite runs 10× during a dev day, council triggers multiply by 10 → **450 Claude Opus calls in one day** from testing alone. Claude MAX will hit its 5-hour rolling window cap before tests complete.

**No fallback for this scenario is specified.**

---

### 2.3 Day-30 Acceptance Test

Spec: "10k events insert + 10 queries." If those events are REALISTIC (have embeddings), that's:
- 10k local embed calls (candle, ~80ms each = **~13 minutes CPU** — fine)
- 10 recall queries (keyword + cosine) — LLM-free per Phase 1 spec
- 10 response generations (Left hemisphere = Claude Opus) = 10 more Claude calls

The test itself is manageable. **The risk is cumulative**: if the test is re-run 5× during debugging, it's 50 Claude calls just from test reruns. Combined with a normal dev day, this is containable.

**Confidence: high** that Day-30 test alone won't blow quota. Dev cycle reruns might.

---

### 2.4 Quota Exhaustion Mid-Session: Unhandled

The spec defines cascades for refusal (G.6, SPEC_mirror_refusal.md) but **not for HTTP 429 / quota exhaustion**. This means:

- Main turn: Claude MAX quota hit → Left hemisphere call fails → no response to user. Cascade defined for error? Unclear. Provider-cascade in MEMORY.md (Jarvis) handles it: `claude → gemini → kimi-k2 → cerebras`. NEOTH's cascade: unclear if it triggers on quota error vs. network error vs. refusal.
- Profile extraction: Gemini 429 → `on_refusal: mirror_pipeline` won't trigger (not a refusal) → silent failure or unhandled exception → WAL event for profile_learn never completes → Hypothalamus region goes dark for remainder of day.
- Council: any participant 429 → council round incomplete → verdict synthesis has 2 responses not 3 → majority_vote undefined behavior with even participant count.

**This is a correctness hole, not just a cost hole.**

---

## ROUND 3 — Costs Not In Spec

### 3.1 Operator Time Cost

| Phase | Spec says | Realistic estimate | Hours |
|---|---|---|---|
| Phase 1 (MVP) | Day 1-30 | Day 1-45 (architect review confirmed) | 225h |
| Phase 2 (16 features) | Day 31-60 | Day 46-135 (90 days) | 450h |
| Phase 3 (cutover) | Day 61-90 | Day 136-210 (75 days) | 375h |
| **Total** | **90 days** | **210 days** | **~900-1050h** |

Phase 2 features listed in session history: WhatsApp + Slack + WASM + Right Hemisphere full + Callosum + Council + Mirror-Refusal + IVF + DSPM + REINFORCE + SESSION_LEDGER + Tailslayer + concept-vocab + profile-extraction. **14 major systems in 30 days = impossible at solo pace.**

At 5h/day solo:
- At €80/hr opportunity cost: **€72,000–€84,000 sunk developer time**
- At €150/hr (security researcher billable rate): **€135,000–€157,500**

**Confidence: medium.** Timeline is fundamentally a solo-capacity constraint. Phase creep is observed across all NEOTH versions (v0.1 through v1.0 = 8 months already spent on design alone).

---

### 3.2 Cognitive Complexity Tax

Current spec surface: 9 spec files, 6 brain regions, 5 LLM roles (Left/Right/Callosum/Council/Extractor), 1 plugin system (WASM), 1 skill system (YAML), multi-node HLC clocks, WAL lifecycle with 5 disk-pressure states, 96-byte binary header with CRC32c + HLC + xxh3-64, REINFORCE feedback loop, 12 pipeline types.

This complexity has **already caused**:
1. v0.1 → v1.0 design churn: 8 versions in ~6 months (observed from git history and file naming)
2. Claude v0.7 review → 10 blockers reopened → v0.8 → v0.9 → v1.0 = rename without fixing blockers
3. Codex review flagged "magic orchestration" (G.5, G.10, G.12) — still unresolved in v1.0 (v1.0 is rename-only per spec)

**Alternative baseline:** a 2-file design (SQLite WAL + single Claude provider + keyword recall) could deliver 70-75% of NEOTH's core value (persistent memory, recall, profile injection) in 2-3 weeks. The remaining 25-30% (Council, multi-node, WASM plugins, 6-region brain) buys marginal return for 10× more complexity.

**Confidence: high** that complexity is the primary delivery risk. This is not an estimate — it's observable from the design history.

---

### 3.3 Vendor Lock-In Cost (CLI-OAuth Fragility)

CLI-OAuth depends on reverse-engineering or scraping the authentication flows of:
- `claude` CLI (Anthropic's binary) — no public auth spec
- `codex` CLI (OpenAI) — no public auth spec
- `gemini` CLI (Google) — no public auth spec

**Fragility events that have already occurred in Jarvis:**
- `cron */5 pkill -9 openclaw-channels` = Workaround for orphan CLI processes
- `*/2 stuck-session-autokill.sh` = CLI hangs requiring external kill
- `03:30 nightly gateway restart` = memory leak mitigation
- CLI-OAuth tokens rotate → all stored sessions invalid → re-auth required manually

If any provider changes their CLI binary auth flow (common: Anthropic has done this multiple times with Claude Code), **NEOTH's provider integration breaks completely**. API keys don't have this failure mode.

**Migration cost if one provider breaks CLI-OAuth:** estimate 3-5 days of debugging + re-implementation per provider. If it happens twice/year = 6-10 dev days = 30-50 hours = **€2,400–€7,500/year in break-fix time** (at €150/hr).

**Confidence: high** that CLI-OAuth will require break-fix work. Jarvis LIVE TRUTH documents it already happening.

---

### 3.4 Future-Self Tax: Phase 2 Scope Is 3× Underestimated

Phase 2 (spec: Day 31-60, 30 days) contains:
- WhatsApp adapter (webhook, signature verify, attachment queue)
- Slack adapter (same)
- WASM runtime (wasmtime integration, plugin sandbox, ABI)
- Right Hemisphere full integration (not just profile extraction)
- Corpus Callosum full integration
- Council pipeline fully operational
- Mirror-Refusal pipeline fully operational
- IVF (Import Vector Format for migration)
- DSPM (Data Sensitivity/Privacy Matrix)
- REINFORCE feedback loop
- SESSION_LEDGER
- Tailslayer integration
- Concept-vocab system
- Profile-extraction full (Day 38-42 specifically)

**14 systems in 30 days = 2.1 days per system.** Each is a non-trivial Rust module with tests, WAL integration, and CLI-OAuth provider calls. The WASM runtime alone (wasmtime + safe ABI) is a 2-3 week project.

**Realistic Phase 2 duration: 90+ days.** Phase 3 starts 60 days late from Day 1.

**Cost of lateness:** Jarvis continues running on its current fragile stack (12 stores, kill-crons, memory leaks) while NEOTH is being built. Every month of delay = one more month of Jarvis operational debt.

---

### 3.5 Opportunity Cost vs Existing Memory-Agent Frameworks

| Framework | Maintenance | Memory model | Build cost to customize | NEOTH equivalence |
|---|---|---|---|---|
| **Letta** (formerly MemGPT) | Active, YC-backed | Archival + in-context + recall | 2-4 weeks to customize | ~70% of NEOTH features |
| **Cognee** | Active | Knowledge graph + vector | 1-2 weeks | ~60% (missing council) |
| **Mem0** | Active, API-based | Multi-level memory | Days (managed API) | ~50% (no local WAL) |
| **NEOTH from scratch** | Alex solo | WAL + 6 brain regions + council | 6-9 months | 100% but delayed |

**Concrete comparison:** Letta (open-source, self-hosted) already provides: persistent memory, tool use, multi-model support, recall search, profile injection. Customizing Letta to match NEOTH Phase-1 scope ≈ **2-3 weeks** vs. 45 days for NEOTH Phase 1. The delta buys: Alex's custom WAL binary format, council pipeline, WASM plugin system — all Phase 2+ features.

**The question isn't "should NEOTH exist?" — it's "should all features be built from scratch simultaneously?"**

**Confidence: high** that Letta/Cognee already solve 60-70% of the stated problem.

---

### 3.6 NEOTH vs Jarvis: Replace or Parallel?

The spec (RUNBOOK_phase3_cutover.md exists) implies cutover, not parallel. But Phase-3 cutover has:
- 14-day shadow run (NEOTH responds but Jarvis stays primary)
- Parity check methodology (SPEC_recall_parity_methodology.md)
- YubiKey/TOTP gated cutover

**If run in parallel during Phase 1-2 (90 days):** debian VM runs both stacks. Current Jarvis: openclaw-gateway (1.1 GB) + 2 context-mode procs (100% CPU stuck) + 12 memory stores. Adding NEOTH: neothd (~200 MB) + Tailslayer hugepages (~800 MB locked). Total additional: **~1 GB RAM + background WAL writes competing with inotify vault-watcher**.

**Risk:** Jarvis already has stuck processes and autokill crons. A second heavy Rust daemon writing WAL events at 2 MB/day alongside 12 existing memory stores = increased I/O contention on the single debian VM.

**If replace early (before parity is proven):** Alex loses Jarvis's working memory (Obsidian sync, 1014 embedded files, hippocampus curated notes) during the gap.

**Confidence: high** that the 14-day shadow run will take 30+ days due to parity failures requiring NEOTH fixes.

---

## Summary: 3 Biggest Cost Shocks Not Anticipated in Spec

### Shock 1: Subscription floor is $320/month regardless of usage
The spec frames CLI-OAuth as a cost-saving strategy. But three provider subscriptions at Claude MAX + ChatGPT Pro + Gemini Advanced = **$320/month fixed**, before a single production turn runs. This is higher than a moderate API-pay-as-go usage pattern for Alex's actual 100 turns/day:
- Claude Opus via API at 12k in + 1k out × 100 turns/day × 30 days = (360M/1M×$15) + (3M/1M×$75) = $5,400 + $225 = **$5,625/month at API pricing** — far more than subscriptions.
- But with profile extraction (145 Gemini calls/day via API): $21/month.
- So subscriptions ARE the right call — but $320/month is the floor, not zero.

### Shock 2: Council auto-triggers on "security" destroy the quota budget in week 1
The trigger keyword list includes `security`. Alex's primary domain is security research. At 25-35% trigger rate (realistic), Council runs 25-35 times/day, each consuming 9 LLM calls across all 3 providers in parallel. During Phase 2 dev when anti-pattern tests are running, this multiplies 3-5×. **The quota wall will be hit on Day 1 of Phase 2 testing**, likely before breakfast. The spec's `usd_max: 0.50` council budget cap only works if API pricing is active — on CLI-OAuth subscriptions, there's no circuit breaker.

### Shock 3: 900 hours of solo Rust dev at €80-150/hr = €72k-135k opportunity cost for a system 60-70% achievable by forking Letta in 2-3 weeks
The design history (v0.1 → v1.0 = 8 versions, 6+ months) shows the cost of perfectionism under complexity. The spec's Phase 2 (30 days, 14 features) is structurally impossible at solo pace. Every day Phase 1 overruns = one more day Jarvis's fragile stack runs unimproved. The net "build from scratch" premium over "fork Letta + customize" is **5-7 months of solo time** — for WAL binary format purity, council pipeline, and WASM plugins. These are real architectural wins, but the time-cost is not acknowledged in the spec.

---

## Mitigation Options

| Cost shock | Mitigation | Cost of mitigation |
|---|---|---|
| $320/month subscription floor | Drop ChatGPT Pro ($200) — use GPT-5.5 via API only when council fires, not subscription | Saves $200/mo; adds $0.50-2.00/council event at API rates |
| Council quota drain | Remove "security" from auto-trigger keywords; add domain qualifier (e.g., "architecture security" as bigram) | Zero cost; spec change only |
| Council quota drain | Add 429-handler → council degrade to 2-participant (left + right only, drop callosum) when GPT quota hit | 1-2 days dev |
| Profile extraction quota | Add jitter + backoff on 429; skip extraction (not error) when Gemini quota hit; profile learning resumes next turn | 1 day dev |
| Operator time | Phase-gate Phase 2: ship 3 features per 30-day sprint, not 14. Council is Phase 3, not Phase 2. | No cost; scope discipline |
| Vendor lock-in | Add abstraction layer: `ProviderAdapter` trait in Rust so CLI-OAuth and API-key are interchangeable at runtime | 3-5 days dev; already implied by Framework v4.1 |

---

*All estimates are point-in-time as of 2026-05-13. Pricing, quota caps, and feature scope can change. Confidence levels (low/medium/high) indicate sensitivity to assumptions.*
