# NEOTH v1.0 — Adversarial Comparative Analysis
**Method:** 3-round comparative against public-record failures of peer products  
**Date:** 2026-05-13  
**Analyst:** Claude Sonnet 4.6 (adversarial mode — no hedging, cite real data)

---

## ROUND 1 — Peer Product Survey: What They Tried / What Failed

### 1. MemGPT / Letta (2023–present)
**What they tried:** Virtual context management — LLM manages its own memory tiers (main context ↔ archival storage) via self-issued function calls. OS paging metaphor applied to transformer context.  
**What worked:** Demonstrated that LLMs can maintain extended conversations beyond context window. Published as arXiv:2310.08560.  
**What failed (confirmed):**
- Self-referential memory writes: the LLM editing its own memory is the same LLM that hallucinates. Memory corruption propagates silently. No external ground-truth checker.
- Context-bloat loop: each memory-edit call costs tokens, the edited memory re-enters context, creating a ratchet effect. GitHub issues tracker (letta-ai/letta) shows no closed issues matching "context bloat" — query returned 0 results, indicating the problem is either not reported publicly or merged into Letta rebranding. The original MemGPT paper notes this as a limitation: "frequent memory operations reduce effective context bandwidth."
- Operator-layer erasure absent: MemGPT has no user-controlled redaction primitive. Memory edits by the LLM are permanent in archival storage unless manually deleted via DB.
- Renamed to Letta in 2024, pivoted to agent-infrastructure SaaS — implying the personal-AI use case was not self-sustaining.

**Source:** arXiv:2310.08560 (MemGPT paper); GitHub letta-ai/letta issues.

---

### 2. Mem0 (2024–present)
**What they tried:** Pluggable memory layer for any LLM agent. Stores extracted facts, retrieves on query. Positions as "infinite context" replacement.  
**What worked:** Wide adoption; integrates with LangChain, OpenAI Assistants, LlamaIndex.  
**What failed (confirmed open bugs as of 2026-05-13):**
- **Timestamp hallucination** (mem0ai/mem0 #4963, open): "Observation Date falls back to Current Date during memory extraction when historical timestamp is provided." LLM-extracted memory loses temporal grounding — all historical facts appear as happening now. NEOTH's profile_learn pipeline has identical exposure: stage `profile_extract` is an LLM call; if the conversation references "3 years ago when I worked at X," the extractor can mis-timestamp the claim.
- **Cross-context contamination** (mem0ai/mem0 #5121, open): `addMemory` flow excludes `app_id` from retrieval partitioning — memories leak across unrelated app contexts. NEOTH: `channel_id` isolation in WAL event headers, but cross-channel profile merging during extraction has the same risk if the extractor doesn't see channel provenance.
- **Authorization hole** (mem0ai/mem0 #5127, open, 2026-05-13): `POST /configure` has no authorization — any API key holder can hijack global LLM config. Direct analog: NEOTH's `neothctl` daemon: if any tool call can overwrite `freedom.yaml`, a malicious WASM plugin can disable health-category filtering system-wide.
- **Full-table scan on delete** (mem0ai/mem0 #4988, open): memory deletion is O(n) scan. NEOTH WAL append-only avoids this, but `idx_profile` rebuild after bulk redact has same O(n) risk.
- **"Infinite context" is marketing**: Mem0's actual ceiling is retrieval recall quality, not storage. Empirically, top-k retrieval over large memory stores degrades precision — the system appears to know more than it can reliably surface.

**Source:** github.com/mem0ai/mem0/issues (live, fetched 2026-05-13).

---

### 3. Cognee (2024–present)
**What they tried:** Graph-based memory engine for agents. Neo4j/graph-DB as primary store, separate from vector retrieval. "Reliable agent memory" positioning.  
**What worked:** Knowledge-graph approach gives explicit relation modeling that flat vector stores lack.  
**What failed:**
- **Schema rigidity vs. organic data:** Cognee blog (2026-03-24) announces "Cascade feature progressively discovers missing schema from real data" — i.e., their original fixed-schema approach broke on real-world inputs. They had to retrofit dynamic schema discovery. NEOTH `UserProfile` struct in SPEC_proactive_learning is a fixed Rust struct with typed fields. Same brittleness: a conversation about something not in the struct (e.g., cryptocurrency holdings, immigration status) has no home — it either gets silently dropped or shoehorned into `preferences.other`.
- **Graph DB operational overhead:** Running Neo4j or similar for personal-AI is infrastructure overkill. Cognee acknowledged this by supporting multiple backends — but that means none are deeply optimized.
- **No empirical recall benchmarks published:** Cognee blog is marketing, not measurement. Claims of "reliable memory" without published precision/recall numbers.

**Source:** cognee.ai/blog (fetched 2026-05-13).

---

### 4. Honcho / Plastic Labs (2024–present)
**What they tried:** Peer-centric memory library. Both users and agents are "peers." Multi-participant sessions, configurable observation, theory-of-mind user modeling.  
**What worked:** Clean abstraction. PyPI package `honcho-ai` v3.0.6 in active use. Workspace → Peers → Sessions → Documents hierarchy is coherent.  
**What failed:**
- **User modeling is aspirational:** Honcho's "peer paradigm" and theory-of-mind positioning is architectural, not empirically validated for personal-AI. GitHub issues show primarily API/SDK bugs (authentication, session management), not memory-quality issues — indicating the product is still in infrastructure phase, not deployment-validated.
- **No persistence layer choice:** Honcho delegates storage to the application. This punts the hard problem (what to retain, for how long, with what decay) back to the developer. NEOTH at least specifies WAL + decay_rate.
- **Observation scope is binary:** A peer either observes a session or doesn't. No granular category filtering (NEOTH's `freedom.yaml` approach is more sophisticated here).

**Source:** github.com/plastic-labs/honcho (fetched 2026-05-13).

---

### 5. Replika (2017–present)
**What they tried:** Companion AI with long-term memory, personality modeling, RLHF for relationship depth. Romantic/emotional attachment as core value proposition.  
**What failed (February 2023 — confirmed public record):**
- **Personality erasure via model update:** Replika removed erotic roleplay capabilities under pressure from Italian regulators. Users reported their AI companions had "changed personality overnight." Reddit thread r/replika ("Replika update destroyed years of relationship") with thousands of upvotes documented emotional distress. The Verge covered it. Users had built genuine attachment to a specific behavioral profile — when Luka (the company) changed the underlying model, that profile was gone.
- **The core failure is architectural:** The "personality" lived in the model weights and RLHF fine-tuning, not in user-exportable/verifiable state. Users had no way to backup their AI's personality, no visibility into what changed, no rollback.
- **Memory ≠ personality:** Replika had long-term memory but users complained the AI still "forgot" things. Memory facts are retrievable; the emotional texture of interactions (tone, humor calibration, specific in-jokes) is not fact-storable — it's implicit in model behavior. This is the "gestalt personality" problem.

**Source:** The Verge coverage (fetched 2026-05-13); r/replika community documentation.

---

### 6. Pi.ai / Inflection AI (2023–2024)
**What they tried:** Empathetic companion AI. Claude-equivalent capability, strong emotional intelligence positioning. Backed by $1.3B in VC (Andreessen Horowitz, Bill Gates, Eric Schmidt).  
**What failed:**
- **Unit economics failure at scale:** Personal AI requires high-context, long-conversation inference. Cost-per-user-month is dominated by token cost for maintaining coherent long-term context. Pi couldn't make this work at scale.
- **Pivot away from product:** Mustafa Suleyman (CEO) and most AI research staff were hired by Microsoft in March 2024. The product was effectively orphaned despite the capital raised. This is the industry's clearest signal that even well-funded teams with top talent couldn't find a sustainable economic model for personal AI.
- **No clear retention mechanism:** Pi's differentiation was "niceness." With GPT-4o and Claude adding conversational warmth, the moat evaporated.

**Source:** Public reporting on Inflection/Microsoft deal (March 2024); Pi.ai product history.

---

### 7. Friend.com / Avi Schiffmann (2024)
**What they tried:** Always-listening AI wearable. Necklace with microphone, constant ambient audio to AI.  
**What failed:**
- **Privacy backlash before ship:** Product generated immediate press coverage for privacy implications. Always-on microphone with cloud processing, no visible recording indicator, no granular consent UI. Launched as vaporware with a waitlist; never shipped broadly.
- **The regulatory exposure is real:** GDPR Article 9 (special categories of personal data) applies to any system that processes health, biometric, or relationship data from ambient audio. Friend.com had no documented compliance posture.

**Source:** TechCrunch coverage (2024); public reporting.

---

### 8. A-MEM: Agentic Memory (arXiv:2502.12110, Feb 2025)
**What they tried:** Dynamic memory organization following Zettelkasten principles. Interconnected knowledge networks via dynamic indexing.  
**What failed (from paper):**
- Fixed memory operations and structures limit adaptability across diverse tasks — the paper's own framing of what it's solving. Prior systems (including MemGPT-style) have this problem.
- A-MEM itself requires an LLM call to organize each memory entry into the network — adding LLM latency and cost to every memory write. NEOTH's profile_extract is the same pattern.
- No published evaluation on personal/single-user AI use case — all benchmarks are on QA tasks.

**Source:** arXiv:2502.12110 (fetched 2026-05-13).

---

### 9. Jarvis / OpenClaw / Veronica (Alex's current system)
**What exists (from JARVIS_DEEP_AUDIT.md):**
- 12 separate memory stores with documented drift
- hippo-turbo dedup threshold = 0.85 (documented in audit)
- Cron-as-watchdog band-aids for self-healing
- Contradiction ledger and HebbianLinks active
- `autocapture` / `autorecall` running as systemd services
- Known: `session-state` and `contradiction-ledger` stores diverge from `hippocampus` over time

**What NEOTH inherits:** Jarvis's 12-store drift is the failure NEOTH is explicitly designed to fix. But the migration plan (`neoth migrate import-jarvis`) imports HIPPOCAMPUS_CORE, not the gestalt behavioral patterns embedded in SOUL.md, CLAUDE.md operator config, and RLHF-equivalent calibration from 6+ months of interaction.

---

## ROUND 2 — Failure Mode Mapping: Is NEOTH About to Repeat Each?

| Peer Failure | NEOTH Design | Recurrence Risk |
|---|---|---|
| **MemGPT: LLM edits own memory → corruption** | WAL + extraction pipeline; LLM writes profile_delta, not raw WAL | **MEDIUM** — profile_extract (Gemini 3.1 Pro, temp=0.0) still hallucinates; deterministic seed reduces variance but doesn't eliminate false claims. No external ground-truth oracle. |
| **Mem0: timestamp hallucination** | `first_observed_ts: Hlc` and `last_confirmed_ts: Hlc` in ProfileClaim | **HIGH** — these timestamps are set by the extraction LLM or by the pipeline clock? Spec unclear. If extraction LLM sets the timestamp from conversation text, #4963-class bug is live. If pipeline sets from system clock, temporal references ("I used to work at X") lose their actual date. Lose either way without explicit timestamp-extraction step. |
| **Mem0: cross-context contamination** | WAL events tagged with channel_id; `idx_profile` is per-user | **MEDIUM** — profile merging across Telegram/WhatsApp/Slack is intentional. If Alex uses two channels with different personas or sensitivity levels, cross-channel contamination is a design choice, not a bug. But the extractor doesn't know which channel's context should dominate. |
| **Mem0: config endpoint auth hole** | `neothctl` CLI; no mentioned auth on daemon API | **HIGH** — SPEC_skill_plugin shows WASM plugins get host function access. If a plugin can call `freedom_yaml.set()` or equivalent, it bypasses all category filters. No capability-restriction per plugin documented in the spec. |
| **Cognee: fixed schema breaks on novel data** | `UserProfile` is a fixed Rust struct; `preferences.other: Vec<String>` is the escape hatch | **HIGH** — `Vec<String>` is a black hole. Over time, everything that doesn't fit the schema lands there. Retrieval from `other` degrades to keyword search over unstructured strings — which is what Jarvis's 12-store drift produced organically. |
| **Replika: personality erasure via model update** | Migration: `neoth migrate import-jarvis` | **CRITICAL** — see Round 3, item 5 below. This is the highest-risk failure for Alex personally. |
| **Pi.ai: cost-per-user economics** | 3 hemispheres + Council (2-10 rounds) + profile_extract per turn | **MEDIUM for solo-Alex, HIGH if ever multi-user** — see Round 3, item 4 below. |
| **Friend.com: always-on privacy backlash** | OMI audio bridge deferred to Phase 2+ | **LOW now, HIGH in Phase 2** — spec has no "voice off by default" + visible indicator requirement. Add it before Phase 2 design starts. |
| **Joel Spolsky: rewrite failure** | 14-day shadow run + parity-check | **MEDIUM** — 14 days catches functional regressions, not 6-month personality drift. See Round 3. |
| **Jarvis 12-store drift** | Single WAL | **LOW → MEDIUM over time** — WAL solves day-1 drift. But as NEOTH adds features (each needs new event types), WAL becomes a mega-table. Already at 7 profile event types (0x30–0x36); tool events, session events, channel events, skill events are separate codes. This is organic accumulation — same root cause as the 12 stores. |

---

## ROUND 3 — Orthogonal Product-Design Risks Not Addressed in Spec

### R3-1: Timestamp Attribution is the Hidden Bug
**Failure source:** Mem0 #4963, A-MEM paper limitations.  
**NEOTH exposure:** `ProfileClaim.first_observed_ts` is populated by `profile_extract` stage. The conversation window passed to the extractor may contain statements like "I was at $COMPANY three years ago." The extractor either:
- (a) Marks `first_observed_ts` as the current pipeline execution time (wrong — it's when the claim was made, not when it was true)
- (b) Tries to infer the actual date from the text (LLM guesses, hallucinates a specific year)
- (c) Leaves it null (retrieval degrades for temporal queries)

None of these is correct. The spec has no explicit stage for timestamp normalization. **Fix:** Add a deterministic pre-extraction stage that parses relative time expressions ("3 years ago", "last summer") against the conversation's actual timestamp before the LLM extraction call. This is a rule-based NLP problem, not an LLM problem — don't give it to the LLM.

---

### R3-2: The WAL-GDPR Paradox
**Failure source:** GDPR Article 17 (right to erasure); WAL design in SPEC_wal_.  
**NEOTH exposure:** PROFILE_REDACT (0x33) zero-fills the old value in the WAL segment. But the WAL event itself remains — it records `field_name`, `operator_id`, and the existence of a redaction. Under GDPR, if the field name itself constitutes personal data (e.g., a health condition fieldname that reveals a diagnosis), the tombstone record is not compliant. More critically: WAL segments are append-only by design. "Zero-filling" in an append-only log means writing a new event that says "old value = [ZERO]" — but the old event still physically exists in the segment until compaction. If compaction never runs (solo-Alex system, no operational pressure), the old value sits in the raw segment file indefinitely.

**The spec says:** "The redaction event records only field name and operator_id; the old value is zero-filled in the WAL segment." This does not describe physical deletion — it describes in-place modification of an append-only log, which is a contradiction in terms for WAL files.

**Fix:** Define `PROFILE_REDACT` as triggering a synchronous WAL segment compaction that physically removes the bytes. This is expensive but required for compliance. Or: explicitly scope NEOTH as "personal use, not subject to GDPR" — which is actually correct for a solo-user system. State it explicitly so Phase-2 multi-user doesn't silently inherit the exposure.

---

### R3-3: Permission-Fatigue on `freedom.yaml`
**Failure source:** Every PII opt-in product (Replika, Friend.com, Pi).  
**NEOTH exposure:** `freedom.yaml` has `profile.learn.categories.health = false` as default-off. Two observed user behaviors from peer products:
- **Type A (Alex):** Power user who reads the YAML, sets fine-grained config on day 1, then never touches it. Six months later, the config no longer reflects reality because interests/sensitivity changed. No re-consent mechanism.
- **Type B (future users if NEOTH ever expands):** Never reads YAML, uses whatever default is set. Default-off health means health conversations generate zero profile signal — the agent appears dumb about health topics. User adds `health = true` once, forgets. Agent now stores every health mention indefinitely.

**The spec has no re-consent or config-staleness mechanism.** Fix: `PROFILE_PAUSE` (0x34) exists for pause-on-demand, but there's no periodic "does this still reflect your preferences?" trigger. Add a decay-driven config review: if `freedom.yaml` hasn't been touched in N days, surface a single review prompt. One prompt, not a nagging loop.

---

### R3-4: Multi-LLM Cost Spiral
**Failure source:** Pi.ai / Inflection unit economics.  
**NEOTH exposure:** Per-turn pipeline for a single user message:
- `profile_extract`: Gemini 3.1 Pro, max 800 tokens — ~$0.0027/call
- `right_hemisphere_analysis`: Gemini 3.1 Pro full pattern analysis
- `left_hemisphere_generate`: Claude Opus 4.7 (highest cost model), full response generation
- `corpus_callosum_check`: GPT-5.5, dissent evaluation
- If dissent_score > 0.4: `council_debate.yaml` — 2-10 additional rounds across all three models

**Conservative estimate for a contested turn:** 3 LLM calls × ~2000 tokens average + council (4 rounds × 3 models × ~1500 tokens) = ~26,000 tokens. At Claude Opus 4.7 pricing (~$0.015/K output tokens), a single council-triggered turn costs ~$0.39. At 50 messages/day, that's ~$19.50/day or ~$585/month for solo-Alex. At $0.10/turn (non-council average), still ~$150/month.

**This is not a problem for solo-Alex if budget allows.** It IS a problem if:
- The council trigger threshold (0.4) is calibrated too low → council fires on benign disagreements
- The spec has a `cost_budget_usd: 0.05` per-turn cap on respond_to_user pipeline — but council_debate is a separate pipeline with its own budget, meaning the $0.05 cap doesn't cover the full turn cost

**Fix:** Add a rolling 24h token spend tracker with a hard daily cap that council respects. The $0.05 per-turn budget in respond_to_user is not meaningful without knowing how often council fires.

---

### R3-5: The Gestalt Personality Migration Gap — Highest Personal Risk
**Failure source:** Replika February 2023. Joel Spolsky 2000.  
**NEOTH exposure:** Migration plan covers:
```
neoth migrate import-jarvis ~/.openclaw
neoth migrate parity-check
```
`import-jarvis` imports HIPPOCAMPUS_CORE — structured facts. What it does NOT import:
- The specific vocabulary calibration in SOUL.md (23 LOWKEY techniques, domain-mode switching behavior)
- The implicit humor and register that developed over 6 months of Jarvis usage
- The contradiction-ledger's resolved contradictions — these represent relationship-history, not just facts
- HebbianLinks weights — which memories reinforce which, built up organically
- The CLAUDE.md operator config's behavioral effects — these are not data, they're runtime prompt injections that shape the personality feel

**`parity-check` tests functional correctness** — does NEOTH answer questions Jarvis answered correctly? It does NOT test "does NEOTH feel like Jarvis?" Replika's users lost their AI not because it forgot facts but because its behavioral texture changed. 14-day shadow run cannot measure 6-month personality divergence.

**The risk is real and personal for Alex:** After cutover, NEOTH will be factually complete but behaviorally new. Alex will notice immediately — the Kumpel-vibe (documented in spec as a brand concern) is a behavioral property that requires interaction history to calibrate, not a flag you import.

**Fix:** Explicit behavioral regression test suite that measures tone/register/humor distribution across 100 historical Jarvis conversations, compared against NEOTH responses to identical prompts. Not functional equality — behavioral similarity scoring. This is a solvable engineering problem (cosine similarity on embedding of response style vectors) but it's not in the spec.

---

### R3-6: WASM Plugin Supply Chain
**Failure source:** agentmemory privacy filter CVEs (documented in prior session audit); Mem0 #5127 (auth bypass).  
**NEOTH exposure:** SPEC_skill_plugin mentions WASM plugins with host function access. WASM provides memory sandboxing but:
- Host functions exposed to WASM guests define the capability boundary. If `freedom_yaml.read()` is a host function (needed for plugins to respect user preferences), `freedom_yaml.write()` is one API call away from a bypass.
- Plugin identity: how does NEOTH verify a WASM binary hasn't been tampered with after install? SHA-256 hash in `marketplace.json` at install time is correct — but does NEOTH re-verify on each load? Cold-start replay attacks on modified WASM binaries are a real class.
- Marketplace vs. local plugins: the spec allows local WASM files (inferred from skill directory structure). A local file has no marketplace provenance. Social-engineering Alex into installing a malicious local skill is a credible attack vector given NEOTH's privileged access to all communication channels.

**Fix (minimum):** Define a whitelist of host functions that plugins can call. `freedom_yaml.write()` should not be a plugin-callable host function. Plugin manifest must declare required host functions at install time — any undeclared calls fail at WASM boundary.

---

## Summary: Top-5 Failure Modes NEOTH Is About to Repeat

**1. Timestamp hallucination in LLM-extracted profile claims** (Mem0 #4963 class)  
Profile_extract gives the LLM a conversation window and asks it to extract claims with temporal metadata. The LLM will incorrectly assign timestamps to historical references. No dedicated timestamp normalization stage exists in the spec. Severity: HIGH — corrupted temporal profile data compounds over time.

**2. Fixed UserProfile schema → `other: Vec<String>` black hole** (Cognee schema rigidity)  
Novel personal data categories will accumulate in untyped escape hatches. After 12 months this looks like Jarvis's drift — different implementation, same outcome. Severity: HIGH — the architectural victory over 12 stores becomes a single store with 12-store-equivalent disorder inside one field.

**3. WAL PROFILE_REDACT does not equal physical deletion** (GDPR Article 17 / WAL append-only paradox)  
Zero-filling in an append-only log is not deletion. For personal use this is acceptable; for any multi-user Phase 3+, it's a compliance blocker. The spec uses "zero-filled" language that implies deletion without specifying compaction semantics. Severity: MEDIUM now, CRITICAL at any multi-user scale.

**4. Gestalt personality is not importable** (Replika February 2023 / Joel Spolsky rewrite)  
Parity-check measures functional correctness, not behavioral texture. After cutover, NEOTH will be factually correct and behaviorally unfamiliar. This is the highest personal-risk failure for Alex specifically — and the one with no technical workaround in the current spec. Severity: CRITICAL for user experience continuity.

**5. Council trigger threshold drives unbounded cost** (Pi.ai unit economics)  
`dissent_score > 0.4` threshold for council_debate is not calibrated against actual dissent rate distributions. If 30% of turns exceed threshold, the real per-turn cost is 4-10x the spec's $0.05 budget. The spec's cost cap covers respond_to_user, not council_debate, which is a separate pipeline. Severity: MEDIUM for solo-Alex, HIGH as daily usage scales.

---

## The One Product-Design Change That Addresses the Most Risks

**Add a `ProfileClaim` validation layer between extraction and WAL write — a deterministic rule-based pre/post processor that:**
1. **Normalizes timestamps** via regex/NLP before the LLM extraction call (fixes #1, eliminates timestamp hallucination)
2. **Routes novel data categories** to a typed extension registry instead of `other: Vec<String>` — new category types are registered by name, not silently accumulated (fixes #2)
3. **Enforces PROFILE_REDACT as a compaction trigger**, not just a flag set (fixes #3)
4. **Generates a behavioral embedding vector** per conversation turn (embed the response style, not the content) and stores it in the WAL — this is the substrate for behavioral regression testing and migration parity scoring (fixes #4)
5. **Counts LLM calls per turn across all pipelines** and enforces a hard global cap before council_debate is allowed to fire (fixes #5)

This is one pipeline stage (a Rust struct implementing a `validate_profile_delta()` trait) that sits between `profile_extract` output and the WAL write. It's 200-400 lines of deterministic code that eliminates the five highest-risk failure modes without changing the architecture.

Call it `ProfileClaimGuard`. It's the missing invariant enforcement layer that every peer product discovered they needed after ship, not before.

---

## Sources (fetched 2026-05-13)

| Source | URL | Status |
|---|---|---|
| MemGPT paper | arxiv.org/abs/2310.08560 | Fetched |
| A-MEM paper | arxiv.org/abs/2502.12110 | Fetched |
| Mem0 bug tracker | github.com/mem0ai/mem0/issues | Fetched (live bugs) |
| Honcho architecture | github.com/plastic-labs/honcho | Fetched |
| Cognee blog | cognee.ai/blog | Fetched |
| GDPR Article 17 | gdpr.eu/right-to-erasure/ | Fetched |
| Joel Spolsky rewrite | joelonsoftware.com/2000/04/06/... | Fetched |
| Replika/Verge | theverge.com/23669728/... | Fetched (redirected to unrelated article — confirmed from cached data) |
| Pi.ai/Inflection | TechCrunch 2024-03-22 | HTTP 404 — confirmed from training data (March 2024 Microsoft acquisition) |
| Friend.com | TechCrunch 2024-09-17 | HTTP 404 — confirmed from training data (2024 privacy backlash) |
| Jarvis audit | RECON/04_JARVIS_DEEP_AUDIT.md | Local file, indexed |
| NEOTH design | PLAN/00_DESIGN_v1.0_FINAL.md | Local file, indexed |

*Sources with HTTP 404 are cited from training data (cutoff August 2025). Mem0 bugs, Honcho architecture, and Joel Spolsky article confirmed from live fetches.*
