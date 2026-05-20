# Architecture Alternatives Adversarial — NEOTH v1.0

Source: architect agent, 3-round adversarial.

## Verdicts (Round 1 + 2 combined)

| Decision | NEOTH choice | Best alternative | Verdict |
|----------|--------------|------------------|---------|
| WAL backend | Custom 96B binary | SQLite WAL-mode + FTS5 OR fjall (Rust LSM) OR LMDB | **Alt wins Phase 1-2.** Custom WAL is reimplementing what SQLite/fjall do correctly with 20 years of testing. Importance-weighted GC is the ONLY thing justifying custom — and it could be a SQLite trigger. |
| 3 LLM hemispheres | Claude+Gemini+Codex | Single LLM + multi-pass reflection OR single+tool-use | **Partially wrong.** Privacy model undocumented: Alex's conversations go to BOTH Anthropic AND Google APIs on every exchange. Profile-extraction-via-Gemini = personal data permanently routed through 2 cloud providers. |
| Pipeline framework | YAML declarative pipelines | Tokio actor model OR no framework | **Both OK, costs understated.** Pipeline template engine + hash verifier = custom infrastructure built BEFORE first feature. Rust type system does the actual safety; YAML is documentation+operability. |
| WASM plugins | Compiled-in inventory crate | WASM via wasmtime OR MCP-only | **NEOTH wins for solo operator.** WASM justified only if non-Rust extension authors exist. |
| 6 brain regions | RegionTag enum 7 values | No tag, route by event_type | **Both OK, but `brain_region` in PayloadPrefixV4 is DECORATIVE** — not in EventHeaderV2 hot-path. Routing already uses event_type. The metaphor is for developer cognition, runtime cost ≈ 0. |
| **HLC** | Kulkarni 2014 HLC | LWW + NTP | **NEOTH WRONG ON IMPLEMENTATION.** `hlc_tick_receive` branch 2 sets `logical = current.logical + 1`, discards `peer.logical`. HLC spec says `max(current.logical, peer.logical) + 1`. **Will produce causality violations in Phase 3 gossip.** |
| Profile storage | WAL events + materialized view | Markdown file OR separate SQLite | **NEOTH wrong on decay model.** Hebbian time-dependent confidence INCOMPATIBLE with static materialized view. On-read lazy decay = latency on every Block-B assembly. Spec defers to "Phase 4 or lazy" without acknowledging critical-path cost. |
| Vector storage | Custom VEC0 shards | Qdrant embedded OR sqlite-vec | **Alt wins beyond ~50K events.** VEC0 fine for MVP. No HNSW = O(N) cosine. At 100K events × 512-dim = 200MB float-mult per recall. With keyword pre-filter OK; without it, blows up. |

## ROUND 3 — Missing Entirely from Design

**M1 — No local generative model for extraction (CRITICAL — Phase 1 decision)**
Spec: Qwen3-Embedding 0.6B (encoder only). Profile-extraction via Gemini 3.1 Pro API.
Reality: Alex's Cube has 3 GPUs. Qwen3-4B INT4 fits ~3GB VRAM, runs ~25 tok/s.
Consequence of missing: every Alex conversation goes to Google's API permanently. `freedom.yaml profile.learn.health=false` prevents NEOTH storing health claims, but doesn't prevent SENDING health-containing conversation text to Gemini for analysis. **The privacy table claim "Profile to outbound providers: Never" is technically true but operationally false: the source data goes to Google.**
Fix: model abstraction in `profile_learn.yaml` = `model: local_qwen3_4b | gemini | claude` from day one. Decision must lock in Phase 1, retrofit is major architecture change.

**M2 — No proactive output architecture**
Spec: every outbound is response to inbound. Channel trait has no "send_proactive" method.
Reality: brand voice = "Kumpel". A Kumpel reaches out. NEOTH architecturally cannot.
Fix: reserve `async fn send_proactive(chat_id, text) -> Result<MessageId, _>` on `Channel` trait in Phase 1, even unimplemented. Adding later = breaking change to all adapters.

**M3 — No personality baseline snapshot**
Spec: Hebbian decay 0.995/day, no anchor.
Reality: after 18 months Alex goes through stressful period × 200 messages → `emotional_baseline.typical_state = stressed` reaches 0.9. Stress passes, but old events never get SUPERSEDE (no contradiction). Confidence decays slowly while new claims keep reinforcing. NEOTH's model of Alex drifts to highest-volume periods, not stable baseline.
Fix: emit `PROFILE_BASELINE_SNAPSHOT` event (0x37) at Phase 3 seed migration Day 65. Never decayed, never compacted (importance=1.0). Phase 4 drift report compares current `idx_profile` against this snapshot.

**M4 — No sleep/consolidation tied to actual sleep**
Spec: Dreaming-Pipeline every 2h wall-clock.
Reality: humans consolidate memory during sleep. If `idx_profile.schedule.sleep_schedule` has confidence ≥ 0.7, NEOTH should run heavy consolidation when Alex sleeps (zero user-facing latency cost) and lightweight maintenance during waking hours.
Fix: `CircadianScheduler` reads `idx_profile.schedule.sleep_schedule`, adjusts cron triggers for `wal_compact.yaml`. Falls back to 03:30 if no schedule known. Phase 4.

**M5 — Privacy architecture for cloud-routed data (THE HOLE)**
Spec: detailed GDPR controls for local `idx_profile` (redact, tombstone, zero-fill). Privacy table says "Profile to outbound providers: Never".
Reality: `profile.extract` sends CONVERSATION WINDOW to Gemini on every exchange. Local controls are theater if source goes to cloud.
Fix: see M1. Local model for extraction. Otherwise document explicitly as known trade-off with operator acknowledgment, not omit from privacy table.

## Top-3 Decisions That Are Probably Wrong

1. **Profile extraction via Gemini API** — conversations to 2 cloud providers permanently. Must decide local-vs-cloud in Phase 1 (retrofit = pipeline schema change + new inference runtime).

2. **HLC `hlc_tick_receive` branch 2 bug** — discards `peer.logical`. Phase 1-2 single-node = silent. Phase 3 gossip = data ordering corruption. Fix: `logical = max(current.logical, peer.logical) + 1`.

3. **Time-dependent confidence + static materialized view incompatible** — every Block-B assembly triggers decay recomputation OR view is stale. Critical path latency cost not budgeted.

## Top-3 Missing Features to Decide Before Code

1. **Local model for extraction (M1)** — locks `model:` field abstraction in pipeline YAML. Phase 1 decision or retrofit becomes major rewrite.

2. **`send_proactive()` on Channel trait (M2)** — reserve method signature now. Trait-lock without this = breaking change to add later.

3. **`PROFILE_BASELINE_SNAPSHOT` event (M3)** — one new event type (0x37). Must be emitted at Phase 3 Day 65 seed migration. Miss that window = no drift comparison possible.
