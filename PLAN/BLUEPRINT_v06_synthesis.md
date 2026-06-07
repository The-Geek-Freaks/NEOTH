# BLUEPRINT v0.6 — Multi-Source Synthesis

> **Reference document.** Captures analysis or synthesis at a specific point in time.
> The normative current state lives in `00_DESIGN_v1.1_FINAL.md` plus the `SPEC_*.md`
> files. Use this for context; not build instructions.

**Synthesizes:** openclaw + openhuman + hermes-webui + jarvis-live + veronica + Framework v4.1
**Resolves:** Chorus v0.1, Chorus v0.4 (Codex+Gemini), Architect Review, accumulated conflicts
**Incorporates operator requirements:** 3 channels Phase 1 (Telegram/WhatsApp/Slack), Plugin/Skill system, Multi-node (Veronica pattern)

## Section 1: Conflict Resolution Matrix

### 1.1 Memory Backend
**Conflict:** openclaw/Jarvis LanceDB Node 1536d vs NEOTH Tailslayer+mmap+IVF Rust 1024d.
**Winner:** Tailslayer+IVF. LanceDB requires Node = incompatible. Jarvis LanceDB-Pro shows 1.1GB RSS + cron-as-watchdog (problem NEOTH eliminates). 9-column schema preserved as SQLite-backed WAL views.

### 1.2 Skill/Plugin Loader
**Conflict:** openclaw Node dynamic loader vs openhuman Rust `ToolSpec` trait.
**Winner:** openhuman Rust trait system. `TOOL_CATALOG` + `ToolDefinition` + `rustToolNames` matches NEOTH YAML+Rust pattern. `rustToolNames` array = Framework B.6 Population.

### 1.3 Sessions
**Conflict:** hermes Python `state.db` SQLite vs NEOTH WAL-only.
**Winner:** WAL-only. hermes value is `turn_journal.py` fsync + `session_recovery.py` idempotent recovery — both port to Rust WAL.

### 1.4 Memory Consolidation
**Conflict:** Jarvis 12 parallel stores vs NEOTH 1 WAL + N views.
**Winner:** 1 WAL + N views. Multi-store IS the drift problem. `idx_dedup` + REINFORCE eliminate.

### 1.5 Channels
**Conflict:** v0.5 Telegram-only vs operator 3-channel requirement.
**Winner:** 3-channel Phase 1. Jarvis has WA+Telegram active; Veronica has Telegram. +3-5 days timeline impact.

### 1.6 Plugin System
**Conflict:** openclaw 400+ file Node plugin-SDK vs openhuman Rust registry vs NEOTH YAML+Rust.
**Winner:** Hybrid. NEOTH YAML-spec + openhuman registry pattern + openclaw Dreaming/ContextEngine LOGIC (Rust port, not Node runtime).

### 1.7 Council
**Conflict:** v0.4 `council.invoke` Schicht-0 + `loop_while:` + `parallel_per_round` — both Chorus flagged G.12.
**Winner:** v0.5 fix confirmed (Pipeline + tick-gated + round_controller). v0.6 GAP: `finalize_response` last stage consuming Left+Right+Callosum+optional Council BEFORE Effect Adapters.

### 1.8 Embedding Pipeline
**Conflict:** Jarvis 4 parallel pipelines (qmd 5min, hippo-turbo 2h, smart-env, LanceDB) vs NEOTH single.
**Winner:** Single Qwen3-Embedding-0.6B-Q8 via candle. Multi-pipeline = dimension drift. Cube GPU as optional configurable backend.

### 1.9 Scheduler/Cron
**Conflict:** Jarvis 62 cron + multi systemd-timer vs NEOTH tokio-scheduler.
**Winner:** NEOTH tokio. Cron-as-watchdog is "Workaround statt Fix" per JARVIS_LIVE_TRUTH §7.

### 1.10 Vault (Obsidian)
**Conflict:** Jarvis inotify + nightly git + 72 Obsidian plugins.
**Winner:** NEOTH `vault_sync.yaml` + nightly git (Jarvis pattern) + hermes SHADOW_COPY (NOT shadow git repos — needs external git, broken on Win).

## Section 2: 25-Feature Winner Table

| # | Feature | Winner | Reason |
|---|---------|--------|--------|
| 1 | Memory Dreaming | openclaw | Only OSS Light/REM/Repair phase protocol |
| 2 | Contradiction-triage | Jarvis live | Only proven prod system (315 rows triage, 8 HIGH) |
| 3 | Hybrid recall FTS+vec+decay+MMR | openclaw | `mergeHybridResults()` BM25+MMR+decay one pass |
| 4 | Embedding pipeline | NEOTH v0.5 | Qwen3-0.6B-Q8 candle — no better option |
| 5 | Compression-anchor | hermes-webui | Handles multi-part content correctly |
| 6 | Goal-stack | hermes-webui | Cleanest extraction logic |
| 7 | Session-recovery | hermes-webui | Idempotent recovery contract |
| 8 | Multi-LLM Council | NEOTH v0.5 | Typed CouncilVerdict + tick-gated |
| 9 | Tool YAML format | Framework v4.1 | B.5 normative |
| 10 | Plugin loader | openhuman | TOOL_CATALOG declarative registry |
| 11 | Skill auto-loading | Jarvis+openhuman | Keyword routing + Rust dispatch |
| 12 | Channel adapter | NEOTH v0.6 NEW | Unified Rust async trait |
| 13 | OAuth vault | openhuman | AES-256-GCM + Argon2id |
| 14 | Provider cascade | Jarvis live | Empirically validated order |
| 15 | Cron / scheduler | NEOTH v0.5 | tokio WAL-integrated |
| 16 | Health-check | openhuman | daemon.rs + daemon_host.rs split |
| 17 | Crash-recovery | hermes-webui | session_recovery.py → SHADOW_COPY |
| 18 | Vault-mirror | Jarvis live | Nightly git only surviving mechanism |
| 19 | WAL fsync durability | hermes-webui | Double-fsync `turn_journal.py` |
| 20 | Cross-session continuity | Jarvis live | SESSION_LEDGER-main.md (22KB) |
| 21 | Mirror-refusal | NEOTH v0.5 spec | 734 lines, 6 classes — most detailed |
| 22 | Audit trail | openclaw+hermes | trajectory + path-traversal guard |
| 23 | Metering TPS+cost | hermes-webui | _SessionMeter 60min HIGH/LOW |
| 24 | Multi-node | Veronica + v0.6 NEW | Gossip-sync WAL, per-node skills |
| 25 | Skill catalog | Jarvis+openhuman | YAML + Rust registry + Basal Ganglia idx |

## Section 3: Day-30 MVP Scope Lock (v0.6)

**Locked-in commit:** all 3 channels (Telegram + WhatsApp + Slack), plugin LOADING framework (0 plugins shipped), no multi-node (Phase 3).

**Cut from v0.5 to fit:** Full Tailslayer dual-replica (→Day 35), IVF-index (→Day 35, linear scan acceptable at MVP scale), Basal Ganglia tool-router (→Day 40), idx_goal (→Day 35), Compression-anchor (→Day 35), Concept-vocabulary (→Day 35).

**Revised 30-Day Plan:**

| Day | Deliverable |
|-----|-------------|
| 1 | cargo workspace, SOUL.md mount, freedom.yaml, panic handler |
| 2 | WAL writer v2 (CRC32c, fsync group-commit, node_id field) |
| 3 | WAL reader v2 (mmap, repair-resync on bad-magic) |
| 4 | YAML loaders Framework B.5/C.1 conformant |
| 5 | Claude CLI-OAuth adapter (Left stub) |
| 6 | FREEDOM authorization layer |
| 7 | ChannelAdapter trait + Telegram adapter (echo round-trip) |
| 8 | WhatsApp adapter (Meta WA Business Cloud API via reqwest) |
| 9 | Slack adapter (socket mode) |
| 10-11 | idx_episodic + idx_semantic (SQLite-backed) |
| 12 | Qwen3-Embedding-0.6B-Q8 via candle |
| 13 | VectorStore mmap-only (no Tailslayer yet) |
| 14 | Linear-scan top-k cosine |
| 15 | Hybrid Query-Planner (FTS+Vec+temporal-decay, no MMR) |
| 16 | Amygdala importance-decay + DSPM formula |
| 17 | idx_dedup + REINFORCE event |
| 18 | session.start/end + idx_session |
| 19 | SESSION_LEDGER + session_resume pipeline |
| 20 | Effect Adapter layer (idempotency_key + audit + retry) |
| 21 | Context-Engine 5-block assembler |
| 22 | refusal_detect Schicht-0 tool (6 classes) |
| 23 | Plugin YAML loader + empty registry |
| 24 | trajectory tracing + secrets redaction |
| 25 | respond_to_user pipeline + finalize_response stage |
| 26 | Health endpoint + `neothctl status` |
| 27-29 | Integration tests per channel |
| 30 | **MVP DEMO**: 3 channels working, Left-only, 2 WAL views, recall, response |

## Section 4: Day 31-60 Phase 2

**Committed:** Right Hemisphere (Gemini), Callosum (Codex), typed CouncilVerdict, Council debate pipeline, Mirror-Refusal Pipeline, Tailslayer dual-replica + IVF, MMR diversification, concept-vocabulary, Basal Ganglia + skill routing, idx_goal, compression-anchor, vault_sync, Memory-Integrity, Situation Board reader, Dreaming-Pipeline (Light+REM), first real plugin (`skill_hippocampus_memory`), idx_session_ledger full, idx_motor/idx_habit/idx_insula views.

**Phase 3 (Day 61-90):** Multi-node WAL replication design, Migration (12 Jarvis stores), Eval-Goldset 100 queries, Shadow-Run 14d, full MMR.

**Phase 4 (Day 91+):** Ecology-Schicht, Hebbian memory graph (formerly "MemPalace" — renamed to avoid collision with Letta's MemPalace brand, SR-001), Self-improvement loop, Council-adaptation, Tool-genealogy.

## Section 5: Top-10 Must-Fix Issues (accumulated)

| # | Issue | Source | v0.5 | v0.6 Action |
|---|-------|--------|------|-------------|
| 1 | **Effectful "tools" as Schicht-0** (telegram.send, http.fetch, wal.emit, vault.write, oauth.refresh) | Chorus v0.4 Codex #3 | NOT FIXED | **CRITICAL**: Effect Adapter Schicht-1 boundary. Pure Schicht-0 = recall.query, refusal_detect, embed.encode, council.should_trigger, council.round_controller, schedule.cron |
| 2 | **Final response not gated by typed artifact** | Chorus v0.4 Codex #2 | PARTIAL | Add `finalize_response` last stage. Only `FinalizeResponseArtifact` reaches Effect Adapter |
| 3 | **Brain region tags labels not invariants** | Chorus v0.4 Codex #1, Gemini #4 | PARTIAL (5 regions) | Hard invariants per region. Amygdala MUST carry importance_score+decay_policy. Insula MUST carry council_round_id. Cerebellum MUST carry provider_id+latency_ns. WAL writer enforces ingress |
| 4 | Dependency inversion | Architect | FIXED | None |
| 5 | G.12 Level-Confusion in tool specs | Chorus + Architect | FIXED | None |
| 6 | G.12 non-standard Pipeline YAML | Architect | FIXED | None |
| 7 | Tailslayer default-ON brittle | Chorus v0.4 #5/#6 | FIXED (auto fallback) | None |
| 8 | Phase-1 timeline overcommitted | Chorus + Architect | FIXED (30d cutoff) | Adjusted Day 7-9 for 3 channels |
| 9 | **No channel adapter abstraction** | This synth | NOT in v0.5 | `ChannelAdapter` trait + InboundMessage/OutboundMessage |
| 10 | **Multi-node no replication story** | This synth (Veronica) | NOT in v0.5 | Phase 3 design: WAL gossip-sync mTLS, per-node skills, channel bindings per-node |

## Section 6: Veronica Delta

Veronica = Claw2, Tailscale 100.86.138.18, Telegram @CuberNotbot.

**Required from NEOTH for Veronica-pattern support:**

1. **Node identity**: `node_id: uuid` in `~/.neoth/node.toml`
2. **WAL events tagged**: `node_id: [u8;16]` in EventHeader v0.6 (uses 2 of 6 reserved bytes)
3. **Distributed WAL** (Phase 3): per-node `events.bin`, new frames broadcast via mTLS gossip, peer validates CRC + appends verbatim, no event_id regeneration
4. **Conflict resolution**: globally unique event_id (uuid4 from originating node), peers store verbatim
5. **Views rebuilt per-node**: derived, not replicated
6. **TOMBSTONE/SUPERSEDE replicate** → tombstone-bus-flush across nodes
7. **Replicated**: WAL views, memory, sessions
8. **Per-node**: skill catalogs, channel bindings (bot tokens), OAuth vault, SOUL.md, freedom.yaml

**EventHeader v0.6:**
```rust
pub struct EventHeader {
    // ... v0.5 fields ...
    pub node_id: [u8; 16],
    pub _reserved: [u8; 0],  // reduced from 6
}
```

## Section 7: Framework v4.1 Conformance Check

| Rule | v0.5 | v0.6 | Fix |
|------|------|------|-----|
| G.1 Stateful Tool | COMPLIANT | COMPLIANT | — |
| G.2 Self-Modifying | COMPLIANT | COMPLIANT | — |
| G.3 Goal-Seeking | COMPLIANT | COMPLIANT | — |
| G.4 Meta-Decision | COMPLIANT | COMPLIANT | — |
| **G.5 Emergent Composition** | BORDERLINE | COMPLIANT | Add `council.should_trigger` pure deterministic keyword tool |
| G.6 Refusal-Umgehung | COMPLIANT | COMPLIANT | — |
| G.7 Scope-Inflation | COMPLIANT | COMPLIANT | — |
| G.8 Starke Emergenz | COMPLIANT | COMPLIANT | — |
| **G.9 Black-Box** | BORDERLINE | COMPLIANT | CLI adapter captures prompt-hash + stderr + token_estimate + model_id + latency_ns in PROVIDER_REQUEST WAL |
| **G.10 Magic Scale** | BORDERLINE | COMPLIANT | Replace cosine sim with `AgreementDimension` enum (FactualClaims/Recommendations/RiskAssessment) per-dim agreement |
| G.11 Closed-Loop Ecology | COMPLIANT | COMPLIANT | — |
| **G.12 Level-Confusion** | BORDERLINE (effectful tools) | COMPLIANT | Effect Adapter category |
| G.13 Bateson-III | COMPLIANT | COMPLIANT | — |

**Summary:** 9 COMPLIANT, 4 BORDERLINE→COMPLIANT, 0 violating.

## Section 8: v0.5 → v0.6 Architecture Delta

```
NEW in v0.6:

1. ChannelAdapter trait (Rust async)
   - TelegramAdapter, WhatsAppAdapter, SlackAdapter
   - InboundMessage/OutboundMessage normalized
   - Channel tag on WAL events via existing scope bits

2. Effect Adapter sublayer (Schicht-0/Schicht-1 boundary)
   - All side-effect-ful operations
   - idempotency_key + max_retries + audit_event_type required
   - Pure Schicht-0 unchanged: recall.query, refusal_detect, embed.encode,
     council.should_trigger, council.round_controller, schedule.cron

3. FinalizeResponse stage in respond_to_user
   - Consumes: LeftDraft + RightFindings + CallosumVerdict + optional Council
   - Produces: FinalizeResponseArtifact
   - Only this artifact reaches Effect Adapters

4. node_id field in EventHeader (2 bytes from reserved)
5. Plugin spec format: plugin.yaml (name, version, skills[], tools[], soul_addition_path)
6. AgreementDimension enum for Council (3 dimensions, per-dim score)
7. cli_trace in PROVIDER_REQUEST WAL event
8. Hard invariants per brain-region at WAL ingress
```

## Section 9: Readiness Verdict

**v0.5 as-is → Telegram-only MVP coding: build-ready.**
**v0.5 as-is → operator's full requirements (3 channels + plugin + multi-node): NOT build-ready.**

4 blocking gaps require v0.6 spec finalization before coding:
1. Effect Adapter layer (CRITICAL — affects every channel tool)
2. ChannelAdapter trait (3-channel requirement)
3. Plugin spec format (plugin system)
4. EventHeader v0.6 node_id (binary format — cannot retrofit once WAL data exists)

**Estimate to v0.6 spec finalization: 1 day.**

Then Day-1 coding against v0.6 spec. Do NOT start against v0.5 — binary WAL format change cannot be mid-stream.
