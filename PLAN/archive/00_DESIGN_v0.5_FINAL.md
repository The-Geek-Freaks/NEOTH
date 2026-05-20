# AGENTER — Design v0.5 FINAL

> **Status:** Build-ready. All Q1-Q8 locked. Both Chorus reviewers' v0.4 critique addressed. Mirror-Refusal-Spec in separate doc.
> **Foundation:** Tool-Framework v4.1 "Pflegbarer Garten" (Schicht 0/1/2, 5 Zutaten, 13 Anti-Patterns).
> **Architecture metaphor:** 3 LLM hemispheres + 5 brain-anatomy memory regions (down from 13 — 8 cosmetic dropped per Chorus).
> **Sources cherry-picked:** openclaw (dreaming, hybrid-search, context-engine, trajectory), hermes-webui (turn-journal, session-recovery, compression-anchor, metering), openhuman (Rust tool traits, spawn-subagent, daemon supervision), Jarvis live (importance≥0.75, provider cascade, vault-git, LanceDB schema, dedup formula).

---

## 0. Locked Decisions (Q1-Q8)

| # | Question | Decision | Source |
|---|----------|----------|--------|
| Q1 | Language | Rust core, ASM kernels via FFI only after profiling proves >20% win | v0.2 |
| Q2 | Council auto-trigger | **Conservative + adaptive**: start with explicit keyword list [architecture, security, refactor, destructive, breaking], track each council outcome in `idx_insula`, adapt thresholds weekly via Phase-4 Ecology scan | v0.5 user pick |
| Q3 | Block-cache TTL | **Tombstone-bus-flush**: no fixed TTL. Cache invalidates on any `TOMBSTONE`/`SUPERSEDE` event for an event_id referenced in the cache key. Plus 24h hard ceiling as safety. | v0.5 user pick |
| Q4 | Embedding model | **Qwen3-Embedding-0.6B-Q8.gguf** (1024d) via candle Rust runtime | v0.4 |
| Q5 | Hemisphere providers | **Left = Claude Opus 4.7** (CLI-OAuth) — sole user-output channel; **Right = Gemini 3.1 Pro** (CLI-OAuth) — pattern-match, no user egress; **Callosum = Codex GPT-5.5** (CLI-OAuth) — interhemispheric synthesis + dissent surfacing | v0.4 + v0.5 confirm |
| Q6 | Tool config format | YAML (Framework B.5 conformance) | v0.4 |
| Q7 | Mirror-Refusal spec | Drafted by code-architect agent in `PLAN\SPEC_mirror_refusal.md` (28 KB, 734 lines, 6 refusal classes, 4 WAL event types). Adopted verbatim. | v0.5 user pick + agent |
| Q8 | Ecology-Schicht start | **Phase 4**, triggered Day 90+ after Phase-3 (full memory + council + dreaming) stable. Trigger: Cerebellum drift-detection OR user explicit `agenterctl ecology enable`. | v0.5 user pick |

---

## 1. What changed vs v0.4 (Chorus + Audit response)

### 1.1 13 brain regions → 5 brain regions (cosmetic dropped)

Chorus v0.4 said 8/13 regions are "magical thinking — metaphor stickers over existing variables". Verified — keep only regions that ENFORCE a constraint not enforced by ordinary view-membership:

| Kept (5) | Why it earns the metaphor |
|----------|--------------------------|
| **Left/Right/Callosum hemispheres** | Output monopoly is a hard architectural constraint — only Left can speak to user |
| **Amygdala** (importance-decay) | Single-writer policy: only the Amygdala writer mutates importance; recall queries default-filter `importance >= θ` |
| **Insula** (council-state) | Council rounds isolated in dedicated view — prevents council-metadata leak into episodic recall |
| **Cerebellum** (provider-cascade-stats) | Single-writer policy + drift-trigger for Phase-4 Ecology scan |
| **Basal Ganglia** (tool-router habit) | Frequency table + Selektion mechanic via promotion/demotion policy tied to outcome events |

**Dropped (8 cosmetic):** BrainStem (daemon lifecycle is runtime not memory), Pineal (scheduler is runtime not memory), MirrorNeurons (refusal-handler is a pipeline not a view), MedialTemporal (already covered by `idx_source`), DefaultMode (dreaming is pipeline not view), Thalamus (context-engine is runtime not view), PrefrontalCortex (goal-stack is `idx_goal`, no benefit from rename), Cortex (semantic-index is `idx_semantic`, no benefit from rename).

**WAL EventHeader change:** `brain_region: Option<u8>` (was `u8`). Set only when event belongs to one of the 5 enforced regions. Saves WAL space, removes dead metadata, fixes Chorus complaint "carrying dead metadata into binary format".

### 1.2 G.12 violations fixed

| Violation in v0.4 | Fix in v0.5 |
|-------------------|-------------|
| Tool YAML had `brain_metadata.invoked_by: [left_hemisphere]` (Tool aware of macro topology) | **Removed from tool spec.** Hemisphere-binding enforced by Pipeline-Router at dispatch time. Tools location-agnostic. |
| Phase-1.2 listed `council.invoke` as Schicht-0 Tool while Council is Schicht-1 Pipeline | **Removed.** Council invocation is `pipelines/council_debate.yaml`, called by Pipeline-Schicht. No `council.*` tool exists at Schicht 0. |
| `pipelines/respond_to_user.yaml` had inline `if_dissent_score > 0.4: trigger:` (non-Framework syntax) | **Replaced with Framework-Teil-C `conditions:` block:** dissent_score defined as typed output of corpus_callosum_check step, condition tested in proper YAML block. |
| `pipelines/council_debate.yaml` had `execution_model: parallel_per_round` + `loop_while:` (non-Framework constructs) | **Replaced with tick-gated stages** + explicit `council.round_controller` tool that decides "next round / stop". Framework Teil-C conformant. |

### 1.3 Council result must produce typed synthesis (Codex critique)

Old: Left produces final answer; Council "decorates" the response path.
New: Council pipeline produces a **typed `CouncilVerdict` artifact**. Left Hemisphere is given the verdict as input to its final user-facing generation step. Order: Right-analysis → Callosum-synthesis → Council-iteration (if triggered) → `CouncilVerdict` → Left-final-generation → user.

### 1.4 Tailslayer default ON but graceful fallback

Chorus called default-ON "brittle". User wants it default-ON.
**Compromise:** Tailslayer enabled by default in config, but daemon at startup probes hugepage availability. If unavailable → log warning, transparently fall back to mmap-backed VectorStore. No hard crash. No degraded silently — startup banner explicitly states which backend was selected.

```toml
[memory.vectors]
backend_preference = ["tailslayer", "mmap"]
hugepage_size_preference = ["2MiB", "1GiB"]
replicas = 2
fallback_mode = "automatic"   # automatic | strict | warn
```

`strict` aborts startup if no hugepages. `automatic` falls back. `warn` logs+continues without Tailslayer.

### 1.5 Dependency inversion in Phase-1 fixed

Old order had Dreaming (1.3) before Memory Engine (1.4). Dreaming writes to WAL views that don't exist yet.
New order: Memory Engine 1.3 → Embedding 1.4 → Context-Engine 1.5 → Council 1.6 → Channels 1.7 → Dreaming 1.8 → Migration 1.9.

### 1.6 30-Day Hard MVP cutoff (Chorus + Architect)

Codex said realistic minimal end-to-end Telegram-response is 10-20 days. Architect agent said 4 steps were 2x underestimated. Final commitment:

**By Day 30**: daemon receives Telegram message, recalls from 2 WAL views (idx_episodic + idx_semantic), generates response via Claude CLI-OAuth (Left Hemisphere only — no Council yet, no Right, no Callosum), sends response back via Telegram. **MVP demo target.**

**Day 31-60**: add Right + Callosum + Council, Tailslayer-vectors, Mirror-Refusal pipeline, SESSION_LEDGER cross-session continuity, more views.

**Day 61-90**: Migration (Phase-1.9 in old plan), Eval-Goldset, Shadow-Run, Cutover.

**Day 91+**: Phase 4 — Ecology-Schicht (drift-detection, tool-genealogy, council-adaptation).

### 1.7 Jarvis-Audit gaps integrated (top-10 from agent)

| # | Audit finding | v0.5 mapping |
|---|---------------|--------------|
| 1 | Memory-Integrity (contradiction-triage, fact-registry, ingress-sanitizer) | New Schicht-1 pipeline `memory_integrity.yaml`. Phase 2. |
| 2 | SOUL behavioral constraints (LOWKEY rules, identity-anchor) | New `~/.agenter/SOUL.md` mounted as Block-B (System Prompt) cache layer. Constraints enforced by Block-Assembler. Phase 1 day 1. |
| 3 | DSPM utility-scoring `(keyword × importance × freshness × reinforcement) / token_cost` | Amygdala writer formula. Phase 1 day 18. |
| 4 | Situation Board control-plane | Obsidian-readable `00 - MOCs/Situation Board.md` as live config-document. Read on every request. Phase 2. |
| 5 | FREEDOM authorization layer (consent schema) | YAML in `~/.agenter/freedom.yaml` — defines scope of Edge-Content, Security-Research, Server-Safety. Phase 1 day 6 (before any tool with side-effects). |
| 6 | MemPalace topology (wings/halls/rooms/tunnels) | Phase 4 Ecology feature. |
| 7 | SESSION_LEDGER cross-session continuity | New WAL view `idx_session_ledger` + `pipelines/session_resume.yaml`. Phase 1 day 27 (before MVP demo). |
| 8 | Self-Improvement loop (ACTIVE_MUTATIONS, ERL lessons) | Phase 4 Ecology feature. |
| 9 | Obsidian Second-Brain 1266-doc backend | `vault_sync.yaml` pipeline. Day 35. |
| 10 | Skill Auto-Loading routing | Basal Ganglia tool-router with skill-keyword index. Day 22. |

---

## 2. Component Stack (final)

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Inputs: Telegram | WhatsApp | CLI | REPL | inotify-Vault-Watcher       │
└──────────────────────────┬──────────────────────────────────────────────┘
                           │
┌──────────────────────────┴──────────────────────────────────────────────┐
│                       agenterd (Rust 1.86 single binary)                │
│                                                                          │
│ ┌─────────────────────────────────────────────────────────────────────┐ │
│ │ Gateway: hyper async | tokio | Trajectory tracing | SSE             │ │
│ ├─────────────────────────────────────────────────────────────────────┤ │
│ │ Pipeline-Router (Schicht 1 dispatcher)                              │ │
│ │  - enforces hemisphere bindings (was tool-spec, now router)         │ │
│ │  - calls Schicht-0 Tools, holds Schicht-1 state                     │ │
│ ├─────────────────────────────────────────────────────────────────────┤ │
│ │ Pipelines (Schicht 1, all YAML-declared):                           │ │
│ │  respond_to_user | council_debate | mirror_refusal | session_resume │ │
│ │  dreaming | vault_sync | memory_integrity (P2) | embed_worker       │ │
│ ├─────────────────────────────────────────────────────────────────────┤ │
│ │ Context-Engine (5-block layered assembly)                           │ │
│ │  Block A Tools (stable cache) │ B System+SOUL (stable cache)        │ │
│ │  Block C Stable Recall (cache, tombstone-bus-flush)                 │ │
│ │  Block D Volatile Recall (fresh) │ E User Msg (fresh)               │ │
│ ├─────────────────────────────────────────────────────────────────────┤ │
│ │ Memory Engine v2                                                    │ │
│ │  WAL events.bin (CRC32c-framed, length-prefix, magic, schema_ver)   │ │
│ │  Views (each = sqlite-backed or mmap-bin):                          │ │
│ │    idx_episodic   │ time-sorted, all events                         │ │
│ │    idx_semantic   │ FTS5 + concept-vocab + temporal-decay           │ │
│ │    idx_importance │ AMYGDALA (single-writer, decay-tick, ≥0.75 gate)│ │
│ │    idx_motor      │ CEREBELLUM (single-writer, provider stats)      │ │
│ │    idx_habit      │ BASAL GANGLIA (tool-router, promotion policy)   │ │
│ │    idx_insula     │ INSULA (council rounds + verdicts)              │ │
│ │    idx_source     │ source_uri_hash → posting list                  │ │
│ │    idx_session    │ session_uuid → posting list                     │ │
│ │    idx_session_ledger │ NEW v0.5: cross-session continuity (Jarvis)│ │
│ │    idx_goal       │ goal-stack per session                          │ │
│ │    idx_dedup      │ content_hash → first event_id (REINFORCE)       │ │
│ │    idx_tombstone  │ bloom-front + set of superseded event_ids       │ │
│ │    idx_vec_ivf    │ IVF index over vectors.bin                      │ │
│ ├─────────────────────────────────────────────────────────────────────┤ │
│ │ VectorStore                                                         │ │
│ │  preferred: tailslayer-rs ReplicatedBuffer (Hugepages 2 MiB × 2)   │ │
│ │  fallback: memmap2 Mmap (automatic when hugepages unavailable)      │ │
│ ├─────────────────────────────────────────────────────────────────────┤ │
│ │ Embedding: candle Rust + Qwen3-Embedding-0.6B-Q8 (1024d)            │ │
│ │ Crypto: ring (AES-256-GCM, SHA-256, ChaCha20-Poly1305)              │ │
│ │ TLS: rustls 0.23+                                                   │ │
│ │ JSON: sonic-rs (SIMD)                                               │ │
│ ├─────────────────────────────────────────────────────────────────────┤ │
│ │ Provider Cascade (CLI-OAuth First)                                  │ │
│ │  Resolver: cli > api-env > oauth-interactive                        │ │
│ │  Cascade order: claude → codex → gemini → qwen-local                │ │
│ │  Refusal-handling: Mirror-Pipeline only, no silent cascade          │ │
│ ├─────────────────────────────────────────────────────────────────────┤ │
│ │ Tools (Schicht 0): YAML-spec + Rust-impl. Stateless, deterministic. │ │
│ │  Phase-1 ten essential tools: telegram.send, vault.read, vault.write│ │
│ │  embed.encode, http.fetch, wal.emit, recall.query, oauth.refresh,   │ │
│ │  refusal_detect, schedule.cron — each in ≥2 variants (Framework B.6)│ │
│ ├─────────────────────────────────────────────────────────────────────┤ │
│ │ OAuth-Vault (own tokens, not LLM-provider tokens)                   │ │
│ │  AES-256-GCM, Argon2id KDF                                          │ │
│ ├─────────────────────────────────────────────────────────────────────┤ │
│ │ Channels (Phase 1: Telegram only; Phase 2+: WhatsApp, Signal, …)    │ │
│ ├─────────────────────────────────────────────────────────────────────┤ │
│ │ Brain Stem: daemon supervision (no longer a "memory region")        │ │
│ │  process tree, restart policy, panic handler, log rotation          │ │
│ ├─────────────────────────────────────────────────────────────────────┤ │
│ │ tokio runtime (io_uring on Linux, IOCP on Win, kqueue on Mac)       │ │
│ └─────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Three LLM Hemispheres (final binding)

| Role | Provider | Auth | User-visible? | Triggered by |
|------|----------|------|---------------|--------------|
| **Left Hemisphere** | Claude Opus 4.7 | claude-code CLI-OAuth (`~/.claude/.credentials.json`) | YES, sole output channel | every user-facing response |
| **Right Hemisphere** | Gemini 3.1 Pro | gemini-cli OAuth (`~/.config/gcloud/application_default_credentials.json`) | NO | parallel to Left, pattern-analysis only |
| **Corpus Callosum** | Codex GPT-5.5 | codex CLI (`~/.codex/auth.json`) | NO | after Right + Left finish, synthesizes typed CouncilVerdict |

All swappable via `~/.agenter/brain.toml`. Hemisphere-binding enforced **by the Pipeline-Router at dispatch time** — tools have zero awareness of which hemisphere invoked them.

---

## 4. WAL EventHeader v2 (final schema)

```rust
#[repr(C, align(8))]
pub struct EventHeader {
    pub magic:              [u8; 4],   // b"AGNT"
    pub schema_version:     u8,        // 2
    pub event_type:         u8,        // see EventType (0x00-0x2F)
    pub event_subtype:      u8,
    pub flags:              u8,        // TOMBSTONE/SUPERSEDED/SYNTHETIC/REDACTED
    pub total_len:          u32,       // frame total bytes incl CRC
    pub generation:         u32,       // writer-generation
    pub event_id:           u64,
    pub ts_ns:              u64,       // CLOCK_REALTIME_COARSE
    pub importance:         f32,
    pub scope:              u32,       // USER/WORLD/RELATIONSHIP/EPISODIC/SESSION/COMMONS
    pub category:           u32,
    pub session_id:         [u8; 16],
    pub source_uri_hash:    u64,       // xxh3 of source path/url
    pub source_mtime_ns:    u64,
    pub content_hash:       [u8; 16],  // xxh3-128 of normalized payload
    pub chunk_id:           u32,
    pub chunk_range_start:  u32,
    pub chunk_range_end:    u32,
    pub embedding_model_id: u8,        // 0 none, 1 qwen3-emb-0.6b-q8, ...
    pub embedding_dim:      u16,
    pub vector_blob_off:    u64,
    pub embedding_hash:     [u8; 16],
    pub parent_event_id:    u64,
    pub supersedes_event_id:u64,
    pub brain_region:       Option<u8>,// Only set for 5 enforced regions (Left/Right/Callosum/Amygdala/Insula/Cerebellum/BasalGanglia). None = no region tag.
    pub hemisphere:         u8,        // 0=N/A, 1=LEFT, 2=RIGHT, 3=CALLOSUM, 4=BOTH (Council)
    pub _reserved:          [u8; 6],   // pad
    // Then payload (variable) and trailing CRC32c (4B) per frame layout
}
```

### EventType (v0.5 final list)

```
0x00 RAW_TEXT
0x01 EMBED
0x02 LINK
0x03 REINFORCE
0x04 TOMBSTONE
0x05 SUPERSEDE
0x06 SESSION_START
0x07 SESSION_END
0x08 SESSION_LEDGER_ENTRY    // cross-session continuity (Jarvis-Audit #7)
0x09 GOAL_PUSH
0x0A GOAL_POP
0x0B TOOL_INVOCATION
0x0C TOOL_RESULT
0x0D PROVIDER_REQUEST
0x0E PROVIDER_RESPONSE
0x0F COMPRESSION_ANCHOR
0x10 DREAMING_SYNTHESIS
0x11 DREAMING_CONCEPT
0x12 OAUTH_GRANT
0x13 OAUTH_REVOKE
0x14 VAULT_FILE_SEEN
0x15 VAULT_FILE_DIFF
0x16 REFUSAL_OBSERVED        // mirror-refusal (Q7 spec)
0x17 REFUSAL_MIRRORED
0x18 REFUSAL_REDIRECTED      // operator-granted authorization, original task retries
0x19 REFUSAL_PERSISTENT      // after N attempts, stop trying
0x1A EMBED_QUEUED
0x1B EMBED_FAILED
0x1C FREEDOM_CONSENT         // FREEDOM authorization scope grant (Jarvis-Audit #5)
0x1D MEMORY_CONTRADICTION    // contradiction-triage (Jarvis-Audit #1, Phase 2)
0x1E SHADOW_COPY             // pre-destructive snapshot (hermes-webui pattern)
0x20 TRAJECTORY_TRACE
0x21 METRIC_SNAPSHOT
0x22 COUNCIL_ROUND
0x23 COUNCIL_VERDICT
```

---

## 5. Phase-1 final 30-day plan (hard MVP commitment)

| Day | Step | Output |
|-----|------|--------|
| 1 | Cargo workspace, SOUL.md mount, panic handler, build pipeline | hello-world Rust binary, < 5 MB |
| 2 | WAL writer v2: CRC32c frame, magic, fsync group-commit | wal_writer crate passes torture-test (kill -9 mid-write) |
| 3 | WAL reader v2: mmap iterate, CRC validate, repair-resync on bad-magic | wal_reader crate reads 1M synthetic events in < 1s |
| 4 | YAML tool-spec + pipeline-spec loaders, Framework Teil-B+C conformant | loads 3 hand-written specs |
| 5 | Three CLI-OAuth adapters: Claude (start with this), Codex, Gemini — Claude first | claude_cli adapter works, others stubbed |
| 6 | FREEDOM authorization layer, audit-trail wiring | freedom.yaml validates, audit events emitted |
| 7 | telegram.send tool + telegram bot ingress | round-trip echo test passes |
| 8-9 | Block-Layer Context-Engine (5-block cache-aware assembler) | assembles request with cache_control markers, integration-test against real Claude CLI |
| 10-11 | idx_episodic + idx_semantic + idx_source views, sqlite-backed | recall.query tool returns events for both views |
| 12 | candle + Qwen3-Embedding-0.6B-Q8 — first embed pipeline | one doc → 1024d vector, < 80 ms on CPU |
| 13-14 | VectorStore with Tailslayer-preferred + mmap-fallback | startup banner shows backend; both paths integration-tested |
| 15-16 | IVF-index over vectors.bin, top-k cosine recall | < 15 ms p95 on 100k vectors |
| 17 | Hybrid Query-Planner (FTS + Vector + MMR + temporal-decay) | port from openclaw hybrid.ts to Rust |
| 18 | Amygdala importance-decay-tick + DSPM utility-scoring | importance recomputed daily, formula matches Jarvis |
| 19 | idx_dedup + REINFORCE event handling | duplicate ingress no longer duplicates events |
| 20 | concept-vocabulary tagger (port openclaw concept-vocabulary.ts) | tags 8 concepts per doc, DE+EN |
| 21 | refusal_detect tool (pure function classifier, 6 classes) | passes 5 test cases from SPEC_mirror_refusal.md |
| 22 | Basal Ganglia tool-router with skill-keyword routing | habit-cache + promotion policy |
| 23 | session.start/end + idx_session view | sessions persisted with uuid |
| 24 | Goal-stack tool (push/pop, idx_goal view) | LIFO per session |
| 25 | Compression-Anchor logic (port hermes compression_anchor.py) | anchor emitted every N tokens |
| 26 | trajectory tracing + secrets redaction layer | every request has trace span |
| 27 | SESSION_LEDGER cross-session resume pipeline | resume after restart loads N-most-recent-session contexts |
| 28 | respond_to_user pipeline (Left-only, no Right/Callosum yet) | full end-to-end Telegram → Claude → Telegram |
| 29 | Health endpoint, metrics, structured logs | `agenterctl status` working |
| 30 | **MVP DEMO**: Telegram message → recall from 2 views → Left-Claude response → Telegram reply | hard commit |

**Stop-criterion if Day 30 not met:** invoke Architect-agent review, identify which 2 days slipped, defer non-blocking features to Day 31-60.

---

## 6. Phase 2 (Day 31-60)

- Right Hemisphere (Gemini) parallel-analysis pipeline
- Corpus Callosum synthesis with typed CouncilVerdict output
- Council debate pipeline (rounds 2-10, agreement 0.66)
- Mirror-Refusal pipeline (per SPEC_mirror_refusal.md)
- 4 remaining Phase-1-essential brain views (idx_motor, idx_habit, idx_insula, idx_session_ledger)
- vault_sync.yaml pipeline (Obsidian Second-Brain integration)
- Memory-Integrity pipeline (contradiction-triage, fact-registry)
- Situation Board live-config-document reader
- Skill Auto-Loading from skill-keyword routing
- Dreaming-Pipeline MVP (Light + REM phases only, Repair later)

## 7. Phase 3 (Day 61-90)

- Migration: import 12 Jarvis stores → AGENTER WAL (shadow-only, non-destructive)
- Eval-Goldset (100 queries from current Jarvis `recall.sh`)
- Recall-Parity test ≥ 0.85 top-10 overlap, critical-fact-recall = 1.0
- Shadow-Run 14 days (Telegram-mirror)
- Cutover when parity stable

## 8. Phase 4 (Day 91+, on-trigger only)

Ecology-Schicht (Framework Schicht 2). Triggered by Cerebellum drift-detection OR explicit `agenterctl ecology enable`. Includes:

- Tool-Genealogie + version-tracking
- Memory-drift detection across stores
- Council-outcome-tracking → adapt council-trigger thresholds
- Self-Improvement loop (ACTIVE_MUTATIONS, ERL lessons)
- MemPalace topology
- Read-only Ecology-Lens (Framework E.5)

Ecology MUST be read-only per Framework G.11 — never directly mutates Schicht-0/1.

---

## 9. Open follow-ups (not blockers)

- **Eval-Goldset content**: 100 queries — extract from `tgf@192.168.178.117 ~/.openclaw/workspace/memory/` transcripts before Day 30 (parallel to dev).
- **Migration-Validator code path**: write the actual importer scripts during Day 27-30, run during Day 31.
- **Mac/Windows ports**: out-of-scope until Phase 4 completes on Linux.

---

## 10. Final files (build-ready)

| File | Purpose | Status |
|------|---------|--------|
| `PLAN/00_DESIGN_v0.5_FINAL.md` | this document | locked |
| `PLAN/SPEC_mirror_refusal.md` | Mirror-Refusal pipeline + 4 WAL event types | locked (28 KB, 6 refusal classes) |
| `PLAN/CHERRY_PICK_RANKING.md` | what to take from each source | locked |
| `PLAN/REVIEW_architect_v0.4.md` | architect agent review | resolved into v0.5 |
| `PLAN/CHORUS_v04_codex.md` + `CHORUS_v04_gemini.md` | external review v0.4 | resolved into v0.5 |
| `PLAN/tool_framework_v4_1.md` | Framework v4.1 foundation | normative |
| `RECON/00_JARVIS_LIVE_TRUTH.md` | Jarvis recon | normative |
| `RECON/01_QUELLEN_ANALYSE.md` | openhuman + hermes mining | normative |
| `RECON/02_OPENCLAW_UPSTREAM_ANALYSE.md` | openclaw upstream mining | normative |
| `RECON/03_JARVIS_RULES_AUDIT.md` | top-10 missing pieces from Jarvis | resolved into §1.7 |

Day-1 starts now: `cargo new agenterd && cd agenterd && cargo add tokio serde hyper rustls ring memmap2 candle-core candle-transformers anyhow thiserror tracing tracing-subscriber crc32c xxhash-rust`.
