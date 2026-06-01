# CHERRY_PICK_RANKING.md

> **Reference document.** Captures analysis or synthesis at a specific point in time.
> The normative current state lives in `00_DESIGN_v1.1_FINAL.md` plus the `SPEC_*.md`
> files. Use this for context; not build instructions.
**Generated:** 2026-05-12 | **Basis:** Tool-Framework v4.1 + NEOTH Design v0.4 | **Reviewer:** Plan agent

---

## SOURCE 1 — openclaw (steipete upstream)

### Top 5 MUST-ADOPT

**1. Dreaming-Phases (Light/REM/Repair) protocol**
- File: `extensions/memory-core/src/dreaming-phases.ts` + `dreaming-narrative.ts` + `dreaming-repair.ts`
- Why: Light-sleep (short-term promotion), REM-sleep (pattern-strength gating, dedup), Repair phases. Only battle-tested OSS Default-Mode-Network consolidation. `NarrativePhaseData` maps to NEOTH Dreaming-Pipeline YAML.
- Maps to: **Default Mode Network** (Dreaming-Pipeline, Schicht 1)

**2. Hybrid FTS5 + Vector search with MMR + Temporal Decay**
- File: `extensions/memory-core/src/memory/hybrid.ts` + `temporal-decay.ts` + `mmr.ts` + `manager.ts`
- Why: `mergeHybridResults()` does vectorWeight+textWeight fusion with BM25 normalization (`bm25RankToScore`), MMR diversity re-ranking, temporal decay in one pass. `chunks_vec` + `chunks_fts` + `embedding_cache` triad = NEOTH's WAL-backed SQLite views (`idx_semantic` + `idx_episodic`).
- Maps to: **Thalamus** (Context-Engine, Query-Planner)

**3. Concept-Vocabulary stop-word tagger**
- File: `extensions/memory-core/src/concept-vocabulary.ts`
- Why: `MAX_CONCEPT_TAGS=8`, script-family detection (latin/cjk/mixed), multilingual stop-word lists. Tags NEOTH's `idx_semantic.concept_tags`. Pure string logic — direct Rust port.
- Maps to: **Cortex** (idx_semantic view)

**4. Context-Engine pluggable interface (ContextEngine trait)**
- File: `src/context-engine/types.ts`
- Why: Defines `bootstrap`, `ingest`, `ingestBatch`, `assemble`, `compact`, `maintain`, `afterTurn`, `prepareSubagentSpawn`. `AssembleResult.systemPromptAddition` powers NEOTH's 5-block-layer model. `CompactResult` + compress_anchor align perfectly.
- Maps to: **Thalamus** (Context-Engine, Schicht 1)

**5. Trajectory JSONL runtime**
- File: `src/trajectory/runtime.ts` + `types.ts` + `paths.ts` + `export.ts`
- Why: Closest existing impl to NEOTH's WAL. Queued file writers, per-event max-byte limits, truncation sentinels, secrets redaction before flush. `TrajectoryRuntimeRecorder` → NEOTH WAL frame format (CRC32c-framed). `TRAJECTORY_RUNTIME_DATA_MAX_DEPTH=6` guards payload.
- Maps to: **WAL** (Memory-Engine core)

### Top 3 DO NOT COPY

**1. LanceDB Node.js plugin (`extensions/memory-lancedb/`)** — Node lazy-loader. NEOTH uses tailslayer-rs + Qwen3 1024d. Copying recreates Jarvis multi-pipeline anti-pattern.

**2. Plugin-SDK mega-module (`src/plugin-sdk/` 400+ files)** — Node/TS glue. Architecturally incompatible with single Rust binary. NEOTH's equivalent = YAML-spec + Rust-impl from Framework B.5.

**3. Session-memory hook transcript compression (`src/hooks/bundled/session-memory/transcript.ts`)** — Conflicts with Context-Engine `compact()` + Prefrontal Cortex Compression-Anchor. Dual compaction paths = Framework Anti-Pattern.

---

## SOURCE 2 — hermes-webui

### Top 5 MUST-ADOPT

**1. Turn Journal (crash-safe fsync JSONL append)**
- File: `api/turn_journal.py`
- Why: `O_CREAT | O_APPEND | O_WRONLY` + `fsync(fd)` + `fsync(dir_fd)` on every write — exact durability NEOTH WAL needs. `_SESSION_ID_RE` path-traversal guard, `_TERMINAL_EVENTS` recovery set. Translate to Rust `File::sync_all()` + parent dir fd fsync.
- Maps to: **WAL write path** (Hippocampus)

**2. Session Recovery from .bak snapshots**
- File: `api/session_recovery.py`
- Why: `recover_all_sessions_on_startup`, `recover_session(sid)`, `inspect_session_recovery_status(sid)` — clean idempotent recovery contract. `.bak` on message-array shrink prevents partial-write data-loss. NEOTH implements as WAL `SHADOW_COPY` event before destructive write.
- Maps to: **Brain Stem** (daemon-lifecycle)

**3. Compression-Anchor metadata extraction**
- File: `api/compression_anchor.py`
- Why: `visible_messages_for_anchor()` differentiates manual vs auto-compression, handles multi-part content (tool_use, tool_calls, input_text/output_text). Maps to `idx_goal` Prefrontal Cortex view.
- Maps to: **Prefrontal Cortex** (idx_goal, Compression-Anchor)

**4. Gateway session watcher (hash-based change detection)**
- File: `api/gateway_watcher.py`
- Why: `_snapshot_hash()` pattern (session_id + updated_at + message_count → MD5) for polling-based change detection. Replaces Jarvis's `watchdog_providers.sh` + `gateway-watchdog.sh` with single deterministic hash poll.
- Maps to: **Brain Stem** (watchdog)

**5. Metering / TPS tracker (rolling window HIGH/LOW)**
- File: `api/metering.py`
- Why: `_SessionMeter` + rolling 60-min HIGH/LOW TPS = `idx_motor` (Cerebellum) provider-call-stats. Tracks `first_token_ts`, `last_token_ts`, per-session TPS. 1 Hz active / 10 Hz idle ticker prevents CPU spin (the 100% CPU context-mode Node problem).
- Maps to: **Cerebellum** (idx_motor)

### Top 3 DO NOT COPY

**1. State-sync bridge (`api/state_sync.py`)** — Bridges WebUI metadata into `state.db`. NEOTH has no state.db. Creating one alongside WAL recreates drift.

**2. Rollback via shadow git repos (`api/rollback.py`)** — SHA-named shadow git repos require external git binary. NEOTH rollback = WAL `SHADOW_COPY` event + replay to cursor. Atomic-on-Windows broken.

**3. Python streaming SSE stack (`api/streaming.py` + `background.py`)** — FastAPI-specific. NEOTH streams via Telegram + internal tokio. Python async event loop incompatible with `tokio::select!`.

---

## SOURCE 3 — openhuman (Tauri Desktop AI)

### Top 5 MUST-ADOPT

**1. Rust Tool trait system (`ToolSpec`, `ToolCategory`, `PermissionLevel`, `ToolScope`)**
- File: `src/openhuman/tools/traits.rs` + `mod.rs` + `ops.rs` + `schema.rs`
- Why: Closest production-Rust impl of NEOTH's YAML-spec + Rust-impl pattern. `ToolCategory` (System/Skill), `PermissionLevel` ordered enum for channel-level gating, `ToolScope` (All/AgentOnly/CliRpcOnly). `filter_tools_by_user_preference()` → NEOTH tool-router access control. `SchemaCleanr` prevents schema drift.
- Maps to: **Tool-Schicht** (Schicht 0, Framework B.5)

**2. `spawn_subagent` Rust tool (archetype delegation)**
- File: `src/openhuman/tools/impl/agent/spawn_subagent.rs` + `archetype_delegation.rs` + `skill_delegation.rs`
- Why: Collapses inner tool-call loop into single `tool_result` for parent — exactly how Council-Pipeline invokes hemisphere-bound sub-agents (L/R/Callosum). `classify_subagent_failure()` upstream-health prevents silent cascade failure. `AgentDefinitionRegistry` → NEOTH brain-region-tagged agent roster.
- Maps to: **Corpus Callosum** (Council-Pipeline)

**3. Typed `TOOL_CATALOG` with `ToolDefinition` and `rustToolNames` mapping**
- File: `app/src/utils/toolDefinitions.ts` + `src/openhuman/tools/impl/mod.rs`
- Why: `ToolDefinition` (id, displayName, description, category, defaultEnabled, rustToolNames) is the declarative registry needed. `rustToolNames` array (1 logical tool → N Rust impl names) = NEOTH tool variants (Framework B.6 Population pattern).
- Maps to: **Tool-Schicht** (registry)

**4. Daemon health service pattern**
- File: `app/src/services/daemonHealthService.ts` + `src/openhuman/service/daemon.rs` + `daemon_host.rs` + `config/daemon.rs`
- Why: Split between `daemon.rs` (lifecycle) and `daemon_host.rs` (process supervision + restart). Replaces Jarvis `systemd-user` + `stuck-session-autokill.sh` with structured Rust supervision tree.
- Maps to: **Brain Stem**

**5. Memory tree query tools (query_source, query_topic, search_entities)**
- File: `src/openhuman/tools/impl/memory/tree/query_source.rs` + `query_topic.rs` + `search_entities.rs`
- Why: Three narrow Rust tools = NEOTH `recall.query` tool + 3 query modes (source-hash via `idx_source`, semantic FTS via `idx_semantic`, entity graph via future `idx_graph`). Concrete Tool-Schicht implementations for Phase 1.2.
- Maps to: **Tool-Schicht** (`recall.query` tool, Mediotemporal Lobe view)

### Top 3 DO NOT COPY

**1. Mascot / lip-sync layer** — Visemes, palette, `useMascotClock`, `useHumanMascot.lipsync`. NEOTH is headless Rust daemon. Zero overlap.

**2. Tauri IPC / CEF browser stack** — `cdp/`, `cef_profile.rs`, `fake_camera/`, screen capture. macOS/desktop Tauri IPC. +150 MB native deps to a lean binary.

**3. Composio integration tool** — SaaS tool-execution proxy. Direct Rust implementations only. Runtime SaaS dependency = framework Anti-Pattern.

---

## SOURCE 4 — Jarvis Live System

### Top 5 MUST-ADOPT

**1. Hippocampus importance-threshold (≥ 0.75 + decay)**
- Proven: `HIPPOCAMPUS_CORE.md` + `index.json`, `hippocampus-preprocess.timer` every 2h
- Why: Only Jarvis memory filter explicitly proven reliable. NEOTH: events < 0.75 = episodic only; ≥ 0.75 = secondary entry in hippocampus bucket. 2h timer = NEOTH Default-Mode-Network dreaming trigger (Pineal scheduler).
- Maps to: **Amygdala + Hippocampus**

**2. Cross-vendor provider cascade (Claude → GPT → Gemini → Qwen-local)**
- Proven: systemd procs + `watchdog_providers.sh`
- Why: Empirically validated on operator hardware. Formalized as `idx_motor` (Cerebellum) with per-provider success+latency tracking, auto-promote fastest healthy.
- Maps to: **Cerebellum**

**3. Nightly vault-git-commit as memory durability**
- Proven: `vault-git-commit.sh` at 23:55
- Why: Only Jarvis mechanism that survived all refactors. NEOTH: `idx_source` (Mediotemporal Lobe) tracks `source_uri_hash` per WAL event. Nightly git-commit = `vault_sync` pipeline emitting `WAL_MIRROR` events.
- Maps to: **Mediotemporal Lobe**

**4. LanceDB schema contract (9 columns)**
- Proven: `lancedb-schema-validator.sh` daily 04:30, `~/.openclaw/memory/lancedb-pro`
- Why: Field set operator's recall queries depend on. NEOTH WAL preserves all 9 as typed columns in SQLite views: id/text/vector/importance/category/createdAt/scope/timestamp/metadata. Validator cron = startup schema-version check.
- Maps to: **WAL schema**

**5. Dedup-aware multi-store import (SHA-256(text+scope+origin))**
- Proven: drift problem derived from §7
- Why: Drift root = same text enters multiple stores without dedup key. NEOTH `idx_dedup.bin` (8-byte hash → event_id) + REINFORCE event (counter +1 instead of new event). Importance reconciliation: `max(lance, hippo, 0.5 if smart_env, 0.4 if reinforced>5, 0.3 default)` — production-calibrated.
- Maps to: **Hippocampus + WAL dedup**

### Top 3 DO NOT COPY

**1. The 12-layer parallel-store architecture itself** — This is the problem NEOTH replaces. Port only data (Phase 1.9 migration), not writer logic.

**2. Cron-as-watchdog band-aids** — `*/2 stuck-session-autokill.sh`, `*/5 pkill -9 openclaw-channels`. Acknowledged as "Workaround statt Fix". Rust process model has no heap leak; uses structured tokio shutdown.

**3. Multiple parallel embedding pipelines** — qmd 5min + hippo-turbo 2h + smart-env on-edit + LanceDB direct. NEOTH hard-locks to ONE pipeline: candle + Qwen3-0.6B-Q8, triggered by WAL `EMBED_PENDING` event, single worker. Different dimensions get re-embedded at import (Phase 1.9).

---

## Overlap/Duplication Notes

- LanceDB schema: take from Jarvis (battle-tested), ignore openclaw TS runtime.
- Session lifecycle: fsync from hermes, lifecycle event-listener pattern from openclaw (→ Rust mpsc).
- Provider routing: empirical cascade from Jarvis, ignore openclaw TS runtime.
- Gateway watchdog: hash-diffing from hermes, polling-interval from Jarvis.
