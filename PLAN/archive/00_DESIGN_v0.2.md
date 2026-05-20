# AGENTER — Architektur-Design v0.2 (Post-Chorus, Post-OpenClaw-Recon)

> **Sprach-Strategie:** Hybrid. Rust für Daemon/Storage/HTTP/Provider, optionale ASM-Kernels via FFI hinter `#[cfg(target_arch=...)]`.
> **Single binary `agenterd`.** Ein Prozess, mmap-WAL, no GC, kein Node, kein Python im Hot-Path.
> **Linux x86_64 First.** Phase-2 Windows x64, Phase-3 macOS ARM64 via Rust-target-triple-Swap.
> **Status:** Chorus-Fixes integriert. OpenClaw-Patterns (Dreaming, Context-Engine, Trajectory, memory-host-sdk-API) übernommen.

## 1. Sprach-Entscheidung — final

| Layer | Sprache | Begründung |
|-------|---------|-----------|
| Daemon-Core, Scheduler, IPC | Rust 1.85+ (edition 2024) | memory-safe, no-GC, statically linked, MUSL target → keine glibc-Drift |
| WAL writer/reader, mmap-views | Rust | mmap zero-copy, validierte Frame-Reader |
| HTTP/1.1 + HTTP/2 client/server | Rust (`hyper` minimal) | audited, async via tokio |
| TLS 1.3 | `rustls` (statisch) | RFC-konform, audited, no OpenSSL |
| JSON | Rust (`serde_json` mit `sonic-rs` Fallback) | SIMD-optimiert, audited |
| Provider HTTP-Wire-Calls | Rust | streaming via `tokio` + `hyper` |
| Inotify / Filewatch | Rust (`notify`) | kernel-syscall-direct |
| Crypto (AES-GCM, SHA-256, ChaCha20) | `ring` (Rust) | identische Intrinsics wie handgeschriebenes ASM |
| Embedding-Inference Phase 1 | `candle` oder `llama.cpp via FFI` | beide haben GGUF-loader |
| Tokenizer (BPE) | Rust `tokenizers` (HF) | hash+trie, gleicher Speed wie ASM-Eigenimpl |
| **Cosine top-k** | Rust `simd::core::arch` Intrinsics **+ optional ASM-Module** | Nur falls Bench zeigt LLVM auto-vec < 90% peak |
| **Hash hot-loop (xxh3, CRC32c)** | Rust `xxhash-rust` + `crc32c` (HW-instructions) | identisch zu ASM |
| **SIMD-Decay-Tick (bulk f32-mul)** | Rust `std::simd` (portable) | identisch |
| ARM64 ports | Rust `aarch64` intrinsics | LLVM macht den AVX→NEON-Swap |

**Keine ASM ohne Profiling-Beweis.** Erst Rust-Implementierung benchmarken; nur Hot-Spots > 5% Gesamt-Latency und Compiler-Output < 80% peak werden ASM-replaced.

## 2. WAL-Schema v2 — Korruptions-resistent

**Frame-Layout (variable Länge, length-prefix + CRC):**

```
┌─────────────────────────────────────────────────────────────────┐
│  MAGIC (4B) │ "AGNT" 0x41 0x47 0x4E 0x54                         │
├─────────────────────────────────────────────────────────────────┤
│  VERSION (1B) │ schema version, current = 0x02                   │
├─────────────────────────────────────────────────────────────────┤
│  RESERVED (3B) │ pad to 8B                                       │
├─────────────────────────────────────────────────────────────────┤
│  TOTAL_LEN (4B) │ length of this frame including header+CRC      │
├─────────────────────────────────────────────────────────────────┤
│  GENERATION (4B) │ writer-generation, increments on daemon start │
├─────────────────────────────────────────────────────────────────┤
│  EVENT_HEADER (fixed 128B) │ see below                           │
├─────────────────────────────────────────────────────────────────┤
│  PAYLOAD (TOTAL_LEN - 152) │ utf-8 text or json                  │
├─────────────────────────────────────────────────────────────────┤
│  CRC32C (4B) │ over MAGIC..PAYLOAD                               │
└─────────────────────────────────────────────────────────────────┘
```

**Event-Header (128 bytes, fixed):**

```rust
#[repr(C, align(8))]
pub struct EventHeader {
    pub event_id:           u64,    // monoton, (generation<<32)|seq
    pub ts_ns:              u64,    // CLOCK_REALTIME_COARSE
    pub schema_version:     u8,     // currently 2
    pub event_type:         u8,     // see EventType
    pub event_subtype:      u8,     // type-specific
    pub flags:              u8,     // TOMBSTONE/SUPERSEDED/SYNTHETIC/...
    pub importance:         f32,    // 0.0 - 1.0
    pub scope:              u32,    // USER/WORLD/RELATIONSHIP/EPISODIC/SESSION/COMMONS
    pub category:           u32,    // facts/todo/knowledge/episode/auth/...
    pub session_id:         [u8;16],// uuid4 of owning session, 0 if none
    pub source_uri_hash:    u64,    // xxh3 of source path/url (full uri in payload-json)
    pub source_mtime_ns:    u64,    // origin file mtime, 0 if not file-derived
    pub content_hash:       [u8;16],// xxh3 128 of normalized payload
    pub chunk_id:           u32,    // chunk seq within source (0 if whole-doc)
    pub chunk_range_start:  u32,    // byte offset in source
    pub chunk_range_end:    u32,    // byte offset
    pub embedding_model_id: u8,     // 0=none, 1=qwen3-emb-0.6b-q8, 2=text-emb-3-large,...
    pub embedding_dim:      u16,    // 0, 1024, 1536, 768, ...
    pub embedding_offset:   u8,     // 0 = no embedding, else lookup table
    pub vector_blob_off:    u64,    // offset into vectors.bin (0 if no embed)
    pub embedding_hash:     [u8;16],// xxh3 of vector bytes (catch silent corruption)
    pub parent_event_id:    u64,    // edit/reply/derived chain
    pub supersedes_event_id:u64,    // explicit supersession (tombstone target)
    pub _reserved:          [u8;8], // pad to 128
}
```

**Eigenschaften (alle Chorus-Punkte abgedeckt):**

- **CRC32c pro Frame** → partial-write detection
- **Magic + Length-Prefix** → Resync nach Korruption durch Magic-Scan
- **Schema-Version** → Forward-compat
- **Generation-Counter** → unterscheidet Records vor/nach Crash-Restart
- **Tombstones via Flag + supersedes_event_id** → keine stale Embeddings überleben Edits
- **Content-Hash + Embedding-Hash** → silent-corruption-detection
- **Source-URI-Hash + Chunk-Range** → faithful round-trip zu Obsidian-Files
- **Embedding-Model-ID** → re-embed-decision bei Modell-Wechsel deterministisch

**EventType-Enum (V2):**

```
0x00 RAW_TEXT                 user message, MD chunk, transcript line
0x01 EMBED                    pure embedding event (vector + content_hash link)
0x02 LINK                     graph edge (parent_event_id meaningful)
0x03 REINFORCE                importance bump (dedup detection)
0x04 TOMBSTONE                deletion (zeroize vector-cache)
0x05 SUPERSEDE                replaces an earlier event_id
0x06 SESSION_START            uuid generation
0x07 SESSION_END              clean close
0x08 GOAL_PUSH                LIFO push to session goal-stack
0x09 GOAL_POP                 status: done/blocked/aborted
0x0A TOOL_INVOCATION          tool name + args (auth-redacted)
0x0B TOOL_RESULT              return value, status
0x0C PROVIDER_REQUEST         which provider/model, prompt hash
0x0D PROVIDER_RESPONSE        completion, tokens, cost
0x0E COMPRESSION_ANCHOR       semantic compaction point (from Hermes pattern)
0x0F DREAMING_SYNTHESIS       consolidated episode (from openclaw memory-core)
0x10 DREAMING_CONCEPT         extracted concept-vocabulary entry
0x11 OAUTH_GRANT              token vault add (encrypted payload)
0x12 OAUTH_REVOKE             token vault revoke
0x13 VAULT_FILE_SEEN          inotify-detected obsidian change
0x14 EMBED_QUEUED             embedding job queued
0x15 EMBED_FAILED             embedding job failed permanent
0x20 TRAJECTORY_TRACE         request-trace span (otel-compatible)
0x21 METRIC_SNAPSHOT          rolling counters
```

## 3. Memory-Engine — Views v2 (CRC-checked, hybrid-query-aware)

```
events.bin                  (truth: append-only, CRC-framed)
vectors.bin                 (raw f32 vector blobs, indexed by header.vector_blob_off)

idx_id_to_offset.bin        (event_id → file_offset, hash table)
idx_time.bin                (ts_ns sorted, B+-tree)
idx_importance.bin          (importance heap, sorted desc, decay-aware)
idx_session.bin             (session_id → posting list of event_ids)
idx_source.bin              (source_uri_hash → posting list)
idx_category.bin            (category enum → bitmap of event_ids)
idx_scope.bin               (scope enum → bitmap)
idx_dedup.bin               (content_hash → first event_id seen)
idx_tombstone.bin           (set of superseded event_ids; bloom filter front)
idx_fts.bin                 (4-gram inverted, postings ordered by importance*recency)
idx_vec_ivf.bin             (IVF-flat / IVF-PQ index for vectors.bin)
idx_graph.bin               (parent_event_id adjacency CSR)
idx_dream.bin               (dreaming_synthesis events index by topic)
```

Alle Indizes sind aus `events.bin` reproduzierbar. CLI `agenterd repair --rebuild-views` regeneriert.

## 4. Hybrid-Query-Engine (von openclaw `src/context-engine/` portiert)

Schließt die Chorus-Lücke: Query-Intersection statt N independent Lookups.

**Query-API:**

```rust
pub struct Query {
    pub text: Option<String>,           // turns into vector via embed
    pub vector: Option<Vec<f32>>,       // direct vector input
    pub filters: QueryFilters,
    pub top_k: usize,
    pub budget_tokens: Option<u32>,     // context-budget assembly
    pub diversity_lambda: f32,          // MMR diversity (0=greedy, 1=full-diverse)
    pub recency_half_life_hours: Option<f32>,
    pub exclude_session: Option<Uuid>,
}

pub struct QueryFilters {
    pub scopes: Vec<u32>,
    pub categories: Vec<u32>,
    pub session_id: Option<Uuid>,
    pub time_range: Option<(u64, u64)>,
    pub min_importance: f32,
    pub exclude_tombstoned: bool,       // default true
    pub source_pattern: Option<Glob>,
}
```

**Planner-Algorithmus (Section 7 in implementation):**

1. **Sieve-Phase**: schnellste Filter zuerst → bitmap-AND von `idx_category`, `idx_scope`, time-range-slice, session.
2. **Tombstone-Filter**: bloom-skip auf `idx_tombstone`.
3. **Candidate-Pool**: ≤ K_planner Kandidaten (default 10k) gebildet.
4. **Vector-Search**: IVF-search nur über Candidate-Pool (kein full-scan).
5. **Re-Rank**: cosine + importance_decay + recency + diversity (MMR) → top_k.
6. **Budget-Assemble**: pack top_k events in budget_tokens, deduplicate by content_hash, preserve session-ordering where relevant.

**Latency-Target:** < 8 ms p95 für 1 Mio Events, < 25 ms p95 für 10 Mio.

## 5. Dreaming-Pipeline (von openclaw `extensions/memory-core/src/dreaming-*.ts`)

Idle-getriebener Memory-Consolidation-Loop.

**Trigger:**
- Default: alle 2 h (matches Jarvis `hippocampus-preprocess.timer` heute).
- Manuell: `agenterd dream now`.
- Adaptive: nach N RAW_TEXT-Events seit letztem Dream.

**Phasen (jeder schreibt eigenen Event-Subtype 0x0F/0x10):**

1. **Concept-Vocabulary-Extraction** — n-gram + entity-recognition über letzte Periode, finde wiederkehrende Begriffe.
2. **Episode-Clustering** — gruppiere RAW_TEXT-Events nach Session × Topic.
3. **Narrative-Synthesis** — LLM call: "fasse Episode X als 1 Absatz zusammen, behalte Fakten, importance ≥ 0.7".
4. **Markdown-Mirror-Write** — schreibe Synthese als MD nach `mirror/dreams/YYYY-MM-DD-N.md` (Obsidian-lesbar).
5. **Repair-Pass** — finde Widersprüche/Korrekturen → emit SUPERSEDE-events für überholte alte Memories.
6. **Importance-Re-Score** — heuristic: episodes appearing in dreams get +0.1 importance boost.

**Output-Event-Schema:** `DREAMING_SYNTHESIS` events tragen Liste der konsolidierten event_ids in payload-JSON; downstream-Queries können Dreaming-Synthese statt Roh-Episoden zurückgeben.

## 6. Komponenten-Schichtung v2

```
┌──────────────────────────────────────────────────────────────────────┐
│  CLI (`agenterctl`)  │  REPL  │  Telegram-Bot  │  Inotify-Watcher    │
└──────────────┬───────┬────────┬─────────────────┬────────────────────┘
               │       │        │                 │ UNIX-Sock + HTTP
┌──────────────┴───────┴────────┴─────────────────┴────────────────────┐
│                       agenterd (Rust, single binary)                 │
│ ┌──────────────────────────────────────────────────────────────────┐ │
│ │  Gateway (hyper async)                                           │ │
│ │  - REST API (Hermes-WebUI-shape)                                 │ │
│ │  - SSE streaming                                                 │ │
│ │  - Trajectory-tracing (otel-export optional)                     │ │
│ └──────────────────────────────────────────────────────────────────┘ │
│ ┌──────────────────────────────────────────────────────────────────┐ │
│ │  Session / Goal / CompressionAnchor / SessionMemoryHook          │ │
│ └──────────────────────────────────────────────────────────────────┘ │
│ ┌──────────────────────────────────────────────────────────────────┐ │
│ │  Context Engine (openclaw-style)                                 │ │
│ │  - Query Planner (bitmap-AND → IVF-search → MMR re-rank)         │ │
│ │  - Budget Assembler                                              │ │
│ │  - Diversity / Recency / Importance weighting                    │ │
│ └──────────────────────────────────────────────────────────────────┘ │
│ ┌──────────────────────────────────────────────────────────────────┐ │
│ │  Memory Engine v2                                                │ │
│ │   - WAL writer (CRC32c framed, fsync group-commit)               │ │
│ │   - WAL reader (mmap, validate, iterate)                         │ │
│ │   - Indexer (rebuilds views from WAL)                            │ │
│ │   - Dreaming Pipeline (idle consolidation)                       │ │
│ │   - 13 View files (see §3)                                       │ │
│ └──────────────────────────────────────────────────────────────────┘ │
│ ┌──────────────────────────────────────────────────────────────────┐ │
│ │  Embedding (candle / llama.cpp FFI, Qwen3-0.6B-Q8 1024d)         │ │
│ │  ┌────────────────────────────────────────────────────────────┐  │ │
│ │  │ Optional ASM-Kernels (only after profiling proves win):    │  │ │
│ │  │   - cosine_topk_avx512.s    (FMA, 16f-wide)                │  │ │
│ │  │   - decay_tick_avx2.s       (bulk f32-mul)                 │  │ │
│ │  │   - frame_crc32c_sse42.s    (CRC instruction)              │  │ │
│ │  └────────────────────────────────────────────────────────────┘  │ │
│ └──────────────────────────────────────────────────────────────────┘ │
│ ┌──────────────────────────────────────────────────────────────────┐ │
│ │  Crypto (`ring`) | TLS (`rustls`) | HTTP (`hyper`) | JSON (sonic)│ │
│ └──────────────────────────────────────────────────────────────────┘ │
│ ┌──────────────────────────────────────────────────────────────────┐ │
│ │  Provider Cascade   │  Tool Router  │  OAuth Vault              │ │
│ │  claude→qwen→...    │  typed-tools  │  AES-GCM, Argon2id        │ │
│ └──────────────────────────────────────────────────────────────────┘ │
│ ┌──────────────────────────────────────────────────────────────────┐ │
│ │  Channels (Phase 1: Telegram only; later WhatsApp/Signal/...)   │ │
│ └──────────────────────────────────────────────────────────────────┘ │
│ ┌──────────────────────────────────────────────────────────────────┐ │
│ │  io_uring runtime (tokio-uring) | Linux                          │ │
│ │  IOCP (tokio Windows) | Windows                                  │ │
│ │  kqueue (tokio macOS) | macOS                                    │ │
│ └──────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

## 7. Metrik-Dekomposition (Chorus-Punkt G)

Statt eine Zahl `<80 MB RSS` → realistische, geschichtete Targets:

| Komponente | Idle | Active (1 req) | Active (Dream-Phase) |
|-----------|------|----------------|---------------------|
| Daemon-Core (Rust runtime, tokio, idx mmap headers) | 30 MB | 35 MB | 40 MB |
| WAL writer/reader buffers | 8 MB | 12 MB | 20 MB |
| Index mmap **resident** (working-set, OS page-cache) | variable, target ≤ 100 MB | ≤ 200 MB | ≤ 300 MB |
| Embedding-Modell (Qwen3-Emb-0.6B-Q8 GGUF) | 0 MB (lazy-load) | 480 MB (resident) | 480 MB |
| Embedding inference scratch | 0 | 40 MB | 40 MB |
| Provider-Pool TLS sessions | 4 MB | 8 MB | 8 MB |
| **Process-RSS total** | **~42 MB ohne Modell, ~520 MB mit Modell** | **~580 MB** | **~880 MB** |
| **(Vergleich Jarvis heute)** | **~3 GB sum across services** | **~5 GB** | n/a |

**Target-Anpassung:**
- "Idle ohne Modell" `< 80 MB` — bleibt erreichbar (geplante 42 MB).
- "Active with embed-model" `< 600 MB` — neu, ersetzt fantasy `< 250 MB`.
- "Dream-Phase Spike" `< 900 MB` — neu, war nicht im v0.1.
- "Binary on-disk" `< 25 MB` — angepasst von 10 MB; rustls+candle+ring brauchen ihren Platz.

## 8. Latenz-Targets (überarbeitet)

| Operation | v0.1 | v0.2 | Begründung |
|-----------|------|------|-----------|
| Recall top-5 (1M corpus) | < 5 ms | **< 8 ms p95** | mit Hybrid-Filter realistischer |
| Recall top-5 (10M corpus) | n/a | **< 25 ms p95** | mit IVF |
| Recall top-5 (no embed at query) | n/a | **< 1 ms** | pre-vectored query case |
| Embed 1 doc (256 tokens) | < 20 ms | **< 60 ms p95 CPU, < 12 ms GPU** | Qwen3-0.6B-Q8 real ~50ms 8-core |
| WAL append (single event) | n/a | **< 80 µs p99** | append + fsync coalesced |
| Cold start | < 100 ms | **< 250 ms** | mmap-attach + index-header load |
| Cold start with model load | n/a | **< 1500 ms** | GGUF mmap + warmup pass |

## 9. Sicherheit / Sicherheits-Trade-Offs

- **TLS:** `rustls` v0.23+ (audited, no OpenSSL/BoringSSL ASM-Glue).
- **Vault:** AES-256-GCM via `ring`, Key-Derivation Argon2id v0.5+ memory-hard.
- **Secret-Redaction:** all logs pipe through redactor (regex match `[A-Za-z0-9_]{20,}` near keywords token/api/key/bearer).
- **Provenance:** every TOOL_INVOCATION-Event sealed with chained hash → audit trail unforgeable.
- **Memory safety:** Rust core eliminiert UAF/double-free/buffer-overflow im Daemon. ASM-Kernels werden via FFI-Boundary (Slice-len-checked) gerufen.
- **Sandboxing (Phase 2):** seccomp-BPF profile, drop Cap_NET_RAW + Cap_SYS_PTRACE.

## 10. Migration v2 — non-destructive shadow

**Hard rule:** keine destructive dedup, alle Quellen behalten `_source` field, Jarvis bleibt 30+ Tage parallel read-only.

**Phasen:**

1. **Snapshot-Day Zero:** `git tag jarvis-pre-migration` auf `~/github-backup/`, snapshot LanceDB + qmd + Smart-env nach `~/migration-snapshot/`.
2. **Eval-Goldset bauen:** 100 Queries gegen Jarvis-`recall.sh`, expected top-10 events pro Query speichern in `eval/golden.jsonl`.
3. **Import-Pass 1 (read-only):**
   - Obsidian-Vault → emit RAW_TEXT events with `source_uri = path:offset`
   - LanceDB-Pro rows → emit RAW_TEXT + EMBED events, preserve original `created_at` als `ts_ns`
   - Smart-Connections `.ajson` → emit EMBED events (re-embed bei dim≠1024)
   - qmd entries → emit EMBED events
   - Hippocampus `index.json` → emit REINFORCE events (importance preservation)
   - github-backup MEMORY.md → emit RAW_TEXT events
   - context-mode SQLite → emit RAW_TEXT events
   - cq local.db → emit RAW_TEXT mit `scope=COMMONS`
   - Claude `.jsonl` transcripts → emit SESSION events + RAW_TEXT per turn
4. **Dedup-Markierung (nicht löschen):** Events mit gleichem `content_hash` werden gegenseitig in `parent_event_id` verlinkt; NICHT supersedet. Manuelle Review möglich.
5. **View-Rebuild:** `agenterd repair --rebuild-views`.
6. **Recall-Parity-Test:** Eval-Goldset replay → vergleiche AGENTER-Output vs Jarvis-Goldset. Acceptance: top-10 overlap ≥ 0.85, critical-fact-recall = 1.0.
7. **Shadow-Run 14 Tage:** Telegram-Bridge spiegelt jede Anfrage parallel an Jarvis (ground truth) und AGENTER (challenger); Divergences in `eval/divergence.jsonl`.
8. **Cutover:** wenn 14 Tage clean → systemd switch (`openclaw-gateway.service` stop, `agenterd.service` start), Telegram-Bot-Token reassign.
9. **Read-only freeze auf Jarvis:** alte stores chmod 0444, 30-Tage Backup-Periode.

**Abort-Kriterien:** Recall-Parity < 0.80, oder daemon-crash > 1/Tag, oder WAL-CRC-Mismatch festgestellt.

## 11. Cross-Platform-Plan v2

Statt "% reuse" → realistische Plattform-Specifics:

| Plattform | Rust target | Was anders | Aufwand vs Linux |
|-----------|-------------|-----------|------------------|
| Linux x86_64 | `x86_64-unknown-linux-musl` | baseline | — |
| Linux ARM64 | `aarch64-unknown-linux-musl` | NEON statt AVX bei optionalen Kernels | 1 Wochenende |
| Windows x64 | `x86_64-pc-windows-msvc` | tokio uses IOCP, kein io_uring; `notify` für ReadDirectoryChangesW; service via WinSvc | 2-3 Wochen |
| macOS ARM64 | `aarch64-apple-darwin` | kqueue/FSEvents, signing/notarization, NEON-Kernels neu | 3-4 Wochen |
| macOS x86_64 | `x86_64-apple-darwin` | gleich wie ARM64 minus NEON | 1 Woche zusätzlich zu Mac-ARM |

Alle Plattformen teilen denselben Rust-Core. ASM-Kernels sind `#[cfg(all(target_arch="x86_64", target_feature="avx2"))]` etc. — fallen auf portable-SIMD zurück wenn nicht verfügbar.

## 12. OpenClaw-Übernahmen (konkret)

| Aus OpenClaw | Verwendung in AGENTER |
|--------------|----------------------|
| `packages/memory-host-sdk/src/engine.ts` Public API | 1:1 als Rust trait `MemoryEngine` |
| `packages/memory-host-sdk/src/query.ts` | als Rust `Query`-struct + `Filters` |
| `extensions/memory-core/src/dreaming-*.ts` | Dreaming-Pipeline-Module in Rust, gleiche Phasen-Namen |
| `extensions/memory-core/src/concept-vocabulary.ts` | Concept-Extractor in Rust |
| `src/context-engine/` | als Rust-Modul `context_engine`, gleiche Verantwortlichkeiten |
| `src/hooks/bundled/session-memory/handler.ts` | als Rust SessionMemoryHook |
| `src/trajectory/` | OTel-Span-Schema |
| `src/gateway/protocol/` | als Rust-Protobuf or JSON-wire |
| `src/channels/telegram/` | Phase 1 — Telegram-Bot-API mit `teloxide` |
| `src/model-catalog/` | static config + dynamic loader |
| `apps/macos-mlx-tts/` | Phase 3 — TTS-Backend für macOS |

## 13. Was zuerst gebaut wird (Phase-1 Reihenfolge revidiert)

> Original-`01_LINUX_PHASE1_STEPS.md` Tag-1-60-Liste bleibt im Geist, aber implementiert in Rust statt NASM. Reduzierung der ASM-Skeleton-Schritte (Tag 1-7) auf Profiling-getriebene-Kernels in Tag 30+.

**Reihenfolge:**

1. Tag 1: cargo workspace, ci, lints, fmt; "hello world" daemon binary
2. Tag 2-3: WAL writer v2 mit CRC32c + fsync group-commit
3. Tag 4-5: WAL reader mmap + iterate + repair
4. Tag 6-8: Eval-Goldset extractor (gegen jetziges Jarvis-`recall.sh`)
5. Tag 9-12: Memory-host-SDK Trait Definition + storage impl
6. Tag 13-16: Embedding-Backend (candle Qwen3-0.6B-Q8)
7. Tag 17-21: IVF-Vector-Index (`hnsw_rs` oder eigene IVF impl)
8. Tag 22-26: Context-Engine + Query-Planner
9. Tag 27-30: ersten Import-Pass (Obsidian + LanceDB)
10. Tag 31-32: Recall-Parity-Test gegen Goldset
11. Tag 33-35: BENCH Cosine etc. → entscheiden welche ASM-Kernels lohnen
12. Tag 36-40: Provider-Cascade + HTTP/Streaming + TLS
13. Tag 41-44: Telegram-Channel
14. Tag 45-50: Dreaming-Pipeline
15. Tag 51-55: Trajectory-Tracing + Otel-Export
16. Tag 56-60: Shadow-Run-Setup + Cutover-Script

## 14. Verbleibende offene Fragen für Phase 1

1. **Embedding-Modell-Wahl Phase 1:** Qwen3-Embedding-0.6B-Q8 (1024d, ~480 MB resident) oder bge-small-en-v1.5 (384d, ~30 MB)? Smaller wins idle-RSS, Qwen wins Recall-Qualität (multilingual de/en wichtig).
2. **HNSW vs IVF-Flat als Vector-Index:** HNSW ist faster bei kleiner Korpus, IVF skaliert besser bei 10M+. Wir starten klein.
3. **Channel-Priorität:** Phase 1 nur Telegram, oder Telegram + WhatsApp gleichzeitig? WA = OpenClaw hat `extensions/whatsapp-business`, könnten 1:1 mocken.
4. **Embedding-on-CPU vs lokales-GPU (RX 6700XT/4070):** CPU genügt für Idle-Inflow, GPU für Re-Embed-Bulk während Dreaming.
5. **Goldset-Größe:** 100 Queries reichen? Codex empfiehlt mehr für statistische Signifikanz, 500 wäre besser.
6. **MUSL vs glibc target:** MUSL = single binary deployable, glibc = bessere TLS/dns aber libc-pinning. Für Linux-Server-Deploy MUSL vorzuziehen.

## 15. Was wir nicht nochmal an Chorus geben

Diese v0.2 adressiert beide Reviewer-Punkte. Bevor wir ein **drittes** Chorus-Review fahren, sollten wir Phase-1 Tag 1-10 Code haben — dann macht ein echter Code-Review (statt Design-Review) mehr Sinn.

## 16. Sicherheits-Sofortmaßnahme (orthogonal zum Plan)

GitHub-PAT aus `~/.openclaw-git-mirror/.git/config` revoken — sichtbar geleakt während Recon. Replace mit SSH-Key oder GitHub-App-Auth. Diese Aktion blockt AGENTER nicht, sollte aber heute passieren.
