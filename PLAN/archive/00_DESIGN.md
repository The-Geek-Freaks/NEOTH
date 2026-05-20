# AGENTER — Architektur-Design v0.1 (Draft für Chorus-Review)

> Codename: **AGENTER** (oder Vorschlag: **ZEUS** — folgt Jarvis/Hermes/Prometheus/Vulcan).
> Ziel: 1 Binary, < 10 MB, < 100 MB RSS im Betrieb, alle Hot-Paths handgeschrieben x86_64 ASM, kein libc-Bloat, kein Node, kein Python im Hot-Path.
> Linux-First (Debian 13), danach Windows x64 (PE), danach Mac (Mach-O ARM64).

## 1. Design-Prinzipien

1. **Eine Binary, ein Daemon.** Keine 11 systemd-Services. Ein Prozess, intern multiplexed mit io_uring + Threads (oder coroutines im ASM-Style).
2. **Direct syscalls, kein libc.** Kein glibc, kein musl. Syscalls direkt via `syscall` Instruktion. Reduziert TLS-Anfälligkeit + Memory-Bloat.
3. **Eine Wahrheit, viele Sichten.** Nicht 12 Memory-Stores parallel — ein interner, append-only Memory-Log + indexed views darauf.
4. **Schema-Contract.** Ein Memory-Item-Layout. Versioniert. Keine 12 verschiedenen JSON-Shapes.
5. **Zero-Copy wo möglich.** mmap-only für Vault-Reads, Vector-DB-Files, Index-Files.
6. **Krypto = Constant-Time + Hardware-Beschleunigt.** AES-NI, SHA-NI, AVX2 dot-product.
7. **Plaintext-Format auf Disk** für Recovery-Lesbarkeit, Binary-Format für Hot-Path.

## 2. Komponenten-Schichtung

```
┌─────────────────────────────────────────────────────────────────┐
│  CLI / REPL / Telegram-Bot / Vault-Watcher  (thin clients)      │
└───────────────────────────┬─────────────────────────────────────┘
                            │ UNIX-Sock / TCP
┌───────────────────────────┴─────────────────────────────────────┐
│                  agenterd (single binary)                       │
│  ┌──────────────┬──────────────┬──────────────┬──────────────┐  │
│  │ HTTP/SSE     │ Tool Router  │ Provider     │ Vault Sync   │  │
│  │ Server       │              │ Cascade      │ + inotify    │  │
│  ├──────────────┴──────────────┴──────────────┴──────────────┤  │
│  │           Session / Goal / Compression Anchor             │  │
│  ├───────────────────────────────────────────────────────────┤  │
│  │  Memory Engine (12-Sichten auf 1 Log)                     │  │
│  │  ┌──────────────────────────────────────────────────────┐ │  │
│  │  │  WAL (append-only events)  →  Indexer (mmap views)   │ │  │
│  │  │  • L1 raw-text             • L7 cosine-vector index  │ │  │
│  │  │  • L2 importance-decay     • L8 graph-edges          │ │  │
│  │  │  • L3 episodic-time-series • L9 session-bucket       │ │  │
│  │  │  • L4 obsidian-mirror      • L10 keyword-FTS         │ │  │
│  │  │  • L5 hippocampus-core     • L11 cross-session       │ │  │
│  │  │  • L6 oauth-vault          • L12 git-mirror          │ │  │
│  │  └──────────────────────────────────────────────────────┘ │  │
│  ├───────────────────────────────────────────────────────────┤  │
│  │   Embedding (SIMD ASM)  |  Crypto (AES-NI/SHA-NI)         │  │
│  │   Tokenizer (BPE in ASM, Qwen3-vocab)                     │  │
│  │   TLS 1.3 (ASM + BearSSL static)                          │  │
│  ├───────────────────────────────────────────────────────────┤  │
│  │   io_uring (Linux) / IOCP (Win) / kqueue (Mac)            │  │
│  │   Syscall wrappers (direct, no libc)                      │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## 3. Memory-Engine — 12 Sichten auf 1 Log

**WAL-Format (append-only, 64-byte aligned):**

```
struct memory_event {
  u64  event_id;        //  monoton, generation << 32 | seq
  u64  ts_ns;           //  CLOCK_MONOTONIC_RAW
  u32  type;            //  RAW_TEXT=1, EMBED=2, DELETE=3, LINK=4, REINFORCE=5, ...
  u32  scope;           //  USER=1, WORLD=2, RELATIONSHIP=3, EPISODIC=4, ...
  u32  category;        //  facts, todo, knowledge, episode, ...
  f32  importance;      //  0.0–1.0
  u64  source_hash;     //  SHA-256 trunc → first 8 bytes of source path/url
  u32  payload_len;
  u32  vector_off;      //  offset into vectors.bin (0 if no embed)
  u64  parent_id;       //  reply-/edit-/derived-from chain
  u8   payload[];       //  utf-8 text or json
};
```

**Index-Views (mmap, regenerable):**

| View | File | Was |
|------|------|-----|
| L1 raw | `events.bin` | append-only Truth |
| L2 importance | `idx_imp.bin` | sorted by importance (heap) |
| L3 episodic | `idx_time.bin` | sorted by ts_ns |
| L4 obsidian mirror | `mirror/*.md` | menschen-lesbarer Spiegel pro event |
| L5 hippocampus-core | `idx_hipp.bin` | importance ≥ threshold, decay-tick aktualisiert |
| L6 oauth-vault | `vault.aes` | AES-NI verschlüsselt, getrennter Key |
| L7 vector-index | `vectors.bin` + `ivf_flat.idx` | 1536-dim or 768-dim Qwen3-Vektoren |
| L8 graph-edges | `idx_graph.bin` | parent_id-Adjazenzliste |
| L9 session-bucket | `idx_session.bin` | event_id → session_uuid |
| L10 keyword-FTS | `idx_fts.bin` | inverted index (4-gram hash) |
| L11 cross-session | `idx_xsess.bin` | semantic-link across sessions |
| L12 git-mirror | `.git/` | nightly snapshot |

Alle Sichten sind aus L1 reproduzierbar. Stirbt eine View, rebuild aus events.bin.

## 4. Hot-Path Komponenten in ASM (NASM, x86_64 Sys-V)

| Komponente | LOC-Schätzung | Warum ASM |
|-----------|--------------|-----------|
| Syscall wrappers (open/read/write/mmap/io_uring) | ~300 | direkt, kein libc |
| Cosine-Similarity (AVX2/AVX-512, FMA) | ~150 | 10–20× vs Compiler |
| Dot-Product 1536-dim (AVX-512) | ~80 | 5× vs Compiler |
| L2-Norm, L2-Distance (AVX2) | ~100 | |
| AES-NI Encrypt/Decrypt (Vault) | ~120 | HW-Acc |
| SHA-256 (SHA-NI) | ~150 | HW-Acc |
| Memcpy/memcmp (rep movs / AVX) | ~80 | Cache-aware |
| BPE-Tokenizer Inner Loop | ~250 | Hot bei jedem Embed |
| HTTP/1.1 Parser (state-machine) | ~400 | Branchless |
| JSON-Parser (subset) | ~600 | Branchless |
| TLS 1.3 record layer (mit BearSSL static-linked) | ~200 | Mix C + ASM |
| io_uring submission (SQE-write) | ~150 | |
| Lock-free Ring-Buffer (für inter-thread IPC) | ~200 | |
| Cosine top-k Heap (partial sort) | ~180 | |
| Importance-Decay Tick (SIMD) | ~120 | Bulk-Update |
| **Sum** | **~3000 LOC ASM hot path** | |

## 5. Was C-Glue bleibt (vorerst)

- **TLS-Stack:** BearSSL statically linked (~50 KB, written in C, audit-friendly).
- **Embedding-Inference:** Phase 1 nutzt llama.cpp via FFI (Qwen3-Embedding-0.6B-Q8). Phase 2 reimpl inneren GEMM-Kernel in ASM.
- **SQLite-Light für FTS:** wir bauen own 4-gram inverted index in ASM, kein SQLite.
- **Git-Operations:** libgit2 statically linked oder shell-out zu `git`.
- **Vault-File-Encoding:** UTF-8 Validator in ASM.

## 6. Provider-Cascade

Übernommen aus jetziger OpenClaw-Config (claude-opus-4.7 → qwen3-235b → wizardlm-2-8x22b → llama-4-maverick), aber:
- HTTP-Client komplett ASM (kein curl, kein libuv).
- Provider-Liste in `~/.agenter/providers.toml`.
- Retry/Refusal-Cascade in C-Wrapper, später ASM.

## 7. OAuth-Vault (Layer 6)

Übernehme OpenHuman-Konzept: typed tools per OAuth provider.
- Vault als AES-256-GCM encrypted Append-Log unter `~/.agenter/vault.aes`.
- Key Derivation: Argon2id (statically linked C, später ASM).
- Tool-Schemas in `~/.agenter/tools/*.toml`.
- Provider-Liste startet bei 5 (Gmail, GitHub, Notion, Obsidian-API, Telegram), wächst.

## 8. Session / Goal / Compression-Anchor

Übernommen aus Hermes-WebUI-Konzepten:
- Goal-Stack pro Session: LIFO mit Status (todo / in-progress / done / blocked).
- Compression-Anchors: alle N Tokens setzt Daemon einen semantischen Anker (= Embedding + Importance > 0.7 events).
- Recovery: Crash-Detection via PID-File + WAL-Replay.

## 9. Vault-Watcher

ASM inotify(7) syscalls:
- `inotify_init1`, `inotify_add_watch` für `/mnt/obsidian/Jarvis` rekursiv.
- On modify → reparse MD → diff → emit memory_event(type=RAW_TEXT) → trigger embed.

## 10. Build-Toolchain

- NASM für ASM (Intel-Syntax, einfacher als AT&T).
- Optional FASM für komplette Self-Hosted Builds.
- C-Glue: TCC oder Clang -O2 -nostdlib.
- Linker: ld direkt, kein cc.
- Static link, no dynamic libs.
- Reproducible builds via fixed timestamps.

## 11. Cross-Platform Plan

- **Phase 1 — Linux x86_64:** alles native. Direct syscalls.
- **Phase 2 — Windows x64:** PE-Loader, Win32-syscalls. Reuse 80% ASM (AES-NI/SHA-NI/AVX identisch), nur Syscall-Schicht tausch.
- **Phase 3 — macOS ARM64:** Mach-O, NEON statt AVX, ARM64-Syscalls. Größerer Rewrite (~30%).

## 12. Was nicht im Scope ist (vorerst)

- Tauri-Frontend / Mascot / Voice-Avatar.
- 118 OAuth-Provider — wir starten mit 5.
- Mobile Apps.
- Multi-User / SaaS.
- Web-Browser-Renderer.

## 13. Erfolgs-Metriken

| Metrik | Jarvis heute | AGENTER Ziel |
|--------|-------------|-------------|
| Binary-Size | n/a (Multi-Service) | < 10 MB |
| Resident Memory (idle) | ~3 GB sum | < 80 MB |
| Resident Memory (active) | ~5 GB sum | < 250 MB |
| Recall-Latency (top-5) | 150–800 ms | < 5 ms |
| Embed-Latency (1 doc) | ~80 ms (Qwen3-0.6B) | < 20 ms (AVX SIMD) |
| Startup Cold | 8–15 s | < 100 ms |
| Cron-Jobs | 12 | 0 (internal scheduler) |
| systemd-Services | 11 | 1 |
| Memory-Drift-Risiko | 12 stores | 1 WAL + reproducible views |

## 14. Offene Fragen (für Chorus-Review)

1. Lohnt BPE-Tokenizer in ASM oder bleibt C? (Qwen3-vocab hat 151k tokens — Trie-Lookup ist branch-heavy.)
2. Eigener Embedding-Kernel (AVX-512 GEMM) ab Phase 1 oder erst Phase 3?
3. TLS-Stack: BearSSL statisch vs eigene minimale TLS-1.3-Impl in ASM (security-risk)?
4. Storage: eigenes mmap-Format vs LMDB / sqlite-vss / lancedb in C-Wrapper?
5. Wie evaluieren wir Recall-Qualität gegen jetziges Jarvis (Eval-Set)?
6. Backwards-Kompatibilität: Migrations-Pfad von 12 alten Stores → 1 WAL?
7. Wann benutzen wir Rust statt C als Glue? (Memory-Safety im Vault-Layer wichtig.)
