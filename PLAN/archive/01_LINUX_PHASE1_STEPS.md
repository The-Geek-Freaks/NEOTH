# AGENTER — Linux Phase-1 Schritt-für-Schritt

> Ziel: end-to-end lauffähiger `agenterd` auf Debian 13.
> Stack: NASM + BearSSL static + llama.cpp static + libgit2 static.
> Migrations-Ziel: bestehender Jarvis bleibt parallel laufen — read-only Mirror, kein destructive cutover.

## Phase 1.0 — Setup (Tag 1)

| # | Schritt | Output |
|---|---------|--------|
| 1 | Toolchain auf Dev-Host: `nasm`, `gcc-14`, `clang-19`, `lld`, `make`, `ld.gold`, `gdb`, `rr`, `valgrind`, `perf` | apt install confirmed |
| 2 | Repo-Skeleton: `SRC/asm/`, `SRC/c-glue/`, `SRC/proto/`, `SRC/tests/`, `SRC/build/`, `SRC/scripts/` | tree |
| 3 | Linker-Script + Makefile (no implicit rules, explicit object list) | `Makefile`, `link.ld` |
| 4 | Build-Test: minimal `_start` → `write(1, "hello", 5)` → `exit_group(0)` via syscall, statisch gelinkt, no libc | 8 KB binary, runs |
| 5 | CI: lokaler `make check` Hook, `nasm-syntax-lint`, `objdump`-Diff-Snapshot | scripted |

## Phase 1.1 — Syscall + I/O Fundament (Tag 2–4)

| # | Schritt | Acceptance |
|---|---------|-----------|
| 6 | `syscall.asm`: read/write/open/close/openat/mmap/munmap/fstat/lseek/clock_gettime/futex/fork/clone/wait/execve/dup2/pipe2/eventfd/timerfd_create | Unit-Tests gegen jeden mit gdb |
| 7 | `io_uring.asm`: setup, sq_enter, cqe_poll, register_files, register_buffers | Echo-Server-Smoke-Test handles 100k req/s |
| 8 | `ring.asm`: SPSC lock-free Ring (per-cpu) für inter-thread IPC | Loom-/TLA-style trace check |
| 9 | `alloc.asm`: Page-Allocator (mmap-backed), Slab-Allocator (8B/16B/32B/.../4KB) | leak tracker via /proc/self/maps diff |
| 10 | `panic.asm`: SIGSEGV-Handler → write stack + regs to `~/.agenter/panic.log` → re-raise | crash-induce test |

## Phase 1.2 — Crypto + Hashing (Tag 5–7)

| # | Schritt | Acceptance |
|---|---------|-----------|
| 11 | `sha256_ni.asm`: SHA-NI Intrinsics (sha256rnds2/msg1/msg2) | matches RFC-vectors |
| 12 | `aes_ni.asm`: AES-256-GCM encrypt + decrypt mit AESNI + PCLMULQDQ | NIST test vectors |
| 13 | `rand.asm`: getrandom syscall + RDSEED fallback | dieharder pass |
| 14 | `chacha20_poly1305.asm`: SSE-Variante (für Win/Mac wo kein AES-NI) | RFC-vectors |
| 15 | BearSSL statisch eingebunden (TLS 1.3 client) | curl-vergleich gegen `claude.ai` |

## Phase 1.3 — Memory Engine MVP (Tag 8–14)

| # | Schritt | Acceptance |
|---|---------|-----------|
| 16 | `wal.asm`: append-only events.bin Writer, 64B aligned, fsync-coalescing, generation-counter | crash-survive test (kill -9 → recover from WAL) |
| 17 | `wal_reader.asm`: mmap-read, validate, iterate | reads 10M events in < 1s |
| 18 | `idx_time.asm`: build idx_time.bin (sortiert nach ts_ns) via merge-sort | rebuild test |
| 19 | `idx_imp.asm`: binary-heap auf importance, top-k query in O(log n) | top-k correctness |
| 20 | `idx_fts.asm`: 4-gram inverted index (hash → posting list of event_ids) | FTS-query "needle" finds correct event |
| 21 | `event_emit_api.asm`: thread-safe append (single-writer via lockf or io_uring serializer) | concurrent 8-thread test |
| 22 | `memory_engine_test`: Schreibe 1M synthetic events, valide alle 5 Sichten | < 30s end-to-end |

## Phase 1.4 — Embedding + Vector Search (Tag 15–21)

| # | Schritt | Acceptance |
|---|---------|-----------|
| 23 | `cosine_avx2.asm`: 768-dim cosine, AVX2 + FMA | ≥ 8 GB/s on Skylake, matches f32 ref ±1e-6 |
| 24 | `cosine_avx512.asm`: 1536-dim, mit AVX-512 wo verfügbar (CPUID dispatch) | ≥ 20 GB/s |
| 25 | `topk_heap.asm`: partial sort über N=10k Kandidaten | < 200 µs |
| 26 | `vectors_bin`-Format + Loader (mmap, aligned 64B) | 1M vectors in 7.5 GB (1536f * 4B = 6 KB each → 6 GB) |
| 27 | llama.cpp static-linked, Qwen3-Embedding-0.6B-Q8.gguf | embeds match Python ref |
| 28 | `embed_pipeline`: text → tokenize (llama.cpp BPE) → embed → store with WAL-link | 1 doc < 20 ms |
| 29 | `recall_api`: query-string → embed → top-k cosine → result-set | < 5 ms for 1M vector corpus |

## Phase 1.5 — HTTP/JSON + Provider Cascade (Tag 22–28)

| # | Schritt | Acceptance |
|---|---------|-----------|
| 30 | `http_parser.asm`: HTTP/1.1 request + response parser, branchless | matches httparser fuzz-corpus |
| 31 | `http_client.asm`: TLS via BearSSL, HTTP/1.1 over TLS, keep-alive | claude.ai roundtrip |
| 32 | `json_parser.asm`: subset (objects, arrays, strings, numbers, bool, null) — no JS-edge-cases | jsonchecker pass |
| 33 | `provider_cascade`: claude-opus → qwen3-235b → wizardlm → llama-maverick, with retry/refusal-detect | offline test via mocked TLS |
| 34 | `system_prompt_assemble`: read SOUL.md + AGENTS.md + recall block + goal-stack → concat → POST | golden output |
| 35 | `streaming.asm`: SSE parse + emit (forward to client) | matches OpenAI stream sample |

## Phase 1.6 — Vault Watcher + Obsidian Mirror (Tag 29–32)

| # | Schritt | Acceptance |
|---|---------|-----------|
| 36 | `inotify.asm`: init1, add_watch recursive, read events | watches /mnt/obsidian/Jarvis |
| 37 | `md_diff.asm`: diff old/new content, emit memory_event(type=RAW_TEXT) per chunk | diff matches `diff -u` |
| 38 | `mirror_writer.asm`: write `mirror/{event_id}.md` for human readability | bidirectional sync test |

## Phase 1.7 — Session / Goal / Compression-Anchor (Tag 33–37)

| # | Schritt | Acceptance |
|---|---------|-----------|
| 39 | `session.asm`: open/close/list, append to WAL with scope=SESSION, generates uuid | concurrent 100 sessions |
| 40 | `goal_stack.asm`: LIFO with status enum, persisted as WAL events | resume after restart |
| 41 | `compaction.asm`: every N tokens, emit COMPRESSION_ANCHOR = top-k events by importance | golden compaction snapshot |
| 42 | `crash_recovery.asm`: detect stale PID, replay WAL since last anchor | kill mid-session, restart, restore |

## Phase 1.8 — OAuth Vault + Tool Router (Tag 38–42)

| # | Schritt | Acceptance |
|---|---------|-----------|
| 43 | `vault.aes`-Format: AES-256-GCM, Argon2id KDF (C-static initial) | OWASP test vectors |
| 44 | OAuth-Flow für Telegram (start point: BotToken in vault) | get/send message roundtrip |
| 45 | Tool-Schema TOML loader, Tool-Router: input → schema-validate → exec → result-event | telegram-send-tool round-trip |
| 46 | Provider 2: GitHub PAT in vault, ListIssues tool | github-issue listed |

## Phase 1.9 — Migrations + Dry-Run Cutover (Tag 43–49)

| # | Schritt | Acceptance |
|---|---------|-----------|
| 47 | `import-lancedb.py` (Hilfs-Python): read `~/.openclaw/memory/lancedb-pro` → emit memory_event per row | 100% rows imported |
| 48 | `import-obsidian.asm`: walk vault → emit memory_event per .md file (chunked) | round-trip match |
| 49 | `import-hippocampus.asm`: read HIPPOCAMPUS_CORE.md + index.json → emit | importance preserved |
| 50 | `import-smart-env.asm`: walk .smart-env/multi/ → emit (vectors as-is if dim matches) | re-embed if mismatch |
| 51 | `import-qmd.asm`: read qmd-DB → emit | row-count match |
| 52 | `import-context-mode.asm`: read .context-mode SQLite → emit (text only, re-embed) | row-count match |
| 53 | `import-cq.asm`: read ~/.cq/local.db → emit | row-count match |
| 54 | `import-github-backup.asm`: walk MEMORY.md + MEMORY_MATRIX.md → emit | match |
| 55 | Migration-Validator: für jeden alten Store → query AGENTER → vergleich Top-10 Recall vs alter Recall | recall-precision ≥ 0.95 |

## Phase 1.10 — Eval + Cutover (Tag 50–56)

| # | Schritt | Acceptance |
|---|---------|-----------|
| 56 | Eval-Set 100 Queries: bekannte Jarvis-Antworten als Goldstandard | scoring framework |
| 57 | Parallel-Run: Jarvis + AGENTER 7 Tage shadow-mode | log divergences |
| 58 | Performance-Benchmark: latency, RAM, throughput | meets all targets in DESIGN §13 |
| 59 | Cutover: openclaw-gateway.service stop → agenterd.service start | seamless to clients |
| 60 | 30-Tage Beobachtung: Jarvis bleibt aus, AGENTER live | no rollback needed |

## Stop-Criteria (Migration abort)

- Recall-Precision < 0.90 vs Jarvis Goldset
- Latency > 50 ms p95 für Recall
- Daemon-Crash > 1/Tag
- WAL-Korruption festgestellt

## Risiken + Mitigation

| Risiko | Mitigation |
|--------|-----------|
| llama.cpp ABI-Drift | Pin commit + checksum + bundled .gguf |
| BearSSL CVE | Replace mit eigener Impl Phase 2 |
| Obsidian-Vault gleichzeitiger Mensch-Edit + AGENTER-Write | Vault-File-Locking via flock, single-writer pro Datei |
| Migrations-Daten-Loss | Read-only auf alten Stores während Import; 30-Tage-Parallel-Run |
| Hot-Patch ohne Restart | Phase 2: liveloader für ASM-Code-Pages |
