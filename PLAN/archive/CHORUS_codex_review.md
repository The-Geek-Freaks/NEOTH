request changes

The design is directionally right on “one source of truth, reproducible views”, but the current draft overclaims the ASM payoff, under-specifies recall quality preservation, and handwaves the dangerous migration/data-loss path. I would not write code from this yet.

## Core Critique

### 1. “12 Views On 1 WAL” Is Plausible, But Not As Written

Section refs: `§3 Memory-Engine`, `§13 Erfolgs-Metriken`

Collapsing 12 stores into one append-only event log is realistic only if the WAL captures enough semantic state to rebuild equivalent views. The draft currently stores:

```c
type, scope, category, importance, source_hash, vector_off, parent_id, payload
```

That is insufficient to faithfully replace:

- LanceDB filters: `id/text/vector/importance/category/createdAt/scope/timestamp/metadata`
- Smart Connections multi-vector chunking
- qmd embedding cache state
- Obsidian file identity, heading path, block ids, frontmatter, backlinks
- Hippocampus curation threshold/history
- session transcript boundaries
- delete/edit tombstones and supersession chains

Attack vector: an Obsidian note changes one paragraph. Current system may preserve note-level, heading-level, and chunk-level embeddings. The proposed WAL emits `RAW_TEXT` and later `EMBED`, but does not define stable chunk IDs, invalidation, supersession, or embedding model/version. Result: duplicate stale facts, bad recall, and unreproducible vector views.

Verdict: the collapse is architecturally sane, but the proposed event schema is too weak. It risks replacing drift with silent semantic loss.

Minimum missing fields:

- `schema_version`
- `source_uri`
- `source_mtime`
- `source_inode/dev` or stable external id
- `content_hash`
- `chunk_id`
- `chunk_range`
- `embedding_model_id`
- `embedding_dim`
- `embedding_hash`
- `deleted_at` / tombstone semantics
- `supersedes_event_id`
- full metadata map or typed sidecar

### 2. ASM Hot Path Does Not Justify The Scope

Section refs: `§4 Hot-Path Komponenten in ASM`, `§10 Build-Toolchain`, `§13 Erfolgs-Metriken`

The ASM section is the weakest part.

Claims like:

> Cosine-Similarity: 10-20x vs Compiler  
> Dot-Product: 5x vs Compiler

are not credible against Rust/Zig/C with `-O3`, AVX2/AVX-512 intrinsics, proper alignment, pre-normalized vectors, and batch layout.

Realistic numbers:

- Scalar naive Python/JS to AVX2 ASM: yes, 10-100x.
- Optimized Rust/C/Zig SIMD to handwritten ASM: usually 0-30%, sometimes negative.
- SHA-NI/AES-NI: no meaningful win over vetted libraries using intrinsics/ASM already.
- Direct syscalls vs libc: basically irrelevant for recall latency; could hurt portability and observability.
- HTTP parser in ASM: not worth the maintenance/security risk.
- JSON parser in ASM: bad tradeoff. Use simdjson-style C/C++/Rust or avoid JSON in hot path.
- BPE tokenizer in ASM: likely a trap. BPE is table/cache/branch dominated, not raw ALU dominated.

The real latency/RAM win comes from deleting Node/Python/Bun service sprawl, consolidating processes, mmap indexes, batching embeddings, and avoiding repeated JSON parse/reparse. That can be achieved in Rust/Zig/C without 3000 LOC of brittle ASM.

Recommended rewrite of the claim:

- ASM only for vector kernels if profiling proves it.
- Use Rust/Zig/C for daemon, WAL, scheduler, HTTP, provider calls, migration, vault sync.
- Use existing audited crypto/TLS.
- Use llama.cpp/ggml for embeddings first.
- Benchmark before committing to ASM.

### 3. Linux Phase 1 Is Missing End-To-End Pieces

Section refs: `§2 Komponenten`, `§6 Provider-Cascade`, `§7 OAuth-Vault`, `§9 Vault-Watcher`

Missing for actual recall + embed + provider call + vault sync + Telegram:

- WAL durability contract: fsync policy, group commit, crash markers, partial record recovery.
- WAL compaction/snapshotting.
- View rebuild strategy and checksums.
- Migration verifier comparing old vs new recall.
- Embedding queue and backpressure.
- Embedding model lifecycle: model path, version, dimensions, quantization, batch size.
- Token budget assembler: ranking, dedup, diversity, recency/importance weighting.
- Provider auth loading and secret redaction.
- Provider streaming response handling.
- Telegram bot ingress: webhook vs long polling, offset persistence, retry semantics.
- Vault sync conflict handling: Obsidian edits while daemon writes mirror files.
- File rename/move handling via inotify.
- Recursive watch exhaustion and recovery.
- State directory layout and backup/restore.
- Health endpoints and request traces.
- Structured logs.
- Metrics.
- Admin repair commands: `wal verify`, `view rebuild`, `migrate dry-run`, `recall compare`.
- Security model for OAuth vault unlock.
- Test harness with golden recall cases.

The design names components but not the control flow that makes them reliable.

### 4. Highest Data-Loss Risks

Section refs: `§3`, `§8`, `§9`, `§11`, `§13`

Ranked failure modes:

1. **Migration dedup destroys distinct memories**
   Same text appears in Obsidian, LanceDB, qmd, Smart Connections, and session transcripts with different metadata. Hash-based dedup can collapse meaningfully different records.

2. **Edits become new facts without tombstoning old chunks**
   A corrected note creates a new event, but old embedded chunks remain recallable unless explicit supersession is modeled.

3. **View rebuild cannot recreate current recall**
   If WAL does not preserve chunking strategy, embedding model/version, metadata filters, and curation state, rebuilt views are not equivalent.

4. **Vault mirror feedback loop**
   Daemon writes Markdown mirror, inotify sees its own write, emits duplicate events, re-embeds, commits garbage.

5. **OAuth/token vault corruption**
   Append-only encrypted vault needs authenticated framing, nonce discipline, key rotation, and recovery. AES-GCM misuse here is catastrophic.

6. **Partial WAL writes**
   Direct append without length-prefix, CRC, generation marker, and fsync policy can leave ambiguous tail records after crash/power loss.

7. **Git mirror illusion**
   `.git/` as L12 view is not a rebuildable index unless the commit mapping and working-tree state are explicit events.

### 5. Migration Path Is Not Realistic Yet

Section refs: `§14.6 Backwards-Kompatibilität`

Current migration plan is basically “import 12 stores into one WAL.” That loses user data unless it is a multi-phase, auditable migration.

Required migration phases:

1. Freeze nothing: run old system and new WAL in shadow mode.
2. Import all stores with source provenance preserved.
3. Never dedup destructively on first import. Mark duplicates as candidate-equivalent.
4. Rebuild all views from WAL.
5. Run recall parity tests against current Jarvis.
6. Compare top-k overlap, answer usefulness, missing critical memories.
7. Run dual-write for Obsidian/session/provider outputs.
8. Cut over only after backup + rollback path exists.
9. Keep old stores read-only for weeks.

The design needs explicit “no destructive migration” as a hard rule.

### 6. Cross-Platform Portability Is Overstated

Section refs: `§11 Cross-Platform Plan`

The “reuse 80% ASM” claim is fantasy.

What carries from Linux x86_64 to Windows x64:

- Some AES-NI/SHA-NI/AVX kernels: mostly yes.
- Calling convention: different.
- Syscalls: no.
- io_uring: no.
- inotify: no.
- ELF/linking/startup: no.
- TLS integration: different.
- file locking/fsync semantics: different.
- sockets/event loop: different.

What carries to macOS ARM64:

- x86_64 ASM: 0%.
- AVX/AES-NI/SHA-NI: 0% directly.
- Need NEON/ARMv8 crypto rewrites.
- kqueue/FSEvents replace io_uring/inotify.
- Mach-O/linking different.
- syscall policy different.

More realistic:

- Linux x86_64 ASM kernels are platform-specific.
- Portable core should be Rust/Zig/C.
- ASM should be optional backend modules selected per target.
- macOS ARM64 is a rewrite of hot kernels, not “30%”.

### 7. Success Metrics

Section refs: `§13 Erfolgs-Metriken`

Plausibility:

- Binary `< 10 MB`: plausible only without embedding model, TLS bloat, libgit2, large tokenizer vocab, and static heavy deps. With real tokenizer/model metadata, maybe still possible, but not guaranteed.
- Idle RSS `< 80 MB`: plausible for daemon alone. Not plausible if embedding model is resident.
- Active RSS `< 250 MB`: fantasy if Qwen3-Embedding-0.6B Q8 is loaded. A 0.6B Q8 model alone is roughly hundreds of MB before runtime overhead.
- Recall `< 5 ms top-5`: plausible only for already-built mmap index, warm page cache, small/medium corpus, no embedding at query time, pre-normalized vectors, approximate search. Not plausible as general end-to-end recall including tokenize/embed/query/rank/dedup.
- Embed latency `< 20 ms`: unlikely for Qwen3-0.6B CPU inference per doc unless tiny text, aggressive batching, or GPU. Tokenizer SIMD will not solve transformer inference cost.
- Startup `< 100 ms`: plausible only if model is not loaded and views are mmap-opened lazily.
- Cron jobs `0`: plausible.
- systemd services `1`: plausible.
- Drift risk lower: plausible, but only with correct event semantics and migration.

## TOP-5 Must-Fix Before Code

1. **Define the WAL/schema properly**
   Add source identity, chunk identity, model/version metadata, tombstones, supersession, checksums, length-prefix framing, CRC, and partial-write recovery.

2. **Replace ASM-first with profile-first**
   Keep ASM only for measured vector/crypto kernels. Implement daemon/storage/migration/provider/vault sync in Rust/Zig/C. The current ASM scope is maintenance risk disguised as performance work.

3. **Write a recall-quality evaluation plan**
   Build a golden set from current Jarvis: queries, expected memories, top-k overlap, answer quality, critical fact recall, stale fact suppression. No eval means you cannot know whether the collapse damaged memory.

4. **Design non-destructive migration**
   Shadow import, provenance-preserving events, no destructive dedup, dual-run, parity checks, rollback. Current migration path is where user data gets lost.

5. **Separate “daemon RSS” from “embedding RSS”**
   Success metrics must distinguish core daemon, loaded embedding model, vector index pages, OS page cache, and active provider/session memory. Current `<80 MB idle` / `<250 MB active` target is misleading.

## Verdict

Do not approve as implementation spec.

Approve the high-level goal: one daemon, one canonical event log, reproducible views, fewer Node/Python services.

Reject the current draft as written because it overcommits to ASM, underspecifies the memory semantics, and lacks a safe migration/evaluation plan. Fix those first, then implement a boring Linux phase-1 in Rust/Zig/C with narrow optional ASM kernels.

## DONE
