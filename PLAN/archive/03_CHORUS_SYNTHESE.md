# Chorus-Review Synthese — Codex (GPT-5.5) + Gemini 3.1 Pro

> **Verdict beider Reviewer: REQUEST CHANGES.**
> Quorum (2 of 2 für Approval) nicht erreicht. Beide unabhängig auf gleiche Kernkritik gestoßen.

## Was beide unabhängig sagen (= harte Wahrheit)

### A. ASM-First-Scope ist überdimensioniert

| Behauptung im Draft | Reviewer-Realität |
|---------------------|-------------------|
| Cosine in ASM: 10–20× vs Compiler | Rust/Zig + AVX2-Intrinsics + Alignment + pre-normalized → 0–30 % Diff zu handgeschriebenem ASM, manchmal Compiler schneller |
| Dot-Product: 5× vs Compiler | LLVM auto-vec mit `core::arch::x86_64` erzeugt **identische** Instruktionen |
| SHA-NI/AES-NI: HW-Acc | Bestehende `ring`/`rustcrypto`/`BoringSSL` nutzen identische Intrinsics |
| HTTP/JSON-Parser ASM "branchless" | 100× größere Security-Angriffsfläche, identische Latency-Output |
| BPE-Tokenizer ASM | Trie + 151k-Vocab ist cache-/branch-bound, nicht ALU-bound — Compiler wins |

**Wirkliche Quelle der Performance-Gewinne:**
- Single binary statt 11 Services (Node-RSS-Bloat weg)
- mmap statt JSON-parse-loop
- io_uring statt sync-syscall
- kein GC
- batching

→ **Das Architektur-Pattern** liefert die `<10 MB binary / <80 MB idle RSS / <5 ms recall`-Ziele, nicht die Wahl ASM vs Rust/Zig.

### B. WAL-Schema ist zu schwach (Daten-Loss-Risiko)

Beide nennen denselben Defekt: `struct memory_event` hat keinen Checksum, kein magic, kein length-prefix, keine schema-version. Ein einziger partial write (power loss, kernel panic, OOM während io_uring flush) korrumpiert das Framing → das **gesamte single-source-of-truth** unlesbar. Jarvis-heute hat implizite Redundanz (12 Stores), AGENTER bündelt alles auf eine Lese-Wahrheit.

**Codex:** schema_version, source_uri, source_mtime, source_inode, content_hash, chunk_id, chunk_range, embedding_model_id, embedding_dim, embedding_hash, deleted_at, supersedes_event_id, CRC.

**Gemini:** CRC32c + Magic Bytes + Version-Byte als Pflicht für jeden Record. Ohne: nach 1 Crash = brain-dead.

### C. Hybrid-Query-Optimizer fehlt komplett

LanceDB löst heute Queries der Form: `vec_sim > 0.8 AND category = 'fact' AND ts > X AND importance > 0.5`. Der Draft hat 12 unabhängige mmap-Files. Ohne expliziten Query-Planner muss man entweder:
- Top-k Vectors holen → post-filter in O(N), oder
- Top-k Time-window holen → on-the-fly embedden

Beides killt das `<5 ms recall`-Ziel sobald Filter ins Spiel kommen.

### D. Cross-Platform-Behauptung ist Fantasie

| Plattform | Reuse-Anteil ASM |
|-----------|------------------|
| Linux x86_64 (Phase 1) | 100 % |
| Windows x64 (Phase 2) | "fast nichts" — verschiedene ABI (RCX,RDX,R8,R9 + shadow space) und keine io_uring/inotify. JEDE Funktion muss in OS-spezifische Makros gewrappt werden |
| macOS ARM64 (Phase 3) | **0 %**. AVX existiert nicht. NEON ist 128-bit. Mach-O ≠ ELF. Komplett neuer Rewrite der Hot-Kernel |

Draft schreibt "80 % carries" und "30 % rewrite" — **realistisch sind 3 separate Codebases**.

### E. Pure-ASM-no-libc bricht an Basics

- **DNS:** kein `getaddrinfo` → eigener UDP-DNS-Client + `/etc/resolv.conf`-Parser nötig. Allein ~500 LOC ASM.
- **TLS:** BearSSL static + raw-ASM-Interface = massive footgun. Audited Lib (rustls/BoringSSL) via FFI ist sicherer Stand der Technik.
- **HTTP/1.1 chunked + SSE:** branchless in ASM ohne buffer-overflow ist berüchtigt schwer.
- **BPE Vocab 151k:** Trie/Hashmap ~10-20 MB RAM, Traversal in ASM ist brutal.

### F. Embedding-Modell sprengt RSS-Target

Qwen3-Embedding-0.6B-Q8.gguf alleine = mehrere hundert MB. Das Idle-RSS-Target `<80 MB` ist erreichbar **nur wenn Modell nicht resident geladen ist**. Sobald Modell rein → mind. 400-800 MB. Metric muss zerlegt werden: `daemon-RSS / model-RSS / index-cache-RSS / OS-page-cache`.

### G. Migration ist destruktiv geplant

- Hash-Dedup kann verschiedene Memories mit identischem Text aber unterschiedlichem Kontext kollabieren.
- Edits ohne Tombstone lassen alte Embeddings recallbar → falsche Fakten überleben.
- View-Rebuild ist nicht garantiert reproduzierbar (kein deterministisches Embedding-Modell-Versionspinning im Schema).

## Synthese der TOP-Probleme (vereint)

| # | Issue | Codex | Gemini | Beide |
|---|-------|-------|--------|-------|
| 1 | ASM-Scope zu groß | ja | ja | **ja** |
| 2 | WAL ohne CRC/Magic/Schema-Version | ja | ja | **ja** |
| 3 | Query-Intersection-Strategie fehlt | indirect | direct | **ja** |
| 4 | Embedding-RSS sprengt Target | ja | ja | **ja** |
| 5 | Cross-Platform 80% Reuse = Fantasie | ja | ja | **ja** |
| 6 | DNS + TLS Stack ohne libc | indirect | direct | **ja** |
| 7 | Destruktive Migration / fehlendes Eval-Set | ja | ja | **ja** |
| 8 | Tombstones / supersedes / chunk-ID fehlen | ja | indirect | **ja** |

## Konkrete Pivot-Empfehlung beider Reviewer

> **Profile-first, ASM-only-where-proven.**
>
> 1. Daemon-Core in **Rust** oder **Zig** schreiben (single binary, no_std oder minimal-std).
> 2. WAL, Storage, Scheduler, HTTP-Client, JSON, Provider-Cascade, Vault-Sync, OAuth, Tool-Router → Rust/Zig.
> 3. Optional Linux-only ASM-Kernels für Cosine/Dot-Product/SHA/AES — **erst nach Profiling-Beweis** dass Rust/Zig-Output messbar schlechter ist.
> 4. WAL: length-prefix + CRC32c + magic + schema_version + tombstone-fähig.
> 5. Embedding: llama.cpp Phase 1, eigener AVX-512-GEMM nur falls Bottleneck.
> 6. TLS: `rustls` oder `BoringSSL` statisch, **kein** ASM-Roll-Your-Own.
> 7. Cross-Platform: Rust portable-core + per-target conditional `#[cfg]` für ASM-kernels.

Damit: identische Hardware-Schonung wie Sawyer's Ansatz, aber:
- Cross-Platform "umsonst" (Rust target triple swap)
- Memory-Safety im Vault/Tool-Router
- Auditierte Krypto/TLS
- Realistischer Liefer-Pfad (Wochen statt Quartale für Phase 1)

## Wo Sawyer-Style-ASM trotzdem ehrlich Sinn macht

1. **AVX-512-Cosine-Inner-Loop (Phase 2):** wenn Profiling zeigt dass Rust auto-vec nur 80 % erreicht.
2. **Custom GEMM (Phase 3):** für eigene Embedding-Inference statt llama.cpp.
3. **inotify-Hot-Loop für Vault** wenn millions-of-events/sec gewünscht (irrelevant hier).
4. **JIT-emitted SIMD-Code** für dimension-spezialisierte Cosine-Variants (das ist Phase 4 territory).

## Was wir aus Codex + Gemini übernehmen müssen (Pflicht vor erstem Code)

- [ ] WAL-Schema neu mit CRC32c + magic + version + length-prefix + tombstone/supersedes
- [ ] Eval-Goldset 100 Queries aus aktuellem Jarvis ableiten (vor Migration!)
- [ ] Shadow-Mode-Migration ohne destruktives Dedup
- [ ] Query-Intersection-Planner-Design (zumindest 1-page-spec)
- [ ] Metric-Decomposition: daemon-RSS vs model-RSS getrennt
- [ ] Sprach-Entscheidung: Rust/Zig-First vs ASM-First — **User-Entscheidung**

## Verbleibende offene Frage an User Alex

**Die Architektur (single binary, mmap-WAL, no Node) ist OK. Die Sprach-Wahl ist die echte Frage.**

Optionen:
1. **Rust-First** (Chorus-Empfehlung): schnellster Liefer-Pfad, sicher, cross-platform automatisch, ASM nur als optionale Kernels nach Profiling. — Verstößt gegen ASM-Philosophie.
2. **Zig-First**: ähnliche Vorteile wie Rust, weniger Memory-Safety-Bürokratie, inline-ASM trivial einbettbar. — Kompromiss.
3. **ASM-First wie ursprünglicher Draft**: User-Philosophie konsequent. — 3× längere Liefer-Zeit, 3 getrennte Codebases (Linux/Win/Mac), höchstes Security-Risiko, höchste Wartungslast. Sawyer-Mode.
4. **Hybrid by-section**: Core/HTTP/Provider/Migration in Rust, Hot-Kernels (Cosine/SHA/AES/AVX) in ASM mit Rust-FFI. Cross-Platform via #[cfg]. — Realistischer Mittelweg.

Mein Vorschlag: **(4) Hybrid**. Du behältst Sawyer-Energie für die Hot-Loops wo's wirklich zählt, kriegst aber den Daemon in 4–6 Wochen statt 6–9 Monaten lauffähig, und Windows/Mac sind Tage statt Quartale.
