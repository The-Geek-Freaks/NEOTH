# ADVERSARIAL: Implementation Hot-Paths - NEOTH v1.0

<!-- scope: NEOTH v1.0 + all PLAN/SPEC_*.md  angle: Phase 1 Rust impl under real load -->
<!-- date: 2026-05-13  status: adversarial analysis, pre-build -->

---

## ROUND 1 - Hot-Path Bottleneck Identification

### HP-1: WAL Append - MmapMut vs Group-Commit Conflict

**Spec claim:** SPEC_wal_lifecycle.md section 9 defines WalMmapWindow using memmap2::MmapMut
for the active append segment. Design narrative references fsync group-commit.

**Conflict:** Mutually exclusive strategies. MmapMut::flush() calls msync(MS_SYNC) on Linux.
On XFS with default nobarrier mount (NVMe standard), msync does NOT issue a drive cache flush.
fsync(2) does. Power loss between msync return and physical write drops the frame without
triggering CRC mismatch on restart - frame is simply absent, not corrupt.

Group-commit requires: acquire write lock, drain pending queue into 64 KB buffer, issue one
write(2) and one fsync(2). Incompatible with mmap-append: MmapMut writes go through page cache
at arbitrary granularity; no tokio-async-friendly API to batch msync across concurrent callers.

**Throughput ceiling:** MmapMut is !Sync. Multiple tokio tasks share it via Mutex<WalMmapWindow>.
At 100 us per msync (NVMe): max ~10k writes/sec. At burst (Council 3-provider x 3-round +
profile extractions + channel events): ~50 concurrent WAL appends queue. At 1 ms/write under
lock contention, 50-event burst = 50 ms stall visible as pipeline backpressure upstream.

**Test gap:** test_vector_blob_write_ordering_survives_crash tests blob orphan only. No test
verifies WAL frames are not silently dropped on power-loss between msync return and physical write.

**Remediation:** Dedicated WalWriterTask owning a tokio::fs::File with O_DSYNC (Linux) or
FILE_FLAG_WRITE_THROUGH (Windows). Callers send over mpsc::Sender<WalEvent>. Task drains channel
into BytesMut (64 KB threshold or 10 ms deadline), calls file.write_all().await then
file.sync_data().await. One fsync per batch = true group-commit. Sealed segments use read-only
Mmap (safe, Sync, no alignment UB). Crates: tokio::fs, bytes. Both in Day-1 dep list.

---

### HP-2: WAL Recall - Vector JOIN Across Two Backends, p95 Violation on Cold Cache

**Spec claim:** SPEC_wal_lifecycle.md section 5.1: vectors in vec-{event_id_hi:08x}.bin shards.
Recall hot path: FTS5 keyword -> posting list -> AND-merge -> cosine on candidates.

**Conflict:** Recall must JOIN two backends: SQLite FTS5 returns Vec<u64> event_ids; for each,
reader must compute shard path, seek to vector_blob_off, read 2060 bytes (dim=512), parse VEC0,
compute cosine. Spec does not define this join.

At 10k candidates: 10000 x 2060 bytes = ~20 MB random reads. NVMe (~400k IOPS, ~2.5 us/IO):
10k reads x 2.5 us = 25 ms minimum on warm cache. Cold page cache (after restart or shard
rewrite during compaction): violates p95 < 30ms. Spinning HDD: 10k seeks x 8 ms = 80 seconds.

WalMmapWindow.previous_segments LRU caches sealed segments only. The ACTIVE shard where all
recent events land is MmapMut write-locked. Cold recall against recent events hits the locked
active shard, not the LRU cache.

**Failure mode:** Profile relevance bonus (SPEC_proactive_learning section 6.2) calls recall
as a sub-path for Block-C scoring. Slow recall = slow response assembly. After daemon restart
or compaction, first recall queries exceed p95 with no operator alert.

**Remediation:** Separate write shard from read shard. Writer appends to vec-active.bin. On
segment rotation, atomic rename to vec-{event_id_hi:08x}.bin. Read path mmaps finalized shard
with no lock contention. For NEOTH actual load (~730k events/year at dim=512 = ~1.5 GB), mmap
entire vector store at startup with madvise(MADV_WILLNEED). Add criterion benchmark: recall p99
across 10k candidates on warm + cold cache before claiming the p95 SLA.

---

### HP-3: Profile Extraction - Missing connect_timeout, 127s TCP Stall During Provider Outage

**Spec claim:** SPEC_proactive_learning section 3.1: max_duration_ms: 8000. Triggered on every
PROVIDER_RESPONSE event.

**Conflict:** tokio::time::timeout(Duration::from_millis(8000), future) wraps the reqwest
future. reqwest::ClientBuilder has two independent timeout controls: .timeout(Duration) for
total request time and .connect_timeout(Duration) for TCP connect phase only. Spec mentions
neither. Naive impl sets only .timeout().

If Gemini endpoint becomes unreachable after DNS resolves (TCP SYN sent, no SYN-ACK), OS
tcp_syn_retries=6 fires at ~127 seconds on Linux. tokio timeout() drops the future but does NOT
close the underlying TCP socket - hyper/reqwest holds it in the connection pool until OS timeout.
During provider incident: 10 concurrent profile pipelines drain 10 pool slots. timeout() returns
Elapsed after 8s, pipeline logs it, emits nothing. No ProfileDelta. Block-B profile stale
indefinitely with no operator alert.

**Remediation:**
- reqwest::ClientBuilder::connect_timeout(Duration::from_millis(3000)) - set separately from .timeout()
- .pool_max_idle_per_host(4) - bound slots per provider endpoint
- Use rustls-tls feature (not native-tls) - avoids cert store divergence Windows dev vs Linux
- Add PROFILE_EXTRACT_SKIPPED WAL sub-event on Elapsed error, visible via neoth wal tail

---

### HP-4: HLC expect() Panic on Logical Counter Overflow

**Spec claim:** SPEC_multinode_clock section 3.1 uses .checked_add(1).expect() on a u32
logical counter in both hlc_tick_local and hlc_tick_receive.

**Conflict:** Single-node production: u32::MAX requires 4 billion events in one nanosecond -
unreachable. But three real attack vectors exist:

1. Migration tool (Phase 3): SPEC_multinode_clock section 5.3: bulk-imported Jarvis files
sharing identical mtime_ns (FAT32/ext4 1-second granularity) increment logical for each
co-timed event. A migration bug synthesizing logical = u32::MAX - 1 causes next hlc_tick_receive
call to .expect() on u32::MAX, panicking the task.

2. Async task crash semantics: .expect() in a tokio task panics the task. Tokio does NOT
restart tasks by default. WalWriterTask panic means neothd continues running but WAL writes
silently dropped. Channel senders receive SendError. No operator alert specified in spec.

3. Adversarial unit tests: any test calling hlc_tick_receive with fabricated peer HLC having
logical = u32::MAX triggers panic without mTLS involved.

**Remediation:** Replace expect with graceful overflow:

Emit WAL event 0x2F CLOCK_LOGICAL_OVERFLOW parallel to existing 0x2E CLOCK_SKEW_DETECTED.
Add test_hlc_logical_overflow_does_not_panic to SPEC_multinode_clock section 8 test plan.

---

### HP-5: repr(C, packed) - Misaligned Reference UB in WAL Reader

**Spec claim:** SPEC_wire_header_v2_slim section 3 defines EventHeaderV2 as repr(C, packed)
with multi-byte fields at misaligned offsets: event_id u64 at bytes 21-28 (not 8-byte aligned),
ts_ns u64 at bytes 29-36 (not 8-byte aligned), importance f32 at bytes 37-40 (not 4-byte aligned).
Same issue in PayloadPrefixV4 (122 bytes, section 5).

**Conflict:** In Rust, creating a reference to a field of a repr(C, packed) struct with
alignment > 1 is undefined behavior. The statement "let id = header.event_id;" in safe Rust
creates an implicit &u64 pointing to a 1-byte-aligned address. Rust reference rules require
&u64 to be 8-byte aligned. This is UB.

On x86/x86_64: misaligned loads work at hardware level (performance penalty). UB invisible.
On aarch64 (ARM), MIPS, RISC-V: strict alignment enforced. Misaligned load = SIGBUS.

cargo miri test flags every multi-byte field access on a packed struct as an error. Miri CI
is blocked entirely on WAL module tests. bytemuck::Pod cannot be implemented for packed structs.
Zero-copy parse via bytemuck::from_bytes is unavailable.

**Failure mode:** NEOTH on aarch64 (Hetzner ARM VPS, future Veronica node): WAL reader SIGBUS
on first frame scan. First cargo miri test run: all WAL module tests blocked.

**Remediation:** Remove repr(C, packed). Parse frames as [u8; 96] with explicit byte-offset reads:

Miri-clean, all platforms, identical x86 performance, bytemuck-composable. Apply same fix to
PayloadPrefixV4. Add test_wal_header_parse_miri_clean running under miri in CI.

---

### HP-6: WAL Index View Update - Recovery Gap

**Spec claim:** SPEC_proactive_learning section 1.3: idx_profile is a materialised view over
all non-tombstoned non-REDACTED Hypothalamus events.

**Conflict:** Spec defines view semantics but not the live update trigger. Natural impl: after
WalWriterTask appends an event, sends IndexUpdateMsg to IndexMaintainerTask over a separate
channel. If neothd crashes while message is queued (WAL frame fsynced, index update not yet
processed), in-memory index diverges from WAL. On restart, WAL replay rebuilds index - but
SPEC_wal_lifecycle section 5.4 recovery scan covers only vector blob orphans. No general index
rebuild procedure specified. No test for startup rebuild == live index.

**Failure mode:** Post-crash, idx_profile reflects different confidence state than before crash.
Block-B injects wrong confidence-gated fields. neoth profile show shows wrong values.

**Remediation:** Add tests/wal_recovery.rs::test_startup_index_rebuild_matches_live_index:
1. Write 1000 WAL events including 50 Hypothalamus events via WalWriterTask
2. Wait for index updates to drain
3. Serialize idx_profile to JSON (snapshot A)
4. Simulate crash: drop tasks, clear in-memory state
5. Restart: replay WAL, rebuild index
6. Serialize idx_profile to JSON (snapshot B)
7. Assert A == B byte-for-byte
This test is absent from all current spec test plans.

---

### HP-7: Profile PII Gate - Extraction vs Injection Asymmetry

**Spec claim:** SPEC_proactive_learning section 7.2: profile.learn.health = false prevents
health field extraction.

**Conflict:** Gate applies to profile.extract only - prevents new PROFILE_DELTA events. Does
NOT gate Block-B injection. Historical health PROFILE_DELTA events remain in idx_profile with
decaying confidence. Default decay_rate = 0.995: 138 days to half-confidence, 276 days to
auto-drop (< 0.1). After user disables health learning, health data continues appearing in
Block-B for up to 276 days. GDPR-relevant: user intent to stop sharing health data is not
honored for existing claims.

**Remediation:** One-line fix in profile::inject_into_block_b(): skip fields whose category
is disabled in freedom.yaml regardless of confidence. Update test_profile_pii_opt_in_required
(section 10 test 7): assert that after health = false, Block-B contains no health fields even
when historical PROFILE_DELTA WAL events exist with confidence above the injection floor.

---

### HP-8: inventory Crate - Silent Registration Failure on Windows GNU Target

**Spec claim:** SPEC_skill_plugin_system section 1: plugins use inventory crate at compile-time
link. No WASM. Note: INDEX.md erroneously says WASM via wasmtime - live doc contradiction. Fix
INDEX.md before any contributor onboards: cargo add wasmtime = +15 MB binary, wrong API.

**Conflict:** inventory (v0.3) uses #[link_section] to place hook registrations in custom
ELF/PE sections. On Linux/macOS: reliable. On x86_64-pc-windows-gnu (MinGW + GNU ld, default
Rust target on Windows without VS installed): GNU ld GCs custom link sections without
--whole-archive. Hooks silently fail to register. Zero error. Zero warning.

Development is on Windows. cargo build succeeds on both platforms. Tests calling hook functions
directly pass on both. Tests using inventory::iter::<Hook>().count() return 0 on Windows.
Bug invisible until Linux deployment shows behavioral difference.

**Remediation:** Add to .cargo/config.toml:

    [target.x86_64-pc-windows-gnu]
    rustflags = ["-C", "link-arg=-Wl,--whole-archive", "-C", "link-arg=-Wl,--no-whole-archive"]

Or use x86_64-pc-windows-msvc target (VS Build Tools, free). Add
tests/plugin_registration.rs::test_all_hooks_registered asserting inventory::iter count > 0.
Converts silent failure to loud Day-1 error.

---

## ROUND 2 - Spec Defense vs Real Rust Reality

| Hot-Path | Spec Defense | Where Defense Fails |
|----------|-------------|---------------------|
| HP-1 WAL append | mmap-pinned for append performance | MmapMut::flush() is msync not fsync. XFS nobarrier: frames silently lost on power-loss without CRC detection. Group-commit never defined in code path. |
| HP-2 Recall join | LRU cache of sealed segments | LRU covers sealed segments only. Active shard is MmapMut write-locked. Cold recall on newest events violates p95 < 30ms. |
| HP-3 Profile TCP | time_max_ms: 8000 budget | tokio timeout wraps future; OS TCP SYN timeout (~127s) controls connect phase independently. reqwest::connect_timeout() must be set explicitly. |
| HP-4 HLC panic | None - spec uses .expect() directly | .expect() panics the async task. Tokio does not restart tasks. WAL writes silently dropped. No operator alert in spec. |
| HP-5 packed UB | None - spec does not address alignment | UB invisible on x86. cargo miri test fails. ARM/RISC-V SIGBUS. bytemuck incompatible. |
| HP-6 Index rebuild | materialised view defined, not implemented | No live-update path specified. No recovery test. Post-crash index diverges by events in unprocessed queue. |
| HP-7 PII injection | freedom.yaml gates extraction | Gate is extraction-only. Historical claims remain in Block-B for up to 276 days after PII flag disabled. GDPR-relevant. |
| HP-8 inventory | inventory crate at compile-time link | Windows GNU ld GCs link sections without --whole-archive. Hooks silently not registered. Function-call tests pass; inventory::iter returns 0. |

---

## ROUND 3 - Orthogonal Implementation Gotchas

### R3-1: Cancel-Safety and Mid-WAL-Append Futures

profile_learn.yaml uses max_duration_ms: 8000. Tokio cancels futures by dropping them. With the
spec current MmapMut approach, a partial memcpy into the mmap window is not detectable by CRC
check until the frame is complete. Partial bytes appear as stale data that the sequential reader
may misinterpret as the next frame magic preamble, silently corrupting scan position.

With recommended WalWriterTask (HP-1 remediation), cancel-safety is guaranteed: mpsc::Sender::send
is atomic. The WalEvent is either in the channel queue or it is not. WAL append only happens
inside the writer task, which is never cancelled. Document this constraint explicitly so
contributors do not bypass the channel with direct file writes.

### R3-2: hf-hub Downloads 600 MB During First cargo test

Phase 2 introduces candle-transformers for Qwen3-0.6B. Transitive dep hf-hub calls
huggingface.co at runtime on first model load via from_pretrained(). cargo build is clean
offline. But cargo test for any test instantiating the embedding model downloads ~600 MB.
In CI (offline or rate-limited), embedding tests fail with a network error indistinguishable
from a test assertion failure. No spec test plan mentions this.

Remediation: Set HF_HUB_OFFLINE=1 in CI. Pre-download model to ~/.cache/huggingface/hub/ on
debian VM once. Add cargo feature offline_test that swaps candle for a stub returning zeroed
f32 vectors. Gate embedding integration tests behind #[cfg(not(feature = "offline_test"))].
Add to Phase 2 Day 38 checklist.

### R3-3: INDEX.md WASM Contradiction - Pre-Contributor Fix Required

INDEX.md Component Specs: Plugin (WASM via wasmtime).
SPEC_skill_plugin_system section 1: No WASM (single-binary constraint Q1). inventory is the
only Q1-compliant option. WASM rejected: WASI does not cover mmap-backed WAL, +12 MB binary,
sandbox escape surface for vault.

A contributor reading INDEX.md will cargo add wasmtime on Day 1. First-contributor trap.
Fix INDEX.md plugin row before any contributor onboards: Plugin = compiled-in Rust via inventory
crate. WASM explicitly rejected (SPEC_skill_plugin_system section 1). Do not add wasmtime.

---

## Top 5 Phase 1 Breakers

Phase 1 scope: WAL core, Telegram channel, basic recall, no profile extraction.

| Rank | Hot-Path | Failure Mode | Discovery Point |
|------|----------|-------------|----------------|
| 1 | HP-5: packed struct UB | Silent miscompilation non-x86; miri blocked; bytemuck incompatible | First cargo miri test or aarch64 deploy |
| 2 | HP-1: MmapMut != fsync | WAL frames silently lost on power-loss, no CRC detection | First crash-safety test on XFS or ext4-writeback |
| 3 | HP-4: HLC expect() panic | Daemon crash, silent WAL drop, no operator alert | Migration tool sim or adversarial unit test |
| 4 | HP-6: Index rebuild gap | Post-crash idx_profile diverges from WAL state | First crash-recovery integration test |
| 5 | HP-8: inventory on Windows | Plugin hooks silently not registered on Windows GNU target | Day-1 plugin test using inventory::iter |

HP-3 and HP-7 are Phase 2 breakers (profile extraction ships Day 38-42).

---

## The One Architectural Decision That Simplifies Multiple Hot-Paths

**Replace MmapMut on the active write segment with a dedicated WalWriterTask owning a tokio::fs::File.**

Single change. Resolves four independent hot-paths:

- HP-1 (group-commit): Channel drain IS the batch. One sync_data().await per drain = true
  group-commit. No msync vs fsync ambiguity.
- HP-4 (HLC panic): HLC tick inside WalWriterTask. Overflow returns Err to mpsc sender,
  not a task panic.
- HP-6 (index rebuild): Index updates go through same ordered channel. WAL append and index
  update always sequenced. No async gap between append and index state.
- R3-1 (cancel-safety): mpsc::send() is atomic. Cancelled pipeline futures never produce
  partial WAL frames.

Sealed-segment read path retains memmap2::Mmap (read-only, Sync, no UB, OS page cache). The split:

    WRITE: mpsc::Sender<WalEvent> -> WalWriterTask -> tokio::fs::File (O_DSYNC) -> batch sync_data()
    READ:  WalMmapWindow { sealed: LruCache<u64, Mmap> } -> zero-copy frame scan

This pattern is used by TiKV raft-engine, RocksDB WAL, and glommio DmaFile. Proven production
lineage for exactly this workload: single-writer append + multi-reader scan. All required crates
(tokio::fs, bytes, memmap2) are either in the Day-1 dep list or already in spec. No experimental
crates required.
