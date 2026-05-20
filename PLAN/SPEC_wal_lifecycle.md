# SPEC: WAL Lifecycle — NEOTH v1.1

**Version:** 1.1
**Last-Updated:** 2026-05-16
**Implementation-Status:** PARTIAL — Hot tier + segment rotation + HMAC compaction + archive SHIPPED at `SRC/neothd/src/wal/{writer, compaction, segment_header, builder}.rs`. SQLite-local warm + cold tiers SHIPPED at `memory/{store, tiers, consolidate}.rs`. S3-backed cold + zstd-3 compression DEFERRED to Phase 4 / v1.2. SQLite SCHEMA_VERSION = 8 (idx_profile + idx_profile_redactions). WAL segment format version = 1; event_schema_version = 4 (canonical, see SPEC_wire_header_v2_slim §6 migration policy).
<!-- revision: 2026-05-16  status: PARTIAL (Hot/Warm/Cold shipped local-only; S3 cold backend Phase 4)  fixes: S5/S6/S7 from ADVERSARIAL review all SHIPPED -->

## 1. Segment Model

### 1.1 Directory Layout

```
~/.neoth/wal/
  wal-00000001.bin            # active segment (append target)
  wal-00000000.bin            # sealed segment
  wal-00000000.bin.cpt        # compacted replacement (atomic rename pending)
  wal-00000000.bin.cpt.hmac   # HMAC-SHA256 over .cpt content (S5 fix)
  WAL_SEQ                     # current sequence number
  vectors/
    vec-00000000.bin          # vector blob shard (event_id_hi = 0x00000000)
    vec-00000001.bin
```

### 1.2 Segment Naming

Segments are named `wal-{seq:08x}.bin` where `seq` is a monotonically increasing u64 counter stored in `~/.neoth/wal/WAL_SEQ` (atomic write on each rotation). The active segment is always the highest-numbered `.bin` file in the directory.

### 1.3 Rotation Triggers

A segment is sealed and a new one started when any of:

| Trigger | Condition | Default |
|---------|-----------|---------|
| Size | segment file >= `size_limit_bytes` | 256 MiB |
| Age | segment age >= `age_limit_hours` since first write | 24 h |
| Generation | event generation number changes | any change |
| Manual | `wal.rotate` Effect Adapter called (Framework v4.1 B.5) | on demand |

Rotation procedure:
1. Final fsync(2) on active segment file fd
2. Flush + close WalWriterTask's File handle
3. Open new file `wal-{seq+1:08x}.bin`
4. fsync(2) on wal/ directory fd (for entry visibility)
5. Atomic write `WAL_SEQ` (write to temp + rename)
6. fsync(2) on wal/ directory fd again

---

## 2. Segment Header

Every segment file begins with a 60-byte header written once at creation time.

```rust
/// SegmentHeader — 60 bytes, little-endian throughout.
/// Written at file offset 0; immutable after creation.
/// Magic: b"NEOT-SEG" (v1.1 brand-aligned).
#[derive(Clone, Copy, Debug)]
pub struct SegmentHeader {
    pub magic:                  [u8; 8],   // b"NEOT-SEG"
    pub segment_format_version: u32,       // LE = 1
    pub generation:             u32,       // LE; generation of first event in segment
    pub segment_seq:            u64,       // LE; matches the seq in filename
    pub first_event_id:         u64,       // LE; event_id of first frame in segment
    pub segment_start_ts_ns:    u64,       // LE; ts_ns of first frame
    pub node_id:                [u8; 16],  // UUID v7 of writing node
    pub header_crc32c:          u32,       // LE; CRC32c of bytes [0..56)
}
// static_assert: 60 bytes wire-encoded
```

Wire layout:
```
[0..8)     8   u8[8]   --   magic = b"NEOT-SEG"
[8..12)    4   u32     LE   segment_format_version = 1
[12..16)   4   u32     LE   generation
[16..24)   8   u64     LE   segment_seq
[24..32)   8   u64     LE   first_event_id
[32..40)   8   u64     LE   segment_start_ts_ns
[40..56)  16   u8[16]  --   node_id (UUID v7)
[56..60)   4   u32     LE   header_crc32c (CRC32c of [0..56))
```

Startup validation: read first 60 bytes, verify magic, recompute CRC32c over `[0..56)`, compare to `header_crc32c`. Mismatch → `Err(WalError::SegmentHeaderCorrupt { seq })`.

S8-conformance: no `#[repr(C, packed)]`. Explicit `from_le_bytes(&[u8; 60])` and `to_le_bytes() → [u8; 60]` per `SPEC_wire_header_v2_slim.md §11` pattern.

---

## 3. Active Segment Write Path (S6+S7 fix: NO MmapMut)

### 3.1 WalWriterTask Architecture

**Problem v0.8 (S6+S7):** Active segment used `MmapMut`. Any same-user process could overwrite arbitrary header bytes (e.g., `importance = 0.0f32`) → silent erasure on next compaction. `MmapMut::flush()` calls `msync(MS_SYNC)`, not `fsync(2)` — on XFS with `nobarrier` (NVMe default), no drive cache flush barrier; power loss between `msync` and platter write drops frames silently with no CRC trace.

**Fix v1.1:** Dedicated `WalWriterTask` owns a `tokio::fs::File` opened with `O_APPEND | O_WRONLY`. ALL writes go through an mpsc channel into this task. No `MmapMut` on active segment. Sealed segments use read-only `memmap2::Mmap` only — same-user processes can map and read but cannot write.

```rust
use tokio::sync::mpsc;
use tokio::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;

pub struct WalWriterTask {
    file:           File,
    file_fd:        i32,           // for raw fsync(2) syscall
    dir_fd:         i32,           // for parent-dir fsync after rotation
    sender:         mpsc::Sender<WriteRequest>,
    receiver:       mpsc::Receiver<WriteRequest>,
    pending:        Vec<WriteRequest>,
    last_fsync_at:  Instant,
    fsync_interval: Duration,      // default 50ms group-commit window
    segment_seq:    u64,
    segment_bytes:  u64,
    size_limit:     u64,           // 256 MiB
}

pub struct WriteRequest {
    pub frame:           Bytes,       // serialized full frame (magic..CRC)
    pub durability:      Durability,  // BatchedFsync | ImmediateFsync
    pub completion:      oneshot::Sender<Result<(u64, Hlc), WalError>>,
}

pub enum Durability {
    BatchedFsync,    // joins next group-commit (≤50ms)
    ImmediateFsync,  // forces fsync immediately (for cutover/critical events)
}
```

### 3.2 Open with O_APPEND, NOT MmapMut

```rust
async fn open_active_segment(path: &Path) -> Result<File, WalError> {
    OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(path)
        .await
        .map_err(WalError::Io)
}
```

`O_APPEND` guarantees that every `write(2)` syscall is atomic-at-fd-level even with multiple concurrent writers — but in NEOTH only the WalWriterTask holds the fd, so concurrency is moot. The flag is defense-in-depth.

### 3.3 Group-Commit fsync (S7 fix: real fsync not msync)

```rust
impl WalWriterTask {
    pub async fn run(mut self) -> Result<(), WalError> {
        let mut tick = tokio::time::interval(self.fsync_interval);
        loop {
            tokio::select! {
                Some(req) = self.receiver.recv() => {
                    let written = self.write_frame(&req.frame).await?;
                    self.pending.push(req);

                    // Check size rotation
                    self.segment_bytes += written as u64;
                    if self.segment_bytes >= self.size_limit {
                        self.fsync_and_complete_batch().await?;
                        self.rotate_segment().await?;
                    }
                }
                _ = tick.tick() => {
                    if !self.pending.is_empty() {
                        self.fsync_and_complete_batch().await?;
                    }
                }
            }
        }
    }

    /// Real fsync(2) — NOT MmapMut::flush()/msync.
    /// On Linux: fdatasync(fd) since file metadata is unchanged after append.
    /// fdatasync forces drive cache flush barrier even with mount option nobarrier.
    async fn fsync_and_complete_batch(&mut self) -> Result<(), WalError> {
        // tokio::fs::File::sync_data() = fdatasync(2) — POSIX-compliant cache barrier
        self.file.sync_data().await?;
        let new_hlc = self.compute_post_batch_hlc();
        for req in self.pending.drain(..) {
            let _ = req.completion.send(Ok((self.segment_bytes, new_hlc)));
        }
        self.last_fsync_at = Instant::now();
        Ok(())
    }

    async fn write_frame(&mut self, frame: &[u8]) -> Result<usize, WalError> {
        use tokio::io::AsyncWriteExt;
        self.file.write_all(frame).await?;
        Ok(frame.len())
    }

    /// Rotation: final fsync, close current, open next, fsync dir.
    async fn rotate_segment(&mut self) -> Result<(), WalError> {
        self.file.sync_data().await?;
        // Drop current File (closes fd)
        let new_seq = self.segment_seq + 1;
        let new_path = wal_dir().join(format!("wal-{:08x}.bin", new_seq));
        let mut new_file = open_active_segment(&new_path).await?;
        write_segment_header(&mut new_file, &SegmentHeader::new(new_seq, ..)).await?;
        new_file.sync_data().await?;
        // fsync parent directory so the new file's directory entry is durable
        fsync_dir(wal_dir()).await?;
        // Atomic update WAL_SEQ
        write_wal_seq_atomic(new_seq).await?;
        fsync_dir(wal_dir()).await?;
        self.file = new_file;
        self.segment_seq = new_seq;
        self.segment_bytes = 60; // header size
        Ok(())
    }
}

async fn fsync_dir(dir: &Path) -> std::io::Result<()> {
    let dir_file = File::open(dir).await?;
    dir_file.sync_data().await
}
```

### 3.4 Why this fixes S6 and S7

- **S6**: No `MmapMut` exposed for the active segment. Same-user processes can `open(O_RDONLY)` but cannot write to the segment file because they don't own the fd. (Note: same-user processes COULD still `open(O_WRONLY)` the segment file if file permissions allow — fix: chmod 0600 on segment files; documented in §3.6.)
- **S7**: `tokio::fs::File::sync_data()` calls `fdatasync(2)` on Linux. `fdatasync(2)` forces drive cache flush barrier regardless of mount option (this is exactly what `nobarrier` does NOT bypass — see ext4/xfs docs). Power loss between `write_all` and `sync_data` may lose un-fsynced events, but those events' completion `Result` is never sent to the caller — caller knows the write didn't durably complete.

### 3.5 Sealed Segment Read Path (read-only Mmap, safe)

Sealed segments are opened read-only:

```rust
use memmap2::Mmap;

pub fn open_sealed_segment(path: &Path) -> Result<Mmap, WalError> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .open(path)?;
    // SAFETY: Mmap (not MmapMut) is read-only. File is sealed by rotation
    // (no further appends). Same-user processes can still write to the
    // underlying file via raw fd if they have permissions, but NEOTH only
    // ever reads sealed segments — MmapMut is never used.
    let mmap = unsafe { Mmap::map(&file)? };
    Ok(mmap)
}
```

LRU cache (≤8 segments) of read-only `Mmap` for hot recall path. On miss, fall through to `std::fs::read` synchronous read.

### 3.6 Filesystem Permission Hardening

`~/.neoth/wal/` directory: mode `0700` (operator-only).
Segment files: mode `0600` written via `umask(0077)` set at daemon startup.
Vector blob files: same.

Documented in `Day-1 §1` of `00_DESIGN_v1.1_FINAL.md`.

---

## 4. Compaction Policy

### 4.1 Threshold and Scheduling

Compaction runs when a sealed segment has `tombstone_count / total_count >= 0.30` (30% threshold). The `wal_compact` pipeline runs daily at 03:30 local time via cron. Segments below threshold are skipped.

### 4.2 GC Eviction Strategy

Events selected for eviction during compaction must satisfy ALL of:

1. `flags & TOMBSTONE != 0` OR `flags & SUPERSEDED != 0`
2. `importance < eviction_importance_floor` (default 0.1)
3. `ts_ns < now_ns - eviction_age_ns` (default 30 days)

Events with `importance >= eviction_importance_floor` are retained regardless of tombstone status — prevents GC from destroying high-value events.

### 4.3 Atomic Compaction with HMAC-SHA256 (S5 fix)

**Problem v0.8 (S5):** Crash-recovery applied `.cpt` files without authenticity check. CRC32c is non-cryptographic — trivially computed. Attacker could pre-place a crafted `.cpt` file with valid CRC32c → next NEOTH restart applies it → full WAL history rewrite, injected Hypothalamus events bypass single-writer gate (applied pre-ingress).

**Fix v1.1:** Every `.cpt` file has a paired `.cpt.hmac` file containing HMAC-SHA256 over the `.cpt` content, keyed with a node-local secret stored in the OAuth vault (NOT a static key — bound to vault unlock = bound to operator presence).

```
~/.neoth/wal/
  wal-00000017.bin.cpt        # compacted replacement
  wal-00000017.bin.cpt.hmac   # HMAC-SHA256 over .cpt content (32 bytes)
```

```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const WAL_CPT_HMAC_KEY_LABEL: &[u8] = b"neoth.wal.cpt.v1";

pub struct CompactionAuthenticator {
    /// Derived from operator vault key + label. Stays in memory only.
    key: [u8; 32],
}

impl CompactionAuthenticator {
    pub fn from_vault(vault_key: &[u8; 32]) -> Self {
        let key = derive_key(vault_key, WAL_CPT_HMAC_KEY_LABEL);
        Self { key }
    }

    /// Compute HMAC-SHA256 over .cpt content. Caller writes result alongside .cpt as .cpt.hmac.
    pub fn sign_cpt(&self, cpt_content: &[u8]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .expect("HMAC key length always valid");
        mac.update(cpt_content);
        mac.finalize().into_bytes().into()
    }

    /// Verify .cpt.hmac matches .cpt content. Returns Err if tampered or missing.
    pub fn verify_cpt(&self, cpt_content: &[u8], hmac_bytes: &[u8; 32]) -> Result<(), WalError> {
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .expect("HMAC key length always valid");
        mac.update(cpt_content);
        mac.verify_slice(hmac_bytes)
            .map_err(|_| WalError::CompactionAuthFailed)
    }
}
```

Compaction procedure (Effect Adapter, idempotency_key = `{segment_seq}_{compaction_epoch}`):

```
1. Write surviving events to wal-{seq:08x}.bin.cpt.tmp (temp file)
2. fdatasync wal-{seq:08x}.bin.cpt.tmp
3. Read .cpt.tmp content, compute HMAC, write to .cpt.tmp.hmac
4. fdatasync .cpt.tmp.hmac
5. Atomic rename: .cpt.tmp.hmac → .cpt.hmac
6. fsync directory
7. Atomic rename: .cpt.tmp → .cpt
8. fsync directory
9. Crash-safe point reached. Apply step below if next startup resumes here.
10. Verify .cpt.hmac matches .cpt (defense-in-depth even on same process)
11. Atomic rename: .cpt → .bin (atomic replace)
12. Delete .cpt.hmac (no longer needed; replaced .bin has no .hmac)
13. fsync directory
14. GC orphaned vector blobs for evicted event_ids (see §6)
```

**Crash-recovery (S5 fix):** On startup, for any `.cpt` file present:
1. Compute HMAC over `.cpt` content
2. Read paired `.cpt.hmac` file
3. **If `.cpt.hmac` missing OR HMAC mismatch: DELETE `.cpt` and `.cpt.hmac`.** Refuse to apply. Emit `0x40 COMPACTION_AUTH_FAILED` WAL event. Operator notified.
4. If valid: apply rename step 11+ above.

Without the vault key (which requires operator unlock), an attacker cannot forge a valid HMAC. Pre-placing crafted `.cpt` files now requires either:
- Stealing the operator's vault key (which requires operator credentials — much higher bar than file write access)
- Or attempting unlock — which is rate-limited and audited

### 4.4 wal_compact.yaml Pipeline (Framework v4.1 C.1)

```yaml
pipeline_name: wal_compact
version: 1.1.0
execution_model:
  type: sequential
schedule:
  cron: "30 3 * * *"
stages:
  - name: scan_candidates
    tool: wal.scan_segments
    input: { threshold_pct: 30 }
  - name: compact
    tool: wal.compact
    effect_adapter: true
    idempotency_key: "{segment_seq}_{compaction_epoch}"
    requires_vault_unlock: true        # NEW v1.1: HMAC key from vault
  - name: reap_tombstones
    tool: wal.tombstone_reaper
    effect_adapter: true
    idempotency_key: reap_run_id
```

### 4.5 New WAL Event Types (v1.1)

| Type | Name | Region | Purpose |
|------|------|--------|---------|
| 0x40 | `COMPACTION_AUTH_FAILED` | None | `.cpt.hmac` verification failed — possibly malicious or filesystem corruption |
| 0x41 | `COMPACTION_STARTED` | None | begin compaction of segment X |
| 0x42 | `COMPACTION_COMPLETED` | None | compaction of segment X succeeded, evicted N events |

---

## 5. Tombstone Reaper

The tombstone reaper runs as the `reap_tombstones` stage inside `wal_compact`. It scans all sealed segments for events where `flags & TOMBSTONE != 0` AND `ts_ns < now_ns - 30_days_ns`. Qualifying events are marked for eviction on next compaction pass regardless of importance score.

30-day grace period ensures tombstoned events still accessible via recall for one month — supports audit and undo.

Reaper output: a reap manifest written to `~/.neoth/wal/reap-{run_id}.json` listing all evicted event_ids and their associated vector blob offsets.

---

## 6. Vector Blob Store

### 6.1 Shard Layout

Vector blobs stored in shard files at `wal/vectors/vec-{event_id_hi:08x}.bin` where `event_id_hi` is upper 32 bits of `event_id`. Caps shard size at ~8M events per shard for typical embedding sizes.

### 6.2 Blob Format (VEC0)

```
[0..4)         b"VEC0"    magic
[4..8)         model_id   u32 LE
[8..10)        dim        u16 LE
[10..12)       _pad       u16 = 0
[12..12+N*4)   floats     N × f32 LE  (N = dim)
[12+N*4..+4)   crc32c     u32 LE
```

For `dim=1024` (Qwen3-Embedding-0.6B-Q8): 12 + 1024×4 + 4 = 4112 bytes per blob.

### 6.3 Write Ordering (Crash Safety)

```
1. Append blob to vec-{shard}.bin
2. fdatasync vec-{shard}.bin
3. Write WAL event (with vector_blob_off pointing to the blob)
4. fdatasync WAL segment
```

### 6.4 Recovery Scan

On startup, after loading WAL index, scan all events with `vector_blob_off != 0`. For each: read blob at stored offset, verify VEC0 magic and crc32c. On failure: emit `0x31 EMBED_REPAIR_NEEDED` event with affected `event_id`. Orphaned blobs (blob exists but no WAL event references it) listed in recovery manifest, GCed during next compaction.

### 6.5 Compaction GC

When a WAL event is evicted, its `vector_blob_off` is recorded in the reap manifest. After WAL rename completes, shard file is rewritten omitting evicted blobs. Same atomic temp+fsync+rename procedure. Vector blobs are **never compressed** (random-access needed).

---

## 7. Disk-Full Policy

Configured in `storage.toml`:

```toml
[storage]
wal_dir = "~/.neoth/wal"

[storage.disk_thresholds]
warn_pct          = 70
stop_raw_text_pct = 80
read_only_pct     = 90
refuse_start_pct  = 95
```

```rust
pub enum DiskPressure {
    Normal,
    Warning,      // >= 70%: emit 0x30 STORAGE_PRESSURE_WARNING
    NoNewRaw,     // >= 80%: reject incoming RAW_TEXT events
    ReadOnly,     // >= 90%: all inbound -> MIRROR-refusal(storage_full)
    RefuseStart,  // >= 95%: daemon refuses to start
}
```

Disk usage checked on startup + every 60 seconds. Transitions strictly monotone-up until compaction completes; compaction may allow downward transition.

At ReadOnly: MIRROR-refusal event (0x2F) written to separate `overflow.log` with max 10 000 entries before log is capped (drop oldest).

---

## 8. Tiering (Phase 4)

| Tier | Storage | Access pattern | Eviction age |
|------|---------|----------------|--------------|
| Hot | Local NVMe (WAL dir) | mmap, <1ms | <= 7 days |
| Warm | Local HDD or compressed NVMe | read on demand, <10ms | <= 90 days |
| Cold | S3-compatible object store | async fetch, <5s | indefinite |

v1.1 ships only Hot tier. Warm/Cold defined to constrain data layout so Phase 4 requires no breaking changes.

---

## 9. Compression

| Data | Format | Level | Rationale |
|------|--------|-------|-----------|
| Active segment | none | — | Minimize write amplification on hot path |
| Compacted segment | zstd | 3 | Balanced CPU/ratio; compacted files are read-heavy |
| Vector blobs | none | — | Float32 arrays compress poorly; hash check covers integrity |

zstd-3 applied per-payload during compaction write. SegmentHeader never compressed. Frames in compacted segment set `flags` bit 5 (COMPRESSED, reserved in v1.1; to be defined in v1.2) to signal payload bytes are zstd-compressed.

---

## 10. Test Plan

Mandatory tests before merging any WAL module PR:

### test_segment_rotation_on_size_trigger
Write events until segment hits 256 MiB. Assert new segment created with seq+1, old segment sealed, WAL_SEQ matches.

### test_compaction_evicts_tombstones_and_preserves_high_importance
60 TOMBSTONE+importance=0.05 (age>30d), 20 TOMBSTONE+importance=0.9, 20 clean. Run compaction. Assert compacted segment contains exactly 40 events.

### test_vector_blob_write_ordering_survives_crash
Simulate crash after blob fsync but before WAL event fsync. On restart: orphaned blob in recovery manifest, no EMBED_REPAIR_NEEDED emitted.

### test_disk_pressure_transitions
Mock statvfs: usage 65, 75, 85, 92, 96. Assert Normal → Warning → NoNewRaw → ReadOnly → RefuseStart. At RefuseStart: `WalWriter::open()` returns `Err(WalError::DiskFull)`.

### test_segment_header_crc_mismatch_returns_error
Corrupt one byte in segment header. Assert `SegmentReader::open()` returns `Err(WalError::SegmentHeaderCorrupt { seq })`.

### test_compaction_auth_failed_rejects_tampered_cpt (NEW v1.1, S5)
1. Run normal compaction → `.cpt` + `.cpt.hmac` written.
2. Tamper one byte in `.cpt`.
3. Simulate restart, recovery scans `.cpt` files.
4. Assert HMAC verification fails.
5. Assert `.cpt` and `.cpt.hmac` DELETED.
6. Assert `0x40 COMPACTION_AUTH_FAILED` event emitted.
7. Assert no `.bin` modification.

### test_no_mmapmut_on_active_segment (NEW v1.1, S6)
Verify via type-system inspection that `WalWriterTask.file` is `tokio::fs::File`, never `memmap2::MmapMut`. Compile-time test via `static_assert::assert_type_eq_all!`.

### test_fdatasync_actually_fsyncs (NEW v1.1, S7)
1. Write event, call `WriteRequest::completion.await` with `Durability::BatchedFsync`.
2. Wait 50ms (group-commit window).
3. Kill -9 the test process.
4. Restart: assert event readable from WAL.
5. Compare to: write event with `Durability::ImmediateFsync`, kill -9 with no wait — event also readable.
6. Negative case: write event, kill -9 immediately (no fsync). Event MAY be lost — assert recovery still produces a consistent (potentially truncated) WAL state, no CRC errors mid-segment.

---

## 11. Status

**v1.1 WAL lifecycle BUILD-READY.** S5 (HMAC auth on .cpt), S6 (no MmapMut on active), S7 (fdatasync not msync) all resolved.
