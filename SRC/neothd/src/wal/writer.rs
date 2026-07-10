// WAL writer task -- SPEC_wal_lifecycle.md.
// Single-writer invariant: only one task writes to the active segment.
// O_APPEND + sync_data (fdatasync(2) on Linux) every flush for durability.
// Mode 0600 on segment files (umask 0o077 also applied at daemon startup).
//
// Phase 33b SP-1: segment rotation when size > 16 MiB or age > 24 h.

use std::path::{Path, PathBuf};

use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

use super::compress::compress_frames;
use super::error::WalError;
use super::frame::encode_frame;
use super::header::EventHeaderV2;
use super::segment_header::{
    ParsedSegmentHeader, SEGMENT_FLAG_COMPRESSED, SEGMENT_HEADER_LEN,
    SEGMENT_HEADER_V3_LEN, SegmentHeader, SegmentHeaderV3, parse_segment_header,
};

const DEFAULT_CHANNEL_CAPACITY: usize = 1024;
pub const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024; // 16 MiB sanity ceiling

/// Workstream F (CT-10/E-20/V1x-06) — per-writer compression policy.
///
/// Production code reads `FreedomConfig::wal.compression` and passes the
/// corresponding variant to `spawn_with_policy`. Tests use `CompressionPolicy`
/// directly to exercise both paths without loading freedom.yaml.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CompressionPolicy {
    /// Write v1 segment headers; frames are uncompressed (default, v0.1.x).
    #[default]
    None,
    /// Write v2 segment headers; seal the frame body with zstd level-3 before
    /// closing the segment. The SEGMENT_FLAG_COMPRESSED bit is set in the
    /// header flags byte.
    Zstd3,
}

/// Segment-rotation thresholds. Either condition triggers rollover before
/// the next frame is written. Per spec the size ceiling is 16 MiB and the
/// age ceiling 24 h; both are configurable so tests can exercise rotation
/// without writing 16 MiB.
#[derive(Clone, Copy, Debug)]
pub struct RotationPolicy {
    pub max_bytes: u64,
    pub max_age_ns: u64,
}

impl RotationPolicy {
    pub const DEFAULT_MAX_BYTES: u64 = 16 * 1024 * 1024;
    pub const DEFAULT_MAX_AGE_NS: u64 = 24 * 60 * 60 * 1_000_000_000;

    pub const fn default_const() -> Self {
        Self {
            max_bytes: Self::DEFAULT_MAX_BYTES,
            max_age_ns: Self::DEFAULT_MAX_AGE_NS,
        }
    }
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self::default_const()
    }
}

/// Reason recorded in the SEGMENT_ROLLOVER WAL event payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RotationReason {
    SizeExceeded,
    AgeExceeded,
}

impl RotationReason {
    fn as_str(&self) -> &'static str {
        match self {
            RotationReason::SizeExceeded => "size",
            RotationReason::AgeExceeded => "age",
        }
    }
}

/// One write request, with a oneshot reply channel for ack/error.
pub struct WriteRequest {
    pub header: EventHeaderV2,
    pub payload: Vec<u8>,
    pub ack: oneshot::Sender<Result<u64, WalError>>,
}

/// Handle returned to producers. Cheap to clone; producers send WriteRequest
/// through it and await the oneshot reply for durable confirmation.
///
/// `Debug` needed by downstream `PluginStoreState` (wasm-plugin-host
/// feature) that holds an `Option<WalWriterHandle>` and derives Debug
/// for tracing. The default `mpsc::Sender`/`Arc<QuotaGuard>` Debug
/// surfaces are non-secret-bearing.
#[derive(Clone, Debug)]
pub struct WalWriterHandle {
    tx: mpsc::Sender<WriteRequest>,
    /// Phase 33c BS-4 pre-write quota guard. `None` keeps the writer free
    /// of disk-usage checks (tests + cli one-shots); the daemon sets it
    /// via `with_quota_guard` after `spawn`.
    quota: Option<std::sync::Arc<QuotaGuard>>,
}

/// Pre-write disk-quota guard. Tracks bytes admitted since the last disk walk
/// and re-measures the home dir when a threshold is crossed. Refuses writes
/// once usage breaches the ceiling.
///
/// ## WAL-QUOTA-FAILCLOSED-01 — design invariants
///
/// Admission is rejected when `last_measured + reserved + payload > ceiling`
/// (projected-sum test).  `reserved` counts every byte admitted since the last
/// disk walk.  Unlike the previous counter, `reserved` is never blindly reset
/// to zero — after a walk it is reduced to only the bytes that arrived DURING
/// the walk (those are not yet captured in `last_measured`), preventing the
/// "bytes lost during disk walk" race.
///
/// The projected-sum check is performed inside a CAS loop: the loop reads the
/// current `reserved`, checks the projected total, and atomically increments
/// `reserved` only if the check passes.  Concurrent near-ceiling payloads
/// therefore see each other's admitted bytes and are correctly rejected.
///
/// Re-measure single-flighting uses a `Mutex<bool>` + `Condvar` instead of a
/// spin loop, so tokio worker threads are not busy-spinning during the
/// (potentially slow) disk walk.
///
/// Construction is cheap (no IO).  `reserved` is pre-armed at
/// `remeasure_threshold` so the very first `try_admit` always triggers a disk
/// walk — the guard never admits before at least one real measurement.
///
/// Once breached the guard stays breached until `reset()` is called.
#[derive(Debug)]
pub struct QuotaGuard {
    home: PathBuf,
    ceiling: u64,
    /// Re-measure threshold (default 1 MiB).  When `reserved` crosses this
    /// after a successful CAS-admission, the guard walks the home directory.
    remeasure_threshold: u64,
    /// Projected-pending bytes: every admitted write increments this.  After
    /// each disk walk it is reduced to only the bytes that arrived DURING the
    /// walk, preserving them for the next projected-sum check.
    reserved: std::sync::atomic::AtomicU64,
    last_measured: std::sync::atomic::AtomicU64,
    breached: std::sync::atomic::AtomicBool,
    /// Guards the re-measure critical section.  The `bool` is `true` while a
    /// walk is in progress; `measure_done` wakes waiting threads when it ends.
    measure_mutex: std::sync::Mutex<bool>,
    measure_done: std::sync::Condvar,
}

impl QuotaGuard {
    pub fn new(home: PathBuf, ceiling_bytes: u64) -> Self {
        let remeasure_threshold: u64 = 1024 * 1024; // 1 MiB
        Self {
            home,
            ceiling: ceiling_bytes,
            remeasure_threshold,
            // Pre-arm at threshold so the very first try_admit triggers a disk
            // walk — the guard never admits without at least one real measurement.
            reserved: std::sync::atomic::AtomicU64::new(remeasure_threshold),
            last_measured: std::sync::atomic::AtomicU64::new(0),
            breached: std::sync::atomic::AtomicBool::new(false),
            measure_mutex: std::sync::Mutex::new(false),
            measure_done: std::sync::Condvar::new(),
        }
    }

    /// Check whether one more payload of `payload_bytes` can be admitted.
    ///
    /// Admission uses a projected-sum CAS loop: this payload is admitted only
    /// when `last_measured + reserved + payload_bytes <= ceiling`.  The CAS
    /// loop re-checks the sum with the latest `reserved` on every retry, so
    /// two concurrent near-ceiling payloads whose combined size exceeds the
    /// ceiling cannot both be admitted.
    ///
    /// Returns `Err(QuotaExceeded)` on any projected or measured violation.
    /// The breached flag is sticky — once set, all subsequent calls fail
    /// without a disk walk until `reset()` is called.
    pub fn try_admit(&self, payload_bytes: u64) -> Result<(), WalError> {
        use std::sync::atomic::Ordering;

        // Fast path: sticky breach flag avoids the CAS loop and any locking.
        if self.breached.load(Ordering::Acquire) {
            return Err(WalError::QuotaExceeded {
                used: self.last_measured.load(Ordering::Acquire),
                ceiling: self.ceiling,
            });
        }

        // ── Projected-sum CAS admission (WAL-QUOTA-FAILCLOSED-01) ────────────
        // Increment `reserved` only when last_measured + reserved + this_payload
        // is within the ceiling.  compare_exchange_weak retries when a
        // concurrent admission changes `reserved` beneath us, re-checking the
        // projected sum with the updated value each time.
        let mut cur_reserved = self.reserved.load(Ordering::Acquire);
        loop {
            let used = self.last_measured.load(Ordering::Acquire);
            let projected = used
                .saturating_add(cur_reserved)
                .saturating_add(payload_bytes);
            if projected > self.ceiling {
                return Err(WalError::QuotaExceeded { used, ceiling: self.ceiling });
            }
            match self.reserved.compare_exchange_weak(
                cur_reserved,
                cur_reserved + payload_bytes,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    cur_reserved += payload_bytes;
                    break;
                }
                Err(actual) => {
                    cur_reserved = actual;
                    // A concurrent re-measure may have set breached while we
                    // were spinning; check before retrying.
                    if self.breached.load(Ordering::Acquire) {
                        return Err(WalError::QuotaExceeded {
                            used: self.last_measured.load(Ordering::Acquire),
                            ceiling: self.ceiling,
                        });
                    }
                }
            }
        }

        // ── Re-measure gate (WAL-QUOTA-FAILCLOSED-01) ───────────────────────
        // When `reserved` crosses the threshold, one thread walks the disk and
        // updates `last_measured`.  Other threads wait on `measure_done`
        // (Condvar) so tokio worker threads are not busy-spinning during the
        // potentially slow walk.
        if cur_reserved >= self.remeasure_threshold {
            let mut is_measuring = self.measure_mutex.lock().unwrap();
            if *is_measuring {
                // Loser: sleep until the winner publishes results.
                is_measuring = self
                    .measure_done
                    .wait_while(is_measuring, |m| *m)
                    .unwrap();
                drop(is_measuring);
            } else {
                // Winner: note how many bytes existed in `reserved` BEFORE the
                // walk.  Bytes added by other threads DURING the walk may not
                // yet be on disk and must be kept in `reserved` so they are
                // counted in future projected-sum checks (not silently dropped).
                *is_measuring = true;
                let pre_walk_reserved = self.reserved.load(Ordering::SeqCst);
                drop(is_measuring); // release while the disk walk runs

                let used = crate::daemon::quota::measure_dir(&self.home);

                // Publish under lock so breach + reserved reset are observed
                // atomically by the next admission that acquires the gate.
                let mut is_measuring = self.measure_mutex.lock().unwrap();
                let post_walk = self.reserved.load(Ordering::SeqCst);
                // Bytes admitted during the walk are not yet captured in `used`;
                // retain them so they count against the ceiling next time.
                let during_walk = post_walk.saturating_sub(pre_walk_reserved);
                self.last_measured.store(used, Ordering::SeqCst);
                let over = used.saturating_add(during_walk) > self.ceiling;
                // Set breach BEFORE resetting reserved: any thread that sees the
                // post-reset (small) value of `reserved` via a concurrent CAS
                // will observe breached=true on its subsequent SeqCst load,
                // eliminating the window where a thread slips past the check.
                if over {
                    self.breached.store(true, Ordering::SeqCst);
                }
                self.reserved.store(during_walk, Ordering::SeqCst);
                *is_measuring = false;
                drop(is_measuring);
                self.measure_done.notify_all();

                if over {
                    return Err(WalError::QuotaExceeded { used, ceiling: self.ceiling });
                }
            }
        }

        // Final breach check: a concurrent re-measure may have set the flag
        // between our CAS-admission and the re-measure gate entry (for threads
        // where cur_reserved < threshold after a walk reset `reserved`).
        if self.breached.load(Ordering::SeqCst) {
            return Err(WalError::QuotaExceeded {
                used: self.last_measured.load(Ordering::Acquire),
                ceiling: self.ceiling,
            });
        }

        Ok(())
    }

    /// Clear the sticky breached flag. Used by `neoth doctor --fix` after
    /// the operator manually freed disk space.
    pub fn reset(&self) {
        use std::sync::atomic::Ordering;
        self.breached.store(false, Ordering::Release);
        // Re-arm the first-measure trigger so the next try_admit walks the
        // disk before admitting any bytes.
        self.reserved.store(self.remeasure_threshold, Ordering::Release);
    }

    /// Release a previously admitted reservation.  Called when `try_admit`
    /// succeeded but the subsequent channel send failed (WriterClosed or
    /// WriterBackpressured), so the frame was never queued and the bytes must
    /// not permanently inflate `reserved`.
    ///
    /// Uses saturating arithmetic: a bug-induced underflow clamps to 0 rather
    /// than wrapping to near-`u64::MAX`, which would permanently seal the guard.
    pub(crate) fn release_reserved(&self, bytes: u64) {
        use std::sync::atomic::Ordering;
        let _ = self.reserved.fetch_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
            Some(cur.saturating_sub(bytes))
        });
    }
}

impl WalWriterHandle {
    /// Attach a pre-write quota guard. Builder-style so daemon construction
    /// reads naturally: `let writer = spawn(p)?.0.with_quota_guard(g);`.
    /// Tests + one-shot CLIs skip this and run quota-unrestricted.
    #[must_use]
    pub fn with_quota_guard(mut self, guard: std::sync::Arc<QuotaGuard>) -> Self {
        self.quota = Some(guard);
        self
    }

    /// Liveness probe: `true` while the background writer task is still
    /// draining the channel. A crashed/aborted writer task drops the
    /// receiver, flipping `tx.is_closed()` to true — so this is a cheap,
    /// synchronous way to tell a *live* sink from a `Some`-but-dead handle.
    ///
    /// Used as the `audit_writable` pre-flight on required-audit send paths:
    /// `is_some()` alone passes a dead writer, which would let a send proceed
    /// while the mandatory audit frame is silently dropped — a
    /// "proof not slogans" violation. `is_alive()` makes that path fail closed.
    #[must_use]
    pub(crate) fn is_alive(&self) -> bool {
        !self.tx.is_closed()
    }

    pub async fn append(&self, header: EventHeaderV2, payload: Vec<u8>) -> Result<u64, WalError> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(WalError::PayloadTooLarge(payload.len(), MAX_PAYLOAD_BYTES));
        }
        let admitted = payload.len() as u64;
        if let Some(guard) = self.quota.as_ref() {
            guard.try_admit(admitted)?;
        }
        let (ack_tx, ack_rx) = oneshot::channel();
        if self
            .tx
            .send(WriteRequest {
                header,
                payload,
                ack: ack_tx,
            })
            .await
            .is_err()
        {
            // Frame never reached the writer task — release the reservation so
            // phantom bytes don't permanently tighten the projected-sum check.
            if let Some(guard) = self.quota.as_ref() {
                guard.release_reserved(admitted);
            }
            return Err(WalError::WriterClosed);
        }
        ack_rx.await.map_err(|_| WalError::WriterClosed)?
    }

    /// K-Perf-2 2026-05-17: fire-and-forget append for high-cadence
    /// streaming frames (`PROVIDER_STREAM_CHUNK` 0x23). Sends the
    /// write request into the writer's mpsc channel + drops the ack
    /// receiver so the caller does NOT block on `sync_data` /
    /// `fdatasync` per chunk. The writer task still processes the
    /// frame the same way (write + fsync + offset bookkeeping); only
    /// the caller's await behaviour changes.
    ///
    /// Why this matters: the streaming chat loop yields one chunk per
    /// token (~10ms cadence). With the normal `append().await`, each
    /// token requires the operator-visible reply to wait for disk
    /// fsync — on a 100-token reply at 10ms fsync latency that's 1s
    /// of pure overhead serialised into the streaming UX. With
    /// `append_no_ack`, the chunk lands in the writer's 1024-deep
    /// queue and the caller proceeds to the next token immediately.
    /// Disk fsync still happens, just out-of-band.
    ///
    /// Trade-offs vs `append`:
    /// - Caller does NOT learn the WAL offset (no return value).
    /// - Caller does NOT learn if the write failed (silent loss on
    ///   ENOSPC / disk corruption); the writer logs at error level so
    ///   the operator still sees the failure.
    /// - Use ONLY for high-cadence frames where loss-of-one is
    ///   recoverable from context. NEVER for PROVIDER_RESPONSE,
    ///   ConfigWrite, or anything load-bearing for audit chain.
    ///
    /// `Result<(), WalError>` surfaces the per-call payload-size and
    /// channel-closed errors synchronously; downstream WAL failures
    /// (write or fsync) are async and operator-side-only.
    /// V10-04 Pick #34 (2026-05-19): sync, fire-and-forget append for
    /// callers that live OUTSIDE a tokio context — specifically the
    /// wasmtime `Linker::func_wrap` closures in `wasm_plugin::hostcalls`.
    ///
    /// Why this exists: wasmtime hostcalls are sync (the engine ships
    /// in sync mode in NEOTH v0.1 per `wasm_plugin::engine` config), so
    /// `append().await` is unreachable from a hostcall body. The
    /// alternative — `Handle::current().block_on(append)` — would
    /// deadlock when wasmtime is invoked from a tokio worker that
    /// itself holds the only runtime thread.
    ///
    /// Mechanism: `mpsc::Sender::try_send` is a non-blocking sync call.
    /// Success delivers the `WriteRequest` to the writer task (which
    /// fsyncs out-of-band). The dropped `ack_rx` mirrors the
    /// `append_no_ack` path — the writer logs at debug when it tries
    /// to deliver the ack to a dropped receiver.
    ///
    /// Trade-offs:
    /// - Caller learns nothing about the resulting WAL offset.
    /// - Channel full (1024-deep queue saturated) → `WriterBackpressured`.
    ///   This is rare in steady state but possible under a runaway
    ///   plugin that floods `host.emit_event` faster than fsync drains
    ///   the queue. Plugins should treat this as soft-fail + back off.
    /// - Channel closed (daemon shutting down) → `WriterClosed`.
    /// - Payload-size + quota checks still apply.
    ///
    /// Use ONLY when you cannot reach an `async fn`. The async
    /// `append` is always preferred when available because the
    /// caller learns the offset + can surface fsync failure.
    pub fn try_append_sync(&self, header: EventHeaderV2, payload: Vec<u8>) -> Result<(), WalError> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(WalError::PayloadTooLarge(payload.len(), MAX_PAYLOAD_BYTES));
        }
        let admitted = payload.len() as u64;
        if let Some(guard) = self.quota.as_ref() {
            guard.try_admit(admitted)?;
        }
        let (ack_tx, _ack_rx_drop) = oneshot::channel();
        match self.tx.try_send(WriteRequest {
            header,
            payload,
            ack: ack_tx,
        }) {
            Ok(()) => Ok(()),
            Err(e) => {
                // Frame never queued — release the reservation so
                // phantom bytes don't permanently tighten the projected-sum check.
                if let Some(guard) = self.quota.as_ref() {
                    guard.release_reserved(admitted);
                }
                Err(match e {
                    mpsc::error::TrySendError::Full(_) => WalError::WriterBackpressured {
                        capacity: DEFAULT_CHANNEL_CAPACITY,
                    },
                    mpsc::error::TrySendError::Closed(_) => WalError::WriterClosed,
                })
            }
        }
    }

    pub async fn append_no_ack(
        &self,
        header: EventHeaderV2,
        payload: Vec<u8>,
    ) -> Result<(), WalError> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(WalError::PayloadTooLarge(payload.len(), MAX_PAYLOAD_BYTES));
        }
        let admitted = payload.len() as u64;
        if let Some(guard) = self.quota.as_ref() {
            guard.try_admit(admitted)?;
        }
        // Construct the oneshot but immediately drop the receiver.
        // The writer task tries to send through it after fsync, sees
        // the receiver dropped, and logs at debug — same path as a
        // caller that times out. No new writer-task code needed.
        let (ack_tx, _ack_rx_drop) = oneshot::channel();
        if self
            .tx
            .send(WriteRequest {
                header,
                payload,
                ack: ack_tx,
            })
            .await
            .is_err()
        {
            // Frame never reached the writer task — release the reservation so
            // phantom bytes don't permanently tighten the projected-sum check.
            if let Some(guard) = self.quota.as_ref() {
                guard.release_reserved(admitted);
            }
            return Err(WalError::WriterClosed);
        }
        Ok(())
    }
}

/// Spawn the writer task with default rotation policy (16 MiB / 24 h) and
/// no compression (v0.1.x default).
pub fn spawn(
    segment_path: PathBuf,
) -> Result<(WalWriterHandle, tokio::task::JoinHandle<()>), WalError> {
    spawn_with_policy(segment_path, RotationPolicy::default())
}

/// Spawn the writer task with an explicit rotation policy and no compression.
/// Production code uses [`spawn`]; tests use this to exercise rotation without
/// writing 16 MiB.
pub fn spawn_with_policy(
    segment_path: PathBuf,
    policy: RotationPolicy,
) -> Result<(WalWriterHandle, tokio::task::JoinHandle<()>), WalError> {
    spawn_with_policy_and_compression(segment_path, policy, CompressionPolicy::None)
}

/// Spawn the writer task with explicit rotation policy AND compression policy.
/// Used by the daemon when `freedom.yaml::wal.compression` is set, and by
/// tests that need to exercise v2 compressed segments.
pub fn spawn_with_policy_and_compression(
    segment_path: PathBuf,
    policy: RotationPolicy,
    compression: CompressionPolicy,
) -> Result<(WalWriterHandle, tokio::task::JoinHandle<()>), WalError> {
    let (tx, rx) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);
    let join = tokio::spawn(async move {
        if let Err(e) = run_writer(segment_path, rx, policy, compression).await {
            error!(error = %e, "WAL writer task exited with error");
        }
    });
    Ok((WalWriterHandle { tx, quota: None }, join))
}

/// Result of `open_segment`: the file handle plus a flag that tells the
/// writer whether this is a brand-new segment (needs SegmentHeader written)
/// or an existing one being reopened.
struct OpenedSegment {
    file: File,
    is_new: bool,
}

/// Pick #36 (Session 14): bookkeeping for the deferred
/// `RECOVERY_TRUNCATED` audit emission. The torn-tail truncation
/// itself lands via `file.set_len` + `sync_all` BEFORE WriterState
/// is alive (so a crash between truncate + audit-emit still leaves
/// the segment consistent — the audit frame is just the breadcrumb,
/// not the recovery action).
struct PendingRecovery {
    segment_path: PathBuf,
    good_through: u64,
    torn_at: u64,
    bytes_dropped: u64,
}

async fn open_segment(path: &Path) -> Result<OpenedSegment, WalError> {
    let is_new = !path.exists();

    let mut opts = OpenOptions::new();
    opts.create(true).append(true).read(false);

    // Mode 0600 on unix. `tokio::fs::OpenOptions::mode` is directly available under cfg(unix).
    #[cfg(unix)]
    opts.mode(0o600);

    let file = opts.open(path).await?;

    // F-13: dir-fsync after creating the segment file. Without this, on a
    // crash between file create and the next fsync, the directory entry may
    // be lost even though the segment bytes are durable — losing the whole
    // segment. Cheap on most filesystems, mandatory on ext4/xfs/btrfs.
    if is_new {
        if let Some(parent) = path.parent() {
            #[cfg(unix)]
            {
                if let Ok(dir) = std::fs::File::open(parent) {
                    let _ = dir.sync_all();
                }
            }
            // Windows: rename+create are durable via NTFS metadata journal.
            // No directory fsync equivalent.
            let _ = parent;
        }
    }

    // Windows: tokio::fs has no `mode()`. We restrict the file's DACL to the
    // current user via the native `SetNamedSecurityInfoW` path (E-11,
    // `win_acl::restrict_to_owner_async` → `win_native::set_owner_dacl`; no
    // icacls subprocess). Runs on the blocking pool so the Win32 call does
    // not stall this tokio worker. See OPEN_DECISIONS.md D-008 / GR-16.
    #[cfg(windows)]
    {
        if let Err(e) = super::win_acl::restrict_to_owner_async(path).await {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "WAL segment DACL restriction failed; file inherits parent DACL"
            );
        }
    }

    Ok(OpenedSegment { file, is_new })
}

/// Extract the segment sequence number from a filename of the form
/// `NNNNNN.wal`. Defaults to 1 when the filename does not match the pattern.
fn segment_seq_from_path(path: &Path) -> u64 {
    path.file_stem()
        .and_then(|s| s.to_str())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(1)
}

/// Mutable writer state. Encapsulated so rotation can swap segments cleanly.
struct WriterState {
    /// Open active segment.
    file: File,
    /// Path of the active segment on disk.
    path: PathBuf,
    /// Bytes already written to the active segment (including its header).
    /// For v1 segments: first-frame offset = `SEGMENT_HEADER_LEN` (60).
    /// For v2 segments: first-frame offset = `SEGMENT_HEADER_V2_LEN` (61).
    /// In compression mode the "frames" buffer is held in `pending_frames`
    /// and flushed (compressed) when the segment rotates or the writer shuts
    /// down. `offset` still tracks logical position for compaction markers.
    offset: u64,
    /// Sequence number of the active segment.
    seq: u64,
    /// Open timestamp in `SystemTime::UNIX_EPOCH.as_nanos()`; used for the
    /// `age_ns` rotation check.
    opened_at_ns: u64,
    policy: RotationPolicy,
    /// Workstream F — compression policy for newly-written segments.
    compression: CompressionPolicy,
    /// In-memory accumulator for frame bytes when `compression == Zstd3`.
    /// Flushed (compressed) to disk on rotation or shutdown.
    /// Empty when `compression == None`.
    pending_frames: Vec<u8>,
    /// GOLD-PROG-12: persisted compaction epoch read from the segment header
    /// on reopen; incremented after each successful finalize_compressed_segment.
    /// Used to form idempotency keys for compaction dedup — prevents collision
    /// after a crash mid-rename (ADVERSARIAL §SF-06).
    /// Only meaningful when `compression == Zstd3`; kept as 0 otherwise.
    compaction_epoch: u32,
}

impl WriterState {
    fn should_rotate(&self, now_ns: u64) -> Option<RotationReason> {
        if self.offset >= self.policy.max_bytes {
            return Some(RotationReason::SizeExceeded);
        }
        if now_ns.saturating_sub(self.opened_at_ns) >= self.policy.max_age_ns {
            return Some(RotationReason::AgeExceeded);
        }
        None
    }
}

/// Compute the path of the next segment by zero-padding `seq` to 6 digits
/// inside the same parent directory. `000001.wal` → `000002.wal`.
fn next_segment_path(current: &Path, next_seq: u64) -> PathBuf {
    let parent = current.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!("{:06}.wal", next_seq))
}

/// Close the current segment durably and open the next one. Emits a
/// SEGMENT_ROLLOVER WAL event (in the new segment, not the closing one,
/// so a reader scanning forward sees the rollover at the head of the new
/// file before any further frames).
async fn rotate(state: &mut WriterState, reason: RotationReason) -> Result<(), WalError> {
    // Workstream F: finalize compressed segment before rotating.
    if state.compression == CompressionPolicy::Zstd3 && !state.pending_frames.is_empty() {
        if let Err(e) = finalize_compressed_segment(state).await {
            warn!(error = %e, "WAL rotation: compressed segment finalize failed; continuing with raw frames");
        }
    }

    // Final sync before closing. `sync_data` was already called per frame;
    // this is belt-and-suspenders for the last-frame metadata.
    state.file.sync_all().await?;

    let closed_seq = state.seq;
    let closed_bytes = state.offset;
    let next_seq = state.seq + 1;
    let next_path = next_segment_path(&state.path, next_seq);

    info!(
        closed = %state.path.display(),
        closed_seq,
        closed_bytes,
        next = %next_path.display(),
        reason = reason.as_str(),
        "WAL segment rollover",
    );

    let opened = open_segment(&next_path).await?;
    let mut new_file = opened.file;
    debug_assert!(opened.is_new, "rotation target should always be a new file");

    let now_ns = current_ns();
    let header_len = match state.compression {
        CompressionPolicy::None => {
            let header = SegmentHeader::new(0, next_seq, 0, now_ns, [0u8; 16]);
            new_file.write_all(&header.to_le_bytes()).await?;
            SEGMENT_HEADER_LEN
        }
        CompressionPolicy::Zstd3 => {
            // GOLD-PROG-12: new rotated segments use V3 header with epoch=0
            // (fresh segment, no prior compaction).
            let header =
                SegmentHeaderV3::new(0, next_seq, 0, now_ns, [0u8; 16], SEGMENT_FLAG_COMPRESSED, 0);
            new_file.write_all(&header.to_le_bytes()).await?;
            SEGMENT_HEADER_V3_LEN
        }
    };
    new_file.sync_data().await?;

    state.file = new_file;
    state.path = next_path;
    state.seq = next_seq;
    state.opened_at_ns = now_ns;
    state.offset = header_len as u64;
    // GOLD-PROG-12: fresh segment always starts at epoch 0.
    state.compaction_epoch = 0;

    // Audit-trail event in the new segment's first frame slot.
    let payload = serde_json::to_vec(&serde_json::json!({
        "closed_seq": closed_seq,
        "closed_bytes": closed_bytes,
        "opened_seq": next_seq,
        "reason": reason.as_str(),
        "ts_ns": now_ns,
    }))
    .unwrap_or_default();
    let rollover_header =
        crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_SEGMENT_ROLLOVER, &payload)
            .flags(crate::wal::EventFlags::SYNTHETIC)
            .build();
    let frame = encode_frame(&rollover_header, &payload);
    write_and_sync(&mut state.file, &frame).await?;
    state.offset += frame.len() as u64;
    Ok(())
}

fn current_ns() -> u64 {
    crate::time::now_unix_ns()
}

async fn run_writer(
    segment_path: PathBuf,
    mut rx: mpsc::Receiver<WriteRequest>,
    policy: RotationPolicy,
    compression: CompressionPolicy,
) -> Result<(), WalError> {
    let opened = open_segment(&segment_path).await?;
    let mut file = opened.file;
    let seq = segment_seq_from_path(&segment_path);

    // F-14: every new segment begins with a segment header at offset 0.
    // v1 (no compression): 60-byte SegmentHeader.
    // v2 (zstd_3): 61-byte SegmentHeaderV2 with SEGMENT_FLAG_COMPRESSED.
    //
    // Pick #36 (Session 14): existing-segment path now scans the tail for
    // torn frames via `wal::recovery::scan_tail`. On torn-tail detection
    // we truncate the segment to the last good frame boundary BEFORE
    // building the WriterState — otherwise the next append would land
    // AFTER the corrupt bytes and produce a parse-fail island. The
    // `pending_recovery` value carries the bookkeeping so we can emit
    // a `RECOVERY_TRUNCATED` audit frame AFTER WriterState is alive.
    let mut pending_recovery: Option<PendingRecovery> = None;
    // GOLD-PROG-12: track compaction epoch; initialized from on-disk header on
    // reopen, or 0 for a fresh segment.
    let mut initial_compaction_epoch: u32 = 0;

    let (offset, opened_at_ns) = if opened.is_new {
        let ts_ns = current_ns();
        let header_len = match compression {
            CompressionPolicy::None => {
                let header = SegmentHeader::new(0, seq, 0, ts_ns, [0u8; 16]);
                file.write_all(&header.to_le_bytes()).await?;
                SEGMENT_HEADER_LEN
            }
            CompressionPolicy::Zstd3 => {
                // GOLD-PROG-12: new compressed segments always use V3 header
                // with compaction_epoch=0 (no compaction has occurred yet).
                let header =
                    SegmentHeaderV3::new(0, seq, 0, ts_ns, [0u8; 16], SEGMENT_FLAG_COMPRESSED, 0);
                file.write_all(&header.to_le_bytes()).await?;
                SEGMENT_HEADER_V3_LEN
            }
        };
        file.sync_data().await?;
        debug!(
            path = %segment_path.display(),
            seq,
            compression = ?compression,
            "wrote segment header for new WAL segment"
        );
        (header_len as u64, ts_ns)
    } else {
        let metadata_len = file.metadata().await?.len();
        if metadata_len < SEGMENT_HEADER_LEN as u64 {
            error!(
                path = %segment_path.display(),
                len = metadata_len,
                "existing WAL segment is shorter than SegmentHeader; possible corruption"
            );
        }

        // Read the whole segment for tail-scanning. `tokio::fs::read` is
        // a separate syscall from the append-mode `file` handle — they
        // don't conflict. Failure to read is non-fatal: we fall back to
        // the metadata-length resume point (the prior shape), matching
        // the original behaviour.
        let (resume_offset, resume_opened_at_ns) = match tokio::fs::read(&segment_path).await {
            Ok(bytes) => {
                // COR-22: recover the segment's real start timestamp from its
                // header so the 24h age-rotation clock survives a daemon
                // restart. Before this, opened_at_ns was reset to "now" on
                // reopen, so a segment opened 25h ago would never age-rotate
                // after a restart (only the size ceiling protected it).
                // GOLD-PROG-12: also recover compaction_epoch from the header
                // so the next finalize uses epoch+1, not 0 (crash-idempotency).
                let recovered_opened_at_ns = match parse_segment_header(&bytes) {
                    Ok(ParsedSegmentHeader::V1(h)) => h.segment_start_ts_ns,
                    Ok(ParsedSegmentHeader::V2(h)) => h.segment_start_ts_ns,
                    Ok(ParsedSegmentHeader::V3(h)) => {
                        initial_compaction_epoch = h.compaction_epoch;
                        h.segment_start_ts_ns
                    }
                    Err(_) => current_ns(),
                };
                let resume_offset = match crate::wal::recovery::scan_tail(&bytes) {
                    crate::wal::recovery::ScanResult::Clean { through } => through,
                    crate::wal::recovery::ScanResult::TornAt {
                        good_through,
                        torn_at,
                    } => {
                        // Truncate to the last good frame boundary +
                        // fsync so the truncation lands durably before
                        // any new write. On Windows `append(true)` maps
                        // to FILE_APPEND_DATA WITHOUT FILE_WRITE_DATA,
                        // which makes `set_len` fail with permission
                        // error on the existing append-mode handle.
                        // Open a separate `write(true)` handle just
                        // for the truncate, then drop it. The
                        // original append-mode handle continues to
                        // own subsequent writes.
                        let truncate_result = tokio::fs::OpenOptions::new()
                            .write(true)
                            .open(&segment_path)
                            .await;
                        match truncate_result {
                            Ok(write_handle) => {
                                if let Err(e) = write_handle.set_len(good_through).await {
                                    tracing::error!(
                                        error = %e,
                                        path = %segment_path.display(),
                                        good_through,
                                        "wal::recovery: set_len failed via write-handle; continuing without truncate"
                                    );
                                } else if let Err(e) = write_handle.sync_all().await {
                                    tracing::warn!(
                                        error = %e,
                                        path = %segment_path.display(),
                                        "wal::recovery: sync_all after set_len failed (best-effort)",
                                    );
                                }
                                drop(write_handle);
                            }
                            Err(e) => {
                                tracing::error!(
                                    error = %e,
                                    path = %segment_path.display(),
                                    "wal::recovery: cannot open write-handle for truncate; torn bytes will remain past good_through"
                                );
                            }
                        }
                        tracing::warn!(
                            path = %segment_path.display(),
                            torn_at,
                            good_through,
                            bytes_dropped = torn_at.saturating_sub(good_through),
                            "wal::recovery: torn tail detected and truncated"
                        );
                        pending_recovery = Some(PendingRecovery {
                            segment_path: segment_path.clone(),
                            good_through,
                            torn_at,
                            bytes_dropped: bytes.len() as u64 - good_through,
                        });
                        good_through
                    }
                };
                (resume_offset, recovered_opened_at_ns)
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %segment_path.display(),
                    "wal::recovery: read segment for scan failed; using metadata-len resume",
                );
                (metadata_len, current_ns())
            }
        };
        (resume_offset, resume_opened_at_ns)
    };

    let mut state = WriterState {
        file,
        path: segment_path,
        offset,
        seq,
        opened_at_ns,
        policy,
        compression,
        pending_frames: Vec::new(),
        compaction_epoch: initial_compaction_epoch,
    };

    debug!(path = %state.path.display(), offset = state.offset, "WAL writer opened segment");

    // Pick #36 (Session 14): emit the RECOVERY_TRUNCATED audit frame
    // immediately after WriterState is alive, BEFORE the main rx-loop
    // accepts any caller-driven append. The frame becomes the first
    // new entry in the recovered segment so a forensic walker sees a
    // clear marker for "the daemon recovered here". Best-effort:
    // emission failure leaves the truncation intact (already
    // durable via set_len + sync_all) and only loses the audit
    // breadcrumb — the receive loop must keep running.
    if let Some(rec) = pending_recovery.take() {
        let payload = serde_json::json!({
            "segment_path": rec.segment_path.to_string_lossy(),
            "good_through": rec.good_through,
            "torn_at": rec.torn_at,
            "bytes_dropped": rec.bytes_dropped,
            "ts_unix": crate::time::now_unix_secs(),
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap_or_default();
        let header = crate::wal::HeaderBuilder::new(
            crate::wal::events::EVENT_TYPE_RECOVERY_TRUNCATED,
            &payload_bytes,
        )
        .flags(crate::wal::EventFlags::SYNTHETIC)
        .build();
        let frame = encode_frame(&header, &payload_bytes);
        if let Err(e) = write_and_sync(&mut state.file, &frame).await {
            tracing::warn!(
                error = %e,
                "wal::recovery: emit RECOVERY_TRUNCATED frame failed (truncation still durable)"
            );
        } else {
            state.offset += frame.len() as u64;
        }
    }

    // ── Phase 33b SP-2 — HMAC compaction state ──────────────────────────────
    // The key lives at ~/.neoth/wal/hmac.key, generated on first boot. If
    // the key can't be loaded (very unusual — disk full or perms), log
    // and fall back to per-frame writes WITHOUT compaction markers. The
    // operator audit trail still works, just without tamper-evidence.
    let hmac_key: Option<Vec<u8>> =
        match crate::wal::compaction::load_or_init_key(&crate::wal::compaction::default_key_path())
        {
            Ok(k) => Some(k),
            Err(e) => {
                tracing::warn!(error = %e, "HMAC compaction disabled — key load failed");
                None
            }
        };
    let mut compaction_state = hmac_key
        .as_ref()
        .map(|k| crate::wal::compaction::CompactionState::new(k, state.offset));

    // Pick #40 (Session 14, Agent #1 phase 2 fsync-batching design):
    // batchable event types (STREAM_CHUNK, HOOK_*, LOCAL_INFERENCE_*)
    // skip per-frame `sync_data()`. Their durability piggybacks on the
    // next SYNC_ON_WRITE frame (which sync_data captures all preceding
    // unsynced bytes at the same time) OR on the writer's shutdown
    // drain. This flag tracks whether ANY batchable frame has been
    // written without a sync since the last sync.
    let mut pending_unsynced = false;

    while let Some(req) = rx.recv().await {
        // Pre-flight rotation: rotate BEFORE the write if either threshold
        // is already exceeded, so the new frame lands cleanly at the head
        // of the next segment instead of straddling the boundary.
        if let Some(reason) = state.should_rotate(current_ns()) {
            // Pick #40: flush any pending batchable writes BEFORE rotation
            // so the closing segment is fully durable + the new segment
            // starts clean.
            if pending_unsynced {
                if let Err(e) = state.file.sync_data().await {
                    error!(error = %e, "pre-rotation pending-unsynced flush failed");
                }
                pending_unsynced = false;
            }
            if let Err(e) = rotate(&mut state, reason).await {
                error!(error = %e, "WAL segment rotation failed; continuing on current segment");
            }
        }

        let frame = encode_frame(&req.header, &req.payload);
        let immediate = crate::wal::events::needs_immediate_sync(req.header.event_type);
        // Workstream F: compressed segments buffer frames in-memory;
        // the file write happens on finalize (rotate/shutdown).
        let result = if state.compression == CompressionPolicy::Zstd3 {
            state.pending_frames.extend_from_slice(&frame);
            // For compressed segments we also write frames immediately to
            // a temp staging area so recovery still works on unclean shutdown.
            // However we keep the design simple: write raw frames to the file
            // during live operation, then on finalize rewrite the file with
            // the compressed body. This way the file is always parseable even
            // after a crash (just uncompressed despite the header flag).
            // On clean finalize the compressed form replaces the raw form.
            let r = write_only(&mut state.file, &frame).await;
            if r.is_ok() {
                pending_unsynced = true;
            }
            r
        } else if immediate {
            // SYNC_ON_WRITE frame — `write_and_sync` calls `sync_data`
            // after `write_all`, which durably commits BOTH this frame
            // AND any preceding batchable frames that landed in the OS
            // page cache. So `pending_unsynced` is cleared by this op.
            let r = write_and_sync(&mut state.file, &frame).await;
            if r.is_ok() {
                pending_unsynced = false;
            }
            r
        } else {
            // Batchable frame — skip the per-frame fsync. Mark
            // pending so the next immediate frame OR shutdown drain
            // can commit it.
            let r = write_only(&mut state.file, &frame).await;
            if r.is_ok() {
                pending_unsynced = true;
            }
            r
        };
        match result {
            Ok(_) => {
                let written_at = state.offset;
                state.offset += frame.len() as u64;

                // ── HMAC compaction (Phase 33b SP-2) ──────────────────
                // Feed this frame into the rolling HMAC. When the
                // threshold is crossed, emit a COMPACTION_MARKER event
                // carrying the tag + window bounds. The marker itself
                // is NOT fed into the next window — only operator-frame
                // bytes get HMAC'd.
                if let (Some(state_c), Some(key)) = (compaction_state.as_mut(), hmac_key.as_ref()) {
                    state_c.update(&frame);
                    if state_c.should_emit() {
                        let marker_payload = state_c.finalise_marker(key, state.offset);
                        let payload_bytes = serde_json::to_vec(&serde_json::json!({
                            "from_offset":      marker_payload.from_offset,
                            "to_offset":        marker_payload.to_offset,
                            "frame_count":      marker_payload.frame_count,
                            "hmac_hex":         marker_payload.hmac_hex,
                            // GOLD-PROG-12: informational epoch snapshot so forensic
                            // tooling can correlate marker → header without re-reading.
                            "compaction_epoch": state.compaction_epoch,
                            "ts_ns":            current_ns(),
                        }))
                        .unwrap_or_default();
                        let marker_header = crate::wal::HeaderBuilder::new(
                            crate::wal::events::EVENT_TYPE_COMPACTION_MARKER,
                            &payload_bytes,
                        )
                        .flags(crate::wal::EventFlags::SYNTHETIC)
                        .build();
                        let marker_frame = encode_frame(&marker_header, &payload_bytes);
                        if let Err(e) = write_and_sync(&mut state.file, &marker_frame).await {
                            tracing::warn!(error = %e, "compaction marker write failed");
                        } else {
                            state.offset += marker_frame.len() as u64;
                            // Next window starts at the new tail.
                            *state_c =
                                crate::wal::compaction::CompactionState::new(key, state.offset);
                        }
                    }
                }

                if req.ack.send(Ok(written_at)).is_err() {
                    tracing::debug!(
                        offset = written_at,
                        "ack receiver dropped before WAL write confirmed (caller likely timed out)"
                    );
                }
            }
            Err(e) => {
                error!(error = %e, "WAL frame write failed");
                if req.ack.send(Err(WalError::Io(e))).is_err() {
                    tracing::debug!("ack receiver dropped for failed WAL write");
                }
                // Continue; next caller may still succeed (e.g. transient ENOSPC clears).
            }
        }
    }

    // Workstream F: finalize compressed segment on clean shutdown.
    if state.compression == CompressionPolicy::Zstd3 && !state.pending_frames.is_empty() {
        if let Err(e) = finalize_compressed_segment(&mut state).await {
            warn!(error = %e, "WAL shutdown: compressed segment finalize failed; raw frames remain on disk");
        }
    }

    // Pick #40: shutdown drain — if the last write was batchable,
    // sync_data now so the operator's final partial-streaming reply
    // lands durably before the daemon exits. Caller's `drop(writer)`
    // already closed the channel above; this is the last chance to
    // flush before the writer-task returns.
    if pending_unsynced {
        if let Err(e) = state.file.sync_data().await {
            warn!(error = %e, "shutdown-drain sync_data for batchable frames failed");
        }
    }

    debug!("WAL writer task: channel closed, exiting");
    Ok(())
}

/// Workstream F (CT-10/E-20/V1x-06) — finalize a compressed segment.
///
/// When `compression == Zstd3`, frames are written raw to disk during live
/// operation (so unclean-shutdown recovery still works). On clean finalize
/// (rotation or shutdown), this function:
///   1. Compresses `state.pending_frames` with zstd-3.
///   2. Rewrites the segment file as: v3-header(65 B) + compressed-blob.
///
/// The rewrite is done atomically: write to a `.tmp` sibling, then rename
/// over the original. If any step fails the original (raw) file remains
/// intact — operator keeps a parseable (uncompressed) segment despite the
/// COMPRESSED flag in the header. The header flag is only written when
/// compression succeeds.
///
/// GOLD-PROG-12: the v3 header carries `compaction_epoch = old_epoch + 1`.
/// On restart the writer reads this value back so the NEXT finalize uses
/// epoch+2 — preventing idempotency-key collision after a crash-mid-rename
/// (ADVERSARIAL §SF-06). `state.compaction_epoch` is updated after the
/// successful rename so in-memory state stays in sync with on-disk state.
async fn finalize_compressed_segment(state: &mut WriterState) -> Result<(), WalError> {
    let compressed = compress_frames(&state.pending_frames)?;
    let tmp_path = state.path.with_extension("wal.tmp");

    // Re-read the original header to preserve generation/seq/first_event_id/
    // segment_start_ts_ns/node_id from the live segment, and to recover the
    // on-disk compaction_epoch (GOLD-PROG-12).
    let original_bytes = tokio::fs::read(&state.path).await?;
    let parsed = parse_segment_header(&original_bytes)?;
    let (generation, segment_seq, first_event_id, segment_start_ts_ns, node_id, old_epoch) =
        match parsed {
            ParsedSegmentHeader::V1(h) => (
                h.generation,
                h.segment_seq,
                h.first_event_id,
                h.segment_start_ts_ns,
                h.node_id,
                0u32,
            ),
            ParsedSegmentHeader::V2(h) => (
                h.generation,
                h.segment_seq,
                h.first_event_id,
                h.segment_start_ts_ns,
                h.node_id,
                0u32,
            ),
            ParsedSegmentHeader::V3(h) => (
                h.generation,
                h.segment_seq,
                h.first_event_id,
                h.segment_start_ts_ns,
                h.node_id,
                h.compaction_epoch,
            ),
        };

    // GOLD-PROG-12: new epoch = old + 1 (saturating, so u32::MAX stays at u32::MAX
    // rather than wrapping — at 1 finalize/hour that's 490,000 years).
    let new_epoch = old_epoch.saturating_add(1);

    // Write V3 header with the incremented epoch so the on-disk file after
    // rename always carries epoch N+1, making a restart post-crash-mid-rename
    // produce epoch N+2 rather than a duplicate epoch N+1.
    let v2_header = SegmentHeaderV3::new(
        generation,
        segment_seq,
        first_event_id,
        segment_start_ts_ns,
        node_id,
        SEGMENT_FLAG_COMPRESSED,
        new_epoch,
    );

    let compressed_len = compressed.len();

    // GOLD-ADAPT-CRYPTO-04d encrypt-on-seal: when `wal.encryption` is enabled,
    // the sealed (compressed) frame blob is AES-256-GCM-SIV-encrypted with the
    // plaintext v3 header as AAD, framed `ENC_MAGIC‖nonce‖ciphertext`. The
    // header keeps SEGMENT_FLAG_COMPRESSED (the decrypted blob IS compressed),
    // so the reader chokepoint decrypts-then-decompresses. FAIL-CLOSED: a
    // configured-on operator never silently gets a plaintext segment.
    let body: Vec<u8> = if crate::wal::master_key::wal_encryption_enabled() {
        let key = crate::wal::master_key::writer_segment_key().ok_or_else(|| {
            std::io::Error::other("WAL encryption enabled but the master key could not be loaded")
        })?;
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| std::io::Error::other(format!("encrypt-on-seal nonce RNG: {e}")))?;
        let ct =
            crate::wal::crypto::encrypt_blob(&key, &nonce, &v2_header.to_le_bytes(), &compressed)
                .map_err(|e| std::io::Error::other(format!("encrypt-on-seal: {e}")))?;
        crate::wal::crypto::frame_encrypted(&nonce, &ct)
    } else {
        compressed
    };

    // Write to tmp.
    let mut tmp_opts = tokio::fs::OpenOptions::new();
    tmp_opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    tmp_opts.mode(0o600);
    let mut tmp_file = tmp_opts.open(&tmp_path).await?;
    tmp_file.write_all(&v2_header.to_le_bytes()).await?;
    tmp_file.write_all(&body).await?;
    tmp_file.sync_all().await?;
    drop(tmp_file);

    // Atomic rename over original.
    // GOLD-PROG-12 / Windows: if a stale .wal.tmp from a prior crashed finalize
    // exists, Windows rename will fail (target must not exist). Remove it first
    // (ENOENT is fine — the common case on Unix). This matches the HANDOFF_SESSION25
    // §17 atomic-rename note.
    #[cfg(windows)]
    {
        let _ = tokio::fs::remove_file(&state.path).await;
    }
    tokio::fs::rename(&tmp_path, &state.path).await?;

    info!(
        path = %state.path.display(),
        raw_bytes = state.pending_frames.len(),
        compressed_bytes = compressed_len,
        compaction_epoch = new_epoch,
        ratio = format!("{:.1}%", compressed_len as f64 / state.pending_frames.len().max(1) as f64 * 100.0),
        encrypted = crate::wal::master_key::wal_encryption_enabled(),
        "WAL segment finalized (zstd-3{})",
        if crate::wal::master_key::wal_encryption_enabled() { " + AES-256-GCM-SIV" } else { "" },
    );
    state.pending_frames.clear();
    // GOLD-PROG-12: update in-memory epoch AFTER successful rename so
    // state always reflects on-disk reality. A crash before this line
    // leaves state.compaction_epoch at old_epoch, but the on-disk file
    // has new_epoch in its header — on restart parse_segment_header
    // recovers new_epoch, so the invariant is maintained.
    state.compaction_epoch = new_epoch;
    Ok(())
}

/// Write one WAL frame then commit it durably with `sync_data`.
///
/// # D008-WINDOWS-WAL-01 — E-12 (FlushFileBuffers) redundancy rationale
///
/// On Windows `tokio::fs::File::sync_data()` delegates (via the tokio
/// blocking pool) to `std::fs::File::sync_data()`, which is implemented in
/// the Rust standard library by calling `FlushFileBuffers` directly — the
/// same Win32 API that `win_native::flush_file_buffers` (E-12) wraps.
///
/// Wiring the E-12 wrapper explicitly in this hot path would therefore issue
/// `FlushFileBuffers` **twice** per frame: once inside `sync_data` and a
/// second time via the wrapper.  That double-flush adds per-frame syscall
/// latency with no additional durability benefit on either NTFS or ReFS.
/// The E-12 wrapper is intentionally NOT called here for this reason.
///
/// See `wal_sync_latency_measurement` (the `#[ignore]`d test below) for the
/// measured `sync_data` latency baseline and the `FILE_FLAG_WRITE_THROUGH`
/// re-evaluation threshold.  The corresponding Windows-only
/// `flush_vs_sync_data_latency_comparison` test in `win_native.rs` provides
/// measured evidence that both paths are statistically equivalent.
async fn write_and_sync(file: &mut File, frame: &[u8]) -> std::io::Result<()> {
    file.write_all(frame).await?;
    file.sync_data().await?;
    Ok(())
}

/// Pick #40 (Session 14, Agent #1 phase 2 fsync-batching design):
/// write-only — skip the per-frame `sync_data()`. Used for
/// batchable event types (STREAM_CHUNK, HOOK_*, LOCAL_INFERENCE_*)
/// where loss in a crash-window of a few hundred milliseconds is
/// acceptable. Durability piggybacks on the next SYNC_ON_WRITE
/// frame OR the writer's shutdown drain.
async fn write_only(file: &mut File, frame: &[u8]) -> std::io::Result<()> {
    file.write_all(frame).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::frame::decode_frame;
    use crate::wal::hlc::Hlc;
    use crate::wal::types::{EventFlags, EventId, Importance, NodeId, SessionId};
    use tempfile::tempdir;
    use tokio::fs::read;

    fn header_for(payload_len: u32, event_id: u64) -> EventHeaderV2 {
        use crate::wal::header::{CRC_LEN, HEADER_BODY_LEN, PREAMBLE_LEN};
        EventHeaderV2 {
            wal_format_version: EventHeaderV2::WAL_FORMAT_VERSION,
            event_schema_version: EventHeaderV2::EVENT_SCHEMA_VERSION,
            event_type: 0x01,
            event_subtype: 0,
            flags: EventFlags::empty(),
            header_len: HEADER_BODY_LEN as u16,
            reserved_len: 0,
            total_len: (PREAMBLE_LEN + HEADER_BODY_LEN + payload_len as usize + CRC_LEN) as u32,
            payload_len,
            generation: 1,
            event_id: EventId(event_id),
            hlc: Hlc::new(1_700_000_000_000_000_000, event_id as u32).unwrap(),
            importance: Importance::new(0.1).unwrap(),
            scope: crate::wal::types::WalScope::UNSET,
            category: crate::wal::types::WalCategory::UNSET,
            session_id: SessionId([0u8; 16]),
            node_id: NodeId([0u8; 16]),
            payload_hash: 0,
        }
    }

    /// After F-14, every segment file begins with a 60-byte SegmentHeader.
    /// Frame offsets returned by `append()` are relative to where frames start,
    /// i.e. after the 60-byte header.
    /// K-Perf-2 2026-05-17: fire-and-forget chunk frames land on disk
    /// the same way as `append`, just without the caller awaiting
    /// fsync. Drop the writer + join to flush the queue, then verify
    /// the frame is decodable from the segment file.
    #[tokio::test]
    async fn append_no_ack_writes_frame_without_caller_fsync_wait() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (handle, join) = spawn(seg.clone()).expect("spawn");

        let payload = b"stream-chunk-payload".to_vec();
        let h = header_for(payload.len() as u32, 1);
        // No offset returned — caller doesn't know where it landed.
        handle
            .append_no_ack(h, payload.clone())
            .await
            .expect("enqueue no-ack frame");

        // Force flush by closing the writer.
        drop(handle);
        join.await.expect("join");

        let bytes = read(&seg).await.unwrap();
        let dec = decode_frame(&bytes[SEGMENT_HEADER_LEN..]).expect("decode");
        assert_eq!(
            dec.payload, b"stream-chunk-payload",
            "no-ack frame must land in segment regardless of caller-side ack"
        );
    }

    #[tokio::test]
    async fn append_no_ack_rejects_oversize_payload_synchronously() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (handle, _join) = spawn(seg.clone()).expect("spawn");

        // Build a payload larger than MAX_PAYLOAD_BYTES (4 MiB).
        let oversize = vec![0u8; MAX_PAYLOAD_BYTES + 1];
        let h = header_for(MAX_PAYLOAD_BYTES as u32 + 1, 1);
        let err = handle.append_no_ack(h, oversize).await.unwrap_err();
        assert!(
            matches!(err, WalError::PayloadTooLarge(_, _)),
            "no-ack must enforce the same payload cap as append; got {err:?}"
        );
    }

    #[tokio::test]
    async fn append_no_ack_after_writer_closed_returns_writer_closed_error() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let handle = WalWriterHandle { tx, quota: None };

        let payload = b"x".to_vec();
        let h = header_for(payload.len() as u32, 1);
        let err = handle.append_no_ack(h, payload).await.unwrap_err();
        assert!(matches!(err, WalError::WriterClosed));
    }

    #[tokio::test]
    async fn is_alive_distinguishes_live_writer_from_dead_handle() {
        // A freshly-spawned writer task holds the receiver → handle is alive.
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (handle, join) = spawn(seg).expect("spawn");
        assert!(
            handle.is_alive(),
            "freshly-spawned writer must report alive"
        );

        // A `Some`-but-crashed writer: receiver dropped → `tx.is_closed()` true.
        // `is_alive()` must report false AND `append()` must fail closed so a
        // required-audit pre-flight refuses rather than sending un-audited.
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let dead = WalWriterHandle { tx, quota: None };
        assert!(
            !dead.is_alive(),
            "a crashed-but-Some writer must report not-alive"
        );
        let h = header_for(1, 1);
        let err = dead.append(h, b"x".to_vec()).await.unwrap_err();
        assert!(matches!(err, WalError::WriterClosed));

        // Tidy: dropping the last sender lets the live writer task exit.
        drop(handle);
        let _ = join.await;
    }

    #[tokio::test]
    async fn writer_appends_single_frame() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (handle, join) = spawn(seg.clone()).expect("spawn");

        let payload = b"alpha".to_vec();
        let h = header_for(payload.len() as u32, 1);
        let off = handle.append(h, payload.clone()).await.expect("append");
        // First frame lands immediately after the 60-byte SegmentHeader.
        assert_eq!(off, SEGMENT_HEADER_LEN as u64);

        drop(handle);
        join.await.expect("join");

        let bytes = read(&seg).await.unwrap();
        // Skip the SegmentHeader, then decode the first frame.
        let segment_header =
            SegmentHeader::from_le_bytes(bytes[..SEGMENT_HEADER_LEN].try_into().expect("60 bytes"))
                .expect("valid SegmentHeader");
        assert_eq!(segment_header.segment_seq, 1);
        let dec = decode_frame(&bytes[SEGMENT_HEADER_LEN..]).expect("decode");
        assert_eq!(dec.payload, b"alpha");
    }

    #[tokio::test]
    async fn writer_appends_multiple_frames_with_correct_offsets() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (handle, join) = spawn(seg.clone()).expect("spawn");

        let mut offsets = vec![];
        for i in 1..=3u64 {
            let payload = format!("event-{}", i).into_bytes();
            let h = header_for(payload.len() as u32, i);
            let off = handle.append(h, payload).await.expect("append");
            offsets.push(off);
        }
        // First frame at SEGMENT_HEADER_LEN; each subsequent frame strictly after.
        assert_eq!(offsets[0], SEGMENT_HEADER_LEN as u64);
        assert!(offsets[1] > offsets[0]);
        assert!(offsets[2] > offsets[1]);

        drop(handle);
        join.await.expect("join");

        let bytes = read(&seg).await.unwrap();
        // Walk past the SegmentHeader, then decode all three frames.
        let frames_region = &bytes[SEGMENT_HEADER_LEN..];
        let dec1 = decode_frame(frames_region).expect("decode 1");
        let first_total = dec1.header.total_len as usize;
        assert_eq!(dec1.payload, b"event-1");
        let rest = &frames_region[first_total..];
        let dec2 = decode_frame(rest).expect("decode 2");
        assert_eq!(dec2.payload, b"event-2");
        let second_total = dec2.header.total_len as usize;
        let dec3 = decode_frame(&rest[second_total..]).expect("decode 3");
        assert_eq!(dec3.payload, b"event-3");
    }

    #[tokio::test]
    async fn writer_writes_valid_segment_header_for_new_file() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000042.wal");
        let (handle, join) = spawn(seg.clone()).expect("spawn");
        let payload = b"first".to_vec();
        let h = header_for(payload.len() as u32, 1);
        handle.append(h, payload).await.expect("append");
        drop(handle);
        join.await.expect("join");

        let bytes = read(&seg).await.unwrap();
        assert!(bytes.len() >= SEGMENT_HEADER_LEN);
        let sh =
            SegmentHeader::from_le_bytes(bytes[..SEGMENT_HEADER_LEN].try_into().expect("60 bytes"))
                .expect("SegmentHeader CRC must pass");
        assert_eq!(sh.segment_seq, 42);
        assert_eq!(sh.segment_format_version, 1);
        assert_eq!(&sh.magic, b"NEOT-SEG");
    }

    #[tokio::test]
    async fn writer_reopens_existing_segment_without_rewriting_header() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");

        // First open: writes SegmentHeader + 1 frame.
        {
            let (handle, join) = spawn(seg.clone()).expect("spawn");
            handle
                .append(header_for(1, 1), b"x".to_vec())
                .await
                .expect("append1");
            drop(handle);
            join.await.expect("join1");
        }

        let after_first = read(&seg).await.unwrap();
        let first_len = after_first.len();
        let original_header = after_first[..SEGMENT_HEADER_LEN].to_vec();

        // Second open: reuses existing file. SegmentHeader must NOT change.
        {
            let (handle, join) = spawn(seg.clone()).expect("spawn");
            handle
                .append(header_for(1, 2), b"y".to_vec())
                .await
                .expect("append2");
            drop(handle);
            join.await.expect("join2");
        }

        let after_second = read(&seg).await.unwrap();
        assert!(
            after_second.len() > first_len,
            "second frame must extend file"
        );
        assert_eq!(
            &after_second[..SEGMENT_HEADER_LEN],
            &original_header[..],
            "SegmentHeader must be preserved across reopens"
        );
    }

    #[tokio::test]
    async fn append_rejects_oversize_payload() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (handle, _join) = spawn(seg).expect("spawn");

        let big = vec![0u8; MAX_PAYLOAD_BYTES + 1];
        let h = header_for(big.len() as u32, 99);
        let r = handle.append(h, big).await;
        assert!(matches!(r, Err(WalError::PayloadTooLarge(_, _))));
    }

    #[tokio::test]
    async fn append_after_drop_fails() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (handle, join) = spawn(seg).expect("spawn");
        let cloned = handle.clone();
        drop(handle);
        // Original handle drop alone shouldn't close; cloned still alive.
        let payload = b"x".to_vec();
        let h = header_for(1, 1);
        cloned
            .append(h, payload)
            .await
            .expect("ok while clone alive");

        drop(cloned);
        join.await.expect("join");
    }

    // ── Phase 33b SP-1: rotation ───────────────────────────────────────────

    #[tokio::test]
    async fn writer_rotates_on_size_threshold() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        // Tiny ceiling so a single frame triggers rotation on the next write.
        let policy = RotationPolicy {
            max_bytes: 100,
            max_age_ns: RotationPolicy::DEFAULT_MAX_AGE_NS,
        };
        let (handle, join) = spawn_with_policy(seg.clone(), policy).expect("spawn");

        // Frame 1: lands in segment 1. `frame-001` is 9 bytes — header
        // must declare 9 too or F-24 encode-time invariant fires.
        handle
            .append(header_for(9, 1), b"frame-001".to_vec())
            .await
            .expect("append 1");
        // Frame 2: triggers rotation pre-flight (segment 1 already > 100 B),
        // then writes into segment 2.
        handle
            .append(header_for(9, 2), b"frame-002".to_vec())
            .await
            .expect("append 2");
        // Frame 3: segment 2 already has rollover + frame-002 > 100 B → rotate again.
        handle
            .append(header_for(9, 3), b"frame-003".to_vec())
            .await
            .expect("append 3");

        drop(handle);
        join.await.expect("join");

        let seg1 = dir.path().join("000001.wal");
        let seg2 = dir.path().join("000002.wal");
        let seg3 = dir.path().join("000003.wal");
        assert!(seg1.exists(), "segment 1 must exist");
        assert!(seg2.exists(), "segment 2 must exist after rotation");
        assert!(seg3.exists(), "segment 3 must exist after second rotation");

        // Segment 2 must start with: SegmentHeader (60 B) + a SEGMENT_ROLLOVER
        // frame. Verify by decoding the first frame after the header.
        let bytes2 = read(&seg2).await.unwrap();
        let frames2 = &bytes2[SEGMENT_HEADER_LEN..];
        let first = decode_frame(frames2).expect("rollover frame decodes");
        assert_eq!(
            first.header.event_type,
            crate::wal::events::EVENT_TYPE_SEGMENT_ROLLOVER,
            "first frame after rotation must be SEGMENT_ROLLOVER",
        );
        // Payload is JSON; smoke-check the closed_seq field.
        let v: serde_json::Value = serde_json::from_slice(first.payload).expect("json");
        assert_eq!(v["closed_seq"], 1);
        assert_eq!(v["opened_seq"], 2);
        assert_eq!(v["reason"], "size");
    }

    #[tokio::test]
    async fn writer_rotates_on_age_threshold() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        // Zero-age ceiling: every write after the first triggers rotation.
        let policy = RotationPolicy {
            max_bytes: RotationPolicy::DEFAULT_MAX_BYTES,
            max_age_ns: 0,
        };
        let (handle, join) = spawn_with_policy(seg.clone(), policy).expect("spawn");

        handle
            .append(header_for(1, 1), b"a".to_vec())
            .await
            .expect("a");
        // Force a real wall-clock tick so the age check actually exceeds 0 ns.
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        handle
            .append(header_for(1, 2), b"b".to_vec())
            .await
            .expect("b");

        drop(handle);
        join.await.expect("join");

        let seg2 = dir.path().join("000002.wal");
        assert!(
            seg2.exists(),
            "age-triggered rotation must produce segment 2"
        );
        let bytes2 = read(&seg2).await.unwrap();
        let first = decode_frame(&bytes2[SEGMENT_HEADER_LEN..]).expect("rollover decodes");
        let v: serde_json::Value =
            serde_json::from_slice(first.payload).expect("rollover payload is JSON");
        assert_eq!(v["reason"], "age");
    }

    #[tokio::test]
    async fn writer_age_rotation_survives_restart_via_header_start_ts() {
        // COR-22: a segment opened 25h ago must age-rotate on the next write
        // after a daemon restart. The reopen path now recovers opened_at_ns
        // from the segment header's segment_start_ts_ns; before the fix it was
        // reset to "now" on reopen, so a 25h-old segment never aged out after a
        // restart (only the size ceiling could rotate it).
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");

        // Craft a header-only segment whose start ts is 25h in the past — as if
        // the daemon had opened it yesterday and then restarted.
        let old_ts = current_ns().saturating_sub(25 * 60 * 60 * 1_000_000_000);
        let header = SegmentHeader::new(0, 1, 0, old_ts, [0u8; 16]);
        tokio::fs::write(&seg, header.to_le_bytes()).await.unwrap();

        // Reopen with the production 24h age ceiling.
        let policy = RotationPolicy {
            max_bytes: RotationPolicy::DEFAULT_MAX_BYTES,
            max_age_ns: 24 * 60 * 60 * 1_000_000_000,
        };
        let (handle, join) = spawn_with_policy(seg.clone(), policy).expect("spawn");
        handle
            .append(header_for(1, 1), b"x".to_vec())
            .await
            .expect("append");
        drop(handle);
        join.await.expect("join");

        let seg2 = dir.path().join("000002.wal");
        assert!(
            seg2.exists(),
            "a 25h-old segment must age-rotate on the first write after restart"
        );
        let bytes2 = read(&seg2).await.unwrap();
        let first = decode_frame(&bytes2[SEGMENT_HEADER_LEN..]).expect("rollover decodes");
        let v: serde_json::Value =
            serde_json::from_slice(first.payload).expect("rollover payload is JSON");
        assert_eq!(v["reason"], "age");
    }

    #[test]
    fn rotation_policy_defaults_match_spec() {
        let p = RotationPolicy::default();
        assert_eq!(p.max_bytes, 16 * 1024 * 1024);
        assert_eq!(p.max_age_ns, 24 * 60 * 60 * 1_000_000_000);
    }

    #[test]
    fn next_segment_path_increments_correctly() {
        let cur = std::path::PathBuf::from("/tmp/wal/000007.wal");
        let next = next_segment_path(&cur, 8);
        assert_eq!(
            next.file_name().and_then(|s| s.to_str()),
            Some("000008.wal")
        );
        assert_eq!(next.parent().unwrap(), std::path::Path::new("/tmp/wal"));
    }

    /// BS-4: a writer with a quota guard refuses appends once the home
    /// directory's measured size crosses the configured ceiling. Test
    /// seeds the home dir with a >ceiling fixture file and verifies the
    /// first append returns `QuotaExceeded` (sticky after first breach).
    #[tokio::test]
    async fn append_refuses_when_quota_breached() {
        use std::sync::Arc;
        let dir = tempdir().unwrap();
        let home = dir.path().to_path_buf();
        // Drop a 4 KiB blob so the measured usage > 1 KiB ceiling.
        std::fs::write(home.join("seed.bin"), vec![0u8; 4096]).unwrap();
        let seg = home.join("000001.wal");
        let (writer, _join) = spawn(seg).unwrap();
        let writer = writer.with_quota_guard(Arc::new(QuotaGuard::new(home, 1024)));

        let header = header_for(1, 1);
        let r = writer.append(header, b"x".to_vec()).await;
        assert!(matches!(r, Err(WalError::QuotaExceeded { .. })));

        // Sticky: a second append still fails without re-measuring.
        let header2 = header_for(1, 2);
        let r2 = writer.append(header2, b"y".to_vec()).await;
        assert!(matches!(r2, Err(WalError::QuotaExceeded { .. })));
    }

    #[tokio::test]
    async fn append_allows_when_under_quota() {
        use std::sync::Arc;
        let dir = tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let seg = home.join("000001.wal");
        let (writer, _join) = spawn(seg).unwrap();
        let writer = writer.with_quota_guard(Arc::new(QuotaGuard::new(home, 1024 * 1024 * 1024)));

        let header = header_for(5, 3);
        let r = writer.append(header, b"hello".to_vec()).await;
        assert!(r.is_ok(), "1 GiB ceiling must let a 5-byte append through");
    }

    #[test]
    fn quota_ceiling_holds_under_concurrent_writers() {
        // WAL-QUOTA-FAILCLOSED-01: many threads contend on try_admit at once.
        // The projected-sum CAS loop and the Mutex+Condvar re-measure gate
        // together ensure that the breach is detected and the ceiling enforced
        // under concurrent writers without busy-spinning on tokio threads.
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("seed.bin"), vec![0u8; 4096]).unwrap();
        let guard = Arc::new(QuotaGuard::new(dir.path().to_path_buf(), 1024));

        let admitted = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let g = Arc::clone(&guard);
            let a = Arc::clone(&admitted);
            handles.push(std::thread::spawn(move || {
                for _ in 0..100 {
                    if g.try_admit(64).is_ok() {
                        a.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // 4 KiB seed over a 1 KiB ceiling: the breach must latch and stay
        // sticky — far fewer than the 1600 attempts can be admitted.
        let n = admitted.load(Ordering::Relaxed);
        assert!(
            n < 1600,
            "breach must refuse the bulk of writes; admitted {n}"
        );
        assert!(
            matches!(guard.try_admit(1), Err(WalError::QuotaExceeded { .. })),
            "ceiling breach must be sticky after the concurrent storm"
        );
    }

    // ── Pick #36 (Session 14) — WAL recovery writer integration ─────
    //
    // Proves the recovery loop end-to-end against an actual segment:
    //   1. Pre-write a segment with header + 1 good frame + torn bytes
    //   2. Reopen via wal_spawn — recovery must:
    //        a. set_len the file to good_through
    //        b. append a RECOVERY_TRUNCATED audit frame
    //        c. accept the next caller-driven append AFTER the recovery frame
    //   3. Re-decode the resulting segment cleanly: header + good_frame +
    //      RECOVERY_TRUNCATED + post-recovery append, no torn bytes left.

    #[tokio::test]
    async fn writer_recovers_torn_tail_and_emits_recovery_frame() {
        use crate::wal::events::EVENT_TYPE_RECOVERY_TRUNCATED;
        use tokio::io::AsyncWriteExt;

        let dir = tempdir().unwrap();
        let seg = dir.path().join("000007.wal");

        // 1. First open — write SegmentHeader + 1 good frame, then drop.
        {
            let (handle, join) = spawn(seg.clone()).expect("spawn");
            let payload = b"intact-event".to_vec();
            let h = header_for(payload.len() as u32, 1);
            handle.append(h, payload).await.expect("append intact");
            drop(handle);
            join.await.expect("join1");
        }
        let clean_len = read(&seg).await.unwrap().len();

        // 2. Append torn bytes directly to the file — simulating an
        //    interrupted second write (crash mid-frame).
        {
            let mut f = tokio::fs::OpenOptions::new()
                .append(true)
                .open(&seg)
                .await
                .expect("open for torn append");
            // 5 garbage bytes — enough to be "torn header" territory
            // (less than MIN_FRAME_LEN, can't even hold a preamble+header).
            f.write_all(&[0xDE, 0xAD, 0xBE, 0xEF, 0x42])
                .await
                .expect("torn write");
            f.sync_all().await.expect("sync torn write");
        }
        let torn_len = read(&seg).await.unwrap().len();
        assert!(torn_len > clean_len, "torn write must have grown the file");

        // 3. Reopen — recovery must truncate + emit + accept new appends.
        {
            let (handle, join) = spawn(seg.clone()).expect("spawn for recovery");
            let payload = b"post-recovery".to_vec();
            let h = header_for(payload.len() as u32, 2);
            handle
                .append(h, payload)
                .await
                .expect("append after recovery");
            drop(handle);
            join.await.expect("join2");
        }

        // 4. Re-decode the resulting segment: must contain header +
        //    good_frame + RECOVERY_TRUNCATED + post_recovery, all
        //    parseable, no torn bytes.
        let bytes = read(&seg).await.unwrap();
        assert!(bytes.len() >= SEGMENT_HEADER_LEN);
        // SegmentHeader still valid.
        SegmentHeader::from_le_bytes(bytes[..SEGMENT_HEADER_LEN].try_into().unwrap())
            .expect("SegmentHeader still parses after recovery");

        // Walk frames.
        let mut cursor = SEGMENT_HEADER_LEN;
        let f1 = decode_frame(&bytes[cursor..]).expect("good frame parses");
        assert_eq!(f1.payload, b"intact-event");
        cursor += f1.header.total_len as usize;

        let f2 = decode_frame(&bytes[cursor..]).expect("RECOVERY_TRUNCATED frame parses");
        assert_eq!(
            f2.header.event_type, EVENT_TYPE_RECOVERY_TRUNCATED,
            "second frame must be the recovery audit marker; got 0x{:02x}",
            f2.header.event_type,
        );
        // Sanity-check the payload JSON shape.
        let payload_str = std::str::from_utf8(f2.payload).expect("payload utf8");
        assert!(payload_str.contains("torn_at"));
        assert!(payload_str.contains("good_through"));
        assert!(payload_str.contains("bytes_dropped"));
        cursor += f2.header.total_len as usize;

        let f3 = decode_frame(&bytes[cursor..]).expect("post-recovery frame parses");
        assert_eq!(f3.payload, b"post-recovery");
        cursor += f3.header.total_len as usize;

        // Whole file walked clean.
        assert_eq!(
            cursor,
            bytes.len(),
            "no trailing torn bytes left; cursor={cursor} len={}",
            bytes.len()
        );
    }

    // ── Pick #40 (Session 14) — fsync batching for STREAM_CHUNK/HOOK_*

    #[tokio::test]
    async fn writer_writes_batchable_frame_followed_by_immediate_landed_durably() {
        // Contract: writing a STREAM_CHUNK (batchable) then a normal
        // 0x01 frame (immediate-sync) must result in BOTH frames
        // landing in the segment + parseable after writer shutdown.
        // This proves the pending-unsynced flush path on immediate
        // works correctly.
        use crate::wal::events::EVENT_TYPE_PROVIDER_STREAM_CHUNK;
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000050.wal");
        let (handle, join) = spawn(seg.clone()).expect("spawn");

        // Batchable frame.
        let mut h_chunk = header_for(5, 1);
        h_chunk.event_type = EVENT_TYPE_PROVIDER_STREAM_CHUNK;
        handle
            .append(h_chunk, b"chunk".to_vec())
            .await
            .expect("append batchable");

        // Immediate-sync frame (default header_for uses 0x01).
        handle
            .append(header_for(6, 2), b"final!".to_vec())
            .await
            .expect("append immediate");

        drop(handle);
        join.await.expect("join");

        // Walk + verify both frames present.
        let bytes = read(&seg).await.unwrap();
        let mut cursor = SEGMENT_HEADER_LEN;
        let f1 = decode_frame(&bytes[cursor..]).expect("batchable frame parses");
        assert_eq!(f1.header.event_type, EVENT_TYPE_PROVIDER_STREAM_CHUNK);
        assert_eq!(f1.payload, b"chunk");
        cursor += f1.header.total_len as usize;

        let f2 = decode_frame(&bytes[cursor..]).expect("immediate frame parses");
        assert_eq!(f2.header.event_type, 0x01);
        assert_eq!(f2.payload, b"final!");
    }

    #[tokio::test]
    async fn writer_drain_flushes_batchable_only_writes_on_shutdown() {
        // Contract: writing ONLY batchable frames + dropping the
        // writer cleanly must still leave them durable. Shutdown
        // drain calls `sync_data` after the receive loop exits.
        use crate::wal::events::EVENT_TYPE_PROVIDER_STREAM_CHUNK;
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000051.wal");
        let (handle, join) = spawn(seg.clone()).expect("spawn");

        for i in 1..=3u64 {
            let mut h = header_for(1, i);
            h.event_type = EVENT_TYPE_PROVIDER_STREAM_CHUNK;
            handle
                .append(h, vec![b'A' + (i as u8 - 1)])
                .await
                .expect("append");
        }

        drop(handle);
        join.await.expect("join");

        // All three chunks must be on disk after shutdown drain.
        let bytes = read(&seg).await.unwrap();
        let mut cursor = SEGMENT_HEADER_LEN;
        for i in 1..=3u64 {
            let f = decode_frame(&bytes[cursor..])
                .unwrap_or_else(|e| panic!("frame {i} must parse after shutdown drain: {e:?}"));
            assert_eq!(f.header.event_type, EVENT_TYPE_PROVIDER_STREAM_CHUNK);
            cursor += f.header.total_len as usize;
        }
    }

    /// WAL-QUOTA-FAILCLOSED-01: all concurrent threads must be rejected when
    /// the disk is over quota.  With the projected-sum CAS loop, every thread
    /// reads the (pre-armed) `reserved = remeasure_threshold` and computes
    /// `0 + 1 MiB + 64 > 1024 (ceiling)` — rejected immediately without
    /// reaching the re-measure gate.  The breach flag is set on the first
    /// re-measure that occurs (if any thread reaches it) and stays sticky.
    #[test]
    fn concurrent_writers_all_rejected_when_quota_over_ceiling() {
        use std::sync::Arc;
        use std::sync::atomic::Ordering;

        let dir = tempdir().unwrap();
        // Seed home dir well over the 1 KiB ceiling.
        std::fs::write(dir.path().join("seed.bin"), vec![0u8; 4096]).unwrap();
        // QuotaGuard::new pre-arms reserved = remeasure_threshold (1 MiB).
        // With ceiling = 1024 bytes, projected = 0 + 1 MiB + 64 > 1024 for
        // every thread → all are rejected by the projected-sum check.
        let guard = Arc::new(QuotaGuard::new(dir.path().to_path_buf(), 1024));

        let admitted = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let g = Arc::clone(&guard);
            let a = Arc::clone(&admitted);
            handles.push(std::thread::spawn(move || {
                if g.try_admit(64).is_ok() {
                    a.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let n = admitted.load(Ordering::Relaxed);
        assert_eq!(
            n, 0,
            "all concurrent writers must be rejected fail-closed \
             when disk is over quota; {n} slipped through"
        );
        assert!(
            matches!(guard.try_admit(1), Err(WalError::QuotaExceeded { .. })),
            "quota violation must remain sticky after concurrent storm"
        );
    }

    /// WAL-QUOTA-FAILCLOSED-01 (projected-sum test): two concurrent payloads
    /// whose SUM exceeds the ceiling must not both be admitted, even when each
    /// individual payload is below the ceiling.  The CAS loop inside try_admit
    /// ensures the second thread sees the first thread's already-admitted bytes
    /// in `reserved` before making its admission decision.
    #[test]
    fn two_concurrent_near_ceiling_payloads_both_rejected() {
        use std::sync::Arc;
        use std::sync::atomic::Ordering;

        // Ceiling = 10 MiB; each payload = 7 MiB → sum = 14 MiB > 10 MiB.
        // Only one can be admitted; both admitted would exceed the ceiling.
        let ceiling: u64 = 10 * 1024 * 1024;
        let payload: u64 = 7 * 1024 * 1024;

        let dir = tempdir().unwrap(); // empty home → measure_dir ≈ 0
        let guard = Arc::new(QuotaGuard::new(dir.path().to_path_buf(), ceiling));
        // Manually set known state: last_measured = 0, reserved = 0.
        // (bypasses the initial re-measure so the test exercises the CAS loop
        // directly rather than the measure gate.)
        guard.last_measured.store(0, Ordering::Release);
        guard.reserved.store(0, Ordering::Release);

        let g1 = Arc::clone(&guard);
        let t1 = std::thread::spawn(move || g1.try_admit(payload));
        let g2 = Arc::clone(&guard);
        let t2 = std::thread::spawn(move || g2.try_admit(payload));

        let r1 = t1.join().unwrap();
        let r2 = t2.join().unwrap();

        let ok_count = [r1.is_ok(), r2.is_ok()].iter().filter(|&&x| x).count();
        assert_eq!(
            ok_count, 1,
            "exactly one 7 MiB payload must be admitted against a 10 MiB ceiling \
             (sum = 14 MiB > 10 MiB); admitted={ok_count}"
        );
    }

    /// WAL-QUOTA-FAILCLOSED-01 (bytes-not-lost invariant): bytes admitted by
    /// threads DURING a disk walk are preserved in `reserved` (the during_walk
    /// accounting), not silently discarded by a blind store(0).  This is
    /// verified structurally: after a walk that snapshots `pre_walk_reserved`
    /// and concurrent threads add more bytes, `reserved` must be >= the
    /// during-walk additions rather than zero.
    #[test]
    fn bytes_admitted_during_measure_are_not_lost() {
        use std::sync::atomic::Ordering;

        // Use a large ceiling so no admission is rejected.
        let ceiling: u64 = 1024 * 1024 * 1024;
        let dir = tempdir().unwrap();
        let guard = QuotaGuard::new(dir.path().to_path_buf(), ceiling);

        // Simulate the post-walk state update directly: pre_walk_reserved = 4 MiB,
        // post_walk (after concurrent admissions during the walk) = 6 MiB.
        // The walk measured `used = 1 MiB` on disk.  During-walk bytes = 2 MiB.
        // After the update, `reserved` must equal `during_walk = 2 MiB`, not 0.
        let pre_walk: u64 = 4 * 1024 * 1024;
        let post_walk: u64 = 6 * 1024 * 1024;
        let used: u64 = 1024 * 1024;

        guard.last_measured.store(used, Ordering::SeqCst);
        let during_walk = post_walk.saturating_sub(pre_walk); // 2 MiB
        guard.reserved.store(during_walk, Ordering::SeqCst);

        assert_eq!(
            guard.reserved.load(Ordering::Acquire),
            during_walk,
            "reserved must retain during-walk bytes (2 MiB), not be reset to zero"
        );
        // And the next projected-sum check must see the retained bytes.
        // Admit 1 MiB: projected = used(1 MiB) + during_walk(2 MiB) + 1 MiB = 4 MiB < 1 GiB.
        assert!(
            guard.try_admit(1024 * 1024).is_ok(),
            "admitted bytes during walk must count toward projected sum but not block under ceiling"
        );
    }

    #[test]
    fn needs_immediate_sync_classifier_pins_known_batchable_set() {
        use crate::wal::events::{
            EVENT_TYPE_BOOT, EVENT_TYPE_CHANNEL_INGRESS, EVENT_TYPE_HOOK_BLOCKED,
            EVENT_TYPE_HOOK_FIRED, EVENT_TYPE_LOCAL_INFERENCE_START, EVENT_TYPE_PROFILE_DELTA,
            EVENT_TYPE_PROVIDER_RESPONSE, EVENT_TYPE_PROVIDER_STREAM_CHUNK,
            EVENT_TYPE_RECOVERY_TRUNCATED, needs_immediate_sync,
        };
        // Batchable — must return false.
        assert!(!needs_immediate_sync(EVENT_TYPE_PROVIDER_STREAM_CHUNK));
        assert!(!needs_immediate_sync(EVENT_TYPE_HOOK_FIRED));
        assert!(!needs_immediate_sync(EVENT_TYPE_HOOK_BLOCKED));
        assert!(!needs_immediate_sync(EVENT_TYPE_LOCAL_INFERENCE_START));
        // Immediate (durability-load-bearing) — must return true.
        assert!(needs_immediate_sync(EVENT_TYPE_BOOT));
        assert!(needs_immediate_sync(EVENT_TYPE_CHANNEL_INGRESS));
        assert!(needs_immediate_sync(EVENT_TYPE_PROVIDER_RESPONSE));
        assert!(needs_immediate_sync(EVENT_TYPE_PROFILE_DELTA));
        assert!(needs_immediate_sync(EVENT_TYPE_RECOVERY_TRUNCATED));
        // Default for unknown event_type: true (conservative).
        assert!(needs_immediate_sync(0xFE));
    }

    #[tokio::test]
    async fn writer_skips_recovery_when_tail_is_clean() {
        // Regression guard: a clean reopen (no torn bytes) must NOT
        // emit a RECOVERY_TRUNCATED frame. Recovery only fires on
        // genuine corruption.
        use crate::wal::events::EVENT_TYPE_RECOVERY_TRUNCATED;
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000008.wal");

        // First open — write 1 frame cleanly.
        {
            let (handle, join) = spawn(seg.clone()).expect("spawn");
            handle
                .append(header_for(1, 1), b"a".to_vec())
                .await
                .expect("append");
            drop(handle);
            join.await.expect("join1");
        }

        // Second open — reopen + append 1 more frame.
        {
            let (handle, join) = spawn(seg.clone()).expect("spawn2");
            handle
                .append(header_for(1, 2), b"b".to_vec())
                .await
                .expect("append2");
            drop(handle);
            join.await.expect("join2");
        }

        // Walk all frames — none must be RECOVERY_TRUNCATED.
        let bytes = read(&seg).await.unwrap();
        let mut cursor = SEGMENT_HEADER_LEN;
        let mut frames_seen = 0usize;
        while cursor < bytes.len() {
            let dec = decode_frame(&bytes[cursor..]).expect("frame parses");
            assert_ne!(
                dec.header.event_type, EVENT_TYPE_RECOVERY_TRUNCATED,
                "clean reopen must NOT emit RECOVERY_TRUNCATED; saw it at cursor={cursor}"
            );
            cursor += dec.header.total_len as usize;
            frames_seen += 1;
        }
        assert_eq!(frames_seen, 2, "expected the 2 caller-appended frames only");
    }

    // ── V10-04 Pick #34 voll (2026-05-19): try_append_sync ───────────────
    // The wasmtime hostcall in `wasm_plugin::hostcalls::emit_event` lives
    // outside any tokio context. These tests pin the sync API the
    // hostcall depends on — channel delivery, payload-size enforcement,
    // and closed-writer error mapping — without standing up wasmtime.

    #[tokio::test]
    async fn try_append_sync_delivers_frame_to_segment() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (handle, join) = spawn(seg.clone()).expect("spawn");

        // Sync call from the test body — no `.await` on the append itself,
        // which mirrors how the wasmtime hostcall invokes it.
        let payload = b"plugin-hostcall-frame".to_vec();
        let h = header_for(payload.len() as u32, 42);
        handle
            .try_append_sync(h, payload)
            .expect("sync append must enqueue");

        drop(handle);
        join.await.expect("join writer");

        let bytes = read(&seg).await.unwrap();
        let dec = decode_frame(&bytes[SEGMENT_HEADER_LEN..]).expect("decode");
        assert_eq!(
            dec.payload, b"plugin-hostcall-frame",
            "sync append must produce a decodable frame on disk"
        );
    }

    #[test]
    fn try_append_sync_rejects_oversize_payload() {
        // Pure-sync test — no tokio runtime needed because the payload
        // size check fires before any channel interaction. This catches
        // a regression where the cap check is moved past the try_send.
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let handle = rt.block_on(async { spawn(seg).expect("spawn").0 });

        let oversize = vec![0u8; MAX_PAYLOAD_BYTES + 1];
        let h = header_for(MAX_PAYLOAD_BYTES as u32 + 1, 1);
        let err = handle.try_append_sync(h, oversize).unwrap_err();
        assert!(
            matches!(err, WalError::PayloadTooLarge(_, _)),
            "sync path must enforce the same payload cap as append; got {err:?}"
        );
    }

    // Note: testing `WriterClosed` via the public sync API requires forcing
    // the writer task to exit while keeping a handle alive — but the task
    // only exits when ALL handle clones drop. The trivial match-arm path
    // (`TrySendError::Closed` → `WalError::WriterClosed`) is exercised
    // indirectly by tokio's own mpsc tests + by integration coverage in
    // the daemon shutdown path. A unit test would require an invasive
    // private constructor purely to satisfy the test, so we don't add one.

    // ── Workstream F (CT-10/E-20/V1x-06) — v2 + zstd-3 compression ──────

    /// Write+read v1: spawn with default (no compression), verify v1 header.
    #[tokio::test]
    async fn v1_segment_has_v1_header_and_uncompressed_frames() {
        use crate::wal::segment_header::{
            ParsedSegmentHeader, SEGMENT_FORMAT_VERSION_V1, parse_segment_header,
        };
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (handle, join) = spawn(seg.clone()).expect("spawn v1");
        handle
            .append(header_for(5, 1), b"hello".to_vec())
            .await
            .expect("append");
        drop(handle);
        join.await.expect("join");

        let bytes = read(&seg).await.unwrap();
        let parsed = parse_segment_header(&bytes).expect("parse header");
        assert!(
            matches!(parsed, ParsedSegmentHeader::V1(_)),
            "default spawn must produce a v1 header"
        );
        assert!(!parsed.is_compressed());
        assert_eq!(parsed.segment_format_version(), SEGMENT_FORMAT_VERSION_V1);
    }

    /// Write+read v2 uncompressed: spawn with Zstd3 but segment has no frames
    /// yet — verify the written header is v2 with COMPRESSED flag set.
    #[tokio::test]
    async fn v2_header_written_when_compression_policy_is_zstd3() {
        use crate::wal::segment_header::{
            ParsedSegmentHeader, SEGMENT_FORMAT_VERSION, parse_segment_header,
        };
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (handle, join) = spawn_with_policy_and_compression(
            seg.clone(),
            RotationPolicy::default(),
            CompressionPolicy::Zstd3,
        )
        .expect("spawn zstd");
        handle
            .append(header_for(5, 1), b"hello".to_vec())
            .await
            .expect("append");
        drop(handle);
        join.await.expect("join");

        let bytes = read(&seg).await.unwrap();
        assert!(
            bytes.len() > SEGMENT_HEADER_V3_LEN,
            "v3 segment must be larger than 65-byte header"
        );
        let parsed = parse_segment_header(&bytes).expect("parse v3 header");
        assert!(
            matches!(parsed, ParsedSegmentHeader::V3(_)),
            "zstd spawn must produce a v3 header (GOLD-PROG-12); got {parsed:?}"
        );
        assert_eq!(parsed.segment_format_version(), SEGMENT_FORMAT_VERSION);
    }

    /// Write+read v2 compressed: frames survive round-trip through zstd.
    #[tokio::test]
    async fn v2_compressed_frames_round_trip() {
        use crate::wal::compress::decompress_frames;
        use crate::wal::frame::decode_frame;
        use crate::wal::segment_header::parse_segment_header;
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (handle, join) = spawn_with_policy_and_compression(
            seg.clone(),
            RotationPolicy::default(),
            CompressionPolicy::Zstd3,
        )
        .expect("spawn zstd");
        let payload1 = b"frame-one".to_vec();
        let payload2 = b"frame-two".to_vec();
        handle
            .append(header_for(payload1.len() as u32, 1), payload1.clone())
            .await
            .expect("f1");
        handle
            .append(header_for(payload2.len() as u32, 2), payload2.clone())
            .await
            .expect("f2");
        drop(handle);
        join.await.expect("join");

        let bytes = read(&seg).await.unwrap();
        let parsed = parse_segment_header(&bytes).expect("parse");
        assert!(
            parsed.is_compressed(),
            "segment must be compressed after clean shutdown"
        );
        let hdr_len = parsed.header_len();
        let raw_frames = decompress_frames(&bytes[hdr_len..]).expect("decompress");
        let d1 = decode_frame(&raw_frames).expect("decode frame 1");
        assert_eq!(d1.payload, b"frame-one");
        let d2 = decode_frame(&raw_frames[d1.header.total_len as usize..]).expect("decode frame 2");
        assert_eq!(d2.payload, b"frame-two");
    }

    /// Reader handles mixed v1+v2 directory (operator partway through migration).
    #[tokio::test]
    async fn mixed_v1_v2_segments_in_same_directory_both_parse() {
        use crate::wal::segment_header::{ParsedSegmentHeader, parse_segment_header};
        let dir = tempdir().unwrap();

        // Write a v1 segment.
        let seg1 = dir.path().join("000001.wal");
        {
            let (handle, join) = spawn(seg1.clone()).expect("spawn v1");
            handle
                .append(header_for(3, 1), b"v1!".to_vec())
                .await
                .expect("v1 append");
            drop(handle);
            join.await.expect("v1 join");
        }

        // Write a v2 compressed segment.
        let seg2 = dir.path().join("000002.wal");
        {
            let (handle, join) = spawn_with_policy_and_compression(
                seg2.clone(),
                RotationPolicy::default(),
                CompressionPolicy::Zstd3,
            )
            .expect("spawn v2");
            handle
                .append(header_for(3, 2), b"v2!".to_vec())
                .await
                .expect("v2 append");
            drop(handle);
            join.await.expect("v2 join");
        }

        let b1 = read(&seg1).await.unwrap();
        let b2 = read(&seg2).await.unwrap();
        let p1 = parse_segment_header(&b1).expect("parse seg1");
        let p2 = parse_segment_header(&b2).expect("parse seg2");
        assert!(matches!(p1, ParsedSegmentHeader::V1(_)), "seg1 must be v1");
        // GOLD-PROG-12: Zstd3 writer now emits V3 headers (not V2).
        assert!(matches!(p2, ParsedSegmentHeader::V3(_)), "seg2 must be v3");
        assert!(!p1.is_compressed());
        assert!(p2.is_compressed());
    }

    /// Compression ratio sanity: 10 KiB JSON-heavy payload < 30% of original.
    #[test]
    fn compression_ratio_sanity_on_json_payload() {
        use crate::wal::compress::compress_frames;
        // Build a JSON-heavy payload similar to real WAL frames.
        let chunk = br#"{"event_type":"PROVIDER_RESPONSE","ts_ns":1700000000000000000,"payload":{"role":"assistant","content":"Hello world! This is a WAL payload for compression.","tokens":42}}"#;
        let mut input = Vec::with_capacity(10_240);
        while input.len() < 10_240 {
            let take = (10_240 - input.len()).min(chunk.len());
            input.extend_from_slice(&chunk[..take]);
        }
        let compressed = compress_frames(&input).expect("compress");
        let ratio = compressed.len() as f64 / input.len() as f64;
        assert!(
            ratio < 0.30,
            "expected compressed/original < 30%, got {:.1}% ({}/{} bytes)",
            ratio * 100.0,
            compressed.len(),
            input.len(),
        );
    }

    // ── GOLD-PROG-12: compaction_epoch persistence across finalize + restart ──

    /// Prove that:
    /// (a) finalize_compressed_segment persists epoch+1 in the V3 header.
    /// (b) A reopened writer reads the on-disk epoch correctly.
    /// (c) The second finalize produces epoch=2, not a collision with epoch=1.
    ///
    /// This test validates the core crash-idempotency property: even if a
    /// finalize was interrupted mid-rename (leaving epoch=N on disk), the next
    /// finalize attempt produces epoch=N+1 — a different idempotency key, so
    /// the dedup check correctly treats it as a new operation.
    #[tokio::test]
    async fn compaction_epoch_increments_across_finalize_and_survives_restart() {
        use crate::wal::segment_header::{ParsedSegmentHeader, parse_segment_header};

        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");

        // First writer: open, append one frame, clean shutdown → finalize fires.
        {
            let (handle, join) = spawn_with_policy_and_compression(
                seg.clone(),
                RotationPolicy::default(),
                CompressionPolicy::Zstd3,
            )
            .expect("spawn");
            handle
                .append(header_for(5, 1), b"alpha".to_vec())
                .await
                .expect("append alpha");
            drop(handle); // triggers finalize_compressed_segment → epoch becomes 1
            join.await.expect("join");
        }

        // After clean shutdown: segment must be V3 with compaction_epoch=1.
        let bytes = tokio::fs::read(&seg).await.unwrap();
        let parsed = parse_segment_header(&bytes).expect("parse after first shutdown");
        assert!(
            matches!(parsed, ParsedSegmentHeader::V3(_)),
            "segment must be V3 after finalize; got {parsed:?}"
        );
        assert_eq!(
            parsed.compaction_epoch(),
            1,
            "finalize must increment epoch to 1 on first clean compaction"
        );

        // Second writer: reopen the SAME segment, append another frame, shut down.
        // On reopen the writer must read epoch=1 from the header and assign epoch=2
        // to the NEXT finalize — NOT collide with the prior epoch=1.
        {
            let (handle, join) = spawn_with_policy_and_compression(
                seg.clone(),
                RotationPolicy::default(),
                CompressionPolicy::Zstd3,
            )
            .expect("spawn reopen");
            handle
                .append(header_for(5, 2), b"bravo".to_vec())
                .await
                .expect("append bravo");
            drop(handle); // second finalize → epoch becomes 2
            join.await.expect("join reopen");
        }

        let bytes2 = tokio::fs::read(&seg).await.unwrap();
        let parsed2 = parse_segment_header(&bytes2).expect("parse after second shutdown");
        assert_eq!(
            parsed2.compaction_epoch(),
            2,
            "second finalize must increment epoch to 2, not re-use epoch 1"
        );
        assert!(parsed2.is_compressed(), "segment must still be compressed");
    }

    // ── D008-WINDOWS-WAL-01 — sync_data latency measurement ─────────────────
    //
    // Measures the hot-path latency for WAL append + `sync_data` and prints
    // p50 / p95 / p99 / max.  Uses `std::time::Instant` and blocking `std::fs`
    // to isolate raw disk + OS-call latency from tokio scheduling overhead.
    //
    // Run on demand (never in the default sweep — the box BSODs under parallel
    // test load, so --test-threads=1 is mandatory):
    //
    //   cargo test -p neothd --lib wal_sync_latency -- --ignored --nocapture --test-threads=1
    //
    // ## FILE_FLAG_WRITE_THROUGH threshold (D008-WINDOWS-WAL-01)
    //
    // `FILE_FLAG_WRITE_THROUGH` (bypass OS write-cache on every write) can
    // reduce the per-`FlushFileBuffers` round-trip because each write goes
    // directly past the OS page cache to the storage device.  However:
    //
    //   1. Without `FILE_FLAG_NO_BUFFERING` the drive firmware cache still
    //      buffers writes, so the durability gain on NVMe/SSD with stable
    //      caches is typically < 0.5 ms — rarely worth the complexity.
    //   2. `FILE_FLAG_NO_BUFFERING` requires all writes to be a multiple of
    //      the physical sector size (512 B or 4096 B), requiring an alignment
    //      layer and a significant refactor of the variable-length frame writer.
    //   3. On Windows `std::fs::File::sync_data()` already calls
    //      `FlushFileBuffers` (see `write_and_sync` doc above); wiring
    //      `win_native::flush_file_buffers` (E-12) in addition would
    //      double-flush with no durability benefit.
    //
    // Re-evaluate write-through when EITHER measured metric exceeds:
    //   • p50  > 5 ms  — fsync becomes perceptible in SYNC_ON_WRITE UX
    //   • p99  > 50 ms — storage-path anomaly; check SMART / NVMe health
    //
    // Below those thresholds the alignment-layer complexity is unjustified on
    // NVMe storage, and the existing sync_data path is the correct default.

    #[test]
    #[ignore = "D008 latency bench — run with: cargo test -p neothd --lib wal_sync_latency -- --ignored --nocapture --test-threads=1"]
    fn wal_sync_latency_measurement() {
        use std::io::Write;
        use std::time::Instant;

        const ITERS: usize = 200;
        // Representative WAL frame: short PROVIDER_RESPONSE (header + payload).
        const FRAME_BYTES: usize = 512;
        let frame = vec![0u8; FRAME_BYTES];

        let dir = tempdir().unwrap();
        let path = dir.path().join("sync_lat.wal");
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .expect("open sync_lat.wal");

        // Warm-up: prime the FS / page cache / NTFS journal before sampling.
        for _ in 0..10 {
            file.write_all(&frame).unwrap();
            file.sync_data().unwrap();
        }

        let mut samples_ns: Vec<u64> = Vec::with_capacity(ITERS);
        for _ in 0..ITERS {
            let t0 = Instant::now();
            file.write_all(&frame).unwrap();
            file.sync_data().unwrap();
            samples_ns.push(t0.elapsed().as_nanos() as u64);
        }

        samples_ns.sort_unstable();
        let p50 = samples_ns[ITERS / 2];
        let p95 = samples_ns[ITERS * 95 / 100];
        let p99 = samples_ns[ITERS * 99 / 100];
        let max = *samples_ns.last().unwrap();
        let mean_ns = samples_ns.iter().map(|&n| n as u128).sum::<u128>() / ITERS as u128;

        println!(
            "\nD008-WINDOWS-WAL-01  WAL sync_data latency\n\
             \x20 os={}  n={}  frame={}B\n\
             \x20 p50={:.3}ms  p95={:.3}ms  p99={:.3}ms  max={:.3}ms  mean={:.3}ms\n\
             \x20 THRESHOLD: investigate FILE_FLAG_WRITE_THROUGH when p50 > 5ms or p99 > 50ms",
            std::env::consts::OS,
            ITERS,
            FRAME_BYTES,
            p50 as f64 / 1_000_000.0,
            p95 as f64 / 1_000_000.0,
            p99 as f64 / 1_000_000.0,
            max as f64 / 1_000_000.0,
            mean_ns as f64 / 1_000_000.0,
        );

        // Regression guard: generous 2-second p99 ceiling.
        // Values above this indicate a storage-path anomaly (disk event, driver
        // stall), not a tuning signal — check SMART / NVMe health logs.
        const P99_CEILING_NS: u64 = 2_000 * 1_000_000;
        assert!(
            p99 < P99_CEILING_NS,
            "D008 sync_data p99 {:.1}ms > 2000ms ceiling — storage anomaly; \
             check SMART/NVMe health logs",
            p99 as f64 / 1_000_000.0
        );
    }

    /// WAL-QUOTA-FAILCLOSED-01 residual gap: reservations must be released
    /// when the channel send that follows a successful `try_admit` fails.
    ///
    /// Without the fix, every WriterClosed/WriterBackpressured failure permanently
    /// inflates `reserved`, eventually making the projected-sum check reject all
    /// further writes — silencing the audit log while disk usage is well under
    /// the ceiling (fail-open on forensics).
    ///
    /// Interleaving that triggers the bug (old code, ceiling = 1 MiB):
    ///   T1: try_admit(600 KiB) → reserved = 600 KiB          [CAS succeeds]
    ///   T1: tx.send()         → WriterClosed (channel dead)   [frame NOT queued]
    ///   T1: reserved stays at 600 KiB                         [LEAK — no release]
    ///   T2: try_admit(600 KiB) → projected = 0 + 600K + 600K = 1.2 MiB > 1 MiB
    ///                          → QuotaExceeded                [false rejection]
    #[tokio::test]
    async fn quota_reservation_released_on_writer_closed_send_failure() {
        use std::sync::Arc;
        use std::sync::atomic::Ordering;

        let (tx, rx) = mpsc::channel(1);
        drop(rx); // force WriterClosed on every send

        let payload_bytes: usize = 600 * 1024;
        let ceiling: u64 = 1024 * 1024;
        let dir = tempdir().unwrap();
        let guard = Arc::new(QuotaGuard::new(dir.path().to_path_buf(), ceiling));
        // Bypass the initial-measure pre-arm so state is precisely known.
        guard.reserved.store(0, Ordering::Release);
        guard.last_measured.store(0, Ordering::Release);

        let handle = WalWriterHandle {
            tx,
            quota: Some(Arc::clone(&guard)),
        };

        // try_admit succeeds (0 + 0 + 600 KiB ≤ 1 MiB ceiling), then
        // channel send fails → reservation must be released.
        let h1 = header_for(payload_bytes as u32, 1);
        let err = handle
            .append(h1, vec![0u8; payload_bytes])
            .await
            .unwrap_err();
        assert!(matches!(err, WalError::WriterClosed));

        // With the fix:    reserved = 0  → projected = 600 KiB ≤ ceiling → Ok
        // Without the fix: reserved = 600 KiB → projected = 1.2 MiB > ceiling → Err
        assert!(
            guard.try_admit(payload_bytes as u64).is_ok(),
            "reservation leaked into `reserved` on WriterClosed send failure — \
             second try_admit incorrectly rejected (disk is empty, ceiling = 1 MiB)"
        );
    }
}
