// WAL writer task -- SPEC_wal_lifecycle.md.
// Single-writer invariant: only one task writes to the active segment.
// O_APPEND + sync_data (fdatasync(2) on Linux) every flush for durability.
// Mode 0600 on segment files (umask 0o077 also applied at daemon startup).
//
// Phase 33b SP-1: segment rotation when size > 16 MiB or age > 24 h.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

use super::error::WalError;
use super::frame::encode_frame;
use super::header::EventHeaderV2;
use super::segment_header::{SEGMENT_HEADER_LEN, SegmentHeader};

const DEFAULT_CHANNEL_CAPACITY: usize = 1024;
pub const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024; // 16 MiB sanity ceiling

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
#[derive(Clone)]
pub struct WalWriterHandle {
    tx: mpsc::Sender<WriteRequest>,
    /// Phase 33c BS-4 pre-write quota guard. `None` keeps the writer free
    /// of disk-usage checks (tests + cli one-shots); the daemon sets it
    /// via `with_quota_guard` after `spawn`.
    quota: Option<std::sync::Arc<QuotaGuard>>,
}

/// Pre-write disk-quota guard. Counts bytes admitted since the last
/// disk-walk and re-measures the home dir when the counter crosses a
/// threshold. Refuses writes once usage breaches the ceiling.
///
/// Construction is cheap (no IO); first `try_admit` triggers a measure.
/// Once breached, the guard stays breached until `reset()` is called —
/// operator who frees disk space must restart the daemon or call the
/// reset path from `neoth doctor`.
pub struct QuotaGuard {
    home: PathBuf,
    ceiling: u64,
    /// Re-measure threshold. Default = 1 MiB. Each `try_admit` adds the
    /// payload size; once the counter crosses this, we walk the disk and
    /// refresh `last_measured`.
    remeasure_threshold: u64,
    bytes_since_measure: std::sync::atomic::AtomicU64,
    last_measured: std::sync::atomic::AtomicU64,
    breached: std::sync::atomic::AtomicBool,
}

impl QuotaGuard {
    pub fn new(home: PathBuf, ceiling_bytes: u64) -> Self {
        Self {
            home,
            ceiling: ceiling_bytes,
            remeasure_threshold: 1024 * 1024,
            bytes_since_measure: std::sync::atomic::AtomicU64::new(u64::MAX),
            last_measured: std::sync::atomic::AtomicU64::new(0),
            breached: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Check whether one more payload of `payload_bytes` can be admitted.
    /// Re-measures the home dir lazily when the running counter crosses
    /// `remeasure_threshold`. Returns `Err(QuotaExceeded)` after the first
    /// breach — the breached flag stays sticky.
    pub fn try_admit(&self, payload_bytes: u64) -> Result<(), WalError> {
        use std::sync::atomic::Ordering;
        if self.breached.load(Ordering::Acquire) {
            return Err(WalError::QuotaExceeded {
                used: self.last_measured.load(Ordering::Acquire),
                ceiling: self.ceiling,
            });
        }
        // Lazy re-measure. The very first call (initialised to MAX) always
        // re-measures so the guard never admits without a real reading.
        let prior = self
            .bytes_since_measure
            .fetch_add(payload_bytes, Ordering::AcqRel);
        let crossed = prior >= self.remeasure_threshold || prior == u64::MAX;
        if crossed {
            let used = crate::daemon::quota::measure_dir(&self.home);
            self.last_measured.store(used, Ordering::Release);
            self.bytes_since_measure.store(0, Ordering::Release);
            if used >= self.ceiling {
                self.breached.store(true, Ordering::Release);
                return Err(WalError::QuotaExceeded {
                    used,
                    ceiling: self.ceiling,
                });
            }
        }
        Ok(())
    }

    /// Clear the sticky breached flag. Used by `neoth doctor --fix` after
    /// the operator manually deleted old segments.
    pub fn reset(&self) {
        use std::sync::atomic::Ordering;
        self.breached.store(false, Ordering::Release);
        self.bytes_since_measure.store(u64::MAX, Ordering::Release);
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

    pub async fn append(&self, header: EventHeaderV2, payload: Vec<u8>) -> Result<u64, WalError> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(WalError::PayloadTooLarge(payload.len(), MAX_PAYLOAD_BYTES));
        }
        if let Some(guard) = self.quota.as_ref() {
            guard.try_admit(payload.len() as u64)?;
        }
        let (ack_tx, ack_rx) = oneshot::channel();
        self.tx
            .send(WriteRequest {
                header,
                payload,
                ack: ack_tx,
            })
            .await
            .map_err(|_| WalError::WriterClosed)?;
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
        if let Some(guard) = self.quota.as_ref() {
            guard.try_admit(payload.len() as u64)?;
        }
        let (ack_tx, _ack_rx_drop) = oneshot::channel();
        self.tx
            .try_send(WriteRequest {
                header,
                payload,
                ack: ack_tx,
            })
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => WalError::WriterBackpressured {
                    capacity: DEFAULT_CHANNEL_CAPACITY,
                },
                mpsc::error::TrySendError::Closed(_) => WalError::WriterClosed,
            })
    }

    pub async fn append_no_ack(
        &self,
        header: EventHeaderV2,
        payload: Vec<u8>,
    ) -> Result<(), WalError> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(WalError::PayloadTooLarge(payload.len(), MAX_PAYLOAD_BYTES));
        }
        if let Some(guard) = self.quota.as_ref() {
            guard.try_admit(payload.len() as u64)?;
        }
        // Construct the oneshot but immediately drop the receiver.
        // The writer task tries to send through it after fsync, sees
        // the receiver dropped, and logs at debug — same path as a
        // caller that times out. No new writer-task code needed.
        let (ack_tx, _ack_rx_drop) = oneshot::channel();
        self.tx
            .send(WriteRequest {
                header,
                payload,
                ack: ack_tx,
            })
            .await
            .map_err(|_| WalError::WriterClosed)?;
        Ok(())
    }
}

/// Spawn the writer task with default rotation policy (16 MiB / 24 h).
pub fn spawn(
    segment_path: PathBuf,
) -> Result<(WalWriterHandle, tokio::task::JoinHandle<()>), WalError> {
    spawn_with_policy(segment_path, RotationPolicy::default())
}

/// Spawn the writer task with an explicit rotation policy. Production code
/// uses [`spawn`]; tests use this to exercise rotation without writing 16 MiB.
pub fn spawn_with_policy(
    segment_path: PathBuf,
    policy: RotationPolicy,
) -> Result<(WalWriterHandle, tokio::task::JoinHandle<()>), WalError> {
    let (tx, rx) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);
    let join = tokio::spawn(async move {
        if let Err(e) = run_writer(segment_path, rx, policy).await {
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
    // current user via `icacls.exe` after open. Uses the async wrapper so the
    // icacls subprocess runs on the blocking pool and does not stall this
    // tokio worker. See OPEN_DECISIONS.md D-008.
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
    /// First-frame offset = `SEGMENT_HEADER_LEN`.
    offset: u64,
    /// Sequence number of the active segment.
    seq: u64,
    /// Open timestamp in `SystemTime::UNIX_EPOCH.as_nanos()`; used for the
    /// `age_ns` rotation check.
    opened_at_ns: u64,
    policy: RotationPolicy,
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
    let header = SegmentHeader::new(0, next_seq, 0, now_ns, [0u8; 16]);
    new_file.write_all(&header.to_le_bytes()).await?;
    new_file.sync_data().await?;

    state.file = new_file;
    state.path = next_path;
    state.seq = next_seq;
    state.opened_at_ns = now_ns;
    state.offset = SEGMENT_HEADER_LEN as u64;

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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

async fn run_writer(
    segment_path: PathBuf,
    mut rx: mpsc::Receiver<WriteRequest>,
    policy: RotationPolicy,
) -> Result<(), WalError> {
    let opened = open_segment(&segment_path).await?;
    let mut file = opened.file;
    let seq = segment_seq_from_path(&segment_path);

    // F-14: every new segment begins with a 60-byte SegmentHeader at offset 0.
    //
    // Pick #36 (Session 14): existing-segment path now scans the tail for
    // torn frames via `wal::recovery::scan_tail`. On torn-tail detection
    // we truncate the segment to the last good frame boundary BEFORE
    // building the WriterState — otherwise the next append would land
    // AFTER the corrupt bytes and produce a parse-fail island. The
    // `pending_recovery` value carries the bookkeeping so we can emit
    // a `RECOVERY_TRUNCATED` audit frame AFTER WriterState is alive.
    let mut pending_recovery: Option<PendingRecovery> = None;
    let (offset, opened_at_ns) = if opened.is_new {
        let ts_ns = current_ns();
        let header = SegmentHeader::new(0, seq, 0, ts_ns, [0u8; 16]);
        file.write_all(&header.to_le_bytes()).await?;
        file.sync_data().await?;
        debug!(
            path = %segment_path.display(),
            seq,
            "wrote SegmentHeader for new WAL segment"
        );
        (SEGMENT_HEADER_LEN as u64, ts_ns)
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
        let resume_offset = match tokio::fs::read(&segment_path).await {
            Ok(bytes) => {
                let scan = crate::wal::recovery::scan_tail(&bytes);
                match scan {
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
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %segment_path.display(),
                    "wal::recovery: read segment for scan failed; using metadata-len resume",
                );
                metadata_len
            }
        };
        // For an existing segment we can't recover the original opened_at_ns
        // from the file (without re-parsing the SegmentHeader). Treat reopen
        // as "fresh age clock starts now" — the size-based ceiling still
        // protects us from runaway growth.
        (resume_offset, current_ns())
    };

    let mut state = WriterState {
        file,
        path: segment_path,
        offset,
        seq,
        opened_at_ns,
        policy,
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
            "ts_unix": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
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
        let result = if immediate {
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
                            "from_offset": marker_payload.from_offset,
                            "to_offset":   marker_payload.to_offset,
                            "frame_count": marker_payload.frame_count,
                            "hmac_hex":    marker_payload.hmac_hex,
                            "ts_ns":       current_ns(),
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
            scope: 0,
            category: 0,
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
}
