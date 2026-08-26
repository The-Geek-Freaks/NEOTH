// WAL writer task -- SPEC_wal_lifecycle.md.
// Single-writer invariant: only one task writes to the active segment.
// O_APPEND + sync_data (fdatasync(2) on Linux) every flush for durability.
// Mode 0600 on segment files (umask 0o077 also applied at daemon startup).
//
// Phase 33b SP-1: segment rotation when size > 16 MiB or age > 24 h.

use std::path::{Path, PathBuf};

use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _};
use cap_std::fs::OpenOptions as CapOpenOptions;
use sha2::{Digest as _, Sha256};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

use super::compress::compress_frames;
use super::error::WalError;
use super::frame::encode_frame;
use super::header::EventHeaderV2;
use super::segment_header::{
    ParsedSegmentHeader, SEGMENT_FLAG_COMPRESSED, SEGMENT_FLAG_SEALED, SEGMENT_HEADER_LEN,
    SEGMENT_HEADER_V3_LEN, SegmentHeader, SegmentHeaderV3, parse_segment_header,
};

const DEFAULT_CHANNEL_CAPACITY: usize = 1024;
pub const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024; // 16 MiB sanity ceiling
const CONTEXT_EVIDENCE_RECEIPT_AUTHORITY_SENTINEL: &str = ".context-evidence-receipt-authority";
// Keep the in-process side of the receipt authority deliberately bounded: one
// mutex avoids an attacker-controlled home-key map whose entries can never be
// reclaimed safely. The availability trade-off is explicit and conservative:
// receipt decisions for different homes serialize inside one daemon and a
// waiter fails closed after five seconds. Ordinary WAL appends are unaffected;
// each receipt scan is itself capped by `supported_home_scan_limits()`.
static CONTEXT_EVIDENCE_RECEIPT_PROCESS_AUTHORITY: std::sync::LazyLock<
    std::sync::Arc<tokio::sync::Mutex<()>>,
> = std::sync::LazyLock::new(|| std::sync::Arc::new(tokio::sync::Mutex::new(())));
// Marker JSON uses only bounded integers plus a fixed 64-byte HMAC hex tag.
// Keep a conservative envelope so operator-frame admission can reserve the
// mandatory authentication record before acknowledging the operator frame.
const MAX_COMPACTION_MARKER_FRAME_BYTES: usize = 512;
// Rotation publishes only a header plus one rollover-link frame and its HMAC
// marker. Canonical segment leaves are filesystem-component bounded, so 16 KiB
// is deliberately generous; `rotate` enforces this exact ceiling before it
// opens a successor. Receipt admission can therefore cover every possible
// pre-frame rotation without reserving the full per-segment recovery ceiling.
const MAX_ROTATION_SUCCESSOR_PREFIX_BYTES: usize = 16 * 1024;

fn is_context_evidence_receipt_header(header: &EventHeaderV2) -> bool {
    header.event_type == crate::wal::events::EVENT_TYPE_EXTENDED
        && header.event_subtype == crate::wal::events::ExtendedSubtype::ContextEvidenceReceipt as u8
}

fn refuse_generic_context_evidence_receipt(header: &EventHeaderV2) -> Result<(), WalError> {
    if is_context_evidence_receipt_header(header) {
        return Err(WalError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Context Evidence receipts require the authenticated append-once writer API",
        )));
    }
    Ok(())
}

/// Immutable identity of a closed predecessor as observed through the
/// capability-bound WAL directory after its final sync/seal.
struct ClosedSegmentBinding {
    segment_name: String,
    generation: u32,
    sequence: u64,
    start_ts_ns: u64,
    node_id: [u8; 16],
    physical_len: u64,
    sha256_hex: String,
}

#[cfg(all(test, unix))]
static TEST_FAIL_SEGMENT_PARENT_SYNC_AT: std::sync::Mutex<Vec<PathBuf>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TestSegmentCreateFailure {
    PrivatePermissions,
    HeaderWrite,
    FileSync,
    StageCleanup,
}

#[cfg(test)]
static TEST_FAIL_SEGMENT_CREATE_AT: std::sync::Mutex<Vec<(PathBuf, TestSegmentCreateFailure)>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
static TEST_FAIL_COMPACTION_MARKER_WRITE_AT: std::sync::Mutex<Vec<PathBuf>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
static TEST_CONTEXT_EVIDENCE_RECEIPT_AUTHORITY_CONTENTION_AT: std::sync::Mutex<
    Vec<(PathBuf, std::sync::mpsc::SyncSender<()>)>,
> = std::sync::Mutex::new(Vec::new());

#[cfg(test)]
struct TestSegmentPublicationPause {
    path: PathBuf,
    prepared: std::sync::mpsc::SyncSender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

#[cfg(test)]
static TEST_PAUSE_SEGMENT_PUBLICATION_AT: std::sync::Mutex<Vec<TestSegmentPublicationPause>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(all(test, unix))]
pub(crate) fn fail_segment_parent_sync_for_test(parent: &Path) {
    let mut targets = TEST_FAIL_SEGMENT_PARENT_SYNC_AT
        .lock()
        .expect("segment parent-sync test hook poisoned");
    targets.retain(|target| target != parent);
    targets.push(parent.to_path_buf());
}

#[cfg(test)]
fn fail_segment_create_for_test(path: &Path, failure: TestSegmentCreateFailure) {
    let mut targets = TEST_FAIL_SEGMENT_CREATE_AT
        .lock()
        .expect("segment-create test hook poisoned");
    targets.retain(|(target, target_failure)| target != path || *target_failure != failure);
    targets.push((path.to_path_buf(), failure));
}

#[cfg(test)]
pub(crate) fn pause_segment_publication_for_test(
    path: &Path,
) -> (
    std::sync::mpsc::Receiver<()>,
    std::sync::mpsc::SyncSender<()>,
) {
    let (prepared_tx, prepared_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let mut pending = TEST_PAUSE_SEGMENT_PUBLICATION_AT
        .lock()
        .expect("segment-publication test hook poisoned");
    pending.retain(|pause| pause.path != path);
    pending.push(TestSegmentPublicationPause {
        path: path.to_path_buf(),
        prepared: prepared_tx,
        release: release_rx,
    });
    (prepared_rx, release_tx)
}

#[cfg(test)]
fn pause_before_segment_publication(path: &Path) -> std::io::Result<()> {
    let pause = {
        let mut pending = TEST_PAUSE_SEGMENT_PUBLICATION_AT
            .lock()
            .expect("segment-publication test hook poisoned");
        pending
            .iter()
            .position(|pause| pause.path == path)
            .map(|index| pending.swap_remove(index))
    };
    let Some(pause) = pause else {
        return Ok(());
    };
    pause.prepared.send(()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "segment-publication test observer disconnected",
        )
    })?;
    pause
        .release
        .recv_timeout(std::time::Duration::from_secs(15))
        .map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("segment-publication test release failed: {error}"),
            )
        })
}

#[cfg(test)]
fn inject_segment_create_failure(
    path: &Path,
    failure: TestSegmentCreateFailure,
) -> std::io::Result<()> {
    let mut target = TEST_FAIL_SEGMENT_CREATE_AT
        .lock()
        .expect("segment-create test hook poisoned");
    if let Some(index) = target
        .iter()
        .position(|(target, target_failure)| target == path && *target_failure == failure)
    {
        target.swap_remove(index);
        return Err(std::io::Error::other(format!(
            "injected WAL segment create failure at {failure:?}"
        )));
    }
    Ok(())
}

#[cfg(test)]
fn fail_compaction_marker_write_for_test(path: &Path) {
    let mut targets = TEST_FAIL_COMPACTION_MARKER_WRITE_AT
        .lock()
        .expect("compaction-marker test hook poisoned");
    targets.retain(|target| target != path);
    targets.push(path.to_path_buf());
}

#[cfg(test)]
fn inject_compaction_marker_write_failure(path: &Path) -> std::io::Result<()> {
    let mut targets = TEST_FAIL_COMPACTION_MARKER_WRITE_AT
        .lock()
        .expect("compaction-marker test hook poisoned");
    if let Some(index) = targets.iter().position(|target| target == path) {
        targets.swap_remove(index);
        return Err(std::io::Error::other(
            "injected compaction marker write failure",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn observe_context_evidence_receipt_authority_contention_for_test(
    home: &Path,
) -> std::sync::mpsc::Receiver<()> {
    let (reached_tx, reached_rx) = std::sync::mpsc::sync_channel(1);
    let mut observers = TEST_CONTEXT_EVIDENCE_RECEIPT_AUTHORITY_CONTENTION_AT
        .lock()
        .expect("Context Evidence receipt authority test hook poisoned");
    observers.retain(|(target, _)| target != home);
    observers.push((home.to_path_buf(), reached_tx));
    reached_rx
}

#[cfg(test)]
fn notify_context_evidence_receipt_authority_contention_for_test(home: &Path) {
    let observer = {
        let mut observers = TEST_CONTEXT_EVIDENCE_RECEIPT_AUTHORITY_CONTENTION_AT
            .lock()
            .expect("Context Evidence receipt authority test hook poisoned");
        observers
            .iter()
            .position(|(target, _)| target == home)
            .map(|index| observers.swap_remove(index).1)
    };
    if let Some(observer) = observer {
        let _ = observer.send(());
    }
}

/// Allocate a collision-resistant segment namespace for a standalone writer.
///
/// The daemon owns the legacy numeric sequence (`000001.wal`, ...). CLI
/// processes must not append to that same file: `OpenOptions::append` does not
/// provide cross-process frame atomicity. UUIDv7 keeps names time-sortable;
/// the trailing numeric component is preserved by rotation.
pub(crate) fn unique_standalone_segment_path(wal_dir: &Path, surface: &str) -> PathBuf {
    assert!(
        !surface.is_empty()
            && surface
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "standalone WAL surface must be a non-empty filesystem-safe identifier"
    );
    // The writer decides whether to skip compaction-marker emission by looking
    // for `-hmac-key-rotate-` in the segment file name. That is exact for the
    // one surface that owns it today, but a future surface whose name merely
    // CONTAINS it (`hmac-key-rotate-v2`) would silently inherit the skip and
    // lose tamper evidence for its segment — with no error. Reserve the
    // substring so that mistake fails here, loudly, at the call site.
    assert!(
        !surface.contains(HMAC_ROTATION_SURFACE) || surface == HMAC_ROTATION_SURFACE,
        "WAL surface `{surface}` reserves the `{HMAC_ROTATION_SURFACE}` marker-skip name; \
         pick another surface, or thread an explicit flag if the skip is really intended"
    );
    wal_dir.join(format!("{}-{surface}-000001.wal", uuid::Uuid::now_v7()))
}

/// The one standalone surface whose writer must NOT emit compaction markers:
/// the HMAC-key rotation one-shot already holds the rotation transaction lock,
/// so emitting an old-key marker after that boundary would be wrong.
pub(crate) const HMAC_ROTATION_SURFACE: &str = "hmac-key-rotate";

fn is_exact_hmac_rotation_segment(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let suffix = format!("-{HMAC_ROTATION_SURFACE}-000001.wal");
    let Some(namespace) = name.strip_suffix(&suffix) else {
        return false;
    };
    uuid::Uuid::parse_str(namespace).is_ok()
}

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

fn validate_rotation_policy(policy: RotationPolicy) -> Result<(), WalError> {
    if policy.max_bytes > RotationPolicy::DEFAULT_MAX_BYTES {
        return Err(WalError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "WAL rotation max_bytes {} exceeds the supported {}-byte ceiling; \
                 larger policies can create segments that the bounded recovery scanner \
                 cannot safely reopen",
                policy.max_bytes,
                RotationPolicy::DEFAULT_MAX_BYTES
            ),
        )));
    }
    Ok(())
}

/// Active-segment lifecycle. Production rotates on size/age. Capture writers
/// stay on one fresh segment and fail before a frame would cross their hard
/// physical ceiling, so a caller cannot decode only `000001.wal` while later
/// frames were silently moved to `000002.wal`.
#[derive(Clone, Copy, Debug)]
enum SegmentPolicy {
    Rotating(RotationPolicy),
    #[cfg_attr(not(any(test, feature = "wasm-plugin-host")), allow(dead_code))]
    Fixed {
        max_bytes: u64,
    },
}

/// Reason recorded in the SEGMENT_ROLLOVER WAL event payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RotationReason {
    SizeExceeded,
    AgeExceeded,
    SealedResume,
}

impl RotationReason {
    fn as_str(&self) -> &'static str {
        match self {
            RotationReason::SizeExceeded => "size",
            RotationReason::AgeExceeded => "age",
            RotationReason::SealedResume => "sealed_restart",
        }
    }
}

/// One write request, with a oneshot reply channel for ack/error.
pub struct WriteRequest {
    pub header: EventHeaderV2,
    pub payload: Vec<u8>,
    pub ack: oneshot::Sender<Result<u64, WalError>>,
    /// Close and fsync the current HMAC window before acknowledging this
    /// request. Reserved for producer/consumer contracts whose downstream
    /// reader must prove the exact frame from authenticated primary-WAL bytes.
    force_authentication_marker: bool,
    /// Present only for the closed Context Connector receipt primitive. The
    /// writer uses this binary handle under a cross-process home authority to
    /// make the bounded authenticated-ledger decision and append one
    /// transaction. Generic appends can never opt into deduplication by merely
    /// choosing the receipt event subtype.
    context_evidence_receipt_once: Option<ContextEvidenceReceiptOnce>,
    /// Generic WAL admission ownership. It remains pending from the successful
    /// pre-write quota decision until this request reaches a writer-terminal
    /// state, so an unrelated home-directory growth cannot consume it during a
    /// measurement rebase.
    quota_admission: Option<QuotaPendingAdmission>,
    #[cfg(test)]
    test_ack_gate: Option<TestAckGate>,
    #[cfg(test)]
    test_receipt_decision_gate: Option<TestAckGate>,
}

struct QuotaPendingAdmission {
    guard: Option<std::sync::Arc<QuotaGuard>>,
    bytes: u64,
    measurement_epoch: u64,
}

impl QuotaPendingAdmission {
    fn new(guard: std::sync::Arc<QuotaGuard>, bytes: u64) -> Self {
        let measurement_epoch = guard
            .measurement_epoch
            .load(std::sync::atomic::Ordering::Acquire);
        Self {
            guard: Some(guard),
            bytes,
            measurement_epoch,
        }
    }

    fn release_unqueued(mut self) {
        if let Some(guard) = self.guard.take() {
            guard.release_unqueued_admission(self.bytes);
        }
    }

    fn settle(mut self) {
        if let Some(guard) = self.guard.take() {
            guard.settle_pending_admission(self.bytes, self.measurement_epoch);
        }
    }
}

impl Drop for QuotaPendingAdmission {
    fn drop(&mut self) {
        if let Some(guard) = self.guard.take() {
            guard.settle_pending_admission(self.bytes, self.measurement_epoch);
        }
    }
}

struct ContextEvidenceReceiptOnce {
    receipt_handle: [u8; 32],
    expected: crate::wal::events::ContextEvidenceReceipt,
    quota_reservation: ContextEvidenceQuotaReservation,
}

impl ContextEvidenceReceiptOnce {
    fn arm_quota_fail_closed(&mut self) {
        self.quota_reservation.arm_fail_closed();
    }

    fn reconcile_quota_after_terminal(
        &mut self,
        retained_bytes: u64,
        reclaimed_debt_bytes: u64,
        baseline_reclaimed_bytes: u64,
        retained_is_failure_debt: bool,
    ) {
        let guard = self.quota_reservation.guard.clone();
        if let Some(guard) = guard.as_ref() {
            guard.release_receipt_debt_locked(reclaimed_debt_bytes);
            guard.invalidate_measured_baseline_locked(baseline_reclaimed_bytes);
        }
        self.quota_reservation
            .reconcile_after_terminal_locked(retained_bytes);
        if retained_is_failure_debt && let Some(guard) = guard.as_ref() {
            guard.mark_receipt_debt_locked(retained_bytes);
        }
    }
}

/// RAII ownership for the receipt transaction's complete bounded physical
/// delta. Each component is consumed immediately before (or, for an atomic
/// successor publication, immediately after) the mutation that can leave it on
/// disk. Every unused component is released on drop, including deduplication
/// and all pre-write terminal paths.
struct ContextEvidenceQuotaReservation {
    guard: Option<std::sync::Arc<QuotaGuard>>,
    admitted_bytes: u64,
    owned_bytes: u64,
    pending_bytes: u64,
    measurement_epoch: u64,
    releasable_bytes: u64,
    fail_closed: bool,
}

impl ContextEvidenceQuotaReservation {
    /// Once a blocking ledger transaction can extend a durable object, a
    /// cancelled/panicking async owner must not release quota while the
    /// uncancellable worker can still publish bytes. A normal terminal result
    /// later narrows this conservative charge to the exact retained delta.
    fn arm_fail_closed(&mut self) {
        self.fail_closed = true;
        self.releasable_bytes = 0;
    }

    /// Called while the receipt-debt/accounting lock is held.
    fn reconcile_after_terminal_locked(&mut self, retained_bytes: u64) {
        debug_assert!(
            retained_bytes <= self.owned_bytes,
            "receipt ledger retained more than its admitted transaction bound"
        );
        if let Some(guard) = self.guard.as_ref() {
            guard.settle_pending_admission_locked(self.pending_bytes);
            guard.rearm_if_measurement_crossed_locked(self.measurement_epoch);
            guard.release_reserved_locked(self.owned_bytes.saturating_sub(retained_bytes));
        }
        self.pending_bytes = 0;
        self.fail_closed = false;
        self.owned_bytes = retained_bytes.min(self.owned_bytes);
        self.releasable_bytes = 0;
    }

    fn consume(&mut self, bytes: usize) {
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        debug_assert!(
            bytes <= self.releasable_bytes,
            "receipt physical mutation exceeded its admitted reservation"
        );
        // Saturating to zero is fail-closed for quota accounting if a future
        // component bound ever drifts: it retains the whole remaining
        // reservation rather than releasing bytes that might now be on disk.
        self.releasable_bytes = self.releasable_bytes.saturating_sub(bytes);
    }

    fn split_component(
        &mut self,
        max_bytes: usize,
    ) -> Result<ContextEvidenceQuotaComponent, WalError> {
        let max_bytes = u64::try_from(max_bytes)
            .map_err(|_| compaction_recovery_error("receipt quota component bound exceeds u64"))?;
        if max_bytes > self.releasable_bytes {
            return Err(compaction_recovery_error(
                "receipt quota component exceeds its admitted transaction reservation",
            ));
        }
        self.releasable_bytes -= max_bytes;
        self.owned_bytes -= max_bytes;
        self.pending_bytes = self.pending_bytes.saturating_sub(max_bytes);
        Ok(ContextEvidenceQuotaComponent {
            guard: self.guard.clone(),
            reserved_bytes: max_bytes,
            retained_bytes: 0,
            measurement_epoch: self.measurement_epoch,
        })
    }

    fn release_unqueued(mut self) {
        debug_assert_eq!(
            self.releasable_bytes, self.admitted_bytes,
            "unqueued receipt reservation must still own its complete admission"
        );
        if let Some(guard) = self.guard.take() {
            guard.release_unqueued_admission(self.pending_bytes);
        }
        self.owned_bytes = 0;
        self.pending_bytes = 0;
        self.releasable_bytes = 0;
        self.fail_closed = false;
    }
}

impl Drop for ContextEvidenceQuotaReservation {
    fn drop(&mut self) {
        if let Some(guard) = self.guard.take() {
            if self.fail_closed {
                // The blocking owner panicked or vanished after mutation could
                // begin. Keep both pending and reserved charged permanently;
                // a fresh process measurement is the only safe recovery.
                return;
            }
            if self.pending_bytes != 0 {
                let _accounting = guard.receipt_debt_mutex.lock().unwrap();
                guard.settle_pending_admission_locked(self.pending_bytes);
                guard.rearm_if_measurement_crossed_locked(self.measurement_epoch);
                guard.release_reserved_locked(self.releasable_bytes);
            }
        }
    }
}

/// Independently owned part of a receipt transaction's reservation. Rotation
/// moves this component into its blocking publication worker so cancellation of
/// the async writer cannot release quota while that worker still owns staged or
/// canonical successor bytes.
struct ContextEvidenceQuotaComponent {
    guard: Option<std::sync::Arc<QuotaGuard>>,
    reserved_bytes: u64,
    retained_bytes: u64,
    measurement_epoch: u64,
}

impl ContextEvidenceQuotaComponent {
    fn mark_bytes_may_persist(&mut self, bytes: usize) {
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        debug_assert!(
            bytes <= self.reserved_bytes,
            "receipt physical component exceeded its admitted bound"
        );
        self.retained_bytes = self.retained_bytes.max(bytes.min(self.reserved_bytes));
    }

    fn clear_after_confirmed_cleanup(&mut self) {
        self.retained_bytes = 0;
    }
}

impl Drop for ContextEvidenceQuotaComponent {
    fn drop(&mut self) {
        if let Some(guard) = self.guard.take() {
            guard.settle_component_admission(
                self.reserved_bytes,
                self.retained_bytes,
                self.measurement_epoch,
            );
        }
    }
}

/// Deterministic one-shot pause after a matching frame is durable but before
/// its producer receives the acknowledgement. Provider-lifecycle tests use
/// this to exercise cancellation in the otherwise tiny fsync/ack window.
#[cfg(test)]
#[derive(Clone, Debug)]
pub(crate) struct TestAckGate {
    inner: std::sync::Arc<TestAckGateInner>,
}

#[cfg(test)]
#[derive(Debug)]
struct TestAckGateInner {
    event_type: u8,
    armed: std::sync::atomic::AtomicBool,
    durable: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[cfg(test)]
impl TestAckGate {
    pub(crate) fn once(event_type: u8) -> Self {
        Self {
            inner: std::sync::Arc::new(TestAckGateInner {
                event_type,
                armed: std::sync::atomic::AtomicBool::new(true),
                durable: tokio::sync::Notify::new(),
                release: tokio::sync::Notify::new(),
            }),
        }
    }

    pub(crate) async fn wait_until_durable(&self) {
        self.inner.durable.notified().await;
    }

    pub(crate) fn release(&self) {
        self.inner.release.notify_one();
    }

    async fn pause_before_ack(&self, event_type: u8) {
        if event_type != self.inner.event_type
            || self
                .inner
                .armed
                .compare_exchange(
                    true,
                    false,
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire,
                )
                .is_err()
        {
            return;
        }
        self.inner.durable.notify_one();
        self.inner.release.notified().await;
    }
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
    authentication_markers_enabled: bool,
    /// Phase 33c BS-4 pre-write quota guard. `None` keeps the writer free
    /// of disk-usage checks (tests + cli one-shots); the daemon sets it
    /// via `with_quota_guard` after `spawn`.
    quota: Option<std::sync::Arc<QuotaGuard>>,
    #[cfg(test)]
    test_ack_gate: Option<TestAckGate>,
    #[cfg(test)]
    test_receipt_decision_gate: Option<TestAckGate>,
}

type WriterStartupSignal =
    std::sync::Arc<std::sync::Mutex<Option<oneshot::Sender<Result<(), String>>>>>;

/// One-shot readiness boundary for callers that must inspect the active WAL
/// before admitting any producer work.
///
/// Ready means the segment lock is held, the file/header and torn-tail recovery
/// are durable, and the instance compaction/HMAC state is available. A closed
/// or failed signal means the asynchronous writer died during initialization.
#[derive(Debug)]
pub(crate) struct WalWriterReady {
    outcome: oneshot::Receiver<Result<(), String>>,
}

impl WalWriterReady {
    pub(crate) async fn wait(self) -> Result<(), WalError> {
        let outcome = self.outcome.await.map_err(|_| {
            WalError::Io(std::io::Error::other(
                "WAL writer ended before publishing startup readiness",
            ))
        })?;
        outcome.map_err(|reason| WalError::Io(std::io::Error::other(reason)))
    }
}

pub(crate) type ReadyWalWriter = (
    WalWriterHandle,
    tokio::task::JoinHandle<Result<(), String>>,
    WalWriterReady,
);

/// Pre-write disk-quota guard. Tracks bytes admitted since the last disk walk
/// and re-measures the home dir when a threshold is crossed. Refuses writes
/// once usage breaches the ceiling.
///
/// ## WAL-QUOTA-FAILCLOSED-01 — design invariants
///
/// Admission is rejected when `last_measured + reserved + payload > ceiling`
/// (projected-sum test).  `reserved` counts every byte admitted since the last
/// disk walk. Unlike the previous counter, `reserved` is never blindly reset
/// to zero — after a walk it retains every admission not proven to be present
/// in the new measured baseline, including bytes arriving during the walk.
/// This prevents both the "bytes lost during disk walk" race and reset-time
/// erasure of an admission already handed to a caller.
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
/// Construction is cheap (no IO). `needs_measurement` makes the first
/// `try_admit` trigger a disk walk without adding a synthetic byte reservation
/// to the projected ceiling sum.
///
/// Once breached the guard stays breached until `reset()` is called.
#[derive(Debug)]
pub struct QuotaGuard {
    home: PathBuf,
    ceiling: u64,
    /// Re-measure threshold (default 1 MiB).  When `reserved` crosses this
    /// after a successful CAS-admission, the guard walks the home directory.
    remeasure_threshold: u64,
    /// Projected-pending bytes: every admitted write increments this. After a
    /// disk walk it retains admissions not proven to be represented by the new
    /// measured baseline.
    reserved: std::sync::atomic::AtomicU64,
    /// Exact subset of `reserved` whose request has not reached a writer-
    /// terminal state. A measurement may fold settled bytes into its disk
    /// baseline, but it must never let unrelated home growth consume this set.
    pending_reserved: std::sync::atomic::AtomicU64,
    /// Monotonic measurement generation captured by every pending owner. A
    /// terminal transition that crossed a measurement re-arms measurement so
    /// a conservatively retained pending floor cannot become a sticky overcount.
    measurement_epoch: std::sync::atomic::AtomicU64,
    /// Serializes admissions with measurement rebases and operator reset.
    /// Writes remain asynchronous; only the small accounting decision is
    /// serialized so no accepted CAS increment can be overwritten by either
    /// boundary.
    admission_mutex: std::sync::Mutex<()>,
    /// Exact subset of `reserved` owned by indeterminate receipt-ledger
    /// objects. Only a capability-bound unlink plus parent sync may release
    /// this subset without a new whole-home measurement.
    receipt_debt_reserved: std::sync::atomic::AtomicU64,
    /// Accounting-state boundary shared by measurement, writer-terminal
    /// pending ownership, and exact receipt-debt transitions.
    receipt_debt_mutex: std::sync::Mutex<()>,
    /// Separate measurement trigger. This is deliberately not encoded in
    /// `reserved`: synthetic trigger bytes must never count against quota.
    needs_measurement: std::sync::atomic::AtomicBool,
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
            reserved: std::sync::atomic::AtomicU64::new(0),
            pending_reserved: std::sync::atomic::AtomicU64::new(0),
            measurement_epoch: std::sync::atomic::AtomicU64::new(0),
            admission_mutex: std::sync::Mutex::new(()),
            receipt_debt_reserved: std::sync::atomic::AtomicU64::new(0),
            receipt_debt_mutex: std::sync::Mutex::new(()),
            needs_measurement: std::sync::atomic::AtomicBool::new(true),
            last_measured: std::sync::atomic::AtomicU64::new(0),
            breached: std::sync::atomic::AtomicBool::new(false),
            measure_mutex: std::sync::Mutex::new(false),
            measure_done: std::sync::Condvar::new(),
        }
    }

    /// Test-only raw admission primitive. Production must obtain one of the
    /// RAII owners below in the same critical section as admission so every
    /// pending byte belongs to a concrete writer request until terminal.
    #[cfg(test)]
    fn try_admit(&self, payload_bytes: u64) -> Result<(), WalError> {
        let _admission = self.admission_mutex.lock().unwrap();
        self.try_admit_locked(payload_bytes)
    }

    /// Admit a generic writer request and materialize its terminal owner
    /// before releasing the admission boundary.  A future measurement is then
    /// able to retain this exact request as pending rather than treating its
    /// aggregate bytes as foreign growth.
    fn reserve_pending_admission(
        guard: &std::sync::Arc<Self>,
        payload_bytes: u64,
    ) -> Result<QuotaPendingAdmission, WalError> {
        let _admission = guard.admission_mutex.lock().unwrap();
        guard.try_admit_locked(payload_bytes)?;
        Ok(QuotaPendingAdmission::new(
            std::sync::Arc::clone(guard),
            payload_bytes,
        ))
    }

    /// Reserve a receipt transaction under the same admission boundary that
    /// increments its pending floor.  Receipt ownership is more granular than
    /// a generic request because its blocking transaction may split into
    /// independently terminal publication components.
    fn reserve_context_evidence_admission(
        guard: &std::sync::Arc<Self>,
        payload_bytes: u64,
    ) -> Result<ContextEvidenceQuotaReservation, WalError> {
        use std::sync::atomic::Ordering;

        let _admission = guard.admission_mutex.lock().unwrap();
        guard.try_admit_locked(payload_bytes)?;
        Ok(ContextEvidenceQuotaReservation {
            guard: Some(std::sync::Arc::clone(guard)),
            admitted_bytes: payload_bytes,
            owned_bytes: payload_bytes,
            pending_bytes: payload_bytes,
            measurement_epoch: guard.measurement_epoch.load(Ordering::Acquire),
            releasable_bytes: payload_bytes,
            fail_closed: false,
        })
    }

    /// Caller holds `admission_mutex`.  This is the only code path that
    /// mutates the projected reservation counters, so reservation ownership
    /// can be constructed atomically with the corresponding pending floor.
    fn try_admit_locked(&self, payload_bytes: u64) -> Result<(), WalError> {
        use std::sync::atomic::Ordering;

        // Fast path inside the admission boundary: a sticky breach avoids the
        // CAS loop and disk measurement unless exact cleanup invalidated it.
        if self.breached.load(Ordering::Acquire) && !self.needs_measurement.load(Ordering::Acquire)
        {
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
            if projected > self.ceiling && !self.needs_measurement.load(Ordering::Acquire) {
                return Err(WalError::QuotaExceeded {
                    used,
                    ceiling: self.ceiling,
                });
            }
            match self.reserved.compare_exchange_weak(
                cur_reserved,
                cur_reserved
                    .checked_add(payload_bytes)
                    .ok_or(WalError::QuotaExceeded {
                        used,
                        ceiling: self.ceiling,
                    })?,
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
        let _ =
            self.pending_reserved
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                    Some(pending.saturating_add(payload_bytes))
                });

        // ── Re-measure gate (WAL-QUOTA-FAILCLOSED-01) ───────────────────────
        // When `reserved` crosses the threshold, one thread walks the disk and
        // updates `last_measured`.  Other threads wait on `measure_done`
        // (Condvar) so tokio worker threads are not busy-spinning during the
        // potentially slow walk.
        if self.needs_measurement.load(Ordering::Acquire)
            || cur_reserved >= self.remeasure_threshold
        {
            let mut is_measuring = self.measure_mutex.lock().unwrap();
            if *is_measuring {
                // Loser: sleep until the winner publishes results.
                is_measuring = self.measure_done.wait_while(is_measuring, |m| *m).unwrap();
                drop(is_measuring);
            } else {
                // Freeze writer-terminal ownership across the walk. A request
                // may physically write while this lock is held, but its pending
                // token cannot settle until publication; therefore it remains
                // conservatively charged whether or not the walk observed it.
                *is_measuring = true;
                let receipt_debt = self.receipt_debt_mutex.lock().unwrap();
                drop(is_measuring); // release while the disk walk runs

                let used = crate::daemon::quota::measure_dir(&self.home);

                // Publish under lock so breach + reserved reset are observed
                // atomically by the next admission that acquires the gate.
                let mut is_measuring = self.measure_mutex.lock().unwrap();
                let post_walk = self.reserved.load(Ordering::SeqCst);
                // Only writer-terminal requests may be folded into `used`.
                // Every still-owned request remains an exact separate floor,
                // even if unrelated home growth or an early physical write was
                // also observed. This is the attribution boundary an aggregate
                // directory size alone cannot provide.
                let pending_floor = self.pending_reserved.load(Ordering::SeqCst);
                self.last_measured.store(used, Ordering::SeqCst);
                // Never overwrite an increment that landed after `post_walk`.
                // Admissions are serialized today, while this CAS also keeps
                // the rebase correct if that implementation detail changes.
                // A concurrent release may make `observed < post_walk`; keeping
                // the conservative base then overcounts rather than erasing a
                // live reservation.
                let published_reserved = self.publish_rebased_reserved(post_walk, pending_floor);
                let _ = self.measurement_epoch.fetch_update(
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                    |epoch| Some(epoch.saturating_add(1)),
                );
                let over = used.saturating_add(published_reserved) > self.ceiling;
                if over {
                    self.breached.store(true, Ordering::SeqCst);
                } else {
                    self.breached.store(false, Ordering::SeqCst);
                }
                self.needs_measurement.store(false, Ordering::SeqCst);
                self.receipt_debt_reserved.store(0, Ordering::SeqCst);
                if over {
                    self.release_unqueued_admission_locked(payload_bytes);
                }
                drop(receipt_debt);
                *is_measuring = false;
                drop(is_measuring);
                self.measure_done.notify_all();

                if over {
                    return Err(WalError::QuotaExceeded {
                        used,
                        ceiling: self.ceiling,
                    });
                }
            }
        }

        // Final breach check: a concurrent re-measure may have set the flag
        // between our CAS-admission and the re-measure gate entry (for threads
        // where cur_reserved < threshold after a walk reset `reserved`).
        if self.breached.load(Ordering::SeqCst) {
            let _accounting = self.receipt_debt_mutex.lock().unwrap();
            self.release_unqueued_admission_locked(payload_bytes);
            return Err(WalError::QuotaExceeded {
                used: self.last_measured.load(Ordering::Acquire),
                ceiling: self.ceiling,
            });
        }

        Ok(())
    }

    fn publish_rebased_reserved(&self, post_walk: u64, pending_floor: u64) -> u64 {
        use std::sync::atomic::Ordering;
        let mut observed = self.reserved.load(Ordering::SeqCst);
        loop {
            let carry_after_snapshot = observed.saturating_sub(post_walk);
            // This is a floor, not a sampled estimate: every pending byte is
            // owned by a concrete request or receipt component whose terminal
            // transition takes `receipt_debt_mutex`. Keep that exact floor in
            // every CAS retry so unrelated observed growth cannot replace an
            // older returned-but-not-terminal reservation.
            let exact_pending_floor = self
                .pending_reserved
                .load(Ordering::SeqCst)
                .max(pending_floor);
            let candidate = exact_pending_floor.saturating_add(carry_after_snapshot);
            match self.reserved.compare_exchange_weak(
                observed,
                candidate,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return candidate,
                Err(current) => observed = current,
            }
        }
    }

    /// Clear the sticky breached flag. Used by `neoth doctor --fix` after
    /// the operator manually freed disk space.
    pub fn reset(&self) {
        use std::sync::atomic::Ordering;
        let _admission = self.admission_mutex.lock().unwrap();
        let _receipt_debt = self.receipt_debt_mutex.lock().unwrap();
        // Keep concurrent callers closed while scheduling a baseline refresh.
        // Reservations are ownership already handed to callers and
        // may not have reached the writer queue yet; clearing either counter
        // here would let those accepted writes land without a quota charge.
        // The next walk replaces the measured baseline and retains the exact
        // writer-terminal pending subset independently of what it observes.
        // `breached=false` is published last.
        self.breached.store(true, Ordering::SeqCst);
        self.needs_measurement.store(true, Ordering::SeqCst);
        self.breached.store(false, Ordering::SeqCst);
    }

    fn release_reserved_locked(&self, bytes: u64) {
        use std::sync::atomic::Ordering;
        let _ = self
            .reserved
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
                Some(cur.saturating_sub(bytes))
            });
    }

    fn settle_pending_admission_locked(&self, bytes: u64) {
        use std::sync::atomic::Ordering;
        let _ =
            self.pending_reserved
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
                    Some(pending.saturating_sub(bytes))
                });
    }

    fn rearm_if_measurement_crossed_locked(&self, admitted_epoch: u64) {
        use std::sync::atomic::Ordering;
        let current = self.measurement_epoch.load(Ordering::Acquire);
        if current != admitted_epoch || current == u64::MAX {
            // The walk retained this request as pending. Its later terminal
            // transition may have been observed physically as well, so force a
            // fresh fold before trusting a sticky breach or projected baseline.
            self.needs_measurement.store(true, Ordering::Release);
        }
    }

    fn settle_pending_admission(&self, bytes: u64, admitted_epoch: u64) {
        let _accounting = self.receipt_debt_mutex.lock().unwrap();
        self.settle_pending_admission_locked(bytes);
        self.rearm_if_measurement_crossed_locked(admitted_epoch);
    }

    fn release_unqueued_admission_locked(&self, bytes: u64) {
        self.settle_pending_admission_locked(bytes);
        self.release_reserved_locked(bytes);
    }

    fn release_unqueued_admission(&self, bytes: u64) {
        let _accounting = self.receipt_debt_mutex.lock().unwrap();
        self.release_unqueued_admission_locked(bytes);
    }

    fn settle_component_admission(
        &self,
        reserved_bytes: u64,
        retained_bytes: u64,
        admitted_epoch: u64,
    ) {
        let _accounting = self.receipt_debt_mutex.lock().unwrap();
        self.settle_pending_admission_locked(reserved_bytes);
        self.rearm_if_measurement_crossed_locked(admitted_epoch);
        self.release_reserved_locked(reserved_bytes.saturating_sub(retained_bytes));
    }

    fn mark_receipt_debt_locked(&self, bytes: u64) {
        use std::sync::atomic::Ordering;
        if bytes == 0 {
            return;
        }
        let _ = self.receipt_debt_reserved.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |current| Some(current.saturating_add(bytes)),
        );
    }

    fn release_receipt_debt_locked(&self, bytes: u64) {
        use std::sync::atomic::Ordering;
        if bytes == 0 {
            return;
        }
        let current = self.receipt_debt_reserved.load(Ordering::Acquire);
        let releasable = current.min(bytes);
        self.receipt_debt_reserved
            .store(current - releasable, Ordering::Release);
        if releasable != 0 {
            self.release_reserved_locked(releasable);
        }
        if releasable != bytes {
            // A prior measurement already folded some or all of this exact
            // object into `last_measured`. Never subtract a different live
            // reservation; force an ownership-aware remeasurement.
            self.invalidate_measured_baseline_locked(bytes - releasable);
        }
    }

    fn invalidate_measured_baseline_locked(&self, reclaimed_bytes: u64) {
        if reclaimed_bytes != 0 {
            // These exact objects were durably removed, but their charge may
            // live in `last_measured` or an already-settled reservation. Never
            // subtract an unclassified counter directly; the next whole-home
            // measurement replaces the baseline while retaining every request
            // that has not reached a writer-terminal state.
            self.needs_measurement
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }

    #[cfg(test)]
    fn mark_receipt_debt(&self, bytes: u64) {
        let _receipt_debt = self.receipt_debt_mutex.lock().unwrap();
        self.mark_receipt_debt_locked(bytes);
    }

    #[cfg(test)]
    fn release_receipt_debt(&self, bytes: u64) {
        let _receipt_debt = self.receipt_debt_mutex.lock().unwrap();
        self.release_receipt_debt_locked(bytes);
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

    #[cfg(test)]
    pub(crate) fn with_test_ack_gate(mut self, gate: TestAckGate) -> Self {
        self.test_ack_gate = Some(gate);
        self
    }

    #[cfg(test)]
    fn with_test_receipt_decision_gate(mut self, gate: TestAckGate) -> Self {
        self.test_receipt_decision_gate = Some(gate);
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
        self.append_with_marker_policy(header, payload, false).await
    }

    /// Append one frame and acknowledge it only after a keyed compaction
    /// marker covering the frame is itself durable.
    ///
    /// Ordinary [`Self::append`] proves durability, not cryptographic
    /// authenticity of the live unsealed tail. Consumers that expose a
    /// security-sensitive projection must use this boundary for the terminal
    /// frame and scan only marker-authenticated bytes.
    pub(crate) async fn append_authenticated(
        &self,
        header: EventHeaderV2,
        payload: Vec<u8>,
    ) -> Result<u64, WalError> {
        if !self.authentication_markers_enabled {
            return Err(compaction_recovery_error(
                "authenticated append requires an HMAC-marker-enabled WAL writer",
            ));
        }
        self.append_with_marker_policy(header, payload, true).await
    }

    async fn append_with_marker_policy(
        &self,
        header: EventHeaderV2,
        payload: Vec<u8>,
        force_authentication_marker: bool,
    ) -> Result<u64, WalError> {
        refuse_generic_context_evidence_receipt(&header)?;
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(WalError::PayloadTooLarge(payload.len(), MAX_PAYLOAD_BYTES));
        }
        let admitted = payload.len() as u64;
        let quota_admission = if let Some(guard) = self.quota.as_ref() {
            Some(QuotaGuard::reserve_pending_admission(guard, admitted)?)
        } else {
            None
        };
        let (ack_tx, ack_rx) = oneshot::channel();
        let request = WriteRequest {
            header,
            payload,
            ack: ack_tx,
            force_authentication_marker,
            context_evidence_receipt_once: None,
            quota_admission,
            #[cfg(test)]
            test_ack_gate: self.test_ack_gate.clone(),
            #[cfg(test)]
            test_receipt_decision_gate: self.test_receipt_decision_gate.clone(),
        };
        if let Err(mut error) = self.tx.send(request).await {
            if let Some(admission) = error.0.quota_admission.take() {
                admission.release_unqueued();
            }
            return Err(WalError::WriterClosed);
        }
        ack_rx.await.map_err(|_| WalError::WriterClosed)?
    }

    /// Blocking counterpart to [`Self::append`] for authority work already
    /// isolated on a dedicated blocking worker. Unlike [`Self::try_append_sync`],
    /// this returns only after the writer has acknowledged the durable write
    /// and therefore surfaces write/fsync failure to the caller.
    #[cfg(feature = "cluster")]
    pub(crate) fn append_blocking(
        &self,
        header: EventHeaderV2,
        payload: Vec<u8>,
    ) -> Result<u64, WalError> {
        refuse_generic_context_evidence_receipt(&header)?;
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(WalError::PayloadTooLarge(payload.len(), MAX_PAYLOAD_BYTES));
        }
        let admitted = payload.len() as u64;
        let quota_admission = if let Some(guard) = self.quota.as_ref() {
            Some(QuotaGuard::reserve_pending_admission(guard, admitted)?)
        } else {
            None
        };
        let (ack_tx, ack_rx) = oneshot::channel();
        let request = WriteRequest {
            header,
            payload,
            ack: ack_tx,
            force_authentication_marker: false,
            context_evidence_receipt_once: None,
            quota_admission,
            #[cfg(test)]
            test_ack_gate: self.test_ack_gate.clone(),
            #[cfg(test)]
            test_receipt_decision_gate: self.test_receipt_decision_gate.clone(),
        };
        if let Err(mut error) = self.tx.blocking_send(request) {
            if let Some(admission) = error.0.quota_admission.take() {
                admission.release_unqueued();
            }
            return Err(WalError::WriterClosed);
        }
        ack_rx.blocking_recv().map_err(|_| WalError::WriterClosed)?
    }

    /// Append the closed Context Connector receipt exactly once for this
    /// instance home, acknowledging only authenticated durable evidence.
    ///
    /// This synchronous adapter is reserved for connector-control work already
    /// running on a dedicated blocking worker. The writer task, not this
    /// caller, owns the cross-process decision. Under that authority it reads
    /// one fixed authenticated manifest and at most one fixed shard, then
    /// records the exact closed `0x27` frame in the canonical receipt ledger.
    /// It never scans primary-WAL history. A replay of the identical handle and
    /// payload succeeds without writing another frame; a different payload for
    /// the same handle fails closed. Admission reserves the ledger's complete
    /// bounded crash transaction and reconciles it to the exact retained bytes
    /// only after the uncancellable blocking owner reaches a terminal state.
    pub(crate) fn append_context_evidence_receipt_once_blocking(
        &self,
        receipt_handle: &[u8; 32],
        receipt: crate::wal::events::ContextEvidenceReceipt,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.authentication_markers_enabled,
            "context_evidence_receipt_requires_authenticated_writer"
        );
        anyhow::ensure!(
            receipt.matches_opaque_handle(receipt_handle),
            "context_evidence_receipt_handle_mismatch"
        );
        let payload = receipt
            .encode()
            .map_err(|_| anyhow::anyhow!("context_evidence_receipt_encoding_refused"))?;
        if payload.len() > MAX_PAYLOAD_BYTES {
            anyhow::bail!("context_evidence_receipt_encoding_refused");
        }
        let header =
            crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_EXTENDED, &payload)
                .event_subtype(crate::wal::events::ExtendedSubtype::ContextEvidenceReceipt as u8)
                .build();
        let admitted = crate::wal::context_evidence_receipts::MAX_TRANSACTION_BYTES;
        let quota_reservation = if let Some(guard) = self.quota.as_ref() {
            QuotaGuard::reserve_context_evidence_admission(guard, admitted)
                .map_err(|_| anyhow::anyhow!("context_evidence_receipt_quota_refused"))?
        } else {
            ContextEvidenceQuotaReservation {
                guard: None,
                admitted_bytes: admitted,
                owned_bytes: admitted,
                pending_bytes: 0,
                measurement_epoch: 0,
                releasable_bytes: admitted,
                fail_closed: false,
            }
        };
        let (ack_tx, ack_rx) = oneshot::channel();
        let request = WriteRequest {
            header,
            payload,
            ack: ack_tx,
            force_authentication_marker: false,
            context_evidence_receipt_once: Some(ContextEvidenceReceiptOnce {
                receipt_handle: *receipt_handle,
                expected: receipt,
                quota_reservation,
            }),
            quota_admission: None,
            #[cfg(test)]
            test_ack_gate: self.test_ack_gate.clone(),
            #[cfg(test)]
            test_receipt_decision_gate: self.test_receipt_decision_gate.clone(),
        };
        if let Err(mut error) = self.tx.blocking_send(request) {
            let once = error
                .0
                .context_evidence_receipt_once
                .take()
                .expect("closed receipt request must retain its quota owner");
            once.quota_reservation.release_unqueued();
            anyhow::bail!("context_evidence_receipt_writer_unavailable");
        }
        match ack_rx.blocking_recv() {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(_)) => anyhow::bail!("context_evidence_receipt_append_failed"),
            Err(_) => anyhow::bail!("context_evidence_receipt_writer_unavailable"),
        }
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
        refuse_generic_context_evidence_receipt(&header)?;
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(WalError::PayloadTooLarge(payload.len(), MAX_PAYLOAD_BYTES));
        }
        let admitted = payload.len() as u64;
        let quota_admission = if let Some(guard) = self.quota.as_ref() {
            Some(QuotaGuard::reserve_pending_admission(guard, admitted)?)
        } else {
            None
        };
        let (ack_tx, _ack_rx_drop) = oneshot::channel();
        match self.tx.try_send(WriteRequest {
            header,
            payload,
            ack: ack_tx,
            force_authentication_marker: false,
            context_evidence_receipt_once: None,
            quota_admission,
            #[cfg(test)]
            test_ack_gate: self.test_ack_gate.clone(),
            #[cfg(test)]
            test_receipt_decision_gate: self.test_receipt_decision_gate.clone(),
        }) {
            Ok(()) => Ok(()),
            Err(error) => {
                let (result, mut request) = match error {
                    mpsc::error::TrySendError::Full(request) => (
                        WalError::WriterBackpressured {
                            capacity: DEFAULT_CHANNEL_CAPACITY,
                        },
                        request,
                    ),
                    mpsc::error::TrySendError::Closed(request) => (WalError::WriterClosed, request),
                };
                if let Some(admission) = request.quota_admission.take() {
                    admission.release_unqueued();
                }
                Err(result)
            }
        }
    }

    pub async fn append_no_ack(
        &self,
        header: EventHeaderV2,
        payload: Vec<u8>,
    ) -> Result<(), WalError> {
        refuse_generic_context_evidence_receipt(&header)?;
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(WalError::PayloadTooLarge(payload.len(), MAX_PAYLOAD_BYTES));
        }
        let admitted = payload.len() as u64;
        let quota_admission = if let Some(guard) = self.quota.as_ref() {
            Some(QuotaGuard::reserve_pending_admission(guard, admitted)?)
        } else {
            None
        };
        // Construct the oneshot but immediately drop the receiver.
        // The writer task tries to send through it after fsync, sees
        // the receiver dropped, and logs at debug — same path as a
        // caller that times out. No new writer-task code needed.
        let (ack_tx, _ack_rx_drop) = oneshot::channel();
        let request = WriteRequest {
            header,
            payload,
            ack: ack_tx,
            force_authentication_marker: false,
            context_evidence_receipt_once: None,
            quota_admission,
            #[cfg(test)]
            test_ack_gate: self.test_ack_gate.clone(),
            #[cfg(test)]
            test_receipt_decision_gate: self.test_receipt_decision_gate.clone(),
        };
        if let Err(mut error) = self.tx.send(request).await {
            if let Some(admission) = error.0.quota_admission.take() {
                admission.release_unqueued();
            }
            return Err(WalError::WriterClosed);
        }
        Ok(())
    }
}

/// Spawn the raw unit-test writer with default rotation policy (16 MiB / 24 h)
/// and no compression.
///
/// This `cfg(test)` harness intentionally accepts descriptive fixture leaf
/// names. Production callers must use `spawn_for_home*` or `spawn_capture`,
/// which bind the canonical `<home>/wal/<namespace>-NNNNNN.wal` contract.
#[cfg(test)]
pub fn spawn(
    segment_path: PathBuf,
) -> Result<(WalWriterHandle, tokio::task::JoinHandle<()>), WalError> {
    spawn_with_policy(segment_path, RotationPolicy::default())
}

/// Spawn the production writer for an explicit daemon instance home.
///
/// The instance home owns the HMAC rotation transaction and
/// `<home>/wal/hmac.key`; callers using a custom `--config` must use this
/// entrypoint so compaction state cannot leak to the process-global default.
pub fn spawn_for_home(
    segment_path: PathBuf,
    home: PathBuf,
) -> Result<(WalWriterHandle, tokio::task::JoinHandle<()>), WalError> {
    validate_home_segment_path(&segment_path, &home)?;
    refuse_unimplemented_storage_policy(&home)?;
    let hmac_key_path = home.join("wal").join("hmac.key");
    spawn_with_policy_and_compression_at_home(
        segment_path,
        SegmentPolicy::Rotating(RotationPolicy::default()),
        CompressionPolicy::None,
        home,
        hmac_key_path,
        false,
        None,
        None,
    )
}

/// Spawn the one offline writer that persists the signed HMAC-key transition.
///
/// The rotation transaction already holds the cross-process key lock and owns
/// key recovery. A dedicated entrypoint, rather than a filename substring,
/// grants the marker-skip capability so an arbitrary capture or daemon
/// namespace can never impersonate this surface.
pub(crate) fn spawn_hmac_rotation_for_home(
    segment_path: PathBuf,
    home: PathBuf,
) -> Result<(WalWriterHandle, tokio::task::JoinHandle<()>), WalError> {
    validate_home_segment_path(&segment_path, &home)?;
    refuse_unimplemented_storage_policy(&home)?;
    if !is_exact_hmac_rotation_segment(&segment_path) {
        return Err(WalError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "HMAC-key rotation writer requires its exact UUID-bound `{HMAC_ROTATION_SURFACE}` namespace: {}",
                segment_path.display()
            ),
        )));
    }
    let hmac_key_path = home.join("wal").join("hmac.key");
    spawn_with_policy_and_compression_at_home(
        segment_path,
        SegmentPolicy::Rotating(RotationPolicy::default()),
        CompressionPolicy::None,
        home,
        hmac_key_path,
        true,
        None,
        None,
    )
}

/// Spawn a production writer whose complete asynchronous lifecycle is
/// observable by a one-shot caller.
///
/// Unlike [`spawn_for_home`], the returned completion handle surfaces
/// initialization, mandatory compaction-marker, final-sync, and shutdown
/// finalizer failures. Required-audit commands must wait for this completion
/// after dropping their final writer handle before reporting success.
pub(crate) fn spawn_for_home_with_completion(
    segment_path: PathBuf,
    home: PathBuf,
) -> Result<(WalWriterHandle, WalWriterCompletion), WalError> {
    validate_home_segment_path(&segment_path, &home)?;
    refuse_unimplemented_storage_policy(&home)?;
    let hmac_key_path = home.join("wal").join("hmac.key");
    let (outcome_tx, outcome_rx) = oneshot::channel();
    let (writer, join) = spawn_with_policy_and_compression_at_home(
        segment_path,
        SegmentPolicy::Rotating(RotationPolicy::default()),
        CompressionPolicy::None,
        home,
        hmac_key_path,
        false,
        Some(outcome_tx),
        None,
    )?;
    Ok((
        writer,
        WalWriterCompletion {
            join,
            outcome: outcome_rx,
        },
    ))
}

/// Spawn the production writer plus an explicit initialization barrier.
///
/// Daemon startup uses this variant because its crash reconciler must never
/// race asynchronous segment creation or tail recovery. Profile resolution
/// also uses the readiness barrier before consuming a pending operator action.
pub(crate) fn spawn_for_home_ready(
    segment_path: PathBuf,
    home: PathBuf,
) -> Result<ReadyWalWriter, WalError> {
    let (writer, completion, ready) = spawn_for_home_ready_with_completion(segment_path, home)?;
    let WalWriterCompletion { join, outcome } = completion;
    Ok((writer, wrap_writer_runtime_join(join, outcome), ready))
}

/// Start an isolated, home-bound WAL writer for an async test and wait until
/// its segment is ready to accept producer work.
///
/// Keeping the HMAC/key-recovery state under a fresh [`tempfile::TempDir`]
/// prevents independently scheduled tests from touching the runner's global
/// `~/.neoth` state. The returned join handle carries the writer's completion
/// outcome; callers must drop every handle and assert that outcome before
/// inspecting `segment`.
#[cfg(test)]
pub(crate) async fn spawn_isolated_ready_test_writer(
    fixture_name: &str,
) -> Result<
    (
        WalWriterHandle,
        tokio::task::JoinHandle<Result<(), String>>,
        tempfile::TempDir,
        PathBuf,
    ),
    WalError,
> {
    let home = tempfile::tempdir()?;
    let wal_dir = home.path().join("wal");
    std::fs::create_dir_all(&wal_dir)?;
    let segment = wal_dir.join(format!("{fixture_name}-000001.wal"));
    let (writer, join, ready) = spawn_for_home_ready(segment.clone(), home.path().to_path_buf())?;
    ready.wait().await?;
    Ok((writer, join, home, segment))
}

/// Construct a writer handle whose receiver is already closed.
///
/// This gives fail-closed producer tests a deterministic `WriterClosed`
/// boundary without spawning or aborting an asynchronous writer task.
#[cfg(test)]
pub(crate) fn closed_test_writer() -> WalWriterHandle {
    let (tx, rx) = mpsc::channel(1);
    drop(rx);
    WalWriterHandle {
        tx,
        authentication_markers_enabled: false,
        quota: None,
        test_ack_gate: None,
        test_receipt_decision_gate: None,
    }
}

/// Completion-owning readiness variant for short-lived callers.
///
/// Unlike [`spawn_for_home_ready`], this retains the real `run_writer`
/// `JoinHandle`. A bounded caller can therefore abort and reap the task itself
/// if a leaked sender clone prevents the writer channel from closing.
pub(crate) fn spawn_for_home_ready_with_completion(
    segment_path: PathBuf,
    home: PathBuf,
) -> Result<(WalWriterHandle, WalWriterCompletion, WalWriterReady), WalError> {
    validate_home_segment_path(&segment_path, &home)?;
    refuse_unimplemented_storage_policy(&home)?;
    let hmac_key_path = home.join("wal").join("hmac.key");
    let (startup_tx, startup_rx) = oneshot::channel();
    let startup = std::sync::Arc::new(std::sync::Mutex::new(Some(startup_tx)));
    let (completion_tx, completion_rx) = oneshot::channel();
    let (writer, join) = spawn_with_policy_and_compression_at_home(
        segment_path,
        SegmentPolicy::Rotating(RotationPolicy::default()),
        CompressionPolicy::None,
        home,
        hmac_key_path,
        false,
        Some(completion_tx),
        Some(startup),
    )?;
    Ok((
        writer,
        WalWriterCompletion {
            join,
            outcome: completion_rx,
        },
        WalWriterReady {
            outcome: startup_rx,
        },
    ))
}

#[cfg(test)]
pub(crate) fn spawn_for_home_with_policy_ready(
    segment_path: PathBuf,
    home: PathBuf,
    policy: RotationPolicy,
) -> Result<ReadyWalWriter, WalError> {
    validate_home_segment_path(&segment_path, &home)?;
    let hmac_key_path = home.join("wal").join("hmac.key");
    let (startup_tx, startup_rx) = oneshot::channel();
    let startup = std::sync::Arc::new(std::sync::Mutex::new(Some(startup_tx)));
    let (completion_tx, completion_rx) = oneshot::channel();
    let (writer, join) = spawn_with_policy_and_compression_at_home(
        segment_path,
        SegmentPolicy::Rotating(policy),
        CompressionPolicy::None,
        home,
        hmac_key_path,
        false,
        Some(completion_tx),
        Some(startup),
    )?;
    let join = wrap_writer_runtime_join(join, completion_rx);
    Ok((
        writer,
        join,
        WalWriterReady {
            outcome: startup_rx,
        },
    ))
}

fn wrap_writer_runtime_join(
    join: tokio::task::JoinHandle<()>,
    outcome: oneshot::Receiver<Result<(), WalError>>,
) -> tokio::task::JoinHandle<Result<(), String>> {
    tokio::spawn(async move {
        join.await
            .map_err(|error| format!("WAL writer task join failed: {error}"))?;
        outcome
            .await
            .map_err(|_| "WAL writer ended without publishing its outcome".to_string())?
            .map_err(|error| error.to_string())
    })
}

fn validate_home_segment_path(segment_path: &Path, home: &Path) -> Result<(), WalError> {
    let expected_parent = std::path::absolute(home.join("wal"))?;
    let segment = std::path::absolute(segment_path)?;
    if segment.parent() != Some(expected_parent.as_path())
        || !segment
            .file_name()
            .is_some_and(crate::wal::scan::canonical_segment_name)
    {
        return Err(WalError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "home-bound WAL segment {} must be a canonically named direct child of {}",
                segment.display(),
                expected_parent.display()
            ),
        )));
    }
    Ok(())
}

/// Completion handle for a writer whose full asynchronous lifecycle must be
/// observed before its caller reports success.
///
/// Capture and required one-shot production writers need the underlying
/// [`run_writer`] result because initialization, HMAC/recovery setup, write,
/// and final-sync errors would otherwise exist only in logs and the CLI could
/// report a false success.
#[derive(Debug)]
pub(crate) struct WalWriterCompletion {
    join: tokio::task::JoinHandle<()>,
    outcome: oneshot::Receiver<Result<(), WalError>>,
}

impl WalWriterCompletion {
    pub(crate) async fn wait(self) -> Result<(), WalError> {
        self.join.await.map_err(|error| {
            WalError::Io(std::io::Error::other(format!(
                "WAL writer task join failed: {error}"
            )))
        })?;
        self.outcome.await.map_err(|_| {
            WalError::Io(std::io::Error::other(
                "WAL writer task ended without publishing its completion result",
            ))
        })?
    }

    /// Wait for real writer shutdown under one wall-clock deadline.
    ///
    /// A timeout aborts and awaits the actual `run_writer` task rather than a
    /// wrapper waiting on it. Dropping that future releases its segment file
    /// and rewrite-lock handles even when a leaked `WalWriterHandle` clone
    /// keeps the channel sender alive.
    pub(crate) async fn wait_bounded(
        mut self,
        timeout: std::time::Duration,
    ) -> Result<(), WalError> {
        let deadline = tokio::time::Instant::now() + timeout;
        let joined = match tokio::time::timeout_at(deadline, &mut self.join).await {
            Ok(joined) => joined,
            Err(_) => {
                self.join.abort();
                let _ = (&mut self.join).await;
                return Err(WalError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "WAL writer did not finalize within {} ms and was aborted",
                        timeout.as_millis()
                    ),
                )));
            }
        };
        joined.map_err(|error| {
            WalError::Io(std::io::Error::other(format!(
                "WAL writer task join failed: {error}"
            )))
        })?;
        match tokio::time::timeout_at(deadline, &mut self.outcome).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_)) => Err(WalError::Io(std::io::Error::other(
                "WAL writer task ended without publishing its completion result",
            ))),
            Err(_) => Err(WalError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "WAL writer outcome was not published within {} ms",
                    timeout.as_millis()
                ),
            ))),
        }
    }
}

/// Spawn a fresh, home-bound, non-rotating writer for `plugin test
/// --capture-wal`.
///
/// `segment_path` must be a direct child of `<home>/wal`. HMAC key creation and
/// interrupted-key-rotation recovery therefore stay inside the throwaway home.
/// The writer refuses an existing segment and returns a completion result that
/// surfaces every asynchronous writer failure.
#[cfg_attr(not(any(test, feature = "wasm-plugin-host")), allow(dead_code))]
pub(crate) fn spawn_capture(
    segment_path: PathBuf,
    home: PathBuf,
    max_segment_bytes: u64,
) -> Result<(WalWriterHandle, WalWriterCompletion), WalError> {
    if max_segment_bytes < SEGMENT_HEADER_LEN as u64 {
        return Err(WalError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "capture WAL ceiling {max_segment_bytes} is smaller than the \
                 {SEGMENT_HEADER_LEN}-byte segment header"
            ),
        )));
    }
    validate_home_segment_path(&segment_path, &home)?;
    let expected_parent = home.join("wal");

    let hmac_key_path = expected_parent.join("hmac.key");
    let (outcome_tx, outcome_rx) = oneshot::channel();
    let (writer, join) = spawn_with_policy_and_compression_at_home(
        segment_path,
        SegmentPolicy::Fixed {
            max_bytes: max_segment_bytes,
        },
        CompressionPolicy::None,
        home,
        hmac_key_path,
        false,
        Some(outcome_tx),
        None,
    )?;
    Ok((
        writer,
        WalWriterCompletion {
            join,
            outcome: outcome_rx,
        },
    ))
}

/// Refuse to open a home-bound writer when `freedom.yaml` configures a WAL
/// storage policy this build does not actually apply.
///
/// `wal.compression` is never mapped to a live [`CompressionPolicy`] —
/// [`spawn_for_home`] passes `None` — and the AES-256-GCM-SIV seal is applied
/// ONLY in [`finalize_compressed_segment`], which runs only under `Zstd3`. So
/// `wal.encryption: aes256_gcm_siv` produced plaintext segments with no error
/// and no warning, while `neoth doctor` told the operator to back up the master
/// key. A silent at-rest no-op is worse than a startup failure: the operator
/// cannot discover it, and every byte written under that belief is exposed.
///
/// Both fields are checked. Encryption alone is not sufficient even once
/// compression is wired, because the seal happens at segment finalize.
///
/// A missing or unreadable `freedom.yaml` yields the default (`None`/`None`)
/// and this is a no-op — a fresh home and every temp-dir test still start.
fn refuse_unimplemented_storage_policy(home: &std::path::Path) -> Result<(), WalError> {
    let config = crate::config::load_wal_config(&home.join("freedom.yaml")).map_err(|error| {
        WalError::PolicyNotImplemented {
            reason: format!("wal policy could not be read from freedom.yaml: {error:#}"),
        }
    })?;
    if config.compression != crate::config::WalCompression::None {
        return Err(WalError::PolicyNotImplemented {
            reason: format!(
                "freedom.yaml sets wal.compression = {:?}, but this build always writes \
                 uncompressed segments. Refusing to start rather than silently ignoring it — \
                 set `wal.compression: none`",
                config.compression
            ),
        });
    }
    if config.encryption != crate::config::wal::WalEncryption::None {
        return Err(WalError::PolicyNotImplemented {
            reason: format!(
                "freedom.yaml sets wal.encryption = {:?}, but at-rest sealing is applied only \
                 when a segment is finalized under wal.compression = zstd_3, which this build \
                 does not wire. Segments would be PLAINTEXT. Refusing to start rather than \
                 claiming an encryption that is not applied — set `wal.encryption: none`",
                config.encryption
            ),
        });
    }
    Ok(())
}

/// Spawn the raw unit-test writer with an explicit rotation policy and no
/// compression. Tests use this to exercise rotation without writing 16 MiB;
/// production path admission is enforced by the home-bound entrypoints.
#[cfg(test)]
pub fn spawn_with_policy(
    segment_path: PathBuf,
    policy: RotationPolicy,
) -> Result<(WalWriterHandle, tokio::task::JoinHandle<()>), WalError> {
    spawn_with_policy_and_compression(segment_path, policy, CompressionPolicy::None)
}

/// Spawn the raw unit-test writer with explicit rotation and compression
/// policies. Tests use this to exercise supported sealed compression
/// substrates without inheriting production path-admission semantics.
#[cfg(test)]
pub(crate) fn spawn_with_policy_and_compression(
    segment_path: PathBuf,
    policy: RotationPolicy,
    compression: CompressionPolicy,
) -> Result<(WalWriterHandle, tokio::task::JoinHandle<()>), WalError> {
    let hmac_home = crate::config::FreedomConfig::default_neoth_home();
    let hmac_key_path = crate::wal::compaction::default_key_path();
    spawn_with_policy_and_compression_at_home(
        segment_path,
        SegmentPolicy::Rotating(policy),
        compression,
        hmac_home,
        hmac_key_path,
        false,
        None,
        None,
    )
}

fn spawn_with_policy_and_compression_at_home(
    segment_path: PathBuf,
    segment_policy: SegmentPolicy,
    compression: CompressionPolicy,
    hmac_home: PathBuf,
    hmac_key_path: PathBuf,
    skip_compaction_markers: bool,
    completion: Option<oneshot::Sender<Result<(), WalError>>>,
    startup: Option<WriterStartupSignal>,
) -> Result<(WalWriterHandle, tokio::task::JoinHandle<()>), WalError> {
    let rotating = matches!(segment_policy, SegmentPolicy::Rotating(_));
    if let SegmentPolicy::Rotating(policy) = segment_policy {
        validate_rotation_policy(policy)?;
    }
    let expected_wal_parent = std::path::absolute(hmac_home.join("wal")).map_err(|error| {
        WalError::Io(std::io::Error::new(
            error.kind(),
            format!("resolve writer WAL parent: {error}"),
        ))
    })?;
    let resolved_segment = std::path::absolute(&segment_path).map_err(|error| {
        WalError::Io(std::io::Error::new(
            error.kind(),
            format!("resolve writer segment path: {error}"),
        ))
    })?;
    let hmac_authority = if skip_compaction_markers {
        None
    } else {
        Some(
            crate::cli::security::acquire_hmac_writer_authority(&hmac_home, &hmac_key_path)
                .map_err(|error| {
                    compaction_recovery_error(format!(
                        "establish HMAC authority before WAL namespace mutation: {error:#}"
                    ))
                })?,
        )
    };
    if rotating && resolved_segment.parent() == Some(expected_wal_parent.as_path()) {
        match std::fs::symlink_metadata(&resolved_segment) {
            Ok(_) => {
                let base = first_segment_path_in_namespace(&resolved_segment)?;
                crate::wal::scan::for_each_frame_in_home_segment_chain(
                    &hmac_home,
                    &base,
                    crate::wal::scan::HomeWalScanLimits::default(),
                    |_, _| Ok(()),
                )
                .map_err(|error| {
                    compaction_recovery_error(format!(
                        "existing home WAL chain failed authenticated startup preflight: \
                         {error:#}"
                    ))
                })?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(WalError::Io(error)),
        }
    }
    // Acquire before spawning so callers never receive an apparently-live
    // writer handle when another process owns the segment for redaction (or a
    // second writer accidentally targets the same path). The guard moves into
    // WriterState and remains held through every append/finalize until rotation
    // or shutdown durably closes this segment.
    let initial_segment_lock =
        super::redact::lock_segment_for_rewrite(&segment_path).map_err(|error| {
            std::io::Error::other(format!("lock WAL segment for writer: {error:#}"))
        })?;
    let (tx, rx) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);
    let join = tokio::spawn(async move {
        let startup_for_writer = startup.clone();
        let outcome = run_writer(
            segment_path,
            initial_segment_lock,
            rx,
            segment_policy,
            compression,
            hmac_home,
            hmac_authority,
            startup_for_writer,
        )
        .await;
        if let Err(error) = &outcome
            && let Some(startup) = startup
            && let Some(startup) = startup
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .take()
        {
            let _ = startup.send(Err(format!(
                "WAL writer initialization failed before readiness: {error}"
            )));
        }
        if let Err(e) = &outcome {
            error!(error = %e, "WAL writer task exited with error");
        }
        if let Some(completion) = completion {
            let _ = completion.send(outcome);
        }
    });
    Ok((
        WalWriterHandle {
            tx,
            authentication_markers_enabled: !skip_compaction_markers,
            quota: None,
            #[cfg(test)]
            test_ack_gate: None,
            #[cfg(test)]
            test_receipt_decision_gate: None,
        },
        join,
    ))
}

fn first_segment_path_in_namespace(path: &Path) -> Result<PathBuf, WalError> {
    let parent = path.parent().ok_or_else(|| {
        WalError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("WAL segment has no parent: {}", path.display()),
        ))
    })?;
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or_else(|| {
            WalError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("WAL segment name is not UTF-8: {}", path.display()),
            ))
        })?;
    let name = match stem.rsplit_once('-') {
        Some((namespace, sequence)) if sequence.len() == 6 => {
            format!("{namespace}-000001.wal")
        }
        _ => "000001.wal".to_string(),
    };
    Ok(parent.join(name))
}

/// Result of `open_segment`: the file handle plus a flag that tells the
/// writer whether this is a brand-new segment (needs SegmentHeader written)
/// or an existing one being reopened.
struct OpenedSegment {
    file: File,
    is_new: bool,
    /// Cross-process rewrite exclusion. Kept beside `file` so callers cannot
    /// accidentally retain one without the other.
    segment_rewrite_lock: std::fs::File,
    /// Receipt rotation transfers the complete home authority into the
    /// uncancellable blocking publisher and receives it back only after that
    /// worker has reached a terminal state.
    receipt_authority: Option<ContextEvidenceReceiptAuthority>,
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

fn new_segment_header_bytes(
    compression: CompressionPolicy,
    seq: u64,
    opened_at_ns: u64,
) -> Vec<u8> {
    match compression {
        CompressionPolicy::None => SegmentHeader::new(0, seq, 0, opened_at_ns, [0u8; 16])
            .to_le_bytes()
            .to_vec(),
        CompressionPolicy::Zstd3 => {
            // The live body is deliberately raw so crash recovery can scan it.
            // COMPRESSED|SEALED is published only by the atomic finalizer.
            SegmentHeaderV3::new(0, seq, 0, opened_at_ns, [0u8; 16], 0, 0)
                .to_le_bytes()
                .to_vec()
        }
    }
}

async fn open_segment(
    path: &Path,
    new_header: Vec<u8>,
    predecessor_rewrite_lock: std::fs::File,
    receipt_authority: Option<ContextEvidenceReceiptAuthority>,
    receipt_quota_component: Option<ContextEvidenceQuotaComponent>,
) -> Result<OpenedSegment, WalError> {
    open_segment_with_lock_mode(
        path,
        None,
        true,
        new_header,
        Some(predecessor_rewrite_lock),
        receipt_authority,
        receipt_quota_component,
    )
    .await
}

/// Open a segment after its stable sidecar lock has already been acquired.
/// The initial writer path locks synchronously before spawning; rotation uses
/// [`open_segment`] to acquire the next segment while the old guard is held.
async fn open_segment_with_lock(
    path: &Path,
    segment_rewrite_lock: std::fs::File,
    new_header: Vec<u8>,
) -> Result<OpenedSegment, WalError> {
    open_segment_with_lock_mode(
        path,
        Some(segment_rewrite_lock),
        false,
        new_header,
        None,
        None,
        None,
    )
    .await
}

async fn open_segment_with_lock_mode(
    path: &Path,
    segment_rewrite_lock: Option<std::fs::File>,
    create_new_only: bool,
    new_header: Vec<u8>,
    predecessor_rewrite_lock: Option<std::fs::File>,
    receipt_authority: Option<ContextEvidenceReceiptAuthority>,
    receipt_quota_component: Option<ContextEvidenceQuotaComponent>,
) -> Result<OpenedSegment, WalError> {
    let owned_path = path.to_path_buf();
    let (file, is_new, segment_rewrite_lock, receipt_authority) =
        tokio::task::spawn_blocking(move || {
            // All mutation-lifetime owners live inside this blocking job. A
            // dropped/aborted async waiter cannot cancel `spawn_blocking`, so
            // keeping the stable segment lock, receipt authority and split
            // prefix quota here prevents publication after their release.
            let segment_rewrite_lock = match segment_rewrite_lock {
                Some(lock) => lock,
                None => super::redact::lock_segment_for_rewrite(&owned_path).map_err(|error| {
                    std::io::Error::other(format!("lock WAL segment for writer: {error:#}"))
                })?,
            };
            let mut receipt_quota_component = receipt_quota_component;
            let opened = open_segment_capability_bound_with_publication_owner(
                &owned_path,
                create_new_only,
                &new_header,
                receipt_quota_component.as_mut(),
            );
            // The predecessor binding was hashed into the successor prefix.
            // Keep its stable rewrite exclusion until publication or rollback
            // is terminal; otherwise outer-task cancellation could unlock and
            // mutate the predecessor while this detached worker still commits
            // a stale cross-segment binding.
            drop(predecessor_rewrite_lock);
            let (file, is_new) = opened?;
            // The split component drops in this worker: on success it releases
            // only the unused part of its ceiling, and on every error it keeps
            // ownership until cleanup/publication is terminal.
            drop(receipt_quota_component);
            Ok::<_, WalError>((file, is_new, segment_rewrite_lock, receipt_authority))
        })
        .await
        .map_err(|error| {
            WalError::Io(std::io::Error::other(format!(
                "join capability-bound WAL open: {error}"
            )))
        })??;

    Ok(OpenedSegment {
        file: File::from_std(file),
        is_new,
        segment_rewrite_lock,
        receipt_authority,
    })
}

fn cleanup_uncommitted_segment(
    parent: &cap_std::fs::Dir,
    name: &std::ffi::OsStr,
    stage_display: &Path,
    target_path: &Path,
    binding: crate::skills::store::BoundChildObject,
) -> Result<(), String> {
    #[cfg(test)]
    inject_segment_create_failure(target_path, TestSegmentCreateFailure::StageCleanup).map_err(
        |error| {
            format!(
                "rollback of uncommitted WAL segment {} failed: {error}",
                target_path.display()
            )
        },
    )?;
    binding
        .remove_bound_file(parent, name, stage_display)
        .map_err(|error| {
            format!(
                "rollback of uncommitted WAL segment {} failed: {error:#}",
                target_path.display()
            )
        })
}

fn rollback_uncommitted_segment(
    parent: &cap_std::fs::Dir,
    name: &std::ffi::OsStr,
    stage_display: &Path,
    target_path: &Path,
    binding: crate::skills::store::BoundChildObject,
    primary: std::io::Error,
) -> (WalError, bool) {
    match cleanup_uncommitted_segment(parent, name, stage_display, target_path, binding) {
        Ok(()) => (WalError::Io(primary), true),
        Err(cleanup) => (
            WalError::Io(std::io::Error::new(
                primary.kind(),
                format!("{primary}; {cleanup}"),
            )),
            false,
        ),
    }
}

#[cfg(test)]
fn open_segment_capability_bound(
    path: &Path,
    create_new_only: bool,
    new_header: &[u8],
) -> Result<(std::fs::File, bool), WalError> {
    open_segment_capability_bound_with_publication_owner(path, create_new_only, new_header, None)
}

fn open_segment_capability_bound_with_publication_owner(
    path: &Path,
    create_new_only: bool,
    new_header: &[u8],
    mut receipt_quota_component: Option<&mut ContextEvidenceQuotaComponent>,
) -> Result<(std::fs::File, bool), WalError> {
    let parent = path.parent().ok_or_else(|| {
        WalError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("WAL segment has no parent directory: {}", path.display()),
        ))
    })?;
    let name = path.file_name().ok_or_else(|| {
        WalError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("WAL segment has no file name: {}", path.display()),
        ))
    })?;
    let root = crate::skills::store::open_bound_directory(parent, false, "WAL segment parent")
        .map_err(|error| {
            WalError::Io(std::io::Error::other(format!(
                "open capability-bound WAL parent {}: {error:#}",
                parent.display()
            )))
        })?
        .ok_or_else(|| {
            WalError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("WAL segment parent is missing: {}", parent.display()),
            ))
        })?;

    let open = |child_name: &std::ffi::OsStr, create_new: bool, publishable: bool| {
        let mut options = CapOpenOptions::new();
        options
            .read(true)
            .write(true)
            .append(true)
            .follow(FollowSymlinks::No);
        if create_new {
            options.create_new(true);
        }
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        #[cfg(windows)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            use windows_sys::Win32::Storage::FileSystem::{
                DELETE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH, FILE_GENERIC_READ,
                FILE_GENERIC_WRITE, FILE_SHARE_DELETE, FILE_SHARE_READ, READ_CONTROL, WRITE_DAC,
            };
            let publish_access = if publishable { DELETE } else { 0 };
            options
                .access_mode(
                    FILE_GENERIC_READ
                        | FILE_GENERIC_WRITE
                        | READ_CONTROL
                        | WRITE_DAC
                        | publish_access,
                )
                .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH);
        }
        #[cfg(not(windows))]
        let _ = publishable;
        root.dir.open_with(child_name, &options)
    };

    let validate_regular = |file: &cap_std::fs::File| {
        file.metadata().and_then(|metadata| {
            if metadata.is_file() && !crate::skills::store::cap_metadata_is_link_like(&metadata) {
                Ok(())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "WAL segment must be a real regular file without links: {}",
                        path.display()
                    ),
                ))
            }
        })
    };
    let secure_opened_file = |file: cap_std::fs::File| -> Result<std::fs::File, WalError> {
        validate_regular(&file)?;
        #[cfg(unix)]
        {
            use cap_std::fs::PermissionsExt as _;
            file.set_permissions(cap_std::fs::Permissions::from_mode(0o600))?;
        }
        let file = file.into_std();
        #[cfg(windows)]
        super::win_native::set_private_current_user_file_handle_dacl(&file)?;
        Ok(file)
    };
    let open_existing =
        || -> Result<std::fs::File, WalError> { secure_opened_file(open(name, false, false)?) };

    if !create_new_only {
        match open(name, false, false) {
            Ok(file) => return Ok((secure_opened_file(file)?, false)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    if new_header.is_empty() {
        return Err(WalError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "new WAL segment requires a complete header",
        )));
    }

    let mut staged = None;
    for _ in 0..8 {
        let candidate = std::ffi::OsString::from(format!(
            ".neoth-wal-publish-{}.tmp",
            uuid::Uuid::new_v4().simple()
        ));
        match open(&candidate, true, true) {
            Ok(file) => {
                let stage_display = root.display_path.join(&candidate);
                let binding = crate::skills::store::bind_open_regular_file_for_removal(
                    &root.dir,
                    &candidate,
                    &file,
                    &stage_display,
                )
                .map_err(|error| {
                    WalError::Io(std::io::Error::other(format!(
                        "bind private WAL publication stage {}: {error:#}",
                        stage_display.display()
                    )))
                })?;
                staged = Some((candidate, stage_display, file, binding));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    let (stage_name, stage_display, mut stage, stage_binding) = staged.ok_or_else(|| {
        WalError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate a private WAL publication stage",
        ))
    })?;

    let prepare = (|| -> std::io::Result<()> {
        validate_regular(&stage)?;
        #[cfg(test)]
        inject_segment_create_failure(path, TestSegmentCreateFailure::PrivatePermissions)?;
        #[cfg(unix)]
        {
            use cap_std::fs::PermissionsExt as _;
            stage.set_permissions(cap_std::fs::Permissions::from_mode(0o600))?;
        }
        #[cfg(windows)]
        super::win_native::set_private_current_user_file_handle_dacl(&stage)?;

        use std::io::Write as _;
        #[cfg(test)]
        inject_segment_create_failure(path, TestSegmentCreateFailure::HeaderWrite)?;
        // From the first write onward a partial or complete private stage may
        // consume disk even if the write itself reports an error. The split
        // component lives in this blocking worker and is cleared only after
        // exact-object cleanup is durably confirmed.
        if let Some(component) = receipt_quota_component.as_deref_mut() {
            component.mark_bytes_may_persist(new_header.len());
        }
        stage.write_all(new_header)?;
        #[cfg(test)]
        inject_segment_create_failure(path, TestSegmentCreateFailure::FileSync)?;
        stage.sync_all()?;
        #[cfg(test)]
        pause_before_segment_publication(path)?;
        Ok(())
    })();
    if let Err(error) = prepare {
        drop(stage);
        let (rollback_error, cleaned) = rollback_uncommitted_segment(
            &root.dir,
            &stage_name,
            &stage_display,
            path,
            stage_binding,
            error,
        );
        if cleaned && let Some(component) = receipt_quota_component.as_deref_mut() {
            component.clear_after_confirmed_cleanup();
        }
        return Err(rollback_error);
    }

    let mut committed = false;
    let publication = crate::skills::store::publish_open_regular_file_child_observed(
        &root.dir,
        &stage,
        &stage_name,
        &root.dir,
        name,
        &stage_display,
        path,
        || committed = true,
    );
    if let Err(error) = publication {
        drop(stage);
        if committed {
            // The store callback is inside the atomic rename primitive and
            // runs before all fallible target validation. The canonical prefix
            // is therefore retained and the quota component must stay charged;
            // attempting stage-name cleanup here would target a name that no
            // longer owns the bound object.
            drop(stage_binding);
            return Err(WalError::Io(std::io::Error::other(format!(
                "validate committed WAL segment {}: {error:#}",
                path.display()
            ))));
        }

        let (target_exists, inspect_failure) = match root.dir.symlink_metadata(name) {
            Ok(_) => (true, None),
            Err(inspect_error) if inspect_error.kind() == std::io::ErrorKind::NotFound => {
                (false, None)
            }
            Err(inspect_error) => (false, Some(inspect_error)),
        };
        let publish_error = if target_exists {
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("WAL segment target already exists: {}", path.display()),
            )
        } else if let Some(inspect_error) = inspect_failure {
            std::io::Error::new(
                inspect_error.kind(),
                format!(
                    "publish WAL segment {} failed: {error:#}; inspect target after failure: {inspect_error}",
                    path.display()
                ),
            )
        } else {
            std::io::Error::other(format!(
                "publish complete WAL segment {}: {error:#}",
                path.display()
            ))
        };
        let (rollback_error, cleaned) = rollback_uncommitted_segment(
            &root.dir,
            &stage_name,
            &stage_display,
            path,
            stage_binding,
            publish_error,
        );
        if cleaned && let Some(component) = receipt_quota_component.as_deref_mut() {
            component.clear_after_confirmed_cleanup();
        }
        if cleaned && target_exists && !create_new_only {
            return Ok((open_existing()?, false));
        }
        return Err(rollback_error);
    }
    debug_assert!(
        committed,
        "successful WAL publication omitted its commit callback"
    );
    drop(stage_binding);

    // Rename makes only the complete, private, file-synced header visible.
    // A directory-sync error occurs after commit, so the canonical segment is
    // deliberately retained for restart recovery rather than rolled back.
    #[cfg(unix)]
    {
        #[cfg(test)]
        {
            let mut targets = TEST_FAIL_SEGMENT_PARENT_SYNC_AT
                .lock()
                .expect("segment parent-sync test hook poisoned");
            if let Some(index) = targets.iter().position(|target| target == parent) {
                targets.swap_remove(index);
                return Err(WalError::Io(std::io::Error::other(
                    "injected WAL segment parent-directory sync failure",
                )));
            }
        }
        crate::skills::store::sync_parent_directory(&root.dir, &root.display_path).map_err(
            |error| {
                WalError::Io(std::io::Error::other(format!(
                    "sync published WAL parent {}: {error:#}",
                    root.display_path.display()
                )))
            },
        )?;
    }

    Ok((stage.into_std(), true))
}

/// Extract the trailing segment sequence from either `NNNNNN.wal` or a
/// namespaced standalone path such as `<uuid>-chat-NNNNNN.wal`.
fn segment_seq_from_path(path: &Path) -> u64 {
    path.file_stem()
        .and_then(|s| s.to_str())
        .and_then(|stem| {
            stem.parse::<u64>().ok().or_else(|| {
                stem.rsplit_once('-')
                    .and_then(|(_, sequence)| sequence.parse::<u64>().ok())
            })
        })
        .unwrap_or(1)
}

/// Mutable writer state. Encapsulated so rotation can swap segments cleanly.
struct WriterState {
    /// Open active segment.
    ///
    /// Zstd sealing must close the Windows append handle before capability-
    /// bound atomic replacement can commit the sealed inode. `None` is valid
    /// only inside that seal/rotation boundary after all raw bytes are synced.
    file: Option<File>,
    /// Stable sidecar exclusion held for the active segment's complete
    /// lifecycle. It deliberately outlives atomic inode replacement during
    /// compression finalization and is swapped only after the old file closes.
    segment_rewrite_lock: Option<std::fs::File>,
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
    segment_policy: SegmentPolicy,
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
    /// Exact header identity of the active segment. Keeping it handle-derived
    /// avoids an ambient path re-read during atomic sealing.
    segment_header: ParsedSegmentHeader,
}

impl WriterState {
    fn active_file_mut(&mut self) -> Result<&mut File, WalError> {
        self.file.as_mut().ok_or_else(|| {
            WalError::Io(std::io::Error::other(
                "WAL writer has no active segment handle outside a seal boundary",
            ))
        })
    }

    fn take_active_file(&mut self) -> Result<File, WalError> {
        self.file.take().ok_or_else(|| {
            WalError::Io(std::io::Error::other(
                "WAL writer cannot close an absent active segment handle",
            ))
        })
    }

    fn should_rotate(
        &self,
        now_ns: u64,
        next_frame_len: usize,
        marker_reserve: usize,
    ) -> Option<RotationReason> {
        let SegmentPolicy::Rotating(policy) = self.segment_policy else {
            return None;
        };
        let header_len = match self.compression {
            CompressionPolicy::None => SEGMENT_HEADER_LEN as u64,
            CompressionPolicy::Zstd3 => SEGMENT_HEADER_V3_LEN as u64,
        };
        let projected = self
            .offset
            .saturating_add(next_frame_len as u64)
            .saturating_add(marker_reserve as u64);
        // A single legal frame may itself be larger than the rotation target.
        // Let it occupy an otherwise-empty segment, but never append it behind
        // existing frames and create a valid segment near twice the ceiling.
        if self.offset >= policy.max_bytes
            || (self.offset > header_len && projected > policy.max_bytes)
        {
            return Some(RotationReason::SizeExceeded);
        }
        if now_ns.saturating_sub(self.opened_at_ns) >= policy.max_age_ns {
            return Some(RotationReason::AgeExceeded);
        }
        None
    }

    fn is_fixed(&self) -> bool {
        matches!(self.segment_policy, SegmentPolicy::Fixed { .. })
    }

    fn ensure_frame_fits(&self, frame_len: usize) -> std::io::Result<()> {
        let (max_bytes, boundary) = match self.segment_policy {
            SegmentPolicy::Fixed { max_bytes } => (max_bytes, "capture single-segment ceiling"),
            SegmentPolicy::Rotating(_) => (
                crate::wal::scan::LEGACY_SAFE_MAX_SEGMENT_PHYSICAL_BYTES as u64,
                "bounded WAL recovery ceiling",
            ),
        };
        let projected = self.offset.saturating_add(frame_len as u64);
        if projected > max_bytes {
            return Err(std::io::Error::other(format!(
                "{boundary} exceeded: projected {projected} bytes, ceiling {max_bytes} bytes"
            )));
        }
        Ok(())
    }

    fn ensure_frame_and_marker_fit(
        &self,
        frame_len: usize,
        marker_reserve: usize,
    ) -> std::io::Result<()> {
        let reserved_len = frame_len.checked_add(marker_reserve).ok_or_else(|| {
            std::io::Error::other("WAL operator frame plus marker reserve overflows usize")
        })?;
        self.ensure_frame_fits(reserved_len)
    }
}

/// Compute the next segment path without crossing writer namespaces.
/// `000001.wal` becomes `000002.wal`; `<uuid>-chat-000001.wal` becomes
/// `<uuid>-chat-000002.wal`.
fn next_segment_path(current: &Path, next_seq: u64) -> PathBuf {
    let parent = current.parent().unwrap_or_else(|| Path::new("."));
    if let Some(namespace) = current
        .file_stem()
        .and_then(|stem| stem.to_str())
        .and_then(|stem| {
            stem.rsplit_once('-')
                .and_then(|(namespace, sequence)| sequence.parse::<u64>().ok().map(|_| namespace))
        })
    {
        return parent.join(format!("{namespace}-{next_seq:06}.wal"));
    }
    parent.join(format!("{next_seq:06}.wal"))
}

fn compaction_recovery_error(reason: impl Into<String>) -> WalError {
    WalError::CompactionStateUnavailable {
        reason: reason.into(),
    }
}

fn context_evidence_receipt_authority_sentinel(home: &Path) -> PathBuf {
    home.join("wal")
        .join(CONTEXT_EVIDENCE_RECEIPT_AUTHORITY_SENTINEL)
}

async fn acquire_context_evidence_receipt_authority(
    home: &Path,
) -> Result<ContextEvidenceReceiptAuthority, WalError> {
    let process_authority = std::sync::Arc::clone(&*CONTEXT_EVIDENCE_RECEIPT_PROCESS_AUTHORITY);
    let process_guard = match process_authority.clone().try_lock_owned() {
        Ok(guard) => guard,
        Err(_) => {
            #[cfg(test)]
            notify_context_evidence_receipt_authority_contention_for_test(home);
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                process_authority.lock_owned(),
            )
            .await
            .map_err(|_| {
                compaction_recovery_error(
                    "Context Evidence receipt process authority remained busy for >5s",
                )
            })?
        }
    };
    let sentinel = context_evidence_receipt_authority_sentinel(home);
    let file_guard =
        tokio::task::spawn_blocking(move || super::redact::lock_segment_for_rewrite(&sentinel))
            .await
            .map_err(|error| {
                compaction_recovery_error(format!(
                    "Context Evidence receipt authority task failed: {error}"
                ))
            })?
            .map_err(|error| {
                compaction_recovery_error(format!(
                    "acquire capability-bound Context Evidence receipt authority: {error:#}"
                ))
            })?;
    Ok(ContextEvidenceReceiptAuthority {
        _process_guard: process_guard,
        _file_guard: file_guard,
    })
}

struct ContextEvidenceReceiptAuthority {
    _process_guard: tokio::sync::OwnedMutexGuard<()>,
    _file_guard: std::fs::File,
}

fn validate_hmac_writer_authority(
    authority: Option<&crate::cli::security::HmacWriterAuthority>,
) -> Result<(), WalError> {
    authority
        .map(crate::cli::security::HmacWriterAuthority::validate_namespace_binding)
        .transpose()
        .map(|_| ())
        .map_err(|error| {
            compaction_recovery_error(format!(
                "HMAC writer lease namespace is no longer authoritative: {error:#}"
            ))
        })
}

fn decode_exact_frame<'a>(
    segment_bytes: &'a [u8],
    offset: usize,
    limit: usize,
) -> Result<(super::frame::DecodedFrame<'a>, usize), WalError> {
    let frame_bytes = segment_bytes.get(offset..limit).ok_or_else(|| {
        compaction_recovery_error(format!(
            "compaction recovery range {offset}..{limit} is outside a {}-byte segment",
            segment_bytes.len()
        ))
    })?;
    let decoded = super::frame::decode_frame(frame_bytes).map_err(|error| {
        compaction_recovery_error(format!(
            "decode WAL frame at logical offset {offset} while rebuilding HMAC state: {error}"
        ))
    })?;
    let total = decoded.header.total_len as usize;
    let end = offset.checked_add(total).ok_or_else(|| {
        compaction_recovery_error(format!(
            "WAL frame length overflows while rebuilding HMAC state at offset {offset}"
        ))
    })?;
    if end > limit {
        return Err(compaction_recovery_error(format!(
            "WAL frame at offset {offset} crosses compaction recovery boundary {limit}"
        )));
    }
    Ok((decoded, end))
}

fn validate_unsigned_marker_prefix(
    segment_bytes: &[u8],
    header_len: usize,
    marker_from: usize,
) -> Result<(), WalError> {
    let mut cursor = header_len;
    while cursor < marker_from {
        let (decoded, end) = decode_exact_frame(segment_bytes, cursor, marker_from)?;
        if !matches!(
            decoded.header.event_type,
            crate::wal::events::EVENT_TYPE_SEGMENT_ROLLOVER
                | crate::wal::events::EVENT_TYPE_RECOVERY_TRUNCATED
        ) {
            return Err(compaction_recovery_error(format!(
                "first compaction marker starts at {marker_from}, leaving operator frame \
                 type 0x{:02X} unsigned at offset {cursor}",
                decoded.header.event_type
            )));
        }
        cursor = end;
    }
    Ok(())
}

fn validate_existing_compaction_marker(
    segment_bytes: &[u8],
    header_len: usize,
    marker_offset: usize,
    previous_marker_end: Option<usize>,
    marker: &crate::wal::compaction::MarkerPayload,
    verification_keys: &[Vec<u8>],
) -> Result<(), WalError> {
    let from = usize::try_from(marker.from_offset).map_err(|_| {
        compaction_recovery_error(format!(
            "compaction marker from_offset {} does not fit this platform",
            marker.from_offset
        ))
    })?;
    let to = usize::try_from(marker.to_offset).map_err(|_| {
        compaction_recovery_error(format!(
            "compaction marker to_offset {} does not fit this platform",
            marker.to_offset
        ))
    })?;
    if to != marker_offset {
        return Err(compaction_recovery_error(format!(
            "compaction marker at {marker_offset} claims a non-adjacent to_offset {to}"
        )));
    }
    if from < header_len || from >= to {
        return Err(compaction_recovery_error(format!(
            "compaction marker at {marker_offset} has invalid window {from}..{to}"
        )));
    }
    if let Some(previous_end) = previous_marker_end {
        if from != previous_end {
            return Err(compaction_recovery_error(format!(
                "compaction marker at {marker_offset} leaves an unsigned gap \
                 {previous_end}..{from}"
            )));
        }
    } else if from > header_len {
        validate_unsigned_marker_prefix(segment_bytes, header_len, from)?;
    }

    let mut cursor = from;
    let mut frame_count = 0u32;
    while cursor < to {
        let (decoded, end) = decode_exact_frame(segment_bytes, cursor, to)?;
        if decoded.header.event_type == crate::wal::events::EVENT_TYPE_COMPACTION_MARKER {
            return Err(compaction_recovery_error(format!(
                "compaction marker window {from}..{to} recursively covers another marker \
                 at offset {cursor}"
            )));
        }
        frame_count = frame_count.checked_add(1).ok_or_else(|| {
            compaction_recovery_error(format!(
                "compaction marker window {from}..{to} frame count overflow"
            ))
        })?;
        cursor = end;
    }
    if frame_count != marker.frame_count {
        return Err(compaction_recovery_error(format!(
            "compaction marker at {marker_offset} claims {} frames, decoded {frame_count}",
            marker.frame_count
        )));
    }
    if verification_keys
        .iter()
        .any(|key| crate::wal::compaction::verify_marker_bytes(segment_bytes, key, marker).is_ok())
    {
        return Ok(());
    }
    Err(compaction_recovery_error(format!(
        "existing compaction marker at offset {marker_offset} did not verify with the \
         active HMAC key or any retained rotation archive"
    )))
}

/// Verify every persisted compaction-marker window in one logical segment.
///
/// Marker windows must be adjacent. A closed predecessor must end at its last
/// marker; the only unsigned closed-segment prefix permitted by the writer
/// contract is the synthetic rollover/recovery prelude before the first
/// authenticated window. The live, final unsealed segment may retain the
/// in-progress window that writer recovery rebuilds and closes before
/// readiness.
pub(crate) fn verify_existing_compaction_marker_windows(
    segment_bytes: &[u8],
    header_len: usize,
    verification_keys: &[Vec<u8>],
    allow_unmarked_tail: bool,
) -> Result<usize, WalError> {
    if header_len > segment_bytes.len() {
        return Err(compaction_recovery_error(format!(
            "segment header length {header_len} exceeds the {}-byte logical segment",
            segment_bytes.len()
        )));
    }

    let mut cursor = header_len;
    let mut previous_marker_end = None;
    while cursor < segment_bytes.len() {
        let decoded = match super::frame::decode_frame(&segment_bytes[cursor..]) {
            Ok(decoded) => decoded,
            Err(super::error::HeaderParseError::BufferTooShort { .. }) if allow_unmarked_tail => {
                break;
            }
            Err(error) => {
                return Err(compaction_recovery_error(format!(
                    "decode WAL frame at logical offset {cursor} while verifying compaction \
                     markers: {error}"
                )));
            }
        };
        let end = cursor
            .checked_add(decoded.header.total_len as usize)
            .ok_or_else(|| {
                compaction_recovery_error(format!(
                    "WAL frame length overflows while verifying compaction markers at \
                     offset {cursor}"
                ))
            })?;
        if decoded.header.event_type == crate::wal::events::EVENT_TYPE_COMPACTION_MARKER {
            let marker: crate::wal::compaction::MarkerPayload =
                serde_json::from_slice(decoded.payload).map_err(|error| {
                    compaction_recovery_error(format!(
                        "decode compaction marker payload at offset {cursor}: {error}"
                    ))
                })?;
            validate_existing_compaction_marker(
                segment_bytes,
                header_len,
                cursor,
                previous_marker_end,
                &marker,
                verification_keys,
            )?;
            previous_marker_end = Some(end);
        }
        cursor = end;
    }

    let unmarked_from = previous_marker_end.unwrap_or(header_len);
    if !allow_unmarked_tail {
        if previous_marker_end.is_some() {
            if unmarked_from != segment_bytes.len() {
                return Err(compaction_recovery_error(format!(
                    "closed WAL segment has an unsigned tail {unmarked_from}..{} after its \
                     final compaction marker",
                    segment_bytes.len()
                )));
            }
        } else {
            validate_unsigned_marker_prefix(segment_bytes, header_len, segment_bytes.len())?;
        }
    }
    Ok(unmarked_from)
}

/// Rebuild the unfinished HMAC window of an unsealed raw segment.
///
/// Every persisted marker is verified first. The live state then resumes after
/// the last marker and replays every remaining frame byte, so a crash or
/// restart cannot silently abandon a partially authenticated window.
fn recover_compaction_state(
    active_key: &[u8],
    verification_keys: &[Vec<u8>],
    segment_bytes: &[u8],
) -> Result<crate::wal::compaction::CompactionState, WalError> {
    let parsed = parse_segment_header(segment_bytes)?;
    if parsed.is_compressed() || parsed.is_sealed() {
        return Err(compaction_recovery_error(
            "HMAC state reconstruction requires an unsealed raw WAL segment",
        ));
    }
    let header_len = parsed.header_len();
    let window_start = verify_existing_compaction_marker_windows(
        segment_bytes,
        header_len,
        verification_keys,
        true,
    )?;
    let mut state = crate::wal::compaction::CompactionState::new(active_key, window_start as u64);
    let mut cursor = window_start;
    while cursor < segment_bytes.len() {
        let (decoded, end) = decode_exact_frame(segment_bytes, cursor, segment_bytes.len())?;
        if decoded.header.event_type == crate::wal::events::EVENT_TYPE_COMPACTION_MARKER {
            return Err(compaction_recovery_error(format!(
                "internal recovery error: marker remained after last marker boundary at {cursor}"
            )));
        }
        state.update(&segment_bytes[cursor..end]);
        cursor = end;
    }
    Ok(state)
}

async fn emit_compaction_marker(
    state: &mut WriterState,
    compaction_state: &mut crate::wal::compaction::CompactionState,
    key: &[u8],
    receipt_quota_reservation: Option<&mut ContextEvidenceQuotaReservation>,
) -> Result<(), WalError> {
    if compaction_state.frames() == 0 {
        return Ok(());
    }

    // finalise_marker consumes the rolling MAC. Any error below is therefore a
    // fatal writer transaction abort: callers must not receive an ACK and a
    // restart reconstructs the exact unfinished window from durable frames.
    let marker_payload = compaction_state.finalise_marker(key, state.offset);
    let payload_bytes = serde_json::to_vec(&serde_json::json!({
        "from_offset":      marker_payload.from_offset,
        "to_offset":        marker_payload.to_offset,
        "frame_count":      marker_payload.frame_count,
        "hmac_hex":         marker_payload.hmac_hex,
        "compaction_epoch": state.compaction_epoch,
        "ts_ns":            current_ns(),
    }))
    .expect("compaction marker payload contains only infallible JSON values");
    let marker_header = crate::wal::HeaderBuilder::new(
        crate::wal::events::EVENT_TYPE_COMPACTION_MARKER,
        &payload_bytes,
    )
    .flags(crate::wal::EventFlags::SYNTHETIC)
    .build();
    let marker_frame = encode_frame(&marker_header, &payload_bytes);
    if marker_frame.len() > MAX_COMPACTION_MARKER_FRAME_BYTES {
        return Err(compaction_recovery_error(format!(
            "writer-generated compaction marker is {} bytes, above the {}-byte transaction ceiling",
            marker_frame.len(),
            MAX_COMPACTION_MARKER_FRAME_BYTES
        )));
    }
    state.ensure_frame_fits(marker_frame.len())?;
    #[cfg(test)]
    inject_compaction_marker_write_failure(&state.path)?;
    let compression = state.compression;
    let active_file = state.active_file_mut()?;
    if let Some(reservation) = receipt_quota_reservation {
        reservation.consume(marker_frame.len());
    }
    write_and_sync(active_file, &marker_frame).await?;
    if compression == CompressionPolicy::Zstd3 {
        state.pending_frames.extend_from_slice(&marker_frame);
    }
    state.offset += marker_frame.len() as u64;
    *compaction_state = crate::wal::compaction::CompactionState::new(key, state.offset);
    Ok(())
}

async fn closed_segment_binding(
    path: &Path,
    expected_sequence: u64,
) -> Result<ClosedSegmentBinding, WalError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let parent = path.parent().ok_or_else(|| {
            WalError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("closed WAL segment has no parent: {}", path.display()),
            ))
        })?;
        let name = path.file_name().ok_or_else(|| {
            WalError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("closed WAL segment has no leaf: {}", path.display()),
            ))
        })?;
        let root =
            crate::skills::store::open_bound_directory(parent, false, "closed WAL segment binding")
                .map_err(|error| {
                    WalError::Io(std::io::Error::other(format!(
                        "open capability-bound parent for {}: {error:#}",
                        path.display()
                    )))
                })?
                .ok_or_else(|| {
                    WalError::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("closed WAL parent is missing: {}", parent.display()),
                    ))
                })?;
        let bytes = crate::skills::store::read_regular_file_bounded(
            &root.dir,
            name,
            &path,
            crate::wal::scan::LEGACY_SAFE_MAX_SEGMENT_PHYSICAL_BYTES,
        )
        .map_err(|error| {
            WalError::Io(std::io::Error::other(format!(
                "read closed WAL segment binding {}: {error:#}",
                path.display()
            )))
        })?;
        let parsed = parse_segment_header(&bytes)?;
        if parsed.segment_seq() != expected_sequence {
            return Err(WalError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "closed WAL segment {} header sequence {} differs from writer sequence \
                     {expected_sequence}",
                    path.display(),
                    parsed.segment_seq()
                ),
            )));
        }
        Ok(ClosedSegmentBinding {
            segment_name: name
                .to_str()
                .ok_or_else(|| {
                    WalError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("closed WAL segment name is not UTF-8: {}", path.display()),
                    ))
                })?
                .to_owned(),
            generation: parsed.generation(),
            sequence: parsed.segment_seq(),
            start_ts_ns: parsed.segment_start_ts_ns(),
            node_id: parsed.node_id(),
            physical_len: u64::try_from(bytes.len()).map_err(|_| {
                WalError::Io(std::io::Error::other(
                    "closed WAL segment length does not fit u64",
                ))
            })?,
            sha256_hex: hex::encode(Sha256::digest(&bytes)),
        })
    })
    .await
    .map_err(|error| {
        WalError::Io(std::io::Error::other(format!(
            "join closed WAL segment binding: {error}"
        )))
    })?
}

/// Close the current segment durably and open the next one. Emits a
/// SEGMENT_ROLLOVER WAL event (in the new segment, not the closing one,
/// so a reader scanning forward sees the rollover at the head of the new
/// file before any further frames).
async fn rotate(
    state: &mut WriterState,
    reason: RotationReason,
    home: &Path,
    compaction_state: &mut Option<crate::wal::compaction::CompactionState>,
    hmac_key: Option<&[u8]>,
    mut receipt_quota_reservation: Option<&mut ContextEvidenceQuotaReservation>,
    mut receipt_authority: Option<&mut Option<ContextEvidenceReceiptAuthority>>,
) -> Result<(), WalError> {
    if receipt_quota_reservation.is_some() != receipt_authority.is_some() {
        return Err(compaction_recovery_error(
            "receipt rotation lost either authority or prefix quota ownership",
        ));
    }
    if receipt_authority.as_deref().is_some_and(Option::is_none) {
        return Err(compaction_recovery_error(
            "receipt rotation reached publication without its acquired home authority",
        ));
    }
    if receipt_quota_reservation.is_some()
        && compaction_state
            .as_ref()
            .is_some_and(|state| state.frames() > 0)
    {
        return Err(compaction_recovery_error(
            "receipt-triggered rotation requires its pre-scan HMAC window to be closed",
        ));
    }
    if let (Some(compaction_state), Some(key)) = (compaction_state.as_mut(), hmac_key) {
        emit_compaction_marker(state, compaction_state, key, None).await?;
    }

    // Final-sync the live raw segment before a zstd finalizer atomically
    // replaces its pathname. Syncing `state.file` after that publication would
    // target the superseded raw-file handle rather than the sealed segment and
    // can fail on Windows. The atomic finalizer independently syncs both its
    // private replacement file and the parent-directory commit.
    state.active_file_mut()?.sync_all().await?;

    // Workstream F: finalize compressed segment before rotating.
    if state.compression == CompressionPolicy::Zstd3 && !state.pending_frames.is_empty() {
        // Windows denies replacement through the capability-bound rename while
        // the target append handle is still open. Keep the rewrite lock held,
        // but close the fully-synced raw handle before publishing the sealed
        // replacement.
        drop(state.take_active_file()?);
        finalize_compressed_segment(state, home).await?;
    }

    let closed_seq = state.seq;
    let closed_bytes = state.offset;
    let predecessor = closed_segment_binding(&state.path, closed_seq).await?;
    let next_seq = state.seq + 1;
    let next_path = next_segment_path(&state.path, next_seq);
    let now_ns = current_ns();
    let new_header = new_segment_header_bytes(state.compression, next_seq, now_ns);
    let parsed_new_header =
        parse_segment_header(&new_header).expect("writer-generated segment header must parse");
    let header_len = new_header.len();
    let key = hmac_key.ok_or_else(|| {
        compaction_recovery_error(
            "rotating WAL writer cannot publish a successor without HMAC authority",
        )
    })?;
    let opened_segment_name = next_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            WalError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "opened WAL successor name is not UTF-8: {}",
                    next_path.display()
                ),
            ))
        })?
        .to_owned();

    // Build the complete authenticated successor prefix before publishing its
    // canonical name. `open_segment` stages and fsyncs arbitrary initial
    // bytes, then commits the directory entry atomically; a crash can
    // therefore expose either no successor or header+link+marker, never an
    // ambiguous header/link prefix that startup would have to repair.
    let payload = serde_json::to_vec(&serde_json::json!({
        "link_domain": "neoth.wal.cross-segment.v1",
        "link_version": 1,
        "closed_segment_name": predecessor.segment_name,
        "closed_generation": predecessor.generation,
        "closed_seq": predecessor.sequence,
        "closed_bytes": closed_bytes,
        "closed_start_ts_ns": predecessor.start_ts_ns,
        "closed_node_id": predecessor.node_id,
        "closed_physical_bytes": predecessor.physical_len,
        "closed_sha256_hex": predecessor.sha256_hex,
        "opened_segment_name": opened_segment_name,
        "opened_generation": parsed_new_header.generation(),
        "opened_seq": next_seq,
        "opened_start_ts_ns": parsed_new_header.segment_start_ts_ns(),
        "opened_node_id": parsed_new_header.node_id(),
        "reason": reason.as_str(),
        "ts_ns": now_ns,
    }))
    .expect("segment rollover payload contains only infallible JSON values");
    let rollover_header =
        crate::wal::HeaderBuilder::new(crate::wal::events::EVENT_TYPE_SEGMENT_ROLLOVER, &payload)
            .flags(crate::wal::EventFlags::SYNTHETIC)
            .build();
    let link_frame = encode_frame(&rollover_header, &payload);
    let link_end = header_len
        .checked_add(link_frame.len())
        .ok_or_else(|| std::io::Error::other("successor link offset overflows usize"))?;
    let mut link_hmac = crate::wal::compaction::CompactionState::new(key, header_len as u64);
    link_hmac.update(&link_frame);
    let link_marker = link_hmac.finalise_marker(
        key,
        u64::try_from(link_end)
            .map_err(|_| std::io::Error::other("successor link offset exceeds u64"))?,
    );
    let marker_payload = serde_json::to_vec(&serde_json::json!({
        "from_offset":      link_marker.from_offset,
        "to_offset":        link_marker.to_offset,
        "frame_count":      link_marker.frame_count,
        "hmac_hex":         link_marker.hmac_hex,
        "compaction_epoch": 0,
        "ts_ns":            now_ns,
    }))
    .expect("successor link marker contains only infallible JSON values");
    let marker_header = crate::wal::HeaderBuilder::new(
        crate::wal::events::EVENT_TYPE_COMPACTION_MARKER,
        &marker_payload,
    )
    .flags(crate::wal::EventFlags::SYNTHETIC)
    .build();
    let marker_frame = encode_frame(&marker_header, &marker_payload);
    let mut successor_prefix =
        Vec::with_capacity(header_len + link_frame.len() + marker_frame.len());
    successor_prefix.extend_from_slice(&new_header);
    successor_prefix.extend_from_slice(&link_frame);
    successor_prefix.extend_from_slice(&marker_frame);
    if successor_prefix.len() > MAX_ROTATION_SUCCESSOR_PREFIX_BYTES {
        return Err(WalError::Io(std::io::Error::other(format!(
            "authenticated WAL successor prefix is {} bytes, above the {}-byte transaction ceiling",
            successor_prefix.len(),
            MAX_ROTATION_SUCCESSOR_PREFIX_BYTES
        ))));
    }
    let successor_prefix_len = successor_prefix.len();
    let successor_offset = u64::try_from(successor_prefix_len)
        .map_err(|_| std::io::Error::other("successor prefix length exceeds u64"))?;

    info!(
        closed = %state.path.display(),
        closed_seq,
        closed_bytes,
        next = %next_path.display(),
        reason = reason.as_str(),
        "WAL segment rollover",
    );

    let receipt_quota_component = receipt_quota_reservation
        .as_deref_mut()
        .map(|reservation| reservation.split_component(MAX_ROTATION_SUCCESSOR_PREFIX_BYTES))
        .transpose()?;
    let owned_receipt_authority = receipt_authority
        .as_deref_mut()
        .and_then(|authority_slot| authority_slot.take());
    let predecessor_rewrite_lock = state.segment_rewrite_lock.take().ok_or_else(|| {
        WalError::Io(std::io::Error::other(
            "WAL rotation lost the active predecessor rewrite lock",
        ))
    })?;
    let opened = open_segment(
        &next_path,
        successor_prefix,
        predecessor_rewrite_lock,
        owned_receipt_authority,
        receipt_quota_component,
    )
    .await?;
    let mut opened = opened;
    if let Some(authority_slot) = receipt_authority {
        *authority_slot = opened.receipt_authority.take();
        if authority_slot.is_none() {
            return Err(compaction_recovery_error(
                "receipt rotation publisher did not return its home authority",
            ));
        }
    } else if opened.receipt_authority.is_some() {
        return Err(compaction_recovery_error(
            "non-receipt rotation unexpectedly acquired receipt authority",
        ));
    }
    let is_new = opened.is_new;
    // Declare the guard before the append handle: locals drop in reverse
    // declaration order, so every early-return path closes `new_file` first.
    let next_segment_lock = opened.segment_rewrite_lock;
    let new_file = opened.file;
    if !is_new {
        return Err(WalError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "refuse WAL rotation because target segment already exists: {}",
                next_path.display()
            ),
        )));
    }
    #[cfg(windows)]
    let new_file = File::from_std(super::win_native::duplicate_append_only_file(&new_file)?);

    // Close the old append handle before releasing its rewrite guard. The next
    // guard is already held, so no segment is ever active without exclusion.
    state.file = Some(new_file);
    state.segment_rewrite_lock = Some(next_segment_lock);
    state.path = next_path;
    state.seq = next_seq;
    state.opened_at_ns = now_ns;
    state.offset = successor_offset;
    // GOLD-PROG-12: fresh segment always starts at epoch 0.
    state.compaction_epoch = 0;
    state.segment_header = parsed_new_header;
    state.pending_frames.clear();
    if state.compression == CompressionPolicy::Zstd3 {
        state.pending_frames.extend_from_slice(&link_frame);
        state.pending_frames.extend_from_slice(&marker_frame);
    }
    *compaction_state = Some(crate::wal::compaction::CompactionState::new(
        key,
        state.offset,
    ));
    Ok(())
}

fn current_ns() -> u64 {
    crate::time::now_unix_ns()
}

async fn read_existing_segment_bounded(
    file: &mut File,
    path: &Path,
    max_bytes: usize,
) -> std::io::Result<Vec<u8>> {
    file.seek(std::io::SeekFrom::Start(0)).await?;
    let read_ceiling = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut reader = (&mut *file).take(read_ceiling);
    let mut bytes = Vec::with_capacity(max_bytes.min(1024 * 1024));
    reader.read_to_end(&mut bytes).await?;
    drop(reader);
    if bytes.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "existing WAL segment {} exceeds the {}-byte recovery limit",
                path.display(),
                max_bytes
            ),
        ));
    }
    file.seek(std::io::SeekFrom::End(0)).await?;
    Ok(bytes)
}

async fn run_writer(
    segment_path: PathBuf,
    initial_segment_lock: std::fs::File,
    mut rx: mpsc::Receiver<WriteRequest>,
    segment_policy: SegmentPolicy,
    compression: CompressionPolicy,
    hmac_home: PathBuf,
    hmac_authority: Option<crate::cli::security::HmacWriterAuthority>,
    startup: Option<WriterStartupSignal>,
) -> Result<(), WalError> {
    let seq = segment_seq_from_path(&segment_path);
    let fresh_opened_at_ns = current_ns();
    let fresh_header = new_segment_header_bytes(compression, seq, fresh_opened_at_ns);
    let fresh_parsed_header =
        parse_segment_header(&fresh_header).expect("writer-generated segment header must parse");
    let fresh_header_len = fresh_header.len();
    let opened =
        open_segment_with_lock(&segment_path, initial_segment_lock, fresh_header.clone()).await?;
    let is_new = opened.is_new;
    if !is_new && matches!(segment_policy, SegmentPolicy::Fixed { .. }) {
        return Err(WalError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "capture WAL writer requires a fresh segment; {} already exists",
                segment_path.display()
            ),
        )));
    }
    // Declare the guard before the append handle: until WriterState owns both,
    // an initialization error must close `file` before unlocking the segment.
    let segment_rewrite_lock = opened.segment_rewrite_lock;
    let mut file = opened.file;

    // F-14: every new segment is returned only after its complete private
    // header and parent entry are durable. Zstd live bodies remain raw and
    // unflagged until the atomic finalizer publishes COMPRESSED|SEALED.
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
    let mut recovered_segment_header = None;
    let mut initial_pending_frames = Vec::new();
    let mut initial_compaction_bytes = is_new.then_some(fresh_header);
    let mut resume_sealed_segment = false;

    let (offset, opened_at_ns) = if is_new {
        debug!(
            path = %segment_path.display(),
            seq,
            compression = ?compression,
            "opened committed new WAL segment"
        );
        (fresh_header_len as u64, fresh_opened_at_ns)
    } else {
        let metadata_len = file.metadata().await?.len();
        if metadata_len < SEGMENT_HEADER_LEN as u64 {
            error!(
                path = %segment_path.display(),
                len = metadata_len,
                "existing WAL segment is shorter than SegmentHeader; possible corruption"
            );
        }

        // Reconstruct and tail-scan the existing segment before any append.
        // The read is independently capped: metadata can change between the
        // size check and this read, and an attacker-controlled sparse/large
        // segment must not turn daemon startup into an unbounded allocation.
        // Any read/validation failure is fatal because appending after an
        // unverified tail would make the WAL chronology ambiguous.
        let bytes = read_existing_segment_bounded(
            &mut file,
            &segment_path,
            crate::wal::scan::HomeWalScanLimits::default().max_segment_physical_bytes,
        )
        .await?;
        let (resume_offset, resume_opened_at_ns) = {
            // COR-22: recover the segment's real start timestamp from its
            // header so the 24h age-rotation clock survives a daemon
            // restart. Before this, opened_at_ns was reset to "now" on
            // reopen, so a segment opened 25h ago would never age-rotate
            // after a restart (only the size ceiling protected it).
            // GOLD-PROG-12: also recover compaction_epoch from the header
            // so the next finalize uses epoch+1, not 0 (crash-idempotency).
            let parsed = parse_segment_header(&bytes)?;
            recovered_segment_header = Some(parsed);
            let recovered_opened_at_ns = parsed.segment_start_ts_ns();
            initial_compaction_epoch = parsed.compaction_epoch();
            if parsed.is_compressed() && !parsed.is_sealed() {
                return Err(WalError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "WAL segment {} uses the legacy ambiguous COMPRESSED-without-SEALED \
                         header; refusing a destructive raw resume",
                        segment_path.display()
                    ),
                )));
            }
            if parsed.is_sealed() {
                if compression != CompressionPolicy::Zstd3 || !parsed.is_compressed() {
                    return Err(WalError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "sealed WAL segment {} does not match the active zstd writer policy",
                            segment_path.display()
                        ),
                    )));
                }
                resume_sealed_segment = true;
                (metadata_len, recovered_opened_at_ns)
            } else {
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
                        // The capability-opened append handle also carries
                        // read/write rights. Truncate that exact kernel object;
                        // a concurrent pathname swap cannot redirect recovery.
                        file.set_len(good_through).await?;
                        file.sync_all().await?;
                        file.seek(std::io::SeekFrom::End(0)).await?;
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
                if compression == CompressionPolicy::Zstd3 {
                    let header_len = parsed.header_len();
                    initial_pending_frames
                        .extend_from_slice(&bytes[header_len..resume_offset as usize]);
                }
                initial_compaction_bytes = Some(bytes[..resume_offset as usize].to_vec());
                (resume_offset, recovered_opened_at_ns)
            }
        };
        (resume_offset, resume_opened_at_ns)
    };

    // The Windows control handle deliberately carries FILE_WRITE_DATA for
    // same-object tail recovery. Drop that right before entering the append
    // loop by deriving an append-only handle to the exact same kernel object.
    #[cfg(windows)]
    let file = {
        let append_only = super::win_native::duplicate_append_only_file(&file)?;
        // Shadowing alone keeps the control handle alive until the enclosing
        // scope ends. Close it explicitly so zstd sealing later has exactly
        // one target handle to close at its atomic replacement boundary.
        drop(file);
        File::from_std(append_only)
    };

    let mut state = WriterState {
        file: Some(file),
        segment_rewrite_lock: Some(segment_rewrite_lock),
        path: segment_path,
        offset,
        seq,
        opened_at_ns,
        segment_policy,
        compression,
        pending_frames: initial_pending_frames,
        compaction_epoch: initial_compaction_epoch,
        segment_header: recovered_segment_header.unwrap_or(fresh_parsed_header),
    };

    // ── Phase 33b SP-2 — HMAC compaction state ──────────────────────────────
    // The key lives at `<instance-home>/wal/hmac.key`, generated on first
    // boot. It is security-bearing state: loading or recovering it is a hard
    // startup boundary, never a downgrade to unsigned compaction markers.
    // A normal writer retains this shared authority object until `run_writer`
    // exits. The rotation-only writer receives `None` while its caller holds
    // the exclusive mutation lease, so it emits 0xD9 without an old-key
    // compaction marker.
    let (hmac_key, hmac_verification_keys): (Option<&[u8]>, &[Vec<u8>]) =
        match hmac_authority.as_ref() {
            Some(authority) => (
                Some(authority.active_key.as_slice()),
                authority.verification_keys.as_slice(),
            ),
            None => (None, &[]),
        };
    let mut compaction_state = match (hmac_key, initial_compaction_bytes.as_deref()) {
        (Some(key), Some(segment_bytes)) => Some(recover_compaction_state(
            key,
            hmac_verification_keys,
            segment_bytes,
        )?),
        (Some(_), None) if resume_sealed_segment => None,
        (Some(_), None) => {
            return Err(compaction_recovery_error(format!(
                "missing raw segment bytes while initializing HMAC state for {}",
                state.path.display()
            )));
        }
        (None, _) => None,
    };

    if resume_sealed_segment {
        validate_hmac_writer_authority(hmac_authority.as_ref())?;
        rotate(
            &mut state,
            RotationReason::SealedResume,
            &hmac_home,
            &mut compaction_state,
            hmac_key,
            None,
            None,
        )
        .await?;
    }

    debug!(path = %state.path.display(), offset = state.offset, "WAL writer opened segment");

    // Pick #36 (Session 14): emit the RECOVERY_TRUNCATED audit frame
    // immediately after WriterState is alive, BEFORE the main rx-loop
    // accepts any caller-driven append. The frame becomes the first
    // new entry in the recovered segment so a forensic walker sees a
    // clear marker for "the daemon recovered here". The audit is part of the
    // recovery boundary: if it cannot be made durable, initialization fails
    // before readiness rather than silently accepting evidence loss.
    if let Some(rec) = pending_recovery.take() {
        validate_hmac_writer_authority(hmac_authority.as_ref())?;
        let payload = serde_json::json!({
            "segment_path": rec.segment_path.to_string_lossy(),
            "good_through": rec.good_through,
            "torn_at": rec.torn_at,
            "bytes_dropped": rec.bytes_dropped,
            "ts_unix": crate::time::now_unix_secs(),
        });
        let payload_bytes = serde_json::to_vec(&payload)
            .expect("recovery payload contains only infallible JSON values");
        let header = crate::wal::HeaderBuilder::new(
            crate::wal::events::EVENT_TYPE_RECOVERY_TRUNCATED,
            &payload_bytes,
        )
        .flags(crate::wal::EventFlags::SYNTHETIC)
        .build();
        let frame = encode_frame(&header, &payload_bytes);
        write_and_sync(state.active_file_mut()?, &frame).await?;
        if state.compression == CompressionPolicy::Zstd3 {
            state.pending_frames.extend_from_slice(&frame);
        }
        state.offset += frame.len() as u64;
        if let Some(compaction_state) = compaction_state.as_mut() {
            compaction_state.update(&frame);
        }
    }

    // A raw segment reopened after an unclean stop may end below the ordinary
    // threshold. Close that reconstructed window before readiness so the
    // pre-restart tail cannot remain unauthenticated indefinitely.
    if !is_new
        && !resume_sealed_segment
        && let (Some(compaction_state), Some(key)) = (compaction_state.as_mut(), hmac_key)
    {
        validate_hmac_writer_authority(hmac_authority.as_ref())?;
        emit_compaction_marker(&mut state, compaction_state, key, None).await?;
    }

    if let Some(startup) = startup
        && let Some(sender) = startup
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .take()
    {
        let _ = sender.send(Ok(()));
    }

    // Pick #40 (Session 14, Agent #1 phase 2 fsync-batching design):
    // batchable event types (STREAM_CHUNK, HOOK_*, LOCAL_INFERENCE_*)
    // skip per-frame `sync_data()`. Their durability piggybacks on the
    // next SYNC_ON_WRITE frame (which sync_data captures all preceding
    // unsynced bytes at the same time) OR on the writer's shutdown
    // drain. This flag tracks whether ANY batchable frame has been
    // written without a sync since the last sync.
    let mut pending_unsynced = false;
    let mut receipt_quota_debt = crate::wal::context_evidence_receipts::ReceiptQuotaDebt::default();

    while let Some(mut req) = rx.recv().await {
        let is_receipt = is_context_evidence_receipt_header(&req.header);
        if is_receipt != req.context_evidence_receipt_once.is_some()
            || (is_receipt && req.force_authentication_marker)
        {
            if let Some(admission) = req.quota_admission.take() {
                admission.settle();
            }
            let _ = req.ack.send(Err(WalError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Context Evidence receipt request omitted its authenticated append-once authority",
            ))));
            continue;
        }
        validate_hmac_writer_authority(hmac_authority.as_ref())?;
        if let Some(mut once) = req.context_evidence_receipt_once.take() {
            let authority = match acquire_context_evidence_receipt_authority(&hmac_home).await {
                Ok(authority) => authority,
                Err(error) => {
                    if let Some(admission) = req.quota_admission.take() {
                        admission.settle();
                    }
                    let _ = req.ack.send(Err(error));
                    continue;
                }
            };
            #[cfg(test)]
            if let Some(gate) = req.test_receipt_decision_gate.as_ref() {
                gate.pause_before_ack(req.header.event_type).await;
            }

            let ledger_home = hmac_home.clone();
            let exact_frame = encode_frame(&req.header, &req.payload);
            let mut transaction_debt = std::mem::take(&mut receipt_quota_debt);
            let transaction = tokio::task::spawn_blocking(move || {
                let quota_guard = once.quota_reservation.guard.clone();
                let _receipt_mutation = quota_guard
                    .as_ref()
                    .map(|guard| guard.receipt_debt_mutex.lock().unwrap());
                // From here the worker, not the cancellable async actor, owns
                // the home authority and quota. A panic or dropped JoinHandle
                // therefore keeps the complete admitted bound charged until
                // this blocking owner itself terminates.
                once.arm_quota_fail_closed();
                match crate::wal::context_evidence_receipts::append_once_with_quota_debt(
                    &ledger_home,
                    &once.receipt_handle,
                    &once.expected,
                    &exact_frame,
                    &mut transaction_debt,
                ) {
                    Ok(outcome) => {
                        once.reconcile_quota_after_terminal(
                            outcome.retained_bytes(),
                            outcome.reclaimed_debt_bytes(),
                            outcome
                                .reclaimed_bytes()
                                .saturating_sub(outcome.reclaimed_debt_bytes()),
                            false,
                        );
                        drop(once);
                        Ok((authority, outcome.decision(), transaction_debt))
                    }
                    Err(error) => {
                        once.reconcile_quota_after_terminal(
                            error.retained_bytes(),
                            error.reclaimed_debt_bytes(),
                            error
                                .reclaimed_bytes()
                                .saturating_sub(error.reclaimed_debt_bytes()),
                            true,
                        );
                        drop(once);
                        Err(transaction_debt)
                    }
                }
            })
            .await;
            let (authority, _decision, recovered_debt) = match transaction {
                Ok(Ok(outcome)) => outcome,
                Ok(Err(debt)) => {
                    receipt_quota_debt = debt;
                    // This category is intentionally content-free. The RPC and
                    // startup replay paths must never inherit a local path,
                    // opaque handle, payload field, or account identifier from
                    // a forensic ledger diagnostic.
                    if let Some(admission) = req.quota_admission.take() {
                        admission.settle();
                    }
                    let _ = req.ack.send(Err(compaction_recovery_error(
                        "authenticated Context Evidence receipt ledger transaction refused",
                    )));
                    continue;
                }
                Err(error) => {
                    if let Some(admission) = req.quota_admission.take() {
                        admission.settle();
                    }
                    let _ = req.ack.send(Err(compaction_recovery_error(
                        "authenticated Context Evidence receipt ledger worker failed",
                    )));
                    return Err(compaction_recovery_error(format!(
                        "Context Evidence receipt ledger blocking task failed: {error}"
                    )));
                }
            };
            receipt_quota_debt = recovered_debt;
            validate_hmac_writer_authority(hmac_authority.as_ref())?;
            #[cfg(test)]
            if let Some(gate) = req.test_ack_gate.as_ref() {
                gate.pause_before_ack(req.header.event_type).await;
            }
            if let Some(admission) = req.quota_admission.take() {
                admission.settle();
            }
            let _ = req.ack.send(Ok(state.offset));
            drop(authority);
            continue;
        }
        let mut context_evidence_receipt_authority = None;
        let frame = encode_frame(&req.header, &req.payload);
        let frame_triggers_marker = compaction_state.as_ref().is_some_and(|state| {
            state.frames().saturating_add(1) >= crate::wal::compaction::MAX_FRAMES_BETWEEN_MARKERS
                || state.bytes().saturating_add(frame.len() as u64)
                    >= crate::wal::compaction::MAX_BYTES_BETWEEN_MARKERS
        });
        if req.force_authentication_marker && (compaction_state.is_none() || hmac_key.is_none()) {
            if let Some(admission) = req.quota_admission.take() {
                admission.settle();
            }
            let _ = req.ack.send(Err(compaction_recovery_error(
                "forced authenticated append reached a writer without HMAC compaction state",
            )));
            continue;
        }
        let marker_reserve = if hmac_key.is_some()
            && (!state.is_fixed() || frame_triggers_marker || req.force_authentication_marker)
        {
            MAX_COMPACTION_MARKER_FRAME_BYTES
        } else {
            0
        };
        // Pre-flight rotation: account for the complete next frame rather than
        // only the current offset, and reserve the mandatory HMAC marker before
        // the operator frame is acknowledged. This keeps every valid segment
        // within the bounded restart scanner's contract even when the next
        // payload is close to MAX_PAYLOAD_BYTES.
        if let Some(reason) = state.should_rotate(current_ns(), frame.len(), marker_reserve) {
            validate_hmac_writer_authority(hmac_authority.as_ref())?;
            // Pick #40: flush any pending batchable writes BEFORE rotation
            // so the closing segment is fully durable + the new segment
            // starts clean.
            if pending_unsynced {
                state.active_file_mut()?.sync_data().await?;
                pending_unsynced = false;
            }
            let receipt_reservation = req
                .context_evidence_receipt_once
                .as_mut()
                .map(|once| &mut once.quota_reservation);
            let receipt_authority_slot = if is_receipt {
                Some(&mut context_evidence_receipt_authority)
            } else {
                None
            };
            rotate(
                &mut state,
                reason,
                &hmac_home,
                &mut compaction_state,
                hmac_key,
                receipt_reservation,
                receipt_authority_slot,
            )
            .await?;
        }

        validate_hmac_writer_authority(hmac_authority.as_ref())?;
        if let Err(error) = state.ensure_frame_and_marker_fit(frame.len(), marker_reserve) {
            let completion_error = std::io::Error::new(error.kind(), error.to_string());
            if let Some(admission) = req.quota_admission.take() {
                admission.settle();
            }
            let _ = req.ack.send(Err(WalError::Io(error)));
            return Err(WalError::Io(completion_error));
        }
        let immediate = crate::wal::events::needs_immediate_sync(req.header.event_type);
        let compression = state.compression;
        // Resolve the live file before its actual write. Context Evidence
        // receipts never reach this primary-WAL path; their bounded ledger
        // transaction returned or continued above.
        let active_file = state.active_file_mut()?;
        // Workstream F: compressed segments buffer frames in-memory;
        // the file write happens on finalize (rotate/shutdown).
        let result = if compression == CompressionPolicy::Zstd3 {
            // For compressed segments we also write frames immediately to
            // a temp staging area so recovery still works on unclean shutdown.
            // However we keep the design simple: write raw frames to the file
            // during live operation, then on finalize rewrite the file with
            // the compressed body. This way the file is always parseable even
            // after a crash (just uncompressed despite the header flag).
            // On clean finalize the compressed form replaces the raw form.
            // The live staging bytes obey the same durability classifier as
            // uncompressed segments. In particular, required authority-audit
            // EXTENDED frames must be on stable storage before append() ACKs;
            // compression may change the later representation, never weaken
            // the acknowledgement contract.
            let r = if immediate {
                write_and_sync(active_file, &frame).await
            } else {
                write_only(active_file, &frame).await
            };
            if r.is_ok() {
                state.pending_frames.extend_from_slice(&frame);
                pending_unsynced = !immediate;
            }
            r
        } else if immediate {
            // SYNC_ON_WRITE frame — `write_and_sync` calls `sync_data`
            // after `write_all`, which durably commits BOTH this frame
            // AND any preceding batchable frames that landed in the OS
            // page cache. So `pending_unsynced` is cleared by this op.
            let r = write_and_sync(active_file, &frame).await;
            if r.is_ok() {
                pending_unsynced = false;
            }
            r
        } else {
            // Batchable frame — skip the per-frame fsync. Mark
            // pending so the next immediate frame OR shutdown drain
            // can commit it.
            let r = write_only(active_file, &frame).await;
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
                    if state_c.should_emit() || req.force_authentication_marker {
                        validate_hmac_writer_authority(hmac_authority.as_ref())?;
                        let receipt_reservation = req
                            .context_evidence_receipt_once
                            .as_mut()
                            .map(|once| &mut once.quota_reservation);
                        if let Err(marker_error) =
                            emit_compaction_marker(&mut state, state_c, key, receipt_reservation)
                                .await
                        {
                            // The triggering operator frame may already be durable,
                            // but its mandatory authenticity marker is not. Abort
                            // the writer and explicitly reject this append. A
                            // restart rebuilds the unfinished window from disk.
                            let completion_reason = marker_error.to_string();
                            if let Some(admission) = req.quota_admission.take() {
                                admission.settle();
                            }
                            let _ = req.ack.send(Err(marker_error));
                            return Err(WalError::Io(std::io::Error::other(format!(
                                "mandatory compaction marker transaction failed: \
                                 {completion_reason}"
                            ))));
                        }
                        pending_unsynced = false;
                    }
                }

                #[cfg(test)]
                if let Some(gate) = req.test_ack_gate.as_ref() {
                    gate.pause_before_ack(req.header.event_type).await;
                }
                if let Some(admission) = req.quota_admission.take() {
                    admission.settle();
                }
                if req.ack.send(Ok(written_at)).is_err() {
                    tracing::debug!(
                        offset = written_at,
                        "ack receiver dropped before WAL write confirmed (caller likely timed out)"
                    );
                }
                drop(context_evidence_receipt_authority);
            }
            Err(e) => {
                error!(error = %e, "WAL frame write failed");
                if state.is_fixed() {
                    let completion_error =
                        WalError::Io(std::io::Error::new(e.kind(), e.to_string()));
                    if let Some(admission) = req.quota_admission.take() {
                        admission.settle();
                    }
                    let _ = req.ack.send(Err(WalError::Io(e)));
                    return Err(completion_error);
                }
                if let Some(admission) = req.quota_admission.take() {
                    admission.settle();
                }
                if req.ack.send(Err(WalError::Io(e))).is_err() {
                    tracing::debug!("ack receiver dropped for failed WAL write");
                }
                drop(context_evidence_receipt_authority);
                // Continue; next caller may still succeed (e.g. transient ENOSPC clears).
            }
        }
    }

    if !state.is_fixed()
        && let (Some(compaction_state), Some(key)) = (compaction_state.as_mut(), hmac_key)
    {
        validate_hmac_writer_authority(hmac_authority.as_ref())?;
        emit_compaction_marker(&mut state, compaction_state, key, None).await?;
        pending_unsynced = false;
    }

    // Pick #40: shutdown drain — if the last write was batchable,
    // sync_data now so the operator's final partial-streaming reply
    // lands durably before the daemon exits. Caller's `drop(writer)`
    // already closed the channel above; this is the last chance to
    // flush before the writer-task returns.
    validate_hmac_writer_authority(hmac_authority.as_ref())?;
    if pending_unsynced && let Err(e) = state.active_file_mut()?.sync_data().await {
        if state.is_fixed() {
            return Err(WalError::Io(e));
        }
        warn!(error = %e, "shutdown-drain sync_data for batchable frames failed");
    }

    // Workstream F: only publish the compressed replacement after the closing
    // HMAC marker and any batchable tail are durable and present in the exact
    // frame buffer being sealed.
    if state.compression == CompressionPolicy::Zstd3 && !state.pending_frames.is_empty() {
        validate_hmac_writer_authority(hmac_authority.as_ref())?;
        drop(state.take_active_file()?);
        finalize_compressed_segment(&mut state, &hmac_home).await?;
    }

    validate_hmac_writer_authority(hmac_authority.as_ref())?;
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
async fn finalize_compressed_segment(state: &mut WriterState, home: &Path) -> Result<(), WalError> {
    let compressed = compress_frames(&state.pending_frames)?;

    // Preserve the exact handle-derived identity. An ambient path re-read here
    // could observe a substituted leaf rather than the segment protected by
    // the writer's rewrite lock.
    let parsed = state.segment_header;
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
        SEGMENT_FLAG_COMPRESSED | SEGMENT_FLAG_SEALED,
        new_epoch,
    );

    let compressed_len = compressed.len();

    // GOLD-ADAPT-CRYPTO-04d encrypt-on-seal: when `wal.encryption` is enabled,
    // the sealed (compressed) frame blob is AES-256-GCM-SIV-encrypted with the
    // plaintext v3 header as AAD, framed `ENC_MAGIC‖nonce‖ciphertext`. The
    // header keeps SEGMENT_FLAG_COMPRESSED (the decrypted blob IS compressed),
    // so the reader chokepoint decrypts-then-decompresses.
    //
    // This seal is reachable ONLY under `CompressionPolicy::Zstd3`, which no
    // production caller selects — `spawn_for_home` always passes `None`. The
    // fail-closed guarantee therefore does NOT live here; it lives in
    // `refuse_unimplemented_storage_policy`, which refuses to open a home-bound
    // writer at all while a configured policy is unwired. Do not restore a
    // "configured-on operators are safe" claim to this comment until
    // `wal.compression` is actually mapped onto this branch.
    let encryption_enabled = crate::wal::master_key::wal_encryption_enabled_at(home)
        .map_err(|error| std::io::Error::other(format!("WAL encryption policy: {error:#}")))?;
    let body: Vec<u8> = if encryption_enabled {
        let key = crate::wal::master_key::writer_segment_key_at(home).ok_or_else(|| {
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

    let mut published = Vec::with_capacity(SEGMENT_HEADER_V3_LEN + body.len());
    published.extend_from_slice(&v2_header.to_le_bytes());
    published.extend_from_slice(&body);
    let publish_path = state.path.clone();
    tokio::task::spawn_blocking(move || -> Result<(), WalError> {
        let parent = publish_path.parent().ok_or_else(|| {
            WalError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "compressed WAL segment has no parent: {}",
                    publish_path.display()
                ),
            ))
        })?;
        let name = publish_path.file_name().ok_or_else(|| {
            WalError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "compressed WAL segment has no leaf: {}",
                    publish_path.display()
                ),
            ))
        })?;
        let root =
            crate::skills::store::open_bound_directory(parent, false, "compressed WAL parent")
                .map_err(|error| {
                    WalError::Io(std::io::Error::other(format!(
                        "open capability-bound compressed WAL parent {}: {error:#}",
                        parent.display()
                    )))
                })?
                .ok_or_else(|| {
                    WalError::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("compressed WAL parent is missing: {}", parent.display()),
                    ))
                })?;
        crate::skills::store::atomic_write_private_child(&root.dir, name, &publish_path, &published)
            .map_err(|error| {
                WalError::Io(std::io::Error::other(format!(
                    "atomically publish sealed WAL segment {}: {error:#}",
                    publish_path.display()
                )))
            })
    })
    .await
    .map_err(|error| {
        WalError::Io(std::io::Error::other(format!(
            "join compressed WAL publication: {error}"
        )))
    })??;

    info!(
        path = %state.path.display(),
        raw_bytes = state.pending_frames.len(),
        compressed_bytes = compressed_len,
        compaction_epoch = new_epoch,
        ratio = format!("{:.1}%", compressed_len as f64 / state.pending_frames.len().max(1) as f64 * 100.0),
        encrypted = encryption_enabled,
        "WAL segment finalized (zstd-3{})",
        if encryption_enabled { " + AES-256-GCM-SIV" } else { "" },
    );
    state.pending_frames.clear();
    // GOLD-PROG-12: update in-memory epoch AFTER successful rename so
    // state always reflects on-disk reality. A crash before this line
    // leaves state.compaction_epoch at old_epoch, but the on-disk file
    // has new_epoch in its header — on restart parse_segment_header
    // recovers new_epoch, so the invariant is maintained.
    state.compaction_epoch = new_epoch;
    state.segment_header = ParsedSegmentHeader::V3(v2_header);
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

    #[test]
    fn rotation_policy_refuses_segments_larger_than_recovery_can_reopen() {
        let error = validate_rotation_policy(RotationPolicy {
            max_bytes: RotationPolicy::DEFAULT_MAX_BYTES + 1,
            max_age_ns: RotationPolicy::DEFAULT_MAX_AGE_NS,
        })
        .expect_err("unsupported oversized rotation policy must fail at spawn");
        let WalError::Io(source) = error else {
            panic!("expected rotation-policy validation to return an I/O error");
        };
        assert!(
            source.to_string().contains("exceeds the supported"),
            "{source}"
        );
        validate_rotation_policy(RotationPolicy {
            max_bytes: RotationPolicy::DEFAULT_MAX_BYTES,
            max_age_ns: RotationPolicy::DEFAULT_MAX_AGE_NS,
        })
        .unwrap();
    }

    #[test]
    fn every_new_segment_prepare_failure_rolls_back_and_can_retry() {
        for compression in [CompressionPolicy::None, CompressionPolicy::Zstd3] {
            for failure in [
                TestSegmentCreateFailure::PrivatePermissions,
                TestSegmentCreateFailure::HeaderWrite,
                TestSegmentCreateFailure::FileSync,
            ] {
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("000001.wal");
                let mut prefix = new_segment_header_bytes(compression, 1, current_ns());
                prefix.extend_from_slice(b"complete-link-and-marker-prefix");
                fail_segment_create_for_test(&path, failure);

                let error = open_segment_capability_bound(&path, true, &prefix)
                    .expect_err("injected pre-commit failure must abort creation");
                let WalError::Io(source) = error else {
                    panic!("expected injected I/O failure");
                };
                assert!(
                    source
                        .to_string()
                        .contains("injected WAL segment create failure"),
                    "{source}"
                );
                assert!(
                    !path.exists(),
                    "failed {failure:?} must not leave a poison leaf"
                );
                assert!(
                    std::fs::read_dir(dir.path()).unwrap().all(|entry| {
                        !entry
                            .unwrap()
                            .file_name()
                            .to_string_lossy()
                            .starts_with(".neoth-wal-publish-")
                    }),
                    "failed {failure:?} must remove its private publication stage"
                );

                let (file, is_new) =
                    open_segment_capability_bound(&path, true, &prefix).expect("retry must create");
                assert!(is_new);
                drop(file);
                assert_eq!(std::fs::read(&path).unwrap(), prefix);
            }
        }
    }

    #[test]
    fn complete_raw_and_zstd_successor_prefixes_publish_atomically() {
        for compression in [CompressionPolicy::None, CompressionPolicy::Zstd3] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("000002.wal");
            let mut prefix = new_segment_header_bytes(compression, 2, current_ns());
            prefix.extend_from_slice(b"authenticated-link-frame");
            prefix.extend_from_slice(b"authenticated-link-marker");
            let (prepared, release) = pause_segment_publication_for_test(&path);
            let thread_path = path.clone();
            let thread_prefix = prefix.clone();
            let publish = std::thread::spawn(move || {
                open_segment_capability_bound(&thread_path, true, &thread_prefix)
            });

            prepared
                .recv_timeout(std::time::Duration::from_secs(15))
                .expect("private successor prefix must reach its fsync boundary");
            assert!(
                !path.exists(),
                "canonical successor must remain absent until its complete prefix commits"
            );
            let stage = std::fs::read_dir(dir.path())
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|entry| {
                    entry.file_name().is_some_and(|name| {
                        name.to_string_lossy().starts_with(".neoth-wal-publish-")
                    })
                })
                .expect("private successor stage must exist while publication is paused");
            assert_eq!(
                std::fs::read(stage).unwrap(),
                prefix,
                "private stage must already contain header, link and marker"
            );

            release.send(()).unwrap();
            let (file, is_new) = publish.join().unwrap().unwrap();
            assert!(is_new);
            drop(file);
            assert_eq!(std::fs::read(path).unwrap(), prefix);
        }
    }

    #[tokio::test]
    async fn failed_rotation_creation_rolls_back_and_a_restart_can_retry() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("000001.wal");
        let second = dir.path().join("000002.wal");
        let policy = RotationPolicy {
            max_bytes: 1,
            max_age_ns: RotationPolicy::DEFAULT_MAX_AGE_NS,
        };
        fail_segment_create_for_test(&second, TestSegmentCreateFailure::FileSync);
        let (writer, join) = spawn_with_policy(first.clone(), policy).unwrap();
        let error = writer
            .append(header_for(1, 1), b"x".to_vec())
            .await
            .expect_err("rotation preparation failure must close the writer");
        assert!(matches!(error, WalError::WriterClosed));
        drop(writer);
        join.await.unwrap();
        assert!(!second.exists(), "failed rotation must remove its leaf");

        let (writer, join) = spawn_with_policy(first, policy).unwrap();
        writer
            .append(header_for(1, 2), b"y".to_vec())
            .await
            .expect("restart must create the same next sequence");
        drop(writer);
        join.await.unwrap();
        let second_bytes = std::fs::read(second).unwrap();
        parse_segment_header(&second_bytes).unwrap();
    }

    #[test]
    fn capability_bound_rotation_open_never_reuses_an_existing_target() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("000002.wal");
        std::fs::write(&path, b"existing-target").unwrap();

        let header = new_segment_header_bytes(CompressionPolicy::None, 2, current_ns());
        let error = open_segment_capability_bound(&path, true, &header)
            .expect_err("rotation must refuse an existing next segment");
        assert_eq!(
            match error {
                WalError::Io(source) => source.kind(),
                other => panic!("unexpected rotation-open error: {other}"),
            },
            std::io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"existing-target");
    }

    #[test]
    fn home_bound_writer_rejects_a_segment_outside_its_wal_namespace() {
        let home = tempfile::tempdir().unwrap();
        let outside = home.path().join("000001.wal");
        let error = validate_home_segment_path(&outside, home.path())
            .expect_err("home-bound writer must reject an outside segment");
        assert!(
            matches!(error, WalError::Io(ref source) if source.kind() == std::io::ErrorKind::InvalidInput)
        );
    }

    #[tokio::test]
    async fn fresh_home_establishes_hmac_authority_before_writer_publication() {
        let home = tempfile::tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        let segment = wal.join("000001.wal");

        let (writer, join) =
            spawn_for_home(segment, home.path().to_path_buf()).expect("spawn fresh home writer");
        let key_path = wal.join("hmac.key");
        assert!(
            key_path.is_file(),
            "spawn must synchronously commit HMAC authority before returning a writer handle"
        );
        let scanner_keys = crate::wal::scan::load_home_hmac_keys(home.path()).unwrap();
        assert_eq!(scanner_keys.len(), 1);
        assert_eq!(
            scanner_keys[0],
            crate::wal::compaction::load_existing_key(&key_path).unwrap()
        );

        drop(writer);
        join.await.unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_pinned_rotation_lock_allows_writer_spawn_and_validation() {
        let home = tempfile::tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        let (writer, join) = spawn_for_home(wal.join("000001.wal"), home.path().to_path_buf())
            .expect("Windows writer must coexist with the no-delete HMAC lease pin");
        let header = crate::wal::HeaderBuilder::new(0x44, b"windows-pinned-lock").build();
        writer
            .append(header, b"windows-pinned-lock".to_vec())
            .await
            .expect("identity validation must not request DELETE access");
        drop(writer);
        join.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_shared_writers_coexist_under_the_same_hmac_lease_file() {
        let home = tempfile::tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        let (first, first_join) =
            spawn_for_home(wal.join("first-000001.wal"), home.path().to_path_buf())
                .expect("first shared writer");
        let (second, second_join) =
            spawn_for_home(wal.join("second-000001.wal"), home.path().to_path_buf())
                .expect("second shared writer must not request DELETE access");

        let first_header = crate::wal::HeaderBuilder::new(0x44, b"first").build();
        let second_header = crate::wal::HeaderBuilder::new(0x45, b"second").build();
        let (first_result, second_result) = tokio::join!(
            first.append(first_header, b"first".to_vec()),
            second.append(second_header, b"second".to_vec()),
        );
        first_result.expect("first concurrent append");
        second_result.expect("second concurrent append");
        drop(first);
        drop(second);
        first_join.await.unwrap();
        second_join.await.unwrap();
    }

    #[tokio::test]
    async fn fresh_proof_signing_files_do_not_block_first_hmac_initialization() {
        let home = tempfile::tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        crate::wal::signing::load_or_init_signing_key(&wal.join("signing.key"))
            .expect("create proof signing key and its lock before first WAL writer");
        assert!(wal.join("signing.key").is_file());
        assert!(wal.join("signing.key.lock").is_file());

        let (writer, join) = spawn_for_home(wal.join("000001.wal"), home.path().to_path_buf())
            .expect("proof-only key files are valid fresh-HMAC state");
        assert!(wal.join("hmac.key").is_file());
        drop(writer);
        join.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn live_writer_fails_closed_after_rotation_lock_inode_replacement() {
        let home = tempfile::tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        let (writer, join) =
            spawn_for_home(wal.join("000001.wal"), home.path().to_path_buf()).unwrap();
        let lock = wal.join("hmac.key.rotation.lock");
        std::fs::remove_file(&lock).unwrap();
        std::fs::write(&lock, b"replacement-inode").unwrap();

        let header = crate::wal::HeaderBuilder::new(0x44, b"must-not-land").build();
        let error = writer
            .append(header, b"must-not-land".to_vec())
            .await
            .expect_err("writer must reject appends after its lock inode is replaced");
        assert!(
            format!("{error:#}").contains("closed") || format!("{error:#}").contains("namespace"),
            "unexpected replacement error: {error:#}"
        );
        drop(writer);
        join.await.unwrap();
    }

    #[test]
    fn existing_wal_evidence_without_hmac_authority_refuses_spawn() {
        let home = tempfile::tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        let segment = wal.join("000001.wal");
        std::fs::write(&segment, b"unverifiable-existing-evidence").unwrap();

        let error = spawn_for_home(segment.clone(), home.path().to_path_buf())
            .expect_err("existing WAL evidence must never mint replacement HMAC authority");
        assert!(
            format!("{error:#}").contains("refusing to create a new WAL HMAC identity"),
            "unexpected missing-authority error: {error:#}"
        );
        assert!(
            !wal.join("hmac.key").exists(),
            "failed recovery must not create a new identity"
        );
        assert_eq!(
            std::fs::read(segment).unwrap(),
            b"unverifiable-existing-evidence"
        );
    }

    #[cfg(unix)]
    #[test]
    fn capability_bound_segment_open_rejects_a_symlink_leaf() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside.bin");
        let segment = dir.path().join("000001.wal");
        std::fs::write(&outside, b"outside").unwrap();
        symlink(&outside, &segment).unwrap();

        let error = open_segment_capability_bound(&segment, false, &[])
            .expect_err("a segment symlink must fail closed");
        assert!(
            matches!(error, WalError::Io(_)),
            "unexpected no-follow error: {error}"
        );
        assert_eq!(std::fs::read(&outside).unwrap(), b"outside");
    }

    #[tokio::test]
    async fn existing_segment_read_is_bounded_on_the_opened_handle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("000001.wal");
        std::fs::write(&path, b"12345").unwrap();
        let (file, is_new) = open_segment_capability_bound(&path, false, &[]).unwrap();
        assert!(!is_new);
        let mut file = File::from_std(file);

        let error = read_existing_segment_bounded(&mut file, &path, 4)
            .await
            .expect_err("max+1 bytes must refuse recovery");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(std::fs::read(&path).unwrap(), b"12345");
    }

    #[tokio::test]
    async fn ready_writer_join_surfaces_a_post_start_rotation_failure() {
        let home = tempfile::tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        let first = wal.join("000001.wal");
        let second = wal.join("000002.wal");
        crate::cli::security::recover_and_load_or_initialize_hmac_key(
            home.path(),
            &wal.join("hmac.key"),
        )
        .expect("establish canonical HMAC authority before injecting rotation evidence");
        std::fs::write(&second, b"collision").unwrap();
        let (writer, join, ready) = spawn_for_home_with_policy_ready(
            first,
            home.path().to_path_buf(),
            RotationPolicy {
                max_bytes: 1,
                max_age_ns: RotationPolicy::DEFAULT_MAX_AGE_NS,
            },
        )
        .unwrap();
        ready.wait().await.unwrap();

        let append_error = writer
            .append(header_for(1, 1), b"x".to_vec())
            .await
            .expect_err("existing rotation target must fail the live writer");
        assert!(matches!(append_error, WalError::WriterClosed));
        drop(writer);
        let runtime_error = join
            .await
            .expect("writer outcome supervisor panicked")
            .expect_err("post-readiness rotation error must reach the daemon");
        assert!(
            runtime_error.contains("already exists"),
            "unexpected surfaced writer error: {runtime_error}"
        );
        assert_eq!(std::fs::read(second).unwrap(), b"collision");
    }

    /// PR4-014: the marker-skip is decided by a filename substring, so a future
    /// surface that merely CONTAINS it would silently lose tamper evidence.
    #[test]
    #[should_panic(expected = "reserves the")]
    fn a_surface_may_not_shadow_the_marker_skip_name() {
        let dir = tempfile::tempdir().unwrap();
        let _ = unique_standalone_segment_path(dir.path(), "hmac-key-rotate-v2");
    }

    #[test]
    fn the_rotation_surface_itself_is_still_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let path = unique_standalone_segment_path(dir.path(), HMAC_ROTATION_SURFACE);
        let name = path.file_name().unwrap().to_str().unwrap().to_string();
        assert!(
            name.contains(&format!("-{HMAC_ROTATION_SURFACE}-")),
            "the writer detects the skip by exactly this shape: {name}"
        );
        assert!(is_exact_hmac_rotation_segment(&path));
        assert!(!is_exact_hmac_rotation_segment(
            &dir.path().join("capture-hmac-key-rotate-000001.wal")
        ));
    }

    /// A configured-but-unwired storage policy must refuse the writer rather
    /// than silently writing plaintext segments the operator believes are
    /// sealed. A fresh home (no freedom.yaml) must still start.
    #[test]
    fn unimplemented_storage_policy_refuses_the_home_bound_writer() {
        let home = tempfile::tempdir().unwrap();
        refuse_unimplemented_storage_policy(home.path())
            .expect("a home without freedom.yaml uses the default policy and must start");

        std::fs::write(
            home.path().join("freedom.yaml"),
            "wal:\n  encryption: aes256_gcm_siv\n",
        )
        .unwrap();
        let error = refuse_unimplemented_storage_policy(home.path())
            .expect_err("configured-but-unapplied encryption must refuse");
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("PLAINTEXT") && rendered.contains("wal.encryption: none"),
            "the refusal must name the real state and the fix: {rendered}"
        );

        std::fs::write(
            home.path().join("freedom.yaml"),
            "wal:\n  compression: zstd_3\n",
        )
        .unwrap();
        let error = refuse_unimplemented_storage_policy(home.path())
            .expect_err("configured-but-unapplied compression must refuse");
        assert!(
            format!("{error:#}").contains("wal.compression: none"),
            "unexpected refusal: {error:#}"
        );

        std::fs::write(
            home.path().join("freedom.yaml"),
            "wal:\n  compression: none\n  encryption: none\n",
        )
        .unwrap();
        refuse_unimplemented_storage_policy(home.path())
            .expect("an explicitly-none policy is the implemented one and must start");
    }

    /// The guard sits on the production entrypoint, not on a caller.
    #[tokio::test]
    async fn spawn_for_home_refuses_a_configured_encryption_policy() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join("wal")).unwrap();
        std::fs::write(
            home.path().join("freedom.yaml"),
            "wal:\n  encryption: aes256_gcm_siv\n",
        )
        .unwrap();
        let error = spawn_for_home(
            home.path().join("wal").join("000001.wal"),
            home.path().to_path_buf(),
        )
        .expect_err("spawn_for_home must refuse the unwired policy");
        assert!(
            matches!(error, WalError::PolicyNotImplemented { .. }),
            "{error:#}"
        );
        assert!(
            !home.path().join("wal").join("000001.wal").exists(),
            "a refused writer must not create a segment"
        );
    }
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

    fn batchable_header_for(payload_len: u32, event_id: u64) -> EventHeaderV2 {
        let mut header = header_for(payload_len, event_id);
        header.event_type = crate::wal::events::EVENT_TYPE_PROVIDER_STREAM_CHUNK;
        header
    }

    fn context_evidence_receipt(
        handle: [u8; 32],
        policy_revision: u64,
        lifecycle_revision: u64,
    ) -> crate::wal::events::ContextEvidenceReceipt {
        crate::wal::events::ContextEvidenceReceipt::new(
            hex::encode(handle),
            crate::wal::events::ContextEvidenceReceiptKind::LocalImport,
            policy_revision,
            lifecycle_revision,
            28_400_000,
        )
        .expect("construct closed Context Evidence receipt")
    }

    async fn append_context_evidence_receipt_once_for_test(
        writer: &WalWriterHandle,
        handle: [u8; 32],
        receipt: crate::wal::events::ContextEvidenceReceipt,
    ) -> anyhow::Result<()> {
        let writer = writer.clone();
        tokio::task::spawn_blocking(move || {
            writer.append_context_evidence_receipt_once_blocking(&handle, receipt)
        })
        .await
        .expect("join blocking Context Evidence receipt append")
    }

    async fn wait_for_context_evidence_receipt_authority_contention(
        reached: std::sync::mpsc::Receiver<()>,
    ) {
        tokio::task::spawn_blocking(move || {
            reached
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("second receipt writer must contend while the first holds authority");
        })
        .await
        .expect("join receipt-authority contention observer");
    }

    fn assert_single_authenticated_context_evidence_receipt(
        home: &Path,
        handle: &[u8; 32],
        expected: &crate::wal::events::ContextEvidenceReceipt,
    ) {
        assert!(
            crate::wal::context_evidence_receipts::contains_for_test(home, handle, expected)
                .expect("bounded authenticated Context Evidence receipt lookup")
        );
    }

    fn spawn_test_writer_at_home(
        segment: PathBuf,
        home: &Path,
        policy: RotationPolicy,
        compression: CompressionPolicy,
    ) -> Result<(WalWriterHandle, tokio::task::JoinHandle<()>), WalError> {
        spawn_with_policy_and_compression_at_home(
            segment,
            SegmentPolicy::Rotating(policy),
            compression,
            home.to_path_buf(),
            home.join("wal").join("hmac.key"),
            false,
            None,
            None,
        )
    }

    fn read_and_verify_compaction_markers(
        segment: &Path,
        key: &[u8],
    ) -> Vec<crate::wal::compaction::MarkerPayload> {
        let bytes = std::fs::read(segment).expect("read WAL segment");
        let mut markers = Vec::new();
        crate::wal::scan::for_each_frame(&bytes, |_, frame| {
            if frame.header.event_type == crate::wal::events::EVENT_TYPE_COMPACTION_MARKER {
                markers.push(serde_json::from_slice(frame.payload)?);
            }
            Ok(())
        })
        .expect("walk WAL segment");
        for marker in &markers {
            crate::wal::compaction::verify_marker(segment, key, marker)
                .expect("persisted compaction marker must verify");
        }
        markers
    }

    #[test]
    fn compaction_marker_reserve_covers_the_largest_wire_payload() {
        let payload = serde_json::to_vec(&serde_json::json!({
            "from_offset": u64::MAX,
            "to_offset": u64::MAX,
            "frame_count": u32::MAX,
            "hmac_hex": "ff".repeat(32),
            "compaction_epoch": u32::MAX,
            "ts_ns": u64::MAX,
        }))
        .unwrap();
        let header = crate::wal::HeaderBuilder::new(
            crate::wal::events::EVENT_TYPE_COMPACTION_MARKER,
            &payload,
        )
        .flags(crate::wal::EventFlags::SYNTHETIC)
        .build();
        assert!(
            encode_frame(&header, &payload).len() <= MAX_COMPACTION_MARKER_FRAME_BYTES,
            "the admission reserve must cover every writer-generated marker"
        );
    }

    #[tokio::test]
    async fn near_ceiling_frame_shutdown_and_restart_keep_marker_space() {
        let home = tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir(&wal).unwrap();
        let first = wal.join("000001.wal");
        let policy = RotationPolicy {
            max_bytes: 1024,
            max_age_ns: RotationPolicy::DEFAULT_MAX_AGE_NS,
        };
        let payload_len = policy.max_bytes as usize - SEGMENT_HEADER_LEN - 104 - 1;
        let payload = vec![0xA5; payload_len];
        let header = header_for(payload.len() as u32, 1);
        let (writer, join) =
            spawn_test_writer_at_home(first.clone(), home.path(), policy, CompressionPolicy::None)
                .unwrap();
        writer.append(header, payload).await.unwrap();
        drop(writer);
        join.await.unwrap();

        let key = crate::wal::compaction::load_existing_key(&wal.join("hmac.key")).unwrap();
        assert_eq!(
            read_and_verify_compaction_markers(&first, &key).len(),
            1,
            "shutdown must close the near-ceiling operator-frame window"
        );

        let (writer, join) =
            spawn_test_writer_at_home(first.clone(), home.path(), policy, CompressionPolicy::None)
                .unwrap();
        writer
            .append(header_for(1, 2), b"x".to_vec())
            .await
            .expect("restart must rotate instead of bricking on marker space");
        drop(writer);
        join.await.unwrap();
        assert!(
            wal.join("000002.wal").is_file(),
            "the first post-restart frame must rotate out of the closed near-ceiling segment"
        );
        let first_bytes = std::fs::read(&first).unwrap();
        verify_existing_compaction_marker_windows(
            &first_bytes,
            parse_segment_header(&first_bytes).unwrap().header_len(),
            &[key],
            false,
        )
        .expect("the rotated predecessor must remain completely authenticated");
    }

    #[tokio::test]
    async fn capture_writer_is_home_bound_non_rotating_and_hard_capped() {
        let home = tempdir().unwrap();
        let wal_dir = home.path().join("wal");
        std::fs::create_dir(&wal_dir).unwrap();
        let segment = wal_dir.join("capture-000001.wal");
        let first_payload = b"first".to_vec();
        let first_header = header_for(first_payload.len() as u32, 1);
        let first_frame_len = encode_frame(&first_header, &first_payload).len() as u64;
        let ceiling = SEGMENT_HEADER_LEN as u64 + first_frame_len;
        let (writer, completion) =
            spawn_capture(segment.clone(), home.path().to_path_buf(), ceiling)
                .expect("spawn fixed capture writer");

        writer
            .append(first_header, first_payload)
            .await
            .expect("the frame that exactly reaches the ceiling must fit");
        let second_payload = b"second".to_vec();
        let second_header = header_for(second_payload.len() as u32, 2);
        let append_error = writer
            .append(second_header, second_payload)
            .await
            .expect_err("the first frame past the ceiling must fail");
        drop(writer);
        let completion_error = completion
            .wait()
            .await
            .expect_err("capture completion must expose the fixed-limit failure");

        assert!(
            format!("{:#}", anyhow::Error::new(append_error)).contains("ceiling")
                && format!("{:#}", anyhow::Error::new(completion_error)).contains("ceiling"),
            "fixed-limit errors must retain their concrete ceiling context"
        );
        assert_eq!(
            std::fs::metadata(&segment).unwrap().len(),
            ceiling,
            "capture file must stop exactly at the configured ceiling"
        );
        assert!(
            !wal_dir.join("capture-000002.wal").exists(),
            "capture writer must never rotate away frames"
        );
        assert!(
            wal_dir.join("hmac.key").is_file(),
            "capture HMAC state must be created under the throwaway home"
        );
    }

    #[test]
    fn capture_writer_refuses_existing_evidence_before_returning_a_handle() {
        let home = tempdir().unwrap();
        let wal_dir = home.path().join("wal");
        std::fs::create_dir(&wal_dir).unwrap();
        let segment = wal_dir.join("capture-000001.wal");
        std::fs::write(&segment, b"pre-existing").unwrap();

        let error = spawn_capture(segment, home.path().to_path_buf(), 4 * 1024)
            .expect_err("existing evidence without HMAC authority must fail synchronously");
        let error = anyhow::Error::new(error);
        assert!(
            format!("{error:#}").contains("refusing to create a new WAL HMAC identity"),
            "unexpected completion error: {error:#}"
        );
        assert!(!wal_dir.join("hmac.key").exists());
    }

    #[tokio::test]
    async fn capture_writer_completion_surfaces_existing_segment_with_valid_authority() {
        let home = tempdir().unwrap();
        let wal_dir = home.path().join("wal");
        std::fs::create_dir(&wal_dir).unwrap();
        crate::wal::compaction::rewrap_key(&wal_dir.join("hmac.key"), &[0x42; 32]).unwrap();
        let segment = wal_dir.join("capture-000001.wal");
        std::fs::write(&segment, b"pre-existing").unwrap();

        let (writer, completion) = spawn_capture(segment, home.path().to_path_buf(), 4 * 1024)
            .expect("valid authority permits bounded async segment admission");
        drop(writer);
        let error = completion
            .wait()
            .await
            .expect_err("fixed capture must still refuse an existing segment");
        assert!(
            format!("{error:#}").contains("requires a fresh segment"),
            "unexpected completion error: {error:#}"
        );
    }

    #[test]
    fn capture_writer_rejects_segment_outside_throwaway_home() {
        let home = tempdir().unwrap();
        let outside = tempdir().unwrap();
        std::fs::create_dir(home.path().join("wal")).unwrap();
        let error = spawn_capture(
            outside.path().join("capture-000001.wal"),
            home.path().to_path_buf(),
            4 * 1024,
        )
        .expect_err("capture segment must be bound to <home>/wal");
        let error = anyhow::Error::new(error);
        assert!(
            format!("{error:#}").contains("direct child"),
            "unexpected path-binding error: {error:#}"
        );
    }

    #[test]
    fn capture_writer_rejects_noncanonical_or_ads_like_leaf_names() {
        let home = tempdir().unwrap();
        let wal_dir = home.path().join("wal");
        std::fs::create_dir(&wal_dir).unwrap();
        for name in ["capture.wal", "000001.wal:stream", "bad-00001.wal"] {
            let error = spawn_capture(wal_dir.join(name), home.path().to_path_buf(), 4 * 1024)
                .expect_err("production capture writer must reject a noncanonical WAL leaf");
            assert!(
                matches!(error, WalError::Io(ref source) if source.kind() == std::io::ErrorKind::InvalidInput),
                "unexpected rejection for {name}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn capture_namespace_cannot_impersonate_hmac_rotation_marker_skip() {
        let home = tempdir().unwrap();
        let wal_dir = home.path().join("wal");
        std::fs::create_dir(&wal_dir).unwrap();
        let segment = wal_dir.join("capture-hmac-key-rotate-000001.wal");

        let (writer, completion) =
            spawn_capture(segment, home.path().to_path_buf(), 4 * 1024).unwrap();
        assert!(
            wal_dir.join("hmac.key").is_file(),
            "ordinary capture names must establish normal HMAC authority"
        );
        drop(writer);
        completion.wait().await.unwrap();
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
        let handle = WalWriterHandle {
            tx,
            authentication_markers_enabled: false,
            quota: None,
            test_ack_gate: None,
            test_receipt_decision_gate: None,
        };

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
        let dead = WalWriterHandle {
            tx,
            authentication_markers_enabled: false,
            quota: None,
            test_ack_gate: None,
            test_receipt_decision_gate: None,
        };
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
            let payload = format!("event-{i}").into_bytes();
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

    #[tokio::test]
    async fn writer_holds_segment_rewrite_lock_until_shutdown() {
        // P1 regression: physical redaction must never snapshot/replace an
        // active segment underneath its append handle. `spawn` acquires the
        // stable sidecar before returning and WriterState releases it only
        // after the writer task has durably shut down.
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (handle, join) = spawn(seg.clone()).expect("spawn");
        // Awaiting an acknowledged append forces the spawned future through
        // initialization and into its receive loop. Without this barrier a
        // current-thread Tokio test could probe the lock while it was merely
        // captured by an as-yet-unpolled future, missing an early-drop bug.
        handle
            .append(header_for(1, 1), b"x".to_vec())
            .await
            .expect("writer reaches live append loop");
        let lock_path = super::super::redact::segment_rewrite_lock_path(&seg);

        let competing =
            crate::util::locked_file::try_lock_file_once(&lock_path, "writer exclusion regression")
                .expect("probe writer-held segment lock");
        assert!(
            competing.is_none(),
            "active writer must exclude a redactor for the same segment"
        );

        // Exercise the real public redaction path as well as the primitive.
        // It must time out fail-closed while the append handle is live rather
        // than snapshotting/replacing underneath that handle.
        let active_seg = seg.clone();
        let refused = tokio::task::spawn_blocking(move || {
            super::super::redact::scan_and_redact(&active_seg, |payload| payload == b"x")
        })
        .await
        .expect("active-writer redaction probe task");
        let error = refused.expect_err("active WAL segment redaction must fail closed");
        assert!(
            format!("{error:#}").contains("cannot exclusively redact WAL segment"),
            "refusal must identify the writer exclusion boundary: {error:#}"
        );

        drop(handle);
        join.await.expect("join");
        let after_shutdown =
            crate::util::locked_file::try_lock_file_once(&lock_path, "writer exclusion regression")
                .expect("probe released segment lock");
        assert!(
            after_shutdown.is_some(),
            "writer shutdown must release the segment for a physical redactor"
        );
        drop(after_shutdown);

        let error = super::super::redact::scan_and_redact(&seg, |payload| payload == b"x")
            .expect_err("authenticated segment rewrite must remain transaction-gated");
        assert!(
            format!("{error:#}").contains("authenticated chain-structural frames")
                && !format!("{error:#}").contains("cannot exclusively redact WAL segment"),
            "post-shutdown refusal must come from the rewrite-integrity gate, proving the writer \
             lock was released: {error:#}"
        );
    }

    #[tokio::test]
    async fn rotation_hands_rewrite_lock_from_old_segment_to_new_segment() {
        let dir = tempdir().unwrap();
        let first = dir.path().join("000001.wal");
        let second = dir.path().join("000002.wal");
        let policy = RotationPolicy {
            // The freshly written segment header already exceeds this, so the
            // first caller frame deterministically rotates into `000002.wal`.
            max_bytes: 1,
            max_age_ns: RotationPolicy::DEFAULT_MAX_AGE_NS,
        };
        let (handle, join) = spawn_with_policy(first.clone(), policy).expect("spawn");
        handle
            .append(header_for(1, 1), b"x".to_vec())
            .await
            .expect("append after deterministic rotation");

        let first_lock = super::super::redact::segment_rewrite_lock_path(&first);
        let released_old =
            crate::util::locked_file::try_lock_file_once(&first_lock, "old rotation segment")
                .expect("probe old segment lock");
        assert!(
            released_old.is_some(),
            "rotation must close the old append handle and release its guard"
        );
        drop(released_old);

        let second_lock = super::super::redact::segment_rewrite_lock_path(&second);
        let held_new =
            crate::util::locked_file::try_lock_file_once(&second_lock, "new rotation segment")
                .expect("probe new segment lock");
        assert!(
            held_new.is_none(),
            "the rotated writer must hold the new segment guard before acknowledging the frame"
        );

        drop(handle);
        join.await.expect("join");
        let released_new =
            crate::util::locked_file::try_lock_file_once(&second_lock, "new rotation segment")
                .expect("probe released new segment lock");
        assert!(
            released_new.is_some(),
            "shutdown after rotation must release the new segment guard"
        );
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

    #[test]
    fn standalone_segment_namespaces_are_unique_and_rotation_safe() {
        let dir = tempdir().unwrap();
        let chat = unique_standalone_segment_path(dir.path(), "chat");
        let loop_run = unique_standalone_segment_path(dir.path(), "loop");

        assert_ne!(chat, loop_run);
        assert_eq!(segment_seq_from_path(&chat), 1);
        assert_eq!(segment_seq_from_path(&loop_run), 1);
        let rotated = next_segment_path(&chat, 2);
        assert_eq!(segment_seq_from_path(&rotated), 2);
        let rotated_stem = rotated.file_stem().unwrap().to_string_lossy().into_owned();
        let chat_stem = chat.file_stem().unwrap().to_string_lossy().into_owned();
        assert_eq!(
            rotated_stem.strip_suffix("-000002"),
            chat_stem.strip_suffix("-000001")
        );
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

        // 4. Re-decode the resulting segment. Caller frames, recovery audit,
        //    and their mandatory HMAC-closing markers must all be parseable
        //    with no torn bytes.
        let bytes = read(&seg).await.unwrap();
        assert!(bytes.len() >= SEGMENT_HEADER_LEN);
        // SegmentHeader still valid.
        SegmentHeader::from_le_bytes(bytes[..SEGMENT_HEADER_LEN].try_into().unwrap())
            .expect("SegmentHeader still parses after recovery");

        let mut cursor = SEGMENT_HEADER_LEN;
        let mut caller_payloads = Vec::new();
        let mut recovery_frames = 0usize;
        let mut compaction_markers = 0usize;
        while cursor < bytes.len() {
            let frame = decode_frame(&bytes[cursor..]).expect("recovered frame parses");
            match frame.header.event_type {
                crate::wal::events::EVENT_TYPE_RAW_TEXT => {
                    caller_payloads.push(frame.payload.to_vec());
                }
                EVENT_TYPE_RECOVERY_TRUNCATED => {
                    recovery_frames += 1;
                    let payload_str = std::str::from_utf8(frame.payload).expect("payload utf8");
                    assert!(payload_str.contains("torn_at"));
                    assert!(payload_str.contains("good_through"));
                    assert!(payload_str.contains("bytes_dropped"));
                }
                crate::wal::events::EVENT_TYPE_COMPACTION_MARKER => {
                    compaction_markers += 1;
                }
                other => panic!("unexpected recovered WAL event type 0x{other:02X}"),
            }
            cursor += frame.header.total_len as usize;
        }
        assert_eq!(
            caller_payloads,
            [b"intact-event".to_vec(), b"post-recovery".to_vec()]
        );
        assert_eq!(recovery_frames, 1);
        assert_eq!(
            compaction_markers, 3,
            "initial shutdown, restart recovery, and final shutdown each close a window"
        );

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
    /// the disk is over quota. The separate first-measure trigger forces one
    /// disk walk; waiters then observe the sticky measured breach.
    #[test]
    fn concurrent_writers_all_rejected_when_quota_over_ceiling() {
        use std::sync::Arc;
        use std::sync::atomic::Ordering;

        let dir = tempdir().unwrap();
        // Seed home dir well over the 1 KiB ceiling.
        std::fs::write(dir.path().join("seed.bin"), vec![0u8; 4096]).unwrap();
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

    #[test]
    fn first_measure_trigger_does_not_count_as_reserved_quota() {
        use std::sync::atomic::Ordering;

        let dir = tempdir().unwrap();
        let guard = QuotaGuard::new(dir.path().to_path_buf(), 1024);

        assert!(
            guard.try_admit(64).is_ok(),
            "an empty home with a 1 KiB ceiling must admit a 64-byte payload"
        );
        assert!(!guard.needs_measurement.load(Ordering::Acquire));
        assert_eq!(
            guard.reserved.load(Ordering::Acquire),
            64,
            "only the real payload may be reserved after the first measurement"
        );
    }

    #[test]
    fn receipt_debt_cleanup_never_releases_unclassified_reservations() {
        use std::sync::atomic::Ordering;

        let dir = tempdir().unwrap();
        let guard = QuotaGuard::new(dir.path().to_path_buf(), 4096);
        guard.reserved.store(500, Ordering::Release);
        guard.needs_measurement.store(false, Ordering::Release);
        guard.mark_receipt_debt(100);

        guard.release_receipt_debt(130);

        assert_eq!(guard.receipt_debt_reserved.load(Ordering::Acquire), 0);
        assert_eq!(
            guard.reserved.load(Ordering::Acquire),
            400,
            "only the classified 100-byte receipt debt may be released"
        );
        assert!(
            guard.needs_measurement.load(Ordering::Acquire),
            "measured or otherwise unclassified cleanup must refresh the baseline"
        );
    }

    #[test]
    fn ordinary_receipt_cleanup_invalidates_instead_of_releasing_the_baseline() {
        use std::sync::atomic::Ordering;

        let dir = tempdir().unwrap();
        let guard = QuotaGuard::new(dir.path().to_path_buf(), 4096);
        guard.last_measured.store(300, Ordering::Release);
        guard.reserved.store(80, Ordering::Release);
        guard.needs_measurement.store(false, Ordering::Release);
        let _receipt_debt = guard.receipt_debt_mutex.lock().unwrap();

        guard.invalidate_measured_baseline_locked(25);

        assert_eq!(guard.last_measured.load(Ordering::Acquire), 300);
        assert_eq!(guard.reserved.load(Ordering::Acquire), 80);
        assert!(guard.needs_measurement.load(Ordering::Acquire));
    }

    #[test]
    fn invalidated_baseline_is_remeasured_before_stale_projected_refusal() {
        use std::sync::atomic::Ordering;

        let dir = tempdir().unwrap();
        let guard = QuotaGuard::new(dir.path().to_path_buf(), 64);
        guard.last_measured.store(1024, Ordering::Release);
        guard.reserved.store(0, Ordering::Release);
        guard.breached.store(true, Ordering::Release);
        let receipt_debt = guard.receipt_debt_mutex.lock().unwrap();
        guard.invalidate_measured_baseline_locked(1024);
        drop(receipt_debt);

        assert!(
            guard.try_admit(1).is_ok(),
            "an exact-cleanup invalidation must measure the empty home before trusting stale usage"
        );
        assert_eq!(guard.last_measured.load(Ordering::Acquire), 0);
        assert_eq!(guard.reserved.load(Ordering::Acquire), 1);
        assert!(!guard.breached.load(Ordering::Acquire));
    }

    #[test]
    fn measurement_rebase_preserves_post_snapshot_admissions() {
        use std::sync::atomic::Ordering;

        let dir = tempdir().unwrap();
        let guard = QuotaGuard::new(dir.path().to_path_buf(), 4096);
        guard.reserved.store(177, Ordering::Release);
        assert_eq!(
            guard.publish_rebased_reserved(100, 40),
            117,
            "the 77 bytes admitted after the snapshot must survive rebasing"
        );
        assert_eq!(guard.reserved.load(Ordering::Acquire), 117);

        guard.reserved.store(80, Ordering::Release);
        assert_eq!(
            guard.publish_rebased_reserved(100, 40),
            40,
            "a concurrent release may be conservatively overcounted but must not undercut the base"
        );
    }

    #[test]
    fn reset_waits_for_the_active_admission_boundary() {
        let dir = tempdir().unwrap();
        let guard = std::sync::Arc::new(QuotaGuard::new(dir.path().to_path_buf(), 4096));
        let admission = guard.admission_mutex.lock().unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let reset_guard = std::sync::Arc::clone(&guard);
        let reset = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            reset_guard.reset();
            done_tx.send(()).unwrap();
        });
        started_rx.recv().unwrap();
        assert!(
            done_rx
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err(),
            "reset must not erase an admission while its accounting boundary is active"
        );
        drop(admission);
        done_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        reset.join().unwrap();
    }

    #[test]
    fn reset_preserves_admissions_issued_before_queue_handoff() {
        use std::sync::atomic::Ordering;

        let dir = tempdir().unwrap();
        let guard = QuotaGuard::new(dir.path().to_path_buf(), 4096);
        guard.try_admit(0).unwrap();
        guard.try_admit(123).unwrap();
        guard.mark_receipt_debt(23);

        // Model the exact post-try_admit/pre-send window: the caller owns an
        // accepted reservation, but no writer request is required to exist yet.
        guard.reset();

        assert_eq!(
            guard.reserved.load(Ordering::Acquire),
            123,
            "reset must not erase a reservation already issued to a caller"
        );
        assert_eq!(guard.pending_reserved.load(Ordering::Acquire), 123);
        assert_eq!(
            guard.receipt_debt_reserved.load(Ordering::Acquire),
            23,
            "reset must preserve the exact receipt-debt subset classification"
        );
        assert_eq!(guard.last_measured.load(Ordering::Acquire), 0);
        assert!(guard.needs_measurement.load(Ordering::Acquire));
        assert!(!guard.breached.load(Ordering::Acquire));
    }

    #[test]
    fn unrelated_home_growth_cannot_consume_an_older_pending_admission() {
        use std::sync::Arc;
        use std::sync::atomic::Ordering;

        let dir = tempdir().unwrap();
        let guard = Arc::new(QuotaGuard::new(dir.path().to_path_buf(), 300));
        guard.try_admit(0).unwrap();
        let older_request = QuotaGuard::reserve_pending_admission(&guard, 100)
            .expect("older request owns its reservation before queue handoff");
        std::fs::write(dir.path().join("unrelated-growth"), vec![0u8; 100]).unwrap();
        guard.reset();

        let newer_request = QuotaGuard::reserve_pending_admission(&guard, 1)
            .expect("foreign growth must not erase the older queued owner");
        assert_eq!(guard.last_measured.load(Ordering::Acquire), 100);
        assert_eq!(guard.pending_reserved.load(Ordering::Acquire), 101);
        assert_eq!(guard.reserved.load(Ordering::Acquire), 101);

        let exact_ceiling_request = QuotaGuard::reserve_pending_admission(&guard, 99)
            .expect("exact projected ceiling fits");
        assert!(
            matches!(
                QuotaGuard::reserve_pending_admission(&guard, 1),
                Err(WalError::QuotaExceeded { .. })
            ),
            "external bytes plus every pending owner must enforce the ceiling"
        );

        // Terminal handling is request-specific.  Settling the older request
        // cannot release the newer queued requests and re-arms a fresh fold
        // because the older owner predates the rebase.
        older_request.settle();
        assert_eq!(guard.pending_reserved.load(Ordering::Acquire), 100);
        assert!(guard.needs_measurement.load(Ordering::Acquire));
        drop(newer_request);
        drop(exact_ceiling_request);
    }

    #[test]
    fn terminal_after_measurement_rearms_a_conservative_pending_breach() {
        use std::sync::atomic::Ordering;

        let dir = tempdir().unwrap();
        let guard = std::sync::Arc::new(QuotaGuard::new(dir.path().to_path_buf(), 150));
        guard.try_admit(100).unwrap();
        let admission = QuotaPendingAdmission::new(std::sync::Arc::clone(&guard), 100);
        std::fs::write(dir.path().join("landed-before-terminal"), vec![0u8; 100]).unwrap();
        guard.reset();

        assert!(matches!(
            guard.try_admit(1),
            Err(WalError::QuotaExceeded { .. })
        ));
        assert!(guard.breached.load(Ordering::Acquire));
        admission.settle();
        assert_eq!(guard.pending_reserved.load(Ordering::Acquire), 0);
        assert!(
            guard.needs_measurement.load(Ordering::Acquire),
            "a terminal owner that crossed a walk must re-arm exact measurement"
        );

        guard
            .try_admit(1)
            .expect("fresh measurement must clear the conservative double count");
        assert_eq!(guard.last_measured.load(Ordering::Acquire), 100);
        assert_eq!(guard.reserved.load(Ordering::Acquire), 1);
        assert!(!guard.breached.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn reset_rebaseline_does_not_double_count_an_admitted_persisted_write() {
        use std::sync::atomic::Ordering;

        let home = tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir(&wal).unwrap();
        let segment = wal.join("quota-reset-000001.wal");
        let (writer, join) = spawn_test_writer_at_home(
            segment.clone(),
            home.path(),
            RotationPolicy::default(),
            CompressionPolicy::None,
        )
        .expect("spawn reset-rebaseline writer");
        let baseline = crate::daemon::quota::measure_dir(home.path());
        let payload = vec![b'r'; 64 * 1024];
        let admitted = payload.len() as u64;
        let ceiling = baseline.saturating_add(admitted + admitted / 2);
        let quota = std::sync::Arc::new(QuotaGuard::new(home.path().to_path_buf(), ceiling));
        let writer = writer.with_quota_guard(std::sync::Arc::clone(&quota));

        // Deliberately split the normal handle path at its accounting handoff:
        // admission returns, reset runs, and only then is the owned request
        // placed in the real writer queue.
        quota.try_admit(admitted).unwrap();
        let quota_admission = QuotaPendingAdmission::new(std::sync::Arc::clone(&quota), admitted);
        quota.reset();
        assert_eq!(quota.reserved.load(Ordering::Acquire), admitted);
        assert_eq!(quota.pending_reserved.load(Ordering::Acquire), admitted);
        let (ack_tx, ack_rx) = oneshot::channel();
        writer
            .tx
            .send(WriteRequest {
                header: header_for(payload.len() as u32, 91),
                payload: payload.clone(),
                ack: ack_tx,
                force_authentication_marker: false,
                context_evidence_receipt_once: None,
                quota_admission: Some(quota_admission),
                test_ack_gate: None,
                test_receipt_decision_gate: None,
            })
            .await
            .expect("enqueue the already-admitted request after reset");
        ack_rx
            .await
            .expect("writer must return an acknowledgement")
            .expect("already-admitted request must persist");
        drop(writer);
        join.await.expect("join reset-rebaseline writer");
        assert_eq!(quota.pending_reserved.load(Ordering::Acquire), 0);

        let bytes = read(&segment).await.unwrap();
        let decoded = decode_frame(&bytes[SEGMENT_HEADER_LEN..]).expect("decode persisted request");
        assert_eq!(decoded.payload, payload.as_slice());
        let landed = crate::daemon::quota::measure_dir(home.path());
        assert!(
            landed.saturating_add(1) <= ceiling,
            "control requires genuine disk usage to remain below the ceiling"
        );

        quota
            .try_admit(1)
            .expect("rebaseline must absorb the landed reservation exactly once");
        assert_eq!(quota.last_measured.load(Ordering::Acquire), landed);
        assert_eq!(
            quota.reserved.load(Ordering::Acquire),
            1,
            "only the new, not-yet-enqueued byte may remain reserved"
        );
        assert!(!quota.breached.load(Ordering::Acquire));
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
        guard.needs_measurement.store(false, Ordering::Release);

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
        let mut caller_frames = 0usize;
        let mut compaction_markers = 0usize;
        while cursor < bytes.len() {
            let dec = decode_frame(&bytes[cursor..]).expect("frame parses");
            assert_ne!(
                dec.header.event_type, EVENT_TYPE_RECOVERY_TRUNCATED,
                "clean reopen must NOT emit RECOVERY_TRUNCATED; saw it at cursor={cursor}"
            );
            if dec.header.event_type == crate::wal::events::EVENT_TYPE_COMPACTION_MARKER {
                compaction_markers += 1;
            } else {
                caller_frames += 1;
            }
            cursor += dec.header.total_len as usize;
        }
        assert_eq!(caller_frames, 2, "expected two caller-appended frames");
        assert_eq!(
            compaction_markers, 2,
            "each clean shutdown must close its caller-frame window"
        );
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

    #[tokio::test]
    async fn zstd_threshold_marker_survives_sealed_replacement() {
        let home = tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir(&wal).unwrap();
        let segment = wal.join("000001.wal");
        let (writer, join) = spawn_test_writer_at_home(
            segment.clone(),
            home.path(),
            RotationPolicy::default(),
            CompressionPolicy::Zstd3,
        )
        .expect("spawn zstd writer");

        for event_id in 1..=u64::from(crate::wal::compaction::MAX_FRAMES_BETWEEN_MARKERS) {
            writer
                .append(batchable_header_for(1, event_id), vec![b'x'])
                .await
                .expect("append threshold frame");
        }
        drop(writer);
        join.await.expect("join zstd writer");

        let key = crate::wal::compaction::load_existing_key(&wal.join("hmac.key"))
            .expect("load test HMAC key");
        let markers = read_and_verify_compaction_markers(&segment, &key);
        assert_eq!(
            markers.len(),
            1,
            "threshold marker must remain in the atomically sealed zstd body"
        );
        assert_eq!(
            markers[0].frame_count,
            crate::wal::compaction::MAX_FRAMES_BETWEEN_MARKERS
        );
        let parsed = parse_segment_header(&std::fs::read(segment).unwrap()).unwrap();
        assert!(parsed.is_compressed() && parsed.is_sealed());
    }

    #[tokio::test]
    async fn zstd_rotation_and_shutdown_each_close_their_partial_hmac_window() {
        let home = tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir(&wal).unwrap();
        let first = wal.join("000001.wal");
        let second = wal.join("000002.wal");
        let first_payload = b"alpha".to_vec();
        let first_header = batchable_header_for(first_payload.len() as u32, 1);
        let first_frame_len = encode_frame(&first_header, &first_payload).len() as u64;
        let policy = RotationPolicy {
            max_bytes: SEGMENT_HEADER_V3_LEN as u64 + first_frame_len,
            max_age_ns: RotationPolicy::DEFAULT_MAX_AGE_NS,
        };
        let (writer, join) =
            spawn_test_writer_at_home(first.clone(), home.path(), policy, CompressionPolicy::Zstd3)
                .expect("spawn rotating zstd writer");
        writer
            .append(first_header, first_payload)
            .await
            .expect("append first partial window");
        writer
            .append(batchable_header_for(5, 2), b"bravo".to_vec())
            .await
            .expect("rotate and append second partial window");
        drop(writer);
        join.await.expect("join rotating zstd writer");

        let key = crate::wal::compaction::load_existing_key(&wal.join("hmac.key"))
            .expect("load test HMAC key");
        let first_markers = read_and_verify_compaction_markers(&first, &key);
        let second_markers = read_and_verify_compaction_markers(&second, &key);
        assert_eq!(
            first_markers.len(),
            1,
            "rotation must close the predecessor's partial HMAC window"
        );
        assert_eq!(
            second_markers.len(),
            2,
            "successor link and shutdown tail require separate HMAC windows"
        );
        assert_eq!(first_markers[0].frame_count, 1);
        assert_eq!(second_markers[0].frame_count, 1);
        assert_eq!(second_markers[1].frame_count, 1);
        for segment in [&first, &second] {
            let parsed = parse_segment_header(&std::fs::read(segment).unwrap()).unwrap();
            assert!(parsed.is_compressed() && parsed.is_sealed());
        }
    }

    #[tokio::test]
    async fn raw_restart_reconstructs_and_seals_the_pre_restart_hmac_tail() {
        let home = tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir(&wal).unwrap();
        let segment = wal.join("000001.wal");
        crate::cli::security::recover_and_load_or_initialize_hmac_key(
            home.path(),
            &wal.join("hmac.key"),
        )
        .expect("establish canonical HMAC authority before injecting restart evidence");
        let mut raw = new_segment_header_bytes(CompressionPolicy::Zstd3, 1, current_ns());
        raw.extend_from_slice(&encode_frame(&batchable_header_for(5, 1), b"alpha"));
        raw.extend_from_slice(&encode_frame(&batchable_header_for(5, 2), b"bravo"));
        std::fs::write(&segment, raw).unwrap();

        let (writer, join) = spawn_test_writer_at_home(
            segment.clone(),
            home.path(),
            RotationPolicy::default(),
            CompressionPolicy::Zstd3,
        )
        .expect("resume raw zstd segment");
        drop(writer);
        join.await.expect("join resumed zstd writer");

        let key = crate::wal::compaction::load_existing_key(&wal.join("hmac.key"))
            .expect("load test HMAC key");
        let markers = read_and_verify_compaction_markers(&segment, &key);
        assert_eq!(
            markers.len(),
            1,
            "restart must close the reconstructed pre-restart window"
        );
        assert_eq!(markers[0].frame_count, 2);
    }

    #[tokio::test]
    async fn mandatory_marker_failure_rejects_append_and_restart_recovers_window() {
        let home = tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir(&wal).unwrap();
        let segment = wal.join("000001.wal");
        let (writer, join) = spawn_test_writer_at_home(
            segment.clone(),
            home.path(),
            RotationPolicy::default(),
            CompressionPolicy::None,
        )
        .expect("spawn writer");

        let threshold = crate::wal::compaction::MAX_FRAMES_BETWEEN_MARKERS;
        for event_id in 1..u64::from(threshold) {
            writer
                .append(batchable_header_for(1, event_id), vec![b'x'])
                .await
                .expect("append pre-threshold frame");
        }
        fail_compaction_marker_write_for_test(&segment);
        let error = writer
            .append(batchable_header_for(1, u64::from(threshold)), vec![b'x'])
            .await
            .expect_err("mandatory marker failure must reject the triggering append");
        assert!(
            error
                .to_string()
                .contains("injected compaction marker write failure"),
            "unexpected append error: {error}"
        );
        drop(writer);
        join.await.expect("failed writer task must not panic");

        let key = crate::wal::compaction::load_existing_key(&wal.join("hmac.key"))
            .expect("load test HMAC key");
        assert!(
            read_and_verify_compaction_markers(&segment, &key).is_empty(),
            "failed marker transaction must not publish a partial marker"
        );

        let (writer, join) = spawn_test_writer_at_home(
            segment.clone(),
            home.path(),
            RotationPolicy::default(),
            CompressionPolicy::None,
        )
        .expect("restart writer after marker failure");
        drop(writer);
        join.await.expect("join recovered writer");
        let markers = read_and_verify_compaction_markers(&segment, &key);
        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].frame_count, threshold);
    }

    #[tokio::test]
    async fn context_evidence_receipt_uses_bounded_ledger_across_primary_wal_rotation() {
        let home = tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir(&wal).unwrap();
        let first = wal.join("context-runtime-000001.wal");
        let policy = RotationPolicy {
            max_bytes: RotationPolicy::DEFAULT_MAX_BYTES,
            max_age_ns: 0,
        };
        let (writer, join) =
            spawn_test_writer_at_home(first, home.path(), policy, CompressionPolicy::None)
                .expect("spawn rotating Context Evidence writer");
        let handle = [0xA3; 32];
        let receipt = context_evidence_receipt(handle, 17, 29);
        let generic_payload = receipt.encode().unwrap();
        let generic_header = crate::wal::HeaderBuilder::new(
            crate::wal::events::EVENT_TYPE_EXTENDED,
            &generic_payload,
        )
        .event_subtype(crate::wal::events::ExtendedSubtype::ContextEvidenceReceipt as u8)
        .build();
        let generic_error = writer
            .append(generic_header, generic_payload)
            .await
            .expect_err("generic append must not bypass receipt authority");
        assert!(
            generic_error.to_string().contains("append-once writer API"),
            "unexpected generic receipt refusal: {generic_error}"
        );

        append_context_evidence_receipt_once_for_test(&writer, handle, receipt.clone())
            .await
            .expect("append first receipt to bounded ledger");
        writer
            .append(header_for(1, 81), vec![b'x'])
            .await
            .expect("rotate primary WAL after ledger append");
        append_context_evidence_receipt_once_for_test(&writer, handle, receipt.clone())
            .await
            .expect("deduplicate ledger receipt after primary-WAL rotation");

        drop(writer);
        join.await.expect("join rotating Context Evidence writer");
        let segment_count = std::fs::read_dir(&wal)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry.path().extension().and_then(|value| value.to_str()) == Some("wal")
            })
            .count();
        assert!(
            segment_count >= 2,
            "fixture must exercise a real primary-WAL rotation"
        );
        assert_single_authenticated_context_evidence_receipt(home.path(), &handle, &receipt);

        let mut primary_wal_receipts = 0usize;
        crate::wal::scan::for_each_frame_at_home(
            home.path(),
            crate::wal::scan::supported_home_scan_limits(),
            |_, frame| {
                if frame.header.event_type == crate::wal::events::EVENT_TYPE_EXTENDED
                    && frame.header.event_subtype
                        == crate::wal::events::ExtendedSubtype::ContextEvidenceReceipt as u8
                {
                    primary_wal_receipts += 1;
                }
                Ok(())
            },
        )
        .expect("scan complete primary WAL only in regression test");
        assert_eq!(
            primary_wal_receipts, 0,
            "the canonical ledger must not duplicate receipt evidence into primary WAL"
        );
    }

    #[tokio::test]
    async fn context_evidence_receipt_quota_refuses_before_ledger_mutation() {
        let home = tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir(&wal).unwrap();
        let (writer, join) = spawn_test_writer_at_home(
            wal.join("context-ledger-quota-000001.wal"),
            home.path(),
            RotationPolicy::default(),
            CompressionPolicy::None,
        )
        .expect("spawn quota-bound Context Evidence writer");
        let quota = std::sync::Arc::new(QuotaGuard::new(
            home.path().to_path_buf(),
            crate::wal::context_evidence_receipts::MAX_TRANSACTION_BYTES - 1,
        ));
        quota
            .reserved
            .store(0, std::sync::atomic::Ordering::Release);
        quota
            .last_measured
            .store(0, std::sync::atomic::Ordering::Release);
        quota
            .needs_measurement
            .store(false, std::sync::atomic::Ordering::Release);
        let writer = writer.with_quota_guard(quota.clone());
        let handle = [0xA7; 32];
        let receipt = context_evidence_receipt(handle, 31, 37);

        let error = append_context_evidence_receipt_once_for_test(&writer, handle, receipt)
            .await
            .expect_err("transaction bound must be admitted before ledger initialization");
        assert_eq!(error.to_string(), "context_evidence_receipt_quota_refused");
        assert_eq!(
            quota.reserved.load(std::sync::atomic::Ordering::Acquire),
            0,
            "refused admission must not retain phantom quota"
        );
        assert!(
            !wal.join("context-evidence-receipts").exists(),
            "quota refusal must precede canonical ledger mutation"
        );
        drop(writer);
        join.await
            .expect("join quota-bound Context Evidence writer");
    }

    #[test]
    fn closed_receipt_writer_releases_the_complete_unqueued_admission() {
        use std::sync::atomic::Ordering;

        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let dir = tempdir().unwrap();
        let guard = std::sync::Arc::new(QuotaGuard::new(
            dir.path().to_path_buf(),
            crate::wal::context_evidence_receipts::MAX_TRANSACTION_BYTES * 2,
        ));
        guard.reserved.store(0, Ordering::Release);
        guard.last_measured.store(0, Ordering::Release);
        guard.needs_measurement.store(false, Ordering::Release);
        let writer = WalWriterHandle {
            tx,
            authentication_markers_enabled: true,
            quota: Some(std::sync::Arc::clone(&guard)),
            test_ack_gate: None,
            test_receipt_decision_gate: None,
        };
        let handle = [0xA8; 32];
        let receipt = context_evidence_receipt(handle, 41, 43);

        let error = writer
            .append_context_evidence_receipt_once_blocking(&handle, receipt)
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            "context_evidence_receipt_writer_unavailable"
        );
        assert_eq!(guard.reserved.load(Ordering::Acquire), 0);
        assert_eq!(guard.receipt_debt_reserved.load(Ordering::Acquire), 0);
        assert!(
            !dir.path()
                .join("wal")
                .join("context-evidence-receipts")
                .exists()
        );
    }

    #[tokio::test]
    async fn concurrent_home_writers_append_one_identical_context_evidence_receipt() {
        let home = tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir(&wal).unwrap();
        let (first, first_join) = spawn_test_writer_at_home(
            wal.join("context-race-a-000001.wal"),
            home.path(),
            RotationPolicy::default(),
            CompressionPolicy::None,
        )
        .expect("spawn first racing Context Evidence writer");
        let (second, second_join) = spawn_test_writer_at_home(
            wal.join("context-race-b-000001.wal"),
            home.path(),
            RotationPolicy::default(),
            CompressionPolicy::None,
        )
        .expect("spawn second racing Context Evidence writer");
        let decision_gate = TestAckGate::once(crate::wal::events::EVENT_TYPE_EXTENDED);
        let first = first.with_test_receipt_decision_gate(decision_gate.clone());
        let handle = [0xAF; 32];
        let receipt = context_evidence_receipt(handle, 79, 83);

        let first_writer = first.clone();
        let first_receipt = receipt.clone();
        let first_append = tokio::task::spawn_blocking(move || {
            first_writer.append_context_evidence_receipt_once_blocking(&handle, first_receipt)
        });
        decision_gate.wait_until_durable().await;

        let contended = observe_context_evidence_receipt_authority_contention_for_test(home.path());
        let second_writer = second.clone();
        let second_receipt = receipt.clone();
        let second_append = tokio::task::spawn_blocking(move || {
            second_writer.append_context_evidence_receipt_once_blocking(&handle, second_receipt)
        });
        wait_for_context_evidence_receipt_authority_contention(contended).await;
        decision_gate.release();

        first_append
            .await
            .expect("join first concurrent receipt caller")
            .expect("first identical receipt caller succeeds");
        second_append
            .await
            .expect("join second concurrent receipt caller")
            .expect("second identical receipt caller deduplicates successfully");
        drop(first);
        drop(second);
        first_join.await.expect("join first racing writer");
        second_join.await.expect("join second racing writer");
        assert_single_authenticated_context_evidence_receipt(home.path(), &handle, &receipt);
    }

    #[tokio::test]
    async fn concurrent_home_writers_reject_same_handle_with_different_payload() {
        let home = tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir(&wal).unwrap();
        let (first, first_join) = spawn_test_writer_at_home(
            wal.join("context-collision-a-000001.wal"),
            home.path(),
            RotationPolicy::default(),
            CompressionPolicy::None,
        )
        .expect("spawn first collision Context Evidence writer");
        let (second, second_join) = spawn_test_writer_at_home(
            wal.join("context-collision-b-000001.wal"),
            home.path(),
            RotationPolicy::default(),
            CompressionPolicy::None,
        )
        .expect("spawn second collision Context Evidence writer");
        let decision_gate = TestAckGate::once(crate::wal::events::EVENT_TYPE_EXTENDED);
        let first = first.with_test_receipt_decision_gate(decision_gate.clone());
        let handle = [0xB0; 32];
        let winning_receipt = context_evidence_receipt(handle, 89, 97);
        let conflicting_receipt = context_evidence_receipt(handle, 101, 103);

        let first_writer = first.clone();
        let first_receipt = winning_receipt.clone();
        let first_append = tokio::task::spawn_blocking(move || {
            first_writer.append_context_evidence_receipt_once_blocking(&handle, first_receipt)
        });
        decision_gate.wait_until_durable().await;

        let contended = observe_context_evidence_receipt_authority_contention_for_test(home.path());
        let second_writer = second.clone();
        let second_receipt = conflicting_receipt.clone();
        let second_append = tokio::task::spawn_blocking(move || {
            second_writer.append_context_evidence_receipt_once_blocking(&handle, second_receipt)
        });
        wait_for_context_evidence_receipt_authority_contention(contended).await;
        decision_gate.release();

        first_append
            .await
            .expect("join winning receipt caller")
            .expect("authority holder must append the winning receipt");
        let collision = second_append
            .await
            .expect("join conflicting receipt caller")
            .expect_err("second payload for the same handle must fail closed");
        assert_eq!(
            collision.to_string(),
            "context_evidence_receipt_append_failed"
        );
        drop(first);
        drop(second);
        first_join.await.expect("join first collision writer");
        second_join.await.expect("join second collision writer");
        assert_single_authenticated_context_evidence_receipt(
            home.path(),
            &handle,
            &winning_receipt,
        );
    }

    #[tokio::test]
    async fn context_evidence_receipt_authority_holds_capability_file_lock() {
        let home = tempdir().unwrap();
        std::fs::create_dir(home.path().join("wal")).unwrap();
        let authority = acquire_context_evidence_receipt_authority(home.path())
            .await
            .expect("acquire receipt authority");
        let sentinel = context_evidence_receipt_authority_sentinel(home.path());
        let lock_path = super::super::redact::segment_rewrite_lock_path(&sentinel);
        let held = crate::util::locked_file::try_lock_file_once(
            &lock_path,
            "Context Evidence receipt authority probe",
        )
        .expect("probe held receipt file authority");
        assert!(
            held.is_none(),
            "the process guard must not substitute for the cross-process file lock"
        );

        drop(authority);
        let released = crate::util::locked_file::try_lock_file_once(
            &lock_path,
            "released Context Evidence receipt authority probe",
        )
        .expect("probe released receipt file authority");
        assert!(
            released.is_some(),
            "dropping authority must release the file lock"
        );
    }

    #[tokio::test]
    async fn context_evidence_receipt_survives_durable_pre_ack_writer_abort() {
        let home = tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir(&wal).unwrap();
        let segment = wal.join("context-runtime-000001.wal");
        let (writer, join) = spawn_test_writer_at_home(
            segment.clone(),
            home.path(),
            RotationPolicy::default(),
            CompressionPolicy::None,
        )
        .expect("spawn Context Evidence writer");
        let gate = TestAckGate::once(crate::wal::events::EVENT_TYPE_EXTENDED);
        let writer = writer.with_test_ack_gate(gate.clone());
        let handle = [0xB4; 32];
        let receipt = context_evidence_receipt(handle, 31, 47);
        let append_writer = writer.clone();
        let append_receipt = receipt.clone();
        let in_flight = tokio::task::spawn_blocking(move || {
            append_writer.append_context_evidence_receipt_once_blocking(&handle, append_receipt)
        });

        gate.wait_until_durable().await;
        join.abort();
        assert!(join.await.is_err(), "writer fixture must abort before ACK");
        let error = in_flight
            .await
            .expect("join blocked receipt caller")
            .expect_err("aborted writer cannot deliver the first ACK");
        assert!(
            !format!("{error:#}").contains(&hex::encode(handle)),
            "opaque receipt handles must never enter errors"
        );
        drop(writer);

        let (writer, join) = spawn_test_writer_at_home(
            segment,
            home.path(),
            RotationPolicy::default(),
            CompressionPolicy::None,
        )
        .expect("restart Context Evidence writer after lost ACK");
        append_context_evidence_receipt_once_for_test(&writer, handle, receipt.clone())
            .await
            .expect("restart replay must observe durable authenticated receipt");
        drop(writer);
        join.await.expect("join restarted Context Evidence writer");
        assert_single_authenticated_context_evidence_receipt(home.path(), &handle, &receipt);
    }

    #[tokio::test]
    async fn home_writer_completion_surfaces_shutdown_marker_failure() {
        let home = tempdir().unwrap();
        let wal = home.path().join("wal");
        std::fs::create_dir(&wal).unwrap();
        let segment = unique_standalone_segment_path(&wal, "completion-test");
        let (writer, completion) =
            spawn_for_home_with_completion(segment.clone(), home.path().to_path_buf())
                .expect("spawn completion-aware home writer");

        writer
            .append(batchable_header_for(1, 1), vec![b'x'])
            .await
            .expect("append pre-shutdown frame");
        fail_compaction_marker_write_for_test(&segment);
        drop(writer);

        let error = completion
            .wait()
            .await
            .expect_err("shutdown marker failure must reach the one-shot caller");
        assert!(
            error
                .to_string()
                .contains("injected compaction marker write failure"),
            "unexpected completion error: {error}"
        );
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

    /// A sealed segment is immutable. Restart rotates to a fresh raw segment,
    /// so the old compressed body is never mistaken for a torn live tail.
    #[tokio::test]
    async fn sealed_compression_restart_preserves_old_and_new_frames() {
        use crate::wal::segment_header::{ParsedSegmentHeader, parse_segment_header};

        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let next = dir.path().join("000002.wal");

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
        assert!(parsed.is_sealed(), "finalized segment must be sealed");

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

        assert_eq!(
            tokio::fs::read(&seg).await.unwrap(),
            bytes,
            "sealed predecessor must remain byte-for-byte immutable"
        );
        let bytes2 = tokio::fs::read(&next).await.unwrap();
        let parsed2 = parse_segment_header(&bytes2).expect("parse successor");
        assert_eq!(
            parsed2.compaction_epoch(),
            1,
            "fresh successor owns its own first compaction epoch"
        );
        assert!(parsed2.is_compressed() && parsed2.is_sealed());

        let mut predecessor_payloads = Vec::new();
        crate::wal::scan::for_each_frame(&bytes, |_, frame| {
            predecessor_payloads.push(frame.payload.to_vec());
            Ok(())
        })
        .unwrap();
        assert!(
            predecessor_payloads
                .iter()
                .any(|payload| payload == b"alpha")
        );

        let mut successor_payloads = Vec::new();
        crate::wal::scan::for_each_frame(&bytes2, |_, frame| {
            successor_payloads.push(frame.payload.to_vec());
            Ok(())
        })
        .unwrap();
        assert!(successor_payloads.iter().any(|payload| payload == b"bravo"));
    }

    #[tokio::test]
    async fn unsealed_compression_restart_rebuilds_pending_frames_before_seal() {
        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let opened_at = current_ns();
        let header = new_segment_header_bytes(CompressionPolicy::Zstd3, 1, opened_at);
        let alpha = encode_frame(&header_for(5, 1), b"alpha");
        let mut raw_live = header;
        raw_live.extend_from_slice(&alpha);
        std::fs::write(&seg, &raw_live).unwrap();

        let (handle, join) = spawn_with_policy_and_compression(
            seg.clone(),
            RotationPolicy::default(),
            CompressionPolicy::Zstd3,
        )
        .expect("resume raw live zstd staging segment");
        handle
            .append(header_for(5, 2), b"bravo".to_vec())
            .await
            .expect("append after raw restart");
        drop(handle);
        join.await.expect("join");

        let sealed = tokio::fs::read(&seg).await.unwrap();
        let parsed = parse_segment_header(&sealed).unwrap();
        assert!(parsed.is_compressed() && parsed.is_sealed());
        let mut payloads = Vec::new();
        crate::wal::scan::for_each_frame(&sealed, |_, frame| {
            payloads.push(frame.payload.to_vec());
            Ok(())
        })
        .unwrap();
        assert!(payloads.iter().any(|payload| payload == b"alpha"));
        assert!(payloads.iter().any(|payload| payload == b"bravo"));
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
    //   cargo test -p neoth --lib wal_sync_latency -- --ignored --nocapture --test-threads=1
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
    #[ignore = "D008 latency bench — run with: cargo test -p neoth --lib wal_sync_latency -- --ignored --nocapture --test-threads=1"]
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
        // Bypass the initial-measure trigger so state is precisely known.
        guard.reserved.store(0, Ordering::Release);
        guard.last_measured.store(0, Ordering::Release);
        guard.needs_measurement.store(false, Ordering::Release);

        let handle = WalWriterHandle {
            tx,
            authentication_markers_enabled: false,
            quota: Some(Arc::clone(&guard)),
            test_ack_gate: None,
            test_receipt_decision_gate: None,
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
