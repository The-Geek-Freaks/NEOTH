//! Crash-safe, exactly-once projection boundary for proactive channel egress.
//!
//! A private durable `Prepared` claim precedes the mandatory WAL intent. The
//! claim is then atomically armed before the sole transport call. Terminal WAL
//! results, the operator sidecar, Cron correlation and queue settlement are all
//! idempotently resumed from that claim after a crash. Claims are never used as
//! authority on their own: recovery authenticates the selected WAL chain before
//! interpreting any of them.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::channels::{Channel, ChannelError, MessageId};
use crate::daemon::proactive_dispatcher::{PROACTIVE_DELIVERED_SIDECAR, ProactiveStatus};
use crate::proactive::{
    MAX_PROACTIVE_BODY_BYTES, MAX_PROACTIVE_CHANNEL_BYTES, MAX_PROACTIVE_ITEM_ENCODED_BYTES,
    ProactiveItem, ProactiveQueue,
};
use crate::wal::events::{EVENT_TYPE_EXTENDED, ExtendedSubtype};
use crate::wal::writer::WalWriterHandle;

pub const PROACTIVE_INFLIGHT_DIR: &str = "proactive_inflight";
pub const PROACTIVE_DELIVERY_LOCK_FILE: &str = "proactive_delivery.lock";

/// Claim/WAL v2 binds an absolute retry budget into the durable authority.
///
/// Version one is deliberately still accepted for recovery: it cannot prove a
/// bounded live attempt, so an Armed v1 claim without a terminal result is
/// immediately settled as `CrashUnknown` rather than replayed.
const CLAIM_VERSION: u8 = 2;
const LEGACY_CLAIM_VERSION: u8 = 1;
const WAL_BINDING_VERSION: u8 = 2;
const LEGACY_WAL_BINDING_VERSION: u8 = 1;
const MAX_CLAIMS: usize = 1_024;
const MAX_CLAIM_DIRECTORY_ENTRIES: usize = 2_048;
const MAX_CLAIM_BYTES: u64 = 2 * 1024 * 1024;
const MIN_CLAIM_ENVELOPE_HEADROOM_BYTES: u64 = 256 * 1024;
const _: () = assert!(
    MAX_PROACTIVE_ITEM_ENCODED_BYTES as u64 + MIN_CLAIM_ENVELOPE_HEADROOM_BYTES <= MAX_CLAIM_BYTES
);
const MAX_HISTORY_RECORD_BYTES: usize = MAX_PROACTIVE_BODY_BYTES + 256 * 1024;
const MIN_HISTORY_RECORD_ENVELOPE_HEADROOM_BYTES: usize = 128 * 1024;
const _: () = assert!(
    MAX_PROACTIVE_ITEM_ENCODED_BYTES + MIN_HISTORY_RECORD_ENVELOPE_HEADROOM_BYTES
        <= MAX_HISTORY_RECORD_BYTES
);
const MAX_TOTAL_CLAIM_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SIDECAR_BYTES: u64 = 64 * 1024 * 1024;
const SIDECAR_ROTATE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ROTATED_SIDECARS: usize = 32;
const MAX_ROTATION_CRASH_ARCHIVES: usize = MAX_ROTATED_SIDECARS + 1;
const DEFAULT_DELIVERY_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(60);
// Windows byte-range locks conflict with reads over their range. Keep the
// cross-process lease on one out-of-band byte so recovery can still read and
// authenticate the private claim before it probes Busy. Unix flock locks do
// not block ordinary reads, but use the same named logical lease.
const ARMED_CLAIM_LEASE_OFFSET: u64 = MAX_CLAIM_BYTES + 4_096;

type TransportJoinHandle = tokio::task::JoinHandle<std::result::Result<MessageId, ChannelError>>;

struct CancelledTransportHandle {
    handle: TransportJoinHandle,
    registration: TransportIntentRegistration,
}

/// Outer-future cancellation cannot await, but it must also never detach a
/// provider task. Drop moves the aborted handle into this process-lifetime
/// supervisor. Every recovery/admission path drains it before it may inspect
/// or change durable claim state; a non-cooperative task therefore blocks new
/// egress fail-closed instead of becoming an unobservable background effect.
static CANCELLED_TRANSPORT_REAP_QUEUE: LazyLock<Mutex<Vec<CancelledTransportHandle>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

/// In-process ownership registry for attempts whose channel future can still
/// be alive. It closes the narrow cancellation/recovery race: recovery checks
/// this intent-associated state before it can turn an expired Armed claim into
/// CrashUnknown. The owning egress task clears it only after join/reap.
static ACTIVE_TRANSPORT_INTENTS: LazyLock<Mutex<HashSet<String>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// Same-process companion to the OS lease. File locking can be re-entrant for
/// handles in one process on some platforms, so recovery needs an intent-bound
/// local gate too. It is registered under DeliveryLock before Armed WAL ACK
/// and is transferred into the cancellation reaper rather than being dropped
/// with an outer egress future.
struct TransportIntentRegistration {
    intent_id: String,
    active: bool,
}

impl TransportIntentRegistration {
    fn acquire(intent_id: &str) -> Self {
        mark_transport_active(intent_id);
        Self {
            intent_id: intent_id.to_string(),
            active: true,
        }
    }

    fn release(&mut self) {
        if self.active {
            mark_transport_inactive(&self.intent_id);
            self.active = false;
        }
    }
}

impl Drop for TransportIntentRegistration {
    fn drop(&mut self) {
        self.release();
    }
}

struct BoundClaimFile {
    root: Arc<crate::skills::store::BoundDirectory>,
    name: OsString,
    display_path: PathBuf,
    removal_binding: Mutex<Option<crate::skills::store::BoundChildObject>>,
}

impl BoundClaimFile {
    fn new(
        root: Arc<crate::skills::store::BoundDirectory>,
        name: OsString,
        removal_binding: crate::skills::store::BoundChildObject,
    ) -> Self {
        let display_path = root.display_path.join(&name);
        Self {
            root,
            name,
            display_path,
            removal_binding: Mutex::new(Some(removal_binding)),
        }
    }

    fn ensure_current(&self) -> Result<()> {
        let binding = self
            .removal_binding
            .lock()
            .map_err(|_| anyhow::anyhow!("proactive claim removal binding lock poisoned"))?;
        let binding = binding
            .as_ref()
            .context("proactive claim removal binding was already consumed")?;
        anyhow::ensure!(
            binding.matches_child(&self.root.dir, &self.name, &self.display_path)?,
            "proactive claim identity changed before its effect"
        );
        Ok(())
    }

    fn identity_token(&self) -> Result<String> {
        let binding = self
            .removal_binding
            .lock()
            .map_err(|_| anyhow::anyhow!("proactive claim removal binding lock poisoned"))?;
        Ok(binding
            .as_ref()
            .context("proactive claim removal binding was already consumed")?
            .identity_token()
            .to_owned())
    }

    /// Release the old Windows leaf handle immediately before replacing a
    /// claim generation.
    ///
    /// The claim-root capability and the process-wide delivery lock remain
    /// held across this window.  The leaf is first revalidated against the
    /// retained kernel identity, then deliberately consumed: the
    /// capability-relative legacy `FILE_RENAME_INFORMATION` commit cannot
    /// replace an opened target even when every participant shares delete
    /// access.  The committed bytes are read back and rebound before the
    /// caller may continue to the Armed WAL frame
    /// or transport.  Failure or cancellation therefore leaves this object
    /// unbound and forces restart recovery instead of authorizing an effect.
    #[cfg(windows)]
    fn release_current_for_atomic_replace(&self) -> Result<()> {
        let mut binding = self
            .removal_binding
            .lock()
            .map_err(|_| anyhow::anyhow!("proactive claim removal binding lock poisoned"))?;
        let current = binding
            .as_ref()
            .context("proactive claim removal binding was already consumed")?;
        anyhow::ensure!(
            current.matches_child(&self.root.dir, &self.name, &self.display_path)?,
            "proactive claim identity changed before its atomic replacement"
        );
        drop(binding.take());
        Ok(())
    }

    fn replace_binding(&self, replacement: crate::skills::store::BoundChildObject) -> Result<()> {
        let mut binding = self
            .removal_binding
            .lock()
            .map_err(|_| anyhow::anyhow!("proactive claim removal binding lock poisoned"))?;
        *binding = Some(replacement);
        Ok(())
    }

    fn remove(self) -> Result<()> {
        let binding = self
            .removal_binding
            .into_inner()
            .map_err(|_| anyhow::anyhow!("proactive claim removal binding lock poisoned"))?
            .context("proactive claim removal binding was already consumed")?;
        binding.remove_bound_file(&self.root.dir, &self.name, &self.display_path)
    }

    #[cfg(test)]
    fn exists(&self) -> bool {
        self.display_path.exists()
    }
}

/// Cross-process lifetime fence for one exact Armed v2 claim file.
///
/// The delivery lock serializes short durable transitions, but it is released
/// for provider I/O.  A wall-clock jump in a second process must therefore not
/// turn the first process's still-monotonic-live attempt into `CrashUnknown`.
/// This lease is acquired only from the capability-bound, no-follow final
/// `.claimed` object and is retained until the provider future has stopped and
/// the Result WAL acknowledgement has made terminal evidence durable. Dropping
/// the file handle releases the OS lease on process crash.
struct ArmedClaimLease {
    root: Arc<crate::skills::store::BoundDirectory>,
    name: OsString,
    display_path: PathBuf,
    intent_id: String,
    binding_sha256: String,
    namespace_binding: crate::skills::store::BoundChildObject,
    // The exact no-follow handle retains the OS lease: an out-of-band
    // LockFileEx byte on Windows and `File::try_lock`/flock on Unix. Do not
    // replace it with a sibling lock path.
    _file: std::fs::File,
}

enum ArmedClaimLeaseProbe {
    Acquired(ArmedClaimLease),
    Busy,
}

/// `true` means this exact claim object is now exclusively leased; `false`
/// means another process owns it. The handle itself retains the lease.
fn try_lock_armed_claim_file(file: &std::fs::File) -> Result<bool> {
    #[cfg(unix)]
    {
        match file.try_lock() {
            Ok(()) => Ok(true),
            Err(std::fs::TryLockError::WouldBlock) => Ok(false),
            Err(std::fs::TryLockError::Error(error)) => {
                Err(error).context("lock proactive Armed claim lease")
            }
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::Foundation::{GetLastError, HANDLE};
        use windows_sys::Win32::Storage::FileSystem::{
            LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
        };

        #[repr(C)]
        struct LeaseOverlapped {
            internal: usize,
            internal_high: usize,
            offset: u32,
            offset_high: u32,
            event: isize,
        }
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn LockFileEx(
                file: HANDLE,
                flags: u32,
                reserved: u32,
                bytes_low: u32,
                bytes_high: u32,
                overlapped: *mut LeaseOverlapped,
            ) -> i32;
        }

        let mut overlapped = LeaseOverlapped {
            internal: 0,
            internal_high: 0,
            offset: ARMED_CLAIM_LEASE_OFFSET as u32,
            offset_high: (ARMED_CLAIM_LEASE_OFFSET >> 32) as u32,
            event: 0,
        };
        // SAFETY: `file` is an owned valid Windows file handle; the
        // stack-backed OVERLAPPED is used synchronously with FAIL_IMMEDIATELY,
        // so it cannot outlive this call.
        let acquired = unsafe {
            LockFileEx(
                file.as_raw_handle() as HANDLE,
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                1,
                0,
                &mut overlapped,
            ) != 0
        };
        if acquired {
            return Ok(true);
        }
        // ERROR_LOCK_VIOLATION is the sole expected non-blocking contention
        // result. Everything else is a real capability/I/O failure.
        const ERROR_LOCK_VIOLATION: u32 = 33;
        let code = unsafe { GetLastError() };
        if code == ERROR_LOCK_VIOLATION {
            Ok(false)
        } else {
            Err(std::io::Error::from_raw_os_error(code as i32))
                .context("lock proactive Armed claim lease")
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        match file.try_lock() {
            Ok(()) => Ok(true),
            Err(std::fs::TryLockError::WouldBlock) => Ok(false),
            Err(std::fs::TryLockError::Error(error)) => {
                Err(error).context("lock proactive Armed claim lease")
            }
        }
    }
}

impl ArmedClaimLease {
    fn try_acquire(
        claim_file: &BoundClaimFile,
        claim: &ProactiveEgressClaim,
    ) -> Result<ArmedClaimLeaseProbe> {
        anyhow::ensure!(
            claim.version == CLAIM_VERSION && claim.phase == ProactiveEgressPhase::Armed,
            "only an Armed v2 proactive claim may acquire a transport lease"
        );
        let expected_name = claim_name(claim);
        anyhow::ensure!(
            claim_file.name == OsStr::new(&expected_name),
            "proactive Armed claim lease name does not match its authenticated claim"
        );
        validate_claim(claim, &expected_name)?;
        anyhow::ensure!(
            claim.binding_sha256 == binding_hash(claim),
            "proactive Armed claim lease received an invalid claim binding"
        );
        // Bind the lease to the exact generation read by recovery/admission,
        // rather than merely whatever object presently occupies its path.
        claim_file.ensure_current()?;
        let expected_identity = claim_file.identity_token()?;

        // This is the no-follow capability open. The returned binding proves
        // that the exact direct child did not change while being opened.
        let (mut opened, namespace_binding, is_private) =
            open_regular_claim_readonly(&claim_file.root, &claim_file.name)?;
        anyhow::ensure!(
            is_private,
            "refuse to lease a proactive claim whose permissions are not private"
        );
        anyhow::ensure!(
            namespace_binding.identity_token() == expected_identity,
            "proactive Armed claim identity changed before lease acquisition"
        );
        let mut bytes = Vec::new();
        (&mut opened)
            .take(MAX_CLAIM_BYTES + 1)
            .read_to_end(&mut bytes)
            .context("read final proactive Armed claim before lease")?;
        anyhow::ensure!(
            bytes.len() as u64 <= MAX_CLAIM_BYTES,
            "proactive Armed claim exceeds size limit before lease"
        );
        let observed: ProactiveEgressClaim = serde_json::from_slice(&bytes)
            .context("decode final proactive Armed claim before lease")?;
        validate_claim(&observed, &expected_name)?;
        anyhow::ensure!(
            observed == *claim,
            "proactive Armed claim bytes changed before lease acquisition"
        );
        // Re-check the original mutation-capability binding immediately after
        // reading; the later lease validation repeats this exact identity
        // check before each provider or terminal effect.
        claim_file.ensure_current()?;

        let file = opened.into_std();

        match try_lock_armed_claim_file(&file)? {
            true => {
                let lease = Self {
                    root: Arc::clone(&claim_file.root),
                    name: claim_file.name.clone(),
                    display_path: claim_file.display_path.clone(),
                    intent_id: claim.intent_id.clone(),
                    binding_sha256: claim.binding_sha256.clone(),
                    namespace_binding,
                    _file: file,
                };
                claim_file.ensure_current()?;
                lease.validate_claim(claim)?;
                Ok(ArmedClaimLeaseProbe::Acquired(lease))
            }
            false => Ok(ArmedClaimLeaseProbe::Busy),
        }
    }

    /// Revalidate the immutable identity/binding immediately before every
    /// effect boundary. This never trusts an ambient path and never reads raw
    /// adapter data into a durable error path.
    fn validate_claim(&self, claim: &ProactiveEgressClaim) -> Result<()> {
        anyhow::ensure!(
            claim.version == CLAIM_VERSION
                && claim.phase == ProactiveEgressPhase::Armed
                && claim.intent_id == self.intent_id
                && claim.binding_sha256 == self.binding_sha256
                && claim.binding_sha256 == binding_hash(claim)
                && claim_name(claim) == self.name.to_string_lossy(),
            "proactive Armed claim lease binding changed before effect"
        );
        self.validate_namespace_binding()
    }

    fn validate_namespace_binding(&self) -> Result<()> {
        let matches = self.namespace_binding.matches_regular_file_child_readonly(
            &self.root.dir,
            &self.name,
            &self.display_path,
        )?;
        anyhow::ensure!(
            matches,
            "proactive Armed claim lease namespace changed before effect"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProactiveEgressPhase {
    Prepared,
    Armed,
}

/// Private recovery state. Raw body data is confined to current-user-only claim
/// and operator-history files and never enters the WAL. Recipients, provider
/// receipts and error evidence are never persisted there in cleartext.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProactiveEgressClaim {
    pub version: u8,
    pub phase: ProactiveEgressPhase,
    pub intent_id: String,
    pub item: ProactiveItem,
    pub target_channel: String,
    pub recipient_sha256: String,
    pub message_sha256: String,
    pub message_bytes: usize,
    pub item_sha256: String,
    pub dedup_sha256: String,
    pub queue_generation: String,
    /// Upgrade marker for the pre-GOLD inflight format whose filename used a
    /// plain SHA-256 of the dedup key. A converted legacy claim remains on that
    /// exact path until its authenticated CrashUnknown projection commits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_claim_sha256: Option<String>,
    pub binding_sha256: String,
    pub created_at_unix: i64,
    /// Absolute UTC seconds at which a v2 Armed attempt is no longer allowed
    /// to remain in-flight. It is included in the v2 claim binding and Intent
    /// frame, so a crash cannot extend an already-admitted transport budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_deadline_unix: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProactiveEgressOutcome {
    Delivered,
    TransportError,
    AuthError,
    RateLimited,
    AdapterConfigurationError,
    SidecarOnly,
    PolicySuppressed,
    CrashUnknown,
    NotAttempted,
}

impl ProactiveEgressOutcome {
    fn status(self) -> ProactiveStatus {
        match self {
            Self::Delivered => ProactiveStatus::Delivered,
            Self::SidecarOnly => ProactiveStatus::SidecarOnly,
            Self::PolicySuppressed => ProactiveStatus::Suppressed,
            Self::NotAttempted => ProactiveStatus::Suppressed,
            Self::TransportError
            | Self::AuthError
            | Self::RateLimited
            | Self::AdapterConfigurationError
            | Self::CrashUnknown => ProactiveStatus::Failed,
        }
    }

    /// Stable wire spelling shared by the CLI, GUI feed and Buddy. Provider-
    /// specific transport failures intentionally collapse to `failed` at the
    /// user surface while the private record retains the exact typed outcome.
    pub fn display_label(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::TransportError | Self::AuthError | Self::RateLimited => "failed",
            Self::AdapterConfigurationError => "configuration_error",
            Self::SidecarOnly => "sidecar_only",
            Self::PolicySuppressed => "suppressed",
            Self::CrashUnknown => "crash_unknown",
            Self::NotAttempted => "not_attempted",
        }
    }

    pub fn from_wire_str(value: &str) -> Option<Self> {
        match value {
            "delivered" => Some(Self::Delivered),
            "transport_error" => Some(Self::TransportError),
            "auth_error" => Some(Self::AuthError),
            "rate_limited" => Some(Self::RateLimited),
            "adapter_configuration_error" | "configuration_error" => {
                Some(Self::AdapterConfigurationError)
            }
            "sidecar_only" => Some(Self::SidecarOnly),
            "policy_suppressed" => Some(Self::PolicySuppressed),
            "crash_unknown" => Some(Self::CrashUnknown),
            "not_attempted" => Some(Self::NotAttempted),
            _ => None,
        }
    }

    pub fn buddy_activity(self) -> &'static str {
        match self {
            Self::Delivered => "success",
            Self::TransportError | Self::AuthError | Self::RateLimited => "error",
            Self::AdapterConfigurationError => "error",
            Self::SidecarOnly => "notification",
            Self::PolicySuppressed | Self::CrashUnknown | Self::NotAttempted => "alert",
        }
    }

    pub fn buddy_caption(self) -> &'static str {
        match self {
            Self::Delivered => "proactive delivered",
            Self::TransportError | Self::AuthError | Self::RateLimited => "proactive failed",
            Self::AdapterConfigurationError => "adapter configuration error",
            Self::SidecarOnly => "saved locally",
            Self::PolicySuppressed => "proactive suppressed",
            Self::CrashUnknown => "delivery unknown",
            Self::NotAttempted => "delivery not attempted",
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProactiveIntentFrame {
    proactive_binding_version: u8,
    intent_id: String,
    binding_sha256: String,
    target_channel: String,
    recipient_sha256: String,
    message_sha256: String,
    message_bytes: usize,
    item_sha256: String,
    dedup_sha256: String,
    queue_generation: String,
    created_at_unix: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attempt_deadline_unix: Option<i64>,
}

/// Authenticated proof that the private claim was durably Armed before any
/// transport call. This distinct ACK removes mutable `claim.phase` from the
/// authority decision during crash recovery.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProactiveArmedFrame {
    proactive_binding_version: u8,
    intent_id: String,
    prepared_binding_sha256: String,
    armed_binding_sha256: String,
    armed_at_unix: i64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProactiveResultFrame {
    proactive_binding_version: u8,
    purpose: String,
    intent_id: String,
    binding_sha256: String,
    target_channel: String,
    recipient_sha256: String,
    message_bytes: usize,
    outcome: ProactiveEgressOutcome,
    receipt_sha256: Option<String>,
    receipt_bytes: usize,
    error_kind: Option<String>,
    error_sha256: Option<String>,
    error_bytes: usize,
    completed_at_unix: i64,
}

/// Canonical operator-inbox projection. Equality over this complete value is
/// the idempotency contract; matching only `intent_id` would accept a partial
/// or conflicting prior projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProactiveDeliveryRecord {
    version: u8,
    intent_id: String,
    /// Canonical first segment of the authenticated daemon WAL namespace that
    /// contains this intent/result transaction. The value is only a locator;
    /// the consumer still authenticates the selected chain and binds every
    /// projected field to its WAL evidence before exposing the record.
    wal_chain_base: String,
    binding_sha256: String,
    recipient_sha256: String,
    intent_frame_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    armed_frame_sha256: Option<String>,
    result_frame_sha256: String,
    delivered_at_unix: i64,
    #[serde(rename = "status")]
    outcome: ProactiveEgressOutcome,
    was_failure: bool,
    target_channel: String,
    dedup_sha256: String,
    message_sha256: String,
    message_bytes: usize,
    item_sha256: String,
    queue_generation: String,
    item: ProactiveItem,
}

impl ProactiveDeliveryRecord {
    pub fn intent_id(&self) -> &str {
        &self.intent_id
    }

    pub fn delivered_at_unix(&self) -> i64 {
        self.delivered_at_unix
    }

    pub fn outcome(&self) -> ProactiveEgressOutcome {
        self.outcome
    }

    pub fn target_channel(&self) -> &str {
        &self.target_channel
    }

    pub fn dedup_sha256(&self) -> &str {
        &self.dedup_sha256
    }

    pub fn message_bytes(&self) -> usize {
        self.message_bytes
    }

    pub fn item(&self) -> &ProactiveItem {
        &self.item
    }

    pub fn is_legacy_unverified(&self) -> bool {
        self.version == 0
    }

    pub fn verification_label(&self) -> &'static str {
        if self.is_legacy_unverified() {
            "legacy_unverified"
        } else {
            // Modern records can only escape `read_delivery_history` after the
            // shared home-WAL scanner authenticated this exact Intent/Result
            // transaction (and its Armed proof for a transport attempt).
            "wal_verified"
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyProactiveDeliveryRecord {
    delivered_at_unix: i64,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    was_failure: Option<bool>,
    #[serde(default)]
    dedup_key: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    body: Option<String>,
    item: ProactiveItem,
}

fn migrate_legacy_delivery_record(
    raw_line: &[u8],
    legacy: LegacyProactiveDeliveryRecord,
) -> Result<ProactiveDeliveryRecord> {
    let outcome = match legacy.status.as_deref() {
        None => ProactiveEgressOutcome::SidecarOnly,
        Some("delivered") => ProactiveEgressOutcome::Delivered,
        // The historical schema collapsed every adapter error to `failed`.
        // TransportError is the honest generic typed migration.
        Some("failed") => ProactiveEgressOutcome::TransportError,
        Some("suppressed") => ProactiveEgressOutcome::PolicySuppressed,
        Some("sidecar_only") => ProactiveEgressOutcome::SidecarOnly,
        Some("crash_recovered") => ProactiveEgressOutcome::CrashUnknown,
        Some(other) => anyhow::bail!("unsupported legacy proactive history status `{other}`"),
    };
    if let Some(was_failure) = legacy.was_failure {
        anyhow::ensure!(
            was_failure == legacy.item.is_failure,
            "legacy proactive history failure marker conflicts with the item"
        );
    }
    if let Some(dedup_key) = legacy.dedup_key.as_deref() {
        anyhow::ensure!(
            dedup_key == legacy.item.dedup_key,
            "legacy proactive history dedup key conflicts with the item"
        );
    }
    if let Some(source) = legacy.source.as_deref() {
        anyhow::ensure!(
            source == legacy.item.source,
            "legacy proactive history source conflicts with the item"
        );
    }
    if let Some(body) = legacy.body.as_deref() {
        anyhow::ensure!(
            body == legacy.item.body,
            "legacy proactive history body conflicts with the item"
        );
    }
    legacy
        .item
        .validate()
        .map_err(anyhow::Error::new)
        .context("validate legacy proactive history item")?;
    let item_bytes = serde_json::to_vec(&legacy.item).context("encode legacy proactive item")?;
    let provenance = effect_hash(b"proactive-egress-legacy-history-v1", raw_line);
    Ok(ProactiveDeliveryRecord {
        version: 0,
        intent_id: format!("legacy-{provenance}"),
        wal_chain_base: String::new(),
        binding_sha256: provenance.clone(),
        recipient_sha256: String::new(),
        intent_frame_sha256: String::new(),
        armed_frame_sha256: None,
        result_frame_sha256: String::new(),
        delivered_at_unix: legacy.delivered_at_unix,
        outcome,
        was_failure: legacy.item.is_failure,
        target_channel: if legacy.item.channel.trim().is_empty() {
            "local_inbox".to_string()
        } else {
            legacy.item.channel.clone()
        },
        dedup_sha256: effect_hash(
            b"proactive-egress-dedup-v1",
            legacy.item.dedup_key.as_bytes(),
        ),
        message_sha256: effect_hash(b"proactive-egress-message-v1", legacy.item.body.as_bytes()),
        message_bytes: legacy.item.body.len(),
        item_sha256: effect_hash(b"proactive-egress-item-v1", &item_bytes),
        queue_generation: provenance,
        item: legacy.item,
    })
}

fn decode_delivery_record_line(
    line: &[u8],
    formerly_broad: bool,
) -> Result<ProactiveDeliveryRecord> {
    let value: serde_json::Value =
        serde_json::from_slice(line).context("decode proactive history JSON")?;
    if value.get("version").is_some() {
        anyhow::ensure!(
            !formerly_broad,
            "modern proactive history was found in a formerly broad file; authenticity cannot be established"
        );
        let record: ProactiveDeliveryRecord =
            serde_json::from_value(value).context("decode proactive history record")?;
        validate_delivery_record(&record)?;
        Ok(record)
    } else {
        let legacy: LegacyProactiveDeliveryRecord =
            serde_json::from_value(value).context("decode legacy proactive history record")?;
        migrate_legacy_delivery_record(line, legacy)
    }
}

fn validate_strict_legacy_snapshot(body: &[u8]) -> Result<()> {
    let lines: Vec<_> = body.split(|byte| *byte == b'\n').collect();
    let mut records = 0usize;
    for (index, line) in lines.iter().enumerate() {
        if line.is_empty() {
            anyhow::ensure!(
                index + 1 == lines.len(),
                "broad legacy proactive history contains an empty record"
            );
            continue;
        }
        anyhow::ensure!(
            line.len() <= MAX_HISTORY_RECORD_BYTES,
            "broad legacy proactive history record exceeds the bounded record limit"
        );
        let record = decode_delivery_record_line(line, true)
            .context("decode broad legacy proactive history during rotation recovery")?;
        anyhow::ensure!(
            record.is_legacy_unverified(),
            "broad proactive history contains a non-legacy record"
        );
        records = records
            .checked_add(1)
            .context("broad legacy proactive history record count overflow")?;
    }
    anyhow::ensure!(
        records > 0,
        "broad legacy proactive history snapshot is empty"
    );
    Ok(())
}

#[derive(Default)]
struct WalEvidence {
    intents: HashMap<String, ProactiveIntentFrame>,
    armed: HashMap<String, ProactiveArmedFrame>,
    results: HashMap<String, ProactiveResultFrame>,
}

fn effect_hash(domain: &[u8], value: &[u8]) -> String {
    crate::wal::events::effect_digest(domain, value)
}

fn typed_frame_hash<T: Serialize>(domain: &[u8], frame: &T) -> Result<String> {
    let encoded = serde_json::to_vec(frame).context("encode proactive WAL evidence frame")?;
    Ok(effect_hash(domain, &encoded))
}

fn canonical_wal_chain_base_name(home: &Path, wal_segment_path: &Path) -> Result<String> {
    let wal_dir =
        std::path::absolute(home.join("wal")).context("resolve proactive history WAL directory")?;
    let segment = std::path::absolute(wal_segment_path)
        .context("resolve proactive history WAL chain base")?;
    let name = segment
        .file_name()
        .context("proactive WAL chain base omitted its file name")?;
    anyhow::ensure!(
        segment.parent() == Some(wal_dir.as_path())
            && crate::wal::scan::canonical_chain_base_segment_name(name),
        "proactive WAL chain base must be a canonical sequence-1 direct child of {}",
        wal_dir.display()
    );
    name.to_str()
        .map(str::to_owned)
        .context("proactive WAL chain base name is not UTF-8")
}

fn binding_hash(claim: &ProactiveEgressClaim) -> String {
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(&[claim.version]);
    bytes.push(match claim.phase {
        ProactiveEgressPhase::Prepared => 0,
        ProactiveEgressPhase::Armed => 1,
    });
    for value in [
        claim.intent_id.as_bytes(),
        claim.target_channel.as_bytes(),
        claim.recipient_sha256.as_bytes(),
        claim.message_sha256.as_bytes(),
        claim.item_sha256.as_bytes(),
        claim.dedup_sha256.as_bytes(),
        claim.queue_generation.as_bytes(),
        claim
            .legacy_claim_sha256
            .as_deref()
            .unwrap_or("")
            .as_bytes(),
    ] {
        bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
        bytes.extend_from_slice(value);
    }
    bytes.extend_from_slice(&(claim.message_bytes as u64).to_be_bytes());
    bytes.extend_from_slice(&claim.created_at_unix.to_be_bytes());
    match claim.version {
        LEGACY_CLAIM_VERSION => effect_hash(b"proactive-egress-binding-v1", &bytes),
        CLAIM_VERSION => {
            // Do not change the v1 preimage: existing persistent claims must
            // continue to authenticate byte-for-byte.  The deadline is a
            // mandatory v2 binding element and has no mutable recovery path.
            let Some(deadline) = claim.attempt_deadline_unix else {
                // Validation rejects this state; keep hashing total so a
                // malformed disk record produces a controlled validation
                // error rather than a recovery-process panic.
                return effect_hash(b"proactive-egress-binding-v2-invalid", &bytes);
            };
            bytes.extend_from_slice(&deadline.to_be_bytes());
            effect_hash(b"proactive-egress-binding-v2", &bytes)
        }
        _ => effect_hash(b"proactive-egress-binding-invalid", &bytes),
    }
}

fn claim_in_phase(
    claim: &ProactiveEgressClaim,
    phase: ProactiveEgressPhase,
) -> ProactiveEgressClaim {
    let mut projected = claim.clone();
    projected.phase = phase;
    projected.binding_sha256 = binding_hash(&projected);
    projected
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn canonical_claim_name(name: &str) -> bool {
    name.len() == 72 && name.ends_with(".claimed") && is_sha256_hex(&name[..64])
}

fn canonical_claim_temp_name(name: &str) -> bool {
    if let Some(token) = name.strip_prefix(".neoth-atomic-") {
        return token.len() == 32
            && token
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
    }
    let Some((claim, suffix)) = name.split_once(".claimed.") else {
        return false;
    };
    if !is_sha256_hex(claim) || !suffix.ends_with(".tmp") {
        return false;
    }
    let token = &suffix[..suffix.len() - 4];
    (!token.is_empty() && token.len() <= 20 && token.bytes().all(|byte| byte.is_ascii_digit()))
        || (token.len() == 32
            && token
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
}

fn claim_name(claim: &ProactiveEgressClaim) -> String {
    format!(
        "{}.claimed",
        claim
            .legacy_claim_sha256
            .as_deref()
            .unwrap_or(&claim.dedup_sha256)
    )
}

fn validate_uuid_v7(value: &str) -> Result<()> {
    let parsed = uuid::Uuid::parse_str(value).context("parse proactive intent UUID")?;
    anyhow::ensure!(
        parsed.get_version_num() == 7,
        "proactive intent id is not UUIDv7"
    );
    anyhow::ensure!(
        parsed.hyphenated().to_string() == value,
        "proactive intent id is not canonical lowercase UUID text"
    );
    Ok(())
}

fn validate_claim(claim: &ProactiveEgressClaim, file_name: &str) -> Result<()> {
    let encoded_claim = serde_json::to_vec(claim).context("encode proactive claim for bound")?;
    anyhow::ensure!(
        encoded_claim.len() as u64 <= MAX_CLAIM_BYTES,
        "serialized proactive claim exceeds size limit"
    );
    anyhow::ensure!(
        matches!(claim.version, LEGACY_CLAIM_VERSION | CLAIM_VERSION),
        "unsupported proactive claim version"
    );
    match claim.version {
        LEGACY_CLAIM_VERSION => anyhow::ensure!(
            claim.attempt_deadline_unix.is_none(),
            "legacy proactive claim unexpectedly carries an attempt deadline"
        ),
        CLAIM_VERSION => {
            let deadline = claim
                .attempt_deadline_unix
                .context("v2 proactive claim is missing its attempt deadline")?;
            anyhow::ensure!(
                deadline > claim.created_at_unix,
                "proactive attempt deadline must be after claim creation"
            );
        }
        _ => unreachable!("version was checked above"),
    }
    validate_uuid_v7(&claim.intent_id)?;
    anyhow::ensure!(
        !claim.target_channel.trim().is_empty()
            && claim.target_channel.len() <= MAX_PROACTIVE_CHANNEL_BYTES,
        "proactive claim target channel is invalid"
    );
    claim
        .item
        .validate()
        .map_err(anyhow::Error::new)
        .context("validate proactive claim item")?;
    anyhow::ensure!(
        claim.message_bytes == claim.item.body.len(),
        "proactive claim message length mismatch"
    );
    anyhow::ensure!(
        claim.message_sha256
            == effect_hash(b"proactive-egress-message-v1", claim.item.body.as_bytes()),
        "proactive claim message binding mismatch"
    );
    let item_bytes = serde_json::to_vec(&claim.item).context("encode proactive claim item")?;
    anyhow::ensure!(
        claim.item_sha256 == effect_hash(b"proactive-egress-item-v1", &item_bytes),
        "proactive claim item binding mismatch"
    );
    anyhow::ensure!(
        claim.dedup_sha256
            == effect_hash(
                b"proactive-egress-dedup-v1",
                claim.item.dedup_key.as_bytes()
            ),
        "proactive claim dedup binding mismatch"
    );
    anyhow::ensure!(
        is_sha256_hex(&claim.recipient_sha256),
        "invalid proactive recipient digest"
    );
    anyhow::ensure!(
        is_sha256_hex(&claim.message_sha256),
        "invalid proactive message digest"
    );
    anyhow::ensure!(
        is_sha256_hex(&claim.item_sha256),
        "invalid proactive item digest"
    );
    anyhow::ensure!(
        is_sha256_hex(&claim.dedup_sha256),
        "invalid proactive dedup digest"
    );
    if let Some(legacy) = &claim.legacy_claim_sha256 {
        anyhow::ensure!(
            is_sha256_hex(legacy),
            "invalid legacy proactive claim digest"
        );
    }
    anyhow::ensure!(
        !claim.queue_generation.is_empty() && claim.queue_generation.len() <= 64,
        "invalid proactive queue generation"
    );
    anyhow::ensure!(
        claim.binding_sha256 == binding_hash(claim),
        "proactive claim aggregate binding mismatch"
    );
    anyhow::ensure!(
        file_name == claim_name(claim),
        "proactive claim filename binding mismatch"
    );
    Ok(())
}

fn open_claim_directory(
    home: &Path,
    create: bool,
) -> Result<Option<Arc<crate::skills::store::BoundDirectory>>> {
    let claim_path = home.join(PROACTIVE_INFLIGHT_DIR);
    let trusted_anchor = home.parent().unwrap_or(home);
    let Some(root) = crate::skills::store::open_bound_directory_from_trusted_anchor(
        trusted_anchor,
        &claim_path,
        create,
        "proactive claim root",
    )?
    else {
        return Ok(None);
    };

    #[cfg(unix)]
    {
        use cap_std::fs::PermissionsExt as _;
        root.dir
            .set_permissions(".", cap_std::fs::Permissions::from_mode(0o700))
            .context("migrate bound proactive claim root to private mode")?;
        crate::skills::store::sync_parent_directory(&root.dir, &root.display_path)
            .context("durably persist bound proactive claim root mode")?;
        anyhow::ensure!(
            root.dir
                .dir_metadata()
                .context("inspect bound proactive claim root mode")?
                .permissions()
                .mode()
                & 0o077
                == 0,
            "proactive claim root permissions are not private"
        );
    }
    #[cfg(windows)]
    {
        crate::wal::win_native::set_private_current_user_directory_dacl_bound(
            &root.display_path,
            &root.dir,
        )
        .context("migrate bound proactive claim root to private DACL")?;
        crate::wal::win_native::verify_private_directory_handle_dacl(&root.dir)
            .context("verify bound proactive claim root private DACL")?;
    }
    Ok(Some(Arc::new(root)))
}

fn ensure_claim_directory(home: &Path) -> Result<Arc<crate::skills::store::BoundDirectory>> {
    open_claim_directory(home, true)?.context("created proactive claim root is unavailable")
}

fn open_regular_claim(
    root: &Arc<crate::skills::store::BoundDirectory>,
    name: &OsStr,
) -> Result<(
    cap_std::fs::File,
    crate::skills::store::BoundChildObject,
    bool,
)> {
    let (file, read_binding, is_private) = open_regular_claim_readonly(root, name)?;
    let display_path = root.display_path.join(name);
    let removal_binding = crate::skills::store::bind_regular_file_for_removal(
        &root.dir,
        name,
        &display_path,
        &read_binding,
    )
    .context("bind capability-bound proactive claim removal authority")?;
    Ok((file, removal_binding, is_private))
}

/// Open a claim for observation without acquiring Windows `DELETE` authority.
/// Legacy DACL migration needs this first phase because its no-delete-share
/// security handle cannot coexist with a retained removal handle.
fn open_regular_claim_readonly(
    root: &Arc<crate::skills::store::BoundDirectory>,
    name: &OsStr,
) -> Result<(
    cap_std::fs::File,
    crate::skills::store::BoundChildObject,
    bool,
)> {
    let display_path = root.display_path.join(name);
    let (file, read_binding) =
        crate::skills::store::open_bound_regular_file(&root.dir, name, &display_path)
            .context("open capability-bound proactive claim for observation")?;
    let metadata = file.metadata().context("inspect opened proactive claim")?;
    anyhow::ensure!(
        metadata.is_file() && !crate::skills::store::cap_metadata_is_link_like(&metadata),
        "proactive claim is not a real regular file"
    );
    anyhow::ensure!(
        metadata.len() <= MAX_CLAIM_BYTES,
        "proactive claim exceeds size limit"
    );
    #[cfg(unix)]
    let is_private = {
        use cap_std::fs::PermissionsExt as _;
        metadata.permissions().mode() & 0o077 == 0
    };
    #[cfg(windows)]
    let is_private = {
        let std_file = file
            .try_clone()
            .context("clone proactive claim for DACL verification")?
            .into_std();
        crate::wal::win_native::verify_private_file_handle(&std_file).is_ok()
    };
    #[cfg(not(any(unix, windows)))]
    let is_private = true;
    Ok((file, read_binding, is_private))
}

fn make_open_file_private(file: &cap_std::fs::File, _display_path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use cap_std::fs::PermissionsExt as _;
        file.set_permissions(cap_std::fs::Permissions::from_mode(0o600))
            .context("make legacy proactive file private")?;
        file.sync_all()
            .context("durably persist legacy proactive file mode")?;
        anyhow::ensure!(
            file.metadata()?.permissions().mode() & 0o077 == 0,
            "legacy proactive file mode migration did not stick"
        );
    }
    #[cfg(windows)]
    {
        crate::wal::win_native::set_private_current_user_file_dacl_bound(_display_path, file)
            .context("make bound legacy proactive file DACL private and durable")?;
        let std_file = file
            .try_clone()
            .context("clone migrated proactive claim for DACL verification")?
            .into_std();
        crate::wal::win_native::verify_private_file_handle(&std_file)
            .context("verify migrated proactive file DACL")?;
    }
    Ok(())
}

fn bind_written_claim(
    root: Arc<crate::skills::store::BoundDirectory>,
    name: OsString,
    expected: &[u8],
) -> Result<BoundClaimFile> {
    let (mut file, removal_binding, is_private) = open_regular_claim(&root, &name)?;
    anyhow::ensure!(
        is_private,
        "written proactive claim permissions are not private"
    );
    let metadata = file.metadata().context("inspect written proactive claim")?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    (&mut file)
        .take(MAX_CLAIM_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("read back written proactive claim")?;
    anyhow::ensure!(
        bytes == expected,
        "written proactive claim bytes changed before binding"
    );
    Ok(BoundClaimFile::new(root, name, removal_binding))
}

fn legacy_claim_digest(item: &ProactiveItem) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(item.dedup_key.as_bytes()))
}

fn read_claims(home: &Path, now_unix: i64) -> Result<Vec<(BoundClaimFile, ProactiveEgressClaim)>> {
    read_claims_with_legacy_migration_hook(home, now_unix, |_| Ok(()))
}

fn read_claims_with_legacy_migration_hook<F>(
    home: &Path,
    now_unix: i64,
    mut after_legacy_acl_migration: F,
) -> Result<Vec<(BoundClaimFile, ProactiveEgressClaim)>>
where
    F: FnMut(&Path) -> Result<()>,
{
    let Some(root) = open_claim_directory(home, false)? else {
        return Ok(Vec::new());
    };

    let mut names = Vec::new();
    let mut entries_seen = 0usize;
    for entry in root
        .dir
        .entries()
        .context("enumerate bound proactive claims")?
    {
        entries_seen += 1;
        anyhow::ensure!(
            entries_seen <= MAX_CLAIM_DIRECTORY_ENTRIES,
            "proactive claim directory entry limit exceeded"
        );
        let entry = entry.context("read bound proactive claim directory entry")?;
        let name = entry.file_name();
        let name_text = name
            .to_str()
            .context("proactive claim filename is not UTF-8")?;
        if canonical_claim_temp_name(name_text) {
            let (temp, binding, _) = open_regular_claim(&root, &name)?;
            drop(temp);
            BoundClaimFile::new(Arc::clone(&root), name, binding)
                .remove()
                .context("remove orphaned proactive claim atomic stage")?;
            continue;
        }
        anyhow::ensure!(
            canonical_claim_name(name_text),
            "non-canonical proactive claim filename"
        );
        names.push(name);
        anyhow::ensure!(
            names.len() <= MAX_CLAIMS,
            "proactive claim count limit exceeded"
        );
    }
    names.sort();

    let mut claims = Vec::with_capacity(names.len());
    let mut intent_ids = HashSet::with_capacity(names.len());
    let mut dedup_hashes = HashSet::with_capacity(names.len());
    let mut total_claim_bytes = 0_u64;
    for name in names {
        let display_path = root.display_path.join(&name);
        let (mut file, read_binding, is_private) = open_regular_claim_readonly(&root, &name)?;
        let metadata = file.metadata().context("inspect proactive claim length")?;
        total_claim_bytes = total_claim_bytes
            .checked_add(metadata.len())
            .context("proactive aggregate claim length overflow")?;
        anyhow::ensure!(
            total_claim_bytes <= MAX_TOTAL_CLAIM_BYTES,
            "proactive aggregate claim bytes exceed recovery limit"
        );
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        (&mut file)
            .take(MAX_CLAIM_BYTES + 1)
            .read_to_end(&mut bytes)
            .context("read proactive claim")?;
        anyhow::ensure!(
            bytes.len() as u64 <= MAX_CLAIM_BYTES,
            "proactive claim exceeds read limit"
        );
        let file_name = name
            .to_str()
            .context("proactive claim lost canonical name")?;
        let (claim, converted_bytes): (ProactiveEgressClaim, Option<Vec<u8>>) =
            match serde_json::from_slice(&bytes) {
                Ok(claim) => {
                    anyhow::ensure!(is_private, "proactive claim permissions are not private");
                    (claim, None)
                }
                Err(typed_error) => {
                    let item: ProactiveItem =
                        serde_json::from_slice(&bytes).with_context(|| {
                            format!("decode proactive claim (typed error: {typed_error})")
                        })?;
                    let legacy_digest = legacy_claim_digest(&item);
                    anyhow::ensure!(
                        file_name == format!("{legacy_digest}.claimed"),
                        "legacy proactive claim filename does not bind its dedup key"
                    );
                    if !is_private {
                        make_open_file_private(&file, &display_path)?;
                        after_legacy_acl_migration(&display_path)
                            .context("run post-migration proactive claim identity check")?;
                    }
                    let queue = ProactiveQueue::load_from(&home.join("proactive_queue.json"))?;
                    let queue_generation = queue
                        .peek()
                        .iter()
                        .find(|queued| **queued == item)
                        .and_then(|queued| queue.entry_generation(&queued.dedup_key))
                        .map(str::to_string)
                        .unwrap_or_else(|| {
                            effect_hash(
                                b"proactive-egress-legacy-unbound-v1",
                                item.dedup_key.as_bytes(),
                            )
                        });
                    let target_channel = if item.channel.trim().is_empty() {
                        "local_inbox".to_string()
                    } else {
                        item.channel.trim().to_string()
                    };
                    let mut converted =
                        new_claim(item, &queue_generation, &target_channel, "", now_unix)?;
                    converted.legacy_claim_sha256 = Some(legacy_digest);
                    // The old implementation may already have called transport.
                    // Conversion therefore starts pessimistically Armed and is
                    // completed into authenticated WAL evidence before retirement.
                    converted.phase = ProactiveEgressPhase::Armed;
                    converted.binding_sha256 = binding_hash(&converted);
                    validate_claim(&converted, file_name)?;
                    let converted_bytes = serde_json::to_vec(&converted)
                        .context("encode migrated proactive claim")?;
                    (converted, Some(converted_bytes))
                }
            };
        let removal_binding = crate::skills::store::bind_regular_file_for_removal(
            &root.dir,
            &name,
            &display_path,
            &read_binding,
        )
        .context("bind observed proactive claim removal authority")?;
        let bound_claim = BoundClaimFile::new(Arc::clone(&root), name.clone(), removal_binding);
        if let Some(converted_bytes) = converted_bytes {
            drop(file);
            #[cfg(windows)]
            {
                bound_claim
                    .release_current_for_atomic_replace()
                    .context("release revalidated legacy proactive claim before migration")?;
                // The observation binding is a second live handle to the same
                // legacy generation. Even though it shares delete access,
                // capability-relative legacy FILE_RENAME_INFORMATION cannot
                // replace an opened target. The removal binding above was
                // acquired only after DACL migration and proved equal to this
                // read identity; its final path revalidation is therefore the
                // commit-point proof for both. Drop the read clone in the same
                // synchronous window before publishing, then authenticate and
                // rebind the replacement below before it can become authority.
                drop(read_binding);
            }
            #[cfg(not(windows))]
            bound_claim
                .ensure_current()
                .context("revalidate legacy proactive claim before migration")?;
            crate::skills::store::atomic_write_private_child(
                &root.dir,
                &name,
                &display_path,
                &converted_bytes,
            )
            .context("atomically migrate bound legacy proactive claim")?;
            let rebound = bind_written_claim(Arc::clone(&root), name.clone(), &converted_bytes)?;
            let replacement = rebound
                .removal_binding
                .into_inner()
                .map_err(|_| anyhow::anyhow!("proactive claim removal binding lock poisoned"))?
                .context("migrated proactive claim binding missing")?;
            bound_claim.replace_binding(replacement)?;
        }
        validate_claim(&claim, file_name)?;
        anyhow::ensure!(
            intent_ids.insert(claim.intent_id.clone()),
            "duplicate proactive intent claim"
        );
        anyhow::ensure!(
            dedup_hashes.insert(claim.dedup_sha256.clone()),
            "duplicate proactive dedup claim"
        );
        claims.push((bound_claim, claim));
    }
    Ok(claims)
}

fn intent_frame(claim: &ProactiveEgressClaim) -> ProactiveIntentFrame {
    ProactiveIntentFrame {
        proactive_binding_version: claim.version,
        intent_id: claim.intent_id.clone(),
        binding_sha256: claim.binding_sha256.clone(),
        target_channel: claim.target_channel.clone(),
        recipient_sha256: claim.recipient_sha256.clone(),
        message_sha256: claim.message_sha256.clone(),
        message_bytes: claim.message_bytes,
        item_sha256: claim.item_sha256.clone(),
        dedup_sha256: claim.dedup_sha256.clone(),
        queue_generation: claim.queue_generation.clone(),
        created_at_unix: claim.created_at_unix,
        attempt_deadline_unix: claim.attempt_deadline_unix,
    }
}

fn armed_frame(claim: &ProactiveEgressClaim) -> Result<ProactiveArmedFrame> {
    anyhow::ensure!(
        claim.phase == ProactiveEgressPhase::Armed,
        "cannot authenticate a proactive claim before it is Armed"
    );
    Ok(ProactiveArmedFrame {
        proactive_binding_version: claim.version,
        intent_id: claim.intent_id.clone(),
        prepared_binding_sha256: claim_in_phase(claim, ProactiveEgressPhase::Prepared)
            .binding_sha256,
        armed_binding_sha256: claim.binding_sha256.clone(),
        armed_at_unix: claim.created_at_unix,
    })
}

fn validate_intent_frame(intent: &ProactiveIntentFrame) -> Result<()> {
    anyhow::ensure!(
        matches!(
            intent.proactive_binding_version,
            LEGACY_WAL_BINDING_VERSION | WAL_BINDING_VERSION
        ),
        "unsupported proactive intent binding version"
    );
    match intent.proactive_binding_version {
        LEGACY_WAL_BINDING_VERSION => anyhow::ensure!(
            intent.attempt_deadline_unix.is_none(),
            "legacy proactive intent unexpectedly carries an attempt deadline"
        ),
        WAL_BINDING_VERSION => anyhow::ensure!(
            intent
                .attempt_deadline_unix
                .is_some_and(|deadline| deadline > intent.created_at_unix),
            "v2 proactive intent has an invalid attempt deadline"
        ),
        _ => unreachable!("version was checked above"),
    }
    validate_uuid_v7(&intent.intent_id)?;
    anyhow::ensure!(
        !intent.target_channel.trim().is_empty()
            && intent.target_channel.len() <= MAX_PROACTIVE_CHANNEL_BYTES,
        "invalid proactive intent target channel"
    );
    anyhow::ensure!(
        intent.message_bytes <= MAX_PROACTIVE_BODY_BYTES,
        "proactive intent message length exceeds limit"
    );
    anyhow::ensure!(
        !intent.queue_generation.is_empty() && intent.queue_generation.len() <= 64,
        "invalid proactive intent queue generation"
    );
    for (label, digest) in [
        ("binding", &intent.binding_sha256),
        ("recipient", &intent.recipient_sha256),
        ("message", &intent.message_sha256),
        ("item", &intent.item_sha256),
        ("dedup", &intent.dedup_sha256),
    ] {
        anyhow::ensure!(
            is_sha256_hex(digest),
            "invalid proactive intent {label} digest"
        );
    }
    Ok(())
}

fn validate_armed_frame(armed: &ProactiveArmedFrame) -> Result<()> {
    anyhow::ensure!(
        matches!(
            armed.proactive_binding_version,
            LEGACY_WAL_BINDING_VERSION | WAL_BINDING_VERSION
        ),
        "unsupported proactive Armed binding version"
    );
    validate_uuid_v7(&armed.intent_id)?;
    anyhow::ensure!(
        is_sha256_hex(&armed.prepared_binding_sha256)
            && is_sha256_hex(&armed.armed_binding_sha256)
            && armed.prepared_binding_sha256 != armed.armed_binding_sha256,
        "invalid proactive Armed transition binding"
    );
    Ok(())
}

fn intent_matches_claim(intent: &ProactiveIntentFrame, claim: &ProactiveEgressClaim) -> bool {
    let prepared = claim_in_phase(claim, ProactiveEgressPhase::Prepared);
    intent.proactive_binding_version == claim.version
        && intent.intent_id == claim.intent_id
        && intent.binding_sha256 == prepared.binding_sha256
        && intent.target_channel == claim.target_channel
        && intent.recipient_sha256 == claim.recipient_sha256
        && intent.message_sha256 == claim.message_sha256
        && intent.message_bytes == claim.message_bytes
        && intent.item_sha256 == claim.item_sha256
        && intent.dedup_sha256 == claim.dedup_sha256
        && intent.queue_generation == claim.queue_generation
        && intent.created_at_unix == claim.created_at_unix
        && intent.attempt_deadline_unix == claim.attempt_deadline_unix
}

fn armed_matches_claim(armed: &ProactiveArmedFrame, claim: &ProactiveEgressClaim) -> bool {
    let prepared = claim_in_phase(claim, ProactiveEgressPhase::Prepared);
    let expected_armed = claim_in_phase(claim, ProactiveEgressPhase::Armed);
    claim.phase == ProactiveEgressPhase::Armed
        && armed.proactive_binding_version == claim.version
        && armed.intent_id == claim.intent_id
        && armed.prepared_binding_sha256 == prepared.binding_sha256
        && armed.armed_binding_sha256 == expected_armed.binding_sha256
        && armed.armed_at_unix == claim.created_at_unix
}

fn validate_result_frame(result: &ProactiveResultFrame) -> Result<()> {
    anyhow::ensure!(
        matches!(
            result.proactive_binding_version,
            LEGACY_WAL_BINDING_VERSION | WAL_BINDING_VERSION
        ),
        "unsupported proactive result binding version"
    );
    anyhow::ensure!(
        result.purpose == "proactive",
        "invalid proactive result purpose"
    );
    validate_uuid_v7(&result.intent_id)?;
    anyhow::ensure!(
        is_sha256_hex(&result.binding_sha256),
        "invalid proactive result binding"
    );
    anyhow::ensure!(
        !result.target_channel.trim().is_empty()
            && result.target_channel.len() <= MAX_PROACTIVE_CHANNEL_BYTES,
        "invalid proactive result target channel"
    );
    anyhow::ensure!(
        is_sha256_hex(&result.recipient_sha256),
        "invalid proactive result recipient digest"
    );
    anyhow::ensure!(
        result.message_bytes <= MAX_PROACTIVE_BODY_BYTES,
        "invalid proactive result message length"
    );
    if let Some(hash) = &result.receipt_sha256 {
        anyhow::ensure!(is_sha256_hex(hash), "invalid proactive receipt digest");
    }
    if let Some(hash) = &result.error_sha256 {
        anyhow::ensure!(is_sha256_hex(hash), "invalid proactive error digest");
    }
    let has_receipt = result.receipt_sha256.is_some();
    let has_error = result.error_kind.is_some() || result.error_sha256.is_some();
    anyhow::ensure!(
        has_receipt == (result.receipt_bytes > 0),
        "proactive receipt hash/length mismatch"
    );
    anyhow::ensure!(
        result.error_kind.is_some() == result.error_sha256.is_some()
            && has_error == (result.error_bytes > 0),
        "proactive error kind/hash/length mismatch"
    );
    match result.outcome {
        ProactiveEgressOutcome::Delivered => anyhow::ensure!(
            has_receipt && !has_error,
            "delivered proactive result lacks an exclusive receipt"
        ),
        ProactiveEgressOutcome::TransportError => anyhow::ensure!(
            !has_receipt
                && matches!(
                    result.error_kind.as_deref(),
                    Some("transport" | "deadline_exceeded" | "transport_task_failed")
                ),
            "transport proactive result has invalid evidence"
        ),
        ProactiveEgressOutcome::AuthError => anyhow::ensure!(
            !has_receipt && result.error_kind.as_deref() == Some("auth"),
            "auth proactive result has invalid evidence"
        ),
        ProactiveEgressOutcome::RateLimited => anyhow::ensure!(
            !has_receipt && result.error_kind.as_deref() == Some("rate_limited"),
            "rate-limited proactive result has invalid evidence"
        ),
        ProactiveEgressOutcome::SidecarOnly => anyhow::ensure!(
            !has_receipt && (!has_error || result.error_kind.as_deref() == Some("not_supported")),
            "sidecar-only proactive result has invalid evidence"
        ),
        ProactiveEgressOutcome::AdapterConfigurationError
        | ProactiveEgressOutcome::PolicySuppressed
        | ProactiveEgressOutcome::CrashUnknown
        | ProactiveEgressOutcome::NotAttempted => {
            anyhow::ensure!(
                !has_receipt && !has_error,
                "synthetic proactive result unexpectedly contains transport evidence"
            )
        }
    }
    Ok(())
}

fn scan_authenticated_wal(
    home: &Path,
    wal_segment_path: &Path,
    active_intent_ids: &HashSet<String>,
) -> Result<WalEvidence> {
    scan_wal_evidence(home, wal_segment_path, active_intent_ids, false)
}

fn scan_authenticated_projection_wal(
    home: &Path,
    wal_segment_path: &Path,
    active_intent_ids: &HashSet<String>,
) -> Result<WalEvidence> {
    scan_wal_evidence(home, wal_segment_path, active_intent_ids, true)
}

fn scan_wal_evidence(
    home: &Path,
    wal_segment_path: &Path,
    active_intent_ids: &HashSet<String>,
    authenticated_prefix_only: bool,
) -> Result<WalEvidence> {
    let mut evidence = WalEvidence::default();
    let mut inspect_frame =
        |_: &crate::wal::scan::HomeWalFrameLocation,
         frame: &crate::wal::frame::DecodedFrame<'_>| {
            if frame.header.event_type != EVENT_TYPE_EXTENDED {
                return Ok(());
            }
            let subtype = frame.header.event_subtype;
            if subtype != ExtendedSubtype::ChannelEgressIntent as u8
                && subtype != ExtendedSubtype::ChannelEgressArmed as u8
                && subtype != ExtendedSubtype::ChannelEgressResult as u8
            {
                return Ok(());
            }
            let value: serde_json::Value =
                serde_json::from_slice(frame.payload).context("decode channel egress WAL frame")?;
            // ChannelEgressIntent/Result are shared with the general channel
            // send gate. Only frames carrying this explicit proactive schema
            // discriminator belong to this recovery state machine.
            if subtype != ExtendedSubtype::ChannelEgressArmed as u8
                && value.get("proactive_binding_version").is_none()
            {
                return Ok(());
            }
            let Some(intent_id) = value.get("intent_id").and_then(serde_json::Value::as_str) else {
                anyhow::bail!("proactive WAL frame is missing intent_id");
            };
            if !active_intent_ids.contains(intent_id) {
                return Ok(());
            }
            anyhow::ensure!(
                value
                    .get("proactive_binding_version")
                    .and_then(serde_json::Value::as_u64)
                    .is_some_and(|version| {
                        version == u64::from(LEGACY_WAL_BINDING_VERSION)
                            || version == u64::from(WAL_BINDING_VERSION)
                    }),
                "unsupported proactive WAL binding version"
            );
            if subtype == ExtendedSubtype::ChannelEgressIntent as u8 {
                let intent: ProactiveIntentFrame =
                    serde_json::from_value(value).context("decode proactive intent frame")?;
                validate_intent_frame(&intent)?;
                anyhow::ensure!(
                    evidence
                        .intents
                        .insert(intent.intent_id.clone(), intent)
                        .is_none(),
                    "duplicate proactive intent frame"
                );
            } else if subtype == ExtendedSubtype::ChannelEgressArmed as u8 {
                let armed: ProactiveArmedFrame =
                    serde_json::from_value(value).context("decode proactive Armed frame")?;
                validate_armed_frame(&armed)?;
                anyhow::ensure!(
                    evidence
                        .armed
                        .insert(armed.intent_id.clone(), armed)
                        .is_none(),
                    "duplicate proactive Armed frame"
                );
            } else {
                let result: ProactiveResultFrame =
                    serde_json::from_value(value).context("decode proactive result frame")?;
                validate_result_frame(&result)?;
                anyhow::ensure!(
                    evidence
                        .results
                        .insert(result.intent_id.clone(), result)
                        .is_none(),
                    "duplicate proactive result frame"
                );
            }
            Ok(())
        };
    if authenticated_prefix_only {
        crate::wal::scan::for_each_authenticated_frame_in_existing_home_segment_chain(
            home,
            wal_segment_path,
            crate::wal::scan::supported_home_scan_limits(),
            &mut inspect_frame,
        )
        .context("authenticate marker-confirmed WAL bytes for proactive history")?;
    } else {
        crate::wal::scan::for_each_frame_in_home_segment_chain(
            home,
            wal_segment_path,
            crate::wal::scan::supported_home_scan_limits(),
            &mut inspect_frame,
        )
        .context("authenticate selected WAL chain for proactive recovery")?;
    }
    for intent_id in evidence.results.keys() {
        anyhow::ensure!(
            evidence.intents.contains_key(intent_id),
            "proactive result exists without its intent"
        );
    }
    for (intent_id, armed) in &evidence.armed {
        let intent = evidence
            .intents
            .get(intent_id)
            .context("proactive Armed frame exists without its intent")?;
        anyhow::ensure!(
            armed.prepared_binding_sha256 == intent.binding_sha256
                && armed.armed_at_unix == intent.created_at_unix,
            "proactive Armed frame conflicts with Prepared intent"
        );
    }
    for (intent_id, result) in &evidence.results {
        let intent = &evidence.intents[intent_id];
        let expected_binding = evidence.armed.get(intent_id).map_or_else(
            || &intent.binding_sha256,
            |armed| &armed.armed_binding_sha256,
        );
        anyhow::ensure!(
            result.binding_sha256.as_str() == expected_binding.as_str(),
            "proactive result conflicts with authenticated dispatch phase"
        );
        anyhow::ensure!(
            result.target_channel == intent.target_channel
                && result.recipient_sha256 == intent.recipient_sha256
                && result.message_bytes == intent.message_bytes,
            "proactive result metadata conflicts with authenticated intent"
        );
    }
    Ok(evidence)
}

async fn append_acked_while_lock_survives_cancellation(
    delivery_lock: &std::fs::File,
    writer: &WalWriterHandle,
    header: crate::wal::EventHeaderV2,
    payload: Vec<u8>,
) -> Result<()> {
    let cancellation_lock = delivery_lock
        .try_clone()
        .context("clone proactive delivery lock for WAL append")?;
    let writer = writer.clone();
    tokio::spawn(async move {
        let _cancellation_lock = cancellation_lock;
        writer.append(header, payload).await
    })
    .await
    .context("join cancellation-safe proactive WAL append")?
    .context("durably append proactive WAL frame")?;
    Ok(())
}

async fn append_authenticated_while_lock_survives_cancellation(
    delivery_lock: &std::fs::File,
    writer: &WalWriterHandle,
    header: crate::wal::EventHeaderV2,
    payload: Vec<u8>,
) -> Result<()> {
    let cancellation_lock = delivery_lock
        .try_clone()
        .context("clone proactive delivery lock for authenticated WAL append")?;
    let writer = writer.clone();
    tokio::spawn(async move {
        let _cancellation_lock = cancellation_lock;
        writer.append_authenticated(header, payload).await
    })
    .await
    .context("join cancellation-safe authenticated proactive WAL append")?
    .context("durably append and authenticate proactive WAL frame")?;
    Ok(())
}

async fn append_intent(
    delivery_lock: &std::fs::File,
    writer: &WalWriterHandle,
    claim: &ProactiveEgressClaim,
) -> Result<()> {
    let intent = intent_frame(claim);
    validate_intent_frame(&intent)?;
    let payload = serde_json::to_vec(&intent).context("encode proactive intent")?;
    let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_EXTENDED, &payload)
        .event_subtype(ExtendedSubtype::ChannelEgressIntent as u8)
        .build();
    append_acked_while_lock_survives_cancellation(delivery_lock, writer, header, payload)
        .await
        .context("durably append proactive egress intent")?;
    Ok(())
}

async fn append_armed(
    delivery_lock: &std::fs::File,
    writer: &WalWriterHandle,
    claim: &ProactiveEgressClaim,
) -> Result<()> {
    let armed = armed_frame(claim)?;
    validate_armed_frame(&armed)?;
    let payload = serde_json::to_vec(&armed).context("encode proactive Armed transition")?;
    let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_EXTENDED, &payload)
        .event_subtype(ExtendedSubtype::ChannelEgressArmed as u8)
        .build();
    append_acked_while_lock_survives_cancellation(delivery_lock, writer, header, payload)
        .await
        .context("durably append proactive Armed transition")?;
    Ok(())
}

async fn append_result(
    delivery_lock: &std::fs::File,
    writer: &WalWriterHandle,
    result: &ProactiveResultFrame,
) -> Result<()> {
    validate_result_frame(result)?;
    let payload = serde_json::to_vec(result).context("encode proactive result")?;
    let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_EXTENDED, &payload)
        .event_subtype(ExtendedSubtype::ChannelEgressResult as u8)
        .build();
    append_authenticated_while_lock_survives_cancellation(delivery_lock, writer, header, payload)
        .await
        .context("durably append proactive egress result")?;
    Ok(())
}

fn terminal_result(
    claim: &ProactiveEgressClaim,
    outcome: ProactiveEgressOutcome,
    receipt: Option<&MessageId>,
    error: Option<&ChannelError>,
    completed_at_unix: i64,
) -> ProactiveResultFrame {
    let receipt_bytes = receipt.map_or(0, |message_id| message_id.0.len());
    let receipt_sha256 = receipt
        .map(|message_id| effect_hash(b"proactive-egress-receipt-v1", message_id.0.as_bytes()));
    let (error_kind, error_sha256, error_bytes) = match error {
        Some(error) => {
            let kind = match error {
                ChannelError::Transport(text) if text == "deadline_exceeded" => "deadline_exceeded",
                ChannelError::Transport(text) if text == "transport_task_failed" => {
                    "transport_task_failed"
                }
                ChannelError::Transport(_) => "transport",
                ChannelError::NotSupported { .. } => "not_supported",
                ChannelError::RateLimited { .. } => "rate_limited",
                ChannelError::Auth(_) => "auth",
            };
            let text = error.to_string();
            (
                Some(kind.to_string()),
                Some(effect_hash(b"proactive-egress-error-v1", text.as_bytes())),
                text.len(),
            )
        }
        None => (None, None, 0),
    };
    ProactiveResultFrame {
        proactive_binding_version: claim.version,
        purpose: "proactive".to_string(),
        intent_id: claim.intent_id.clone(),
        binding_sha256: claim.binding_sha256.clone(),
        target_channel: claim.target_channel.clone(),
        recipient_sha256: claim.recipient_sha256.clone(),
        message_bytes: claim.message_bytes,
        outcome,
        receipt_sha256,
        receipt_bytes,
        error_kind,
        error_sha256,
        error_bytes,
        completed_at_unix,
    }
}

fn outcome_for_error(error: &ChannelError) -> ProactiveEgressOutcome {
    match error {
        ChannelError::Transport(_) => ProactiveEgressOutcome::TransportError,
        ChannelError::NotSupported { .. } => ProactiveEgressOutcome::SidecarOnly,
        ChannelError::RateLimited { .. } => ProactiveEgressOutcome::RateLimited,
        ChannelError::Auth(_) => ProactiveEgressOutcome::AuthError,
    }
}

fn verify_result_binding(
    result: &ProactiveResultFrame,
    claim: &ProactiveEgressClaim,
) -> Result<()> {
    anyhow::ensure!(
        result.proactive_binding_version == claim.version
            && result.purpose == "proactive"
            && result.intent_id == claim.intent_id
            && result.binding_sha256 == claim.binding_sha256,
        "proactive result does not match its durable claim"
    );
    anyhow::ensure!(
        result.target_channel == claim.target_channel
            && result.recipient_sha256 == claim.recipient_sha256
            && result.message_bytes == claim.message_bytes,
        "proactive result metadata does not match its durable claim"
    );
    Ok(())
}

fn open_regular_sidecar(path: &Path) -> Result<(std::fs::File, bool)> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path).context("open proactive sidecar")?;
    let metadata = file
        .metadata()
        .context("inspect opened proactive sidecar")?;
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "opened proactive sidecar is not a regular file"
    );
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        anyhow::ensure!(
            metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
            "opened proactive sidecar must not be a reparse point"
        );
    }
    #[cfg(unix)]
    let needs_privacy_migration = {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o077 != 0
    };
    #[cfg(windows)]
    let needs_privacy_migration =
        crate::wal::win_native::verify_private_file_handle(&file).is_err();
    #[cfg(not(any(unix, windows)))]
    let needs_privacy_migration = false;
    Ok((file, needs_privacy_migration))
}

fn read_sidecar_snapshot(path: &Path) -> Result<Option<(Vec<u8>, bool)>> {
    let (mut file, needs_privacy_migration) = match open_regular_sidecar(path) {
        Ok(opened) => opened,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let metadata = file
        .metadata()
        .context("inspect proactive sidecar snapshot length")?;
    anyhow::ensure!(
        metadata.len() <= MAX_SIDECAR_BYTES,
        "proactive sidecar exceeds scan limit"
    );
    let mut body = Vec::with_capacity(metadata.len() as usize);
    (&mut file)
        .take(MAX_SIDECAR_BYTES + 1)
        .read_to_end(&mut body)
        .context("read proactive sidecar snapshot")?;
    anyhow::ensure!(
        body.len() as u64 <= MAX_SIDECAR_BYTES,
        "proactive sidecar exceeds bounded read limit"
    );
    anyhow::ensure!(
        file.metadata()
            .context("recheck proactive sidecar snapshot length")?
            .len()
            == metadata.len(),
        "proactive sidecar changed during snapshot read"
    );
    Ok(Some((body, needs_privacy_migration)))
}

fn validate_current_sidecar_tail(path: &Path) -> Result<()> {
    let Some((body, _)) = read_sidecar_snapshot(path)? else {
        return Ok(());
    };

    if !body.is_empty() && body.last() != Some(&b'\n') {
        let committed = body
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |index| index + 1);
        anyhow::ensure!(
            serde_json::from_slice::<serde_json::Value>(&body[committed..]).is_ok(),
            "proactive sidecar has a torn legacy tail; evidence was preserved at {}",
            path.display()
        );
    }
    Ok(())
}

fn delivery_record(
    claim: &ProactiveEgressClaim,
    result: &ProactiveResultFrame,
    wal_chain_base: &str,
) -> Result<ProactiveDeliveryRecord> {
    anyhow::ensure!(
        crate::wal::scan::canonical_chain_base_segment_name(std::ffi::OsStr::new(wal_chain_base)),
        "proactive history WAL chain locator is not a canonical base segment"
    );
    let prepared = claim_in_phase(claim, ProactiveEgressPhase::Prepared);
    let intent = intent_frame(&prepared);
    let armed = if claim.phase == ProactiveEgressPhase::Armed {
        Some(armed_frame(claim)?)
    } else {
        None
    };
    let record = ProactiveDeliveryRecord {
        version: 1,
        intent_id: claim.intent_id.clone(),
        wal_chain_base: wal_chain_base.to_string(),
        binding_sha256: claim.binding_sha256.clone(),
        recipient_sha256: claim.recipient_sha256.clone(),
        intent_frame_sha256: typed_frame_hash(b"proactive-egress-intent-frame-v1", &intent)?,
        armed_frame_sha256: armed
            .as_ref()
            .map(|frame| typed_frame_hash(b"proactive-egress-armed-frame-v1", frame))
            .transpose()?,
        result_frame_sha256: typed_frame_hash(b"proactive-egress-result-frame-v1", result)?,
        delivered_at_unix: result.completed_at_unix,
        outcome: result.outcome,
        was_failure: claim.item.is_failure,
        target_channel: claim.target_channel.clone(),
        dedup_sha256: claim.dedup_sha256.clone(),
        message_sha256: claim.message_sha256.clone(),
        message_bytes: claim.message_bytes,
        item_sha256: claim.item_sha256.clone(),
        queue_generation: claim.queue_generation.clone(),
        // This current-user-only file is the zero-channel operator inbox. It
        // intentionally retains the message the operator must be able to read;
        // Recipient values, provider receipts and raw error material remain
        // excluded; only the recipient digest required for request binding is
        // retained.
        item: claim.item.clone(),
    };
    validate_delivery_record(&record)?;
    Ok(record)
}

fn rotated_sidecar_uuid(name: &str) -> Option<uuid::Uuid> {
    let token = name
        .strip_prefix("proactive_delivered.")
        .and_then(|value| value.strip_suffix(".jsonl"))?;
    let parsed = uuid::Uuid::parse_str(token).ok()?;
    (parsed.get_version_num() == 7 && parsed.hyphenated().to_string() == token).then_some(parsed)
}

fn rotated_sidecar_name(name: &str) -> bool {
    rotated_sidecar_uuid(name).is_some()
}

fn uuid_v7_unix_millis(value: &uuid::Uuid) -> u64 {
    value.as_bytes()[..6]
        .iter()
        .fold(0u64, |millis, byte| (millis << 8) | u64::from(*byte))
}

fn uuid_v7_with_unix_millis(value: uuid::Uuid, millis: u64) -> Result<uuid::Uuid> {
    const MAX_UUID_V7_UNIX_MILLIS: u64 = (1u64 << 48) - 1;
    anyhow::ensure!(
        millis <= MAX_UUID_V7_UNIX_MILLIS,
        "proactive archive UUIDv7 timestamp space is exhausted"
    );
    let mut bytes = *value.as_bytes();
    for (index, byte) in bytes[..6].iter_mut().enumerate() {
        let shift = (5 - index) * 8;
        *byte = ((millis >> shift) & 0xff) as u8;
    }
    let adjusted = uuid::Uuid::from_bytes(bytes);
    anyhow::ensure!(
        adjusted.get_version_num() == 7,
        "adjusted proactive archive identifier lost UUIDv7 version"
    );
    Ok(adjusted)
}

fn next_rotated_sidecar_path(home: &Path) -> Result<PathBuf> {
    let mut maximum = None::<uuid::Uuid>;
    for entry in std::fs::read_dir(home).context("enumerate proactive archive sequence")? {
        let entry = entry.context("read proactive archive sequence entry")?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(candidate) = rotated_sidecar_uuid(name) else {
            continue;
        };
        if maximum
            .as_ref()
            .is_none_or(|observed| candidate.as_bytes() > observed.as_bytes())
        {
            maximum = Some(candidate);
        }
    }

    let mut next = uuid::Uuid::now_v7();
    if let Some(maximum) = maximum
        && next.as_bytes() <= maximum.as_bytes()
    {
        let next_millis = uuid_v7_unix_millis(&maximum)
            .checked_add(1)
            .context("proactive archive UUIDv7 timestamp overflow")?;
        next = uuid_v7_with_unix_millis(next, next_millis)?;
    }
    Ok(home.join(format!("proactive_delivered.{next}.jsonl")))
}

fn prune_rotated_sidecars(home: &Path) -> Result<()> {
    let mut archives = Vec::new();
    for entry in std::fs::read_dir(home).context("enumerate proactive sidecar archives")? {
        let entry = entry.context("read proactive sidecar archive entry")?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if rotated_sidecar_name(name) {
            archives.push(entry.path());
        }
    }
    archives.sort();
    let remove_count = archives.len().saturating_sub(MAX_ROTATED_SIDECARS);
    for archive in archives.into_iter().take(remove_count) {
        crate::util::atomic_write::durable_remove_file(&archive)
            .with_context(|| format!("prune proactive sidecar archive {}", archive.display()))?;
    }
    Ok(())
}

fn validate_delivery_record(record: &ProactiveDeliveryRecord) -> Result<()> {
    anyhow::ensure!(record.version == 1, "unsupported proactive history version");
    let intent_id = uuid::Uuid::parse_str(&record.intent_id)
        .context("proactive history intent_id is not a UUID")?;
    anyhow::ensure!(
        intent_id.get_version_num() == 7 && intent_id.hyphenated().to_string() == record.intent_id,
        "proactive history intent_id is not canonical UUIDv7"
    );
    anyhow::ensure!(
        is_sha256_hex(&record.binding_sha256)
            && is_sha256_hex(&record.recipient_sha256)
            && is_sha256_hex(&record.intent_frame_sha256)
            && record
                .armed_frame_sha256
                .as_deref()
                .is_none_or(is_sha256_hex)
            && is_sha256_hex(&record.result_frame_sha256)
            && is_sha256_hex(&record.dedup_sha256)
            && is_sha256_hex(&record.message_sha256)
            && is_sha256_hex(&record.item_sha256),
        "proactive history contains a malformed digest"
    );
    anyhow::ensure!(
        crate::wal::scan::canonical_chain_base_segment_name(std::ffi::OsStr::new(
            &record.wal_chain_base
        )),
        "proactive history WAL chain locator is not a canonical base segment"
    );
    anyhow::ensure!(
        !record.queue_generation.is_empty() && record.queue_generation.len() <= 64,
        "proactive history queue generation is invalid"
    );
    anyhow::ensure!(
        !record.target_channel.is_empty()
            && record.target_channel.len() <= MAX_PROACTIVE_CHANNEL_BYTES,
        "proactive history target channel is invalid"
    );
    record
        .item
        .validate()
        .map_err(anyhow::Error::new)
        .context("validate proactive history item")?;
    anyhow::ensure!(
        record.message_bytes == record.item.body.len(),
        "proactive history message length conflicts with the item"
    );
    anyhow::ensure!(
        record.was_failure == record.item.is_failure,
        "proactive history failure marker conflicts with the item"
    );
    anyhow::ensure!(
        record.message_sha256
            == effect_hash(b"proactive-egress-message-v1", record.item.body.as_bytes()),
        "proactive history message digest conflicts with the item"
    );
    anyhow::ensure!(
        record.dedup_sha256
            == effect_hash(
                b"proactive-egress-dedup-v1",
                record.item.dedup_key.as_bytes(),
            ),
        "proactive history dedup digest conflicts with the item"
    );
    let item_bytes = serde_json::to_vec(&record.item).context("encode proactive history item")?;
    anyhow::ensure!(
        record.item_sha256 == effect_hash(b"proactive-egress-item-v1", &item_bytes),
        "proactive history item digest conflicts with the item"
    );
    Ok(())
}

fn read_delivery_records_from(path: &Path) -> Result<Vec<ProactiveDeliveryRecord>> {
    let (mut file, needs_privacy_migration) = open_regular_sidecar(path)?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect proactive history file {}", path.display()))?;
    anyhow::ensure!(
        metadata.len() <= MAX_SIDECAR_BYTES,
        "proactive history file exceeds the bounded read limit: {}",
        path.display()
    );
    let mut body = Vec::with_capacity(metadata.len() as usize);
    (&mut file)
        .take(MAX_SIDECAR_BYTES + 1)
        .read_to_end(&mut body)
        .with_context(|| format!("read proactive history file {}", path.display()))?;
    anyhow::ensure!(
        body.len() as u64 <= MAX_SIDECAR_BYTES,
        "proactive history file grew beyond the bounded read limit: {}",
        path.display()
    );
    anyhow::ensure!(
        file.metadata()
            .with_context(|| format!("recheck proactive history file {}", path.display()))?
            .len()
            == metadata.len(),
        "proactive history file changed during read: {}",
        path.display()
    );

    let lines: Vec<_> = body.split(|byte| *byte == b'\n').collect();
    let mut records = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if line.is_empty() {
            anyhow::ensure!(
                index + 1 == lines.len(),
                "proactive history contains an empty record"
            );
            continue;
        }
        anyhow::ensure!(
            line.len() <= MAX_HISTORY_RECORD_BYTES,
            "proactive history record exceeds the bounded record limit"
        );
        let record = decode_delivery_record_line(line, needs_privacy_migration)
            .with_context(|| format!("decode proactive history record in {}", path.display()))?;
        records.push(record);
    }
    if needs_privacy_migration {
        // A broad modern v1 row is rejected above without mutating its mode or
        // DACL, so a second poll cannot accidentally bless it. Only an entire
        // file that decoded through the explicit legacy schema reaches here.
        // Replace the path atomically with the exact validated bytes under a
        // new private inode/file instead of chmod'ing a potentially mutable
        // broad inode in place.
        drop(file);
        crate::util::atomic_write::atomic_write_private(path, &body).with_context(|| {
            format!(
                "privately replace legacy proactive history: {}",
                path.display()
            )
        })?;
        crate::util::atomic_write::sync_parent_directory_required(path).with_context(|| {
            format!(
                "durably commit legacy history migration: {}",
                path.display()
            )
        })?;
    }
    Ok(records)
}

/// Read the complete private operator-inbox history, including retained
/// rotations, through the same strict record contract used by the writer.
/// Symlinks/reparse leaves, broad permissions, malformed records, duplicate
/// intents and mid-read replacements fail closed instead of fabricating a
/// partial history.
fn delivery_history_paths(home: &Path) -> Result<Vec<PathBuf>> {
    const MAX_HISTORY_FILES: usize = MAX_ROTATION_CRASH_ARCHIVES + 1;

    let entries = match std::fs::read_dir(home) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).context("enumerate proactive history directory"),
    };
    let mut archives = Vec::new();
    let mut current = None;
    for entry in entries {
        let entry = entry.context("read proactive history directory entry")?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name == PROACTIVE_DELIVERED_SIDECAR {
            anyhow::ensure!(
                current.is_none(),
                "duplicate proactive current history path"
            );
            current = Some(entry.path());
        } else if rotated_sidecar_name(name) {
            archives.push(entry.path());
        }
    }
    archives.sort();
    anyhow::ensure!(
        archives.len() <= MAX_ROTATION_CRASH_ARCHIVES,
        "proactive history exceeds the bounded post-crash archive allowance"
    );
    if let Some(current) = current {
        archives.push(current);
    }
    anyhow::ensure!(
        archives.len() <= MAX_HISTORY_FILES,
        "proactive history file count exceeds the bounded limit"
    );
    Ok(archives)
}

/// Cheap change token for long-running GUI consumers. It is only a cache key;
/// records are still accepted exclusively through [`read_delivery_history`].
pub fn delivery_history_revision(home: &Path) -> Result<String> {
    let mut revision = Vec::new();
    for path in delivery_history_paths(home)? {
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .context("proactive history path is not UTF-8")?;
        let metadata = std::fs::symlink_metadata(&path)
            .with_context(|| format!("inspect proactive history path {}", path.display()))?;
        revision.extend_from_slice(&(name.len() as u64).to_be_bytes());
        revision.extend_from_slice(name.as_bytes());
        revision.extend_from_slice(&metadata.len().to_be_bytes());
        let modified = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok());
        revision.extend_from_slice(
            &modified
                .map_or(0, |duration| duration.as_nanos())
                .to_be_bytes(),
        );
        revision.push(u8::from(metadata.file_type().is_file()));
    }
    Ok(effect_hash(
        b"proactive-egress-history-revision-v1",
        &revision,
    ))
}

fn read_delivery_projection_history(home: &Path) -> Result<Vec<ProactiveDeliveryRecord>> {
    const MAX_HISTORY_RECORDS: usize = 65_536;

    let mut records_by_intent = BTreeMap::new();
    for path in delivery_history_paths(home)? {
        for record in read_delivery_records_from(&path)? {
            if let Some(previous) = records_by_intent.get(&record.intent_id) {
                anyhow::ensure!(
                    record.version == 0 && previous == &record,
                    "proactive history contains a duplicate intent"
                );
                continue;
            }
            records_by_intent.insert(record.intent_id.clone(), record);
            anyhow::ensure!(
                records_by_intent.len() <= MAX_HISTORY_RECORDS,
                "proactive history record count exceeds the bounded limit"
            );
        }
    }
    let mut records: Vec<_> = records_by_intent.into_values().collect();
    records.sort_by(|left, right| {
        left.delivered_at_unix
            .cmp(&right.delivered_at_unix)
            .then_with(|| left.intent_id.cmp(&right.intent_id))
    });
    Ok(records)
}

fn verify_delivery_record_against_wal(
    record: &ProactiveDeliveryRecord,
    evidence: &WalEvidence,
) -> Result<()> {
    validate_delivery_record(record)?;
    let intent = evidence
        .intents
        .get(&record.intent_id)
        .context("proactive history has no authenticated WAL Intent")?;
    let result = evidence
        .results
        .get(&record.intent_id)
        .context("proactive history has no authenticated WAL Result")?;
    let armed = evidence.armed.get(&record.intent_id);

    anyhow::ensure!(
        record.intent_frame_sha256
            == typed_frame_hash(b"proactive-egress-intent-frame-v1", intent)?
            && record.result_frame_sha256
                == typed_frame_hash(b"proactive-egress-result-frame-v1", result)?,
        "proactive history frame digest conflicts with authenticated WAL evidence"
    );
    let authenticated_armed_sha256 = armed
        .map(|frame| typed_frame_hash(b"proactive-egress-armed-frame-v1", frame))
        .transpose()?;
    anyhow::ensure!(
        record.armed_frame_sha256 == authenticated_armed_sha256,
        "proactive history Armed digest conflicts with authenticated WAL evidence"
    );
    anyhow::ensure!(
        record.binding_sha256 == result.binding_sha256
            && record.recipient_sha256 == intent.recipient_sha256
            && record.delivered_at_unix == result.completed_at_unix
            && record.outcome == result.outcome
            && record.target_channel == intent.target_channel
            && record.target_channel == result.target_channel
            && record.message_sha256 == intent.message_sha256
            && record.message_bytes == intent.message_bytes
            && record.message_bytes == result.message_bytes
            && record.item_sha256 == intent.item_sha256
            && record.dedup_sha256 == intent.dedup_sha256
            && record.queue_generation == intent.queue_generation,
        "proactive history fields conflict with authenticated WAL request/result"
    );

    let armed_required = match result.outcome {
        ProactiveEgressOutcome::Delivered
        | ProactiveEgressOutcome::TransportError
        | ProactiveEgressOutcome::AuthError
        | ProactiveEgressOutcome::RateLimited
        | ProactiveEgressOutcome::CrashUnknown => true,
        ProactiveEgressOutcome::AdapterConfigurationError
        | ProactiveEgressOutcome::PolicySuppressed
        | ProactiveEgressOutcome::NotAttempted => false,
        ProactiveEgressOutcome::SidecarOnly => result.error_kind.is_some(),
    };
    anyhow::ensure!(
        armed.is_some() == armed_required,
        "proactive history outcome conflicts with authenticated dispatch phase"
    );
    Ok(())
}

/// Read the retained operator inbox and authenticate every modern projection
/// against its exact marker-confirmed WAL Intent/Armed/Result transaction.
/// Legacy pre-contract rows remain visible, but are explicitly labelled
/// `legacy_unverified`; a modern row never falls back to file permissions as
/// proof of authenticity.
pub fn read_delivery_history(home: &Path) -> Result<Vec<ProactiveDeliveryRecord>> {
    let records = read_delivery_projection_history(home)?;
    let mut intents_by_chain: BTreeMap<String, HashSet<String>> = BTreeMap::new();
    for record in &records {
        if !record.is_legacy_unverified() {
            intents_by_chain
                .entry(record.wal_chain_base.clone())
                .or_default()
                .insert(record.intent_id.clone());
        }
    }
    let mut evidence_by_chain = HashMap::new();
    for (chain_base, intent_ids) in &intents_by_chain {
        let base_path = home.join("wal").join(chain_base);
        let evidence = scan_authenticated_projection_wal(home, &base_path, intent_ids)
            .with_context(|| format!("verify proactive history WAL chain `{chain_base}`"))?;
        evidence_by_chain.insert(chain_base.clone(), evidence);
    }
    for record in &records {
        if record.is_legacy_unverified() {
            continue;
        }
        let evidence = evidence_by_chain
            .get(&record.wal_chain_base)
            .context("proactive history lost its selected WAL evidence")?;
        verify_delivery_record_against_wal(record, evidence)?;
    }
    Ok(records)
}

fn rotate_sidecar(home: &Path, path: &Path, validated_bytes: &[u8]) -> Result<()> {
    rotate_sidecar_with_hooks(home, path, validated_bytes, || Ok(()), || Ok(()))
}

fn rotate_sidecar_with_hooks<F, G>(
    home: &Path,
    path: &Path,
    validated_bytes: &[u8],
    before_archive_publish: F,
    after_archive_publish: G,
) -> Result<()>
where
    F: FnOnce() -> Result<()>,
    G: FnOnce() -> Result<()>,
{
    anyhow::ensure!(
        !validated_bytes.is_empty() && validated_bytes.len() as u64 <= MAX_SIDECAR_BYTES,
        "validated proactive sidecar rotation bytes are invalid"
    );
    // Names are strictly monotonic relative to retained archives, even when
    // the wall clock moves backwards. Lexicographic retention can therefore
    // never classify this just-committed sole history copy as the oldest.
    let archive = next_rotated_sidecar_path(home)?;
    before_archive_publish()?;
    // Archive the exact bytes accepted through the original read handle. A
    // path swap before this point can no longer redirect which history is
    // retained. CREATE_NEW is the archive commit point and establishes private
    // permissions before writing any evidence.
    crate::util::atomic_write::write_private_create_new_durable(&archive, validated_bytes)
        .context("durably publish validated proactive sidecar archive")?;
    verify_published_private_bytes(home, &archive, validated_bytes)
        .context("verify validated proactive sidecar archive publication")?;
    after_archive_publish()?;

    // Replace any current-path swap with an empty, private current generation.
    // A crash after the archive commit therefore leaves all accepted history
    // in the archive and a valid empty current file for deterministic replay.
    republish_validated_sidecar_bytes(home, path, b"")
        .context("commit empty proactive sidecar generation after rotation")?;
    prune_rotated_sidecars(home)
}

fn republish_validated_sidecar_bytes(home: &Path, path: &Path, bytes: &[u8]) -> Result<()> {
    republish_validated_sidecar_bytes_with_hook(home, path, bytes, || Ok(()))
}

fn republish_validated_sidecar_bytes_with_hook<F>(
    home: &Path,
    path: &Path,
    bytes: &[u8],
    after_publish: F,
) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_SIDECAR_BYTES,
        "validated proactive sidecar exceeds publication limit"
    );
    crate::util::atomic_write::atomic_write_private(path, bytes)
        .context("atomically republish validated proactive sidecar")?;
    crate::util::atomic_write::sync_parent_directory_required(path)
        .context("durably commit republished proactive sidecar namespace")?;
    after_publish()?;

    verify_published_private_bytes(home, path, bytes)
}

fn verify_published_private_bytes(home: &Path, path: &Path, bytes: &[u8]) -> Result<()> {
    verify_published_bytes(home, path, bytes, true)
}

fn verify_published_bytes(
    home: &Path,
    path: &Path,
    bytes: &[u8],
    require_private: bool,
) -> Result<()> {
    let directory = cap_std::fs::Dir::open_ambient_dir(home, cap_std::ambient_authority())
        .context("open proactive home for sidecar publication proof")?;
    let name = path
        .file_name()
        .context("published proactive sidecar path has no file name")?;
    let (file, binding) = crate::skills::store::open_bound_regular_file(&directory, name, path)
        .context("bind republished proactive sidecar identity")?;
    let mut file = file.into_std();
    let metadata = file
        .metadata()
        .context("inspect republished proactive sidecar")?;
    anyhow::ensure!(
        metadata.len() == bytes.len() as u64,
        "republished proactive sidecar has an unexpected length"
    );
    #[cfg(unix)]
    if require_private {
        use std::os::unix::fs::PermissionsExt as _;
        anyhow::ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "republished proactive sidecar permissions are not private"
        );
    }
    #[cfg(windows)]
    if require_private {
        crate::wal::win_native::verify_private_file_handle(&file)
            .context("verify republished proactive sidecar DACL")?;
    }
    #[cfg(not(any(unix, windows)))]
    let _ = require_private;

    let mut observed = Vec::with_capacity(bytes.len());
    (&mut file)
        .take(MAX_SIDECAR_BYTES + 1)
        .read_to_end(&mut observed)
        .context("read back republished proactive sidecar")?;
    anyhow::ensure!(
        observed == bytes,
        "republished proactive sidecar changed after atomic publication"
    );
    anyhow::ensure!(
        file.metadata()
            .context("recheck republished proactive sidecar length")?
            .len()
            == metadata.len(),
        "republished proactive sidecar changed during read-back"
    );
    anyhow::ensure!(
        binding.matches_regular_file_child_readonly(&directory, name, path)?,
        "republished proactive sidecar namespace identity changed during proof"
    );
    Ok(())
}

fn reconcile_interrupted_sidecar_rotation(home: &Path, current: &Path) -> Result<()> {
    let Some((current_bytes, current_needs_privacy_migration)) = read_sidecar_snapshot(current)?
    else {
        return Ok(());
    };
    if current_bytes.is_empty() {
        return Ok(());
    }

    let mut matching_archive = None;
    for archive in delivery_history_paths(home)? {
        if archive == current {
            continue;
        }
        let Some((archive_bytes, archive_needs_privacy_migration)) =
            read_sidecar_snapshot(&archive)?
        else {
            continue;
        };
        if archive_bytes != current_bytes {
            continue;
        }
        anyhow::ensure!(
            !archive_needs_privacy_migration,
            "interrupted proactive rotation archive is not private"
        );
        if current_needs_privacy_migration {
            validate_strict_legacy_snapshot(&current_bytes)
                .context("validate broad legacy current before rotation reconciliation")?;
            verify_published_bytes(home, current, &current_bytes, false)
                .context("bind broad legacy current before rotation reconciliation")?;
        } else {
            verify_published_private_bytes(home, current, &current_bytes)
                .context("bind current proactive sidecar before rotation reconciliation")?;
        }
        verify_published_private_bytes(home, &archive, &current_bytes)
            .context("bind matching proactive archive before rotation reconciliation")?;
        matching_archive = Some(archive);
        break;
    }

    if matching_archive.is_some() {
        // The only accepted recovery shape is whole-file byte identity between
        // a private, bound current file and a private, bound durable archive.
        // Keep the archive as the sole history copy and finish the interrupted
        // empty-current commit before duplicate-intent evaluation.
        republish_validated_sidecar_bytes(home, current, b"")
            .context("reconcile interrupted proactive sidecar rotation")?;
    }
    Ok(())
}

fn archived_delivery_record_matches(
    home: &Path,
    expected: &ProactiveDeliveryRecord,
) -> Result<bool> {
    let mut observed_intents: BTreeMap<String, ProactiveDeliveryRecord> = BTreeMap::new();
    let mut archived_match = false;
    for path in delivery_history_paths(home)? {
        let is_current =
            path.file_name().and_then(|name| name.to_str()) == Some(PROACTIVE_DELIVERED_SIDECAR);
        for observed in read_delivery_records_from(&path)? {
            if let Some(previous) = observed_intents.get(observed.intent_id()) {
                anyhow::ensure!(
                    observed.is_legacy_unverified() && previous == &observed,
                    "proactive history archive contains a duplicate or conflicting intent"
                );
            } else {
                observed_intents.insert(observed.intent_id().to_string(), observed.clone());
            }
            if observed.intent_id() == expected.intent_id() {
                anyhow::ensure!(
                    &observed == expected,
                    "proactive history contains a conflicting projection"
                );
                archived_match |= !is_current;
            }
        }
    }
    Ok(archived_match)
}

fn append_delivery_record_once(
    home: &Path,
    wal_segment_path: &Path,
    claim: &ProactiveEgressClaim,
    result: &ProactiveResultFrame,
) -> Result<()> {
    let path = home.join(PROACTIVE_DELIVERED_SIDECAR);
    // Validate the only legacy crash shape before archive pruning or replay.
    // An incomplete suffix is evidence and must block all projection mutation
    // with the same explicit operator-facing error as the local decode path.
    validate_current_sidecar_tail(&path)?;
    reconcile_interrupted_sidecar_rotation(home, &path)?;
    // Heal a crash after archive publication but before retention pruning on
    // every serialized projection, even when the current file is still small.
    prune_rotated_sidecars(home)?;
    let wal_chain_base = canonical_wal_chain_base_name(home, wal_segment_path)?;
    let expected = delivery_record(claim, result, &wal_chain_base)?;
    if archived_delivery_record_matches(home, &expected)? {
        return Ok(());
    }
    let record = serde_json::to_vec(&expected).context("encode proactive sidecar record")?;
    anyhow::ensure!(
        record.len() <= MAX_HISTORY_RECORD_BYTES,
        "proactive sidecar record exceeds the bounded record limit"
    );
    let (mut file, needs_privacy_migration) = match open_regular_sidecar(&path) {
        Ok(opened) => opened,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            crate::util::atomic_write::write_private_create_new_durable(&path, b"")?;
            open_regular_sidecar(&path)?
        }
        Err(error) => return Err(error),
    };
    let metadata = file
        .metadata()
        .context("inspect proactive sidecar length")?;
    anyhow::ensure!(
        metadata.len() <= MAX_SIDECAR_BYTES,
        "proactive sidecar exceeds scan limit"
    );
    let mut existing = String::with_capacity(metadata.len() as usize);
    (&mut file)
        .take(MAX_SIDECAR_BYTES + 1)
        .read_to_string(&mut existing)
        .context("read proactive sidecar")?;
    anyhow::ensure!(
        existing.len() as u64 <= MAX_SIDECAR_BYTES,
        "proactive sidecar exceeds bounded read limit"
    );
    let mut repaired_legacy_tail = false;
    if !existing.is_empty() && !existing.ends_with('\n') {
        // The superseded writer appended directly and could crash between JSON
        // bytes and the newline. The current writer is whole-file atomic, so a
        // non-terminated suffix is legacy derived state. A complete JSON value
        // can be normalized by adding the missing delimiter. An incomplete
        // value is evidence, not disposable garbage: leave the file byte-for-
        // byte intact and fail closed for operator recovery.
        let committed = existing.rfind('\n').map_or(0, |index| index + 1);
        let suffix = &existing[committed..];
        anyhow::ensure!(
            serde_json::from_str::<serde_json::Value>(suffix).is_ok(),
            "proactive sidecar has a torn legacy tail; evidence was preserved at {}",
            path.display()
        );
        existing.push('\n');
        repaired_legacy_tail = true;
    }
    let mut matching_record = false;
    let mut observed_intents: BTreeMap<String, ProactiveDeliveryRecord> = BTreeMap::new();
    for line in existing.lines() {
        anyhow::ensure!(
            !line.trim().is_empty(),
            "proactive sidecar contains an empty record"
        );
        let observed = decode_delivery_record_line(line.as_bytes(), needs_privacy_migration)
            .context("decode typed proactive sidecar record")?;
        if let Some(previous) = observed_intents.get(observed.intent_id()) {
            anyhow::ensure!(
                observed.is_legacy_unverified() && previous == &observed,
                "proactive sidecar contains duplicate or conflicting intent records"
            );
        } else {
            observed_intents.insert(observed.intent_id().to_string(), observed.clone());
        }
        if observed.intent_id() == claim.intent_id {
            anyhow::ensure!(
                observed == expected,
                "proactive sidecar intent has a conflicting projection"
            );
            matching_record = true;
        }
    }
    if matching_record && !needs_privacy_migration && !repaired_legacy_tail {
        // Never accept a path that merely matched an earlier read handle. The
        // delivery lock serialises cooperating writers; atomically republish
        // the exact validated bytes, commit the namespace, then bind and read
        // back the currently visible object before settling other projections.
        drop(file);
        republish_validated_sidecar_bytes(home, &path, existing.as_bytes())?;
        return Ok(());
    }
    let mut replacement = existing.into_bytes();
    if !matching_record {
        let projected_len = replacement
            .len()
            .checked_add(record.len())
            .and_then(|length| length.checked_add(1))
            .context("proactive sidecar length overflow")?;
        if projected_len as u64 > SIDECAR_ROTATE_BYTES && !replacement.is_empty() {
            drop(file);
            rotate_sidecar(home, &path, &replacement)?;
            replacement.clear();
        } else {
            anyhow::ensure!(
                file.metadata()
                    .context("recheck proactive sidecar length before replacement")?
                    .len()
                    == metadata.len(),
                "proactive sidecar changed during locked scan"
            );
            drop(file);
        }
        replacement.extend_from_slice(&record);
        replacement.push(b'\n');
    } else {
        drop(file);
    }
    crate::util::atomic_write::atomic_write_private(&path, &replacement)
        .context("atomically replace proactive sidecar projection")?;
    crate::util::atomic_write::sync_parent_directory_required(&path)
        .context("durably commit proactive sidecar projection")?;
    Ok(())
}

fn cron_status(outcome: ProactiveEgressOutcome) -> crate::cron::state::DeliveryStatus {
    match outcome {
        ProactiveEgressOutcome::Delivered => crate::cron::state::DeliveryStatus::Delivered,
        ProactiveEgressOutcome::SidecarOnly => crate::cron::state::DeliveryStatus::SidecarOnly,
        ProactiveEgressOutcome::PolicySuppressed => crate::cron::state::DeliveryStatus::Skipped,
        ProactiveEgressOutcome::NotAttempted => crate::cron::state::DeliveryStatus::Skipped,
        ProactiveEgressOutcome::CrashUnknown => crate::cron::state::DeliveryStatus::CrashUnknown,
        ProactiveEgressOutcome::TransportError
        | ProactiveEgressOutcome::AuthError
        | ProactiveEgressOutcome::RateLimited
        | ProactiveEgressOutcome::AdapterConfigurationError => {
            crate::cron::state::DeliveryStatus::Failed
        }
    }
}

fn apply_projections(
    home: &Path,
    wal_segment_path: &Path,
    claim_file: BoundClaimFile,
    claim: &ProactiveEgressClaim,
    result: &ProactiveResultFrame,
) -> Result<()> {
    verify_result_binding(result, claim)?;
    claim_file
        .ensure_current()
        .context("revalidate bound proactive claim before projections")?;
    append_delivery_record_once(home, wal_segment_path, claim, result)?;
    crate::cron::state::update_announce_result_once(
        home,
        &claim.item.dedup_key,
        &claim.intent_id,
        cron_status(result.outcome),
    )
    .context("persist idempotent Cron proactive result")?;
    if result.outcome != ProactiveEgressOutcome::NotAttempted {
        let queue_path = home.join("proactive_queue.json");
        ProactiveQueue::modify(&queue_path, |queue| {
            queue.settle_egress_once(
                &claim.intent_id,
                &claim.item.dedup_key,
                &claim.queue_generation,
                result.completed_at_unix,
            );
            // Even an already-present tombstone is rewritten through the
            // strict parent-sync boundary. A prior rename may have landed but
            // reported a failed directory fsync; absence of a logical change
            // is not proof that its namespace commit is durable.
            (true, ())
        })
        .context("settle proactive queue result exactly once")?;
    }
    claim_file
        .remove()
        .context("durably remove settled proactive claim")?;
    let queue_path = home.join("proactive_queue.json");
    if queue_path.exists() {
        ProactiveQueue::modify(&queue_path, |queue| {
            let changed = queue.forget_settled_egress_intent(&claim.intent_id);
            (changed, ())
        })
        .context("clean tombstone after durable proactive claim removal")?;
    }
    Ok(())
}

async fn apply_projections_blocking(
    delivery_lock: &std::fs::File,
    home: &Path,
    wal_segment_path: &Path,
    claim_file: BoundClaimFile,
    claim: &ProactiveEgressClaim,
    result: &ProactiveResultFrame,
) -> Result<()> {
    let cancellation_lock = delivery_lock
        .try_clone()
        .context("clone proactive delivery lock for projections")?;
    let home = home.to_path_buf();
    let wal_segment_path = wal_segment_path.to_path_buf();
    let claim = claim.clone();
    let result = result.clone();
    tokio::task::spawn_blocking(move || {
        let _cancellation_lock = cancellation_lock;
        apply_projections(&home, &wal_segment_path, claim_file, &claim, &result)
    })
    .await
    .context("join proactive projection transaction")?
}

async fn persist_prepared_claim(
    delivery_lock: &std::fs::File,
    home: &Path,
    claim: &ProactiveEgressClaim,
) -> Result<BoundClaimFile> {
    let cancellation_lock = delivery_lock
        .try_clone()
        .context("clone proactive delivery lock for Prepared claim")?;
    let home = home.to_path_buf();
    let claim = claim.clone();
    tokio::task::spawn_blocking(move || {
        let _cancellation_lock = cancellation_lock;
        let claim_root = ensure_claim_directory(&home)?;
        let claim_name = claim_name(&claim);
        let name = OsString::from(&claim_name);
        let claim_path = claim_root.display_path.join(&name);
        validate_claim(&claim, &claim_name)?;
        let prepared = serde_json::to_vec(&claim).context("encode Prepared proactive claim")?;
        crate::skills::store::atomic_write_private_child_create_new(
            &claim_root.dir,
            &name,
            &claim_path,
            &prepared,
        )
        .context("durably publish capability-bound Prepared proactive claim")?;
        bind_written_claim(claim_root, name, &prepared)
            .context("bind published Prepared proactive claim identity")
    })
    .await
    .context("join Prepared proactive claim persistence")?
}

async fn persist_armed_claim(
    delivery_lock: &std::fs::File,
    claim_file: &BoundClaimFile,
    claim: &ProactiveEgressClaim,
) -> Result<()> {
    let cancellation_lock = delivery_lock
        .try_clone()
        .context("clone proactive delivery lock for Armed claim")?;
    let claim = claim.clone();
    let root = Arc::clone(&claim_file.root);
    let name = claim_file.name.clone();
    let display_path = claim_file.display_path.clone();
    #[cfg(windows)]
    claim_file
        .release_current_for_atomic_replace()
        .context("release revalidated Prepared proactive claim before arming")?;
    #[cfg(not(windows))]
    claim_file
        .ensure_current()
        .context("revalidate Prepared proactive claim before arming")?;
    tokio::task::spawn_blocking(move || {
        let _cancellation_lock = cancellation_lock;
        let armed = serde_json::to_vec(&claim).context("encode Armed proactive claim")?;
        crate::skills::store::atomic_write_private_child(&root.dir, &name, &display_path, &armed)
            .context("durably arm capability-bound proactive claim")?;
        let rebound = bind_written_claim(root, name, &armed)?;
        rebound
            .removal_binding
            .into_inner()
            .map_err(|_| anyhow::anyhow!("proactive claim removal binding lock poisoned"))?
            .context("Armed proactive claim binding missing")
    })
    .await
    .context("join Armed proactive claim persistence")?
    .and_then(|binding| claim_file.replace_binding(binding))
}

async fn queue_generation_matches(
    delivery_lock: &std::fs::File,
    home: &Path,
    dedup_key: &str,
    queue_generation: &str,
) -> Result<bool> {
    let cancellation_lock = delivery_lock
        .try_clone()
        .context("clone proactive delivery lock for queue read")?;
    let queue_path = home.join("proactive_queue.json");
    let dedup_key = dedup_key.to_string();
    let queue_generation = queue_generation.to_string();
    tokio::task::spawn_blocking(move || {
        let _cancellation_lock = cancellation_lock;
        ProactiveQueue::modify(&queue_path, |fresh| {
            (
                false,
                fresh.entry_generation(&dedup_key) == Some(queue_generation.as_str()),
            )
        })
    })
    .await
    .context("join proactive queue generation read")?
}

/// Detect an already-admitted, still-live v2 attempt while the caller owns the
/// process-wide admission lock. This is intentionally dedup based: a restart
/// must not turn an authenticated in-flight transport into a second provider
/// send merely because its original task no longer exists in this process.
async fn has_unexpired_inflight_dedup(
    delivery_lock: &std::fs::File,
    home: &Path,
    dedup_sha256: &str,
    now_unix: i64,
) -> Result<bool> {
    let cancellation_lock = delivery_lock
        .try_clone()
        .context("clone proactive delivery lock for in-flight dedup scan")?;
    let home = home.to_path_buf();
    let dedup_sha256 = dedup_sha256.to_string();
    tokio::task::spawn_blocking(move || {
        let _cancellation_lock = cancellation_lock;
        for (claim_file, claim) in read_claims(&home, now_unix)? {
            if claim.dedup_sha256 != dedup_sha256
                || claim.phase != ProactiveEgressPhase::Armed
                || claim.version != CLAIM_VERSION
            {
                continue;
            }
            // Same-process flock/LockFileEx reentrancy differs by platform,
            // so retain the local gate as well as the OS lease.
            if transport_is_locally_active(&claim.intent_id) {
                return Ok::<_, anyhow::Error>(true);
            }
            match ArmedClaimLease::try_acquire(&claim_file, &claim)? {
                // A different process holds the exact Armed claim lease. Its
                // monotonic provider budget is authoritative even if this
                // observer's wall clock has jumped past the persisted UTC
                // deadline, so the dedup claim must remain in-flight.
                ArmedClaimLeaseProbe::Busy => return Ok(true),
                ArmedClaimLeaseProbe::Acquired(_lease) => {
                    if claim
                        .attempt_deadline_unix
                        .is_some_and(|deadline| now_unix < deadline)
                    {
                        return Ok(true);
                    }
                }
            }
        }
        Ok::<_, anyhow::Error>(false)
    })
    .await
    .context("join proactive in-flight dedup scan")?
}

fn deadline_after(now_unix: i64, timeout: Duration) -> Result<i64> {
    anyhow::ensure!(
        !timeout.is_zero(),
        "proactive delivery attempt timeout must be non-zero"
    );
    let seconds = timeout
        .as_secs()
        .checked_add(u64::from(timeout.subsec_nanos() != 0))
        .context("proactive delivery attempt timeout overflow")?;
    anyhow::ensure!(
        (crate::config::automation::ProactiveConfig::MIN_DELIVERY_ATTEMPT_TIMEOUT_SECS
            ..=crate::config::automation::ProactiveConfig::MAX_DELIVERY_ATTEMPT_TIMEOUT_SECS)
            .contains(&seconds),
        "proactive delivery attempt timeout is outside the configured safety bounds"
    );
    let seconds =
        i64::try_from(seconds).context("proactive delivery attempt timeout is too large")?;
    now_unix
        .checked_add(seconds)
        .context("proactive delivery attempt deadline overflow")
}

/// Derive the wall-clock share of an attempt budget from one admission sample.
/// The persisted deadline is second-granular. Recovery treats equality as
/// expired, while live provider I/O uses this subsecond remainder so it never
/// exceeds the configured timeout merely because the WAL stores whole Unix
/// seconds.
fn wall_budget_from_admission_sample(
    deadline_unix: i64,
    sample: chrono::DateTime<chrono::Utc>,
) -> Result<Duration> {
    let seconds = deadline_unix
        .checked_sub(sample.timestamp())
        .context("proactive attempt wall deadline subtraction overflow")?;
    anyhow::ensure!(
        seconds > 0,
        "proactive attempt deadline expired at admission"
    );
    let nanos = sample.timestamp_subsec_nanos();
    if nanos == 0 {
        return Ok(Duration::from_secs(
            u64::try_from(seconds).context("proactive attempt wall budget overflow")?,
        ));
    }
    Duration::from_secs(
        u64::try_from(seconds - 1).context("proactive attempt wall budget overflow")?,
    )
    .checked_add(Duration::from_nanos(u64::from(1_000_000_000 - nanos)))
    .context("proactive attempt wall budget overflow")
}

fn new_claim(
    item: ProactiveItem,
    queue_generation: &str,
    target_channel: &str,
    transport_recipient: &str,
    now_unix: i64,
) -> Result<ProactiveEgressClaim> {
    new_claim_with_deadline(
        item,
        queue_generation,
        target_channel,
        transport_recipient,
        now_unix,
        deadline_after(now_unix, DEFAULT_DELIVERY_ATTEMPT_TIMEOUT)?,
    )
}

fn new_claim_with_deadline(
    item: ProactiveItem,
    queue_generation: &str,
    target_channel: &str,
    transport_recipient: &str,
    now_unix: i64,
    attempt_deadline_unix: i64,
) -> Result<ProactiveEgressClaim> {
    item.validate()
        .map_err(anyhow::Error::new)
        .context("validate proactive item before claim")?;
    anyhow::ensure!(
        !target_channel.trim().is_empty() && target_channel.len() <= MAX_PROACTIVE_CHANNEL_BYTES,
        "proactive claim target channel is invalid"
    );
    let item_bytes = serde_json::to_vec(&item).context("encode proactive item binding")?;
    let mut claim = ProactiveEgressClaim {
        version: CLAIM_VERSION,
        phase: ProactiveEgressPhase::Prepared,
        intent_id: uuid::Uuid::now_v7().to_string(),
        message_bytes: item.body.len(),
        message_sha256: effect_hash(b"proactive-egress-message-v1", item.body.as_bytes()),
        item_sha256: effect_hash(b"proactive-egress-item-v1", &item_bytes),
        dedup_sha256: effect_hash(b"proactive-egress-dedup-v1", item.dedup_key.as_bytes()),
        queue_generation: queue_generation.to_string(),
        legacy_claim_sha256: None,
        recipient_sha256: effect_hash(
            b"proactive-egress-recipient-v1",
            transport_recipient.as_bytes(),
        ),
        binding_sha256: String::new(),
        item,
        target_channel: target_channel.to_string(),
        created_at_unix: now_unix,
        attempt_deadline_unix: Some(attempt_deadline_unix),
    };
    claim.binding_sha256 = binding_hash(&claim);
    Ok(claim)
}

async fn acquire_delivery_lock(home: &Path) -> Result<std::fs::File> {
    let lock_path = home.join(PROACTIVE_DELIVERY_LOCK_FILE);
    tokio::task::spawn_blocking(move || {
        crate::util::locked_file::lock_file_blocking(&lock_path, "proactive delivery")
    })
    .await
    .context("join proactive delivery lock acquisition")?
}

async fn recover_pending_claims_locked(
    home: &Path,
    wal_segment_path: &Path,
    writer: &WalWriterHandle,
    delivery_lock: &std::fs::File,
    now_unix: i64,
) -> Result<usize> {
    reap_cancelled_transport_attempts()
        .await
        .context("reap cancelled proactive transport attempts before recovery")?;
    let scan_lock = delivery_lock
        .try_clone()
        .context("clone proactive delivery lock for recovery scan")?;
    let scan_home = home.to_path_buf();
    let scan_segment = wal_segment_path.to_path_buf();
    let (claims, evidence) = tokio::task::spawn_blocking(move || {
        let _scan_lock = scan_lock;
        let claims = read_claims(&scan_home, now_unix)?;
        let evidence = if claims.is_empty() {
            // A crash after durable claim deletion but before the final queue
            // cleanup can leave a tombstone with no remaining replay purpose.
            // Claims-empty is the only safe global GC proof.
            let queue_path = scan_home.join("proactive_queue.json");
            ProactiveQueue::modify(&queue_path, |queue| {
                let changed = queue.clear_settled_egress_intents();
                (changed, ())
            })?;
            WalEvidence::default()
        } else {
            let active_intent_ids = claims
                .iter()
                .map(|(_, claim)| claim.intent_id.clone())
                .collect();
            scan_authenticated_wal(&scan_home, &scan_segment, &active_intent_ids)?
        };
        Ok::<_, anyhow::Error>((claims, evidence))
    })
    .await
    .context("join proactive claim/WAL recovery scan")??;
    if claims.is_empty() {
        return Ok(0);
    }
    let mut recovered = 0usize;
    for (claim_file, claim) in claims {
        let intent = evidence.intents.get(&claim.intent_id);
        let armed = evidence.armed.get(&claim.intent_id);
        let result = evidence.results.get(&claim.intent_id);
        if claim.legacy_claim_sha256.is_some() {
            anyhow::ensure!(
                claim.phase == ProactiveEgressPhase::Armed,
                "converted legacy proactive claim is not pessimistically Armed"
            );
            if let Some(intent) = intent {
                anyhow::ensure!(
                    intent_matches_claim(intent, &claim),
                    "legacy proactive intent conflicts with converted claim binding"
                );
            }
            if intent.is_none() {
                let prepared = claim_in_phase(&claim, ProactiveEgressPhase::Prepared);
                append_intent(delivery_lock, writer, &prepared).await?;
                append_armed(delivery_lock, writer, &claim).await?;
                let terminal = terminal_result(
                    &claim,
                    ProactiveEgressOutcome::CrashUnknown,
                    None,
                    None,
                    now_unix,
                );
                append_result(delivery_lock, writer, &terminal).await?;
                apply_projections_blocking(
                    delivery_lock,
                    home,
                    wal_segment_path,
                    claim_file,
                    &claim,
                    &terminal,
                )
                .await?;
                recovered += 1;
                continue;
            }
            if armed.is_none() && result.is_none() {
                append_armed(delivery_lock, writer, &claim).await?;
                let terminal = terminal_result(
                    &claim,
                    ProactiveEgressOutcome::CrashUnknown,
                    None,
                    None,
                    now_unix,
                );
                append_result(delivery_lock, writer, &terminal).await?;
                apply_projections_blocking(
                    delivery_lock,
                    home,
                    wal_segment_path,
                    claim_file,
                    &claim,
                    &terminal,
                )
                .await?;
                recovered += 1;
                continue;
            }
        }
        claim_file
            .ensure_current()
            .context("revalidate recovered proactive claim before WAL reconciliation")?;
        if let Some(intent) = intent {
            anyhow::ensure!(
                intent_matches_claim(intent, &claim),
                "proactive intent conflicts with claim binding"
            );
        }
        if let Some(armed) = armed {
            anyhow::ensure!(
                armed_matches_claim(armed, &claim),
                "proactive Armed proof conflicts with durable claim phase or binding"
            );
        }
        if transport_is_locally_active(&claim.intent_id) {
            // A same-process egress task has retained ownership of this exact
            // provider future or its cancelled JoinHandle. Do not reconcile
            // the claim—even at wall-clock expiry—until that ownership is
            // joined/reaped; otherwise a cancellation racing recovery could
            // remove the sole dedup authority behind live I/O.
            continue;
        }
        // A different process may own a monotonic-live provider future while
        // this process observes a wall-clock jump. Probe the exact, bound
        // Armed inode before applying any v2 expiry rule: Busy means that
        // process still owns the attempt, regardless of `now_unix`.
        let armed_claim_lease = if claim.version == CLAIM_VERSION
            && claim.phase == ProactiveEgressPhase::Armed
            && intent.is_some()
            && armed.is_some()
            && result.is_none()
        {
            match ArmedClaimLease::try_acquire(&claim_file, &claim)? {
                ArmedClaimLeaseProbe::Busy => continue,
                ArmedClaimLeaseProbe::Acquired(lease) => Some(lease),
            }
        } else {
            None
        };
        match (intent, armed, result) {
            (None, None, None) if claim.phase == ProactiveEgressPhase::Prepared => {
                let remove_lock = delivery_lock
                    .try_clone()
                    .context("clone proactive delivery lock for claim removal")?;
                tokio::task::spawn_blocking(move || {
                    let _remove_lock = remove_lock;
                    claim_file.remove()
                })
                .await
                .context("join unadmitted Prepared claim removal")?
                .context("remove unadmitted Prepared proactive claim")?;
            }
            (Some(_), None, None) => {
                // Even if the private file reached Armed, transport was not
                // permitted before the authenticated Armed ACK. Settle only
                // the attempt record; the queue item remains retryable.
                let prepared = claim_in_phase(&claim, ProactiveEgressPhase::Prepared);
                let result = terminal_result(
                    &prepared,
                    ProactiveEgressOutcome::NotAttempted,
                    None,
                    None,
                    now_unix,
                );
                append_result(delivery_lock, writer, &result).await?;
                apply_projections_blocking(
                    delivery_lock,
                    home,
                    wal_segment_path,
                    claim_file,
                    &prepared,
                    &result,
                )
                .await?;
            }
            (Some(_), None, Some(result)) => {
                let prepared = claim_in_phase(&claim, ProactiveEgressPhase::Prepared);
                apply_projections_blocking(
                    delivery_lock,
                    home,
                    wal_segment_path,
                    claim_file,
                    &prepared,
                    result,
                )
                .await?;
            }
            (Some(_), Some(_), None)
                if claim.version == CLAIM_VERSION
                    && claim
                        .attempt_deadline_unix
                        .is_some_and(|deadline| now_unix < deadline) =>
            {
                // This is a v2 transport that was durably admitted but whose
                // bounded attempt can still be live in another dispatcher.
                // Keep its exact dedup claim instead of fabricating a retry or
                // a terminal answer. A later recovery at/after the immutable
                // deadline will settle the uncertainty once.
                continue;
            }
            (Some(_), Some(_), None) => {
                // v1 has no authenticated absolute deadline, and an expired
                // v2 attempt can no longer be safely treated as in-flight.
                // Neither is re-sent: both become visible CrashUnknown.
                if let Some(lease) = armed_claim_lease.as_ref() {
                    lease
                        .validate_claim(&claim)
                        .context("revalidate proactive Armed claim lease before CrashUnknown")?;
                }
                let result = terminal_result(
                    &claim,
                    ProactiveEgressOutcome::CrashUnknown,
                    None,
                    None,
                    now_unix,
                );
                append_result(delivery_lock, writer, &result).await?;
                // The Result ACK is now durable authority. Drop the exact
                // lease before a Windows deletion/projection path needs its
                // mutation handle, but never before this acknowledgement.
                drop(armed_claim_lease);
                apply_projections_blocking(
                    delivery_lock,
                    home,
                    wal_segment_path,
                    claim_file,
                    &claim,
                    &result,
                )
                .await?;
            }
            (Some(_), Some(_), Some(result)) => {
                apply_projections_blocking(
                    delivery_lock,
                    home,
                    wal_segment_path,
                    claim_file,
                    &claim,
                    result,
                )
                .await?;
            }
            (None, _, Some(_)) => {
                anyhow::bail!("proactive claim has result without authenticated intent")
            }
            (None, Some(_), None) => {
                anyhow::bail!("proactive claim has Armed proof without authenticated intent")
            }
            (None, None, None) => {
                anyhow::bail!("Armed proactive claim has no authenticated intent")
            }
        }
        recovered += 1;
    }
    Ok(recovered)
}

/// Reconcile every durable claim before config, enabled, quiet-hours, idle or
/// routing gates are allowed to make a new delivery decision.
pub(crate) async fn recover_pending_claims(
    home: &Path,
    wal_segment_path: &Path,
    writer: &WalWriterHandle,
    now_unix: i64,
) -> Result<usize, String> {
    let delivery_lock = acquire_delivery_lock(home)
        .await
        .map_err(|error| format!("acquire proactive recovery lock: {error:#}"))?;
    recover_pending_claims_locked(home, wal_segment_path, writer, &delivery_lock, now_unix)
        .await
        .map_err(|error| format!("recover proactive egress claims: {error:#}"))
}

/// Immutable process and WAL authority shared by every decision in one
/// proactive delivery tick. Item-specific routing and transport bindings stay
/// explicit at the sole egress seam.
pub(crate) struct ProactiveEgressContext<'a> {
    home: &'a Path,
    wal_segment_path: &'a Path,
    writer: &'a WalWriterHandle,
    now_unix: i64,
    /// Dispatcher-provided, configuration-bounded duration for one live
    /// provider attempt. The durable claim receives its absolute UTC deadline
    /// before the Armed ACK; this relative value is never persisted alone.
    delivery_attempt_timeout: Duration,
}

impl<'a> ProactiveEgressContext<'a> {
    pub(crate) fn new(
        home: &'a Path,
        wal_segment_path: &'a Path,
        writer: &'a WalWriterHandle,
        now_unix: i64,
        delivery_attempt_timeout: Duration,
    ) -> Self {
        Self {
            home,
            wal_segment_path,
            writer,
            now_unix,
            delivery_attempt_timeout,
        }
    }

    pub(crate) fn home(&self) -> &'a Path {
        self.home
    }

    pub(crate) fn wal_segment_path(&self) -> &'a Path {
        self.wal_segment_path
    }

    pub(crate) fn writer(&self) -> &'a WalWriterHandle {
        self.writer
    }

    pub(crate) fn now_unix(&self) -> i64 {
        self.now_unix
    }

    pub(crate) fn delivery_attempt_timeout(&self) -> Duration {
        self.delivery_attempt_timeout
    }
}

/// An owned provider future. Cancellation never leaves a detached adapter call
/// behind: normal and timeout paths await its `JoinHandle`, while dropping an
/// outer delivery future aborts the owned task immediately.
fn mark_transport_active(intent_id: &str) {
    let mut active = match ACTIVE_TRANSPORT_INTENTS.lock() {
        Ok(active) => active,
        Err(poisoned) => poisoned.into_inner(),
    };
    // UUIDv7 intent identity is already unique in the durable claim set. A
    // duplicate in the local registry is fail-closed at the caller's normal
    // claim admission boundary; retaining membership is safer than removing a
    // different attempt's cancellation authority.
    active.insert(intent_id.to_string());
}

fn mark_transport_inactive(intent_id: &str) {
    match ACTIVE_TRANSPORT_INTENTS.lock() {
        Ok(mut active) => {
            active.remove(intent_id);
        }
        Err(poisoned) => {
            poisoned.into_inner().remove(intent_id);
        }
    }
}

fn transport_is_locally_active(intent_id: &str) -> bool {
    match ACTIVE_TRANSPORT_INTENTS.lock() {
        Ok(active) => active.contains(intent_id),
        Err(poisoned) => poisoned.into_inner().contains(intent_id),
    }
}

struct OwnedTransportAttempt {
    handle: Option<TransportJoinHandle>,
    registration: Option<TransportIntentRegistration>,
    // The owner retains this through Result WAL acknowledgement. The spawned
    // provider future gets its own Arc clone, so outer cancellation releases
    // cross-process authority exactly when that future actually stops—not
    // when an asynchronous JoinHandle happens to be reaped later.
    armed_claim_lease: Option<Arc<ArmedClaimLease>>,
}

enum OwnedTransportOutcome {
    Completed(std::result::Result<MessageId, ChannelError>),
    DeadlineExceeded,
    TaskFailed,
}

impl OwnedTransportAttempt {
    fn start(
        registration: TransportIntentRegistration,
        channel: Arc<dyn Channel>,
        recipient: String,
        body: String,
        deadline: tokio::time::Instant,
        armed_claim_lease: Arc<ArmedClaimLease>,
    ) -> Self {
        let runtime = tokio::runtime::Handle::current();
        let task_lease = Arc::clone(&armed_claim_lease);
        Self {
            handle: Some(runtime.spawn(async move {
                // The post-admission caller has a fast-path check too, but
                // this check is deliberately colocated with the sole adapter
                // invocation so a scheduler handoff cannot begin provider I/O
                // after the immutable attempt boundary.
                if tokio::time::Instant::now() >= deadline {
                    return Err(ChannelError::Transport("deadline_exceeded".to_string()));
                }
                // Keep `task_lease` captured across the adapter await. An
                // outer egress Drop may release its owner Arc, but this clone
                // keeps the exact OS claim-file lease until provider I/O has
                // really stopped (including cancellation/abort teardown).
                task_lease
                    .validate_namespace_binding()
                    .map_err(|_| ChannelError::Transport("claim_lease_invalid".to_string()))?;
                let result = channel.send_proactive(&recipient, &body).await;
                // Keep the Arc observable across the await rather than
                // relying on compiler liveness after its last validation use.
                drop(task_lease);
                result
            })),
            registration: Some(registration),
            armed_claim_lease: Some(armed_claim_lease),
        }
    }

    /// Keep the intent locally owned across a completed provider join until
    /// terminal WAL evidence is acknowledged. This prevents recovery from
    /// replacing a known receipt/error with `CrashUnknown` while this task is
    /// merely waiting to reacquire the short terminal DeliveryLock.
    fn release_after_terminal_result(&mut self) {
        // Do not release early: a second process can observe a forward wall
        // clock while this task is waiting for its Result WAL ACK.
        drop(self.armed_claim_lease.take());
        drop(self.registration.take());
    }

    fn validate_claim_lease(&self, claim: &ProactiveEgressClaim) -> Result<()> {
        self.armed_claim_lease
            .as_ref()
            .context("proactive transport lost its Armed claim lease")?
            .validate_claim(claim)
    }

    async fn finish_before(&mut self, deadline: tokio::time::Instant) -> OwnedTransportOutcome {
        let handle = self
            .handle
            .as_mut()
            .expect("transport attempt is polled only once");
        match tokio::time::timeout_at(deadline, handle).await {
            Ok(Ok(result)) => {
                let _ = self.handle.take();
                OwnedTransportOutcome::Completed(result)
            }
            Ok(Err(_join_error)) => {
                let _ = self.handle.take();
                // A task panic/cancellation is intentionally collapsed to the
                // same fixed transport category as timeout. No adapter error
                // text crosses the durable boundary.
                OwnedTransportOutcome::TaskFailed
            }
            Err(_) => {
                let mut handle = self
                    .handle
                    .take()
                    .expect("timed-out transport keeps its join handle");
                handle.abort();
                // Await the abort before terminal WAL evidence. This makes a
                // timeout a real terminal boundary, not a detached retry race.
                let _ = (&mut handle).await;
                OwnedTransportOutcome::DeadlineExceeded
            }
        }
    }
}

impl Drop for OwnedTransportAttempt {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
            // `Drop` cannot await. Retain, rather than detach, the aborted
            // JoinHandle for the structured process supervisor below. Future
            // recovery/admission must explicitly reap it before durable state
            // can be reconciled. Poison cannot discard a live task either.
            let registration = self
                .registration
                .take()
                .expect("live transport must retain its local intent registration");
            match CANCELLED_TRANSPORT_REAP_QUEUE.lock() {
                Ok(mut queue) => queue.push(CancelledTransportHandle {
                    handle,
                    registration,
                }),
                Err(poisoned) => poisoned.into_inner().push(CancelledTransportHandle {
                    handle,
                    registration,
                }),
            }
        } else if self.registration.is_some() {
            // The provider task had already joined, but the owning egress
            // future was cancelled before its Result could become durable.
            // No live I/O remains; release only this local gate so recovery
            // can conservatively record CrashUnknown rather than leak an
            // unresolvable claim forever.
            self.release_after_terminal_result();
        }
    }
}

/// Cancellation-safe ownership transfer for one queued aborted task. If the
/// recovery future itself is cancelled while awaiting, this guard's Drop puts
/// the exact JoinHandle back into process-lifetime supervision rather than
/// allowing the runtime to detach it.
struct CancelledTransportReapGuard {
    entry: Option<CancelledTransportHandle>,
}

impl CancelledTransportReapGuard {
    fn take_next() -> Option<Self> {
        let entry = match CANCELLED_TRANSPORT_REAP_QUEUE.lock() {
            Ok(mut queue) => queue.pop(),
            Err(poisoned) => poisoned.into_inner().pop(),
        };
        entry.map(|entry| Self { entry: Some(entry) })
    }

    async fn reap(mut self) {
        let entry = self
            .entry
            .as_mut()
            .expect("reap guard owns exactly one cancelled transport handle");
        let _ = (&mut entry.handle).await;
        // Only a terminal JoinHandle is removed. If this future is cancelled
        // during the await, `self` drops with the entry still present and its
        // Drop implementation requeues the exact handle.
        let entry = self
            .entry
            .take()
            .expect("terminal cancelled transport reap entry is present");
        drop(entry.registration);
    }
}

impl Drop for CancelledTransportReapGuard {
    fn drop(&mut self) {
        if let Some(entry) = self.entry.take() {
            match CANCELLED_TRANSPORT_REAP_QUEUE.lock() {
                Ok(mut queue) => queue.push(entry),
                Err(poisoned) => poisoned.into_inner().push(entry),
            }
        }
    }
}

async fn reap_cancelled_transport_attempts() -> Result<()> {
    // Fixed-point drain: every handle stays under a cancellation-safe guard
    // until its join completes. A Drop that arrives while this loop awaits is
    // observed by a following iteration before recovery is allowed to inspect
    // durable claims.
    while let Some(guard) = CancelledTransportReapGuard::take_next() {
        guard.reap().await;
    }
    Ok(())
}

#[cfg(test)]
fn cancelled_transport_reap_queue_len() -> usize {
    match CANCELLED_TRANSPORT_REAP_QUEUE.lock() {
        Ok(queue) => queue.len(),
        Err(poisoned) => poisoned.into_inner().len(),
    }
}

fn fixed_transport_failure(category: &'static str) -> ChannelError {
    // Fixed, secret-free diagnostic input. `terminal_result` stores only its
    // category, size and digest; provider-generated error strings are never
    // synthesized or persisted by timeout/join handling.
    ChannelError::Transport(category.to_string())
}

/// Sole production transport seam for proactive messages.
///
/// Adapter construction happens before entry. Once inside, failure to create a
/// durable claim or WAL intent is fail-closed and performs zero transport I/O.
pub(crate) async fn execute_claimed_once(
    context: &ProactiveEgressContext<'_>,
    item: ProactiveItem,
    queue_generation: &str,
    target_channel: &str,
    transport_recipient: &str,
    channel: Arc<dyn Channel>,
) -> Result<Option<ProactiveStatus>, String> {
    let home = context.home;
    let wal_segment_path = context.wal_segment_path;
    let writer = context.writer;
    let now_unix = context.now_unix;
    let timeout = context.delivery_attempt_timeout();

    // Admission is one short critical section only. It includes recovery,
    // generation validation and all irreversible durable pre-transport ACKs;
    // provider I/O happens after the lock is dropped so unrelated deliveries
    // can make progress.
    let (claim, claim_file, transport_deadline, armed_claim_lease, registration) = {
        let delivery_lock = acquire_delivery_lock(home)
            .await
            .map_err(|error| format!("acquire proactive delivery lock: {error:#}"))?;
        recover_pending_claims_locked(home, wal_segment_path, writer, &delivery_lock, now_unix)
            .await
            .map_err(|error| format!("recover before proactive delivery: {error:#}"))?;
        let generation_matches =
            queue_generation_matches(&delivery_lock, home, &item.dedup_key, queue_generation)
                .await
                .map_err(|error| format!("load fresh proactive queue before claim: {error:#}"))?;
        if !generation_matches {
            return Ok(None);
        }
        let dedup_sha256 = effect_hash(b"proactive-egress-dedup-v1", item.dedup_key.as_bytes());
        if has_unexpired_inflight_dedup(&delivery_lock, home, &dedup_sha256, now_unix)
            .await
            .map_err(|error| format!("check proactive in-flight dedup: {error:#}"))?
        {
            return Ok(None);
        }
        // Sample both clocks once at admission. The original monotonic budget
        // prevents a later wall-clock rollback from extending live I/O; the
        // wall-derived budget prevents whole-second WAL encoding from adding a
        // hidden fractional second. The actual transport deadline is their
        // minimum after accounting for elapsed admission work.
        let monotonic_admission = tokio::time::Instant::now();
        let wall_admission = chrono::Utc::now();
        let original_monotonic_deadline = monotonic_admission
            .checked_add(timeout)
            .context("proactive transport deadline overflow")
            .map_err(|error| format!("bind proactive transport deadline: {error:#}"))?;
        let admission_now_unix = wall_admission.timestamp();
        let attempt_deadline_unix = deadline_after(admission_now_unix, timeout)
            .map_err(|error| format!("bind proactive attempt deadline: {error:#}"))?;
        let wall_budget = wall_budget_from_admission_sample(attempt_deadline_unix, wall_admission)
            .map_err(|error| format!("bind proactive wall budget: {error:#}"))?;
        let wall_budget = wall_budget
            .checked_sub(monotonic_admission.elapsed())
            .context("proactive attempt deadline expired during admission")
            .map_err(|error| format!("bind proactive wall budget: {error:#}"))?;
        let wall_deadline = monotonic_admission
            .checked_add(wall_budget)
            .context("proactive wall deadline overflow")
            .map_err(|error| format!("bind proactive wall deadline: {error:#}"))?;
        let transport_deadline = original_monotonic_deadline.min(wall_deadline);
        let mut claim = new_claim_with_deadline(
            item,
            queue_generation,
            target_channel,
            transport_recipient,
            admission_now_unix,
            attempt_deadline_unix,
        )
        .map_err(|error| format!("bind proactive claim: {error:#}"))?;
        let claim_file = persist_prepared_claim(&delivery_lock, home, &claim)
            .await
            .map_err(|error| format!("persist Prepared proactive claim: {error:#}"))?;
        append_intent(&delivery_lock, writer, &claim)
            .await
            .map_err(|error| format!("append proactive intent: {error:#}"))?;
        claim.phase = ProactiveEgressPhase::Armed;
        claim.binding_sha256 = binding_hash(&claim);
        persist_armed_claim(&delivery_lock, &claim_file, &claim)
            .await
            .map_err(|error| format!("persist Armed proactive claim: {error:#}"))?;
        // Acquire the exact final Armed inode while DeliveryLock is still
        // held, before its WAL ACK permits any provider call. A Busy outcome
        // is fail-closed: no transport starts and recovery sees no Armed WAL
        // authority, therefore records the attempt as NotAttempted.
        let armed_claim_lease = match ArmedClaimLease::try_acquire(&claim_file, &claim)
            .map_err(|error| format!("acquire proactive Armed claim lease: {error:#}"))?
        {
            ArmedClaimLeaseProbe::Acquired(lease) => Arc::new(lease),
            ArmedClaimLeaseProbe::Busy => {
                return Err(
                    "acquire proactive Armed claim lease: exact claim lease is already busy"
                        .to_string(),
                );
            }
        };
        // Register the same-process gate before Armed WAL acknowledgement and
        // before DeliveryLock is released. This closes local re-entrant file
        // lock behavior in the admission-to-spawn window.
        let registration = TransportIntentRegistration::acquire(&claim.intent_id);
        append_armed(&delivery_lock, writer, &claim)
            .await
            .map_err(|error| format!("append proactive Armed transition: {error:#}"))?;
        (
            claim,
            claim_file,
            transport_deadline,
            armed_claim_lease,
            registration,
        )
    };
    if tokio::time::Instant::now() >= transport_deadline {
        return Err("proactive attempt deadline expired before transport start".to_string());
    }

    let mut transport = OwnedTransportAttempt::start(
        registration,
        channel,
        transport_recipient.to_string(),
        claim.item.body.clone(),
        transport_deadline,
        armed_claim_lease,
    );
    let completed = transport.finish_before(transport_deadline).await;
    // Capture this only after the transport task either returned or was
    // aborted and reaped. It is an audit timestamp for the terminal boundary,
    // not the tick's stale `now_unix` input.
    let completed_at_unix = chrono::Utc::now().timestamp();
    let timeout_error = fixed_transport_failure("deadline_exceeded");
    let task_error = fixed_transport_failure("transport_task_failed");
    let (outcome, receipt, error) = match &completed {
        OwnedTransportOutcome::Completed(Ok(receipt)) => {
            (ProactiveEgressOutcome::Delivered, Some(receipt), None)
        }
        OwnedTransportOutcome::Completed(Err(error)) => {
            (outcome_for_error(error), None, Some(error))
        }
        OwnedTransportOutcome::DeadlineExceeded => (
            ProactiveEgressOutcome::TransportError,
            None,
            Some(&timeout_error),
        ),
        OwnedTransportOutcome::TaskFailed => (
            ProactiveEgressOutcome::TransportError,
            None,
            Some(&task_error),
        ),
    };
    let result = terminal_result(&claim, outcome, receipt, error, completed_at_unix);

    // Terminalization deliberately re-locks after live I/O. A competing
    // recovery may have reached the immutable deadline first; do not append a
    // second Result or promise provider-side exactly-once. The claim/evidence
    // check makes this race idempotent at NEOTH's durable boundary.
    let delivery_lock = acquire_delivery_lock(home)
        .await
        .map_err(|error| format!("reacquire proactive terminal lock: {error:#}"))?;
    let active = HashSet::from([claim.intent_id.clone()]);
    let evidence_home = home.to_path_buf();
    let evidence_segment = wal_segment_path.to_path_buf();
    let evidence_lock = delivery_lock
        .try_clone()
        .map_err(|error| format!("clone proactive terminal lock: {error:#}"))?;
    let evidence = tokio::task::spawn_blocking(move || {
        let _evidence_lock = evidence_lock;
        scan_authenticated_wal(&evidence_home, &evidence_segment, &active)
    })
    .await
    .map_err(|error| format!("join proactive terminal evidence scan: {error:#}"))?
    .map_err(|error| format!("scan proactive terminal evidence: {error:#}"))?;
    transport.validate_claim_lease(&claim).map_err(|error| {
        format!("revalidate proactive Armed claim lease before Result: {error:#}")
    })?;
    if let Some(existing) = evidence.results.get(&claim.intent_id) {
        verify_result_binding(existing, &claim)
            .map_err(|error| format!("verify raced proactive terminal result: {error:#}"))?;
        transport.release_after_terminal_result();
        return Ok(Some(existing.outcome.status()));
    }
    append_result(&delivery_lock, writer, &result)
        .await
        .map_err(|error| format!("append terminal proactive result: {error:#}"))?;
    // Result ACK is the authority hand-off: recovery can now authenticate and
    // replay this terminal evidence without ever synthesizing CrashUnknown.
    transport.release_after_terminal_result();
    apply_projections_blocking(
        &delivery_lock,
        home,
        wal_segment_path,
        claim_file,
        &claim,
        &result,
    )
    .await
    .map_err(|error| format!("project terminal proactive result: {error:#}"))?;
    Ok(Some(outcome.status()))
}

/// Settle a configured-but-unavailable route through the same durable
/// intent/result/projection chain without invoking a transport.
async fn record_without_transport_once(
    home: &Path,
    wal_segment_path: &Path,
    writer: &WalWriterHandle,
    item: ProactiveItem,
    queue_generation: &str,
    target_channel: &str,
    outcome: ProactiveEgressOutcome,
    now_unix: i64,
) -> Result<Option<ProactiveStatus>, String> {
    let delivery_lock = acquire_delivery_lock(home)
        .await
        .map_err(|error| format!("acquire proactive sidecar lock: {error:#}"))?;
    recover_pending_claims_locked(home, wal_segment_path, writer, &delivery_lock, now_unix)
        .await
        .map_err(|error| format!("recover before proactive sidecar result: {error:#}"))?;
    let generation_matches =
        queue_generation_matches(&delivery_lock, home, &item.dedup_key, queue_generation)
            .await
            .map_err(|error| {
                format!("load fresh proactive queue before sidecar claim: {error:#}")
            })?;
    if !generation_matches {
        return Ok(None);
    }
    let claim = new_claim(item, queue_generation, target_channel, "", now_unix)
        .map_err(|error| format!("bind sidecar proactive claim: {error:#}"))?;
    let claim_file = persist_prepared_claim(&delivery_lock, home, &claim)
        .await
        .map_err(|error| format!("persist sidecar proactive claim: {error:#}"))?;
    append_intent(&delivery_lock, writer, &claim)
        .await
        .map_err(|error| format!("append sidecar proactive intent: {error:#}"))?;
    let result = terminal_result(&claim, outcome, None, None, now_unix);
    append_result(&delivery_lock, writer, &result)
        .await
        .map_err(|error| format!("append sidecar proactive result: {error:#}"))?;
    apply_projections_blocking(
        &delivery_lock,
        home,
        wal_segment_path,
        claim_file,
        &claim,
        &result,
    )
    .await
    .map_err(|error| format!("project sidecar proactive result: {error:#}"))?;
    Ok(Some(outcome.status()))
}

/// Settle a route that intentionally uses the private operator inbox or has no
/// configured live adapter. This is a first-class terminal outcome, not a
/// transport failure.
pub(crate) async fn record_sidecar_only_once(
    home: &Path,
    wal_segment_path: &Path,
    writer: &WalWriterHandle,
    item: ProactiveItem,
    queue_generation: &str,
    target_channel: &str,
    now_unix: i64,
) -> Result<Option<ProactiveStatus>, String> {
    record_without_transport_once(
        home,
        wal_segment_path,
        writer,
        item,
        queue_generation,
        target_channel,
        ProactiveEgressOutcome::SidecarOnly,
        now_unix,
    )
    .await
}

/// Settle an explicit autonomy-policy denial with durable audit and queue
/// projection. It must not be confused with a pre-dispatch crash, which is
/// retryable and uses `NotAttempted`.
pub(crate) async fn record_policy_suppressed_once(
    home: &Path,
    wal_segment_path: &Path,
    writer: &WalWriterHandle,
    item: ProactiveItem,
    queue_generation: &str,
    target_channel: &str,
    now_unix: i64,
) -> Result<Option<ProactiveStatus>, String> {
    record_without_transport_once(
        home,
        wal_segment_path,
        writer,
        item,
        queue_generation,
        target_channel,
        ProactiveEgressOutcome::PolicySuppressed,
        now_unix,
    )
    .await
}

/// Settle an item whose selected adapter rejected its local configuration
/// before transport admission. The failure remains item-specific and visible,
/// while claim/WAL/projection failures still stop the dispatcher globally.
pub(crate) async fn record_adapter_configuration_error_once(
    home: &Path,
    wal_segment_path: &Path,
    writer: &WalWriterHandle,
    item: ProactiveItem,
    queue_generation: &str,
    target_channel: &str,
    now_unix: i64,
) -> Result<Option<ProactiveStatus>, String> {
    record_without_transport_once(
        home,
        wal_segment_path,
        writer,
        item,
        queue_generation,
        target_channel,
        ProactiveEgressOutcome::AdapterConfigurationError,
        now_unix,
    )
    .await
}

#[cfg(test)]
pub(crate) fn delivery_record_for_gui_test() -> ProactiveDeliveryRecord {
    let item = ProactiveItem {
        priority: 50,
        dedup_key: "gui-proactive".to_string(),
        channel: "telegram".to_string(),
        source: "test".to_string(),
        body: "operator notification".to_string(),
        scheduled_for_unix: 0,
        is_failure: false,
        expires_unix: 0,
    };
    let mut claim = new_claim(item, "gui-generation", "telegram", "123456", 1_700_000_000)
        .expect("build GUI proactive delivery fixture");
    claim.phase = ProactiveEgressPhase::Armed;
    claim.binding_sha256 = binding_hash(&claim);
    let receipt = MessageId("provider-receipt".to_string());
    let result = terminal_result(
        &claim,
        ProactiveEgressOutcome::Delivered,
        Some(&receipt),
        None,
        1_700_000_001,
    );
    delivery_record(&claim, &result, "000001.wal").expect("build GUI proactive delivery record")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingChannel {
        sends: AtomicUsize,
    }

    impl CountingChannel {
        fn new() -> Self {
            Self {
                sends: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl Channel for CountingChannel {
        fn name(&self) -> &'static str {
            "counting"
        }

        async fn run(&self, _handler: crate::channels::PipelineHandler) -> Result<()> {
            Ok(())
        }

        async fn send_proactive(
            &self,
            _chat_id: &str,
            _text: &str,
        ) -> std::result::Result<MessageId, ChannelError> {
            self.sends.fetch_add(1, Ordering::SeqCst);
            Ok(MessageId("counted".to_string()))
        }
    }

    struct BlockingChannel {
        sends: AtomicUsize,
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }

    impl BlockingChannel {
        fn new() -> Self {
            Self {
                sends: AtomicUsize::new(0),
                entered: tokio::sync::Notify::new(),
                release: tokio::sync::Notify::new(),
            }
        }
    }

    #[async_trait::async_trait]
    impl Channel for BlockingChannel {
        fn name(&self) -> &'static str {
            "blocking"
        }

        async fn run(&self, _handler: crate::channels::PipelineHandler) -> Result<()> {
            Ok(())
        }

        async fn send_proactive(
            &self,
            _chat_id: &str,
            _text: &str,
        ) -> std::result::Result<MessageId, ChannelError> {
            self.sends.fetch_add(1, Ordering::SeqCst);
            self.entered.notify_one();
            self.release.notified().await;
            Ok(MessageId("released".to_string()))
        }
    }

    async fn ready_writer(
        home: &Path,
    ) -> (
        PathBuf,
        WalWriterHandle,
        tokio::task::JoinHandle<std::result::Result<(), String>>,
    ) {
        let wal_dir = home.join("wal");
        std::fs::create_dir_all(&wal_dir).unwrap();
        let segment = wal_dir.join("000001.wal");
        let (writer, join, ready) =
            crate::wal::writer::spawn_for_home_ready(segment.clone(), home.to_path_buf()).unwrap();
        ready.wait().await.unwrap();
        (segment, writer, join)
    }

    fn seed_queue(home: &Path, queued: ProactiveItem) -> String {
        let mut queue = ProactiveQueue::new();
        assert!(queue.enqueue(queued.clone()).unwrap());
        let generation = queue
            .entry_generation(&queued.dedup_key)
            .unwrap()
            .to_string();
        queue.save_to(&home.join("proactive_queue.json")).unwrap();
        generation
    }

    async fn prepared_claim_with_intent(
        home: &Path,
        writer: &WalWriterHandle,
        queued: ProactiveItem,
        generation: &str,
        now_unix: i64,
    ) -> (std::fs::File, BoundClaimFile, ProactiveEgressClaim) {
        let delivery_lock = acquire_delivery_lock(home).await.unwrap();
        let claim = new_claim(queued, generation, "telegram", "operator", now_unix).unwrap();
        let claim_path = persist_prepared_claim(&delivery_lock, home, &claim)
            .await
            .unwrap();
        append_intent(&delivery_lock, writer, &claim).await.unwrap();
        (delivery_lock, claim_path, claim)
    }

    async fn armed_v2_claim_with_evidence(
        home: &Path,
        writer: &WalWriterHandle,
        queued: ProactiveItem,
        generation: &str,
        created_at_unix: i64,
        attempt_deadline_unix: i64,
    ) -> (BoundClaimFile, ProactiveEgressClaim) {
        let delivery_lock = acquire_delivery_lock(home).await.unwrap();
        let prepared = new_claim_with_deadline(
            queued,
            generation,
            "telegram",
            "operator",
            created_at_unix,
            attempt_deadline_unix,
        )
        .unwrap();
        let claim_file = persist_prepared_claim(&delivery_lock, home, &prepared)
            .await
            .unwrap();
        append_intent(&delivery_lock, writer, &prepared)
            .await
            .unwrap();
        let armed = claim_in_phase(&prepared, ProactiveEgressPhase::Armed);
        persist_armed_claim(&delivery_lock, &claim_file, &armed)
            .await
            .unwrap();
        append_armed(&delivery_lock, writer, &armed).await.unwrap();
        drop(delivery_lock);
        (claim_file, armed)
    }

    fn item(key: &str) -> ProactiveItem {
        ProactiveItem {
            priority: 50,
            dedup_key: key.to_string(),
            channel: "telegram".to_string(),
            source: "test".to_string(),
            body: "private body".to_string(),
            scheduled_for_unix: 0,
            is_failure: false,
            expires_unix: 0,
        }
    }

    #[cfg(any(unix, windows))]
    fn make_test_file_broad(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        #[cfg(windows)]
        {
            crate::wal::win_native::set_unprotected_current_user_file_dacl_for_test(path)
                .expect("seed deliberately unprotected owner DACL");
            assert!(
                crate::wal::win_native::verify_private_dacl(path).is_err(),
                "fixture must be broad before the production reader runs"
            );
            std::fs::File::open(path).expect("broad fixture must remain readable by TokenUser");
        }
    }

    fn evidence_for_claim(
        claim: &ProactiveEgressClaim,
        result: &ProactiveResultFrame,
    ) -> WalEvidence {
        let mut evidence = WalEvidence::default();
        let prepared = claim_in_phase(claim, ProactiveEgressPhase::Prepared);
        evidence
            .intents
            .insert(claim.intent_id.clone(), intent_frame(&prepared));
        if claim.phase == ProactiveEgressPhase::Armed {
            evidence
                .armed
                .insert(claim.intent_id.clone(), armed_frame(claim).unwrap());
        }
        evidence
            .results
            .insert(claim.intent_id.clone(), result.clone());
        evidence
    }

    #[test]
    fn claim_binding_is_uuidv7_secret_safe_and_self_verifying() {
        let claim = new_claim(
            item("private-dedup"),
            "queue-generation",
            "keet",
            "nk1_SECRET_CAPABILITY",
            7,
        )
        .unwrap();
        assert_eq!(
            claim
                .intent_id
                .parse::<uuid::Uuid>()
                .unwrap()
                .get_version_num(),
            7
        );
        assert!(!claim.recipient_sha256.contains("SECRET"));
        assert!(!claim.message_sha256.contains("private body"));
        assert_eq!(claim.binding_sha256, binding_hash(&claim));
        validate_claim(&claim, &claim_name(&claim)).unwrap();
    }

    #[tokio::test]
    async fn escaped_body_within_shared_admission_bound_round_trips_history() {
        let home = tempfile::tempdir().unwrap();
        let mut queued = item("escaped-history");
        queued.body = "\0".repeat(180_000);
        queued.validate().unwrap();
        let encoded_item = serde_json::to_vec(&queued).unwrap();
        assert!(encoded_item.len() > MAX_PROACTIVE_BODY_BYTES);
        assert!(encoded_item.len() <= MAX_PROACTIVE_ITEM_ENCODED_BYTES);
        let generation = seed_queue(home.path(), queued.clone());
        let (segment, writer, join) = ready_writer(home.path()).await;

        assert_eq!(
            record_sidecar_only_once(
                home.path(),
                &segment,
                &writer,
                queued.clone(),
                &generation,
                "local_inbox",
                7,
            )
            .await
            .unwrap(),
            Some(ProactiveStatus::SidecarOnly)
        );
        let sidecar = std::fs::read(home.path().join(PROACTIVE_DELIVERED_SIDECAR)).unwrap();
        let row = sidecar.strip_suffix(b"\n").unwrap();
        assert!(row.len() <= MAX_HISTORY_RECORD_BYTES);
        let history = read_delivery_history(home.path()).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].item(), &queued);

        drop(writer);
        join.await.unwrap().unwrap();
    }

    #[test]
    fn verified_projection_enforces_exact_phase_matrix_and_chain_base() {
        let prepared =
            new_claim(item("phase-prepared"), "generation-a", "local_inbox", "", 8).unwrap();
        let prepared_result = terminal_result(
            &prepared,
            ProactiveEgressOutcome::SidecarOnly,
            None,
            None,
            9,
        );
        let prepared_record = delivery_record(&prepared, &prepared_result, "000001.wal").unwrap();
        let prepared_evidence = evidence_for_claim(&prepared, &prepared_result);
        verify_delivery_record_against_wal(&prepared_record, &prepared_evidence).unwrap();

        let mut unexpected_armed = prepared_evidence;
        let armed_projection = claim_in_phase(&prepared, ProactiveEgressPhase::Armed);
        unexpected_armed.armed.insert(
            prepared.intent_id.clone(),
            armed_frame(&armed_projection).unwrap(),
        );
        assert!(verify_delivery_record_against_wal(&prepared_record, &unexpected_armed).is_err());

        let delivered_result = terminal_result(
            &armed_projection,
            ProactiveEgressOutcome::Delivered,
            Some(&MessageId("phase-receipt".to_string())),
            None,
            10,
        );
        let delivered_record =
            delivery_record(&armed_projection, &delivered_result, "000001.wal").unwrap();
        let mut missing_armed = evidence_for_claim(&armed_projection, &delivered_result);
        missing_armed.armed.clear();
        assert!(verify_delivery_record_against_wal(&delivered_record, &missing_armed).is_err());

        let unsupported = ChannelError::NotSupported {
            feature: "proactive",
        };
        let armed_sidecar_result = terminal_result(
            &armed_projection,
            ProactiveEgressOutcome::SidecarOnly,
            None,
            Some(&unsupported),
            11,
        );
        let armed_sidecar_record =
            delivery_record(&armed_projection, &armed_sidecar_result, "000001.wal").unwrap();
        verify_delivery_record_against_wal(
            &armed_sidecar_record,
            &evidence_for_claim(&armed_projection, &armed_sidecar_result),
        )
        .unwrap();

        for outcome in [
            ProactiveEgressOutcome::PolicySuppressed,
            ProactiveEgressOutcome::AdapterConfigurationError,
            ProactiveEgressOutcome::NotAttempted,
        ] {
            let result = terminal_result(&prepared, outcome, None, None, 12);
            let record = delivery_record(&prepared, &result, "000001.wal").unwrap();
            verify_delivery_record_against_wal(&record, &evidence_for_claim(&prepared, &result))
                .unwrap();
        }
        for (outcome, error) in [
            (
                ProactiveEgressOutcome::TransportError,
                ChannelError::Transport("offline".to_string()),
            ),
            (
                ProactiveEgressOutcome::AuthError,
                ChannelError::Auth("expired".to_string()),
            ),
            (
                ProactiveEgressOutcome::RateLimited,
                ChannelError::RateLimited {
                    retry_after_secs: 30,
                },
            ),
        ] {
            let result = terminal_result(&armed_projection, outcome, None, Some(&error), 13);
            let record = delivery_record(&armed_projection, &result, "000001.wal").unwrap();
            verify_delivery_record_against_wal(
                &record,
                &evidence_for_claim(&armed_projection, &result),
            )
            .unwrap();
        }
        let crash_result = terminal_result(
            &armed_projection,
            ProactiveEgressOutcome::CrashUnknown,
            None,
            None,
            14,
        );
        let crash_record = delivery_record(&armed_projection, &crash_result, "000001.wal").unwrap();
        verify_delivery_record_against_wal(
            &crash_record,
            &evidence_for_claim(&armed_projection, &crash_result),
        )
        .unwrap();

        assert!(delivery_record(&prepared, &prepared_result, "000002.wal").is_err());
        assert!(delivery_record(&prepared, &prepared_result, "../000001.wal").is_err());
        let home = tempfile::tempdir().unwrap();
        assert!(
            canonical_wal_chain_base_name(home.path(), &home.path().join("000001.wal")).is_err()
        );
    }

    #[test]
    fn queue_tombstone_preserves_a_later_same_key_enqueue() {
        let mut queue = ProactiveQueue::new();
        queue.enqueue(item("same")).unwrap();
        let generation = queue.entry_generation("same").unwrap().to_string();
        let intent = uuid::Uuid::now_v7().to_string();
        assert!(queue.settle_egress_once(&intent, "same", &generation, 10));
        assert!(queue.enqueue(item("same")).unwrap());
        assert!(!queue.settle_egress_once(&intent, "same", &generation, 11));
        assert_eq!(queue.peek().len(), 1);
    }

    #[tokio::test]
    async fn recovery_discards_prepared_claim_without_intent_and_keeps_queue() {
        let home = tempfile::tempdir().unwrap();
        let queued = item("prepared-only");
        let generation = seed_queue(home.path(), queued.clone());
        let (segment, writer, join) = ready_writer(home.path()).await;
        let delivery_lock = acquire_delivery_lock(home.path()).await.unwrap();
        let claim = new_claim(queued, &generation, "telegram", "operator", 10).unwrap();
        let claim_path = persist_prepared_claim(&delivery_lock, home.path(), &claim)
            .await
            .unwrap();
        drop(delivery_lock);

        assert_eq!(
            recover_pending_claims(home.path(), &segment, &writer, 11)
                .await
                .unwrap(),
            1
        );
        assert!(!claim_path.exists());
        assert_eq!(
            ProactiveQueue::load_from(&home.path().join("proactive_queue.json"))
                .unwrap()
                .peek()
                .len(),
            1
        );
        assert!(read_delivery_history(home.path()).unwrap().is_empty());
        drop(writer);
        join.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn recovery_marks_intent_without_armed_not_attempted_and_keeps_queue() {
        let home = tempfile::tempdir().unwrap();
        let queued = item("intent-only");
        let generation = seed_queue(home.path(), queued.clone());
        let (segment, writer, join) = ready_writer(home.path()).await;
        let (delivery_lock, claim_path, _claim) =
            prepared_claim_with_intent(home.path(), &writer, queued, &generation, 20).await;
        drop(delivery_lock);

        recover_pending_claims(home.path(), &segment, &writer, 21)
            .await
            .unwrap();
        assert!(!claim_path.exists());
        assert_eq!(
            ProactiveQueue::load_from(&home.path().join("proactive_queue.json"))
                .unwrap()
                .peek()
                .len(),
            1
        );
        let history = read_delivery_history(home.path()).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].outcome(), ProactiveEgressOutcome::NotAttempted);
        drop(writer);
        join.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn recovery_marks_armed_without_result_crash_unknown_and_settles_queue() {
        let home = tempfile::tempdir().unwrap();
        let queued = item("armed-only");
        let generation = seed_queue(home.path(), queued.clone());
        let (segment, writer, join) = ready_writer(home.path()).await;
        let (delivery_lock, claim_path, prepared) =
            prepared_claim_with_intent(home.path(), &writer, queued, &generation, 30).await;
        let armed = claim_in_phase(&prepared, ProactiveEgressPhase::Armed);
        persist_armed_claim(&delivery_lock, &claim_path, &armed)
            .await
            .unwrap();
        append_armed(&delivery_lock, &writer, &armed).await.unwrap();
        drop(delivery_lock);

        recover_pending_claims(home.path(), &segment, &writer, 31)
            .await
            .unwrap();
        assert!(!claim_path.exists());
        assert!(
            ProactiveQueue::load_from(&home.path().join("proactive_queue.json"))
                .unwrap()
                .is_empty()
        );
        let history = read_delivery_history(home.path()).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].outcome(), ProactiveEgressOutcome::CrashUnknown);
        drop(writer);
        join.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn authenticated_armed_proof_rejects_a_claim_phase_rollback() {
        let home = tempfile::tempdir().unwrap();
        let queued = item("armed-phase-rollback");
        let generation = seed_queue(home.path(), queued.clone());
        let (segment, writer, join) = ready_writer(home.path()).await;
        let (delivery_lock, claim_path, prepared) =
            prepared_claim_with_intent(home.path(), &writer, queued, &generation, 35).await;
        let armed = claim_in_phase(&prepared, ProactiveEgressPhase::Armed);
        persist_armed_claim(&delivery_lock, &claim_path, &armed)
            .await
            .unwrap();
        append_armed(&delivery_lock, &writer, &armed).await.unwrap();
        crate::util::atomic_write::atomic_write_private(
            &claim_path.display_path,
            &serde_json::to_vec(&prepared).unwrap(),
        )
        .unwrap();
        drop(delivery_lock);

        let error = recover_pending_claims(home.path(), &segment, &writer, 36)
            .await
            .unwrap_err();
        assert!(error.contains("Armed proof conflicts"), "{error}");
        assert!(
            claim_path.exists(),
            "conflicting evidence must be preserved"
        );
        assert_eq!(
            ProactiveQueue::load_from(&home.path().join("proactive_queue.json"))
                .unwrap()
                .peek()
                .len(),
            1
        );
        drop(writer);
        join.await.unwrap().unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn armed_replace_rebinds_exact_delete_without_target_handle_interference() {
        let home = tempfile::tempdir().unwrap();
        let delivery_lock = acquire_delivery_lock(home.path()).await.unwrap();
        let prepared = new_claim(
            item("armed-rebind"),
            "queue-generation",
            "telegram",
            "operator",
            37,
        )
        .unwrap();
        let claim_file = persist_prepared_claim(&delivery_lock, home.path(), &prepared)
            .await
            .unwrap();
        let armed = claim_in_phase(&prepared, ProactiveEgressPhase::Armed);
        let armed_bytes = serde_json::to_vec(&armed).unwrap();

        persist_armed_claim(&delivery_lock, &claim_file, &armed)
            .await
            .expect("Prepared binding must not block the authorized Armed replacement");
        assert_eq!(
            std::fs::read(&claim_file.display_path).unwrap(),
            armed_bytes
        );

        // Move the rebound Armed object away and publish an attacker-controlled
        // same-name sentinel. Exact-handle deletion must remove only the Armed
        // object, never follow the public name to the replacement.
        let public_path = claim_file.display_path.clone();
        let displaced = home.path().join("displaced-armed.claim");
        std::fs::rename(&public_path, &displaced).unwrap();
        std::fs::write(&public_path, b"same-name replacement sentinel").unwrap();
        claim_file
            .remove()
            .expect("rebound claim authority must delete its exact Armed object");

        assert_eq!(
            std::fs::read(&public_path).unwrap(),
            b"same-name replacement sentinel"
        );
        assert!(
            !displaced.exists(),
            "exact deletion must settle only the handle-bound Armed object"
        );
    }

    #[cfg(windows)]
    #[test]
    fn legacy_replace_drops_observation_handles_and_rebinds_exact_generation() {
        let home = tempfile::tempdir().unwrap();
        let queued = item("legacy-rebind");
        seed_queue(home.path(), queued.clone());
        let claim_root = ensure_claim_directory(home.path()).unwrap();
        let legacy_digest = legacy_claim_digest(&queued);
        let claim_path = claim_root
            .display_path
            .join(format!("{legacy_digest}.claimed"));
        crate::util::atomic_write::write_private_create_new_durable(
            &claim_path,
            &serde_json::to_vec(&queued).unwrap(),
        )
        .unwrap();
        make_test_file_broad(&claim_path);

        let mut scanned = read_claims(home.path(), 38)
            .expect("legacy conversion must release every old-generation handle before replace");
        assert_eq!(scanned.len(), 1);
        let (claim_file, converted) = scanned.pop().unwrap();
        assert_eq!(converted.phase, ProactiveEgressPhase::Armed);
        assert_eq!(
            converted.legacy_claim_sha256.as_deref(),
            Some(legacy_digest.as_str())
        );
        assert_eq!(
            std::fs::read(&claim_path).unwrap(),
            serde_json::to_vec(&converted).unwrap()
        );

        // Prove the post-conversion authority was rebound to the exact new
        // generation rather than left path-based or attached to the legacy
        // object that the atomic replacement retired.
        let displaced = claim_root.display_path.join("displaced-legacy.claim");
        std::fs::rename(&claim_path, &displaced).unwrap();
        std::fs::write(&claim_path, b"same-name replacement sentinel").unwrap();
        claim_file
            .remove()
            .expect("rebound authority must delete only the converted generation");
        assert_eq!(
            std::fs::read(&claim_path).unwrap(),
            b"same-name replacement sentinel"
        );
        assert!(
            !displaced.exists(),
            "exact removal must settle the converted generation only"
        );
    }

    #[tokio::test]
    async fn recovery_replays_terminal_result_without_duplicate_projection_or_budget() {
        let home = tempfile::tempdir().unwrap();
        let queued = item("result-replay");
        let generation = seed_queue(home.path(), queued.clone());
        let (segment, writer, join) = ready_writer(home.path()).await;
        let (delivery_lock, claim_path, prepared) =
            prepared_claim_with_intent(home.path(), &writer, queued, &generation, 40).await;
        let armed = claim_in_phase(&prepared, ProactiveEgressPhase::Armed);
        persist_armed_claim(&delivery_lock, &claim_path, &armed)
            .await
            .unwrap();
        append_armed(&delivery_lock, &writer, &armed).await.unwrap();
        let result = terminal_result(
            &armed,
            ProactiveEgressOutcome::Delivered,
            Some(&MessageId("receipt".to_string())),
            None,
            41,
        );
        append_result(&delivery_lock, &writer, &result)
            .await
            .unwrap();
        append_delivery_record_once(home.path(), &segment, &armed, &result).unwrap();
        let sidecar_path = home.path().join(PROACTIVE_DELIVERED_SIDECAR);
        let exact_projection = std::fs::read(&sidecar_path).unwrap();
        let parent_syncs_before_replay =
            crate::util::atomic_write::required_parent_sync_attempts_for_test();
        append_delivery_record_once(home.path(), &segment, &armed, &result).unwrap();
        assert!(
            crate::util::atomic_write::required_parent_sync_attempts_for_test()
                > parent_syncs_before_replay,
            "an exact replay must retry the required namespace durability barrier"
        );
        assert_eq!(
            std::fs::read(&sidecar_path).unwrap(),
            exact_projection,
            "an exact replay must atomically republish the validated bytes"
        );
        assert_eq!(
            exact_projection
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .count(),
            1,
            "an exact replay must not append a duplicate row"
        );
        ProactiveQueue::modify(&home.path().join("proactive_queue.json"), |queue| {
            let changed = queue.settle_egress_once(
                &armed.intent_id,
                &armed.item.dedup_key,
                &armed.queue_generation,
                41,
            );
            (true, changed)
        })
        .unwrap();
        drop(delivery_lock);

        recover_pending_claims(home.path(), &segment, &writer, 42)
            .await
            .unwrap();
        let queue = ProactiveQueue::load_from(&home.path().join("proactive_queue.json")).unwrap();
        assert!(queue.is_empty());
        assert_eq!(queue.stats(42).drained_last_24h, 1);
        assert_eq!(read_delivery_history(home.path()).unwrap().len(), 1);
        assert!(!claim_path.exists());
        drop(writer);
        join.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn concurrent_delivery_attempts_call_transport_once() {
        let home = tempfile::tempdir().unwrap();
        let queued = item("concurrent");
        let generation = seed_queue(home.path(), queued.clone());
        let (segment, writer, join) = ready_writer(home.path()).await;
        let channel = Arc::new(CountingChannel::new());
        let context = ProactiveEgressContext::new(
            home.path(),
            &segment,
            &writer,
            50,
            DEFAULT_DELIVERY_ATTEMPT_TIMEOUT,
        );

        let first = execute_claimed_once(
            &context,
            queued.clone(),
            &generation,
            "telegram",
            "operator",
            channel.clone(),
        );
        let second = execute_claimed_once(
            &context,
            queued,
            &generation,
            "telegram",
            "operator",
            channel.clone(),
        );
        let (first, second) = tokio::join!(first, second);
        let outcomes = [first.unwrap(), second.unwrap()];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == Some(ProactiveStatus::Delivered))
                .count(),
            1
        );
        assert_eq!(channel.sends.load(Ordering::SeqCst), 1);
        assert_eq!(read_delivery_history(home.path()).unwrap().len(), 1);
        drop(writer);
        join.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn replacement_generation_survives_a_blocked_old_send() {
        let home = tempfile::tempdir().unwrap();
        let queued = item("replace-during-send");
        let old_generation = seed_queue(home.path(), queued.clone());
        let (segment, writer, join) = ready_writer(home.path()).await;
        let channel = Arc::new(BlockingChannel::new());
        let task_home = home.path().to_path_buf();
        let task_segment = segment.clone();
        let task_writer = writer.clone();
        let task_channel = Arc::clone(&channel);
        let task_item = queued.clone();
        let task_generation = old_generation.clone();
        let delivery = tokio::spawn(async move {
            let context = ProactiveEgressContext::new(
                &task_home,
                &task_segment,
                &task_writer,
                60,
                DEFAULT_DELIVERY_ATTEMPT_TIMEOUT,
            );
            execute_claimed_once(
                &context,
                task_item,
                &task_generation,
                "telegram",
                "operator",
                task_channel,
            )
            .await
        });
        channel.entered.notified().await;
        let replacement_generation =
            ProactiveQueue::modify(&home.path().join("proactive_queue.json"), |queue| {
                assert_eq!(queue.remove_by_key(&queued.dedup_key), 1);
                assert!(queue.enqueue(queued.clone()).unwrap());
                let generation = queue
                    .entry_generation(&queued.dedup_key)
                    .unwrap()
                    .to_string();
                (true, generation)
            })
            .unwrap();
        assert_ne!(replacement_generation, old_generation);
        channel.release.notify_one();
        assert_eq!(
            delivery.await.unwrap().unwrap(),
            Some(ProactiveStatus::Delivered)
        );
        let queue = ProactiveQueue::load_from(&home.path().join("proactive_queue.json")).unwrap();
        assert_eq!(
            queue.entry_generation(&queued.dedup_key),
            Some(replacement_generation.as_str())
        );
        assert_eq!(queue.peek().len(), 1);
        assert_eq!(channel.sends.load(Ordering::SeqCst), 1);
        drop(writer);
        join.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn cancellation_during_wal_ack_keeps_lock_until_recovery_is_safe() {
        let home = tempfile::tempdir().unwrap();
        let queued = item("cancel-at-ack");
        let generation = seed_queue(home.path(), queued.clone());
        let (segment, writer, join) = ready_writer(home.path()).await;
        let gate = crate::wal::writer::TestAckGate::once(EVENT_TYPE_EXTENDED);
        let gated_writer = writer.with_test_ack_gate(gate.clone());
        let channel = Arc::new(CountingChannel::new());
        let task_home = home.path().to_path_buf();
        let task_segment = segment.clone();
        let task_writer = gated_writer.clone();
        let task_channel = Arc::clone(&channel);
        let delivery = tokio::spawn(async move {
            let context = ProactiveEgressContext::new(
                &task_home,
                &task_segment,
                &task_writer,
                70,
                DEFAULT_DELIVERY_ATTEMPT_TIMEOUT,
            );
            execute_claimed_once(
                &context,
                queued,
                &generation,
                "telegram",
                "operator",
                task_channel,
            )
            .await
        });
        gate.wait_until_durable().await;
        delivery.abort();
        let _ = delivery.await;

        let recovery_home = home.path().to_path_buf();
        let recovery_segment = segment.clone();
        let recovery_writer = gated_writer.clone();
        let mut recovery = tokio::spawn(async move {
            recover_pending_claims(&recovery_home, &recovery_segment, &recovery_writer, 71).await
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut recovery)
                .await
                .is_err(),
            "recovery acquired the delivery lock before the cancelled WAL ACK completed"
        );
        gate.release();
        recovery.await.unwrap().unwrap();
        assert_eq!(channel.sends.load(Ordering::SeqCst), 0);
        assert_eq!(
            ProactiveQueue::load_from(&home.path().join("proactive_queue.json"))
                .unwrap()
                .peek()
                .len(),
            1
        );
        let history = read_delivery_history(home.path()).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].outcome(), ProactiveEgressOutcome::NotAttempted);
        drop(gated_writer);
        join.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn terminal_result_marker_is_authenticated_before_ack() {
        let home = tempfile::tempdir().unwrap();
        let (segment, writer, join) = ready_writer(home.path()).await;
        let delivery_lock = acquire_delivery_lock(home.path()).await.unwrap();
        let claim = new_claim(
            item("marker-before-ack"),
            "generation",
            "local_inbox",
            "",
            75,
        )
        .unwrap();
        append_intent(&delivery_lock, &writer, &claim)
            .await
            .unwrap();
        let intent_ids = HashSet::from([claim.intent_id.clone()]);
        let before = scan_authenticated_projection_wal(home.path(), &segment, &intent_ids).unwrap();
        assert!(before.intents.is_empty());
        assert!(before.results.is_empty());

        let result = terminal_result(&claim, ProactiveEgressOutcome::SidecarOnly, None, None, 76);
        let gate = crate::wal::writer::TestAckGate::once(EVENT_TYPE_EXTENDED);
        let gated_writer = writer.clone().with_test_ack_gate(gate.clone());
        let append =
            tokio::spawn(
                async move { append_result(&delivery_lock, &gated_writer, &result).await },
            );
        gate.wait_until_durable().await;

        let while_ack_paused =
            scan_authenticated_projection_wal(home.path(), &segment, &intent_ids).unwrap();
        assert!(while_ack_paused.intents.contains_key(&claim.intent_id));
        assert!(while_ack_paused.results.contains_key(&claim.intent_id));
        gate.release();
        append.await.unwrap().unwrap();
        drop(writer);
        join.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn sidecar_only_and_policy_suppressed_use_typed_terminal_chain() {
        let home = tempfile::tempdir().unwrap();
        let sidecar_item = item("disabled-sidecar");
        let suppressed_item = item("policy-suppressed");
        let mut queue = ProactiveQueue::new();
        assert!(queue.enqueue(sidecar_item.clone()).unwrap());
        assert!(queue.enqueue(suppressed_item.clone()).unwrap());
        let sidecar_generation = queue
            .entry_generation(&sidecar_item.dedup_key)
            .unwrap()
            .to_string();
        let suppressed_generation = queue
            .entry_generation(&suppressed_item.dedup_key)
            .unwrap()
            .to_string();
        queue
            .save_to(&home.path().join("proactive_queue.json"))
            .unwrap();
        let (segment, writer, join) = ready_writer(home.path()).await;

        assert_eq!(
            record_sidecar_only_once(
                home.path(),
                &segment,
                &writer,
                sidecar_item,
                &sidecar_generation,
                "local_inbox",
                80,
            )
            .await
            .unwrap(),
            Some(ProactiveStatus::SidecarOnly)
        );
        assert_eq!(
            record_policy_suppressed_once(
                home.path(),
                &segment,
                &writer,
                suppressed_item,
                &suppressed_generation,
                "telegram",
                81,
            )
            .await
            .unwrap(),
            Some(ProactiveStatus::Suppressed)
        );
        let history = read_delivery_history(home.path()).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].outcome(), ProactiveEgressOutcome::SidecarOnly);
        assert_eq!(
            history[1].outcome(),
            ProactiveEgressOutcome::PolicySuppressed
        );
        assert!(
            ProactiveQueue::load_from(&home.path().join("proactive_queue.json"))
                .unwrap()
                .is_empty()
        );
        drop(writer);
        join.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn self_consistent_forged_modern_projection_is_rejected_by_wal_binding() {
        let home = tempfile::tempdir().unwrap();
        let queued = item("forged-projection");
        let generation = seed_queue(home.path(), queued.clone());
        let (segment, writer, join) = ready_writer(home.path()).await;
        record_sidecar_only_once(
            home.path(),
            &segment,
            &writer,
            queued,
            &generation,
            "local_inbox",
            90,
        )
        .await
        .unwrap();
        assert_eq!(read_delivery_history(home.path()).unwrap().len(), 1);

        let path = home.path().join(PROACTIVE_DELIVERED_SIDECAR);
        let mut value: serde_json::Value =
            serde_json::from_slice(std::fs::read(&path).unwrap().strip_suffix(b"\n").unwrap())
                .unwrap();
        value["item"]["body"] = serde_json::Value::String("forged body".to_string());
        let forged_item: ProactiveItem = serde_json::from_value(value["item"].clone()).unwrap();
        let forged_item_bytes = serde_json::to_vec(&forged_item).unwrap();
        value["message_bytes"] = serde_json::json!(forged_item.body.len());
        value["message_sha256"] = serde_json::Value::String(effect_hash(
            b"proactive-egress-message-v1",
            forged_item.body.as_bytes(),
        ));
        value["item_sha256"] =
            serde_json::Value::String(effect_hash(b"proactive-egress-item-v1", &forged_item_bytes));
        let mut forged = serde_json::to_vec(&value).unwrap();
        forged.push(b'\n');
        crate::util::atomic_write::atomic_write_private(&path, &forged).unwrap();

        let error = read_delivery_history(home.path()).unwrap_err();
        assert!(
            format!("{error:#}").contains("authenticated WAL request/result"),
            "{error:#}"
        );
        drop(writer);
        join.await.unwrap().unwrap();
    }

    #[test]
    fn legacy_delivery_schemas_migrate_without_claiming_authentication() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join(PROACTIVE_DELIVERED_SIDECAR);
        let legacy_item = item("legacy-history");
        let statuses = [
            (None, ProactiveEgressOutcome::SidecarOnly),
            (Some("delivered"), ProactiveEgressOutcome::Delivered),
            (Some("failed"), ProactiveEgressOutcome::TransportError),
            (Some("suppressed"), ProactiveEgressOutcome::PolicySuppressed),
            (Some("sidecar_only"), ProactiveEgressOutcome::SidecarOnly),
            (
                Some("crash_recovered"),
                ProactiveEgressOutcome::CrashUnknown,
            ),
        ];
        let mut body = Vec::new();
        for (index, (status, _)) in statuses.iter().enumerate() {
            let mut value = serde_json::json!({
                "delivered_at_unix": 100 + index as i64,
                "item": legacy_item,
            });
            if let Some(status) = status {
                value["status"] = serde_json::Value::String((*status).to_string());
                value["was_failure"] = serde_json::Value::Bool(legacy_item.is_failure);
                value["dedup_key"] = serde_json::Value::String(legacy_item.dedup_key.clone());
                value["source"] = serde_json::Value::String(legacy_item.source.clone());
                value["body"] = serde_json::Value::String(legacy_item.body.clone());
            }
            body.extend_from_slice(serde_json::to_string(&value).unwrap().as_bytes());
            body.push(b'\n');
        }
        crate::util::atomic_write::write_private_create_new_durable(&path, &body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }

        let history = read_delivery_history(home.path()).unwrap();
        assert_eq!(history.len(), statuses.len());
        for (record, (_, expected)) in history.iter().zip(statuses) {
            assert_eq!(record.outcome(), expected);
            assert!(record.is_legacy_unverified());
            assert_eq!(record.verification_label(), "legacy_unverified");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o077,
                0,
                "legacy history permissions must be narrowed through the open handle"
            );
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn broad_modern_history_is_rejected_repeatedly_without_permission_blessing() {
        let home = tempfile::tempdir().unwrap();
        let segment = home.path().join("wal").join("000001.wal");
        let path = home.path().join(PROACTIVE_DELIVERED_SIDECAR);
        let claim = new_claim(item("broad-modern"), "generation", "local_inbox", "", 99).unwrap();
        let result = terminal_result(&claim, ProactiveEgressOutcome::SidecarOnly, None, None, 100);
        append_delivery_record_once(home.path(), &segment, &claim, &result).unwrap();
        make_test_file_broad(&path);

        for _ in 0..2 {
            let error = read_delivery_history(home.path()).unwrap_err();
            assert!(
                format!("{error:#}")
                    .contains("modern proactive history was found in a formerly broad file")
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                assert_ne!(
                    std::fs::metadata(&path).unwrap().permissions().mode() & 0o077,
                    0,
                    "a rejected modern projection must never be permission-blessed"
                );
            }
            #[cfg(windows)]
            assert!(
                crate::wal::win_native::verify_private_dacl(&path).is_err(),
                "a rejected modern projection must never be DACL-blessed"
            );
        }
    }

    #[test]
    fn private_modern_projection_without_authenticated_wal_is_rejected() {
        let home = tempfile::tempdir().unwrap();
        let segment = home.path().join("wal").join("000001.wal");
        let claim = new_claim(
            item("projection-without-wal"),
            "generation",
            "local_inbox",
            "",
            100,
        )
        .unwrap();
        let result = terminal_result(&claim, ProactiveEgressOutcome::SidecarOnly, None, None, 101);
        append_delivery_record_once(home.path(), &segment, &claim, &result).unwrap();
        let error = read_delivery_history(home.path()).unwrap_err();
        assert!(
            format!("{error:#}").contains("proactive history WAL chain"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn legacy_claim_is_pessimistically_armed_and_settled_crash_unknown() {
        let home = tempfile::tempdir().unwrap();
        let mut queued = item("legacy-claimed");
        queued.channel.clear();
        seed_queue(home.path(), queued.clone());
        let claim_dir = ensure_claim_directory(home.path()).unwrap();
        let claim_path = claim_dir
            .display_path
            .join(format!("{}.claimed", legacy_claim_digest(&queued)));
        crate::util::atomic_write::write_private_create_new_durable(
            &claim_path,
            &serde_json::to_vec(&queued).unwrap(),
        )
        .unwrap();
        #[cfg(any(unix, windows))]
        make_test_file_broad(&claim_path);
        let (segment, writer, join) = ready_writer(home.path()).await;

        assert_eq!(
            recover_pending_claims(home.path(), &segment, &writer, 101)
                .await
                .unwrap(),
            1
        );
        assert!(!claim_path.exists());
        assert!(
            ProactiveQueue::load_from(&home.path().join("proactive_queue.json"))
                .unwrap()
                .is_empty()
        );
        let history = read_delivery_history(home.path()).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].outcome(), ProactiveEgressOutcome::CrashUnknown);
        assert_eq!(history[0].target_channel(), "local_inbox");
        assert_eq!(history[0].verification_label(), "wal_verified");
        drop(writer);
        join.await.unwrap().unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn legacy_acl_migration_rejects_swap_before_delete_authority_bind() {
        let home = tempfile::tempdir().unwrap();
        let queued = item("legacy-migration-swap");
        seed_queue(home.path(), queued.clone());
        let claim_dir = ensure_claim_directory(home.path()).unwrap();
        let claim_path = claim_dir
            .display_path
            .join(format!("{}.claimed", legacy_claim_digest(&queued)));
        crate::util::atomic_write::write_private_create_new_durable(
            &claim_path,
            &serde_json::to_vec(&queued).unwrap(),
        )
        .unwrap();
        make_test_file_broad(&claim_path);

        let moved_original = claim_dir.display_path.join("migrated-original.evidence");
        let replacement_stage = home.path().join("same-name-replacement.stage");
        let replacement = b"same-name attacker replacement";
        std::fs::write(&replacement_stage, replacement).unwrap();
        make_test_file_broad(&replacement_stage);

        let hook_claim = claim_path.clone();
        let hook_moved = moved_original.clone();
        let hook_replacement = replacement_stage.clone();
        let result = read_claims_with_legacy_migration_hook(home.path(), 101, move |_| {
            std::fs::rename(&hook_claim, &hook_moved)
                .context("move identity-matched legacy claim after DACL migration")?;
            std::fs::rename(&hook_replacement, &hook_claim)
                .context("install same-name replacement before removal binding")?;
            Ok(())
        });
        let error = match result {
            Ok(_) => panic!("post-migration namespace replacement must fail closed"),
            Err(error) => error,
        };

        assert!(
            format!("{error:#}")
                .contains("regular file changed while its removal authority was being bound"),
            "{error:#}"
        );
        crate::wal::win_native::verify_private_dacl(&moved_original)
            .expect("only the exact opened legacy claim may be hardened");
        assert!(
            crate::wal::win_native::verify_private_dacl(&claim_path).is_err(),
            "the same-name replacement must not be permission-blessed"
        );
        assert_eq!(std::fs::read(&claim_path).unwrap(), replacement);
        assert!(moved_original.exists(), "legacy evidence must be preserved");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn claim_root_and_leaf_authority_survive_namespace_replacement_attempts() {
        let home = tempfile::tempdir().unwrap();
        let delivery_lock = acquire_delivery_lock(home.path()).await.unwrap();
        let claim = new_claim(item("root-identity"), "generation", "local_inbox", "", 120).unwrap();
        let prepared = persist_prepared_claim(&delivery_lock, home.path(), &claim)
            .await
            .unwrap();
        drop(prepared);

        let mut scanned = read_claims(home.path(), 120).unwrap();
        assert_eq!(scanned.len(), 1);
        let claim_root = home.path().join(PROACTIVE_INFLIGHT_DIR);
        let moved_root = home.path().join("proactive_inflight-moved");
        assert!(
            std::fs::rename(&claim_root, &moved_root).is_err(),
            "the retained scan root handle must pin the authoritative Windows directory"
        );

        let canonical = claim_root.join(claim_name(&claim));
        let moved_original = claim_root.join("opened-original.claim");
        let sentinel_stage = claim_root.join("same-name-sentinel.stage");
        let sentinel = b"same-name replacement must survive";
        crate::util::atomic_write::write_private_create_new_durable(&sentinel_stage, sentinel)
            .unwrap();
        std::fs::rename(&canonical, &moved_original).unwrap();
        std::fs::rename(&sentinel_stage, &canonical).unwrap();

        let (bound_claim, _) = scanned.pop().unwrap();
        let removal = bound_claim.remove();
        assert_eq!(std::fs::read(&canonical).unwrap(), sentinel);
        if removal.is_ok() {
            assert!(
                !moved_original.exists(),
                "a successful bound removal must delete the originally opened identity"
            );
        } else {
            assert!(
                moved_original.exists(),
                "a failed bound removal must preserve the original evidence"
            );
        }

        drop(scanned);
        drop(delivery_lock);
        std::fs::rename(&claim_root, &moved_root)
            .expect("claim root becomes movable only after every bound authority is dropped");
    }

    #[test]
    fn rotated_history_replay_is_visible_and_does_not_duplicate_projection() {
        let home = tempfile::tempdir().unwrap();
        let segment = home.path().join("wal").join("000001.wal");
        let first = new_claim(
            item("rotation-first"),
            "generation-1",
            "telegram",
            "one",
            110,
        )
        .unwrap();
        let first_result =
            terminal_result(&first, ProactiveEgressOutcome::SidecarOnly, None, None, 111);
        append_delivery_record_once(home.path(), &segment, &first, &first_result).unwrap();
        let current = home.path().join(PROACTIVE_DELIVERED_SIDECAR);
        let validated = std::fs::read(&current).unwrap();
        rotate_sidecar(home.path(), &current, &validated).unwrap();

        let second = new_claim(
            item("rotation-second"),
            "generation-2",
            "telegram",
            "two",
            112,
        )
        .unwrap();
        let receipt = MessageId("rotation-receipt".to_string());
        let second_result = terminal_result(
            &second,
            ProactiveEgressOutcome::Delivered,
            Some(&receipt),
            None,
            113,
        );
        append_delivery_record_once(home.path(), &segment, &second, &second_result).unwrap();
        append_delivery_record_once(home.path(), &segment, &first, &first_result).unwrap();

        let history = read_delivery_projection_history(home.path()).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].item().dedup_key, "rotation-first");
        assert_eq!(history[1].item().dedup_key, "rotation-second");
    }

    #[cfg(windows)]
    #[test]
    fn broad_legacy_sidecar_rotation_preserves_bytes_and_hardens_archive() {
        let home = tempfile::tempdir().unwrap();
        let current = home.path().join(PROACTIVE_DELIVERED_SIDECAR);
        let evidence = b"legacy operator evidence\n";
        std::fs::write(&current, evidence).unwrap();
        crate::wal::win_native::set_unprotected_current_user_file_dacl_for_test(&current)
            .expect("seed deliberately unprotected owner DACL");
        assert!(
            crate::wal::win_native::verify_private_dacl(&current).is_err(),
            "fixture must enter the privacy-migration branch"
        );

        rotate_sidecar(home.path(), &current, evidence).unwrap();

        assert_eq!(
            std::fs::read(&current).unwrap(),
            b"",
            "rotation must commit a private empty current generation"
        );
        let archives: Vec<_> = std::fs::read_dir(home.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(rotated_sidecar_name)
            })
            .collect();
        assert_eq!(archives.len(), 1);
        assert_eq!(std::fs::read(&archives[0]).unwrap(), evidence);
        crate::wal::win_native::verify_private_dacl(&archives[0])
            .expect("rotated legacy archive must have a private final DACL");
    }

    #[test]
    fn rotation_archives_validated_bytes_despite_same_length_current_path_swap() {
        let home = tempfile::tempdir().unwrap();
        let current = home.path().join(PROACTIVE_DELIVERED_SIDECAR);
        let validated = b"validated-a\n";
        let replacement = b"replacement\n";
        assert_eq!(validated.len(), replacement.len());
        crate::util::atomic_write::write_private_create_new_durable(&current, validated).unwrap();

        rotate_sidecar_with_hooks(
            home.path(),
            &current,
            validated,
            || {
                crate::util::atomic_write::atomic_write_private(&current, replacement)
                    .context("inject same-length pre-rotation path swap")?;
                Ok(())
            },
            || Ok(()),
        )
        .unwrap();

        assert_eq!(std::fs::read(&current).unwrap(), b"");
        let archives: Vec<_> = std::fs::read_dir(home.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(rotated_sidecar_name)
            })
            .collect();
        assert_eq!(archives.len(), 1);
        assert_eq!(
            std::fs::read(&archives[0]).unwrap(),
            validated,
            "rotation must archive bytes authorized through the original read handle"
        );
    }

    #[test]
    fn retry_reconciles_crash_between_archive_and_empty_current_commits() {
        let home = tempfile::tempdir().unwrap();
        let segment = home.path().join("wal").join("000001.wal");
        let first = new_claim(
            item("rotation-crash-first"),
            "generation-1",
            "local_inbox",
            "",
            120,
        )
        .unwrap();
        let first_result =
            terminal_result(&first, ProactiveEgressOutcome::SidecarOnly, None, None, 121);
        append_delivery_record_once(home.path(), &segment, &first, &first_result).unwrap();
        let current = home.path().join(PROACTIVE_DELIVERED_SIDECAR);
        let validated = std::fs::read(&current).unwrap();

        let error = rotate_sidecar_with_hooks(
            home.path(),
            &current,
            &validated,
            || Ok(()),
            || anyhow::bail!("injected crash after archive proof"),
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("injected crash after archive proof"),
            "{error:#}"
        );
        assert_eq!(
            std::fs::read(&current).unwrap(),
            validated,
            "injected crash must leave the old current generation intact"
        );

        let second = new_claim(
            item("rotation-crash-second"),
            "generation-2",
            "local_inbox",
            "",
            122,
        )
        .unwrap();
        let second_result = terminal_result(
            &second,
            ProactiveEgressOutcome::SidecarOnly,
            None,
            None,
            123,
        );
        append_delivery_record_once(home.path(), &segment, &second, &second_result)
            .expect("retry must reconcile the exact duplicate rotation shape");

        let history = read_delivery_projection_history(home.path()).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].item().dedup_key, "rotation-crash-first");
        assert_eq!(history[1].item().dedup_key, "rotation-crash-second");
        let current_rows = std::fs::read(&current).unwrap();
        assert_eq!(
            current_rows
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .count(),
            1,
            "reconciliation must leave exactly the new row in current history"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn retry_reconciles_strict_broad_legacy_rotation_crash() {
        let home = tempfile::tempdir().unwrap();
        let segment = home.path().join("wal").join("000001.wal");
        let current = home.path().join(PROACTIVE_DELIVERED_SIDECAR);
        let legacy_item = item("broad-legacy-rotation");
        let mut legacy = serde_json::to_vec(&serde_json::json!({
            "delivered_at_unix": 200,
            "item": legacy_item,
        }))
        .unwrap();
        legacy.push(b'\n');
        crate::util::atomic_write::write_private_create_new_durable(&current, &legacy).unwrap();
        make_test_file_broad(&current);

        let error = rotate_sidecar_with_hooks(
            home.path(),
            &current,
            &legacy,
            || Ok(()),
            || anyhow::bail!("injected broad legacy crash after archive proof"),
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("injected broad legacy crash"),
            "{error:#}"
        );

        let next = new_claim(
            item("after-broad-legacy-crash"),
            "generation",
            "local_inbox",
            "",
            202,
        )
        .unwrap();
        let next_result =
            terminal_result(&next, ProactiveEgressOutcome::SidecarOnly, None, None, 203);
        append_delivery_record_once(home.path(), &segment, &next, &next_result)
            .expect("strict legacy-only duplicate must recover before history evaluation");

        let history = read_delivery_projection_history(home.path()).unwrap();
        assert_eq!(history.len(), 2);
        assert!(history[0].is_legacy_unverified());
        assert_eq!(history[0].item().dedup_key, "broad-legacy-rotation");
        assert_eq!(history[1].item().dedup_key, "after-broad-legacy-crash");
        let archive = delivery_history_paths(home.path())
            .unwrap()
            .into_iter()
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(rotated_sidecar_name)
            })
            .unwrap();
        assert_eq!(std::fs::read(&archive).unwrap(), legacy);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&archive).unwrap().permissions().mode() & 0o077,
                0
            );
        }
        #[cfg(windows)]
        crate::wal::win_native::verify_private_dacl(&archive)
            .expect("recovered legacy archive must remain private");
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn broad_modern_duplicate_is_not_reconciled_as_legacy_rotation() {
        let home = tempfile::tempdir().unwrap();
        let segment = home.path().join("wal").join("000001.wal");
        let current = home.path().join(PROACTIVE_DELIVERED_SIDECAR);
        let claim = new_claim(
            item("broad-modern-reconcile"),
            "generation",
            "local_inbox",
            "",
            204,
        )
        .unwrap();
        let result = terminal_result(&claim, ProactiveEgressOutcome::SidecarOnly, None, None, 205);
        append_delivery_record_once(home.path(), &segment, &claim, &result).unwrap();
        let modern = std::fs::read(&current).unwrap();
        let archive = next_rotated_sidecar_path(home.path()).unwrap();
        crate::util::atomic_write::write_private_create_new_durable(&archive, &modern).unwrap();
        make_test_file_broad(&current);

        let error = reconcile_interrupted_sidecar_rotation(home.path(), &current).unwrap_err();
        assert!(
            format!("{error:#}")
                .contains("modern proactive history was found in a formerly broad file"),
            "{error:#}"
        );
        assert_eq!(
            std::fs::read(&current).unwrap(),
            modern,
            "broad modern evidence must not be cleared or permission-blessed"
        );
    }

    #[test]
    fn monotonic_archive_ids_survive_clock_rollback_retention_and_followup_prune() {
        let home = tempfile::tempdir().unwrap();
        let current = home.path().join(PROACTIVE_DELIVERED_SIDECAR);
        let base = uuid_v7_unix_millis(&uuid::Uuid::now_v7()) + 86_400_000;
        for index in 0..MAX_ROTATED_SIDECARS {
            let identifier = uuid_v7_with_unix_millis(
                uuid::Uuid::now_v7(),
                base + u64::try_from(index).unwrap(),
            )
            .unwrap();
            let archive = home
                .path()
                .join(format!("proactive_delivered.{identifier}.jsonl"));
            crate::util::atomic_write::write_private_create_new_durable(
                &archive,
                format!("future fixture {index}\n").as_bytes(),
            )
            .unwrap();
        }

        let first = b"validated after clock rollback\n";
        crate::util::atomic_write::write_private_create_new_durable(&current, first).unwrap();
        rotate_sidecar(home.path(), &current, first).unwrap();
        let first_archive = delivery_history_paths(home.path())
            .unwrap()
            .into_iter()
            .find(|path| std::fs::read(path).is_ok_and(|bytes| bytes == first))
            .expect("fresh monotonic archive must survive first retention pass");
        let first_identifier =
            rotated_sidecar_uuid(first_archive.file_name().unwrap().to_str().unwrap()).unwrap();
        assert!(uuid_v7_unix_millis(&first_identifier) >= base + MAX_ROTATED_SIDECARS as u64);

        let second = b"second validated generation\n";
        crate::util::atomic_write::atomic_write_private(&current, second).unwrap();
        rotate_sidecar(home.path(), &current, second).unwrap();
        assert_eq!(
            std::fs::read(&first_archive).unwrap(),
            first,
            "a follow-up prune must retain the previous monotonic successor"
        );
        assert!(
            delivery_history_paths(home.path())
                .unwrap()
                .into_iter()
                .any(|path| std::fs::read(path).is_ok_and(|bytes| bytes == second)),
            "follow-up rotation must retain its own monotonic successor"
        );
    }

    #[test]
    fn exact_sidecar_republication_rejects_same_length_namespace_replacement() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join(PROACTIVE_DELIVERED_SIDECAR);
        let expected = b"validated-a\n";
        let replacement = b"replacement\n";
        assert_eq!(expected.len(), replacement.len());

        let error =
            republish_validated_sidecar_bytes_with_hook(home.path(), &path, expected, || {
                crate::util::atomic_write::atomic_write_private(&path, replacement)
                    .context("inject same-length sidecar namespace replacement")?;
                crate::util::atomic_write::sync_parent_directory_required(&path)
                    .context("commit injected sidecar namespace replacement")?;
                Ok(())
            })
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("changed after atomic publication"),
            "{error:#}"
        );
        assert_eq!(std::fs::read(path).unwrap(), replacement);
    }

    #[cfg(unix)]
    #[test]
    fn sidecar_and_claim_symlinks_are_rejected_without_following_them() {
        use std::os::unix::fs::symlink;

        let history_home = tempfile::tempdir().unwrap();
        let outside_history = history_home.path().join("outside-history.jsonl");
        std::fs::write(&outside_history, b"{}\n").unwrap();
        symlink(
            &outside_history,
            history_home.path().join(PROACTIVE_DELIVERED_SIDECAR),
        )
        .unwrap();
        assert!(read_delivery_history(history_home.path()).is_err());

        let claim_home = tempfile::tempdir().unwrap();
        let claim_dir = ensure_claim_directory(claim_home.path()).unwrap();
        let queued = item("symlink-claim");
        let outside_claim = claim_home.path().join("outside-claim.json");
        std::fs::write(&outside_claim, serde_json::to_vec(&queued).unwrap()).unwrap();
        let claim_path = claim_dir
            .display_path
            .join(format!("{}.claimed", legacy_claim_digest(&queued)));
        symlink(&outside_claim, &claim_path).unwrap();
        assert!(read_claims(claim_home.path(), 120).is_err());
        assert!(
            claim_path.exists(),
            "suspicious link evidence must be preserved"
        );
    }

    #[test]
    fn torn_legacy_sidecar_tail_is_preserved_and_blocks_new_projection() {
        let home = tempfile::tempdir().unwrap();
        let segment = home.path().join("wal").join("000001.wal");
        let path = home.path().join(PROACTIVE_DELIVERED_SIDECAR);
        let torn = br#"{"delivered_at_unix":1,"item":{"priority":50"#;
        crate::util::atomic_write::write_private_create_new_durable(&path, torn).unwrap();
        let archives: Vec<_> = (0..MAX_ROTATED_SIDECARS + 2)
            .map(|index| {
                let archive = home.path().join(format!(
                    "proactive_delivered.{}.jsonl",
                    uuid::Uuid::now_v7()
                ));
                let evidence = format!("archive evidence {index}\n").into_bytes();
                crate::util::atomic_write::write_private_create_new_durable(&archive, &evidence)
                    .unwrap();
                (archive, evidence)
            })
            .collect();
        let claim = new_claim(item("torn-tail"), "generation", "local_inbox", "", 90).unwrap();
        let result = terminal_result(&claim, ProactiveEgressOutcome::SidecarOnly, None, None, 90);

        let error =
            append_delivery_record_once(home.path(), &segment, &claim, &result).unwrap_err();
        assert!(format!("{error:#}").contains("torn legacy tail"));
        assert_eq!(std::fs::read(path).unwrap(), torn);
        for (archive, evidence) in archives {
            assert_eq!(
                std::fs::read(&archive).unwrap(),
                evidence,
                "tail preflight must run before retention pruning: {}",
                archive.display()
            );
        }
    }

    #[test]
    fn orphan_claim_stage_is_removed_without_becoming_authority() {
        let home = tempfile::tempdir().unwrap();
        let dir = ensure_claim_directory(home.path()).unwrap();
        let stages = [
            dir.display_path.join(format!(
                "{}.claimed.{}.tmp",
                "a".repeat(64),
                uuid::Uuid::now_v7().simple()
            )),
            dir.display_path
                .join(format!(".neoth-atomic-{}", uuid::Uuid::new_v4().simple())),
        ];
        for stage in &stages {
            crate::util::atomic_write::write_private_create_new_durable(stage, b"partial").unwrap();
        }
        assert!(read_claims(home.path(), 100).unwrap().is_empty());
        assert!(stages.iter().all(|stage| !stage.exists()));
    }

    #[test]
    fn suspicious_claim_is_preserved_and_blocks_recovery_before_wal_scan() {
        let home = tempfile::tempdir().unwrap();
        let dir = ensure_claim_directory(home.path()).unwrap();
        let path = dir.display_path.join(format!("{}.claimed", "a".repeat(64)));
        crate::util::atomic_write::write_private_create_new_durable(&path, b"not-json").unwrap();
        assert!(read_claims(home.path(), 7).is_err());
        assert!(path.exists(), "suspicious evidence must be preserved");
    }

    #[test]
    fn extended_egress_frames_are_immediate_sync() {
        assert!(crate::wal::events::needs_immediate_sync(
            EVENT_TYPE_EXTENDED
        ));
    }

    #[test]
    fn v2_deadline_is_tamper_evident_and_v1_preimage_stays_compatible() {
        assert_eq!(
            deadline_after(100, Duration::from_secs(60)).unwrap(),
            160,
            "a second-granular admission must not add a hidden rounding second"
        );
        let sampled = chrono::DateTime::<chrono::Utc>::from_timestamp(100, 1_000_000)
            .expect("fixed admission sample");
        assert!(
            wall_budget_from_admission_sample(160, sampled).unwrap() < Duration::from_secs(60),
            "the live wall-clock budget is never longer than configuration"
        );
        let mut v2 = new_claim_with_deadline(
            item("deadline-binding"),
            "generation",
            "telegram",
            "operator",
            100,
            160,
        )
        .unwrap();
        let v2_binding = v2.binding_sha256.clone();
        assert_eq!(intent_frame(&v2).attempt_deadline_unix, Some(160));
        v2.attempt_deadline_unix = Some(161);
        assert_ne!(binding_hash(&v2), v2_binding);
        assert!(validate_claim(&v2, &claim_name(&v2)).is_err());

        let mut v1 =
            new_claim(item("legacy-v1"), "generation", "telegram", "operator", 100).unwrap();
        v1.version = LEGACY_CLAIM_VERSION;
        v1.attempt_deadline_unix = None;
        v1.binding_sha256 = binding_hash(&v1);
        validate_claim(&v1, &claim_name(&v1)).unwrap();
        let v1_intent = intent_frame(&v1);
        assert_eq!(
            v1_intent.proactive_binding_version,
            LEGACY_WAL_BINDING_VERSION
        );
        assert_eq!(v1_intent.attempt_deadline_unix, None);
        validate_intent_frame(&v1_intent).unwrap();
    }

    #[tokio::test]
    async fn outer_cancellation_retains_and_structurally_reaps_transport_handle() {
        let baseline = cancelled_transport_reap_queue_len();
        let home = tempfile::tempdir().unwrap();
        let queued = item("reap-queue-test");
        let generation = seed_queue(home.path(), queued.clone());
        let (_segment, writer, join) = ready_writer(home.path()).await;
        let (claim_file, claim) =
            armed_v2_claim_with_evidence(home.path(), &writer, queued, &generation, 100, 160).await;
        let lease = match ArmedClaimLease::try_acquire(&claim_file, &claim).unwrap() {
            ArmedClaimLeaseProbe::Acquired(lease) => Arc::new(lease),
            ArmedClaimLeaseProbe::Busy => panic!("fresh test claim lease must be acquirable"),
        };
        let channel = Arc::new(BlockingChannel::new());
        let attempt = OwnedTransportAttempt::start(
            TransportIntentRegistration::acquire(&claim.intent_id),
            channel.clone(),
            "operator".to_string(),
            "body".to_string(),
            tokio::time::Instant::now() + Duration::from_secs(60),
            Arc::clone(&lease),
        );
        channel.entered.notified().await;
        drop(attempt);
        assert_eq!(
            cancelled_transport_reap_queue_len(),
            baseline + 1,
            "Drop must retain the aborted JoinHandle for structured reaping"
        );
        reap_cancelled_transport_attempts().await.unwrap();
        assert_eq!(
            cancelled_transport_reap_queue_len(),
            baseline,
            "recovery/admission supervisor must observe and drain cancellation"
        );
        assert!(
            !transport_is_locally_active(&claim.intent_id),
            "only a joined/reaped task may release its local claim authority"
        );
        assert_eq!(
            Arc::strong_count(&lease),
            1,
            "reaping must release the provider-held Armed lease Arc"
        );
        drop(lease);
        drop(claim_file);
        drop(writer);
        join.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn completed_transport_stays_active_until_terminal_authority_handoff() {
        let home = tempfile::tempdir().unwrap();
        let queued = item("terminal-handoff-test");
        let generation = seed_queue(home.path(), queued.clone());
        let (_segment, writer, join) = ready_writer(home.path()).await;
        let (claim_file, claim) =
            armed_v2_claim_with_evidence(home.path(), &writer, queued, &generation, 100, 160).await;
        let lease = match ArmedClaimLease::try_acquire(&claim_file, &claim).unwrap() {
            ArmedClaimLeaseProbe::Acquired(lease) => Arc::new(lease),
            ArmedClaimLeaseProbe::Busy => panic!("fresh test claim lease must be acquirable"),
        };
        let channel: Arc<dyn Channel> = Arc::new(CountingChannel::new());
        let mut attempt = OwnedTransportAttempt::start(
            TransportIntentRegistration::acquire(&claim.intent_id),
            channel,
            "operator".to_string(),
            "body".to_string(),
            tokio::time::Instant::now() + Duration::from_secs(60),
            Arc::clone(&lease),
        );
        assert!(matches!(
            attempt
                .finish_before(tokio::time::Instant::now() + Duration::from_secs(60))
                .await,
            OwnedTransportOutcome::Completed(Ok(_))
        ));
        assert!(
            transport_is_locally_active(&claim.intent_id),
            "provider completion alone must not let recovery erase known evidence"
        );
        assert_eq!(
            Arc::strong_count(&lease),
            2,
            "owner lease must survive provider join until Result WAL authority"
        );
        attempt.release_after_terminal_result();
        assert!(!transport_is_locally_active(&claim.intent_id));
        assert_eq!(Arc::strong_count(&lease), 1);
        drop(lease);
        drop(claim_file);
        drop(writer);
        join.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn recovery_retains_only_an_unexpired_v2_armed_attempt() {
        let home = tempfile::tempdir().unwrap();
        let queued = item("retain-v2-armed");
        let generation = seed_queue(home.path(), queued.clone());
        let (segment, writer, join) = ready_writer(home.path()).await;
        let delivery_lock = acquire_delivery_lock(home.path()).await.unwrap();
        let prepared =
            new_claim_with_deadline(queued, &generation, "telegram", "operator", 100, 160).unwrap();
        let claim_file = persist_prepared_claim(&delivery_lock, home.path(), &prepared)
            .await
            .unwrap();
        append_intent(&delivery_lock, &writer, &prepared)
            .await
            .unwrap();
        let armed = claim_in_phase(&prepared, ProactiveEgressPhase::Armed);
        persist_armed_claim(&delivery_lock, &claim_file, &armed)
            .await
            .unwrap();
        append_armed(&delivery_lock, &writer, &armed).await.unwrap();
        let claim_path = claim_file.display_path.clone();
        drop(claim_file);
        drop(delivery_lock);

        assert_eq!(
            recover_pending_claims(home.path(), &segment, &writer, 120)
                .await
                .unwrap(),
            0
        );
        assert!(
            claim_path.exists(),
            "unexpired v2 attempt must remain durable"
        );
        assert!(read_delivery_history(home.path()).unwrap().is_empty());

        assert_eq!(
            recover_pending_claims(home.path(), &segment, &writer, 160)
                .await
                .unwrap(),
            1
        );
        assert!(
            !claim_path.exists(),
            "expired v2 attempt is terminally reconciled"
        );
        assert_eq!(
            read_delivery_history(home.path()).unwrap()[0].outcome(),
            ProactiveEgressOutcome::CrashUnknown
        );
        drop(writer);
        join.await.unwrap().unwrap();
    }

    /// This test reinvokes the test binary as a second process. The child owns
    /// the exact claim-file lease, while the parent deliberately advances its
    /// recovery wall clock to the persisted deadline. That must defer instead
    /// of fabricating CrashUnknown; once the child exits, the OS releases the
    /// lease and the parent can reconcile exactly once.
    #[tokio::test]
    async fn cross_process_armed_claim_lease_defers_wall_forward_and_releases_on_exit() {
        const CHILD_ROLE: &str = "NEOTH_EGRESS_ARMED_LEASE_CHILD";
        const CHILD_HOME: &str = "NEOTH_EGRESS_ARMED_LEASE_HOME";
        const CHILD_READY: &str = "armed-lease-child.ready";
        const CHILD_RELEASE: &str = "armed-lease-child.release";

        if std::env::var_os(CHILD_ROLE).is_some() {
            let home = PathBuf::from(std::env::var_os(CHILD_HOME).unwrap());
            let (claim_file, claim) = read_claims(&home, 160)
                .unwrap()
                .into_iter()
                .next()
                .expect("child must observe parent Armed claim");
            let _lease = match ArmedClaimLease::try_acquire(&claim_file, &claim).unwrap() {
                ArmedClaimLeaseProbe::Acquired(lease) => lease,
                ArmedClaimLeaseProbe::Busy => panic!("child must own a fresh cross-process lease"),
            };
            std::fs::write(home.join(CHILD_READY), b"ready").unwrap();
            let release = home.join(CHILD_RELEASE);
            let started = std::time::Instant::now();
            while !release.exists() {
                assert!(
                    started.elapsed() < Duration::from_secs(10),
                    "parent did not release cross-process lease child"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            // Returning drops the OS lock as an abrupt child-process exit
            // would; the parent verifies another process can take it.
            return;
        }

        let home = tempfile::tempdir().unwrap();
        let queued = item("cross-process-lease");
        let generation = seed_queue(home.path(), queued.clone());
        let (segment, writer, join) = ready_writer(home.path()).await;
        let (claim_file, claim) =
            armed_v2_claim_with_evidence(home.path(), &writer, queued, &generation, 100, 160).await;
        let claim_path = claim_file.display_path.clone();
        drop(claim_file);

        // libtest reports names relative to the crate root, while
        // `module_path!()` includes the crate name. Build an exact filter
        // that works for the self-reexec child on every crate rename.
        let test_module = module_path!()
            .strip_prefix(concat!(env!("CARGO_CRATE_NAME"), "::"))
            .unwrap_or(module_path!());
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(format!(
                "{}::cross_process_armed_claim_lease_defers_wall_forward_and_releases_on_exit",
                test_module
            ))
            .arg("--nocapture")
            .env(CHILD_ROLE, "1")
            .env(CHILD_HOME, home.path())
            .spawn()
            .expect("spawn cross-process Armed lease holder");
        let ready = home.path().join(CHILD_READY);
        let started = std::time::Instant::now();
        while !ready.exists() {
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "cross-process Armed lease child did not become ready"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let dedup_lock = acquire_delivery_lock(home.path()).await.unwrap();
        assert!(
            has_unexpired_inflight_dedup(&dedup_lock, home.path(), &claim.dedup_sha256, 160)
                .await
                .unwrap(),
            "Busy exact Armed lease must retain dedup despite wall-clock expiry"
        );
        drop(dedup_lock);
        assert_eq!(
            recover_pending_claims(home.path(), &segment, &writer, 160)
                .await
                .unwrap(),
            0,
            "Busy exact Armed lease must defer CrashUnknown after wall-clock forward"
        );
        assert!(claim_path.exists());

        std::fs::write(home.path().join(CHILD_RELEASE), b"release").unwrap();
        assert!(child.wait().unwrap().success());
        assert_eq!(
            recover_pending_claims(home.path(), &segment, &writer, 160)
                .await
                .unwrap(),
            1,
            "lease release on child exit must permit one terminal reconciliation"
        );
        assert_eq!(
            read_delivery_history(home.path()).unwrap()[0].outcome(),
            ProactiveEgressOutcome::CrashUnknown
        );
        drop(writer);
        join.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn v1_armed_without_result_is_immediately_crash_unknown() {
        let home = tempfile::tempdir().unwrap();
        let queued = item("legacy-v1-recovery");
        let generation = seed_queue(home.path(), queued.clone());
        let (segment, writer, join) = ready_writer(home.path()).await;
        let delivery_lock = acquire_delivery_lock(home.path()).await.unwrap();
        let mut prepared = new_claim(queued, &generation, "telegram", "operator", 100).unwrap();
        prepared.version = LEGACY_CLAIM_VERSION;
        prepared.attempt_deadline_unix = None;
        prepared.binding_sha256 = binding_hash(&prepared);
        let claim_file = persist_prepared_claim(&delivery_lock, home.path(), &prepared)
            .await
            .unwrap();
        append_intent(&delivery_lock, &writer, &prepared)
            .await
            .unwrap();
        let armed = claim_in_phase(&prepared, ProactiveEgressPhase::Armed);
        persist_armed_claim(&delivery_lock, &claim_file, &armed)
            .await
            .unwrap();
        append_armed(&delivery_lock, &writer, &armed).await.unwrap();
        drop(claim_file);
        drop(delivery_lock);

        assert_eq!(
            recover_pending_claims(home.path(), &segment, &writer, 101)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            read_delivery_history(home.path()).unwrap()[0].outcome(),
            ProactiveEgressOutcome::CrashUnknown
        );
        drop(writer);
        join.await.unwrap().unwrap();
    }
}
