//! Durable transaction journal for consent-marker mutations.
//!
//! Consent changes are security-relevant permission changes. A one-shot CLI
//! cannot safely append to the daemon-owned WAL segment, and a process can
//! crash between preparing a marker update, changing the marker, and receiving
//! the WAL acknowledgement. This module gives that sequence one durable,
//! recoverable operation record.
//!
//! One operation is allowed at a time. `begin` acquires both the process mutex
//! and the cross-process file lock and returns a transaction guard which keeps
//! them until the caller has delivered the prepared phase, committed or
//! aborted the marker update, and delivered the terminal phase. A crash drops
//! the OS lock but leaves `pending-mutation.json`; `recover_pending` compares
//! its exact SHA-256 marker bindings with the current provider marker and
//! resolves a prepared operation to committed or aborted. Any third state is a
//! fail-closed conflict and the journal remains for operator inspection.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cli::init::ProviderKind;
use crate::consent::{self, ConsentMarkerBinding, ConsentMarkerUpdate};
use crate::wal::events::{EVENT_TYPE_CONSENT_GRANTED, EVENT_TYPE_CONSENT_REVOKED};

const JOURNAL_VERSION: u32 = 1;
const MAX_AUDIT_PAYLOAD_BYTES: usize = 2_800;
const MAX_JOURNAL_BYTES: u64 = 16 * 1024;
const QUEUED_AUDIT_PREFIX: &str = "pending-audit-";
const MAX_QUEUED_AUDITS: usize = 4_096;

/// Mutex-first ordering is shared with every other NEOTH durable outbox.
static JOURNAL_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConsentMutationAction {
    Grant,
    Revoke,
}

impl ConsentMutationAction {
    fn event_type(self) -> u8 {
        match self {
            Self::Grant => EVENT_TYPE_CONSENT_GRANTED,
            Self::Revoke => EVENT_TYPE_CONSENT_REVOKED,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Grant => "grant",
            Self::Revoke => "revoke",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConsentMutationSource {
    Cli,
    Slash,
    Gui,
    Tty,
    Wizard,
}

impl ConsentMutationSource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Slash => "slash",
            // `--source gui` is a subprocess routing assertion, not an
            // authenticated desktop principal. Keep the audit label honest;
            // request/challenge hashes provide the actual binding.
            Self::Gui => "gui_caller_claimed",
            Self::Tty => "tty",
            Self::Wizard => "wizard",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConsentMutationPhase {
    Prepared,
    Committed,
    Aborted,
}

impl ConsentMutationPhase {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Committed => "committed",
            Self::Aborted => "aborted",
        }
    }

    fn is_terminal(self) -> bool {
        matches!(self, Self::Committed | Self::Aborted)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MarkerBinding {
    exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
}

impl MarkerBinding {
    fn from_update_source(update: &ConsentMarkerUpdate) -> Self {
        Self {
            exists: update.source_exists(),
            sha256: update.source_sha256().map(str::to_owned),
        }
    }

    fn from_update_target(update: &ConsentMarkerUpdate) -> Self {
        Self {
            exists: update.target_exists(),
            sha256: update.target_sha256().map(str::to_owned),
        }
    }

    fn matches_snapshot(&self, current: &ConsentMarkerBinding) -> bool {
        self.exists == current.exists() && self.sha256.as_deref() == current.sha256()
    }
}

/// The on-disk schema. The operation id is UUIDv7; the audit event id is a
/// deterministic SHA-256 binding of the complete operation plus its phase.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingConsentMutation {
    version: u32,
    operation_id: String,
    audit_event_id: String,
    provider: ProviderKind,
    action: ConsentMutationAction,
    source: ConsentMutationSource,
    endpoint_origins: Vec<String>,
    source_binding: MarkerBinding,
    target_binding: MarkerBinding,
    phase: ConsentMutationPhase,
    required_audit: bool,
    ts_unix: i64,
}

impl PendingConsentMutation {
    pub(crate) fn operation_id(&self) -> &str {
        &self.operation_id
    }

    #[cfg(test)]
    fn audit_event_id(&self) -> &str {
        &self.audit_event_id
    }

    fn set_phase(&mut self, phase: ConsentMutationPhase) {
        self.phase = phase;
        self.audit_event_id = derive_audit_event_id(self);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AuditDelivery {
    Delivered,
    /// Optional posture only: the journal is still durable and a later
    /// recovery can retry the exact same phase and audit-event id.
    Pending {
        error: String,
    },
}

impl AuditDelivery {
    pub(crate) fn is_pending(&self) -> bool {
        matches!(self, Self::Pending { .. })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryOutcome {
    None,
    Recovered {
        operation_id: String,
        phase: ConsentMutationPhase,
        delivery: AuditDelivery,
    },
}

/// Holds the journal's process and cross-process locks for the complete
/// prepare -> marker CAS -> terminal-audit transaction.
pub(crate) struct ConsentMutationTransaction {
    home: PathBuf,
    record: PendingConsentMutation,
    cleared: bool,
    // Struct fields drop in declaration order: release the OS lock before the
    // process-local mutex, matching the inverse of acquisition.
    _file_guard: std::fs::File,
    _process_guard: tokio::sync::MutexGuard<'static, ()>,
}

impl ConsentMutationTransaction {
    pub(crate) fn record(&self) -> &PendingConsentMutation {
        &self.record
    }

    /// Deliver the current phase. A successful terminal delivery removes the
    /// journal only after the daemon/local writer acknowledged its append.
    pub(crate) async fn deliver_phase(&mut self) -> Result<AuditDelivery> {
        if self.cleared {
            anyhow::bail!(
                "consent mutation {} is already durably acknowledged",
                self.record.operation_id
            );
        }
        let delivery = deliver_record(&self.home, &self.record).await?;
        if matches!(delivery, AuditDelivery::Delivered) && self.record.phase.is_terminal() {
            clear_journal(&self.home)?;
            self.cleared = true;
        }
        Ok(delivery)
    }

    /// Persist the committed phase only when the provider marker currently
    /// equals the prepared target binding.
    pub(crate) fn mark_committed(&mut self) -> Result<()> {
        self.transition_committed()
    }

    /// Record that a committed marker was rolled back after its required
    /// terminal audit failed. This is the only legal terminal-to-terminal
    /// transition: the exact source binding must already be restored.
    pub(crate) fn mark_rolled_back_after_commit(&mut self) -> Result<()> {
        if self.cleared {
            anyhow::bail!(
                "consent mutation {} is already durably acknowledged",
                self.record.operation_id
            );
        }
        if self.record.phase != ConsentMutationPhase::Committed {
            anyhow::bail!(
                "consent mutation {} cannot record a post-commit rollback from {}",
                self.record.operation_id,
                self.record.phase.as_str()
            );
        }
        let current = consent::marker_snapshot_binding(&self.home, self.record.provider)
            .context("snapshot consent marker after post-commit rollback")?;
        if !self.record.source_binding.matches_snapshot(&current) {
            anyhow::bail!(
                "consent mutation {} marker binding does not match its restored source state; \
                 refusing to mark the durable journal aborted",
                self.record.operation_id
            );
        }
        self.record.set_phase(ConsentMutationPhase::Aborted);
        persist_record(&self.home, &self.record)
    }

    fn transition_committed(&mut self) -> Result<()> {
        if self.cleared {
            anyhow::bail!(
                "consent mutation {} is already durably acknowledged",
                self.record.operation_id
            );
        }
        if self.record.phase != ConsentMutationPhase::Prepared {
            anyhow::bail!(
                "consent mutation {} cannot transition from {} to {}",
                self.record.operation_id,
                self.record.phase.as_str(),
                ConsentMutationPhase::Committed.as_str()
            );
        }
        let current = consent::marker_snapshot_binding(&self.home, self.record.provider)
            .context("snapshot consent marker before terminal journal transition")?;
        if !self.record.target_binding.matches_snapshot(&current) {
            anyhow::bail!(
                "consent mutation {} marker binding conflicts with its expected target state; \
                 refusing to rewrite the durable journal",
                self.record.operation_id
            );
        }
        self.record.set_phase(ConsentMutationPhase::Committed);
        persist_record(&self.home, &self.record)
    }
}

/// Fixed, operator-inspectable journal path.
pub(crate) fn journal_path(home: &Path) -> PathBuf {
    home.join("consent").join("pending-mutation.json")
}

fn queued_audit_path(home: &Path, operation_id: &str) -> PathBuf {
    home.join("consent")
        .join(format!("{QUEUED_AUDIT_PREFIX}{operation_id}.json"))
}

/// Runtime fail-closed guard for provider dispatch.
///
/// The journal is atomically replaced, so an unlocked read sees either the
/// complete old or complete new record. Waiting on the transaction's OS lock
/// here would deadlock a provider call made by the mutation owner itself; the
/// phase/binding contract is the synchronization boundary instead.
pub(crate) fn blocks_provider_use(home: &Path, provider: ProviderKind) -> Result<bool> {
    if let Some(record) = read_record_if_present(home)?
        && record.provider == provider
        && record_blocks_provider_use(&record)
    {
        return Ok(true);
    }
    Ok(read_queued_records(home)?
        .into_iter()
        .any(|(_, record)| record.provider == provider && record_blocks_provider_use(&record)))
}

pub(crate) fn has_pending_audit(home: &Path, provider: ProviderKind) -> Result<bool> {
    if read_record_if_present(home)?.is_some_and(|record| record.provider == provider) {
        return Ok(true);
    }
    Ok(read_queued_records(home)?
        .into_iter()
        .any(|(_, record)| record.provider == provider))
}

/// Whether the single active mutation journal currently prevents opening a
/// new authority-increasing transaction. Optional terminal records can be
/// moved to the durable audit queue; Prepared or required Committed records
/// must be recovered first.
pub(crate) fn blocks_new_grant(home: &Path) -> Result<bool> {
    Ok(read_record_if_present(home)?.is_some_and(|record| record_blocks_provider_use(&record)))
}

fn record_blocks_provider_use(record: &PendingConsentMutation) -> bool {
    match record.phase {
        // Marker state is intentionally ambiguous until recovery or the owner
        // writes a terminal phase.
        ConsentMutationPhase::Prepared => true,
        // Required audit is part of the permission contract, so a committed
        // marker cannot be consumed until that audit receives an ACK.
        ConsentMutationPhase::Committed => record.required_audit,
        // No target permission survived an aborted transaction.
        ConsentMutationPhase::Aborted => false,
    }
}

fn lock_path(home: &Path) -> PathBuf {
    home.join("consent").join("pending-mutation.lock")
}

/// Begin one durable mutation and retain both serialization locks in the
/// returned guard. Existing pending work must be recovered first.
pub(crate) async fn begin(
    home: &Path,
    update: &ConsentMarkerUpdate,
    action: ConsentMutationAction,
    source: ConsentMutationSource,
    endpoint_origins: Vec<String>,
    required_audit: bool,
) -> Result<ConsentMutationTransaction> {
    if !update.changed() {
        anyhow::bail!(
            "consent mutation for `{}` is a no-op and must not create an audit transaction",
            consent::slug(update.kind())
        );
    }

    let process_guard = JOURNAL_MUTEX.lock().await;
    let file_guard = acquire_file_lock(home).await?;
    if let Some(mut existing) = read_record_if_present(home)? {
        if action == ConsentMutationAction::Revoke || !record_blocks_provider_use(&existing) {
            // Authority reduction must not depend on audit transport
            // availability. Likewise, an optional terminal record must not
            // monopolize the single active journal and block an unrelated
            // grant. Resolve only from exact marker bindings, then move its
            // terminal audit obligation aside durably.
            reconcile_record_with_marker(home, &mut existing)?;
            archive_nonblocking_terminal_record(home, &existing)?;
        } else {
            anyhow::bail!(
                "pending consent mutation {} ({}/{}) must be recovered before another mutation",
                existing.operation_id,
                consent::slug(existing.provider),
                existing.phase.as_str()
            );
        }
    }
    let current = consent::marker_snapshot_binding(home, update.kind())
        .context("revalidate consent marker after acquiring mutation journal locks")?;
    let expected_source = MarkerBinding::from_update_source(update);
    if !expected_source.matches_snapshot(&current) {
        anyhow::bail!(
            "consent marker for `{}` changed after the mutation was prepared; \
             refusing to persist stale intent",
            consent::slug(update.kind())
        );
    }

    let mut endpoint_origins = endpoint_origins;
    endpoint_origins.sort();
    endpoint_origins.dedup();
    let mut record = PendingConsentMutation {
        version: JOURNAL_VERSION,
        operation_id: uuid::Uuid::now_v7().to_string(),
        audit_event_id: String::new(),
        provider: update.kind(),
        action,
        source,
        endpoint_origins,
        source_binding: MarkerBinding::from_update_source(update),
        target_binding: MarkerBinding::from_update_target(update),
        phase: ConsentMutationPhase::Prepared,
        required_audit,
        ts_unix: crate::time::now_unix_i64(),
    };
    record.audit_event_id = derive_audit_event_id(&record);
    persist_record(home, &record)?;

    Ok(ConsentMutationTransaction {
        home: home.to_path_buf(),
        record,
        cleared: false,
        _file_guard: file_guard,
        _process_guard: process_guard,
    })
}

/// Recover a journal left by a crashed process. A prepared record is resolved
/// solely by comparing the current marker with its captured bindings:
/// source -> aborted, target -> committed, anything else -> conflict.
pub(crate) async fn recover_pending(home: &Path) -> Result<RecoveryOutcome> {
    recover_pending_inner(home, None).await
}

/// Daemon-start recovery path. It appends through the daemon's already-owned
/// writer directly, avoiding the startup interval in which the pidfile is live
/// but the loopback audit-RPC listener is not yet accepting requests.
pub(crate) async fn recover_pending_with_writer(
    home: &Path,
    writer: &crate::wal::writer::WalWriterHandle,
) -> Result<RecoveryOutcome> {
    recover_pending_inner(home, Some(writer)).await
}

async fn recover_pending_inner(
    home: &Path,
    writer: Option<&crate::wal::writer::WalWriterHandle>,
) -> Result<RecoveryOutcome> {
    let _process_guard = JOURNAL_MUTEX.lock().await;
    let _file_guard = acquire_file_lock(home).await?;
    let mut active = read_record_if_present(home)?;
    let queued = read_queued_records(home)?;

    // A crash between durable queue creation and active-journal removal leaves
    // two identical names for one obligation. Collapse that state without
    // emitting the audit twice; conflicting bytes remain fail-closed.
    if let Some(record) = active.as_ref()
        && let Some((_, duplicate)) = queued
            .iter()
            .find(|(_, queued)| queued.operation_id == record.operation_id)
    {
        if duplicate != record {
            anyhow::bail!(
                "active and queued consent audit {} disagree; retaining both for inspection",
                record.operation_id
            );
        }
        clear_journal(home).context("clear duplicate active consent audit after queue handoff")?;
        active = None;
    }

    // Historical terminal obligations are independent of the marker's current
    // value after a later revoke. Retry them in UUIDv7 order; delivery outages
    // leave each private file intact and must not prevent authority reduction.
    for (path, record) in queued {
        let result = match writer {
            Some(writer) => deliver_record_with_writer(writer, &record).await,
            None => deliver_record(home, &record).await,
        };
        match result {
            Ok(AuditDelivery::Delivered) => {
                crate::util::atomic_write::durable_remove_file(&path).with_context(|| {
                    format!("remove delivered queued consent audit {}", path.display())
                })?;
            }
            Ok(AuditDelivery::Pending { error }) => {
                tracing::warn!(
                    operation_id = %record.operation_id,
                    error = %error,
                    "queued consent audit remains pending"
                );
            }
            Err(error) => {
                tracing::warn!(
                    operation_id = %record.operation_id,
                    error = %crate::security::redact::redact_text(&format!("{error:#}")),
                    "required queued consent audit remains pending"
                );
            }
        }
    }

    let Some(mut record) = active else {
        return Ok(RecoveryOutcome::None);
    };

    reconcile_record_with_marker(home, &mut record)?;

    let delivery = match writer {
        Some(writer) => deliver_record_with_writer(writer, &record).await?,
        None => deliver_record(home, &record).await?,
    };
    if matches!(delivery, AuditDelivery::Delivered) {
        clear_journal(home)?;
    }
    Ok(RecoveryOutcome::Recovered {
        operation_id: record.operation_id,
        phase: record.phase,
        delivery,
    })
}

fn reconcile_record_with_marker(home: &Path, record: &mut PendingConsentMutation) -> Result<()> {
    let current = consent::marker_snapshot_binding(home, record.provider)
        .context("snapshot consent marker during pending-mutation recovery")?;
    let prior_phase = record.phase;
    match prior_phase {
        ConsentMutationPhase::Prepared => {
            if record.source_binding.matches_snapshot(&current) {
                record.set_phase(ConsentMutationPhase::Aborted);
            } else if record.target_binding.matches_snapshot(&current) {
                record.set_phase(ConsentMutationPhase::Committed);
            } else {
                anyhow::bail!(
                    "pending consent mutation {} conflicts with the current `{}` marker: \
                     it matches neither the captured source nor target binding; journal retained",
                    record.operation_id,
                    consent::slug(record.provider)
                );
            }
        }
        ConsentMutationPhase::Committed => {
            if record.source_binding.matches_snapshot(&current) {
                // A required committed-audit failure rolls the marker back
                // before recording this phase. Recover that narrow crash
                // window as an aborted transaction.
                record.set_phase(ConsentMutationPhase::Aborted);
            } else if !record.target_binding.matches_snapshot(&current) {
                anyhow::bail!(
                    "committed consent mutation {} no longer matches its target marker binding; \
                     it also does not match the captured source rollback binding; \
                     refusing audit recovery and retaining the journal",
                    record.operation_id
                );
            }
        }
        ConsentMutationPhase::Aborted => {
            if !record.source_binding.matches_snapshot(&current) {
                anyhow::bail!(
                    "aborted consent mutation {} no longer matches its source marker binding; \
                     refusing audit recovery and retaining the journal",
                    record.operation_id
                );
            }
        }
    }
    if record.phase != prior_phase {
        persist_record(home, record)?;
    }
    Ok(())
}

fn daemon_is_live(home: &Path) -> bool {
    matches!(
        crate::daemon::pidfile::live_daemon_pid(&home.join("neothd.pid")),
        Ok(Some(_))
    )
}

async fn deliver_record(home: &Path, record: &PendingConsentMutation) -> Result<AuditDelivery> {
    let (event_type, payload) = audit_payload(record)?;
    resolve_delivery(
        record,
        deliver_raw(home, event_type, payload).await,
        "consent audit delivery",
    )
}

async fn deliver_record_with_writer(
    writer: &crate::wal::writer::WalWriterHandle,
    record: &PendingConsentMutation,
) -> Result<AuditDelivery> {
    let (event_type, payload) = audit_payload(record)?;
    let header = crate::wal::HeaderBuilder::new(event_type, &payload).build();
    resolve_delivery(
        record,
        writer
            .append(header, payload)
            .await
            .map(|_| ())
            .map_err(anyhow::Error::from),
        "daemon WAL append",
    )
}

fn resolve_delivery(
    record: &PendingConsentMutation,
    result: Result<()>,
    surface: &str,
) -> Result<AuditDelivery> {
    match result {
        Ok(()) => Ok(AuditDelivery::Delivered),
        // Authority-increasing grants require a WAL ACK for their prepared
        // phase even under optional audit posture. A revoke may proceed from
        // its already-durable journal record: its terminal record carries the
        // complete source/target binding and remains queued if WAL delivery is
        // unavailable, so audit degradation can never trap granted authority.
        Err(error)
            if record.action == ConsentMutationAction::Grant
                && (record.required_audit || record.phase == ConsentMutationPhase::Prepared) =>
        {
            Err(error).with_context(|| {
                format!(
                    "required {surface} failed for operation {} phase {}; journal retained",
                    record.operation_id,
                    record.phase.as_str()
                )
            })
        }
        Err(error) => Ok(AuditDelivery::Pending {
            error: crate::security::redact::redact_text(&format!("{error:#}")),
        }),
    }
}

async fn deliver_raw(home: &Path, event_type: u8, payload: Vec<u8>) -> Result<()> {
    if daemon_is_live(home) {
        crate::daemon::audit_rpc::try_post_audit_frame(home, event_type, &payload)
            .await
            .context("daemon audit-RPC did not acknowledge consent event")?;
        return Ok(());
    }

    let wal_dir = home.join("wal");
    std::fs::create_dir_all(&wal_dir)
        .with_context(|| format!("create standalone WAL directory {}", wal_dir.display()))?;
    let segment = crate::wal::writer::unique_standalone_segment_path(&wal_dir, "consent-change");
    let (writer, join) = crate::wal::writer::spawn_for_home(segment.clone(), home.to_path_buf())
        .with_context(|| format!("spawn standalone consent WAL {}", segment.display()))?;
    let header = crate::wal::HeaderBuilder::new(event_type, &payload).build();
    let append_result = writer.append(header, payload).await;
    drop(writer);
    let join_result = join.await;
    append_result.with_context(|| {
        format!(
            "standalone consent WAL append was not acknowledged in {}",
            segment.display()
        )
    })?;
    join_result.with_context(|| {
        format!(
            "standalone consent WAL writer task failed for {}",
            segment.display()
        )
    })?;
    Ok(())
}

fn audit_payload(record: &PendingConsentMutation) -> Result<(u8, Vec<u8>)> {
    let bytes = serde_json::to_vec(&serde_json::json!({
        "schema_version": JOURNAL_VERSION,
        "operation_id": record.operation_id,
        "audit_event_id": record.audit_event_id,
        "provider": consent::slug(record.provider),
        "action": record.action.as_str(),
        "source": record.source.as_str(),
        "endpoint_origins": record.endpoint_origins,
        "source_binding": record.source_binding,
        "target_binding": record.target_binding,
        "phase": record.phase.as_str(),
        "required_audit": record.required_audit,
        "ts_unix": record.ts_unix,
    }))
    .context("serialize consent audit payload")?;
    if bytes.len() > MAX_AUDIT_PAYLOAD_BYTES {
        anyhow::bail!(
            "consent audit payload is {} bytes, exceeding the {}-byte daemon-RPC-safe ceiling",
            bytes.len(),
            MAX_AUDIT_PAYLOAD_BYTES
        );
    }
    Ok((record.action.event_type(), bytes))
}

fn derive_audit_event_id(record: &PendingConsentMutation) -> String {
    let mut digest = Sha256::new();
    digest.update(b"neoth:consent-mutation:audit-event:v1\0");
    hash_len_prefixed(&mut digest, record.operation_id.as_bytes());
    hash_len_prefixed(&mut digest, consent::slug(record.provider).as_bytes());
    digest.update([match record.action {
        ConsentMutationAction::Grant => 1,
        ConsentMutationAction::Revoke => 2,
    }]);
    digest.update([match record.source {
        ConsentMutationSource::Cli => 1,
        ConsentMutationSource::Slash => 2,
        ConsentMutationSource::Gui => 3,
        ConsentMutationSource::Tty => 4,
        ConsentMutationSource::Wizard => 5,
    }]);
    digest.update([match record.phase {
        ConsentMutationPhase::Prepared => 1,
        ConsentMutationPhase::Committed => 2,
        ConsentMutationPhase::Aborted => 3,
    }]);
    digest.update([u8::from(record.required_audit)]);
    digest.update(record.ts_unix.to_le_bytes());
    digest.update([u8::from(record.source_binding.exists)]);
    hash_optional(&mut digest, record.source_binding.sha256.as_deref());
    digest.update([u8::from(record.target_binding.exists)]);
    hash_optional(&mut digest, record.target_binding.sha256.as_deref());
    digest.update((record.endpoint_origins.len() as u64).to_le_bytes());
    for origin in &record.endpoint_origins {
        hash_len_prefixed(&mut digest, origin.as_bytes());
    }
    hex::encode(digest.finalize())
}

fn hash_optional(digest: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            digest.update([1]);
            hash_len_prefixed(digest, value.as_bytes());
        }
        None => digest.update([0]),
    }
}

fn hash_len_prefixed(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_le_bytes());
    digest.update(value);
}

async fn acquire_file_lock(home: &Path) -> Result<std::fs::File> {
    let path = lock_path(home);
    tokio::task::spawn_blocking(move || {
        crate::util::locked_file::lock_file_blocking(&path, "consent mutation journal")
    })
    .await
    .context("consent mutation journal lock task failed")?
}

fn persist_record(home: &Path, record: &PendingConsentMutation) -> Result<()> {
    let bytes = serialize_record(record)?;
    let path = journal_path(home);
    crate::util::atomic_write::atomic_write_private(&path, &bytes)
        .with_context(|| format!("private atomic write {}", path.display()))
}

fn serialize_record(record: &PendingConsentMutation) -> Result<Vec<u8>> {
    validate_record(record)?;
    let mut bytes = serde_json::to_vec_pretty(record).context("serialize consent journal")?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn archive_nonblocking_terminal_record(home: &Path, record: &PendingConsentMutation) -> Result<()> {
    if !record.phase.is_terminal() {
        anyhow::bail!(
            "pending consent mutation {} is still prepared; refusing to supersede ambiguous state",
            record.operation_id
        );
    }
    let current = consent::marker_snapshot_binding(home, record.provider)
        .context("snapshot prior consent marker before queuing its terminal audit")?;
    let expected = match record.phase {
        ConsentMutationPhase::Committed => &record.target_binding,
        ConsentMutationPhase::Aborted => &record.source_binding,
        ConsentMutationPhase::Prepared => unreachable!("checked terminal phase above"),
    };
    if !expected.matches_snapshot(&current) {
        anyhow::bail!(
            "pending consent mutation {} does not match its terminal marker binding; \
             refusing journal supersession",
            record.operation_id
        );
    }
    let bytes = serialize_record(record)?;
    let queued_path = queued_audit_path(home, &record.operation_id);
    match crate::util::atomic_write::write_private_create_new_durable(&queued_path, &bytes) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            let existing = read_record_file(home, &queued_path, "existing queued consent audit")?;
            if existing != *record {
                anyhow::bail!(
                    "queued consent audit {} exists with conflicting content",
                    record.operation_id
                );
            }
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("durably queue audit {}", queued_path.display()));
        }
    }
    clear_journal(home).context("retire active consent journal after durable audit-queue handoff")
}

fn clear_journal(home: &Path) -> Result<()> {
    let path = journal_path(home);
    crate::util::atomic_write::durable_remove_file(&path)
        .with_context(|| format!("remove acknowledged consent journal {}", path.display()))
}

fn read_queued_records(home: &Path) -> Result<Vec<(PathBuf, PendingConsentMutation)>> {
    let paths = queued_audit_paths(home)?;
    if paths.len() > MAX_QUEUED_AUDITS {
        anyhow::bail!(
            "consent audit queue contains {} records, exceeding the {}-record safety ceiling",
            paths.len(),
            MAX_QUEUED_AUDITS
        );
    }
    paths
        .into_iter()
        .map(|path| {
            let record = read_record_file(home, &path, "queued consent audit")?;
            let expected_name = queued_audit_path(home, &record.operation_id);
            if path != expected_name {
                anyhow::bail!(
                    "queued consent audit filename does not match operation {}",
                    record.operation_id
                );
            }
            if !record.phase.is_terminal() {
                anyhow::bail!(
                    "queued consent audit {} is not terminal",
                    record.operation_id
                );
            }
            Ok((path, record))
        })
        .collect()
}

fn queued_audit_paths(home: &Path) -> Result<Vec<PathBuf>> {
    let dir = home.join("consent");
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).with_context(|| format!("read {}", dir.display())),
    };
    let mut paths = Vec::new();
    for entry in entries {
        let path = entry
            .with_context(|| format!("enumerate queued consent audits in {}", dir.display()))?
            .path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(QUEUED_AUDIT_PREFIX) && name.ends_with(".json"))
        {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

fn read_record_if_present(home: &Path) -> Result<Option<PendingConsentMutation>> {
    let path = journal_path(home);
    match read_record_file(home, &path, "consent journal") {
        Ok(record) => Ok(Some(record)),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn read_record_file(home: &Path, path: &Path, label: &str) -> Result<PendingConsentMutation> {
    let bytes = crate::updater::self_update::read_private_control_file_bounded(
        home,
        path,
        MAX_JOURNAL_BYTES as usize,
        label,
    )?;
    let record: PendingConsentMutation = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse {label} {}; evidence retained", path.display()))?;
    validate_record(&record)
        .with_context(|| format!("validate {label} {}; evidence retained", path.display()))?;
    Ok(record)
}

fn validate_record(record: &PendingConsentMutation) -> Result<()> {
    if record.version != JOURNAL_VERSION {
        anyhow::bail!(
            "unsupported consent journal version {} (expected {})",
            record.version,
            JOURNAL_VERSION
        );
    }
    let operation_id =
        uuid::Uuid::parse_str(&record.operation_id).context("operation_id is not a UUID")?;
    if operation_id.get_version_num() != 7 {
        anyhow::bail!("operation_id must be UUIDv7");
    }
    if record.source_binding == record.target_binding {
        anyhow::bail!("consent journal source and target bindings must differ");
    }
    validate_binding("source", &record.source_binding)?;
    validate_binding("target", &record.target_binding)?;
    if record.endpoint_origins.len() > 64 {
        anyhow::bail!("consent journal carries more than 64 endpoint origins");
    }
    if record
        .endpoint_origins
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        anyhow::bail!("endpoint_origins must be sorted and unique");
    }
    for origin in &record.endpoint_origins {
        if origin.is_empty() || origin.len() > 512 || origin.contains('\0') {
            anyhow::bail!("endpoint origin must be 1..=512 bytes and contain no NUL");
        }
        let url = url::Url::parse(origin).context("endpoint origin is not an absolute URL")?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.origin().ascii_serialization() != *origin
        {
            anyhow::bail!("endpoint origin must be a canonical credential-free HTTP(S) origin");
        }
    }
    let expected = derive_audit_event_id(record);
    if record.audit_event_id != expected {
        anyhow::bail!("audit_event_id does not match the journal's canonical content");
    }
    let _ = audit_payload(record)?;
    Ok(())
}

fn validate_binding(label: &str, binding: &MarkerBinding) -> Result<()> {
    match (binding.exists, binding.sha256.as_deref()) {
        (false, None) => Ok(()),
        (true, Some(hash))
            if hash.len() == 64
                && hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) =>
        {
            Ok(())
        }
        _ => anyhow::bail!(
            "{label} marker binding must have one lowercase SHA-256 exactly when it exists"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consent::ConsentRoute;
    use tempfile::TempDir;

    fn openai_update(home: &Path) -> ConsentMarkerUpdate {
        consent::prepare_grant_routes(home, &[ConsentRoute::new(ProviderKind::OpenaiApi, None)])
            .unwrap()
    }

    #[tokio::test]
    async fn invalid_endpoint_origin_errors_do_not_echo_embedded_credentials() {
        let home = TempDir::new().unwrap();
        let update = openai_update(home.path());
        let transaction = begin(
            home.path(),
            &update,
            ConsentMutationAction::Grant,
            ConsentMutationSource::Cli,
            Vec::new(),
            true,
        )
        .await
        .unwrap();
        let mut record = transaction.record().clone();
        record.endpoint_origins = vec!["https://operator:super-secret@example.com".to_owned()];

        let error = validate_record(&record).unwrap_err();
        let rendered = format!("{error:#}");
        assert!(!rendered.contains("operator"));
        assert!(!rendered.contains("super-secret"));
        assert!(rendered.contains("credential-free"));
    }

    #[tokio::test]
    async fn persisted_schema_is_versioned_and_content_bound() {
        let home = TempDir::new().unwrap();
        let update = openai_update(home.path());
        let transaction = begin(
            home.path(),
            &update,
            ConsentMutationAction::Grant,
            ConsentMutationSource::Cli,
            Vec::new(),
            true,
        )
        .await
        .unwrap();

        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(journal_path(home.path())).unwrap()).unwrap();
        assert_eq!(value["version"], 1);
        assert_eq!(value["provider"], "openai_api");
        assert_eq!(value["action"], "grant");
        assert_eq!(value["source"], "cli");
        assert_eq!(value["phase"], "prepared");
        assert_eq!(value["required_audit"], true);
        assert_eq!(
            value["operation_id"].as_str().unwrap(),
            transaction.record().operation_id()
        );
        assert_eq!(
            value["audit_event_id"].as_str().unwrap(),
            transaction.record().audit_event_id()
        );
        assert_eq!(
            uuid::Uuid::parse_str(transaction.record().operation_id())
                .unwrap()
                .get_version_num(),
            7
        );
    }

    #[tokio::test]
    async fn recovery_resolves_prepared_source_as_aborted() {
        let home = TempDir::new().unwrap();
        let update = openai_update(home.path());
        let transaction = begin(
            home.path(),
            &update,
            ConsentMutationAction::Grant,
            ConsentMutationSource::Cli,
            Vec::new(),
            false,
        )
        .await
        .unwrap();
        let operation_id = transaction.record().operation_id().to_owned();
        drop(transaction);

        let recovered = recover_pending(home.path()).await.unwrap();
        assert_eq!(
            recovered,
            RecoveryOutcome::Recovered {
                operation_id,
                phase: ConsentMutationPhase::Aborted,
                delivery: AuditDelivery::Delivered,
            }
        );
        assert!(!journal_path(home.path()).exists());
        assert!(!consent::marker_path(home.path(), ProviderKind::OpenaiApi).exists());
    }

    #[tokio::test]
    async fn recovery_resolves_prepared_target_as_committed() {
        let home = TempDir::new().unwrap();
        let update = openai_update(home.path());
        let transaction = begin(
            home.path(),
            &update,
            ConsentMutationAction::Grant,
            ConsentMutationSource::Slash,
            Vec::new(),
            false,
        )
        .await
        .unwrap();
        let operation_id = transaction.record().operation_id().to_owned();
        assert!(update.commit().unwrap());
        drop(transaction);

        let recovered = recover_pending(home.path()).await.unwrap();
        assert_eq!(
            recovered,
            RecoveryOutcome::Recovered {
                operation_id,
                phase: ConsentMutationPhase::Committed,
                delivery: AuditDelivery::Delivered,
            }
        );
        assert!(!journal_path(home.path()).exists());
        assert!(consent::marker_path(home.path(), ProviderKind::OpenaiApi).exists());
    }

    #[tokio::test]
    async fn begin_rejects_update_whose_source_changed_before_locking() {
        let home = TempDir::new().unwrap();
        let stale_update = openai_update(home.path());
        assert!(stale_update.commit().unwrap());

        let error = match begin(
            home.path(),
            &stale_update,
            ConsentMutationAction::Grant,
            ConsentMutationSource::Cli,
            Vec::new(),
            false,
        )
        .await
        {
            Ok(_) => panic!("stale prepared source must not become durable intent"),
            Err(error) => error,
        };

        assert!(format!("{error:#}").contains("changed after the mutation was prepared"));
        assert!(!journal_path(home.path()).exists());
    }

    #[tokio::test]
    async fn recovery_resolves_committed_marker_rollback_as_aborted() {
        let home = TempDir::new().unwrap();
        let update = openai_update(home.path());
        let mut transaction = begin(
            home.path(),
            &update,
            ConsentMutationAction::Grant,
            ConsentMutationSource::Cli,
            Vec::new(),
            true,
        )
        .await
        .unwrap();
        assert_eq!(
            transaction.deliver_phase().await.unwrap(),
            AuditDelivery::Delivered
        );
        let operation_id = transaction.record().operation_id().to_owned();
        assert!(update.commit().unwrap());
        transaction.mark_committed().unwrap();
        assert!(update.rollback().unwrap());
        drop(transaction);

        let recovered = recover_pending(home.path()).await.unwrap();
        assert_eq!(
            recovered,
            RecoveryOutcome::Recovered {
                operation_id,
                phase: ConsentMutationPhase::Aborted,
                delivery: AuditDelivery::Delivered,
            }
        );
        assert!(!journal_path(home.path()).exists());
        assert!(!consent::marker_path(home.path(), ProviderKind::OpenaiApi).exists());
    }

    #[tokio::test]
    async fn audit_outage_cannot_trap_authority_from_emergency_revoke() {
        let home = TempDir::new().unwrap();
        let update = openai_update(home.path());
        let mut transaction = begin(
            home.path(),
            &update,
            ConsentMutationAction::Grant,
            ConsentMutationSource::Cli,
            Vec::new(),
            false,
        )
        .await
        .unwrap();
        assert_eq!(
            transaction.deliver_phase().await.unwrap(),
            AuditDelivery::Delivered
        );
        assert!(update.commit().unwrap());
        transaction.mark_committed().unwrap();

        // A live PID with no audit-RPC listener reproduces the degraded daemon
        // window: the optional committed grant audit remains pending.
        let pid_guard = crate::daemon::pidfile::acquire(&home.path().join("neothd.pid")).unwrap();
        assert!(transaction.deliver_phase().await.unwrap().is_pending());
        drop(transaction);

        let receipt = crate::cli::consent::change_consent_with_config_at(
            home.path(),
            ProviderKind::OpenaiApi,
            false,
            &crate::config::FreedomConfig::default(),
            ConsentMutationSource::Cli,
        )
        .await
        .unwrap();
        assert!(receipt.changed);
        assert!(!consent::marker_path(home.path(), ProviderKind::OpenaiApi).exists());
        assert!(journal_path(home.path()).exists());
        assert_eq!(read_queued_records(home.path()).unwrap().len(), 1);

        drop(pid_guard);
        let recovered = recover_pending(home.path()).await.unwrap();
        assert!(matches!(
            recovered,
            RecoveryOutcome::Recovered {
                phase: ConsentMutationPhase::Committed,
                delivery: AuditDelivery::Delivered,
                ..
            }
        ));
        assert!(!journal_path(home.path()).exists());
        assert!(read_queued_records(home.path()).unwrap().is_empty());
    }

    #[tokio::test]
    async fn optional_terminal_audit_is_queued_before_unrelated_grant() {
        let home = TempDir::new().unwrap();
        let first_update = openai_update(home.path());
        let mut first = begin(
            home.path(),
            &first_update,
            ConsentMutationAction::Grant,
            ConsentMutationSource::Cli,
            Vec::new(),
            false,
        )
        .await
        .unwrap();
        assert_eq!(
            first.deliver_phase().await.unwrap(),
            AuditDelivery::Delivered
        );
        assert!(first_update.commit().unwrap());
        first.mark_committed().unwrap();
        let _daemon_owner =
            crate::daemon::pidfile::acquire(&home.path().join("neothd.pid")).unwrap();
        assert!(first.deliver_phase().await.unwrap().is_pending());
        drop(first);

        let second_route = ConsentRoute::new(ProviderKind::AnthropicApi, None);
        let second_update = consent::prepare_grant_routes(home.path(), &[second_route]).unwrap();
        let second = begin(
            home.path(),
            &second_update,
            ConsentMutationAction::Grant,
            ConsentMutationSource::Gui,
            Vec::new(),
            false,
        )
        .await
        .unwrap();

        assert_eq!(second.record().provider, ProviderKind::AnthropicApi);
        assert_eq!(read_queued_records(home.path()).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn prepared_grant_audit_outage_cannot_trap_prior_authority() {
        let home = TempDir::new().unwrap();
        let route_a = ConsentRoute::new(
            ProviderKind::LocalOllama,
            Some("http://ollama-a.example:11434"),
        );
        let route_b = ConsentRoute::new(
            ProviderKind::LocalOllama,
            Some("http://ollama-b.example:11434"),
        );
        let initial = consent::prepare_grant_routes(home.path(), &[route_a.clone()]).unwrap();
        assert!(initial.commit().unwrap());

        let add_route = consent::prepare_grant_routes(home.path(), &[route_a, route_b]).unwrap();
        let transaction = begin(
            home.path(),
            &add_route,
            ConsentMutationAction::Grant,
            ConsentMutationSource::Gui,
            vec!["http://ollama-b.example:11434".to_string()],
            true,
        )
        .await
        .unwrap();
        drop(transaction);

        // A live PID without an audit-RPC listener makes normal recovery of
        // the required prepared grant fail. Revoke must still reconcile the
        // exact source binding, queue the aborted grant intent, and remove the
        // authority that existed before that attempted add-route.
        let pid_guard = crate::daemon::pidfile::acquire(&home.path().join("neothd.pid")).unwrap();
        let receipt = crate::cli::consent::change_consent_with_config_at(
            home.path(),
            ProviderKind::LocalOllama,
            false,
            &crate::config::FreedomConfig::default(),
            ConsentMutationSource::Cli,
        )
        .await
        .unwrap();
        assert!(receipt.changed);
        assert!(!consent::marker_path(home.path(), ProviderKind::LocalOllama).exists());
        assert_eq!(read_queued_records(home.path()).unwrap().len(), 1);
        drop(pid_guard);
    }

    #[tokio::test]
    async fn malformed_historical_audit_cannot_block_emergency_revoke() {
        let home = TempDir::new().unwrap();
        let update = openai_update(home.path());
        assert!(update.commit().unwrap());
        let consent_dir = home.path().join("consent");
        std::fs::create_dir_all(&consent_dir).unwrap();
        let malformed = consent_dir.join("pending-audit-malformed.json");
        std::fs::write(&malformed, b"{not-json").unwrap();

        let receipt = crate::cli::consent::change_consent_with_config_at(
            home.path(),
            ProviderKind::OpenaiApi,
            false,
            &crate::config::FreedomConfig::default(),
            ConsentMutationSource::Cli,
        )
        .await
        .unwrap();

        assert!(receipt.changed);
        assert!(!consent::marker_path(home.path(), ProviderKind::OpenaiApi).exists());
        assert_eq!(std::fs::read(&malformed).unwrap(), b"{not-json");
    }

    #[tokio::test]
    async fn recovery_conflict_fails_closed_and_retains_journal() {
        let home = TempDir::new().unwrap();
        let update = openai_update(home.path());
        let transaction = begin(
            home.path(),
            &update,
            ConsentMutationAction::Grant,
            ConsentMutationSource::Gui,
            Vec::new(),
            false,
        )
        .await
        .unwrap();
        drop(transaction);

        let marker = consent::marker_path(home.path(), ProviderKind::OpenaiApi);
        std::fs::write(&marker, b"competing marker state\n").unwrap();
        let error = recover_pending(home.path())
            .await
            .expect_err("third marker state must fail closed");
        assert!(format!("{error:#}").contains("matches neither"));
        assert!(journal_path(home.path()).exists());
    }

    #[tokio::test]
    async fn standalone_delivery_uses_unique_namespace_not_daemon_segment() {
        let home = TempDir::new().unwrap();
        let update = openai_update(home.path());
        let mut transaction = begin(
            home.path(),
            &update,
            ConsentMutationAction::Grant,
            ConsentMutationSource::Tty,
            Vec::new(),
            true,
        )
        .await
        .unwrap();

        assert_eq!(
            transaction.deliver_phase().await.unwrap(),
            AuditDelivery::Delivered
        );
        let names: Vec<_> = std::fs::read_dir(home.path().join("wal"))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".wal"))
            .collect();
        assert_eq!(names.len(), 1);
        assert!(names[0].contains("-consent-change-000001.wal"));
        assert_ne!(names[0], "000001.wal");
        assert!(journal_path(home.path()).exists());
    }
}
