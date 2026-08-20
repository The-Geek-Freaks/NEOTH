//! GOLD-CC-02 — instance-local, encrypted context-graph persistence.
//!
//! This deliberately provides neither a connector runtime nor an account-erase
//! API. Secure erasure needs an account DEK lifecycle and a separately reviewed
//! deletion protocol; deleting SQL rows while retaining a master-derived key is
//! not a truthful erasure guarantee. That work remains outside this substrate.
//!
//! The public store surface is account-capability scoped. Every read, batch,
//! outbox query, and replay is bound to an opaque [`AccountContext`]; issuance
//! is deliberately unavailable until authenticated-session wiring can provide
//! a verified principal. A connector cannot name an account in an operation.

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use hmac::{Hmac, Mac};
#[cfg(not(windows))]
use rusqlite::OpenFlags;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};

#[cfg(not(windows))]
use crate::wal::crypto::derive_subkey;
use crate::wal::crypto::{WalMasterKey, WalSegmentKey, decrypt_blob, encrypt_blob};
use crate::connectors::{
    ConnectorId, ConnectorInstanceId, SubjectId,
    control_plane::{
        ContextImportCapabilityBinding, ContextImportOperationLease, ContextImportRuntimeBinding,
    },
    local_import::LocalImportPlan,
};

#[cfg(not(windows))]
const APPLICATION_ID: i64 = 0x4e43_5432; // "NCT2"
#[cfg(not(windows))]
const SCHEMA_VERSION: i64 = 6;
#[cfg(not(windows))]
const CRYPTO_DOMAIN: &[u8] = b"neoth-context-graph-content-v1";
#[cfg(not(windows))]
const LOOKUP_DOMAIN: &[u8] = b"neoth-context-graph-lookup-v1";
const MAX_BATCH_OPS: usize = 64;
const MAX_CONTENT_BYTES: usize = 1024 * 1024;
const MAX_CURSOR_BYTES: usize = 64 * 1024;
const MAX_PROVENANCE_BYTES: usize = 4096;
const MAX_ID_BYTES: usize = 128;
/// A single instance must not admit unbounded account scope identities. This
/// protects a shared local context store from a connector creating a new
/// SQLite namespace for every provider-controlled identifier.
const MAX_SCOPES_PER_STORE: i64 = 4096;
/// Absolute allocated-size ceiling for the whole instance-local context DB.
/// The check uses SQLite's page accounting plus a pessimistic reservation for
/// all rows a newly claimed batch can create, before that batch is written.
const MAX_STORE_BYTES: i64 = 512 * 1024 * 1024;
const MAX_SCOPE_BYTES: i64 = 32 * 1024 * 1024;
const MAX_OBJECTS_PER_SCOPE: i64 = 8192;
const MAX_REVISIONS_PER_OBJECT: i64 = 4096;
const MAX_CURSORS_PER_SCOPE: i64 = 512;
const MAX_PENDING_AUDIT_ENTRIES: i64 = 4096;
const MAX_EVENTS_PER_SCOPE: i64 = 65_536;
const MAX_APPLIED_BATCHES_PER_SCOPE: i64 = MAX_EVENTS_PER_SCOPE;
const ENCRYPTED_VALUE_OVERHEAD: i64 = 39; // ENC_MAGIC + nonce + GCM-SIV tag
// Each row reserves four pages: one for table/BLOB growth and three for its
// indexes or B-tree splits. This deliberately overestimates ordinary SQLite
// writes so a maximum batch cannot pass admission then cross the store cap.
const PROJECTED_PAGES_PER_ROW: i64 = 4;
const STORE_GROWTH_SAFETY_PAGES: i64 = 4;
#[cfg(not(windows))]
const WAL_AUTOCHECKPOINT_PAGES: i64 = 256;
#[cfg(not(windows))]
const JOURNAL_SIZE_LIMIT_BYTES: i64 = 8 * 1024 * 1024;
const WAL_HEADER_BYTES: i64 = 32;
const WAL_FRAME_HEADER_BYTES: i64 = 24;
const WAL_INDEX_REGION_BYTES: i64 = 32 * 1024;
const WAL_FRAMES_IN_FIRST_INDEX_REGION: i64 = 4062;
const WAL_FRAMES_PER_LATER_INDEX_REGION: i64 = 4096;
const MAX_MAINTENANCE_RECOVERY_ATTEMPTS: usize = 2;

/// Capability issued only by an authenticated in-crate account/session layer.
/// Its account identity is intentionally neither caller-supplied per operation
/// nor publicly readable.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountContext {
    principal: String,
    connector_instance: ConnectorInstance,
    _unforgeable: AccountCapability,
}

impl std::fmt::Debug for AccountContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AccountContext(***)")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AccountCapability(());

/// Closed, validated connector-instance identity. It is held in the
/// authenticated capability and never accepted on individual store calls.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ConnectorInstance(String);

impl ConnectorInstance {
    fn new(value: &str) -> Result<Self> {
        validate_identifier("connector instance", value)?;
        Ok(Self(value.to_owned()))
    }
}

impl AccountContext {
    /// This constructor is deliberately module-private. The connector-facing
    /// layer must not manufacture an account capability from a request field;
    /// authenticated-session wiring is intentionally deferred until it can
    /// pass a verified principal rather than an arbitrary string.
    #[cfg(test)]
    fn from_authenticated_identity(principal: &str, connector_instance: &str) -> Result<Self> {
        validate_identifier("authenticated principal", principal)?;
        Ok(Self {
            principal: principal.to_owned(),
            connector_instance: ConnectorInstance::new(connector_instance)?,
            _unforgeable: AccountCapability(()),
        })
    }

    fn from_local_import_binding(
        subject_id: &SubjectId,
        instance_id: &ConnectorInstanceId,
    ) -> Result<Self> {
        let mut digest = Sha256::new();
        digest.update(b"neoth/context-account/local-import/v1\0");
        digest.update(subject_id.as_str().as_bytes());
        digest.update([0]);
        digest.update(instance_id.connector_id.as_str().as_bytes());
        digest.update([0]);
        if let Some(account_id) = &instance_id.account_id {
            digest.update(account_id.as_str().as_bytes());
        }
        let connector_instance = format!("{:x}", digest.finalize());
        Ok(Self {
            principal: subject_id.as_str().to_owned(),
            connector_instance: ConnectorInstance::new(&connector_instance)?,
            _unforgeable: AccountCapability(()),
        })
    }
}

/// Check the two non-forgeable halves of the runtime pair before deriving the
/// only ContextStore account that the P0 bridge may access.
fn validate_context_import_runtime_pair(
    runtime_binding: &ContextImportRuntimeBinding,
    lease: &ContextImportOperationLease,
) -> Result<AccountContext> {
    let instance_id = runtime_binding.instance_id();
    let subject_id = runtime_binding.subject_id();
    if instance_id.connector_id != ConnectorId::LocalImport
        || !runtime_binding.matches_operation_lease(lease)
        || !lease.binding_matches(
            instance_id,
            subject_id,
            runtime_binding.policy_revision(),
            runtime_binding.lifecycle_revision(),
        )
    {
        bail!("context import runtime pair does not authorize a local-import store operation");
    }
    AccountContext::from_local_import_binding(subject_id, instance_id)
}

/// Stable object identity inside the account bound by [`AccountContext`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectRef {
    pub object_id: String,
    pub object_kind: ObjectKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    Memory,
    Evidence,
    Note,
}

impl ObjectKind {
    fn code(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Evidence => "evidence",
            Self::Note => "note",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provenance {
    pub source_kind: ProvenanceKind,
    /// Provider/resource reference. It is encrypted at rest and bounded before
    /// a transaction begins; it never enters audit receipts.
    pub source_ref: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProvenanceKind {
    Connector,
    User,
    Migration,
}

impl ProvenanceKind {
    fn code(self) -> &'static str {
        match self {
            Self::Connector => "connector",
            Self::User => "user",
            Self::Migration => "migration",
        }
    }
}

/// A provider-controlled idempotency key. It is validated and stored only as a
/// SHA-256 digest, so duplicate provider pages/retries are no-ops without
/// retaining an external identifier in plaintext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceKey(pub String);

impl SourceKey {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_identifier("source key", &value)?;
        Ok(Self(value))
    }
}

/// Non-free-form, content-free receipt metadata. The database stores only
/// these allowlisted codes plus a digest of the source mutation key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditReceipt {
    RevisionStored,
    ObjectTombstoned,
    CursorAdvanced,
    /// Content-free receipt for the sole connector-bound `UntrustedExternal`
    /// Evidence bridge below. Generic callers cannot select it accidentally.
    ContextEvidenceStored,
}

/// One local-import payload that can become only encrypted Evidence with fixed
/// `UntrustedExternal`/Connector provenance. It does not expose object kind,
/// trust class, receipt kind, or arbitrary source provenance to callers.
pub(crate) struct UntrustedExternalEvidenceBatch {
    batch_key: SourceKey,
    mutation_key: SourceKey,
    object_id: String,
    content: Vec<u8>,
    evidence_binding: ContextImportCapabilityBinding,
}

impl std::fmt::Debug for UntrustedExternalEvidenceBatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("UntrustedExternalEvidenceBatch(<redacted>)")
    }
}

impl UntrustedExternalEvidenceBatch {
    /// Derive storage identities and content only from a validated,
    /// capability-bound LocalImport plan. No caller can provide raw source
    /// keys, object identities, provenance, or content to this bridge.
    pub(crate) fn from_local_import_plan(plan: &LocalImportPlan) -> Result<Self> {
        let evidence_binding = plan
            .evidence_binding()
            .ok_or_else(|| anyhow!("local import plan has no runtime capability binding"))?
            .for_evidence();
        let mut content = Vec::new();
        for (index, record) in plan.records().iter().enumerate() {
            if index != 0 {
                content.push(b'\n');
            }
            content.extend_from_slice(record.text().as_bytes());
        }
        if content.is_empty() || content.len() > MAX_CONTENT_BYTES {
            bail!("local import evidence content must contain 1..={MAX_CONTENT_BYTES} bytes");
        }
        let plan_hex = hex_bytes(plan.id().as_bytes());
        let object_id = format!(
            "local-import-evidence-{}",
            hex_bytes(plan.source_object_id().as_bytes())
        );
        validate_identifier("local import evidence object id", &object_id)?;
        Ok(Self {
            batch_key: SourceKey::new(format!("local-import-batch-{plan_hex}"))?,
            mutation_key: SourceKey::new(format!("local-import-mutation-{plan_hex}"))?,
            object_id,
            content,
            evidence_binding,
        })
    }
}

/// A mutation has a unique source key. Repeating the same key in a later batch
/// is a strict no-op: no revision, cursor write, event, or audit-outbox record
/// is added. Duplicate keys within one batch are rejected as ambiguous.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContextOperation {
    PutRevision {
        source_key: SourceKey,
        object: ObjectRef,
        content: Vec<u8>,
        provenance: Provenance,
        receipt: AuditReceipt,
    },
    Tombstone {
        source_key: SourceKey,
        object_id: String,
        receipt: AuditReceipt,
    },
    AdvanceCursor {
        source_key: SourceKey,
        cursor_name: String,
        cursor: Vec<u8>,
        receipt: AuditReceipt,
    },
}

/// A provider page/batch has its own idempotency boundary in addition to every
/// source-mutation key. Both are persisted as digest-keyed unique constraints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitBatch {
    pub source_batch_key: SourceKey,
    pub operations: Vec<ContextOperation>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AuditReceiptHandle([u8; 32]);

impl AuditReceiptHandle {
    /// Stable only within this encrypted instance and account scope. The bytes
    /// are opaque and suitable for downstream receipt deduplication; they do
    /// not reveal SQLite row ids or provider identifiers.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for AuditReceiptHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AuditReceiptHandle(***)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct AuditOutboxEntry {
    pub handle: AuditReceiptHandle,
    pub receipt: AuditReceipt,
    /// Coarsened at the public boundary to avoid leaking precise activity
    /// timing. SQLite retains the internal timestamp only for ordering.
    pub occurred_at_unix_minute: i64,
    authority_revisions: Option<(u64, u64)>,
    row_id: i64,
}

impl AuditOutboxEntry {
    pub(crate) fn context_evidence_revisions(&self) -> Result<(u64, u64)> {
        self.authority_revisions
            .ok_or_else(|| anyhow!("Context Evidence audit receipt lacks committed authority revisions"))
    }
}

impl std::fmt::Debug for AuditOutboxEntry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuditOutboxEntry")
            .field("handle", &self.handle)
            .field("receipt", &self.receipt)
            .field("occurred_at_unix_minute", &self.occurred_at_unix_minute)
            .finish_non_exhaustive()
    }
}

/// A narrow replay seam. WAL/event routing remains outside this module. A row
/// is acknowledged only after the supplied sink returns success.
pub trait AuditReceiptSink {
    fn deliver(&mut self, entry: &AuditOutboxEntry) -> Result<()>;
}

pub struct ContextStore {
    path: PathBuf,
    conn: Connection,
    key: WalSegmentKey,
    lookup_key: WalSegmentKey,
    #[cfg(test)]
    fail_next_post_commit_maintenance: bool,
    #[cfg(test)]
    fail_next_recovery_maintenance: bool,
}

impl ContextStore {
    /// Open an explicitly selected, instance-local `context.db`. No fallback
    /// to HOME/USERPROFILE is permitted.
    pub fn open_at(path: impl AsRef<Path>, master_key: &WalMasterKey) -> Result<Self> {
        #[cfg(windows)]
        {
            open_windows_context_store_unwired(path.as_ref(), master_key)
        }
        #[cfg(not(windows))]
        {
            let path = path.as_ref().to_path_buf();
            if path.file_name().and_then(|name| name.to_str()) != Some("context.db") {
                bail!("context store path must be the instance-local context.db");
            }
            let parent = path
                .parent()
                .ok_or_else(|| anyhow!("context.db has no parent directory"))?;
            ensure_private_parent(parent)?;
            reject_links(&path)?;
            reject_database_sidecars(&path)?;
            let existed = path.exists();
            let existing_len = if existed {
                let metadata = fs::metadata(&path)?;
                if !metadata.is_file() {
                    bail!("context.db must be a regular file");
                }
                metadata.len()
            } else {
                0
            };
            if existed && existing_len == 0 {
                bail!("refusing to initialize an existing empty context.db as a new store");
            }
            let mut conn = Connection::open_with_flags(
                &path,
                OpenFlags::SQLITE_OPEN_READ_WRITE
                    | OpenFlags::SQLITE_OPEN_CREATE
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX
                    | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            )
            .with_context(|| format!("open context store {}", path.display()))?;
            conn.busy_timeout(std::time::Duration::from_secs(5))?;
            configure_connection(&conn)?;
            validate_or_initialize_schema(&conn, existed && existing_len > 0)?;
            validate_schema(&conn)?;
            recover_required_maintenance_on_open(&mut conn, &path)?;
            // SQLite may create WAL/SHM files while opening or setting WAL
            // mode. Inspect them after initialization as well; a linked
            // sidecar is a hard failure, never a recoverable warning.
            reject_database_sidecars(&path)?;
            restrict_database_sidecars(&path)?;
            let key = derive_subkey(master_key, CRYPTO_DOMAIN)?;
            let lookup_key = derive_subkey(master_key, LOOKUP_DOMAIN)?;
            Ok(Self {
                path,
                conn,
                key,
                lookup_key,
                #[cfg(test)]
                fail_next_post_commit_maintenance: false,
                #[cfg(test)]
                fail_next_recovery_maintenance: false,
            })
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Commit an account-bound provider batch atomically. A repeated batch key
    /// has no effect; a new batch with previously applied source operation keys
    /// applies only its new operations. Validation and quota checks occur before
    /// `BEGIN IMMEDIATE` so malformed input never takes the writer lock.
    pub fn commit_batch(&mut self, account: &AccountContext, batch: &CommitBatch) -> Result<()> {
        self.commit_batch_with_limits(account, batch, DEFAULT_STORE_LIMITS)
    }

    /// The sole Context Connector P0 write bridge. Caller-supplied binding
    /// values are assertions only: each must match the non-forgeable live
    /// lease. This fixes persisted semantics to `Evidence`, Connector
    /// provenance, explicit `UntrustedExternal`, and a content-free receipt.
    pub(crate) fn commit_local_import_evidence(
        &mut self,
        runtime_binding: &ContextImportRuntimeBinding,
        lease: &ContextImportOperationLease,
        evidence: UntrustedExternalEvidenceBatch,
    ) -> Result<()> {
        let account = validate_context_import_runtime_pair(runtime_binding, lease)?;
        if !evidence.evidence_binding.matches_runtime_binding(runtime_binding)
            || !evidence.evidence_binding.matches_operation_lease(lease)
        {
            bail!("local-import evidence is not bound to this runtime pair");
        }
        let policy_revision = runtime_binding.policy_revision();
        let lifecycle_revision = runtime_binding.lifecycle_revision();
        let batch = CommitBatch {
            source_batch_key: evidence.batch_key,
            operations: vec![ContextOperation::PutRevision {
                source_key: evidence.mutation_key,
                object: ObjectRef {
                    object_id: evidence.object_id,
                    object_kind: ObjectKind::Evidence,
                },
                content: evidence.content,
                provenance: Provenance {
                    source_kind: ProvenanceKind::Connector,
                    source_ref: "untrusted_external:local_import".into(),
                },
                receipt: AuditReceipt::ContextEvidenceStored,
            }],
        };
        lease.with_context_import_commit_permit(|| {
            self.commit_batch_with_limits_and_context_evidence_receipt(
                &account,
                &batch,
                DEFAULT_STORE_LIMITS,
                true,
                Some((policy_revision, lifecycle_revision)),
            )
        })
    }

    /// Reserve the current P0 receipt rows while the exact lease is live.
    /// Delivery intentionally occurs outside the gate: a WAL adapter is an
    /// extensible boundary and must never block account retirement.
    pub(crate) fn reserve_local_import_audit(
        &mut self,
        runtime_binding: &ContextImportRuntimeBinding,
        lease: &ContextImportOperationLease,
    ) -> Result<Vec<AuditOutboxEntry>> {
        let account = validate_context_import_runtime_pair(runtime_binding, lease)?;
        lease.with_context_import_commit_permit(|| {
            let entries = self.pending_audit(&account)?;
            if entries
                .iter()
                .any(|entry| entry.receipt != AuditReceipt::ContextEvidenceStored)
            {
                bail!("local-import audit scope contains a non-ContextEvidence receipt");
            }
            Ok(entries)
        })
    }

    /// Conditionally acknowledge a successfully delivered, reserved receipt.
    /// If retirement won after external WAL delivery, the permit fails and the
    /// row remains durable; handle-based append-once then makes later retry
    /// safe.
    pub(crate) fn acknowledge_local_import_audit(
        &mut self,
        runtime_binding: &ContextImportRuntimeBinding,
        lease: &ContextImportOperationLease,
        entry: &AuditOutboxEntry,
    ) -> Result<()> {
        let account = validate_context_import_runtime_pair(runtime_binding, lease)?;
        if entry.receipt != AuditReceipt::ContextEvidenceStored {
            bail!("context import lease binding does not authorize this local-import commit");
        }
        lease.with_context_import_commit_permit(|| {
            if self.conn.execute(
                "DELETE FROM audit_outbox WHERE scope_key=?1 AND event_id=?2 AND receipt_code=?3",
                params![
                    self.scope(&account).key.as_slice(),
                    entry.row_id,
                    receipt_code(AuditReceipt::ContextEvidenceStored),
                ],
            )? != 1 {
                bail!("local-import audit outbox entry changed before acknowledged replay");
            }
            Ok(())
        })
    }

    fn commit_batch_with_limits(
        &mut self,
        account: &AccountContext,
        batch: &CommitBatch,
        limits: StoreLimits,
    ) -> Result<()> {
        self.commit_batch_with_limits_and_context_evidence_receipt(account, batch, limits, false, None)
    }

    fn commit_batch_with_limits_and_context_evidence_receipt(
        &mut self,
        account: &AccountContext,
        batch: &CommitBatch,
        limits: StoreLimits,
        permits_context_evidence_receipt: bool,
        authority_revisions: Option<(u64, u64)>,
    ) -> Result<()> {
        validate_batch(batch, permits_context_evidence_receipt)?;
        // Reject oversized / malformed payloads and exhausted account capacity
        // before acquiring SQLite's writer lock. Re-check under that lock below
        // so concurrent store handles cannot race the quota.
        let preflight = self.preflight(account, batch, limits)?;
        if preflight.batch_seen {
            return Ok(());
        }
        let scope = self.scope(account);
        let batch_digest = scope.pseudonym(&self.lookup_key, b"batch", &batch.source_batch_key.0);
        for recovery_attempt in 0..=MAX_MAINTENANCE_RECOVERY_ATTEMPTS {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let batch_seen = tx
                .query_row(
                    "SELECT 1 FROM applied_batches WHERE scope_key=?1 AND batch_key=?2 LIMIT 1",
                    params![scope.key.as_slice(), batch_digest.as_slice()],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if batch_seen {
                tx.commit()?;
                return Ok(());
            }
            if let Some(generation) = maintenance_generation(&tx)? {
                tx.rollback()?;
                if recovery_attempt == MAX_MAINTENANCE_RECOVERY_ATTEMPTS {
                    bail!("context store maintenance recovery retry limit exceeded");
                }
                self.recover_maintenance_generation(generation)?;
                continue;
            }

            let mut newly_claimed = Vec::with_capacity(preflight.new_operation_indexes.len());
            for operation in &batch.operations {
                let key = scope.pseudonym(
                    &self.lookup_key,
                    b"mutation",
                    &operation_source_key(operation).0,
                );
                let seen = tx
                    .query_row(
                        "SELECT 1 FROM applied_mutations WHERE scope_key=?1 AND mutation_key=?2 LIMIT 1",
                        params![scope.key.as_slice(), key.as_slice()],
                        |_| Ok(()),
                    )
                    .optional()?
                    .is_some();
                if !seen {
                    newly_claimed.push(operation);
                }
            }
            // A fresh page containing only previously-claimed mutations is a
            // true no-op and retains neither a marker nor a batch-key row.
            if newly_claimed.is_empty() {
                tx.commit()?;
                return Ok(());
            }

            let now = Utc::now().timestamp_millis();
            tx.execute(
                "INSERT INTO store_state(state_key,generation,set_at_ms) VALUES('maintenance_required',randomblob(32),?1)",
                [now],
            )?;
            let generation = maintenance_generation(&tx)?.ok_or_else(|| {
                anyhow!("context store failed to retain its maintenance generation")
            })?;

            ensure_store_limits_with(&tx, &self.path, &scope, &newly_claimed, limits)?;
            ensure_scope_limits(&tx, &self.lookup_key, &scope, &newly_claimed)?;
            for operation in &newly_claimed {
                let mutation_key = scope.pseudonym(
                    &self.lookup_key,
                    b"mutation",
                    &operation_source_key(operation).0,
                );
                if tx.execute(
                    "INSERT INTO applied_mutations(scope_key,mutation_key,applied_at_ms) VALUES(?1,?2,?3)",
                    params![scope.key.as_slice(), mutation_key.as_slice(), now],
                )? != 1
                {
                    bail!("context mutation claim changed under the immediate writer lock");
                }
                apply_operation(
                    &tx,
                    &self.key,
                    &self.lookup_key,
                    &scope,
                    operation,
                    mutation_key,
                    authority_revisions,
                )?;
            }
            let retained_batches: i64 = tx.query_row(
                "SELECT COUNT(*) FROM applied_batches WHERE scope_key=?1",
                [scope.key.as_slice()],
                |row| row.get(0),
            )?;
            if retained_batches >= MAX_APPLIED_BATCHES_PER_SCOPE {
                bail!("context retained batch-key safety cap exceeded");
            }
            tx.execute(
                "INSERT INTO applied_batches(scope_key,batch_key,applied_at_ms) VALUES(?1,?2,?3)",
                params![scope.key.as_slice(), batch_digest.as_slice(), now],
            )?;
            tx.commit()?;

            #[cfg(test)]
            let inject_failure = {
                let inject = self.fail_next_post_commit_maintenance;
                self.fail_next_post_commit_maintenance = false;
                inject
            };
            #[cfg(not(test))]
            let inject_failure = false;
            finish_committed_maintenance(&mut self.conn, &self.path, generation, inject_failure);
            return Ok(());
        }
        bail!("context store maintenance recovery retry limit exceeded")
    }

    fn preflight(
        &self,
        account: &AccountContext,
        batch: &CommitBatch,
        limits: StoreLimits,
    ) -> Result<Preflight> {
        let scope = self.scope(account);
        let batch_digest = scope.pseudonym(&self.lookup_key, b"batch", &batch.source_batch_key.0);
        let batch_seen = self
            .conn
            .query_row(
                "SELECT 1 FROM applied_batches WHERE scope_key=?1 AND batch_key=?2 LIMIT 1",
                params![scope.key.as_slice(), batch_digest.as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if batch_seen {
            return Ok(Preflight {
                batch_seen: true,
                new_operation_indexes: Vec::new(),
            });
        }

        let mut new_operation_indexes = Vec::with_capacity(batch.operations.len());
        for (index, operation) in batch.operations.iter().enumerate() {
            let digest = scope.pseudonym(
                &self.lookup_key,
                b"mutation",
                &operation_source_key(operation).0,
            );
            let seen = self
                .conn
                .query_row(
                    "SELECT 1 FROM applied_mutations WHERE scope_key=?1 AND mutation_key=?2 LIMIT 1",
                    params![scope.key.as_slice(), digest.as_slice()],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if !seen {
                new_operation_indexes.push(index);
            }
        }
        let operations = new_operation_indexes
            .iter()
            .map(|index| &batch.operations[*index])
            .collect::<Vec<_>>();
        // A new provider page whose every mutation was already claimed is a
        // true no-op. Do not consult capacity here: it will retain neither a
        // batch key nor any new row, and the in-transaction re-check below
        // makes the same guarantee if another writer wins the race.
        if operations.is_empty() {
            return Ok(Preflight {
                batch_seen: false,
                new_operation_indexes,
            });
        }
        // A retained generation must be recovered under the writer protocol
        // before physical quota is evaluated: the checkpoint may shrink the
        // WAL enough to admit this batch. Both quotas are still enforced under
        // BEGIN IMMEDIATE after recovery, so this cannot bypass admission.
        if maintenance_generation(&self.conn)?.is_some() {
            return Ok(Preflight {
                batch_seen: false,
                new_operation_indexes,
            });
        }
        ensure_store_limits_with(&self.conn, &self.path, &scope, &operations, limits)?;
        ensure_scope_limits(&self.conn, &self.lookup_key, &scope, &operations)?;
        Ok(Preflight {
            batch_seen: false,
            new_operation_indexes,
        })
    }

    pub fn revision_content(
        &self,
        account: &AccountContext,
        object_id: &str,
        revision: i64,
    ) -> Result<Option<Vec<u8>>> {
        validate_identifier("object id", object_id)?;
        let scope = self.scope(account);
        let object_key = scope.pseudonym(&self.lookup_key, b"object", object_id);
        let encrypted: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT content FROM revisions WHERE scope_key=?1 AND object_key=?2 AND revision=?3",
                params![scope.key.as_slice(), object_key.as_slice(), revision],
                |row| row.get(0),
            )
            .optional()?;
        encrypted
            .map(|blob| decrypt_value(&self.key, b"revision", &scope, object_id, revision, &blob))
            .transpose()
    }

    pub fn cursor(&self, account: &AccountContext, cursor_name: &str) -> Result<Option<Vec<u8>>> {
        validate_identifier("cursor name", cursor_name)?;
        let scope = self.scope(account);
        let cursor_key = scope.pseudonym(&self.lookup_key, b"cursor", cursor_name);
        let encrypted: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT value FROM cursors WHERE scope_key=?1 AND cursor_key=?2",
                params![scope.key.as_slice(), cursor_key.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        encrypted
            .map(|blob| decrypt_value(&self.key, b"cursor", &scope, cursor_name, 0, &blob))
            .transpose()
    }

    pub fn pending_audit(&self, account: &AccountContext) -> Result<Vec<AuditOutboxEntry>> {
        let scope = self.scope(account);
        let pending: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM audit_outbox WHERE scope_key=?1",
            [scope.key.as_slice()],
            |row| row.get(0),
        )?;
        if pending > MAX_PENDING_AUDIT_ENTRIES {
            bail!("context audit outbox exceeds its safety cap");
        }
        let mut stmt = self.conn.prepare(
            "SELECT event_id, receipt_code, occurred_at_ms, mutation_key, policy_revision, lifecycle_revision FROM audit_outbox WHERE scope_key=?1 ORDER BY event_id",
        )?;
        stmt.query_map([scope.key.as_slice()], |row| {
            let row_id: i64 = row.get(0)?;
            let digest: Vec<u8> = row.get(3)?;
            let mutation_key: [u8; 32] = digest.try_into().map_err(|_| {
                rusqlite::Error::InvalidColumnType(
                    3,
                    "mutation_key".into(),
                    rusqlite::types::Type::Blob,
                )
            })?;
            Ok(AuditOutboxEntry {
                handle: audit_receipt_handle(&self.lookup_key, &scope, &mutation_key),
                receipt: receipt_from_code(row.get::<_, i64>(1)?)?,
                occurred_at_unix_minute: row.get::<_, i64>(2)?.div_euclid(60_000),
                authority_revisions: match (row.get::<_, Option<i64>>(4)?, row.get::<_, Option<i64>>(5)?) {
                    (Some(policy), Some(lifecycle)) => Some((
                        u64::try_from(policy).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(4, policy))?,
                        u64::try_from(lifecycle).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(5, lifecycle))?,
                    )),
                    (None, None) => None,
                    _ => return Err(rusqlite::Error::InvalidQuery),
                },
                row_id,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
    }

    pub fn replay_audit(
        &mut self,
        account: &AccountContext,
        sink: &mut dyn AuditReceiptSink,
    ) -> Result<usize> {
        let entries = self.pending_audit(account)?;
        let mut delivered = 0;
        for entry in entries {
            sink.deliver(&entry)?;
            if self.conn.execute(
                "DELETE FROM audit_outbox WHERE scope_key=?1 AND event_id=?2",
                params![self.scope(account).key.as_slice(), entry.row_id],
            )? != 1 {
                bail!("context audit outbox entry changed during acknowledged replay");
            }
            delivered += 1;
        }
        Ok(delivered)
    }

    fn scope(&self, account: &AccountContext) -> Scope {
        Scope::new(&self.lookup_key, account)
    }

    fn recover_maintenance_generation(&mut self, generation: [u8; 32]) -> Result<()> {
        #[cfg(test)]
        if self.fail_next_recovery_maintenance {
            self.fail_next_recovery_maintenance = false;
            bail!("injected maintenance recovery failure");
        }
        recover_persisted_maintenance_generation(&mut self.conn, &self.path, generation)
    }
}

/// Windows is deliberately not a path-based implementation placeholder.
///
/// `win_native` now supplies process-token DACL and exact-handle identity
/// primitives, and `skills::store` supplies capability-relative no-reparse
/// traversal. Those primitives are necessary but not sufficient for SQLite:
/// rusqlite's ordinary path VFS would resolve `context.db`, `context.db-wal`,
/// and `context.db-shm` separately after the capability checks. That cannot
/// prove that SQLite opened the same private, non-reparse objects whose DACLs,
/// allocation quota, and recovery state were checked. Retaining a main-file
/// handle alone is also insufficient because SQLite may create, replace, or
/// reopen either sidecar later in the connection lifetime.
///
/// The future Windows implementation must therefore start with a dedicated
/// capability-bound SQLite VFS (or equivalent reviewed SQLite handle API). It
/// must open every database object below an already verified private parent,
/// reject every reparse ancestor and leaf, bind stable file identity before and
/// after SQLite use, retain the appropriate no-delete handles through quota and
/// recovery, and fail the whole open if a main or sidecar DACL proof fails.
/// Do not weaken this boundary into pre-open/post-open path checks.
#[cfg(windows)]
fn open_windows_context_store_unwired(
    path: &Path,
    master_key: &WalMasterKey,
) -> Result<ContextStore> {
    let _ = (path, master_key);
    bail!(
        "context graph store is disabled on Windows: a capability-bound SQLite VFS for private, identity-pinned context.db and WAL/SHM sidecars is not wired"
    );
}

struct Scope {
    key: [u8; 32],
}

impl Scope {
    fn new(lookup_key: &WalSegmentKey, account: &AccountContext) -> Self {
        let mut identity =
            Vec::with_capacity(account.principal.len() + account.connector_instance.0.len() + 1);
        identity.extend_from_slice(account.principal.as_bytes());
        identity.push(0);
        identity.extend_from_slice(account.connector_instance.0.as_bytes());
        Self {
            key: keyed_pseudonym(lookup_key, b"scope", &identity),
        }
    }

    fn pseudonym(&self, lookup_key: &WalSegmentKey, domain: &[u8], value: &str) -> [u8; 32] {
        let mut data = Vec::with_capacity(self.key.len() + value.len() + 1);
        data.extend_from_slice(&self.key);
        data.push(0);
        data.extend_from_slice(value.as_bytes());
        keyed_pseudonym(lookup_key, domain, &data)
    }
}

struct Preflight {
    batch_seen: bool,
    new_operation_indexes: Vec<usize>,
}

/// Create a non-reversible, per-instance lookup key. The value itself never
/// reaches SQLite; each caller selects a distinct domain for object, cursor,
/// mutation, and batch identifiers.
fn keyed_pseudonym(key: &WalSegmentKey, domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.expose())
        .expect("HMAC-SHA256 accepts the fixed-size lookup key");
    mac.update(domain);
    mac.update(&[0]);
    mac.update(value);
    mac.finalize().into_bytes().into()
}

fn audit_receipt_handle(
    lookup_key: &WalSegmentKey,
    scope: &Scope,
    mutation_key: &[u8; 32],
) -> AuditReceiptHandle {
    let mut scoped_mutation = Vec::with_capacity(scope.key.len() + mutation_key.len());
    scoped_mutation.extend_from_slice(&scope.key);
    scoped_mutation.extend_from_slice(mutation_key);
    AuditReceiptHandle(keyed_pseudonym(
        lookup_key,
        b"audit-receipt",
        &scoped_mutation,
    ))
}

#[cfg(not(windows))]
const EXPECTED_TABLE_SQL: &[(&str, &str)] = &[
    (
        "applied_batches",
        "CREATE TABLE applied_batches (scope_key BLOB NOT NULL, batch_key BLOB NOT NULL, applied_at_ms INTEGER NOT NULL, PRIMARY KEY(scope_key, batch_key))",
    ),
    (
        "applied_mutations",
        "CREATE TABLE applied_mutations (scope_key BLOB NOT NULL, mutation_key BLOB NOT NULL, applied_at_ms INTEGER NOT NULL, PRIMARY KEY(scope_key, mutation_key))",
    ),
    (
        "audit_outbox",
        "CREATE TABLE audit_outbox (event_id INTEGER PRIMARY KEY, scope_key BLOB NOT NULL, receipt_code INTEGER NOT NULL, occurred_at_ms INTEGER NOT NULL, mutation_key BLOB NOT NULL, policy_revision INTEGER, lifecycle_revision INTEGER, CHECK((receipt_code=4 AND policy_revision IS NOT NULL AND policy_revision>0 AND lifecycle_revision IS NOT NULL AND lifecycle_revision>0) OR (receipt_code<>4 AND policy_revision IS NULL AND lifecycle_revision IS NULL)), FOREIGN KEY(event_id) REFERENCES events(event_id) ON DELETE CASCADE, UNIQUE(scope_key, mutation_key))",
    ),
    (
        "cursors",
        "CREATE TABLE cursors (scope_key BLOB NOT NULL, cursor_key BLOB NOT NULL, mutation_key BLOB NOT NULL, value BLOB NOT NULL, updated_at_ms INTEGER NOT NULL, PRIMARY KEY(scope_key, cursor_key), UNIQUE(scope_key, mutation_key))",
    ),
    (
        "events",
        "CREATE TABLE events (event_id INTEGER PRIMARY KEY AUTOINCREMENT, scope_key BLOB NOT NULL, mutation_key BLOB NOT NULL, object_key BLOB, revision INTEGER, receipt_code INTEGER NOT NULL, occurred_at_ms INTEGER NOT NULL, UNIQUE(scope_key, mutation_key))",
    ),
    (
        "objects",
        "CREATE TABLE objects (scope_key BLOB NOT NULL, object_key BLOB NOT NULL, object_kind TEXT NOT NULL, created_at_ms INTEGER NOT NULL, tombstoned_at_ms INTEGER, PRIMARY KEY(scope_key, object_key))",
    ),
    (
        "provenance",
        "CREATE TABLE provenance (scope_key BLOB NOT NULL, object_key BLOB NOT NULL, revision INTEGER NOT NULL, source_kind TEXT NOT NULL, source_ref BLOB NOT NULL, PRIMARY KEY(scope_key, object_key, revision))",
    ),
    (
        "revisions",
        "CREATE TABLE revisions (scope_key BLOB NOT NULL, object_key BLOB NOT NULL, revision INTEGER NOT NULL, mutation_key BLOB NOT NULL, created_at_ms INTEGER NOT NULL, content BLOB NOT NULL, PRIMARY KEY(scope_key, object_key, revision), UNIQUE(scope_key, object_key, mutation_key))",
    ),
    (
        "scopes",
        "CREATE TABLE scopes (scope_key BLOB PRIMARY KEY, created_at_ms INTEGER NOT NULL)",
    ),
    (
        "store_state",
        "CREATE TABLE store_state (state_key TEXT PRIMARY KEY CHECK(state_key='maintenance_required'), generation BLOB NOT NULL CHECK(length(generation)=32), set_at_ms INTEGER NOT NULL)",
    ),
    (
        "tombstones",
        "CREATE TABLE tombstones (scope_key BLOB NOT NULL, object_key BLOB NOT NULL, mutation_key BLOB NOT NULL, revision INTEGER NOT NULL, deleted_at_ms INTEGER NOT NULL, PRIMARY KEY(scope_key, object_key, mutation_key))",
    ),
];

/// The exact v5 outbox shape accepted as a migration source.  It is kept
/// separate from v6 so an attacker cannot smuggle a relaxed schema through a
/// write-first "upgrade" path.
#[cfg(not(windows))]
const V5_AUDIT_OUTBOX_SQL: &str = "CREATE TABLE audit_outbox (event_id INTEGER PRIMARY KEY, scope_key BLOB NOT NULL, receipt_code INTEGER NOT NULL, occurred_at_ms INTEGER NOT NULL, mutation_key BLOB NOT NULL, FOREIGN KEY(event_id) REFERENCES events(event_id) ON DELETE CASCADE, UNIQUE(scope_key, mutation_key))";

#[cfg(not(windows))]
fn configure_connection(conn: &Connection) -> Result<()> {
    conn.execute_batch(&format!(
        "PRAGMA foreign_keys=ON;\
         PRAGMA secure_delete=ON;\
         PRAGMA trusted_schema=OFF;\
         PRAGMA synchronous=FULL;\
         PRAGMA temp_store=MEMORY;\
         PRAGMA wal_autocheckpoint={WAL_AUTOCHECKPOINT_PAGES};\
         PRAGMA journal_size_limit={JOURNAL_SIZE_LIMIT_BYTES};"
    ))?;
    ensure_pragma_i64(conn, "foreign_keys", 1)?;
    ensure_pragma_i64(conn, "secure_delete", 1)?;
    ensure_pragma_i64(conn, "trusted_schema", 0)?;
    ensure_pragma_i64(conn, "synchronous", 2)?;
    ensure_pragma_i64(conn, "temp_store", 2)?;
    ensure_pragma_i64(conn, "wal_autocheckpoint", WAL_AUTOCHECKPOINT_PAGES)?;
    ensure_pragma_i64(conn, "journal_size_limit", JOURNAL_SIZE_LIMIT_BYTES)?;
    Ok(())
}

#[cfg(not(windows))]
fn ensure_pragma_i64(conn: &Connection, name: &str, expected: i64) -> Result<()> {
    // All names are fixed literals from configure_connection; accepting a
    // caller-supplied PRAGMA name here would create an injection boundary.
    let actual: i64 = conn.query_row(&format!("PRAGMA {name}"), [], |row| row.get(0))?;
    if actual != expected {
        bail!("context store PRAGMA {name} is {actual}, expected {expected}");
    }
    Ok(())
}

#[cfg(not(windows))]
fn validate_or_initialize_schema(conn: &Connection, existing: bool) -> Result<()> {
    let app_id: i64 = conn.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if existing && app_id != APPLICATION_ID {
        bail!(
            "context.db is corrupt, foreign, or has an unsupported schema version (application_id={app_id}, user_version={version})"
        );
    }
    if existing && version == SCHEMA_VERSION - 1 {
        // Validate the complete pre-upgrade database before `BEGIN IMMEDIATE`
        // can alter it.  A matching header is not evidence that a v5 file is
        // one of ours; in particular, a relaxed audit_outbox must fail closed.
        validate_v5_schema(conn)?;
        conn.execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE audit_outbox_v5_backup (event_id INTEGER PRIMARY KEY, scope_key BLOB NOT NULL, receipt_code INTEGER NOT NULL, occurred_at_ms INTEGER NOT NULL, mutation_key BLOB NOT NULL);
             INSERT INTO audit_outbox_v5_backup(event_id,scope_key,receipt_code,occurred_at_ms,mutation_key) SELECT event_id,scope_key,receipt_code,occurred_at_ms,mutation_key FROM audit_outbox;
             DROP TABLE audit_outbox;
             CREATE TABLE audit_outbox (event_id INTEGER PRIMARY KEY, scope_key BLOB NOT NULL, receipt_code INTEGER NOT NULL, occurred_at_ms INTEGER NOT NULL, mutation_key BLOB NOT NULL, policy_revision INTEGER, lifecycle_revision INTEGER, CHECK((receipt_code=4 AND policy_revision IS NOT NULL AND policy_revision>0 AND lifecycle_revision IS NOT NULL AND lifecycle_revision>0) OR (receipt_code<>4 AND policy_revision IS NULL AND lifecycle_revision IS NULL)), FOREIGN KEY(event_id) REFERENCES events(event_id) ON DELETE CASCADE, UNIQUE(scope_key, mutation_key));
             INSERT INTO audit_outbox(event_id,scope_key,receipt_code,occurred_at_ms,mutation_key) SELECT event_id,scope_key,receipt_code,occurred_at_ms,mutation_key FROM audit_outbox_v5_backup;
             DROP TABLE audit_outbox_v5_backup;
             PRAGMA user_version=6;
             COMMIT;",
        )?;
    } else if existing && version != SCHEMA_VERSION {
        bail!(
            "context.db is corrupt, foreign, or has an unsupported schema version (application_id={app_id}, user_version={version})"
        );
    }
    if !existing {
        let journal_mode: String =
            conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            bail!("context store could not enable WAL journal mode");
        }
        for (_, statement) in EXPECTED_TABLE_SQL {
            conn.execute(statement, [])?;
        }
        conn.execute_batch(&format!(
            "PRAGMA application_id={APPLICATION_ID}; PRAGMA user_version={SCHEMA_VERSION};"
        ))?;
    }
    Ok(())
}

#[cfg(not(windows))]
#[derive(Debug, PartialEq, Eq)]
struct ColumnSignature {
    cid: i64,
    name: String,
    declared_type: String,
    not_null: i64,
    default_value: Option<String>,
    primary_key_order: i64,
    hidden: i64,
}

#[cfg(not(windows))]
#[derive(Debug, PartialEq, Eq)]
struct IndexColumnSignature {
    sequence: i64,
    column_id: i64,
    column_name: Option<String>,
    descending: i64,
    collation: Option<String>,
    key_column: i64,
}

#[cfg(not(windows))]
#[derive(Debug, PartialEq, Eq)]
struct IndexSignature {
    name: String,
    unique: i64,
    origin: String,
    partial: i64,
    columns: Vec<IndexColumnSignature>,
}

#[cfg(not(windows))]
#[derive(Debug, PartialEq, Eq)]
struct SchemaSignature {
    sql_fingerprint: [u8; 32],
    tables: Vec<(String, Vec<ColumnSignature>, Vec<IndexSignature>)>,
}

#[cfg(not(windows))]
fn validate_schema(conn: &Connection) -> Result<()> {
    let expected = Connection::open_in_memory()?;
    for (_, statement) in EXPECTED_TABLE_SQL {
        expected.execute(statement, [])?;
    }
    validate_schema_against(conn, &expected)
}

#[cfg(not(windows))]
fn validate_v5_schema(conn: &Connection) -> Result<()> {
    let expected = Connection::open_in_memory()?;
    for (table_name, statement) in EXPECTED_TABLE_SQL {
        expected.execute(
            if *table_name == "audit_outbox" {
                V5_AUDIT_OUTBOX_SQL
            } else {
                statement
            },
            [],
        )?;
    }
    validate_schema_against(conn, &expected)?;
    let unsupported_receipt: Option<i64> = conn
        .query_row(
            "SELECT receipt_code FROM audit_outbox WHERE receipt_code NOT IN (1,2,3) LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(receipt_code) = unsupported_receipt {
        bail!("context.db v5 audit outbox contains unsupported receipt code {receipt_code}");
    }
    Ok(())
}

#[cfg(not(windows))]
fn validate_schema_against(conn: &Connection, expected: &Connection) -> Result<()> {
    let journal_mode: String = conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        bail!("context store must use WAL journal mode");
    }
    let quick_check: String = conn.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    if quick_check != "ok" {
        bail!("context.db failed SQLite quick_check: {quick_check}");
    }

    let expected_signature = schema_signature(expected)?;
    let actual_signature = schema_signature(conn)?;
    if actual_signature != expected_signature {
        bail!("context.db schema tables, columns, indexes, or SQL fingerprint do not match");
    }
    let violation = conn
        .query_row("PRAGMA foreign_key_check", [], |_| Ok(()))
        .optional()?;
    if violation.is_some() {
        bail!("context.db contains a foreign-key violation");
    }
    Ok(())
}

#[cfg(not(windows))]
fn schema_signature(conn: &Connection) -> Result<SchemaSignature> {
    let mut master = conn.prepare(
        "SELECT type,name,tbl_name,COALESCE(sql,'') FROM sqlite_master ORDER BY type,name",
    )?;
    let objects = master
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut hasher = Sha256::new();
    for (object_type, name, table_name, sql) in objects {
        for component in [object_type, name, table_name, sql] {
            hasher.update((component.len() as u64).to_le_bytes());
            hasher.update(component.as_bytes());
        }
    }

    let mut tables = Vec::with_capacity(EXPECTED_TABLE_SQL.len());
    for (table_name, _) in EXPECTED_TABLE_SQL {
        tables.push((
            (*table_name).to_owned(),
            column_signature(conn, table_name)?,
            index_signature(conn, table_name)?,
        ));
    }
    Ok(SchemaSignature {
        sql_fingerprint: hasher.finalize().into(),
        tables,
    })
}

#[cfg(not(windows))]
fn column_signature(conn: &Connection, table_name: &str) -> Result<Vec<ColumnSignature>> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_xinfo('{table_name}')"))?;
    stmt.query_map([], |row| {
        Ok(ColumnSignature {
            cid: row.get(0)?,
            name: row.get(1)?,
            declared_type: row.get(2)?,
            not_null: row.get(3)?,
            default_value: row.get(4)?,
            primary_key_order: row.get(5)?,
            hidden: row.get(6)?,
        })
    })?
    .collect::<rusqlite::Result<Vec<_>>>()
    .map_err(Into::into)
}

#[cfg(not(windows))]
fn index_signature(conn: &Connection, table_name: &str) -> Result<Vec<IndexSignature>> {
    let mut stmt = conn.prepare(&format!("PRAGMA index_list('{table_name}')"))?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut indexes = Vec::with_capacity(rows.len());
    for (name, unique, origin, partial) in rows {
        let escaped_name = name.replace('\'', "''");
        let mut columns = conn.prepare(&format!("PRAGMA index_xinfo('{escaped_name}')"))?;
        let columns = columns
            .query_map([], |row| {
                Ok(IndexColumnSignature {
                    sequence: row.get(0)?,
                    column_id: row.get(1)?,
                    column_name: row.get(2)?,
                    descending: row.get(3)?,
                    collation: row.get(4)?,
                    key_column: row.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        indexes.push(IndexSignature {
            name,
            unique,
            origin,
            partial,
            columns,
        });
    }
    indexes.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(indexes)
}

fn apply_operation(
    tx: &rusqlite::Transaction<'_>,
    key: &WalSegmentKey,
    lookup_key: &WalSegmentKey,
    scope: &Scope,
    operation: &ContextOperation,
    mutation_key: [u8; 32],
    authority_revisions: Option<(u64, u64)>,
) -> Result<()> {
    let now = Utc::now().timestamp_millis();
    match operation {
        ContextOperation::PutRevision {
            object,
            content,
            provenance,
            receipt,
            ..
        } => {
            let object_key = scope.pseudonym(lookup_key, b"object", &object.object_id);
            tx.execute(
                "INSERT OR IGNORE INTO scopes(scope_key,created_at_ms) VALUES(?1,?2)",
                params![scope.key.as_slice(), now],
            )?;
            tx.execute("INSERT INTO objects(scope_key,object_key,object_kind,created_at_ms,tombstoned_at_ms) VALUES(?1,?2,?3,?4,NULL) ON CONFLICT(scope_key,object_key) DO NOTHING", params![scope.key.as_slice(), object_key.as_slice(), object.object_kind.code(), now])?;
            let (stored_kind, tombstoned_at): (String, Option<i64>) = tx.query_row("SELECT object_kind,tombstoned_at_ms FROM objects WHERE scope_key=?1 AND object_key=?2", params![scope.key.as_slice(), object_key.as_slice()], |row| Ok((row.get(0)?, row.get(1)?)))?;
            if stored_kind != object.object_kind.code() {
                bail!("object kind is immutable once an object id exists");
            }
            if tombstoned_at.is_some() {
                bail!("cannot create a revision for a tombstoned object");
            }
            let revision: i64 = tx.query_row("SELECT COALESCE(MAX(revision),0)+1 FROM revisions WHERE scope_key=?1 AND object_key=?2", params![scope.key.as_slice(), object_key.as_slice()], |r| r.get(0))?;
            let content = encrypt_value(
                key,
                b"revision",
                scope,
                &object.object_id,
                revision,
                content,
            )?;
            let source_ref = encrypt_value(
                key,
                b"provenance",
                scope,
                &object.object_id,
                revision,
                provenance.source_ref.as_bytes(),
            )?;
            tx.execute("INSERT INTO revisions(scope_key,object_key,revision,mutation_key,created_at_ms,content) VALUES(?1,?2,?3,?4,?5,?6)", params![scope.key.as_slice(), object_key.as_slice(), revision, mutation_key.as_slice(), now, content])?;
            tx.execute("INSERT INTO provenance(scope_key,object_key,revision,source_kind,source_ref) VALUES(?1,?2,?3,?4,?5)", params![scope.key.as_slice(), object_key.as_slice(), revision, provenance.source_kind.code(), source_ref])?;
            append_event(
                tx,
                scope,
                mutation_key,
                Some(object_key),
                Some(revision),
                *receipt,
                now,
                authority_revisions,
            )?;
        }
        ContextOperation::Tombstone {
            object_id, receipt, ..
        } => {
            let object_key = scope.pseudonym(lookup_key, b"object", object_id);
            let revision: i64 = tx
                .query_row(
                    "SELECT MAX(revision) FROM revisions WHERE scope_key=?1 AND object_key=?2",
                    params![scope.key.as_slice(), object_key.as_slice()],
                    |r| r.get::<_, Option<i64>>(0),
                )?
                .ok_or_else(|| anyhow!("cannot tombstone unknown object"))?;
            if tx.execute("UPDATE objects SET tombstoned_at_ms=?3 WHERE scope_key=?1 AND object_key=?2 AND tombstoned_at_ms IS NULL", params![scope.key.as_slice(), object_key.as_slice(), now])? != 1 { bail!("cannot tombstone an already tombstoned or unknown object"); }
            tx.execute("INSERT INTO tombstones(scope_key,object_key,mutation_key,revision,deleted_at_ms) VALUES(?1,?2,?3,?4,?5)", params![scope.key.as_slice(), object_key.as_slice(), mutation_key.as_slice(), revision, now])?;
            append_event(
                tx,
                scope,
                mutation_key,
                Some(object_key),
                Some(revision),
                *receipt,
                now,
                authority_revisions,
            )?;
        }
        ContextOperation::AdvanceCursor {
            cursor_name,
            cursor,
            receipt,
            ..
        } => {
            tx.execute(
                "INSERT OR IGNORE INTO scopes(scope_key,created_at_ms) VALUES(?1,?2)",
                params![scope.key.as_slice(), now],
            )?;
            let cursor_key = scope.pseudonym(lookup_key, b"cursor", cursor_name);
            let encrypted = encrypt_value(key, b"cursor", scope, cursor_name, 0, cursor)?;
            tx.execute("INSERT INTO cursors(scope_key,cursor_key,mutation_key,value,updated_at_ms) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(scope_key,cursor_key) DO UPDATE SET mutation_key=excluded.mutation_key,value=excluded.value,updated_at_ms=excluded.updated_at_ms", params![scope.key.as_slice(), cursor_key.as_slice(), mutation_key.as_slice(), encrypted, now])?;
            append_event(
                tx,
                scope,
                mutation_key,
                None,
                None,
                *receipt,
                now,
                authority_revisions,
            )?;
        }
    }
    Ok(())
}

fn append_event(
    tx: &rusqlite::Transaction<'_>,
    scope: &Scope,
    mutation_key: [u8; 32],
    object_key: Option<[u8; 32]>,
    revision: Option<i64>,
    receipt: AuditReceipt,
    now: i64,
    authority_revisions: Option<(u64, u64)>,
) -> Result<()> {
    tx.execute("INSERT INTO events(scope_key,mutation_key,object_key,revision,receipt_code,occurred_at_ms) VALUES(?1,?2,?3,?4,?5,?6)", params![scope.key.as_slice(), mutation_key.as_slice(), object_key.as_ref().map(|value| value.as_slice()), revision, receipt_code(receipt), now])?;
    let event_id = tx.last_insert_rowid();
    let (policy_revision, lifecycle_revision) = authority_revisions
        .map(|(policy, lifecycle)| {
            Ok((
                Some(i64::try_from(policy).map_err(|_| anyhow!("policy revision exceeds SQLite integer range"))?),
                Some(i64::try_from(lifecycle).map_err(|_| anyhow!("lifecycle revision exceeds SQLite integer range"))?),
            ))
        })
        .transpose()?
        .unwrap_or((None, None));
    tx.execute("INSERT INTO audit_outbox(event_id,scope_key,receipt_code,occurred_at_ms,mutation_key,policy_revision,lifecycle_revision) VALUES(?1,?2,?3,?4,?5,?6,?7)", params![event_id, scope.key.as_slice(), receipt_code(receipt), now, mutation_key.as_slice(), policy_revision, lifecycle_revision])?;
    Ok(())
}

#[derive(Clone, Copy)]
struct StoreLimits {
    max_scopes: i64,
    max_bytes: i64,
}

const DEFAULT_STORE_LIMITS: StoreLimits = StoreLimits {
    max_scopes: MAX_SCOPES_PER_STORE,
    max_bytes: MAX_STORE_BYTES,
};

/// Enforce a store-wide admission boundary in addition to the per-account
/// limits below. This runs before any mutation claim is committed and then
/// again inside `BEGIN IMMEDIATE`; in particular, no account capability can
/// grow the shared DB by racing another `ContextStore` handle.
fn ensure_store_limits_with(
    conn: &Connection,
    database_path: &Path,
    scope: &Scope,
    operations: &[&ContextOperation],
    limits: StoreLimits,
) -> Result<()> {
    if limits.max_scopes < 0 || limits.max_bytes < 0 {
        bail!("context store limits must be non-negative");
    }

    let scope_exists = conn
        .query_row(
            "SELECT 1 FROM scopes WHERE scope_key=?1 LIMIT 1",
            [scope.key.as_slice()],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !scope_exists {
        let scopes: i64 = conn.query_row("SELECT COUNT(*) FROM scopes", [], |row| row.get(0))?;
        if scopes >= limits.max_scopes {
            bail!("context store scope-count safety cap exceeded");
        }
    }

    let page_count: i64 = conn.query_row("PRAGMA page_count", [], |row| row.get(0))?;
    let page_size: i64 = conn.query_row("PRAGMA page_size", [], |row| row.get(0))?;
    if page_count < 0 || page_size <= 0 {
        bail!("context store returned invalid SQLite page accounting");
    }
    let logical_bytes = page_count
        .checked_mul(page_size)
        .ok_or_else(|| anyhow!("context store SQLite allocation overflows quota accounting"))?;
    let footprint = physical_store_footprint(database_path)?;
    let database_growth = projected_store_growth(page_size, !scope_exists, operations)?;
    let projected_growth = projected_database_and_pinned_wal_growth(database_growth, page_size)?;
    ensure_projected_store_bytes(logical_bytes, footprint, projected_growth, limits.max_bytes)?;
    Ok(())
}

/// Reserve both possible destinations for every dirty page. With a pinned
/// reader, older frames can remain in `-wal` while a checkpoint grows the main
/// database and newer frames accumulate behind the reader's snapshot. The
/// admission boundary therefore reserves the page-rounded variable growth
/// twice, plus WAL frame headers, a WAL header, and complete SHM index regions.
fn projected_database_and_pinned_wal_growth(database_growth: i64, page_size: i64) -> Result<i64> {
    if database_growth < 0 || page_size <= 0 {
        bail!("context store projected WAL accounting cannot be negative");
    }
    let frames = checked_ceil_div(database_growth, page_size)?;
    let rounded_growth = frames
        .checked_mul(page_size)
        .ok_or_else(|| anyhow!("context store page-rounded growth overflows quota accounting"))?;
    let database_and_wal_pages = rounded_growth
        .checked_mul(2)
        .ok_or_else(|| anyhow!("context store DB/WAL growth overflows quota accounting"))?;
    let frame_headers = frames
        .checked_mul(WAL_FRAME_HEADER_BYTES)
        .ok_or_else(|| anyhow!("context store WAL frame headers overflow quota accounting"))?;
    let shm_bytes = projected_wal_index_bytes(frames.max(1))?;
    database_and_wal_pages
        .checked_add(frame_headers)
        .and_then(|total| total.checked_add(WAL_HEADER_BYTES))
        .and_then(|total| total.checked_add(shm_bytes))
        .ok_or_else(|| anyhow!("context store pinned-reader growth overflows quota accounting"))
}

fn projected_wal_index_bytes(frames: i64) -> Result<i64> {
    if frames <= 0 {
        bail!("context store WAL index frame count must be positive");
    }
    // SQLite's first 32-KiB wal-index region holds 4062 frame mappings after
    // its headers; every subsequent region holds 4096. Using 4096 for the
    // first region under-reserves exactly at the security-critical boundary.
    let regions = if frames <= WAL_FRAMES_IN_FIRST_INDEX_REGION {
        1
    } else {
        let remainder = frames
            .checked_sub(WAL_FRAMES_IN_FIRST_INDEX_REGION)
            .ok_or_else(|| anyhow!("context store WAL index accounting underflows"))?;
        1_i64
            .checked_add(checked_ceil_div(
                remainder,
                WAL_FRAMES_PER_LATER_INDEX_REGION,
            )?)
            .ok_or_else(|| anyhow!("context store WAL index region count overflows"))?
    };
    regions
        .checked_mul(WAL_INDEX_REGION_BYTES)
        .ok_or_else(|| anyhow!("context store SHM growth overflows quota accounting"))
}

fn checked_ceil_div(value: i64, divisor: i64) -> Result<i64> {
    if value < 0 || divisor <= 0 {
        bail!("context store quota divisor is invalid");
    }
    if value == 0 {
        return Ok(0);
    }
    value
        .checked_add(divisor - 1)
        .map(|adjusted| adjusted / divisor)
        .ok_or_else(|| anyhow!("context store quota division overflows"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StoreFootprint {
    database_bytes: i64,
    wal_bytes: i64,
    shm_bytes: i64,
}

impl StoreFootprint {
    fn total_bytes(self) -> Result<i64> {
        self.database_bytes
            .checked_add(self.wal_bytes)
            .and_then(|total| total.checked_add(self.shm_bytes))
            .ok_or_else(|| anyhow!("context store physical footprint overflows quota accounting"))
    }
}

fn ensure_projected_store_bytes(
    logical_bytes: i64,
    footprint: StoreFootprint,
    projected_growth: i64,
    max_bytes: i64,
) -> Result<()> {
    if logical_bytes < 0 || projected_growth < 0 || max_bytes < 0 {
        bail!("context store byte accounting cannot be negative");
    }
    let allocated_bytes = logical_bytes.max(footprint.total_bytes()?);
    let projected_total = allocated_bytes
        .checked_add(projected_growth)
        .ok_or_else(|| anyhow!("context store projected allocation overflows quota accounting"))?;
    if projected_total > max_bytes {
        bail!("context store byte safety cap exceeded");
    }
    Ok(())
}

fn physical_store_footprint(database_path: &Path) -> Result<StoreFootprint> {
    reject_database_sidecars(database_path)?;
    Ok(StoreFootprint {
        database_bytes: regular_file_len(database_path)?,
        wal_bytes: regular_file_len(&sqlite_sidecar_path(database_path, "-wal"))?,
        shm_bytes: regular_file_len(&sqlite_sidecar_path(database_path, "-shm"))?,
    })
}

fn maintain_bounded_wal(conn: &Connection, database_path: &Path) -> Result<()> {
    // PASSIVE never waits for readers. A blocked reader may leave frames in
    // the WAL, which is why physical_store_footprint remains part of every
    // admission check; journal_size_limit bounds the retained file after the
    // next successful reset/checkpoint.
    let (busy, log_pages, checkpointed_pages): (i64, i64, i64) =
        conn.query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
    if !(0..=1).contains(&busy) || log_pages < 0 || checkpointed_pages < 0 {
        bail!("context store returned invalid WAL checkpoint accounting");
    }
    if physical_store_footprint(database_path)?.total_bytes()? > MAX_STORE_BYTES {
        bail!("context store physical footprint exceeds its byte safety cap");
    }
    Ok(())
}

fn maintenance_generation(conn: &Connection) -> Result<Option<[u8; 32]>> {
    let generation: Option<Vec<u8>> = conn
        .query_row(
            "SELECT generation FROM store_state WHERE state_key='maintenance_required'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    generation
        .map(|value| {
            value.try_into().map_err(|_| {
                anyhow!("context store maintenance generation has an invalid byte length")
            })
        })
        .transpose()
}

#[cfg(not(windows))]
fn recover_required_maintenance_on_open(conn: &mut Connection, database_path: &Path) -> Result<()> {
    if let Some(generation) = maintenance_generation(conn)? {
        recover_persisted_maintenance_generation(conn, database_path, generation)?;
    } else {
        maintain_bounded_wal(conn, database_path)?;
    }
    Ok(())
}

fn recover_persisted_maintenance_generation(
    conn: &mut Connection,
    database_path: &Path,
    generation: [u8; 32],
) -> Result<()> {
    maintain_bounded_wal(conn, database_path)?;
    clear_maintenance_generation(conn, generation)?;
    Ok(())
}

fn clear_maintenance_generation(conn: &mut Connection, generation: [u8; 32]) -> Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    // Conditional deletion prevents a delayed recovery from clearing a newer
    // writer's generation after another process already recovered the one it
    // observed.
    tx.execute(
        "DELETE FROM store_state WHERE state_key='maintenance_required' AND generation=?1",
        [generation.as_slice()],
    )?;
    tx.commit()?;
    Ok(())
}

fn finish_committed_maintenance(
    conn: &mut Connection,
    database_path: &Path,
    generation: [u8; 32],
    inject_failure: bool,
) {
    let maintenance = if inject_failure {
        Err(anyhow!("injected post-commit WAL maintenance failure"))
    } else {
        maintain_bounded_wal(conn, database_path)
    };
    match maintenance {
        Ok(()) => {
            if let Err(error) = clear_maintenance_generation(conn, generation) {
                // The committed mutation still returns success. Its durable
                // generation remains unless the conditional clear succeeded;
                // later writers/openers will retry bounded recovery.
                tracing::error!(%error, "context store could not clear maintenance generation");
            }
        }
        Err(error) => {
            // The mutation is already durable; returning an error here would
            // be a false failure. Leave its generation committed so every new
            // writer must recover before it can mutate state.
            tracing::error!(%error, "context store WAL maintenance deferred; recovery generation retained");
        }
    }
}

fn regular_file_len(path: &Path) -> Result<i64> {
    match fs::metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file() {
                bail!("context database component must be a regular file");
            }
            i64::try_from(metadata.len())
                .map_err(|_| anyhow!("context store component size overflows quota accounting"))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error)
            .with_context(|| format!("inspect context database component {}", path.display())),
    }
}

/// Pessimistically reserve encrypted payload bytes and four SQLite pages per
/// touched row (table/BLOB plus indexes or B-tree splits), plus a small
/// batch-level allocation reserve. The caller supplies only
/// operations that successfully claimed a new source mutation, so exact
/// replays consume no shared-store capacity.
fn projected_store_growth(
    page_size: i64,
    creates_scope: bool,
    operations: &[&ContextOperation],
) -> Result<i64> {
    if page_size <= 0 {
        bail!("context store returned invalid SQLite page size");
    }
    let mut projected = 0_i64;
    if creates_scope {
        reserve_rows(&mut projected, page_size, 1)?;
    }
    // The durable maintenance generation is inserted in the same transaction
    // before any mutation rows and remains through post-commit maintenance.
    reserve_rows(&mut projected, page_size, 1)?;
    for operation in operations {
        // Every new operation creates an applied_mutations row before it can
        // reach apply_operation.
        reserve_rows(&mut projected, page_size, 1)?;
        match operation {
            ContextOperation::PutRevision {
                content,
                provenance,
                ..
            } => {
                // objects + revisions + provenance + events + audit_outbox
                reserve_rows(&mut projected, page_size, 5)?;
                reserve_encrypted_payload(&mut projected, content.len())?;
                reserve_encrypted_payload(&mut projected, provenance.source_ref.len())?;
            }
            ContextOperation::Tombstone { .. } => {
                // tombstones + events + audit_outbox
                reserve_rows(&mut projected, page_size, 3)?;
            }
            ContextOperation::AdvanceCursor { cursor, .. } => {
                // cursors + events + audit_outbox
                reserve_rows(&mut projected, page_size, 3)?;
                reserve_encrypted_payload(&mut projected, cursor.len())?;
            }
        }
    }
    // A non-replay batch also retains one applied_batches row. Reserve a few
    // extra pages to account for a fresh WAL/B-tree allocation boundary.
    reserve_rows(&mut projected, page_size, 1)?;
    let safety = page_size
        .checked_mul(STORE_GROWTH_SAFETY_PAGES)
        .ok_or_else(|| anyhow!("context store safety reservation overflows quota accounting"))?;
    projected
        .checked_add(safety)
        .ok_or_else(|| anyhow!("context store projected allocation overflows quota accounting"))
}

fn reserve_rows(projected: &mut i64, page_size: i64, rows: i64) -> Result<()> {
    let per_row = page_size
        .checked_mul(PROJECTED_PAGES_PER_ROW)
        .ok_or_else(|| anyhow!("context store row reservation overflows quota accounting"))?;
    let reservation = per_row
        .checked_mul(rows)
        .ok_or_else(|| anyhow!("context store row reservation overflows quota accounting"))?;
    *projected = projected
        .checked_add(reservation)
        .ok_or_else(|| anyhow!("context store projected allocation overflows quota accounting"))?;
    Ok(())
}

fn reserve_encrypted_payload(projected: &mut i64, plaintext_len: usize) -> Result<()> {
    *projected = projected
        .checked_add(encrypted_storage_len(plaintext_len)?)
        .ok_or_else(|| anyhow!("context store projected allocation overflows quota accounting"))?;
    Ok(())
}

fn ensure_scope_limits(
    conn: &Connection,
    lookup_key: &WalSegmentKey,
    scope: &Scope,
    operations: &[&ContextOperation],
) -> Result<()> {
    let mut projected_bytes: i64 = conn.query_row("SELECT COALESCE((SELECT SUM(length(content)) FROM revisions WHERE scope_key=?1),0)+COALESCE((SELECT SUM(length(source_ref)) FROM provenance WHERE scope_key=?1),0)+COALESCE((SELECT SUM(length(value)) FROM cursors WHERE scope_key=?1),0)", [scope.key.as_slice()], |row| row.get(0))?;
    for operation in operations {
        match operation {
            ContextOperation::PutRevision {
                content,
                provenance,
                ..
            } => {
                projected_bytes = projected_bytes
                    .saturating_add(encrypted_storage_len(content.len())?)
                    .saturating_add(encrypted_storage_len(provenance.source_ref.len())?);
            }
            ContextOperation::AdvanceCursor {
                cursor_name,
                cursor,
                ..
            } => {
                let cursor_key = scope.pseudonym(lookup_key, b"cursor", cursor_name);
                let previous: Option<i64> = conn
                    .query_row(
                        "SELECT length(value) FROM cursors WHERE scope_key=?1 AND cursor_key=?2",
                        params![scope.key.as_slice(), cursor_key.as_slice()],
                        |row| row.get(0),
                    )
                    .optional()?;
                projected_bytes = projected_bytes
                    .saturating_sub(previous.unwrap_or(0))
                    .saturating_add(encrypted_storage_len(cursor.len())?);
            }
            ContextOperation::Tombstone { .. } => {}
        }
    }
    if projected_bytes > MAX_SCOPE_BYTES {
        bail!("context scope storage quota exceeded");
    }

    let existing_outbox: i64 = conn.query_row(
        "SELECT COUNT(*) FROM audit_outbox WHERE scope_key=?1",
        [scope.key.as_slice()],
        |row| row.get(0),
    )?;
    let incoming_outbox = i64::try_from(operations.len()).unwrap_or(i64::MAX);
    if existing_outbox.saturating_add(incoming_outbox) > MAX_PENDING_AUDIT_ENTRIES {
        bail!("context audit outbox safety cap exceeded");
    }
    let existing_events: i64 = conn.query_row(
        "SELECT COUNT(*) FROM events WHERE scope_key=?1",
        [scope.key.as_slice()],
        |row| row.get(0),
    )?;
    if existing_events.saturating_add(incoming_outbox) > MAX_EVENTS_PER_SCOPE {
        bail!("context event-history safety cap exceeded");
    }

    let existing_objects: i64 = conn.query_row(
        "SELECT COUNT(*) FROM objects WHERE scope_key=?1",
        [scope.key.as_slice()],
        |row| row.get(0),
    )?;
    let new_object_ids = operations
        .iter()
        .filter_map(|operation| match operation {
            ContextOperation::PutRevision { object, .. } => Some(object.object_id.as_str()),
            _ => None,
        })
        .collect::<HashSet<_>>();
    let mut new_objects = 0_i64;
    for object_id in &new_object_ids {
        let object_key = scope.pseudonym(lookup_key, b"object", object_id);
        let existing = conn
            .query_row(
                "SELECT 1 FROM objects WHERE scope_key=?1 AND object_key=?2 LIMIT 1",
                params![scope.key.as_slice(), object_key.as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !existing {
            new_objects = new_objects.saturating_add(1);
        }
    }
    if existing_objects.saturating_add(new_objects) > MAX_OBJECTS_PER_SCOPE {
        bail!("context object-count safety cap exceeded");
    }

    let existing_cursors: i64 = conn.query_row(
        "SELECT COUNT(*) FROM cursors WHERE scope_key=?1",
        [scope.key.as_slice()],
        |row| row.get(0),
    )?;
    let new_cursor_names = operations
        .iter()
        .filter_map(|operation| match operation {
            ContextOperation::AdvanceCursor { cursor_name, .. } => Some(cursor_name.as_str()),
            _ => None,
        })
        .collect::<HashSet<_>>();
    let mut new_cursors = 0_i64;
    for cursor_name in &new_cursor_names {
        let cursor_key = scope.pseudonym(lookup_key, b"cursor", cursor_name);
        let existing = conn
            .query_row(
                "SELECT 1 FROM cursors WHERE scope_key=?1 AND cursor_key=?2 LIMIT 1",
                params![scope.key.as_slice(), cursor_key.as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !existing {
            new_cursors = new_cursors.saturating_add(1);
        }
    }
    if existing_cursors.saturating_add(new_cursors) > MAX_CURSORS_PER_SCOPE {
        bail!("context cursor-count safety cap exceeded");
    }

    for object_id in new_object_ids {
        let object_key = scope.pseudonym(lookup_key, b"object", object_id);
        let existing_revisions: i64 = conn.query_row(
            "SELECT COUNT(*) FROM revisions WHERE scope_key=?1 AND object_key=?2",
            params![scope.key.as_slice(), object_key.as_slice()],
            |row| row.get(0),
        )?;
        let incoming_revisions = operations
            .iter()
            .filter(|operation| {
                matches!(operation, ContextOperation::PutRevision { object, .. } if object.object_id == object_id)
            })
            .count() as i64;
        if existing_revisions.saturating_add(incoming_revisions) > MAX_REVISIONS_PER_OBJECT {
            bail!("context revision-count safety cap exceeded");
        }
    }
    Ok(())
}

fn encrypted_storage_len(plaintext_len: usize) -> Result<i64> {
    let plaintext_len = i64::try_from(plaintext_len)
        .map_err(|_| anyhow!("content length overflows quota accounting"))?;
    plaintext_len
        .checked_add(ENCRYPTED_VALUE_OVERHEAD)
        .ok_or_else(|| anyhow!("encrypted value length overflows quota accounting"))
}

fn validate_batch(batch: &CommitBatch, permits_context_evidence_receipt: bool) -> Result<()> {
    if batch.operations.is_empty() || batch.operations.len() > MAX_BATCH_OPS {
        bail!("context batch must contain 1..={MAX_BATCH_OPS} operations");
    }
    validate_identifier("source batch key", &batch.source_batch_key.0)?;
    let mut source_keys = HashSet::with_capacity(batch.operations.len());
    let mut cursor_names = HashSet::new();
    for op in &batch.operations {
        validate_identifier("source mutation key", &operation_source_key(op).0)?;
        if !source_keys.insert(operation_source_key(op).0.as_str()) {
            bail!("context batch contains a duplicate source mutation key");
        }
        match op {
            ContextOperation::PutRevision {
                object,
                content,
                provenance,
                receipt,
                ..
            } => {
                validate_identifier("object id", &object.object_id)?;
                if content.is_empty() || content.len() > MAX_CONTENT_BYTES {
                    bail!("context content must contain 1..={MAX_CONTENT_BYTES} bytes");
                }
                if provenance.source_ref.is_empty()
                    || provenance.source_ref.len() > MAX_PROVENANCE_BYTES
                {
                    bail!("provenance reference must contain 1..={MAX_PROVENANCE_BYTES} bytes");
                }
                if *receipt != AuditReceipt::RevisionStored {
                    if *receipt != AuditReceipt::ContextEvidenceStored
                        || !permits_context_evidence_receipt
                    {
                        bail!("revision mutations require RevisionStored receipt");
                    }
                }
            }
            ContextOperation::Tombstone {
                object_id, receipt, ..
            } => {
                validate_identifier("object id", object_id)?;
                if *receipt != AuditReceipt::ObjectTombstoned {
                    bail!("tombstones require ObjectTombstoned receipt");
                }
            }
            ContextOperation::AdvanceCursor {
                cursor_name,
                cursor,
                receipt,
                ..
            } => {
                validate_identifier("cursor name", cursor_name)?;
                if cursor.len() > MAX_CURSOR_BYTES {
                    bail!("cursor exceeds {MAX_CURSOR_BYTES} bytes");
                }
                if !cursor_names.insert(cursor_name.as_str()) {
                    bail!("context batch contains multiple updates for one cursor");
                }
                if *receipt != AuditReceipt::CursorAdvanced {
                    bail!("cursor mutations require CursorAdvanced receipt");
                }
            }
        }
    }
    Ok(())
}

fn operation_source_key(operation: &ContextOperation) -> &SourceKey {
    match operation {
        ContextOperation::PutRevision { source_key, .. }
        | ContextOperation::Tombstone { source_key, .. }
        | ContextOperation::AdvanceCursor { source_key, .. } => source_key,
    }
}

fn receipt_code(receipt: AuditReceipt) -> i64 {
    match receipt {
        AuditReceipt::RevisionStored => 1,
        AuditReceipt::ObjectTombstoned => 2,
        AuditReceipt::CursorAdvanced => 3,
        AuditReceipt::ContextEvidenceStored => 4,
    }
}
fn receipt_from_code(code: i64) -> rusqlite::Result<AuditReceipt> {
    match code {
        1 => Ok(AuditReceipt::RevisionStored),
        2 => Ok(AuditReceipt::ObjectTombstoned),
        3 => Ok(AuditReceipt::CursorAdvanced),
        4 => Ok(AuditReceipt::ContextEvidenceStored),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn validate_identifier(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        bail!("{label} must be 1..={MAX_ID_BYTES} ASCII [A-Za-z0-9._:-] bytes");
    }
    Ok(())
}

fn aad(domain: &[u8], scope: &Scope, name: &str, revision: i64) -> Vec<u8> {
    [
        domain,
        b"\0",
        &scope.key,
        b"\0",
        name.as_bytes(),
        b"\0",
        &revision.to_le_bytes(),
    ]
    .concat()
}
fn encrypt_value(
    key: &WalSegmentKey,
    domain: &[u8],
    scope: &Scope,
    name: &str,
    revision: i64,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|e| anyhow!("context-store nonce RNG: {e}"))?;
    let ciphertext = encrypt_blob(key, &nonce, &aad(domain, scope, name, revision), plaintext)?;
    Ok(crate::wal::crypto::frame_encrypted(&nonce, &ciphertext))
}
fn decrypt_value(
    key: &WalSegmentKey,
    domain: &[u8],
    scope: &Scope,
    name: &str,
    revision: i64,
    blob: &[u8],
) -> Result<Vec<u8>> {
    let (nonce, ciphertext) = crate::wal::crypto::split_encrypted(blob)?;
    decrypt_blob(key, &nonce, &aad(domain, scope, name, revision), ciphertext)
}

fn reject_links(path: &Path) -> Result<()> {
    let mut current = Some(path);
    while let Some(candidate) = current {
        match fs::symlink_metadata(candidate) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!(
                    "context store path contains a symbolic link: {}",
                    candidate.display()
                );
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "inspect context store path component {}",
                        candidate.display()
                    )
                });
            }
        }
        current = candidate.parent();
    }
    Ok(())
}

#[cfg(not(windows))]
fn ensure_private_parent(parent: &Path) -> Result<()> {
    if !parent.exists() {
        bail!(
            "context store parent must already exist and be private: {}",
            parent.display()
        );
    }
    reject_links(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(parent)?.permissions().mode() & 0o077 != 0 {
            bail!("context store parent is not private: {}", parent.display());
        }
    }
    Ok(())
}

fn reject_database_sidecars(path: &Path) -> Result<()> {
    for candidate in [
        path.to_path_buf(),
        sqlite_sidecar_path(path, "-wal"),
        sqlite_sidecar_path(path, "-shm"),
    ] {
        reject_links(&candidate)?;
    }
    Ok(())
}

fn sqlite_sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut sidecar = path.as_os_str().to_os_string();
    sidecar.push(suffix);
    PathBuf::from(sidecar)
}

#[cfg(not(windows))]
fn restrict_database_sidecars(path: &Path) -> Result<()> {
    #[cfg(not(unix))]
    let _ = path;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for candidate in [
            path.to_path_buf(),
            sqlite_sidecar_path(path, "-wal"),
            sqlite_sidecar_path(path, "-shm"),
        ] {
            match fs::symlink_metadata(&candidate) {
                Ok(metadata) => {
                    reject_links(&candidate)?;
                    if !metadata.file_type().is_file() {
                        bail!("context database sidecar must be a regular file");
                    }
                    fs::set_permissions(candidate, fs::Permissions::from_mode(0o600))?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("inspect context database sidecar {}", candidate.display())
                    });
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
fn test_master_key() -> &'static WalMasterKey {
    static KEY: std::sync::OnceLock<WalMasterKey> = std::sync::OnceLock::new();
    KEY.get_or_init(|| WalMasterKey::generate().expect("generate context-store test key"))
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    fn store() -> ContextStore {
        let home = crate::test_env::canonical_tempdir().unwrap().keep();
        ContextStore::open_at(home.join("context.db"), test_master_key()).unwrap()
    }
    fn account() -> AccountContext {
        AccountContext::from_authenticated_identity("principal-a", "local-import").unwrap()
    }
    fn other_account() -> AccountContext {
        AccountContext::from_authenticated_identity("principal-b", "local-import").unwrap()
    }
    fn key(value: &str) -> SourceKey {
        SourceKey::new(value).unwrap()
    }

    fn v5_connection(path: &Path) -> Connection {
        let conn = Connection::open(path).unwrap();
        configure_connection(&conn).unwrap();
        let journal_mode: String = conn
            .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
            .unwrap();
        assert!(journal_mode.eq_ignore_ascii_case("wal"));
        for (table_name, statement) in EXPECTED_TABLE_SQL {
            conn.execute(
                if *table_name == "audit_outbox" {
                    V5_AUDIT_OUTBOX_SQL
                } else {
                    statement
                },
                [],
            )
            .unwrap();
        }
        conn.execute_batch(&format!(
            "PRAGMA application_id={APPLICATION_ID}; PRAGMA user_version={};",
            SCHEMA_VERSION - 1,
        ))
        .unwrap();
        conn
    }

    #[test]
    fn canonical_v5_outbox_migrates_atomically_without_losing_rows() {
        let home = crate::test_env::canonical_tempdir().unwrap().keep();
        let path = home.join("context.db");
        let conn = v5_connection(&path);
        conn.execute(
            "INSERT INTO events(scope_key,mutation_key,object_key,revision,receipt_code,occurred_at_ms) VALUES(?1,?2,NULL,NULL,1,0)",
            params![&[7_u8; 32][..], &[8_u8; 32][..]],
        )
        .unwrap();
        let event_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO audit_outbox(event_id,scope_key,receipt_code,occurred_at_ms,mutation_key) VALUES(?1,?2,1,0,?3)",
            params![event_id, &[7_u8; 32][..], &[8_u8; 32][..]],
        )
        .unwrap();
        validate_or_initialize_schema(&conn, true).unwrap();
        validate_schema(&conn).unwrap();
        assert_eq!(conn.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0)).unwrap(), SCHEMA_VERSION);
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM audit_outbox", [], |row| row.get::<_, i64>(0)).unwrap(), 1);
        assert_eq!(
            conn.query_row(
                "SELECT policy_revision IS NULL AND lifecycle_revision IS NULL FROM audit_outbox WHERE event_id=?1",
                [event_id],
                |row| row.get::<_, bool>(0),
            )
            .unwrap(),
            true,
        );
    }

    #[test]
    fn malformed_v5_is_rejected_before_schema_or_data_mutation() {
        let home = crate::test_env::canonical_tempdir().unwrap().keep();
        let path = home.join("context.db");
        let conn = v5_connection(&path);
        conn.execute_batch("DROP TABLE audit_outbox; CREATE TABLE audit_outbox (event_id INTEGER PRIMARY KEY, scope_key BLOB NOT NULL, receipt_code INTEGER NOT NULL, occurred_at_ms INTEGER NOT NULL, mutation_key BLOB NOT NULL);")
            .unwrap();
        assert!(validate_or_initialize_schema(&conn, true).is_err());
        assert_eq!(conn.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0)).unwrap(), SCHEMA_VERSION - 1);
        let sql: String = conn
            .query_row("SELECT sql FROM sqlite_master WHERE type='table' AND name='audit_outbox'", [], |row| row.get(0))
            .unwrap();
        assert!(!sql.contains("policy_revision"));
    }

    #[test]
    fn audit_outbox_enforces_context_receipt_revision_pairs() {
        let mut store = store();
        let scope = store.scope(&account());
        for (receipt, policy, lifecycle) in [(4_i64, None, None), (1_i64, Some(7_i64), Some(11_i64))] {
            store.conn.execute(
                "INSERT INTO events(scope_key,mutation_key,object_key,revision,receipt_code,occurred_at_ms) VALUES(?1,?2,NULL,NULL,?3,0)",
                params![scope.key.as_slice(), [receipt as u8; 32].as_slice(), receipt],
            ).unwrap();
            let event_id = store.conn.last_insert_rowid();
            assert!(store.conn.execute(
                "INSERT INTO audit_outbox(event_id,scope_key,receipt_code,occurred_at_ms,mutation_key,policy_revision,lifecycle_revision) VALUES(?1,?2,?3,0,?4,?5,?6)",
                params![event_id, scope.key.as_slice(), receipt, [receipt as u8; 32].as_slice(), policy, lifecycle],
            ).is_err());
        }
    }
    fn put(source_key: &str, content: &[u8]) -> ContextOperation {
        ContextOperation::PutRevision {
            source_key: key(source_key),
            object: ObjectRef {
                object_id: "note-1".into(),
                object_kind: ObjectKind::Note,
            },
            content: content.into(),
            provenance: Provenance {
                source_kind: ProvenanceKind::Connector,
                source_ref: "provider:object-1".into(),
            },
            receipt: AuditReceipt::RevisionStored,
        }
    }
    #[test]
    fn encrypted_account_scoped_round_trip_and_idempotency() {
        let mut store = store();
        let account = account();
        let batch = CommitBatch {
            source_batch_key: key("page-1"),
            operations: vec![
                put("revision-1", b"plaintext must not persist"),
                ContextOperation::AdvanceCursor {
                    source_key: key("cursor-1"),
                    cursor_name: "feed".into(),
                    cursor: b"cursor-value".to_vec(),
                    receipt: AuditReceipt::CursorAdvanced,
                },
            ],
        };
        store.commit_batch(&account, &batch).unwrap();
        store.commit_batch(&account, &batch).unwrap();
        assert_eq!(
            store.revision_content(&account, "note-1", 1).unwrap(),
            Some(b"plaintext must not persist".to_vec())
        );
        assert_eq!(store.revision_content(&account, "note-1", 2).unwrap(), None);
        assert_eq!(
            store.cursor(&account, "feed").unwrap(),
            Some(b"cursor-value".to_vec())
        );
        assert_eq!(store.pending_audit(&account).unwrap().len(), 2);
        let bytes = fs::read(store.path()).unwrap();
        assert!(
            !bytes
                .windows(b"plaintext must not persist".len())
                .any(|w| w == b"plaintext must not persist")
        );
        assert!(
            !bytes
                .windows(b"cursor-value".len())
                .any(|w| w == b"cursor-value")
        );
        for plaintext_identifier in [
            "principal-a",
            "local-import",
            "note-1",
            "page-1",
            "revision-1",
            "feed",
        ] {
            assert!(
                !bytes
                    .windows(plaintext_identifier.len())
                    .any(|window| window == plaintext_identifier.as_bytes()),
                "plaintext identifier {plaintext_identifier:?} persisted"
            );
        }
    }

    #[test]
    fn reopened_partial_schema_is_rejected_even_with_matching_version_pragmas() {
        let store = store();
        let path = store.path().to_path_buf();
        store.conn.execute("DROP TABLE provenance", []).unwrap();
        drop(store);

        let error = ContextStore::open_at(&path, test_master_key())
            .err()
            .expect("partial schema must fail closed on reopen");
        assert!(error.to_string().contains("schema"));
    }

    #[test]
    fn security_pragmas_are_reapplied_and_verified_on_every_open() {
        let store = store();
        let path = store.path().to_path_buf();
        drop(store);
        let reopened = ContextStore::open_at(&path, test_master_key()).unwrap();
        for (pragma, expected) in [
            ("foreign_keys", 1),
            ("secure_delete", 1),
            ("trusted_schema", 0),
            ("synchronous", 2),
            ("temp_store", 2),
            ("wal_autocheckpoint", WAL_AUTOCHECKPOINT_PAGES),
            ("journal_size_limit", JOURNAL_SIZE_LIMIT_BYTES),
        ] {
            let actual: i64 = reopened
                .conn
                .query_row(&format!("PRAGMA {pragma}"), [], |row| row.get(0))
                .unwrap();
            assert_eq!(actual, expected, "PRAGMA {pragma}");
        }
    }

    #[test]
    fn blocked_reader_near_cap_rejects_before_any_durable_claim() {
        let mut store = store();
        let reader = Connection::open(store.path()).unwrap();
        reader
            .execute_batch("PRAGMA query_only=ON; BEGIN DEFERRED")
            .unwrap();
        let _: i64 = reader
            .query_row("SELECT COUNT(*) FROM scopes", [], |row| row.get(0))
            .unwrap();

        let account = account();
        let batch = CommitBatch {
            source_batch_key: key("pinned-reader-near-cap-page"),
            operations: vec![put("pinned-reader-near-cap-revision", b"never-stored")],
        };
        let operations = batch.operations.iter().collect::<Vec<_>>();
        let page_size: i64 = store
            .conn
            .query_row("PRAGMA page_size", [], |row| row.get(0))
            .unwrap();
        let page_count: i64 = store
            .conn
            .query_row("PRAGMA page_count", [], |row| row.get(0))
            .unwrap();
        let logical_bytes = page_count.checked_mul(page_size).unwrap();
        let footprint = physical_store_footprint(store.path()).unwrap();
        let single_destination_growth =
            projected_store_growth(page_size, true, &operations).unwrap();
        let old_single_reservation_limit = logical_bytes
            .max(footprint.total_bytes().unwrap())
            .checked_add(single_destination_growth)
            .unwrap();
        assert!(
            projected_database_and_pinned_wal_growth(single_destination_growth, page_size).unwrap()
                > single_destination_growth,
            "admission must reserve DB and pinned WAL, not one destination"
        );

        let result = store.commit_batch_with_limits(
            &account,
            &batch,
            StoreLimits {
                max_scopes: MAX_SCOPES_PER_STORE,
                max_bytes: old_single_reservation_limit,
            },
        );
        assert!(result.is_err());
        for table in ["scopes", "applied_mutations", "applied_batches"] {
            let count: i64 = store
                .conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "near-cap rejection leaked a row into {table}");
        }
        reader.execute_batch("ROLLBACK").unwrap();
    }

    #[test]
    fn wal_index_geometry_reserves_first_and_later_region_boundaries() {
        assert_eq!(
            projected_wal_index_bytes(4062).unwrap(),
            WAL_INDEX_REGION_BYTES
        );
        assert_eq!(
            projected_wal_index_bytes(4063).unwrap(),
            2 * WAL_INDEX_REGION_BYTES
        );
        assert_eq!(
            projected_wal_index_bytes(8158).unwrap(),
            2 * WAL_INDEX_REGION_BYTES
        );
        assert_eq!(
            projected_wal_index_bytes(8159).unwrap(),
            3 * WAL_INDEX_REGION_BYTES
        );
        assert!(projected_wal_index_bytes(i64::MAX).is_err());
    }

    #[test]
    fn audit_receipt_handle_is_scope_bound_and_hides_global_row_ids() {
        let mut store = store();
        let first = account();
        let second = other_account();
        for (account, page) in [
            (&first, "first-receipt-page"),
            (&second, "second-receipt-page"),
        ] {
            store
                .commit_batch(
                    account,
                    &CommitBatch {
                        source_batch_key: key(page),
                        operations: vec![put("shared-source-key", b"content")],
                    },
                )
                .unwrap();
        }
        let first_entry = store.pending_audit(&first).unwrap().remove(0);
        let second_entry = store.pending_audit(&second).unwrap().remove(0);
        assert_ne!(first_entry.handle, second_entry.handle);
        assert_eq!(
            format!("{:?}", first_entry.handle),
            "AuditReceiptHandle(***)"
        );
        let debug = format!("{first_entry:?}");
        assert!(!debug.contains("row_id"));
        let now_minute = Utc::now().timestamp_millis().div_euclid(60_000);
        assert!((0..=1).contains(&(now_minute - first_entry.occurred_at_unix_minute)));
    }

    #[test]
    fn authenticated_capability_scopes_all_reads_to_its_account() {
        let mut store = store();
        let owner = account();
        let neighbour = other_account();
        assert_eq!(format!("{owner:?}"), "AccountContext(***)");
        store
            .commit_batch(
                &owner,
                &CommitBatch {
                    source_batch_key: key("owner-page"),
                    operations: vec![put("owner-revision", b"owner-only")],
                },
            )
            .unwrap();

        assert_eq!(
            store.revision_content(&neighbour, "note-1", 1).unwrap(),
            None
        );
        assert!(store.pending_audit(&neighbour).unwrap().is_empty());
    }

    #[test]
    fn invalid_payload_is_rejected_before_any_batch_claim_is_durable() {
        let mut store = store();
        let account = account();
        let batch = CommitBatch {
            source_batch_key: key("oversized-page"),
            operations: vec![put("oversized-revision", &vec![0; MAX_CONTENT_BYTES + 1])],
        };
        assert!(store.commit_batch(&account, &batch).is_err());
        let claims: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM applied_batches", [], |row| row.get(0))
            .unwrap();
        assert_eq!(claims, 0);
    }

    #[test]
    fn store_scope_cap_rejects_a_new_account_without_leaking_claims() {
        let mut store = store();
        let first = account();
        store
            .commit_batch(
                &first,
                &CommitBatch {
                    source_batch_key: key("first-account-page"),
                    operations: vec![put("first-account-revision", b"first")],
                },
            )
            .unwrap();

        let second = other_account();
        let result = store.commit_batch_with_limits(
            &second,
            &CommitBatch {
                source_batch_key: key("second-account-page"),
                operations: vec![put("second-account-revision", b"second")],
            },
            StoreLimits {
                max_scopes: 1,
                max_bytes: i64::MAX,
            },
        );
        assert!(result.is_err());
        let scopes: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM scopes", [], |row| row.get(0))
            .unwrap();
        let claims: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM applied_mutations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(scopes, 1);
        assert_eq!(claims, 1, "rejected account must not retain a claim");
    }

    #[test]
    fn store_byte_cap_rejects_new_work_before_any_claim_or_scope_is_durable() {
        let mut store = store();
        let account = account();
        let page_count: i64 = store
            .conn
            .query_row("PRAGMA page_count", [], |row| row.get(0))
            .unwrap();
        let page_size: i64 = store
            .conn
            .query_row("PRAGMA page_size", [], |row| row.get(0))
            .unwrap();
        let current_bytes = page_count.checked_mul(page_size).unwrap();
        let result = store.commit_batch_with_limits(
            &account,
            &CommitBatch {
                source_batch_key: key("byte-capped-page"),
                operations: vec![put("byte-capped-revision", b"never-stored")],
            },
            StoreLimits {
                max_scopes: MAX_SCOPES_PER_STORE,
                max_bytes: current_bytes,
            },
        );
        assert!(result.is_err());
        let scopes: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM scopes", [], |row| row.get(0))
            .unwrap();
        let claims: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM applied_mutations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(scopes, 0);
        assert_eq!(claims, 0, "rejected byte growth must not retain a claim");
    }

    #[test]
    fn exact_replay_is_allowed_when_store_admission_is_now_exhausted() {
        let mut store = store();
        let account = account();
        let batch = CommitBatch {
            source_batch_key: key("replay-page"),
            operations: vec![put("replay-revision", b"stored-once")],
        };
        store.commit_batch(&account, &batch).unwrap();
        store
            .commit_batch_with_limits(
                &account,
                &batch,
                StoreLimits {
                    max_scopes: 0,
                    max_bytes: 0,
                },
            )
            .unwrap();
        store
            .commit_batch_with_limits(
                &account,
                &CommitBatch {
                    source_batch_key: key("replay-page-with-no-new-ops"),
                    operations: vec![put("replay-revision", b"ignored-retry-payload")],
                },
                StoreLimits {
                    max_scopes: 0,
                    max_bytes: 0,
                },
            )
            .unwrap();
        let revisions: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM revisions", [], |row| row.get(0))
            .unwrap();
        assert_eq!(revisions, 1);
        let retained_batches: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM applied_batches", [], |row| row.get(0))
            .unwrap();
        assert_eq!(retained_batches, 1);
    }

    #[test]
    fn wal_recovery_quarantine_blocks_only_new_mutations() {
        let mut store = store();
        let path = store.path().to_path_buf();
        let account = account();
        let committed = CommitBatch {
            source_batch_key: key("committed-before-recovery"),
            operations: vec![put("committed-before-recovery-op", b"durable")],
        };
        store.fail_next_post_commit_maintenance = true;
        store
            .commit_batch(&account, &committed)
            .expect("durable mutation must not return a false maintenance failure");
        let retained_generation = maintenance_generation(&store.conn)
            .unwrap()
            .expect("failed post-commit maintenance must retain its DB generation");

        store.commit_batch(&account, &committed).unwrap();
        store.fail_next_recovery_maintenance = true;
        assert!(
            store
                .commit_batch(
                    &account,
                    &CommitBatch {
                        source_batch_key: key("blocked-during-recovery"),
                        operations: vec![put("blocked-during-recovery-op", b"blocked")],
                    },
                )
                .is_err()
        );
        assert_eq!(
            maintenance_generation(&store.conn).unwrap(),
            Some(retained_generation)
        );
        let revisions: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM revisions", [], |row| row.get(0))
            .unwrap();
        assert_eq!(revisions, 1);

        drop(store);
        let mut recovered = ContextStore::open_at(&path, test_master_key()).unwrap();
        assert!(maintenance_generation(&recovered.conn).unwrap().is_none());
        recovered
            .commit_batch(
                &account,
                &CommitBatch {
                    source_batch_key: key("accepted-after-recovery"),
                    operations: vec![put("accepted-after-recovery-op", b"after-recovery")],
                },
            )
            .unwrap();
    }

    #[test]
    fn second_handle_recovers_persisted_generation_before_its_new_write() {
        let mut first = store();
        let path = first.path().to_path_buf();
        let mut second = ContextStore::open_at(&path, test_master_key()).unwrap();
        let account = account();

        first.fail_next_post_commit_maintenance = true;
        first
            .commit_batch(
                &account,
                &CommitBatch {
                    source_batch_key: key("first-handle-page"),
                    operations: vec![put("first-handle-operation", b"first")],
                },
            )
            .unwrap();
        assert!(maintenance_generation(&first.conn).unwrap().is_some());

        second
            .commit_batch(
                &account,
                &CommitBatch {
                    source_batch_key: key("second-handle-page"),
                    operations: vec![put("second-handle-operation", b"second")],
                },
            )
            .unwrap();
        assert!(maintenance_generation(&second.conn).unwrap().is_none());
        let revisions: i64 = second
            .conn
            .query_row("SELECT COUNT(*) FROM revisions", [], |row| row.get(0))
            .unwrap();
        assert_eq!(revisions, 2);
    }

    #[test]
    fn stale_recovery_cannot_clear_a_newer_writer_generation() {
        let mut store = store();
        let current = [7_u8; 32];
        store
            .conn
            .execute(
                "INSERT INTO store_state(state_key,generation,set_at_ms) VALUES('maintenance_required',?1,0)",
                [current.as_slice()],
            )
            .unwrap();
        clear_maintenance_generation(&mut store.conn, [6_u8; 32]).unwrap();
        assert_eq!(maintenance_generation(&store.conn).unwrap(), Some(current));
        clear_maintenance_generation(&mut store.conn, current).unwrap();
        assert!(maintenance_generation(&store.conn).unwrap().is_none());
    }

    #[test]
    fn duplicate_mutation_or_cursor_targets_are_rejected_as_ambiguous() {
        let mut store = store();
        let account = account();
        let duplicate_mutation = CommitBatch {
            source_batch_key: key("duplicate-mutation-page"),
            operations: vec![put("same-key", b"first"), put("same-key", b"second")],
        };
        assert!(store.commit_batch(&account, &duplicate_mutation).is_err());

        let duplicate_cursor = CommitBatch {
            source_batch_key: key("duplicate-cursor-page"),
            operations: vec![
                ContextOperation::AdvanceCursor {
                    source_key: key("cursor-one"),
                    cursor_name: "feed".into(),
                    cursor: b"one".to_vec(),
                    receipt: AuditReceipt::CursorAdvanced,
                },
                ContextOperation::AdvanceCursor {
                    source_key: key("cursor-two"),
                    cursor_name: "feed".into(),
                    cursor: b"two".to_vec(),
                    receipt: AuditReceipt::CursorAdvanced,
                },
            ],
        };
        assert!(store.commit_batch(&account, &duplicate_cursor).is_err());
    }

    #[test]
    fn outbox_cap_rejects_new_work_without_appending_another_event() {
        let mut store = store();
        let account = account();
        let scope = store.scope(&account);
        for number in 0..MAX_PENDING_AUDIT_ENTRIES {
            let mut mutation_key = [0_u8; 32];
            mutation_key[..8].copy_from_slice(&(number as u64).to_le_bytes());
            store
                .conn
                .execute(
                    "INSERT INTO events(scope_key,mutation_key,object_key,revision,receipt_code,occurred_at_ms) VALUES(?1,?2,NULL,NULL,?3,0)",
                    params![scope.key.as_slice(), mutation_key.as_slice(), receipt_code(AuditReceipt::CursorAdvanced)],
                )
                .unwrap();
            let event_id = store.conn.last_insert_rowid();
            store
                .conn
                .execute(
                    "INSERT INTO audit_outbox(event_id,scope_key,receipt_code,occurred_at_ms,mutation_key) VALUES(?1,?2,?3,0,?4)",
                    params![event_id, scope.key.as_slice(), receipt_code(AuditReceipt::CursorAdvanced), mutation_key.as_slice()],
                )
                .unwrap();
        }
        assert!(
            store
                .commit_batch(
                    &account,
                    &CommitBatch {
                        source_batch_key: key("blocked-outbox-page"),
                        operations: vec![put("blocked-outbox-revision", b"never-stored")],
                    },
                )
                .is_err()
        );
        assert_eq!(
            store.pending_audit(&account).unwrap().len() as i64,
            MAX_PENDING_AUDIT_ENTRIES
        );
    }

    #[cfg(unix)]
    #[test]
    fn linked_database_or_sidecar_is_rejected_before_sqlite_opens_it() {
        use std::os::unix::fs::symlink;

        let home = crate::test_env::canonical_tempdir().unwrap();
        let target = home.path().join("outside.db");
        fs::write(&target, b"not a database").unwrap();
        let db = home.path().join("context.db");
        symlink(&target, &db).unwrap();
        assert!(ContextStore::open_at(&db, test_master_key()).is_err());

        fs::remove_file(&db).unwrap();
        let wal = sqlite_sidecar_path(&db, "-wal");
        symlink(&target, &wal).unwrap();
        assert!(ContextStore::open_at(&db, test_master_key()).is_err());
    }
    #[test]
    fn repeated_mutation_key_in_a_new_batch_is_a_noop() {
        let mut store = store();
        let account = account();
        store
            .commit_batch(
                &account,
                &CommitBatch {
                    source_batch_key: key("page-1"),
                    operations: vec![put("revision-1", b"first")],
                },
            )
            .unwrap();
        store
            .commit_batch(
                &account,
                &CommitBatch {
                    source_batch_key: key("page-2"),
                    operations: vec![put("revision-1", b"retry")],
                },
            )
            .unwrap();
        assert_eq!(store.revision_content(&account, "note-1", 2).unwrap(), None);
        assert_eq!(store.pending_audit(&account).unwrap().len(), 1);
        let retained_batches: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM applied_batches", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            retained_batches, 1,
            "fully replayed page must not consume a batch key"
        );
    }
    #[test]
    fn tombstone_is_terminal_and_erase_is_not_an_api() {
        let mut store = store();
        let account = account();
        store
            .commit_batch(
                &account,
                &CommitBatch {
                    source_batch_key: key("page-1"),
                    operations: vec![put("revision-1", b"before")],
                },
            )
            .unwrap();
        store
            .commit_batch(
                &account,
                &CommitBatch {
                    source_batch_key: key("page-2"),
                    operations: vec![ContextOperation::Tombstone {
                        source_key: key("delete-1"),
                        object_id: "note-1".into(),
                        receipt: AuditReceipt::ObjectTombstoned,
                    }],
                },
            )
            .unwrap();
        assert!(
            store
                .commit_batch(
                    &account,
                    &CommitBatch {
                        source_batch_key: key("page-3"),
                        operations: vec![put("revision-2", b"after")]
                    }
                )
                .is_err()
        );
        assert!(
            maintenance_generation(&store.conn).unwrap().is_none(),
            "a rolled-back mutation must roll back its maintenance generation"
        );
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    #[test]
    fn context_store_fails_closed_without_a_capability_bound_sqlite_vfs() {
        let home = crate::test_env::canonical_tempdir().unwrap();
        let path = home.path().join("context.db");
        let error = ContextStore::open_at(&path, test_master_key())
            .err()
            .expect("Windows context storage must remain unavailable without a bound SQLite VFS");
        assert!(error.to_string().contains("capability-bound SQLite VFS"));
        assert!(
            !path.exists(),
            "the fail-closed Windows gate must not create context.db before it can bind SQLite's exact handles"
        );
    }
}
