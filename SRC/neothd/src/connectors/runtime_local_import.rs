//! CC-RUNTIME-P0's intentionally un-wired local-import coordinator.
//!
//! This is a crate-private bridge between a non-live CC-01 runtime binding,
//! the capability-relative LocalImport reader, the encrypted ContextStore and
//! its durable receipt outbox. It is not a daemon, RPC handler, CLI command,
//! scheduler, provider, message-transport, action, or MCP surface. Each
//! effect acquires and drops a fresh short-lived operation lease; idle runtime
//! objects therefore cannot block retirement.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow, bail};
use crate::{
    connectors::{
        control_plane::{ContextImportOperationLease, ContextImportRuntimeBinding},
        local_import::{
            LocalImportPlan, LocalImportPlanId, LocalImportPolicy, LocalImportRequest,
            OperatorImportCapability, plan_operator_selected_file,
        },
    },
    context_graph::{
        AuditOutboxEntry, AuditReceipt, AuditReceiptSink, ContextStore,
        UntrustedExternalEvidenceBatch,
    },
    wal::events::{ContextEvidenceReceipt, ContextEvidenceReceiptKind},
};

const MAX_RETAINED_PLANS: usize = 64;
const DEFAULT_PLAN_TTL: Duration = Duration::from_secs(5 * 60);

/// The only P0 WAL seam. The caller supplies a real WAL adapter later; this
/// coordinator deliberately knows neither WAL paths nor writer handles.
pub(crate) trait ContextEvidenceWalSink {
    /// Persist this opaque handle at most once. A duplicate handle is a
    /// successful acknowledgement, allowing DB-success/WAL-crash recovery
    /// without duplicating a receipt.
    fn append_context_evidence_receipt_once(
        &mut self,
        receipt_handle: &[u8; 32],
        receipt: ContextEvidenceReceipt,
    ) -> Result<()>;
}

struct RetainedPlan {
    plan: LocalImportPlan,
    selected_relative_path: PathBuf,
    expires_at: Instant,
}

/// Capability-owned, in-memory-only import coordinator. It never persists a
/// path, a plan, imported text, or an operator identity outside ContextStore's
/// encrypted Evidence representation. Process restart drops every plan.
pub(crate) struct RuntimeLocalImport {
    capability: OperatorImportCapability,
    runtime_binding: ContextImportRuntimeBinding,
    store: ContextStore,
    plans: BTreeMap<LocalImportPlanId, RetainedPlan>,
    plan_ttl: Duration,
}

impl RuntimeLocalImport {
    pub(crate) fn new(
        capability: OperatorImportCapability,
        runtime_binding: ContextImportRuntimeBinding,
        store: ContextStore,
    ) -> Result<Self> {
        Self::with_plan_ttl(capability, runtime_binding, store, DEFAULT_PLAN_TTL)
    }

    pub(crate) fn with_plan_ttl(
        capability: OperatorImportCapability,
        runtime_binding: ContextImportRuntimeBinding,
        store: ContextStore,
        plan_ttl: Duration,
    ) -> Result<Self> {
        if !capability.binding_matches_runtime(&runtime_binding) {
            bail!("local-import runtime requires an exact capability and binding pair");
        }
        Ok(Self {
            capability,
            runtime_binding,
            store,
            plans: BTreeMap::new(),
            plan_ttl,
        })
    }

    /// Plan one operator-selected path through the existing no-follow,
    /// capability-relative reader. The opaque HMAC plan id is returned; no
    /// raw path or imported record text appears in the result.
    pub(crate) fn plan_import(
        &mut self,
        selected_relative_path: &Path,
    ) -> Result<LocalImportPlanId> {
        let lease = self.acquire_live_operation_lease()?;
        self.purge_expired();
        if self.plans.len() >= MAX_RETAINED_PLANS {
            bail!("local-import plan retention cap reached");
        }
        let policy = LocalImportPolicy::default_bounded(self.runtime_binding.policy_revision())?;
        let plan = plan_operator_selected_file(LocalImportRequest::new(
            &self.capability,
            selected_relative_path,
            policy,
        )?)?;
        let id = plan.id();
        let expires_at = Instant::now()
            .checked_add(self.plan_ttl)
            .ok_or_else(|| anyhow!("local-import plan TTL overflow"))?;
        self.plans.insert(
            id,
            RetainedPlan {
                plan,
                selected_relative_path: selected_relative_path.to_path_buf(),
                expires_at,
            },
        );
        drop(lease);
        Ok(id)
    }

    /// Confirm exactly the previously returned plan once. The entry is removed
    /// before rereading its source or touching SQLite; a retry therefore needs
    /// a new explicit plan. Re-reading through the original capability detects
    /// a replacement/change between planning and confirmation.
    pub(crate) fn confirm_import(
        &mut self,
        plan_id: LocalImportPlanId,
        confirm_plan_id: LocalImportPlanId,
    ) -> Result<()> {
        if plan_id != confirm_plan_id {
            bail!("confirmed local-import plan id does not exactly match planned id");
        }
        let lease = self.acquire_live_operation_lease()?;
        self.purge_expired();
        let retained = self
            .plans
            .remove(&plan_id)
            .ok_or_else(|| anyhow!("local-import plan is absent, expired, or already consumed"))?;
        let policy = LocalImportPolicy::default_bounded(self.runtime_binding.policy_revision())?;
        let reread = plan_operator_selected_file(LocalImportRequest::new(
            &self.capability,
            &retained.selected_relative_path,
            policy,
        )?)?;
        if reread.id() != retained.plan.id()
            || reread.source_object_id() != retained.plan.source_object_id()
            || reread.version_fingerprint() != retained.plan.version_fingerprint()
            || reread.policy_revision() != retained.plan.policy_revision()
            || reread.parser_revision() != retained.plan.parser_revision()
        {
            bail!("local-import source changed after planning; a new explicit plan is required");
        }
        let evidence = UntrustedExternalEvidenceBatch::from_local_import_plan(&retained.plan)?;
        // ContextStore takes the short-lived lease's final commit permit
        // around the whole SQLite transaction.
        self.store.commit_local_import_evidence(
            &self.runtime_binding,
            &lease,
            evidence,
        )
    }

    /// Drain durable, content-free receipt rows to the supplied WAL adapter.
    /// A successful append removes exactly that row; a failed append leaves it
    /// durable for the next authenticated replay call.
    pub(crate) fn replay_receipts(
        &mut self,
        wal: &mut dyn ContextEvidenceWalSink,
    ) -> Result<usize> {
        let reserve_lease = self.acquire_live_operation_lease()?;
        let entries = self
            .store
            .reserve_local_import_audit(&self.runtime_binding, &reserve_lease)?;
        drop(reserve_lease);
        let mut adapter = ReceiptWalAdapter {
            wal,
        };
        let mut delivered = 0;
        for entry in entries {
            // WAL is explicitly outside the account gate. If retirement wins
            // before the following conditional ACK, the durable row remains
            // and append-once handle semantics make recovery safe.
            adapter.deliver(&entry)?;
            let acknowledge_lease = self.acquire_live_operation_lease()?;
            self.store.acknowledge_local_import_audit(
                &self.runtime_binding,
                &acknowledge_lease,
                &entry,
            )?;
            delivered += 1;
        }
        Ok(delivered)
    }

    fn acquire_live_operation_lease(&self) -> Result<ContextImportOperationLease> {
        let lease = self
            .runtime_binding
            .acquire_context_import_operation_lease()
            .map_err(|error| anyhow!(error))?;
        if !self.runtime_binding.matches_operation_lease(&lease)
            || !self.capability.binding_matches(&self.runtime_binding, &lease)
        {
            bail!("local-import runtime requires an exact live context-import lease binding");
        }
        lease.ensure_live().map_err(|error| anyhow!(error))?;
        Ok(lease)
    }

    fn purge_expired(&mut self) {
        let now = Instant::now();
        self.plans.retain(|_, plan| plan.expires_at > now);
    }
}

struct ReceiptWalAdapter<'a> {
    wal: &'a mut dyn ContextEvidenceWalSink,
}

impl AuditReceiptSink for ReceiptWalAdapter<'_> {
    fn deliver(&mut self, entry: &AuditOutboxEntry) -> Result<()> {
        if entry.receipt != AuditReceipt::ContextEvidenceStored {
            bail!("refusing to route a non-ContextEvidence audit entry to the WAL");
        }
        let (policy_revision, lifecycle_revision) = entry.context_evidence_revisions()?;
        let receipt = ContextEvidenceReceipt::new(
            hex(entry.handle.as_bytes()),
            ContextEvidenceReceiptKind::LocalImport,
            policy_revision,
            lifecycle_revision,
            entry.occurred_at_unix_minute.try_into().map_err(|_| anyhow!("negative audit receipt minute"))?,
        )?;
        self.wal
            .append_context_evidence_receipt_once(entry.handle.as_bytes(), receipt)
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;
    use crate::{
        connectors::{
            ConnectorId, ConnectorInstanceId, SubjectId,
            control_plane::test_context_import_runtime_fixture,
            local_import::{approve_import_root, issue_operator_import_capability},
        },
        wal::crypto::WalMasterKey,
    };

    struct RecordingWal {
        delivered: usize,
        fail: bool,
    }

    impl ContextEvidenceWalSink for RecordingWal {
        fn append_context_evidence_receipt_once(
            &mut self,
            _: &[u8; 32],
            _: ContextEvidenceReceipt,
        ) -> Result<()> {
            if self.fail {
                bail!("injected WAL append failure");
            }
            self.delivered += 1;
            Ok(())
        }
    }

    fn identity() -> (ConnectorInstanceId, SubjectId) {
        (
            ConnectorInstanceId::accountless(ConnectorId::LocalImport),
            SubjectId::new("operator").unwrap(),
        )
    }

    fn runtime(root: &Path) -> RuntimeLocalImport {
        let (instance, subject) = identity();
        let binding = test_context_import_runtime_fixture(
            instance.clone(),
            subject.clone(),
            7,
            11,
        )
        .unwrap();
        let capability = issue_operator_import_capability(
            approve_import_root(root).unwrap(),
            [42; 32],
            binding.capability_binding(),
        );
        let store_home = crate::test_env::canonical_tempdir().unwrap().keep();
        let store = ContextStore::open_at(
            store_home.join("context.db"),
            &WalMasterKey::generate().unwrap(),
        )
        .unwrap();
        RuntimeLocalImport::new(capability, binding, store).unwrap()
    }

    #[test]
    fn confirm_is_one_shot_and_receipt_replay_is_durable() {
        let root = crate::test_env::canonical_tempdir().unwrap();
        std::fs::write(root.path().join("selected.txt"), "untrusted evidence").unwrap();
        let mut runtime = runtime(root.path());
        let plan = runtime.plan_import(Path::new("selected.txt")).unwrap();
        runtime.confirm_import(plan, plan).unwrap();
        assert!(runtime.confirm_import(plan, plan).is_err());
        let mut wal = RecordingWal {
            delivered: 0,
            fail: false,
        };
        assert_eq!(runtime.replay_receipts(&mut wal).unwrap(), 1);
        assert_eq!(wal.delivered, 1);
        assert_eq!(runtime.replay_receipts(&mut wal).unwrap(), 0);
    }

    #[test]
    fn changed_source_is_consumed_without_a_store_or_receipt_effect() {
        let root = crate::test_env::canonical_tempdir().unwrap();
        let source = root.path().join("selected.txt");
        std::fs::write(&source, "first").unwrap();
        let mut runtime = runtime(root.path());
        let plan = runtime.plan_import(Path::new("selected.txt")).unwrap();
        std::fs::write(&source, "second").unwrap();
        assert!(runtime.confirm_import(plan, plan).is_err());
        let mut wal = RecordingWal {
            delivered: 0,
            fail: false,
        };
        assert_eq!(runtime.replay_receipts(&mut wal).unwrap(), 0);
    }

    #[test]
    fn failed_wal_ack_retains_the_exact_receipt_for_retry() {
        let root = crate::test_env::canonical_tempdir().unwrap();
        std::fs::write(root.path().join("selected.txt"), "receipt retry").unwrap();
        let mut runtime = runtime(root.path());
        let plan = runtime.plan_import(Path::new("selected.txt")).unwrap();
        runtime.confirm_import(plan, plan).unwrap();
        let mut failing = RecordingWal {
            delivered: 0,
            fail: true,
        };
        assert!(runtime.replay_receipts(&mut failing).is_err());
        let mut recovered = RecordingWal {
            delivered: 0,
            fail: false,
        };
        assert_eq!(runtime.replay_receipts(&mut recovered).unwrap(), 1);
        assert_eq!(recovered.delivered, 1);
    }

    #[test]
    fn construction_rejects_a_capability_witness_from_another_runtime_pair() {
        let root = crate::test_env::canonical_tempdir().unwrap();
        std::fs::write(root.path().join("selected.txt"), "cross lease").unwrap();
        let (instance, subject) = identity();
        let first_binding = test_context_import_runtime_fixture(
            instance.clone(),
            subject.clone(),
            7,
            11,
        )
        .unwrap();
        let second_binding = test_context_import_runtime_fixture(
            instance,
            subject,
            7,
            11,
        )
        .unwrap();
        let capability = issue_operator_import_capability(
            approve_import_root(root.path()).unwrap(),
            [42; 32],
            first_binding.capability_binding(),
        );
        let store_home = crate::test_env::canonical_tempdir().unwrap().keep();
        let store = ContextStore::open_at(
            store_home.join("context.db"),
            &WalMasterKey::generate().unwrap(),
        )
        .unwrap();
        assert!(RuntimeLocalImport::new(capability, second_binding, store).is_err());
    }

    #[test]
    fn expired_plan_never_reaches_store_or_wal() {
        let root = crate::test_env::canonical_tempdir().unwrap();
        std::fs::write(root.path().join("selected.txt"), "expiry").unwrap();
        let mut runtime = runtime(root.path());
        runtime.plan_ttl = Duration::ZERO;
        let plan = runtime.plan_import(Path::new("selected.txt")).unwrap();
        assert!(runtime.confirm_import(plan, plan).is_err());
        let mut wal = RecordingWal {
            delivered: 0,
            fail: false,
        };
        assert_eq!(runtime.replay_receipts(&mut wal).unwrap(), 0);
    }
}
