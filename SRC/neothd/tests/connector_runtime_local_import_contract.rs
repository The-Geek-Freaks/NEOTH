//! GOLD-CC-RUNTIME-P0 source contracts. Functional tests live with the
//! crate-private runtime because no production session issuer/RPC exists yet.

const RUNTIME: &str = include_str!("../src/connectors/runtime_local_import.rs");
const LOCAL_IMPORT: &str = include_str!("../src/connectors/local_import.rs");
const STORE: &str = include_str!("../src/context_graph/mod.rs");

#[test]
fn runtime_is_private_plan_bound_and_effectively_one_shot() {
    let compact_runtime = RUNTIME
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>();
    assert!(RUNTIME.contains("pub(crate) struct RuntimeLocalImport"));
    assert!(!RUNTIME.contains("pub struct RuntimeLocalImport"));
    assert!(RUNTIME.contains("MAX_RETAINED_PLANS"));
    assert!(RUNTIME.contains("plan_ttl"));
    assert!(compact_runtime.contains("plans.remove(&plan_id)"));
    assert!(RUNTIME.contains("plan_id != confirm_plan_id"));
    assert!(RUNTIME.contains("source changed after planning"));
    assert!(RUNTIME.contains("purge_expired"));
    assert!(
        RUNTIME.contains("LocalImportPlanId(<redacted>)")
            || LOCAL_IMPORT.contains("LocalImportPlanId(<redacted>)")
    );
    assert!(RUNTIME.contains("runtime_binding: ContextImportRuntimeBinding"));
    assert!(!RUNTIME.contains("lease: ContextImportOperationLease"));
    assert!(RUNTIME.contains("acquire_context_import_operation_lease"));
    assert!(RUNTIME.contains("matches_operation_lease(&lease)"));
    assert!(
        RUNTIME
            .contains("LocalImportPolicy::default_bounded(self.runtime_binding.policy_revision())")
    );
    assert!(RUNTIME.contains("self.capability.binding_matches("));
    assert!(LOCAL_IMPORT.contains("runtime_binding: Option<ContextImportCapabilityBinding>"));
    assert!(LOCAL_IMPORT.contains("runtime_binding: Some(runtime_binding)"));
}

#[test]
fn runtime_has_no_public_or_legacy_effect_surface() {
    for forbidden in [
        "pub fn",
        "pub struct",
        "pub async",
        "GroundTruth",
        "ObjectKind::Memory",
        "ObjectKind::Note",
        "Provider",
        "Mcp",
        "obsidian",
        "std::fs::read",
        "tokio::",
        "dispatch",
        "channel",
        "credential",
    ] {
        assert!(
            !RUNTIME.contains(forbidden),
            "runtime must not expose {forbidden}"
        );
    }
    assert!(LOCAL_IMPORT.contains("read_bound_source"));
    assert!(LOCAL_IMPORT.contains("PlatformUnsupported"));
}

#[test]
fn store_bridge_is_exactly_untrusted_connector_evidence_and_outbox_backed() {
    assert!(STORE.contains("pub(crate) fn commit_local_import_evidence"));
    assert!(STORE.contains("ObjectKind::Evidence"));
    assert!(STORE.contains("ProvenanceKind::Connector"));
    assert!(STORE.contains("untrusted_external:local_import"));
    assert!(STORE.contains("AuditReceipt::ContextEvidenceStored"));
    // The operation gate, not a pre-transaction probe, is the final
    // revocation-safe boundary around the SQLite transaction and WAL ACK.
    assert!(STORE.contains("with_context_import_commit_permit"));
    assert!(STORE.contains("commit_batch_with_limits_and_context_evidence_receipt"));
    assert!(STORE.contains("permits_context_evidence_receipt"));
    assert!(STORE.contains("pub(crate) fn reserve_local_import_audit"));
    assert!(STORE.contains("pub(crate) fn acknowledge_local_import_audit"));
    assert!(RUNTIME.contains("ContextEvidenceReceipt::new"));
    assert!(RUNTIME.contains("reserve_local_import_audit"));
    assert!(RUNTIME.contains("acknowledge_local_import_audit"));
    assert!(RUNTIME.contains("append_context_evidence_receipt_once"));
    assert!(STORE.contains("authority_revisions"));
    let reserve = RUNTIME.find("reserve_local_import_audit").unwrap();
    let deliver = RUNTIME.find("adapter.deliver(&entry)").unwrap();
    let acknowledge = RUNTIME.find("acknowledge_local_import_audit").unwrap();
    assert!(reserve < deliver && deliver < acknowledge);
}
