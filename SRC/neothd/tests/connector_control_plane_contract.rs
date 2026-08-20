//! GOLD-CC-01 source contract for the private runtime-control substrate.
//!
//! Functional authority tests remain next to the private implementation. This
//! public-facing gate ensures future wiring cannot make config presence or a
//! caller-supplied subject string into a connector capability.

const CONTROL_PLANE: &str = include_str!("../src/connectors/control_plane.rs");
const CONTROL_STATE: &str = include_str!("../src/connectors/control_state.rs");
const CONNECTORS: &str = include_str!("../src/connectors/mod.rs");
const CONFIG: &str = include_str!("../src/config/mod.rs");

#[test]
fn control_plane_exposes_no_public_capability_mint_or_effect_surface() {
    assert!(!CONTROL_PLANE.contains("pub struct AuthenticatedControlSession"));
    assert!(!CONTROL_PLANE.contains("pub struct AccountAuthority"));
    assert!(!CONTROL_PLANE.contains("pub struct ContextImportCapabilityBinding"));
    assert!(!CONTROL_PLANE.contains("pub struct ContextImportRuntimeBinding"));
    assert!(!CONTROL_PLANE.contains("pub struct ContextImportOperationLease"));
    assert!(!CONTROL_PLANE.contains("AuthenticatedControlSessionIssuer"));
    assert!(!CONTROL_PLANE.contains("pub fn authorize_context_import"));
    assert!(!CONTROL_PLANE.contains("pub fn acquire_context_import_operation_lease"));
    assert!(!CONTROL_PLANE.contains("pub fn acquire_context_import_runtime"));
    assert!(!CONTROL_PLANE.contains("pub fn test_context_import_runtime_fixture"));
    assert!(!CONTROL_PLANE.contains("pub async fn"));
    for forbidden in [
        "use crate::context_graph",
        "pub fn plan_import",
        "pub fn execute",
        "pub fn dispatch_mcp",
    ] {
        assert!(
            !CONTROL_PLANE.contains(forbidden),
            "control plane must not wire {forbidden}"
        );
    }
}

#[test]
fn operation_lease_and_durable_transition_stay_private_and_fail_closed() {
    assert!(CONTROL_PLANE.contains("pub(crate) struct ContextImportOperationLease"));
    assert!(CONTROL_PLANE.contains("pub(crate) struct ContextImportRuntimeBinding"));
    assert!(CONTROL_PLANE.contains("pub(crate) struct ContextImportCapabilityBinding"));
    assert!(!CONTROL_PLANE.contains("impl Clone for ContextImportRuntimeBinding"));
    assert!(!CONTROL_PLANE.contains("impl Clone for ContextImportCapabilityBinding"));
    assert!(!CONTROL_PLANE.contains("impl Clone for ContextImportOperationLease"));
    assert!(
        !CONTROL_PLANE
            .contains("#[derive(Clone, Debug)]\npub(crate) struct ContextImportOperationLease")
    );
    assert!(CONTROL_PLANE.contains("live_leases: usize"));
    assert!(CONTROL_PLANE.contains("fn retire_and_drain"));
    assert!(CONTROL_PLANE.contains("ProjectionFailedClosed"));
    assert!(CONTROL_PLANE.contains("commit_context_connectors_if_matches"));
    assert!(CONTROL_PLANE.contains("fn with_context_import_commit_permit"));
    assert!(CONTROL_PLANE.contains("let result = commit();\n        drop(state);"));
    assert!(CONTROL_PLANE.contains("next_runtime_id: u64"));
    assert!(CONTROL_PLANE.contains("next_operation_id: u64"));
    assert!(CONTROL_PLANE.contains("active_operation_ids: BTreeSet<u64>"));
    assert!(CONTROL_PLANE.contains("active_operation_ids.contains(&self.operation_id)"));
    assert!(CONTROL_PLANE.contains("active_operation_ids.remove(&self.operation_id)"));
    assert!(CONTROL_PLANE.contains("self.runtime_id == lease.runtime_id"));
    assert!(CONTROL_PLANE.contains("fn acquire_context_import_operation_lease("));
    assert!(
        CONTROL_PLANE.contains("fn capability_binding(&self) -> ContextImportCapabilityBinding")
    );
    assert!(CONTROL_PLANE.contains("fn for_evidence(&self) -> Self"));
    assert!(
        CONTROL_PLANE
            .contains("fn matches_runtime_binding(&self, binding: &ContextImportRuntimeBinding)")
    );
    assert!(CONTROL_PLANE.contains("struct GateRestore"));
    assert!(CONTROL_PLANE.contains("restore.gate.reopen(restore.accepting_leases)"));
    assert!(CONTROL_PLANE.contains("emergency_retirement_in_progress: bool"));
    assert!(
        CONTROL_PLANE.contains("#[cfg(test)]\npub(crate) fn test_context_import_runtime_fixture")
    );

    let commit_start = CONTROL_PLANE
        .find("pub(crate) fn commit_durable_update(")
        .expect("connector transition must retain the durable commit method");
    let commit_body = &CONTROL_PLANE[commit_start..];
    let publication = commit_body
        .find("commit_context_connectors_if_matches")
        .expect("transition must publish only a config-bound CAS update");
    let install = commit_body
        .find("install_after_durable_commit")
        .expect("transition must install the projection after publication");
    assert!(publication < install);
}

#[test]
fn durable_control_schema_stays_default_off_and_content_free() {
    assert!(CONTROL_STATE.contains("pub enabled: bool"));
    assert!(CONTROL_STATE.contains("enabled: false"));
    assert!(CONTROL_STATE.contains("pub registered_accounts: Vec<RegisteredConnectorAccount>"));
    assert!(CONTROL_STATE.contains("const MAX_REGISTERED_CONNECTOR_ACCOUNTS: usize = 64"));
    assert!(!CONTROL_STATE.contains("String content"));
    assert!(!CONTROL_STATE.contains("SecretString"));
    assert!(CONFIG.contains(
        "pub context_connectors: crate::connectors::control_state::ConnectorControlConfig"
    ));
    assert!(CONFIG.contains("invalid context_connectors config"));
}

#[test]
fn only_cc01_admission_can_precede_context_import_authority() {
    let start = CONTROL_PLANE
        .find("pub(crate) fn authorize_context_import(")
        .expect("control plane must retain the context-import admission method");
    let body = &CONTROL_PLANE[start..];
    let body = &body[..body
        .find("\n    /// Retire only in-memory authority")
        .expect("authorize_context_import body must end before retirement")];
    let admission = body
        .find("admit_entry_point(")
        .expect("authority issuance must re-run CC-01 admission");
    let authority = body
        .find("Ok(AccountAuthority")
        .expect("control plane must issue only a private authority");
    assert!(admission < authority);
    assert!(CONNECTORS.contains("pub fn admit_entry_point("));
    assert!(CONNECTORS.contains("ConnectorEntryPoint::ContextImport"));
}
