//! GOLD-CC-02 public-surface contract. Functional contract tests remain
//! in `context_graph::tests` because the module-private capability issuer is
//! deliberately unavailable to connector-facing code until real authenticated
//! session wiring exists.

#[test]
fn context_store_never_exposes_a_public_account_context_constructor_or_erase_api() {
    let source = include_str!("../src/context_graph/mod.rs");
    assert!(source.contains("fn from_authenticated_identity"));
    assert!(!source.contains("pub fn from_authenticated_identity"));
    assert!(!source.contains("pub(crate) fn from_authenticated_identity"));
    assert!(!source.contains("pub fn erase_account"));
    assert!(!source.contains("EraseAccount"));
}

#[test]
fn context_store_contract_includes_batch_and_mutation_idempotency_boundaries() {
    let source = include_str!("../src/context_graph/mod.rs");
    assert!(source.contains("CREATE TABLE applied_batches"));
    assert!(source.contains("CREATE TABLE applied_mutations"));
    assert!(source.contains("INSERT INTO applied_batches"));
    assert!(source.contains("INSERT INTO applied_mutations"));
    assert!(source.contains("if newly_claimed.is_empty()"));
    assert!(source.contains("MAX_APPLIED_BATCHES_PER_SCOPE"));
}

#[test]
fn context_store_persists_only_scope_bound_pseudonyms() {
    let source = include_str!("../src/context_graph/mod.rs");
    for table in [
        "objects",
        "revisions",
        "tombstones",
        "provenance",
        "events",
        "cursors",
        "audit_outbox",
        "applied_batches",
        "applied_mutations",
    ] {
        assert!(
            source.contains(&format!("CREATE TABLE {table} (")),
            "{table} must be present in the scope schema"
        );
    }
    assert!(source.contains("scope_key BLOB NOT NULL"));
    assert!(!source.contains("account_id"));
    assert!(!source.contains("CREATE TABLE accounts"));
}

#[test]
fn context_store_contract_enforces_typed_content_free_receipts_and_preflight_limits() {
    let source = include_str!("../src/context_graph/mod.rs");
    assert!(source.contains("pub enum AuditReceipt"));
    assert!(!source.contains("audit_metadata: String"));
    assert!(source.contains("mutation_key: [u8; 32]"));
    assert!(source.contains("MAX_PENDING_AUDIT_ENTRIES"));
    assert!(source.contains("MAX_SCOPE_BYTES"));
    assert!(source.contains("MAX_EVENTS_PER_SCOPE"));
    assert!(source.contains("context batch contains a duplicate source mutation key"));
    assert!(source.contains("context batch contains multiple updates for one cursor"));

    let preflight = source.find("let preflight = self.preflight").unwrap();
    let write_lock = source
        .find("transaction_with_behavior(TransactionBehavior::Immediate)")
        .unwrap();
    assert!(
        preflight < write_lock,
        "validation and capacity preflight must precede BEGIN IMMEDIATE"
    );
}

#[test]
fn context_store_contract_fails_closed_for_unsafe_paths_and_windows() {
    let source = include_str!("../src/context_graph/mod.rs");
    assert!(source.contains("SQLITE_OPEN_NOFOLLOW"));
    assert!(source.contains("reject_database_sidecars(&path)?"));
    assert!(source.contains("context store parent must already exist and be private"));
    assert!(source.contains("disabled on Windows pending strict DACL and reparse-point hardening"));
}
