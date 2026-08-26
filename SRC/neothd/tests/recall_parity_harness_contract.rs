//! GOLD-LF-P1-08 regression fence for the offline parity-evaluation harness.
//!
//! The source contracts pin authority and persistence boundaries which score
//! fixtures cannot observe: mutable run artifacts stay capability-relative,
//! while trust in complete imports comes only from an explicitly supplied key.

const HARNESS: &str = include_str!("../src/recall/parity_harness.rs");
const RECEIPT: &str = include_str!("../src/recall/parity_import_receipt.rs");
const CLI: &str = include_str!("../src/cli/recall_score.rs");

#[test]
fn harness_keeps_network_wal_and_gate_authority_outside_the_slice() {
    for forbidden in [
        "reqwest",
        "emit_critical_divergences",
        "audit_rpc",
        "ParityVerdict",
        "pub fn write_verdict",
    ] {
        assert!(
            !HARNESS.contains(forbidden),
            "offline harness must not acquire {forbidden} authority"
        );
    }
    assert!(HARNESS.contains("ValidatedGraderConfigFile"));
    assert!(HARNESS.contains("derived_gate_passed"));
    assert!(HARNESS.contains("cannot replace the existing fail-closed gate"));
}

#[test]
fn bound_run_artifact_io_never_reresolves_ambient_paths() {
    let boundary = HARNESS
        .split("/// Read a caller-selected offline input")
        .next()
        .expect("bound run source prefix");
    for forbidden in ["File::open(", "fs::copy", "fs::remove_file", "fs::rename", ".exists("] {
        assert!(
            !boundary.contains(forbidden),
            "bound run artifact path must not use ambient persistence API {forbidden}"
        );
    }
    for required in [
        "open_bound_directory_from_trusted_anchor",
        "open_or_create_bound_lockfile",
        "read_regular_file_bounded",
        "atomic_write_private_child_create_new",
        "replace_existing_regular_file_if_matches_report",
        "matches_regular_file_child_readonly",
        "open_or_create_imports_locked",
    ] {
        assert!(boundary.contains(required), "bound run lost required capability primitive {required}");
    }
    assert!(HARNESS.contains("state_evidence_sha256"));
}

#[test]
fn receipt_v2_contract_requires_external_complete_signed_evidence() {
    for required in [
        "PARITY_IMPORT_RECEIPT_PURPOSE",
        "ParityImportReceiptBody",
        "purpose: String",
        "signature_b64",
        "verify_b64",
        "strictly sorted by unique grader_id",
        "validate_run_id",
        "validate_sha256",
    ] {
        assert!(RECEIPT.contains(required), "receipt contract lost {required}");
    }
    for required in [
        "getrandom::getrandom",
        "receipt.body.run_id",
        "receipt.body.manifest_sha256",
        "receipt.body.imports != imports",
        "long = \"import-receipt\"",
        "long = \"expected-receipt-pubkey\"",
    ] {
        assert!(HARNESS.contains(required) || CLI.contains(required), "receipt provenance path lost {required}");
    }
}
