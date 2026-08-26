//! GOLD-LF-P1-08 regression fence for the offline parity-evaluation harness.
//!
//! The source contracts pin authority and persistence boundaries which score
//! fixtures cannot observe: mutable run artifacts stay capability-relative,
//! while trust in complete imports comes only from an explicitly supplied key.

const HARNESS: &str = include_str!("../src/recall/parity_harness.rs");
const ANCHOR: &str = include_str!("../src/recall/parity_anchor.rs");
const CANDIDATE_EVIDENCE: &str = include_str!("../src/recall/parity_candidate_evidence.rs");
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

#[test]
fn operator_anchor_is_bounded_offline_and_never_claims_to_change_the_gate() {
    for forbidden in ["reqwest", "Command::", "wal::", "build_report("] {
        assert!(
            !ANCHOR.contains(forbidden),
            "operator anchor must remain an offline analysis boundary: {forbidden}"
        );
    }
    for required in [
        "OPERATOR_ANCHOR_GRADER_ID",
        "OPERATOR_ANCHOR_QUERY_COUNT",
        "load_operator_anchor_bytes",
        "assess_shared_family_bias",
        "recommended_unanchored_correction",
        "compute_parity_run",
        "canonical_goldset_sha256",
        "canonical_roster_sha256",
    ] {
        assert!(ANCHOR.contains(required), "operator-anchor contract lost {required}");
    }
}

#[test]
fn candidate_evidence_is_capability_bound_redacted_and_requires_operator_labels() {
    for forbidden in [
        "File::open(",
        "fs::copy",
        "fs::remove_file",
        "fs::rename",
        "reqwest",
        "wal::writer",
        "build_report(",
        "GoldsetEntry",
    ] {
        assert!(
            !CANDIDATE_EVIDENCE.contains(forbidden),
            "candidate evidence must not acquire ambient/raw/gate authority: {forbidden}"
        );
    }
    for required in [
        "open_bound_directory_from_trusted_anchor",
        "read_regular_file_bounded",
        "CANDIDATE_EVIDENCE_PURPOSE",
        "source_span_sha256",
        "SignedCandidateEvidenceReceipt",
        "CANDIDATE_EVIDENCE_RECEIPT_PURPOSE",
        "pub fn canonical_bytes",
        "verify_b64",
        "operator_labeling_required: true",
        "gate_eligible: false",
        "deny_unknown_fields",
    ] {
        assert!(
            CANDIDATE_EVIDENCE.contains(required),
            "candidate evidence lost safety/provenance contract {required}"
        );
    }
    assert!(CLI.contains("CandidateEvidenceValidate"));
    assert!(CLI.contains("long = \"evidence-dir\""));
    assert!(CLI.contains("long = \"expected-evidence-receipt-pubkey\""));
}
