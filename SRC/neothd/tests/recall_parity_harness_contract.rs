//! GOLD-LF-P1-08 regression fence for the offline parity-evaluation harness.
//!
//! The source contracts pin authority and persistence boundaries which score
//! fixtures cannot observe: mutable run artifacts stay capability-relative,
//! while trust in complete imports comes only from an explicitly supplied key.

const HARNESS: &str = include_str!("../src/recall/parity_harness.rs");
const ANCHOR: &str = include_str!("../src/recall/parity_anchor.rs");
const CANDIDATE_EVIDENCE: &str = include_str!("../src/recall/parity_candidate_evidence.rs");
const BATCH: &str = include_str!("../src/recall/parity_batch_plan.rs");
const RECEIPT: &str = include_str!("../src/recall/parity_import_receipt.rs");
const CLI: &str = include_str!("../src/cli/recall_score.rs");
const STORE: &str = include_str!("../src/skills/store.rs");

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
    for forbidden in [
        "File::open(",
        "fs::copy",
        "fs::remove_file",
        "fs::rename",
        ".exists(",
    ] {
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
        assert!(
            boundary.contains(required),
            "bound run lost required capability primitive {required}"
        );
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
        assert!(
            RECEIPT.contains(required),
            "receipt contract lost {required}"
        );
    }
    for required in [
        "getrandom::getrandom",
        "receipt.body.run_id",
        "receipt.body.manifest_sha256",
        "receipt.body.imports != imports",
        "long = \"import-receipt\"",
        "long = \"expected-receipt-pubkey\"",
    ] {
        assert!(
            HARNESS.contains(required) || CLI.contains(required),
            "receipt provenance path lost {required}"
        );
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
        assert!(
            ANCHOR.contains(required),
            "operator-anchor contract lost {required}"
        );
    }
}

#[test]
fn candidate_evidence_is_capability_bound_redacted_and_requires_operator_labels() {
    let candidate_production = CANDIDATE_EVIDENCE
        .split("#[cfg(test)]")
        .next()
        .expect("candidate evidence production source");
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
            !candidate_production.contains(forbidden),
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
        "expected_receipt_pubkey_sha256",
        "candidate_bytes",
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

#[test]
fn bound_operator_anchor_ingest_stays_immutable_redacted_and_non_gate() {
    let anchor_ingest = HARNESS
        .split("pub fn ingest_operator_anchor_evidence")
        .nth(1)
        .and_then(|tail| {
            tail.split("/// Import one explicit, offline grade file")
                .next()
        })
        .expect("operator anchor ingest source");
    for forbidden in [
        "File::open(",
        "fs::copy",
        "fs::remove_file",
        "fs::rename",
        "reqwest",
        "wal::writer",
        "build_report(",
    ] {
        assert!(
            !anchor_ingest.contains(forbidden),
            "bound operator anchor ingest must not acquire {forbidden} authority"
        );
    }
    for required in [
        "BoundParityRun::open_or_create",
        "load_operator_anchor_evidence_link_bytes",
        "create_immutable_run_child",
        "operator_labels_complete: true",
        "gate_eligible: false",
        "candidate_receipt_sha256",
        "candidate_receipt_pubkey_sha256",
        "candidate_vector_sha256",
        "canonical_sha256",
        "CANDIDATE_EVIDENCE_RECEIPT_PUBKEY_FILE",
        "receipt.verify(expected_receipt_pubkey_b64)",
    ] {
        assert!(
            anchor_ingest.contains(required),
            "operator anchor ingest lost {required}"
        );
    }
    assert!(HARNESS.contains("validate_operator_anchor_artifacts_if_present"));
    for required in [
        "OperatorAnchorEvidenceLink",
        "OPERATOR_ANCHOR_EVIDENCE_LINK_PURPOSE",
        "candidate_manifest_sha256",
        "candidate_receipt_sha256",
        "operator_anchor_sha256",
        "strictly sorted by unique query_id",
    ] {
        assert!(
            ANCHOR.contains(required),
            "operator-anchor link lost {required}"
        );
    }
    assert!(CLI.contains("AnchorIngest"));
    assert!(CLI.contains("long = \"operator-anchor-link\""));
}

#[test]
fn four_grader_batch_stays_offline_attested_and_non_gate() {
    for forbidden in [
        "File::open(",
        "fs::copy",
        "fs::rename",
        "reqwest",
        "Command::",
        "wal::writer",
        "build_report(",
    ] {
        assert!(
            !BATCH.contains(forbidden),
            "four-grader batch contract must not acquire {forbidden} authority"
        );
    }
    for required in [
        "FOUR_GRADER_COUNT: usize = 4",
        "FOUR_GRADER_BATCH_PLAN_PURPOSE",
        "FOUR_GRADER_BATCH_RESULT_RECEIPT_PURPOSE",
        "run_manifest_sha256",
        "operator_anchor_binding_sha256",
        "candidate_vector_sha256",
        "prompt_sha256",
        "input_sha256",
        "strictly sorted by unique grader_id",
        "verify_b64",
        "gate_eligible: bool",
        "deny_unknown_fields",
    ] {
        assert!(
            BATCH.contains(required),
            "four-grader batch contract lost {required}"
        );
    }
    for required in [
        "plan_four_grader_batch",
        "validate_attested_four_grader_batch_results",
        "validate_four_grader_batch_plan_if_present",
        "FOUR_GRADER_BATCH_PLAN_FILE",
        "immutable four-grader batch plan is not the exact canonical plan bytes",
        "result_receipt_verified: true",
        "gate_eligible: false",
        "existing offline ingest plus signed import",
    ] {
        assert!(
            HARNESS.contains(required),
            "four-grader harness seam lost {required}"
        );
    }
    assert!(CLI.contains("BatchPlan"));
    assert!(CLI.contains("BatchResultsVerify"));
    assert!(CLI.contains("BatchResultsIngest"));
    assert!(CLI.contains("long = \"expected-batch-result-pubkey\""));
    assert!(CLI.contains("num_args = 4"));
}

#[test]
fn attested_batch_result_ingest_is_bound_resumable_and_non_gate() {
    let ingest = HARNESS
        .split("pub fn ingest_attested_four_grader_batch_results")
        .nth(1)
        .and_then(|tail| tail.split("fn validate_batch_result_inputs").next())
        .expect("batch result ingest source");
    for forbidden in [
        "File::open(",
        "reqwest",
        "Command::",
        "wal::writer",
        "build_report(",
    ] {
        assert!(
            !ingest.contains(forbidden),
            "batch result ingest acquired {forbidden} authority"
        );
    }
    for required in [
        "validate_batch_result_inputs",
        "validate_single_grader_matrix",
        "stage_attested_import",
        "BoundParityRun::open_existing",
        "load_existing_run_manifest",
        "FOUR_GRADER_BATCH_RESULT_RECEIPT_FILE",
        "FOUR_GRADER_BATCH_RESULT_PUBKEY_FILE",
        "FOUR_GRADER_BATCH_RESULT_BINDING_FILE",
        "result_receipt_pubkey_sha256",
        "state_evidence_sha256",
        "gate_eligible: false",
    ] {
        assert!(
            ingest.contains(required),
            "batch result ingest lost {required}"
        );
    }
    for required in [
        "incomplete four-grader batch result ingest",
        "receipt.verify(pubkey)",
        "validate_state_imports",
        "revalidate(run, FOUR_GRADER_BATCH_RESULT_BINDING_FILE)",
        "read_pinned_attested_imports",
        "state_bytes.revalidate(run, STATE_FILE)",
        "pinned_imports.revalidate(run)",
        "directory_identity.matches_child",
        "attested imports directory identity changed",
    ] {
        assert!(
            HARNESS.contains(required),
            "batch result reopen fence lost {required}"
        );
    }
    for required in [
        "pub(crate) fn open_bound_real_child_dir",
        "let child = open_real_child_dir(parent, name, display_path)?",
        "child.dir_metadata()",
        "let binding = bind_child_object(parent, name, display_path)?",
        "opened_identity == binding.identity_token()",
        "binding.matches_child(parent, name, display_path)?",
    ] {
        assert!(
            STORE.contains(required),
            "bound child-directory helper lost {required}"
        );
    }
    assert!(
        HARNESS.contains("open_bound_real_child_dir("),
        "attested imports must bind their retained directory capability through the shared helper"
    );
}

#[test]
fn attested_family_bias_export_is_read_only_pinned_and_non_gate() {
    let summary = HARNESS
        .split("pub fn summarize_attested_four_grader_family_bias")
        .nth(1)
        .and_then(|tail| {
            tail.split("fn cluster_attested_four_grader_family_bias")
                .next()
        })
        .expect("attested family-bias summary source");
    for forbidden in [
        "open_or_create",
        "create_child(",
        "replace_child",
        "File::open(",
        "reqwest",
        "Command::",
        "wal::writer",
        "build_report(",
    ] {
        assert!(
            !summary.contains(forbidden),
            "attested family-bias summary acquired mutable/ambient authority {forbidden}"
        );
    }
    for required in [
        "BoundParityRun::open_existing",
        "load_existing_run_manifest",
        "validate_operator_anchor_artifacts_if_present",
        "load_validated_operator_anchor_artifacts_if_present",
        "validate_four_grader_batch_result_artifacts_if_present",
        "OPERATOR_ANCHOR_QUERY_COUNT",
        "anchor_group.revalidate",
        "results.revalidate",
        "run.revalidate_lock",
        "gate_eligible: false",
        "ATTESTED_FAMILY_BIAS_EXPORT_PURPOSE",
        "result_binding_sha256",
        "canonical_bytes",
    ] {
        assert!(
            summary.contains(required) || HARNESS.contains(required),
            "family-bias summary lost {required}"
        );
    }
    for required in [
        "struct ValidatedOperatorAnchorEvidenceGroup",
        "candidate_manifest",
        "candidate_receipt",
        "candidate_receipt_pubkey",
        "candidate_vector",
        "anchor_link",
        "binding_artifact",
        "group.revalidate(run)?",
    ] {
        assert!(
            HARNESS.contains(required),
            "anchor provenance retain/revalidate fence lost {required}"
        );
    }
    let clustering = HARNESS
        .split("fn cluster_attested_four_grader_family_bias")
        .nth(1)
        .and_then(|tail| tail.split("fn attested_family_name").next())
        .expect("family-bias clustering source");
    for required in [
        "exact 20-query by four-grader coverage",
        "duplicate validated roster identity",
        "batch plan family does not match the validated roster",
        "duplicate persisted grade observation",
        "incomplete anchor coverage",
        "bounded_mean",
        "same_direction",
        "IndependentExternalFamilyEvidence",
        "SameFamilyCorrelation",
    ] {
        assert!(
            clustering.contains(required),
            "family-bias adversarial/determinism fence lost {required}"
        );
    }
    assert!(CLI.contains("BatchFamilyBias"));
    assert!(CLI.contains("summary.export()?"));
}

#[test]
fn attested_gate_report_is_the_only_full_evidence_publish_transition() {
    let gate = HARNESS
        .split("pub fn build_attested_parity_gate_report")
        .nth(1)
        .and_then(|tail| tail.split("fn attested_family_bias_policy_passes").next())
        .expect("attested gate-report source");
    for forbidden in [
        "BoundParityRun::open_or_create",
        "File::open(",
        "reqwest",
        "Command::",
        "wal::writer",
        "build_report(",
    ] {
        assert!(
            !gate.contains(forbidden),
            "attested gate report acquired ambient authority {forbidden}"
        );
    }
    for required in [
        "BoundParityRun::open_existing",
        "load_existing_run_manifest",
        "load_validated_operator_anchor_artifacts_if_present",
        "load_validated_four_grader_batch_result_artifacts_if_present",
        "parse_signed_parity_import_receipt",
        "verify_external_import_receipt",
        "compute_parity_run",
        "independent_external_family_gate_met",
        "attested_family_bias_policy_passes",
        "parity.verdict.passed",
        "publish_attested_gate_report",
        "validate_attested_gate_publication_if_present",
        "anchor_group.revalidate",
        "reopened.revalidate",
        "gate_eligible",
    ] {
        assert!(
            gate.contains(required),
            "attested gate transition lost {required}"
        );
    }
    for required in [
        "ATTESTED_GATE_REPORT_FILE",
        "ATTESTED_GATE_IMPORT_RECEIPT_FILE",
        "ATTESTED_GATE_IMPORT_PUBKEY_FILE",
        "ATTESTED_GATE_PUBLICATION_RECEIPT_FILE",
        "replace_child_if_matches",
        "refuses a stale state report binding",
        "incomplete attested gate report publication",
        "results.state.report_sha256",
        "AttestedParityGatePublicationReceipt",
        "reject_legacy_report_mutation_after_attested_gate",
        "legacy report cannot mutate a run with attested gate publication evidence",
    ] {
        assert!(
            HARNESS.contains(required),
            "attested gate crash-safe receipt/state fence lost {required}"
        );
    }
    assert!(CLI.contains("AttestedGateReport"));
    assert!(CLI.contains("long = \"import-receipt\""));
    assert!(CLI.contains("long = \"expected-receipt-pubkey\""));
    let publish = HARNESS
        .split("fn publish_attested_gate_report")
        .nth(1)
        .and_then(|tail| {
            tail.split("fn reject_legacy_report_mutation_after_attested_gate")
                .next()
        })
        .expect("attested gate publish source");
    let state_publish = publish
        .split("None => {")
        .nth(1)
        .and_then(|tail| tail.split("run.replace_child_if_matches").next())
        .expect("attested gate state publish fence");
    assert!(
        state_publish
            .contains("anchor_group.revalidate(run)?;\n            results.revalidate(run)?;")
    );
    assert!(gate.matches("anchor_group.revalidate(&run)?;").count() >= 2);
}
