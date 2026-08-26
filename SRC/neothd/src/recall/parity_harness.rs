//! GOLD-LF-P1-08 — offline, resumable recall-parity evaluation harness.
//!
//! This module deliberately has no provider, network, daemon, or WAL authority.
//! It binds one explicitly supplied, already-validated grader roster and one
//! canonical goldset to SHA256 digests, accepts only bounded offline grade files,
//! clusters grader-family bias deterministically, and writes a derived report.
//! The report is *not* a cutover verdict and cannot replace the existing
//! fail-closed [`super::parity_run`] verdict path.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{
    goldset::{
        GoldsetEntry, GradedSystem, GraderGrade, ValidatedGraderConfigFile,
        EXPECTED_GOLDSET_QUERIES, MAX_GRADES_BYTES, MAX_GRADERS,
    },
    parity::Dimension,
    parity_anchor::{
        ValidatedOperatorAnchorEvidenceLink, load_operator_anchor_bytes,
        load_operator_anchor_evidence_link_bytes,
        load_operator_anchor_evidence_link_with_provenance,
    },
    parity_candidate_evidence::{
        ValidatedCandidateEvidence, validate_persisted_candidate_evidence_metadata,
    },
    parity_import_receipt::{SignedParityImportReceipt, validate_run_id},
    parity_run::compute_parity_run,
};

/// Persisted schema version for the P1-08 harness files.
pub const PARITY_HARNESS_SCHEMA_VERSION: u32 = 2;
/// A run owns at most one imported source per configured grader.
pub const MAX_HARNESS_GRADE_FILES: usize = MAX_GRADERS;
const MANIFEST_FILE: &str = "manifest.json";
const STATE_FILE: &str = "state.json";
const REPORT_FILE: &str = "report.json";
const IMPORTS_DIR: &str = "imports";
const OPERATOR_ANCHOR_FILE: &str = "operator-anchor.jsonl";
const OPERATOR_ANCHOR_LINK_FILE: &str = "operator-anchor-link.json";
const OPERATOR_ANCHOR_BINDING_FILE: &str = "operator-anchor-binding.json";
const CANDIDATE_EVIDENCE_MANIFEST_FILE: &str = "candidate-evidence-manifest.json";
const CANDIDATE_EVIDENCE_RECEIPT_FILE: &str = "candidate-evidence-receipt.json";
const CANDIDATE_EVIDENCE_RECEIPT_PUBKEY_FILE: &str = "candidate-evidence-receipt-pubkey.txt";
const CANDIDATE_EVIDENCE_CANDIDATES_FILE: &str = "candidate-evidence-candidates.jsonl";
const LOCK_FILE: &str = ".parity-harness.lock";

/// Capability-bound run namespace. Its root directory and advisory lock are
/// opened exactly once; every persistent child operation must be relative to
/// this retained directory handle rather than re-resolving `run_dir`.
struct BoundParityRun {
    root: crate::skills::store::BoundDirectory,
    lock: std::fs::File,
    lock_identity: crate::skills::store::BoundChildObject,
}

impl BoundParityRun {
    fn open_or_create(run_dir: &Path) -> Result<Self> {
        let anchor = run_dir.parent().context("parity run directory has no trusted parent")?;
        let root = crate::skills::store::open_bound_directory_from_trusted_anchor(
            anchor, run_dir, true, "parity run",
        )?.context("parity run directory was not created")?;
        let lock_display = root.display_path.join(LOCK_FILE);
        let (lock, lock_identity) = crate::skills::store::open_or_create_bound_lockfile(
            &root.dir, std::ffi::OsStr::new(LOCK_FILE), &lock_display,
        )?;
        lock.try_lock().context("parity run is already being modified")?;
        Ok(Self { root, lock, lock_identity })
    }

    fn revalidate_lock(&self) -> Result<()> {
        if !self.lock_identity.matches_regular_file_child_readonly(
            &self.root.dir, std::ffi::OsStr::new(LOCK_FILE), &self.root.display_path.join(LOCK_FILE),
        )? {
            anyhow::bail!("parity run lock identity changed before publication");
        }
        Ok(())
    }

    fn child_display(&self, name: &str) -> PathBuf { self.root.display_path.join(name) }

    fn read_child(&self, name: &str, max: usize) -> Result<Vec<u8>> {
        crate::skills::store::read_regular_file_bounded(
            &self.root.dir, std::ffi::OsStr::new(name), &self.child_display(name), max,
        )
    }

    fn read_child_if_present(&self, name: &str, max: usize) -> Result<Option<Vec<u8>>> {
        match self.root.dir.symlink_metadata(std::ffi::OsStr::new(name)) {
            Ok(metadata) => {
                if !metadata.is_file() { anyhow::bail!("parity run child is not a regular file: {}", self.child_display(name).display()); }
                self.read_child(name, max).map(Some)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).with_context(|| format!("inspect parity run child {}", self.child_display(name).display())),
        }
    }

    fn create_child(&self, name: &str, bytes: &[u8]) -> Result<()> {
        self.revalidate_lock()?;
        crate::skills::store::atomic_write_private_child_create_new(
            &self.root.dir, std::ffi::OsStr::new(name), &self.child_display(name), bytes,
        )?;
        self.revalidate_lock()
    }

    fn replace_child_if_matches(&self, name: &str, expected_old: &[u8], bytes: &[u8]) -> Result<()> {
        self.revalidate_lock()?;
        crate::skills::store::replace_existing_regular_file_if_matches_report(
            &self.root.dir, std::ffi::OsStr::new(name), &self.child_display(name), expected_old, bytes,
        )?;
        self.revalidate_lock()
    }

    fn open_imports(&self) -> Result<cap_std::fs::Dir> {
        crate::skills::store::open_real_child_dir(
            &self.root.dir, std::ffi::OsStr::new(IMPORTS_DIR), &self.child_display(IMPORTS_DIR),
        )
    }

    fn open_or_create_imports_locked(&self) -> Result<cap_std::fs::Dir> {
        self.revalidate_lock()?;
        let imports = crate::skills::store::open_or_create_private_child_dir(
            &self.root.dir, std::ffi::OsStr::new(IMPORTS_DIR), &self.child_display(IMPORTS_DIR),
        )?;
        self.revalidate_lock()?;
        Ok(imports)
    }
}

impl Drop for BoundParityRun {
    fn drop(&mut self) { let _ = self.lock.unlock(); }
}

/// Read a caller-selected offline input once, with an explicit byte cap. The
/// harness callers parse and fingerprint this returned payload; they never
/// reopen the input path after provenance has been recorded.
pub fn read_offline_input(path: &Path, max_bytes: u64, label: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut reader = File::open(path)
        .with_context(|| format!("open explicit offline {label} {}", path.display()))?
        .take(max_bytes.saturating_add(1));
    reader.read_to_end(&mut bytes)
        .with_context(|| format!("read explicit offline {label} {}", path.display()))?;
    if bytes.len() as u64 > max_bytes { anyhow::bail!("explicit offline {label} exceeds byte limit"); }
    Ok(bytes)
}

/// Plan provenance bound to the exact input bytes, never ambient configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParityRunManifest {
    pub schema_version: u32,
    /// CSPRNG-minted opaque run identity. v1 manifests are deliberately not
    /// upgraded because they cannot be retroactively receipt-authenticated.
    pub run_id: String,
    pub config_sha256: String,
    pub goldset_sha256: String,
    pub graders: Vec<ManifestGrader>,
}

/// Canonical roster projection used only to make plan provenance inspectable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestGrader {
    pub grader_id: String,
    pub provider: String,
    pub model_id: String,
    pub family: String,
}

/// Persisted state for a manifest. It records opaque byte hashes, not verdicts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParityRunState {
    pub schema_version: u32,
    pub manifest_sha256: String,
    pub imported_grades: Vec<ImportedGradeFile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_sha256: Option<String>,
}

/// Exact imported offline-grade artifact. Its filename is derived from SHA256.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportedGradeFile {
    pub grader_id: String,
    pub source_sha256: String,
    pub record_count: usize,
}

/// Immutable, redacted run-local binding for a complete operator-label anchor.
/// It records hashes and counts only: neither raw candidate source data nor
/// label/grading payloads are rendered by this summary or used as a gate input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorAnchorRunBinding {
    pub schema_version: u32,
    pub run_manifest_sha256: String,
    pub operator_anchor_sha256: String,
    pub operator_anchor_link_sha256: String,
    pub candidate_manifest_sha256: String,
    pub candidate_receipt_sha256: String,
    pub candidate_receipt_pubkey_sha256: String,
    pub candidate_vector_sha256: String,
    pub label_record_count: usize,
    pub linked_candidate_count: usize,
    pub operator_labels_complete: bool,
    pub gate_eligible: bool,
}

/// Canonical state provenance. Publication bookkeeping stays in
/// `ParityRunState::report_sha256` and is deliberately excluded so an auditor
/// can recompute this digest from every persisted state generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ParityRunStateEvidence<'a> {
    schema_version: u32,
    manifest_sha256: &'a str,
    imported_grades: &'a [ImportedGradeFile],
}

/// Deterministic, non-authoritative report. `derived_gate_passed` is reporting
/// data only; it does not write or alter the established fail-closed gate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParityHarnessReport {
    pub schema_version: u32,
    pub manifest_sha256: String,
    pub state_evidence_sha256: String,
    pub imported_grade_sha256: Vec<ImportedGradeFile>,
    pub derived_gate_passed: bool,
    pub aggregate: f64,
    pub mean_kappa: f64,
    pub critical_count: usize,
    pub family_bias_clusters: Vec<FamilyBiasCluster>,
}

/// One validated-family's bounded bias summary versus all graders' mean.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FamilyBiasCluster {
    pub family: String,
    pub grader_count: usize,
    pub dimensions: Vec<FamilyBiasDimension>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FamilyBiasDimension {
    pub system: String,
    pub dimension: String,
    pub observation_count: usize,
    pub family_mean: f64,
    pub all_grader_mean: f64,
    pub signed_bias: f64,
}

/// Create an immutable plan, or return the identical existing plan unchanged.
pub fn plan_run(
    run_dir: &Path,
    grader_config: &ValidatedGraderConfigFile,
    config_bytes: &[u8],
    goldset: &[GoldsetEntry],
    goldset_bytes: &[u8],
) -> Result<ParityRunManifest> {
    let run = BoundParityRun::open_or_create(run_dir)?;
    let manifest = plan_run_locked(&run, grader_config, config_bytes, goldset, goldset_bytes)?;
    validate_operator_anchor_artifacts_if_present(&run, &manifest, grader_config, goldset)?;
    Ok(manifest)
}

fn plan_run_locked(
    run: &BoundParityRun,
    grader_config: &ValidatedGraderConfigFile,
    config_bytes: &[u8],
    goldset: &[GoldsetEntry],
    goldset_bytes: &[u8],
) -> Result<ParityRunManifest> {
    verify_bound_inputs(grader_config, config_bytes, goldset, goldset_bytes)?;
    if goldset.len() != EXPECTED_GOLDSET_QUERIES {
        anyhow::bail!("harness refuses a non-canonical goldset");
    }
    if let Some(bytes) = run.read_child_if_present(MANIFEST_FILE, 1024 * 1024)? {
        let stored: ParityRunManifest = serde_json::from_slice(&bytes).context("parse bound parity manifest")?;
        validate_manifest(&stored)?;
        if !manifest_matches_inputs(&stored, grader_config, config_bytes, goldset_bytes) {
            anyhow::bail!(
                "run directory already binds different config/goldset/roster bytes; create a new run directory"
            );
        }
        let state = if run.read_child_if_present(STATE_FILE, 1024 * 1024)?.is_none() {
            // The only valid creation-window recovery: a manifest was synced
            // but initial state publication never began. No state generation,
            // report, or import may exist. Otherwise we must fail closed rather
            // than reconstruct an empty state over an interrupted ingest.
            if run.read_child_if_present(REPORT_FILE, 1024 * 1024)?.is_some()
                || crate::skills::store::open_real_child_dir_if_present(
                    &run.root.dir,
                    std::ffi::OsStr::new(IMPORTS_DIR),
                    &run.child_display(IMPORTS_DIR),
                )?.is_some()
            {
                anyhow::bail!("manifest without state has later run artifacts; replan in a fresh run directory");
            }
            let state = empty_state_for_manifest(&stored)?;
            run.create_child(STATE_FILE, &serde_json::to_vec(&state)?)?;
            state
        } else {
            load_state_for_manifest(run, &stored)?
        };
        validate_state_imports(run, &state, grader_config, goldset)?;
        return Ok(stored);
    }

    let manifest = manifest_for(grader_config, config_bytes, goldset_bytes)?;
    validate_manifest(&manifest)?;
    run.create_child(MANIFEST_FILE, &serde_json::to_vec(&manifest)?)?;
    let state = empty_state_for_manifest(&manifest)?;
    run.create_child(STATE_FILE, &serde_json::to_vec(&state)?)?;
    Ok(manifest)
}

fn empty_state_for_manifest(manifest: &ParityRunManifest) -> Result<ParityRunState> {
    Ok(ParityRunState {
        schema_version: PARITY_HARNESS_SCHEMA_VERSION,
        manifest_sha256: sha256_json(manifest)?,
        imported_grades: Vec::new(),
        report_sha256: None,
    })
}

/// Persist a complete 20×2 operator-label anchor and its verified candidate
/// evidence link as immutable, capability-relative run artifacts. This is an
/// idempotent review-provenance step only: it does not add grades, change state,
/// create a report, or make the existing parity gate eligible to pass.
pub fn ingest_operator_anchor_evidence(
    run_dir: &Path,
    grader_config: &ValidatedGraderConfigFile,
    config_bytes: &[u8],
    goldset: &[GoldsetEntry],
    goldset_bytes: &[u8],
    candidate_evidence: &ValidatedCandidateEvidence,
    operator_anchor_bytes: &[u8],
    operator_anchor_link_bytes: &[u8],
) -> Result<OperatorAnchorRunBinding> {
    let run = BoundParityRun::open_or_create(run_dir)?;
    let manifest = plan_run_locked(&run, grader_config, config_bytes, goldset, goldset_bytes)?;
    let anchor = load_operator_anchor_bytes(
        operator_anchor_bytes,
        "bound operator anchor import",
        goldset,
        grader_config,
    )?;
    let link = load_operator_anchor_evidence_link_bytes(
        operator_anchor_link_bytes,
        operator_anchor_bytes,
        &anchor,
        candidate_evidence,
    )?;
    let binding = operator_anchor_binding(
        &manifest,
        candidate_evidence,
        operator_anchor_bytes,
        operator_anchor_link_bytes,
        &link,
        anchor.grades().len(),
    )?;

    create_immutable_run_child(
        &run,
        CANDIDATE_EVIDENCE_MANIFEST_FILE,
        candidate_evidence.manifest_bytes(),
        1024 * 1024,
    )?;
    create_immutable_run_child(
        &run,
        CANDIDATE_EVIDENCE_CANDIDATES_FILE,
        candidate_evidence.candidate_bytes(),
        1024 * 1024,
    )?;
    create_immutable_run_child(
        &run,
        CANDIDATE_EVIDENCE_RECEIPT_FILE,
        candidate_evidence.receipt_bytes(),
        64 * 1024,
    )?;
    create_immutable_run_child(
        &run,
        CANDIDATE_EVIDENCE_RECEIPT_PUBKEY_FILE,
        candidate_evidence.expected_receipt_pubkey_b64().as_bytes(),
        128,
    )?;
    create_immutable_run_child(&run, OPERATOR_ANCHOR_FILE, operator_anchor_bytes, MAX_GRADES_BYTES as usize)?;
    create_immutable_run_child(
        &run,
        OPERATOR_ANCHOR_LINK_FILE,
        operator_anchor_link_bytes,
        64 * 1024,
    )?;
    create_immutable_run_child(
        &run,
        OPERATOR_ANCHOR_BINDING_FILE,
        &serde_json::to_vec(&binding).context("serialize operator anchor run binding")?,
        64 * 1024,
    )?;
    validate_operator_anchor_artifacts_if_present(&run, &manifest, grader_config, goldset)?;
    Ok(binding)
}

fn operator_anchor_binding(
    manifest: &ParityRunManifest,
    candidate_evidence: &ValidatedCandidateEvidence,
    operator_anchor_bytes: &[u8],
    operator_anchor_link_bytes: &[u8],
    link: &ValidatedOperatorAnchorEvidenceLink,
    label_record_count: usize,
) -> Result<OperatorAnchorRunBinding> {
    let linked_candidate_count = link.link().links.len();
    if label_record_count != 40 || linked_candidate_count != 20 {
        anyhow::bail!("operator anchor binding requires complete 20-query × two-system labels");
    }
    Ok(OperatorAnchorRunBinding {
        schema_version: PARITY_HARNESS_SCHEMA_VERSION,
        run_manifest_sha256: sha256_json(manifest)?,
        operator_anchor_sha256: sha256_bytes(operator_anchor_bytes),
        operator_anchor_link_sha256: sha256_bytes(operator_anchor_link_bytes),
        candidate_manifest_sha256: candidate_evidence.manifest_sha256().to_owned(),
        candidate_receipt_sha256: candidate_evidence.receipt_sha256().to_owned(),
        candidate_receipt_pubkey_sha256: candidate_evidence.expected_receipt_pubkey_sha256().to_owned(),
        candidate_vector_sha256: sha256_bytes(candidate_evidence.candidate_bytes()),
        label_record_count,
        linked_candidate_count,
        operator_labels_complete: true,
        // This run-local review binding has no authority to change the existing
        // fail-closed scoring gate. A future correction/report slice must prove
        // its own complete provenance and retain that gate separately.
        gate_eligible: false,
    })
}

fn create_immutable_run_child(
    run: &BoundParityRun,
    name: &str,
    bytes: &[u8],
    max_bytes: usize,
) -> Result<()> {
    if bytes.len() > max_bytes {
        anyhow::bail!("operator anchor artifact exceeds its bounded run contract");
    }
    match read_bound_immutable_run_child(run, name, max_bytes)? {
        Some(existing) if existing.bytes == bytes => Ok(()),
        Some(_) => anyhow::bail!("run already contains a different immutable operator anchor artifact"),
        None => {
            run.create_child(name, bytes)?;
            if read_bound_immutable_run_child(run, name, max_bytes)?
                .as_ref()
                .map(|artifact| artifact.bytes.as_slice()) != Some(bytes)
            {
                anyhow::bail!("new immutable operator anchor artifact failed exact byte verification");
            }
            Ok(())
        }
    }
}

struct BoundImmutableRunChild {
    bytes: Vec<u8>,
    identity: crate::skills::store::BoundChildObject,
}

impl BoundImmutableRunChild {
    fn revalidate(&self, run: &BoundParityRun, name: &str) -> Result<()> {
        if !self.identity.matches_regular_file_child_readonly(
            &run.root.dir,
            std::ffi::OsStr::new(name),
            &run.child_display(name),
        )? {
            anyhow::bail!("immutable run artifact identity changed before aggregate return");
        }
        Ok(())
    }
}

fn read_bound_immutable_run_child(
    run: &BoundParityRun,
    name: &str,
    max_bytes: usize,
) -> Result<Option<BoundImmutableRunChild>> {
    match run.root.dir.symlink_metadata(std::ffi::OsStr::new(name)) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("inspect immutable run artifact {}", run.child_display(name).display())),
    }
    run.revalidate_lock()?;
    let (mut file, binding) = crate::skills::store::open_bound_regular_file(
        &run.root.dir,
        std::ffi::OsStr::new(name),
        &run.child_display(name),
    )?;
    let mut bytes = Vec::new();
    file.take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("read immutable run artifact {}", run.child_display(name).display()))?;
    if bytes.len() > max_bytes {
        anyhow::bail!("immutable run artifact exceeds its bounded contract");
    }
    if !binding.matches_regular_file_child_readonly(
        &run.root.dir,
        std::ffi::OsStr::new(name),
        &run.child_display(name),
    )? {
        anyhow::bail!("immutable run artifact identity changed before return");
    }
    run.revalidate_lock()?;
    Ok(Some(BoundImmutableRunChild { bytes, identity: binding }))
}

fn validate_operator_anchor_artifacts_if_present(
    run: &BoundParityRun,
    manifest: &ParityRunManifest,
    grader_config: &ValidatedGraderConfigFile,
    goldset: &[GoldsetEntry],
) -> Result<()> {
    let artifact_contracts = [
        (CANDIDATE_EVIDENCE_MANIFEST_FILE, 1024 * 1024),
        (CANDIDATE_EVIDENCE_RECEIPT_FILE, 64 * 1024),
        (CANDIDATE_EVIDENCE_RECEIPT_PUBKEY_FILE, 128),
        (CANDIDATE_EVIDENCE_CANDIDATES_FILE, 1024 * 1024),
        (OPERATOR_ANCHOR_FILE, MAX_GRADES_BYTES as usize),
        (OPERATOR_ANCHOR_LINK_FILE, 64 * 1024),
        (OPERATOR_ANCHOR_BINDING_FILE, 64 * 1024),
    ];
    let present = artifact_contracts
        .iter()
        .map(|(name, max_bytes)| read_bound_immutable_run_child(run, name, *max_bytes))
        .collect::<Result<Vec<_>>>()?;
    if present.iter().all(Option::is_none) {
        return Ok(());
    }
    if present.iter().any(Option::is_none) {
        anyhow::bail!("incomplete operator anchor ingest; retry anchor-ingest with identical artifacts or use a fresh run");
    }
    let mut values = present.into_iter().map(Option::unwrap);
    let candidate_manifest = values.next().expect("fixed anchor artifact count");
    let candidate_receipt = values.next().expect("fixed anchor artifact count");
    let candidate_receipt_pubkey = values.next().expect("fixed anchor artifact count");
    let candidate_vector = values.next().expect("fixed anchor artifact count");
    let anchor_bytes = values.next().expect("fixed anchor artifact count");
    let link_bytes = values.next().expect("fixed anchor artifact count");
    let binding_bytes = values.next().expect("fixed anchor artifact count");
    let binding: OperatorAnchorRunBinding = serde_json::from_slice(&binding_bytes.bytes)
        .map_err(|_| anyhow::anyhow!("parse immutable operator anchor run binding"))?;
    validate_operator_anchor_binding(&binding, manifest)?;
    let candidate_metadata = validate_persisted_candidate_evidence_metadata(
        &candidate_manifest.bytes,
        &candidate_receipt.bytes,
        &candidate_vector.bytes,
        std::str::from_utf8(&candidate_receipt_pubkey.bytes)
            .map_err(|_| anyhow::anyhow!("persisted candidate receipt public key is not UTF-8"))?,
        &binding.candidate_manifest_sha256,
        &binding.candidate_receipt_sha256,
        &binding.candidate_receipt_pubkey_sha256,
    )?;
    if sha256_bytes(&candidate_vector.bytes) != binding.candidate_vector_sha256 {
        anyhow::bail!("operator anchor binding candidate vector SHA256 mismatch");
    }
    let anchor = load_operator_anchor_bytes(
        &anchor_bytes.bytes,
        "persisted operator anchor",
        goldset,
        grader_config,
    )?;
    let link = load_operator_anchor_evidence_link_with_provenance(
        &link_bytes.bytes,
        &anchor_bytes.bytes,
        &anchor,
        &binding.candidate_manifest_sha256,
        &binding.candidate_receipt_sha256,
        candidate_metadata.candidate_ids(),
    )?;
    if sha256_bytes(&anchor_bytes.bytes) != binding.operator_anchor_sha256
        || sha256_bytes(&link_bytes.bytes) != binding.operator_anchor_link_sha256
        || link.link().links.len() != binding.linked_candidate_count
        || anchor.grades().len() != binding.label_record_count
    {
        anyhow::bail!("operator anchor binding does not match immutable anchor artifacts");
    }
    for ((name, _), child) in artifact_contracts.iter().zip([
        &candidate_manifest,
        &candidate_receipt,
        &candidate_receipt_pubkey,
        &candidate_vector,
        &anchor_bytes,
        &link_bytes,
        &binding_bytes,
    ]) {
        child.revalidate(run, name)?;
    }
    run.revalidate_lock()?;
    Ok(())
}

fn validate_operator_anchor_binding(
    binding: &OperatorAnchorRunBinding,
    manifest: &ParityRunManifest,
) -> Result<()> {
    if binding.schema_version != PARITY_HARNESS_SCHEMA_VERSION
        || binding.run_manifest_sha256 != sha256_json(manifest)?
        || binding.label_record_count != 40
        || binding.linked_candidate_count != 20
        || !binding.operator_labels_complete
        || binding.gate_eligible
    {
        anyhow::bail!("operator anchor binding is not a complete non-gate artifact for this run");
    }
    for (value, label) in [
        (&binding.operator_anchor_sha256, "operator anchor"),
        (&binding.operator_anchor_link_sha256, "operator anchor link"),
        (&binding.candidate_manifest_sha256, "candidate manifest"),
        (&binding.candidate_receipt_sha256, "candidate receipt"),
        (&binding.candidate_receipt_pubkey_sha256, "candidate receipt public key"),
        (&binding.candidate_vector_sha256, "candidate vector"),
    ] {
        validate_sha256(value, label)?;
    }
    Ok(())
}

/// Import one explicit, offline grade file. A byte-identical retry is a no-op;
/// a second or altered file for the same grader is rejected.
pub fn ingest_offline_grades(
    run_dir: &Path,
    grader_config: &ValidatedGraderConfigFile,
    config_bytes: &[u8],
    goldset: &[GoldsetEntry],
    goldset_bytes: &[u8],
    grade_bytes: &[u8],
) -> Result<ParityRunState> {
    let run = BoundParityRun::open_or_create(run_dir)?;
    let manifest = plan_run_locked(&run, grader_config, config_bytes, goldset, goldset_bytes)?;
    validate_operator_anchor_artifacts_if_present(&run, &manifest, grader_config, goldset)?;
    let state_bytes = run.read_child(STATE_FILE, 1024 * 1024)?;
    let mut state = load_state_for_manifest(&run, &manifest)?;
    validate_state_imports(&run, &state, grader_config, goldset)?;
    if grade_bytes.len() as u64 > MAX_GRADES_BYTES {
        anyhow::bail!("offline grades exceed the {MAX_GRADES_BYTES}-byte limit");
    }
    let grades = super::goldset::load_grades_bytes(grade_bytes, "offline grade import")?;
    let grader_id = validate_single_grader_matrix(grader_config, goldset, &grades)?;
    let source_sha256 = sha256_bytes(grade_bytes);

    if let Some(existing) = state
        .imported_grades
        .iter()
        .find(|entry| entry.grader_id == grader_id)
    {
        if existing.source_sha256 == source_sha256 && existing.record_count == grades.len() {
            return Ok(state);
        }
        anyhow::bail!("grader {grader_id:?} already has a different imported grade artifact");
    }
    if state.imported_grades.len() >= MAX_HARNESS_GRADE_FILES {
        anyhow::bail!("run already contains the maximum {MAX_HARNESS_GRADE_FILES} grade artifacts");
    }

    let record = ImportedGradeFile {
        grader_id,
        source_sha256: source_sha256.clone(),
        record_count: grades.len(),
    };
    let imports = run.open_or_create_imports_locked()?;
    let import_name = format!("{source_sha256}.jsonl");
    let import_display = run.child_display(IMPORTS_DIR).join(&import_name);
    match imports.symlink_metadata(std::ffi::OsStr::new(&import_name)) {
        Ok(_) => {
            let stored = crate::skills::store::read_regular_file_bounded(
                &imports, std::ffi::OsStr::new(&import_name), &import_display, MAX_GRADES_BYTES as usize,
            )?;
            if stored != grade_bytes {
                anyhow::bail!("existing imported grade artifact does not match its SHA256 filename");
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // `atomic_write_private_child_create_new` stages privately and
            // creates the immutable import exactly once through `imports`.
            run.revalidate_lock()?;
            crate::skills::store::atomic_write_private_child_create_new(
                &imports, std::ffi::OsStr::new(&import_name), &import_display, grade_bytes,
            )?;
            let stored = crate::skills::store::read_regular_file_bounded(
                &imports, std::ffi::OsStr::new(&import_name), &import_display, MAX_GRADES_BYTES as usize,
            )?;
            if stored != grade_bytes {
                anyhow::bail!("new imported grade artifact failed exact byte verification");
            }
            run.revalidate_lock()?;
        }
        Err(error) => return Err(error).with_context(|| format!("inspect staged import {}", import_display.display())),
    }
    state.imported_grades.push(record);
    state.imported_grades.sort_by(|a, b| a.grader_id.cmp(&b.grader_id));
    state.report_sha256 = None;
    run.replace_child_if_matches(STATE_FILE, &state_bytes, &serde_json::to_vec(&state)?)?;
    Ok(state)
}

/// Rebuild the deterministic derived report from provenance-verified imports.
/// This intentionally writes no durable gate verdict and never calls the WAL.
pub fn build_report(
    run_dir: &Path,
    grader_config: &ValidatedGraderConfigFile,
    config_bytes: &[u8],
    goldset: &[GoldsetEntry],
    goldset_bytes: &[u8],
    receipt: &SignedParityImportReceipt,
    expected_receipt_pubkey_b64: &str,
) -> Result<ParityHarnessReport> {
    let run_dir = BoundParityRun::open_or_create(run_dir)?;
    let manifest = plan_run_locked(&run_dir, grader_config, config_bytes, goldset, goldset_bytes)?;
    validate_operator_anchor_artifacts_if_present(&run_dir, &manifest, grader_config, goldset)?;
    let state_bytes = run_dir.read_child(STATE_FILE, 1024 * 1024)?;
    let mut state = load_state_for_manifest(&run_dir, &manifest)?;
    validate_state_imports(&run_dir, &state, grader_config, goldset)?;
    // `report_sha256` is publication bookkeeping, not evidence. The report
    // exposes the separately named canonical state-evidence projection below,
    // so retries remain byte-identical while on-disk state stays auditable.
    state.report_sha256 = None;
    if state.imported_grades.len() != grader_config.graders().len() {
        anyhow::bail!(
            "report requires one exact offline grade artifact for every validated grader ({} imported, {} configured)",
            state.imported_grades.len(), grader_config.graders().len()
        );
    }
    verify_external_import_receipt(
        &manifest,
        &state.imported_grades,
        receipt,
        expected_receipt_pubkey_b64,
    )?;

    let mut all_grades = Vec::new();
    for import in &state.imported_grades {
        let imports = run_dir.open_imports()?;
        let name = format!("{}.jsonl", import.source_sha256);
        let bytes = crate::skills::store::read_regular_file_bounded(&imports, std::ffi::OsStr::new(&name), &run_dir.child_display(IMPORTS_DIR).join(&name), MAX_GRADES_BYTES as usize)?;
        if sha256_bytes(&bytes) != import.source_sha256 {
            anyhow::bail!("imported grade artifact for {:?} failed SHA256 verification", import.grader_id);
        }
        let grades = super::goldset::load_grades_bytes(&bytes, "stored offline grade import")?;
        let grader_id = validate_single_grader_matrix(grader_config, goldset, &grades)?;
        if grader_id != import.grader_id || grades.len() != import.record_count {
            anyhow::bail!("stored grade import metadata does not match its validated contents");
        }
        all_grades.extend(grades);
    }

    let run = compute_parity_run(grader_config, goldset, &all_grades)
        .context("compute existing fail-closed recall-parity verdict")?;
    let report = ParityHarnessReport {
        schema_version: PARITY_HARNESS_SCHEMA_VERSION,
        manifest_sha256: sha256_json(&manifest)?,
        state_evidence_sha256: sha256_json(&state_evidence(&state))?,
        imported_grade_sha256: state.imported_grades.clone(),
        derived_gate_passed: run.verdict.passed,
        aggregate: run.aggregate,
        mean_kappa: run.mean_kappa,
        critical_count: run.critical_queries.len(),
        family_bias_clusters: cluster_family_bias(grader_config, &all_grades)?,
    };
    let report_sha256 = sha256_json(&report)?;
    let report_bytes = serde_json::to_vec(&report)?;
    match run_dir.read_child_if_present(REPORT_FILE, 1024 * 1024)? {
        Some(old) => run_dir.replace_child_if_matches(REPORT_FILE, &old, &report_bytes)?,
        None => run_dir.create_child(REPORT_FILE, &report_bytes)?,
    }
    state.report_sha256 = Some(report_sha256);
    run_dir.replace_child_if_matches(STATE_FILE, &state_bytes, &serde_json::to_vec(&state)?)?;
    Ok(report)
}

fn manifest_for(
    grader_config: &ValidatedGraderConfigFile,
    config_bytes: &[u8],
    goldset_bytes: &[u8],
) -> Result<ParityRunManifest> {
    let mut run_id = [0u8; 16];
    getrandom::getrandom(&mut run_id).context("OS RNG unavailable for parity run_id")?;
    Ok(ParityRunManifest {
        schema_version: PARITY_HARNESS_SCHEMA_VERSION,
        run_id: hex::encode(run_id),
        config_sha256: sha256_bytes(config_bytes),
        goldset_sha256: sha256_bytes(goldset_bytes),
        graders: manifest_graders(grader_config),
    })
}

fn manifest_graders(grader_config: &ValidatedGraderConfigFile) -> Vec<ManifestGrader> {
    let mut graders: Vec<_> = grader_config
        .graders()
        .iter()
        .map(|grader| ManifestGrader {
            grader_id: grader.grader_id.clone(),
            provider: serde_json::to_string(&grader.provider)
                .expect("provider serialization is infallible")
                .trim_matches('"')
                .to_owned(),
            model_id: grader.model_id.clone(),
            family: serde_json::to_string(&grader.family)
                .expect("family serialization is infallible")
                .trim_matches('"')
                .to_owned(),
        })
        .collect();
    graders.sort_by(|a, b| a.grader_id.cmp(&b.grader_id));
    graders
}

fn manifest_matches_inputs(
    manifest: &ParityRunManifest,
    grader_config: &ValidatedGraderConfigFile,
    config_bytes: &[u8],
    goldset_bytes: &[u8],
) -> bool {
    manifest.schema_version == PARITY_HARNESS_SCHEMA_VERSION
        && manifest.config_sha256 == sha256_bytes(config_bytes)
        && manifest.goldset_sha256 == sha256_bytes(goldset_bytes)
        && manifest.graders == manifest_graders(grader_config)
}

fn verify_bound_inputs(
    grader_config: &ValidatedGraderConfigFile,
    config_bytes: &[u8],
    goldset: &[GoldsetEntry],
    goldset_bytes: &[u8],
) -> Result<()> {
    let parsed_config = super::goldset::load_grader_config_bytes(config_bytes, "harness config bytes")?;
    if &parsed_config != grader_config {
        anyhow::bail!("validated grader config does not match the SHA256-bound config bytes");
    }
    let parsed_goldset = super::goldset::load_goldset_bytes(goldset_bytes, "harness goldset bytes")?;
    if parsed_goldset != goldset {
        anyhow::bail!("goldset does not match the SHA256-bound goldset bytes");
    }
    Ok(())
}

fn validate_manifest(manifest: &ParityRunManifest) -> Result<()> {
    if manifest.schema_version != PARITY_HARNESS_SCHEMA_VERSION {
        anyhow::bail!("unsupported harness manifest schema version");
    }
    validate_run_id(&manifest.run_id)?;
    validate_sha256(&manifest.config_sha256, "manifest config")?;
    validate_sha256(&manifest.goldset_sha256, "manifest goldset")?;
    if manifest.graders.is_empty() || manifest.graders.len() > MAX_GRADERS {
        anyhow::bail!("manifest grader count is out of bounds");
    }
    let mut ids = BTreeSet::new();
    for grader in &manifest.graders {
        if grader.grader_id.is_empty() || grader.grader_id.len() > 64 || !ids.insert(&grader.grader_id) {
            anyhow::bail!("manifest has invalid or duplicate grader identity");
        }
    }
    Ok(())
}

fn verify_external_import_receipt(
    manifest: &ParityRunManifest,
    imports: &[ImportedGradeFile],
    receipt: &SignedParityImportReceipt,
    expected_receipt_pubkey_b64: &str,
) -> Result<()> {
    receipt.verify(expected_receipt_pubkey_b64)?;
    if receipt.body.run_id != manifest.run_id
        || receipt.body.manifest_sha256 != sha256_json(manifest)?
        || receipt.body.imports != imports
    {
        anyhow::bail!("signed parity import receipt does not exactly bind this complete run import set");
    }
    Ok(())
}

fn load_state_for_manifest(run: &BoundParityRun, manifest: &ParityRunManifest) -> Result<ParityRunState> {
    let state: ParityRunState = serde_json::from_slice(&run.read_child(STATE_FILE, 1024 * 1024)?)
        .context("parse bound parity state")?;
    if state.schema_version != PARITY_HARNESS_SCHEMA_VERSION || state.manifest_sha256 != sha256_json(manifest)? {
        anyhow::bail!("state does not bind the current run manifest");
    }
    if state.imported_grades.len() > MAX_HARNESS_GRADE_FILES {
        anyhow::bail!("state has too many imported grade artifacts");
    }
    let mut graders = BTreeSet::new();
    let roster: BTreeSet<&str> = manifest.graders.iter().map(|grader| grader.grader_id.as_str()).collect();
    let mut prior: Option<&str> = None;
    for import in &state.imported_grades {
        validate_sha256(&import.source_sha256, "imported grade")?;
        if import.grader_id.is_empty()
            || import.grader_id.len() > 64
            || import.record_count != EXPECTED_GOLDSET_QUERIES * 2
            || !roster.contains(import.grader_id.as_str())
            || !graders.insert(&import.grader_id)
            || prior.is_some_and(|previous| previous >= import.grader_id.as_str())
        {
            anyhow::bail!("state contains invalid or duplicate imported grade metadata");
        }
        prior = Some(&import.grader_id);
    }
    if let Some(hash) = &state.report_sha256 {
        validate_sha256(hash, "report")?;
    }
    Ok(state)
}

fn state_evidence(state: &ParityRunState) -> ParityRunStateEvidence<'_> {
    ParityRunStateEvidence {
        schema_version: state.schema_version,
        manifest_sha256: &state.manifest_sha256,
        imported_grades: &state.imported_grades,
    }
}

fn validate_state_imports(
    run: &BoundParityRun,
    state: &ParityRunState,
    grader_config: &ValidatedGraderConfigFile,
    goldset: &[GoldsetEntry],
) -> Result<()> {
    if state.imported_grades.is_empty() { return Ok(()); }
    let imports = run.open_imports()?;
    for import in &state.imported_grades {
        let name = format!("{}.jsonl", import.source_sha256);
        let bytes = crate::skills::store::read_regular_file_bounded(&imports, std::ffi::OsStr::new(&name), &run.child_display(IMPORTS_DIR).join(&name), MAX_GRADES_BYTES as usize)?;
        if sha256_bytes(&bytes) != import.source_sha256 {
            anyhow::bail!("stored import {:?} failed SHA256 verification", import.grader_id);
        }
        let grades = super::goldset::load_grades_bytes(&bytes, "stored staged parity grade import")?;
        let grader_id = validate_single_grader_matrix(grader_config, goldset, &grades)?;
        if grader_id != import.grader_id || grades.len() != import.record_count {
            anyhow::bail!("stored import metadata does not match its validated grade matrix");
        }
    }
    Ok(())
}

fn validate_single_grader_matrix(
    grader_config: &ValidatedGraderConfigFile,
    goldset: &[GoldsetEntry],
    grades: &[GraderGrade],
) -> Result<String> {
    let expected_records = goldset.len().checked_mul(2).context("grade matrix size overflow")?;
    if grades.len() != expected_records {
        anyhow::bail!("each offline grade artifact must contain exactly {expected_records} records");
    }
    let grader_id = grades.first().context("offline grade artifact is empty")?.grader_id.clone();
    if !grader_config.graders().iter().any(|grader| grader.grader_id == grader_id) {
        anyhow::bail!("offline grade artifact names a grader absent from the validated roster");
    }
    let goldset_ids: BTreeSet<&str> = goldset.iter().map(|entry| entry.query_id.as_str()).collect();
    let mut pairs = BTreeSet::new();
    for grade in grades {
        grade.validate()?;
        if grade.grader_id != grader_id || !goldset_ids.contains(grade.query_id.as_str()) {
            anyhow::bail!("offline grade artifact is not a single exact roster/goldset matrix");
        }
        let system = match grade.system { GradedSystem::Neoth => "neoth", GradedSystem::Reference => "reference" };
        if !pairs.insert((grade.query_id.as_str(), system)) {
            anyhow::bail!("offline grade artifact has duplicate query/system observations");
        }
    }
    if pairs.len() != expected_records {
        anyhow::bail!("offline grade artifact omits a query/system observation");
    }
    Ok(grader_id)
}

fn cluster_family_bias(
    grader_config: &ValidatedGraderConfigFile,
    grades: &[GraderGrade],
) -> Result<Vec<FamilyBiasCluster>> {
    let family_by_grader: BTreeMap<&str, String> = grader_config.graders().iter().map(|grader| {
        (grader.grader_id.as_str(), serde_json::to_string(&grader.family)
            .expect("family serialization is infallible").trim_matches('"').to_owned())
    }).collect();
    let mut totals: BTreeMap<(String, String, String), (u64, u64)> = BTreeMap::new();
    let mut family_totals: BTreeMap<(String, String, String), (u64, u64)> = BTreeMap::new();
    for grade in grades {
        let family = family_by_grader.get(grade.grader_id.as_str())
            .context("grade references a non-validated grader during clustering")?.clone();
        let system = match grade.system { GradedSystem::Neoth => "neoth", GradedSystem::Reference => "reference" };
        for dimension in Dimension::ALL {
            let key = (system.to_owned(), dimension.as_str().to_owned());
            accumulate_total(&mut totals, key.clone(), grade.score(dimension))?;
            accumulate_family(&mut family_totals, (family.clone(), key.0, key.1), grade.score(dimension))?;
        }
    }
    let mut family_grader_counts: BTreeMap<String, usize> = BTreeMap::new();
    for family in family_by_grader.values() {
        *family_grader_counts.entry(family.clone()).or_default() += 1;
    }
    let mut clusters = Vec::new();
    for (family, grader_count) in family_grader_counts {
        let mut dimensions = Vec::new();
        for system in ["neoth", "reference"] {
            for dimension in Dimension::ALL {
                let key = (system.to_owned(), dimension.as_str().to_owned());
                let (all_sum, all_count) = totals.get(&key).context("missing aggregate cluster bucket")?;
                let (family_sum, family_count) = family_totals.get(&(family.clone(), key.0.clone(), key.1.clone()))
                    .context("missing family cluster bucket")?;
                let all_mean = *all_sum as f64 / *all_count as f64;
                let family_mean = *family_sum as f64 / *family_count as f64;
                dimensions.push(FamilyBiasDimension {
                    system: system.to_owned(),
                    dimension: dimension.as_str().to_owned(),
                    observation_count: usize::try_from(*family_count).context("family observation count overflow")?,
                    family_mean,
                    all_grader_mean: all_mean,
                    signed_bias: family_mean - all_mean,
                });
            }
        }
        clusters.push(FamilyBiasCluster { family, grader_count, dimensions });
    }
    Ok(clusters)
}

fn accumulate_total(
    target: &mut BTreeMap<(String, String, String), (u64, u64)>,
    key: (String, String),
    score: u8,
) -> Result<()> {
    let entry = target.entry((String::new(), key.0, key.1)).or_default();
    entry.0 = entry.0.checked_add(u64::from(score)).context("score sum overflow")?;
    entry.1 = entry.1.checked_add(1).context("score count overflow")?;
    Ok(())
}

fn accumulate_family(
    target: &mut BTreeMap<(String, String, String), (u64, u64)>,
    key: (String, String, String),
    score: u8,
) -> Result<()> {
    let entry = target.entry(key).or_default();
    entry.0 = entry.0.checked_add(u64::from(score)).context("score sum overflow")?;
    entry.1 = entry.1.checked_add(1).context("score count overflow")?;
    Ok(())
}

fn validate_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()) {
        anyhow::bail!("{label} SHA256 must be 64 lowercase hexadecimal characters");
    }
    Ok(())
}

fn sha256_bytes(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }

fn sha256_json<T: Serialize>(value: &T) -> Result<String> {
    Ok(sha256_bytes(&serde_json::to_vec(value).context("serialize deterministic harness data")?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recall::goldset::{GraderConfig, GraderConfigFile, GraderFamily, GraderProvider, GoldsetCategory};
    use crate::recall::parity_import_receipt::{
        PARITY_IMPORT_RECEIPT_PURPOSE, PARITY_IMPORT_RECEIPT_SCHEMA_VERSION,
        ParityImportReceiptBody, SignedParityImportReceipt,
    };
    use crate::recall::{
        parity_anchor::{
            OPERATOR_ANCHOR_EVIDENCE_LINK_PURPOSE, OPERATOR_ANCHOR_EVIDENCE_LINK_SCHEMA_VERSION,
            OPERATOR_ANCHOR_GRADER_ID, OperatorAnchorCandidateLink, OperatorAnchorEvidenceLink,
        },
        parity_candidate_evidence::{
            CANDIDATE_EVIDENCE_PURPOSE, CANDIDATE_EVIDENCE_RECEIPT_PURPOSE,
            CANDIDATE_EVIDENCE_RECEIPT_SCHEMA_VERSION, CANDIDATE_EVIDENCE_SCHEMA_VERSION,
            CandidateEvidenceManifest, CandidateEvidenceReceiptBody, CandidateEvidenceSourceKind,
            MinedCandidate, SignedCandidateEvidenceReceipt, load_imported_candidate_evidence,
        },
    };

    fn roster() -> ValidatedGraderConfigFile {
        GraderConfigFile { schema_version: 1, graders: vec![
            GraderConfig { grader_id: "shared".into(), provider: GraderProvider::Openai, model_id: "model-a".into(), family: GraderFamily::AnthropicOpenaiGoogle },
            GraderConfig { grader_id: "external".into(), provider: GraderProvider::Mistral, model_id: "model-b".into(), family: GraderFamily::IndependentExternal },
        ] }.into_validated().unwrap()
    }

    fn goldset() -> Vec<GoldsetEntry> {
        (0..EXPECTED_GOLDSET_QUERIES).map(|i| GoldsetEntry { query_id: format!("q-{i}"), query_text: "q".into(), category: GoldsetCategory::Recall, expected_sources: vec![], expected_response: String::new() }).collect()
    }

    fn grades(grader_id: &str) -> Vec<u8> {
        goldset().iter().flat_map(|entry| [GraderGrade { query_id: entry.query_id.clone(), grader_id: grader_id.into(), system: GradedSystem::Neoth, factual: 5, completeness: 5, on_tone: 5, usefulness: 5, brevity: 5 }, GraderGrade { query_id: entry.query_id.clone(), grader_id: grader_id.into(), system: GradedSystem::Reference, factual: 5, completeness: 5, on_tone: 5, usefulness: 5, brevity: 5 }]).map(|grade| serde_json::to_string(&grade).unwrap()).collect::<Vec<_>>().join("\n").into_bytes()
    }

    fn signed_receipt(manifest: &ParityRunManifest, imports: Vec<ImportedGradeFile>) -> (SignedParityImportReceipt, String) {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut receipt = SignedParityImportReceipt {
            body: ParityImportReceiptBody {
                schema_version: PARITY_IMPORT_RECEIPT_SCHEMA_VERSION,
                purpose: PARITY_IMPORT_RECEIPT_PURPOSE.into(),
                run_id: manifest.run_id.clone(),
                manifest_sha256: sha256_json(manifest).unwrap(),
                imports,
            },
            signature_b64: String::new(),
        };
        receipt.signature_b64 = crate::wal::signing::sign_b64(&key, &receipt.canonical_bytes().unwrap());
        (receipt, crate::wal::signing::pubkey_b64(&key))
    }

    fn resign(receipt: &mut SignedParityImportReceipt) {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        receipt.signature_b64 = crate::wal::signing::sign_b64(&key, &receipt.canonical_bytes().unwrap());
    }

    fn candidate_evidence_fixture() -> (tempfile::TempDir, ValidatedCandidateEvidence, String) {
        let directory = tempfile::tempdir().unwrap();
        let source = b"01234567890123456789";
        let candidates = (0..20)
            .map(|index| MinedCandidate {
                candidate_id: format!("cand-{index:03}"),
                source_offset: index,
                source_len: 1,
                source_span_sha256: sha256_bytes(&source[index..index + 1]),
            })
            .collect::<Vec<_>>();
        let candidate_bytes = candidates
            .iter()
            .map(|candidate| serde_json::to_string(candidate).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes();
        let manifest = CandidateEvidenceManifest {
            schema_version: CANDIDATE_EVIDENCE_SCHEMA_VERSION,
            purpose: CANDIDATE_EVIDENCE_PURPOSE.into(),
            bundle_id: "anchor-fixture".into(),
            source_kind: CandidateEvidenceSourceKind::TranscriptExport,
            source_sha256: sha256_bytes(source),
            source_bytes: source.len(),
            candidates_sha256: sha256_bytes(&candidate_bytes),
            candidate_count: candidates.len(),
        };
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let signer = ed25519_dalek::SigningKey::from_bytes(&[29; 32]);
        let mut receipt = SignedCandidateEvidenceReceipt {
            body: CandidateEvidenceReceiptBody {
                schema_version: CANDIDATE_EVIDENCE_RECEIPT_SCHEMA_VERSION,
                purpose: CANDIDATE_EVIDENCE_RECEIPT_PURPOSE.into(),
                bundle_id: manifest.bundle_id.clone(),
                manifest_sha256: sha256_bytes(&manifest_bytes),
                source_kind: manifest.source_kind,
                source_sha256: manifest.source_sha256.clone(),
                source_bytes: manifest.source_bytes,
                candidates_sha256: manifest.candidates_sha256.clone(),
                candidate_count: manifest.candidate_count,
            },
            signature_b64: String::new(),
        };
        receipt.signature_b64 = crate::wal::signing::sign_b64(&signer, &receipt.canonical_bytes().unwrap());
        std::fs::write(directory.path().join("candidate-evidence-manifest.json"), &manifest_bytes).unwrap();
        std::fs::write(directory.path().join("candidate-evidence-receipt.json"), serde_json::to_vec(&receipt).unwrap()).unwrap();
        std::fs::write(directory.path().join("source.evidence"), source).unwrap();
        std::fs::write(directory.path().join("candidates.jsonl"), &candidate_bytes).unwrap();
        let pubkey = crate::wal::signing::pubkey_b64(&signer);
        let evidence = load_imported_candidate_evidence(directory.path(), &pubkey).unwrap();
        (directory, evidence, pubkey)
    }

    fn operator_anchor_inputs(evidence: &ValidatedCandidateEvidence) -> (Vec<u8>, Vec<u8>) {
        let anchor_bytes = (0..20)
            .flat_map(|index| [GradedSystem::Neoth, GradedSystem::Reference].map(|system| GraderGrade {
                query_id: format!("q-{index}"),
                grader_id: OPERATOR_ANCHOR_GRADER_ID.into(),
                system,
                factual: 3,
                completeness: 3,
                on_tone: 3,
                usefulness: 3,
                brevity: 3,
            }))
            .map(|grade| serde_json::to_string(&grade).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes();
        let mut queries = (0..20).map(|index| format!("q-{index}")).collect::<Vec<_>>();
        queries.sort();
        let link = OperatorAnchorEvidenceLink {
            schema_version: OPERATOR_ANCHOR_EVIDENCE_LINK_SCHEMA_VERSION,
            purpose: OPERATOR_ANCHOR_EVIDENCE_LINK_PURPOSE.into(),
            candidate_manifest_sha256: evidence.manifest_sha256().to_owned(),
            candidate_receipt_sha256: evidence.receipt_sha256().to_owned(),
            operator_anchor_sha256: sha256_bytes(&anchor_bytes),
            links: queries.into_iter().enumerate().map(|(index, query_id)| OperatorAnchorCandidateLink {
                query_id,
                candidate_id: format!("cand-{index:03}"),
            }).collect(),
        };
        (anchor_bytes, serde_json::to_vec(&link).unwrap())
    }

    #[test]
    fn plan_ingest_report_is_idempotent_and_tamper_rejecting() {
        let dir = tempfile::tempdir().unwrap();
        let config = roster(); let goldset = goldset();
        let config_bytes = serde_json::to_vec(&GraderConfigFile { schema_version: 1, graders: config.graders().to_vec() }).unwrap();
        let goldset_bytes = goldset.iter().map(|entry| serde_json::to_string(entry).unwrap()).collect::<Vec<_>>().join("\n").into_bytes();
        let manifest = plan_run(dir.path(), &config, config_bytes, &goldset, goldset_bytes).unwrap();
        let first = ingest_offline_grades(dir.path(), &config, config_bytes, &goldset, goldset_bytes, &grades("shared")).unwrap();
        let retry = ingest_offline_grades(dir.path(), &config, config_bytes, &goldset, goldset_bytes, &grades("shared")).unwrap();
        assert_eq!(first, retry);
        let complete = ingest_offline_grades(dir.path(), &config, config_bytes, &goldset, goldset_bytes, &grades("external")).unwrap();
        let (receipt, pubkey) = signed_receipt(&manifest, complete.imported_grades.clone());
        let report = build_report(dir.path(), &config, config_bytes, &goldset, goldset_bytes, &receipt, &pubkey).unwrap();
        let retry_report = build_report(dir.path(), &config, config_bytes, &goldset, goldset_bytes, &receipt, &pubkey).unwrap();
        assert_eq!(report, retry_report);
        let persisted: ParityRunState = serde_json::from_slice(
            &std::fs::read(dir.path().join(STATE_FILE)).unwrap(),
        ).unwrap();
        assert_eq!(report.state_evidence_sha256, sha256_json(&state_evidence(&persisted)).unwrap());
        assert!(report.derived_gate_passed);
        assert_eq!(report.family_bias_clusters.len(), 2);
        assert!(report.derived_gate_passed);
    }

    #[test]
    fn anchor_ingest_persists_complete_redacted_provenance_and_resumes_only_identically() {
        let run = tempfile::tempdir().unwrap();
        let (_candidate_dir, evidence, _pubkey) = candidate_evidence_fixture();
        let config = roster();
        let entries = goldset();
        let config_bytes = serde_json::to_vec(&GraderConfigFile { schema_version: 1, graders: config.graders().to_vec() }).unwrap();
        let goldset_bytes = entries.iter().map(|entry| serde_json::to_string(entry).unwrap()).collect::<Vec<_>>().join("\n").into_bytes();
        let (anchor_bytes, link_bytes) = operator_anchor_inputs(&evidence);
        let first = ingest_operator_anchor_evidence(
            run.path(), &config, &config_bytes, &entries, &goldset_bytes,
            &evidence, &anchor_bytes, &link_bytes,
        ).unwrap();
        let retry = ingest_operator_anchor_evidence(
            run.path(), &config, &config_bytes, &entries, &goldset_bytes,
            &evidence, &anchor_bytes, &link_bytes,
        ).unwrap();
        assert_eq!(first, retry);
        assert!(first.operator_labels_complete);
        assert!(!first.gate_eligible);
        for name in [
            CANDIDATE_EVIDENCE_MANIFEST_FILE,
            CANDIDATE_EVIDENCE_RECEIPT_FILE,
            CANDIDATE_EVIDENCE_RECEIPT_PUBKEY_FILE,
            CANDIDATE_EVIDENCE_CANDIDATES_FILE,
            OPERATOR_ANCHOR_FILE,
            OPERATOR_ANCHOR_LINK_FILE,
            OPERATOR_ANCHOR_BINDING_FILE,
        ] {
            assert!(run.path().join(name).is_file(), "missing immutable anchor artifact {name}");
        }
        plan_run(run.path(), &config, &config_bytes, &entries, &goldset_bytes).unwrap();
        let mut altered_anchor = anchor_bytes.clone();
        altered_anchor.push(b'\n');
        assert!(ingest_operator_anchor_evidence(
            run.path(), &config, &config_bytes, &entries, &goldset_bytes,
            &evidence, &altered_anchor, &link_bytes,
        ).is_err());

        let partial_run = tempfile::tempdir().unwrap();
        plan_run(partial_run.path(), &config, &config_bytes, &entries, &goldset_bytes).unwrap();
        let bound = BoundParityRun::open_or_create(partial_run.path()).unwrap();
        create_immutable_run_child(
            &bound,
            CANDIDATE_EVIDENCE_MANIFEST_FILE,
            evidence.manifest_bytes(),
            1024 * 1024,
        ).unwrap();
        drop(bound);
        assert!(plan_run(partial_run.path(), &config, &config_bytes, &entries, &goldset_bytes).is_err());
        assert!(ingest_operator_anchor_evidence(
            partial_run.path(), &config, &config_bytes, &entries, &goldset_bytes,
            &evidence, &anchor_bytes, &link_bytes,
        ).is_ok());

        let receipt_path = run.path().join(CANDIDATE_EVIDENCE_RECEIPT_FILE);
        let mut tampered_receipt: SignedCandidateEvidenceReceipt =
            serde_json::from_slice(&std::fs::read(&receipt_path).unwrap()).unwrap();
        tampered_receipt.signature_b64 = "A".repeat(88);
        std::fs::write(&receipt_path, serde_json::to_vec(&tampered_receipt).unwrap()).unwrap();
        assert!(plan_run(run.path(), &config, &config_bytes, &entries, &goldset_bytes).is_err());
    }

    #[test]
    fn report_rejects_validly_resigned_receipts_for_another_run_or_import_set() {
        let dir = tempfile::tempdir().unwrap();
        let config = roster(); let goldset = goldset();
        let config_bytes = serde_json::to_vec(&GraderConfigFile { schema_version: 1, graders: config.graders().to_vec() }).unwrap();
        let goldset_bytes = goldset.iter().map(|entry| serde_json::to_string(entry).unwrap()).collect::<Vec<_>>().join("\n").into_bytes();
        let manifest = plan_run(dir.path(), &config, &config_bytes, &goldset, &goldset_bytes).unwrap();
        ingest_offline_grades(dir.path(), &config, &config_bytes, &goldset, &goldset_bytes, &grades("shared")).unwrap();
        let complete = ingest_offline_grades(dir.path(), &config, &config_bytes, &goldset, &goldset_bytes, &grades("external")).unwrap();
        let (receipt, pubkey) = signed_receipt(&manifest, complete.imported_grades);
        let mutations: [fn(&mut SignedParityImportReceipt); 4] = [
            |receipt: &mut SignedParityImportReceipt| receipt.body.run_id = "a".repeat(32),
            |receipt: &mut SignedParityImportReceipt| receipt.body.manifest_sha256 = "b".repeat(64),
            |receipt: &mut SignedParityImportReceipt| { receipt.body.imports.pop(); },
            |receipt: &mut SignedParityImportReceipt| receipt.body.imports.swap(0, 1),
        ];
        for mutate in mutations {
            let mut altered = receipt.clone();
            mutate(&mut altered);
            resign(&mut altered);
            assert!(build_report(
                dir.path(), &config, &config_bytes, &goldset, &goldset_bytes, &altered, &pubkey,
            ).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn bound_run_rejects_linked_imports_and_lock_leaf_replacement() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let config = roster(); let goldset = goldset();
        let config_bytes = serde_json::to_vec(&GraderConfigFile { schema_version: 1, graders: config.graders().to_vec() }).unwrap();
        let goldset_bytes = goldset.iter().map(|entry| serde_json::to_string(entry).unwrap()).collect::<Vec<_>>().join("\n").into_bytes();
        plan_run(dir.path(), &config, &config_bytes, &goldset, &goldset_bytes).unwrap();
        let bound = BoundParityRun::open_or_create(dir.path()).unwrap();
        let lock = dir.path().join(LOCK_FILE);
        std::fs::rename(&lock, dir.path().join("moved-lock")).unwrap();
        std::fs::File::create(&lock).unwrap();
        assert!(bound.create_child("must-not-publish.json", b"{}").is_err());
        drop(bound);

        std::fs::remove_file(lock).unwrap();
        symlink(dir.path(), dir.path().join(IMPORTS_DIR)).unwrap();
        assert!(ingest_offline_grades(
            dir.path(), &config, &config_bytes, &goldset, &goldset_bytes, &grades("shared"),
        ).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn bound_root_handle_does_not_publish_into_a_replaced_ancestor_namespace() {
        let parent = tempfile::tempdir().unwrap();
        let visible_ancestor = parent.path().join("visible-ancestor");
        std::fs::create_dir(&visible_ancestor).unwrap();
        let run_path = visible_ancestor.join("run");
        let config = roster(); let goldset = goldset();
        let config_bytes = serde_json::to_vec(&GraderConfigFile { schema_version: 1, graders: config.graders().to_vec() }).unwrap();
        let goldset_bytes = goldset.iter().map(|entry| serde_json::to_string(entry).unwrap()).collect::<Vec<_>>().join("\n").into_bytes();
        plan_run(&run_path, &config, &config_bytes, &goldset, &goldset_bytes).unwrap();
        let bound = BoundParityRun::open_or_create(&run_path).unwrap();
        let retained_ancestor = parent.path().join("retained-ancestor");
        std::fs::rename(&visible_ancestor, &retained_ancestor).unwrap();
        std::fs::create_dir(&visible_ancestor).unwrap();
        std::fs::create_dir(&run_path).unwrap();
        bound.create_child("bound-only.json", b"{}").unwrap();
        assert!(retained_ancestor.join("run").join("bound-only.json").is_file());
        assert!(!run_path.join("bound-only.json").exists());
    }
}
