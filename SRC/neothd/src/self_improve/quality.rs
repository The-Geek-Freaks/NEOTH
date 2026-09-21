//! Fixed-root proposal quality evidence.
//!
//! Narrative scores supplied by SkillOpt are intentionally absent here. The
//! only producer is the exact operator-approved verifier selected by the
//! execution lifecycle.

use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{Proposal, SelfImproveConfig};

pub const QUALITY_SCHEMA_V1: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QualityRegressionV1 {
    pub id: String,
    pub passed: bool,
    pub evidence_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProposalQualityEvidenceV1 {
    pub schema_version: u32,
    pub evaluator_source_id: String,
    pub corpus_manifest_sha256: String,
    pub before_sha256: String,
    pub after_sha256: String,
    pub source_map_receipt_sha256: String,
    pub metric: String,
    pub score_before: f64,
    pub score_after: f64,
    pub regressions: Vec<QualityRegressionV1>,
    pub evaluator_output_sha256: String,
    pub evidence_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProposalQualityState {
    Incomplete,
    Current,
    Stale,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProposalQualityReadback {
    pub state: ProposalQualityState,
    pub reason: Option<String>,
    pub metric: Option<String>,
    pub score_before: Option<f64>,
    pub score_after: Option<f64>,
    pub score_delta: Option<f64>,
    pub evaluator_source_short_id: Option<String>,
    pub corpus_manifest_sha256: Option<String>,
    pub regression_total: usize,
    pub regression_passed: usize,
    pub evidence_sha256: Option<String>,
}

/// A core-owned, immutable-at-read snapshot of the fixed evaluation corpus.
/// The verifier sees only a copy of these bytes in its temporary workspace.
#[derive(Debug, Clone)]
pub(crate) struct FixedCorpus {
    pub manifest_sha256: String,
    pub metric: String,
    pub manifest_bytes: String,
    pub cases: Vec<FixedCorpusCase>,
}

#[derive(Debug, Clone)]
pub(crate) struct FixedCorpusCase {
    pub id: String,
    pub bytes: String,
}

pub(crate) fn fixed_eval_root(home: &Path) -> PathBuf {
    home.join("self_improve_eval").join("v1")
}

pub(crate) fn fixed_skill_corpus_root(home: &Path, skill: &str) -> Result<PathBuf> {
    ensure!(
        valid_component(skill),
        "self-improve quality skill id is not a fixed corpus component"
    );
    Ok(fixed_eval_root(home).join(skill))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusManifest {
    schema_version: u32,
    metric: String,
    cases: Vec<CorpusCase>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusCase {
    id: String,
    sha256: String,
}

/// Read the sole NEOTH-owned evaluation corpus. Names come only from the
/// fixed manifest and every leaf goes through the existing bounded regular-file
/// reader, which rejects links and special files.
pub(crate) fn load_fixed_corpus(home: &Path, skill: &str) -> Result<FixedCorpus> {
    let root = fixed_skill_corpus_root(home, skill)?;
    let manifest_bytes = super::read_regular_file_bounded_utf8(
        &root.join("manifest.json"),
        1024 * 1024,
        "self-improve evaluation manifest",
    )?;
    let manifest: CorpusManifest = serde_json::from_str(&manifest_bytes)
        .context("parse fixed self-improve evaluation manifest")?;
    ensure!(
        manifest.schema_version == QUALITY_SCHEMA_V1,
        "unknown fixed corpus schema"
    );
    ensure!(
        valid_component(&manifest.metric)
            && !manifest.cases.is_empty()
            && manifest.cases.len() <= 1024,
        "fixed corpus manifest is invalid"
    );
    let mut ids = std::collections::BTreeSet::new();
    let mut canonical = format!("v1\n{}\n", manifest.metric);
    let mut cases = Vec::with_capacity(manifest.cases.len());
    for case in manifest.cases {
        ensure!(
            valid_component(&case.id) && ids.insert(case.id.clone()) && valid_sha256(&case.sha256),
            "fixed corpus case descriptor is invalid"
        );
        let bytes = super::read_regular_file_bounded_utf8(
            &root.join("cases").join(format!("{}.json", case.id)),
            1024 * 1024,
            "self-improve evaluation case",
        )?;
        ensure!(
            digest(&bytes) == case.sha256.to_ascii_lowercase(),
            "fixed corpus case content hash changed"
        );
        canonical.push_str(&format!(
            "{}\n{}\n",
            case.id,
            case.sha256.to_ascii_lowercase()
        ));
        cases.push(FixedCorpusCase { id: case.id, bytes });
    }
    Ok(FixedCorpus {
        manifest_sha256: digest(&canonical),
        metric: manifest.metric,
        manifest_bytes,
        cases,
    })
}

pub(crate) fn proposal_quality_readback(
    home: &Path,
    proposal: &Proposal,
) -> ProposalQualityReadback {
    match proposal.quality_evidence.as_ref() {
        None => ProposalQualityReadback {
            state: ProposalQualityState::Incomplete,
            reason: Some(
                "quality evidence is incomplete; re-stage and run the fixed approved verifier"
                    .into(),
            ),
            metric: None,
            score_before: None,
            score_after: None,
            score_delta: None,
            evaluator_source_short_id: None,
            corpus_manifest_sha256: None,
            regression_total: 0,
            regression_passed: 0,
            evidence_sha256: None,
        },
        Some(evidence) => match validate_evidence(proposal, evidence)
            .and_then(|()| revalidate_live_authority(home, proposal, evidence))
        {
            Ok(()) => ProposalQualityReadback {
                state: ProposalQualityState::Current,
                reason: None,
                metric: Some(evidence.metric.clone()),
                score_before: Some(evidence.score_before),
                score_after: Some(evidence.score_after),
                score_delta: Some(evidence.score_after - evidence.score_before),
                evaluator_source_short_id: Some(short_hash(&evidence.evaluator_source_id)),
                corpus_manifest_sha256: Some(evidence.corpus_manifest_sha256.clone()),
                regression_total: evidence.regressions.len(),
                regression_passed: evidence
                    .regressions
                    .iter()
                    .filter(|case| case.passed)
                    .count(),
                evidence_sha256: Some(evidence.evidence_sha256.clone()),
            },
            Err(error) => ProposalQualityReadback {
                state: ProposalQualityState::Stale,
                reason: Some(error.to_string()),
                metric: None,
                score_before: None,
                score_after: None,
                score_delta: None,
                evaluator_source_short_id: None,
                corpus_manifest_sha256: None,
                regression_total: 0,
                regression_passed: 0,
                evidence_sha256: None,
            },
        },
    }
}

pub(crate) fn require_current_proposal_quality(home: &Path, proposal: &Proposal) -> Result<()> {
    let readback = proposal_quality_readback(home, proposal);
    ensure!(
        readback.state == ProposalQualityState::Current,
        "{}",
        readback
            .reason
            .unwrap_or_else(|| "proposal quality evidence is not current".into())
    );
    Ok(())
}

pub(crate) fn validate_evidence(
    proposal: &Proposal,
    evidence: &ProposalQualityEvidenceV1,
) -> Result<()> {
    ensure!(
        evidence.schema_version == QUALITY_SCHEMA_V1,
        "unknown proposal quality evidence schema"
    );
    ensure!(
        valid_sha256(&evidence.corpus_manifest_sha256),
        "quality corpus manifest digest is invalid"
    );
    ensure!(
        valid_sha256(&evidence.evaluator_output_sha256),
        "quality evaluator output digest is invalid"
    );
    ensure!(
        valid_sha256(&evidence.source_map_receipt_sha256),
        "quality source-map receipt digest is invalid"
    );
    ensure!(
        valid_component(&evidence.metric),
        "quality metric is invalid"
    );
    ensure!(
        !evidence.evaluator_source_id.is_empty() && evidence.evaluator_source_id.len() <= 4096,
        "quality evaluator source is invalid"
    );
    ensure!(
        evidence.score_before.is_finite() && evidence.score_after.is_finite(),
        "quality scores must be finite"
    );
    ensure!(
        evidence.score_after > evidence.score_before,
        "quality metric did not strictly improve"
    );
    ensure!(
        !evidence.regressions.is_empty() && evidence.regressions.len() <= 1024,
        "quality regressions are missing or oversized"
    );
    let mut ids = std::collections::BTreeSet::new();
    for case in &evidence.regressions {
        ensure!(
            valid_component(&case.id) && ids.insert(&case.id),
            "quality regression ids must be unique"
        );
        ensure!(
            case.passed && valid_sha256(&case.evidence_sha256),
            "quality regression failed or digest is invalid"
        );
    }
    ensure!(
        evidence.before_sha256 == digest(&proposal.before),
        "quality evidence baseline no longer matches proposal"
    );
    ensure!(
        evidence.after_sha256 == digest(&proposal.after),
        "quality evidence candidate no longer matches proposal"
    );
    ensure!(
        evidence.source_map_receipt_sha256 == source_map_receipt_digest(proposal)?,
        "quality evidence source-map receipt no longer matches proposal"
    );
    ensure!(
        evidence.evidence_sha256 == canonical_evidence_digest(proposal, evidence),
        "quality evidence digest does not bind proposal payload"
    );
    Ok(())
}

/// Evidence becomes stale as soon as either the fixed corpus or its exact
/// operator command authority changes. This is deliberately a live check: a
/// syntactically intact stored envelope is never sufficient for approval.
fn revalidate_live_authority(
    home: &Path,
    proposal: &Proposal,
    evidence: &ProposalQualityEvidenceV1,
) -> Result<()> {
    let config = SelfImproveConfig::load(home)?;
    ensure!(
        config.allow_shell_verify
            && config
                .approved_verification_commands
                .iter()
                .any(|command| command == &evidence.evaluator_source_id),
        "quality evaluator is no longer an exact enabled operator-approved verifier"
    );
    let corpus = load_fixed_corpus(home, &proposal.skill)?;
    ensure!(
        corpus.manifest_sha256 == evidence.corpus_manifest_sha256,
        "fixed quality corpus changed or is unavailable"
    );
    ensure!(
        corpus.metric == evidence.metric,
        "fixed quality corpus metric changed"
    );
    let expected_ids = corpus
        .cases
        .iter()
        .map(|case| case.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let actual_ids = evidence
        .regressions
        .iter()
        .map(|case| case.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    ensure!(
        expected_ids == actual_ids,
        "quality regression cases no longer match the fixed corpus"
    );
    Ok(())
}

pub(crate) fn canonical_evidence_digest(
    proposal: &Proposal,
    evidence: &ProposalQualityEvidenceV1,
) -> String {
    let cases = evidence
        .regressions
        .iter()
        .map(|case| format!("{}:{}:{}", case.id, case.passed, case.evidence_sha256))
        .collect::<Vec<_>>()
        .join("\n");
    digest(&format!(
        "neoth-self-improve-quality-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        proposal.id,
        evidence.evaluator_source_id,
        evidence.corpus_manifest_sha256,
        evidence.before_sha256,
        evidence.after_sha256,
        evidence.source_map_receipt_sha256,
        evidence.metric,
        evidence.score_before,
        evidence.score_after,
        evidence.evaluator_output_sha256,
        cases
    ))
}

pub(crate) fn source_map_receipt_digest(proposal: &Proposal) -> Result<String> {
    let super::ProposalCodeMapAnalysis::CapturedFresh {
        receipt,
        source_fingerprint_sha256: Some(source_fingerprint_sha256),
        ..
    } = &proposal.code_map_analysis
    else {
        anyhow::bail!("proposal has no captured source-map receipt for quality evaluation");
    };
    // Capture timestamps and the later audited-payload marker are lifecycle
    // metadata, not source identity. Bind the verifier to the concrete receipt
    // and its source fingerprint so an ordinary approval transition does not
    // invalidate the evidence it just approved.
    let encoded = serde_json::to_vec(&(receipt, source_fingerprint_sha256))
        .context("serialize proposal source-map receipt for quality binding")?;
    Ok(format!("{:x}", Sha256::digest(encoded)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifierResult {
    kind: String,
    schema_version: u32,
    evaluator_source_id: String,
    corpus_manifest_sha256: String,
    before_sha256: String,
    after_sha256: String,
    source_map_receipt_sha256: String,
    metric: String,
    score_before: f64,
    score_after: f64,
    regressions: Vec<QualityRegressionV1>,
}

pub(crate) fn mint_from_verifier_output(
    proposal: &Proposal,
    evaluator_source_id: &str,
    corpus: &FixedCorpus,
    output: &str,
) -> Result<ProposalQualityEvidenceV1> {
    ensure!(
        output.len() <= 1024 * 1024,
        "approved verifier result exceeds bounded output"
    );
    let result: VerifierResult = serde_json::from_str(output)
        .context("approved verifier must emit self_improve_eval_result.v1 JSON")?;
    ensure!(
        result.kind == "self_improve_eval_result.v1" && result.schema_version == QUALITY_SCHEMA_V1,
        "approved verifier result schema binding failed"
    );
    ensure!(
        result.evaluator_source_id == evaluator_source_id,
        "approved verifier result evaluator binding failed"
    );
    ensure!(
        result.corpus_manifest_sha256 == corpus.manifest_sha256,
        "approved verifier result corpus binding failed"
    );
    ensure!(
        result.before_sha256 == digest(&proposal.before),
        "approved verifier result baseline binding failed"
    );
    ensure!(
        result.after_sha256 == digest(&proposal.after),
        "approved verifier result candidate binding failed"
    );
    ensure!(
        result.source_map_receipt_sha256 == source_map_receipt_digest(proposal)?,
        "approved verifier result source-map receipt binding failed"
    );
    ensure!(
        result.metric == corpus.metric,
        "approved verifier result metric binding failed"
    );
    let expected_ids = corpus
        .cases
        .iter()
        .map(|case| case.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let actual_ids = result
        .regressions
        .iter()
        .map(|case| case.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    ensure!(
        expected_ids == actual_ids,
        "approved verifier result regression cases do not match fixed corpus"
    );
    let mut evidence = ProposalQualityEvidenceV1 {
        schema_version: QUALITY_SCHEMA_V1,
        evaluator_source_id: evaluator_source_id.to_owned(),
        corpus_manifest_sha256: corpus.manifest_sha256.clone(),
        before_sha256: digest(&proposal.before),
        after_sha256: digest(&proposal.after),
        source_map_receipt_sha256: source_map_receipt_digest(proposal)?,
        metric: result.metric,
        score_before: result.score_before,
        score_after: result.score_after,
        regressions: result.regressions,
        evaluator_output_sha256: digest(output),
        evidence_sha256: String::new(),
    };
    evidence.evidence_sha256 = canonical_evidence_digest(proposal, &evidence);
    validate_evidence(proposal, &evidence)?;
    Ok(evidence)
}

fn digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}
fn short_hash(value: &str) -> String {
    digest(value)[..12].to_owned()
}
fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
fn valid_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && Path::new(value).components().count() == 1
        && !Path::new(value)
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
}
