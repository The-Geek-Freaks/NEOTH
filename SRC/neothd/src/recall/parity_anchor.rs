//! GOLD-LF-P1-08 — strict operator calibration-anchor artifact validation.
//!
//! This is deliberately an offline, pure analysis boundary. It neither calls a
//! grader/provider nor mutates a parity run: the operator supplies an explicit
//! 20-query × two-system label artifact, which is validated against the exact
//! goldset before its deterministic shared-family bias assessment is exposed.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{
    goldset::{
        GoldsetEntry, GradedSystem, GraderFamily, GraderGrade, ValidatedGraderConfigFile,
        EXPECTED_GOLDSET_QUERIES, MAX_GRADES_BYTES,
    },
    parity::Dimension,
    parity_candidate_evidence::ValidatedCandidateEvidence,
    parity_run::compute_parity_run,
};

/// Exact synthetic grader ID reserved for manual calibration labels.
pub const OPERATOR_ANCHOR_GRADER_ID: &str = "operator-anchor";
/// The methodology calibrates twenty of the one hundred canonical queries.
pub const OPERATOR_ANCHOR_QUERY_COUNT: usize = 20;
/// SPEC §4: all shared-family graders must exceed this signed Likert delta.
pub const FAMILY_BIAS_THRESHOLD: f64 = 0.5;
const OPERATOR_ANCHOR_RECORD_COUNT: usize = OPERATOR_ANCHOR_QUERY_COUNT * 2;
pub const OPERATOR_ANCHOR_EVIDENCE_LINK_SCHEMA_VERSION: u32 = 1;
pub const OPERATOR_ANCHOR_EVIDENCE_LINK_PURPOSE: &str = "neoth-recall-parity-operator-anchor-link/v1";
pub const MAX_OPERATOR_ANCHOR_EVIDENCE_LINK_BYTES: usize = 64 * 1024;

/// Validated manual labels. The artifact intentionally reuses the existing
/// grade JSONL schema so all five Likert bounds and system tags have one parser.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedOperatorAnchor {
    grades: Vec<GraderGrade>,
    query_ids: Vec<String>,
    goldset_sha256: String,
    roster_sha256: String,
}

impl ValidatedOperatorAnchor {
    pub fn grades(&self) -> &[GraderGrade] { &self.grades }

    pub fn query_ids(&self) -> &[String] { &self.query_ids }

    pub fn goldset_sha256(&self) -> &str { &self.goldset_sha256 }

    pub fn roster_sha256(&self) -> &str { &self.roster_sha256 }
}

/// Stable summary rendered by the CLI before any evaluator-grade evidence is
/// accepted into a report run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperatorAnchorSummary {
    pub grader_id: &'static str,
    pub query_count: usize,
    pub record_count: usize,
    pub source_sha256: String,
    pub goldset_sha256: String,
    pub roster_sha256: String,
}

/// One opaque candidate-to-goldset selection made by the operator. Candidate
/// IDs and query IDs are stable identifiers only; no transcript/WAL content is
/// permitted in this link artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorAnchorCandidateLink {
    pub query_id: String,
    pub candidate_id: String,
}

/// External operator-review provenance. The link carries the exact hashes of
/// the already signature-verified candidate bundle and of the exact 20×2
/// label bytes. It is persisted only after all joins are complete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorAnchorEvidenceLink {
    pub schema_version: u32,
    pub purpose: String,
    pub candidate_manifest_sha256: String,
    pub candidate_receipt_sha256: String,
    pub operator_anchor_sha256: String,
    pub links: Vec<OperatorAnchorCandidateLink>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedOperatorAnchorEvidenceLink {
    link: OperatorAnchorEvidenceLink,
}

impl ValidatedOperatorAnchorEvidenceLink {
    pub fn link(&self) -> &OperatorAnchorEvidenceLink { &self.link }
}

/// Per shared-family grader / dimension delta to the operator's manual labels.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GraderAnchorBias {
    pub grader_id: String,
    pub family: GraderFamily,
    pub dimensions: Vec<DimensionBias>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DimensionBias {
    pub dimension: String,
    pub observation_count: usize,
    pub mean_grader_minus_operator: f64,
}

/// A correction recommendation exists only if at least three shared-family
/// graders all exceed the configured bias threshold in the same direction.
/// Applying that recommendation to unanchored scoring remains a later P1-08
/// slice; this type deliberately does not claim that it changed a gate result.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SharedFamilyBiasAssessment {
    pub dimension: String,
    pub shared_family_grader_ids: Vec<String>,
    pub per_grader_bias: Vec<(String, f64)>,
    pub consensus_detected: bool,
    pub recommended_unanchored_correction: Option<f64>,
}

/// Parse a bounded manual-label JSONL artifact and bind it to the canonical
/// goldset. The selected query subset is explicit in the file and may be any
/// twenty distinct canonical IDs; callers persist/hash the exact input bytes.
pub fn load_operator_anchor_bytes(
    bytes: &[u8],
    source: &str,
    goldset: &[GoldsetEntry],
    grader_config: &ValidatedGraderConfigFile,
) -> Result<ValidatedOperatorAnchor> {
    super::goldset::validate_goldset_contract(goldset)
        .context("operator anchor requires the canonical goldset contract")?;
    if bytes.len() as u64 > MAX_GRADES_BYTES {
        anyhow::bail!("operator anchor {source} exceeds the {MAX_GRADES_BYTES}-byte limit");
    }
    let grades = super::goldset::load_grades_bytes(bytes, source)?;
    if grades.len() != OPERATOR_ANCHOR_RECORD_COUNT {
        anyhow::bail!(
            "operator anchor must contain exactly {OPERATOR_ANCHOR_RECORD_COUNT} records (20 queries × neoth/reference)"
        );
    }
    let known_queries: BTreeSet<&str> = goldset.iter().map(|entry| entry.query_id.as_str()).collect();
    let mut query_ids = BTreeSet::new();
    let mut observations = BTreeSet::new();
    for grade in &grades {
        grade.validate()?;
        if grade.grader_id != OPERATOR_ANCHOR_GRADER_ID {
            anyhow::bail!("operator anchor grader_id must be {OPERATOR_ANCHOR_GRADER_ID:?}");
        }
        if !known_queries.contains(grade.query_id.as_str()) {
            anyhow::bail!("operator anchor contains query absent from canonical goldset: {:?}", grade.query_id);
        }
        let system = match grade.system {
            GradedSystem::Neoth => "neoth",
            GradedSystem::Reference => "reference",
        };
        if !observations.insert((grade.query_id.as_str(), system)) {
            anyhow::bail!("operator anchor contains duplicate query/system observation");
        }
        query_ids.insert(grade.query_id.clone());
    }
    if query_ids.len() != OPERATOR_ANCHOR_QUERY_COUNT
        || observations.len() != OPERATOR_ANCHOR_RECORD_COUNT
    {
        anyhow::bail!("operator anchor must cover exactly 20 complete query/system pairs");
    }
    Ok(ValidatedOperatorAnchor {
        grades,
        query_ids: query_ids.into_iter().collect(),
        goldset_sha256: canonical_goldset_sha256(goldset)?,
        roster_sha256: canonical_roster_sha256(grader_config)?,
    })
}

pub fn summarize_operator_anchor(
    anchor: &ValidatedOperatorAnchor,
    source_bytes: &[u8],
) -> OperatorAnchorSummary {
    OperatorAnchorSummary {
        grader_id: OPERATOR_ANCHOR_GRADER_ID,
        query_count: anchor.query_ids.len(),
        record_count: anchor.grades.len(),
        source_sha256: hex::encode(Sha256::digest(source_bytes)),
        goldset_sha256: anchor.goldset_sha256.clone(),
        roster_sha256: anchor.roster_sha256.clone(),
    }
}

/// Validate a bounded operator selection link against both the complete
/// operator anchor and the previously signature-verified imported candidate
/// evidence. The link is intentionally not a gate input: it only permits the
/// caller to persist immutable review provenance after all twenty labels exist.
pub fn load_operator_anchor_evidence_link_bytes(
    bytes: &[u8],
    anchor_bytes: &[u8],
    anchor: &ValidatedOperatorAnchor,
    candidate_evidence: &ValidatedCandidateEvidence,
) -> Result<ValidatedOperatorAnchorEvidenceLink> {
    let candidate_ids = candidate_evidence
        .candidates()
        .iter()
        .map(|candidate| candidate.candidate_id.clone())
        .collect::<Vec<_>>();
    load_operator_anchor_evidence_link_with_provenance(
        bytes,
        anchor_bytes,
        anchor,
        candidate_evidence.manifest_sha256(),
        candidate_evidence.receipt_sha256(),
        &candidate_ids,
    )
}

/// Same strict link validation for metadata re-opened from immutable run
/// artifacts. The caller supplies only candidate IDs and signed provenance
/// digests, never raw transcript/WAL source bytes.
pub(crate) fn load_operator_anchor_evidence_link_with_provenance(
    bytes: &[u8],
    anchor_bytes: &[u8],
    anchor: &ValidatedOperatorAnchor,
    candidate_manifest_sha256: &str,
    candidate_receipt_sha256: &str,
    candidate_ids: &[String],
) -> Result<ValidatedOperatorAnchorEvidenceLink> {
    if bytes.len() > MAX_OPERATOR_ANCHOR_EVIDENCE_LINK_BYTES {
        anyhow::bail!("operator anchor evidence link exceeds the bounded byte limit");
    }
    let link: OperatorAnchorEvidenceLink = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("parse operator anchor evidence link"))?;
    if link.schema_version != OPERATOR_ANCHOR_EVIDENCE_LINK_SCHEMA_VERSION
        || link.purpose != OPERATOR_ANCHOR_EVIDENCE_LINK_PURPOSE
    {
        anyhow::bail!("operator anchor evidence link has unsupported schema or purpose");
    }
    validate_sha256(&link.candidate_manifest_sha256, "operator anchor candidate manifest")?;
    validate_sha256(&link.candidate_receipt_sha256, "operator anchor candidate receipt")?;
    validate_sha256(&link.operator_anchor_sha256, "operator anchor source")?;
    if link.candidate_manifest_sha256 != candidate_manifest_sha256
        || link.candidate_receipt_sha256 != candidate_receipt_sha256
        || link.operator_anchor_sha256 != sha256_bytes(anchor_bytes)
    {
        anyhow::bail!("operator anchor evidence link does not bind the verified candidate evidence and label bytes");
    }
    if link.links.len() != OPERATOR_ANCHOR_QUERY_COUNT {
        anyhow::bail!("operator anchor evidence link must bind exactly 20 labeled queries");
    }
    let anchor_queries: BTreeSet<&str> = anchor.query_ids().iter().map(String::as_str).collect();
    let candidates: BTreeSet<&str> = candidate_ids.iter().map(String::as_str).collect();
    let mut linked_queries = BTreeSet::new();
    let mut linked_candidates = BTreeSet::new();
    let mut prior_query: Option<&str> = None;
    for item in &link.links {
        if let Some(previous) = prior_query {
            if item.query_id.as_str() <= previous {
                anyhow::bail!("operator anchor evidence links must be strictly sorted by unique query_id");
            }
        }
        prior_query = Some(item.query_id.as_str());
        if !anchor_queries.contains(item.query_id.as_str())
            || !linked_queries.insert(item.query_id.as_str())
        {
            anyhow::bail!("operator anchor evidence link contains an unknown or duplicate anchor query");
        }
        if !candidates.contains(item.candidate_id.as_str())
            || !linked_candidates.insert(item.candidate_id.as_str())
        {
            anyhow::bail!("operator anchor evidence link contains an unknown or duplicate evidence candidate");
        }
    }
    if linked_queries != anchor_queries {
        anyhow::bail!("operator anchor evidence link does not cover the complete 20-query label set");
    }
    Ok(ValidatedOperatorAnchorEvidenceLink { link })
}

/// Compute the P1-08 calibration deltas for the three-or-more shared-family
/// graders. `automated_grades` must be the complete validated scoring matrix;
/// `compute_parity_run` is called first solely to enforce that invariant.
pub fn assess_shared_family_bias(
    grader_config: &ValidatedGraderConfigFile,
    goldset: &[GoldsetEntry],
    automated_grades: &[GraderGrade],
    operator_anchor: &ValidatedOperatorAnchor,
) -> Result<(Vec<GraderAnchorBias>, Vec<SharedFamilyBiasAssessment>)> {
    if operator_anchor.goldset_sha256() != canonical_goldset_sha256(goldset)? {
        anyhow::bail!("operator anchor was validated for a different canonical goldset");
    }
    if operator_anchor.roster_sha256() != canonical_roster_sha256(grader_config)? {
        anyhow::bail!("operator anchor was validated for a different grader roster");
    }
    compute_parity_run(grader_config, goldset, automated_grades)
        .context("operator-anchor bias analysis requires a complete valid automated grade matrix")?;
    let automated: BTreeMap<(&str, &str, bool), &GraderGrade> = automated_grades
        .iter()
        .map(|grade| ((grade.query_id.as_str(), grade.grader_id.as_str(), matches!(grade.system, GradedSystem::Neoth)), grade))
        .collect();
    let mut biases = Vec::new();
    for grader in grader_config.graders() {
        let mut dimensions = Vec::new();
        for dimension in Dimension::ALL {
            let mut sum = 0i64;
            let mut count = 0usize;
            for operator_grade in operator_anchor.grades() {
                let automated_grade = automated
                    .get(&(operator_grade.query_id.as_str(), grader.grader_id.as_str(), matches!(operator_grade.system, GradedSystem::Neoth)))
                    .context("complete matrix lost an operator-anchor grader observation")?;
                sum = sum
                    .checked_add(i64::from(automated_grade.score(dimension)) - i64::from(operator_grade.score(dimension)))
                    .context("operator-anchor bias sum overflow")?;
                count = count.checked_add(1).context("operator-anchor bias count overflow")?;
            }
            dimensions.push(DimensionBias {
                dimension: dimension.as_str().to_owned(),
                observation_count: count,
                mean_grader_minus_operator: sum as f64 / count as f64,
            });
        }
        biases.push(GraderAnchorBias {
            grader_id: grader.grader_id.clone(),
            family: grader.family,
            dimensions,
        });
    }
    let mut shared: Vec<_> = biases
        .iter()
        .filter(|bias| bias.family == GraderFamily::AnthropicOpenaiGoogle)
        .cloned()
        .collect();
    shared.sort_by(|a, b| a.grader_id.cmp(&b.grader_id));
    let shared_ids = shared.iter().map(|bias| bias.grader_id.clone()).collect::<Vec<_>>();
    let mut assessments = Vec::new();
    for dimension in Dimension::ALL {
        let per_grader_bias = shared
            .iter()
            .map(|bias| {
                let value = bias.dimensions.iter()
                    .find(|entry| entry.dimension == dimension.as_str())
                    .expect("every bias has every dimension")
                    .mean_grader_minus_operator;
                (bias.grader_id.clone(), value)
            })
            .collect::<Vec<_>>();
        let same_positive = per_grader_bias.iter().all(|(_, value)| *value > FAMILY_BIAS_THRESHOLD);
        let same_negative = per_grader_bias.iter().all(|(_, value)| *value < -FAMILY_BIAS_THRESHOLD);
        let consensus_detected = per_grader_bias.len() >= 3 && (same_positive || same_negative);
        let correction = consensus_detected.then(|| {
            per_grader_bias.iter().map(|(_, value)| value).sum::<f64>() / per_grader_bias.len() as f64
        });
        assessments.push(SharedFamilyBiasAssessment {
            dimension: dimension.as_str().to_owned(),
            shared_family_grader_ids: shared_ids.clone(),
            per_grader_bias,
            consensus_detected,
            recommended_unanchored_correction: correction,
        });
    }
    Ok((biases, assessments))
}

fn canonical_goldset_sha256(goldset: &[GoldsetEntry]) -> Result<String> {
    let mut canonical = goldset.to_vec();
    canonical.sort_by(|left, right| left.query_id.cmp(&right.query_id));
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(&canonical).context("serialize canonical operator-anchor goldset")?,
    )))
}

fn canonical_roster_sha256(grader_config: &ValidatedGraderConfigFile) -> Result<String> {
    let mut canonical = grader_config.graders().to_vec();
    canonical.sort_by(|left, right| left.grader_id.cmp(&right.grader_id));
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(&canonical).context("serialize canonical operator-anchor roster")?,
    )))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn validate_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()) {
        anyhow::bail!("{label} SHA256 must be 64 lowercase hexadecimal characters");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recall::goldset::{GoldsetCategory, GraderConfig, GraderConfigFile, GraderProvider};

    fn goldset() -> Vec<GoldsetEntry> {
        (0..EXPECTED_GOLDSET_QUERIES).map(|i| GoldsetEntry {
            query_id: format!("q{i:03}"), query_text: "q".into(), category: GoldsetCategory::Recall,
            expected_sources: vec![], expected_response: String::new(),
        }).collect()
    }

    fn grade(query_id: &str, grader_id: &str, system: GradedSystem, score: u8) -> GraderGrade {
        GraderGrade { query_id: query_id.into(), grader_id: grader_id.into(), system,
            factual: score, completeness: score, on_tone: score, usefulness: score, brevity: score }
    }

    fn anchor_bytes() -> Vec<u8> {
        (0..OPERATOR_ANCHOR_QUERY_COUNT).flat_map(|i| [
            grade(&format!("q{i:03}"), OPERATOR_ANCHOR_GRADER_ID, GradedSystem::Neoth, 3),
            grade(&format!("q{i:03}"), OPERATOR_ANCHOR_GRADER_ID, GradedSystem::Reference, 3),
        ]).map(|grade| serde_json::to_string(&grade).unwrap()).collect::<Vec<_>>().join("\n").into_bytes()
    }

    #[test]
    fn operator_anchor_requires_twenty_complete_canonical_pairs() {
        let goldset = goldset();
        let config = GraderConfigFile { schema_version: 1, graders: vec![
            GraderConfig { grader_id: "shared".into(), provider: GraderProvider::Anthropic, model_id: "shared".into(), family: GraderFamily::AnthropicOpenaiGoogle },
            GraderConfig { grader_id: "external".into(), provider: GraderProvider::Mistral, model_id: "external".into(), family: GraderFamily::IndependentExternal },
        ] }.into_validated().unwrap();
        let anchor = load_operator_anchor_bytes(&anchor_bytes(), "fixture", &goldset, &config).unwrap();
        assert_eq!(anchor.query_ids().len(), OPERATOR_ANCHOR_QUERY_COUNT);
        assert_eq!(anchor.grades().len(), OPERATOR_ANCHOR_RECORD_COUNT);
        let mut truncated = anchor_bytes();
        truncated.truncate(truncated.len() - 1);
        assert!(load_operator_anchor_bytes(&truncated, "truncated", &goldset, &config).is_err());
        let mut duplicate_goldset = goldset.clone();
        duplicate_goldset[99] = duplicate_goldset[0].clone();
        assert!(load_operator_anchor_bytes(&anchor_bytes(), "duplicate-goldset", &duplicate_goldset, &config).is_err());
    }

    #[test]
    fn three_shared_graders_with_same_large_bias_get_a_correction_recommendation() {
        let goldset = goldset();
        let config = GraderConfigFile { schema_version: 1, graders: vec![
            GraderConfig { grader_id: "a".into(), provider: GraderProvider::Anthropic, model_id: "a".into(), family: GraderFamily::AnthropicOpenaiGoogle },
            GraderConfig { grader_id: "b".into(), provider: GraderProvider::Openai, model_id: "b".into(), family: GraderFamily::AnthropicOpenaiGoogle },
            GraderConfig { grader_id: "c".into(), provider: GraderProvider::Google, model_id: "c".into(), family: GraderFamily::AnthropicOpenaiGoogle },
            GraderConfig { grader_id: "d".into(), provider: GraderProvider::Mistral, model_id: "d".into(), family: GraderFamily::IndependentExternal },
        ] }.into_validated().unwrap();
        let mut automated = Vec::new();
        for entry in &goldset {
            for grader in config.graders() {
                let score = if grader.family == GraderFamily::AnthropicOpenaiGoogle { 4 } else { 3 };
                automated.push(grade(&entry.query_id, &grader.grader_id, GradedSystem::Neoth, score));
                automated.push(grade(&entry.query_id, &grader.grader_id, GradedSystem::Reference, score));
            }
        }
        let anchor = load_operator_anchor_bytes(&anchor_bytes(), "fixture", &goldset, &config).unwrap();
        let (_, assessments) = assess_shared_family_bias(&config, &goldset, &automated, &anchor).unwrap();
        let factual = assessments.iter().find(|assessment| assessment.dimension == "factual").unwrap();
        assert!(factual.consensus_detected);
        assert_eq!(factual.recommended_unanchored_correction, Some(1.0));
        let mut changed_goldset = goldset.clone();
        changed_goldset[0].expected_response = "changed reference evidence".into();
        assert!(assess_shared_family_bias(&config, &changed_goldset, &automated, &anchor).is_err());
        let mut changed_graders = config.graders().to_vec();
        changed_graders[0].model_id = "a-replacement-model".into();
        let changed_config = GraderConfigFile { schema_version: 1, graders: changed_graders }
            .into_validated().unwrap();
        assert!(assess_shared_family_bias(&changed_config, &goldset, &automated, &anchor).is_err());
    }
}
