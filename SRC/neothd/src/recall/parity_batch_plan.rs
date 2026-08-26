//! GOLD-LF-P1-08 — offline four-grader batch-plan and result-attestation wire contracts.
//!
//! This module names evidence only. It never dispatches a provider, opens a
//! credential, or renders prompt/result content. An external executor may use
//! a plan export, but results are accepted only after a detached Ed25519
//! attestation binds their exact bytes to that plan.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::parity_import_receipt::{validate_run_id, validate_sha256};

pub const FOUR_GRADER_BATCH_SCHEMA_VERSION: u32 = 1;
pub const FOUR_GRADER_BATCH_INPUT_PURPOSE: &str =
    "neoth-recall-parity-four-grader-input-digests/v1";
pub const FOUR_GRADER_BATCH_PLAN_PURPOSE: &str = "neoth-recall-parity-four-grader-batch-plan/v1";
pub const FOUR_GRADER_BATCH_RESULT_RECEIPT_PURPOSE: &str =
    "neoth-recall-parity-four-grader-result-receipt/v1";
pub const FOUR_GRADER_COUNT: usize = 4;
pub const MAX_FOUR_GRADER_BATCH_BYTES: usize = 64 * 1024;
pub const MAX_FOUR_GRADER_SIGNATURE_BYTES: usize = 256;
pub const MAX_FOUR_GRADER_PUBKEY_BYTES: usize = 128;

/// One opaque externally-prepared request identity. The actual prompt and
/// request payload remain outside the run directory and this module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FourGraderInputDigest {
    pub grader_id: String,
    pub prompt_sha256: String,
    pub input_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FourGraderInputDigestFile {
    pub schema_version: u32,
    pub purpose: String,
    pub inputs: Vec<FourGraderInputDigest>,
}

/// One exact validated roster projection that an offline executor must score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FourGraderBatchItem {
    pub grader_id: String,
    pub provider: String,
    pub model_id: String,
    pub family: String,
    pub grader_config_sha256: String,
    pub prompt_sha256: String,
    pub input_sha256: String,
    pub expected_record_count: usize,
}

/// Persistent redacted plan. It deliberately contains only stable identities,
/// digest evidence and expected output cardinality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FourGraderBatchPlan {
    pub schema_version: u32,
    pub purpose: String,
    pub run_id: String,
    pub run_manifest_sha256: String,
    pub config_sha256: String,
    pub goldset_sha256: String,
    pub operator_anchor_binding_sha256: String,
    pub operator_anchor_sha256: String,
    pub operator_anchor_link_sha256: String,
    pub candidate_manifest_sha256: String,
    pub candidate_receipt_sha256: String,
    pub candidate_receipt_pubkey_sha256: String,
    pub candidate_vector_sha256: String,
    pub items: Vec<FourGraderBatchItem>,
    pub gate_eligible: bool,
}

/// Stable operator export: the digest is over `plan.canonical_bytes()`, i.e.
/// precisely the immutable bytes a result signer must bind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FourGraderBatchPlanExport {
    pub batch_plan_sha256: String,
    pub plan: FourGraderBatchPlan,
    pub gate_eligible: bool,
}

impl FourGraderBatchPlan {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).context("serialize canonical four-grader batch plan")
    }

    pub fn canonical_sha256(&self) -> Result<String> {
        Ok(hex::encode(Sha256::digest(self.canonical_bytes()?)))
    }

    pub fn export(&self) -> Result<FourGraderBatchPlanExport> {
        Ok(FourGraderBatchPlanExport {
            batch_plan_sha256: self.canonical_sha256()?,
            plan: self.clone(),
            gate_eligible: false,
        })
    }
}

/// Exact external result bytes admitted by a batch receipt. This is distinct
/// from the later full-import receipt that the existing report path requires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FourGraderBatchResultArtifact {
    pub grader_id: String,
    pub result_sha256: String,
    pub record_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FourGraderBatchResultReceiptBody {
    pub schema_version: u32,
    pub purpose: String,
    pub run_id: String,
    pub run_manifest_sha256: String,
    pub batch_plan_sha256: String,
    pub results: Vec<FourGraderBatchResultArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedFourGraderBatchResultReceipt {
    pub body: FourGraderBatchResultReceiptBody,
    pub signature_b64: String,
}

impl SignedFourGraderBatchResultReceipt {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&self.body)
            .context("serialize canonical four-grader batch result receipt")
    }

    pub fn validate_shape(&self) -> Result<()> {
        if self.body.schema_version != FOUR_GRADER_BATCH_SCHEMA_VERSION
            || self.body.purpose != FOUR_GRADER_BATCH_RESULT_RECEIPT_PURPOSE
        {
            anyhow::bail!("unsupported four-grader batch result receipt schema or purpose");
        }
        validate_run_id(&self.body.run_id)?;
        validate_sha256(
            &self.body.run_manifest_sha256,
            "batch result receipt manifest",
        )?;
        validate_sha256(&self.body.batch_plan_sha256, "batch result receipt plan")?;
        validate_result_artifacts(&self.body.results)?;
        if self.signature_b64.is_empty()
            || self.signature_b64.len() > MAX_FOUR_GRADER_SIGNATURE_BYTES
            || self
                .signature_b64
                .bytes()
                .any(|byte| byte.is_ascii_whitespace())
        {
            anyhow::bail!(
                "four-grader batch result receipt signature must be bounded non-whitespace base64"
            );
        }
        Ok(())
    }

    pub fn verify(&self, expected_pubkey_b64: &str) -> Result<()> {
        self.validate_shape()?;
        if expected_pubkey_b64.is_empty()
            || expected_pubkey_b64.len() > MAX_FOUR_GRADER_PUBKEY_BYTES
            || expected_pubkey_b64
                .bytes()
                .any(|byte| byte.is_ascii_whitespace())
        {
            anyhow::bail!(
                "expected batch result receipt public key must be bounded non-whitespace base64"
            );
        }
        crate::wal::signing::verify_b64(
            expected_pubkey_b64,
            &self.signature_b64,
            &self.canonical_bytes()?,
        )
        .context("four-grader batch result receipt signature verification failed")
    }
}

pub fn parse_four_grader_input_digests(bytes: &[u8]) -> Result<FourGraderInputDigestFile> {
    if bytes.len() > MAX_FOUR_GRADER_BATCH_BYTES {
        anyhow::bail!("four-grader input digest file exceeds bounded byte limit");
    }
    let value: FourGraderInputDigestFile = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("parse four-grader input digest file"))?;
    validate_input_digest_file(&value)?;
    Ok(value)
}

pub fn parse_signed_four_grader_batch_result_receipt(
    bytes: &[u8],
) -> Result<SignedFourGraderBatchResultReceipt> {
    if bytes.len() > MAX_FOUR_GRADER_BATCH_BYTES {
        anyhow::bail!("four-grader batch result receipt exceeds bounded byte limit");
    }
    let receipt: SignedFourGraderBatchResultReceipt = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("parse four-grader batch result receipt"))?;
    receipt.validate_shape()?;
    Ok(receipt)
}

pub fn validate_input_digest_file(value: &FourGraderInputDigestFile) -> Result<()> {
    if value.schema_version != FOUR_GRADER_BATCH_SCHEMA_VERSION
        || value.purpose != FOUR_GRADER_BATCH_INPUT_PURPOSE
    {
        anyhow::bail!("unsupported four-grader input digest schema or purpose");
    }
    if value.inputs.len() != FOUR_GRADER_COUNT {
        anyhow::bail!("four-grader batch input digests must contain exactly four graders");
    }
    let mut prior: Option<&str> = None;
    for input in &value.inputs {
        validate_id(&input.grader_id, "batch input grader")?;
        validate_sha256(&input.prompt_sha256, "batch prompt")?;
        validate_sha256(&input.input_sha256, "batch input")?;
        if prior.is_some_and(|previous| previous >= input.grader_id.as_str()) {
            anyhow::bail!("four-grader batch inputs must be strictly sorted by unique grader_id");
        }
        prior = Some(&input.grader_id);
    }
    Ok(())
}

pub fn validate_plan_shape(plan: &FourGraderBatchPlan) -> Result<()> {
    if plan.schema_version != FOUR_GRADER_BATCH_SCHEMA_VERSION
        || plan.purpose != FOUR_GRADER_BATCH_PLAN_PURPOSE
        || plan.gate_eligible
    {
        anyhow::bail!("four-grader batch plan is not a supported non-gate plan");
    }
    validate_run_id(&plan.run_id)?;
    for (value, label) in [
        (&plan.run_manifest_sha256, "batch plan manifest"),
        (&plan.config_sha256, "batch plan config"),
        (&plan.goldset_sha256, "batch plan goldset"),
        (
            &plan.operator_anchor_binding_sha256,
            "batch plan anchor binding",
        ),
        (&plan.operator_anchor_sha256, "batch plan anchor"),
        (&plan.operator_anchor_link_sha256, "batch plan anchor link"),
        (
            &plan.candidate_manifest_sha256,
            "batch plan candidate manifest",
        ),
        (
            &plan.candidate_receipt_sha256,
            "batch plan candidate receipt",
        ),
        (
            &plan.candidate_receipt_pubkey_sha256,
            "batch plan candidate receipt public key",
        ),
        (&plan.candidate_vector_sha256, "batch plan candidate vector"),
    ] {
        validate_sha256(value, label)?;
    }
    if plan.items.len() != FOUR_GRADER_COUNT {
        anyhow::bail!("four-grader batch plan must contain exactly four items");
    }
    let mut prior: Option<&str> = None;
    for item in &plan.items {
        validate_id(&item.grader_id, "batch plan grader")?;
        validate_model_id(&item.model_id)?;
        validate_sha256(&item.grader_config_sha256, "batch grader config")?;
        validate_sha256(&item.prompt_sha256, "batch prompt")?;
        validate_sha256(&item.input_sha256, "batch input")?;
        if item.provider.is_empty()
            || item.provider.len() > 64
            || item.family.is_empty()
            || item.family.len() > 64
            || item.expected_record_count == 0
            || item.expected_record_count > 512
        {
            anyhow::bail!("four-grader batch plan item is outside bounded contract");
        }
        if prior.is_some_and(|previous| previous >= item.grader_id.as_str()) {
            anyhow::bail!(
                "four-grader batch plan items must be strictly sorted by unique grader_id"
            );
        }
        prior = Some(&item.grader_id);
    }
    Ok(())
}

fn validate_result_artifacts(results: &[FourGraderBatchResultArtifact]) -> Result<()> {
    if results.len() != FOUR_GRADER_COUNT {
        anyhow::bail!("four-grader batch result receipt must bind exactly four result artifacts");
    }
    let mut prior: Option<&str> = None;
    for result in results {
        validate_id(&result.grader_id, "batch result grader")?;
        validate_sha256(&result.result_sha256, "batch result")?;
        if result.record_count == 0 || result.record_count > 512 {
            anyhow::bail!("four-grader batch result record count is outside bounded contract");
        }
        if prior.is_some_and(|previous| previous >= result.grader_id.as_str()) {
            anyhow::bail!("four-grader batch results must be strictly sorted by unique grader_id");
        }
        prior = Some(&result.grader_id);
    }
    Ok(())
}

fn validate_id(value: &str, label: &str) -> Result<()> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 64
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        anyhow::bail!("{label} is not canonical");
    }
    Ok(())
}

/// Mirror the already validated roster's model-id domain exactly. A batch plan
/// is a projection of `ValidatedGraderConfigFile`, so it must not reject a
/// provider-qualified model identifier the roster has already accepted.
fn validate_model_id(value: &str) -> Result<()> {
    let trimmed = value.trim();
    if value != trimmed
        || !(1..=128).contains(&trimmed.len())
        || !value.as_bytes().iter().any(u8::is_ascii_alphanumeric)
        || value.as_bytes().iter().any(u8::is_ascii_control)
        || !value.as_bytes().iter().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':' | b'@' | b'+')
        })
    {
        anyhow::bail!("batch plan model id is not within the validated roster domain");
    }
    Ok(())
}
