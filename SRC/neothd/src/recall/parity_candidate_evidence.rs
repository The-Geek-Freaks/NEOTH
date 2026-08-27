//! GOLD-LF-P1-08 — bounded transcript/WAL candidate-evidence intake.
//!
//! A miner outside this process may reduce a transcript or WAL export to opaque
//! candidate spans. This module verifies that imported evidence bundle without
//! exposing its raw content: every span is checked against the exact bounded
//! source bytes and every report is explicitly **not gate eligible**. An
//! operator must turn a selected span into a separately reviewed goldset entry
//! before it can reach any recall-parity scorer.

use std::{collections::BTreeSet, ffi::OsStr, path::Path};

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const MANIFEST_FILE: &str = "candidate-evidence-manifest.json";
const SOURCE_FILE: &str = "source.evidence";
const CANDIDATES_FILE: &str = "candidates.jsonl";
const RECEIPT_FILE: &str = "candidate-evidence-receipt.json";

/// Wire format version for an imported transcript/WAL candidate bundle.
pub const CANDIDATE_EVIDENCE_SCHEMA_VERSION: u32 = 1;
/// Domain-separation string for candidate-evidence manifests.
pub const CANDIDATE_EVIDENCE_PURPOSE: &str = "neoth-recall-parity-candidate-evidence/v1";
pub const CANDIDATE_EVIDENCE_RECEIPT_SCHEMA_VERSION: u32 = 1;
pub const CANDIDATE_EVIDENCE_RECEIPT_PURPOSE: &str =
    "neoth-recall-parity-candidate-evidence-receipt/v1";
/// A source export is intentionally capped: this is a review queue, never a
/// general transcript/WAL ingestion path.
pub const MAX_CANDIDATE_SOURCE_BYTES: usize = 32 * 1024 * 1024;
/// Candidate metadata is much smaller than the source export it traces.
pub const MAX_CANDIDATE_RECORD_BYTES: usize = 1024 * 1024;
pub const MAX_CANDIDATE_RECORDS: usize = 512;
pub const MAX_CANDIDATE_EVIDENCE_RECEIPT_BYTES: usize = 64 * 1024;
pub const MAX_CANDIDATE_EVIDENCE_SIGNATURE_BYTES: usize = 256;
pub const MAX_CANDIDATE_EVIDENCE_PUBKEY_BYTES: usize = 128;

/// The imported source class. It is provenance metadata, not a capability to
/// open a daemon transcript or WAL itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateEvidenceSourceKind {
    TranscriptExport,
    WalExport,
}

/// The fixed-name manifest binds the unrendered raw source and candidate JSONL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateEvidenceManifest {
    pub schema_version: u32,
    pub purpose: String,
    pub bundle_id: String,
    pub source_kind: CandidateEvidenceSourceKind,
    pub source_sha256: String,
    pub source_bytes: usize,
    pub candidates_sha256: String,
    pub candidate_count: usize,
}

/// One opaque span selected by the external candidate miner. No prompt,
/// response, transcript text, WAL payload, event ID, or credential-bearing
/// field is permitted on this wire type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinedCandidate {
    pub candidate_id: String,
    pub source_offset: usize,
    pub source_len: usize,
    pub source_span_sha256: String,
}

/// Externally signed assertion over the complete imported bundle identity. The
/// expected key is never read from mutable evidence state; it is supplied out
/// of band by the caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateEvidenceReceiptBody {
    pub schema_version: u32,
    pub purpose: String,
    pub bundle_id: String,
    pub manifest_sha256: String,
    pub source_kind: CandidateEvidenceSourceKind,
    pub source_sha256: String,
    pub source_bytes: usize,
    pub candidates_sha256: String,
    pub candidate_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCandidateEvidenceReceipt {
    pub body: CandidateEvidenceReceiptBody,
    pub signature_b64: String,
}

impl SignedCandidateEvidenceReceipt {
    /// Exact stable UTF-8 bytes covered by the detached Ed25519 signature.
    /// External candidate miners/signers must sign these bytes, not a freshly
    /// pretty-printed or map-reordered rendering of the receipt body.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&self.body)
            .context("serialize canonical candidate evidence receipt body")
    }

    fn validate_shape(&self) -> Result<()> {
        let body = &self.body;
        if body.schema_version != CANDIDATE_EVIDENCE_RECEIPT_SCHEMA_VERSION {
            anyhow::bail!("unsupported candidate evidence receipt schema version");
        }
        if body.purpose != CANDIDATE_EVIDENCE_RECEIPT_PURPOSE {
            anyhow::bail!("unexpected candidate evidence receipt purpose");
        }
        if !is_valid_id(&body.bundle_id) {
            anyhow::bail!("candidate evidence receipt bundle_id is not canonical");
        }
        validate_sha256(
            &body.manifest_sha256,
            "candidate evidence receipt manifest_sha256",
        )?;
        validate_sha256(
            &body.source_sha256,
            "candidate evidence receipt source_sha256",
        )?;
        validate_sha256(
            &body.candidates_sha256,
            "candidate evidence receipt candidates_sha256",
        )?;
        if body.source_bytes == 0
            || body.source_bytes > MAX_CANDIDATE_SOURCE_BYTES
            || body.candidate_count == 0
            || body.candidate_count > MAX_CANDIDATE_RECORDS
        {
            anyhow::bail!(
                "candidate evidence receipt exceeds bounded source or candidate contract"
            );
        }
        if self.signature_b64.is_empty()
            || self.signature_b64.len() > MAX_CANDIDATE_EVIDENCE_SIGNATURE_BYTES
            || self
                .signature_b64
                .bytes()
                .any(|byte| byte.is_ascii_whitespace())
        {
            anyhow::bail!(
                "candidate evidence receipt signature must be bounded non-whitespace base64"
            );
        }
        Ok(())
    }

    fn verify(&self, expected_pubkey_b64: &str) -> Result<()> {
        self.validate_shape()?;
        if expected_pubkey_b64.is_empty()
            || expected_pubkey_b64.len() > MAX_CANDIDATE_EVIDENCE_PUBKEY_BYTES
            || expected_pubkey_b64
                .bytes()
                .any(|byte| byte.is_ascii_whitespace())
        {
            anyhow::bail!(
                "expected candidate evidence public key must be bounded non-whitespace base64"
            );
        }
        crate::wal::signing::verify_b64(
            expected_pubkey_b64,
            &self.signature_b64,
            &self.canonical_bytes()?,
        )
        .context("candidate evidence receipt signature verification failed")
    }
}

/// Validated imported evidence. Raw source bytes are intentionally discarded
/// after span verification so callers cannot accidentally render them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedCandidateEvidence {
    manifest: CandidateEvidenceManifest,
    candidates: Vec<MinedCandidate>,
    manifest_sha256: String,
    receipt_sha256: String,
    manifest_bytes: Vec<u8>,
    receipt_bytes: Vec<u8>,
    candidate_bytes: Vec<u8>,
    expected_receipt_pubkey_b64: String,
    expected_receipt_pubkey_sha256: String,
}

impl ValidatedCandidateEvidence {
    pub fn manifest(&self) -> &CandidateEvidenceManifest {
        &self.manifest
    }

    pub fn candidates(&self) -> &[MinedCandidate] {
        &self.candidates
    }

    /// Digest of the exact signed manifest bytes read through the retained
    /// capability. This is safe provenance metadata, never raw source content.
    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    /// Digest of the exact signed receipt bytes. Persisting this lets a later
    /// operator-review binding retain the verified evidence identity alongside
    /// a separately persisted immutable receipt copy, never mutable run state.
    pub fn receipt_sha256(&self) -> &str {
        &self.receipt_sha256
    }

    /// Exact, already verified manifest bytes. The manifest carries metadata
    /// and hashes only, never raw transcript/WAL source bytes.
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }

    /// Exact detached receipt bytes. Keeping this allows a run-local immutable
    /// provenance copy without retaining raw source data or a signing key.
    pub fn receipt_bytes(&self) -> &[u8] {
        &self.receipt_bytes
    }

    /// Exact candidate vector bytes already bound by the signed manifest. The
    /// vector is opaque metadata (IDs, offsets, lengths, hashes), never raw
    /// transcript/WAL source data.
    pub fn candidate_bytes(&self) -> &[u8] {
        &self.candidate_bytes
    }

    /// Canonical base64 encoding of the explicit, decoded Ed25519 public key
    /// used to verify the receipt. This public value is retained only so a
    /// bound run can re-verify its immutable receipt on every reopen.
    pub fn expected_receipt_pubkey_b64(&self) -> &str {
        &self.expected_receipt_pubkey_b64
    }

    /// SHA-256 fingerprint of the canonical decoded expected Ed25519 public
    /// key used for this verification. It is safe trust-anchor provenance.
    pub fn expected_receipt_pubkey_sha256(&self) -> &str {
        &self.expected_receipt_pubkey_sha256
    }
}

/// Safe report projection. The raw source and candidate spans are never
/// serializable through this report; the report is a review-queue receipt only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CandidateEvidenceSummary {
    pub schema_version: u32,
    pub bundle_id: String,
    pub source_kind: CandidateEvidenceSourceKind,
    pub source_sha256: String,
    pub source_bytes: usize,
    pub candidates_sha256: String,
    pub candidate_count: usize,
    pub evidence_receipt_verified: bool,
    pub operator_labeling_required: bool,
    pub gate_eligible: bool,
}

/// Revalidated, raw-free candidate membership recovered from immutable run
/// artifacts. The run retains the canonical public verification key separately
/// from this metadata, so every reopen can re-check the detached signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PersistedCandidateEvidenceMetadata {
    candidate_ids: Vec<String>,
}

impl PersistedCandidateEvidenceMetadata {
    pub(crate) fn candidate_ids(&self) -> &[String] {
        &self.candidate_ids
    }
}

/// Capability-bound imported evidence namespace. Its directory is bound once
/// from the caller-selected trusted anchor; all three artifact reads remain
/// handle-relative and no source path is reopened after that point.
struct BoundCandidateEvidence {
    root: crate::skills::store::BoundDirectory,
}

impl BoundCandidateEvidence {
    fn open(evidence_dir: &Path) -> Result<Self> {
        let anchor = evidence_dir
            .parent()
            .context("candidate evidence directory has no trusted parent")?;
        let root = crate::skills::store::open_bound_directory_from_trusted_anchor(
            anchor,
            evidence_dir,
            false,
            "recall candidate evidence",
        )?
        .context("candidate evidence directory is absent")?;
        Ok(Self { root })
    }

    fn read_child(&self, name: &str, max_bytes: usize) -> Result<Vec<u8>> {
        crate::skills::store::read_regular_file_bounded(
            &self.root.dir,
            OsStr::new(name),
            &self.root.display_path.join(name),
            max_bytes,
        )
    }
}

/// Consume an explicitly imported candidate-evidence bundle through a bounded,
/// no-follow directory capability. This function is read-only: it never opens
/// a WAL/transcript path beyond the imported bundle, changes receipts, or
/// writes an evaluation artifact.
pub fn load_imported_candidate_evidence(
    evidence_dir: &Path,
    expected_receipt_pubkey_b64: &str,
) -> Result<ValidatedCandidateEvidence> {
    let bundle = BoundCandidateEvidence::open(evidence_dir)?;
    let manifest_bytes = bundle.read_child(MANIFEST_FILE, MAX_CANDIDATE_RECORD_BYTES)?;
    let manifest: CandidateEvidenceManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|_| anyhow::anyhow!("parse candidate evidence manifest"))?;
    validate_manifest(&manifest)?;
    let receipt_bytes = bundle.read_child(RECEIPT_FILE, MAX_CANDIDATE_EVIDENCE_RECEIPT_BYTES)?;
    let receipt: SignedCandidateEvidenceReceipt = serde_json::from_slice(&receipt_bytes)
        .map_err(|_| anyhow::anyhow!("parse candidate evidence receipt"))?;
    validate_receipt_for_manifest(
        &receipt,
        &manifest,
        &manifest_bytes,
        expected_receipt_pubkey_b64,
    )?;
    let (expected_receipt_pubkey_b64, expected_receipt_pubkey_sha256) =
        canonical_receipt_pubkey(expected_receipt_pubkey_b64)?;

    let source = bundle.read_child(SOURCE_FILE, MAX_CANDIDATE_SOURCE_BYTES)?;
    if source.len() != manifest.source_bytes || sha256_bytes(&source) != manifest.source_sha256 {
        anyhow::bail!("candidate evidence source bytes do not match manifest provenance");
    }

    let candidate_bytes = bundle.read_child(CANDIDATES_FILE, MAX_CANDIDATE_RECORD_BYTES)?;
    if sha256_bytes(&candidate_bytes) != manifest.candidates_sha256 {
        anyhow::bail!("candidate evidence JSONL does not match manifest SHA256");
    }
    let candidates = parse_candidates(&candidate_bytes)?;
    if candidates.len() != manifest.candidate_count {
        anyhow::bail!("candidate evidence manifest count does not match parsed candidate records");
    }
    validate_candidate_spans(&candidates, &source)?;

    Ok(ValidatedCandidateEvidence {
        manifest,
        candidates,
        manifest_sha256: sha256_bytes(&manifest_bytes),
        receipt_sha256: sha256_bytes(&receipt_bytes),
        manifest_bytes,
        receipt_bytes,
        candidate_bytes,
        expected_receipt_pubkey_b64,
        expected_receipt_pubkey_sha256,
    })
}

pub fn summarize_candidate_evidence(
    evidence: &ValidatedCandidateEvidence,
) -> CandidateEvidenceSummary {
    let manifest = evidence.manifest();
    CandidateEvidenceSummary {
        schema_version: manifest.schema_version,
        bundle_id: manifest.bundle_id.clone(),
        source_kind: manifest.source_kind,
        source_sha256: manifest.source_sha256.clone(),
        source_bytes: manifest.source_bytes,
        candidates_sha256: manifest.candidates_sha256.clone(),
        candidate_count: evidence.candidates().len(),
        evidence_receipt_verified: true,
        // Candidate evidence deliberately lacks query/response/operator-label
        // fields. It cannot become a goldset or scorer input by serialization.
        operator_labeling_required: true,
        gate_eligible: false,
    }
}

fn validate_receipt_for_manifest(
    receipt: &SignedCandidateEvidenceReceipt,
    manifest: &CandidateEvidenceManifest,
    manifest_bytes: &[u8],
    expected_pubkey_b64: &str,
) -> Result<()> {
    receipt.verify(expected_pubkey_b64)?;
    validate_receipt_matches_manifest(receipt, manifest, manifest_bytes)
}

fn validate_receipt_matches_manifest(
    receipt: &SignedCandidateEvidenceReceipt,
    manifest: &CandidateEvidenceManifest,
    manifest_bytes: &[u8],
) -> Result<()> {
    let body = &receipt.body;
    if body.manifest_sha256 != sha256_bytes(manifest_bytes)
        || body.bundle_id != manifest.bundle_id
        || body.source_kind != manifest.source_kind
        || body.source_sha256 != manifest.source_sha256
        || body.source_bytes != manifest.source_bytes
        || body.candidates_sha256 != manifest.candidates_sha256
        || body.candidate_count != manifest.candidate_count
    {
        anyhow::bail!("signed candidate evidence receipt does not exactly bind this manifest");
    }
    Ok(())
}

/// Revalidate the immutable metadata retained by an anchor-ingested run. This
/// intentionally does not retain or reopen `source.evidence`; the original
/// intake verified every span against that raw source before persistence, while
/// the run preserves only the signature-bound candidate membership vector.
pub(crate) fn validate_persisted_candidate_evidence_metadata(
    manifest_bytes: &[u8],
    receipt_bytes: &[u8],
    candidate_bytes: &[u8],
    expected_receipt_pubkey_b64: &str,
    expected_manifest_sha256: &str,
    expected_receipt_sha256: &str,
    expected_receipt_pubkey_sha256: &str,
) -> Result<PersistedCandidateEvidenceMetadata> {
    validate_sha256(expected_manifest_sha256, "persisted candidate manifest")?;
    validate_sha256(expected_receipt_sha256, "persisted candidate receipt")?;
    validate_sha256(
        expected_receipt_pubkey_sha256,
        "persisted candidate receipt public key",
    )?;
    if sha256_bytes(manifest_bytes) != expected_manifest_sha256
        || sha256_bytes(receipt_bytes) != expected_receipt_sha256
    {
        anyhow::bail!("persisted candidate evidence metadata does not match run binding hashes");
    }
    let manifest: CandidateEvidenceManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|_| anyhow::anyhow!("parse persisted candidate evidence manifest"))?;
    validate_manifest(&manifest)?;
    let receipt: SignedCandidateEvidenceReceipt = serde_json::from_slice(receipt_bytes)
        .map_err(|_| anyhow::anyhow!("parse persisted candidate evidence receipt"))?;
    receipt.validate_shape()?;
    let (_, actual_receipt_pubkey_sha256) = canonical_receipt_pubkey(expected_receipt_pubkey_b64)?;
    if actual_receipt_pubkey_sha256 != expected_receipt_pubkey_sha256 {
        anyhow::bail!("persisted candidate receipt public key does not match run binding hash");
    }
    receipt.verify(expected_receipt_pubkey_b64)?;
    validate_receipt_matches_manifest(&receipt, &manifest, manifest_bytes)?;
    if sha256_bytes(candidate_bytes) != manifest.candidates_sha256 {
        anyhow::bail!("persisted candidate vector does not match signed manifest SHA256");
    }
    let candidates = parse_candidates(candidate_bytes)?;
    if candidates.len() != manifest.candidate_count {
        anyhow::bail!("persisted candidate vector count does not match signed manifest");
    }
    Ok(PersistedCandidateEvidenceMetadata {
        candidate_ids: candidates
            .into_iter()
            .map(|candidate| candidate.candidate_id)
            .collect(),
    })
}

fn canonical_receipt_pubkey(expected_pubkey_b64: &str) -> Result<(String, String)> {
    let bytes = STANDARD.decode(expected_pubkey_b64).map_err(|_| {
        anyhow::anyhow!("expected candidate evidence public key is not valid base64")
    })?;
    if bytes.len() != 32 {
        anyhow::bail!("expected candidate evidence public key has an invalid Ed25519 length");
    }
    Ok((STANDARD.encode(&bytes), sha256_bytes(&bytes)))
}

fn validate_manifest(manifest: &CandidateEvidenceManifest) -> Result<()> {
    if manifest.schema_version != CANDIDATE_EVIDENCE_SCHEMA_VERSION {
        anyhow::bail!(
            "unsupported candidate evidence schema {}; expected {}",
            manifest.schema_version,
            CANDIDATE_EVIDENCE_SCHEMA_VERSION
        );
    }
    if manifest.purpose != CANDIDATE_EVIDENCE_PURPOSE {
        anyhow::bail!(
            "candidate evidence manifest purpose is not the P1-08 candidate-evidence domain"
        );
    }
    if !is_valid_id(&manifest.bundle_id) {
        anyhow::bail!("candidate evidence bundle_id is not canonical");
    }
    validate_sha256(&manifest.source_sha256, "candidate evidence source_sha256")?;
    validate_sha256(
        &manifest.candidates_sha256,
        "candidate evidence candidates_sha256",
    )?;
    if manifest.source_bytes == 0 || manifest.source_bytes > MAX_CANDIDATE_SOURCE_BYTES {
        anyhow::bail!("candidate evidence source_bytes exceeds the bounded source contract");
    }
    if manifest.candidate_count == 0 || manifest.candidate_count > MAX_CANDIDATE_RECORDS {
        anyhow::bail!("candidate evidence candidate_count exceeds the bounded record contract");
    }
    Ok(())
}

fn parse_candidates(bytes: &[u8]) -> Result<Vec<MinedCandidate>> {
    let text = std::str::from_utf8(bytes).context("decode candidate evidence JSONL as UTF-8")?;
    let mut candidates = Vec::new();
    let mut prior_id: Option<String> = None;
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if candidates.len() >= MAX_CANDIDATE_RECORDS {
            anyhow::bail!("candidate evidence exceeds the {MAX_CANDIDATE_RECORDS}-record limit");
        }
        let candidate: MinedCandidate = serde_json::from_str(line)
            .map_err(|_| anyhow::anyhow!("parse candidate evidence line {}", index + 1))?;
        if !is_valid_id(&candidate.candidate_id) {
            anyhow::bail!(
                "candidate evidence line {} has noncanonical candidate_id",
                index + 1
            );
        }
        validate_sha256(
            &candidate.source_span_sha256,
            "candidate evidence source_span_sha256",
        )?;
        if candidate.source_len == 0 {
            anyhow::bail!(
                "candidate evidence line {} has an empty source span",
                index + 1
            );
        }
        if prior_id
            .as_deref()
            .is_some_and(|previous| candidate.candidate_id.as_str() <= previous)
        {
            anyhow::bail!(
                "candidate evidence records must be strictly sorted by unique candidate_id"
            );
        }
        prior_id = Some(candidate.candidate_id.clone());
        candidates.push(candidate);
    }
    if candidates.is_empty() {
        anyhow::bail!("candidate evidence contains no candidate records");
    }
    Ok(candidates)
}

fn validate_candidate_spans(candidates: &[MinedCandidate], source: &[u8]) -> Result<()> {
    let mut ranges = BTreeSet::new();
    for candidate in candidates {
        let end = candidate
            .source_offset
            .checked_add(candidate.source_len)
            .context("candidate source span overflow")?;
        let span = source
            .get(candidate.source_offset..end)
            .context("candidate source span lies outside imported source bytes")?;
        if sha256_bytes(span) != candidate.source_span_sha256 {
            anyhow::bail!("candidate source span SHA256 does not match imported source bytes");
        }
        if !ranges.insert((candidate.source_offset, end)) {
            anyhow::bail!("candidate evidence contains a duplicate source span");
        }
    }
    Ok(())
}

fn is_valid_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn validate_sha256(value: &str, field: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        anyhow::bail!("{field} must be exactly 64 lowercase hexadecimal characters");
    }
    Ok(())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recall::{
        goldset::{
            GoldsetCategory, GoldsetEntry, GradedSystem, GraderConfig, GraderConfigFile,
            GraderFamily, GraderGrade, GraderProvider,
        },
        parity_anchor::{
            OPERATOR_ANCHOR_EVIDENCE_LINK_PURPOSE, OPERATOR_ANCHOR_EVIDENCE_LINK_SCHEMA_VERSION,
            OPERATOR_ANCHOR_GRADER_ID, OperatorAnchorCandidateLink, OperatorAnchorEvidenceLink,
            load_operator_anchor_bytes, load_operator_anchor_evidence_link_bytes,
        },
    };

    fn candidate(id: &str, source: &[u8], offset: usize, len: usize) -> MinedCandidate {
        MinedCandidate {
            candidate_id: id.into(),
            source_offset: offset,
            source_len: len,
            source_span_sha256: sha256_bytes(&source[offset..offset + len]),
        }
    }

    fn bundle(
        source: &[u8],
        candidates: &[MinedCandidate],
    ) -> (CandidateEvidenceManifest, Vec<u8>) {
        let candidate_bytes = candidates
            .iter()
            .map(|candidate| serde_json::to_string(candidate).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes();
        (
            CandidateEvidenceManifest {
                schema_version: CANDIDATE_EVIDENCE_SCHEMA_VERSION,
                purpose: CANDIDATE_EVIDENCE_PURPOSE.into(),
                bundle_id: "bundle-1".into(),
                source_kind: CandidateEvidenceSourceKind::TranscriptExport,
                source_sha256: sha256_bytes(source),
                source_bytes: source.len(),
                candidates_sha256: sha256_bytes(&candidate_bytes),
                candidate_count: candidates.len(),
            },
            candidate_bytes,
        )
    }

    fn anchor_goldset() -> Vec<GoldsetEntry> {
        (0..100)
            .map(|index| GoldsetEntry {
                query_id: format!("q{index:03}"),
                query_text: "q".into(),
                category: GoldsetCategory::Recall,
                expected_sources: vec![],
                expected_response: String::new(),
            })
            .collect()
    }

    fn anchor_config() -> crate::recall::goldset::ValidatedGraderConfigFile {
        GraderConfigFile {
            schema_version: 1,
            graders: vec![
                GraderConfig {
                    grader_id: "shared".into(),
                    provider: GraderProvider::Anthropic,
                    model_id: "shared".into(),
                    family: GraderFamily::AnthropicOpenaiGoogle,
                },
                GraderConfig {
                    grader_id: "external".into(),
                    provider: GraderProvider::Mistral,
                    model_id: "external".into(),
                    family: GraderFamily::IndependentExternal,
                },
            ],
        }
        .into_validated()
        .unwrap()
    }

    fn operator_anchor_bytes() -> Vec<u8> {
        (0..20)
            .flat_map(|index| {
                [GradedSystem::Neoth, GradedSystem::Reference].map(|system| GraderGrade {
                    query_id: format!("q{index:03}"),
                    grader_id: OPERATOR_ANCHOR_GRADER_ID.into(),
                    system,
                    factual: 3,
                    completeness: 3,
                    on_tone: 3,
                    usefulness: 3,
                    brevity: 3,
                })
            })
            .map(|grade| serde_json::to_string(&grade).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes()
    }

    fn signed_receipt(
        manifest: &CandidateEvidenceManifest,
        manifest_bytes: &[u8],
    ) -> (SignedCandidateEvidenceReceipt, String) {
        let key = ed25519_dalek::SigningKey::from_bytes(&[31; 32]);
        let mut receipt = SignedCandidateEvidenceReceipt {
            body: CandidateEvidenceReceiptBody {
                schema_version: CANDIDATE_EVIDENCE_RECEIPT_SCHEMA_VERSION,
                purpose: CANDIDATE_EVIDENCE_RECEIPT_PURPOSE.into(),
                bundle_id: manifest.bundle_id.clone(),
                manifest_sha256: sha256_bytes(manifest_bytes),
                source_kind: manifest.source_kind,
                source_sha256: manifest.source_sha256.clone(),
                source_bytes: manifest.source_bytes,
                candidates_sha256: manifest.candidates_sha256.clone(),
                candidate_count: manifest.candidate_count,
            },
            signature_b64: String::new(),
        };
        receipt.signature_b64 =
            crate::wal::signing::sign_b64(&key, &receipt.canonical_bytes().unwrap());
        (receipt, crate::wal::signing::pubkey_b64(&key))
    }

    #[test]
    fn parsed_candidate_bundle_discards_raw_content_from_summary() {
        let source = b"operator secret is only in raw source";
        let candidates = vec![candidate("cand-1", source, 0, source.len())];
        let (manifest, candidate_bytes) = bundle(source, &candidates);
        validate_manifest(&manifest).unwrap();
        let parsed = parse_candidates(&candidate_bytes).unwrap();
        validate_candidate_spans(&parsed, source).unwrap();
        let summary = summarize_candidate_evidence(&ValidatedCandidateEvidence {
            manifest,
            candidates: parsed,
            manifest_sha256: "a".repeat(64),
            receipt_sha256: "b".repeat(64),
            manifest_bytes: Vec::new(),
            receipt_bytes: Vec::new(),
            candidate_bytes: Vec::new(),
            expected_receipt_pubkey_b64: String::new(),
            expected_receipt_pubkey_sha256: "c".repeat(64),
        });
        let rendered = serde_json::to_string(&summary).unwrap();
        assert!(!rendered.contains("operator secret"));
        assert!(summary.operator_labeling_required);
        assert!(!summary.gate_eligible);
    }

    #[test]
    fn signed_receipt_rejects_bundle_substitution_and_sanitizes_parse_errors() {
        let source = b"operator secret is only in raw source";
        let candidates = vec![candidate("cand-1", source, 0, source.len())];
        let (manifest, _) = bundle(source, &candidates);
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let (receipt, public_key) = signed_receipt(&manifest, &manifest_bytes);
        validate_receipt_for_manifest(&receipt, &manifest, &manifest_bytes, &public_key).unwrap();

        let mut substituted = manifest.clone();
        substituted.bundle_id = "other-bundle".into();
        let substituted_bytes = serde_json::to_vec(&substituted).unwrap();
        assert!(
            validate_receipt_for_manifest(&receipt, &substituted, &substituted_bytes, &public_key)
                .is_err()
        );
        let error = serde_json::from_slice::<CandidateEvidenceManifest>(
            br#"{"schema_version":"TRANSCRIPT_SECRET"}"#,
        )
        .map_err(|_| anyhow::anyhow!("parse candidate evidence manifest"))
        .unwrap_err();
        assert!(!format!("{error:#}").contains("TRANSCRIPT_SECRET"));
    }

    #[test]
    fn candidate_evidence_receipt_public_payload_has_a_fixed_vector() {
        let source = b"0123456789";
        let candidates = vec![candidate("cand-a", source, 0, 2)];
        let (manifest, _) = bundle(source, &candidates);
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let (receipt, _) = signed_receipt(&manifest, &manifest_bytes);
        let expected = format!(
            "{{\"schema_version\":1,\"purpose\":\"{}\",\"bundle_id\":\"bundle-1\",\"manifest_sha256\":\"{}\",\"source_kind\":\"transcript_export\",\"source_sha256\":\"{}\",\"source_bytes\":10,\"candidates_sha256\":\"{}\",\"candidate_count\":1}}",
            CANDIDATE_EVIDENCE_RECEIPT_PURPOSE,
            sha256_bytes(&manifest_bytes),
            sha256_bytes(source),
            manifest.candidates_sha256,
        );
        assert_eq!(
            String::from_utf8(receipt.canonical_bytes().unwrap()).unwrap(),
            expected
        );
    }

    #[test]
    fn operator_link_requires_all_twenty_labels_and_verified_candidate_provenance() {
        let anchor_bytes = operator_anchor_bytes();
        let anchor = load_operator_anchor_bytes(
            &anchor_bytes,
            "fixture",
            &anchor_goldset(),
            &anchor_config(),
        )
        .unwrap();
        let evidence = ValidatedCandidateEvidence {
            manifest: CandidateEvidenceManifest {
                schema_version: CANDIDATE_EVIDENCE_SCHEMA_VERSION,
                purpose: CANDIDATE_EVIDENCE_PURPOSE.into(),
                bundle_id: "fixture-bundle".into(),
                source_kind: CandidateEvidenceSourceKind::TranscriptExport,
                source_sha256: "a".repeat(64),
                source_bytes: 100,
                candidates_sha256: "b".repeat(64),
                candidate_count: 20,
            },
            candidates: (0..20)
                .map(|index| MinedCandidate {
                    candidate_id: format!("cand-{index:03}"),
                    source_offset: index,
                    source_len: 1,
                    source_span_sha256: "c".repeat(64),
                })
                .collect(),
            manifest_sha256: "d".repeat(64),
            receipt_sha256: "e".repeat(64),
            manifest_bytes: Vec::new(),
            receipt_bytes: Vec::new(),
            candidate_bytes: Vec::new(),
            expected_receipt_pubkey_b64: String::new(),
            expected_receipt_pubkey_sha256: "f".repeat(64),
        };
        let link = OperatorAnchorEvidenceLink {
            schema_version: OPERATOR_ANCHOR_EVIDENCE_LINK_SCHEMA_VERSION,
            purpose: OPERATOR_ANCHOR_EVIDENCE_LINK_PURPOSE.into(),
            candidate_manifest_sha256: evidence.manifest_sha256().to_owned(),
            candidate_receipt_sha256: evidence.receipt_sha256().to_owned(),
            operator_anchor_sha256: sha256_bytes(&anchor_bytes),
            links: (0..20)
                .map(|index| OperatorAnchorCandidateLink {
                    query_id: format!("q{index:03}"),
                    candidate_id: format!("cand-{index:03}"),
                })
                .collect(),
        };
        let link_bytes = serde_json::to_vec(&link).unwrap();
        assert!(
            load_operator_anchor_evidence_link_bytes(
                &link_bytes,
                &anchor_bytes,
                &anchor,
                &evidence
            )
            .is_ok()
        );
        let mut incomplete = link;
        incomplete.links.pop();
        assert!(
            load_operator_anchor_evidence_link_bytes(
                &serde_json::to_vec(&incomplete).unwrap(),
                &anchor_bytes,
                &anchor,
                &evidence,
            )
            .is_err()
        );
    }

    #[test]
    fn span_hash_count_order_and_unknown_fields_fail_closed() {
        let source = b"0123456789";
        let candidates = vec![
            candidate("cand-b", source, 0, 2),
            candidate("cand-a", source, 2, 2),
        ];
        let (_, bytes) = bundle(source, &candidates);
        assert!(
            parse_candidates(&bytes).is_err(),
            "unsorted candidate IDs must fail"
        );

        let candidate = candidate("cand-a", source, 0, 2);
        let mut wrong_hash = candidate.clone();
        wrong_hash.source_span_sha256 = "0".repeat(64);
        assert!(validate_candidate_spans(&[wrong_hash], source).is_err());
        assert!(serde_json::from_str::<MinedCandidate>(r#"{"candidate_id":"cand-a","source_offset":0,"source_len":1,"source_span_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","raw_text":"forbidden"}"#).is_err());
    }
}
