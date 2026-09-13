//! Explicit local transcript selections and live custody revalidation.
//! A signed artifact preserves identity; current retained RAW/Bound proof is
//! still required every time that artifact is consumed.

use std::{ffi::OsStr, path::Path};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::memory::transcript_mining_runtime::AuthenticatedLocalTranscriptReader;
use crate::memory::transcript_mining_store::{
    AuthenticatedTranscriptProjection, TranscriptMiningFrameCustody,
};

use super::parity_candidate_evidence::{
    CANDIDATE_EVIDENCE_PURPOSE, CANDIDATE_EVIDENCE_RECEIPT_PURPOSE,
    CANDIDATE_EVIDENCE_RECEIPT_SCHEMA_VERSION, CANDIDATE_EVIDENCE_SCHEMA_VERSION,
    CandidateEvidenceManifest, CandidateEvidenceReceiptBody, CandidateEvidenceSourceKind,
    CandidateEvidenceSummary, MAX_CANDIDATE_RECORD_BYTES, MAX_CANDIDATE_RECORDS,
    MAX_CANDIDATE_SOURCE_BYTES, MinedCandidate, SignedCandidateEvidenceReceipt,
    load_candidate_evidence_with_context, summarize_candidate_evidence,
};

pub(crate) const MAX_LOCAL_CUSTODY_BYTES: usize = 1024 * 1024;
pub(crate) const LOCAL_CANDIDATE_EVIDENCE_CUSTODY_FILE: &str =
    "candidate-evidence-local-custody.json";
const CUSTODY_PURPOSE: &str = "neoth-local-transcript-candidate-custody/v1";

/// No serialization/Debug: the selected home and its authority are ephemeral.
pub(crate) struct CandidateEvidenceUseContext {
    reader: Option<AuthenticatedLocalTranscriptReader>,
}

impl CandidateEvidenceUseContext {
    pub(crate) const fn external_only() -> Self {
        Self { reader: None }
    }

    pub(crate) fn open(local_home: Option<&Path>) -> Result<Self> {
        match local_home {
            None => Ok(Self::external_only()),
            Some(home) => Ok(Self {
                reader: Some(
                    AuthenticatedLocalTranscriptReader::open_existing(home)?.context(
                        "local evidence requires an existing authenticated home and views database",
                    )?,
                ),
            }),
        }
    }

    fn reader(&self) -> Result<&AuthenticatedLocalTranscriptReader> {
        self.reader
            .as_ref()
            .context("local transcript evidence requires --local-evidence-home")
    }

    pub(crate) fn validate_local_custody(
        &self,
        bytes: &[u8],
        manifest: &CandidateEvidenceManifest,
        candidates: &[MinedCandidate],
    ) -> Result<()> {
        ensure!(
            manifest.source_kind
                == CandidateEvidenceSourceKind::AuthenticatedLocalTranscriptBoundV1,
            "local custody cannot authorize an imported source kind"
        );
        ensure!(
            bytes.len() <= MAX_LOCAL_CUSTODY_BYTES
                && manifest.local_custody_sha256.as_deref() == Some(sha256(bytes).as_str()),
            "local custody does not match the signed manifest"
        );
        let custody: LocalCandidateCustody = serde_json::from_slice(bytes)
            .map_err(|_| anyhow::anyhow!("parse closed local candidate custody"))?;
        ensure!(
            custody.schema_version == 1
                && custody.purpose == CUSTODY_PURPOSE
                && custody.bundle_id == manifest.bundle_id
                && custody.source_sha256 == manifest.source_sha256
                && custody.source_bytes == manifest.source_bytes
                && custody.candidates_sha256 == manifest.candidates_sha256
                && !custody.entries.is_empty()
                && custody.entries.len() <= MAX_CANDIDATE_RECORDS
                && custody.entries.len() == candidates.len()
                && custody.entries.len() == manifest.candidate_count,
            "local custody does not exactly bind this candidate vector"
        );
        let reader = self.reader()?;
        let version = reader.revalidation_token()?;
        let mut source = Sha256::new();
        let mut next_offset = 0usize;
        let mut earliest_expiry = i64::MAX;
        let mut latest_birth = i64::MIN;
        for (entry, candidate) in custody.entries.iter().zip(candidates) {
            ensure!(
                entry.candidate_id == candidate.candidate_id
                    && entry.source_offset == candidate.source_offset
                    && entry.source_len == candidate.source_len
                    && entry.source_span_sha256 == candidate.source_span_sha256
                    && entry.source_offset == next_offset
                    && entry.source_len > 0,
                "local custody candidate membership or byte ranges changed"
            );
            let projection = reader.read_active(&entry.provenance_id, MAX_CANDIDATE_SOURCE_BYTES)?
                .context("local transcript evidence is absent, expired, revoked or no longer authenticated")?;
            ensure!(
                entry.matches_projection(&projection),
                "local transcript custody no longer matches its authenticated source"
            );
            let span = selected_span(
                projection.operator_text(),
                entry.raw_offset,
                entry.source_len,
            )?;
            ensure!(
                sha256(span) == entry.source_span_sha256,
                "local candidate span no longer matches retained operator text"
            );
            next_offset = next_offset
                .checked_add(span.len())
                .context("local candidate source size overflow")?;
            ensure!(
                next_offset <= MAX_CANDIDATE_SOURCE_BYTES,
                "local candidate source exceeds its byte limit"
            );
            source.update(span);
            earliest_expiry = earliest_expiry.min(projection.expires_at_unix());
            latest_birth = latest_birth.max(projection.created_at_unix());
        }
        ensure!(
            next_offset == manifest.source_bytes
                && hex::encode(source.finalize()) == manifest.source_sha256
                && custody.issued_at_unix == latest_birth
                && custody.expires_at_unix == earliest_expiry
                && latest_birth <= now_unix()?
                && earliest_expiry > now_unix()?,
            "local evidence aggregate source or eligibility window changed"
        );
        ensure!(
            reader.revalidation_token()? == version,
            "local transcript state changed during aggregate evidence validation; retry"
        );
        ensure!(
            earliest_expiry > now_unix()?,
            "local evidence expired before aggregate return"
        );
        Ok(())
    }
}

/// Metadata lets the operator select source IDs without implicitly exporting
/// any transcript text, platform subject or SQLite row identifier.
#[derive(Serialize)]
pub(crate) struct AvailableLocalCandidate {
    provenance_id: String,
    lifecycle_id: String,
    created_at_unix: i64,
    expires_at_unix: i64,
    text_bytes: usize,
}

pub(crate) fn list_local_candidates(
    context: &CandidateEvidenceUseContext,
    limit: usize,
) -> Result<Vec<AvailableLocalCandidate>> {
    let reader = context.reader()?;
    let version = reader.revalidation_token()?;
    let mut available = Vec::new();
    for id in reader.list_active_ids(limit)? {
        if let Some(projection) = reader.read_active(&id, MAX_CANDIDATE_SOURCE_BYTES)? {
            available.push(AvailableLocalCandidate {
                provenance_id: projection.provenance_id().to_owned(),
                lifecycle_id: projection.lifecycle_id().to_owned(),
                created_at_unix: projection.created_at_unix(),
                expires_at_unix: projection.expires_at_unix(),
                text_bytes: projection.operator_text().len(),
            });
        }
    }
    ensure!(
        reader.revalidation_token()? == version,
        "transcripts changed during candidate listing; retry"
    );
    let now = now_unix()?;
    available.retain(|candidate| candidate.expires_at_unix > now);
    Ok(available)
}

/// Explicit operator/miner input. It describes a source span, never a label
/// or a claim that a raw row itself grants evidence authority.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalCandidateSelection {
    candidate_id: String,
    provenance_id: String,
    #[serde(default)]
    raw_offset: usize,
    #[serde(default)]
    source_len: Option<usize>,
}

fn parse_selections(bytes: &[u8]) -> Result<Vec<LocalCandidateSelection>> {
    ensure!(
        bytes.len() <= MAX_CANDIDATE_RECORD_BYTES,
        "local candidate selections exceed the byte limit"
    );
    let text = std::str::from_utf8(bytes).context("local candidate selections are not UTF-8")?;
    let mut selections: Vec<LocalCandidateSelection> = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        ensure!(
            selections.len() < MAX_CANDIDATE_RECORDS,
            "too many local candidate selections"
        );
        let selection: LocalCandidateSelection = serde_json::from_str(line)
            .map_err(|_| anyhow::anyhow!("parse closed local candidate selection"))?;
        ensure!(
            canonical_id(&selection.candidate_id) && canonical_id(&selection.provenance_id),
            "local candidate selection identifiers are not canonical"
        );
        if let Some(prior) = selections.last() {
            ensure!(
                prior.candidate_id < selection.candidate_id,
                "local candidate selections must be sorted by unique candidate_id"
            );
        }
        selections.push(selection);
    }
    ensure!(
        !selections.is_empty(),
        "local candidate selections are empty"
    );
    Ok(selections)
}

fn canonical_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// Build only the explicitly selected bytes. The receipt is deterministic for
/// unchanged selections/source/key, so interrupted publication can verify and
/// reuse existing identical children without replacing any prior artifact.
pub(crate) fn export_local_candidates(
    context: &CandidateEvidenceUseContext,
    selections_bytes: &[u8],
    bundle_id: &str,
    evidence_dir: &Path,
    expected_receipt_pubkey_b64: &str,
) -> Result<CandidateEvidenceSummary> {
    ensure!(
        canonical_id(bundle_id),
        "local candidate bundle_id is not canonical"
    );
    let selections = parse_selections(selections_bytes)?;
    let reader = context.reader()?;
    let version = reader.revalidation_token()?;
    let signer = crate::wal::signing::load_existing_signing_key_with_recovery(
        &reader.home().join("wal").join("signing.key"),
    )?;
    ensure!(
        crate::wal::signing::pubkey_b64(&signer) == expected_receipt_pubkey_b64,
        "local signing key does not match the operator-supplied expected public key"
    );
    let mut source = Vec::new();
    let mut candidate_bytes = Vec::new();
    let mut candidates = Vec::new();
    let mut entries = Vec::new();
    let mut ranges = std::collections::BTreeSet::new();
    let mut earliest_expiry = i64::MAX;
    let mut latest_birth = i64::MIN;
    for selection in selections {
        let projection = reader
            .read_active(&selection.provenance_id, MAX_CANDIDATE_SOURCE_BYTES)?
            .context("selected transcript is absent, expired, revoked or not authenticated")?;
        let remaining = projection
            .operator_text()
            .len()
            .checked_sub(selection.raw_offset)
            .context("local candidate offset is outside retained text")?;
        let len = selection.source_len.unwrap_or(remaining);
        let span = selected_span(projection.operator_text(), selection.raw_offset, len)?;
        ensure!(
            ranges.insert((selection.provenance_id.clone(), selection.raw_offset, len)),
            "local candidate selections duplicate the same source span"
        );
        let total = source
            .len()
            .checked_add(span.len())
            .context("local candidate source size overflow")?;
        ensure!(
            total <= MAX_CANDIDATE_SOURCE_BYTES,
            "selected local source exceeds the export byte limit"
        );
        let candidate = MinedCandidate {
            candidate_id: selection.candidate_id.clone(),
            source_offset: source.len(),
            source_len: span.len(),
            source_span_sha256: sha256(span),
        };
        serde_json::to_writer(&mut candidate_bytes, &candidate)?;
        candidate_bytes.push(b'\n');
        ensure!(
            candidate_bytes.len() <= MAX_CANDIDATE_RECORD_BYTES,
            "local candidate vector exceeds its byte limit"
        );
        entries.push(LocalCandidateCustodyEntry {
            candidate_id: selection.candidate_id,
            provenance_id: projection.provenance_id().to_owned(),
            lifecycle_id: projection.lifecycle_id().to_owned(),
            raw_offset: selection.raw_offset,
            source_offset: source.len(),
            source_len: span.len(),
            source_span_sha256: candidate.source_span_sha256.clone(),
            created_at_unix: projection.created_at_unix(),
            expires_at_unix: projection.expires_at_unix(),
            raw: FrameCustody::from(projection.raw()),
            bound: FrameCustody::from(projection.bound()),
        });
        source.extend_from_slice(span);
        candidates.push(candidate);
        earliest_expiry = earliest_expiry.min(projection.expires_at_unix());
        latest_birth = latest_birth.max(projection.created_at_unix());
    }
    ensure!(
        reader.revalidation_token()? == version,
        "transcripts changed during candidate export; retry"
    );
    let custody = LocalCandidateCustody {
        schema_version: 1,
        purpose: CUSTODY_PURPOSE.into(),
        bundle_id: bundle_id.into(),
        source_sha256: sha256(&source),
        source_bytes: source.len(),
        candidates_sha256: sha256(&candidate_bytes),
        issued_at_unix: latest_birth,
        expires_at_unix: earliest_expiry,
        entries,
    };
    let custody_bytes = serde_json::to_vec(&custody)?;
    ensure!(
        custody_bytes.len() <= MAX_LOCAL_CUSTODY_BYTES,
        "local candidate custody exceeds its byte limit"
    );
    let manifest = CandidateEvidenceManifest {
        schema_version: CANDIDATE_EVIDENCE_SCHEMA_VERSION,
        purpose: CANDIDATE_EVIDENCE_PURPOSE.into(),
        bundle_id: bundle_id.into(),
        source_kind: CandidateEvidenceSourceKind::AuthenticatedLocalTranscriptBoundV1,
        source_sha256: custody.source_sha256.clone(),
        source_bytes: source.len(),
        candidates_sha256: custody.candidates_sha256.clone(),
        candidate_count: candidates.len(),
        local_custody_sha256: Some(sha256(&custody_bytes)),
    };
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    let mut receipt = SignedCandidateEvidenceReceipt {
        body: CandidateEvidenceReceiptBody {
            schema_version: CANDIDATE_EVIDENCE_RECEIPT_SCHEMA_VERSION,
            purpose: CANDIDATE_EVIDENCE_RECEIPT_PURPOSE.into(),
            bundle_id: bundle_id.into(),
            manifest_sha256: sha256(&manifest_bytes),
            source_kind: manifest.source_kind,
            source_sha256: manifest.source_sha256.clone(),
            source_bytes: manifest.source_bytes,
            candidates_sha256: manifest.candidates_sha256.clone(),
            candidate_count: manifest.candidate_count,
            local_custody_sha256: manifest.local_custody_sha256.clone(),
        },
        signature_b64: String::new(),
    };
    receipt.signature_b64 = crate::wal::signing::sign_b64(&signer, &receipt.canonical_bytes()?);
    let receipt_bytes = serde_json::to_vec(&receipt)?;
    context.validate_local_custody(&custody_bytes, &manifest, &candidates)?;
    let root = crate::skills::store::open_bound_directory_from_trusted_anchor(
        evidence_dir
            .parent()
            .context("local candidate evidence directory has no parent")?,
        evidence_dir,
        true,
        "local candidate evidence export",
    )?
    .context("local candidate evidence directory is absent")?;
    let lock_name = OsStr::new(".local-candidate-export.lock");
    let lock_display = root.display_path.join(lock_name);
    let (lock, lock_identity) =
        crate::skills::store::open_or_create_bound_lockfile(&root.dir, lock_name, &lock_display)?;
    lock.try_lock()
        .context("local candidate evidence export is already being modified")?;
    for (name, bytes) in [
        ("source.evidence", source.as_slice()),
        ("candidates.jsonl", candidate_bytes.as_slice()),
        (
            LOCAL_CANDIDATE_EVIDENCE_CUSTODY_FILE,
            custody_bytes.as_slice(),
        ),
        (
            "candidate-evidence-manifest.json",
            manifest_bytes.as_slice(),
        ),
        ("candidate-evidence-receipt.json", receipt_bytes.as_slice()),
    ] {
        ensure!(
            lock_identity.matches_regular_file_child_readonly(
                &root.dir,
                lock_name,
                &lock_display
            )?,
            "local candidate export lock identity changed"
        );
        context.validate_local_custody(&custody_bytes, &manifest, &candidates)?;
        let name = OsStr::new(name);
        let display = root.display_path.join(name);
        match root.dir.symlink_metadata(name) {
            Ok(_) => ensure!(
                crate::skills::store::read_regular_file_bounded(
                    &root.dir,
                    name,
                    &display,
                    bytes.len()
                )? == bytes,
                "existing local candidate artifact differs; use a new evidence directory",
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                crate::skills::store::atomic_write_private_child_create_new(
                    &root.dir, name, &display, bytes,
                )?;
            }
            Err(error) => return Err(error).context("inspect local candidate export artifact"),
        }
    }
    ensure!(
        lock_identity.matches_regular_file_child_readonly(&root.dir, lock_name, &lock_display)?,
        "local candidate export lock identity changed before return"
    );
    let evidence =
        load_candidate_evidence_with_context(evidence_dir, expected_receipt_pubkey_b64, context)?;
    Ok(summarize_candidate_evidence(&evidence))
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrameCustody {
    header_sha256: String,
    payload_sha256: String,
    frame_sha256: String,
    location_sha256: String,
    operation_sha256: String,
}

impl From<&TranscriptMiningFrameCustody> for FrameCustody {
    fn from(value: &TranscriptMiningFrameCustody) -> Self {
        Self {
            header_sha256: hex::encode(value.header_sha256),
            payload_sha256: hex::encode(value.payload_sha256),
            frame_sha256: hex::encode(value.frame_sha256),
            location_sha256: hex::encode(value.location_sha256),
            operation_sha256: hex::encode(value.operation_sha256),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalCandidateCustody {
    schema_version: u32,
    purpose: String,
    bundle_id: String,
    source_sha256: String,
    source_bytes: usize,
    candidates_sha256: String,
    issued_at_unix: i64,
    expires_at_unix: i64,
    entries: Vec<LocalCandidateCustodyEntry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalCandidateCustodyEntry {
    candidate_id: String,
    provenance_id: String,
    lifecycle_id: String,
    raw_offset: usize,
    source_offset: usize,
    source_len: usize,
    source_span_sha256: String,
    created_at_unix: i64,
    expires_at_unix: i64,
    raw: FrameCustody,
    bound: FrameCustody,
}

impl LocalCandidateCustodyEntry {
    fn matches_projection(&self, projection: &AuthenticatedTranscriptProjection) -> bool {
        self.provenance_id == projection.provenance_id()
            && self.lifecycle_id == projection.lifecycle_id()
            && self.created_at_unix == projection.created_at_unix()
            && self.expires_at_unix == projection.expires_at_unix()
            && self.raw == FrameCustody::from(projection.raw())
            && self.bound == FrameCustody::from(projection.bound())
    }
}

fn selected_span(text: &str, offset: usize, len: usize) -> Result<&[u8]> {
    let end = offset
        .checked_add(len)
        .context("local candidate span overflow")?;
    ensure!(
        len > 0 && text.is_char_boundary(offset) && text.is_char_boundary(end),
        "local candidate span must select nonempty complete UTF-8 characters"
    );
    text.as_bytes()
        .get(offset..end)
        .context("local candidate span is outside its authenticated source")
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn now_unix() -> Result<i64> {
    i64::try_from(crate::time::now_unix_ns() / 1_000_000_000)
        .context("local evidence clock exceeds i64")
}

#[cfg(test)]
#[path = "local_candidate_evidence_tests.rs"]
pub(crate) mod tests;
