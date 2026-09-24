//! ADOPT31-B7 approved document proposal consumer.
//!
//! A staged document is immutable JSON in the ordinary proposal store.  This
//! module reloads and validates that typed draft at the approval boundary,
//! applies exactly its selected route, then emits a separate metadata-only WAL
//! receipt.  The Memory ledger and create-only note helper own replay safety;
//! a missing audit acknowledgement therefore never authorizes a duplicate
//! route effect.

use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::memory::document_claims::{DocumentClaimBatch, apply_document_claim_batch};
use crate::proactive::action_staging::{
    ProposalKind, ProposalStatus, ProposedAction, adopt_approved_skill,
    make_proposal_id_content_only,
};
use crate::skills::document_staging::{
    DocumentStagingDraftV1, DocumentStagingRoute, decode_document_staging_draft,
};
use crate::wal::events::ExtendedSubtype;

/// Publicly printable, metadata-only result of one approved document route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DocumentStagingApplyReceipt {
    Skill {
        installed: bool,
    },
    Memory {
        applied_count: usize,
        replayed_count: usize,
    },
    /// Operator-owned document note. This is never `wiki/*` or self-wiki.
    VaultNote {
        reconciled: bool,
        namespace_durability_unsupported: bool,
    },
}

impl DocumentStagingApplyReceipt {
    pub const fn route_name(&self) -> &'static str {
        match self {
            Self::Skill { .. } => "skill",
            Self::Memory { .. } => "memory",
            Self::VaultNote { .. } => "vault_note",
        }
    }
}

/// Decode only an immutable `Document` proposal.  Operator-facing rationale
/// is deliberately excluded from this authority path.
pub fn parse_approved_document_staging(
    proposal: &ProposedAction,
) -> Result<DocumentStagingDraftV1> {
    anyhow::ensure!(
        proposal.kind == ProposalKind::Document,
        "proposal {} is not a Document proposal",
        proposal.id
    );
    let draft = decode_document_staging_draft(&proposal.draft_yaml).with_context(|| {
        format!(
            "validate immutable document staging proposal {}",
            proposal.id
        )
    })?;
    let canonical = serde_json::to_string(&draft).context("canonicalize document staging draft")?;
    anyhow::ensure!(
        canonical == proposal.draft_yaml,
        "document proposal {} draft is not canonical",
        proposal.id
    );
    let expected_id =
        make_proposal_id_content_only(ProposalKind::Document, &proposal.title, &canonical);
    anyhow::ensure!(
        proposal.id == expected_id,
        "document proposal {} does not bind its immutable title and draft",
        proposal.id
    );
    Ok(draft)
}

/// Apply exactly one already-approved route, then deliver its separate audit.
///
/// Approval is checked before every route effect.  When audit delivery fails,
/// this returns an explicit post-effect error.  Re-accepting the unchanged
/// proposal re-enters the route's own reconciliation boundary instead of
/// treating WAL as a mutation ledger.
pub fn apply_approved_document_staging(
    home: &Path,
    proposal: &ProposedAction,
    now_ns: i64,
) -> Result<DocumentStagingApplyReceipt> {
    anyhow::ensure!(
        proposal.kind == ProposalKind::Document,
        "proposal {} is not a Document proposal",
        proposal.id
    );
    anyhow::ensure!(
        proposal.status == ProposalStatus::Approved,
        "document proposal {} is not approved",
        proposal.id
    );
    let draft = parse_approved_document_staging(proposal)?;

    let (receipt, subtype, target_identity_sha256, route_content_sha256) = match &draft.route {
        DocumentStagingRoute::Skill {
            skill_manifest_yaml,
        } => {
            let derived = ProposedAction {
                id: make_proposal_id_content_only(
                    ProposalKind::Skill,
                    &proposal.id,
                    skill_manifest_yaml,
                ),
                kind: ProposalKind::Skill,
                title: format!("Approved document skill from {}", proposal.id),
                rationale: "Derived only from an explicitly approved immutable document proposal."
                    .to_owned(),
                draft_yaml: skill_manifest_yaml.clone(),
                generated_ts_unix: proposal.generated_ts_unix,
                status: ProposalStatus::Approved,
                operator_note: String::new(),
            };
            adopt_approved_skill(home, &derived)
                .context("apply approved document Skill route as inactive package")?;
            (
                DocumentStagingApplyReceipt::Skill { installed: true },
                ExtendedSubtype::DocumentSkillApplied,
                sha256_hex(skill_manifest_yaml.as_bytes()),
                draft.candidate_sha256.clone(),
            )
        }
        DocumentStagingRoute::Memory { scope, claims } => {
            let conn = crate::memory::store::open(&home.join("views.db"))
                .context("open document-memory views database")?;
            let memory = apply_document_claim_batch(
                &conn,
                &DocumentClaimBatch {
                    proposal_id: proposal.id.clone(),
                    source_bytes_sha256: draft.source_bytes_sha256.clone(),
                    scope: scope.clone(),
                    claims: claims.clone(),
                },
                now_ns,
            )
            .context("apply approved document Memory route through applied-once ledger")?;
            (
                DocumentStagingApplyReceipt::Memory {
                    applied_count: memory.applied_count,
                    replayed_count: memory.replayed_count,
                },
                ExtendedSubtype::DocumentMemoryApplied,
                sha256_hex(scope.as_bytes()),
                draft.candidate_sha256.clone(),
            )
        }
        DocumentStagingRoute::Wiki {
            vault_root,
            subdir,
            note_markdown,
        } => {
            let note = crate::proactive::document_note::apply_document_note(
                Path::new(vault_root),
                subdir,
                &proposal.id,
                &draft.source_bytes_sha256,
                &draft.candidate_sha256,
                note_markdown,
            )
            .context("apply approved document Vault-note route")?;
            anyhow::ensure!(
                note.proposal_id == proposal.id
                    && note.source_sha256 == draft.source_bytes_sha256
                    && note.candidate_sha256 == draft.candidate_sha256,
                "document Vault-note receipt does not bind the approved immutable proposal"
            );
            if matches!(
                note.durability,
                crate::proactive::document_note::DocumentNoteDurability::PublishedDurabilityUnknown
            ) {
                anyhow::bail!(
                    "document Vault-note route published the exact note but directory durability is unconfirmed; no WAL receipt was emitted, so re-run `neoth proactive accept {}` to reconcile before considering it audited",
                    proposal.id
                );
            }
            (
                DocumentStagingApplyReceipt::VaultNote {
                    reconciled: note.reconciled,
                    namespace_durability_unsupported: matches!(
                        note.durability,
                        crate::proactive::document_note::DocumentNoteDurability::NamespaceDurabilityUnsupported
                    ),
                },
                ExtendedSubtype::DocumentNoteApplied,
                hash_note_target_identity(&note.note_path)?,
                note.note_sha256,
            )
        }
    };

    let payload = DocumentRouteAuditV1::from_receipt(
        proposal,
        &draft,
        &receipt,
        &target_identity_sha256,
        &route_content_sha256,
        now_ns,
    )
    .encode()?;
    emit_post_effect_audit(home, subtype, payload).with_context(|| {
        format!(
            "document {} route effect committed but its required audit receipt was not durably recorded; retry `neoth proactive accept {}` to reconcile the effect and audit without changing approval",
            receipt.route_name(), proposal.id
        )
    })?;
    Ok(receipt)
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct DocumentRouteAuditV1 {
    schema_version: u8,
    proposal_id: String,
    source_bytes_sha256: String,
    sanitized_input_hash: String,
    candidate_sha256: String,
    route: &'static str,
    target_identity_sha256: String,
    route_content_sha256: String,
    applied_count: usize,
    replayed_count: usize,
    reconciled: bool,
    namespace_durability: &'static str,
    ts_ns: i64,
}

impl DocumentRouteAuditV1 {
    fn from_receipt(
        proposal: &ProposedAction,
        draft: &DocumentStagingDraftV1,
        receipt: &DocumentStagingApplyReceipt,
        target_identity_sha256: &str,
        route_content_sha256: &str,
        now_ns: i64,
    ) -> Self {
        let (applied_count, replayed_count, reconciled, namespace_durability) = match receipt {
            DocumentStagingApplyReceipt::Skill { .. } => (1, 0, false, "not_applicable"),
            DocumentStagingApplyReceipt::Memory {
                applied_count,
                replayed_count,
            } => (
                *applied_count,
                *replayed_count,
                *replayed_count > 0,
                "not_applicable",
            ),
            DocumentStagingApplyReceipt::VaultNote {
                reconciled,
                namespace_durability_unsupported,
            } => (
                1,
                0,
                *reconciled,
                if *namespace_durability_unsupported {
                    "unsupported"
                } else {
                    "confirmed"
                },
            ),
        };
        Self {
            schema_version: 1,
            proposal_id: proposal.id.clone(),
            source_bytes_sha256: draft.source_bytes_sha256.clone(),
            sanitized_input_hash: draft.sanitized_input_hash.clone(),
            candidate_sha256: draft.candidate_sha256.clone(),
            route: receipt.route_name(),
            target_identity_sha256: target_identity_sha256.to_owned(),
            route_content_sha256: route_content_sha256.to_owned(),
            applied_count,
            replayed_count,
            reconciled,
            namespace_durability,
            ts_ns: now_ns,
        }
    }

    fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).context("serialize metadata-only document route audit")
    }
}

/// The CLI dispatcher owns a Tokio runtime while `run_proactive` stays
/// synchronous for its established callers.  A short-lived dedicated thread
/// avoids nested-runtime panics and reuses the standard home-bound / daemon
/// audit delivery helper, including its durable acknowledgement semantics.
fn emit_post_effect_audit(home: &Path, subtype: ExtendedSubtype, payload: Vec<u8>) -> Result<()> {
    let home = home.to_path_buf();
    let worker = std::thread::Builder::new()
        .name("neoth-document-route-audit".to_owned())
        .spawn(move || -> Result<()> {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("build document route audit runtime")?;
            runtime.block_on(crate::cli::todo::emit_oneshot_audit_at_with_subtype(
                &home,
                crate::wal::events::EVENT_TYPE_EXTENDED,
                subtype as u8,
                payload,
                "DOCUMENT_STAGING_APPLIED",
                true,
            ))
        })
        .context("start document route audit worker")?;
    worker
        .join()
        .map_err(|_| anyhow::anyhow!("document route audit worker panicked"))?
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Hash the exact helper-returned UTF-8 target representation before it crosses
/// the audit boundary. JSON encoding is only an input to the hash: the
/// absolute operator path is never serialized into the WAL.
fn hash_note_target_identity(path: &Path) -> Result<String> {
    let utf8 = path
        .to_str()
        .context("document-note target path is not UTF-8 and cannot be audit-bound")?;
    let encoded = serde_json::to_vec(utf8).context("encode document-note target identity")?;
    Ok(sha256_hex(&encoded))
}
