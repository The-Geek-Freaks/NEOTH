//! QM-11 — Skills installer.
//!
//! Per `PLAN/QUELLEN_ADOPT_cc-switch_2026-05-21.md` §4 pick #4. NEOTH
//! ships a plugin SDK + WASM host + a skill loader (`skills::loader`)
//! that reads `~/.neoth/skills/<id>/skill.yaml`, but until QM-11
//! shipping there was no operator-facing surface for placing skill
//! directories there. Operators had to drop folders by hand.
//!
//! This module provides:
//!
//! - [`prepare_install_from_local_with_expectation`] — validate and privately
//!   stage a local skill while retaining the mutation lock. The caller durably
//!   ACKs its exact binding before [`PreparedSkillInstall::commit`].
//! - [`prepare_uninstall_with_expectation`] — capture one public generation
//!   under that same lock before a durable removal intent and commit.
//! - [`list_installed`] — return every skill currently present under
//!   `~/.neoth/skills/`. Mirrors `skills::loader::load_all` but
//!   surfaces broken installs (no skill.yaml, malformed YAML) so
//!   `neoth skills list` can report them honestly.
//!
//! ## What this module does NOT do (yet)
//!
//! - **GitHub fetch.** The cc-switch installer downloads a repo ZIP
//!   from `https://github.com/<owner>/<repo>/archive/<ref>.zip`,
//!   extracts, validates, then enters the prepared mutation lifecycle. Adding
//!   that here means a new outbound HTTP surface; per the AIO hard
//!   rule (`[[neoth-aio-cross-platform]]`) that fetch belongs in
//!   `src/installers/` not in `src/skills/` (the providers/+installers/
//!   path is the only network-allowed band per `tests/no_outbound_network.rs`).
//!   Follow-up: `installers::skill_github::fetch` chains into this
//!   module's authenticated intent/commit path after the ZIP is unpacked.
//! - **Symlinks.** cc-switch supports symlink installs for editable
//!   skill development; that's a power-user feature. Operators get
//!   copy-install in v0.1; symlink installs ship when there's an
//!   explicit operator ask.
//! - **Per-skill enable/disable from the installer.** That's a
//!   wizard / settings-panel concern; the manifest's `enabled: false`
//!   field already exists for the disable case.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Context, Result};
use cap_fs_ext::{DirExt as _, FollowSymlinks, OpenOptionsFollowExt as _};
#[cfg(unix)]
use cap_std::fs::DirBuilder;
use cap_std::fs::{Dir, OpenOptions};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::schema::SkillManifest;
use super::store::{
    BoundChildObject, BoundDirectory, BoundDirectoryChild, bind_child_object, bind_real_child_dir,
    cap_metadata_is_link_like, open_bound_directory, open_bound_directory_from_trusted_anchor,
    open_real_child_dir, open_regular_file, read_regular_file_bounded,
    read_regular_file_bounded_observed, remove_bound_real_directory_tree, remove_child_file,
    remove_real_directory_tree, rename_child, valid_child_identity_token,
};

const MAX_SKILL_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_SKILL_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SKILL_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SKILL_ENTRIES: usize = 4096;
const MAX_RUNTIME_AUTHORITY_TRAVERSAL_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_RUNTIME_AUTHORITY_TRAVERSAL_ENTRIES: usize = 16_384;
const MAX_SKILL_TREE_DEPTH: usize = 32;
pub(crate) const SKILL_MUTATION_LOCK_FILE: &str = ".neoth-skills.lock";
const SKILL_MUTATION_JOURNAL_FILE: &str = ".neoth-skill-mutation.json";
const SKILL_MUTATION_JOURNAL_STAGE_PREFIX: &str = ".neoth-skill-mutation-write-";
const SKILL_MUTATION_JOURNAL_VERSION: u32 = 2;
const MAX_SKILL_MUTATION_JOURNAL_BYTES: usize = 16 * 1024;
const INSTALL_TRANSACTION_PREFIX: &str = ".neoth-install-";
const BACKUP_TRANSACTION_PREFIX: &str = ".neoth-backup-";
const DELETE_TRANSACTION_PREFIX: &str = ".neoth-delete-";
const CREATOR_DIRECTORY_STAGE_PREFIX: &str = ".skill-create-stage-";
const CREATOR_MANIFEST_STAGE_PREFIX: &str = ".skill-yaml.stage-";
const FILE_REPLACEMENT_STAGE_PREFIX: &str = ".neoth-replace-";
static SKILL_MUTATION_PROCESS_NONCE: OnceLock<String> = OnceLock::new();

fn open_or_create_bound_skills_root(target_skills_dir: &Path) -> Result<BoundDirectory> {
    let absolute_skills_dir = std::path::absolute(target_skills_dir).with_context(|| {
        format!(
            "resolve absolute target skills root {}",
            target_skills_dir.display()
        )
    })?;
    let instance_home = absolute_skills_dir
        .parent()
        .context("target skills root has no NEOTH-home parent")?;
    let trusted_anchor = instance_home.parent().unwrap_or(instance_home);
    open_bound_directory_from_trusted_anchor(
        trusted_anchor,
        &absolute_skills_dir,
        true,
        "skills root",
    )?
    .context("created skills root is unexpectedly absent")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FinalLookupSwapPoint {
    Replace,
    RemoveDirectory,
    RemoveLeaf,
}

#[cfg(test)]
struct TestFinalLookupSwap {
    point: FinalLookupSwapPoint,
    replacement_name: OsString,
    displaced_name: OsString,
}

#[cfg(test)]
thread_local! {
    static TEST_FINAL_LOOKUP_SWAP: std::cell::RefCell<Option<TestFinalLookupSwap>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn arm_final_lookup_swap(
    point: FinalLookupSwapPoint,
    replacement_name: impl Into<OsString>,
    displaced_name: impl Into<OsString>,
) {
    TEST_FINAL_LOOKUP_SWAP.with(|slot| {
        *slot.borrow_mut() = Some(TestFinalLookupSwap {
            point,
            replacement_name: replacement_name.into(),
            displaced_name: displaced_name.into(),
        });
    });
}

fn maybe_inject_final_lookup_swap(
    root: &BoundDirectory,
    public_name: &str,
    point: FinalLookupSwapPoint,
) -> Result<()> {
    #[cfg(not(test))]
    {
        let _ = (root, public_name, point);
        Ok(())
    }
    #[cfg(test)]
    {
        let Some(swap) = TEST_FINAL_LOOKUP_SWAP.with(|slot| {
            if slot
                .borrow()
                .as_ref()
                .is_some_and(|armed| armed.point == point)
            {
                slot.borrow_mut().take()
            } else {
                None
            }
        }) else {
            return Ok(());
        };
        let public = root.display_path.join(public_name);
        let displaced = root.display_path.join(&swap.displaced_name);
        let replacement = root.display_path.join(&swap.replacement_name);
        rename_child(
            &root.dir,
            OsStr::new(public_name),
            &root.dir,
            &swap.displaced_name,
            false,
            &public,
            &displaced,
        )
        .context("test hook displace preflight-bound Skill object")?;
        rename_child(
            &root.dir,
            &swap.replacement_name,
            &root.dir,
            OsStr::new(public_name),
            false,
            &replacement,
            &public,
        )
        .context("test hook publish same-name replacement in final lookup gap")
    }
}

/// Default skills dir: `~/.neoth/skills/`.
pub fn default_skills_dir() -> PathBuf {
    crate::config::FreedomConfig::default_neoth_home().join("skills")
}

/// Report of one committed installation operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallReport {
    /// The skill id (matches the directory name + the manifest's `id`).
    pub id: String,
    /// Absolute path where the skill was placed.
    pub installed_at: PathBuf,
    /// True when the install REPLACED a prior install at the same id.
    /// Operators see "Reinstalled `xyz`" vs "Installed `xyz`" in CLI
    /// output.
    pub replaced_existing: bool,
    /// SHA-256 of the exact validated `skill.yaml` bytes copied into the
    /// committed generation. GUI callers bind their confirmation to it.
    pub source_manifest_sha256: String,
    /// Canonical SHA-256 over every package path, type, and file byte copied
    /// into the committed generation.
    pub source_generation_sha256: String,
    /// Exact generation replaced by this operation, or `None` for a new id.
    /// This binds the final receipt to the destination state the operator saw.
    pub replaced_generation_sha256: Option<String>,
    /// Non-fatal post-commit cleanup problems. The new skill is live when
    /// this is non-empty; CLI and GUI must surface every message.
    pub warnings: Vec<String>,
}

/// The only top-level package documents that generated/runtime writers may
/// replace. Keeping this typed prevents a writer-controlled path from turning
/// the installed-Skill lifecycle into an arbitrary package-file mutation API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SkillPackageDocument {
    Manifest,
    Instructions,
}

impl SkillPackageDocument {
    #[must_use]
    fn file_name(self) -> &'static OsStr {
        match self {
            Self::Manifest => OsStr::new("skill.yaml"),
            Self::Instructions => OsStr::new("skill.md"),
        }
    }

    #[must_use]
    fn display_name(self) -> &'static str {
        match self {
            Self::Manifest => "skill.yaml",
            Self::Instructions => "skill.md",
        }
    }
}

/// Owned, thread-safe input for one generated/runtime package write. Bound
/// filesystem capabilities and the OS mutation lock are constructed only
/// after this request reaches its dedicated transaction runtime.
#[derive(Clone, Debug)]
pub(crate) struct SkillDocumentMutationRequest {
    pub(crate) target_skills_dir: PathBuf,
    pub(crate) id: String,
    pub(crate) document: SkillPackageDocument,
    pub(crate) replacement: Vec<u8>,
    pub(crate) existing: super::creator::ExistingSkillPolicy,
    /// `None` means no preflight was supplied. `Some(None)` binds an absent
    /// target; `Some(Some(hash))` binds that exact package generation.
    pub(crate) expected_target_generation_sha256: Option<Option<String>>,
    /// When present, the live document must still equal these exact bytes
    /// under the mutation lock. Self-Improve uses this in addition to the full
    /// package-generation expectation.
    pub(crate) expected_document: Option<Vec<u8>>,
    pub(crate) origin: SkillMutationOrigin,
}

pub(crate) enum PreparedSkillDocumentMutation {
    Unchanged(InstallReport),
    Prepared(Box<PreparedSkillInstall>),
}

/// Read-only result used before a GUI asks whether an existing skill may be
/// replaced. The later install must present both fields as an expectation;
/// otherwise a changed source manifest cannot inherit the earlier consent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallPreflight {
    pub id: String,
    pub source_manifest_sha256: String,
    pub source_generation_sha256: String,
    pub replacing_existing: bool,
    pub target_generation_sha256: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallExpectation {
    pub id: String,
    pub source_generation_sha256: String,
    pub target_generation_sha256: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SkillMutationKind {
    Install,
    Replace,
    Remove,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SkillMutationOrigin {
    CliInstall,
    CliUninstall,
    CliCreate,
    ProactiveAccept,
    ProactiveCurator,
    Teacher,
    SelfImproveAccept,
    SelfImproveRollback,
}

impl SkillMutationOrigin {
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::CliInstall => "cli_install",
            Self::CliUninstall => "cli_uninstall",
            Self::CliCreate => "cli_create",
            Self::ProactiveAccept => "proactive_accept",
            Self::ProactiveCurator => "proactive_curator",
            Self::Teacher => "teacher",
            Self::SelfImproveAccept => "self_improve_accept",
            Self::SelfImproveRollback => "self_improve_rollback",
        }
    }
}

impl SkillMutationKind {
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Replace => "replace",
            Self::Remove => "remove",
        }
    }

    #[must_use]
    pub(crate) const fn is_install(self) -> bool {
        matches!(self, Self::Install | Self::Replace)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SkillMutationPhase {
    Prepared,
    IntentSubmitting,
    IntentDurable,
    CommitStarted,
    Committed,
    Aborted,
    Indeterminate,
}

impl SkillMutationPhase {
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::IntentSubmitting => "intent_submitting",
            Self::IntentDurable => "intent_durable",
            Self::CommitStarted => "commit_started",
            Self::Committed => "committed",
            Self::Aborted => "aborted",
            Self::Indeterminate => "indeterminate",
        }
    }

    #[must_use]
    pub(crate) const fn is_terminal(self) -> bool {
        matches!(self, Self::Committed | Self::Aborted | Self::Indeterminate)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SkillTerminalDeliveryState {
    NotStarted,
    Submitting,
    Durable,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SkillCleanupArtifactKind {
    InstallStage,
    ReplacementBackup,
    RemovalTombstone,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct SkillCleanupState {
    artifact_name: String,
    artifact_kind: SkillCleanupArtifactKind,
    object_identity: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SkillMutationAuditReceipt {
    pub(crate) audit_event_id: String,
    pub(crate) payload_sha256: String,
    pub(crate) segment_name: String,
    pub(crate) segment_generation: u32,
    pub(crate) segment_seq: u64,
    pub(crate) segment_start_ts_ns: u64,
    pub(crate) segment_node_id_hex: String,
    pub(crate) logical_offset: u64,
    pub(crate) event_id: u64,
    pub(crate) event_hlc_physical_ns: u64,
    pub(crate) event_hlc_logical: u32,
    pub(crate) event_node_id_hex: String,
}

/// Durable, metadata-only operation record. The record is written before the
/// intent may be emitted and retained until exactly one correlated terminal
/// result is observed in the WAL. Raw source or destination paths never land
/// here.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct SkillMutationJournal {
    version: u32,
    operation_id: String,
    kind: SkillMutationKind,
    origin: SkillMutationOrigin,
    skill_id: String,
    /// Present on v3 mutation-audit payloads. Kept optional so an interrupted
    /// pre-v1.0 v2 journal can still be reconciled without inventing authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mutation_sequence: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_terminal_receipt_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prior_install_incarnation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resulting_install_incarnation: Option<u64>,
    source_generation_sha256: Option<String>,
    prior_generation_sha256: Option<String>,
    prior_object_identity: Option<String>,
    intent_delivery_owner_nonce: Option<String>,
    intent_receipt: Option<SkillMutationAuditReceipt>,
    commit_boundary_nonce: Option<String>,
    phase: SkillMutationPhase,
    observed_generation_sha256: Option<String>,
    error_sha256: Option<String>,
    terminal_delivery_state: SkillTerminalDeliveryState,
    terminal_delivery_owner_nonce: Option<String>,
    terminal_receipt: Option<SkillMutationAuditReceipt>,
    cleanup_started: Option<SkillCleanupState>,
    created_at_unix: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SkillMutationAuditBinding {
    pub(crate) operation_id: String,
    pub(crate) kind: SkillMutationKind,
    pub(crate) origin: SkillMutationOrigin,
    pub(crate) skill_id: String,
    pub(crate) mutation_sequence: Option<u64>,
    pub(crate) previous_terminal_receipt_sha256: Option<String>,
    pub(crate) prior_install_incarnation: Option<u64>,
    pub(crate) resulting_install_incarnation: Option<u64>,
    pub(crate) source_generation_sha256: Option<String>,
    pub(crate) prior_generation_sha256: Option<String>,
    pub(crate) prior_object_identity_sha256: Option<String>,
    pub(crate) intent_receipt: Option<SkillMutationAuditReceipt>,
    pub(crate) commit_boundary_sha256: Option<String>,
    pub(crate) phase: SkillMutationPhase,
    pub(crate) observed_generation_sha256: Option<String>,
    pub(crate) error_sha256: Option<String>,
    pub(crate) created_at_unix: i64,
}

impl SkillMutationAuditBinding {
    #[must_use]
    pub(crate) fn intent_audit_event_id(&self) -> String {
        derive_skill_mutation_audit_event_id(self, "intent")
    }

    #[must_use]
    pub(crate) fn terminal_audit_event_id(&self) -> String {
        derive_skill_mutation_audit_event_id(self, self.phase.as_str())
    }
}

impl SkillMutationJournal {
    fn audit_binding(&self) -> SkillMutationAuditBinding {
        SkillMutationAuditBinding {
            operation_id: self.operation_id.clone(),
            kind: self.kind,
            origin: self.origin,
            skill_id: self.skill_id.clone(),
            mutation_sequence: self.mutation_sequence,
            previous_terminal_receipt_sha256: self.previous_terminal_receipt_sha256.clone(),
            prior_install_incarnation: self.prior_install_incarnation,
            resulting_install_incarnation: self.resulting_install_incarnation,
            source_generation_sha256: self.source_generation_sha256.clone(),
            prior_generation_sha256: self.prior_generation_sha256.clone(),
            prior_object_identity_sha256: self
                .prior_object_identity
                .as_deref()
                .map(|identity| hex::encode(Sha256::digest(identity.as_bytes()))),
            intent_receipt: self.intent_receipt.clone(),
            commit_boundary_sha256: self
                .commit_boundary_nonce
                .as_deref()
                .map(|nonce| hex::encode(Sha256::digest(nonce.as_bytes()))),
            phase: self.phase,
            observed_generation_sha256: self.observed_generation_sha256.clone(),
            error_sha256: self.error_sha256.clone(),
            created_at_unix: self.created_at_unix,
        }
    }
}

fn derive_skill_mutation_audit_event_id(
    binding: &SkillMutationAuditBinding,
    audit_phase: &str,
) -> String {
    fn hash_optional(digest: &mut Sha256, value: Option<&str>) {
        match value {
            Some(value) => {
                digest.update([1]);
                digest.update((value.len() as u64).to_le_bytes());
                digest.update(value.as_bytes());
            }
            None => digest.update([0]),
        }
    }

    let mut digest = Sha256::new();
    digest.update(b"neoth:skill-mutation:audit-event:v1\0");
    for value in [
        binding.operation_id.as_str(),
        binding.kind.as_str(),
        binding.origin.as_str(),
        binding.skill_id.as_str(),
        audit_phase,
    ] {
        digest.update((value.len() as u64).to_le_bytes());
        digest.update(value.as_bytes());
    }
    hash_optional(&mut digest, binding.source_generation_sha256.as_deref());
    hash_optional(&mut digest, binding.prior_generation_sha256.as_deref());
    hash_optional(&mut digest, binding.prior_object_identity_sha256.as_deref());
    if let Some(sequence) = binding.mutation_sequence {
        digest.update(sequence.to_le_bytes());
        hash_optional(
            &mut digest,
            binding.previous_terminal_receipt_sha256.as_deref(),
        );
        digest.update(
            binding
                .prior_install_incarnation
                .unwrap_or_default()
                .to_le_bytes(),
        );
        digest.update([u8::from(binding.prior_install_incarnation.is_some())]);
        digest.update(
            binding
                .resulting_install_incarnation
                .unwrap_or_default()
                .to_le_bytes(),
        );
        digest.update([u8::from(binding.resulting_install_incarnation.is_some())]);
    }
    if audit_phase != "intent" {
        hash_optional(
            &mut digest,
            binding
                .intent_receipt
                .as_ref()
                .map(|receipt| receipt.audit_event_id.as_str()),
        );
        hash_optional(&mut digest, binding.commit_boundary_sha256.as_deref());
        hash_optional(&mut digest, binding.observed_generation_sha256.as_deref());
        hash_optional(&mut digest, binding.error_sha256.as_deref());
    }
    digest.update(binding.created_at_unix.to_le_bytes());
    hex::encode(digest.finalize())
}

fn validate_skill_mutation_journal(record: &SkillMutationJournal) -> Result<()> {
    fn validate_receipt(label: &str, receipt: &SkillMutationAuditReceipt) -> Result<()> {
        if !valid_sha256(&receipt.audit_event_id) || !valid_sha256(&receipt.payload_sha256) {
            anyhow::bail!(
                "skill mutation {label} receipt carries an invalid event or payload digest"
            );
        }
        if [&receipt.segment_node_id_hex, &receipt.event_node_id_hex]
            .into_iter()
            .any(|node| {
                node.len() != 32
                    || !node
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
        {
            anyhow::bail!("skill mutation {label} receipt carries an invalid node id");
        }
        if !crate::wal::scan::canonical_segment_name(OsStr::new(&receipt.segment_name)) {
            anyhow::bail!("skill mutation {label} receipt has an invalid segment name");
        }
        Ok(())
    }

    if record.version != SKILL_MUTATION_JOURNAL_VERSION {
        anyhow::bail!(
            "unsupported skill mutation journal version {}",
            record.version
        );
    }
    validate_mutation_operation_id(&record.operation_id)?;
    validate_mutation_skill_id(&record.skill_id, record.kind)?;
    match record.mutation_sequence {
        Some(sequence) => {
            if sequence == 0 {
                anyhow::bail!("skill mutation sequence must be non-zero");
            }
            if sequence == 1 && record.previous_terminal_receipt_sha256.is_some() {
                anyhow::bail!("first skill mutation sequence must not name a predecessor");
            }
            if sequence > 1 && record.previous_terminal_receipt_sha256.is_none() {
                anyhow::bail!("non-first skill mutation sequence requires a predecessor");
            }
            if record
                .previous_terminal_receipt_sha256
                .as_deref()
                .is_some_and(|digest| !valid_sha256(digest))
            {
                anyhow::bail!(
                    "skill mutation predecessor receipt SHA-256 must be 64 lowercase hex characters"
                );
            }
            if record
                .prior_install_incarnation
                .is_some_and(|incarnation| incarnation == 0 || incarnation >= sequence)
            {
                anyhow::bail!("prior Skill install incarnation is not older than its mutation");
            }
            match (
                record.kind.is_install(),
                record.resulting_install_incarnation,
            ) {
                (true, Some(incarnation)) if incarnation == sequence => {}
                (false, None) => {}
                _ => anyhow::bail!(
                    "resulting Skill install incarnation does not match mutation kind"
                ),
            }
        }
        None => {
            if record.previous_terminal_receipt_sha256.is_some()
                || record.prior_install_incarnation.is_some()
                || record.resulting_install_incarnation.is_some()
            {
                anyhow::bail!("legacy skill mutation carries a partial incarnation binding");
            }
        }
    }
    for (label, digest) in [
        (
            "source generation",
            record.source_generation_sha256.as_deref(),
        ),
        (
            "prior generation",
            record.prior_generation_sha256.as_deref(),
        ),
        (
            "observed generation",
            record.observed_generation_sha256.as_deref(),
        ),
        ("error", record.error_sha256.as_deref()),
    ] {
        if digest.is_some_and(|value| !valid_sha256(value)) {
            anyhow::bail!(
                "skill mutation journal {label} SHA-256 must be 64 lowercase hex characters"
            );
        }
    }
    if record
        .prior_object_identity
        .as_deref()
        .is_some_and(|identity| !valid_child_identity_token(identity))
    {
        anyhow::bail!("skill mutation journal carries an invalid prior object identity");
    }
    match record.kind {
        SkillMutationKind::Install
            if record.source_generation_sha256.is_some()
                && record.prior_generation_sha256.is_none()
                && record.prior_object_identity.is_none() => {}
        SkillMutationKind::Replace
            if record.source_generation_sha256.is_some()
                && record.prior_generation_sha256.is_some()
                && record.prior_object_identity.is_some() => {}
        SkillMutationKind::Remove
            if record.source_generation_sha256.is_none()
                && record.prior_generation_sha256.is_some()
                    == record.prior_object_identity.is_some() => {}
        _ => anyhow::bail!(
            "skill mutation journal generation bindings do not match mutation kind {}",
            record.kind.as_str()
        ),
    }
    if record.created_at_unix < 0 {
        anyhow::bail!("skill mutation journal timestamp must not be negative");
    }
    if record
        .intent_delivery_owner_nonce
        .as_deref()
        .is_some_and(|nonce| !valid_operation_nonce(nonce))
    {
        anyhow::bail!("skill mutation journal carries an invalid delivery-owner nonce");
    }
    if record
        .commit_boundary_nonce
        .as_deref()
        .is_some_and(|nonce| !valid_operation_nonce(nonce))
    {
        anyhow::bail!("skill mutation journal carries an invalid commit-boundary nonce");
    }
    if record
        .terminal_delivery_owner_nonce
        .as_deref()
        .is_some_and(|nonce| !valid_operation_nonce(nonce))
    {
        anyhow::bail!("skill mutation journal carries an invalid terminal-delivery owner");
    }
    if let Some(receipt) = record.intent_receipt.as_ref() {
        validate_receipt("intent", receipt)?;
    }
    if let Some(receipt) = record.terminal_receipt.as_ref() {
        validate_receipt("terminal", receipt)?;
    }
    if record.phase == SkillMutationPhase::Prepared && record.intent_delivery_owner_nonce.is_some()
    {
        anyhow::bail!("prepared skill mutation unexpectedly has a delivery owner");
    }
    if matches!(
        record.phase,
        SkillMutationPhase::IntentSubmitting
            | SkillMutationPhase::IntentDurable
            | SkillMutationPhase::CommitStarted
    ) && record.intent_delivery_owner_nonce.is_none()
    {
        anyhow::bail!("active submitted skill mutation is missing its delivery-owner nonce");
    }
    if matches!(
        record.phase,
        SkillMutationPhase::IntentDurable | SkillMutationPhase::CommitStarted
    ) || record.phase.is_terminal()
    {
        if record.intent_receipt.is_none() {
            anyhow::bail!("durable skill mutation is missing its authenticated intent receipt");
        }
    } else if record.intent_receipt.is_some() {
        anyhow::bail!("pre-durability skill mutation unexpectedly has an intent receipt");
    }
    if matches!(record.phase, SkillMutationPhase::CommitStarted) || record.phase.is_terminal() {
        if record.commit_boundary_nonce.is_none() {
            anyhow::bail!("committing skill mutation is missing its durable boundary");
        }
    } else if record.commit_boundary_nonce.is_some() {
        anyhow::bail!("pre-commit skill mutation unexpectedly has a commit boundary");
    }
    match record.terminal_delivery_state {
        SkillTerminalDeliveryState::NotStarted => {
            if record.terminal_delivery_owner_nonce.is_some() || record.terminal_receipt.is_some() {
                anyhow::bail!("terminal delivery state does not match its owner/receipt");
            }
        }
        SkillTerminalDeliveryState::Submitting => {
            if !record.phase.is_terminal()
                || record.terminal_delivery_owner_nonce.is_none()
                || record.terminal_receipt.is_some()
            {
                anyhow::bail!("terminal submitting state is incomplete or non-terminal");
            }
        }
        SkillTerminalDeliveryState::Durable => {
            if !record.phase.is_terminal()
                || record.terminal_delivery_owner_nonce.is_none()
                || record.terminal_receipt.is_none()
            {
                anyhow::bail!("terminal durable state is incomplete or non-terminal");
            }
        }
    }
    if let Some(cleanup) = record.cleanup_started.as_ref() {
        if !record.phase.is_terminal()
            || !valid_child_identity_token(&cleanup.object_identity)
            || cleanup.artifact_name.is_empty()
            || cleanup.artifact_name.contains(['\0', '/', '\\'])
        {
            anyhow::bail!("skill mutation cleanup-started binding is invalid");
        }
        let expected = match cleanup.artifact_kind {
            SkillCleanupArtifactKind::InstallStage => mutation_install_stage_name(record),
            SkillCleanupArtifactKind::ReplacementBackup => mutation_backup_name(record),
            SkillCleanupArtifactKind::RemovalTombstone => mutation_tombstone_name(record),
        };
        if expected != OsStr::new(&cleanup.artifact_name) {
            anyhow::bail!("skill mutation cleanup-started artifact is not operation-bound");
        }
    }
    if !record.phase.is_terminal()
        && (record.observed_generation_sha256.is_some() || record.error_sha256.is_some())
    {
        anyhow::bail!(
            "non-terminal skill mutation journal unexpectedly carries terminal observations"
        );
    }
    Ok(())
}

fn read_skill_mutation_journal(root: &BoundDirectory) -> Result<Option<SkillMutationJournal>> {
    let display = root.display_path.join(SKILL_MUTATION_JOURNAL_FILE);
    let bytes = match read_regular_file_bounded(
        &root.dir,
        OsStr::new(SKILL_MUTATION_JOURNAL_FILE),
        &display,
        MAX_SKILL_MUTATION_JOURNAL_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(error)
            if error
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error).context("read pending skill mutation journal"),
    };
    let record: SkillMutationJournal = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse skill mutation journal {}", display.display()))?;
    validate_skill_mutation_journal(&record)
        .with_context(|| format!("validate skill mutation journal {}", display.display()))?;
    Ok(Some(record))
}

fn skill_mutation_journal_stage_name(operation_id: &str) -> OsString {
    OsString::from(format!(
        "{SKILL_MUTATION_JOURNAL_STAGE_PREFIX}{operation_id}"
    ))
}

fn write_private_metadata_file_create_new(
    parent: &Dir,
    name: &OsStr,
    display: &Path,
    bytes: &[u8],
) -> Result<()> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = parent
        .open_with(name, &options)
        .with_context(|| format!("create private skill metadata {}", display.display()))?;
    std::io::Write::write_all(&mut file, bytes)
        .with_context(|| format!("write private skill metadata {}", display.display()))?;
    file.sync_all()
        .with_context(|| format!("sync private skill metadata {}", display.display()))
}

fn remove_private_metadata_stage_if_present(
    root: &BoundDirectory,
    stage_name: &OsStr,
) -> Result<()> {
    let display = root.display_path.join(stage_name);
    match root.dir.symlink_metadata(stage_name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(metadata) if metadata.is_file() && !cap_metadata_is_link_like(&metadata) => {
            remove_child_file(&root.dir, stage_name, &display)
        }
        Ok(_) => anyhow::bail!(
            "private skill mutation journal stage is not a regular file: {}",
            display.display()
        ),
        Err(error) => Err(error)
            .with_context(|| format!("inspect skill mutation journal stage {}", display.display())),
    }
}

fn persist_skill_mutation_journal(
    root: &BoundDirectory,
    record: &SkillMutationJournal,
) -> Result<()> {
    validate_skill_mutation_journal(record)?;
    if let Some(existing) = read_skill_mutation_journal(root)?
        && existing.operation_id != record.operation_id
    {
        anyhow::bail!(
            "pending skill mutation {} must be reconciled before starting {}",
            existing.operation_id,
            record.operation_id
        );
    }
    let mut bytes =
        serde_json::to_vec_pretty(record).context("serialize skill mutation journal")?;
    bytes.push(b'\n');
    if bytes.len() > MAX_SKILL_MUTATION_JOURNAL_BYTES {
        anyhow::bail!(
            "skill mutation journal is {} bytes, exceeding the {}-byte limit",
            bytes.len(),
            MAX_SKILL_MUTATION_JOURNAL_BYTES
        );
    }

    let stage_name = skill_mutation_journal_stage_name(&record.operation_id);
    let stage_display = root.display_path.join(&stage_name);
    remove_private_metadata_stage_if_present(root, &stage_name)?;
    write_private_metadata_file_create_new(&root.dir, &stage_name, &stage_display, &bytes)?;
    if let Err(error) = rename_child(
        &root.dir,
        &stage_name,
        &root.dir,
        OsStr::new(SKILL_MUTATION_JOURNAL_FILE),
        true,
        &stage_display,
        &root.display_path.join(SKILL_MUTATION_JOURNAL_FILE),
    ) {
        let _ = remove_private_metadata_stage_if_present(root, &stage_name);
        return Err(error).context("publish skill mutation journal");
    }
    sync_directory(&root.dir, &root.display_path).context("sync skill mutation journal")
}

fn clear_skill_mutation_journal(root: &BoundDirectory) -> Result<()> {
    let display = root.display_path.join(SKILL_MUTATION_JOURNAL_FILE);
    match root
        .dir
        .symlink_metadata(OsStr::new(SKILL_MUTATION_JOURNAL_FILE))
    {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(metadata) if metadata.is_file() && !cap_metadata_is_link_like(&metadata) => {
            remove_child_file(&root.dir, OsStr::new(SKILL_MUTATION_JOURNAL_FILE), &display)?;
        }
        Ok(_) => anyhow::bail!(
            "skill mutation journal is not a regular file: {}",
            display.display()
        ),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect skill mutation journal {}", display.display()));
        }
    }
    sync_directory(&root.dir, &root.display_path)
        .context("sync acknowledged skill mutation journal removal")
}

fn transition_skill_mutation_phase(
    root: &BoundDirectory,
    record: &mut SkillMutationJournal,
    phase: SkillMutationPhase,
    observed_generation_sha256: Option<String>,
    error_sha256: Option<String>,
) -> Result<()> {
    let legal = matches!(
        (record.phase, phase),
        (
            SkillMutationPhase::Prepared,
            SkillMutationPhase::IntentSubmitting
                | SkillMutationPhase::Aborted
                | SkillMutationPhase::Indeterminate
        ) | (
            SkillMutationPhase::IntentSubmitting,
            SkillMutationPhase::IntentDurable
                | SkillMutationPhase::Aborted
                | SkillMutationPhase::Indeterminate
        ) | (
            SkillMutationPhase::IntentDurable,
            SkillMutationPhase::CommitStarted
                | SkillMutationPhase::Aborted
                | SkillMutationPhase::Indeterminate
        ) | (
            SkillMutationPhase::CommitStarted,
            SkillMutationPhase::Committed
                | SkillMutationPhase::Aborted
                | SkillMutationPhase::Indeterminate
        ) | (
            SkillMutationPhase::Committed | SkillMutationPhase::Aborted,
            SkillMutationPhase::Indeterminate
        )
    ) || record.phase == phase;
    if !legal {
        anyhow::bail!(
            "illegal skill mutation journal transition {} -> {} for {}",
            record.phase.as_str(),
            phase.as_str(),
            record.operation_id
        );
    }
    let prior = record.clone();
    if (phase == SkillMutationPhase::CommitStarted || phase.is_terminal())
        && record.commit_boundary_nonce.is_none()
    {
        record.commit_boundary_nonce = Some(uuid::Uuid::now_v7().simple().to_string());
    }
    record.phase = phase;
    record.observed_generation_sha256 = observed_generation_sha256;
    record.error_sha256 = error_sha256;
    if phase.is_terminal() && !prior.phase.is_terminal() {
        record.terminal_delivery_state = SkillTerminalDeliveryState::NotStarted;
        record.terminal_delivery_owner_nonce = None;
        record.terminal_receipt = None;
    }
    if let Err(error) = persist_skill_mutation_journal(root, record) {
        *record = prior;
        return Err(error);
    }
    Ok(())
}

/// Exact, read-only binding carried by a prepared install while the shared
/// cross-process mutation lock remains held. Callers must durably acknowledge
/// this binding before calling [`PreparedSkillInstall::commit`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg(test)]
pub(crate) struct SkillInstallIntentBinding {
    pub(crate) operation_id: String,
    pub(crate) id: String,
    pub(crate) source_generation_sha256: String,
    pub(crate) replacing_existing: bool,
    pub(crate) target_generation_sha256: Option<String>,
}

/// Opaque install prepared under the same lock that guards its later public
/// commit. Staging is private; dropping this value can leave only a private
/// recovery artifact and can never publish a Skill.
pub(crate) struct PreparedSkillInstall {
    target_root: BoundDirectory,
    _mutation_guard: SkillMutationGuard,
    journal: SkillMutationJournal,
    target_identity: Option<BoundDirectoryChild>,
    stage_identity: BoundDirectoryChild,
    id: String,
    manifest_sha256: String,
    generation_sha256: String,
    stage_name: OsString,
    backup_candidate: OsString,
    replaced_generation_sha256: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SkillMutationFailureState {
    /// The public anchor is unchanged (or was restored) and the requested
    /// mutation did not commit.
    Aborted,
    /// Recovery state was retained because the public anchor could not be
    /// proven restored after a failed commit attempt.
    Indeterminate,
}

impl SkillMutationFailureState {
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Aborted => "aborted",
            Self::Indeterminate => "indeterminate",
        }
    }
}

#[derive(Debug)]
pub(crate) struct SkillMutationCommitError {
    state: SkillMutationFailureState,
    error: anyhow::Error,
}

impl SkillMutationCommitError {
    fn aborted(error: anyhow::Error) -> Self {
        Self {
            state: SkillMutationFailureState::Aborted,
            error,
        }
    }

    fn indeterminate(error: anyhow::Error) -> Self {
        Self {
            state: SkillMutationFailureState::Indeterminate,
            error,
        }
    }

    #[must_use]
    pub(crate) const fn state(&self) -> SkillMutationFailureState {
        self.state
    }

    #[must_use]
    pub(crate) fn into_inner(self) -> anyhow::Error {
        self.error
    }
}

impl std::fmt::Display for SkillMutationCommitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for SkillMutationCommitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.error.as_ref())
    }
}

impl PreparedSkillInstall {
    #[must_use]
    pub(crate) fn audit_binding(&self) -> SkillMutationAuditBinding {
        self.journal.audit_binding()
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn intent_binding(&self) -> SkillInstallIntentBinding {
        SkillInstallIntentBinding {
            operation_id: self.journal.operation_id.clone(),
            id: self.id.clone(),
            source_generation_sha256: self.generation_sha256.clone(),
            replacing_existing: self.replaced_generation_sha256.is_some(),
            target_generation_sha256: self.replaced_generation_sha256.clone(),
        }
    }

    /// Persist that the exact intent received a durable WAL acknowledgement.
    /// This transition happens while the original mutation lock is still held.
    pub(crate) fn mark_intent_submitting(&mut self) -> Result<()> {
        mark_skill_mutation_intent_submitting(&self.target_root, &mut self.journal)
    }

    pub(crate) fn mark_intent_durable_authenticated(
        &mut self,
        receipt: SkillMutationAuditReceipt,
    ) -> Result<()> {
        if receipt.audit_event_id != self.journal.audit_binding().intent_audit_event_id() {
            anyhow::bail!("authenticated Skill install receipt does not match its exact intent");
        }
        self.journal.intent_receipt = Some(receipt);
        transition_skill_mutation_phase(
            &self.target_root,
            &mut self.journal,
            SkillMutationPhase::IntentDurable,
            None,
            None,
        )
    }

    #[cfg(test)]
    pub(crate) fn mark_intent_durable(&mut self) -> Result<()> {
        if self.journal.phase == SkillMutationPhase::Prepared {
            self.mark_intent_submitting()?;
        }
        self.mark_intent_durable_authenticated(test_audit_receipt(
            self.journal.audit_binding().intent_audit_event_id(),
        ))
    }

    /// Abort a prepared operation only after the caller proved that no matching
    /// intent frame exists. An ambiguous delivery must go through the journal
    /// reconciler instead.
    pub(crate) fn abort_without_intent(self) -> Result<()> {
        if !matches!(
            self.journal.phase,
            SkillMutationPhase::Prepared | SkillMutationPhase::IntentSubmitting
        ) {
            anyhow::bail!(
                "skill mutation {} cannot abort without intent from phase {}",
                self.journal.operation_id,
                self.journal.phase.as_str()
            );
        }
        remove_transaction_artifact_if_present(&self.target_root, &self.stage_name, None)
            .context("remove uncommitted prepared skill install")?;
        clear_skill_mutation_journal(&self.target_root)
    }
}

/// Read-only binding for one public entry below the skills root. The digest is
/// `None` only when the exact child name is absent. Directory generations are
/// content-addressed; broken file/link/reparse entries use the bounded,
/// no-follow identity described by [`installed_entry_generation_locked`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkillTargetPreflight {
    pub id: String,
    pub target_generation_sha256: Option<String>,
}

/// A healthy canonical install read under the mutation lock. This is the
/// post-commit readback boundary used by GUI receipts: both hashes describe
/// the currently live `<skills>/<id>` entry, not an independently opened
/// source path which may already have been replaced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentSkillGeneration {
    pub id: String,
    pub manifest_sha256: String,
    pub generation_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UninstallExpectation {
    pub id: String,
    pub target_generation_sha256: String,
}

/// Exact public-anchor state carried by a prepared removal while the shared
/// cross-process mutation lock remains held.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg(test)]
pub(crate) struct SkillRemovalIntentBinding {
    pub(crate) operation_id: String,
    pub(crate) id: String,
    pub(crate) target_generation_sha256: String,
}

/// Preparation resolves an already-absent target before any mutation journal
/// exists. Only `Prepared` may enter the intent/terminal WAL lifecycle.
pub(crate) enum PreparedSkillRemovalOutcome {
    Unchanged(UninstallReport),
    Prepared(Box<PreparedSkillRemoval>),
}

#[cfg(test)]
impl PreparedSkillRemovalOutcome {
    fn into_prepared_for_test(self) -> PreparedSkillRemoval {
        match self {
            Self::Prepared(prepared) => *prepared,
            Self::Unchanged(_) => panic!("expected prepared removal, got unchanged report"),
        }
    }
}

/// Opaque removal prepared under the same lock that guards its public commit.
/// No public directory entry is changed until [`PreparedSkillRemoval::commit`].
pub(crate) struct PreparedSkillRemoval {
    root: BoundDirectory,
    _mutation_guard: SkillMutationGuard,
    journal: SkillMutationJournal,
    target_identity: BoundChildObject,
    id: String,
    target_generation_sha256: String,
}

impl PreparedSkillRemoval {
    #[must_use]
    pub(crate) fn audit_binding(&self) -> SkillMutationAuditBinding {
        self.journal.audit_binding()
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn intent_binding(&self) -> SkillRemovalIntentBinding {
        SkillRemovalIntentBinding {
            operation_id: self.journal.operation_id.clone(),
            id: self.id.clone(),
            target_generation_sha256: self.target_generation_sha256.clone(),
        }
    }

    pub(crate) fn mark_intent_submitting(&mut self) -> Result<()> {
        mark_skill_mutation_intent_submitting(&self.root, &mut self.journal)
    }

    pub(crate) fn mark_intent_durable_authenticated(
        &mut self,
        receipt: SkillMutationAuditReceipt,
    ) -> Result<()> {
        if receipt.audit_event_id != self.journal.audit_binding().intent_audit_event_id() {
            anyhow::bail!("authenticated Skill removal receipt does not match its exact intent");
        }
        self.journal.intent_receipt = Some(receipt);
        transition_skill_mutation_phase(
            &self.root,
            &mut self.journal,
            SkillMutationPhase::IntentDurable,
            None,
            None,
        )
    }

    #[cfg(test)]
    pub(crate) fn mark_intent_durable(&mut self) -> Result<()> {
        if self.journal.phase == SkillMutationPhase::Prepared {
            self.mark_intent_submitting()?;
        }
        self.mark_intent_durable_authenticated(test_audit_receipt(
            self.journal.audit_binding().intent_audit_event_id(),
        ))
    }

    pub(crate) fn abort_without_intent(self) -> Result<()> {
        if !matches!(
            self.journal.phase,
            SkillMutationPhase::Prepared | SkillMutationPhase::IntentSubmitting
        ) {
            anyhow::bail!(
                "skill mutation {} cannot abort without intent from phase {}",
                self.journal.operation_id,
                self.journal.phase.as_str()
            );
        }
        clear_skill_mutation_journal(&self.root)
    }
}

struct ValidatedInstallSource {
    source: BoundDirectory,
    manifest: SkillManifest,
    manifest_bytes: Vec<u8>,
    manifest_sha256: String,
    generation_sha256: String,
}

fn validate_local_source(source_dir: &Path) -> Result<ValidatedInstallSource> {
    let Some(source) = open_bound_directory(source_dir, false, "skill source")? else {
        anyhow::bail!(
            "source `{}` is not a directory — pass the skill folder, not the skill.yaml",
            source_dir.display()
        );
    };
    let manifest_path = source.display_path.join("skill.yaml");
    let manifest_bytes = match read_regular_file_bounded(
        &source.dir,
        OsStr::new("skill.yaml"),
        &manifest_path,
        MAX_SKILL_MANIFEST_BYTES,
    ) {
        Ok(body) => body,
        Err(error)
            if error
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            anyhow::bail!(
                "no skill.yaml in `{}` — install source must contain a manifest",
                source.display_path.display()
            );
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("read manifest at {}", manifest_path.display()));
        }
    };
    let manifest_text = std::str::from_utf8(&manifest_bytes)
        .with_context(|| format!("manifest is not UTF-8 at {}", manifest_path.display()))?;
    let manifest: SkillManifest = serde_yaml::from_str(manifest_text)
        .with_context(|| format!("parse YAML at {}", manifest_path.display()))?;
    super::creator::validate_skill_id(&manifest.id).with_context(|| {
        format!(
            "invalid skill id in {} (only lowercase [a-z0-9_-] allowed)",
            manifest_path.display()
        )
    })?;
    if manifest.description.trim().is_empty() {
        anyhow::bail!(
            "skill.yaml at `{}` has empty `description` — refuse to install",
            manifest_path.display()
        );
    }
    let manifest_sha256 = hex::encode(Sha256::digest(&manifest_bytes));
    let generation_sha256 =
        skill_tree_generation_sha256(&source.dir, &source.display_path, Some(&manifest_bytes))?;
    Ok(ValidatedInstallSource {
        source,
        manifest,
        manifest_bytes,
        manifest_sha256,
        generation_sha256,
    })
}

pub(crate) fn target_generation_locked(root: &BoundDirectory, id: &str) -> Result<Option<String>> {
    let mut aggregate = RuntimeAuthorityTraversalBudget::unbounded_for_internal();
    target_generation_locked_with_budget(root, id, &mut aggregate)
}

pub(crate) fn target_generation_locked_with_budget(
    root: &BoundDirectory,
    id: &str,
    aggregate: &mut RuntimeAuthorityTraversalBudget,
) -> Result<Option<String>> {
    let target = root.display_path.join(id);
    match root.dir.symlink_metadata(id) {
        Ok(_) => {
            let target_dir = open_real_child_dir(&root.dir, OsStr::new(id), &target)?;
            Ok(Some(skill_tree_generation_sha256_with_aggregate_budget(
                &target_dir,
                &target,
                None,
                aggregate,
            )?))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("inspect prior install at {}", target.display()))
        }
    }
}

fn valid_sha256(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_mutation_operation_id(operation_id: &str) -> Result<()> {
    if !valid_operation_nonce(operation_id) {
        anyhow::bail!("skill mutation operation id must be 32 lowercase hex characters");
    }
    Ok(())
}

fn valid_operation_nonce(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn skill_mutation_process_nonce() -> &'static str {
    SKILL_MUTATION_PROCESS_NONCE
        .get_or_init(|| uuid::Uuid::now_v7().simple().to_string())
        .as_str()
}

#[cfg(test)]
fn test_audit_receipt(audit_event_id: String) -> SkillMutationAuditReceipt {
    SkillMutationAuditReceipt {
        audit_event_id,
        payload_sha256: "11".repeat(32),
        segment_name: "000001.wal".to_string(),
        segment_generation: 0,
        segment_seq: 1,
        segment_start_ts_ns: 1,
        segment_node_id_hex: "00".repeat(16),
        logical_offset: 60,
        event_id: 1,
        event_hlc_physical_ns: 1,
        event_hlc_logical: 0,
        event_node_id_hex: "00".repeat(16),
    }
}

fn mark_skill_mutation_intent_submitting(
    root: &BoundDirectory,
    journal: &mut SkillMutationJournal,
) -> Result<()> {
    if journal.phase != SkillMutationPhase::Prepared {
        anyhow::bail!(
            "skill mutation {} cannot begin intent delivery from phase {}",
            journal.operation_id,
            journal.phase.as_str()
        );
    }
    let prior = journal.clone();
    journal.phase = SkillMutationPhase::IntentSubmitting;
    journal.intent_delivery_owner_nonce = Some(skill_mutation_process_nonce().to_string());
    if let Err(error) = persist_skill_mutation_journal(root, journal) {
        *journal = prior;
        return Err(error);
    }
    Ok(())
}

/// Bind any direct public entry without following it. Healthy/repairable real
/// directories retain the canonical package-generation algorithm. If the
/// directory contains a link/special entry, or the public child itself is a
/// file/link/reparse point, a second bounded walker hashes names, entry kinds,
/// regular-file bytes, and link targets. It never opens a link target.
pub(crate) fn installed_entry_generation_locked(
    root: &BoundDirectory,
    id: &str,
) -> Result<Option<String>> {
    installed_entry_generation_at_locked(root, id, id)
}

/// Hash an entry that currently lives under a private transaction name as the
/// same logical public object that was bound before the rename. Directory-tree
/// generations are already root-name independent; broken leaf/link generations
/// must receive the original public name or a safe rename would change the
/// object digest by construction.
fn installed_entry_generation_at_locked(
    root: &BoundDirectory,
    entry_name: &str,
    logical_id: &str,
) -> Result<Option<String>> {
    let display = root.display_path.join(entry_name);
    let metadata = match root.dir.symlink_metadata(entry_name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect skill entry {}", display.display()));
        }
    };

    if metadata.is_dir() && !cap_metadata_is_link_like(&metadata) {
        let directory = open_real_child_dir(&root.dir, OsStr::new(entry_name), &display)?;
        if let Ok(generation) = skill_tree_generation_sha256(&directory, &display, None) {
            return Ok(Some(generation));
        }
        let mut hasher = Sha256::new();
        hasher.update(b"NEOTH_INSTALLED_ENTRY_GENERATION\0v2\0");
        hash_installed_record_header(&mut hasher, b'D', Path::new(""), 0, &metadata)?;
        let mut budget = CopyBudget::default();
        hash_installed_entry_directory(
            &directory,
            &display,
            Path::new(""),
            0,
            &mut budget,
            &mut hasher,
        )?;
        return Ok(Some(hex::encode(hasher.finalize())));
    }

    let mut hasher = Sha256::new();
    hasher.update(b"NEOTH_INSTALLED_ENTRY_GENERATION\0v2\0");
    hash_installed_leaf(
        &root.dir,
        OsStr::new(entry_name),
        &display,
        Path::new(logical_id),
        &metadata,
        &mut CopyBudget::default(),
        &mut hasher,
    )?;
    Ok(Some(hex::encode(hasher.finalize())))
}

/// Inspect one exact public target under the shared cross-process mutation
/// lock. This is intentionally separate from activation authority (R3-17).
pub fn inspect_installed_target(
    target_skills_dir: &Path,
    id: &str,
) -> Result<SkillTargetPreflight> {
    validate_installed_skill_dir_name(id)?;
    let target_generation_sha256 =
        match open_bound_directory(target_skills_dir, false, "skills root")? {
            None => None,
            Some(root) => {
                let _mutation_guard = lock_skill_mutations(&root)?;
                recover_pending_transactions_locked(&root)?;
                installed_entry_generation_locked(&root, id)?
            }
        };
    Ok(SkillTargetPreflight {
        id: id.to_string(),
        target_generation_sha256,
    })
}

/// Read the exact currently-live canonical install under the shared mutation
/// lock. Callers use this after a typed receipt to rule out accepting an old
/// source handle while a different destination generation is live.
pub fn inspect_current_install(
    target_skills_dir: &Path,
    id: &str,
) -> Result<CurrentSkillGeneration> {
    super::creator::validate_skill_id(id).context("validate installed skill id")?;
    let root = open_bound_directory(target_skills_dir, false, "skills root")?
        .with_context(|| format!("skills root is absent at {}", target_skills_dir.display()))?;
    let _mutation_guard = lock_skill_mutations(&root)?;
    recover_pending_transactions_locked(&root)?;
    let display = root.display_path.join(id);
    let directory = open_real_child_dir(&root.dir, OsStr::new(id), &display)?;
    let manifest_path = display.join("skill.yaml");
    let manifest_bytes = read_regular_file_bounded(
        &directory,
        OsStr::new("skill.yaml"),
        &manifest_path,
        MAX_SKILL_MANIFEST_BYTES,
    )?;
    let manifest: SkillManifest = serde_yaml::from_slice(&manifest_bytes)
        .with_context(|| format!("parse installed manifest at {}", manifest_path.display()))?;
    if manifest.id != id {
        anyhow::bail!(
            "installed manifest id `{}` does not match canonical target `{id}`",
            manifest.id
        );
    }
    super::creator::validate_skill_id(&manifest.id).context("validate installed manifest id")?;
    let manifest_sha256 = hex::encode(Sha256::digest(&manifest_bytes));
    let generation_sha256 = skill_tree_generation_sha256(&directory, &display, None)?;
    Ok(CurrentSkillGeneration {
        id: id.to_string(),
        manifest_sha256,
        generation_sha256,
    })
}

/// Validate a local source and inspect the recovered target namespace without
/// installing anything. This is the typed GUI confirmation boundary.
pub fn inspect_local_install(
    source_dir: &Path,
    target_skills_dir: &Path,
) -> Result<InstallPreflight> {
    let validated = validate_local_source(source_dir)?;
    let target_generation_sha256 =
        match open_bound_directory(target_skills_dir, false, "skills root")? {
            None => {
                validate_prospective_route_ownership(None, &validated.manifest)?;
                None
            }
            Some(root) => {
                let _mutation_guard = lock_skill_mutations(&root)?;
                recover_pending_transactions_locked(&root)?;
                validate_prospective_route_ownership(Some(&root), &validated.manifest)?;
                target_generation_locked(&root, &validated.manifest.id)?
            }
        };
    Ok(InstallPreflight {
        id: validated.manifest.id,
        source_manifest_sha256: validated.manifest_sha256,
        source_generation_sha256: validated.generation_sha256,
        replacing_existing: target_generation_sha256.is_some(),
        target_generation_sha256,
    })
}

/// Validate every executable post-mutation catalogue while the caller holds
/// the Skill-namespace mutation lock. Raw installed manifests override bundled
/// ids, but an installed candidate without exact active authority leaves its
/// same-id bundled fallback executable. Authority is deliberately stored
/// outside the package tree, so mutation preflight conservatively validates
/// both the installed override and every possible bundled fallback. Broken
/// entries cannot route and therefore contribute no aliases.
fn validate_prospective_route_ownership(
    target_root: Option<&BoundDirectory>,
    candidate: &SkillManifest,
) -> Result<()> {
    validate_prospective_route_ownership_change(target_root, Some(candidate), None)
        .with_context(|| format!("Skill `{}` route-owner preflight failed", candidate.id))
}

/// Validate removal or authority reduction before its commit boundary. The
/// caller must hold `target_root`'s Skill mutation lock for the full mutation.
pub(crate) fn validate_prospective_route_reduction_locked(
    target_root: &BoundDirectory,
    removed_installed_id: &str,
) -> Result<()> {
    validate_prospective_route_ownership_change(Some(target_root), None, Some(removed_installed_id))
        .with_context(|| {
            format!("Skill `{removed_installed_id}` route-owner reduction preflight failed")
        })
}

/// Revalidate the complete installed/fallback catalogue immediately before an
/// authority activation commits. The caller must retain `target_root`'s Skill
/// mutation lock through the authority and policy transaction.
pub(crate) fn validate_prospective_route_activation_locked(
    target_root: &BoundDirectory,
) -> Result<()> {
    validate_prospective_route_ownership_change(Some(target_root), None, None)
        .context("Skill activation route-owner preflight failed")
}

fn validate_prospective_route_ownership_change(
    target_root: Option<&BoundDirectory>,
    candidate: Option<&SkillManifest>,
    removed_installed_id: Option<&str>,
) -> Result<()> {
    let bundled = super::loader::parse_bundled_skills()
        .context("load bundled catalogue for Skill route-owner preflight")?;
    let mut by_id = bundled.clone();
    let mut installed_override_ids = Vec::new();
    if let Some(root) = target_root {
        for entry in list_installed_locked_with_limit(root, MAX_SKILL_ENTRIES)? {
            let Some(manifest) = entry.manifest else {
                continue;
            };
            if removed_installed_id.is_some_and(|removed| manifest.id == removed) {
                continue;
            }
            installed_override_ids.push(manifest.id.clone());
            by_id.insert(
                manifest.id.clone(),
                super::schema::Skill {
                    manifest,
                    path: entry.path.join("skill.yaml"),
                    content_hash: String::new(),
                },
            );
        }
    }
    if let Some(candidate) = candidate {
        installed_override_ids.retain(|id| id != &candidate.id);
        installed_override_ids.push(candidate.id.clone());
        by_id.insert(
            candidate.id.clone(),
            super::schema::Skill {
                manifest: candidate.clone(),
                path: PathBuf::from("<prospective>/skill.yaml"),
                content_hash: String::new(),
            },
        );
    }

    validate_route_ownership_map(by_id.values())?;
    installed_override_ids.sort();
    installed_override_ids.dedup();
    for fallback_id in installed_override_ids {
        let Some(fallback) = bundled.get(&fallback_id) else {
            continue;
        };
        let mut fallback_view = by_id.clone();
        fallback_view.insert(fallback_id.clone(), fallback.clone());
        validate_route_ownership_map(fallback_view.values()).with_context(|| {
            format!("validate bundled fallback route ownership for `{fallback_id}`")
        })?;
    }
    Ok(())
}

fn validate_route_ownership_map<'a>(
    skills: impl Iterator<Item = &'a super::schema::Skill>,
) -> Result<()> {
    let mut prospective = skills.cloned().collect::<Vec<_>>();
    prospective.sort_by(|left, right| left.id().cmp(right.id()));
    super::route_ownership::validate_inventory(&prospective)
}

/// Test-only compatibility wrapper that copies `<source_dir>/skill.yaml`
/// (+ any sibling files) into
/// `<target_skills_dir>/<id>/`, where `<id>` is the manifest's id
/// field. Validates the manifest before the copy starts — a broken
/// YAML never lands in the operator's skills dir.
///
/// `replace_existing = false` errors when the target id already exists;
/// `true` stages the replacement and keeps the prior tree available for
/// rollback until commit. Operators get the safe behaviour by default; the
/// CLI exposes `--force` to enable replacement.
#[cfg(test)]
pub(crate) fn install_from_local(
    source_dir: &Path,
    target_skills_dir: &Path,
    replace_existing: bool,
) -> Result<InstallReport> {
    install_from_local_with_expectation(source_dir, target_skills_dir, replace_existing, None)
}

#[cfg(test)]
pub(crate) fn install_from_local_with_expectation(
    source_dir: &Path,
    target_skills_dir: &Path,
    replace_existing: bool,
    expectation: Option<&InstallExpectation>,
) -> Result<InstallReport> {
    let operation_id = uuid::Uuid::now_v7().simple().to_string();
    let mut prepared = prepare_install_from_local_with_expectation(
        source_dir,
        target_skills_dir,
        replace_existing,
        expectation,
        &operation_id,
    )?;
    prepared.mark_intent_submitting()?;
    prepared.mark_intent_durable()?;
    let report = prepared
        .commit()
        .map_err(SkillMutationCommitError::into_inner)?;
    acknowledge_test_skill_mutation(target_skills_dir)?;
    Ok(report)
}

/// Validate and privately stage an install while retaining the cross-process
/// mutation lock. This performs no public Skill mutation. The returned binding
/// is therefore the only race-free payload that may be durably ACKed as the
/// corresponding install intent.
pub(crate) fn prepare_install_from_local_with_expectation(
    source_dir: &Path,
    target_skills_dir: &Path,
    replace_existing: bool,
    expectation: Option<&InstallExpectation>,
    operation_id: &str,
) -> Result<PreparedSkillInstall> {
    prepare_install_from_local_with_expectation_and_origin(
        source_dir,
        target_skills_dir,
        replace_existing,
        expectation,
        operation_id,
        SkillMutationOrigin::CliInstall,
    )
}

pub(crate) fn prepare_install_from_local_with_expectation_and_origin(
    source_dir: &Path,
    target_skills_dir: &Path,
    replace_existing: bool,
    expectation: Option<&InstallExpectation>,
    operation_id: &str,
    origin: SkillMutationOrigin,
) -> Result<PreparedSkillInstall> {
    validate_mutation_operation_id(operation_id)?;
    // Re-open and revalidate after any GUI confirmation. Consent is bound to
    // both the exact manifest bytes and their declared id before the target
    // namespace is opened or changed.
    let ValidatedInstallSource {
        source,
        manifest,
        manifest_bytes,
        manifest_sha256,
        generation_sha256,
    } = validate_local_source(source_dir)?;
    if let Some(expectation) = expectation {
        super::creator::validate_skill_id(&expectation.id).context("validate expected skill id")?;
        if expectation.source_generation_sha256.len() != 64
            || !expectation
                .source_generation_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            anyhow::bail!("expected generation SHA-256 must be 64 lowercase hex characters");
        }
        if expectation
            .target_generation_sha256
            .as_ref()
            .is_some_and(|digest| {
                digest.len() != 64
                    || !digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
        {
            anyhow::bail!("expected target generation SHA-256 must be 64 lowercase hex characters");
        }
        if expectation.id != manifest.id
            || expectation.source_generation_sha256 != generation_sha256
        {
            anyhow::bail!(
                "skill install source changed after preflight; inspect it again before installing"
            );
        }
    }

    let target_root = open_or_create_bound_skills_root(target_skills_dir)?;
    let _mutation_guard = lock_skill_mutations(&target_root)?;
    recover_pending_transactions_locked(&target_root)?;
    validate_prospective_route_ownership(Some(&target_root), &manifest)?;
    let target_dir = target_root.display_path.join(&manifest.id);
    let replaced_generation_sha256 = target_generation_locked(&target_root, &manifest.id)?;
    let replacing = replaced_generation_sha256.is_some();
    let kind = if replacing {
        SkillMutationKind::Replace
    } else {
        SkillMutationKind::Install
    };
    let target_identity = if replacing {
        Some(bind_real_child_dir(
            &target_root.dir,
            OsStr::new(&manifest.id),
            &target_dir,
        )?)
    } else {
        None
    };
    if let Some(expectation) = expectation
        && expectation.target_generation_sha256 != replaced_generation_sha256
    {
        anyhow::bail!(
            "skill install destination changed after preflight; inspect it again before installing"
        );
    }
    if replacing && !replace_existing {
        anyhow::bail!(
            "skill `{}` already installed at `{}`; pass --force to replace",
            manifest.id,
            target_dir.display()
        );
    }

    let incarnation = super::mutation_lifecycle::prepare_skill_mutation_incarnation(
        target_skills_dir,
        &manifest.id,
        kind,
    )?;
    // Copy into a private sibling first. A parse/read/copy failure never
    // exposes a partial skill directory and never destroys the prior install.
    let (stage_name, backup_candidate, stage_dir) =
        create_install_transaction(&target_root.dir, &manifest.id, operation_id)?;
    let stage_display = target_root.display_path.join(&stage_name);
    let copy_result = copy_dir_recursive(
        &source.dir,
        &stage_dir,
        &source.display_path,
        &stage_display,
        Some(RootFileOverride {
            name: OsStr::new("skill.yaml"),
            bytes: &manifest_bytes,
        }),
        0,
        &mut CopyBudget::default(),
    )
    .and_then(|()| {
        let staged = read_regular_file_bounded(
            &stage_dir,
            OsStr::new("skill.yaml"),
            &stage_display.join("skill.yaml"),
            MAX_SKILL_MANIFEST_BYTES,
        )?;
        if staged != manifest_bytes {
            anyhow::bail!("staged skill manifest differs from the validated generation");
        }
        let staged_generation = skill_tree_generation_sha256(&stage_dir, &stage_display, None)?;
        if staged_generation != generation_sha256 {
            anyhow::bail!("staged skill package differs from the preflight-validated generation");
        }
        Ok(())
    });
    drop(stage_dir);
    if let Err(copy_error) = copy_result {
        return Err(cleanup_after_failed_operation(
            copy_error,
            &target_root.dir,
            &stage_name,
            "partial skill staging directory",
        ));
    }
    let stage_identity = match bind_real_child_dir(&target_root.dir, &stage_name, &stage_display) {
        Ok(identity) => identity,
        Err(error) => {
            return Err(cleanup_after_failed_operation(
                error.context("bind the exact prepared Skill staging object"),
                &target_root.dir,
                &stage_name,
                "prepared skill staging directory",
            ));
        }
    };
    sync_directory(&target_root.dir, &target_root.display_path)?;

    let journal = SkillMutationJournal {
        version: SKILL_MUTATION_JOURNAL_VERSION,
        operation_id: operation_id.to_string(),
        kind,
        origin,
        skill_id: manifest.id.clone(),
        mutation_sequence: Some(incarnation.mutation_sequence),
        previous_terminal_receipt_sha256: incarnation.previous_terminal_receipt_sha256,
        prior_install_incarnation: incarnation.prior_install_incarnation,
        resulting_install_incarnation: incarnation.resulting_install_incarnation,
        source_generation_sha256: Some(generation_sha256.clone()),
        prior_generation_sha256: replaced_generation_sha256.clone(),
        prior_object_identity: target_identity
            .as_ref()
            .map(|identity| identity.identity_token().to_string()),
        intent_delivery_owner_nonce: None,
        intent_receipt: None,
        commit_boundary_nonce: None,
        phase: SkillMutationPhase::Prepared,
        observed_generation_sha256: None,
        error_sha256: None,
        terminal_delivery_state: SkillTerminalDeliveryState::NotStarted,
        terminal_delivery_owner_nonce: None,
        terminal_receipt: None,
        cleanup_started: None,
        created_at_unix: crate::time::now_unix_i64(),
    };
    if let Err(error) = persist_skill_mutation_journal(&target_root, &journal) {
        if target_root
            .dir
            .symlink_metadata(OsStr::new(SKILL_MUTATION_JOURNAL_FILE))
            .is_ok()
        {
            return Err(error.context(
                "prepared skill mutation journal may be durable; private stage retained for recovery",
            ));
        }
        return Err(cleanup_after_failed_operation(
            error,
            &target_root.dir,
            &stage_name,
            "prepared skill staging directory",
        ));
    }

    Ok(PreparedSkillInstall {
        target_root,
        _mutation_guard,
        journal,
        target_identity,
        stage_identity,
        id: manifest.id,
        manifest_sha256,
        generation_sha256,
        stage_name,
        backup_candidate,
        replaced_generation_sha256,
    })
}

/// Prepare one generated/runtime document write as a complete package
/// replacement. Existing packages are cloned through bound, no-follow handles
/// while the mutation lock is held; only the typed root document is
/// substituted. Sibling assets therefore survive byte-for-byte and the WAL
/// binding covers the resulting full package generation.
pub(crate) fn prepare_skill_document_mutation(
    request: &SkillDocumentMutationRequest,
    operation_id: &str,
) -> Result<PreparedSkillDocumentMutation> {
    validate_mutation_operation_id(operation_id)?;
    super::creator::validate_skill_id(&request.id).context("validate generated Skill id")?;
    let document_name = request.document.file_name();
    let document_display_name = request.document.display_name();
    let document_limit = match request.document {
        SkillPackageDocument::Manifest => MAX_SKILL_MANIFEST_BYTES,
        SkillPackageDocument::Instructions => MAX_SKILL_FILE_BYTES as usize,
    };
    if request.replacement.len() > document_limit {
        anyhow::bail!(
            "{document_display_name} exceeds the {document_limit}-byte installed-Skill limit"
        );
    }
    if request.document == SkillPackageDocument::Instructions {
        std::str::from_utf8(&request.replacement)
            .context("generated skill.md replacement is not valid UTF-8")?;
    }
    if let Some(expected) = request
        .expected_target_generation_sha256
        .as_ref()
        .and_then(Option::as_ref)
        && !valid_sha256(expected)
    {
        anyhow::bail!(
            "expected installed-Skill package generation must be 64 lowercase hex characters"
        );
    }
    let prospective_manifest = if request.document == SkillPackageDocument::Manifest {
        let manifest: SkillManifest = serde_yaml::from_slice(&request.replacement)
            .context("parse generated skill manifest before staging")?;
        if manifest.id != request.id {
            anyhow::bail!(
                "generated skill manifest id `{}` does not match target directory `{}`",
                manifest.id,
                request.id
            );
        }
        if manifest.description.trim().is_empty() {
            anyhow::bail!("generated skill manifest description must not be empty");
        }
        Some(manifest)
    } else {
        None
    };

    let target_root = open_or_create_bound_skills_root(&request.target_skills_dir)?;
    let mutation_guard = lock_skill_mutations(&target_root)?;
    recover_pending_transactions_locked(&target_root)?;
    if let Some(manifest) = prospective_manifest.as_ref() {
        validate_prospective_route_ownership(Some(&target_root), manifest)?;
    }
    let target_display = target_root.display_path.join(&request.id);
    let replaced_generation_sha256 = installed_entry_generation_locked(&target_root, &request.id)?;
    let kind = if replaced_generation_sha256.is_some() {
        SkillMutationKind::Replace
    } else {
        SkillMutationKind::Install
    };
    if let Some(expected) = request.expected_target_generation_sha256.as_ref()
        && expected != &replaced_generation_sha256
    {
        return Err(super::store::ConditionalReplacePreconditionFailed::at(&target_display).into());
    }

    let target_identity = match replaced_generation_sha256.as_ref() {
        Some(_) => Some(bind_real_child_dir(
            &target_root.dir,
            OsStr::new(&request.id),
            &target_display,
        )?),
        None => None,
    };
    let source_directory = match replaced_generation_sha256.as_ref() {
        Some(_) => Some(open_real_child_dir(
            &target_root.dir,
            OsStr::new(&request.id),
            &target_display,
        )?),
        None => None,
    };

    if source_directory.is_none() && request.document != SkillPackageDocument::Manifest {
        anyhow::bail!(
            "cannot write {document_display_name} for absent installed Skill `{}`",
            request.id
        );
    }
    if let Some(source_directory) = source_directory.as_ref() {
        let document_display = target_display.join(document_name);
        let current = read_regular_file_bounded(
            source_directory,
            document_name,
            &document_display,
            document_limit,
        )
        .with_context(|| {
            format!(
                "read current installed-Skill {document_display_name} at {}",
                document_display.display()
            )
        })?;
        if request
            .expected_document
            .as_ref()
            .is_some_and(|expected| expected != &current)
        {
            return Err(
                super::store::ConditionalReplacePreconditionFailed::at(document_display).into(),
            );
        }
        match request.existing {
            super::creator::ExistingSkillPolicy::Refuse => {
                anyhow::bail!(
                    "skill `{}` already exists at `{}`; explicit replacement is required",
                    request.id,
                    target_display.display()
                );
            }
            super::creator::ExistingSkillPolicy::KeepIfIdentical => {
                if current != request.replacement {
                    anyhow::bail!(
                        "skill `{}` already exists with a different {document_display_name} at `{}`; explicit replacement preflight is required",
                        request.id,
                        document_display.display()
                    );
                }
            }
            super::creator::ExistingSkillPolicy::Replace => {}
        }
        if current == request.replacement
            && request.existing == super::creator::ExistingSkillPolicy::KeepIfIdentical
        {
            let manifest_display = target_display.join("skill.yaml");
            let manifest_bytes = read_regular_file_bounded(
                source_directory,
                OsStr::new("skill.yaml"),
                &manifest_display,
                MAX_SKILL_MANIFEST_BYTES,
            )?;
            let manifest: SkillManifest =
                serde_yaml::from_slice(&manifest_bytes).with_context(|| {
                    format!("parse installed manifest at {}", manifest_display.display())
                })?;
            if manifest.id != request.id {
                anyhow::bail!(
                    "installed manifest id `{}` does not match target directory `{}`",
                    manifest.id,
                    request.id
                );
            }
            let generation = replaced_generation_sha256
                .clone()
                .context("identical installed package generation is unexpectedly absent")?;
            return Ok(PreparedSkillDocumentMutation::Unchanged(InstallReport {
                id: request.id.clone(),
                installed_at: target_display,
                replaced_existing: false,
                source_manifest_sha256: hex::encode(Sha256::digest(&manifest_bytes)),
                source_generation_sha256: generation,
                replaced_generation_sha256: None,
                warnings: Vec::new(),
            }));
        }
    }

    let incarnation = super::mutation_lifecycle::prepare_skill_mutation_incarnation(
        &request.target_skills_dir,
        &request.id,
        kind,
    )?;
    let (stage_name, backup_candidate, stage_dir) =
        create_install_transaction(&target_root.dir, &request.id, operation_id)?;
    let stage_display = target_root.display_path.join(&stage_name);
    let stage_result = match source_directory.as_ref() {
        Some(source_directory) => copy_dir_recursive(
            source_directory,
            &stage_dir,
            &target_display,
            &stage_display,
            Some(RootFileOverride {
                name: document_name,
                bytes: &request.replacement,
            }),
            0,
            &mut CopyBudget::default(),
        ),
        None => write_regular_file_create_new(
            &stage_dir,
            OsStr::new("skill.yaml"),
            &request.replacement,
            &stage_display.join("skill.yaml"),
            None,
        ),
    }
    .and_then(|()| sync_directory(&stage_dir, &stage_display))
    .and_then(|()| {
        let manifest_display = stage_display.join("skill.yaml");
        let manifest_bytes = read_regular_file_bounded(
            &stage_dir,
            OsStr::new("skill.yaml"),
            &manifest_display,
            MAX_SKILL_MANIFEST_BYTES,
        )?;
        let manifest: SkillManifest =
            serde_yaml::from_slice(&manifest_bytes).with_context(|| {
                format!(
                    "parse staged skill manifest at {}",
                    manifest_display.display()
                )
            })?;
        if manifest.id != request.id {
            anyhow::bail!(
                "staged skill manifest id `{}` does not match target directory `{}`",
                manifest.id,
                request.id
            );
        }
        if manifest.description.trim().is_empty() {
            anyhow::bail!("staged skill manifest description must not be empty");
        }
        let generation = skill_tree_generation_sha256(&stage_dir, &stage_display, None)?;
        Ok((manifest_bytes, generation))
    });
    drop(stage_dir);
    let (manifest_bytes, generation_sha256) = match stage_result {
        Ok(staged) => staged,
        Err(error) => {
            return Err(cleanup_after_failed_operation(
                error,
                &target_root.dir,
                &stage_name,
                "prepared generated-Skill staging directory",
            ));
        }
    };
    let manifest_sha256 = hex::encode(Sha256::digest(&manifest_bytes));
    let stage_identity = match bind_real_child_dir(&target_root.dir, &stage_name, &stage_display) {
        Ok(identity) => identity,
        Err(error) => {
            return Err(cleanup_after_failed_operation(
                error.context("bind exact generated-Skill staging object"),
                &target_root.dir,
                &stage_name,
                "prepared generated-Skill staging directory",
            ));
        }
    };
    sync_directory(&target_root.dir, &target_root.display_path)?;

    let journal = SkillMutationJournal {
        version: SKILL_MUTATION_JOURNAL_VERSION,
        operation_id: operation_id.to_string(),
        kind,
        origin: request.origin,
        skill_id: request.id.clone(),
        mutation_sequence: Some(incarnation.mutation_sequence),
        previous_terminal_receipt_sha256: incarnation.previous_terminal_receipt_sha256,
        prior_install_incarnation: incarnation.prior_install_incarnation,
        resulting_install_incarnation: incarnation.resulting_install_incarnation,
        source_generation_sha256: Some(generation_sha256.clone()),
        prior_generation_sha256: replaced_generation_sha256.clone(),
        prior_object_identity: target_identity
            .as_ref()
            .map(|identity| identity.identity_token().to_string()),
        intent_delivery_owner_nonce: None,
        intent_receipt: None,
        commit_boundary_nonce: None,
        phase: SkillMutationPhase::Prepared,
        observed_generation_sha256: None,
        error_sha256: None,
        terminal_delivery_state: SkillTerminalDeliveryState::NotStarted,
        terminal_delivery_owner_nonce: None,
        terminal_receipt: None,
        cleanup_started: None,
        created_at_unix: crate::time::now_unix_i64(),
    };
    if let Err(error) = persist_skill_mutation_journal(&target_root, &journal) {
        if target_root
            .dir
            .symlink_metadata(OsStr::new(SKILL_MUTATION_JOURNAL_FILE))
            .is_ok()
        {
            return Err(error.context(
                "generated Skill mutation journal may be durable; private stage retained for recovery",
            ));
        }
        return Err(cleanup_after_failed_operation(
            error,
            &target_root.dir,
            &stage_name,
            "prepared generated-Skill staging directory",
        ));
    }

    Ok(PreparedSkillDocumentMutation::Prepared(Box::new(
        PreparedSkillInstall {
            target_root,
            _mutation_guard: mutation_guard,
            journal,
            target_identity,
            stage_identity,
            id: request.id.clone(),
            manifest_sha256,
            generation_sha256,
            stage_name,
            backup_candidate,
            replaced_generation_sha256,
        },
    )))
}

fn persist_skill_mutation_failure(
    root: &BoundDirectory,
    journal: &mut SkillMutationJournal,
    state: SkillMutationFailureState,
    observed_generation_sha256: Option<String>,
    error: anyhow::Error,
) -> SkillMutationCommitError {
    let error_sha256 = hex::encode(Sha256::digest(format!("{error:#}").as_bytes()));
    let phase = match state {
        SkillMutationFailureState::Aborted => SkillMutationPhase::Aborted,
        SkillMutationFailureState::Indeterminate => SkillMutationPhase::Indeterminate,
    };
    match transition_skill_mutation_phase(
        root,
        journal,
        phase,
        observed_generation_sha256,
        Some(error_sha256),
    ) {
        Ok(()) => match state {
            SkillMutationFailureState::Aborted => SkillMutationCommitError::aborted(error),
            SkillMutationFailureState::Indeterminate => {
                SkillMutationCommitError::indeterminate(error)
            }
        },
        Err(journal_error) => SkillMutationCommitError::indeterminate(error.context(format!(
            "persist terminal skill mutation phase `{}` failed; journal retained for reconciliation: {journal_error:#}",
            phase.as_str()
        ))),
    }
}

impl PreparedSkillInstall {
    /// Publish the prepared generation while the same mutation lock remains
    /// held. For replacement the old public anchor is moved to a private
    /// rollback name first; the new public `<skills>/<id>` anchor is the last
    /// visible rename and therefore the commit point.
    pub(crate) fn commit(mut self) -> std::result::Result<InstallReport, SkillMutationCommitError> {
        let target_dir = self.target_root.display_path.join(&self.id);
        let stage_display = self.target_root.display_path.join(&self.stage_name);
        let replacing = self.replaced_generation_sha256.is_some();

        if let Err(error) = transition_skill_mutation_phase(
            &self.target_root,
            &mut self.journal,
            SkillMutationPhase::CommitStarted,
            None,
            None,
        ) {
            return Err(persist_skill_mutation_failure(
                &self.target_root,
                &mut self.journal,
                SkillMutationFailureState::Aborted,
                self.replaced_generation_sha256.clone(),
                error.context("persist commit-start boundary before skill namespace mutation"),
            ));
        }

        let mut backup_name = None;
        if replacing {
            if let Err(error) = (|| -> Result<()> {
                let target_identity = self
                    .target_identity
                    .as_ref()
                    .context("prepared replacement is missing its bound target identity")?;
                if !target_identity.matches_directory_child(
                    &self.target_root.dir,
                    OsStr::new(&self.id),
                    &target_dir,
                )? {
                    anyhow::bail!(
                        "skill `{}` target identity changed before replacement commit",
                        self.id
                    );
                }
                if target_generation_locked(&self.target_root, &self.id)?
                    != self.replaced_generation_sha256
                {
                    anyhow::bail!(
                        "skill `{}` destination changed while staging; refusing the stale replacement",
                        self.id
                    );
                }
                if !target_identity.matches_directory_child(
                    &self.target_root.dir,
                    OsStr::new(&self.id),
                    &target_dir,
                )? {
                    anyhow::bail!(
                        "skill `{}` target identity changed while its generation was revalidated",
                        self.id
                    );
                }
                maybe_inject_final_lookup_swap(
                    &self.target_root,
                    &self.id,
                    FinalLookupSwapPoint::Replace,
                )?;
                rename_child(
                    &self.target_root.dir,
                    OsStr::new(&self.id),
                    &self.target_root.dir,
                    &self.backup_candidate,
                    false,
                    &target_dir,
                    &self.target_root.display_path.join(&self.backup_candidate),
                )
                .with_context(|| format!("stage prior install at {}", target_dir.display()))
            })() {
                return Err(persist_skill_mutation_failure(
                    &self.target_root,
                    &mut self.journal,
                    SkillMutationFailureState::Aborted,
                    self.replaced_generation_sha256.clone(),
                    error,
                ));
            }
            backup_name = Some(self.backup_candidate.clone());
            let moved_prior = (|| -> Result<()> {
                let target_identity = self
                    .target_identity
                    .as_ref()
                    .context("prepared replacement is missing its bound target identity")?;
                let backup_display = self.target_root.display_path.join(&self.backup_candidate);
                if !target_identity.matches_directory_child(
                    &self.target_root.dir,
                    &self.backup_candidate,
                    &backup_display,
                )? {
                    anyhow::bail!(
                        "replacement rename moved a different object than the preflight-bound target"
                    );
                }
                let backup_name = self
                    .backup_candidate
                    .to_str()
                    .context("private replacement backup name is not UTF-8")?;
                if installed_entry_generation_at_locked(&self.target_root, backup_name, &self.id)?
                    != self.replaced_generation_sha256
                {
                    anyhow::bail!(
                        "replacement backup generation differs from the preflight-bound target"
                    );
                }
                Ok(())
            })();
            if let Err(error) = moved_prior {
                return Err(persist_skill_mutation_failure(
                    &self.target_root,
                    &mut self.journal,
                    SkillMutationFailureState::Indeterminate,
                    installed_entry_generation_locked(&self.target_root, &self.id)
                        .ok()
                        .flatten(),
                    error.context(
                        "replacement final-lookup identity verification failed; private artifacts retained",
                    ),
                ));
            }
            if let Err(error) =
                sync_directory(&self.target_root.dir, &self.target_root.display_path)
            {
                return Err(persist_skill_mutation_failure(
                    &self.target_root,
                    &mut self.journal,
                    SkillMutationFailureState::Indeterminate,
                    None,
                    error.context(
                        "prior generation was moved to its private backup, but the parent directory was not durably synced",
                    ),
                ));
            }
        } else {
            match self.target_root.dir.symlink_metadata(&self.id) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Ok(_) => {
                    let error = anyhow::anyhow!(
                        "skill `{}` appeared at `{}` during install; refusing to replace it",
                        self.id,
                        target_dir.display()
                    );
                    return Err(persist_skill_mutation_failure(
                        &self.target_root,
                        &mut self.journal,
                        SkillMutationFailureState::Aborted,
                        installed_entry_generation_locked(&self.target_root, &self.id)
                            .ok()
                            .flatten(),
                        error,
                    ));
                }
                Err(error) => {
                    let error = anyhow::Error::new(error).context(format!(
                        "recheck target before commit at {}",
                        target_dir.display()
                    ));
                    return Err(persist_skill_mutation_failure(
                        &self.target_root,
                        &mut self.journal,
                        SkillMutationFailureState::Aborted,
                        None,
                        error,
                    ));
                }
            }
        }

        let publish_result = (|| -> Result<()> {
            if !self.stage_identity.matches_directory_child(
                &self.target_root.dir,
                &self.stage_name,
                &stage_display,
            )? {
                anyhow::bail!("prepared Skill staging object identity changed before publication");
            }
            let stage_name = self
                .stage_name
                .to_str()
                .context("private install stage name is not UTF-8")?;
            if installed_entry_generation_locked(&self.target_root, stage_name)?
                != Some(self.generation_sha256.clone())
            {
                anyhow::bail!("prepared Skill staging generation changed before publication");
            }
            if !self.stage_identity.matches_directory_child(
                &self.target_root.dir,
                &self.stage_name,
                &stage_display,
            )? {
                anyhow::bail!(
                    "prepared Skill staging object identity changed while its generation was revalidated"
                );
            }
            rename_child(
                &self.target_root.dir,
                &self.stage_name,
                &self.target_root.dir,
                OsStr::new(&self.id),
                false,
                &stage_display,
                &target_dir,
            )
            .with_context(|| format!("commit staged skill at {}", target_dir.display()))?;
            if !self.stage_identity.matches_directory_child(
                &self.target_root.dir,
                OsStr::new(&self.id),
                &target_dir,
            )? {
                anyhow::bail!(
                    "Skill publication rename moved a different object than the prepared stage"
                );
            }
            if installed_entry_generation_locked(&self.target_root, &self.id)?
                != Some(self.generation_sha256.clone())
            {
                anyhow::bail!(
                    "published Skill generation differs from the exact prepared generation"
                );
            }
            Ok(())
        })();
        if let Err(commit_error) = publish_result {
            let mut error = commit_error;
            let stage_may_have_moved = match self.target_root.dir.symlink_metadata(&self.stage_name)
            {
                Ok(_) => false,
                Err(stage_error) if stage_error.kind() == std::io::ErrorKind::NotFound => true,
                Err(_) => true,
            };
            let mut state = if stage_may_have_moved {
                SkillMutationFailureState::Indeterminate
            } else {
                SkillMutationFailureState::Aborted
            };
            let mut observed = installed_entry_generation_locked(&self.target_root, &self.id)
                .ok()
                .flatten();
            if let Some(backup) = backup_name.as_ref() {
                let rollback = (|| -> Result<()> {
                    let target_identity = self
                        .target_identity
                        .as_ref()
                        .context("replacement rollback lacks its bound prior identity")?;
                    let backup_display = self.target_root.display_path.join(backup);
                    if !target_identity.matches_directory_child(
                        &self.target_root.dir,
                        backup,
                        &backup_display,
                    )? {
                        anyhow::bail!(
                            "replacement rollback object no longer matches the preflight-bound target"
                        );
                    }
                    let backup_name = backup
                        .to_str()
                        .context("private replacement backup name is not UTF-8")?;
                    if installed_entry_generation_at_locked(
                        &self.target_root,
                        backup_name,
                        &self.id,
                    )? != self.replaced_generation_sha256
                    {
                        anyhow::bail!(
                            "replacement rollback generation no longer matches the preflight-bound target"
                        );
                    }
                    rename_child(
                        &self.target_root.dir,
                        backup,
                        &self.target_root.dir,
                        OsStr::new(&self.id),
                        false,
                        &backup_display,
                        &target_dir,
                    )?;
                    if !target_identity.matches_directory_child(
                        &self.target_root.dir,
                        OsStr::new(&self.id),
                        &target_dir,
                    )? {
                        anyhow::bail!(
                            "replacement rollback rename restored a different object than the bound prior target"
                        );
                    }
                    if installed_entry_generation_locked(&self.target_root, &self.id)?
                        != self.replaced_generation_sha256
                    {
                        anyhow::bail!(
                            "replacement rollback restored a generation other than the bound prior target"
                        );
                    }
                    sync_directory(&self.target_root.dir, &self.target_root.display_path)
                        .context("sync restored prior Skill generation")
                })();
                match rollback {
                    Ok(()) => {
                        state = SkillMutationFailureState::Aborted;
                        observed = self.replaced_generation_sha256.clone();
                    }
                    Err(rollback_error) => {
                        state = SkillMutationFailureState::Indeterminate;
                        observed = installed_entry_generation_locked(&self.target_root, &self.id)
                            .ok()
                            .flatten();
                        error = error.context(format!(
                            "rollback also failed for prior install at {}: {rollback_error}",
                            target_dir.display()
                        ));
                    }
                }
            }
            return Err(persist_skill_mutation_failure(
                &self.target_root,
                &mut self.journal,
                state,
                observed,
                error,
            ));
        }

        if let Err(error) = sync_directory(&self.target_root.dir, &self.target_root.display_path) {
            return Err(persist_skill_mutation_failure(
                &self.target_root,
                &mut self.journal,
                SkillMutationFailureState::Indeterminate,
                Some(self.generation_sha256.clone()),
                error.context(
                    "new public skill generation is visible, but its parent directory was not durably synced",
                ),
            ));
        }
        if let Err(error) = transition_skill_mutation_phase(
            &self.target_root,
            &mut self.journal,
            SkillMutationPhase::Committed,
            Some(self.generation_sha256.clone()),
            None,
        ) {
            return Err(persist_skill_mutation_failure(
                &self.target_root,
                &mut self.journal,
                SkillMutationFailureState::Indeterminate,
                Some(self.generation_sha256.clone()),
                error.context(
                    "public skill generation is durable, but its committed outbox phase was not",
                ),
            ));
        }

        // Backup/stage cleanup is intentionally deferred until the correlated
        // terminal WAL frame is proven present. Cancellation after this return
        // therefore retains everything required for same-operation recovery.
        Ok(InstallReport {
            id: self.id,
            installed_at: target_dir,
            replaced_existing: replacing,
            source_manifest_sha256: self.manifest_sha256,
            source_generation_sha256: self.generation_sha256,
            replaced_generation_sha256: self.replaced_generation_sha256,
            warnings: Vec::new(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UninstallReport {
    pub id: String,
    pub removed: bool,
    /// Exact public generation removed by this operation, or `None` for an
    /// idempotent direct-CLI no-op on an already-absent id.
    pub removed_generation_sha256: Option<String>,
    /// Non-fatal durability/cleanup warnings after the public name is gone.
    pub warnings: Vec<String>,
}

/// Test-only compatibility wrapper for assertions that only need the
/// desired-state bit. Production operator surfaces use the prepared
/// intent/commit contract below.
#[cfg(test)]
pub(crate) fn uninstall(target_skills_dir: &Path, id: &str) -> Result<bool> {
    Ok(uninstall_with_report(target_skills_dir, id)?.removed)
}

#[cfg(test)]
pub(crate) fn uninstall_with_report(target_skills_dir: &Path, id: &str) -> Result<UninstallReport> {
    uninstall_with_report_and_expectation(target_skills_dir, id, None)
}

#[cfg(test)]
pub(crate) fn uninstall_with_report_and_expectation(
    target_skills_dir: &Path,
    id: &str,
    expectation: Option<&UninstallExpectation>,
) -> Result<UninstallReport> {
    let operation_id = uuid::Uuid::now_v7().simple().to_string();
    let mut prepared = match prepare_uninstall_with_expectation(
        target_skills_dir,
        id,
        expectation,
        &operation_id,
    )? {
        PreparedSkillRemovalOutcome::Unchanged(report) => return Ok(report),
        PreparedSkillRemovalOutcome::Prepared(prepared) => *prepared,
    };
    prepared.mark_intent_submitting()?;
    prepared.mark_intent_durable()?;
    let report = prepared
        .commit()
        .map_err(SkillMutationCommitError::into_inner)?;
    acknowledge_test_skill_mutation(target_skills_dir)?;
    Ok(report)
}

#[cfg(test)]
fn acknowledge_test_skill_mutation(target_skills_dir: &Path) -> Result<()> {
    let pending = open_pending_skill_mutation_reconciliation(target_skills_dir)?
        .context("test mutation unexpectedly lacks its terminal journal")?;
    pending.acknowledge_terminal()
}

/// Capture the exact public anchor under the mutation lock without changing
/// it. Callers must durably ACK [`PreparedSkillRemoval::intent_binding`] before
/// invoking the commit.
pub(crate) fn prepare_uninstall_with_expectation(
    target_skills_dir: &Path,
    id: &str,
    expectation: Option<&UninstallExpectation>,
    operation_id: &str,
) -> Result<PreparedSkillRemovalOutcome> {
    prepare_uninstall_with_expectation_and_origin(
        target_skills_dir,
        id,
        expectation,
        operation_id,
        SkillMutationOrigin::CliUninstall,
    )
}

pub(crate) fn prepare_uninstall_with_expectation_and_origin(
    target_skills_dir: &Path,
    id: &str,
    expectation: Option<&UninstallExpectation>,
    operation_id: &str,
    origin: SkillMutationOrigin,
) -> Result<PreparedSkillRemovalOutcome> {
    validate_mutation_operation_id(operation_id)?;
    validate_installed_skill_dir_name(id)?;
    if let Some(expectation) = expectation {
        validate_installed_skill_dir_name(&expectation.id)?;
        if expectation.id != id {
            anyhow::bail!("skill uninstall expectation id does not match the requested id");
        }
        if !valid_sha256(&expectation.target_generation_sha256) {
            anyhow::bail!(
                "expected uninstall generation SHA-256 must be 64 lowercase hex characters"
            );
        }
    }

    let root = open_or_create_bound_skills_root(target_skills_dir)?;
    let mutation_guard = lock_skill_mutations(&root)?;
    recover_pending_transactions_locked(&root)?;
    let target_generation_sha256 = installed_entry_generation_locked(&root, id)?;
    if let Some(expectation) = expectation
        && target_generation_sha256.as_deref()
            != Some(expectation.target_generation_sha256.as_str())
    {
        anyhow::bail!(
            "skill uninstall destination changed after preflight; inspect it again before uninstalling"
        );
    }
    let Some(target_generation_sha256) = target_generation_sha256 else {
        return Ok(PreparedSkillRemovalOutcome::Unchanged(UninstallReport {
            id: id.to_string(),
            removed: false,
            removed_generation_sha256: None,
            warnings: Vec::new(),
        }));
    };
    validate_prospective_route_reduction_locked(&root, id)?;
    let incarnation = super::mutation_lifecycle::prepare_skill_mutation_incarnation(
        target_skills_dir,
        id,
        SkillMutationKind::Remove,
    )?;
    let target_identity =
        bind_child_object(&root.dir, OsStr::new(id), &root.display_path.join(id))?;

    let journal = SkillMutationJournal {
        version: SKILL_MUTATION_JOURNAL_VERSION,
        operation_id: operation_id.to_string(),
        kind: SkillMutationKind::Remove,
        origin,
        skill_id: id.to_string(),
        mutation_sequence: Some(incarnation.mutation_sequence),
        previous_terminal_receipt_sha256: incarnation.previous_terminal_receipt_sha256,
        prior_install_incarnation: incarnation.prior_install_incarnation,
        resulting_install_incarnation: incarnation.resulting_install_incarnation,
        source_generation_sha256: None,
        prior_generation_sha256: Some(target_generation_sha256.clone()),
        prior_object_identity: Some(target_identity.identity_token().to_string()),
        intent_delivery_owner_nonce: None,
        intent_receipt: None,
        commit_boundary_nonce: None,
        phase: SkillMutationPhase::Prepared,
        observed_generation_sha256: None,
        error_sha256: None,
        terminal_delivery_state: SkillTerminalDeliveryState::NotStarted,
        terminal_delivery_owner_nonce: None,
        terminal_receipt: None,
        cleanup_started: None,
        created_at_unix: crate::time::now_unix_i64(),
    };
    persist_skill_mutation_journal(&root, &journal)?;

    Ok(PreparedSkillRemovalOutcome::Prepared(Box::new(
        PreparedSkillRemoval {
            root,
            _mutation_guard: mutation_guard,
            journal,
            target_identity,
            id: id.to_string(),
            target_generation_sha256,
        },
    )))
}

impl PreparedSkillRemoval {
    /// Remove the public anchor while the same preparation lock is held.
    /// Directory installs commit as one rename to a private tombstone; broken
    /// leaf entries commit as one no-follow unlink.
    pub(crate) fn commit(
        mut self,
    ) -> std::result::Result<UninstallReport, SkillMutationCommitError> {
        let target = self.root.display_path.join(&self.id);
        if let Err(error) = transition_skill_mutation_phase(
            &self.root,
            &mut self.journal,
            SkillMutationPhase::CommitStarted,
            None,
            None,
        ) {
            return Err(persist_skill_mutation_failure(
                &self.root,
                &mut self.journal,
                SkillMutationFailureState::Aborted,
                Some(self.target_generation_sha256.clone()),
                error.context("persist commit-start boundary before skill removal"),
            ));
        }

        let bound_identity = &self.target_identity;
        let precommit = (|| -> Result<FinalLookupSwapPoint> {
            if !bound_identity.matches_child(&self.root.dir, OsStr::new(&self.id), &target)? {
                anyhow::bail!("skill uninstall target identity changed before commit");
            }
            let observed = installed_entry_generation_locked(&self.root, &self.id)?;
            if observed.as_deref() != Some(self.target_generation_sha256.as_str()) {
                anyhow::bail!(
                    "skill uninstall destination changed after its intent was acknowledged"
                );
            }
            if !bound_identity.matches_child(&self.root.dir, OsStr::new(&self.id), &target)? {
                anyhow::bail!(
                    "skill uninstall target identity changed while its generation was revalidated"
                );
            }
            let metadata =
                self.root.dir.symlink_metadata(&self.id).with_context(|| {
                    format!("inspect bound removal target {}", target.display())
                })?;
            Ok(
                if metadata.is_dir() && !cap_metadata_is_link_like(&metadata) {
                    FinalLookupSwapPoint::RemoveDirectory
                } else {
                    FinalLookupSwapPoint::RemoveLeaf
                },
            )
        })();
        let swap_point = match precommit {
            Ok(point) => point,
            Err(error) => {
                return Err(persist_skill_mutation_failure(
                    &self.root,
                    &mut self.journal,
                    SkillMutationFailureState::Aborted,
                    installed_entry_generation_locked(&self.root, &self.id)
                        .ok()
                        .flatten(),
                    error.context("revalidate bound skill removal object"),
                ));
            }
        };
        if let Err(error) = maybe_inject_final_lookup_swap(&self.root, &self.id, swap_point) {
            return Err(persist_skill_mutation_failure(
                &self.root,
                &mut self.journal,
                SkillMutationFailureState::Indeterminate,
                installed_entry_generation_locked(&self.root, &self.id)
                    .ok()
                    .flatten(),
                error.context("inject deterministic final-lookup removal swap"),
            ));
        }

        // Every removal, including broken leaves and reparse points, commits as
        // one no-follow rename to a private tombstone. Only the verified bound
        // object may later be recursively deleted.
        let tombstone = match allocate_delete_transaction_name(
            &self.root,
            &self.id,
            &self.journal.operation_id,
        ) {
            Ok(tombstone) => tombstone,
            Err(error) => {
                return Err(persist_skill_mutation_failure(
                    &self.root,
                    &mut self.journal,
                    SkillMutationFailureState::Aborted,
                    Some(self.target_generation_sha256.clone()),
                    error,
                ));
            }
        };
        let tombstone_path = self.root.display_path.join(&tombstone);
        if let Err(error) = rename_child(
            &self.root.dir,
            OsStr::new(&self.id),
            &self.root.dir,
            &tombstone,
            false,
            &target,
            &tombstone_path,
        )
        .with_context(|| format!("commit uninstall of {}", target.display()))
        {
            return Err(persist_skill_mutation_failure(
                &self.root,
                &mut self.journal,
                SkillMutationFailureState::Aborted,
                Some(self.target_generation_sha256.clone()),
                error,
            ));
        }
        let moved_target = (|| -> Result<()> {
            if !bound_identity.matches_child(&self.root.dir, &tombstone, &tombstone_path)? {
                anyhow::bail!(
                    "removal rename moved a different object than the preflight-bound target"
                );
            }
            let tombstone_name = tombstone
                .to_str()
                .context("private removal tombstone name is not UTF-8")?;
            if installed_entry_generation_at_locked(&self.root, tombstone_name, &self.id)?
                .as_deref()
                != Some(self.target_generation_sha256.as_str())
            {
                anyhow::bail!(
                    "removal tombstone generation differs from the preflight-bound target"
                );
            }
            Ok(())
        })();
        if let Err(error) = moved_target {
            return Err(persist_skill_mutation_failure(
                &self.root,
                &mut self.journal,
                SkillMutationFailureState::Indeterminate,
                installed_entry_generation_locked(&self.root, &self.id)
                    .ok()
                    .flatten(),
                error.context(
                    "removal final-lookup identity verification failed; tombstone retained",
                ),
            ));
        }
        if let Err(error) = sync_directory(&self.root.dir, &self.root.display_path) {
            return Err(persist_skill_mutation_failure(
                &self.root,
                &mut self.journal,
                SkillMutationFailureState::Indeterminate,
                None,
                error.context(format!(
                    "skill is absent, but its parent directory was not durably synced; \
                     private tombstone `{}` was retained",
                    tombstone_path.display()
                )),
            ));
        }

        if let Err(error) = transition_skill_mutation_phase(
            &self.root,
            &mut self.journal,
            SkillMutationPhase::Committed,
            None,
            None,
        ) {
            return Err(persist_skill_mutation_failure(
                &self.root,
                &mut self.journal,
                SkillMutationFailureState::Indeterminate,
                None,
                error.context("skill removal is durable, but its committed outbox phase was not"),
            ));
        }

        Ok(UninstallReport {
            id: self.id,
            removed: true,
            removed_generation_sha256: Some(self.target_generation_sha256),
            warnings: Vec::new(),
        })
    }
}

fn allocate_delete_transaction_name(
    root: &BoundDirectory,
    id: &str,
    operation_id: &str,
) -> Result<OsString> {
    let name = OsString::from(format!("{DELETE_TRANSACTION_PREFIX}{id}-{operation_id}"));
    match root.dir.symlink_metadata(&name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(name),
        Ok(_) => {
            anyhow::bail!("private uninstall transaction already exists for the prepared operation")
        }
        Err(error) => Err(error).context("inspect private uninstall transaction name"),
    }
}

fn mutation_install_stage_name(record: &SkillMutationJournal) -> OsString {
    OsString::from(format!(
        "{INSTALL_TRANSACTION_PREFIX}{}-{}",
        record.skill_id, record.operation_id
    ))
}

fn mutation_backup_name(record: &SkillMutationJournal) -> OsString {
    OsString::from(format!(
        "{BACKUP_TRANSACTION_PREFIX}{}-{}",
        record.skill_id, record.operation_id
    ))
}

fn mutation_tombstone_name(record: &SkillMutationJournal) -> OsString {
    OsString::from(format!(
        "{DELETE_TRANSACTION_PREFIX}{}-{}",
        record.skill_id, record.operation_id
    ))
}

fn private_artifact_exists(root: &BoundDirectory, name: &OsStr) -> Result<bool> {
    match root.dir.symlink_metadata(name) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| {
            format!(
                "inspect private skill artifact {}",
                root.display_path.join(name).display()
            )
        }),
    }
}

fn restore_prior_backup_if_present(
    root: &BoundDirectory,
    record: &SkillMutationJournal,
) -> Result<bool> {
    let Some(prior) = record.prior_generation_sha256.as_deref() else {
        return Ok(false);
    };
    let Some(prior_identity) = record.prior_object_identity.as_deref() else {
        anyhow::bail!(
            "skill mutation {} has a prior generation without a bound object identity",
            record.operation_id
        );
    };
    let backup = mutation_backup_name(record);
    if !private_artifact_exists(root, &backup)? {
        return Ok(false);
    }
    let backup_display = root.display_path.join(&backup);
    let bound_backup = bind_child_object(&root.dir, &backup, &backup_display)?;
    if bound_backup.identity_token() != prior_identity {
        return Ok(false);
    }
    let backup_generation = installed_entry_generation_at_locked(
        root,
        backup
            .to_str()
            .context("private skill backup name is not UTF-8")?,
        &record.skill_id,
    )?;
    if backup_generation.as_deref() != Some(prior) {
        anyhow::bail!(
            "private backup for skill mutation {} does not match its bound prior generation",
            record.operation_id
        );
    }
    if !bound_backup.matches_child(&root.dir, &backup, &backup_display)? {
        return Ok(false);
    }
    let current = installed_entry_generation_locked(root, &record.skill_id)?;
    if current.is_some() {
        return Ok(false);
    }
    if !bound_backup.matches_child(&root.dir, &backup, &backup_display)? {
        anyhow::bail!(
            "private backup identity changed at the final recovery lookup for {}",
            record.operation_id
        );
    }
    rename_child(
        &root.dir,
        &backup,
        &root.dir,
        OsStr::new(&record.skill_id),
        false,
        &root.display_path.join(&backup),
        &root.display_path.join(&record.skill_id),
    )
    .context("restore bound prior skill generation during reconciliation")?;
    if !bound_backup.matches_child(
        &root.dir,
        OsStr::new(&record.skill_id),
        &root.display_path.join(&record.skill_id),
    )? {
        anyhow::bail!(
            "restored public Skill object does not match the journal-bound prior object for {}",
            record.operation_id
        );
    }
    if installed_entry_generation_locked(root, &record.skill_id)?.as_deref() != Some(prior) {
        anyhow::bail!(
            "restored public Skill generation does not match the journal-bound prior generation for {}",
            record.operation_id
        );
    }
    sync_directory(&root.dir, &root.display_path)
        .context("sync restored prior skill generation during reconciliation")?;
    Ok(true)
}

fn restore_prior_removal_tombstone(
    root: &BoundDirectory,
    record: &SkillMutationJournal,
) -> Result<()> {
    if record.kind != SkillMutationKind::Remove {
        anyhow::bail!("skill mutation {} is not a removal", record.operation_id);
    }
    let prior = record
        .prior_generation_sha256
        .as_deref()
        .context("indeterminate skill removal lacks its bound prior generation")?;
    let prior_identity = record
        .prior_object_identity
        .as_deref()
        .context("indeterminate skill removal lacks its bound prior object identity")?;
    let expected_tombstone = mutation_tombstone_name(record);
    let entries = root.dir.entries().with_context(|| {
        format!(
            "enumerate removal tombstones under {}",
            root.display_path.display()
        )
    })?;
    let mut candidate_tombstones = Vec::<OsString>::new();
    let mut root_entry_count = 0usize;
    for entry in entries {
        root_entry_count = root_entry_count
            .checked_add(1)
            .context("removal tombstone recovery entry counter overflow")?;
        if root_entry_count > MAX_SKILL_ENTRIES {
            anyhow::bail!(
                "removal tombstone recovery under {} exceeds the {MAX_SKILL_ENTRIES}-entry limit",
                root.display_path.display()
            );
        }
        let entry = entry.with_context(|| {
            format!(
                "read removal tombstone candidate under {}",
                root.display_path.display()
            )
        })?;
        let name = entry.file_name();
        if parse_delete_transaction_artifact(&name)?.as_deref() == Some(record.skill_id.as_str()) {
            candidate_tombstones.push(name);
        }
    }
    match candidate_tombstones.as_slice() {
        [] => anyhow::bail!(
            "cannot restore indeterminate skill removal {}: operation-bound tombstone is missing",
            record.operation_id
        ),
        [only] if only != &expected_tombstone => anyhow::bail!(
            "cannot restore indeterminate skill removal {}: sole tombstone belongs to another operation",
            record.operation_id
        ),
        [_] => {}
        candidates => anyhow::bail!(
            "cannot restore indeterminate skill removal {}: {} candidate tombstones are ambiguous",
            record.operation_id,
            candidates.len()
        ),
    }

    let tombstone_display = root.display_path.join(&expected_tombstone);
    let bound_tombstone = bind_child_object(&root.dir, &expected_tombstone, &tombstone_display)?;
    if bound_tombstone.identity_token() != prior_identity {
        anyhow::bail!(
            "cannot restore indeterminate skill removal {}: tombstone is not the bound prior object",
            record.operation_id
        );
    }
    let tombstone_name = expected_tombstone
        .to_str()
        .context("private removal tombstone name is not UTF-8")?;
    if installed_entry_generation_at_locked(root, tombstone_name, &record.skill_id)?.as_deref()
        != Some(prior)
    {
        anyhow::bail!(
            "cannot restore indeterminate skill removal {}: tombstone does not match the bound v2 prior generation",
            record.operation_id
        );
    }
    if installed_entry_generation_locked(root, &record.skill_id)?.is_some() {
        anyhow::bail!(
            "cannot restore indeterminate skill removal {}: public anchor is no longer absent",
            record.operation_id
        );
    }
    if !bound_tombstone.matches_child(&root.dir, &expected_tombstone, &tombstone_display)? {
        anyhow::bail!(
            "cannot restore indeterminate skill removal {}: tombstone identity changed during verification",
            record.operation_id
        );
    }

    let public_display = root.display_path.join(&record.skill_id);
    rename_child(
        &root.dir,
        &expected_tombstone,
        &root.dir,
        OsStr::new(&record.skill_id),
        false,
        &tombstone_display,
        &public_display,
    )
    .context("atomically restore bound removal tombstone during reconciliation")?;
    if !bound_tombstone.matches_child(&root.dir, OsStr::new(&record.skill_id), &public_display)? {
        anyhow::bail!(
            "restored removal object does not match the journal-bound prior object for {}",
            record.operation_id
        );
    }
    if installed_entry_generation_locked(root, &record.skill_id)?.as_deref() != Some(prior) {
        anyhow::bail!(
            "restored removal generation does not match the journal-bound v2 prior generation for {}",
            record.operation_id
        );
    }
    sync_directory(&root.dir, &root.display_path)
        .context("sync restored prior skill removal generation during reconciliation")
}

fn public_anchor_matches_prior_binding(
    root: &BoundDirectory,
    record: &SkillMutationJournal,
    observed_generation: &Option<String>,
) -> Result<bool> {
    if observed_generation != &record.prior_generation_sha256 {
        return Ok(false);
    }
    match (
        record.prior_generation_sha256.as_ref(),
        record.prior_object_identity.as_deref(),
    ) {
        (None, None) => Ok(true),
        (Some(_), Some(expected_identity)) => {
            let display = root.display_path.join(&record.skill_id);
            let bound = bind_child_object(&root.dir, OsStr::new(&record.skill_id), &display)?;
            Ok(bound.identity_token() == expected_identity
                && bound.matches_child(&root.dir, OsStr::new(&record.skill_id), &display)?)
        }
        _ => anyhow::bail!(
            "skill mutation {} has inconsistent prior generation/object identity",
            record.operation_id
        ),
    }
}

/// Holds the same process + OS mutation lock while a crashed operation is
/// reconciled against both WAL evidence and the real public anchor.
pub(crate) struct PendingSkillMutationReconciliation {
    root: BoundDirectory,
    _mutation_guard: SkillMutationGuard,
    record: SkillMutationJournal,
}

pub(crate) fn open_pending_skill_mutation_reconciliation(
    target_skills_dir: &Path,
) -> Result<Option<PendingSkillMutationReconciliation>> {
    let Some(root) = open_bound_directory(target_skills_dir, false, "skills root")? else {
        return Ok(None);
    };
    let mutation_guard = lock_skill_mutations(&root)?;
    cleanup_skill_mutation_journal_stages_locked(&root)?;
    let Some(record) = read_skill_mutation_journal(&root)? else {
        recover_pending_transactions_locked(&root)?;
        return Ok(None);
    };
    Ok(Some(PendingSkillMutationReconciliation {
        root,
        _mutation_guard: mutation_guard,
        record,
    }))
}

impl PendingSkillMutationReconciliation {
    #[must_use]
    pub(crate) fn audit_binding(&self) -> SkillMutationAuditBinding {
        self.record.audit_binding()
    }

    #[must_use]
    pub(crate) fn intent_delivery_owned_by_current_process(&self) -> bool {
        self.record.phase == SkillMutationPhase::IntentSubmitting
            && self.record.intent_delivery_owner_nonce.as_deref()
                == Some(skill_mutation_process_nonce())
    }

    pub(crate) fn mark_intent_durable_authenticated(
        &mut self,
        receipt: SkillMutationAuditReceipt,
    ) -> Result<()> {
        if !matches!(
            self.record.phase,
            SkillMutationPhase::IntentSubmitting | SkillMutationPhase::IntentDurable
        ) {
            anyhow::bail!(
                "skill mutation {} cannot bind an intent receipt from phase {}",
                self.record.operation_id,
                self.record.phase.as_str()
            );
        }
        if let Some(existing) = self.record.intent_receipt.as_ref() {
            if existing != &receipt {
                anyhow::bail!(
                    "skill mutation {} conflicts with its persisted intent receipt",
                    self.record.operation_id
                );
            }
            return Ok(());
        }
        if receipt.audit_event_id != self.record.audit_binding().intent_audit_event_id() {
            anyhow::bail!(
                "skill mutation {} received an authenticated receipt for another intent",
                self.record.operation_id
            );
        }
        self.record.intent_receipt = Some(receipt);
        transition_skill_mutation_phase(
            &self.root,
            &mut self.record,
            SkillMutationPhase::IntentDurable,
            None,
            None,
        )
    }

    #[must_use]
    pub(crate) fn terminal_delivery_owned_by_current_process(&self) -> bool {
        self.record.terminal_delivery_state == SkillTerminalDeliveryState::Submitting
            && self.record.terminal_delivery_owner_nonce.as_deref()
                == Some(skill_mutation_process_nonce())
    }

    pub(crate) fn mark_terminal_submitting(&mut self) -> Result<()> {
        if !self.record.phase.is_terminal() {
            anyhow::bail!(
                "skill mutation {} cannot submit a terminal audit from phase {}",
                self.record.operation_id,
                self.record.phase.as_str()
            );
        }
        match self.record.terminal_delivery_state {
            SkillTerminalDeliveryState::Durable => return Ok(()),
            SkillTerminalDeliveryState::Submitting => {
                if self.terminal_delivery_owned_by_current_process() {
                    return Ok(());
                }
            }
            SkillTerminalDeliveryState::NotStarted => {}
        }
        let prior = self.record.clone();
        self.record.terminal_delivery_state = SkillTerminalDeliveryState::Submitting;
        self.record.terminal_delivery_owner_nonce =
            Some(skill_mutation_process_nonce().to_string());
        self.record.terminal_receipt = None;
        if let Err(error) = persist_skill_mutation_journal(&self.root, &self.record) {
            self.record = prior;
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn mark_terminal_durable(
        &mut self,
        receipt: SkillMutationAuditReceipt,
    ) -> Result<()> {
        if !self.record.phase.is_terminal()
            || self.record.terminal_delivery_state == SkillTerminalDeliveryState::NotStarted
        {
            anyhow::bail!(
                "skill mutation {} cannot bind a terminal receipt before submitting it",
                self.record.operation_id
            );
        }
        if receipt.audit_event_id != self.record.audit_binding().terminal_audit_event_id() {
            anyhow::bail!(
                "skill mutation {} received an authenticated receipt for another terminal",
                self.record.operation_id
            );
        }
        if let Some(existing) = self.record.terminal_receipt.as_ref()
            && existing != &receipt
        {
            anyhow::bail!(
                "skill mutation {} conflicts with its persisted terminal receipt",
                self.record.operation_id
            );
        }
        let prior = self.record.clone();
        self.record.terminal_delivery_state = SkillTerminalDeliveryState::Durable;
        self.record.terminal_receipt = Some(receipt);
        if let Err(error) = persist_skill_mutation_journal(&self.root, &self.record) {
            self.record = prior;
            return Err(error);
        }
        Ok(())
    }

    /// Resolve the durable journal to one terminal state. `intent_seen` comes
    /// from a full WAL scan for this exact operation and audit-event id.
    ///
    /// `Ok(None)` means the prepared journal had no durable intent and was
    /// safely removed without emitting a terminal result.
    pub(crate) fn reconcile(
        &mut self,
        intent_seen: bool,
    ) -> Result<Option<SkillMutationAuditBinding>> {
        if !intent_seen {
            match self.record.phase {
                SkillMutationPhase::Prepared => {}
                SkillMutationPhase::IntentSubmitting => {
                    anyhow::bail!(
                        "skill mutation {} entered intent delivery but has no durable WAL frame \
                         yet; exact same-operation delivery/reconciliation must retry later",
                        self.record.operation_id
                    );
                }
                _ => {
                    anyhow::bail!(
                        "skill mutation {} is in phase {}, but its durable intent is missing from the WAL",
                        self.record.operation_id,
                        self.record.phase.as_str()
                    );
                }
            }
            if self.record.kind.is_install() {
                let stage = mutation_install_stage_name(&self.record);
                remove_transaction_artifact_if_present(&self.root, &stage, None)?;
            }
            clear_skill_mutation_journal(&self.root)?;
            return Ok(None);
        }

        match self.record.phase {
            SkillMutationPhase::Prepared
            | SkillMutationPhase::IntentSubmitting
            | SkillMutationPhase::IntentDurable => {
                let current = installed_entry_generation_locked(&self.root, &self.record.skill_id)?;
                let (phase, error_sha256) =
                    if public_anchor_matches_prior_binding(&self.root, &self.record, &current)? {
                        (
                            SkillMutationPhase::Aborted,
                            Some(recovery_error_sha256(
                                "intent was durable but commit never started",
                            )),
                        )
                    } else {
                        (
                            SkillMutationPhase::Indeterminate,
                            Some(recovery_error_sha256(
                                "public anchor changed before the durable commit-start boundary",
                            )),
                        )
                    };
                transition_skill_mutation_phase(
                    &self.root,
                    &mut self.record,
                    phase,
                    current,
                    error_sha256,
                )?;
            }
            SkillMutationPhase::CommitStarted => {
                self.reconcile_commit_started()?;
            }
            SkillMutationPhase::Committed => {
                let current = installed_entry_generation_locked(&self.root, &self.record.skill_id)?;
                let expected = if self.record.kind.is_install() {
                    self.record.source_generation_sha256.clone()
                } else {
                    None
                };
                if current != expected {
                    transition_skill_mutation_phase(
                        &self.root,
                        &mut self.record,
                        SkillMutationPhase::Indeterminate,
                        current,
                        Some(recovery_error_sha256(
                            "committed journal conflicts with the current public anchor",
                        )),
                    )?;
                }
            }
            SkillMutationPhase::Aborted => {
                let current = installed_entry_generation_locked(&self.root, &self.record.skill_id)?;
                if !public_anchor_matches_prior_binding(&self.root, &self.record, &current)? {
                    transition_skill_mutation_phase(
                        &self.root,
                        &mut self.record,
                        SkillMutationPhase::Indeterminate,
                        current,
                        Some(recovery_error_sha256(
                            "aborted journal conflicts with the bound prior anchor",
                        )),
                    )?;
                }
            }
            SkillMutationPhase::Indeterminate => {}
        }
        Ok(Some(self.record.audit_binding()))
    }

    fn reconcile_commit_started(&mut self) -> Result<()> {
        let current = installed_entry_generation_locked(&self.root, &self.record.skill_id)?;
        let prior = self.record.prior_generation_sha256.clone();
        let desired = self.record.source_generation_sha256.clone();
        let (phase, error) = match self.record.kind {
            SkillMutationKind::Install => {
                if current.is_none() {
                    (
                        SkillMutationPhase::Aborted,
                        "fresh install did not reach its public anchor",
                    )
                } else {
                    (
                        SkillMutationPhase::Indeterminate,
                        "fresh install crossed commit-start without a durable terminal phase",
                    )
                }
            }
            SkillMutationKind::Replace => {
                if public_anchor_matches_prior_binding(&self.root, &self.record, &current)? {
                    (
                        SkillMutationPhase::Aborted,
                        "replacement restored its bound prior generation",
                    )
                } else if current == desired {
                    (
                        SkillMutationPhase::Indeterminate,
                        "replacement published its desired generation without a durable terminal phase",
                    )
                } else if current.is_none()
                    && restore_prior_backup_if_present(&self.root, &self.record)?
                {
                    (
                        SkillMutationPhase::Indeterminate,
                        "replacement was interrupted with only its private rollback generation",
                    )
                } else {
                    (
                        SkillMutationPhase::Indeterminate,
                        "replacement anchor does not match either bound generation",
                    )
                }
            }
            SkillMutationKind::Remove => {
                if prior.is_none() && current.is_none() {
                    (
                        SkillMutationPhase::Committed,
                        "idempotent removal confirmed the anchor was absent",
                    )
                } else if public_anchor_matches_prior_binding(&self.root, &self.record, &current)? {
                    (
                        SkillMutationPhase::Aborted,
                        "removal left its bound prior generation live",
                    )
                } else {
                    (
                        SkillMutationPhase::Indeterminate,
                        "removal crossed commit-start without a durable terminal phase",
                    )
                }
            }
        };
        transition_skill_mutation_phase(
            &self.root,
            &mut self.record,
            phase,
            current,
            if phase == SkillMutationPhase::Committed {
                None
            } else {
                Some(recovery_error_sha256(error))
            },
        )
    }

    /// Remove the outbox only after the caller proved that the exact terminal
    /// audit event exists once in the WAL. Indeterminate namespace states are
    /// first settled durably while their backup/tombstone is still retained.
    pub(crate) fn acknowledge_terminal(mut self) -> Result<()> {
        if !self.record.phase.is_terminal() {
            anyhow::bail!(
                "skill mutation {} is not terminal",
                self.record.operation_id
            );
        }
        #[cfg(not(test))]
        if self.record.terminal_delivery_state != SkillTerminalDeliveryState::Durable
            || self.record.terminal_receipt.is_none()
        {
            anyhow::bail!(
                "skill mutation {} terminal audit is not durably authenticated",
                self.record.operation_id
            );
        }
        self.settle_terminal_namespace()?;
        clear_skill_mutation_journal(&self.root)
    }

    fn settle_terminal_namespace(&mut self) -> Result<()> {
        let mut current = installed_entry_generation_locked(&self.root, &self.record.skill_id)?;
        if self.record.phase == SkillMutationPhase::Indeterminate {
            if current.is_none() && self.record.prior_generation_sha256.is_some() {
                match self.record.kind {
                    SkillMutationKind::Install | SkillMutationKind::Replace => {
                        if restore_prior_backup_if_present(&self.root, &self.record)? {
                            current = installed_entry_generation_locked(
                                &self.root,
                                &self.record.skill_id,
                            )?;
                        }
                    }
                    SkillMutationKind::Remove => {
                        restore_prior_removal_tombstone(&self.root, &self.record)?;
                        current =
                            installed_entry_generation_locked(&self.root, &self.record.skill_id)?;
                    }
                }
            }
            if !public_anchor_matches_prior_binding(&self.root, &self.record, &current)? {
                anyhow::bail!(
                    "cannot settle indeterminate skill mutation {}: the exact bound prior namespace \
                     is not restored; desired state and rollback evidence are retained and Skill \
                     activation remains blocked",
                    self.record.operation_id
                );
            }
        }
        if let Some(active) = self.record.cleanup_started.clone() {
            cleanup_transaction_artifact_restartable(
                &self.root,
                &mut self.record,
                OsStr::new(&active.artifact_name),
                active.artifact_kind,
                None,
            )?;
        }
        match self.record.kind {
            SkillMutationKind::Install | SkillMutationKind::Replace => {
                let desired = self.record.source_generation_sha256.clone();
                let prior = self.record.prior_generation_sha256.clone();
                if current.is_none()
                    && prior.is_some()
                    && restore_prior_backup_if_present(&self.root, &self.record)?
                {
                    // The operation remains `indeterminate` in its already
                    // emitted audit result, but the namespace is now safely
                    // settled back to the bound prior generation.
                } else if current != desired && current != prior {
                    anyhow::bail!(
                        "cannot settle skill mutation {}: public anchor matches neither bound generation",
                        self.record.operation_id
                    );
                } else {
                    sync_directory(&self.root.dir, &self.root.display_path).context(
                        "durably settle public skill anchor before outbox acknowledgement",
                    )?;
                }
                let stage = mutation_install_stage_name(&self.record);
                if private_artifact_exists(&self.root, &stage)? {
                    let stage_name = stage
                        .to_str()
                        .context("private install stage name is not UTF-8")?;
                    if installed_entry_generation_locked(&self.root, stage_name)?
                        != self.record.source_generation_sha256
                    {
                        anyhow::bail!(
                            "cannot settle skill mutation {}: private stage no longer matches the desired generation",
                            self.record.operation_id
                        );
                    }
                    cleanup_transaction_artifact_restartable(
                        &self.root,
                        &mut self.record,
                        &stage,
                        SkillCleanupArtifactKind::InstallStage,
                        None,
                    )?;
                }
                let backup = mutation_backup_name(&self.record);
                if private_artifact_exists(&self.root, &backup)? {
                    let expected_identity = self
                        .record
                        .prior_object_identity
                        .clone()
                        .context("replacement backup lacks its bound object identity")?;
                    let backup_display = self.root.display_path.join(&backup);
                    let bound_backup = bind_child_object(&self.root.dir, &backup, &backup_display)?;
                    let backup_name = backup
                        .to_str()
                        .context("private replacement backup name is not UTF-8")?;
                    if bound_backup.identity_token() != expected_identity
                        || installed_entry_generation_at_locked(
                            &self.root,
                            backup_name,
                            &self.record.skill_id,
                        )? != self.record.prior_generation_sha256
                        || !bound_backup.matches_child(&self.root.dir, &backup, &backup_display)?
                    {
                        anyhow::bail!(
                            "cannot settle skill mutation {}: private backup is not the authorized prior object",
                            self.record.operation_id
                        );
                    }
                    drop(bound_backup);
                    cleanup_transaction_artifact_restartable(
                        &self.root,
                        &mut self.record,
                        &backup,
                        SkillCleanupArtifactKind::ReplacementBackup,
                        Some(&expected_identity),
                    )?;
                }
            }
            SkillMutationKind::Remove => {
                let prior = self.record.prior_generation_sha256.clone();
                if current.is_some() && current != prior {
                    anyhow::bail!(
                        "cannot settle skill removal {}: public anchor changed to an unbound generation",
                        self.record.operation_id
                    );
                }
                sync_directory(&self.root.dir, &self.root.display_path)
                    .context("durably settle skill removal anchor")?;
                let tombstone = mutation_tombstone_name(&self.record);
                if private_artifact_exists(&self.root, &tombstone)? {
                    let expected_identity = self
                        .record
                        .prior_object_identity
                        .clone()
                        .context("removal tombstone lacks its bound object identity")?;
                    let tombstone_display = self.root.display_path.join(&tombstone);
                    let bound_tombstone =
                        bind_child_object(&self.root.dir, &tombstone, &tombstone_display)?;
                    if bound_tombstone.identity_token() != expected_identity {
                        anyhow::bail!(
                            "cannot settle skill removal {}: tombstone identity is not the authorized object",
                            self.record.operation_id
                        );
                    }
                    let tombstone_name = tombstone
                        .to_str()
                        .context("private removal tombstone name is not UTF-8")?;
                    if installed_entry_generation_at_locked(
                        &self.root,
                        tombstone_name,
                        &self.record.skill_id,
                    )? != self.record.prior_generation_sha256
                    {
                        anyhow::bail!(
                            "cannot settle skill removal {}: tombstone generation is not the authorized object",
                            self.record.operation_id
                        );
                    }
                    if !bound_tombstone.matches_child(
                        &self.root.dir,
                        &tombstone,
                        &tombstone_display,
                    )? {
                        anyhow::bail!(
                            "cannot settle skill removal {}: tombstone identity changed during verification",
                            self.record.operation_id
                        );
                    }
                    drop(bound_tombstone);
                    cleanup_transaction_artifact_restartable(
                        &self.root,
                        &mut self.record,
                        &tombstone,
                        SkillCleanupArtifactKind::RemovalTombstone,
                        Some(&expected_identity),
                    )?;
                }
            }
        }
        Ok(())
    }
}

fn recovery_error_sha256(message: &str) -> String {
    hex::encode(Sha256::digest(message.as_bytes()))
}

fn cleanup_transaction_artifact_restartable(
    root: &BoundDirectory,
    record: &mut SkillMutationJournal,
    name: &OsStr,
    kind: SkillCleanupArtifactKind,
    expected_identity: Option<&str>,
) -> Result<()> {
    let name_text = name
        .to_str()
        .context("private cleanup artifact name is not UTF-8")?;
    if let Some(active) = record.cleanup_started.as_ref()
        && (active.artifact_name != name_text || active.artifact_kind != kind)
    {
        anyhow::bail!(
            "skill mutation {} must finish cleanup of `{}` before starting `{name_text}`",
            record.operation_id,
            active.artifact_name
        );
    }
    let display = root.display_path.join(name);
    let exists = match root.dir.symlink_metadata(name) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect cleanup artifact {}", display.display()));
        }
    };

    if exists {
        // The binding can carry a native Windows handle. Persist only its
        // verified identity before recursive cleanup; the deletion helper
        // reacquires a short-lived no-follow directory capability and proves
        // that identity again before its final destructive operation.
        let bound_identity = {
            let bound = bind_child_object(&root.dir, name, &display)?;
            let identity = bound.identity_token().to_string();
            if let Some(active) = record.cleanup_started.as_ref() {
                if identity != active.object_identity
                    || !bound.matches_child(&root.dir, name, &display)?
                {
                    anyhow::bail!(
                        "skill mutation {} cleanup artifact `{name_text}` changed identity",
                        record.operation_id
                    );
                }
            } else if expected_identity.is_some_and(|expected| expected != identity.as_str()) {
                anyhow::bail!(
                    "skill mutation {} cleanup artifact `{name_text}` is not the authorized object",
                    record.operation_id
                );
            }
            identity
        };
        if record.cleanup_started.is_none() {
            let prior = record.clone();
            record.cleanup_started = Some(SkillCleanupState {
                artifact_name: name_text.to_string(),
                artifact_kind: kind,
                object_identity: bound_identity.clone(),
            });
            if let Err(error) = persist_skill_mutation_journal(root, record) {
                *record = prior;
                return Err(error).context("persist restartable Skill cleanup boundary");
            }
        }
        remove_transaction_artifact_if_present(root, name, Some(&bound_identity))?;
    } else if record.cleanup_started.is_none() {
        return Ok(());
    }

    // The top-level object is now absent through the bound parent capability.
    // Make that namespace change durable before clearing CleanupStarted.
    sync_directory(&root.dir, &root.display_path)
        .context("sync restartable Skill cleanup parent")?;
    let prior = record.clone();
    record.cleanup_started = None;
    if let Err(error) = persist_skill_mutation_journal(root, record) {
        *record = prior;
        return Err(error).context("clear durable Skill cleanup boundary");
    }
    Ok(())
}

pub(crate) fn validate_installed_skill_dir_name(id: &str) -> Result<()> {
    if id.is_empty() || id.contains(['\0', '/', '\\', ':']) || matches!(id, "." | "..") {
        anyhow::bail!("invalid installed skill directory name `{id}`");
    }
    let mut components = Path::new(id).components();
    if !matches!(components.next(), Some(std::path::Component::Normal(_)))
        || components.next().is_some()
    {
        anyhow::bail!("invalid installed skill directory name `{id}`");
    }
    Ok(())
}

pub(crate) fn validate_mutation_skill_id(id: &str, kind: SkillMutationKind) -> Result<()> {
    if kind == SkillMutationKind::Remove {
        validate_installed_skill_dir_name(id)
    } else {
        super::creator::validate_skill_id(id)
    }
}

/// One row in the operator-facing skills list. Distinct from
/// `super::Skill` because this surface includes BROKEN entries (no
/// skill.yaml / malformed YAML) so the operator can see + fix them.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillRepairability {
    /// A real skill directory whose manifest is absent or a replaceable
    /// regular no-follow file. Creator repair can safely commit a new YAML.
    ManifestReplaceable,
    /// Files, links/reparse entries, unsafe directories, and linked/non-regular
    /// manifests can only be removed; creator repair would necessarily fail.
    RemoveOnly,
}

#[derive(Clone, Debug)]
pub struct InstalledEntry {
    /// Directory name under `~/.neoth/skills/`.
    pub dir_name: String,
    /// Absolute path to the skill directory.
    pub path: PathBuf,
    /// `Some(id)` when the manifest parsed cleanly; `None` when the
    /// directory exists but has no skill.yaml OR the YAML is broken.
    /// The CLI shows broken entries with a warn indicator so the
    /// operator notices.
    pub manifest_id: Option<String>,
    /// Parsed manifest for a healthy entry. Diagnostic inventory consumers
    /// use this without re-opening the path outside the mutation-locked
    /// snapshot.
    pub manifest: Option<SkillManifest>,
    /// Exact package generation captured under the same mutation lock as the
    /// manifest. Present only for a structurally healthy package.
    pub generation_sha256: Option<String>,
    /// `Some(message)` when manifest load failed. Empty when the
    /// manifest is healthy.
    pub error: Option<String>,
    /// Exact structural repair contract captured under the same mutation lock
    /// and no-follow directory capabilities as the rest of this snapshot.
    pub repairability: Option<SkillRepairability>,
}

/// List every entry under `<target_skills_dir>`. Includes broken ones.
/// Sorted by `dir_name` for stable output.
pub fn list_installed(target_skills_dir: &Path) -> Result<Vec<InstalledEntry>> {
    list_installed_with_limit(target_skills_dir, MAX_SKILL_ENTRIES)
}

fn list_installed_with_limit(
    target_skills_dir: &Path,
    max_root_entries: usize,
) -> Result<Vec<InstalledEntry>> {
    let Some(root) = open_bound_directory(target_skills_dir, false, "skills root")? else {
        return Ok(Vec::new());
    };
    let _mutation_guard = lock_skill_mutations(&root)?;
    recover_pending_transactions_locked(&root)?;
    list_installed_locked_with_limit(&root, max_root_entries)
}

/// Capture the installed tree and its authenticated incarnation index under
/// one shared mutation lock. Diagnostic/runtime presentation must use this
/// boundary so an identical-byte reinstall cannot splice a stale WAL
/// incarnation onto a newer directory snapshot.
pub(crate) fn list_installed_with_incarnation_index(
    target_skills_dir: &Path,
) -> Result<(
    Vec<InstalledEntry>,
    super::mutation_lifecycle::SkillInstallIncarnationIndex,
)> {
    let home = target_skills_dir
        .parent()
        .context("installed Skills root has no instance-home parent")?;
    let Some(root) = open_bound_directory(target_skills_dir, false, "skills root")? else {
        return Ok((
            Vec::new(),
            super::mutation_lifecycle::scan_skill_install_incarnation_index(home)?,
        ));
    };
    let _mutation_guard = lock_skill_mutations(&root)?;
    recover_pending_transactions_locked(&root)?;
    let install_incarnations =
        super::mutation_lifecycle::scan_skill_install_incarnation_index(home)
            .context("index installed Skill incarnations under inventory mutation lock")?;
    let entries = list_installed_locked_with_limit(&root, MAX_SKILL_ENTRIES)?;
    Ok((entries, install_incarnations))
}

fn list_installed_locked_with_limit(
    root: &BoundDirectory,
    max_root_entries: usize,
) -> Result<Vec<InstalledEntry>> {
    let mut out = Vec::new();
    let mut generation_budget = RuntimeAuthorityTraversalBudget::new();
    let entries = root.dir.entries().with_context(|| {
        format!(
            "enumerate installed skills under {}",
            root.display_path.display()
        )
    })?;
    let mut root_entry_count = 0usize;
    for entry in entries {
        root_entry_count = root_entry_count
            .checked_add(1)
            .context("installed skill inventory entry counter overflow")?;
        if root_entry_count > max_root_entries {
            anyhow::bail!(
                "installed skill inventory under {} exceeds the {max_root_entries}-entry limit",
                root.display_path.display()
            );
        }
        let entry = entry.with_context(|| {
            format!(
                "read installed skill entry under {}",
                root.display_path.display()
            )
        })?;
        let name = entry.file_name();
        let dir_name = match name.to_str() {
            Some(value) if !value.starts_with('.') => value.to_string(),
            _ => continue,
        };
        let path = root.display_path.join(&name);
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                out.push(InstalledEntry {
                    dir_name,
                    path,
                    manifest_id: None,
                    manifest: None,
                    generation_sha256: None,
                    error: Some(format!("entry inspection error: {error}")),
                    repairability: Some(SkillRepairability::RemoveOnly),
                });
                continue;
            }
        };
        if file_type.is_symlink() {
            out.push(InstalledEntry {
                dir_name,
                path,
                manifest_id: None,
                manifest: None,
                generation_sha256: None,
                error: Some("linked/reparse skill directories are not allowed".to_string()),
                repairability: Some(SkillRepairability::RemoveOnly),
            });
            continue;
        }
        if !file_type.is_dir() {
            out.push(InstalledEntry {
                dir_name,
                path,
                manifest_id: None,
                manifest: None,
                generation_sha256: None,
                error: Some("skill entry is not a directory".to_string()),
                repairability: Some(SkillRepairability::RemoveOnly),
            });
            continue;
        }
        let skill_dir = match open_real_child_dir(&root.dir, &name, &path) {
            Ok(skill_dir) => skill_dir,
            Err(error) => {
                out.push(InstalledEntry {
                    dir_name,
                    path,
                    manifest_id: None,
                    manifest: None,
                    generation_sha256: None,
                    error: Some(format!("unsafe skill directory: {error:#}")),
                    repairability: Some(SkillRepairability::RemoveOnly),
                });
                continue;
            }
        };
        let structural_repairability = match skill_dir.symlink_metadata("skill.yaml") {
            Ok(metadata) if metadata.is_file() && !cap_metadata_is_link_like(&metadata) => {
                SkillRepairability::ManifestReplaceable
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                SkillRepairability::ManifestReplaceable
            }
            _ => SkillRepairability::RemoveOnly,
        };
        let manifest_path = path.join("skill.yaml");
        let (manifest, error) = match read_regular_file_bounded(
            &skill_dir,
            OsStr::new("skill.yaml"),
            &manifest_path,
            MAX_SKILL_MANIFEST_BYTES,
        ) {
            Ok(body) => match std::str::from_utf8(&body)
                .map_err(anyhow::Error::from)
                .and_then(|body| {
                    serde_yaml::from_str::<SkillManifest>(body).map_err(anyhow::Error::from)
                }) {
                Ok(manifest) if super::creator::validate_skill_id(&manifest.id).is_err() => (
                    None,
                    Some("manifest id is not canonical lowercase [a-z0-9_-]".to_string()),
                ),
                Ok(manifest) if manifest.id != dir_name => (
                    None,
                    Some(format!(
                        "manifest id `{}` does not match directory `{dir_name}`",
                        manifest.id
                    )),
                ),
                Ok(manifest) if manifest.description.trim().is_empty() => {
                    (None, Some("manifest description is empty".to_string()))
                }
                Ok(manifest) => (Some(manifest), None),
                Err(error) => (None, Some(format!("YAML parse error: {error}"))),
            },
            Err(error)
                if error
                    .root_cause()
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
            {
                (None, Some("no skill.yaml in directory".to_string()))
            }
            Err(error) => (None, Some(format!("read error: {error:#}"))),
        };
        let (manifest, error, generation_sha256, generation_invalid) = if manifest.is_some()
            && error.is_none()
        {
            match target_generation_locked_with_budget(root, &dir_name, &mut generation_budget) {
                Ok(Some(generation)) => (manifest, None, Some(generation), false),
                Ok(None) => (
                    None,
                    Some("skill package disappeared during inventory".to_string()),
                    None,
                    true,
                ),
                Err(error) if is_runtime_authority_traversal_limit(&error) => {
                    return Err(error).context(
                        "installed Skill inventory exceeded its aggregate generation budget",
                    );
                }
                Err(error) => (
                    None,
                    Some(format!("package generation error: {error:#}")),
                    None,
                    true,
                ),
            }
        } else {
            (manifest, error, None, false)
        };
        let manifest_id = manifest.as_ref().map(|manifest| manifest.id.clone());
        let repairability = error.as_ref().map(|_| {
            if generation_invalid {
                SkillRepairability::RemoveOnly
            } else {
                structural_repairability
            }
        });
        out.push(InstalledEntry {
            dir_name,
            path,
            manifest_id,
            manifest,
            generation_sha256,
            error,
            repairability,
        });
    }
    out.sort_by(|a, b| a.dir_name.cmp(&b.dir_name));
    Ok(out)
}

#[derive(Default)]
struct CopyBudget {
    entries: usize,
    bytes: u64,
}

/// One bounded resource budget shared by every installed package and
/// authority-record namespace traversed during a runtime reload/publication
/// attempt. A caller must discard the whole candidate snapshot on overflow.
pub(crate) struct RuntimeAuthorityTraversalBudget {
    entries: usize,
    bytes: u64,
    max_entries: usize,
    max_bytes: u64,
}

impl RuntimeAuthorityTraversalBudget {
    pub(crate) fn new() -> Self {
        Self {
            entries: 0,
            bytes: 0,
            max_entries: MAX_RUNTIME_AUTHORITY_TRAVERSAL_ENTRIES,
            max_bytes: MAX_RUNTIME_AUTHORITY_TRAVERSAL_BYTES,
        }
    }

    pub(crate) fn unbounded_for_internal() -> Self {
        Self {
            entries: 0,
            bytes: 0,
            max_entries: usize::MAX,
            max_bytes: u64::MAX,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_limits(max_entries: usize, max_bytes: u64) -> Self {
        Self {
            entries: 0,
            bytes: 0,
            max_entries,
            max_bytes,
        }
    }

    pub(crate) fn observe_entry(&mut self) -> Result<()> {
        self.entries = self
            .entries
            .checked_add(1)
            .context("runtime authority traversal entry counter overflow")?;
        if self.entries > self.max_entries {
            return Err(RuntimeAuthorityTraversalLimitExceeded.into());
        }
        Ok(())
    }

    pub(crate) fn observe_bytes(&mut self, bytes: u64) -> Result<()> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .context("runtime authority traversal byte counter overflow")?;
        if self.bytes > self.max_bytes {
            return Err(RuntimeAuthorityTraversalLimitExceeded.into());
        }
        Ok(())
    }

    pub(crate) fn ensure_within_limits(&self) -> Result<()> {
        if self.entries > self.max_entries || self.bytes > self.max_bytes {
            return Err(RuntimeAuthorityTraversalLimitExceeded.into());
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("runtime Skill authority aggregate traversal budget exceeded")]
pub(crate) struct RuntimeAuthorityTraversalLimitExceeded;

pub(crate) fn is_runtime_authority_traversal_limit(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<RuntimeAuthorityTraversalLimitExceeded>()
            .is_some()
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InstalledSkillAuthorityTreeSnapshot {
    pub(crate) generation_sha256: String,
    pub(crate) manifest_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InstalledSkillTestFileSnapshot {
    pub(crate) file_name: String,
    pub(crate) bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InstalledSkillTestSnapshot {
    pub(crate) generation_sha256: String,
    pub(crate) manifest_bytes: Vec<u8>,
    pub(crate) test_directory_entries: usize,
    pub(crate) test_files: Vec<InstalledSkillTestFileSnapshot>,
}

#[derive(Default)]
struct SkillTreeSnapshotCollector {
    capture_manifest: bool,
    capture_tests: bool,
    manifest_bytes: Option<Vec<u8>>,
    test_directory_entries: usize,
    test_files: Vec<InstalledSkillTestFileSnapshot>,
}

impl SkillTreeSnapshotCollector {
    fn capture_tests() -> Self {
        Self {
            capture_manifest: true,
            capture_tests: true,
            ..Self::default()
        }
    }

    fn capture_manifest() -> Self {
        Self {
            capture_manifest: true,
            ..Self::default()
        }
    }

    fn observe_directory(&self, relative: &str) -> Result<()> {
        if self.capture_tests && relative.starts_with("tests/") {
            anyhow::bail!("installed Skill tests directory contains a nested directory");
        }
        Ok(())
    }

    fn observe_entry(&mut self, relative_prefix: &str) -> Result<()> {
        if self.capture_tests && relative_prefix == "tests" {
            self.test_directory_entries = self
                .test_directory_entries
                .checked_add(1)
                .context("installed Skill test-directory entry counter overflow")?;
        }
        Ok(())
    }

    fn observe_file(&mut self, relative: &str, bytes: &[u8]) -> Result<()> {
        if self.capture_manifest && relative == "skill.yaml" {
            self.manifest_bytes = Some(bytes.to_vec());
            return Ok(());
        }
        if !self.capture_tests {
            return Ok(());
        }
        if relative == "tests" {
            anyhow::bail!("installed Skill tests entry is not a directory");
        }
        let Some(file_name) = relative.strip_prefix("tests/") else {
            return Ok(());
        };
        if file_name.is_empty() || file_name.contains('/') {
            return Ok(());
        }
        let is_yaml = Path::new(file_name)
            .extension()
            .and_then(OsStr::to_str)
            .is_some_and(|extension| extension == "yaml" || extension == "yml");
        if is_yaml {
            self.test_files.push(InstalledSkillTestFileSnapshot {
                file_name: file_name.to_string(),
                bytes: bytes.to_vec(),
            });
        }
        Ok(())
    }
}

/// Hash one installed package and freeze its direct `tests/*.yaml|yml` bytes
/// during the same capability traversal. The returned scenario bytes are
/// exactly the bytes fed into `generation_sha256`, eliminating pre/post-hash
/// ABA windows before provider-backed test execution.
///
/// The caller must already hold the global installed-Skill mutation lock.
pub(crate) fn capture_installed_skill_test_snapshot_locked(
    skills_root: &BoundDirectory,
    skill_id: &str,
) -> Result<InstalledSkillTestSnapshot> {
    validate_installed_skill_dir_name(skill_id)?;
    let name = OsStr::new(skill_id);
    let display = skills_root.display_path.join(name);
    let metadata = skills_root
        .dir
        .symlink_metadata(name)
        .with_context(|| format!("inspect installed Skill test package {}", display.display()))?;
    if !metadata.is_dir() || cap_metadata_is_link_like(&metadata) {
        anyhow::bail!(
            "installed Skill test package is linked or not a directory: {}",
            display.display()
        );
    }
    let directory = open_real_child_dir(&skills_root.dir, name, &display)?;
    let mut collector = SkillTreeSnapshotCollector::capture_tests();
    let generation_sha256 = skill_tree_generation_sha256_with_root_override_and_collector(
        &directory,
        &display,
        None,
        &mut collector,
    )?;
    let manifest_bytes = collector
        .manifest_bytes
        .context("installed Skill test snapshot lacks skill.yaml")?;
    Ok(InstalledSkillTestSnapshot {
        generation_sha256,
        manifest_bytes,
        test_directory_entries: collector.test_directory_entries,
        test_files: collector.test_files,
    })
}

pub(crate) fn skill_tree_generation_sha256(
    root: &Dir,
    display_root: &Path,
    validated_root_manifest: Option<&[u8]>,
) -> Result<String> {
    let root_override = validated_root_manifest.map(|bytes| RootFileOverride {
        name: SkillPackageDocument::Manifest.file_name(),
        bytes,
    });
    skill_tree_generation_sha256_with_root_override(root, display_root, root_override)
}

/// Hash one bound installed package under a budget shared by the complete
/// reload/publication attempt.
pub(crate) fn skill_tree_generation_sha256_with_aggregate_budget(
    root: &Dir,
    display_root: &Path,
    validated_root_manifest: Option<&[u8]>,
    aggregate: &mut RuntimeAuthorityTraversalBudget,
) -> Result<String> {
    let root_override = validated_root_manifest.map(|bytes| RootFileOverride {
        name: SkillPackageDocument::Manifest.file_name(),
        bytes,
    });
    skill_tree_generation_sha256_with_root_override_and_collector_and_budget(
        root,
        display_root,
        root_override,
        &mut SkillTreeSnapshotCollector::default(),
        aggregate,
    )
}

/// Capture the manifest bytes and package generation in the same bounded
/// traversal, so the authority expectation cannot bind bytes from a different
/// package instant.
pub(crate) fn capture_installed_skill_authority_tree_snapshot(
    root: &Dir,
    display_root: &Path,
    aggregate: &mut RuntimeAuthorityTraversalBudget,
) -> Result<InstalledSkillAuthorityTreeSnapshot> {
    let mut collector = SkillTreeSnapshotCollector::capture_manifest();
    let generation_sha256 =
        skill_tree_generation_sha256_with_root_override_and_collector_and_budget(
            root,
            display_root,
            None,
            &mut collector,
            aggregate,
        )?;
    let manifest_bytes = collector
        .manifest_bytes
        .context("installed Skill authority snapshot lacks skill.yaml")?;
    Ok(InstalledSkillAuthorityTreeSnapshot {
        generation_sha256,
        manifest_bytes,
    })
}

/// Compute the exact canonical package generation that would result from
/// replacing one typed root document while retaining every other package
/// entry and its permission metadata.
///
/// Staging callers use this before publication so their expected generation is
/// guaranteed to share the installer's versioned hashing contract. Keeping the
/// override typed prevents this helper from becoming an arbitrary path-hashing
/// API.
pub(crate) fn skill_tree_generation_sha256_with_document_override(
    root: &Dir,
    display_root: &Path,
    document: SkillPackageDocument,
    replacement: &[u8],
) -> Result<String> {
    let max_bytes = match document {
        SkillPackageDocument::Manifest => MAX_SKILL_MANIFEST_BYTES,
        SkillPackageDocument::Instructions => {
            usize::try_from(MAX_SKILL_FILE_BYTES).expect("skill file limit fits usize")
        }
    };
    if replacement.len() > max_bytes {
        anyhow::bail!(
            "{} exceeds the {max_bytes}-byte installed-Skill limit",
            document.display_name()
        );
    }
    skill_tree_generation_sha256_with_root_override(
        root,
        display_root,
        Some(RootFileOverride {
            name: document.file_name(),
            bytes: replacement,
        }),
    )
}

fn skill_tree_generation_sha256_with_root_override(
    root: &Dir,
    display_root: &Path,
    root_override: Option<RootFileOverride<'_>>,
) -> Result<String> {
    skill_tree_generation_sha256_with_root_override_and_collector(
        root,
        display_root,
        root_override,
        &mut SkillTreeSnapshotCollector::default(),
    )
}

fn skill_tree_generation_sha256_with_root_override_and_collector(
    root: &Dir,
    display_root: &Path,
    root_override: Option<RootFileOverride<'_>>,
    collector: &mut SkillTreeSnapshotCollector,
) -> Result<String> {
    let mut aggregate = RuntimeAuthorityTraversalBudget::unbounded_for_internal();
    skill_tree_generation_sha256_with_root_override_and_collector_and_budget(
        root,
        display_root,
        root_override,
        collector,
        &mut aggregate,
    )
}

fn skill_tree_generation_sha256_with_root_override_and_collector_and_budget(
    root: &Dir,
    display_root: &Path,
    root_override: Option<RootFileOverride<'_>>,
    collector: &mut SkillTreeSnapshotCollector,
    aggregate: &mut RuntimeAuthorityTraversalBudget,
) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"NEOTH_SKILL_PACKAGE_GENERATION\0v2\0");
    let root_metadata = root
        .dir_metadata()
        .with_context(|| format!("inspect skill package root {}", display_root.display()))?;
    if !root_metadata.is_dir() || cap_metadata_is_link_like(&root_metadata) {
        anyhow::bail!(
            "skill package root is linked or not a directory: {}",
            display_root.display()
        );
    }
    hash_tree_record_header(&mut hasher, b'D', "", 0, &root_metadata)?;
    let mut budget = CopyBudget::default();
    let mut context = SkillTreeHashContext {
        budget: &mut budget,
        hasher: &mut hasher,
        collector,
        aggregate,
    };
    hash_skill_tree_directory(root, display_root, "", root_override, 0, &mut context)?;
    Ok(hex::encode(hasher.finalize()))
}

struct SkillTreeHashContext<'a> {
    budget: &'a mut CopyBudget,
    hasher: &'a mut Sha256,
    collector: &'a mut SkillTreeSnapshotCollector,
    aggregate: &'a mut RuntimeAuthorityTraversalBudget,
}

fn hash_skill_tree_directory(
    directory: &Dir,
    display_directory: &Path,
    relative_prefix: &str,
    root_override: Option<RootFileOverride<'_>>,
    depth: usize,
    context: &mut SkillTreeHashContext<'_>,
) -> Result<()> {
    if depth > MAX_SKILL_TREE_DEPTH {
        anyhow::bail!(
            "skill tree exceeds maximum depth {MAX_SKILL_TREE_DEPTH} at {}",
            display_directory.display()
        );
    }
    let remaining_entry_budget = MAX_SKILL_ENTRIES
        .checked_sub(context.budget.entries)
        .context("skill package entry budget already exceeded")?;
    let entries = directory
        .entries()
        .with_context(|| format!("enumerate skill package {}", display_directory.display()))?;
    let mut names = Vec::with_capacity(remaining_entry_budget.min(64));
    for entry in entries {
        context.aggregate.observe_entry()?;
        if names.len() >= remaining_entry_budget {
            anyhow::bail!("skill tree exceeds {MAX_SKILL_ENTRIES} entries");
        }
        names.push(
            entry.map(|entry| entry.file_name()).with_context(|| {
                format!("enumerate skill package {}", display_directory.display())
            })?,
        );
    }
    if let Some(root_override) = root_override
        && !names.iter().any(|name| name == root_override.name)
    {
        context.aggregate.observe_entry()?;
        if names.len() >= remaining_entry_budget {
            anyhow::bail!("skill tree exceeds {MAX_SKILL_ENTRIES} entries");
        }
        names.push(root_override.name.to_os_string());
    }
    names.sort();

    for name in names {
        let name_text = name.to_str().ok_or_else(|| {
            anyhow::anyhow!(
                "skill package entry name is not UTF-8 under {}",
                display_directory.display()
            )
        })?;
        let relative = if relative_prefix.is_empty() {
            name_text.to_string()
        } else {
            format!("{relative_prefix}/{name_text}")
        };
        let display = display_directory.join(&name);
        context.collector.observe_entry(relative_prefix)?;
        context.budget.entries = context
            .budget
            .entries
            .checked_add(1)
            .context("skill package entry counter overflow")?;
        if context.budget.entries > MAX_SKILL_ENTRIES {
            anyhow::bail!("skill tree exceeds {MAX_SKILL_ENTRIES} entries");
        }

        let metadata = directory
            .symlink_metadata(&name)
            .with_context(|| format!("inspect skill package entry {}", display.display()))?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            anyhow::bail!(
                "skill package contains unsupported linked or reparse entry: {}",
                display.display()
            );
        }
        if depth == 0
            && let Some(root_override) = root_override
            && name == root_override.name
        {
            if !file_type.is_file() || cap_metadata_is_link_like(&metadata) {
                anyhow::bail!(
                    "replacement skill document is not a real regular file: {}",
                    display.display()
                );
            }
            context
                .collector
                .observe_file(&relative, root_override.bytes)?;
            context
                .aggregate
                .observe_bytes(root_override.bytes.len() as u64)?;
            hash_skill_file_record(
                context.hasher,
                &relative,
                root_override.bytes,
                &metadata,
                context.budget,
            )?;
            continue;
        }
        if file_type.is_dir() {
            context.collector.observe_directory(&relative)?;
            hash_tree_record_header(context.hasher, b'D', &relative, 0, &metadata)?;
            let child = open_real_child_dir(directory, &name, &display)?;
            hash_skill_tree_directory(&child, &display, &relative, None, depth + 1, context)?;
        } else if file_type.is_file() {
            let bytes = read_regular_file_bounded_observed(
                directory,
                &name,
                &display,
                usize::try_from(MAX_SKILL_FILE_BYTES).expect("skill file limit fits usize"),
                |bytes| context.aggregate.observe_bytes(bytes),
            )?;
            context.collector.observe_file(&relative, &bytes)?;
            hash_skill_file_record(context.hasher, &relative, &bytes, &metadata, context.budget)?;
        } else {
            anyhow::bail!(
                "skill package contains unsupported special entry: {}",
                display.display()
            );
        }
    }
    Ok(())
}

fn hash_skill_file_record(
    hasher: &mut Sha256,
    relative: &str,
    bytes: &[u8],
    metadata: &cap_std::fs::Metadata,
    budget: &mut CopyBudget,
) -> Result<()> {
    budget.bytes = budget
        .bytes
        .checked_add(bytes.len() as u64)
        .context("skill package byte counter overflow")?;
    if budget.bytes > MAX_SKILL_TOTAL_BYTES {
        anyhow::bail!("skill tree exceeds {MAX_SKILL_TOTAL_BYTES} total bytes");
    }
    hash_tree_record_header(hasher, b'F', relative, bytes.len() as u64, metadata)?;
    hasher.update(bytes);
    Ok(())
}

fn hash_tree_record_header(
    hasher: &mut Sha256,
    kind: u8,
    relative: &str,
    byte_len: u64,
    metadata: &cap_std::fs::Metadata,
) -> Result<()> {
    let path_len = u64::try_from(relative.len()).context("skill package path length overflow")?;
    hasher.update([kind]);
    hasher.update(path_len.to_le_bytes());
    hasher.update(relative.as_bytes());
    hasher.update(byte_len.to_le_bytes());
    let (permission_kind, permission_bits) = skill_permission_fingerprint(metadata);
    hasher.update([permission_kind]);
    hasher.update(permission_bits.to_le_bytes());
    Ok(())
}

#[cfg(unix)]
fn skill_permission_fingerprint(metadata: &cap_std::fs::Metadata) -> (u8, u32) {
    use cap_std::fs::PermissionsExt as _;
    (b'U', metadata.permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
fn skill_permission_fingerprint(metadata: &cap_std::fs::Metadata) -> (u8, u32) {
    (b'P', u32::from(metadata.permissions().readonly()))
}

fn hash_installed_entry_directory(
    directory: &Dir,
    display_directory: &Path,
    relative_prefix: &Path,
    depth: usize,
    budget: &mut CopyBudget,
    hasher: &mut Sha256,
) -> Result<()> {
    if depth > MAX_SKILL_TREE_DEPTH {
        anyhow::bail!(
            "installed skill entry exceeds maximum depth {MAX_SKILL_TREE_DEPTH} at {}",
            display_directory.display()
        );
    }
    let remaining = MAX_SKILL_ENTRIES
        .checked_sub(budget.entries)
        .context("installed skill entry budget already exceeded")?;
    let mut names = Vec::with_capacity(remaining.min(64));
    for entry in directory.entries().with_context(|| {
        format!(
            "enumerate installed skill entry {}",
            display_directory.display()
        )
    })? {
        if names.len() >= remaining {
            anyhow::bail!("installed skill entry exceeds {MAX_SKILL_ENTRIES} entries");
        }
        names.push(
            entry
                .with_context(|| {
                    format!(
                        "enumerate installed skill entry {}",
                        display_directory.display()
                    )
                })?
                .file_name(),
        );
    }
    names.sort();

    for name in names {
        budget.entries = budget
            .entries
            .checked_add(1)
            .context("installed skill entry counter overflow")?;
        if budget.entries > MAX_SKILL_ENTRIES {
            anyhow::bail!("installed skill entry exceeds {MAX_SKILL_ENTRIES} entries");
        }
        let display = display_directory.join(&name);
        let relative = relative_prefix.join(&name);
        let metadata = directory
            .symlink_metadata(&name)
            .with_context(|| format!("inspect installed skill entry {}", display.display()))?;
        if metadata.is_dir() && !cap_metadata_is_link_like(&metadata) {
            hash_installed_record_header(hasher, b'D', &relative, 0, &metadata)?;
            let child = open_real_child_dir(directory, &name, &display)?;
            hash_installed_entry_directory(&child, &display, &relative, depth + 1, budget, hasher)?;
        } else {
            hash_installed_leaf(
                directory, &name, &display, &relative, &metadata, budget, hasher,
            )?;
        }
    }
    Ok(())
}

fn hash_installed_leaf(
    parent: &Dir,
    name: &OsStr,
    display: &Path,
    relative: &Path,
    metadata: &cap_std::fs::Metadata,
    budget: &mut CopyBudget,
    hasher: &mut Sha256,
) -> Result<()> {
    if metadata.is_file() && !cap_metadata_is_link_like(metadata) {
        let bytes = read_regular_file_bounded(
            parent,
            name,
            display,
            usize::try_from(MAX_SKILL_FILE_BYTES).expect("skill file limit fits usize"),
        )?;
        budget.bytes = budget
            .bytes
            .checked_add(bytes.len() as u64)
            .context("installed skill entry byte counter overflow")?;
        if budget.bytes > MAX_SKILL_TOTAL_BYTES {
            anyhow::bail!("installed skill entry exceeds {MAX_SKILL_TOTAL_BYTES} total bytes");
        }
        hash_installed_record_header(hasher, b'F', relative, bytes.len() as u64, metadata)?;
        hasher.update(&bytes);
        return Ok(());
    }

    if cap_metadata_is_link_like(metadata) || metadata.file_type().is_symlink() {
        match parent.read_link(name) {
            Ok(target) => {
                let target_bytes = os_string_bytes(target.as_os_str());
                hash_installed_record_header(
                    hasher,
                    b'L',
                    relative,
                    target_bytes.len() as u64,
                    metadata,
                )?;
                hasher.update(target_bytes);
            }
            Err(_) => {
                // Some Windows reparse kinds do not expose a symbolic-link
                // target. Bind the no-follow metadata instead of opening the
                // reparse target or pretending the entry is absent.
                hash_installed_record_header(hasher, b'R', relative, metadata.len(), metadata)?;
                hash_metadata_fingerprint(hasher, metadata);
            }
        }
        return Ok(());
    }

    hash_installed_record_header(hasher, b'X', relative, metadata.len(), metadata)?;
    hash_metadata_fingerprint(hasher, metadata);
    Ok(())
}

fn hash_installed_record_header(
    hasher: &mut Sha256,
    kind: u8,
    relative: &Path,
    byte_len: u64,
    metadata: &cap_std::fs::Metadata,
) -> Result<()> {
    let path_bytes = os_string_bytes(relative.as_os_str());
    let path_len =
        u64::try_from(path_bytes.len()).context("installed entry path length overflow")?;
    hasher.update([kind]);
    hasher.update(path_len.to_le_bytes());
    hasher.update(path_bytes);
    hasher.update(byte_len.to_le_bytes());
    let (permission_kind, permission_bits) = skill_permission_fingerprint(metadata);
    hasher.update([permission_kind]);
    hasher.update(permission_bits.to_le_bytes());
    Ok(())
}

fn hash_metadata_fingerprint(hasher: &mut Sha256, metadata: &cap_std::fs::Metadata) {
    hasher.update(metadata.len().to_le_bytes());
    hasher.update([u8::from(metadata.permissions().readonly())]);
    for timestamp in [metadata.modified(), metadata.created()] {
        match timestamp
            .ok()
            .and_then(|value| value.into_std().duration_since(std::time::UNIX_EPOCH).ok())
        {
            Some(value) => {
                hasher.update([1]);
                hasher.update(value.as_secs().to_le_bytes());
                hasher.update(value.subsec_nanos().to_le_bytes());
            }
            None => hasher.update([0]),
        }
    }
}

#[cfg(unix)]
fn os_string_bytes(value: &OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt as _;
    value.as_bytes().to_vec()
}

#[cfg(windows)]
fn os_string_bytes(value: &OsStr) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt as _;
    value
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>()
}

#[cfg(not(any(unix, windows)))]
fn os_string_bytes(value: &OsStr) -> Vec<u8> {
    value.to_string_lossy().as_bytes().to_vec()
}

#[derive(Clone, Copy)]
struct RootFileOverride<'a> {
    name: &'a OsStr,
    bytes: &'a [u8],
}

/// Recursively copy one already-bound source directory into one already-bound
/// private stage. All opens are no-follow and handle-relative. At the root, an
/// optional typed package document is written from the exact validated bytes,
/// so concurrent source edits cannot substitute that document.
fn copy_dir_recursive(
    source: &Dir,
    destination: &Dir,
    source_display: &Path,
    destination_display: &Path,
    root_override: Option<RootFileOverride<'_>>,
    depth: usize,
    budget: &mut CopyBudget,
) -> Result<()> {
    if depth > MAX_SKILL_TREE_DEPTH {
        anyhow::bail!(
            "skill tree exceeds maximum depth {MAX_SKILL_TREE_DEPTH} at {}",
            source_display.display()
        );
    }
    let source_metadata = source.dir_metadata().with_context(|| {
        format!(
            "inspect skill source directory {}",
            source_display.display()
        )
    })?;
    if !source_metadata.is_dir() || cap_metadata_is_link_like(&source_metadata) {
        anyhow::bail!(
            "skill source is linked or not a directory: {}",
            source_display.display()
        );
    }
    let source_permissions = source_metadata.permissions();

    if let Some(root_override) = root_override {
        if root_override.bytes.len() as u64 > MAX_SKILL_FILE_BYTES {
            anyhow::bail!(
                "skill package document exceeds {MAX_SKILL_FILE_BYTES} bytes at {}",
                source_display.join(root_override.name).display()
            );
        }
        let source_document_display = source_display.join(root_override.name);
        let source_document_metadata =
            source
                .symlink_metadata(root_override.name)
                .with_context(|| {
                    format!(
                        "inspect overridden package document {}",
                        source_document_display.display()
                    )
                })?;
        if cap_metadata_is_link_like(&source_document_metadata)
            || !source_document_metadata.is_file()
        {
            anyhow::bail!(
                "overridden package document must be a real regular file: {}",
                source_document_display.display()
            );
        }
        write_regular_file_create_new(
            destination,
            root_override.name,
            root_override.bytes,
            &destination_display.join(root_override.name),
            Some(source_document_metadata.permissions()),
        )?;
        budget.entries = budget
            .entries
            .checked_add(1)
            .context("skill copy entry counter overflow")?;
        if budget.entries > MAX_SKILL_ENTRIES {
            anyhow::bail!("skill tree exceeds {MAX_SKILL_ENTRIES} entries");
        }
        budget.bytes = budget
            .bytes
            .checked_add(root_override.bytes.len() as u64)
            .context("skill copy byte counter overflow")?;
        if budget.bytes > MAX_SKILL_TOTAL_BYTES {
            anyhow::bail!("skill tree exceeds {MAX_SKILL_TOTAL_BYTES} total bytes");
        }
    }

    let entries = source
        .entries()
        .with_context(|| format!("enumerate skill source {}", source_display.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| format!("enumerate {}", source_display.display()))?;
        let name = entry.file_name();
        if root_override.is_some_and(|root_override| name == root_override.name) {
            continue;
        }
        budget.entries = budget
            .entries
            .checked_add(1)
            .context("skill copy entry counter overflow")?;
        if budget.entries > MAX_SKILL_ENTRIES {
            anyhow::bail!("skill tree exceeds {MAX_SKILL_ENTRIES} entries");
        }

        let from_display = source_display.join(&name);
        let to_display = destination_display.join(&name);
        // The store's crash-recovery artifacts own these prefixes. A package
        // entry must never occupy that namespace.
        if let Some(entry_name) = name.to_str()
            && let Some(prefix) = RESERVED_SKILL_ENTRY_PREFIXES
                .iter()
                .find(|prefix| entry_name.starts_with(**prefix))
        {
            anyhow::bail!(
                "skill package entry uses the reserved private-artifact prefix `{prefix}`: {}",
                from_display.display()
            );
        }
        let file_type = entry
            .file_type()
            .with_context(|| format!("inspect skill source entry {}", from_display.display()))?;
        if file_type.is_symlink() {
            anyhow::bail!(
                "skill package contains unsupported linked or reparse entry: {}",
                from_display.display()
            );
        }
        if file_type.is_dir() {
            let source_child = source.open_dir_nofollow(&name).with_context(|| {
                format!(
                    "open source directory without following links {}",
                    from_display.display()
                )
            })?;
            ensure_real_cap_directory(&source_child, &from_display, "skill source directory")?;
            create_private_directory(destination, &name, &to_display)?;
            let destination_child = destination.open_dir_nofollow(&name).with_context(|| {
                format!(
                    "open destination directory without following links {}",
                    to_display.display()
                )
            })?;
            ensure_real_cap_directory(
                &destination_child,
                &to_display,
                "skill destination directory",
            )?;
            copy_dir_recursive(
                &source_child,
                &destination_child,
                &from_display,
                &to_display,
                None,
                depth + 1,
                budget,
            )?;
        } else if file_type.is_file() {
            copy_regular_file_create_new(
                source,
                destination,
                &name,
                &from_display,
                &to_display,
                budget,
            )?;
        } else {
            anyhow::bail!(
                "skill package contains unsupported special entry: {}",
                from_display.display()
            );
        }
    }
    destination
        .set_permissions(".", source_permissions)
        .with_context(|| {
            format!(
                "preserve permissions on skill destination directory {}",
                destination_display.display()
            )
        })?;
    sync_directory(destination, destination_display)
}

fn copy_regular_file_create_new(
    source: &Dir,
    destination: &Dir,
    name: &OsStr,
    source_display: &Path,
    target_display: &Path,
    budget: &mut CopyBudget,
) -> Result<()> {
    let input = open_regular_file(source, name, source_display)?;
    let metadata = input
        .metadata()
        .with_context(|| format!("inspect skill source {}", source_display.display()))?;
    if metadata.len() > MAX_SKILL_FILE_BYTES {
        anyhow::bail!(
            "skill file exceeds {MAX_SKILL_FILE_BYTES} bytes: {}",
            source_display.display()
        );
    }

    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    let mut output = destination
        .open_with(name, &options)
        .with_context(|| format!("create skill target {}", target_display.display()))?;
    let mut limited = input.take(MAX_SKILL_FILE_BYTES.saturating_add(1));
    let copied = std::io::copy(&mut limited, &mut output).with_context(|| {
        format!(
            "copy {} → {}",
            source_display.display(),
            target_display.display()
        )
    })?;
    if copied > MAX_SKILL_FILE_BYTES {
        anyhow::bail!(
            "skill file grew beyond {MAX_SKILL_FILE_BYTES} bytes while copying: {}",
            source_display.display()
        );
    }
    budget.bytes = budget
        .bytes
        .checked_add(copied)
        .context("skill copy byte counter overflow")?;
    if budget.bytes > MAX_SKILL_TOTAL_BYTES {
        anyhow::bail!("skill tree exceeds {MAX_SKILL_TOTAL_BYTES} total bytes");
    }
    output
        .set_permissions(metadata.permissions())
        .with_context(|| {
            format!(
                "set permissions on skill target {}",
                target_display.display()
            )
        })?;
    output
        .sync_all()
        .with_context(|| format!("sync skill target {}", target_display.display()))?;
    Ok(())
}

fn write_regular_file_create_new(
    destination: &Dir,
    name: &OsStr,
    bytes: &[u8],
    target_display: &Path,
    permissions: Option<cap_std::fs::Permissions>,
) -> Result<()> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    let mut output = destination
        .open_with(name, &options)
        .with_context(|| format!("create skill target {}", target_display.display()))?;
    std::io::Write::write_all(&mut output, bytes)
        .with_context(|| format!("write skill target {}", target_display.display()))?;
    if let Some(permissions) = permissions {
        output.set_permissions(permissions).with_context(|| {
            format!(
                "preserve permissions on generated Skill document {}",
                target_display.display()
            )
        })?;
    }
    output
        .sync_all()
        .with_context(|| format!("sync skill target {}", target_display.display()))?;
    Ok(())
}

fn create_private_directory(parent: &Dir, name: &OsStr, display_path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use cap_std::fs::DirBuilderExt as _;
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        parent
            .create_dir_with(name, &builder)
            .with_context(|| format!("create private directory {}", display_path.display()))?;
    }
    #[cfg(not(unix))]
    {
        parent
            .create_dir(name)
            .with_context(|| format!("create private directory {}", display_path.display()))?;
    }
    Ok(())
}

fn ensure_real_cap_directory(dir: &Dir, display_path: &Path, label: &str) -> Result<()> {
    let metadata = dir
        .dir_metadata()
        .with_context(|| format!("inspect {label} {}", display_path.display()))?;
    if !metadata.is_dir() || cap_metadata_is_link_like(&metadata) {
        anyhow::bail!(
            "{label} is linked or not a directory: {}",
            display_path.display()
        );
    }
    Ok(())
}

fn create_install_transaction(
    root: &Dir,
    id: &str,
    operation_id: &str,
) -> Result<(OsString, OsString, Dir)> {
    let stage_name = OsString::from(format!("{INSTALL_TRANSACTION_PREFIX}{id}-{operation_id}"));
    let backup_name = OsString::from(format!("{BACKUP_TRANSACTION_PREFIX}{id}-{operation_id}"));
    match root.symlink_metadata(&backup_name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => anyhow::bail!("private install backup already exists for the prepared operation"),
        Err(error) => {
            return Err(error).context("inspect private skill backup transaction name");
        }
    }
    create_private_directory(root, &stage_name, Path::new(&stage_name))
        .with_context(|| "create private skill stage for the prepared operation")?;
    let dir = root
        .open_dir_nofollow(&stage_name)
        .context("open private skill stage for the prepared operation")?;
    ensure_real_cap_directory(&dir, Path::new(&stage_name), "private skill stage")?;
    Ok((stage_name, backup_name, dir))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransactionArtifactKind {
    Stage,
    Backup,
}

#[derive(Default)]
struct PendingTransaction {
    stages: Vec<OsString>,
    backups: Vec<OsString>,
}

/// Recover interrupted skill installs without consulting ambient paths.
///
/// Recovery deliberately prefers a known-live, journal-bound backup over an
/// uncommitted stage. A stage can survive a crash during its recursive copy,
/// whereas a backup is only created after the staged tree and its directory
/// entries have been synced. A journal-less backup is unauthenticated rollback
/// evidence: even an existing public entry cannot prove which generation won,
/// so recovery preserves every artifact and fails closed until explicit repair.
/// Ambiguous duplicate backups likewise fail closed instead of selecting an
/// arbitrary prior generation.
pub fn recover_pending_transactions(target_skills_dir: &Path) -> Result<()> {
    let Some(root) = open_bound_directory(target_skills_dir, false, "skills root")? else {
        return Ok(());
    };
    let _mutation_guard = lock_skill_mutations(&root)?;
    recover_pending_transactions_locked(&root)
}

fn cleanup_skill_mutation_journal_stages_locked(root: &BoundDirectory) -> Result<()> {
    cleanup_skill_mutation_journal_stages_with_limit(root, MAX_SKILL_ENTRIES)
}

fn cleanup_skill_mutation_journal_stages_with_limit(
    root: &BoundDirectory,
    max_root_entries: usize,
) -> Result<()> {
    let entries = root.dir.entries().with_context(|| {
        format!(
            "enumerate skill mutation journal stages under {}",
            root.display_path.display()
        )
    })?;
    let mut journal_stages = Vec::new();
    let mut root_entry_count = 0usize;
    for entry in entries {
        root_entry_count = root_entry_count
            .checked_add(1)
            .context("skill mutation journal cleanup entry counter overflow")?;
        if root_entry_count > max_root_entries {
            anyhow::bail!(
                "skill mutation journal cleanup under {} exceeds the {max_root_entries}-entry limit",
                root.display_path.display()
            );
        }
        let entry = entry.with_context(|| {
            format!(
                "read skill mutation journal stage under {}",
                root.display_path.display()
            )
        })?;
        let name = entry.file_name();
        let Some(name_text) = name.to_str() else {
            continue;
        };
        let Some(operation_id) = name_text.strip_prefix(SKILL_MUTATION_JOURNAL_STAGE_PREFIX) else {
            continue;
        };
        validate_mutation_operation_id(operation_id)
            .context("malformed private skill mutation journal stage")?;
        journal_stages.push(name);
    }
    // Finish the bounded, validating preflight before mutating anything. A
    // later over-budget or malformed entry must not leave a partially-cleaned
    // root that makes the failed operation look more successful than it was.
    for name in &journal_stages {
        remove_private_metadata_stage_if_present(root, name)?;
    }
    if !journal_stages.is_empty() {
        sync_directory(&root.dir, &root.display_path)
            .context("sync orphaned skill mutation journal stage cleanup")?;
    }
    Ok(())
}

pub(crate) fn recover_pending_transactions_locked(root: &BoundDirectory) -> Result<()> {
    if let Some(record) = read_skill_mutation_journal(root)? {
        anyhow::bail!(
            "pending audited skill mutation {} ({}/{}) requires WAL reconciliation",
            record.operation_id,
            record.kind.as_str(),
            record.phase.as_str()
        );
    }
    cleanup_skill_mutation_journal_stages_locked(root)?;
    let mut pending = BTreeMap::<String, PendingTransaction>::new();
    let mut delete_tombstones = Vec::<OsString>::new();
    let mut creator_directory_stages = Vec::<OsString>::new();
    let mut public_skill_directories = Vec::<OsString>::new();
    let entries = root.dir.entries().with_context(|| {
        format!(
            "enumerate pending skill transactions under {}",
            root.display_path.display()
        )
    })?;
    let mut root_entry_count = 0usize;
    for entry in entries {
        root_entry_count = root_entry_count
            .checked_add(1)
            .context("skill recovery entry counter overflow")?;
        if root_entry_count > MAX_SKILL_ENTRIES {
            anyhow::bail!(
                "skill recovery under {} exceeds the {MAX_SKILL_ENTRIES}-entry limit",
                root.display_path.display()
            );
        }
        let entry = entry.with_context(|| {
            format!(
                "read pending skill transaction under {}",
                root.display_path.display()
            )
        })?;
        let name = entry.file_name();
        if matches_private_stage_marker(&name, CREATOR_DIRECTORY_STAGE_PREFIX, &root.display_path) {
            let display_path = root.display_path.join(&name);
            drop(
                open_real_child_dir(&root.dir, &name, &display_path).with_context(|| {
                    format!(
                        "creator stage must be a real directory: {}",
                        display_path.display()
                    )
                })?,
            );
            creator_directory_stages.push(name);
            continue;
        }
        if parse_delete_transaction_artifact(&name)?.is_some() {
            let display_path = root.display_path.join(&name);
            drop(
                open_real_child_dir(&root.dir, &name, &display_path).with_context(|| {
                    format!(
                        "pending uninstall tombstone must be a real directory: {}",
                        display_path.display()
                    )
                })?,
            );
            delete_tombstones.push(name);
            continue;
        }
        let Some((kind, id)) = parse_transaction_artifact(&name)? else {
            if name.as_encoded_bytes().first() != Some(&b'.')
                && entry.file_type().is_ok_and(|file_type| file_type.is_dir())
            {
                public_skill_directories.push(name);
            }
            continue;
        };
        let display_path = root.display_path.join(&name);
        drop(
            open_real_child_dir(&root.dir, &name, &display_path).with_context(|| {
                format!(
                    "pending skill transaction must be a real directory: {}",
                    display_path.display()
                )
            })?,
        );
        let transaction = pending.entry(id).or_default();
        match kind {
            TransactionArtifactKind::Stage => transaction.stages.push(name),
            TransactionArtifactKind::Backup => transaction.backups.push(name),
        }
    }

    if let Some((id, transaction)) = pending
        .iter()
        .find(|(_, transaction)| !transaction.backups.is_empty())
    {
        anyhow::bail!(
            "legacy skill recovery found {} journal-less backup generation(s) for `{id}` under {}; \
             refusing to publish or delete unauthenticated rollback evidence",
            transaction.backups.len(),
            root.display_path.display()
        );
    }

    // A tombstone is the only recoverable proof that the public uninstall
    // rename happened. Persist that rename before deleting the tombstone;
    // otherwise a crash can resurrect the public name after recovery already
    // discarded the only private generation.
    if !delete_tombstones.is_empty() {
        sync_directory(&root.dir, &root.display_path)?;
    }
    for stage in &creator_directory_stages {
        remove_transaction_directory(root, stage, None)?;
    }
    for tombstone in &delete_tombstones {
        remove_transaction_directory(root, tombstone, None)?;
    }
    if !creator_directory_stages.is_empty() || !delete_tombstones.is_empty() {
        sync_directory(&root.dir, &root.display_path)?;
    }

    for name in public_skill_directories {
        let display_path = root.display_path.join(&name);
        let Ok(directory) = open_real_child_dir(&root.dir, &name, &display_path) else {
            // Unsafe public entries remain visible as BROKEN and removable;
            // recovery must not follow them merely to search for private files.
            continue;
        };
        cleanup_private_file_stages(&directory, &display_path)?;
    }

    for (id, mut transaction) in pending {
        transaction.stages.sort();
        transaction.backups.sort();
        let public_path = root.display_path.join(&id);
        let public_exists = match root.dir.symlink_metadata(&id) {
            Ok(_) => {
                drop(open_real_child_dir(
                    &root.dir,
                    OsStr::new(&id),
                    &public_path,
                )?);
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("inspect skill during recovery {}", public_path.display())
                });
            }
        };

        // When a public generation and a private rollback generation coexist,
        // first make the observed winner + rollback namespace durable. Only
        // then may recovery discard the rollback tree.
        if public_exists && (!transaction.stages.is_empty() || !transaction.backups.is_empty()) {
            sync_directory(&root.dir, &root.display_path)?;
        }
        for artifact in transaction.stages.iter().chain(transaction.backups.iter()) {
            remove_transaction_directory(root, artifact, None)?;
        }
        if !transaction.stages.is_empty() || !transaction.backups.is_empty() {
            sync_directory(&root.dir, &root.display_path)?;
        }
    }
    Ok(())
}

/// What one directory entry is, relative to a private stage-marker prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrivateStageMarker {
    /// Exactly one of ours — recover it.
    Ours,
    /// Carries the reserved prefix but not the 32-hex nonce. NOT one of ours:
    /// recovery must neither act on it nor guess what it was.
    Malformed,
    /// Unrelated entry.
    Foreign,
}

/// Classify a private crash-recovery artifact by its fixed-shape marker.
///
/// The marker prevents transaction-name collisions; it is not a credential.
/// Malformed names are untrusted filesystem input and are never copied into
/// diagnostics a caller may persist.
///
/// A malformed marker is reported, not fatal. Failing the store on it was a
/// self-inflicted denial of service: skill packages are externally sourced, the
/// install copy was name-agnostic, and recovery runs `?`-propagated ahead of
/// every store read — so a single package file named `.skill-yaml.stage-readme`
/// wedged `neoth serve`, `neoth chat`, the inventory AND the uninstall that
/// could have removed it, leaving no in-product repair path. Planting one is now
/// refused at install time (see [`RESERVED_SKILL_ENTRY_PREFIXES`]); an entry
/// that still appears is left untouched for the operator.
fn classify_private_stage_marker(name: &OsStr, prefix: &str) -> PrivateStageMarker {
    let Some(name) = name.to_str() else {
        return PrivateStageMarker::Foreign;
    };
    let Some(nonce) = name.strip_prefix(prefix) else {
        return PrivateStageMarker::Foreign;
    };
    if nonce.len() == 32
        && nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        PrivateStageMarker::Ours
    } else {
        PrivateStageMarker::Malformed
    }
}

/// True only for an artifact this store owns. A malformed marker is reported
/// once — WITHOUT echoing the untrusted name — and then ignored.
fn matches_private_stage_marker(name: &OsStr, prefix: &str, directory: &Path) -> bool {
    match classify_private_stage_marker(name, prefix) {
        PrivateStageMarker::Ours => true,
        PrivateStageMarker::Malformed => {
            tracing::warn!(
                directory = %directory.display(),
                prefix,
                "ignoring a foreign entry that carries a reserved private skill stage prefix \
                 with a malformed nonce; it is not a recoverable transaction"
            );
            false
        }
        PrivateStageMarker::Foreign => false,
    }
}

/// Reserved private-artifact prefixes that a skill package may never carry.
///
/// Rejected at install time so a foreign file can never occupy the namespace
/// this store's crash recovery owns.
const RESERVED_SKILL_ENTRY_PREFIXES: [&str; 3] = [
    CREATOR_DIRECTORY_STAGE_PREFIX,
    CREATOR_MANIFEST_STAGE_PREFIX,
    FILE_REPLACEMENT_STAGE_PREFIX,
];

fn cleanup_private_file_stages(directory: &Dir, display_directory: &Path) -> Result<()> {
    let entries = directory.entries().with_context(|| {
        format!(
            "enumerate private skill stages under {}",
            display_directory.display()
        )
    })?;
    let mut stages = Vec::new();
    let mut entry_count = 0usize;
    for entry in entries {
        entry_count = entry_count
            .checked_add(1)
            .context("private skill stage entry counter overflow")?;
        if entry_count > MAX_SKILL_ENTRIES {
            anyhow::bail!(
                "private stage recovery under {} exceeds the {MAX_SKILL_ENTRIES}-entry limit",
                display_directory.display()
            );
        }
        let entry = entry.with_context(|| {
            format!(
                "read private skill stage under {}",
                display_directory.display()
            )
        })?;
        let name = entry.file_name();
        if matches_private_stage_marker(&name, CREATOR_MANIFEST_STAGE_PREFIX, display_directory)
            || matches_private_stage_marker(&name, FILE_REPLACEMENT_STAGE_PREFIX, display_directory)
        {
            let metadata = directory.symlink_metadata(&name).with_context(|| {
                format!(
                    "inspect private skill stage {}",
                    display_directory.join(&name).display()
                )
            })?;
            if metadata.is_dir() && !cap_metadata_is_link_like(&metadata) {
                anyhow::bail!(
                    "private skill file stage is unexpectedly a directory: {}",
                    display_directory.join(&name).display()
                );
            }
            stages.push(name);
        }
    }
    for stage in stages.iter() {
        remove_child_file(directory, stage, &display_directory.join(stage))?;
    }
    if !stages.is_empty() {
        sync_directory(directory, display_directory)?;
    }
    Ok(())
}

fn parse_delete_transaction_artifact(name: &OsStr) -> Result<Option<String>> {
    let Some(name) = name.to_str() else {
        return Ok(None);
    };
    let Some(body) = name.strip_prefix(DELETE_TRANSACTION_PREFIX) else {
        return Ok(None);
    };
    let Some((id, nonce)) = body.rsplit_once('-') else {
        anyhow::bail!("malformed pending skill uninstall name `{name}`");
    };
    if nonce.len() != 32
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        anyhow::bail!("malformed pending skill uninstall nonce in `{name}`");
    }
    validate_installed_skill_dir_name(id)
        .with_context(|| format!("malformed pending skill uninstall id in `{name}`"))?;
    Ok(Some(id.to_string()))
}

fn parse_transaction_artifact(name: &OsStr) -> Result<Option<(TransactionArtifactKind, String)>> {
    let Some(name) = name.to_str() else {
        return Ok(None);
    };
    let (kind, body) = if let Some(body) = name.strip_prefix(INSTALL_TRANSACTION_PREFIX) {
        (TransactionArtifactKind::Stage, body)
    } else if let Some(body) = name.strip_prefix(BACKUP_TRANSACTION_PREFIX) {
        (TransactionArtifactKind::Backup, body)
    } else {
        return Ok(None);
    };
    let Some((id, nonce)) = body.rsplit_once('-') else {
        anyhow::bail!("malformed pending skill transaction name `{name}`");
    };
    if nonce.len() != 32
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        anyhow::bail!("malformed pending skill transaction nonce in `{name}`");
    }
    super::creator::validate_skill_id(id)
        .with_context(|| format!("malformed pending skill transaction id in `{name}`"))?;
    Ok(Some((kind, id.to_string())))
}

fn remove_transaction_directory(
    root: &BoundDirectory,
    name: &OsStr,
    expected_identity: Option<&str>,
) -> Result<()> {
    let display_path = root.display_path.join(name);
    let observed = bind_real_child_dir(&root.dir, name, &display_path).with_context(|| {
        format!(
            "refuse to remove unsafe pending skill transaction {}",
            display_path.display()
        )
    })?;
    if let Some(expected_identity) = expected_identity {
        anyhow::ensure!(
            observed.identity_token() == expected_identity,
            "refuse to remove pending skill transaction whose identity changed: {}",
            display_path.display()
        );
    }
    let observed_identity = observed.identity_token().to_string();
    drop(observed);
    remove_bound_real_directory_tree(&root.dir, name, &display_path, &observed_identity)
        .with_context(|| {
            format!(
                "remove pending skill transaction {}",
                display_path.display()
            )
        })
}

fn remove_transaction_artifact_if_present(
    root: &BoundDirectory,
    name: &OsStr,
    expected_identity: Option<&str>,
) -> Result<()> {
    let display = root.display_path.join(name);
    match root.dir.symlink_metadata(name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(metadata) if metadata.is_dir() && !cap_metadata_is_link_like(&metadata) => {
            remove_transaction_directory(root, name, expected_identity)
        }
        Ok(_) if expected_identity.is_some() => anyhow::bail!(
            "refuse to remove pending skill transaction whose bound directory changed type: {}",
            display.display()
        ),
        Ok(_) => remove_child_file(&root.dir, name, &display)
            .with_context(|| format!("remove private skill artifact {}", display.display())),
        Err(error) => Err(error)
            .with_context(|| format!("inspect private skill artifact {}", display.display())),
    }
}

fn sync_directory(directory: &Dir, display_path: &Path) -> Result<()> {
    #[cfg(test)]
    {
        let fail_at = TEST_SYNC_FAIL_AT.with(|target| {
            let call = TEST_SYNC_CALLS.with(|calls| {
                let next = calls.get().saturating_add(1);
                calls.set(next);
                next
            });
            if target.get() == Some(call) {
                target.set(None);
                true
            } else {
                false
            }
        });
        let fail_next = TEST_SYNC_FAILURES.with(|remaining| {
            let count = remaining.get();
            if count > 0 {
                remaining.set(count - 1);
                true
            } else {
                false
            }
        });
        if fail_at || fail_next {
            anyhow::bail!(
                "injected skill directory sync failure for {}",
                display_path.display()
            );
        }
    }
    #[cfg(unix)]
    {
        directory
            .open(".")
            .and_then(|file| file.sync_all())
            .with_context(|| format!("sync skill directory {}", display_path.display()))?;
    }
    #[cfg(not(unix))]
    {
        // Windows namespace commits in `skills::store::{rename_child,
        // remove_child_file}` use no-follow handles opened with
        // FILE_FLAG_WRITE_THROUGH. There is no portable cap-std equivalent of
        // fsyncing a directory handle there; the handle-bound mutation itself
        // is the durability boundary.
        let _ = (directory, display_path);
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    static TEST_SYNC_FAILURES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static TEST_SYNC_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static TEST_SYNC_FAIL_AT: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn fail_next_directory_syncs(count: usize) {
    TEST_SYNC_FAILURES.with(|remaining| remaining.set(count));
}

#[cfg(test)]
fn fail_directory_sync_call(call: usize) {
    TEST_SYNC_CALLS.with(|calls| calls.set(0));
    TEST_SYNC_FAIL_AT.with(|target| target.set(Some(call)));
}

#[cfg(test)]
fn clear_directory_sync_failure() {
    TEST_SYNC_FAILURES.with(|remaining| remaining.set(0));
    TEST_SYNC_CALLS.with(|calls| calls.set(0));
    TEST_SYNC_FAIL_AT.with(|target| target.set(None));
}

fn cleanup_after_failed_operation(
    error: anyhow::Error,
    root: &Dir,
    child: &OsStr,
    label: &str,
) -> anyhow::Error {
    match remove_real_directory_tree(root, child, Path::new(child)) {
        Ok(()) => error,
        Err(cleanup_error)
            if cleanup_error
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            error
        }
        Err(cleanup_error) => error.context(format!(
            "cleanup of {label} `{}` also failed: {cleanup_error}",
            child.to_string_lossy()
        )),
    }
}

/// Cross-thread-capable ownership of the capability-bound OS lock.
///
/// The file lock is the single serialization authority for both threads and
/// processes. Keeping a `std::sync::MutexGuard` here made every audited async
/// reconciliation future non-`Send`, so registry hot reload could not run in
/// its Tokio task.
pub(crate) struct SkillMutationGuard {
    _file: std::fs::File,
}

#[cfg(test)]
thread_local! {
    static TEST_SKILL_MUTATION_LOCK_OPEN_NOT_FOUND_REMAINING: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn fail_skill_mutation_lock_open_with_not_found_for_test(attempts: usize) {
    TEST_SKILL_MUTATION_LOCK_OPEN_NOT_FOUND_REMAINING.with(|remaining| remaining.set(attempts));
}

#[cfg(test)]
fn take_skill_mutation_lock_open_not_found_for_test() -> Option<std::io::Error> {
    TEST_SKILL_MUTATION_LOCK_OPEN_NOT_FOUND_REMAINING.with(|remaining| {
        let attempts = remaining.get();
        if attempts == 0 {
            None
        } else {
            remaining.set(attempts - 1);
            Some(std::io::Error::from(std::io::ErrorKind::NotFound))
        }
    })
}

pub(crate) fn lock_skill_mutations(root: &BoundDirectory) -> Result<SkillMutationGuard> {
    let started = std::time::Instant::now();
    loop {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .follow(FollowSymlinks::No);
        #[cfg(windows)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            const FILE_SHARE_READ: u32 = 0x0000_0001;
            options.share_mode(FILE_SHARE_READ);
        }
        let opened = {
            #[cfg(test)]
            if let Some(error) = take_skill_mutation_lock_open_not_found_for_test() {
                Err(error)
            } else {
                root.dir.open_with(SKILL_MUTATION_LOCK_FILE, &options)
            }
            #[cfg(not(test))]
            root.dir.open_with(SKILL_MUTATION_LOCK_FILE, &options)
        };
        let file = match opened {
            Ok(file) => file,
            #[cfg(windows)]
            Err(error) if error.raw_os_error() == Some(32) => {
                if started.elapsed() >= std::time::Duration::from_secs(5) {
                    anyhow::bail!(
                        "skills mutation lock held for >5s at {}",
                        root.display_path.join(SKILL_MUTATION_LOCK_FILE).display()
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
            // On macOS, cap-std resolves this no-follow create one component
            // at a time. A concurrent creator can transiently surface ENOENT
            // even though this already-bound root remains live. Re-open only
            // through that capability; no ambient path is re-resolved and the
            // regular-file/no-follow verification below remains mandatory.
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && started.elapsed() < std::time::Duration::from_secs(5) =>
            {
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "open skills mutation lock {}",
                        root.display_path.join(SKILL_MUTATION_LOCK_FILE).display()
                    )
                });
            }
        };
        let metadata = file.metadata().context("inspect skills mutation lock")?;
        if !metadata.is_file() || cap_metadata_is_link_like(&metadata) {
            anyhow::bail!(
                "skills mutation lock is not a real regular file: {}",
                root.display_path.join(SKILL_MUTATION_LOCK_FILE).display()
            );
        }
        let file = file.into_std();
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd as _;
            // SAFETY: flock is called on a live owned regular-file descriptor.
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result != 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::WouldBlock
                    && started.elapsed() < std::time::Duration::from_secs(5)
                {
                    drop(file);
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    continue;
                }
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    anyhow::bail!(
                        "skills mutation lock held for >5s at {}",
                        root.display_path.join(SKILL_MUTATION_LOCK_FILE).display()
                    );
                }
                return Err(error).with_context(|| {
                    format!(
                        "lock skills mutation file {}",
                        root.display_path.join(SKILL_MUTATION_LOCK_FILE).display()
                    )
                });
            }
        }
        return Ok(SkillMutationGuard { _file: file });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::{TempDir, tempdir};

    struct TestSkillsRoot {
        _home: TempDir,
        skills: PathBuf,
    }

    impl TestSkillsRoot {
        fn path(&self) -> &Path {
            &self.skills
        }
    }

    fn temp_skills_root() -> TestSkillsRoot {
        let home = tempdir().unwrap();
        let skills = home.path().join("skills");
        std::fs::create_dir(&skills).unwrap();
        TestSkillsRoot {
            _home: home,
            skills,
        }
    }

    #[cfg(unix)]
    fn try_symlink_dir(source: &Path, target: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(source, target)
    }

    #[cfg(windows)]
    fn try_symlink_dir(source: &Path, target: &Path) -> std::io::Result<()> {
        match std::os::windows::fs::symlink_dir(source, target) {
            Ok(()) => Ok(()),
            Err(_) => {
                let status = std::process::Command::new("cmd.exe")
                    .args(["/D", "/C", "mklink", "/J"])
                    .arg(target)
                    .arg(source)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()?;
                if status.success() {
                    Ok(())
                } else {
                    Err(std::io::Error::other(format!(
                        "mklink /J failed with {status}"
                    )))
                }
            }
        }
    }

    fn write_skill(dir: &Path, id: &str, body: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("skill.yaml"), body).unwrap();
        let _ = id; // dir name supplies the id
    }

    fn good_yaml(id: &str) -> String {
        format!(
            "id: {id}\n\
             description: A test skill\n\
             trigger_keywords: [fixture-{id}-trigger]\n\
             system_prompt: You are a test skill.\n"
        )
    }

    fn transaction_names(id: &str) -> (String, String) {
        let nonce = "0123456789abcdef0123456789abcdef";
        (
            format!("{INSTALL_TRANSACTION_PREFIX}{id}-{nonce}"),
            format!("{BACKUP_TRANSACTION_PREFIX}{id}-{nonce}"),
        )
    }

    fn prepared_journal_for_id(kind: SkillMutationKind, skill_id: &str) -> SkillMutationJournal {
        SkillMutationJournal {
            version: SKILL_MUTATION_JOURNAL_VERSION,
            operation_id: "0123456789abcdef0123456789abcdef".to_string(),
            kind,
            origin: SkillMutationOrigin::CliInstall,
            skill_id: skill_id.to_string(),
            mutation_sequence: None,
            previous_terminal_receipt_sha256: None,
            prior_install_incarnation: None,
            resulting_install_incarnation: None,
            source_generation_sha256: kind.is_install().then(|| "a".repeat(64)),
            prior_generation_sha256: (kind == SkillMutationKind::Replace).then(|| "b".repeat(64)),
            prior_object_identity: (kind == SkillMutationKind::Replace)
                .then(|| "windows:00000001:0000000000000001:dir".to_string()),
            intent_delivery_owner_nonce: None,
            intent_receipt: None,
            commit_boundary_nonce: None,
            phase: SkillMutationPhase::Prepared,
            observed_generation_sha256: None,
            error_sha256: None,
            terminal_delivery_state: SkillTerminalDeliveryState::NotStarted,
            terminal_delivery_owner_nonce: None,
            terminal_receipt: None,
            cleanup_started: None,
            created_at_unix: 0,
        }
    }

    #[test]
    fn mutation_journal_accepts_legacy_ids_only_for_removal() {
        let legacy_id = "legacy skill.β";
        assert!(
            validate_skill_mutation_journal(&prepared_journal_for_id(
                SkillMutationKind::Remove,
                legacy_id,
            ))
            .is_ok()
        );
        for kind in [SkillMutationKind::Install, SkillMutationKind::Replace] {
            let error = validate_skill_mutation_journal(&prepared_journal_for_id(kind, legacy_id))
                .unwrap_err();
            // The validator now states the rule it enforced ("skill id may
            // only contain lowercase [a-z0-9_-]") instead of a bare "invalid
            // skill id" — more useful, and it strands a test pinned to the old
            // wording. Assert what the test is about: the rejection is about
            // the id, and it names the offending value.
            let detail = format!("{error:#}");
            assert!(
                detail.contains("skill id") && detail.contains(legacy_id),
                "{kind:?} must retain the canonical creator id boundary: {detail}"
            );
        }
        for kind in [
            SkillMutationKind::Install,
            SkillMutationKind::Replace,
            SkillMutationKind::Remove,
        ] {
            validate_skill_mutation_journal(&prepared_journal_for_id(kind, "canonical_skill"))
                .unwrap();
        }
    }

    fn force_indeterminate_removal_after_parent_sync_failure(
        skills_dir: &Path,
        id: &str,
        operation_id: &str,
    ) -> PathBuf {
        let public = skills_dir.join(id);
        write_skill(&public, id, &good_yaml(id));
        std::fs::write(public.join("sentinel"), b"recoverable").unwrap();
        let mut prepared = prepare_uninstall_with_expectation(skills_dir, id, None, operation_id)
            .unwrap()
            .into_prepared_for_test();
        prepared.mark_intent_durable().unwrap();

        // commit-start journal sync is call 1; the tombstone rename's parent
        // fsync is call 2 and must leave exact rollback evidence.
        fail_directory_sync_call(2);
        let error = prepared.commit().unwrap_err();
        clear_directory_sync_failure();
        assert_eq!(error.state(), SkillMutationFailureState::Indeterminate);
        assert!(!public.exists());

        let tombstone = skills_dir.join(format!("{DELETE_TRANSACTION_PREFIX}{id}-{operation_id}"));
        assert!(tombstone.exists());
        tombstone
    }

    #[test]
    fn skill_mutation_guard_can_cross_async_worker_threads() {
        fn assert_send<T: Send>() {}
        assert_send::<SkillMutationGuard>();
    }

    #[test]
    fn second_os_process_is_blocked_by_the_held_skill_mutation_lock() {
        // GOLD-R3-11 cross-process regression: prove the capability-bound store
        // mutation lock serialises SEPARATE OS PROCESSES (the Unix flock /
        // Windows share-mode open), not merely threads sharing the in-process
        // mutex — thread-only evidence does not establish the Windows/macOS/
        // Linux release claim.
        //
        // Child mode: this same test is re-execed by the parent with the shared
        // directory in the environment; it attempts the lock and exits 0 when it
        // acquires, 3 when it is blocked.
        const CHILD_ENV: &str = "NEOTH_SKILL_LOCK_CHILD";
        const TEST_PATH: &str = "skills::installer::tests::second_os_process_is_blocked_by_the_held_skill_mutation_lock";

        if let Ok(shared) = std::env::var(CHILD_ENV) {
            let root = open_or_create_bound_skills_root(Path::new(&shared))
                .expect("child: open bound dir");
            match lock_skill_mutations(&root) {
                Ok(_guard) => std::process::exit(0),
                Err(_) => std::process::exit(3),
            }
        }

        let dir = tempdir().unwrap();
        let shared = dir.path();
        let root = open_or_create_bound_skills_root(shared).expect("parent: bound dir present");

        // Parent holds the lock across the child's entire attempt.
        let guard = lock_skill_mutations(&root).expect("parent acquires the lock");
        let blocked = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST_PATH])
            .env(CHILD_ENV, shared)
            .output()
            .expect("spawn blocked child");
        assert_eq!(
            blocked.status.code(),
            Some(3),
            "a second OS process must NOT acquire the lock while it is held (stderr: {})",
            String::from_utf8_lossy(&blocked.stderr)
        );
        drop(guard);

        // Lock released → a second OS process can now acquire it.
        let acquired = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST_PATH])
            .env(CHILD_ENV, shared)
            .output()
            .expect("spawn acquiring child");
        assert_eq!(
            acquired.status.code(),
            Some(0),
            "once released a second OS process must acquire the lock (stderr: {})",
            String::from_utf8_lossy(&acquired.stderr)
        );
    }

    #[test]
    fn skill_mutation_lock_retries_a_transient_nofollow_open_not_found() {
        let root = temp_skills_root();
        let bound = open_or_create_bound_skills_root(root.path()).unwrap();

        // cap-std's component-at-a-time no-follow resolver has surfaced this
        // transient ENOENT under concurrent macOS creates. The existing bound
        // root capability is still authoritative, so retrying the exact
        // handle-relative open must acquire the same lock rather than fail a
        // cooperating writer.
        fail_skill_mutation_lock_open_with_not_found_for_test(1);
        let _guard = lock_skill_mutations(&bound).unwrap();

        let metadata = bound
            .dir
            .symlink_metadata(SKILL_MUTATION_LOCK_FILE)
            .unwrap();
        assert!(metadata.is_file());
        assert!(!cap_metadata_is_link_like(&metadata));
    }

    #[test]
    fn install_from_local_copies_skill_dir_into_target() {
        let staging = tempdir().unwrap();
        let dest = temp_skills_root();

        let src = staging.path().join("my_skill_source");
        write_skill(&src, "my_skill", &good_yaml("my_skill"));

        let report = install_from_local(&src, dest.path(), false).expect("install must succeed");
        assert_eq!(report.id, "my_skill");
        assert!(!report.replaced_existing);
        assert!(report.installed_at.exists());
        assert!(report.installed_at.join("skill.yaml").exists());
    }

    #[test]
    fn prepared_install_keeps_public_anchor_absent_until_commit_and_retries_cleanly() {
        let staging = tempdir().unwrap();
        let dest = temp_skills_root();
        let source = staging.path().join("source");
        write_skill(&source, "prepared", &good_yaml("prepared"));
        std::fs::write(source.join("asset.txt"), b"prepared bytes").unwrap();
        let operation_id = "0123456789abcdef0123456789abcdef";

        let prepared = prepare_install_from_local_with_expectation(
            &source,
            dest.path(),
            false,
            None,
            operation_id,
        )
        .unwrap();
        let binding = prepared.intent_binding();
        assert_eq!(binding.operation_id, operation_id);
        assert_eq!(binding.id, "prepared");
        assert!(!binding.replacing_existing);
        assert_eq!(binding.target_generation_sha256, None);
        assert!(
            !dest.path().join("prepared").exists(),
            "private preparation must not publish the public Skill anchor"
        );
        assert!(
            dest.path()
                .join(format!(
                    "{INSTALL_TRANSACTION_PREFIX}prepared-{operation_id}"
                ))
                .exists(),
            "the private stage must be bound to the operation id"
        );

        // Simulate interruption after preparation but before the intent ACK.
        // Recovery proves that no WAL intent exists, removes only the private
        // stage/journal, and the SAME operation id remains safe to retry.
        drop(prepared);
        let mut pending = open_pending_skill_mutation_reconciliation(dest.path())
            .unwrap()
            .expect("prepared journal must survive interruption");
        assert_eq!(pending.audit_binding().operation_id, operation_id);
        assert!(pending.reconcile(false).unwrap().is_none());
        assert!(!dest.path().join("prepared").exists());
        drop(pending);
        let mut retry = prepare_install_from_local_with_expectation(
            &source,
            dest.path(),
            false,
            None,
            operation_id,
        )
        .unwrap();
        assert_eq!(retry.intent_binding(), binding);
        retry.mark_intent_durable().unwrap();
        let report = retry.commit().unwrap();
        assert_eq!(
            report.source_generation_sha256,
            binding.source_generation_sha256
        );
        assert_eq!(
            std::fs::read(dest.path().join("prepared").join("asset.txt")).unwrap(),
            b"prepared bytes"
        );
    }

    #[test]
    fn prepared_replace_binds_old_anchor_and_keeps_it_live_until_commit() {
        let staging = tempdir().unwrap();
        let dest = temp_skills_root();
        let old_source = staging.path().join("old");
        write_skill(&old_source, "replace_me", &good_yaml("replace_me"));
        std::fs::write(old_source.join("asset.txt"), b"old").unwrap();
        let old = install_from_local(&old_source, dest.path(), false).unwrap();

        let new_source = staging.path().join("new");
        write_skill(&new_source, "replace_me", &good_yaml("replace_me"));
        std::fs::write(new_source.join("asset.txt"), b"new").unwrap();
        let operation_id = "11111111111111111111111111111111";
        let mut prepared = prepare_install_from_local_with_expectation(
            &new_source,
            dest.path(),
            true,
            None,
            operation_id,
        )
        .unwrap();
        let binding = prepared.intent_binding();

        assert!(binding.replacing_existing);
        assert_eq!(
            binding.target_generation_sha256.as_deref(),
            Some(old.source_generation_sha256.as_str())
        );
        assert_eq!(
            std::fs::read(dest.path().join("replace_me").join("asset.txt")).unwrap(),
            b"old",
            "prepare must leave the old public anchor unchanged"
        );

        prepared.mark_intent_durable().unwrap();
        let report = prepared.commit().unwrap();
        assert!(report.replaced_existing);
        assert_eq!(
            report.replaced_generation_sha256,
            binding.target_generation_sha256
        );
        assert_eq!(
            std::fs::read(dest.path().join("replace_me").join("asset.txt")).unwrap(),
            b"new"
        );
    }

    #[test]
    fn prepared_install_abort_removes_only_private_stage() {
        let staging = tempdir().unwrap();
        let dest = temp_skills_root();
        let source = staging.path().join("source");
        write_skill(&source, "abort_me", &good_yaml("abort_me"));
        let operation_id = "22222222222222222222222222222222";
        let stage = dest.path().join(format!(
            "{INSTALL_TRANSACTION_PREFIX}abort_me-{operation_id}"
        ));

        let prepared = prepare_install_from_local_with_expectation(
            &source,
            dest.path(),
            false,
            None,
            operation_id,
        )
        .unwrap();
        assert!(stage.exists());
        prepared.abort_without_intent().unwrap();

        assert!(!stage.exists());
        assert!(!dest.path().join("abort_me").exists());
    }

    #[test]
    fn bound_pending_stage_cleanup_rejects_a_same_name_swap_before_delete() {
        let dest = temp_skills_root();
        let operation_id = "20202020202020202020202020202020";
        let stage_name = OsString::from(format!(
            "{INSTALL_TRANSACTION_PREFIX}swap_cleanup-{operation_id}"
        ));
        let stage = dest.path().join(&stage_name);
        let displaced = dest.path().join("displaced-private-stage");
        write_skill(&stage, "swap_cleanup", &good_yaml("swap_cleanup"));

        let root = open_bound_directory(dest.path(), false, "test skills root")
            .unwrap()
            .unwrap();
        let _guard = lock_skill_mutations(&root).unwrap();
        let expected_identity = bind_real_child_dir(&root.dir, &stage_name, &stage)
            .unwrap()
            .identity_token()
            .to_string();

        std::fs::rename(&stage, &displaced).unwrap();
        write_skill(&stage, "swap_cleanup", &good_yaml("swap_cleanup"));

        let error = remove_transaction_directory(&root, &stage_name, Some(&expected_identity))
            .unwrap_err();
        assert!(format!("{error:#}").contains("identity changed"));
        assert!(stage.exists(), "same-name replacement must never be deleted");
        assert!(displaced.exists(), "original private evidence must be retained");
    }

    #[test]
    fn crash_after_intent_before_commit_recovers_same_operation_as_aborted() {
        let staging = tempdir().unwrap();
        let dest = temp_skills_root();
        let source = staging.path().join("source");
        write_skill(&source, "intent_crash", &good_yaml("intent_crash"));
        let operation_id = "abababababababababababababababab";

        let mut prepared = prepare_install_from_local_with_expectation(
            &source,
            dest.path(),
            false,
            None,
            operation_id,
        )
        .unwrap();
        prepared.mark_intent_durable().unwrap();
        let stage = dest
            .path()
            .join(mutation_install_stage_name(&prepared.journal));
        drop(prepared);

        let mut pending = open_pending_skill_mutation_reconciliation(dest.path())
            .unwrap()
            .unwrap();
        assert_eq!(pending.audit_binding().operation_id, operation_id);
        let terminal = pending.reconcile(true).unwrap().unwrap();
        assert_eq!(terminal.operation_id, operation_id);
        assert_eq!(terminal.phase, SkillMutationPhase::Aborted);
        assert!(stage.exists(), "evidence remains until terminal WAL ACK");
        pending.acknowledge_terminal().unwrap();
        assert!(!stage.exists());
        assert!(!dest.path().join(SKILL_MUTATION_JOURNAL_FILE).exists());
    }

    #[test]
    fn crash_at_commit_started_before_rename_is_aborted_not_committed() {
        let staging = tempdir().unwrap();
        let dest = temp_skills_root();
        let source = staging.path().join("source");
        write_skill(&source, "before_rename", &good_yaml("before_rename"));
        let operation_id = "bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc";

        let mut prepared = prepare_install_from_local_with_expectation(
            &source,
            dest.path(),
            false,
            None,
            operation_id,
        )
        .unwrap();
        prepared.mark_intent_durable().unwrap();
        transition_skill_mutation_phase(
            &prepared.target_root,
            &mut prepared.journal,
            SkillMutationPhase::CommitStarted,
            None,
            None,
        )
        .unwrap();
        drop(prepared);

        let mut pending = open_pending_skill_mutation_reconciliation(dest.path())
            .unwrap()
            .unwrap();
        let terminal = pending.reconcile(true).unwrap().unwrap();
        assert_eq!(terminal.operation_id, operation_id);
        assert_eq!(terminal.phase, SkillMutationPhase::Aborted);
        assert!(!dest.path().join("before_rename").exists());
        pending.acknowledge_terminal().unwrap();
    }

    #[test]
    fn crash_after_public_rename_before_dirsync_is_indeterminate() {
        let staging = tempdir().unwrap();
        let dest = temp_skills_root();
        let source = staging.path().join("source");
        write_skill(&source, "after_rename", &good_yaml("after_rename"));
        let operation_id = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

        let mut prepared = prepare_install_from_local_with_expectation(
            &source,
            dest.path(),
            false,
            None,
            operation_id,
        )
        .unwrap();
        prepared.mark_intent_durable().unwrap();
        transition_skill_mutation_phase(
            &prepared.target_root,
            &mut prepared.journal,
            SkillMutationPhase::CommitStarted,
            None,
            None,
        )
        .unwrap();
        let stage = prepared.stage_name.clone();
        rename_child(
            &prepared.target_root.dir,
            &stage,
            &prepared.target_root.dir,
            OsStr::new("after_rename"),
            false,
            &prepared.target_root.display_path.join(&stage),
            &prepared.target_root.display_path.join("after_rename"),
        )
        .unwrap();
        // Deliberately skip the parent-directory fsync and terminal transition.
        drop(prepared);

        let mut pending = open_pending_skill_mutation_reconciliation(dest.path())
            .unwrap()
            .unwrap();
        let terminal = pending.reconcile(true).unwrap().unwrap();
        assert_eq!(terminal.operation_id, operation_id);
        assert_eq!(terminal.phase, SkillMutationPhase::Indeterminate);
        assert!(dest.path().join("after_rename").exists());
        let error = pending.acknowledge_terminal().unwrap_err();
        assert!(format!("{error:#}").contains("exact bound prior namespace"));
        assert!(dest.path().join("after_rename").exists());
        assert!(dest.path().join(SKILL_MUTATION_JOURNAL_FILE).exists());
    }

    #[test]
    fn parent_sync_failure_never_reports_fresh_install_committed() {
        let staging = tempdir().unwrap();
        let dest = temp_skills_root();
        let source = staging.path().join("source");
        write_skill(&source, "sync_install", &good_yaml("sync_install"));
        let operation_id = "dededededededededededededededede";

        let mut prepared = prepare_install_from_local_with_expectation(
            &source,
            dest.path(),
            false,
            None,
            operation_id,
        )
        .unwrap();
        prepared.mark_intent_durable().unwrap();
        fail_directory_sync_call(2);
        let error = prepared.commit().unwrap_err();
        clear_directory_sync_failure();

        assert_eq!(error.state(), SkillMutationFailureState::Indeterminate);
        assert!(dest.path().join("sync_install").exists());
        let record = {
            let root = open_bound_directory(dest.path(), false, "skills")
                .unwrap()
                .unwrap();
            read_skill_mutation_journal(&root).unwrap().unwrap()
        };
        assert_eq!(record.operation_id, operation_id);
        assert_eq!(record.phase, SkillMutationPhase::Indeterminate);
    }

    #[test]
    fn parent_sync_failure_never_reports_replace_committed_and_retains_backup() {
        let staging = tempdir().unwrap();
        let dest = temp_skills_root();
        let old_source = staging.path().join("old");
        write_skill(&old_source, "sync_replace", &good_yaml("sync_replace"));
        std::fs::write(old_source.join("asset.txt"), b"old").unwrap();
        install_from_local(&old_source, dest.path(), false).unwrap();

        let new_source = staging.path().join("new");
        write_skill(&new_source, "sync_replace", &good_yaml("sync_replace"));
        std::fs::write(new_source.join("asset.txt"), b"new").unwrap();
        let operation_id = "efefefefefefefefefefefefefefefef";
        let mut prepared = prepare_install_from_local_with_expectation(
            &new_source,
            dest.path(),
            true,
            None,
            operation_id,
        )
        .unwrap();
        prepared.mark_intent_durable().unwrap();
        let backup = dest.path().join(mutation_backup_name(&prepared.journal));
        // commit-start journal=1, prior->backup sync=2, desired-anchor sync=3.
        fail_directory_sync_call(3);
        let error = prepared.commit().unwrap_err();
        clear_directory_sync_failure();

        assert_eq!(error.state(), SkillMutationFailureState::Indeterminate);
        assert!(
            backup.exists(),
            "rollback generation must remain recoverable"
        );
        assert_eq!(
            std::fs::read(dest.path().join("sync_replace").join("asset.txt")).unwrap(),
            b"new"
        );
        let mut pending = open_pending_skill_mutation_reconciliation(dest.path())
            .unwrap()
            .unwrap();
        let terminal = pending.reconcile(true).unwrap().unwrap();
        assert_eq!(terminal.operation_id, operation_id);
        assert_eq!(terminal.phase, SkillMutationPhase::Indeterminate);
        assert!(backup.exists());
        let error = pending.acknowledge_terminal().unwrap_err();
        assert!(format!("{error:#}").contains("exact bound prior namespace"));
        assert!(backup.exists());
        assert_eq!(
            std::fs::read(dest.path().join("sync_replace").join("asset.txt")).unwrap(),
            b"new"
        );
    }

    #[test]
    fn prior_backup_sync_failure_restores_only_after_indeterminate_terminal_ack() {
        let staging = tempdir().unwrap();
        let dest = temp_skills_root();
        let old_source = staging.path().join("old");
        write_skill(&old_source, "backup_sync", &good_yaml("backup_sync"));
        std::fs::write(old_source.join("asset.txt"), b"old").unwrap();
        install_from_local(&old_source, dest.path(), false).unwrap();

        let new_source = staging.path().join("new");
        write_skill(&new_source, "backup_sync", &good_yaml("backup_sync"));
        std::fs::write(new_source.join("asset.txt"), b"new").unwrap();
        let operation_id = "56565656565656565656565656565656";
        let mut prepared = prepare_install_from_local_with_expectation(
            &new_source,
            dest.path(),
            true,
            None,
            operation_id,
        )
        .unwrap();
        prepared.mark_intent_durable().unwrap();
        let backup = dest.path().join(mutation_backup_name(&prepared.journal));
        let stage = dest
            .path()
            .join(mutation_install_stage_name(&prepared.journal));

        // commit-start journal=1; prior->backup parent sync=2.
        fail_directory_sync_call(2);
        let error = prepared.commit().unwrap_err();
        clear_directory_sync_failure();

        assert_eq!(error.state(), SkillMutationFailureState::Indeterminate);
        assert!(!dest.path().join("backup_sync").exists());
        assert!(
            backup.exists(),
            "the bound rollback generation must survive"
        );
        assert!(
            stage.exists(),
            "the uncommitted desired generation remains private"
        );

        let mut pending = open_pending_skill_mutation_reconciliation(dest.path())
            .unwrap()
            .unwrap();
        let terminal = pending.reconcile(true).unwrap().unwrap();
        assert_eq!(terminal.operation_id, operation_id);
        assert_eq!(terminal.phase, SkillMutationPhase::Indeterminate);
        pending.acknowledge_terminal().unwrap();
        assert_eq!(
            std::fs::read(dest.path().join("backup_sync").join("asset.txt")).unwrap(),
            b"old"
        );
        assert!(!backup.exists());
        assert!(!stage.exists());
    }

    #[test]
    fn cleanup_started_resumes_the_same_partial_backup_after_restart() {
        let staging = tempdir().unwrap();
        let dest = temp_skills_root();
        let old_source = staging.path().join("old");
        write_skill(&old_source, "cleanup_resume", &good_yaml("cleanup_resume"));
        std::fs::create_dir(old_source.join("nested")).unwrap();
        std::fs::write(old_source.join("nested/a.txt"), b"a").unwrap();
        std::fs::write(old_source.join("nested/b.txt"), b"b").unwrap();
        install_from_local(&old_source, dest.path(), false).unwrap();

        let new_source = staging.path().join("new");
        write_skill(&new_source, "cleanup_resume", &good_yaml("cleanup_resume"));
        std::fs::write(new_source.join("new.txt"), b"new").unwrap();
        let operation_id = "78787878787878787878787878787878";
        let mut prepared = prepare_install_from_local_with_expectation(
            &new_source,
            dest.path(),
            true,
            None,
            operation_id,
        )
        .unwrap();
        prepared.mark_intent_durable().unwrap();
        let backup = dest.path().join(mutation_backup_name(&prepared.journal));
        prepared.commit().unwrap();

        let mut pending = open_pending_skill_mutation_reconciliation(dest.path())
            .unwrap()
            .unwrap();
        assert_eq!(
            pending.reconcile(true).unwrap().unwrap().phase,
            SkillMutationPhase::Committed
        );
        crate::skills::store::fail_delete_after_work_units(2);
        let error = pending.acknowledge_terminal().unwrap_err();
        assert!(format!("{error:#}").contains("injected recursive Skill cleanup"));
        assert!(
            backup.exists(),
            "partial top-level backup must remain bound"
        );
        assert!(dest.path().join(SKILL_MUTATION_JOURNAL_FILE).exists());

        let mut resumed = open_pending_skill_mutation_reconciliation(dest.path())
            .unwrap()
            .unwrap();
        assert_eq!(
            resumed.reconcile(true).unwrap().unwrap().phase,
            SkillMutationPhase::Committed
        );
        resumed.acknowledge_terminal().unwrap();
        assert!(!backup.exists());
        assert!(!dest.path().join(SKILL_MUTATION_JOURNAL_FILE).exists());
    }

    #[test]
    fn crash_after_dirsync_before_result_retains_committed_same_operation_outbox() {
        let staging = tempdir().unwrap();
        let dest = temp_skills_root();
        let source = staging.path().join("source");
        write_skill(&source, "result_pending", &good_yaml("result_pending"));
        let operation_id = "12121212121212121212121212121212";

        let mut prepared = prepare_install_from_local_with_expectation(
            &source,
            dest.path(),
            false,
            None,
            operation_id,
        )
        .unwrap();
        prepared.mark_intent_durable().unwrap();
        let report = prepared.commit().unwrap();
        assert_eq!(report.id, "result_pending");
        assert!(dest.path().join(SKILL_MUTATION_JOURNAL_FILE).exists());

        let mut pending = open_pending_skill_mutation_reconciliation(dest.path())
            .unwrap()
            .unwrap();
        let terminal = pending.reconcile(true).unwrap().unwrap();
        assert_eq!(terminal.operation_id, operation_id);
        assert_eq!(terminal.phase, SkillMutationPhase::Committed);
        pending.acknowledge_terminal().unwrap();
        assert!(!dest.path().join(SKILL_MUTATION_JOURNAL_FILE).exists());
    }

    #[test]
    fn prepared_removal_keeps_anchor_until_commit_and_same_id_retry_is_idempotent() {
        let staging = tempdir().unwrap();
        let dest = temp_skills_root();
        let source = staging.path().join("source");
        write_skill(&source, "remove_me", &good_yaml("remove_me"));
        let installed = install_from_local(&source, dest.path(), false).unwrap();
        let operation_id = "33333333333333333333333333333333";

        let mut prepared =
            prepare_uninstall_with_expectation(dest.path(), "remove_me", None, operation_id)
                .unwrap()
                .into_prepared_for_test();
        let binding = prepared.intent_binding();
        assert_eq!(binding.operation_id, operation_id);
        assert_eq!(
            binding.target_generation_sha256,
            installed.source_generation_sha256
        );
        assert!(dest.path().join("remove_me").exists());
        prepared.mark_intent_durable().unwrap();
        let removed = prepared.commit().unwrap();
        assert!(removed.removed);
        assert!(!dest.path().join("remove_me").exists());
        acknowledge_test_skill_mutation(dest.path()).unwrap();

        let no_op =
            match prepare_uninstall_with_expectation(dest.path(), "remove_me", None, operation_id)
                .unwrap()
            {
                PreparedSkillRemovalOutcome::Unchanged(report) => report,
                PreparedSkillRemovalOutcome::Prepared(_) => {
                    panic!("already-absent removal must not enter the WAL lifecycle")
                }
            };
        assert!(!no_op.removed);
        assert!(
            !dest.path().join(SKILL_MUTATION_JOURNAL_FILE).exists(),
            "already-absent removal must not create a mutation outbox"
        );
    }

    #[test]
    fn prepared_removal_refuses_generation_drift_after_intent_binding() {
        let staging = tempdir().unwrap();
        let dest = temp_skills_root();
        let source = staging.path().join("source");
        write_skill(&source, "drifted_remove", &good_yaml("drifted_remove"));
        std::fs::write(source.join("asset.txt"), b"old").unwrap();
        install_from_local(&source, dest.path(), false).unwrap();
        let live_asset = dest.path().join("drifted_remove").join("asset.txt");

        let mut prepared = prepare_uninstall_with_expectation(
            dest.path(),
            "drifted_remove",
            None,
            "44444444444444444444444444444444",
        )
        .unwrap()
        .into_prepared_for_test();
        prepared.mark_intent_durable().unwrap();
        std::fs::write(&live_asset, b"changed outside the cooperative lock").unwrap();

        let error = prepared.commit().unwrap_err();
        assert!(format!("{error:#}").contains("changed after its intent was acknowledged"));
        assert_eq!(
            std::fs::read(live_asset).unwrap(),
            b"changed outside the cooperative lock"
        );
    }

    #[test]
    fn replacement_final_lookup_swap_is_indeterminate_even_with_identical_prior_bytes() {
        let staging = tempdir().unwrap();
        let dest = temp_skills_root();
        let old_source = staging.path().join("old");
        write_skill(
            &old_source,
            "identity_replace",
            &good_yaml("identity_replace"),
        );
        std::fs::write(old_source.join("asset.txt"), b"same prior bytes").unwrap();
        install_from_local(&old_source, dest.path(), false).unwrap();

        let new_source = staging.path().join("new");
        write_skill(
            &new_source,
            "identity_replace",
            &good_yaml("identity_replace"),
        );
        std::fs::write(new_source.join("asset.txt"), b"desired bytes").unwrap();
        let operation_id = "78787878787878787878787878787878";
        let mut prepared = prepare_install_from_local_with_expectation(
            &new_source,
            dest.path(),
            true,
            None,
            operation_id,
        )
        .unwrap();
        let replacement_name = ".test-swap-replace-attacker";
        let displaced_name = ".test-swap-replace-original";
        let replacement = dest.path().join(replacement_name);
        std::fs::create_dir(&replacement).unwrap();
        std::fs::write(
            replacement.join("skill.yaml"),
            good_yaml("identity_replace"),
        )
        .unwrap();
        std::fs::write(replacement.join("asset.txt"), b"same prior bytes").unwrap();
        arm_final_lookup_swap(
            FinalLookupSwapPoint::Replace,
            replacement_name,
            displaced_name,
        );

        prepared.mark_intent_durable().unwrap();
        let error = prepared.commit().unwrap_err();
        assert_eq!(error.state(), SkillMutationFailureState::Indeterminate);
        assert!(
            format!("{error:#}").contains("different object"),
            "identity mismatch, not content, must trip the final gap"
        );
        assert!(dest.path().join(displaced_name).exists());
        assert!(
            dest.path()
                .join(format!(
                    "{BACKUP_TRANSACTION_PREFIX}identity_replace-{operation_id}"
                ))
                .exists()
        );

        let mut pending = open_pending_skill_mutation_reconciliation(dest.path())
            .unwrap()
            .unwrap();
        let terminal = pending.reconcile(true).unwrap().unwrap();
        assert_eq!(terminal.phase, SkillMutationPhase::Indeterminate);
        assert!(
            pending.acknowledge_terminal().is_err(),
            "a same-content but different-identity backup must never be restored or deleted"
        );
        assert!(dest.path().join(SKILL_MUTATION_JOURNAL_FILE).exists());
    }

    #[test]
    fn directory_removal_final_lookup_swap_preserves_both_objects_as_indeterminate() {
        let staging = tempdir().unwrap();
        let dest = temp_skills_root();
        let source = staging.path().join("source");
        write_skill(
            &source,
            "identity_remove_dir",
            &good_yaml("identity_remove_dir"),
        );
        std::fs::write(source.join("asset.txt"), b"same removal bytes").unwrap();
        install_from_local(&source, dest.path(), false).unwrap();
        let operation_id = "89898989898989898989898989898989";
        let mut prepared = prepare_uninstall_with_expectation(
            dest.path(),
            "identity_remove_dir",
            None,
            operation_id,
        )
        .unwrap()
        .into_prepared_for_test();
        let replacement_name = ".test-swap-remove-dir-attacker";
        let displaced_name = ".test-swap-remove-dir-original";
        let replacement = dest.path().join(replacement_name);
        std::fs::create_dir(&replacement).unwrap();
        std::fs::write(
            replacement.join("skill.yaml"),
            good_yaml("identity_remove_dir"),
        )
        .unwrap();
        std::fs::write(replacement.join("asset.txt"), b"same removal bytes").unwrap();
        arm_final_lookup_swap(
            FinalLookupSwapPoint::RemoveDirectory,
            replacement_name,
            displaced_name,
        );

        prepared.mark_intent_durable().unwrap();
        let error = prepared.commit().unwrap_err();
        assert_eq!(error.state(), SkillMutationFailureState::Indeterminate);
        assert!(format!("{error:#}").contains("different object"));
        let tombstone = dest.path().join(format!(
            "{DELETE_TRANSACTION_PREFIX}identity_remove_dir-{operation_id}"
        ));
        assert!(tombstone.exists());
        assert!(dest.path().join(displaced_name).exists());

        let mut pending = open_pending_skill_mutation_reconciliation(dest.path())
            .unwrap()
            .unwrap();
        let terminal = pending.reconcile(true).unwrap().unwrap();
        assert_eq!(terminal.phase, SkillMutationPhase::Indeterminate);
        assert!(
            pending.acknowledge_terminal().is_err(),
            "a mismatched tombstone must remain operator-visible"
        );
        assert!(tombstone.exists());
    }

    #[test]
    fn leaf_removal_final_lookup_swap_renames_but_never_unlinks_the_swapped_leaf() {
        let dest = temp_skills_root();
        let target = dest.path().join("identity_remove_leaf");
        std::fs::write(&target, b"same leaf bytes").unwrap();
        let operation_id = "90909090909090909090909090909090";
        let mut prepared = prepare_uninstall_with_expectation(
            dest.path(),
            "identity_remove_leaf",
            None,
            operation_id,
        )
        .unwrap()
        .into_prepared_for_test();
        let replacement_name = ".test-swap-remove-leaf-attacker";
        let displaced_name = ".test-swap-remove-leaf-original";
        std::fs::write(dest.path().join(replacement_name), b"same leaf bytes").unwrap();
        arm_final_lookup_swap(
            FinalLookupSwapPoint::RemoveLeaf,
            replacement_name,
            displaced_name,
        );

        prepared.mark_intent_durable().unwrap();
        let error = prepared.commit().unwrap_err();
        assert_eq!(error.state(), SkillMutationFailureState::Indeterminate);
        assert!(format!("{error:#}").contains("different object"));
        let tombstone = dest.path().join(format!(
            "{DELETE_TRANSACTION_PREFIX}identity_remove_leaf-{operation_id}"
        ));
        assert_eq!(std::fs::read(&tombstone).unwrap(), b"same leaf bytes");
        assert_eq!(
            std::fs::read(dest.path().join(displaced_name)).unwrap(),
            b"same leaf bytes"
        );

        let mut pending = open_pending_skill_mutation_reconciliation(dest.path())
            .unwrap()
            .unwrap();
        let terminal = pending.reconcile(true).unwrap().unwrap();
        assert_eq!(terminal.phase, SkillMutationPhase::Indeterminate);
        assert!(pending.acknowledge_terminal().is_err());
        assert!(tombstone.exists(), "mismatched leaf must not be unlinked");
    }

    #[test]
    fn prepared_skill_mutations_reject_unbound_operation_ids() {
        let staging = tempdir().unwrap();
        let dest = temp_skills_root();
        let source = staging.path().join("source");
        write_skill(&source, "invalid_op", &good_yaml("invalid_op"));

        let install_error = prepare_install_from_local_with_expectation(
            &source,
            dest.path(),
            false,
            None,
            "not-a-bound-id",
        )
        .err()
        .expect("invalid install operation id must fail");
        assert!(format!("{install_error:#}").contains("32 lowercase hex"));

        let remove_error =
            prepare_uninstall_with_expectation(dest.path(), "invalid_op", None, "ABC")
                .err()
                .expect("invalid removal operation id must fail");
        assert!(format!("{remove_error:#}").contains("32 lowercase hex"));
    }

    #[test]
    fn install_from_local_copies_sibling_files() {
        let staging = tempdir().unwrap();
        let dest = temp_skills_root();

        let src = staging.path().join("rich_skill_source");
        write_skill(&src, "rich_skill", &good_yaml("rich_skill"));
        // Drop an extra file alongside the manifest.
        std::fs::write(src.join("README.md"), b"# Rich skill").unwrap();

        let report = install_from_local(&src, dest.path(), false).unwrap();
        assert!(report.installed_at.join("README.md").exists());
    }

    #[test]
    fn install_preflight_rejects_cross_owner_alias_before_publication() {
        let staging = tempdir().unwrap();
        let dest = temp_skills_root();
        let source = staging.path().join("collision-source");
        write_skill(
            &source,
            "custom_collision",
            "id: custom_collision\n\
             description: Must not capture a bundled route\n\
             trigger_keywords: [research]\n\
             system_prompt: collision fixture\n",
        );

        let error = inspect_local_install(&source, dest.path()).unwrap_err();
        let detail = format!("{error:#}");
        assert!(detail.contains("route-owner preflight failed"), "{detail}");
        assert!(detail.contains("academic_research"), "{detail}");
        assert!(detail.contains("custom_collision"), "{detail}");
        assert!(!dest.path().join("custom_collision").exists());
    }

    #[test]
    fn install_preflight_rejects_alias_hidden_by_inactive_bundled_override() {
        let staging = tempdir().unwrap();
        let dest = temp_skills_root();
        let shadow = dest.path().join("academic_research");
        write_skill(
            &shadow,
            "academic_research",
            "id: academic_research\n\
             description: Inactive installed shadow\n\
             trigger_keywords: [installed-shadow-only]\n\
             system_prompt: shadow fixture\n\
             enabled: false\n",
        );
        let shadow_before = std::fs::read(shadow.join("skill.yaml")).unwrap();
        let source = staging.path().join("collision-source");
        write_skill(
            &source,
            "custom_collision",
            "id: custom_collision\n\
             description: Must not capture a fallback route\n\
             trigger_keywords: [research]\n\
             system_prompt: collision fixture\n",
        );

        let error = inspect_local_install(&source, dest.path()).unwrap_err();
        let detail = format!("{error:#}");
        assert!(detail.contains("bundled fallback"), "{detail}");
        assert!(detail.contains("academic_research"), "{detail}");
        assert!(detail.contains("custom_collision"), "{detail}");
        assert_eq!(
            std::fs::read(shadow.join("skill.yaml")).unwrap(),
            shadow_before
        );
        assert!(!dest.path().join("custom_collision").exists());
    }

    #[test]
    fn install_from_local_rejects_a_linked_source_root() {
        let parent = tempdir().unwrap();
        let outside = tempdir().unwrap();
        write_skill(outside.path(), "linked-source", &good_yaml("linked-source"));
        let linked_source = parent.path().join("source");
        try_symlink_dir(outside.path(), &linked_source)
            .expect("create linked source-root test fixture");
        let dest = temp_skills_root();

        let error = install_from_local(&linked_source, dest.path(), false).unwrap_err();
        assert!(format!("{error:#}").contains("skill source must be a real directory"));
        assert!(!dest.path().join("linked-source").exists());
    }

    #[test]
    fn install_from_local_rejects_linked_sibling_directories() {
        let staging = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let dest = temp_skills_root();
        let source = staging.path().join("source");
        write_skill(&source, "linked-child", &good_yaml("linked-child"));
        let sentinel = outside.path().join("keep.txt");
        std::fs::write(&sentinel, b"keep").unwrap();
        try_symlink_dir(outside.path(), &source.join("linked-assets"))
            .expect("create linked child test fixture");

        let error = install_from_local(&source, dest.path(), false).unwrap_err();

        assert!(format!("{error:#}").contains("unsupported linked or reparse entry"));
        assert!(!dest.path().join("linked-child").exists());
        assert_eq!(std::fs::read(sentinel).unwrap(), b"keep");
    }

    #[test]
    fn install_expectation_binds_every_package_file() {
        let staging = tempdir().unwrap();
        let dest = temp_skills_root();
        let source = staging.path().join("source");
        write_skill(&source, "bound-package", &good_yaml("bound-package"));
        std::fs::write(source.join("README.md"), b"generation one").unwrap();

        let preflight = inspect_local_install(&source, dest.path()).unwrap();
        assert_eq!(preflight.id, "bound-package");
        assert_eq!(preflight.source_manifest_sha256.len(), 64);
        assert_eq!(preflight.source_generation_sha256.len(), 64);
        std::fs::write(source.join("README.md"), b"generation two").unwrap();

        let error = install_from_local_with_expectation(
            &source,
            dest.path(),
            false,
            Some(&InstallExpectation {
                id: preflight.id,
                source_generation_sha256: preflight.source_generation_sha256,
                target_generation_sha256: preflight.target_generation_sha256,
            }),
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("source changed after preflight"));
        assert!(!dest.path().join("bound-package").exists());
    }

    #[test]
    fn install_report_matches_the_preflight_generation() {
        let staging = tempdir().unwrap();
        let dest = temp_skills_root();
        let source = staging.path().join("source");
        write_skill(&source, "bound-package", &good_yaml("bound-package"));
        std::fs::create_dir(source.join("assets")).unwrap();
        std::fs::write(source.join("assets").join("payload.bin"), b"payload").unwrap();

        let preflight = inspect_local_install(&source, dest.path()).unwrap();
        let report = install_from_local_with_expectation(
            &source,
            dest.path(),
            false,
            Some(&InstallExpectation {
                id: preflight.id.clone(),
                source_generation_sha256: preflight.source_generation_sha256.clone(),
                target_generation_sha256: preflight.target_generation_sha256.clone(),
            }),
        )
        .unwrap();

        assert_eq!(report.id, preflight.id);
        assert_eq!(
            report.source_manifest_sha256,
            preflight.source_manifest_sha256
        );
        assert_eq!(
            report.source_generation_sha256,
            preflight.source_generation_sha256
        );
        assert_eq!(
            report.replaced_generation_sha256,
            preflight.target_generation_sha256
        );
    }

    #[cfg(unix)]
    #[test]
    fn package_generation_binds_and_install_preserves_unix_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let staging = tempdir().unwrap();
        let dest = temp_skills_root();
        let source = staging.path().join("source");
        let assets = source.join("assets");
        let payload = assets.join("payload.bin");
        write_skill(&source, "mode-bound", &good_yaml("mode-bound"));
        std::fs::create_dir(&assets).unwrap();
        std::fs::write(&payload, b"payload").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o750)).unwrap();
        std::fs::set_permissions(&assets, std::fs::Permissions::from_mode(0o711)).unwrap();
        std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o640)).unwrap();

        let original = inspect_local_install(&source, dest.path()).unwrap();
        std::fs::set_permissions(&assets, std::fs::Permissions::from_mode(0o700)).unwrap();
        let nested_chmod = inspect_local_install(&source, dest.path()).unwrap();
        assert_ne!(
            nested_chmod.source_generation_sha256,
            original.source_generation_sha256
        );
        std::fs::set_permissions(&assets, std::fs::Permissions::from_mode(0o711)).unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root_chmod = inspect_local_install(&source, dest.path()).unwrap();
        assert_ne!(
            root_chmod.source_generation_sha256,
            original.source_generation_sha256
        );
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o750)).unwrap();
        let restored = inspect_local_install(&source, dest.path()).unwrap();
        assert_eq!(
            restored.source_generation_sha256,
            original.source_generation_sha256
        );

        install_from_local_with_expectation(
            &source,
            dest.path(),
            false,
            Some(&InstallExpectation {
                id: restored.id,
                source_generation_sha256: restored.source_generation_sha256,
                target_generation_sha256: restored.target_generation_sha256,
            }),
        )
        .unwrap();
        let installed = dest.path().join("mode-bound");
        assert_eq!(
            std::fs::metadata(&installed).unwrap().permissions().mode() & 0o7777,
            0o750
        );
        assert_eq!(
            std::fs::metadata(installed.join("assets"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o711
        );
        assert_eq!(
            std::fs::metadata(installed.join("assets").join("payload.bin"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o640
        );
    }

    #[cfg(unix)]
    #[test]
    fn prepared_replacement_rejects_unix_directory_mode_drift() {
        use std::os::unix::fs::PermissionsExt as _;

        let staging = tempdir().unwrap();
        let dest = temp_skills_root();
        let old_source = staging.path().join("old");
        let new_source = staging.path().join("new");
        write_skill(&old_source, "mode-drift", &good_yaml("mode-drift"));
        std::fs::create_dir(old_source.join("assets")).unwrap();
        std::fs::write(old_source.join("assets").join("payload"), b"old").unwrap();
        install_from_local(&old_source, dest.path(), false).unwrap();
        write_skill(&new_source, "mode-drift", &good_yaml("mode-drift"));
        std::fs::write(new_source.join("replacement"), b"new").unwrap();

        let mut prepared = prepare_install_from_local_with_expectation(
            &new_source,
            dest.path(),
            true,
            None,
            "61616161616161616161616161616161",
        )
        .unwrap();
        prepared.mark_intent_durable().unwrap();
        let live_assets = dest.path().join("mode-drift").join("assets");
        std::fs::set_permissions(&live_assets, std::fs::Permissions::from_mode(0o711)).unwrap();

        let error = prepared.commit().unwrap_err();
        assert!(format!("{error:#}").contains("destination changed while staging"));
        assert_eq!(
            std::fs::metadata(live_assets).unwrap().permissions().mode() & 0o7777,
            0o711
        );
    }

    #[test]
    fn replacement_expectation_rejects_a_destination_generation_that_changed() {
        let staging = tempdir().unwrap();
        let dest = temp_skills_root();
        let source = staging.path().join("source");
        write_skill(&source, "bound-target", &good_yaml("bound-target"));
        std::fs::write(source.join("asset.txt"), b"new generation").unwrap();
        let installed = dest.path().join("bound-target");
        write_skill(&installed, "bound-target", &good_yaml("bound-target"));
        std::fs::write(installed.join("asset.txt"), b"old generation").unwrap();

        let preflight = inspect_local_install(&source, dest.path()).unwrap();
        assert!(preflight.replacing_existing);
        assert!(preflight.target_generation_sha256.is_some());
        std::fs::write(installed.join("asset.txt"), b"concurrent generation").unwrap();

        let error = install_from_local_with_expectation(
            &source,
            dest.path(),
            true,
            Some(&InstallExpectation {
                id: preflight.id,
                source_generation_sha256: preflight.source_generation_sha256,
                target_generation_sha256: preflight.target_generation_sha256,
            }),
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("destination changed after preflight"));
        assert_eq!(
            std::fs::read(installed.join("asset.txt")).unwrap(),
            b"concurrent generation"
        );
    }

    #[test]
    fn generation_walk_rejects_an_entry_before_exceeding_its_collection_budget() {
        let source = tempdir().unwrap();
        std::fs::write(source.path().join("one-more-entry"), b"payload").unwrap();
        let bound = open_bound_directory(source.path(), false, "generation budget fixture")
            .unwrap()
            .unwrap();
        let mut budget = CopyBudget {
            entries: MAX_SKILL_ENTRIES,
            bytes: 0,
        };
        let mut hasher = Sha256::new();
        let mut collector = SkillTreeSnapshotCollector::default();
        let mut aggregate = RuntimeAuthorityTraversalBudget::unbounded_for_internal();

        let error = {
            let mut context = SkillTreeHashContext {
                budget: &mut budget,
                hasher: &mut hasher,
                collector: &mut collector,
                aggregate: &mut aggregate,
            };
            hash_skill_tree_directory(&bound.dir, &bound.display_path, "", None, 0, &mut context)
                .unwrap_err()
        };

        assert!(format!("{error:#}").contains("exceeds 4096 entries"));
        assert_eq!(budget.entries, MAX_SKILL_ENTRIES);
    }

    #[test]
    fn installed_test_snapshot_returns_only_bytes_from_its_generation_walk() {
        let home = tempdir().unwrap();
        let skills = home.path().join("skills");
        let package = skills.join("snapshot_skill");
        std::fs::create_dir_all(package.join("tests")).unwrap();
        let manifest = b"id: snapshot_skill\ndescription: Snapshot fixture\n";
        std::fs::write(package.join("skill.yaml"), manifest).unwrap();
        std::fs::write(package.join("tests/a.yaml"), b"id: a\nprompt: one\n").unwrap();
        std::fs::write(package.join("tests/b.yml"), b"id: b\nprompt: two\n").unwrap();
        std::fs::write(package.join("tests/ignore.txt"), b"ignored").unwrap();
        let root = open_bound_directory(&skills, false, "test snapshot root")
            .unwrap()
            .unwrap();
        let _guard = lock_skill_mutations(&root).unwrap();

        let snapshot =
            capture_installed_skill_test_snapshot_locked(&root, "snapshot_skill").unwrap();
        let directory =
            open_real_child_dir(&root.dir, OsStr::new("snapshot_skill"), &package).unwrap();
        let expected_generation = skill_tree_generation_sha256(&directory, &package, None).unwrap();

        assert_eq!(snapshot.generation_sha256, expected_generation);
        assert_eq!(snapshot.manifest_bytes, manifest);
        assert_eq!(snapshot.test_directory_entries, 3);
        assert_eq!(
            snapshot
                .test_files
                .iter()
                .map(|file| (file.file_name.as_str(), file.bytes.as_slice()))
                .collect::<Vec<_>>(),
            vec![
                ("a.yaml", b"id: a\nprompt: one\n".as_slice()),
                ("b.yml", b"id: b\nprompt: two\n".as_slice()),
            ]
        );
    }

    #[test]
    fn journal_stage_cleanup_bounds_all_root_entries_before_filtering() {
        let skills = tempdir().unwrap();
        std::fs::write(skills.path().join("unrelated-one"), b"").unwrap();
        std::fs::write(skills.path().join("unrelated-two"), b"").unwrap();
        let root = open_bound_directory(skills.path(), false, "cleanup limit fixture")
            .unwrap()
            .unwrap();

        let error = cleanup_skill_mutation_journal_stages_with_limit(&root, 1).unwrap_err();
        assert!(format!("{error:#}").contains("exceeds the 1-entry limit"));
    }

    #[test]
    fn installed_inventory_bounds_hidden_and_unrelated_root_entries() {
        let skills = tempdir().unwrap();
        std::fs::write(skills.path().join(".unrelated-one"), b"").unwrap();
        std::fs::write(skills.path().join(".unrelated-two"), b"").unwrap();

        let error = list_installed_with_limit(skills.path(), 1).unwrap_err();
        assert!(format!("{error:#}").contains("exceeds the 1-entry limit"));
    }

    #[test]
    fn failed_force_install_preserves_the_prior_tree_and_cleans_the_stage() {
        let staging = tempdir().unwrap();
        let dest = temp_skills_root();
        let original = staging.path().join("original");
        write_skill(&original, "bounded", &good_yaml("bounded"));
        std::fs::write(original.join("VERSION"), b"old").unwrap();
        install_from_local(&original, dest.path(), false).unwrap();

        let oversized = staging.path().join("oversized");
        write_skill(&oversized, "bounded", &good_yaml("bounded"));
        let oversized_file = std::fs::File::create(oversized.join("payload.bin")).unwrap();
        oversized_file.set_len(MAX_SKILL_FILE_BYTES + 1).unwrap();

        let error = install_from_local(&oversized, dest.path(), true).unwrap_err();
        assert!(format!("{error:#}").contains("exceeds"));
        assert_eq!(
            std::fs::read(dest.path().join("bounded").join("VERSION")).unwrap(),
            b"old"
        );
        let leaked_stages = std::fs::read_dir(dest.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".neoth-install-bounded-")
            })
            .count();
        assert_eq!(leaked_stages, 0);
    }

    #[cfg(unix)]
    #[test]
    fn install_rejects_a_fifo_manifest_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt as _;

        let source = tempdir().unwrap();
        let manifest = source.path().join("skill.yaml");
        let manifest_c = CString::new(manifest.as_os_str().as_bytes()).unwrap();
        // SAFETY: `manifest_c` is a valid NUL-terminated path and mode is
        // limited to owner read/write for this private temporary directory.
        let result = unsafe { libc::mkfifo(manifest_c.as_ptr(), 0o600) };
        assert_eq!(
            result,
            0,
            "mkfifo failed: {}",
            std::io::Error::last_os_error()
        );
        let dest = temp_skills_root();

        let error = install_from_local(source.path(), dest.path(), false).unwrap_err();
        assert!(format!("{error:#}").contains("expected a real regular file"));
    }

    #[test]
    fn install_from_local_refuses_when_target_exists_without_force() {
        let staging = tempdir().unwrap();
        let dest = temp_skills_root();

        let src = staging.path().join("dup_source");
        write_skill(&src, "dup", &good_yaml("dup"));

        install_from_local(&src, dest.path(), false).unwrap();
        let err = install_from_local(&src, dest.path(), false).unwrap_err();
        assert!(err.to_string().contains("already installed"));
        assert!(err.to_string().contains("--force"));
    }

    #[test]
    fn install_from_local_with_force_replaces_prior_install() {
        let staging = tempdir().unwrap();
        let dest = temp_skills_root();

        let src_v1 = staging.path().join("replaceable_v1");
        write_skill(&src_v1, "replaceable", &good_yaml("replaceable"));
        std::fs::write(src_v1.join("VERSION"), b"v1").unwrap();
        install_from_local(&src_v1, dest.path(), false).unwrap();

        let src_v2 = staging.path().join("replaceable_v2");
        write_skill(&src_v2, "replaceable", &good_yaml("replaceable"));
        std::fs::write(src_v2.join("VERSION"), b"v2").unwrap();

        let report = install_from_local(&src_v2, dest.path(), true).unwrap();
        assert!(report.replaced_existing);
        let version = std::fs::read_to_string(report.installed_at.join("VERSION")).unwrap();
        assert_eq!(version, "v2");
    }

    #[test]
    fn list_recovery_refuses_journal_less_backup_instead_of_silently_cleaning() {
        let dest = temp_skills_root();
        let (stage_name, backup_name) = transaction_names("recoverable");
        let public = dest.path().join("recoverable");
        write_skill(&public, "recoverable", &good_yaml("recoverable"));
        std::fs::write(public.join("VERSION"), b"new").unwrap();
        let backup = dest.path().join(&backup_name);
        write_skill(&backup, "recoverable", &good_yaml("recoverable"));
        std::fs::write(backup.join("VERSION"), b"old").unwrap();
        let stage = dest.path().join(&stage_name);
        write_skill(&stage, "recoverable", &good_yaml("recoverable"));

        let error = list_installed(dest.path()).unwrap_err();

        assert!(format!("{error:#}").contains("journal-less backup"));
        assert_eq!(std::fs::read(public.join("VERSION")).unwrap(), b"new");
        assert!(backup.exists());
        assert!(stage.exists());
    }

    #[test]
    fn recovery_never_discards_journal_less_backup_even_with_public_winner() {
        let dest = temp_skills_root();
        let (_, backup_name) = transaction_names("recoverable");
        let public = dest.path().join("recoverable");
        write_skill(&public, "recoverable", &good_yaml("recoverable"));
        std::fs::write(public.join("VERSION"), b"new").unwrap();
        let backup = dest.path().join(&backup_name);
        write_skill(&backup, "recoverable", &good_yaml("recoverable"));
        std::fs::write(backup.join("VERSION"), b"old").unwrap();

        let error = recover_pending_transactions(dest.path()).unwrap_err();

        assert!(format!("{error:#}").contains("journal-less backup"));
        assert!(public.exists(), "the observed public winner remains live");
        assert!(
            backup.exists(),
            "unauthenticated rollback evidence must survive until explicit repair"
        );

        let retry = recover_pending_transactions(dest.path()).unwrap_err();
        assert!(format!("{retry:#}").contains("journal-less backup"));
        assert!(public.exists());
        assert!(backup.exists());
    }

    #[test]
    fn list_recovery_refuses_to_publish_journal_less_backup() {
        let dest = temp_skills_root();
        let (stage_name, backup_name) = transaction_names("recoverable");
        let backup = dest.path().join(&backup_name);
        write_skill(&backup, "recoverable", &good_yaml("recoverable"));
        std::fs::write(backup.join("VERSION"), b"old").unwrap();
        let stage = dest.path().join(&stage_name);
        write_skill(&stage, "recoverable", &good_yaml("recoverable"));
        std::fs::write(stage.join("VERSION"), b"new").unwrap();

        let error = list_installed(dest.path()).unwrap_err();

        let public = dest.path().join("recoverable");
        assert!(format!("{error:#}").contains("journal-less backup"));
        assert!(!public.exists());
        assert!(backup.exists());
        assert!(stage.exists());
    }

    #[test]
    fn list_recovery_discards_stage_only_interrupted_copy() {
        let dest = temp_skills_root();
        let (stage_name, _) = transaction_names("incomplete");
        let stage = dest.path().join(&stage_name);
        std::fs::create_dir(&stage).unwrap();
        std::fs::write(stage.join("partial.bin"), b"partial").unwrap();

        let rows = list_installed(dest.path()).unwrap();

        assert!(rows.is_empty());
        assert!(!stage.exists());
        assert!(!dest.path().join("incomplete").exists());
    }

    #[test]
    fn install_blocks_on_journal_less_backup_without_mutating_it() {
        let source_root = tempdir().unwrap();
        let dest = temp_skills_root();
        let source = source_root.path().join("source");
        write_skill(&source, "recoverable", &good_yaml("recoverable"));
        std::fs::write(source.join("VERSION"), b"new").unwrap();
        let (stage_name, backup_name) = transaction_names("recoverable");
        let backup = dest.path().join(&backup_name);
        write_skill(&backup, "recoverable", &good_yaml("recoverable"));
        std::fs::write(backup.join("VERSION"), b"old").unwrap();
        write_skill(
            &dest.path().join(&stage_name),
            "recoverable",
            &good_yaml("recoverable"),
        );

        let error = install_from_local(&source, dest.path(), false).unwrap_err();

        assert!(format!("{error:#}").contains("journal-less backup"));
        assert!(!dest.path().join("recoverable").exists());
        assert!(backup.exists());
        assert!(dest.path().join(stage_name).exists());
    }

    #[test]
    fn uninstall_blocks_on_journal_less_backup_without_mutating_it() {
        let dest = temp_skills_root();
        let (stage_name, backup_name) = transaction_names("recoverable");
        write_skill(
            &dest.path().join(&backup_name),
            "recoverable",
            &good_yaml("recoverable"),
        );
        write_skill(
            &dest.path().join(&stage_name),
            "recoverable",
            &good_yaml("recoverable"),
        );

        let error = uninstall(dest.path(), "recoverable").unwrap_err();
        assert!(format!("{error:#}").contains("journal-less backup"));
        assert!(!dest.path().join("recoverable").exists());
        assert!(dest.path().join(backup_name).exists());
        assert!(dest.path().join(stage_name).exists());
    }

    #[test]
    fn uninstall_retains_tombstone_until_indeterminate_rollback_is_acked() {
        let dest = temp_skills_root();
        let public = dest.path().join("doomed");
        let operation_id = "55555555555555555555555555555555";
        let tombstone = force_indeterminate_removal_after_parent_sync_failure(
            dest.path(),
            "doomed",
            operation_id,
        );
        assert_eq!(
            std::fs::read(tombstone.join("sentinel")).unwrap(),
            b"recoverable"
        );

        let mut pending = open_pending_skill_mutation_reconciliation(dest.path())
            .unwrap()
            .unwrap();
        let terminal = pending.reconcile(true).unwrap().unwrap();
        assert_eq!(terminal.operation_id, operation_id);
        assert_eq!(terminal.phase, SkillMutationPhase::Indeterminate);
        pending.acknowledge_terminal().unwrap();

        assert_eq!(
            std::fs::read(public.join("sentinel")).unwrap(),
            b"recoverable"
        );
        assert!(!tombstone.exists());
        assert!(!dest.path().join(SKILL_MUTATION_JOURNAL_FILE).exists());
    }

    #[test]
    fn crash_after_removal_rename_before_parent_sync_restores_prior_on_ack() {
        let dest = temp_skills_root();
        let public = dest.path().join("crash_remove");
        write_skill(&public, "crash_remove", &good_yaml("crash_remove"));
        std::fs::write(public.join("sentinel"), b"prior").unwrap();
        let operation_id = "56565656565656565656565656565656";
        let mut prepared =
            prepare_uninstall_with_expectation(dest.path(), "crash_remove", None, operation_id)
                .unwrap()
                .into_prepared_for_test();
        prepared.mark_intent_durable().unwrap();
        transition_skill_mutation_phase(
            &prepared.root,
            &mut prepared.journal,
            SkillMutationPhase::CommitStarted,
            None,
            None,
        )
        .unwrap();
        let tombstone_name = mutation_tombstone_name(&prepared.journal);
        let tombstone = dest.path().join(&tombstone_name);
        rename_child(
            &prepared.root.dir,
            OsStr::new("crash_remove"),
            &prepared.root.dir,
            &tombstone_name,
            false,
            &public,
            &tombstone,
        )
        .unwrap();
        // Simulate host loss: no parent fsync and no terminal journal phase.
        drop(prepared);

        let mut pending = open_pending_skill_mutation_reconciliation(dest.path())
            .unwrap()
            .unwrap();
        let terminal = pending.reconcile(true).unwrap().unwrap();
        assert_eq!(terminal.operation_id, operation_id);
        assert_eq!(terminal.phase, SkillMutationPhase::Indeterminate);
        pending.acknowledge_terminal().unwrap();

        assert_eq!(std::fs::read(public.join("sentinel")).unwrap(), b"prior");
        assert!(!tombstone.exists());
        assert!(!dest.path().join(SKILL_MUTATION_JOURNAL_FILE).exists());
    }

    #[test]
    fn indeterminate_removal_rollback_retries_parent_sync_before_ack() {
        let dest = temp_skills_root();
        let public = dest.path().join("retry_remove");
        let operation_id = "57575757575757575757575757575757";
        let tombstone = force_indeterminate_removal_after_parent_sync_failure(
            dest.path(),
            "retry_remove",
            operation_id,
        );
        let mut pending = open_pending_skill_mutation_reconciliation(dest.path())
            .unwrap()
            .unwrap();
        assert_eq!(
            pending.reconcile(true).unwrap().unwrap().phase,
            SkillMutationPhase::Indeterminate
        );

        fail_next_directory_syncs(1);
        let error = pending.acknowledge_terminal().unwrap_err();
        clear_directory_sync_failure();
        assert!(format!("{error:#}").contains("sync restored prior skill removal generation"));
        assert!(
            public.exists(),
            "atomic rollback rename must already be live"
        );
        assert!(!tombstone.exists());
        assert!(dest.path().join(SKILL_MUTATION_JOURNAL_FILE).exists());

        let mut resumed = open_pending_skill_mutation_reconciliation(dest.path())
            .unwrap()
            .unwrap();
        let terminal = resumed.reconcile(true).unwrap().unwrap();
        assert_eq!(terminal.phase, SkillMutationPhase::Indeterminate);
        resumed.acknowledge_terminal().unwrap();
        assert_eq!(
            std::fs::read(public.join("sentinel")).unwrap(),
            b"recoverable"
        );
        assert!(!dest.path().join(SKILL_MUTATION_JOURNAL_FILE).exists());
    }

    #[test]
    fn indeterminate_removal_without_tombstone_fails_closed() {
        let dest = temp_skills_root();
        let operation_id = "58585858585858585858585858585858";
        let tombstone = force_indeterminate_removal_after_parent_sync_failure(
            dest.path(),
            "missing_remove",
            operation_id,
        );
        std::fs::remove_dir_all(&tombstone).unwrap();

        let mut pending = open_pending_skill_mutation_reconciliation(dest.path())
            .unwrap()
            .unwrap();
        assert_eq!(
            pending.reconcile(true).unwrap().unwrap().phase,
            SkillMutationPhase::Indeterminate
        );
        let error = pending.acknowledge_terminal().unwrap_err();

        assert!(format!("{error:#}").contains("operation-bound tombstone is missing"));
        assert!(!dest.path().join("missing_remove").exists());
        assert!(dest.path().join(SKILL_MUTATION_JOURNAL_FILE).exists());
    }

    #[test]
    fn indeterminate_removal_with_other_operation_tombstone_fails_closed() {
        let dest = temp_skills_root();
        let operation_id = "59595959595959595959595959595959";
        let tombstone = force_indeterminate_removal_after_parent_sync_failure(
            dest.path(),
            "wrong_operation",
            operation_id,
        );
        let wrong_tombstone = dest.path().join(format!(
            "{DELETE_TRANSACTION_PREFIX}wrong_operation-60606060606060606060606060606060"
        ));
        std::fs::rename(&tombstone, &wrong_tombstone).unwrap();

        let mut pending = open_pending_skill_mutation_reconciliation(dest.path())
            .unwrap()
            .unwrap();
        assert_eq!(
            pending.reconcile(true).unwrap().unwrap().phase,
            SkillMutationPhase::Indeterminate
        );
        let error = pending.acknowledge_terminal().unwrap_err();

        assert!(format!("{error:#}").contains("sole tombstone belongs to another operation"));
        assert!(!dest.path().join("wrong_operation").exists());
        assert!(!tombstone.exists());
        assert!(wrong_tombstone.exists());
        assert!(dest.path().join(SKILL_MUTATION_JOURNAL_FILE).exists());
    }

    #[test]
    fn indeterminate_removal_with_generation_drift_fails_closed() {
        let dest = temp_skills_root();
        let operation_id = "61616161616161616161616161616161";
        let tombstone = force_indeterminate_removal_after_parent_sync_failure(
            dest.path(),
            "drifted_tombstone",
            operation_id,
        );
        std::fs::write(tombstone.join("tampered"), b"changed generation").unwrap();

        let mut pending = open_pending_skill_mutation_reconciliation(dest.path())
            .unwrap()
            .unwrap();
        assert_eq!(
            pending.reconcile(true).unwrap().unwrap().phase,
            SkillMutationPhase::Indeterminate
        );
        let error = pending.acknowledge_terminal().unwrap_err();

        assert!(format!("{error:#}").contains("bound v2 prior generation"));
        assert!(!dest.path().join("drifted_tombstone").exists());
        assert!(tombstone.exists());
        assert!(dest.path().join(SKILL_MUTATION_JOURNAL_FILE).exists());
    }

    #[test]
    fn indeterminate_removal_with_multiple_tombstones_fails_closed() {
        let dest = temp_skills_root();
        let operation_id = "62626262626262626262626262626262";
        let tombstone = force_indeterminate_removal_after_parent_sync_failure(
            dest.path(),
            "ambiguous_remove",
            operation_id,
        );
        let other_tombstone = dest.path().join(format!(
            "{DELETE_TRANSACTION_PREFIX}ambiguous_remove-63636363636363636363636363636363"
        ));
        write_skill(
            &other_tombstone,
            "ambiguous_remove",
            &good_yaml("ambiguous_remove"),
        );

        let mut pending = open_pending_skill_mutation_reconciliation(dest.path())
            .unwrap()
            .unwrap();
        assert_eq!(
            pending.reconcile(true).unwrap().unwrap().phase,
            SkillMutationPhase::Indeterminate
        );
        let error = pending.acknowledge_terminal().unwrap_err();

        assert!(format!("{error:#}").contains("2 candidate tombstones are ambiguous"));
        assert!(!dest.path().join("ambiguous_remove").exists());
        assert!(tombstone.exists());
        assert!(other_tombstone.exists());
        assert!(dest.path().join(SKILL_MUTATION_JOURNAL_FILE).exists());
    }

    #[test]
    fn recovery_fails_closed_on_ambiguous_backup_generations() {
        let dest = temp_skills_root();
        for nonce in [
            "0123456789abcdef0123456789abcdef",
            "fedcba9876543210fedcba9876543210",
        ] {
            write_skill(
                &dest
                    .path()
                    .join(format!("{BACKUP_TRANSACTION_PREFIX}ambiguous-{nonce}")),
                "ambiguous",
                &good_yaml("ambiguous"),
            );
        }

        let error = list_installed(dest.path()).unwrap_err();

        assert!(format!("{error:#}").contains("2 journal-less backup"));
        assert!(!dest.path().join("ambiguous").exists());
    }

    #[test]
    fn recovery_refuses_linked_transaction_artifacts() {
        let dest = temp_skills_root();
        let outside = tempdir().unwrap();
        let sentinel = outside.path().join("keep.txt");
        std::fs::write(&sentinel, b"keep").unwrap();
        let (stage_name, _) = transaction_names("linked");
        try_symlink_dir(outside.path(), &dest.path().join(stage_name))
            .expect("create linked transaction fixture");

        let error = list_installed(dest.path()).unwrap_err();

        assert!(
            format!("{error:#}").contains("pending skill transaction must be a real directory")
        );
        assert_eq!(std::fs::read(sentinel).unwrap(), b"keep");
    }

    #[test]
    fn install_from_local_rejects_missing_manifest() {
        let staging = tempdir().unwrap();
        let dest = temp_skills_root();

        let src = staging.path().join("no_manifest");
        std::fs::create_dir_all(&src).unwrap();
        // No skill.yaml.
        let err = install_from_local(&src, dest.path(), false).unwrap_err();
        assert!(err.to_string().contains("no skill.yaml"));
    }

    #[test]
    fn install_from_local_rejects_broken_yaml() {
        let staging = tempdir().unwrap();
        let dest = temp_skills_root();

        let src = staging.path().join("broken");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("skill.yaml"), "this is = not [valid").unwrap();

        let err = install_from_local(&src, dest.path(), false).unwrap_err();
        assert!(err.to_string().contains("parse YAML"));
        // Confirm the target dir was never created — atomic-fail.
        assert!(!dest.path().join("broken").exists());
    }

    #[test]
    fn install_from_local_rejects_empty_id() {
        let staging = tempdir().unwrap();
        let dest = temp_skills_root();

        let src = staging.path().join("emptyid");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("skill.yaml"),
            "id: \"\"\ndescription: empty id\nsystem_prompt: x\n",
        )
        .unwrap();

        let err = install_from_local(&src, dest.path(), false).unwrap_err();
        let chain = format!("{err:#}");
        assert!(
            chain.contains("invalid skill id") && chain.contains("must not be empty"),
            "empty id must be rejected by validate_skill_id: {chain}"
        );
    }

    #[test]
    fn install_from_local_rejects_path_traversal_id() {
        let staging = tempdir().unwrap();
        let dest = temp_skills_root();
        let src = staging.path().join("evil_source");
        std::fs::create_dir_all(&src).unwrap();
        // Malicious manifest id that would escape the skills dir.
        std::fs::write(
            src.join("skill.yaml"),
            "id: \"../../pwned\"\ndescription: evil\nsystem_prompt: x\n",
        )
        .unwrap();
        let err = install_from_local(&src, dest.path(), false).unwrap_err();
        assert!(
            err.to_string().contains("invalid skill id"),
            "traversal id must be rejected: {err}"
        );
        // Nothing was written outside the target skills dir.
        assert!(!dest.path().join("..").join("pwned").exists());
        assert!(!dest.path().join("pwned").exists());
    }

    #[test]
    fn uninstall_removes_skill_dir() {
        let dest = temp_skills_root();
        let target = dest.path().join("doomed");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("skill.yaml"), "id: doomed\n").unwrap();

        let removed = uninstall(dest.path(), "doomed").unwrap();
        assert!(removed);
        assert!(!target.exists());
    }

    #[test]
    fn uninstall_rejects_reexposed_bundled_alias_before_journaling() {
        let dest = temp_skills_root();
        let target = dest.path().join("academic_research");
        write_skill(
            &target,
            "academic_research",
            "id: academic_research\n\
             description: Active installed override\n\
             trigger_keywords: [installed-override-only]\n\
             system_prompt: override fixture\n",
        );
        write_skill(
            &dest.path().join("custom_collision"),
            "custom_collision",
            "id: custom_collision\n\
             description: Claims the bundled fallback alias\n\
             trigger_keywords: [research]\n\
             system_prompt: collision fixture\n",
        );
        let target_before = std::fs::read(target.join("skill.yaml")).unwrap();

        let error = uninstall(dest.path(), "academic_research").unwrap_err();
        let detail = format!("{error:#}");
        assert!(
            detail.contains("route-owner reduction preflight"),
            "{detail}"
        );
        assert!(detail.contains("academic_research"), "{detail}");
        assert!(detail.contains("custom_collision"), "{detail}");
        assert_eq!(
            std::fs::read(target.join("skill.yaml")).unwrap(),
            target_before
        );
        assert!(
            open_pending_skill_mutation_reconciliation(dest.path())
                .unwrap()
                .is_none(),
            "ownership rejection must happen before mutation journaling"
        );
    }

    #[test]
    fn uninstall_missing_id_is_ok_false() {
        let dest = temp_skills_root();
        let removed = uninstall(dest.path(), "never_installed").unwrap();
        assert!(!removed);
    }

    #[test]
    fn stale_uninstall_expectation_preserves_a_changed_healthy_generation() {
        let dest = temp_skills_root();
        let target = dest.path().join("healthy");
        write_skill(&target, "healthy", &good_yaml("healthy"));
        std::fs::write(target.join("asset.txt"), b"first").unwrap();
        let preflight = inspect_installed_target(dest.path(), "healthy").unwrap();
        let expected = preflight.target_generation_sha256.unwrap();

        std::fs::write(target.join("asset.txt"), b"changed after confirmation").unwrap();
        let error = uninstall_with_report_and_expectation(
            dest.path(),
            "healthy",
            Some(&UninstallExpectation {
                id: "healthy".to_string(),
                target_generation_sha256: expected,
            }),
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("changed after preflight"));
        assert_eq!(
            std::fs::read(target.join("asset.txt")).unwrap(),
            b"changed after confirmation"
        );
    }

    #[test]
    fn stale_uninstall_expectation_preserves_a_changed_broken_entry() {
        let dest = temp_skills_root();
        let target = dest.path().join("broken");
        std::fs::write(&target, b"first broken generation").unwrap();
        let preflight = inspect_installed_target(dest.path(), "broken").unwrap();
        let expected = preflight.target_generation_sha256.unwrap();

        std::fs::write(&target, b"changed broken generation").unwrap();
        let error = uninstall_with_report_and_expectation(
            dest.path(),
            "broken",
            Some(&UninstallExpectation {
                id: "broken".to_string(),
                target_generation_sha256: expected,
            }),
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("changed after preflight"));
        assert_eq!(std::fs::read(target).unwrap(), b"changed broken generation");
    }

    #[test]
    fn uninstall_rejects_ids_that_can_escape_the_skills_root() {
        let dest = temp_skills_root();
        let outside = tempdir().unwrap();
        let sentinel = outside.path().join("keep.txt");
        std::fs::write(&sentinel, b"keep").unwrap();

        for id in [
            "",
            "..",
            "../outside",
            "nested/skill",
            "nested\\skill",
            "skill:stream",
        ] {
            let error = uninstall(dest.path(), id).unwrap_err();
            assert!(
                format!("{error:#}").contains("invalid installed skill directory name"),
                "unexpected error for {id:?}: {error:#}"
            );
        }
        let absolute = outside.path().to_string_lossy();
        let error = uninstall(dest.path(), &absolute).unwrap_err();
        assert!(format!("{error:#}").contains("invalid installed skill directory name"));
        assert_eq!(std::fs::read(sentinel).unwrap(), b"keep");
    }

    #[test]
    fn uninstall_accepts_safe_legacy_directory_names() {
        let dest = temp_skills_root();
        let target = dest.path().join("legacy skill.β");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("skill.yaml"), "id: legacy skill.β\n").unwrap();

        assert!(uninstall(dest.path(), "legacy skill.β").unwrap());
        assert!(!target.exists());
    }

    #[test]
    fn uninstall_unlinks_broken_skill_directories_without_following_them() {
        let dest = temp_skills_root();
        let outside = tempdir().unwrap();
        let sentinel = outside.path().join("keep.txt");
        std::fs::write(&sentinel, b"keep").unwrap();
        let linked = dest.path().join("linked-skill");
        try_symlink_dir(outside.path(), &linked).expect("create directory link test fixture");

        let report = uninstall_with_report(dest.path(), "linked-skill").unwrap();

        assert!(report.removed);
        assert_eq!(std::fs::read(sentinel).unwrap(), b"keep");
        assert!(std::fs::symlink_metadata(linked).is_err());
    }

    #[test]
    fn broken_file_entry_is_visible_and_removable() {
        let dest = temp_skills_root();
        let broken = dest.path().join("broken-file");
        std::fs::write(&broken, b"not a skill directory").unwrap();

        let rows = list_installed(dest.path()).unwrap();
        let row = rows
            .iter()
            .find(|row| row.dir_name == "broken-file")
            .expect("broken file must remain operator-visible");
        assert_eq!(row.error.as_deref(), Some("skill entry is not a directory"));
        assert_eq!(row.repairability, Some(SkillRepairability::RemoveOnly));

        let report = uninstall_with_report(dest.path(), "broken-file").unwrap();
        assert!(report.removed);
        assert!(!broken.exists());
    }

    #[test]
    fn uninstall_rejects_a_linked_skills_root() {
        let parent = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let victim = outside.path().join("victim");
        std::fs::create_dir(&victim).unwrap();
        let sentinel = victim.join("keep.txt");
        std::fs::write(&sentinel, b"keep").unwrap();
        let linked_root = parent.path().join("skills");
        try_symlink_dir(outside.path(), &linked_root)
            .expect("create linked skills-root test fixture");

        let error = uninstall(&linked_root, "victim").unwrap_err();
        assert!(format!("{error:#}").contains("skills root must be a real directory"));
        assert_eq!(std::fs::read(sentinel).unwrap(), b"keep");
    }

    #[test]
    fn fresh_install_rejects_a_linked_skills_root() {
        let staging = tempdir().unwrap();
        let parent = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let linked_root = parent.path().join("skills");
        try_symlink_dir(outside.path(), &linked_root)
            .expect("create linked skills-root test fixture");
        let source = staging.path().join("source");
        write_skill(&source, "new-skill", &good_yaml("new-skill"));

        let error = install_from_local(&source, &linked_root, false).unwrap_err();
        assert!(format!("{error:#}").contains("skills root must be a real directory"));
        assert!(!outside.path().join("new-skill").exists());
    }

    #[test]
    fn recursive_remove_does_not_follow_a_swapped_target_link() {
        let dest = temp_skills_root();
        let outside = tempdir().unwrap();
        let sentinel = outside.path().join("keep.txt");
        std::fs::write(&sentinel, b"keep").unwrap();
        let target = dest.path().join("victim");
        std::fs::create_dir(&target).unwrap();

        let root = open_bound_directory(dest.path(), false, "test skills root")
            .unwrap()
            .unwrap();
        drop(open_real_child_dir(&root.dir, OsStr::new("victim"), &target).unwrap());
        std::fs::remove_dir(&target).unwrap();
        try_symlink_dir(outside.path(), &target).expect("create swapped target test fixture");

        let _ = root.dir.remove_dir_all("victim");
        assert_eq!(std::fs::read(sentinel).unwrap(), b"keep");
    }

    #[test]
    fn file_copy_refuses_a_preexisting_target_alias() {
        let source_dir = tempdir().unwrap();
        let target_dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let source = source_dir.path().join("source.txt");
        let target = target_dir.path().join("source.txt");
        let sentinel = outside.path().join("keep.txt");
        std::fs::write(&source, b"replacement").unwrap();
        std::fs::write(&sentinel, b"keep").unwrap();
        std::fs::hard_link(&sentinel, &target).unwrap();

        let source_root = open_bound_directory(source_dir.path(), false, "test source")
            .unwrap()
            .unwrap();
        let target_root = open_bound_directory(target_dir.path(), false, "test target")
            .unwrap()
            .unwrap();
        let error = copy_regular_file_create_new(
            &source_root.dir,
            &target_root.dir,
            OsStr::new("source.txt"),
            &source,
            &target,
            &mut CopyBudget::default(),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("create skill target"));
        assert_eq!(std::fs::read(sentinel).unwrap(), b"keep");
    }

    #[test]
    fn forced_reinstall_rejects_linked_target_directories() {
        let staging = tempdir().unwrap();
        let dest = temp_skills_root();
        let outside = tempdir().unwrap();
        let sentinel = outside.path().join("keep.txt");
        std::fs::write(&sentinel, b"keep").unwrap();
        let linked = dest.path().join("linked-skill");
        try_symlink_dir(outside.path(), &linked).expect("create directory link test fixture");
        let source = staging.path().join("source");
        write_skill(&source, "linked-skill", &good_yaml("linked-skill"));

        let error = install_from_local(&source, dest.path(), true).unwrap_err();
        assert!(format!("{error:#}").contains("real directory"));
        assert_eq!(std::fs::read(sentinel).unwrap(), b"keep");
        assert!(std::fs::symlink_metadata(linked).is_ok());
    }

    #[test]
    fn list_installed_surfaces_broken_entries() {
        let dest = temp_skills_root();

        let healthy = dest.path().join("healthy");
        std::fs::create_dir_all(&healthy).unwrap();
        std::fs::write(healthy.join("skill.yaml"), good_yaml("healthy")).unwrap();

        let no_manifest = dest.path().join("no_manifest");
        std::fs::create_dir_all(&no_manifest).unwrap();

        let broken_yaml = dest.path().join("broken_yaml");
        std::fs::create_dir_all(&broken_yaml).unwrap();
        std::fs::write(broken_yaml.join("skill.yaml"), "this is = not [valid").unwrap();

        let rows = list_installed(dest.path()).unwrap();
        assert_eq!(rows.len(), 3);

        let h = rows.iter().find(|r| r.dir_name == "healthy").unwrap();
        assert_eq!(h.manifest_id.as_deref(), Some("healthy"));
        assert!(h.error.is_none());

        let n = rows.iter().find(|r| r.dir_name == "no_manifest").unwrap();
        assert!(n.manifest_id.is_none());
        assert!(n.error.as_ref().unwrap().contains("no skill.yaml"));
        assert_eq!(
            n.repairability,
            Some(SkillRepairability::ManifestReplaceable)
        );

        let b = rows.iter().find(|r| r.dir_name == "broken_yaml").unwrap();
        assert!(b.manifest_id.is_none());
        assert!(b.error.as_ref().unwrap().contains("YAML parse error"));
        assert_eq!(
            b.repairability,
            Some(SkillRepairability::ManifestReplaceable)
        );
    }

    #[test]
    fn list_installed_returns_empty_for_missing_dir() {
        let dest = temp_skills_root();
        let rows = list_installed(&dest.path().join("nope")).unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn list_installed_skips_private_dotfiles_but_surfaces_public_files() {
        let dest = temp_skills_root();
        // Hidden dir
        std::fs::create_dir_all(dest.path().join(".hidden")).unwrap();
        // Plain file
        std::fs::write(dest.path().join("loose.txt"), b"x").unwrap();
        let rows = list_installed(dest.path()).unwrap();
        assert_eq!(rows.len(), 1, "expected exactly one public broken entry");
        assert_eq!(rows[0].dir_name, "loose.txt");
        assert_eq!(
            rows[0].error.as_deref(),
            Some("skill entry is not a directory")
        );
    }

    #[test]
    fn recovery_cleans_creator_directory_and_private_file_stages() {
        let dest = temp_skills_root();
        let nonce = "0123456789abcdef0123456789abcdef";
        let creator_stage = dest
            .path()
            .join(format!("{CREATOR_DIRECTORY_STAGE_PREFIX}{nonce}"));
        std::fs::create_dir(&creator_stage).unwrap();
        std::fs::write(creator_stage.join("partial"), b"partial").unwrap();

        let public = dest.path().join("healthy");
        write_skill(&public, "healthy", &good_yaml("healthy"));
        let manifest_stage = public.join(format!("{CREATOR_MANIFEST_STAGE_PREFIX}{nonce}"));
        let replacement_stage = public.join(format!("{FILE_REPLACEMENT_STAGE_PREFIX}{nonce}"));
        std::fs::write(&manifest_stage, b"staged manifest").unwrap();
        std::fs::write(&replacement_stage, b"staged replacement").unwrap();

        let rows = list_installed(dest.path()).unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].dir_name, "healthy");
        assert!(!creator_stage.exists());
        assert!(!manifest_stage.exists());
        assert!(!replacement_stage.exists());
    }

    #[test]
    fn recovery_finishes_private_uninstall_tombstones() {
        let dest = temp_skills_root();
        let nonce = "0123456789abcdef0123456789abcdef";
        let tombstone = dest
            .path()
            .join(format!("{DELETE_TRANSACTION_PREFIX}doomed-{nonce}"));
        write_skill(&tombstone, "doomed", &good_yaml("doomed"));
        std::fs::write(tombstone.join("sentinel"), b"private").unwrap();

        let rows = list_installed(dest.path()).unwrap();

        assert!(rows.is_empty());
        assert!(!tombstone.exists());
    }

    #[test]
    fn recovery_accepts_the_same_safe_broken_names_as_uninstall() {
        let dest = temp_skills_root();
        let nonce = "0123456789abcdef0123456789abcdef";
        let tombstone = dest
            .path()
            .join(format!("{DELETE_TRANSACTION_PREFIX}Broken Skill-{nonce}"));
        std::fs::create_dir(&tombstone).unwrap();
        std::fs::write(tombstone.join("sentinel"), b"private").unwrap();

        recover_pending_transactions(dest.path()).unwrap();

        assert!(!tombstone.exists());
    }

    #[test]
    fn recovery_retains_uninstall_tombstone_until_parent_sync_succeeds() {
        let dest = temp_skills_root();
        let nonce = "0123456789abcdef0123456789abcdef";
        let tombstone = dest
            .path()
            .join(format!("{DELETE_TRANSACTION_PREFIX}doomed-{nonce}"));
        write_skill(&tombstone, "doomed", &good_yaml("doomed"));

        fail_next_directory_syncs(1);
        let error = recover_pending_transactions(dest.path()).unwrap_err();

        assert!(format!("{error:#}").contains("injected skill directory sync failure"));
        assert!(
            tombstone.exists(),
            "recovery must not discard the uninstall proof before a parent sync"
        );

        recover_pending_transactions(dest.path()).unwrap();
        assert!(!tombstone.exists());
    }

    #[test]
    fn recovery_ignores_noncanonical_private_transaction_nonces() {
        // A non-canonical nonce is NOT one of our transactions: recovery must
        // neither act on it nor guess. It must also not fail the store — that
        // turned one foreign entry into a permanent product-wide outage with no
        // in-product repair path (external review PR5-001).
        let dest = temp_skills_root();
        let uppercase = "0123456789ABCDEF0123456789ABCDEF";
        let stage = dest
            .path()
            .join(format!("{CREATOR_DIRECTORY_STAGE_PREFIX}{uppercase}"));
        std::fs::create_dir(&stage).unwrap();
        write_skill(
            &dest.path().join("healthy"),
            "healthy",
            &good_yaml("healthy"),
        );

        let rows = list_installed(dest.path()).expect("a foreign entry must not fail the store");
        assert!(
            rows.iter().any(|row| row.dir_name == "healthy"),
            "the healthy skill must still be inventoried: {rows:?}"
        );
        assert!(
            stage.exists(),
            "an entry we do not own must be left untouched for the operator"
        );
        assert_eq!(
            classify_private_stage_marker(
                std::ffi::OsStr::new(&format!("{CREATOR_DIRECTORY_STAGE_PREFIX}{uppercase}")),
                CREATOR_DIRECTORY_STAGE_PREFIX
            ),
            PrivateStageMarker::Malformed
        );
    }

    #[test]
    fn install_refuses_a_package_entry_with_a_reserved_private_prefix() {
        // The planting vector for PR5-001: the install copy was name-agnostic,
        // so a package could drop a file into the namespace the store's crash
        // recovery owns.
        for prefix in RESERVED_SKILL_ENTRY_PREFIXES {
            let staging = tempdir().unwrap();
            let dest = temp_skills_root();
            let source = staging.path().join("planted");
            write_skill(&source, "planted", &good_yaml("planted"));
            std::fs::write(source.join(format!("{prefix}readme")), b"x").unwrap();

            let error = install_from_local(&source, dest.path(), false)
                .expect_err("a reserved prefix must be refused at install time");
            let rendered = format!("{error:#}");
            assert!(
                rendered.contains("reserved private-artifact prefix"),
                "unexpected error for {prefix}: {rendered}"
            );
        }
    }
}
