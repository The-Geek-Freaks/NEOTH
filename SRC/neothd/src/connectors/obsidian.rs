//! Capability-bound, effect-free Obsidian import planning.
//!
//! This module deliberately stops at deterministic drafts. It never opens a
//! database or WAL, never writes a cursor, never contacts a service, and never
//! turns note text into GroundTruth. The only ambient path lookup happens
//! while a policy-bound grant is issued; every component is then opened
//! relative to a retained directory handle without following links. Planning
//! itself uses only those retained capabilities.

use std::{
    cell::RefCell,
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    fmt,
    io::{self, Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
    rc::{Rc, Weak},
};

use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _};
use cap_std::fs::{Dir, Metadata, OpenOptions};
use hmac::{Hmac, Mac as _};
use serde_yaml::Value as YamlValue;
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use super::{
    ConnectorConfiguration, ConnectorEntryPoint, ConnectorId, ConnectorPolicySnapshot,
    ResourceLimits, admit_entry_point,
};

type HmacSha256 = Hmac<Sha256>;

const VAULT_ID_DOMAIN: &[u8] = b"neoth/cc04/obsidian/vault-id/v1\0";
const SOURCE_ID_DOMAIN: &[u8] = b"neoth/cc04/obsidian/source-id/v1\0";
const REVISION_DOMAIN: &[u8] = b"neoth/cc04/obsidian/revision/v1\0";

const ABSOLUTE_MAX_ENTRIES: usize = 32_768;
const ABSOLUTE_MAX_FILES: usize = 8_192;
const ABSOLUTE_MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
const ABSOLUTE_MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const ABSOLUTE_MAX_NORMALIZED_FILE_BYTES: usize = 16 * 1024 * 1024;
const ABSOLUTE_MAX_TOTAL_NORMALIZED_BYTES: usize = 512 * 1024 * 1024;
const ABSOLUTE_MAX_RETAINED_BYTES: usize = 256 * 1024 * 1024;
const ABSOLUTE_MAX_DEPTH: usize = 64;
const MAX_POLICY_VAULT_ID_LEN: usize = 64;

/// Control-plane-owned liveness state for one admitted Obsidian policy.
///
/// A grant retains only a `Weak` proof of this state. The owner must therefore
/// outlive queued work, and can invalidate every queued capability by revoking
/// it or advancing its generation when consent or policy changes. This remains
/// module-private until CC-03 wires a durable, authenticated authority owner.
#[cfg_attr(not(test), allow(dead_code))]
struct ObsidianPolicyAuthority {
    subject_id: String,
    policy_snapshot: ConnectorPolicySnapshot,
    state: Rc<RefCell<ObsidianPolicyAuthorityState>>,
}

#[derive(Debug)]
struct ObsidianPolicyAuthorityState {
    active: bool,
    generation: u64,
}

#[cfg_attr(not(test), allow(dead_code))]
impl ObsidianPolicyAuthority {
    fn for_admitted_configuration(
        configuration: &ConnectorConfiguration,
    ) -> Result<Self, ObsidianPlanError> {
        admit_obsidian_configuration(configuration)?;
        Ok(Self {
            subject_id: configuration.subject_id.as_str().to_owned(),
            policy_snapshot: configuration.policy.clone(),
            state: Rc::new(RefCell::new(ObsidianPolicyAuthorityState {
                active: true,
                generation: 0,
            })),
        })
    }

    /// Invalidates all capabilities issued by this authority.
    #[cfg_attr(not(test), allow(dead_code))]
    fn revoke(&self) {
        self.state.borrow_mut().active = false;
    }

    /// Invalidates queued capabilities after an admitted-policy or consent
    /// revision. A later CC-03 owner replaces its snapshot before reissuing.
    #[cfg_attr(not(test), allow(dead_code))]
    fn advance_generation(&self) {
        let mut state = self.state.borrow_mut();
        if let Some(next_generation) = state.generation.checked_add(1) {
            state.generation = next_generation;
        } else {
            // Never let counter wrap make an old queued grant valid again.
            state.active = false;
        }
    }

    fn issue_root_grant(
        &self,
        configuration: &ConnectorConfiguration,
        selected_root: PathBuf,
        stable_policy_vault_id: impl Into<String>,
        identity_key: [u8; 32],
    ) -> Result<ObsidianPolicyRootGrant, ObsidianPlanError> {
        admit_obsidian_configuration(configuration)?;
        if configuration.subject_id.as_str() != self.subject_id
            || configuration.policy != self.policy_snapshot
        {
            return Err(ObsidianPlanError::GrantBindingMismatch);
        }
        let state = self.state.borrow();
        if !state.active {
            return Err(ObsidianPlanError::AuthorityNoLongerLive);
        }
        ObsidianPolicyRootGrant::issue_for_admitted_policy(
            configuration,
            selected_root,
            stable_policy_vault_id,
            identity_key,
            Rc::downgrade(&self.state),
            state.generation,
        )
    }
}

/// A root selection bound to one already-admitted Obsidian policy snapshot.
/// Fields and construction are module-private, so external callers
/// cannot mint filesystem authority by supplying an arbitrary path.
#[cfg_attr(not(test), allow(dead_code))]
struct ObsidianPolicyRootGrant {
    selected_root: PathBuf,
    stable_policy_vault_id: String,
    identity_key: Zeroizing<[u8; 32]>,
    subject_id: String,
    policy_snapshot: ConnectorPolicySnapshot,
    authority_state: Weak<RefCell<ObsidianPolicyAuthorityState>>,
    authority_generation: u64,
}

impl fmt::Debug for ObsidianPolicyRootGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ObsidianPolicyRootGrant(<redacted>)")
    }
}

#[cfg_attr(not(test), allow(dead_code))]
impl ObsidianPolicyRootGrant {
    fn ensure_live_authority(&self) -> Result<(), ObsidianPlanError> {
        let authority_state = self
            .authority_state
            .upgrade()
            .ok_or(ObsidianPlanError::AuthorityNoLongerLive)?;
        let state = authority_state.borrow();
        if !state.active || state.generation != self.authority_generation {
            return Err(ObsidianPlanError::AuthorityNoLongerLive);
        }
        Ok(())
    }

    /// Sole root-grant issuer. The control plane supplies the operator-selected
    /// root, stable policy id, and a SecretStore-derived identity key only after
    /// context-import admission.
    fn issue_for_admitted_policy(
        configuration: &ConnectorConfiguration,
        selected_root: PathBuf,
        stable_policy_vault_id: impl Into<String>,
        identity_key: [u8; 32],
        authority_state: Weak<RefCell<ObsidianPolicyAuthorityState>>,
        authority_generation: u64,
    ) -> Result<Self, ObsidianPlanError> {
        admit_obsidian_configuration(configuration)?;
        validate_root_path_form(&selected_root)?;
        let stable_policy_vault_id = stable_policy_vault_id.into();
        validate_policy_vault_id(&stable_policy_vault_id)?;
        if identity_key.iter().all(|byte| *byte == 0) {
            return Err(ObsidianPlanError::InvalidIdentityKey);
        }
        Ok(Self {
            selected_root,
            stable_policy_vault_id,
            identity_key: Zeroizing::new(identity_key),
            subject_id: configuration.subject_id.as_str().to_owned(),
            policy_snapshot: configuration.policy.clone(),
            authority_state,
            authority_generation,
        })
    }
}

/// Opaque identity derived from policy state, never from an absolute path.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ObsidianVaultId([u8; 32]);

impl ObsidianVaultId {
    pub(crate) fn encoded(self) -> String {
        format!("obsidian:vault:hmac-sha256:{}", hex::encode(self.0))
    }
}

impl fmt::Debug for ObsidianVaultId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ObsidianVaultId(hmac-sha256:<redacted>)")
    }
}

/// Non-forgeable runtime capability retained after policy issuance.
/// There is no path constructor, public field, `Clone`, or path accessor.
#[must_use = "an approved Obsidian vault is a one-shot planning capability"]
pub(crate) struct ApprovedObsidianVault {
    root: Dir,
    namespace_fences: Vec<NamespaceFence>,
    root_identity: PhysicalIdentity,
    vault_id: ObsidianVaultId,
    identity_key: Zeroizing<[u8; 32]>,
    policy_limits: ResourceLimits,
    authority_state: Weak<RefCell<ObsidianPolicyAuthorityState>>,
    authority_generation: u64,
}

impl fmt::Debug for ApprovedObsidianVault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovedObsidianVault")
            .field("vault_id", &self.vault_id)
            .field("root", &"<capability-redacted>")
            .finish_non_exhaustive()
    }
}

impl ApprovedObsidianVault {
    #[cfg_attr(not(test), allow(dead_code))]
    fn issue(
        configuration: &ConnectorConfiguration,
        grant: ObsidianPolicyRootGrant,
    ) -> Result<Self, ObsidianPlanError> {
        // A queued root grant must be live before opening even its first path.
        // Planning repeats the check because authority can change after issue.
        grant.ensure_live_authority()?;
        admit_obsidian_configuration(configuration)?;
        if configuration.subject_id.as_str() != grant.subject_id
            || configuration.policy != grant.policy_snapshot
        {
            return Err(ObsidianPlanError::GrantBindingMismatch);
        }

        let (root, namespace_fences) = open_absolute_directory_capability(&grant.selected_root)?;
        let root_metadata = root.dir_metadata().map_err(map_io)?;
        validate_real_directory_metadata(&root_metadata)?;
        let root_identity = physical_identity(&root_metadata, PhysicalKind::Directory)?;
        validate_namespace_fences(&namespace_fences)?;
        let vault_digest = domain_hmac(
            &grant.identity_key[..],
            VAULT_ID_DOMAIN,
            &[
                grant.subject_id.as_bytes(),
                grant.stable_policy_vault_id.as_bytes(),
            ],
        );
        Ok(Self {
            root,
            namespace_fences,
            root_identity,
            vault_id: ObsidianVaultId(vault_digest),
            identity_key: grant.identity_key,
            policy_limits: configuration.policy.limits,
            authority_state: grant.authority_state,
            authority_generation: grant.authority_generation,
        })
    }

    pub(crate) fn vault_id(&self) -> ObsidianVaultId {
        self.vault_id
    }

    fn ensure_live_authority(&self) -> Result<(), ObsidianPlanError> {
        let authority_state = self
            .authority_state
            .upgrade()
            .ok_or(ObsidianPlanError::AuthorityNoLongerLive)?;
        let state = authority_state.borrow();
        if !state.active || state.generation != self.authority_generation {
            return Err(ObsidianPlanError::AuthorityNoLongerLive);
        }
        Ok(())
    }
}

struct NamespaceFence {
    parent: Dir,
    child_name: OsString,
    expected_identity: PhysicalIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ObsidianImportLimits {
    /// All enumerated children, including ignored and non-Markdown entries.
    pub max_entries: usize,
    pub max_files: usize,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    /// Checked while NFC scalars are emitted, before the normalized String grows.
    pub max_normalized_file_bytes: usize,
    /// Total normalized bytes processed across all candidates.
    pub max_total_normalized_bytes: usize,
    /// Total bytes retained in draft bodies.
    pub max_retained_bytes: usize,
    /// A direct child has depth one.
    pub max_depth: usize,
}

impl Default for ObsidianImportLimits {
    fn default() -> Self {
        Self {
            max_entries: 8_192,
            max_files: 1_000,
            max_file_bytes: 1024 * 1024,
            // Two bounded reads prove one stable source snapshot, so this is
            // the physical I/O budget rather than a one-read logical size.
            max_total_bytes: 128 * 1024 * 1024,
            max_normalized_file_bytes: 2 * 1024 * 1024,
            max_total_normalized_bytes: 128 * 1024 * 1024,
            max_retained_bytes: 64 * 1024 * 1024,
            max_depth: 16,
        }
    }
}

impl ObsidianImportLimits {
    fn validate(self, policy: ResourceLimits) -> Result<(), ObsidianPlanError> {
        if self.max_entries == 0
            || self.max_entries > ABSOLUTE_MAX_ENTRIES
            || self.max_files == 0
            || self.max_files > ABSOLUTE_MAX_FILES
            || self.max_files > self.max_entries
            || self.max_file_bytes == 0
            || self.max_file_bytes > ABSOLUTE_MAX_FILE_BYTES
            || self.max_total_bytes == 0
            || self.max_total_bytes > ABSOLUTE_MAX_TOTAL_BYTES
            || self.max_file_bytes > self.max_total_bytes
            || self.max_normalized_file_bytes == 0
            || self.max_normalized_file_bytes > ABSOLUTE_MAX_NORMALIZED_FILE_BYTES
            || self.max_total_normalized_bytes == 0
            || self.max_total_normalized_bytes > ABSOLUTE_MAX_TOTAL_NORMALIZED_BYTES
            || self.max_normalized_file_bytes > self.max_total_normalized_bytes
            || self.max_retained_bytes == 0
            || self.max_retained_bytes > ABSOLUTE_MAX_RETAINED_BYTES
            || self.max_depth == 0
            || self.max_depth > ABSOLUTE_MAX_DEPTH
        {
            return Err(ObsidianPlanError::InvalidLimits);
        }
        if self.max_files > policy.max_items_per_run as usize
            || self.max_file_bytes > policy.max_bytes_per_item
            || self.max_normalized_file_bytes as u64 > policy.max_bytes_per_item
            || self.max_total_bytes > policy.max_total_bytes_per_run
            || self.max_total_normalized_bytes as u64 > policy.max_total_bytes_per_run
            || self.max_retained_bytes as u64 > policy.max_total_bytes_per_run
        {
            return Err(ObsidianPlanError::PolicyLimitExceeded);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SourceSpan {
    source_id: String,
    start_byte: usize,
    end_byte: usize,
    start_line: usize,
    end_line: usize,
}

impl fmt::Debug for SourceSpan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceSpan")
            .field("source_id", &self.source_id)
            .field("start_byte", &self.start_byte)
            .field("end_byte", &self.end_byte)
            .field("start_line", &self.start_line)
            .field("end_line", &self.end_line)
            .finish()
    }
}

impl SourceSpan {
    pub(crate) fn source_id(&self) -> &str {
        &self.source_id
    }
    pub(crate) fn start_byte(&self) -> usize {
        self.start_byte
    }
    pub(crate) fn end_byte(&self) -> usize {
        self.end_byte
    }
    pub(crate) fn start_line(&self) -> usize {
        self.start_line
    }
    pub(crate) fn end_line(&self) -> usize {
        self.end_line
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ObsidianImportDraft {
    source_id: String,
    source_revision_hmac_sha256: String,
    body: String,
    source_span: SourceSpan,
}

impl fmt::Debug for ObsidianImportDraft {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObsidianImportDraft")
            .field("source_id", &self.source_id)
            .field(
                "source_revision_hmac_sha256",
                &self.source_revision_hmac_sha256,
            )
            .field("body_bytes", &self.body.len())
            .field("source_span", &self.source_span)
            .finish()
    }
}

impl ObsidianImportDraft {
    pub(crate) fn source_id(&self) -> &str {
        &self.source_id
    }
    pub(crate) fn source_revision_hmac_sha256(&self) -> &str {
        &self.source_revision_hmac_sha256
    }
    /// Explicit raw-data boundary. `Debug` and status never call this.
    pub(crate) fn body(&self) -> &str {
        &self.body
    }
    pub(crate) fn source_span(&self) -> &SourceSpan {
        &self.source_span
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ObsidianPlanStatus {
    pub enumerated_entries: usize,
    pub visited_directories: usize,
    pub scanned_markdown_files: usize,
    pub scanned_source_bytes: u64,
    pub normalized_source_bytes: usize,
    pub retained_draft_bytes: usize,
    pub draft_count: usize,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ObsidianImportPlan {
    drafts: Vec<ObsidianImportDraft>,
    status: ObsidianPlanStatus,
}

impl fmt::Debug for ObsidianImportPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObsidianImportPlan")
            .field("status", &self.status)
            .field("redacted_draft_count", &self.drafts.len())
            .finish()
    }
}

impl ObsidianImportPlan {
    pub(crate) fn status(&self) -> ObsidianPlanStatus {
        self.status
    }
    pub(crate) fn drafts(&self) -> &[ObsidianImportDraft] {
        &self.drafts
    }
    pub(crate) fn into_drafts(self) -> Vec<ObsidianImportDraft> {
        self.drafts
    }
}

/// Builds a synchronous, capability-bound plan without owning a clock, process,
/// daemon, or executor. The CC-03 authority adapter must enforce the admitted
/// `max_runtime_seconds` at its scheduling boundary; this primitive independently
/// bounds every growing collection and every source read. The approved vault is
/// consumed so a capability issued before a later revocation cannot be reused.
pub(crate) fn plan_import(
    vault: ApprovedObsidianVault,
    limits: ObsidianImportLimits,
) -> Result<ObsidianImportPlan, ObsidianPlanError> {
    // This precedes every retained capability operation. A queued vault must
    // not touch the filesystem after its authority is revoked, superseded, or
    // dropped by the control plane.
    vault.ensure_live_authority()?;
    limits.validate(vault.policy_limits)?;
    validate_namespace_fences(&vault.namespace_fences)?;
    let current_root = physical_identity(
        &vault.root.dir_metadata().map_err(map_io)?,
        PhysicalKind::Directory,
    )?;
    if current_root != vault.root_identity {
        return Err(ObsidianPlanError::ChangedDuringPlanning);
    }

    let mut state = PlannerState {
        limits,
        vault_id: vault.vault_id,
        identity_key: &vault.identity_key[..],
        directory_identities: BTreeSet::new(),
        file_identities: BTreeSet::new(),
        source_ids: BTreeSet::new(),
        enumerated_entries: 0,
        visited_directories: 0,
        scanned_markdown_files: 0,
        scanned_source_bytes: 0,
        normalized_source_bytes: 0,
        retained_draft_bytes: 0,
        drafts: Vec::new(),
    };
    walk_directory(&vault.root, 0, &mut Vec::new(), &mut state)?;

    validate_namespace_fences(&vault.namespace_fences)?;
    let final_root = physical_identity(
        &vault.root.dir_metadata().map_err(map_io)?,
        PhysicalKind::Directory,
    )?;
    if final_root != vault.root_identity {
        return Err(ObsidianPlanError::ChangedDuringPlanning);
    }

    Ok(ObsidianImportPlan {
        status: ObsidianPlanStatus {
            enumerated_entries: state.enumerated_entries,
            visited_directories: state.visited_directories,
            scanned_markdown_files: state.scanned_markdown_files,
            scanned_source_bytes: state.scanned_source_bytes,
            normalized_source_bytes: state.normalized_source_bytes,
            retained_draft_bytes: state.retained_draft_bytes,
            draft_count: state.drafts.len(),
        },
        drafts: state.drafts,
    })
}

struct PlannerState<'a> {
    limits: ObsidianImportLimits,
    vault_id: ObsidianVaultId,
    identity_key: &'a [u8],
    directory_identities: BTreeSet<PhysicalIdentity>,
    file_identities: BTreeSet<PhysicalIdentity>,
    source_ids: BTreeSet<String>,
    enumerated_entries: usize,
    visited_directories: usize,
    scanned_markdown_files: usize,
    scanned_source_bytes: u64,
    normalized_source_bytes: usize,
    retained_draft_bytes: usize,
    drafts: Vec<ObsidianImportDraft>,
}

struct ScannedEntry {
    raw_name: OsString,
    normalized_name: String,
    portable_key: String,
}

fn walk_directory(
    directory: &Dir,
    depth: usize,
    relative_components: &mut Vec<String>,
    state: &mut PlannerState<'_>,
) -> Result<(), ObsidianPlanError> {
    let directory_identity = physical_identity(
        &directory.dir_metadata().map_err(map_io)?,
        PhysicalKind::Directory,
    )?;
    if !state.directory_identities.insert(directory_identity) {
        return Err(ObsidianPlanError::DirectoryCycleOrAmbiguity);
    }
    state.visited_directories = state
        .visited_directories
        .checked_add(1)
        .ok_or(ObsidianPlanError::LimitExceeded(ObsidianLimit::Entries))?;

    let mut entries = Vec::new();
    let mut normalized_names = BTreeSet::new();
    let mut portable_keys = BTreeSet::new();
    for entry in directory.entries().map_err(map_io)? {
        state.enumerated_entries = state
            .enumerated_entries
            .checked_add(1)
            .ok_or(ObsidianPlanError::LimitExceeded(ObsidianLimit::Entries))?;
        if state.enumerated_entries > state.limits.max_entries {
            return Err(ObsidianPlanError::LimitExceeded(ObsidianLimit::Entries));
        }
        let raw_name = entry.map_err(map_io)?.file_name();
        let name = raw_name
            .to_str()
            .ok_or(ObsidianPlanError::NonUtf8PathComponent)?;
        validate_text_component(name)?;
        let normalized_name = name.nfc().collect::<String>();
        let portable_key = portable_collision_key(name);
        if !normalized_names.insert(normalized_name.clone())
            || !portable_keys.insert(portable_key.clone())
        {
            return Err(ObsidianPlanError::PortableNameCollision);
        }
        // The global counter is checked before this retained allocation.
        entries.push(ScannedEntry {
            raw_name,
            normalized_name,
            portable_key,
        });
    }
    entries.sort_unstable_by(|left, right| {
        left.portable_key
            .cmp(&right.portable_key)
            .then_with(|| left.normalized_name.cmp(&right.normalized_name))
    });

    for entry in entries {
        let name = entry.raw_name.as_os_str();
        let observed = directory.symlink_metadata(name).map_err(map_io)?;
        if cap_metadata_is_link_like(&observed) {
            return Err(ObsidianPlanError::SymlinkOrReparsePoint);
        }
        let next_depth = depth
            .checked_add(1)
            .ok_or(ObsidianPlanError::LimitExceeded(ObsidianLimit::Depth))?;
        if next_depth > state.limits.max_depth {
            return Err(ObsidianPlanError::LimitExceeded(ObsidianLimit::Depth));
        }

        if observed.is_dir() {
            if is_excluded_entry(&entry.normalized_name, &observed) {
                continue;
            }
            let expected = physical_identity(&observed, PhysicalKind::Directory)?;
            let child = open_direct_child_directory(directory, name)?;
            let opened = physical_identity(
                &child.dir_metadata().map_err(map_io)?,
                PhysicalKind::Directory,
            )?;
            if opened != expected {
                return Err(ObsidianPlanError::ChangedDuringPlanning);
            }
            run_after_child_directory_open_for_test();
            relative_components.push(entry.normalized_name);
            walk_directory(&child, next_depth, relative_components, state)?;
            relative_components.pop();
            let after = directory
                .symlink_metadata(name)
                .map_err(|_| ObsidianPlanError::ChangedDuringPlanning)?;
            if cap_metadata_is_link_like(&after)
                || physical_identity(&after, PhysicalKind::Directory)? != expected
            {
                return Err(ObsidianPlanError::ChangedDuringPlanning);
            }
            continue;
        }
        if !observed.is_file() {
            return Err(ObsidianPlanError::NonRegularFilesystemEntry);
        }
        if is_excluded_entry(&entry.normalized_name, &observed)
            || !is_markdown_name(&entry.normalized_name)
        {
            continue;
        }

        state.scanned_markdown_files = state
            .scanned_markdown_files
            .checked_add(1)
            .ok_or(ObsidianPlanError::LimitExceeded(ObsidianLimit::Files))?;
        if state.scanned_markdown_files > state.limits.max_files {
            return Err(ObsidianPlanError::LimitExceeded(ObsidianLimit::Files));
        }
        let expected = physical_identity(&observed, PhysicalKind::File)?;
        if !state.file_identities.insert(expected) {
            return Err(ObsidianPlanError::DirectoryCycleOrAmbiguity);
        }

        relative_components.push(entry.normalized_name);
        let relative_path = relative_components.join("/");
        let source_id = source_id(state.identity_key, state.vault_id, relative_path.as_bytes());
        if !state.source_ids.insert(source_id.clone()) {
            return Err(ObsidianPlanError::DirectoryCycleOrAmbiguity);
        }
        let remaining_source_bytes = state
            .limits
            .max_total_bytes
            .saturating_sub(state.scanned_source_bytes);
        let source = read_candidate(
            directory,
            name,
            expected,
            state.limits.max_file_bytes,
            remaining_source_bytes,
        )?;
        relative_components.pop();
        state.scanned_source_bytes = state
            .scanned_source_bytes
            .checked_add(source.io_bytes)
            .ok_or(ObsidianPlanError::LimitExceeded(ObsidianLimit::TotalBytes))?;
        if state.scanned_source_bytes > state.limits.max_total_bytes {
            return Err(ObsidianPlanError::LimitExceeded(ObsidianLimit::TotalBytes));
        }

        let normalized = normalize_markdown(&source.bytes, state.limits.max_normalized_file_bytes)?;
        state.normalized_source_bytes = state
            .normalized_source_bytes
            .checked_add(normalized.len())
            .ok_or(ObsidianPlanError::LimitExceeded(
                ObsidianLimit::NormalizedBytes,
            ))?;
        if state.normalized_source_bytes > state.limits.max_total_normalized_bytes {
            return Err(ObsidianPlanError::LimitExceeded(
                ObsidianLimit::NormalizedBytes,
            ));
        }
        let frontmatter = parse_frontmatter(&normalized)?;
        if frontmatter.managed {
            continue;
        }
        let body = &normalized[frontmatter.body_start..];
        if body.trim().is_empty() {
            continue;
        }
        state.retained_draft_bytes = state.retained_draft_bytes.checked_add(body.len()).ok_or(
            ObsidianPlanError::LimitExceeded(ObsidianLimit::RetainedBytes),
        )?;
        if state.retained_draft_bytes > state.limits.max_retained_bytes {
            return Err(ObsidianPlanError::LimitExceeded(
                ObsidianLimit::RetainedBytes,
            ));
        }

        let start_line = normalized[..frontmatter.body_start]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1;
        let revision = domain_hmac(
            state.identity_key,
            REVISION_DOMAIN,
            &[
                state.vault_id.0.as_slice(),
                source_id.as_bytes(),
                normalized.as_bytes(),
            ],
        );
        state.drafts.push(ObsidianImportDraft {
            source_span: SourceSpan {
                source_id: source_id.clone(),
                start_byte: frontmatter.body_start,
                end_byte: normalized.len(),
                start_line,
                end_line: normalized.lines().count().max(1),
            },
            source_id,
            source_revision_hmac_sha256: format!("hmac-sha256:{}", hex::encode(revision)),
            body: body.to_owned(),
        });
    }
    Ok(())
}

fn read_candidate(
    parent: &Dir,
    name: &OsStr,
    expected: PhysicalIdentity,
    max_bytes: u64,
    remaining_total_bytes: u64,
) -> Result<CandidateRead, ObsidianPlanError> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_SHARE_READ,
        };
        options
            .access_mode(FILE_GENERIC_READ)
            // No write/delete sharing: the observed file cannot be mutated or
            // replaced while its bounded snapshot is read.
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(not(any(unix, windows)))]
    return Err(ObsidianPlanError::UnsupportedPlatform);

    let mut file = parent.open_with(name, &options).map_err(map_io)?;
    let opened = file.metadata().map_err(map_io)?;
    validate_real_file_metadata(&opened)?;
    if physical_identity(&opened, PhysicalKind::File)? != expected {
        return Err(ObsidianPlanError::ChangedDuringPlanning);
    }
    let expected_len = opened.len();
    if expected_len > max_bytes {
        return Err(ObsidianPlanError::LimitExceeded(
            ObsidianLimit::PerFileBytes,
        ));
    }
    let per_read_cap = expected_len.min(max_bytes).min(remaining_total_bytes / 2);
    if per_read_cap != expected_len {
        return Err(ObsidianPlanError::LimitExceeded(ObsidianLimit::TotalBytes));
    }
    let planned_io_bytes = per_read_cap
        .checked_mul(2)
        .ok_or(ObsidianPlanError::LimitExceeded(ObsidianLimit::TotalBytes))?;
    let opened_modified = opened.modified().map_err(map_io)?;
    run_after_file_open_for_test();
    let mut bytes = Vec::with_capacity((expected_len as usize).min(64 * 1024));
    (&mut file)
        .take(per_read_cap)
        .read_to_end(&mut bytes)
        .map_err(map_io)?;
    if bytes.len() as u64 != expected_len {
        return Err(ObsidianPlanError::ChangedDuringPlanning);
    }
    run_between_file_reads_for_test();
    file.seek(SeekFrom::Start(0)).map_err(map_io)?;
    let mut verification = Vec::with_capacity(bytes.len().min(64 * 1024));
    (&mut file)
        .take(per_read_cap)
        .read_to_end(&mut verification)
        .map_err(map_io)?;
    if verification.len() as u64 != expected_len || verification != bytes {
        return Err(ObsidianPlanError::ChangedDuringPlanning);
    }
    let opened_after = file.metadata().map_err(map_io)?;
    let named_after = parent
        .symlink_metadata(name)
        .map_err(|_| ObsidianPlanError::ChangedDuringPlanning)?;
    if opened_after.len() != bytes.len() as u64
        || opened_after.modified().map_err(map_io)? != opened_modified
        || physical_identity(&opened_after, PhysicalKind::File)? != expected
        || cap_metadata_is_link_like(&named_after)
        || physical_identity(&named_after, PhysicalKind::File)? != expected
    {
        return Err(ObsidianPlanError::ChangedDuringPlanning);
    }
    Ok(CandidateRead {
        bytes,
        io_bytes: planned_io_bytes,
    })
}

struct CandidateRead {
    bytes: Vec<u8>,
    io_bytes: u64,
}

fn open_absolute_directory_capability(
    path: &Path,
) -> Result<(Dir, Vec<NamespaceFence>), ObsidianPlanError> {
    validate_root_path_form(path)?;
    #[cfg(unix)]
    let mut current =
        Dir::open_ambient_dir(Path::new("/"), cap_std::ambient_authority()).map_err(map_io)?;
    #[cfg(windows)]
    let mut current = {
        use std::path::Prefix;
        let Some(Component::Prefix(prefix)) = path.components().next() else {
            return Err(ObsidianPlanError::UnsupportedRootNamespace);
        };
        let Prefix::Disk(letter) = prefix.kind() else {
            return Err(ObsidianPlanError::UnsupportedRootNamespace);
        };
        let drive_root = PathBuf::from(format!("{}:\\", char::from(letter)));
        Dir::open_ambient_dir(drive_root, cap_std::ambient_authority()).map_err(map_io)?
    };
    #[cfg(not(any(unix, windows)))]
    return Err(ObsidianPlanError::UnsupportedPlatform);

    let mut fences = Vec::new();
    let mut normal_components = 0usize;
    for component in path.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        normal_components += 1;
        validate_text_component(
            name.to_str()
                .ok_or(ObsidianPlanError::NonUtf8PathComponent)?,
        )?;
        let observed = current.symlink_metadata(name).map_err(map_io)?;
        validate_real_directory_metadata(&observed)?;
        let expected_identity = physical_identity(&observed, PhysicalKind::Directory)?;
        let child = open_direct_child_directory(&current, name)?;
        let opened_identity = physical_identity(
            &child.dir_metadata().map_err(map_io)?,
            PhysicalKind::Directory,
        )?;
        if opened_identity != expected_identity {
            return Err(ObsidianPlanError::ChangedDuringPlanning);
        }
        fences.push(NamespaceFence {
            parent: current.try_clone().map_err(map_io)?,
            child_name: name.to_os_string(),
            expected_identity,
        });
        current = child;
    }
    if normal_components == 0 {
        return Err(ObsidianPlanError::FilesystemRootNotAllowed);
    }
    validate_namespace_fences(&fences)?;
    Ok((current, fences))
}

fn open_direct_child_directory(parent: &Dir, name: &OsStr) -> Result<Dir, ObsidianPlanError> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
            FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        options
            .access_mode(FILE_GENERIC_READ)
            // No FILE_SHARE_DELETE: the retained handle pins this ancestor.
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(not(any(unix, windows)))]
    return Err(ObsidianPlanError::UnsupportedPlatform);

    let file = parent.open_with(name, &options).map_err(map_io)?;
    let metadata = file.metadata().map_err(map_io)?;
    validate_real_directory_metadata(&metadata)?;
    Ok(Dir::from_std_file(file.into_std()))
}

fn validate_namespace_fences(fences: &[NamespaceFence]) -> Result<(), ObsidianPlanError> {
    for fence in fences {
        let metadata = fence
            .parent
            .symlink_metadata(&fence.child_name)
            .map_err(|_| ObsidianPlanError::ChangedDuringPlanning)?;
        if cap_metadata_is_link_like(&metadata)
            || physical_identity(&metadata, PhysicalKind::Directory)? != fence.expected_identity
        {
            return Err(ObsidianPlanError::ChangedDuringPlanning);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PhysicalKind {
    Directory,
    File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct PhysicalIdentity {
    device: u64,
    inode: u64,
    kind: PhysicalKind,
}

fn physical_identity(
    metadata: &Metadata,
    expected_kind: PhysicalKind,
) -> Result<PhysicalIdentity, ObsidianPlanError> {
    use cap_fs_ext::MetadataExt as _;
    let actual_kind = if metadata.is_dir() {
        PhysicalKind::Directory
    } else if metadata.is_file() {
        PhysicalKind::File
    } else {
        return Err(ObsidianPlanError::NonRegularFilesystemEntry);
    };
    if cap_metadata_is_link_like(metadata) || actual_kind != expected_kind {
        return Err(ObsidianPlanError::SymlinkOrReparsePoint);
    }
    let device = metadata.dev();
    let inode = metadata.ino();
    if inode == 0 {
        return Err(ObsidianPlanError::StableIdentityUnavailable);
    }
    Ok(PhysicalIdentity {
        device,
        inode,
        kind: actual_kind,
    })
}

fn cap_metadata_is_link_like(metadata: &Metadata) -> bool {
    if metadata.is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use cap_std::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn validate_real_directory_metadata(metadata: &Metadata) -> Result<(), ObsidianPlanError> {
    if cap_metadata_is_link_like(metadata) {
        return Err(ObsidianPlanError::SymlinkOrReparsePoint);
    }
    if !metadata.is_dir() {
        return Err(ObsidianPlanError::RootNotDirectory);
    }
    Ok(())
}

fn validate_real_file_metadata(metadata: &Metadata) -> Result<(), ObsidianPlanError> {
    if cap_metadata_is_link_like(metadata) {
        return Err(ObsidianPlanError::SymlinkOrReparsePoint);
    }
    if !metadata.is_file() {
        return Err(ObsidianPlanError::NonRegularFilesystemEntry);
    }
    Ok(())
}

fn admit_obsidian_configuration(
    configuration: &ConnectorConfiguration,
) -> Result<(), ObsidianPlanError> {
    if configuration.connector_id != ConnectorId::Obsidian {
        return Err(ObsidianPlanError::AdmissionDenied);
    }
    admit_entry_point(configuration, ConnectorEntryPoint::ContextImport)
        .map_err(|_| ObsidianPlanError::AdmissionDenied)
}

fn validate_policy_vault_id(value: &str) -> Result<(), ObsidianPlanError> {
    let bytes = value.as_bytes();
    let alphanumeric = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    if bytes.is_empty()
        || bytes.len() > MAX_POLICY_VAULT_ID_LEN
        || !alphanumeric(bytes[0])
        || !alphanumeric(bytes[bytes.len() - 1])
        || !bytes
            .iter()
            .copied()
            .all(|byte| alphanumeric(byte) || matches!(byte, b'_' | b'-'))
    {
        return Err(ObsidianPlanError::InvalidPolicyVaultId);
    }
    Ok(())
}

fn validate_root_path_form(path: &Path) -> Result<(), ObsidianPlanError> {
    if !path.is_absolute() {
        return Err(ObsidianPlanError::RootNotAbsolute);
    }
    #[cfg(unix)]
    if path.components().any(|component| {
        matches!(
            component,
            Component::Prefix(_) | Component::CurDir | Component::ParentDir
        )
    }) {
        return Err(ObsidianPlanError::UnsupportedRootNamespace);
    }
    #[cfg(windows)]
    {
        use std::path::Prefix;
        let mut components = path.components();
        let Some(Component::Prefix(prefix)) = components.next() else {
            return Err(ObsidianPlanError::UnsupportedRootNamespace);
        };
        // UNC, DeviceNS, VerbatimDisk, and VerbatimUNC all fail closed.
        if !matches!(prefix.kind(), Prefix::Disk(_))
            || !matches!(components.next(), Some(Component::RootDir))
            || components.any(|component| {
                matches!(
                    component,
                    Component::CurDir | Component::ParentDir | Component::Prefix(_)
                )
            })
        {
            return Err(ObsidianPlanError::UnsupportedRootNamespace);
        }
    }
    #[cfg(not(any(unix, windows)))]
    return Err(ObsidianPlanError::UnsupportedPlatform);
    Ok(())
}

fn validate_text_component(value: &str) -> Result<(), ObsidianPlanError> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.chars().any(char::is_control)
        || value.chars().any(|character| {
            matches!(
                character,
                '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
            )
        })
        || value.ends_with(' ')
        || value.ends_with('.')
    {
        return Err(ObsidianPlanError::InvalidPathComponent);
    }
    let folded_stem = portable_collision_key(value.split('.').next().unwrap_or(value));
    if matches!(folded_stem.as_str(), "con" | "prn" | "aux" | "nul")
        || folded_stem.strip_prefix("com").is_some_and(|suffix| {
            matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        })
        || folded_stem.strip_prefix("lpt").is_some_and(|suffix| {
            matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        })
    {
        return Err(ObsidianPlanError::InvalidPathComponent);
    }
    Ok(())
}

/// Conservative portable caseless key. NFKC handles compatibility aliases;
/// upper-then-lower expansion handles multi-scalar folds such as `ß`/`SS`
/// instead of relying on `to_lowercase` alone.
fn portable_collision_key(value: &str) -> String {
    value
        .nfkc()
        .flat_map(char::to_uppercase)
        .flat_map(char::to_lowercase)
        .nfkc()
        .collect()
}

fn is_excluded_entry(name: &str, metadata: &Metadata) -> bool {
    if name.starts_with('.') {
        return true;
    }
    #[cfg(windows)]
    {
        use cap_std::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
        metadata.file_attributes() & FILE_ATTRIBUTE_HIDDEN != 0
    }
    #[cfg(not(windows))]
    {
        let _ = metadata;
        false
    }
}

fn is_markdown_name(name: &str) -> bool {
    name.rsplit_once('.')
        .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("md"))
}

fn normalize_markdown(bytes: &[u8], max_bytes: usize) -> Result<String, ObsidianPlanError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ObsidianPlanError::InvalidUtf8)?;
    let mut line_normalized = String::with_capacity(text.len().min(max_bytes));
    let mut chars = text.chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '\0' => return Err(ObsidianPlanError::NulByte),
            '\r' => {
                if chars.next_if_eq(&'\n').is_none() {
                    return Err(ObsidianPlanError::InvalidLineEnding);
                }
                line_normalized.push('\n');
            }
            '\n' | '\t' => line_normalized.push(character),
            character if character.is_control() => {
                return Err(ObsidianPlanError::ForbiddenControl);
            }
            _ => line_normalized.push(character),
        }
    }
    let mut normalized = String::with_capacity(line_normalized.len().min(max_bytes));
    for character in line_normalized.nfc() {
        let next_len = normalized.len().checked_add(character.len_utf8()).ok_or(
            ObsidianPlanError::LimitExceeded(ObsidianLimit::NormalizedBytes),
        )?;
        if next_len > max_bytes {
            return Err(ObsidianPlanError::LimitExceeded(
                ObsidianLimit::NormalizedBytes,
            ));
        }
        normalized.push(character);
    }
    Ok(normalized)
}

struct ParsedFrontmatter {
    body_start: usize,
    managed: bool,
}

fn parse_frontmatter(text: &str) -> Result<ParsedFrontmatter, ObsidianPlanError> {
    if text == "---" {
        return Err(ObsidianPlanError::MalformedFrontmatter);
    }
    if !text.starts_with("---\n") {
        return Ok(ParsedFrontmatter {
            body_start: 0,
            managed: false,
        });
    }
    let mut offset = 4usize;
    let mut closing_start = None;
    let mut body_start = None;
    for line in text[4..].split_inclusive('\n') {
        if line.trim_end_matches('\n') == "---" {
            closing_start = Some(offset);
            body_start = Some(offset + line.len());
            break;
        }
        offset = offset
            .checked_add(line.len())
            .ok_or(ObsidianPlanError::MalformedFrontmatter)?;
    }
    let (closing_start, body_start) = closing_start
        .zip(body_start)
        .ok_or(ObsidianPlanError::MalformedFrontmatter)?;
    let yaml: YamlValue = serde_yaml::from_str(&text[4..closing_start])
        .map_err(|_| ObsidianPlanError::MalformedFrontmatter)?;
    let managed = match yaml {
        YamlValue::Null => false,
        YamlValue::Mapping(mapping) => match mapping.get(&YamlValue::String("source".to_owned())) {
            None => false,
            Some(YamlValue::String(source)) => {
                let source = source.trim().to_ascii_lowercase();
                source.starts_with("neoth-") || source.starts_with("openclaw-")
            }
            Some(_) => return Err(ObsidianPlanError::MalformedFrontmatter),
        },
        _ => return Err(ObsidianPlanError::MalformedFrontmatter),
    };
    Ok(ParsedFrontmatter {
        body_start,
        managed,
    })
}

fn source_id(key: &[u8], vault_id: ObsidianVaultId, relative_path: &[u8]) -> String {
    let digest = domain_hmac(
        key,
        SOURCE_ID_DOMAIN,
        &[vault_id.0.as_slice(), relative_path],
    );
    format!("obsidian:source:hmac-sha256:{}", hex::encode(digest))
}

fn domain_hmac(key: &[u8], domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts every key length");
    mac.update(domain);
    for field in fields {
        mac.update(&(field.len() as u64).to_be_bytes());
        mac.update(field);
    }
    let bytes = mac.finalize().into_bytes();
    let mut output = [0u8; 32];
    output.copy_from_slice(&bytes);
    output
}

fn map_io(error: io::Error) -> ObsidianPlanError {
    ObsidianPlanError::Io(error.kind())
}

#[cfg(test)]
thread_local! {
    static AFTER_CHILD_DIRECTORY_OPEN: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    static AFTER_FILE_OPEN: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    static BETWEEN_FILE_READS: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn set_after_child_directory_open_for_test(hook: impl FnOnce() + 'static) {
    AFTER_CHILD_DIRECTORY_OPEN.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_after_child_directory_open_for_test() {
    AFTER_CHILD_DIRECTORY_OPEN.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_after_child_directory_open_for_test() {}

#[cfg(test)]
fn set_after_file_open_for_test(hook: impl FnOnce() + 'static) {
    AFTER_FILE_OPEN.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_after_file_open_for_test() {
    AFTER_FILE_OPEN.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_after_file_open_for_test() {}

#[cfg(test)]
fn set_between_file_reads_for_test(hook: impl FnOnce() + 'static) {
    BETWEEN_FILE_READS.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_between_file_reads_for_test() {
    BETWEEN_FILE_READS.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_between_file_reads_for_test() {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ObsidianLimit {
    Entries,
    Files,
    PerFileBytes,
    TotalBytes,
    NormalizedBytes,
    RetainedBytes,
    Depth,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ObsidianPlanError {
    #[error("the connector configuration is not admitted for Obsidian context import")]
    AdmissionDenied,
    #[error("the root grant no longer matches the admitted policy snapshot")]
    GrantBindingMismatch,
    #[error("the queued Obsidian capability no longer has live policy authority")]
    AuthorityNoLongerLive,
    #[error("the policy-owned vault id is not canonical")]
    InvalidPolicyVaultId,
    #[error("the vault identity key is invalid")]
    InvalidIdentityKey,
    #[error("the selected vault root must be absolute")]
    RootNotAbsolute,
    #[error("the selected vault root uses an unsupported namespace")]
    UnsupportedRootNamespace,
    #[error("a filesystem root cannot be selected as an Obsidian vault")]
    FilesystemRootNotAllowed,
    #[error("the selected root is not a normal directory")]
    RootNotDirectory,
    #[error("the import limits are invalid or exceed a hard safety ceiling")]
    InvalidLimits,
    #[error("the import limits exceed the admitted connector policy")]
    PolicyLimitExceeded,
    #[error("a filesystem entry is a symlink, junction, or reparse point")]
    SymlinkOrReparsePoint,
    #[error("the vault contains a cycle or duplicate physical object")]
    DirectoryCycleOrAmbiguity,
    #[error("the vault contains a portable normalized-name collision")]
    PortableNameCollision,
    #[error("the vault contains a non-regular filesystem entry")]
    NonRegularFilesystemEntry,
    #[error("a source path component is not valid UTF-8")]
    NonUtf8PathComponent,
    #[error("a source path component is not portable or contains forbidden characters")]
    InvalidPathComponent,
    #[error("the filesystem cannot provide a stable object identity")]
    StableIdentityUnavailable,
    #[error("a Markdown source is not valid UTF-8")]
    InvalidUtf8,
    #[error("a Markdown source contains a NUL byte")]
    NulByte,
    #[error("a Markdown source contains a forbidden control character")]
    ForbiddenControl,
    #[error("a Markdown source contains a lone carriage return")]
    InvalidLineEnding,
    #[error("a Markdown source has malformed or ambiguous YAML frontmatter")]
    MalformedFrontmatter,
    #[error("a source or ancestor changed while the plan was being built")]
    ChangedDuringPlanning,
    #[error("a planning resource limit was exceeded: {0:?}")]
    LimitExceeded(ObsidianLimit),
    #[error("filesystem access failed ({0:?})")]
    Io(io::ErrorKind),
    #[error("capability-bound traversal is unsupported on this platform")]
    UnsupportedPlatform,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::{ConnectorPolicySnapshot, SubjectId};

    const TEST_KEY: [u8; 32] = [0x42; 32];

    thread_local! {
        // The production control plane owns authorities. Existing planner tests
        // need the same lifetime without granting ownership to a capability.
        static TEST_LIVE_AUTHORITIES: RefCell<Vec<ObsidianPolicyAuthority>> =
            const { RefCell::new(Vec::new()) };
    }

    fn test_tempdir() -> tempfile::TempDir {
        crate::test_env::canonical_tempdir().expect("create canonical test directory")
    }

    fn configuration() -> ConnectorConfiguration {
        ConnectorConfiguration {
            connector_id: ConnectorId::Obsidian,
            account_id: None,
            subject_id: SubjectId::new("operator").unwrap(),
            credential_ref: None,
            policy: ConnectorPolicySnapshot::local_read_only(7),
        }
    }

    fn issue(
        configuration: &ConnectorConfiguration,
        path: &Path,
    ) -> (ObsidianPolicyAuthority, ApprovedObsidianVault) {
        let authority = ObsidianPolicyAuthority::for_admitted_configuration(configuration).unwrap();
        let grant = authority
            .issue_root_grant(configuration, path.to_path_buf(), "primary-vault", TEST_KEY)
            .unwrap();
        let vault = ApprovedObsidianVault::issue(configuration, grant).unwrap();
        (authority, vault)
    }

    fn approved(path: &Path) -> ApprovedObsidianVault {
        let config = configuration();
        let (authority, vault) = issue(&config, path);
        TEST_LIVE_AUTHORITIES.with(|authorities| authorities.borrow_mut().push(authority));
        vault
    }

    #[test]
    fn queued_vault_requires_live_authority_before_first_planning_io() {
        let vault_root = test_tempdir();
        std::fs::write(vault_root.path().join("note.md"), "operator material").unwrap();
        let config = configuration();

        let (authority, vault) = issue(&config, vault_root.path());
        authority.revoke();
        assert_eq!(
            plan_import(vault, ObsidianImportLimits::default()),
            Err(ObsidianPlanError::AuthorityNoLongerLive)
        );

        let (authority, vault) = issue(&config, vault_root.path());
        authority.advance_generation();
        assert_eq!(
            plan_import(vault, ObsidianImportLimits::default()),
            Err(ObsidianPlanError::AuthorityNoLongerLive)
        );

        let dropped_owner_vault = {
            let (_authority, vault) = issue(&config, vault_root.path());
            vault
        };
        assert_eq!(
            plan_import(dropped_owner_vault, ObsidianImportLimits::default()),
            Err(ObsidianPlanError::AuthorityNoLongerLive)
        );

        let (_authority, fresh_vault) = issue(&config, vault_root.path());
        assert!(plan_import(fresh_vault, ObsidianImportLimits::default()).is_ok());
    }

    #[test]
    fn revoked_root_grant_is_rejected_before_vault_capability_open() {
        let vault_root = test_tempdir();
        let config = configuration();
        let authority = ObsidianPolicyAuthority::for_admitted_configuration(&config).unwrap();
        let grant = authority
            .issue_root_grant(
                &config,
                vault_root.path().to_path_buf(),
                "primary-vault",
                TEST_KEY,
            )
            .unwrap();

        authority.revoke();
        assert_eq!(
            ApprovedObsidianVault::issue(&config, grant).unwrap_err(),
            ObsidianPlanError::AuthorityNoLongerLive
        );
    }

    #[test]
    fn planner_is_deterministic_bounded_and_redacted() {
        let vault = test_tempdir();
        std::fs::create_dir(vault.path().join("notes")).unwrap();
        std::fs::create_dir(vault.path().join(".obsidian")).unwrap();
        std::fs::write(vault.path().join("notes").join("z.md"), "zeta\r\n").unwrap();
        std::fs::write(vault.path().join("a.md"), "alpha\n").unwrap();
        std::fs::write(vault.path().join(".hidden.md"), "hidden").unwrap();
        std::fs::write(vault.path().join(".obsidian").join("state.md"), "internal").unwrap();

        let first = plan_import(approved(vault.path()), ObsidianImportLimits::default()).unwrap();
        let second = plan_import(approved(vault.path()), ObsidianImportLimits::default()).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.status().draft_count, 2);
        assert_eq!(
            first
                .drafts()
                .iter()
                .map(ObsidianImportDraft::body)
                .collect::<Vec<_>>(),
            vec!["alpha\n", "zeta\n"]
        );
        let debug = format!("{first:?}");
        assert!(!debug.contains("alpha"));
        assert!(!debug.contains("zeta"));
    }

    #[test]
    fn managed_yaml_is_parsed_and_malformed_yaml_fails_closed() {
        let vault = test_tempdir();
        std::fs::write(
            vault.path().join("neoth.md"),
            "---\nsource: \"neoth-groundtruth\" # managed\n---\nignored",
        )
        .unwrap();
        std::fs::write(
            vault.path().join("openclaw.md"),
            "---\nsource: 'openclaw-import'\n---\nignored",
        )
        .unwrap();
        std::fs::write(
            vault.path().join("operator.md"),
            "---\nsource: personal\n---\noperator material",
        )
        .unwrap();
        let plan = plan_import(approved(vault.path()), ObsidianImportLimits::default()).unwrap();
        assert_eq!(plan.status().draft_count, 1);
        assert_eq!(plan.drafts()[0].body(), "operator material");

        let malformed = test_tempdir();
        std::fs::write(
            malformed.path().join("bad.md"),
            "---\nsource: [unterminated\n---\nbody",
        )
        .unwrap();
        assert_eq!(
            plan_import(approved(malformed.path()), ObsidianImportLimits::default()),
            Err(ObsidianPlanError::MalformedFrontmatter)
        );
    }

    #[test]
    fn all_entries_are_capped_before_non_markdown_material_is_retained() {
        let vault = test_tempdir();
        for name in ["one.txt", "two.txt", "three.txt"] {
            std::fs::write(vault.path().join(name), "ignored").unwrap();
        }
        let limits = ObsidianImportLimits {
            max_entries: 2,
            max_files: 1,
            ..ObsidianImportLimits::default()
        };
        assert_eq!(
            plan_import(approved(vault.path()), limits),
            Err(ObsidianPlanError::LimitExceeded(ObsidianLimit::Entries))
        );
    }

    #[test]
    fn normalization_expansion_and_retained_output_have_independent_caps() {
        let expanding = test_tempdir();
        std::fs::write(expanding.path().join("expand.md"), "\u{0344}").unwrap();
        let normalized_limits = ObsidianImportLimits {
            max_file_bytes: 8,
            max_total_bytes: 8,
            max_normalized_file_bytes: 2,
            max_retained_bytes: 8,
            ..ObsidianImportLimits::default()
        };
        assert_eq!(
            plan_import(approved(expanding.path()), normalized_limits),
            Err(ObsidianPlanError::LimitExceeded(
                ObsidianLimit::NormalizedBytes
            ))
        );

        let retained = test_tempdir();
        std::fs::write(retained.path().join("body.md"), "abcd").unwrap();
        let retained_limits = ObsidianImportLimits {
            max_file_bytes: 8,
            max_total_bytes: 8,
            max_normalized_file_bytes: 8,
            max_retained_bytes: 3,
            ..ObsidianImportLimits::default()
        };
        assert_eq!(
            plan_import(approved(retained.path()), retained_limits),
            Err(ObsidianPlanError::LimitExceeded(
                ObsidianLimit::RetainedBytes
            ))
        );

        let policy_bound = test_tempdir();
        let normalized_over_policy = ObsidianImportLimits {
            max_total_normalized_bytes: ResourceLimits::LOCAL_DEFAULT.max_total_bytes_per_run
                as usize
                + 1,
            ..ObsidianImportLimits::default()
        };
        assert_eq!(
            plan_import(approved(policy_bound.path()), normalized_over_policy),
            Err(ObsidianPlanError::PolicyLimitExceeded)
        );

        let per_item_bound = test_tempdir();
        let mut narrow_configuration = configuration();
        narrow_configuration.policy.limits.max_bytes_per_item = 1024;
        let narrow_authority =
            ObsidianPolicyAuthority::for_admitted_configuration(&narrow_configuration).unwrap();
        let grant = narrow_authority
            .issue_root_grant(
                &narrow_configuration,
                per_item_bound.path().to_path_buf(),
                "primary-vault",
                TEST_KEY,
            )
            .unwrap();
        let narrow_vault = ApprovedObsidianVault::issue(&narrow_configuration, grant).unwrap();
        let normalized_item_over_policy = ObsidianImportLimits {
            max_file_bytes: 1024,
            max_normalized_file_bytes: 1025,
            ..ObsidianImportLimits::default()
        };
        assert_eq!(
            plan_import(narrow_vault, normalized_item_over_policy),
            Err(ObsidianPlanError::PolicyLimitExceeded)
        );
    }

    #[test]
    fn ids_are_policy_stable_and_do_not_digest_absolute_paths() {
        let first_root = test_tempdir();
        let second_root = test_tempdir();
        for root in [first_root.path(), second_root.path()] {
            std::fs::create_dir(root.join("folder")).unwrap();
            std::fs::write(root.join("folder").join("note.md"), "same").unwrap();
        }
        let first_vault = approved(first_root.path());
        let second_vault = approved(second_root.path());
        assert_eq!(first_vault.vault_id(), second_vault.vault_id());
        let first = plan_import(first_vault, ObsidianImportLimits::default()).unwrap();
        let second = plan_import(second_vault, ObsidianImportLimits::default()).unwrap();
        assert_eq!(
            first.drafts()[0].source_id(),
            second.drafts()[0].source_id()
        );
        assert_eq!(
            first.drafts()[0].source_revision_hmac_sha256(),
            second.drafts()[0].source_revision_hmac_sha256()
        );
    }

    #[test]
    fn changed_content_keeps_source_identity_and_changes_revision() {
        let root = test_tempdir();
        let note = root.path().join("note.md");
        std::fs::write(&note, "first\r\n").unwrap();
        let first = plan_import(approved(root.path()), ObsidianImportLimits::default()).unwrap();
        std::fs::write(&note, "second\n").unwrap();
        let second = plan_import(approved(root.path()), ObsidianImportLimits::default()).unwrap();
        assert_eq!(
            first.drafts()[0].source_id(),
            second.drafts()[0].source_id()
        );
        assert_ne!(
            first.drafts()[0].source_revision_hmac_sha256(),
            second.drafts()[0].source_revision_hmac_sha256()
        );
        assert_eq!(second.drafts()[0].body(), "second\n");
    }

    #[test]
    fn portable_collision_key_handles_compatibility_and_expanding_folds() {
        assert_eq!(
            portable_collision_key("straße.md"),
            portable_collision_key("STRASSE.md")
        );
        assert_eq!(
            portable_collision_key("K.md"),
            portable_collision_key("K.md")
        );
        assert!(validate_text_component("CON.txt").is_err());
        assert!(validate_text_component("trailing. ").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_intermediate_links_and_same_size_file_replacement() {
        use std::os::unix::fs::symlink;

        let linked = test_tempdir();
        let outside = test_tempdir();
        std::fs::write(outside.path().join("outside.md"), "outside").unwrap();
        symlink(outside.path(), linked.path().join("linked")).unwrap();
        assert_eq!(
            plan_import(approved(linked.path()), ObsidianImportLimits::default()),
            Err(ObsidianPlanError::SymlinkOrReparsePoint)
        );

        let replaced = test_tempdir();
        let note = replaced.path().join("note.md");
        let parked = replaced.path().join("parked.md");
        std::fs::write(&note, "first").unwrap();
        set_after_file_open_for_test({
            let note = note.clone();
            move || {
                std::fs::rename(&note, &parked).unwrap();
                std::fs::write(&note, "other").unwrap();
            }
        });
        assert_eq!(
            plan_import(approved(replaced.path()), ObsidianImportLimits::default()),
            Err(ObsidianPlanError::ChangedDuringPlanning)
        );

        let mutated = test_tempdir();
        let mutated_note = mutated.path().join("note.md");
        std::fs::write(&mutated_note, "first").unwrap();
        let mutated_vault = approved(mutated.path());
        set_between_file_reads_for_test({
            let mutated_note = mutated_note.clone();
            move || std::fs::write(&mutated_note, "other").unwrap()
        });
        assert_eq!(
            plan_import(mutated_vault, ObsidianImportLimits::default()),
            Err(ObsidianPlanError::ChangedDuringPlanning)
        );
    }

    #[cfg(unix)]
    #[test]
    fn growth_after_metadata_cannot_escape_the_two_read_budget() {
        let vault = test_tempdir();
        let note = vault.path().join("note.md");
        std::fs::write(&note, "first").unwrap();
        let approved = approved(vault.path());
        set_after_file_open_for_test({
            let note = note.clone();
            move || std::fs::write(&note, "first-grow").unwrap()
        });
        let exact_remaining_budget = ObsidianImportLimits {
            max_file_bytes: 8,
            max_total_bytes: 10,
            ..ObsidianImportLimits::default()
        };
        assert_eq!(
            plan_import(approved, exact_remaining_budget),
            Err(ObsidianPlanError::ChangedDuringPlanning)
        );
    }

    #[cfg(unix)]
    #[test]
    fn detects_an_intermediate_directory_namespace_swap() {
        let vault = test_tempdir();
        let child = vault.path().join("child");
        let parked = vault.path().join("parked");
        std::fs::create_dir(&child).unwrap();
        std::fs::write(child.join("note.md"), "original").unwrap();
        set_after_child_directory_open_for_test({
            let child = child.clone();
            move || {
                std::fs::rename(&child, &parked).unwrap();
                std::fs::create_dir(&child).unwrap();
                std::fs::write(child.join("note.md"), "replacement").unwrap();
            }
        });
        assert_eq!(
            plan_import(approved(vault.path()), ObsidianImportLimits::default()),
            Err(ObsidianPlanError::ChangedDuringPlanning)
        );
    }

    #[cfg(windows)]
    #[test]
    fn rejects_unc_device_and_verbatim_namespaces_before_open() {
        let config = configuration();
        let authority = ObsidianPolicyAuthority::for_admitted_configuration(&config).unwrap();
        for root in [
            r"\\server\share\vault",
            r"\\?\UNC\server\share\vault",
            r"\\?\C:\vault",
            r"\\.\C:\vault",
        ] {
            assert_eq!(
                authority
                    .issue_root_grant(&config, PathBuf::from(root), "primary-vault", TEST_KEY,)
                    .unwrap_err(),
                ObsidianPlanError::UnsupportedRootNamespace
            );
        }
    }
}
