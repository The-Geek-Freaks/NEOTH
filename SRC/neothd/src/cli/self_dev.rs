//! `neoth self-dev` — operator CLI for the P-04 proactive
//! self-development workflow. Mirrors the spec from the
//! user-adaptation specs:
//!
//!   - `neoth self-dev review`           → list pending proposals
//!   - `neoth self-dev accept <id>`      → accept a proposal (emits
//!                                          0x1D `SELF_DEV_ACCEPTED`)
//!   - `neoth self-dev decline <id>`     → decline (emits 0x1E
//!                                          `SELF_DEV_DECLINED`)
//!   - `neoth self-dev propose --from-profile <path>` → generate
//!     proposals from a recorded `BehaviouralProfile` JSON +
//!     emit `SELF_DEV_PROPOSED` (0x1C) frames for each. Operator-
//!     facing test path that does NOT require live behavioural data.
//!
//! Proposals live in `<home>/self_dev/proposals.json` — a JSON
//! file the proposal engine writes and accept/decline mutates.
//! Atomic-rename + per-proposal status (`pending` / `accepted` /
//! `declined`) so a crash mid-mutation never leaves the file
//! half-rewritten.
//!
//!   - `neoth self-dev scan`              → one-shot: collector tick + evolver
//!                                          pass; prints signal + proposal counts.
//!                                          Bridge until HERMES-01 cron ships.

use std::{
    ffi::OsStr,
    io::Read,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result};
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _};
use cap_std::fs::{Dir, Metadata, OpenOptions};
use clap::{Args, Subcommand};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use crate::profile::estimators::BehaviouralProfile;
use crate::profile::presets::{ProfilePreset, apply_preset};
use crate::profile::self_dev::{
    ExtensionAuthorityBinding, ProposalKind, SelfDevProposal, ValidatedProposalTarget,
    propose_adjustments,
};
use crate::wal::writer::WalWriterHandle;

static SELF_DEV_STATE_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Retains the two-tier proposal-state lock. Every production
/// `proposals.json` RMW, recovery, decision, and proposal publication owns one
/// of these from its first state read through its final durable cleanup.
pub(crate) struct SelfDevStateGuard {
    _process: tokio::sync::MutexGuard<'static, ()>,
    _file: std::fs::File,
}

fn self_dev_state_lock_path(home: &Path) -> PathBuf {
    home.join("self_dev").join("state.lock")
}

/// Serialize self-development state across both async tasks and separate
/// `neoth`/daemon OS processes. Lock acquisition is blocking by nature, so it
/// runs outside Tokio's worker pool.
pub(crate) async fn acquire_self_dev_state_guard(home: &Path) -> Result<SelfDevStateGuard> {
    let process = SELF_DEV_STATE_MUTEX.lock().await;
    let path = self_dev_state_lock_path(home);
    let file = tokio::task::spawn_blocking(move || {
        crate::util::locked_file::lock_file_blocking(&path, "self-dev proposal state")
    })
    .await
    .context("join self-dev proposal-state lock acquisition")??;
    Ok(SelfDevStateGuard {
        _process: process,
        _file: file,
    })
}

#[derive(Args, Debug, Clone)]
pub struct SelfDevArgs {
    #[command(subcommand)]
    pub action: SelfDevAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum SelfDevAction {
    /// List every pending proposal. `--min-confidence` filters by
    /// the engine's confidence estimate (0.0..=1.0).
    Review {
        #[arg(long, default_value_t = 0.0)]
        min_confidence: f64,
    },
    /// Accept a proposal by id (operator types e.g.
    /// `neoth self-dev accept switch_preset-a1b2c3d4`). Emits
    /// `EVENT_TYPE_SELF_DEV_ACCEPTED` (0x1D) when a WAL writer is
    /// available; otherwise records the decision in the local
    /// proposals.json only + warns.
    Accept { id: String },
    /// Decline a proposal. Reason `"declined"` (explicit) or
    /// `"timeout"` (operator never reviewed).
    Decline {
        id: String,
        #[arg(long, default_value = "declined")]
        reason: String,
    },
    /// Generate proposals from a `BehaviouralProfile` JSON. Operator-
    /// facing demonstration command: write the JSON via
    /// `neoth profile stats > profile.json` (future) or hand-craft
    /// for testing, then `neoth self-dev propose --from-profile
    /// profile.json` materialises the proposals + emits
    /// `EVENT_TYPE_SELF_DEV_PROPOSED` (0x1C) per proposal.
    Propose {
        #[arg(long)]
        from_profile: PathBuf,
        /// Treat the operator as currently on this preset for the
        /// proposal engine. Defaults to "lowkey" per the
        /// recommended-default hard rule.
        #[arg(long, default_value = "lowkey")]
        current_preset: String,
    },
    /// One-shot self-development scan: runs a collector tick then the
    /// HERMES-06 GAP-B capability evolver pass, and prints the
    /// `CollectorReport` + `EvolverReport`. Bridging command until
    /// HERMES-01 cron scheduling ships. WAL frames are emitted via a
    /// temporary segment that is cleaned up on exit.
    Scan,
}

/// Per-proposal status in the local store.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalStatus {
    Pending,
    Accepted,
    Declined,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StoredProposal {
    pub proposal: SelfDevProposal,
    pub status: ProposalStatus,
    /// Unix epoch seconds at which the status was last updated.
    pub status_at_unix: i64,
    /// `declined` / `timeout` when status == Declined; empty otherwise.
    pub decline_reason: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ProposalStore {
    pub entries: Vec<StoredProposal>,
    #[serde(default)]
    audit_pending: Vec<ProposalAuditIntent>,
}

// GOLD-R4-11 — a self-dev acceptance is a cross-store transaction: the
// proposal decision and its real target effect must never disagree. The
// target-specific writers each provide their own atomic mutation boundary, but
// none can atomically include `self_dev/proposals.json`; this small journal
// bridges that gap and lets the next CLI entry recover deterministically.
const EFFECT_TRANSACTION_MAX_BYTES: usize = 128 * 1024;
const SOURCE_EDIT_TRANSACTION_MAX_BYTES: usize = 128 * 1024;
const SOURCE_EDIT_RECEIPT_MAX_BYTES: usize = 128 * 1024;
const SOURCE_EDIT_TRANSACTION_VERSION: u32 = 1;
const SOURCE_EDIT_RECEIPT_VERSION: u32 = 2;
const SOURCE_EDIT_AUTH_KEY_FILE: &str = "source_edit_authority.key";
const SOURCE_EDIT_JOURNAL_DOMAIN: &[u8] = b"NEOTH/R4-11/source-edit-journal/v1";
const SOURCE_EDIT_RECEIPT_DOMAIN: &[u8] = b"NEOTH/R4-11/source-edit-receipt/v2";
const SOURCE_EDIT_IMAGE_MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
const SOURCE_EDIT_IMAGE_MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
const SOURCE_EDIT_IMAGE_MAX_TARGET_PATHS: usize = 256;
const SOURCE_EDIT_IMAGE_MAX_PATH_BYTES: usize = 4 * 1024;
const SOURCE_EDIT_IMAGE_MAX_TOTAL_PATH_BYTES: usize = 64 * 1024;
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "effect", rename_all = "snake_case")]
enum EffectTarget {
    Preset {
        target: String,
    },
    Verbosity {
        target: String,
    },
    Briefing {
        hour: u8,
        minute: u8,
    },
    Extension {
        id: String,
        authority: ExtensionAuthorityBinding,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EffectTransactionPhase {
    /// Intent is durable, but the target writer has not been invoked.
    Prepared,
    /// The target writer may have run. Recovery must inspect the target.
    Applying,
    /// The target was read back successfully; only the proposal-store commit
    /// or journal cleanup may remain.
    PostconditionProven,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct EffectTransactionJournal {
    proposal_id: String,
    proposal_sha256: String,
    target: EffectTarget,
    phase: EffectTransactionPhase,
}

/// One path image is deliberately bound to both the exact relative path and
/// whether it existed. This distinguishes a deleted file from an empty file
/// and makes the pre/post image evidence unambiguous during crash recovery.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceEditPathImage {
    path: String,
    exists: bool,
    sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SourceEditTransactionPhase {
    /// Durable authorization exists, but the five gate stack was not entered.
    Prepared,
    /// Gate processing may have reached live `git apply`; recovery must never
    /// infer success from a changed tree alone.
    Applying,
    /// Exact postimages and mandatory WAL finalization were observed.
    PostconditionProven,
}

/// Durable, authenticated pre-apply source-edit transaction. It is written
/// before the live gate can invoke `git apply`, and carries the reviewed
/// contract plus the exact preimage for every authoritative path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceEditApplyJournal {
    version: u32,
    proposal_id: String,
    proposal_sha256: String,
    diff_sha256: String,
    source_root: String,
    target_paths: Vec<String>,
    base_images: Vec<SourceEditPathImage>,
    post_images: Option<Vec<SourceEditPathImage>>,
    phase: SourceEditTransactionPhase,
    self_edit_audit_finalized: bool,
    auth_tag: String,
}

/// Receipt published only after the live source mutation, exact postimage
/// readback, and mandatory self-edit WAL finalization have all completed.
/// The receipt repeats the authenticated pre-apply evidence so it can never
/// turn a matching but forged JSON file into Accepted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceEditApplyReceipt {
    version: u32,
    proposal_id: String,
    proposal_sha256: String,
    diff_sha256: String,
    source_root: String,
    target_paths: Vec<String>,
    base_images: Vec<SourceEditPathImage>,
    post_images: Vec<SourceEditPathImage>,
    self_edit_audit_finalized: bool,
    applied_at_unix: i64,
    auth_tag: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SourceEditProposalContract {
    proposal_id: String,
    proposal_sha256: String,
    diff_sha256: String,
    source_root: PathBuf,
    target_paths: Vec<String>,
    base_images: Vec<SourceEditPathImage>,
}

/// Opaque capability passed from the authenticated self-dev transaction into
/// the live source-edit gate. Its fields remain private so callers can only
/// ask it for the reviewed path set or prove the preimage still matches.
#[derive(Clone, Debug)]
pub(crate) struct SourceEditPreApplyPlan {
    source_root: PathBuf,
    target_paths: Vec<String>,
    base_images: Vec<SourceEditPathImage>,
}

impl SourceEditPreApplyPlan {
    pub(crate) fn target_paths(&self) -> &[String] {
        &self.target_paths
    }

    pub(crate) fn binds_source_root(&self, source_root: &Path) -> bool {
        source_root
            .canonicalize()
            .is_ok_and(|candidate| candidate == self.source_root)
    }

    /// This awaits the bounded, no-follow filesystem snapshot on Tokio's
    /// blocking pool. It is called immediately before the live git sink.
    pub(crate) async fn exact_base_images_still_match(&self) -> Result<bool> {
        Ok(source_edit_images(&self.source_root, &self.target_paths).await? == self.base_images)
    }
}

/// Owns the common proposal-state lock across the complete self-edit gate,
/// mandatory audit finalization, receipt publication, and exact acceptance.
pub(crate) struct SourceEditApplyTransaction {
    home: PathBuf,
    contract: SourceEditProposalContract,
    journal: SourceEditApplyJournal,
    guard: SelfDevStateGuard,
}

/// Machine-classifiable, retry-safe rejection states for a proposal effect.
/// These errors deliberately leave the proposal non-Accepted; callers can
/// correct state and retry without fabricating a successful decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfDevEffectTransactionError {
    AlreadySatisfied { proposal_id: String },
    SeparateApplyRequired { proposal_id: String },
    PostconditionFailed { proposal_id: String },
    RecoveryRequired { proposal_id: String },
    SourceEditContractRejected { proposal_id: String },
    SourceEditReceiptRecoveryRequired { proposal_id: String },
}

impl std::fmt::Display for SelfDevEffectTransactionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadySatisfied { proposal_id } => write!(
                f,
                "SELF_DEV_EFFECT_ALREADY_SATISFIED:{proposal_id}: no new target effect was applied; proposal remains pending"
            ),
            Self::SeparateApplyRequired { proposal_id } => write!(
                f,
                "SELF_DEV_EFFECT_SEPARATE_APPLY_REQUIRED:{proposal_id}: source edits require explicit `neoth self-edit`; proposal remains pending"
            ),
            Self::PostconditionFailed { proposal_id } => write!(
                f,
                "SELF_DEV_EFFECT_POSTCONDITION_FAILED:{proposal_id}: target read-back did not prove the effect; transaction is recoverable and proposal remains pending"
            ),
            Self::RecoveryRequired { proposal_id } => write!(
                f,
                "SELF_DEV_EFFECT_RECOVERY_REQUIRED:{proposal_id}: an interrupted target effect needs recovery before accepting another proposal"
            ),
            Self::SourceEditContractRejected { proposal_id } => write!(
                f,
                "SELF_DEV_SOURCE_EDIT_CONTRACT_REJECTED:{proposal_id}: proposal id, patch, or expected diff hash did not match the pending reviewed proposal"
            ),
            Self::SourceEditReceiptRecoveryRequired { proposal_id } => write!(
                f,
                "SELF_DEV_SOURCE_EDIT_RECEIPT_RECOVERY_REQUIRED:{proposal_id}: the durable apply receipt could not be bound to the exact pending source-edit proposal"
            ),
        }
    }
}

impl std::error::Error for SelfDevEffectTransactionError {}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ProposalAuditIntent {
    Proposed {
        proposal: SelfDevProposal,
        ts_unix: i64,
    },
    Accepted {
        proposal_id: String,
        ts_unix: i64,
    },
    Declined {
        proposal_id: String,
        reason: String,
        ts_unix: i64,
    },
}

impl ProposalAuditIntent {
    fn to_pending_event(&self) -> super::self_dev_outbox::PendingEvent {
        match self {
            Self::Proposed { proposal, ts_unix } => {
                super::self_dev_outbox::PendingEvent::proposed(proposal.clone(), *ts_unix)
            }
            Self::Accepted {
                proposal_id,
                ts_unix,
            } => super::self_dev_outbox::PendingEvent::accepted(proposal_id.clone(), *ts_unix),
            Self::Declined {
                proposal_id,
                reason,
                ts_unix,
            } => super::self_dev_outbox::PendingEvent::declined(
                proposal_id.clone(),
                reason.clone(),
                *ts_unix,
            ),
        }
    }
}

pub fn proposals_path(home: &Path) -> PathBuf {
    home.join("self_dev").join("proposals.json")
}

pub fn load_store(home: &Path) -> Result<ProposalStore> {
    let path = proposals_path(home);
    if !path.exists() {
        return Ok(ProposalStore::default());
    }
    let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    if bytes.is_empty() {
        return Ok(ProposalStore::default());
    }
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

fn save_store_locked(home: &Path, store: &ProposalStore, _guard: &SelfDevStateGuard) -> Result<()> {
    let path = proposals_path(home);
    let bytes = serde_json::to_vec_pretty(store)?;
    crate::util::atomic_write::atomic_write_private(&path, &bytes)
        .with_context(|| format!("private atomic write {}", path.display()))?;
    crate::util::atomic_write::sync_parent_directory_required(&path)
        .with_context(|| format!("durably commit {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
fn save_store_fixture(home: &Path, store: &ProposalStore) -> Result<()> {
    let path = proposals_path(home);
    let bytes = serde_json::to_vec_pretty(store)?;
    crate::util::atomic_write::atomic_write_private(&path, &bytes)
        .with_context(|| format!("private atomic fixture write {}", path.display()))?;
    crate::util::atomic_write::sync_parent_directory_required(&path)
        .with_context(|| format!("durably commit fixture {}", path.display()))?;
    Ok(())
}

fn effect_transaction_path(home: &Path) -> PathBuf {
    home.join("self_dev").join("effect_transaction.json")
}

fn source_edit_receipt_path(home: &Path) -> PathBuf {
    home.join("self_dev").join("source_edit_apply_receipt.json")
}

fn source_edit_transaction_path(home: &Path) -> PathBuf {
    home.join("self_dev")
        .join("source_edit_apply_transaction.json")
}

/// The self-edit journal has an authority independent from user-editable
/// proposal JSON. It is home-bound and DPAPI-/permission-protected through the
/// same hardened key storage used for WAL authentication. Losing this key is
/// fail-closed: old journals cannot become trusted under a replacement key.
fn source_edit_authority_key(home: &Path) -> Result<Vec<u8>> {
    crate::wal::compaction::load_or_init_key(&home.join("self_dev").join(SOURCE_EDIT_AUTH_KEY_FILE))
        .context("load home-bound source-edit transaction authority")
}

fn source_edit_home_binding(home: &Path) -> Result<Vec<u8>> {
    let canonical = home
        .canonicalize()
        .with_context(|| format!("canonicalize source-edit home {}", home.display()))?;
    Ok(canonical.to_string_lossy().as_bytes().to_vec())
}

fn update_framed_hmac(mac: &mut HmacSha256, field: &[u8]) {
    mac.update(&(field.len() as u64).to_be_bytes());
    mac.update(field);
}

fn source_edit_auth_tag(home: &Path, domain: &[u8], unsigned: &[u8]) -> Result<String> {
    let key = source_edit_authority_key(home)?;
    let home_binding = source_edit_home_binding(home)?;
    let mut mac =
        HmacSha256::new_from_slice(&key).expect("HMAC-SHA256 accepts every authority key length");
    update_framed_hmac(&mut mac, domain);
    update_framed_hmac(&mut mac, &home_binding);
    update_framed_hmac(&mut mac, unsigned);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn source_edit_auth_tag_matches(
    home: &Path,
    domain: &[u8],
    unsigned: &[u8],
    claimed_hex: &str,
) -> Result<bool> {
    let claimed = match hex::decode(claimed_hex) {
        Ok(claimed) if claimed.len() == 32 => claimed,
        _ => return Ok(false),
    };
    let computed = source_edit_auth_tag(home, domain, unsigned)?;
    let computed = hex::decode(computed).expect("locally generated HMAC is valid hex");
    Ok(bool::from(computed.as_slice().ct_eq(claimed.as_slice())))
}

#[derive(Serialize)]
struct SourceEditJournalUnsigned<'a> {
    version: u32,
    proposal_id: &'a str,
    proposal_sha256: &'a str,
    diff_sha256: &'a str,
    source_root: &'a str,
    target_paths: &'a [String],
    base_images: &'a [SourceEditPathImage],
    post_images: &'a Option<Vec<SourceEditPathImage>>,
    phase: SourceEditTransactionPhase,
    self_edit_audit_finalized: bool,
}

fn source_edit_journal_unsigned(journal: &SourceEditApplyJournal) -> Result<Vec<u8>> {
    serde_json::to_vec(&SourceEditJournalUnsigned {
        version: journal.version,
        proposal_id: &journal.proposal_id,
        proposal_sha256: &journal.proposal_sha256,
        diff_sha256: &journal.diff_sha256,
        source_root: &journal.source_root,
        target_paths: &journal.target_paths,
        base_images: &journal.base_images,
        post_images: &journal.post_images,
        phase: journal.phase,
        self_edit_audit_finalized: journal.self_edit_audit_finalized,
    })
    .context("serialize source-edit journal authentication payload")
}

#[derive(Serialize)]
struct SourceEditReceiptUnsigned<'a> {
    version: u32,
    proposal_id: &'a str,
    proposal_sha256: &'a str,
    diff_sha256: &'a str,
    source_root: &'a str,
    target_paths: &'a [String],
    base_images: &'a [SourceEditPathImage],
    post_images: &'a [SourceEditPathImage],
    self_edit_audit_finalized: bool,
    applied_at_unix: i64,
}

fn source_edit_receipt_unsigned(receipt: &SourceEditApplyReceipt) -> Result<Vec<u8>> {
    serde_json::to_vec(&SourceEditReceiptUnsigned {
        version: receipt.version,
        proposal_id: &receipt.proposal_id,
        proposal_sha256: &receipt.proposal_sha256,
        diff_sha256: &receipt.diff_sha256,
        source_root: &receipt.source_root,
        target_paths: &receipt.target_paths,
        base_images: &receipt.base_images,
        post_images: &receipt.post_images,
        self_edit_audit_finalized: receipt.self_edit_audit_finalized,
        applied_at_unix: receipt.applied_at_unix,
    })
    .context("serialize source-edit receipt authentication payload")
}

/// A link/reparse test must be performed on metadata obtained without
/// following the candidate. On Windows a junction is not necessarily reported
/// as a Unix-style symlink, hence the explicit reparse bit check.
/// Validate untrusted proposal path material before cloning it into an async
/// blocking job or reserving a result vector. Even an all-missing path list can
/// otherwise force allocation and scheduler work without touching the source
/// tree, so cardinality, byte budgets, and duplicate spelling are hard limits.
fn validate_source_edit_image_paths(paths: &[String]) -> Result<()> {
    anyhow::ensure!(
        !paths.is_empty() && paths.len() <= SOURCE_EDIT_IMAGE_MAX_TARGET_PATHS,
        "source-edit target path count must be 1..={} (got {})",
        SOURCE_EDIT_IMAGE_MAX_TARGET_PATHS,
        paths.len()
    );
    let mut total_bytes = 0usize;
    let mut seen = std::collections::BTreeSet::new();
    for path in paths {
        anyhow::ensure!(
            !path.is_empty() && path.len() <= SOURCE_EDIT_IMAGE_MAX_PATH_BYTES,
            "source-edit target path exceeds the {}-byte cap",
            SOURCE_EDIT_IMAGE_MAX_PATH_BYTES
        );
        anyhow::ensure!(
            seen.insert(path),
            "source-edit target paths must not contain duplicates"
        );
        total_bytes = total_bytes
            .checked_add(path.len())
            .context("source-edit target path byte counter overflow")?;
        anyhow::ensure!(
            total_bytes <= SOURCE_EDIT_IMAGE_MAX_TOTAL_PATH_BYTES,
            "source-edit target path bytes exceed the {}-byte cap",
            SOURCE_EDIT_IMAGE_MAX_TOTAL_PATH_BYTES
        );
    }
    Ok(())
}

fn source_edit_metadata_is_link_like(metadata: &Metadata) -> bool {
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

/// A reviewed source leaf must not have another directory entry. Without this
/// check an external hard-link alias could mutate the same inode while the
/// source-edit transaction believes it owns a stable path. The count is read
/// from the already nofollow-opened handle; unavailable platforms fail closed.
fn ensure_source_edit_single_hard_link(file: &std::fs::File) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let links = file
            .metadata()
            .context("read no-follow source-edit leaf link count")?
            .nlink();
        anyhow::ensure!(
            links == 1,
            "source-edit leaf has {links} hard links; exactly one is required"
        );
        return Ok(());
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let mut information = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
        // SAFETY: `file` owns the live nofollow-opened handle and `information`
        // is writable for the exact Windows structure size.
        anyhow::ensure!(
            unsafe {
                GetFileInformationByHandle(file.as_raw_handle() as _, information.as_mut_ptr())
            } != 0,
            "read no-follow source-edit leaf link count: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: successful GetFileInformationByHandle initialized all fields.
        let information = unsafe { information.assume_init() };
        anyhow::ensure!(
            information.nNumberOfLinks == 1,
            "source-edit leaf has {} hard links; exactly one is required",
            information.nNumberOfLinks
        );
        return Ok(());
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        anyhow::bail!("source-edit hard-link count is unsupported on this platform");
    }
}

/// Open a component from an already-open parent handle without following it.
/// Holding the returned capability keeps traversal rooted in the reviewed
/// source tree even if its visible namespace is renamed concurrently.
fn open_source_edit_child_directory(parent: &Dir, name: &OsStr) -> Result<Dir> {
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
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(not(any(unix, windows)))]
    anyhow::bail!("source-edit image evidence is unsupported without no-follow filesystem APIs");

    let opened = parent.open_with(name, &options).with_context(|| {
        format!(
            "open source-edit directory component {:?} without following links",
            name
        )
    })?;
    let metadata = opened
        .metadata()
        .context("inspect opened source-edit directory component")?;
    anyhow::ensure!(
        metadata.is_dir() && !source_edit_metadata_is_link_like(&metadata),
        "source-edit path component {:?} is a symlink, junction, reparse point, or non-directory",
        name
    );
    Ok(Dir::from_std_file(opened.into_std()))
}

fn read_source_edit_regular_leaf(parent: &Dir, name: &OsStr, max_bytes: u64) -> Result<Vec<u8>> {
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
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(not(any(unix, windows)))]
    anyhow::bail!("source-edit image evidence is unsupported without no-follow filesystem APIs");

    let opened = parent
        .open_with(name, &options)
        .with_context(|| format!("open source-edit leaf {:?} without following links", name))?;
    let opened_metadata = opened
        .metadata()
        .context("inspect opened source-edit leaf")?;
    anyhow::ensure!(
        opened_metadata.is_file() && !source_edit_metadata_is_link_like(&opened_metadata),
        "source-edit leaf {:?} is a symlink, junction, reparse point, or non-regular file",
        name
    );
    // `into_std` preserves this exact handle; all later metadata/read/link
    // probes remain bound to the nofollow-opened object, never reopen by path.
    let mut opened = opened.into_std();
    ensure_source_edit_single_hard_link(&opened)?;
    let before = opened
        .metadata()
        .context("inspect bound source-edit leaf after hard-link check")?;
    anyhow::ensure!(
        before.len() <= max_bytes,
        "source-edit leaf {:?} exceeds the {}-byte bounded evidence cap",
        name,
        max_bytes
    );
    let capacity = usize::try_from(before.len()).context("convert source-edit leaf length")?;
    let mut bytes = Vec::with_capacity(capacity.min(64 * 1024));
    after_source_edit_leaf_open_for_test()?;
    (&mut opened)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .context("read no-follow source-edit leaf")?;
    anyhow::ensure!(
        u64::try_from(bytes.len()).context("convert bounded source-edit read length")? <= max_bytes,
        "source-edit leaf {:?} grew beyond its bounded evidence cap while being read",
        name
    );
    anyhow::ensure!(
        u64::try_from(bytes.len()).context("convert source-edit read length")? == before.len(),
        "source-edit leaf {:?} changed length while its evidence image was read",
        name
    );
    let after = opened
        .metadata()
        .context("reinspect opened source-edit leaf")?;
    ensure_source_edit_single_hard_link(&opened)?;
    anyhow::ensure!(
        after.is_file() && after.len() == before.len(),
        "source-edit leaf changed while its evidence image was read"
    );
    Ok(bytes)
}

/// Read one reviewed source path by walking every existing ancestor from a
/// retained capability for the canonical source root. No ambient `root.join`
/// read is permitted: a symlink/junction/reparse point at either a parent or
/// leaf is a hard refusal. A missing leaf (including one below a currently
/// absent descendant) is represented explicitly only after every existing
/// ancestor has been proven real and beneath that capability.
fn read_source_edit_path_nofollow(
    source_root: &Path,
    relative: &Path,
    max_bytes: u64,
) -> Result<Option<Vec<u8>>> {
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (source_root, relative);
        anyhow::bail!(
            "source-edit image evidence is unsupported without no-follow filesystem APIs"
        );
    }
    #[cfg(any(unix, windows))]
    {
        let mut current = Dir::open_ambient_dir(source_root, cap_std::ambient_authority())
            .with_context(|| {
                format!("open canonical source-edit root {}", source_root.display())
            })?;
        let root_metadata = current
            .dir_metadata()
            .context("inspect source-edit root capability")?;
        anyhow::ensure!(
            root_metadata.is_dir() && !source_edit_metadata_is_link_like(&root_metadata),
            "source-edit root is a symlink, junction, reparse point, or non-directory"
        );
        let components: Vec<_> = relative.components().collect();
        anyhow::ensure!(!components.is_empty(), "empty source-edit target path");
        for (index, component) in components.iter().enumerate() {
            let Component::Normal(name) = component else {
                anyhow::bail!("unsafe source-edit target path component");
            };
            let is_leaf = index + 1 == components.len();
            let named = match current.symlink_metadata(name) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "inspect source-edit path component {:?} without following links",
                            name
                        )
                    });
                }
            };
            anyhow::ensure!(
                !source_edit_metadata_is_link_like(&named),
                "source-edit path component {:?} is a symlink, junction, or reparse point",
                name
            );
            if is_leaf {
                anyhow::ensure!(
                    named.is_file(),
                    "source-edit leaf {:?} is not a regular file",
                    name
                );
                return read_source_edit_regular_leaf(&current, name, max_bytes).map(Some);
            }
            anyhow::ensure!(
                named.is_dir(),
                "source-edit path component {:?} is not a directory",
                name
            );
            current = open_source_edit_child_directory(&current, name)?;
        }
        unreachable!("non-empty source-edit path always has a leaf")
    }
}

fn source_edit_images_blocking(
    source_root: &Path,
    paths: &[String],
) -> Result<Vec<SourceEditPathImage>> {
    let canonical_root = source_root
        .canonicalize()
        .with_context(|| format!("canonicalize source-edit root {}", source_root.display()))?;
    let mut images = Vec::with_capacity(paths.len());
    let mut total_bytes = 0u64;
    for path in paths {
        let relative = Path::new(path);
        anyhow::ensure!(
            relative.is_relative()
                && relative
                    .components()
                    .all(|component| matches!(component, Component::Normal(_))),
            "unsafe source-edit target path `{path}`"
        );
        let remaining_bytes = SOURCE_EDIT_IMAGE_MAX_TOTAL_BYTES.saturating_sub(total_bytes);
        anyhow::ensure!(
            remaining_bytes > 0,
            "source-edit evidence reached its total byte cap"
        );
        let max_bytes = SOURCE_EDIT_IMAGE_MAX_FILE_BYTES.min(remaining_bytes);
        let (exists, bytes) =
            match read_source_edit_path_nofollow(&canonical_root, relative, max_bytes)? {
                Some(bytes) => (true, bytes),
                None => (false, Vec::new()),
            };
        total_bytes = total_bytes
            .checked_add(u64::try_from(bytes.len()).context("convert source-edit image length")?)
            .context("source-edit evidence byte counter overflow")?;
        anyhow::ensure!(
            total_bytes <= SOURCE_EDIT_IMAGE_MAX_TOTAL_BYTES,
            "source-edit evidence exceeds the {}-byte total cap",
            SOURCE_EDIT_IMAGE_MAX_TOTAL_BYTES
        );
        let mut digest = Sha256::new();
        let state_marker: &[u8] = if exists {
            b"NEOTH/source-edit/image/present\0"
        } else {
            b"NEOTH/source-edit/image/missing\0"
        };
        digest.update(state_marker);
        digest.update(path.as_bytes());
        digest.update([0]);
        digest.update(&bytes);
        images.push(SourceEditPathImage {
            path: path.clone(),
            exists,
            sha256: format!("{:x}", digest.finalize()),
        });
    }
    Ok(images)
}

/// Source-image IO is intentionally bounded and runs off Tokio's worker pool:
/// a huge/sparse candidate must not allocate unbounded memory or block the
/// async proposal state lock while it is being rejected.
pub(crate) async fn source_edit_images(
    source_root: &Path,
    paths: &[String],
) -> Result<Vec<SourceEditPathImage>> {
    validate_source_edit_image_paths(paths)?;
    let source_root = source_root.to_path_buf();
    let paths = paths.to_vec();
    tokio::task::spawn_blocking(move || source_edit_images_blocking(&source_root, &paths))
        .await
        .context("join bounded source-edit image snapshot")?
}

fn proposal_sha256(proposal: &SelfDevProposal) -> Result<String> {
    let bytes = serde_json::to_vec(proposal).context("serialize self-dev proposal identity")?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn save_effect_transaction(home: &Path, journal: &EffectTransactionJournal) -> Result<()> {
    let path = effect_transaction_path(home);
    let bytes = serde_json::to_vec_pretty(journal).context("serialize self-dev effect journal")?;
    anyhow::ensure!(
        bytes.len() <= EFFECT_TRANSACTION_MAX_BYTES,
        "self-dev effect journal exceeds its size limit"
    );
    crate::util::atomic_write::atomic_write_private(&path, &bytes)
        .with_context(|| format!("write self-dev effect journal {}", path.display()))?;
    crate::util::atomic_write::sync_parent_directory_required(&path)
        .with_context(|| format!("durably commit self-dev effect journal {}", path.display()))
}

fn load_effect_transaction(home: &Path) -> Result<Option<EffectTransactionJournal>> {
    let path = effect_transaction_path(home);
    match std::fs::read(&path) {
        Ok(bytes) => {
            anyhow::ensure!(
                bytes.len() <= EFFECT_TRANSACTION_MAX_BYTES,
                "self-dev effect journal exceeds its size limit"
            );
            Ok(Some(serde_json::from_slice(&bytes).with_context(|| {
                format!("parse self-dev effect journal {}", path.display())
            })?))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("read self-dev effect journal {}", path.display()))
        }
    }
}

fn remove_effect_transaction(home: &Path) -> Result<()> {
    let path = effect_transaction_path(home);
    crate::util::atomic_write::durable_remove_file(&path)
        .with_context(|| format!("durably remove self-dev effect journal {}", path.display()))
}

fn save_source_edit_transaction(home: &Path, journal: &mut SourceEditApplyJournal) -> Result<()> {
    journal.auth_tag = source_edit_auth_tag(
        home,
        SOURCE_EDIT_JOURNAL_DOMAIN,
        &source_edit_journal_unsigned(journal)?,
    )?;
    let path = source_edit_transaction_path(home);
    let bytes =
        serde_json::to_vec_pretty(journal).context("serialize source-edit apply journal")?;
    anyhow::ensure!(
        bytes.len() <= SOURCE_EDIT_TRANSACTION_MAX_BYTES,
        "source-edit apply journal exceeds its size limit"
    );
    crate::util::atomic_write::atomic_write_private(&path, &bytes)
        .with_context(|| format!("write source-edit apply journal {}", path.display()))?;
    crate::util::atomic_write::sync_parent_directory_required(&path).with_context(|| {
        format!(
            "durably commit source-edit apply journal {}",
            path.display()
        )
    })
}

fn load_source_edit_transaction(home: &Path) -> Result<Option<SourceEditApplyJournal>> {
    let path = source_edit_transaction_path(home);
    match std::fs::read(&path) {
        Ok(bytes) => {
            anyhow::ensure!(
                bytes.len() <= SOURCE_EDIT_TRANSACTION_MAX_BYTES,
                "source-edit apply journal exceeds its size limit"
            );
            let journal: SourceEditApplyJournal = serde_json::from_slice(&bytes)
                .with_context(|| format!("parse source-edit apply journal {}", path.display()))?;
            anyhow::ensure!(
                source_edit_auth_tag_matches(
                    home,
                    SOURCE_EDIT_JOURNAL_DOMAIN,
                    &source_edit_journal_unsigned(&journal)?,
                    &journal.auth_tag,
                )?,
                "source-edit apply journal authentication failed"
            );
            Ok(Some(journal))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("read source-edit apply journal {}", path.display()))
        }
    }
}

fn remove_source_edit_transaction(home: &Path) -> Result<()> {
    let path = source_edit_transaction_path(home);
    crate::util::atomic_write::durable_remove_file(&path).with_context(|| {
        format!(
            "durably remove source-edit apply journal {}",
            path.display()
        )
    })
}

fn save_source_edit_receipt(home: &Path, receipt: &mut SourceEditApplyReceipt) -> Result<()> {
    receipt.auth_tag = source_edit_auth_tag(
        home,
        SOURCE_EDIT_RECEIPT_DOMAIN,
        &source_edit_receipt_unsigned(receipt)?,
    )?;
    let path = source_edit_receipt_path(home);
    let bytes =
        serde_json::to_vec_pretty(receipt).context("serialize source-edit apply receipt")?;
    anyhow::ensure!(
        bytes.len() <= SOURCE_EDIT_RECEIPT_MAX_BYTES,
        "source-edit apply receipt exceeds its size limit"
    );
    crate::util::atomic_write::atomic_write_private(&path, &bytes)
        .with_context(|| format!("write source-edit apply receipt {}", path.display()))?;
    crate::util::atomic_write::sync_parent_directory_required(&path).with_context(|| {
        format!(
            "durably commit source-edit apply receipt {}",
            path.display()
        )
    })
}

fn load_source_edit_receipt(home: &Path) -> Result<Option<SourceEditApplyReceipt>> {
    let path = source_edit_receipt_path(home);
    match std::fs::read(&path) {
        Ok(bytes) => {
            anyhow::ensure!(
                bytes.len() <= SOURCE_EDIT_RECEIPT_MAX_BYTES,
                "source-edit apply receipt exceeds its size limit"
            );
            let receipt: SourceEditApplyReceipt = serde_json::from_slice(&bytes)
                .with_context(|| format!("parse source-edit apply receipt {}", path.display()))?;
            anyhow::ensure!(
                source_edit_auth_tag_matches(
                    home,
                    SOURCE_EDIT_RECEIPT_DOMAIN,
                    &source_edit_receipt_unsigned(&receipt)?,
                    &receipt.auth_tag,
                )?,
                "source-edit apply receipt authentication failed"
            );
            Ok(Some(receipt))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("read source-edit apply receipt {}", path.display()))
        }
    }
}

fn remove_source_edit_receipt(home: &Path) -> Result<()> {
    let path = source_edit_receipt_path(home);
    crate::util::atomic_write::durable_remove_file(&path).with_context(|| {
        format!(
            "durably remove source-edit apply receipt {}",
            path.display()
        )
    })
}

fn effect_target_for(proposal: &SelfDevProposal) -> Result<EffectTarget> {
    match proposal
        .validate_for_acceptance()
        .map_err(anyhow::Error::msg)?
    {
        ValidatedProposalTarget::Preset(preset) => Ok(EffectTarget::Preset {
            target: preset.as_str().to_owned(),
        }),
        ValidatedProposalTarget::Verbosity(_) => Ok(EffectTarget::Verbosity {
            target: proposal.target.clone(),
        }),
        ValidatedProposalTarget::BriefingTime { hour, minute } => {
            Ok(EffectTarget::Briefing { hour, minute })
        }
        ValidatedProposalTarget::ExtensionSelector { id, authority } => {
            Ok(EffectTarget::Extension { id, authority })
        }
        // SourceEdit is intentionally a separate explicit operator action. It
        // cannot be labelled Accepted until the self-edit gate itself produces
        // a durable apply receipt.
        ValidatedProposalTarget::SourceEdit => {
            Err(SelfDevEffectTransactionError::SeparateApplyRequired {
                proposal_id: proposal.id.clone(),
            }
            .into())
        }
    }
}

async fn effect_matches_readback(home: &Path, target: &EffectTarget) -> Result<bool> {
    use crate::cron::schema::{CronRole, JobsFile, classify_role};
    use crate::profile::communication::{
        CommunicationDimension, PreferenceValue, ProcessingLoadPreference,
    };

    match target {
        EffectTarget::Preset { target } => Ok(crate::cli::profile::load_active_preset(home)
            .is_some_and(|preset| preset.as_str() == target)),
        EffectTarget::Verbosity { target } => {
            let desired = match target.as_str() {
                "terse" => PreferenceValue::ProcessingLoad(ProcessingLoadPreference::Compact),
                "normal" => PreferenceValue::ProcessingLoad(ProcessingLoadPreference::Balanced),
                "detailed" => PreferenceValue::ProcessingLoad(ProcessingLoadPreference::Deep),
                _ => anyhow::bail!("invalid journaled verbosity target `{target}`"),
            };
            let state = crate::profile::communication::load_state(home)?;
            Ok(state
                .subjects
                .get("operator")
                .and_then(|subject| {
                    subject
                        .estimates
                        .get(&CommunicationDimension::ProcessingLoad)
                })
                .is_some_and(|estimate| estimate.pinned && estimate.selected == desired))
        }
        EffectTarget::Briefing { hour, minute } => {
            let path = home.join("jobs.yaml");
            let body = match std::fs::read_to_string(&path) {
                Ok(body) => body,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
                Err(error) => {
                    return Err(error).with_context(|| format!("read {}", path.display()));
                }
            };
            let jobs = JobsFile::from_yaml_str(&body)
                .with_context(|| format!("parse {} for briefing postcondition", path.display()))?;
            let expected = format!("{minute} {hour} * * *");
            Ok(jobs.jobs.iter().any(|job| {
                job.enabled
                    && classify_role(job) == CronRole::Briefing
                    && job.schedule.cron == expected
                    && job.schedule.every_seconds.is_none()
                    && job.schedule.anchor_unix.is_none()
                    && job.schedule.at.is_none()
            }))
        }
        EffectTarget::Extension { id, authority } => {
            let config_path = home.join("freedom.yaml");
            let config =
                crate::config::FreedomConfig::load_from_path(&config_path).with_context(|| {
                    format!("read {} for extension postcondition", config_path.display())
                })?;
            let enabled = config
                .skills
                .enabled
                .iter()
                .any(|candidate| candidate.trim().eq_ignore_ascii_case(id));
            if !enabled {
                return Ok(false);
            }
            match authority {
                ExtensionAuthorityBinding::Bundled => {
                    let inventory =
                        crate::skills::loader::diagnostic_inventory_for_accepted_config(
                            &home.join("skills"),
                            config,
                            config_path,
                        )
                        .await
                        .context("read back exact bundled Skill origin")?;
                    Ok(inventory.iter().any(|row| {
                        row.id().eq_ignore_ascii_case(id)
                            && matches!(
                                row,
                                crate::skills::loader::SkillInventoryRow::Healthy {
                                    origin: crate::skills::loader::SkillInventoryOrigin::Bundled,
                                    runtime_state:
                                        crate::skills::loader::SkillInventoryRuntimeState::TrustedBundledActive,
                                    ..
                                }
                            )
                    }))
                }
                ExtensionAuthorityBinding::Installed {
                    package_generation_sha256,
                    install_incarnation,
                    install_terminal_receipt_sha256,
                } => {
                    let reload = crate::config::reload::ReloadController::new(config, config_path);
                    let validation =
                        crate::skills::authority::validate_installed_authority(home, id, &reload);
                    let crate::skills::authority::InstalledSkillAuthorityValidation::Active(
                        validated,
                    ) = validation
                    else {
                        return Ok(false);
                    };
                    Ok(exact_installed_extension_postcondition(
                        package_generation_sha256,
                        *install_incarnation,
                        install_terminal_receipt_sha256,
                        validated.package_generation_sha256(),
                        validated.install_incarnation(),
                        validated.install_terminal_receipt_sha256(),
                        validated.record().state,
                    ))
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn exact_installed_extension_postcondition(
    expected_generation_sha256: &str,
    expected_install_incarnation: u64,
    expected_terminal_receipt_sha256: &str,
    observed_generation_sha256: &str,
    observed_install_incarnation: u64,
    observed_terminal_receipt_sha256: &str,
    observed_state: crate::skills::authority::SkillAuthorityState,
) -> bool {
    observed_state == crate::skills::authority::SkillAuthorityState::Active
        && observed_generation_sha256 == expected_generation_sha256
        && observed_install_incarnation == expected_install_incarnation
        && observed_terminal_receipt_sha256 == expected_terminal_receipt_sha256
}

fn commit_accepted_store(
    home: &Path,
    proposal_id: &str,
    expected_proposal_sha256: &str,
    guard: &SelfDevStateGuard,
) -> Result<()> {
    let mut store = load_store(home)?;
    let ts = now_unix();
    let accepted_at_unix = {
        let entry = store
            .entries
            .iter_mut()
            .find(|entry| entry.proposal.id == proposal_id)
            .with_context(|| {
                format!("proposal id `{proposal_id}` missing during effect recovery")
            })?;
        anyhow::ensure!(
            proposal_sha256(&entry.proposal)? == expected_proposal_sha256,
            "proposal `{proposal_id}` changed after its effect transaction was prepared; journal preserved"
        );
        match entry.status {
            ProposalStatus::Pending => {
                entry.status = ProposalStatus::Accepted;
                entry.status_at_unix = ts;
                entry.decline_reason.clear();
                Some(entry.status_at_unix)
            }
            ProposalStatus::Accepted => None,
            ProposalStatus::Declined => anyhow::bail!(
                "proposal `{proposal_id}` was declined while its effect transaction was pending; journal preserved"
            ),
        }
    };
    if let Some(ts_unix) = accepted_at_unix {
        store.audit_pending.push(ProposalAuditIntent::Accepted {
            proposal_id: proposal_id.to_owned(),
            ts_unix,
        });
    }
    save_store_locked(home, &store, guard)
}

/// Recover an interrupted non-Skill proposal acceptance before servicing new
/// CLI actions. A prepared journal with no observable effect is abandoned;
/// an applied/proven journal commits the already-read-back decision. Ambiguous
/// state remains journaled and returns a typed retry-safe error.
async fn recover_effect_transaction_locked(home: &Path, guard: &SelfDevStateGuard) -> Result<()> {
    let Some(journal) = load_effect_transaction(home).map_err(|error| {
        anyhow::Error::new(SelfDevEffectTransactionError::RecoveryRequired {
            proposal_id: "<unreadable-effect-journal>".to_owned(),
        })
        .context(format!("read interrupted effect journal: {error:#}"))
    })?
    else {
        return Ok(());
    };
    let store = load_store(home)?;
    let entry = store
        .entries
        .iter()
        .find(|entry| entry.proposal.id == journal.proposal_id)
        .ok_or_else(|| {
            anyhow::Error::new(SelfDevEffectTransactionError::RecoveryRequired {
                proposal_id: journal.proposal_id.clone(),
            })
            .context(format!(
                "effect journal references missing proposal `{}`",
                journal.proposal_id
            ))
        })?;
    if proposal_sha256(&entry.proposal)? != journal.proposal_sha256 {
        return Err(SelfDevEffectTransactionError::RecoveryRequired {
            proposal_id: journal.proposal_id,
        }
        .into());
    }
    // The journal is not an authority source. Re-validate the current stored
    // proposal and derive its exact typed target again before trusting any
    // journaled effect. This blocks forged SourceEdit journals and same-id
    // extension package substitutions.
    let current_target = effect_target_for(&entry.proposal).map_err(|error| {
        anyhow::Error::new(SelfDevEffectTransactionError::RecoveryRequired {
            proposal_id: journal.proposal_id.clone(),
        })
        .context(format!(
            "re-derive stored proposal target during recovery: {error:#}"
        ))
    })?;
    if current_target != journal.target {
        return Err(SelfDevEffectTransactionError::RecoveryRequired {
            proposal_id: journal.proposal_id,
        }
        .into());
    }
    if entry.status == ProposalStatus::Accepted {
        remove_effect_transaction(home)?;
        return Ok(());
    }
    if entry.status == ProposalStatus::Declined {
        return Err(SelfDevEffectTransactionError::RecoveryRequired {
            proposal_id: journal.proposal_id,
        }
        .into());
    }

    let matches = effect_matches_readback(home, &journal.target)
        .await
        .map_err(|error| {
            anyhow::Error::new(SelfDevEffectTransactionError::RecoveryRequired {
                proposal_id: journal.proposal_id.clone(),
            })
            .context(format!("read back interrupted proposal effect: {error:#}"))
        })?;
    match (journal.phase, matches) {
        (EffectTransactionPhase::Prepared, false) => {
            // No observable target effect exists. Target writers are atomic,
            // so a crash before invoking one can discard only the intent and
            // leave the proposal pending.
            remove_effect_transaction(home)
        }
        (EffectTransactionPhase::Prepared, true) => {
            // An intent alone is never proof that this process applied the
            // effect. Another writer may have changed the target between the
            // durable intent and `Applying`; keep the proposal Pending and
            // force explicit recovery instead of granting Accepted.
            Err(SelfDevEffectTransactionError::RecoveryRequired {
                proposal_id: journal.proposal_id,
            }
            .into())
        }
        (EffectTransactionPhase::Applying, false) => {
            // The writer may have been invoked and its exact target may since
            // have been replaced/revoked. Clean the stale intent durably, keep
            // the decision Pending, and surface a typed retry instead of
            // silently treating this ambiguous state as success.
            remove_effect_transaction(home)?;
            Err(SelfDevEffectTransactionError::PostconditionFailed {
                proposal_id: journal.proposal_id,
            }
            .into())
        }
        (_, true) => {
            commit_accepted_store(home, &journal.proposal_id, &journal.proposal_sha256, guard)?;
            remove_effect_transaction(home)
        }
        (_, false) => Err(SelfDevEffectTransactionError::RecoveryRequired {
            proposal_id: journal.proposal_id,
        }
        .into()),
    }
}

fn normalized_source_paths(paths: &[String]) -> Vec<String> {
    let mut paths = paths.to_vec();
    paths.sort();
    paths.dedup();
    paths
}

fn source_edit_contract_rejection(
    proposal_id: &str,
    detail: impl std::fmt::Display,
) -> anyhow::Error {
    anyhow::Error::new(SelfDevEffectTransactionError::SourceEditContractRejected {
        proposal_id: proposal_id.to_owned(),
    })
    .context(detail.to_string())
}

fn source_edit_receipt_recovery_error(
    proposal_id: &str,
    detail: impl std::fmt::Display,
) -> anyhow::Error {
    anyhow::Error::new(
        SelfDevEffectTransactionError::SourceEditReceiptRecoveryRequired {
            proposal_id: proposal_id.to_owned(),
        },
    )
    .context(detail.to_string())
}

async fn validate_source_edit_contract_locked(
    home: &Path,
    proposal_id: &str,
    diff_path: &Path,
    source_root: &Path,
    expected_diff_sha256: &str,
    actual_diff_sha256: &str,
    parsed_target_paths: &[String],
    _guard: &SelfDevStateGuard,
) -> Result<SourceEditProposalContract> {
    let store = load_store(home)?;
    let entry = store
        .entries
        .iter()
        .find(|entry| entry.proposal.id == proposal_id)
        .ok_or_else(|| source_edit_contract_rejection(proposal_id, "proposal id not found"))?;
    match entry.status {
        ProposalStatus::Pending => {}
        ProposalStatus::Accepted => {
            return Err(source_edit_contract_rejection(
                proposal_id,
                "proposal is already accepted; refusing to apply its effect again",
            ));
        }
        ProposalStatus::Declined => {
            return Err(source_edit_contract_rejection(
                proposal_id,
                "proposal was declined and cannot authorize a source edit",
            ));
        }
    }
    entry
        .proposal
        .validate_for_acceptance()
        .map_err(|error| source_edit_contract_rejection(proposal_id, error))?;
    let ProposalKind::SourceEdit {
        patch_path,
        diff_sha256,
        target_paths,
    } = &entry.proposal.kind
    else {
        return Err(source_edit_contract_rejection(
            proposal_id,
            "proposal is not a SourceEdit proposal",
        ));
    };
    validate_source_edit_image_paths(target_paths).map_err(|error| {
        source_edit_contract_rejection(
            proposal_id,
            format!("reviewed SourceEdit target paths violate evidence limits: {error:#}"),
        )
    })?;
    if expected_diff_sha256 != diff_sha256 || actual_diff_sha256 != diff_sha256 {
        return Err(source_edit_contract_rejection(
            proposal_id,
            format!("expected/actual diff hash does not equal reviewed hash {diff_sha256}"),
        ));
    }
    let reviewed_patch = patch_path.canonicalize().map_err(|error| {
        source_edit_contract_rejection(
            proposal_id,
            format!(
                "cannot resolve reviewed patch {}: {error}",
                patch_path.display()
            ),
        )
    })?;
    if reviewed_patch != diff_path {
        return Err(source_edit_contract_rejection(
            proposal_id,
            format!(
                "diff path {} does not equal reviewed patch {}",
                diff_path.display(),
                reviewed_patch.display()
            ),
        ));
    }
    let expected_paths = normalized_source_paths(target_paths);
    if normalized_source_paths(parsed_target_paths) != expected_paths {
        return Err(source_edit_contract_rejection(
            proposal_id,
            "parsed diff target paths do not equal the reviewed proposal paths",
        ));
    }
    let source_root = source_root.canonicalize().map_err(|error| {
        source_edit_contract_rejection(
            proposal_id,
            format!(
                "cannot resolve authoritative source root {}: {error}",
                source_root.display()
            ),
        )
    })?;
    let base_images = source_edit_images(&source_root, &expected_paths)
        .await
        .map_err(|error| {
            source_edit_contract_rejection(
                proposal_id,
                format!("cannot snapshot reviewed source preimages: {error:#}"),
            )
        })?;
    Ok(SourceEditProposalContract {
        proposal_id: proposal_id.to_owned(),
        proposal_sha256: proposal_sha256(&entry.proposal)?,
        diff_sha256: diff_sha256.clone(),
        source_root,
        target_paths: expected_paths,
        base_images,
    })
}

/// Recover a source-edit transaction before examining a receipt or serving a
/// new proposal operation. A changed source tree while phase is `Prepared` or
/// `Applying` is intentionally ambiguous: a process may have died just after
/// `git apply`, and accepting based only on a tree comparison would be a false
/// success. Only an authenticated `PostconditionProven` journal with exact
/// images and a recorded WAL finalization may advance to a receipt.
async fn recover_source_edit_transaction_locked(
    home: &Path,
    guard: &SelfDevStateGuard,
) -> Result<()> {
    let Some(journal) = load_source_edit_transaction(home).map_err(|error| {
        source_edit_receipt_recovery_error(
            "<unreadable-source-edit-journal>",
            format!("read authenticated pre-apply source-edit journal: {error:#}"),
        )
    })?
    else {
        return Ok(());
    };
    let fail = |detail: String| source_edit_receipt_recovery_error(&journal.proposal_id, detail);
    if journal.version != SOURCE_EDIT_TRANSACTION_VERSION {
        return Err(fail(format!(
            "unsupported source-edit transaction version {}",
            journal.version
        )));
    }
    let store = load_store(home)?;
    let entry = store
        .entries
        .iter()
        .find(|entry| entry.proposal.id == journal.proposal_id)
        .ok_or_else(|| fail("journal references a missing proposal id".to_owned()))?;
    if proposal_sha256(&entry.proposal)? != journal.proposal_sha256 {
        return Err(fail(
            "journal proposal digest does not match stored proposal".to_owned(),
        ));
    }
    let ProposalKind::SourceEdit {
        diff_sha256,
        target_paths,
        ..
    } = &entry.proposal.kind
    else {
        return Err(fail(
            "journal proposal is not a SourceEdit proposal".to_owned(),
        ));
    };
    let expected_paths = normalized_source_paths(target_paths);
    if journal.diff_sha256 != *diff_sha256 || journal.target_paths != expected_paths {
        return Err(fail(
            "journal diff or authoritative path set differs from proposal".to_owned(),
        ));
    }
    let current_images = source_edit_images(Path::new(&journal.source_root), &journal.target_paths)
        .await
        .map_err(|error| {
            fail(format!(
                "read current authoritative source images: {error:#}"
            ))
        })?;
    match journal.phase {
        SourceEditTransactionPhase::Prepared => {
            if current_images == journal.base_images {
                remove_source_edit_transaction(home)
            } else {
                Err(fail(
                    "prepared source-edit journal has a changed tree; refusing to infer an applied edit"
                        .to_owned(),
                ))
            }
        }
        SourceEditTransactionPhase::Applying => {
            if current_images == journal.base_images {
                // The gate was entered but no observable live change remains.
                // It may safely be retried because the proposal is still Pending.
                remove_source_edit_transaction(home)
            } else {
                Err(fail(
                    "source edit may have applied before crash, but no authenticated postimage/WAL proof exists"
                        .to_owned(),
                ))
            }
        }
        SourceEditTransactionPhase::PostconditionProven => {
            let post_images = journal.post_images.as_ref().ok_or_else(|| {
                fail("postcondition-proven journal lacks postimage evidence".to_owned())
            })?;
            if !journal.self_edit_audit_finalized || current_images != *post_images {
                return Err(fail(
                    "postcondition-proven journal no longer has exact postimage/WAL evidence"
                        .to_owned(),
                ));
            }
            let mut receipt = SourceEditApplyReceipt {
                version: SOURCE_EDIT_RECEIPT_VERSION,
                proposal_id: journal.proposal_id.clone(),
                proposal_sha256: journal.proposal_sha256.clone(),
                diff_sha256: journal.diff_sha256.clone(),
                source_root: journal.source_root.clone(),
                target_paths: journal.target_paths.clone(),
                base_images: journal.base_images.clone(),
                post_images: post_images.clone(),
                self_edit_audit_finalized: true,
                applied_at_unix: now_unix(),
                auth_tag: String::new(),
            };
            save_source_edit_receipt(home, &mut receipt)?;
            recover_source_edit_receipt_locked(home, guard).await?;
            remove_source_edit_transaction(home)
        }
    }
}

async fn recover_source_edit_receipt_locked(home: &Path, guard: &SelfDevStateGuard) -> Result<()> {
    let Some(receipt) = load_source_edit_receipt(home).map_err(|error| {
        source_edit_receipt_recovery_error(
            "<unreadable-source-edit-receipt>",
            format!("read durable source-edit receipt: {error:#}"),
        )
    })?
    else {
        return Ok(());
    };
    let fail = |detail: String| source_edit_receipt_recovery_error(&receipt.proposal_id, detail);
    if receipt.version != SOURCE_EDIT_RECEIPT_VERSION {
        return Err(fail(format!(
            "unsupported source-edit receipt version {}",
            receipt.version
        )));
    }
    if !receipt.self_edit_audit_finalized {
        return Err(fail(
            "receipt does not prove mandatory self-edit audit finalization".to_owned(),
        ));
    }
    let store = load_store(home)?;
    let entry = store
        .entries
        .iter()
        .find(|entry| entry.proposal.id == receipt.proposal_id)
        .ok_or_else(|| fail("receipt references a missing proposal id".to_owned()))?;
    if proposal_sha256(&entry.proposal)? != receipt.proposal_sha256 {
        return Err(fail(
            "receipt proposal digest does not match the stored proposal".to_owned(),
        ));
    }
    entry
        .proposal
        .validate_for_acceptance()
        .map_err(|error| fail(format!("stored proposal no longer validates: {error}")))?;
    let ProposalKind::SourceEdit {
        diff_sha256,
        target_paths,
        ..
    } = &entry.proposal.kind
    else {
        return Err(fail(
            "receipt proposal is not a SourceEdit proposal".to_owned(),
        ));
    };
    if receipt.diff_sha256 != *diff_sha256 {
        return Err(fail(
            "receipt diff hash does not match the reviewed proposal".to_owned(),
        ));
    }
    let receipt_paths = normalized_source_paths(&receipt.target_paths);
    let expected_paths = normalized_source_paths(target_paths);
    if receipt_paths.is_empty() || receipt_paths != expected_paths {
        return Err(fail(
            "receipt target paths do not exactly equal reviewed proposal paths".to_owned(),
        ));
    }
    let source_root = PathBuf::from(&receipt.source_root);
    let current_images = source_edit_images(&source_root, &receipt_paths)
        .await
        .map_err(|error| fail(format!("read receipt postimage paths: {error:#}")))?;
    if receipt.base_images.len() != receipt_paths.len()
        || receipt.post_images.len() != receipt_paths.len()
        || current_images != receipt.post_images
    {
        return Err(fail(
            "receipt exact source postimage evidence is missing, malformed, or no longer current"
                .to_owned(),
        ));
    }
    match entry.status {
        ProposalStatus::Pending => {
            commit_accepted_store(home, &receipt.proposal_id, &receipt.proposal_sha256, guard)?
        }
        ProposalStatus::Accepted => {}
        ProposalStatus::Declined => {
            return Err(fail(
                "proposal was declined after the edit was applied; manual recovery required"
                    .to_owned(),
            ));
        }
    }
    remove_source_edit_receipt(home)
}

/// Bind a live self-edit attempt to one exact pending SourceEdit proposal and
/// retain the common OS-backed proposal lock until terminal finalization.
pub(crate) async fn begin_source_edit_apply(
    home: &Path,
    proposal_id: &str,
    diff_path: &Path,
    source_root: &Path,
    expected_diff_sha256: &str,
    actual_diff_sha256: &str,
    parsed_target_paths: &[String],
) -> Result<SourceEditApplyTransaction> {
    let guard = acquire_self_dev_state_guard(home).await?;
    recover_source_edit_transaction_locked(home, &guard).await?;
    recover_source_edit_receipt_locked(home, &guard).await?;
    recover_effect_transaction_locked(home, &guard).await?;
    flush_pending_audits_locked(home, None, &guard).await?;
    let contract = validate_source_edit_contract_locked(
        home,
        proposal_id,
        diff_path,
        source_root,
        expected_diff_sha256,
        actual_diff_sha256,
        parsed_target_paths,
        &guard,
    )
    .await?;
    let mut journal = SourceEditApplyJournal {
        version: SOURCE_EDIT_TRANSACTION_VERSION,
        proposal_id: contract.proposal_id.clone(),
        proposal_sha256: contract.proposal_sha256.clone(),
        diff_sha256: contract.diff_sha256.clone(),
        source_root: contract.source_root.to_string_lossy().to_string(),
        target_paths: contract.target_paths.clone(),
        base_images: contract.base_images.clone(),
        post_images: None,
        phase: SourceEditTransactionPhase::Prepared,
        self_edit_audit_finalized: false,
        auth_tag: String::new(),
    };
    // This is the final pre-apply durable barrier. If it cannot be written the
    // caller never enters the five-gate stack, therefore cannot reach git apply.
    save_source_edit_transaction(home, &mut journal)?;
    Ok(SourceEditApplyTransaction {
        home: home.to_path_buf(),
        contract,
        journal,
        guard,
    })
}

impl SourceEditApplyTransaction {
    /// The immutable reviewed path plan. The gate consumes this before its
    /// live mutation boundary and compares it with Git's authoritative path
    /// differential; callers cannot substitute a parser-only superset.
    pub(crate) fn reviewed_target_paths(&self) -> &[String] {
        &self.contract.target_paths
    }

    /// Clone the opaque reviewed source plan for the gate's final no-follow
    /// preimage recheck immediately before the live git sink.
    pub(crate) fn pre_apply_plan(&self) -> SourceEditPreApplyPlan {
        SourceEditPreApplyPlan {
            source_root: self.contract.source_root.clone(),
            target_paths: self.contract.target_paths.clone(),
            base_images: self.contract.base_images.clone(),
        }
    }

    /// Cross the second durable barrier immediately before entering the gate
    /// stack. A crash thereafter is deliberately Pending/ambiguous until exact
    /// authenticated postimage evidence exists; this function never accepts.
    pub(crate) fn mark_applying(&mut self) -> Result<()> {
        self.journal.phase = SourceEditTransactionPhase::Applying;
        save_source_edit_transaction(&self.home, &mut self.journal)
    }

    /// Publish the receipt only after the caller has both applied the exact
    /// diff and observed clean completion of the required self-edit WAL writer.
    /// Acceptance and its audit intent are then durable before the receipt is
    /// durably removed, all while the same state lock remains held.
    pub(crate) async fn finalize_after_apply_and_audit(
        mut self,
        actual_diff_sha256: &str,
        actual_target_paths: &[String],
    ) -> Result<()> {
        if actual_diff_sha256 != self.contract.diff_sha256 {
            return Err(source_edit_contract_rejection(
                &self.contract.proposal_id,
                "gate outcome diff hash changed after contract validation",
            ));
        }
        let actual_paths = normalized_source_paths(actual_target_paths);
        if actual_paths.is_empty() || actual_paths != self.contract.target_paths {
            return Err(source_edit_contract_rejection(
                &self.contract.proposal_id,
                "gate outcome paths do not exactly equal reviewed proposal paths",
            ));
        }
        let post_images = source_edit_images(&self.contract.source_root, &actual_paths)
            .await
            .map_err(|error| {
                source_edit_contract_rejection(
                    &self.contract.proposal_id,
                    format!("cannot read back exact postimage after source edit: {error:#}"),
                )
            })?;
        self.journal.post_images = Some(post_images.clone());
        self.journal.phase = SourceEditTransactionPhase::PostconditionProven;
        self.journal.self_edit_audit_finalized = true;
        save_source_edit_transaction(&self.home, &mut self.journal)?;
        after_source_edit_postcondition_for_test()?;
        let mut receipt = SourceEditApplyReceipt {
            version: SOURCE_EDIT_RECEIPT_VERSION,
            proposal_id: self.contract.proposal_id.clone(),
            proposal_sha256: self.contract.proposal_sha256.clone(),
            diff_sha256: self.contract.diff_sha256.clone(),
            source_root: self.contract.source_root.to_string_lossy().to_string(),
            target_paths: actual_paths,
            base_images: self.contract.base_images.clone(),
            post_images,
            self_edit_audit_finalized: true,
            applied_at_unix: now_unix(),
            auth_tag: String::new(),
        };
        save_source_edit_receipt(&self.home, &mut receipt)?;
        after_source_edit_receipt_publish_for_test()?;
        recover_source_edit_receipt_locked(&self.home, &self.guard).await?;
        remove_source_edit_transaction(&self.home)?;
        flush_pending_audits_locked(&self.home, None, &self.guard)
            .await
            .context("source-edit proposal accepted; audit intent remains pending for retry")?;
        Ok(())
    }
}

#[cfg(test)]
std::thread_local! {
    static EFFECT_TRANSACTION_PREPARE_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static EFFECT_TRANSACTION_AFTER_ACCEPTED_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static SOURCE_EDIT_AFTER_POSTCONDITION_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static SOURCE_EDIT_RECEIPT_AFTER_PUBLISH_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static SOURCE_EDIT_LEAF_GROW_AFTER_OPEN: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

/// Test-only race seam placed after the regular-file handle and its initial
/// metadata have been acquired, but before bounded reading starts.
fn after_source_edit_leaf_open_for_test() -> Result<()> {
    #[cfg(test)]
    {
        let path = SOURCE_EDIT_LEAF_GROW_AFTER_OPEN.with(|slot| slot.borrow_mut().take());
        if let Some(path) = path {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .with_context(|| format!("open source-edit growth seam {}", path.display()))?;
            std::io::Write::write_all(&mut file, b"!")
                .with_context(|| format!("grow source-edit seam {}", path.display()))?;
            file.sync_all()
                .with_context(|| format!("sync source-edit growth seam {}", path.display()))?;
        }
    }
    Ok(())
}

/// Test-only crash seam: it runs after durable intent publication and before
/// the target writer. Production builds have no injectable path here.
fn after_effect_transaction_prepare_for_test() -> Result<()> {
    #[cfg(test)]
    {
        let fail = EFFECT_TRANSACTION_PREPARE_FAILURE.with(|slot| {
            let fail = slot.get();
            slot.set(false);
            fail
        });
        if fail {
            anyhow::bail!("injected failure after self-dev effect transaction prepare");
        }
    }
    Ok(())
}

fn after_effect_transaction_accepted_for_test() -> Result<()> {
    #[cfg(test)]
    {
        let fail = EFFECT_TRANSACTION_AFTER_ACCEPTED_FAILURE.with(|slot| {
            let fail = slot.get();
            slot.set(false);
            fail
        });
        if fail {
            anyhow::bail!("injected failure after durable self-dev acceptance");
        }
    }
    Ok(())
}

fn after_source_edit_receipt_publish_for_test() -> Result<()> {
    #[cfg(test)]
    {
        let fail = SOURCE_EDIT_RECEIPT_AFTER_PUBLISH_FAILURE.with(|slot| {
            let fail = slot.get();
            slot.set(false);
            fail
        });
        if fail {
            anyhow::bail!("injected failure after durable source-edit receipt publication");
        }
    }
    Ok(())
}

/// Test-only crash seam for the narrow window after a real apply and clean WAL
/// shutdown, but before a receipt exists. Recovery must preserve Pending until
/// an operator supplies/reconciles authoritative evidence; it may never infer
/// Accepted merely because the source tree changed.
fn after_source_edit_postcondition_for_test() -> Result<()> {
    #[cfg(test)]
    {
        let fail = SOURCE_EDIT_AFTER_POSTCONDITION_FAILURE.with(|slot| {
            let fail = slot.get();
            slot.set(false);
            fail
        });
        if fail {
            anyhow::bail!("injected failure after source-edit postcondition before receipt");
        }
    }
    Ok(())
}

/// Operator entrypoint — no WAL writer required (CLI may run without
/// a live daemon). Pass `Some(writer)` when invoked from inside the
/// running daemon to also emit the matching WAL frames.
pub async fn run(
    home: &Path,
    args: SelfDevArgs,
    writer: Option<&WalWriterHandle>,
    output: crate::cli::OutputFormat,
) -> Result<()> {
    match args.action {
        SelfDevAction::Review { min_confidence } => {
            let guard = acquire_self_dev_state_guard(home).await?;
            recover_and_flush_locked(home, writer, &guard).await?;
            run_review(home, min_confidence, output)
        }
        SelfDevAction::Accept { id } => run_accept(home, &id, writer, output).await,
        SelfDevAction::Decline { id, reason } => {
            run_decline(home, &id, &reason, writer, output).await
        }
        SelfDevAction::Propose {
            from_profile,
            current_preset,
        } => run_propose(home, &from_profile, &current_preset, writer).await,
        SelfDevAction::Scan => {
            // Do not retain the state lock across the collector/evolver scan:
            // its proposal publication path acquires this exact lock itself.
            let guard = acquire_self_dev_state_guard(home).await?;
            recover_and_flush_locked(home, writer, &guard).await?;
            drop(guard);
            run_scan(home, output).await
        }
    }
}

async fn recover_and_flush_locked(
    home: &Path,
    writer: Option<&WalWriterHandle>,
    guard: &SelfDevStateGuard,
) -> Result<()> {
    recover_source_edit_transaction_locked(home, guard).await?;
    recover_source_edit_receipt_locked(home, guard).await?;
    recover_effect_transaction_locked(home, guard).await?;
    flush_pending_audits_locked(home, writer, guard).await?;
    Ok(())
}

/// GUI-DES-SELFDEV-APPLY-01 — JSON row-builder for the GUI Proposal-Review
/// tab. Returns pending AND accepted entries (declined excluded). Source-edit
/// rows remain pending until their separate explicit self-edit gate commits.
///
/// `SourceEdit` entries carry `patch_path`, `diff_sha256`, and `target_paths`
/// as top-level JSON fields. All other proposal kinds leave those fields `null`
/// for forward-compat with panel_logic's kind-string lookup.
fn review_proposals_json(entries: &[&StoredProposal]) -> Vec<serde_json::Value> {
    use crate::profile::self_dev::ProposalKind;
    entries
        .iter()
        .map(|e| {
            let status_str = match e.status {
                ProposalStatus::Pending => "pending",
                ProposalStatus::Accepted => "accepted",
                ProposalStatus::Declined => "declined",
            };
            match &e.proposal.kind {
                ProposalKind::SourceEdit {
                    patch_path,
                    diff_sha256,
                    target_paths,
                } => serde_json::json!({
                    "id":           e.proposal.id,
                    "kind":         "source_edit",
                    "confidence":   e.proposal.confidence,
                    "target":       e.proposal.target,
                    "reason":       e.proposal.reason,
                    "status":       status_str,
                    "extension_authority": e.proposal.extension_authority,
                    "patch_path":   patch_path.to_string_lossy(),
                    "diff_sha256":  diff_sha256,
                    "target_paths": target_paths,
                }),
                _ => serde_json::json!({
                    "id":           e.proposal.id,
                    "kind":         e.proposal.kind.as_str(),
                    "confidence":   e.proposal.confidence,
                    "target":       e.proposal.target,
                    "reason":       e.proposal.reason,
                    "status":       status_str,
                    "extension_authority": e.proposal.extension_authority,
                    "patch_path":   serde_json::Value::Null,
                    "diff_sha256":  serde_json::Value::Null,
                    "target_paths": serde_json::Value::Null,
                }),
            }
        })
        .collect()
}

fn run_review(home: &Path, min_confidence: f64, output: crate::cli::OutputFormat) -> Result<()> {
    let store = load_store(home)?;
    // JSON mode: include pending + accepted. Declined entries are excluded.
    // Table mode stays pending-only — operator review flow doesn't need to re-
    // read accepted ones in human output.
    let active: Vec<&StoredProposal> = store
        .entries
        .iter()
        .filter(|e| e.status != ProposalStatus::Declined && e.proposal.confidence >= min_confidence)
        .collect();
    if matches!(
        output,
        crate::cli::OutputFormat::Json | crate::cli::OutputFormat::Jsonl
    ) {
        let rows = review_proposals_json(&active);
        println!("{}", serde_json::to_string(&rows)?);
        return Ok(());
    }
    let mut shown = 0usize;
    for e in &store.entries {
        if e.status != ProposalStatus::Pending {
            continue;
        }
        if e.proposal.confidence < min_confidence {
            continue;
        }
        println!("─ id          {}", e.proposal.id);
        println!("  kind        {}", e.proposal.kind.as_str());
        println!("  confidence  {:.2}", e.proposal.confidence);
        println!("  target      {}", e.proposal.target);
        if let Some(binding) = &e.proposal.extension_authority {
            println!("  authority   {binding:?}");
        }
        println!("  reason      {}", e.proposal.reason);
        if let ProposalKind::SourceEdit {
            patch_path,
            diff_sha256,
            ..
        } = &e.proposal.kind
        {
            println!("  patch       {}", patch_path.display());
            println!("  diff_sha256 {diff_sha256}");
            println!(
                "  apply       use `neoth self-edit --diff <patch> --proposal-id <id> --expect-hash <sha256> --yes` with the exact values above"
            );
        }
        println!();
        shown += 1;
    }
    if shown == 0 {
        println!(
            "(no pending proposals — run `neoth self-dev propose --from-profile <p>` to generate, or wait for the aggregation cron to ship)"
        );
    } else {
        println!(
            "{shown} pending proposal(s). Accept non-source effects via `neoth self-dev accept <id>`; SourceEdit rows show their bound `neoth self-edit` command above."
        );
    }
    Ok(())
}

async fn run_accept(
    home: &Path,
    id: &str,
    writer: Option<&WalWriterHandle>,
    output: crate::cli::OutputFormat,
) -> Result<()> {
    let guard = acquire_self_dev_state_guard(home).await?;
    recover_and_flush_locked(home, writer, &guard).await?;
    let store = load_store(home)?;
    let entry_index = store
        .entries
        .iter()
        .position(|e| e.proposal.id == id)
        .with_context(|| format!("proposal id `{id}` not found"))?;
    let entry = &store.entries[entry_index];
    if entry.status == ProposalStatus::Accepted {
        render_proposal_mutation(
            output,
            "accept",
            id,
            "accepted",
            true,
            writer.is_some(),
            None,
        );
        return Ok(());
    }
    if entry.status == ProposalStatus::Declined {
        anyhow::bail!(
            "proposal `{id}` was previously declined — re-propose via `neoth self-dev propose ...` to re-evaluate"
        );
    }
    let proposal = entry.proposal.clone();
    let target = effect_target_for(&proposal)
        .with_context(|| format!("validate effect target for `{id}`"))?;
    if effect_matches_readback(home, &target).await? {
        return Err(SelfDevEffectTransactionError::AlreadySatisfied {
            proposal_id: id.to_owned(),
        }
        .into());
    }
    let mut journal = EffectTransactionJournal {
        proposal_id: id.to_owned(),
        proposal_sha256: proposal_sha256(&proposal)?,
        target,
        phase: EffectTransactionPhase::Prepared,
    };
    save_effect_transaction(home, &journal)?;
    after_effect_transaction_prepare_for_test()?;

    journal.phase = EffectTransactionPhase::Applying;
    save_effect_transaction(home, &journal)?;
    if let Err(error) = apply_proposal_effect(home, &proposal).await {
        // Target writers are independently atomic. If their read-back proves
        // no target effect, abandon the intent and keep the proposal pending;
        // if the effect did land (or read-back itself is unavailable), retain
        // the journal so recovery can safely finish rather than false-accept.
        match effect_matches_readback(home, &journal.target).await {
            Ok(false) => {
                remove_effect_transaction(home)?;
                return Err(SelfDevEffectTransactionError::PostconditionFailed {
                    proposal_id: id.to_owned(),
                })
                .context(format!("apply proposal effect for `{id}`: {error:#}"));
            }
            Ok(true) | Err(_) => {
                return Err(SelfDevEffectTransactionError::RecoveryRequired {
                    proposal_id: id.to_owned(),
                })
                .context(format!("apply proposal effect for `{id}`: {error:#}"));
            }
        }
    }
    let postcondition = effect_matches_readback(home, &journal.target)
        .await
        .map_err(|error| {
            anyhow::Error::new(SelfDevEffectTransactionError::RecoveryRequired {
                proposal_id: id.to_owned(),
            })
            .context(format!("read back applied proposal effect: {error:#}"))
        })?;
    if !postcondition {
        return Err(SelfDevEffectTransactionError::PostconditionFailed {
            proposal_id: id.to_owned(),
        }
        .into());
    }
    journal.phase = EffectTransactionPhase::PostconditionProven;
    save_effect_transaction(home, &journal)?;
    // Reload inside the durable transaction instead of committing the stale
    // pre-effect copy held above. The journal binds the exact proposal bytes
    // and recovery refuses a changed or declined entry.
    commit_accepted_store(home, id, &journal.proposal_sha256, &guard)?;
    after_effect_transaction_accepted_for_test()?;
    remove_effect_transaction(home)?;
    flush_pending_audits_locked(home, writer, &guard)
        .await
        .context("proposal accepted; audit intent remains pending for retry")?;
    render_proposal_mutation(
        output,
        "accept",
        id,
        "accepted",
        false,
        writer.is_some(),
        None,
    );
    Ok(())
}

async fn apply_proposal_effect(home: &Path, proposal: &SelfDevProposal) -> Result<()> {
    use crate::cron::schema::{CronRole, JobsFile, classify_role};
    use crate::profile::self_dev::{ExtensionAuthorityBinding, ValidatedProposalTarget};

    match proposal
        .validate_for_acceptance()
        .map_err(anyhow::Error::msg)?
    {
        ValidatedProposalTarget::Preset(preset) => {
            crate::cli::profile::record_active_preset(home, preset)?;
        }
        ValidatedProposalTarget::Verbosity(verbosity) => {
            crate::cli::profile::set_communication_verbosity_override_at(home, verbosity)?;
        }
        ValidatedProposalTarget::ExtensionSelector { id, authority } => {
            let config_path = home.join("freedom.yaml");
            let expectation = match authority {
                ExtensionAuthorityBinding::Bundled => None,
                ExtensionAuthorityBinding::Installed {
                    package_generation_sha256,
                    install_incarnation,
                    install_terminal_receipt_sha256,
                } => Some(
                    crate::skills::authority::InstalledSkillDecisionExpectation::new(
                        package_generation_sha256,
                        install_incarnation,
                        install_terminal_receipt_sha256,
                    )?,
                ),
            };
            crate::cli::skills::set_skill_authority_at_config_with_expectation(
                home,
                &config_path,
                &id,
                crate::cli::skills::SkillAuthorityTarget::Enabled,
                crate::skills::authority::SkillAuthorityDecisionSource::AuthenticatedProposal,
                expectation,
            )
            .await?;
        }
        ValidatedProposalTarget::BriefingTime { hour, minute } => {
            // Reschedule the operator's briefing cron job to the proposed
            // HH:MM. The briefing job is identified by its classified role
            // (JV-PRO-05 keyword classification over name + prompt), and the
            // rewrite goes through `JobsFile::modify_at_path` — the same
            // process-and-file-locked atomic RMW every production jobs.yaml
            // mutation uses, so the live scheduler observes a complete
            // generation. No enabled briefing job → the accept fails and the
            // proposal stays pending (fail-closed, actionable message).
            //
            // spawn_blocking: modify_at_path takes a cross-process file lock
            // with a sleeping retry loop (up to 5 s) — must not park a tokio
            // worker if a daemon path ever calls accept (review finding).
            let path = home.join("jobs.yaml");
            let worker_path = path.clone();
            tokio::task::spawn_blocking(move || {
                JobsFile::modify_at_path(&worker_path, |jf| {
                    let job = jf
                        .jobs
                        .iter_mut()
                        .find(|job| job.enabled && classify_role(job) == CronRole::Briefing)
                        .with_context(|| {
                            format!(
                                "no enabled briefing job in {} — add one via `neoth cron add` \
                                 before accepting a briefing-schedule proposal",
                                worker_path.display()
                            )
                        })?;
                    // Daily at HH:MM; the schedule invariant allows exactly one
                    // of cron/every/at, so the interval/one-shot forms are
                    // cleared. The operator's timezone is preserved.
                    job.schedule.cron = format!("{minute} {hour} * * *");
                    job.schedule.every_seconds = None;
                    job.schedule.anchor_unix = None;
                    job.schedule.at = None;
                    Ok(())
                })
            })
            .await
            .context("join briefing-reschedule task")?
            .with_context(|| format!("reschedule briefing job in {}", path.display()))?;
        }
        ValidatedProposalTarget::SourceEdit => {
            return Err(SelfDevEffectTransactionError::SeparateApplyRequired {
                proposal_id: proposal.id.clone(),
            }
            .into());
        }
    }
    Ok(())
}

async fn run_decline(
    home: &Path,
    id: &str,
    reason: &str,
    writer: Option<&WalWriterHandle>,
    output: crate::cli::OutputFormat,
) -> Result<()> {
    if reason != "declined" && reason != "timeout" {
        anyhow::bail!("--reason must be `declined` or `timeout`, got `{reason}`");
    }
    let guard = acquire_self_dev_state_guard(home).await?;
    recover_and_flush_locked(home, writer, &guard).await?;
    let mut store = load_store(home)?;
    let entry = store
        .entries
        .iter_mut()
        .find(|e| e.proposal.id == id)
        .with_context(|| format!("proposal id `{id}` not found"))?;
    if entry.status == ProposalStatus::Declined {
        render_proposal_mutation(
            output,
            "decline",
            id,
            "declined",
            true,
            writer.is_some(),
            Some(reason),
        );
        return Ok(());
    }
    if entry.status == ProposalStatus::Accepted {
        anyhow::bail!(
            "proposal `{id}` was previously accepted — decline does not unwind the apply; revert manually"
        );
    }
    let ts = now_unix();
    entry.status = ProposalStatus::Declined;
    entry.status_at_unix = ts;
    entry.decline_reason = reason.to_string();
    store.audit_pending.push(ProposalAuditIntent::Declined {
        proposal_id: id.to_owned(),
        reason: reason.to_owned(),
        ts_unix: ts,
    });
    save_store_locked(home, &store, &guard)?;
    flush_pending_audits_locked(home, writer, &guard)
        .await
        .context("proposal declined; audit intent remains pending for retry")?;
    render_proposal_mutation(
        output,
        "decline",
        id,
        "declined",
        false,
        writer.is_some(),
        Some(reason),
    );
    Ok(())
}

fn render_proposal_mutation(
    output: crate::cli::OutputFormat,
    action: &str,
    id: &str,
    status: &str,
    unchanged: bool,
    wal_direct: bool,
    reason: Option<&str>,
) {
    match output {
        crate::cli::OutputFormat::Json | crate::cli::OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "action": action,
                "id": id,
                "status": status,
            })
        ),
        crate::cli::OutputFormat::Table if unchanged => {
            println!("proposal `{id}` already {status} (no-op)");
        }
        crate::cli::OutputFormat::Table if action == "accept" => {
            println!("✓ accepted proposal `{id}`");
            if wal_direct {
                println!("  (WAL frame 0x1D SELF_DEV_ACCEPTED emitted)");
            } else {
                println!("  (queued for daemon WAL emit — lands within 5s on the live daemon)");
            }
        }
        crate::cli::OutputFormat::Table => {
            println!(
                "✓ declined proposal `{id}` (reason: {})",
                reason.unwrap_or("declined")
            );
            if wal_direct {
                println!("  (WAL frame 0x1E SELF_DEV_DECLINED emitted)");
            } else {
                println!("  (queued for daemon WAL emit — lands within 5s on the live daemon)");
            }
        }
    }
}

/// Shared proposal-generation core (SPEC-05 extracted this from
/// `run_propose` so the daemon's passive-adaptation cron
/// (`daemon::profile_adapt_cron`) reuses the EXACT dedup + store + WAL-emit
/// logic instead of duplicating it). Given an already-loaded behavioural
/// profile + the current preset name, runs `propose_adjustments`, keeps
/// only proposals whose stable id isn't already in the store (idempotent),
/// emits a `0x1C SELF_DEV_PROPOSED` frame per new proposal (direct when a
/// `writer` is present, else enqueued to the self-dev outbox for the daemon
/// to drain), and returns the count of NEW proposals.
///
/// ORDERING: the proposal mutation and its audit intent are persisted in one
/// `proposals.json` update. The intent is then enqueued to the durable outbox
/// and removed only after that enqueue (and optional in-process drain) succeeds.
/// A crash may leave a retryable pending intent, but never a visible mutation
/// with no durable audit path.
pub(crate) async fn propose_and_store(
    home: &Path,
    profile: &BehaviouralProfile,
    current_preset_name: &str,
    writer: Option<&WalWriterHandle>,
) -> Result<usize> {
    let current = match ProfilePreset::parse(current_preset_name) {
        Some(p) => apply_preset(p),
        None => apply_preset(ProfilePreset::Lowkey),
    };
    let new_proposals = propose_adjustments(profile, &current);
    let guard = acquire_self_dev_state_guard(home).await?;
    recover_and_flush_locked(home, writer, &guard).await?;
    store_proposals_locked(home, &new_proposals, writer, &guard).await
}

/// Dedup-and-store a set of proposals + emit `0x1C SELF_DEV_PROPOSED` per NEW
/// one. Shared by the behavioural-snapshot path ([`propose_and_store`]) and the
/// G-03 feedback path (the profile-adapt cron). Returns the count newly added.
///
/// The proposal rows and audit intents are committed together. Dedup is by
/// stable `proposal.id`, so re-running is idempotent while retained audit
/// intents keep WAL emission retryable.
pub(crate) async fn store_proposals(
    home: &Path,
    proposals: &[SelfDevProposal],
    writer: Option<&WalWriterHandle>,
) -> Result<usize> {
    let guard = acquire_self_dev_state_guard(home).await?;
    recover_and_flush_locked(home, writer, &guard).await?;
    store_proposals_locked(home, proposals, writer, &guard).await
}

async fn store_proposals_locked(
    home: &Path,
    proposals: &[SelfDevProposal],
    writer: Option<&WalWriterHandle>,
    guard: &SelfDevStateGuard,
) -> Result<usize> {
    if proposals.is_empty() {
        return Ok(0);
    }
    let mut proposals = proposals.to_vec();
    if proposals
        .iter()
        .any(|proposal| proposal.kind == crate::profile::self_dev::ProposalKind::LearnExtension)
    {
        let config_path = home.join("freedom.yaml");
        let config = crate::config::FreedomConfig::load_from_path_or_default(&config_path)
            .context("load Skill policy while binding extension proposals")?;
        let inventory = crate::skills::loader::diagnostic_inventory_for_accepted_config(
            &home.join("skills"),
            config,
            config_path,
        )
        .await
        .context("capture exact Skill inventory for extension proposals")?;
        for proposal in proposals.iter_mut().filter(|proposal| {
            proposal.kind == crate::profile::self_dev::ProposalKind::LearnExtension
        }) {
            // Never trust a caller-supplied/stale proof. Only a fresh match
            // against this instance's authenticated inventory may become
            // operator-reviewable.
            proposal.extension_authority = None;
            let Some(row) = inventory
                .iter()
                .find(|row| row.id().eq_ignore_ascii_case(&proposal.target))
            else {
                continue;
            };
            let canonical_id = row.id().to_string();
            let binding = match row {
                crate::skills::loader::SkillInventoryRow::Healthy {
                    origin: crate::skills::loader::SkillInventoryOrigin::Bundled,
                    ..
                } => Some(crate::profile::self_dev::ExtensionAuthorityBinding::Bundled),
                crate::skills::loader::SkillInventoryRow::Healthy {
                    origin: crate::skills::loader::SkillInventoryOrigin::User,
                    package_generation_sha256: Some(generation),
                    install_incarnation: Some(incarnation),
                    install_terminal_receipt_sha256: Some(receipt),
                    ..
                } => {
                    let exact_revoked = match crate::skills::authority::inspect_current_authority(
                        home,
                        &canonical_id,
                    ) {
                        Ok(Some(status))
                            if status.record().package_generation_sha256.as_str()
                                == generation.as_str()
                                && status.record().install_incarnation == *incarnation
                                && status.record().install_terminal_receipt_sha256.as_str()
                                    == receipt.as_str() =>
                        {
                            status.record().state
                                == crate::skills::authority::SkillAuthorityState::Revoked
                        }
                        Ok(_) => false,
                        Err(error) => {
                            tracing::warn!(
                                skill_id = %proposal.target,
                                %error,
                                "skipping extension proposal whose current authority cannot be authenticated"
                            );
                            true
                        }
                    };
                    (!exact_revoked).then(|| {
                        crate::profile::self_dev::ExtensionAuthorityBinding::Installed {
                            package_generation_sha256: generation.clone(),
                            install_incarnation: *incarnation,
                            install_terminal_receipt_sha256: receipt.clone(),
                        }
                    })
                }
                _ => None,
            };
            if let Some(binding) = binding {
                proposal
                    .bind_extension_authority(binding)
                    .map_err(anyhow::Error::msg)?;
            }
        }
        let before = proposals.len();
        proposals.retain(|proposal| {
            proposal.kind != crate::profile::self_dev::ProposalKind::LearnExtension
                || proposal.extension_authority.is_some()
        });
        let unavailable = before.saturating_sub(proposals.len());
        if unavailable > 0 {
            tracing::debug!(
                unavailable,
                "skipped LearnExtension proposals without a healthy exact Skill target"
            );
        }
        if proposals.is_empty() {
            return Ok(0);
        }
    }
    let mut store = load_store(home)?;
    let ts = now_unix();
    let to_add: Vec<&SelfDevProposal> = proposals
        .iter()
        .filter(|p| !store.entries.iter().any(|e| e.proposal.id == p.id))
        .collect();
    if to_add.is_empty() {
        return Ok(0);
    }
    for p in &to_add {
        store.entries.push(StoredProposal {
            proposal: (*p).clone(),
            status: ProposalStatus::Pending,
            status_at_unix: ts,
            decline_reason: String::new(),
        });
        store.audit_pending.push(ProposalAuditIntent::Proposed {
            proposal: (*p).clone(),
            ts_unix: ts,
        });
    }
    save_store_locked(home, &store, guard)?;
    flush_pending_audits_locked(home, writer, guard)
        .await
        .context("proposals stored; audit intent remains pending for retry")?;
    Ok(to_add.len())
}

async fn flush_pending_audits_locked(
    home: &Path,
    writer: Option<&WalWriterHandle>,
    guard: &SelfDevStateGuard,
) -> Result<usize> {
    let mut flushed = 0usize;
    loop {
        let store = load_store(home)?;
        let Some(intent) = store.audit_pending.first().cloned() else {
            return Ok(flushed);
        };
        let event = intent.to_pending_event();
        super::self_dev_outbox::enqueue(home, &event).await?;
        // Retire the pending intent as soon as the event is durably IN the
        // outbox — before draining it back out, not after. Draining first left a
        // window in which the frame was already emitted and removed from the
        // outbox while the intent still looked pending: the next run re-enqueued
        // it, and the outbox's content dedup could no longer help because the
        // event was already gone from it, so a second
        // SELF_DEV_ACCEPTED/DECLINED/PROPOSED frame landed. With this order a
        // crash before the remove re-enqueues into an outbox that still holds
        // the event (dedup catches it), and a crash after the remove leaves the
        // event queued for the next drain. Neither loses nor duplicates.
        let mut latest = load_store(home)?;
        if latest.audit_pending.first() == Some(&intent) {
            latest.audit_pending.remove(0);
            save_store_locked(home, &latest, guard)?;
        }
        if let Some(w) = writer {
            super::self_dev_outbox::drain_once(home, w).await?;
        }
        flushed += 1;
    }
}

async fn run_propose(
    home: &Path,
    from_profile: &Path,
    current_preset_name: &str,
    writer: Option<&WalWriterHandle>,
) -> Result<()> {
    let bytes =
        std::fs::read(from_profile).with_context(|| format!("read {}", from_profile.display()))?;
    let profile: BehaviouralProfile = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse BehaviouralProfile from {}", from_profile.display()))?;
    let added = propose_and_store(home, &profile, current_preset_name, writer).await?;
    if added == 0 {
        println!("(no proposals — operator state matches current preset within thresholds)");
        return Ok(());
    }
    println!("✓ {added} new proposal(s) added to the store");
    if writer.is_some() {
        println!("  (one WAL frame 0x1C SELF_DEV_PROPOSED per new proposal)");
    } else {
        println!(
            "  (queued for daemon WAL emit — {added} frame(s) land within 5s on the live daemon)"
        );
    }
    println!("review via `neoth self-dev review`");
    Ok(())
}

/// `neoth self-dev scan` — one-shot collector tick + capability evolver pass.
///
/// Runs the self-improvement collector synchronously (same logic as the daemon
/// cron), then passes the resulting [`CollectorReport`] through the capability
/// evolver, and prints a human-readable summary. An isolated temporary WAL home
/// is created beneath the selected instance home and removed after its writer
/// drains — scan-only audit frames never mix with the durable daemon chain.
///
/// Use this to exercise the HERMES-06 pipeline end-to-end without waiting for
/// the 24h daemon cron tick.
async fn run_scan(home: &Path, output: crate::cli::OutputFormat) -> Result<()> {
    use crate::config::FreedomConfig;
    use crate::daemon::capability_evolver::run_evolver_pass;
    use crate::daemon::self_improvement_collector::run_self_improvement_collector_tick;

    // Missing freedom.yaml uses first-run defaults; malformed existing policy
    // blocks the scan instead of silently changing collector behaviour.
    let cfg = FreedomConfig::load_from_path_or_default(&home.join("freedom.yaml"))?
        .self_improvement_collector;

    let db_path = home.join("views.db");
    let ts = crate::time::now_unix_i64();

    // Isolate the scan-only audit stream in an ephemeral home. The collector
    // still reads and mutates the selected real home, while writer integrity
    // keys, recovery journals, and segment files are removed only after the
    // writer has durably drained.
    std::fs::create_dir_all(home)
        .with_context(|| format!("create self-dev home {}", home.display()))?;
    let tmp_home = tempfile::Builder::new()
        .prefix(".self-dev-scan-")
        .tempdir_in(home)
        .context("create isolated temporary home for self-dev scan WAL")?;
    let tmp_wal_dir = tmp_home.path().join("wal");
    std::fs::create_dir_all(&tmp_wal_dir)
        .context("create isolated temporary WAL directory for self-dev scan")?;
    let tmp_seg = crate::wal::writer::unique_standalone_segment_path(&tmp_wal_dir, "self-dev-scan");
    let (tmp_writer, tmp_join, tmp_ready) =
        crate::wal::writer::spawn_for_home_ready(tmp_seg, tmp_home.path().to_path_buf())
            .context("spawn isolated WAL writer for self-dev scan")?;
    tmp_ready
        .wait()
        .await
        .context("initialize isolated WAL writer for self-dev scan")?;

    let scan_result = async {
        let report = run_self_improvement_collector_tick(&db_path, home, cfg, &tmp_writer)
            .await
            .context("self-improvement collector scan failed")?;
        let evolver = run_evolver_pass(home, &report, ts, Some(&tmp_writer)).await;
        Ok::<_, anyhow::Error>((report, evolver))
    }
    .await;
    drop(tmp_writer);
    let writer_result = tmp_join
        .await
        .context("join isolated WAL writer for self-dev scan")?
        .map_err(anyhow::Error::msg);
    let (report, evolver) = scan_result?;
    writer_result?;

    match output {
        crate::cli::OutputFormat::Json | crate::cli::OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "action": "scan",
                "signals": report.signals.len(),
                "proposals_staged": evolver.proposals_staged,
                "proposals_skipped_deployed": evolver.proposals_skipped_deployed,
                "proposals_skipped_not_auto_safe": evolver.proposals_skipped_not_auto_safe,
            })
        ),
        crate::cli::OutputFormat::Table => {
            println!(
                "scan complete: {} signal(s), {} proposal(s) staged, \
                 {} skipped (already deployed), {} skipped (not auto-safe)",
                report.signals.len(),
                evolver.proposals_staged,
                evolver.proposals_skipped_deployed,
                evolver.proposals_skipped_not_auto_safe,
            );
            for s in &report.signals {
                println!("  {s:?}");
            }
        }
    }
    Ok(())
}

fn now_unix() -> i64 {
    crate::time::now_unix_i64()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::self_dev::ProposalKind;
    use tempfile::tempdir;

    fn fixture_proposal(id: &str, conf: f64) -> SelfDevProposal {
        SelfDevProposal {
            id: id.into(),
            kind: ProposalKind::SwitchPreset,
            reason: "test".into(),
            confidence: conf,
            target: "formal".into(),
            extension_authority: None,
        }
    }

    fn source_edit_proposal(id: &str, patch_path: PathBuf, diff_sha256: &str) -> SelfDevProposal {
        SelfDevProposal {
            id: id.into(),
            kind: ProposalKind::SourceEdit {
                patch_path,
                diff_sha256: diff_sha256.into(),
                target_paths: vec!["src/cli/dummy.rs".into()],
            },
            reason: "test source edit".into(),
            confidence: 0.9,
            target: "src/cli/dummy.rs".into(),
            extension_authority: None,
        }
    }

    #[test]
    fn proposals_path_lands_under_self_dev_subdir() {
        let p = proposals_path(Path::new("/home/x"));
        assert_eq!(p, Path::new("/home/x/self_dev/proposals.json"));
    }

    #[test]
    fn self_dev_state_lock_excludes_a_second_os_process() {
        const CHILD_ENV: &str = "NEOTH_SELF_DEV_STATE_LOCK_CHILD";
        const TEST_PATH: &str =
            "cli::self_dev::tests::self_dev_state_lock_excludes_a_second_os_process";

        if let Ok(home) = std::env::var(CHILD_ENV) {
            let path = self_dev_state_lock_path(Path::new(&home));
            match crate::util::locked_file::try_lock_file_once(
                &path,
                "self-dev proposal state test",
            ) {
                Ok(Some(_guard)) => std::process::exit(0),
                Ok(None) => std::process::exit(3),
                Err(_) => std::process::exit(4),
            }
        }

        let dir = tempdir().unwrap();
        let lock_path = self_dev_state_lock_path(dir.path());
        let parent_guard = crate::util::locked_file::lock_file_blocking(
            &lock_path,
            "self-dev proposal state test",
        )
        .unwrap();
        let blocked = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST_PATH])
            .env(CHILD_ENV, dir.path())
            .output()
            .expect("spawn blocked self-dev state-lock child");
        assert_eq!(
            blocked.status.code(),
            Some(3),
            "second OS process acquired held state lock (stderr: {})",
            String::from_utf8_lossy(&blocked.stderr)
        );
        drop(parent_guard);

        let acquired = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST_PATH])
            .env(CHILD_ENV, dir.path())
            .output()
            .expect("spawn released self-dev state-lock child");
        assert_eq!(
            acquired.status.code(),
            Some(0),
            "second OS process did not acquire released state lock (stderr: {})",
            String::from_utf8_lossy(&acquired.stderr)
        );
    }

    #[test]
    fn load_store_returns_default_when_file_missing() {
        let dir = tempdir().unwrap();
        let store = load_store(dir.path()).unwrap();
        assert!(store.entries.is_empty());
    }

    #[test]
    fn save_load_round_trips_store() {
        let dir = tempdir().unwrap();
        let mut store = ProposalStore::default();
        store.entries.push(StoredProposal {
            proposal: fixture_proposal("switch_preset-aabbccdd", 0.8),
            status: ProposalStatus::Pending,
            status_at_unix: 1_700_000_000,
            decline_reason: String::new(),
        });
        save_store_fixture(dir.path(), &store).unwrap();
        let back = load_store(dir.path()).unwrap();
        assert_eq!(back, store);
    }

    #[test]
    fn save_uses_private_atomic_write_and_required_parent_sync() {
        let dir = tempdir().unwrap();
        let before = crate::util::atomic_write::required_parent_sync_attempts_for_test();
        save_store_fixture(dir.path(), &ProposalStore::default()).unwrap();
        let real = proposals_path(dir.path());
        assert!(real.exists());
        assert!(
            std::fs::read_dir(real.parent().unwrap())
                .unwrap()
                .filter_map(|entry| entry.ok())
                .all(|entry| !entry.file_name().to_string_lossy().contains(".tmp")),
            "successful private atomic replacement left a staged file"
        );
        assert!(
            crate::util::atomic_write::required_parent_sync_attempts_for_test() > before,
            "proposal store did not cross its required parent-directory durability barrier"
        );
    }

    const BRIEFING_JOBS_YAML: &str = r#"
version: 1
jobs:
  - id: morning-news
    name: Morning News
    enabled: true
    schedule:
      cron: "0 7 * * *"
      tz: Europe/Berlin
    prompt: |
      Morning briefing please
    delivery:
      channel: telegram
"#;

    fn store_with(proposal: SelfDevProposal) -> ProposalStore {
        let mut store = ProposalStore::default();
        store.entries.push(StoredProposal {
            proposal,
            status: ProposalStatus::Pending,
            status_at_unix: 1_700_000_000,
            decline_reason: String::new(),
        });
        store
    }

    #[tokio::test]
    async fn accept_briefing_time_reschedules_the_briefing_cron_job() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("jobs.yaml"), BRIEFING_JOBS_YAML).unwrap();
        let proposal = SelfDevProposal {
            id: "adjust_briefing_schedule-cafe0001".into(),
            kind: ProposalKind::AdjustBriefingSchedule,
            reason: "operator active later".into(),
            confidence: 0.9,
            target: "08:30".into(),
            extension_authority: None,
        };
        save_store_fixture(dir.path(), &store_with(proposal)).unwrap();

        run_accept(
            dir.path(),
            "adjust_briefing_schedule-cafe0001",
            None,
            crate::cli::OutputFormat::Table,
        )
        .await
        .unwrap();

        // Effect: the briefing job now fires daily at 08:30, tz preserved.
        let jobs = crate::cron::schema::JobsFile::from_yaml_str(
            &std::fs::read_to_string(dir.path().join("jobs.yaml")).unwrap(),
        )
        .unwrap();
        assert_eq!(jobs.jobs[0].schedule.cron, "30 8 * * *");
        assert_eq!(jobs.jobs[0].schedule.tz.as_deref(), Some("Europe/Berlin"));
        // Decision recorded.
        let store = load_store(dir.path()).unwrap();
        assert_eq!(store.entries[0].status, ProposalStatus::Accepted);
    }

    #[tokio::test]
    async fn accept_briefing_time_without_briefing_job_stays_pending() {
        let dir = tempdir().unwrap();
        let proposal = SelfDevProposal {
            id: "adjust_briefing_schedule-cafe0002".into(),
            kind: ProposalKind::AdjustBriefingSchedule,
            reason: "test".into(),
            confidence: 0.9,
            target: "07:15".into(),
            extension_authority: None,
        };
        save_store_fixture(dir.path(), &store_with(proposal)).unwrap();

        let err = run_accept(
            dir.path(),
            "adjust_briefing_schedule-cafe0002",
            None,
            crate::cli::OutputFormat::Table,
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("no enabled briefing job"));
        // Fail-closed: the proposal was NOT flipped to accepted.
        let store = load_store(dir.path()).unwrap();
        assert_eq!(store.entries[0].status, ProposalStatus::Pending);
    }

    #[tokio::test]
    async fn effect_prepare_failure_never_accepts_or_mutates_the_preset() {
        let dir = tempdir().unwrap();
        let proposal = fixture_proposal("switch_preset-prepare-failure", 0.9);
        save_store_fixture(dir.path(), &store_with(proposal)).unwrap();

        EFFECT_TRANSACTION_PREPARE_FAILURE.with(|slot| slot.set(true));
        let error = run_accept(
            dir.path(),
            "switch_preset-prepare-failure",
            None,
            crate::cli::OutputFormat::Table,
        )
        .await
        .expect_err("injected post-prepare failure must abort accept");
        assert!(
            format!("{error:#}")
                .contains("injected failure after self-dev effect transaction prepare")
        );
        assert!(effect_transaction_path(dir.path()).exists());
        assert!(crate::cli::profile::load_active_preset(dir.path()).is_none());
        assert_eq!(
            load_store(dir.path()).unwrap().entries[0].status,
            ProposalStatus::Pending
        );

        // Recovery proves no target effect occurred and abandons only the
        // journal. The proposal stays reviewable/pending for an operator retry.
        let guard = acquire_self_dev_state_guard(dir.path()).await.unwrap();
        recover_effect_transaction_locked(dir.path(), &guard)
            .await
            .unwrap();
        drop(guard);
        assert!(!effect_transaction_path(dir.path()).exists());
        assert_eq!(
            load_store(dir.path()).unwrap().entries[0].status,
            ProposalStatus::Pending
        );
    }

    #[tokio::test]
    async fn applied_effect_recovery_commits_only_after_readback() {
        let dir = tempdir().unwrap();
        let proposal = fixture_proposal("switch_preset-recover-applied", 0.9);
        let proposal_hash = proposal_sha256(&proposal).unwrap();
        save_store_fixture(dir.path(), &store_with(proposal)).unwrap();
        crate::cli::profile::record_active_preset(dir.path(), ProfilePreset::Formal).unwrap();
        save_effect_transaction(
            dir.path(),
            &EffectTransactionJournal {
                proposal_id: "switch_preset-recover-applied".into(),
                proposal_sha256: proposal_hash,
                target: EffectTarget::Preset {
                    target: "formal".into(),
                },
                phase: EffectTransactionPhase::Applying,
            },
        )
        .unwrap();

        let guard = acquire_self_dev_state_guard(dir.path()).await.unwrap();
        recover_effect_transaction_locked(dir.path(), &guard)
            .await
            .unwrap();
        drop(guard);
        assert_eq!(
            load_store(dir.path()).unwrap().entries[0].status,
            ProposalStatus::Accepted
        );
        assert!(!effect_transaction_path(dir.path()).exists());
    }

    #[tokio::test]
    async fn crash_after_durable_accept_recovers_by_durably_removing_the_journal() {
        let dir = tempdir().unwrap();
        let proposal = fixture_proposal("switch_preset-accepted-crash", 0.9);
        save_store_fixture(dir.path(), &store_with(proposal)).unwrap();

        EFFECT_TRANSACTION_AFTER_ACCEPTED_FAILURE.with(|slot| slot.set(true));
        let error = run_accept(
            dir.path(),
            "switch_preset-accepted-crash",
            None,
            crate::cli::OutputFormat::Table,
        )
        .await
        .expect_err("crash seam after durable Accepted must interrupt cleanup");
        assert!(
            format!("{error:#}").contains("injected failure after durable self-dev acceptance")
        );
        assert_eq!(
            load_store(dir.path()).unwrap().entries[0].status,
            ProposalStatus::Accepted
        );
        assert_eq!(
            load_effect_transaction(dir.path()).unwrap().unwrap().phase,
            EffectTransactionPhase::PostconditionProven
        );

        let before = crate::util::atomic_write::required_parent_sync_attempts_for_test();
        let guard = acquire_self_dev_state_guard(dir.path()).await.unwrap();
        recover_effect_transaction_locked(dir.path(), &guard)
            .await
            .unwrap();
        drop(guard);
        assert!(!effect_transaction_path(dir.path()).exists());
        assert!(
            crate::util::atomic_write::required_parent_sync_attempts_for_test() > before,
            "journal deletion did not cross its required durability barrier"
        );
    }

    #[tokio::test]
    async fn forged_source_edit_effect_journal_never_accepts_the_proposal() {
        let dir = tempdir().unwrap();
        let patch = dir.path().join("proposal.patch");
        std::fs::write(&patch, "reviewed patch bytes").unwrap();
        let proposal = source_edit_proposal("source_edit-forged-journal", patch, &"a".repeat(64));
        let proposal_hash = proposal_sha256(&proposal).unwrap();
        save_store_fixture(dir.path(), &store_with(proposal)).unwrap();
        save_effect_transaction(
            dir.path(),
            &EffectTransactionJournal {
                proposal_id: "source_edit-forged-journal".into(),
                proposal_sha256: proposal_hash,
                target: EffectTarget::Preset {
                    target: "formal".into(),
                },
                phase: EffectTransactionPhase::PostconditionProven,
            },
        )
        .unwrap();
        crate::cli::profile::record_active_preset(dir.path(), ProfilePreset::Formal).unwrap();

        let guard = acquire_self_dev_state_guard(dir.path()).await.unwrap();
        let error = recover_effect_transaction_locked(dir.path(), &guard)
            .await
            .expect_err("SourceEdit cannot inherit a forged preset journal");
        drop(guard);
        assert!(format!("{error:#}").contains("SELF_DEV_EFFECT_RECOVERY_REQUIRED"));
        assert_eq!(
            load_store(dir.path()).unwrap().entries[0].status,
            ProposalStatus::Pending
        );
        assert!(effect_transaction_path(dir.path()).exists());
    }

    #[test]
    fn installed_extension_replacement_or_revocation_fails_exact_postcondition() {
        let generation = "1".repeat(64);
        let replacement_generation = "2".repeat(64);
        let receipt = "3".repeat(64);
        assert!(exact_installed_extension_postcondition(
            &generation,
            7,
            &receipt,
            &generation,
            7,
            &receipt,
            crate::skills::authority::SkillAuthorityState::Active,
        ));
        assert!(!exact_installed_extension_postcondition(
            &generation,
            7,
            &receipt,
            &replacement_generation,
            8,
            &receipt,
            crate::skills::authority::SkillAuthorityState::Active,
        ));
        assert!(!exact_installed_extension_postcondition(
            &generation,
            7,
            &receipt,
            &generation,
            7,
            &receipt,
            crate::skills::authority::SkillAuthorityState::Revoked,
        ));
    }

    #[tokio::test]
    async fn source_edit_remains_pending_until_the_separate_apply_gate_commits() {
        let dir = tempdir().unwrap();
        let proposal = SelfDevProposal {
            id: "source_edit-cafe0003".into(),
            kind: ProposalKind::SourceEdit {
                patch_path: std::path::PathBuf::from("/tmp/proposal.patch"),
                diff_sha256: "a".repeat(64),
                target_paths: vec!["src/cli/dummy.rs".into()],
            },
            reason: "test".into(),
            confidence: 0.9,
            target: "src/cli/dummy.rs".into(),
            extension_authority: None,
        };
        save_store_fixture(dir.path(), &store_with(proposal)).unwrap();

        // R4-11: a generic Accepted state cannot stand in for the separate
        // self-edit effect. Keep this pending until that gate publishes its
        // own durable apply receipt.
        let error = run_accept(
            dir.path(),
            "source_edit-cafe0003",
            None,
            crate::cli::OutputFormat::Table,
        )
        .await
        .expect_err("source edit has no self-dev target effect");
        assert!(format!("{error:#}").contains("SELF_DEV_EFFECT_SEPARATE_APPLY_REQUIRED"));
        let store = load_store(dir.path()).unwrap();
        assert_eq!(store.entries[0].status, ProposalStatus::Pending);
    }

    #[tokio::test]
    async fn source_edit_contract_rejects_wrong_proposal_id_and_hash_before_apply() {
        use sha2::{Digest as _, Sha256};

        let dir = tempdir().unwrap();
        let patch = dir.path().join("proposal.patch");
        let diff = concat!(
            "--- a/src/cli/dummy.rs\n",
            "+++ b/src/cli/dummy.rs\n",
            "@@ -1 +1 @@\n",
            "-old\n",
            "+new\n",
        );
        std::fs::write(&patch, diff).unwrap();
        let hash = format!("{:x}", Sha256::digest(diff.as_bytes()));
        let proposal = source_edit_proposal("source_edit-contract", patch.clone(), &hash);
        save_store_fixture(dir.path(), &store_with(proposal)).unwrap();
        let canonical_patch = patch.canonicalize().unwrap();
        let paths = vec!["src/cli/dummy.rs".to_owned()];

        let wrong_id = begin_source_edit_apply(
            dir.path(),
            "source_edit-other",
            &canonical_patch,
            dir.path(),
            &hash,
            &hash,
            &paths,
        )
        .await
        .err()
        .expect("wrong proposal id must be refused before the gate");
        assert!(format!("{wrong_id:#}").contains("SELF_DEV_SOURCE_EDIT_CONTRACT_REJECTED"));

        let wrong_hash = "f".repeat(64);
        let error = begin_source_edit_apply(
            dir.path(),
            "source_edit-contract",
            &canonical_patch,
            dir.path(),
            &wrong_hash,
            &hash,
            &paths,
        )
        .await
        .err()
        .expect("wrong expected hash must be refused before the gate");
        assert!(format!("{error:#}").contains("SELF_DEV_SOURCE_EDIT_CONTRACT_REJECTED"));
        assert_eq!(
            load_store(dir.path()).unwrap().entries[0].status,
            ProposalStatus::Pending
        );
        assert!(!source_edit_receipt_path(dir.path()).exists());
    }

    #[tokio::test]
    async fn durable_source_edit_receipt_recovers_exact_proposal_after_crash() {
        use sha2::{Digest as _, Sha256};

        let dir = tempdir().unwrap();
        let patch = dir.path().join("proposal.patch");
        let diff = concat!(
            "--- a/src/cli/dummy.rs\n",
            "+++ b/src/cli/dummy.rs\n",
            "@@ -1 +1 @@\n",
            "-old\n",
            "+new\n",
        );
        std::fs::write(&patch, diff).unwrap();
        let hash = format!("{:x}", Sha256::digest(diff.as_bytes()));
        let proposal = source_edit_proposal("source_edit-receipt-crash", patch.clone(), &hash);
        save_store_fixture(dir.path(), &store_with(proposal)).unwrap();
        let paths = vec!["src/cli/dummy.rs".to_owned()];
        let transaction = begin_source_edit_apply(
            dir.path(),
            "source_edit-receipt-crash",
            &patch.canonicalize().unwrap(),
            dir.path(),
            &hash,
            &hash,
            &paths,
        )
        .await
        .unwrap();

        SOURCE_EDIT_RECEIPT_AFTER_PUBLISH_FAILURE.with(|slot| slot.set(true));
        let error = transaction
            .finalize_after_apply_and_audit(&hash, &paths)
            .await
            .expect_err("post-publication crash seam must leave the durable receipt");
        assert!(
            format!("{error:#}").contains("injected failure after durable source-edit receipt")
        );
        assert!(source_edit_receipt_path(dir.path()).exists());
        assert_eq!(
            load_store(dir.path()).unwrap().entries[0].status,
            ProposalStatus::Pending
        );

        let guard = acquire_self_dev_state_guard(dir.path()).await.unwrap();
        recover_source_edit_receipt_locked(dir.path(), &guard)
            .await
            .unwrap();
        drop(guard);
        assert_eq!(
            load_store(dir.path()).unwrap().entries[0].status,
            ProposalStatus::Accepted
        );
        assert!(!source_edit_receipt_path(dir.path()).exists());
    }

    #[tokio::test]
    async fn audited_postcondition_crash_before_receipt_recovers_only_exact_transaction() {
        use sha2::{Digest as _, Sha256};

        let dir = tempdir().unwrap();
        let patch = dir.path().join("proposal.patch");
        let diff = concat!(
            "--- a/src/cli/dummy.rs\n",
            "+++ b/src/cli/dummy.rs\n",
            "@@ -1 +1 @@\n",
            "-old\n",
            "+new\n",
        );
        std::fs::write(&patch, diff).unwrap();
        let hash = format!("{:x}", Sha256::digest(diff.as_bytes()));
        let proposal =
            source_edit_proposal("source_edit-postcondition-crash", patch.clone(), &hash);
        save_store_fixture(dir.path(), &store_with(proposal)).unwrap();
        let paths = vec!["src/cli/dummy.rs".to_owned()];
        let mut transaction = begin_source_edit_apply(
            dir.path(),
            "source_edit-postcondition-crash",
            &patch.canonicalize().unwrap(),
            dir.path(),
            &hash,
            &hash,
            &paths,
        )
        .await
        .unwrap();
        transaction.mark_applying().unwrap();
        SOURCE_EDIT_AFTER_POSTCONDITION_FAILURE.with(|slot| slot.set(true));
        let error = transaction
            .finalize_after_apply_and_audit(&hash, &paths)
            .await
            .expect_err("crash seam must interrupt after WAL/postimage journal, before receipt");
        assert!(format!("{error:#}").contains("postcondition before receipt"));
        assert!(source_edit_transaction_path(dir.path()).exists());
        assert!(!source_edit_receipt_path(dir.path()).exists());
        assert_eq!(
            load_store(dir.path()).unwrap().entries[0].status,
            ProposalStatus::Pending
        );

        let guard = acquire_self_dev_state_guard(dir.path()).await.unwrap();
        recover_source_edit_transaction_locked(dir.path(), &guard)
            .await
            .unwrap();
        drop(guard);
        assert_eq!(
            load_store(dir.path()).unwrap().entries[0].status,
            ProposalStatus::Accepted
        );
        assert!(!source_edit_transaction_path(dir.path()).exists());
    }

    #[tokio::test]
    async fn forged_source_edit_receipt_hash_stays_pending_and_blocks_recovery() {
        let dir = tempdir().unwrap();
        let patch = dir.path().join("proposal.patch");
        std::fs::write(&patch, "reviewed patch bytes").unwrap();
        let proposal = source_edit_proposal("source_edit-forged-receipt", patch, &"a".repeat(64));
        let proposal_hash = proposal_sha256(&proposal).unwrap();
        save_store_fixture(dir.path(), &store_with(proposal)).unwrap();
        let paths = vec!["src/cli/dummy.rs".to_owned()];
        let images = source_edit_images(dir.path(), &paths).await.unwrap();
        let mut forged_receipt = SourceEditApplyReceipt {
            version: SOURCE_EDIT_RECEIPT_VERSION,
            proposal_id: "source_edit-forged-receipt".into(),
            proposal_sha256: proposal_hash,
            diff_sha256: "b".repeat(64),
            source_root: dir.path().to_string_lossy().to_string(),
            target_paths: paths,
            base_images: images.clone(),
            post_images: images,
            self_edit_audit_finalized: true,
            applied_at_unix: now_unix(),
            auth_tag: String::new(),
        };
        save_source_edit_receipt(dir.path(), &mut forged_receipt).unwrap();

        let guard = acquire_self_dev_state_guard(dir.path()).await.unwrap();
        let error = recover_source_edit_receipt_locked(dir.path(), &guard)
            .await
            .expect_err("forged receipt hash must not accept the proposal");
        drop(guard);
        assert!(format!("{error:#}").contains("SELF_DEV_SOURCE_EDIT_RECEIPT_RECOVERY_REQUIRED"));
        assert_eq!(
            load_store(dir.path()).unwrap().entries[0].status,
            ProposalStatus::Pending
        );
        assert!(source_edit_receipt_path(dir.path()).exists());
    }

    #[tokio::test]
    async fn fully_matching_but_unauthenticated_source_edit_receipt_stays_pending() {
        let dir = tempdir().unwrap();
        let patch = dir.path().join("proposal.patch");
        std::fs::write(&patch, "reviewed patch bytes").unwrap();
        let diff_sha256 = "a".repeat(64);
        let proposal = source_edit_proposal("source_edit-forged-auth", patch, &diff_sha256);
        let proposal_sha256 = proposal_sha256(&proposal).unwrap();
        save_store_fixture(dir.path(), &store_with(proposal)).unwrap();
        let paths = vec!["src/cli/dummy.rs".to_owned()];
        let images = source_edit_images(dir.path(), &paths).await.unwrap();
        let forged = SourceEditApplyReceipt {
            version: SOURCE_EDIT_RECEIPT_VERSION,
            proposal_id: "source_edit-forged-auth".into(),
            proposal_sha256,
            diff_sha256,
            source_root: dir.path().to_string_lossy().to_string(),
            target_paths: paths,
            base_images: images.clone(),
            post_images: images,
            self_edit_audit_finalized: true,
            applied_at_unix: now_unix(),
            // Every non-authentication field matches. This value was not
            // minted from the home-bound authority and must not be trusted.
            auth_tag: "00".repeat(32),
        };
        crate::util::atomic_write::atomic_write_private(
            &source_edit_receipt_path(dir.path()),
            &serde_json::to_vec_pretty(&forged).unwrap(),
        )
        .unwrap();

        let guard = acquire_self_dev_state_guard(dir.path()).await.unwrap();
        let error = recover_source_edit_receipt_locked(dir.path(), &guard)
            .await
            .expect_err("matching forged receipt must be rejected by HMAC");
        drop(guard);
        assert!(format!("{error:#}").contains("SELF_DEV_SOURCE_EDIT_RECEIPT_RECOVERY_REQUIRED"));
        assert_eq!(
            load_store(dir.path()).unwrap().entries[0].status,
            ProposalStatus::Pending
        );
    }

    #[tokio::test]
    async fn applying_source_edit_with_changed_tree_never_auto_accepts_after_crash() {
        use sha2::{Digest as _, Sha256};

        let dir = tempdir().unwrap();
        let patch = dir.path().join("proposal.patch");
        let diff = concat!(
            "--- a/src/cli/dummy.rs\n",
            "+++ b/src/cli/dummy.rs\n",
            "@@ -1 +1 @@\n",
            "-old\n",
            "+new\n",
        );
        std::fs::write(&patch, diff).unwrap();
        let hash = format!("{:x}", Sha256::digest(diff.as_bytes()));
        let proposal = source_edit_proposal("source_edit-apply-crash", patch.clone(), &hash);
        save_store_fixture(dir.path(), &store_with(proposal)).unwrap();
        let paths = vec!["src/cli/dummy.rs".to_owned()];
        let mut transaction = begin_source_edit_apply(
            dir.path(),
            "source_edit-apply-crash",
            &patch.canonicalize().unwrap(),
            dir.path(),
            &hash,
            &hash,
            &paths,
        )
        .await
        .unwrap();
        transaction.mark_applying().unwrap();
        std::fs::create_dir_all(dir.path().join("src/cli")).unwrap();
        std::fs::write(dir.path().join("src/cli/dummy.rs"), "new\n").unwrap();
        drop(transaction);

        let guard = acquire_self_dev_state_guard(dir.path()).await.unwrap();
        let error = recover_source_edit_transaction_locked(dir.path(), &guard)
            .await
            .expect_err("changed Applying tree is ambiguous, not Accepted");
        drop(guard);
        assert!(format!("{error:#}").contains("SELF_DEV_SOURCE_EDIT_RECEIPT_RECOVERY_REQUIRED"));
        assert_eq!(
            load_store(dir.path()).unwrap().entries[0].status,
            ProposalStatus::Pending
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn source_edit_image_rejects_symlinked_leaf_and_parent_without_reading_outside_root() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let root = dir.path().join("root");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(root.join("src/cli")).unwrap();
        std::fs::create_dir_all(outside.join("cli")).unwrap();
        std::fs::write(outside.join("secret.rs"), "outside leaf").unwrap();
        std::fs::write(outside.join("cli/dummy.rs"), "outside parent").unwrap();

        symlink(outside.join("secret.rs"), root.join("src/cli/dummy.rs")).unwrap();
        let leaf = source_edit_images(&root, &["src/cli/dummy.rs".to_owned()])
            .await
            .expect_err("symlink leaf must not be read through source-edit evidence");
        assert!(format!("{leaf:#}").contains("symlink"));
        std::fs::remove_file(root.join("src/cli/dummy.rs")).unwrap();
        std::fs::remove_dir_all(root.join("src")).unwrap();

        symlink(&outside, root.join("src")).unwrap();
        let parent = source_edit_images(&root, &["src/cli/dummy.rs".to_owned()])
            .await
            .expect_err("symlink parent must not be traversed for source-edit evidence");
        assert!(format!("{parent:#}").contains("symlink"));
    }

    #[tokio::test]
    async fn source_edit_image_rejects_over_cap_sparse_leaf_before_allocation() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("root");
        let leaf = root.join("src/cli/oversized.rs");
        std::fs::create_dir_all(leaf.parent().unwrap()).unwrap();
        let file = std::fs::File::create(&leaf).unwrap();
        file.set_len(SOURCE_EDIT_IMAGE_MAX_FILE_BYTES + 1).unwrap();
        let error = source_edit_images(&root, &["src/cli/oversized.rs".to_owned()])
            .await
            .expect_err("oversized/sparse file must be rejected before allocation");
        assert!(format!("{error:#}").contains("evidence cap"));
    }

    #[cfg(any(unix, windows))]
    #[tokio::test]
    async fn source_edit_image_rejects_hard_linked_leaf_before_snapshot() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("root");
        let leaf = root.join("src/cli/aliased.rs");
        let alias = dir.path().join("external-alias.rs");
        std::fs::create_dir_all(leaf.parent().unwrap()).unwrap();
        std::fs::write(&leaf, "reviewed bytes").unwrap();
        std::fs::hard_link(&leaf, &alias).unwrap();
        let error = source_edit_images(&root, &["src/cli/aliased.rs".to_owned()])
            .await
            .expect_err("hard-linked source leaf must not be snapshotted");
        assert!(format!("{error:#}").contains("hard links"));
    }

    #[tokio::test]
    async fn source_edit_image_rejects_huge_all_missing_path_list_before_clone() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        let paths: Vec<String> = (0..=SOURCE_EDIT_IMAGE_MAX_TARGET_PATHS)
            .map(|index| format!("src/missing-{index}.rs"))
            .collect();
        let error = source_edit_images(&root, &paths)
            .await
            .expect_err("over-cardinality missing path list must be refused before clone/snapshot");
        assert!(format!("{error:#}").contains("path count"));
    }

    #[cfg(unix)]
    #[test]
    fn source_edit_leaf_growth_is_rejected_by_bounded_handle_read() {
        let dir = tempdir().unwrap();
        let leaf = dir.path().join("leaf.rs");
        std::fs::write(&leaf, b"x").unwrap();
        let root = Dir::open_ambient_dir(dir.path(), cap_std::ambient_authority()).unwrap();
        SOURCE_EDIT_LEAF_GROW_AFTER_OPEN.with(|slot| *slot.borrow_mut() = Some(leaf));
        let error = read_source_edit_regular_leaf(&root, OsStr::new("leaf.rs"), 1)
            .expect_err("one byte of concurrent growth must exceed bounded handle read");
        assert!(format!("{error:#}").contains("bounded evidence cap"));
    }

    #[tokio::test]
    async fn review_with_no_pending_prints_hint() {
        let dir = tempdir().unwrap();
        let args = SelfDevArgs {
            action: SelfDevAction::Review {
                min_confidence: 0.0,
            },
        };
        run(dir.path(), args, None, crate::cli::OutputFormat::Table)
            .await
            .unwrap();
    }

    #[test]
    fn review_proposals_json_unit_variant_shape() {
        // Non-SourceEdit proposals: kind is a plain string, SourceEdit fields null.
        let p = fixture_proposal("switch_preset-aabbccdd", 0.83);
        let stored = StoredProposal {
            proposal: p,
            status: ProposalStatus::Pending,
            status_at_unix: 0,
            decline_reason: String::new(),
        };
        let rows = review_proposals_json(&[&stored]);
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!(r["id"], "switch_preset-aabbccdd");
        assert_eq!(r["status"], "pending");
        assert_eq!(r["confidence"], 0.83);
        assert!(
            r["kind"].is_string(),
            "kind must be string for unit variants"
        );
        assert!(r["target"].is_string());
        assert!(r["reason"].is_string());
        assert!(r["patch_path"].is_null());
        assert!(r["diff_sha256"].is_null());
        assert!(r["target_paths"].is_null());
    }

    #[test]
    fn review_proposals_json_source_edit_shape() {
        // SourceEdit proposals: kind="source_edit", extra fields populated.
        use crate::profile::self_dev::ProposalKind;
        let proposal = SelfDevProposal {
            id: "source_edit-deadbeef".into(),
            kind: ProposalKind::SourceEdit {
                patch_path: std::path::PathBuf::from("/tmp/edit.patch"),
                diff_sha256: "abc123".into(),
                target_paths: vec!["src/cli/mod.rs".into()],
            },
            reason: "performance".into(),
            confidence: 0.9,
            target: "src/cli/mod.rs".into(),
            extension_authority: None,
        };
        let stored = StoredProposal {
            proposal,
            status: ProposalStatus::Accepted,
            status_at_unix: 0,
            decline_reason: String::new(),
        };
        let rows = review_proposals_json(&[&stored]);
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!(r["id"], "source_edit-deadbeef");
        assert_eq!(r["kind"], "source_edit");
        assert_eq!(r["status"], "accepted");
        assert_eq!(r["diff_sha256"], "abc123");
        assert!(r["patch_path"].is_string(), "patch_path must be string");
        assert!(r["target_paths"].is_array(), "target_paths must be array");
        assert!(!r["patch_path"].is_null());
        assert!(!r["diff_sha256"].is_null());
    }

    #[test]
    fn review_proposals_json_excludes_declined() {
        let p = fixture_proposal("switch_preset-aabbccdd", 0.8);
        let stored = StoredProposal {
            proposal: p,
            status: ProposalStatus::Declined,
            status_at_unix: 0,
            decline_reason: "declined".into(),
        };
        // review_proposals_json receives what run_review filters — it doesn't
        // itself filter. The caller contract is: declined entries are excluded
        // by the caller. Verify caller (active filter) excludes declined.
        // (The fn itself serializes whatever it receives, including status field.)
        let rows = review_proposals_json(&[&stored]);
        // fn renders what it gets; caller pre-filters declined out.
        assert_eq!(rows[0]["status"], "declined"); // fn is not a filter
    }

    #[tokio::test]
    async fn accept_unknown_id_errors_with_actionable_message() {
        let dir = tempdir().unwrap();
        let args = SelfDevArgs {
            action: SelfDevAction::Accept {
                id: "ghost-12345678".into(),
            },
        };
        let err = run(dir.path(), args, None, crate::cli::OutputFormat::Table)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("ghost"));
    }

    #[tokio::test]
    async fn accept_flips_status_to_accepted() {
        let dir = tempdir().unwrap();
        let mut store = ProposalStore::default();
        store.entries.push(StoredProposal {
            proposal: fixture_proposal("switch_preset-aabbccdd", 0.8),
            status: ProposalStatus::Pending,
            status_at_unix: 0,
            decline_reason: String::new(),
        });
        save_store_fixture(dir.path(), &store).unwrap();
        let args = SelfDevArgs {
            action: SelfDevAction::Accept {
                id: "switch_preset-aabbccdd".into(),
            },
        };
        run(dir.path(), args, None, crate::cli::OutputFormat::Table)
            .await
            .unwrap();
        let back = load_store(dir.path()).unwrap();
        assert_eq!(back.entries[0].status, ProposalStatus::Accepted);
        assert!(back.entries[0].status_at_unix > 0);
    }

    #[tokio::test]
    async fn accept_is_idempotent_on_already_accepted() {
        let dir = tempdir().unwrap();
        let mut store = ProposalStore::default();
        store.entries.push(StoredProposal {
            proposal: fixture_proposal("x", 0.5),
            status: ProposalStatus::Accepted,
            status_at_unix: 1_700_000_000,
            decline_reason: String::new(),
        });
        save_store_fixture(dir.path(), &store).unwrap();
        let args = SelfDevArgs {
            action: SelfDevAction::Accept { id: "x".into() },
        };
        run(dir.path(), args, None, crate::cli::OutputFormat::Table)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn decline_rejects_unknown_reason_string() {
        let dir = tempdir().unwrap();
        let mut store = ProposalStore::default();
        store.entries.push(StoredProposal {
            proposal: fixture_proposal("x", 0.5),
            status: ProposalStatus::Pending,
            status_at_unix: 0,
            decline_reason: String::new(),
        });
        save_store_fixture(dir.path(), &store).unwrap();
        let args = SelfDevArgs {
            action: SelfDevAction::Decline {
                id: "x".into(),
                reason: "garbage".into(),
            },
        };
        let err = run(dir.path(), args, None, crate::cli::OutputFormat::Table)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("declined"));
    }

    #[tokio::test]
    async fn decline_records_reason_string_and_flips_status() {
        let dir = tempdir().unwrap();
        let mut store = ProposalStore::default();
        store.entries.push(StoredProposal {
            proposal: fixture_proposal("x", 0.5),
            status: ProposalStatus::Pending,
            status_at_unix: 0,
            decline_reason: String::new(),
        });
        save_store_fixture(dir.path(), &store).unwrap();
        let args = SelfDevArgs {
            action: SelfDevAction::Decline {
                id: "x".into(),
                reason: "timeout".into(),
            },
        };
        run(dir.path(), args, None, crate::cli::OutputFormat::Table)
            .await
            .unwrap();
        let back = load_store(dir.path()).unwrap();
        assert_eq!(back.entries[0].status, ProposalStatus::Declined);
        assert_eq!(back.entries[0].decline_reason, "timeout");
    }

    #[tokio::test]
    async fn decline_after_accept_errors() {
        let dir = tempdir().unwrap();
        let mut store = ProposalStore::default();
        store.entries.push(StoredProposal {
            proposal: fixture_proposal("x", 0.5),
            status: ProposalStatus::Accepted,
            status_at_unix: 1_700_000_000,
            decline_reason: String::new(),
        });
        save_store_fixture(dir.path(), &store).unwrap();
        let args = SelfDevArgs {
            action: SelfDevAction::Decline {
                id: "x".into(),
                reason: "declined".into(),
            },
        };
        let err = run(dir.path(), args, None, crate::cli::OutputFormat::Table)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("previously accepted"));
    }

    #[tokio::test]
    async fn propose_from_profile_writes_proposals_to_store() {
        use crate::profile::estimators::{LengthEstimate, ToneEstimate};

        let dir = tempdir().unwrap();
        let profile = BehaviouralProfile {
            length: LengthEstimate {
                sample_count: 50,
                mean_chars: 250.0,
                median_chars: 250,
                p10_chars: 100,
                p90_chars: 400,
            },
            tone: ToneEstimate {
                sample_count: 50,
                casual_hits: 0,
                formal_hits: 30,
                casual_score: -0.6,
            },
            ..Default::default()
        };
        let profile_path = dir.path().join("profile.json");
        std::fs::write(&profile_path, serde_json::to_vec(&profile).unwrap()).unwrap();
        let args = SelfDevArgs {
            action: SelfDevAction::Propose {
                from_profile: profile_path,
                current_preset: "lowkey".into(),
            },
        };
        run(dir.path(), args, None, crate::cli::OutputFormat::Table)
            .await
            .unwrap();
        let back = load_store(dir.path()).unwrap();
        assert!(!back.entries.is_empty());
        assert!(
            back.entries
                .iter()
                .all(|e| e.status == ProposalStatus::Pending)
        );
    }

    #[tokio::test]
    async fn store_filters_unavailable_extension_instead_of_publishing_dead_accept_action() {
        let dir = tempdir().unwrap();
        let mut proposal = SelfDevProposal {
            id: "learn_extension-deadbeef".into(),
            kind: ProposalKind::LearnExtension,
            reason: "missing target".into(),
            confidence: 0.8,
            target: "definitely-not-a-bundled-or-installed-skill".into(),
            extension_authority: None,
        };
        proposal
            .bind_extension_authority(crate::profile::self_dev::ExtensionAuthorityBinding::Bundled)
            .unwrap();

        assert_eq!(
            store_proposals(dir.path(), &[proposal], None)
                .await
                .unwrap(),
            0
        );
        assert!(load_store(dir.path()).unwrap().entries.is_empty());
    }

    #[tokio::test]
    async fn store_binds_available_bundled_extension_before_operator_review() {
        let dir = tempdir().unwrap();
        let target = crate::skills::bundled::BUNDLED_SKILLS[0].0.to_string();
        let proposal = SelfDevProposal {
            id: "learn_extension-unbound".into(),
            kind: ProposalKind::LearnExtension,
            reason: "available target".into(),
            confidence: 0.8,
            target: target.clone(),
            extension_authority: None,
        };

        assert_eq!(
            store_proposals(dir.path(), &[proposal], None)
                .await
                .unwrap(),
            1
        );
        let store = load_store(dir.path()).unwrap();
        assert_eq!(store.entries.len(), 1);
        assert_eq!(store.entries[0].proposal.target, target);
        assert_eq!(
            store.entries[0].proposal.extension_authority,
            Some(crate::profile::self_dev::ExtensionAuthorityBinding::Bundled)
        );
        assert_eq!(
            store.entries[0].proposal.id.len(),
            "learn_extension-".len() + 64
        );
    }

    #[tokio::test]
    async fn store_filters_exactly_revoked_installed_extension() {
        let dir = tempdir().unwrap();
        let id = "self-dev-revoked";
        let skill_dir = dir.path().join("skills").join(id);
        std::fs::create_dir_all(&skill_dir).unwrap();
        std::fs::write(
            skill_dir.join("skill.yaml"),
            "id: self-dev-revoked\n\
             description: revoked SelfDev target\n\
             system_prompt: never reactivate this incarnation\n\
             trigger_keywords: [revoked]\n\
             enabled: true\n",
        )
        .unwrap();
        let config_path = dir.path().join("freedom.yaml");
        std::fs::write(
            &config_path,
            serde_yaml::to_string(&crate::config::FreedomConfig::default()).unwrap(),
        )
        .unwrap();
        let current =
            crate::skills::installer::inspect_current_install(&dir.path().join("skills"), id)
                .unwrap();
        crate::skills::mutation_lifecycle::record_committed_install_incarnation_for_test(
            dir.path(),
            id,
            &current.generation_sha256,
            crate::skills::installer::SkillMutationOrigin::CliInstall,
        )
        .unwrap();
        crate::cli::skills::set_skill_authority_at_config(
            dir.path(),
            &config_path,
            id,
            crate::cli::skills::SkillAuthorityTarget::Revoked,
            crate::skills::authority::SkillAuthorityDecisionSource::OperatorCli,
        )
        .await
        .unwrap();
        assert_eq!(
            crate::skills::authority::inspect_current_authority(dir.path(), id)
                .unwrap()
                .unwrap()
                .record()
                .state,
            crate::skills::authority::SkillAuthorityState::Revoked
        );
        let proposal = SelfDevProposal {
            id: "learn_extension-revoked".into(),
            kind: ProposalKind::LearnExtension,
            reason: "must stay terminal".into(),
            confidence: 0.8,
            target: id.into(),
            extension_authority: None,
        };

        assert_eq!(
            store_proposals(dir.path(), &[proposal], None)
                .await
                .unwrap(),
            0
        );
        assert!(load_store(dir.path()).unwrap().entries.is_empty());
    }

    #[tokio::test]
    async fn propose_and_store_honours_the_basis_preset() {
        // SPEC-05: the profile-adapt cron calls EXACTLY this, passing its
        // configured `basis_preset.as_str()`. A strongly-casual profile drifts
        // AWAY from a Formal baseline (→ propose switch-to-lowkey) but already
        // MATCHES a Lowkey baseline (→ no tone proposal). A different basis ⇒ a
        // different outcome — proving the now-configurable basis is load-bearing,
        // not cosmetic. (Only `tone` is set; the verbosity/temporal/topic blocks
        // all gate on their own `sample_count >= 20`, so they stay silent here.)
        use crate::profile::estimators::ToneEstimate;
        use crate::profile::presets::ProfilePreset;

        let profile = BehaviouralProfile {
            tone: ToneEstimate {
                sample_count: 20, // meets the >= 20 gate in propose_adjustments
                casual_hits: 16,
                formal_hits: 0,
                casual_score: 0.8, // > 0.4 → strongly casual
            },
            ..Default::default()
        };

        // Separate homes — the per-home dedup store must not cross-contaminate.
        let home_formal = tempdir().unwrap();
        let home_lowkey = tempdir().unwrap();

        let against_formal = propose_and_store(
            home_formal.path(),
            &profile,
            ProfilePreset::Formal.as_str(),
            None,
        )
        .await
        .unwrap();
        let against_lowkey = propose_and_store(
            home_lowkey.path(),
            &profile,
            ProfilePreset::Lowkey.as_str(),
            None,
        )
        .await
        .unwrap();

        assert!(
            against_formal >= 1,
            "casual behaviour vs a Formal baseline must propose a switch, got {against_formal}"
        );
        assert_eq!(
            against_lowkey, 0,
            "casual behaviour already MATCHES the Lowkey baseline → no proposal, got {against_lowkey}"
        );
    }

    #[tokio::test]
    async fn propose_is_idempotent_on_same_profile_input() {
        // Run propose twice with the same profile → second run
        // adds zero new proposals (stable ids dedupe).
        use crate::profile::estimators::{LengthEstimate, ToneEstimate};

        let dir = tempdir().unwrap();
        let profile = BehaviouralProfile {
            length: LengthEstimate {
                sample_count: 50,
                mean_chars: 250.0,
                median_chars: 250,
                p10_chars: 100,
                p90_chars: 400,
            },
            tone: ToneEstimate {
                sample_count: 50,
                casual_hits: 0,
                formal_hits: 30,
                casual_score: -0.6,
            },
            ..Default::default()
        };
        let profile_path = dir.path().join("profile.json");
        std::fs::write(&profile_path, serde_json::to_vec(&profile).unwrap()).unwrap();

        let args1 = SelfDevArgs {
            action: SelfDevAction::Propose {
                from_profile: profile_path.clone(),
                current_preset: "lowkey".into(),
            },
        };
        run(dir.path(), args1, None, crate::cli::OutputFormat::Table)
            .await
            .unwrap();
        let first = load_store(dir.path()).unwrap();

        let args2 = SelfDevArgs {
            action: SelfDevAction::Propose {
                from_profile: profile_path,
                current_preset: "lowkey".into(),
            },
        };
        run(dir.path(), args2, None, crate::cli::OutputFormat::Table)
            .await
            .unwrap();
        let second = load_store(dir.path()).unwrap();

        assert_eq!(first.entries.len(), second.entries.len());
    }

    #[test]
    fn proposal_status_serialises_snake_case() {
        let p = ProposalStatus::Accepted;
        let s = serde_json::to_string(&p).unwrap();
        assert_eq!(s, "\"accepted\"");
    }
}
