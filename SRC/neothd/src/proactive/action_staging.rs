//! OB-03 (Session 24) — proactive action staging.
//!
//! NEOTH proposes a cron job, skill, hook, or config tweak. Rather
//! than applying it silently, the proposal is STAGED: written as a
//! human-readable markdown draft to the operator's Obsidian vault
//! under `<vault>/<subdir>/Proposals/<id>.md`, with the raw YAML
//! the operator would merge into the live config block embedded
//! inside the note. Approval flips the status; the actual config
//! mutation is the operator's call (drop the YAML into the live
//! file then `neoth config reload`) — NEOTH never edits operator
//! configuration files behind their back.
//!
//! Companion side-effect: every new proposal pushes one
//! [`crate::proactive::ProactiveItem`] into the shared G-01a
//! [`crate::proactive::ProactiveQueue`] so the operator's regular
//! drain path surfaces the proposal in the active channel.
//!
//! ## Storage
//!
//! One JSON file per proposal at
//! `~/.neoth/proposals/<id>.json`. Files are mutable in-place — the
//! status field flips between `Pending` → `Approved` / `Rejected`
//! and any operator note ends up in `operator_note`. JSONL was
//! considered + rejected: per-proposal files map cleanly to the
//! per-proposal vault `.md` files + let operators delete individual
//! rejected proposals without re-writing a log.
//!
//! ## Why the operator-approves-not-NEOTH-applies rule
//!
//! Auto-applying config changes is the single highest-risk pattern
//! for an autonomous agent. Even with a rollback button, a bad
//! cron run between propose-and-rollback can deliver a wrong
//! notification, charge a paid API, or surface poisoned memory to
//! a third party. Staging makes "did I see this?" the precondition
//! to any change.

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _};
use cap_std::fs::OpenOptions as CapOpenOptions;
use serde::{Deserialize, Serialize};

use crate::proactive::{ProactiveItem, ProactiveQueue};
use crate::skills::store::{
    BoundDirectory, cap_metadata_is_link_like, open_bound_directory, read_regular_file_bounded,
    remove_child_file, rename_child, replace_existing_regular_file_report,
};

const MAX_PROPOSAL_BYTES: usize = 1024 * 1024;
const MAX_PROPOSAL_ENTRIES: usize = 4096;
const MAX_PROPOSAL_ID_BYTES: usize = 128;
const PROPOSAL_MUTATION_LOCK_FILE: &str = ".neoth-proposals.lock";
const PROPOSAL_STAGE_PREFIX: &str = ".neoth-proposal-stage-";
static PROPOSAL_MUTATION_LOCK: Mutex<()> = Mutex::new(());

/// Kinds of operator-config artefact NEOTH may propose. New variants
/// are non-breaking — operator vaults pin existing variants by
/// snake_case wire form so the JSON survives schema evolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalKind {
    /// A cron job to append to `jobs.yaml`.
    CronJob,
    /// A skill definition to drop into `~/.neoth/skills/`.
    Skill,
    /// A hook to add under `freedom.yaml::hooks`.
    Hook,
    /// A scalar tweak to `freedom.yaml` (e.g. enable a feature flag).
    ConfigTweak,
}

impl ProposalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ProposalKind::CronJob => "cron_job",
            ProposalKind::Skill => "skill",
            ProposalKind::Hook => "hook",
            ProposalKind::ConfigTweak => "config_tweak",
        }
    }
}

/// Operator's verdict on a proposal. Stays `Pending` until the
/// operator explicitly accepts or rejects via the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalStatus {
    Pending,
    Approved,
    Rejected,
}

impl ProposalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ProposalStatus::Pending => "pending",
            ProposalStatus::Approved => "approved",
            ProposalStatus::Rejected => "rejected",
        }
    }
}

/// A staged proposal. Filename is `<id>.json`; `id` itself is the
/// `<unix-secs>-<kind>-<short-hash>` format `make_proposal_id`
/// produces so operators see proposals sorted oldest-first by
/// natural filesystem listing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProposedAction {
    pub id: String,
    pub kind: ProposalKind,
    /// One-line summary, e.g. `"Daily 09:00 morning briefing"`.
    pub title: String,
    /// Multi-paragraph operator-facing explanation of WHY NEOTH
    /// thinks this is useful. Renders verbatim into the vault note.
    pub rationale: String,
    /// The exact YAML / JSON block the operator would merge into
    /// the live config. Rendered inside a fenced code block in the
    /// vault note so operators copy-paste cleanly.
    pub draft_yaml: String,
    pub generated_ts_unix: i64,
    pub status: ProposalStatus,
    /// Operator's review note when accepting or rejecting. Empty
    /// while `Pending`.
    #[serde(default)]
    pub operator_note: String,
}

impl ProposedAction {
    /// Render the proposal as an operator-readable Obsidian note.
    /// YAML frontmatter exposes id / kind / status / generated_unix
    /// so Dataview can list `WHERE status = "pending"`.
    pub fn to_obsidian_md(&self) -> String {
        format!(
            "---\n\
             id: \"{id}\"\n\
             kind: \"{kind}\"\n\
             status: \"{status}\"\n\
             generated_unix: {ts}\n\
             ---\n\n\
             # Proposal — {title}\n\n\
             ## Why\n\n\
             {rationale}\n\n\
             ## Draft config\n\n\
             ```yaml\n\
             {draft}\n\
             ```\n\n\
             ## Operator action\n\n\
             - Approve: `neoth proactive accept {id}`\n\
             - Reject:  `neoth proactive reject {id}`\n",
            id = escape_yaml_string(&self.id),
            kind = self.kind.as_str(),
            status = self.status.as_str(),
            ts = self.generated_ts_unix,
            title = self.title,
            rationale = self.rationale,
            draft = self.draft_yaml.trim_end_matches('\n'),
        )
    }
}

/// What one curator reconciliation pass did.
#[derive(Debug)]
pub enum SkillReconciliation {
    /// The skill was created, or already matched the approved draft byte for
    /// byte.
    Adopted(Box<crate::skills::creator::CreateReport>),
    /// The skill exists but no longer matches the draft: the operator edited it
    /// after adoption, which is the normal follow-up workflow. Neither an error
    /// nor something to overwrite.
    OperatorModified { id: String },
}

/// Reconcile an approved Skill proposal for the CURATOR CRON.
///
/// Differs from [`adopt_approved_skill`] only in how an operator-modified
/// target is reported. The cron re-walks every approved proposal on every tick
/// and has no terminal state to mark, so once the operator edited an adopted
/// `skill.yaml` — the normal follow-up — `ExistingSkillPolicy::KeepIfIdentical`
/// made that proposal fail on every tick forever, with nothing to do about it.
/// The explicit `neoth proactive accept` path keeps erroring, because there an
/// operator asked for the write and needs to hear that it was refused.
///
/// The divergence is detected POSITIVELY, by comparing bytes — never by
/// classifying an error message.
pub fn reconcile_approved_skill(
    home: &Path,
    proposal: &ProposedAction,
) -> anyhow::Result<SkillReconciliation> {
    use anyhow::Context as _;
    let manifest: crate::skills::schema::SkillManifest = serde_yaml::from_str(&proposal.draft_yaml)
        .with_context(|| {
            format!(
                "approved skill proposal {} carries invalid draft_yaml",
                proposal.id
            )
        })?;
    if let Some(current) = installed_skill_yaml(home, &manifest.id)?
        && current != proposal.draft_yaml
    {
        return Ok(SkillReconciliation::OperatorModified { id: manifest.id });
    }
    adopt_approved_skill_with_origin(
        home,
        proposal,
        crate::skills::installer::SkillMutationOrigin::ProactiveCurator,
    )
    .map(|report| SkillReconciliation::Adopted(Box::new(report)))
}

/// The installed `skill.yaml` for `id`, or `None` when it is not installed.
///
/// Read through the bound, no-follow store primitives: this compares operator
/// content, so a symlinked or oversized path must not be followed into.
fn installed_skill_yaml(home: &Path, id: &str) -> anyhow::Result<Option<String>> {
    let Some(root) = open_bound_directory(&home.join("skills"), false, "skills root")? else {
        return Ok(None);
    };
    let name = OsStr::new(id);
    let display = root.display_path.join(name);
    let Ok(skill_dir) = crate::skills::store::open_real_child_dir(&root.dir, name, &display) else {
        return Ok(None);
    };
    let manifest_name = OsStr::new("skill.yaml");
    let manifest_path = display.join("skill.yaml");
    match read_regular_file_bounded(
        &skill_dir,
        manifest_name,
        &manifest_path,
        MAX_PROPOSAL_BYTES,
    ) {
        Ok(bytes) => Ok(String::from_utf8(bytes).ok()),
        Err(_) => Ok(None),
    }
}

/// Adopt an operator-approved Skill proposal into the live skill loader path.
///
/// This is the single schema boundary used by both `neoth proactive accept`
/// and the curator reconciliation cron. The draft is parsed as the real
/// [`SkillManifest`], its id is validated as a safe directory component, and
/// the authenticated complete-package lifecycle publishes
/// `<home>/skills/<id>/skill.yaml` without dropping sibling assets.
pub fn adopt_approved_skill(
    home: &Path,
    proposal: &ProposedAction,
) -> anyhow::Result<crate::skills::creator::CreateReport> {
    adopt_approved_skill_with_origin(
        home,
        proposal,
        crate::skills::installer::SkillMutationOrigin::ProactiveAccept,
    )
}

fn adopt_approved_skill_with_origin(
    home: &Path,
    proposal: &ProposedAction,
    origin: crate::skills::installer::SkillMutationOrigin,
) -> anyhow::Result<crate::skills::creator::CreateReport> {
    use crate::skills::creator::{
        ExistingSkillPolicy, validate_skill_id, write_skill_yaml_audited,
    };
    use crate::skills::schema::SkillManifest;
    use anyhow::Context;

    if proposal.kind != ProposalKind::Skill {
        anyhow::bail!("proposal {} is not a Skill proposal", proposal.id);
    }
    if proposal.status != ProposalStatus::Approved {
        anyhow::bail!(
            "skill proposal {} is not operator-approved (status={})",
            proposal.id,
            proposal.status.as_str()
        );
    }

    let manifest: SkillManifest =
        serde_yaml::from_str(&proposal.draft_yaml).with_context(|| {
            format!(
                "approved skill proposal {} carries invalid draft_yaml",
                proposal.id
            )
        })?;
    validate_skill_id(&manifest.id)
        .with_context(|| format!("skill id {:?} is not a safe directory name", manifest.id))?;
    write_skill_yaml_audited(
        home,
        &home.join("skills"),
        &manifest.id,
        &proposal.draft_yaml,
        ExistingSkillPolicy::KeepIfIdentical,
        None,
        origin,
    )
}

fn escape_yaml_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Construct a stable, time-sortable, kind-prefixed proposal id.
/// Format `<unix-secs>-<kind>-<short-hash>`. The short-hash is a
/// xxh3-64 of `(title, draft_yaml, generated_ts_unix)` so two
/// proposals with identical content produce the same id (idempotent
/// re-runs of the same producer don't double-stage).
pub fn make_proposal_id(
    kind: ProposalKind,
    title: &str,
    draft_yaml: &str,
    generated_ts_unix: i64,
) -> String {
    let hash_input = format!("{title}|{draft_yaml}|{generated_ts_unix}");
    let hash = xxhash_rust::xxh3::xxh3_64(hash_input.as_bytes());
    let short = format!("{:08x}", hash & 0xFFFF_FFFF);
    format!("{}-{}-{}", generated_ts_unix, kind.as_str(), short)
}

/// Content-only variant of [`make_proposal_id`].
///
/// Format `<kind>-<short-hash>` where the hash covers ONLY `(title,
/// draft_yaml)` — NOT the timestamp. Two extractions of the same skill
/// at different wall-clock times produce the **same** id, enabling
/// stable dedup across runs. `generated_ts_unix` is still stored on
/// the [`ProposedAction`] record for display/ordering; it just does not
/// enter the identity hash.
///
/// Use this for auto-extract paths where idempotency-across-time is the
/// goal. Use [`make_proposal_id`] for cron/config proposals that are
/// legitimately different across ticks even with equal content.
pub fn make_proposal_id_content_only(kind: ProposalKind, title: &str, draft_yaml: &str) -> String {
    let hash_input = format!("{title}|{draft_yaml}");
    let hash = xxhash_rust::xxh3::xxh3_64(hash_input.as_bytes());
    let short = format!("{:08x}", hash & 0xFFFF_FFFF);
    format!("{}-{}", kind.as_str(), short)
}

/// Directory under `home` that holds staged proposal JSON files.
pub fn proposals_dir(home: &Path) -> PathBuf {
    home.join("proposals")
}

/// Path to one proposal's JSON file.
pub fn proposal_path(home: &Path, id: &str) -> PathBuf {
    let name = proposal_file_name(id).unwrap_or_else(|_| {
        let hash = xxhash_rust::xxh3::xxh3_64(id.as_bytes());
        OsString::from(format!(".invalid-proposal-id-{hash:016x}.json"))
    });
    proposals_dir(home).join(name)
}

fn validate_proposal_id(id: &str) -> std::io::Result<()> {
    if id.is_empty()
        || id.len() > MAX_PROPOSAL_ID_BYTES
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "invalid proposal id {id:?}: expected 1..={MAX_PROPOSAL_ID_BYTES} ASCII letters, digits, '-' or '_'"
            ),
        ));
    }
    Ok(())
}

fn proposal_file_name(id: &str) -> std::io::Result<OsString> {
    validate_proposal_id(id)?;
    Ok(OsString::from(format!("{id}.json")))
}

fn proposals_root(home: &Path, create: bool) -> std::io::Result<Option<BoundDirectory>> {
    open_bound_directory(&proposals_dir(home), create, "proposal store").map_err(anyhow_to_io)
}

struct ProposalMutationGuard {
    _process: MutexGuard<'static, ()>,
    _file: std::fs::File,
}

fn lock_proposal_mutations(root: &BoundDirectory) -> std::io::Result<ProposalMutationGuard> {
    let process = PROPOSAL_MUTATION_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let started = std::time::Instant::now();
    loop {
        let mut options = CapOpenOptions::new();
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
        let file = match root.dir.open_with(PROPOSAL_MUTATION_LOCK_FILE, &options) {
            Ok(file) => file,
            #[cfg(windows)]
            Err(error) if error.raw_os_error() == Some(32) => {
                if started.elapsed() >= std::time::Duration::from_secs(5) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!(
                            "proposal mutation lock held for >5s at {}",
                            root.display_path
                                .join(PROPOSAL_MUTATION_LOCK_FILE)
                                .display()
                        ),
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
            Err(error) => return Err(error),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file() || cap_metadata_is_link_like(&metadata) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "proposal mutation lock is not a real regular file: {}",
                    root.display_path
                        .join(PROPOSAL_MUTATION_LOCK_FILE)
                        .display()
                ),
            ));
        }
        let file = file.into_std();
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd as _;
            // SAFETY: flock operates on a live, owned regular-file descriptor.
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
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!(
                            "proposal mutation lock held for >5s at {}",
                            root.display_path
                                .join(PROPOSAL_MUTATION_LOCK_FILE)
                                .display()
                        ),
                    ));
                }
                return Err(error);
            }
        }
        return Ok(ProposalMutationGuard {
            _process: process,
            _file: file,
        });
    }
}

fn anyhow_is_not_found(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|error| error.kind() == std::io::ErrorKind::NotFound)
}

fn anyhow_to_io(error: anyhow::Error) -> std::io::Error {
    let kind = error
        .chain()
        .find_map(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind)
        })
        .unwrap_or(std::io::ErrorKind::Other);
    std::io::Error::new(kind, error)
}

fn decode_proposal(bytes: Vec<u8>, display_path: &Path) -> std::io::Result<ProposedAction> {
    let body = String::from_utf8(bytes).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "staged proposal {} is not UTF-8: {error}",
                display_path.display()
            ),
        )
    })?;
    serde_json::from_str(&body).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("parse staged proposal {}: {error}", display_path.display()),
        )
    })
}

fn read_proposal_from_root(
    root: &BoundDirectory,
    id: &str,
) -> std::io::Result<Option<ProposedAction>> {
    let name = proposal_file_name(id)?;
    let display_path = root.display_path.join(&name);
    let bytes = match read_regular_file_bounded(&root.dir, &name, &display_path, MAX_PROPOSAL_BYTES)
    {
        Ok(bytes) => bytes,
        Err(error) if anyhow_is_not_found(&error) => return Ok(None),
        Err(error) => return Err(anyhow_to_io(error)),
    };
    let proposal = decode_proposal(bytes, &display_path)?;
    if proposal.id != id {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "proposal filename id {id:?} does not match record id {:?} at {}",
                proposal.id,
                display_path.display()
            ),
        ));
    }
    Ok(Some(proposal))
}

fn proposal_body(proposal: &ProposedAction) -> std::io::Result<Vec<u8>> {
    validate_proposal_id(&proposal.id)?;
    let body = serde_json::to_vec_pretty(proposal).map_err(std::io::Error::other)?;
    if body.len() > MAX_PROPOSAL_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "proposal {} exceeds the {MAX_PROPOSAL_BYTES}-byte limit",
                proposal.id
            ),
        ));
    }
    Ok(body)
}

fn create_proposal_file(
    root: &BoundDirectory,
    proposal: &ProposedAction,
    body: &[u8],
) -> std::io::Result<()> {
    let final_name = proposal_file_name(&proposal.id)?;
    let final_path = root.display_path.join(&final_name);
    create_new_regular_file(root, &final_name, &final_path, body, PROPOSAL_STAGE_PREFIX)
}

fn create_new_regular_file(
    root: &BoundDirectory,
    final_name: &OsStr,
    final_path: &Path,
    body: &[u8],
    stage_prefix: &str,
) -> std::io::Result<()> {
    let stage_name = OsString::from(format!("{stage_prefix}{}", uuid::Uuid::new_v4().simple()));
    let stage_path = root.display_path.join(&stage_name);
    let mut options = CapOpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut stage = root.dir.open_with(&stage_name, &options)?;
    let write_result = (|| -> std::io::Result<()> {
        stage.write_all(body)?;
        stage.sync_all()?;
        drop(stage);
        rename_child(
            &root.dir,
            &stage_name,
            &root.dir,
            final_name,
            false,
            &stage_path,
            final_path,
        )
        .map_err(anyhow_to_io)
    })();
    if write_result.is_err() {
        match remove_child_file(&root.dir, &stage_name, &stage_path) {
            Ok(()) => {}
            Err(cleanup_error) if anyhow_is_not_found(&cleanup_error) => {}
            Err(cleanup_error) => {
                tracing::warn!(
                    path = %stage_path.display(),
                    error = %cleanup_error,
                    "failed to remove staged proposal after write failure"
                );
            }
        }
    }
    write_result
}

fn replace_proposal_file(
    root: &BoundDirectory,
    proposal: &ProposedAction,
    body: &[u8],
) -> std::io::Result<()> {
    let name = proposal_file_name(&proposal.id)?;
    let path = root.display_path.join(&name);
    let report = replace_existing_regular_file_report(&root.dir, &name, &path, body)
        .map_err(anyhow_to_io)?;
    for warning in crate::skills::operator_skill_warnings(&report.warnings) {
        tracing::warn!(path = %path.display(), %warning, "proposal replacement committed with warning");
    }
    Ok(())
}

fn same_stable_payload(left: &ProposedAction, right: &ProposedAction) -> bool {
    left.id == right.id
        && left.kind == right.kind
        && left.title == right.title
        && left.draft_yaml == right.draft_yaml
}

/// Persist a proposal to disk. Every mutation is serialized across daemon and
/// CLI processes, and both staging and commit stay relative to a stable
/// directory capability. A terminal operator verdict cannot be overwritten.
pub fn save_proposal(home: &Path, proposal: &ProposedAction) -> std::io::Result<PathBuf> {
    validate_proposal_id(&proposal.id)?;
    let root = proposals_root(home, true)?.expect("created proposal root must exist");
    let _guard = lock_proposal_mutations(&root)?;
    let final_path = proposal_path(home, &proposal.id);
    let existing = read_proposal_from_root(&root, &proposal.id)?;
    if let Some(existing) = existing.as_ref()
        && existing.status != ProposalStatus::Pending
        && existing != proposal
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "proposal {} already has terminal status {}; refusing to overwrite the operator verdict",
                proposal.id,
                existing.status.as_str()
            ),
        ));
    }
    if existing.as_ref() == Some(proposal) {
        return Ok(final_path);
    }
    let body = proposal_body(proposal)?;
    if existing.is_some() {
        replace_proposal_file(&root, proposal, &body)?;
    } else {
        create_proposal_file(&root, proposal, &body)?;
    }
    Ok(final_path)
}

/// Load one proposal by id. Returns `None` when the file is
/// missing or malformed (corrupted disk doesn't kill the read path).
pub fn load_proposal(home: &Path, id: &str) -> Option<ProposedAction> {
    validate_proposal_id(id).ok()?;
    let root = proposals_root(home, false).ok()??;
    read_proposal_from_root(&root, id).ok()?
}

/// Load every proposal in `proposals_dir`, optionally filtered by status.
/// A missing directory is an empty store; every other directory-entry, read,
/// or JSON error is surfaced so autonomous consumers fail closed instead of
/// silently skipping corrupted approved proposals. Sorted ascending by id
/// (which starts with unix-seconds, so older proposals come first).
pub fn list_proposals(
    home: &Path,
    status_filter: Option<ProposalStatus>,
) -> std::io::Result<Vec<ProposedAction>> {
    let Some(root) = proposals_root(home, false)? else {
        return Ok(Vec::new());
    };
    let read = root.dir.entries()?;

    let mut out = Vec::new();
    let mut entry_count = 0usize;
    for entry in read {
        let entry = entry?;
        entry_count = entry_count.checked_add(1).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "proposal entry counter overflow",
            )
        })?;
        if entry_count > MAX_PROPOSAL_ENTRIES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "proposal store {} exceeds the {MAX_PROPOSAL_ENTRIES}-entry limit",
                    root.display_path.display()
                ),
            ));
        }
        // An entry this store could never have written is FOREIGN, not corrupt:
        // an editor backup, a manual rename, a non-UTF-8 name. Failing the whole
        // listing on one of those took down the curator (approved proposals
        // stopped being promoted, every tick just logged), the vault sync, AND
        // the operator's view — exactly when they most need to see the store.
        // Anything that IS recognisably one of ours stays fail-closed below, so
        // a corrupted approved proposal is still never silently skipped.
        let name = entry.file_name();
        let Some(name_text) = name.to_str() else {
            tracing::warn!(
                store = %root.display_path.display(),
                "skipping a proposal-store entry with a non-UTF-8 name; no proposal this store \
                 wrote can have one"
            );
            continue;
        };
        let Some(id) = name_text.strip_suffix(".json") else {
            continue;
        };
        if let Err(error) = validate_proposal_id(id) {
            tracing::warn!(
                store = %root.display_path.display(),
                %error,
                "skipping a `.json` entry whose name is not a proposal id; no proposal this \
                 store wrote can have one"
            );
            continue;
        }
        let path = root.display_path.join(&name);
        let bytes = read_regular_file_bounded(&root.dir, &name, &path, MAX_PROPOSAL_BYTES)
            .map_err(anyhow_to_io)?;
        let proposal = decode_proposal(bytes, &path)?;
        if proposal.id != id {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "proposal filename id {id:?} does not match record id {:?} at {}",
                    proposal.id,
                    path.display()
                ),
            ));
        }
        if status_filter
            .map(|status| proposal.status == status)
            .unwrap_or(true)
        {
            out.push(proposal);
        }
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

/// Mark a proposal as `Approved` or `Rejected`. Returns the
/// updated `ProposedAction`. The actual config-file mutation is
/// the operator's responsibility — NEOTH never edits user config
/// behind their back; status flips just record the verdict.
pub fn set_proposal_status(
    home: &Path,
    id: &str,
    new_status: ProposalStatus,
    operator_note: &str,
) -> std::io::Result<ProposedAction> {
    validate_proposal_id(id)?;
    if new_status == ProposalStatus::Pending {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "an operator verdict must be approved or rejected, not pending",
        ));
    }
    let root = proposals_root(home, false)?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("proposal {id} not found"),
        )
    })?;
    let _guard = lock_proposal_mutations(&root)?;
    let mut p = read_proposal_from_root(&root, id)?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("proposal {id} not found"),
        )
    })?;
    if p.status == new_status {
        return Ok(p);
    }
    if p.status != ProposalStatus::Pending {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "proposal {id} already has terminal status {}; refusing transition to {}",
                p.status.as_str(),
                new_status.as_str()
            ),
        ));
    }
    p.status = new_status;
    p.operator_note = operator_note.to_string();
    let body = proposal_body(&p)?;
    replace_proposal_file(&root, &p, &body)?;
    Ok(p)
}

/// Outcome of [`sync_proposals_to_obsidian`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalSyncOutcome {
    pub written: usize,
    pub skipped: usize,
    /// Final paths of files actually written (skipped proposals not
    /// included). Sorted ascending by id.
    pub target_paths: Vec<PathBuf>,
}

/// OB-03 — render every proposal under `status_filter` (default
/// `Pending`) into `<vault>/<subdir>/Proposals/<id>.md`. Atomic
/// per-file write. Existing `.md` files are overwritten — the
/// proposal JSON is the source of truth; the markdown is a
/// renderable view of it.
pub fn sync_proposals_to_obsidian(
    neoth_home: &Path,
    vault_root: &Path,
    subdir: &str,
    status_filter: Option<ProposalStatus>,
) -> std::io::Result<ProposalSyncOutcome> {
    crate::cli::obsidian::validate_subdir(Path::new(subdir)).map_err(anyhow_to_io)?;
    let proposals = list_proposals(neoth_home, status_filter)?;
    let dest_dir = vault_root.join(subdir).join("Proposals");
    if proposals.is_empty() {
        return Ok(ProposalSyncOutcome {
            written: 0,
            skipped: 0,
            target_paths: Vec::new(),
        });
    }
    let dest_root = open_bound_directory(&dest_dir, true, "proposal vault view")
        .map_err(anyhow_to_io)?
        .expect("created proposal vault view must exist");
    let _guard = lock_proposal_mutations(&dest_root)?;

    let mut target_paths = Vec::with_capacity(proposals.len());
    let mut written = 0usize;
    for p in &proposals {
        validate_proposal_id(&p.id)?;
        let final_name = OsString::from(format!("{}.md", p.id));
        let final_path = dest_root.display_path.join(&final_name);
        let body = p.to_obsidian_md();
        match dest_root.dir.symlink_metadata(&final_name) {
            Ok(metadata) => {
                if !metadata.is_file() || cap_metadata_is_link_like(&metadata) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "proposal vault target is not a real regular file: {}",
                            final_path.display()
                        ),
                    ));
                }
                let report = replace_existing_regular_file_report(
                    &dest_root.dir,
                    &final_name,
                    &final_path,
                    body.as_bytes(),
                )
                .map_err(anyhow_to_io)?;
                for warning in crate::skills::operator_skill_warnings(&report.warnings) {
                    tracing::warn!(
                        path = %final_path.display(),
                        %warning,
                        "proposal vault view replacement committed with warning"
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                create_new_regular_file(
                    &dest_root,
                    &final_name,
                    &final_path,
                    body.as_bytes(),
                    ".neoth-proposal-view-stage-",
                )?;
            }
            Err(error) => return Err(error),
        }
        target_paths.push(final_path);
        written += 1;
    }

    Ok(ProposalSyncOutcome {
        written,
        skipped: 0,
        target_paths,
    })
}

/// Build a [`ProactiveItem`] that nudges the operator about a new
/// proposal. Caller pushes the returned item into the shared
/// `ProactiveQueue`; dedup_key uses the proposal id so the same
/// proposal can never enqueue twice.
pub fn build_proposal_notification(proposal: &ProposedAction) -> ProactiveItem {
    ProactiveItem {
        priority: 40,
        dedup_key: format!("ob_03_proposal:{}", proposal.id),
        channel: String::new(),
        source: "ob_03".to_string(),
        body: format!(
            "Vorschlag bereit zur Sichtung: {} — siehe Obsidian-Vault unter Proposals/{}.md",
            proposal.title, proposal.id
        ),
        scheduled_for_unix: 0,
        is_failure: false,
        expires_unix: 0, // a pending proposal stays relevant until acted on
    }
}

/// One-call helper for producer paths: save + enqueue + return the
/// item. Used by the cron path so producers don't have to remember
/// the two-step dance.
pub fn stage_and_enqueue(
    home: &Path,
    proposal: ProposedAction,
    queue: &mut ProactiveQueue,
) -> std::io::Result<(ProposedAction, bool)> {
    validate_proposal_id(&proposal.id)?;
    if proposal.status != ProposalStatus::Pending || !proposal.operator_note.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "new proposal {} must start pending with an empty operator note",
                proposal.id
            ),
        ));
    }
    let root = proposals_root(home, true)?.expect("created proposal root must exist");
    let _guard = lock_proposal_mutations(&root)?;
    if let Some(existing) = read_proposal_from_root(&root, &proposal.id)? {
        if !same_stable_payload(&existing, &proposal) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "proposal id {} collides with different staged content",
                    proposal.id
                ),
            ));
        }
        if existing.status == ProposalStatus::Pending {
            let item = build_proposal_notification(&existing);
            let enqueued = queue.enqueue(item);
            return Ok((existing, enqueued));
        }
        return Ok((existing, false));
    }
    let body = proposal_body(&proposal)?;
    create_proposal_file(&root, &proposal, &body)?;
    drop(_guard);
    let item = build_proposal_notification(&proposal);
    let enqueued = queue.enqueue(item);
    Ok((proposal, enqueued))
}

/// Convenience helper to capture wall-clock at proposal generation.
pub fn now_unix_seconds() -> i64 {
    crate::time::now_unix_i64()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(kind: ProposalKind, title: &str, ts: i64) -> ProposedAction {
        let draft =
            "schedule:\n  cron: \"0 9 * * *\"\n  tz: Europe/Berlin\nprompt: \"Morning briefing\"\n";
        let id = make_proposal_id(kind, title, draft, ts);
        ProposedAction {
            id,
            kind,
            title: title.to_string(),
            rationale: "Operator reads morning email at 09:00 most weekdays.".to_string(),
            draft_yaml: draft.to_string(),
            generated_ts_unix: ts,
            status: ProposalStatus::Pending,
            operator_note: String::new(),
        }
    }

    #[test]
    fn kind_status_as_str_pinned_for_audit() {
        assert_eq!(ProposalKind::CronJob.as_str(), "cron_job");
        assert_eq!(ProposalKind::Skill.as_str(), "skill");
        assert_eq!(ProposalKind::Hook.as_str(), "hook");
        assert_eq!(ProposalKind::ConfigTweak.as_str(), "config_tweak");
        assert_eq!(ProposalStatus::Pending.as_str(), "pending");
        assert_eq!(ProposalStatus::Approved.as_str(), "approved");
        assert_eq!(ProposalStatus::Rejected.as_str(), "rejected");
    }

    #[test]
    fn make_proposal_id_is_deterministic_for_same_inputs() {
        let a = make_proposal_id(ProposalKind::CronJob, "x", "yaml", 100);
        let b = make_proposal_id(ProposalKind::CronJob, "x", "yaml", 100);
        assert_eq!(a, b);
    }

    #[test]
    fn make_proposal_id_differs_for_different_drafts() {
        let a = make_proposal_id(ProposalKind::CronJob, "x", "yaml_a", 100);
        let b = make_proposal_id(ProposalKind::CronJob, "x", "yaml_b", 100);
        assert_ne!(a, b);
    }

    #[test]
    fn make_proposal_id_prefix_is_kind_and_timestamp() {
        let id = make_proposal_id(ProposalKind::Skill, "x", "y", 1_700_000_000);
        assert!(id.starts_with("1700000000-skill-"));
    }

    // ── make_proposal_id_content_only tests ───────────────────────────────

    #[test]
    fn content_only_id_stable_across_different_timestamps() {
        // Same content at different timestamps → same id (the core dedup guarantee).
        let a = make_proposal_id_content_only(ProposalKind::Skill, "my-skill", "yaml: body");
        let b = make_proposal_id_content_only(ProposalKind::Skill, "my-skill", "yaml: body");
        assert_eq!(a, b, "content-only id must be timestamp-independent");
    }

    #[test]
    fn content_only_id_differs_for_different_content() {
        let a = make_proposal_id_content_only(ProposalKind::Skill, "skill-a", "yaml: a");
        let b = make_proposal_id_content_only(ProposalKind::Skill, "skill-b", "yaml: a");
        assert_ne!(a, b, "different title must produce different id");
        let c = make_proposal_id_content_only(ProposalKind::Skill, "skill-a", "yaml: b");
        assert_ne!(a, c, "different draft_yaml must produce different id");
    }

    #[test]
    fn content_only_id_format_is_kind_hash() {
        let id = make_proposal_id_content_only(ProposalKind::Skill, "x", "y");
        // Format is "<kind>-<8hex>" — no timestamp prefix.
        assert!(id.starts_with("skill-"), "id must start with kind");
        let parts: Vec<&str> = id.splitn(2, '-').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], "skill");
        // Hash suffix is exactly 8 hex chars.
        assert_eq!(parts[1].len(), 8, "hash suffix must be 8 hex chars");
        assert!(
            parts[1].chars().all(|c| c.is_ascii_hexdigit()),
            "suffix must be hex"
        );
    }

    #[test]
    fn save_and_load_roundtrip() {
        let home = tempfile::tempdir().unwrap();
        let p = sample(ProposalKind::CronJob, "Morning briefing", 100);
        save_proposal(home.path(), &p).unwrap();
        let loaded = load_proposal(home.path(), &p.id).expect("load");
        assert_eq!(loaded, p);
    }

    #[test]
    fn load_missing_proposal_returns_none() {
        let home = tempfile::tempdir().unwrap();
        assert!(load_proposal(home.path(), "nonexistent").is_none());
    }

    #[test]
    fn proposal_ids_cannot_escape_the_capability_root() {
        let home = tempfile::tempdir().unwrap();
        let mut proposal = sample(ProposalKind::CronJob, "escape", 100);
        proposal.id = "../../outside".to_string();

        let error = save_proposal(home.path(), &proposal).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(!home.path().join("outside.json").exists());
        assert!(proposal_path(home.path(), &proposal.id).starts_with(proposals_dir(home.path())));
        assert!(load_proposal(home.path(), &proposal.id).is_none());
    }

    #[test]
    fn save_overwrites_existing_atomically() {
        let home = tempfile::tempdir().unwrap();
        let mut p = sample(ProposalKind::CronJob, "title", 100);
        save_proposal(home.path(), &p).unwrap();
        p.title = "new title".to_string();
        save_proposal(home.path(), &p).unwrap();
        let loaded = load_proposal(home.path(), &p.id).unwrap();
        assert_eq!(loaded.title, "new title");
        // No .tmp leaks.
        let dir = proposals_dir(home.path());
        let leftover_stage_count = std::fs::read_dir(&dir)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(PROPOSAL_STAGE_PREFIX)
            })
            .count();
        assert_eq!(leftover_stage_count, 0);
    }

    #[test]
    fn approved_skill_adoption_returns_the_complete_create_report() {
        let home = tempfile::tempdir().unwrap();
        let (_, draft_yaml) =
            crate::skills::creator::build_manifest(&crate::skills::creator::CreateParams {
                id: "typed_report".to_string(),
                description: "Typed adoption report".to_string(),
                keywords: vec!["report".to_string()],
                system_prompt: "Exercise the typed adoption path.".to_string(),
            })
            .unwrap();
        let mut proposal = sample(ProposalKind::Skill, "typed report", 100);
        proposal.status = ProposalStatus::Approved;
        proposal.draft_yaml = draft_yaml;

        let report = adopt_approved_skill(home.path(), &proposal).unwrap();

        assert_eq!(report.id, "typed_report");
        assert_eq!(
            report.path,
            home.path()
                .join("skills")
                .join("typed_report")
                .join("skill.yaml")
        );
        assert!(!report.replaced_existing);
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn proposal_reads_reject_oversized_files_before_allocation() {
        let home = tempfile::tempdir().unwrap();
        let path = proposals_dir(home.path()).join("oversized.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_PROPOSAL_BYTES as u64 + 1).unwrap();

        assert!(load_proposal(home.path(), "oversized").is_none());
        let error = list_proposals(home.path(), None).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("exceeds"));
    }

    #[test]
    fn proposal_writes_reject_oversized_records() {
        let home = tempfile::tempdir().unwrap();
        let mut proposal = sample(ProposalKind::Skill, "oversized", 100);
        proposal.draft_yaml = "x".repeat(MAX_PROPOSAL_BYTES);

        let error = save_proposal(home.path(), &proposal).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(!proposal_path(home.path(), &proposal.id).exists());
    }

    #[test]
    fn list_proposals_sorted_by_id_ascending() {
        let home = tempfile::tempdir().unwrap();
        let earlier = sample(ProposalKind::CronJob, "earlier", 100);
        let later = sample(ProposalKind::Skill, "later", 200);
        save_proposal(home.path(), &later).unwrap();
        save_proposal(home.path(), &earlier).unwrap();
        let all = list_proposals(home.path(), None).unwrap();
        assert_eq!(all.len(), 2);
        assert!(all[0].id < all[1].id);
    }

    #[test]
    fn list_proposals_status_filter_excludes_others() {
        let home = tempfile::tempdir().unwrap();
        let mut a = sample(ProposalKind::CronJob, "a", 100);
        let mut b = sample(ProposalKind::Skill, "b", 200);
        b.status = ProposalStatus::Approved;
        a.status = ProposalStatus::Pending;
        save_proposal(home.path(), &a).unwrap();
        save_proposal(home.path(), &b).unwrap();
        let pending = list_proposals(home.path(), Some(ProposalStatus::Pending)).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, a.id);
    }

    #[test]
    fn list_proposals_missing_directory_is_empty() {
        let home = tempfile::tempdir().unwrap();
        let proposals = list_proposals(home.path(), None).unwrap();
        assert!(proposals.is_empty());
        assert!(!proposals_dir(home.path()).exists());
    }

    #[test]
    fn curator_reconciliation_leaves_an_operator_modified_skill_alone() {
        // External review PR5-029: the curator re-walks every approved proposal
        // on every tick and has no terminal state, so once the operator edited
        // the adopted skill.yaml — the normal follow-up — KeepIfIdentical made
        // that proposal fail on every tick forever with nothing to do about it.
        let home = tempfile::tempdir().unwrap();
        let draft = "id: adopted_one\ndescription: d\ntrigger_keywords: [x]\nsystem_prompt: s\n";
        let mut proposal = sample(ProposalKind::Skill, "adopted", 100);
        proposal.draft_yaml = draft.to_string();
        proposal.status = ProposalStatus::Approved;

        assert!(matches!(
            reconcile_approved_skill(home.path(), &proposal).unwrap(),
            SkillReconciliation::Adopted(_)
        ));
        // Identical bytes: the repeated tick is a clean no-op, not an error.
        assert!(matches!(
            reconcile_approved_skill(home.path(), &proposal).unwrap(),
            SkillReconciliation::Adopted(_)
        ));

        let installed = home
            .path()
            .join("skills")
            .join("adopted_one")
            .join("skill.yaml");
        std::fs::write(&installed, format!("{draft}# operator note\n")).unwrap();

        match reconcile_approved_skill(home.path(), &proposal).unwrap() {
            SkillReconciliation::OperatorModified { id } => assert_eq!(id, "adopted_one"),
            other => panic!("an operator edit must not error on every tick: {other:?}"),
        }
        assert!(
            std::fs::read_to_string(&installed)
                .unwrap()
                .contains("# operator note"),
            "and the operator's edit must survive — overwriting it was the original bug"
        );
    }

    #[test]
    fn list_proposals_skips_foreign_entries_but_still_fails_on_corrupt_proposals() {
        // External review PR5-008: one entry this store could never have written
        // used to fail the WHOLE listing, which silently stopped the curator
        // from promoting approved proposals, stopped the vault sync, and blanked
        // the operator's view of every healthy proposal.
        let home = tempfile::tempdir().unwrap();
        let healthy = sample(ProposalKind::CronJob, "healthy", 100);
        save_proposal(home.path(), &healthy).unwrap();
        // An editor/backup artefact: `.json`, but the stem is not a proposal id.
        std::fs::write(
            proposals_dir(home.path()).join("notes.backup.json"),
            b"whatever",
        )
        .unwrap();

        let listed = list_proposals(home.path(), None)
            .expect("a foreign entry must not blank the whole store");
        assert_eq!(listed.len(), 1, "the healthy proposal must still be listed");
        assert_eq!(listed[0].id, healthy.id);

        // A recognisable proposal that is corrupt stays fail-closed: an approved
        // proposal must never be silently skipped.
        std::fs::write(
            proposals_dir(home.path()).join("corrupt-one.json"),
            b"{not-json",
        )
        .unwrap();
        let error = list_proposals(home.path(), None)
            .expect_err("a corrupt proposal must still fail the listing");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn list_proposals_propagates_json_corruption() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(proposals_dir(home.path())).unwrap();
        std::fs::write(proposals_dir(home.path()).join("broken.json"), b"{not-json").unwrap();

        let error = list_proposals(home.path(), None).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("broken.json"));
    }

    #[test]
    fn list_proposals_rejects_filename_record_id_mismatch() {
        let home = tempfile::tempdir().unwrap();
        let proposal = sample(ProposalKind::CronJob, "mismatch", 100);
        std::fs::create_dir_all(proposals_dir(home.path())).unwrap();
        std::fs::write(
            proposals_dir(home.path()).join("different-id.json"),
            serde_json::to_vec(&proposal).unwrap(),
        )
        .unwrap();

        let error = list_proposals(home.path(), None).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("does not match record id"));
    }

    #[test]
    fn list_proposals_propagates_entry_read_failure() {
        let home = tempfile::tempdir().unwrap();
        let unreadable = proposals_dir(home.path()).join("directory.json");
        std::fs::create_dir_all(&unreadable).unwrap();

        let error = list_proposals(home.path(), None).unwrap_err();
        assert_ne!(error.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn set_proposal_status_flips_and_writes_note() {
        let home = tempfile::tempdir().unwrap();
        let p = sample(ProposalKind::CronJob, "x", 100);
        save_proposal(home.path(), &p).unwrap();
        let updated =
            set_proposal_status(home.path(), &p.id, ProposalStatus::Approved, "looks good")
                .unwrap();
        assert_eq!(updated.status, ProposalStatus::Approved);
        assert_eq!(updated.operator_note, "looks good");
        // Persisted.
        let again = load_proposal(home.path(), &p.id).unwrap();
        assert_eq!(again.status, ProposalStatus::Approved);
    }

    #[test]
    fn set_proposal_status_missing_id_errors() {
        let home = tempfile::tempdir().unwrap();
        let err =
            set_proposal_status(home.path(), "nope", ProposalStatus::Approved, "").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn proposal_verdicts_are_terminal_and_idempotent() {
        let home = tempfile::tempdir().unwrap();
        let proposal = sample(ProposalKind::CronJob, "terminal", 100);
        save_proposal(home.path(), &proposal).unwrap();
        let approved = set_proposal_status(
            home.path(),
            &proposal.id,
            ProposalStatus::Approved,
            "first verdict",
        )
        .unwrap();

        let repeated = set_proposal_status(
            home.path(),
            &proposal.id,
            ProposalStatus::Approved,
            "must not replace the first audit note",
        )
        .unwrap();
        assert_eq!(repeated, approved);

        let error = set_proposal_status(
            home.path(),
            &proposal.id,
            ProposalStatus::Rejected,
            "reverse verdict",
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(load_proposal(home.path(), &proposal.id).unwrap(), approved);
    }

    #[test]
    fn direct_save_cannot_overwrite_a_terminal_verdict() {
        let home = tempfile::tempdir().unwrap();
        let proposal = sample(ProposalKind::CronJob, "terminal", 100);
        save_proposal(home.path(), &proposal).unwrap();
        let approved = set_proposal_status(
            home.path(),
            &proposal.id,
            ProposalStatus::Approved,
            "approved",
        )
        .unwrap();

        let error = save_proposal(home.path(), &proposal).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(load_proposal(home.path(), &proposal.id).unwrap(), approved);
    }

    #[test]
    fn to_obsidian_md_contains_frontmatter_and_yaml_block() {
        let p = sample(ProposalKind::CronJob, "Morning briefing", 1_700_000_000);
        let md = p.to_obsidian_md();
        assert!(md.starts_with("---\n"));
        assert!(md.contains(&format!("id: \"{}\"", p.id)));
        assert!(md.contains("kind: \"cron_job\""));
        assert!(md.contains("status: \"pending\""));
        assert!(md.contains("# Proposal — Morning briefing"));
        assert!(md.contains("```yaml"));
        assert!(md.contains("neoth proactive accept"));
        assert!(md.contains("neoth proactive reject"));
    }

    #[test]
    fn sync_empty_proposals_writes_nothing() {
        let home = tempfile::tempdir().unwrap();
        let vault = tempfile::tempdir().unwrap();
        let out = sync_proposals_to_obsidian(
            home.path(),
            vault.path(),
            "NEOTH",
            Some(ProposalStatus::Pending),
        )
        .unwrap();
        assert_eq!(out.written, 0);
        assert!(out.target_paths.is_empty());
    }

    #[test]
    fn sync_rejects_a_subdir_that_escapes_the_vault() {
        let home = tempfile::tempdir().unwrap();
        let vault_parent = tempfile::tempdir().unwrap();
        let vault = vault_parent.path().join("vault");
        std::fs::create_dir(&vault).unwrap();
        let proposal = sample(ProposalKind::CronJob, "escape", 100);
        save_proposal(home.path(), &proposal).unwrap();

        let error = sync_proposals_to_obsidian(
            home.path(),
            &vault,
            "../outside",
            Some(ProposalStatus::Pending),
        )
        .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert!(!vault_parent.path().join("outside").exists());
    }

    #[test]
    fn sync_writes_one_md_per_proposal() {
        let home = tempfile::tempdir().unwrap();
        let vault = tempfile::tempdir().unwrap();
        let a = sample(ProposalKind::CronJob, "a", 100);
        let b = sample(ProposalKind::Skill, "b", 200);
        save_proposal(home.path(), &a).unwrap();
        save_proposal(home.path(), &b).unwrap();
        let out = sync_proposals_to_obsidian(
            home.path(),
            vault.path(),
            "NEOTH",
            Some(ProposalStatus::Pending),
        )
        .unwrap();
        assert_eq!(out.written, 2);
        assert_eq!(out.target_paths.len(), 2);
        for path in &out.target_paths {
            assert!(path.exists());
            let body = std::fs::read_to_string(path).unwrap();
            assert!(body.contains("# Proposal"));
        }
    }

    #[test]
    fn sync_filter_skips_non_matching_status() {
        let home = tempfile::tempdir().unwrap();
        let vault = tempfile::tempdir().unwrap();
        let mut approved = sample(ProposalKind::CronJob, "a", 100);
        approved.status = ProposalStatus::Approved;
        let pending = sample(ProposalKind::Skill, "b", 200);
        save_proposal(home.path(), &approved).unwrap();
        save_proposal(home.path(), &pending).unwrap();
        let out = sync_proposals_to_obsidian(
            home.path(),
            vault.path(),
            "NEOTH",
            Some(ProposalStatus::Pending),
        )
        .unwrap();
        assert_eq!(out.written, 1);
    }

    #[test]
    fn sync_replaces_an_existing_view_without_ambient_remove() {
        let home = tempfile::tempdir().unwrap();
        let vault = tempfile::tempdir().unwrap();
        let mut proposal = sample(ProposalKind::CronJob, "first title", 100);
        save_proposal(home.path(), &proposal).unwrap();
        let first = sync_proposals_to_obsidian(
            home.path(),
            vault.path(),
            "NEOTH",
            Some(ProposalStatus::Pending),
        )
        .unwrap();
        proposal.title = "updated title".to_string();
        save_proposal(home.path(), &proposal).unwrap();

        let second = sync_proposals_to_obsidian(
            home.path(),
            vault.path(),
            "NEOTH",
            Some(ProposalStatus::Pending),
        )
        .unwrap();

        assert_eq!(second.target_paths, first.target_paths);
        let body = std::fs::read_to_string(&second.target_paths[0]).unwrap();
        assert!(body.contains("# Proposal — updated title"));
        let view_dir = second.target_paths[0].parent().unwrap();
        assert!(!std::fs::read_dir(view_dir).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".neoth-proposal-view-stage-")
        }));
    }

    #[test]
    fn build_proposal_notification_dedup_key_includes_id() {
        let p = sample(ProposalKind::CronJob, "title", 100);
        let item = build_proposal_notification(&p);
        assert!(item.dedup_key.contains(&p.id));
        assert_eq!(item.source, "ob_03");
        assert_eq!(item.priority, 40);
    }

    #[test]
    fn stage_and_enqueue_persists_then_pushes() {
        let home = tempfile::tempdir().unwrap();
        let mut q = ProactiveQueue::new();
        let p = sample(ProposalKind::CronJob, "x", 100);
        let id = p.id.clone();
        let (returned, enqueued) = stage_and_enqueue(home.path(), p, &mut q).unwrap();
        assert!(enqueued);
        assert_eq!(returned.id, id);
        assert_eq!(q.len(), 1);
        assert!(load_proposal(home.path(), &id).is_some());
    }

    #[test]
    fn stage_and_enqueue_dedups_via_proposal_id() {
        let home = tempfile::tempdir().unwrap();
        let mut q = ProactiveQueue::new();
        let p1 = sample(ProposalKind::CronJob, "x", 100);
        let p2 = p1.clone(); // same id → ProactiveQueue dedupes
        let (_, e1) = stage_and_enqueue(home.path(), p1, &mut q).unwrap();
        let (_, e2) = stage_and_enqueue(home.path(), p2, &mut q).unwrap();
        assert!(e1);
        assert!(!e2, "duplicate proposal must not enqueue twice");
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn pending_retry_can_restore_a_missing_queue_notification() {
        let home = tempfile::tempdir().unwrap();
        let proposal = sample(ProposalKind::CronJob, "recover notification", 100);
        save_proposal(home.path(), &proposal).unwrap();
        let mut fresh_queue = ProactiveQueue::new();

        let (returned, enqueued) =
            stage_and_enqueue(home.path(), proposal.clone(), &mut fresh_queue).unwrap();

        assert!(enqueued);
        assert_eq!(fresh_queue.len(), 1);
        assert_eq!(returned, proposal);
    }

    #[test]
    fn stable_retry_preserves_terminal_verdict_and_does_not_reenqueue() {
        let home = tempfile::tempdir().unwrap();
        let mut first_queue = ProactiveQueue::new();
        let proposal = sample(ProposalKind::Skill, "stable", 100);
        stage_and_enqueue(home.path(), proposal.clone(), &mut first_queue).unwrap();
        let approved = set_proposal_status(
            home.path(),
            &proposal.id,
            ProposalStatus::Approved,
            "ship it",
        )
        .unwrap();
        let mut fresh_queue = ProactiveQueue::new();
        let mut retry = proposal;
        retry.generated_ts_unix = 999;
        retry.rationale = "producer generated a newer explanation".to_string();

        let (returned, enqueued) = stage_and_enqueue(home.path(), retry, &mut fresh_queue).unwrap();

        assert!(!enqueued);
        assert!(fresh_queue.is_empty());
        assert_eq!(returned, approved);
        assert_eq!(load_proposal(home.path(), &approved.id).unwrap(), approved);
    }

    #[test]
    fn stable_id_collision_with_different_payload_fails_closed() {
        let home = tempfile::tempdir().unwrap();
        let mut queue = ProactiveQueue::new();
        let proposal = sample(ProposalKind::CronJob, "original", 100);
        stage_and_enqueue(home.path(), proposal.clone(), &mut queue).unwrap();
        let mut collision = proposal.clone();
        collision.title = "different".to_string();

        let error = stage_and_enqueue(home.path(), collision, &mut queue).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(load_proposal(home.path(), &proposal.id).unwrap(), proposal);
    }

    #[test]
    fn proposal_store_uses_an_os_visible_mutation_lock() {
        let home = tempfile::tempdir().unwrap();
        let root = proposals_root(home.path(), true).unwrap().unwrap();
        let _guard = lock_proposal_mutations(&root).unwrap();
        let second = crate::util::locked_file::try_lock_file_once(
            &root.display_path.join(PROPOSAL_MUTATION_LOCK_FILE),
            "proposal mutation",
        )
        .unwrap();

        assert!(second.is_none());
    }

    #[test]
    fn to_obsidian_md_escapes_quotes_in_id() {
        // Hypothetical id with a quote — the YAML frontmatter must escape it.
        let mut p = sample(ProposalKind::CronJob, "x", 100);
        p.id = "weird\"id".to_string();
        let md = p.to_obsidian_md();
        assert!(md.contains("id: \"weird\\\"id\""), "got {md}");
    }

    #[test]
    fn json_status_serialisation_is_snake_case() {
        let mut p = sample(ProposalKind::Skill, "x", 100);
        p.status = ProposalStatus::Approved;
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"status\":\"approved\""));
        assert!(json.contains("\"kind\":\"skill\""));
    }
}
