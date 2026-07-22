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
//! status follows the authenticated monotonic lifecycle from `Pending` to an
//! operator verdict and, for generated Skills, through Applying/Applied or
//! Revoked. The original operator note remains immutable. JSONL was
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

use anyhow::Context as _;
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _};
use cap_std::fs::OpenOptions as CapOpenOptions;
use hmac::{Hmac, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::proactive::{ProactiveItem, ProactiveQueue};
use crate::skills::authority::{
    AuthorityDecision, AuthorityDecisionRequest, AuthorityDecisionSource, InstalledToolScope,
    SkillActivation, SkillAuthorityGrant, SkillAuthorityRecord, SkillAuthorityState,
    SkillProvenance,
};
use crate::skills::authority_key::{
    SkillAuthorityKey, load_authority_key_at, load_or_init_authority_key_at,
};
use crate::skills::installer;
use crate::skills::schema::SkillManifest;
use crate::skills::store::{
    BoundDirectory, cap_metadata_is_link_like, open_bound_directory, open_real_child_dir,
    read_regular_file_bounded, remove_child_file, remove_real_directory_tree, rename_child,
    replace_existing_regular_file_report, sync_parent_directory,
};

const MAX_PROPOSAL_BYTES: usize = 1024 * 1024;
const MAX_PROPOSAL_ENTRIES: usize = 4096;
const MAX_PROPOSAL_ID_BYTES: usize = 128;
const PROPOSAL_ENVELOPE_SCHEMA_VERSION: u8 = 1;
const PROPOSAL_MAC_DOMAIN: &[u8] = b"neoth-proactive-proposal-hmac-v1";
const PROPOSAL_MUTATION_LOCK_FILE: &str = ".neoth-proposals.lock";
const PROPOSAL_STAGE_PREFIX: &str = ".neoth-proposal-stage-";
pub(crate) const GENERATED_SKILL_STAGE_PREFIX: &str = ".neoth-generated-skill-stage-";
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

/// Authenticated monotonic lifecycle for a proposal.
///
/// `Approved` and `Rejected` are operator verdicts. `Applying`, `Applied`, and
/// `Revoked` are machine lifecycle states; machine transitions never rewrite
/// the operator note that records the original verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalStatus {
    Pending,
    Approved,
    Rejected,
    Applying,
    Applied,
    Revoked,
}

impl ProposalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ProposalStatus::Pending => "pending",
            ProposalStatus::Approved => "approved",
            ProposalStatus::Rejected => "rejected",
            ProposalStatus::Applying => "applying",
            ProposalStatus::Applied => "applied",
            ProposalStatus::Revoked => "revoked",
        }
    }
}

fn valid_proposal_lifecycle_transition(from: ProposalStatus, to: ProposalStatus) -> bool {
    from == to
        || matches!(
            (from, to),
            (ProposalStatus::Pending, ProposalStatus::Approved)
                | (ProposalStatus::Pending, ProposalStatus::Rejected)
                | (ProposalStatus::Approved, ProposalStatus::Applying)
                | (ProposalStatus::Approved, ProposalStatus::Revoked)
                | (ProposalStatus::Applying, ProposalStatus::Applied)
                | (ProposalStatus::Applying, ProposalStatus::Revoked)
                | (ProposalStatus::Applied, ProposalStatus::Revoked)
        )
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

/// Authenticated on-disk representation of a proposal.
///
/// Proposal JSON is an authority input after operator approval, so a bare
/// self-consistent `ProposedAction` is never trusted from disk.  The envelope
/// binds every displayed and executable field to the per-instance authority
/// key.  Unsigned pre-v1 records fail closed and must be re-staged/reviewed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredProposalEnvelope {
    schema_version: u8,
    key_id: String,
    proposal: ProposedAction,
    mac: String,
}

#[derive(Serialize)]
struct ProposalMacPayload<'a> {
    schema_version: u8,
    key_id: &'a str,
    proposal: &'a ProposedAction,
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

/// Exact install and authority receipt for one generated Skill proposal.
///
/// Install and authority mutation are two atomic filesystem generations, not
/// one cross-generation transaction. If authority mutation fails after a new
/// install, the installer-owned pending sidecar keeps the Skill inactive and
/// non-routable. Retrying the same approved proposal deterministically resumes
/// from that exact pending generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkillAdoptionReport {
    pub proposal_id: String,
    pub id: String,
    pub installed_at: PathBuf,
    pub installed_new: bool,
    pub authority_changed: bool,
    pub install_manifest_sha256: String,
    pub install_package_generation_sha256: String,
    /// Installed-tree hash immediately before the authority decision. On a
    /// fresh adoption this is the pending, fail-closed install generation.
    pub pending_installed_generation_sha256: String,
    /// Installed-tree hash after the exact Active authority decision.
    pub authority_installed_generation_sha256: String,
    pub authority_record_sha256: String,
    pub authority_state: SkillAuthorityState,
    pub provenance: SkillProvenance,
    pub warnings: Vec<String>,
}

struct PreparedSkillAuthorityAdoption {
    proposal_id: String,
    id: String,
    installed_at: PathBuf,
    installed_new: bool,
    install_manifest_sha256: String,
    install_package_generation_sha256: String,
    pending_installed_generation_sha256: String,
    authority: installer::PreparedAuthorityMutation,
    warnings: Vec<String>,
}

enum SkillAdoptionPreparation {
    Complete(SkillAdoptionReport),
    RequiresAuthority(PreparedSkillAuthorityAdoption),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProposalAdoptionClaim {
    NewlyApplying,
    RecoveringApplying,
    AlreadyApplied,
}

#[derive(Debug, Clone)]
struct ClaimedSkillProposal {
    proposal: ProposedAction,
    claim: ProposalAdoptionClaim,
}

impl SkillAdoptionPreparation {
    fn warnings_mut(&mut self) -> &mut Vec<String> {
        match self {
            Self::Complete(report) => &mut report.warnings,
            Self::RequiresAuthority(prepared) => &mut prepared.warnings,
        }
    }
}

/// Adopt an operator-approved generated Skill through the hardened installer.
///
/// The exact displayed `draft_yaml` is copied into a private source directory,
/// inspected with [`SkillProvenance::Generated`], installed pending, then
/// granted Active authority for exactly its qualified manifest tool claims and
/// exact delegate/model/source claims. No manifest claim is synthesized.
pub async fn adopt_approved_skill(
    home: &Path,
    proposal: &ProposedAction,
    direct_writer: Option<&crate::wal::writer::WalWriterHandle>,
) -> anyhow::Result<SkillAdoptionReport> {
    let preparation_home = home.to_path_buf();
    let supplied = proposal.clone();
    let (claimed, preparation) = tokio::task::spawn_blocking(move || {
        prepare_approved_skill_adoption(&preparation_home, &supplied)
    })
    .await
    .context("generated Skill adoption preparation worker failed")??;

    let prepared = match preparation {
        SkillAdoptionPreparation::Complete(report) => {
            return complete_generated_skill_adoption(home, &claimed, report).await;
        }
        SkillAdoptionPreparation::RequiresAuthority(prepared) => prepared,
    };
    let PreparedSkillAuthorityAdoption {
        proposal_id,
        id,
        installed_at,
        installed_new,
        install_manifest_sha256,
        install_package_generation_sha256,
        pending_installed_generation_sha256,
        authority: prepared_authority,
        mut warnings,
    } = prepared;

    run_before_generated_authority_commit_test_hook();
    let recheck_home = home.to_path_buf();
    let recheck_claimed = claimed.clone();
    tokio::task::spawn_blocking(move || {
        reauthenticate_claimed_proposal(&recheck_home, &recheck_claimed, ProposalStatus::Applying)
    })
    .await
    .context("generated Skill lifecycle reauthentication worker failed")??;

    let prior_warning_context = if warnings.is_empty() {
        String::new()
    } else {
        format!("; prior durability warnings: {}", warnings.join(" | "))
    };
    let identity = crate::skills::authority_audit::mint_skill_authority_transition_identity();
    let authority = installer::audit_and_commit_prepared_authority_mutation(
        prepared_authority,
        direct_writer,
        identity.decision_id,
        identity.ts_unix,
    )
    .await
    .with_context(|| {
        format!(
            "generated Skill `{id}` remains pending and non-routable because its exact authority transition was not durably audited and committed; retry proposal {proposal_id}{prior_warning_context}"
        )
    })?;
    warnings.extend(authority.warnings);
    let committed_generation_sha256 = authority.installed_generation_sha256.clone();
    let report = adoption_report(
        &proposal_id,
        &id,
        installed_at,
        installed_new,
        true,
        &install_manifest_sha256,
        &install_package_generation_sha256,
        pending_installed_generation_sha256,
        authority.installed_generation_sha256,
        authority.authority,
        warnings,
    );
    let report = match report {
        Ok(report) => report,
        Err(error) => {
            let cleanup = remove_generated_adoption_generation(
                home,
                &id,
                &proposal_id,
                &committed_generation_sha256,
            )
            .await;
            return match cleanup {
                Ok(()) => Err(error).context(
                    "generated Skill authority commit returned an invalid receipt; the exact installed generation was removed",
                ),
                Err(cleanup_error) => Err(error).context(format!(
                    "generated Skill authority commit returned an invalid receipt, and fail-closed removal also failed: {cleanup_error:#}"
                )),
            };
        }
    };
    complete_generated_skill_adoption(home, &claimed, report).await
}

fn prepare_approved_skill_adoption(
    home: &Path,
    proposal: &ProposedAction,
) -> anyhow::Result<(ClaimedSkillProposal, SkillAdoptionPreparation)> {
    let claimed = claim_generated_skill_proposal(home, proposal)?;
    validate_skill_proposal_payload(&claimed.proposal)?;
    let manifest: SkillManifest =
        serde_yaml::from_str(&claimed.proposal.draft_yaml).with_context(|| {
            format!(
                "approved skill proposal {} carries invalid draft_yaml SkillManifest",
                claimed.proposal.id
            )
        })?;
    crate::skills::creator::validate_skill_id(&manifest.id)
        .with_context(|| format!("skill id {:?} is not a safe directory name", manifest.id))?;

    let mut stage = stage_generated_skill(home, claimed.proposal.draft_yaml.as_bytes())?;
    let result = prepare_staged_generated_skill(
        home,
        &claimed.proposal,
        claimed.claim,
        &manifest,
        stage.path(),
    );
    let cleanup = stage.cleanup();
    let preparation = match (result, cleanup) {
        (Ok(preparation), Ok(())) => preparation,
        (Ok(mut preparation), Err(error)) => {
            preparation.warnings_mut().push(format!(
                "private generated skill staging cleanup remains pending: {error:#}"
            ));
            preparation
        }
        (Err(error), Ok(())) => return Err(error),
        (Err(error), Err(cleanup_error)) => {
            return Err(error.context(format!(
                "generated skill adoption failed and private staging cleanup also failed: {cleanup_error:#}"
            )));
        }
    };
    Ok((claimed, preparation))
}

fn validate_skill_proposal_payload(proposal: &ProposedAction) -> anyhow::Result<()> {
    if proposal.kind != ProposalKind::Skill {
        anyhow::bail!("proposal {} is not a Skill proposal", proposal.id);
    }
    validate_proposal_id(&proposal.id).map_err(anyhow::Error::from)?;
    let timestamp_id = make_proposal_id(
        proposal.kind,
        &proposal.title,
        &proposal.draft_yaml,
        proposal.generated_ts_unix,
    );
    let content_id =
        make_proposal_id_content_only(proposal.kind, &proposal.title, &proposal.draft_yaml);
    if proposal.id != timestamp_id && proposal.id != content_id {
        anyhow::bail!(
            "skill proposal {} payload no longer matches its staged proposal id; refusing stale or tampered approval",
            proposal.id
        );
    }
    Ok(())
}

async fn complete_generated_skill_adoption(
    home: &Path,
    claimed: &ClaimedSkillProposal,
    report: SkillAdoptionReport,
) -> anyhow::Result<SkillAdoptionReport> {
    let finish_home = home.to_path_buf();
    let finish_claimed = claimed.clone();
    let finished = tokio::task::spawn_blocking(move || {
        finish_claimed_proposal_lifecycle(&finish_home, &finish_claimed)
    })
    .await
    .context("generated Skill lifecycle finalization worker failed")?;

    match finished {
        Ok(ProposalStatus::Applied) => Ok(report),
        Ok(ProposalStatus::Revoked) => {
            remove_revoked_adoption_generation(home, &report).await?;
            anyhow::bail!(
                "generated Skill proposal {} was revoked during adoption; its exact installed generation was removed",
                report.proposal_id
            )
        }
        Ok(status) => {
            remove_revoked_adoption_generation(home, &report).await?;
            anyhow::bail!(
                "generated Skill proposal {} reached unexpected lifecycle status {}; its exact installed generation was removed",
                report.proposal_id,
                status.as_str()
            )
        }
        Err(error) => {
            let cleanup = remove_revoked_adoption_generation(home, &report).await;
            match cleanup {
                Ok(()) => Err(error).context(
                    "generated Skill lifecycle could not be authenticated after authority commit; the exact installed generation was removed",
                ),
                Err(cleanup_error) => Err(error).context(format!(
                    "generated Skill lifecycle could not be authenticated after authority commit, and fail-closed removal also failed: {cleanup_error:#}"
                )),
            }
        }
    }
}

async fn remove_revoked_adoption_generation(
    home: &Path,
    report: &SkillAdoptionReport,
) -> anyhow::Result<()> {
    remove_generated_adoption_generation(
        home,
        &report.id,
        &report.proposal_id,
        &report.authority_installed_generation_sha256,
    )
    .await
}

async fn remove_generated_adoption_generation(
    home: &Path,
    id: &str,
    proposal_id: &str,
    installed_generation_sha256: &str,
) -> anyhow::Result<()> {
    let home = home.to_path_buf();
    let id = id.to_owned();
    let proposal_id = proposal_id.to_owned();
    let installed_generation_sha256 = installed_generation_sha256.to_owned();
    tokio::task::spawn_blocking(move || {
        ensure_generated_proposal_generation_not_routable(
            &home,
            &id,
            &proposal_id,
            &installed_generation_sha256,
        )
    })
    .await
    .context("revoked generated Skill cleanup worker failed")?
}

fn ensure_generated_proposal_generation_not_routable(
    home: &Path,
    id: &str,
    proposal_id: &str,
    initial_generation_sha256: &str,
) -> anyhow::Result<()> {
    let skills_dir = home.join("skills");
    let mut expected_generation = initial_generation_sha256.to_owned();
    for _ in 0..4 {
        let target = installer::inspect_installed_target(&skills_dir, id)?;
        let Some(current_generation) = target.target_generation_sha256 else {
            return Ok(());
        };
        if current_generation != expected_generation {
            let Ok(authenticated) =
                installer::inspect_authenticated_current_authority(&skills_dir, id)
            else {
                return Ok(());
            };
            let still_bound_to_revoked_proposal = authenticated.record.provenance
                == SkillProvenance::Generated
                && authenticated.record.state()? == SkillAuthorityState::Active
                && matches!(
                    authenticated.record.decision_source.as_ref(),
                    Some(AuthorityDecisionSource::Proactive { proposal_id: bound })
                        if bound == proposal_id
                );
            if !still_bound_to_revoked_proposal {
                return Ok(());
            }
            expected_generation = current_generation;
            continue;
        }

        let expectation = installer::UninstallExpectation {
            id: id.to_owned(),
            target_generation_sha256: expected_generation.clone(),
        };
        match installer::uninstall_with_report_and_expectation(&skills_dir, id, Some(&expectation))
        {
            Ok(report) => {
                for warning in report.warnings {
                    tracing::warn!(
                        proposal_id = %proposal_id,
                        skill_id = id,
                        %warning,
                        "revoked generated Skill removal committed with warning"
                    );
                }
                return Ok(());
            }
            Err(error) => {
                let changed = installer::inspect_installed_target(&skills_dir, id)?;
                if changed.target_generation_sha256.as_deref() == Some(expected_generation.as_str())
                {
                    return Err(error).context(format!(
                        "remove active generation of revoked proposal {proposal_id}"
                    ));
                }
            }
        }
    }
    anyhow::bail!(
        "generated Skill `{id}` kept changing while removing revoked proposal {proposal_id}"
    )
}

#[cfg(test)]
thread_local! {
    static BEFORE_GENERATED_AUTHORITY_COMMIT_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn set_before_generated_authority_commit_test_hook(hook: impl FnOnce() + 'static) {
    BEFORE_GENERATED_AUTHORITY_COMMIT_HOOK.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(hook));
    });
}

#[cfg(test)]
fn run_before_generated_authority_commit_test_hook() {
    BEFORE_GENERATED_AUTHORITY_COMMIT_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_before_generated_authority_commit_test_hook() {}

/// Verify that a generic installed-skill activation cannot mint Generated
/// authority from a caller-supplied proposal id.  The request must be a
/// non-escalating subset of one authenticated proposal whose Approved verdict
/// has been atomically claimed as Applying, and must target the exact
/// single-file package generation produced by its reviewed draft.
pub(crate) fn verify_generated_authority_approval(
    home: &Path,
    current: &installer::CurrentSkillGeneration,
    request: &AuthorityDecisionRequest,
) -> anyhow::Result<()> {
    request.validate()?;
    if current.authority.provenance != SkillProvenance::Generated
        || request.provenance != SkillProvenance::Generated
        || !current.authority.sidecar_present
    {
        anyhow::bail!(
            "generated proposal verification requires an installed Generated authority sidecar"
        );
    }
    let proposal_id = match &request.decision_source {
        AuthorityDecisionSource::Proactive { proposal_id } => proposal_id,
        _ => anyhow::bail!(
            "generated skill approval must be bound to an authenticated proactive proposal"
        ),
    };
    let AuthorityDecision::Approve {
        activation: SkillActivation::Active,
        tool_scope,
        approve_delegate,
        approve_model,
        approve_source,
        approve_effort,
        approve_loop_trigger,
    } = &request.decision
    else {
        anyhow::bail!("generated proposal verification accepts only an Active approval");
    };

    let proposal = load_proposal(home, proposal_id)
        .with_context(|| format!("authenticate generated proposal {proposal_id}"))?
        .with_context(|| format!("approved generated proposal {proposal_id} is missing"))?;
    validate_skill_proposal_payload(&proposal)?;
    if proposal.status != ProposalStatus::Applying {
        anyhow::bail!(
            "generated proposal {proposal_id} is not in the authenticated Applying lifecycle state (status={}); use `neoth proactive accept {proposal_id}`",
            proposal.status.as_str()
        );
    }
    let manifest: SkillManifest =
        serde_yaml::from_str(&proposal.draft_yaml).with_context(|| {
            format!(
                "approved generated proposal {proposal_id} carries invalid draft_yaml SkillManifest"
            )
        })?;
    if manifest.id != current.id {
        anyhow::bail!(
            "approved generated proposal {proposal_id} targets skill `{}`, not `{}`",
            manifest.id,
            current.id
        );
    }

    let mut stage = stage_generated_skill(home, proposal.draft_yaml.as_bytes())?;
    let inspected = installer::inspect_local_install_with_provenance(
        stage.path(),
        &home.join("skills"),
        SkillProvenance::Generated,
    )
    .context("inspect authenticated generated proposal generation");
    let cleanup = stage.cleanup();
    let inspected = match (inspected, cleanup) {
        (Ok(inspected), Ok(())) => inspected,
        (Ok(_), Err(error)) => {
            return Err(error).context(
                "authenticated generated proposal verification left private staging state",
            );
        }
        (Err(error), Ok(())) => return Err(error),
        (Err(error), Err(cleanup_error)) => {
            return Err(error.context(format!(
                "generated proposal verification failed and private staging cleanup also failed: {cleanup_error:#}"
            )));
        }
    };
    if inspected.id != current.id
        || inspected.source_manifest_sha256 != current.manifest_sha256
        || inspected.source_generation_sha256 != current.package_generation_sha256
        || request.expected_manifest_sha256 != current.manifest_sha256
        || request.expected_package_generation_sha256 != current.package_generation_sha256
    {
        anyhow::bail!(
            "installed Generated skill `{}` is not the exact package generation approved by proposal {proposal_id}",
            current.id
        );
    }

    if let Some(tools) = tool_scope.exact_tools() {
        for tool in tools {
            if !manifest
                .tool_allowlist
                .iter()
                .any(|claim| claim == tool.as_str())
            {
                anyhow::bail!(
                    "generated authority request grants tool `{}` outside approved proposal {proposal_id}",
                    tool.as_str()
                );
            }
        }
    }
    for (label, granted, claimed) in [
        (
            "delegate",
            approve_delegate.as_deref(),
            manifest.delegate_to.as_deref(),
        ),
        ("model", approve_model.as_deref(), manifest.model.as_deref()),
        (
            "source",
            approve_source.as_deref(),
            manifest.source.as_deref(),
        ),
    ] {
        if granted.is_some() && granted != claimed {
            anyhow::bail!(
                "generated authority request grants {label} outside approved proposal {proposal_id}"
            );
        }
    }
    if *approve_effort != manifest.effort || *approve_loop_trigger != manifest.loop_trigger {
        anyhow::bail!(
            "generated authority request changes effort or loop execution outside approved proposal {proposal_id}"
        );
    }
    Ok(())
}

fn generated_authority_request(
    proposal: &ProposedAction,
    manifest: &SkillManifest,
    manifest_sha256: &str,
    package_generation_sha256: &str,
) -> anyhow::Result<AuthorityDecisionRequest> {
    let tool_scope = InstalledToolScope::allow_only(&manifest.tool_allowlist).with_context(|| {
        format!(
            "generated skill proposal {} contains a tool claim that is not an exact qualified server::tool id",
            proposal.id
        )
    })?;
    let request = AuthorityDecisionRequest {
        expected_manifest_sha256: manifest_sha256.to_owned(),
        expected_package_generation_sha256: package_generation_sha256.to_owned(),
        provenance: SkillProvenance::Generated,
        decision_source: AuthorityDecisionSource::Proactive {
            proposal_id: proposal.id.clone(),
        },
        decision: AuthorityDecision::Approve {
            activation: SkillActivation::Active,
            tool_scope,
            approve_delegate: manifest.delegate_to.clone(),
            approve_model: manifest.model.clone(),
            approve_source: manifest.source.clone(),
            approve_effort: manifest.effort,
            approve_loop_trigger: manifest.loop_trigger,
        },
    };
    request.validate()?;
    Ok(request)
}

fn expected_generated_authority_record(
    id: &str,
    request: &AuthorityDecisionRequest,
) -> anyhow::Result<SkillAuthorityRecord> {
    let AuthorityDecision::Approve {
        activation,
        tool_scope,
        approve_delegate,
        approve_model,
        approve_source,
        approve_effort,
        approve_loop_trigger,
    } = &request.decision
    else {
        unreachable!("generated adoption always builds an approval request")
    };
    SkillAuthorityRecord::granted(
        id,
        &request.expected_manifest_sha256,
        &request.expected_package_generation_sha256,
        request.provenance,
        request.decision_source.clone(),
        *activation,
        SkillAuthorityGrant::granted_with_behavior(
            tool_scope.clone(),
            approve_delegate.clone(),
            approve_model.clone(),
            approve_source.clone(),
            *approve_effort,
            *approve_loop_trigger,
        )?,
    )
}

fn prepare_staged_generated_skill(
    home: &Path,
    proposal: &ProposedAction,
    claim: ProposalAdoptionClaim,
    manifest: &SkillManifest,
    source_dir: &Path,
) -> anyhow::Result<SkillAdoptionPreparation> {
    let skills_dir = home.join("skills");
    let preflight = installer::inspect_local_install_with_provenance(
        source_dir,
        &skills_dir,
        SkillProvenance::Generated,
    )
    .context("inspect exact generated Skill draft")?;
    if preflight.id != manifest.id {
        anyhow::bail!("generated Skill preflight changed the parsed manifest id");
    }
    let request = generated_authority_request(
        proposal,
        manifest,
        &preflight.source_manifest_sha256,
        &preflight.source_generation_sha256,
    )?;
    let expected_record = expected_generated_authority_record(&manifest.id, &request)?;

    if preflight.replacing_existing {
        return prepare_over_exact_existing(
            &skills_dir,
            proposal,
            claim,
            &preflight,
            &request,
            &expected_record,
        );
    }

    match claim {
        ProposalAdoptionClaim::NewlyApplying => {}
        ProposalAdoptionClaim::RecoveringApplying => anyhow::bail!(
            "generated Skill proposal {} is Applying but `{}` is absent; refusing a fresh install during crash recovery",
            proposal.id,
            manifest.id
        ),
        ProposalAdoptionClaim::AlreadyApplied => anyhow::bail!(
            "generated Skill proposal {} is already Applied but `{}` is absent; historical approval cannot reinstall it",
            proposal.id,
            manifest.id
        ),
    }

    let install = installer::install_from_local_with_provenance_expectation(
        source_dir,
        &skills_dir,
        false,
        &preflight.provenance_expectation(),
    )
    .context("install exact generated Skill draft pending and inactive")?;
    if install.authority.state != SkillAuthorityState::Pending
        || install.authority.provenance != SkillProvenance::Generated
        || install.source_manifest_sha256 != preflight.source_manifest_sha256
        || install.source_generation_sha256 != preflight.source_generation_sha256
    {
        anyhow::bail!("generated Skill installer returned an unexpected pending authority binding");
    }
    let pending_installed_generation_sha256 = install.installed_generation_sha256.clone();
    let authority = installer::prepare_installed_authority_mutation(
        &skills_dir,
        &manifest.id,
        &pending_installed_generation_sha256,
        &request,
    )
    .with_context(|| {
        format!(
            "generated Skill `{}` is installed pending and non-routable because exact authority activation failed; fix the cause and retry proposal {}",
            manifest.id, proposal.id
        )
    })?;
    Ok(SkillAdoptionPreparation::RequiresAuthority(
        PreparedSkillAuthorityAdoption {
            proposal_id: proposal.id.clone(),
            id: manifest.id.clone(),
            installed_at: install.installed_at,
            installed_new: true,
            install_manifest_sha256: preflight.source_manifest_sha256.clone(),
            install_package_generation_sha256: preflight.source_generation_sha256.clone(),
            pending_installed_generation_sha256,
            authority,
            warnings: install.warnings,
        },
    ))
}

fn prepare_over_exact_existing(
    skills_dir: &Path,
    proposal: &ProposedAction,
    claim: ProposalAdoptionClaim,
    preflight: &installer::InstallPreflight,
    request: &AuthorityDecisionRequest,
    expected_record: &SkillAuthorityRecord,
) -> anyhow::Result<SkillAdoptionPreparation> {
    let authenticated =
        installer::inspect_authenticated_current_authority(skills_dir, &preflight.id)
            .with_context(|| {
                format!(
                    "skill `{}` already exists but is not the exact healthy authenticated generated proposal generation",
                    preflight.id
                )
            })?;
    let current = authenticated.current;
    if current.manifest_sha256 != preflight.source_manifest_sha256
        || current.package_generation_sha256 != preflight.source_generation_sha256
    {
        anyhow::bail!(
            "skill `{}` already exists with a different package tree; KeepIfIdentical refuses replacement",
            preflight.id
        );
    }
    if current.authority.provenance != SkillProvenance::Generated {
        anyhow::bail!(
            "skill `{}` already exists with different provenance; refusing generated proposal binding",
            preflight.id
        );
    }
    let record = authenticated.record;
    if &record == expected_record {
        return adoption_report(
            &proposal.id,
            &preflight.id,
            skills_dir.join(&preflight.id),
            false,
            false,
            &preflight.source_manifest_sha256,
            &preflight.source_generation_sha256,
            current.installed_generation_sha256.clone(),
            current.installed_generation_sha256,
            record.receipt()?,
            Vec::new(),
        )
        .map(SkillAdoptionPreparation::Complete);
    }
    if claim == ProposalAdoptionClaim::AlreadyApplied {
        anyhow::bail!(
            "generated Skill proposal {} is already Applied, but `{}` is not its exact authenticated Active generation",
            proposal.id,
            preflight.id
        );
    }
    if record.state()? != SkillAuthorityState::Pending {
        anyhow::bail!(
            "skill `{}` already exists with a different authority or proactive proposal binding; refusing to overwrite it",
            preflight.id
        );
    }

    let authority = installer::prepare_installed_authority_mutation(
        skills_dir,
        &preflight.id,
        &current.installed_generation_sha256,
        request,
    )
    .with_context(|| {
        format!(
            "generated Skill `{}` remains pending and non-routable because exact authority activation failed; retry proposal {}",
            preflight.id, proposal.id
        )
    })?;
    Ok(SkillAdoptionPreparation::RequiresAuthority(
        PreparedSkillAuthorityAdoption {
            proposal_id: proposal.id.clone(),
            id: preflight.id.clone(),
            installed_at: skills_dir.join(&preflight.id),
            installed_new: false,
            install_manifest_sha256: preflight.source_manifest_sha256.clone(),
            install_package_generation_sha256: preflight.source_generation_sha256.clone(),
            pending_installed_generation_sha256: current.installed_generation_sha256,
            authority,
            warnings: Vec::new(),
        },
    ))
}

fn adoption_report(
    proposal_id: &str,
    id: &str,
    installed_at: PathBuf,
    installed_new: bool,
    authority_changed: bool,
    manifest_sha256: &str,
    package_generation_sha256: &str,
    pending_installed_generation_sha256: String,
    authority_installed_generation_sha256: String,
    authority: crate::skills::authority::SkillAuthorityReceipt,
    warnings: Vec<String>,
) -> anyhow::Result<SkillAdoptionReport> {
    if authority.state != SkillAuthorityState::Active
        || authority.provenance != SkillProvenance::Generated
        || authority.manifest_sha256 != manifest_sha256
        || authority.package_generation_sha256 != package_generation_sha256
    {
        anyhow::bail!(
            "generated Skill adoption did not produce the exact Active authority binding"
        );
    }
    Ok(SkillAdoptionReport {
        proposal_id: proposal_id.to_owned(),
        id: id.to_owned(),
        installed_at,
        installed_new,
        authority_changed,
        install_manifest_sha256: manifest_sha256.to_owned(),
        install_package_generation_sha256: package_generation_sha256.to_owned(),
        pending_installed_generation_sha256,
        authority_installed_generation_sha256,
        authority_record_sha256: authority.record_sha256,
        authority_state: authority.state,
        provenance: authority.provenance,
        warnings,
    })
}

struct PrivateGeneratedSkillStage {
    parent: BoundDirectory,
    name: OsString,
    stage: Option<BoundDirectory>,
}

impl PrivateGeneratedSkillStage {
    fn path(&self) -> &Path {
        &self
            .stage
            .as_ref()
            .expect("private stage exists until cleanup")
            .display_path
    }

    fn cleanup(&mut self) -> anyhow::Result<()> {
        let Some(stage) = self.stage.take() else {
            return Ok(());
        };
        let display_path = stage.display_path;
        drop(stage.dir);
        remove_real_directory_tree(&self.parent.dir, &self.name, &display_path)?;
        sync_parent_directory(&self.parent.dir, &self.parent.display_path)
    }
}

impl Drop for PrivateGeneratedSkillStage {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            tracing::warn!(
                error = %error,
                "generated Skill private staging cleanup remains pending"
            );
        }
    }
}

fn stage_generated_skill(
    home: &Path,
    draft_yaml: &[u8],
) -> anyhow::Result<PrivateGeneratedSkillStage> {
    let parent = open_bound_directory(home, true, "NEOTH home")?
        .context("created NEOTH home is unexpectedly absent")?;
    let mut created = None;
    for _ in 0..8 {
        let name = OsString::from(format!(
            "{GENERATED_SKILL_STAGE_PREFIX}{}",
            uuid::Uuid::new_v4().simple()
        ));
        let display_path = parent.display_path.join(&name);
        match create_private_stage_directory(&parent.dir, &name) {
            Ok(()) => {
                let dir = match open_real_child_dir(&parent.dir, &name, &display_path) {
                    Ok(dir) => dir,
                    Err(error) => {
                        let cleanup = remove_real_directory_tree(&parent.dir, &name, &display_path);
                        return match cleanup {
                            Ok(()) => Err(error.context(
                                "open private generated Skill staging directory",
                            )),
                            Err(cleanup_error) => Err(error.context(format!(
                                "open private generated Skill staging directory; cleanup failed: {cleanup_error:#}"
                            ))),
                        };
                    }
                };
                created = Some((name, BoundDirectory { dir, display_path }));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).context("create private generated Skill staging directory");
            }
        }
    }
    let (name, stage) = created.context("could not allocate private generated Skill staging")?;
    if let Err(error) = create_new_regular_file(
        &stage,
        OsStr::new("skill.yaml"),
        &stage.display_path.join("skill.yaml"),
        draft_yaml,
        ".neoth-generated-manifest-stage-",
    )
    .map_err(anyhow::Error::from)
    .and_then(|()| sync_parent_directory(&stage.dir, &stage.display_path))
    {
        let stage_path = stage.display_path.clone();
        drop(stage.dir);
        let cleanup = remove_real_directory_tree(&parent.dir, &name, &stage_path);
        return match cleanup {
            Ok(()) => Err(error.context("write exact generated Skill draft into private staging")),
            Err(cleanup_error) => Err(error.context(format!(
                "write exact generated Skill draft into private staging; cleanup failed: {cleanup_error:#}"
            ))),
        };
    }
    Ok(PrivateGeneratedSkillStage {
        parent,
        name,
        stage: Some(stage),
    })
}

fn create_private_stage_directory(parent: &cap_std::fs::Dir, name: &OsStr) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use cap_std::fs::{DirBuilder, DirBuilderExt as _};
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        parent.create_dir_with(name, &builder)
    }
    #[cfg(not(unix))]
    {
        parent.create_dir(name)
    }
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

fn proposal_mac_payload_bytes(proposal: &ProposedAction, key_id: &str) -> std::io::Result<Vec<u8>> {
    serde_json::to_vec(&ProposalMacPayload {
        schema_version: PROPOSAL_ENVELOPE_SCHEMA_VERSION,
        key_id,
        proposal,
    })
    .map_err(std::io::Error::other)
}

fn proposal_envelope(
    proposal: &ProposedAction,
    key: &SkillAuthorityKey,
) -> std::io::Result<StoredProposalEnvelope> {
    let key_id = key.key_id();
    let payload = proposal_mac_payload_bytes(proposal, &key_id)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key.expose())
        .expect("HMAC-SHA256 accepts a 32-byte authority key");
    mac.update(PROPOSAL_MAC_DOMAIN);
    mac.update(&payload);
    Ok(StoredProposalEnvelope {
        schema_version: PROPOSAL_ENVELOPE_SCHEMA_VERSION,
        key_id,
        proposal: proposal.clone(),
        mac: hex::encode(mac.finalize().into_bytes()),
    })
}

fn verify_proposal_envelope(
    envelope: &StoredProposalEnvelope,
    key: &SkillAuthorityKey,
    display_path: &Path,
) -> std::io::Result<()> {
    if envelope.schema_version != PROPOSAL_ENVELOPE_SCHEMA_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "unsupported proposal envelope schema {} at {}",
                envelope.schema_version,
                display_path.display()
            ),
        ));
    }
    if envelope.key_id != key.key_id() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "proposal {} was not authenticated by this NEOTH instance",
                display_path.display()
            ),
        ));
    }
    let expected = hex::decode(&envelope.mac).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "proposal {} has a malformed authentication tag: {error}",
                display_path.display()
            ),
        )
    })?;
    let payload = proposal_mac_payload_bytes(&envelope.proposal, &envelope.key_id)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key.expose())
        .expect("HMAC-SHA256 accepts a 32-byte authority key");
    mac.update(PROPOSAL_MAC_DOMAIN);
    mac.update(&payload);
    mac.verify_slice(&expected).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "proposal {} failed authentication; refusing tampered or forged authority input",
                display_path.display()
            ),
        )
    })
}

fn decode_proposal(
    bytes: Vec<u8>,
    display_path: &Path,
    key: &SkillAuthorityKey,
) -> std::io::Result<ProposedAction> {
    let body = String::from_utf8(bytes).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "staged proposal {} is not UTF-8: {error}",
                display_path.display()
            ),
        )
    })?;
    let envelope: StoredProposalEnvelope = serde_json::from_str(&body).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "parse authenticated staged proposal {}: {error}; unsigned legacy proposals are not trusted and must be re-staged and reviewed",
                display_path.display()
            ),
        )
    })?;
    let canonical = serde_json::to_vec_pretty(&envelope).map_err(std::io::Error::other)?;
    if body.as_bytes() != canonical {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "proposal envelope {} is not in canonical form",
                display_path.display()
            ),
        ));
    }
    verify_proposal_envelope(&envelope, key, display_path)?;
    Ok(envelope.proposal)
}

fn read_proposal_from_root(
    root: &BoundDirectory,
    id: &str,
    key: &SkillAuthorityKey,
) -> std::io::Result<Option<ProposedAction>> {
    let name = proposal_file_name(id)?;
    let display_path = root.display_path.join(&name);
    let bytes = match read_regular_file_bounded(&root.dir, &name, &display_path, MAX_PROPOSAL_BYTES)
    {
        Ok(bytes) => bytes,
        Err(error) if anyhow_is_not_found(&error) => return Ok(None),
        Err(error) => return Err(anyhow_to_io(error)),
    };
    let proposal = decode_proposal(bytes, &display_path, key)?;
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

fn proposal_body(proposal: &ProposedAction, key: &SkillAuthorityKey) -> std::io::Result<Vec<u8>> {
    validate_proposal_id(&proposal.id)?;
    let envelope = proposal_envelope(proposal, key)?;
    let body = serde_json::to_vec_pretty(&envelope).map_err(std::io::Error::other)?;
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

fn existing_proposal_key(home: &Path) -> std::io::Result<SkillAuthorityKey> {
    load_authority_key_at(home)
        .map_err(anyhow_to_io)?
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "proposal store exists without the instance authority key; refusing unsigned or foreign proposal state",
            )
        })
}

fn same_authenticated_proposal_payload(left: &ProposedAction, right: &ProposedAction) -> bool {
    left.id == right.id
        && left.kind == right.kind
        && left.title == right.title
        && left.rationale == right.rationale
        && left.draft_yaml == right.draft_yaml
        && left.generated_ts_unix == right.generated_ts_unix
        && left.operator_note == right.operator_note
}

fn claim_generated_skill_proposal(
    home: &Path,
    supplied: &ProposedAction,
) -> anyhow::Result<ClaimedSkillProposal> {
    validate_proposal_id(&supplied.id).map_err(anyhow::Error::from)?;
    let root = proposals_root(home, false)?
        .with_context(|| format!("proposal store is missing for {}", supplied.id))?;
    let key = existing_proposal_key(home)?;
    let _guard = lock_proposal_mutations(&root)?;
    let mut durable = read_proposal_from_root(&root, &supplied.id, &key)?
        .with_context(|| format!("durable proposal {} is missing", supplied.id))?;
    if !same_authenticated_proposal_payload(&durable, supplied) {
        anyhow::bail!(
            "proposal {} changed between approval and adoption; refusing stale or substituted authority input",
            supplied.id
        );
    }
    validate_skill_proposal_payload(&durable)?;

    let claim = match durable.status {
        ProposalStatus::Approved => {
            debug_assert!(valid_proposal_lifecycle_transition(
                ProposalStatus::Approved,
                ProposalStatus::Applying
            ));
            durable.status = ProposalStatus::Applying;
            let body = proposal_body(&durable, &key)?;
            replace_proposal_file(&root, &durable, &body)?;
            ProposalAdoptionClaim::NewlyApplying
        }
        ProposalStatus::Applying => ProposalAdoptionClaim::RecoveringApplying,
        ProposalStatus::Applied => ProposalAdoptionClaim::AlreadyApplied,
        status => anyhow::bail!(
            "skill proposal {} is not adoptable (status={})",
            durable.id,
            status.as_str()
        ),
    };
    Ok(ClaimedSkillProposal {
        proposal: durable,
        claim,
    })
}

fn reauthenticate_claimed_proposal(
    home: &Path,
    claimed: &ClaimedSkillProposal,
    expected_status: ProposalStatus,
) -> anyhow::Result<ProposedAction> {
    let root = proposals_root(home, false)?
        .with_context(|| format!("proposal store is missing for {}", claimed.proposal.id))?;
    let key = existing_proposal_key(home)?;
    let _guard = lock_proposal_mutations(&root)?;
    let durable = read_proposal_from_root(&root, &claimed.proposal.id, &key)?
        .with_context(|| format!("durable proposal {} is missing", claimed.proposal.id))?;
    if !same_authenticated_proposal_payload(&durable, &claimed.proposal) {
        anyhow::bail!(
            "proposal {} changed during adoption; refusing stale or substituted authority input",
            claimed.proposal.id
        );
    }
    if durable.status != expected_status {
        anyhow::bail!(
            "proposal {} lifecycle changed during adoption (expected {}, found {})",
            durable.id,
            expected_status.as_str(),
            durable.status.as_str()
        );
    }
    Ok(durable)
}

fn finish_claimed_proposal_lifecycle(
    home: &Path,
    claimed: &ClaimedSkillProposal,
) -> anyhow::Result<ProposalStatus> {
    let root = proposals_root(home, false)?
        .with_context(|| format!("proposal store is missing for {}", claimed.proposal.id))?;
    let key = existing_proposal_key(home)?;
    let _guard = lock_proposal_mutations(&root)?;
    let mut durable = read_proposal_from_root(&root, &claimed.proposal.id, &key)?
        .with_context(|| format!("durable proposal {} is missing", claimed.proposal.id))?;
    if !same_authenticated_proposal_payload(&durable, &claimed.proposal) {
        anyhow::bail!(
            "proposal {} changed after authority commit; refusing stale or substituted lifecycle state",
            claimed.proposal.id
        );
    }
    match durable.status {
        ProposalStatus::Applying => {
            debug_assert!(valid_proposal_lifecycle_transition(
                ProposalStatus::Applying,
                ProposalStatus::Applied
            ));
            durable.status = ProposalStatus::Applied;
            let body = proposal_body(&durable, &key)?;
            replace_proposal_file(&root, &durable, &body)?;
            Ok(ProposalStatus::Applied)
        }
        ProposalStatus::Applied => Ok(ProposalStatus::Applied),
        ProposalStatus::Revoked => Ok(ProposalStatus::Revoked),
        status => anyhow::bail!(
            "proposal {} has invalid post-adoption lifecycle status {}",
            durable.id,
            status.as_str()
        ),
    }
}

/// Result of revoking every generated proposal that can authorize one Skill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedSkillProposalRevocation {
    pub skill_id: String,
    pub revoked_proposal_ids: Vec<String>,
}

/// Revoke every authenticated generated proposal that can still authorize
/// `id`. The full store is authenticated and parsed before the first write;
/// callers must complete uninstall only after this function succeeds.
pub fn revoke_generated_skill_proposals_for_skill_id(
    home: &Path,
    id: &str,
    note: &str,
) -> std::io::Result<GeneratedSkillProposalRevocation> {
    crate::skills::creator::validate_skill_id(id).map_err(anyhow_to_io)?;
    let Some(root) = proposals_root(home, false)? else {
        return Ok(GeneratedSkillProposalRevocation {
            skill_id: id.to_owned(),
            revoked_proposal_ids: Vec::new(),
        });
    };
    let key = existing_proposal_key(home)?;
    let _guard = lock_proposal_mutations(&root)?;
    let proposals = read_all_proposals_from_root(&root, &key)?;

    let mut updates = Vec::new();
    for mut proposal in proposals {
        if proposal.kind != ProposalKind::Skill
            || !matches!(
                proposal.status,
                ProposalStatus::Approved | ProposalStatus::Applying | ProposalStatus::Applied
            )
        {
            continue;
        }
        let manifest: SkillManifest = serde_yaml::from_str(&proposal.draft_yaml).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "parse authenticated generated proposal {} while revoking skill `{id}`: {error}",
                    proposal.id
                ),
            )
        })?;
        if manifest.id != id {
            continue;
        }
        debug_assert!(valid_proposal_lifecycle_transition(
            proposal.status,
            ProposalStatus::Revoked
        ));
        proposal.status = ProposalStatus::Revoked;
        let body = proposal_body(&proposal, &key)?;
        updates.push((proposal, body));
    }

    let mut revoked_proposal_ids = Vec::with_capacity(updates.len());
    for (proposal, body) in updates {
        replace_proposal_file(&root, &proposal, &body)?;
        revoked_proposal_ids.push(proposal.id);
    }
    if !revoked_proposal_ids.is_empty() {
        tracing::info!(
            skill_id = id,
            proposal_count = revoked_proposal_ids.len(),
            revocation_note = %note,
            "revoked generated Skill proposal authority before uninstall"
        );
    }
    Ok(GeneratedSkillProposalRevocation {
        skill_id: id.to_owned(),
        revoked_proposal_ids,
    })
}

/// Persist a proposal to disk. Every mutation is serialized across daemon and
/// CLI processes, and both staging and commit stay relative to a stable
/// directory capability. An authenticated lifecycle state cannot be rolled
/// back or overwritten through this producer path.
pub fn save_proposal(home: &Path, proposal: &ProposedAction) -> std::io::Result<PathBuf> {
    validate_proposal_id(&proposal.id)?;
    let key = load_or_init_authority_key_at(home).map_err(anyhow_to_io)?;
    let root = proposals_root(home, true)?.expect("created proposal root must exist");
    let _guard = lock_proposal_mutations(&root)?;
    let final_path = proposal_path(home, &proposal.id);
    let existing = read_proposal_from_root(&root, &proposal.id, &key)?;
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
    if proposal.status != ProposalStatus::Pending || !proposal.operator_note.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "proposal {} cannot mint its own operator verdict; stage it pending, then use the explicit approval path",
                proposal.id
            ),
        ));
    }
    let body = proposal_body(proposal, &key)?;
    if existing.is_some() {
        replace_proposal_file(&root, proposal, &body)?;
    } else {
        create_proposal_file(&root, proposal, &body)?;
    }
    Ok(final_path)
}

/// Load and authenticate one proposal by id. Missing records are `None`; an
/// unsigned, foreign-key, malformed, or tampered record is an explicit error.
pub fn load_proposal(home: &Path, id: &str) -> std::io::Result<Option<ProposedAction>> {
    validate_proposal_id(id)?;
    let Some(root) = proposals_root(home, false)? else {
        return Ok(None);
    };
    let key = existing_proposal_key(home)?;
    read_proposal_from_root(&root, id, &key)
}

fn read_all_proposals_from_root(
    root: &BoundDirectory,
    key: &SkillAuthorityKey,
) -> std::io::Result<Vec<ProposedAction>> {
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
        let name = entry.file_name();
        let Some(name_text) = name.to_str() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "proposal store {} contains a non-UTF-8 entry name",
                    root.display_path.display()
                ),
            ));
        };
        let Some(id) = name_text.strip_suffix(".json") else {
            continue;
        };
        validate_proposal_id(id).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "invalid proposal filename {} under {}: {error}",
                    name_text,
                    root.display_path.display()
                ),
            )
        })?;
        let path = root.display_path.join(&name);
        let bytes = read_regular_file_bounded(&root.dir, &name, &path, MAX_PROPOSAL_BYTES)
            .map_err(anyhow_to_io)?;
        let proposal = decode_proposal(bytes, &path, key)?;
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
        out.push(proposal);
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
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
    let key = existing_proposal_key(home)?;
    let mut proposals = read_all_proposals_from_root(&root, &key)?;
    if let Some(status) = status_filter {
        proposals.retain(|proposal| proposal.status == status);
    }
    Ok(proposals)
}

/// Record the operator's `Approved` or `Rejected` verdict. Repeating accept on
/// an `Applying` or `Applied` proposal is an idempotent retry and preserves the
/// original operator note; machine lifecycle states cannot be set here.
pub fn set_proposal_status(
    home: &Path,
    id: &str,
    new_status: ProposalStatus,
    operator_note: &str,
) -> std::io::Result<ProposedAction> {
    validate_proposal_id(id)?;
    if !matches!(
        new_status,
        ProposalStatus::Approved | ProposalStatus::Rejected
    ) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "an operator verdict must be approved or rejected",
        ));
    }
    let root = proposals_root(home, false)?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("proposal {id} not found"),
        )
    })?;
    let key = existing_proposal_key(home)?;
    let _guard = lock_proposal_mutations(&root)?;
    let mut p = read_proposal_from_root(&root, id, &key)?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("proposal {id} not found"),
        )
    })?;
    if p.status == new_status {
        return Ok(p);
    }
    if new_status == ProposalStatus::Approved
        && matches!(p.status, ProposalStatus::Applying | ProposalStatus::Applied)
    {
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
    let body = proposal_body(&p, &key)?;
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
    let key = load_or_init_authority_key_at(home).map_err(anyhow_to_io)?;
    let root = proposals_root(home, true)?.expect("created proposal root must exist");
    let _guard = lock_proposal_mutations(&root)?;
    if let Some(existing) = read_proposal_from_root(&root, &proposal.id, &key)? {
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
    let body = proposal_body(&proposal, &key)?;
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
    use crate::skills::authority::AUTHORITY_SIDECAR_FILE;

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

    fn generated_skill_proposal(
        skill_id: &str,
        description: &str,
        generated_ts_unix: i64,
        status: ProposalStatus,
    ) -> ProposedAction {
        let (mut manifest, _) =
            crate::skills::creator::build_manifest(&crate::skills::creator::CreateParams {
                id: skill_id.to_string(),
                description: description.to_string(),
                keywords: vec!["generated".to_string()],
                system_prompt: "Follow the generated workflow.".to_string(),
            })
            .unwrap();
        manifest.tool_allowlist = vec!["web::search".to_string(), "memory::recall".to_string()];
        manifest.delegate_to = Some("researcher".to_string());
        manifest.model = Some("provider/model-exact".to_string());
        manifest.source = Some("git+https://example.invalid/generated.git".to_string());
        manifest.effort = Some(crate::providers::effort_override::EffortBudget::High);
        manifest.loop_trigger = true;
        let draft_yaml = serde_yaml::to_string(&manifest).unwrap();
        let title = format!("Skill: {skill_id}");
        ProposedAction {
            id: make_proposal_id(ProposalKind::Skill, &title, &draft_yaml, generated_ts_unix),
            kind: ProposalKind::Skill,
            title,
            rationale: "Generated from an operator-reviewed workflow.".to_string(),
            draft_yaml,
            generated_ts_unix,
            status,
            operator_note: String::new(),
        }
    }

    fn persist_with_verdict(home: &Path, proposal: &ProposedAction) -> ProposedAction {
        let mut pending = proposal.clone();
        pending.status = ProposalStatus::Pending;
        pending.operator_note.clear();
        save_proposal(home, &pending).unwrap();
        match proposal.status {
            ProposalStatus::Pending => pending,
            status => {
                set_proposal_status(home, &pending.id, status, &proposal.operator_note).unwrap()
            }
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
        assert_eq!(ProposalStatus::Applying.as_str(), "applying");
        assert_eq!(ProposalStatus::Applied.as_str(), "applied");
        assert_eq!(ProposalStatus::Revoked.as_str(), "revoked");
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
        let loaded = load_proposal(home.path(), &p.id)
            .expect("authenticate")
            .expect("load");
        assert_eq!(loaded, p);
    }

    #[test]
    fn unsigned_approved_proposal_is_explicitly_rejected() {
        let home = tempfile::tempdir().unwrap();
        load_or_init_authority_key_at(home.path()).unwrap();
        let mut proposal = sample(ProposalKind::Skill, "forged approval", 101);
        proposal.status = ProposalStatus::Approved;
        std::fs::create_dir_all(proposals_dir(home.path())).unwrap();
        std::fs::write(
            proposal_path(home.path(), &proposal.id),
            serde_json::to_vec_pretty(&proposal).unwrap(),
        )
        .unwrap();

        let error = load_proposal(home.path(), &proposal.id).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            error
                .to_string()
                .contains("unsigned legacy proposals are not trusted")
        );
    }

    #[test]
    fn authenticated_proposal_field_tampering_is_rejected() {
        let home = tempfile::tempdir().unwrap();
        let proposal = sample(ProposalKind::Skill, "signed", 102);
        let path = save_proposal(home.path(), &proposal).unwrap();
        let body = std::fs::read(&path).unwrap();
        let mut envelope: StoredProposalEnvelope = serde_json::from_slice(&body).unwrap();
        envelope.proposal.status = ProposalStatus::Approved;
        std::fs::write(&path, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();

        let error = load_proposal(home.path(), &proposal.id).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("failed authentication"));
    }

    #[test]
    fn direct_save_cannot_mint_an_approved_proposal() {
        let home = tempfile::tempdir().unwrap();
        let mut proposal = sample(ProposalKind::Skill, "self approval", 103);
        proposal.status = ProposalStatus::Approved;

        let error = save_proposal(home.path(), &proposal).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(!proposal_path(home.path(), &proposal.id).exists());
    }

    #[test]
    fn load_missing_proposal_returns_none() {
        let home = tempfile::tempdir().unwrap();
        assert!(load_proposal(home.path(), "nonexistent").unwrap().is_none());
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
        assert!(load_proposal(home.path(), &proposal.id).is_err());
    }

    #[test]
    fn save_overwrites_existing_atomically() {
        let home = tempfile::tempdir().unwrap();
        let mut p = sample(ProposalKind::CronJob, "title", 100);
        save_proposal(home.path(), &p).unwrap();
        p.title = "new title".to_string();
        save_proposal(home.path(), &p).unwrap();
        let loaded = load_proposal(home.path(), &p.id).unwrap().unwrap();
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

    #[tokio::test]
    async fn approved_skill_adoption_returns_the_complete_create_report() {
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
        proposal.id = make_proposal_id(
            proposal.kind,
            &proposal.title,
            &proposal.draft_yaml,
            proposal.generated_ts_unix,
        );
        persist_with_verdict(home.path(), &proposal);

        let report = adopt_approved_skill(home.path(), &proposal, None)
            .await
            .unwrap();

        assert_eq!(report.id, "typed_report");
        assert_eq!(
            report.installed_at,
            home.path().join("skills").join("typed_report")
        );
        assert!(report.installed_new);
        assert!(report.authority_changed);
        assert_eq!(report.proposal_id, proposal.id);
        assert_eq!(report.authority_state, SkillAuthorityState::Active);
        assert_eq!(report.provenance, SkillProvenance::Generated);
        assert!(report.warnings.is_empty());
        assert_eq!(
            load_proposal(home.path(), &proposal.id)
                .unwrap()
                .unwrap()
                .status,
            ProposalStatus::Applied
        );
    }

    #[tokio::test]
    async fn generated_adoption_is_active_and_exact_for_a_fresh_loader() {
        use crate::skills::authority::{
            AuthorityDecisionSource, EffectiveToolScope, QualifiedTool, SkillAuthorityGrant,
        };

        let home = tempfile::tempdir().unwrap();
        let proposal = generated_skill_proposal(
            "generated_exact",
            "Exact generated authority",
            1_700_000_100,
            ProposalStatus::Approved,
        );
        persist_with_verdict(home.path(), &proposal);
        let report = adopt_approved_skill(home.path(), &proposal, None)
            .await
            .unwrap();

        let loaded = crate::skills::loader::load_all(&home.path().join("skills"))
            .await
            .unwrap();
        let skill = loaded
            .iter()
            .find(|skill| skill.id() == "generated_exact")
            .unwrap();
        assert_eq!(skill.provenance(), SkillProvenance::Generated);
        assert_eq!(skill.authority_state(), SkillAuthorityState::Active);
        assert!(skill.is_routable());
        assert_eq!(skill.delegate_to(), Some("researcher"));
        assert_eq!(skill.model(), Some("provider/model-exact"));
        assert_eq!(
            skill.effort(),
            Some(crate::providers::effort_override::EffortBudget::High)
        );
        assert!(skill.loop_trigger());
        assert_eq!(
            skill.source(),
            Some("git+https://example.invalid/generated.git")
        );
        let EffectiveToolScope::AllowOnly(tools) = skill.effective_tool_scope() else {
            panic!("generated exact claims must become a qualified allow-set")
        };
        assert_eq!(
            tools,
            vec![
                QualifiedTool::parse("memory::recall").unwrap(),
                QualifiedTool::parse("web::search").unwrap(),
            ]
        );

        let authenticated = installer::inspect_authenticated_current_authority(
            &home.path().join("skills"),
            "generated_exact",
        )
        .unwrap();
        let current = authenticated.current;
        let record = authenticated.record;
        assert_eq!(
            record.decision_source,
            Some(AuthorityDecisionSource::Proactive {
                proposal_id: proposal.id.clone()
            })
        );
        let SkillAuthorityGrant::Granted {
            tool_scope,
            delegate_to,
            model,
            source,
            effort,
            loop_trigger,
        } = record.grant
        else {
            panic!("generated proposal must have a granted authority record")
        };
        assert_eq!(tool_scope.exact_tools().unwrap(), tools);
        assert_eq!(delegate_to.as_deref(), Some("researcher"));
        assert_eq!(model.as_deref(), Some("provider/model-exact"));
        assert_eq!(
            source.as_deref(),
            Some("git+https://example.invalid/generated.git")
        );
        assert_eq!(
            effort,
            Some(crate::providers::effort_override::EffortBudget::High)
        );
        assert!(loop_trigger);
        assert_eq!(
            report.authority_record_sha256,
            current.authority.record_sha256
        );
    }

    #[tokio::test]
    async fn generated_adoption_rejects_stale_or_tampered_proposal_payload() {
        let home = tempfile::tempdir().unwrap();
        let mut proposal = generated_skill_proposal(
            "generated_tampered",
            "Original exact draft",
            1_700_000_101,
            ProposalStatus::Approved,
        );
        persist_with_verdict(home.path(), &proposal);
        proposal.draft_yaml.push_str("# changed after staging\n");

        let error = adopt_approved_skill(home.path(), &proposal, None)
            .await
            .unwrap_err();

        assert!(format!("{error:#}").contains("changed between approval and adoption"));
        assert!(!home.path().join("skills").exists());
    }

    #[tokio::test]
    async fn generated_adoption_rejects_different_existing_tree_and_proposal_binding() {
        let home = tempfile::tempdir().unwrap();
        let first = generated_skill_proposal(
            "generated_collision",
            "First exact tree",
            1_700_000_102,
            ProposalStatus::Approved,
        );
        persist_with_verdict(home.path(), &first);
        let first_report = adopt_approved_skill(home.path(), &first, None)
            .await
            .unwrap();

        let different_tree = generated_skill_proposal(
            "generated_collision",
            "Different exact tree",
            1_700_000_103,
            ProposalStatus::Approved,
        );
        persist_with_verdict(home.path(), &different_tree);
        let tree_error = adopt_approved_skill(home.path(), &different_tree, None)
            .await
            .unwrap_err();
        assert!(format!("{tree_error:#}").contains("different package tree"));

        let mut different_binding = first.clone();
        different_binding.generated_ts_unix += 1;
        different_binding.id = make_proposal_id(
            different_binding.kind,
            &different_binding.title,
            &different_binding.draft_yaml,
            different_binding.generated_ts_unix,
        );
        persist_with_verdict(home.path(), &different_binding);
        let binding_error = adopt_approved_skill(home.path(), &different_binding, None)
            .await
            .unwrap_err();
        assert!(format!("{binding_error:#}").contains("different authority or proactive proposal"));

        let current = installer::inspect_installed_authority(
            &home.path().join("skills"),
            "generated_collision",
        )
        .unwrap();
        assert_eq!(
            current.installed_generation_sha256,
            first_report.authority_installed_generation_sha256
        );
    }

    #[tokio::test]
    async fn generated_adoption_requires_approved_status() {
        for status in [ProposalStatus::Pending, ProposalStatus::Rejected] {
            let home = tempfile::tempdir().unwrap();
            let proposal = generated_skill_proposal(
                "generated_not_approved",
                "No authority without approval",
                1_700_000_104,
                status,
            );
            persist_with_verdict(home.path(), &proposal);

            let error = adopt_approved_skill(home.path(), &proposal, None)
                .await
                .unwrap_err();

            assert!(format!("{error:#}").contains("not adoptable"));
            assert!(!home.path().join("skills").exists());
        }
    }

    #[tokio::test]
    async fn generated_adoption_is_idempotent_for_identical_active_proposal() {
        let home = tempfile::tempdir().unwrap();
        let proposal = generated_skill_proposal(
            "generated_idempotent",
            "Identical retry",
            1_700_000_105,
            ProposalStatus::Approved,
        );
        persist_with_verdict(home.path(), &proposal);
        let first = adopt_approved_skill(home.path(), &proposal, None)
            .await
            .unwrap();
        let second = adopt_approved_skill(home.path(), &proposal, None)
            .await
            .unwrap();

        assert_eq!(
            load_proposal(home.path(), &proposal.id)
                .unwrap()
                .unwrap()
                .status,
            ProposalStatus::Applied
        );

        assert!(first.installed_new);
        assert!(first.authority_changed);
        assert!(!second.installed_new);
        assert!(!second.authority_changed);
        assert_eq!(
            first.authority_installed_generation_sha256,
            second.authority_installed_generation_sha256
        );
        assert_eq!(
            first.authority_record_sha256,
            second.authority_record_sha256
        );
        let mut names = std::fs::read_dir(home.path().join("skills").join("generated_idempotent"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(
            names,
            vec![AUTHORITY_SIDECAR_FILE.to_string(), "skill.yaml".to_string()]
        );
        assert!(!std::fs::read_dir(home.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(GENERATED_SKILL_STAGE_PREFIX)
        }));
    }

    #[tokio::test]
    async fn generated_retry_requires_the_authenticated_sidecar_anchor_pair() {
        for tamper_sidecar in [false, true] {
            let home = tempfile::tempdir().unwrap();
            let id = if tamper_sidecar {
                "generated_retry_tampered_sidecar"
            } else {
                "generated_retry_missing_anchor"
            };
            let proposal = generated_skill_proposal(
                id,
                "Authenticated retry",
                1_700_000_107,
                ProposalStatus::Approved,
            );
            persist_with_verdict(home.path(), &proposal);
            adopt_approved_skill(home.path(), &proposal, None)
                .await
                .unwrap();

            if tamper_sidecar {
                std::fs::write(
                    home.path()
                        .join("skills")
                        .join(id)
                        .join(AUTHORITY_SIDECAR_FILE),
                    b"{}\n",
                )
                .unwrap();
            } else {
                std::fs::remove_file(installer::authority_anchor_path(home.path(), id).unwrap())
                    .unwrap();
            }

            let error = adopt_approved_skill(home.path(), &proposal, None)
                .await
                .unwrap_err();

            assert!(
                format!("{error:#}")
                    .contains("not the exact healthy authenticated generated proposal generation")
            );
        }
    }

    #[tokio::test]
    async fn exact_pending_generated_install_is_safe_and_retryable() {
        let home = tempfile::tempdir().unwrap();
        let proposal = generated_skill_proposal(
            "generated_pending_retry",
            "Pending retry",
            1_700_000_106,
            ProposalStatus::Approved,
        );
        persist_with_verdict(home.path(), &proposal);
        let mut stage = stage_generated_skill(home.path(), proposal.draft_yaml.as_bytes()).unwrap();
        let skills_dir = home.path().join("skills");
        let preflight = installer::inspect_local_install_with_provenance(
            stage.path(),
            &skills_dir,
            SkillProvenance::Generated,
        )
        .unwrap();
        installer::install_from_local_with_provenance_expectation(
            stage.path(),
            &skills_dir,
            false,
            &preflight.provenance_expectation(),
        )
        .unwrap();
        stage.cleanup().unwrap();

        let pending = crate::skills::loader::load_all(&skills_dir).await.unwrap();
        let pending = pending
            .iter()
            .find(|skill| skill.id() == "generated_pending_retry")
            .unwrap();
        assert_eq!(pending.authority_state(), SkillAuthorityState::Pending);
        assert_eq!(pending.provenance(), SkillProvenance::Generated);
        assert!(!pending.is_routable());

        let report = adopt_approved_skill(home.path(), &proposal, None)
            .await
            .unwrap();
        assert!(!report.installed_new);
        assert!(report.authority_changed);
        assert_eq!(report.authority_state, SkillAuthorityState::Active);
    }

    #[test]
    fn generic_generated_activation_requires_the_exact_authenticated_proposal() {
        let home = tempfile::tempdir().unwrap();
        let proposal = generated_skill_proposal(
            "generated_cli_binding",
            "CLI binding",
            1_700_000_108,
            ProposalStatus::Approved,
        );
        persist_with_verdict(home.path(), &proposal);
        let claimed = claim_generated_skill_proposal(home.path(), &proposal).unwrap();
        assert_eq!(claimed.claim, ProposalAdoptionClaim::NewlyApplying);
        let manifest: SkillManifest = serde_yaml::from_str(&proposal.draft_yaml).unwrap();
        let mut stage = stage_generated_skill(home.path(), proposal.draft_yaml.as_bytes()).unwrap();
        let skills_dir = home.path().join("skills");
        let preflight = installer::inspect_local_install_with_provenance(
            stage.path(),
            &skills_dir,
            SkillProvenance::Generated,
        )
        .unwrap();
        installer::install_from_local_with_provenance_expectation(
            stage.path(),
            &skills_dir,
            false,
            &preflight.provenance_expectation(),
        )
        .unwrap();
        stage.cleanup().unwrap();
        let current = installer::inspect_installed_authority(&skills_dir, &manifest.id).unwrap();
        let request = generated_authority_request(
            &proposal,
            &manifest,
            &current.manifest_sha256,
            &current.package_generation_sha256,
        )
        .unwrap();

        verify_generated_authority_approval(home.path(), &current, &request).unwrap();

        let mut forged_id = request.clone();
        forged_id.decision_source = AuthorityDecisionSource::Proactive {
            proposal_id: "any-nonempty-id".to_string(),
        };
        let error =
            verify_generated_authority_approval(home.path(), &current, &forged_id).unwrap_err();
        assert!(format!("{error:#}").contains("is missing"));

        let mut extra_tool = request;
        let AuthorityDecision::Approve { tool_scope, .. } = &mut extra_tool.decision else {
            unreachable!()
        };
        *tool_scope = InstalledToolScope::allow_only(["shell::exec"]).unwrap();
        let error =
            verify_generated_authority_approval(home.path(), &current, &extra_tool).unwrap_err();
        assert!(format!("{error:#}").contains("outside approved proposal"));
    }

    #[tokio::test]
    async fn applying_with_absent_target_fails_closed() {
        let home = tempfile::tempdir().unwrap();
        let proposal = generated_skill_proposal(
            "generated_applying_absent",
            "Applying without installed generation",
            1_700_000_109,
            ProposalStatus::Approved,
        );
        persist_with_verdict(home.path(), &proposal);
        let claimed = claim_generated_skill_proposal(home.path(), &proposal).unwrap();

        let error = adopt_approved_skill(home.path(), &claimed.proposal, None)
            .await
            .unwrap_err();

        assert!(format!("{error:#}").contains("refusing a fresh install during crash recovery"));
        assert_eq!(
            load_proposal(home.path(), &proposal.id)
                .unwrap()
                .unwrap()
                .status,
            ProposalStatus::Applying
        );
        assert!(!home.path().join("skills").exists());
    }

    #[tokio::test]
    async fn applying_with_exact_active_generation_finalizes_applied() {
        let home = tempfile::tempdir().unwrap();
        let proposal = generated_skill_proposal(
            "generated_applying_active",
            "Recover active generation",
            1_700_000_110,
            ProposalStatus::Approved,
        );
        persist_with_verdict(home.path(), &proposal);
        let claimed = claim_generated_skill_proposal(home.path(), &proposal).unwrap();
        let manifest: SkillManifest = serde_yaml::from_str(&claimed.proposal.draft_yaml).unwrap();
        let mut stage =
            stage_generated_skill(home.path(), claimed.proposal.draft_yaml.as_bytes()).unwrap();
        let skills_dir = home.path().join("skills");
        let preflight = installer::inspect_local_install_with_provenance(
            stage.path(),
            &skills_dir,
            SkillProvenance::Generated,
        )
        .unwrap();
        installer::install_from_local_with_provenance_expectation(
            stage.path(),
            &skills_dir,
            false,
            &preflight.provenance_expectation(),
        )
        .unwrap();
        stage.cleanup().unwrap();
        let pending = installer::inspect_installed_authority(&skills_dir, &manifest.id).unwrap();
        let request = generated_authority_request(
            &claimed.proposal,
            &manifest,
            &pending.manifest_sha256,
            &pending.package_generation_sha256,
        )
        .unwrap();
        verify_generated_authority_approval(home.path(), &pending, &request).unwrap();
        installer::mutate_installed_authority_with_expectation(
            &skills_dir,
            &manifest.id,
            &pending.installed_generation_sha256,
            &request,
        )
        .unwrap();

        let report = adopt_approved_skill(home.path(), &claimed.proposal, None)
            .await
            .unwrap();

        assert!(!report.installed_new);
        assert!(!report.authority_changed);
        assert_eq!(
            load_proposal(home.path(), &proposal.id)
                .unwrap()
                .unwrap()
                .status,
            ProposalStatus::Applied
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn revocation_after_preparation_prevents_authority_commit() {
        let home = tempfile::tempdir().unwrap();
        let proposal = generated_skill_proposal(
            "generated_revoked_before_commit",
            "Concurrent revocation",
            1_700_000_111,
            ProposalStatus::Approved,
        );
        persist_with_verdict(home.path(), &proposal);
        let hook_home = home.path().to_path_buf();
        set_before_generated_authority_commit_test_hook(move || {
            revoke_generated_skill_proposals_for_skill_id(
                &hook_home,
                "generated_revoked_before_commit",
                "concurrent uninstall",
            )
            .unwrap();
        });

        let error = adopt_approved_skill(home.path(), &proposal, None)
            .await
            .unwrap_err();

        assert!(format!("{error:#}").contains("lifecycle changed during adoption"));
        assert_eq!(
            load_proposal(home.path(), &proposal.id)
                .unwrap()
                .unwrap()
                .status,
            ProposalStatus::Revoked
        );
        let installed = installer::inspect_installed_authority(
            &home.path().join("skills"),
            "generated_revoked_before_commit",
        )
        .unwrap();
        assert_eq!(installed.authority.state, SkillAuthorityState::Pending);
        let loaded = crate::skills::loader::load_all(&home.path().join("skills"))
            .await
            .unwrap();
        assert!(!loaded.iter().any(|skill| skill.is_routable()));
    }

    #[tokio::test]
    async fn generated_adoption_rejects_unqualified_tool_claims_before_install() {
        let home = tempfile::tempdir().unwrap();
        let mut proposal = generated_skill_proposal(
            "generated_bad_tool",
            "Unqualified claim",
            1_700_000_107,
            ProposalStatus::Approved,
        );
        let mut manifest: SkillManifest = serde_yaml::from_str(&proposal.draft_yaml).unwrap();
        manifest.tool_allowlist = vec!["search".to_string()];
        proposal.draft_yaml = serde_yaml::to_string(&manifest).unwrap();
        proposal.id = make_proposal_id(
            proposal.kind,
            &proposal.title,
            &proposal.draft_yaml,
            proposal.generated_ts_unix,
        );
        persist_with_verdict(home.path(), &proposal);

        let error = adopt_approved_skill(home.path(), &proposal, None)
            .await
            .unwrap_err();

        assert!(format!("{error:#}").contains("qualified server::tool"));
        assert!(!home.path().join("skills").exists());
    }

    #[test]
    fn proposal_reads_reject_oversized_files_before_allocation() {
        let home = tempfile::tempdir().unwrap();
        load_or_init_authority_key_at(home.path()).unwrap();
        let path = proposals_dir(home.path()).join("oversized.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_PROPOSAL_BYTES as u64 + 1).unwrap();

        assert!(load_proposal(home.path(), "oversized").is_err());
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
        persist_with_verdict(home.path(), &b);
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
    fn list_proposals_propagates_json_corruption() {
        let home = tempfile::tempdir().unwrap();
        load_or_init_authority_key_at(home.path()).unwrap();
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
        let original = save_proposal(home.path(), &proposal).unwrap();
        std::fs::rename(
            original,
            proposals_dir(home.path()).join("different-id.json"),
        )
        .unwrap();

        let error = list_proposals(home.path(), None).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("does not match record id"));
    }

    #[test]
    fn list_proposals_propagates_entry_read_failure() {
        let home = tempfile::tempdir().unwrap();
        load_or_init_authority_key_at(home.path()).unwrap();
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
        let again = load_proposal(home.path(), &p.id).unwrap().unwrap();
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
        assert_eq!(
            load_proposal(home.path(), &proposal.id).unwrap().unwrap(),
            approved
        );
    }

    #[test]
    fn proposal_lifecycle_transition_matrix_is_monotonic() {
        let statuses = [
            ProposalStatus::Pending,
            ProposalStatus::Approved,
            ProposalStatus::Rejected,
            ProposalStatus::Applying,
            ProposalStatus::Applied,
            ProposalStatus::Revoked,
        ];
        for from in statuses {
            for to in statuses {
                let expected = from == to
                    || matches!(
                        (from, to),
                        (ProposalStatus::Pending, ProposalStatus::Approved)
                            | (ProposalStatus::Pending, ProposalStatus::Rejected)
                            | (ProposalStatus::Approved, ProposalStatus::Applying)
                            | (ProposalStatus::Approved, ProposalStatus::Revoked)
                            | (ProposalStatus::Applying, ProposalStatus::Applied)
                            | (ProposalStatus::Applying, ProposalStatus::Revoked)
                            | (ProposalStatus::Applied, ProposalStatus::Revoked)
                    );
                assert_eq!(
                    valid_proposal_lifecycle_transition(from, to),
                    expected,
                    "unexpected transition {} -> {}",
                    from.as_str(),
                    to.as_str()
                );
            }
        }
    }

    #[test]
    fn accept_retry_preserves_operator_verdict_through_machine_states() {
        let home = tempfile::tempdir().unwrap();
        let mut proposal = generated_skill_proposal(
            "verdict_evidence",
            "Immutable operator verdict",
            1_700_000_112,
            ProposalStatus::Approved,
        );
        proposal.operator_note = "original verdict".to_string();
        let approved = persist_with_verdict(home.path(), &proposal);
        let claimed = claim_generated_skill_proposal(home.path(), &approved).unwrap();

        let applying_retry = set_proposal_status(
            home.path(),
            &proposal.id,
            ProposalStatus::Approved,
            "must not overwrite",
        )
        .unwrap();
        assert_eq!(applying_retry.status, ProposalStatus::Applying);
        assert_eq!(applying_retry.operator_note, "original verdict");

        finish_claimed_proposal_lifecycle(home.path(), &claimed).unwrap();
        let applied_retry = set_proposal_status(
            home.path(),
            &proposal.id,
            ProposalStatus::Approved,
            "still must not overwrite",
        )
        .unwrap();
        assert_eq!(applied_retry.status, ProposalStatus::Applied);
        assert_eq!(applied_retry.operator_note, "original verdict");
    }

    #[test]
    fn revocation_api_revokes_every_matching_authority_state() {
        let home = tempfile::tempdir().unwrap();
        let mut proposals = Vec::new();
        for (offset, final_status) in [
            (0, ProposalStatus::Approved),
            (1, ProposalStatus::Applying),
            (2, ProposalStatus::Applied),
        ] {
            let mut proposal = generated_skill_proposal(
                "revocation_target",
                "Revoke every proposal",
                1_700_000_120 + offset,
                ProposalStatus::Approved,
            );
            proposal.operator_note = format!("verdict {offset}");
            let approved = persist_with_verdict(home.path(), &proposal);
            let durable = match final_status {
                ProposalStatus::Approved => approved,
                ProposalStatus::Applying => {
                    claim_generated_skill_proposal(home.path(), &approved)
                        .unwrap()
                        .proposal
                }
                ProposalStatus::Applied => {
                    let claimed = claim_generated_skill_proposal(home.path(), &approved).unwrap();
                    finish_claimed_proposal_lifecycle(home.path(), &claimed).unwrap();
                    load_proposal(home.path(), &proposal.id).unwrap().unwrap()
                }
                _ => unreachable!(),
            };
            proposals.push(durable);
        }

        let report = revoke_generated_skill_proposals_for_skill_id(
            home.path(),
            "revocation_target",
            "uninstall requested",
        )
        .unwrap();

        let expected_ids = proposals
            .iter()
            .map(|proposal| proposal.id.clone())
            .collect::<Vec<_>>();
        assert_eq!(report.revoked_proposal_ids, expected_ids);
        for proposal in proposals {
            let revoked = load_proposal(home.path(), &proposal.id).unwrap().unwrap();
            assert_eq!(revoked.status, ProposalStatus::Revoked);
            assert_eq!(revoked.operator_note, proposal.operator_note);
        }
    }

    #[test]
    fn revocation_api_authenticates_the_whole_store_before_mutating() {
        let home = tempfile::tempdir().unwrap();
        let target = generated_skill_proposal(
            "revocation_fail_closed",
            "Target remains approved",
            1_700_000_130,
            ProposalStatus::Approved,
        );
        persist_with_verdict(home.path(), &target);
        let unrelated = generated_skill_proposal(
            "unrelated_tampered",
            "Tampered unrelated record",
            1_700_000_131,
            ProposalStatus::Approved,
        );
        persist_with_verdict(home.path(), &unrelated);
        std::fs::write(proposal_path(home.path(), &unrelated.id), b"{}\n").unwrap();

        let error = revoke_generated_skill_proposals_for_skill_id(
            home.path(),
            "revocation_fail_closed",
            "must fail",
        )
        .unwrap_err();

        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::InvalidData | std::io::ErrorKind::PermissionDenied
        ));
        assert_eq!(
            load_proposal(home.path(), &target.id)
                .unwrap()
                .unwrap()
                .status,
            ProposalStatus::Approved
        );
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
        assert_eq!(
            load_proposal(home.path(), &proposal.id).unwrap().unwrap(),
            approved
        );
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
        persist_with_verdict(home.path(), &approved);
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
        assert!(load_proposal(home.path(), &id).unwrap().is_some());
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
        assert_eq!(
            load_proposal(home.path(), &approved.id).unwrap().unwrap(),
            approved
        );
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
        assert_eq!(
            load_proposal(home.path(), &proposal.id).unwrap().unwrap(),
            proposal
        );
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
