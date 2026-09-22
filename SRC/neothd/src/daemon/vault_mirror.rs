//! W184 — private, opt-in Git mirror for a WAL-inclusive backup archive.
//!
//! This module deliberately owns a repository below the NEOTH home.  It never
//! opens an operator supplied worktree and it persists `PushIntent` before a
//! push, so an interrupted push is reconciled rather than replayed.

use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{config::VaultMirrorConfig, daemon::backup, skills::store};
use cap_std::fs::Dir;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::io::{Seek as _, Write as _};

pub const VAULT_MIRROR_STATE_SCHEMA_V1: u32 = 1;
const MAX_STATE_BYTES: u64 = 512 * 1024;
const MAX_GIT_OUTPUT_BYTES: usize = 16 * 1024;
const GIT_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_VERIFIED_RECEIPTS: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MirrorBlockReason {
    Disabled,
    NightlyPushNotAllowed,
    ManualPushNotAllowed,
    InvalidConfiguration,
    BusyOrStaleLock,
    CorruptState,
    RemoteAdvanced,
    CredentialUnavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MirrorIndeterminateReason {
    PushOutcomeUnknown,
    RemoteOutcomeUnknown,
    StatePersistenceUnknown,
    Timeout,
    OutputLimitExceeded,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "reason", rename_all = "snake_case")]
pub enum MirrorPhase {
    Disabled,
    Prepared,
    PushIntent,
    Verified,
    Blocked(MirrorBlockReason),
    Indeterminate(MirrorIndeterminateReason),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MirrorConfigStatus {
    Disabled,
    Ready,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MirrorRepairAdvice {
    NoAction,
    RunVerification,
    FixConfig,
    RestoreCredential,
    ResolveRemoteAdvance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionReceipt {
    pub enabled: bool,
    pub retained_verified_runs: u32,
    pub removed_runs: Vec<String>,
    pub phase: Option<MirrorPhase>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMirrorReceipt {
    pub schema_version: u32,
    pub run_id: String,
    pub config_fingerprint_sha256: String,
    pub archive_sha256: String,
    pub archive_bytes: u64,
    pub wal_included: bool,
    pub credentials_included: bool,
    pub branch: String,
    pub remote_redaction: String,
    pub commit_oid: Option<String>,
    pub remote_head_oid: Option<String>,
    pub phase: MirrorPhase,
    pub created_at_unix: i64,
    pub verified_at_unix: Option<i64>,
    pub retention: RetentionReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMirrorState {
    pub schema_version: u32,
    pub active: Option<VaultMirrorReceipt>,
    pub verified_runs: Vec<VaultMirrorReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMirrorStatus {
    pub config: MirrorConfigStatus,
    pub receipt: Option<VaultMirrorReceipt>,
    pub repair: MirrorRepairAdvice,
}

impl VaultMirrorStatus {
    fn disabled() -> Self {
        Self {
            config: MirrorConfigStatus::Disabled,
            receipt: None,
            repair: MirrorRepairAdvice::NoAction,
        }
    }
    fn blocked(reason: MirrorBlockReason) -> Self {
        Self {
            config: MirrorConfigStatus::Blocked,
            receipt: Some(blocked_receipt(reason.clone())),
            repair: match reason {
                MirrorBlockReason::CredentialUnavailable => MirrorRepairAdvice::RestoreCredential,
                MirrorBlockReason::RemoteAdvanced => MirrorRepairAdvice::ResolveRemoteAdvance,
                _ => MirrorRepairAdvice::FixConfig,
            },
        }
    }
}

/// Scheduler entrypoint.  A disabled configuration is an observable no-op.
pub async fn run_nightly(home: &Path, config: &VaultMirrorConfig) -> VaultMirrorStatus {
    if !config.enabled {
        return VaultMirrorStatus::disabled();
    }
    if !config.allow_nightly_push {
        return VaultMirrorStatus::blocked(MirrorBlockReason::NightlyPushNotAllowed);
    }
    run_impl(home, config, true).await
}

/// CLI entrypoint. `push=false` performs no Git network action.
pub async fn run_manual(home: &Path, config: &VaultMirrorConfig, push: bool) -> VaultMirrorStatus {
    if !config.enabled {
        return VaultMirrorStatus::disabled();
    }
    if push && !config.allow_manual_push {
        return VaultMirrorStatus::blocked(MirrorBlockReason::ManualPushNotAllowed);
    }
    run_impl(home, config, push).await
}

/// Read-only status projection used by Backup, Buddy, and the desktop GUI.
/// It deliberately never validates credentials or starts a Git child.
pub fn status(home: &Path, config: &VaultMirrorConfig) -> VaultMirrorStatus {
    if !config.enabled {
        return VaultMirrorStatus::disabled();
    }
    if config.validate().is_err() {
        return VaultMirrorStatus::blocked(MirrorBlockReason::InvalidConfiguration);
    }
    let paths = match MirrorPaths::open(home, false) {
        Ok(paths) => paths,
        Err(_)
            if std::fs::symlink_metadata(home.join("vault-mirror"))
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            return VaultMirrorStatus {
                config: MirrorConfigStatus::Ready,
                receipt: None,
                repair: MirrorRepairAdvice::NoAction,
            };
        }
        Err(_) => return VaultMirrorStatus::blocked(MirrorBlockReason::CorruptState),
    };
    match load_state(&paths) {
        Ok(Some(state)) => match state.active {
            Some(receipt) => configured_receipt_status(receipt, config),
            None => match state.verified_runs.first().cloned() {
                Some(receipt) => configured_receipt_status(receipt, config),
                None => VaultMirrorStatus {
                    config: MirrorConfigStatus::Ready,
                    receipt: None,
                    repair: MirrorRepairAdvice::NoAction,
                },
            },
        },
        Ok(None) => VaultMirrorStatus {
            config: MirrorConfigStatus::Ready,
            receipt: None,
            repair: MirrorRepairAdvice::NoAction,
        },
        Err(_) => VaultMirrorStatus::blocked(MirrorBlockReason::CorruptState),
    }
}

/// Reconcile only the one exact ref recorded before the ambiguous push.
pub async fn repair(home: &Path, config: &VaultMirrorConfig) -> VaultMirrorStatus {
    if !config.enabled {
        return VaultMirrorStatus::disabled();
    }
    if config.validate().is_err() {
        return VaultMirrorStatus::blocked(MirrorBlockReason::InvalidConfiguration);
    }
    let Some(remote) = config.remote_url.as_deref() else {
        return VaultMirrorStatus::blocked(MirrorBlockReason::InvalidConfiguration);
    };
    repair_for_remote(home, config, remote).await
}

#[cfg(test)]
async fn repair_with_test_remote(
    home: &Path,
    config: &VaultMirrorConfig,
    test_remote: &str,
) -> VaultMirrorStatus {
    if !config.enabled || config.validate().is_err() {
        return VaultMirrorStatus::blocked(MirrorBlockReason::InvalidConfiguration);
    }
    repair_for_remote(home, config, test_remote).await
}

async fn repair_for_remote(
    home: &Path,
    config: &VaultMirrorConfig,
    remote: &str,
) -> VaultMirrorStatus {
    let paths = match MirrorPaths::open(home, true) {
        Ok(paths) => paths,
        Err(_) => return VaultMirrorStatus::blocked(MirrorBlockReason::CorruptState),
    };
    let _lock = match MirrorLock::acquire(&paths, "repair") {
        Ok(lock) => lock,
        Err(_) => return VaultMirrorStatus::blocked(MirrorBlockReason::BusyOrStaleLock),
    };
    let mut state = match load_state(&paths) {
        Ok(Some(state)) => state,
        Ok(None) => {
            return VaultMirrorStatus {
                config: MirrorConfigStatus::Ready,
                receipt: None,
                repair: MirrorRepairAdvice::NoAction,
            };
        }
        Err(_) => return VaultMirrorStatus::blocked(MirrorBlockReason::CorruptState),
    };
    let Some(mut receipt) = state.active.clone() else {
        return VaultMirrorStatus {
            config: MirrorConfigStatus::Ready,
            receipt: state.verified_runs.first().cloned(),
            repair: MirrorRepairAdvice::NoAction,
        };
    };
    if receipt.config_fingerprint_sha256 != config_fingerprint(config)
        || receipt.remote_redaction != redact_remote(remote)
        || receipt.branch != config.branch
    {
        return VaultMirrorStatus::blocked(MirrorBlockReason::InvalidConfiguration);
    }
    if !matches!(
        receipt.phase,
        MirrorPhase::PushIntent | MirrorPhase::Indeterminate(_)
    ) {
        return status_for_receipt(receipt);
    }
    let Some(commit) = receipt.commit_oid.clone() else {
        return VaultMirrorStatus::blocked(MirrorBlockReason::CorruptState);
    };
    match git_ls_remote(&paths.repository, remote, &receipt.branch).await {
        Ok(Some(oid)) if oid == commit => {
            receipt.phase = MirrorPhase::Verified;
            receipt.remote_head_oid = Some(oid);
            receipt.verified_at_unix = Some(now());
            let receipt = settle_verified(&mut state, receipt);
            if persist_state(&paths, &state).is_err() {
                return VaultMirrorStatus::blocked(MirrorBlockReason::CorruptState);
            }
            status_for_receipt(receipt)
        }
        Ok(Some(_)) => {
            receipt.phase =
                MirrorPhase::Indeterminate(MirrorIndeterminateReason::RemoteOutcomeUnknown);
            state.active = Some(receipt.clone());
            if persist_state(&paths, &state).is_err() {
                return VaultMirrorStatus::blocked(MirrorBlockReason::CorruptState);
            }
            VaultMirrorStatus {
                config: MirrorConfigStatus::Blocked,
                receipt: Some(receipt),
                repair: MirrorRepairAdvice::ResolveRemoteAdvance,
            }
        }
        Ok(None) | Err(_) => {
            receipt.phase =
                MirrorPhase::Indeterminate(MirrorIndeterminateReason::RemoteOutcomeUnknown);
            state.active = Some(receipt.clone());
            if persist_state(&paths, &state).is_err() {
                return VaultMirrorStatus::blocked(MirrorBlockReason::CorruptState);
            }
            VaultMirrorStatus {
                config: MirrorConfigStatus::Blocked,
                receipt: Some(receipt),
                repair: MirrorRepairAdvice::RunVerification,
            }
        }
    }
}

async fn run_impl(home: &Path, config: &VaultMirrorConfig, push: bool) -> VaultMirrorStatus {
    if config.validate().is_err() {
        return VaultMirrorStatus::blocked(MirrorBlockReason::InvalidConfiguration);
    }
    let Some(remote) = config.remote_url.as_deref() else {
        return VaultMirrorStatus::blocked(MirrorBlockReason::InvalidConfiguration);
    };
    run_impl_for_remote(home, config, push, remote).await
}

/// The production entrypoint obtains its remote only from validated config.
/// Tests inject a local bare transport here while retaining the same archive,
/// state, repository, push, exact-head, and recovery state machine.
#[cfg(test)]
async fn run_impl_with_test_remote(
    home: &Path,
    config: &VaultMirrorConfig,
    push: bool,
    test_remote: &str,
) -> VaultMirrorStatus {
    if config.validate().is_err() {
        return VaultMirrorStatus::blocked(MirrorBlockReason::InvalidConfiguration);
    }
    run_impl_for_remote(home, config, push, test_remote).await
}

async fn run_impl_for_remote(
    home: &Path,
    config: &VaultMirrorConfig,
    push: bool,
    remote: &str,
) -> VaultMirrorStatus {
    let paths = match MirrorPaths::open(home, true) {
        Ok(paths) => paths,
        Err(_) => return VaultMirrorStatus::blocked(MirrorBlockReason::CorruptState),
    };
    let run_id = uuid::Uuid::now_v7().to_string();
    let lock = match MirrorLock::acquire(&paths, &run_id) {
        Ok(lock) => std::sync::Arc::new(lock),
        Err(_) => return VaultMirrorStatus::blocked(MirrorBlockReason::BusyOrStaleLock),
    };
    let mut state = match load_state(&paths) {
        Ok(Some(state)) => state,
        Ok(None) => VaultMirrorState {
            schema_version: VAULT_MIRROR_STATE_SCHEMA_V1,
            active: None,
            verified_runs: Vec::new(),
        },
        Err(_) => return VaultMirrorStatus::blocked(MirrorBlockReason::CorruptState),
    };
    if let Some(active) = state.active.clone()
        && matches!(
            active.phase,
            MirrorPhase::PushIntent | MirrorPhase::Indeterminate(_)
        )
    {
        return VaultMirrorStatus {
            config: MirrorConfigStatus::Blocked,
            receipt: Some(active),
            repair: MirrorRepairAdvice::RunVerification,
        };
    }
    let result = prepare_and_maybe_push(
        home, config, &paths, &mut state, &run_id, push, remote, &lock,
    )
    .await;
    drop(lock);
    result
}

#[allow(clippy::too_many_arguments)] // One transaction retains its shared kernel lease in blocking workers.
async fn prepare_and_maybe_push(
    home: &Path,
    config: &VaultMirrorConfig,
    paths: &MirrorPaths,
    state: &mut VaultMirrorState,
    run_id: &str,
    push: bool,
    remote: &str,
    lock: &std::sync::Arc<MirrorLock>,
) -> VaultMirrorStatus {
    if !verify_workspace_bindings(paths) {
        return VaultMirrorStatus::blocked(MirrorBlockReason::CorruptState);
    }
    let archive_home = home.to_path_buf();
    let stage = match paths.staging.child(run_id) {
        Ok(stage) => stage,
        Err(_) => return VaultMirrorStatus::blocked(MirrorBlockReason::CorruptState),
    };
    let worker_lock = std::sync::Arc::clone(lock);
    let archive_result =
        tokio::task::spawn_blocking(move || -> anyhow::Result<(std::fs::File, String, u64)> {
            let _worker_lock = worker_lock;
            let mut archive = stage.new_file("archive.tar.gz")?;
            backup::write_backup_to_file(&archive_home, &mut archive, true, false)?;
            let (sha256, bytes) = sha256_file(&mut archive)?;
            Ok((archive, sha256, bytes))
        })
        .await;
    let (archive, archive_sha256, archive_bytes) = match archive_result {
        Ok(Ok(value)) => value,
        Ok(Err(_)) | Err(_) => return VaultMirrorStatus::blocked(MirrorBlockReason::CorruptState),
    };
    let mut receipt = VaultMirrorReceipt {
        schema_version: VAULT_MIRROR_STATE_SCHEMA_V1,
        run_id: run_id.to_string(),
        config_fingerprint_sha256: config_fingerprint(config),
        archive_sha256: archive_sha256.clone(),
        archive_bytes,
        wal_included: true,
        credentials_included: false,
        branch: config.branch.clone(),
        remote_redaction: redact_remote(remote),
        commit_oid: None,
        remote_head_oid: None,
        phase: MirrorPhase::Prepared,
        created_at_unix: now(),
        verified_at_unix: None,
        retention: RetentionReceipt {
            enabled: config.allow_managed_retention,
            retained_verified_runs: config.retain_verified_runs,
            removed_runs: Vec::new(),
            phase: None,
        },
    };
    state.active = Some(receipt.clone());
    if persist_state(paths, state).is_err() {
        return VaultMirrorStatus::blocked(MirrorBlockReason::CorruptState);
    }
    if !push {
        return status_for_receipt(receipt);
    }
    let prior_head = match git_ls_remote(&paths.repository, remote, &config.branch).await {
        Ok(head) => head,
        Err(class) => return VaultMirrorStatus::blocked(class),
    };
    if let Err(class) = git_prepare_repository(
        &paths.repository,
        remote,
        &config.branch,
        prior_head.is_some(),
    )
    .await
    {
        return VaultMirrorStatus::blocked(class);
    }
    if let Err(class) = git_prepare_commit(
        &paths.repository,
        archive,
        run_id,
        &receipt,
        &paths.instance_id,
        lock,
    )
    .await
    {
        return VaultMirrorStatus::blocked(class);
    }
    let commit = match git_rev_parse(&paths.repository).await {
        Ok(oid) => oid,
        Err(class) => return VaultMirrorStatus::blocked(class),
    };
    // A fetch is deliberately exact and non-destructive.  Re-check immediately before push.
    match git_ls_remote(&paths.repository, remote, &config.branch).await {
        Ok(current) if current == prior_head => {}
        Ok(_) => return VaultMirrorStatus::blocked(MirrorBlockReason::RemoteAdvanced),
        Err(class) => return VaultMirrorStatus::blocked(class),
    }
    receipt.commit_oid = Some(commit.clone());
    receipt.phase = MirrorPhase::PushIntent;
    state.active = Some(receipt.clone());
    if persist_state(paths, state).is_err() {
        return VaultMirrorStatus::blocked(MirrorBlockReason::CorruptState);
    }
    match git_push_exact(&paths.repository, remote, &commit, &config.branch).await {
        Ok(()) => match git_ls_remote(&paths.repository, remote, &config.branch).await {
            Ok(Some(oid)) if oid == commit => {
                receipt.phase = MirrorPhase::Verified;
                receipt.remote_head_oid = Some(oid);
                receipt.verified_at_unix = Some(now());
                let receipt = settle_verified(state, receipt);
                if persist_state(paths, state).is_err() {
                    return VaultMirrorStatus::blocked(MirrorBlockReason::CorruptState);
                }
                match apply_managed_retention(paths, state, config, remote).await {
                    Ok(()) => {
                        status_for_receipt(state.verified_runs.first().cloned().unwrap_or(receipt))
                    }
                    Err(status) => status,
                }
            }
            Ok(_) => indeterminate(
                paths,
                state,
                receipt,
                MirrorIndeterminateReason::RemoteOutcomeUnknown,
            ),
            Err(_) => indeterminate(
                paths,
                state,
                receipt,
                MirrorIndeterminateReason::RemoteOutcomeUnknown,
            ),
        },
        Err(_) => indeterminate(
            paths,
            state,
            receipt,
            MirrorIndeterminateReason::PushOutcomeUnknown,
        ),
    }
}

/// Retention is a second ordinary commit.  It selects only receipt-backed,
/// verified run directories below this instance's namespace; it never deletes
/// a ref, object, archive current pointer, or an unrecognised repository path.
async fn apply_managed_retention(
    paths: &MirrorPaths,
    state: &mut VaultMirrorState,
    config: &VaultMirrorConfig,
    remote: &str,
) -> Result<(), VaultMirrorStatus> {
    if !config.allow_managed_retention {
        return Ok(());
    }
    let fingerprint = config_fingerprint(config);
    let mut candidates = Vec::new();
    for receipt in state
        .verified_runs
        .iter()
        .filter(|receipt| matches!(receipt.phase, MirrorPhase::Verified))
        .filter(|receipt| receipt.config_fingerprint_sha256 == fingerprint)
        .filter(|receipt| receipt.branch == config.branch)
        .filter(|receipt| valid_run_id(&receipt.run_id))
        .skip(config.retain_verified_runs as usize)
    {
        candidates.push(receipt.run_id.clone());
    }
    if candidates.is_empty() {
        return Ok(());
    }

    let prior_head = git_ls_remote(&paths.repository, remote, &config.branch)
        .await
        .map_err(VaultMirrorStatus::blocked)?;
    let Some(prior_head) = prior_head else {
        return Err(VaultMirrorStatus::blocked(
            MirrorBlockReason::RemoteAdvanced,
        ));
    };
    if state
        .verified_runs
        .first()
        .and_then(|receipt| receipt.commit_oid.as_deref())
        != Some(prior_head.as_str())
    {
        return Err(VaultMirrorStatus::blocked(
            MirrorBlockReason::RemoteAdvanced,
        ));
    }
    git_fetch_exact(&paths.repository, remote, &config.branch)
        .await
        .map_err(VaultMirrorStatus::blocked)?;
    let current = git_ls_remote(&paths.repository, remote, &config.branch)
        .await
        .map_err(VaultMirrorStatus::blocked)?;
    if current.as_deref() != Some(prior_head.as_str()) {
        return Err(VaultMirrorStatus::blocked(
            MirrorBlockReason::RemoteAdvanced,
        ));
    }
    for run_id in &candidates {
        let run = paths
            .repository
            .existing_child(".neoth-mirror")
            .and_then(|directory| directory.existing_child(&paths.instance_id))
            .and_then(|directory| directory.existing_child("runs"))
            .and_then(|directory| directory.existing_child(run_id))
            .map_err(|_| VaultMirrorStatus::blocked(MirrorBlockReason::CorruptState))?;
        let bytes = store::read_regular_file_bounded(
            &run.dir,
            OsStr::new("manifest.json"),
            &run.display.join("manifest.json"),
            MAX_STATE_BYTES as usize,
        )
        .map_err(|_| VaultMirrorStatus::blocked(MirrorBlockReason::CorruptState))?;
        let manifest: VaultMirrorReceipt = serde_json::from_slice(&bytes)
            .map_err(|_| VaultMirrorStatus::blocked(MirrorBlockReason::CorruptState))?;
        let authorized = state.verified_runs.iter().any(|receipt| {
            receipt.run_id == *run_id
                && manifest.run_id == *run_id
                && manifest.archive_sha256 == receipt.archive_sha256
                && manifest.config_fingerprint_sha256 == fingerprint
                && manifest.branch == config.branch
        });
        if !authorized {
            return Err(VaultMirrorStatus::blocked(MirrorBlockReason::CorruptState));
        }
        // Only the receipt-backed manifest is owned. An unrelated child in
        // that directory must survive, so never recursively remove the tree.
        let owned = format!(
            ".neoth-mirror/{}/runs/{run_id}/manifest.json",
            paths.instance_id
        );
        git(&paths.repository, &["rm", "--", &owned])
            .await
            .map_err(VaultMirrorStatus::blocked)?;
    }
    let message = format!("NEOTH vault mirror retention {}", uuid::Uuid::now_v7());
    git(
        &paths.repository,
        &[
            "-c",
            "user.name=NEOTH Vault Mirror",
            "-c",
            "user.email=neoth-vault-mirror@localhost",
            "commit",
            "--no-gpg-sign",
            "-m",
            &message,
        ],
    )
    .await
    .map_err(VaultMirrorStatus::blocked)?;
    let commit = git_rev_parse(&paths.repository)
        .await
        .map_err(VaultMirrorStatus::blocked)?;
    if git_ls_remote(&paths.repository, remote, &config.branch)
        .await
        .map_err(VaultMirrorStatus::blocked)?
        .as_deref()
        != Some(prior_head.as_str())
    {
        return Err(VaultMirrorStatus::blocked(
            MirrorBlockReason::RemoteAdvanced,
        ));
    }
    let mut cleanup = VaultMirrorReceipt {
        schema_version: VAULT_MIRROR_STATE_SCHEMA_V1,
        run_id: format!("retention-{}", uuid::Uuid::now_v7()),
        config_fingerprint_sha256: fingerprint,
        archive_sha256: String::new(),
        archive_bytes: 0,
        wal_included: true,
        credentials_included: false,
        branch: config.branch.clone(),
        remote_redaction: redact_remote(remote),
        commit_oid: Some(commit.clone()),
        remote_head_oid: None,
        phase: MirrorPhase::PushIntent,
        created_at_unix: now(),
        verified_at_unix: None,
        retention: RetentionReceipt {
            enabled: true,
            retained_verified_runs: config.retain_verified_runs,
            removed_runs: candidates,
            phase: Some(MirrorPhase::PushIntent),
        },
    };
    state.active = Some(cleanup.clone());
    persist_state(paths, state)
        .map_err(|_| VaultMirrorStatus::blocked(MirrorBlockReason::CorruptState))?;
    match git_push_exact(&paths.repository, remote, &commit, &config.branch).await {
        Ok(()) => match git_ls_remote(&paths.repository, remote, &config.branch).await {
            Ok(Some(oid)) if oid == commit => {
                cleanup.phase = MirrorPhase::Verified;
                cleanup.remote_head_oid = Some(oid);
                cleanup.verified_at_unix = Some(now());
                settle_verified(state, cleanup);
                persist_state(paths, state)
                    .map_err(|_| VaultMirrorStatus::blocked(MirrorBlockReason::CorruptState))
            }
            Ok(_) | Err(_) => Err(indeterminate(
                paths,
                state,
                cleanup,
                MirrorIndeterminateReason::RemoteOutcomeUnknown,
            )),
        },
        Err(_) => Err(indeterminate(
            paths,
            state,
            cleanup,
            MirrorIndeterminateReason::PushOutcomeUnknown,
        )),
    }
}

fn valid_run_id(run_id: &str) -> bool {
    uuid::Uuid::parse_str(run_id).is_ok()
}

/// Cleanup operations are not backups and never consume backup retention
/// slots. Immediate completion and repair share the same durable projection.
fn settle_verified(
    state: &mut VaultMirrorState,
    mut receipt: VaultMirrorReceipt,
) -> VaultMirrorReceipt {
    state.active = None;
    if is_cleanup_run(&receipt) {
        receipt.retention.phase = Some(MirrorPhase::Verified);
        state
            .verified_runs
            .retain(|prior| !receipt.retention.removed_runs.contains(&prior.run_id));
        if let Some(latest) = state.verified_runs.iter_mut().find(|prior| {
            prior.config_fingerprint_sha256 == receipt.config_fingerprint_sha256
                && prior.branch == receipt.branch
        }) {
            latest.retention = receipt.retention;
            return latest.clone();
        }
        return receipt;
    }
    state
        .verified_runs
        .retain(|prior| prior.run_id != receipt.run_id);
    state.verified_runs.insert(0, receipt.clone());
    state.verified_runs.truncate(MAX_VERIFIED_RECEIPTS);
    receipt
}

fn indeterminate(
    paths: &MirrorPaths,
    state: &mut VaultMirrorState,
    mut receipt: VaultMirrorReceipt,
    reason: MirrorIndeterminateReason,
) -> VaultMirrorStatus {
    receipt.phase = MirrorPhase::Indeterminate(reason);
    state.active = Some(receipt.clone());
    if persist_state(paths, state).is_err() {
        receipt.phase =
            MirrorPhase::Indeterminate(MirrorIndeterminateReason::StatePersistenceUnknown);
        return VaultMirrorStatus {
            config: MirrorConfigStatus::Blocked,
            receipt: Some(receipt),
            repair: MirrorRepairAdvice::RunVerification,
        };
    }
    VaultMirrorStatus {
        config: MirrorConfigStatus::Blocked,
        receipt: Some(receipt),
        repair: MirrorRepairAdvice::RunVerification,
    }
}
fn status_for_receipt(receipt: VaultMirrorReceipt) -> VaultMirrorStatus {
    let repair = if matches!(receipt.phase, MirrorPhase::Verified | MirrorPhase::Prepared) {
        MirrorRepairAdvice::NoAction
    } else {
        MirrorRepairAdvice::RunVerification
    };
    VaultMirrorStatus {
        config: MirrorConfigStatus::Ready,
        receipt: Some(receipt),
        repair,
    }
}
fn configured_receipt_status(
    receipt: VaultMirrorReceipt,
    config: &VaultMirrorConfig,
) -> VaultMirrorStatus {
    if receipt.config_fingerprint_sha256 != config_fingerprint(config)
        || receipt.branch != config.branch
        || Some(receipt.remote_redaction.as_str())
            != config.remote_url.as_deref().map(redact_remote).as_deref()
    {
        return VaultMirrorStatus {
            config: MirrorConfigStatus::Blocked,
            receipt: Some(receipt),
            repair: MirrorRepairAdvice::FixConfig,
        };
    }
    status_for_receipt(receipt)
}
fn blocked_receipt(reason: MirrorBlockReason) -> VaultMirrorReceipt {
    VaultMirrorReceipt {
        schema_version: VAULT_MIRROR_STATE_SCHEMA_V1,
        run_id: String::new(),
        config_fingerprint_sha256: String::new(),
        archive_sha256: String::new(),
        archive_bytes: 0,
        wal_included: true,
        credentials_included: false,
        branch: String::new(),
        remote_redaction: String::new(),
        commit_oid: None,
        remote_head_oid: None,
        phase: MirrorPhase::Blocked(reason),
        created_at_unix: now(),
        verified_at_unix: None,
        retention: RetentionReceipt {
            enabled: false,
            retained_verified_runs: 0,
            removed_runs: Vec::new(),
            phase: None,
        },
    }
}

struct MirrorDirectory {
    dir: Dir,
    display: PathBuf,
}
impl MirrorDirectory {
    fn child(&self, name: &str) -> anyhow::Result<Self> {
        let display = self.display.join(name);
        let dir = store::open_or_create_private_child_dir(&self.dir, OsStr::new(name), &display)?;
        Ok(Self { dir, display })
    }

    fn existing_child(&self, name: &str) -> anyhow::Result<Self> {
        let display = self.display.join(name);
        let (dir, _) = store::open_bound_real_child_dir(&self.dir, OsStr::new(name), &display)?;
        Ok(Self { dir, display })
    }

    fn new_file(&self, name: &str) -> anyhow::Result<std::fs::File> {
        let display = self.display.join(name);
        // The empty stage and its publication are fully capability-relative,
        // including on Windows. No private bytes are written via a path.
        store::atomic_write_private_child_create_new(&self.dir, OsStr::new(name), &display, &[])?;
        Ok(store::open_or_create_bound_lockfile(&self.dir, OsStr::new(name), &display)?.0)
    }
}

struct MirrorPaths {
    root: Dir,
    stage_binding: store::BoundDirectoryChild,
    repository_binding: store::BoundDirectoryChild,
    state: PathBuf,
    lock: PathBuf,
    staging: MirrorDirectory,
    repository: MirrorDirectory,
    instance_id: String,
}
impl MirrorPaths {
    fn open(home: &Path, create: bool) -> anyhow::Result<Self> {
        let Some(home_cap) =
            crate::skills::store::open_bound_directory(home, create, "vault mirror home")?
        else {
            anyhow::bail!("vault mirror home is absent");
        };
        let root_display = home_cap.physical_display_path.join("vault-mirror");
        let root = if create {
            crate::skills::store::open_or_create_private_child_dir(
                &home_cap.dir,
                OsStr::new("vault-mirror"),
                &root_display,
            )?
        } else {
            crate::skills::store::open_bound_real_child_dir(
                &home_cap.dir,
                OsStr::new("vault-mirror"),
                &root_display,
            )?
            .0
        };
        let staging = root_display.join("staging");
        let repository = root_display.join("repository");
        for (name, display) in [("staging", &staging), ("repository", &repository)] {
            if create {
                crate::skills::store::open_or_create_private_child_dir(
                    &root,
                    OsStr::new(name),
                    display,
                )?;
            } else {
                crate::skills::store::open_bound_real_child_dir(&root, OsStr::new(name), display)?;
            }
        }
        let (stage_dir, stage_binding) = crate::skills::store::open_bound_real_child_dir(
            &root,
            OsStr::new("staging"),
            &staging,
        )?;
        let (repository_dir, repository_binding) = crate::skills::store::open_bound_real_child_dir(
            &root,
            OsStr::new("repository"),
            &repository,
        )?;
        let mut hash = Sha256::new();
        hash.update(home_cap.physical_display_path.to_string_lossy().as_bytes());
        let instance_id = hex::encode(hash.finalize())[..24].to_string();
        Ok(Self {
            root,
            stage_binding,
            repository_binding,
            state: root_display.join("state-v1.json"),
            lock: root_display.join("run.lock"),
            staging: MirrorDirectory {
                dir: stage_dir,
                display: staging,
            },
            repository: MirrorDirectory {
                dir: repository_dir,
                display: repository,
            },
            instance_id,
        })
    }
}

fn verify_workspace_bindings(paths: &MirrorPaths) -> bool {
    paths
        .stage_binding
        .matches_directory_child(&paths.root, OsStr::new("staging"), &paths.staging.display)
        .unwrap_or(false)
        && paths
            .repository_binding
            .matches_directory_child(
                &paths.root,
                OsStr::new("repository"),
                &paths.repository.display,
            )
            .unwrap_or(false)
}
// Keep the lock inode permanently. The kernel releases its exclusive lease on
// crash, so repair can resume without guessing whether an old PID is alive.
struct MirrorLock {
    _file: std::fs::File,
}
impl MirrorLock {
    fn acquire(paths: &MirrorPaths, run_id: &str) -> anyhow::Result<Self> {
        let (mut file, _) =
            store::open_or_create_bound_lockfile(&paths.root, OsStr::new("run.lock"), &paths.lock)?;
        file.try_lock()
            .map_err(|error| anyhow::anyhow!("vault mirror is already owned: {error}"))?;
        file.set_len(0)?;
        file.write_all(format!("run_id={run_id}\nstarted_at={}\n", now()).as_bytes())?;
        file.sync_all()?;
        Ok(Self { _file: file })
    }
}

fn load_state(paths: &MirrorPaths) -> anyhow::Result<Option<VaultMirrorState>> {
    let name = OsStr::new("state-v1.json");
    let bytes = match crate::skills::store::read_regular_file_bounded(
        &paths.root,
        name,
        &paths.state,
        MAX_STATE_BYTES as usize,
    ) {
        Ok(bytes) => bytes,
        Err(error)
            if error
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let state: VaultMirrorState = serde_json::from_slice(&bytes)?;
    validate_state(&state)?;
    Ok(Some(state))
}
fn persist_state(paths: &MirrorPaths, state: &VaultMirrorState) -> anyhow::Result<()> {
    validate_state(state)?;
    let bytes = serde_json::to_vec(state)?;
    if bytes.len() > MAX_STATE_BYTES as usize {
        anyhow::bail!("vault mirror state exceeds cap");
    }
    crate::skills::store::atomic_write_private_child(
        &paths.root,
        OsStr::new("state-v1.json"),
        &paths.state,
        &bytes,
    )?;
    Ok(())
}

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
fn is_cleanup_run(receipt: &VaultMirrorReceipt) -> bool {
    receipt
        .run_id
        .strip_prefix("retention-")
        .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())
}
fn is_archive_run(receipt: &VaultMirrorReceipt) -> bool {
    uuid::Uuid::parse_str(&receipt.run_id).is_ok()
}
fn validate_receipt(receipt: &VaultMirrorReceipt, history: bool) -> anyhow::Result<()> {
    anyhow::ensure!(
        receipt.schema_version == VAULT_MIRROR_STATE_SCHEMA_V1
            && valid_hex(&receipt.config_fingerprint_sha256, 64),
        "invalid vault mirror receipt schema or config fingerprint"
    );
    let cleanup = is_cleanup_run(receipt);
    anyhow::ensure!(
        cleanup || is_archive_run(receipt),
        "invalid vault mirror receipt identity"
    );
    if cleanup {
        anyhow::ensure!(
            receipt.archive_sha256.is_empty()
                && receipt.archive_bytes == 0
                && receipt.retention.enabled
                && !receipt.retention.removed_runs.is_empty(),
            "invalid cleanup receipt payload"
        );
    } else {
        anyhow::ensure!(
            valid_hex(&receipt.archive_sha256, 64) && receipt.archive_bytes > 0,
            "invalid archive receipt payload"
        );
    }
    anyhow::ensure!(
        (1..=255).contains(&receipt.retention.retained_verified_runs),
        "invalid retention count"
    );
    let mut removed = std::collections::HashSet::new();
    for run_id in &receipt.retention.removed_runs {
        anyhow::ensure!(
            valid_run_id(run_id) && removed.insert(run_id.as_str()) && run_id != &receipt.run_id,
            "invalid or duplicate retention run id"
        );
    }
    if !receipt.retention.removed_runs.is_empty() {
        anyhow::ensure!(
            receipt.retention.enabled,
            "retention candidates require explicit policy"
        );
        if !cleanup {
            anyhow::ensure!(
                matches!(receipt.retention.phase, Some(MirrorPhase::Verified)),
                "archive retention metadata must be verified"
            );
        }
    } else {
        anyhow::ensure!(
            receipt.retention.phase.is_none(),
            "retention phase without candidates"
        );
    }
    anyhow::ensure!(
        !receipt.branch.is_empty()
            && !receipt.remote_redaction.is_empty()
            && receipt.wal_included
            && !receipt.credentials_included,
        "invalid vault mirror receipt policy fields"
    );
    anyhow::ensure!(
        receipt
            .commit_oid
            .as_deref()
            .is_none_or(|oid| valid_hex(oid, 40))
            && receipt
                .remote_head_oid
                .as_deref()
                .is_none_or(|oid| valid_hex(oid, 40)),
        "invalid vault mirror receipt oid"
    );
    if history {
        anyhow::ensure!(
            is_archive_run(receipt)
                && valid_hex(&receipt.archive_sha256, 64)
                && receipt.archive_bytes > 0
                && matches!(receipt.phase, MirrorPhase::Verified),
            "history must contain only verified archive receipts"
        );
    }
    match &receipt.phase {
        MirrorPhase::Verified => anyhow::ensure!(
            receipt.commit_oid.is_some()
                && receipt.remote_head_oid == receipt.commit_oid
                && receipt.verified_at_unix.is_some(),
            "verified receipt lacks exact remote confirmation"
        ),
        MirrorPhase::Prepared => anyhow::ensure!(
            is_archive_run(receipt)
                && valid_hex(&receipt.archive_sha256, 64)
                && receipt.archive_bytes > 0
                && receipt.commit_oid.is_none()
                && receipt.remote_head_oid.is_none()
                && receipt.verified_at_unix.is_none(),
            "prepared receipt is malformed"
        ),
        MirrorPhase::PushIntent | MirrorPhase::Indeterminate(_) => anyhow::ensure!(
            receipt.commit_oid.is_some()
                && receipt.remote_head_oid.is_none()
                && receipt.verified_at_unix.is_none(),
            "push receipt lacks an unresolved commit intent"
        ),
        MirrorPhase::Disabled | MirrorPhase::Blocked(_) => {
            anyhow::bail!("terminal blocked receipt cannot persist in mirror state")
        }
    }
    Ok(())
}
fn validate_state(state: &VaultMirrorState) -> anyhow::Result<()> {
    anyhow::ensure!(
        state.schema_version == VAULT_MIRROR_STATE_SCHEMA_V1
            && state.verified_runs.len() <= MAX_VERIFIED_RECEIPTS,
        "unsupported vault mirror state"
    );
    let mut runs = std::collections::HashSet::new();
    for receipt in &state.verified_runs {
        validate_receipt(receipt, true)?;
        anyhow::ensure!(
            runs.insert(receipt.run_id.as_str()),
            "duplicate verified run id"
        );
    }
    if let Some(active) = &state.active {
        validate_receipt(active, false)?;
        anyhow::ensure!(
            !runs.contains(active.run_id.as_str()),
            "active receipt duplicates verified history"
        );
        if is_cleanup_run(active) {
            anyhow::ensure!(
                !active.retention.removed_runs.is_empty()
                    && active
                        .retention
                        .phase
                        .as_ref()
                        .is_some_and(|phase| matches!(
                            phase,
                            MirrorPhase::PushIntent | MirrorPhase::Indeterminate(_)
                        ))
                    && active.retention.removed_runs.iter().all(|run_id| state
                        .verified_runs
                        .iter()
                        .any(|prior| &prior.run_id == run_id
                            && prior.config_fingerprint_sha256
                                == active.config_fingerprint_sha256
                            && prior.branch == active.branch
                            && prior.remote_redaction == active.remote_redaction)),
                "cleanup receipt must retain owned verified candidates"
            );
        }
    }
    Ok(())
}
fn sha256_file(file: &mut std::fs::File) -> anyhow::Result<(String, u64)> {
    file.rewind()?;
    let mut digest = Sha256::new();
    let bytes = std::io::copy(file, &mut DigestWriter(&mut digest))?;
    Ok((hex::encode(digest.finalize()), bytes))
}
struct DigestWriter<'a>(&'a mut Sha256);
impl std::io::Write for DigestWriter<'_> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.update(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
fn config_fingerprint(config: &VaultMirrorConfig) -> String {
    let mut d = Sha256::new();
    d.update(config.remote_url.as_deref().unwrap_or_default().as_bytes());
    d.update(config.branch.as_bytes());
    d.update(config.interval_secs.to_le_bytes());
    d.update(config.retain_verified_runs.to_le_bytes());
    hex::encode(d.finalize())
}
fn redact_remote(value: &str) -> String {
    if let Some((scheme, rest)) = value.split_once("://") {
        format!("{scheme}://{}", rest.split('@').next_back().unwrap_or_default())
    } else {
        value.to_string()
    }
}

async fn git_prepare_repository(
    repo: &MirrorDirectory,
    remote: &str,
    branch: &str,
    remote_exists: bool,
) -> Result<(), MirrorBlockReason> {
    // An existing .git must be a real directory, never a redirecting gitfile.
    let _metadata = repo
        .child(".git")
        .map_err(|_| MirrorBlockReason::CorruptState)?;
    git(repo, &["init", "--template="]).await?;
    if remote_exists {
        git_fetch_exact(repo, remote, branch).await?;
        git(repo, &["checkout", "-B", branch, "FETCH_HEAD"])
            .await
            .map(|_| ())
    } else {
        git(repo, &["checkout", "--orphan", branch])
            .await
            .map(|_| ())
    }
}

async fn git_prepare_commit(
    repo: &MirrorDirectory,
    mut archive: std::fs::File,
    run_id: &str,
    receipt: &VaultMirrorReceipt,
    instance_id: &str,
    lock: &std::sync::Arc<MirrorLock>,
) -> Result<(), MirrorBlockReason> {
    let owned = repo
        .child(".neoth-mirror")
        .and_then(|directory| directory.child(instance_id))
        .map_err(|_| MirrorBlockReason::CorruptState)?;
    let current = owned
        .child("current")
        .map_err(|_| MirrorBlockReason::CorruptState)?;
    let run = owned
        .child("runs")
        .and_then(|directory| directory.child(run_id))
        .map_err(|_| MirrorBlockReason::CorruptState)?;
    let manifest = serde_json::to_vec(receipt).map_err(|_| MirrorBlockReason::CorruptState)?;
    let expected_hash = receipt.archive_sha256.clone();
    let expected_bytes = receipt.archive_bytes;
    let worker_lock = std::sync::Arc::clone(lock);
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let _worker_lock = worker_lock;
        let name = OsStr::new("archive.tar.gz");
        let display = current.display.join(name);
        // Replace the leaf itself before opening the new private inode. A
        // fetched link is refused by the store; no archive bytes follow it.
        store::atomic_write_private_child(&current.dir, name, &display, &[])?;
        let (mut target, _) = store::open_or_create_bound_lockfile(&current.dir, name, &display)?;
        archive.rewind()?;
        let copied = std::io::copy(&mut archive, &mut target)?;
        target.sync_all()?;
        let (actual_hash, actual_bytes) = sha256_file(&mut target)?;
        anyhow::ensure!(
            copied == expected_bytes
                && actual_bytes == expected_bytes
                && actual_hash == expected_hash,
            "vault mirror archive copy changed"
        );
        store::atomic_write_private_child_create_new(
            &run.dir,
            OsStr::new("manifest.json"),
            &run.display.join("manifest.json"),
            &manifest,
        )?;
        Ok(())
    })
    .await
    .map_err(|_| MirrorBlockReason::CorruptState)?
    .map_err(|_| MirrorBlockReason::CorruptState)?;
    let current = format!(".neoth-mirror/{instance_id}/current/archive.tar.gz");
    let manifest = format!(".neoth-mirror/{instance_id}/runs/{run_id}/manifest.json");
    git(repo, &["add", "--", &current, &manifest]).await?;
    let message = format!("NEOTH vault mirror {run_id}");
    git(
        repo,
        &[
            "-c",
            "user.name=NEOTH Vault Mirror",
            "-c",
            "user.email=neoth-vault-mirror@localhost",
            "commit",
            "--no-gpg-sign",
            "-m",
            &message,
        ],
    )
    .await
    .map(|_| ())
}

async fn git_rev_parse(repo: &MirrorDirectory) -> Result<String, MirrorBlockReason> {
    let output = git(repo, &["rev-parse", "HEAD"]).await?;
    let oid = String::from_utf8(output)
        .map_err(|_| MirrorBlockReason::CorruptState)?
        .trim()
        .to_string();
    if oid.len() == 40 && oid.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(oid)
    } else {
        Err(MirrorBlockReason::CorruptState)
    }
}
async fn git_fetch_exact(
    repo: &MirrorDirectory,
    remote: &str,
    branch: &str,
) -> Result<(), MirrorBlockReason> {
    let reference = format!("refs/heads/{branch}");
    git(repo, &["fetch", "--no-tags", "--", remote, &reference])
        .await
        .map(|_| ())
}
async fn git_push_exact(
    repo: &MirrorDirectory,
    remote: &str,
    commit: &str,
    branch: &str,
) -> Result<(), MirrorBlockReason> {
    let refspec = format!("{commit}:refs/heads/{branch}");
    git(repo, &["push", "--porcelain", "--", remote, &refspec])
        .await
        .map(|_| ())
}
async fn git_ls_remote(
    repo: &MirrorDirectory,
    remote: &str,
    branch: &str,
) -> Result<Option<String>, MirrorBlockReason> {
    let wanted_ref = format!("refs/heads/{branch}");
    let output = git(repo, &["ls-remote", "--refs", "--", remote, &wanted_ref]).await?;
    let text = String::from_utf8(output).map_err(|_| MirrorBlockReason::InvalidConfiguration)?;
    let mut lines = text.lines();
    let Some(line) = lines.next() else {
        return Ok(None);
    };
    if lines.next().is_some() {
        return Err(MirrorBlockReason::InvalidConfiguration);
    }
    let mut fields = line.split_whitespace();
    let oid = fields.next().unwrap_or_default();
    let reference = fields.next().unwrap_or_default();
    if fields.next().is_some()
        || reference != wanted_ref
        || oid.len() != 40
        || !oid.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(MirrorBlockReason::InvalidConfiguration);
    }
    Ok(Some(oid.to_string()))
}
async fn git(repo: &MirrorDirectory, args: &[&str]) -> Result<Vec<u8>, MirrorBlockReason> {
    let mut command = tokio::process::Command::new("git");
    // Keep the operator's credential manager / SSH agent, but disallow
    // inherited repository/index redirection and executable repository hooks.
    for key in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
        "GIT_ASKPASS",
        "SSH_ASKPASS",
    ] {
        command.env_remove(key);
    }
    command
        .args([
            "-c",
            "core.hooksPath=",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "commit.gpgSign=false",
        ])
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0");
    let mut child =
        crate::updater::process_containment::ContainedChild::spawn_in_retained_directory(
            command,
            &repo.dir,
            &repo.display,
            &[],
            MAX_GIT_OUTPUT_BYTES,
        )
        .await
        .map_err(|_| MirrorBlockReason::CredentialUnavailable)?;
    let deadline = std::time::Instant::now() + GIT_TIMEOUT;
    let output = match child.wait_until(deadline).await {
        Ok(output) => output,
        Err(crate::updater::process_containment::ContainedChildError::DeadlineElapsed) => {
            let _ = child.terminate_and_reap().await;
            return Err(MirrorBlockReason::CredentialUnavailable);
        }
        Err(_) => return Err(MirrorBlockReason::CredentialUnavailable),
    };
    if !output.status.success() {
        return Err(MirrorBlockReason::CredentialUnavailable);
    }
    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(retain_verified_runs: u32, allow_managed_retention: bool) -> VaultMirrorConfig {
        VaultMirrorConfig {
            enabled: true,
            allow_nightly_push: false,
            allow_manual_push: true,
            remote_url: Some("ssh://git@git.example.invalid/operator/neoth-vault.git".into()),
            branch: "neoth-vault".into(),
            interval_secs: VaultMirrorConfig::MIN_INTERVAL_SECS,
            retain_verified_runs,
            allow_managed_retention,
        }
    }

    fn verified_state_receipt() -> VaultMirrorReceipt {
        let run_id = uuid::Uuid::now_v7().to_string();
        let oid = "a".repeat(40);
        VaultMirrorReceipt {
            schema_version: VAULT_MIRROR_STATE_SCHEMA_V1,
            run_id,
            config_fingerprint_sha256: "b".repeat(64),
            archive_sha256: "c".repeat(64),
            archive_bytes: 1,
            wal_included: true,
            credentials_included: false,
            branch: "neoth-vault".into(),
            remote_redaction: "ssh://git.example.invalid/operator/neoth-vault.git".into(),
            commit_oid: Some(oid.clone()),
            remote_head_oid: Some(oid),
            phase: MirrorPhase::Verified,
            created_at_unix: 1,
            verified_at_unix: Some(2),
            retention: RetentionReceipt {
                enabled: false,
                retained_verified_runs: 1,
                removed_runs: Vec::new(),
                phase: None,
            },
        }
    }

    #[test]
    fn persisted_state_rejects_malformed_receipt_and_duplicate_history() {
        let receipt = verified_state_receipt();
        let mut malformed = receipt.clone();
        malformed.archive_sha256 = "bad".into();
        assert!(
            validate_state(&VaultMirrorState {
                schema_version: VAULT_MIRROR_STATE_SCHEMA_V1,
                active: None,
                verified_runs: vec![malformed]
            })
            .is_err()
        );
        assert!(
            validate_state(&VaultMirrorState {
                schema_version: VAULT_MIRROR_STATE_SCHEMA_V1,
                active: None,
                verified_runs: vec![receipt.clone(), receipt]
            })
            .is_err()
        );
    }

    #[test]
    fn persisted_cleanup_requires_unique_verified_owned_candidates() {
        let archived = verified_state_receipt();
        let mut cleanup = archived.clone();
        cleanup.run_id = format!("retention-{}", uuid::Uuid::now_v7());
        cleanup.archive_sha256.clear();
        cleanup.archive_bytes = 0;
        cleanup.remote_head_oid = None;
        cleanup.verified_at_unix = None;
        cleanup.phase = MirrorPhase::PushIntent;
        cleanup.retention = RetentionReceipt {
            enabled: true,
            retained_verified_runs: 1,
            removed_runs: vec![archived.run_id.clone()],
            phase: Some(MirrorPhase::PushIntent),
        };
        validate_state(&VaultMirrorState {
            schema_version: VAULT_MIRROR_STATE_SCHEMA_V1,
            active: Some(cleanup.clone()),
            verified_runs: vec![archived.clone()],
        })
        .expect("valid cleanup control before duplicate injection");
        cleanup.retention.removed_runs.push(archived.run_id.clone());
        assert!(
            validate_state(&VaultMirrorState {
                schema_version: VAULT_MIRROR_STATE_SCHEMA_V1,
                active: Some(cleanup),
                verified_runs: vec![archived]
            })
            .is_err()
        );
    }

    fn init_bare_remote(path: &Path) {
        assert!(
            std::process::Command::new("git")
                .args(["init", "--bare"])
                .arg(path)
                .status()
                .expect("start bare remote init")
                .success()
        );
    }

    async fn push_backup(
        home: &Path,
        config: &VaultMirrorConfig,
        remote: &str,
    ) -> VaultMirrorReceipt {
        let status = run_impl_with_test_remote(home, config, true, remote).await;
        let receipt = status.receipt.expect("mirror receipt");
        assert!(matches!(&receipt.phase, MirrorPhase::Verified));
        receipt
    }

    async fn add_foreign_run_child(paths: &MirrorPaths, remote: &str, branch: &str, run_id: &str) {
        let relative = format!(
            ".neoth-mirror/{}/runs/{run_id}/foreign-child.txt",
            paths.instance_id
        );
        std::fs::write(
            paths.repository.display.join(&relative),
            b"foreign child survives retention",
        )
        .expect("write unrelated run child");
        git(&paths.repository, &["add", "--", &relative])
            .await
            .expect("stage unrelated run child");
        git(
            &paths.repository,
            &[
                "-c",
                "user.name=fixture",
                "-c",
                "user.email=fixture@example.test",
                "commit",
                "--no-gpg-sign",
                "-m",
                "fixture foreign run child",
            ],
        )
        .await
        .expect("commit unrelated run child");
        let commit = git_rev_parse(&paths.repository)
            .await
            .expect("foreign-child commit id");
        git_push_exact(&paths.repository, remote, &commit, branch)
            .await
            .expect("push unrelated run child");
    }

    // Hosted-only: this fixture creates a local bare Git remote and exercises
    // archive -> commit -> push -> exact-ref reconciliation.  Do not run it on
    // the BSOD-held local workstation.
    #[tokio::test]
    async fn hosted_fixture_runs_backup_state_push_remote_and_repair_against_a_real_bare_remote() {
        let fixture = tempfile::tempdir().unwrap();
        let home = fixture.path().join("neoth-home");
        let bare = fixture.path().join("remote.git");
        std::fs::create_dir_all(home.join("wal")).unwrap();
        std::fs::write(home.join("wal/fixture.wal"), b"known WAL fixture bytes").unwrap();
        init_bare_remote(&bare);
        let remote = bare.to_str().unwrap();
        let config = test_config(1, false);
        let status = run_impl_with_test_remote(&home, &config, true, remote).await;
        let receipt = status.receipt.expect("full state-machine receipt");
        assert!(matches!(receipt.phase, MirrorPhase::Verified));
        assert!(receipt.wal_included && !receipt.credentials_included);
        let paths = MirrorPaths::open(&home, true).unwrap();
        let archive = paths
            .staging
            .display
            .join(&receipt.run_id)
            .join("archive.tar.gz");
        assert!(archive.is_file());
        let mut archive_file = std::fs::File::open(&archive).unwrap();
        assert_eq!(
            sha256_file(&mut archive_file).unwrap().0,
            receipt.archive_sha256
        );
        let commit = receipt.commit_oid.clone().expect("verified commit");
        assert_eq!(
            git_ls_remote(&paths.repository, remote, &config.branch)
                .await
                .unwrap(),
            Some(commit.clone())
        );
        let manifest_path = format!(
            "{}:.neoth-mirror/{}/runs/{}/manifest.json",
            commit, paths.instance_id, receipt.run_id
        );
        let manifest = git(&paths.repository, &["show", &manifest_path])
            .await
            .unwrap();
        let committed: VaultMirrorReceipt = serde_json::from_slice(&manifest).unwrap();
        assert_eq!(committed.archive_sha256, receipt.archive_sha256);
        let mut state = load_state(&paths).unwrap().unwrap();
        let mut pending = state.verified_runs.first().cloned().unwrap();
        pending.phase = MirrorPhase::PushIntent;
        pending.remote_head_oid = None;
        pending.verified_at_unix = None;
        state.active = Some(pending);
        state.verified_runs.clear();
        persist_state(&paths, &state).unwrap();
        let repaired = repair_with_test_remote(&home, &config, remote).await;
        assert!(matches!(
            repaired.receipt.unwrap().phase,
            MirrorPhase::Verified
        ));
    }

    #[tokio::test]
    async fn managed_retention_keeps_two_archive_receipts_and_only_removes_owned_manifests() {
        let fixture = tempfile::tempdir().unwrap();
        let home = fixture.path().join("neoth-home");
        let bare = fixture.path().join("remote.git");
        std::fs::create_dir_all(home.join("wal")).unwrap();
        std::fs::write(home.join("wal/fixture.wal"), b"known WAL fixture bytes").unwrap();
        init_bare_remote(&bare);
        let remote = bare.to_str().unwrap();
        let config = test_config(2, true);

        let first = push_backup(&home, &config, remote).await;
        let paths = MirrorPaths::open(&home, true).unwrap();
        add_foreign_run_child(&paths, remote, &config.branch, &first.run_id).await;
        let second = push_backup(&home, &config, remote).await;
        let third = push_backup(&home, &config, remote).await;
        let fourth = push_backup(&home, &config, remote).await;

        let state = load_state(&paths).unwrap().expect("retention state");
        assert!(state.active.is_none());
        assert_eq!(
            state.verified_runs.len(),
            2,
            "retention history counts archives, not cleanup operations"
        );
        let retained_ids = state
            .verified_runs
            .iter()
            .map(|receipt| receipt.run_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            retained_ids,
            vec![fourth.run_id.as_str(), third.run_id.as_str()]
        );
        assert!(
            state
                .verified_runs
                .iter()
                .all(|receipt| valid_run_id(&receipt.run_id))
        );
        assert!(
            state
                .verified_runs
                .iter()
                .all(|receipt| receipt.run_id != second.run_id)
        );
        assert!(
            state
                .verified_runs
                .iter()
                .all(|receipt| receipt.run_id != first.run_id)
        );

        let run_root = format!(".neoth-mirror/{}/runs", paths.instance_id);
        let names = String::from_utf8(
            git(
                &paths.repository,
                &["ls-tree", "-r", "--name-only", "HEAD", "--", &run_root],
            )
            .await
            .expect("list retained run tree"),
        )
        .expect("UTF-8 git tree names");
        assert_eq!(
            names
                .lines()
                .filter(|name| name.ends_with("/manifest.json"))
                .count(),
            2,
            "only the two retained run manifests remain on the mirror branch"
        );
        let foreign = format!(
            ".neoth-mirror/{}/runs/{}/foreign-child.txt",
            paths.instance_id, first.run_id
        );
        let foreign_object = format!("HEAD:{foreign}");
        let foreign_bytes = git(&paths.repository, &["show", &foreign_object])
            .await
            .expect("foreign child remains in old run directory");
        assert_eq!(foreign_bytes, b"foreign child survives retention");
    }

    #[tokio::test]
    async fn repair_settles_an_already_pushed_retention_commit_without_creating_cleanup_history() {
        let fixture = tempfile::tempdir().unwrap();
        let home = fixture.path().join("neoth-home");
        let bare = fixture.path().join("remote.git");
        std::fs::create_dir_all(home.join("wal")).unwrap();
        std::fs::write(home.join("wal/fixture.wal"), b"known WAL fixture bytes").unwrap();
        init_bare_remote(&bare);
        let remote = bare.to_str().unwrap();
        let config = test_config(2, true);

        let first = push_backup(&home, &config, remote).await;
        let second = push_backup(&home, &config, remote).await;
        let third = push_backup(&home, &config, remote).await;
        let paths = MirrorPaths::open(&home, true).unwrap();
        let cleanup_commit = git_ls_remote(&paths.repository, remote, &config.branch)
            .await
            .expect("read actual pushed retention head")
            .expect("retention commit exists");

        let mut pre_cleanup_third = third.clone();
        pre_cleanup_third.retention.removed_runs.clear();
        pre_cleanup_third.retention.phase = None;
        let retained_third_id = pre_cleanup_third.run_id.clone();
        let mut pending = third;
        pending.run_id = format!("retention-{}", uuid::Uuid::now_v7());
        pending.archive_sha256.clear();
        pending.archive_bytes = 0;
        pending.commit_oid = Some(cleanup_commit);
        pending.remote_head_oid = None;
        pending.phase = MirrorPhase::PushIntent;
        pending.verified_at_unix = None;
        pending.retention = RetentionReceipt {
            enabled: true,
            retained_verified_runs: 2,
            removed_runs: vec![first.run_id.clone()],
            phase: Some(MirrorPhase::PushIntent),
        };
        let mut state = load_state(&paths)
            .unwrap()
            .expect("settled retention state");
        state.active = Some(pending);
        state.verified_runs = vec![pre_cleanup_third, second.clone(), first.clone()];
        persist_state(&paths, &state).unwrap();

        let repaired = repair_with_test_remote(&home, &config, remote).await;
        assert!(matches!(
            repaired.receipt.as_ref().map(|receipt| &receipt.phase),
            Some(MirrorPhase::Verified)
        ));
        let repaired_state = load_state(&paths)
            .unwrap()
            .expect("repaired retention state");
        assert!(repaired_state.active.is_none());
        assert_eq!(repaired_state.verified_runs.len(), 2);
        assert_eq!(repaired_state.verified_runs[0].run_id, retained_third_id);
        assert_eq!(repaired_state.verified_runs[1].run_id, second.run_id);
        assert!(
            repaired_state
                .verified_runs
                .iter()
                .all(|receipt| receipt.run_id != first.run_id),
            "the active retention receipt removes only its recorded candidate"
        );
        assert!(
            repaired_state
                .verified_runs
                .iter()
                .all(|receipt| valid_run_id(&receipt.run_id))
        );
        let latest = repaired_state
            .verified_runs
            .first()
            .expect("latest archive receipt");
        assert_eq!(latest.retention.removed_runs, vec![first.run_id]);
        assert!(matches!(
            latest.retention.phase,
            Some(MirrorPhase::Verified)
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fetched_owned_namespace_symlink_refuses_outside_archive_writes() {
        use std::os::unix::fs::symlink;

        let fixture = tempfile::tempdir().unwrap();
        let home = fixture.path().join("neoth-home");
        let bare = fixture.path().join("remote.git");
        let seed = fixture.path().join("seed");
        let outside = fixture.path().join("outside");
        std::fs::create_dir_all(home.join("wal")).unwrap();
        std::fs::write(home.join("wal/fixture.wal"), b"known WAL fixture bytes").unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("sentinel"), b"outside remains untouched").unwrap();
        init_bare_remote(&bare);
        assert!(
            std::process::Command::new("git")
                .args(["init", "--initial-branch=neoth-vault"])
                .arg(&seed)
                .status()
                .expect("initialize attacker seed")
                .success()
        );
        symlink(&outside, seed.join(".neoth-mirror")).unwrap();
        for args in [
            vec!["add", "--", ".neoth-mirror"],
            vec![
                "-c",
                "user.name=fixture",
                "-c",
                "user.email=fixture@example.test",
                "commit",
                "--no-gpg-sign",
                "-m",
                "symlink fixture",
            ],
            vec!["remote", "add", "origin", bare.to_str().unwrap()],
            vec!["push", "origin", "neoth-vault"],
        ] {
            assert!(
                std::process::Command::new("git")
                    .current_dir(&seed)
                    .args(args)
                    .status()
                    .expect("run attacker seed command")
                    .success()
            );
        }

        let config = test_config(1, false);
        let status = run_impl_with_test_remote(&home, &config, true, bare.to_str().unwrap()).await;
        assert!(matches!(
            status.receipt.as_ref().map(|receipt| &receipt.phase),
            Some(MirrorPhase::Blocked(MirrorBlockReason::CorruptState))
        ));
        assert_eq!(
            std::fs::read(outside.join("sentinel")).unwrap(),
            b"outside remains untouched"
        );
        assert!(!outside.join("current/archive.tar.gz").exists());
        assert!(!outside.join("runs").exists());
    }

    #[tokio::test]
    async fn prepared_nonpush_runs_never_touch_an_absent_remote_and_a_later_push_uses_a_new_run() {
        let fixture = tempfile::tempdir().unwrap();
        let home = fixture.path().join("neoth-home");
        let bare = fixture.path().join("remote.git");
        std::fs::create_dir_all(home.join("wal")).unwrap();
        std::fs::write(home.join("wal/fixture.wal"), b"known WAL fixture bytes").unwrap();
        let config = test_config(2, false);
        let absent_remote = bare.to_str().unwrap();

        let first = run_impl_with_test_remote(&home, &config, false, absent_remote)
            .await
            .receipt
            .expect("first prepared receipt");
        let second = run_impl_with_test_remote(&home, &config, false, absent_remote)
            .await
            .receipt
            .expect("second prepared receipt");
        assert!(matches!(&first.phase, MirrorPhase::Prepared));
        assert!(matches!(&second.phase, MirrorPhase::Prepared));
        assert_ne!(first.run_id, second.run_id);
        assert!(
            !bare.exists(),
            "nonpush must not initialize or contact its supplied remote"
        );
        let paths = MirrorPaths::open(&home, true).unwrap();
        let state = load_state(&paths).unwrap().expect("prepared state");
        assert!(state.verified_runs.is_empty());
        assert_eq!(
            state.active.as_ref().map(|receipt| receipt.run_id.as_str()),
            Some(second.run_id.as_str())
        );

        init_bare_remote(&bare);
        let pushed = push_backup(&home, &config, bare.to_str().unwrap()).await;
        assert!(matches!(&pushed.phase, MirrorPhase::Verified));
        assert_ne!(pushed.run_id, first.run_id);
        assert_ne!(pushed.run_id, second.run_id);
        assert_eq!(
            git_ls_remote(&paths.repository, bare.to_str().unwrap(), &config.branch)
                .await
                .unwrap(),
            pushed.commit_oid.clone(),
            "only the later explicit push may create the remote branch"
        );
        let state = load_state(&paths).unwrap().expect("verified state");
        assert!(state.active.is_none());
        assert_eq!(state.verified_runs.len(), 1);
        assert_eq!(state.verified_runs[0].run_id, pushed.run_id);
    }

    #[tokio::test]
    async fn active_push_uncertainty_blocks_replay_and_mismatched_repair_preserves_the_receipt() {
        let fixture = tempfile::tempdir().unwrap();
        let home = fixture.path().join("neoth-home");
        let bare = fixture.path().join("remote.git");
        std::fs::create_dir_all(home.join("wal")).unwrap();
        std::fs::write(home.join("wal/fixture.wal"), b"known WAL fixture bytes").unwrap();
        init_bare_remote(&bare);
        let remote = bare.to_str().unwrap();
        let config = test_config(2, false);
        let verified = push_backup(&home, &config, remote).await;
        let paths = MirrorPaths::open(&home, true).unwrap();
        let original_head = git_ls_remote(&paths.repository, remote, &config.branch)
            .await
            .unwrap()
            .expect("verified remote head");

        let mut active = verified.clone();
        active.run_id = uuid::Uuid::now_v7().to_string();
        active.phase = MirrorPhase::PushIntent;
        active.remote_head_oid = None;
        active.verified_at_unix = None;
        let active_id = active.run_id.clone();
        let mut state = load_state(&paths).unwrap().expect("verified state");
        state.active = Some(active.clone());
        persist_state(&paths, &state).unwrap();

        let blocked_push = run_impl_with_test_remote(&home, &config, true, remote).await;
        assert!(matches!(&blocked_push.config, MirrorConfigStatus::Blocked));
        assert_eq!(
            blocked_push
                .receipt
                .as_ref()
                .map(|receipt| receipt.run_id.as_str()),
            Some(active_id.as_str())
        );
        assert_eq!(
            git_ls_remote(&paths.repository, remote, &config.branch)
                .await
                .unwrap(),
            Some(original_head.clone())
        );
        assert_eq!(
            load_state(&paths)
                .unwrap()
                .unwrap()
                .active
                .as_ref()
                .map(|receipt| receipt.run_id.as_str()),
            Some(active_id.as_str())
        );

        add_foreign_run_child(&paths, remote, &config.branch, &verified.run_id).await;
        let advanced_head = git_ls_remote(&paths.repository, remote, &config.branch)
            .await
            .unwrap()
            .expect("externally advanced remote head");
        assert_ne!(advanced_head, original_head);
        state.active = Some(VaultMirrorReceipt {
            phase: MirrorPhase::Indeterminate(MirrorIndeterminateReason::PushOutcomeUnknown),
            ..active
        });
        persist_state(&paths, &state).unwrap();

        let blocked_indeterminate = run_impl_with_test_remote(&home, &config, true, remote).await;
        assert!(matches!(
            &blocked_indeterminate.config,
            MirrorConfigStatus::Blocked
        ));
        assert_eq!(
            blocked_indeterminate
                .receipt
                .as_ref()
                .map(|receipt| receipt.run_id.as_str()),
            Some(active_id.as_str())
        );
        assert_eq!(
            git_ls_remote(&paths.repository, remote, &config.branch)
                .await
                .unwrap(),
            Some(advanced_head.clone())
        );

        let unresolved = repair_with_test_remote(&home, &config, remote).await;
        assert!(matches!(&unresolved.config, MirrorConfigStatus::Blocked));
        assert!(matches!(
            &unresolved.repair,
            MirrorRepairAdvice::ResolveRemoteAdvance
        ));
        assert_eq!(
            unresolved
                .receipt
                .as_ref()
                .map(|receipt| receipt.run_id.as_str()),
            Some(active_id.as_str())
        );
        assert_eq!(
            git_ls_remote(&paths.repository, remote, &config.branch)
                .await
                .unwrap(),
            Some(advanced_head)
        );
        let persisted = load_state(&paths)
            .unwrap()
            .expect("unresolved persisted state");
        assert_eq!(
            persisted
                .active
                .as_ref()
                .map(|receipt| receipt.run_id.as_str()),
            Some(active_id.as_str())
        );
        assert!(matches!(
            persisted.active.as_ref().map(|receipt| &receipt.phase),
            Some(MirrorPhase::Indeterminate(
                MirrorIndeterminateReason::RemoteOutcomeUnknown
            ))
        ));
    }

    #[test]
    fn malformed_retention_prefix_is_rejected_before_it_can_enter_active_state() {
        let config = test_config(2, true);
        let malformed = VaultMirrorReceipt {
            schema_version: VAULT_MIRROR_STATE_SCHEMA_V1,
            run_id: "retention-not-a-uuid".into(),
            config_fingerprint_sha256: config_fingerprint(&config),
            archive_sha256: String::new(),
            archive_bytes: 0,
            wal_included: true,
            credentials_included: false,
            branch: config.branch.clone(),
            remote_redaction: "file:///fixture-remote".into(),
            commit_oid: Some("0".repeat(40)),
            remote_head_oid: None,
            phase: MirrorPhase::PushIntent,
            created_at_unix: now(),
            verified_at_unix: None,
            retention: RetentionReceipt {
                enabled: true,
                retained_verified_runs: config.retain_verified_runs,
                removed_runs: Vec::new(),
                phase: Some(MirrorPhase::PushIntent),
            },
        };
        let state = VaultMirrorState {
            schema_version: VAULT_MIRROR_STATE_SCHEMA_V1,
            active: Some(malformed),
            verified_runs: Vec::new(),
        };
        assert!(validate_state(&state).is_err());
    }

    #[test]
    fn kernel_lock_can_be_reacquired_after_the_prior_owner_releases_it() {
        let fixture = tempfile::tempdir().unwrap();
        let paths = MirrorPaths::open(fixture.path(), true).unwrap();
        let first = MirrorLock::acquire(&paths, "first").expect("acquire initial kernel lease");
        assert!(MirrorLock::acquire(&paths, "contender").is_err());
        drop(first);
        let _second =
            MirrorLock::acquire(&paths, "second").expect("kernel releases lease after owner drop");
    }
}
