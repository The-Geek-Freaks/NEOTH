//! Receipt-bound, same-instance Paperless volume backup.
//!
//! This deliberately captures Docker's archive stream from the six existing,
//! receipt-owned mounts. It does not extract an archive, select a target, or
//! attempt an update/restore.

use super::*;
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _};
use cap_std::fs::OpenOptions;
use sha2::Sha256;
use std::{ffi::OsStr, io::{Read as _, Seek as _, SeekFrom}, path::Path};

pub(crate) const BACKUP_CUSTODY_NAME: &str = ".neoth-paperless-backup-custody.v1.json";
const BACKUP_DIR: &str = "backups";
const BACKUP_SOURCE_NAME: &str = "source.v1.json";
const BACKUP_ARCHIVE_LIMIT: u64 = 8 * 1024 * 1024 * 1024;
const BACKUP_TOTAL_LIMIT: u64 = 24 * 1024 * 1024 * 1024;
const RESTORE_CONFIG_KEYS: [&str; 6] = [
    "PAPERLESS_SECRET_KEY",
    "PAPERLESS_DB_NAME",
    "PAPERLESS_DB_USER",
    "PAPERLESS_DB_PASSWORD",
    "PAPERLESS_ADMIN_USER",
    "PAPERLESS_ADMIN_PASSWORD",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BackupPhase {
    Prepared,
    StopDispatched,
    Stopped,
    CopyDispatched,
    ArchiveVerified,
    StartDispatched,
    SourceRestored,
    Held,
    Complete,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupMember {
    service: String,
    container_id: String,
    running: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupCustody {
    schema_version: u8,
    operation: String,
    job_id: String,
    project: String,
    install_receipt_sha256: String,
    volume_set_id: String,
    volume_set_snapshot_sha256: String,
    phase: BackupPhase,
    members: Vec<BackupMember>,
    archives: Vec<PaperlessBackupArchive>,
    install_receipt_bytes: Vec<u8>,
    volume_set_snapshot_bytes: Vec<u8>,
    #[serde(default)]
    pending_start: Option<String>,
    #[serde(default)]
    restore_binding: Option<RestoreConfigBinding>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupSource {
    schema_version: u8,
    operation: String,
    job_id: String,
    install_receipt_bytes: Vec<u8>,
    volume_set_snapshot_bytes: Vec<u8>,
    #[serde(default)]
    restore_binding: Option<RestoreConfigBinding>,
}
/// Stable non-secret compatibility binding needed to restore a historical
/// Paperless archive into the currently configured instance.  Values are
/// domain-separated fingerprints; no configuration secret or API token is
/// retained in backup custody.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RestoreConfigBinding {
    pub(crate) compose_contract_id: String,
    pub(crate) environment_fingerprint: String,
    pub(crate) token_fingerprint: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PaperlessHistoricalBackup {
    pub(crate) job_id: String,
    pub(crate) project: String,
    pub(crate) volume_set_id: String,
    pub(crate) install_receipt_bytes: Vec<u8>,
    pub(crate) volume_set_snapshot_bytes: Vec<u8>,
    pub(crate) archives: Vec<PaperlessBackupArchive>,
    pub(crate) restore_binding: RestoreConfigBinding,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PaperlessBackupArchive {
    pub(crate) logical_name: String,
    pub(crate) service: String,
    pub(crate) container_id: String,
    pub(crate) image_id: String,
    pub(crate) mounted_source: String,
    pub(crate) archive_path: String,
    pub(crate) bytes: u64,
    pub(crate) sha256: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PaperlessBackupState {
    pub(crate) service: String,
    pub(crate) running: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PaperlessBackupReceipt {
    pub(crate) schema_version: u8,
    pub(crate) operation: String,
    pub(crate) job_id: String,
    pub(crate) contract_id: String,
    pub(crate) project: String,
    pub(crate) install_receipt_sha256: String,
    pub(crate) volume_set_id: String,
    pub(crate) volume_set_snapshot_sha256: String,
    pub(crate) archives: Vec<PaperlessBackupArchive>,
    pub(crate) original_running: Vec<PaperlessBackupState>,
    pub(crate) restored_running: Vec<PaperlessBackupState>,
    pub(crate) authenticated_api_ready: bool,
}

pub(crate) async fn backup_at(
    home: &Path,
    credentials: &Credentials,
) -> Result<PaperlessBackupReceipt, LifecycleError> {
    backup_at_with(home, credentials, &mut DockerExecutor, &ConfiguredReadiness).await
}
pub(super) async fn backup_at_with<E: ComposeExecutor, R: ReadinessVerifier>(
    home: &Path,
    credentials: &Credentials,
    executor: &mut E,
    readiness: &R,
) -> Result<PaperlessBackupReceipt, LifecycleError> {
    let root_path = crate::config::InstancePaths::for_home(home).paperless_root;
    let owned = paperless_staging::open_owned_root_at(&root_path)
        .map_err(|_| LifecycleError::UnownedOrMismatch)?;
    let mut binding = read_binding(&owned)?;
    reject_legacy_state(&owned)?;
    compose_environment(&binding)?;
    validate_credentials_origin(credentials, &binding.origin)?;
    let restore_binding = restore_config_binding(&binding, credentials)?;
    let _launch = acquire_launch_guard(&owned, &binding)?;
    let _lock = paperless_operation_lock::acquire(&owned, OsStr::new(OPERATIONS_LOCK_NAME))
        .map_err(map_operation_lock_error)?;
    if paperless_restore::blocks_peer_operation(&owned)? {
        return Err(LifecycleError::Command("paperless_restore_in_progress"));
    }
    refuse_peer_custody(&owned)?;
    let (install_bytes, install) = read_install_receipt_with_bytes(&owned)?;
    validate_install_receipt(&install, &root_path)?;
    let volume_set_id = install
        .volume_set_id
        .clone()
        .ok_or(LifecycleError::Receipt)?;
    let snapshot_bytes = read_state_bytes(&owned, VOLUME_SET_NAME)?;
    let snapshot: PaperlessVolumeSetSnapshot =
        serde_json::from_slice(&snapshot_bytes).map_err(|_| LifecycleError::Receipt)?;
    validate_volume_set_snapshot(&snapshot, &install.project)?;
    if snapshot.volume_set_id != volume_set_id {
        return Err(LifecycleError::UnownedOrMismatch);
    }
    binding.volume_set_id = Some(volume_set_id.clone());
    let engine = select_local_engine(executor, &owned).await?;
    if preflight_existing_volumes(executor, &engine, &install.project, &owned, &binding)
        .await?
        .as_deref()
        != Some(volume_set_id.as_str())
    {
        return Err(LifecycleError::UnownedOrMismatch);
    }
    let mut custody = match read_custody(&owned)? {
        Some(mut c) => {
            if c.phase == BackupPhase::Complete {
                validate_historical_custody(&owned, &c)?;
            } else {
                validate_custody(&c, &install, &install_bytes, &snapshot_bytes)?;
                if ensure_source_companion(&owned, &c).is_err() {
                    if c.phase == BackupPhase::Held {
                        return Err(LifecycleError::Receipt);
                    }
                    return restore_then_hold(
                        executor,
                        &engine,
                        &owned,
                        &binding,
                        &install,
                        &mut c,
                        "paperless_backup_source_companion_invalid",
                    )
                    .await;
                }
            }
            c
        }
        None => {
            let members = inspect_members(executor, &engine, &owned, &binding, &install).await?;
            let nonce = uuid::Uuid::new_v4();
            let c = BackupCustody {
                schema_version: 1,
                operation: "paperless.backup".into(),
                job_id: format!("paperless-backup-{}", digest(nonce.as_bytes())),
                project: install.project.clone(),
                install_receipt_sha256: digest(&install_bytes),
                volume_set_id: volume_set_id.clone(),
                volume_set_snapshot_sha256: digest(&snapshot_bytes),
                phase: BackupPhase::Prepared,
                members,
                archives: Vec::new(),
                pending_start: None,
                restore_binding: Some(restore_binding.clone()),
                install_receipt_bytes: install_bytes.clone(),
                volume_set_snapshot_bytes: snapshot_bytes.clone(),
            };
            write_custody_new(&owned, &c)?;
            ensure_source_companion(&owned, &c)?;
            c
        }
    };
    // Every retained archive is an admission input on re-entry.  Never skip a
    // logical volume based only on JSON metadata.
    if verify_custody_archives_on_disk(&owned, &custody).is_err() {
        if matches!(custody.phase, BackupPhase::Complete | BackupPhase::Held) {
            return Err(LifecycleError::Receipt);
        }
        return restore_then_hold(
            executor,
            &engine,
            &owned,
            &binding,
            &install,
            &mut custody,
            "paperless_backup_retained_archive_invalid",
        )
        .await;
    }
    // A completed backup is historical evidence only. It never turns the
    // backup command into a cached selector; the next deliberate invocation
    // receives a fresh custody/job directory.
    if custody.phase == BackupPhase::Complete {
        let historical = validate_historical_custody(&owned, &custody)?;
        let receipt = read_receipt(
            &owned,
            &custody,
            &historical.install,
            &historical.source.install_receipt_bytes,
            &historical.source.volume_set_snapshot_bytes,
        )?;
        verify_archives_on_disk(&owned, &receipt)?;
        // A completed receipt records historical source state. The operator
        // may have deliberately stopped services before requesting a new copy.
        let members = inspect_members(executor, &engine, &owned, &binding, &install).await?;
        let nonce = uuid::Uuid::new_v4();
        let next = BackupCustody {
            schema_version: 1,
            operation: "paperless.backup".into(),
            job_id: format!("paperless-backup-{}", digest(nonce.as_bytes())),
            project: install.project.clone(),
            install_receipt_sha256: digest(&install_bytes),
            volume_set_id: volume_set_id.clone(),
            volume_set_snapshot_sha256: digest(&snapshot_bytes),
            phase: BackupPhase::Prepared,
            members,
            archives: Vec::new(),
            pending_start: None,
            restore_binding: Some(restore_binding),
            install_receipt_bytes: install_bytes.clone(),
            volume_set_snapshot_bytes: snapshot_bytes.clone(),
        };
        write_custody(&owned, &next)?;
        ensure_source_companion(&owned, &next)?;
        custody = next;
    }
    if matches!(
        custody.phase,
        BackupPhase::ArchiveVerified
            | BackupPhase::StartDispatched
            | BackupPhase::SourceRestored
            | BackupPhase::Held
    ) && custody.archives.len() == paperless_staging::PAPERLESS_VOLUMES.len()
        && receipt_exists(&owned, &custody)?
    {
        let receipt = read_receipt(&owned, &custody, &install, &install_bytes, &snapshot_bytes)?;
        verify_archives_on_disk(&owned, &receipt)?;
        verify_members_with_state(
            executor,
            &engine,
            &owned,
            &binding,
            &install,
            &custody.members,
            true,
        )
        .await?;
        if receipt.authenticated_api_ready {
            let mut c = credentials.clone();
            c.paperless_url = Some(binding.origin.clone());
            if wait_for_readiness(home, &c, readiness, &owned, &binding)
                .await
                .is_err()
            {
                return hold(
                    &owned,
                    &mut custody,
                    "paperless_backup_completed_readiness_failed",
                );
            }
        }
        custody.pending_start = None;
        custody.phase = BackupPhase::Complete;
        write_custody(&owned, &custody)?;
        return Ok(receipt);
    }
    if matches!(
        custody.phase,
        BackupPhase::CopyDispatched | BackupPhase::StopDispatched | BackupPhase::StartDispatched
    ) {
        return restore_then_hold(
            executor,
            &engine,
            &owned,
            &binding,
            &install,
            &mut custody,
            "paperless_backup_effect_outcome_ambiguous",
        )
        .await;
    }
    if custody.phase == BackupPhase::Held {
        return Err(LifecycleError::Command("paperless_backup_held"));
    }
    if custody.phase == BackupPhase::Prepared {
        // Fence every original container immediately before the stop series.
        verify_members_with_state(
            executor,
            &engine,
            &owned,
            &binding,
            &install,
            &custody.members,
            true,
        )
        .await?;
        for service in ["webserver", "broker", "db"] {
            let member = custody
                .members
                .iter()
                .find(|m| m.service == service)
                .cloned()
                .ok_or(LifecycleError::Receipt)?;
            if !member.running {
                continue;
            }
            if revalidate_effect_binding(
                executor,
                &engine,
                &owned,
                &binding,
                &install,
                &install_bytes,
                &snapshot_bytes,
                &custody,
            )
            .await
            .is_err()
            {
                return restore_then_hold(
                    executor,
                    &engine,
                    &owned,
                    &binding,
                    &install,
                    &mut custody,
                    "paperless_backup_stop_rebind_failed",
                )
                .await;
            }
            custody.phase = BackupPhase::StopDispatched;
            if write_custody(&owned, &custody).is_err() {
                return restore_then_hold(
                    executor,
                    &engine,
                    &owned,
                    &binding,
                    &install,
                    &mut custody,
                    "paperless_backup_custody_persist_failed",
                )
                .await;
            }
            let result = executor
                .run(
                    &engine.docker("container", &["stop", &member.container_id]),
                    &owned.display,
                )
                .await;
            if result.is_err() {
                return restore_then_fail(
                    executor,
                    &engine,
                    &owned,
                    &binding,
                    &install,
                    &mut custody,
                )
                .await;
            }
            let stopped = inspect_members(executor, &engine, &owned, &binding, &install).await;
            if !stopped.is_ok_and(|members| {
                members.iter().any(|observed| {
                    observed.service == member.service
                        && observed.container_id == member.container_id
                        && !observed.running
                })
            }) {
                return restore_then_hold(
                    executor,
                    &engine,
                    &owned,
                    &binding,
                    &install,
                    &mut custody,
                    "paperless_backup_stop_state_unknown",
                )
                .await;
            }
        }
        custody.phase = BackupPhase::Stopped;
        if write_custody(&owned, &custody).is_err() {
            return restore_then_hold(
                executor,
                &engine,
                &owned,
                &binding,
                &install,
                &mut custody,
                "paperless_backup_custody_persist_failed",
            )
            .await;
        }
    }
    if custody.phase != BackupPhase::SourceRestored {
        if assert_all_stopped(executor, &engine, &owned, &binding, &install)
            .await
            .is_err()
        {
            return restore_then_hold(
                executor,
                &engine,
                &owned,
                &binding,
                &install,
                &mut custody,
                "paperless_backup_source_not_stopped",
            )
            .await;
        }
        for volume in paperless_staging::PAPERLESS_VOLUMES {
            if custody
                .archives
                .iter()
                .any(|a| a.logical_name == volume.logical_name)
            {
                continue;
            }
            let Some(member) = custody
                .members
                .iter()
                .find(|m| m.service == volume.service)
                .cloned()
            else {
                return restore_then_hold(
                    executor,
                    &engine,
                    &owned,
                    &binding,
                    &install,
                    &mut custody,
                    "paperless_backup_member_binding_failed",
                )
                .await;
            };
            if revalidate_effect_binding(
                executor,
                &engine,
                &owned,
                &binding,
                &install,
                &install_bytes,
                &snapshot_bytes,
                &custody,
            )
            .await
            .is_err()
                || assert_all_stopped(executor, &engine, &owned, &binding, &install)
                    .await
                    .is_err()
            {
                return restore_then_hold(
                    executor,
                    &engine,
                    &owned,
                    &binding,
                    &install,
                    &mut custody,
                    "paperless_backup_copy_rebind_failed",
                )
                .await;
            }
            custody.phase = BackupPhase::CopyDispatched;
            if write_custody(&owned, &custody).is_err() {
                return restore_then_hold(
                    executor,
                    &engine,
                    &owned,
                    &binding,
                    &install,
                    &mut custody,
                    "paperless_backup_custody_persist_failed",
                )
                .await;
            }
            let relative = format!(
                "state/{BACKUP_DIR}/{}/{}.tar",
                custody.job_id, volume.logical_name
            );
            if ensure_archive_parent(&owned, &custody.job_id).is_err() {
                return restore_then_hold(
                    executor,
                    &engine,
                    &owned,
                    &binding,
                    &install,
                    &mut custody,
                    "paperless_backup_archive_parent_failed",
                )
                .await;
            }
            let pending_name = format!("{}.tar.pending", volume.logical_name);
            let pending = match create_pending_archive(&owned, &custody.job_id, &pending_name) {
                Ok(file) => file,
                Err(_) => {
                    return restore_then_hold(
                        executor,
                        &engine,
                        &owned,
                        &binding,
                        &install,
                        &mut custody,
                        "paperless_backup_archive_reservation_failed",
                    )
                    .await;
                }
            };
            let remaining = BACKUP_TOTAL_LIMIT
                .saturating_sub(custody.archives.iter().map(|a| a.bytes).sum::<u64>());
            let stream = executor
                .run_stream_to_file(
                    &engine.docker(
                        "container",
                        &[
                            "cp",
                            &format!("{}:{}", member.container_id, volume.destination),
                            "-",
                        ],
                    ),
                    &owned.display,
                    pending,
                    BACKUP_ARCHIVE_LIMIT.min(remaining),
                )
                .await;
            let stream = match stream {
                Ok(v) => v,
                Err(_) => {
                    return restore_then_hold(
                        executor,
                        &engine,
                        &owned,
                        &binding,
                        &install,
                        &mut custody,
                        "paperless_backup_copy_outcome_ambiguous",
                    )
                    .await;
                }
            };
            if stream.bytes == 0
                || custody
                    .archives
                    .iter()
                    .map(|a| a.bytes)
                    .sum::<u64>()
                    .saturating_add(stream.bytes)
                    > BACKUP_TOTAL_LIMIT
            {
                return restore_then_hold(
                    executor,
                    &engine,
                    &owned,
                    &binding,
                    &install,
                    &mut custody,
                    "paperless_backup_stream_limit",
                )
                .await;
            }
            let (readback_bytes, readback_sha256) = match digest_archive_readback_cap(
                &owned,
                &custody.job_id,
                &pending_name,
                BACKUP_ARCHIVE_LIMIT,
            ) {
                Ok(value) => value,
                Err(_) => {
                    return restore_then_hold(
                        executor,
                        &engine,
                        &owned,
                        &binding,
                        &install,
                        &mut custody,
                        "paperless_backup_archive_readback_failed",
                    )
                    .await;
                }
            };
            if readback_bytes != stream.bytes || readback_sha256 != stream.sha256 {
                return restore_then_hold(
                    executor,
                    &engine,
                    &owned,
                    &binding,
                    &install,
                    &mut custody,
                    "paperless_backup_archive_readback_mismatch",
                )
                .await;
            }
            if publish_pending_archive(
                &owned,
                &custody.job_id,
                &pending_name,
                &format!("{}.tar", volume.logical_name),
            )
            .is_err()
            {
                return restore_then_hold(
                    executor,
                    &engine,
                    &owned,
                    &binding,
                    &install,
                    &mut custody,
                    "paperless_backup_archive_publish_failed",
                )
                .await;
            }
            let Some(image) = install
                .containers
                .iter()
                .find(|c| c.service == volume.service)
            else {
                return restore_then_hold(
                    executor,
                    &engine,
                    &owned,
                    &binding,
                    &install,
                    &mut custody,
                    "paperless_backup_image_binding_failed",
                )
                .await;
            };
            let image_id = image.image_id.clone();
            custody.archives.push(PaperlessBackupArchive {
                logical_name: volume.logical_name.into(),
                service: volume.service.into(),
                container_id: member.container_id.clone(),
                image_id,
                mounted_source: volume.destination.into(),
                archive_path: relative,
                bytes: stream.bytes,
                sha256: stream.sha256,
            });
            custody.phase = BackupPhase::ArchiveVerified;
            if write_custody(&owned, &custody).is_err() {
                return restore_then_hold(
                    executor,
                    &engine,
                    &owned,
                    &binding,
                    &install,
                    &mut custody,
                    "paperless_backup_custody_persist_failed",
                )
                .await;
            }
        }
    }
    if restore_all(executor, &engine, &owned, &binding, &install, &mut custody)
        .await
        .is_err()
    {
        return restore_then_hold(
            executor,
            &engine,
            &owned,
            &binding,
            &install,
            &mut custody,
            "paperless_backup_restore_outcome_ambiguous",
        )
        .await;
    }
    if custody.archives.len() != paperless_staging::PAPERLESS_VOLUMES.len() {
        return hold(&owned, &mut custody, "paperless_backup_incomplete_archives");
    }
    if custody.members.iter().all(|m| m.running) {
        let mut c = credentials.clone();
        c.paperless_url = Some(binding.origin.clone());
        if wait_for_readiness(home, &c, readiness, &owned, &binding)
            .await
            .is_err()
        {
            return hold(&owned, &mut custody, "paperless_backup_readiness_failed");
        }
    }
    if verify_members_with_state(
        executor,
        &engine,
        &owned,
        &binding,
        &install,
        &custody.members,
        true,
    )
    .await
    .is_err()
    {
        return hold(
            &owned,
            &mut custody,
            "paperless_backup_restored_state_mismatch",
        );
    }
    let fully_running = custody.members.iter().all(|m| m.running);
    let receipt = PaperlessBackupReceipt {
        schema_version: 1,
        operation: "paperless.backup".into(),
        job_id: custody.job_id.clone(),
        contract_id: paperless_staging::OCI_CONTRACT_ID.into(),
        project: custody.project.clone(),
        install_receipt_sha256: custody.install_receipt_sha256.clone(),
        volume_set_id: custody.volume_set_id.clone(),
        volume_set_snapshot_sha256: custody.volume_set_snapshot_sha256.clone(),
        archives: custody.archives.clone(),
        original_running: custody
            .members
            .iter()
            .map(|m| PaperlessBackupState {
                service: m.service.clone(),
                running: m.running,
            })
            .collect(),
        restored_running: custody
            .members
            .iter()
            .map(|m| PaperlessBackupState {
                service: m.service.clone(),
                running: m.running,
            })
            .collect(),
        authenticated_api_ready: fully_running,
    };
    ensure_source_companion(&owned, &custody)?;
    if write_receipt_new(&owned, &receipt).is_err() {
        return hold(
            &owned,
            &mut custody,
            "paperless_backup_receipt_commit_failed",
        );
    }
    custody.phase = BackupPhase::Complete;
    if write_custody(&owned, &custody).is_err() {
        // The immutable receipt is already the source of truth. Re-entry
        // validates it and finalizes this sidecar without recopying.
        return Err(LifecycleError::Command(
            "paperless_backup_receipt_committed_custody_pending",
        ));
    }
    Ok(receipt)
}

fn refuse_peer_custody(root: &OwnedPaperlessRoot) -> Result<(), LifecycleError> {
    for name in [
        UNINSTALL_RECEIPT_NAME,
        paperless_purge::PURGE_CUSTODY_NAME,
        paperless_purge::PURGE_RECEIPT_NAME,
    ] {
        if read_optional(root, name)?.is_some() {
            return Err(LifecycleError::Command(
                "paperless_backup_peer_custody_present",
            ));
        }
    }
    if read_optional(root, ".neoth-paperless-repair.v1.json")?.is_some()
        && !paperless_repair::completed_repair_journal_is_valid(root)?
    {
        return Err(LifecycleError::Command(
            "paperless_backup_peer_custody_present",
        ));
    }
    Ok(())
}
/// Resolve exactly one immutable completed backup. Restore callers must use
/// this instead of mutable latest custody: a newer backup cannot substitute
/// the operator-selected job.
pub(crate) fn resolve_completed_backup_at(
    root: &OwnedPaperlessRoot,
    job_id: &str,
) -> Result<PaperlessHistoricalBackup, LifecycleError> {
    if !canonical_backup_job_id(job_id) {
        return Err(LifecycleError::Command("paperless_restore_backup_job_invalid"));
    }
    ensure_bound(root)?;
    let dir = backup_job_dir(root, job_id)?;
    let source_path = root.display.join("state").join(BACKUP_DIR).join(job_id).join(BACKUP_SOURCE_NAME);
    let source_bytes = crate::skills::store::read_regular_file_bounded(
        &dir, OsStr::new(BACKUP_SOURCE_NAME), &source_path, RECEIPT_READ_LIMIT,
    ).map_err(|_| LifecycleError::Receipt)?;
    let source: BackupSource = serde_json::from_slice(&source_bytes).map_err(|_| LifecycleError::Receipt)?;
    let Some(restore_binding) = source.restore_binding.clone() else {
        return Err(LifecycleError::Command("paperless_restore_historical_config_unsupported"));
    };
    if source.schema_version != 2
        || source.operation != "paperless.backup.source"
        || source.job_id != job_id
        || !valid_restore_binding(&restore_binding)
    {
        return Err(LifecycleError::Receipt);
    }
    let install: StoredPaperlessInstallReceipt = serde_json::from_slice(&source.install_receipt_bytes)
        .map_err(|_| LifecycleError::Receipt)?;
    validate_install_receipt(&install, &root.display)?;
    let snapshot: PaperlessVolumeSetSnapshot = serde_json::from_slice(&source.volume_set_snapshot_bytes)
        .map_err(|_| LifecycleError::Receipt)?;
    validate_volume_set_snapshot(&snapshot, &install.project)?;
    if install.volume_set_id.as_deref() != Some(snapshot.volume_set_id.as_str()) {
        return Err(LifecycleError::Receipt);
    }
    let receipt_path = root.display.join("state").join(BACKUP_DIR).join(job_id).join("receipt.v1.json");
    let receipt_bytes = crate::skills::store::read_regular_file_bounded(
        &dir, OsStr::new("receipt.v1.json"), &receipt_path, RECEIPT_READ_LIMIT,
    ).map_err(|_| LifecycleError::Receipt)?;
    let receipt: PaperlessBackupReceipt = serde_json::from_slice(&receipt_bytes)
        .map_err(|_| LifecycleError::Receipt)?;
    let custody = historical_custody_from_receipt(&source, &install, &snapshot, &receipt)?;
    validate_receipt(&receipt, &custody, &install, &source.install_receipt_bytes, &source.volume_set_snapshot_bytes)?;
    verify_archives_on_disk(root, &receipt)?;
    Ok(PaperlessHistoricalBackup {
        job_id: receipt.job_id,
        project: receipt.project,
        volume_set_id: receipt.volume_set_id,
        install_receipt_bytes: source.install_receipt_bytes,
        volume_set_snapshot_bytes: source.volume_set_snapshot_bytes,
        archives: receipt.archives,
        restore_binding,
    })
}

/// Re-open one resolver-validated archive by its fixed logical member name.
/// The returned handle is re-hashed after opening and rewound before Docker
/// receives it, closing the check/use substitution window without exposing a
/// filesystem path to Restore.
pub(crate) fn open_archive_for_restore(
    root: &OwnedPaperlessRoot,
    historical: &PaperlessHistoricalBackup,
    archive: &PaperlessBackupArchive,
) -> Result<std::fs::File, LifecycleError> {
    if archive.archive_path != format!("state/{BACKUP_DIR}/{}/{}.tar", historical.job_id, archive.logical_name)
        || !historical.archives.iter().any(|known| known == archive)
    {
        return Err(LifecycleError::Receipt);
    }
    let dir = backup_job_dir(root, &historical.job_id)?;
    let name = format!("{}.tar", archive.logical_name);
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = dir.open_with(OsStr::new(&name), &options).map_err(|_| LifecycleError::Io)?;
    let metadata = file.metadata().map_err(|_| LifecycleError::Io)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(LifecycleError::Receipt);
    }
    let mut file = file.into_std();
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|_| LifecycleError::Io)?;
        if read == 0 { break; }
        total = total.checked_add(read as u64).ok_or(LifecycleError::Receipt)?;
        if total > BACKUP_ARCHIVE_LIMIT { return Err(LifecycleError::Receipt); }
        hasher.update(&buffer[..read]);
    }
    if total != archive.bytes || format!("{:x}", hasher.finalize()) != archive.sha256 {
        return Err(LifecycleError::Receipt);
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| LifecycleError::Io)?;
    Ok(file)
}

fn canonical_backup_job_id(value: &str) -> bool {
    value.len() == "paperless-backup-".len() + 64
        && value.starts_with("paperless-backup-")
        && value["paperless-backup-".len()..].bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn valid_restore_binding(binding: &RestoreConfigBinding) -> bool {
    binding.compose_contract_id == paperless_staging::OCI_CONTRACT_ID
        && [binding.environment_fingerprint.as_str(), binding.token_fingerprint.as_str()]
            .into_iter()
            .all(|value| value.len() == 64 && value.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')))
}

fn historical_custody_from_receipt(
    source: &BackupSource,
    install: &StoredPaperlessInstallReceipt,
    snapshot: &PaperlessVolumeSetSnapshot,
    receipt: &PaperlessBackupReceipt,
) -> Result<BackupCustody, LifecycleError> {
    if receipt.original_running.len() != install.containers.len() {
        return Err(LifecycleError::Receipt);
    }
    let mut members = Vec::with_capacity(install.containers.len());
    for container in &install.containers {
        let running = receipt.original_running.iter().find(|state| state.service == container.service)
            .ok_or(LifecycleError::Receipt)?;
        members.push(BackupMember { service: container.service.clone(), container_id: container.id.clone(), running: running.running });
    }
    Ok(BackupCustody {
        schema_version: 1,
        operation: "paperless.backup".to_owned(),
        job_id: source.job_id.clone(),
        project: install.project.clone(),
        install_receipt_sha256: digest(&source.install_receipt_bytes),
        volume_set_id: snapshot.volume_set_id.clone(),
        volume_set_snapshot_sha256: digest(&source.volume_set_snapshot_bytes),
        phase: BackupPhase::Complete,
        members,
        archives: receipt.archives.clone(),
        install_receipt_bytes: source.install_receipt_bytes.clone(),
        volume_set_snapshot_bytes: source.volume_set_snapshot_bytes.clone(),
        pending_start: None,
        restore_binding: source.restore_binding.clone(),
    })
}

fn read_optional(root: &OwnedPaperlessRoot, name: &str) -> Result<Option<Vec<u8>>, LifecycleError> {
    let state = lifecycle_state_dir(root)?;
    match crate::skills::store::read_regular_file_bounded(
        &state,
        OsStr::new(name),
        &root.display.join("state").join(name),
        RECEIPT_READ_LIMIT,
    ) {
        Ok(v) => Ok(Some(v)),
        Err(e)
            if e.root_cause()
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(_) => Err(LifecycleError::Receipt),
    }
}
fn read_state_bytes(root: &OwnedPaperlessRoot, name: &str) -> Result<Vec<u8>, LifecycleError> {
    crate::skills::store::read_regular_file_bounded(
        &lifecycle_state_dir(root)?,
        OsStr::new(name),
        &root.display.join("state").join(name),
        RECEIPT_READ_LIMIT,
    )
    .map_err(|_| LifecycleError::Receipt)
}
fn read_custody(root: &OwnedPaperlessRoot) -> Result<Option<BackupCustody>, LifecycleError> {
    match read_optional(root, BACKUP_CUSTODY_NAME)? {
        Some(v) => serde_json::from_slice(&v)
            .map(Some)
            .map_err(|_| LifecycleError::Receipt),
        None => Ok(None),
    }
}
pub(super) fn blocks_peer_operation(root: &OwnedPaperlessRoot) -> Result<bool, LifecycleError> {
    let Some(custody) = read_custody(root)? else {
        return Ok(false);
    };
    if custody.phase != BackupPhase::Complete {
        return Ok(true);
    }
    let historical = validate_historical_custody(root, &custody)?;
    // Peers need proof that this transaction restored its source and finished.
    // They never restore from these archives; damaged historical backup media
    // must not prevent source repair. Backup itself rehashes all prior archives.
    read_receipt(
        root,
        &custody,
        &historical.install,
        &historical.source.install_receipt_bytes,
        &historical.source.volume_set_snapshot_bytes,
    )?;
    Ok(false)
}
struct HistoricalBackupSource {
    install: StoredPaperlessInstallReceipt,
    source: BackupSource,
}
fn validate_historical_custody(
    root: &OwnedPaperlessRoot,
    custody: &BackupCustody,
) -> Result<HistoricalBackupSource, LifecycleError> {
    let source = read_source_companion(root, custody)?;
    let install: StoredPaperlessInstallReceipt =
        serde_json::from_slice(&source.install_receipt_bytes)
            .map_err(|_| LifecycleError::Receipt)?;
    validate_install_receipt(&install, &root.display)?;
    let snapshot: PaperlessVolumeSetSnapshot =
        serde_json::from_slice(&source.volume_set_snapshot_bytes)
            .map_err(|_| LifecycleError::Receipt)?;
    validate_volume_set_snapshot(&snapshot, &install.project)?;
    if snapshot.volume_set_id != custody.volume_set_id {
        return Err(LifecycleError::Receipt);
    }
    validate_custody(
        custody,
        &install,
        &source.install_receipt_bytes,
        &source.volume_set_snapshot_bytes,
    )?;
    Ok(HistoricalBackupSource { install, source })
}
fn validate_custody(
    c: &BackupCustody,
    install: &StoredPaperlessInstallReceipt,
    install_bytes: &[u8],
    snapshot: &[u8],
) -> Result<(), LifecycleError> {
    if c.install_receipt_bytes != install_bytes
        || c.volume_set_snapshot_bytes != snapshot
        || c.pending_start
            .as_ref()
            .is_some_and(|service| !c.members.iter().any(|m| &m.service == service && m.running))
        || c.archives
            .iter()
            .any(|archive| archive.bytes > BACKUP_ARCHIVE_LIMIT)
        || c.archives
            .iter()
            .try_fold(0u64, |sum, archive| sum.checked_add(archive.bytes))
            .is_none_or(|sum| sum > BACKUP_TOTAL_LIMIT)
    {
        return Err(LifecycleError::Receipt);
    }
    if c.schema_version != 1
        || c.operation != "paperless.backup"
        || c.project != install.project
        || c.install_receipt_sha256 != digest(install_bytes)
        || c.volume_set_id
            != install
                .volume_set_id
                .clone()
                .ok_or(LifecycleError::Receipt)?
        || c.volume_set_snapshot_sha256 != digest(snapshot)
        || !c.job_id.starts_with("paperless-backup-")
        || c.job_id.len() != "paperless-backup-".len() + 64
        || !c.job_id["paperless-backup-".len()..]
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        || c.members.len() != 3
        || c.archives.len() > 6
    {
        return Err(LifecycleError::Receipt);
    }
    let mut services = std::collections::BTreeSet::new();
    for member in &c.members {
        if !services.insert(member.service.as_str())
            || !install.containers.iter().any(|expected| {
                expected.service == member.service && expected.id == member.container_id
            })
        {
            return Err(LifecycleError::Receipt);
        }
    }
    let mut names = std::collections::BTreeSet::new();
    for archive in &c.archives {
        let expected = paperless_staging::PAPERLESS_VOLUMES
            .iter()
            .find(|v| v.logical_name == archive.logical_name)
            .ok_or(LifecycleError::Receipt)?;
        let member = c
            .members
            .iter()
            .find(|m| m.service == archive.service)
            .ok_or(LifecycleError::Receipt)?;
        let image = install
            .containers
            .iter()
            .find(|v| v.service == archive.service)
            .ok_or(LifecycleError::Receipt)?;
        if !names.insert(&archive.logical_name)
            || archive.service != expected.service
            || archive.container_id != member.container_id
            || archive.image_id != image.image_id
            || archive.mounted_source != expected.destination
            || archive.bytes == 0
            || archive.sha256.len() != 64
            || !archive
                .sha256
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            || archive.archive_path
                != format!(
                    "state/{BACKUP_DIR}/{}/{}.tar",
                    c.job_id, archive.logical_name
                )
        {
            return Err(LifecycleError::Receipt);
        }
    }
    match c.phase {
        BackupPhase::Prepared | BackupPhase::StopDispatched | BackupPhase::Stopped => {
            if !c.archives.is_empty() {
                return Err(LifecycleError::Receipt);
            }
        }
        BackupPhase::Complete => {
            if c.archives.len() != 6 || c.pending_start.is_some() {
                return Err(LifecycleError::Receipt);
            }
        }
        BackupPhase::ArchiveVerified
        | BackupPhase::StartDispatched
        | BackupPhase::CopyDispatched
        | BackupPhase::Held => {}
        BackupPhase::SourceRestored => {
            if c.pending_start.is_some() {
                return Err(LifecycleError::Receipt);
            }
        }
    }
    Ok(())
}
fn write_custody_new(root: &OwnedPaperlessRoot, c: &BackupCustody) -> Result<(), LifecycleError> {
    write_json_new(root, BACKUP_CUSTODY_NAME, c)
}
fn receipt_exists(
    root: &OwnedPaperlessRoot,
    custody: &BackupCustody,
) -> Result<bool, LifecycleError> {
    let dir = backup_job_dir(root, &custody.job_id)?;
    match dir.symlink_metadata("receipt.v1.json") {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(LifecycleError::Receipt),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(LifecycleError::Receipt),
    }
}
fn source_companion_exists(
    root: &OwnedPaperlessRoot,
    custody: &BackupCustody,
) -> Result<bool, LifecycleError> {
    let dir = backup_job_dir(root, &custody.job_id)?;
    match dir.symlink_metadata(BACKUP_SOURCE_NAME) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(LifecycleError::Receipt),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(LifecycleError::Receipt),
    }
}
fn read_source_companion(
    root: &OwnedPaperlessRoot,
    custody: &BackupCustody,
) -> Result<BackupSource, LifecycleError> {
    let dir = backup_job_dir(root, &custody.job_id)?;
    let path = root
        .display
        .join("state")
        .join(BACKUP_DIR)
        .join(&custody.job_id)
        .join(BACKUP_SOURCE_NAME);
    let bytes = crate::skills::store::read_regular_file_bounded(
        &dir,
        OsStr::new(BACKUP_SOURCE_NAME),
        &path,
        RECEIPT_READ_LIMIT,
    )
    .map_err(|_| LifecycleError::Receipt)?;
    let source: BackupSource =
        serde_json::from_slice(&bytes).map_err(|_| LifecycleError::Receipt)?;
    if !matches!(source.schema_version, 1 | 2)
        || source.operation != "paperless.backup.source"
        || source.job_id != custody.job_id
        || source.install_receipt_bytes != custody.install_receipt_bytes
        || source.volume_set_snapshot_bytes != custody.volume_set_snapshot_bytes
        || source.restore_binding != custody.restore_binding
        || (source.schema_version == 1 && source.restore_binding.is_some())
        || (source.schema_version == 2 && source.restore_binding.is_none())
    {
        return Err(LifecycleError::Receipt);
    }
    Ok(source)
}
fn write_source_companion_new(
    root: &OwnedPaperlessRoot,
    custody: &BackupCustody,
) -> Result<(), LifecycleError> {
    let source = BackupSource {
        // An interrupted legacy v1 custody may still need its absent source
        // companion reconstructed.  Do not manufacture an invalid v2 record
        // with a null binding: v2 means the binding is present and verified.
        schema_version: if custody.restore_binding.is_some() { 2 } else { 1 },
        operation: "paperless.backup.source".into(),
        job_id: custody.job_id.clone(),
        install_receipt_bytes: custody.install_receipt_bytes.clone(),
        volume_set_snapshot_bytes: custody.volume_set_snapshot_bytes.clone(),
        restore_binding: custody.restore_binding.clone(),
    };
    let bytes = serde_json::to_vec(&source).map_err(|_| LifecycleError::Io)?;
    if bytes.len() > RECEIPT_READ_LIMIT {
        return Err(LifecycleError::Receipt);
    }
    let dir = backup_job_dir(root, &custody.job_id)?;
    crate::skills::store::atomic_write_private_child_create_new(
        &dir,
        OsStr::new(BACKUP_SOURCE_NAME),
        &root
            .display
            .join("state")
            .join(BACKUP_DIR)
            .join(&custody.job_id)
            .join(BACKUP_SOURCE_NAME),
        &bytes,
    )
    .map_err(|_| LifecycleError::Io)?;
    ensure_bound(root)
}
fn ensure_source_companion(
    root: &OwnedPaperlessRoot,
    custody: &BackupCustody,
) -> Result<(), LifecycleError> {
    ensure_archive_parent(root, &custody.job_id)?;
    if source_companion_exists(root, custody)? {
        read_source_companion(root, custody)?;
        return Ok(());
    }
    // A final receipt cannot retroactively manufacture its missing source.
    if receipt_exists(root, custody)? {
        return Err(LifecycleError::Receipt);
    }
    if write_source_companion_new(root, custody).is_err() {
        // A create-new result can be uncertain. Only an exact existing
        // companion makes retry safe; it is never replaced.
        read_source_companion(root, custody)?;
    }
    Ok(())
}
fn write_custody(root: &OwnedPaperlessRoot, c: &BackupCustody) -> Result<(), LifecycleError> {
    write_json(root, BACKUP_CUSTODY_NAME, c)
}
fn write_json_new<T: Serialize>(
    root: &OwnedPaperlessRoot,
    name: &str,
    value: &T,
) -> Result<(), LifecycleError> {
    let b = serde_json::to_vec(value).map_err(|_| LifecycleError::Io)?;
    crate::skills::store::atomic_write_private_child_create_new(
        &lifecycle_state_dir(root)?,
        OsStr::new(name),
        &root.display.join("state").join(name),
        &b,
    )
    .map_err(|_| LifecycleError::Io)?;
    ensure_bound(root)
}
fn write_json<T: Serialize>(
    root: &OwnedPaperlessRoot,
    name: &str,
    value: &T,
) -> Result<(), LifecycleError> {
    let b = serde_json::to_vec(value).map_err(|_| LifecycleError::Io)?;
    crate::skills::store::atomic_write_private_child(
        &lifecycle_state_dir(root)?,
        OsStr::new(name),
        &root.display.join("state").join(name),
        &b,
    )
    .map_err(|_| LifecycleError::Io)?;
    ensure_bound(root)
}
fn ensure_archive_parent(root: &OwnedPaperlessRoot, job: &str) -> Result<(), LifecycleError> {
    let state = lifecycle_state_dir(root)?;
    let backups = crate::skills::store::open_or_create_private_child_dir(
        &state,
        OsStr::new(BACKUP_DIR),
        &root.display.join("state").join(BACKUP_DIR),
    )
    .map_err(|_| LifecycleError::Io)?;
    let job_dir = crate::skills::store::open_or_create_private_child_dir(
        &backups,
        OsStr::new(job),
        &root.display.join("state").join(BACKUP_DIR).join(job),
    )
    .map_err(|_| LifecycleError::Receipt)?;
    crate::skills::store::sync_parent_directory(
        &job_dir,
        &root.display.join("state").join(BACKUP_DIR).join(job),
    )
    .map_err(|_| LifecycleError::Io)?;
    crate::skills::store::sync_parent_directory(
        &backups,
        &root.display.join("state").join(BACKUP_DIR),
    )
    .map_err(|_| LifecycleError::Io)?;
    ensure_bound(root)
}
fn create_pending_archive(
    root: &OwnedPaperlessRoot,
    job: &str,
    name: &str,
) -> Result<std::fs::File, LifecycleError> {
    let dir = backup_job_dir(root, job)?;
    let (file, binding) = crate::skills::store::create_private_regular_file_child_create_new(
        &dir,
        OsStr::new(name),
        &root
            .display
            .join("state")
            .join(BACKUP_DIR)
            .join(job)
            .join(name),
    )
    .map_err(|_| LifecycleError::Io)?;
    if !binding
        .matches_regular_file_child_readonly(
            &dir,
            OsStr::new(name),
            &root
                .display
                .join("state")
                .join(BACKUP_DIR)
                .join(job)
                .join(name),
        )
        .map_err(|_| LifecycleError::Io)?
    {
        return Err(LifecycleError::Receipt);
    }
    Ok(file.into_std())
}
fn publish_pending_archive(
    root: &OwnedPaperlessRoot,
    job: &str,
    pending: &str,
    final_name: &str,
) -> Result<(), LifecycleError> {
    let dir = backup_job_dir(root, job)?; /* hard_link is create-new on every supported platform; unlike rename it cannot replace an attacker-created final name. */
    dir.hard_link(OsStr::new(pending), &dir, OsStr::new(final_name))
        .map_err(|_| LifecycleError::Io)?;
    let final_meta = dir
        .symlink_metadata(OsStr::new(final_name))
        .map_err(|_| LifecycleError::Io)?;
    if !final_meta.is_file() || final_meta.file_type().is_symlink() {
        return Err(LifecycleError::Receipt);
    }
    crate::skills::store::sync_parent_directory(
        &dir,
        &root.display.join("state").join(BACKUP_DIR).join(job),
    )
    .map_err(|_| LifecycleError::Io)?;
    crate::skills::store::remove_child_file(
        &dir,
        OsStr::new(pending),
        &root
            .display
            .join("state")
            .join(BACKUP_DIR)
            .join(job)
            .join(pending),
    )
    .map_err(|_| LifecycleError::Io)?;
    crate::skills::store::sync_parent_directory(
        &dir,
        &root.display.join("state").join(BACKUP_DIR).join(job),
    )
    .map_err(|_| LifecycleError::Io)?;
    ensure_bound(root)
}
fn backup_job_dir(
    root: &OwnedPaperlessRoot,
    job: &str,
) -> Result<cap_std::fs::Dir, LifecycleError> {
    let state = lifecycle_state_dir(root)?;
    let backups = crate::skills::store::open_real_child_dir(
        &state,
        OsStr::new(BACKUP_DIR),
        &root.display.join("state").join(BACKUP_DIR),
    )
    .map_err(|_| LifecycleError::Receipt)?;
    crate::skills::store::open_real_child_dir(
        &backups,
        OsStr::new(job),
        &root.display.join("state").join(BACKUP_DIR).join(job),
    )
    .map_err(|_| LifecycleError::Receipt)
}
fn write_receipt_new(
    root: &OwnedPaperlessRoot,
    r: &PaperlessBackupReceipt,
) -> Result<(), LifecycleError> {
    let b = serde_json::to_vec(r).map_err(|_| LifecycleError::Io)?;
    let dir = backup_job_dir(root, &r.job_id)?;
    crate::skills::store::atomic_write_private_child_create_new(
        &dir,
        OsStr::new("receipt.v1.json"),
        &root
            .display
            .join("state")
            .join(BACKUP_DIR)
            .join(&r.job_id)
            .join("receipt.v1.json"),
        &b,
    )
    .map_err(|_| LifecycleError::Io)?;
    ensure_bound(root)
}
fn read_receipt(
    root: &OwnedPaperlessRoot,
    c: &BackupCustody,
    install: &StoredPaperlessInstallReceipt,
    install_bytes: &[u8],
    snapshot: &[u8],
) -> Result<PaperlessBackupReceipt, LifecycleError> {
    let source = read_source_companion(root, c)?;
    if source.install_receipt_bytes != install_bytes || source.volume_set_snapshot_bytes != snapshot
    {
        return Err(LifecycleError::Receipt);
    }
    let dir = backup_job_dir(root, &c.job_id)?;
    let path = root
        .display
        .join("state")
        .join(BACKUP_DIR)
        .join(&c.job_id)
        .join("receipt.v1.json");
    let bytes = crate::skills::store::read_regular_file_bounded(
        &dir,
        OsStr::new("receipt.v1.json"),
        &path,
        RECEIPT_READ_LIMIT,
    )
    .map_err(|_| LifecycleError::Receipt)?;
    let r: PaperlessBackupReceipt =
        serde_json::from_slice(&bytes).map_err(|_| LifecycleError::Receipt)?;
    validate_receipt(&r, c, install, install_bytes, snapshot)?;
    Ok(r)
}
fn validate_receipt(
    r: &PaperlessBackupReceipt,
    c: &BackupCustody,
    install: &StoredPaperlessInstallReceipt,
    install_bytes: &[u8],
    snapshot: &[u8],
) -> Result<(), LifecycleError> {
    validate_custody(c, install, install_bytes, snapshot)?;
    if r.schema_version != 1
        || r.operation != "paperless.backup"
        || r.contract_id != paperless_staging::OCI_CONTRACT_ID
        || r.job_id != c.job_id
        || r.project != c.project
        || r.install_receipt_sha256 != digest(install_bytes)
        || r.volume_set_id != c.volume_set_id
        || r.volume_set_snapshot_sha256 != digest(snapshot)
        || r.archives != c.archives
        || r.original_running.len() != 3
        || r.restored_running.len() != 3
    {
        return Err(LifecycleError::Receipt);
    }
    for member in &c.members {
        if !r
            .original_running
            .iter()
            .any(|s| s.service == member.service && s.running == member.running)
            || !r
                .restored_running
                .iter()
                .any(|s| s.service == member.service && s.running == member.running)
        {
            return Err(LifecycleError::Receipt);
        }
    }
    if r.authenticated_api_ready != c.members.iter().all(|m| m.running) {
        return Err(LifecycleError::Receipt);
    }
    Ok(())
}
fn verify_archives_on_disk(
    root: &OwnedPaperlessRoot,
    receipt: &PaperlessBackupReceipt,
) -> Result<(), LifecycleError> {
    if receipt.archives.len() != 6 {
        return Err(LifecycleError::Receipt);
    }
    for archive in &receipt.archives {
        let name = format!("{}.tar", archive.logical_name);
        let (bytes, sha256) =
            digest_archive_readback_cap(root, &receipt.job_id, &name, BACKUP_ARCHIVE_LIMIT)?;
        if bytes != archive.bytes || sha256 != archive.sha256 {
            return Err(LifecycleError::Receipt);
        }
    }
    Ok(())
}
fn verify_custody_archives_on_disk(
    root: &OwnedPaperlessRoot,
    custody: &BackupCustody,
) -> Result<(), LifecycleError> {
    for archive in &custody.archives {
        let name = format!("{}.tar", archive.logical_name);
        let (bytes, sha256) =
            digest_archive_readback_cap(root, &custody.job_id, &name, BACKUP_ARCHIVE_LIMIT)?;
        if bytes != archive.bytes || sha256 != archive.sha256 {
            return Err(LifecycleError::Receipt);
        }
    }
    Ok(())
}
async fn inspect_members<E: ComposeExecutor>(
    e: &mut E,
    engine: &Engine,
    root: &OwnedPaperlessRoot,
    binding: &EnvBinding,
    install: &StoredPaperlessInstallReceipt,
) -> Result<Vec<BackupMember>, LifecycleError> {
    let mut out = Vec::new();
    for c in &install.containers {
        let raw = e
            .run(
                &engine.docker(
                    "container",
                    &["inspect", &c.id, "--format", CONTAINER_INSPECT_TEMPLATE],
                ),
                &root.display,
            )
            .await?;
        let d: DockerContainer =
            serde_json::from_str(&raw.stdout).map_err(|_| LifecycleError::Receipt)?;
        verify_backup_identity(c, &install.project, binding.port, &d)?;
        out.push(BackupMember {
            service: c.service.clone(),
            container_id: c.id.clone(),
            running: d.state.running,
        });
    }
    Ok(out)
}
fn verify_backup_identity(
    expected: &StoredVerifiedContainer,
    project: &str,
    port: u16,
    actual: &DockerContainer,
) -> Result<(), LifecycleError> {
    if actual.id != expected.id
        || actual.image != expected.image_id
        || actual.config.labels.get("com.docker.compose.project") != Some(&project.to_owned())
        || actual.config.labels.get("com.docker.compose.service") != Some(&expected.service)
    {
        return Err(LifecycleError::UnownedOrMismatch);
    }
    if expected.service == "webserver"
        && !actual
            .host_config
            .port_bindings
            .as_ref()
            .and_then(|m| m.get("8000/tcp"))
            .and_then(|v| v.as_ref())
            .is_some_and(|v| {
                v.len() == 1 && v[0].host_ip == "127.0.0.1" && v[0].host_port == port.to_string()
            })
    {
        return Err(LifecycleError::UnownedOrMismatch);
    }
    let mounts: Vec<_> = paperless_staging::PAPERLESS_VOLUMES
        .iter()
        .filter(|v| v.service == expected.service)
        .collect();
    if actual.mounts.len() != mounts.len()
        || mounts.iter().any(|v| {
            !actual.mounts.iter().any(|m| {
                m.kind == "volume"
                    && m.name == volume_name(project, v.logical_name)
                    && m.destination == v.destination
            })
        })
    {
        return Err(LifecycleError::UnownedOrMismatch);
    }
    Ok(())
}
async fn verify_members_with_state<E: ComposeExecutor>(
    e: &mut E,
    engine: &Engine,
    root: &OwnedPaperlessRoot,
    binding: &EnvBinding,
    install: &StoredPaperlessInstallReceipt,
    members: &[BackupMember],
    expected_original: bool,
) -> Result<(), LifecycleError> {
    let got = inspect_members(e, engine, root, binding, install).await?;
    if got.len() != members.len()
        || got.iter().zip(members).any(|(a, b)| {
            a.service != b.service
                || a.container_id != b.container_id
                || (expected_original && a.running != b.running)
                || (!expected_original && a.running)
        })
    {
        return Err(LifecycleError::UnownedOrMismatch);
    }
    Ok(())
}
async fn assert_all_stopped<E: ComposeExecutor>(
    e: &mut E,
    engine: &Engine,
    root: &OwnedPaperlessRoot,
    binding: &EnvBinding,
    install: &StoredPaperlessInstallReceipt,
) -> Result<(), LifecycleError> {
    let got = inspect_members(e, engine, root, binding, install).await?;
    if got.iter().any(|m| m.running) {
        return Err(LifecycleError::Command(
            "paperless_backup_source_not_stopped",
        ));
    }
    Ok(())
}
/// Bind every physical effect to the current owned root, raw install receipt,
/// six-volume snapshot, and Docker generation. This is deliberately repeated
/// before each stop and copy rather than trusting the admission-time view.
#[allow(clippy::too_many_arguments)] // Carry the exact retained source bytes alongside the live view.
async fn revalidate_effect_binding<E: ComposeExecutor>(
    e: &mut E,
    engine: &Engine,
    root: &OwnedPaperlessRoot,
    binding: &EnvBinding,
    install: &StoredPaperlessInstallReceipt,
    install_bytes: &[u8],
    snapshot: &[u8],
    custody: &BackupCustody,
) -> Result<(), LifecycleError> {
    ensure_bound(root)?;
    let (current_bytes, current) = read_install_receipt_with_bytes(root)?;
    validate_install_receipt(&current, &root.display)?;
    if current_bytes != install_bytes || current.project != install.project {
        return Err(LifecycleError::Receipt);
    }
    let current_snapshot = read_state_bytes(root, VOLUME_SET_NAME)?;
    if current_snapshot != snapshot {
        return Err(LifecycleError::Receipt);
    }
    let parsed: PaperlessVolumeSetSnapshot =
        serde_json::from_slice(&current_snapshot).map_err(|_| LifecycleError::Receipt)?;
    validate_volume_set_snapshot(&parsed, &install.project)?;
    if parsed.volume_set_id != custody.volume_set_id
        || preflight_existing_volumes(e, engine, &install.project, root, binding)
            .await?
            .as_deref()
            != Some(custody.volume_set_id.as_str())
    {
        return Err(LifecycleError::UnownedOrMismatch);
    }
    validate_custody(custody, install, install_bytes, snapshot)
}
async fn restore_all<E: ComposeExecutor>(
    e: &mut E,
    engine: &Engine,
    root: &OwnedPaperlessRoot,
    binding: &EnvBinding,
    install: &StoredPaperlessInstallReceipt,
    c: &mut BackupCustody,
) -> Result<(), LifecycleError> {
    let (install_bytes, _) = read_install_receipt_with_bytes(root)?;
    let snapshot = read_state_bytes(root, VOLUME_SET_NAME)?;
    revalidate_effect_binding(
        e,
        engine,
        root,
        binding,
        install,
        &install_bytes,
        &snapshot,
        c,
    )
    .await?;
    // An uncertain start is observed only. Never issue it a second time.
    if let Some(service) = c.pending_start.clone() {
        let current = inspect_members(e, engine, root, binding, install).await?;
        if !current
            .iter()
            .any(|member| member.service == service && member.running)
        {
            return Err(LifecycleError::Command(
                "paperless_backup_start_outcome_ambiguous",
            ));
        }
        c.pending_start = None;
        write_custody(root, c)?;
    }
    for service in ["db", "broker", "webserver"] {
        let Some(member) = c
            .members
            .iter()
            .find(|m| m.service == service && m.running)
            .cloned()
        else {
            continue;
        };
        revalidate_effect_binding(
            e,
            engine,
            root,
            binding,
            install,
            &install_bytes,
            &snapshot,
            c,
        )
        .await?;
        let current = inspect_members(e, engine, root, binding, install).await?;
        if current
            .iter()
            .find(|m| m.service == service)
            .ok_or(LifecycleError::Receipt)?
            .running
        {
            continue;
        }
        c.phase = BackupPhase::StartDispatched;
        c.pending_start = Some(service.into());
        write_custody(root, c)?;
        e.run(
            &engine.docker("container", &["start", &member.container_id]),
            &root.display,
        )
        .await
        .map_err(|_| LifecycleError::Command("paperless_backup_start_outcome_ambiguous"))?;
        let observed = inspect_members(e, engine, root, binding, install).await?;
        if !observed.iter().any(|m| m.service == service && m.running) {
            return Err(LifecycleError::Command(
                "paperless_backup_start_outcome_ambiguous",
            ));
        }
        c.pending_start = None;
        write_custody(root, c)?;
    }
    verify_members_with_state(e, engine, root, binding, install, &c.members, true).await?;
    c.phase = BackupPhase::SourceRestored;
    write_custody(root, c)
}
async fn restore_then_fail<E: ComposeExecutor>(
    e: &mut E,
    engine: &Engine,
    root: &OwnedPaperlessRoot,
    binding: &EnvBinding,
    install: &StoredPaperlessInstallReceipt,
    c: &mut BackupCustody,
) -> Result<PaperlessBackupReceipt, LifecycleError> {
    let _ = restore_all(e, engine, root, binding, install, c).await;
    hold(root, c, "paperless_backup_stop_failed")
}
async fn restore_then_hold<E: ComposeExecutor>(
    e: &mut E,
    engine: &Engine,
    root: &OwnedPaperlessRoot,
    binding: &EnvBinding,
    install: &StoredPaperlessInstallReceipt,
    c: &mut BackupCustody,
    code: &'static str,
) -> Result<PaperlessBackupReceipt, LifecycleError> {
    if restore_all(e, engine, root, binding, install, c)
        .await
        .is_err()
    {
        return hold(root, c, "paperless_backup_restore_outcome_ambiguous");
    }
    hold(root, c, code)
}
fn hold<T>(
    root: &OwnedPaperlessRoot,
    c: &mut BackupCustody,
    code: &'static str,
) -> Result<T, LifecycleError> {
    c.phase = BackupPhase::Held;
    write_custody(root, c)?;
    Err(LifecycleError::Command(code))
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub(crate) fn restore_config_binding(
    binding: &EnvBinding,
    credentials: &Credentials,
) -> Result<RestoreConfigBinding, LifecycleError> {
    let values = paperless_bootstrap::parse_dotenv_values(binding.env.as_slice(), &RESTORE_CONFIG_KEYS)
        .map_err(|_| LifecycleError::Credentials)?;
    if values.len() != RESTORE_CONFIG_KEYS.len()
        || RESTORE_CONFIG_KEYS
            .iter()
            .any(|key| values.get(*key).is_none_or(|value| value.is_empty()))
    {
        return Err(LifecycleError::Credentials);
    }
    let mut environment = Sha256::new();
    environment.update(b"neoth.paperless.restore.environment.v1\0");
    for key in RESTORE_CONFIG_KEYS {
        let value = values.get(key).ok_or(LifecycleError::Credentials)?;
        environment.update((key.len() as u64).to_be_bytes());
        environment.update(key.as_bytes());
        environment.update((value.len() as u64).to_be_bytes());
        environment.update(value.as_bytes());
    }
    let token = valid_token(credentials.paperless_token.as_ref())
        .ok_or(LifecycleError::Credentials)?;
    let mut token_digest = Sha256::new();
    token_digest.update(b"neoth.paperless.restore.token.v1\0");
    token_digest.update((token.expose_secret().len() as u64).to_be_bytes());
    token_digest.update(token.expose_secret().as_bytes());
    Ok(RestoreConfigBinding {
        compose_contract_id: paperless_staging::OCI_CONTRACT_ID.to_owned(),
        environment_fingerprint: format!("{:x}", environment.finalize()),
        token_fingerprint: format!("{:x}", token_digest.finalize()),
    })
}
fn digest_archive_readback_cap(
    root: &OwnedPaperlessRoot,
    job: &str,
    name: &str,
    limit: u64,
) -> Result<(u64, String), LifecycleError> {
    let dir = backup_job_dir(root, job)?;
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = dir
        .open_with(OsStr::new(name), &options)
        .map_err(|_| LifecycleError::Io)?;
    let metadata = file.metadata().map_err(|_| LifecycleError::Io)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(LifecycleError::Receipt);
    }
    let mut file = file.into_std();
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|_| LifecycleError::Io)?;
        if n == 0 {
            break;
        }
        total = total.checked_add(n as u64).ok_or(LifecycleError::Receipt)?;
        if total > limit {
            return Err(LifecycleError::Receipt);
        }
        hasher.update(&buf[..n]);
    }
    Ok((total, format!("{:x}", hasher.finalize())))
}

#[cfg(test)]
#[path = "paperless_backup_tests.rs"]
mod tests;
