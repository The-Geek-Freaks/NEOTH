//! Explicit, receipt-bound removal of the six volumes retained by safe uninstall.
//!
//! This module deliberately has no caller-selected Docker target.  It resolves
//! one schema-2 install receipt and its matching completed safe-uninstall
//! custody, then keeps a per-volume durable dispatch marker while removing the
//! resulting six exact names one at a time.

use super::*;

const PURGE_CUSTODY_NAME: &str = ".neoth-paperless-purge-custody.v1.json";
const PURGE_RECEIPT_NAME: &str = ".neoth-paperless-purge-receipt.v1.json";
const PURGE_OPERATION: &str = "paperless.confirmed_purge";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PaperlessPurgeState {
    ConfirmationRequired,
    VolumesRemoved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PaperlessPurgeCustodyPhase {
    Prepared,
    RemoveDispatched,
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PaperlessPurgeVolumeState {
    Prepared,
    RemoveDispatched,
    AbsentVerified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PaperlessPurgeVolume {
    pub(crate) logical_name: String,
    pub(crate) name: String,
    pub(crate) state: PaperlessPurgeVolumeState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct PaperlessPurgePreview {
    pub(crate) schema_version: u8,
    pub(crate) operation: &'static str,
    pub(crate) state: PaperlessPurgeState,
    pub(crate) project: String,
    pub(crate) install_receipt_sha256: String,
    pub(crate) uninstall_receipt_sha256: String,
    pub(crate) volume_set_id: String,
    pub(crate) volumes: Vec<PaperlessPurgeVolume>,
    pub(crate) confirmation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PaperlessPurgeReceipt {
    pub(crate) schema_version: u8,
    pub(crate) operation: String,
    pub(crate) state: PaperlessPurgeState,
    pub(crate) project: String,
    pub(crate) install_receipt_sha256: String,
    pub(crate) uninstall_receipt_sha256: String,
    pub(crate) volume_set_id: String,
    pub(crate) volumes: Vec<PaperlessPurgeVolume>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PaperlessPurgeCustody {
    schema_version: u8,
    operation: String,
    phase: PaperlessPurgeCustodyPhase,
    project: String,
    install_receipt_sha256: String,
    uninstall_receipt_sha256: String,
    volume_set_id: String,
    volumes: Vec<PaperlessPurgeVolume>,
}

#[derive(Debug, Clone)]
struct ResolvedPurge {
    project: String,
    install_receipt_sha256: String,
    uninstall_receipt_sha256: String,
    volume_set_id: String,
    volumes: Vec<PaperlessPurgeVolume>,
}

/// Resolve the current completed receipt chain without selecting Docker,
/// acquiring the operation lock, or writing custody.  This is the CLI preview.
pub(crate) fn preview_at(home: &Path) -> Result<PaperlessPurgePreview, LifecycleError> {
    let root_path = crate::config::InstancePaths::for_home(home).paperless_root;
    match paperless_staging::inspect_at(&root_path).status {
        PaperlessStagingStatus::PreparedPinned | PaperlessStagingStatus::AlreadyPrepared => {}
        PaperlessStagingStatus::NotPrepared => return Err(LifecycleError::NotPrepared),
        PaperlessStagingStatus::UnownedOrMismatch => return Err(LifecycleError::UnownedOrMismatch),
    }
    let owned = paperless_staging::open_owned_root_at(&root_path)
        .map_err(|_| LifecycleError::UnownedOrMismatch)?;
    let resolved = resolve_purge_chain(&owned, &root_path)?;
    Ok(preview_from_resolved(resolved))
}

pub(crate) async fn purge_at(
    home: &Path,
    confirmation: &str,
) -> Result<PaperlessPurgeReceipt, LifecycleError> {
    purge_at_with(home, confirmation, &mut DockerExecutor).await
}

pub(crate) async fn purge_at_with<E: ComposeExecutor>(
    home: &Path,
    confirmation: &str,
    executor: &mut E,
) -> Result<PaperlessPurgeReceipt, LifecycleError> {
    // Reject an accidental or stale confirmation without a lock-file write or
    // Docker selection.  The chain is resolved again after the lock below.
    let preview = preview_at(home)?;
    if confirmation != preview.confirmation {
        return Err(LifecycleError::Command(
            "paperless_purge_confirmation_mismatch",
        ));
    }

    let root_path = crate::config::InstancePaths::for_home(home).paperless_root;
    let owned = paperless_staging::open_owned_root_at(&root_path)
        .map_err(|_| LifecycleError::UnownedOrMismatch)?;
    let binding = read_binding(&owned)?;
    let _operation_lock =
        paperless_operation_lock::acquire(&owned, OsStr::new(OPERATIONS_LOCK_NAME))
            .map_err(map_operation_lock_error)?;
    let resolved = resolve_purge_chain(&owned, &root_path)?;
    if confirmation != confirmation_for(&resolved) {
        return Err(LifecycleError::Command(
            "paperless_purge_confirmation_mismatch",
        ));
    }
    let engine = select_local_engine(executor, &owned).await?;

    let mut custody = match read_purge_custody(&owned)? {
        Some(custody) => {
            validate_purge_custody(&custody, &resolved)?;
            custody
        }
        None => {
            preflight_all_volumes(executor, &engine, &owned, &binding, &resolved).await?;
            let custody = custody_from_resolved(&resolved);
            write_purge_custody_create_new(&owned, &custody)?;
            custody
        }
    };

    if custody.phase == PaperlessPurgeCustodyPhase::Complete {
        revalidate_completed_absence(executor, &engine, &owned, &binding, &resolved, &custody)
            .await?;
        return read_completed_purge_receipt(&owned, &resolved);
    }

    reconcile_dispatched_volume(executor, &engine, &owned, &binding, &resolved, &mut custody)
        .await?;

    for index in 0..custody.volumes.len() {
        if custody.volumes[index].state == PaperlessPurgeVolumeState::AbsentVerified {
            continue;
        }
        if custody.volumes[index].state == PaperlessPurgeVolumeState::RemoveDispatched {
            return Err(LifecycleError::Command(
                "paperless_purge_remove_outcome_ambiguous",
            ));
        }
        revalidate_active_fence(executor, &engine, &owned, &binding, &resolved, &custody).await?;
        let volume = custody.volumes[index].clone();
        verify_bound_volume(executor, &engine, &owned, &binding, &resolved, &volume).await?;
        exact_volume_has_no_containers(executor, &engine, &owned, &binding, &volume.name).await?;

        custody.phase = PaperlessPurgeCustodyPhase::RemoveDispatched;
        custody.volumes[index].state = PaperlessPurgeVolumeState::RemoveDispatched;
        write_purge_custody(&owned, &custody)?;

        // No --force and no retry.  The post-dispatch observation, rather
        // than Docker's exit status, decides whether this member progressed.
        let remove_result = executor
            .run(
                &engine.docker("volume", &["rm", &volume.name]),
                &owned.display,
            )
            .await;
        ensure_stage(&owned, &binding)?;
        if exact_volume_absent(executor, &engine, &owned, &binding, &volume.name).await? {
            custody.volumes[index].state = PaperlessPurgeVolumeState::AbsentVerified;
            custody.phase = PaperlessPurgeCustodyPhase::Prepared;
            write_purge_custody(&owned, &custody)?;
            // A transport error followed by observed absence is a completed
            // effect, and must not cause a resend on this or a later run.
            let _ = remove_result;
            continue;
        }
        let _ = remove_result;
        return Err(LifecycleError::Command(
            "paperless_purge_remove_outcome_ambiguous",
        ));
    }

    if custody
        .volumes
        .iter()
        .any(|volume| volume.state != PaperlessPurgeVolumeState::AbsentVerified)
    {
        return Err(LifecycleError::Receipt);
    }
    let receipt = receipt_from_custody(&custody);
    write_or_verify_purge_receipt(&owned, &receipt)?;
    custody.phase = PaperlessPurgeCustodyPhase::Complete;
    write_purge_custody(&owned, &custody)?;
    Ok(receipt)
}

fn preview_from_resolved(resolved: ResolvedPurge) -> PaperlessPurgePreview {
    let confirmation = confirmation_for(&resolved);
    PaperlessPurgePreview {
        schema_version: 1,
        operation: PURGE_OPERATION,
        state: PaperlessPurgeState::ConfirmationRequired,
        project: resolved.project,
        install_receipt_sha256: resolved.install_receipt_sha256,
        uninstall_receipt_sha256: resolved.uninstall_receipt_sha256,
        volume_set_id: resolved.volume_set_id,
        volumes: resolved.volumes,
        confirmation,
    }
}

fn confirmation_for(resolved: &ResolvedPurge) -> String {
    format!(
        "PURGE PAPERLESS VOLUME SET {} {}",
        resolved.install_receipt_sha256, resolved.volume_set_id
    )
}

fn resolve_purge_chain(
    owned: &OwnedPaperlessRoot,
    root_path: &Path,
) -> Result<ResolvedPurge, LifecycleError> {
    let (install_bytes, install) = read_install_receipt_with_bytes(owned)?;
    validate_install_receipt(&install, root_path)?;
    let volume_set_id = install
        .volume_set_id
        .clone()
        .ok_or(LifecycleError::Command(
            "paperless_purge_unsupported_legacy_volume_set",
        ))?;
    if install.schema_version != 2
        || install.volumes.len() != paperless_staging::PAPERLESS_VOLUMES.len()
        || install
            .volumes
            .iter()
            .zip(paperless_staging::PAPERLESS_VOLUMES)
            .any(|(actual, expected)| actual.logical_name != expected.logical_name)
    {
        return Err(LifecycleError::Command(
            "paperless_purge_unsupported_legacy_volume_set",
        ));
    }
    let snapshot = read_volume_set_snapshot(owned)?.ok_or(LifecycleError::Receipt)?;
    validate_volume_set_snapshot(&snapshot, &install.project)?;
    if snapshot.volume_set_id != volume_set_id {
        return Err(LifecycleError::Command(
            "paperless_purge_volume_set_mismatch",
        ));
    }
    let (uninstall_bytes, uninstall) = read_completed_uninstall_with_bytes(owned)?;
    validate_uninstall_custody(&uninstall)?;
    if uninstall.phase != PaperlessUninstallPhase::Complete {
        return Err(LifecycleError::Command(
            "paperless_purge_requires_completed_uninstall",
        ));
    }
    let install_receipt_sha256 = format!("{:x}", Sha256::digest(&install_bytes));
    if uninstall.project != install.project
        || uninstall.install_receipt_sha256 != install_receipt_sha256
    {
        return Err(LifecycleError::Command(
            "paperless_purge_volume_set_mismatch",
        ));
    }
    validate_completed_uninstall_snapshot(&uninstall, &install)?;
    if uninstall.schema_version != 2
        || uninstall.retained_volume_snapshot.len() != paperless_staging::PAPERLESS_VOLUMES.len()
        || uninstall
            .retained_volume_snapshot
            .iter()
            .zip(&install.volumes)
            .any(|(retained, installed)| {
                retained.logical_name != installed.logical_name
                    || retained.name != installed.name
                    || retained.project != installed.project
                    || retained.volume_set_id.as_deref() != Some(volume_set_id.as_str())
            })
    {
        return Err(LifecycleError::Command(
            "paperless_purge_volume_set_mismatch",
        ));
    }
    Ok(ResolvedPurge {
        project: install.project,
        install_receipt_sha256,
        uninstall_receipt_sha256: format!("{:x}", Sha256::digest(&uninstall_bytes)),
        volume_set_id,
        volumes: install
            .volumes
            .iter()
            .map(|volume| PaperlessPurgeVolume {
                logical_name: volume.logical_name.clone(),
                name: volume.name.clone(),
                state: PaperlessPurgeVolumeState::Prepared,
            })
            .collect(),
    })
}

fn read_completed_uninstall_with_bytes(
    root: &OwnedPaperlessRoot,
) -> Result<(Vec<u8>, PaperlessUninstallReceipt), LifecycleError> {
    ensure_bound(root)?;
    let state = lifecycle_state_dir(root)?;
    let bytes = crate::skills::store::read_regular_file_bounded(
        &state,
        OsStr::new(UNINSTALL_RECEIPT_NAME),
        &root.display.join(RECEIPT_DIR).join(UNINSTALL_RECEIPT_NAME),
        RECEIPT_READ_LIMIT,
    )
    .map_err(|_| LifecycleError::Command("paperless_purge_requires_completed_uninstall"))?;
    let receipt = serde_json::from_slice(&bytes).map_err(|_| LifecycleError::Receipt)?;
    Ok((bytes, receipt))
}

fn custody_from_resolved(resolved: &ResolvedPurge) -> PaperlessPurgeCustody {
    PaperlessPurgeCustody {
        schema_version: 1,
        operation: PURGE_OPERATION.to_owned(),
        phase: PaperlessPurgeCustodyPhase::Prepared,
        project: resolved.project.clone(),
        install_receipt_sha256: resolved.install_receipt_sha256.clone(),
        uninstall_receipt_sha256: resolved.uninstall_receipt_sha256.clone(),
        volume_set_id: resolved.volume_set_id.clone(),
        volumes: resolved.volumes.clone(),
    }
}

fn receipt_from_custody(custody: &PaperlessPurgeCustody) -> PaperlessPurgeReceipt {
    PaperlessPurgeReceipt {
        schema_version: 1,
        operation: PURGE_OPERATION.to_owned(),
        state: PaperlessPurgeState::VolumesRemoved,
        project: custody.project.clone(),
        install_receipt_sha256: custody.install_receipt_sha256.clone(),
        uninstall_receipt_sha256: custody.uninstall_receipt_sha256.clone(),
        volume_set_id: custody.volume_set_id.clone(),
        volumes: custody.volumes.clone(),
    }
}

fn validate_purge_custody(
    custody: &PaperlessPurgeCustody,
    resolved: &ResolvedPurge,
) -> Result<(), LifecycleError> {
    if custody.schema_version != 1
        || custody.operation != PURGE_OPERATION
        || custody.project != resolved.project
        || custody.install_receipt_sha256 != resolved.install_receipt_sha256
        || custody.uninstall_receipt_sha256 != resolved.uninstall_receipt_sha256
        || custody.volume_set_id != resolved.volume_set_id
        || custody.volumes.len() != resolved.volumes.len()
        || custody
            .volumes
            .iter()
            .zip(&resolved.volumes)
            .any(|(actual, expected)| {
                actual.logical_name != expected.logical_name || actual.name != expected.name
            })
    {
        return Err(LifecycleError::Receipt);
    }
    let dispatched = custody
        .volumes
        .iter()
        .filter(|volume| volume.state == PaperlessPurgeVolumeState::RemoveDispatched)
        .count();
    let mut seen_non_absent = false;
    for volume in &custody.volumes {
        if volume.state == PaperlessPurgeVolumeState::AbsentVerified {
            if seen_non_absent {
                return Err(LifecycleError::Receipt);
            }
        } else {
            seen_non_absent = true;
        }
    }
    match custody.phase {
        PaperlessPurgeCustodyPhase::Prepared if dispatched == 0 => {}
        PaperlessPurgeCustodyPhase::RemoveDispatched if dispatched == 1 => {}
        PaperlessPurgeCustodyPhase::Complete
            if dispatched == 0
                && custody
                    .volumes
                    .iter()
                    .all(|volume| volume.state == PaperlessPurgeVolumeState::AbsentVerified) => {}
        _ => return Err(LifecycleError::Receipt),
    }
    Ok(())
}

fn read_purge_custody(
    root: &OwnedPaperlessRoot,
) -> Result<Option<PaperlessPurgeCustody>, LifecycleError> {
    read_optional_json(root, PURGE_CUSTODY_NAME)
}

fn read_optional_json<T: serde::de::DeserializeOwned>(
    root: &OwnedPaperlessRoot,
    name: &str,
) -> Result<Option<T>, LifecycleError> {
    ensure_bound(root)?;
    let state = lifecycle_state_dir(root)?;
    match crate::skills::store::read_regular_file_bounded(
        &state,
        OsStr::new(name),
        &root.display.join(RECEIPT_DIR).join(name),
        RECEIPT_READ_LIMIT,
    ) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| LifecycleError::Receipt),
        Err(error)
            if error
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .is_some_and(|cause| cause.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(_) => Err(LifecycleError::Receipt),
    }
}

fn write_purge_custody_create_new(
    root: &OwnedPaperlessRoot,
    custody: &PaperlessPurgeCustody,
) -> Result<(), LifecycleError> {
    write_json_create_new(root, PURGE_CUSTODY_NAME, custody)
}

fn write_purge_custody(
    root: &OwnedPaperlessRoot,
    custody: &PaperlessPurgeCustody,
) -> Result<(), LifecycleError> {
    write_json(root, PURGE_CUSTODY_NAME, custody)
}

fn write_or_verify_purge_receipt(
    root: &OwnedPaperlessRoot,
    receipt: &PaperlessPurgeReceipt,
) -> Result<(), LifecycleError> {
    match read_optional_json::<PaperlessPurgeReceipt>(root, PURGE_RECEIPT_NAME)? {
        Some(existing) if existing == *receipt => Ok(()),
        Some(_) => Err(LifecycleError::Receipt),
        None => write_json_create_new(root, PURGE_RECEIPT_NAME, receipt),
    }
}

fn write_json<T: Serialize>(
    root: &OwnedPaperlessRoot,
    name: &str,
    value: &T,
) -> Result<(), LifecycleError> {
    ensure_bound(root)?;
    let state = lifecycle_state_dir(root)?;
    let bytes = serde_json::to_vec(value).map_err(|_| LifecycleError::Io)?;
    crate::skills::store::atomic_write_private_child(
        &state,
        OsStr::new(name),
        &root.display.join(RECEIPT_DIR).join(name),
        &bytes,
    )
    .map_err(|_| LifecycleError::Io)?;
    ensure_bound(root)
}

fn write_json_create_new<T: Serialize>(
    root: &OwnedPaperlessRoot,
    name: &str,
    value: &T,
) -> Result<(), LifecycleError> {
    ensure_bound(root)?;
    let state = lifecycle_state_dir(root)?;
    let bytes = serde_json::to_vec(value).map_err(|_| LifecycleError::Io)?;
    crate::skills::store::atomic_write_private_child_create_new(
        &state,
        OsStr::new(name),
        &root.display.join(RECEIPT_DIR).join(name),
        &bytes,
    )
    .map_err(|_| LifecycleError::Io)?;
    ensure_bound(root)
}

async fn preflight_all_volumes<E: ComposeExecutor>(
    executor: &mut E,
    engine: &Engine,
    root: &OwnedPaperlessRoot,
    binding: &EnvBinding,
    resolved: &ResolvedPurge,
) -> Result<(), LifecycleError> {
    ensure_source_containers_absent(executor, engine, root, binding, resolved).await?;
    let volumes = inspect_owned_volumes(
        executor,
        engine,
        &resolved.project,
        Some(&resolved.volume_set_id),
        root,
        binding,
    )
    .await?;
    if volumes
        .iter()
        .zip(&resolved.volumes)
        .any(|(observed, expected)| {
            observed.logical_name != expected.logical_name || observed.name != expected.name
        })
    {
        return Err(LifecycleError::Command(
            "paperless_purge_volume_set_mismatch",
        ));
    }
    for volume in &resolved.volumes {
        exact_volume_has_no_containers(executor, engine, root, binding, &volume.name).await?;
    }
    Ok(())
}

async fn revalidate_active_fence<E: ComposeExecutor>(
    executor: &mut E,
    engine: &Engine,
    root: &OwnedPaperlessRoot,
    binding: &EnvBinding,
    resolved: &ResolvedPurge,
    custody: &PaperlessPurgeCustody,
) -> Result<(), LifecycleError> {
    let current = resolve_purge_chain(root, &root.display)?;
    if current.install_receipt_sha256 != resolved.install_receipt_sha256
        || current.uninstall_receipt_sha256 != resolved.uninstall_receipt_sha256
        || current.volume_set_id != resolved.volume_set_id
    {
        return Err(LifecycleError::Command(
            "paperless_purge_volume_set_mismatch",
        ));
    }
    validate_purge_custody(custody, &current)?;
    ensure_source_containers_absent(executor, engine, root, binding, resolved).await?;
    for volume in &custody.volumes {
        match volume.state {
            PaperlessPurgeVolumeState::AbsentVerified => {
                if !exact_volume_absent(executor, engine, root, binding, &volume.name).await? {
                    return Err(LifecycleError::Command(
                        "paperless_purge_volume_set_mismatch",
                    ));
                }
            }
            PaperlessPurgeVolumeState::Prepared => {
                verify_bound_volume(executor, engine, root, binding, resolved, volume).await?;
                exact_volume_has_no_containers(executor, engine, root, binding, &volume.name)
                    .await?;
            }
            PaperlessPurgeVolumeState::RemoveDispatched => {
                return Err(LifecycleError::Command(
                    "paperless_purge_remove_outcome_ambiguous",
                ));
            }
        }
    }
    Ok(())
}

async fn reconcile_dispatched_volume<E: ComposeExecutor>(
    executor: &mut E,
    engine: &Engine,
    root: &OwnedPaperlessRoot,
    binding: &EnvBinding,
    resolved: &ResolvedPurge,
    custody: &mut PaperlessPurgeCustody,
) -> Result<(), LifecycleError> {
    if custody.phase != PaperlessPurgeCustodyPhase::RemoveDispatched {
        return Ok(());
    }
    let index = custody
        .volumes
        .iter()
        .position(|volume| volume.state == PaperlessPurgeVolumeState::RemoveDispatched)
        .ok_or(LifecycleError::Receipt)?;
    let current = resolve_purge_chain(root, &root.display)?;
    if current.install_receipt_sha256 != resolved.install_receipt_sha256
        || current.uninstall_receipt_sha256 != resolved.uninstall_receipt_sha256
        || current.volume_set_id != resolved.volume_set_id
    {
        return Err(LifecycleError::Command(
            "paperless_purge_volume_set_mismatch",
        ));
    }
    ensure_source_containers_absent(executor, engine, root, binding, resolved).await?;
    let volume = custody.volumes[index].clone();
    if exact_volume_absent(executor, engine, root, binding, &volume.name).await? {
        custody.volumes[index].state = PaperlessPurgeVolumeState::AbsentVerified;
        custody.phase = PaperlessPurgeCustodyPhase::Prepared;
        write_purge_custody(root, custody)?;
        return Ok(());
    }
    Err(LifecycleError::Command(
        "paperless_purge_remove_outcome_ambiguous",
    ))
}

async fn revalidate_completed_absence<E: ComposeExecutor>(
    executor: &mut E,
    engine: &Engine,
    root: &OwnedPaperlessRoot,
    binding: &EnvBinding,
    resolved: &ResolvedPurge,
    custody: &PaperlessPurgeCustody,
) -> Result<(), LifecycleError> {
    validate_purge_custody(custody, resolved)?;
    ensure_source_containers_absent(executor, engine, root, binding, resolved).await?;
    for volume in &custody.volumes {
        if !exact_volume_absent(executor, engine, root, binding, &volume.name).await? {
            return Err(LifecycleError::Command(
                "paperless_purge_volume_set_mismatch",
            ));
        }
    }
    Ok(())
}

fn read_completed_purge_receipt(
    root: &OwnedPaperlessRoot,
    resolved: &ResolvedPurge,
) -> Result<PaperlessPurgeReceipt, LifecycleError> {
    let receipt: PaperlessPurgeReceipt =
        read_optional_json(root, PURGE_RECEIPT_NAME)?.ok_or(LifecycleError::Receipt)?;
    if receipt.schema_version != 1
        || receipt.operation != PURGE_OPERATION
        || receipt.state != PaperlessPurgeState::VolumesRemoved
        || receipt.project != resolved.project
        || receipt.install_receipt_sha256 != resolved.install_receipt_sha256
        || receipt.uninstall_receipt_sha256 != resolved.uninstall_receipt_sha256
        || receipt.volume_set_id != resolved.volume_set_id
        || receipt.volumes.len() != resolved.volumes.len()
        || receipt
            .volumes
            .iter()
            .zip(&resolved.volumes)
            .any(|(actual, expected)| {
                actual.logical_name != expected.logical_name
                    || actual.name != expected.name
                    || actual.state != PaperlessPurgeVolumeState::AbsentVerified
            })
    {
        return Err(LifecycleError::Receipt);
    }
    Ok(receipt)
}

async fn ensure_source_containers_absent<E: ComposeExecutor>(
    executor: &mut E,
    engine: &Engine,
    root: &OwnedPaperlessRoot,
    binding: &EnvBinding,
    resolved: &ResolvedPurge,
) -> Result<(), LifecycleError> {
    let (bytes, install) = read_install_receipt_with_bytes(root)?;
    if format!("{:x}", Sha256::digest(&bytes)) != resolved.install_receipt_sha256 {
        return Err(LifecycleError::Command(
            "paperless_purge_volume_set_mismatch",
        ));
    }
    for container in &install.containers {
        if exact_container_present(executor, engine, &container.id, root, binding).await? {
            return Err(LifecycleError::Command(
                "paperless_purge_requires_completed_uninstall",
            ));
        }
    }
    Ok(())
}

async fn verify_bound_volume<E: ComposeExecutor>(
    executor: &mut E,
    engine: &Engine,
    root: &OwnedPaperlessRoot,
    binding: &EnvBinding,
    resolved: &ResolvedPurge,
    volume: &PaperlessPurgeVolume,
) -> Result<(), LifecycleError> {
    let expected = paperless_staging::PAPERLESS_VOLUMES
        .iter()
        .find(|candidate| candidate.logical_name == volume.logical_name)
        .copied()
        .ok_or(LifecycleError::Receipt)?;
    ensure_stage(root, binding)?;
    let inspected = executor
        .run(
            &engine.docker(
                "volume",
                &["inspect", &volume.name, "--format", VOLUME_INSPECT_TEMPLATE],
            ),
            &root.display,
        )
        .await?;
    ensure_stage(root, binding)?;
    let observed = verify_volume(
        expected,
        &resolved.project,
        Some(&resolved.volume_set_id),
        &inspected.stdout,
    )?;
    if observed.name != volume.name || observed.logical_name != volume.logical_name {
        return Err(LifecycleError::Command(
            "paperless_purge_volume_set_mismatch",
        ));
    }
    Ok(())
}

async fn exact_volume_has_no_containers<E: ComposeExecutor>(
    executor: &mut E,
    engine: &Engine,
    root: &OwnedPaperlessRoot,
    binding: &EnvBinding,
    name: &str,
) -> Result<(), LifecycleError> {
    ensure_stage(root, binding)?;
    let listed = executor
        .run(
            &engine.docker(
                "container",
                &[
                    "ls",
                    "--all",
                    "--filter",
                    &format!("volume={name}"),
                    "--no-trunc",
                    "--format",
                    "{{.ID}}",
                ],
            ),
            &root.display,
        )
        .await?;
    ensure_stage(root, binding)?;
    if listed.stdout.trim().is_empty() {
        Ok(())
    } else {
        Err(LifecycleError::Command("paperless_purge_volume_attached"))
    }
}

async fn exact_volume_absent<E: ComposeExecutor>(
    executor: &mut E,
    engine: &Engine,
    root: &OwnedPaperlessRoot,
    binding: &EnvBinding,
    name: &str,
) -> Result<bool, LifecycleError> {
    ensure_stage(root, binding)?;
    let listed = executor
        .run(
            &engine.docker(
                "volume",
                &[
                    "ls",
                    "--filter",
                    &format!("name=^{name}$"),
                    "--format",
                    VOLUME_LIST_TEMPLATE,
                ],
            ),
            &root.display,
        )
        .await?;
    ensure_stage(root, binding)?;
    Ok(!listed_expected_volume(&listed.stdout, name)?)
}

#[cfg(test)]
#[path = "paperless_purge_tests.rs"]
mod tests;
