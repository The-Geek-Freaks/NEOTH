//! Receipt-bound same-instance Paperless Restore.
//!
//! Restore consumes one explicitly named immutable Backup job. Its custody is
//! retained after commit so schema-3 active generations remain attributable to
//! the exact historical archive and rollback source.

use super::*;

/// Mutable transaction journal.  It is deliberately distinct from completed
/// custody, so an interrupted restore never overwrites historical evidence.
const RESTORE_JOURNAL_NAME: &str = ".neoth-paperless-restore-journal.v1.json";
const RESTORE_ACTIVE_POINTER_NAME: &str = ".neoth-paperless-restore-active.v1.json";
const RESTORE_HISTORY_NAME: &str = ".neoth-paperless-restore-history.v1.json";
const RESTORE_RETIRED_PREFIX: &str = ".neoth-paperless-restore-retired-";
const RESTORE_OPERATION: &str = "paperless.restore";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreActivePointer {
    schema_version: u8,
    operation: String,
    restore_job_id: String,
    custody_name: String,
    custody_sha256: String,
    authorized_volume_set_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreHistory {
    schema_version: u8,
    operation: String,
    custody_names: Vec<String>,
    #[serde(default)]
    authorized_volume_set_ids: std::collections::BTreeMap<String, Vec<String>>,
}

/// Immutable authority for a failed generation whose exact Docker volumes are
/// intentionally retained after container compensation.  A later journal may
/// be replaced, but this evidence cannot be silently overwritten.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreRetiredGeneration {
    schema_version: u8,
    operation: String,
    restore_job_id: String,
    restore_project: String,
    restored_volume_set_id: String,
    volume_names: Vec<String>,
    outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RestorePhase {
    Prepared,
    /// Persisted before `compose create`; reentry must discover or retain the
    /// exact generation before it may allocate another one.
    CreateDispatched,
    CandidateCreated,
    /// Persisted before each archive stdin transfer. A lost result is never
    /// replayed because Docker may already have applied the tar stream.
    ArchiveCopyDispatched,
    ArchivesExtracted,
    CandidateReady,
    OldStopDispatched,
    OldStopped,
    ActiveCreated,
    ActiveReady,
    SnapshotPublished,
    Compensating,
    SourceRestored,
    Committed,
    Held,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreOldContainer {
    service: String,
    id: String,
    image_id: String,
    running: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreArchive {
    logical_name: String,
    bytes: u64,
    sha256: String,
}

/// Exact bytes of the active Restore authority displaced by this transaction.
/// Absence is representable only when the capability-safe read found no
/// pointer at all; corrupt or inaccessible pointers are never normalized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum RestorePriorActivePointer {
    Present { bytes: Vec<u8>, sha256: String },
    Absent { absence: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreCustody {
    schema_version: u8,
    operation: String,
    phase: RestorePhase,
    restore_job_id: String,
    backup_job_id: String,
    base_project: String,
    source_project: String,
    source_volume_set_id: String,
    /// The live generation that was actually displaced during this restore.
    /// It can differ from the historical archive source after a prior Restore,
    /// Repair, or Reinstall.
    rollback_project: String,
    rollback_volume_set_id: String,
    restore_project: String,
    restored_volume_set_id: String,
    /// Append-only project-local generation lineage.  The first entry is the
    /// archive-restored set; terminal purge/reinstall may append successors
    /// without ever substituting that source anchor.
    #[serde(default)]
    authorized_volume_set_ids: Vec<String>,
    source_install_receipt_sha256: String,
    source_install_receipt_bytes: Vec<u8>,
    prior_install_receipt_bytes: Vec<u8>,
    source_volume_set_snapshot_bytes: Vec<u8>,
    prior_volume_set_snapshot_bytes: Vec<u8>,
    archives: Vec<RestoreArchive>,
    old_containers: Vec<RestoreOldContainer>,
    #[serde(default)]
    candidate_container_ids: Vec<String>,
    #[serde(default)]
    active_container_ids: Vec<String>,
    #[serde(default)]
    committed_install_receipt_sha256: Option<String>,
    /// Schema-2 rollback prerequisite: immutable proof of the authority that
    /// named the displaced schema-3 generation, or a strict NotFound proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prior_active_pointer: Option<RestorePriorActivePointer>,
    /// Schema-2 rollback prerequisite: non-secret binding of the live source
    /// actually displaced by this restore, kept distinct from archive source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rollback_restore_binding: Option<paperless_backup::RestoreConfigBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaperlessRestoreArchive {
    pub logical_name: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaperlessRestoreReceipt {
    pub schema_version: u8,
    pub operation: &'static str,
    pub restore_job_id: String,
    pub backup_job_id: String,
    pub source_project: String,
    pub restore_project: String,
    pub source_volume_set_id: String,
    pub restored_volume_set_id: String,
    pub previous_install_receipt_sha256: String,
    pub archives: Vec<PaperlessRestoreArchive>,
    pub candidate_authenticated_api_ready: bool,
    pub active_authenticated_api_ready: bool,
    pub rollback_retained: bool,
    pub rollback_custody_ref: String,
    pub rollback_custody_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RestoreActiveAuthority {
    pub(crate) base_project: String,
    pub(crate) restore_project: String,
    pub(crate) backup_job_id: String,
    pub(crate) restored_volume_set_id: String,
    pub(crate) custody_sha256: String,
}

/// Authorize only an immutable, committed Restore generation. Lifecycle,
/// Backup, Repair and Purge use this instead of trusting a schema-3 project
/// string on its own.
pub(super) fn active_restore_authority_at(
    root: &OwnedPaperlessRoot,
    receipt: &StoredPaperlessInstallReceipt,
) -> Result<RestoreActiveAuthority, LifecycleError> {
    for (pointer, _bytes, custody) in restore_history_custodies(root)? {
        if custody.phase == RestorePhase::Committed
            && receipt.schema_version == 3
            && restore_receipt_identity_authorized(&custody, &pointer, receipt)
        {
            return Ok(RestoreActiveAuthority {
                base_project: custody.base_project,
                restore_project: custody.restore_project,
                backup_job_id: custody.backup_job_id,
                restored_volume_set_id: custody.restored_volume_set_id,
                custody_sha256: pointer.custody_sha256,
            });
        }
    }
    Err(LifecycleError::Receipt)
}

fn restore_receipt_identity_authorized(
    custody: &RestoreCustody,
    pointer: &RestoreActivePointer,
    receipt: &StoredPaperlessInstallReceipt,
) -> bool {
    receipt.schema_version == 3
        && receipt.operation == "install"
        && receipt.contract_id == paperless_staging::OCI_CONTRACT_ID
        && receipt.authenticated_api_ready
        && receipt.project == custody.restore_project
        && receipt.volume_set_id.as_deref().is_some_and(|id| {
            pointer
                .authorized_volume_set_ids
                .iter()
                .any(|known| known == id)
        })
}

/// Validate the immutable Restore namespace after a terminal lifecycle action
/// has legitimately replaced the mutable active receipt.  This deliberately
/// does not compare receipt bytes or container IDs: Repair and reinstall are
/// allowed to refresh those effects without erasing historical provenance.
pub(crate) fn restore_project_authorized_at(
    root: &OwnedPaperlessRoot,
    project: &str,
) -> Result<(), LifecycleError> {
    if !restore_history_custodies(root)?
        .iter()
        .any(|(_, _, custody)| {
            custody.phase == RestorePhase::Committed && project == custody.restore_project
        })
    {
        return Err(LifecycleError::Receipt);
    }
    Ok(())
}

/// Peer lifecycle operations must refuse a durable Restore that has not
/// committed or completed known-source compensation.
pub(crate) fn blocks_peer_operation(root: &OwnedPaperlessRoot) -> Result<bool, LifecycleError> {
    let state = lifecycle_state_dir(root)?;
    let restore_blocks = match crate::skills::store::read_regular_file_bounded(
        &state,
        std::ffi::OsStr::new(RESTORE_JOURNAL_NAME),
        &root.display.join(RECEIPT_DIR).join(RESTORE_JOURNAL_NAME),
        RECEIPT_READ_LIMIT,
    ) {
        Ok(bytes) => {
            let custody: RestoreCustody =
                serde_json::from_slice(&bytes).map_err(|_| LifecycleError::Receipt)?;
            validate_restore_custody(&custody)?;
            Ok(!matches!(
                custody.phase,
                RestorePhase::Committed | RestorePhase::SourceRestored
            ))
        }
        Err(error)
            if error
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .is_some_and(|cause| cause.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(false)
        }
        Err(_) => Err(LifecycleError::Receipt),
    }?;
    Ok(restore_blocks || paperless_rollback::blocks_peer_operation(root)?)
}

/// Append one post-purge generation to a committed Restore lineage before its
/// first Docker effect.  A duplicate is idempotent; a different project or an
/// invalid id is refused.  Callers must still publish a schema-3 receipt only
/// after their own normal container/readiness proof.
pub(crate) fn authorize_restore_successor_volume_set_at(
    root: &OwnedPaperlessRoot,
    project: &str,
    volume_set_id: &str,
) -> Result<(), LifecycleError> {
    if !paperless_staging::valid_volume_set_id(volume_set_id) {
        return Err(LifecycleError::Receipt);
    }
    let (mut pointer, _, custody) = read_active_restore_custody(root)?;
    validate_restore_custody(&custody)?;
    if custody.phase != RestorePhase::Committed || custody.restore_project != project {
        return Err(LifecycleError::Receipt);
    }
    if !pointer
        .authorized_volume_set_ids
        .iter()
        .any(|known| known == volume_set_id)
    {
        pointer
            .authorized_volume_set_ids
            .push(volume_set_id.to_owned());
        pointer.authorized_volume_set_ids.sort();
        append_restore_history(root, &pointer)?;
        write_active_pointer_value(root, &pointer)?;
    }
    Ok(())
}

fn validate_restore_custody(custody: &RestoreCustody) -> Result<(), LifecycleError> {
    if !matches!(custody.schema_version, 1 | 2)
        || custody.operation != RESTORE_OPERATION
        || !valid_restore_job_id(&custody.restore_job_id)
        || !paperless_staging::valid_volume_set_id(&custody.source_volume_set_id)
        || !paperless_staging::valid_volume_set_id(&custody.restored_volume_set_id)
        || custody.source_volume_set_id == custody.restored_volume_set_id
        || custody.authorized_volume_set_ids.is_empty()
        || custody
            .authorized_volume_set_ids
            .first()
            .is_none_or(|id| !paperless_staging::valid_volume_set_id(id))
        || custody
            .authorized_volume_set_ids
            .iter()
            .any(|id| !paperless_staging::valid_volume_set_id(id))
        || custody
            .authorized_volume_set_ids
            .windows(2)
            .any(|ids| ids[0] >= ids[1])
        || !custody
            .authorized_volume_set_ids
            .iter()
            .any(|id| id == &custody.restored_volume_set_id)
        || custody.restore_project
            != restore_project_name(
                &custody.base_project,
                &custody.backup_job_id,
                &custody.restored_volume_set_id,
            )
            .ok_or(LifecycleError::Receipt)?
        || custody.archives.len() != paperless_staging::PAPERLESS_VOLUMES.len()
        || custody.old_containers.len() != expected_images()?.len()
        || custody.source_install_receipt_sha256
            != restore_digest(&custody.source_install_receipt_bytes)
    {
        return Err(LifecycleError::Receipt);
    }
    let source: StoredPaperlessInstallReceipt =
        serde_json::from_slice(&custody.source_install_receipt_bytes)
            .map_err(|_| LifecycleError::Receipt)?;
    if source.project != custody.source_project
        || source.volume_set_id.as_deref() != Some(custody.source_volume_set_id.as_str())
    {
        return Err(LifecycleError::Receipt);
    }
    let prior: StoredPaperlessInstallReceipt =
        serde_json::from_slice(&custody.prior_install_receipt_bytes)
            .map_err(|_| LifecycleError::Receipt)?;
    if prior.project != custody.rollback_project
        || prior.volume_set_id.as_deref() != Some(custody.rollback_volume_set_id.as_str())
        || !paperless_staging::valid_volume_set_id(&custody.rollback_volume_set_id)
    {
        return Err(LifecycleError::Receipt);
    }
    let snapshot: PaperlessVolumeSetSnapshot =
        serde_json::from_slice(&custody.source_volume_set_snapshot_bytes)
            .map_err(|_| LifecycleError::Receipt)?;
    validate_volume_set_snapshot(&snapshot, &custody.source_project)?;
    if snapshot.volume_set_id != custody.source_volume_set_id {
        return Err(LifecycleError::Receipt);
    }
    let rollback_snapshot: PaperlessVolumeSetSnapshot =
        serde_json::from_slice(&custody.prior_volume_set_snapshot_bytes)
            .map_err(|_| LifecycleError::Receipt)?;
    validate_volume_set_snapshot(&rollback_snapshot, &custody.rollback_project)?;
    if rollback_snapshot.volume_set_id != custody.rollback_volume_set_id {
        return Err(LifecycleError::Receipt);
    }
    for expected in paperless_staging::PAPERLESS_VOLUMES {
        let archive = custody
            .archives
            .iter()
            .find(|item| item.logical_name == expected.logical_name)
            .ok_or(LifecycleError::Receipt)?;
        if archive.bytes == 0
            || archive.sha256.len() != 64
            || !archive
                .sha256
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(LifecycleError::Receipt);
        }
    }
    match (
        custody.schema_version,
        &custody.prior_active_pointer,
        &custody.rollback_restore_binding,
    ) {
        (1, None, None) => {}
        (2, Some(pointer), Some(binding)) => {
            if !paperless_backup::valid_restore_binding(binding) {
                return Err(LifecycleError::Receipt);
            }
            match pointer {
                RestorePriorActivePointer::Present { bytes, sha256 } => {
                    if sha256.len() != 64
                        || !sha256
                            .bytes()
                            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
                        || restore_digest(bytes) != *sha256
                    {
                        return Err(LifecycleError::Receipt);
                    }
                    let pointer: RestoreActivePointer =
                        serde_json::from_slice(bytes).map_err(|_| LifecycleError::Receipt)?;
                    validate_restore_active_pointer(&pointer)?;
                    if prior.schema_version != 3
                        || !pointer
                            .authorized_volume_set_ids
                            .iter()
                            .any(|id| id == &custody.rollback_volume_set_id)
                    {
                        return Err(LifecycleError::Receipt);
                    }
                }
                RestorePriorActivePointer::Absent { absence }
                    if absence == "not_found"
                        && matches!(prior.schema_version, 1 | 2)
                        && prior.project == custody.base_project => {}
                RestorePriorActivePointer::Absent { .. } => return Err(LifecycleError::Receipt),
            }
        }
        _ => return Err(LifecycleError::Receipt),
    }
    Ok(())
}

fn restore_digest(bytes: &[u8]) -> String {
    format!("{:x}", sha2::Sha256::digest(bytes))
}

fn valid_restore_job_id(value: &str) -> bool {
    value.len() == "paperless-restore-".len() + 36
        && value.starts_with("paperless-restore-")
        && paperless_staging::valid_volume_set_id(&value["paperless-restore-".len()..])
}

/// Restore one exact, immutable schema-2 Backup into a fresh, deterministic
/// Compose generation.  The normal staged Compose file is never modified:
/// both renderings are supplied to Docker privately from the trusted template.
pub(crate) async fn restore_at(
    home: &std::path::Path,
    credentials: &Credentials,
    backup_job_id: &str,
) -> Result<PaperlessRestoreReceipt, LifecycleError> {
    restore_at_with(
        home,
        credentials,
        backup_job_id,
        &mut DockerExecutor,
        &ConfiguredReadiness,
    )
    .await
}

async fn restore_at_with<E: RetainedComposeExecutor, R: ReadinessVerifier>(
    home: &std::path::Path,
    credentials: &Credentials,
    backup_job_id: &str,
    executor: &mut E,
    readiness: &R,
) -> Result<PaperlessRestoreReceipt, LifecycleError> {
    if !valid_backup_job_id(backup_job_id) {
        return Err(LifecycleError::Command(
            "paperless_restore_backup_job_invalid",
        ));
    }
    let root_path = crate::config::InstancePaths::for_home(home).paperless_root;
    let owned = paperless_staging::open_owned_root_at(&root_path)
        .map_err(|_| LifecycleError::UnownedOrMismatch)?;
    let binding = read_binding(&owned)?;
    ensure_stage(&owned, &binding)?;
    validate_credentials_origin(credentials, &binding.origin)?;
    let _launch = acquire_launch_guard(&owned, &binding)?;
    let _operation_lock =
        paperless_operation_lock::acquire(&owned, std::ffi::OsStr::new(OPERATIONS_LOCK_NAME))
            .map_err(map_operation_lock_error)?;
    if paperless_backup::blocks_peer_operation(&owned)? {
        return Err(LifecycleError::Command("paperless_backup_in_progress"));
    }
    if paperless_rollback::blocks_peer_operation(&owned)? {
        return Err(LifecycleError::Command("paperless_rollback_in_progress"));
    }

    if let Some(mut existing) = read_restore_journal(&owned).map_err(restore_journal_stage_error)? {
        validate_restore_custody(&existing)?;
        if existing.phase == RestorePhase::ArchiveCopyDispatched {
            existing.phase = RestorePhase::Held;
            write_restore_journal(&owned, &existing)?;
            return Err(LifecycleError::Command(
                "paperless_restore_archive_copy_outcome_ambiguous",
            ));
        }
        if existing.phase == RestorePhase::Held {
            return Err(LifecycleError::Command(
                "paperless_restore_requires_recovery",
            ));
        }
        if matches!(
            existing.phase,
            RestorePhase::SourceRestored | RestorePhase::Committed
        ) {
            // A verified rollback is terminal for this journal.  Replace it
            // only with a fresh restore job; all committed generations stay
            // separately immutable.
        } else {
            if let Ok((_, _, committed)) = read_active_restore_custody(&owned)
                && committed.restore_job_id == existing.restore_job_id
                && current_restore_semantically_valid(&owned, &committed)?
            {
                let mut published = existing;
                published.phase = RestorePhase::Committed;
                write_restore_journal(&owned, &published)?;
                return receipt_from_committed_custody(&owned, &committed);
            }
            // Every nonterminal journal carries exact candidate and old-source
            // IDs.  Reconcile by compensating those IDs before allocating a
            // fresh generation; never replay create/cp/up against an unknown
            // partial transaction.
            let engine = select_local_engine(executor, &owned).await?;
            let mut recovered = existing;
            compensate_old_source(executor, &engine, &owned, &mut recovered).await?;
        }
    }
    if let Some(existing) =
        active_restore_for_backup(&owned, backup_job_id).map_err(restore_active_stage_error)?
    {
        if current_restore_semantically_valid(&owned, &existing)? {
            return receipt_from_committed_custody(&owned, &existing);
        }
        return Err(LifecycleError::Command(
            "paperless_restore_active_generation_invalid",
        ));
    }

    let historical = paperless_backup::resolve_completed_backup_at(&owned, backup_job_id)
        .map_err(restore_backup_stage_error)?;
    let current_binding = paperless_backup::restore_config_binding(&binding, credentials)?;
    if historical.restore_binding != current_binding {
        return Err(LifecycleError::Command(
            "paperless_restore_config_fingerprint_mismatch",
        ));
    }
    let (current_bytes, current) = read_install_receipt_with_bytes(&owned)?;
    validate_install_receipt(&current, &root_path)?;
    let prior_volume_set_snapshot_bytes = read_current_volume_set_snapshot_bytes(&owned)?;
    let base_project = project_name(&root_path);
    let prior_active_pointer = capture_prior_active_pointer(&owned, &current, &base_project)?;
    let engine = select_local_engine(executor, &owned).await?;
    let restored_volume_set_id = uuid::Uuid::new_v4().to_string();
    let restore_project = restore_project_name(
        &project_name(&root_path),
        backup_job_id,
        &restored_volume_set_id,
    )
    .ok_or(LifecycleError::Receipt)?;
    let mut old_containers = current
        .containers
        .iter()
        .map(|container| {
            let image = current
                .images
                .iter()
                .find(|image| image.service == container.service)
                .ok_or(LifecycleError::Receipt)?;
            Ok(RestoreOldContainer {
                service: container.service.clone(),
                id: container.id.clone(),
                image_id: image.config_id.clone(),
                running: false,
            })
        })
        .collect::<Result<Vec<_>, LifecycleError>>()?;
    for old in &mut old_containers {
        let inspected = executor
            .run(
                &engine.docker(
                    "container",
                    &["inspect", &old.id, "--format", CONTAINER_INSPECT_TEMPLATE],
                ),
                &owned.display,
            )
            .await?;
        let actual: DockerContainer =
            serde_json::from_str(&inspected.stdout).map_err(|_| LifecycleError::Receipt)?;
        if actual.id != old.id
            || actual.image != old.image_id
            || actual.config.labels.get("com.docker.compose.project") != Some(&current.project)
            || actual.config.labels.get("com.docker.compose.service") != Some(&old.service)
        {
            return Err(LifecycleError::Command(
                "paperless_restore_old_source_changed",
            ));
        }
        validate_old_source_mounts(&actual, &current.project, &old.service)
            .map_err(|_| LifecycleError::Command("paperless_restore_old_source_changed"))?;
        if actual.state.running {
            let expected = expected_images()?
                .into_iter()
                .find(|image| image.service == old.service)
                .ok_or(LifecycleError::Receipt)?;
            let recorded = current
                .images
                .iter()
                .find(|image| image.service == old.service)
                .ok_or(LifecycleError::Receipt)?;
            let verified = VerifiedImage {
                service: expected.service,
                reference: expected.reference,
                repo_digest: recorded.repo_digest.clone(),
                config_id: recorded.config_id.clone(),
                os: recorded.os.clone(),
                architecture: recorded.architecture.clone(),
            };
            verify_container(&verified, &current.project, binding.port, &inspected.stdout)
                .map_err(|_| LifecycleError::Command("paperless_restore_old_source_changed"))?;
        }
        old.running = actual.state.running;
    }
    let archives = historical
        .archives
        .iter()
        .map(|archive| RestoreArchive {
            logical_name: archive.logical_name.clone(),
            bytes: archive.bytes,
            sha256: archive.sha256.clone(),
        })
        .collect();
    let mut custody = RestoreCustody {
        schema_version: 2,
        operation: RESTORE_OPERATION.to_owned(),
        phase: RestorePhase::Prepared,
        restore_job_id: format!("paperless-restore-{restored_volume_set_id}"),
        backup_job_id: backup_job_id.to_owned(),
        base_project,
        source_project: historical.project.clone(),
        source_volume_set_id: historical.volume_set_id.clone(),
        rollback_project: current.project.clone(),
        rollback_volume_set_id: current
            .volume_set_id
            .clone()
            .ok_or(LifecycleError::Receipt)?,
        restore_project,
        restored_volume_set_id: restored_volume_set_id.clone(),
        authorized_volume_set_ids: vec![restored_volume_set_id.clone()],
        source_install_receipt_sha256: restore_digest(&historical.install_receipt_bytes),
        source_install_receipt_bytes: historical.install_receipt_bytes.clone(),
        prior_install_receipt_bytes: current_bytes,
        source_volume_set_snapshot_bytes: historical.volume_set_snapshot_bytes.clone(),
        prior_volume_set_snapshot_bytes,
        archives,
        old_containers,
        candidate_container_ids: Vec::new(),
        active_container_ids: Vec::new(),
        committed_install_receipt_sha256: None,
        prior_active_pointer: Some(prior_active_pointer),
        rollback_restore_binding: Some(current_binding),
    };
    // Capturing the current receipt is intentional: source archive lineage is
    // immutable above, while exact old runtime IDs are separately retained for
    // rollback even after a repair has refreshed the active receipt.
    write_restore_journal(&owned, &custody)?;

    let candidate_compose = paperless_staging::render_restore_compose(
        &custody.restored_volume_set_id,
        paperless_staging::RestorePublishMode::None,
    )
    .ok_or(LifecycleError::Receipt)?;
    custody.phase = RestorePhase::CreateDispatched;
    write_restore_journal(&owned, &custody)?;
    executor
        .run_retained_with_compose(
            // `create` allocates the six labelled volumes and exact containers
            // without running initdb/Paperless against an empty generation.  The
            // six immutable tar streams below therefore land before any service
            // process can observe or mutate the restored mounts.
            &engine.compose(
                &custody.restore_project,
                &["create", "--no-build", "--pull", "never"],
            ),
            &owned,
            &binding,
            candidate_compose,
        )
        .await?;
    custody.phase = RestorePhase::CandidateCreated;
    custody.candidate_container_ids = restore_container_ids(
        executor,
        &engine,
        &owned,
        &binding,
        &custody.restore_project,
        &custody.restored_volume_set_id,
    )
    .await?;
    write_restore_journal(&owned, &custody)?;

    // Docker cp consumes a tar stream on stdin.  The handle is capability-opened
    // and rehashed by Backup immediately before this call; Restore has no path.
    for archive in &historical.archives {
        let spec = paperless_staging::PAPERLESS_VOLUMES
            .iter()
            .find(|item| item.logical_name == archive.logical_name)
            .ok_or(LifecycleError::Receipt)?;
        let id = candidate_id_for_service(&custody.candidate_container_ids, spec.service)?;
        let file = paperless_backup::open_archive_for_restore(&owned, &historical, archive)?;
        // Backup archives the mount directory itself (`container:/mount -`),
        // so Docker's tar has that final basename at its root.  Extract into
        // the parent, with `-a`, to reconstruct `/mount` exactly instead of
        // nesting it as `/mount/mount` and to retain original ownership.
        let parent = match spec.destination.rsplit_once('/') {
            Some(("", _)) => "/",
            Some((parent, _)) if !parent.is_empty() => parent,
            _ => return Err(LifecycleError::Receipt),
        };
        custody.phase = RestorePhase::ArchiveCopyDispatched;
        write_restore_journal(&owned, &custody)?;
        match executor
            .run_stream_from_file(
                &engine.docker("cp", &["-a", "-", &format!("{id}:{parent}")]),
                &owned,
                file,
                archive.bytes,
                &archive.sha256,
            )
            .await
        {
            Ok(()) => {
                custody.phase = RestorePhase::CandidateCreated;
                write_restore_journal(&owned, &custody)?;
            }
            Err(_) => {
                return hold_restore(
                    &owned,
                    &mut custody,
                    "paperless_restore_archive_copy_outcome_ambiguous",
                );
            }
        }
    }
    custody.phase = RestorePhase::ArchivesExtracted;
    write_restore_journal(&owned, &custody)?;
    // Start only after every archive reached its stopped exact-ID target.  The
    // project namespace remains isolated from the retained source generation.
    executor
        .run_retained_with_compose(
            &engine.compose(
                &custody.restore_project,
                &["up", "-d", "--no-build", "--pull", "never"],
            ),
            &owned,
            &binding,
            paperless_staging::render_restore_compose(
                &custody.restored_volume_set_id,
                paperless_staging::RestorePublishMode::None,
            )
            .ok_or(LifecycleError::Receipt)?,
        )
        .await?;
    custody.candidate_container_ids = restore_container_ids(
        executor,
        &engine,
        &owned,
        &binding,
        &custody.restore_project,
        &custody.restored_volume_set_id,
    )
    .await?;
    verify_restore_generation(executor, &engine, &owned, &binding, &custody, false).await?;
    authenticated_candidate_probe(
        executor,
        &engine,
        &owned,
        &binding,
        credentials,
        &custody.candidate_container_ids,
    )
    .await?;
    custody.phase = RestorePhase::CandidateReady;
    write_restore_journal(&owned, &custody)?;

    custody.phase = RestorePhase::OldStopDispatched;
    write_restore_journal(&owned, &custody)?;
    for old in custody.old_containers.iter().filter(|old| old.running) {
        if let Err(error) = executor
            .run(
                &engine.docker("container", &["stop", &old.id]),
                &owned.display,
            )
            .await
        {
            compensate_old_source(executor, &engine, &owned, &mut custody).await?;
            return Err(error);
        }
    }
    for old in &custody.old_containers {
        let inspected = match executor
            .run(
                &engine.docker(
                    "container",
                    &["inspect", &old.id, "--format", CONTAINER_INSPECT_TEMPLATE],
                ),
                &owned.display,
            )
            .await
        {
            Ok(output) => output,
            Err(error) => {
                compensate_old_source(executor, &engine, &owned, &mut custody).await?;
                return Err(error);
            }
        };
        let actual: DockerContainer =
            serde_json::from_str(&inspected.stdout).map_err(|_| LifecycleError::Receipt)?;
        if actual.id != old.id
            || actual.image != old.image_id
            || (old.running && actual.state.running)
        {
            return hold_restore(&owned, &mut custody, "paperless_restore_old_stop_ambiguous");
        }
    }
    custody.phase = RestorePhase::OldStopped;
    write_restore_journal(&owned, &custody)?;
    macro_rules! compensate_try {
        ($expression:expr) => {{
            match $expression {
                Ok(value) => value,
                Err(error) => {
                    compensate_old_source(executor, &engine, &owned, &mut custody).await?;
                    return Err(error);
                }
            }
        }};
    }
    // Remove only the exact candidate IDs retained in custody.  Never run a
    // broad compose `down`/`--remove-orphans` during cutover: it could claim
    // resources outside the evidence set after a crash or operator change.
    let recorded_candidates = custody.candidate_container_ids.clone();
    for encoded in recorded_candidates {
        let id = candidate_id_for_service(
            &custody.candidate_container_ids,
            encoded.split_once(':').ok_or(LifecycleError::Receipt)?.0,
        )?
        .to_owned();
        compensate_try!(
            executor
                .run(&engine.docker("container", &["stop", &id]), &owned.display)
                .await
        );
        compensate_try!(
            executor
                .run(&engine.docker("container", &["rm", &id]), &owned.display)
                .await
        );
        custody
            .candidate_container_ids
            .retain(|known| known != &encoded);
        compensate_try!(write_restore_journal(&owned, &custody));
    }
    custody.phase = RestorePhase::ActiveCreated;
    compensate_try!(write_restore_journal(&owned, &custody));
    let active_compose = match paperless_staging::render_restore_compose(
        &custody.restored_volume_set_id,
        paperless_staging::RestorePublishMode::Loopback,
    ) {
        Some(value) => value,
        None => {
            compensate_old_source(executor, &engine, &owned, &mut custody).await?;
            return Err(LifecycleError::Receipt);
        }
    };
    compensate_try!(
        executor
            .run_retained_with_compose(
                &engine.compose(
                    &custody.restore_project,
                    &["up", "-d", "--no-build", "--pull", "never"]
                ),
                &owned,
                &binding,
                active_compose,
            )
            .await
    );
    custody.active_container_ids = compensate_try!(
        restore_container_ids(
            executor,
            &engine,
            &owned,
            &binding,
            &custody.restore_project,
            &custody.restored_volume_set_id
        )
        .await
    );
    let (images, containers, volumes) = compensate_try!(
        verify_restore_generation(executor, &engine, &owned, &binding, &custody, true).await
    );
    let mut ready_credentials = credentials.clone();
    ready_credentials.paperless_url = Some(binding.origin.clone());
    if wait_for_readiness(home, &ready_credentials, readiness, &owned, &binding)
        .await
        .is_err()
    {
        compensate_old_source(executor, &engine, &owned, &mut custody).await?;
        return Err(LifecycleError::Command(
            "paperless_restore_active_not_ready",
        ));
    }
    custody.phase = RestorePhase::ActiveReady;
    compensate_try!(write_restore_journal(&owned, &custody));
    let restore_snapshot = PaperlessVolumeSetSnapshot {
        schema_version: 1,
        project: custody.restore_project.clone(),
        volume_set_id: custody.restored_volume_set_id.clone(),
        logical_volumes: paperless_staging::PAPERLESS_VOLUMES
            .iter()
            .map(|volume| volume.logical_name.to_owned())
            .collect(),
    };
    compensate_try!(write_volume_set_snapshot_replace(&owned, &restore_snapshot));
    custody.phase = RestorePhase::SnapshotPublished;
    compensate_try!(write_restore_journal(&owned, &custody));
    let receipt = PaperlessLifecycleReceipt {
        schema_version: 3,
        operation: "install",
        contract_id: paperless_staging::OCI_CONTRACT_ID,
        project: custody.restore_project.clone(),
        loopback_port: binding.port,
        images,
        containers,
        volumes,
        volume_set_id: Some(custody.restored_volume_set_id.clone()),
        authenticated_api_ready: true,
    };
    compensate_try!(write_receipt(&owned, &receipt));
    custody.committed_install_receipt_sha256 = Some(restore_digest(&compensate_try!(
        serde_json::to_vec(&receipt).map_err(|_| LifecycleError::Io)
    )));
    custody.phase = RestorePhase::Committed;
    // Commit is publish-once.  The pointer is deliberately last: a crash
    // before it leaves an in-progress journal and cannot silently redirect a
    // schema-3 consumer to an unproven generation.
    compensate_try!(write_committed_custody_new(&owned, &custody));
    compensate_try!(write_active_pointer(&owned, &custody));
    // Pointer publication is authoritative once it names and hashes the
    // immutable custody.  A subsequent journal-write failure must not invoke
    // compensation: that would revive the old source while leaving the new
    // pointer live. Reentry completes this journal after semantic validation.
    if write_restore_journal(&owned, &custody).is_err() {
        return receipt_from_committed_custody(&owned, &custody);
    }
    Ok(compensate_try!(receipt_from_committed_custody(
        &owned, &custody
    )))
}

/// Deterministic compensation for a known failure after source-stop dispatch.
/// Every target originates in durable custody.  An inspect mismatch or an
/// unremovable recorded target is ambiguous and remains held rather than
/// guessing at a project-wide Docker cleanup.
async fn compensate_old_source<E: RetainedComposeExecutor>(
    executor: &mut E,
    engine: &Engine,
    root: &OwnedPaperlessRoot,
    custody: &mut RestoreCustody,
) -> Result<(), LifecycleError> {
    let phase = custody.phase.clone();
    // `up` can have created exact labelled containers before the following
    // journal write records their IDs.  Discover all six through the retained
    // compose contract before considering the old source restartable.
    if matches!(
        phase,
        RestorePhase::CreateDispatched
            | RestorePhase::CandidateCreated
            | RestorePhase::ArchivesExtracted
            | RestorePhase::CandidateReady
            | RestorePhase::OldStopDispatched
            | RestorePhase::OldStopped
            | RestorePhase::ActiveCreated
            | RestorePhase::ActiveReady
            | RestorePhase::SnapshotPublished
    ) && custody.candidate_container_ids.is_empty()
        && custody.active_container_ids.is_empty()
    {
        let binding = read_binding(root)?;
        custody.candidate_container_ids = match restore_container_ids(
            executor,
            engine,
            root,
            &binding,
            &custody.restore_project,
            &custody.restored_volume_set_id,
        )
        .await
        {
            Ok(ids) => ids,
            Err(_) => {
                return hold_restore(root, custody, "paperless_restore_create_outcome_ambiguous");
            }
        };
    }
    custody.phase = RestorePhase::Compensating;
    write_restore_journal(root, custody)?;
    // If publication got far enough to replace the live snapshot/receipt,
    // restore the exact pre-restore bytes before reviving the old IDs.
    if matches!(
        custody.phase,
        RestorePhase::SnapshotPublished | RestorePhase::ActiveReady | RestorePhase::Compensating
    ) {
        let source_snapshot: PaperlessVolumeSetSnapshot =
            serde_json::from_slice(&custody.prior_volume_set_snapshot_bytes)
                .map_err(|_| LifecycleError::Receipt)?;
        write_volume_set_snapshot_replace(root, &source_snapshot)?;
        write_install_receipt_bytes(root, &custody.prior_install_receipt_bytes)?;
    }
    for encoded in custody
        .candidate_container_ids
        .iter()
        .chain(custody.active_container_ids.iter())
    {
        let (_, id) = encoded.split_once(':').ok_or(LifecycleError::Receipt)?;
        let inspected = executor
            .run(
                &engine.docker(
                    "container",
                    &["inspect", id, "--format", CONTAINER_INSPECT_TEMPLATE],
                ),
                &root.display,
            )
            .await;
        match inspected {
            Ok(output) => {
                let actual: DockerContainer =
                    serde_json::from_str(&output.stdout).map_err(|_| LifecycleError::Receipt)?;
                if actual.id != id {
                    return hold_restore(
                        root,
                        custody,
                        "paperless_restore_compensation_candidate_ambiguous",
                    );
                }
                if actual.state.running {
                    executor
                        .run(&engine.docker("container", &["stop", id]), &root.display)
                        .await?;
                }
                executor
                    .run(&engine.docker("container", &["rm", id]), &root.display)
                    .await?;
            }
            Err(_) => {
                return hold_restore(
                    root,
                    custody,
                    "paperless_restore_compensation_candidate_ambiguous",
                );
            }
        }
    }
    for old in &custody.old_containers {
        let inspected = executor
            .run(
                &engine.docker(
                    "container",
                    &["inspect", &old.id, "--format", CONTAINER_INSPECT_TEMPLATE],
                ),
                &root.display,
            )
            .await?;
        let actual: DockerContainer =
            serde_json::from_str(&inspected.stdout).map_err(|_| LifecycleError::Receipt)?;
        if actual.id != old.id || actual.image != old.image_id {
            return hold_restore(
                root,
                custody,
                "paperless_restore_compensation_source_ambiguous",
            );
        }
        if old.running && !actual.state.running {
            executor
                .run(
                    &engine.docker("container", &["start", &old.id]),
                    &root.display,
                )
                .await?;
        }
        let inspected = executor
            .run(
                &engine.docker(
                    "container",
                    &["inspect", &old.id, "--format", CONTAINER_INSPECT_TEMPLATE],
                ),
                &root.display,
            )
            .await?;
        let actual: DockerContainer =
            serde_json::from_str(&inspected.stdout).map_err(|_| LifecycleError::Receipt)?;
        if actual.id != old.id
            || actual.image != old.image_id
            || actual.state.running != old.running
        {
            return hold_restore(
                root,
                custody,
                "paperless_restore_compensation_source_ambiguous",
            );
        }
    }
    if !matches!(
        phase,
        RestorePhase::Prepared | RestorePhase::SourceRestored | RestorePhase::Committed
    ) {
        write_retired_generation_new(root, custody, "source_restored_after_failed_generation")?;
    }
    custody.phase = RestorePhase::SourceRestored;
    write_restore_journal(root, custody)
}

fn write_install_receipt_bytes(
    root: &OwnedPaperlessRoot,
    bytes: &[u8],
) -> Result<(), LifecycleError> {
    let _: StoredPaperlessInstallReceipt =
        serde_json::from_slice(bytes).map_err(|_| LifecycleError::Receipt)?;
    let state = lifecycle_state_dir(root)?;
    crate::skills::store::atomic_write_private_child(
        &state,
        std::ffi::OsStr::new(RECEIPT_NAME),
        &root.display.join(RECEIPT_DIR).join(RECEIPT_NAME),
        bytes,
    )
    .map_err(|_| LifecycleError::Io)?;
    ensure_bound(root)
}

async fn restore_container_ids<E: RetainedComposeExecutor>(
    executor: &mut E,
    engine: &Engine,
    root: &OwnedPaperlessRoot,
    binding: &EnvBinding,
    project: &str,
    volume_set_id: &str,
) -> Result<Vec<String>, LifecycleError> {
    let mut ids = Vec::new();
    for image in expected_images()? {
        let raw = executor
            .run_retained_with_compose(
                &engine.compose(project, &["ps", "--all", "-q", image.service]),
                root,
                binding,
                paperless_staging::render_restore_compose(
                    volume_set_id,
                    paperless_staging::RestorePublishMode::None,
                )
                .ok_or(LifecycleError::Receipt)?,
            )
            .await?
            .stdout;
        ids.push(format!(
            "{}:{}",
            image.service,
            exact_identifier(&raw).ok_or(LifecycleError::Container(
                "paperless_restore_candidate_id_missing"
            ))?
        ));
    }
    Ok(ids)
}

fn candidate_id_for_service<'a>(
    ids: &'a [String],
    service: &str,
) -> Result<&'a str, LifecycleError> {
    ids.iter()
        .find_map(|value| {
            value
                .split_once(':')
                .filter(|(known, _)| *known == service)
                .map(|(_, id)| id)
        })
        .ok_or(LifecycleError::Receipt)
}

fn valid_backup_job_id(value: &str) -> bool {
    value.len() == "paperless-backup-".len() + 64
        && value.starts_with("paperless-backup-")
        && value["paperless-backup-".len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
}

// Fixed, content-free preflight diagnostics.  These preserve non-receipt
// errors while making product evidence distinguish an initial source failure
// from a repeated-restore journal or active-authority failure.
fn restore_journal_stage_error(error: LifecycleError) -> LifecycleError {
    match error {
        LifecycleError::Receipt => LifecycleError::Command("paperless_restore_journal_invalid"),
        other => other,
    }
}
fn restore_active_stage_error(error: LifecycleError) -> LifecycleError {
    match error {
        LifecycleError::Receipt => {
            LifecycleError::Command("paperless_restore_active_authority_invalid")
        }
        other => other,
    }
}
fn restore_backup_stage_error(error: LifecycleError) -> LifecycleError {
    match error {
        LifecycleError::Receipt => {
            LifecycleError::Command("paperless_restore_historical_backup_invalid")
        }
        other => other,
    }
}

async fn verify_restore_generation<E: RetainedComposeExecutor>(
    executor: &mut E,
    engine: &Engine,
    root: &OwnedPaperlessRoot,
    binding: &EnvBinding,
    custody: &RestoreCustody,
    active: bool,
) -> Result<
    (
        Vec<VerifiedImage>,
        Vec<VerifiedContainer>,
        Vec<VerifiedVolume>,
    ),
    LifecycleError,
> {
    let mut images = Vec::new();
    for expected in expected_images()? {
        let raw = executor
            .run(
                &engine.docker(
                    "image",
                    &[
                        "inspect",
                        expected.reference,
                        "--format",
                        IMAGE_INSPECT_TEMPLATE,
                    ],
                ),
                &root.display,
            )
            .await?
            .stdout;
        images.push(verify_image(&expected, &engine.platform, &raw)?);
    }
    let ids = if active {
        &custody.active_container_ids
    } else {
        &custody.candidate_container_ids
    };
    let mut containers = Vec::new();
    for image in &images {
        let id = candidate_id_for_service(ids, image.service)?;
        let raw = executor
            .run(
                &engine.docker(
                    "container",
                    &["inspect", id, "--format", CONTAINER_INSPECT_TEMPLATE],
                ),
                &root.display,
            )
            .await?
            .stdout;
        if active {
            containers.push(verify_container(
                image,
                &custody.restore_project,
                binding.port,
                &raw,
            )?);
        } else {
            containers.push(verify_candidate_container(
                image,
                &custody.restore_project,
                &raw,
            )?);
        }
    }
    let volumes = inspect_owned_volumes(
        executor,
        engine,
        &custody.restore_project,
        Some(&custody.restored_volume_set_id),
        root,
        binding,
    )
    .await?;
    Ok((images, containers, volumes))
}

fn verify_candidate_container(
    image: &VerifiedImage,
    project: &str,
    raw: &str,
) -> Result<VerifiedContainer, LifecycleError> {
    let actual: DockerContainer = serde_json::from_str(raw).map_err(|_| LifecycleError::Receipt)?;
    let expected_mounts: Vec<_> = paperless_staging::PAPERLESS_VOLUMES
        .iter()
        .filter(|volume| volume.service == image.service)
        .collect();
    if exact_identifier(&actual.id).as_deref() != Some(actual.id.as_str())
        || !actual.state.running
        || actual.image != image.config_id
        || actual.config.labels.get("com.docker.compose.project") != Some(&project.to_owned())
        || actual.config.labels.get("com.docker.compose.service") != Some(&image.service.to_owned())
        || actual
            .host_config
            .port_bindings
            .as_ref()
            .is_some_and(|bindings| {
                bindings
                    .values()
                    .any(|entries| entries.as_ref().is_some_and(|ports| !ports.is_empty()))
            })
        || actual.network.ports.values().any(Option::is_some)
        || actual.mounts.len() != expected_mounts.len()
        || expected_mounts.iter().any(|expected| {
            !actual.mounts.iter().any(|mount| {
                mount.kind == "volume"
                    && mount.name == volume_name(project, expected.logical_name)
                    && mount.destination == expected.destination
            })
        })
    {
        return Err(LifecycleError::Receipt);
    }
    Ok(VerifiedContainer {
        service: image.service,
        id: actual.id,
        image_id: actual.image,
    })
}

/// A stopped source cannot satisfy `verify_container`'s running/port proof,
/// but its project/service label and exact volume generation remain mandatory
/// before Restore may retain it as a rollback target.
fn validate_old_source_mounts(
    actual: &DockerContainer,
    project: &str,
    service: &str,
) -> Result<(), LifecycleError> {
    let expected: Vec<_> = paperless_staging::PAPERLESS_VOLUMES
        .iter()
        .filter(|volume| volume.service == service)
        .collect();
    if actual.mounts.len() != expected.len()
        || expected.iter().any(|volume| {
            !actual.mounts.iter().any(|mount| {
                mount.kind == "volume"
                    && mount.name == volume_name(project, volume.logical_name)
                    && mount.destination == volume.destination
            })
        })
    {
        return Err(LifecycleError::Receipt);
    }
    Ok(())
}

async fn authenticated_candidate_probe<E: RetainedComposeExecutor>(
    executor: &mut E,
    engine: &Engine,
    root: &OwnedPaperlessRoot,
    binding: &EnvBinding,
    credentials: &Credentials,
    ids: &[String],
) -> Result<(), LifecycleError> {
    let token =
        valid_token(credentials.paperless_token.as_ref()).ok_or(LifecycleError::Credentials)?;
    let id = candidate_id_for_service(ids, "webserver")?;
    let script = "import sys,urllib.request; t=sys.stdin.buffer.read().decode().strip(); r=urllib.request.Request('http://127.0.0.1:8000/api/documents/?page=1',headers={'Authorization':'Token '+t}); sys.exit(0 if 200<=urllib.request.urlopen(r,timeout=10).status<300 else 1)";
    let deadline = tokio::time::Instant::now() + READINESS_DEADLINE;
    loop {
        ensure_stage(root, binding)?;
        match executor
            .run_with_stdin(
                &engine.docker("exec", &["-i", id, "python", "-c", script]),
                root,
                Zeroizing::new(format!("{}\n", token.expose_secret()).into_bytes()),
            )
            .await
        {
            Ok(_) => {
                ensure_stage(root, binding)?;
                return Ok(());
            }
            Err(LifecycleError::Command("paperless_stdin_failed")) => {
                ensure_stage(root, binding)?;
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    return Err(LifecycleError::Command(
                        "paperless_restore_candidate_probe_not_ready",
                    ));
                }
                tokio::time::sleep_until(std::cmp::min(deadline, now + READINESS_RETRY)).await;
            }
            Err(error) => {
                ensure_stage(root, binding)?;
                return Err(error);
            }
        }
    }
}

fn restore_custody_name(job_id: &str) -> Result<String, LifecycleError> {
    if !valid_restore_job_id(job_id) {
        return Err(LifecycleError::Receipt);
    }
    Ok(format!(".neoth-paperless-restore-{job_id}.v1.json"))
}

fn retired_generation_name(job_id: &str) -> Result<String, LifecycleError> {
    if !valid_restore_job_id(job_id) {
        return Err(LifecycleError::Receipt);
    }
    Ok(format!("{RESTORE_RETIRED_PREFIX}{job_id}.v1.json"))
}

fn write_retired_generation_new(
    root: &OwnedPaperlessRoot,
    custody: &RestoreCustody,
    outcome: &str,
) -> Result<(), LifecycleError> {
    let name = retired_generation_name(&custody.restore_job_id)?;
    let volume_names: Vec<String> = paperless_staging::PAPERLESS_VOLUMES
        .iter()
        .map(|volume| volume_name(&custody.restore_project, volume.logical_name))
        .collect();
    let retired = RestoreRetiredGeneration {
        schema_version: 1,
        operation: RESTORE_OPERATION.to_owned(),
        restore_job_id: custody.restore_job_id.clone(),
        restore_project: custody.restore_project.clone(),
        restored_volume_set_id: custody.restored_volume_set_id.clone(),
        volume_names,
        outcome: outcome.to_owned(),
    };
    let state = lifecycle_state_dir(root)?;
    let bytes = serde_json::to_vec(&retired).map_err(|_| LifecycleError::Io)?;
    match crate::skills::store::atomic_write_private_child_create_new(
        &state,
        std::ffi::OsStr::new(&name),
        &root.display.join(RECEIPT_DIR).join(&name),
        &bytes,
    ) {
        Ok(()) => ensure_bound(root),
        // Reentry after a completed compensation must validate that the
        // same deterministic authority already exists, never overwrite it.
        Err(_) => {
            let stored = crate::skills::store::read_regular_file_bounded(
                &state,
                std::ffi::OsStr::new(&name),
                &root.display.join(RECEIPT_DIR).join(&name),
                RECEIPT_READ_LIMIT,
            )
            .map_err(|_| LifecycleError::Receipt)?;
            let existing: RestoreRetiredGeneration =
                serde_json::from_slice(&stored).map_err(|_| LifecycleError::Receipt)?;
            if existing != retired {
                return Err(LifecycleError::Receipt);
            }
            Ok(())
        }
    }
}

fn read_current_volume_set_snapshot_bytes(
    root: &OwnedPaperlessRoot,
) -> Result<Vec<u8>, LifecycleError> {
    const CURRENT_VOLUME_SET_NAME: &str = ".neoth-paperless-volume-set.v1.json";
    let state = lifecycle_state_dir(root)?;
    let bytes = crate::skills::store::read_regular_file_bounded(
        &state,
        std::ffi::OsStr::new(CURRENT_VOLUME_SET_NAME),
        &root.display.join(RECEIPT_DIR).join(CURRENT_VOLUME_SET_NAME),
        RECEIPT_READ_LIMIT,
    )
    .map_err(|_| LifecycleError::Receipt)?;
    let _: PaperlessVolumeSetSnapshot =
        serde_json::from_slice(&bytes).map_err(|_| LifecycleError::Receipt)?;
    Ok(bytes)
}

fn read_restore_journal(
    root: &OwnedPaperlessRoot,
) -> Result<Option<RestoreCustody>, LifecycleError> {
    let state = lifecycle_state_dir(root)?;
    match crate::skills::store::read_regular_file_bounded(
        &state,
        std::ffi::OsStr::new(RESTORE_JOURNAL_NAME),
        &root.display.join(RECEIPT_DIR).join(RESTORE_JOURNAL_NAME),
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

fn write_restore_journal(
    root: &OwnedPaperlessRoot,
    custody: &RestoreCustody,
) -> Result<(), LifecycleError> {
    ensure_bound(root)?;
    let state = lifecycle_state_dir(root)?;
    let bytes = serde_json::to_vec(custody).map_err(|_| LifecycleError::Io)?;
    crate::skills::store::atomic_write_private_child(
        &state,
        std::ffi::OsStr::new(RESTORE_JOURNAL_NAME),
        &root.display.join(RECEIPT_DIR).join(RESTORE_JOURNAL_NAME),
        &bytes,
    )
    .map_err(|_| LifecycleError::Io)?;
    ensure_bound(root)
}

fn read_committed_custody(
    root: &OwnedPaperlessRoot,
    name: &str,
) -> Result<(Vec<u8>, RestoreCustody), LifecycleError> {
    if !name.starts_with(".neoth-paperless-restore-paperless-restore-")
        || !name.ends_with(".v1.json")
    {
        return Err(LifecycleError::Receipt);
    }
    let state = lifecycle_state_dir(root)?;
    let bytes = crate::skills::store::read_regular_file_bounded(
        &state,
        std::ffi::OsStr::new(name),
        &root.display.join(RECEIPT_DIR).join(name),
        RECEIPT_READ_LIMIT,
    )
    .map_err(|_| LifecycleError::Receipt)?;
    let custody: RestoreCustody =
        serde_json::from_slice(&bytes).map_err(|_| LifecycleError::Receipt)?;
    validate_restore_custody(&custody)?;
    if restore_custody_name(&custody.restore_job_id)? != name
        || custody.phase != RestorePhase::Committed
    {
        return Err(LifecycleError::Receipt);
    }
    Ok((bytes, custody))
}

fn write_committed_custody_new(
    root: &OwnedPaperlessRoot,
    custody: &RestoreCustody,
) -> Result<(), LifecycleError> {
    if custody.phase != RestorePhase::Committed {
        return Err(LifecycleError::Receipt);
    }
    let name = restore_custody_name(&custody.restore_job_id)?;
    let state = lifecycle_state_dir(root)?;
    let bytes = serde_json::to_vec(custody).map_err(|_| LifecycleError::Io)?;
    crate::skills::store::atomic_write_private_child_create_new(
        &state,
        std::ffi::OsStr::new(&name),
        &root.display.join(RECEIPT_DIR).join(&name),
        &bytes,
    )
    .map_err(|_| LifecycleError::Io)?;
    ensure_bound(root)
}

fn read_active_restore_custody(
    root: &OwnedPaperlessRoot,
) -> Result<(RestoreActivePointer, Vec<u8>, RestoreCustody), LifecycleError> {
    let state = lifecycle_state_dir(root)?;
    let pointer_bytes = crate::skills::store::read_regular_file_bounded(
        &state,
        std::ffi::OsStr::new(RESTORE_ACTIVE_POINTER_NAME),
        &root
            .display
            .join(RECEIPT_DIR)
            .join(RESTORE_ACTIVE_POINTER_NAME),
        RECEIPT_READ_LIMIT,
    )
    .map_err(|_| LifecycleError::Receipt)?;
    let pointer: RestoreActivePointer =
        serde_json::from_slice(&pointer_bytes).map_err(|_| LifecycleError::Receipt)?;
    validate_restore_active_pointer(&pointer)?;
    let (custody_bytes, custody) = read_committed_custody(root, &pointer.custody_name)?;
    if custody.restore_job_id != pointer.restore_job_id
        || restore_digest(&custody_bytes) != pointer.custody_sha256
        || !pointer
            .authorized_volume_set_ids
            .iter()
            .any(|id| id == &custody.restored_volume_set_id)
    {
        return Err(LifecycleError::Receipt);
    }
    Ok((pointer, custody_bytes, custody))
}

/// Read the current active Restore pointer as exact capability bytes.  Rollback
/// uses these bytes only for compensation; the custody bytes returned by
/// `read_active_restore_custody` are a different immutable object.
fn read_active_pointer_bytes(root: &OwnedPaperlessRoot) -> Result<Vec<u8>, LifecycleError> {
    let state = lifecycle_state_dir(root)?;
    crate::skills::store::read_regular_file_bounded(
        &state,
        std::ffi::OsStr::new(RESTORE_ACTIVE_POINTER_NAME),
        &root
            .display
            .join(RECEIPT_DIR)
            .join(RESTORE_ACTIVE_POINTER_NAME),
        RECEIPT_READ_LIMIT,
    )
    .map_err(|_| LifecycleError::Receipt)
}

fn validate_restore_active_pointer(pointer: &RestoreActivePointer) -> Result<(), LifecycleError> {
    if pointer.schema_version != 1
        || pointer.operation != RESTORE_OPERATION
        || !valid_restore_job_id(&pointer.restore_job_id)
        || restore_custody_name(&pointer.restore_job_id)? != pointer.custody_name
        || pointer.custody_sha256.len() != 64
        || !pointer
            .custody_sha256
            .bytes()
            .all(|c| c.is_ascii_hexdigit())
        || pointer.authorized_volume_set_ids.is_empty()
        || pointer
            .authorized_volume_set_ids
            .iter()
            .any(|id| !paperless_staging::valid_volume_set_id(id))
        || pointer
            .authorized_volume_set_ids
            .windows(2)
            .any(|ids| ids[0] >= ids[1])
    {
        return Err(LifecycleError::Receipt);
    }
    Ok(())
}

fn capture_prior_active_pointer(
    root: &OwnedPaperlessRoot,
    displaced: &StoredPaperlessInstallReceipt,
    base_project: &str,
) -> Result<RestorePriorActivePointer, LifecycleError> {
    let state = lifecycle_state_dir(root)?;
    match crate::skills::store::read_regular_file_bounded(
        &state,
        std::ffi::OsStr::new(RESTORE_ACTIVE_POINTER_NAME),
        &root
            .display
            .join(RECEIPT_DIR)
            .join(RESTORE_ACTIVE_POINTER_NAME),
        RECEIPT_READ_LIMIT,
    ) {
        Ok(bytes) => {
            let pointer: RestoreActivePointer =
                serde_json::from_slice(&bytes).map_err(|_| LifecycleError::Receipt)?;
            validate_restore_active_pointer(&pointer)?;
            let (custody_bytes, custody) = read_committed_custody(root, &pointer.custody_name)?;
            if custody.restore_job_id != pointer.restore_job_id
                || restore_digest(&custody_bytes) != pointer.custody_sha256
                || !pointer
                    .authorized_volume_set_ids
                    .iter()
                    .any(|id| id == &custody.restored_volume_set_id)
            {
                return Err(LifecycleError::Receipt);
            }
            if displaced.schema_version != 3
                || !restore_receipt_identity_authorized(&custody, &pointer, displaced)
            {
                return Err(LifecycleError::Receipt);
            }
            Ok(RestorePriorActivePointer::Present {
                sha256: restore_digest(&bytes),
                bytes,
            })
        }
        Err(error)
            if error
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .is_some_and(|cause| cause.kind() == std::io::ErrorKind::NotFound) =>
        {
            if !matches!(displaced.schema_version, 1 | 2) || displaced.project != base_project {
                return Err(LifecycleError::Receipt);
            }
            Ok(RestorePriorActivePointer::Absent {
                absence: "not_found".to_owned(),
            })
        }
        Err(_) => Err(LifecycleError::Receipt),
    }
}

fn write_active_pointer(
    root: &OwnedPaperlessRoot,
    custody: &RestoreCustody,
) -> Result<(), LifecycleError> {
    let name = restore_custody_name(&custody.restore_job_id)?;
    let (bytes, stored) = read_committed_custody(root, &name)?;
    if stored != *custody {
        return Err(LifecycleError::Receipt);
    }
    let pointer = RestoreActivePointer {
        schema_version: 1,
        operation: RESTORE_OPERATION.to_owned(),
        restore_job_id: custody.restore_job_id.clone(),
        custody_name: name,
        custody_sha256: restore_digest(&bytes),
        authorized_volume_set_ids: custody.authorized_volume_set_ids.clone(),
    };
    append_restore_history(root, &pointer)?;
    write_active_pointer_value(root, &pointer)
}

fn restore_history_custodies(
    root: &OwnedPaperlessRoot,
) -> Result<Vec<(RestoreActivePointer, Vec<u8>, RestoreCustody)>, LifecycleError> {
    let state = lifecycle_state_dir(root)?;
    let bytes = crate::skills::store::read_regular_file_bounded(
        &state,
        std::ffi::OsStr::new(RESTORE_HISTORY_NAME),
        &root.display.join(RECEIPT_DIR).join(RESTORE_HISTORY_NAME),
        RECEIPT_READ_LIMIT,
    )
    .map_err(|_| LifecycleError::Receipt)?;
    let history: RestoreHistory =
        serde_json::from_slice(&bytes).map_err(|_| LifecycleError::Receipt)?;
    if history.schema_version != 1
        || history.operation != RESTORE_OPERATION
        || history.custody_names.is_empty()
        || history
            .custody_names
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(LifecycleError::Receipt);
    }
    let RestoreHistory {
        custody_names,
        authorized_volume_set_ids,
        ..
    } = history;
    custody_names
        .into_iter()
        .map(|name| {
            let (bytes, custody) = read_committed_custody(root, &name)?;
            let authorized = authorized_volume_set_ids
                .get(&name)
                .cloned()
                .unwrap_or_else(|| custody.authorized_volume_set_ids.clone());
            Ok((
                RestoreActivePointer {
                    schema_version: 1,
                    operation: RESTORE_OPERATION.to_owned(),
                    restore_job_id: custody.restore_job_id.clone(),
                    custody_name: name,
                    custody_sha256: restore_digest(&bytes),
                    authorized_volume_set_ids: authorized,
                },
                bytes,
                custody,
            ))
        })
        .collect()
}

fn append_restore_history(
    root: &OwnedPaperlessRoot,
    pointer: &RestoreActivePointer,
) -> Result<(), LifecycleError> {
    let state = lifecycle_state_dir(root)?;
    let path = root.display.join(RECEIPT_DIR).join(RESTORE_HISTORY_NAME);
    let mut history = match crate::skills::store::read_regular_file_bounded(
        &state,
        std::ffi::OsStr::new(RESTORE_HISTORY_NAME),
        &path,
        RECEIPT_READ_LIMIT,
    ) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| LifecycleError::Receipt)?,
        Err(error)
            if error
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .is_some_and(|cause| cause.kind() == std::io::ErrorKind::NotFound) =>
        {
            RestoreHistory {
                schema_version: 1,
                operation: RESTORE_OPERATION.to_owned(),
                custody_names: Vec::new(),
                authorized_volume_set_ids: std::collections::BTreeMap::new(),
            }
        }
        Err(_) => return Err(LifecycleError::Receipt),
    };
    if history.schema_version != 1 || history.operation != RESTORE_OPERATION {
        return Err(LifecycleError::Receipt);
    }
    if !history
        .custody_names
        .iter()
        .any(|name| name == &pointer.custody_name)
    {
        history.custody_names.push(pointer.custody_name.clone());
        history.custody_names.sort();
    }
    history.authorized_volume_set_ids.insert(
        pointer.custody_name.clone(),
        pointer.authorized_volume_set_ids.clone(),
    );
    let bytes = serde_json::to_vec(&history).map_err(|_| LifecycleError::Io)?;
    crate::skills::store::atomic_write_private_child(
        &state,
        std::ffi::OsStr::new(RESTORE_HISTORY_NAME),
        &path,
        &bytes,
    )
    .map_err(|_| LifecycleError::Io)?;
    ensure_bound(root)
}

fn write_active_pointer_value(
    root: &OwnedPaperlessRoot,
    pointer: &RestoreActivePointer,
) -> Result<(), LifecycleError> {
    let state = lifecycle_state_dir(root)?;
    let bytes = serde_json::to_vec(pointer).map_err(|_| LifecycleError::Io)?;
    crate::skills::store::atomic_write_private_child(
        &state,
        std::ffi::OsStr::new(RESTORE_ACTIVE_POINTER_NAME),
        &root
            .display
            .join(RECEIPT_DIR)
            .join(RESTORE_ACTIVE_POINTER_NAME),
        &bytes,
    )
    .map_err(|_| LifecycleError::Io)?;
    ensure_bound(root)
}

/// Restore the exact authority bytes captured by a later Restore custody.
/// This intentionally accepts raw validated bytes: reserializing would change
/// the capability that rollback promises to reinstate.
fn restore_active_pointer_bytes(
    root: &OwnedPaperlessRoot,
    prior: &RestorePriorActivePointer,
) -> Result<(), LifecycleError> {
    let state = lifecycle_state_dir(root)?;
    let name = std::ffi::OsStr::new(RESTORE_ACTIVE_POINTER_NAME);
    let path = root
        .display
        .join(RECEIPT_DIR)
        .join(RESTORE_ACTIVE_POINTER_NAME);
    match prior {
        RestorePriorActivePointer::Present { bytes, sha256 } => {
            if restore_digest(bytes) != *sha256 {
                return Err(LifecycleError::Receipt);
            }
            let pointer: RestoreActivePointer =
                serde_json::from_slice(bytes).map_err(|_| LifecycleError::Receipt)?;
            validate_restore_active_pointer(&pointer)?;
            crate::skills::store::atomic_write_private_child(&state, name, &path, bytes)
                .map_err(|_| LifecycleError::Io)?;
        }
        RestorePriorActivePointer::Absent { absence } if absence == "not_found" => {
            match state.remove_file(name) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(LifecycleError::Io),
            }
        }
        _ => return Err(LifecycleError::Receipt),
    }
    ensure_bound(root)
}

fn active_restore_for_backup(
    root: &OwnedPaperlessRoot,
    backup_job_id: &str,
) -> Result<Option<RestoreCustody>, LifecycleError> {
    let state = lifecycle_state_dir(root)?;
    match crate::skills::store::read_regular_file_bounded(
        &state,
        std::ffi::OsStr::new(RESTORE_ACTIVE_POINTER_NAME),
        &root
            .display
            .join(RECEIPT_DIR)
            .join(RESTORE_ACTIVE_POINTER_NAME),
        RECEIPT_READ_LIMIT,
    ) {
        Ok(_) => {
            let (_, _, custody) = read_active_restore_custody(root)?;
            Ok((custody.backup_job_id == backup_job_id).then_some(custody))
        }
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

fn current_restore_semantically_valid(
    root: &OwnedPaperlessRoot,
    custody: &RestoreCustody,
) -> Result<bool, LifecycleError> {
    let (_, _, active) = read_active_restore_custody(root)?;
    if active != *custody {
        return Ok(false);
    }
    let (_, current) = read_install_receipt_with_bytes(root)?;
    Ok(restore_receipt_identity_authorized(
        &active,
        &read_active_restore_custody(root)?.0,
        &current,
    ))
}

fn hold_restore<T>(
    root: &OwnedPaperlessRoot,
    custody: &mut RestoreCustody,
    code: &'static str,
) -> Result<T, LifecycleError> {
    custody.phase = RestorePhase::Held;
    write_restore_journal(root, custody)?;
    Err(LifecycleError::Command(code))
}

fn receipt_from_committed_custody(
    root: &OwnedPaperlessRoot,
    custody: &RestoreCustody,
) -> Result<PaperlessRestoreReceipt, LifecycleError> {
    if custody.phase != RestorePhase::Committed {
        return Err(LifecycleError::Receipt);
    }
    let name = restore_custody_name(&custody.restore_job_id)?;
    let (custody_bytes, stored) = read_committed_custody(root, &name)?;
    if stored != *custody {
        return Err(LifecycleError::Receipt);
    }
    Ok(PaperlessRestoreReceipt {
        schema_version: 1,
        operation: RESTORE_OPERATION,
        restore_job_id: custody.restore_job_id.clone(),
        backup_job_id: custody.backup_job_id.clone(),
        source_project: custody.source_project.clone(),
        restore_project: custody.restore_project.clone(),
        source_volume_set_id: custody.source_volume_set_id.clone(),
        restored_volume_set_id: custody.restored_volume_set_id.clone(),
        previous_install_receipt_sha256: custody.source_install_receipt_sha256.clone(),
        archives: custody
            .archives
            .iter()
            .map(|item| PaperlessRestoreArchive {
                logical_name: item.logical_name.clone(),
                bytes: item.bytes,
                sha256: item.sha256.clone(),
            })
            .collect(),
        candidate_authenticated_api_ready: true,
        active_authenticated_api_ready: true,
        rollback_retained: true,
        rollback_custody_ref: name,
        rollback_custody_sha256: restore_digest(&custody_bytes),
    })
}

#[path = "paperless_rollback.rs"]
pub(crate) mod paperless_rollback;
pub(crate) use paperless_rollback::{rollback_at, rollback_preview_at};

#[cfg(test)]
#[path = "paperless_restore_tests.rs"]
mod tests;
