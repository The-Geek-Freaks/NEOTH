//! Exact, custody-selected Restore rollback with retained generations.
use super::*;

const ROLLBACK_OPERATION: &str = "paperless.rollback";
const ROLLBACK_JOURNAL_NAME: &str = ".neoth-paperless-rollback-journal.v1.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct PaperlessRollbackPreview {
    pub operation: &'static str,
    pub restore_job_id: String,
    pub current_project: String,
    pub rollback_project: String,
    pub current_install_receipt_sha256: String,
    pub confirmation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct PaperlessRollbackReceipt {
    pub operation: &'static str,
    pub restore_job_id: String,
    pub current_project: String,
    pub rollback_project: String,
    pub old_source_was_running: bool,
    pub authenticated_api_ready: bool,
    pub rollback_custody_ref: String,
    pub rollback_custody_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RollbackPhase {
    Prepared,
    CurrentStopDispatched,
    CurrentStopped,
    OldStartDispatched,
    OldReady,
    PublicationDispatched,
    Compensating,
    Compensated,
    Committed,
    Held,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RollbackContainer {
    service: String,
    id: String,
    image_id: String,
    running: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RollbackCommand {
    action: String,
    id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RollbackJournal {
    schema_version: u8,
    operation: String,
    phase: RollbackPhase,
    restore_job_id: String,
    restore_custody_sha256: String,
    current_install_receipt_bytes: Vec<u8>,
    current_snapshot_bytes: Vec<u8>,
    current_active_pointer: RestorePriorActivePointer,
    current_project: String,
    rollback_project: String,
    current: Vec<RollbackContainer>,
    old: Vec<RollbackContainer>,
    current_stop_attempted: bool,
    old_start_attempted: bool,
    readiness_attempted: bool,
    authenticated_api_ready: bool,
    pending_command: Option<RollbackCommand>,
}

pub(crate) fn blocks_peer_operation(root: &OwnedPaperlessRoot) -> Result<bool, LifecycleError> {
    Ok(read_journal(root)?.is_some_and(|journal| {
        !matches!(
            journal.phase,
            RollbackPhase::Committed | RollbackPhase::Compensated
        )
    }))
}

pub(crate) fn rollback_preview_at(
    home: &Path,
    credentials: &Credentials,
    id: &str,
) -> Result<PaperlessRollbackPreview, LifecycleError> {
    let (owned, binding) = open(home)?;
    let _launch = acquire_launch_guard(&owned, &binding)?;
    let _lock = paperless_operation_lock::acquire(&owned, OsStr::new(OPERATIONS_LOCK_NAME))
        .map_err(map_operation_lock_error)?;
    ensure_stage(&owned, &binding)?;
    validate_credentials_origin(credentials, &binding.origin)?;
    reject_peer_operations(&owned)?;
    let (bytes, custody) = selected(&owned, id)?;
    validate_config(&custody, &binding, credentials)?;
    let (current_bytes, current) = current_for_custody(&owned, &custody)?;
    Ok(PaperlessRollbackPreview {
        operation: ROLLBACK_OPERATION,
        restore_job_id: id.to_owned(),
        current_project: current.project,
        rollback_project: custody.rollback_project,
        current_install_receipt_sha256: restore_digest(&current_bytes),
        confirmation: confirm(id, &bytes, &current_bytes),
    })
}

pub(crate) async fn rollback_at(
    home: &Path,
    credentials: &Credentials,
    id: &str,
    confirmation: &str,
) -> Result<PaperlessRollbackReceipt, LifecycleError> {
    rollback_at_with(
        home,
        credentials,
        id,
        confirmation,
        &mut DockerExecutor,
        &ConfiguredReadiness,
    )
    .await
}

pub(super) async fn rollback_at_with<E: RetainedComposeExecutor, R: ReadinessVerifier>(
    home: &Path,
    credentials: &Credentials,
    id: &str,
    confirmation: &str,
    executor: &mut E,
    readiness: &R,
) -> Result<PaperlessRollbackReceipt, LifecycleError> {
    let (owned, binding) = open(home)?;
    let _launch = acquire_launch_guard(&owned, &binding)?;
    let _lock = paperless_operation_lock::acquire(&owned, OsStr::new(OPERATIONS_LOCK_NAME))
        .map_err(map_operation_lock_error)?;
    ensure_stage(&owned, &binding)?;
    validate_credentials_origin(credentials, &binding.origin)?;
    let (custody_bytes, custody) = selected(&owned, id)?;
    validate_config(&custody, &binding, credentials)?;
    let existing = read_journal(&owned)?;

    // An incomplete newer transaction always fences a historical terminal retry.
    if let Some(journal) = existing.as_ref()
        && !matches!(
            journal.phase,
            RollbackPhase::Committed | RollbackPhase::Compensated
        )
    {
        if journal.restore_job_id != id {
            return Err(LifecycleError::Command("paperless_rollback_peer_operation"));
        }
        check_confirmation(
            id,
            confirmation,
            &custody_bytes,
            &journal.current_install_receipt_bytes,
        )?;
        let mut journal = journal.clone();
        if journal.pending_command.is_some() || journal.phase == RollbackPhase::Held {
            return hold(&owned, &mut journal, "paperless_rollback_requires_recovery");
        }
        if journal.phase == RollbackPhase::PublicationDispatched
            && let Some(bytes) = read_record(&owned, &name(id)?)?
        {
            let terminal = decode_journal(&owned, &bytes)?;
            if prepared(&terminal) != prepared(&journal) {
                return hold(&owned, &mut journal, "paperless_rollback_terminal_mismatch");
            }
            let result = receipt(&owned, &terminal, &custody, &bytes)?;
            let engine = select_local_engine(executor, &owned).await?;
            let current_states = observe_generation(
                executor,
                &engine,
                &owned,
                &binding,
                &journal.current_project,
                &journal.current,
            )
            .await?;
            require_states(&current_states, &journal.current, false)?;
            let old_states = observe_generation(
                executor,
                &engine,
                &owned,
                &binding,
                &journal.rollback_project,
                &journal.old,
            )
            .await?;
            require_states(&old_states, &journal.old, true)?;
            write_journal(&owned, &terminal)?;
            return Ok(result);
        }
        // A clean durable boundary may compensate observed state. It never replays
        // an unacknowledged command and never resumes partially published success.
        let engine = select_local_engine(executor, &owned).await?;
        return compensate(
            &owned,
            &binding,
            executor,
            &engine,
            &mut journal,
            "paperless_rollback_interrupted_compensated",
        )
        .await;
    }
    if let Some(terminal_bytes) = read_record(&owned, &name(id)?)? {
        let terminal = decode_journal(&owned, &terminal_bytes)?;
        check_confirmation(
            id,
            confirmation,
            &custody_bytes,
            &terminal.current_install_receipt_bytes,
        )?;
        reject_peer_operations(&owned)?;
        let result = receipt(&owned, &terminal, &custody, &terminal_bytes)?;
        let engine = select_local_engine(executor, &owned).await?;
        verify_rollback_runtime(executor, &engine, &owned, &binding, &terminal).await?;
        return Ok(result);
    }
    if existing
        .as_ref()
        .is_some_and(|journal| journal.restore_job_id == id)
    {
        return Err(LifecycleError::Command(
            "paperless_rollback_already_compensated",
        ));
    }
    reject_peer_operations(&owned)?;
    let (current_bytes, current) = current_for_custody(&owned, &custody)?;
    check_confirmation(id, confirmation, &custody_bytes, &current_bytes)?;
    let pointer_bytes = read_active_pointer_bytes(&owned)?;
    let mut journal = RollbackJournal {
        schema_version: 1,
        operation: ROLLBACK_OPERATION.to_owned(),
        phase: RollbackPhase::Prepared,
        restore_job_id: id.to_owned(),
        restore_custody_sha256: restore_digest(&custody_bytes),
        current_install_receipt_bytes: current_bytes,
        current_snapshot_bytes: read_current_volume_set_snapshot_bytes(&owned)?,
        current_active_pointer: RestorePriorActivePointer::Present {
            sha256: restore_digest(&pointer_bytes),
            bytes: pointer_bytes,
        },
        current_project: current.project.clone(),
        rollback_project: custody.rollback_project.clone(),
        current: current
            .containers
            .iter()
            .map(|item| RollbackContainer {
                service: item.service.clone(),
                id: item.id.clone(),
                image_id: item.image_id.clone(),
                running: true,
            })
            .collect(),
        old: custody
            .old_containers
            .iter()
            .map(|item| RollbackContainer {
                service: item.service.clone(),
                id: item.id.clone(),
                image_id: item.image_id.clone(),
                running: item.running,
            })
            .collect(),
        current_stop_attempted: false,
        old_start_attempted: false,
        readiness_attempted: false,
        authenticated_api_ready: false,
        pending_command: None,
    };
    validate_plan(&owned, &journal, &custody_bytes, &custody)?;
    let engine = select_local_engine(executor, &owned).await?;
    let current_states = observe_generation(
        executor,
        &engine,
        &owned,
        &binding,
        &journal.current_project,
        &journal.current,
    )
    .await?;
    require_states(&current_states, &journal.current, true)?;
    let old_states = observe_generation(
        executor,
        &engine,
        &owned,
        &binding,
        &journal.rollback_project,
        &journal.old,
    )
    .await?;
    require_states(&old_states, &journal.old, false)?;
    inspect_owned_volumes(
        executor,
        &engine,
        &current.project,
        current.volume_set_id.as_deref(),
        &owned,
        &binding,
    )
    .await?;
    inspect_owned_volumes(
        executor,
        &engine,
        &custody.rollback_project,
        Some(&custody.rollback_volume_set_id),
        &owned,
        &binding,
    )
    .await?;
    write_new_record(&owned, &intent_name(id)?, &journal)?;
    write_journal(&owned, &journal)?;
    journal.phase = RollbackPhase::CurrentStopDispatched;
    journal.current_stop_attempted = true;
    write_journal(&owned, &journal)?;
    transition_generation(
        executor,
        &engine,
        &owned,
        &binding,
        &mut journal,
        false,
        false,
    )
    .await?;
    journal.phase = RollbackPhase::CurrentStopped;
    write_journal(&owned, &journal)?;
    journal.phase = RollbackPhase::OldStartDispatched;
    journal.old_start_attempted = true;
    write_journal(&owned, &journal)?;
    transition_generation(
        executor,
        &engine,
        &owned,
        &binding,
        &mut journal,
        true,
        true,
    )
    .await?;
    journal.readiness_attempted = journal.old.iter().all(|item| item.running);
    write_journal(&owned, &journal)?;
    if journal.readiness_attempted {
        let mut local_credentials = credentials.clone();
        local_credentials.paperless_url = Some(binding.origin.clone());
        if wait_for_readiness(home, &local_credentials, readiness, &owned, &binding)
            .await
            .is_err()
        {
            return compensate(
                &owned,
                &binding,
                executor,
                &engine,
                &mut journal,
                "paperless_rollback_readiness_failed",
            )
            .await;
        }
        journal.authenticated_api_ready = true;
    }
    journal.phase = RollbackPhase::OldReady;
    write_journal(&owned, &journal)?;
    if verify_rollback_runtime(executor, &engine, &owned, &binding, &journal)
        .await
        .is_err()
    {
        return hold(
            &owned,
            &mut journal,
            "paperless_rollback_container_state_ambiguous",
        );
    }
    journal.phase = RollbackPhase::PublicationDispatched;
    write_journal(&owned, &journal)?;
    if publish_authority(
        &owned,
        &binding,
        &custody.prior_install_receipt_bytes,
        &custody.prior_volume_set_snapshot_bytes,
        custody
            .prior_active_pointer
            .as_ref()
            .ok_or(LifecycleError::Receipt)?,
    )
    .is_err()
    {
        return compensate(
            &owned,
            &binding,
            executor,
            &engine,
            &mut journal,
            "paperless_rollback_publication_failed",
        )
        .await;
    }
    let mut terminal = journal.clone();
    terminal.phase = RollbackPhase::Committed;
    // Terminal custody precedes the mutable success marker. If either write is
    // uncertain, retain the publication phase: peers cannot mistake it for done.
    write_new_record(&owned, &name(id)?, &terminal)?;
    write_journal(&owned, &terminal)?;
    let bytes = read_record(&owned, &name(id)?)?.ok_or(LifecycleError::Receipt)?;
    receipt(&owned, &terminal, &custody, &bytes)
}

fn open(home: &Path) -> Result<(OwnedPaperlessRoot, EnvBinding), LifecycleError> {
    let path = crate::config::InstancePaths::for_home(home).paperless_root;
    let root = paperless_staging::open_owned_root_at(&path)
        .map_err(|_| LifecycleError::UnownedOrMismatch)?;
    let binding = read_binding(&root)?;
    Ok((root, binding))
}

fn valid_rollback_restore_id(id: &str) -> bool {
    valid_restore_job_id(id) && id.bytes().all(|byte| !byte.is_ascii_uppercase())
}

fn selected(
    root: &OwnedPaperlessRoot,
    id: &str,
) -> Result<(Vec<u8>, RestoreCustody), LifecycleError> {
    if !valid_rollback_restore_id(id) {
        return Err(LifecycleError::Receipt);
    }
    let (bytes, custody) = read_committed_custody(root, &restore_custody_name(id)?)?;
    if custody.restore_job_id != id
        || custody.schema_version != 2
        || custody.prior_active_pointer.is_none()
        || custody.rollback_restore_binding.is_none()
    {
        return Err(LifecycleError::Command("paperless_rollback_legacy_custody"));
    }
    Ok((bytes, custody))
}

fn validate_config(
    custody: &RestoreCustody,
    binding: &EnvBinding,
    credentials: &Credentials,
) -> Result<(), LifecycleError> {
    if custody.rollback_restore_binding.as_ref()
        != Some(&paperless_backup::restore_config_binding(
            binding,
            credentials,
        )?)
    {
        return Err(LifecycleError::Command(
            "paperless_rollback_config_mismatch",
        ));
    }
    Ok(())
}

fn confirm(id: &str, custody: &[u8], current: &[u8]) -> String {
    format!(
        "rollback:{id}:{}:{}",
        &restore_digest(custody)[..16],
        &restore_digest(current)[..16]
    )
}

fn check_confirmation(
    id: &str,
    phrase: &str,
    custody: &[u8],
    current: &[u8],
) -> Result<(), LifecycleError> {
    if phrase != confirm(id, custody, current) {
        return Err(LifecycleError::Command(
            "paperless_rollback_confirmation_invalid",
        ));
    }
    Ok(())
}

fn reject_peer_operations(root: &OwnedPaperlessRoot) -> Result<(), LifecycleError> {
    if paperless_backup::blocks_peer_operation(root)?
        || super::blocks_peer_operation(root)?
        || !paperless_repair::completed_repair_journal_is_valid(root)?
        || read_uninstall_receipt(root)?.is_some()
    {
        return Err(LifecycleError::Command("paperless_rollback_peer_operation"));
    }
    for name in [
        paperless_purge::PURGE_CUSTODY_NAME,
        paperless_purge::PURGE_RECEIPT_NAME,
    ] {
        if read_record(root, name)?.is_some() {
            return Err(LifecycleError::Command("paperless_rollback_peer_operation"));
        }
    }
    Ok(())
}

fn current_for_custody(
    root: &OwnedPaperlessRoot,
    custody: &RestoreCustody,
) -> Result<(Vec<u8>, StoredPaperlessInstallReceipt), LifecycleError> {
    let (bytes, current) = read_install_receipt_with_bytes(root)?;
    validate_install_receipt(&current, &root.display)?;
    let (pointer, _, active) = read_active_restore_custody(root)?;
    if active != *custody || !restore_receipt_identity_authorized(custody, &pointer, &current) {
        return Err(LifecycleError::Receipt);
    }
    Ok((bytes, current))
}

fn name(id: &str) -> Result<String, LifecycleError> {
    if !valid_rollback_restore_id(id) {
        return Err(LifecycleError::Receipt);
    }
    Ok(format!(".neoth-paperless-rollback-{id}.v1.json"))
}

fn intent_name(id: &str) -> Result<String, LifecycleError> {
    if !valid_rollback_restore_id(id) {
        return Err(LifecycleError::Receipt);
    }
    Ok(format!(".neoth-paperless-rollback-{id}-intent.v1.json"))
}

fn read_record(root: &OwnedPaperlessRoot, name: &str) -> Result<Option<Vec<u8>>, LifecycleError> {
    ensure_bound(root)?;
    let state = lifecycle_state_dir(root)?;
    match crate::skills::store::read_regular_file_bounded(
        &state,
        OsStr::new(name),
        &root.display.join(RECEIPT_DIR).join(name),
        RECEIPT_READ_LIMIT,
    ) {
        Ok(bytes) => {
            ensure_bound(root)?;
            Ok(Some(bytes))
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

fn prepared(journal: &RollbackJournal) -> RollbackJournal {
    let mut intent = journal.clone();
    intent.phase = RollbackPhase::Prepared;
    intent.current_stop_attempted = false;
    intent.old_start_attempted = false;
    intent.readiness_attempted = false;
    intent.authenticated_api_ready = false;
    intent.pending_command = None;
    intent
}

fn validate_plan(
    root: &OwnedPaperlessRoot,
    journal: &RollbackJournal,
    custody_bytes: &[u8],
    custody: &RestoreCustody,
) -> Result<(), LifecycleError> {
    if journal.schema_version != 1
        || journal.operation != ROLLBACK_OPERATION
        || journal.restore_job_id != custody.restore_job_id
        || journal.restore_custody_sha256 != restore_digest(custody_bytes)
        || journal.current_project != custody.restore_project
        || journal.rollback_project != custody.rollback_project
        || journal.current_project == journal.rollback_project
    {
        return Err(LifecycleError::Receipt);
    }
    let current: StoredPaperlessInstallReceipt =
        serde_json::from_slice(&journal.current_install_receipt_bytes)
            .map_err(|_| LifecycleError::Receipt)?;
    validate_install_receipt(&current, &root.display)?;
    let prior: StoredPaperlessInstallReceipt =
        serde_json::from_slice(&custody.prior_install_receipt_bytes)
            .map_err(|_| LifecycleError::Receipt)?;
    validate_install_receipt(&prior, &root.display)?;
    let snapshot: PaperlessVolumeSetSnapshot =
        serde_json::from_slice(&journal.current_snapshot_bytes)
            .map_err(|_| LifecycleError::Receipt)?;
    validate_volume_set_snapshot(&snapshot, &current.project)?;
    if current.project != journal.current_project
        || current.volume_set_id.as_deref() != Some(snapshot.volume_set_id.as_str())
    {
        return Err(LifecycleError::Receipt);
    }
    let pointer = match &journal.current_active_pointer {
        RestorePriorActivePointer::Present { bytes, sha256 }
            if restore_digest(bytes) == *sha256 =>
        {
            let pointer: RestoreActivePointer =
                serde_json::from_slice(bytes).map_err(|_| LifecycleError::Receipt)?;
            validate_restore_active_pointer(&pointer)?;
            pointer
        }
        _ => return Err(LifecycleError::Receipt),
    };
    if pointer.restore_job_id != custody.restore_job_id
        || pointer.custody_name != restore_custody_name(&custody.restore_job_id)?
        || pointer.custody_sha256 != journal.restore_custody_sha256
        || !restore_receipt_identity_authorized(custody, &pointer, &current)
    {
        return Err(LifecycleError::Receipt);
    }
    let expected_current: Vec<_> = current
        .containers
        .iter()
        .map(|item| RollbackContainer {
            service: item.service.clone(),
            id: item.id.clone(),
            image_id: item.image_id.clone(),
            running: true,
        })
        .collect();
    let expected_old: Vec<_> = custody
        .old_containers
        .iter()
        .map(|item| RollbackContainer {
            service: item.service.clone(),
            id: item.id.clone(),
            image_id: item.image_id.clone(),
            running: item.running,
        })
        .collect();
    if journal.current != expected_current
        || journal.old != expected_old
        || journal.old.len() != prior.containers.len()
        || journal.old.iter().any(|old| {
            !prior.containers.iter().any(|item| {
                item.service == old.service && item.id == old.id && item.image_id == old.image_id
            })
        })
    {
        return Err(LifecycleError::Receipt);
    }
    let mut ids = std::collections::BTreeSet::new();
    for item in journal.current.iter().chain(&journal.old) {
        if !exact_container_id(&item.id) || !ids.insert(&item.id) {
            return Err(LifecycleError::Receipt);
        }
    }
    for group in [&journal.current, &journal.old] {
        if group.len() != 3
            || group
                .iter()
                .map(|item| &item.service)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != 3
        {
            return Err(LifecycleError::Receipt);
        }
    }
    Ok(())
}

fn decode_journal(
    root: &OwnedPaperlessRoot,
    bytes: &[u8],
) -> Result<RollbackJournal, LifecycleError> {
    let journal: RollbackJournal =
        serde_json::from_slice(bytes).map_err(|_| LifecycleError::Receipt)?;
    let (custody_bytes, custody) = selected(root, &journal.restore_job_id)?;
    validate_plan(root, &journal, &custody_bytes, &custody)?;
    let intent_bytes = read_record(root, &intent_name(&journal.restore_job_id)?)?
        .ok_or(LifecycleError::Receipt)?;
    let intent: RollbackJournal =
        serde_json::from_slice(&intent_bytes).map_err(|_| LifecycleError::Receipt)?;
    if intent != prepared(&journal)
        || (journal.old_start_attempted && !journal.current_stop_attempted)
        || (journal.readiness_attempted
            && (!journal.old_start_attempted || !journal.old.iter().all(|item| item.running)))
        || (journal.authenticated_api_ready && !journal.readiness_attempted)
    {
        return Err(LifecycleError::Receipt);
    }
    if let Some(command) = &journal.pending_command {
        let allowed = match journal.phase {
            RollbackPhase::CurrentStopDispatched => {
                command.action == "stop" && journal.current.iter().any(|item| item.id == command.id)
            }
            RollbackPhase::OldStartDispatched => {
                command.action == "start"
                    && journal
                        .old
                        .iter()
                        .any(|item| item.id == command.id && item.running)
            }
            RollbackPhase::Compensating | RollbackPhase::Held => {
                (command.action == "stop"
                    && journal
                        .old
                        .iter()
                        .chain(&journal.current)
                        .any(|item| item.id == command.id))
                    || (command.action == "start"
                        && journal
                            .current
                            .iter()
                            .chain(&journal.old)
                            .any(|item| item.id == command.id && item.running))
            }
            _ => false,
        };
        if !allowed {
            return Err(LifecycleError::Receipt);
        }
    }
    if matches!(
        journal.phase,
        RollbackPhase::Committed | RollbackPhase::Compensated
    ) && journal.pending_command.is_some()
    {
        return Err(LifecycleError::Receipt);
    }
    if journal.phase == RollbackPhase::Committed
        && (!journal.current_stop_attempted
            || !journal.old_start_attempted
            || journal.authenticated_api_ready != journal.old.iter().all(|item| item.running))
    {
        return Err(LifecycleError::Receipt);
    }
    let terminal_name = match journal.phase {
        RollbackPhase::Committed => Some(name(&journal.restore_job_id)?),
        RollbackPhase::Compensated => Some(format!(
            ".neoth-paperless-rollback-{}-compensated.v1.json",
            journal.restore_job_id
        )),
        _ => None,
    };
    if let Some(terminal_name) = terminal_name {
        let bytes = read_record(root, &terminal_name)?.ok_or(LifecycleError::Receipt)?;
        let terminal: RollbackJournal =
            serde_json::from_slice(&bytes).map_err(|_| LifecycleError::Receipt)?;
        if terminal != journal {
            return Err(LifecycleError::Receipt);
        }
    }
    Ok(journal)
}

fn read_journal(root: &OwnedPaperlessRoot) -> Result<Option<RollbackJournal>, LifecycleError> {
    read_record(root, ROLLBACK_JOURNAL_NAME)?
        .map(|bytes| decode_journal(root, &bytes))
        .transpose()
}

fn write_journal(
    root: &OwnedPaperlessRoot,
    journal: &RollbackJournal,
) -> Result<(), LifecycleError> {
    let bytes = serde_json::to_vec(journal).map_err(|_| LifecycleError::Io)?;
    let state = lifecycle_state_dir(root)?;
    ensure_bound(root)?;
    crate::skills::store::atomic_write_private_child(
        &state,
        OsStr::new(ROLLBACK_JOURNAL_NAME),
        &root.display.join(RECEIPT_DIR).join(ROLLBACK_JOURNAL_NAME),
        &bytes,
    )
    .map_err(|_| LifecycleError::Io)?;
    ensure_bound(root)
}

fn write_new_record(
    root: &OwnedPaperlessRoot,
    name: &str,
    journal: &RollbackJournal,
) -> Result<(), LifecycleError> {
    let bytes = serde_json::to_vec(journal).map_err(|_| LifecycleError::Io)?;
    let state = lifecycle_state_dir(root)?;
    ensure_bound(root)?;
    if crate::skills::store::atomic_write_private_child_create_new(
        &state,
        OsStr::new(name),
        &root.display.join(RECEIPT_DIR).join(name),
        &bytes,
    )
    .is_err()
        && read_record(root, name)?.as_deref() != Some(bytes.as_slice())
    {
        return Err(LifecycleError::Receipt);
    }
    ensure_bound(root)
}

fn hold<T>(
    root: &OwnedPaperlessRoot,
    journal: &mut RollbackJournal,
    code: &'static str,
) -> Result<T, LifecycleError> {
    journal.phase = RollbackPhase::Held;
    write_journal(root, journal)?;
    Err(LifecycleError::Command(code))
}

async fn observe_generation<E: ComposeExecutor>(
    executor: &mut E,
    engine: &Engine,
    root: &OwnedPaperlessRoot,
    binding: &EnvBinding,
    project: &str,
    items: &[RollbackContainer],
) -> Result<Vec<bool>, LifecycleError> {
    let mut states = Vec::with_capacity(items.len());
    for item in items {
        ensure_stage(root, binding)?;
        let raw = executor
            .run(
                &engine.docker(
                    "container",
                    &["inspect", &item.id, "--format", CONTAINER_INSPECT_TEMPLATE],
                ),
                &root.display,
            )
            .await?
            .stdout;
        ensure_stage(root, binding)?;
        let actual: DockerContainer =
            serde_json::from_str(&raw).map_err(|_| LifecycleError::Receipt)?;
        let expected = expected_images()?
            .into_iter()
            .find(|image| image.service == item.service)
            .ok_or(LifecycleError::Receipt)?;
        if actual.id != item.id
            || actual.image != item.image_id
            || expected.configs.get(&engine.platform) != Some(&item.image_id)
            || actual
                .config
                .labels
                .get("com.docker.compose.project")
                .map(String::as_str)
                != Some(project)
            || actual.config.labels.get("com.docker.compose.service") != Some(&item.service)
        {
            return Err(LifecycleError::Receipt);
        }
        validate_old_source_mounts(&actual, project, &item.service)?;
        let webserver = item.service == "webserver";
        for (key, entries) in &actual.host_config.port_bindings {
            if entries.as_ref().is_some_and(|entries| !entries.is_empty())
                && (!webserver || key != "8000/tcp")
            {
                return Err(LifecycleError::Receipt);
            }
        }
        if webserver
            && !actual
                .host_config
                .port_bindings
                .get("8000/tcp")
                .and_then(|entries| entries.as_ref())
                .is_some_and(|entries| {
                    entries.len() == 1
                        && entries[0].host_ip == "127.0.0.1"
                        && entries[0].host_port == binding.port.to_string()
                })
        {
            return Err(LifecycleError::Receipt);
        }
        for (key, entries) in &actual.network.ports {
            if entries.as_ref().is_some_and(|entries| !entries.is_empty())
                && (!actual.state.running || !webserver || key != "8000/tcp")
            {
                return Err(LifecycleError::Receipt);
            }
        }
        if actual.state.running
            && webserver
            && !actual
                .network
                .ports
                .get("8000/tcp")
                .and_then(|entries| entries.as_ref())
                .is_some_and(|entries| {
                    entries.len() == 1
                        && entries[0].host_ip == "127.0.0.1"
                        && entries[0].host_port == binding.port.to_string()
                })
        {
            return Err(LifecycleError::Receipt);
        }
        states.push(actual.state.running);
    }
    Ok(states)
}

fn require_states(
    states: &[bool],
    items: &[RollbackContainer],
    original: bool,
) -> Result<(), LifecycleError> {
    if states.len() != items.len()
        || states
            .iter()
            .zip(items)
            .any(|(state, item)| *state != (original && item.running))
    {
        return Err(LifecycleError::Receipt);
    }
    Ok(())
}

async fn verify_rollback_runtime<E: ComposeExecutor>(
    executor: &mut E,
    engine: &Engine,
    root: &OwnedPaperlessRoot,
    binding: &EnvBinding,
    journal: &RollbackJournal,
) -> Result<(), LifecycleError> {
    let states = observe_generation(
        executor,
        engine,
        root,
        binding,
        &journal.current_project,
        &journal.current,
    )
    .await?;
    require_states(&states, &journal.current, false)?;
    let states = observe_generation(
        executor,
        engine,
        root,
        binding,
        &journal.rollback_project,
        &journal.old,
    )
    .await?;
    require_states(&states, &journal.old, true)
}

async fn transition_generation<E: ComposeExecutor>(
    executor: &mut E,
    engine: &Engine,
    root: &OwnedPaperlessRoot,
    binding: &EnvBinding,
    journal: &mut RollbackJournal,
    old: bool,
    original: bool,
) -> Result<(), LifecycleError> {
    let (project, items) = if old {
        (journal.rollback_project.clone(), journal.old.clone())
    } else {
        (journal.current_project.clone(), journal.current.clone())
    };
    for index in 0..items.len() {
        let states =
            match observe_generation(executor, engine, root, binding, &project, &items).await {
                Ok(states) => states,
                Err(_) => {
                    return hold(
                        root,
                        journal,
                        "paperless_rollback_container_state_ambiguous",
                    );
                }
            };
        let desired = original && items[index].running;
        if states[index] == desired {
            continue;
        }
        if desired {
            let (other_project, other_items) = if old {
                (&journal.current_project, &journal.current)
            } else {
                (&journal.rollback_project, &journal.old)
            };
            let others =
                observe_generation(executor, engine, root, binding, other_project, other_items)
                    .await;
            if others
                .and_then(|states| require_states(&states, other_items, false))
                .is_err()
            {
                return hold(
                    root,
                    journal,
                    "paperless_rollback_other_generation_not_stopped",
                );
            }
        }
        let action = if desired { "start" } else { "stop" };
        journal.pending_command = Some(RollbackCommand {
            action: action.to_owned(),
            id: items[index].id.clone(),
        });
        write_journal(root, journal)?;
        ensure_stage(root, binding)?;
        let result = executor
            .run(
                &engine.docker("container", &[action, &items[index].id]),
                &root.display,
            )
            .await;
        if result.is_err() {
            return hold(
                root,
                journal,
                if desired {
                    "paperless_rollback_start_ambiguous"
                } else {
                    "paperless_rollback_stop_ambiguous"
                },
            );
        }
        let observed = observe_generation(executor, engine, root, binding, &project, &items).await;
        if observed.is_err()
            || observed.as_ref().is_ok_and(|observed| {
                observed.iter().enumerate().any(|(position, state)| {
                    *state
                        != if position == index {
                            desired
                        } else {
                            states[position]
                        }
                })
            })
        {
            return hold(
                root,
                journal,
                "paperless_rollback_container_state_ambiguous",
            );
        }
        journal.pending_command = None;
        write_journal(root, journal)?;
    }
    let observed = observe_generation(executor, engine, root, binding, &project, &items).await;
    if observed
        .and_then(|states| require_states(&states, &items, original))
        .is_err()
    {
        return hold(
            root,
            journal,
            "paperless_rollback_container_state_ambiguous",
        );
    }
    Ok(())
}

fn publish_authority(
    root: &OwnedPaperlessRoot,
    binding: &EnvBinding,
    receipt: &[u8],
    snapshot: &[u8],
    pointer: &RestorePriorActivePointer,
) -> Result<(), LifecycleError> {
    ensure_stage(root, binding)?;
    let parsed_receipt: StoredPaperlessInstallReceipt =
        serde_json::from_slice(receipt).map_err(|_| LifecycleError::Receipt)?;
    validate_install_receipt(&parsed_receipt, &root.display)?;
    let parsed_snapshot: PaperlessVolumeSetSnapshot =
        serde_json::from_slice(snapshot).map_err(|_| LifecycleError::Receipt)?;
    validate_volume_set_snapshot(&parsed_snapshot, &parsed_receipt.project)?;
    if parsed_receipt.volume_set_id.as_deref() != Some(parsed_snapshot.volume_set_id.as_str()) {
        return Err(LifecycleError::Receipt);
    }
    let state = lifecycle_state_dir(root)?;
    // Write the original bytes, including any whitespace. Reserializing the
    // snapshot would destroy the exact authority captured in Restore custody.
    crate::skills::store::atomic_write_private_child(
        &state,
        OsStr::new(VOLUME_SET_NAME),
        &root.display.join(RECEIPT_DIR).join(VOLUME_SET_NAME),
        snapshot,
    )
    .map_err(|_| LifecycleError::Io)?;
    ensure_stage(root, binding)?;
    write_install_receipt_bytes(root, receipt)?;
    ensure_stage(root, binding)?;
    restore_active_pointer_bytes(root, pointer)?;
    ensure_stage(root, binding)?;
    if !authority_matches(root, receipt, snapshot, pointer)? {
        return Err(LifecycleError::Receipt);
    }
    Ok(())
}

fn authority_matches(
    root: &OwnedPaperlessRoot,
    receipt: &[u8],
    snapshot: &[u8],
    pointer: &RestorePriorActivePointer,
) -> Result<bool, LifecycleError> {
    if read_install_receipt_with_bytes(root)?.0 != receipt
        || read_current_volume_set_snapshot_bytes(root)? != snapshot
    {
        return Ok(false);
    }
    let actual = read_record(root, RESTORE_ACTIVE_POINTER_NAME)?;
    Ok(match (pointer, actual) {
        (RestorePriorActivePointer::Present { bytes, sha256 }, Some(actual)) => {
            actual == *bytes && restore_digest(&actual) == *sha256
        }
        (RestorePriorActivePointer::Absent { absence }, None) => absence == "not_found",
        _ => false,
    })
}

fn receipt(
    root: &OwnedPaperlessRoot,
    journal: &RollbackJournal,
    custody: &RestoreCustody,
    bytes: &[u8],
) -> Result<PaperlessRollbackReceipt, LifecycleError> {
    let terminal = decode_journal(root, bytes)?;
    if terminal != *journal || terminal.phase != RollbackPhase::Committed {
        return Err(LifecycleError::Receipt);
    }
    if !authority_matches(
        root,
        &custody.prior_install_receipt_bytes,
        &custody.prior_volume_set_snapshot_bytes,
        custody
            .prior_active_pointer
            .as_ref()
            .ok_or(LifecycleError::Receipt)?,
    )? {
        return Err(LifecycleError::Command("paperless_rollback_terminal_stale"));
    }
    Ok(PaperlessRollbackReceipt {
        operation: ROLLBACK_OPERATION,
        restore_job_id: journal.restore_job_id.clone(),
        current_project: journal.current_project.clone(),
        rollback_project: journal.rollback_project.clone(),
        old_source_was_running: journal.old.iter().any(|item| item.running),
        authenticated_api_ready: journal.authenticated_api_ready,
        rollback_custody_ref: name(&journal.restore_job_id)?,
        rollback_custody_sha256: restore_digest(bytes),
    })
}

async fn compensate<E: ComposeExecutor>(
    root: &OwnedPaperlessRoot,
    binding: &EnvBinding,
    executor: &mut E,
    engine: &Engine,
    journal: &mut RollbackJournal,
    failure: &'static str,
) -> Result<PaperlessRollbackReceipt, LifecycleError> {
    if journal.pending_command.is_some() {
        return hold(root, journal, "paperless_rollback_compensation_ambiguous");
    }
    journal.phase = RollbackPhase::Compensating;
    write_journal(root, journal)?;
    transition_generation(executor, engine, root, binding, journal, true, false).await?;
    transition_generation(executor, engine, root, binding, journal, false, true).await?;
    if publish_authority(
        root,
        binding,
        &journal.current_install_receipt_bytes,
        &journal.current_snapshot_bytes,
        &journal.current_active_pointer,
    )
    .is_err()
    {
        return hold(root, journal, "paperless_rollback_compensation_ambiguous");
    }
    journal.phase = RollbackPhase::Compensated;
    write_new_record(
        root,
        &format!(
            ".neoth-paperless-rollback-{}-compensated.v1.json",
            journal.restore_job_id
        ),
        journal,
    )?;
    write_journal(root, journal)?;
    Err(LifecycleError::Command(failure))
}
