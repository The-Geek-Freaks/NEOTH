//! Durable retirement of one fully confirmed Paperless volume generation.

use std::collections::BTreeSet;

use super::*;

const ROTATION_NAME: &str = ".neoth-paperless-generation-rotation.v1.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RotationPhase {
    Prepared,
    Archived,
    LiveAuthorityCleared,
    NewSnapshotWritten,
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RotationArchiveRole {
    Install,
    Uninstall,
    VolumeSet,
    PurgeCustody,
    PurgeReceipt,
}

impl RotationArchiveRole {
    const ALL: [Self; 5] = [
        Self::Install,
        Self::Uninstall,
        Self::VolumeSet,
        Self::PurgeCustody,
        Self::PurgeReceipt,
    ];
    fn from_str(value: &str) -> Option<Self> {
        match value {
            "install" => Some(Self::Install),
            "uninstall" => Some(Self::Uninstall),
            "volume-set" => Some(Self::VolumeSet),
            "purge-custody" => Some(Self::PurgeCustody),
            "purge-receipt" => Some(Self::PurgeReceipt),
            _ => None,
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Uninstall => "uninstall",
            Self::VolumeSet => "volume-set",
            Self::PurgeCustody => "purge-custody",
            Self::PurgeReceipt => "purge-receipt",
        }
    }
    fn live_name(self) -> &'static str {
        match self {
            Self::Install => RECEIPT_NAME,
            Self::Uninstall => UNINSTALL_RECEIPT_NAME,
            Self::VolumeSet => VOLUME_SET_NAME,
            Self::PurgeCustody => paperless_purge::PURGE_CUSTODY_NAME,
            Self::PurgeReceipt => paperless_purge::PURGE_RECEIPT_NAME,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct RotationArchive {
    role: RotationArchiveRole,
    sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct RotationJournal {
    schema_version: u8,
    operation: String,
    phase: RotationPhase,
    project: String,
    retired_volume_set_id: String,
    new_volume_set_id: String,
    new_snapshot_bytes: Vec<u8>,
    new_snapshot_sha256: String,
    archives: Vec<RotationArchive>,
}

/// A new terminal purge is the only way to create this journal.  A completed
/// journal is retired after revalidating its immutable archive and snapshot.
pub(crate) async fn rotate_completed_purge_generation_at<E: ComposeExecutor>(
    executor: &mut E,
    engine: &Engine,
    root: &OwnedPaperlessRoot,
    binding: &EnvBinding,
) -> Result<(), LifecycleError> {
    let project = project_name(&root.display);
    let mut journal = match read_journal(root)? {
        Some(journal) => {
            validate_journal(&journal, &project)?;
            if journal.phase == RotationPhase::Prepared {
                let authority = paperless_purge::completed_purge_authority_for_rotation(
                    executor, engine, root, binding,
                )
                .await?
                .ok_or(LifecycleError::Receipt)?;
                validate_live_authority(&journal, &authority)?;
            } else if journal.phase == RotationPhase::Archived {
                let authority = archived_authority(root, &journal)?;
                paperless_purge::validate_archived_purge_authority_for_rotation(
                    executor, engine, root, binding, &authority,
                )
                .await?;
            }
            journal
        }
        None => {
            let Some(authority) = paperless_purge::completed_purge_authority_for_rotation(
                executor, engine, root, binding,
            )
            .await?
            else {
                return Ok(());
            };
            let journal = journal_from_authority(authority)?;
            write_journal_create_new(root, &journal)?;
            journal
        }
    };
    resume_rotation(root, &mut journal)?;
    if journal.phase != RotationPhase::Complete {
        return Err(LifecycleError::Receipt);
    }
    retire_complete_journal(root, &journal)
}

fn journal_from_authority(
    authority: paperless_purge::PaperlessCompletedPurgeAuthority,
) -> Result<RotationJournal, LifecycleError> {
    if authority.sources.len() != RotationArchiveRole::ALL.len()
        || !paperless_staging::valid_volume_set_id(&authority.volume_set_id)
    {
        return Err(LifecycleError::Receipt);
    }
    let new_volume_set_id = uuid::Uuid::new_v4().to_string();
    let new_snapshot = PaperlessVolumeSetSnapshot {
        schema_version: 1,
        project: authority.project.clone(),
        volume_set_id: new_volume_set_id.clone(),
        logical_volumes: paperless_staging::PAPERLESS_VOLUMES
            .iter()
            .map(|volume| volume.logical_name.to_owned())
            .collect(),
    };
    validate_volume_set_snapshot(&new_snapshot, &authority.project)?;
    let new_snapshot_bytes = serde_json::to_vec(&new_snapshot).map_err(|_| LifecycleError::Io)?;
    let mut archives = Vec::with_capacity(authority.sources.len());
    let mut roles = BTreeSet::new();
    for source in authority.sources {
        let role = RotationArchiveRole::from_str(source.role).ok_or(LifecycleError::Receipt)?;
        let digest = sha256(&source.bytes);
        if source.live_name != role.live_name() || digest != source.sha256 || !roles.insert(role) {
            return Err(LifecycleError::Receipt);
        }
        archives.push(RotationArchive {
            role,
            sha256: digest,
        });
    }
    if roles.len() != RotationArchiveRole::ALL.len() {
        return Err(LifecycleError::Receipt);
    }
    Ok(RotationJournal {
        schema_version: 1,
        operation: "paperless.generation_rotation".to_owned(),
        phase: RotationPhase::Prepared,
        project: authority.project,
        retired_volume_set_id: authority.volume_set_id,
        new_volume_set_id,
        new_snapshot_sha256: sha256(&new_snapshot_bytes),
        new_snapshot_bytes,
        archives,
    })
}

fn validate_live_authority(
    journal: &RotationJournal,
    authority: &paperless_purge::PaperlessCompletedPurgeAuthority,
) -> Result<(), LifecycleError> {
    if authority.project != journal.project
        || authority.volume_set_id != journal.retired_volume_set_id
        || authority.sources.len() != journal.archives.len()
    {
        return Err(LifecycleError::Receipt);
    }
    let mut seen = BTreeSet::new();
    for source in &authority.sources {
        let role = RotationArchiveRole::from_str(source.role).ok_or(LifecycleError::Receipt)?;
        let archive = journal
            .archives
            .iter()
            .find(|archive| archive.role == role)
            .ok_or(LifecycleError::Receipt)?;
        if !seen.insert(role)
            || source.live_name != role.live_name()
            || sha256(&source.bytes) != archive.sha256
            || source.sha256 != archive.sha256
        {
            return Err(LifecycleError::Receipt);
        }
    }
    (seen.len() == RotationArchiveRole::ALL.len())
        .then_some(())
        .ok_or(LifecycleError::Receipt)
}

fn archived_authority(
    root: &OwnedPaperlessRoot,
    journal: &RotationJournal,
) -> Result<paperless_purge::PaperlessCompletedPurgeAuthority, LifecycleError> {
    validate_archives(root, journal, true)?;
    let mut sources = Vec::with_capacity(journal.archives.len());
    for archive in &journal.archives {
        let bytes = read_required_child(root, &archive_name(journal, archive))?;
        if sha256(&bytes) != archive.sha256 {
            return Err(LifecycleError::Receipt);
        }
        sources.push(paperless_purge::PaperlessPurgeAuthoritySource {
            role: archive.role.as_str(),
            live_name: archive.role.live_name().to_owned(),
            sha256: archive.sha256.clone(),
            bytes,
        });
    }
    Ok(paperless_purge::PaperlessCompletedPurgeAuthority {
        project: journal.project.clone(),
        volume_set_id: journal.retired_volume_set_id.clone(),
        sources,
    })
}

fn resume_rotation(
    root: &OwnedPaperlessRoot,
    journal: &mut RotationJournal,
) -> Result<(), LifecycleError> {
    validate_journal(journal, &project_name(&root.display))?;
    validate_archives(root, journal, journal.phase != RotationPhase::Prepared)?;
    if journal.phase == RotationPhase::Prepared {
        for archive in &journal.archives {
            let source = read_required_child(root, archive.role.live_name())?;
            if sha256(&source) != archive.sha256 {
                return Err(LifecycleError::Receipt);
            }
            write_or_verify_archive(root, &archive_name(journal, archive), &source)?;
        }
        validate_archives(root, journal, true)?;
        journal.phase = RotationPhase::Archived;
        write_journal(root, journal)?;
    }
    if journal.phase == RotationPhase::Archived {
        validate_archives(root, journal, true)?;
        for archive in &journal.archives {
            let archived = read_required_child(root, &archive_name(journal, archive))?;
            if let Some(live) = read_optional_child(root, archive.role.live_name())? {
                if live != archived {
                    return Err(LifecycleError::Receipt);
                }
                remove_exact_child(root, archive.role.live_name())?;
            }
        }
        journal.phase = RotationPhase::LiveAuthorityCleared;
        write_journal(root, journal)?;
    }
    if journal.phase == RotationPhase::LiveAuthorityCleared {
        validate_archives(root, journal, true)?;
        let snapshot: PaperlessVolumeSetSnapshot =
            serde_json::from_slice(&journal.new_snapshot_bytes)
                .map_err(|_| LifecycleError::Receipt)?;
        validate_volume_set_snapshot(&snapshot, &journal.project)?;
        match read_optional_child(root, VOLUME_SET_NAME)? {
            Some(bytes) if bytes == journal.new_snapshot_bytes => {}
            Some(_) => return Err(LifecycleError::Receipt),
            None => write_create_new(root, VOLUME_SET_NAME, &journal.new_snapshot_bytes)?,
        }
        journal.phase = RotationPhase::NewSnapshotWritten;
        write_journal(root, journal)?;
    }
    if journal.phase == RotationPhase::NewSnapshotWritten {
        validate_archives(root, journal, true)?;
        validate_new_snapshot(root, journal)?;
        journal.phase = RotationPhase::Complete;
        write_journal(root, journal)?;
    }
    if journal.phase == RotationPhase::Complete {
        validate_new_snapshot(root, journal)?;
    }
    validate_archives(root, journal, journal.phase != RotationPhase::Prepared)
}

fn validate_journal(journal: &RotationJournal, project: &str) -> Result<(), LifecycleError> {
    let mut roles = BTreeSet::new();
    if journal.schema_version != 1
        || journal.operation != "paperless.generation_rotation"
        || journal.project != project
        || !paperless_staging::valid_volume_set_id(&journal.retired_volume_set_id)
        || !paperless_staging::valid_volume_set_id(&journal.new_volume_set_id)
        || journal.retired_volume_set_id == journal.new_volume_set_id
        || journal.archives.len() != RotationArchiveRole::ALL.len()
        || sha256(&journal.new_snapshot_bytes) != journal.new_snapshot_sha256
        || journal.archives.iter().any(|archive| {
            archive.sha256.len() != 64
                || !archive.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
                || !roles.insert(archive.role)
        })
        || roles.len() != RotationArchiveRole::ALL.len()
    {
        return Err(LifecycleError::Receipt);
    }
    let snapshot: PaperlessVolumeSetSnapshot =
        serde_json::from_slice(&journal.new_snapshot_bytes).map_err(|_| LifecycleError::Receipt)?;
    validate_volume_set_snapshot(&snapshot, project)?;
    (snapshot.volume_set_id == journal.new_volume_set_id)
        .then_some(())
        .ok_or(LifecycleError::Receipt)
}

fn archive_name(journal: &RotationJournal, archive: &RotationArchive) -> String {
    format!(
        ".neoth-paperless-retired-{}-{}-{}.v1.json",
        journal.retired_volume_set_id,
        archive.role.as_str(),
        &archive.sha256[..16]
    )
}

fn validate_archives(
    root: &OwnedPaperlessRoot,
    journal: &RotationJournal,
    required: bool,
) -> Result<(), LifecycleError> {
    for archive in &journal.archives {
        match read_optional_child(root, &archive_name(journal, archive))? {
            Some(bytes) if sha256(&bytes) == archive.sha256 => {}
            Some(_) => return Err(LifecycleError::Receipt),
            None if required => return Err(LifecycleError::Receipt),
            None => {}
        }
    }
    Ok(())
}

fn validate_new_snapshot(
    root: &OwnedPaperlessRoot,
    journal: &RotationJournal,
) -> Result<(), LifecycleError> {
    let snapshot = read_volume_set_snapshot(root)?.ok_or(LifecycleError::Receipt)?;
    validate_volume_set_snapshot(&snapshot, &journal.project)?;
    if snapshot.volume_set_id != journal.new_volume_set_id
        || serde_json::to_vec(&snapshot).map_err(|_| LifecycleError::Io)?
            != journal.new_snapshot_bytes
    {
        return Err(LifecycleError::Receipt);
    }
    Ok(())
}

fn retire_complete_journal(
    root: &OwnedPaperlessRoot,
    journal: &RotationJournal,
) -> Result<(), LifecycleError> {
    validate_archives(root, journal, true)?;
    let expected = serde_json::to_vec(journal).map_err(|_| LifecycleError::Io)?;
    if read_required_child(root, ROTATION_NAME)? != expected {
        return Err(LifecycleError::Receipt);
    }
    remove_exact_child(root, ROTATION_NAME)
}

fn state(root: &OwnedPaperlessRoot) -> Result<cap_std::fs::Dir, LifecycleError> {
    lifecycle_state_dir(root)
}
fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn read_optional_child(
    root: &OwnedPaperlessRoot,
    name: &str,
) -> Result<Option<Vec<u8>>, LifecycleError> {
    let state = state(root)?;
    match crate::skills::store::read_regular_file_bounded(
        &state,
        OsStr::new(name),
        &root.display.join(RECEIPT_DIR).join(name),
        RECEIPT_READ_LIMIT,
    ) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error)
            if error
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(_) => Err(LifecycleError::Receipt),
    }
}
fn read_required_child(root: &OwnedPaperlessRoot, name: &str) -> Result<Vec<u8>, LifecycleError> {
    read_optional_child(root, name)?.ok_or(LifecycleError::Receipt)
}
fn write_create_new(
    root: &OwnedPaperlessRoot,
    name: &str,
    bytes: &[u8],
) -> Result<(), LifecycleError> {
    let state = state(root)?;
    crate::skills::store::atomic_write_private_child_create_new(
        &state,
        OsStr::new(name),
        &root.display.join(RECEIPT_DIR).join(name),
        bytes,
    )
    .map_err(|_| LifecycleError::Io)?;
    ensure_bound(root)
}
fn write_replace(
    root: &OwnedPaperlessRoot,
    name: &str,
    bytes: &[u8],
) -> Result<(), LifecycleError> {
    let state = state(root)?;
    crate::skills::store::atomic_write_private_child(
        &state,
        OsStr::new(name),
        &root.display.join(RECEIPT_DIR).join(name),
        bytes,
    )
    .map_err(|_| LifecycleError::Io)?;
    ensure_bound(root)
}
fn remove_exact_child(root: &OwnedPaperlessRoot, name: &str) -> Result<(), LifecycleError> {
    let state = state(root)?;
    crate::skills::store::remove_child_file(
        &state,
        OsStr::new(name),
        &root.display.join(RECEIPT_DIR).join(name),
    )
    .map_err(|_| LifecycleError::Io)?;
    ensure_bound(root)
}
fn write_or_verify_archive(
    root: &OwnedPaperlessRoot,
    name: &str,
    bytes: &[u8],
) -> Result<(), LifecycleError> {
    match read_optional_child(root, name)? {
        Some(existing) if existing == bytes => Ok(()),
        Some(_) => Err(LifecycleError::Receipt),
        None => write_create_new(root, name, bytes),
    }
}
fn read_journal(root: &OwnedPaperlessRoot) -> Result<Option<RotationJournal>, LifecycleError> {
    read_optional_child(root, ROTATION_NAME)?
        .map(|bytes| serde_json::from_slice(&bytes).map_err(|_| LifecycleError::Receipt))
        .transpose()
}
fn write_journal_create_new(
    root: &OwnedPaperlessRoot,
    journal: &RotationJournal,
) -> Result<(), LifecycleError> {
    write_create_new(
        root,
        ROTATION_NAME,
        &serde_json::to_vec(journal).map_err(|_| LifecycleError::Io)?,
    )
}
fn write_journal(
    root: &OwnedPaperlessRoot,
    journal: &RotationJournal,
) -> Result<(), LifecycleError> {
    write_replace(
        root,
        ROTATION_NAME,
        &serde_json::to_vec(journal).map_err(|_| LifecycleError::Io)?,
    )
}

#[cfg(test)]
#[path = "paperless_generation_rotation_tests.rs"]
mod tests;
