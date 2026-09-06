//! Crash-safe preservation of a corrupt code-map SQLite store.
//!
//! This module deliberately has no rebuild logic. Its sole authority is to
//! move the exact database leaf and its SQLite sidecars into unique forensic
//! names after a durable manifest has bound every allowed artifact. A normal
//! lifecycle refresh must refuse to proceed while that manifest exists.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

const MANIFEST_SUFFIX: &str = ".corrupt-repair-pending";
const MANIFEST_SCHEMA_VERSION: u8 = 1;
const MAX_MANIFEST_BYTES: u64 = 32 * 1024;
const MAX_PATH_BYTES: usize = 4 * 1024;
const ARTIFACT_COUNT: usize = 3;

#[derive(Clone, Debug)]
struct RepairLayout {
    database: PathBuf,
    parent: PathBuf,
    artifacts: [PathBuf; ARTIFACT_COUNT],
    manifest: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepairManifest {
    schema_version: u8,
    phase: RepairPhase,
    database_path: String,
    parent_path: String,
    parent_identity: ParentIdentity,
    artifacts: Vec<RepairArtifact>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RepairPhase {
    Prepared,
    Completed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ParentIdentity {
    canonical_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    unix_device: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unix_inode: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    windows_creation_time: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepairArtifact {
    role: ArtifactRole,
    source_path: String,
    preserved_path: String,
    source_identity: Option<FileIdentity>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ArtifactRole {
    Main,
    Wal,
    Shm,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileIdentity {
    length: u64,
    modified_unix_nanos: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    unix_device: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unix_inode: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    windows_creation_time: Option<u64>,
}

/// Return an error while a durable corrupt-store preservation manifest exists.
///
/// Lifecycle inspection calls this before opening SQLite, including when the
/// database leaf itself has already moved. A malformed or substituted manifest
/// also fails closed so a refresh can never recreate a database over incomplete
/// forensic preservation.
pub(crate) fn inspection_error(database_path: &Path) -> Result<()> {
    let layout = layout_for(database_path)?;
    let Some(manifest) = read_manifest(&layout)? else {
        return Ok(());
    };
    validate_manifest(&manifest, &layout)?;
    match manifest.phase {
        RepairPhase::Prepared => anyhow::bail!(
            "corrupt code-map preservation is pending; explicit repair resume is required"
        ),
        // Windows deliberately retains a terminal manifest instead of claiming
        // that an ordinary DeleteFile namespace update was crash-durable.
        RepairPhase::Completed => verify_terminal_accounting(&layout, &manifest),
    }
}

/// Start or explicitly resume corrupt-store preservation.
///
/// The manifest is published durably before the first rename. If a crash or
/// I/O failure lands between moves, a subsequent explicit invocation verifies
/// the original accounting and completes only the still-unmoved allowlisted
/// artifacts. Unix removes the pending manifest only after every declared
/// artifact is accounted for; Windows retains a durably published terminal
/// manifest because ordinary marker deletion has no equivalent proof.
pub(crate) fn preserve_explicitly<F>(database_path: &Path, checkpoint: F) -> Result<()>
where
    F: FnMut() -> Result<()>,
{
    preserve_with_checkpoint(database_path, checkpoint)
}

fn preserve_with_checkpoint<F>(database_path: &Path, mut checkpoint: F) -> Result<()>
where
    F: FnMut() -> Result<()>,
{
    let layout = layout_for(database_path)?;
    // Do not even publish the durable intent after cancellation has been
    // requested. A resumed manifest remains safe because each remaining move
    // gets the same checkpoint immediately before the namespace mutation.
    checkpoint()?;
    let manifest = match read_manifest(&layout)? {
        Some(manifest) => {
            validate_manifest(&manifest, &layout)?;
            manifest
        }
        None => install_manifest(&layout)?,
    };
    match manifest.phase {
        RepairPhase::Prepared => complete_manifest(&layout, &manifest, &mut checkpoint),
        RepairPhase::Completed => verify_terminal_accounting(&layout, &manifest),
    }
}

fn layout_for(database_path: &Path) -> Result<RepairLayout> {
    let parent = database_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .context("code-map database path has no parent")?
        .to_path_buf();
    let name = database_path
        .file_name()
        .filter(|name| !name.is_empty())
        .context("code-map database path has no file name")?;
    ensure!(
        name != "." && name != "..",
        "invalid code-map database leaf name"
    );
    let database = parent.join(name);
    ensure!(
        database == database_path,
        "code-map database path is not a direct parent leaf"
    );
    let as_text = exact_path(&database, "code-map database path")?;
    ensure!(
        as_text.len() <= MAX_PATH_BYTES,
        "code-map database path exceeds preservation bound"
    );
    let wal = PathBuf::from(format!("{}-wal", database.display()));
    let shm = PathBuf::from(format!("{}-shm", database.display()));
    let manifest = PathBuf::from(format!("{}{MANIFEST_SUFFIX}", database.display()));
    for path in [&wal, &shm, &manifest] {
        ensure!(
            path.parent() == Some(parent.as_path()),
            "code-map preservation path escaped database parent"
        );
        ensure!(
            exact_path(path, "code-map preservation path")?.len() <= MAX_PATH_BYTES,
            "code-map preservation path exceeds bound"
        );
    }
    Ok(RepairLayout {
        database,
        parent,
        artifacts: [database_path.to_path_buf(), wal, shm],
        manifest,
    })
}

fn install_manifest(layout: &RepairLayout) -> Result<RepairManifest> {
    let parent_identity = parent_identity(&layout.parent)?;
    let suffix = format!("corrupt-{}", uuid::Uuid::now_v7());
    let artifacts = layout
        .artifacts
        .iter()
        .enumerate()
        .map(|(index, source)| {
            let preserved = PathBuf::from(format!("{}.{}", source.display(), suffix));
            ensure!(
                preserved.parent() == Some(layout.parent.as_path()),
                "preserved code-map evidence escaped database parent"
            );
            let source_identity = optional_file_identity(source, "corrupt code-map evidence")?;
            ensure!(
                optional_file_identity(&preserved, "preserved corrupt code-map evidence")?
                    .is_none(),
                "refusing to overwrite existing preserved corrupt code-map evidence {}",
                preserved.display()
            );
            Ok(RepairArtifact {
                role: match index {
                    0 => ArtifactRole::Main,
                    1 => ArtifactRole::Wal,
                    2 => ArtifactRole::Shm,
                    _ => unreachable!("fixed artifact allowlist has exactly three entries"),
                },
                source_path: exact_path(source, "corrupt code-map evidence")?,
                preserved_path: exact_path(&preserved, "preserved corrupt code-map evidence")?,
                source_identity,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let manifest = RepairManifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        phase: RepairPhase::Prepared,
        database_path: exact_path(&layout.database, "code-map database path")?,
        parent_path: exact_path(&layout.parent, "code-map database parent")?,
        parent_identity,
        artifacts,
    };
    validate_manifest(&manifest, layout)?;
    let mut bytes =
        serde_json::to_vec_pretty(&manifest).context("serialize corrupt repair manifest")?;
    bytes.push(b'\n');
    ensure!(
        bytes.len() as u64 <= MAX_MANIFEST_BYTES,
        "corrupt repair manifest exceeds bound"
    );
    match crate::util::atomic_write::write_private_create_new_durable(&layout.manifest, &bytes) {
        Ok(()) => read_manifest(layout)?
            .context("corrupt repair manifest disappeared after durable install"),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => read_manifest(layout)?
            .context("corrupt repair manifest disappeared after concurrent install"),
        Err(error) => Err(error).with_context(|| {
            format!(
                "durably install corrupt code-map repair manifest {}",
                layout.manifest.display()
            )
        }),
    }
}

fn complete_manifest(
    layout: &RepairLayout,
    manifest: &RepairManifest,
    checkpoint: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    validate_manifest(manifest, layout)?;
    ensure!(
        manifest.phase == RepairPhase::Prepared,
        "only a prepared corrupt repair manifest may move evidence"
    );
    for artifact in &manifest.artifacts {
        ensure_parent_unchanged(&layout.parent, &manifest.parent_identity)?;
        let source = Path::new(&artifact.source_path);
        let preserved = Path::new(&artifact.preserved_path);
        let source_observed = optional_file_identity(source, "corrupt code-map evidence")?;
        let preserved_observed =
            optional_file_identity(preserved, "preserved corrupt code-map evidence")?;
        match (
            &artifact.source_identity,
            source_observed,
            preserved_observed,
        ) {
            (None, None, None) => {}
            (None, Some(_), None) => anyhow::bail!(
                "unexpected code-map artifact appeared after preservation was prepared: {}",
                source.display()
            ),
            (None, None, Some(_)) | (None, Some(_), Some(_)) => anyhow::bail!(
                "unexpected preserved artifact for absent source: {}",
                preserved.display()
            ),
            (Some(expected), Some(observed), None) => {
                ensure!(
                    &observed == expected,
                    "corrupt code-map evidence changed after preservation was prepared: {}",
                    source.display()
                );
                checkpoint()?;
                rename_preserving(source, preserved)?;
                let preserved_after =
                    optional_file_identity(preserved, "preserved corrupt code-map evidence")?
                        .context("preserved code-map evidence disappeared after rename")?;
                ensure!(
                    &preserved_after == expected,
                    "preserved code-map evidence identity changed during rename: {}",
                    preserved.display()
                );
            }
            (Some(expected), None, Some(observed)) => ensure!(
                &observed == expected,
                "preserved code-map evidence identity does not match manifest: {}",
                preserved.display()
            ),
            (Some(_), None, None) => anyhow::bail!(
                "code-map evidence vanished before preservation completed: {}",
                source.display()
            ),
            (Some(_), Some(_), Some(_)) => anyhow::bail!(
                "both source and preserved code-map evidence exist; refusing ambiguous accounting: {}",
                source.display()
            ),
        }
    }
    ensure_parent_unchanged(&layout.parent, &manifest.parent_identity)?;
    checkpoint()?;
    complete_manifest_terminal(layout, manifest)
}

fn rename_preserving(source: &Path, preserved: &Path) -> Result<()> {
    ensure!(
        optional_file_identity(preserved, "preserved corrupt code-map evidence")?.is_none(),
        "refusing to overwrite preserved corrupt code-map evidence {}",
        preserved.display()
    );
    durable_rename_no_replace(source, preserved).with_context(|| {
        format!(
            "durably preserve corrupt code-map evidence {} as {}",
            source.display(),
            preserved.display()
        )
    })
}

/// Same-parent, destination-absent rename with a platform-specific namespace
/// durability proof. The ordinary `std::fs::rename` path is deliberately not
/// accepted on Windows: a later no-op directory sync cannot prove that its
/// namespace update survived a crash.
fn durable_rename_no_replace(source: &Path, preserved: &Path) -> std::io::Result<()> {
    if source.parent() != preserved.parent() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "corrupt evidence rename escaped its parent directory",
        ));
    }

    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};

        let source_wide = source
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let preserved_wide = preserved
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        // SAFETY: both paths are exact same-parent leaf paths, encoded as
        // live NUL-terminated UTF-16 buffers for the call. Omitting
        // REPLACE_EXISTING makes a destination race fail closed. Microsoft's
        // MOVEFILE_WRITE_THROUGH contract waits for the move to reach disk.
        if unsafe {
            MoveFileExW(
                source_wide.as_ptr(),
                preserved_wide.as_ptr(),
                MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(unix)]
    {
        fs::rename(source, preserved)?;
        let parent = preserved.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "preserved evidence has no parent",
            )
        })?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (source, preserved);
        Err(std::io::Error::other(
            "corrupt evidence preservation has no proven durable rename on this platform",
        ))
    }
}

/// Check that every manifest entry reached exactly one terminal position.
/// This is used for a Windows retained terminal manifest as well as by an
/// explicit restart/resume before allowing a normal lifecycle refresh.
fn verify_terminal_accounting(layout: &RepairLayout, manifest: &RepairManifest) -> Result<()> {
    validate_manifest(manifest, layout)?;
    ensure_parent_unchanged(&layout.parent, &manifest.parent_identity)?;
    for artifact in &manifest.artifacts {
        let source = Path::new(&artifact.source_path);
        let preserved = Path::new(&artifact.preserved_path);
        let source_observed = optional_file_identity(source, "corrupt code-map evidence")?;
        let preserved_observed =
            optional_file_identity(preserved, "preserved corrupt code-map evidence")?;
        match (
            &artifact.source_identity,
            source_observed,
            preserved_observed,
        ) {
            (None, None, None) => {}
            (Some(expected), None, Some(observed)) if &observed == expected => {}
            (None, _, _) => anyhow::bail!(
                "terminal corrupt repair accounting changed for an originally absent artifact: {}",
                source.display()
            ),
            (Some(_), _, _) => anyhow::bail!(
                "terminal corrupt repair accounting is incomplete or ambiguous for {}",
                source.display()
            ),
        }
    }
    Ok(())
}

fn complete_manifest_terminal(layout: &RepairLayout, manifest: &RepairManifest) -> Result<()> {
    #[cfg(windows)]
    {
        let mut terminal = manifest.clone();
        terminal.phase = RepairPhase::Completed;
        write_terminal_manifest(layout, &terminal)?;
        let observed =
            read_manifest(layout)?.context("terminal corrupt repair manifest disappeared")?;
        ensure!(
            observed.phase == RepairPhase::Completed,
            "terminal corrupt repair manifest phase was not durably published"
        );
        verify_terminal_accounting(layout, &observed)
    }

    #[cfg(unix)]
    {
        let _ = manifest;
        crate::util::atomic_write::durable_remove_file(&layout.manifest).with_context(|| {
            format!(
                "durably clear completed corrupt code-map repair manifest {}",
                layout.manifest.display()
            )
        })?;
        Ok(())
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (layout, manifest);
        anyhow::bail!(
            "corrupt repair completion has no proven durable terminal state on this platform"
        )
    }
}

#[cfg(windows)]
fn write_terminal_manifest(layout: &RepairLayout, manifest: &RepairManifest) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(manifest)
        .context("serialize terminal corrupt repair manifest")?;
    bytes.push(b'\n');
    ensure!(
        bytes.len() as u64 <= MAX_MANIFEST_BYTES,
        "terminal corrupt repair manifest exceeds bound"
    );
    // atomic_write_private publishes its staged private file through the
    // project's handle-bound FILE_FLAG_WRITE_THROUGH rename on Windows.
    crate::util::atomic_write::atomic_write_private(&layout.manifest, &bytes).with_context(|| {
        format!(
            "durably publish terminal corrupt repair manifest {}",
            layout.manifest.display()
        )
    })
}

fn read_manifest(layout: &RepairLayout) -> Result<Option<RepairManifest>> {
    let metadata = match fs::symlink_metadata(&layout.manifest) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "inspect corrupt repair manifest {}",
                    layout.manifest.display()
                )
            });
        }
    };
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "corrupt repair manifest is not a regular non-symlink file: {}",
        layout.manifest.display()
    );
    ensure!(
        metadata.len() <= MAX_MANIFEST_BYTES,
        "corrupt repair manifest exceeds bound"
    );
    let bytes = fs::read(&layout.manifest)
        .with_context(|| format!("read corrupt repair manifest {}", layout.manifest.display()))?;
    ensure!(
        bytes.len() as u64 == metadata.len(),
        "corrupt repair manifest changed during read"
    );
    let manifest = serde_json::from_slice(&bytes).context("parse corrupt repair manifest")?;
    Ok(Some(manifest))
}

fn validate_manifest(manifest: &RepairManifest, layout: &RepairLayout) -> Result<()> {
    ensure!(
        manifest.schema_version == MANIFEST_SCHEMA_VERSION,
        "unsupported corrupt repair manifest schema"
    );
    ensure!(
        manifest.database_path == exact_path(&layout.database, "code-map database path")?,
        "corrupt repair manifest database path does not match requested database"
    );
    ensure!(
        manifest.parent_path == exact_path(&layout.parent, "code-map database parent")?,
        "corrupt repair manifest parent path does not match requested database"
    );
    ensure!(
        manifest.artifacts.len() == ARTIFACT_COUNT,
        "corrupt repair manifest does not declare the exact SQLite artifact allowlist"
    );
    ensure_parent_unchanged(&layout.parent, &manifest.parent_identity)?;
    for (index, artifact) in manifest.artifacts.iter().enumerate() {
        let source = &layout.artifacts[index];
        ensure!(
            matches!(
                (&artifact.role, index),
                (ArtifactRole::Main, 0) | (ArtifactRole::Wal, 1) | (ArtifactRole::Shm, 2)
            ),
            "corrupt repair manifest artifact roles are not the SQLite main/wal/shm allowlist"
        );
        ensure!(
            artifact.source_path == exact_path(source, "corrupt code-map evidence")?,
            "corrupt repair manifest source path differs from SQLite allowlist"
        );
        let preserved = PathBuf::from(&artifact.preserved_path);
        ensure!(
            preserved.parent() == Some(layout.parent.as_path()),
            "corrupt repair manifest preserved path escaped database parent"
        );
        let expected_prefix = format!("{}.corrupt-", source.display());
        ensure!(
            artifact.preserved_path.starts_with(&expected_prefix),
            "corrupt repair manifest preserved path is outside the generated forensic namespace"
        );
        let suffix = artifact
            .preserved_path
            .strip_prefix(&expected_prefix)
            .context("corrupt repair manifest preserved path lacks forensic suffix")?;
        ensure!(
            uuid::Uuid::parse_str(suffix).is_ok(),
            "corrupt repair manifest preserved path has invalid forensic suffix"
        );
    }
    let suffixes: Vec<&str> = manifest
        .artifacts
        .iter()
        .map(|artifact| {
            artifact
                .preserved_path
                .rsplit_once(".corrupt-")
                .map(|(_, suffix)| suffix)
        })
        .collect::<Option<Vec<_>>>()
        .context("corrupt repair manifest lacks forensic suffix")?;
    ensure!(
        suffixes.windows(2).all(|pair| pair[0] == pair[1]),
        "corrupt repair manifest artifacts do not share one forensic destination suffix"
    );
    Ok(())
}

fn optional_file_identity(path: &Path, label: &str) -> Result<Option<FileIdentity>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("inspect {label} {}", path.display()));
        }
    };
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "{label} is not a regular non-symlink file: {}",
        path.display()
    );
    file_identity_from_metadata(&metadata).map(Some)
}

fn file_identity_from_metadata(metadata: &fs::Metadata) -> Result<FileIdentity> {
    let modified_unix_nanos = u64::try_from(
        metadata
            .modified()
            .context("read code-map artifact modification time")?
            .duration_since(UNIX_EPOCH)
            .context("code-map artifact modification time predates Unix epoch")?
            .as_nanos(),
    )
    .context("code-map artifact modification time exceeds manifest range")?;
    #[cfg(unix)]
    let (unix_device, unix_inode) = {
        use std::os::unix::fs::MetadataExt as _;
        (Some(metadata.dev()), Some(metadata.ino()))
    };
    #[cfg(not(unix))]
    let (unix_device, unix_inode) = (None, None);
    #[cfg(windows)]
    let windows_creation_time = {
        use std::os::windows::fs::MetadataExt as _;
        Some(metadata.creation_time())
    };
    #[cfg(not(windows))]
    let windows_creation_time = None;
    Ok(FileIdentity {
        length: metadata.len(),
        modified_unix_nanos,
        unix_device,
        unix_inode,
        windows_creation_time,
    })
}

fn parent_identity(parent: &Path) -> Result<ParentIdentity> {
    let metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("inspect code-map database parent {}", parent.display()))?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "code-map database parent is not a regular non-symlink directory"
    );
    let canonical_path = exact_path(
        &fs::canonicalize(parent).with_context(|| {
            format!("canonicalize code-map database parent {}", parent.display())
        })?,
        "canonical code-map database parent",
    )?;
    #[cfg(unix)]
    let (unix_device, unix_inode) = {
        use std::os::unix::fs::MetadataExt as _;
        (Some(metadata.dev()), Some(metadata.ino()))
    };
    #[cfg(not(unix))]
    let (unix_device, unix_inode) = (None, None);
    #[cfg(windows)]
    let windows_creation_time = {
        use std::os::windows::fs::MetadataExt as _;
        Some(metadata.creation_time())
    };
    #[cfg(not(windows))]
    let windows_creation_time = None;
    Ok(ParentIdentity {
        canonical_path,
        unix_device,
        unix_inode,
        windows_creation_time,
    })
}

fn ensure_parent_unchanged(parent: &Path, expected: &ParentIdentity) -> Result<()> {
    ensure!(
        &parent_identity(parent)? == expected,
        "code-map database parent changed during corrupt evidence preservation"
    );
    Ok(())
}

fn exact_path(path: &Path, label: &str) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .with_context(|| format!("{label} is not valid UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn layout(database: &Path) -> RepairLayout {
        layout_for(database).expect("valid temporary database layout")
    }

    fn destinations(database: &Path) -> Vec<PathBuf> {
        let repair_layout = layout(database);
        let manifest = read_manifest(&repair_layout)
            .expect("read manifest")
            .expect("manifest exists");
        manifest
            .artifacts
            .iter()
            .map(|artifact| PathBuf::from(&artifact.preserved_path))
            .collect()
    }

    #[test]
    fn corrupt_sqlite_set_is_preserved_as_exact_leaf_artifacts() {
        let workspace = tempdir().unwrap();
        let database = workspace.path().join("code_map.db");
        let wal = PathBuf::from(format!("{}-wal", database.display()));
        let shm = PathBuf::from(format!("{}-shm", database.display()));
        fs::write(&database, b"broken-main").unwrap();
        fs::write(&wal, b"broken-wal").unwrap();
        fs::write(&shm, b"broken-shm").unwrap();

        preserve_explicitly(&database, || Ok(())).unwrap();

        assert!(!database.exists());
        assert!(!wal.exists());
        assert!(!shm.exists());
        #[cfg(not(windows))]
        assert!(read_manifest(&layout(&database)).unwrap().is_none());
        #[cfg(windows)]
        assert_eq!(
            read_manifest(&layout(&database))
                .unwrap()
                .expect("Windows retains terminal manifest")
                .phase,
            RepairPhase::Completed
        );
        let entries: Vec<_> = fs::read_dir(workspace.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        #[cfg(not(windows))]
        assert_eq!(entries.len(), 3);
        #[cfg(windows)]
        assert_eq!(entries.len(), 4);
        assert!(
            entries
                .iter()
                .any(|path| fs::read(path).unwrap() == b"broken-main")
        );
        assert!(
            entries
                .iter()
                .any(|path| fs::read(path).unwrap() == b"broken-wal")
        );
        assert!(
            entries
                .iter()
                .any(|path| fs::read(path).unwrap() == b"broken-shm")
        );
    }

    #[test]
    fn non_regular_artifact_is_rejected_before_manifest_install() {
        let workspace = tempdir().unwrap();
        let database = workspace.path().join("code_map.db");
        fs::create_dir(&database).unwrap();

        assert!(preserve_explicitly(&database, || Ok(())).is_err());
        assert!(database.is_dir());
        assert!(read_manifest(&layout(&database)).unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_artifact_is_rejected_before_manifest_install() {
        use std::os::unix::fs::symlink;

        let workspace = tempdir().unwrap();
        let database = workspace.path().join("code_map.db");
        let outside = workspace.path().join("outside.db");
        fs::write(&outside, b"do not follow").unwrap();
        symlink(&outside, &database).unwrap();

        assert!(preserve_explicitly(&database, || Ok(())).is_err());
        assert!(
            fs::symlink_metadata(&database)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(&outside).unwrap(), b"do not follow");
    }

    #[test]
    fn cancellation_after_first_move_keeps_manifest_until_explicit_resume() {
        let workspace = tempdir().unwrap();
        let database = workspace.path().join("code_map.db");
        let wal = PathBuf::from(format!("{}-wal", database.display()));
        let shm = PathBuf::from(format!("{}-shm", database.display()));
        fs::write(&database, b"main").unwrap();
        fs::write(&wal, b"wal").unwrap();
        fs::write(&shm, b"shm").unwrap();

        let mut checkpoints = 0;
        assert!(
            preserve_explicitly(&database, || {
                checkpoints += 1;
                anyhow::ensure!(
                    checkpoints < 3,
                    "simulated cancellation before the second move"
                );
                Ok(())
            })
            .is_err()
        );
        let repair_layout = layout(&database);
        assert!(repair_layout.manifest.exists());
        assert!(
            !database.exists(),
            "first artifact must have moved before interruption"
        );
        assert!(wal.exists());
        assert!(shm.exists());
        assert!(inspection_error(&database).is_err());
        let preserved = destinations(&database);
        assert!(preserved[0].exists());

        preserve_explicitly(&database, || Ok(())).unwrap();

        #[cfg(not(windows))]
        assert!(read_manifest(&repair_layout).unwrap().is_none());
        #[cfg(windows)]
        {
            let terminal = read_manifest(&repair_layout)
                .unwrap()
                .expect("Windows retains a durable terminal manifest");
            assert_eq!(terminal.phase, RepairPhase::Completed);
            assert!(inspection_error(&database).is_ok());
        }
        assert!(preserved.iter().all(|path| path.exists()));
        assert!(!database.exists());
        assert!(!wal.exists());
        assert!(!shm.exists());
    }

    #[test]
    fn tampered_manifest_fails_closed_without_touching_remaining_artifacts() {
        let workspace = tempdir().unwrap();
        let database = workspace.path().join("code_map.db");
        let wal = PathBuf::from(format!("{}-wal", database.display()));
        fs::write(&database, b"main").unwrap();
        fs::write(&wal, b"wal").unwrap();

        let mut checkpoints = 0;
        let _ = preserve_explicitly(&database, || {
            checkpoints += 1;
            anyhow::ensure!(
                checkpoints < 3,
                "simulated cancellation before the second move"
            );
            Ok(())
        });
        let repair_layout = layout(&database);
        fs::write(&repair_layout.manifest, b"{not valid json").unwrap();

        assert!(inspection_error(&database).is_err());
        assert!(preserve_explicitly(&database, || Ok(())).is_err());
        assert!(
            wal.exists(),
            "remaining source must remain forensic evidence"
        );
    }

    #[test]
    fn unknown_sibling_files_are_untouched() {
        let workspace = tempdir().unwrap();
        let database = workspace.path().join("code_map.db");
        let unknown = PathBuf::from(format!("{}-journal", database.display()));
        fs::write(&database, b"main").unwrap();
        fs::write(&unknown, b"unknown sqlite sibling").unwrap();

        preserve_explicitly(&database, || Ok(())).unwrap();

        assert_eq!(fs::read(&unknown).unwrap(), b"unknown sqlite sibling");
        assert!(unknown.exists());
    }
}
