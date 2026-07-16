//! Backup + restore — Phase 33c BS-2.
//!
//! Bundles the operator's stateful files into a gzipped tarball so an
//! offsite copy is a one-shot command. Symmetric `restore` unpacks the
//! same shape back. Config and credential snapshots/publication use the live
//! transaction boundary; stopping the daemon is still recommended for a fully
//! quiescent snapshot of databases and other independently managed files.
//!
//! ## What goes into the tarball
//!
//! - `freedom.yaml`              — config (contains operator-id, no secrets at rest by design)
//! - `views.db`                  — SQLite views (idx_episode + tiers + groundtruth)
//! - `archive/sessions/`         — session MD files (operator-readable companion)
//! - `tweaks.toml` (if present)  — UI customisation
//! - `commands/*.toml`           — slash command overrides
//! - `hooks/*.toml`              — hook definitions
//! - `agents/*.toml`             — sub-agent overrides
//! - `skills/`                   — installed skills
//! - `wizard/`                   — operator-edited question bank
//! - `policy.yaml` (if present)  — dangerous-targets policy
//! - `clock.floor`               — monotonic clock floor
//!
//! ## What is NOT in the tarball
//!
//! - `wal/*.wal`              — raw WAL segments. These are the source of
//!                              truth; copying them across machines without
//!                              the matching `views.db` is a foot-gun.
//!                              Operator can opt-in via `--include-wal`.
//! - `.initialized` marker    — re-init resets it cleanly anyway.
//! - PID file, lock files     — runtime ephemera.
//!
//! ## Secrets in the tarball
//!
//! `credentials.yaml` (API keys, Telegram/Slack tokens) is excluded by
//! default. The operator must explicitly pass `--include-credentials`; backup
//! emits a loud warning when those bytes are plaintext. An already encrypted
//! CONF_MAGIC frame is copied byte-exactly without a false plaintext warning.
//!
//! ## Restore safety
//!
//! Archive entry paths are untrusted. `restore_backup` validates and writes
//! every regular file/directory into a private staging tree first. `safe_join`
//! refuses absolute paths and any `..` component (zip-slip / CWE-22); all link
//! and special-file entries, duplicate paths, runtime lock/journal metadata,
//! and pre-existing symlink destinations are rejected before live writes.
//! Publication then holds the config/credential transaction locks and creates
//! a private durable `.restore-in-progress.yaml` marker before the first live
//! write. If the process or machine stops mid-publication, subsequent runtime
//! config activation fails closed; rerunning the same restore resumes it and
//! clears the marker only after every file and the exact config pair commit.
//!
//! ## Format
//!
//! `tar.gz` with paths relative to `~/.neoth/`. Restore stages and validates
//! the complete archive, publishes ordinary files privately, then commits
//! `freedom.yaml` + `credentials.yaml` together as the activation point.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;

use crate::config::FreedomConfig;

/// Top-level entries that go into the tarball. Operator can extend the
/// list via `--include` paths on the CLI — those are appended at backup
/// time with no validation beyond "exists and is under ~/.neoth/".
///
/// Pick #34 (Session 14, audit-fix): `credentials.yaml` added —
/// previously OMITTED, which meant a restore would silently miss
/// every API key + Telegram/Slack token. Operators discovered this
/// mid-crisis. Code-map persistence (`code_map.db`) added so the
/// repo-context snapshot survives migration. `routing_weights.json`
/// added so smartest-wins memory survives.
const DEFAULT_INCLUDES: &[&str] = &[
    "freedom.yaml",
    "credentials.yaml",
    "views.db",
    "code_map.db",
    "tweaks.toml",
    "policy.yaml",
    "clock.floor",
    "routing_weights.json",
    "models_catalog.json",
    ".initialized",
    "archive",
    "commands",
    "hooks",
    "agents",
    "skills",
    "wizard",
];

/// Outcome of [`write_backup`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupOutcome {
    /// Number of top-level paths included in the tarball.
    pub included: usize,
    /// True when the operator explicitly included an unencrypted
    /// `credentials.yaml` (API keys, channel tokens). The caller MUST warn the
    /// operator to store the archive on encrypted media (GOLD-SEC-27).
    pub included_plaintext_credentials: bool,
}

/// Write a `.tar.gz` backup of the operator's `~/.neoth/` state to `out`.
///
/// Missing files are silently skipped — a fresh install has no
/// `tweaks.toml` and that's fine. Caller passes `include_wal = true` to
/// add raw WAL segments to the bundle, and must explicitly pass
/// `include_credentials = true` to bundle `credentials.yaml`. The returned
/// [`BackupOutcome::included_plaintext_credentials`] is set only when the
/// bundled bytes are not already CONF_MAGIC-framed at-rest ciphertext.
pub fn write_backup(
    home: &Path,
    out: &Path,
    include_wal: bool,
    include_credentials: bool,
) -> Result<BackupOutcome> {
    write_backup_with_pair_loader(
        home,
        out,
        include_wal,
        include_credentials,
        crate::config::snapshot_raw_config_pair,
    )
}

fn write_backup_with_pair_loader(
    home: &Path,
    out: &Path,
    include_wal: bool,
    include_credentials: bool,
    load_pair: impl FnOnce(&Path) -> Result<crate::config::RawConfigPairSnapshot>,
) -> Result<BackupOutcome> {
    // Capture the two files governed by the config transaction before opening
    // the archive. The helper recovers any PREPARED journal and copies both
    // exact byte generations under one short-lived lock; large databases,
    // archives, skills, and WAL directories are tarred only after release.
    let config_pair = load_pair(&home.join("freedom.yaml"))?;

    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create backup parent {}", parent.display()))?;
    }
    let file = File::create(out).with_context(|| format!("create backup {}", out.display()))?;
    let writer = BufWriter::new(file);
    let gz = GzEncoder::new(writer, Compression::default());
    let mut tar = tar::Builder::new(gz);

    let mut included = 0usize;
    let mut included_plaintext_credentials = false;
    if let Some(freedom) = config_pair.freedom.as_deref() {
        append_snapshot(&mut tar, "freedom.yaml", freedom)?;
        included += 1;
    }
    if include_credentials && let Some(credentials) = config_pair.credentials.as_deref() {
        append_snapshot(&mut tar, "credentials.yaml", credentials)?;
        included += 1;
        included_plaintext_credentials = !config_pair.credentials_encrypted;
    }

    for rel in DEFAULT_INCLUDES {
        // These two were captured as one coherent generation above. Reading
        // either path again here could split a concurrent dual-file commit.
        if matches!(*rel, "freedom.yaml" | "credentials.yaml") {
            continue;
        }
        let path = home.join(rel);
        if !path.exists() {
            continue;
        }
        if path.is_dir() {
            tar.append_dir_all(rel, &path)
                .with_context(|| format!("tar dir {}", path.display()))?;
        } else {
            tar.append_path_with_name(&path, rel)
                .with_context(|| format!("tar file {}", path.display()))?;
        }
        included += 1;
    }
    if include_wal {
        let wal = home.join("wal");
        if wal.exists() {
            tar.append_dir_all("wal", &wal)
                .with_context(|| format!("tar wal {}", wal.display()))?;
            included += 1;
        }
    }

    let gz = tar.into_inner().context("finalise tar")?;
    let mut buf_writer = gz.finish().context("finish gzip")?;
    buf_writer.flush().context("flush backup")?;
    // Pick #34 (Session 14, audit-fix): force the OS to push the
    // archive's bytes to disk before returning Ok. Without this, a
    // power loss or Windows-update reboot mid-archive leaves a
    // partial tarball on disk that LOOKS complete (no error from
    // `flush`) but won't restore — operator discovers the corruption
    // months later when they actually need the backup. `into_inner()`
    // surrenders the BufWriter; the inner `File` is what we sync.
    let file = buf_writer
        .into_inner()
        .map_err(|e| anyhow::anyhow!("unwrap BufWriter to fsync backup file: {e}"))?;
    file.sync_all().context("fsync backup archive to disk")?;
    Ok(BackupOutcome {
        included,
        included_plaintext_credentials,
    })
}

fn append_snapshot<W: Write>(tar: &mut tar::Builder<W>, name: &str, bytes: &[u8]) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o600);
    header.set_size(bytes.len() as u64);
    header.set_cksum();
    tar.append_data(&mut header, name, bytes)
        .with_context(|| format!("tar coherent snapshot {name}"))
}

/// Restore a `.tar.gz` backup into `target_home`. If `target_home` is
/// non-empty and `force == false`, returns an error to prevent
/// accidentally overwriting a live install.
pub fn restore_backup(archive: &Path, target_home: &Path, force: bool) -> Result<usize> {
    anyhow::ensure!(
        target_home.parent().is_some(),
        "refusing to restore directly into a filesystem root"
    );
    let target_nonempty = match std::fs::symlink_metadata(target_home) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
                "restore target {} must be a real directory, never a symlink",
                target_home.display()
            );
            std::fs::read_dir(target_home)
                .with_context(|| format!("inspect target {}", target_home.display()))?
                .next()
                .is_some()
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(error).with_context(|| format!("inspect target {}", target_home.display()));
        }
    };
    if target_nonempty && !force {
        anyhow::bail!(
            "target {} is not empty. Pass --force to overwrite, or restore into a fresh path.",
            target_home.display()
        );
    }
    crate::cli::init::ensure_dir_secure(target_home)
        .with_context(|| format!("create private restore target {}", target_home.display()))?;

    let staging_parent = target_home
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let staging = tempfile::Builder::new()
        .prefix(".neoth-restore-")
        .tempdir_in(staging_parent)
        .with_context(|| format!("create restore staging beside {}", target_home.display()))?;
    crate::cli::init::ensure_dir_secure(staging.path())
        .context("secure private restore staging")?;

    let file = File::open(archive).with_context(|| format!("open backup {}", archive.display()))?;
    let mut reader = BufReader::new(file);
    let mut gz = GzDecoder::new(&mut reader);
    let mut tar_bytes = zeroize::Zeroizing::new(Vec::new());
    gz.read_to_end(&mut tar_bytes).context("decode gzip")?;
    let mut archive = tar::Archive::new(&tar_bytes[..]);
    let mut count = 0usize;
    let mut seen = std::collections::HashSet::new();
    let mut staged_files = Vec::new();
    let mut staged_dirs = Vec::new();
    let mut staged_executables = std::collections::HashSet::new();
    for entry in archive.entries().context("read tar entries")? {
        let mut entry = entry.context("tar entry")?;
        let rel = entry.path().context("tar entry path")?.into_owned();
        let etype = entry.header().entry_type();
        if !etype.is_file() && !etype.is_dir() {
            anyhow::bail!(
                "refusing {:?} archive entry {} — NEOTH backups contain only regular files and directories",
                etype,
                rel.display()
            );
        }
        let staged_dest = safe_join(staging.path(), &rel)
            .with_context(|| format!("reject unsafe archive entry {}", rel.display()))?;
        let normalized = staged_dest
            .strip_prefix(staging.path())
            .expect("safe_join always remains below staging")
            .to_path_buf();
        anyhow::ensure!(
            !normalized.as_os_str().is_empty(),
            "refusing empty/root archive entry"
        );
        anyhow::ensure!(
            !restore_path_is_transaction_metadata(&normalized),
            "refusing runtime lock/journal archive entry {}",
            normalized.display()
        );
        anyhow::ensure!(
            seen.insert(normalized.clone()),
            "duplicate archive entry {}",
            normalized.display()
        );

        if etype.is_dir() {
            crate::cli::init::ensure_dir_secure(&staged_dest).with_context(|| {
                format!("create private staged directory {}", normalized.display())
            })?;
            staged_dirs.push(normalized);
        } else {
            let executable = entry
                .header()
                .mode()
                .map(|mode| mode & 0o111 != 0)
                .unwrap_or(false);
            let parent = staged_dest
                .parent()
                .context("staged regular file must have a parent")?;
            crate::cli::init::ensure_dir_secure(parent).with_context(|| {
                format!("create private staged parent for {}", normalized.display())
            })?;
            let mut output = crate::cli::init::open_for_create_secure(&staged_dest)
                .with_context(|| format!("create staged file {}", normalized.display()))?;
            std::io::copy(&mut entry, &mut output)
                .with_context(|| format!("stage archive file {}", normalized.display()))?;
            output
                .flush()
                .with_context(|| format!("flush staged file {}", normalized.display()))?;
            output
                .sync_all()
                .with_context(|| format!("fsync staged file {}", normalized.display()))?;
            if executable {
                staged_executables.insert(normalized.clone());
            }
            staged_files.push(normalized);
        }
        count += 1;
    }

    let freedom_staged = staged_files
        .iter()
        .any(|path| path == Path::new("freedom.yaml"));
    let credentials_staged = staged_files
        .iter()
        .any(|path| path == Path::new("credentials.yaml"));
    let freedom = freedom_staged
        .then(|| std::fs::read(staging.path().join("freedom.yaml")))
        .transpose()
        .context("read staged freedom.yaml")?
        .map(zeroize::Zeroizing::new);
    let credentials = credentials_staged
        .then(|| std::fs::read(staging.path().join("credentials.yaml")))
        .transpose()
        .context("read staged credentials.yaml")?
        .map(zeroize::Zeroizing::new);
    crate::config::credentials::Credentials::validate_exact_raw_pair(
        &target_home.join("freedom.yaml"),
        &target_home.join("credentials.yaml"),
        freedom.as_ref().map(|bytes| bytes.as_slice()),
        credentials.as_ref().map(|bytes| bytes.as_slice()),
    )
    .context("validate staged config/credential pair")?;
    if freedom.is_some() || credentials.is_some() {
        validate_restore_destination(target_home, Path::new("freedom.yaml"), false, force)?;
        validate_restore_destination(target_home, Path::new("credentials.yaml"), false, force)?;
    }

    // Validate every live destination before changing any of them. This is a
    // second containment layer after staging and refuses pre-existing symlink
    // parents/finals even under --force.
    for rel in &staged_dirs {
        validate_restore_destination(target_home, rel, true, force)?;
    }
    for rel in &staged_files {
        validate_restore_destination(target_home, rel, false, force)?;
    }

    staged_dirs.sort_by_key(|path| path.components().count());
    crate::config::credentials::with_restore_publication_at(
        &target_home.join("freedom.yaml"),
        || {
            for rel in &staged_dirs {
                ensure_restore_directory(target_home, rel)?;
            }
            for rel in &staged_files {
                if rel == Path::new("freedom.yaml") || rel == Path::new("credentials.yaml") {
                    continue;
                }
                publish_staged_regular_file(
                    staging.path(),
                    target_home,
                    rel,
                    staged_executables.contains(rel),
                )?;
            }

            // Config + credentials are the activation/commit point and
            // therefore land last, through the same durable PREPARED journal
            // as live mutations. The outer restore marker covers ancillary
            // files as well, so a crash can never activate their mixed state.
            if freedom.is_some() || credentials.is_some() {
                crate::config::credentials::Credentials::publish_exact_raw_pair_at(
                    &target_home.join("freedom.yaml"),
                    &target_home.join("credentials.yaml"),
                    freedom.as_ref().map(|bytes| bytes.as_slice()),
                    credentials.as_ref().map(|bytes| bytes.as_slice()),
                )
                .context("publish restored config/credential pair")?;
            }
            Ok(())
        },
    )?;
    Ok(count)
}

fn restore_path_is_transaction_metadata(rel: &Path) -> bool {
    rel.parent()
        .is_none_or(|parent| parent.as_os_str().is_empty())
        && matches!(
            rel.file_name().and_then(|name| name.to_str()),
            Some(
                ".freedom-credentials.prepared.yaml"
                    | ".freedom-credentials.transaction.lock"
                    | ".restore-in-progress.yaml"
                    | "freedom.lock"
                    | "credentials.lock"
                    | "neothd.pid"
            )
        )
}

fn validate_restore_destination(
    root: &Path,
    rel: &Path,
    expected_directory: bool,
    force: bool,
) -> Result<()> {
    let components: Vec<_> = rel.components().collect();
    let mut current = root.to_path_buf();
    for (index, component) in components.iter().enumerate() {
        let std::path::Component::Normal(segment) = component else {
            anyhow::bail!("non-normal staged restore component in {}", rel.display());
        };
        current.push(segment);
        let final_component = index + 1 == components.len();
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) => {
                anyhow::ensure!(
                    !metadata.file_type().is_symlink(),
                    "refusing restore through existing symlink {}",
                    current.display()
                );
                if final_component {
                    anyhow::ensure!(
                        (expected_directory && metadata.file_type().is_dir())
                            || (!expected_directory && metadata.file_type().is_file()),
                        "restore destination {} has the wrong file type",
                        current.display()
                    );
                    anyhow::ensure!(
                        force,
                        "restore destination {} appeared after the empty-target check",
                        current.display()
                    );
                } else {
                    anyhow::ensure!(
                        metadata.file_type().is_dir(),
                        "restore parent {} is not a directory",
                        current.display()
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect restore destination {}", current.display()));
            }
        }
    }
    Ok(())
}

fn ensure_restore_directory(root: &Path, rel: &Path) -> Result<()> {
    let mut current = root.to_path_buf();
    for component in rel.components() {
        let std::path::Component::Normal(segment) = component else {
            anyhow::bail!("non-normal staged restore component in {}", rel.display());
        };
        current.push(segment);
        crate::cli::init::ensure_dir_secure(&current)
            .with_context(|| format!("create private restore directory {}", current.display()))?;
    }
    Ok(())
}

fn publish_staged_regular_file(
    staging: &Path,
    root: &Path,
    rel: &Path,
    executable: bool,
) -> Result<()> {
    if let Some(parent) = rel.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        ensure_restore_directory(root, parent)?;
    }
    let destination = safe_join(root, rel)?;
    match std::fs::symlink_metadata(&destination) {
        Ok(metadata) => anyhow::ensure!(
            metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
            "restore destination {} changed to a symlink/non-file",
            destination.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect restore file {}", destination.display()));
        }
    }
    let bytes = zeroize::Zeroizing::new(
        std::fs::read(staging.join(rel))
            .with_context(|| format!("read staged restore file {}", rel.display()))?,
    );
    crate::util::atomic_write::atomic_write_private(&destination, &bytes)
        .with_context(|| format!("atomically restore {}", destination.display()))?;
    #[cfg(unix)]
    if executable {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("restore executable mode on {}", destination.display()))?;
    }
    #[cfg(not(unix))]
    let _ = executable;
    Ok(())
}

/// Join an untrusted archive-relative path onto `base`, rejecting any
/// path that would escape `base` (zip-slip / CWE-22). Only normal path
/// components are allowed: absolute paths, root/prefix, and `..` are
/// refused; `.` is ignored. The result is therefore always contained
/// within `base`.
fn safe_join(base: &Path, rel: &Path) -> Result<PathBuf> {
    use std::path::Component;
    let mut out = base.to_path_buf();
    for comp in rel.components() {
        match comp {
            Component::Normal(seg) => out.push(seg),
            Component::CurDir => {}
            Component::ParentDir => {
                anyhow::bail!("path traversal `..` in archive entry: {}", rel.display());
            }
            Component::RootDir | Component::Prefix(_) => {
                anyhow::bail!("absolute path in archive entry: {}", rel.display());
            }
        }
    }
    Ok(out)
}

/// Conventional default backup path: `<home>/backups/neoth-<ts>.tar.gz`.
pub fn default_backup_path() -> PathBuf {
    let now = crate::time::utc_now().format("%Y%m%dT%H%M%SZ").to_string();
    FreedomConfig::default_neoth_home()
        .join("backups")
        .join(format!("neoth-{now}.tar.gz"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fake_home(dir: &Path) -> PathBuf {
        let home = dir.join("neoth");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(home.join("freedom.yaml"), "operator_id: sam\n").unwrap();
        std::fs::write(
            home.join("credentials.yaml"),
            "anthropic_api_key: sk-secret\n",
        )
        .unwrap();
        std::fs::write(home.join("views.db"), b"\x00not really sqlite").unwrap();
        std::fs::write(home.join("tweaks.toml"), "banner = \"x\"\n").unwrap();
        let archive = home.join("archive").join("sessions").join("2026-05-14");
        std::fs::create_dir_all(&archive).unwrap();
        std::fs::write(archive.join("093412-abc.md"), "session text").unwrap();
        let wal = home.join("wal");
        std::fs::create_dir_all(&wal).unwrap();
        std::fs::write(wal.join("000001.wal"), b"NEOT").unwrap();
        home
    }

    #[test]
    fn write_backup_creates_tarball_with_expected_entries() {
        let dir = tempdir().unwrap();
        let home = fake_home(dir.path());
        let out = dir.path().join("backup.tar.gz");
        let n = write_backup(&home, &out, false, true).unwrap();
        assert!(out.exists());
        assert!(n.included >= 4, "expected ≥4 entries, got {}", n.included);
    }

    #[test]
    fn backup_cannot_split_a_concurrent_config_credential_generation() {
        use std::sync::mpsc;
        use std::time::Duration;

        let dir = tempdir().unwrap();
        let home = fake_home(dir.path());
        let freedom_path = home.join("freedom.yaml");
        let credentials_path = home.join("credentials.yaml");
        std::fs::write(&credentials_path, "provider_key: old-secret\n").unwrap();
        let out = dir.path().join("coherent-backup.tar.gz");

        let (freedom_read_tx, freedom_read_rx) = mpsc::channel();
        let (release_snapshot_tx, release_snapshot_rx) = mpsc::channel();
        let backup_home = home.clone();
        let backup_out = out.clone();
        let backup = std::thread::spawn(move || {
            write_backup_with_pair_loader(&backup_home, &backup_out, false, true, |path| {
                crate::config::snapshot_raw_config_pair_with_hook(path, || {
                    freedom_read_tx.send(()).unwrap();
                    release_snapshot_rx.recv().unwrap();
                })
            })
            .unwrap()
        });

        freedom_read_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        let writer_freedom = freedom_path.clone();
        let writer_credentials = credentials_path.clone();
        let (writer_done_tx, writer_done_rx) = mpsc::channel();
        let writer = std::thread::spawn(move || {
            crate::config::credentials::Credentials::update_with_freedom_at(
                &writer_freedom,
                &writer_credentials,
                |config, credentials| {
                    config.operator_id = Some("new-operator".to_string());
                    credentials.provider_key =
                        Some(crate::secret::SecretString::from("new-secret"));
                    Ok(())
                },
            )
            .unwrap();
            writer_done_tx.send(()).unwrap();
        });
        assert!(
            writer_done_rx
                .recv_timeout(Duration::from_millis(100))
                .is_err(),
            "dual-file writer must remain blocked while backup captures its pair"
        );

        release_snapshot_tx.send(()).unwrap();
        let outcome = backup.join().unwrap();
        writer_done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        writer.join().unwrap();
        assert!(outcome.included_plaintext_credentials);

        let restored = dir.path().join("coherent-restore");
        restore_backup(&out, &restored, false).unwrap();
        let archived_config: serde_yaml::Value =
            serde_yaml::from_slice(&std::fs::read(restored.join("freedom.yaml")).unwrap()).unwrap();
        let archived_credentials: serde_yaml::Value =
            serde_yaml::from_slice(&std::fs::read(restored.join("credentials.yaml")).unwrap())
                .unwrap();
        assert_eq!(archived_config["operator_id"].as_str(), Some("sam"));
        assert_eq!(
            archived_credentials["provider_key"].as_str(),
            Some("old-secret")
        );

        let live_config: serde_yaml::Value =
            serde_yaml::from_slice(&std::fs::read(&freedom_path).unwrap()).unwrap();
        let live_credentials: serde_yaml::Value =
            serde_yaml::from_slice(&std::fs::read(&credentials_path).unwrap()).unwrap();
        assert_eq!(live_config["operator_id"].as_str(), Some("new-operator"));
        assert_eq!(
            live_credentials["provider_key"].as_str(),
            Some("new-secret")
        );
    }

    #[test]
    fn write_backup_skips_wal_by_default() {
        let dir = tempdir().unwrap();
        let home = fake_home(dir.path());
        let out = dir.path().join("backup.tar.gz");
        write_backup(&home, &out, false, true).unwrap();
        let target = dir.path().join("restored");
        restore_backup(&out, &target, false).unwrap();
        assert!(
            !target.join("wal").exists(),
            "wal must be excluded by default"
        );
        assert!(target.join("freedom.yaml").exists());
        assert!(target.join("views.db").exists());
    }

    #[test]
    fn write_backup_includes_wal_when_opted_in() {
        let dir = tempdir().unwrap();
        let home = fake_home(dir.path());
        let out = dir.path().join("backup.tar.gz");
        write_backup(&home, &out, true, true).unwrap();
        let target = dir.path().join("restored");
        restore_backup(&out, &target, false).unwrap();
        assert!(target.join("wal").join("000001.wal").exists());
    }

    #[test]
    fn restore_round_trips_file_content() {
        let dir = tempdir().unwrap();
        let home = fake_home(dir.path());
        let out = dir.path().join("backup.tar.gz");
        write_backup(&home, &out, false, true).unwrap();
        let target = dir.path().join("restored");
        restore_backup(&out, &target, false).unwrap();
        let body = std::fs::read_to_string(target.join("freedom.yaml")).unwrap();
        assert_eq!(body.trim(), "operator_id: sam");
        let session =
            std::fs::read_to_string(target.join("archive/sessions/2026-05-14/093412-abc.md"))
                .unwrap();
        assert_eq!(session, "session text");
    }

    #[test]
    fn restore_refuses_to_overwrite_non_empty_target_without_force() {
        let dir = tempdir().unwrap();
        let home = fake_home(dir.path());
        let out = dir.path().join("backup.tar.gz");
        write_backup(&home, &out, false, true).unwrap();
        let target = dir.path().join("preexisting");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("dont-clobber"), "important").unwrap();
        let r = restore_backup(&out, &target, false);
        assert!(r.is_err());
        // File still there.
        assert!(target.join("dont-clobber").exists());
    }

    #[test]
    fn restore_with_force_overwrites() {
        let dir = tempdir().unwrap();
        let home = fake_home(dir.path());
        let out = dir.path().join("backup.tar.gz");
        write_backup(&home, &out, false, true).unwrap();
        let target = dir.path().join("preexisting");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("dont-clobber"), "old").unwrap();
        restore_backup(&out, &target, true).unwrap();
        assert!(target.join("freedom.yaml").exists());
    }

    #[test]
    fn restore_validates_pair_before_publishing_any_other_file() {
        let dir = tempdir().unwrap();
        let archive_path = dir.path().join("invalid-pair.tar.gz");
        {
            let file = File::create(&archive_path).unwrap();
            let gz = GzEncoder::new(BufWriter::new(file), Compression::default());
            let mut tar = tar::Builder::new(gz);
            for (name, body) in [
                ("views.db", b"new-view-state".as_slice()),
                ("freedom.yaml", b"not: [valid yaml".as_slice()),
                ("credentials.yaml", b"provider_key: new-secret\n".as_slice()),
            ] {
                let mut header = tar::Header::new_gnu();
                header.set_entry_type(tar::EntryType::Regular);
                header.set_mode(0o600);
                header.set_size(body.len() as u64);
                header.set_cksum();
                tar.append_data(&mut header, name, body).unwrap();
            }
            let gz = tar.into_inner().unwrap();
            gz.finish().unwrap();
        }
        let target = dir.path().join("live");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("views.db"), b"old-view-state").unwrap();
        std::fs::write(target.join("freedom.yaml"), b"operator_id: old\n").unwrap();
        std::fs::write(
            target.join("credentials.yaml"),
            b"provider_key: old-secret\n",
        )
        .unwrap();

        let error = restore_backup(&archive_path, &target, true).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("validate staged config/credential pair")
        );
        assert_eq!(
            std::fs::read(target.join("views.db")).unwrap(),
            b"old-view-state"
        );
        assert_eq!(
            std::fs::read(target.join("freedom.yaml")).unwrap(),
            b"operator_id: old\n"
        );
        assert_eq!(
            std::fs::read(target.join("credentials.yaml")).unwrap(),
            b"provider_key: old-secret\n"
        );
    }

    #[test]
    fn incomplete_restore_blocks_runtime_until_restore_is_resumed() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("live");
        std::fs::create_dir_all(&target).unwrap();
        let freedom_path = target.join("freedom.yaml");
        let credentials_path = target.join("credentials.yaml");
        let views_path = target.join("views.db");

        let mut old_config = crate::config::FreedomConfig::default();
        old_config.operator_id = Some("old-operator".to_string());
        let old_freedom = serde_yaml::to_string(&old_config).unwrap().into_bytes();
        let old_credentials = b"provider_key: old-secret\n".to_vec();
        std::fs::write(&freedom_path, &old_freedom).unwrap();
        std::fs::write(&credentials_path, &old_credentials).unwrap();
        std::fs::write(&views_path, b"old-view-state").unwrap();

        let interrupted = crate::config::credentials::with_restore_publication_at(
            &freedom_path,
            || -> Result<()> {
                crate::util::atomic_write::atomic_write_private(
                    &views_path,
                    b"partially-restored-view-state",
                )?;
                anyhow::bail!("injected restore interruption after ancillary publication")
            },
        )
        .unwrap_err();
        assert!(
            format!("{interrupted:#}").contains("injected restore interruption"),
            "{interrupted:#}"
        );
        assert_eq!(std::fs::read(&freedom_path).unwrap(), old_freedom);
        assert_eq!(std::fs::read(&credentials_path).unwrap(), old_credentials);
        assert_eq!(
            std::fs::read(&views_path).unwrap(),
            b"partially-restored-view-state"
        );
        assert!(target.join(".restore-in-progress.yaml").exists());

        let blocked = crate::config::FreedomConfig::load_from_path(&freedom_path).unwrap_err();
        assert!(
            format!("{blocked:#}").contains("incomplete backup restore"),
            "{blocked:#}"
        );

        let mut new_config = crate::config::FreedomConfig::default();
        new_config.operator_id = Some("new-operator".to_string());
        let new_freedom = serde_yaml::to_string(&new_config).unwrap().into_bytes();
        let new_credentials = b"provider_key: new-secret\n".to_vec();
        crate::config::credentials::with_restore_publication_at(&freedom_path, || {
            crate::util::atomic_write::atomic_write_private(
                &views_path,
                b"fully-restored-view-state",
            )?;
            crate::config::credentials::Credentials::publish_exact_raw_pair_at(
                &freedom_path,
                &credentials_path,
                Some(&new_freedom),
                Some(&new_credentials),
            )
        })
        .unwrap();

        assert!(!target.join(".restore-in-progress.yaml").exists());
        assert_eq!(std::fs::read(&freedom_path).unwrap(), new_freedom);
        assert_eq!(std::fs::read(&credentials_path).unwrap(), new_credentials);
        assert_eq!(
            std::fs::read(&views_path).unwrap(),
            b"fully-restored-view-state"
        );
        let pair = crate::config::load_runtime_config_pair_from_path(&freedom_path).unwrap();
        assert_eq!(pair.config.operator_id.as_deref(), Some("new-operator"));
    }

    #[cfg(unix)]
    #[test]
    fn restore_force_refuses_existing_symlink_destination() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let home = fake_home(dir.path());
        let archive_path = dir.path().join("backup.tar.gz");
        write_backup(&home, &archive_path, false, true).unwrap();
        let target = dir.path().join("live");
        std::fs::create_dir_all(&target).unwrap();
        let outside = dir.path().join("outside.db");
        std::fs::write(&outside, b"outside-untouched").unwrap();
        symlink(&outside, target.join("views.db")).unwrap();

        let error = restore_backup(&archive_path, &target, true).unwrap_err();
        assert!(error.to_string().contains("existing symlink"));
        assert_eq!(std::fs::read(&outside).unwrap(), b"outside-untouched");
        assert!(!target.join("freedom.yaml").exists());
    }

    #[test]
    fn missing_files_are_skipped_not_errored() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("sparse");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(home.join("freedom.yaml"), "only this file").unwrap();
        let out = dir.path().join("backup.tar.gz");
        let n = write_backup(&home, &out, false, true).unwrap();
        assert_eq!(
            n.included, 1,
            "only freedom.yaml is present in this fixture"
        );
        assert!(!n.included_plaintext_credentials);
    }

    #[test]
    fn backup_includes_credentials_when_explicitly_opted_in_and_flags_them() {
        let dir = tempdir().unwrap();
        let home = fake_home(dir.path());
        let out = dir.path().join("backup.tar.gz");
        let outcome = write_backup(&home, &out, false, true).unwrap();
        assert!(
            outcome.included_plaintext_credentials,
            "credentials.yaml present + opted in → flag must be set so the caller warns"
        );
        let target = dir.path().join("restored");
        restore_backup(&out, &target, false).unwrap();
        assert!(target.join("credentials.yaml").exists());
    }

    #[test]
    fn backup_excludes_credentials_by_default() {
        let dir = tempdir().unwrap();
        let home = fake_home(dir.path());
        let out = dir.path().join("backup.tar.gz");
        let outcome = write_backup(&home, &out, false, false).unwrap();
        assert!(!outcome.included_plaintext_credentials);
        let target = dir.path().join("restored");
        restore_backup(&out, &target, false).unwrap();
        assert!(
            !target.join("credentials.yaml").exists(),
            "--no-credentials must exclude the secrets file"
        );
        // The rest of the backup is intact.
        assert!(target.join("freedom.yaml").exists());
    }

    #[test]
    fn encrypted_credentials_are_included_without_plaintext_warning() {
        let dir = tempdir().unwrap();
        let home = fake_home(dir.path());
        let mut encrypted = b"NEOTH_CONF_ENCv1\n".to_vec();
        encrypted.extend_from_slice(&[7_u8; 12]);
        encrypted.extend_from_slice(&[9_u8; 16]);
        std::fs::write(home.join("credentials.yaml"), &encrypted).unwrap();
        let out = dir.path().join("encrypted-credentials.tar.gz");

        let outcome = write_backup(&home, &out, false, true).unwrap();

        assert!(
            !outcome.included_plaintext_credentials,
            "an encrypted-at-rest blob must not trigger the plaintext archive warning"
        );
        let restored = dir.path().join("restored-encrypted");
        restore_backup(&out, &restored, false).unwrap();
        assert_eq!(
            std::fs::read(restored.join("credentials.yaml")).unwrap(),
            encrypted
        );
    }

    #[test]
    fn safe_join_allows_normal_paths_and_rejects_escapes() {
        let base = Path::new("/srv/neoth");
        assert_eq!(
            safe_join(base, Path::new("a/b.txt")).unwrap(),
            Path::new("/srv/neoth/a/b.txt")
        );
        assert_eq!(
            safe_join(base, Path::new("./a/./b")).unwrap(),
            Path::new("/srv/neoth/a/b")
        );
        assert!(safe_join(base, Path::new("../escape")).is_err());
        assert!(safe_join(base, Path::new("a/../../escape")).is_err());
        assert!(safe_join(base, Path::new("/etc/passwd")).is_err());
    }

    #[test]
    fn restore_rejects_all_root_transaction_metadata() {
        for name in [
            ".freedom-credentials.prepared.yaml",
            ".freedom-credentials.transaction.lock",
            ".restore-in-progress.yaml",
            "freedom.lock",
            "credentials.lock",
            "neothd.pid",
        ] {
            assert!(
                restore_path_is_transaction_metadata(Path::new(name)),
                "{name} must never be restorable from an untrusted archive"
            );
        }
        assert!(!restore_path_is_transaction_metadata(Path::new(
            "archive/neothd.pid"
        )));
    }

    #[test]
    fn restore_rejects_symlink_entry() {
        use std::io::Write as _;
        // The high-level tar `Builder` refuses to even CREATE a `..`
        // entry (`set_path` validates) — defense in depth on the write
        // side — so the restore-side `..`/absolute guard is proven by
        // `safe_join_allows_normal_paths_and_rejects_escapes`. Here we
        // prove the restore-side ENTRY-TYPE guard end-to-end: a crafted
        // symlink entry (the classic redirect-a-later-write vector) must
        // be rejected outright.
        let dir = tempdir().unwrap();
        let archive_path = dir.path().join("evil.tar.gz");
        {
            let f = File::create(&archive_path).unwrap();
            let gz = GzEncoder::new(BufWriter::new(f), Compression::default());
            let mut tb = tar::Builder::new(gz);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            tb.append_link(&mut header, "innocent.txt", "../../etc/escape")
                .unwrap();
            let gz = tb.into_inner().unwrap();
            let mut w = gz.finish().unwrap();
            w.flush().unwrap();
        }
        let target = dir.path().join("restore-target");
        let r = restore_backup(&archive_path, &target, false);
        assert!(r.is_err(), "symlink entry must be rejected");
        assert!(!target.join("innocent.txt").exists());
    }
}
