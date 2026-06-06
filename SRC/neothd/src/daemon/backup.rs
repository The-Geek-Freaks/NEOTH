//! Backup + restore — Phase 33c BS-2.
//!
//! Bundles the operator's stateful files into a gzipped tarball so an
//! offsite copy is a one-shot command. Symmetric `restore` unpacks the
//! same shape back. No daemon-side coordination: the operator should
//! stop the daemon before either operation to avoid mid-write snapshots.
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
//! `credentials.yaml` (API keys, Telegram/Slack tokens) is bundled BY
//! DEFAULT so a restore is not silently missing every key (Pick #34).
//! The archive is **plaintext** until `age` encryption lands, so backup
//! emits a loud warning when it includes credentials and the operator
//! can pass `--no-credentials` to exclude them (GOLD-SEC-27). Store the
//! archive on encrypted media regardless.
//!
//! ## Restore safety
//!
//! Archive entry paths are untrusted. `restore_backup` joins each entry
//! through `safe_join`, which refuses absolute paths and any `..`
//! component (zip-slip / CWE-22), and rejects symlink/hard-link entries
//! outright — NEOTH backups only ever contain regular files + dirs
//! (GOLD-SEC-02).
//!
//! ## Format
//!
//! `tar.gz` with paths relative to `~/.neoth/`. Restore unpacks straight
//! into an empty target directory. Operator passphrase encryption is a
//! Phase 33c follow-up (`age` crate); for v0.1 the tarball is plaintext —
//! the operator is responsible for storing it on encrypted media.

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
    /// True when the tarball contains the plaintext `credentials.yaml`
    /// (API keys, channel tokens). The caller MUST warn the operator to
    /// store the archive on encrypted media (GOLD-SEC-27).
    pub included_plaintext_credentials: bool,
}

/// Write a `.tar.gz` backup of the operator's `~/.neoth/` state to `out`.
///
/// Missing files are silently skipped — a fresh install has no
/// `tweaks.toml` and that's fine. Caller passes `include_wal = true` to
/// add raw WAL segments to the bundle, and `include_credentials = true`
/// to bundle `credentials.yaml` (plaintext secrets — the returned
/// [`BackupOutcome::included_plaintext_credentials`] is set so the caller
/// can warn the operator).
pub fn write_backup(
    home: &Path,
    out: &Path,
    include_wal: bool,
    include_credentials: bool,
) -> Result<BackupOutcome> {
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
    for rel in DEFAULT_INCLUDES {
        // credentials.yaml is plaintext secrets — only bundle it when the
        // operator opted in (default true), and flag it so the caller warns.
        if *rel == "credentials.yaml" && !include_credentials {
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
        if *rel == "credentials.yaml" {
            included_plaintext_credentials = true;
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

/// Restore a `.tar.gz` backup into `target_home`. If `target_home` is
/// non-empty and `force == false`, returns an error to prevent
/// accidentally overwriting a live install.
pub fn restore_backup(archive: &Path, target_home: &Path, force: bool) -> Result<usize> {
    if target_home.exists()
        && std::fs::read_dir(target_home)
            .map(|mut d| d.next().is_some())
            .unwrap_or(false)
        && !force
    {
        anyhow::bail!(
            "target {} is not empty. Pass --force to overwrite, or restore into a fresh path.",
            target_home.display()
        );
    }
    std::fs::create_dir_all(target_home)
        .with_context(|| format!("create target {}", target_home.display()))?;
    let file = File::open(archive).with_context(|| format!("open backup {}", archive.display()))?;
    let mut reader = BufReader::new(file);
    let mut gz = GzDecoder::new(&mut reader);
    let mut tar_bytes = Vec::new();
    gz.read_to_end(&mut tar_bytes).context("decode gzip")?;
    let mut archive = tar::Archive::new(&tar_bytes[..]);
    let mut count = 0usize;
    for entry in archive.entries().context("read tar entries")? {
        let mut entry = entry.context("tar entry")?;
        let rel = entry.path().context("tar entry path")?.into_owned();
        // Reject symlink/hard-link entries — a NEOTH backup only ever
        // contains regular files + dirs, and a crafted link could be used
        // to redirect a later entry's write outside the target tree.
        let etype = entry.header().entry_type();
        if etype.is_symlink() || etype.is_hard_link() {
            anyhow::bail!(
                "refusing {:?} archive entry {} — NEOTH backups contain only regular files and directories",
                etype,
                rel.display()
            );
        }
        // Zip-slip guard (CWE-22): join through `safe_join` so an entry
        // path with `..` or an absolute root cannot escape target_home.
        let dest = safe_join(target_home, &rel)
            .with_context(|| format!("reject unsafe archive entry {}", rel.display()))?;
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create restore parent {}", parent.display()))?;
        }
        entry
            .unpack(&dest)
            .with_context(|| format!("unpack {} → {}", rel.display(), dest.display()))?;
        count += 1;
    }
    Ok(count)
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
    let now = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
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
        std::fs::write(home.join("credentials.yaml"), "anthropic_api_key: sk-secret\n").unwrap();
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
    fn missing_files_are_skipped_not_errored() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("sparse");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(home.join("freedom.yaml"), "only this file").unwrap();
        let out = dir.path().join("backup.tar.gz");
        let n = write_backup(&home, &out, false, true).unwrap();
        assert_eq!(n.included, 1, "only freedom.yaml is present in this fixture");
        assert!(!n.included_plaintext_credentials);
    }

    #[test]
    fn backup_includes_credentials_by_default_and_flags_them() {
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
    fn backup_excludes_credentials_when_opted_out() {
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
