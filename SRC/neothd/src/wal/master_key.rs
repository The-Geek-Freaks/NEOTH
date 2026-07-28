//! GOLD-ADAPT-CRYPTO-04 slice 2 — WAL master-key lifecycle.
//!
//! The 32-byte root key for the AEAD-at-rest layer ([`super::crypto`]). Its
//! storage mirrors the existing HMAC-key path EXACTLY (it reuses
//! `compaction::write_key_securely` + `maybe_unwrap_dpapi`): DPAPI-wrapped on
//! Windows (bound to the user account), mode-0600 on Unix.
//!
//! ## The catastrophic footgun
//! Unlike the HMAC key (losing it only forfeits tamper-evidence — content stays
//! readable), losing the master key makes every ENCRYPTED sealed segment
//! permanently unreadable. So this module also ships the recovery path:
//! [`backup_master_key`] exports the RAW (portable, un-wrapped) key to an
//! operator-chosen offline location, and [`restore_master_key`] re-wraps it for
//! the current machine. The CLI + wizard (slice 6) force a backup before
//! enabling encryption.

use super::compaction::{maybe_unwrap_dpapi, write_key_securely};
use super::crypto::{INFO_CONFIG, INFO_WAL_SEGMENT, WalMasterKey, WalSegmentKey, derive_subkey};
use anyhow::{Context, Result};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Raw keys are 32 bytes and a DPAPI envelope for that input is small. Keep a
/// hard ceiling so a capture/read path never follows an unbounded `master.key`
/// allocation controlled by the filesystem.
const MAX_STORED_MASTER_KEY_BYTES: usize = 4 * 1024;

/// Default master-key path: `<home>/wal/master.key`.
pub fn master_key_path(home: &Path) -> PathBuf {
    home.join("wal").join("master.key")
}

/// Process-memoized WAL segment subkey, derived from the default-home master
/// key, for the reader chokepoint (`compaction::logical_segment_bytes`) to
/// decrypt sealed segments WITHOUT threading a key through every caller.
///
/// **Load-only** — returns `None` when no `master.key` exists (encryption was
/// never enabled), so a reader never creates a key as a side effect. It is only
/// consulted when a segment body is actually AEAD-framed (the common plaintext
/// path never calls this), and by then the writer has already created the key.
pub fn default_segment_key() -> Option<&'static WalSegmentKey> {
    static KEY: OnceLock<Option<WalSegmentKey>> = OnceLock::new();
    KEY.get_or_init(|| {
        let home = crate::config::FreedomConfig::default_neoth_home();
        segment_key_at(&home)
    })
    .as_ref()
}

/// Load the WAL segment subkey for an explicit daemon instance home.
/// Load-only: a missing key returns `None` and never creates state.
pub fn segment_key_at(home: &Path) -> Option<WalSegmentKey> {
    let path = master_key_path(home);
    if !path.exists() {
        return None;
    }
    let body = std::fs::read(&path).ok()?;
    let raw = maybe_unwrap_dpapi(&body, &path).ok()?;
    let master = WalMasterKey::from_bytes(&raw).ok()?;
    derive_subkey(&master, INFO_WAL_SEGMENT).ok()
}

/// Checked variant for security-sensitive readers.
///
/// Every untrusted component below the trusted ancestor is opened
/// capability-relatively without following symlinks or Windows reparse points.
/// The leaf must be a real regular file and is read through the validated handle
/// with [`MAX_STORED_MASTER_KEY_BYTES`] as a hard allocation ceiling.
pub(crate) fn segment_key_at_checked(home: &Path) -> Result<Option<WalSegmentKey>> {
    let Some(master) = load_master_key_at_checked(home)? else {
        return Ok(None);
    };
    derive_subkey(&master, INFO_WAL_SEGMENT)
        .context("derive WAL segment subkey")
        .map(Some)
}

fn load_master_key_at_checked(home: &Path) -> Result<Option<WalMasterKey>> {
    let wal_dir = home.join("wal");
    let Some(parent) =
        crate::skills::store::open_bound_directory(&wal_dir, false, "WAL master-key directory")?
    else {
        return Ok(None);
    };
    let path = wal_dir.join("master.key");
    match parent.dir.symlink_metadata(OsStr::new("master.key")) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect WAL master key {}", path.display()));
        }
    }
    let body = crate::skills::store::read_regular_file_bounded(
        &parent.dir,
        OsStr::new("master.key"),
        &path,
        MAX_STORED_MASTER_KEY_BYTES,
    )
    .with_context(|| {
        format!(
            "read WAL master key {} without following links (maximum {} bytes)",
            path.display(),
            MAX_STORED_MASTER_KEY_BYTES
        )
    })?;
    let raw = maybe_unwrap_dpapi(&body, &path)?;
    WalMasterKey::from_bytes(&raw)
        .with_context(|| format!("WAL master key at {} is malformed", path.display()))
        .map(Some)
}

/// Resolve the WAL encryption policy for an explicit daemon instance.
///
/// The process-global sibling that read the ambient default home is gone: every
/// live caller is instance-bound, and a second ambient accessor on a key surface
/// is how a custom `--config` instance ends up consulting another instance's
/// policy.
pub fn wal_encryption_enabled_at(home: &Path) -> Result<bool> {
    crate::config::wal::load_wal_config(&home.join("freedom.yaml"))
        .map(|config| config.encryption == crate::config::wal::WalEncryption::Aes256GcmSiv)
        .context("load instance WAL encryption policy")
}

/// Config-at-rest subkey (CRYPTO-04 #5) for an explicit daemon instance home —
/// domain-separated (`INFO_CONFIG`) from the WAL segment key. **Load-only** for
/// the decrypt/read path; `None` when no master.key exists.
pub fn config_subkey_at(home: &Path) -> Option<WalSegmentKey> {
    let path = master_key_path(home);
    if !path.exists() {
        return None;
    }
    let body = std::fs::read(&path).ok()?;
    let raw = maybe_unwrap_dpapi(&body, &path).ok()?;
    let master = WalMasterKey::from_bytes(&raw).ok()?;
    derive_subkey(&master, INFO_CONFIG).ok()
}

/// Config-at-rest subkey for the WRITE path at an explicit daemon instance
/// home: load-OR-INIT the master key, derive the `INFO_CONFIG` subkey. Creates
/// the key on the first encrypted credentials write.
pub fn config_subkey_ensure_at(home: &Path) -> Option<WalSegmentKey> {
    let master = load_or_init_master_key(&master_key_path(home)).ok()?;
    derive_subkey(&master, INFO_CONFIG).ok()
}

/// Writer-side segment subkey for an explicit daemon instance home:
/// load-OR-INIT that home's master key (CREATES + persists it on the first
/// encrypted seal — the writer owns key creation) and derive the segment
/// subkey. `None` only on RNG/IO failure.
pub fn writer_segment_key_at(home: &Path) -> Option<WalSegmentKey> {
    let master = load_or_init_master_key(&master_key_path(home)).ok()?;
    derive_subkey(&master, INFO_WAL_SEGMENT).ok()
}

/// Load the master key, generating + persisting a fresh one on first use.
/// Fail-closed on RNG failure (mirrors `compaction::load_or_init_key`).
pub fn load_or_init_master_key(path: &Path) -> Result<WalMasterKey> {
    if path.exists() {
        let body = std::fs::read(path)
            .with_context(|| format!("read WAL master key {}", path.display()))?;
        let raw = maybe_unwrap_dpapi(&body, path)?;
        return WalMasterKey::from_bytes(&raw)
            .with_context(|| format!("WAL master key at {} is malformed", path.display()));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create master key parent {}", parent.display()))?;
    }
    let key = WalMasterKey::generate()?;
    write_key_securely(path, key.expose())?;
    Ok(key)
}

/// Export the master key as RAW bytes to `dst` (portable backup — NOT
/// DPAPI-wrapped, so it survives a Windows reinstall / migration). The operator
/// stores this offline; it is the ONLY recovery if the wrapped key is lost.
pub fn backup_master_key(src: &Path, dst: &Path) -> Result<()> {
    let body = std::fs::read(src)
        .with_context(|| format!("read master key {} for backup", src.display()))?;
    let raw = maybe_unwrap_dpapi(&body, src)?;
    // Validate it is a real 32-byte key before writing a "backup" of garbage.
    let _ = WalMasterKey::from_bytes(&raw).context("source master key is malformed")?;
    write_raw_owner_only(dst, &raw)
}

/// Re-bind an operator-supplied RAW backup to THIS machine (DPAPI-wrap on
/// Windows), overwriting `dst`. Run with the daemon stopped. Refuses a key that
/// is not exactly 32 bytes.
pub fn restore_master_key(raw: &[u8], dst: &Path) -> Result<()> {
    let _ =
        WalMasterKey::from_bytes(raw).context("restore source must be exactly 32 raw key bytes")?;
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create master key parent {}", parent.display()))?;
    }
    if dst.exists() {
        std::fs::remove_file(dst).with_context(|| {
            format!(
                "remove existing master key {} before restore",
                dst.display()
            )
        })?;
    }
    write_key_securely(dst, raw)
}

/// Write raw bytes owner-only WITHOUT DPAPI-wrapping (for portable backups).
fn write_raw_owner_only(path: &Path, raw: &[u8]) -> Result<()> {
    crate::util::atomic_write::atomic_write_private(path, raw).with_context(|| {
        format!(
            "atomically write private master-key backup {}",
            path.display()
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_generates_then_loads_stable_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = master_key_path(dir.path());
        let k1 = load_or_init_master_key(&path).unwrap();
        assert!(path.exists(), "key persisted on first init");
        let k2 = load_or_init_master_key(&path).unwrap();
        assert_eq!(k1.expose(), k2.expose(), "second load returns the same key");
    }

    #[test]
    fn backup_then_restore_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = master_key_path(dir.path());
        let orig = load_or_init_master_key(&key_path).unwrap();
        let orig_bytes = *orig.expose();

        let backup = dir.path().join("master.key.backup");
        backup_master_key(&key_path, &backup).unwrap();
        // The backup is RAW (portable): exactly the 32 key bytes.
        assert_eq!(std::fs::read(&backup).unwrap(), orig_bytes.to_vec());
        #[cfg(windows)]
        crate::wal::win_native::verify_private_dacl(&backup).unwrap();

        // Restore onto a fresh path re-binds for this machine + matches.
        let restored_path = dir.path().join("wal").join("restored.key");
        restore_master_key(&orig_bytes, &restored_path).unwrap();
        let restored = load_or_init_master_key(&restored_path).unwrap();
        assert_eq!(restored.expose(), &orig_bytes);
    }

    #[test]
    fn restore_rejects_wrong_length() {
        let dir = tempfile::tempdir().unwrap();
        let dst = dir.path().join("k.key");
        assert!(restore_master_key(&[0u8; 16], &dst).is_err());
        assert!(restore_master_key(&[0u8; 32], &dst).is_ok());
    }

    #[test]
    fn checked_segment_key_read_is_bounded() {
        let home = tempfile::tempdir().unwrap();
        let wal_dir = home.path().join("wal");
        std::fs::create_dir(&wal_dir).unwrap();
        std::fs::write(
            wal_dir.join("master.key"),
            vec![0u8; MAX_STORED_MASTER_KEY_BYTES + 1],
        )
        .unwrap();

        let error = segment_key_at_checked(home.path())
            .expect_err("oversized master.key must fail before allocation grows without bound");
        let message = format!("{error:#}");
        assert!(
            message.contains("maximum") || message.contains("too large"),
            "unexpected bounded-read error: {message}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn checked_segment_key_read_rejects_symlink_leaf() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let wal_dir = home.path().join("wal");
        std::fs::create_dir(&wal_dir).unwrap();
        let target = outside.path().join("master.key");
        std::fs::write(&target, [0x5au8; 32]).unwrap();
        std::os::unix::fs::symlink(&target, wal_dir.join("master.key")).unwrap();

        let error = segment_key_at_checked(home.path())
            .expect_err("master.key symlink must not be followed");
        assert!(
            format!("{error:#}").contains("without following links"),
            "unexpected no-follow error: {error:#}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn checked_segment_key_read_rejects_wal_directory_junction() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("master.key"), [0x5au8; 32]).unwrap();
        let junction = home.path().join("wal");
        let status = std::process::Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&junction)
            .arg(outside.path())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("spawn mklink /J");
        assert!(status.success(), "mklink /J must create test junction");

        let result = segment_key_at_checked(home.path());
        std::fs::remove_dir(&junction).expect("remove test junction without following it");
        let error = result.expect_err("WAL directory junction must not redirect master.key read");
        assert!(
            format!("{error:#}").contains("real directory"),
            "unexpected reparse rejection: {error:#}"
        );
    }
}
