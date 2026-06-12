//! Crash-safe file writes (GOLD-ARCH-09).
//!
//! [`atomic_write`] is the canonical "write a file so a crash mid-write can't
//! leave a torn or empty target" primitive. It writes to a sibling temp file,
//! fsyncs it, then `rename`s over the target. The rename is atomic on both Unix
//! and Windows (std `rename` uses `MoveFileExW` with `REPLACE_EXISTING` /
//! `ReplaceFile` semantics on Windows), so **no explicit target-remove is
//! needed** — a remove-then-rename opens a window where a concurrent reader
//! sees no file at all, which is the exact bug this replaces in callers that
//! hand-rolled `if path.exists() { remove_file } ; rename`.

use std::io::Write;
use std::path::{Path, PathBuf};

/// Atomically write `bytes` to `path`. Creates the parent directory if missing.
///
/// On success the file at `path` contains exactly `bytes`; on a crash mid-write
/// the previous contents (if any) survive intact. NOT a concurrency primitive:
/// two threads writing the same `path` should serialise externally (the temp
/// file is pid-scoped to avoid cross-process collisions, but same-process
/// racing writers can still clobber each other's rename — see the `*_LOCK`
/// patterns in `memory::channel_weights` / `cluster::registry` for that).
pub fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let tmp = tmp_sibling(path);
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.flush()?;
        // Durability: the bytes must hit disk before the rename so a crash
        // between rename and the next fsync can't leave a renamed-but-empty file.
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path).inspect_err(|_| {
        // Best-effort: don't leave the orphan temp behind on a rename failure.
        let _ = std::fs::remove_file(&tmp);
    })?;
    // GR-088 — fsync the PARENT directory so the new directory entry created by
    // the rename is durable. The file's DATA was fsynced above, but on POSIX the
    // rename only updates the parent inode's metadata, which survives a power
    // loss only once the directory itself is fsynced. Best-effort + Unix-only
    // (on Windows the rename is journalled, and opening a directory as a File to
    // fsync it isn't valid).
    #[cfg(unix)]
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// The pid-scoped temp sibling for `path` (`<name>.<pid>.tmp` in the SAME
/// directory, so the rename stays on one filesystem and is therefore atomic).
fn tmp_sibling(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(format!(".{}.tmp", std::process::id()));
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_bytes_and_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("out.txt");
        atomic_write(&target, b"hello world").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"hello world");
        // The temp sibling must be gone after a successful rename.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "no .tmp file may survive a successful write");
    }

    #[test]
    fn overwrites_existing_target_without_a_no_file_window() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("out.txt");
        std::fs::write(&target, b"old contents").unwrap();
        atomic_write(&target, b"new").unwrap();
        // The target file always existed (rename replaces in place); no
        // remove-then-rename gap. Content is the new bytes.
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
    }

    #[test]
    fn creates_missing_parent_dir() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("nested").join("deep").join("out.txt");
        atomic_write(&target, b"x").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"x");
    }
}
