//! PC-01 (write slice) — the actual file write, AFTER the gate passed.
//!
//! Best-effort atomic write: stage into a temp file in the SAME directory (so
//! the rename stays on one filesystem) then rename over the target. On a crash
//! mid-write the operator sees the old file or the temp, never a half-written
//! target. The path here is the already-resolved, allowlist-validated target —
//! this module performs NO gating.

use std::io;
use std::path::Path;

/// Write `contents` to `path` best-effort-atomically (temp + rename). The
/// caller has already validated `path` through the write-allowlist + autonomy
/// gate. The parent dir must exist (we never create it).
pub fn write_file_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "write target has no parent dir",
        )
    })?;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("target");
    // Temp name in the same dir; pid keeps concurrent daemon writes from
    // colliding (writes are gated + effectively serial, so this is ample).
    let tmp = parent.join(format!(
        ".neoth-write-{}-{file_name}.tmp",
        std::process::id()
    ));

    if let Err(e) = std::fs::write(&tmp, contents) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    // Single rename is the atomic commit: `std::fs::rename` REPLACES an existing
    // destination file on BOTH Unix (`rename(2)` — replaces the target inode,
    // never follows a dest symlink) and modern Windows (std uses MoveFileExW
    // with MOVEFILE_REPLACE_EXISTING). The earlier remove-then-rename fallback
    // was unnecessary AND opened a swap window between the remove and the second
    // rename (SL review MEDIUM) — dropped. On a hard rename failure, clean up.
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn writes_new_file() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("new.txt");
        write_file_atomic(&f, b"hello").unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"hello");
    }

    #[test]
    fn overwrites_existing_file_and_leaves_no_temp() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("x.txt");
        std::fs::write(&f, b"old contents here").unwrap();
        write_file_atomic(&f, b"new").unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"new");
        // No `.tmp` left behind.
        let leftover: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(leftover.is_empty(), "temp file must be cleaned up");
    }
}
