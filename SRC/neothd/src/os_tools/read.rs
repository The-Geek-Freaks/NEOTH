//! PC-01 pure file reader — called ONLY after the gate validated the path.

use std::io::Read;
use std::path::Path;

use anyhow::Context;

/// Read a UTF-8 text file, capped at `max_bytes`. Rejects oversize files,
/// non-regular files (pipe / device / dir / `/proc`), and non-UTF-8 (binary)
/// content. The caller MUST have already passed `canonical` through
/// [`super::allowlist::resolve_within_allowlist`] + the autonomy gate.
///
/// Hardening (PC-01 security review): the size cap is enforced on an ALREADY-
/// OPEN fd, and the read itself is bounded by `take(max + 1)`. This closes
/// two holes:
///   - **special-file bypass**: a FIFO / device / `/proc` entry reports
///     `len() == 0`, so a `len() > max` pre-check would pass and the read
///     would block forever or stream unbounded bytes — `is_file()` on the fd
///     refuses them up front.
///   - **stat→read TOCTOU**: statting the OPEN fd (not the path) plus the
///     `take(max + 1)` bound means a file swapped/grown after the size check
///     still cannot OOM us — the read is hard-bounded regardless.
pub fn read_file_text(canonical: &Path, max_bytes: usize) -> anyhow::Result<String> {
    let file =
        std::fs::File::open(canonical).with_context(|| format!("open {}", canonical.display()))?;
    let meta = file
        .metadata()
        .with_context(|| format!("stat {}", canonical.display()))?;
    if !meta.file_type().is_file() {
        anyhow::bail!(
            "{} is not a regular file — pipes, devices, directories and /proc \
             entries are refused (their size is unbounded / unreportable)",
            canonical.display()
        );
    }
    let len = meta.len();
    if len > max_bytes as u64 {
        anyhow::bail!(
            "file {} is {len} bytes, exceeds tools.os.max_read_bytes={max_bytes}",
            canonical.display()
        );
    }
    // Read from the SAME fd we statted, hard-capped at max+1 so even a
    // post-stat growth (TOCTOU) cannot exceed the budget.
    let mut buf = Vec::with_capacity(len.min(max_bytes as u64) as usize);
    file.take(max_bytes as u64 + 1)
        .read_to_end(&mut buf)
        .with_context(|| format!("read {}", canonical.display()))?;
    if buf.len() > max_bytes {
        anyhow::bail!(
            "file {} exceeded tools.os.max_read_bytes={max_bytes} during read (grew after stat?)",
            canonical.display()
        );
    }
    String::from_utf8(buf)
        .with_context(|| format!("{} is not valid UTF-8 (binary file?)", canonical.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn reads_small_utf8_file() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("a.txt");
        fs::write(&f, b"hello").unwrap();
        assert_eq!(read_file_text(&f, 1024).unwrap(), "hello");
    }

    #[test]
    fn rejects_oversize_file() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("big.txt");
        fs::write(&f, vec![b'x'; 100]).unwrap();
        let err = read_file_text(&f, 10).unwrap_err();
        assert!(err.to_string().contains("exceeds"));
    }

    #[test]
    fn rejects_binary_non_utf8() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("bin");
        fs::write(&f, [0xff, 0xfe, 0x00, 0x01]).unwrap();
        let err = read_file_text(&f, 1024).unwrap_err();
        assert!(err.to_string().contains("not valid UTF-8"));
    }

    #[test]
    fn rejects_non_regular_file() {
        // A directory is the portable non-regular file: `is_file()` is false
        // on every OS (and File::open of a dir errors on Windows) — either way
        // the read is refused, which is the special-file (pipe/device/proc)
        // bypass guard the size cap alone could not provide.
        let dir = tempdir().unwrap();
        let sub = dir.path().join("subdir");
        fs::create_dir(&sub).unwrap();
        assert!(read_file_text(&sub, 1024).is_err());
    }
}
