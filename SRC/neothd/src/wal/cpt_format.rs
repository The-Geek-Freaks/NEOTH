//! ADV-01 — `.cpt` + `.cpt.hmac` file format read/write helpers.
//!
//! See [`super::cpt_auth`] for the threat model. This module owns the
//! on-disk format: two paired files per compacted segment.
//!
//! ```text
//! ~/.neoth/wal/
//!   wal-00000017.bin.cpt        # compacted replacement bytes
//!   wal-00000017.bin.cpt.hmac   # 32-byte HMAC-SHA256 over .cpt content
//! ```
//!
//! Writes follow the SPEC §4.3 atomic-rename order so that a crash
//! between any two steps still leaves the recovery scan in a
//! verifiable state:
//!
//! ```text
//! 1. write    {cpt_path}.tmp
//! 2. fsync    {cpt_path}.tmp
//! 3. write    {cpt_path}.hmac.tmp
//! 4. fsync    {cpt_path}.hmac.tmp
//! 5. rename   {cpt_path}.hmac.tmp -> {cpt_path}.hmac
//! 6. rename   {cpt_path}.tmp      -> {cpt_path}
//! 7. fsync    parent dir   (unix only — durable rename barrier)
//! ```
//!
//! The hmac file lands BEFORE the .cpt file so the recovery scan
//! never sees a .cpt without its paired .hmac (which would be the
//! pre-ADV-01 unauthenticated state).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::cpt_auth::{CPT_HMAC_TAG_LEN, CompactionAuthenticator};
use super::error::WalError;

/// Suffix appended to a `.cpt` path to derive its sibling HMAC file
/// path. Operators inspecting `~/.neoth/wal/` directly see the pair
/// as `.cpt` and `.cpt.hmac` — wire-stable.
pub const CPT_HMAC_SUFFIX: &str = ".hmac";

/// Suffix used to quarantine a `.cpt`/`.cpt.hmac` pair that failed
/// authentication. Includes a unix-ts so multiple quarantines from
/// repeated startup-failures don't collide.
pub fn rejected_suffix(ts_unix: u64) -> String {
    format!(".rejected.{ts_unix}")
}

/// Build the `.cpt.hmac` path for a given `.cpt` path.
pub fn hmac_path_for(cpt_path: &Path) -> PathBuf {
    let mut s = cpt_path.as_os_str().to_owned();
    s.push(CPT_HMAC_SUFFIX);
    PathBuf::from(s)
}

/// SPEC §4.3 step 1-7: write `content` to `{cpt_path}` and its HMAC
/// to `{cpt_path}.hmac` using the atomic-rename sequence above.
///
/// Caller passes the already-computed cpt content (the writer that
/// builds the compacted segment owns frame layout — this function is
/// only the persistence + auth layer).
pub fn write_cpt_pair(
    cpt_path: &Path,
    content: &[u8],
    auth: &CompactionAuthenticator,
) -> Result<()> {
    let hmac_path = hmac_path_for(cpt_path);
    let cpt_tmp = with_suffix(cpt_path, ".tmp");
    let hmac_tmp = with_suffix(&hmac_path, ".tmp");

    // 1-2: write + fsync the .cpt content.
    write_and_sync(&cpt_tmp, content).with_context(|| format!("write {}", cpt_tmp.display()))?;

    // 3-4: compute + write + fsync the HMAC.
    let tag = auth.sign(content);
    write_and_sync(&hmac_tmp, &tag).with_context(|| format!("write {}", hmac_tmp.display()))?;

    // 5: rename .hmac.tmp -> .hmac FIRST so a crash here leaves a
    // verifiable .hmac without a matching .cpt — recovery treats
    // orphan .hmac as "no work to do" + cleans up.
    fs::rename(&hmac_tmp, &hmac_path)
        .with_context(|| format!("rename {} -> {}", hmac_tmp.display(), hmac_path.display()))?;

    // 6: rename .cpt.tmp -> .cpt. After this point the pair is live
    // for the next recovery scan.
    fs::rename(&cpt_tmp, cpt_path)
        .with_context(|| format!("rename {} -> {}", cpt_tmp.display(), cpt_path.display()))?;

    // 7: best-effort parent-dir fsync (unix only — Windows has no
    // equivalent API; the file renames are already durable on NTFS).
    #[cfg(unix)]
    if let Some(parent) = cpt_path.parent() {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    Ok(())
}

/// SPEC §4.3 crash-recovery: read `.cpt` + verify against `.cpt.hmac`.
/// On success returns the verified `.cpt` content. On any failure
/// returns `WalError::CompactionAuthFailed` — caller MUST treat as a
/// security event (quarantine via [`quarantine_pair`] + emit
/// `EVENT_TYPE_COMPACTION_AUTH_FAILED`).
pub fn read_and_verify_cpt(
    cpt_path: &Path,
    auth: &CompactionAuthenticator,
) -> Result<Vec<u8>, WalError> {
    let hmac_path = hmac_path_for(cpt_path);

    let content = fs::read(cpt_path).map_err(WalError::Io)?;

    let hmac_bytes = match fs::read(&hmac_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(WalError::CompactionAuthFailed {
                reason: format!(
                    "hmac sidecar missing: {} has no paired .hmac file",
                    cpt_path.display()
                ),
            });
        }
        Err(e) => return Err(WalError::Io(e)),
    };

    if hmac_bytes.len() != CPT_HMAC_TAG_LEN {
        return Err(WalError::CompactionAuthFailed {
            reason: format!(
                "hmac sidecar at {} has wrong length: {} bytes (expected {})",
                hmac_path.display(),
                hmac_bytes.len(),
                CPT_HMAC_TAG_LEN
            ),
        });
    }

    auth.verify(&content, &hmac_bytes)?;
    Ok(content)
}

/// Move a failed `.cpt` + `.cpt.hmac` pair out of the recovery scan
/// path so a subsequent restart doesn't keep retrying the same
/// poisoned input. Returns the quarantine destination path so callers
/// can embed it in the audit-event payload.
pub fn quarantine_pair(cpt_path: &Path, ts_unix: u64) -> Result<PathBuf> {
    let hmac_path = hmac_path_for(cpt_path);
    let suffix = rejected_suffix(ts_unix);
    let cpt_quarantine = with_suffix(cpt_path, &suffix);
    let hmac_quarantine = with_suffix(&hmac_path, &suffix);

    // Best-effort: rename .cpt even if the .hmac was already missing.
    if cpt_path.exists() {
        fs::rename(cpt_path, &cpt_quarantine)
            .with_context(|| format!("quarantine .cpt {}", cpt_path.display()))?;
    }
    if hmac_path.exists() {
        // Sidecar may not exist (missing-hmac branch) — ignore the
        // error if so, surface real I/O failures otherwise.
        if let Err(e) = fs::rename(&hmac_path, &hmac_quarantine) {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(e).context(format!("quarantine .hmac {}", hmac_path.display()));
            }
        }
    }
    Ok(cpt_quarantine)
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

fn write_and_sync(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fixture_auth() -> CompactionAuthenticator {
        let master: Vec<u8> = (0u8..32).collect();
        CompactionAuthenticator::from_master_key(&master)
    }

    #[test]
    fn hmac_path_appends_dot_hmac_suffix() {
        let cpt = PathBuf::from("/tmp/wal/wal-00000007.bin.cpt");
        let h = hmac_path_for(&cpt);
        assert_eq!(h.to_string_lossy(), "/tmp/wal/wal-00000007.bin.cpt.hmac");
    }

    #[test]
    fn write_and_read_roundtrips_with_valid_hmac() {
        let dir = tempdir().unwrap();
        let cpt = dir.path().join("wal-00000001.bin.cpt");
        let auth = fixture_auth();
        let content = b"compacted segment bytes, including frames and a SEGMENT_HEADER";
        write_cpt_pair(&cpt, content, &auth).unwrap();

        // Pair exists on disk.
        assert!(cpt.exists(), ".cpt must exist after write");
        assert!(
            hmac_path_for(&cpt).exists(),
            ".cpt.hmac must exist after write"
        );

        // Verifies cleanly.
        let recovered = read_and_verify_cpt(&cpt, &auth).expect("valid pair verifies");
        assert_eq!(recovered, content);
    }

    #[test]
    fn read_rejects_tampered_cpt_content() {
        let dir = tempdir().unwrap();
        let cpt = dir.path().join("wal-00000002.bin.cpt");
        let auth = fixture_auth();
        let content = b"original compacted payload";
        write_cpt_pair(&cpt, content, &auth).unwrap();

        // Tamper: flip a byte in the .cpt file (post-rename) without
        // updating the .hmac. Simulates an attacker who modifies the
        // payload but cannot forge the HMAC without the key.
        let mut bytes = fs::read(&cpt).unwrap();
        bytes[3] ^= 0xFF;
        fs::write(&cpt, &bytes).unwrap();

        let err = read_and_verify_cpt(&cpt, &auth).expect_err("tampered payload must fail auth");
        match err {
            WalError::CompactionAuthFailed { .. } => {}
            other => panic!("expected CompactionAuthFailed, got: {other:?}"),
        }
    }

    #[test]
    fn read_rejects_missing_hmac_sidecar() {
        let dir = tempdir().unwrap();
        let cpt = dir.path().join("wal-00000003.bin.cpt");
        let auth = fixture_auth();
        write_cpt_pair(&cpt, b"payload", &auth).unwrap();

        // Delete the .hmac, leaving an orphan .cpt — the pre-ADV-01
        // unauthenticated-state that the recovery scan MUST refuse.
        fs::remove_file(hmac_path_for(&cpt)).unwrap();

        let err = read_and_verify_cpt(&cpt, &auth).expect_err("missing .hmac must fail auth");
        match err {
            WalError::CompactionAuthFailed { reason } => {
                assert!(
                    reason.contains("hmac sidecar missing"),
                    "expected missing-sidecar reason, got: {reason}"
                );
            }
            other => panic!("expected CompactionAuthFailed, got: {other:?}"),
        }
    }

    #[test]
    fn read_rejects_wrong_length_hmac() {
        let dir = tempdir().unwrap();
        let cpt = dir.path().join("wal-00000004.bin.cpt");
        let auth = fixture_auth();
        write_cpt_pair(&cpt, b"payload", &auth).unwrap();

        // Truncate the .hmac sidecar to 16 bytes — wrong length.
        let h = hmac_path_for(&cpt);
        let mut hbytes = fs::read(&h).unwrap();
        hbytes.truncate(16);
        fs::write(&h, &hbytes).unwrap();

        let err = read_and_verify_cpt(&cpt, &auth).expect_err("short .hmac must fail auth");
        match err {
            WalError::CompactionAuthFailed { reason } => {
                assert!(
                    reason.contains("wrong length"),
                    "expected wrong-length reason, got: {reason}"
                );
            }
            other => panic!("expected CompactionAuthFailed, got: {other:?}"),
        }
    }

    #[test]
    fn read_rejects_pair_signed_with_different_key() {
        let dir = tempdir().unwrap();
        let cpt = dir.path().join("wal-00000005.bin.cpt");
        let alice = fixture_auth();
        let bob_master: Vec<u8> = (32u8..64).collect();
        let bob = CompactionAuthenticator::from_master_key(&bob_master);

        // Alice signs + writes.
        write_cpt_pair(&cpt, b"alice payload", &alice).unwrap();

        // Bob's authenticator must NOT verify Alice's signature.
        let err = bob
            .verify(b"alice payload", &fs::read(hmac_path_for(&cpt)).unwrap())
            .expect_err("cross-key verify must fail");
        match err {
            WalError::CompactionAuthFailed { .. } => {}
            other => panic!("expected CompactionAuthFailed, got: {other:?}"),
        }
    }

    #[test]
    fn quarantine_moves_both_files_with_timestamp_suffix() {
        let dir = tempdir().unwrap();
        let cpt = dir.path().join("wal-00000006.bin.cpt");
        let auth = fixture_auth();
        write_cpt_pair(&cpt, b"will be quarantined", &auth).unwrap();

        let dest = quarantine_pair(&cpt, 1_716_595_200).unwrap();
        assert!(!cpt.exists(), "original .cpt must be gone after quarantine");
        assert!(
            !hmac_path_for(&cpt).exists(),
            "original .cpt.hmac must be gone after quarantine"
        );
        assert!(dest.exists(), "quarantine destination must exist");
        let dest_str = dest.to_string_lossy();
        assert!(
            dest_str.contains(".rejected.1716595200"),
            "destination must include rejected suffix, got: {dest_str}"
        );
    }

    #[test]
    fn quarantine_handles_missing_hmac_gracefully() {
        let dir = tempdir().unwrap();
        let cpt = dir.path().join("wal-00000007.bin.cpt");
        fs::write(&cpt, b"orphan .cpt without .hmac").unwrap();

        let dest = quarantine_pair(&cpt, 1_716_595_201).unwrap();
        assert!(dest.exists());
        assert!(!cpt.exists());
    }

    #[test]
    fn quarantine_no_op_when_neither_file_exists() {
        let dir = tempdir().unwrap();
        let cpt = dir.path().join("wal-00000008.bin.cpt");
        // Neither file exists — quarantine should not panic and
        // should return a destination path even if no rename happened.
        let r = quarantine_pair(&cpt, 1_716_595_202);
        assert!(r.is_ok(), "quarantine over absent files must not error");
    }

    #[test]
    fn write_cpt_pair_creates_atomic_rename_invariant() {
        // After write_cpt_pair completes successfully, the .tmp files
        // must be gone (renamed to their final names). Verifies the
        // SPEC §4.3 atomic-rename sequence didn't leak intermediates.
        let dir = tempdir().unwrap();
        let cpt = dir.path().join("wal-00000009.bin.cpt");
        let auth = fixture_auth();
        write_cpt_pair(&cpt, b"x", &auth).unwrap();
        assert!(!with_suffix(&cpt, ".tmp").exists());
        assert!(!with_suffix(&hmac_path_for(&cpt), ".tmp").exists());
    }
}
