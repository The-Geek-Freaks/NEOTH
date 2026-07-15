//! Rolling-24h council-convene counter — GOLD-SEC-32 / B-25.
//!
//! # Atomic admission invariant
//!
//! At most [`MAX_CONVENES_PER_24H`] council convenes may be recorded in any
//! rolling 24-hour window. This is enforced with strict fail-closed semantics:
//! every I/O failure (lock timeout, read error, parse error, write error)
//! returns [`AdmitResult::StateInvalid`] — never a silent admission.
//!
//! State is a JSON array of unix-second timestamps at
//! `<home>/council_convene_log.json`, written atomically via
//! [`crate::util::atomic_write::atomic_write`]. A sibling lock file
//! `council_convene_log.lock` serialises the read-modify-write cycle across
//! concurrent CLI invocations and channel-pipeline tasks so no two processes
//! can race past the cap.

use std::path::{Path, PathBuf};

/// Hard ceiling on council convenes in any rolling 24-hour window.
/// Generous enough that an interactive operator never hits it (that would be
/// a convene every ~3 minutes, non-stop, for a day), but stops a runaway
/// autonomous loop from fanning out provider calls without bound.
/// A fixed safety backstop — not an operator tunable.
pub const MAX_CONVENES_PER_24H: u32 = 500;

const WINDOW_SECS: i64 = 24 * 60 * 60;

fn log_path(home: &Path) -> PathBuf {
    home.join("council_convene_log.json")
}

fn lock_path(home: &Path) -> PathBuf {
    home.join("council_convene_log.lock")
}

/// Result of a single council-convene admission attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitResult {
    /// Convene admitted; the timestamp has been durably appended.
    Admitted,
    /// Rolling-24h cap already reached; this convene is denied.
    Capped,
    /// Log state is invalid (corrupt, unreadable, lock timeout, or write
    /// failure). Admission is denied; the operator should inspect the home
    /// directory for a `.corrupt.<pid>` quarantine file.
    StateInvalid,
}

/// Attempt to admit one council convene at `now_unix` under a strict OS file
/// lock.
///
/// The lock on `council_convene_log.lock` is held for the entire
/// load → prune → cap-check → append → atomic-persist cycle, so at most
/// `MAX_CONVENES_PER_24H` convenes can commit in any rolling window
/// regardless of concurrency, crash, corruption, or I/O failure.
///
/// Fail-closed: any error (lock timeout, read, parse, write) returns
/// [`AdmitResult::StateInvalid`].
pub fn try_admit_convene(home: &Path, now_unix: i64) -> AdmitResult {
    // Step 1 — exclusive cross-process lock (5 s give-up → fail-closed).
    let _lock = match lock_log_file(home) {
        Ok(f) => f,
        Err(_) => return AdmitResult::StateInvalid,
    };

    let log = log_path(home);

    // Step 2 — strict load (missing → empty, any error → quarantine + deny).
    let mut timestamps = match load_strict(&log, now_unix) {
        Ok(ts) => ts,
        Err(LoadFail::Missing) => Vec::new(),
        Err(LoadFail::Corrupt(raw)) => {
            quarantine_corrupt(&log, raw);
            return AdmitResult::StateInvalid;
        }
    };

    // Step 3 — cap check (>= is correct: len is post-prune in-window count).
    if timestamps.len() >= MAX_CONVENES_PER_24H as usize {
        return AdmitResult::Capped;
    }

    // Step 4 — append + atomic persist (fsync + rename via atomic_write).
    timestamps.push(now_unix);
    let bytes = match serde_json::to_vec(&timestamps) {
        Ok(b) => b,
        Err(_) => return AdmitResult::StateInvalid,
    };
    match crate::util::atomic_write::atomic_write(&log, &bytes) {
        Ok(()) => AdmitResult::Admitted,
        Err(_) => AdmitResult::StateInvalid,
    }
}

/// GR-020-style bounded-blocking exclusive OS lock on
/// `<home>/council_convene_log.lock`. Dropping the returned `File` releases
/// the lock. Non-blocking acquire retried every 50 ms; gives up after 5 s and
/// returns `Err` (caller maps to `StateInvalid` — fail-closed).
fn lock_log_file(home: &Path) -> std::io::Result<std::fs::File> {
    let lock = lock_path(home);
    if let Some(parent) = lock.parent() {
        std::fs::create_dir_all(parent)?;
    }
    const RETRY: std::time::Duration = std::time::Duration::from_millis(50);
    const GIVE_UP: std::time::Duration = std::time::Duration::from_secs(5);
    let started = std::time::Instant::now();
    loop {
        if let Some(f) = try_lock_log_file_once(&lock)? {
            return Ok(f);
        }
        if started.elapsed() >= GIVE_UP {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "council convene log lock {} held by another process for >5 s",
                    lock.display()
                ),
            ));
        }
        std::thread::sleep(RETRY);
    }
}

/// One non-blocking exclusive-acquire attempt on the lock file.
/// `Ok(Some(file))` = acquired (drop releases); `Ok(None)` = currently held
/// elsewhere; `Err` = real I/O failure. Windows: `FILE_SHARE_READ` share-mode
/// (second write-open hits `ERROR_SHARING_VIOLATION`); Unix: advisory
/// `flock(LOCK_EX | LOCK_NB)`.
fn try_lock_log_file_once(lock_path: &Path) -> std::io::Result<Option<std::fs::File>> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const ERROR_SHARING_VIOLATION: i32 = 32;
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(FILE_SHARE_READ)
            .open(lock_path)
        {
            Ok(f) => Ok(Some(f)),
            Err(e) if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => Ok(None),
            Err(e) => Err(e),
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        // SAFETY: plain flock syscall on a valid owned fd.
        let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            Ok(Some(f))
        } else {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

/// Why [`load_strict`] failed to return a usable timestamp list.
enum LoadFail {
    /// The log file does not yet exist — treat as empty (no quarantine needed).
    Missing,
    /// The file exists but could not be read (I/O error) or could not be
    /// parsed (JSON error). Carries the raw bytes for quarantine; empty `Vec`
    /// when the file could not be read at all.
    Corrupt(Vec<u8>),
}

/// Load and prune the convene log strictly.
///
/// - `NotFound` → `Err(LoadFail::Missing)` (caller treats as empty).
/// - Any other read error → `Err(LoadFail::Corrupt(vec![]))`.
/// - JSON parse error → `Err(LoadFail::Corrupt(raw_bytes))`.
/// - Success → `Ok(in_window_timestamps)`.
fn load_strict(log_path: &Path, now_unix: i64) -> Result<Vec<i64>, LoadFail> {
    let raw = match std::fs::read(log_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(LoadFail::Missing);
        }
        Err(_) => return Err(LoadFail::Corrupt(vec![])),
    };
    let mut tss: Vec<i64> =
        serde_json::from_slice(&raw).map_err(|_| LoadFail::Corrupt(raw.clone()))?;
    let cutoff = now_unix - WINDOW_SECS;
    tss.retain(|&t| t > cutoff);
    Ok(tss)
}

/// Preserve corrupt log bytes by renaming the file to
/// `<log_path>.corrupt.<pid>`. If the rename fails (e.g. the file path is
/// unreadable so there is nothing to rename, or a cross-device move), write
/// `raw` to the quarantine path directly. Never silently overwrites the
/// original.
fn quarantine_corrupt(log_path: &Path, raw: Vec<u8>) {
    let quarantine = PathBuf::from(format!(
        "{}.corrupt.{}",
        log_path.display(),
        std::process::id()
    ));
    if std::fs::rename(log_path, &quarantine).is_err() {
        // rename failed — write the captured bytes to the quarantine path.
        let _ = std::fs::write(&quarantine, &raw);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use tempfile::tempdir;

    // ── test helpers ─────────────────────────────────────────────────────────

    fn read_log(home: &Path) -> Vec<i64> {
        let raw = std::fs::read(log_path(home)).unwrap_or_default();
        serde_json::from_slice(&raw).unwrap_or_default()
    }

    fn seed_log(home: &Path, timestamps: &[i64]) {
        let bytes = serde_json::to_vec(timestamps).unwrap();
        crate::util::atomic_write::atomic_write(&log_path(home), &bytes).unwrap();
    }

    // ── adapted existing tests ────────────────────────────────────────────────

    #[test]
    fn empty_log_counts_zero_and_not_capped() {
        let dir = tempdir().unwrap();
        // No log file present: first admission must succeed and create the log.
        assert_eq!(
            try_admit_convene(dir.path(), 1_000_000),
            AdmitResult::Admitted
        );
        assert_eq!(read_log(dir.path()).len(), 1);
    }

    #[test]
    fn record_increments_within_window() {
        let dir = tempdir().unwrap();
        let now = 1_000_000_i64;
        assert_eq!(try_admit_convene(dir.path(), now), AdmitResult::Admitted);
        assert_eq!(
            try_admit_convene(dir.path(), now + 10),
            AdmitResult::Admitted
        );
        assert_eq!(
            try_admit_convene(dir.path(), now + 20),
            AdmitResult::Admitted
        );
        // All three timestamps are within the window relative to now+30.
        let in_window: Vec<_> = read_log(dir.path())
            .into_iter()
            .filter(|&t| t > (now + 30 - WINDOW_SECS))
            .collect();
        assert_eq!(in_window.len(), 3);
    }

    #[test]
    fn entries_outside_24h_window_are_pruned() {
        let dir = tempdir().unwrap();
        let now = 2_000_000_i64;
        // Two old entries (just outside the window) + one in-window.
        seed_log(
            dir.path(),
            &[now - WINDOW_SECS - 5, now - WINDOW_SECS - 1, now - 100],
        );
        // Admitting at `now` prunes the two old entries; returns Admitted.
        assert_eq!(try_admit_convene(dir.path(), now), AdmitResult::Admitted);
        // Post-admit log: only the in-window entry (now-100) + newly admitted
        // `now` survive — 2 total.
        let after = read_log(dir.path());
        assert_eq!(after.len(), 2, "only in-window entries survive: {after:?}");
    }

    #[test]
    fn cap_reached_at_threshold() {
        let dir = tempdir().unwrap();
        let now = 3_000_000_i64;
        // Seed exactly MAX in-window timestamps.
        let tss: Vec<i64> = (0..MAX_CONVENES_PER_24H as i64).map(|i| now - i).collect();
        seed_log(dir.path(), &tss);
        assert_eq!(try_admit_convene(dir.path(), now), AdmitResult::Capped);
    }

    // ── new tests from B25 spec ───────────────────────────────────────────────

    #[test]
    fn missing_log_admits_and_creates_file() {
        let dir = tempdir().unwrap();
        assert!(!log_path(dir.path()).exists());
        assert_eq!(
            try_admit_convene(dir.path(), 5_000_000),
            AdmitResult::Admitted
        );
        assert!(log_path(dir.path()).exists());
        assert_eq!(read_log(dir.path()), vec![5_000_000_i64]);
    }

    #[test]
    fn corrupt_log_blocks_admission_bytes_preserved() {
        let dir = tempdir().unwrap();
        let corrupt: &[u8] = b"not json at all";
        std::fs::write(log_path(dir.path()), corrupt).unwrap();

        let result = try_admit_convene(dir.path(), 1_000_000);
        assert_eq!(result, AdmitResult::StateInvalid);

        // A quarantine file must exist alongside (or instead of) the log.
        let quarantine_file = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .find(|e| e.path().to_string_lossy().contains(".corrupt."))
            .map(|e| e.path())
            .expect("quarantine file must be created");

        let quarantine_bytes = std::fs::read(&quarantine_file).unwrap();
        assert_eq!(
            quarantine_bytes, corrupt,
            "quarantine file must be byte-identical to original corrupt content"
        );

        // The main log path must not still hold the corrupt bytes.
        let main_content = std::fs::read(log_path(dir.path())).unwrap_or_default();
        assert_ne!(
            main_content, corrupt,
            "original corrupt bytes must not remain at log path after quarantine"
        );
    }

    #[test]
    #[cfg(unix)]
    fn unreadable_log_blocks_admission() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let log = log_path(dir.path());
        std::fs::write(&log, b"[1000000]").unwrap();
        // Remove all permissions — makes the file unreadable.
        std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o000)).unwrap();
        let result = try_admit_convene(dir.path(), 2_000_000);
        // Restore so tempdir can clean up.
        std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o644)).ok();
        assert_eq!(result, AdmitResult::StateInvalid);
    }

    #[test]
    #[cfg(windows)]
    fn unreadable_log_blocks_admission() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = tempdir().unwrap();
        let log = log_path(dir.path());
        std::fs::write(&log, b"[1000000]").unwrap();
        // Hold exclusive (no-share) handle: our std::fs::read will hit
        // ERROR_SHARING_VIOLATION → Err(Corrupt) → StateInvalid.
        let _hold = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(&log)
            .unwrap();
        let result = try_admit_convene(dir.path(), 2_000_000);
        assert_eq!(result, AdmitResult::StateInvalid);
    }

    /// Seed the log at MAX-3; spawn 5 threads all racing through a Barrier.
    /// Exactly 3 must be admitted and 2 must be capped (OS lock serialises).
    #[test]
    fn n_concurrent_admissions_near_cap_exact_remaining() {
        let dir = tempdir().unwrap();
        let now = 10_000_000_i64;
        let seed: Vec<i64> = (0..(MAX_CONVENES_PER_24H - 3) as i64)
            .map(|i| now - i)
            .collect();
        seed_log(dir.path(), &seed);

        let home = Arc::new(dir.path().to_path_buf());
        let barrier = Arc::new(Barrier::new(5));

        let handles: Vec<_> = (0..5)
            .map(|_| {
                let home = Arc::clone(&home);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    try_admit_convene(&home, now)
                })
            })
            .collect();

        let results: Vec<AdmitResult> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        let admitted = results
            .iter()
            .filter(|&&r| r == AdmitResult::Admitted)
            .count();
        let capped = results
            .iter()
            .filter(|&&r| r == AdmitResult::Capped)
            .count();

        assert_eq!(
            admitted, 3,
            "exactly 3 threads must be admitted (filling to cap): {results:?}"
        );
        assert_eq!(capped, 2, "exactly 2 threads must be capped: {results:?}");
    }

    #[test]
    #[cfg(unix)]
    fn write_failure_preserves_valid_state_returns_state_invalid() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let now = 4_000_000_i64;
        seed_log(dir.path(), &[now - 100, now - 50]);
        // Pre-create the lock file so lock acquisition can open it even after
        // the directory becomes read-only (opening existing file doesn't need
        // dir-write; creating a new entry does).
        std::fs::write(lock_path(dir.path()), b"").unwrap();

        // Make the parent dir read-only: atomic_write can't create the .tmp
        // sibling (new directory entry) → write fails → StateInvalid.
        let path = dir.path().to_path_buf();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o555)).unwrap();
        let result = try_admit_convene(&path, now);
        // Restore so tempdir can clean up.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).ok();

        assert_eq!(result, AdmitResult::StateInvalid);
        // Original 2-entry log must still be intact.
        let restored = read_log(&path);
        assert_eq!(
            restored.len(),
            2,
            "original log must be preserved on write failure"
        );
    }

    #[test]
    #[cfg(windows)]
    fn write_failure_preserves_valid_state_returns_state_invalid() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = tempdir().unwrap();
        let now = 4_000_000_i64;
        seed_log(dir.path(), &[now - 100, now - 50]);

        // Hold the JSON log file with FILE_SHARE_READ only (no delete sharing).
        // Our lock acquisition targets council_convene_log.lock (unaffected).
        // Our std::fs::read uses GENERIC_READ (compatible with FILE_SHARE_READ).
        // atomic_write's rename-over-target needs delete → fails with
        // ERROR_ACCESS_DENIED → StateInvalid.
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        let hold = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ)
            .open(log_path(dir.path()))
            .unwrap();

        let result = try_admit_convene(dir.path(), now);
        drop(hold); // release before reading to verify
        assert_eq!(result, AdmitResult::StateInvalid);

        let restored = read_log(dir.path());
        assert_eq!(
            restored.len(),
            2,
            "original log must be preserved on write failure"
        );
    }

    #[test]
    fn rolling_window_boundary_exact() {
        let dir = tempdir().unwrap();
        let now = 6_000_000_i64;
        // Entry exactly AT the cutoff (t == now - WINDOW_SECS) is EXCLUDED
        // (retain condition: t > cutoff). Entry at now - WINDOW_SECS + 1 is
        // INCLUDED.
        seed_log(dir.path(), &[now - WINDOW_SECS, now - WINDOW_SECS + 1]);
        assert_eq!(try_admit_convene(dir.path(), now), AdmitResult::Admitted);
        let after = read_log(dir.path());
        // Should contain only (now - WINDOW_SECS + 1) and the new `now`.
        assert_eq!(
            after.len(),
            2,
            "boundary-excluded entry pruned, in-window entry retained: {after:?}"
        );
        assert!(
            after.contains(&(now - WINDOW_SECS + 1)),
            "in-window entry must survive"
        );
        assert!(after.contains(&now), "newly admitted entry must appear");
    }

    #[test]
    fn admitted_count_reaches_cap_then_blocks() {
        let dir = tempdir().unwrap();
        let now = 7_000_000_i64;
        for i in 0..MAX_CONVENES_PER_24H {
            assert_eq!(
                try_admit_convene(dir.path(), now + i as i64),
                AdmitResult::Admitted,
                "admission {} of {} should be Admitted",
                i + 1,
                MAX_CONVENES_PER_24H
            );
        }
        assert_eq!(
            try_admit_convene(dir.path(), now + MAX_CONVENES_PER_24H as i64),
            AdmitResult::Capped,
            "call after cap must be Capped"
        );
    }
}
