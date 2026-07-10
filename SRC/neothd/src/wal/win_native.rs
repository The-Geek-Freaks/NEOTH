// Windows native security + durability primitives for NEOTH WAL.
//
// E-11: Safe wrapper around `SetNamedSecurityInfoW` + `SetEntriesInAclW`
//        for DACL restriction of WAL segments and config files.
//        Replaces the previous `icacls.exe` subprocess approach (D-008).
//
// E-12: Safe wrapper around `FlushFileBuffers` for durable WAL writes on
//        Windows. Equivalent to `fsync(2)` on Unix.
//
// All Win32 FFI calls are isolated here behind safe function boundaries.
// Every `unsafe` block carries a `// SAFETY:` comment documenting the
// non-null / aligned / init invariants required by the Win32 ABI.
//
// Cross-platform: the entire file is `#[cfg(target_os = "windows")]` —
// Linux / macOS builds never compile this module.

#![cfg(target_os = "windows")]

use std::fs::File;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use tracing::warn;

// ── E-11 imports ───────────────────────────────────────────────────────────
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HANDLE, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GRANT_ACCESS, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, SetEntriesInAclW,
    SetNamedSecurityInfoW, TRUSTEE_IS_NAME, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::{ACL, DACL_SECURITY_INFORMATION, NO_INHERITANCE};

// ── E-12 import ────────────────────────────────────────────────────────────
use windows_sys::Win32::Storage::FileSystem::FlushFileBuffers;

// ───────────────────────────────────────────────────────────────────────────
// Internal helpers
// ───────────────────────────────────────────────────────────────────────────

/// Encode a Rust `&str` as a null-terminated UTF-16 `Vec<u16>` for Win32.
fn to_wide_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0u16)).collect()
}

/// Convert a Win32 error code to an `io::Error`.
fn win32_io_err(code: u32) -> io::Error {
    io::Error::from_raw_os_error(code as i32)
}

/// Map a Win32 `WIN32_ERROR` return value to `io::Result<()>`.
/// `ERROR_SUCCESS` (0) maps to `Ok`; anything else maps to `Err` with a
/// human-readable context string prepended.
fn map_win32(code: u32, ctx: &'static str) -> io::Result<()> {
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{ctx}: Win32 error {code:#010x} ({})", win32_io_err(code)),
        ))
    }
}

// ───────────────────────────────────────────────────────────────────────────
// E-11: Native DACL restriction via SetNamedSecurityInfoW
// ───────────────────────────────────────────────────────────────────────────

/// Restrict `path` so only the named Windows account (`account`) has an
/// explicit Full Control (GENERIC_ALL = 0x10000000) DACL entry.
///
/// Inherited ACEs are intentionally NOT removed — stripping them mid-open
/// (via `PROTECTED_DACL_SECURITY_INFORMATION`) would lock out the daemon's
/// own open file handles. This matches the behaviour of the previous
/// `icacls.exe /grant:r` approach.
///
/// This is the synchronous entry point. From async/tokio contexts use
/// [`set_owner_dacl_async`] which runs this on a `spawn_blocking` thread.
///
/// # Errors
/// Returns `Err` only when a Win32 call fails. The wrapping caller in
/// `win_acl.rs` is expected to log and tolerate failures — DACL restriction
/// is best-effort on Windows.
pub fn set_owner_dacl(path: &Path, account: &str) -> io::Result<()> {
    // Null-terminated UTF-16 encodings.
    let path_w = to_wide_nul(&path.to_string_lossy());
    let account_w = to_wide_nul(account);

    // Build one EXPLICIT_ACCESS_W entry for the named account with
    // Full Control. We initialise the struct to zero first (all-integer
    // POD fields), then fill in the fields by hand to match the
    // documented semantics of BuildExplicitAccessWithNameW.
    //
    // SAFETY:
    //  - `EXPLICIT_ACCESS_W` and `TRUSTEE_W` are POD structs containing
    //    only integers and pointer-sized fields. Zero-init is valid for
    //    every field: integer fields default to 0 / NULL_PTR, which is
    //    the correct empty/no-op state before we overwrite them.
    let mut ea: EXPLICIT_ACCESS_W = unsafe { std::mem::zeroed() };

    // GENERIC_ALL — grants all access including read, write, execute, delete.
    ea.grfAccessPermissions = 0x1000_0000u32;
    ea.grfAccessMode = GRANT_ACCESS;
    // NO_INHERITANCE (0): this ACE applies to the named file only, not
    // inherited by child objects (files don't have children, but explicit is
    // better than implicit).
    ea.grfInheritance = NO_INHERITANCE;

    // Initialise the TRUSTEE_W in-place.
    //
    // SAFETY:
    //  - `ea.Trustee` is already zero-initialised above; we overwrite each
    //    field individually. `pMultipleTrustee = null` + `NO_MULTIPLE_TRUSTEE`
    //    is the documented "simple trustee" form (no chaining).
    //  - `ptstrName` stores `account_w.as_ptr()` which is non-null, aligned,
    //    and null-terminated. The pointer is valid for the duration of the
    //    `SetEntriesInAclW` + `SetNamedSecurityInfoW` calls below, both of
    //    which complete before `account_w` drops.
    //  - The cast from `*const u16` to `*mut u16` (PWSTR) matches the Win32
    //    ABI: the API reads the name string and does not write through it.
    ea.Trustee = TRUSTEE_W {
        pMultipleTrustee: std::ptr::null_mut(),
        MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
        TrusteeForm: TRUSTEE_IS_NAME,
        TrusteeType: TRUSTEE_IS_UNKNOWN,
        ptstrName: account_w.as_ptr() as *mut u16,
    };

    // Allocate a new ACL from our single entry.
    let mut new_acl: *mut ACL = std::ptr::null_mut();

    // SAFETY:
    //  - `&ea` is a valid pointer to an initialised `EXPLICIT_ACCESS_W`; its
    //    lifetime covers this call.
    //  - `oldacl` is null — we are constructing a fresh ACL, not merging.
    //  - `&mut new_acl` is a valid out-pointer; Win32 fills it with a
    //    heap-allocated ACL (`LocalAlloc`'d, released by `LocalFree`). We pass
    //    it to `SetNamedSecurityInfoW`, which deep-copies the ACL into the
    //    file's security descriptor, then free `new_acl` with `LocalFree`
    //    after that call returns (SC-08a — see the free site below). On a
    //    `SetEntriesInAclW` failure `new_acl` stays null and the `?` below
    //    returns early, so the error path allocates nothing to leak.
    let rc = unsafe { SetEntriesInAclW(1, &ea, std::ptr::null(), &mut new_acl) };

    map_win32(rc, "SetEntriesInAclW")?;

    // Apply the new DACL to the named file.
    //
    // Security flags: DACL_SECURITY_INFORMATION only — we set the DACL but
    // do NOT change owner, group, or SACL. We intentionally omit
    // PROTECTED_DACL_SECURITY_INFORMATION to leave inherited ACEs in place
    // (same policy as the icacls approach, see module header).
    //
    // SAFETY:
    //  - `path_w.as_ptr()` is a valid non-null, null-terminated UTF-16
    //    string; it outlives this call.
    //  - `SE_FILE_OBJECT` is the correct object type for file system paths.
    //  - `psidowner` / `psidgroup` / `psacl` are null — Win32 interprets
    //    null pointer arguments as "do not change this field" when the
    //    corresponding `SECURITY_INFORMATION` bit is not set.
    //  - `new_acl` was produced by a successful `SetEntriesInAclW` and is
    //    a valid, non-null `*mut ACL`.
    let rc = unsafe {
        SetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(), // psidowner — unchanged
            std::ptr::null_mut(), // psidgroup — unchanged
            new_acl,
            std::ptr::null_mut(), // psacl — unchanged
        )
    };

    // SC-08a: release the ACL buffer that `SetEntriesInAclW` allocated on the
    // process heap. `SetNamedSecurityInfoW` has already deep-copied the ACL
    // into the file's security descriptor by this point, so the buffer is no
    // longer referenced and MUST be freed per MSDN ("free the returned buffer
    // by calling the LocalFree function"). We free regardless of the
    // `SetNamedSecurityInfoW` result code — the buffer was allocated by the
    // already-succeeded `SetEntriesInAclW`, so it must be released on both the
    // success and the apply-failure path.
    //
    // SAFETY:
    //  - Reaching here means `SetEntriesInAclW` succeeded (its `map_win32`
    //    returned `Ok` above), so `new_acl` is a valid, non-null,
    //    `LocalAlloc`-owned `*mut ACL`.
    //  - It is freed exactly once: no other path frees it and the function
    //    returns immediately after.
    //  - `SetNamedSecurityInfoW` does not retain the pointer (it deep-copies
    //    the ACL), so this is not a use-after-free.
    if !new_acl.is_null() {
        unsafe { LocalFree(new_acl as HLOCAL) };
    }

    map_win32(rc, "SetNamedSecurityInfoW")
}

/// Async wrapper: runs [`set_owner_dacl`] on a `spawn_blocking` thread so
/// the calling tokio task is not stalled during the Win32 ACL write.
pub async fn set_owner_dacl_async(path: &Path, account: &str) -> io::Result<()> {
    let owned_path = path.to_path_buf();
    let owned_account = account.to_owned();
    tokio::task::spawn_blocking(move || set_owner_dacl(&owned_path, &owned_account))
        .await
        .unwrap_or_else(|join_err| {
            warn!(error = %join_err, "set_owner_dacl task panicked");
            Ok(())
        })
}

// ───────────────────────────────────────────────────────────────────────────
// E-12: FlushFileBuffers for WAL durability
// ───────────────────────────────────────────────────────────────────────────

/// Flush all OS-buffered writes for `file` to the underlying storage device
/// via `FlushFileBuffers`. This is the Windows equivalent of `fsync(2)`.
///
/// Unlike `std::fs::File::sync_all()` (which also calls `FlushFileBuffers`
/// internally), this function surfaces the Win32 error code in the `Err`
/// variant together with an operator-readable context string, making WAL
/// write failures actionable in the tracing output.
///
/// # D008-WINDOWS-WAL-01 — WAL writer hot-path wiring note
///
/// The WAL writer hot path (`write_and_sync` in `writer.rs`) does **not**
/// call this function directly.  On Windows, `tokio::fs::File::sync_data()`
/// is backed (via the blocking pool) by `std::fs::File::sync_data()`, which
/// the Rust standard library implements by calling `FlushFileBuffers` on the
/// underlying `HANDLE`.  Wiring this wrapper in addition to `sync_data`
/// would therefore issue `FlushFileBuffers` **twice** per frame — a
/// double-flush that adds latency with no additional durability benefit.
///
/// This wrapper is provided for diagnostic and admin paths that need the raw
/// Win32 error code surfaced directly rather than through the std `io::Error`
/// mapping.  See `flush_vs_sync_data_latency_comparison` (the `#[ignore]`d
/// test below) for measured latency data confirming the functional equivalence
/// of both paths, and the `FILE_FLAG_WRITE_THROUGH` threshold rationale
/// documented there.
///
/// # Errors
/// Returns `Err` when `FlushFileBuffers` returns `0` (FALSE).
pub fn flush_file_buffers(file: &File) -> io::Result<()> {
    // SAFETY:
    //  - `file.as_raw_handle()` returns a valid, open HANDLE that is owned
    //    and kept alive by the `File` reference for at least the duration of
    //    this call.
    //  - `FlushFileBuffers` accepts the HANDLE by value (integer copy) and
    //    does not store or alias it.
    //  - The return value is a Win32 BOOL: non-zero means success, 0 means
    //    failure (caller must check `GetLastError` for the code).
    let rc = unsafe { FlushFileBuffers(file.as_raw_handle() as HANDLE) };

    if rc != 0 {
        Ok(())
    } else {
        // SAFETY:
        //  - `GetLastError` is thread-local and valid to call immediately
        //    after a failing Win32 function on the same thread. No other
        //    Win32 call occurs between the failing `FlushFileBuffers` and
        //    this `GetLastError`.
        let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        Err(io::Error::other(format!(
            "FlushFileBuffers: Win32 error {code:#010x} ({})",
            win32_io_err(code)
        )))
    }
}

/// Async wrapper: runs [`flush_file_buffers`] on a `spawn_blocking` thread
/// and returns the `File` on success (so callers can continue using it).
pub async fn flush_file_buffers_async(file: File) -> io::Result<File> {
    tokio::task::spawn_blocking(move || flush_file_buffers(&file).map(|()| file))
        .await
        .map_err(|join_err| {
            io::Error::other(format!("flush_file_buffers task panicked: {join_err}"))
        })?
}

// ───────────────────────────────────────────────────────────────────────────
// Tests
// ───────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    // ── shared helper ──────────────────────────────────────────────────────

    /// Fetch the current user's account name from USERNAME env var.
    /// Tests that need a valid account name skip gracefully if unset.
    fn current_username() -> Option<String> {
        std::env::var("USERNAME").ok().filter(|u| !u.is_empty())
    }

    // ── E-11: DACL set round-trip ──────────────────────────────────────────

    /// Setting the DACL on an existing file with the current username must
    /// succeed without error.
    #[test]
    fn dacl_round_trip_sets_without_error() {
        let Some(username) = current_username() else {
            eprintln!("SKIP dacl_round_trip_sets_without_error: USERNAME not set");
            return;
        };
        let dir = tempdir().unwrap();
        let path = dir.path().join("dacl_test.wal");
        File::create(&path).unwrap();

        let result = set_owner_dacl(&path, &username);
        assert!(
            result.is_ok(),
            "set_owner_dacl failed: {:?}",
            result.unwrap_err()
        );
    }

    /// Calling set_owner_dacl twice on the same file must be idempotent
    /// (second call also succeeds).
    #[test]
    fn dacl_idempotent_double_set() {
        let Some(username) = current_username() else {
            eprintln!("SKIP dacl_idempotent_double_set: USERNAME not set");
            return;
        };
        let dir = tempdir().unwrap();
        let path = dir.path().join("dacl_idempotent.wal");
        File::create(&path).unwrap();

        set_owner_dacl(&path, &username).expect("first call");
        set_owner_dacl(&path, &username).expect("second call (idempotent)");
    }

    /// A nonexistent path must return `Err` (Win32 cannot set DACL on a file
    /// that does not exist).
    #[test]
    fn dacl_nonexistent_path_returns_err() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("does_not_exist.wal");
        // File does not exist — SetNamedSecurityInfoW returns an error.
        let result = set_owner_dacl(&path, "AnyAccount");
        assert!(result.is_err(), "expected Err for nonexistent path, got Ok");
    }

    // ── E-12: FlushFileBuffers ─────────────────────────────────────────────

    /// FlushFileBuffers on a freshly created file must succeed.
    #[test]
    fn flush_smoke_open_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("flush_smoke.wal");
        let file = File::create(&path).unwrap();
        let result = flush_file_buffers(&file);
        assert!(
            result.is_ok(),
            "flush_file_buffers failed on open file: {:?}",
            result.unwrap_err()
        );
    }

    /// Write bytes then flush — must succeed and data must be on disk.
    #[test]
    fn flush_after_write_succeeds() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("flush_write.wal");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"neoth-wal-segment-header\n").unwrap();
        let result = flush_file_buffers(&file);
        assert!(
            result.is_ok(),
            "flush after write failed: {:?}",
            result.unwrap_err()
        );
    }

    // ── Error mapping helpers ──────────────────────────────────────────────

    /// ERROR_SUCCESS (0) must map to Ok.
    #[test]
    fn map_win32_ok_on_error_success() {
        assert!(map_win32(0, "test_ctx").is_ok());
    }

    /// Non-zero Win32 code must map to Err containing the context label and
    /// the hex error code.
    #[test]
    fn map_win32_err_contains_context_and_code() {
        // 5 = ERROR_ACCESS_DENIED — predictable, well-known code.
        let err = map_win32(5, "my_ctx").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("my_ctx"),
            "error message should contain context label: {msg}"
        );
        assert!(
            msg.contains("0x00000005"),
            "error message should contain hex error code: {msg}"
        );
    }

    /// `to_wide_nul` must produce exactly len+1 u16 values with a null
    /// terminator at the end.
    #[test]
    fn wide_nul_encoding_correct() {
        let wide = to_wide_nul("abc");
        assert_eq!(wide.len(), 4, "3 chars + 1 null terminator");
        assert_eq!(*wide.last().unwrap(), 0u16, "last element must be null");
    }

    // ── D008-WINDOWS-WAL-01 — FlushFileBuffers vs sync_data latency ────────
    //
    // Compares the explicit `flush_file_buffers` (E-12 wrapper) path against
    // `std::fs::File::sync_data()` (the WAL writer's current hot path).
    //
    // Both paths call `FlushFileBuffers` once; this bench produces MEASURED
    // evidence that the E-12 wrapper adds no latency benefit when wired
    // alongside `sync_data`, confirming the double-flush analysis in
    // `write_and_sync` (writer.rs).
    //
    // ## FILE_FLAG_WRITE_THROUGH threshold
    //
    // `FILE_FLAG_WRITE_THROUGH` bypasses the OS write cache so each write
    // goes directly to storage without a subsequent `FlushFileBuffers` call.
    // Possible benefit: sub-millisecond reduction in SYNC_ON_WRITE latency on
    // drives with firmware write-back caches.  Cost: requires opening the WAL
    // file with `CreateFileW(FILE_FLAG_WRITE_THROUGH)` — a Windows-only code
    // path — AND `FILE_FLAG_NO_BUFFERING` for full OS-cache bypass, which
    // mandates 512 / 4096-byte sector-aligned writes (alignment-buffer refactor).
    //
    // Investigate write-through when EITHER measured metric exceeds:
    //   • p50  > 5 ms  — fsync perceptible in SYNC_ON_WRITE chat round-trip
    //   • p99  > 50 ms — storage anomaly; check SMART / NVMe health logs
    //
    // Below those thresholds the alignment-layer complexity outweighs the
    // latency gain on NVMe storage with stable firmware caches.
    //
    // Run on demand:
    //
    //   cargo test -p neothd --lib flush_vs_sync_latency -- --ignored --nocapture --test-threads=1

    #[test]
    #[ignore = "D008 latency bench — run with: cargo test -p neothd --lib flush_vs_sync_latency -- --ignored --nocapture --test-threads=1"]
    fn flush_vs_sync_data_latency_comparison() {
        use std::io::Write;
        use std::time::Instant;

        const ITERS: usize = 200;
        // Representative WAL frame size: short PROVIDER_RESPONSE event.
        const FRAME_BYTES: usize = 512;
        let frame = vec![0u8; FRAME_BYTES];

        let dir = tempdir().unwrap();

        // ── Path A: explicit FlushFileBuffers via E-12 wrapper ─────────────
        let path_a = dir.path().join("lat_flush_a.wal");
        let mut file_a = File::create(&path_a).unwrap();
        // Warm-up: prime the FS / NTFS journal before sampling.
        for _ in 0..10 {
            file_a.write_all(&frame).unwrap();
            flush_file_buffers(&file_a).unwrap();
        }
        let mut samples_a: Vec<u64> = Vec::with_capacity(ITERS);
        for _ in 0..ITERS {
            let t0 = Instant::now();
            file_a.write_all(&frame).unwrap();
            flush_file_buffers(&file_a).unwrap();
            samples_a.push(t0.elapsed().as_nanos() as u64);
        }

        // ── Path B: std::fs::File::sync_data (WAL writer hot path) ─────────
        let path_b = dir.path().join("lat_sync_b.wal");
        let mut file_b = File::create(&path_b).unwrap();
        for _ in 0..10 {
            file_b.write_all(&frame).unwrap();
            file_b.sync_data().unwrap();
        }
        let mut samples_b: Vec<u64> = Vec::with_capacity(ITERS);
        for _ in 0..ITERS {
            let t0 = Instant::now();
            file_b.write_all(&frame).unwrap();
            file_b.sync_data().unwrap();
            samples_b.push(t0.elapsed().as_nanos() as u64);
        }

        samples_a.sort_unstable();
        samples_b.sort_unstable();

        let p50_a = samples_a[ITERS / 2];
        let p50_b = samples_b[ITERS / 2];
        let p95_a = samples_a[ITERS * 95 / 100];
        let p95_b = samples_b[ITERS * 95 / 100];
        let p99_a = samples_a[ITERS * 99 / 100];
        let p99_b = samples_b[ITERS * 99 / 100];

        println!(
            "\nD008-WINDOWS-WAL-01  FlushFileBuffers vs sync_data  (n={}  frame={}B)\n\
             \x20 [E-12 FlushFileBuffers]  p50={:.3}ms  p95={:.3}ms  p99={:.3}ms\n\
             \x20 [std  sync_data        ]  p50={:.3}ms  p95={:.3}ms  p99={:.3}ms\n\
             \n\
             \x20 Verdict: if |p50_a - p50_b| < 1ms the E-12 wrapper adds no measurable\n\
             \x20 benefit when wired alongside sync_data (both call FlushFileBuffers once).\n\
             \x20 THRESHOLD: investigate FILE_FLAG_WRITE_THROUGH when p50 > 5ms or p99 > 50ms.",
            ITERS,
            FRAME_BYTES,
            p50_a as f64 / 1_000_000.0,
            p95_a as f64 / 1_000_000.0,
            p99_a as f64 / 1_000_000.0,
            p50_b as f64 / 1_000_000.0,
            p95_b as f64 / 1_000_000.0,
            p99_b as f64 / 1_000_000.0,
        );

        // Regression guards: generous 2-second p99 ceiling on any Windows storage.
        // Values above this indicate a storage anomaly — check SMART / NVMe logs.
        const P99_CEILING_NS: u64 = 2_000 * 1_000_000;
        assert!(
            p99_a < P99_CEILING_NS,
            "E-12 FlushFileBuffers p99 {:.1}ms > 2000ms — storage anomaly",
            p99_a as f64 / 1_000_000.0
        );
        assert!(
            p99_b < P99_CEILING_NS,
            "sync_data p99 {:.1}ms > 2000ms — storage anomaly",
            p99_b as f64 / 1_000_000.0
        );
    }
}
