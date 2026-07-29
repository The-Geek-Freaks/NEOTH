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
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;

use tracing::warn;

// ── E-11 imports ───────────────────────────────────────────────────────────
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS,
    GetLastError, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, GetSecurityInfo, NO_MULTIPLE_TRUSTEE,
    SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW, SetSecurityInfo, TRUSTEE_IS_NAME,
    TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
    CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
    GetLengthSid, GetSecurityDescriptorControl, GetTokenInformation, INHERITED_ACE,
    InitializeSecurityDescriptor, IsValidAcl, IsValidSid, NO_INHERITANCE, OBJECT_INHERIT_ACE,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED,
    SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

// ── E-12 import ────────────────────────────────────────────────────────────
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW, DELETE, FILE_ALL_ACCESS,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_RENAME_INFO, FILE_RENAME_INFO_0, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FileRenameInfoEx, FlushFileBuffers, GetFileInformationByHandle,
    OPEN_EXISTING, READ_CONTROL, SetFileInformationByHandle, WRITE_DAC,
};

// ───────────────────────────────────────────────────────────────────────────
// Internal helpers
// ───────────────────────────────────────────────────────────────────────────

/// Encode a Rust `&str` as a null-terminated UTF-16 `Vec<u16>` for Win32.
fn to_wide_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0u16)).collect()
}

/// Encode a Windows path losslessly as a null-terminated UTF-16 string.
fn path_to_wide_nul(path: &Path) -> io::Result<Vec<u16>> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows path contains an interior NUL",
        ));
    }
    wide.push(0);
    Ok(wide)
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
    set_owner_dacl_impl(path, account, false)
}

/// Replace `path`'s DACL with a protected, non-inherited Full Control ACE for
/// the exact TokenUser SID of the current process, then read the descriptor
/// back and verify the private contract against that same SID.
///
/// Unlike [`set_owner_dacl`], this is fail-closed and deliberately removes
/// inherited ACEs. It is used for private state before any secret bytes are
/// written, so a permissive parent-directory ACL can never leak those bytes.
pub fn set_private_current_user_dacl(path: &Path) -> io::Result<()> {
    let sid = current_process_token_sid()?;
    set_trustee_dacl(
        path,
        sid.as_ptr() as *mut u16,
        TRUSTEE_IS_SID,
        NO_INHERITANCE,
        true,
    )?;
    verify_private_dacl_for_sid(path, &sid, NO_INHERITANCE as u8)
}

/// Replace a directory DACL with one protected TokenUser Full Control ACE
/// inherited by both child files and child directories.
///
/// This is intentionally separate from [`set_private_current_user_dacl`]: a
/// private file must not carry inheritable ACE flags, while a private
/// directory must protect children during their own creation, before a caller
/// can apply a more specific descriptor to them.
pub fn set_private_current_user_directory_dacl(path: &Path) -> io::Result<()> {
    let sid = current_process_token_sid()?;
    let inheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
    set_trustee_dacl(
        path,
        sid.as_ptr() as *mut u16,
        TRUSTEE_IS_SID,
        inheritance,
        true,
    )?;
    verify_private_dacl_for_sid(path, &sid, inheritance as u8)
}

/// Replace the DACL on an already-open directory capability with one protected
/// TokenUser Full Control ACE inherited by both child files and directories.
///
/// Both the mutation and its read-back proof use the exact kernel object behind
/// `directory`, so a concurrent path rename or replacement cannot redirect
/// either operation. The handle must have `WRITE_DAC | READ_CONTROL` access.
pub fn set_private_current_user_directory_handle_dacl<H: AsRawHandle + ?Sized>(
    directory: &H,
) -> io::Result<()> {
    let handle = checked_raw_handle(directory)?;
    let sid = current_process_token_sid()?;
    set_private_current_user_directory_handle_dacl_for_sid(handle, &sid)
}

fn set_private_current_user_directory_handle_dacl_for_sid(
    handle: HANDLE,
    sid: &[u8],
) -> io::Result<()> {
    verify_handle_owner_for_sid(handle, sid)?;
    let inheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
    let acl = single_trustee_acl(sid.as_ptr() as *mut u16, TRUSTEE_IS_SID, inheritance)?;

    // SAFETY:
    // - `handle` is the live handle borrowed from `directory` and was checked
    //   against both null and INVALID_HANDLE_VALUE.
    // - `acl` is a valid LocalAlloc-owned ACL and remains live for this call.
    // - owner, group, and SACL pointers are null because their corresponding
    //   SECURITY_INFORMATION bits are not requested.
    // - the caller-provided handle must carry WRITE_DAC, which Win32 verifies.
    let rc = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            acl.0,
            std::ptr::null_mut(),
        )
    };
    map_win32(rc, "SetSecurityInfo")?;
    verify_private_directory_handle_for_sid(handle, sid)
}

/// Harden a path-resolved directory only when it is the exact object behind an
/// already-open capability directory.
///
/// `expected_directory` needs only `READ_CONTROL`, as provided by an ordinary
/// `cap_std::fs::Dir` on Windows. This function opens a short-lived
/// `READ_CONTROL | WRITE_DAC` security handle without following a final
/// reparse point, compares stable volume/file identity with the capability
/// handle, and mutates only that identity-matched handle. A stale or swapped
/// display path therefore fails before any DACL is changed.
pub fn set_private_current_user_directory_dacl_bound<H: AsRawHandle + ?Sized>(
    path: &Path,
    expected_directory: &H,
) -> io::Result<()> {
    let expected_handle = checked_raw_handle(expected_directory)?;
    let expected_identity = private_directory_identity(expected_handle)?;
    let path_w = path_to_wide_nul(path)?;

    // SAFETY:
    // - `path_w` is a live, null-terminated UTF-16 path.
    // - READ_CONTROL | WRITE_DAC are exactly the rights needed by the
    //   handle-bound read-back and DACL mutation.
    // - OPEN_EXISTING cannot create or truncate an object.
    // - BACKUP_SEMANTICS permits opening a directory, while OPEN_REPARSE_POINT
    //   exposes a final reparse point itself so it can be rejected below.
    // - omitting FILE_SHARE_DELETE pins the resolved namespace object against
    //   rename/delete for the lifetime of the security handle.
    let raw_security_handle = unsafe {
        CreateFileW(
            path_w.as_ptr(),
            READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if raw_security_handle == INVALID_HANDLE_VALUE {
        return Err(last_win32_error(
            "CreateFileW(bound directory security handle)",
        ));
    }
    let security_handle = OwnedHandle(raw_security_handle);
    let actual_identity = private_directory_identity(security_handle.0)?;
    if actual_identity != expected_identity {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "directory display path no longer identifies the bound capability",
        ));
    }

    let sid = current_process_token_sid()?;
    set_private_current_user_directory_handle_dacl_for_sid(security_handle.0, &sid)
}

fn set_owner_dacl_impl(path: &Path, account: &str, protected: bool) -> io::Result<()> {
    let account_w = to_wide_nul(account);
    set_trustee_dacl(
        path,
        account_w.as_ptr() as *mut u16,
        TRUSTEE_IS_NAME,
        NO_INHERITANCE,
        protected,
    )
}

fn set_trustee_dacl(
    path: &Path,
    trustee: *mut u16,
    trustee_form: i32,
    inheritance: u32,
    protected: bool,
) -> io::Result<()> {
    let path_w = path_to_wide_nul(path)?;
    let new_acl = single_trustee_acl(trustee, trustee_form, inheritance)?;

    // Apply the new DACL to the named file.
    //
    // Security flags: we set only the DACL. Private state additionally marks
    // the DACL protected, which prevents parent-directory ACE inheritance.
    //
    // SAFETY:
    //  - `path_w.as_ptr()` is a valid non-null, null-terminated UTF-16
    //    string; it outlives this call.
    //  - `SE_FILE_OBJECT` is the correct object type for file system paths.
    //  - `psidowner` / `psidgroup` / `psacl` are null — Win32 interprets
    //    null pointer arguments as "do not change this field" when the
    //    corresponding `SECURITY_INFORMATION` bit is not set.
    //  - `new_acl` owns the valid ACL returned by `SetEntriesInAclW` and
    //    remains live until after Win32 has copied it into the descriptor.
    let rc = unsafe {
        SetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION
                | if protected {
                    PROTECTED_DACL_SECURITY_INFORMATION
                } else {
                    0
                },
            std::ptr::null_mut(), // psidowner — unchanged
            std::ptr::null_mut(), // psidgroup — unchanged
            new_acl.0,
            std::ptr::null_mut(), // psacl — unchanged
        )
    };

    map_win32(rc, "SetNamedSecurityInfoW")
}

struct OwnedLocalAcl(*mut ACL);

impl Drop for OwnedLocalAcl {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `SetEntriesInAclW` returned this LocalAlloc-owned ACL.
            // The guard is its sole owner and releases it exactly once.
            unsafe { LocalFree(self.0 as HLOCAL) };
        }
    }
}

fn single_trustee_acl(
    trustee: *mut u16,
    trustee_form: i32,
    inheritance: u32,
) -> io::Result<OwnedLocalAcl> {
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
    ea.grfInheritance = inheritance;

    // Initialise the TRUSTEE_W in-place.
    //
    // SAFETY:
    //  - `ea.Trustee` is already zero-initialised above; we overwrite each
    //    field individually. `pMultipleTrustee = null` + `NO_MULTIPLE_TRUSTEE`
    //    is the documented "simple trustee" form (no chaining).
    //  - `trustee` points either to a live null-terminated account-name buffer
    //    (`TRUSTEE_IS_NAME`) or a validated process-token SID
    //    (`TRUSTEE_IS_SID`). The caller keeps it live through both Win32 calls.
    //    TRUSTEE_W uses the PWSTR-shaped union field for either representation.
    ea.Trustee = TRUSTEE_W {
        pMultipleTrustee: std::ptr::null_mut(),
        MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
        TrusteeForm: trustee_form,
        TrusteeType: TRUSTEE_IS_UNKNOWN,
        ptstrName: trustee,
    };

    // Allocate a new ACL from our single entry.
    let mut new_acl: *mut ACL = std::ptr::null_mut();

    // SAFETY:
    //  - `&ea` is a valid pointer to an initialised `EXPLICIT_ACCESS_W`; its
    //    lifetime covers this call.
    //  - `oldacl` is null — we are constructing a fresh ACL, not merging.
    //  - `&mut new_acl` is a valid out-pointer; Win32 fills it with a
    //    heap-allocated ACL (`LocalAlloc`'d, released by `OwnedLocalAcl` on
    //    both success and defensive non-null failure paths).
    let rc = unsafe { SetEntriesInAclW(1, &ea, std::ptr::null(), &mut new_acl) };

    // Guard even a defensive non-null failure output before propagating the
    // Win32 status, so every LocalAlloc-owned return is released exactly once.
    let new_acl = OwnedLocalAcl(new_acl);
    map_win32(rc, "SetEntriesInAclW")?;
    if new_acl.0.is_null() {
        return Err(io::Error::other(
            "SetEntriesInAclW succeeded with a null ACL",
        ));
    }
    Ok(new_acl)
}

/// Atomically create a new private file for the current process TokenUser.
///
/// The protected, single-SID DACL is supplied to `CreateFileW` through
/// `SECURITY_ATTRIBUTES`, so the file never exists with an inherited or token
/// default DACL. The returned [`File`] owns the exact handle created by that
/// call. Read, write, and delete sharing are all disabled for its lifetime.
///
/// The descriptor is verified through `GetSecurityInfo` on that handle before
/// it is returned, avoiding path replacement races in the security check.
pub fn create_private_file_new(path: &Path) -> io::Result<File> {
    create_private_file_new_with_share(path, 0)
}

/// Create a private file that same-token child processes can reopen by path.
///
/// The file is protected from its first observable instant by the same exact
/// TokenUser DACL as [`create_private_file_new`]. Sharing is required for
/// sandboxed media tools such as ffmpeg: the parent retains the cleanup handle
/// while the authorized child opens the random path. The DACL, not an
/// inherited temp-directory ACL, remains the access-control boundary.
pub fn create_private_shared_file_new(path: &Path) -> io::Result<File> {
    create_private_file_new_with_share(path, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
}

fn create_private_file_new_with_share(path: &Path, share_mode: u32) -> io::Result<File> {
    let path_w = path_to_wide_nul(path)?;
    let sid = current_process_token_sid()?;
    let acl = single_trustee_acl(sid.as_ptr() as *mut u16, TRUSTEE_IS_SID, NO_INHERITANCE)?;

    // SAFETY: SECURITY_DESCRIPTOR is a Win32 POD structure. Zero is the
    // documented pre-initialization state and the API below initializes it.
    let mut descriptor: SECURITY_DESCRIPTOR = unsafe { std::mem::zeroed() };
    let descriptor_ptr = std::ptr::addr_of_mut!(descriptor) as *mut std::ffi::c_void;
    // SECURITY_DESCRIPTOR_REVISION is defined by Win32 as 1. Keeping the
    // value local avoids enabling the large SystemServices feature solely for
    // this constant.
    const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

    // SAFETY:
    // - `descriptor_ptr` addresses writable storage of the exact descriptor
    //   layout for the whole call.
    // - the revision is the documented Win32 revision.
    if unsafe { InitializeSecurityDescriptor(descriptor_ptr, SECURITY_DESCRIPTOR_REVISION) } == 0 {
        return Err(last_win32_error("InitializeSecurityDescriptor"));
    }
    // SAFETY:
    // - `descriptor_ptr` is initialized above.
    // - `acl.0` is a valid LocalAlloc-owned ACL and stays live through
    //   `CreateFileW`; Win32 reads but does not retain this process buffer.
    // - TRUE/FALSE select a present, non-defaulted DACL.
    if unsafe { SetSecurityDescriptorDacl(descriptor_ptr, 1, acl.0, 0) } == 0 {
        return Err(last_win32_error("SetSecurityDescriptorDacl"));
    }
    // SAFETY: the absolute descriptor is initialized and writable. Setting
    // SE_DACL_PROTECTED prevents CreateFileW from merging parent ACEs into the
    // supplied exact TokenUser DACL.
    if unsafe { SetSecurityDescriptorControl(descriptor_ptr, SE_DACL_PROTECTED, SE_DACL_PROTECTED) }
        == 0
    {
        return Err(last_win32_error("SetSecurityDescriptorControl"));
    }

    let security_attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor_ptr,
        bInheritHandle: 0,
    };

    // SAFETY:
    // - `path_w` is a lossless, live, null-terminated UTF-16 path.
    // - `security_attributes`, its descriptor, ACL, and SID-derived ACL bytes
    //   all remain live until the call returns.
    // - CREATE_NEW prevents replacement/truncation of an existing object.
    // - `share_mode` is either zero for state commits or the explicit
    //   read/write/delete set for private child-process media staging.
    // - a null template handle is documented for ordinary file creation.
    let raw_handle = unsafe {
        CreateFileW(
            path_w.as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE,
            share_mode,
            &security_attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if raw_handle == INVALID_HANDLE_VALUE {
        // SAFETY: no Win32 call intervened after the failed CreateFileW.
        let code = unsafe { GetLastError() };
        return Err(io::Error::new(
            win32_io_err(code).kind(),
            format!(
                "CreateFileW(CREATE_NEW): Win32 error {code:#010x} ({})",
                win32_io_err(code)
            ),
        ));
    }
    let owned_handle = OwnedHandle(raw_handle);

    if let Err(verification_error) = verify_private_handle_for_sid(raw_handle, &sid) {
        // Close first because the zero-share handle intentionally prevents
        // deletion even by this process. The file is already private, but a
        // failed proof must not leave it as a caller-visible committed object.
        drop(owned_handle);
        if let Err(cleanup_error) = std::fs::remove_file(path) {
            return Err(io::Error::new(
                verification_error.kind(),
                format!(
                    "{verification_error}; cleanup of unverified private file failed: {cleanup_error}"
                ),
            ));
        }
        return Err(verification_error);
    }

    Ok(owned_handle.into_file())
}

/// Atomically create a private directory for the current process TokenUser.
///
/// The protected inheritable DACL is supplied to `CreateDirectoryW`, so there
/// is no public-directory interval before media files are staged inside it.
pub fn create_private_directory_new(path: &Path) -> io::Result<()> {
    let path_w = path_to_wide_nul(path)?;
    let sid = current_process_token_sid()?;
    let inheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
    let acl = single_trustee_acl(sid.as_ptr() as *mut u16, TRUSTEE_IS_SID, inheritance)?;

    // SAFETY: SECURITY_DESCRIPTOR is a Win32 POD structure initialized by the
    // API immediately below before it is exposed through SECURITY_ATTRIBUTES.
    let mut descriptor: SECURITY_DESCRIPTOR = unsafe { std::mem::zeroed() };
    let descriptor_ptr = std::ptr::addr_of_mut!(descriptor) as *mut std::ffi::c_void;
    const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
    // SAFETY: `descriptor_ptr` addresses live, correctly sized writable
    // storage and the revision is the documented Win32 value.
    if unsafe { InitializeSecurityDescriptor(descriptor_ptr, SECURITY_DESCRIPTOR_REVISION) } == 0 {
        return Err(last_win32_error("InitializeSecurityDescriptor"));
    }
    // SAFETY: the descriptor and LocalAlloc-owned ACL remain live through
    // CreateDirectoryW; Win32 copies rather than retains them.
    if unsafe { SetSecurityDescriptorDacl(descriptor_ptr, 1, acl.0, 0) } == 0 {
        return Err(last_win32_error("SetSecurityDescriptorDacl"));
    }
    // SAFETY: the initialized absolute descriptor is writable for this call.
    if unsafe { SetSecurityDescriptorControl(descriptor_ptr, SE_DACL_PROTECTED, SE_DACL_PROTECTED) }
        == 0
    {
        return Err(last_win32_error("SetSecurityDescriptorControl"));
    }

    let security_attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor_ptr,
        bInheritHandle: 0,
    };
    // SAFETY: `path_w` is a live null-terminated UTF-16 path and every pointer
    // reachable from `security_attributes` stays live for the call.
    if unsafe { CreateDirectoryW(path_w.as_ptr(), &security_attributes) } == 0 {
        return Err(last_win32_error("CreateDirectoryW"));
    }

    if let Err(verification_error) = verify_private_dacl_for_sid(path, &sid, inheritance as u8) {
        if let Err(cleanup_error) = std::fs::remove_dir(path) {
            return Err(io::Error::new(
                verification_error.kind(),
                format!(
                    "{verification_error}; cleanup of unverified private directory failed: \
                     {cleanup_error}"
                ),
            ));
        }
        return Err(verification_error);
    }
    Ok(())
}

/// Atomically replace `target` with the private file behind `file` without
/// closing or reopening its handle.
///
/// `file` must originate from [`create_private_file_new`]; this function
/// verifies that contract handle-bound, flushes its contents, and publishes it
/// with `SetFileInformationByHandle(FileRenameInfoEx)`. There is deliberately
/// no path-based fallback: closing before `MoveFileExW` would reopen a
/// temp-path substitution window.
///
/// A relative `target` is resolved to one absolute current-directory snapshot
/// before the kernel call. Source and target must be on the same volume, as
/// required for an atomic filesystem rename.
pub fn replace_private_file_handle(file: &File, target: &Path) -> io::Result<()> {
    rename_private_file_handle(file, target, true)
}

/// Atomically publish the private file behind `file` only when `target` is
/// absent. A raced existing target returns `AlreadyExists`; no path fallback is
/// used because the still-open handle is the security boundary.
pub fn create_private_file_handle(file: &File, target: &Path) -> io::Result<()> {
    rename_private_file_handle(file, target, false)
}

fn rename_private_file_handle(
    file: &File,
    target: &Path,
    replace_existing: bool,
) -> io::Result<()> {
    verify_private_file_handle(file)?;
    flush_file_buffers(file)?;

    let absolute_target = std::path::absolute(target)?;
    let target_w = path_to_wide_nul(&absolute_target)?;
    let file_name_units = target_w
        .len()
        .checked_sub(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty target path"))?;
    let file_name_bytes = file_name_units
        .checked_mul(std::mem::size_of::<u16>())
        .and_then(|length| u32::try_from(length).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "target path is too long"))?;
    let file_name_offset = u32::try_from(std::mem::offset_of!(FILE_RENAME_INFO, FileName))
        .expect("FILE_RENAME_INFO offset fits in u32");
    // Include storage for the trailing NUL even though FileNameLength excludes
    // it. This matches the Win32 variable-length structure contract.
    let buffer_size = file_name_offset
        .checked_add(file_name_bytes)
        .and_then(|length| length.checked_add(std::mem::size_of::<u16>() as u32))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "target path is too long"))?;
    let machine_words = (buffer_size as usize).div_ceil(std::mem::size_of::<usize>());
    // usize storage guarantees at least FILE_RENAME_INFO pointer alignment.
    let mut storage = vec![0usize; machine_words];
    let rename_info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();

    // FILE_RENAME_FLAG_* live under a windows-sys feature this crate does not
    // otherwise need. These values are stable Win32 ABI constants.
    const FILE_RENAME_FLAG_REPLACE_IF_EXISTS: u32 = 0x1;
    const FILE_RENAME_FLAG_POSIX_SEMANTICS: u32 = 0x2;
    let flags = FILE_RENAME_FLAG_POSIX_SEMANTICS
        | if replace_existing {
            FILE_RENAME_FLAG_REPLACE_IF_EXISTS
        } else {
            0
        };

    // SAFETY:
    // - `storage` is zeroed, aligned for FILE_RENAME_INFO, and sized through
    //   the complete variable-length FileName including its trailing NUL.
    // - every fixed field is initialized before the API reads it.
    // - the copy length exactly equals the allocated UTF-16 filename region.
    unsafe {
        std::ptr::addr_of_mut!((*rename_info).Anonymous).write(FILE_RENAME_INFO_0 { Flags: flags });
        std::ptr::addr_of_mut!((*rename_info).RootDirectory).write(std::ptr::null_mut());
        std::ptr::addr_of_mut!((*rename_info).FileNameLength).write(file_name_bytes);
        target_w.as_ptr().copy_to_nonoverlapping(
            std::ptr::addr_of_mut!((*rename_info).FileName).cast::<u16>(),
            target_w.len(),
        );
    }

    // SAFETY:
    // - `file` keeps the successful CreateFileW handle alive and that handle
    //   includes DELETE access.
    // - `rename_info` points to a fully initialized buffer of `buffer_size`
    //   bytes and the API neither retains nor frees it.
    // - FileRenameInfoEx with REPLACE_IF_EXISTS is the atomic commit point;
    //   POSIX_SEMANTICS permits replacement without a close/reopen fallback.
    let rc = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle() as HANDLE,
            FileRenameInfoEx,
            rename_info.cast::<std::ffi::c_void>(),
            buffer_size,
        )
    };
    if rc == 0 {
        // SAFETY: no Win32 call intervened after the failed rename.
        let code = unsafe { GetLastError() };
        let kind =
            if !replace_existing && (code == ERROR_ALREADY_EXISTS || code == ERROR_FILE_EXISTS) {
                io::ErrorKind::AlreadyExists
            } else {
                io::ErrorKind::PermissionDenied
            };
        return Err(io::Error::new(
            kind,
            format!(
                "SetFileInformationByHandle(FileRenameInfoEx): Win32 error {code:#010x} ({})",
                win32_io_err(code)
            ),
        ));
    }

    // Rename is the commit point. All fallible security and durability checks
    // happen before it so a successful namespace commit is never reported as
    // failure by a later proof step.
    Ok(())
}

/// Verify that `path` has a protected DACL containing exactly one explicit
/// Full Control allow ACE. This detects both inherited access and any extra
/// principal that could read operator-private state.
pub fn verify_private_dacl(path: &Path) -> io::Result<()> {
    let expected_sid = current_process_token_sid()?;
    verify_private_dacl_for_sid(path, &expected_sid, NO_INHERITANCE as u8)
}

/// Verify a private file descriptor through its already-open kernel handle.
///
/// This binds the proof to the object used by the caller rather than to a
/// path that could resolve to a different object between operations.
pub fn verify_private_file_handle(file: &File) -> io::Result<()> {
    let expected_sid = current_process_token_sid()?;
    verify_private_handle_for_sid(file.as_raw_handle() as HANDLE, &expected_sid)
}

/// Verify owner identity and the protected, inheritable TokenUser DACL through
/// an already-open directory capability.
///
/// The proof is bound to the same kernel object the caller will subsequently
/// use, rather than resolving its display path again.
pub fn verify_private_directory_handle_dacl<H: AsRawHandle + ?Sized>(
    directory: &H,
) -> io::Result<()> {
    let expected_sid = current_process_token_sid()?;
    verify_private_directory_handle_for_sid(checked_raw_handle(directory)?, &expected_sid)
}

/// Verify the protected, inheritable TokenUser DACL expected on a private
/// directory.
pub fn verify_private_directory_dacl(path: &Path) -> io::Result<()> {
    let expected_sid = current_process_token_sid()?;
    verify_private_dacl_for_sid(
        path,
        &expected_sid,
        (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
    )
}

struct OwnedLocalDescriptor(*mut std::ffi::c_void);

impl Drop for OwnedLocalDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the Win32 security-info APIs returned this
            // LocalAlloc-owned descriptor. The guard owns it exactly once.
            unsafe { LocalFree(self.0 as HLOCAL) };
        }
    }
}

fn verify_private_dacl_for_sid(
    path: &Path,
    expected_sid: &[u8],
    expected_ace_flags: u8,
) -> io::Result<()> {
    let path_w = path_to_wide_nul(path)?;
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor: *mut std::ffi::c_void = std::ptr::null_mut();

    // SAFETY:
    // - `path_w` is a live, null-terminated UTF-16 path.
    // - all unused SID/SACL out-pointers are null.
    // - `dacl` and `descriptor` are valid out-pointers. On success the latter
    //   is LocalAlloc-owned and released below after every validation branch.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    let descriptor = OwnedLocalDescriptor(descriptor);
    map_win32(rc, "GetNamedSecurityInfoW")?;
    if descriptor.0.is_null() {
        return Err(io::Error::other(
            "GetNamedSecurityInfoW returned a null security descriptor",
        ));
    }
    verify_private_descriptor(descriptor.0, dacl, expected_sid, expected_ace_flags)
}

fn verify_private_handle_for_sid(handle: HANDLE, expected_sid: &[u8]) -> io::Result<()> {
    verify_private_handle_security_for_sid(handle, expected_sid, NO_INHERITANCE as u8, false)
}

fn verify_private_directory_handle_for_sid(handle: HANDLE, expected_sid: &[u8]) -> io::Result<()> {
    verify_private_handle_security_for_sid(
        handle,
        expected_sid,
        (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
        true,
    )
}

fn checked_raw_handle<H: AsRawHandle + ?Sized>(object: &H) -> io::Result<HANDLE> {
    let handle = object.as_raw_handle() as HANDLE;
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cannot use a null or invalid file-system handle",
        ));
    }
    Ok(handle)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PrivateDirectoryIdentity {
    volume_serial_number: u32,
    file_index: u64,
}

fn private_directory_identity(handle: HANDLE) -> io::Result<PrivateDirectoryIdentity> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cannot identify a null or invalid directory handle",
        ));
    }
    let mut information = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    // SAFETY:
    // - `handle` is a live file-system handle validated above.
    // - `information` is correctly sized, aligned writable storage and is
    //   assumed initialized only after Win32 reports success.
    if unsafe { GetFileInformationByHandle(handle, information.as_mut_ptr()) } == 0 {
        return Err(last_win32_error("GetFileInformationByHandle"));
    }
    // SAFETY: the successful Win32 call initialized the complete structure.
    let information = unsafe { information.assume_init() };
    if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bound security object is not a directory",
        ));
    }
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "bound security directory must not be a reparse point",
        ));
    }
    let file_index =
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
    if file_index == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "file system did not provide a stable directory file identifier",
        ));
    }
    Ok(PrivateDirectoryIdentity {
        volume_serial_number: information.dwVolumeSerialNumber,
        file_index,
    })
}

fn verify_handle_owner_for_sid(handle: HANDLE, expected_sid: &[u8]) -> io::Result<()> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cannot verify owner on a null or invalid file-system handle",
        ));
    }
    let mut owner: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut descriptor: *mut std::ffi::c_void = std::ptr::null_mut();
    // SAFETY:
    // - `handle` is a live file-system handle with READ_CONTROL access.
    // - `owner` and `descriptor` are valid out-pointers; unused group, DACL,
    //   and SACL out-pointers are null.
    // - any successful descriptor is LocalAlloc-owned and guarded immediately.
    let rc = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    let descriptor = OwnedLocalDescriptor(descriptor);
    map_win32(rc, "GetSecurityInfo(owner)")?;
    if descriptor.0.is_null() {
        return Err(io::Error::other(
            "GetSecurityInfo(owner) returned a null security descriptor",
        ));
    }
    verify_owner_sid(owner, expected_sid)
}

fn verify_private_handle_security_for_sid(
    handle: HANDLE,
    expected_sid: &[u8],
    expected_ace_flags: u8,
    verify_owner: bool,
) -> io::Result<()> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cannot verify a null or invalid file-system handle",
        ));
    }
    let mut owner: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor: *mut std::ffi::c_void = std::ptr::null_mut();

    // SAFETY:
    // - `handle` is an open file handle with READ_CONTROL access.
    // - the owner out-pointer is supplied iff OWNER_SECURITY_INFORMATION was
    //   requested; group and SACL out-pointers are always null.
    // - `dacl` and `descriptor` are valid out-pointers. Any returned descriptor
    //   is LocalAlloc-owned and immediately guarded below.
    let rc = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION
                | if verify_owner {
                    OWNER_SECURITY_INFORMATION
                } else {
                    0
                },
            if verify_owner {
                &mut owner
            } else {
                std::ptr::null_mut()
            },
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    let descriptor = OwnedLocalDescriptor(descriptor);
    map_win32(rc, "GetSecurityInfo")?;
    if descriptor.0.is_null() {
        return Err(io::Error::other(
            "GetSecurityInfo returned a null security descriptor",
        ));
    }
    if verify_owner {
        verify_owner_sid(owner, expected_sid)?;
    }
    verify_private_descriptor(descriptor.0, dacl, expected_sid, expected_ace_flags)
}

fn verify_owner_sid(owner: *mut std::ffi::c_void, expected_sid: &[u8]) -> io::Result<()> {
    if owner.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private directory has no owner SID",
        ));
    }
    // SAFETY: `owner` points into the live descriptor returned by
    // GetSecurityInfo and remains valid until its guard is dropped.
    if unsafe { IsValidSid(owner) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "private directory contains an invalid owner SID",
        ));
    }
    // SAFETY: both SIDs are valid and EqualSid only reads them.
    if unsafe { EqualSid(owner, expected_sid.as_ptr() as *mut std::ffi::c_void) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private directory is not owned by the current user",
        ));
    }
    Ok(())
}

const SID_HEADER_LEN: usize = 8;

fn checked_access_allowed_sid_len(ace_size: usize, sub_authority_count: u8) -> io::Result<usize> {
    let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    let sid_len = usize::from(sub_authority_count)
        .checked_mul(4)
        .and_then(|sub_authorities_len| SID_HEADER_LEN.checked_add(sub_authorities_len))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ACE SID length overflow"))?;
    let sid_capacity = ace_size.checked_sub(sid_offset).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "allow ACE is shorter than its SID offset",
        )
    })?;
    if sid_capacity < sid_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "allow ACE contains a truncated SID",
        ));
    }
    Ok(sid_len)
}

fn verify_private_descriptor(
    descriptor: *mut std::ffi::c_void,
    dacl: *mut ACL,
    expected_sid: &[u8],
    expected_ace_flags: u8,
) -> io::Result<()> {
    if descriptor.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cannot verify a null security descriptor",
        ));
    }

    (|| {
        if dacl.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private object has a null DACL (access is unrestricted)",
            ));
        }
        // SAFETY: `dacl` belongs to the live security descriptor. Validating
        // the complete ACL before walking it ensures GetAce can only expose
        // structurally bounded ACE records.
        if unsafe { IsValidAcl(dacl) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "private object contains an invalid DACL",
            ));
        }

        let mut control = 0u16;
        let mut revision = 0u32;
        // SAFETY: `descriptor` is the valid descriptor returned above and both
        // scalar out-pointers are initialized storage for the Win32 call.
        if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
            return Err(last_win32_error("GetSecurityDescriptorControl"));
        }
        if control & SE_DACL_PROTECTED == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private object DACL is not protected from inherited ACEs",
            ));
        }

        // SAFETY: ACL_SIZE_INFORMATION is POD and zero is a valid initial
        // state before GetAclInformation fills every field.
        let mut info: ACL_SIZE_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: `dacl` belongs to the live descriptor, `info` is writable and
        // the supplied length exactly matches the destination type.
        if unsafe {
            GetAclInformation(
                dacl,
                &mut info as *mut ACL_SIZE_INFORMATION as *mut std::ffi::c_void,
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        } == 0
        {
            return Err(last_win32_error("GetAclInformation"));
        }
        if info.AceCount == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private object DACL has no ACEs",
            ));
        }
        if expected_ace_flags == NO_INHERITANCE as u8 && info.AceCount != 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "private file DACL has {} ACEs; expected exactly one",
                    info.AceCount
                ),
            ));
        }

        const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
        const GENERIC_ALL: u32 = 0x1000_0000;
        const INHERIT_ONLY_ACE_FLAG: u8 = 0x08;
        let allowed_ace_flags = if expected_ace_flags == NO_INHERITANCE as u8 {
            expected_ace_flags
        } else {
            expected_ace_flags | INHERIT_ONLY_ACE_FLAG
        };

        let mut combined_flags = 0u8;
        for index in 0..info.AceCount {
            let mut ace_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
            // SAFETY: `dacl` is valid and `index` is bounded by AceCount;
            // `ace_ptr` is a valid out-pointer.
            if unsafe { GetAce(dacl, index, &mut ace_ptr) } == 0 {
                return Err(last_win32_error("GetAce"));
            }
            let ace_ptr = std::ptr::NonNull::new(ace_ptr.cast::<u8>())
                .ok_or_else(|| io::Error::other("GetAce returned a null ACE"))?;
            // SAFETY: IsValidAcl accepted the complete ACL and GetAce
            // succeeded for an in-range index. Copy only the common header
            // first; do not construct a reference to a larger ACE layout.
            let header = unsafe { std::ptr::read_unaligned(ace_ptr.as_ptr().cast::<ACE_HEADER>()) };
            if header.AceType != ACCESS_ALLOWED_ACE_TYPE {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("private object ACE {index} is not an allow ACE"),
                ));
            }
            let ace_size = usize::from(header.AceSize);
            let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
            if ace_size < sid_offset + SID_HEADER_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("private object ACE {index} is too short for a SID"),
                ));
            }
            // SAFETY: the validated AceSize is now large enough for the fixed
            // ACCESS_ALLOWED_ACE prefix. Copying avoids a reference whose
            // lifetime could accidentally outlive the descriptor buffer.
            let ace =
                unsafe { std::ptr::read_unaligned(ace_ptr.as_ptr().cast::<ACCESS_ALLOWED_ACE>()) };
            if ace.Header.AceFlags as u32 & INHERITED_ACE != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("private object ACE {index} is inherited"),
                ));
            }
            if ace.Header.AceFlags & !allowed_ace_flags != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "private object ACE {index} has flags {:#04x}; expected subset of {expected_ace_flags:#04x}",
                        ace.Header.AceFlags
                    ),
                ));
            }
            combined_flags |= ace.Header.AceFlags & expected_ace_flags;

            let has_generic_all = ace.Mask & GENERIC_ALL == GENERIC_ALL;
            // Windows may map GENERIC_ALL into the object-specific access mask
            // when the DACL is stored. Both encodings represent full file control.
            let has_file_all_access = ace.Mask & FILE_ALL_ACCESS == FILE_ALL_ACCESS;
            if !has_generic_all && !has_file_all_access {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "private object ACE {index} does not grant Full Control (mask {:#010x})",
                        ace.Mask
                    ),
                ));
            }
            // SAFETY: AceSize was checked to contain the complete fixed SID
            // header, so reading its SubAuthorityCount byte is in bounds.
            let ace_sid = unsafe { ace_ptr.as_ptr().add(sid_offset) };
            let sub_authority_count = unsafe { ace_sid.add(1).read() };
            let sid_len =
                checked_access_allowed_sid_len(ace_size, sub_authority_count).map_err(|error| {
                    io::Error::new(error.kind(), format!("private object ACE {index}: {error}"))
                })?;
            let ace_sid = ace_sid.cast::<std::ffi::c_void>();
            // SAFETY: the variable-length SID was bounded against AceSize and
            // the descriptor remains live for the whole verification call.
            if unsafe { IsValidSid(ace_sid) } == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("private object ACE {index} contains an invalid SID"),
                ));
            }
            // SAFETY: IsValidSid succeeded, so GetLengthSid may inspect it.
            if unsafe { GetLengthSid(ace_sid) } as usize != sid_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("private object ACE {index} has an inconsistent SID length"),
                ));
            }
            // SAFETY: both SIDs are valid and EqualSid only reads them.
            if unsafe { EqualSid(ace_sid, expected_sid.as_ptr() as *mut std::ffi::c_void) } == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("private object ACE {index} does not belong to the current user"),
                ));
            }
        }
        if combined_flags != expected_ace_flags {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "private object DACL combined flags {combined_flags:#04x}; expected {expected_ace_flags:#04x}"
                ),
            ));
        }
        Ok(())
    })()
}

fn last_win32_error(context: &'static str) -> io::Error {
    // SAFETY: GetLastError has no arguments and reads the calling thread's
    // last-error slot immediately after the failed Win32 call.
    let code = unsafe { GetLastError() };
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "{context}: Win32 error {code:#010x} ({})",
            win32_io_err(code)
        ),
    )
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn into_file(self) -> File {
        let owned = std::mem::ManuallyDrop::new(self);
        // SAFETY: `owned.0` is a successful CreateFileW handle, is not closed
        // by ManuallyDrop, and ownership moves exactly once into `File`.
        unsafe { File::from_raw_handle(owned.0) }
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: this wrapper owns one successful Win32 handle and closes
            // it exactly once when the guard leaves scope.
            unsafe { CloseHandle(self.0) };
        }
    }
}

fn current_process_token_sid() -> io::Result<Vec<u8>> {
    let mut raw_token: HANDLE = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess returns the caller's pseudo-handle and
    // `raw_token` is a valid out-pointer for a TOKEN_QUERY handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) } == 0 {
        return Err(last_win32_error("OpenProcessToken"));
    }
    let token = OwnedHandle(raw_token);

    let mut required = 0u32;
    // SAFETY: this is the documented sizing call; a null output buffer with
    // length zero makes Win32 return the required TokenUser byte count.
    let first =
        unsafe { GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut required) };
    let first_error = if first == 0 {
        // SAFETY: no Win32 call intervened after GetTokenInformation.
        unsafe { GetLastError() }
    } else {
        ERROR_SUCCESS
    };
    if first != 0 || first_error != ERROR_INSUFFICIENT_BUFFER {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "GetTokenInformation(size): Win32 error {first_error:#010x} ({})",
                win32_io_err(first_error)
            ),
        ));
    }
    if required < std::mem::size_of::<TOKEN_USER>() as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "GetTokenInformation returned an undersized TokenUser buffer",
        ));
    }

    let mut buffer = vec![0u8; required as usize];
    // SAFETY: `buffer` is writable for exactly `required` bytes and the return
    // length out-pointer is valid. TokenUser is the requested layout.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
            required,
            &mut required,
        )
    } == 0
    {
        return Err(last_win32_error("GetTokenInformation(TokenUser)"));
    }
    // SAFETY: Win32 initialized the leading TOKEN_USER structure. `read_unaligned`
    // avoids assuming Vec<u8> has TOKEN_USER alignment; its SID pointer targets
    // storage inside `buffer`, which remains live until after the copy below.
    let token_user = unsafe { std::ptr::read_unaligned(buffer.as_ptr() as *const TOKEN_USER) };
    let sid = token_user.User.Sid;
    // SAFETY: `sid` is the TokenUser SID returned by GetTokenInformation.
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "current process token contains an invalid user SID",
        ));
    }
    // SAFETY: IsValidSid succeeded, so GetLengthSid can read its header.
    let sid_len = unsafe { GetLengthSid(sid) } as usize;
    if sid_len == 0 || sid_len > buffer.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "current process token returned an invalid user SID length",
        ));
    }
    // SAFETY: valid SID storage contains exactly sid_len readable bytes and is
    // still owned by the live TokenUser buffer. Copying detaches it from both
    // the buffer and token handle.
    Ok(unsafe { std::slice::from_raw_parts(sid as *const u8, sid_len) }.to_vec())
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
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::fs::OpenOptionsExt as _;
    use tempfile::tempdir;

    // ── shared helper ──────────────────────────────────────────────────────

    /// Fetch the current user's account name from USERNAME env var.
    /// Tests that need a valid account name skip gracefully if unset.
    fn current_username() -> Option<String> {
        std::env::var("USERNAME").ok().filter(|u| !u.is_empty())
    }

    #[test]
    fn access_allowed_ace_sid_bounds_reject_truncated_records() {
        let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);

        assert!(checked_access_allowed_sid_len(sid_offset + 7, 0).is_err());
        assert_eq!(
            checked_access_allowed_sid_len(sid_offset + SID_HEADER_LEN, 0).unwrap(),
            SID_HEADER_LEN
        );
        assert!(checked_access_allowed_sid_len(sid_offset + SID_HEADER_LEN, 1).is_err());
        assert_eq!(
            checked_access_allowed_sid_len(sid_offset + SID_HEADER_LEN + 4, 1).unwrap(),
            SID_HEADER_LEN + 4
        );
    }

    #[test]
    fn cap_std_directory_satisfies_handle_bound_dacl_api() {
        fn assert_as_raw_handle<T: AsRawHandle>() {}
        assert_as_raw_handle::<cap_std::fs::Dir>();
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

    #[test]
    fn private_dacl_round_trip_uses_exact_process_token_sid() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("private_state.json");
        File::create(&path).unwrap();

        set_private_current_user_dacl(&path).expect("set protected token-SID DACL");
        verify_private_dacl(&path).expect("read-back must match process TokenUser SID");
    }

    #[test]
    fn private_directory_dacl_is_protected_and_inheritable() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("private-state");
        std::fs::create_dir(&path).unwrap();

        set_private_current_user_directory_dacl(&path)
            .expect("set protected inheritable TokenUser DACL");
        verify_private_directory_dacl(&path)
            .expect("directory ACE must carry exact OI+CI inheritance flags");

        let child = path.join("child.txt");
        std::fs::write(&child, b"owner can create children").unwrap();
        assert_eq!(std::fs::read(&child).unwrap(), b"owner can create children");
    }

    #[test]
    fn private_directory_handle_dacl_remains_bound_across_path_swap() {
        let root = tempdir().unwrap();
        let bound_path = root.path().join("bound");
        let replacement_path = root.path().join("replacement");
        let moved_path = root.path().join("moved");
        std::fs::create_dir(&bound_path).unwrap();
        std::fs::create_dir(&replacement_path).unwrap();

        let directory = OpenOptions::new()
            .access_mode(READ_CONTROL | WRITE_DAC)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&bound_path)
            .expect("open directory capability with DACL rights");

        std::fs::rename(&bound_path, &moved_path).expect("rename handle-bound directory");
        std::fs::rename(&replacement_path, &bound_path).expect("swap original display path");

        set_private_current_user_directory_handle_dacl(&directory)
            .expect("set DACL through original directory handle");
        verify_private_directory_handle_dacl(&directory)
            .expect("same handle must retain owner/DACL proof");
        verify_private_directory_dacl(&moved_path)
            .expect("renamed original object must receive the private DACL");

        let sid = current_process_token_sid().unwrap();
        let inheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
        set_trustee_dacl(
            &bound_path,
            sid.as_ptr() as *mut u16,
            TRUSTEE_IS_SID,
            inheritance,
            false,
        )
        .expect("make swapped path deliberately fail the protected-DACL contract");
        assert!(
            verify_private_directory_dacl(&bound_path).is_err(),
            "the replacement at the stale display path must remain unprotected"
        );
        verify_private_directory_handle_dacl(&directory)
            .expect("path replacement must not redirect handle-bound verification");
    }

    #[test]
    fn bound_directory_dacl_bridge_upgrades_read_only_capability() {
        let root = tempdir().unwrap();
        let path = root.path().join("capability");
        std::fs::create_dir(&path).unwrap();

        let directory = OpenOptions::new()
            .access_mode(READ_CONTROL)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)
            .expect("open read-only directory capability");

        set_private_current_user_directory_dacl_bound(&path, &directory)
            .expect("identity-matched bridge must harden the capability directory");
        verify_private_directory_handle_dacl(&directory)
            .expect("read-only capability must verify the resulting owner/DACL");
        verify_private_directory_dacl(&path)
            .expect("path and capability proofs must agree after hardening");
    }

    #[test]
    fn bound_directory_dacl_bridge_rejects_swapped_display_path() {
        let root = tempdir().unwrap();
        let bound_path = root.path().join("bound");
        let replacement_path = root.path().join("replacement");
        let moved_path = root.path().join("moved");
        std::fs::create_dir(&bound_path).unwrap();
        std::fs::create_dir(&replacement_path).unwrap();

        let directory = OpenOptions::new()
            .access_mode(READ_CONTROL)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&bound_path)
            .expect("open read-only directory capability");

        let sid = current_process_token_sid().unwrap();
        let inheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
        for path in [&bound_path, &replacement_path] {
            set_trustee_dacl(
                path,
                sid.as_ptr() as *mut u16,
                TRUSTEE_IS_SID,
                inheritance,
                false,
            )
            .expect("start from a deliberately unprotected directory DACL");
        }

        std::fs::rename(&bound_path, &moved_path).expect("rename handle-bound directory");
        std::fs::rename(&replacement_path, &bound_path).expect("swap original display path");

        let error = set_private_current_user_directory_dacl_bound(&bound_path, &directory)
            .expect_err("identity mismatch must fail before changing either DACL");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            verify_private_directory_dacl(&bound_path).is_err(),
            "replacement directory must remain unprotected"
        );
        assert!(
            verify_private_directory_dacl(&moved_path).is_err(),
            "original capability directory must remain unprotected"
        );
    }

    #[test]
    fn private_create_is_atomic_handle_bound_and_unicode_safe() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("neoth-私密-🔐.json");

        let mut file = create_private_file_new(&path).expect("atomic private create");
        verify_private_file_handle(&file).expect("handle-bound DACL proof");
        verify_private_dacl(&path).expect("path proof agrees with handle proof");
        file.write_all(b"secret").unwrap();
        file.sync_all().unwrap();
        drop(file);

        assert_eq!(std::fs::read(path).unwrap(), b"secret");
    }

    #[test]
    fn private_create_never_truncates_an_existing_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("already-exists.json");
        let mut original = create_private_file_new(&path).unwrap();
        original.write_all(b"preserve-me").unwrap();
        original.sync_all().unwrap();

        let second = create_private_file_new(&path);
        assert!(second.is_err(), "CREATE_NEW must reject an existing path");
        drop(original);
        assert_eq!(std::fs::read(path).unwrap(), b"preserve-me");
    }

    #[test]
    fn private_create_disables_read_write_and_delete_sharing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("zero-share.json");
        let file = create_private_file_new(&path).unwrap();

        assert!(
            OpenOptions::new().read(true).open(&path).is_err(),
            "a second read handle must be rejected while the private handle is live"
        );
        assert!(
            OpenOptions::new().write(true).open(&path).is_err(),
            "a second write handle must be rejected while the private handle is live"
        );
        assert!(
            std::fs::remove_file(&path).is_err(),
            "delete sharing must be disabled while the private handle is live"
        );

        drop(file);
        std::fs::remove_file(path).expect("file is removable after the handle closes");
    }

    #[test]
    fn private_create_rejects_interior_nul_without_path_truncation() {
        let dir = tempdir().unwrap();
        let mut raw: Vec<u16> = dir.path().as_os_str().encode_wide().collect();
        raw.push(b'\\' as u16);
        raw.extend("nul".encode_utf16());
        raw.push(0);
        raw.extend("suffix".encode_utf16());
        let path = std::path::PathBuf::from(std::ffi::OsString::from_wide(&raw));

        let error = create_private_file_new(&path).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(!dir.path().join("nul").exists());
    }

    #[test]
    fn handle_bound_replace_atomically_replaces_unicode_target() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("private-temp.json");
        let target = dir.path().join("最终-🔐.json");
        std::fs::write(&target, b"old-value").unwrap();

        let mut private_file = create_private_file_new(&source).unwrap();
        private_file.write_all(b"new-private-value").unwrap();
        replace_private_file_handle(&private_file, &target)
            .expect("same-handle atomic replacement");
        assert!(!source.exists(), "source name must be consumed by rename");
        verify_private_file_handle(&private_file).expect("renamed handle remains private");
        drop(private_file);

        assert_eq!(std::fs::read(&target).unwrap(), b"new-private-value");
        verify_private_dacl(&target).expect("final target keeps protected TokenUser DACL");
    }

    #[test]
    fn failed_handle_bound_replace_preserves_old_target() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("private-temp.json");
        let target = dir.path().join("existing-target");
        std::fs::create_dir(&target).unwrap();
        let old_target = target.join("old-target.txt");
        std::fs::write(&old_target, b"old-target").unwrap();

        let mut private_file = create_private_file_new(&source).unwrap();
        private_file.write_all(b"unpublished-value").unwrap();
        let result = replace_private_file_handle(&private_file, &target);
        assert!(
            result.is_err(),
            "a file must not replace a non-empty directory target"
        );
        assert!(source.exists(), "failed rename must retain its source name");
        verify_private_file_handle(&private_file)
            .expect("failed publication must not alter the private source DACL");

        drop(private_file);
        assert!(target.is_dir(), "failed rename must preserve target type");
        assert_eq!(std::fs::read(&old_target).unwrap(), b"old-target");
        assert_eq!(std::fs::read(&source).unwrap(), b"unpublished-value");
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
    //   cargo test -p neoth --lib flush_vs_sync_latency -- --ignored --nocapture --test-threads=1

    #[test]
    #[ignore = "D008 latency bench — run with: cargo test -p neoth --lib flush_vs_sync_latency -- --ignored --nocapture --test-threads=1"]
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
