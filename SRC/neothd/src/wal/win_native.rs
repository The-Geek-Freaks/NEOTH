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
// Cross-platform: the entire file is `#[cfg(target_os = "windows")]` â€”
// Linux / macOS builds never compile this module.

#![cfg(target_os = "windows")]

use std::fs::File;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use tracing::warn;

// â”€â”€ E-11 imports â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, GetLastError, HANDLE, HLOCAL, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT,
    SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_NAME, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN,
    TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, DACL_SECURITY_INFORMATION,
    EqualSid, GetAce, GetAclInformation, GetLengthSid, GetSecurityDescriptorControl,
    GetTokenInformation, INHERITED_ACE, IsValidSid, NO_INHERITANCE,
    PROTECTED_DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

// â”€â”€ E-12 import â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
use windows_sys::Win32::Storage::FileSystem::{FILE_ALL_ACCESS, FlushFileBuffers};

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Internal helpers
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// E-11: Native DACL restriction via SetNamedSecurityInfoW
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Restrict `path` so only the named Windows account (`account`) has an
/// explicit Full Control (GENERIC_ALL = 0x10000000) DACL entry.
///
/// Inherited ACEs are intentionally NOT removed â€” stripping them mid-open
/// (via `PROTECTED_DACL_SECURITY_INFORMATION`) would lock out the daemon's
/// own open file handles. This matches the behaviour of the previous
/// `icacls.exe /grant:r` approach.
///
/// This is the synchronous entry point. From async/tokio contexts use
/// [`set_owner_dacl_async`] which runs this on a `spawn_blocking` thread.
///
/// # Errors
/// Returns `Err` only when a Win32 call fails. The wrapping caller in
/// `win_acl.rs` is expected to log and tolerate failures â€” DACL restriction
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
    set_trustee_dacl(path, sid.as_ptr() as *mut u16, TRUSTEE_IS_SID, true)?;
    verify_private_dacl_for_sid(path, &sid)
}

fn set_owner_dacl_impl(path: &Path, account: &str, protected: bool) -> io::Result<()> {
    let account_w = to_wide_nul(account);
    set_trustee_dacl(
        path,
        account_w.as_ptr() as *mut u16,
        TRUSTEE_IS_NAME,
        protected,
    )
}

fn set_trustee_dacl(
    path: &Path,
    trustee: *mut u16,
    trustee_form: i32,
    protected: bool,
) -> io::Result<()> {
    let path_w = to_wide_nul(&path.to_string_lossy());

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

    // GENERIC_ALL â€” grants all access including read, write, execute, delete.
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
    //  - `oldacl` is null â€” we are constructing a fresh ACL, not merging.
    //  - `&mut new_acl` is a valid out-pointer; Win32 fills it with a
    //    heap-allocated ACL (`LocalAlloc`'d, released by `LocalFree`). We pass
    //    it to `SetNamedSecurityInfoW`, which deep-copies the ACL into the
    //    file's security descriptor, then free `new_acl` with `LocalFree`
    //    after that call returns (SC-08a â€” see the free site below). On a
    //    `SetEntriesInAclW` failure `new_acl` stays null and the `?` below
    //    returns early, so the error path allocates nothing to leak.
    let rc = unsafe { SetEntriesInAclW(1, &ea, std::ptr::null(), &mut new_acl) };

    map_win32(rc, "SetEntriesInAclW")?;

    // Apply the new DACL to the named file.
    //
    // Security flags: we set only the DACL. Private state additionally marks
    // the DACL protected, which prevents parent-directory ACE inheritance.
    //
    // SAFETY:
    //  - `path_w.as_ptr()` is a valid non-null, null-terminated UTF-16
    //    string; it outlives this call.
    //  - `SE_FILE_OBJECT` is the correct object type for file system paths.
    //  - `psidowner` / `psidgroup` / `psacl` are null â€” Win32 interprets
    //    null pointer arguments as "do not change this field" when the
    //    corresponding `SECURITY_INFORMATION` bit is not set.
    //  - `new_acl` was produced by a successful `SetEntriesInAclW` and is
    //    a valid, non-null `*mut ACL`.
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
            std::ptr::null_mut(), // psidowner â€” unchanged
            std::ptr::null_mut(), // psidgroup â€” unchanged
            new_acl,
            std::ptr::null_mut(), // psacl â€” unchanged
        )
    };

    // SC-08a: release the ACL buffer that `SetEntriesInAclW` allocated on the
    // process heap. `SetNamedSecurityInfoW` has already deep-copied the ACL
    // into the file's security descriptor by this point, so the buffer is no
    // longer referenced and MUST be freed per MSDN ("free the returned buffer
    // by calling the LocalFree function"). We free regardless of the
    // `SetNamedSecurityInfoW` result code â€” the buffer was allocated by the
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

/// Verify that `path` has a protected DACL containing exactly one explicit
/// Full Control allow ACE. This detects both inherited access and any extra
/// principal that could read operator-private state.
pub fn verify_private_dacl(path: &Path) -> io::Result<()> {
    let expected_sid = current_process_token_sid()?;
    verify_private_dacl_for_sid(path, &expected_sid)
}

fn verify_private_dacl_for_sid(path: &Path, expected_sid: &[u8]) -> io::Result<()> {
    let path_w = to_wide_nul(&path.to_string_lossy());
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();

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
    if rc != ERROR_SUCCESS {
        if !descriptor.is_null() {
            // SAFETY: any non-null descriptor returned by this API is
            // LocalAlloc-owned, including a partial failure result.
            unsafe { LocalFree(descriptor as HLOCAL) };
        }
        return map_win32(rc, "GetNamedSecurityInfoW");
    }
    if descriptor.is_null() {
        return Err(io::Error::other(
            "GetNamedSecurityInfoW returned a null security descriptor",
        ));
    }

    let verification = (|| {
        if dacl.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private file has a null DACL (access is unrestricted)",
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
                "private file DACL is not protected from inherited ACEs",
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
        if info.AceCount != 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "private file DACL has {} ACEs; expected exactly one",
                    info.AceCount
                ),
            ));
        }

        let mut ace_ptr: *mut std::ffi::c_void = std::ptr::null_mut();ÛŽx¶‰žËkºwµçI•ÍÕ±Ðð ¤øì(€€€±•Ð½Ý¹•‘}Á…Ñ €ôÁ…Ñ ¹Ñ½}Á…Ñ¡}‰Õ˜ ¤ì(€€€±•Ð½Ý¹•‘}…½Õ¹Ð€ô…½Õ¹Ð¹Ñ½}½Ý¹• ¤ì(€€€Ñ½­¥¼èéÑ…Í¬èéÍÁ…Ý¹}‰±½­¥¹œ¡µ½Ù”ñðÍ•Ñ}½Ý¹•É}‘…° ™½Ý¹•‘}Á…Ñ °€™½Ý¹•‘}…½Õ¹Ð¤¤(€€€€€€€€¹…Ý…¥Ð(€€€€€€€€¹Õ¹ÝÉ…Á}½É}•±Í”¡ñ©½¥¹}•ÉÉðì(€€€€€€€€€€€Ý…É¸„¡•ÉÉ½È€ô€•©½¥¹}•ÉÈ°€‰Í•Ñ}½Ý¹•É}‘…°Ñ…Í¬Á…¹¥­•ˆ¤ì(€€€€€€€€€€€=¬  ¤¤(€€€€€€€ô¤)ô((¼¼ƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR (¼¼´ÄÈè±ÕÍ¡¥±•	Õ™™•ÉÌ™½È]0‘ÕÉ…‰¥±¥Ñä(¼¼ƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ((¼¼¼±ÕÍ …±°=Lµ‰Õ™™•É•ÝÉ¥Ñ•Ì™½È™¥±•€Ñ¼Ñ¡”Õ¹‘•É±å¥¹œÍÑ½É…”‘•Ù¥”(¼¼¼Ù¥„±ÕÍ¡¥±•	Õ™™•ÉÍ€¸Q¡¥Ì¥ÌÑ¡”]¥¹‘½ÝÌ•ÅÕ¥Ù…±•¹Ð½˜™Íå¹Œ È¥€¸(¼¼¼(¼¼¼U¹±¥­”ÍÑèé™Ìèé¥±”èéÍå¹}…±° ¥€€¡Ý¡¥ …±Í¼…±±Ì±ÕÍ¡¥±•	Õ™™•ÉÍ€(¼¼¼¥¹Ñ•É¹…±±ä¤°Ñ¡¥Ì™Õ¹Ñ¥½¸ÍÕÉ™…•ÌÑ¡”]¥¸ÌÈ•ÉÉ½È½‘”¥¸Ñ¡”ÉÉ€(¼¼¼Ù…É¥…¹ÐÑ½•Ñ¡•ÈÝ¥Ñ …¸½Á•É…Ñ½ÈµÉ•…‘…‰±”½¹Ñ•áÐÍÑÉ¥¹œ°µ…­¥¹œ]0(¼¼¼ÝÉ¥Ñ”™…¥±ÕÉ•Ì…Ñ¥½¹…‰±”¥¸Ñ¡”ÑÉ…¥¹œ½ÕÑÁÕÐ¸(¼¼¼(¼¼¼€ŒÀÀàµ]%9=]Lµ]0´ÀÄƒŠP]0ÝÉ¥Ñ•È¡½ÐµÁ…Ñ Ý¥É¥¹œ¹½Ñ”(¼¼¼(¼¼¼Q¡”]0ÝÉ¥Ñ•È¡½ÐÁ…Ñ €¡ÝÉ¥Ñ•}…¹‘}Íå¹€¥¸ÝÉ¥Ñ•È¹ÉÍ€¤‘½•Ì€¨©¹½Ð¨¨(¼¼¼…±°Ñ¡¥Ì™Õ¹Ñ¥½¸‘¥É•Ñ±ä¸€=¸]¥¹‘½ÝÌ°Ñ½­¥¼èé™Ìèé¥±”èéÍå¹}‘…Ñ„ ¥€(¼¼¼¥Ì‰…­•€¡Ù¥„Ñ¡”‰±½­¥¹œÁ½½°¤‰äÍÑèé™Ìèé¥±”èéÍå¹}‘…Ñ„ ¥€°Ý¡¥ (¼¼¼Ñ¡”IÕÍÐÍÑ…¹‘…É±¥‰É…Éä¥µÁ±•µ•¹ÑÌ‰ä…±±¥¹œ±ÕÍ¡¥±•	Õ™™•ÉÍ€½¸Ñ¡”(¼¼¼Õ¹‘•É±å¥¹œ!91€¸€]¥É¥¹œÑ¡¥ÌÝÉ…ÁÁ•È¥¸…‘‘¥Ñ¥½¸Ñ¼Íå¹}‘…Ñ…€(¼¼¼Ý½Õ±Ñ¡•É•™½É”¥ÍÍÕ”±ÕÍ¡¥±•	Õ™™•ÉÍ€€¨©ÑÝ¥”¨¨Á•È™É…µ”ƒŠP„(¼¼¼‘½Õ‰±”µ™±ÕÍ Ñ¡…Ð…‘‘Ì±…Ñ•¹äÝ¥Ñ ¹¼…‘‘¥Ñ¥½¹…°‘ÕÉ…‰¥±¥Ñä‰•¹•™¥Ð¸(¼¼¼(¼¼¼Q¡¥ÌÝÉ…ÁÁ•È¥ÌÁÉ½Ù¥‘•™½È‘¥…¹½ÍÑ¥Œ…¹…‘µ¥¸Á…Ñ¡ÌÑ¡…Ð¹••Ñ¡”É…Ü(¼¼¼]¥¸ÌÈ•ÉÉ½È½‘”ÍÕÉ™…•‘¥É•Ñ±äÉ…Ñ¡•ÈÑ¡…¸Ñ¡É½Õ Ñ¡”ÍÑ¥¼èéÉÉ½É€(¼¼¼µ…ÁÁ¥¹œ¸€M•”™±ÕÍ¡}ÙÍ}Íå¹}‘…Ñ…}±…Ñ•¹å}½µÁ…É¥Í½¹€€¡Ñ¡”€m¥¹½É•u(¼¼¼Ñ•ÍÐ‰•±½Ü¤™½Èµ•…ÍÕÉ•±…Ñ•¹ä‘…Ñ„½¹™¥Éµ¥¹œÑ¡”™Õ¹Ñ¥½¹…°•ÅÕ¥Ù…±•¹”(¼¼¼½˜‰½Ñ Á…Ñ¡Ì°…¹Ñ¡”%1}1}]I%Q}Q!I=U!€Ñ¡É•Í¡½±É…Ñ¥½¹…±”(¼¼¼‘½Õµ•¹Ñ•Ñ¡•É”¸(¼¼¼(¼¼¼€ŒÉÉ½ÉÌ(¼¼¼I•ÑÕÉ¹ÌÉÉ€Ý¡•¸±ÕÍ¡¥±•	Õ™™•ÉÍ€É•ÑÕÉ¹Ì€Á€€¡1M¤¸)ÁÕˆ™¸™±ÕÍ¡}™¥±•}‰Õ™™•ÉÌ¡™¥±”è€™¥±”¤€´ø¥¼èéI•ÍÕ±Ðð ¤øì(€€€€¼¼MQdè(€€€€¼¼€€´™¥±”¹…Í}É…Ý}¡…¹‘±” ¥€É•ÑÕÉ¹Ì„Ù…±¥°½Á•¸!91Ñ¡…Ð¥Ì½Ý¹•(€€€€¼¼€€€…¹­•ÁÐ…±¥Ù”‰äÑ¡”¥±•€É•™•É•¹”™½È…Ð±•…ÍÐÑ¡”‘ÕÉ…Ñ¥½¸½˜(€€€€¼¼€€€Ñ¡¥Ì…±°¸(€€€€¼¼€€´±ÕÍ¡¥±•	Õ™™•ÉÍ€…•ÁÑÌÑ¡”!91‰äÙ…±Õ”€¡¥¹Ñ••È½Áä¤…¹(€€€€¼¼€€€‘½•Ì¹½ÐÍÑ½É”½È…±¥…Ì¥Ð¸(€€€€¼¼€€´Q¡”É•ÑÕÉ¸Ù…±Õ”¥Ì„]¥¸ÌÈ	==0è¹½¸µé•É¼µ•…¹ÌÍÕ•ÍÌ°€Àµ•…¹Ì(€€€€¼¼€€€™…¥±ÕÉ”€¡…±±•ÈµÕÍÐ¡•¬•Ñ1…ÍÑÉÉ½É€™½ÈÑ¡”½‘”¤¸(€€€±•ÐÉŒ€ôÕ¹Í…™”ì±ÕÍ¡¥±•	Õ™™•ÉÌ¡™¥±”¹…Í}É…Ý}¡…¹‘±” ¤…Ì!91¤ôì((€€€¥˜ÉŒ€„ô€Àì(€€€€€€€=¬  ¤¤(€€€ô•±Í”ì(€€€€€€€€¼¼MQdè(€€€€€€€€¼¼€€´•Ñ1…ÍÑÉÉ½É€¥ÌÑ¡É•…µ±½…°…¹Ù…±¥Ñ¼…±°¥µµ•‘¥…Ñ•±ä(€€€€€€€€¼¼€€€…™Ñ•È„™…¥±¥¹œ]¥¸ÌÈ™Õ¹Ñ¥½¸½¸Ñ¡”Í…µ”Ñ¡É•…¸9¼½Ñ¡•È(€€€€€€€€¼¼€€€]¥¸ÌÈ…±°½ÕÉÌ‰•ÑÝ••¸Ñ¡”™…¥±¥¹œ±ÕÍ¡¥±•	Õ™™•ÉÍ€…¹(€€€€€€€€¼¼€€€Ñ¡¥Ì•Ñ1…ÍÑÉÉ½É€¸(€€€€€€€±•Ð½‘”€ôÕ¹Í…™”ìÝ¥¹‘½ÝÍ}ÍåÌèé]¥¸ÌÈèé½Õ¹‘…Ñ¥½¸èé•Ñ1…ÍÑÉÉ½È ¤ôì(€€€€€€€ÉÈ¡¥¼èéÉÉ½Èèé½Ñ¡•È¡™½Éµ…Ð„ (€€€€€€€€€€€€‰±ÕÍ¡¥±•	Õ™™•ÉÌè]¥¸ÌÈ•ÉÉ½Èí½‘”èŒÀÄÁáô€¡íô¤ˆ°(€€€€€€€€€€€Ý¥¸ÌÉ}¥½}•ÉÈ¡½‘”¤(€€€€€€€€¤¤¤(€€€ô)ô((¼¼¼Íå¹ŒÝÉ…ÁÁ•ÈèÉÕ¹Ìm™±ÕÍ¡}™¥±•}‰Õ™™•ÉÍt½¸„ÍÁ…Ý¹}‰±½­¥¹€Ñ¡É•…(¼¼¼…¹É•ÑÕÉ¹ÌÑ¡”¥±•€½¸ÍÕ•ÍÌ€¡Í¼…±±•ÉÌ…¸½¹Ñ¥¹Õ”ÕÍ¥¹œ¥Ð¤¸)ÁÕˆ…Íå¹Œ™¸™±ÕÍ¡}™¥±•}‰Õ™™•ÉÍ}…Íå¹Œ¡™¥±”è¥±”¤€´ø¥¼èéI•ÍÕ±Ðñ¥±”øì(€€€Ñ½­¥¼èéÑ…Í¬èéÍÁ…Ý¹}‰±½­¥¹œ¡µ½Ù”ñð™±ÕÍ¡}™¥±•}‰Õ™™•ÉÌ ™™¥±”¤¹µ…À¡ð ¥ð™¥±”¤¤(€€€€€€€€¹…Ý…¥Ð(€€€€€€€€¹µ…Á}•ÉÈ¡ñ©½¥¹}•ÉÉðì(€€€€€€€€€€€¥¼èéÉÉ½Èèé½Ñ¡•È¡™½Éµ…Ð„ ‰™±ÕÍ¡}™¥±•}‰Õ™™•ÉÌÑ…Í¬Á…¹¥­•èí©½¥¹}•ÉÉôˆ¤¤(€€€€€€€ô¤ü)ô((¼¼ƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR (¼¼Q•ÍÑÌ(¼¼ƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ((m™œ¡Ñ•ÍÐ¥t)µ½Ñ•ÍÑÌì(€€€ÕÍ”ÍÕÁ•Èèè¨ì(€€€ÕÍ”ÍÑèé™Ìèé¥±”ì(€€€ÕÍ”ÍÑèé¥¼èé]É¥Ñ”ì(€€€ÕÍ”Ñ•µÁ™¥±”èéÑ•µÁ‘¥Èì((€€€€¼¼ƒŠRŠR Í¡…É•¡•±Á•ÈƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ((€€€€¼¼¼•Ñ Ñ¡”ÕÉÉ•¹ÐÕÍ•ÈÌ…½Õ¹Ð¹…µ”™É½´UMI95•¹ØÙ…È¸(€€€€¼¼¼Q•ÍÑÌÑ¡…Ð¹••„Ù…±¥…½Õ¹Ð¹…µ”Í­¥ÀÉ…•™Õ±±ä¥˜Õ¹Í•Ð¸(€€€™¸ÕÉÉ•¹Ñ}ÕÍ•É¹…µ” ¤€´ø=ÁÑ¥½¸ñMÑÉ¥¹œøì(€€€€€€€ÍÑèé•¹ØèéÙ…È ‰UMI95ˆ¤¹½¬ ¤¹™¥±Ñ•È¡ñÕð€…Ô¹¥Í}•µÁÑä ¤¤(€€€ô((€€€€¼¼ƒŠRŠR ´ÄÄè0Í•ÐÉ½Õ¹µÑÉ¥ÀƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ((€€€€¼¼¼M•ÑÑ¥¹œÑ¡”0½¸…¸•á¥ÍÑ¥¹œ™¥±”Ý¥Ñ Ñ¡”ÕÉÉ•¹ÐÕÍ•É¹…µ”µÕÍÐ(€€€€¼¼¼ÍÕ••Ý¥Ñ¡½ÕÐ•ÉÉ½È¸(€€€€mÑ•ÍÑt(€€€™¸‘…±}É½Õ¹‘}ÑÉ¥Á}Í•ÑÍ}Ý¥Ñ¡½ÕÑ}•ÉÉ½È ¤ì(€€€€€€€±•ÐM½µ”¡ÕÍ•É¹…µ”¤€ôÕÉÉ•¹Ñ}ÕÍ•É¹…µ” ¤•±Í”ì(€€€€€€€€€€€•ÁÉ¥¹Ñ±¸„ ‰M-%@‘…±}É½Õ¹‘}ÑÉ¥Á}Í•ÑÍ}Ý¥Ñ¡½ÕÑ}•ÉÉ½ÈèUMI95¹½ÐÍ•Ðˆ¤ì(€€€€€€€€€€€É•ÑÕÉ¸ì(€€€€€€€ôì(€€€€€€€±•Ð‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•ÐÁ…Ñ €ô‘¥È¹Á…Ñ  ¤¹©½¥¸ ‰‘…±}Ñ•ÍÐ¹Ý…°ˆ¤ì(€€€€€€€¥±”èéÉ•…Ñ” ™Á…Ñ ¤¹Õ¹ÝÉ…À ¤ì((€€€€€€€±•ÐÉ•ÍÕ±Ð€ôÍ•Ñ}½Ý¹•É}‘…° ™Á…Ñ °€™ÕÍ•É¹…µ”¤ì(€€€€€€€…ÍÍ•ÉÐ„ (€€€€€€€€€€€É•ÍÕ±Ð¹¥Í}½¬ ¤°(€€€€€€€€€€€€‰Í•Ñ}½Ý¹•É}‘…°™…¥±•èìèýôˆ°(€€€€€€€€€€€É•ÍÕ±Ð¹Õ¹ÝÉ…Á}•ÉÈ ¤(€€€€€€€€¤ì(€€€ô((€€€€mÑ•ÍÑt(€€€™¸ÁÉ¥Ù…Ñ•}‘…±}É½Õ¹‘}ÑÉ¥Á}ÕÍ•Í}•á…Ñ}ÁÉ½•ÍÍ}Ñ½­•¹}Í¥ ¤ì(€€€€€€€±•Ð‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•ÐÁ…Ñ €ô‘¥È¹Á…Ñ  ¤¹©½¥¸ ‰ÁÉ¥Ù…Ñ•}ÍÑ…Ñ”¹©Í½¸ˆ¤ì(€€€€€€€¥±”èéÉ•…Ñ” ™Á…Ñ ¤¹Õ¹ÝÉ…À ¤ì((€€€€€€€Í•Ñ}ÁÉ¥Ù…Ñ•}ÕÉÉ•¹Ñ}ÕÍ•É}‘…° ™Á…Ñ ¤¹•áÁ•Ð ‰Í•ÐÁÉ½Ñ•Ñ•Ñ½­•¸µM%0ˆ¤ì(€€€€€€€Ù•É¥™å}ÁÉ¥Ù…Ñ•}‘…° ™Á…Ñ ¤¹•áÁ•Ð ‰É•…µ‰…¬µÕÍÐµ…Ñ ÁÉ½•ÍÌQ½­•¹UÍ•ÈM%ˆ¤ì(€€€ô((€€€€¼¼¼…±±¥¹œÍ•Ñ}½Ý¹•É}‘…°ÑÝ¥”½¸Ñ¡”Í…µ”™¥±”µÕÍÐ‰”¥‘•µÁ½Ñ•¹Ð(€€€€¼¼¼€¡Í•½¹…±°…±Í¼ÍÕ••‘Ì¤¸(€€€€mÑ•ÍÑt(€€€™¸‘…±}¥‘•µÁ½Ñ•¹Ñ}‘½Õ‰±•}Í•Ð ¤ì(€€€€€€€±•ÐM½µ”¡ÕÍ•É¹…µ”¤€ôÕÉÉ•¹Ñ}ÕÍ•É¹…µ” ¤•±Í”ì(€€€€€€€€€€€•ÁÉ¥¹Ñ±¸„ ‰M-%@‘…±}¥‘•µÁ½Ñ•¹Ñ}‘½Õ‰±•}Í•ÐèUMI95¹½ÐÍ•Ðˆ¤ì(€€€€€€€€€€€É•ÑÕÉ¸ì(€€€€€€€ôì(€€€€€€€±•Ð‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•ÐÁ…Ñ €ô‘¥È¹Á…Ñ  ¤¹©½¥¸ ‰‘…±}¥‘•µÁ½Ñ•¹Ð¹Ý…°ˆ¤ì(€€€€€€€¥±”èéÉ•…Ñ” ™Á…Ñ ¤¹Õ¹ÝÉ…À ¤ì((€€€€€€€Í•Ñ}½Ý¹•É}‘…° ™Á…Ñ °€™ÕÍ•É¹…µ”¤¹•áÁ•Ð ‰™¥ÉÍÐ…±°ˆ¤ì(€€€€€€€Í•Ñ}½Ý¹•É}‘…° ™Á…Ñ °€™ÕÍ•É¹…µ”¤¹•áÁ•Ð ‰Í•½¹…±°€¡¥‘•µÁ½Ñ•¹Ð¤ˆ¤ì(€€€ô((€€€€¼¼¼¹½¹•á¥ÍÑ•¹ÐÁ…Ñ µÕÍÐÉ•ÑÕÉ¸ÉÉ€€¡]¥¸ÌÈ…¹¹½ÐÍ•Ð0½¸„™¥±”(€€€€¼¼¼Ñ¡…Ð‘½•Ì¹½Ð•á¥ÍÐ¤¸(€€€€mÑ•ÍÑt(€€€™¸‘…±}¹½¹•á¥ÍÑ•¹Ñ}Á…Ñ¡}É•ÑÕÉ¹Í}•ÉÈ ¤ì(€€€€€€€±•Ð‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•ÐÁ…Ñ €ô‘¥È¹Á…Ñ  ¤¹©½¥¸ ‰‘½•Í}¹½Ñ}•á¥ÍÐ¹Ý…°ˆ¤ì(€€€€€€€€¼¼¥±”‘½•Ì¹½Ð•á¥ÍÐƒŠPM•Ñ9…µ•‘M•ÕÉ¥Ñå%¹™½\É•ÑÕÉ¹Ì…¸•ÉÉ½È¸(€€€€€€€±•ÐÉ•ÍÕ±Ð€ôÍ•Ñ}½Ý¹•É}‘…° ™Á…Ñ °€‰¹å½Õ¹Ðˆ¤ì(€€€€€€€…ÍÍ•ÉÐ„¡É•ÍÕ±Ð¹¥Í}•ÉÈ ¤°€‰•áÁ•Ñ•ÉÈ™½È¹½¹•á¥ÍÑ•¹ÐÁ…Ñ °½Ð=¬ˆ¤ì(€€€ô((€€€€¼¼ƒŠRŠR ´ÄÈè±ÕÍ¡¥±•	Õ™™•ÉÌƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ((€€€€¼¼¼±ÕÍ¡¥±•	Õ™™•ÉÌ½¸„™É•Í¡±äÉ•…Ñ•™¥±”µÕÍÐÍÕ••¸(€€€€mÑ•ÍÑt(€€€™¸™±ÕÍ¡}Íµ½­•}½Á•¹}™¥±” ¤ì(€€€€€€€±•Ð‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•ÐÁ…Ñ €ô‘¥È¹Á…Ñ  ¤¹©½¥¸ ‰™±ÕÍ¡}Íµ½­”¹Ý…°ˆ¤ì(€€€€€€€±•Ð™¥±”€ô¥±”èéÉ•…Ñ” ™Á…Ñ ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•ÐÉ•ÍÕ±Ð€ô™±ÕÍ¡}™¥±•}‰Õ™™•ÉÌ ™™¥±”¤ì(€€€€€€€…ÍÍ•ÉÐ„ (€€€€€€€€€€€É•ÍÕ±Ð¹¥Í}½¬ ¤°(€€€€€€€€€€€€‰™±ÕÍ¡}™¥±•}‰Õ™™•ÉÌ™…¥±•½¸½Á•¸™¥±”èìèýôˆ°(€€€€€€€€€€€É•ÍÕ±Ð¹Õ¹ÝÉ…Á}•ÉÈ ¤(€€€€€€€€¤ì(€€€ô((€€€€¼¼¼]É¥Ñ”‰åÑ•ÌÑ¡•¸™±ÕÍ ƒŠPµÕÍÐÍÕ••…¹‘…Ñ„µÕÍÐ‰”½¸‘¥Í¬¸(€€€€mÑ•ÍÑt(€€€™¸™±ÕÍ¡}…™Ñ•É}ÝÉ¥Ñ•}ÍÕ••‘Ì ¤ì(€€€€€€€±•Ð‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•ÐÁ…Ñ €ô‘¥È¹Á…Ñ  ¤¹©½¥¸ ‰™±ÕÍ¡}ÝÉ¥Ñ”¹Ý…°ˆ¤ì(€€€€€€€±•ÐµÕÐ™¥±”€ô¥±”èéÉ•…Ñ” ™Á…Ñ ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€™¥±”¹ÝÉ¥Ñ•}…±°¡ˆ‰¹•½Ñ µÝ…°µÍ•µ•¹Ðµ¡•…‘•Éq¸ˆ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€±•ÐÉ•ÍÕ±Ð€ô™±ÕÍ¡}™¥±•}‰Õ™™•ÉÌ ™™¥±”¤ì(€€€€€€€…ÍÍ•ÉÐ„ (€€€€€€€€€€€É•ÍÕ±Ð¹¥Í}½¬ ¤°(€€€€€€€€€€€€‰™±ÕÍ …™Ñ•ÈÝÉ¥Ñ”™…¥±•èìèýôˆ°(€€€€€€€€€€€É•ÍÕ±Ð¹Õ¹ÝÉ…Á}•ÉÈ ¤(€€€€€€€€¤ì(€€€ô((€€€€¼¼ƒŠRŠR ÉÉ½Èµ…ÁÁ¥¹œ¡•±Á•ÉÌƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR ((€€€€¼¼¼II=I}MUML€ À¤µÕÍÐµ…ÀÑ¼=¬¸(€€€€mÑ•ÍÑt(€€€™¸µ…Á}Ý¥¸ÌÉ}½­}½¹}•ÉÉ½É}ÍÕ•ÍÌ ¤ì(€€€€€€€…ÍÍ•ÉÐ„¡µ…Á}Ý¥¸ÌÈ À°€‰Ñ•ÍÑ}Ñàˆ¤¹¥Í}½¬ ¤¤ì(€€€ô((€€€€¼¼¼9½¸µé•É¼]¥¸ÌÈ½‘”µÕÍÐµ…ÀÑ¼ÉÈ½¹Ñ…¥¹¥¹œÑ¡”½¹Ñ•áÐ±…‰•°…¹(€€€€¼¼¼Ñ¡”¡•à•ÉÉ½È½‘”¸(€€€€mÑ•ÍÑt(€€€™¸µ…Á}Ý¥¸ÌÉ}•ÉÉ}½¹Ñ…¥¹Í}½¹Ñ•áÑ}…¹‘}½‘” ¤ì(€€€€€€€€¼¼€Ô€ôII=I}MM}9%ƒŠPÁÉ•‘¥Ñ…‰±”°Ý•±°µ­¹½Ý¸½‘”¸(€€€€€€€±•Ð•ÉÈ€ôµ…Á}Ý¥¸ÌÈ Ô°€‰µå}Ñàˆ¤¹Õ¹ÝÉ…Á}•ÉÈ ¤ì(€€€€€€€±•ÐµÍœ€ô•ÉÈ¹Ñ½}ÍÑÉ¥¹œ ¤ì(€€€€€€€…ÍÍ•ÉÐ„ (€€€€€€€€€€€µÍœ¹½¹Ñ…¥¹Ì ‰µå}Ñàˆ¤°(€€€€€€€€€€€€‰•ÉÉ½Èµ•ÍÍ…”Í¡½Õ±½¹Ñ…¥¸½¹Ñ•áÐ±…‰•°èíµÍôˆ(€€€€€€€€¤ì(€€€€€€€…ÍÍ•ÉÐ„ (€€€€€€€€€€€µÍœ¹½¹Ñ…¥¹Ì ˆÁàÀÀÀÀÀÀÀÔˆ¤°(€€€€€€€€€€€€‰•ÉÉ½Èµ•ÍÍ…”Í¡½Õ±½¹Ñ…¥¸¡•à•ÉÉ½È½‘”èíµÍôˆ(€€€€€€€€¤ì(€€€ô((€€€€¼¼¼Ñ½}Ý¥‘•}¹Õ±€µÕÍÐÁÉ½‘Õ”•á…Ñ±ä±•¸¬ÄÔÄØÙ…±Õ•ÌÝ¥Ñ „¹Õ±°(€€€€¼¼¼Ñ•Éµ¥¹…Ñ½È…ÐÑ¡”•¹¸(€€€€mÑ•ÍÑt(€€€™¸Ý¥‘•}¹Õ±}•¹½‘¥¹}½ÉÉ•Ð ¤ì(€€€€€€€±•ÐÝ¥‘”€ôÑ½}Ý¥‘•}¹Õ° ‰…‰Œˆ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„¡Ý¥‘”¹±•¸ ¤°€Ð°€ˆÌ¡…ÉÌ€¬€Ä¹Õ±°Ñ•Éµ¥¹…Ñ½Èˆ¤ì(€€€€€€€…ÍÍ•ÉÑ}•Ä„ ©Ý¥‘”¹±…ÍÐ ¤¹Õ¹ÝÉ…À ¤°€ÁÔÄØ°€‰±…ÍÐ•±•µ•¹ÐµÕÍÐ‰”¹Õ±°ˆ¤ì(€€€ô((€€€€¼¼ƒŠRŠR ÀÀàµ]%9=]Lµ]0´ÀÄƒŠP±ÕÍ¡¥±•	Õ™™•ÉÌÙÌÍå¹}‘…Ñ„±…Ñ•¹äƒŠRŠRŠRŠRŠRŠRŠRŠR (€€€€¼¼(€€€€¼¼½µÁ…É•ÌÑ¡”•áÁ±¥¥Ð™±ÕÍ¡}™¥±•}‰Õ™™•ÉÍ€€¡´ÄÈÝÉ…ÁÁ•È¤Á…Ñ ……¥¹ÍÐ(€€€€¼¼ÍÑèé™Ìèé¥±”èéÍå¹}‘…Ñ„ ¥€€¡Ñ¡”]0ÝÉ¥Ñ•ÈÌÕÉÉ•¹Ð¡½ÐÁ…Ñ ¤¸(€€€€¼¼(€€€€¼¼	½Ñ Á…Ñ¡Ì…±°±ÕÍ¡¥±•	Õ™™•ÉÍ€½¹”ìÑ¡¥Ì‰•¹ ÁÉ½‘Õ•Ì5MUI(€€€€¼¼•Ù¥‘•¹”Ñ¡…ÐÑ¡”´ÄÈÝÉ…ÁÁ•È…‘‘Ì¹¼±…Ñ•¹ä‰•¹•™¥ÐÝ¡•¸Ý¥É•(€€€€¼¼…±½¹Í¥‘”Íå¹}‘…Ñ…€°½¹™¥Éµ¥¹œÑ¡”‘½Õ‰±”µ™±ÕÍ …¹…±åÍ¥Ì¥¸(€€€€¼¼ÝÉ¥Ñ•}…¹‘}Íå¹€€¡ÝÉ¥Ñ•È¹ÉÌ¤¸(€€€€¼¼(€€€€¼¼€ŒŒ%1}1}]I%Q}Q!I=U Ñ¡É•Í¡½±(€€€€¼¼(€€€€¼¼%1}1}]I%Q}Q!I=U!€‰åÁ…ÍÍ•ÌÑ¡”=LÝÉ¥Ñ”…¡”Í¼•… ÝÉ¥Ñ”(€€€€¼¼½•Ì‘¥É•Ñ±äÑ¼ÍÑ½É…”Ý¥Ñ¡½ÕÐ„ÍÕ‰Í•ÅÕ•¹Ð±ÕÍ¡¥±•	Õ™™•ÉÍ€…±°¸(€€€€¼¼A½ÍÍ¥‰±”‰•¹•™¥ÐèÍÕˆµµ¥±±¥Í•½¹É•‘ÕÑ¥½¸¥¸Me9}=9}]I%Q±…Ñ•¹ä½¸(€€€€¼¼‘É¥Ù•ÌÝ¥Ñ ™¥ÉµÝ…É”ÝÉ¥Ñ”µ‰…¬…¡•Ì¸€½ÍÐèÉ•ÅÕ¥É•Ì½Á•¹¥¹œÑ¡”]0(€€€€¼¼™¥±”Ý¥Ñ É•…Ñ•¥±•\¡%1}1}]I%Q}Q!I=U ¥€ƒŠP„]¥¹‘½ÝÌµ½¹±ä½‘”(€€€€¼¼Á…Ñ ƒŠP9%1}1}9=}	UI%9€™½È™Õ±°=Lµ…¡”‰åÁ…ÍÌ°Ý¡¥ (€€€€¼¼µ…¹‘…Ñ•Ì€ÔÄÈ€¼€ÐÀäØµ‰åÑ”Í•Ñ½Èµ…±¥¹•ÝÉ¥Ñ•Ì€¡…±¥¹µ•¹Ðµ‰Õ™™•ÈÉ•™…Ñ½È¤¸(€€€€¼¼(€€€€¼¼%¹Ù•ÍÑ¥…Ñ”ÝÉ¥Ñ”µÑ¡É½Õ Ý¡•¸%Q!Hµ•…ÍÕÉ•µ•ÑÉ¥Œ•á••‘Ìè(€€€€¼¼€€ƒŠˆÀÔÀ€€ø€ÔµÌ€ƒŠP™Íå¹ŒÁ•É•ÁÑ¥‰±”¥¸Me9}=9}]I%Q¡…ÐÉ½Õ¹µÑÉ¥À(€€€€¼¼€€ƒŠˆÀää€€ø€ÔÀµÌƒŠPÍÑ½É…”…¹½µ…±äì¡•¬M5IP€¼9Y5”¡•…±Ñ ±½Ì(€€€€¼¼(€€€€¼¼	•±½ÜÑ¡½Í”Ñ¡É•Í¡½±‘ÌÑ¡”…±¥¹µ•¹Ðµ±…å•È½µÁ±•á¥Ñä½ÕÑÝ•¥¡ÌÑ¡”(€€€€¼¼±…Ñ•¹ä…¥¸½¸9Y5”ÍÑ½É…”Ý¥Ñ ÍÑ…‰±”™¥ÉµÝ…É”…¡•Ì¸(€€€€¼¼(€€€€¼¼IÕ¸½¸‘•µ…¹è(€€€€¼¼(€€€€¼¼€€…É¼Ñ•ÍÐ€µÀ¹•½Ñ €´µ±¥ˆ™±ÕÍ¡}ÙÍ}Íå¹}±…Ñ•¹ä€´´€´µ¥¹½É•€´µ¹½…ÁÑÕÉ”€´µÑ•ÍÐµÑ¡É•…‘ÌôÄ((€€€€mÑ•ÍÑt(€€€€m¥¹½É”€ô€‰ÀÀà±…Ñ•¹ä‰•¹ ƒŠPÉÕ¸Ý¥Ñ è…É¼Ñ•ÍÐ€µÀ¹•½Ñ €´µ±¥ˆ™±ÕÍ¡}ÙÍ}Íå¹}±…Ñ•¹ä€´´€´µ¥¹½É•€´µ¹½…ÁÑÕÉ”€´µÑ•ÍÐµÑ¡É•…‘ÌôÄ‰t(€€€™¸™±ÕÍ¡}ÙÍ}Íå¹}‘…Ñ…}±…Ñ•¹å}½µÁ…É¥Í½¸ ¤ì(€€€€€€€ÕÍ”ÍÑèé¥¼èé]É¥Ñ”ì(€€€€€€€ÕÍ”ÍÑèéÑ¥µ”èé%¹ÍÑ…¹Ðì((€€€€€€€½¹ÍÐ%QILèÕÍ¥é”€ô€ÈÀÀì(€€€€€€€€¼¼I•ÁÉ•Í•¹Ñ…Ñ¥Ù”]0™É…µ”Í¥é”èÍ¡½ÉÐAI=Y%I}IMA=9M•Ù•¹Ð¸(€€€€€€€½¹ÍÐI5}	eQLèÕÍ¥é”€ô€ÔÄÈì(€€€€€€€±•Ð™É…µ”€ôÙ•Œ…lÁÔàìI5}	eQMtì((€€€€€€€±•Ð‘¥È€ôÑ•µÁ‘¥È ¤¹Õ¹ÝÉ…À ¤ì((€€€€€€€€¼¼ƒŠRŠR A…Ñ è•áÁ±¥¥Ð±ÕÍ¡¥±•	Õ™™•ÉÌÙ¥„´ÄÈÝÉ…ÁÁ•ÈƒŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠRŠR (€€€€€€€±•ÐÁ…Ñ¡}„€ô‘¥È¹Á…Ñ  ¤¹©½¥¸ ‰±…Ñ}™±ÕÍ¡}„¹Ý…°ˆ¤ì(€€€€€€€±•ÐµÕÐ™¥±•}„€ô¥±”èéÉ•…Ñ” ™Á…Ñ¡}„¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€€¼¼]…É´µÕÀèÁÉ¥µ”Ñ¡”L€¼9QL©½ÕÉ¹…°‰•™½É”Í…µÁ±¥¹œ¸(€€€€€€€™½È|¥¸€À¸¸ÄÀì(€€€€€€€€€€€™¥±•}„¹ÝÉ¥Ñ•}…±° ™™É…µ”¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€€€€€™±ÕÍ¡}™¥±•}‰Õ™™•ÉÌ ™™¥±•}„¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€ô(€€€€€€€±•ÐµÕÐÍ…µÁ±•Í}„èY•ŒñÔØÐø€ôY•ŒèéÝ¥Ñ¡}…Á…¥Ñä¡%QIL¤ì(€€€€€€€™½È|¥¸€À¸¹%QILì(€€€€€€€€€€€±•ÐÐÀ€ô%¹ÍÑ…¹Ðèé¹½Ü ¤ì(€€€€€€€€€€€™¥±•}„¹ÝÉ¥Ñ•}…±° ™™É…µ”¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€€€€€™±ÕÍ¡}™¥±•}‰Õ™™•ÉÌ ™™¥±•}„¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€€€€€Í…µÁ±•Í}„¹ÁÕÍ ¡ÐÀ¹•±…ÁÍ• ¤¹…Í}¹…¹½Ì ¤…ÌÔØÐ¤ì(€€€€€€€ô((€€€€€€€€¼¼ƒŠRŠR A…Ñ èÍÑèé™Ìèé¥±”èéÍå¹}‘…Ñ„€¡]0ÝÉ¥Ñ•È¡½ÐÁ…Ñ ¤ƒŠRŠRŠRŠRŠRŠRŠRŠRŠR (€€€€€€€±•ÐÁ…Ñ¡}ˆ€ô‘¥È¹Á…Ñ  ¤¹©½¥¸ ‰±…Ñ}Íå¹}ˆ¹Ý…°ˆ¤ì(€€€€€€€±•ÐµÕÐ™¥±•}ˆ€ô¥±”èéÉ•…Ñ” ™Á…Ñ¡}ˆ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€™½È|¥¸€À¸¸ÄÀì(€€€€€€€€€€€™¥±•}ˆ¹ÝÉ¥Ñ•}…±° ™™É…µ”¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€€€€€™¥±•}ˆ¹Íå¹}‘…Ñ„ ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€ô(€€€€€€€±•ÐµÕÐÍ…µÁ±•Í}ˆèY•ŒñÔØÐø€ôY•ŒèéÝ¥Ñ¡}…Á…¥Ñä¡%QIL¤ì(€€€€€€€™½È|¥¸€À¸¹%QILì(€€€€€€€€€€€±•ÐÐÀ€ô%¹ÍÑ…¹Ðèé¹½Ü ¤ì(€€€€€€€€€€€™¥±•}ˆ¹ÝÉ¥Ñ•}…±° ™™É…µ”¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€€€€€™¥±•}ˆ¹Íå¹}‘…Ñ„ ¤¹Õ¹ÝÉ…À ¤ì(€€€€€€€€€€€Í…µÁ±•Í}ˆ¹ÁÕÍ ¡ÐÀ¹•±…ÁÍ• ¤¹…Í}¹…¹½Ì ¤…ÌÔØÐ¤ì(€€€€€€€ô((€€€€€€€Í…µÁ±•Í}„¹Í½ÉÑ}Õ¹ÍÑ…‰±” ¤ì(€€€€€€€Í…µÁ±•Í}ˆ¹Í½ÉÑ}Õ¹ÍÑ…‰±” ¤ì((€€€€€€€±•ÐÀÔÁ}„€ôÍ…µÁ±•Í}…m%QIL€¼€Étì(€€€€€€€±•ÐÀÔÁ}ˆ€ôÍ…µÁ±•Í}‰m%QIL€¼€Étì(€€€€€€€±•ÐÀäÕ}„€ôÍ…µÁ±•Í}…m%QIL€¨€äÔ€¼€ÄÀÁtì(€€€€€€€±•ÐÀäÕ}ˆ€ôÍ…µÁ±•Í}‰m%QIL€¨€äÔ€¼€ÄÀÁtì(€€€€€€€±•ÐÀäå}„€ôÍ…µÁ±•Í}…m%QIL€¨€ää€¼€ÄÀÁtì(€€€€€€€±•ÐÀäå}ˆ€ôÍ…µÁ±•Í}‰m%QIL€¨€ää€¼€ÄÀÁtì((€€€€€€€ÁÉ¥¹Ñ±¸„ (€€€€€€€€€€€€‰q¹ÀÀàµ]%9=]Lµ]0´ÀÄ€±ÕÍ¡¥±•	Õ™™•ÉÌÙÌÍå¹}‘…Ñ„€€¡¸õíô€™É…µ”õíõ¥q¹p(€€€€€€€€€€€€qàÈÀm´ÄÈ±ÕÍ¡¥±•	Õ™™•ÉÍt€ÀÔÀõìè¸ÍõµÌ€ÀäÔõìè¸ÍõµÌ€Àääõìè¸ÍõµÍq¹p(€€€€€€€€€€€€qàÈÀmÍÑ€Íå¹}‘…Ñ„€€€€€€€t€ÀÔÀõìè¸ÍõµÌ€ÀäÔõìè¸ÍõµÌ€Àääõìè¸ÍõµÍq¹p(€€€€€€€€€€€€q¹p(€€€€€€€€€€€€qàÈÀY•É‘¥Ðè¥˜ñÀÔÁ}„€´ÀÔÁ}‰ð€ð€ÅµÌÑ¡”´ÄÈÝÉ…ÁÁ•È…‘‘Ì¹¼µ•…ÍÕÉ…‰±•q¹p(€€€€€€€€€€€€qàÈÀ‰•¹•™¥ÐÝ¡•¸Ý¥É•…±½¹Í¥‘”Íå¹}‘…Ñ„€¡‰½Ñ …±°±ÕÍ¡¥±•	Õ™™•ÉÌ½¹”¤¹q¹p(€€€€€€€€€€€€qàÈÀQ!IM!=1è¥¹Ù•ÍÑ¥…Ñ”%1}1}]I%Q}Q!I=U Ý¡•¸ÀÔÀ€ø€ÕµÌ½ÈÀää€ø€ÔÁµÌ¸ˆ°(€€€€€€€€€€€%QIL°(€€€€€€€€€€€I5}	eQL°(€€€€€€€€€€€ÀÔÁ}„…Ì˜ØÐ€¼€Å|ÀÀÁ|ÀÀÀ¸À°(€€€€€€€€€€€ÀäÕ}„…Ì˜ØÐ€¼€Å|ÀÀÁ|ÀÀÀ¸À°(€€€€€€€€€€€Àäå}„…Ì˜ØÐ€¼€Å|ÀÀÁ|ÀÀÀ¸À°(€€€€€€€€€€€ÀÔÁ}ˆ…Ì˜ØÐ€¼€Å|ÀÀÁ|ÀÀÀ¸À°(€€€€€€€€€€€ÀäÕ}ˆ…Ì˜ØÐ€¼€Å|ÀÀÁ|ÀÀÀ¸À°(€€€€€€€€€€€Àäå}ˆ…Ì˜ØÐ€¼€Å|ÀÀÁ|ÀÀÀ¸À°(€€€€€€€€¤ì((€€€€€€€€¼¼I•É•ÍÍ¥½¸Õ…É‘Ìè•¹•É½ÕÌ€ÈµÍ•½¹Àää•¥±¥¹œ½¸…¹ä]¥¹‘½ÝÌÍÑ½É…”¸(€€€€€€€€¼¼Y…±Õ•Ì…‰½Ù”Ñ¡¥Ì¥¹‘¥…Ñ”„ÍÑ½É…”…¹½µ…±äƒŠP¡•¬M5IP€¼9Y5”±½Ì¸(€€€€€€€½¹ÍÐ@äå}%1%9}9LèÔØÐ€ô€É|ÀÀÀ€¨€Å|ÀÀÁ|ÀÀÀì(€€€€€€€…ÍÍ•ÉÐ„ (€€€€€€€€€€€Àäå}„€ð@äå}%1%9}9L°(€€€€€€€€€€€€‰´ÄÈ±ÕÍ¡¥±•	Õ™™•ÉÌÀääìè¸ÅõµÌ€ø€ÈÀÀÁµÌƒŠPÍÑ½É…”…¹½µ…±äˆ°(€€€€€€€€€€€Àäå}„…Ì˜ØÐ€¼€Å|ÀÀÁ|ÀÀÀ¸À(€€€€€€€€¤ì(€€€€€€€…ÍÍ•ÉÐ„ (€€€€€€€€€€€Àäå}ˆ€ð@äå}%1%9}9L°(€€€€€€€€€€€€‰Íå¹}‘…Ñ„Àääìè¸ÅõµÌ€ø€ÈÀÀÁµÌƒŠPÍÑ½É…”…¹½µ…±äˆ°(€€€€€€€€€€€Àäå}ˆ…Ì˜ØÐ€¼€Å|ÀÀÁ|ÀÀÀ¸À(€€€€€€€€¤ì(€€€ô)ô(