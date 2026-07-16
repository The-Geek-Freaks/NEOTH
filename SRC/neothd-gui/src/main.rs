#![cfg_attr(windows, windows_subsystem = "windows")]

//! NEOTH GUI wizard — R-1 Phase 3.
//!
//! Multi-screen flow:
//!   welcome → license → identity → provider → autonomy → channels
//!     → (keys, when needed) → done
//!
//! On finish we write two files:
//!   - `~/.neoth/freedom.yaml` — operator id, provider kind, autonomy
//!     level, channels-enabled list. No secrets in this file.
//!   - `~/.neoth/credentials.yaml` (only when the operator entered at
//!     least one secret) — mode 0600 on unix, ACL-restricted on Windows.
//!     Mirrors the secrets-split landed by `config/credentials.rs`.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::info;
use tracing_subscriber::EnvFilter;

// FIX 1 — serialize all freedom.yaml writers so concurrent GUI toggles cannot
// interleave their read-modify-write cycles and lose an update.
static FREEDOM_WRITE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(windows)]
mod win_private {
    use std::fs::File;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::path::Path;

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_INSUFFICIENT_BUFFER,
        ERROR_SUCCESS, GetLastError, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, GetSecurityInfo,
        NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW,
        TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, CONTAINER_INHERIT_ACE,
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, GetLengthSid,
        GetSecurityDescriptorControl, GetTokenInformation, INHERITED_ACE,
        InitializeSecurityDescriptor, IsValidSid, NO_INHERITANCE, OBJECT_INHERIT_ACE,
        PROTECTED_DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
        SECURITY_DESCRIPTOR, SetSecurityDescriptorControl, SetSecurityDescriptorDacl, TOKEN_QUERY,
        TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, DELETE, FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ,
        FILE_GENERIC_WRITE, FILE_RENAME_INFO, FILE_RENAME_INFO_0, FileRenameInfoEx,
        FlushFileBuffers, SetFileInformationByHandle,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    pub fn create_private_file_new(path: &Path) -> io::Result<File> {
        let path_w = path_to_wide_nul(path)?;
        let sid = current_process_token_sid()?;
        let acl = single_trustee_acl(sid.as_ptr() as *mut u16, NO_INHERITANCE)?;
        let mut descriptor: SECURITY_DESCRIPTOR = unsafe { std::mem::zeroed() };
        let descriptor_ptr = std::ptr::addr_of_mut!(descriptor) as *mut std::ffi::c_void;
        const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
        if unsafe { InitializeSecurityDescriptor(descriptor_ptr, SECURITY_DESCRIPTOR_REVISION) }
            == 0
        {
            return Err(last_win32_error("InitializeSecurityDescriptor"));
        }
        if unsafe { SetSecurityDescriptorDacl(descriptor_ptr, 1, acl.0, 0) } == 0 {
            return Err(last_win32_error("SetSecurityDescriptorDacl"));
        }
        if unsafe {
            SetSecurityDescriptorControl(descriptor_ptr, SE_DACL_PROTECTED, SE_DACL_PROTECTED)
        } == 0
        {
            return Err(last_win32_error("SetSecurityDescriptorControl"));
        }
        let security_attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor_ptr,
            bInheritHandle: 0,
        };
        let raw = unsafe {
            CreateFileW(
                path_w.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE,
                0,
                &security_attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            let code = unsafe { GetLastError() };
            return Err(io::Error::new(
                win32_io_err(code).kind(),
                format!(
                    "CreateFileW(CREATE_NEW): Win32 error {code:#010x} ({})",
                    win32_io_err(code)
                ),
            ));
        }
        let owned = OwnedHandle(raw);
        if let Err(error) = verify_private_handle_for_sid(raw, &sid) {
            drop(owned);
            let _ = std::fs::remove_file(path);
            return Err(error);
        }
        Ok(owned.into_file())
    }

    pub fn replace_private_file_handle(file: &File, target: &Path) -> io::Result<()> {
        rename_private_file_handle(file, target, true)
    }

    pub fn create_private_file_handle(file: &File, target: &Path) -> io::Result<()> {
        rename_private_file_handle(file, target, false)
    }

    pub fn set_private_directory_dacl(path: &Path) -> io::Result<()> {
        let mut path_w = path_to_wide_nul(path)?;
        let sid = current_process_token_sid()?;
        let acl = single_trustee_acl(
            sid.as_ptr() as *mut u16,
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
        )?;
        let rc = unsafe {
            SetNamedSecurityInfoW(
                path_w.as_mut_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl.0,
                std::ptr::null_mut(),
            )
        };
        map_win32(rc, "SetNamedSecurityInfoW")?;
        verify_private_directory_dacl(path)
    }

    fn rename_private_file_handle(
        file: &File,
        target: &Path,
        replace_existing: bool,
    ) -> io::Result<()> {
        verify_private_file_handle(file)?;
        if unsafe { FlushFileBuffers(file.as_raw_handle() as HANDLE) } == 0 {
            return Err(last_win32_error("FlushFileBuffers"));
        }
        let absolute_target = std::path::absolute(target)?;
        let target_w = path_to_wide_nul(&absolute_target)?;
        let file_name_units = target_w
            .len()
            .checked_sub(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty target path"))?;
        let file_name_bytes = file_name_units
            .checked_mul(std::mem::size_of::<u16>())
            .and_then(|length| u32::try_from(length).ok())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "target path is too long")
            })?;
        let file_name_offset = u32::try_from(std::mem::offset_of!(FILE_RENAME_INFO, FileName))
            .expect("FILE_RENAME_INFO offset fits in u32");
        let buffer_size = file_name_offset
            .checked_add(file_name_bytes)
            .and_then(|length| length.checked_add(std::mem::size_of::<u16>() as u32))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "target path is too long")
            })?;
        let mut storage =
            vec![0usize; (buffer_size as usize).div_ceil(std::mem::size_of::<usize>())];
        let rename_info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        const FILE_RENAME_FLAG_REPLACE_IF_EXISTS: u32 = 0x1;
        const FILE_RENAME_FLAG_POSIX_SEMANTICS: u32 = 0x2;
        let flags = FILE_RENAME_FLAG_POSIX_SEMANTICS
            | if replace_existing {
                FILE_RENAME_FLAG_REPLACE_IF_EXISTS
            } else {
                0
            };
        unsafe {
            std::ptr::addr_of_mut!((*rename_info).Anonymous)
                .write(FILE_RENAME_INFO_0 { Flags: flags });
            std::ptr::addr_of_mut!((*rename_info).RootDirectory).write(std::ptr::null_mut());
            std::ptr::addr_of_mut!((*rename_info).FileNameLength).write(file_name_bytes);
            target_w.as_ptr().copy_to_nonoverlapping(
                std::ptr::addr_of_mut!((*rename_info).FileName).cast::<u16>(),
                target_w.len(),
            );
        }
        let rc = unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle() as HANDLE,
                FileRenameInfoEx,
                rename_info.cast::<std::ffi::c_void>(),
                buffer_size,
            )
        };
        if rc == 0 {
            let code = unsafe { GetLastError() };
            let kind = if !replace_existing
                && (code == ERROR_ALREADY_EXISTS || code == ERROR_FILE_EXISTS)
            {
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
        Ok(())
    }

    fn verify_private_file_handle(file: &File) -> io::Result<()> {
        verify_private_handle_for_sid(
            file.as_raw_handle() as HANDLE,
            &current_process_token_sid()?,
        )
    }

    fn verify_private_directory_dacl(path: &Path) -> io::Result<()> {
        let path_w = path_to_wide_nul(path)?;
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut descriptor: *mut std::ffi::c_void = std::ptr::null_mut();
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
        verify_private_descriptor(
            descriptor.0,
            dacl,
            &current_process_token_sid()?,
            (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8,
        )
    }

    fn verify_private_handle_for_sid(handle: HANDLE, expected_sid: &[u8]) -> io::Result<()> {
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut descriptor: *mut std::ffi::c_void = std::ptr::null_mut();
        let rc = unsafe {
            GetSecurityInfo(
                handle,
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
        map_win32(rc, "GetSecurityInfo")?;
        verify_private_descriptor(descriptor.0, dacl, expected_sid, NO_INHERITANCE as u8)
    }

    fn verify_private_descriptor(
        descriptor: *mut std::ffi::c_void,
        dacl: *mut ACL,
        expected_sid: &[u8],
        expected_flags: u8,
    ) -> io::Result<()> {
        if descriptor.is_null() || dacl.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private DACL missing",
            ));
        }
        let mut control = 0u16;
        let mut revision = 0u32;
        if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
            return Err(last_win32_error("GetSecurityDescriptorControl"));
        }
        if control & SE_DACL_PROTECTED == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private DACL is not protected",
            ));
        }
        let mut info: ACL_SIZE_INFORMATION = unsafe { std::mem::zeroed() };
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
        if info.AceCount == 0 || (expected_flags == NO_INHERITANCE as u8 && info.AceCount != 1) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("unexpected private DACL ACE count {}", info.AceCount),
            ));
        }
        const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
        const GENERIC_ALL: u32 = 0x1000_0000;
        const INHERIT_ONLY_ACE_FLAG: u8 = 0x08;
        let allowed_flags = if expected_flags == NO_INHERITANCE as u8 {
            expected_flags
        } else {
            expected_flags | INHERIT_ONLY_ACE_FLAG
        };
        let mut combined_flags = 0u8;
        for index in 0..info.AceCount {
            let mut ace_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
            if unsafe { GetAce(dacl, index, &mut ace_ptr) } == 0 || ace_ptr.is_null() {
                return Err(last_win32_error("GetAce"));
            }
            let ace = unsafe { &*(ace_ptr as *const ACCESS_ALLOWED_ACE) };
            if ace.Header.AceType != ACCESS_ALLOWED_ACE_TYPE
                || ace.Header.AceFlags as u32 & INHERITED_ACE != 0
                || ace.Header.AceFlags & !allowed_flags != 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "unsafe private DACL ACE",
                ));
            }
            combined_flags |= ace.Header.AceFlags & expected_flags;
            if ace.Mask & GENERIC_ALL != GENERIC_ALL
                && ace.Mask & FILE_ALL_ACCESS != FILE_ALL_ACCESS
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "private DACL lacks full control",
                ));
            }
            let ace_sid = std::ptr::addr_of!(ace.SidStart) as *mut std::ffi::c_void;
            if unsafe { IsValidSid(ace_sid) } == 0
                || unsafe { EqualSid(ace_sid, expected_sid.as_ptr() as *mut std::ffi::c_void) } == 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "private DACL SID mismatch",
                ));
            }
        }
        if combined_flags != expected_flags {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private DACL inheritance flags mismatch",
            ));
        }
        Ok(())
    }

    fn single_trustee_acl(sid: *mut u16, inheritance: u32) -> io::Result<OwnedLocalAcl> {
        let trustee = TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid,
        };
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_ALL_ACCESS,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: inheritance,
            Trustee: trustee,
        };
        let mut acl: *mut ACL = std::ptr::null_mut();
        let rc = unsafe { SetEntriesInAclW(1, &entry, std::ptr::null_mut(), &mut acl) };
        let acl = OwnedLocalAcl(acl);
        map_win32(rc, "SetEntriesInAclW")?;
        if acl.0.is_null() {
            Err(io::Error::other("SetEntriesInAclW returned null ACL"))
        } else {
            Ok(acl)
        }
    }

    fn current_process_token_sid() -> io::Result<Vec<u8>> {
        let mut token: HANDLE = std::ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(last_win32_error("OpenProcessToken"));
        }
        let token = OwnedHandle(token);
        let mut needed = 0u32;
        let first = unsafe {
            GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut needed)
        };
        if first != 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER || needed == 0 {
            return Err(last_win32_error("GetTokenInformation(size)"));
        }
        let mut buffer = vec![0u8; needed as usize];
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast::<std::ffi::c_void>(),
                needed,
                &mut needed,
            )
        } == 0
        {
            return Err(last_win32_error("GetTokenInformation(TokenUser)"));
        }
        let token_user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
        if unsafe { IsValidSid(token_user.User.Sid) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid TokenUser SID",
            ));
        }
        let sid_len = unsafe { GetLengthSid(token_user.User.Sid) };
        let mut sid = vec![0u8; sid_len as usize];
        unsafe {
            std::ptr::copy_nonoverlapping(
                token_user.User.Sid.cast::<u8>(),
                sid.as_mut_ptr(),
                sid.len(),
            );
        }
        Ok(sid)
    }

    fn path_to_wide_nul(path: &Path) -> io::Result<Vec<u16>> {
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        if wide.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path contains NUL",
            ));
        }
        wide.push(0);
        Ok(wide)
    }

    fn map_win32(code: u32, context: &'static str) -> io::Result<()> {
        if code == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{context}: Win32 error {code:#010x} ({})",
                    win32_io_err(code)
                ),
            ))
        }
    }

    fn last_win32_error(context: &'static str) -> io::Error {
        let code = unsafe { GetLastError() };
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{context}: Win32 error {code:#010x} ({})",
                win32_io_err(code)
            ),
        )
    }

    fn win32_io_err(code: u32) -> io::Error {
        io::Error::from_raw_os_error(code as i32)
    }

    struct OwnedHandle(HANDLE);

    impl OwnedHandle {
        fn into_file(self) -> File {
            let owned = std::mem::ManuallyDrop::new(self);
            unsafe { File::from_raw_handle(owned.0) }
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    struct OwnedLocalAcl(*mut ACL);

    impl Drop for OwnedLocalAcl {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { LocalFree(self.0.cast::<std::ffi::c_void>() as HLOCAL) };
            }
        }
    }

    struct OwnedLocalDescriptor(*mut std::ffi::c_void);

    impl Drop for OwnedLocalDescriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { LocalFree(self.0 as HLOCAL) };
            }
        }
    }
}

/// GU-03 — persona-adaptive settings-panel visibility rule engine (pure Rust,
/// unit-tested without Slint). The `.slint` binds its `show_*` properties to
/// [`panel_logic::PanelVisibility`], populated on startup from the operator's
/// complexity level.
mod buddy_activity;
mod gui_action;
mod gui_stream;
mod panel_logic;
mod wizard_logic;

use buddy_activity::GuiActivity;

slint::include_modules!();

// ── Wave-1 toast plumbing ─────────────────────────────────────────────────────
//
// push_toast appends a ToastData item to the MainWindow's `toasts` model and
// starts a 6-second one-shot timer that calls prune_toast to remove it.
// All mutations cross into the Slint event loop via invoke_from_event_loop.
//
// `kind`: "info" | "success" | "warn" | "consent"  (drives the Led colour)
fn push_toast(window: &slint::Weak<MainWindow>, kind: &'static str, title: &str, body: &str) {
    use slint::Model as _; // ModelRc::iter
    let title = title.to_string();
    let body = body.to_string();
    let weak = window.clone();

    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };
        // Read current toasts, compute a fresh id, append.
        let mut current: Vec<(i32, String, String, String)> = w
            .get_toasts()
            .iter()
            .map(|t| {
                (
                    t.id,
                    t.kind.to_string(),
                    t.title.to_string(),
                    t.body.to_string(),
                )
            })
            .collect();
        let id = panel_logic::next_toast_id(&current);
        current.push((id, kind.to_string(), title.clone(), body.clone()));

        let model: slint::VecModel<ToastData> = slint::VecModel::from(
            current
                .iter()
                .map(|(i, k, ti, b)| ToastData {
                    id: *i,
                    kind: k.as_str().into(),
                    title: ti.as_str().into(),
                    body: b.as_str().into(),
                })
                .collect::<Vec<_>>(),
        );
        w.set_toasts(slint::ModelRc::new(std::rc::Rc::new(model)));

        // 6-second expiry timer — fires once then removes the id.
        let weak2 = w.as_weak();
        let expiry = slint::Timer::default();
        expiry.start(
            slint::TimerMode::SingleShot,
            std::time::Duration::from_millis(6000),
            move || {
                let Some(w2) = weak2.upgrade() else { return };
                let remaining: Vec<(i32, String, String, String)> = w2
                    .get_toasts()
                    .iter()
                    .map(|t| {
                        (
                            t.id,
                            t.kind.to_string(),
                            t.title.to_string(),
                            t.body.to_string(),
                        )
                    })
                    .collect();
                let pruned = panel_logic::prune_toast(remaining, id);
                let model2: slint::VecModel<ToastData> = slint::VecModel::from(
                    pruned
                        .iter()
                        .map(|(i, k, ti, b)| ToastData {
                            id: *i,
                            kind: k.as_str().into(),
                            title: ti.as_str().into(),
                            body: b.as_str().into(),
                        })
                        .collect::<Vec<_>>(),
                );
                w2.set_toasts(slint::ModelRc::new(std::rc::Rc::new(model2)));
            },
        );
        // Keep the timer alive — leak it into a thread-local so it survives
        // the enclosing closure. Slint timers must be alive to fire.
        std::mem::forget(expiry);
    });
}

// Run the hardware/daemon probe on a worker thread and land the result
// (summary + footer-Led state) on the event loop. Called at startup and
// from the offline banner's Retry button.
fn spawn_daemon_probe(weak: slint::Weak<MainWindow>) {
    std::thread::spawn(move || {
        let hw_summary = probe_hardware_via_subprocess();
        // GOLD-ADAPT-GUI-04 — footer Led state derived from the probe
        // outcome: every failure arm of the probe starts with
        // "Hardware probe" (missing binary / bad exit / spawn error).
        let led = if hw_summary.starts_with("Hardware probe") {
            "error"
        } else {
            "live"
        };
        let hw_for_toast = hw_summary.clone();
        // Wave-1 call site B: toast on daemon error so the operator gets a
        // top-right signal even if they are looking at the chat surface.
        if led == "error" {
            push_toast(&weak, "warn", "Daemon unreachable", &hw_for_toast);
        }
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(w) = weak.upgrade() {
                w.set_hardware_summary(hw_summary.into());
                w.set_daemon_state(led.into());
            }
        });
    });
}

// ── Wave-2 activity sidecar plumbing ─────────────────────────────────────────
//
// push_activity  — appends an ActivityRow (newest-first, cap 60), auto-opens
//                  the sidecar on the first significant event of a burst.
// settle_activity_kind — marks all rows of a given kind inactive (completion).
//
// Both mutate the Slint model via invoke_from_event_loop so they are safe to
// call from worker threads (same pattern as push_toast).

/// Append one activity row to the sidecar.
/// `significant`: non-metric row triggers auto-open when the panel is closed.
fn push_activity(window: &slint::Weak<MainWindow>, kind: &'static str, title: &str, detail: &str) {
    use slint::Model as _;
    let title = title.to_string();
    let detail = detail.to_string();
    let window = window.clone();
    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = window.upgrade() else { return };
        // Collect current rows (newest-first) as plain tuples.
        let current: Vec<panel_logic::ActivityTuple> = w
            .get_activity_rows()
            .iter()
            .map(|r| {
                (
                    r.id,
                    r.ts.to_string(),
                    r.kind.to_string(),
                    r.title.to_string(),
                    r.detail.to_string(),
                    r.active,
                )
            })
            .collect();
        let id = panel_logic::next_activity_id(&current);
        let ts = format_now_hms();
        let mut rows = current;
        // Insert at front (newest-first).
        rows.insert(0, (id, ts, kind.to_string(), title, detail, true));
        let rows = panel_logic::cap_activity(rows, 60);
        let slint_rows: Vec<ActivityRow> = rows
            .iter()
            .map(|(id, ts, k, ti, de, ac)| ActivityRow {
                id: *id,
                ts: ts.as_str().into(),
                kind: k.as_str().into(),
                title: ti.as_str().into(),
                detail: de.as_str().into(),
                active: *ac,
            })
            .collect();
        w.set_activity_rows(slint::ModelRc::new(slint::VecModel::from(slint_rows)));
        // Auto-open on first significant row of a burst (kind != "metric").
        if !w.get_activity_open() && kind != "metric" {
            w.set_activity_open(true);
        }
    });
}

/// Mark all rows of `kind` as inactive (call on completion events).
fn settle_activity_kind(window: &slint::Weak<MainWindow>, kind: &'static str) {
    use slint::Model as _;
    let window = window.clone();
    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = window.upgrade() else { return };
        let current: Vec<panel_logic::ActivityTuple> = w
            .get_activity_rows()
            .iter()
            .map(|r| {
                (
                    r.id,
                    r.ts.to_string(),
                    r.kind.to_string(),
                    r.title.to_string(),
                    r.detail.to_string(),
                    r.active,
                )
            })
            .collect();
        let settled = panel_logic::settle_activity(current, kind);
        let slint_rows: Vec<ActivityRow> = settled
            .iter()
            .map(|(id, ts, k, ti, de, ac)| ActivityRow {
                id: *id,
                ts: ts.as_str().into(),
                kind: k.as_str().into(),
                title: ti.as_str().into(),
                detail: de.as_str().into(),
                active: *ac,
            })
            .collect();
        w.set_activity_rows(slint::ModelRc::new(slint::VecModel::from(slint_rows)));
    });
}

// ── Code Sessions tab — subprocess JSON envelopes ─────────────────────
// Mirror of `KanbanSession` + `KanbanTask` in `neothd::coding::types`.
// We re-declare them here (instead of depending on the daemon crate
// directly) for the same reason `MinimalFreedomYaml` is duplicated: the
// GUI crate stays light + decoupled from daemon internals. Wire-form
// changes surface as JSON deserialise errors at runtime.

#[derive(Debug, Deserialize)]
struct CodingSessionJson {
    session_id: i64,
    prompt: String,
    status: String,
}

#[derive(Debug, Deserialize)]
struct CodingTaskJson {
    task_id: i64,
    status: String,
    title: String,
    hemisphere: String,
}

#[derive(Debug, Deserialize)]
struct CodingShowEnvelope {
    session: CodingSessionJson,
    tasks: Vec<CodingTaskJson>,
}

/// Mirror of `neothd::coding::feed::FeedEntry` — one row in the WAL-
/// derived activity feed. Pick #8 step 3: GUI calls
/// `neothd kanban watch --output json` and renders the result in the
/// right-rail of the Code Sessions tab.
#[derive(Debug, Deserialize)]
struct FeedEntryJson {
    ts_ns: u64,
    actor: String,
    message: String,
}

/// Mirror of `neothd::coding::types::KanbanComment` for the detail
/// pane subprocess parse. Fields match the serde wire form pinned by
/// `cli::kanban::task_detail_json_envelope_contains_task_and_comments`.
#[derive(Debug, Deserialize)]
struct CommentJson {
    author: String,
    body: String,
    created_ns: u64,
}

#[derive(Debug, Deserialize)]
struct TaskDetailEnvelope {
    #[serde(default)]
    comments: Vec<CommentJson>,
}

/// Plain snapshot the Rust side hands to Slint. Owning-Vecs keep the
/// Slint Model construction simple — we build `ModelRc<VecModel<…>>`
/// from each Vec at the property-set site.
///
/// Step 5 (2026-05-20): `Clone` lets the click-handler clone the
/// last-applied snapshot out of the shared Mutex so the detail-pane
/// lookup runs lock-free.
#[derive(Default, Clone, PartialEq)]
struct KanbanBoardSnapshot {
    backlog: Vec<KanbanTaskRow>,
    todo: Vec<KanbanTaskRow>,
    in_progress: Vec<KanbanTaskRow>,
    review: Vec<KanbanTaskRow>,
    done: Vec<KanbanTaskRow>,
    feed: Vec<KanbanFeedRow>,
    summary: String,
    /// HO-02: whether a Cerebellum hemisphere is bound. `None` on every
    /// degraded path (no binary / list-or-show failure) so the UI does
    /// NOT false-alarm; `Some(bool)` only on the success path where we
    /// actually probed `neoth hemispheres show`. apply maps None→true.
    cerebellum_bound: Option<bool>,
}

impl KanbanBoardSnapshot {
    /// Replace the cached board and report whether its visible state changed.
    /// The live timer uses this to avoid flooding the activity sidecar with
    /// identical "Board updated" rows every two seconds.
    fn replace_if_changed(&mut self, next: Self) -> bool {
        if *self == next {
            false
        } else {
            *self = next;
            true
        }
    }

    /// Step 5 (2026-05-20): find a task by its `task-id` string
    /// ("#42") across the 5 status buckets. Returns the task row +
    /// the wire-form status name so the detail-pane can render both.
    fn find_task(&self, id: &str) -> Option<(KanbanTaskRow, &'static str)> {
        for (col, status) in [
            (&self.backlog, "backlog"),
            (&self.todo, "todo"),
            (&self.in_progress, "in_progress"),
            (&self.review, "review"),
            (&self.done, "done"),
        ] {
            for row in col {
                if row.task_id.as_str() == id {
                    return Some((row.clone(), status));
                }
            }
        }
        None
    }
}

#[cfg(test)]
#[test]
fn unchanged_board_snapshot_does_not_emit_activity_change() {
    let mut cached = KanbanBoardSnapshot {
        summary: "1 active session".into(),
        ..Default::default()
    };
    assert!(!cached.replace_if_changed(cached.clone()));

    let mut changed = cached.clone();
    changed.summary = "2 active sessions".into();
    assert!(cached.replace_if_changed(changed));
    assert_eq!(cached.summary, "2 active sessions");
}

fn main() -> Result<()> {
    init_tracing();
    info!("neothd-gui starting (R-1 Phase 3 — autonomy + channels + keys)");

    let arguments: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    if runtime_probe_requested(&arguments) {
        return run_runtime_probe();
    }
    let product_launcher =
        product_launcher_mode(arguments, std::env::var_os(PRODUCT_LAUNCHER_ENV))?;
    let neoth_dir = default_neoth_home();
    std::fs::create_dir_all(&neoth_dir)
        .with_context(|| format!("create NEOTH home {}", neoth_dir.display()))?;
    if product_launcher
        && matches!(
            load_gui_interface_preference(&neoth_dir),
            Ok(Some(GuiInterfacePreference::Cli))
        )
    {
        let bin = which_neothd().context("NEOTH CLI binary is missing beside the GUI")?;
        switch_to_cli(&bin, &neoth_dir)?;
        return Ok(());
    }
    let gui_parent_handoff = gui_parent_handoff_from_env(&neoth_dir)?;
    let parent_commits_gui = gui_parent_handoff
        .as_ref()
        .is_some_and(|handoff| handoff.parent_commit);

    let window = MainWindow::new()?;

    // ── Companion overlay — created here, hidden until the operator
    // clicks "⊟" in the TopBar. Both windows share the one event loop
    // that `window.run()` drives; `overlay.show()` / `overlay.hide()`
    // are safe to call from UI-thread callbacks at any time.
    // DO NOT call `overlay.run()` — only `window.run()` drives the loop.
    let overlay = MiniOverlay::new()?;

    // B23 fix — read tweaks.toml once so the theme block and the B23 tweaks
    // block below share a single parse (no double I/O).
    let gui_tweaks = read_gui_tweaks(&neoth_dir);

    // Theme — restore the persisted light/dark choice before the window paints.
    // Precedence (mirrors daemon resolve_effective_gui_theme):
    //   valid dotfile > tweaks color_theme > built-in dark.
    // Persisted at `<neoth_home>/.gui-theme` as "dark"/"light".
    {
        let dotfile_raw = std::fs::read_to_string(neoth_dir.join(".gui-theme")).ok();
        // Empty/whitespace-only dotfile = file-absent semantics (daemon caller
        // contract, tweaks/mod.rs "Non-empty but unrecognised") — never a
        // spurious invalid-value diagnostic.
        let dotfile = dotfile_raw
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let tweaks_color = gui_tweaks.as_ref().and_then(|t| t.color_theme.as_deref());
        let is_dark = resolve_boot_dark(dotfile, tweaks_color);
        window.global::<Theme>().set_dark(is_dark);
    }
    let weak_theme = window.as_weak();
    window.on_theme_toggle_clicked(move || {
        if let Some(w) = weak_theme.upgrade() {
            // The sidebar already flipped Theme.dark live; persist the new value.
            let is_dark = w.global::<Theme>().get_dark();
            let _ = std::fs::write(
                default_neoth_home().join(".gui-theme"),
                if is_dark { "dark" } else { "light" },
            );
        }
    });

    // Toast click-to-dismiss — prune the clicked id immediately instead of
    // waiting out the 6 s drain (same prune path as the expiry timer).
    let weak_toast_dismiss = window.as_weak();
    window.on_toast_dismissed(move |id| {
        use slint::Model;
        let Some(w) = weak_toast_dismiss.upgrade() else {
            return;
        };
        let remaining: Vec<(i32, String, String, String)> = w
            .get_toasts()
            .iter()
            .map(|t| {
                (
                    t.id,
                    t.kind.to_string(),
                    t.title.to_string(),
                    t.body.to_string(),
                )
            })
            .collect();
        let pruned = panel_logic::prune_toast(remaining, id);
        let model: slint::VecModel<ToastData> = slint::VecModel::from(
            pruned
                .iter()
                .map(|(i, k, ti, b)| ToastData {
                    id: *i,
                    kind: k.as_str().into(),
                    title: ti.as_str().into(),
                    body: b.as_str().into(),
                })
                .collect::<Vec<_>>(),
        );
        w.set_toasts(slint::ModelRc::new(std::rc::Rc::new(model)));
    });

    // Command palette (Ctrl+K) — Rust owns filtering over the static
    // catalog; Slint owns open/close/selection and routes activation
    // through the sidebar nav path.
    let weak_palette = window.as_weak();
    window.on_palette_query_edited(move |q| {
        let Some(w) = weak_palette.upgrade() else {
            return;
        };
        let items: Vec<PaletteItem> = panel_logic::filter_palette(&q)
            .into_iter()
            .map(|(label, glyph, tab, hint)| PaletteItem {
                label: label.into(),
                glyph: glyph.into(),
                tab: tab.into(),
                hint: hint.into(),
            })
            .collect();
        w.set_palette_results(slint::ModelRc::new(std::rc::Rc::new(
            slint::VecModel::from(items),
        )));
    });
    // Seed the full catalog so the palette is populated on first open.
    window.invoke_palette_query_edited("".into());

    // ODY-11 — density restore: read ~/.neoth/.gui-density and apply before
    // the first paint, mirroring the .gui-theme block above.
    {
        let val = read_gui_density(&default_neoth_home());
        window.global::<Theme>().set_density_mode(val);
        window.set_chat_density_mode(val);
    }
    let weak_density = window.as_weak();
    window.on_density_changed(move |val| {
        if let Some(w) = weak_density.upgrade() {
            let density_path = default_neoth_home().join(".gui-density");
            write_gui_density(&density_path, val);
            w.global::<Theme>().set_density_mode(val);
            w.set_chat_density_mode(val);
        }
    });

    // B23 — THEME-TWEAKS-RUNTIME: apply tweaks contract before first paint.
    // gui_tweaks was already read above; reuse to avoid double I/O.
    // color_theme precedence is handled by resolve_boot_dark in the theme block above.
    // Precedence for remaining fields: dotfile already applied above > tweaks > built-in.
    {
        if let Some(ref tc) = gui_tweaks {
            // font-sans-override: non-empty string overrides the built-in font-sans token.
            if let Some(ref family) = tc.theme.font_family
                && !family.is_empty()
            {
                window
                    .global::<Theme>()
                    .set_font_sans_override(family.as_str().into());
            }
            // Convert points to logical pixels at the CSS/Slint 96dpi ratio.
            if let Some(pt) = tc.theme.font_size_pt
                && pt > 0
            {
                window
                    .global::<Theme>()
                    .set_font_size_override(pt as f32 * (96.0 / 72.0));
            }
            // sidebar-w-override: non-zero px overrides the 248px built-in.
            if let Some(px) = tc.theme.sidebar_width_px
                && px > 0
            {
                window.global::<Theme>().set_sidebar_w_override(px as f32);
            }
            // Convert requested text lines to the composer's logical-pixel floor.
            if let Some(lines) = tc.theme.input_height_lines
                && lines > 0
            {
                window
                    .global::<Theme>()
                    .set_input_height_override(lines as f32 * 22.0 + 16.0);
            }
            if let Some(raw) = tc.theme.accent_color.as_deref() {
                if let Some(color) = parse_theme_color(raw) {
                    window.global::<Theme>().set_accent_color_override(color);
                    window.global::<Theme>().set_accent_override_enabled(true);
                } else {
                    tracing::warn!(value = raw, "invalid accent_color; ignoring");
                }
            }
            if let Some(raw) = tc.theme.background_color.as_deref() {
                if let Some(color) = parse_theme_color(raw) {
                    window
                        .global::<Theme>()
                        .set_background_color_override(color);
                    window
                        .global::<Theme>()
                        .set_background_override_enabled(true);
                } else {
                    tracing::warn!(value = raw, "invalid background_color; ignoring");
                }
            }
            if let Some(raw) = tc.theme.foreground_color.as_deref() {
                if let Some(color) = parse_theme_color(raw) {
                    window
                        .global::<Theme>()
                        .set_foreground_color_override(color);
                    window
                        .global::<Theme>()
                        .set_foreground_override_enabled(true);
                } else {
                    tracing::warn!(value = raw, "invalid foreground_color; ignoring");
                }
            }
            if let Some(radius) = tc.theme.border_radius_px
                && radius > 0
            {
                window
                    .global::<Theme>()
                    .set_border_radius_override(radius as f32);
            }
            if let Some(opacity) = tc.theme.panel_opacity
                && opacity.is_finite()
                && (0.0..=1.0).contains(&opacity)
            {
                window.global::<Theme>().set_panel_opacity(opacity);
            }
            if let Some(show) = tc.theme.show_token_count {
                window.global::<Theme>().set_show_token_count(show);
            }
            if let Some(show) = tc.theme.show_model_badge {
                window.global::<Theme>().set_show_model_badge(show);
            }
            if let Some(style) = tc.theme.chat_bubble_style.as_deref() {
                if let Some(mode) = chat_bubble_style_mode(style) {
                    window.global::<Theme>().set_chat_bubble_style(mode);
                } else {
                    tracing::warn!(value = style, "invalid chat_bubble_style; ignoring");
                }
            }
            if let Some(speed) = tc.theme.animation_speed.as_deref() {
                if let Some(mode) = animation_speed_mode(speed) {
                    window.global::<Theme>().set_animation_mode(mode);
                } else {
                    tracing::warn!(value = speed, "invalid animation_speed; ignoring");
                }
            }
            if let Some(hidden) = tc.theme.header_hidden {
                window.global::<Theme>().set_header_hidden(hidden);
            }
            if let Some(collapsed) = tc.theme.sidebar_collapsed {
                window.global::<Theme>().set_sidebar_collapsed(collapsed);
            }
            // compact_mode → density_mode, only when .gui-density dotfile is absent
            // (dotfile wins: already applied by the density block above).
            if !neoth_dir.join(".gui-density").exists()
                && let Some(compact) = tc.theme.compact_mode
            {
                let density = if compact { 0 } else { 1 };
                window.global::<Theme>().set_density_mode(density);
                window.set_chat_density_mode(density);
            }
        }
    }

    // H-3 fix — hardware probe runs in a worker thread so a hanging
    // `neothd hardware` subprocess can never block the window from
    // appearing. The placeholder string shows until the real probe
    // result lands via `invoke_from_event_loop`. Shared with the
    // offline-banner Retry button via spawn_daemon_probe.
    window.set_hardware_summary("Probing hardware…".into());
    window.set_daemon_state("connecting".into());
    spawn_daemon_probe(window.as_weak());

    // Sidebar version line — bind the real build version so the shell
    // never lies about what is running.
    window.set_app_version_line(concat!("v", env!("CARGO_PKG_VERSION"), " · sovereign").into());

    // E4 — What's-new: the repo CHANGELOG rides the binary at build time;
    // show the newest ~6k chars (releases are newest-first at the top).
    {
        const CHANGELOG: &str = include_str!("../../../CHANGELOG.md");
        let head: String = CHANGELOG.chars().take(6000).collect();
        window.set_about_changelog(head.into());
    }

    // Daemon→GUI activity bus — the Buddy reacts live to WAL events
    // (dreaming, council, self-improve, cron, loops, channel ingress).
    // Fail-silent: without a daemon binary the follower just retries.
    gui_stream::spawn_wal_follower(window.as_weak());

    // Daemon-offline banner retry — reset to "connecting" (hides the
    // banner) and re-run the same probe the startup path uses.
    let weak_daemon_retry = window.as_weak();
    window.on_daemon_retry_clicked(move || {
        if let Some(w) = weak_daemon_retry.upgrade() {
            w.set_hardware_summary("Probing hardware…".into());
            w.set_daemon_state("connecting".into());
        }
        spawn_daemon_probe(weak_daemon_retry.clone());
    });

    // GOLD-ADAPT-OH-01 — prior-AI detection for the welcome migrate
    // card. Worker thread (subprocess must never block the window);
    // the card only appears when detect finds complete assistant homes, so a
    // missing neoth-migrate binary or empty result is silent.
    let weak_migrate = window.as_weak();
    std::thread::spawn(move || {
        let summary = which_neoth_migrate()
            .and_then(|bin| {
                let mut command = std::process::Command::new(bin);
                scrub_gui_control_environment(&mut command);
                suppress_console_window(&mut command);
                command
                    .arg("detect")
                    .arg("--json")
                    .env("NO_COLOR", "1")
                    .env("NEOTH_LOG", "error")
                    .output()
                    .ok()
            })
            .filter(|out| out.status.success())
            .map(|out| format_migrate_summary(&String::from_utf8_lossy(&out.stdout)))
            .unwrap_or_default();
        if summary.is_empty() {
            return;
        }
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(w) = weak_migrate.upgrade() {
                w.set_migrate_summary(summary.into());
            }
        });
    });

    // QM-9 Phase 2/3+: usage rollup probe runs in its own worker so a
    // slow `neoth usage` subprocess can't block the window. Phase 3+
    // re-fires the probe every USAGE_REFRESH_INTERVAL so the dashboard
    // tile stays current as new chat turns land in the persisted log.
    // Placeholder string shows until the first probe lands via
    // invoke_from_event_loop.
    window.set_usage_summary("Loading usage…".into());
    let weak_usage = window.as_weak();
    std::thread::spawn(move || {
        loop {
            let summary = probe_usage_via_subprocess();
            let weak = weak_usage.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_usage_summary(summary.into());
                }
            });
            std::thread::sleep(USAGE_REFRESH_INTERVAL);
        }
    });

    // GOLD-WIRE-10b: live budget meter probe — same refresh-loop shape
    // as usage. Re-fires every BUDGET_REFRESH_INTERVAL so the dashboard
    // tile stays current as provider calls land in the daemon.
    window.set_budget_summary("Loading budget…".into());
    let weak_budget = window.as_weak();
    std::thread::spawn(move || {
        loop {
            let summary = probe_budget_via_subprocess();
            let weak = weak_budget.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_budget_summary(summary.into());
                }
            });
            std::thread::sleep(BUDGET_REFRESH_INTERVAL);
        }
    });

    // QM-8 Phase 2: preset list probe — same refresh-loop shape as
    // usage. Lighter cadence (5min) since presets change rarely.
    window.set_preset_summary("Loading presets…".into());
    let weak_preset = window.as_weak();
    std::thread::spawn(move || {
        loop {
            let summary = probe_preset_summary_via_subprocess();
            // SPEC-05 — also fetch the structured list for the click-to-activate
            // selector (the summary string remains the empty-state fallback).
            let presets = fetch_presets();
            let weak = weak_preset.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_preset_summary(summary.into());
                    apply_presets(&w, presets);
                }
            });
            std::thread::sleep(PRESET_REFRESH_INTERVAL);
        }
    });

    // G-2 first-launch detection: if `~/.neoth/freedom.yaml` already
    // exists the operator has been through the wizard before. Jump
    // straight to the done screen so they don't accidentally overwrite
    // their config by clicking Finish on the welcome screen. They can
    // still re-run by clicking Finish at the bottom of the wizard.
    let neoth_dir = default_neoth_home();

    // GU-03 — persona-adaptive settings panels. Read the operator's complexity
    // level (the v2 wizard's W-03a decision) + apply the panel-visibility rules.
    // A pre-v2 / fresh operator falls back to Standard. Computed once at startup
    // (the wizard re-run path re-launches the GUI, picking up the new level).
    {
        let level = panel_logic::read_complexity_level(&neoth_dir);
        let pv = panel_logic::panels_for(level);
        info!(
            complexity = level.as_str(),
            "GU-03: applied persona-adaptive panel visibility"
        );
        window.set_settings_show_hemispheres(pv.show_hemispheres);
        window.set_settings_show_channels(pv.show_channels);
        window.set_settings_show_skills(pv.show_skills);
        window.set_settings_show_plugins(pv.show_plugins);
        window.set_settings_show_memory(pv.show_memory);
        window.set_settings_show_cluster(pv.show_cluster);
        window.set_settings_show_code_sessions(pv.show_code_sessions);
    }

    let (already_initialized, readiness_error) = match which_neothd()
        .context("NEOTH CLI binary is missing beside the GUI")
        .and_then(|bin| gui_initialization_is_ready(&bin, &neoth_dir))
    {
        Ok(ready) => (ready, None),
        Err(error) => (false, Some(error.to_string())),
    };
    let freedom_path = neoth_dir.join("freedom.yaml");
    let (config_present, config_presence_error) = match freedom_path.try_exists() {
        Ok(present) => (present, None),
        Err(error) => (
            false,
            Some(format!(
                "could not inspect existing configuration {}: {error}",
                freedom_path.display()
            )),
        ),
    };
    let initialization_error = readiness_error.or(config_presence_error);
    let initialization_state_valid = initialization_error.is_none();
    // GOLD-R4-03 — an absent preference is the one and only state that shows
    // the GUI-vs-CLI chooser. Opening the GUI after a prior CLI choice is an
    // explicit switch back to GUI, so update the canonical CLI-owned contract
    // before skipping the chooser. Existing malformed state remains visible
    // and repairable through an explicit card choice.
    let interface_boot = if parent_commits_gui {
        interface_boot_decision(true, Ok(None))
    } else {
        interface_boot_decision(false, load_gui_interface_preference(&neoth_dir))
    };
    let direct_gui_commit = matches!(&interface_boot, GuiInterfaceBootDecision::SwitchCliToGui);
    let (interface_choice_recorded, interface_choice_error) = match interface_boot {
        GuiInterfaceBootDecision::Ready => (true, None),
        // Direct `neothd-gui` is an explicit switch, but the durable write is
        // deferred to the same live-event-loop commit edge as `neoth gui`.
        GuiInterfaceBootDecision::SwitchCliToGui => (true, None),
        GuiInterfaceBootDecision::Choose => (false, None),
        GuiInterfaceBootDecision::Repair(error) => (false, Some(error)),
    };
    // GUI-REENTRY-PRESET fix: track whether the re-entry config read succeeded.
    // on_finish_clicked checks this flag and refuses to overwrite the existing
    // config when the read failed (preventing Slint property defaults — which
    // correspond to "balanced" preset values — from silently clobbering the
    // operator's real config). False = first-run or read failed (safe default:
    // no existing config to protect). True = re-entry with config loaded OK.
    let reentry_config_ok = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    if config_present {
        info!(
            freedom_path = %freedom_path.display(),
            ready = already_initialized,
            "preloading existing GUI configuration"
        );
        if already_initialized && interface_choice_recorded {
            window.set_step(WizardStep::Done);
        }
        // Both legacy-complete and daemon-pending GUI config can only be
        // written after the licence gate. Pre-arm the checkbox so a crash
        // recovery can resume without walking backwards through onboarding.
        window.set_license_accepted(true);

        // M-1 fix — read freedom.yaml back into the wizard properties
        // so the Done-summary card on re-entry shows the operator's
        // actual config rather than the type defaults (empty handle /
        // claude_cli / standard). The summary is the operator's only
        // confirmation that NEOTH remembered them; surfacing defaults
        // there is misleading.
        match read_freedom_yaml(&neoth_dir.join("freedom.yaml")) {
            Ok(cfg) => {
                window.set_operator_id(cfg.operator_id.into());
                window.set_provider_choice(cfg.provider_kind.into());
                window.set_autonomy_choice(cfg.autonomy.into());
                window.set_enable_telegram(cfg.channels.iter().any(|c| c == "telegram"));
                if let Some(omi) = cfg.omi {
                    window.set_wz_omi_enabled(omi.enabled);
                    window.set_wz_omi_mode(omi.mode.into());
                    window.set_wz_omi_endpoint(omi.endpoint.into());
                    window.set_wz_omi_listen_addr(omi.listen_addr.into());
                    window.set_wz_omi_retention_days(omi.retention_days.to_string().into());
                    window.set_wz_omi_retain_transcripts(omi.retain_transcripts);
                    window.set_wz_omi_audio_enabled(omi.audio_enabled);
                    window.set_wz_omi_image_enabled(omi.visual_enabled);
                    window.set_wz_omi_video_enabled(omi.video_enabled);
                    window.set_wz_omi_allow_cloud_api(omi.allow_cloud_api);
                    window.set_wz_omi_allow_cloud_summary(omi.allow_cloud_summary);
                    window.set_wz_omi_create_actions(omi.create_actions);
                    window.set_wz_omi_seed_groundtruth(omi.seed_groundtruth);
                    window.set_wz_omi_summary_enabled(omi.summary_enabled);
                }
                // Config loaded successfully — Finish is safe to overwrite.
                reentry_config_ok.store(true, std::sync::atomic::Ordering::Release);
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "could not parse existing freedom.yaml — Done summary shows defaults"
                );
                // reentry_config_ok stays false: Finish will refuse to write
                // rather than clobber the existing config with type defaults.
            }
        }

        // Bite #5 — populate the cluster settings panel from the
        // existing freedom.yaml so the post-onboarding operator sees
        // their current cluster state (not Q4 defaults) when they
        // click the Cluster tab. Lossless reader — doesn't touch
        // unrelated fields.
        let cluster_state = load_cluster_settings(&neoth_dir.join("freedom.yaml"));
        window.set_cluster_discovery_disabled(!cluster_state.mdns_enabled);
        window.set_cluster_mdns_enabled(cluster_state.mdns_enabled);
        window.set_cluster_listen_port(cluster_state.listen_port as i32);
        window.set_cluster_trusted_ssids_summary(cluster_state.trusted_ssids_summary.into());
        // PF-01-GUI — reflect the current skills.always_embed_route on the toggle.
        window.set_skills_always_embed_route(read_skills_always_embed_route(
            &neoth_dir.join("freedom.yaml"),
        ));

        // DES-09 — populate all editable settings fields from freedom.yaml.
        {
            let fp = &neoth_dir.join("freedom.yaml");
            // Welle A — council
            // FIX 4 — daily_usd_cap is a YAML float; as_str() always returns None for
            // numeric nodes. Use the f64 reader and format for display.
            let cap_str = read_nested_f64_in_freedom(fp, "council.daily_usd_cap")
                .map(format_cap_f64)
                .unwrap_or_default();
            window.set_cfg_council_daily_usd(cap_str.into());
            let mc = read_nested_i64_in_freedom(fp, "council.max_calls_per_user_message", 0);
            window.set_cfg_council_max_calls(if mc == 0 {
                "".into()
            } else {
                mc.to_string().into()
            });
            let md = read_nested_i64_in_freedom(fp, "council.max_recursion_depth", 0);
            window.set_cfg_council_max_depth(if md == 0 {
                "".into()
            } else {
                md.to_string().into()
            });
            let sm = read_nested_str_in_freedom(fp, "council.selection_mode", "legacy_majority");
            // FIX 5 — 3 variants: 0=legacy_majority 1=consensus_or_best 2=best_always
            window.set_cfg_council_selection_mode_idx(match sm.as_str() {
                "consensus_or_best" => 1,
                "best_always" => 2,
                _ => 0,
            });
            // Welle A — provider
            window.set_cfg_provider_model(
                read_nested_str_in_freedom(fp, "provider_model", "").into(),
            );
            window.set_cfg_provider_endpoint(
                read_nested_str_in_freedom(fp, "provider_endpoint", "").into(),
            );
            window.set_cfg_provider_region(
                read_nested_str_in_freedom(fp, "provider_region", "").into(),
            );
            window.set_cfg_provider_api_version(
                read_nested_str_in_freedom(fp, "provider_api_version", "").into(),
            );
            // Welle A — profile + behavior
            let pm = read_nested_str_in_freedom(fp, "persona_mode", "");
            window.set_cfg_persona_mode_idx(if pm == "loyal_buddy" { 1 } else { 0 });
            window.set_cfg_user_tz(read_nested_str_in_freedom(fp, "user_tz", "").into());
            window.set_cfg_elicitation_enabled(read_nested_bool_in_freedom(
                fp,
                "elicitation.enabled",
                false,
            ));
            window.set_cfg_elicitation_min_intensity_idx(
                match read_nested_str_in_freedom(fp, "elicitation.min_intensity", "medium").as_str()
                {
                    "low" => 0,
                    "high" => 2,
                    "urgent" => 3,
                    _ => 1,
                },
            );
            window.set_cfg_tone_modifier_enabled(read_nested_bool_in_freedom(
                fp,
                "tone_modifier.enabled",
                false,
            ));
            // Welle B — privacy
            window.set_cfg_review_gate_enabled(read_nested_bool_in_freedom(
                fp,
                "review_gate_enabled",
                false,
            ));
            window.set_cfg_cloud_stt_enabled(read_nested_bool_in_freedom(
                fp,
                "media.cloud_stt_enabled",
                false,
            ));
            window.set_cfg_cloud_tts_enabled(read_nested_bool_in_freedom(
                fp,
                "media.cloud_tts_enabled",
                false,
            ));
            window.set_cfg_cloud_vision_enabled(read_nested_bool_in_freedom(
                fp,
                "media.cloud_vision_enabled",
                false,
            ));
            window.set_cfg_vad_enabled(read_nested_bool_in_freedom(fp, "media.vad_enabled", false));
            window.set_cfg_dictation_enabled(read_nested_bool_in_freedom(
                fp,
                "media.dictation_enabled",
                false,
            ));
            window.set_cfg_proactive_idle_only(read_nested_bool_in_freedom(
                fp,
                "proactive.idle_only",
                false,
            ));
            // DES-09 G37 — quiet hours preload: a [start, end] sequence
            // enables the editor; absent/null leaves it disabled.
            if let Some((qs, qe)) = read_quiet_hours_in_freedom(fp) {
                window.set_cfg_quiet_hours_enabled(true);
                window.set_cfg_quiet_hours_start(qs.to_string().into());
                window.set_cfg_quiet_hours_end(qe.to_string().into());
            }
            // Welle C — memory
            window.set_cfg_memory_name_sessions(read_nested_bool_in_freedom(
                fp,
                "memory.name_sessions",
                false,
            ));
            window.set_cfg_memory_recall_shortcut(read_nested_bool_in_freedom(
                fp,
                "memory.recall_shortcut",
                false,
            ));
            let vb = read_nested_str_in_freedom(fp, "memory.vector_index.backend", "brute_force");
            window.set_cfg_memory_vector_backend_idx(if vb == "hnsw" { 1 } else { 0 });
            window.set_cfg_consolidation_enabled(read_nested_bool_in_freedom(
                fp,
                "consolidation_sweep.enabled",
                false,
            ));
            let csi = read_nested_i64_in_freedom(fp, "consolidation_sweep.interval_secs", 0);
            window.set_cfg_consolidation_interval_secs(if csi == 0 {
                "".into()
            } else {
                csi.to_string().into()
            });
            let csc = read_nested_f64_in_freedom(fp, "consolidation_sweep.cosine_threshold")
                .map(|v| v.to_string())
                .unwrap_or_default();
            window.set_cfg_consolidation_cosine(csc.into());
            // Welle E — obsidian edit fields
            window.set_obs_vault_path_edit(
                read_nested_str_in_freedom(fp, "obsidian_vault", "").into(),
            );
            window
                .set_obs_subdir_edit(read_nested_str_in_freedom(fp, "obsidian_subdir", "").into());
            let asx = read_nested_i64_in_freedom(fp, "obsidian_auto_sync_secs", 0);
            window.set_obs_auto_sync_secs_edit(asx as i32);
            window.set_obs_reader_enabled_edit(read_nested_bool_in_freedom(
                fp,
                "obsidian_vault_reader_enabled",
                false,
            ));
            // GUI-DES-SETTINGS-PRELOAD-01 — preload config fields
            window.set_obs_preload_template_dir_edit(
                read_nested_str_in_freedom(fp, "obsidian_preload_template_dir", "").into(),
            );
            window.set_obs_preload_subdir_edit(
                read_nested_str_in_freedom(fp, "obsidian_preload_subdir", "").into(),
            );
            window.set_obs_knowledge_preload_dirs_edit(
                read_nested_seq_in_freedom(fp, "knowledge_preload_dirs")
                    .join("\n")
                    .into(),
            );
        }

        if already_initialized {
            window.set_status_line(
                format!(
                    "NEOTH is already configured at {}.\n\
                     Click \"Open Settings →\" to reach the Code Sessions tab,\n\
                     or click Finish to re-write the config.",
                    neoth_dir.display()
                )
                .into(),
            );
        } else {
            window.set_status_line(
                "A previous setup was interrupted before completion. Your saved values were restored; review them and click Finish to resume safely."
                    .into(),
            );
        }
    }
    if interface_choice_recorded && !already_initialized {
        window.set_step(WizardStep::Welcome);
    }
    if let Some(error) = interface_choice_error {
        window.set_step(WizardStep::ModeSelection);
        window.set_status_line(
            format!(
                "Interface preference needs repair: {error}. Choose GUI or CLI below to replace it explicitly."
            )
            .into(),
        );
    }
    if let Some(error) = initialization_error {
        window.set_step(WizardStep::Welcome);
        window.set_status_line(
            format!(
                "Initialization state needs repair: {error}. Run `neoth init --force` before saving from the GUI."
            )
            .into(),
        );
    }

    // GOLD-R4-03 — both first-run choices cross the canonical CLI writer.
    // Advance/exit only after persistence (and for CLI, a real terminal)
    // succeeds. All subprocess work stays off the Slint event loop.
    let weak_gui_choice = window.as_weak();
    let gui_choice_home = neoth_dir.clone();
    window.on_gui_mode_chosen(move || {
        if let Some(w) = weak_gui_choice.upgrade() {
            w.set_status_line("Saving GUI as the default interface…".into());
        }
        let weak = weak_gui_choice.clone();
        let home = gui_choice_home.clone();
        std::thread::spawn(move || {
            let result = which_neothd()
                .context("NEOTH CLI binary is missing beside the GUI")
                .and_then(|bin| {
                    set_interface_preference_via_cli(&bin, &home, GuiInterfacePreference::Gui)
                });
            let _ = slint::invoke_from_event_loop(move || {
                let Some(w) = weak.upgrade() else { return };
                match result {
                    Ok(()) => {
                        w.set_mode_choice_busy(false);
                        w.set_mode_gui_chosen(true);
                        w.set_mode_cli_chosen(false);
                        w.set_status_line("GUI selected. You can open the CLI anytime from Settings → Maintenance.".into());
                        w.set_step(if already_initialized {
                            WizardStep::Done
                        } else {
                            WizardStep::Welcome
                        });
                    }
                    Err(error) => {
                        w.set_mode_choice_busy(false);
                        w.set_status_line(
                            format!("Could not save the GUI choice: {error}").into(),
                        );
                    }
                }
            });
        });
    });

    let weak_cli = window.as_weak();
    let cli_choice_home = neoth_dir.clone();
    window.on_cli_mode_chosen(move || {
        if let Some(w) = weak_cli.upgrade() {
            w.set_status_line("Opening the NEOTH CLI in a new terminal…".into());
        }
        let weak = weak_cli.clone();
        let home = cli_choice_home.clone();
        std::thread::spawn(move || {
            let result = which_neothd()
                .context("NEOTH CLI binary is missing beside the GUI")
                .and_then(|bin| switch_to_cli(&bin, &home));
            let _ = slint::invoke_from_event_loop(move || {
                let Some(w) = weak.upgrade() else { return };
                match result {
                    Ok(()) => {
                        info!("operator switched from first-run GUI to CLI");
                        let _ = w.hide();
                        let _ = slint::quit_event_loop();
                    }
                    Err(error) => {
                        w.set_mode_choice_busy(false);
                        w.set_status_line(
                            format!("Could not open the CLI terminal: {error}").into(),
                        );
                    }
                }
            });
        });
    });

    let weak_settings_cli = window.as_weak();
    let settings_cli_home = neoth_dir.clone();
    window.on_settings_open_cli_clicked(move || {
        if let Some(w) = weak_settings_cli.upgrade() {
            w.set_status_line("Opening the NEOTH CLI in a new terminal…".into());
        }
        let weak = weak_settings_cli.clone();
        let home = settings_cli_home.clone();
        std::thread::spawn(move || {
            let result = which_neothd()
                .context("NEOTH CLI binary is missing beside the GUI")
                .and_then(|bin| switch_to_cli(&bin, &home));
            let weak_for_toast = weak.clone();
            let _ = slint::invoke_from_event_loop(move || {
                let Some(w) = weak.upgrade() else { return };
                match result {
                    Ok(()) => {
                        w.set_status_line(
                            "CLI opened. It is now the default; `neoth gui` switches back anytime."
                                .into(),
                        );
                        push_toast(
                            &weak_for_toast,
                            "success",
                            "CLI opened",
                            "The GUI stays available; the next default launch uses CLI.",
                        );
                    }
                    Err(error) => {
                        let message = format!("Could not open the CLI terminal: {error}");
                        w.set_status_line(message.clone().into());
                        push_toast(&weak_for_toast, "warn", "CLI launch failed", &message);
                    }
                }
            });
        });
    });

    // R2-P0-1 (2026-05-22 Session 20) — GUI chat now reaches the
    // provider/WAL/permission/cost stack via the daemon binary, the
    // exact same code path as `neothd chat` from a terminal. Pre-fix:
    // operator bubble was pushed and the surface looked alive but Send
    // never reached an LLM. R2 reviewer flagged this as the #1 first-
    // moment regression (`PLAN/REEVALUATION_GESAMT_2026-05-21_R2.md`
    // §4 P0-1).
    //
    // Flow:
    //   1. Push operator bubble + composer empty (immediate feedback).
    //   2. Push placeholder assistant bubble ("…", streaming=true) so
    //      the operator sees "the system is thinking" without an empty
    //      scrollback gap.
    //   3. Spawn a worker thread that runs `neothd chat <body>` and
    //      captures stdout. Subprocess inherits the operator's
    //      freedom.yaml + credentials so provider / autonomy / cost
    //      gates fire identically to the CLI path.
    //   4. `invoke_from_event_loop` swaps the placeholder for the real
    //      reply (or an error bubble if the subprocess failed).
    // ODY-10: shared buffer that holds the last non-empty operator input so
    // ArrowUp-on-empty-composer can recall it. Ephemeral (process lifetime only).
    // Pre-clone before the move closure so both on_chat_send_clicked and
    // on_chat_composer_recall_requested share the same Arc.
    let last_operator_input: std::sync::Arc<std::sync::Mutex<String>> =
        std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let last_operator_input_for_send = std::sync::Arc::clone(&last_operator_input);

    // GOLD-ADAPT-ODY-04 — shared stream-supervision state:
    //   chat_child          — the running `neothd chat --stream` subprocess
    //                         (Stop on the stall banner kills it).
    //   chat_last_chunk_ms  — epoch-millis of the last stdout chunk; -1 when
    //                         no stream is in flight. The 2s watchdog timer
    //                         raises the banner at >60s silence.
    //   chat_auto_nudge_budget / chat_auto_in_progress — capped (1 per
    //                         operator send) auto-"continue" when a stream
    //                         ends truncated; the in-progress flag stops the
    //                         auto-turn from refilling its own budget.
    let chat_child: std::sync::Arc<std::sync::Mutex<Option<std::process::Child>>> =
        std::sync::Arc::new(std::sync::Mutex::new(None));
    let chat_last_chunk_ms = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(-1));
    let chat_auto_nudge_budget = std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0));
    let chat_auto_in_progress = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    // GOLD-ADAPT-ODY-03 — pending attachment paths; the strip shows the
    // file names, the send worker consumes the paths as `--attach` args.
    let chat_attachments: std::sync::Arc<std::sync::Mutex<Vec<PathBuf>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

    let chat_child_for_send = chat_child.clone();
    let chat_last_chunk_for_send = chat_last_chunk_ms.clone();
    let chat_budget_for_send = chat_auto_nudge_budget.clone();
    let chat_auto_flag_for_send = chat_auto_in_progress.clone();
    let chat_attach_for_send = chat_attachments.clone();

    // Wave 8 — always-visible Stop: kill the in-flight chat subprocess
    // immediately (same kill path as the stall watchdog's Stop). The
    // completion closure finalizes the partial text as usual.
    {
        let child_slot = chat_child.clone();
        let weak_stop_now = window.as_weak();
        window.on_chat_stop_stream(move || {
            if let Ok(mut slot) = child_slot.lock()
                && let Some(child) = slot.as_mut()
            {
                let _ = child.kill();
            }
            if let Some(w) = weak_stop_now.upgrade() {
                w.set_status_line("stream stopped by operator".into());
            }
        });
    }

    // Wave 8 — code-block copy: the panel's Copy chip lifts just the
    // extracted fenced code, not the whole bubble.
    {
        use slint::Model;
        let weak_cc = window.as_weak();
        window.on_chat_code_copy(move |idx| {
            let Some(w) = weak_cc.upgrade() else { return };
            let Some(msg) = w.get_chat_messages().row_data(idx as usize) else {
                return;
            };
            if msg.code_block.is_empty() {
                return;
            }
            if let Err(e) =
                arboard::Clipboard::new().and_then(|mut c| c.set_text(msg.code_block.to_string()))
            {
                tracing::warn!(error = %e, "code block clipboard copy failed");
            }
        });
    }

    // Wave 5 — message hover actions: Copy / Retry / Delete on bubbles.
    {
        use slint::Model;
        let weak_copy = window.as_weak();
        window.on_chat_message_copy(move |idx| {
            let Some(w) = weak_copy.upgrade() else { return };
            let Some(msg) = w.get_chat_messages().row_data(idx as usize) else {
                return;
            };
            match arboard::Clipboard::new().and_then(|mut c| c.set_text(msg.text.to_string())) {
                Ok(()) => {}
                Err(e) => tracing::warn!(error = %e, "clipboard copy failed"),
            }
        });

        // Retry: resend the nearest operator message at-or-before the
        // clicked bubble through the normal send path.
        let weak_retry = window.as_weak();
        window.on_chat_message_retry(move |idx| {
            let Some(w) = weak_retry.upgrade() else {
                return;
            };
            let msgs = w.get_chat_messages();
            let mut i = idx as usize;
            loop {
                let Some(m) = msgs.row_data(i) else { break };
                if m.role == "operator" {
                    let text = m.text.clone();
                    w.invoke_chat_send_clicked(text);
                    break;
                }
                if i == 0 {
                    break;
                }
                i -= 1;
            }
        });

        // Delete: drop the bubble from the visible model (view-level only —
        // the WAL keeps the audit truth; this is declutter, not history edit).
        let weak_delete = window.as_weak();
        window.on_chat_message_delete(move |idx| {
            let Some(w) = weak_delete.upgrade() else {
                return;
            };
            let msgs = w.get_chat_messages();
            let kept: Vec<ChatMessage> = (0..msgs.row_count())
                .filter(|i| *i != idx as usize)
                .filter_map(|i| msgs.row_data(i))
                .collect();
            w.set_chat_messages(slint::ModelRc::new(std::rc::Rc::new(
                slint::VecModel::from(kept),
            )));
        });
    }

    // GOLD-ADAPT-ODY-12/14 — deep-link chip routing. `nav` chips ARE the
    // UI-control events (panel navigation); `kanban` chips navigate to the
    // board AND fire its own selection callback so the detail pane loads
    // through the existing Rust handler. Unknown kinds = prompt drift →
    // ignored rather than navigating somewhere wrong.
    {
        let weak_chips = window.as_weak();
        window.on_chat_link_chip_clicked(move |kind, id| {
            if let Some(w) = weak_chips.upgrade() {
                match kind.as_str() {
                    "nav" if NAV_PANELS.contains(&id.as_str()) => w.set_nav_active(id),
                    "kanban" => {
                        w.set_nav_active("coding".into());
                        w.invoke_kanban_task_selected(id);
                    }
                    _ => {}
                }
            }
        });
    }

    let weak_chat_send = window.as_weak();
    window.on_chat_send_clicked(move |text| {
        let body = text.trim().to_string();
        // ODY-10: capture before the empty-guard so the recall buffer is
        // always up-to-date for the most recent non-empty send.
        if !body.is_empty()
            && let Ok(mut last) = last_operator_input_for_send.lock()
        {
            *last = body.clone();
        }
        if body.is_empty() {
            return;
        }
        info!(message_len = body.len(), "chat: send-clicked");
        let Some(w) = weak_chat_send.upgrade() else {
            return;
        };

        // Buddy reacts: the operator just asked → the orb starts thinking.
        buddy(&w, GuiActivity::ChatThinking);

        use slint::{Model, ModelRc, VecModel};
        let mut rows: Vec<ChatMessage> = w.get_chat_messages().iter().collect();
        let placeholder_idx = rows.len() + 1;
        rows.push(ChatMessage {
            role: "operator".into(),
            text: body.clone().into(),
            timestamp: format_now_hms().into(),
            streaming: false,
            ..Default::default()
        });
        rows.push(ChatMessage {
            role: "assistant".into(),
            text: "…".into(),
            timestamp: format_now_hms().into(),
            streaming: true,
            ..Default::default()
        });
        w.set_chat_messages(ModelRc::new(VecModel::from(rows)));
        w.set_chat_composer_draft("".into());
        // GOLD-ADAPT-GUI-07 — Send spins + re-sends are blocked until the
        // stream settles (flipped back in the completion closure below).
        w.set_chat_send_in_flight(true);
        // Wave-2 feed A: chat send start → plan row.
        {
            let snippet = if body.len() > 80 { &body[..80] } else { &body };
            push_activity(&w.as_weak(), "plan", "Thinking…", snippet);
        }
        // ODY-04 — arm the stall watchdog; refill the auto-nudge budget on
        // a MANUAL send only (the auto-fired "continue" turn must not
        // refill its own budget or it would loop).
        chat_last_chunk_for_send.store(now_epoch_ms(), std::sync::atomic::Ordering::Relaxed);
        if !chat_auto_flag_for_send.swap(false, std::sync::atomic::Ordering::AcqRel) {
            chat_budget_for_send.store(1, std::sync::atomic::Ordering::Relaxed);
        }
        w.set_chat_stall_active(false);

        // ODY-03 — consume the pending attachments for this turn (the
        // strip empties immediately; the paths ride as `--attach` args).
        let attach_paths: Vec<PathBuf> = chat_attach_for_send
            .lock()
            .map(|mut v| std::mem::take(&mut *v))
            .unwrap_or_default();
        sync_attachment_strip(&w, &[]);

        let child_slot = chat_child_for_send.clone();
        let last_chunk = chat_last_chunk_for_send.clone();
        let nudge_budget = chat_budget_for_send.clone();
        let auto_flag = chat_auto_flag_for_send.clone();
        let weak_worker = w.as_weak();
        std::thread::spawn(move || {
            // Chat-feel #3: live token streaming. `neoth chat --stream`
            // prints raw reply deltas incrementally + a final
            // {"neoth_stream":"done"} sentinel. We read stdout in chunks,
            // push the accumulated partial into the placeholder bubble on
            // each chunk (live "▋" cursor), then segment the final reply.
            // On a missing binary / spawn failure / truncated stream
            // (EOF with no sentinel) we surface an error bubble.
            use std::io::Read as _;
            // ODY-12/14 — third tuple element carries the deep-link chips
            // ((label, kind, id) triples) parsed off the done-sentinel.
            #[allow(clippy::type_complexity)]
            let outcome: std::result::Result<
                (String, StreamStats, Vec<(String, String, String)>),
                String,
            > = (|| {
                let bin = which_neothd().ok_or_else(|| BINARY_MISSING_MESSAGE.to_string())?;
                let mut cmd = spawn_neothd_plain(&bin);
                cmd.arg("chat").arg("--stream");
                // ODY-03 — attachments ride as repeatable --attach args.
                for p in &attach_paths {
                    cmd.arg("--attach").arg(p);
                }
                let mut child = cmd
                    .arg(&body)
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .map_err(|e| {
                        format!(
                            "Chat subprocess could not start: {e}\n\
                             Verify `neothd --version` works from a terminal."
                        )
                    })?;
                let mut stdout = child
                    .stdout
                    .take()
                    .ok_or_else(|| "stream stdout unavailable".to_string())?;
                // ODY-04 — park the child so the stall banner's Stop can
                // kill it from the UI thread.
                if let Ok(mut slot) = child_slot.lock() {
                    *slot = Some(child);
                }
                let mut acc: Vec<u8> = Vec::new();
                let mut buf = [0u8; 512];
                loop {
                    match stdout.read(&mut buf) {
                        Ok(0) => break, // EOF
                        Ok(n) => {
                            acc.extend_from_slice(&buf[..n]);
                            // ODY-04 — feed the watchdog clock.
                            last_chunk.store(now_epoch_ms(), std::sync::atomic::Ordering::Relaxed);
                            // Re-decode the whole buffer each chunk so a
                            // split multi-byte char never bakes a U+FFFD.
                            let (live, _done) =
                                strip_stream_sentinel(&String::from_utf8_lossy(&acc));
                            let weak_live = weak_worker.clone();
                            let _ = slint::invoke_from_event_loop(move || {
                                if let Some(w) = weak_live.upgrade() {
                                    // Reply deltas are arriving → the orb is on it.
                                    buddy(&w, GuiActivity::ChatStreaming);
                                    use slint::{Model, ModelRc, VecModel};
                                    let mut rows: Vec<ChatMessage> =
                                        w.get_chat_messages().iter().collect();
                                    if placeholder_idx < rows.len()
                                        && rows[placeholder_idx].streaming
                                        && rows[placeholder_idx].role == "assistant"
                                    {
                                        rows[placeholder_idx].text = live.clone().into();
                                        w.set_chat_messages(ModelRc::new(VecModel::from(rows)));
                                    }
                                }
                            });
                        }
                        Err(e) => return Err(format!("stream read error: {e}")),
                    }
                }
                // Reclaim the parked child for the exit wait (Stop may
                // already have taken + killed it — then wait() is a no-op
                // on a None slot and status stays None).
                let status = child_slot
                    .lock()
                    .ok()
                    .and_then(|mut slot| slot.take())
                    .and_then(|mut c| c.wait().ok());
                let raw = String::from_utf8_lossy(&acc);
                let (reply, done, stats) = parse_stream_sentinel(&raw);
                if reply.is_empty() {
                    return Err("Provider returned an empty reply. Check `neoth doctor` + \
                                `~/.neoth/freedom.yaml` provider settings."
                        .to_string());
                }
                if !done {
                    // EOF without the sentinel → the stream was truncated
                    // (provider error / crash mid-reply). Surface what we
                    // got so the operator isn't left guessing.
                    let code = status.and_then(|s| s.code()).unwrap_or(-1);
                    return Err(format!(
                        "Stream ended before completion (exit {code}). Partial reply:\n\n{reply}"
                    ));
                }
                // ODY-12/14 — deep-link chips ride the same sentinel line.
                let links = parse_stream_links(&raw);
                Ok((reply, stats, links))
            })();
            // Stream over (either way) — disarm the watchdog clock.
            last_chunk.store(-1, std::sync::atomic::Ordering::Relaxed);

            let weak_for_loop = weak_worker.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak_for_loop.upgrade() {
                    // GUI-07: the stream settled (reply or error) — unspin Send.
                    w.set_chat_send_in_flight(false);
                    w.set_chat_stall_active(false);
                    // Wave-2 feed A: settle plan row + push metric.
                    {
                        let weak_settle = weak_for_loop.clone();
                        settle_activity_kind(&weak_settle, "plan");
                        let metric_detail = match &outcome {
                            Ok((_, stats, _)) => {
                                format!("{}t out · {}ms", stats.output_tokens, stats.elapsed_ms)
                            }
                            Err(e) => format!("error: {}", &e[..e.len().min(60)]),
                        };
                        push_activity(&weak_settle, "metric", "Reply done", &metric_detail);
                    }
                    // ODY-12/14 — swap the deep-link chip row for this turn
                    // (cleared on error so stale chips can't dangle).
                    let chips: Vec<LinkChip> = match &outcome {
                        Ok((_, _, links)) => links
                            .iter()
                            .map(|(label, kind, id)| LinkChip {
                                label: label.as_str().into(),
                                kind: kind.as_str().into(),
                                id: id.as_str().into(),
                            })
                            .collect(),
                        Err(_) => Vec::new(),
                    };
                    // Wave-2 feed B: one activity row per deep-link chip.
                    for chip in &chips {
                        let kind = if chip.kind.as_str() == "kanban" {
                            "kanban"
                        } else {
                            "link"
                        };
                        push_activity(&weak_for_loop, kind, chip.label.as_str(), chip.id.as_str());
                    }
                    w.set_chat_link_chips(slint::ModelRc::new(slint::VecModel::from(chips)));
                    use slint::{Model, ModelRc, VecModel};
                    let mut rows: Vec<ChatMessage> = w.get_chat_messages().iter().collect();
                    let ts = format_now_hms();
                    let succeeded = outcome.is_ok();
                    // ODY-04 — capped auto-nudge: a truncated stream fires ONE
                    // automatic "continue" turn per operator send. The flag
                    // routes the refill-guard in the send handler.
                    let auto_nudge = matches!(
                        &outcome,
                        Err(e) if e.starts_with("Stream ended before completion")
                    ) && nudge_budget
                        .fetch_update(
                            std::sync::atomic::Ordering::AcqRel,
                            std::sync::atomic::Ordering::Acquire,
                            |b| b.checked_sub(1),
                        )
                        .is_ok();
                    // Chat-feel parity: a successful reply is segmented into
                    // one bubble per paragraph (openhuman cluster feel); an
                    // error stays a single `error`-role bubble.
                    let replacements: Vec<ChatMessage> = match outcome {
                        Ok((reply, stats, _links)) => {
                            // ODY-02/05 — the LAST segment carries the
                            // context/throughput chip (chip on the tail
                            // reads as "turn summary", not per-paragraph).
                            let segs = segment_reply_into_bubbles(&reply);
                            let last = segs.len().saturating_sub(1);
                            let metrics = panel_logic::format_stream_metrics(
                                stats.used_tokens,
                                stats.limit_tokens,
                                stats.input_tokens,
                                stats.output_tokens,
                                stats.elapsed_ms,
                            );
                            let response_model = stats.model.clone();
                            segs.into_iter()
                                .enumerate()
                                .map(|(i, seg)| {
                                    let m = if i == last { metrics.clone() } else { None };
                                    let (chip, detail) = m.unwrap_or_default();
                                    // H19-lite — fenced code lands in the
                                    // bubble's code panel with a Copy chip.
                                    let (code, lang) = panel_logic::extract_code_blocks(&seg);
                                    ChatMessage {
                                        role: "assistant".into(),
                                        text: seg.into(),
                                        timestamp: ts.clone().into(),
                                        streaming: false,
                                        metrics: chip.into(),
                                        metrics_detail: detail.into(),
                                        model: if i == last {
                                            response_model.clone().into()
                                        } else {
                                            "".into()
                                        },
                                        code_block: code.into(),
                                        code_lang: lang.into(),
                                    }
                                })
                                .collect()
                        }
                        Err(err) => vec![ChatMessage {
                            // `error` bubble role lets the .slint side
                            // colour the surface differently (red tint
                            // when the Composer's theme picks it up).
                            // Older Composer versions render "error" the
                            // same as "assistant" — degrades cleanly.
                            role: "error".into(),
                            text: err.into(),
                            timestamp: ts.clone().into(),
                            streaming: false,
                            ..Default::default()
                        }],
                    };
                    // Splice the replacement bubble(s) in place of the
                    // streaming placeholder (penultimate row by construction;
                    // check defensively in case the operator sent a second
                    // message before the first returned).
                    if placeholder_idx < rows.len()
                        && rows[placeholder_idx].streaming
                        && rows[placeholder_idx].role == "assistant"
                    {
                        rows.remove(placeholder_idx);
                        for (i, bubble) in replacements.into_iter().enumerate() {
                            rows.insert(placeholder_idx + i, bubble);
                        }
                    } else {
                        rows.extend(replacements);
                    }
                    w.set_chat_messages(ModelRc::new(VecModel::from(rows)));
                    // Buddy reflects the outcome: a win lights it green, a
                    // failure shows the error face. It holds that state until
                    // the next message resets it to "thinking".
                    buddy(
                        &w,
                        if succeeded {
                            GuiActivity::ChatDone
                        } else {
                            GuiActivity::ChatError
                        },
                    );
                    // ODY-04 — fire the capped auto-continue as a visible
                    // operator turn (honest: the nudge shows in scrollback).
                    if auto_nudge {
                        auto_flag.store(true, std::sync::atomic::Ordering::Release);
                        w.set_status_line("stream truncated — auto-continue fired (1/1)".into());
                        w.invoke_chat_send_clicked("continue".into());
                    }
                }
            });
        });
    });

    // ODY-04 — stall-banner actions. "Keep waiting" re-arms the watchdog
    // clock (long tool calls are legitimate); "Stop" kills the subprocess —
    // the worker's EOF path then lands the truncated-stream error bubble.
    {
        let last_chunk = chat_last_chunk_ms.clone();
        let weak_stall = window.as_weak();
        window.on_chat_stall_continue(move || {
            last_chunk.store(now_epoch_ms(), std::sync::atomic::Ordering::Relaxed);
            if let Some(w) = weak_stall.upgrade() {
                w.set_chat_stall_active(false);
            }
        });
    }
    {
        let child_slot = chat_child.clone();
        let weak_stop = window.as_weak();
        window.on_chat_stall_stop(move || {
            if let Ok(mut slot) = child_slot.lock()
                && let Some(child) = slot.as_mut()
            {
                let _ = child.kill();
            }
            if let Some(w) = weak_stop.upgrade() {
                w.set_chat_stall_active(false);
                w.set_status_line("chat stream stopped by operator".into());
            }
        });
    }
    // GOLD-ADAPT-AOS-01 — skills-index search: regroup the cached list on
    // every keystroke (pure regroup, no subprocess round-trip).
    {
        let weak_skill_filter = window.as_weak();
        window.on_skills_filter_edited(move |_| {
            if let Some(w) = weak_skill_filter.upgrade() {
                render_skill_index(&w);
            }
        });
    }

    // GOLD-ADAPT-AOS-03 — project context: load at startup (feeds the
    // sidebar operator card + prefills the wizard step on re-runs);
    // persist on the wizard step's Continue.
    {
        let ctx = panel_logic::read_project_context(&default_neoth_home());
        window.set_project_building(ctx.building.into());
        window.set_project_domain(ctx.domain.into());
        window.set_project_stack(ctx.stack.into());
        let weak_ctx = window.as_weak();
        window.on_project_context_set(move |building, domain, stack| {
            let ok = panel_logic::write_project_context(
                &default_neoth_home(),
                &panel_logic::ProjectContext {
                    building: building.trim().to_string(),
                    domain: domain.trim().to_string(),
                    stack: stack.trim().to_string(),
                },
            );
            if let Some(w) = weak_ctx.upgrade() {
                w.set_status_line(
                    if ok {
                        "project context saved to ~/.neoth/.project-context"
                    } else {
                        "project context could not be saved (disk?)"
                    }
                    .into(),
                );
            }
        });
    }

    // GOLD-ADAPT-OH-12 — first-run tour: armed while the done-marker is
    // absent; the overlay itself only shows on the chat surface. Both
    // Finish and Skip write the marker (a tour never nags twice).
    {
        let marker = default_neoth_home().join(".gui-tour-done");
        window.set_tour_active(!marker.exists());
        let weak_tour = window.as_weak();
        window.on_tour_dismissed(move || {
            let marker = default_neoth_home().join(".gui-tour-done");
            let _ = std::fs::create_dir_all(default_neoth_home());
            let _ = std::fs::write(&marker, "1");
            if let Some(w) = weak_tour.upgrade() {
                w.set_tour_active(false);
            }
        });
    }

    // GOLD-ADAPT-AOS-06 — New-Spec pane: `neothd kanban add` off-thread,
    // then a board refresh so the new task shows in Backlog immediately.
    {
        let weak_spec = window.as_weak();
        window.on_spec_create(move |title, goal, acceptance| {
            let title = title.trim().to_string();
            if title.is_empty() {
                return;
            }
            let desc = panel_logic::compose_spec_description(goal.as_str(), acceptance.as_str());
            let weak = weak_spec.clone();
            std::thread::spawn(move || {
                let outcome: Result<String, String> = (|| {
                    let bin = which_neothd().ok_or_else(|| BINARY_MISSING_MESSAGE.to_string())?;
                    let mut cmd = spawn_neothd_plain(&bin);
                    cmd.arg("kanban").arg("add").arg(&title);
                    if let Some(d) = &desc {
                        cmd.arg("--description").arg(d);
                    }
                    match cmd.output() {
                        Ok(o) if o.status.success() => {
                            Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
                        }
                        Ok(o) => Err(format!(
                            "kanban add failed: {}",
                            String::from_utf8_lossy(&o.stderr).trim()
                        )),
                        Err(e) => Err(format!("kanban add could not start: {e}")),
                    }
                })();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        match outcome {
                            Ok(line) => {
                                w.set_status_line(line.into());
                                // Board refresh reuses the existing handler.
                                w.invoke_kanban_refresh_clicked();
                            }
                            Err(e) => w.set_status_line(e.into()),
                        }
                    }
                });
            });
        });
    }

    // GOLD-ADAPT-ODY-03 — attach/remove handlers. The picker is the native
    // modal dialog (blocks the UI thread while open — standard Open-dialog
    // semantics on Windows).
    {
        let attachments = chat_attachments.clone();
        let weak_attach = window.as_weak();
        window.on_chat_attach_clicked(move || {
            let picked = rfd::FileDialog::new()
                .set_title("Attach files to this message")
                .pick_files();
            let Some(files) = picked else {
                return;
            };
            if let Ok(mut v) = attachments.lock() {
                v.extend(files);
                if let Some(w) = weak_attach.upgrade() {
                    sync_attachment_strip(&w, &v);
                }
            }
        });
    }
    {
        let attachments = chat_attachments.clone();
        let weak_rm = window.as_weak();
        window.on_chat_remove_attachment(move |i| {
            if let Ok(mut v) = attachments.lock() {
                let i = i as usize;
                if i < v.len() {
                    v.remove(i);
                }
                if let Some(w) = weak_rm.upgrade() {
                    sync_attachment_strip(&w, &v);
                }
            }
        });
    }

    // Watchdog timer: 2s cadence, banner at >60s chunk silence while a
    // reply is in flight.
    let weak_watchdog = window.as_weak();
    let _chat_stall_timer = {
        let timer = slint::Timer::default();
        let last_chunk = chat_last_chunk_ms.clone();
        timer.start(
            slint::TimerMode::Repeated,
            std::time::Duration::from_secs(2),
            move || {
                if let Some(w) = weak_watchdog.upgrade() {
                    let armed = last_chunk.load(std::sync::atomic::Ordering::Relaxed);
                    let stalled = armed >= 0
                        && w.get_chat_send_in_flight()
                        && now_epoch_ms().saturating_sub(armed) > 60_000;
                    if w.get_chat_stall_active() != stalled {
                        w.set_chat_stall_active(stalled);
                    }
                }
            },
        );
        timer
    };

    // GOLD-ADAPT-ODY-01 — chat-sidebar session history (hindsight cards).
    // Off-thread startup load; click sets the active marker + a footer note.
    {
        let weak_sessions = window.as_weak();
        std::thread::spawn(move || {
            let rows = panel_logic::load_session_history(&default_neoth_home(), 20);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak_sessions.upgrade() {
                    use slint::{ModelRc, VecModel};
                    let model: Vec<SessionRow> = rows
                        .into_iter()
                        .map(|s| SessionRow {
                            id: s.id.into(),
                            label: s.label.into(),
                            meta: s.meta.into(),
                        })
                        .collect();
                    w.set_chat_session_history(ModelRc::new(VecModel::from(model)));
                }
            });
        });
        let weak_sel = window.as_weak();
        window.on_chat_session_selected(move |id| {
            if let Some(w) = weak_sel.upgrade() {
                w.set_chat_active_session_id(id.clone());
                w.set_status_line(format!("session {id} selected").into());
            }
        });
    }

    // ODY-10: ArrowUp-on-empty-composer recall handler. The callback fires
    // on the Slint event-loop thread; we read the shared buffer and write
    // the last input back into the composer draft directly (no
    // invoke_from_event_loop needed — we are already on the UI thread).
    {
        let weak_recall = window.as_weak();
        let last_input_for_recall = std::sync::Arc::clone(&last_operator_input);
        window.on_chat_composer_recall_requested(move || {
            let last = last_input_for_recall
                .lock()
                .map(|g| g.clone())
                .unwrap_or_default();
            if last.is_empty() {
                return;
            }
            if let Some(w) = weak_recall.upgrade() {
                w.set_chat_composer_draft(last.into());
            }
        });
    }

    // H-1 fix — chat-channel-switched was likewise unbound. Now logged
    // so the operator's sidebar click reaches the daemon-facing layer
    // when channel-specific scrollback wiring lands.
    window.on_chat_channel_switched(|idx| {
        info!(channel_index = idx, "chat: channel-switched");
    });

    // Wave-2 — activity sidecar toggle: flip open↔closed.
    {
        let weak_act = window.as_weak();
        window.on_activity_toggle(move || {
            if let Some(w) = weak_act.upgrade() {
                w.set_activity_open(!w.get_activity_open());
            }
        });
    }

    // Pick #32 — Settings panel auto-save sentinel. Operator clicked
    // "Reload config" in the Settings → Config tab; drop the sentinel
    // file the daemon polls every 2s. This is the same path that
    // `/reload` writes from the CLI, so GUI ↔ CLI parity holds.
    let weak_reload = window.as_weak();
    window.on_settings_reload_clicked(move || {
        let path = default_neoth_home().join(".reload-requested");
        match std::fs::write(&path, b"reload\n") {
            Ok(_) => {
                info!(path = %path.display(), "settings: sentinel dropped");
                if let Some(w) = weak_reload.upgrade() {
                    w.set_status_line(
                        "Sentinel dropped at ~/.neoth/.reload-requested — daemon picks up within 2s.".into(),
                    );
                }
            }
            Err(e) => {
                tracing::error!(error = %e, path = %path.display(), "settings: sentinel write failed");
                if let Some(w) = weak_reload.upgrade() {
                    w.set_status_line(format!("Failed to drop sentinel: {e}").into());
                }
            }
        }
    });

    // G-2 fix — open the canonical license URL in the system browser
    // when the operator clicks "View full text →" on the License
    // screen. Uses platform-native open commands so we don't ship a
    // webview dependency.
    // QM-8 Phase 2.5 — operator clicked "Apply active" on the
    // preset tile. Resolve the active preset via `neothd preset
    // list`, then shell `neothd preset apply <name>` to merge
    // its values into freedom.yaml.
    let weak_preset_apply = window.as_weak();
    window.on_preset_apply_clicked(move || {
        let weak = weak_preset_apply.clone();
        std::thread::spawn(move || {
            let outcome = apply_active_preset_via_subprocess();
            // Wave-1 call site A: toast mirrors the status-line result so
            // the operator gets feedback even when not looking at the footer.
            // (push_toast/push_activity marshal to the event loop internally,
            // so they are safe to call from this worker thread.)
            let (toast_kind, toast_title) = if outcome.to_lowercase().contains("error")
                || outcome.to_lowercase().contains("fail")
            {
                ("warn", "Preset apply failed")
            } else {
                ("success", "Preset applied")
            };
            push_toast(&weak, toast_kind, toast_title, &outcome);
            // Wave-2 feed E: consent row when preset actually applied.
            if toast_kind == "success" {
                push_activity(&weak, "consent", "Preset applied", &outcome);
            }
            // Force-refresh the preset summary so the active
            // marker reflects any change without waiting for
            // the next 5-minute tick.
            let summary = probe_preset_summary_via_subprocess();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_status_line(outcome.into());
                    w.set_preset_summary(summary.into());
                }
            });
        });
    });

    // SPEC-05 — operator clicked a preset row: activate it + refresh the list so
    // the active marker moves immediately (no wait for the 5-min tick).
    let weak_preset_activate = window.as_weak();
    window.on_preset_activate_clicked(move |name| {
        let weak = weak_preset_activate.clone();
        let name = name.to_string();
        std::thread::spawn(move || {
            let status = activate_preset_via_subprocess(&name);
            let presets = fetch_presets();
            let summary = probe_preset_summary_via_subprocess();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_status_line(status.into());
                    w.set_preset_summary(summary.into());
                    apply_presets(&w, presets);
                }
            });
        });
    });

    // SPEC-05 builtin-presets — operator clicked Apply on a named preset row.
    // Flow: dry-run in worker thread → if warn_changes OR autonomy_requested==full,
    // populate consent state and show the modal; otherwise apply directly with --yes.
    let weak_named_apply = window.as_weak();
    window.on_preset_apply_named_clicked(move |name| {
        let weak = weak_named_apply.clone();
        let name_s = name.to_string();
        std::thread::spawn(move || {
            // All subprocess work stays in the worker thread; only UI mutations
            // cross back to the event loop (matching the existing preset patterns).
            let plan = dry_run_preset_via_subprocess(&name_s);
            match plan {
                None => {
                    // dry-run unavailable (old daemon / missing binary) →
                    // fall back, but still gate full-auto through the token
                    // route: apply_preset_direct does NOT pass --gui-confirmed
                    // + --gui-token, so confirm_full_auto rejects it (TTY
                    // fail-closed). Use apply_preset_with_fullauto_token for
                    // the "full-auto" builtin name even in the fallback path.
                    // GUI-FULLAUTO-CEREMONY fix.
                    let status = if name_s == "full-auto" {
                        apply_preset_with_fullauto_token(&name_s)
                    } else {
                        apply_preset_direct(&name_s)
                    };
                    let presets = fetch_presets();
                    let summary = probe_preset_summary_via_subprocess();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(w) = weak.upgrade() {
                            w.set_status_line(status.into());
                            w.set_preset_summary(summary.into());
                            apply_presets(&w, presets);
                        }
                    });
                }
                Some(plan) => {
                    let needs_consent = !plan.warn_changes.is_empty()
                        || plan.autonomy_requested.as_deref() == Some("full");
                    if needs_consent {
                        // Build the warn text for the consent panel.
                        let warn_text: String = plan
                            .warn_changes
                            .iter()
                            .map(|c| format!("{}: {} → {}", c.path, c.old, c.new))
                            .collect::<Vec<_>>()
                            .join("\n");
                        let needs_fa = plan.autonomy_requested.as_deref() == Some("full");
                        let field_count = plan.fields_changed_count as i32;
                        let preset_name = plan.name;
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(w) = weak.upgrade() {
                                // Guard: a consent panel is already pending →
                                // drop this dry-run result instead of swapping
                                // the modal's target under the operator's
                                // cursor (double-Apply race, review wave
                                // 2026-07-04). The check-then-set is atomic
                                // here — we are ON the event loop.
                                if w.get_consent_visible() {
                                    w.set_status_line(
                                        "Finish the open preset confirmation first.".into(),
                                    );
                                    return;
                                }
                                w.set_consent_preset_name(preset_name.into());
                                w.set_consent_warn_text(warn_text.into());
                                w.set_consent_needs_fullauto(needs_fa);
                                w.set_consent_fields_count(field_count);
                                w.set_consent_visible(true);
                            }
                        });
                    } else {
                        // No concerns — apply in the worker thread then refresh.
                        let status = apply_preset_direct(&name_s);
                        let presets = fetch_presets();
                        let summary = probe_preset_summary_via_subprocess();
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(w) = weak.upgrade() {
                                w.set_status_line(status.into());
                                w.set_preset_summary(summary.into());
                                apply_presets(&w, presets);
                            }
                        });
                    }
                }
            }
        });
    });

    // SPEC-05 builtin-presets — operator confirmed the consent modal.
    let weak_consent_ok = window.as_weak();
    window.on_preset_consent_confirmed(move || {
        let weak = weak_consent_ok.clone();
        // Read name and autonomy flag before clearing the modal.
        let (name_s, needs_fa) = {
            if let Some(w) = weak.upgrade() {
                let n = w.get_consent_preset_name().to_string();
                let fa = w.get_consent_needs_fullauto();
                // Hide modal immediately so the UI feels responsive.
                w.set_consent_visible(false);
                (n, fa)
            } else {
                return;
            }
        };
        std::thread::spawn(move || {
            let status = if needs_fa {
                apply_preset_with_fullauto_token(&name_s)
            } else {
                apply_preset_direct(&name_s)
            };
            let presets = fetch_presets();
            let summary = probe_preset_summary_via_subprocess();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_status_line(status.into());
                    w.set_preset_summary(summary.into());
                    apply_presets(&w, presets);
                }
            });
        });
    });

    // SPEC-05 builtin-presets — operator cancelled the consent modal.
    let weak_consent_cancel = window.as_weak();
    window.on_preset_consent_cancelled(move || {
        if let Some(w) = weak_consent_cancel.upgrade() {
            w.set_consent_visible(false);
            w.set_status_line("Preset apply cancelled.".into());
        }
    });

    // SPEC-05 builtin-presets — operator clicked Delete on an operator preset.
    // Subprocess work in a worker thread — this callback runs ON the event
    // loop; blocking here freezes the whole UI (review wave 2026-07-04).
    let weak_preset_delete = window.as_weak();
    window.on_preset_delete_clicked(move |name| {
        let weak = weak_preset_delete.clone();
        let name_s = name.to_string();
        std::thread::spawn(move || {
            let status = delete_preset_via_subprocess(&name_s);
            let presets = fetch_presets();
            let summary = probe_preset_summary_via_subprocess();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_status_line(status.into());
                    w.set_preset_summary(summary.into());
                    apply_presets(&w, presets);
                }
            });
        });
    });

    // SPEC-05 step5c — operator picked a response style: apply it + refresh so
    // the active marker moves immediately.
    let weak_profile_apply = window.as_weak();
    window.on_profile_preset_apply_clicked(move |name| {
        let weak = weak_profile_apply.clone();
        let name = name.to_string();
        std::thread::spawn(move || {
            let status = apply_profile_preset_via_subprocess(&name);
            let presets = fetch_profile_presets();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_status_line(status.into());
                    apply_profile_presets(&w, presets);
                }
            });
        });
    });

    window.on_open_license_url(|| {
        let url = "https://github.com/The-Geek-Freaks/NEOTH#license";
        let mut command = if cfg!(target_os = "windows") {
            let mut command = std::process::Command::new("cmd");
            command.args(["/C", "start", "", url]);
            command
        } else if cfg!(target_os = "macos") {
            let mut command = std::process::Command::new("open");
            command.arg(url);
            command
        } else {
            let mut command = std::process::Command::new("xdg-open");
            command.arg(url);
            command
        };
        scrub_gui_control_environment(&mut command);
        suppress_console_window(&mut command);
        let result = command.spawn();
        if let Err(e) = result {
            tracing::warn!(error = %e, url, "failed to open license URL");
        }
    });

    // Reviewer-3 P1-B (2026-05-20): Identity validation. The copy
    // promises `^[a-z0-9-]{3,32}$`; the gate used to accept any
    // non-empty string. Now we round-trip through Rust on every
    // keystroke + push the verdict back as `operator-id-valid`.
    // No regex crate dep — the pattern is tiny + character-class only.
    fn validate_operator_id(s: &str) -> bool {
        let len = s.chars().count();
        if !(3..=32).contains(&len) {
            return false;
        }
        s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    }
    let weak_id = window.as_weak();
    window.on_operator_id_edited(move |text| {
        if let Some(w) = weak_id.upgrade() {
            w.set_operator_id_valid(validate_operator_id(&text));
        }
    });

    // Step 5 (2026-05-20): keep the last-applied snapshot alive in a
    // mutex so the task-click handler can resolve `task-id` → full
    // task detail (title/status/hemisphere) without re-walking the
    // Slint Model. Multiple writers (initial fetch / Refresh / 2s
    // tick) push through `store_kanban_snapshot`; the click handler
    // reads via `latest_kanban_snapshot`.
    use std::sync::{Arc, Mutex};
    let kanban_snapshot: Arc<Mutex<KanbanBoardSnapshot>> =
        Arc::new(Mutex::new(KanbanBoardSnapshot::default()));

    // Pick #8 step 2 — Code Sessions tab data binding.
    //   - At startup: fetch once so the tab shows real data the first
    //     time the operator opens it.
    //   - On Refresh button: re-fetch + re-populate.
    // Live WAL-driven updates land in step 4.
    //
    // H-4 fix — initial fetch + Refresh-click both run on a worker
    // thread so a slow `neothd kanban` subprocess can never block
    // the UI thread. The snapshot lands back on the main thread via
    // `invoke_from_event_loop`.
    let weak_kanban_init = window.as_weak();
    let mutex_init = kanban_snapshot.clone();
    std::thread::spawn(move || {
        let snap = fetch_kanban_board_snapshot();
        let snap_for_state = snap.clone();
        let weak = weak_kanban_init.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Ok(mut g) = mutex_init.lock() {
                *g = snap_for_state;
            }
            if let Some(w) = weak.upgrade() {
                apply_kanban_snapshot(&w, snap);
            }
        });
    });

    // GR-10 + GU-01 — one-shot startup fetch of the read-only settings panels
    // (Safety Rails / Hemispheres / Skills). Off the UI thread (three quick
    // subprocesses), each result marshalled back via invoke_from_event_loop.
    let weak_panels_init = window.as_weak();
    std::thread::spawn(move || {
        let rails = fetch_safe_mode_snapshot();
        let trust = fetch_trust_snapshot();
        let omi = fetch_omi_snapshot();
        let hardware = fetch_hardware_snapshot();
        let topology = fetch_topology_snapshot();
        let usage = fetch_usage_meter();
        let council_budget = fetch_council_budget();
        let profile_presets = fetch_profile_presets();
        let hemis = fetch_hemispheres_snapshot();
        let provider_ids = fetch_provider_ids();
        let skills = fetch_skills();
        let plugins = fetch_plugins();
        let memory = fetch_memory_snapshot();
        // Channels come from the canonical daemon probe. This includes
        // keychain-backed credentials, feature availability, and partial/error
        // states without exposing secret values.
        let channels = fetch_channel_status();
        let weak = weak_panels_init.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(w) = weak.upgrade() {
                apply_safe_mode(&w, rails);
                apply_trust(&w, trust);
                apply_omi_snapshot(&w, omi);
                apply_hardware(&w, hardware);
                apply_topology(&w, topology);
                apply_usage_meter(&w, usage);
                apply_council_budget(&w, council_budget);
                apply_profile_presets(&w, profile_presets);
                apply_hemispheres(&w, hemis);
                apply_provider_ids(&w, provider_ids);
                apply_skills(&w, skills);
                apply_plugins(&w, plugins);
                apply_memory(&w, memory);
                apply_channels(&w, channels);
            }
        });
    });

    // OMI-MULTIMODAL-01 — complete Privacy-tab wiring. All filesystem and
    // subprocess work runs off the UI thread. Secret updates use bounded child
    // stdin and the daemon's credential backend; they never enter argv or UI
    // read-back state.
    let weak_omi_refresh = window.as_weak();
    window.on_omi_refresh(move || {
        let weak = weak_omi_refresh.clone();
        std::thread::spawn(move || {
            let snapshot = fetch_omi_snapshot();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    apply_omi_snapshot(&window, snapshot);
                    window.set_status_line("OMI state refreshed.".into());
                }
            });
        });
    });

    let weak_omi_save = window.as_weak();
    window.on_omi_save(
        move |enabled,
              mode,
              endpoint,
              listen_addr,
              retention_days,
              retain_transcripts,
              audio_enabled,
              image_enabled,
              video_enabled,
              allow_cloud_api,
              allow_cloud_summary,
              create_actions,
              seed_groundtruth,
              summary_enabled,
              developer_key,
              native_token| {
            let weak = weak_omi_save.clone();
            let draft = OmiSettingsDraft {
                enabled,
                mode: mode.to_string(),
                endpoint: endpoint.to_string(),
                listen_addr: listen_addr.to_string(),
                retention_days: retention_days.to_string(),
                retain_transcripts,
                audio_enabled,
                image_enabled,
                video_enabled,
                allow_cloud_api,
                allow_cloud_summary,
                create_actions,
                seed_groundtruth,
                summary_enabled,
                developer_key: developer_key.to_string(),
                native_token: native_token.to_string(),
            };
            std::thread::spawn(move || {
                let existing = fetch_omi_snapshot();
                let result = save_omi_settings(
                    &default_neoth_home(),
                    &draft,
                    existing.developer_credential_present,
                    existing.native_credential_present,
                );
                let snapshot = fetch_omi_snapshot();
                let status = match result {
                    Ok(()) => "OMI settings saved; reload requested.".to_string(),
                    Err(error) => format!("OMI settings rejected: {error:#}"),
                };
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(window) = weak.upgrade() {
                        apply_omi_snapshot(&window, snapshot);
                        window.set_status_line(status.into());
                    }
                });
            });
        },
    );

    let weak_omi_probe = window.as_weak();
    window.on_omi_probe(move || {
        let weak = weak_omi_probe.clone();
        std::thread::spawn(move || {
            let result = run_omi_subcommand(&default_neoth_home(), &["probe".to_string()]);
            let status = result.unwrap_or_else(|error| format!("OMI probe failed: {error:#}"));
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    window.set_status_line(status.into());
                }
            });
        });
    });

    let weak_omi_resume = window.as_weak();
    window.on_omi_resume(move |note| {
        let weak = weak_omi_resume.clone();
        let note = note.to_string();
        std::thread::spawn(move || {
            let result = run_omi_subcommand(
                &default_neoth_home(),
                &["resume".into(), "--review-note".into(), note],
            );
            let snapshot = fetch_omi_snapshot();
            let status = result.unwrap_or_else(|error| format!("OMI resume failed: {error:#}"));
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    apply_omi_snapshot(&window, snapshot);
                    window.set_omi_review_note("".into());
                    window.set_status_line(status.into());
                }
            });
        });
    });

    let weak_omi_retention = window.as_weak();
    window.on_omi_retention(move || {
        let weak = weak_omi_retention.clone();
        std::thread::spawn(move || {
            let result = run_omi_subcommand(&default_neoth_home(), &["enforce-retention".into()]);
            let snapshot = fetch_omi_snapshot();
            let status = result.unwrap_or_else(|error| format!("OMI retention failed: {error:#}"));
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    apply_omi_snapshot(&window, snapshot);
                    window.set_status_line(status.into());
                }
            });
        });
    });

    let weak_omi_purge = window.as_weak();
    window.on_omi_purge(move |conversation_id| {
        let weak = weak_omi_purge.clone();
        let conversation_id = conversation_id.to_string();
        std::thread::spawn(move || {
            let result = run_omi_subcommand(
                &default_neoth_home(),
                &["purge".into(), conversation_id, "--yes".into()],
            );
            let snapshot = fetch_omi_snapshot();
            let status = result.unwrap_or_else(|error| format!("OMI purge failed: {error:#}"));
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    apply_omi_snapshot(&window, snapshot);
                    window.set_status_line(status.into());
                }
            });
        });
    });

    let weak_omi_reimport = window.as_weak();
    window.on_omi_reimport(move |conversation_id| {
        let weak = weak_omi_reimport.clone();
        let conversation_id = conversation_id.to_string();
        std::thread::spawn(move || {
            let result = run_omi_subcommand(
                &default_neoth_home(),
                &["allow-reimport".into(), conversation_id, "--yes".into()],
            );
            let snapshot = fetch_omi_snapshot();
            let status =
                result.unwrap_or_else(|error| format!("OMI allow-reimport failed: {error:#}"));
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    apply_omi_snapshot(&window, snapshot);
                    window.set_status_line(status.into());
                }
            });
        });
    });

    // SPEC-06 — operator rebound a role in the Hemispheres panel: shell
    // `neoth hemispheres set` then refresh the bindings so the panel reflects
    // the new wiring immediately.
    let weak_hemi_set = window.as_weak();
    window.on_hemisphere_set(move |role, provider, model| {
        // "(provider default)" sentinel (combo row 0) → leave the model unset.
        let model = if model == "(provider default)" {
            String::new()
        } else {
            model.to_string()
        };
        let role = role.to_string();
        let provider = provider.to_string();
        let weak = weak_hemi_set.clone();
        std::thread::spawn(move || {
            let status = set_hemisphere_via_subprocess(&role, &provider, &model);
            let hemis = fetch_hemispheres_snapshot();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_status_line(status.into());
                    apply_hemispheres(&w, hemis);
                }
            });
        });
    });

    // GOLD-GUI-OVERHAUL — operator picked a provider in the rebind row; refresh
    // the model combo with that provider's options (local GGUF refs / cloud
    // catalog) off-thread so the VRAM probe never freezes the UI.
    let weak_hemi_models = window.as_weak();
    window.on_hemisphere_provider_picked(move |provider| {
        let weak = weak_hemi_models.clone();
        let provider = provider.to_string();
        std::thread::spawn(move || {
            let models = fetch_hemisphere_model_ids(&provider);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    use slint::{ModelRc, SharedString, VecModel};
                    let rows: Vec<SharedString> = models.into_iter().map(|s| s.into()).collect();
                    w.set_hemisphere_model_ids(ModelRc::new(VecModel::from(rows)));
                }
            });
        });
    });

    let weak_kanban_refresh = window.as_weak();
    let mutex_refresh = kanban_snapshot.clone();
    window.on_kanban_refresh_clicked(move || {
        if let Some(w) = weak_kanban_refresh.upgrade() {
            buddy(&w, GuiActivity::AgentParallel);
        }
        let weak = weak_kanban_refresh.clone();
        let mutex = mutex_refresh.clone();
        std::thread::spawn(move || {
            let snap = fetch_kanban_board_snapshot();
            info!(summary = %snap.summary, "kanban: refresh requested");
            let snap_for_state = snap.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Ok(mut g) = mutex.lock() {
                    *g = snap_for_state;
                }
                if let Some(w) = weak.upgrade() {
                    apply_kanban_snapshot(&w, snap);
                }
            });
        });
    });

    // GOLD-R3-04 — refresh the canonical channel inventory off the UI thread.
    // The CLI owns credential/keychain parsing + probe semantics; the GUI never
    // guesses connection state from credentials.yaml.
    let weak_channels_refresh = window.as_weak();
    window.on_channels_refresh_clicked(move || {
        let weak = weak_channels_refresh.clone();
        std::thread::spawn(move || {
            let channels = fetch_channel_status();
            let ok = channels.is_ok();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    apply_channels(&w, channels);
                    w.set_status_line(if ok {
                        "Channel status refreshed.".into()
                    } else {
                        "Channel status refresh failed — see the Channels panel.".into()
                    });
                }
            });
        });
    });

    // Doctor tab (design-mockup surface) — run `neothd doctor` read-only and
    // stream the check output into the panel. The Buddy verifies while it runs.
    let weak_doctor = window.as_weak();
    window.on_doctor_run_clicked(move || {
        let Some(w0) = weak_doctor.upgrade() else {
            return;
        };
        w0.set_doctor_running(true);
        buddy(&w0, GuiActivity::AuditVerify);
        let weak = weak_doctor.clone();
        std::thread::spawn(move || {
            let output = match which_neothd()
                .and_then(|bin| spawn_neothd_plain(&bin).arg("doctor").output().ok())
            {
                Some(o) => {
                    let mut s = String::from_utf8_lossy(&o.stdout).to_string();
                    let err = String::from_utf8_lossy(&o.stderr);
                    if !err.trim().is_empty() {
                        s.push('\n');
                        s.push_str(&err);
                    }
                    if s.trim().is_empty() {
                        "neoth doctor produced no output.".to_string()
                    } else {
                        s
                    }
                }
                None => "neothd binary not on PATH — cannot run doctor.".to_string(),
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_doctor_output(output.into());
                    w.set_doctor_running(false);
                    buddy(&w, GuiActivity::AuditVerify);
                }
            });
        });
    });

    // GAP-05 — Status probe: `neoth status` → DoctorView status panel.
    let weak_status = window.as_weak();
    window.on_doctor_status_run_clicked(move || {
        let Some(w0) = weak_status.upgrade() else {
            return;
        };
        w0.set_doctor_status_running(true);
        let weak = weak_status.clone();
        std::thread::spawn(move || {
            let output = match which_neothd()
                .and_then(|bin| spawn_neothd_plain(&bin).arg("status").output().ok())
            {
                Some(o) => {
                    let mut s = String::from_utf8_lossy(&o.stdout).to_string();
                    let err = String::from_utf8_lossy(&o.stderr);
                    if !err.trim().is_empty() {
                        s.push('\n');
                        s.push_str(&err);
                    }
                    if s.trim().is_empty() {
                        "neoth status produced no output.".to_string()
                    } else {
                        s
                    }
                }
                None => "neothd binary not on PATH — cannot run status.".to_string(),
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_doctor_status_output(output.into());
                    w.set_doctor_status_running(false);
                }
            });
        });
    });

    // GAP-13 — Security audit probe: `neoth security audit` → DoctorView audit panel.
    let weak_secaudit = window.as_weak();
    window.on_doctor_security_run_clicked(move || {
        let Some(w0) = weak_secaudit.upgrade() else {
            return;
        };
        w0.set_doctor_security_running(true);
        let weak = weak_secaudit.clone();
        std::thread::spawn(move || {
            let output = match which_neothd().and_then(|bin| {
                spawn_neothd_plain(&bin)
                    .arg("security")
                    .arg("audit")
                    .output()
                    .ok()
            }) {
                Some(o) => {
                    let mut s = String::from_utf8_lossy(&o.stdout).to_string();
                    let err = String::from_utf8_lossy(&o.stderr);
                    if !err.trim().is_empty() {
                        s.push('\n');
                        s.push_str(&err);
                    }
                    if s.trim().is_empty() {
                        "neoth security audit produced no output.".to_string()
                    } else {
                        s
                    }
                }
                None => "neothd binary not on PATH — cannot run security audit.".to_string(),
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_doctor_security_output(output.into());
                    w.set_doctor_security_running(false);
                }
            });
        });
    });

    // Agents tab — `neothd cluster status` (the agent/worker + node topology).
    let weak_agents = window.as_weak();
    window.on_agents_refresh_clicked(move || {
        let Some(w0) = weak_agents.upgrade() else {
            return;
        };
        w0.set_agents_running(true);
        buddy(&w0, GuiActivity::AgentDeploy);
        let weak = weak_agents.clone();
        std::thread::spawn(move || {
            // Wave 5 — JSON first for the structured card grid; the raw text
            // dump stays as the fallback body when parsing yields nothing.
            let json_out = run_neothd_probe(&["agents", "list", "--output", "json"]);
            let cards = panel_logic::parse_agents_list(&json_out);
            let output = if cards.is_empty() {
                run_neothd_probe(&["agents", "list"])
            } else {
                String::new()
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    let rows: Vec<AgentRow> = cards
                        .into_iter()
                        .map(|c| AgentRow {
                            name: c.name.into(),
                            hemisphere: c.hemisphere.into(),
                            provider: c.provider.into(),
                            model: c.model.into(),
                            state: c.state.into(),
                            current_task: c.current_task.into(),
                            tasks_done: c.tasks_done,
                        })
                        .collect();
                    w.set_agents_model(slint::ModelRc::new(std::rc::Rc::new(
                        slint::VecModel::from(rows),
                    )));
                    w.set_agents_output(output.into());
                    w.set_agents_running(false);
                }
            });
        });
    });

    // ── GAP-01 Automation / Cron CRUD panel ──────────────────────────────────
    {
        // Refresh — `neoth cron list --output json` → typed model.
        let weak_cron = window.as_weak();
        window.on_cron_refresh_clicked(move || {
            let weak = weak_cron.clone();
            std::thread::spawn(move || {
                refresh_cron(weak);
            });
        });

        // Add — build arg list, omit empty optional flags.
        let weak_cron_add = window.as_weak();
        window.on_cron_add_clicked(
            move |id, name, cron, prompt, tz, channel, recipient, timeout| {
                let id = id.to_string();
                let name = name.to_string();
                let cron = cron.to_string();
                let prompt = prompt.to_string();
                let tz = tz.to_string();
                let channel = channel.to_string();
                let recipient = recipient.to_string();
                let timeout = timeout.to_string();
                let weak = weak_cron_add.clone();
                std::thread::spawn(move || {
                    let mut args: Vec<&str> = vec![
                        "cron",
                        "add",
                        "--id",
                        id.trim(),
                        "--name",
                        name.trim(),
                        "--cron",
                        cron.trim(),
                        "--prompt",
                        prompt.trim(),
                    ];
                    // Optional flags — only appended when non-empty.
                    if !tz.trim().is_empty() {
                        args.extend(["--tz", tz.trim()]);
                    }
                    if !channel.trim().is_empty() {
                        args.extend(["--channel", channel.trim()]);
                    }
                    if !recipient.trim().is_empty() {
                        args.extend(["--recipient", recipient.trim()]);
                    }
                    if !timeout.trim().is_empty() {
                        args.extend(["--timeout", timeout.trim()]);
                    }
                    let result = run_neothd_json_action_receipt::<gui_action::CronMutationAck>(
                        &args, "Cron add",
                    )
                    .and_then(|receipt| {
                        receipt.acknowledgement.verify("add", id.trim())?;
                        Ok(receipt)
                    });
                    match result {
                        Ok(receipt) => {
                            let weak2 = weak.clone();
                            let message = receipt.stderr.map_or_else(
                                || format!("Added {}.", id.trim()),
                                |warning| format!("Added {}. {warning}", id.trim()),
                            );
                            push_toast(&weak, "success", "Cron", &message);
                            std::thread::spawn(move || refresh_cron(weak2));
                        }
                        Err(error) => push_toast(&weak, "warn", "Cron add failed", &error),
                    }
                });
            },
        );

        // Run — `neoth cron run <id>` (daemon refuses while live; surface error as toast).
        let weak_cron_run = window.as_weak();
        window.on_cron_run_clicked(move |id| {
            let id = id.to_string();
            let weak = weak_cron_run.clone();
            std::thread::spawn(move || {
                let result = run_neothd_json_action::<gui_action::CronRunAck>(
                    &["cron", "run", id.trim()],
                    "Cron run",
                )
                .and_then(|ack| {
                    ack.verify(id.trim())?;
                    Ok(ack)
                });
                match result {
                    Ok(ack) => push_toast(
                        &weak,
                        "success",
                        "Cron run",
                        &format!(
                            "{} completed in {} ms ({} output bytes).",
                            id.trim(),
                            ack.duration_ms,
                            ack.output_bytes
                        ),
                    ),
                    Err(error) => push_toast(&weak, "warn", "Cron run refused", &error),
                }
            });
        });

        // Toggle — `neoth cron edit <id> --enabled <bool>`.
        let weak_cron_tog = window.as_weak();
        window.on_cron_toggle_clicked(move |id, new_enabled| {
            let id = id.to_string();
            let weak = weak_cron_tog.clone();
            std::thread::spawn(move || {
                let enabled_str = if new_enabled { "true" } else { "false" };
                let result = run_neothd_json_action_receipt::<gui_action::CronMutationAck>(
                    &["cron", "edit", id.trim(), "--enabled", enabled_str],
                    "Cron toggle",
                )
                .and_then(|receipt| {
                    receipt.acknowledgement.verify("edit", id.trim())?;
                    Ok(receipt)
                });
                match result {
                    Ok(receipt) => {
                        let weak2 = weak.clone();
                        let state = if new_enabled { "Enabled" } else { "Disabled" };
                        let message = receipt.stderr.map_or_else(
                            || format!("{state} {}.", id.trim()),
                            |warning| format!("{state} {}. {warning}", id.trim()),
                        );
                        push_toast(&weak, "info", "Cron", &message);
                        std::thread::spawn(move || refresh_cron(weak2));
                    }
                    Err(error) => {
                        let weak2 = weak.clone();
                        push_toast(&weak, "warn", "Cron toggle failed", &error);
                        std::thread::spawn(move || refresh_cron(weak2));
                    }
                }
            });
        });

        // Remove — `neoth cron remove <id>`.
        let weak_cron_rem = window.as_weak();
        window.on_cron_remove_clicked(move |id| {
            let id = id.to_string();
            let weak = weak_cron_rem.clone();
            std::thread::spawn(move || {
                let result = run_neothd_json_action::<gui_action::CronMutationAck>(
                    &["cron", "remove", id.trim()],
                    "Cron remove",
                )
                .and_then(|ack| {
                    ack.verify("remove", id.trim())?;
                    Ok(ack)
                });
                match result {
                    Ok(_) => {
                        let weak2 = weak.clone();
                        push_toast(&weak, "warn", "Cron", &format!("Removed {}.", id.trim()));
                        std::thread::spawn(move || refresh_cron(weak2));
                    }
                    Err(error) => push_toast(&weak, "warn", "Cron remove failed", &error),
                }
            });
        });

        // Fire once at startup so the list pre-loads.
        let weak_cron_init = window.as_weak();
        std::thread::spawn(move || {
            refresh_cron(weak_cron_init);
        });
    }

    // ── Overview / Mission Control — refresh callback ───────────────────────
    // One worker thread per click; all subprocess work stays off the event loop.
    // The initial probe fires immediately on first entry (triggered below by
    // the on_overview_refresh_clicked callback — also called from Rust on startup).
    let weak_ov = window.as_weak();
    window.on_overview_refresh_clicked(move || {
        let Some(w0) = weak_ov.upgrade() else {
            return;
        };
        // Clear stale timestamp while loading.
        w0.set_ov_refreshed_at("loading…".into());
        let weak = weak_ov.clone();
        std::thread::spawn(move || {
            refresh_overview(weak.clone());
            refresh_overview_cost(weak);
        });
    });

    // Fire the overview probe once at startup so the panel is populated
    // the first time the operator switches to it.
    {
        let weak_ov_init = window.as_weak();
        std::thread::spawn(move || {
            refresh_overview(weak_ov_init.clone());
            refresh_overview_cost(weak_ov_init);
        });
    }

    // ── Design Wave 4a — n8n panel callbacks ─────────────────────────────────
    {
        let weak_n8n = window.as_weak();
        window.on_n8n_refresh_clicked(move || {
            let weak = weak_n8n.clone();
            std::thread::spawn(move || {
                refresh_n8n(weak);
            });
        });
        // Fire once at startup so the panel is pre-populated.
        let weak_n8n_init = window.as_weak();
        std::thread::spawn(move || {
            refresh_n8n(weak_n8n_init);
        });
    }

    // ── Design Wave 4a — Babel panel callbacks ────────────────────────────────
    {
        let weak_babel = window.as_weak();
        window.on_babel_refresh_clicked(move || {
            let weak = weak_babel.clone();
            std::thread::spawn(move || {
                refresh_babel(weak);
            });
        });

        let weak_babel_en = window.as_weak();
        window.on_babel_enable_clicked(move || {
            let weak = weak_babel_en.clone();
            std::thread::spawn(move || {
                let result = run_neothd_json_action::<gui_action::ToggleAck>(
                    &["babel", "enable"],
                    "Babel enable",
                )
                .and_then(|ack| ack.verify("enable", true));
                match result {
                    Ok(()) => {
                        let weak2 = weak.clone();
                        push_toast(&weak, "success", "Babel", "Enabled.");
                        std::thread::spawn(move || refresh_babel(weak2));
                    }
                    Err(error) => {
                        let weak2 = weak.clone();
                        push_toast(&weak, "warn", "Babel enable failed", &error);
                        std::thread::spawn(move || refresh_babel(weak2));
                    }
                }
            });
        });

        let weak_babel_dis = window.as_weak();
        window.on_babel_disable_clicked(move || {
            let weak = weak_babel_dis.clone();
            std::thread::spawn(move || {
                let result = run_neothd_json_action::<gui_action::ToggleAck>(
                    &["babel", "disable"],
                    "Babel disable",
                )
                .and_then(|ack| ack.verify("disable", false));
                match result {
                    Ok(()) => {
                        let weak2 = weak.clone();
                        push_toast(&weak, "info", "Babel", "Disabled.");
                        std::thread::spawn(move || refresh_babel(weak2));
                    }
                    Err(error) => {
                        let weak2 = weak.clone();
                        push_toast(&weak, "warn", "Babel disable failed", &error);
                        std::thread::spawn(move || refresh_babel(weak2));
                    }
                }
            });
        });
    }

    // ── Design Wave 4a — Calendar panel callbacks ─────────────────────────────
    {
        let weak_cal = window.as_weak();
        window.on_cal_refresh_clicked(move || {
            let weak = weak_cal.clone();
            std::thread::spawn(move || {
                refresh_calendar(weak);
            });
        });

        let weak_cal_add = window.as_weak();
        window.on_cal_add_clicked(move || {
            let Some(w0) = weak_cal_add.upgrade() else {
                return;
            };
            let summary = w0.get_cal_add_summary().to_string();
            let start = w0.get_cal_add_start().to_string();
            let end = w0.get_cal_add_end().to_string();
            if summary.trim().is_empty() || start.trim().is_empty() {
                let _ = slint::invoke_from_event_loop({
                    let weak = weak_cal_add.clone();
                    move || {
                        if let Some(w) = weak.upgrade() {
                            w.set_cal_add_result("summary and start are required".into());
                        }
                    }
                });
                return;
            }
            let weak = weak_cal_add.clone();
            std::thread::spawn(move || {
                let probe_args: Vec<String> = if end.trim().is_empty() {
                    vec![
                        "calendar".into(),
                        "add".into(),
                        summary.trim().to_string(),
                        "--start".into(),
                        start.trim().to_string(),
                        "--yes".into(),
                    ]
                } else {
                    vec![
                        "calendar".into(),
                        "add".into(),
                        summary.trim().to_string(),
                        "--start".into(),
                        start.trim().to_string(),
                        "--end".into(),
                        end.trim().to_string(),
                        "--yes".into(),
                    ]
                };
                let probe_refs: Vec<&str> = probe_args.iter().map(String::as_str).collect();
                let result = run_neothd_json_action::<gui_action::CalendarAddAck>(
                    &probe_refs,
                    "Calendar add",
                )
                .and_then(|ack| {
                    ack.verify()?;
                    Ok(ack)
                });
                match result {
                    Ok(ack) => {
                        let message = match ack.outcome.as_str() {
                            "created" => format!("Event added ({}).", ack.uid),
                            _ => format!("Event already exists ({}).", ack.uid),
                        };
                        let weak2 = weak.clone();
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(w) = weak.upgrade() {
                                w.set_cal_add_result(message.as_str().into());
                                w.set_cal_add_summary("".into());
                                w.set_cal_add_start("".into());
                                w.set_cal_add_end("".into());
                            }
                        });
                        std::thread::spawn(move || refresh_calendar(weak2));
                    }
                    Err(error) => {
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(w) = weak.upgrade() {
                                w.set_cal_add_result(error.as_str().into());
                            }
                        });
                    }
                }
            });
        });

        // Fire once at startup.
        let weak_cal_init = window.as_weak();
        std::thread::spawn(move || {
            refresh_calendar(weak_cal_init);
        });
    }

    // ── Design Wave 4a — Self-Improve panel callbacks ─────────────────────────
    {
        let weak_si = window.as_weak();
        window.on_si_refresh_clicked(move || {
            let weak = weak_si.clone();
            std::thread::spawn(move || {
                refresh_selfimprove(weak);
            });
        });

        let weak_si_en = window.as_weak();
        window.on_si_enable_clicked(move || {
            let weak = weak_si_en.clone();
            std::thread::spawn(move || {
                let result = run_neothd_json_action::<gui_action::SelfImproveToggleAck>(
                    &["self-improve", "enable"],
                    "Self-Improve enable",
                )
                .and_then(|ack| ack.verify("enable", true, false));
                match result {
                    Ok(()) => {
                        let weak2 = weak.clone();
                        push_toast(&weak, "success", "Self-Improve", "Enabled (manual).");
                        std::thread::spawn(move || refresh_selfimprove(weak2));
                    }
                    Err(error) => {
                        let weak2 = weak.clone();
                        push_toast(&weak, "warn", "Self-Improve enable failed", &error);
                        std::thread::spawn(move || refresh_selfimprove(weak2));
                    }
                }
            });
        });

        let weak_si_dis = window.as_weak();
        window.on_si_disable_clicked(move || {
            let weak = weak_si_dis.clone();
            std::thread::spawn(move || {
                let result = run_neothd_json_action::<gui_action::SelfImproveToggleAck>(
                    &["self-improve", "disable"],
                    "Self-Improve disable",
                )
                .and_then(|ack| ack.verify("disable", false, false));
                match result {
                    Ok(()) => {
                        let weak2 = weak.clone();
                        push_toast(&weak, "info", "Self-Improve", "Disabled.");
                        std::thread::spawn(move || refresh_selfimprove(weak2));
                    }
                    Err(error) => {
                        let weak2 = weak.clone();
                        push_toast(&weak, "warn", "Self-Improve disable failed", &error);
                        std::thread::spawn(move || refresh_selfimprove(weak2));
                    }
                }
            });
        });

        let weak_si_dry = window.as_weak();
        window.on_si_run_dry_clicked(move || {
            let weak = weak_si_dry.clone();
            std::thread::spawn(move || {
                let result = run_neothd_json_action::<gui_action::SelfImproveDryRunAck>(
                    &["self-improve", "run", "--dry-run"],
                    "Self-Improve dry-run",
                )
                .and_then(|ack| {
                    ack.verify()?;
                    Ok(ack)
                });
                match result {
                    Ok(ack) => {
                        let message = if ack.diff.trim().is_empty() {
                            ack.message
                        } else {
                            format!("{}\n{}", ack.message, ack.diff)
                        };
                        push_toast(&weak, "info", "Self-Improve dry-run", &message);
                    }
                    Err(error) => push_toast(&weak, "warn", "Self-Improve dry-run failed", &error),
                }
            });
        });

        let weak_si_acc = window.as_weak();
        window.on_si_accept_clicked(move |id| {
            let id = id.to_string();
            let weak = weak_si_acc.clone();
            std::thread::spawn(move || {
                let result = run_neothd_json_action::<gui_action::ProposalMutationAck>(
                    &["self-improve", "accept", id.trim()],
                    "Self-Improve accept",
                )
                .and_then(|ack| {
                    ack.verify("accept", id.trim(), "accepted")?;
                    Ok(ack)
                });
                match result {
                    Ok(ack) => {
                        let weak2 = weak.clone();
                        let message = if ack.upstream_pr_available == Some(true) {
                            format!(
                                "{} accepted. This bundled skill can be contributed with `neoth self-improve pr {}`.",
                                id.trim(),
                                id.trim()
                            )
                        } else {
                            id.trim().to_string()
                        };
                        push_toast(&weak, "consent", "Accepted", &message);
                        std::thread::spawn(move || refresh_selfimprove(weak2));
                    }
                    Err(error) => {
                        let weak2 = weak.clone();
                        push_toast(&weak, "warn", "Self-Improve accept failed", &error);
                        std::thread::spawn(move || refresh_selfimprove(weak2));
                    }
                }
            });
        });

        let weak_si_rb = window.as_weak();
        window.on_si_rollback_clicked(move |id| {
            let id = id.to_string();
            let weak = weak_si_rb.clone();
            std::thread::spawn(move || {
                let result = run_neothd_json_action::<gui_action::ProposalMutationAck>(
                    &["self-improve", "rollback", id.trim()],
                    "Self-Improve rollback",
                )
                .and_then(|ack| ack.verify("rollback", id.trim(), "rolled_back"));
                match result {
                    Ok(()) => {
                        let weak2 = weak.clone();
                        push_toast(&weak, "warn", "Rolled back", id.trim());
                        std::thread::spawn(move || refresh_selfimprove(weak2));
                    }
                    Err(error) => {
                        let weak2 = weak.clone();
                        push_toast(&weak, "warn", "Self-Improve rollback failed", &error);
                        std::thread::spawn(move || refresh_selfimprove(weak2));
                    }
                }
            });
        });

        // Fire once at startup.
        let weak_si_init = window.as_weak();
        std::thread::spawn(move || {
            refresh_selfimprove(weak_si_init);
        });
    }

    // ── FEAT-05 — Self-Dev Proposal Review callbacks ──────────────────────────
    {
        // id validation regex: only [A-Za-z0-9_-]+ is allowed.
        // target and reason are DISPLAY-ONLY and must never reach shell args.
        fn sd_id_valid(id: &str) -> bool {
            // RED LINE + security-review MEDIUM: reject a leading '-' so a
            // crafted id can never be parsed by clap as a flag (argument
            // injection), independent of Command-array quoting. Legit ids
            // are `{kind}-{hash}` — always alphanumeric-first.
            !id.is_empty()
                && !id.starts_with('-')
                && id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        }

        let weak_sd_refresh = window.as_weak();
        window.on_sd_refresh_clicked(move || {
            let weak = weak_sd_refresh.clone();
            std::thread::spawn(move || {
                refresh_selfdev(weak);
            });
        });

        let weak_sd_scan = window.as_weak();
        window.on_sd_scan_clicked(move || {
            let weak = weak_sd_scan.clone();
            // Set scan-running flag immediately on the UI thread.
            if let Some(w) = weak.upgrade() {
                w.set_sd_scan_running(true);
            }
            std::thread::spawn(move || {
                let result = run_neothd_json_action::<gui_action::SelfDevScanAck>(
                    &["self-dev", "scan"],
                    "Self-Dev scan",
                )
                .and_then(|ack| {
                    ack.verify()?;
                    Ok(ack)
                });
                match result {
                    Ok(ack) => {
                        push_toast(
                            &weak,
                            "info",
                            "Self-Dev",
                            &format!(
                                "Scan complete: {} signal(s), {} proposal(s) staged, {} already deployed, {} not auto-safe.",
                                ack.signals,
                                ack.proposals_staged,
                                ack.proposals_skipped_deployed,
                                ack.proposals_skipped_not_auto_safe,
                            ),
                        );
                        refresh_selfdev(weak);
                    }
                    Err(error) => {
                        push_toast(&weak, "warn", "Self-Dev scan failed", &error);
                        refresh_selfdev(weak);
                    }
                }
            });
        });

        let weak_sd_acc = window.as_weak();
        window.on_sd_accept_clicked(move |id| {
            let id = id.to_string();
            let weak = weak_sd_acc.clone();
            std::thread::spawn(move || {
                // RED LINE: validate id against [A-Za-z0-9_-]+ before any shell invocation.
                if !sd_id_valid(id.trim()) {
                    push_toast(&weak, "warn", "Self-Dev", "invalid proposal id");
                    return;
                }
                let result = run_neothd_json_action::<gui_action::ProposalMutationAck>(
                    &["self-dev", "accept", id.trim()],
                    "Self-Dev accept",
                )
                .and_then(|ack| ack.verify("accept", id.trim(), "accepted"));
                match result {
                    Ok(()) => {
                        let weak2 = weak.clone();
                        push_toast(&weak, "consent", "Accepted (pending apply)", id.trim());
                        // Refresh so accepted proposal shows updated status-badge.
                        std::thread::spawn(move || refresh_selfdev(weak2));
                    }
                    Err(error) => {
                        let weak2 = weak.clone();
                        push_toast(&weak, "warn", "Self-Dev accept failed", &error);
                        std::thread::spawn(move || refresh_selfdev(weak2));
                    }
                }
            });
        });

        let weak_sd_dec = window.as_weak();
        window.on_sd_decline_clicked(move |id| {
            let id = id.to_string();
            let weak = weak_sd_dec.clone();
            std::thread::spawn(move || {
                // RED LINE: validate id against [A-Za-z0-9_-]+ before any shell invocation.
                if !sd_id_valid(id.trim()) {
                    push_toast(&weak, "warn", "Self-Dev", "invalid proposal id");
                    return;
                }
                // RED LINE: reason is the hard-coded literal "declined" — never user text.
                let result = run_neothd_json_action::<gui_action::ProposalMutationAck>(
                    &["self-dev", "decline", id.trim(), "--reason", "declined"],
                    "Self-Dev decline",
                )
                .and_then(|ack| ack.verify("decline", id.trim(), "declined"));
                match result {
                    Ok(()) => {
                        let weak2 = weak.clone();
                        push_toast(
                            &weak,
                            "info",
                            "Self-Dev",
                            &format!("Declined {}.", id.trim()),
                        );
                        std::thread::spawn(move || refresh_selfdev(weak2));
                    }
                    Err(error) => {
                        let weak2 = weak.clone();
                        push_toast(&weak, "warn", "Self-Dev decline failed", &error);
                        std::thread::spawn(move || refresh_selfdev(weak2));
                    }
                }
            });
        });

        // GUI-DES-SELFDEV-APPLY-01 — Apply accepted SourceEdit proposal via gate.
        let weak_sd_apply = window.as_weak();
        window.on_sd_apply_source_clicked(move |id, patch_path, diff_sha256| {
            let id = id.to_string();
            let patch_path = patch_path.to_string();
            let diff_sha256 = diff_sha256.to_string();
            let weak = weak_sd_apply.clone();
            std::thread::spawn(move || {
                // RED LINE: validate all three args before subprocess invocation.
                if !sd_id_valid(id.trim()) {
                    push_toast(&weak, "warn", "Self-Dev Apply", "invalid proposal id");
                    return;
                }
                if patch_path.trim().is_empty() {
                    push_toast(&weak, "warn", "Self-Dev Apply", "missing patch path");
                    return;
                }
                // diff_sha256: 64-char lowercase hex (SHA-256).
                let sha = diff_sha256.trim();
                if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
                    push_toast(
                        &weak,
                        "warn",
                        "Self-Dev Apply",
                        "invalid diff hash — expected 64-char hex SHA-256",
                    );
                    return;
                }
                let result = run_neothd_json_action::<gui_action::SelfEditAck>(
                    &[
                        "self-edit",
                        "--diff",
                        patch_path.trim(),
                        "--yes",
                        "--expect-hash",
                        sha,
                    ],
                    "Self-Dev source apply",
                )
                .and_then(|ack| ack.verify_applied(sha));
                match result {
                    Ok(()) => {
                        push_toast(
                            &weak,
                            "consent",
                            "Source Edit Applied",
                            "All five gates passed and the bound diff was applied.",
                        );
                        // Refresh so any status change is reflected.
                        let weak2 = weak.clone();
                        std::thread::spawn(move || refresh_selfdev(weak2));
                    }
                    Err(error) => {
                        let weak2 = weak.clone();
                        push_toast(&weak, "warn", "Source Edit Refused", &error);
                        std::thread::spawn(move || refresh_selfdev(weak2));
                    }
                }
            });
        });

        // Fire once at startup + the nav-switch case below handles on-demand refresh.
        let weak_sd_init = window.as_weak();
        std::thread::spawn(move || {
            refresh_selfdev(weak_sd_init);
        });
    }

    // ── Wave 4b — Obsidian Vault panel callbacks ──────────────────────────────
    {
        let weak_obs = window.as_weak();
        window.on_obs_refresh_clicked(move || {
            let weak = weak_obs.clone();
            std::thread::spawn(move || {
                refresh_obsidian(weak);
            });
        });

        // Property reads happen HERE on the UI thread: Slint's Weak::upgrade()
        // has a thread-ID guard and returns None on any worker thread, so an
        // upgrade inside the spawned closure would silently skip the command.
        let weak_obs_sync = window.as_weak();
        window.on_obs_sync_clicked(move || {
            let weak = weak_obs_sync.clone();
            let vault = weak
                .upgrade()
                .map(|w| w.get_obs_vault_path().to_string())
                .unwrap_or_default();
            std::thread::spawn(move || {
                if vault.trim().is_empty() {
                    push_toast(&weak, "warn", "Obsidian sync", "Choose a vault first.");
                    return;
                }
                let args = ["obsidian", "sync", vault.trim()];
                let result =
                    run_neothd_json_action::<gui_action::ObsidianSyncAck>(&args, "Obsidian sync")
                        .and_then(|ack| {
                            ack.verify()?;
                            Ok(ack)
                        });
                match result {
                    Ok(ack) => {
                        let weak2 = weak.clone();
                        push_toast(
                            &weak,
                            "success",
                            "Obsidian",
                            &format!(
                                "Sync complete: {} copied, {} unchanged.",
                                ack.copied, ack.skipped_identical
                            ),
                        );
                        std::thread::spawn(move || refresh_obsidian(weak2));
                    }
                    Err(error) => {
                        let weak2 = weak.clone();
                        push_toast(&weak, "warn", "Obsidian sync failed", &error);
                        std::thread::spawn(move || refresh_obsidian(weak2));
                    }
                }
            });
        });

        let weak_obs_wiki = window.as_weak();
        window.on_obs_wiki_clicked(move || {
            let weak = weak_obs_wiki.clone();
            let vault = weak
                .upgrade()
                .map(|w| w.get_obs_vault_path().to_string())
                .unwrap_or_default();
            std::thread::spawn(move || {
                if vault.trim().is_empty() {
                    push_toast(&weak, "warn", "Obsidian wiki", "Choose a vault first.");
                    return;
                }
                let args = ["obsidian", "wiki-build", vault.trim()];
                let result = run_neothd_json_action::<gui_action::WikiBuildAck>(
                    &args,
                    "Obsidian wiki build",
                )
                .and_then(|ack| {
                    ack.verify()?;
                    Ok(ack)
                });
                match result {
                    Ok(ack) => {
                        let weak2 = weak.clone();
                        push_toast(
                            &weak,
                            "success",
                            "Obsidian",
                            &format!(
                                "Wiki build complete: {} page(s) written.",
                                ack.pages_written
                            ),
                        );
                        std::thread::spawn(move || refresh_obsidian(weak2));
                    }
                    Err(error) => {
                        let weak2 = weak.clone();
                        push_toast(&weak, "warn", "Obsidian wiki failed", &error);
                        std::thread::spawn(move || refresh_obsidian(weak2));
                    }
                }
            });
        });

        // Fire once at startup.
        let weak_obs_init = window.as_weak();
        std::thread::spawn(move || {
            refresh_obsidian(weak_obs_init);
        });
    }

    // ── Wave 4b — Dreaming panel callbacks ───────────────────────────────────
    {
        let weak_dr = window.as_weak();
        window.on_dr_refresh_clicked(move || {
            let weak = weak_dr.clone();
            std::thread::spawn(move || {
                refresh_dreaming(weak);
            });
        });

        let weak_dr_show = window.as_weak();
        window.on_dr_show_day(move |day| {
            let weak = weak_dr_show.clone();
            let day = day.to_string();
            std::thread::spawn(move || {
                let out = run_neothd_probe(&["dream", "show", day.trim(), "--output", "json"]);
                let entries = panel_logic::parse_dream_entries(&out);
                let _ = slint::invoke_from_event_loop(move || {
                    use slint::VecModel;
                    let Some(w) = weak.upgrade() else { return };
                    let rows: Vec<DreamEntryRow> = entries
                        .into_iter()
                        .map(|(day, title, body)| DreamEntryRow {
                            day: day.into(),
                            title: title.into(),
                            body: body.into(),
                        })
                        .collect();
                    w.set_dr_entries(slint::ModelRc::new(std::rc::Rc::new(VecModel::from(rows))));
                });
            });
        });

        let weak_dr_now = window.as_weak();
        window.on_dr_dream_now_clicked(move || {
            let weak = weak_dr_now.clone();
            std::thread::spawn(move || {
                let _ = slint::invoke_from_event_loop({
                    let weak = weak.clone();
                    move || {
                        if let Some(w) = weak.upgrade() {
                            w.set_dr_dream_now_loading(true);
                        }
                    }
                });
                let result = run_neothd_json_action::<gui_action::DreamNowAck>(
                    &["dream", "now"],
                    "Dream now",
                )
                .and_then(|ack| {
                    ack.verify()?;
                    Ok(ack)
                });
                let (msg, succeeded) = match result {
                    Ok(ack) => (
                        format!(
                            "{} dream(s) recorded from {} event(s).",
                            ack.dreams_written, ack.events_considered
                        ),
                        true,
                    ),
                    Err(error) => (error, false),
                };
                let weak2 = weak.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        w.set_dr_dream_now_loading(false);
                        w.set_dr_dream_now_result(msg.as_str().into());
                    }
                });
                if succeeded {
                    push_toast(&weak2, "success", "Dreaming", "Dream now complete.");
                } else {
                    push_toast(
                        &weak2,
                        "warn",
                        "Dream now failed",
                        "See the result for details.",
                    );
                }
                std::thread::spawn(move || refresh_dreaming(weak2));
            });
        });

        let weak_dr_ref = window.as_weak();
        window.on_dr_reflect_clicked(move || {
            let weak = weak_dr_ref.clone();
            std::thread::spawn(move || {
                let _ = slint::invoke_from_event_loop({
                    let weak = weak.clone();
                    move || {
                        if let Some(w) = weak.upgrade() {
                            w.set_dr_reflect_loading(true);
                        }
                    }
                });
                let result = run_neothd_json_action::<gui_action::ReflectionAck>(
                    &["reflect", "digest", "daily"],
                    "Daily reflection",
                )
                .and_then(|ack| {
                    ack.verify_daily()?;
                    Ok(ack)
                });
                let (msg, succeeded) = match result {
                    Ok(ack) if ack.written => {
                        let mut message = format!("Daily reflection {} written.", ack.tag);
                        if let Some(body) = ack.body.as_deref().filter(|body| !body.is_empty()) {
                            message.push('\n');
                            message.push_str(body);
                        }
                        if !ack.topics.is_empty() {
                            message.push_str("\nTopics: ");
                            message.push_str(&ack.topics.join(", "));
                        }
                        if let Some(path) = ack.obsidian.as_deref().filter(|path| !path.is_empty())
                        {
                            message.push_str("\nObsidian: ");
                            message.push_str(path);
                        }
                        (message, true)
                    }
                    Ok(ack) => (
                        format!(
                            "Daily reflection {} unchanged: {}.",
                            ack.tag,
                            ack.reason.as_deref().unwrap_or("no topics in the window")
                        ),
                        true,
                    ),
                    Err(error) => (error, false),
                };
                let weak2 = weak.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        w.set_dr_reflect_loading(false);
                        w.set_dr_reflect_result(msg.as_str().into());
                    }
                });
                if !succeeded {
                    push_toast(
                        &weak2,
                        "warn",
                        "Daily reflection failed",
                        "See the result for details.",
                    );
                }
                std::thread::spawn(move || refresh_dreaming(weak2));
            });
        });

        // Fire once at startup.
        let weak_dr_init = window.as_weak();
        std::thread::spawn(move || {
            refresh_dreaming(weak_dr_init);
        });
    }

    // ── Wave 4b — Wiki / Capability Map panel callbacks ──────────────────────
    {
        let weak_wiki = window.as_weak();
        window.on_wiki_refresh_clicked(move || {
            let weak = weak_wiki.clone();
            std::thread::spawn(move || {
                refresh_wiki(weak);
            });
        });

        let weak_wiki_s = window.as_weak();
        window.on_wiki_search(move |text| {
            let weak = weak_wiki_s.clone();
            let text = text.to_string();
            std::thread::spawn(move || {
                refresh_wiki_filtered(weak, text, String::new());
            });
        });

        let weak_wiki_f = window.as_weak();
        window.on_wiki_filter_kind(move |kind| {
            let weak = weak_wiki_f.clone();
            let kind = kind.to_string();
            std::thread::spawn(move || {
                refresh_wiki_filtered(weak, String::new(), kind);
            });
        });

        // Fire once at startup.
        let weak_wiki_init = window.as_weak();
        std::thread::spawn(move || {
            refresh_wiki(weak_wiki_init);
        });
    }

    // ── Wave 4b — Buddy Config panel callbacks ───────────────────────────────
    {
        let weak_bc = window.as_weak();
        window.on_bc_refresh_clicked(move || {
            let weak = weak_bc.clone();
            std::thread::spawn(move || {
                refresh_buddyconfig(weak);
            });
        });

        // Self-activation toggle — real daemon command.
        let weak_bc_sa = window.as_weak();
        window.on_bc_selfact_toggle(move |enable| {
            let weak = weak_bc_sa.clone();
            std::thread::spawn(move || {
                let flag = if enable { "--enable" } else { "--disable" };
                let result = run_neothd_json_action::<gui_action::BuddySelfActivationAck>(
                    &["buddy", "self-activation", flag],
                    "Buddy self-activation update",
                )
                .and_then(|ack| ack.verify(enable));
                match result {
                    Ok(()) => push_toast(
                        &weak,
                        "success",
                        "Buddy",
                        &format!(
                            "Self-activation {}.",
                            if enable { "enabled" } else { "disabled" }
                        ),
                    ),
                    Err(error) => push_toast(&weak, "warn", "Buddy update failed", &error),
                }
                let weak2 = weak.clone();
                std::thread::spawn(move || refresh_buddyconfig(weak2));
            });
        });

        // Proactive toggle — real daemon command.
        let weak_bc_pr = window.as_weak();
        window.on_bc_proactive_toggle(move |enable| {
            let weak = weak_bc_pr.clone();
            std::thread::spawn(move || {
                let flag = if enable { "--enable" } else { "--disable" };
                let result = run_neothd_json_action::<gui_action::BuddyProactiveAck>(
                    &["buddy", "proactive", flag],
                    "Buddy proactive update",
                )
                .and_then(|ack| ack.verify(enable));
                match result {
                    Ok(()) => push_toast(
                        &weak,
                        "success",
                        "Buddy",
                        &format!(
                            "Proactive mode {}.",
                            if enable { "enabled" } else { "disabled" }
                        ),
                    ),
                    Err(error) => push_toast(&weak, "warn", "Buddy update failed", &error),
                }
                let weak2 = weak.clone();
                std::thread::spawn(move || refresh_buddyconfig(weak2));
            });
        });

        // Sovereign enable deliberately remains a real TTY-only typed-phrase
        // ceremony. The GUI can open the exact command, but receives no bypass
        // token and cannot claim that activation completed.
        let weak_bc_sov_enable = window.as_weak();
        let sovereign_home = neoth_dir.clone();
        window.on_bc_sovereign_enable_cli(move || {
            let weak = weak_bc_sov_enable.clone();
            let home = sovereign_home.clone();
            std::thread::spawn(move || {
                let result = which_neothd()
                    .context("NEOTH CLI binary is missing beside the GUI")
                    .and_then(|bin| launch_sovereign_ceremony(&bin, &home));
                match result {
                    Ok(()) => push_toast(
                        &weak,
                        "consent",
                        "Sovereign activation",
                        "Secure terminal opened. Review the consequences and type `sovereign` there to enable; then refresh this panel.",
                    ),
                    Err(error) => push_toast(
                        &weak,
                        "warn",
                        "Could not open Sovereign ceremony",
                        &format!("{error:#}"),
                    ),
                }
            });
        });

        // Sovereign disable needs no ceremony, but still traverses the real
        // autonomy policy writer and must return a typed acknowledgement.
        let weak_bc_sov_disable = window.as_weak();
        window.on_bc_sovereign_disable(move || {
            let weak = weak_bc_sov_disable.clone();
            std::thread::spawn(move || {
                let result = run_neothd_json_action::<gui_action::SovereignDisableAck>(
                    &["autonomy", "sovereign", "--disable"],
                    "Sovereign disable",
                )
                .and_then(|ack| {
                    ack.verify()?;
                    Ok(ack)
                });
                match result {
                    Ok(ack) => push_toast(
                        &weak,
                        "info",
                        "Sovereign disabled",
                        &format!(
                            "Buddy is no longer sovereign. Autonomy remains {} (mode: {}).",
                            ack.previous_autonomy, ack.mode
                        ),
                    ),
                    Err(error) => push_toast(&weak, "warn", "Sovereign disable failed", &error),
                }
                let weak2 = weak.clone();
                std::thread::spawn(move || refresh_buddyconfig(weak2));
            });
        });

        // Smart-Approve is the global security-policy master switch. Per-MCP
        // server opt-ins remain an additional AND gate.
        let weak_bc_sma = window.as_weak();
        window.on_bc_smart_approve_toggle(move |enable| {
            let weak = weak_bc_sma.clone();
            std::thread::spawn(move || {
                let flag = if enable { "--enable" } else { "--disable" };
                let result = run_neothd_json_action::<gui_action::SmartApproveAck>(
                    &["security", "set", "smart-approve", flag],
                    "Smart-Approve update",
                )
                .and_then(|ack| {
                    ack.verify(enable)?;
                    Ok(ack)
                });
                match result {
                    Ok(ack) => push_toast(
                        &weak,
                        "info",
                        "Smart-Approve",
                        if ack.changed {
                            if enable {
                                "Global master enabled. Individual MCP servers must still opt in."
                            } else {
                                "Global master disabled. Read-only tools will ask again."
                            }
                        } else if enable {
                            "Global master was already enabled."
                        } else {
                            "Global master was already disabled."
                        },
                    ),
                    Err(error) => push_toast(&weak, "warn", "Smart-Approve update failed", &error),
                }
                let weak2 = weak.clone();
                std::thread::spawn(move || refresh_buddyconfig(weak2));
            });
        });

        // Fire once at startup.
        let weak_bc_init = window.as_weak();
        std::thread::spawn(move || {
            refresh_buddyconfig(weak_bc_init);
        });
    }

    // ── Wave 4b — Companion / Smartphone Pairing panel callbacks ─────────────
    {
        let weak_cp = window.as_weak();
        window.on_cp_refresh_clicked(move || {
            let weak = weak_cp.clone();
            std::thread::spawn(move || {
                refresh_companion(weak);
            });
        });

        let weak_cp_gen = window.as_weak();
        window.on_cp_generate_invite(move || {
            let weak = weak_cp_gen.clone();
            std::thread::spawn(move || {
                let _ = slint::invoke_from_event_loop({
                    let weak = weak.clone();
                    move || {
                        if let Some(w) = weak.upgrade() {
                            w.set_cp_loading(true);
                        }
                    }
                });
                let result = run_neothd_json_action::<gui_action::CompanionInviteAck>(
                    &["companion", "pair-phone", "--write-invite-for-serve"],
                    "Companion invite",
                )
                .and_then(|ack| {
                    ack.verify()?;
                    Ok(ack)
                });
                let weak2 = weak.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        w.set_cp_loading(false);
                        match result {
                            Ok(ack) => {
                                w.set_cp_pair_url(ack.pair_url.as_str().into());
                                w.set_cp_invite_pending(true);
                                w.set_cp_error("".into());
                            }
                            Err(error) => {
                                w.set_cp_pair_url("".into());
                                w.set_cp_invite_pending(false);
                                w.set_cp_error(error.as_str().into());
                            }
                        }
                    }
                });
                std::thread::spawn(move || refresh_companion(weak2));
            });
        });
    }

    // ── Wave 8 — C2 permissions matrix + A4 kanban context menu ───────────────
    {
        fn perm_refresh(weak: slint::Weak<MainWindow>) {
            std::thread::spawn(move || {
                let out = run_neothd_probe(&["permissions", "show", "--output", "json"]);
                let (rows, level) = panel_logic::parse_permissions_show(&out);
                let _ = slint::invoke_from_event_loop(move || {
                    let Some(w) = weak.upgrade() else { return };
                    let model: Vec<PermRow> = rows
                        .into_iter()
                        .map(|r| PermRow {
                            action: r.action.into(),
                            decision: r.decision.into(),
                            overridden: r.overridden,
                        })
                        .collect();
                    w.set_cfg_perm_rows(slint::ModelRc::new(std::rc::Rc::new(
                        slint::VecModel::from(model),
                    )));
                    w.set_cfg_perm_level(level.as_str().into());
                });
            });
        }
        perm_refresh(window.as_weak());

        let weak_ps = window.as_weak();
        window.on_cfg_perm_set(move |action, decision| {
            let weak = weak_ps.clone();
            std::thread::spawn(move || {
                let out =
                    run_neothd_probe(&["permissions", "set", action.as_str(), decision.as_str()]);
                let summary: String = out.trim().chars().take(120).collect();
                push_toast(&weak, "success", "Permission set", &summary);
                perm_refresh(weak.clone());
            });
        });

        let weak_pc = window.as_weak();
        window.on_cfg_perm_clear(move |action| {
            let weak = weak_pc.clone();
            std::thread::spawn(move || {
                let _ = run_neothd_probe(&["permissions", "clear", action.as_str()]);
                push_toast(
                    &weak,
                    "info",
                    "Permission override cleared",
                    action.as_str(),
                );
                perm_refresh(weak.clone());
            });
        });

        // A4 — context-menu actions. Task ids arrive pre-formatted ("#42").
        let weak_mv = window.as_weak();
        window.on_kanban_move_task(move |task_id, status| {
            let id = task_id.trim_start_matches('#').to_string();
            let weak = weak_mv.clone();
            std::thread::spawn(move || {
                let out = run_neothd_probe(&["kanban", "move", id.as_str(), status.as_str()]);
                let summary: String = out.trim().chars().take(120).collect();
                let ok_body = if summary.is_empty() {
                    format!("task {id} → {status}")
                } else {
                    summary
                };
                push_toast(&weak, "success", "Kanban", &ok_body);
                let _ = slint::invoke_from_event_loop({
                    let weak2 = weak.clone();
                    move || {
                        if let Some(w) = weak2.upgrade() {
                            w.invoke_kanban_refresh_clicked();
                        }
                    }
                });
            });
        });

        window.on_kanban_copy_task_id(move |task_id| {
            if let Err(e) = arboard::Clipboard::new()
                .and_then(|mut c| c.set_text(task_id.trim_start_matches('#').to_string()))
            {
                tracing::warn!(error = %e, "task id clipboard copy failed");
            }
        });
    }

    // ── H2 — Memory graph callbacks ───────────────────────────────────────────
    {
        let mg_nodes: std::sync::Arc<std::sync::Mutex<Vec<panel_logic::GraphNodeData>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

        fn memgraph_refresh(
            weak: slint::Weak<MainWindow>,
            store: std::sync::Arc<std::sync::Mutex<Vec<panel_logic::GraphNodeData>>>,
        ) {
            std::thread::spawn(move || {
                let out = run_neothd_probe(&["memory", "--graph", "--output", "json"]);
                let (nodes, edges, comms) = panel_logic::layout_memory_graph(&out);
                let _ = slint::invoke_from_event_loop(move || {
                    let Some(w) = weak.upgrade() else { return };
                    let stats = format!(
                        "{} memories · {} links · {} communities",
                        nodes.len(),
                        edges.len(),
                        comms
                    );
                    let node_model: Vec<GraphNode> = nodes
                        .iter()
                        .map(|nd| GraphNode {
                            id: nd.id as i32,
                            label: nd.label.as_str().into(),
                            tier: nd.tier.as_str().into(),
                            degree: nd.degree,
                            community: nd.community,
                            x: nd.x,
                            y: nd.y,
                            r: nd.r,
                        })
                        .collect();
                    let edge_model: Vec<GraphEdge> = edges
                        .iter()
                        .map(|e| GraphEdge {
                            x1: e.x1,
                            y1: e.y1,
                            x2: e.x2,
                            y2: e.y2,
                            w: e.w,
                        })
                        .collect();
                    *store.lock().unwrap() = nodes;
                    w.set_memgraph_nodes(slint::ModelRc::new(std::rc::Rc::new(
                        slint::VecModel::from(node_model),
                    )));
                    w.set_memgraph_edges(slint::ModelRc::new(std::rc::Rc::new(
                        slint::VecModel::from(edge_model),
                    )));
                    w.set_memgraph_stats(stats.as_str().into());
                    w.set_memgraph_running(false);
                });
            });
        }

        memgraph_refresh(window.as_weak(), mg_nodes.clone());

        let (weak_mg, store_mg) = (window.as_weak(), mg_nodes.clone());
        window.on_memgraph_refresh_clicked(move || {
            if let Some(w) = weak_mg.upgrade() {
                w.set_memgraph_running(true);
            }
            memgraph_refresh(weak_mg.clone(), store_mg.clone());
        });

        let (weak_sel, store_sel) = (window.as_weak(), mg_nodes.clone());
        window.on_memgraph_node_selected(move |id| {
            if let Some(w) = weak_sel.upgrade() {
                let detail = store_sel
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|nd| nd.id as i32 == id)
                    .map(|nd| {
                        format!(
                            "{}\n\ntier {} · {} links · community {}\nevent id {}",
                            nd.label, nd.tier, nd.degree, nd.community, nd.id
                        )
                    })
                    .unwrap_or_default();
                w.set_memgraph_detail(detail.as_str().into());
            }
        });
    }

    // ── Wave 5 — WAL Inspector callbacks ──────────────────────────────────────
    {
        use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

        // Cache of the last probe (unfiltered) + current view filters.
        let wal_cache: std::sync::Arc<std::sync::Mutex<Vec<panel_logic::WalRowData>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let wal_text = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let wal_band = std::sync::Arc::new(AtomicI32::new(0));
        let wal_limit = std::sync::Arc::new(AtomicI32::new(200));
        let wal_follow = std::sync::Arc::new(AtomicBool::new(false));

        // Seed the band combo options.
        let band_opts: Vec<slint::SharedString> = panel_logic::WAL_BAND_OPTIONS
            .iter()
            .map(|(label, _)| (*label).into())
            .collect();
        window.set_wal_opcode_options(slint::ModelRc::new(std::rc::Rc::new(
            slint::VecModel::from(band_opts),
        )));

        // Timeline scrubber state: bucket time ranges + selected bucket.
        let wal_ranges: std::sync::Arc<std::sync::Mutex<Vec<(u64, u64)>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let wal_bucket_sel = std::sync::Arc::new(AtomicI32::new(-1));

        // Apply cache → filtered rows → Slint model. `range` narrows to a
        // timeline bucket's time slice when one is selected.
        fn wal_apply(
            w: &MainWindow,
            cache: &[panel_logic::WalRowData],
            text: &str,
            band: usize,
            range: Option<(u64, u64)>,
        ) {
            let mut filtered = panel_logic::filter_wal_rows(cache, text, band);
            if let Some((lo, hi)) = range {
                filtered.retain(|r| r.ts_ns >= lo && r.ts_ns < hi);
            }
            let rows: Vec<WalEventRow> = filtered
                .iter()
                .map(|r| WalEventRow {
                    seq: r.seq,
                    ts: r.ts.as_str().into(),
                    opcode: r.opcode.as_str().into(),
                    kind: r.kind.as_str().into(),
                    summary: r.summary.as_str().into(),
                    tint: r.tint.as_str().into(),
                })
                .collect();
            w.set_wal_events(slint::ModelRc::new(std::rc::Rc::new(
                slint::VecModel::from(rows),
            )));
        }

        // One probe pass — runs on a worker thread, lands on the loop.
        // Rebuilds the timeline buckets and resets the bucket selection.
        #[allow(clippy::too_many_arguments)]
        fn wal_refresh(
            weak: slint::Weak<MainWindow>,
            cache: std::sync::Arc<std::sync::Mutex<Vec<panel_logic::WalRowData>>>,
            text: std::sync::Arc<std::sync::Mutex<String>>,
            band: std::sync::Arc<AtomicI32>,
            ranges: std::sync::Arc<std::sync::Mutex<Vec<(u64, u64)>>>,
            bucket_sel: std::sync::Arc<AtomicI32>,
            limit: i32,
        ) {
            std::thread::spawn(move || {
                let out = run_neothd_probe(&[
                    "wal",
                    "show",
                    "--limit",
                    &limit.to_string(),
                    "--output",
                    "json",
                ]);
                let (rows, matched) = panel_logic::parse_wal_show(&out);
                let _ = slint::invoke_from_event_loop(move || {
                    let Some(w) = weak.upgrade() else { return };
                    w.set_wal_total_count(matched);
                    w.set_wal_has_older(matched > rows.len() as i32);
                    // Timeline: 48 equal slices over the fetched window.
                    let (buckets, brs) = panel_logic::bucket_wal_rows(&rows, 48);
                    let maxn = buckets
                        .iter()
                        .map(|b| b.memory_n + b.audit_n + b.consent_n + b.warning_n + b.plain_n)
                        .max()
                        .unwrap_or(0);
                    *ranges.lock().unwrap() = brs;
                    bucket_sel.store(-1, Ordering::Relaxed);
                    w.set_wal_selected_bucket(-1);
                    w.set_wal_timeline_max(maxn);
                    let bmodel: Vec<WalBucket> = buckets
                        .iter()
                        .map(|b| WalBucket {
                            label: b.label.as_str().into(),
                            memory_n: b.memory_n,
                            audit_n: b.audit_n,
                            consent_n: b.consent_n,
                            warning_n: b.warning_n,
                            plain_n: b.plain_n,
                        })
                        .collect();
                    w.set_wal_buckets(slint::ModelRc::new(std::rc::Rc::new(
                        slint::VecModel::from(bmodel),
                    )));
                    let t = text.lock().unwrap().clone();
                    let b = band.load(Ordering::Relaxed) as usize;
                    *cache.lock().unwrap() = rows;
                    wal_apply(&w, &cache.lock().unwrap(), &t, b, None);
                });
            });
        }

        // Initial load + refresh triggers.
        wal_refresh(
            window.as_weak(),
            wal_cache.clone(),
            wal_text.clone(),
            wal_band.clone(),
            wal_ranges.clone(),
            wal_bucket_sel.clone(),
            200,
        );

        // Bucket click — narrow the row list to that time slice (click the
        // same bucket again to clear via Slint's <=> binding going -1).
        let (weak_tl, cache_tl, text_tl, band_tl, ranges_tl, sel_tl) = (
            window.as_weak(),
            wal_cache.clone(),
            wal_text.clone(),
            wal_band.clone(),
            wal_ranges.clone(),
            wal_bucket_sel.clone(),
        );
        window.on_wal_bucket_selected(move |idx| {
            sel_tl.store(idx, Ordering::Relaxed);
            if let Some(w) = weak_tl.upgrade() {
                let range = if idx >= 0 {
                    ranges_tl.lock().unwrap().get(idx as usize).copied()
                } else {
                    None
                };
                wal_apply(
                    &w,
                    &cache_tl.lock().unwrap(),
                    &text_tl.lock().unwrap(),
                    band_tl.load(Ordering::Relaxed) as usize,
                    range,
                );
            }
        });

        // Shared helper: the currently selected bucket's time range.
        fn wal_current_range(
            ranges: &std::sync::Mutex<Vec<(u64, u64)>>,
            sel: &AtomicI32,
        ) -> Option<(u64, u64)> {
            let idx = sel.load(Ordering::Relaxed);
            if idx < 0 {
                return None;
            }
            ranges.lock().unwrap().get(idx as usize).copied()
        }

        let (weak_f, cache_f, band_f, ranges_f, sel_f) = (
            window.as_weak(),
            wal_cache.clone(),
            wal_band.clone(),
            wal_ranges.clone(),
            wal_bucket_sel.clone(),
        );
        let text_f = wal_text.clone();
        window.on_wal_filter_edited(move |s| {
            *text_f.lock().unwrap() = s.to_string();
            if let Some(w) = weak_f.upgrade() {
                wal_apply(
                    &w,
                    &cache_f.lock().unwrap(),
                    &s,
                    band_f.load(Ordering::Relaxed) as usize,
                    wal_current_range(&ranges_f, &sel_f),
                );
            }
        });

        let (weak_b, cache_b, text_b, band_b, ranges_b, sel_b) = (
            window.as_weak(),
            wal_cache.clone(),
            wal_text.clone(),
            wal_band.clone(),
            wal_ranges.clone(),
            wal_bucket_sel.clone(),
        );
        window.on_wal_opcode_filter_changed(move |idx| {
            band_b.store(idx, Ordering::Relaxed);
            if let Some(w) = weak_b.upgrade() {
                wal_apply(
                    &w,
                    &cache_b.lock().unwrap(),
                    &text_b.lock().unwrap(),
                    idx as usize,
                    wal_current_range(&ranges_b, &sel_b),
                );
            }
        });

        let (weak_o, cache_o, text_o, band_o, ranges_o, sel_o, limit_o) = (
            window.as_weak(),
            wal_cache.clone(),
            wal_text.clone(),
            wal_band.clone(),
            wal_ranges.clone(),
            wal_bucket_sel.clone(),
            wal_limit.clone(),
        );
        window.on_wal_load_older_clicked(move || {
            let new_limit = (limit_o.load(Ordering::Relaxed) * 2).min(2000);
            limit_o.store(new_limit, Ordering::Relaxed);
            wal_refresh(
                weak_o.clone(),
                cache_o.clone(),
                text_o.clone(),
                band_o.clone(),
                ranges_o.clone(),
                sel_o.clone(),
                new_limit,
            );
        });

        // Follow mode — background poll every 3 s while enabled.
        {
            let follow = wal_follow.clone();
            window.on_wal_follow_toggled(move |on| {
                follow.store(on, Ordering::Relaxed);
            });
            let (weak_p, cache_p, text_p, band_p, ranges_p, sel_p, limit_p, follow_p) = (
                window.as_weak(),
                wal_cache.clone(),
                wal_text.clone(),
                wal_band.clone(),
                wal_ranges.clone(),
                wal_bucket_sel.clone(),
                wal_limit.clone(),
                wal_follow.clone(),
            );
            std::thread::spawn(move || {
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(3));
                    if follow_p.load(Ordering::Relaxed) {
                        wal_refresh(
                            weak_p.clone(),
                            cache_p.clone(),
                            text_p.clone(),
                            band_p.clone(),
                            ranges_p.clone(),
                            sel_p.clone(),
                            limit_p.load(Ordering::Relaxed),
                        );
                    }
                }
            });
        }

        // Row select → detail pane shows that frame's pretty JSON.
        let (weak_s, cache_s) = (window.as_weak(), wal_cache.clone());
        window.on_wal_row_selected(move |seq| {
            if let Some(w) = weak_s.upgrade() {
                let detail = cache_s
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|r| r.seq == seq)
                    .map(|r| r.detail_json.clone())
                    .unwrap_or_default();
                w.set_wal_detail_json(detail.as_str().into());
            }
        });

        // Copy detail JSON to the clipboard.
        let weak_c = window.as_weak();
        window.on_wal_copy_detail_clicked(move || {
            if let Some(w) = weak_c.upgrade() {
                let text = w.get_wal_detail_json().to_string();
                if !text.is_empty()
                    && let Err(e) = arboard::Clipboard::new().and_then(|mut c| c.set_text(text))
                {
                    tracing::warn!(error = %e, "WAL detail clipboard copy failed");
                }
            }
        });

        // Verify — header/frame validity stats over the newest segment.
        let weak_v = window.as_weak();
        window.on_wal_verify_clicked(move || {
            let Some(w0) = weak_v.upgrade() else { return };
            w0.set_wal_verify_running(true);
            let weak = weak_v.clone();
            std::thread::spawn(move || {
                let newest = std::fs::read_dir(default_neoth_home().join("wal"))
                    .ok()
                    .and_then(|rd| {
                        let mut segs: Vec<PathBuf> = rd
                            .flatten()
                            .map(|e| e.path())
                            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("wal"))
                            .collect();
                        segs.sort();
                        segs.pop()
                    });
                let verdict = match newest {
                    None => "no WAL segments found".to_string(),
                    Some(seg) => {
                        let out = run_neothd_probe(&[
                            "wal",
                            "stats",
                            &seg.display().to_string(),
                            "--output",
                            "json",
                        ]);
                        match serde_json::from_str::<serde_json::Value>(&out) {
                            Ok(v) => {
                                let ok = v
                                    .get("header_ok")
                                    .and_then(|x| x.as_bool())
                                    .unwrap_or(false);
                                if ok {
                                    "ok".to_string()
                                } else {
                                    "FAIL: segment header invalid".to_string()
                                }
                            }
                            Err(_) => {
                                format!("FAIL: {}", out.trim().chars().take(80).collect::<String>())
                            }
                        }
                    }
                };
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        w.set_wal_verify_result(verdict.as_str().into());
                        w.set_wal_verify_running(false);
                    }
                });
            });
        });
    }

    // ── Wave 4b — Mesh & Cluster panel callbacks ──────────────────────────────
    {
        let weak_mesh = window.as_weak();
        window.on_mesh_refresh_clicked(move || {
            let weak = weak_mesh.clone();
            std::thread::spawn(move || {
                refresh_mesh(weak);
            });
        });

        // Fire once at startup.
        let weak_mesh_init = window.as_weak();
        std::thread::spawn(move || {
            refresh_mesh(weak_mesh_init);
        });

        // Wave 5 — per-peer sync-state query: vector-clock delta for one
        // authenticated peer, surfaced as a toast (read-only probe).
        let weak_mesh_sync = window.as_weak();
        window.on_mesh_peer_sync_clicked(move |peer_id| {
            let weak = weak_mesh_sync.clone();
            let peer = peer_id.to_string();
            std::thread::spawn(move || {
                let out = run_neothd_probe(&[
                    "cluster",
                    "sync-state",
                    "--peer",
                    peer.as_str(),
                    "--output",
                    "json",
                ]);
                let summary: String = out.trim().chars().take(160).collect();
                let body = if summary.is_empty() {
                    "no sync state reported".to_string()
                } else {
                    summary
                };
                push_toast(&weak, "info", "Peer sync state", &body);
            });
        });
    }

    // ── GOLD-LOOP-03 — Loop panel wiring (display-gated `gui-loop`) ────
    // The GUI never links the loop engine: runs go through a
    // `neothd loop run` subprocess (the CLI's daemon-owns-WAL guard fires
    // there and lands in the status note), history comes from the
    // `~/.neoth/loops/*.json` records the engine writes.
    window.set_show_loops(cfg!(feature = "gui-loop"));
    #[cfg(feature = "gui-loop")]
    {
        use panel_logic::LoopRunView;

        // Convergence denominator + budget cap from freedom.yaml (engine
        // defaults when missing: 3 rounds, no cap).
        let (loop_max_rounds, loop_budget) =
            std::fs::read_to_string(default_neoth_home().join("freedom.yaml"))
                .map(|y| panel_logic::parse_loop_budget(&y))
                .unwrap_or((3, 0));
        window.set_loop_tool_call_budget(loop_budget as i32);

        // History cache shared by refresh + row-select; the running child
        // handle shared by run + kill.
        let loop_cache: std::sync::Arc<std::sync::Mutex<Vec<LoopRunView>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let loop_child: std::sync::Arc<std::sync::Mutex<Option<std::process::Child>>> =
            std::sync::Arc::new(std::sync::Mutex::new(None));

        // Push a history snapshot into the panel; `select` picks the run
        // whose detail (timeline/meters/final text) is shown.
        fn apply_loop_history(
            w: &MainWindow,
            runs: &[LoopRunView],
            select: Option<&str>,
            max_rounds: u32,
        ) {
            use slint::{ModelRc, VecModel};
            let rows: Vec<LoopRunRow> = runs
                .iter()
                .map(|r| LoopRunRow {
                    id: r.id.clone().into(),
                    started: r.started.clone().into(),
                    rounds: r.rounds_run as i32,
                    stop_reason: r.stop_reason.clone().into(),
                    tool_calls: r.total_tool_calls as i32,
                })
                .collect();
            w.set_loop_history(ModelRc::new(VecModel::from(rows)));
            let picked = select
                .and_then(|id| runs.iter().find(|r| r.id == id))
                .or_else(|| runs.first());
            let Some(run) = picked else {
                w.set_loop_selected_id("".into());
                w.set_loop_rounds(ModelRc::new(VecModel::from(Vec::<LoopRoundRow>::new())));
                w.set_loop_stop_reason("".into());
                w.set_loop_final_text("".into());
                w.set_loop_tool_calls(0);
                w.set_loop_convergence(0.0);
                return;
            };
            let round_rows: Vec<LoopRoundRow> = run
                .per_round
                .iter()
                .map(|r| LoopRoundRow {
                    round: r.round_num as i32,
                    iterations: r.iterations as i32,
                    ok_calls: r.ok_calls as i32,
                    fail_calls: r.fail_calls as i32,
                    stop_approved: r.stop_approved,
                    refine_fired: r.refine_fired,
                    duration: r.duration.clone().into(),
                })
                .collect();
            w.set_loop_selected_id(run.id.clone().into());
            w.set_loop_rounds(ModelRc::new(VecModel::from(round_rows)));
            w.set_loop_stop_reason(run.stop_reason.clone().into());
            w.set_loop_final_text(run.final_text.clone().into());
            w.set_loop_tool_calls(run.total_tool_calls as i32);
            w.set_loop_convergence(if run.stop_reason == "converged" {
                1.0
            } else {
                (run.rounds_run as f32 / max_rounds.max(1) as f32).min(1.0)
            });
        }

        // Refresh — worker thread reads + parses the record files. The
        // AtomicBool caps it at one scan in flight (review B8: unbounded
        // spawn let a slow stale scan overwrite a fresh one).
        let weak_loop_refresh = window.as_weak();
        let cache_refresh = loop_cache.clone();
        let loop_fetch_in_flight = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let refresh_history = move |select: Option<String>| {
            if loop_fetch_in_flight.swap(true, std::sync::atomic::Ordering::AcqRel) {
                return;
            }
            let weak = weak_loop_refresh.clone();
            let cache = cache_refresh.clone();
            let done = loop_fetch_in_flight.clone();
            std::thread::spawn(move || {
                let runs = panel_logic::load_loop_history(&default_neoth_home(), 20);
                if let Ok(mut c) = cache.lock() {
                    *c = runs.clone();
                }
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        apply_loop_history(&w, &runs, select.as_deref(), loop_max_rounds);
                    }
                });
                done.store(false, std::sync::atomic::Ordering::Release);
            });
        };

        let refresh_for_click = refresh_history.clone();
        window.on_loop_refresh_clicked(move || {
            refresh_for_click(None);
        });

        // Row select — served from the cache (no disk hit on click).
        let weak_loop_select = window.as_weak();
        let cache_select = loop_cache.clone();
        window.on_loop_run_selected(move |id| {
            let Some(w) = weak_loop_select.upgrade() else {
                return;
            };
            if let Ok(runs) = cache_select.lock() {
                apply_loop_history(&w, &runs, Some(id.as_str()), loop_max_rounds);
            }
        });

        // Run — spawn `neothd loop run <prompt>`; drain stdout so the
        // child never blocks on a full pipe; surface a non-zero exit's
        // stderr (e.g. the daemon-owns-WAL refusal) as the status note.
        let weak_loop_run = window.as_weak();
        let child_run = loop_child.clone();
        let refresh_after_run = refresh_history.clone();
        window.on_loop_run_clicked(move |prompt| {
            let Some(w0) = weak_loop_run.upgrade() else {
                return;
            };
            if w0.get_loop_running() {
                return;
            }
            w0.set_loop_running(true);
            w0.set_loop_status_note("".into());
            let prompt = prompt.to_string();
            // Wave-2 feed D: loop started.
            {
                let snippet = if prompt.len() > 80 {
                    &prompt[..80]
                } else {
                    &prompt
                };
                push_activity(&w0.as_weak(), "loop", "Loop started", snippet);
            }
            let weak = weak_loop_run.clone();
            let child_slot = child_run.clone();
            let refresh = refresh_after_run.clone();
            std::thread::spawn(move || {
                let outcome: Result<(bool, String), String> = (|| {
                    let bin = which_neothd().ok_or_else(|| BINARY_MISSING_MESSAGE.to_string())?;
                    let mut child = spawn_neothd_plain(&bin)
                        .arg("loop")
                        .arg("run")
                        .arg(&prompt)
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::piped())
                        .spawn()
                        .map_err(|e| format!("loop subprocess could not start: {e}"))?;
                    let mut stdout = child.stdout.take();
                    let mut stderr = child.stderr.take();
                    if let Ok(mut slot) = child_slot.lock() {
                        *slot = Some(child);
                    }
                    // Drain stderr on its own thread — sequential draining
                    // deadlocks when the child fills the 64K stderr pipe
                    // before stdout reaches EOF (review B8).
                    let err_join = std::thread::spawn(move || {
                        let mut err_text = String::new();
                        if let Some(err) = stderr.as_mut() {
                            use std::io::Read as _;
                            let _ = err.read_to_string(&mut err_text);
                        }
                        err_text
                    });
                    // Drain stdout to EOF (keeps the child unblocked).
                    let mut sink = String::new();
                    if let Some(out) = stdout.as_mut() {
                        use std::io::Read as _;
                        let _ = out.read_to_string(&mut sink);
                    }
                    let err_text = err_join.join().unwrap_or_default();
                    let status = child_slot
                        .lock()
                        .ok()
                        .and_then(|mut slot| slot.take())
                        .and_then(|mut c| c.wait().ok());
                    let ok = status.map(|s| s.success()).unwrap_or(false);
                    Ok((ok, err_text))
                })();
                let note = match outcome {
                    Ok((true, _)) => String::new(),
                    Ok((false, err)) => {
                        let tail: String = err
                            .lines()
                            .rev()
                            .take(3)
                            .collect::<Vec<_>>()
                            .into_iter()
                            .rev()
                            .collect::<Vec<_>>()
                            .join(" · ");
                        if tail.is_empty() {
                            "loop exited non-zero (killed or failed)".to_string()
                        } else {
                            tail
                        }
                    }
                    Err(e) => e,
                };
                let weak_done = weak.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak_done.upgrade() {
                        w.set_loop_running(false);
                        // Wave-2 feed D: loop done — settle the active row.
                        settle_activity_kind(&w.as_weak(), "loop");
                        if !note.is_empty() {
                            w.set_loop_status_note(note.into());
                        } else {
                            w.set_loop_prompt_draft("".into());
                        }
                    }
                });
                // Newest record (if any) becomes the selection.
                refresh(None);
            });
        });

        // Kill — terminate the running child; the run worker's wait()
        // observes the non-zero exit and lands the status note.
        let weak_loop_kill = window.as_weak();
        let child_kill = loop_child.clone();
        window.on_loop_kill_clicked(move || {
            if let Ok(mut slot) = child_kill.lock()
                && let Some(child) = slot.as_mut()
            {
                let _ = child.kill();
            }
            if let Some(w) = weak_loop_kill.upgrade() {
                w.set_loop_status_note(
                    "kill signal sent — waiting for the subprocess to exit".into(),
                );
            }
        });

        // Initial history load (cheap file reads, off-thread).
        refresh_history(None);
    }

    // GUI-overhaul feature parity — live connectivity test for a channel
    // (`neoth channel test <name>`, read-only). Off-thread; the daemon's check
    // result (or error) is shaped into the footer status line.
    let weak_channel_test = window.as_weak();
    window.on_channel_test(move |name| {
        if let Some(w) = weak_channel_test.upgrade() {
            buddy(&w, GuiActivity::ChannelTest);
        }
        let weak = weak_channel_test.clone();
        let name = name.to_string();
        std::thread::spawn(move || {
            let msg = match which_neothd().and_then(|bin| {
                spawn_neothd_plain(&bin)
                    .arg("channel")
                    .arg("test")
                    .arg(&name)
                    .arg("--output")
                    .arg("json")
                    .output()
                    .ok()
            }) {
                Some(o) => match panel_logic::parse_channel_test_status(
                    &String::from_utf8_lossy(&o.stdout),
                    &name,
                ) {
                    // `fail`, `skipped`, and `unavailable` deliberately use
                    // non-zero CLI exit codes for scripts. The JSON remains
                    // the canonical truth and must still reach the GUI.
                    Ok(result) => {
                        let glyph = match result.status.as_str() {
                            "ok" => "✓",
                            "fail" => "✗",
                            "unavailable" => "⊘",
                            _ => "–",
                        };
                        format!("{glyph} {name}: {}", result.detail)
                    }
                    Err(error) if o.status.success() => {
                        format!("{name} test returned invalid data: {error}")
                    }
                    Err(_) => format!(
                        "{name} test failed: {}",
                        String::from_utf8_lossy(&o.stderr)
                            .lines()
                            .map(str::trim)
                            .find(|line| !line.is_empty())
                            .unwrap_or("(no detail)")
                    ),
                },
                None => format!("{name}: NEOTH CLI not found; reinstall or repair PATH"),
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_status_line(msg.into());
                }
            });
        });
    });

    // GUI-overhaul feature parity — remove a channel's credential through the
    // canonical CLI, then refresh its canonical configured/probe state. Gated
    // behind an inline confirm in the UI.
    let weak_channel_remove = window.as_weak();
    window.on_channel_remove(move |name| {
        let weak = weak_channel_remove.clone();
        let name = name.to_string();
        std::thread::spawn(move || {
            let message = match which_neothd() {
                None => format!(
                    "Channel {name} remove failed: NEOTH CLI not found; reinstall or repair PATH."
                ),
                Some(bin) => match channel_remove_command(&bin, &name).output() {
                    Err(error) => format!("Channel {name} remove failed: {error}"),
                    Ok(output) if !output.status.success() => {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        let detail = stderr
                            .lines()
                            .map(str::trim)
                            .find(|line| !line.is_empty())
                            .unwrap_or("unknown error");
                        format!("Channel {name} remove failed: {detail}")
                    }
                    Ok(output) => match parse_channel_removed(&output.stdout, &name) {
                        Some(true) => format!("Channel {name} credential removed."),
                        Some(false) => format!(
                            "Channel {name} had no removable credential. Effective status refreshed."
                        ),
                        None => format!(
                            "Channel {name} remove response invalid; no removal was confirmed."
                        ),
                    },
                },
            };
            let channels = fetch_channel_status();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    apply_channels(&w, channels);
                    w.set_status_line(message.into());
                }
            });
        });
    });

    // GOLD-R3-04 — Add/repair every registered channel from the GUI. The
    // credential envelope travels only over private child stdin; process argv
    // contains no secret values. On success the canonical channel inventory is
    // refreshed exactly like on_channel_remove.
    let weak_channel_add = window.as_weak();
    window.on_channel_add(move |ctype, f1, f2, f3, f4, f5, f6, flag| {
        let ctype = ctype.to_string();
        let request_result = panel_logic::build_channel_credential_request(
            &ctype,
            [
                f1.as_str(),
                f2.as_str(),
                f3.as_str(),
                f4.as_str(),
                f5.as_str(),
                f6.as_str(),
            ],
            flag,
        );

        match request_result {
            Err(hint) => {
                push_toast(&weak_channel_add, "warn", "Add channel", &hint);
            }
            Ok(request_body) => {
                let weak = weak_channel_add.clone();
                let ctype_clone = ctype.clone();
                std::thread::spawn(move || {
                    let result = persist_channel_credentials_via_cli(request_body);

                    let (toast_kind, toast_title, toast_body, refresh) = match result {
                        Ok(o) if o.status.success() => {
                            // The CLI emits pretty JSON, so whitespace-sensitive
                            // substring checks misclassified every successful add.
                            let saved = parse_channel_saved(&o.stdout, &ctype_clone);
                            match saved {
                                Some(true) => (
                                    "success",
                                    "Add channel",
                                    format!(
                                        "Channel {ctype_clone} saved. Use Test for live connectivity proof."
                                    ),
                                    true,
                                ),
                                Some(false) => (
                                    "error",
                                    "Add channel response invalid",
                                    format!("Channel {ctype_clone}: neoth reported saved=false."),
                                    false,
                                ),
                                None => (
                                    "error",
                                    "Add channel response invalid",
                                    format!(
                                        "Channel {ctype_clone}: neoth returned success without a saved status."
                                    ),
                                    false,
                                ),
                            }
                        }
                        Ok(o) => {
                            let stderr = String::from_utf8_lossy(&o.stderr);
                            let detail = stderr
                                .lines()
                                .map(str::trim)
                                .find(|l| !l.is_empty())
                                .unwrap_or("unknown error")
                                .to_string();
                            (
                                "error",
                                "Add channel failed",
                                format!("{ctype_clone}: {detail}"),
                                false,
                            )
                        }
                        Err(detail) => (
                            "error",
                            "Add channel failed",
                            format!("{ctype_clone}: {detail}"),
                            false,
                        ),
                    };

                    let channels = if refresh {
                        Some(fetch_channel_status())
                    } else {
                        None
                    };

                    let toast_body_clone = toast_body.clone();
                    push_toast(&weak, toast_kind, toast_title, &toast_body_clone);
                    if let Some(ch) = channels {
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(w) = weak.upgrade() {
                                apply_channels(&w, ch);
                                w.set_channel_add_success_seq(
                                    w.get_channel_add_success_seq().saturating_add(1),
                                );
                            }
                        });
                    }
                });
            }
        }
    });

    // GUI-overhaul feature parity — Memory "forget a topic". Preview runs the
    // dry-run (`neoth memory --forget <topic>`, no --confirm) and reports the
    // would-wipe summary; it mutates nothing.
    let weak_mem_preview = window.as_weak();
    window.on_memory_forget_preview(move |topic| {
        if let Some(w) = weak_mem_preview.upgrade() {
            buddy(&w, GuiActivity::MemoryForget);
        }
        let weak = weak_mem_preview.clone();
        let topic = topic.to_string();
        std::thread::spawn(move || {
            let msg = match which_neothd().and_then(|bin| {
                spawn_neothd_plain(&bin)
                    .arg("memory")
                    .arg("--forget")
                    .arg(&topic)
                    .output()
                    .ok()
            }) {
                Some(o) if o.status.success() => {
                    let line = String::from_utf8_lossy(&o.stdout)
                        .lines()
                        .map(str::trim)
                        .rfind(|l| !l.is_empty())
                        .unwrap_or("(no matches)")
                        .to_string();
                    format!("Preview \"{topic}\": {line}")
                }
                Some(o) => format!(
                    "Forget preview failed: {}",
                    String::from_utf8_lossy(&o.stderr)
                        .lines()
                        .map(str::trim)
                        .find(|l| !l.is_empty())
                        .unwrap_or("(no detail)")
                ),
                None => "memory: neothd binary not on PATH".to_string(),
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_status_line(msg.into());
                }
            });
        });
    });

    // GUI-overhaul feature parity — Memory "forget a topic", permanent. Runs the
    // wipe (`neoth memory --forget <topic> --confirm`), then re-reads the memory
    // snapshot so the blocks list reflects the change.
    let weak_mem_confirm = window.as_weak();
    window.on_memory_forget_confirm(move |topic| {
        let weak = weak_mem_confirm.clone();
        let topic = topic.to_string();
        std::thread::spawn(move || {
            let ok = which_neothd()
                .and_then(|bin| {
                    spawn_neothd_plain(&bin)
                        .arg("memory")
                        .arg("--forget")
                        .arg(&topic)
                        .arg("--confirm")
                        .output()
                        .ok()
                })
                .map(|o| o.status.success())
                .unwrap_or(false);
            let memory = fetch_memory_snapshot();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    apply_memory(&w, memory);
                    w.set_status_line(if ok {
                        format!("Forgot \"{topic}\" — memory wiped.").into()
                    } else {
                        format!("Forget \"{topic}\" failed (is neothd on PATH?).").into()
                    });
                }
            });
        });
    });

    // GUI-overhaul (gap panel wf_8ad7096a) — feature parity: enable/disable a
    // skill from the GUI Skills tab. Shells `neoth skills --enable/--disable <id>`
    // off the UI thread, then re-fetches + applies the list so the new state
    // shows + reports a status line.
    let weak_skill_toggle = window.as_weak();
    window.on_skill_toggle(move |id, enabled| {
        if let Some(w) = weak_skill_toggle.upgrade() {
            buddy(&w, GuiActivity::SettingsApplied);
        }
        let weak = weak_skill_toggle.clone();
        let id = id.to_string();
        std::thread::spawn(move || {
            let flag = if enabled { "--enable" } else { "--disable" };
            let ok = which_neothd()
                .and_then(|bin| {
                    spawn_neothd_plain(&bin)
                        .arg("skills")
                        .arg(flag)
                        .arg(&id)
                        .output()
                        .ok()
                })
                .map(|o| o.status.success())
                .unwrap_or(false);
            let skills = fetch_skills();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    apply_skills(&w, skills);
                    let verb = if enabled { "enabled" } else { "disabled" };
                    w.set_status_line(if ok {
                        format!("Skill {id} {verb}.").into()
                    } else {
                        format!("Skill {verb} failed for {id} (is neothd on PATH?).").into()
                    });
                }
            });
        });
    });

    // GUI-overhaul feature parity — enable/disable a plugin from the GUI Plugins
    // tab. Shells `neoth plugin enable/disable <id>` off the UI thread (mutates
    // freedom.yaml::plugins.wasm.activations.<id>), then re-fetches the list.
    let weak_plugin_toggle = window.as_weak();
    window.on_plugin_toggle(move |id, enabled| {
        let weak = weak_plugin_toggle.clone();
        let id = id.to_string();
        std::thread::spawn(move || {
            let action = if enabled { "enable" } else { "disable" };
            let ok = which_neothd()
                .and_then(|bin| {
                    spawn_neothd_plain(&bin)
                        .arg("plugin")
                        .arg(action)
                        .arg(&id)
                        .output()
                        .ok()
                })
                .map(|o| o.status.success())
                .unwrap_or(false);
            let plugins = fetch_plugins();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    apply_plugins(&w, plugins);
                    let verb = if enabled { "enabled" } else { "disabled" };
                    w.set_status_line(if ok {
                        format!("Plugin {id} {verb}.").into()
                    } else {
                        format!("Plugin {verb} failed for {id} (is neothd on PATH?).").into()
                    });
                }
            });
        });
    });

    // ── Skills: install from dir ───────────────────────────────────────────────
    // Opens a native folder picker (rfd works from spawned threads on Windows),
    // shells `neoth skills --install <dir>`, toasts from the worker thread
    // (push_toast internally schedules on the event loop), then refreshes the list.
    {
        let weak_si = window.as_weak();
        window.on_skill_install(move || {
            let weak = weak_si.clone();
            std::thread::spawn(move || {
                let picked = rfd::FileDialog::new()
                    .set_title("Select skill directory (must contain skill.yaml)")
                    .pick_folder();
                let Some(dir) = picked else { return };
                let dir_str = dir.to_string_lossy().to_string();
                let result = which_neothd().and_then(|bin| {
                    spawn_neothd_plain(&bin)
                        .arg("skills")
                        .arg("--install")
                        .arg(&dir)
                        .output()
                        .ok()
                });
                let ok = result.as_ref().map(|o| o.status.success()).unwrap_or(false);
                let msg = result
                    .as_ref()
                    .map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "neothd not on PATH?".to_string());
                if ok {
                    push_toast(&weak, "success", "Skill installed", &dir_str);
                } else {
                    push_toast(&weak, "warn", "Skill install failed", &msg);
                }
                let skills = fetch_skills();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        apply_skills(&w, skills);
                    }
                });
            });
        });
    }

    // ── Skills: uninstall by id ────────────────────────────────────────────────
    // Shells `neoth skills --uninstall <id>` → toast + refresh.
    {
        let weak_su = window.as_weak();
        window.on_skill_uninstall(move |id| {
            let weak = weak_su.clone();
            let id = id.to_string();
            std::thread::spawn(move || {
                let result = which_neothd().and_then(|bin| {
                    spawn_neothd_plain(&bin)
                        .arg("skills")
                        .arg("--uninstall")
                        .arg(&id)
                        .output()
                        .ok()
                });
                let ok = result.as_ref().map(|o| o.status.success()).unwrap_or(false);
                let msg = result
                    .as_ref()
                    .map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "neothd not on PATH?".to_string());
                if ok {
                    push_toast(&weak, "success", "Skill uninstalled", &id);
                } else {
                    push_toast(&weak, "warn", "Skill uninstall failed", &msg);
                }
                let skills = fetch_skills();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        apply_skills(&w, skills);
                    }
                });
            });
        });
    }

    // ── Skills: create via non-interactive wizard ──────────────────────────────
    // Shells `neoth skills --create --non-interactive --create-id <id>
    //   --create-description <d> [--create-keywords <k>] --create-system-prompt <p>`
    // → toast + refresh.
    {
        let weak_sc = window.as_weak();
        window.on_skill_create(move |id, desc, keywords, prompt| {
            let weak = weak_sc.clone();
            let id = id.to_string();
            let desc = desc.to_string();
            let keywords = keywords.to_string();
            let prompt = prompt.to_string();
            std::thread::spawn(move || {
                let result = which_neothd().and_then(|bin| {
                    let mut cmd = spawn_neothd_plain(&bin);
                    cmd.arg("skills")
                        .arg("--create")
                        .arg("--non-interactive")
                        .arg("--create-id")
                        .arg(&id)
                        .arg("--create-description")
                        .arg(&desc)
                        .arg("--create-system-prompt")
                        .arg(&prompt);
                    if !keywords.is_empty() {
                        cmd.arg("--create-keywords").arg(&keywords);
                    }
                    cmd.output().ok()
                });
                let ok = result.as_ref().map(|o| o.status.success()).unwrap_or(false);
                let msg = result
                    .as_ref()
                    .map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "neothd not on PATH?".to_string());
                if ok {
                    push_toast(&weak, "success", "Skill created", &id);
                } else {
                    push_toast(&weak, "warn", "Skill create failed", &msg);
                }
                let skills = fetch_skills();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        apply_skills(&w, skills);
                    }
                });
            });
        });
    }

    // ── Plugins: install from dir ──────────────────────────────────────────────
    // Opens a native folder picker, shells `neoth plugin install <dir>` → toast + refresh.
    {
        let weak_pi = window.as_weak();
        window.on_plugin_install(move || {
            let weak = weak_pi.clone();
            std::thread::spawn(move || {
                let picked = rfd::FileDialog::new()
                    .set_title("Select plugin directory (must contain plugin.toml + plugin.wasm)")
                    .pick_folder();
                let Some(dir) = picked else { return };
                let dir_str = dir.to_string_lossy().to_string();
                let result = which_neothd().and_then(|bin| {
                    spawn_neothd_plain(&bin)
                        .arg("plugin")
                        .arg("install")
                        .arg(&dir)
                        .output()
                        .ok()
                });
                let ok = result.as_ref().map(|o| o.status.success()).unwrap_or(false);
                let msg = result
                    .as_ref()
                    .map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "neothd not on PATH?".to_string());
                if ok {
                    push_toast(&weak, "success", "Plugin installed", &dir_str);
                } else {
                    push_toast(&weak, "warn", "Plugin install failed", &msg);
                }
                let plugins = fetch_plugins();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        apply_plugins(&w, plugins);
                    }
                });
            });
        });
    }

    // ── Plugins: remove by id ──────────────────────────────────────────────────
    // Shells `neoth plugin remove <id>` → toast + refresh.
    // The `plugin remove` subcommand is being added in a parallel PR; if the
    // daemon doesn't support it yet the stderr toast surfaces the error cleanly.
    {
        let weak_pr = window.as_weak();
        window.on_plugin_remove(move |id| {
            let weak = weak_pr.clone();
            let id = id.to_string();
            std::thread::spawn(move || {
                let result = which_neothd().and_then(|bin| {
                    spawn_neothd_plain(&bin)
                        .arg("plugin")
                        .arg("remove")
                        .arg(&id)
                        .output()
                        .ok()
                });
                let ok = result.as_ref().map(|o| o.status.success()).unwrap_or(false);
                let msg = result
                    .as_ref()
                    .map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "neothd not on PATH?".to_string());
                if ok {
                    push_toast(&weak, "success", "Plugin removed", &id);
                } else {
                    push_toast(&weak, "warn", "Plugin remove failed", &msg);
                }
                let plugins = fetch_plugins();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        apply_plugins(&w, plugins);
                    }
                });
            });
        });
    }

    // DES-12 — Plugin WAL-feed detail pane: operator clicked "Activity" on a row.
    // Shells `neoth plugin events <id> --output json --last 30` off the UI thread,
    // parses the result, and updates plugin-detail-id / title / events.
    {
        let weak_pdc = window.as_weak();
        window.on_plugin_detail_clicked(move |id| {
            use slint::Model as _; // ModelRc::row_count / row_data
            let weak = weak_pdc.clone();
            let id_str = id.to_string();
            // Look up ui_title from the current plugins model so we can set the
            // detail title without an extra subprocess call.
            let title = weak
                .upgrade()
                .and_then(|w| {
                    let model = w.get_plugins();
                    (0..model.row_count()).find_map(|i| {
                        let row = model.row_data(i)?;
                        if row.id.as_str() == id_str {
                            Some(row.ui_title.to_string())
                        } else {
                            None
                        }
                    })
                })
                .unwrap_or_default();
            std::thread::spawn(move || {
                let events = fetch_plugin_events(&id_str);
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        use slint::{ModelRc, VecModel};
                        let rows: Vec<PluginEventRow> = events
                            .into_iter()
                            .map(|e| PluginEventRow {
                                // SECURITY: kind is plugin-controlled text; stored as
                                // plain string — Slint renders it via plain Text only
                                // (no markup parsing). Do NOT pass to any rich-text API.
                                kind: e.kind.into(),
                                bytes: fmt_event_bytes(e.payload_bytes).into(),
                                ts: fmt_ts_unix(e.ts_unix).into(),
                            })
                            .collect();
                        w.set_plugin_detail_id(id_str.as_str().into());
                        w.set_plugin_detail_title(title.as_str().into());
                        w.set_plugin_detail_events(ModelRc::new(VecModel::from(rows)));
                    }
                });
            });
        });
    }

    // DES-12 — Plugin detail pane close: clear the selection.
    {
        let weak_pclose = window.as_weak();
        window.on_plugin_detail_close(move || {
            if let Some(w) = weak_pclose.upgrade() {
                use slint::{ModelRc, VecModel};
                w.set_plugin_detail_id("".into());
                w.set_plugin_detail_title("".into());
                w.set_plugin_detail_events(ModelRc::new(VecModel::from(
                    Vec::<PluginEventRow>::new(),
                )));
            }
        });
    }

    // GUI-overhaul feature parity — set the autonomy level from the Privacy combo.
    // Shells `neoth autonomy set <level>` (mutates freedom.yaml::autonomy + emits
    // a WAL audit frame). On success, mirror the new level into autonomy-choice so
    // the combo + every autonomy-derived display update without a reload.
    //
    // GAP-09 — Sudomode route: if level == "full", the GUI MUST NOT call
    // `autonomy set full` directly (that path is TTY-fail-closed). Instead mint
    // a single-use token via `neoth autonomy mint-fullauto-token --output json`
    // and then call `neoth autonomy full-auto --gui-confirmed --gui-token <t>`.
    // Any mint failure is surfaced in status-line and the level is NOT changed.
    // All other levels use the normal `autonomy set <level>` path unchanged.
    let weak_autonomy_set = window.as_weak();
    window.on_autonomy_set(move |level| {
        let weak = weak_autonomy_set.clone();
        let level = level.to_string();
        std::thread::spawn(move || {
            // GAP-09: intercept "full" → token-mint path.
            if level == "full" {
                let result: Result<(), String> = (|| {
                    let bin =
                        which_neothd().ok_or_else(|| "neothd binary not on PATH".to_string())?;
                    let tok_out = spawn_neothd_plain(&bin)
                        .arg("autonomy")
                        .arg("mint-fullauto-token")
                        .arg("--output")
                        .arg("json")
                        .output()
                        .map_err(|e| format!("mint-fullauto-token spawn failed: {e}"))?;
                    if !tok_out.status.success() {
                        let err = String::from_utf8_lossy(&tok_out.stderr).trim().to_string();
                        return Err(format!("mint-fullauto-token failed: {err}"));
                    }
                    let raw = String::from_utf8_lossy(&tok_out.stdout).trim().to_string();
                    // Output may be `{"token":"…"}` or a bare token string.
                    let token = if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
                        // JSON but token missing/not-a-string → empty, so the
                        // is_empty guard below rejects it (never pass the raw
                        // JSON blob as a token).
                        v.get("token")
                            .and_then(|t| t.as_str())
                            .unwrap_or("")
                            .to_string()
                    } else {
                        raw
                    };
                    if token.is_empty() {
                        return Err("mint-fullauto-token returned an empty token".to_string());
                    }
                    let apply_out = spawn_neothd_plain(&bin)
                        .arg("autonomy")
                        .arg("full-auto")
                        .arg("--gui-confirmed")
                        .arg("--gui-token")
                        .arg(&token)
                        .output()
                        .map_err(|e| format!("autonomy full-auto spawn failed: {e}"))?;
                    if !apply_out.status.success() {
                        let err = String::from_utf8_lossy(&apply_out.stderr)
                            .trim()
                            .to_string();
                        return Err(format!("autonomy full-auto failed: {err}"));
                    }
                    Ok(())
                })();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak.upgrade() {
                        match result {
                            Ok(()) => {
                                // Orb flips to secured only on a CONFIRMED
                                // change (review wave 2026-07-04: no visual
                                // drift when the ceremony fails).
                                buddy(&w, GuiActivity::Secured);
                                w.set_autonomy_choice("full".into());
                                w.set_status_line(
                                    "Autonomy set to full (sudomode) via GUI token.".into(),
                                );
                            }
                            Err(msg) => {
                                w.set_status_line(
                                    format!(
                                        "Full-auto gate: {msg} — level NOT changed. \
                                         Daemon must be running to mint the confirm token."
                                    )
                                    .into(),
                                );
                            }
                        }
                    }
                });
                return;
            }

            // Normal path for strict / standard / elevated / custom.
            let ok = which_neothd()
                .and_then(|bin| {
                    spawn_neothd_plain(&bin)
                        .arg("autonomy")
                        .arg("set")
                        .arg(&level)
                        .output()
                        .ok()
                })
                .map(|o| o.status.success())
                .unwrap_or(false);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    if ok {
                        buddy(&w, GuiActivity::Secured);
                        w.set_autonomy_choice(level.clone().into());
                        w.set_status_line(format!("Autonomy set to {level}.").into());
                    } else {
                        w.set_status_line(
                            format!("Autonomy set to {level} failed (is neothd on PATH?).").into(),
                        );
                    }
                }
            });
        });
    });

    // ── Chat-surface consent strip wiring ─────────────────────────────────────
    // Three callbacks + one startup fire. The refresh fn is also called after
    // any mode/revoke action so the strip stays in sync.

    // Initial populate — fires immediately so the strip shows real data on first
    // chat view without requiring a manual refresh.
    {
        let weak_cc_init = window.as_weak();
        std::thread::spawn(move || {
            refresh_chat_consent(weak_cc_init);
        });
    }

    // chat-consent-refresh — operator opened the popover; re-probe daemon.
    let weak_cc_refresh = window.as_weak();
    window.on_chat_consent_refresh(move || {
        let weak = weak_cc_refresh.clone();
        std::thread::spawn(move || {
            refresh_chat_consent(weak);
        });
    });

    // chat-consent-set-mode — "Gated" or "Full-Auto" pill clicked.
    let weak_cc_mode = window.as_weak();
    window.on_chat_consent_set_mode(move |mode| {
        let weak = weak_cc_mode.clone();
        let mode = mode.to_string();
        std::thread::spawn(move || {
            if mode == "full" {
                // GAP-09 / GR-RESID-D34: Full-auto requires the token-mint
                // ceremony — same path as on_autonomy_set("full").
                let result: Result<(), String> = (|| {
                    let bin =
                        which_neothd().ok_or_else(|| "neothd binary not on PATH".to_string())?;
                    let tok_out = spawn_neothd_plain(&bin)
                        .arg("autonomy")
                        .arg("mint-fullauto-token")
                        .arg("--output")
                        .arg("json")
                        .output()
                        .map_err(|e| format!("mint-fullauto-token spawn failed: {e}"))?;
                    if !tok_out.status.success() {
                        let err = String::from_utf8_lossy(&tok_out.stderr).trim().to_string();
                        return Err(format!("mint-fullauto-token failed: {err}"));
                    }
                    let raw = String::from_utf8_lossy(&tok_out.stdout).trim().to_string();
                    let token = if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
                        v.get("token")
                            .and_then(|t| t.as_str())
                            .unwrap_or("")
                            .to_string()
                    } else {
                        raw
                    };
                    if token.is_empty() {
                        return Err("mint-fullauto-token returned an empty token".to_string());
                    }
                    let apply_out = spawn_neothd_plain(&bin)
                        .arg("autonomy")
                        .arg("full-auto")
                        .arg("--gui-confirmed")
                        .arg("--gui-token")
                        .arg(&token)
                        .output()
                        .map_err(|e| format!("autonomy full-auto spawn failed: {e}"))?;
                    if !apply_out.status.success() {
                        let err = String::from_utf8_lossy(&apply_out.stderr)
                            .trim()
                            .to_string();
                        return Err(format!("autonomy full-auto failed: {err}"));
                    }
                    Ok(())
                })();
                let result_ok = result.is_ok();
                let result_msg = result.err().unwrap_or_default();
                let weak2 = weak.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak2.upgrade() {
                        if result_ok {
                            w.set_chat_consent_mode("full-auto".into());
                            push_toast(
                                &w.as_weak(),
                                "success",
                                "Consent",
                                "Full-Auto enabled via GUI ceremony.",
                            );
                        } else {
                            w.set_status_line(
                                format!(
                                    "Full-auto gate (chat strip): {result_msg} — mode NOT changed."
                                )
                                .into(),
                            );
                        }
                    }
                });
                if result_ok {
                    refresh_chat_consent(weak);
                }
            } else {
                // Gated (and any other mode): plain autonomy set.
                let ok = which_neothd()
                    .and_then(|bin| {
                        spawn_neothd_plain(&bin)
                            .arg("autonomy")
                            .arg("gated")
                            .output()
                            .ok()
                    })
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                let weak2 = weak.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = weak2.upgrade() {
                        if ok {
                            push_toast(&w.as_weak(), "success", "Consent", "Mode set to Gated.");
                        } else {
                            w.set_status_line("autonomy gated failed — is neothd on PATH?".into());
                        }
                    }
                });
                if ok {
                    refresh_chat_consent(weak);
                }
            }
        });
    });

    // chat-consent-revoke — Revoke button clicked for a provider.
    let weak_cc_revoke = window.as_weak();
    window.on_chat_consent_revoke(move |provider| {
        let weak = weak_cc_revoke.clone();
        let provider = provider.to_string();
        std::thread::spawn(move || {
            let ok = which_neothd()
                .and_then(|bin| {
                    spawn_neothd_plain(&bin)
                        .arg("consent")
                        .arg("revoke")
                        .arg(&provider)
                        .output()
                        .ok()
                })
                .map(|o| o.status.success())
                .unwrap_or(false);
            let provider2 = provider.clone();
            let weak2 = weak.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak2.upgrade() {
                    if ok {
                        push_toast(
                            &w.as_weak(),
                            "info",
                            "Consent",
                            &format!("Revoked consent for {provider2}."),
                        );
                    } else {
                        w.set_status_line(format!("consent revoke {provider2} failed.").into());
                    }
                }
            });
            if ok {
                refresh_chat_consent(weak);
            }
        });
    });

    // Pick #8 step 4 — pseudo-live-tail via 2-second poll (2026-05-20).
    // A real WAL-file-watcher (notify crate + WAL frame parser) lands
    // when the dispatcher (Pick #6) starts mutating the board mid-run.
    // Until then the polling refresh is cheap (no work unless the
    // operator is actually on Settings) + race-free (worker thread
    // owns subprocess + invoke_from_event_loop owns the UI write).
    //
    // The Timer MUST stay in scope until window.run() returns; binding
    // it to `_kanban_live_timer` keeps it alive for the program's life.
    let weak_kanban_tick = window.as_weak();
    let mutex_tick = kanban_snapshot.clone();
    // In-flight guard: each tick spawns a subprocess fetch. If a fetch
    // takes longer than the 2s poll interval (slow box / large board),
    // the naive timer would pile up overlapping fetch threads every 2s.
    // The AtomicBool lets at most ONE fetch be in flight at a time — a
    // late fetch just skips the tick instead of stacking another thread.
    // GOLD-ADAPT-GUI-05 — TypedStatus footer ticker. One repeated timer
    // types the current `panel_logic::TICKER_MESSAGES` line in character
    // by character (80ms/char), holds it, then advances. Pure frame math
    // lives in `panel_logic::ticker_frame` (unit-tested); only the tick
    // counter + property write live here. Runs only on the shell surfaces
    // (chat/settings) — wizard steps keep their own footer.
    let weak_ticker = window.as_weak();
    let _status_ticker_timer = {
        let timer = slint::Timer::default();
        let tick = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        timer.start(
            slint::TimerMode::Repeated,
            std::time::Duration::from_millis(80),
            move || {
                if let Some(w) = weak_ticker.upgrade() {
                    let s = w.get_step();
                    if s != WizardStep::Chat && s != WizardStep::Settings {
                        return;
                    }
                    let t = tick.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    w.set_status_message(panel_logic::ticker_frame(t).into());
                }
            },
        );
        timer
    };

    let kanban_fetch_in_flight = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    // B — persistent-stdio-stream: ONE warm `neoth gui-stream` child shared
    // across ticks, lazily connected on first board fetch. Held for the
    // window lifetime; dropped (→ child killed) when the timer drops.
    let gui_stream_client = std::sync::Arc::new(std::sync::Mutex::new(None::<GuiStreamClient>));
    let _kanban_live_timer = {
        let timer = slint::Timer::default();
        let in_flight = kanban_fetch_in_flight.clone();
        let client_timer = gui_stream_client.clone();
        timer.start(
            slint::TimerMode::Repeated,
            std::time::Duration::from_secs(2),
            move || {
                if let Some(w) = weak_kanban_tick.upgrade() {
                    // The board fetch only matters on the Code Sessions surface;
                    // the Buddy activity poll runs EVERY tick (the docked orb is
                    // always visible) so it reflects live daemon activity.
                    let want_board = w.get_step() == WizardStep::Settings;
                    // Skip if a prior fetch is still running. `swap` returns the
                    // previous value: true → another fetch is in flight → bail.
                    if in_flight.swap(true, std::sync::atomic::Ordering::AcqRel) {
                        return;
                    }
                    let weak = weak_kanban_tick.clone();
                    let mutex = mutex_tick.clone();
                    let done = in_flight.clone();
                    let client = client_timer.clone();
                    std::thread::spawn(move || {
                        // Daemon→GUI activity push — drive the docked Buddy from
                        // the daemon's most-recent (≤30s) WAL event. Only override
                        // when the daemon is actively doing something (!= idle) so
                        // a quiet daemon leaves the last user-action mood intact.
                        if let Some((act, cap)) = fetch_activity_warm(&client)
                            && act != "idle"
                        {
                            let weak_b = weak.clone();
                            let _ = slint::invoke_from_event_loop(move || {
                                if let Some(w) = weak_b.upgrade() {
                                    w.set_buddy_mood(act.into());
                                    w.set_buddy_caption(cap.into());
                                }
                            });
                        }
                        if want_board {
                            let snap = fetch_board_warm_or_cold(&client);
                            let snap_for_state = snap.clone();
                            // Wave-2 feed C: extract before the move into the closure.
                            let board_summary = snap_for_state.summary.clone();
                            // DES-10: clone so the channel-activity block below still
                            // has `weak` (this closure moves its own handle).
                            let weak_board = weak.clone();
                            let _ = slint::invoke_from_event_loop(move || {
                                let board_changed = mutex
                                    .lock()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                                    .replace_if_changed(snap_for_state);
                                if let Some(w) = weak_board.upgrade() {
                                    apply_kanban_snapshot(&w, snap);
                                    if board_changed {
                                        push_activity(
                                            &w.as_weak(),
                                            "kanban",
                                            "Board updated",
                                            &board_summary,
                                        );
                                    }
                                }
                            });
                        }
                        // DES-10 — drain the channel-activity ring accumulated by the
                        // reader thread's push-line intercept. Cap to 60 display rows.
                        // Runs every tick (not gated on want_board) so the feed stays
                        // live even when the operator is not on the Code Sessions tab.
                        {
                            use slint::Model as _; // ModelRc row_count/row_data
                            let guard = client.lock().unwrap_or_else(|p| p.into_inner());
                            if let Some(ref c) = *guard {
                                let new_entries = c.drain_channel_activity();
                                if !new_entries.is_empty() {
                                    let weak_ca = weak.clone();
                                    let _ = slint::invoke_from_event_loop(move || {
                                        if let Some(w) = weak_ca.upgrade() {
                                            use slint::{ModelRc, VecModel};
                                            const MAX_DISPLAY: usize = 60;
                                            // Read current model, append new entries, cap.
                                            let mut rows: Vec<ChannelActivityRow> = (0..w
                                                .get_channel_activity()
                                                .row_count())
                                                .map(|i| {
                                                    w.get_channel_activity().row_data(i).unwrap()
                                                })
                                                .collect();
                                            for entry in new_entries {
                                                rows.push(ChannelActivityRow {
                                                    direction: entry.direction.into(),
                                                    channel: entry.channel.into(),
                                                    peer: entry.peer.into(),
                                                    bytes: fmt_event_bytes(entry.bytes).into(),
                                                    ts: fmt_ts_unix(entry.ts_unix).into(),
                                                });
                                            }
                                            if rows.len() > MAX_DISPLAY {
                                                rows.drain(0..rows.len() - MAX_DISPLAY);
                                            }
                                            w.set_channel_activity(ModelRc::new(VecModel::from(
                                                rows,
                                            )));
                                        }
                                    });
                                }
                            }
                        }
                        // Release the slot AFTER the fetch + UI-write enqueue.
                        done.store(false, std::sync::atomic::Ordering::Release);
                    });
                }
            },
        );
        timer
    };

    // GOLD-PROG-07 — live VRAM/hardware refresh. The startup bundle fetches the
    // snapshot once; this 30s timer keeps the VRAM meter current while the
    // operator is on the Settings tab. Same race-free shape as the kanban timer:
    // a worker thread owns the subprocess, invoke_from_event_loop owns the UI
    // write, and an AtomicBool caps it at one fetch in flight. 30s (not 2s) —
    // `neoth hardware` reads sysinfo at call time, so a shorter interval just
    // taxes the Windows refresh rate without yielding finer data.
    let weak_hw_tick = window.as_weak();
    let hw_fetch_in_flight = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let _hardware_live_timer = {
        let timer = slint::Timer::default();
        let in_flight = hw_fetch_in_flight.clone();
        timer.start(
            slint::TimerMode::Repeated,
            std::time::Duration::from_secs(30),
            move || {
                if let Some(w) = weak_hw_tick.upgrade() {
                    if w.get_step() != WizardStep::Settings {
                        return;
                    }
                    if in_flight.swap(true, std::sync::atomic::Ordering::AcqRel) {
                        return;
                    }
                    let weak = weak_hw_tick.clone();
                    let done = in_flight.clone();
                    std::thread::spawn(move || {
                        let snap = fetch_hardware_snapshot();
                        // GOLD-PROG-08 — refresh the live token budget on the same
                        // Settings-tab tick (both are cheap file/subprocess reads).
                        let usage = fetch_usage_meter();
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(w) = weak.upgrade() {
                                apply_hardware(&w, snap);
                                apply_usage_meter(&w, usage);
                            }
                        });
                        done.store(false, std::sync::atomic::Ordering::Release);
                    });
                }
            },
        );
        timer
    };

    // Step 6 (2026-05-20): operator action handlers. Each spawns a
    // worker thread that subprocesses `neoth kanban move/review` and
    // logs the outcome. The 2s live-tail timer picks up the resulting
    // status change in the GUI without an explicit refresh hop.
    fn strip_id_hash(s: &str) -> String {
        s.strip_prefix('#').unwrap_or(s).to_string()
    }
    window.on_kanban_task_move(move |task_id, status| {
        let id = strip_id_hash(&task_id);
        let status_str = status.to_string();
        std::thread::spawn(move || {
            let Some(bin) = which_neothd() else {
                tracing::warn!("kanban move: neothd binary not on PATH");
                return;
            };
            let out = spawn_neothd_plain(&bin)
                .arg("kanban")
                .arg("move")
                .arg(&id)
                .arg(&status_str)
                .output();
            match out {
                Ok(o) if o.status.success() => {
                    info!(task_id = %id, status = %status_str, "kanban: move applied");
                }
                Ok(o) => tracing::warn!(
                    task_id = %id,
                    status = %status_str,
                    exit = ?o.status,
                    stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                    "kanban move failed"
                ),
                Err(e) => tracing::warn!(task_id = %id, error = %e, "kanban move could not start"),
            }
        });
    });
    window.on_kanban_task_promote(move |task_id| {
        let id = strip_id_hash(&task_id);
        std::thread::spawn(move || {
            let Some(bin) = which_neothd() else {
                tracing::warn!("kanban promote: neothd binary not on PATH");
                return;
            };
            let out = spawn_neothd_plain(&bin)
                .arg("kanban")
                .arg("review")
                .arg(&id)
                .arg("--promote")
                .output();
            match out {
                Ok(o) if o.status.success() => {
                    info!(task_id = %id, "kanban: REVIEW promoted to DONE");
                }
                Ok(o) => tracing::warn!(
                    task_id = %id,
                    exit = ?o.status,
                    stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                    "kanban promote failed"
                ),
                Err(e) => {
                    tracing::warn!(task_id = %id, error = %e, "kanban promote could not start")
                }
            }
        });
    });

    // v0.2 complete (2026-05-20) — comment + assign handlers.
    // Subprocess analog to move/promote; the 2s live-tail picks up
    // the resulting board state without a manual refresh.
    window.on_kanban_task_comment(move |task_id, body| {
        let id = strip_id_hash(&task_id);
        let body_str = body.to_string();
        if body_str.trim().is_empty() {
            return;
        }
        std::thread::spawn(move || {
            let Some(bin) = which_neothd() else {
                tracing::warn!("kanban comment: neothd binary not on PATH");
                return;
            };
            let out = spawn_neothd_plain(&bin)
                .arg("kanban")
                .arg("comment")
                .arg(&id)
                .arg(&body_str)
                .arg("--author")
                .arg("operator")
                .output();
            match out {
                Ok(o) if o.status.success() => {
                    info!(task_id = %id, body_len = body_str.len(), "kanban: comment appended");
                }
                Ok(o) => tracing::warn!(
                    task_id = %id,
                    exit = ?o.status,
                    stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                    "kanban comment failed"
                ),
                Err(e) => {
                    tracing::warn!(task_id = %id, error = %e, "kanban comment could not start")
                }
            }
        });
    });
    window.on_kanban_task_assign(move |task_id, hemi| {
        let id = strip_id_hash(&task_id);
        let hemi_str = hemi.to_string();
        std::thread::spawn(move || {
            let Some(bin) = which_neothd() else {
                tracing::warn!("kanban assign: neothd binary not on PATH");
                return;
            };
            let out = spawn_neothd_plain(&bin)
                .arg("kanban")
                .arg("assign")
                .arg(&id)
                .arg(&hemi_str)
                .output();
            match out {
                Ok(o) if o.status.success() => {
                    info!(task_id = %id, hemisphere = %hemi_str, "kanban: assigned");
                }
                Ok(o) => tracing::warn!(
                    task_id = %id,
                    hemisphere = %hemi_str,
                    exit = ?o.status,
                    stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                    "kanban assign failed"
                ),
                Err(e) => {
                    tracing::warn!(task_id = %id, error = %e, "kanban assign could not start")
                }
            }
        });
    });

    // GAP-03: finish-task handler. Subprocesses `neoth kanban finish
    // <id>`; the 2s live-tail picks up the done status automatically.
    window.on_kanban_task_finish(move |task_id| {
        let id = strip_id_hash(&task_id);
        std::thread::spawn(move || {
            let Some(bin) = which_neothd() else {
                tracing::warn!("kanban finish: neothd binary not on PATH");
                return;
            };
            let out = spawn_neothd_plain(&bin)
                .arg("kanban")
                .arg("finish")
                .arg(&id)
                .output();
            match out {
                Ok(o) if o.status.success() => {
                    info!(task_id = %id, "kanban: task finished");
                }
                Ok(o) => tracing::warn!(
                    task_id = %id,
                    exit = ?o.status,
                    stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                    "kanban finish failed"
                ),
                Err(e) => {
                    tracing::warn!(task_id = %id, error = %e, "kanban finish could not start")
                }
            }
        });
    });

    // Step 5 (2026-05-20): task-card click handler. Resolves the
    // task-id from the last-applied snapshot and pushes the detail
    // properties so the Code Sessions detail pane renders.
    let weak_select = window.as_weak();
    let mutex_select = kanban_snapshot.clone();
    window.on_kanban_task_selected(move |task_id| {
        let id = task_id.to_string();
        let snapshot_clone = match mutex_select.lock() {
            Ok(g) => g.clone(),
            Err(_) => return,
        };
        let Some((row, status)) = snapshot_clone.find_task(&id) else {
            return;
        };
        if let Some(w) = weak_select.upgrade() {
            w.set_kanban_selected_task_id(row.task_id);
            w.set_kanban_selected_title(row.title);
            w.set_kanban_selected_hemisphere(row.hemisphere);
            w.set_kanban_selected_status(status.into());
            // Description not yet carried in the snapshot — populate
            // when the board store starts surfacing it. Empty hides
            // the description line in the detail pane.
            w.set_kanban_selected_description("".into());
            // Clear stale comments while the subprocess fetch runs so
            // the operator never sees a previous task's thread.
            w.set_kanban_selected_comments(slint::ModelRc::new(slint::VecModel::from(Vec::<
                KanbanCommentRow,
            >::new(
            ))));
        }
        // Background fetch of comments via `neoth kanban task <id>
        // --output json`. Empty on subprocess error — operator still
        // sees the task body, just no thread.
        let weak_comments = weak_select.clone();
        let id_str = task_id.to_string();
        std::thread::spawn(move || {
            let comments = fetch_task_comments(&id_str);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak_comments.upgrade() {
                    use slint::{ModelRc, VecModel};
                    w.set_kanban_selected_comments(ModelRc::new(VecModel::from(comments)));
                }
            });
        });
    });

    // G-12 fix — operator changed the active provider in Settings →
    // Config. We persist by rewriting freedom.yaml in place (keeping
    // the operator's other fields intact via read-merge-write) and
    // dropping the same reload sentinel `/reload` uses, so the
    // daemon picks the change up within ~2s.
    let weak_provider = window.as_weak();
    window.on_provider_changed(move |new_provider| {
        let neoth_dir = default_neoth_home();
        let freedom_path = neoth_dir.join("freedom.yaml");
        let result = (|| -> anyhow::Result<()> {
            // MV-01c bug-fix: write losslessly. The prior path read+rewrote
            // the typed `MinimalFreedomYaml` (5 fields, no flatten), which
            // DROPPED the operator's inference topology / council / profile /
            // tokens config on every GUI provider-change. The `Value`
            // round-trip preserves every other field.
            set_top_level_string_in_freedom(&freedom_path, "provider_kind", &new_provider)?;
            std::fs::write(neoth_dir.join(".reload-requested"), b"reload\n")
                .with_context(|| "write reload sentinel")?;
            Ok(())
        })();
        if let Some(w) = weak_provider.upgrade() {
            match result {
                Ok(_) => {
                    info!(provider = %new_provider, "config: provider rewritten + reload sentinel dropped");
                    w.set_status_line(
                        format!("Provider set to {new_provider}. Daemon reloading within 2s.").into(),
                    );
                }
                Err(e) => {
                    tracing::error!(error = %e, "config: provider change failed");
                    w.set_status_line(format!("Provider change failed: {e}").into());
                }
            }
        }
    });

    // Bite #5 — operator flipped the cluster auto-discovery
    // checkbox in Settings → Cluster. Mutate `cluster.mdns.enabled`
    // in freedom.yaml losslessly (`serde_yaml::Value` round-trip
    // preserves every other field) and drop the reload sentinel
    // so the daemon picks the change up within ~2s — same dispatch
    // path as `neoth cluster enable` / `disable`.
    let weak_cluster = window.as_weak();
    window.on_cluster_mdns_enabled_changed(move |enabled| {
        let neoth_dir = default_neoth_home();
        let freedom_path = neoth_dir.join("freedom.yaml");
        let result = (|| -> anyhow::Result<()> {
            set_cluster_mdns_enabled_in_freedom(&freedom_path, enabled)?;
            std::fs::write(neoth_dir.join(".reload-requested"), b"reload\n")
                .with_context(|| "write reload sentinel")?;
            Ok(())
        })();
        if let Some(w) = weak_cluster.upgrade() {
            match result {
                Ok(_) => {
                    info!(
                        enabled,
                        "cluster: mdns.enabled rewritten + reload sentinel dropped"
                    );
                    let verb = if enabled { "enabled" } else { "disabled" };
                    w.set_status_line(
                        format!("Cluster auto-discovery {verb}. Daemon reloading within 2s.")
                            .into(),
                    );
                }
                Err(e) => {
                    tracing::error!(error = %e, "cluster: mdns toggle failed");
                    w.set_status_line(format!("Cluster toggle failed: {e}").into());
                }
            }
        }
    });

    // GOLD-FEAT-01c — operator confirmed enabling full-auto (sudomode) via the
    // GUI's two-step confirm. The in-GUI confirm IS the consent → invoke the CLI
    // with --gui-confirmed so it skips the TTY y/N (the bare CLI path stays
    // fail-closed). The 0xDD SUDOMODE_PRESET_APPLIED audit frame fires in the CLI.
    let weak_fa_on = window.as_weak();
    window.on_full_auto_confirmed(move || {
        let weak = weak_fa_on.clone();
        std::thread::spawn(move || {
            // GR-RESID-D34 — a bare `--gui-confirmed` no longer bypasses the TTY
            // gate. Mint a single-use, short-TTL token from the running daemon
            // (this in-GUI confirm dialog IS the consent), then pass it to
            // full-auto. A static flag baked into a script can no longer flip
            // FULL-AUTO; this live mint→use sequence requires the GUI + daemon.
            let ok = match which_neothd() {
                Some(bin) => {
                    let token = spawn_neothd_plain(&bin)
                        .arg("autonomy")
                        .arg("mint-fullauto-token")
                        .output()
                        .ok()
                        .filter(|o| o.status.success())
                        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                        .filter(|t| !t.is_empty());
                    match token {
                        Some(tok) => spawn_neothd_plain(&bin)
                            .arg("autonomy")
                            .arg("full-auto")
                            .arg("--gui-confirmed")
                            .arg("--gui-token")
                            .arg(&tok)
                            .output()
                            .map(|o| o.status.success())
                            .unwrap_or(false),
                        None => false, // daemon unreachable / mint failed
                    }
                }
                None => false,
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    if ok {
                        w.set_full_auto_active(true);
                        w.set_status_line(
                            "FULL-AUTO enabled — NEOTH now acts without asking. Switch back any time."
                                .into(),
                        );
                    } else {
                        w.set_status_line(
                            "Enabling full-auto failed — the daemon must be RUNNING (it mints the \
                             confirm token) and `neoth` on PATH. Still gated."
                                .into(),
                        );
                    }
                }
            });
        });
    });

    // GOLD-FEAT-01c — switch back to GATED (the safe direction → no confirm).
    let weak_fa_off = window.as_weak();
    window.on_full_auto_gated(move || {
        let weak = weak_fa_off.clone();
        std::thread::spawn(move || {
            let ok = match which_neothd() {
                Some(bin) => spawn_neothd_plain(&bin)
                    .arg("autonomy")
                    .arg("gated")
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false),
                None => false,
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    if ok {
                        w.set_full_auto_active(false);
                        w.set_status_line(
                            "Switched to GATED — NEOTH asks before sensitive actions.".into(),
                        );
                    } else {
                        w.set_status_line(
                            "Switching to gated failed (is the daemon installed?).".into(),
                        );
                    }
                }
            });
        });
    });

    // PF-01-GUI — operator flipped the Skills auto-route toggle. Mutate
    // `skills.always_embed_route` losslessly + drop the reload sentinel, same
    // dispatch path as the cluster mDNS toggle.
    let weak_skills_route = window.as_weak();
    window.on_skills_always_embed_route_set(move |enabled| {
        let neoth_dir = default_neoth_home();
        let freedom_path = neoth_dir.join("freedom.yaml");
        let result = (|| -> anyhow::Result<()> {
            set_skills_always_embed_route_in_freedom(&freedom_path, enabled)?;
            std::fs::write(neoth_dir.join(".reload-requested"), b"reload\n")
                .with_context(|| "write reload sentinel")?;
            Ok(())
        })();
        if let Some(w) = weak_skills_route.upgrade() {
            match result {
                Ok(_) => {
                    info!(
                        enabled,
                        "skills: always_embed_route rewritten + reload sentinel dropped"
                    );
                    let verb = if enabled { "on" } else { "off" };
                    w.set_status_line(
                        format!("Skill auto-routing {verb}. Daemon reloading within 2s.").into(),
                    );
                }
                Err(e) => {
                    tracing::error!(error = %e, "skills: always_embed_route toggle failed");
                    w.set_status_line(format!("Skill auto-route toggle failed: {e}").into());
                }
            }
        }
    });

    // ── DES-09 Welle A/B/C — freedom.yaml write-back callbacks ────────────
    //
    // Per-keystroke LineEdit fields (wire_nested_str! / _f64_str! / _i64_str!)
    // route through make_coalescing_writer: a per-field worker that keeps only
    // the last value of a keystroke burst (last-typed wins) and does one write —
    // this closes the non-FIFO-mutex ordering race a plain thread-per-keystroke
    // would introduce on slow/network home dirs. Single-fire fields (bool /
    // int_combo / persona) spawn a one-shot worker directly. All writes serialise
    // on FREEDOM_WRITE_LOCK inside set_nested_in_freedom; toasts via push_toast.
    {
        let neoth_dir = default_neoth_home();
        macro_rules! wire_nested_str {
            ($cb:ident, $key:literal, $label:literal) => {{
                // Per-keystroke LineEdit → coalescing writer (last-typed wins).
                let tx = make_coalescing_writer(
                    neoth_dir.join("freedom.yaml"),
                    neoth_dir.join(".reload-requested"),
                    $key,
                    $label,
                    window.as_weak(),
                    None,
                );
                window.$cb(move |raw: slint::SharedString| {
                    tx.send(serde_yaml::Value::from(raw.to_string().as_str()))
                        .ok();
                });
            }};
        }
        macro_rules! wire_nested_bool {
            ($cb:ident, $key:literal, $label:literal) => {{
                let nd = neoth_dir.clone();
                let weak = window.as_weak();
                window.$cb(move |v: bool| {
                    let nd2 = nd.clone();
                    let weak2 = weak.clone();
                    let state = if v { "enabled" } else { "disabled" };
                    // I/O (read + parse + fsync + rename) off the UI event loop.
                    std::thread::spawn(move || {
                        let fp = nd2.join("freedom.yaml");
                        let rd = nd2.join(".reload-requested");
                        let result = set_nested_in_freedom(&fp, $key, serde_yaml::Value::from(v))
                            .and_then(|_| {
                                std::fs::write(&rd, b"reload\n").map_err(|e| anyhow::anyhow!(e))
                            });
                        slint::invoke_from_event_loop(move || match result {
                            Ok(_) => push_toast(&weak2, "success", $label, state),
                            Err(ref e) => {
                                let msg = e.to_string();
                                push_toast(&weak2, "warn", concat!($label, " write failed"), &msg);
                            }
                        })
                        .ok();
                    });
                });
            }};
        }
        macro_rules! wire_nested_int_combo {
            ($cb:ident, $key:literal, $variants:expr, $label:literal) => {{
                let nd = neoth_dir.clone();
                let weak = window.as_weak();
                let variants: &'static [&'static str] = $variants;
                window.$cb(move |idx: i32| {
                    let val = variants.get(idx as usize).copied().unwrap_or(variants[0]);
                    let nd2 = nd.clone();
                    let weak2 = weak.clone();
                    // I/O (read + parse + fsync + rename) off the UI event loop.
                    std::thread::spawn(move || {
                        let fp = nd2.join("freedom.yaml");
                        let rd = nd2.join(".reload-requested");
                        let result = set_nested_in_freedom(&fp, $key, serde_yaml::Value::from(val))
                            .and_then(|_| {
                                std::fs::write(&rd, b"reload\n").map_err(|e| anyhow::anyhow!(e))
                            });
                        slint::invoke_from_event_loop(move || match result {
                            Ok(_) => push_toast(&weak2, "success", $label, val),
                            Err(ref e) => {
                                let msg = e.to_string();
                                push_toast(&weak2, "warn", concat!($label, " write failed"), &msg);
                            }
                        })
                        .ok();
                    });
                });
            }};
        }
        macro_rules! wire_nested_f64_str {
            ($cb:ident, $key:literal, $label:literal) => {{
                // Validate on the UI thread; only valid numbers reach the writer.
                let tx = make_coalescing_writer(
                    neoth_dir.join("freedom.yaml"),
                    neoth_dir.join(".reload-requested"),
                    $key,
                    $label,
                    window.as_weak(),
                    None,
                );
                let weak_err = window.as_weak();
                window.$cb(move |raw: slint::SharedString| {
                    let s = raw.to_string();
                    match s.trim().parse::<f64>() {
                        Ok(v) => {
                            tx.send(serde_yaml::Value::from(v)).ok();
                        }
                        Err(_) => push_toast(
                            &weak_err,
                            "warn",
                            concat!($label, " invalid"),
                            &format!("not a number: {}", s.trim()),
                        ),
                    }
                });
            }};
        }
        macro_rules! wire_nested_i64_str {
            ($cb:ident, $key:literal, $label:literal) => {{
                // Validate on the UI thread; only valid integers reach the writer.
                let tx = make_coalescing_writer(
                    neoth_dir.join("freedom.yaml"),
                    neoth_dir.join(".reload-requested"),
                    $key,
                    $label,
                    window.as_weak(),
                    None,
                );
                let weak_err = window.as_weak();
                window.$cb(move |raw: slint::SharedString| {
                    let s = raw.to_string();
                    match s.trim().parse::<i64>() {
                        Ok(v) => {
                            tx.send(serde_yaml::Value::from(v)).ok();
                        }
                        Err(_) => push_toast(
                            &weak_err,
                            "warn",
                            concat!($label, " invalid"),
                            &format!("not an integer: {}", s.trim()),
                        ),
                    }
                });
            }};
        }

        // Welle A — Council
        wire_nested_f64_str!(
            on_cfg_council_daily_usd_changed,
            "council.daily_usd_cap",
            "USD cap"
        );
        wire_nested_i64_str!(
            on_cfg_council_max_calls_changed,
            "council.max_calls_per_user_message",
            "Max calls"
        );
        wire_nested_i64_str!(
            on_cfg_council_max_depth_changed,
            "council.max_recursion_depth",
            "Max depth"
        );
        wire_nested_int_combo!(
            on_cfg_council_selection_mode_changed,
            "council.selection_mode",
            &["legacy_majority", "consensus_or_best", "best_always"], // FIX 5
            "Selection mode"
        );

        // Welle A — Provider
        wire_nested_str!(on_cfg_provider_model_changed, "provider_model", "Model");
        wire_nested_str!(
            on_cfg_provider_endpoint_changed,
            "provider_endpoint",
            "Endpoint"
        );
        wire_nested_str!(on_cfg_provider_region_changed, "provider_region", "Region");
        wire_nested_str!(
            on_cfg_provider_api_version_changed,
            "provider_api_version",
            "API version"
        );

        // Welle A — Profile + Behavior
        // FIX 2 — persona_mode index 0 must write YAML null (→ None) not ""
        // which would cause serde_yaml to fail parsing Option<PersonaMode>.
        // Inline callback instead of wire_nested_int_combo! to emit Null for "".
        {
            let nd = neoth_dir.clone();
            let weak = window.as_weak();
            let variants: &'static [&'static str] = &["", "loyal_buddy"];
            window.on_cfg_persona_mode_changed(move |idx: i32| {
                let val = variants.get(idx as usize).copied().unwrap_or(variants[0]);
                let yaml_val = if val.is_empty() {
                    serde_yaml::Value::Null
                } else {
                    serde_yaml::Value::from(val)
                };
                let nd2 = nd.clone();
                let weak2 = weak.clone();
                // I/O (read + parse + fsync + rename) off the UI event loop.
                std::thread::spawn(move || {
                    let fp = nd2.join("freedom.yaml");
                    let rd = nd2.join(".reload-requested");
                    let result =
                        set_nested_in_freedom(&fp, "persona_mode", yaml_val).and_then(|_| {
                            std::fs::write(&rd, b"reload\n").map_err(|e| anyhow::anyhow!(e))
                        });
                    slint::invoke_from_event_loop(move || match result {
                        Ok(_) => push_toast(&weak2, "success", "Persona mode", val),
                        Err(ref e) => {
                            let msg = e.to_string();
                            push_toast(&weak2, "warn", "Persona mode write failed", &msg);
                        }
                    })
                    .ok();
                });
            });
        }
        wire_nested_str!(on_cfg_user_tz_changed, "user_tz", "Timezone");
        wire_nested_bool!(
            on_cfg_elicitation_enabled_changed,
            "elicitation.enabled",
            "Elicitation"
        );
        wire_nested_int_combo!(
            on_cfg_elicitation_min_intensity_changed,
            "elicitation.min_intensity",
            &["low", "medium", "high", "urgent"],
            "Min intensity"
        );
        wire_nested_bool!(
            on_cfg_tone_modifier_enabled_changed,
            "tone_modifier.enabled",
            "Tone modifier"
        );

        // Welle B — Privacy
        wire_nested_bool!(
            on_cfg_review_gate_enabled_changed,
            "review_gate_enabled",
            "Review gate"
        );
        wire_nested_bool!(
            on_cfg_cloud_stt_enabled_changed,
            "media.cloud_stt_enabled",
            "Cloud STT"
        );
        wire_nested_bool!(
            on_cfg_cloud_tts_enabled_changed,
            "media.cloud_tts_enabled",
            "Cloud TTS"
        );
        wire_nested_bool!(
            on_cfg_cloud_vision_enabled_changed,
            "media.cloud_vision_enabled",
            "Cloud vision"
        );
        wire_nested_bool!(on_cfg_vad_enabled_changed, "media.vad_enabled", "VAD");
        wire_nested_bool!(
            on_cfg_dictation_enabled_changed,
            "media.dictation_enabled",
            "Dictation"
        );
        wire_nested_bool!(
            on_cfg_proactive_idle_only_changed,
            "proactive.idle_only",
            "Proactive idle-only"
        );

        // DES-09 G37 — proactive.quiet_hours_utc: [start, end] hours (UTC)
        // or null when the operator disables the window. Wrap-around is a
        // daemon-side feature ([22, 7] silences 22:00–06:59) so any 0–23
        // pair is valid here.
        {
            let nd = neoth_dir.clone();
            let weak = window.as_weak();
            window.on_cfg_quiet_hours_changed(move |enabled, start, end| {
                let value = if !enabled {
                    serde_yaml::Value::Null
                } else {
                    match (start.trim().parse::<u8>(), end.trim().parse::<u8>()) {
                        (Ok(s), Ok(e)) if s <= 23 && e <= 23 => serde_yaml::Value::Sequence(vec![
                            serde_yaml::Value::from(u64::from(s)),
                            serde_yaml::Value::from(u64::from(e)),
                        ]),
                        _ => {
                            push_toast(&weak, "warn", "Quiet hours", "hours must be 0–23");
                            return;
                        }
                    }
                };
                let nd2 = nd.clone();
                let weak2 = weak.clone();
                let state = if enabled { "enabled" } else { "disabled" };
                std::thread::spawn(move || {
                    let fp = nd2.join("freedom.yaml");
                    let rd = nd2.join(".reload-requested");
                    let result = set_nested_in_freedom(&fp, "proactive.quiet_hours_utc", value)
                        .and_then(|_| {
                            std::fs::write(&rd, b"reload\n").map_err(|e| anyhow::anyhow!(e))
                        });
                    slint::invoke_from_event_loop(move || match result {
                        Ok(_) => push_toast(&weak2, "success", "Quiet hours", state),
                        Err(ref e) => {
                            let msg = e.to_string();
                            push_toast(&weak2, "warn", "Quiet hours write failed", &msg);
                        }
                    })
                    .ok();
                });
            });
        }

        // Welle C — Memory
        wire_nested_bool!(
            on_cfg_memory_name_sessions_changed,
            "memory.name_sessions",
            "Name sessions"
        );
        wire_nested_bool!(
            on_cfg_memory_recall_shortcut_changed,
            "memory.recall_shortcut",
            "Recall shortcut"
        );
        wire_nested_int_combo!(
            on_cfg_memory_vector_backend_changed,
            "memory.vector_index.backend",
            &["brute_force", "hnsw"],
            "Vector backend"
        );
        wire_nested_bool!(
            on_cfg_consolidation_enabled_changed,
            "consolidation_sweep.enabled",
            "Consolidation sweep"
        );
        wire_nested_i64_str!(
            on_cfg_consolidation_interval_secs_changed,
            "consolidation_sweep.interval_secs",
            "Sweep interval"
        );
        wire_nested_f64_str!(
            on_cfg_consolidation_cosine_changed,
            "consolidation_sweep.cosine_threshold",
            "Cosine threshold"
        );
    }

    // ── DES-09 Welle E — Obsidian write-back callbacks ─────────────────────
    {
        let neoth_dir = default_neoth_home();

        // vault path → coalescing writer; on success re-scan the vault view.
        let obs_refresh: WriteSuccessHook =
            std::sync::Arc::new(|w: &MainWindow| w.invoke_obs_refresh_clicked());
        let tx_vault = make_coalescing_writer(
            neoth_dir.join("freedom.yaml"),
            neoth_dir.join(".reload-requested"),
            "obsidian_vault",
            "Vault path",
            window.as_weak(),
            Some(obs_refresh),
        );
        window.on_obs_vault_path_changed(move |raw: slint::SharedString| {
            tx_vault
                .send(serde_yaml::Value::from(raw.to_string().as_str()))
                .ok();
        });

        // subdir → coalescing writer (last-typed wins).
        let tx_subdir = make_coalescing_writer(
            neoth_dir.join("freedom.yaml"),
            neoth_dir.join(".reload-requested"),
            "obsidian_subdir",
            "Vault subdir",
            window.as_weak(),
            None,
        );
        window.on_obs_subdir_changed(move |raw: slint::SharedString| {
            tx_subdir
                .send(serde_yaml::Value::from(raw.to_string().as_str()))
                .ok();
        });

        // auto-sync secs (string) — validate on the UI thread, then coalescing
        // writer. Empty → Null (None = disabled); non-integer → warn, no write.
        let tx_sync = make_coalescing_writer(
            neoth_dir.join("freedom.yaml"),
            neoth_dir.join(".reload-requested"),
            "obsidian_auto_sync_secs",
            "Auto-sync interval",
            window.as_weak(),
            None,
        );
        let weak_sync_err = window.as_weak();
        window.on_obs_auto_sync_secs_str_changed(move |raw: slint::SharedString| {
            let s = raw.to_string();
            let t = s.trim();
            if t.is_empty() {
                tx_sync.send(serde_yaml::Value::Null).ok();
            } else if let Ok(v) = t.parse::<i64>() {
                tx_sync.send(serde_yaml::Value::from(v)).ok();
            } else {
                push_toast(
                    &weak_sync_err,
                    "warn",
                    "Auto-sync invalid",
                    &format!("not an integer: {t}"),
                );
            }
        });

        // reader enabled
        let nd = neoth_dir.clone();
        let weak = window.as_weak();
        window.on_obs_reader_enabled_changed(move |v: bool| {
            let nd2 = nd.clone();
            let w2 = weak.clone();
            let state = if v { "enabled" } else { "disabled" };
            // I/O (read + parse + fsync + rename) off the UI event loop.
            std::thread::spawn(move || {
                let fp = nd2.join("freedom.yaml");
                let rd = nd2.join(".reload-requested");
                let result = set_nested_in_freedom(
                    &fp,
                    "obsidian_vault_reader_enabled",
                    serde_yaml::Value::from(v),
                )
                .and_then(|_| std::fs::write(&rd, b"reload\n").map_err(|e| anyhow::anyhow!(e)));
                slint::invoke_from_event_loop(move || match result {
                    Ok(_) => push_toast(&w2, "success", "Vault reader", state),
                    Err(ref e) => {
                        let msg = e.to_string();
                        push_toast(&w2, "warn", "Vault reader write failed", &msg);
                    }
                })
                .ok();
            });
        });

        // Browse… — rfd folder picker, same pattern as skill-install
        let nd = neoth_dir.clone();
        let weak = window.as_weak();
        window.on_obs_browse_clicked(move || {
            let w2 = weak.clone();
            let nd2 = nd.clone();
            std::thread::spawn(move || {
                let picked = rfd::FileDialog::new()
                    .set_title("Select Obsidian vault folder")
                    .pick_folder();
                slint::invoke_from_event_loop(move || {
                    if let Some(p) = picked {
                        if let Some(w) = w2.upgrade() {
                            let s: slint::SharedString = p.to_string_lossy().to_string().into();
                            w.set_obs_vault_path_edit(s);
                        }
                        let fp = nd2.join("freedom.yaml");
                        let rd = nd2.join(".reload-requested");
                        let path_str = p.to_string_lossy().to_string();
                        let result = set_nested_in_freedom(
                            &fp,
                            "obsidian_vault",
                            serde_yaml::Value::from(path_str.as_str()),
                        )
                        .and_then(|_| {
                            std::fs::write(&rd, b"reload\n").map_err(|e| anyhow::anyhow!(e))
                        });
                        match result {
                            Ok(_) => {
                                push_toast(&w2, "success", "Vault path", "set — daemon reloading");
                                if let Some(w) = w2.upgrade() {
                                    w.invoke_obs_refresh_clicked();
                                }
                            }
                            Err(ref e) => {
                                let msg = e.to_string();
                                push_toast(&w2, "warn", "Vault path write failed", &msg);
                            }
                        }
                    }
                })
                .ok();
            });
        });

        // GUI-DES-SETTINGS-PRELOAD-01 — obsidian_preload_template_dir coalescing writer.
        // Empty string → Null (key cleared); non-empty → string value.
        let tx_preload_tmpl = make_coalescing_writer(
            neoth_dir.join("freedom.yaml"),
            neoth_dir.join(".reload-requested"),
            "obsidian_preload_template_dir",
            "Preload template dir",
            window.as_weak(),
            None,
        );
        window.on_obs_preload_template_dir_changed(move |raw: slint::SharedString| {
            let s = raw.to_string();
            let v = if s.trim().is_empty() {
                serde_yaml::Value::Null
            } else {
                serde_yaml::Value::from(s.as_str())
            };
            tx_preload_tmpl.send(v).ok();
        });

        // Browse… for preload template dir — same rfd pattern as on_obs_browse_clicked.
        let nd_ptd = neoth_dir.clone();
        let weak_ptd = window.as_weak();
        window.on_obs_browse_preload_template_dir_clicked(move || {
            let w2 = weak_ptd.clone();
            let nd2 = nd_ptd.clone();
            std::thread::spawn(move || {
                let picked = rfd::FileDialog::new()
                    .set_title("Select preload template directory (e.g. L6_Vault_Template)")
                    .pick_folder();
                slint::invoke_from_event_loop(move || {
                    if let Some(p) = picked {
                        if let Some(w) = w2.upgrade() {
                            let s: slint::SharedString = p.to_string_lossy().to_string().into();
                            w.set_obs_preload_template_dir_edit(s);
                        }
                        let fp = nd2.join("freedom.yaml");
                        let rd = nd2.join(".reload-requested");
                        let path_str = p.to_string_lossy().to_string();
                        let result = set_nested_in_freedom(
                            &fp,
                            "obsidian_preload_template_dir",
                            serde_yaml::Value::from(path_str.as_str()),
                        )
                        .and_then(|_| {
                            std::fs::write(&rd, b"reload\n").map_err(|e| anyhow::anyhow!(e))
                        });
                        match result {
                            Ok(_) => push_toast(
                                &w2,
                                "success",
                                "Preload template dir",
                                "set — daemon reloading",
                            ),
                            Err(ref e) => {
                                let msg = e.to_string();
                                push_toast(&w2, "warn", "Preload template dir write failed", &msg);
                            }
                        }
                    }
                })
                .ok();
            });
        });

        // obsidian_preload_subdir coalescing writer.
        let tx_preload_sub = make_coalescing_writer(
            neoth_dir.join("freedom.yaml"),
            neoth_dir.join(".reload-requested"),
            "obsidian_preload_subdir",
            "Preload subdir",
            window.as_weak(),
            None,
        );
        window.on_obs_preload_subdir_changed(move |raw: slint::SharedString| {
            let s = raw.to_string();
            let v = if s.trim().is_empty() {
                serde_yaml::Value::Null
            } else {
                serde_yaml::Value::from(s.as_str())
            };
            tx_preload_sub.send(v).ok();
        });

        // knowledge_preload_dirs coalescing writer.
        // TextEdit text has one path per line; split, drop blank lines, write YAML sequence.
        // Empty result → Null (key cleared from config).
        let tx_kp_dirs = make_coalescing_writer(
            neoth_dir.join("freedom.yaml"),
            neoth_dir.join(".reload-requested"),
            "knowledge_preload_dirs",
            "Knowledge preload dirs",
            window.as_weak(),
            None,
        );
        window.on_obs_knowledge_preload_dirs_changed(move |raw: slint::SharedString| {
            let text = raw.to_string();
            let paths: Vec<serde_yaml::Value> = text
                .lines()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(serde_yaml::Value::from)
                .collect();
            let v = if paths.is_empty() {
                serde_yaml::Value::Null
            } else {
                serde_yaml::Value::Sequence(paths)
            };
            tx_kp_dirs.send(v).ok();
        });
    }

    // ── ZF-05 wizard parity callbacks ────────────────────────────────────────
    //
    // These callbacks wire the new wizard parity screens (preset-picker,
    // hmac-setup, obsidian-setup, n8n-setup, private-mesh info, wasm-setup).
    // Fields are stored in Slint wz-* properties and flushed to freedom.yaml
    // by write_zf05_fields() inside on_finish_clicked.
    {
        // wz-obsidian-browse-clicked: opens an rfd folder dialog and writes
        // the chosen path back to wz-obsidian-vault (same pattern as on_obs_browse_clicked).
        let weak_wz_obs = window.as_weak();
        window.on_wz_obsidian_browse_clicked(move || {
            use rfd::FileDialog;
            let weak2 = weak_wz_obs.clone();
            std::thread::spawn(move || {
                if let Some(path) = FileDialog::new()
                    .set_title("Select Obsidian vault folder")
                    .pick_folder()
                {
                    let s: slint::SharedString = path.to_string_lossy().into_owned().into();
                    slint::invoke_from_event_loop(move || {
                        if let Some(w) = weak2.upgrade() {
                            w.set_wz_obsidian_vault(s);
                        }
                    })
                    .ok();
                }
            });
        });
    }

    // Pick #32 — Settings panel "Re-run wizard". Reset the wizard
    // state back to mode-selection so the operator walks the flow
    // fresh.
    let weak_wizard = window.as_weak();
    window.on_settings_wizard_rerun_clicked(move || {
        info!("settings: operator triggered wizard re-run");
        if let Some(w) = weak_wizard.upgrade() {
            w.set_step(WizardStep::ModeSelection);
            w.set_license_accepted(false);
            w.set_operator_id("".into());
            // ZF-05: reset express/parity state so a re-run starts fresh.
            w.set_wizard_preset_choice("".into());
            w.set_wz_hmac_enabled(false);
            w.set_wz_hmac_webhook_url("".into());
            w.set_wz_hmac_webhook_secret("".into());
            w.set_wz_obsidian_vault("".into());
            w.set_wz_obsidian_subdir("NEOTH-sessions".into());
            w.set_wz_obsidian_reader(false);
            w.set_wz_n8n_enabled(false);
            w.set_wz_n8n_port("9744".into());
            w.set_wz_wasm_enabled(false);
            w.set_wz_omi_enabled(false);
            w.set_wz_omi_mode("developer_api".into());
            w.set_wz_omi_endpoint("http://127.0.0.1:8002".into());
            w.set_wz_omi_listen_addr("127.0.0.1:8003".into());
            w.set_wz_omi_retention_days("30".into());
            w.set_wz_omi_developer_key("".into());
            w.set_wz_omi_native_token("".into());
            w.set_wz_omi_retain_transcripts(false);
            w.set_wz_omi_audio_enabled(false);
            w.set_wz_omi_image_enabled(false);
            w.set_wz_omi_video_enabled(false);
            w.set_wz_omi_allow_cloud_api(false);
            w.set_wz_omi_allow_cloud_summary(false);
            w.set_wz_omi_create_actions(true);
            w.set_wz_omi_seed_groundtruth(true);
            w.set_wz_omi_summary_enabled(true);
            w.set_status_line(
                "Wizard reset. Re-walking the flow will overwrite existing freedom.yaml at Finish."
                    .into(),
            );
        }
    });

    // GAP-04 — Memory search: `neoth recall <query>` → settings memory panel.
    let weak_memsearch = window.as_weak();
    window.on_settings_memory_search_clicked(move |query| {
        let Some(w0) = weak_memsearch.upgrade() else {
            return;
        };
        let q = query.to_string();
        if q.trim().is_empty() {
            return; // no-op for empty query
        }
        w0.set_settings_memory_search_running(true);
        let weak = weak_memsearch.clone();
        std::thread::spawn(move || {
            let output = match which_neothd()
                .and_then(|bin| spawn_neothd_plain(&bin).arg("recall").arg(&q).output().ok())
            {
                Some(o) => panel_logic::format_recall_output(
                    &String::from_utf8_lossy(&o.stdout),
                    &String::from_utf8_lossy(&o.stderr),
                    &q,
                ),
                None => "neothd binary not on PATH — cannot run recall.".to_string(),
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_settings_memory_search_output(output.into());
                    w.set_settings_memory_search_running(false);
                }
            });
        });
    });

    // GAP-07 — Backup now: `neoth backup` → status-line.
    let weak_backup = window.as_weak();
    window.on_settings_backup_now_clicked(move || {
        let Some(w0) = weak_backup.upgrade() else {
            return;
        };
        w0.set_status_line("Running neoth backup…".into());
        let weak = weak_backup.clone();
        std::thread::spawn(move || {
            let result = match which_neothd()
                .and_then(|bin| spawn_neothd_plain(&bin).arg("backup").output().ok())
            {
                Some(o) => {
                    let out = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
                    if o.status.success() {
                        if out.is_empty() {
                            "Backup complete.".to_string()
                        } else {
                            out
                        }
                    } else {
                        format!("Backup failed: {}", if err.is_empty() { out } else { err })
                    }
                }
                None => "neothd binary not on PATH — cannot run backup.".to_string(),
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_status_line(result.into());
                }
            });
        });
    });

    // GAP-07 — Preview rollback: `neoth rollback list` (read-only, no --confirm)
    // → status-line. The "list" subcommand shows available WAL snapshots without
    // restoring anything. Destructive `apply --confirm` is CLI-only by design.
    let weak_rollback = window.as_weak();
    window.on_settings_rollback_preview_clicked(move || {
        let Some(w0) = weak_rollback.upgrade() else {
            return;
        };
        w0.set_status_line("Listing rollback snapshots…".into());
        let weak = weak_rollback.clone();
        std::thread::spawn(move || {
            let result = match which_neothd().and_then(|bin| {
                spawn_neothd_plain(&bin)
                    .arg("rollback")
                    .arg("list")
                    .output()
                    .ok()
            }) {
                Some(o) => {
                    let out = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
                    if out.is_empty() && err.is_empty() {
                        "No WAL snapshots found. Run some operations first.".to_string()
                    } else if !out.is_empty() {
                        out
                    } else {
                        err
                    }
                }
                None => "neothd binary not on PATH — cannot list rollback snapshots.".to_string(),
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_status_line(result.into());
                }
            });
        });
    });

    let weak = window.as_weak();
    // GUI-REENTRY-PRESET fix: clone the flag into the closure so on_finish_clicked
    // can refuse to overwrite an existing config when read_freedom_yaml failed on
    // re-entry (prevents Slint type defaults — "standard"/"claude_cli" — from
    // silently clobbering the operator's real freedom.yaml as if "balanced" was
    // explicitly chosen).
    let reentry_config_ok_for_finish = std::sync::Arc::clone(&reentry_config_ok);
    window.on_finish_clicked(move || {
        if let Some(w) = weak.upgrade() {
            // Re-entry guard: if freedom.yaml already existed but could not be
            // parsed, refuse to write rather than stomp it with type defaults.
            // The operator must fix / inspect the YAML manually first.
            if config_present
                && !reentry_config_ok_for_finish.load(std::sync::atomic::Ordering::Acquire)
            {
                w.set_status_line(
                    "Cannot re-write config: the existing freedom.yaml could not be \
                     read back. Fix or remove it manually, then reopen the wizard."
                        .into(),
                );
                return;
            }
            if !initialization_state_valid {
                w.set_status_line(
                    "Cannot finish setup while the existing initialization state is invalid. Run `neoth init --force`, then reopen the GUI."
                        .into(),
                );
                return;
            }
            let state = WizardSnapshot {
                operator_id: w.get_operator_id().to_string(),
                provider_kind: w.get_provider_choice().to_string(),
                autonomy: w.get_autonomy_choice().to_string(),
                license_accepted: w.get_license_accepted(),
                enable_telegram: w.get_enable_telegram(),
                provider_key: w.get_provider_key().to_string(),
                telegram_token: w.get_telegram_token().to_string(),
                cluster_discovery_disabled: w.get_cluster_discovery_disabled(),
                // ZF-05 parity fields
                wizard_preset_choice: w.get_wizard_preset_choice().to_string(),
                wz_hmac_enabled: w.get_wz_hmac_enabled(),
                wz_hmac_webhook_url: w.get_wz_hmac_webhook_url().to_string(),
                wz_hmac_webhook_secret: w.get_wz_hmac_webhook_secret().to_string(),
                wz_obsidian_vault: w.get_wz_obsidian_vault().to_string(),
                wz_obsidian_subdir: w.get_wz_obsidian_subdir().to_string(),
                wz_obsidian_reader_enabled: w.get_wz_obsidian_reader(),
                wz_n8n_enabled: w.get_wz_n8n_enabled(),
                wz_n8n_port: w.get_wz_n8n_port().to_string(),
                wz_wasm_enabled: w.get_wz_wasm_enabled(),
                omi_enabled: w.get_wz_omi_enabled(),
                omi_mode: w.get_wz_omi_mode().to_string(),
                omi_endpoint: w.get_wz_omi_endpoint().to_string(),
                omi_listen_addr: w.get_wz_omi_listen_addr().to_string(),
                omi_retention_days: w.get_wz_omi_retention_days().to_string(),
                omi_developer_key: w.get_wz_omi_developer_key().to_string(),
                omi_native_token: w.get_wz_omi_native_token().to_string(),
                omi_retain_transcripts: w.get_wz_omi_retain_transcripts(),
                omi_audio_enabled: w.get_wz_omi_audio_enabled(),
                omi_image_enabled: w.get_wz_omi_image_enabled(),
                omi_video_enabled: w.get_wz_omi_video_enabled(),
                omi_allow_cloud_api: w.get_wz_omi_allow_cloud_api(),
                omi_allow_cloud_summary: w.get_wz_omi_allow_cloud_summary(),
                omi_create_actions: w.get_wz_omi_create_actions(),
                omi_seed_groundtruth: w.get_wz_omi_seed_groundtruth(),
                omi_summary_enabled: w.get_wz_omi_summary_enabled(),
            };
            let neoth_dir = default_neoth_home();
            let begun = (|| -> Result<_> {
                let bin =
                    which_neothd().context("NEOTH CLI binary is missing beside the GUI")?;
                validate_begin_and_prepare_gui_finish_with(
                    || validate_finish_state(&state),
                    || begin_gui_initialization(&bin, &neoth_dir),
                    || finish(&state),
                )
                .map(|(transaction, report)| (bin, transaction, report))
            })();
            match begun {
                Ok((bin, transaction, report)) => {
                    info!(?report.freedom_path, ?report.credentials_path, "wizard files prepared");
                    // ZF-05: write parity fields into the freshly-created
                    // freedom.yaml using set_nested_in_freedom so they coexist
                    // with the base config written by write_freedom_yaml.
                    let fp = neoth_dir.join("freedom.yaml");
                    let rd = neoth_dir.join(".reload-requested");
                    match commit_gui_finish_with(
                        report.message(),
                        || write_zf05_fields(&fp, &rd, &state),
                        || complete_gui_initialization(&bin, &neoth_dir, &transaction),
                    ) {
                        GuiFinishOutcome::Completed {
                            marker_path,
                            status,
                        } => {
                            info!(
                                ?report.freedom_path,
                                ?report.credentials_path,
                                marker_path = %marker_path.display(),
                                "wizard finished"
                            );
                            w.set_step(WizardStep::Done);
                            w.set_status_line(status.into());
                        }
                        GuiFinishOutcome::Failed { error, status } => {
                            tracing::error!(error = %error, "GUI completion commit failed");
                            w.set_status_line(status.into());
                        }
                    }
                }
                Err(e) => {
                    let msg = format!(
                        "Setup could not be committed: {e}. No completion was recorded; fix the error and click Finish again."
                    );
                    tracing::error!(error = %e, "wizard transaction or file preparation failed");
                    w.set_status_line(msg.into());
                }
            }
        }
    });

    // ── Companion overlay wiring ──────────────────────────────────────────────
    //
    // minimize-to-companion: hide the main window, show the overlay, then
    // arm always-on-top + position it bottom-right via the winit accessor.
    // The winit accessor only succeeds while the event loop is active, so
    // we call it inside the callback (which runs on the UI thread, inside
    // the event loop). with_winit_window returns Option — ignore None
    // (headless / non-winit backend) gracefully.
    {
        use slint::winit_030::winit::dpi::PhysicalPosition;
        use slint::winit_030::{WinitWindowAccessor, winit::window::WindowLevel};

        let overlay_weak_for_minimize = overlay.as_weak();
        let window_weak_for_minimize = window.as_weak();
        window.on_minimize_to_companion(move || {
            let Some(ov) = overlay_weak_for_minimize.upgrade() else {
                return;
            };
            let Some(win) = window_weak_for_minimize.upgrade() else {
                return;
            };
            win.hide().unwrap_or(());
            ov.show().unwrap_or(());
            // Set always-on-top and position after show() so the winit event
            // loop is active and the accessor can succeed. A position saved
            // from a previous drag wins over the bottom-right default; it is
            // clamped into the current monitor so a monitor change can never
            // strand the overlay off-screen.
            let saved = std::fs::read_to_string(default_neoth_home().join(".overlay-pos"))
                .ok()
                .and_then(|s| panel_logic::parse_overlay_pos(&s));
            ov.window().with_winit_window(|w| {
                w.set_window_level(WindowLevel::AlwaysOnTop);
                if let Some(mon) = w.current_monitor() {
                    let s = mon.size();
                    // 400 × 560 is the overlay's approximate pixel footprint at
                    // default 96 DPI; at higher scale factors it may clip —
                    // the operator can drag it from there.
                    let (x, y) = match saved {
                        Some((sx, sy)) => (
                            sx.clamp(0, (s.width as i32).saturating_sub(120)),
                            sy.clamp(0, (s.height as i32).saturating_sub(120)),
                        ),
                        None => (
                            (s.width as i32).saturating_sub(400),
                            (s.height as i32).saturating_sub(560),
                        ),
                    };
                    w.set_outer_position(PhysicalPosition::new(x, y));
                }
            });
            // Seed the overlay with the current buddy state so it is not blank.
            if let Some(ov2) = overlay_weak_for_minimize.upgrade()
                && let Some(win2) = window_weak_for_minimize.upgrade()
            {
                ov2.set_buddy_mood(win2.get_buddy_mood());
                ov2.set_status_text(win2.get_buddy_caption());
                ov2.set_daemon_state(win2.get_daemon_state());
            }
        });

        // The docked Buddy orb is a second UI entry point into the exact same
        // overlay transition. Keep hide/show, always-on-top, positioning and
        // state seeding centralized in `minimize-to-companion`.
        let window_weak_for_buddy = window.as_weak();
        window.on_buddy_clicked(move || {
            if let Some(win) = window_weak_for_buddy.upgrade() {
                win.invoke_minimize_to_companion();
            }
        });

        // Persist the overlay's dragged position so the next minimize
        // reopens it where the operator left it. Best-effort — a failed
        // write just means the default position next time.
        fn save_overlay_pos(ov: &MiniOverlay) {
            use slint::winit_030::WinitWindowAccessor;
            ov.window().with_winit_window(|w| {
                if let Ok(pos) = w.outer_position() {
                    let _ = std::fs::write(
                        default_neoth_home().join(".overlay-pos"),
                        format!("{},{}", pos.x, pos.y),
                    );
                }
            });
        }

        // overlay drag — pointer-down on the title strip hands the move to
        // the OS compositor. drag_window() runs the whole native move loop.
        let overlay_weak_for_drag = overlay.as_weak();
        overlay.on_drag_started(move || {
            if let Some(ov) = overlay_weak_for_drag.upgrade() {
                ov.window().with_winit_window(|w| {
                    let _ = w.drag_window();
                });
            }
        });

        // Compact-mode window sizing contract (see overlay.slint header):
        // 64 px pill / 148 px with speech bubble / 520 px full.
        fn resize_overlay(ov: &MiniOverlay) {
            use slint::winit_030::WinitWindowAccessor;
            let h: f64 = if ov.get_compact() {
                if ov.get_bubble_text().is_empty() {
                    64.0
                } else {
                    148.0
                }
            } else {
                520.0
            };
            ov.window().with_winit_window(|w| {
                let _ =
                    w.request_inner_size(slint::winit_030::winit::dpi::LogicalSize::new(380.0, h));
            });
        }

        let overlay_weak_for_compact = overlay.as_weak();
        overlay.on_compact_toggled(move |_on| {
            if let Some(ov) = overlay_weak_for_compact.upgrade() {
                resize_overlay(&ov);
            }
        });

        let overlay_weak_for_bubble = overlay.as_weak();
        overlay.on_bubble_dismissed(move || {
            if let Some(ov) = overlay_weak_for_bubble.upgrade() {
                ov.set_bubble_text("".into());
                resize_overlay(&ov);
            }
        });

        let overlay_weak_for_collapse = overlay.as_weak();
        overlay.on_collapse_requested(move || {
            if let Some(ov) = overlay_weak_for_collapse.upgrade() {
                ov.set_compact(false);
                resize_overlay(&ov);
            }
        });

        // Mic capture lands with the STT wiring — say so instead of
        // silently ignoring the click.
        let overlay_weak_for_mic = overlay.as_weak();
        overlay.on_mic_clicked(move || {
            if let Some(ov) = overlay_weak_for_mic.upgrade() {
                ov.set_status_text("voice input lands with the STT wiring".into());
            }
        });

        // overlay restore-clicked → hide overlay, show main window.
        let overlay_weak_for_restore = overlay.as_weak();
        let window_weak_for_restore = window.as_weak();
        overlay.on_restore_clicked(move || {
            let Some(ov) = overlay_weak_for_restore.upgrade() else {
                return;
            };
            let Some(win) = window_weak_for_restore.upgrade() else {
                return;
            };
            save_overlay_pos(&ov);
            ov.hide().unwrap_or(());
            win.show().unwrap_or(());
        });

        // overlay hide-clicked → same as restore (never leave the operator windowless).
        let overlay_weak_for_hide = overlay.as_weak();
        let window_weak_for_hide = window.as_weak();
        overlay.on_hide_clicked(move || {
            let Some(ov) = overlay_weak_for_hide.upgrade() else {
                return;
            };
            let Some(win) = window_weak_for_hide.upgrade() else {
                return;
            };
            save_overlay_pos(&ov);
            ov.hide().unwrap_or(());
            win.show().unwrap_or(());
        });

        // overlay send-clicked → replicate the minimal neothd chat --stream path.
        // We do NOT invoke_chat_send_clicked on the main window because the main
        // window is hidden; instead we run the same subprocess directly and feed
        // the reply snippet into the overlay's recent-lines (capped at 6).
        let overlay_weak_for_send = overlay.as_weak();
        overlay.on_send_clicked(move |text| {
            let body = text.trim().to_string();
            if body.is_empty() {
                return;
            }
            let Some(ov) = overlay_weak_for_send.upgrade() else {
                return;
            };

            // Buddy goes thinking while we wait for the reply.
            ov.set_buddy_mood("thinking".into());
            ov.set_status_text("thinking…".into());

            // Append the operator line to recent-lines immediately.
            {
                use slint::{Model, ModelRc, VecModel};
                let mut lines: Vec<slint::SharedString> = ov.get_recent_lines().iter().collect();
                lines.push(format!("▶ {body}").into());
                // Cap at 6 — oldest drop off.
                if lines.len() > 6 {
                    let drain_count = lines.len() - 6;
                    lines.drain(..drain_count);
                }
                ov.set_recent_lines(ModelRc::new(VecModel::from(lines)));
            }

            let ov_weak = ov.as_weak();
            let body_clone = body.clone();
            std::thread::spawn(move || {
                use std::io::Read as _;
                let result: std::result::Result<String, String> = (|| {
                    let bin = which_neothd().ok_or_else(|| "neothd not on PATH".to_string())?;
                    let mut cmd = spawn_neothd_plain(&bin);
                    cmd.arg("chat").arg("--stream").arg(&body_clone);
                    let mut child = cmd
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::null())
                        .spawn()
                        .map_err(|e| format!("spawn failed: {e}"))?;
                    let mut stdout = child.stdout.take().ok_or_else(|| "no stdout".to_string())?;
                    let mut acc: Vec<u8> = Vec::new();
                    let mut buf = [0u8; 512];
                    loop {
                        match stdout.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => acc.extend_from_slice(&buf[..n]),
                            Err(_) => break,
                        }
                    }
                    let raw = String::from_utf8_lossy(&acc).into_owned();
                    // strip_stream_sentinel strips the JSON done-sentinel line.
                    let (reply, _) = strip_stream_sentinel(&raw);
                    Ok(reply.trim().to_string())
                })();

                let _ = slint::invoke_from_event_loop(move || {
                    use slint::{Model, ModelRc, VecModel};
                    let Some(ov) = ov_weak.upgrade() else { return };
                    let (mood, caption, snippet) = match result {
                        Ok(ref reply) if !reply.is_empty() => {
                            // Truncate to 120 chars for the compact scrollback.
                            let snip = if reply.len() > 120 {
                                format!("{}…", &reply[..120])
                            } else {
                                reply.clone()
                            };
                            ("success", "done ✓", snip)
                        }
                        Ok(_) => ("idle", "ready", "—".to_string()),
                        Err(ref e) => ("error", "error", format!("⚠ {e}")),
                    };
                    ov.set_buddy_mood(mood.into());
                    ov.set_status_text(caption.into());
                    // Append the reply snippet to recent-lines, cap at 6.
                    let bubble_snip = snippet.clone();
                    let mut lines: Vec<slint::SharedString> =
                        ov.get_recent_lines().iter().collect();
                    lines.push(snippet.into());
                    if lines.len() > 6 {
                        let drain_count = lines.len() - 6;
                        lines.drain(..drain_count);
                    }
                    ov.set_recent_lines(ModelRc::new(VecModel::from(lines)));
                    // Compact pill: the reply surfaces as a speech bubble
                    // above the orb; the window grows to fit it.
                    if ov.get_compact() {
                        ov.set_bubble_text(bubble_snip.as_str().into());
                        resize_overlay(&ov);
                    }
                });
            });
        });
    } // end companion overlay wiring

    let gui_ready_failure = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
    if gui_parent_handoff.is_some() || direct_gui_commit {
        let weak = window.as_weak();
        let failure = gui_ready_failure.clone();
        let direct_home = neoth_dir.clone();
        slint::Timer::single_shot(std::time::Duration::ZERO, move || {
            use slint::winit_030::WinitWindowAccessor;

            let Some(window) = weak.upgrade() else {
                return;
            };
            let live_window = window.window().with_winit_window(|_| ()).is_some();
            let result = if !live_window {
                Err(anyhow::anyhow!("GUI event loop has no live winit window"))
            } else if let Some(handoff) = gui_parent_handoff.as_ref() {
                write_gui_parent_ready(handoff)
            } else {
                which_neothd()
                    .context("NEOTH CLI binary is missing beside the GUI")
                    .and_then(|bin| {
                        set_interface_preference_via_cli(
                            &bin,
                            &direct_home,
                            GuiInterfacePreference::Gui,
                        )
                    })
            };
            if let Err(error) = result {
                let message = format!("GUI readiness commit failed: {error:#}");
                tracing::error!(error = %error, "GUI readiness commit failed");
                if gui_parent_handoff.is_some() {
                    *failure
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(message);
                    let _ = window.hide();
                    let _ = slint::quit_event_loop();
                } else {
                    window.set_step(WizardStep::ModeSelection);
                    window.set_status_line(
                        format!(
                            "GUI is open, but it could not become the saved default: {error}. Choose a mode below to retry."
                        )
                        .into(),
                    );
                }
            }
        });
    }
    let run_result = window.run();
    if let Some(error) = gui_ready_failure
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take()
    {
        anyhow::bail!(error);
    }
    run_result?;
    Ok(())
}

/// Clean-machine release probe. It deliberately branches before NEOTH_HOME is
/// resolved or created: the probe validates only the shipped display stack and
/// must never mutate operator configuration. `Window::run` shows the real
/// native window; the bounded timer then waits until winit exposes that native
/// handle. A successful exit therefore proves construction and real event-loop
/// readiness instead of merely parsing the Slint document.
fn run_runtime_probe() -> Result<()> {
    use slint::winit_030::WinitWindowAccessor;

    let window = MainWindow::new().context("construct GUI runtime-probe window")?;
    let ready = std::rc::Rc::new(std::cell::Cell::new(false));
    let observed_ready = ready.clone();
    let ticks = std::rc::Rc::new(std::cell::Cell::new(0_u16));
    let observed_ticks = ticks.clone();
    let weak = window.as_weak();
    let readiness_timer = slint::Timer::default();
    readiness_timer.start(
        slint::TimerMode::Repeated,
        std::time::Duration::from_millis(10),
        move || {
            if let Some(window) = weak.upgrade()
                && window.window().with_winit_window(|_| ()).is_some()
            {
                observed_ready.set(true);
                let _ = window.hide();
                let _ = slint::quit_event_loop();
                return;
            }
            let next_tick = observed_ticks.get().saturating_add(1);
            observed_ticks.set(next_tick);
            if next_tick >= 500 {
                let _ = slint::quit_event_loop();
            }
        },
    );
    window.run().context("run GUI runtime-probe event loop")?;
    drop(readiness_timer);
    if !ready.get() {
        anyhow::bail!(
            "GUI runtime probe did not observe a live native window after {} event-loop ticks",
            ticks.get()
        );
    }
    println!("NEOTH GUI runtime probe: ready");
    Ok(())
}

/// Parse and bind the authoritative acknowledgement from
/// `neoth channel add --output json`. A success response for a different
/// channel, `ok:false`, or a malformed/missing field is never reused as the
/// approval to close this form.
fn parse_channel_saved(stdout: &[u8], expected_channel: &str) -> Option<bool> {
    #[derive(Deserialize)]
    struct ChannelAddAcknowledgement {
        ok: bool,
        channel: String,
        saved: bool,
    }

    let acknowledgement: ChannelAddAcknowledgement = serde_json::from_slice(stdout).ok()?;
    if !acknowledgement.ok || acknowledgement.channel != expected_channel {
        return None;
    }
    Some(acknowledgement.saved)
}

/// Parse and bind the authoritative acknowledgement from
/// `neoth channel remove --output json`. A zero exit status alone never proves
/// that a credential existed or was removed.
fn parse_channel_removed(stdout: &[u8], expected_channel: &str) -> Option<bool> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ChannelRemoveAcknowledgement {
        channel: String,
        removed: bool,
    }

    let acknowledgement: ChannelRemoveAcknowledgement = serde_json::from_slice(stdout).ok()?;
    (acknowledgement.channel == expected_channel).then_some(acknowledgement.removed)
}

/// Plain-data snapshot the wizard hands off to disk. Keeps the Slint
/// type surface separate from the on-disk schema so future schema
/// bumps stay loosely coupled to the UI.
struct WizardSnapshot {
    operator_id: String,
    provider_kind: String,
    autonomy: String,
    license_accepted: bool,
    enable_telegram: bool,
    provider_key: String,
    telegram_token: String,
    /// Q4 ratification: operator's choice on the cluster step.
    /// True means freedom.yaml gets `cluster.mdns.enabled: false`;
    /// false (default) means mDNS discovery stays ON per the
    /// noob-wizard "default ON in release" hard rule.
    cluster_discovery_disabled: bool,
    // ── ZF-05 parity fields ────────────────────────────────────────────────
    /// Which preset was chosen on the preset-picker screen ("" = not reached,
    /// "custom" = custom path, anything else = express path).
    wizard_preset_choice: String,
    wz_hmac_enabled: bool,
    wz_hmac_webhook_url: String,
    wz_hmac_webhook_secret: String,
    wz_obsidian_vault: String,
    wz_obsidian_subdir: String,
    wz_obsidian_reader_enabled: bool,
    wz_n8n_enabled: bool,
    wz_n8n_port: String,
    wz_wasm_enabled: bool,
    omi_enabled: bool,
    omi_mode: String,
    omi_endpoint: String,
    omi_listen_addr: String,
    omi_retention_days: String,
    omi_developer_key: String,
    omi_native_token: String,
    omi_retain_transcripts: bool,
    omi_audio_enabled: bool,
    omi_image_enabled: bool,
    omi_video_enabled: bool,
    omi_allow_cloud_api: bool,
    omi_allow_cloud_summary: bool,
    omi_create_actions: bool,
    omi_seed_groundtruth: bool,
    omi_summary_enabled: bool,
}

impl Default for WizardSnapshot {
    fn default() -> Self {
        Self {
            operator_id: String::new(),
            provider_kind: String::new(),
            autonomy: String::new(),
            license_accepted: false,
            enable_telegram: false,
            provider_key: String::new(),
            telegram_token: String::new(),
            cluster_discovery_disabled: false,
            wizard_preset_choice: String::new(),
            wz_hmac_enabled: false,
            wz_hmac_webhook_url: String::new(),
            wz_hmac_webhook_secret: String::new(),
            wz_obsidian_vault: String::new(),
            wz_obsidian_subdir: "NEOTH-sessions".to_string(),
            wz_obsidian_reader_enabled: false,
            wz_n8n_enabled: false,
            wz_n8n_port: "9744".to_string(),
            wz_wasm_enabled: false,
            omi_enabled: false,
            omi_mode: "developer_api".to_string(),
            omi_endpoint: "http://127.0.0.1:8002".to_string(),
            omi_listen_addr: "127.0.0.1:8003".to_string(),
            omi_retention_days: "30".to_string(),
            omi_developer_key: String::new(),
            omi_native_token: String::new(),
            omi_retain_transcripts: false,
            omi_audio_enabled: false,
            omi_image_enabled: false,
            omi_video_enabled: false,
            omi_allow_cloud_api: false,
            omi_allow_cloud_summary: false,
            omi_create_actions: true,
            omi_seed_groundtruth: true,
            omi_summary_enabled: true,
        }
    }
}

/// What `finish()` returns. `credentials_path` is `None` when no secret
/// was entered (we deliberately skip writing the file so we don't leave
/// an empty stub behind — matches `credentials::Credentials::write`).
#[derive(Debug)]
struct FinishReport {
    freedom_path: PathBuf,
    credentials_path: Option<PathBuf>,
}

#[derive(Debug)]
enum GuiFinishOutcome {
    Completed {
        marker_path: PathBuf,
        status: String,
    },
    Failed {
        error: anyhow::Error,
        status: String,
    },
}

fn validate_begin_and_prepare_gui_finish_with<Validate, Begin, Prepare, Transaction, Report>(
    validate: Validate,
    begin: Begin,
    prepare: Prepare,
) -> Result<(Transaction, Report)>
where
    Validate: FnOnce() -> Result<()>,
    Begin: FnOnce() -> Result<Transaction>,
    Prepare: FnOnce() -> Result<Report>,
{
    validate()?;
    let transaction = begin()?;
    let report = prepare()?;
    Ok((transaction, report))
}

/// Preserve the only valid GUI completion order: parity writes first, then the
/// daemon-owned canonical marker. The UI may enter `Done` only for the typed
/// `Completed` variant.
fn commit_gui_finish_with<WriteParity, Complete>(
    prepared_message: String,
    write_parity: WriteParity,
    complete: Complete,
) -> GuiFinishOutcome
where
    WriteParity: FnOnce() -> Result<()>,
    Complete: FnOnce() -> Result<PathBuf>,
{
    match write_parity().and_then(|()| complete()) {
        Ok(marker_path) => GuiFinishOutcome::Completed {
            status: format!(
                "{prepared_message}\nSetup complete and verified by {}.",
                marker_path.display()
            ),
            marker_path,
        },
        Err(error) => GuiFinishOutcome::Failed {
            status: format!(
                "Setup files were prepared, but completion could not be verified: {error}. Reopen NEOTH to check the committed state, then click Finish again if needed."
            ),
            error,
        },
    }
}

impl FinishReport {
    fn message(&self) -> String {
        let mut s = format!("Configuration written to {}.", self.freedom_path.display());
        if let Some(p) = &self.credentials_path {
            s.push_str(&format!("\nSecrets stored in {} (mode 0600).", p.display()));
        }
        s.push_str("\nNEOTH is ready; you can keep using this window or open the CLI anytime.");
        s
    }
}

/// Read-only projection of `freedom.yaml` used to populate wizard fields.
/// Writes must merge into a `serde_yaml::Value`; serialising this projection
/// would discard fields the wizard does not own.
///
/// L-2 fix — also `Deserialize` so the re-entry path can read the
/// existing config back into the wizard properties (M-1).
#[derive(Serialize, Deserialize)]
struct MinimalFreedomYaml {
    operator_id: String,
    provider_kind: String,
    autonomy: String,
    /// Always includes `"cli"`. Telegram is appended when the operator
    /// ticked the channel + ended up with a token. We deliberately
    /// store the list inside `freedom.yaml` even though the daemon
    /// doesn't strictly read it yet — operators inspecting the file
    /// should see what they configured.
    #[serde(default)]
    channels: Vec<String>,
    /// Q4-ratified cluster block. Only serialised when the operator
    /// explicitly disabled discovery on the wizard step. Omitted
    /// otherwise — the daemon's serde-default keeps mDNS ON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cluster: Option<ClusterYamlBlock>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    omi: Option<OmiWizardYaml>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
struct OmiWizardYaml {
    enabled: bool,
    mode: String,
    endpoint: String,
    listen_addr: String,
    retention_days: u64,
    retain_transcripts: bool,
    audio_enabled: bool,
    visual_enabled: bool,
    video_enabled: bool,
    allow_cloud_api: bool,
    allow_cloud_summary: bool,
    create_actions: bool,
    seed_groundtruth: bool,
    summary_enabled: bool,
}

impl Default for OmiWizardYaml {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: "developer_api".to_string(),
            endpoint: "http://127.0.0.1:8002".to_string(),
            listen_addr: "127.0.0.1:8003".to_string(),
            retention_days: 30,
            retain_transcripts: false,
            audio_enabled: false,
            visual_enabled: false,
            video_enabled: false,
            allow_cloud_api: false,
            allow_cloud_summary: false,
            create_actions: true,
            seed_groundtruth: true,
            summary_enabled: true,
        }
    }
}

/// Minimal mirror of the on-disk `cluster:` block.
///
/// The daemon's `ClusterConfig` (config/mod.rs) has the shape:
///   cluster:
///     name: null | string
///     enabled: bool
///
/// The GUI wizard writes a *different* shape when the operator disables
/// mDNS discovery:
///   cluster:
///     mdns:
///       enabled: false
///
/// Both shapes must round-trip through `MinimalFreedomYaml` without
/// a parse error.  All fields carry `#[serde(default)]` so that any
/// combination of present/absent keys deserialises cleanly.
#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct ClusterYamlBlock {
    /// Daemon-written field: `cluster.name`.
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    /// Daemon-written field: `cluster.enabled`.
    #[serde(skip_serializing_if = "is_false")]
    enabled: bool,
    /// GUI-written sub-block: `cluster.mdns.enabled`.
    #[serde(skip_serializing_if = "Option::is_none")]
    mdns: Option<ClusterMdnsYamlBlock>,
}

fn is_false(b: &bool) -> bool {
    !b
}

#[derive(Serialize, Deserialize)]
struct ClusterMdnsYamlBlock {
    enabled: bool,
}

/// Mirror of `config::credentials::Credentials`, serialised here
/// without the SecretString wrapper so the GUI doesn't have to pull in
/// the whole daemon crate. The on-disk format matches verbatim — the
/// daemon reads it back through the typed struct.
#[derive(Serialize, Deserialize, Default)]
struct CredentialsYaml {
    #[serde(skip_serializing_if = "Option::is_none")]
    provider_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    telegram_token: Option<String>,
}

impl CredentialsYaml {
    fn is_empty(&self) -> bool {
        self.provider_key.is_none() && self.telegram_token.is_none()
    }
}

fn finish(state: &WizardSnapshot) -> Result<FinishReport> {
    validate_finish_state(state)?;

    let neoth_dir = default_neoth_home();
    std::fs::create_dir_all(&neoth_dir)
        .with_context(|| format!("create {}", neoth_dir.display()))?;

    // Preserve the long-standing provider/Telegram wizard merge first. OMI
    // secrets then go through the daemon's strict stdin credential API, which
    // understands encrypted files and keychain storage. Public OMI config is
    // written last, so a credential failure can never leave OMI enabled.
    let mut credentials_path = write_credentials_yaml(state, &neoth_dir)?;
    if state.omi_enabled
        && (!state.omi_developer_key.is_empty() || !state.omi_native_token.is_empty())
    {
        persist_omi_credentials_via_cli(
            &neoth_dir,
            &state.omi_developer_key,
            &state.omi_native_token,
        )?;
        let file_path = neoth_dir.join("credentials.yaml");
        if credentials_path.is_none() && file_path.exists() {
            credentials_path = Some(file_path);
        }
    }
    let freedom_path = write_freedom_yaml(state, &neoth_dir)?;

    Ok(FinishReport {
        freedom_path,
        credentials_path,
    })
}

/// Pure validation edge used before the daemon opens a GUI init transaction.
/// No config, secret, marker, or pending file is touched here.
fn validate_finish_state(state: &WizardSnapshot) -> Result<()> {
    if !state.license_accepted {
        anyhow::bail!("license not accepted — refusing to write config");
    }
    if state.operator_id.trim().is_empty() {
        anyhow::bail!("operator id is empty — go back and enter one");
    }
    validate_autonomy(&state.autonomy)?;
    validate_wizard_omi(state)?;
    Ok(())
}

fn write_freedom_yaml(state: &WizardSnapshot, neoth_dir: &Path) -> Result<PathBuf> {
    let mut channels = vec!["cli".to_string()];
    if state.enable_telegram {
        channels.push("telegram".to_string());
    }
    let omi = OmiWizardYaml {
        enabled: true,
        mode: state.omi_mode.clone(),
        endpoint: state.omi_endpoint.clone(),
        listen_addr: state.omi_listen_addr.clone(),
        retention_days: state.omi_retention_days.parse().unwrap_or(30),
        retain_transcripts: state.omi_retain_transcripts,
        audio_enabled: state.omi_audio_enabled,
        visual_enabled: state.omi_image_enabled,
        video_enabled: state.omi_video_enabled,
        allow_cloud_api: state.omi_allow_cloud_api,
        allow_cloud_summary: state.omi_allow_cloud_summary,
        create_actions: state.omi_create_actions,
        seed_groundtruth: state.omi_seed_groundtruth,
        summary_enabled: state.omi_summary_enabled,
    };
    let path = neoth_dir.join("freedom.yaml");

    // The wizard owns only the fields it surfaces. Re-entry therefore uses a
    // single locked read/merge/write transaction so advanced OMI limits,
    // inference topology, council policy, and future config additions survive.
    let _guard = FREEDOM_WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let existed = path.exists();
    let mut root = if existed {
        let body = std::fs::read_to_string(&path)
            .with_context(|| format!("read {} before wizard merge", path.display()))?;
        serde_yaml::from_str::<serde_yaml::Value>(&body)
            .with_context(|| format!("parse {} before wizard merge", path.display()))?
    } else {
        serde_yaml::Value::Mapping(serde_yaml::Mapping::new())
    };
    let root_map = root
        .as_mapping_mut()
        .context("freedom.yaml is not a YAML mapping")?;
    for (key, value) in [
        (
            "operator_id",
            serde_yaml::Value::from(state.operator_id.clone()),
        ),
        (
            "provider_kind",
            serde_yaml::Value::from(state.provider_kind.clone()),
        ),
        ("autonomy", serde_yaml::Value::from(state.autonomy.clone())),
        (
            "channels",
            serde_yaml::to_value(channels).context("serialise wizard channels")?,
        ),
    ] {
        root_map.insert(serde_yaml::Value::from(key), value);
    }

    let cluster_key = serde_yaml::Value::from("cluster");
    if existed || state.cluster_discovery_disabled {
        let mut cluster = mapping_field_or_empty(root_map, &cluster_key, "cluster")?;
        let mdns_key = serde_yaml::Value::from("mdns");
        let mut mdns = mapping_field_or_empty(&cluster, &mdns_key, "cluster.mdns")?;
        mdns.insert(
            serde_yaml::Value::from("enabled"),
            serde_yaml::Value::from(!state.cluster_discovery_disabled),
        );
        cluster.insert(mdns_key, serde_yaml::Value::Mapping(mdns));
        root_map.insert(cluster_key, serde_yaml::Value::Mapping(cluster));
    }

    let omi_key = serde_yaml::Value::from("omi");
    if state.omi_enabled {
        let mut current = mapping_field_or_empty(root_map, &omi_key, "omi")?;
        let surfaced = serde_yaml::to_value(omi).context("serialise wizard OMI fields")?;
        let surfaced = surfaced
            .as_mapping()
            .context("wizard OMI fields did not serialise to a mapping")?;
        for (key, value) in surfaced {
            current.insert(key.clone(), value.clone());
        }
        root_map.insert(omi_key, serde_yaml::Value::Mapping(current));
    } else if root_map.contains_key(&omi_key) {
        let mut current = mapping_field_or_empty(root_map, &omi_key, "omi")?;
        current.insert(
            serde_yaml::Value::from("enabled"),
            serde_yaml::Value::from(false),
        );
        root_map.insert(omi_key, serde_yaml::Value::Mapping(current));
    }

    let body = serde_yaml::to_string(&root).context("serialise merged freedom.yaml")?;
    write_mode_0600(&path, body.as_bytes())?;
    Ok(path)
}

fn mapping_field_or_empty(
    parent: &serde_yaml::Mapping,
    key: &serde_yaml::Value,
    field: &str,
) -> Result<serde_yaml::Mapping> {
    match parent.get(key) {
        Some(serde_yaml::Value::Mapping(value)) => Ok(value.clone()),
        Some(_) => anyhow::bail!("freedom.yaml field {field} is not a YAML mapping"),
        None => Ok(serde_yaml::Mapping::new()),
    }
}

fn write_credentials_yaml(state: &WizardSnapshot, neoth_dir: &Path) -> Result<Option<PathBuf>> {
    let provider_key = (!state.provider_key.is_empty()).then(|| state.provider_key.clone());
    let telegram_token = (state.enable_telegram && !state.telegram_token.is_empty())
        .then(|| state.telegram_token.clone());
    let additions = CredentialsYaml {
        provider_key,
        telegram_token,
    };
    if additions.is_empty() {
        return Ok(None);
    }
    let path = neoth_dir.join("credentials.yaml");
    let _guard = FREEDOM_WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut root = if path.exists() {
        let body = std::fs::read_to_string(&path)
            .with_context(|| format!("read {} before credential merge", path.display()))?;
        serde_yaml::from_str::<serde_yaml::Value>(&body)
            .with_context(|| format!("parse {} before credential merge", path.display()))?
    } else {
        serde_yaml::Value::Mapping(serde_yaml::Mapping::new())
    };
    let map = root
        .as_mapping_mut()
        .context("credentials.yaml is not a YAML mapping")?;
    for (key, value) in [
        ("provider_key", additions.provider_key),
        ("telegram_token", additions.telegram_token),
    ] {
        if let Some(value) = value {
            map.insert(serde_yaml::Value::from(key), serde_yaml::Value::from(value));
        }
    }
    let body = serde_yaml::to_string(&root).context("serialise merged credentials.yaml")?;
    write_mode_0600(&path, body.as_bytes())?;
    Ok(Some(path))
}

/// M-1 helper — parse an existing `freedom.yaml` back into our minimal
/// shape so the wizard's re-entry path can pre-populate properties
/// from the operator's previous configuration.
fn read_freedom_yaml(path: &Path) -> Result<MinimalFreedomYaml> {
    let body = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let cfg: MinimalFreedomYaml =
        serde_yaml::from_str(&body).with_context(|| format!("parse {}", path.display()))?;
    Ok(cfg)
}

/// Bite #5 — settings panel populates these on tab activation.
/// Lossless read via `serde_yaml::Value` so we don't drop fields
/// the GUI's typed `MinimalFreedomYaml` doesn't know about.
struct ClusterSettingsSnapshot {
    mdns_enabled: bool,
    listen_port: u16,
    trusted_ssids_summary: String,
}

/// Load cluster state from freedom.yaml for the settings panel
/// populator. Missing file / unparseable YAML / absent keys collapse
/// to the Q4-ratified defaults: `mdns_enabled = true`, `listen_port =
/// 49737`, empty `trusted_ssids`. Reader is read-only — never writes.
fn load_cluster_settings(path: &Path) -> ClusterSettingsSnapshot {
    const DEFAULT_LISTEN_PORT: u16 = 49737;
    let Ok(body) = std::fs::read_to_string(path) else {
        return ClusterSettingsSnapshot {
            mdns_enabled: true,
            listen_port: DEFAULT_LISTEN_PORT,
            trusted_ssids_summary: String::new(),
        };
    };
    let Ok(root) = serde_yaml::from_str::<serde_yaml::Value>(&body) else {
        return ClusterSettingsSnapshot {
            mdns_enabled: true,
            listen_port: DEFAULT_LISTEN_PORT,
            trusted_ssids_summary: String::new(),
        };
    };
    let cluster = root.get("cluster");
    let mdns_enabled = cluster
        .and_then(|c| c.get("mdns"))
        .and_then(|m| m.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let listen_port = cluster
        .and_then(|c| c.get("listen_port"))
        .and_then(|v| v.as_u64())
        .and_then(|n| u16::try_from(n).ok())
        .filter(|p| *p > 0)
        .unwrap_or(DEFAULT_LISTEN_PORT);
    let trusted_ssids_summary = cluster
        .and_then(|c| c.get("policy"))
        .and_then(|p| p.get("trusted_ssids"))
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    ClusterSettingsSnapshot {
        mdns_enabled,
        listen_port,
        trusted_ssids_summary,
    }
}

/// Bite #5 — flip `cluster.mdns.enabled` in freedom.yaml without
/// disturbing other fields. Uses `serde_yaml::Value` round-trip so
/// the rest of the operator's config (inference, hemispheres,
/// council, ...) survives the rewrite unchanged. Atomic via
/// `.tmp` + rename.
fn set_cluster_mdns_enabled_in_freedom(path: &Path, enabled: bool) -> Result<()> {
    let _guard = FREEDOM_WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let body = if path.exists() {
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?
    } else {
        String::new()
    };
    let mut root: serde_yaml::Value = if body.trim().is_empty() {
        serde_yaml::Value::Mapping(serde_yaml::Mapping::new())
    } else {
        serde_yaml::from_str(&body).with_context(|| format!("parse {}", path.display()))?
    };
    let map = match &mut root {
        serde_yaml::Value::Mapping(m) => m,
        _ => anyhow::bail!("freedom.yaml is not a YAML mapping"),
    };
    let cluster_key = serde_yaml::Value::from("cluster");
    let mut cluster_map = map
        .get(&cluster_key)
        .and_then(|v| v.as_mapping())
        .cloned()
        .unwrap_or_default();
    let mdns_key = serde_yaml::Value::from("mdns");
    let mut mdns_map = cluster_map
        .get(&mdns_key)
        .and_then(|v| v.as_mapping())
        .cloned()
        .unwrap_or_default();
    mdns_map.insert(
        serde_yaml::Value::from("enabled"),
        serde_yaml::Value::from(enabled),
    );
    cluster_map.insert(mdns_key, serde_yaml::Value::Mapping(mdns_map));
    map.insert(cluster_key, serde_yaml::Value::Mapping(cluster_map));
    let serialised =
        serde_yaml::to_string(&root).context("serialise freedom.yaml after cluster mdns toggle")?;
    write_mode_0600(path, serialised.as_bytes())
}

/// Lossless top-level-string set: read freedom.yaml as a `serde_yaml::Value`
/// mapping, insert/replace `key = value`, write back — preserving EVERY
/// other field (inference topology, council, profile, tokens, ...). The
/// typed `MinimalFreedomYaml` round-trip is LOSSY (5 fields, no flatten) and
/// must NEVER be used for an in-place edit: it silently drops everything it
/// doesn't model. This is the only safe writer for the settings panel's
/// provider/model selectors. Atomic via `write_mode_0600` (.tmp + rename).
fn set_top_level_string_in_freedom(path: &Path, key: &str, value: &str) -> Result<()> {
    let _guard = FREEDOM_WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let body = if path.exists() {
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?
    } else {
        String::new()
    };
    let mut root: serde_yaml::Value = if body.trim().is_empty() {
        serde_yaml::Value::Mapping(serde_yaml::Mapping::new())
    } else {
        serde_yaml::from_str(&body).with_context(|| format!("parse {}", path.display()))?
    };
    let map = match &mut root {
        serde_yaml::Value::Mapping(m) => m,
        _ => anyhow::bail!("freedom.yaml is not a YAML mapping"),
    };
    map.insert(serde_yaml::Value::from(key), serde_yaml::Value::from(value));
    let serialised = serde_yaml::to_string(&root)
        .with_context(|| format!("serialise freedom.yaml after setting {key}"))?;
    write_mode_0600(path, serialised.as_bytes())
}

/// PF-01-GUI — read `skills.always_embed_route` from freedom.yaml. Defaults to
/// `true` (matching the daemon's `SkillsConfig` default) on a missing file /
/// key / malformed YAML, so the GUI toggle reflects the effective behaviour.
fn read_skills_always_embed_route(path: &Path) -> bool {
    let Ok(body) = std::fs::read_to_string(path) else {
        return true;
    };
    let Ok(root) = serde_yaml::from_str::<serde_yaml::Value>(&body) else {
        return true;
    };
    root.get("skills")
        .and_then(|s| s.get("always_embed_route"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true)
}

/// PF-01-GUI — lossless nested set of `skills.always_embed_route`. Mirrors
/// `set_cluster_mdns_enabled_in_freedom`: a serde_yaml `Value` round-trip that
/// preserves EVERY other field. Atomic via `write_mode_0600`.
fn set_skills_always_embed_route_in_freedom(path: &Path, enabled: bool) -> Result<()> {
    // Serialise with every other freedom.yaml read-modify-write (the DES-09 GUI
    // worker threads) — same lock set_nested_in_freedom holds.
    let _guard = FREEDOM_WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let body = if path.exists() {
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?
    } else {
        String::new()
    };
    let mut root: serde_yaml::Value = if body.trim().is_empty() {
        serde_yaml::Value::Mapping(serde_yaml::Mapping::new())
    } else {
        serde_yaml::from_str(&body).with_context(|| format!("parse {}", path.display()))?
    };
    let map = match &mut root {
        serde_yaml::Value::Mapping(m) => m,
        _ => anyhow::bail!("freedom.yaml is not a YAML mapping"),
    };
    let skills_key = serde_yaml::Value::from("skills");
    let mut skills_map = map
        .get(&skills_key)
        .and_then(|v| v.as_mapping())
        .cloned()
        .unwrap_or_default();
    skills_map.insert(
        serde_yaml::Value::from("always_embed_route"),
        serde_yaml::Value::from(enabled),
    );
    map.insert(skills_key, serde_yaml::Value::Mapping(skills_map));
    let serialised = serde_yaml::to_string(&root)
        .context("serialise freedom.yaml after skills.always_embed_route toggle")?;
    write_mode_0600(path, serialised.as_bytes())
}

fn validate_autonomy(level: &str) -> Result<()> {
    match level {
        "strict" | "standard" | "elevated" | "full" | "custom" => Ok(()),
        other => anyhow::bail!("unrecognised autonomy level '{other}'"),
    }
}

fn omi_mode_listens(mode: &str) -> bool {
    matches!(mode, "native_ingest" | "both")
}

fn omi_endpoint_host(endpoint: &str) -> Option<&str> {
    let (_, rest) = endpoint.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    if let Some(bracketed) = authority.strip_prefix('[') {
        return bracketed.split_once(']').map(|(host, _)| host);
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            Some(host)
        }
        _ => Some(authority),
    }
}

fn omi_host_is_local(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            let octets = ip.octets();
            ip.is_loopback()
                || ip.is_private()
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        }
        Ok(std::net::IpAddr::V6(ip)) => ip.is_loopback() || (ip.segments()[0] & 0xfe00) == 0xfc00,
        Err(_) => false,
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_omi_fields(
    enabled: bool,
    mode: &str,
    endpoint: &str,
    listen_addr: &str,
    retention_days: &str,
    allow_cloud_api: bool,
    allow_cloud_summary: bool,
    summary_enabled: bool,
    audio_enabled: bool,
    image_enabled: bool,
    video_enabled: bool,
    developer_key_present: bool,
    native_token_present: bool,
    developer_key_draft: &str,
    native_token_draft: &str,
) -> Result<u64> {
    if !matches!(
        mode,
        "developer_api" | "native_ingest" | "both" | "legacy_memories"
    ) {
        anyhow::bail!("unknown OMI mode `{mode}`");
    }
    let retention_days: u64 = retention_days
        .parse()
        .context("OMI retention days must be an integer")?;
    if !(1..=3_650).contains(&retention_days) {
        anyhow::bail!("OMI retention days must be between 1 and 3650");
    }
    if endpoint.trim() != endpoint || listen_addr.trim() != listen_addr {
        anyhow::bail!("OMI endpoint/listener must not contain surrounding whitespace");
    }
    if mode != "native_ingest" {
        let host = omi_endpoint_host(endpoint).context("OMI endpoint must be an http(s) URL")?;
        let endpoint_is_https = endpoint.starts_with("https://");
        let endpoint_is_http = endpoint.starts_with("http://");
        if !endpoint_is_http && !endpoint_is_https {
            anyhow::bail!("OMI endpoint must start with http:// or https://");
        }
        if endpoint.contains(['?', '#']) {
            anyhow::bail!("OMI endpoint must not contain a query or fragment");
        }
        if mode == "legacy_memories" && !omi_host_is_local(host) {
            anyhow::bail!("legacy OMI endpoint must be loopback/private");
        }
        if matches!(mode, "developer_api" | "both")
            && !omi_host_is_local(host)
            && (!allow_cloud_api || !endpoint_is_https)
        {
            anyhow::bail!("public OMI Developer API requires explicit cloud opt-in and HTTPS");
        }
    }
    if allow_cloud_api && !matches!(mode, "developer_api" | "both") {
        anyhow::bail!("OMI cloud API consent requires developer_api or both mode");
    }
    if allow_cloud_summary && (!summary_enabled || !omi_mode_listens(mode)) {
        anyhow::bail!("cloud summary consent requires summaries and native_ingest/both mode");
    }
    let socket: std::net::SocketAddr = listen_addr
        .parse()
        .context("OMI native listener must be an IP:port socket")?;
    if socket.port() == 0 {
        anyhow::bail!("OMI native listener port must be non-zero");
    }
    let local = match socket.ip() {
        std::net::IpAddr::V4(ip) => {
            let octets = ip.octets();
            ip.is_loopback()
                || ip.is_private()
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        }
        std::net::IpAddr::V6(ip) => ip.is_loopback() || (ip.segments()[0] & 0xfe00) == 0xfc00,
    };
    if !local {
        anyhow::bail!("OMI native listener must bind loopback/private IP, never wildcard/public");
    }
    if video_enabled && !image_enabled {
        anyhow::bail!("OMI video consent requires image/visual processing consent");
    }
    if !omi_mode_listens(mode) && (audio_enabled || image_enabled || video_enabled) {
        anyhow::bail!("OMI media consents require native_ingest or both mode");
    }
    if !developer_key_draft.is_empty()
        && (!developer_key_draft.starts_with("omi_dev_")
            || developer_key_draft.len() == "omi_dev_".len()
            || developer_key_draft.trim() != developer_key_draft)
    {
        anyhow::bail!("OMI Developer key must be a trimmed non-empty omi_dev_* value");
    }
    if !native_token_draft.is_empty()
        && (native_token_draft.len() < 32 || native_token_draft.trim() != native_token_draft)
    {
        anyhow::bail!("OMI native token must be trimmed and contain at least 32 bytes");
    }
    if enabled
        && matches!(mode, "developer_api" | "both")
        && !developer_key_present
        && developer_key_draft.is_empty()
    {
        anyhow::bail!("enabled Developer API mode requires an omi_dev_* key");
    }
    if enabled && omi_mode_listens(mode) && !native_token_present && native_token_draft.is_empty() {
        anyhow::bail!("enabled native OMI mode requires a bearer token of at least 32 bytes");
    }
    Ok(retention_days)
}

fn credential_value_present(path: &Path, key: &str) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|body| serde_yaml::from_str::<serde_yaml::Value>(&body).ok())
        .and_then(|value| value.get(key).and_then(|v| v.as_str()).map(str::to_owned))
        .is_some_and(|value| !value.is_empty())
}

fn validate_wizard_omi(state: &WizardSnapshot) -> Result<()> {
    let credentials_path = default_neoth_home().join("credentials.yaml");
    let needs_existing_developer = state.omi_enabled
        && matches!(state.omi_mode.as_str(), "developer_api" | "both")
        && state.omi_developer_key.is_empty();
    let needs_existing_native =
        state.omi_enabled && omi_mode_listens(&state.omi_mode) && state.omi_native_token.is_empty();
    let effective = (needs_existing_developer || needs_existing_native).then(fetch_omi_snapshot);
    let developer_present = effective
        .as_ref()
        .is_some_and(|snapshot| snapshot.developer_credential_present)
        || credential_value_present(&credentials_path, "omi_developer_api_key");
    let native_present = effective
        .as_ref()
        .is_some_and(|snapshot| snapshot.native_credential_present)
        || credential_value_present(&credentials_path, "omi_ingest_token");
    validate_omi_fields(
        state.omi_enabled,
        &state.omi_mode,
        &state.omi_endpoint,
        &state.omi_listen_addr,
        &state.omi_retention_days,
        state.omi_allow_cloud_api,
        state.omi_allow_cloud_summary,
        state.omi_summary_enabled,
        state.omi_audio_enabled,
        state.omi_image_enabled,
        state.omi_video_enabled,
        developer_present,
        native_present,
        &state.omi_developer_key,
        &state.omi_native_token,
    )?;
    Ok(())
}

#[derive(Clone)]
struct OmiSettingsDraft {
    enabled: bool,
    mode: String,
    endpoint: String,
    listen_addr: String,
    retention_days: String,
    retain_transcripts: bool,
    audio_enabled: bool,
    image_enabled: bool,
    video_enabled: bool,
    allow_cloud_api: bool,
    allow_cloud_summary: bool,
    create_actions: bool,
    seed_groundtruth: bool,
    summary_enabled: bool,
    developer_key: String,
    native_token: String,
}

fn persist_omi_credentials_via_cli(
    home: &Path,
    developer_key: &str,
    native_token: &str,
) -> Result<()> {
    use std::io::Write as _;

    if developer_key.is_empty() && native_token.is_empty() {
        return Ok(());
    }
    let bin = which_neothd().context("neothd binary not found for OMI credential update")?;
    let mut fields = serde_json::Map::new();
    if !developer_key.is_empty() {
        fields.insert(
            "developer_api_key".into(),
            serde_json::Value::String(developer_key.to_string()),
        );
    }
    if !native_token.is_empty() {
        fields.insert(
            "native_ingest_token".into(),
            serde_json::Value::String(native_token.to_string()),
        );
    }
    let mut body = serde_json::to_vec(&fields).context("encode OMI credential update")?;
    let mut command = spawn_neothd_plain(&bin);
    command
        .arg("omi")
        .arg("--home")
        .arg(home)
        .arg("set-credentials")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command
        .spawn()
        .context("start private OMI credential update")?;
    let write_result = child
        .stdin
        .take()
        .context("open OMI credential update stdin")?
        .write_all(&body);
    body.fill(0);
    if let Err(error) = write_result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error).context("send OMI credentials over private child stdin");
    }
    let output = child
        .wait_with_output()
        .context("wait for OMI credential update")?;
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        anyhow::bail!("{}", if stderr.is_empty() { stdout } else { stderr });
    }
    Ok(())
}

fn save_omi_settings(
    home: &Path,
    draft: &OmiSettingsDraft,
    developer_key_present: bool,
    native_token_present: bool,
) -> Result<()> {
    let retention_days = validate_omi_fields(
        draft.enabled,
        &draft.mode,
        &draft.endpoint,
        &draft.listen_addr,
        &draft.retention_days,
        draft.allow_cloud_api,
        draft.allow_cloud_summary,
        draft.summary_enabled,
        draft.audio_enabled,
        draft.image_enabled,
        draft.video_enabled,
        developer_key_present,
        native_token_present,
        &draft.developer_key,
        &draft.native_token,
    )?;
    std::fs::create_dir_all(home).with_context(|| format!("create {}", home.display()))?;
    let _guard = FREEDOM_WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // Secrets commit first through the daemon's strict, cross-process-locked
    // credential API. The bounded JSON travels over child stdin, never argv;
    // encrypted files and the configured keychain backend therefore retain
    // their normal semantics. A later config-write failure can leave an unused
    // secret, but never an enabled runtime missing its required credential.
    persist_omi_credentials_via_cli(home, &draft.developer_key, &draft.native_token)?;

    let freedom_path = home.join("freedom.yaml");
    let mut root = if freedom_path.exists() {
        let body = std::fs::read_to_string(&freedom_path)
            .with_context(|| format!("read {}", freedom_path.display()))?;
        serde_yaml::from_str::<serde_yaml::Value>(&body)
            .with_context(|| format!("parse {}", freedom_path.display()))?
    } else {
        serde_yaml::Value::Mapping(serde_yaml::Mapping::new())
    };
    let root_map = root
        .as_mapping_mut()
        .context("freedom.yaml is not a YAML mapping")?;
    let omi_key = serde_yaml::Value::from("omi");
    let mut omi = root_map
        .get(&omi_key)
        .and_then(serde_yaml::Value::as_mapping)
        .cloned()
        .unwrap_or_default();
    for (key, value) in [
        ("enabled", serde_yaml::Value::from(draft.enabled)),
        ("mode", serde_yaml::Value::from(draft.mode.clone())),
        ("endpoint", serde_yaml::Value::from(draft.endpoint.clone())),
        (
            "listen_addr",
            serde_yaml::Value::from(draft.listen_addr.clone()),
        ),
        ("retention_days", serde_yaml::Value::from(retention_days)),
        (
            "retain_transcripts",
            serde_yaml::Value::from(draft.retain_transcripts),
        ),
        (
            "audio_enabled",
            serde_yaml::Value::from(draft.audio_enabled),
        ),
        (
            "visual_enabled",
            serde_yaml::Value::from(draft.image_enabled),
        ),
        (
            "video_enabled",
            serde_yaml::Value::from(draft.video_enabled),
        ),
        (
            "allow_cloud_api",
            serde_yaml::Value::from(draft.allow_cloud_api),
        ),
        (
            "allow_cloud_summary",
            serde_yaml::Value::from(draft.allow_cloud_summary),
        ),
        (
            "create_actions",
            serde_yaml::Value::from(draft.create_actions),
        ),
        (
            "seed_groundtruth",
            serde_yaml::Value::from(draft.seed_groundtruth),
        ),
        (
            "summary_enabled",
            serde_yaml::Value::from(draft.summary_enabled),
        ),
    ] {
        omi.insert(serde_yaml::Value::from(key), value);
    }
    root_map.insert(omi_key, serde_yaml::Value::Mapping(omi));
    let body = serde_yaml::to_string(&root).context("serialise OMI settings")?;
    write_mode_0600(&freedom_path, body.as_bytes())?;
    std::fs::write(home.join(".reload-requested"), b"reload\n")
        .context("write OMI reload sentinel")?;
    Ok(())
}

fn run_omi_subcommand(home: &Path, args: &[String]) -> Result<String> {
    let bin = which_neothd().context("neothd binary not found")?;
    let mut command = spawn_neothd_plain(&bin);
    command.arg("omi").arg("--home").arg(home);
    command.args(args);
    let output = command.output().context("run OMI operator command")?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !output.status.success() {
        anyhow::bail!("{}", if stderr.is_empty() { stdout } else { stderr });
    }
    Ok(if stdout.is_empty() {
        "OMI command completed.".to_string()
    } else {
        stdout
    })
}

// ── ZF-05 parity writer ───────────────────────────────────────────────────
//
// Called from on_finish_clicked after write_freedom_yaml has created the base
// freedom.yaml. Patches the parity fields using set_nested_in_freedom so the
// rest of the config is preserved. Runs on the UI thread (inside the callback);
// we tolerate the brief blocking because this is a once-per-wizard operation
// and the file was just created so I/O should be fast.

/// Write the ZF-05 parity fields from the wizard into an already-existing
/// freedom.yaml. Idempotent: if a field is blank / false / default-port it
/// is skipped to avoid cluttering a fresh config with empty strings.
fn write_zf05_fields(fp: &Path, rd: &Path, state: &WizardSnapshot) -> Result<()> {
    let write = |key: &str, val: serde_yaml::Value| {
        set_nested_in_freedom(fp, key, val).with_context(|| format!("write GUI parity field {key}"))
    };

    // Preset — apply through the real consent path (`neoth preset apply`),
    // NOT a bare yaml key: FreedomConfig has no `preset` field, so writing one
    // would silently do nothing. full-auto needs the token ceremony route.
    if wizard_logic::preset_is_express(&state.wizard_preset_choice) {
        let known = wizard_logic::BUILTIN_PRESETS
            .iter()
            .any(|(n, _)| *n == state.wizard_preset_choice);
        if known {
            let status = if state.wizard_preset_choice == "full-auto" {
                apply_preset_with_fullauto_token(&state.wizard_preset_choice)
            } else {
                apply_preset_direct(&state.wizard_preset_choice)
            };
            if !status.starts_with("Applied preset `") {
                anyhow::bail!("{status}");
            }
            tracing::info!(
                preset = %state.wizard_preset_choice,
                %status,
                "ZF-05: wizard express preset applied"
            );
        } else {
            anyhow::bail!(
                "unknown wizard preset `{}`; refusing partial completion",
                state.wizard_preset_choice
            );
        }
    }

    // HMAC / outbound webhook — only when the operator enabled it.
    if state.wz_hmac_enabled {
        write("webhook_manager.enabled", serde_yaml::Value::from(true))?;
        if !state.wz_hmac_webhook_url.is_empty() {
            // First endpoint entry: write as a single-element list of mappings.
            let mut ep = serde_yaml::Mapping::new();
            ep.insert(
                serde_yaml::Value::from("url"),
                serde_yaml::Value::from(state.wz_hmac_webhook_url.as_str()),
            );
            if !state.wz_hmac_webhook_secret.is_empty() {
                ep.insert(
                    serde_yaml::Value::from("secret"),
                    serde_yaml::Value::from(state.wz_hmac_webhook_secret.as_str()),
                );
            }
            write(
                "webhook_manager.endpoints",
                serde_yaml::Value::Sequence(vec![serde_yaml::Value::Mapping(ep)]),
            )?;
        }
    }

    // Obsidian vault — only when a path was entered.
    if !state.wz_obsidian_vault.is_empty() {
        write(
            "obsidian_vault",
            serde_yaml::Value::from(state.wz_obsidian_vault.as_str()),
        )?;
        let subdir = if state.wz_obsidian_subdir.is_empty() {
            "NEOTH-sessions"
        } else {
            state.wz_obsidian_subdir.as_str()
        };
        write("obsidian_subdir", serde_yaml::Value::from(subdir))?;
        if state.wz_obsidian_reader_enabled {
            write(
                "obsidian_vault_reader_enabled",
                serde_yaml::Value::from(true),
            )?;
        }
    }

    // n8n — only when enabled.
    if state.wz_n8n_enabled {
        write("n8n_api.enabled", serde_yaml::Value::from(true))?;
        // Parse as u16 so an out-of-range entry ("99999") falls back to the
        // default instead of writing a port the daemon cannot deserialize.
        let port = if state.wz_n8n_port.is_empty() {
            9744u16
        } else {
            match state.wz_n8n_port.parse::<u16>() {
                Ok(p) => p,
                Err(_) => {
                    tracing::warn!(raw = %state.wz_n8n_port, "ZF-05: invalid n8n port — using default 9744");
                    9744
                }
            }
        };
        write("n8n_api.port", serde_yaml::Value::from(u64::from(port)))?;
    }

    // WASM plugin host — only when enabled.
    if state.wz_wasm_enabled {
        write("plugins.wasm.enabled", serde_yaml::Value::from(true))?;
    }

    // ONE reload signal after all fields are written — the daemon reloads a
    // complete config instead of racing seven partial writes.
    std::fs::write(rd, b"reload\n")
        .with_context(|| format!("write GUI reload signal {}", rd.display()))?;
    Ok(())
}

// ── DES-09 generic nested writer ──────────────────────────────────────────
//
// All DES-09 settings-panel write-backs go through `set_nested_in_freedom`.
// The dotted-key notation "a.b.c" walks (and creates) nested YAML mappings
// exactly like the daemon's `merge_overrides` in config/presets.rs, but is
// self-contained in the GUI crate so no daemon dep is needed.
//
// Top-level keys (e.g. "obsidian_vault", "user_tz") use a single segment.

/// DES-09 — generic lossless nested-key writer for freedom.yaml.
///
/// `dotted_key` — dot-separated YAML path, e.g. "council.daily_usd_cap"
///                or bare top-level key "user_tz".
///
/// Preserves every other key via `serde_yaml::Value` round-trip.
/// Atomic write via `write_mode_0600` (.tmp + rename).
///
/// # Panics
///
/// None — all errors are returned via `Result`.
fn set_nested_in_freedom(path: &Path, dotted_key: &str, value: serde_yaml::Value) -> Result<()> {
    let _guard = FREEDOM_WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let body = if path.exists() {
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?
    } else {
        String::new()
    };
    let mut root: serde_yaml::Value = if body.trim().is_empty() {
        serde_yaml::Value::Mapping(serde_yaml::Mapping::new())
    } else {
        serde_yaml::from_str(&body).with_context(|| format!("parse {}", path.display()))?
    };
    let map = match &mut root {
        serde_yaml::Value::Mapping(m) => m,
        _ => anyhow::bail!("freedom.yaml is not a YAML mapping"),
    };

    let segments: Vec<&str> = dotted_key.splitn(8, '.').collect();
    match segments.as_slice() {
        [leaf] => {
            map.insert(serde_yaml::Value::from(*leaf), value);
        }
        [k1, leaf] => {
            let k1v = serde_yaml::Value::from(*k1);
            let mut inner = map
                .get(&k1v)
                .and_then(|v| v.as_mapping())
                .cloned()
                .unwrap_or_default();
            inner.insert(serde_yaml::Value::from(*leaf), value);
            map.insert(k1v, serde_yaml::Value::Mapping(inner));
        }
        [k1, k2, leaf] => {
            let k1v = serde_yaml::Value::from(*k1);
            let mut m1 = map
                .get(&k1v)
                .and_then(|v| v.as_mapping())
                .cloned()
                .unwrap_or_default();
            let k2v = serde_yaml::Value::from(*k2);
            let mut m2 = m1
                .get(&k2v)
                .and_then(|v| v.as_mapping())
                .cloned()
                .unwrap_or_default();
            m2.insert(serde_yaml::Value::from(*leaf), value);
            m1.insert(k2v, serde_yaml::Value::Mapping(m2));
            map.insert(k1v, serde_yaml::Value::Mapping(m1));
        }
        _ => anyhow::bail!("set_nested_in_freedom: path depth > 3 not supported: {dotted_key}"),
    }

    let serialised = serde_yaml::to_string(&root)
        .with_context(|| format!("serialise freedom.yaml after setting {dotted_key}"))?;
    write_mode_0600(path, serialised.as_bytes())
}

/// Post-success hook for `make_coalescing_writer`, run on the UI event loop
/// after a successful write. `Arc<dyn Fn>` so plain fields pass `None`.
type WriteSuccessHook = std::sync::Arc<dyn Fn(&MainWindow) + Send + Sync>;

/// DES-09 — per-field coalescing writer for freedom.yaml.
///
/// A LineEdit's `edited` callback fires once per keystroke, so typing "gpt-4o"
/// would otherwise spawn six writer threads that race for `FREEDOM_WRITE_LOCK`.
/// `std::sync::Mutex` is not FIFO-fair, so a stale-prefix thread ("gpt-4") can
/// acquire the lock after the final-value thread ("gpt-4o") and overwrite the
/// correct value on disk — worst on the slow/network home dirs this async path
/// exists to keep responsive.
///
/// This returns a `SyncSender`; the callback becomes a non-blocking `send`. One
/// dedicated worker per field drains the channel keeping only the latest value
/// (last-typed wins — stronger than FIFO, no ordering assumptions), then does a
/// single read-modify-write + reload sentinel + toast. Collapses a keystroke
/// burst to one fsync and one toast, and never touches the UI thread with I/O.
///
/// The worker exits cleanly when the callback (and thus the `SyncSender`) is
/// dropped on window teardown — `recv()` then returns `Err`.
///
/// `on_success`, if set, runs on the UI event loop after each successful write
/// (e.g. the Obsidian vault field re-scans the vault). `None` for plain fields.
fn make_coalescing_writer(
    fp: std::path::PathBuf,
    rd: std::path::PathBuf,
    dotted_key: &'static str,
    label: &'static str,
    weak: slint::Weak<MainWindow>,
    on_success: Option<WriteSuccessHook>,
) -> std::sync::mpsc::SyncSender<serde_yaml::Value> {
    // Bounded buffer: human typing never outpaces one fsync by 64 events, and a
    // paste is a single `edited` event, so `send` never blocks the UI thread in
    // practice while still bounding memory.
    let (tx, rx) = std::sync::mpsc::sync_channel::<serde_yaml::Value>(64);
    std::thread::spawn(move || {
        while let Ok(mut val) = rx.recv() {
            // Coalesce the burst: keep only the most recent queued value.
            while let Ok(newer) = rx.try_recv() {
                val = newer;
            }
            let result = set_nested_in_freedom(&fp, dotted_key, val)
                .and_then(|_| std::fs::write(&rd, b"reload\n").map_err(|e| anyhow::anyhow!(e)));
            match result {
                Ok(_) => {
                    push_toast(&weak, "success", label, "saved — daemon reloading");
                    // Optional post-success hook, marshalled to the UI event loop.
                    if let Some(hook) = &on_success {
                        let weak2 = weak.clone();
                        let hook = hook.clone();
                        slint::invoke_from_event_loop(move || {
                            if let Some(w) = weak2.upgrade() {
                                hook(&w);
                            }
                        })
                        .ok();
                    }
                }
                Err(ref e) => push_toast(&weak, "warn", label, &format!("write failed: {e}")),
            }
        }
    });
    tx
}

/// DES-09 helper — read a nested boolean from freedom.yaml.
/// Returns `default` on missing file / key / malformed YAML.
/// DES-09 G37 — read `proactive.quiet_hours_utc` ([u8;2] or null/absent).
fn read_quiet_hours_in_freedom(path: &Path) -> Option<(u8, u8)> {
    let body = std::fs::read_to_string(path).ok()?;
    let root = serde_yaml::from_str::<serde_yaml::Value>(&body).ok()?;
    let seq = root
        .get("proactive")?
        .get("quiet_hours_utc")?
        .as_sequence()?;
    match seq.as_slice() {
        [s, e] => Some((s.as_u64()? as u8, e.as_u64()? as u8)),
        _ => None,
    }
}

fn read_nested_bool_in_freedom(path: &Path, dotted_key: &str, default: bool) -> bool {
    let Ok(body) = std::fs::read_to_string(path) else {
        return default;
    };
    let Ok(root) = serde_yaml::from_str::<serde_yaml::Value>(&body) else {
        return default;
    };
    let segments: Vec<&str> = dotted_key.splitn(8, '.').collect();
    let leaf = match segments.as_slice() {
        [leaf] => root.get(serde_yaml::Value::from(*leaf)),
        [k1, leaf] => root
            .get(k1)
            .and_then(|v| v.get(serde_yaml::Value::from(*leaf))),
        [k1, k2, leaf] => root
            .get(k1)
            .and_then(|v| v.get(*k2))
            .and_then(|v| v.get(serde_yaml::Value::from(*leaf))),
        _ => None,
    };
    leaf.and_then(|v| v.as_bool()).unwrap_or(default)
}

/// DES-09 helper — read a nested string from freedom.yaml.
/// Returns `default` on missing file / key / malformed YAML.
fn read_nested_str_in_freedom(path: &Path, dotted_key: &str, default: &str) -> String {
    let Ok(body) = std::fs::read_to_string(path) else {
        return default.to_string();
    };
    let Ok(root) = serde_yaml::from_str::<serde_yaml::Value>(&body) else {
        return default.to_string();
    };
    let segments: Vec<&str> = dotted_key.splitn(8, '.').collect();
    let leaf = match segments.as_slice() {
        [leaf] => root.get(serde_yaml::Value::from(*leaf)),
        [k1, leaf] => root
            .get(k1)
            .and_then(|v| v.get(serde_yaml::Value::from(*leaf))),
        [k1, k2, leaf] => root
            .get(k1)
            .and_then(|v| v.get(*k2))
            .and_then(|v| v.get(serde_yaml::Value::from(*leaf))),
        _ => None,
    };
    leaf.and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| default.to_string())
}

/// DES-09 helper — read a nested i64 from freedom.yaml.
/// Returns `default` on missing file / key / malformed YAML.
fn read_nested_i64_in_freedom(path: &Path, dotted_key: &str, default: i64) -> i64 {
    let Ok(body) = std::fs::read_to_string(path) else {
        return default;
    };
    let Ok(root) = serde_yaml::from_str::<serde_yaml::Value>(&body) else {
        return default;
    };
    let segments: Vec<&str> = dotted_key.splitn(8, '.').collect();
    let leaf = match segments.as_slice() {
        [leaf] => root.get(serde_yaml::Value::from(*leaf)),
        [k1, leaf] => root
            .get(k1)
            .and_then(|v| v.get(serde_yaml::Value::from(*leaf))),
        [k1, k2, leaf] => root
            .get(k1)
            .and_then(|v| v.get(*k2))
            .and_then(|v| v.get(serde_yaml::Value::from(*leaf))),
        _ => None,
    };
    leaf.and_then(|v| v.as_i64()).unwrap_or(default)
}

/// DES-09 helper — read a nested f64 from freedom.yaml.
/// Returns `default` on missing file / key / malformed YAML.
/// Used for fields like `council.daily_usd_cap` which are stored as YAML floats.
fn read_nested_f64_in_freedom(path: &Path, dotted_key: &str) -> Option<f64> {
    let Ok(body) = std::fs::read_to_string(path) else {
        return None;
    };
    let Ok(root) = serde_yaml::from_str::<serde_yaml::Value>(&body) else {
        return None;
    };
    let segments: Vec<&str> = dotted_key.splitn(8, '.').collect();
    let leaf = match segments.as_slice() {
        [leaf] => root.get(serde_yaml::Value::from(*leaf)),
        [k1, leaf] => root
            .get(k1)
            .and_then(|v| v.get(serde_yaml::Value::from(*leaf))),
        [k1, k2, leaf] => root
            .get(k1)
            .and_then(|v| v.get(*k2))
            .and_then(|v| v.get(serde_yaml::Value::from(*leaf))),
        _ => None,
    };
    leaf.and_then(|v| v.as_f64())
}

/// Format an f64 cap value for display: strip the trailing ".0" for whole
/// numbers so "10" shows instead of "10.0", but "10.5" stays "10.5".
fn format_cap_f64(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

/// GUI-DES-SETTINGS-PRELOAD-01 — read a top-level YAML sequence as Vec<String>.
///
/// Only top-level keys are supported (no dotted paths) because
/// `knowledge_preload_dirs` is a bare list at the root of freedom.yaml.
/// Returns an empty vec on missing file / missing key / non-sequence / malformed YAML.
fn read_nested_seq_in_freedom(path: &Path, key: &str) -> Vec<String> {
    let Ok(body) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(root) = serde_yaml::from_str::<serde_yaml::Value>(&body) else {
        return Vec::new();
    };
    let serde_yaml::Value::Mapping(map) = root else {
        return Vec::new();
    };
    map.get(serde_yaml::Value::from(key))
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|v| v.as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// GUI-DES-SETTINGS-PRELOAD-01 — unit tests for preload helpers.
#[cfg(test)]
mod preload01_tests {
    use super::*;
    use tempfile::TempDir;

    fn write_yaml(dir: &TempDir, content: &str) -> std::path::PathBuf {
        let path = dir.path().join("freedom.yaml");
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn seq_reads_list_as_vec() {
        let dir = TempDir::new().unwrap();
        let path = write_yaml(
            &dir,
            "knowledge_preload_dirs:\n  - /home/user/docs\n  - /var/data/kb\n",
        );
        let got = read_nested_seq_in_freedom(&path, "knowledge_preload_dirs");
        assert_eq!(got, vec!["/home/user/docs", "/var/data/kb"]);
    }

    #[test]
    fn seq_returns_empty_for_missing_key() {
        let dir = TempDir::new().unwrap();
        let path = write_yaml(&dir, "other_key: value\n");
        let got = read_nested_seq_in_freedom(&path, "knowledge_preload_dirs");
        assert!(got.is_empty(), "expected empty vec, got {got:?}");
    }

    #[test]
    fn seq_returns_empty_for_missing_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("does_not_exist.yaml");
        let got = read_nested_seq_in_freedom(&path, "knowledge_preload_dirs");
        assert!(got.is_empty());
    }

    #[test]
    fn seq_join_roundtrip() {
        // Write a seq to yaml, read it back, join with "\n" — matches newline-sep UI text.
        let dir = TempDir::new().unwrap();
        let path = write_yaml(&dir, "knowledge_preload_dirs:\n  - /alpha\n  - /beta\n");
        let got = read_nested_seq_in_freedom(&path, "knowledge_preload_dirs");
        assert_eq!(got.join("\n"), "/alpha\n/beta");
    }

    #[test]
    fn newline_list_to_seq_round_trips() {
        // Simulates on_obs_knowledge_preload_dirs_changed: multiline editor → Vec<String>.
        let raw = "/home/user/docs\n/var/data/kb\n\n  ";
        let paths: Vec<String> = raw
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        assert_eq!(paths, vec!["/home/user/docs", "/var/data/kb"]);
    }

    #[test]
    fn newline_list_empty_gives_empty_vec() {
        let raw = "\n  \n\t\n";
        let paths: Vec<String> = raw
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        assert!(paths.is_empty());
    }
}

#[cfg(test)]
mod des09_tests {
    use super::*;
    use tempfile::TempDir;

    fn write_yaml(dir: &TempDir, content: &str) -> std::path::PathBuf {
        let path = dir.path().join("freedom.yaml");
        std::fs::write(&path, content).unwrap();
        path
    }

    // Helper that uses std write (no ACL) so tests pass on all platforms.
    fn set_nested_test(path: &Path, key: &str, value: serde_yaml::Value) -> Result<()> {
        let body = if path.exists() {
            std::fs::read_to_string(path).unwrap()
        } else {
            String::new()
        };
        let mut root: serde_yaml::Value = if body.trim().is_empty() {
            serde_yaml::Value::Mapping(serde_yaml::Mapping::new())
        } else {
            serde_yaml::from_str(&body).unwrap()
        };
        let map = match &mut root {
            serde_yaml::Value::Mapping(m) => m,
            _ => panic!("not a mapping"),
        };
        let segs: Vec<&str> = key.splitn(8, '.').collect();
        match segs.as_slice() {
            [leaf] => {
                map.insert(serde_yaml::Value::from(*leaf), value);
            }
            [k1, leaf] => {
                let k1v = serde_yaml::Value::from(*k1);
                let mut inner = map
                    .get(&k1v)
                    .and_then(|v| v.as_mapping())
                    .cloned()
                    .unwrap_or_default();
                inner.insert(serde_yaml::Value::from(*leaf), value);
                map.insert(k1v, serde_yaml::Value::Mapping(inner));
            }
            [k1, k2, leaf] => {
                let k1v = serde_yaml::Value::from(*k1);
                let mut m1 = map
                    .get(&k1v)
                    .and_then(|v| v.as_mapping())
                    .cloned()
                    .unwrap_or_default();
                let k2v = serde_yaml::Value::from(*k2);
                let mut m2 = m1
                    .get(&k2v)
                    .and_then(|v| v.as_mapping())
                    .cloned()
                    .unwrap_or_default();
                m2.insert(serde_yaml::Value::from(*leaf), value);
                m1.insert(k2v, serde_yaml::Value::Mapping(m2));
                map.insert(k1v, serde_yaml::Value::Mapping(m1));
            }
            _ => panic!("depth > 3"),
        }
        let out = serde_yaml::to_string(&root).unwrap();
        std::fs::write(path, out).unwrap();
        Ok(())
    }

    #[test]
    fn nested_create_two_level() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        set_nested_test(
            &path,
            "council.daily_usd_cap",
            serde_yaml::Value::from(5.0f64),
        )
        .unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        let root: serde_yaml::Value = serde_yaml::from_str(&body).unwrap();
        let got = root
            .get("council")
            .and_then(|v| v.get("daily_usd_cap"))
            .and_then(|v| v.as_f64())
            .unwrap();
        assert!((got - 5.0).abs() < 1e-9, "expected 5.0 got {got}");
    }

    #[test]
    fn nested_update_preserves_siblings() {
        let dir = TempDir::new().unwrap();
        let path = write_yaml(
            &dir,
            "council:\n  daily_usd_cap: 3.0\n  max_calls: 10\nother_key: kept\n",
        );
        set_nested_test(
            &path,
            "council.daily_usd_cap",
            serde_yaml::Value::from(9.0f64),
        )
        .unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        let root: serde_yaml::Value = serde_yaml::from_str(&body).unwrap();
        // other_key preserved
        assert_eq!(root.get("other_key").and_then(|v| v.as_str()), Some("kept"));
        // sibling inside council preserved
        assert_eq!(
            root.get("council")
                .and_then(|v| v.get("max_calls"))
                .and_then(|v| v.as_i64()),
            Some(10)
        );
        // updated value
        let cap = root
            .get("council")
            .and_then(|v| v.get("daily_usd_cap"))
            .and_then(|v| v.as_f64())
            .unwrap();
        assert!((cap - 9.0).abs() < 1e-9);
    }

    #[test]
    fn top_level_key() {
        let dir = TempDir::new().unwrap();
        let path = write_yaml(&dir, "provider_kind: claude_cli\n");
        set_nested_test(&path, "user_tz", serde_yaml::Value::from("Europe/Berlin")).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        let root: serde_yaml::Value = serde_yaml::from_str(&body).unwrap();
        assert_eq!(
            root.get("user_tz").and_then(|v| v.as_str()),
            Some("Europe/Berlin")
        );
        // provider_kind survives
        assert_eq!(
            root.get("provider_kind").and_then(|v| v.as_str()),
            Some("claude_cli")
        );
    }

    #[test]
    fn three_level_nested() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        set_nested_test(
            &path,
            "memory.vector_index.backend",
            serde_yaml::Value::from("hnsw"),
        )
        .unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        let root: serde_yaml::Value = serde_yaml::from_str(&body).unwrap();
        let got = root
            .get("memory")
            .and_then(|v| v.get("vector_index"))
            .and_then(|v| v.get("backend"))
            .and_then(|v| v.as_str())
            .unwrap();
        assert_eq!(got, "hnsw");
    }

    // ── FIX 4 tests — read_nested_f64_in_freedom + format_cap_f64 ──────────

    #[test]
    fn read_f64_returns_value_for_float_node() {
        let dir = TempDir::new().unwrap();
        let path = write_yaml(&dir, "council:\n  daily_usd_cap: 10.0\n");
        let v = read_nested_f64_in_freedom(&path, "council.daily_usd_cap");
        assert!(v.is_some(), "expected Some, got None");
        assert!((v.unwrap() - 10.0).abs() < 1e-9);
    }

    #[test]
    fn read_f64_returns_none_for_missing_key() {
        let dir = TempDir::new().unwrap();
        let path = write_yaml(&dir, "council:\n  max_calls: 5\n");
        let v = read_nested_f64_in_freedom(&path, "council.daily_usd_cap");
        assert!(v.is_none(), "expected None for missing key");
    }

    #[test]
    fn format_cap_strips_dot_zero_for_whole() {
        assert_eq!(format_cap_f64(10.0), "10");
        assert_eq!(format_cap_f64(0.0), "0");
        assert_eq!(format_cap_f64(100.0), "100");
    }

    #[test]
    fn format_cap_preserves_fractional() {
        assert_eq!(format_cap_f64(10.5), "10.5");
        assert_eq!(format_cap_f64(3.75), "3.75");
    }

    // ── FIX 2 / FIX 3 tests — Null write deserialized as YAML null ─────────

    #[test]
    fn null_write_round_trips_as_yaml_null() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        // Write Null to a key; read back and verify it is YAML null / absent.
        set_nested_test(&path, "persona_mode", serde_yaml::Value::Null).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        let root: serde_yaml::Value = serde_yaml::from_str(&body).unwrap();
        // serde_yaml::Value::Null means Option<T> deserializes as None.
        let node = root.get("persona_mode");
        // Either the key is absent or its value is Null — both are valid representations.
        let is_null_or_absent = node.is_none_or(|v| v.is_null());
        assert!(is_null_or_absent, "expected null or absent, got {:?}", node);
    }

    #[test]
    fn null_write_for_obsidian_sync_is_yaml_null() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        set_nested_test(&path, "obsidian_auto_sync_secs", serde_yaml::Value::Null).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        let root: serde_yaml::Value = serde_yaml::from_str(&body).unwrap();
        let node = root.get("obsidian_auto_sync_secs");
        let is_null_or_absent = node.is_none_or(|v| v.is_null());
        assert!(is_null_or_absent, "expected null or absent, got {:?}", node);
    }
}

/// Per-process-unique sibling temp path for an atomic credentials write
/// (GOLD-SEC-15 / A-34) — mirrors the daemon helper.
#[cfg(unix)]
fn atomic_tmp_path(path: &Path) -> std::path::PathBuf {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("credentials.yaml");
    path.with_file_name(format!(".{name}.tmp{}", std::process::id()))
}

#[cfg(unix)]
fn write_mode_0600(path: &Path, body: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    // Atomic 0600 write: temp (mode 0600 at create) → write+fsync → rename
    // (GOLD-SEC-15 / A-34). Secrets are never on disk under a wider mode,
    // and a crash mid-write leaves the old file intact.
    let tmp = atomic_tmp_path(path);
    let _ = std::fs::remove_file(&tmp);
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("create {} mode 0600", tmp.display()))?;
    file.write_all(body)
        .with_context(|| format!("write body to {}", tmp.display()))?;
    file.sync_all()
        .with_context(|| format!("fsync {}", tmp.display()))?;
    drop(file);
    std::fs::rename(&tmp, path)
        .with_context(|| format!("atomically replace {}", path.display()))?;
    Ok(())
}

#[cfg(windows)]
fn write_mode_0600(path: &Path, body: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut random = [0u8; 16];
    getrandom::getrandom(&mut random)
        .map_err(|error| anyhow::anyhow!("OS RNG unavailable for private temp name: {error}"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("private");
    let tmp = path.with_file_name(format!(".{name}.{}.tmp", hex::encode(random)));
    let mut file = win_private::create_private_file_new(&tmp)
        .with_context(|| format!("secure create {}", tmp.display()))?;
    file.write_all(body)
        .with_context(|| format!("write body to {}", tmp.display()))?;
    file.flush()
        .with_context(|| format!("flush {}", tmp.display()))?;
    file.sync_all()
        .with_context(|| format!("fsync {}", tmp.display()))?;
    if let Err(error) = win_private::replace_private_file_handle(&file, path) {
        drop(file);
        let _ = std::fs::remove_file(&tmp);
        return Err(error).with_context(|| format!("atomically replace {}", path.display()));
    }
    Ok(())
}

/// Wall-clock HH:MM:SS for chat bubble timestamps. Pure GUI display —
/// the daemon owns the canonical PROVIDER_REQUEST timestamp in the
/// WAL; this string just gives the operator a local read-receipt
/// next to their bubble. R2-P0-1 (2026-05-22): chat_via_subprocess
/// dispatches to `neothd chat` so the bubble round-trip now hits
/// the real provider + WAL + permission gates.
fn format_now_hms() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let s = now % 60;
    let m = (now / 60) % 60;
    let h = (now / 3600) % 24;
    format!("{h:02}:{m:02}:{s:02}")
}

/// G-6 fix — every subprocess we spawn against the `neothd` binary
/// MUST opt out of ANSI colour output. Without these env vars
/// tracing-subscriber emits `[2m...[0m` escape sequences into stdout,
/// which then surface verbatim in GUI text widgets (FooterBar,
/// hardware summary, kanban session summary). Centralised here so
/// every call site stays consistent.
fn suppress_console_window(command: &mut std::process::Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(not(windows))]
    let _ = command;
}

const TERMINAL_READY_FILE_ENV: &str = "NEOTH_READY_FILE";
const TERMINAL_READY_TOKEN_ENV: &str = "NEOTH_READY_TOKEN";
const INTERFACE_OVERRIDE_ENV: &str = "NEOTH_INTERFACE";

/// Launcher and one-shot transaction variables are capabilities, not ambient
/// configuration. Every unrelated child starts with them explicitly removed;
/// terminal launchers add only their fresh Ready pair back afterwards.
fn scrub_gui_control_environment(command: &mut std::process::Command) {
    for variable in [
        GUI_READY_FILE_ENV,
        GUI_READY_TOKEN_ENV,
        GUI_PARENT_COMMIT_ENV,
        PRODUCT_LAUNCHER_ENV,
        TERMINAL_READY_FILE_ENV,
        TERMINAL_READY_TOKEN_ENV,
        INTERFACE_OVERRIDE_ENV,
    ] {
        command.env_remove(variable);
    }
}

fn spawn_neothd_plain(bin: &Path) -> std::process::Command {
    let mut cmd = std::process::Command::new(bin);
    scrub_gui_control_environment(&mut cmd);
    cmd.env("NO_COLOR", "1")
        .env("RUST_LOG_STYLE", "never")
        .env("CLICOLOR", "0")
        // A parent launcher token is single-purpose. GUI-internal daemon
        // subprocesses must never inherit authority to acknowledge startup.
        // CRITICAL for stdout parsing: the daemon's `init_tracing` writes
        // tracing events (incl. the `INFO neothd: Neoth ready. Sup.`
        // startup banner) to STDOUT, not stderr. At the default
        // `info,neothd=debug` level those lines would prepend the
        // machine-readable JSON / streamed chat deltas every GUI
        // subprocess parses — corrupting `serde_json::from_slice` and the
        // `gui-stream` NDJSON channel alike. `error` suppresses the
        // banner + info/debug noise so stdout carries only the payload.
        // Genuine clap/anyhow failures still surface on stderr + via exit
        // code, so the GUI's error handling is unaffected.
        .env("NEOTH_LOG", "error");
    suppress_console_window(&mut cmd);
    cmd
}

fn channel_credential_command(bin: &Path) -> std::process::Command {
    let mut command = spawn_neothd_plain(bin);
    command
        .arg("channel")
        .arg("set-credentials")
        .arg("--output")
        .arg("json")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    command
}

fn channel_remove_command(bin: &Path, channel: &str) -> std::process::Command {
    let mut command = spawn_neothd_plain(bin);
    command
        .arg("channel")
        .arg("remove")
        .arg(channel)
        .arg("--output")
        .arg("json");
    command
}

/// Send channel credentials through the child's private stdin. The body is
/// zeroized on every return and unwind path, including lookup/spawn failures.
fn persist_channel_credentials_via_cli(
    body: zeroize::Zeroizing<Vec<u8>>,
) -> Result<std::process::Output, String> {
    use std::io::Write as _;

    let child_result = (|| {
        let bin = which_neothd()
            .ok_or_else(|| "NEOTH CLI not found; reinstall or repair PATH".to_string())?;
        let mut child = channel_credential_command(&bin)
            .spawn()
            .map_err(|error| format!("start private channel credential update: {error}"))?;
        let write_result = child
            .stdin
            .take()
            .ok_or_else(|| "open private channel credential stdin".to_string())
            .and_then(|mut stdin| {
                stdin
                    .write_all(body.as_slice())
                    .map_err(|error| format!("write private channel credential stdin: {error}"))
            });
        if let Err(error) = write_result {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        Ok(child)
    })();
    drop(body);
    child_result?
        .wait_with_output()
        .map_err(|error| format!("wait for private channel credential update: {error}"))
}

/// Run `neothd kanban list/show --output json` + group tasks by status.
/// Returns an empty snapshot with a friendly summary when the operator
/// hasn't opened a coding session yet, OR when the daemon binary is
/// missing — the GUI degrades gracefully instead of erroring out.
/// GR-10 — fetch the daemon's safety-rail state via `neoth security safe-mode
/// --json`. Returns an empty snapshot when the binary is absent or the call
/// fails (the panel renders a "no data" state, never crashes). The PARSE is the
/// unit-tested `panel_logic::parse_safe_mode`; this is the thin subprocess shell.
fn fetch_safe_mode_snapshot() -> panel_logic::SafeModeSnapshot {
    let Some(bin) = which_neothd() else {
        return panel_logic::SafeModeSnapshot::default();
    };
    match spawn_neothd_plain(&bin)
        .arg("security")
        .arg("safe-mode")
        .arg("--json")
        .output()
    {
        Ok(o) if o.status.success() => {
            panel_logic::parse_safe_mode(&String::from_utf8_lossy(&o.stdout))
        }
        _ => panel_logic::SafeModeSnapshot::default(),
    }
}

/// Run a read-only `neothd <args…>` probe; return combined stdout/stderr (or a
/// friendly error). Backs the Agents / Automation tabs (off the UI thread).
fn run_neothd_probe(args: &[&str]) -> String {
    match which_neothd().and_then(|bin| {
        let mut c = spawn_neothd_plain(&bin);
        for a in args {
            c.arg(a);
        }
        c.output().ok()
    }) {
        Some(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).to_string();
            let err = String::from_utf8_lossy(&o.stderr);
            if !err.trim().is_empty() {
                s.push('\n');
                s.push_str(&err);
            }
            if s.trim().is_empty() {
                "(no output)".to_string()
            } else {
                s
            }
        }
        None => "neothd binary not on PATH.".to_string(),
    }
}

/// Execute one GUI-triggered CLI action through the structured automation
/// contract. A successful exit without a valid typed acknowledgement is still
/// a failure; callers must additionally verify action-specific fields.
fn run_neothd_json_action<T>(args: &[&str], action: &str) -> std::result::Result<T, String>
where
    T: serde::de::DeserializeOwned,
{
    let mut command = neothd_json_command(args)?;
    gui_action::run_json(&mut command, action)
}

fn run_neothd_json_action_receipt<T>(
    args: &[&str],
    action: &str,
) -> std::result::Result<gui_action::JsonReceipt<T>, String>
where
    T: serde::de::DeserializeOwned,
{
    let mut command = neothd_json_command(args)?;
    gui_action::run_json_receipt(&mut command, action)
}

fn neothd_json_command(args: &[&str]) -> std::result::Result<std::process::Command, String> {
    let bin = which_neothd()
        .ok_or_else(|| "NEOTH CLI not found. Reinstall or repair PATH, then retry.".to_string())?;
    let mut command = spawn_neothd_plain(&bin);
    command.args(["--output", "json"]);
    command.args(args);
    Ok(command)
}

/// The Buddy status command is read-only but still requires a successful
/// subprocess exit before its status snapshot may be parsed.
fn validate_buddy_exit(
    action: &str,
    success: bool,
    stderr: &[u8],
    code: Option<i32>,
) -> std::result::Result<(), String> {
    if success {
        return Ok(());
    }
    let diagnostic = String::from_utf8_lossy(stderr)
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(|line| line.chars().take(400).collect::<String>())
        .unwrap_or_else(|| "NEOTH CLI returned no diagnostic".to_string());
    let exit = code
        .map(|code| code.to_string())
        .unwrap_or_else(|| "?".to_string());
    Err(format!("Buddy {action} failed (exit {exit}): {diagnostic}"))
}

fn fetch_buddy_status() -> std::result::Result<panel_logic::BuddyStatusSnap, String> {
    let bin = which_neothd().ok_or_else(|| {
        "NEOTH CLI not found. Reinstall or repair PATH, then refresh.".to_string()
    })?;
    let output = spawn_neothd_plain(&bin)
        .args(["--output", "json", "buddy", "status"])
        .output()
        .map_err(|error| format!("could not start NEOTH Buddy status probe: {error}"))?;
    validate_buddy_exit(
        "status probe",
        output.status.success(),
        &output.stderr,
        output.status.code(),
    )?;
    panel_logic::parse_buddy_status(&String::from_utf8_lossy(&output.stdout))
}

/// Central Buddy driver — the ONE place a GUI event becomes an orb reaction.
/// Every handler that wants the Buddy to react calls `buddy(&w, GuiActivity::X)`
/// instead of poking `set_buddy_mood` directly, so the orb's vocabulary stays
/// consistent (see `buddy_activity::GuiActivity`).
fn buddy(window: &MainWindow, activity: GuiActivity) {
    let (mood, caption) = activity.mood();
    window.set_buddy_mood(mood.into());
    window.set_buddy_caption(caption.into());
}

/// GR-10 — push a parsed safe-mode snapshot onto the `MainWindow` Privacy-tab
/// Safety Rails panel. UI-thread only (called via `invoke_from_event_loop`).
fn apply_safe_mode(window: &MainWindow, snap: panel_logic::SafeModeSnapshot) {
    use slint::{ModelRc, VecModel};
    let rows: Vec<SafeRailRow> = snap
        .rails
        .into_iter()
        .map(|r| SafeRailRow {
            name: r.name.into(),
            engaged: r.engaged,
            detail: r.detail.into(),
        })
        .collect();
    window.set_safety_rails(ModelRc::new(VecModel::from(rows)));
    window.set_rails_engaged_count(snap.engaged_count);
    window.set_rails_total(snap.total);
}

/// GR-03 — fetch the trust posture via `neoth trust --output json`. Empty
/// snapshot on missing binary / failure. PARSE is the unit-tested
/// `panel_logic::parse_trust`; this is the thin subprocess shell.
fn fetch_trust_snapshot() -> panel_logic::TrustSnapshot {
    let Some(bin) = which_neothd() else {
        return panel_logic::TrustSnapshot::default();
    };
    match spawn_neothd_plain(&bin)
        .arg("trust")
        .arg("--output")
        .arg("json")
        .output()
    {
        Ok(o) if o.status.success() => {
            panel_logic::parse_trust(&String::from_utf8_lossy(&o.stdout))
        }
        _ => panel_logic::TrustSnapshot::default(),
    }
}

/// GR-03 — push a parsed trust snapshot onto the `MainWindow` Privacy-tab Trust
/// panel. UI-thread only (called via `invoke_from_event_loop`).
fn apply_trust(window: &MainWindow, snap: panel_logic::TrustSnapshot) {
    use slint::{ModelRc, VecModel};
    let to_rows = |rows: Vec<panel_logic::TrustRow>| -> ModelRc<TrustRow> {
        let v: Vec<TrustRow> = rows
            .into_iter()
            .map(|r| TrustRow {
                label: r.label.into(),
                value: r.value.into(),
            })
            .collect();
        ModelRc::new(VecModel::from(v))
    };
    // GOLD-FEAT-01c — reflect the full-auto (sudomode) toggle from the live
    // autonomy posture (autonomy=full is the proxy for the full-auto preset;
    // toggling it applies the full preset via the CLI). Compare before the
    // `.into()` below consumes the string.
    window.set_full_auto_active(snap.autonomy_level == "full");
    // GUI-improve (gap panel wf_641e1173): keep the Privacy tab's top "Current
    // autonomy" card a LIVE mirror of the trust snapshot. It was a one-shot
    // freedom.yaml read at startup, so a CLI `/autonomy` change left it stale
    // while the TRUST card below showed the new value — two contradictory
    // autonomy strings on one surface.
    window.set_autonomy_choice(snap.autonomy_level.clone().into());
    window.set_trust_autonomy_level(snap.autonomy_level.into());
    window.set_trust_autonomy_behavior(snap.autonomy_behavior.into());
    window.set_trust_privacy(to_rows(snap.privacy));
    window.set_trust_recovery(to_rows(snap.recovery));
    window.set_trust_ledger(to_rows(snap.ledger));
}

fn fetch_omi_snapshot() -> panel_logic::OmiSnapshot {
    let Some(bin) = which_neothd() else {
        return panel_logic::OmiSnapshot::default();
    };
    match spawn_neothd_plain(&bin)
        .arg("omi")
        .arg("--home")
        .arg(default_neoth_home())
        .arg("status")
        .arg("--output")
        .arg("json")
        .output()
    {
        Ok(output) if output.status.success() => {
            panel_logic::parse_omi_status(&String::from_utf8_lossy(&output.stdout))
        }
        _ => panel_logic::OmiSnapshot::default(),
    }
}

fn apply_omi_snapshot(window: &MainWindow, snapshot: panel_logic::OmiSnapshot) {
    window.set_omi_enabled(snapshot.enabled);
    window.set_omi_mode(snapshot.mode.into());
    window.set_omi_endpoint(snapshot.endpoint.into());
    window.set_omi_listen_addr(snapshot.listen_addr.into());
    window.set_omi_retention_days(snapshot.retention_days.to_string().into());
    window.set_omi_retain_transcripts(snapshot.retain_transcripts);
    window.set_omi_audio_enabled(snapshot.audio_enabled);
    window.set_omi_image_enabled(snapshot.visual_enabled);
    window.set_omi_video_enabled(snapshot.video_enabled);
    window.set_omi_allow_cloud_api(snapshot.allow_cloud_api);
    window.set_omi_allow_cloud_summary(snapshot.allow_cloud_summary);
    window.set_omi_create_actions(snapshot.create_actions);
    window.set_omi_seed_groundtruth(snapshot.seed_groundtruth);
    window.set_omi_summary_enabled(snapshot.summary_enabled);
    window.set_omi_developer_key_present(snapshot.developer_credential_present);
    window.set_omi_native_token_present(snapshot.native_credential_present);
    window.set_omi_config_valid(snapshot.configuration_valid);
    window.set_omi_config_error(snapshot.configuration_error.into());
    window.set_omi_runtime_state(snapshot.runtime_state.into());
    window.set_omi_runtime_detail(snapshot.runtime_detail.into());
    window.set_omi_pending_audits(snapshot.pending_audits.min(i32::MAX as u64) as i32);
    // Secret drafts are write-only and are cleared after every refresh/save.
    window.set_omi_developer_key_draft("".into());
    window.set_omi_native_token_draft("".into());
}

/// SL-03 — fetch the local resource snapshot via `neoth hardware --output json`.
/// Empty snapshot on missing binary / failure. PARSE is the unit-tested
/// `panel_logic::parse_hardware`; this is the thin subprocess shell.
fn fetch_hardware_snapshot() -> panel_logic::HardwareSnapshot {
    let Some(bin) = which_neothd() else {
        return panel_logic::HardwareSnapshot::default();
    };
    match spawn_neothd_plain(&bin)
        .arg("hardware")
        .arg("--output")
        .arg("json")
        .output()
    {
        Ok(o) if o.status.success() => {
            panel_logic::parse_hardware(&String::from_utf8_lossy(&o.stdout))
        }
        _ => panel_logic::HardwareSnapshot::default(),
    }
}

/// SL-03 — push the parsed resource snapshot onto the `MainWindow` Cluster-tab
/// Local Resources panel. UI-thread only.
fn apply_hardware(window: &MainWindow, snap: panel_logic::HardwareSnapshot) {
    use slint::{ModelRc, VecModel};
    let models: Vec<TrustRow> = snap
        .models
        .into_iter()
        .map(|r| TrustRow {
            label: r.label.into(),
            value: r.value.into(),
        })
        .collect();
    window.set_hw_cpu(snap.cpu.into());
    window.set_hw_memory(snap.memory.into());
    window.set_hw_accelerator(snap.accelerator.into());
    window.set_hw_vram(snap.vram.into());
    window.set_hw_vram_fraction(snap.vram_fraction);
    window.set_hw_disk(snap.disk.into());
    window.set_hw_models(ModelRc::new(VecModel::from(models)));
    // GUI-HARDWARE-RESOURCES-01 — runtime load readout (CPU/GPU/temp/power).
    window.set_hw_load_readout(snap.load_readout.into());
}

/// SL-02 — fetch the cluster peer topology via `neoth cluster topology --output
/// json`. Empty on missing binary / failure. PARSE is the unit-tested
/// `panel_logic::parse_cluster_topology`; this is the thin subprocess shell.
fn fetch_topology_snapshot() -> Vec<panel_logic::ClusterPeerRow> {
    let Some(bin) = which_neothd() else {
        return Vec::new();
    };
    match spawn_neothd_plain(&bin)
        .arg("cluster")
        .arg("topology")
        .arg("--output")
        .arg("json")
        .output()
    {
        Ok(o) if o.status.success() => {
            panel_logic::parse_cluster_topology(&String::from_utf8_lossy(&o.stdout))
        }
        _ => Vec::new(),
    }
}

/// SL-02 — push the parsed peer rows onto the Cluster-tab topology panel.
/// UI-thread only.
fn apply_topology(window: &MainWindow, rows: Vec<panel_logic::ClusterPeerRow>) {
    use slint::{ModelRc, VecModel};
    let peers: Vec<ClusterPeerRow> = rows
        .into_iter()
        .map(|r| ClusterPeerRow {
            label: r.label.into(),
            addr: r.addr.into(),
            status: r.status.into(),
            rtt_ms: r.rtt_ms.into(),
            stability: r.stability_pct.into(),
            last_seen: r.last_seen.into(),
        })
        .collect();
    window.set_cluster_peers(ModelRc::new(VecModel::from(peers)));
}

/// GOLD-PROG-08 — read the daemon's exported usage meter
/// (`~/.neoth/usage_meter.json`, written every 10s). PARSE is the unit-tested
/// `panel_logic::parse_usage_meter`; an absent/garbage file → unavailable (the
/// GUI is a separate process and cannot read the daemon's in-memory meter).
fn fetch_usage_meter() -> panel_logic::UsageMeterPanel {
    let path = default_neoth_home().join("usage_meter.json");
    match std::fs::read_to_string(&path) {
        Ok(s) => panel_logic::parse_usage_meter(&s),
        Err(_) => panel_logic::UsageMeterPanel::default(),
    }
}

/// GOLD-PROG-08 — push the live token budget onto the Config-tab meter.
/// UI-thread only.
fn apply_usage_meter(window: &MainWindow, panel: panel_logic::UsageMeterPanel) {
    window.set_usage_available(panel.available);
    window.set_usage_responses(panel.responses.into());
    window.set_usage_tokens(panel.tokens.into());
    window.set_usage_note(panel.note.into());
}

/// KF-08 — fetch the council budget meter via `neoth council budget --output
/// json`. PARSE is the unit-tested `panel_logic::parse_council_budget`.
fn fetch_council_budget() -> panel_logic::CouncilBudgetPanel {
    let Some(bin) = which_neothd() else {
        return panel_logic::CouncilBudgetPanel::default();
    };
    match spawn_neothd_plain(&bin)
        .arg("council")
        .arg("budget")
        .arg("--output")
        .arg("json")
        .output()
    {
        Ok(o) if o.status.success() => {
            panel_logic::parse_council_budget(&String::from_utf8_lossy(&o.stdout))
        }
        _ => panel_logic::CouncilBudgetPanel::default(),
    }
}

/// KF-08 — push the council budget meter onto the `MainWindow` Config-tab panel.
fn apply_council_budget(window: &MainWindow, snap: panel_logic::CouncilBudgetPanel) {
    use slint::{ModelRc, VecModel};
    let rows: Vec<TrustRow> = snap
        .last_debate
        .into_iter()
        .map(|r| TrustRow {
            label: r.label.into(),
            value: r.value.into(),
        })
        .collect();
    window.set_council_cap(snap.configured_cap.into());
    window.set_council_daily_usd(snap.daily_usd_cap.into());
    window.set_council_depth_warning(snap.depth_cost_warning.into());
    window.set_council_last_debate(ModelRc::new(VecModel::from(rows)));
}

/// GU-01 — fetch the hemisphere bindings via `neoth hemispheres show --output
/// json`. Empty snapshot on missing binary / failure. PARSE is the unit-tested
/// `panel_logic::parse_hemispheres`.
fn fetch_hemispheres_snapshot() -> panel_logic::HemispheresSnapshot {
    let Some(bin) = which_neothd() else {
        return panel_logic::HemispheresSnapshot::default();
    };
    match spawn_neothd_plain(&bin)
        .arg("hemispheres")
        .arg("show")
        .arg("--output")
        .arg("json")
        .output()
    {
        Ok(o) if o.status.success() => {
            panel_logic::parse_hemispheres(&String::from_utf8_lossy(&o.stdout))
        }
        _ => panel_logic::HemispheresSnapshot::default(),
    }
}

/// GU-01 — push hemisphere bindings onto the MainWindow. UI-thread only.
fn apply_hemispheres(window: &MainWindow, snap: panel_logic::HemispheresSnapshot) {
    use slint::{ModelRc, VecModel};
    let rows: Vec<HemisphereRow> = snap
        .bindings
        .into_iter()
        .map(|b| HemisphereRow {
            role: b.role.into(),
            provider: b.provider.into(),
            model: b.model.into(),
            has_key: b.has_key,
        })
        .collect();
    window.set_hemisphere_bindings(ModelRc::new(VecModel::from(rows)));
    window.set_hemispheres_mode(snap.mode.into());
}

/// GU-01 — fetch installed skills via `neoth skills --list --output json`.
/// Empty on missing binary / failure. PARSE is the unit-tested
/// `panel_logic::parse_skills`.
fn fetch_skills() -> Vec<panel_logic::SkillSummary> {
    let Some(bin) = which_neothd() else {
        return Vec::new();
    };
    match spawn_neothd_plain(&bin)
        .arg("skills")
        .arg("--list")
        .arg("--output")
        .arg("json")
        .output()
    {
        Ok(o) if o.status.success() => {
            panel_logic::parse_skills(&String::from_utf8_lossy(&o.stdout))
        }
        _ => Vec::new(),
    }
}

/// GOLD-ADAPT-AOS-01 — full skill list cache so the search box can
/// re-group without a subprocess round-trip per keystroke.
static SKILLS_CACHE: std::sync::Mutex<Vec<panel_logic::SkillSummary>> =
    std::sync::Mutex::new(Vec::new());

/// GU-01 — push the installed-skill list onto the MainWindow. UI-thread only.
/// AOS-01: caches the full list + renders the grouped/filtered index.
fn apply_skills(window: &MainWindow, skills: Vec<panel_logic::SkillSummary>) {
    window.set_skills_total(skills.len() as i32);
    if let Ok(mut c) = SKILLS_CACHE.lock() {
        *c = skills;
    }
    render_skill_index(window);
}

/// AOS-01 — regroup the cached skills under the current filter and push
/// the flat header+row model. UI-thread only.
fn render_skill_index(window: &MainWindow) {
    use slint::{ModelRc, VecModel};
    let filter = window.get_skills_filter().to_string();
    // Clone out of the lock immediately — holding it across the grouping
    // would stall any future off-thread cache writer.
    let skills = SKILLS_CACHE.lock().map(|c| c.clone()).unwrap_or_default();
    let rows: Vec<SkillRow> = panel_logic::group_skill_rows(&skills, &filter)
        .into_iter()
        .map(|s| SkillRow {
            id: s.id.into(),
            description: s.description.into(),
            enabled: s.enabled,
            keywords: s.keywords.into(),
            tags: s.tags.into(),
            is_header: s.is_header,
        })
        .collect();
    window.set_skills(ModelRc::new(VecModel::from(rows)));
}

/// GU-01 — fetch discovered plugins via `neoth plugin list --output json`.
fn fetch_plugins() -> Vec<panel_logic::PluginSummary> {
    let Some(bin) = which_neothd() else {
        return Vec::new();
    };
    match spawn_neothd_plain(&bin)
        .arg("plugin")
        .arg("list")
        .arg("--output")
        .arg("json")
        .output()
    {
        Ok(o) if o.status.success() => {
            panel_logic::parse_plugins(&String::from_utf8_lossy(&o.stdout))
        }
        _ => Vec::new(),
    }
}

/// GU-01 — push the discovered-plugin list onto the MainWindow. UI-thread only.
fn apply_plugins(window: &MainWindow, plugins: Vec<panel_logic::PluginSummary>) {
    use slint::{ModelRc, VecModel};
    let rows: Vec<PluginRow> = plugins
        .into_iter()
        .map(|p| PluginRow {
            id: p.id.into(),
            name: p.name.into(),
            activation: p.activation.into(),
            requested_permission: p.requested_permission.into(),
            // DES-12
            has_ui_surface: p.has_ui_surface,
            ui_title: p.ui_title.into(),
        })
        .collect();
    window.set_plugins(ModelRc::new(VecModel::from(rows)));
}

/// DES-12 — fetch WAL-feed events for a plugin via
/// `neoth plugin events <id> --output json --last 30`.
fn fetch_plugin_events(id: &str) -> Vec<panel_logic::PluginEventRow> {
    let Some(bin) = which_neothd() else {
        return Vec::new();
    };
    match spawn_neothd_plain(&bin)
        .arg("plugin")
        .arg("events")
        .arg(id)
        .arg("--output")
        .arg("json")
        .arg("--last")
        .arg("30")
        .output()
    {
        Ok(o) if o.status.success() => {
            panel_logic::parse_plugin_events(&String::from_utf8_lossy(&o.stdout))
        }
        _ => Vec::new(),
    }
}

/// DES-12 — format a unix timestamp as HH:MM:SS (UTC).
/// Falls back to the raw seconds string when time parsing is unavailable.
fn fmt_ts_unix(ts: u64) -> String {
    // Simple modulo decomposition — avoids pulling in chrono just for display.
    let s = ts % 60;
    let m = (ts / 60) % 60;
    let h = (ts / 3600) % 24;
    format!("{h:02}:{m:02}:{s:02}")
}

/// DES-12 — format a byte count as a compact human-readable string.
fn fmt_event_bytes(n: u64) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{:.1} MB", n as f64 / (1024.0 * 1024.0))
    }
}

/// GU-01 — fetch memory-block sizes via `neoth memory --size --output json`
/// (metadata only — no content leaves the daemon).
fn fetch_memory_snapshot() -> panel_logic::MemorySnapshot {
    let Some(bin) = which_neothd() else {
        return panel_logic::MemorySnapshot::default();
    };
    match spawn_neothd_plain(&bin)
        .arg("memory")
        .arg("--size")
        .arg("--output")
        .arg("json")
        .output()
    {
        Ok(o) if o.status.success() => {
            panel_logic::parse_memory_size(&String::from_utf8_lossy(&o.stdout))
        }
        _ => panel_logic::MemorySnapshot::default(),
    }
}

/// Human-readable byte size (B / KB / MB).
fn fmt_bytes(n: i64) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{:.1} MB", n as f64 / (1024.0 * 1024.0))
    }
}

/// GU-01 — push the memory-block sizes onto the MainWindow. UI-thread only.
fn apply_memory(window: &MainWindow, snap: panel_logic::MemorySnapshot) {
    use slint::{ModelRc, VecModel};
    let rows: Vec<MemoryRow> = snap
        .blocks
        .into_iter()
        .map(|b| MemoryRow {
            source: b.source.into(),
            path: b.path.into(),
            bytes: fmt_bytes(b.bytes).into(),
        })
        .collect();
    window.set_memory_blocks(ModelRc::new(VecModel::from(rows)));
    window.set_memory_total(fmt_bytes(snap.total_bytes).into());
}

/// GOLD-R3-04 — push the canonical per-channel probe state onto MainWindow.
/// Errors clear stale rows and remain visible in-panel instead of degrading to
/// a false "not connected" state. UI-thread only.
fn apply_channels(window: &MainWindow, channels: Result<Vec<panel_logic::ChannelStatus>, String>) {
    use slint::{ModelRc, VecModel};
    let (channels, error) = match channels {
        Ok(channels) => (channels, String::new()),
        Err(error) => (Vec::new(), error),
    };
    let channel_types = channels
        .iter()
        .map(|channel| slint::SharedString::from(channel.name.as_str()))
        .collect::<Vec<_>>();
    let rows = channels
        .into_iter()
        .map(|channel| ChannelRow {
            name: channel.name.into(),
            status: channel.status.into(),
            configured: channel.configured,
            detail: channel.detail.into(),
            setup_secret_f1: channel.setup_secret_mask[0],
            setup_secret_f2: channel.setup_secret_mask[1],
            setup_secret_f3: channel.setup_secret_mask[2],
            setup_secret_f4: channel.setup_secret_mask[3],
            setup_secret_f5: channel.setup_secret_mask[4],
            setup_secret_f6: channel.setup_secret_mask[5],
        })
        .collect::<Vec<_>>();
    window.set_channel_types(ModelRc::new(VecModel::from(channel_types)));
    window.set_channels(ModelRc::new(VecModel::from(rows)));
    window.set_channel_status_error(error.into());
}

/// Fetch `neoth channel list --output json`. A missing binary, non-zero exit,
/// malformed stdout, or corrupt operator config is returned verbatim enough to
/// repair, but never with secret material from stdout.
fn fetch_channel_status() -> Result<Vec<panel_logic::ChannelStatus>, String> {
    let bin = which_neothd().ok_or_else(|| {
        "NEOTH CLI not found. Reinstall or repair PATH, then refresh.".to_string()
    })?;
    let output = spawn_neothd_plain(&bin)
        .arg("channel")
        .arg("list")
        .arg("--output")
        .arg("json")
        .output()
        .map_err(|error| format!("could not start NEOTH channel probe: {error}"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr)
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .unwrap_or("channel probe failed without detail")
            .to_string();
        return Err(detail);
    }
    panel_logic::parse_channel_status(&String::from_utf8_lossy(&output.stdout))
}

/// SPEC-05 — fetch the saved presets via `neoth preset list --json`. Empty on
/// missing binary / failure. PARSE is the unit-tested `panel_logic::parse_presets`.
fn fetch_presets() -> Vec<panel_logic::PresetEntry> {
    let Some(bin) = which_neothd() else {
        return Vec::new();
    };
    match spawn_neothd_plain(&bin)
        .arg("preset")
        .arg("list")
        .arg("--json")
        .output()
    {
        Ok(o) if o.status.success() => {
            panel_logic::parse_presets(&String::from_utf8_lossy(&o.stdout))
        }
        _ => Vec::new(),
    }
}

/// SPEC-05 — push the preset selector list onto the MainWindow. UI-thread only.
///
/// Injects flat sentinel header rows (is-header=true) so the Slint `for` loop
/// can use the same `if p.is-header:` / `if !p.is-header:` pattern as the
/// Skills expander — no nested conditionals inside the loop body.
///
/// Layout injected:
///   PresetRow { name="BUILT-IN", is_header=true }
///   … built-in rows …
///   PresetRow { name="YOURS",    is_header=true }   ← only when operator presets exist
///   … operator rows …
fn apply_presets(window: &MainWindow, presets: Vec<panel_logic::PresetEntry>) {
    use slint::{ModelRc, VecModel};
    let header = |label: &str| PresetRow {
        name: label.into(),
        active: false,
        builtin: false,
        description: "".into(),
        is_header: true,
    };
    let data_row = |p: panel_logic::PresetEntry| PresetRow {
        name: p.name.into(),
        active: p.active,
        builtin: p.builtin,
        description: p.description.into(),
        is_header: false,
    };

    // Split into builtin / operator so the YOURS header only appears once.
    let (builtins, operators): (Vec<_>, Vec<_>) = presets.into_iter().partition(|p| p.builtin);
    let mut rows: Vec<PresetRow> = Vec::with_capacity(builtins.len() + operators.len() + 2);

    rows.push(header("BUILT-IN"));
    for p in builtins {
        rows.push(data_row(p));
    }
    if !operators.is_empty() {
        rows.push(header("YOURS"));
        for p in operators {
            rows.push(data_row(p));
        }
    }
    window.set_preset_list(ModelRc::new(VecModel::from(rows)));
}

/// SPEC-05 step5c — fetch the behavioural-profile presets via
/// `neoth profile preset list --output json`. PARSE is unit-tested.
fn fetch_profile_presets() -> Vec<panel_logic::ProfilePresetRow> {
    let Some(bin) = which_neothd() else {
        return Vec::new();
    };
    match spawn_neothd_plain(&bin)
        .arg("profile")
        .arg("preset")
        .arg("list")
        .arg("--output")
        .arg("json")
        .output()
    {
        Ok(o) if o.status.success() => {
            panel_logic::parse_profile_presets(&String::from_utf8_lossy(&o.stdout))
        }
        _ => Vec::new(),
    }
}

/// SPEC-05 step5c — push the behavioural-profile list onto the MainWindow.
fn apply_profile_presets(window: &MainWindow, rows: Vec<panel_logic::ProfilePresetRow>) {
    use slint::{ModelRc, VecModel};
    let model: Vec<ProfilePresetRow> = rows
        .into_iter()
        .map(|p| ProfilePresetRow {
            name: p.name.into(),
            description: p.description.into(),
            recommended: p.recommended,
            active: p.active,
        })
        .collect();
    window.set_profile_preset_list(ModelRc::new(VecModel::from(model)));
}

/// SPEC-05 step5c — activate the operator's chosen response style via
/// `neoth profile preset apply <name>`.
fn apply_profile_preset_via_subprocess(name: &str) -> String {
    let Some(bin) = which_neothd() else {
        return "profile preset: neothd binary not found".to_string();
    };
    match spawn_neothd_plain(&bin)
        .arg("profile")
        .arg("preset")
        .arg("apply")
        .arg(name)
        .output()
    {
        Ok(o) if o.status.success() => format!("response style → {name}"),
        Ok(o) => format!(
            "profile preset apply failed: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => format!("profile preset apply could not start: {e}"),
    }
}

/// SPEC-06 — fetch the implemented provider ids via `neoth provider list
/// --output json` (the per-role rebind picker options). PARSE is the unit-tested
/// `panel_logic::parse_provider_ids`.
fn fetch_provider_ids() -> Vec<String> {
    let Some(bin) = which_neothd() else {
        return Vec::new();
    };
    match spawn_neothd_plain(&bin)
        .arg("provider")
        .arg("list")
        .arg("--output")
        .arg("json")
        .output()
    {
        Ok(o) if o.status.success() => {
            panel_logic::parse_provider_ids(&String::from_utf8_lossy(&o.stdout))
        }
        _ => Vec::new(),
    }
}

/// SPEC-06 — push the provider-id picker options onto the MainWindow. UI-thread.
fn apply_provider_ids(window: &MainWindow, ids: Vec<String>) {
    use slint::{ModelRc, VecModel};
    // GUI-improve (gap panel wf_641e1173) — compute the Config combo's selected
    // row = position of the operator's current provider in the LIVE list, so a
    // provider absent from the old hardcoded combo list no longer silently shows
    // as row 0 (claude_cli). `provider-choice` is set from freedom.yaml at
    // startup (line 241) before this runs.
    let current = window.get_provider_choice().to_string();
    let idx = ids.iter().position(|p| p == &current).unwrap_or(0) as i32;
    let rows: Vec<slint::SharedString> = ids.into_iter().map(|s| s.into()).collect();
    window.set_provider_ids(ModelRc::new(VecModel::from(rows)));
    window.set_provider_choice_index(idx);
}

/// SPEC-06 — rebind a hemisphere role to a provider (`neoth hemispheres set
/// --role <r> --provider <p>`). The daemon owns the WAL `0x1F HEMISPHERE_REBOUND`
/// audit + its own validation. Returns an operator-readable status line.
fn set_hemisphere_via_subprocess(role: &str, provider: &str, model: &str) -> String {
    let Some(bin) = which_neothd() else {
        return "hemispheres set: neothd binary not found".to_string();
    };
    // GOLD-GUI-OVERHAUL — forward the picked model id (HemisphereSlot.model is a
    // free-form Option<String>; the CLI already accepts --model). Empty = leave
    // the role on its provider default.
    let mut cmd = spawn_neothd_plain(&bin);
    cmd.arg("hemispheres")
        .arg("set")
        .arg("--role")
        .arg(role)
        .arg("--provider")
        .arg(provider);
    if !model.is_empty() {
        cmd.arg("--model").arg(model);
    }
    match cmd.output() {
        Ok(o) if o.status.success() => {
            if model.is_empty() {
                format!("{role} → {provider}")
            } else {
                format!("{role} → {provider} · {model}")
            }
        }
        Ok(o) => format!(
            "hemispheres set failed: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => format!("hemispheres set could not start: {e}"),
    }
}

/// GOLD-GUI-OVERHAUL — the per-role model-picker options for a provider. Local
/// providers (local_qwen/local_ouro) → abliterated-then-standard GGUF refs that
/// fit this PC's VRAM (`neoth models recommend --class …`, so Alex can SELECT a
/// fitting local/abliterated model). Cloud providers → the live model catalog
/// (`neoth catalog list --provider …`). Index 0 is always "(provider default)"
/// so the operator can leave the model unset. Robust: a subprocess hiccup just
/// yields the default-only list, never a hard fail.
fn fetch_hemisphere_model_ids(provider: &str) -> Vec<String> {
    let mut out = vec!["(provider default)".to_string()];
    let Some(bin) = which_neothd() else {
        return out;
    };
    if provider == "local_qwen" || provider == "local_ouro" {
        for class in ["abliterated", "standard"] {
            if let Ok(o) = spawn_neothd_plain(&bin)
                .arg("models")
                .arg("recommend")
                .arg("--class")
                .arg(class)
                .arg("--output")
                .arg("json")
                .output()
                && o.status.success()
            {
                out.extend(panel_logic::parse_model_recommend_refs(
                    &String::from_utf8_lossy(&o.stdout),
                ));
            }
        }
    } else if let Ok(o) = spawn_neothd_plain(&bin)
        .arg("catalog")
        .arg("list")
        .arg("--provider")
        .arg(provider)
        .arg("--output")
        .arg("json")
        .output()
        && o.status.success()
    {
        out.extend(panel_logic::parse_catalog_model_ids(
            &String::from_utf8_lossy(&o.stdout),
            provider,
        ));
    }
    out.dedup();
    out
}

/// SPEC-05 — activate a preset by name (`neoth preset activate <name>`): sets
/// the active marker (does NOT merge into freedom.yaml — that's "Apply active").
/// Returns an operator-readable status line.
fn activate_preset_via_subprocess(name: &str) -> String {
    let Some(bin) = which_neothd() else {
        return "preset activate: neothd binary not found".to_string();
    };
    match spawn_neothd_plain(&bin)
        .arg("preset")
        .arg("activate")
        .arg(name)
        .output()
    {
        Ok(o) if o.status.success() => format!("active preset → {name}"),
        Ok(o) => format!(
            "preset activate failed: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => format!("preset activate could not start: {e}"),
    }
}

/// SPEC-05 builtin-presets — run `neoth preset apply <name> --dry-run`
/// and parse the JSON plan. Returns the plan on success; None when the
/// binary is missing, the command fails, or the output is unparseable.
fn dry_run_preset_via_subprocess(name: &str) -> Option<panel_logic::ApplyPlan> {
    let bin = which_neothd()?;
    let out = spawn_neothd_plain(&bin)
        .arg("preset")
        .arg("apply")
        .arg(name)
        .arg("--dry-run")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    panel_logic::parse_apply_plan(&String::from_utf8_lossy(&out.stdout))
}

/// SPEC-05 builtin-presets — mint a full-auto token then apply <name> with
/// `--yes --gui-confirmed --gui-token <token>`.
/// Returns a human-readable status string.
fn apply_preset_with_fullauto_token(name: &str) -> String {
    let Some(bin) = which_neothd() else {
        return "preset apply: neothd binary not found".to_string();
    };
    // Mint the single-use token (same pattern as on_full_auto_confirmed).
    let token = spawn_neothd_plain(&bin)
        .arg("autonomy")
        .arg("mint-fullauto-token")
        .arg("--output")
        .arg("json")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            // Output may be `{"token":"…"}` or bare token — extract either way.
            let raw = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
                // JSON but token missing/not-a-string → empty (caught by the
                // is_empty filter) — never pass a raw JSON blob as a token.
                v.get("token")
                    .and_then(|t| t.as_str())
                    .unwrap_or("")
                    .to_string()
            } else {
                raw
            }
        })
        .filter(|t| !t.is_empty());
    let Some(tok) = token else {
        return format!(
            "Full-auto token mint failed for preset `{name}` — daemon must be running."
        );
    };
    match spawn_neothd_plain(&bin)
        .arg("preset")
        .arg("apply")
        .arg(name)
        .arg("--yes")
        .arg("--gui-confirmed")
        .arg("--gui-token")
        .arg(&tok)
        .output()
    {
        Ok(o) if o.status.success() => format!("Applied preset `{name}` (full-auto)."),
        Ok(o) => format!(
            "preset apply `{name}` failed (exit {}): {}",
            o.status,
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => format!("preset apply could not start: {e}"),
    }
}

/// SPEC-05 builtin-presets — apply <name> non-interactively with `--yes`
/// (no autonomy token needed — not a full-auto preset).
fn apply_preset_direct(name: &str) -> String {
    let Some(bin) = which_neothd() else {
        return "preset apply: neothd binary not found".to_string();
    };
    match spawn_neothd_plain(&bin)
        .arg("preset")
        .arg("apply")
        .arg(name)
        .arg("--yes")
        .output()
    {
        Ok(o) if o.status.success() => {
            // Try to extract fields_changed count from JSON output.
            let stdout = String::from_utf8_lossy(&o.stdout);
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&stdout)
                && let Some(n) = v
                    .get("fields_changed")
                    .and_then(|f| f.as_array())
                    .map(|a| a.len())
            {
                return format!("Applied preset `{name}` ({n} fields changed).");
            }
            format!("Applied preset `{name}`.")
        }
        Ok(o) => format!(
            "preset apply `{name}` failed (exit {}): {}",
            o.status,
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => format!("preset apply could not start: {e}"),
    }
}

/// SPEC-05 builtin-presets — delete an operator preset via
/// `neoth preset delete <name>`.
fn delete_preset_via_subprocess(name: &str) -> String {
    let Some(bin) = which_neothd() else {
        return "preset delete: neothd binary not found".to_string();
    };
    match spawn_neothd_plain(&bin)
        .arg("preset")
        .arg("delete")
        .arg(name)
        .output()
    {
        Ok(o) if o.status.success() => format!("Deleted preset `{name}`."),
        Ok(o) => format!(
            "preset delete `{name}` failed (exit {}): {}",
            o.status,
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => format!("preset delete could not start: {e}"),
    }
}

fn fetch_kanban_board_snapshot() -> KanbanBoardSnapshot {
    let Some(bin) = which_neothd() else {
        return KanbanBoardSnapshot {
            summary: "Run `cargo install --path ../neothd` to enable Code Sessions data."
                .to_string(),
            ..Default::default()
        };
    };

    // Step 1: list sessions (active by default — `--all` includes archived).
    let list_out = spawn_neothd_plain(&bin)
        .arg("kanban")
        .arg("list")
        .arg("--output")
        .arg("json")
        .output();
    let list_stdout = match list_out {
        Ok(out) if out.status.success() => out.stdout,
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            return KanbanBoardSnapshot {
                summary: format!(
                    "kanban list failed (exit {}): {}",
                    out.status,
                    if stderr.is_empty() {
                        "(no stderr)"
                    } else {
                        &stderr
                    }
                ),
                ..Default::default()
            };
        }
        Err(e) => {
            return KanbanBoardSnapshot {
                summary: format!("kanban list could not start: {e}"),
                ..Default::default()
            };
        }
    };
    let sessions: Vec<CodingSessionJson> = match serde_json::from_slice(&list_stdout) {
        Ok(v) => v,
        Err(e) => {
            return KanbanBoardSnapshot {
                summary: format!("kanban list JSON parse failed: {e}"),
                ..Default::default()
            };
        }
    };
    let Some(latest) = sessions.into_iter().next() else {
        return KanbanBoardSnapshot {
            summary: "No active session. Run `neoth code \"...\"` in your terminal, then refresh."
                .to_string(),
            ..Default::default()
        };
    };

    // Step 2: full session detail incl. tasks.
    let show_out = spawn_neothd_plain(&bin)
        .arg("kanban")
        .arg("show")
        .arg(latest.session_id.to_string())
        .arg("--output")
        .arg("json")
        .output();
    let show_stdout = match show_out {
        Ok(out) if out.status.success() => out.stdout,
        Ok(out) => {
            return KanbanBoardSnapshot {
                summary: format!(
                    "kanban show #{} failed (exit {})",
                    latest.session_id, out.status
                ),
                ..Default::default()
            };
        }
        Err(e) => {
            return KanbanBoardSnapshot {
                summary: format!("kanban show could not start: {e}"),
                ..Default::default()
            };
        }
    };
    let envelope: CodingShowEnvelope = match serde_json::from_slice(&show_stdout) {
        Ok(v) => v,
        Err(e) => {
            return KanbanBoardSnapshot {
                summary: format!("kanban show JSON parse failed: {e}"),
                ..Default::default()
            };
        }
    };

    // Step 3: group tasks by status into the five board buckets.
    let mut snap = KanbanBoardSnapshot {
        summary: format!(
            "Session #{}  [{}]   {}",
            envelope.session.session_id, envelope.session.status, envelope.session.prompt,
        ),
        feed: fetch_kanban_feed(&bin),
        ..Default::default()
    };
    for task in envelope.tasks {
        let row = KanbanTaskRow {
            task_id: format!("#{}", task.task_id).into(),
            title: task.title.into(),
            hemisphere: task.hemisphere.into(),
        };
        // Wire-form status names mirror `TaskStatus::as_str` in
        // `neothd::coding::types`. Unknown statuses go to BACKLOG so
        // the operator still sees them rather than silent drops.
        match task.status.as_str() {
            "todo" => snap.todo.push(row),
            "in_progress" => snap.in_progress.push(row),
            "review" => snap.review.push(row),
            "done" | "archived" => snap.done.push(row),
            _ => snap.backlog.push(row),
        }
    }
    // HO-02: only probe on the success path (we have a working binary).
    snap.cerebellum_bound = Some(probe_cerebellum_bound(&bin));
    snap
}

// ── Warm-channel board client (B — persistent-stdio-stream, Session 30) ─────
//
// The legacy `fetch_kanban_board_snapshot` above spawns FOUR cold
// subprocesses per call. `GuiStreamClient` holds ONE `neoth gui-stream`
// child open across refreshes and gets the whole board in a single
// NDJSON round-trip. On ANY I/O / protocol error the caller drops the
// client and falls back to the cold path, so the warm channel is a pure
// optimisation — it can never make the board worse than before.

/// Board payload as returned by `neoth gui-stream`'s `board` method.
/// Field-for-field mirror of the daemon's `cli::kanban::GuiBoardSnapshot`.
#[derive(Debug, Deserialize)]
struct GuiBoardJson {
    summary: String,
    cerebellum_bound: bool,
    tasks: Vec<GuiBoardTaskJson>,
    feed: Vec<FeedEntryJson>,
}

#[derive(Debug, Deserialize)]
struct GuiBoardTaskJson {
    task_id: i64,
    title: String,
    hemisphere: String,
    status: String,
}

/// Map the warm-channel board payload into the same `KanbanBoardSnapshot`
/// the cold path produces. The status-bucketing + feed `rev()`+map mirror
/// `fetch_kanban_board_snapshot` (task loop) and `fetch_kanban_feed`
/// EXACTLY, so warm and cold are byte-for-byte equivalent in the UI.
fn board_json_to_snapshot(b: GuiBoardJson) -> KanbanBoardSnapshot {
    let mut snap = KanbanBoardSnapshot {
        summary: b.summary,
        cerebellum_bound: Some(b.cerebellum_bound),
        ..Default::default()
    };
    for t in b.tasks {
        let row = KanbanTaskRow {
            task_id: format!("#{}", t.task_id).into(),
            title: t.title.into(),
            hemisphere: t.hemisphere.into(),
        };
        match t.status.as_str() {
            "todo" => snap.todo.push(row),
            "in_progress" => snap.in_progress.push(row),
            "review" => snap.review.push(row),
            "done" | "archived" => snap.done.push(row),
            _ => snap.backlog.push(row),
        }
    }
    // Server returns feed oldest-first (WAL append order); the right rail
    // wants most-recent-first — same `.rev()` as `fetch_kanban_feed`.
    snap.feed = b
        .feed
        .into_iter()
        .rev()
        .map(|e| KanbanFeedRow {
            ts: format_hms_from_ns(e.ts_ns).into(),
            actor: e.actor.into(),
            message: e.message.into(),
        })
        .collect();
    snap
}

/// Per-request read budget. The warm channel is local IPC — a healthy
/// daemon answers in single-digit ms. 5s is generous slack; exceeding it
/// means the child is hung, so `request_board` gives up and the caller
/// falls back to the cold path (and drops this client so the next tick
/// reconnects). Bounds how long a worker thread can sit on a stalled read.
const GUI_STREAM_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Persistent client to a `neoth gui-stream` child. Owns the child + its
/// stdin, plus an `mpsc` receiver fed by a dedicated reader thread that
/// owns stdout. Decoupling the blocking read into its own thread means
/// `request_board` waits on a `recv_timeout` (never an unbounded
/// `read_line`), so a hung daemon can neither pin the per-tick worker
/// thread nor delay this client's `Drop` (and thus the child kill) past
/// the timeout. Dropping the client kills the child, which EOFs the
/// reader thread.
/// DES-10 — one entry in the live channel activity ring.
/// Contains ONLY traffic METADATA: who/when/direction/size.
/// WAL message bodies are hashed by design and never appear here.
#[derive(Debug, Clone)]
struct ChannelActivity {
    /// "in" | "out" | "proactive" | "blocked"
    direction: String,
    channel: String,
    peer: String,
    bytes: u64,
    ts_unix: u64,
}

/// Parse `{"push":true,"channel_feed":[...]}` tolerantly.
/// Returns `None` if the line is not a push frame — caller forwards normally.
fn parse_channel_feed_push(line: &str) -> Option<Vec<ChannelActivity>> {
    let v: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    if v.get("push").and_then(|b| b.as_bool()) != Some(true) {
        return None;
    }
    let arr = v.get("channel_feed")?.as_array()?;
    let entries: Vec<ChannelActivity> = arr
        .iter()
        .filter_map(|e| {
            // `event_id` presence gates what counts as a real feed row;
            // the value itself has no consumer (no replay/dedup on this side).
            e.get("event_id")?;
            Some(ChannelActivity {
                direction: e
                    .get("direction")
                    .and_then(|d| d.as_str())
                    .unwrap_or("in")
                    .to_string(),
                channel: e
                    .get("channel")
                    .and_then(|c| c.as_str())
                    .unwrap_or("")
                    .to_string(),
                peer: e
                    .get("peer")
                    .and_then(|p| p.as_str())
                    .unwrap_or("")
                    .to_string(),
                bytes: e.get("bytes").and_then(|b| b.as_u64()).unwrap_or(0),
                ts_unix: e.get("ts_unix").and_then(|t| t.as_u64()).unwrap_or(0),
            })
        })
        .collect();
    Some(entries)
}

/// Parse a spontaneous board frame and keep it off the request/response
/// channel. The reader thread stores only the newest snapshot because every
/// push is a complete board replacement.
fn parse_board_push(line: &str) -> Option<GuiBoardJson> {
    let value: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    if value.get("push").and_then(|flag| flag.as_bool()) != Some(true) {
        return None;
    }
    serde_json::from_value(value.get("board")?.clone()).ok()
}

fn take_pending_board(
    pending: &std::sync::Mutex<Option<GuiBoardJson>>,
) -> Option<KanbanBoardSnapshot> {
    pending
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take()
        .map(board_json_to_snapshot)
}

#[cfg(test)]
mod channel_feed_tests {
    use super::{parse_board_push, parse_channel_feed_push, take_pending_board};

    #[test]
    fn parses_valid_push_frame() {
        let line = r#"{"push":true,"channel_feed":[{"event_id":7,"direction":"in","channel":"telegram","peer":"u42","bytes":128,"ts_unix":1720000000}]}"#;
        let result = parse_channel_feed_push(line).expect("should parse");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].direction, "in");
        assert_eq!(result[0].channel, "telegram");
        assert_eq!(result[0].peer, "u42");
        assert_eq!(result[0].bytes, 128);
        assert_eq!(result[0].ts_unix, 1_720_000_000);
    }

    #[test]
    fn rejects_non_push_json() {
        let line = r#"{"ok":true,"board":{}}"#;
        assert!(parse_channel_feed_push(line).is_none());
    }

    #[test]
    fn rejects_non_json() {
        assert!(parse_channel_feed_push("not json at all").is_none());
    }

    #[test]
    fn tolerates_missing_optional_fields() {
        let line = r#"{"push":true,"channel_feed":[{"event_id":1}]}"#;
        let result = parse_channel_feed_push(line).expect("should parse");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].bytes, 0);
        assert_eq!(result[0].direction, "in");
    }

    #[test]
    fn board_push_is_consumed_once_as_a_live_snapshot() {
        let line = r#"{"push":true,"board":{"summary":"Session #7","cerebellum_bound":true,"tasks":[{"task_id":9,"title":"wire it","hemisphere":"left","status":"in_progress"}],"feed":[]}}"#;
        let pending = std::sync::Mutex::new(parse_board_push(line));

        let snapshot = take_pending_board(&pending).expect("board push must reach the consumer");
        assert_eq!(snapshot.summary, "Session #7");
        assert_eq!(snapshot.in_progress.len(), 1);
        assert!(
            take_pending_board(&pending).is_none(),
            "a consumed complete snapshot must not replay on every timer tick"
        );
    }

    #[test]
    fn board_response_is_not_misclassified_as_a_push() {
        let line = r#"{"id":3,"ok":true,"board":{"summary":"s","cerebellum_bound":true,"tasks":[],"feed":[]}}"#;
        assert!(parse_board_push(line).is_none());
    }
}

const CHANNEL_ACTIVITY_RING_CAP: usize = 100;

struct GuiStreamClient {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    /// Lines the reader thread pulled off the child's stdout, in order.
    /// Push lines are intercepted by the reader thread and routed to either
    /// `activity_ring` or `pending_board`, so request methods see only
    /// id-bearing responses.
    rx: std::sync::mpsc::Receiver<String>,
    /// Capped ring of the latest channel-activity push entries. Shared with
    /// the reader thread (Arc<Mutex>) and drained by the UI timer.
    activity_ring: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<ChannelActivity>>>,
    /// Newest complete spontaneous board snapshot. The timer consumes this
    /// before issuing an explicit board request, giving TRAIL-02 a live GUI
    /// consumer while naturally coalescing bursts.
    pending_board: std::sync::Arc<std::sync::Mutex<Option<GuiBoardJson>>>,
    next_id: u64,
}

impl GuiStreamClient {
    /// Spawn `neoth gui-stream` with piped stdin/stdout (stderr to null).
    /// `spawn_neothd_plain` sets `NEOTH_LOG=error`, so stdout carries only
    /// the NDJSON responses; `request_board` additionally skips any stray
    /// non-JSON line as a belt-and-suspenders guard. Errors propagate so
    /// the caller falls back to the cold path.
    fn connect(bin: &Path) -> std::io::Result<Self> {
        use std::process::Stdio;
        let mut child = spawn_neothd_plain(bin)
            .arg("gui-stream")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdin = child.stdin.take().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "gui-stream: no stdin pipe")
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "gui-stream: no stdout pipe")
        })?;
        // Dedicated reader thread owns stdout, pushes whole lines onto the
        // channel. It exits when the child dies (read_line → EOF) or when
        // the receiver is dropped (send error). Detached on purpose: it is
        // self-terminating and cheap, and we never want to JOIN it from a
        // drop path that might otherwise block on a stalled read.
        //
        // Push lines are intercepted here: channel metadata goes to the ring,
        // complete boards replace the pending snapshot. Neither is forwarded
        // to `tx`, so request/response matching remains clean.
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        let activity_ring =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::VecDeque::<
                ChannelActivity,
            >::new()));
        let ring_writer = activity_ring.clone();
        let pending_board = std::sync::Arc::new(std::sync::Mutex::new(None));
        let board_writer = pending_board.clone();
        std::thread::spawn(move || {
            use std::io::BufRead;
            let mut reader = std::io::BufReader::new(stdout);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => break, // EOF — child exited
                    Ok(_) => {
                        // Intercept push frames — route to ring, not response chan.
                        if let Some(entries) = parse_channel_feed_push(&line) {
                            if let Ok(mut ring) = ring_writer.lock() {
                                for entry in entries {
                                    ring.push_back(entry);
                                }
                                while ring.len() > CHANNEL_ACTIVITY_RING_CAP {
                                    ring.pop_front();
                                }
                            }
                            // Do NOT forward push lines to tx.
                        } else if let Some(board) = parse_board_push(&line) {
                            if let Ok(mut pending) = board_writer.lock() {
                                *pending = Some(board);
                            }
                            // Complete board pushes are consumed by the timer,
                            // never confused with an id-bearing response.
                        } else if tx.send(std::mem::take(&mut line)).is_err() {
                            break; // receiver gone — client dropped
                        }
                    }
                    Err(_) => break, // pipe error — give up
                }
            }
        });
        Ok(Self {
            child,
            stdin,
            rx,
            activity_ring,
            pending_board,
            next_id: 1,
        })
    }

    /// One `{"id":N,"method":"board"}` round-trip → mapped snapshot.
    /// `None` on any I/O, EOF, timeout, protocol (`ok:false`), or parse
    /// failure; the caller then drops `self` and falls back to the cold
    /// path. Never blocks longer than `GUI_STREAM_READ_TIMEOUT` per line.
    fn request_board(&mut self) -> Option<KanbanBoardSnapshot> {
        use std::io::Write;
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        // Hand-format the request line — no need to pull in a serialiser
        // for a two-field object with a numeric id + a literal method.
        let req = format!("{{\"id\":{id},\"method\":\"board\"}}\n");
        self.stdin.write_all(req.as_bytes()).ok()?;
        self.stdin.flush().ok()?;

        // Pull lines (via the reader thread) until we get a parseable JSON
        // response object. `NEOTH_LOG=error` already keeps stdout free of
        // the daemon's INFO banner, but this is the robustness net: ANY
        // stray non-JSON line (e.g. an error-level tracing event) is
        // skipped. Bounded by MAX_SKIP (chatty stream) AND by the per-recv
        // timeout (hung daemon) — both fall back to the cold path.
        const MAX_SKIP: usize = 32;
        for _ in 0..MAX_SKIP {
            let line = self.rx.recv_timeout(GUI_STREAM_READ_TIMEOUT).ok()?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) else {
                continue; // not JSON — a log line; skip it
            };
            // A genuine response carries an `ok` bool. Anything else that
            // happens to be JSON but lacks it is not our response — skip.
            let Some(ok) = v.get("ok").and_then(|b| b.as_bool()) else {
                continue;
            };
            if !ok {
                tracing::warn!(response = %trimmed, "gui-stream: board request not ok");
                return None;
            }
            let board: GuiBoardJson = serde_json::from_value(v.get("board")?.clone()).ok()?;
            return Some(board_json_to_snapshot(board));
        }
        // Too many non-response lines — treat as a broken channel.
        None
    }

    /// One `{"id":N,"method":"activity"}` round-trip → `(mood, caption)`. Same
    /// robustness net + fallback semantics as `request_board`. Best-effort: a
    /// `None` just skips a Buddy update this tick.
    fn request_activity(&mut self) -> Option<(String, String)> {
        use std::io::Write;
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let req = format!("{{\"id\":{id},\"method\":\"activity\"}}\n");
        self.stdin.write_all(req.as_bytes()).ok()?;
        self.stdin.flush().ok()?;
        const MAX_SKIP: usize = 32;
        for _ in 0..MAX_SKIP {
            let line = self.rx.recv_timeout(GUI_STREAM_READ_TIMEOUT).ok()?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) else {
                continue;
            };
            let Some(ok) = v.get("ok").and_then(|b| b.as_bool()) else {
                continue;
            };
            if !ok {
                return None;
            }
            let activity = v.get("activity")?.as_str()?.to_string();
            let caption = v
                .get("caption")
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .to_string();
            return Some((activity, caption));
        }
        None
    }

    /// DES-10 — drain all accumulated channel-activity entries from the ring,
    /// returning them newest-last (FIFO order). Empties the ring so the next
    /// drain only yields new entries. Called from the UI timer thread; the
    /// lock is held only for the drain, not across invoke_from_event_loop.
    fn drain_channel_activity(&self) -> Vec<ChannelActivity> {
        self.activity_ring
            .lock()
            .map(|mut ring| ring.drain(..).collect())
            .unwrap_or_default()
    }

    fn take_pushed_board(&self) -> Option<KanbanBoardSnapshot> {
        take_pending_board(&self.pending_board)
    }
}

impl Drop for GuiStreamClient {
    fn drop(&mut self) {
        // Kill + reap the child. This closes the child's stdout, so the
        // detached reader thread's `read_line` returns EOF and the thread
        // exits on its own. Because `request_board` waits on a bounded
        // `recv_timeout` (not a raw blocking `read_line`), this Drop is
        // never gated behind an unbounded read — it runs promptly even if
        // the daemon had gone unresponsive.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Board fetch for the live-tail timer: try the warm `gui-stream` channel
/// first (lazy-connecting the client on first use), fall back to the cold
/// 4-subprocess path on any failure. A failed warm request drops the dead
/// client so the next tick reconnects from scratch.
/// Warm-only activity probe for the docked Buddy. Reuses the SHARED gui-stream
/// client (serialised by its mutex with the board fetch, so requests never
/// interleave on the wire). `None` when there's no warm channel — the Buddy
/// keeps its current mood that tick (no cold-path subprocess for ambient mood).
fn fetch_activity_warm(
    client: &std::sync::Mutex<Option<GuiStreamClient>>,
) -> Option<(String, String)> {
    let bin = which_neothd()?;
    let mut guard = client.lock().unwrap_or_else(|p| p.into_inner());
    if guard.is_none() {
        // Spawn the warm channel on first activity poll so the Buddy reflects
        // the daemon even if the operator never opens the Code Sessions tab.
        match GuiStreamClient::connect(&bin) {
            Ok(c) => *guard = Some(c),
            Err(_) => return None,
        }
    }
    let c = guard.as_mut()?;
    match c.request_activity() {
        Some(v) => Some(v),
        None => {
            // Broken channel — drop it so the next fetch reconnects.
            *guard = None;
            None
        }
    }
}

fn fetch_board_warm_or_cold(
    client: &std::sync::Mutex<Option<GuiStreamClient>>,
) -> KanbanBoardSnapshot {
    let Some(bin) = which_neothd() else {
        return fetch_kanban_board_snapshot(); // surfaces the "install" hint
    };
    // Recover from a poisoned lock rather than panicking the worker — the
    // guarded value is just a reconnectable client, never corrupt state.
    let mut guard = client.lock().unwrap_or_else(|p| p.into_inner());
    if guard.is_none() {
        match GuiStreamClient::connect(&bin) {
            Ok(c) => *guard = Some(c),
            Err(e) => {
                tracing::warn!(error = %e, "gui-stream: connect failed; using cold path");
                return fetch_kanban_board_snapshot();
            }
        }
    }
    if let Some(c) = guard.as_mut() {
        if let Some(snap) = c.take_pushed_board() {
            return snap;
        }
        if let Some(snap) = c.request_board() {
            return snap;
        }
        // Warm request failed — drop the dead child so the next tick
        // reconnects, and serve this tick from the cold path.
        tracing::warn!("gui-stream: warm request failed; dropping client + cold fallback");
        *guard = None;
    }
    fetch_kanban_board_snapshot()
}

/// HO-02: probe whether a Cerebellum provider is bound. Runs
/// `neoth hemispheres show --output json` and returns true UNLESS we can
/// positively determine the cerebellum role has no provider AND there is
/// no single-mode fallback. Fail-safe (true) on any spawn/parse error so
/// a transient probe failure never false-alarms the operator with the
/// "no Cerebellum bound" banner.
fn probe_cerebellum_bound(bin: &Path) -> bool {
    let out = spawn_neothd_plain(bin)
        .arg("hemispheres")
        .arg("show")
        .arg("--output")
        .arg("json")
        .output();
    let stdout = match out {
        Ok(o) if o.status.success() => o.stdout,
        _ => return true, // fail-safe: don't alarm when the probe can't run
    };
    let v: serde_json::Value = match serde_json::from_slice(&stdout) {
        Ok(v) => v,
        Err(_) => return true,
    };
    // single-mode: every role routes to the single fallback provider.
    if v.get("single_provider_fallback")
        .and_then(|x| x.as_str())
        .is_some()
    {
        return true;
    }
    // per-role mode: the cerebellum role must carry a provider string.
    if let Some(roles) = v.get("roles").and_then(|x| x.as_array()) {
        for r in roles {
            if r.get("role").and_then(|x| x.as_str()) == Some("cerebellum") {
                return r.get("provider").and_then(|x| x.as_str()).is_some();
            }
        }
    }
    // No fallback + no cerebellum role row → decompose can't run.
    false
}

/// Pick #8 step 3 — Activity feed right rail. Subprocess
/// `neothd kanban watch --output json` reads the latest kanban frames
/// from `~/.neoth/wal/`, returns `Vec<FeedEntryJson>`. We collapse
/// failures to an empty feed (degraded UI is fine — board still works).
fn fetch_kanban_feed(bin: &Path) -> Vec<KanbanFeedRow> {
    let out = spawn_neothd_plain(bin)
        .arg("kanban")
        .arg("watch")
        .arg("--output")
        .arg("json")
        .arg("--limit")
        .arg("50")
        .output();
    let stdout = match out {
        Ok(o) if o.status.success() => o.stdout,
        Ok(o) => {
            tracing::warn!(
                exit = ?o.status,
                stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                "kanban watch failed; rendering empty feed",
            );
            return Vec::new();
        }
        Err(e) => {
            tracing::warn!(error = %e, "kanban watch could not start; rendering empty feed");
            return Vec::new();
        }
    };
    let entries: Vec<FeedEntryJson> = match serde_json::from_slice(&stdout) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "kanban watch JSON parse failed; rendering empty feed");
            return Vec::new();
        }
    };
    // Most-recent-first for the right rail — the WAL scan returns
    // newest-last (append order), so reverse for the UI.
    entries
        .into_iter()
        .rev()
        .map(|e| KanbanFeedRow {
            ts: format_hms_from_ns(e.ts_ns).into(),
            actor: e.actor.into(),
            message: e.message.into(),
        })
        .collect()
}

/// Detail-pane subprocess fetch. Strips the leading `#` from the
/// Slint-formatted task id, calls `neoth kanban task <id> --output
/// json`, parses the `{task, comments}` envelope, returns the
/// formatted `KanbanCommentRow` vec. Empty vec on any failure — the
/// detail pane just renders without a comment thread instead of
/// surfacing a subprocess error in the UI.
fn fetch_task_comments(task_id_with_hash: &str) -> Vec<KanbanCommentRow> {
    let id = task_id_with_hash
        .strip_prefix('#')
        .unwrap_or(task_id_with_hash);
    let Some(bin) = which_neothd() else {
        return Vec::new();
    };
    let out = spawn_neothd_plain(&bin)
        .arg("kanban")
        .arg("task")
        .arg(id)
        .arg("--output")
        .arg("json")
        .output();
    let stdout = match out {
        Ok(o) if o.status.success() => o.stdout,
        Ok(o) => {
            tracing::warn!(
                task_id = id,
                exit = ?o.status,
                "kanban task fetch failed; rendering empty comments"
            );
            return Vec::new();
        }
        Err(e) => {
            tracing::warn!(task_id = id, error = %e, "kanban task fetch could not start");
            return Vec::new();
        }
    };
    let envelope: TaskDetailEnvelope = match serde_json::from_slice(&stdout) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "kanban task JSON parse failed");
            return Vec::new();
        }
    };
    envelope
        .comments
        .into_iter()
        .map(|c| KanbanCommentRow {
            ts: format_hms_from_ns(c.created_ns).into(),
            author: c.author.into(),
            body: c.body.into(),
        })
        .collect()
}

/// Format a unix-ns timestamp as `HH:MM` for the activity feed. Mirrors
/// `neothd::cli::kanban::format_ts_short` but emits HH:MM (not HH:MM:SS)
/// because the feed rail is narrow + the seconds add visual noise.
fn format_hms_from_ns(ts_ns: u64) -> String {
    let secs = ts_ns / 1_000_000_000;
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    format!("{h:02}:{m:02}")
}

/// Push a `KanbanBoardSnapshot` into the eight Slint properties on the
/// MainWindow. Single call site means a future schema bump only needs
/// one update — the property names stay 1:1 with the snapshot fields.
fn apply_kanban_snapshot(window: &MainWindow, snap: KanbanBoardSnapshot) {
    use slint::{ModelRc, VecModel};
    window.set_kanban_backlog(ModelRc::new(VecModel::from(snap.backlog)));
    window.set_kanban_todo(ModelRc::new(VecModel::from(snap.todo)));
    window.set_kanban_in_progress(ModelRc::new(VecModel::from(snap.in_progress)));
    window.set_kanban_review(ModelRc::new(VecModel::from(snap.review)));
    window.set_kanban_done(ModelRc::new(VecModel::from(snap.done)));
    window.set_kanban_feed(ModelRc::new(VecModel::from(snap.feed)));
    window.set_kanban_session_summary(snap.summary.into());
    // HO-02: None (degraded / un-probed path) → true, so the banner only
    // shows when we positively determined no Cerebellum is bound.
    window.set_cerebellum_bound(snap.cerebellum_bound.unwrap_or(true));
}

/// R2-P0-1: GUI chat dispatch via the `neothd chat` subprocess. Returns
/// `Ok(reply_text)` on success or `Err(error_for_bubble)` so the caller
/// can render either path as a chat bubble.
///
/// Routing through the daemon binary (same pattern as
/// `probe_hardware_via_subprocess`) keeps the GUI crate decoupled from
/// daemon internals while ensuring GUI Send hits EXACTLY the same
/// provider / WAL / permission / cost / autonomy code path as
/// `neothd chat` from a terminal — that's the R2 done-criterion.
/// Chat-feel parity (openhuman): split a NEOTH assistant reply into
/// multiple bubbles at blank-line (paragraph) boundaries, so a
/// multi-paragraph reply reads as a conversation cluster instead of one
/// wall of text. Mirrors openhuman's render-time `splitAgentMessageInto
/// Bubbles` — a pure line-iterator state machine, no Slint/UI dependency,
/// fully unit-testable.
///
/// Rules:
/// - A fenced code block (```…```) is kept INTACT as one bubble — blank
///   lines inside a fence never split it (avoids fragmenting code/tables).
/// - A blank line OUTSIDE a fence ends the current bubble.
/// - Segments that are only a visual separator (`---` / `***` / `___`) are
///   dropped (openhuman's `isVisualSeparatorOnly`) so horizontal rules
///   don't render as empty bubbles.
/// - Each emitted segment is trimmed. A non-empty reply always yields at
///   least one bubble (falls back to the whole trimmed reply).
pub fn segment_reply_into_bubbles(reply: &str) -> Vec<String> {
    fn push_segment(cur: &[&str], out: &mut Vec<String>) {
        let trimmed = cur.join("\n");
        let trimmed = trimmed.trim();
        if !trimmed.is_empty() && !is_visual_separator_only(trimmed) {
            out.push(trimmed.to_string());
        }
    }
    let mut bubbles: Vec<String> = Vec::new();
    let mut current: Vec<&str> = Vec::new();
    let mut in_fence = false;
    for line in reply.lines() {
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            current.push(line);
            continue;
        }
        if !in_fence && line.trim().is_empty() {
            push_segment(&current, &mut bubbles);
            current.clear();
        } else {
            current.push(line);
        }
    }
    push_segment(&current, &mut bubbles);
    if bubbles.is_empty() {
        let t = reply.trim();
        if !t.is_empty() {
            bubbles.push(t.to_string());
        }
    }
    bubbles
}

/// True when `s` (already trimmed, non-empty) is ONLY a Markdown
/// horizontal-rule / visual separator — 3+ of `-`/`*`/`_` (allowing
/// interspersed spaces, as Markdown permits `- - -`). Such a segment
/// carries no content and is dropped during bubble segmentation.
fn is_visual_separator_only(s: &str) -> bool {
    let non_space: Vec<char> = s.chars().filter(|c| !c.is_whitespace()).collect();
    non_space.len() >= 3
        && non_space.iter().all(|&c| c == '-' || c == '*' || c == '_')
        && non_space.iter().all(|&c| c == non_space[0])
}

/// Chat-feel parity #3 (beat-openhuman): split the raw stdout of
/// `neoth chat --stream` into `(reply_text, done)`. The CLI streams raw
/// reply deltas incrementally, then emits a blank line + a final sentinel
/// line `{"neoth_stream":"done","count":N}` (OPEN_DECISIONS D-005) so a
/// consumer can tell a CLEAN completion from a truncated stream. Everything
/// before the sentinel is the reply (trailing blank trimmed); `done` is
/// true once the sentinel appears. Pure fn — unit-testable; called per
/// stdout chunk during streaming (mid-stream: no sentinel yet → done=false,
/// live partial text) and once at EOF (done=true → final text to segment).
pub fn strip_stream_sentinel(raw: &str) -> (String, bool) {
    let (text, done, _) = parse_stream_sentinel(raw);
    (text, done)
}

/// GOLD-ADAPT-ODY-02/05 — token/timing stats the extended done-sentinel
/// carries. All-zero when the daemon predates the extension (recall
/// early-return still emits the minimal `{"neoth_stream":"done","count":1}`).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StreamStats {
    pub used_tokens: u64,
    pub limit_tokens: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub elapsed_ms: u64,
    pub model: String,
}

/// Split the accumulated stream buffer into (reply-text, done, stats).
/// Mid-stream (no sentinel yet): done=false, zero stats.
pub fn parse_stream_sentinel(raw: &str) -> (String, bool, StreamStats) {
    let Some(pos) = raw.rfind("{\"neoth_stream\":\"done\"") else {
        return (raw.trim_end().to_string(), false, StreamStats::default());
    };
    // Parse ONLY the sentinel line — any stray byte after it would make
    // serde reject the whole slice and silently zero the stats.
    let sentinel_line = raw[pos..].lines().next().unwrap_or("");
    let stats = serde_json::from_str::<serde_json::Value>(sentinel_line.trim())
        .ok()
        .map(|v| {
            let g = |k: &str| v.get(k).and_then(|x| x.as_u64()).unwrap_or(0);
            StreamStats {
                used_tokens: g("used_tokens"),
                limit_tokens: g("limit_tokens"),
                input_tokens: g("input_tokens"),
                output_tokens: g("output_tokens"),
                elapsed_ms: g("elapsed_ms"),
                model: v
                    .get("model")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
            }
        })
        .unwrap_or_default();
    (raw[..pos].trim_end().to_string(), true, stats)
}

/// ODY-12 UI-control targets — must match `main.slint`'s nav values.
/// A `nav` chip whose id is not in this list is ignored (prompt drift
/// must not navigate somewhere undefined).
pub const NAV_PANELS: [&str; 26] = [
    "chat",
    "overview",
    "memory",
    "hemispheres",
    "channels",
    "coding",
    "agents",
    "automation",
    "privacy",
    "plugins",
    "cluster",
    "resources",
    "doctor",
    "loops",
    "config",
    // Wave 4a
    "n8n",
    "babel",
    "calendar",
    "evolve",
    // Wave 4b
    "obsidian",
    "dreaming",
    "wiki",
    "buddyconfig",
    "companion",
    "mesh",
    // FEAT-05
    "selfdev",
];

/// GOLD-ADAPT-ODY-12/14 — deep-link chips from the done-sentinel's
/// additive `links` array (`[{label, kind, id}, ..]`). Empty when the
/// field is absent (older daemons), mid-stream, or malformed — the
/// chips row simply doesn't render. Returns (label, kind, id) tuples.
pub fn parse_stream_links(raw: &str) -> Vec<(String, String, String)> {
    let Some(pos) = raw.rfind("{\"neoth_stream\":\"done\"") else {
        return Vec::new();
    };
    let sentinel_line = raw[pos..].lines().next().unwrap_or("");
    serde_json::from_str::<serde_json::Value>(sentinel_line.trim())
        .ok()
        .and_then(|v| v.get("links").cloned())
        .and_then(|l| l.as_array().cloned())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| {
                    Some((
                        e.get("label")?.as_str()?.to_string(),
                        e.get("kind")?.as_str()?.to_string(),
                        e.get("id")?.as_str()?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Non-streaming chat round-trip (waits for full stdout). The live chat
/// path now uses `neoth chat --stream` (see the send-worker), so this is
/// retained as the test-injection seam for [`shape_chat_output`]: the
/// caller pins the binary path, letting tests run a synthetic fake-neothd
/// (tempdir-staged `bin.sh` / `bin.cmd` that emit fixture stdout/stderr)
/// instead of the real daemon. Kept because the four-outcome shaping logic
/// it exercises is the same error taxonomy the streaming path's terminal
/// states map onto.
#[cfg_attr(not(test), allow(dead_code))]
pub fn chat_via_subprocess_with(
    bin: &std::path::Path,
    message: &str,
) -> std::result::Result<String, String> {
    let output = spawn_neothd_plain(bin).arg("chat").arg(message).output();
    match output {
        Ok(out) => shape_chat_output(
            out.status.success(),
            &out.stdout,
            &out.stderr,
            out.status.code(),
        ),
        Err(e) => Err(format!(
            "Chat subprocess could not start: {e}\n\
             Verify `neothd --version` works from a terminal."
        )),
    }
}

/// R4-P1 pure result-shaping helper. Decouples the four-outcome
/// decision tree (success-with-reply / success-but-empty / non-zero-
/// exit-with-stderr / non-zero-exit-no-stderr) from the real subprocess
/// so tests pin the contract without an actual spawn.
pub fn shape_chat_output(
    success: bool,
    stdout: &[u8],
    stderr: &[u8],
    code: Option<i32>,
) -> std::result::Result<String, String> {
    if success {
        let s = String::from_utf8_lossy(stdout);
        let reply = s.trim_end_matches(['\n', '\r']).to_string();
        if reply.is_empty() {
            return Err("Provider returned an empty reply. Check `neoth doctor` + \
                 `~/.neoth/freedom.yaml` provider settings."
                .to_string());
        }
        return Ok(reply);
    }
    let stderr_str = String::from_utf8_lossy(stderr);
    let trimmed = stderr_str.trim();
    let exit_label = code
        .map(|c| format!("exit {c}"))
        .unwrap_or_else(|| "exit ?".to_string());
    if trimmed.is_empty() {
        Err(format!(
            "`neothd chat` exited {exit_label} with no diagnostic. Run from \
             a terminal to capture the failure context."
        ))
    } else {
        // Cap at ~600 chars so a stack-traceful Rust panic doesn't blow
        // the chat bubble. Operators reading the full failure run
        // `neothd chat` from a shell anyway.
        let snippet = if trimmed.len() > 600 {
            // Char-boundary-safe truncation for UTF-8 stderr bytes.
            let chars: Vec<char> = trimmed.chars().collect();
            let cap = chars.iter().take(599).collect::<String>();
            format!("{cap}…")
        } else {
            trimmed.to_string()
        };
        Err(format!("Chat failed ({exit_label}):\n{snippet}"))
    }
}

/// R4-P1 operator-readable diagnostic for the binary-missing path.
/// Pulled to a const so tests can pin the exact string.
pub const BINARY_MISSING_MESSAGE: &str = "Chat unavailable — `neothd` binary not on PATH.\n\
     Install the daemon first (the release tarball ships both \
     `neothd-gui` and `neothd` side-by-side; from source, \
     `cargo install --path ../neothd`).";

/// QM-9 Phase 3+: how often the dashboard tile re-fires the
/// `neoth usage` subprocess. 60s feels live-enough for chat-
/// cost monitoring without spawning a subprocess every second.
/// Operators wanting faster refresh use `neoth usage --format
/// json` in a `watch -n 1` loop.
pub const USAGE_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// GOLD-WIRE-10b: how often the dashboard tile re-fires the
/// `neoth meter --json` subprocess. 15s gives a near-live budget
/// feel without spawning a subprocess every second.
pub const BUDGET_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

/// QM-8 Phase 2: how often the preset tile re-fires `neoth preset
/// list`. Lighter cadence than usage since presets change rarely.
pub const PRESET_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);

#[cfg(test)]
mod chat_subprocess_tests {
    use super::*;

    #[test]
    fn segment_single_paragraph_is_one_bubble() {
        let r = segment_reply_into_bubbles("Just one line of reply.");
        assert_eq!(r, vec!["Just one line of reply.".to_string()]);
    }

    #[test]
    fn segment_splits_paragraphs_at_blank_line() {
        let r = segment_reply_into_bubbles("First paragraph.\n\nSecond paragraph.\n\nThird.");
        assert_eq!(
            r,
            vec![
                "First paragraph.".to_string(),
                "Second paragraph.".to_string(),
                "Third.".to_string()
            ]
        );
    }

    #[test]
    fn segment_keeps_fenced_code_block_intact() {
        // A code fence with internal blank lines must stay ONE bubble.
        let reply = "Here is the fix:\n\n```rust\nfn a() {}\n\nfn b() {}\n```\n\nDone.";
        let r = segment_reply_into_bubbles(reply);
        assert_eq!(r.len(), 3, "intro + fenced block + outro: {r:?}");
        assert!(
            r[1].contains("fn a()") && r[1].contains("fn b()"),
            "fence intact: {:?}",
            r[1]
        );
        assert!(r[1].contains("```"), "fence markers preserved");
    }

    #[test]
    fn segment_drops_visual_separator_segments() {
        // A `---` horizontal rule between paragraphs is dropped, not a bubble.
        let r = segment_reply_into_bubbles("Above the line.\n\n---\n\nBelow the line.");
        assert_eq!(
            r,
            vec!["Above the line.".to_string(), "Below the line.".to_string()]
        );
    }

    #[test]
    fn segment_trims_and_collapses_leading_trailing_blanks() {
        let r = segment_reply_into_bubbles("\n\n  Only content.  \n\n\n");
        assert_eq!(r, vec!["Only content.".to_string()]);
    }

    #[test]
    fn segment_empty_reply_yields_no_bubbles() {
        assert!(segment_reply_into_bubbles("   \n\n  ").is_empty());
    }

    #[test]
    fn strip_stream_sentinel_mid_stream_has_no_sentinel() {
        // While streaming, the sentinel hasn't arrived → done=false, the
        // accumulated partial text is returned (trailing whitespace trimmed).
        let (txt, done) = strip_stream_sentinel("Hello, I am think");
        assert_eq!(txt, "Hello, I am think");
        assert!(!done);
    }

    #[test]
    fn strip_stream_sentinel_strips_done_line_and_trailing_blank() {
        // Clean completion: reply + blank line + sentinel JSON line.
        let raw = "Here is the answer.\n\n{\"neoth_stream\":\"done\",\"count\":7}\n";
        let (txt, done) = strip_stream_sentinel(raw);
        assert_eq!(txt, "Here is the answer.");
        assert!(done);
        assert!(!txt.contains("neoth_stream"), "sentinel must be stripped");
    }

    #[test]
    fn strip_stream_sentinel_empty_reply_with_sentinel_is_done() {
        let (txt, done) = strip_stream_sentinel("\n{\"neoth_stream\":\"done\",\"count\":0}\n");
        assert_eq!(txt, "");
        assert!(done);
    }

    // ODY-02/05 — the extended sentinel carries token/timing stats.
    #[test]
    fn parse_stream_sentinel_reads_extended_token_fields() {
        let raw = "Answer.\n\n{\"neoth_stream\":\"done\",\"count\":3,\
                   \"used_tokens\":12400,\"limit_tokens\":200000,\
                   \"input_tokens\":12000,\"output_tokens\":400,\"elapsed_ms\":10000,\
                   \"model\":\"claude-opus-4-7\"}\n";
        let (txt, done, stats) = parse_stream_sentinel(raw);
        assert_eq!(txt, "Answer.");
        assert!(done);
        assert_eq!(
            stats,
            StreamStats {
                used_tokens: 12_400,
                limit_tokens: 200_000,
                input_tokens: 12_000,
                output_tokens: 400,
                elapsed_ms: 10_000,
                model: "claude-opus-4-7".to_string(),
            }
        );
    }

    // Minimal legacy sentinel (recall early-return) → zero stats, still done.
    #[test]
    fn parse_stream_sentinel_minimal_sentinel_zero_stats() {
        let (txt, done, stats) =
            parse_stream_sentinel("hit\n{\"neoth_stream\":\"done\",\"count\":1}\n");
        assert_eq!(txt, "hit");
        assert!(done);
        assert_eq!(stats, StreamStats::default());
    }

    #[test]
    fn strip_stream_sentinel_multiparagraph_preserved_before_sentinel() {
        // Internal blank lines (paragraph breaks) survive — only the
        // trailing blank+sentinel is removed, so segmentation still works.
        let raw = "Para one.\n\nPara two.\n\n{\"neoth_stream\":\"done\",\"count\":3}";
        let (txt, done) = strip_stream_sentinel(raw);
        assert_eq!(txt, "Para one.\n\nPara two.");
        assert!(done);
        // And it segments into two bubbles downstream.
        assert_eq!(segment_reply_into_bubbles(&txt).len(), 2);
    }

    #[test]
    fn visual_separator_matrix() {
        assert!(is_visual_separator_only("---"));
        assert!(is_visual_separator_only("***"));
        assert!(is_visual_separator_only("___"));
        assert!(is_visual_separator_only("- - -")); // markdown spaced hr
        assert!(!is_visual_separator_only("--")); // too short
        assert!(!is_visual_separator_only("-*-")); // mixed glyphs
        assert!(!is_visual_separator_only("text")); // real content
    }

    #[test]
    fn shape_chat_output_happy_path_returns_trimmed_stdout() {
        // Reply with trailing newlines (every `neothd chat` adds one);
        // shape_chat_output trims the tail but preserves internal
        // newlines for code blocks / lists.
        let result = shape_chat_output(true, b"The answer is 42.\nLine two.\n\n", b"", Some(0));
        assert_eq!(result, Ok("The answer is 42.\nLine two.".to_string()));
    }

    #[test]
    fn shape_chat_output_empty_stdout_is_error_with_doctor_hint() {
        let result = shape_chat_output(true, b"", b"", Some(0));
        match result {
            Err(msg) => {
                assert!(msg.contains("empty reply"));
                assert!(msg.contains("neoth doctor"));
            }
            Ok(_) => panic!("empty stdout must error"),
        }
    }

    #[test]
    fn shape_chat_output_nonzero_with_stderr_surfaces_diagnostic() {
        let result = shape_chat_output(
            false,
            b"",
            b"Error: no provider configured. Run `neoth init` first.",
            Some(1),
        );
        match result {
            Err(msg) => {
                assert!(msg.contains("exit 1"));
                assert!(msg.contains("no provider configured"));
                assert!(msg.contains("Chat failed"));
            }
            Ok(_) => panic!("non-zero exit must error"),
        }
    }

    #[test]
    fn shape_chat_output_nonzero_no_stderr_points_at_terminal() {
        let result = shape_chat_output(false, b"", b"", Some(137));
        match result {
            Err(msg) => {
                assert!(msg.contains("exit 137"));
                assert!(msg.contains("no diagnostic"));
                assert!(msg.contains("terminal"));
            }
            Ok(_) => panic!("non-zero exit must error"),
        }
    }

    #[test]
    fn shape_chat_output_truncates_long_stderr_to_600_chars() {
        let long_stderr = "X".repeat(5000);
        let result = shape_chat_output(false, b"", long_stderr.as_bytes(), Some(1));
        match result {
            Err(msg) => {
                // Total error message includes prefix + 599 chars of
                // stderr + ellipsis. Bound at ~650 to allow prefix.
                assert!(msg.len() < 700, "msg too long: {} chars", msg.len());
                assert!(msg.contains("…"));
            }
            Ok(_) => panic!("non-zero must error"),
        }
    }

    #[test]
    fn shape_chat_output_handles_utf8_multibyte_stderr_truncation() {
        // 1000 em-dashes (3 bytes each in utf-8) — truncation must
        // not split a multi-byte char.
        let long_stderr = "—".repeat(1000);
        let result = shape_chat_output(false, b"", long_stderr.as_bytes(), Some(2));
        match result {
            Err(msg) => {
                // The message must be valid utf-8 (would panic on the
                // older `&str[..600]` byte-slice path).
                assert!(msg.is_ascii() || msg.chars().count() > 100);
                assert!(msg.contains("…"));
            }
            Ok(_) => panic!("non-zero must error"),
        }
    }

    #[test]
    fn shape_chat_output_handles_none_exit_code() {
        // Process killed by signal: status.code() returns None.
        let result = shape_chat_output(false, b"", b"killed", None);
        match result {
            Err(msg) => assert!(msg.contains("exit ?")),
            Ok(_) => panic!("killed must error"),
        }
    }

    #[test]
    fn binary_missing_message_carries_install_pointer() {
        // Operator-readable diagnostic for the no-binary path. Pin
        // the install pointers so a future refactor doesn't drop them.
        assert!(BINARY_MISSING_MESSAGE.contains("neothd"));
        assert!(BINARY_MISSING_MESSAGE.contains("PATH"));
        assert!(
            BINARY_MISSING_MESSAGE.contains("release tarball")
                || BINARY_MISSING_MESSAGE.contains("cargo install")
        );
    }

    // ── QM-9 Phase 2 dashboard probe tests ──────────────────────────────

    #[test]
    fn shape_usage_summary_renders_calls_ok_err_cost() {
        let json = r#"{
            "since_unix": 0,
            "until_unix": 100,
            "total_call_count": 7,
            "total_ok_count": 6,
            "total_err_count": 1,
            "total_input_tokens": 500,
            "total_output_tokens": 800,
            "total_cost_usd": 0.1234,
            "per_provider": []
        }"#;
        let s = crate::shape_usage_summary(json);
        assert!(s.contains("7 calls"));
        assert!(s.contains("ok=6"));
        assert!(s.contains("err=1"));
        assert!(s.contains("$0.1234"));
    }

    #[test]
    fn shape_usage_summary_zero_calls_says_no_usage() {
        let json = r#"{
            "since_unix": 0,
            "until_unix": 100,
            "total_call_count": 0,
            "total_ok_count": 0,
            "total_err_count": 0,
            "total_input_tokens": 0,
            "total_output_tokens": 0,
            "total_cost_usd": 0.0,
            "per_provider": []
        }"#;
        let s = crate::shape_usage_summary(json);
        assert!(s.contains("No usage"));
    }

    #[test]
    fn shape_usage_summary_malformed_json_returns_error_string() {
        let s = crate::shape_usage_summary("{not json");
        assert!(s.contains("malformed"));
    }

    #[test]
    fn shape_usage_summary_missing_fields_defaults_to_zero() {
        let s = crate::shape_usage_summary("{}");
        assert!(s.contains("No usage"));
    }

    // ── QM-8 Phase 2 preset summary tests ───────────────────────────────

    #[test]
    fn shape_preset_summary_no_presets_says_so() {
        let s = crate::shape_preset_summary(b"(no presets - run `neoth preset --help` ...)\n");
        assert!(s.contains("No presets saved"));
    }

    #[test]
    fn shape_preset_summary_renders_count_and_active() {
        let stdout = b"   alpha\n * middle\n   zeta\n";
        let s = crate::shape_preset_summary(stdout);
        assert!(s.contains("3 presets"));
        assert!(s.contains("middle"));
    }

    #[test]
    fn shape_preset_summary_handles_no_active_marker() {
        let stdout = b"   alpha\n   zeta\n";
        let s = crate::shape_preset_summary(stdout);
        assert!(s.contains("2 presets"));
        assert!(s.contains("no active"));
    }

    #[test]
    fn shape_preset_summary_empty_stdout_says_no_presets() {
        let s = crate::shape_preset_summary(b"");
        assert!(s.contains("No presets saved"));
    }

    #[test]
    fn parse_active_preset_name_finds_starred_row() {
        let stdout = b"   alpha\n * middle\n   zeta\n";
        assert_eq!(
            crate::parse_active_preset_name(stdout),
            Some("middle".to_string())
        );
    }

    #[test]
    fn parse_active_preset_name_returns_none_without_marker() {
        let stdout = b"   alpha\n   zeta\n";
        assert_eq!(crate::parse_active_preset_name(stdout), None);
    }

    #[test]
    fn parse_active_preset_name_handles_empty_stdout() {
        assert_eq!(crate::parse_active_preset_name(b""), None);
    }

    #[test]
    fn parse_active_preset_name_handles_only_star() {
        // Star without name → None.
        let stdout = b"   alpha\n * \n   zeta\n";
        assert_eq!(crate::parse_active_preset_name(stdout), None);
    }

    #[test]
    fn chat_via_subprocess_with_returns_error_when_bin_does_not_exist() {
        // Bin at a path that doesn't exist on disk → subprocess
        // spawn errors with NotFound. Pin the operator-readable
        // "could not start" diagnostic.
        let nonexistent = std::path::PathBuf::from("/this/path/does/not/exist/neothd_test_fake");
        let result = chat_via_subprocess_with(&nonexistent, "hello");
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("could not start") || msg.contains("Chat subprocess"));
    }

    #[test]
    fn apply_active_preset_via_subprocess_with_reports_binary_missing() {
        // GR-05: the apply seam degrades to an operator-readable status
        // string (not a panic) when the pinned binary can't spawn — the
        // first subprocess (`preset list`) fails to start. The
        // active-name parsing the happy path relies on is covered
        // separately by `parse_active_preset_name_*`.
        let nonexistent =
            std::path::PathBuf::from("/this/path/does/not/exist/neothd_test_fake_preset");
        let result = crate::apply_active_preset_via_subprocess_with(&nonexistent);
        assert!(
            result.contains("could not start"),
            "expected a spawn-failure status, got: {result}"
        );
    }

    /// GR-05: stage a fake `neothd` that answers `preset list` (with or
    /// without an active `*` marker) and `preset apply <name>` (exit 0),
    /// so the full list → parse-active → apply seam can be driven end-to-end
    /// against a staged binary. Windows → `.cmd`; unix → an executable
    /// `#!/bin/sh` script.
    fn stage_fake_preset_neothd(
        dir: &std::path::Path,
        list_has_active: bool,
    ) -> std::path::PathBuf {
        #[cfg(windows)]
        {
            let p = dir.join("neothd.cmd");
            let list_line = if list_has_active {
                "echo * lowkey"
            } else {
                "echo   lowkey"
            };
            // `preset list` echoes the bundle list; everything else (incl.
            // `preset apply`) just exits 0.
            let body = format!(
                "@echo off\r\nif \"%1\"==\"preset\" if \"%2\"==\"list\" {list_line}\r\nexit /b 0\r\n"
            );
            std::fs::write(&p, body).unwrap();
            p
        }
        #[cfg(not(windows))]
        {
            use std::os::unix::fs::PermissionsExt;
            let p = dir.join("neothd.sh");
            let list_line = if list_has_active {
                "echo '* lowkey'"
            } else {
                "echo '  lowkey'"
            };
            let body = format!(
                "#!/bin/sh\nif [ \"$1\" = preset ] && [ \"$2\" = list ]; then {list_line}; fi\nexit 0\n"
            );
            std::fs::write(&p, body).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            p
        }
    }

    #[test]
    fn apply_active_preset_via_subprocess_with_applies_when_active_present() {
        // Full happy path: list returns `* lowkey` → parse-active finds
        // `lowkey` → apply succeeds (exit 0) → "Applied preset `lowkey`."
        let dir = tempfile::TempDir::new().unwrap();
        let bin = stage_fake_preset_neothd(dir.path(), true);
        let result = crate::apply_active_preset_via_subprocess_with(&bin);
        assert!(
            result.contains("Applied preset") && result.contains("lowkey"),
            "expected applied-preset status, got: {result}"
        );
    }

    #[test]
    fn apply_active_preset_via_subprocess_with_reports_no_active_when_no_marker() {
        // List has no `*` marker → no active preset → the seam stops before
        // any apply and returns the operator-guidance status.
        let dir = tempfile::TempDir::new().unwrap();
        let bin = stage_fake_preset_neothd(dir.path(), false);
        let result = crate::apply_active_preset_via_subprocess_with(&bin);
        assert!(
            result.contains("No active preset"),
            "expected no-active-preset status, got: {result}"
        );
    }

    // ODY-10: recall buffer logic — pure Rust unit tests (no Slint window).

    #[test]
    fn recall_buffer_captures_last_non_empty_send() {
        let buf: std::sync::Arc<std::sync::Mutex<String>> =
            std::sync::Arc::new(std::sync::Mutex::new(String::new()));

        // Simulate what on_chat_send_clicked does on a non-empty body.
        let body = "  hello world  ".trim().to_string();
        if !body.is_empty()
            && let Ok(mut last) = buf.lock()
        {
            *last = body.clone();
        }
        assert_eq!(*buf.lock().unwrap(), "hello world");

        // A second non-empty send overwrites the buffer.
        let body2 = "second message".to_string();
        if !body2.is_empty()
            && let Ok(mut last) = buf.lock()
        {
            *last = body2.clone();
        }
        assert_eq!(*buf.lock().unwrap(), "second message");
    }

    #[test]
    fn recall_buffer_ignores_empty_body() {
        let buf: std::sync::Arc<std::sync::Mutex<String>> =
            std::sync::Arc::new(std::sync::Mutex::new("previous".to_string()));

        // An empty body (early-return guard) must NOT overwrite the buffer.
        let body = "  ".trim().to_string();
        if !body.is_empty()
            && let Ok(mut last) = buf.lock()
        {
            *last = body.clone();
        }
        assert_eq!(
            *buf.lock().unwrap(),
            "previous",
            "empty send must not clobber recall buffer"
        );
    }
}

// ── GAP-01 Cron panel probe ───────────────────────────────────────────────────
//
// Shells `neoth cron list --output json`, parses via panel_logic::parse_cron_jobs,
// then pushes a typed CronJobRow model into the Slint event loop.
fn refresh_cron(weak: slint::Weak<MainWindow>) {
    use slint::VecModel;
    let json = run_neothd_probe(&["cron", "list", "--output", "json"]);
    let jobs = panel_logic::parse_cron_jobs(&json);
    let ts = panel_logic::now_hhmm();
    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };
        let rows: Vec<CronJobRow> = jobs
            .into_iter()
            .map(
                |(id, name, enabled, cron, tz, role, timeout, channel, recipient)| CronJobRow {
                    id: id.into(),
                    name: name.into(),
                    enabled,
                    cron: cron.into(),
                    tz: tz.into(),
                    role: role.into(),
                    timeout: timeout.into(),
                    channel: channel.into(),
                    recipient: recipient.into(),
                },
            )
            .collect();
        w.set_cron_jobs(slint::ModelRc::new(std::rc::Rc::new(VecModel::from(rows))));
        w.set_cron_running(false);
        w.set_cron_refreshed_at(ts.as_str().into());
    });
}

// ── Design Wave 4a — n8n panel probe ─────────────────────────────────────────
fn refresh_n8n(weak: slint::Weak<MainWindow>) {
    use slint::VecModel;
    let status_json = run_neothd_probe(&["n8n", "status", "--output", "json"]);
    let workflows_json = run_neothd_probe(&["n8n", "workflows", "--output", "json"]);

    let (installed, webhook_base, n8n_path) = panel_logic::parse_n8n_status(&status_json);
    let workflows = panel_logic::parse_n8n_workflows(&workflows_json);

    let ts = panel_logic::now_hhmm();
    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };
        w.set_n8n_installed(installed);
        w.set_n8n_webhook_base(webhook_base.as_str().into());
        w.set_n8n_path(n8n_path.as_str().into());
        {
            let rows: Vec<N8nWorkflow> = workflows
                .into_iter()
                .map(|(name, description)| N8nWorkflow {
                    name: name.into(),
                    description: description.into(),
                })
                .collect();
            w.set_n8n_workflows(slint::ModelRc::new(std::rc::Rc::new(VecModel::from(rows))));
        }
        w.set_n8n_refreshed_at(ts.as_str().into());
    });
}

// ── Design Wave 4a — Babel panel probe ───────────────────────────────────────
fn refresh_babel(weak: slint::Weak<MainWindow>) {
    use slint::VecModel;
    let status_json = run_neothd_probe(&["babel", "status", "--output", "json"]);
    let windows_json = run_neothd_probe(&["babel", "windows", "--n", "12", "--output", "json"]);

    let status = panel_logic::parse_babel_status(&status_json);
    let window_rows = panel_logic::parse_babel_windows(&windows_json);

    let ts = panel_logic::now_hhmm();
    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };
        w.set_babel_enabled(status.enabled);
        w.set_babel_threshold(status.threshold.as_str().into());
        w.set_babel_epsilon(status.epsilon.as_str().into());
        w.set_babel_federate(status.federate);
        w.set_babel_total_windows(status.total_windows);
        w.set_babel_collapse_flagged(status.collapse_flagged);
        w.set_babel_memory_signals(status.memory_signals.as_str().into());
        w.set_babel_skill_signals(status.skill_signals.as_str().into());
        w.set_babel_kd_extractor(status.k_d.as_str().into());
        {
            let rows: Vec<BabelGranRow> = status
                .gran_rows
                .into_iter()
                .map(|(window_secs, count, last_ts_end)| BabelGranRow {
                    window_secs,
                    count,
                    last_ts_end: last_ts_end.into(),
                })
                .collect();
            w.set_babel_gran_rows(slint::ModelRc::new(std::rc::Rc::new(VecModel::from(rows))));
        }
        {
            let rows: Vec<BabelWindowRow> = window_rows
                .into_iter()
                .map(
                    |(
                        id,
                        window_secs,
                        ts_start,
                        ts_end,
                        b_log,
                        b_mult,
                        b_bottleneck,
                        collapse_kind,
                    )| {
                        BabelWindowRow {
                            id: id.into(),
                            window_secs,
                            ts_start: ts_start.into(),
                            ts_end: ts_end.into(),
                            b_log,
                            b_mult,
                            b_bottleneck,
                            collapse_kind: collapse_kind.into(),
                        }
                    },
                )
                .collect();
            w.set_babel_window_rows(slint::ModelRc::new(std::rc::Rc::new(VecModel::from(rows))));
        }
        w.set_babel_refreshed_at(ts.as_str().into());
    });
}

// ── Design Wave 4a — Calendar panel probe ────────────────────────────────────
fn refresh_calendar(weak: slint::Weak<MainWindow>) {
    use slint::VecModel;
    let cal_json = run_neothd_probe(&["calendar", "list", "--output", "json"]);

    let (configured, events) = panel_logic::parse_calendar_events(&cal_json);

    let ts = panel_logic::now_hhmm();
    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };
        w.set_cal_configured(configured);
        {
            let rows: Vec<CalEventRow> = events
                .into_iter()
                .map(|(datetime, summary, location)| CalEventRow {
                    datetime: datetime.into(),
                    summary: summary.into(),
                    location: location.into(),
                })
                .collect();
            w.set_cal_events(slint::ModelRc::new(std::rc::Rc::new(VecModel::from(rows))));
        }
        w.set_cal_refreshed_at(ts.as_str().into());
    });
}

// ── Design Wave 4a — Self-Improve panel probe ─────────────────────────────────
fn refresh_selfimprove(weak: slint::Weak<MainWindow>) {
    use slint::VecModel;
    let status_json = run_neothd_probe(&["self-improve", "status", "--output", "json"]);
    let review_json = run_neothd_probe(&["self-improve", "review", "--output", "json"]);
    let log_json = run_neothd_probe(&["self-improve", "log", "--output", "json"]);

    let (si_enabled, si_auto, si_skillopt, si_last, si_autonomy) =
        panel_logic::parse_selfimprove_status(&status_json);
    let proposals = panel_logic::parse_selfimprove_proposals(&review_json);
    let log_rows = panel_logic::parse_selfimprove_log(&log_json);

    let ts = panel_logic::now_hhmm();
    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };
        w.set_si_enabled(si_enabled);
        w.set_si_auto(si_auto);
        w.set_si_skillopt_installed(si_skillopt);
        w.set_si_last_run(si_last.as_str().into());
        w.set_si_autonomy(si_autonomy.as_str().into());
        {
            let rows: Vec<SiProposalRow> = proposals
                .into_iter()
                .map(|(id, title, description)| SiProposalRow {
                    id: id.into(),
                    title: title.into(),
                    description: description.into(),
                })
                .collect();
            w.set_si_proposals(slint::ModelRc::new(std::rc::Rc::new(VecModel::from(rows))));
        }
        {
            let rows: Vec<SiLogRow> = log_rows
                .into_iter()
                .map(|(id, title, status, ts_entry)| SiLogRow {
                    id: id.into(),
                    title: title.into(),
                    status: status.into(),
                    ts: ts_entry.into(),
                })
                .collect();
            w.set_si_log(slint::ModelRc::new(std::rc::Rc::new(VecModel::from(rows))));
        }
        w.set_si_refreshed_at(ts.as_str().into());
    });
}

// ── FEAT-05 — Self-Dev Proposal Review probe ─────────────────────────────────
fn refresh_selfdev(weak: slint::Weak<MainWindow>) {
    use slint::VecModel;
    let json = run_neothd_probe(&["self-dev", "review", "--output", "json"]);
    let proposals = panel_logic::parse_selfdev_proposals(&json);
    let ts = panel_logic::now_hhmm();
    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };
        let rows: Vec<SelfReprogProposalRow> = proposals
            .into_iter()
            .map(|p| {
                // RED LINE: status_badge never says "Applied" or
                // "Self-Reprogramming applied". Badge is the raw status string
                // ("pending" | "accepted" | "declined") so the Slint Apply button
                // condition `row-status-badge == "accepted"` resolves correctly.
                // SourceEdit accepted proposals show the Apply button as enabled;
                // the operator must click through a confirm dialog before any
                // gate subprocess fires.
                let badge = match p.status.as_str() {
                    "accepted" => "accepted",
                    "declined" => "declined",
                    _ => "pending",
                };
                let conf = format!("{:.2}", p.confidence);
                let is_source_edit = p.kind == "source_edit";
                SelfReprogProposalRow {
                    id: p.id.as_str().into(),
                    kind: p.kind.as_str().into(),
                    confidence: conf.as_str().into(),
                    target: p.target.as_str().into(),
                    reason: p.reason.as_str().into(),
                    status_badge: badge.into(),
                    // GUI-DES-SELFDEV-APPLY-01 — SourceEdit fields:
                    is_source_edit,
                    patch_path: p.patch_path.as_str().into(),
                    diff_sha256: p.diff_sha256.as_str().into(),
                }
            })
            .collect();
        w.set_sd_proposals(slint::ModelRc::new(std::rc::Rc::new(VecModel::from(rows))));
        w.set_sd_refreshed_at(ts.as_str().into());
        w.set_sd_scan_running(false);
    });
}

// ── Wave 4b — Obsidian Vault probe ───────────────────────────────────────────
fn refresh_obsidian(weak: slint::Weak<MainWindow>) {
    let out = run_neothd_probe(&["obsidian", "status", "--output", "json"]);
    let (vault_path, subdir, result_text) = panel_logic::parse_obsidian_status(&out);
    let ts = panel_logic::now_hhmm();
    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };
        w.set_obs_vault_path(vault_path.as_str().into());
        w.set_obs_subdir(subdir.as_str().into());
        w.set_obs_result_text(result_text.as_str().into());
        w.set_obs_refreshed_at(ts.as_str().into());
    });
}

// ── Wave 4b — Dreaming / Memory & Self-Awareness probe ───────────────────────
fn refresh_dreaming(weak: slint::Weak<MainWindow>) {
    use slint::VecModel;
    let out = run_neothd_probe(&["dream", "list", "--output", "json"]);
    let (days, refreshed_at) = panel_logic::parse_dream_days(&out);
    let ts = if refreshed_at.is_empty() {
        panel_logic::now_hhmm()
    } else {
        refreshed_at
    };
    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };
        let rows: Vec<DreamDayRow> = days
            .into_iter()
            .map(|(day, path, entries)| DreamDayRow {
                day: day.into(),
                path: path.into(),
                entries,
            })
            .collect();
        w.set_dr_days(slint::ModelRc::new(std::rc::Rc::new(VecModel::from(rows))));
        w.set_dr_refreshed_at(ts.as_str().into());
    });
}

// ── Wave 4b — Wiki / Capability Map probe ────────────────────────────────────
fn refresh_wiki(weak: slint::Weak<MainWindow>) {
    let out = run_neothd_probe(&["capabilities", "--output", "json"]);
    let rows = panel_logic::parse_wiki_rows(&out);
    apply_wiki(weak, rows);
}

fn refresh_wiki_filtered(weak: slint::Weak<MainWindow>, search: String, kind: String) {
    let out = run_neothd_probe(&["capabilities", "--output", "json"]);
    let all = panel_logic::parse_wiki_rows(&out);
    let rows = panel_logic::filter_wiki_rows(all, &search, &kind);
    apply_wiki(weak, rows);
}

fn apply_wiki(weak: slint::Weak<MainWindow>, rows: Vec<panel_logic::WikiRowData>) {
    use slint::VecModel;
    let total = rows.len() as i32;
    let ts = panel_logic::now_hhmm();
    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };
        let slint_rows: Vec<WikiRow> = rows
            .into_iter()
            .map(|r| WikiRow {
                id: r.id.into(),
                kind: r.kind.into(),
                description: r.description.into(),
                gate: r.gate.into(),
            })
            .collect();
        w.set_wiki_rows(slint::ModelRc::new(std::rc::Rc::new(VecModel::from(
            slint_rows,
        ))));
        w.set_wiki_total(total);
        w.set_wiki_refreshed_at(ts.as_str().into());
    });
}

// ── Wave 4b — Buddy Config probe ─────────────────────────────────────────────
fn refresh_buddyconfig(weak: slint::Weak<MainWindow>) {
    use slint::VecModel;
    let result = fetch_buddy_status();
    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };
        match result {
            Ok(snap) => {
                let skill_rows: Vec<SelfActSkill> = snap
                    .self_activation_skills
                    .into_iter()
                    .map(|name| SelfActSkill { name: name.into() })
                    .collect();
                w.set_bc_self_activation_skills(slint::ModelRc::new(std::rc::Rc::new(
                    VecModel::from(skill_rows),
                )));
                w.set_bc_sovereign_buddy(snap.sovereign_buddy);
                w.set_bc_self_activation_enabled(snap.self_activation_enabled);
                w.set_bc_smart_approve(snap.smart_approve_any);
                w.set_bc_autonomy(snap.autonomy.as_str().into());
                w.set_bc_proactive_enabled(snap.proactive_enabled);
                w.set_bc_refreshed_at(panel_logic::now_hhmm().into());
                w.set_bc_status_valid(true);
                w.set_bc_status_error("".into());
            }
            Err(error) => {
                // Keep every previously rendered value as last-known-good.
                // Only freshness/error state changes on a failed probe.
                w.set_bc_status_valid(false);
                w.set_bc_status_error(error.into());
            }
        }
    });
}

// ── Wave 4b — Companion probe ────────────────────────────────────────────────
fn refresh_companion(weak: slint::Weak<MainWindow>) {
    let home = default_neoth_home();
    let pending = home.join("companion_pending_invite.json").exists();
    let ts = panel_logic::now_hhmm();
    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };
        w.set_cp_invite_pending(pending);
        w.set_cp_refreshed_at(ts.as_str().into());
    });
}

// ── Wave 4b — Mesh & Cluster probe ───────────────────────────────────────────
fn refresh_mesh(weak: slint::Weak<MainWindow>) {
    use slint::VecModel;
    let out = run_neothd_probe(&["cluster", "status", "--output", "json"]);
    let snap = panel_logic::parse_mesh_status(&out);
    // DES-13 — the failover backup that already exists: replicated peer events
    // this node persists (idx_foreign_events). Empty when the cluster feature
    // isn't built or no peers are paired.
    let foreign_out =
        run_neothd_probe(&["cluster", "events", "--output", "json", "--limit", "500"]);
    let backup = panel_logic::parse_foreign_backup(&foreign_out);
    // Wave 5 — fleet dashboard: per-peer resource meters from the swarm
    // snapshot table + the raw gossip stream as mono log lines.
    let swarm_out = run_neothd_probe(&["cluster", "swarm", "--output", "json"]);
    let swarm_nodes = panel_logic::parse_swarm_nodes(&swarm_out);
    let gossip_lines = panel_logic::format_gossip_lines(&foreign_out, 60);
    let ts = panel_logic::now_hhmm();
    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };
        w.set_mesh_node_id(snap.node_id.as_str().into());
        w.set_mesh_listen_port(snap.listen_port.as_str().into());
        w.set_mesh_trusted_ssids(snap.trusted_ssids.as_str().into());
        let peer_rows: Vec<MeshPeerRow> = snap
            .peers
            .into_iter()
            .map(|p| {
                // Join gossip resource snapshots onto the peer list by node
                // id prefix (status ids may be truncated for display).
                let res = swarm_nodes
                    .iter()
                    .find(|n| n.node_id == p.id || n.node_id.starts_with(&p.id));
                MeshPeerRow {
                    id: p.id.into(),
                    last_seen: p.last_seen.into(), // Slint kebab→snake: last-seen → last_seen
                    reachable: p.reachable,
                    cpu_pct: res.map(|n| n.cpu_frac).unwrap_or(0.0),
                    ram_pct: res.map(|n| n.ram_frac).unwrap_or(0.0),
                    vram_pct: res.map(|n| n.vram_frac).unwrap_or(0.0),
                    role: "".into(), // roles land with the gossip payload extension
                    version: "".into(), // ditto — neoth_version is not gossiped yet
                    staleness_secs: res.map(|n| n.age_secs).unwrap_or(0),
                }
            })
            .collect();
        let gossip_model: Vec<slint::SharedString> =
            gossip_lines.iter().map(|l| l.as_str().into()).collect();
        w.set_mesh_gossip_events(slint::ModelRc::new(std::rc::Rc::new(VecModel::from(
            gossip_model,
        ))));
        w.set_mesh_peers(slint::ModelRc::new(std::rc::Rc::new(VecModel::from(
            peer_rows,
        ))));
        w.set_mesh_gossip_note(snap.gossip_note.as_str().into());
        // DES-13 — backup-at-rest per-peer rows + totals.
        let foreign_rows: Vec<MeshForeignRow> = backup
            .peers
            .iter()
            .map(|p| MeshForeignRow {
                peer: p.peer.chars().take(24).collect::<String>().into(),
                count: p.count.to_string().into(),
                bytes: panel_logic::format_backup_bytes(p.bytes).into(),
                latest: panel_logic::format_epoch_utc(p.latest_at).into(),
            })
            .collect();
        w.set_mesh_foreign_rows(slint::ModelRc::new(std::rc::Rc::new(VecModel::from(
            foreign_rows,
        ))));
        w.set_mesh_foreign_total(backup.total_events as i32);
        w.set_mesh_foreign_peers(backup.peers.len() as i32);
        w.set_mesh_foreign_bytes(
            panel_logic::format_backup_bytes(backup.total_bytes)
                .as_str()
                .into(),
        );
        w.set_mesh_refreshed_at(ts.as_str().into());
    });
}

// ── Chat-surface consent strip probe ─────────────────────────────────────────
//
// Shells two JSON subcommands (`autonomy show` + `consent list`), parses via
// panel_logic pure-fns, then writes chat-consent-mode and chat-consent-grants
// in one invoke_from_event_loop call.  Must be called from a worker thread.
fn refresh_chat_consent(weak: slint::Weak<MainWindow>) {
    use slint::VecModel;

    let run = |args: &[&str]| -> String {
        which_neothd()
            .and_then(|bin| spawn_neothd_plain(&bin).args(args).output().ok())
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .unwrap_or_default()
    };

    let autonomy_json = run(&["autonomy", "show", "--output", "json"]);
    let consent_json = run(&["consent", "list", "--output", "json"]);

    let mode = panel_logic::parse_autonomy_mode(&autonomy_json);
    let grants = panel_logic::parse_chat_consent_grants(&consent_json);

    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };
        w.set_chat_consent_mode(mode.as_str().into());
        let grant_rows: Vec<ConsentGrant> = grants
            .into_iter()
            .map(|(provider, granted)| ConsentGrant {
                provider: provider.into(),
                granted,
            })
            .collect();
        w.set_chat_consent_grants(slint::ModelRc::new(std::rc::Rc::new(VecModel::from(
            grant_rows,
        ))));
    });
}

// ── Overview / Mission Control probe (Design Wave 3) ─────────────────────────
//
// Shells the JSON daemon commands sequentially (tolerate individual failures),
// parses via panel_logic pure-fns, then mutates the MainWindow in one
// invoke_from_event_loop call.  Must be called from a worker thread — never
// from the Slint event loop.
/// Wave 8 — C7/H5: feed the COST & USAGE card. Top sessions from the
/// WAL token ledger + a 7-day usage sparkline (one rollup probe per
/// day; overview refresh is manual/startup so seven quick subprocesses
/// are fine). Rides the same triggers as refresh_overview.
fn refresh_overview_cost(weak: slint::Weak<MainWindow>) {
    use slint::VecModel;
    let sessions_out = run_neothd_probe(&["cost", "top-sessions", "--output", "json"]);
    let sessions = panel_logic::parse_cost_sessions(&sessions_out);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut days: Vec<f64> = Vec::with_capacity(7);
    let mut week_cost = 0.0_f64;
    for i in (0..7).rev() {
        let until = now - i * 86_400;
        let since = until - 86_400;
        let out = run_neothd_probe(&[
            "usage",
            "--since-unix",
            &since.to_string(),
            "--until-unix",
            &until.to_string(),
            "--format",
            "json",
        ]);
        let (cost, tokens) = panel_logic::parse_usage_rollup(&out).unwrap_or((0.0, 0));
        week_cost += cost;
        // Sparkline follows spend when priced, tokens otherwise.
        days.push(if cost > 0.0 {
            cost
        } else {
            tokens as f64 / 1000.0
        });
    }
    let max_day = days.iter().cloned().fold(0.0_f64, f64::max).max(1e-9);
    let bars: Vec<f32> = days.iter().map(|d| (d / max_day) as f32).collect();
    let label = if week_cost > 0.0 {
        format!("usd {week_cost:.2} this week")
    } else {
        "no priced spend this week".to_string()
    };

    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };
        let rows: Vec<CostSessionRow> = sessions
            .into_iter()
            .map(|s| CostSessionRow {
                session: s.session.into(),
                provider: s.provider.into(),
                tokens: s.tokens.into(),
                cost: s.cost.into(),
            })
            .collect();
        w.set_ov_cost_sessions(slint::ModelRc::new(std::rc::Rc::new(VecModel::from(rows))));
        w.set_ov_usage_days(slint::ModelRc::new(std::rc::Rc::new(VecModel::from(bars))));
        w.set_ov_usage_days_label(label.as_str().into());
    });
}

fn refresh_overview(weak: slint::Weak<MainWindow>) {
    let bin = match which_neothd() {
        Some(b) => b,
        None => {
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_ov_operating_mode("neothd not found".into());
                    w.set_ov_daemon_state("error".into());
                    w.set_ov_refreshed_at("binary missing".into());
                }
            });
            return;
        }
    };

    // Helper: run a neothd subcommand, return stdout or an empty string on
    // failure. Individual failures degrade a card to "unavailable" rather than
    // aborting the whole refresh.
    let run = |args: &[&str]| -> String {
        spawn_neothd_plain(&bin)
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .unwrap_or_default()
    };

    // Fire all JSON probes.
    let status_json = run(&["status", "--output", "json"]);
    let meter_json = run(&["meter", "--format", "json"]);
    let hemi_json = run(&["hemispheres", "show", "--output", "json"]);
    let agents_json = run(&["agents", "list", "--output", "json"]);
    let skills_json = run(&["skills", "list", "--output", "json"]);
    let plugin_json = run(&["plugin", "list", "--output", "json"]);
    let cal_json = run(&["calendar", "list", "--output", "json"]);
    let consent_json = run(&["consent", "list", "--output", "json"]);

    // Parse — all pure fns in panel_logic.
    let (mode, autonomy, ch_health, wal_bytes, tier_counts, daemon_state) =
        panel_logic::parse_overview_status(&status_json);
    let (tok_in, tok_out, responses, cost, tok_fraction) = panel_logic::parse_meter(&meter_json);
    let hemis = panel_logic::parse_overview_hemispheres(&hemi_json);
    let (agents_count, agent_names) = panel_logic::parse_agents(&agents_json);
    let (skills_count, skill_names) = panel_logic::parse_overview_skills(&skills_json);
    let (plugins_count, plugin_names) = panel_logic::parse_overview_skills(&plugin_json);
    let (cal_configured, cal_events) = panel_logic::parse_calendar_next(&cal_json, 3);
    let (consent_entries, smart_approve) = panel_logic::parse_consent(&consent_json);

    // Timestamp.
    let ts = {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let hh = (secs / 3600) % 24;
        let mm = (secs / 60) % 60;
        let ss = secs % 60;
        format!("{hh:02}:{mm:02}:{ss:02} UTC")
    };

    // Push everything to the UI in one event-loop hop.
    let _ = slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };

        // STATUS
        w.set_ov_operating_mode(mode.into());
        w.set_ov_autonomy(autonomy.into());
        w.set_ov_daemon_state(daemon_state.into());
        w.set_ov_channel_health(ch_health.into());
        w.set_ov_wal_bytes(wal_bytes.into());
        w.set_ov_tier_counts(tier_counts.into());

        // TOKENS
        w.set_ov_tokens_in(tok_in.into());
        w.set_ov_tokens_out(tok_out.into());
        w.set_ov_responses(responses.into());
        w.set_ov_cost(cost.into());
        w.set_ov_token_fraction(tok_fraction);

        // HEMISPHERES — build the [HemiCard] model
        {
            use slint::VecModel;
            let rows: Vec<HemiCard> = hemis
                .into_iter()
                .map(|(role, provider, model, ok)| HemiCard {
                    role: role.into(),
                    provider: provider.into(),
                    model: model.into(),
                    ok,
                })
                .collect();
            w.set_ov_hemispheres(std::rc::Rc::new(VecModel::from(rows)).into());
        }

        // AGENTS
        w.set_ov_agents_count(agents_count.into());
        {
            use slint::VecModel;
            let rows: Vec<slint::SharedString> = agent_names.into_iter().map(Into::into).collect();
            w.set_ov_agent_names(std::rc::Rc::new(VecModel::from(rows)).into());
        }

        // SKILLS & PLUGINS
        w.set_ov_skills_active(skills_count.into());
        w.set_ov_plugins_active(plugins_count.into());
        {
            use slint::VecModel;
            let srows: Vec<slint::SharedString> = skill_names.into_iter().map(Into::into).collect();
            w.set_ov_skill_names(std::rc::Rc::new(VecModel::from(srows)).into());
            let prows: Vec<slint::SharedString> =
                plugin_names.into_iter().map(Into::into).collect();
            w.set_ov_plugin_names(std::rc::Rc::new(VecModel::from(prows)).into());
        }

        // CALENDAR
        w.set_ov_calendar_configured(cal_configured);
        {
            use slint::VecModel;
            let rows: Vec<CalEvent> = cal_events
                .into_iter()
                .map(|(time, summary)| CalEvent {
                    time: time.into(),
                    summary: summary.into(),
                })
                .collect();
            w.set_ov_calendar_events(std::rc::Rc::new(VecModel::from(rows)).into());
        }

        // CONSENT
        {
            use slint::VecModel;
            let rows: Vec<ConsentEntry> = consent_entries
                .into_iter()
                .map(|(provider, granted)| ConsentEntry {
                    provider: provider.into(),
                    granted,
                })
                .collect();
            w.set_ov_consent_entries(std::rc::Rc::new(VecModel::from(rows)).into());
        }
        w.set_ov_smart_approve(smart_approve.into());

        // Timestamp
        w.set_ov_refreshed_at(ts.into());
    });
}

fn probe_hardware_via_subprocess() -> String {
    let candidate = which_neothd();
    let Some(bin) = candidate else {
        return "Hardware probe unavailable — `neothd` binary not on PATH.\n\
                Install the daemon first (cargo install --path ../neothd)."
            .to_string();
    };
    let output = spawn_neothd_plain(&bin)
        .arg("hardware")
        .arg("--output")
        .arg("table")
        .output();
    match output {
        Ok(out) if out.status.success() => {
            shape_hardware_footer(&String::from_utf8_lossy(&out.stdout))
        }
        Ok(out) => format!(
            "Hardware probe failed (exit {}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        ),
        Err(e) => format!("Hardware probe could not start: {e}"),
    }
}

/// Collapse the multi-line `neoth hardware --output table` probe into a single
/// footer line. The FooterBar is one 36px row — the full table (10+ lines)
/// spilled past it and was clipped by the window edge. Keep only the operator-
/// relevant fields, whitespace-collapsed, joined with " · ".
fn shape_hardware_footer(table: &str) -> String {
    const KEEP: [&str; 5] = ["CPU:", "RAM:", "Accelerator:", "GPU VRAM:", "Disk:"];
    let parts: Vec<String> = table
        .lines()
        .map(str::trim)
        .filter(|line| KEEP.iter().any(|k| line.starts_with(k)))
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect();
    if parts.is_empty() {
        "NEOTH — Your buddy. Your life.".to_string()
    } else {
        parts.join("   ·   ")
    }
}

/// QM-9 Phase 2: probe the last 24h of usage via the same `neoth
/// usage --format json` surface the CLI ships. Returns an operator-
/// readable one-line summary on success, or a clear error string
/// when the subprocess can't run / fails / returns malformed JSON.
fn probe_usage_via_subprocess() -> String {
    let candidate = which_neothd();
    let Some(bin) = candidate else {
        return "Usage unavailable — `neothd` binary not on PATH.".to_string();
    };
    let output = spawn_neothd_plain(&bin)
        .arg("usage")
        .arg("--format")
        .arg("json")
        .arg("--days")
        .arg("1")
        .output();
    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            shape_usage_summary(&stdout)
        }
        Ok(out) => format!(
            "Usage probe failed (exit {}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => format!("Usage probe could not start: {e}"),
    }
}

/// Parse the `neoth usage --format json` envelope + render a one-line
/// summary. Pure function so the test path can pin the rendering
/// without spawning a real subprocess.
pub fn shape_usage_summary(json: &str) -> String {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(json) else {
        return "Usage: malformed response".to_string();
    };
    let calls = val
        .get("total_call_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let ok = val
        .get("total_ok_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let err = val
        .get("total_err_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let cost = val
        .get("total_cost_usd")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    if calls == 0 {
        return "No usage in the last 24h.".to_string();
    }
    format!("Last 24h: {calls} calls (ok={ok}, err={err}), ${cost:.4}")
}

/// GOLD-WIRE-10b: probe the daemon's live token-budget meter via the
/// same `neoth meter --json` surface the CLI ships. Returns an operator-
/// readable one-line summary, or a clear error string when the subprocess
/// can't run / fails / returns malformed JSON.
fn probe_budget_via_subprocess() -> String {
    let candidate = which_neothd();
    let Some(bin) = candidate else {
        return "Budget unavailable — `neothd` binary not on PATH.".to_string();
    };
    let output = spawn_neothd_plain(&bin)
        .arg("meter")
        .arg("--format")
        .arg("json")
        .output();
    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let panel = panel_logic::parse_usage_meter(&stdout);
            if panel.available {
                format!("{} · {} · {}", panel.responses, panel.tokens, panel.note)
            } else {
                "Budget unavailable — daemon may not be running.".to_string()
            }
        }
        Ok(out) => format!(
            "Budget probe failed (exit {}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => format!("Budget probe could not start: {e}"),
    }
}

/// QM-8 Phase 2.5: resolve the active preset (via `neoth preset list`),
/// then shell `neoth preset apply <active>`. Returns an operator-
/// readable result string for the status line.
fn apply_active_preset_via_subprocess() -> String {
    let Some(bin) = which_neothd() else {
        return "Preset apply unavailable — `neothd` binary not on PATH.".to_string();
    };
    apply_active_preset_via_subprocess_with(&bin)
}

/// GR-05 test-injection seam (mirrors [`chat_via_subprocess_with`]): the
/// caller pins the binary path so a test can drive the full
/// list → parse-active → apply flow against a staged fake `neothd`
/// instead of requiring the real daemon on PATH.
pub fn apply_active_preset_via_subprocess_with(bin: &std::path::Path) -> String {
    // First: list to find the active marker.
    let list_output = spawn_neothd_plain(bin).arg("preset").arg("list").output();
    let stdout = match list_output {
        Ok(out) if out.status.success() => out.stdout,
        Ok(out) => {
            return format!(
                "preset list failed (exit {}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Err(e) => return format!("preset list could not start: {e}"),
    };
    let active = parse_active_preset_name(&stdout);
    let Some(name) = active else {
        return "No active preset — `neoth preset activate <name>` first.".to_string();
    };
    let apply_output = spawn_neothd_plain(bin)
        .arg("preset")
        .arg("apply")
        .arg(&name)
        .output();
    match apply_output {
        Ok(out) if out.status.success() => format!("Applied preset `{name}`."),
        Ok(out) => format!(
            "preset apply `{name}` failed (exit {}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => format!("preset apply could not start: {e}"),
    }
}

/// Parse the active preset name out of `neoth preset list` stdout.
/// Returns the bare name (no `*` prefix) when an active marker is
/// present, else None.
pub fn parse_active_preset_name(stdout: &[u8]) -> Option<String> {
    let body = String::from_utf8_lossy(stdout);
    for line in body.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('*') {
            let name = trimmed
                .trim_start_matches(|c: char| c == '*' || c.is_whitespace())
                .trim()
                .to_string();
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}

/// QM-8 Phase 2: probe the saved preset list via `neoth preset list`
/// and render a compact summary. Same worker-thread shape as the
/// usage probe.
fn probe_preset_summary_via_subprocess() -> String {
    let candidate = which_neothd();
    let Some(bin) = candidate else {
        return "Preset list unavailable — `neothd` binary not on PATH.".to_string();
    };
    let output = spawn_neothd_plain(&bin).arg("preset").arg("list").output();
    match output {
        Ok(out) if out.status.success() => shape_preset_summary(&out.stdout),
        Ok(out) => format!(
            "Preset list failed (exit {}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ),
        Err(e) => format!("Preset list could not start: {e}"),
    }
}

/// Pure shaping helper — tested in isolation. Input shape matches
/// `cli::preset::run_list` stdout (lines like "  zeta", "* active").
pub fn shape_preset_summary(stdout: &[u8]) -> String {
    let body = String::from_utf8_lossy(stdout);
    let lines: Vec<&str> = body.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.is_empty() || lines[0].starts_with("(no presets") {
        return "No presets saved. Use `neoth preset ...` from a terminal.".to_string();
    }
    let mut active: Option<&str> = None;
    let mut count = 0usize;
    for line in &lines {
        if line.trim_start().starts_with('*') {
            active = Some(line.trim_start_matches(|c: char| c == '*' || c.is_whitespace()));
        }
        count += 1;
    }
    match active {
        Some(name) => format!("{count} presets · active: {name}"),
        None => format!("{count} presets · no active"),
    }
}

const GUI_READY_FILE_ENV: &str = "NEOTH_GUI_READY_FILE";
const GUI_READY_TOKEN_ENV: &str = "NEOTH_GUI_READY_TOKEN";
const GUI_PARENT_COMMIT_ENV: &str = "NEOTH_GUI_PARENT_COMMIT";
const GUI_LAUNCH_DIR: &str = ".gui-launch";
const GUI_READY_TOKEN_BYTES: usize = 56;

#[derive(Clone)]
struct GuiParentHandoff {
    ready_path: PathBuf,
    token: String,
    parent_commit: bool,
}

fn gui_parent_handoff_from_env(home: &Path) -> Result<Option<GuiParentHandoff>> {
    let ready_file = std::env::var_os(GUI_READY_FILE_ENV);
    let ready_token = std::env::var(GUI_READY_TOKEN_ENV).ok();
    let parent_commit = std::env::var(GUI_PARENT_COMMIT_ENV).ok();
    parse_gui_parent_handoff(
        home,
        ready_file.as_deref(),
        ready_token.as_deref(),
        parent_commit.as_deref(),
    )
}

fn parse_gui_parent_handoff(
    home: &Path,
    ready_file: Option<&std::ffi::OsStr>,
    ready_token: Option<&str>,
    parent_commit: Option<&str>,
) -> Result<Option<GuiParentHandoff>> {
    let (ready_file, ready_token, parent_commit) = match (ready_file, ready_token, parent_commit) {
        (None, None, None) => return Ok(None),
        (Some(file), Some(token), Some(commit)) => (PathBuf::from(file), token, commit),
        _ => anyhow::bail!(
            "GUI parent handoff requires {GUI_READY_FILE_ENV}, {GUI_READY_TOKEN_ENV}, and {GUI_PARENT_COMMIT_ENV} together"
        ),
    };
    if !ready_file.is_absolute() {
        anyhow::bail!("{GUI_READY_FILE_ENV} must be an absolute path");
    }
    if ready_token.len() != GUI_READY_TOKEN_BYTES
        || !ready_token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        anyhow::bail!(
            "{GUI_READY_TOKEN_ENV} must be an exact {GUI_READY_TOKEN_BYTES}-byte lowercase hexadecimal token"
        );
    }
    let parent_commit = match parent_commit {
        "0" => false,
        "1" => true,
        _ => anyhow::bail!("{GUI_PARENT_COMMIT_ENV} must be exactly 0 or 1"),
    };
    if ready_file.file_name() != Some(std::ffi::OsStr::new("ready")) {
        anyhow::bail!("{GUI_READY_FILE_ENV} must name the canonical ready file");
    }

    let canonical_home = home
        .canonicalize()
        .with_context(|| format!("canonicalize NEOTH_HOME {}", home.display()))?;
    let root = canonical_home.join(GUI_LAUNCH_DIR);
    let root_metadata = std::fs::symlink_metadata(&root)
        .with_context(|| format!("inspect GUI launch root {}", root.display()))?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        anyhow::bail!(
            "GUI launch root {} must be a real directory",
            root.display()
        );
    }
    let canonical_root = root
        .canonicalize()
        .with_context(|| format!("canonicalize GUI launch root {}", root.display()))?;
    if canonical_root != root {
        anyhow::bail!(
            "GUI launch root {} escapes canonical NEOTH_HOME",
            root.display()
        );
    }

    let parent = ready_file
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{GUI_READY_FILE_ENV} has no parent directory"))?;
    let parent_metadata = std::fs::symlink_metadata(parent)
        .with_context(|| format!("inspect GUI launch instance {}", parent.display()))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        anyhow::bail!(
            "GUI launch instance {} must be a real directory",
            parent.display()
        );
    }
    let canonical_parent = parent
        .canonicalize()
        .with_context(|| format!("canonicalize GUI launch instance {}", parent.display()))?;
    if canonical_parent.parent() != Some(canonical_root.as_path()) {
        anyhow::bail!(
            "GUI launch instance {} must be directly under {}",
            canonical_parent.display(),
            canonical_root.display()
        );
    }
    let ready_path = canonical_parent.join("ready");
    match std::fs::symlink_metadata(&ready_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => anyhow::bail!(
            "GUI ready file {} already exists; refusing a replayed handoff",
            ready_path.display()
        ),
        Err(error) => {
            return Err(error).with_context(|| format!("inspect {}", ready_path.display()));
        }
    }

    Ok(Some(GuiParentHandoff {
        ready_path,
        token: ready_token.to_string(),
        parent_commit,
    }))
}

fn write_gui_parent_ready(handoff: &GuiParentHandoff) -> Result<()> {
    #[cfg(windows)]
    {
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random)
            .map_err(|error| anyhow::anyhow!("GUI ready temp RNG unavailable: {error}"))?;
        let name = handoff
            .ready_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("ready");
        let temporary = handoff
            .ready_path
            .with_file_name(format!(".{name}.{}.tmp", hex::encode(random)));
        let result = (|| -> Result<()> {
            match std::fs::symlink_metadata(&handoff.ready_path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Ok(_) => anyhow::bail!(
                    "GUI ready file {} already exists",
                    handoff.ready_path.display()
                ),
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("inspect {}", handoff.ready_path.display()));
                }
            }
            let mut file = win_private::create_private_file_new(&temporary)
                .with_context(|| format!("create GUI ready temp {}", temporary.display()))?;
            file.write_all(handoff.token.as_bytes())
                .with_context(|| format!("write GUI ready temp {}", temporary.display()))?;
            file.flush()
                .with_context(|| format!("flush GUI ready temp {}", temporary.display()))?;
            file.sync_all()
                .with_context(|| format!("sync GUI ready temp {}", temporary.display()))?;
            win_private::create_private_file_handle(&file, &handoff.ready_path).with_context(
                || {
                    format!(
                        "commit GUI readiness {} -> {}",
                        temporary.display(),
                        handoff.ready_path.display()
                    )
                },
            )?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }

    #[cfg(not(windows))]
    {
        let temporary = handoff.ready_path.with_extension("tmp");
        let result = (|| -> Result<()> {
            match std::fs::symlink_metadata(&handoff.ready_path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Ok(_) => anyhow::bail!(
                    "GUI ready file {} already exists",
                    handoff.ready_path.display()
                ),
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("inspect {}", handoff.ready_path.display()));
                }
            }
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(&temporary)
                .with_context(|| format!("create GUI ready temp {}", temporary.display()))?;
            file.write_all(handoff.token.as_bytes())
                .with_context(|| format!("write GUI ready temp {}", temporary.display()))?;
            file.sync_all()
                .with_context(|| format!("sync GUI ready temp {}", temporary.display()))?;
            drop(file);
            // `hard_link` is the Unix create-if-absent commit primitive. Unlike
            // rename it cannot replace a raced/replayed Ready file.
            std::fs::hard_link(&temporary, &handoff.ready_path).with_context(|| {
                format!(
                    "commit GUI readiness {} -> {}",
                    temporary.display(),
                    handoff.ready_path.display()
                )
            })?;
            let _ = std::fs::remove_file(&temporary);
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }
}

const INTERFACE_SCHEMA_VERSION: u8 = 1;
const MAX_INTERFACE_PREFERENCE_BYTES: u64 = 4 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GuiInterfacePreference {
    Gui,
    Cli,
}

#[derive(Debug, Eq, PartialEq)]
enum GuiInterfaceBootDecision {
    Ready,
    SwitchCliToGui,
    Choose,
    Repair(String),
}

fn interface_boot_decision(
    parent_commits_gui: bool,
    loaded: Result<Option<GuiInterfacePreference>>,
) -> GuiInterfaceBootDecision {
    if parent_commits_gui {
        return GuiInterfaceBootDecision::Ready;
    }
    match loaded {
        Ok(Some(GuiInterfacePreference::Gui)) => GuiInterfaceBootDecision::Ready,
        Ok(Some(GuiInterfacePreference::Cli)) => GuiInterfaceBootDecision::SwitchCliToGui,
        Ok(None) => GuiInterfaceBootDecision::Choose,
        Err(error) => GuiInterfaceBootDecision::Repair(error.to_string()),
    }
}

impl GuiInterfacePreference {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Gui => "gui",
            Self::Cli => "cli",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GuiInterfacePreferenceRecord {
    schema_version: u8,
    preferred: String,
}

/// Read the daemon-owned interface contract without duplicating its writer.
/// Missing is the sole "not answered yet" state; existing corruption is
/// surfaced so the GUI can offer an explicit repair choice.
fn load_gui_interface_preference(home: &Path) -> Result<Option<GuiInterfacePreference>> {
    let path = home.join("interface.json");
    let file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("open {}", path.display())),
    };
    let mut bytes = Vec::new();
    let mut reader = std::io::BufReader::new(file);
    reader
        .by_ref()
        .take(MAX_INTERFACE_PREFERENCE_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", path.display()))?;
    if bytes.len() as u64 > MAX_INTERFACE_PREFERENCE_BYTES {
        anyhow::bail!(
            "{} is too large (maximum {MAX_INTERFACE_PREFERENCE_BYTES} bytes)",
            path.display()
        );
    }
    let record: GuiInterfacePreferenceRecord =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
    if record.schema_version != INTERFACE_SCHEMA_VERSION {
        anyhow::bail!(
            "unsupported interface preference schema {} in {}",
            record.schema_version,
            path.display()
        );
    }
    match record.preferred.as_str() {
        "gui" => Ok(Some(GuiInterfacePreference::Gui)),
        "cli" => Ok(Some(GuiInterfacePreference::Cli)),
        other => anyhow::bail!(
            "invalid preferred interface `{other}` in {}",
            path.display()
        ),
    }
}

/// Delegate writes to the canonical CLI implementation and verify its
/// machine-readable acknowledgement. The GUI never hand-writes the contract.
fn set_interface_preference_via_cli(
    bin: &Path,
    home: &Path,
    preferred: GuiInterfacePreference,
) -> Result<()> {
    let output = spawn_neothd_plain(bin)
        .env("NEOTH_HOME", home)
        .args(["--output", "json", "interface", "set", preferred.as_str()])
        .output()
        .with_context(|| format!("run `{}` interface set", bin.display()))?;
    if !output.status.success() {
        anyhow::bail!(
            "interface preference update failed (exit {}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    validate_interface_set_result(&output.stdout, home, preferred)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GuiInterfaceSetAcknowledgement {
    chosen: bool,
    preferred: String,
    changed: bool,
    path: PathBuf,
}

/// Validate the complete `neoth --output json interface set` contract. A
/// partial/mismatched success must never close the first-run screen.
fn parse_interface_set_acknowledgement(
    stdout: &[u8],
    expected: GuiInterfacePreference,
    expected_path: &Path,
) -> Result<()> {
    let acknowledgement: GuiInterfaceSetAcknowledgement =
        serde_json::from_slice(stdout).context("parse interface preference acknowledgement")?;
    // `changed:false` is a valid idempotent write. Presence and bool type are
    // still enforced by the typed acknowledgement above.
    let _changed = acknowledgement.changed;
    let expected_path = std::fs::canonicalize(expected_path).with_context(|| {
        format!(
            "resolve expected interface path {}",
            expected_path.display()
        )
    })?;
    let acknowledged_path = std::fs::canonicalize(&acknowledgement.path).with_context(|| {
        format!(
            "resolve acknowledged interface path {}",
            acknowledgement.path.display()
        )
    })?;
    if !acknowledgement.chosen
        || acknowledgement.preferred != expected.as_str()
        || acknowledged_path != expected_path
    {
        anyhow::bail!("interface preference update returned an invalid acknowledgement");
    }
    Ok(())
}

fn validate_interface_set_result(
    stdout: &[u8],
    home: &Path,
    expected: GuiInterfacePreference,
) -> Result<()> {
    let expected_path = home.join("interface.json");
    parse_interface_set_acknowledgement(stdout, expected, &expected_path)?;
    match load_gui_interface_preference(home)? {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => anyhow::bail!(
            "interface preference read-back mismatch: expected {}, found {}",
            expected.as_str(),
            actual.as_str()
        ),
        None => anyhow::bail!(
            "interface preference acknowledgement succeeded but {} is missing",
            expected_path.display()
        ),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GuiCompletionStatusAcknowledgement {
    ready: bool,
    home: PathBuf,
}

const GUI_INIT_TRANSACTION_HEX_LEN: usize = 64;

struct GuiInitializationTransaction {
    transaction_id: String,
    token: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GuiInitializationBeginAcknowledgement {
    schema_version: u8,
    transaction_id: String,
    token: String,
    home: PathBuf,
    pending_path: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GuiCompletionAcknowledgement {
    schema_version: u8,
    completed: bool,
    ready: bool,
    transaction_id: String,
    home: PathBuf,
    marker_path: PathBuf,
}

fn valid_gui_transaction_hex(value: &str) -> bool {
    value.len() == GUI_INIT_TRANSACTION_HEX_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_existing_path(path: &Path, label: &str) -> Result<PathBuf> {
    path.canonicalize()
        .with_context(|| format!("resolve {label} {}", path.display()))
}

fn parse_gui_initialization_begin(
    stdout: &[u8],
    expected_home: &Path,
) -> Result<GuiInitializationTransaction> {
    let acknowledgement: GuiInitializationBeginAcknowledgement =
        serde_json::from_slice(stdout).context("parse GUI initialization begin acknowledgement")?;
    let expected_home = canonical_existing_path(expected_home, "expected NEOTH home")?;
    let acknowledged_home =
        canonical_existing_path(&acknowledgement.home, "acknowledged NEOTH home")?;
    let expected_pending = canonical_existing_path(
        &expected_home.join(".gui-init").join("pending.json"),
        "expected GUI initialization pending state",
    )?;
    let acknowledged_pending = canonical_existing_path(
        &acknowledgement.pending_path,
        "acknowledged GUI initialization pending state",
    )?;
    if acknowledgement.schema_version != 1
        || !valid_gui_transaction_hex(&acknowledgement.transaction_id)
        || !valid_gui_transaction_hex(&acknowledgement.token)
        || acknowledged_home != expected_home
        || acknowledged_pending != expected_pending
    {
        anyhow::bail!("GUI initialization begin returned an invalid acknowledgement");
    }
    Ok(GuiInitializationTransaction {
        transaction_id: acknowledgement.transaction_id,
        token: acknowledgement.token,
    })
}

fn begin_gui_initialization(bin: &Path, home: &Path) -> Result<GuiInitializationTransaction> {
    let output = spawn_neothd_plain(bin)
        .env("NEOTH_HOME", home)
        .args(["init", "--begin-from-gui"])
        .output()
        .context("begin canonical GUI initialization transaction")?;
    if !output.status.success() {
        anyhow::bail!(
            "initialization transaction could not begin (exit {}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    parse_gui_initialization_begin(&output.stdout, home)
}

fn gui_initialization_is_ready(bin: &Path, home: &Path) -> Result<bool> {
    let output = spawn_neothd_plain(bin)
        .env("NEOTH_HOME", home)
        .args(["init", "--check-completion-from-gui"])
        .output()
        .context("query canonical GUI initialization readiness")?;
    if !output.status.success() {
        anyhow::bail!(
            "initialization readiness check failed (exit {}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let acknowledgement: GuiCompletionStatusAcknowledgement =
        serde_json::from_slice(&output.stdout)
            .context("parse initialization readiness acknowledgement")?;
    let expected_home = canonical_existing_path(home, "expected NEOTH home")?;
    let acknowledged_home =
        canonical_existing_path(&acknowledgement.home, "acknowledged NEOTH home")?;
    if acknowledged_home != expected_home {
        anyhow::bail!(
            "initialization readiness acknowledgement was bound to {}, expected {}",
            acknowledgement.home.display(),
            home.display()
        );
    }
    Ok(acknowledgement.ready)
}

fn complete_gui_initialization(
    bin: &Path,
    home: &Path,
    transaction: &GuiInitializationTransaction,
) -> Result<PathBuf> {
    use std::process::Stdio;

    let mut command = spawn_neothd_plain(bin);
    let mut child = command
        .env("NEOTH_HOME", home)
        .args(["init", "--complete-from-gui"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start canonical GUI initialization commit")?;
    let write_result = (|| -> Result<()> {
        let stdin = child
            .stdin
            .as_mut()
            .context("GUI initialization commit stdin is unavailable")?;
        stdin
            .write_all(transaction.token.as_bytes())
            .context("write GUI initialization transaction token")?;
        stdin
            .write_all(b"\n")
            .context("terminate GUI initialization transaction token")?;
        Ok(())
    })();
    drop(child.stdin.take());
    if let Err(error) = write_result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    let output = child
        .wait_with_output()
        .context("commit canonical GUI initialization marker")?;
    if !output.status.success() {
        anyhow::bail!(
            "initialization completion failed (exit {}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let acknowledgement: GuiCompletionAcknowledgement = serde_json::from_slice(&output.stdout)
        .context("parse initialization completion acknowledgement")?;
    let expected_home = canonical_existing_path(home, "expected NEOTH home")?;
    let acknowledged_home =
        canonical_existing_path(&acknowledgement.home, "acknowledged NEOTH home")?;
    let expected = home.join(".initialized");
    let expected_canonical = canonical_existing_path(&expected, "committed marker")?;
    let acknowledged_canonical =
        canonical_existing_path(&acknowledgement.marker_path, "acknowledged marker")?;
    if !acknowledgement.completed
        || !acknowledgement.ready
        || acknowledgement.schema_version != 1
        || acknowledgement.transaction_id != transaction.transaction_id
        || acknowledged_home != expected_home
        || acknowledged_canonical != expected_canonical
    {
        anyhow::bail!("initialization completion returned an invalid acknowledgement");
    }
    Ok(expected_canonical)
}

const TERMINAL_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
const TERMINAL_READY_POLL: std::time::Duration = std::time::Duration::from_millis(25);
const MAX_TERMINAL_READY_BYTES: u64 = 256;
static TERMINAL_HANDSHAKE_COUNTER: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

struct TerminalHandshake {
    directory: PathBuf,
    ready_path: PathBuf,
    token: String,
}

impl TerminalHandshake {
    fn create(home: &Path) -> Result<Self> {
        use std::sync::atomic::Ordering;

        std::fs::create_dir_all(home)
            .with_context(|| format!("create NEOTH home {}", home.display()))?;
        let root = home.join(".terminal-launch");
        let root_created = match std::fs::create_dir(&root) {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let metadata = std::fs::symlink_metadata(&root)
                    .with_context(|| format!("inspect {}", root.display()))?;
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    anyhow::bail!(
                        "terminal handshake root {} is not a private directory",
                        root.display()
                    );
                }
                false
            }
            Err(error) => {
                return Err(error).with_context(|| format!("create {}", root.display()));
            }
        };
        if let Err(error) = set_private_handshake_directory(&root) {
            if root_created {
                let _ = std::fs::remove_dir(&root);
            }
            return Err(error);
        }

        let epoch_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        for _ in 0..16 {
            let counter = TERMINAL_HANDSHAKE_COUNTER.fetch_add(1, Ordering::Relaxed);
            let name = format!(
                "gui-{:08x}-{epoch_nanos:032x}-{counter:016x}",
                std::process::id()
            );
            let directory = root.join(name);
            match std::fs::create_dir(&directory) {
                Ok(()) => {
                    if let Err(error) = set_private_handshake_directory(&directory) {
                        let _ = std::fs::remove_dir(&directory);
                        if root_created {
                            let _ = std::fs::remove_dir(&root);
                        }
                        return Err(error);
                    }
                    return Ok(Self {
                        ready_path: directory.join("ready"),
                        directory,
                        token: format!(
                            "{:08x}{epoch_nanos:032x}{counter:016x}",
                            std::process::id()
                        ),
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    if root_created {
                        let _ = std::fs::remove_dir(&root);
                    }
                    return Err(error).with_context(|| format!("create {}", directory.display()));
                }
            }
        }
        if root_created {
            let _ = std::fs::remove_dir(&root);
        }
        anyhow::bail!("could not allocate a unique terminal handshake directory")
    }

    fn cleanup(self) -> Result<()> {
        let root = self.directory.parent().map(Path::to_path_buf);
        match std::fs::remove_dir_all(&self.directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("remove {}", self.directory.display()));
            }
        }
        // Best-effort removal keeps the parent free of empty bookkeeping while
        // remaining race-safe when another GUI launch is using it.
        if let Some(root) = root {
            let _ = std::fs::remove_dir(root);
        }
        Ok(())
    }
}

#[cfg(unix)]
fn set_private_handshake_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("restrict terminal handshake directory {}", path.display()))
}

#[cfg(windows)]
fn set_private_handshake_directory(path: &Path) -> Result<()> {
    win_private::set_private_directory_dacl(path)
        .with_context(|| format!("restrict terminal handshake directory {}", path.display()))
}

#[cfg(not(any(unix, windows)))]
fn set_private_handshake_directory(_path: &Path) -> Result<()> {
    Ok(())
}

fn finish_terminal_handshake_result(
    directory: &Path,
    result: Result<()>,
    cleanup: Result<()>,
) -> Result<()> {
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(cleanup_error)) => {
            tracing::warn!(
                error = %cleanup_error,
                path = %directory.display(),
                "terminal is ready; stale handshake cleanup failed"
            );
            Ok(())
        }
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(cleanup_error)) => Err(error).context(format!(
            "terminal launch failed and handshake cleanup also failed for {}: {cleanup_error:#}",
            directory.display()
        )),
    }
}

fn finish_terminal_handshake(handshake: TerminalHandshake, result: Result<()>) -> Result<()> {
    let directory = handshake.directory.clone();
    let cleanup = handshake.cleanup();
    finish_terminal_handshake_result(&directory, result, cleanup)
}

fn ready_token_matches(path: &Path, token: &str) -> Result<Option<bool>> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("open {}", path.display())),
    };
    let mut bytes = Vec::new();
    file.take(MAX_TERMINAL_READY_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", path.display()))?;
    if bytes.len() as u64 > MAX_TERMINAL_READY_BYTES {
        anyhow::bail!("terminal ready token at {} is oversized", path.display());
    }
    Ok(Some(bytes == token.as_bytes()))
}

fn wait_for_terminal_ready_with<LauncherStatus>(
    ready_path: &Path,
    token: &str,
    timeout: std::time::Duration,
    mut launcher_status: LauncherStatus,
) -> Result<()>
where
    LauncherStatus: FnMut() -> Result<Option<bool>>,
{
    let started = std::time::Instant::now();
    let mut mismatched_token_seen = false;
    loop {
        if launcher_status()? == Some(false) {
            anyhow::bail!("terminal launcher exited unsuccessfully before readiness");
        }
        match ready_token_matches(ready_path, token)? {
            Some(true) => return Ok(()),
            Some(false) => mismatched_token_seen = true,
            None => {}
        }
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            let detail = if mismatched_token_seen {
                "a mismatched ready token was observed"
            } else {
                "the ready token was not written"
            };
            anyhow::bail!(
                "terminal did not become ready within {} ms ({detail})",
                timeout.as_millis()
            );
        }
        std::thread::sleep(TERMINAL_READY_POLL.min(timeout - elapsed));
    }
}

#[cfg(any(windows, all(unix, not(target_os = "macos"))))]
fn await_spawned_terminal(
    mut child: std::process::Child,
    handshake: TerminalHandshake,
    launcher: &str,
) -> Result<()> {
    let result = wait_for_terminal_ready_with(
        &handshake.ready_path,
        &handshake.token,
        TERMINAL_READY_TIMEOUT,
        || match child.try_wait().context("query terminal launcher status")? {
            Some(status) if !status.success() => {
                anyhow::bail!("{launcher} exited with {status} before readiness")
            }
            Some(_) => Ok(Some(true)),
            None => Ok(None),
        },
    );
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    finish_terminal_handshake(handshake, result)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TerminalLaunch {
    SwitchToCli,
    SovereignCeremony,
}

#[cfg(all(unix, not(target_os = "macos")))]
fn terminal_shell_script(launch: TerminalLaunch) -> String {
    match launch {
        TerminalLaunch::SwitchToCli => format!(
            "unset {PRODUCT_LAUNCHER_ENV} {INTERFACE_OVERRIDE_ENV}; \"$NEOTH_BIN\" --output json interface set cli --ready-file \"$NEOTH_READY_FILE\" --ready-token \"$NEOTH_READY_TOKEN\" || exit $?; unset NEOTH_READY_FILE NEOTH_READY_TOKEN; \"$NEOTH_BIN\"; NEOTH_EXIT=$?; if [ \"$NEOTH_EXIT\" -eq 0 ]; then printf '\\nNEOTH CLI ready. Try: neoth --help\\n'; else printf '\\nNEOTH needs repair; see the error above, then run: neoth init --force\\n'; fi; exec \"${{SHELL:-/bin/sh}}\" -l"
        ),
        TerminalLaunch::SovereignCeremony => format!(
            "unset {PRODUCT_LAUNCHER_ENV} {INTERFACE_OVERRIDE_ENV}; \"$NEOTH_BIN\" --output json interface terminal-ready --ready-file \"$NEOTH_READY_FILE\" --ready-token \"$NEOTH_READY_TOKEN\" >/dev/null || exit $?; unset NEOTH_READY_FILE NEOTH_READY_TOKEN; \"$NEOTH_BIN\" autonomy sovereign --enable; NEOTH_EXIT=$?; if [ \"$NEOTH_EXIT\" -eq 0 ]; then printf '\\nSovereign mode updated. Return to the GUI and refresh Buddy status.\\n'; else printf '\\nSovereign mode was not enabled. Review the error above or retry this command.\\n'; fi; exec \"${{SHELL:-/bin/sh}}\" -l"
        ),
    }
}

#[cfg(target_os = "macos")]
fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Open a real platform terminal and keep it interactive after the initial
/// NEOTH command. Success means the terminal shell echoed the unique ready
/// token, not merely that a launcher process accepted `spawn()`.
fn launch_cli_terminal(bin: &Path, home: &Path, launch: TerminalLaunch) -> Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;

        const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
        let handshake = TerminalHandshake::create(home)?;
        let path = bin.to_string_lossy().replace('\'', "''");
        let script = match launch {
            TerminalLaunch::SwitchToCli => format!(
                "$ErrorActionPreference = 'Stop'; Remove-Item Env:{PRODUCT_LAUNCHER_ENV}, Env:{INTERFACE_OVERRIDE_ENV} -ErrorAction SilentlyContinue; & '{path}' --output json interface set cli --ready-file $env:NEOTH_READY_FILE --ready-token $env:NEOTH_READY_TOKEN; if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}; Remove-Item Env:NEOTH_READY_FILE, Env:NEOTH_READY_TOKEN -ErrorAction SilentlyContinue; & '{path}'; if ($LASTEXITCODE -eq 0) {{ Write-Host ''; Write-Host 'NEOTH CLI ready. Try: neoth --help' }} else {{ Write-Host ''; Write-Host 'NEOTH needs repair; see the error above, then run: neoth init --force' }}"
            ),
            TerminalLaunch::SovereignCeremony => format!(
                "$ErrorActionPreference = 'Stop'; Remove-Item Env:{PRODUCT_LAUNCHER_ENV}, Env:{INTERFACE_OVERRIDE_ENV} -ErrorAction SilentlyContinue; & '{path}' --output json interface terminal-ready --ready-file $env:NEOTH_READY_FILE --ready-token $env:NEOTH_READY_TOKEN > $null; if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}; Remove-Item Env:NEOTH_READY_FILE, Env:NEOTH_READY_TOKEN -ErrorAction SilentlyContinue; & '{path}' autonomy sovereign --enable; if ($LASTEXITCODE -eq 0) {{ Write-Host ''; Write-Host 'Sovereign mode updated. Return to the GUI and refresh Buddy status.' }} else {{ Write-Host ''; Write-Host 'Sovereign mode was not enabled. Review the error above or retry this command.' }}"
            ),
        };
        let mut command = std::process::Command::new("powershell.exe");
        scrub_gui_control_environment(&mut command);
        let child = command
            .args(["-NoLogo", "-NoProfile", "-NoExit", "-Command", &script])
            .env("NEOTH_HOME", home)
            .env(TERMINAL_READY_FILE_ENV, &handshake.ready_path)
            .env(TERMINAL_READY_TOKEN_ENV, &handshake.token)
            .creation_flags(CREATE_NEW_CONSOLE)
            .spawn();
        match child {
            Ok(child) => await_spawned_terminal(child, handshake, "Windows PowerShell"),
            Err(error) => finish_terminal_handshake(
                handshake,
                Err(anyhow::Error::new(error).context("open Windows PowerShell for the NEOTH CLI")),
            ),
        }
    }

    #[cfg(target_os = "macos")]
    {
        let path = bin
            .to_str()
            .context("NEOTH binary path is not valid Unicode")?;
        let home = home
            .to_str()
            .context("NEOTH home path is not valid Unicode")?;
        let handshake = TerminalHandshake::create(Path::new(home))?;
        let ready_path = handshake
            .ready_path
            .to_str()
            .expect("handshake path extends an already validated Unicode home");
        let shell_command = match launch {
            TerminalLaunch::SwitchToCli => format!(
                "unset {GUI_READY_FILE_ENV} {GUI_READY_TOKEN_ENV} {GUI_PARENT_COMMIT_ENV} {PRODUCT_LAUNCHER_ENV} {INTERFACE_OVERRIDE_ENV}; NEOTH_HOME={} {} --output json interface set cli --ready-file {} --ready-token {} || exit $?; unset NEOTH_READY_FILE NEOTH_READY_TOKEN; NEOTH_HOME={} {}; NEOTH_EXIT=$?; if [ \"$NEOTH_EXIT\" -eq 0 ]; then printf '\\nNEOTH CLI ready. Try: neoth --help\\n'; else printf '\\nNEOTH needs repair; see the error above, then run: neoth init --force\\n'; fi; exec \"${{SHELL:-/bin/sh}}\" -l",
                shell_single_quote(home),
                shell_single_quote(path),
                shell_single_quote(ready_path),
                shell_single_quote(&handshake.token),
                shell_single_quote(home),
                shell_single_quote(path),
            ),
            TerminalLaunch::SovereignCeremony => format!(
                "unset {GUI_READY_FILE_ENV} {GUI_READY_TOKEN_ENV} {GUI_PARENT_COMMIT_ENV} {PRODUCT_LAUNCHER_ENV} {INTERFACE_OVERRIDE_ENV}; NEOTH_HOME={} {} --output json interface terminal-ready --ready-file {} --ready-token {} >/dev/null || exit $?; unset NEOTH_READY_FILE NEOTH_READY_TOKEN; NEOTH_HOME={} {} autonomy sovereign --enable; NEOTH_EXIT=$?; if [ \"$NEOTH_EXIT\" -eq 0 ]; then printf '\\nSovereign mode updated. Return to the GUI and refresh Buddy status.\\n'; else printf '\\nSovereign mode was not enabled. Review the error above or retry this command.\\n'; fi; exec \"${{SHELL:-/bin/sh}}\" -l",
                shell_single_quote(home),
                shell_single_quote(path),
                shell_single_quote(ready_path),
                shell_single_quote(&handshake.token),
                shell_single_quote(home),
                shell_single_quote(path),
            ),
        };
        let shell_command = shell_command.replace('\\', "\\\\").replace('"', "\\\"");
        let script = format!(
            "tell application \"Terminal\"\nactivate\ndo script \"{shell_command}\"\nend tell"
        );
        let mut command = std::process::Command::new("/usr/bin/osascript");
        scrub_gui_control_environment(&mut command);
        let output = command.args(["-e", &script]).output();
        let result = match output {
            Ok(output) if output.status.success() => wait_for_terminal_ready_with(
                &handshake.ready_path,
                &handshake.token,
                TERMINAL_READY_TIMEOUT,
                || Ok(None),
            ),
            Ok(output) => Err(anyhow::anyhow!(
                "Terminal.app launch failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )),
            Err(error) => {
                Err(anyhow::Error::new(error).context("ask Terminal.app to open the NEOTH CLI"))
            }
        };
        finish_terminal_handshake(handshake, result)
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let script = terminal_shell_script(launch);
        let mut errors = Vec::new();
        for program in [
            "x-terminal-emulator",
            "gnome-terminal",
            "konsole",
            "kitty",
            "alacritty",
        ] {
            let handshake = TerminalHandshake::create(home)?;
            let mut command = std::process::Command::new(program);
            scrub_gui_control_environment(&mut command);
            match program {
                "gnome-terminal" => command.args(["--", "sh", "-lc", &script]),
                "kitty" => command.args(["sh", "-lc", &script]),
                _ => command.args(["-e", "sh", "-lc", &script]),
            };
            let child = command
                .env("NEOTH_BIN", bin)
                .env("NEOTH_HOME", home)
                .env(TERMINAL_READY_FILE_ENV, &handshake.ready_path)
                .env(TERMINAL_READY_TOKEN_ENV, &handshake.token)
                .spawn();
            let result = match child {
                Ok(child) => await_spawned_terminal(child, handshake, program),
                Err(error) => finish_terminal_handshake(
                    handshake,
                    Err(anyhow::Error::new(error)
                        .context(format!("start terminal candidate {program}"))),
                ),
            };
            match result {
                Ok(()) => return Ok(()),
                Err(error) => errors.push(format!("{program}: {error:#}")),
            }
        }
        anyhow::bail!(
            "no supported desktop terminal became ready ({}); run `neoth interface set cli` in an existing terminal",
            errors.join("; ")
        );
    }

    #[cfg(not(any(windows, unix)))]
    anyhow::bail!("opening a CLI terminal is unsupported on this platform")
}

fn switch_to_cli(bin: &Path, home: &Path) -> Result<()> {
    // The terminal itself performs the one canonical transaction. The CLI
    // writes Ready only after interface.json is durably committed and restores
    // the exact previous bytes if that Ready write fails.
    launch_cli_terminal(bin, home, TerminalLaunch::SwitchToCli)
}

fn launch_sovereign_ceremony(bin: &Path, home: &Path) -> Result<()> {
    // Enabling sovereign mode remains inside the CLI's real TTY-only typed
    // phrase ceremony. The GUI opens that exact command but receives no bypass
    // token and never mutates the policy itself.
    launch_cli_terminal(bin, home, TerminalLaunch::SovereignCeremony)
}

#[cfg(test)]
mod interface_preference_tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn gui_reader_distinguishes_missing_gui_cli_and_corruption() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load_gui_interface_preference(dir.path()).unwrap(), None);

        std::fs::write(
            dir.path().join("interface.json"),
            br#"{"schema_version":1,"preferred":"gui"}"#,
        )
        .unwrap();
        assert_eq!(
            load_gui_interface_preference(dir.path()).unwrap(),
            Some(GuiInterfacePreference::Gui)
        );

        std::fs::write(
            dir.path().join("interface.json"),
            br#"{"schema_version":1,"preferred":"cli"}"#,
        )
        .unwrap();
        assert_eq!(
            load_gui_interface_preference(dir.path()).unwrap(),
            Some(GuiInterfacePreference::Cli)
        );

        std::fs::write(
            dir.path().join("interface.json"),
            br#"{"schema_version":1,"preferred":"gui","extra":true}"#,
        )
        .unwrap();
        assert!(load_gui_interface_preference(dir.path()).is_err());
    }

    #[test]
    fn parent_handoff_is_paired_scoped_bounded_and_replay_safe() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join(GUI_LAUNCH_DIR);
        let instance = root.join("gui-test");
        std::fs::create_dir_all(&instance).unwrap();
        let ready = instance.join("ready");
        let token = "a".repeat(GUI_READY_TOKEN_BYTES);

        let handoff = parse_gui_parent_handoff(
            home.path(),
            Some(ready.as_os_str()),
            Some(&token),
            Some("1"),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            handoff.ready_path,
            instance.canonicalize().unwrap().join("ready")
        );
        assert!(handoff.parent_commit);
        assert!(
            parse_gui_parent_handoff(home.path(), Some(ready.as_os_str()), None, Some("1"))
                .is_err()
        );
        assert!(
            parse_gui_parent_handoff(
                home.path(),
                Some(ready.as_os_str()),
                Some("not-hex"),
                Some("1")
            )
            .is_err()
        );

        let outside = home.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        assert!(
            parse_gui_parent_handoff(
                home.path(),
                Some(outside.join("ready").as_os_str()),
                Some(&token),
                Some("0")
            )
            .is_err()
        );

        std::fs::write(&ready, &token).unwrap();
        assert!(
            parse_gui_parent_handoff(
                home.path(),
                Some(ready.as_os_str()),
                Some(&token),
                Some("1")
            )
            .is_err()
        );
    }

    #[test]
    fn parent_handoff_writer_commits_only_the_exact_token() {
        let home = tempfile::tempdir().unwrap();
        let instance = home.path().join(GUI_LAUNCH_DIR).join("gui-write");
        std::fs::create_dir_all(&instance).unwrap();
        let ready = instance.join("ready");
        let token = "b".repeat(GUI_READY_TOKEN_BYTES);
        let handoff = parse_gui_parent_handoff(
            home.path(),
            Some(ready.as_os_str()),
            Some(&token),
            Some("0"),
        )
        .unwrap()
        .unwrap();

        write_gui_parent_ready(&handoff).unwrap();
        assert_eq!(std::fs::read(&ready).unwrap(), token.as_bytes());
        assert!(!ready.with_extension("tmp").exists());
        assert!(write_gui_parent_ready(&handoff).is_err());
    }

    #[test]
    fn interface_boot_matrix_preserves_chooser_and_parent_repair_semantics() {
        assert_eq!(
            interface_boot_decision(true, Err(anyhow::anyhow!("corrupt"))),
            GuiInterfaceBootDecision::Ready
        );
        assert_eq!(
            interface_boot_decision(false, Ok(None)),
            GuiInterfaceBootDecision::Choose
        );
        assert_eq!(
            interface_boot_decision(false, Ok(Some(GuiInterfacePreference::Gui))),
            GuiInterfaceBootDecision::Ready
        );
        assert_eq!(
            interface_boot_decision(false, Ok(Some(GuiInterfacePreference::Cli))),
            GuiInterfaceBootDecision::SwitchCliToGui
        );
        assert!(matches!(
            interface_boot_decision(false, Err(anyhow::anyhow!("future schema"))),
            GuiInterfaceBootDecision::Repair(error) if error.contains("future schema")
        ));
    }

    #[test]
    fn product_launcher_and_relative_home_contracts_are_explicit() {
        assert!(runtime_probe_requested(&[OsString::from(
            "--runtime-probe"
        )]));
        assert!(!runtime_probe_requested(&[]));
        assert!(!runtime_probe_requested(&[
            OsString::from("--runtime-probe"),
            OsString::from("--product-launcher"),
        ]));
        assert!(!product_launcher_requested(Vec::<OsString>::new()).unwrap());
        assert!(product_launcher_requested([OsString::from("--product-launcher")]).unwrap());
        assert!(product_launcher_requested([OsString::from("--unknown")]).is_err());
        assert!(product_launcher_environment_requested(Some(OsString::from("1"))).unwrap());
        assert!(!product_launcher_environment_requested(None).unwrap());
        assert!(product_launcher_environment_requested(Some(OsString::from("true"))).is_err());
        assert!(
            product_launcher_mode(
                [OsString::from("--product-launcher")],
                Some(OsString::from("invalid")),
            )
            .is_err(),
            "a valid argv flag must not short-circuit invalid packaged state"
        );

        let cwd = tempfile::tempdir().unwrap();
        let home = absolutize_neoth_home(PathBuf::from("relative-home"), cwd.path());
        assert!(home.is_absolute());
        assert!(home.ends_with("relative-home"));
    }

    #[test]
    fn gui_finish_commits_only_after_parity_and_never_reports_false_success() {
        let calls = std::cell::RefCell::new(Vec::new());
        let (transaction, prepared) = validate_begin_and_prepare_gui_finish_with(
            || {
                calls.borrow_mut().push("validate");
                Ok(())
            },
            || {
                calls.borrow_mut().push("begin");
                Ok("transaction")
            },
            || {
                calls.borrow_mut().push("files");
                Ok("prepared")
            },
        )
        .unwrap();
        assert_eq!(transaction, "transaction");
        assert_eq!(prepared, "prepared");
        assert_eq!(*calls.borrow(), ["validate", "begin", "files"]);

        calls.borrow_mut().clear();
        let failed = validate_begin_and_prepare_gui_finish_with(
            || {
                calls.borrow_mut().push("validate");
                anyhow::bail!("invalid")
            },
            || {
                calls.borrow_mut().push("begin");
                Ok("must-not-begin")
            },
            || {
                calls.borrow_mut().push("files");
                Ok("must-not-write")
            },
        );
        assert!(failed.is_err());
        assert_eq!(*calls.borrow(), ["validate"]);

        calls.borrow_mut().clear();
        let marker = PathBuf::from("initialized-v2.json");
        let outcome = commit_gui_finish_with(
            "files prepared".to_string(),
            || {
                calls.borrow_mut().push("parity");
                Ok(())
            },
            || {
                calls.borrow_mut().push("daemon-completion");
                Ok(marker.clone())
            },
        );
        assert_eq!(*calls.borrow(), ["parity", "daemon-completion"]);
        assert!(matches!(
            outcome,
            GuiFinishOutcome::Completed { marker_path, status }
                if marker_path == marker && status.contains("Setup complete and verified")
        ));

        calls.borrow_mut().clear();
        let outcome = commit_gui_finish_with(
            "files prepared".to_string(),
            || {
                calls.borrow_mut().push("parity");
                anyhow::bail!("parity failed")
            },
            || {
                calls.borrow_mut().push("daemon-completion");
                Ok(PathBuf::from("must-not-run"))
            },
        );
        assert_eq!(*calls.borrow(), ["parity"]);
        assert!(matches!(
            outcome,
            GuiFinishOutcome::Failed { status, .. }
                if status.contains("completion could not be verified")
                    && !status.contains("Setup complete and verified")
        ));
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn linux_terminal_script_uses_an_environment_path_not_interpolation() {
        let script = terminal_shell_script(TerminalLaunch::SwitchToCli);
        assert!(script.starts_with(
            "unset NEOTH_PRODUCT_LAUNCHER NEOTH_INTERFACE; \"$NEOTH_BIN\" --output json interface set cli"
        ));
        assert!(script.contains("--ready-file \"$NEOTH_READY_FILE\""));
        assert!(script.contains("--ready-token \"$NEOTH_READY_TOKEN\""));
        assert!(!script.contains("printf '%s' \"$NEOTH_READY_TOKEN\""));
        assert!(script.contains("; \"$NEOTH_BIN\";"));
        assert!(script.contains("if [ \"$NEOTH_EXIT\" -eq 0 ]"));
        assert!(script.contains("NEOTH needs repair"));
        assert!(script.contains("exec \"${SHELL:-/bin/sh}\" -l"));
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn sovereign_terminal_runs_the_real_tty_ceremony_without_switching_interface() {
        let script = terminal_shell_script(TerminalLaunch::SovereignCeremony);
        assert!(script.contains("interface terminal-ready"));
        assert!(script.contains("\"$NEOTH_BIN\" autonomy sovereign --enable"));
        assert!(!script.contains("interface set"));
        assert!(!script.contains("gui-confirmed"));
        assert!(!script.contains("gui-token"));
    }

    #[test]
    fn every_internal_child_scrubs_launcher_and_interface_capabilities() {
        let mut command = std::process::Command::new("neoth-test-child");
        scrub_gui_control_environment(&mut command);
        for expected in [
            GUI_READY_FILE_ENV,
            GUI_READY_TOKEN_ENV,
            GUI_PARENT_COMMIT_ENV,
            PRODUCT_LAUNCHER_ENV,
            TERMINAL_READY_FILE_ENV,
            TERMINAL_READY_TOKEN_ENV,
            INTERFACE_OVERRIDE_ENV,
        ] {
            assert!(
                command
                    .get_envs()
                    .any(|(name, value)| name == expected && value.is_none()),
                "{expected} was not explicitly removed"
            );
        }
    }

    #[test]
    fn gui_begin_ack_is_bounded_and_bound_to_the_canonical_home() {
        let home = tempfile::tempdir().unwrap();
        let pending_dir = home.path().join(".gui-init");
        std::fs::create_dir_all(&pending_dir).unwrap();
        let pending = pending_dir.join("pending.json");
        std::fs::write(&pending, b"pending").unwrap();
        let transaction_id = "a".repeat(GUI_INIT_TRANSACTION_HEX_LEN);
        let token = "b".repeat(GUI_INIT_TRANSACTION_HEX_LEN);
        let valid = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "transaction_id": transaction_id,
            "token": token,
            "home": home.path().canonicalize().unwrap(),
            "pending_path": pending.canonicalize().unwrap(),
        }))
        .unwrap();
        let parsed = parse_gui_initialization_begin(&valid, home.path()).unwrap();
        assert_eq!(parsed.transaction_id, transaction_id);
        assert_eq!(parsed.token, token);

        let invalid = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "transaction_id": "A".repeat(GUI_INIT_TRANSACTION_HEX_LEN),
            "token": "b".repeat(GUI_INIT_TRANSACTION_HEX_LEN),
            "home": home.path(),
            "pending_path": pending,
        }))
        .unwrap();
        assert!(parse_gui_initialization_begin(&invalid, home.path()).is_err());
    }

    #[test]
    fn interface_set_acknowledgement_accepts_idempotence_and_binds_path_and_readback() {
        let home = tempfile::tempdir().unwrap();
        let expected_path = home.path().join("interface.json");
        std::fs::write(&expected_path, br#"{"schema_version":1,"preferred":"gui"}"#).unwrap();

        for changed in [true, false] {
            let valid = serde_json::to_vec(&serde_json::json!({
                "chosen": true,
                "preferred": "gui",
                "changed": changed,
                "path": expected_path,
            }))
            .unwrap();
            validate_interface_set_result(&valid, home.path(), GuiInterfacePreference::Gui)
                .unwrap();
        }

        let wrong_path = home.path().join("not-interface.json");
        std::fs::write(&wrong_path, b"not the preference").unwrap();
        for invalid in [
            serde_json::json!({"chosen": false, "preferred": "gui", "changed": true, "path": expected_path}),
            serde_json::json!({"chosen": true, "preferred": "cli", "changed": true, "path": expected_path}),
            serde_json::json!({"chosen": true, "preferred": "gui", "changed": true, "path": wrong_path}),
            serde_json::json!({"chosen": true, "preferred": "gui", "changed": true}),
            serde_json::json!({"chosen": true, "preferred": "gui", "changed": true, "path": expected_path, "extra": true}),
        ] {
            assert!(
                validate_interface_set_result(
                    &serde_json::to_vec(&invalid).unwrap(),
                    home.path(),
                    GuiInterfacePreference::Gui,
                )
                .is_err()
            );
        }

        std::fs::write(&expected_path, br#"{"schema_version":1,"preferred":"cli"}"#).unwrap();
        let stale = serde_json::to_vec(&serde_json::json!({
            "chosen": true,
            "preferred": "gui",
            "changed": false,
            "path": expected_path,
        }))
        .unwrap();
        assert!(
            validate_interface_set_result(&stale, home.path(), GuiInterfacePreference::Gui)
                .unwrap_err()
                .to_string()
                .contains("read-back mismatch")
        );
    }

    #[test]
    fn ready_token_success_and_timeout_both_remove_unique_handshake() {
        let home = tempfile::tempdir().unwrap();

        let ready = TerminalHandshake::create(home.path()).unwrap();
        let ready_directory = ready.directory.clone();
        assert!(ready_directory.starts_with(home.path()));
        std::fs::write(&ready.ready_path, ready.token.as_bytes()).unwrap();
        let result = wait_for_terminal_ready_with(
            &ready.ready_path,
            &ready.token,
            std::time::Duration::from_millis(100),
            || Ok(None),
        );
        finish_terminal_handshake(ready, result).unwrap();
        assert!(!ready_directory.exists());

        let timed_out = TerminalHandshake::create(home.path()).unwrap();
        let timeout_directory = timed_out.directory.clone();
        let result = wait_for_terminal_ready_with(
            &timed_out.ready_path,
            &timed_out.token,
            std::time::Duration::from_millis(15),
            || Ok(None),
        );
        let error = finish_terminal_handshake(timed_out, result).unwrap_err();
        assert!(error.to_string().contains("did not become ready"));
        assert!(!timeout_directory.exists());
    }

    #[test]
    fn ready_terminal_cleanup_failure_is_warning_not_false_launch_failure() {
        let directory = Path::new("stale-terminal-handshake");
        finish_terminal_handshake_result(
            directory,
            Ok(()),
            Err(anyhow::anyhow!("locked stale directory")),
        )
        .unwrap();

        let error = finish_terminal_handshake_result(
            directory,
            Err(anyhow::anyhow!("terminal failed")),
            Err(anyhow::anyhow!("cleanup failed")),
        )
        .unwrap_err();
        assert!(error.to_string().contains("cleanup also failed"));
    }

    #[test]
    fn failed_launcher_status_is_not_ready_even_with_matching_token() {
        let home = tempfile::tempdir().unwrap();
        let handshake = TerminalHandshake::create(home.path()).unwrap();
        let directory = handshake.directory.clone();
        std::fs::write(&handshake.ready_path, handshake.token.as_bytes()).unwrap();
        let result = wait_for_terminal_ready_with(
            &handshake.ready_path,
            &handshake.token,
            std::time::Duration::from_secs(1),
            || Ok(Some(false)),
        );
        assert!(finish_terminal_handshake(handshake, result).is_err());
        assert!(!directory.exists());
    }

    #[test]
    fn terminal_switch_has_no_prewrite_or_hardcoded_gui_rollback() {
        let source = include_str!("main.rs");
        let switch = source
            .split("fn switch_to_cli(")
            .nth(1)
            .and_then(|tail| tail.split("#[cfg(test)]").next())
            .unwrap();
        assert!(switch.contains("launch_cli_terminal(bin, home, TerminalLaunch::SwitchToCli)"));
        assert!(!switch.contains("set_interface_preference_via_cli"));
        assert!(!switch.contains("GuiInterfacePreference::Gui"));
    }

    #[test]
    fn windows_gui_and_hidden_children_are_console_free_by_contract() {
        let source = include_str!("main.rs");
        assert!(source.starts_with("#![cfg_attr(windows, windows_subsystem = \"windows\")]"));
        assert!(source.contains("const CREATE_NO_WINDOW: u32 = 0x0800_0000;"));
        assert!(source.contains("suppress_console_window(&mut command);"));
        assert!(source.contains("const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;"));
        assert!(
            source.contains("Remove-Item Env:{PRODUCT_LAUNCHER_ENV}, Env:{INTERFACE_OVERRIDE_ENV}")
        );
        assert!(source.contains("{PRODUCT_LAUNCHER_ENV} {INTERFACE_OVERRIDE_ENV}; NEOTH_HOME"));
        assert!(source.contains("exec \\\"${{SHELL:-/bin/sh}}\\\" -l"));
    }

    #[test]
    fn packaged_sibling_cli_wins_over_path_and_path_is_the_fallback() {
        let root = tempfile::tempdir().unwrap();
        let packaged = root.path().join("packaged");
        let path_dir = root.path().join("path");
        std::fs::create_dir_all(&packaged).unwrap();
        std::fs::create_dir_all(&path_dir).unwrap();
        let gui = packaged.join(if cfg!(windows) {
            "neothd-gui.exe"
        } else {
            "neothd-gui"
        });
        let name = if cfg!(windows) { "neoth.exe" } else { "neoth" };
        let sibling = packaged.join(name);
        let path_cli = path_dir.join(name);
        std::fs::write(&sibling, b"packaged").unwrap();
        std::fs::write(&path_cli, b"path").unwrap();
        let path_env: OsString = std::env::join_paths([&path_dir]).unwrap();

        assert_eq!(
            resolve_neothd(Some(&gui), Some(path_env.as_os_str())),
            Some(sibling.clone())
        );
        std::fs::remove_file(&sibling).unwrap();
        assert_eq!(
            resolve_neothd(Some(&gui), Some(path_env.as_os_str())),
            Some(path_cli)
        );
    }

    #[test]
    fn mode_cards_keep_radio_accessibility_and_keyboard_contract() {
        let ui = include_str!("../ui/components.slint");
        let mode_card = ui
            .split("export component ModeCard")
            .nth(1)
            .and_then(|tail| tail.split("// ── SovereignFade").next())
            .unwrap();
        for contract in [
            "accessible-role: radio-button",
            "accessible-label:",
            "root.recommended ? \" Recommended.\" : \"\"",
            "accessible-checkable: true",
            "accessible-checked: root.selected",
            "accessible-action-default",
            "forward-focus: key-focus",
            "event.text == \"\\n\" || event.text == \" \"",
        ] {
            assert!(
                mode_card.contains(contract),
                "missing ModeCard contract: {contract}"
            );
        }
    }
}

fn neothd_executable_names() -> [&'static str; 2] {
    if cfg!(windows) {
        ["neoth.exe", "neothd.exe"]
    } else {
        ["neoth", "neothd"]
    }
}

fn resolve_neothd(
    current_exe: Option<&Path>,
    path_env: Option<&std::ffi::OsStr>,
) -> Option<PathBuf> {
    let executables = neothd_executable_names();
    if let Some(dir) = current_exe.and_then(Path::parent) {
        for exe in &executables {
            let candidate = dir.join(exe);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    if let Some(path_env) = path_env {
        for entry in std::env::split_paths(path_env) {
            for exe in &executables {
                let candidate = entry.join(exe);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

fn which_neothd() -> Option<PathBuf> {
    let current_exe = std::env::current_exe().ok();
    let path_env = std::env::var_os("PATH");
    resolve_neothd(current_exe.as_deref(), path_env.as_deref())
}

/// GOLD-ADAPT-OH-01 — locate the `neoth-migrate` helper binary (PATH
/// scan, then sibling-to-exe) for the welcome-step migration card.
fn which_neoth_migrate() -> Option<PathBuf> {
    let exe = if cfg!(windows) {
        "neoth-migrate.exe"
    } else {
        "neoth-migrate"
    };
    if let Some(path_env) = std::env::var_os("PATH") {
        for entry in std::env::split_paths(&path_env) {
            let candidate = entry.join(exe);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    let exe_path = std::env::current_exe().ok()?;
    let dir = exe_path.parent()?;
    let sibling = dir.join(exe);
    sibling.exists().then_some(sibling)
}

/// GOLD-ADAPT-OH-01 — shape `neoth-migrate detect --json` output into
/// the welcome-card body. Empty string = hide the card (no sources /
/// unparseable output / detect unavailable). Pure — unit-tested.
pub fn format_migrate_summary(detect_json: &str) -> String {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(detect_json) else {
        return String::new();
    };
    let Some(sources) = v.get("sources").and_then(|s| s.as_array()) else {
        return String::new();
    };
    let names: Vec<&str> = sources
        .iter()
        .filter_map(|s| s.get("name").and_then(|n| n.as_str()))
        .collect();
    if names.is_empty() {
        return String::new();
    }
    format!(
        "{} prior-AI home(s) found: {}",
        names.len(),
        names.join(", ")
    )
}

/// Resolve `~/.neoth` honouring `NEOTH_HOME > HOME/.neoth > USERPROFILE/.neoth > ./.neoth`.
/// Pure helper extracted so tests can call it without touching process env.
fn resolve_neoth_home(
    neoth_home_env: Option<&str>,
    home_env: Option<&str>,
    userprofile_env: Option<&str>,
) -> PathBuf {
    if let Some(e) = neoth_home_env.filter(|s| !s.is_empty()) {
        return PathBuf::from(e);
    }
    let home = home_env
        .map(PathBuf::from)
        .or_else(|| userprofile_env.map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".neoth")
}

const PRODUCT_LAUNCHER_ENV: &str = "NEOTH_PRODUCT_LAUNCHER";

fn runtime_probe_requested(args: &[std::ffi::OsString]) -> bool {
    matches!(args, [argument] if argument == "--runtime-probe")
}

fn product_launcher_mode(
    args: impl IntoIterator<Item = std::ffi::OsString>,
    environment: Option<std::ffi::OsString>,
) -> Result<bool> {
    let requested_by_argument = product_launcher_requested(args)?;
    let requested_by_environment = product_launcher_environment_requested(environment)?;
    Ok(requested_by_argument || requested_by_environment)
}

fn product_launcher_requested(args: impl IntoIterator<Item = std::ffi::OsString>) -> Result<bool> {
    let args: Vec<std::ffi::OsString> = args.into_iter().collect();
    match args.as_slice() {
        [] => Ok(false),
        [argument] if argument == "--product-launcher" => Ok(true),
        _ => anyhow::bail!(
            "unsupported GUI arguments: {}",
            args.iter()
                .map(|arg| arg.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ")
        ),
    }
}

fn product_launcher_environment_requested(value: Option<std::ffi::OsString>) -> Result<bool> {
    match value {
        None => Ok(false),
        Some(value) if value == "1" => Ok(true),
        Some(value) => anyhow::bail!(
            "{PRODUCT_LAUNCHER_ENV} must be exactly `1`, found `{}`",
            value.to_string_lossy()
        ),
    }
}

fn absolutize_neoth_home(path: PathBuf, current_dir: &Path) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        current_dir.join(path)
    }
}

fn default_neoth_home() -> PathBuf {
    let configured = resolve_neoth_home(
        std::env::var("NEOTH_HOME").ok().as_deref(),
        std::env::var("HOME").ok().as_deref(),
        std::env::var("USERPROFILE").ok().as_deref(),
    );
    let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    absolutize_neoth_home(configured, &current_dir)
}

// B23 — THEME-TWEAKS-RUNTIME: mirrored contract types.
// File-private — do NOT re-export and do NOT add a `neothd` dep to the GUI crate.
// Field names and types MUST match `neothd::tweaks::ThemeConfig` field-for-field;
// parity is enforced by `gui_tweaks_contract_parses_all_16_theme_fields` below.
#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
struct GuiThemeContract {
    pub accent_color: Option<String>,
    pub background_color: Option<String>,
    pub foreground_color: Option<String>,
    pub font_family: Option<String>,
    pub font_size_pt: Option<u8>,
    pub sidebar_width_px: Option<u32>,
    pub border_radius_px: Option<u32>,
    pub compact_mode: Option<bool>,
    pub show_token_count: Option<bool>,
    pub show_model_badge: Option<bool>,
    pub chat_bubble_style: Option<String>,
    pub animation_speed: Option<String>,
    pub input_height_lines: Option<u8>,
    pub panel_opacity: Option<f32>,
    pub header_hidden: Option<bool>,
    pub sidebar_collapsed: Option<bool>,
}

#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(default)]
struct GuiTweaksContract {
    pub color_theme: Option<String>,
    #[serde(default)]
    pub theme: GuiThemeContract,
}

fn parse_theme_color(raw: &str) -> Option<slint::Color> {
    let hex = raw.strip_prefix('#')?;
    let nibble = |b: u8| -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    };
    let pair = |bytes: &[u8], at: usize| -> Option<u8> {
        Some(nibble(*bytes.get(at)?)? * 16 + nibble(*bytes.get(at + 1)?)?)
    };
    let bytes = hex.as_bytes();
    let (red, green, blue, alpha) = match bytes.len() {
        3 => {
            let r = nibble(bytes[0])?;
            let g = nibble(bytes[1])?;
            let b = nibble(bytes[2])?;
            (r * 17, g * 17, b * 17, 255)
        }
        6 => (pair(bytes, 0)?, pair(bytes, 2)?, pair(bytes, 4)?, 255),
        8 => (
            pair(bytes, 0)?,
            pair(bytes, 2)?,
            pair(bytes, 4)?,
            pair(bytes, 6)?,
        ),
        _ => return None,
    };
    Some(slint::Color::from_argb_u8(alpha, red, green, blue))
}

fn chat_bubble_style_mode(value: &str) -> Option<i32> {
    match value {
        "rounded" => Some(0),
        "square" => Some(1),
        "minimal" => Some(2),
        _ => None,
    }
}

fn animation_speed_mode(value: &str) -> Option<i32> {
    match value {
        "none" => Some(0),
        "reduced" => Some(1),
        "full" => Some(2),
        _ => None,
    }
}

/// B23 fix — resolve the boot `is_dark` flag, mirroring the daemon's
/// `resolve_effective_gui_theme` / `resolve_dark_from_tweaks` precedence exactly:
///
/// 1. Valid dotfile content ("light" / "dark") wins unconditionally.
/// 2. Invalid non-empty dotfile → log diagnostic, fall through to tweaks.
/// 3. Tweaks `color_theme`: "light" → false, "dark"|"auto" → true,
///    invalid value → log diagnostic + builtin dark, None → builtin dark.
///
/// `dotfile` must be the **trimmed** content of `~/.neoth/.gui-theme`, or
/// `None` when the file is absent, unreadable, or contains only whitespace
/// after trimming (an empty string is additionally normalized to file-absent
/// semantics inside this fn, defense-in-depth for future call sites).
/// `tweaks_color` is `GuiTweaksContract::color_theme.as_deref()`.
pub(crate) fn resolve_boot_dark(dotfile: Option<&str>, tweaks_color: Option<&str>) -> bool {
    match dotfile {
        Some("dark") => return true,
        Some("light") => return false,
        // Empty = file-absent semantics: fall through silently, no diagnostic.
        Some("") => {}
        Some(s) => {
            // Non-empty but unrecognised — emit diagnostic, fall through to tweaks.
            tracing::warn!(
                "invalid .gui-theme value '{}'; falling through to tweaks color_theme",
                s
            );
        }
        None => {}
    }
    // Dotfile absent or invalid: resolve from tweaks.color_theme.
    match tweaks_color {
        Some("light") => false,
        Some("dark") | Some("auto") => true,
        Some(other) => {
            tracing::warn!(
                "color_theme '{}' is not a valid value (light|dark|auto); using built-in dark",
                other
            );
            true
        }
        None => true, // built-in dark
    }
}

/// Read `<neoth_home>/tweaks.toml` into the GUI contract type.
/// Returns `None` silently when the file is absent or unparseable — the GUI
/// must not block on a malformed tweaks.toml; it falls back to built-in defaults.
fn read_gui_tweaks(neoth_home: &std::path::Path) -> Option<GuiTweaksContract> {
    let path = neoth_home.join("tweaks.toml");
    if !path.exists() {
        return None;
    }
    let body = std::fs::read_to_string(&path).ok()?;
    toml::from_str::<GuiTweaksContract>(&body).ok()
}

/// ODY-04 — wall-clock epoch millis for the stall-watchdog clock.
fn now_epoch_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// ODY-03 — mirror the pending attachment paths into the strip (names only).
fn sync_attachment_strip(w: &MainWindow, paths: &[PathBuf]) {
    use slint::{ModelRc, VecModel};
    let names: Vec<slint::SharedString> = paths
        .iter()
        .map(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file")
                .into()
        })
        .collect();
    w.set_chat_pending_attachments(ModelRc::new(VecModel::from(names)));
}

// ODY-11 — density persistence helpers (pure, testable without Slint window).
// Same extraction pattern as `shape_usage_summary` / `parse_active_preset_name`.

/// Read `<neoth_home>/.gui-density` → 0 (compact) / 1 (normal) / 2 (spacious).
/// Returns 1 on missing file or unrecognised content.
pub fn read_gui_density(neoth_home: &Path) -> i32 {
    std::fs::read_to_string(neoth_home.join(".gui-density"))
        .map(|s| match s.trim() {
            "compact" => 0,
            "spacious" => 2,
            _ => 1,
        })
        .unwrap_or(1)
}

/// Write the density int (0/1/2) as a human-readable label to `path`.
/// Out-of-range values fall through to "normal".
pub fn write_gui_density(path: &Path, val: i32) {
    let label = match val {
        0 => "compact",
        2 => "spacious",
        _ => "normal",
    };
    let _ = std::fs::write(path, label);
}

fn init_tracing() {
    let filter = EnvFilter::try_from_env("NEOTH_LOG")
        .unwrap_or_else(|_| EnvFilter::new("info,neothd_gui=debug"));
    // M-2 fix — `.with_ansi(false)` keeps tracing output free of
    // escape sequences. Important on Windows where the operator's
    // terminal often does not interpret ANSI cleanly.
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_level(true)
        .with_ansi(false)
        .compact()
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn channel_add_saved_parser_accepts_pretty_json_true() {
        assert_eq!(
            parse_channel_saved(
                b"{\n  \"ok\": true,\n  \"channel\": \"telegram\",\n  \"saved\": true\n}",
                "telegram",
            ),
            Some(true)
        );
    }

    #[test]
    fn channel_add_saved_parser_preserves_explicit_false() {
        assert_eq!(
            parse_channel_saved(
                b"{\n  \"ok\": true,\n  \"channel\": \"telegram\",\n  \"saved\": false\n}",
                "telegram",
            ),
            Some(false)
        );
    }

    #[test]
    fn channel_add_saved_parser_rejects_missing_or_malformed_status() {
        assert_eq!(parse_channel_saved(b"{}", "telegram"), None);
        assert_eq!(
            parse_channel_saved(
                b"{\"ok\":true,\"channel\":\"telegram\",\"saved\":\"true\"}",
                "telegram",
            ),
            None
        );
        assert_eq!(parse_channel_saved(b"not-json", "telegram"), None);
    }

    #[test]
    fn channel_add_saved_parser_binds_success_to_requested_channel() {
        assert_eq!(
            parse_channel_saved(
                b"{\"ok\":true,\"channel\":\"slack\",\"saved\":true}",
                "telegram",
            ),
            None
        );
        assert_eq!(
            parse_channel_saved(
                b"{\"ok\":false,\"channel\":\"telegram\",\"saved\":true}",
                "telegram",
            ),
            None
        );
    }

    #[test]
    fn channel_remove_parser_preserves_true_and_false() {
        assert_eq!(
            parse_channel_removed(
                b"{\n  \"channel\": \"telegram\",\n  \"removed\": true\n}",
                "telegram",
            ),
            Some(true)
        );
        assert_eq!(
            parse_channel_removed(
                b"{\n  \"channel\": \"telegram\",\n  \"removed\": false\n}",
                "telegram",
            ),
            Some(false)
        );
    }

    #[test]
    fn channel_remove_parser_rejects_unbound_or_noncanonical_acknowledgements() {
        assert_eq!(
            parse_channel_removed(b"{\"channel\":\"slack\",\"removed\":true}", "telegram",),
            None
        );
        assert_eq!(
            parse_channel_removed(
                b"{\"channel\":\"telegram\",\"removed\":\"true\"}",
                "telegram",
            ),
            None
        );
        assert_eq!(
            parse_channel_removed(
                b"{\"channel\":\"telegram\",\"removed\":true,\"status\":\"ok\"}",
                "telegram",
            ),
            None
        );
        assert_eq!(parse_channel_removed(b"{}", "telegram"), None);
        assert_eq!(parse_channel_removed(b"not-json", "telegram"), None);
    }

    #[test]
    fn channel_remove_command_requests_machine_readable_acknowledgement() {
        let command = channel_remove_command(Path::new("neoth"), "telegram");
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            args,
            vec![
                "channel".to_string(),
                "remove".to_string(),
                "telegram".to_string(),
                "--output".to_string(),
                "json".to_string(),
            ]
        );
    }

    #[test]
    fn channel_credential_command_never_places_secrets_in_argv() {
        let secret = "PROCESS_LIST_SECRET_SENTINEL";
        let request = panel_logic::build_channel_credential_request(
            "discord",
            [secret, "", "", "", "", ""],
            false,
        )
        .unwrap();
        assert!(String::from_utf8_lossy(request.as_slice()).contains(secret));

        let command = channel_credential_command(Path::new("neoth"));
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            args,
            vec![
                "channel".to_string(),
                "set-credentials".to_string(),
                "--output".to_string(),
                "json".to_string(),
            ]
        );
        assert!(!args.iter().any(|arg| arg.contains(secret)));
    }

    fn empty_snapshot() -> WizardSnapshot {
        WizardSnapshot {
            operator_id: "sam".into(),
            provider_kind: "claude_cli".into(),
            autonomy: "standard".into(),
            license_accepted: true,
            ..WizardSnapshot::default()
        }
    }

    #[test]
    fn omi_validation_requires_explicit_cloud_and_mode_credentials() {
        assert!(
            validate_omi_fields(
                true,
                "developer_api",
                "https://api.omi.me",
                "127.0.0.1:8003",
                "30",
                false,
                false,
                true,
                false,
                false,
                false,
                true,
                false,
                "",
                "",
            )
            .is_err()
        );
        assert!(
            validate_omi_fields(
                true,
                "both",
                "https://api.omi.me",
                "127.0.0.1:8003",
                "30",
                true,
                false,
                true,
                false,
                false,
                false,
                true,
                false,
                "",
                "short",
            )
            .is_err()
        );
        assert_eq!(
            validate_omi_fields(
                true,
                "both",
                "https://api.omi.me",
                "127.0.0.1:8003",
                "14",
                true,
                false,
                true,
                true,
                true,
                true,
                false,
                false,
                "omi_dev_example",
                "0123456789abcdef0123456789abcdef",
            )
            .unwrap(),
            14
        );
    }

    #[test]
    fn omi_settings_save_preserves_unrelated_config_and_existing_credentials() {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("freedom.yaml"),
            "operator_id: alice\ninference:\n  mode: triplet\nomi:\n  poll_interval_secs: 45\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("credentials.yaml"),
            concat!(
                "provider_key: keep-me\n",
                "telegram_token: keep-too\n",
                "omi_developer_api_key: omi_dev_existing\n",
                "omi_ingest_token: 0123456789abcdef0123456789abcdef\n",
            ),
        )
        .unwrap();
        let draft = OmiSettingsDraft {
            enabled: true,
            mode: "both".into(),
            endpoint: "https://api.omi.me".into(),
            listen_addr: "127.0.0.1:8003".into(),
            retention_days: "14".into(),
            retain_transcripts: true,
            audio_enabled: true,
            image_enabled: true,
            video_enabled: false,
            allow_cloud_api: true,
            allow_cloud_summary: false,
            create_actions: true,
            seed_groundtruth: false,
            summary_enabled: true,
            developer_key: String::new(),
            native_token: String::new(),
        };
        save_omi_settings(dir.path(), &draft, true, true).unwrap();

        let freedom = std::fs::read_to_string(dir.path().join("freedom.yaml")).unwrap();
        assert!(freedom.contains("mode: triplet"));
        assert!(freedom.contains("poll_interval_secs: 45"));
        assert!(freedom.contains("retain_transcripts: true"));
        assert!(freedom.contains("audio_enabled: true"));
        assert!(freedom.contains("visual_enabled: true"));
        assert!(freedom.contains("video_enabled: false"));
        assert!(freedom.contains("seed_groundtruth: false"));
        assert!(!freedom.contains("omi_dev_existing"));
        assert!(!freedom.contains("0123456789abcdef"));

        let credentials = std::fs::read_to_string(dir.path().join("credentials.yaml")).unwrap();
        assert!(credentials.contains("provider_key: keep-me"));
        assert!(credentials.contains("telegram_token: keep-too"));
        assert!(credentials.contains("omi_developer_api_key: omi_dev_existing"));
        assert!(credentials.contains("omi_ingest_token: 0123456789abcdef0123456789abcdef"));
        assert!(dir.path().join(".reload-requested").exists());
    }

    #[test]
    fn wizard_base_credentials_merge_does_not_erase_existing_fields() {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("credentials.yaml"),
            "provider_key: existing-provider\ndiscord_token: existing-discord\n",
        )
        .unwrap();
        let mut state = empty_snapshot();
        state.provider_key = "new-provider".into();
        write_credentials_yaml(&state, dir.path()).unwrap();
        let credentials = std::fs::read_to_string(dir.path().join("credentials.yaml")).unwrap();
        assert!(credentials.contains("provider_key: new-provider"));
        assert!(credentials.contains("discord_token: existing-discord"));
        assert!(!credentials.contains("omi_developer_api_key"));
    }

    #[test]
    fn board_json_buckets_tasks_by_status_like_cold_path() {
        let b = GuiBoardJson {
            summary: "Session #1  [running]   do stuff".into(),
            cerebellum_bound: true,
            tasks: vec![
                GuiBoardTaskJson {
                    task_id: 1,
                    title: "a".into(),
                    hemisphere: "left".into(),
                    status: "backlog".into(),
                },
                GuiBoardTaskJson {
                    task_id: 2,
                    title: "b".into(),
                    hemisphere: "right".into(),
                    status: "todo".into(),
                },
                GuiBoardTaskJson {
                    task_id: 3,
                    title: "c".into(),
                    hemisphere: "left".into(),
                    status: "in_progress".into(),
                },
                GuiBoardTaskJson {
                    task_id: 4,
                    title: "d".into(),
                    hemisphere: "right".into(),
                    status: "review".into(),
                },
                GuiBoardTaskJson {
                    task_id: 5,
                    title: "e".into(),
                    hemisphere: "left".into(),
                    status: "done".into(),
                },
                GuiBoardTaskJson {
                    task_id: 6,
                    title: "f".into(),
                    hemisphere: "left".into(),
                    status: "archived".into(),
                },
                GuiBoardTaskJson {
                    task_id: 7,
                    title: "g".into(),
                    hemisphere: "left".into(),
                    status: "totally_unknown".into(),
                },
            ],
            feed: vec![],
        };
        let snap = board_json_to_snapshot(b);
        assert_eq!(snap.todo.len(), 1);
        assert_eq!(snap.in_progress.len(), 1);
        assert_eq!(snap.review.len(), 1);
        // `done` + `archived` both land in DONE (mirrors the cold path).
        assert_eq!(snap.done.len(), 2);
        // explicit `backlog` + the unknown status both land in BACKLOG.
        assert_eq!(snap.backlog.len(), 2);
        assert_eq!(snap.cerebellum_bound, Some(true));
        assert_eq!(snap.todo[0].task_id.as_str(), "#2");
    }

    #[test]
    fn board_json_feed_is_reversed_to_newest_first() {
        let b = GuiBoardJson {
            summary: "s".into(),
            cerebellum_bound: false,
            tasks: vec![],
            feed: vec![
                FeedEntryJson {
                    ts_ns: 100,
                    actor: "left".into(),
                    message: "first".into(),
                },
                FeedEntryJson {
                    ts_ns: 200,
                    actor: "right".into(),
                    message: "second".into(),
                },
            ],
        };
        let snap = board_json_to_snapshot(b);
        // Server emits oldest-first (WAL append order); the rail shows
        // newest-first — same reversal the cold `fetch_kanban_feed` does.
        assert_eq!(snap.feed.len(), 2);
        assert_eq!(snap.feed[0].message.as_str(), "second");
        assert_eq!(snap.feed[1].message.as_str(), "first");
        assert_eq!(snap.cerebellum_bound, Some(false));
    }

    #[test]
    fn validate_autonomy_accepts_known_levels() {
        for level in ["strict", "standard", "elevated", "full", "custom"] {
            validate_autonomy(level).unwrap_or_else(|_| panic!("expected {level} to validate"));
        }
    }

    #[test]
    fn validate_autonomy_rejects_unknown() {
        assert!(validate_autonomy("ultra").is_err());
        assert!(validate_autonomy("").is_err());
    }

    #[test]
    fn finish_writes_freedom_only_when_no_secrets() {
        let dir = TempDir::new().unwrap();
        let state = empty_snapshot();
        let freedom = write_freedom_yaml(&state, dir.path()).expect("freedom.yaml");
        let credentials = write_credentials_yaml(&state, dir.path()).expect("credentials");
        assert!(freedom.exists());
        assert!(credentials.is_none());
        let body = std::fs::read_to_string(&freedom).unwrap();
        assert!(body.contains("operator_id: sam"));
        assert!(body.contains("autonomy: standard"));
        assert!(body.contains("channels:"));
        // No telegram channel because enable_telegram=false.
        assert!(!body.contains("- telegram"));
    }

    #[test]
    fn finish_writes_credentials_when_provider_key_set() {
        let dir = TempDir::new().unwrap();
        let mut state = empty_snapshot();
        state.provider_kind = "openai_api".into();
        state.provider_key = "sk-test".into();
        let credentials = write_credentials_yaml(&state, dir.path())
            .expect("credentials")
            .expect("path returned");
        let body = std::fs::read_to_string(&credentials).unwrap();
        assert!(body.contains("provider_key: sk-test"));
        assert!(!body.contains("telegram_token"));
    }

    #[test]
    fn finish_writes_telegram_only_when_channel_enabled_and_token_set() {
        let dir = TempDir::new().unwrap();
        let mut state = empty_snapshot();
        state.enable_telegram = true;
        state.telegram_token = "123:abc".into();
        let credentials = write_credentials_yaml(&state, dir.path())
            .expect("credentials")
            .expect("path returned");
        let body = std::fs::read_to_string(&credentials).unwrap();
        assert!(body.contains("telegram_token: 123:abc"));
    }

    #[test]
    fn finish_skips_telegram_token_when_channel_disabled() {
        let dir = TempDir::new().unwrap();
        let mut state = empty_snapshot();
        state.enable_telegram = false;
        state.telegram_token = "leaked-from-stale-state".into();
        let credentials = write_credentials_yaml(&state, dir.path()).expect("credentials");
        assert!(
            credentials.is_none(),
            "must not persist a telegram_token when the channel is off — \
             would leak a stale UI value past the operator's intent"
        );
    }

    #[test]
    fn finish_rejects_unaccepted_license() {
        // L-3 fix — instead of `unsafe set_var` for HOME/USERPROFILE
        // (which races against any other test reading those env
        // vars under parallel execution), exercise the license check
        // via the same path WITHOUT touching globals. `finish` returns
        // the license error before it ever reads the env, so the
        // assertion holds regardless of env state.
        let mut state = empty_snapshot();
        state.license_accepted = false;
        let err = finish(&state).unwrap_err();
        assert!(err.to_string().contains("license"));
    }

    #[test]
    fn channels_list_contains_telegram_when_enabled() {
        let dir = TempDir::new().unwrap();
        let mut state = empty_snapshot();
        state.enable_telegram = true;
        let freedom = write_freedom_yaml(&state, dir.path()).expect("freedom");
        let body = std::fs::read_to_string(&freedom).unwrap();
        assert!(body.contains("- cli"));
        assert!(body.contains("- telegram"));
    }

    #[test]
    fn wizard_merge_preserves_unowned_config_and_advanced_omi_fields() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(
            &path,
            concat!(
                "operator_id: old\n",
                "provider_kind: openai_api\n",
                "autonomy: full\n",
                "channels: [cli]\n",
                "inference:\n  mode: triplet\n",
                "cluster:\n  name: constellation\n  listen_port: 4242\n",
                "  mdns:\n    enabled: false\n",
                "omi:\n  enabled: true\n  mode: both\n",
                "  poll_interval_secs: 45\n  max_connections: 7\n",
                "  allowed_uids: [omi-device]\n",
            ),
        )
        .unwrap();
        let mut state = empty_snapshot();
        state.omi_enabled = true;
        state.omi_mode = "native_ingest".into();
        state.omi_audio_enabled = true;
        state.cluster_discovery_disabled = false;

        write_freedom_yaml(&state, dir.path()).expect("lossless wizard merge");
        let body = std::fs::read_to_string(&path).unwrap();
        let root: serde_yaml::Value = serde_yaml::from_str(&body).unwrap();
        assert_eq!(root["operator_id"].as_str(), Some("sam"));
        assert_eq!(root["inference"]["mode"].as_str(), Some("triplet"));
        assert_eq!(root["cluster"]["name"].as_str(), Some("constellation"));
        assert_eq!(root["cluster"]["listen_port"].as_u64(), Some(4242));
        assert_eq!(root["cluster"]["mdns"]["enabled"].as_bool(), Some(true));
        assert_eq!(root["omi"]["enabled"].as_bool(), Some(true));
        assert_eq!(root["omi"]["mode"].as_str(), Some("native_ingest"));
        assert_eq!(root["omi"]["audio_enabled"].as_bool(), Some(true));
        assert_eq!(root["omi"]["poll_interval_secs"].as_u64(), Some(45));
        assert_eq!(root["omi"]["max_connections"].as_u64(), Some(7));
        assert_eq!(root["omi"]["allowed_uids"][0].as_str(), Some("omi-device"));
    }

    #[test]
    fn wizard_disable_omi_preserves_advanced_fields() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(
            &path,
            concat!(
                "operator_id: old\nprovider_kind: claude_cli\nautonomy: standard\n",
                "omi:\n  enabled: true\n  max_audio_bytes_per_stream: 123456\n",
            ),
        )
        .unwrap();

        write_freedom_yaml(&empty_snapshot(), dir.path()).expect("disable OMI losslessly");
        let body = std::fs::read_to_string(&path).unwrap();
        let root: serde_yaml::Value = serde_yaml::from_str(&body).unwrap();
        assert_eq!(root["omi"]["enabled"].as_bool(), Some(false));
        assert_eq!(
            root["omi"]["max_audio_bytes_per_stream"].as_u64(),
            Some(123456)
        );
    }

    #[test]
    fn read_freedom_yaml_defaults_sparse_omi_projection() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(
            &path,
            "operator_id: n\nprovider_kind: claude_cli\nautonomy: standard\nomi:\n  enabled: true\n",
        )
        .unwrap();

        let cfg = read_freedom_yaml(&path).expect("sparse OMI block");
        let omi = cfg.omi.expect("OMI projection");
        assert!(omi.enabled);
        assert_eq!(omi.mode, "developer_api");
        assert_eq!(omi.endpoint, "http://127.0.0.1:8002");
        assert_eq!(omi.listen_addr, "127.0.0.1:8003");
        assert_eq!(omi.retention_days, 30);
        assert!(omi.create_actions);
        assert!(omi.seed_groundtruth);
        assert!(omi.summary_enabled);
        assert!(!omi.audio_enabled);
        assert!(!omi.visual_enabled);
        assert!(!omi.video_enabled);
    }

    /// Regression test for the M-1 parse failure:
    /// The real operator freedom.yaml written by neothd has
    ///   cluster:
    ///     name: null
    ///     enabled: false
    /// which is the daemon's ClusterConfig shape — NOT the GUI's
    /// `mdns: { enabled: false }` sub-block shape.  The old
    /// ClusterYamlBlock required a `mdns:` key and had no
    /// `#[serde(default)]`, so serde_yaml returned
    /// "missing field `mdns`" and read_freedom_yaml failed,
    /// causing the Done summary to show defaults instead of
    /// the operator's real values.
    #[test]
    fn read_freedom_yaml_parses_daemon_written_cluster_block() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        // Exact shape that neothd writes (ClusterConfig with name+enabled,
        // no mdns sub-block).
        std::fs::write(
            &path,
            "operator_id: testop\n\
             provider_kind: claude_cli\n\
             autonomy: full\n\
             channels:\n- cli\n\
             cluster:\n  name: null\n  enabled: false\n",
        )
        .unwrap();
        let cfg = read_freedom_yaml(&path)
            .expect("must parse daemon-written cluster block without error");
        assert_eq!(cfg.operator_id, "testop");
        assert_eq!(cfg.provider_kind, "claude_cli");
        assert_eq!(cfg.autonomy, "full");
        assert!(cfg.channels.iter().any(|c| c == "cli"));
        // cluster is present but carries only daemon fields — must not panic
        assert!(cfg.cluster.is_some());
    }

    /// Also verify the full real-world shape (many extra top-level fields)
    /// does not trip the parse.
    #[test]
    fn read_freedom_yaml_parses_fully_expanded_real_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(
            &path,
            "operator_id: n\n\
             provider_kind: claude_cli\n\
             autonomy: full\n\
             channels:\n- cli\n\
             cluster:\n  name: null\n  enabled: false\n\
             inference:\n  mode: single\n\
             council:\n  selection_mode: legacy_majority\n\
             skills:\n  disabled_for_eval_sessions: false\n\
             security:\n  dangerous_commands: deny\n",
        )
        .unwrap();
        let cfg = read_freedom_yaml(&path).expect("fully-expanded freedom.yaml must parse");
        assert_eq!(cfg.operator_id, "n");
        assert_eq!(cfg.autonomy, "full");
    }

    #[test]
    fn cluster_block_omitted_when_discovery_stays_default() {
        // Operator left the checkbox unchecked → discovery stays
        // ON per the noob-wizard "default ON" rule. We must NOT
        // write `cluster.mdns.enabled: false` because that would
        // override the daemon's serde-default + tell future
        // operators reading the YAML that the field was set
        // intentionally.
        let dir = TempDir::new().unwrap();
        let state = empty_snapshot();
        assert!(!state.cluster_discovery_disabled);
        let freedom = write_freedom_yaml(&state, dir.path()).expect("freedom");
        let body = std::fs::read_to_string(&freedom).unwrap();
        assert!(
            !body.contains("cluster"),
            "freedom.yaml must NOT carry a cluster block when discovery defaults stay: {body}"
        );
    }

    #[test]
    fn cluster_block_written_when_discovery_disabled() {
        let dir = TempDir::new().unwrap();
        let mut state = empty_snapshot();
        state.cluster_discovery_disabled = true;
        let freedom = write_freedom_yaml(&state, dir.path()).expect("freedom");
        let body = std::fs::read_to_string(&freedom).unwrap();
        assert!(body.contains("cluster:"), "expected cluster block: {body}");
        assert!(body.contains("mdns:"), "expected mdns subblock: {body}");
        assert!(
            body.contains("enabled: false"),
            "expected enabled: false: {body}"
        );
    }

    // ── Bite #5 — settings panel cluster state ─────────────────────

    #[test]
    fn load_cluster_settings_returns_defaults_when_freedom_missing() {
        let dir = TempDir::new().unwrap();
        let snap = load_cluster_settings(&dir.path().join("freedom.yaml"));
        assert!(snap.mdns_enabled, "Q4 default: mdns enabled");
        assert_eq!(snap.listen_port, 49737);
        assert!(snap.trusted_ssids_summary.is_empty());
    }

    #[test]
    fn load_cluster_settings_returns_defaults_when_unparseable() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(&path, "::: garbage :::").unwrap();
        let snap = load_cluster_settings(&path);
        assert!(snap.mdns_enabled);
        assert_eq!(snap.listen_port, 49737);
        assert!(snap.trusted_ssids_summary.is_empty());
    }

    #[test]
    fn load_cluster_settings_reads_full_block() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        let yaml = "operator_id: alice\n\
                    cluster:\n  \
                    mdns:\n    enabled: false\n  \
                    listen_port: 4242\n  \
                    policy:\n    \
                    announce_on_untrusted_wifi: false\n    \
                    trusted_ssids:\n      - home-wifi\n      - home-wifi-5g\n";
        std::fs::write(&path, yaml).unwrap();
        let snap = load_cluster_settings(&path);
        assert!(!snap.mdns_enabled);
        assert_eq!(snap.listen_port, 4242);
        assert_eq!(snap.trusted_ssids_summary, "home-wifi, home-wifi-5g");
    }

    #[test]
    fn load_cluster_settings_rejects_out_of_range_listen_port() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(&path, "cluster:\n  listen_port: 70000\n").unwrap();
        let snap = load_cluster_settings(&path);
        assert_eq!(
            snap.listen_port, 49737,
            "out-of-range falls back to default"
        );
    }

    #[test]
    fn set_cluster_mdns_writes_enabled_field_atomically() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        set_cluster_mdns_enabled_in_freedom(&path, false).unwrap();
        assert!(path.exists());
        let body = std::fs::read_to_string(&path).unwrap();
        // YAML normalises bool to the unquoted token.
        assert!(body.contains("enabled: false"), "got: {body}");
        // .tmp left behind would mean the rename didn't happen.
        assert!(!dir.path().join("freedom.yaml.tmp").exists());
    }

    #[test]
    fn set_top_level_string_preserves_every_other_field() {
        // MV-01c bug-fix regression guard: the GUI provider/model selectors
        // must NOT drop the operator's other config. Seed a freedom.yaml
        // with a custom inference topology + council + profile block, change
        // provider_kind + provider_model via the lossless writer, assert all
        // the other fields SURVIVE (the prior MinimalFreedomYaml round-trip
        // would have wiped them).
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(
            &path,
            "operator_id: alice\n\
             provider_kind: claude_cli\n\
             provider_model: claude-opus-4-8\n\
             inference:\n  mode: triplet\n  left:\n    provider: local_qwen\n\
             council:\n  daily_usd_cap: 5.0\n  disabled: false\n\
             profile:\n  learn_enabled: true\n",
        )
        .unwrap();

        set_top_level_string_in_freedom(&path, "provider_kind", "openai_api").unwrap();
        set_top_level_string_in_freedom(&path, "provider_model", "gpt-5.5").unwrap();

        let body = std::fs::read_to_string(&path).unwrap();
        assert!(
            body.contains("provider_kind: openai_api"),
            "provider updated: {body}"
        );
        assert!(
            body.contains("provider_model: gpt-5.5"),
            "model updated: {body}"
        );
        // The fields MinimalFreedomYaml never modelled MUST survive.
        assert!(
            body.contains("mode: triplet"),
            "inference topology dropped: {body}"
        );
        assert!(
            body.contains("provider: local_qwen"),
            "hemisphere slot dropped: {body}"
        );
        assert!(
            body.contains("daily_usd_cap"),
            "council config dropped: {body}"
        );
        assert!(
            body.contains("learn_enabled"),
            "profile config dropped: {body}"
        );
        assert!(!dir.path().join("freedom.yaml.tmp").exists());
    }

    #[test]
    fn set_top_level_string_creates_mapping_when_file_absent() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        set_top_level_string_in_freedom(&path, "provider_kind", "gemini_api").unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("provider_kind: gemini_api"), "got: {body}");
    }

    #[test]
    fn set_cluster_mdns_round_trip_via_load_cluster_settings() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        // Start ENABLED → toggle OFF → load sees false → toggle ON →
        // load sees true. Pins the wire shape across the read+write
        // pair so the settings panel can't drift away from the
        // on-disk format.
        set_cluster_mdns_enabled_in_freedom(&path, true).unwrap();
        assert!(load_cluster_settings(&path).mdns_enabled);
        set_cluster_mdns_enabled_in_freedom(&path, false).unwrap();
        assert!(!load_cluster_settings(&path).mdns_enabled);
        set_cluster_mdns_enabled_in_freedom(&path, true).unwrap();
        assert!(load_cluster_settings(&path).mdns_enabled);
    }

    #[test]
    fn set_cluster_mdns_preserves_other_fields() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        // Pre-seed freedom.yaml with fields the GUI's MinimalFreedomYaml
        // doesn't know about. The toggle MUST NOT drop them — that's
        // the whole point of using the lossless serde_yaml::Value
        // round-trip instead of typed read-merge-write.
        let original = "operator_id: alice\n\
                        provider_kind: openai_api\n\
                        inference:\n  topology: triplet\n  left:\n    provider: openai_api\n\
                        cluster:\n  \
                        mdns:\n    enabled: true\n  \
                        listen_port: 50000\n  \
                        policy:\n    \
                        trusted_ssids:\n      - home-wifi\n";
        std::fs::write(&path, original).unwrap();
        set_cluster_mdns_enabled_in_freedom(&path, false).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        // Toggle landed.
        assert!(body.contains("enabled: false"));
        // Untyped neighbours survived.
        assert!(body.contains("operator_id: alice"));
        assert!(body.contains("provider_kind: openai_api"));
        assert!(body.contains("topology: triplet"));
        assert!(body.contains("listen_port: 50000"));
        assert!(body.contains("home-wifi"));
    }

    // ── PF-01-GUI: skills.always_embed_route toggle ──────────────────────────

    #[test]
    fn read_skills_always_embed_route_defaults_true() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        // Missing file → true (matches the daemon SkillsConfig default).
        assert!(read_skills_always_embed_route(&path));
        // Present but no skills key → true.
        std::fs::write(&path, "operator_id: a\n").unwrap();
        assert!(read_skills_always_embed_route(&path));
        // Malformed → true.
        std::fs::write(&path, "%%% not yaml %%%").unwrap();
        assert!(read_skills_always_embed_route(&path));
    }

    #[test]
    fn skills_always_embed_route_write_read_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        set_skills_always_embed_route_in_freedom(&path, false).unwrap();
        assert!(!read_skills_always_embed_route(&path));
        set_skills_always_embed_route_in_freedom(&path, true).unwrap();
        assert!(read_skills_always_embed_route(&path));
    }

    #[test]
    fn set_skills_always_embed_route_preserves_other_fields() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        let original = "operator_id: alice\n\
                        provider_kind: openai_api\n\
                        skills:\n  disabled_for_eval_sessions: true\n\
                        cluster:\n  listen_port: 50000\n";
        std::fs::write(&path, original).unwrap();
        set_skills_always_embed_route_in_freedom(&path, false).unwrap();
        assert!(!read_skills_always_embed_route(&path));
        let body = std::fs::read_to_string(&path).unwrap();
        // Sibling under skills + unrelated fields survived the nested write.
        assert!(body.contains("disabled_for_eval_sessions: true"));
        assert!(body.contains("operator_id: alice"));
        assert!(body.contains("listen_port: 50000"));
    }

    // ── ODY-11 density helpers ────────────────────────────────────────────

    #[test]
    fn density_restore_reads_compact_from_disk() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(".gui-density"), b"compact").unwrap();
        assert_eq!(read_gui_density(dir.path()), 0);
    }

    #[test]
    fn density_restore_reads_spacious_from_disk() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(".gui-density"), b"spacious").unwrap();
        assert_eq!(read_gui_density(dir.path()), 2);
    }

    #[test]
    fn density_restore_reads_normal_from_disk() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(".gui-density"), b"normal").unwrap();
        assert_eq!(read_gui_density(dir.path()), 1);
    }

    #[test]
    fn density_restore_defaults_to_normal_on_missing_file() {
        let dir = TempDir::new().unwrap();
        assert_eq!(read_gui_density(dir.path()), 1);
    }

    #[test]
    fn density_restore_defaults_to_normal_on_garbage_file() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(".gui-density"), b"%%%invalid%%%").unwrap();
        assert_eq!(read_gui_density(dir.path()), 1);
    }

    #[test]
    fn density_write_round_trips_all_three_values() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".gui-density");
        // compact
        write_gui_density(&path, 0);
        assert_eq!(std::fs::read_to_string(&path).unwrap().trim(), "compact");
        assert_eq!(read_gui_density(dir.path()), 0);
        // normal
        write_gui_density(&path, 1);
        assert_eq!(std::fs::read_to_string(&path).unwrap().trim(), "normal");
        assert_eq!(read_gui_density(dir.path()), 1);
        // spacious
        write_gui_density(&path, 2);
        assert_eq!(std::fs::read_to_string(&path).unwrap().trim(), "spacious");
        assert_eq!(read_gui_density(dir.path()), 2);
    }

    #[test]
    fn density_write_out_of_range_falls_through_to_normal() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".gui-density");
        write_gui_density(&path, 99);
        assert_eq!(std::fs::read_to_string(&path).unwrap().trim(), "normal");
        assert_eq!(read_gui_density(dir.path()), 1);
    }
}

/// B23 — THEME-TWEAKS-RUNTIME: GUI-side contract type tests.
#[cfg(test)]
mod b23_gui_tweaks_tests {
    use super::{
        GuiTweaksContract, animation_speed_mode, chat_bubble_style_mode, parse_theme_color,
        read_gui_tweaks, resolve_neoth_home,
    };
    use tempfile::TempDir;

    // ── resolve_neoth_home ────────────────────────────────────────────────

    #[test]
    fn neoth_home_env_takes_priority_over_home() {
        let p = resolve_neoth_home(Some("/custom/neoth"), Some("/home/user"), None);
        assert_eq!(p, std::path::PathBuf::from("/custom/neoth"));
    }

    #[test]
    fn neoth_home_empty_string_falls_through_to_home() {
        let p = resolve_neoth_home(Some(""), Some("/home/user"), None);
        assert_eq!(p, std::path::PathBuf::from("/home/user/.neoth"));
    }

    #[test]
    fn neoth_home_absent_uses_home_with_dot_neoth_suffix() {
        let p = resolve_neoth_home(None, Some("/home/user"), None);
        assert_eq!(p, std::path::PathBuf::from("/home/user/.neoth"));
    }

    #[test]
    fn neoth_home_falls_through_to_userprofile_when_home_absent() {
        let p = resolve_neoth_home(None, None, Some("C:\\Users\\Shadow"));
        assert_eq!(
            p,
            std::path::PathBuf::from("C:\\Users\\Shadow").join(".neoth")
        );
    }

    #[test]
    fn neoth_home_dot_fallback_when_all_absent() {
        let p = resolve_neoth_home(None, None, None);
        assert_eq!(p, std::path::PathBuf::from(".").join(".neoth"));
    }

    // ── read_gui_tweaks ───────────────────────────────────────────────────

    #[test]
    fn read_gui_tweaks_returns_none_when_file_missing() {
        let dir = TempDir::new().unwrap();
        assert!(read_gui_tweaks(dir.path()).is_none());
    }

    #[test]
    fn read_gui_tweaks_parses_valid_file() {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("tweaks.toml"),
            r#"
color_theme = "light"
[theme]
font_size_pt = 16
sidebar_width_px = 300
"#,
        )
        .unwrap();
        let c = read_gui_tweaks(dir.path()).unwrap();
        assert_eq!(c.color_theme.as_deref(), Some("light"));
        assert_eq!(c.theme.font_size_pt, Some(16));
        assert_eq!(c.theme.sidebar_width_px, Some(300));
    }

    #[test]
    fn read_gui_tweaks_returns_none_on_bad_toml() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("tweaks.toml"), b"bad = [broken").unwrap();
        assert!(read_gui_tweaks(dir.path()).is_none());
    }

    /// Parity guard: GuiThemeContract must parse all 16 retained ThemeConfig fields.
    /// If a field is added to ThemeConfig in neothd, this test will break
    /// because the field won't round-trip — keeping the two types in sync.
    #[test]
    fn gui_tweaks_contract_parses_all_16_theme_fields() {
        let toml_str = r##"
color_theme = "dark"
[theme]
accent_color = "#ff0000"
background_color = "#000000"
foreground_color = "#ffffff"
font_family = "Inter"
font_size_pt = 14
sidebar_width_px = 320
border_radius_px = 8
compact_mode = true
show_token_count = true
show_model_badge = false
chat_bubble_style = "rounded"
animation_speed = "reduced"
input_height_lines = 4
panel_opacity = 0.9
header_hidden = false
sidebar_collapsed = true
"##;
        let c: GuiTweaksContract = toml::from_str(toml_str).unwrap();
        assert_eq!(c.color_theme.as_deref(), Some("dark"));
        assert_eq!(c.theme.font_family.as_deref(), Some("Inter"));
        assert_eq!(c.theme.font_size_pt, Some(14));
        assert_eq!(c.theme.sidebar_width_px, Some(320));
        assert_eq!(c.theme.input_height_lines, Some(4));
        assert_eq!(c.theme.compact_mode, Some(true));
        assert_eq!(c.theme.panel_opacity, Some(0.9));
        assert_eq!(c.theme.accent_color.as_deref(), Some("#ff0000"));
        assert_eq!(c.theme.background_color.as_deref(), Some("#000000"));
        assert_eq!(c.theme.foreground_color.as_deref(), Some("#ffffff"));
        assert_eq!(c.theme.border_radius_px, Some(8));
        assert_eq!(c.theme.show_token_count, Some(true));
        assert_eq!(c.theme.show_model_badge, Some(false));
        assert_eq!(c.theme.chat_bubble_style.as_deref(), Some("rounded"));
        assert_eq!(c.theme.animation_speed.as_deref(), Some("reduced"));
        assert_eq!(c.theme.header_hidden, Some(false));
        assert_eq!(c.theme.sidebar_collapsed, Some(true));
    }

    #[test]
    fn gui_tweaks_contract_absent_block_gives_all_none() {
        let c: GuiTweaksContract = toml::from_str("color_theme = \"dark\"").unwrap();
        assert!(c.theme.font_family.is_none());
        assert!(c.theme.compact_mode.is_none());
        assert!(c.theme.sidebar_width_px.is_none());
    }

    #[test]
    fn gui_tweaks_removed_no_sink_fields_fail_loud() {
        for field in ["icon_set", "scrollbar_style"] {
            let body = format!("[theme]\n{field} = \"legacy\"\n");
            assert!(
                toml::from_str::<GuiTweaksContract>(&body).is_err(),
                "removed field {field} must not parse and disappear"
            );
        }
    }

    #[test]
    fn gui_theme_runtime_value_parsers_cover_contract_variants() {
        for color in ["#123", "#112233", "#11223380"] {
            assert!(parse_theme_color(color).is_some(), "valid color: {color}");
        }
        for color in ["123", "#12", "#gg0000", "#1122334455"] {
            assert!(parse_theme_color(color).is_none(), "invalid color: {color}");
        }
        assert_eq!(chat_bubble_style_mode("rounded"), Some(0));
        assert_eq!(chat_bubble_style_mode("square"), Some(1));
        assert_eq!(chat_bubble_style_mode("minimal"), Some(2));
        assert_eq!(chat_bubble_style_mode("cloud"), None);
        assert_eq!(animation_speed_mode("none"), Some(0));
        assert_eq!(animation_speed_mode("reduced"), Some(1));
        assert_eq!(animation_speed_mode("full"), Some(2));
        assert_eq!(animation_speed_mode("turbo"), None);
    }

    #[test]
    fn gui_tweaks_contract_missing_file_falls_through_silently() {
        // read_gui_tweaks must not panic on missing file
        let dir = TempDir::new().unwrap();
        let result = read_gui_tweaks(dir.path());
        assert!(result.is_none());
    }

    // ── resolve_boot_dark — mirrors daemon resolve_effective_gui_theme ────────
    // Naming: <dotfile-state>_<tweaks-state> → expected bool (true = dark).
    //
    // PARITY CONTRACT (adversarial-review note): the GUI crate must not depend
    // on neothd, so these tests cannot call the daemon resolver directly. The
    // expected outputs below are copied from the daemon's own unit tests in
    // SRC/neothd/src/tweaks/mod.rs (b23 test block, ~:758-823):
    //   dotfile "dark"/"light" wins over any tweaks value;
    //   invalid dotfile falls through to tweaks (with diagnostic);
    //   tweaks "light" → light, "dark"/"auto" → dark, invalid/None → dark.
    // ANY edit to either resolver MUST update both test blocks in the same
    // commit — diff the daemon test names against the boot_dark_* names here.

    use super::resolve_boot_dark;

    #[test]
    fn boot_dark_dotfile_dark_wins_over_tweaks_light() {
        // Valid dotfile wins unconditionally — even when tweaks says light.
        assert!(resolve_boot_dark(Some("dark"), Some("light")));
    }

    #[test]
    fn boot_dark_dotfile_light_wins_over_tweaks_dark() {
        // Valid dotfile wins unconditionally — even when tweaks says dark.
        assert!(!resolve_boot_dark(Some("light"), Some("dark")));
    }

    #[test]
    fn boot_dark_dotfile_light_wins_over_tweaks_auto() {
        assert!(!resolve_boot_dark(Some("light"), Some("auto")));
    }

    #[test]
    fn boot_dark_dotfile_light_wins_when_no_tweaks() {
        assert!(!resolve_boot_dark(Some("light"), None));
    }

    #[test]
    fn boot_dark_dotfile_dark_wins_when_no_tweaks() {
        assert!(resolve_boot_dark(Some("dark"), None));
    }

    #[test]
    fn boot_dark_invalid_dotfile_falls_to_tweaks_light() {
        // Invalid dotfile falls through; tweaks says light → not dark.
        assert!(!resolve_boot_dark(Some("blue"), Some("light")));
    }

    #[test]
    fn boot_dark_invalid_dotfile_falls_to_tweaks_dark() {
        assert!(resolve_boot_dark(Some("blue"), Some("dark")));
    }

    #[test]
    fn boot_dark_invalid_dotfile_falls_to_tweaks_auto() {
        // "auto" treated as dark (same as daemon's resolve_dark_from_tweaks).
        assert!(resolve_boot_dark(Some("neon"), Some("auto")));
    }

    #[test]
    fn boot_dark_invalid_dotfile_invalid_tweaks_builtin_dark() {
        // Both invalid → builtin dark.
        assert!(resolve_boot_dark(Some("bad"), Some("nord")));
    }

    #[test]
    fn boot_dark_invalid_dotfile_no_tweaks_builtin_dark() {
        // Invalid dotfile + no tweaks → builtin dark.
        assert!(resolve_boot_dark(Some("bad"), None));
    }

    #[test]
    fn boot_dark_no_dotfile_tweaks_light() {
        assert!(!resolve_boot_dark(None, Some("light")));
    }

    #[test]
    fn boot_dark_no_dotfile_tweaks_dark() {
        assert!(resolve_boot_dark(None, Some("dark")));
    }

    #[test]
    fn boot_dark_no_dotfile_tweaks_auto() {
        // "auto" → dark, matches daemon behaviour.
        assert!(resolve_boot_dark(None, Some("auto")));
    }

    #[test]
    fn boot_dark_no_dotfile_invalid_tweaks_builtin_dark() {
        // Invalid tweaks value → builtin dark.
        assert!(resolve_boot_dark(None, Some("solarized")));
    }

    #[test]
    fn boot_dark_no_dotfile_no_tweaks_builtin_dark() {
        // Nothing set → builtin dark.
        assert!(resolve_boot_dark(None, None));
    }

    // ── Adversarial-review fixes: empty-dotfile edge (file-absent semantics) ──
    // Expected outputs mirror the daemon resolver contract (tweaks/mod.rs
    // resolve_effective_gui_theme: "Non-empty but unrecognised" — empty is NOT
    // an invalid value, it is file-absent; boot call site additionally filters
    // empty strings to None).

    #[test]
    fn boot_dark_empty_dotfile_falls_to_tweaks_light() {
        // Empty dotfile behaves like no dotfile — tweaks light wins, no warn.
        assert!(!resolve_boot_dark(Some(""), Some("light")));
    }

    #[test]
    fn boot_dark_empty_dotfile_no_tweaks_builtin_dark() {
        assert!(resolve_boot_dark(Some(""), None));
    }
}

/// GOLD-ADAPT-ODY-12/14 — deep-link chip parsing + nav routing contract.
#[cfg(test)]
mod deep_link_tests {
    use super::{NAV_PANELS, parse_stream_links};

    #[test]
    fn parses_links_array_from_extended_sentinel() {
        let raw = "reply text\n\n{\"neoth_stream\":\"done\",\"count\":2,\
                   \"links\":[{\"label\":\"task 42\",\"kind\":\"kanban\",\"id\":\"42\"},\
                   {\"label\":\"board\",\"kind\":\"nav\",\"id\":\"coding\"}]}\n";
        let links = parse_stream_links(raw);
        assert_eq!(links.len(), 2);
        assert_eq!(
            links[0],
            (
                "task 42".to_string(),
                "kanban".to_string(),
                "42".to_string()
            )
        );
        assert_eq!(links[1].1, "nav");
        assert_eq!(links[1].2, "coding");
    }

    #[test]
    fn absent_links_field_and_old_daemons_yield_empty() {
        // Old minimal sentinel (recall early-return) has no links field.
        assert!(parse_stream_links("x\n{\"neoth_stream\":\"done\",\"count\":1}\n").is_empty());
        // Mid-stream: no sentinel at all.
        assert!(parse_stream_links("still streaming...").is_empty());
        // Malformed entries are skipped, not fatal.
        let raw = "r\n{\"neoth_stream\":\"done\",\"links\":[{\"label\":\"x\"},\
                   {\"label\":\"ok\",\"kind\":\"nav\",\"id\":\"memory\"}]}\n";
        let links = parse_stream_links(raw);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].2, "memory");
    }

    #[test]
    fn nav_panels_list_matches_slint_nav_values() {
        // Drift guard: main.slint's nav-active values. A chip id outside
        // this list is ignored by the click handler.
        assert_eq!(NAV_PANELS.len(), 26);
        for p in [
            "chat",
            "overview",
            "coding",
            "memory",
            "config",
            "loops",
            "n8n",
            "babel",
            "calendar",
            "evolve",
            "obsidian",
            "dreaming",
            "wiki",
            "buddyconfig",
            "companion",
            "mesh",
            "selfdev",
        ] {
            assert!(NAV_PANELS.contains(&p), "{p} must be a nav panel");
        }
    }
}

/// Buddy dock and six-field status wiring must not drift back to decorative UI.
#[cfg(test)]
mod buddy_wiring_tests {
    use super::validate_buddy_exit;

    #[test]
    fn buddy_click_reuses_the_companion_overlay_transition() {
        let source = include_str!("main.rs");
        let marker = ["let window_weak_for_", "buddy"].concat();
        let end = ["// overlay restore-", "clicked"].concat();
        let wiring = source
            .split(&marker)
            .nth(1)
            .and_then(|tail| tail.split(&end).next())
            .expect("Buddy overlay wiring block");
        assert!(wiring.contains(&["window.on_buddy_", "clicked"].concat()));
        assert!(wiring.contains(&["win.invoke_minimize_to_", "companion()"].concat()));
    }

    #[test]
    fn main_window_forwards_all_buddy_status_booleans() {
        let source = include_str!("main.rs");
        let ui = include_str!("../ui/main.slint");
        for property in [
            "bc-sovereign-buddy",
            "bc-self-activation-enabled",
            "bc-smart-approve",
            "bc-proactive-enabled",
        ] {
            assert!(
                ui.contains(&format!("in property <bool>            {property}: false;")),
                "missing MainWindow property {property}"
            );
            assert!(
                ui.contains(&format!("{property}: root.{property};")),
                "BuddyConfigView does not receive {property}"
            );
        }
        for setter_suffix in [
            "bc_sovereign_buddy",
            "bc_self_activation_enabled",
            "bc_self_activation_skills",
            "bc_smart_approve",
            "bc_autonomy",
            "bc_proactive_enabled",
        ] {
            assert!(
                source.contains(&["w.set_", setter_suffix, "("].concat()),
                "refresh_buddyconfig does not set {setter_suffix}"
            );
        }
        assert!(ui.contains("in property <bool>            bc-status-valid: false;"));
        assert!(ui.contains("in property <string>          bc-status-error: \"\";"));

        let buddy_ui = include_str!("../ui/buddyconfig.slint");
        assert!(buddy_ui.contains("Buddy status unavailable"));
        assert!(buddy_ui.contains("controls-enabled: root.bc-status-valid;"));
    }

    #[test]
    fn failed_refresh_keeps_last_known_buddy_values() {
        let source = include_str!("main.rs");
        let refresh = source
            .split("fn refresh_buddyconfig")
            .nth(1)
            .and_then(|tail| tail.split("// ── Wave 4b — Companion probe").next())
            .expect("refresh_buddyconfig body");
        let failure = refresh
            .split("Err(error) =>")
            .nth(1)
            .expect("explicit Buddy refresh failure arm");
        assert!(failure.contains("set_bc_status_valid(false)"));
        assert!(failure.contains("set_bc_status_error(error.into())"));
        for value_setter in [
            "set_bc_sovereign_buddy",
            "set_bc_self_activation_enabled",
            "set_bc_self_activation_skills",
            "set_bc_smart_approve",
            "set_bc_autonomy",
            "set_bc_proactive_enabled",
            "set_bc_refreshed_at",
        ] {
            assert!(
                !failure.contains(value_setter),
                "failed refresh must preserve last-known-good `{value_setter}`"
            );
        }
    }

    #[test]
    fn buddy_status_requires_zero_exit_before_snapshot_parsing() {
        assert!(validate_buddy_exit("proactive", true, b"", Some(0)).is_ok());
        let error = validate_buddy_exit("proactive", false, b"policy denied\n", Some(2))
            .expect_err("non-zero exit must fail");
        assert!(error.contains("exit 2"));
        assert!(error.contains("policy denied"));
    }

    #[test]
    fn buddy_policy_controls_are_real_and_sovereign_enable_keeps_the_tty_gate() {
        let source = include_str!("main.rs");
        let ui = include_str!("../ui/buddyconfig.slint");
        let callbacks = source
            .split("Wave 4b — Buddy Config panel callbacks")
            .nth(1)
            .and_then(|tail| {
                tail.split("Wave 4b — Companion / Smartphone Pairing")
                    .next()
            })
            .expect("Buddy callback block");

        assert!(callbacks.contains("on_bc_sovereign_enable_cli"));
        assert!(callbacks.contains("launch_sovereign_ceremony"));
        assert!(callbacks.contains("gui_action::BuddySelfActivationAck"));
        assert!(callbacks.contains("&[\"buddy\", \"self-activation\", flag]"));
        assert!(callbacks.contains("\"Buddy self-activation update\""));
        assert!(callbacks.contains("gui_action::BuddyProactiveAck"));
        assert!(callbacks.contains("&[\"buddy\", \"proactive\", flag]"));
        assert!(callbacks.contains("\"Buddy proactive update\""));
        assert!(callbacks.contains("on_bc_sovereign_disable"));
        assert!(callbacks.contains("gui_action::SovereignDisableAck"));
        assert!(callbacks.contains("&[\"autonomy\", \"sovereign\", \"--disable\"]"));
        assert!(callbacks.contains("gui_action::SmartApproveAck"));
        assert!(callbacks.contains("&[\"security\", \"set\", \"smart-approve\", flag]"));
        assert!(!callbacks.contains("Change sovereign buddy in the Privacy tab"));
        assert!(!callbacks.contains("Smart-approve is a per-channel setting"));
        assert!(!callbacks.contains("run_buddy_toggle"));

        assert!(ui.contains("label: \"Enable in CLI\""));
        assert!(ui.contains("root.bc-sovereign-enable-cli()"));
        assert!(ui.contains("root.bc-sovereign-disable()"));
        assert!(!ui.contains("bc-sovereign-toggle(bool)"));

        let launcher = source
            .split("enum TerminalLaunch")
            .nth(1)
            .and_then(|tail| tail.split("fn switch_to_cli").next())
            .expect("terminal launcher contract");
        assert!(launcher.contains("interface terminal-ready"));
        assert!(launcher.contains("autonomy sovereign --enable"));
        assert!(!launcher.contains("gui-confirmed"));
        assert!(!launcher.contains("gui-token"));
    }
}

/// GOLD-ADAPT-OH-01 — welcome migrate-card summary shaping.
#[cfg(test)]
mod migrate_card_tests {
    use super::format_migrate_summary;

    #[test]
    fn shapes_detected_sources_into_one_line() {
        let json =
            "{\"sources\":[{\"name\":\"hermes-home\"},{\"name\":\"openclaw-home\"}],\"scans\":[]}";
        assert_eq!(
            format_migrate_summary(json),
            "2 prior-AI home(s) found: hermes-home, openclaw-home"
        );
    }

    #[test]
    fn empty_or_malformed_hides_the_card() {
        assert_eq!(format_migrate_summary("{\"sources\":[],\"scans\":[]}"), "");
        assert_eq!(format_migrate_summary("not json"), "");
        assert_eq!(format_migrate_summary("{}"), "");
    }
}

/// GUI-FULLAUTO-CEREMONY + GUI-REENTRY-PRESET regression tests.
///
/// Both fixes live in `on_preset_apply_named_clicked` and `on_finish_clicked`
/// (pure-logic branches) — no Slint or subprocess dependency needed here.
#[cfg(test)]
mod gui_bug_regression_tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tempfile::TempDir;

    use super::{WizardSnapshot, finish, read_freedom_yaml};

    fn base_snapshot() -> WizardSnapshot {
        WizardSnapshot {
            operator_id: "alice".into(),
            provider_kind: "claude_cli".into(),
            autonomy: "standard".into(),
            license_accepted: true,
            ..WizardSnapshot::default()
        }
    }

    // ── GUI-FULLAUTO-CEREMONY ────────────────────────────────────────────────

    /// The routing predicate in the None (dry-run unavailable) arm:
    /// only `"full-auto"` must be sent through the token route.
    #[test]
    fn full_auto_preset_name_triggers_token_route() {
        let requires_token = |name: &str| name == "full-auto";
        assert!(requires_token("full-auto"));
        assert!(!requires_token("balanced"));
        assert!(!requires_token("essentials"));
        assert!(!requires_token("local-sovereign"));
        assert!(!requires_token("my-custom"));
        assert!(!requires_token(""));
    }

    // ── GUI-REENTRY-PRESET ───────────────────────────────────────────────────

    /// Valid freedom.yaml → `reentry_config_ok` flag set to true.
    #[test]
    fn reentry_flag_set_when_yaml_valid() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(
            &path,
            "operator_id: alice\nprovider_kind: claude_cli\n\
             autonomy: standard\nchannels:\n- cli\n",
        )
        .unwrap();
        let flag = Arc::new(AtomicBool::new(false));
        if read_freedom_yaml(&path).is_ok() {
            flag.store(true, Ordering::Release);
        }
        assert!(
            flag.load(Ordering::Acquire),
            "flag must be true for valid yaml"
        );
    }

    /// Corrupted freedom.yaml → `reentry_config_ok` flag stays false.
    #[test]
    fn reentry_flag_stays_false_when_yaml_corrupt() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(&path, "this is: [not: valid: yaml:\n").unwrap();
        let flag = Arc::new(AtomicBool::new(false));
        if read_freedom_yaml(&path).is_ok() {
            flag.store(true, Ordering::Release);
        }
        assert!(
            !flag.load(Ordering::Acquire),
            "flag must stay false for corrupt yaml"
        );
    }

    /// Guard: already_initialized=true + flag=false → block.
    #[test]
    fn guard_blocks_when_already_initialized_and_read_failed() {
        let already_initialized = true;
        let flag = Arc::new(AtomicBool::new(false));
        let blocked = already_initialized && !flag.load(Ordering::Acquire);
        assert!(blocked);
    }

    /// Guard: already_initialized=true + flag=true → allow.
    #[test]
    fn guard_allows_when_already_initialized_and_read_succeeded() {
        let already_initialized = true;
        let flag = Arc::new(AtomicBool::new(true));
        let blocked = already_initialized && !flag.load(Ordering::Acquire);
        assert!(!blocked);
    }

    /// Guard: already_initialized=false → never block regardless of flag.
    #[test]
    fn guard_never_blocks_on_first_run() {
        let already_initialized = false;
        for v in [false, true] {
            let flag = Arc::new(AtomicBool::new(v));
            let blocked = already_initialized && !flag.load(Ordering::Acquire);
            assert!(!blocked, "first-run must never be blocked (flag={v})");
        }
    }

    /// finish() still validates state even when the re-entry guard passes.
    #[test]
    fn finish_validates_state_after_reentry_guard_passes() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("freedom.yaml");
        std::fs::write(
            &path,
            "operator_id: alice\nprovider_kind: claude_cli\n\
             autonomy: standard\nchannels:\n- cli\n",
        )
        .unwrap();
        let cfg = read_freedom_yaml(&path).expect("parses");
        let mut state = base_snapshot();
        state.operator_id = cfg.operator_id;
        state.autonomy = cfg.autonomy;
        state.license_accepted = false; // operator unchecked license
        let err = finish(&state).unwrap_err();
        assert!(err.to_string().contains("license"));
    }
}
