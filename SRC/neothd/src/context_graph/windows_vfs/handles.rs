//! Capability-relative file operations used by the Windows Context SQLite VFS.
//!
//! This module deliberately has no `Path`-taking open operation.  The only
//! namespace capability is a verified, no-delete directory handle retained by
//! [`PinnedContextDirectory`].  Every SQLite object is opened below that
//! handle with the native relative-open primitive.

#![cfg(windows)]

use std::{
    ffi::OsStr,
    fs::File,
    io,
    os::windows::io::{AsRawHandle, FromRawHandle},
};

use windows_sys::Win32::{
    Foundation::{HANDLE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        GetFileInformationByHandle,
    },
};

/// The only persistent SQLite namespace entries accepted by the VFS.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum ContextLeaf {
    Main,
    Wal,
    Shm,
    Journal,
}

impl ContextLeaf {
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Main => "context.db",
            Self::Wal => "context.db-wal",
            Self::Shm => "context.db-shm",
            Self::Journal => "context.db-journal",
        }
    }

    pub(super) fn parse_sqlite_name(name: &str) -> Option<Self> {
        // SQLite is allowed to hand the VFS a bare name, or to hand back the
        // opaque name emitted by xFullPathname.  Components, streams, trailing
        // dots, and every other spelling are rejected instead of normalized.
        match name {
            "context.db" => Some(Self::Main),
            "context.db-wal" => Some(Self::Wal),
            "context.db-shm" => Some(Self::Shm),
            "context.db-journal" => Some(Self::Journal),
            _ => None,
        }
    }
}

/// Kernel identity recorded for a directory or file capability.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct FileIdentity {
    pub(super) volume_serial: u32,
    pub(super) file_index: u64,
}

/// A no-reparse, TokenUser-private directory capability.
///
/// Construction intentionally consumes an already-open directory handle.  The
/// caller must obtain it by walking a separately trusted anchor one component
/// at a time with `FILE_OPEN_REPARSE_POINT`; converting an arbitrary path to a
/// handle here would recreate the path substitution boundary this VFS exists to
/// remove.
pub(crate) struct PinnedContextDirectory {
    directory: File,
    identity: FileIdentity,
}

impl PinnedContextDirectory {
    /// Duplicate an already no-follow-opened directory capability. The source
    /// remains with the caller while this VFS keeps the duplicate through every
    /// main/WAL/SHM/journal operation.
    pub(crate) fn duplicate_verified_handle<H: AsRawHandle + ?Sized>(
        directory: &H,
    ) -> io::Result<Self> {
        let mut duplicate = std::ptr::null_mut();
        // SAFETY: `directory` supplies a live kernel handle. DuplicateHandle
        // returns exactly one independently-owned duplicate on success.
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                directory.as_raw_handle() as HANDLE,
                GetCurrentProcess(),
                &mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful DuplicateHandle transfers ownership of `duplicate`.
        Self::from_verified_handle(unsafe { File::from_raw_handle(duplicate) })
    }

    /// Adopt a directory capability after proving its object type, reparse
    /// state, identity, owner, and protected private DACL on that same handle.
    pub(crate) fn from_verified_handle(directory: File) -> io::Result<Self> {
        let identity = identity_of(&directory, true)?;
        crate::wal::win_native::verify_private_directory_handle_dacl(&directory)?;
        Ok(Self {
            directory,
            identity,
        })
    }
    pub(super) fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// Opens an exact allow-listed leaf relative to the retained root handle.
    ///
    /// `create_if_missing` uses the WAL module's capability-relative creator:
    /// it supplies the protected single-TokenUser DACL to NtCreateFile before
    /// the child first becomes observable.  It never falls back to CreateFileW
    /// with an absolute path.
    pub(super) fn open_leaf(
        &self,
        leaf: ContextLeaf,
        read_write: bool,
        create_if_missing: bool,
    ) -> io::Result<File> {
        let desired_access = if read_write {
            // `xSync` calls `File::sync_all`, which reaches
            // FlushFileBuffers. Windows requires GENERIC_WRITE for that
            // operation. Request its specific file-right components here,
            // without DELETE, so ordinary SQLite handles remain unable to
            // replace a pinned main database or sidecar.
            FILE_READ_DATA
                | FILE_WRITE_DATA
                | FILE_APPEND_DATA
                | FILE_READ_EA
                | FILE_WRITE_EA
                | FILE_READ_ATTRIBUTES
                | FILE_WRITE_ATTRIBUTES
                | SYNCHRONIZE
                | READ_CONTROL
        } else {
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE | READ_CONTROL
        };
        let file = crate::wal::win_native::create_private_child_file_relative(
            self.directory.as_raw_handle() as HANDLE,
            OsStr::new(leaf.name()),
            desired_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            create_if_missing,
        )?;
        identity_of(&file, false)?;
        crate::wal::win_native::verify_private_file_handle(&file)?;
        Ok(file)
    }

    /// Deletes only an allow-listed leaf using a child handle rooted at this
    /// directory.  The native helper holds a no-delete parent capability and
    /// marks the opened child for delete; no post-check path operation occurs.
    pub(super) fn delete_leaf(&self, leaf: ContextLeaf) -> io::Result<()> {
        crate::wal::win_native::delete_private_child_file_relative(
            self.directory.as_raw_handle() as HANDLE,
            OsStr::new(leaf.name()),
        )
    }
}

pub(super) fn identity_of(file: &File, expect_directory: bool) -> io::Result<FileIdentity> {
    let handle = file.as_raw_handle() as HANDLE;
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid context capability handle",
        ));
    }
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let attributes = info.dwFileAttributes;
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "context capability is a reparse point",
        ));
    }
    let is_directory = attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    if is_directory != expect_directory {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "context capability object type changed",
        ));
    }
    let file_index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
    if file_index == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "context volume lacks a stable file identity",
        ));
    }
    Ok(FileIdentity {
        volume_serial: info.dwVolumeSerialNumber,
        file_index,
    })
}

const FILE_READ_DATA: u32 = 0x0000_0001;
const FILE_WRITE_DATA: u32 = 0x0000_0002;
const FILE_APPEND_DATA: u32 = 0x0000_0004;
const FILE_READ_EA: u32 = 0x0000_0008;
const FILE_WRITE_EA: u32 = 0x0000_0010;
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
const READ_CONTROL: u32 = 0x0002_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const DUPLICATE_SAME_ACCESS: u32 = 0x0000_0002;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn DuplicateHandle(
        source_process: HANDLE,
        source: HANDLE,
        target_process: HANDLE,
        target: *mut HANDLE,
        desired_access: u32,
        inherit: i32,
        options: u32,
    ) -> i32;
    fn GetCurrentProcess() -> HANDLE;
}
