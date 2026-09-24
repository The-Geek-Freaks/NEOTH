//! Windows handle-relative history-import source capture.
//!
//! The public bridge lives in the parent module. This implementation never
//! reopens a selected path through the ambient namespace after root approval:
//! every descendant component is opened relative to a retained ancestor handle
//! with delete sharing withheld and `FILE_OPEN_REPARSE_POINT` set.

use std::{
    ffi::OsStr,
    fs::File,
    io::Read,
    mem::{MaybeUninit, size_of},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Component, Path},
    ptr::{null, null_mut},
};

/// A regular file retained with write/delete sharing withheld.  The bytes are
/// captured from this same handle so an external Windows consumer can safely
/// use its still-named path while the guard stays alive.
pub(super) struct WindowsApprovedFile {
    _opened: OpenedLeaf,
    bytes: zeroize::Zeroizing<Vec<u8>>,
}

impl WindowsApprovedFile {
    pub(super) fn bytes(&self) -> &[u8] { &self.bytes }
}

use windows_sys::Win32::{
    Foundation::{HANDLE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_BASIC_INFO, FILE_ID_INFO,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO, FILE_TYPE_DISK, FileBasicInfo,
        FileIdInfo, FileStandardInfo, GetDriveTypeW, GetFileInformationByHandleEx, GetFileType,
    },
};

#[cfg(test)]
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_DELETE;

use super::{
    ApprovedImportRoot, BoundSourceIdentity, LocalImportError, PhysicalFileId, checked_len,
    validate_relative_selection,
};
use crate::windows_nt::{
    NtCreateFile, NtIoStatusBlock, NtObjectAttributes, NtOpenFile, NtUnicodeString,
};

// Win32 GetDriveTypeW returns DRIVE_FIXED (3) for a fixed disk:
// https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-getdrivetypew
const DRIVE_FIXED: u32 = 3;
const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
const FILE_OPEN: u32 = 0x0000_0001;
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
const FILE_OPEN_FOR_BACKUP_INTENT: u32 = 0x0000_4000;
const FILE_READ_DATA: u32 = 0x0000_0001;
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const SYNCHRONIZE: u32 = 0x0010_0000;

/// Retains every component of an approved root. These are deliberate delete
/// fences: no handle includes `FILE_SHARE_DELETE`, so a rename/delete cannot
/// exchange an ancestor after its identity was accepted.
pub(super) struct WindowsApprovedRoot {
    ancestors: Vec<File>,
}

impl WindowsApprovedRoot {
    fn root(&self) -> Result<&File, LocalImportError> {
        self.ancestors.last().ok_or(LocalImportError::Unavailable)
    }
}

struct OpenedLeaf {
    leaf: File,
    leaf_snapshot: WindowsSnapshot,
    ancestor_ids: Vec<PhysicalFileId>,
    _ancestor_fences: Vec<File>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WindowsSnapshot {
    identity: PhysicalFileId,
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
    attributes: u32,
    allocation_size: i64,
    end_of_file: i64,
    link_count: u32,
    delete_pending: u8,
    directory: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DriveRootNames {
    win32: [u16; 3],
    native: [u16; 7],
}

pub(super) fn open_approved_root(path: &Path) -> Result<ApprovedImportRoot, LocalImportError> {
    let drive = drive_root_names(path)?;
    ensure_local_drive(&drive.win32)?;
    let mut ancestors = vec![open_absolute_directory(&drive.native)?];
    let current = ancestors.last().ok_or(LocalImportError::Unavailable)?;
    let mut current_identity = directory_snapshot(current)?.identity;

    for component in path.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        let parent = ancestors.last().ok_or(LocalImportError::Unavailable)?;
        let child = open_child_directory(parent, name)?;
        current_identity = directory_snapshot(&child)?.identity;
        ancestors.push(child);
    }

    Ok(ApprovedImportRoot {
        handle: WindowsApprovedRoot { ancestors },
        identity: current_identity,
    })
}

pub(super) fn verify_approved_root_handle(
    root: &ApprovedImportRoot,
    directory: &File,
) -> Result<(), LocalImportError> {
    let approved = root.handle.root()?;
    if directory_snapshot(approved)?.identity != directory_snapshot(directory)?.identity {
        return Err(LocalImportError::ChangedDuringRead);
    }
    Ok(())
}

pub(super) fn read_bound_source(
    root: &ApprovedImportRoot,
    path: &Path,
    max_bytes: usize,
) -> Result<(Vec<u8>, BoundSourceIdentity), LocalImportError> {
    read_bound_source_with_hook(root, path, max_bytes, || {})
}

pub(super) fn read_bound_source_with_hook(
    root: &ApprovedImportRoot,
    path: &Path,
    max_bytes: usize,
    after_read: impl FnOnce(),
) -> Result<(Vec<u8>, BoundSourceIdentity), LocalImportError> {
    let mut opened = open_relative_leaf(root, path)?;
    let before = opened.leaf_snapshot;
    let expected_len = checked_len(before.end_of_file as u64, max_bytes)?;
    let mut raw = Vec::with_capacity(expected_len);
    opened
        .leaf
        .by_ref()
        .take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut raw)
        .map_err(|_| LocalImportError::Unavailable)?;
    if raw.len() > max_bytes {
        return Err(LocalImportError::SizeLimitExceeded);
    }
    if raw.len() != expected_len {
        return Err(LocalImportError::ChangedDuringRead);
    }
    after_read();
    if file_snapshot(&opened.leaf)? != before {
        return Err(LocalImportError::ChangedDuringRead);
    }

    let rebound = open_relative_leaf(root, path)?;
    if rebound.ancestor_ids != opened.ancestor_ids || rebound.leaf_snapshot != before {
        return Err(LocalImportError::ChangedDuringRead);
    }
    Ok((
        raw,
        BoundSourceIdentity {
            root: root.identity,
            source: before.identity,
        },
    ))
}

fn drive_root_names(path: &Path) -> Result<DriveRootNames, LocalImportError> {
    let Some(Component::Prefix(prefix)) = path.components().next() else {
        return Err(LocalImportError::ForbiddenPathPrefix);
    };
    let std::path::Prefix::Disk(letter) = prefix.kind() else {
        return Err(LocalImportError::ForbiddenPathPrefix);
    };
    let letter = letter as u16;
    Ok(DriveRootNames {
        win32: [letter, b':' as u16, b'\\' as u16],
        native: [
            b'\\' as u16,
            b'?' as u16,
            b'?' as u16,
            b'\\' as u16,
            letter,
            b':' as u16,
            b'\\' as u16,
        ],
    })
}

fn ensure_local_drive(drive: &[u16; 3]) -> Result<(), LocalImportError> {
    let mut terminated = drive.to_vec();
    terminated.push(0);
    // SAFETY: `terminated` is a NUL-terminated `X:\\` root path that stays
    // live for the complete Win32 query.
    if unsafe { GetDriveTypeW(terminated.as_ptr()) } != DRIVE_FIXED {
        return Err(LocalImportError::RemoteOrUnknownFilesystem);
    }
    Ok(())
}

fn open_relative_leaf(
    root: &ApprovedImportRoot,
    path: &Path,
) -> Result<OpenedLeaf, LocalImportError> {
    open_relative_leaf_with_share(root, path, false)
}

fn open_relative_leaf_with_readonly_file(
    root: &ApprovedImportRoot,
    path: &Path,
) -> Result<OpenedLeaf, LocalImportError> {
    open_relative_leaf_with_share(root, path, true)
}

fn open_relative_leaf_with_share(
    root: &ApprovedImportRoot,
    path: &Path,
    readonly_file: bool,
) -> Result<OpenedLeaf, LocalImportError> {
    validate_relative_selection(path)?;
    let root_handle = root
        .handle
        .root()?
        .try_clone()
        .map_err(|_| LocalImportError::Unavailable)?;
    let root_snapshot = directory_snapshot(&root_handle)?;
    if root_snapshot.identity != root.identity {
        return Err(LocalImportError::ChangedDuringRead);
    }
    let mut fences = vec![root_handle];
    let mut ancestor_ids = vec![root_snapshot.identity];
    let mut components = path.components().peekable();
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(LocalImportError::OutsideApprovedRoot);
        };
        let parent = fences.last().ok_or(LocalImportError::Unavailable)?;
        if components.peek().is_some() {
            let child = open_child_directory(parent, name)?;
            ancestor_ids.push(directory_snapshot(&child)?.identity);
            fences.push(child);
        } else {
            let leaf = if readonly_file { open_child_file_readonly(parent, name)? } else { open_child_file(parent, name)? };
            let leaf_snapshot = file_snapshot(&leaf)?;
            return Ok(OpenedLeaf {
                leaf,
                leaf_snapshot,
                ancestor_ids,
                _ancestor_fences: fences,
            });
        }
    }
    Err(LocalImportError::OutsideApprovedRoot)
}

fn open_absolute_directory(path: &[u16; 7]) -> Result<File, LocalImportError> {
    nt_create(path, null_mut(), true)
}

fn open_child_directory(parent: &File, name: &OsStr) -> Result<File, LocalImportError> {
    nt_open(name, parent.as_raw_handle() as HANDLE, true)
}

fn open_child_file(parent: &File, name: &OsStr) -> Result<File, LocalImportError> {
    nt_open(name, parent.as_raw_handle() as HANDLE, false)
}
fn open_child_file_readonly(parent: &File, name: &OsStr) -> Result<File, LocalImportError> {
    nt_open_with_share(name, parent.as_raw_handle() as HANDLE, false, FILE_SHARE_READ)
}

fn nt_create(name: &[u16], root: HANDLE, directory: bool) -> Result<File, LocalImportError> {
    let mut unicode = unicode_string(name)?;
    let attributes = object_attributes(&mut unicode, root);
    let mut handle: HANDLE = null_mut();
    let mut status = NtIoStatusBlock::zeroed();
    let options = open_options(directory);
    // SAFETY: the UTF-16 backing slice and all output buffers stay alive for
    // the call. A successful HANDLE is transferred immediately to `File`.
    let result = unsafe {
        NtCreateFile(
            &mut handle,
            desired_access(directory),
            &attributes,
            &mut status,
            null(),
            0,
            share_mode(),
            FILE_OPEN,
            options,
            null(),
            0,
        )
    };
    nt_result(result, handle)
}

fn nt_open(name: &OsStr, root: HANDLE, directory: bool) -> Result<File, LocalImportError> {
    nt_open_with_share(name, root, directory, share_mode())
}

fn nt_open_with_share(name: &OsStr, root: HANDLE, directory: bool, share: u32) -> Result<File, LocalImportError> {
    let wide: Vec<u16> = name.encode_wide().collect();
    reject_component(&wide)?;
    let mut unicode = unicode_string(&wide)?;
    let attributes = object_attributes(&mut unicode, root);
    let mut handle: HANDLE = null_mut();
    let mut status = NtIoStatusBlock::zeroed();
    // SAFETY: see `nt_create`; this is only a relative, single-component
    // open rooted in a retained, already-validated handle.
    let result = unsafe {
        NtOpenFile(
            &mut handle,
            desired_access(directory),
            &attributes,
            &mut status,
            share,
            open_options(directory),
        )
    };
    nt_result(result, handle)
}

pub(super) fn hold_approved_regular_file(root: &ApprovedImportRoot, path: &Path, max_bytes: usize) -> Result<WindowsApprovedFile, LocalImportError> {
    let mut opened = open_relative_leaf_with_readonly_file(root, path)?;
    let before = opened.leaf_snapshot;
    let expected_len = checked_len(before.end_of_file as u64, max_bytes)?;
    let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(expected_len));
    opened.leaf.by_ref().take((max_bytes as u64).saturating_add(1)).read_to_end(&mut bytes).map_err(|_| LocalImportError::Unavailable)?;
    if bytes.len() != expected_len || bytes.len() > max_bytes || file_snapshot(&opened.leaf)? != before { return Err(LocalImportError::ChangedDuringRead); }
    Ok(WindowsApprovedFile { _opened: opened, bytes })
}

fn unicode_string(name: &[u16]) -> Result<NtUnicodeString, LocalImportError> {
    let byte_length = name
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|value| u16::try_from(value).ok())
        .ok_or(LocalImportError::OutsideApprovedRoot)?;
    Ok(NtUnicodeString {
        length: byte_length,
        maximum_length: byte_length,
        buffer: name.as_ptr().cast_mut(),
    })
}

fn object_attributes(unicode: &mut NtUnicodeString, root: HANDLE) -> NtObjectAttributes {
    NtObjectAttributes {
        length: u32::try_from(size_of::<NtObjectAttributes>()).unwrap_or(u32::MAX),
        root_directory: root,
        object_name: unicode,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: null_mut(),
        security_quality_of_service: null_mut(),
    }
}

fn desired_access(directory: bool) -> u32 {
    FILE_READ_ATTRIBUTES | SYNCHRONIZE | if directory { 0 } else { FILE_READ_DATA }
}

fn open_options(directory: bool) -> u32 {
    FILE_OPEN_REPARSE_POINT
        | FILE_SYNCHRONOUS_IO_NONALERT
        | FILE_OPEN_FOR_BACKUP_INTENT
        | if directory {
            FILE_DIRECTORY_FILE
        } else {
            FILE_NON_DIRECTORY_FILE
        }
}

fn share_mode() -> u32 {
    FILE_SHARE_READ | FILE_SHARE_WRITE
}

fn nt_result(status: i32, handle: HANDLE) -> Result<File, LocalImportError> {
    if status < 0 || native_handle_is_invalid(handle) {
        return Err(LocalImportError::Unavailable);
    }
    // SAFETY: successful Nt*File transfers exactly one owned Win32 HANDLE.
    Ok(unsafe { File::from_raw_handle(handle as _) })
}

fn native_handle_is_invalid(handle: HANDLE) -> bool {
    handle.is_null() || handle == INVALID_HANDLE_VALUE
}

fn directory_snapshot(handle: &File) -> Result<WindowsSnapshot, LocalImportError> {
    let snapshot = raw_snapshot(handle)?;
    if snapshot.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(LocalImportError::SymlinkOrReparsePoint);
    }
    if snapshot.directory == 0 || snapshot.attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(LocalImportError::NotRegularFile);
    }
    Ok(snapshot)
}

fn file_snapshot(handle: &File) -> Result<WindowsSnapshot, LocalImportError> {
    let snapshot = raw_snapshot(handle)?;
    if snapshot.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(LocalImportError::SymlinkOrReparsePoint);
    }
    if snapshot.directory != 0 || snapshot.attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Err(LocalImportError::NotRegularFile);
    }
    if snapshot.link_count != 1 {
        return Err(LocalImportError::MultipleHardLinks);
    }
    if snapshot.end_of_file < 0 || snapshot.allocation_size < 0 {
        return Err(LocalImportError::ChangedDuringRead);
    }
    Ok(snapshot)
}

fn raw_snapshot(handle: &File) -> Result<WindowsSnapshot, LocalImportError> {
    let raw = handle.as_raw_handle() as HANDLE;
    if unsafe { GetFileType(raw) } != FILE_TYPE_DISK {
        return Err(LocalImportError::NotRegularFile);
    }
    let basic = file_information::<FILE_BASIC_INFO>(raw, FileBasicInfo)?;
    let standard = file_information::<FILE_STANDARD_INFO>(raw, FileStandardInfo)?;
    let identifier = file_information::<FILE_ID_INFO>(raw, FileIdInfo)?;
    let object = identifier.FileId.Identifier;
    if !valid_identity(identifier.VolumeSerialNumber, &object) {
        return Err(LocalImportError::Unavailable);
    }
    Ok(WindowsSnapshot {
        identity: PhysicalFileId {
            volume: identifier.VolumeSerialNumber,
            object,
        },
        creation_time: basic.CreationTime,
        last_access_time: basic.LastAccessTime,
        last_write_time: basic.LastWriteTime,
        change_time: basic.ChangeTime,
        attributes: basic.FileAttributes,
        allocation_size: standard.AllocationSize,
        end_of_file: standard.EndOfFile,
        link_count: standard.NumberOfLinks,
        delete_pending: standard.DeletePending,
        directory: standard.Directory,
    })
}

fn file_information<T>(handle: HANDLE, class: i32) -> Result<T, LocalImportError> {
    let mut information = MaybeUninit::<T>::uninit();
    let length = u32::try_from(size_of::<T>()).map_err(|_| LocalImportError::Unavailable)?;
    // SAFETY: the output allocation is large enough for the requested fixed
    // information class and `handle` is owned by a live `File`.
    if unsafe {
        GetFileInformationByHandleEx(handle, class, information.as_mut_ptr().cast(), length)
    } == 0
    {
        return Err(LocalImportError::Unavailable);
    }
    // SAFETY: a successful fixed-size GetFileInformationByHandleEx call fully
    // initializes the supplied information record.
    Ok(unsafe { information.assume_init() })
}

fn reject_component(component: &[u16]) -> Result<(), LocalImportError> {
    if component.is_empty()
        || component
            .iter()
            .any(|value| *value == 0 || *value == b':' as u16)
        || component.last() == Some(&(b'.' as u16))
    {
        return Err(LocalImportError::OutsideApprovedRoot);
    }
    Ok(())
}

fn valid_identity(volume: u64, object: &[u8; 16]) -> bool {
    volume != 0 && object.iter().any(|byte| *byte != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_nt_open_uses_native_object_manager_drive_root() {
        let drive = drive_root_names(Path::new(r"C:\approved")).unwrap();
        assert_eq!(String::from_utf16(&drive.win32).unwrap(), r"C:\");
        assert_eq!(String::from_utf16(&drive.native).unwrap(), r"\??\C:\");
        assert_eq!(
            drive.native[0..4],
            [b'\\' as u16, b'?' as u16, b'?' as u16, b'\\' as u16]
        );
    }

    #[test]
    fn native_handle_sentinels_are_rejected_before_file_ownership() {
        assert!(native_handle_is_invalid(null_mut()));
        assert!(native_handle_is_invalid(INVALID_HANDLE_VALUE));
    }

    #[test]
    fn share_mode_is_read_write_only_and_never_permits_delete() {
        assert_eq!(share_mode() & FILE_SHARE_DELETE, 0);
        assert_eq!(share_mode(), FILE_SHARE_READ | FILE_SHARE_WRITE);
    }

    #[test]
    fn every_open_requests_a_reparse_object_instead_of_following_it() {
        for options in [open_options(true), open_options(false)] {
            assert_ne!(options & FILE_OPEN_REPARSE_POINT, 0);
            assert_ne!(options & FILE_SYNCHRONOUS_IO_NONALERT, 0);
        }
        assert_ne!(open_options(true) & FILE_DIRECTORY_FILE, 0);
        assert_ne!(open_options(false) & FILE_NON_DIRECTORY_FILE, 0);
    }

    #[test]
    fn selector_component_rejects_ads_nuls_and_trailing_dots() {
        for component in [
            vec![
                b'e' as u16,
                b'x' as u16,
                b'p' as u16,
                b':' as u16,
                b'x' as u16,
            ],
            vec![b'x' as u16, 0],
            vec![b'x' as u16, b'.' as u16],
            Vec::new(),
        ] {
            assert_eq!(
                reject_component(&component),
                Err(LocalImportError::OutsideApprovedRoot)
            );
        }
        assert!(reject_component(&[b'e' as u16, b'x' as u16, b'p' as u16]).is_ok());
    }

    #[test]
    fn zero_volume_or_file_identifier_is_fail_closed() {
        assert!(!valid_identity(0, &[7; 16]));
        assert!(!valid_identity(7, &[0; 16]));
        assert!(valid_identity(7, &[9; 16]));
    }

    #[test]
    fn held_regular_file_fence_blocks_writer_and_rename() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("compose.yaml");
        std::fs::write(&source, b"pinned-compose").unwrap();
        let approved = open_approved_root(root.path()).unwrap();
        let guard = hold_approved_regular_file(&approved, Path::new("compose.yaml"), 1024).unwrap();
        assert_eq!(guard.bytes(), b"pinned-compose");
        assert!(std::fs::OpenOptions::new().write(true).open(&source).is_err());
        assert!(std::fs::rename(&source, root.path().join("decoy.yaml")).is_err());
        drop(guard);
        assert!(std::fs::OpenOptions::new().write(true).open(&source).is_ok());
    }
}
