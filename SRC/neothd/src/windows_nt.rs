//! Canonical Windows NT file-open ABI declarations.
//!
//! These definitions are intentionally shared: Rust requires every declaration
//! of an imported symbol to have the same ABI-visible parameter types. Callers
//! retain ownership of their path-validation, sharing, and no-follow policy.

use std::{ffi::c_void, mem::size_of};

use windows_sys::Win32::Foundation::HANDLE;

pub(crate) type NtHandle = HANDLE;

#[repr(C)]
pub(crate) struct NtUnicodeString {
    pub(crate) length: u16,
    pub(crate) maximum_length: u16,
    pub(crate) buffer: *mut u16,
}

#[repr(C)]
pub(crate) struct NtObjectAttributes {
    pub(crate) length: u32,
    pub(crate) root_directory: NtHandle,
    pub(crate) object_name: *mut NtUnicodeString,
    pub(crate) attributes: u32,
    pub(crate) security_descriptor: *mut c_void,
    pub(crate) security_quality_of_service: *mut c_void,
}

#[repr(C)]
pub(crate) union NtIoStatusValue {
    pub(crate) status: i32,
    pub(crate) pointer: *mut c_void,
}

#[repr(C)]
pub(crate) struct NtIoStatusBlock {
    pub(crate) value: NtIoStatusValue,
    pub(crate) information: usize,
}

impl NtIoStatusBlock {
    pub(crate) const fn zeroed() -> Self {
        Self {
            value: NtIoStatusValue { status: 0 },
            information: 0,
        }
    }
}

// These layout checks cover both supported pointer widths: NT's UNICODE_STRING
// and IO_STATUS_BLOCK each occupy two pointer words, while OBJECT_ATTRIBUTES
// occupies six. They fail at compile time before an incompatible FFI call can
// be emitted.
const _: () = assert!(size_of::<NtUnicodeString>() == 2 * size_of::<usize>());
const _: () = assert!(size_of::<NtIoStatusBlock>() == 2 * size_of::<usize>());
const _: () = assert!(size_of::<NtObjectAttributes>() == 6 * size_of::<usize>());

#[link(name = "ntdll")]
unsafe extern "system" {
    pub(crate) fn NtCreateFile(
        file_handle: *mut NtHandle,
        desired_access: u32,
        object_attributes: *const NtObjectAttributes,
        io_status_block: *mut NtIoStatusBlock,
        allocation_size: *const i64,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: *const c_void,
        ea_length: u32,
    ) -> i32;
    pub(crate) fn NtOpenFile(
        file_handle: *mut NtHandle,
        desired_access: u32,
        object_attributes: *const NtObjectAttributes,
        io_status_block: *mut NtIoStatusBlock,
        share_access: u32,
        open_options: u32,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_open_structures_match_nt_pointer_word_layout() {
        assert_eq!(size_of::<NtUnicodeString>(), 2 * size_of::<usize>());
        assert_eq!(size_of::<NtIoStatusBlock>(), 2 * size_of::<usize>());
        assert_eq!(size_of::<NtObjectAttributes>(), 6 * size_of::<usize>());
    }
}
