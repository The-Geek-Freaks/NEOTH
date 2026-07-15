//! Versioned guest-side ABI for NEOTH Wasmtime plugins.
//!
//! This module is the public bridge between a Rust plugin compiled for
//! `wasm32-unknown-unknown` and the imports/exports implemented by `neothd`.
//! [`GuestHost`] uses the SDK permission lattice to catch accidental hostcall
//! misuse in Rust code. It is not runtime authority: the daemon independently
//! checks the operator-approved `HostcallPermission` on every hostcall.

use std::marker::PhantomData;

use crate::permission::{AtLeast, PermissionLevel, ReadOnly, Write};

/// Current NEOTH guest ABI version.
///
/// Plugins export this value through [`ABI_VERSION_EXPORT`]. The host refuses
/// missing or different versions before calling [`RUN_EXPORT`].
pub const ABI_VERSION: i32 = 1;

/// Wasmtime import module containing all NEOTH hostcalls.
pub const IMPORT_MODULE: &str = "neoth";
/// Required guest export returning [`ABI_VERSION`].
pub const ABI_VERSION_EXPORT: &str = "neoth_abi_version";
/// Required guest entry-point export with signature `() -> i32`.
pub const RUN_EXPORT: &str = "neoth_run";
/// Permission-`None` diagnostic hostcall.
pub const HOSTCALL_LOG: &str = "log";
/// Permission-`None` fuel-query hostcall.
pub const HOSTCALL_FUEL_LEFT: &str = "fuel_left";
/// Permission-`Write` WAL-event hostcall.
pub const HOSTCALL_EMIT_EVENT: &str = "emit_event";
/// Permission-`ReadOnly` recall-count hostcall.
pub const HOSTCALL_RECALL_TOP: &str = "recall_top";

/// Error returned by a safe guest hostcall wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HostcallError {
    /// Guest hostcalls are only available when compiling to WebAssembly.
    #[error("NEOTH guest hostcalls require target wasm32-unknown-unknown")]
    UnsupportedTarget,
    /// A byte slice cannot be represented by the ABI's signed 32-bit length.
    #[error("hostcall input exceeds i32::MAX bytes")]
    InputTooLong,
    /// The guest passed a pointer/length pair outside its exported memory.
    #[error("host rejected an out-of-bounds guest-memory range")]
    MemoryBounds,
    /// Event kind exceeds the host limit.
    #[error("host rejected an overlong event kind")]
    KindTooLong,
    /// Event payload exceeds the host limit.
    #[error("host rejected an overlong event payload")]
    PayloadTooLong,
    /// WAL writer queue is full.
    #[error("host WAL writer is backpressured")]
    Backpressured,
    /// WAL writer is closed during daemon shutdown.
    #[error("host WAL writer is closed")]
    WriterClosed,
    /// Host failed to append the event for another reason.
    #[error("host failed to append the event")]
    AppendFailed,
    /// Operator-approved runtime permission is below the hostcall requirement.
    #[error("host denied the call because the approved permission is too low")]
    PermissionDenied,
    /// Host returned a status introduced by a newer ABI.
    #[error("host returned unknown status code {0}")]
    UnknownStatus(i32),
}

/// Safe guest-side access to NEOTH hostcalls at declared marker level `L`.
///
/// The type parameter provides compile-time API guidance: for example,
/// `recall_top` is unavailable below `ReadOnly`, and `emit_event` is unavailable
/// below `Write`. A plugin can choose any marker, so this is deliberately not a
/// security primitive. The manifest approval bound by the host remains the
/// runtime authority.
#[derive(Clone, Copy, Debug)]
pub struct GuestHost<L: PermissionLevel> {
    _level: PhantomData<L>,
}

impl<L: PermissionLevel> GuestHost<L> {
    /// Construct the guest handle used by [`export_wasm_plugin!`].
    ///
    /// Public because exported macro expansion occurs in the plugin crate. The
    /// value is zero-sized API guidance, not an authorization token.
    #[doc(hidden)]
    pub const fn for_export() -> Self {
        Self {
            _level: PhantomData,
        }
    }

    /// Write diagnostic bytes through `neoth.log`.
    pub fn log(self, message: &[u8]) -> Result<(), HostcallError> {
        let len = abi_len(message.len())?;
        call_log(message.as_ptr(), len)
    }

    /// Read remaining Wasmtime fuel.
    pub fn fuel_left(self) -> Result<u64, HostcallError> {
        call_fuel_left().map(|fuel| fuel.max(0) as u64)
    }
}

impl<L> GuestHost<L>
where
    L: PermissionLevel + AtLeast<ReadOnly>,
{
    /// Return the number of recall rows matching `prompt_hash`.
    ///
    /// The host deliberately returns `0` both for no hits and a denied read;
    /// denials remain operator-visible through the WAL capability-denied event.
    pub fn recall_top(self, prompt_hash: u64) -> Result<u32, HostcallError> {
        call_recall_top(prompt_hash as i64).map(|hits| hits.max(0) as u32)
    }
}

impl<L> GuestHost<L>
where
    L: PermissionLevel + AtLeast<Write>,
{
    /// Append an operator-auditable plugin event through `neoth.emit_event`.
    pub fn emit_event(self, kind: &[u8], payload: &[u8]) -> Result<(), HostcallError> {
        let kind_len = abi_len(kind.len())?;
        let payload_len = abi_len(payload.len())?;
        let status = call_emit_event(kind.as_ptr(), kind_len, payload.as_ptr(), payload_len)?;
        emit_event_status(status)
    }
}

/// Convert a plugin entry-point result into the ABI return code.
///
/// `0` means success; any `Err` becomes `1`, which the host treats as a failed
/// invocation. Plugins needing richer diagnostics should call [`GuestHost::log`]
/// before returning an error.
pub trait IntoRunCode {
    /// Convert into the signed 32-bit `neoth_run` result.
    fn into_run_code(self) -> i32;
}

impl IntoRunCode for () {
    fn into_run_code(self) -> i32 {
        0
    }
}

impl<E> IntoRunCode for Result<(), E> {
    fn into_run_code(self) -> i32 {
        if self.is_ok() { 0 } else { 1 }
    }
}

/// Export a versioned NEOTH Wasmtime plugin entry point.
///
/// The entry function must accept one [`GuestHost<L>`] and return either `()`
/// or `Result<(), E>`. The macro exports both `neoth_abi_version() -> i32` and
/// `neoth_run() -> i32` with stable C symbol names.
///
/// ```ignore
/// use neoth_plugin_sdk::guest::GuestHost;
/// use neoth_plugin_sdk::permission::ReadOnly;
///
/// fn run(host: GuestHost<ReadOnly>) -> Result<(), neoth_plugin_sdk::guest::HostcallError> {
///     let _hits = host.recall_top(42)?;
///     Ok(())
/// }
///
/// neoth_plugin_sdk::export_wasm_plugin!(ReadOnly, run);
/// ```
#[macro_export]
macro_rules! export_wasm_plugin {
    ($level:ty, $entry:path) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn neoth_abi_version() -> i32 {
            $crate::guest::ABI_VERSION
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn neoth_run() -> i32 {
            $crate::guest::IntoRunCode::into_run_code($entry(
                $crate::guest::GuestHost::<$level>::for_export(),
            ))
        }
    };
}

fn abi_len(len: usize) -> Result<i32, HostcallError> {
    i32::try_from(len).map_err(|_| HostcallError::InputTooLong)
}

fn emit_event_status(status: i32) -> Result<(), HostcallError> {
    match status {
        0 => Ok(()),
        1 => Err(HostcallError::MemoryBounds),
        2 => Err(HostcallError::KindTooLong),
        3 => Err(HostcallError::PayloadTooLong),
        4 => Err(HostcallError::Backpressured),
        5 => Err(HostcallError::WriterClosed),
        6 => Err(HostcallError::AppendFailed),
        7 => Err(HostcallError::PermissionDenied),
        other => Err(HostcallError::UnknownStatus(other)),
    }
}

#[cfg(target_arch = "wasm32")]
#[allow(unsafe_code)]
mod imports {
    #[link(wasm_import_module = "neoth")]
    unsafe extern "C" {
        fn log(ptr: i32, len: i32);
        fn fuel_left() -> i64;
        fn emit_event(kind_ptr: i32, kind_len: i32, payload_ptr: i32, payload_len: i32) -> i32;
        fn recall_top(prompt_hash: i64) -> i32;
    }

    pub(super) fn call_log(ptr: *const u8, len: i32) {
        // SAFETY: wasm32 pointers are 32-bit offsets into the guest's linear
        // memory. The host validates the complete pointer/length range before
        // reading it.
        unsafe { log(ptr as i32, len) }
    }

    pub(super) fn call_fuel_left() -> i64 {
        // SAFETY: exact zero-argument ABI imported from the versioned host.
        unsafe { fuel_left() }
    }

    pub(super) fn call_emit_event(
        kind_ptr: *const u8,
        kind_len: i32,
        payload_ptr: *const u8,
        payload_len: i32,
    ) -> i32 {
        // SAFETY: both slices remain borrowed for the call and the host checks
        // both ranges against exported guest memory before reading.
        unsafe { emit_event(kind_ptr as i32, kind_len, payload_ptr as i32, payload_len) }
    }

    pub(super) fn call_recall_top(prompt_hash: i64) -> i32 {
        // SAFETY: exact scalar ABI imported from the versioned host.
        unsafe { recall_top(prompt_hash) }
    }
}

#[cfg(target_arch = "wasm32")]
fn call_log(ptr: *const u8, len: i32) -> Result<(), HostcallError> {
    imports::call_log(ptr, len);
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn call_log(_ptr: *const u8, _len: i32) -> Result<(), HostcallError> {
    Err(HostcallError::UnsupportedTarget)
}

#[cfg(target_arch = "wasm32")]
fn call_fuel_left() -> Result<i64, HostcallError> {
    Ok(imports::call_fuel_left())
}

#[cfg(not(target_arch = "wasm32"))]
fn call_fuel_left() -> Result<i64, HostcallError> {
    Err(HostcallError::UnsupportedTarget)
}

#[cfg(target_arch = "wasm32")]
fn call_emit_event(
    kind_ptr: *const u8,
    kind_len: i32,
    payload_ptr: *const u8,
    payload_len: i32,
) -> Result<i32, HostcallError> {
    Ok(imports::call_emit_event(
        kind_ptr,
        kind_len,
        payload_ptr,
        payload_len,
    ))
}

#[cfg(not(target_arch = "wasm32"))]
fn call_emit_event(
    _kind_ptr: *const u8,
    _kind_len: i32,
    _payload_ptr: *const u8,
    _payload_len: i32,
) -> Result<i32, HostcallError> {
    Err(HostcallError::UnsupportedTarget)
}

#[cfg(target_arch = "wasm32")]
fn call_recall_top(prompt_hash: i64) -> Result<i32, HostcallError> {
    Ok(imports::call_recall_top(prompt_hash))
}

#[cfg(not(target_arch = "wasm32"))]
fn call_recall_top(_prompt_hash: i64) -> Result<i32, HostcallError> {
    Err(HostcallError::UnsupportedTarget)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permission::{Dangerous, None as NoPermission, ReadOnly, Write};

    #[test]
    fn abi_v1_names_are_pinned() {
        assert_eq!(ABI_VERSION, 1);
        assert_eq!(IMPORT_MODULE, "neoth");
        assert_eq!(ABI_VERSION_EXPORT, "neoth_abi_version");
        assert_eq!(RUN_EXPORT, "neoth_run");
        assert_eq!(HOSTCALL_LOG, "log");
        assert_eq!(HOSTCALL_FUEL_LEFT, "fuel_left");
        assert_eq!(HOSTCALL_EMIT_EVENT, "emit_event");
        assert_eq!(HOSTCALL_RECALL_TOP, "recall_top");
    }

    #[test]
    fn emit_event_status_is_exhaustive_and_fail_closed() {
        assert_eq!(emit_event_status(0), Ok(()));
        assert_eq!(emit_event_status(7), Err(HostcallError::PermissionDenied));
        assert_eq!(emit_event_status(99), Err(HostcallError::UnknownStatus(99)));
    }

    #[test]
    fn entry_result_maps_to_host_status() {
        assert_eq!(().into_run_code(), 0);
        assert_eq!(Result::<(), ()>::Ok(()).into_run_code(), 0);
        assert_eq!(Result::<(), ()>::Err(()).into_run_code(), 1);
    }

    #[test]
    fn permission_markers_expose_expected_positive_surface() {
        fn none_surface(host: GuestHost<NoPermission>) {
            let _ = host.log(b"diagnostic");
            let _ = host.fuel_left();
        }
        fn read_surface(host: GuestHost<ReadOnly>) {
            let _ = host.recall_top(1);
        }
        fn write_surface(host: GuestHost<Write>) {
            let _ = host.recall_top(1);
            let _ = host.emit_event(b"kind", b"payload");
        }
        fn dangerous_inherits_surface(host: GuestHost<Dangerous>) {
            let _ = host.recall_top(1);
            let _ = host.emit_event(b"kind", b"payload");
        }

        none_surface(GuestHost::for_export());
        read_surface(GuestHost::for_export());
        write_surface(GuestHost::for_export());
        dangerous_inherits_surface(GuestHost::for_export());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn native_calls_refuse_instead_of_faking_a_host() {
        let host = GuestHost::<NoPermission>::for_export();
        assert_eq!(host.log(b"x"), Err(HostcallError::UnsupportedTarget));
        assert_eq!(host.fuel_left(), Err(HostcallError::UnsupportedTarget));
    }
}
