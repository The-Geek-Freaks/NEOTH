//! Echo plugin — minimal NEOTH WASM plugin example.
//!
//! Demonstrates the Phase-1 hostcall ABI:
//!   - `neoth.log(ptr, len)` — write a diagnostic line to the host log
//!   - `neoth.fuel_left() -> i64` — read remaining fuel budget
//!
//! ## Build
//!
//! ```sh
//! cargo build --target wasm32-unknown-unknown --release
//! # Output: target/wasm32-unknown-unknown/release/neoth_plugin_echo.wasm
//! ```
//!
//! ## Activation
//!
//! Copy the `.wasm` to `~/.neoth/plugins/echo/plugin.wasm` plus a
//! matching `plugin.toml` manifest.  Then:
//!
//! ```sh
//! neoth plugin enable echo
//! ```
//!
//! The plugin starts as PENDING (D-102 default-inactive contract);
//! `neoth plugin enable` is the only activation path.

#![no_std]
#![no_main]

// ── hostcall imports ────────────────────────────────────────────────────────
// The host (neothd) binds these in the "neoth" namespace.
// Types must match exactly what `wasm_plugin/hostcalls.rs` registers.

extern "C" {
    /// Write a diagnostic log line. `ptr` + `len` point into this
    /// plugin's linear memory. The host reads UTF-8 (lossy) and emits
    /// a `tracing::info!` under target `"wasm_plugin"`.
    fn log(ptr: i32, len: i32);

    /// Returns remaining fuel as i64. Plugins use this to short-circuit
    /// before expensive work when the budget is almost exhausted.
    #[allow(dead_code)]
    fn fuel_left() -> i64;
}

// ── static message ──────────────────────────────────────────────────────────
// no_std means no heap; embed the message as a static byte slice.
static MSG: &[u8] = b"echo: neoth_run called";

// ── entry point ─────────────────────────────────────────────────────────────

/// The host invokes this function when the plugin is triggered.
/// ABI: `() -> i32`. Return 0 for success; non-zero values are
/// recorded by the dispatcher but not treated as fatal errors.
#[unsafe(no_mangle)]
pub extern "C" fn neoth_run() -> i32 {
    // SAFETY: MSG is a &[u8] with known valid pointer + length.
    // The host's `neoth.log` hostcall reads only `len` bytes from `ptr`
    // (bounds-checked in `wasm_plugin/hostcalls.rs::read_slice`).
    unsafe {
        log(MSG.as_ptr() as i32, MSG.len() as i32);
    }
    0
}

// ── panic handler ─────────────────────────────────────────────────────────
// Required by no_std. The host fuel-trap catches infinite loops before
// any panic, but a panic handler must exist at link time.
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
