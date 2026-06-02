//! Post-Provider hook plugin — NEOTH WASM plugin example (UX-08).
//!
//! Demonstrates the HOOK-STAGE lifecycle: a plugin whose manifest declares
//! `hook_stages = ["post_provider"]` is invoked by the daemon's hook dispatcher
//! AFTER a provider produces a response, so it can observe (read-only) what the
//! model returned. This is the wasm-plugin analogue of a TOML PostProvider hook.
//!
//! It also shows the **fuel-budget pattern** the `echo` example only mentions:
//! read `neoth.fuel_left()` and short-circuit before any expensive work when the
//! budget is nearly exhausted, so a plugin degrades gracefully instead of
//! tripping the host fuel-trap mid-computation.
//!
//! ## Build
//!
//! ```sh
//! cargo build --target wasm32-unknown-unknown --release
//! # Output: target/wasm32-unknown-unknown/release/neoth_plugin_hook_post_provider.wasm
//! ```
//!
//! ## Activation
//!
//! Copy the `.wasm` to `~/.neoth/plugins/hook_post_provider/plugin.wasm` next to
//! the `plugin.toml` in this directory, then:
//!
//! ```sh
//! neoth plugin enable hook_post_provider
//! ```
//!
//! The plugin starts as PENDING (D-102 default-inactive contract);
//! `neoth plugin enable` is the only activation path.

#![no_std]
#![no_main]

// ── hostcall imports ────────────────────────────────────────────────────────
// The host (neothd) binds these in the "neoth" namespace. Signatures must match
// exactly what `wasm_plugin/hostcalls.rs` registers.

extern "C" {
    /// Write a diagnostic log line. `ptr` + `len` point into this plugin's
    /// linear memory; the host reads UTF-8 (lossy) under target `"wasm_plugin"`.
    fn log(ptr: i32, len: i32);

    /// Remaining fuel budget. Plugins read this to short-circuit before
    /// expensive work when the budget is almost exhausted.
    fn fuel_left() -> i64;
}

// ── static messages (no_std ⇒ no heap; embed as static byte slices) ──────────
static MSG_OBSERVED: &[u8] = b"hook_post_provider: observed a PostProvider stage";
static MSG_LOW_FUEL: &[u8] = b"hook_post_provider: fuel low - skipping extra work";
static MSG_DONE: &[u8] = b"hook_post_provider: observation complete";

/// Below this many fuel units, skip the (illustrative) extra work.
const FUEL_FLOOR: i64 = 10_000;

/// Write a log line via the host.
///
/// # Safety
/// `msg` must be a valid byte slice in this plugin's linear memory. The host
/// bounds-checks `ptr + len` against the linear-memory size, so a bad slice is
/// rejected there rather than causing UB in the host process.
#[inline]
unsafe fn host_log(msg: &[u8]) {
    unsafe { log(msg.as_ptr() as i32, msg.len() as i32) }
}

// ── entry point ─────────────────────────────────────────────────────────────

/// The host invokes this when the PostProvider stage fires. ABI: `() -> i32`.
/// Return 0 for success; non-zero is recorded by the dispatcher but is not
/// treated as a fatal error.
#[unsafe(no_mangle)]
pub extern "C" fn neoth_run() -> i32 {
    // SAFETY: every `host_log` arg is a `&'static [u8]` with a valid ptr+len;
    // `fuel_left` takes no memory args.
    unsafe {
        host_log(MSG_OBSERVED);

        // Budget-aware: bail before expensive work when fuel is nearly gone.
        if fuel_left() < FUEL_FLOOR {
            host_log(MSG_LOW_FUEL);
            return 0;
        }

        // A real PostProvider hook would inspect / annotate the provider
        // response here (read-only). This example just records completion.
        host_log(MSG_DONE);
    }
    0
}

// ── panic handler ───────────────────────────────────────────────────────────
// Required by no_std. The host fuel-trap catches runaway loops before any
// panic, but a panic handler must exist at link time.
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
