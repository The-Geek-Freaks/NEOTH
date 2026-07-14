//! Echo plugin — minimal NEOTH WASM plugin example.
//!
//! Demonstrates the versioned ABI v1 hostcalls:
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

use neoth_plugin_sdk::guest::{GuestHost, HostcallError};
use neoth_plugin_sdk::permission::None as NoPermission;

// ── static message ──────────────────────────────────────────────────────────
// Keep the example allocation-free by embedding the message.
static MSG: &[u8] = b"echo: neoth_run called";

// ── entry point ─────────────────────────────────────────────────────────────

fn run(host: GuestHost<NoPermission>) -> Result<(), HostcallError> {
    host.log(MSG)
}

neoth_plugin_sdk::export_wasm_plugin!(NoPermission, run);
