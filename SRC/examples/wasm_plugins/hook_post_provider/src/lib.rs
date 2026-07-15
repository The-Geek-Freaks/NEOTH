//! Post-Provider hook plugin — NEOTH WASM plugin example (UX-08).
//!
//! Demonstrates the HOOK-STAGE lifecycle. `hook_stages` advertises intended
//! stages; the operator explicitly wires `plugin_id = "hook_post_provider"` in
//! a PostProvider `HookDef` before the dispatcher invokes it.
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

use neoth_plugin_sdk::guest::{GuestHost, HostcallError};
use neoth_plugin_sdk::permission::None as NoPermission;

// ── allocation-free static messages ─────────────────────────────────────────
static MSG_OBSERVED: &[u8] = b"hook_post_provider: observed a PostProvider stage";
static MSG_LOW_FUEL: &[u8] = b"hook_post_provider: fuel low - skipping extra work";
static MSG_DONE: &[u8] = b"hook_post_provider: observation complete";

/// Below this many fuel units, skip the (illustrative) extra work.
const FUEL_FLOOR: u64 = 10_000;

// ── entry point ─────────────────────────────────────────────────────────────

fn run(host: GuestHost<NoPermission>) -> Result<(), HostcallError> {
    host.log(MSG_OBSERVED)?;

    // Budget-aware: bail before expensive work when fuel is nearly gone.
    if host.fuel_left()? < FUEL_FLOOR {
        host.log(MSG_LOW_FUEL)?;
        return Ok(());
    }

    host.log(MSG_DONE)?;
    Ok(())
}

neoth_plugin_sdk::export_wasm_plugin!(NoPermission, run);
