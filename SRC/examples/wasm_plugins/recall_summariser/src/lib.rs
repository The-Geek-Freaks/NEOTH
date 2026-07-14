//! Recall-summariser plugin — NEOTH WASM plugin example.
//!
//! Demonstrates the two read/write hostcalls:
//!   - `neoth.recall_top(prompt_hash) -> i32` — how many times has this
//!     hash been seen in the episode store?
//!   - `neoth.emit_event(kind_ptr, kind_len, payload_ptr, payload_len) -> i32`
//!     — write a WAL frame so the operator can audit the plugin's decision.
//!   - `neoth.log(ptr, len)` — fallback diagnostic when the WAL writer
//!     is not attached (e.g. in automated tests).
//!
//! ## Build
//!
//! ```sh
//! cargo build --target wasm32-unknown-unknown --release
//! # Output: target/wasm32-unknown-unknown/release/neoth_plugin_recall_summariser.wasm
//! ```
//!
//! ## Activation
//!
//! ```sh
//! neoth plugin enable recall_summariser
//! ```
//!
//! The plugin starts as PENDING (D-102 default-inactive contract).

use neoth_plugin_sdk::guest::{GuestHost, HostcallError};
use neoth_plugin_sdk::permission::Write;

// ── static strings ──────────────────────────────────────────────────────────

/// A probe hash — xxh3 of the string "neoth". In a real plugin this
/// would be derived at runtime from the current operator prompt.
const PROBE_HASH: i64 = 0x5e4d_3c2b_1a09_8765_u64 as i64;

static KIND: &[u8] = b"recall_summariser.probe";
/// JSON-shaped payload kept static so the example stays allocation-free.
static PAYLOAD_SEEN: &[u8] = b"{\"seen\":true}";
static PAYLOAD_UNSEEN: &[u8] = b"{\"seen\":false}";

static LOG_SEEN: &[u8] = b"recall_summariser: prompt seen before - emitting event";
static LOG_UNSEEN: &[u8] = b"recall_summariser: prompt not seen - emitting event";

// ── entry point ─────────────────────────────────────────────────────────────

fn run(host: GuestHost<Write>) -> Result<(), HostcallError> {
    let hits = host.recall_top(PROBE_HASH as u64)?;
    if hits > 0 {
        host.log(LOG_SEEN)?;
        host.emit_event(KIND, PAYLOAD_SEEN)?;
    } else {
        host.log(LOG_UNSEEN)?;
        host.emit_event(KIND, PAYLOAD_UNSEEN)?;
    }
    Ok(())
}

neoth_plugin_sdk::export_wasm_plugin!(Write, run);
