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
//! neoth plugin enable recall-summariser
//! ```
//!
//! The plugin starts as PENDING (D-102 default-inactive contract).

#![no_std]
#![no_main]

// ── hostcall imports ────────────────────────────────────────────────────────

extern "C" {
    fn log(ptr: i32, len: i32);

    /// Query how many times `prompt_hash` has been seen in `idx_episode`.
    /// Returns 0 when no recall DB is attached or on error.
    fn recall_top(prompt_hash: i64) -> i32;

    /// Append a WAL frame (0xC4 PLUGIN_HOSTCALL).
    /// Returns 0 on success; non-zero return codes are defined in
    /// `wasm_plugin/hostcalls.rs` (kind-too-long, payload-too-long, etc).
    fn emit_event(kind_ptr: i32, kind_len: i32, payload_ptr: i32, payload_len: i32) -> i32;
}

// ── static strings ──────────────────────────────────────────────────────────

/// A probe hash — xxh3 of the string "neoth". In a real plugin this
/// would be derived at runtime from the current operator prompt.
const PROBE_HASH: i64 = 0x5e4d_3c2b_1a09_8765_u64 as i64;

static KIND: &[u8] = b"recall_summariser.probe";
/// JSON-shaped payload (static for no_std / no alloc).
static PAYLOAD_SEEN: &[u8] = b"{\"seen\":true}";
static PAYLOAD_UNSEEN: &[u8] = b"{\"seen\":false}";

static LOG_SEEN: &[u8] = b"recall_summariser: prompt seen before — emitting event";
static LOG_UNSEEN: &[u8] = b"recall_summariser: prompt not seen — emitting event";

// ── helpers ─────────────────────────────────────────────────────────────────

/// Write a log line via the host.
///
/// # Safety
/// `msg` must be a valid byte slice pointing into this plugin's linear
/// memory. The host bounds-checks `ptr + len` against the linear memory
/// size, so a bad slice will be caught + rejected there rather than
/// causing UB in the host process.
#[inline]
unsafe fn host_log(msg: &[u8]) {
    unsafe { log(msg.as_ptr() as i32, msg.len() as i32) }
}

/// Emit a WAL event, ignoring the return code (non-zero = host rejected
/// it; the operator can inspect via `neoth wal show --type 0xC4`).
#[inline]
unsafe fn host_emit(kind: &[u8], payload: &[u8]) {
    unsafe {
        emit_event(
            kind.as_ptr() as i32,
            kind.len() as i32,
            payload.as_ptr() as i32,
            payload.len() as i32,
        );
    }
}

// ── entry point ─────────────────────────────────────────────────────────────

#[unsafe(no_mangle)]
pub extern "C" fn neoth_run() -> i32 {
    // SAFETY: all pointers reference static byte slices in this
    // plugin's own linear memory.  The host hostcall ABI bounds-checks
    // every (ptr, len) pair before reading.
    unsafe {
        let hits = recall_top(PROBE_HASH);
        if hits > 0 {
            host_log(LOG_SEEN);
            host_emit(KIND, PAYLOAD_SEEN);
        } else {
            host_log(LOG_UNSEEN);
            host_emit(KIND, PAYLOAD_UNSEEN);
        }
    }
    0
}

// ── panic handler ─────────────────────────────────────────────────────────
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
