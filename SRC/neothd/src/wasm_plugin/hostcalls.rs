//! Wasmtime Linker + hostcall surface — V10-04 Pick #34.
//!
//! Plugins talk to NEOTH only through the hostcalls bound in this
//! module. SC-04: each hostcall is gated at runtime against the
//! permission level the operator granted the plugin — carried on the
//! per-instance [`PluginStoreState::granted`] field and read inside
//! every closure via `caller.data().granted`. A plugin granted
//! `ReadOnly` cannot call `emit_event` (requires `Write`) even though
//! the import is bound: the closure checks
//! `granted.allows(required)` and, on a shortfall, REFUSES fail-closed
//! (`emit_event` → no WAL write + return code 7; `recall_top` →
//! returns 0 hits) and emits a `0xC7 PLUGIN_CAP_DENIED` audit frame.
//! The granted level comes from the exact approval record written by
//! `neoth plugin enable <id>` and bound to the canonical manifest + WASM
//! digests. Dispatch never derives authority from a mutable manifest.
//! The Linker imports are namespaced under `neoth` so the wasm module
//! declares them as `(import "neoth" "log" ...)`.
//!
//! ## Bound surface (guest ABI v1)
//!
//! | Import name        | Permission | Effect |
//! |--------------------|-----------|--------|
//! | `neoth.log`        | None       | Stderr line — diagnostic only. |
//! | `neoth.fuel_left`  | None       | Returns remaining fuel as i64. |
//! | `neoth.emit_event` | Write      | Appends a WAL frame (0xC4 hostcall). |
//! | `neoth.recall_top` | ReadOnly   | Returns the episode count for the supplied text hash. |
//!
//! ## Phase 2 (follow-up)
//!
//! `host_send_text` (Execute), `host_open_url` (Dangerous), and
//! capability-token threading through a typed handle table are not part of ABI
//! v1. Adding them requires a versioned ABI change and runtime-policy tests.
//!
//! Compiled only when the `wasm-plugin-host` Cargo feature is on.

#![cfg(feature = "wasm-plugin-host")]

use anyhow::{Context, Result};
use neoth_plugin_sdk::guest::{
    HOSTCALL_EMIT_EVENT, HOSTCALL_FUEL_LEFT, HOSTCALL_LOG, HOSTCALL_RECALL_TOP, IMPORT_MODULE,
};
use wasmtime::{Caller, Linker};

use super::engine::{PluginStoreState, RecallDbHandle};
use super::manifest::RequestedPermission;
use crate::wal::builder::HeaderBuilder;
use crate::wal::events::{
    EVENT_TYPE_PLUGIN_CAP_DENIED, EVENT_TYPE_PLUGIN_CAP_USED, EVENT_TYPE_PLUGIN_HOSTCALL,
};

/// V10-04 Pick #34 voll (2026-05-19): per-frame upper bound on the
/// plugin-supplied payload that gets folded into the WAL frame body.
///
/// Rationale: a runaway plugin can call `host.emit_event` in a tight
/// loop. The WAL writer's own backpressure caps the *rate* (1024-deep
/// queue + sync_data), but a single 16 MiB payload would still fit
/// under `MAX_PAYLOAD_BYTES`. We clamp earlier so plugins can't write
/// individual giant frames — keeps `neoth wal show --type 0xC4` output
/// scannable + bounds the audit chain growth per call.
///
/// `kind` is the operator-readable tag the plugin chose (e.g.
/// `"indexer.file_seen"`). `payload` is plugin-defined opaque bytes
/// (usually JSON or msgpack); we hash + length-prefix them but do not
/// parse — the audit-chain just records "plugin X emitted Y bytes of
/// kind Z at time T".
const MAX_KIND_BYTES: usize = 128;
const MAX_PAYLOAD_BYTES_PER_HOSTCALL: usize = 4 * 1024;

/// Build the JSON payload for a `0xC4 PLUGIN_HOSTCALL` WAL frame.
///
/// Layout is line-oriented JSON so `neoth wal show --type 0xC4 --json`
/// can stream entries through `jq` without a custom decoder:
///
/// ```json
/// {"plugin":"indexer-v1","kind":"file_seen","payload_bytes":42}
/// ```
///
/// The plugin-supplied opaque `payload` is NOT embedded — only its
/// length. Two reasons: (1) opaque bytes may include non-UTF-8 which
/// would force base64 + double the frame size; (2) the audit chain's
/// job is "what + when + how much", not "verbatim plugin output". Pick
/// #34c can add an `--include-payload` operator flag if a real plugin
/// needs full body retention.
///
/// ## Concern-3 ADR (Session 24) — cross-node WAL equivalence rule
///
/// **Decision:** for cross-node verification, compare
/// `header.payload_hash` (xxh3 over THIS JSON blob), NOT the full
/// frame HMAC.
///
/// **Rationale:** `HeaderBuilder::build()` samples wall-clock for
/// `event_id` + `hlc.physical_ns` at frame creation time. Two nodes
/// running the same plugin with the same inputs will produce
/// byte-identical PAYLOADS (this helper is pure: only inputs are
/// plugin_id + kind + payload_bytes_len) but DIFFERENT `event_id`s
/// (sampled per-call). The frame-level HMAC would therefore disagree
/// across nodes while the underlying "what did the plugin decide"
/// is identical. Comparing `payload_hash` (= `xxh3_64(payload)`)
/// gives nodes a stable cross-node identity that excludes the
/// intentionally-non-deterministic clock sample.
///
/// **Why event_id is non-deterministic by design:** event_id is
/// the per-node ordering anchor for the WAL replay path. Making it
/// content-deterministic would mean two frames with the same payload
/// collapse into one ordering position — operators couldn't tell
/// "plugin fired twice with the same shape" from "the same frame
/// was replayed". The architect-recommended approach (Concern-3 §3
/// from Session 24) is to keep event_id wall-clock-stamped and put
/// the cross-node content equivalence on payload_hash.
///
/// **Drift guard:** the test
/// `event_id_is_non_deterministic_across_invocations_by_design`
/// pins this contract — a future refactor that accidentally makes
/// event_id deterministic (e.g. derives it from payload_hash) would
/// silently break audit semantics; the test fails loudly.
fn build_hostcall_payload(plugin_id: &str, kind: &[u8], payload_bytes: usize) -> Vec<u8> {
    let kind_str = String::from_utf8_lossy(kind);
    // serde_json::to_vec on a small flat object is allocation-light and
    // already canonical (sorted keys when the input is a struct, but a
    // map preserves insertion order). We use the map form to keep the
    // operator-visible key order matching the docstring above.
    let value = serde_json::json!({
        "plugin": plugin_id,
        "kind": kind_str,
        "payload_bytes": payload_bytes,
    });
    serde_json::to_vec(&value).expect("PLUGIN_HOSTCALL payload is a serde_json::Value")
}

/// KF-09 — body for a `0xC6 PLUGIN_CAP_USED` frame. `prompt_hash` renders
/// as `{:016x}` (matching the wire form `recall_top` queries against), so
/// an operator grepping `neoth wal show --type plugin_cap_used --json`
/// can correlate a plugin's memory probe with the hashed prompt. The
/// header carries the timestamp, so the body stays minimal.
fn build_cap_used_payload(
    plugin_id: &str,
    capability: &str,
    prompt_hash: i64,
    hits: i32,
) -> Vec<u8> {
    let value = serde_json::json!({
        "plugin": plugin_id,
        "capability": capability,
        "prompt_hash": format!("{:016x}", prompt_hash as u64),
        "hits": hits,
    });
    serde_json::to_vec(&value).expect("PLUGIN_CAP_USED payload is a serde_json::Value")
}

/// Permission level the hostcall requires. Mirrors the
/// `neoth-plugin-sdk` ladder but lives here as a serde-free enum
/// because hostcall dispatch is type-erased at the wasmtime boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostcallPermission {
    None,
    ReadOnly,
    Write,
    Execute,
    Dangerous,
}

impl HostcallPermission {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ReadOnly => "read_only",
            Self::Write => "write",
            Self::Execute => "execute",
            Self::Dangerous => "dangerous",
        }
    }

    /// Monotonic ladder rank. Each higher level is a strict superset of
    /// the capabilities below it, so a single `>=` comparison decides
    /// whether a grant covers a requirement.
    pub const fn level(self) -> u8 {
        match self {
            Self::None => 0,
            Self::ReadOnly => 1,
            Self::Write => 2,
            Self::Execute => 3,
            Self::Dangerous => 4,
        }
    }

    /// True when a plugin holding `self` may perform an action that
    /// requires `required`. Fail-closed by construction: `None` (rank 0)
    /// only ever covers a `None` requirement, so an un-granted plugin
    /// (the default) passes only the permission-`None` hostcalls
    /// (`log`, `fuel_left`). A higher grant covers every lower
    /// requirement (a `Dangerous` plugin may also `Write`).
    pub const fn allows(self, required: HostcallPermission) -> bool {
        self.level() >= required.level()
    }
}

/// The manifest declares `requested_permissions` (`RequestedPermission`,
/// serde-backed); the runtime gate compares `HostcallPermission`
/// (serde-free). The two ladders are 1:1 — convert at the store-build
/// boundary so a manifest level flows into `PluginStoreState::granted`.
impl From<RequestedPermission> for HostcallPermission {
    fn from(r: RequestedPermission) -> Self {
        match r {
            RequestedPermission::None => HostcallPermission::None,
            RequestedPermission::ReadOnly => HostcallPermission::ReadOnly,
            RequestedPermission::Write => HostcallPermission::Write,
            RequestedPermission::Execute => HostcallPermission::Execute,
            RequestedPermission::Dangerous => HostcallPermission::Dangerous,
        }
    }
}

/// Build the body for a `0xC7 PLUGIN_CAP_DENIED` audit frame. Pure +
/// deterministic (no clock/random — the timestamp lives in the header)
/// so the cross-node equivalence rule that governs `0xC4`/`0xC6` holds
/// here too. Operators grep `neoth wal show --type plugin_cap_denied
/// --json | jq '.hostcall, .granted'`.
fn build_cap_denied_payload(
    plugin_id: &str,
    hostcall: &str,
    required: HostcallPermission,
    granted: HostcallPermission,
) -> Vec<u8> {
    let value = serde_json::json!({
        "plugin": plugin_id,
        "hostcall": hostcall,
        "required": required.as_str(),
        "granted": granted.as_str(),
    });
    serde_json::to_vec(&value).expect("PLUGIN_CAP_DENIED payload is a serde_json::Value")
}

/// Best-effort emit of a `0xC7 PLUGIN_CAP_DENIED` frame. Called from a
/// hostcall's deny branch. A WAL issue here NEVER changes the refusal
/// the plugin already received — the audit is a side record, not part
/// of the gate decision.
fn audit_cap_denied(
    writer: &Option<crate::wal::writer::WalWriterHandle>,
    plugin_id: &str,
    hostcall: &str,
    required: HostcallPermission,
    granted: HostcallPermission,
) {
    if let Some(w) = writer {
        let payload = build_cap_denied_payload(plugin_id, hostcall, required, granted);
        let header = HeaderBuilder::new(EVENT_TYPE_PLUGIN_CAP_DENIED, &payload).build();
        if let Err(e) = w.try_append_sync(header, payload) {
            tracing::warn!(
                target: "wasm_plugin",
                plugin = %plugin_id,
                hostcall,
                error = %e,
                "cap-denied audit-frame append failed (refusal still enforced)"
            );
        }
    }
}

/// Build a wasmtime `Linker` pre-bound with NEOTH's hostcall surface.
///
/// Phase 1 minimal binding — `log`, `fuel_left`, `emit_event`,
/// `recall_top`. All four live under the `neoth` import namespace so
/// the plugin's wasm imports read as:
///
/// ```wat
/// (import "neoth" "log" (func (param i32 i32)))
/// ```
///
/// Errors propagate from `Linker::func_wrap` failures (duplicate
/// binding, name conflict). On success the linker is ready for
/// `linker.instantiate(&mut store, &module)`.
pub fn build_linker(engine: &wasmtime::Engine) -> Result<Linker<PluginStoreState>> {
    let mut linker = Linker::<PluginStoreState>::new(engine);

    // ── neoth.log ─────────────────────────────────────────────────────
    // Diagnostic stderr line. Permission: None. The plugin passes a
    // (ptr, len) pair pointing into its own linear memory; we read
    // the bytes + log them under `target: "wasm_plugin"`.
    linker
        .func_wrap(
            IMPORT_MODULE,
            HOSTCALL_LOG,
            |mut caller: Caller<'_, PluginStoreState>, ptr: i32, len: i32| {
                let plugin_id = caller.data().plugin_id.clone();
                let memory = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                    Some(m) => m,
                    None => {
                        tracing::warn!(plugin = %plugin_id, "host.log: plugin has no exported memory");
                        return;
                    }
                };
                let data = memory.data(&caller);
                let start = ptr as usize;
                let end = start.saturating_add(len as usize);
                if end > data.len() {
                    tracing::warn!(
                        plugin = %plugin_id,
                        ptr, len,
                        memory_size = data.len(),
                        "host.log: out-of-bounds string slice — clamping"
                    );
                    return;
                }
                // SX-03 (A5 CRIT-03): plugin-supplied bytes MUST run
                // through the credential redactor before the tracing
                // pass. WASM linear memory hands us a &str that bypasses
                // `SecretString` Debug protection, so a plugin that
                // logs e.g. a parsed config row containing `sk-...` was
                // leaking the raw key into NEOTH_LOG / stdout / the
                // tracing-subscriber JSON sink. `redact_text` swaps
                // every match for `[REDACTED:<class>]`.
                let raw = String::from_utf8_lossy(&data[start..end]);
                let msg = crate::security::redact::redact_text(&raw);
                tracing::info!(target: "wasm_plugin", plugin = %plugin_id, "plugin log: {msg}");
            },
        )
        .context("bind neoth.log")?;

    // ── neoth.fuel_left ───────────────────────────────────────────────
    // Returns the per-store fuel remaining as i64. Permission: None.
    // Plugins use this to bail early before expensive ops they
    // know won't fit.
    linker
        .func_wrap(
            IMPORT_MODULE,
            HOSTCALL_FUEL_LEFT,
            |caller: Caller<'_, PluginStoreState>| -> i64 {
                caller.get_fuel().map(|f| f as i64).unwrap_or(0)
            },
        )
        .context("bind neoth.fuel_left")?;

    // ── neoth.emit_event ──────────────────────────────────────────────
    // Append a WAL frame (event_type 0xC4 PLUGIN_HOSTCALL). The plugin
    // passes (kind_ptr, kind_len, payload_ptr, payload_len). Permission:
    // Write. V10-04 Pick #34 voll (2026-05-19): now writes a real
    // frame via the writer handle in `PluginStoreState::wal_writer`
    // when one is attached; falls back to tracing-only when not.
    //
    // Return codes (i32):
    //   0  — frame queued (sync `try_append_sync` succeeded OR
    //         writer absent + fallback log emitted)
    //   1  — memory bounds error (kind/payload escape linear memory)
    //   2  — kind too long ( > 128 bytes ) — operators must keep tags
    //         short for `neoth wal show` readability
    //   3  — payload too long ( > 4 KiB ) — runaway-plugin guard
    //   4  — WAL writer queue full (`WriterBackpressured`)
    //   5  — WAL writer closed (`WriterClosed`, daemon shutting down)
    //   6  — WAL append failed for any other reason
    //   7  — SC-04 PERMISSION DENIED: the plugin's grant is below `Write`.
    //         No WAL frame is written; a 0xC7 PLUGIN_CAP_DENIED audit
    //         frame is emitted instead. Fail-closed.
    linker
        .func_wrap(
            IMPORT_MODULE,
            HOSTCALL_EMIT_EVENT,
            |mut caller: Caller<'_, PluginStoreState>,
             kind_ptr: i32,
             kind_len: i32,
             payload_ptr: i32,
             payload_len: i32|
             -> i32 {
                let plugin_id = caller.data().plugin_id.clone();
                let writer = caller.data().wal_writer.clone();

                // ── SC-04 capability gate ──────────────────────────────
                // emit_event WRITES a WAL frame → requires `Write`. A
                // plugin granted below that is refused fail-closed: no
                // frame written, a 0xC7 PLUGIN_CAP_DENIED audit frame
                // emitted, return code 7. The gate reads the grant the
                // operator approved (manifest level) off the store.
                let granted = caller.data().granted;
                if !granted.allows(HostcallPermission::Write) {
                    tracing::warn!(
                        target: "wasm_plugin",
                        plugin = %plugin_id,
                        granted = %granted.as_str(),
                        required = "write",
                        "host.emit_event: DENIED — plugin grant is below Write"
                    );
                    audit_cap_denied(
                        &writer,
                        &plugin_id,
                        "emit_event",
                        HostcallPermission::Write,
                        granted,
                    );
                    return 7;
                }

                let memory = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                    Some(m) => m,
                    None => return 1,
                };
                let data = memory.data(&caller);
                let kind_bytes = match read_slice(data, kind_ptr, kind_len) {
                    Some(b) => b,
                    None => return 1,
                };
                let payload_bytes = match read_slice(data, payload_ptr, payload_len) {
                    Some(b) => b,
                    None => return 1,
                };

                if kind_bytes.len() > MAX_KIND_BYTES {
                    tracing::warn!(
                        target: "wasm_plugin",
                        plugin = %plugin_id,
                        kind_len = kind_bytes.len(),
                        max = MAX_KIND_BYTES,
                        "host.emit_event: kind too long — rejected"
                    );
                    return 2;
                }
                if payload_bytes.len() > MAX_PAYLOAD_BYTES_PER_HOSTCALL {
                    tracing::warn!(
                        target: "wasm_plugin",
                        plugin = %plugin_id,
                        payload_len = payload_bytes.len(),
                        max = MAX_PAYLOAD_BYTES_PER_HOSTCALL,
                        "host.emit_event: payload too long — rejected"
                    );
                    return 3;
                }

                let frame_payload =
                    build_hostcall_payload(&plugin_id, kind_bytes, payload_bytes.len());
                let header = HeaderBuilder::new(EVENT_TYPE_PLUGIN_HOSTCALL, &frame_payload).build();

                match writer {
                    Some(w) => match w.try_append_sync(header, frame_payload) {
                        Ok(()) => 0,
                        Err(crate::wal::error::WalError::WriterBackpressured { .. }) => {
                            tracing::warn!(
                                target: "wasm_plugin",
                                plugin = %plugin_id,
                                "host.emit_event: WAL writer queue full — plugin should back off"
                            );
                            4
                        }
                        Err(crate::wal::error::WalError::WriterClosed) => {
                            tracing::warn!(
                                target: "wasm_plugin",
                                plugin = %plugin_id,
                                "host.emit_event: WAL writer closed — daemon shutting down"
                            );
                            5
                        }
                        Err(e) => {
                            tracing::error!(
                                target: "wasm_plugin",
                                plugin = %plugin_id,
                                error = %e,
                                "host.emit_event: WAL append failed"
                            );
                            6
                        }
                    },
                    None => {
                        // No writer wired (slim daemon, tests). Preserve
                        // the Pick #34 stub behaviour so existing tests
                        // + smoke paths keep their observable shape.
                        // SX-03 (A5 CRIT-03): pipe `kind_bytes` through
                        // the redactor — a plugin that emits an event
                        // whose `kind` happens to include a credential-
                        // shape (or sets `kind` to `API_KEY=sk-...`)
                        // would otherwise leak it via the fallback log.
                        let kind_raw = String::from_utf8_lossy(kind_bytes);
                        let kind_safe = crate::security::redact::redact_text(&kind_raw);
                        tracing::info!(
                            target: "wasm_plugin",
                            plugin = %plugin_id,
                            kind = %kind_safe,
                            payload_bytes = payload_bytes.len(),
                            "host.emit_event (no WAL writer attached — fallback log only)"
                        );
                        0
                    }
                }
            },
        )
        .context("bind neoth.emit_event")?;

    // ── neoth.recall_top ──────────────────────────────────────────────
    // Returns the count of `idx_episode` rows whose stored `text_hash`
    // matches the plugin-supplied `prompt_hash` (u64 xxh3, sent as i64
    // because wasm's value ABI tops out at i64). Permission: ReadOnly.
    //
    // Mechanism: V10-04 Pick #34c (2026-05-19) — the daemon's
    // plugin-load path attaches `recall_db: Option<RecallDbHandle>`
    // (an `Arc<Mutex<rusqlite::Connection>>`); the hostcall locks the
    // mutex, formats the hash as `{:016x}` (matching the wire form
    // `indexer::insert_episode` writes), and runs a single-row
    // `SELECT COUNT(*) FROM idx_episode WHERE text_hash = ?` query.
    //
    // Return contract:
    //   0      — no hits OR connection absent OR error (plugin treats
    //            0 as "no signal" + falls back; errors logged for the
    //            operator, not surfaced to the plugin)
    //   1..N   — actual hit count, clamped to `i32::MAX`
    //
    // We DELIBERATELY do not surface error codes via the return value
    // here (unlike `emit_event`): recall is a read-only hint, plugins
    // that branch on `count > 0` get the right answer + plugins that
    // need diagnostic detail can call `host.log`.
    linker
        .func_wrap(
            IMPORT_MODULE,
            HOSTCALL_RECALL_TOP,
            |caller: Caller<'_, PluginStoreState>, prompt_hash: i64| -> i32 {
                let plugin_id = caller.data().plugin_id.clone();
                let writer = caller.data().wal_writer.clone();

                // ── SC-04 capability gate ──────────────────────────────
                // recall_top READS operator memory → requires `ReadOnly`.
                // A plugin granted `None` (the fail-closed default) is
                // refused: a 0xC7 PLUGIN_CAP_DENIED audit frame is emitted
                // and we return 0 — indistinguishable to the plugin from
                // an empty store (recall is a pure hint), so the refusal
                // is silent to the plugin but VISIBLE in the WAL.
                let granted = caller.data().granted;
                if !granted.allows(HostcallPermission::ReadOnly) {
                    tracing::warn!(
                        target: "wasm_plugin",
                        plugin = %plugin_id,
                        granted = %granted.as_str(),
                        required = "read_only",
                        "host.recall_top: DENIED — plugin grant is below ReadOnly"
                    );
                    audit_cap_denied(
                        &writer,
                        &plugin_id,
                        "recall_top",
                        HostcallPermission::ReadOnly,
                        granted,
                    );
                    return 0;
                }

                let db_handle = caller.data().recall_db.clone();
                let hits = match db_handle {
                    None => {
                        tracing::debug!(
                            target: "wasm_plugin",
                            plugin = %plugin_id,
                            prompt_hash,
                            "host.recall_top: no views.db attached — returning 0"
                        );
                        0
                    }
                    Some(db) => match recall_count_by_text_hash(&db, prompt_hash) {
                        Ok(n) => n,
                        Err(e) => {
                            tracing::warn!(
                                target: "wasm_plugin",
                                plugin = %plugin_id,
                                prompt_hash,
                                error = %e,
                                "host.recall_top: views.db query failed — returning 0"
                            );
                            0
                        }
                    },
                };
                // KF-09 — durable audit of the READ capability. recall_top
                // reads operator memory; unlike emit_event (0xC4) it was
                // previously UNTRACED, so a plugin could probe memory with
                // no signal. Emit a 0xC6 PLUGIN_CAP_USED frame per call,
                // BEST-EFFORT — a WAL writer issue must never change the
                // read hint the plugin gets back (recall stays a pure hint).
                if let Some(w) = writer {
                    let payload =
                        build_cap_used_payload(&plugin_id, "recall_top", prompt_hash, hits);
                    let header = HeaderBuilder::new(EVENT_TYPE_PLUGIN_CAP_USED, &payload).build();
                    if let Err(e) = w.try_append_sync(header, payload) {
                        tracing::warn!(
                            target: "wasm_plugin",
                            plugin = %plugin_id,
                            error = %e,
                            "host.recall_top: capability-ledger WAL append failed (audit only)"
                        );
                    }
                }
                hits
            },
        )
        .context("bind neoth.recall_top")?;

    Ok(linker)
}

/// V10-04 Pick #34c (2026-05-19): sync helper that runs the
/// `idx_episode` text-hash lookup against the shared views.db.
///
/// Hash encoding pinned to `format!("{:016x}", hash as u64)` so the
/// lookup matches what `memory::indexer::insert_episode` writes when
/// it derives `text_hash` from the WAL frame's `payload_hash`. Both
/// sites MUST agree — a divergence would silently return 0 for hashes
/// that exist on disk.
///
/// Mutex held only for the duration of the prepared-statement run.
/// SQLite query plan is index-backed (`idx_episode_hash`) so the
/// hold time stays in the microsecond range even for large stores.
///
/// Errors propagate as `anyhow::Error`; the hostcall caller catches
/// + logs them and returns 0 to the plugin.
fn recall_count_by_text_hash(db: &RecallDbHandle, prompt_hash: i64) -> Result<i32> {
    let text_hash = format!("{:016x}", prompt_hash as u64);
    let conn = db
        .lock()
        .map_err(|_| anyhow::anyhow!("recall_db mutex poisoned"))?;
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM idx_episode WHERE text_hash = ?1",
            [&text_hash],
            |row| row.get::<_, i64>(0),
        )
        .context("query idx_episode hit count")?;
    // i64 -> i32 clamp. A plugin asking "how many?" gets at most
    // `i32::MAX`; the actual ceiling in steady state is tiny because
    // a single text_hash collision implies the same payload was seen
    // multiple times, which itself is rare.
    Ok(count.try_into().unwrap_or(i32::MAX))
}

/// Read a (ptr, len) slice from the plugin's linear memory. Returns
/// `None` when the range escapes the memory bounds — caller decides
/// how to surface that to the operator.
fn read_slice(memory: &[u8], ptr: i32, len: i32) -> Option<&[u8]> {
    let start = ptr as usize;
    let end = start.checked_add(len.try_into().ok()?)?;
    if end <= memory.len() {
        Some(&memory[start..end])
    } else {
        None
    }
}

/// Hostcall permission catalogue. Operators inspecting `neoth doctor
/// --explain wasm-plugin-host` see the full surface + required permission
/// per binding. Mirrors the Linker's func_wrap calls above so a future
/// addition / removal must touch both.
pub const PHASE_1_HOSTCALLS: &[(&str, HostcallPermission)] = &[
    ("neoth.log", HostcallPermission::None),
    ("neoth.fuel_left", HostcallPermission::None),
    ("neoth.emit_event", HostcallPermission::Write),
    ("neoth.recall_top", HostcallPermission::ReadOnly),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wasm_plugin::engine::NeothEngine;

    #[test]
    fn phase_1_catalogue_has_four_entries() {
        // Pin the surface — any addition / removal must update the
        // operator-facing docs surface too.
        assert_eq!(PHASE_1_HOSTCALLS.len(), 4);
    }

    #[test]
    fn permission_strings_are_snake_case() {
        // Wire-form stability for WAL payload + operator logs.
        assert_eq!(HostcallPermission::None.as_str(), "none");
        assert_eq!(HostcallPermission::ReadOnly.as_str(), "read_only");
        assert_eq!(HostcallPermission::Write.as_str(), "write");
        assert_eq!(HostcallPermission::Execute.as_str(), "execute");
        assert_eq!(HostcallPermission::Dangerous.as_str(), "dangerous");
    }

    #[test]
    fn allows_ladder_is_monotonic_and_fail_closed() {
        use HostcallPermission::*;
        // Fail-closed default: None grant covers ONLY None-required
        // hostcalls (log, fuel_left), never a Read or Write.
        assert!(None.allows(None));
        assert!(!None.allows(ReadOnly));
        assert!(!None.allows(Write));
        // ReadOnly covers None + ReadOnly, but NOT Write.
        assert!(ReadOnly.allows(None));
        assert!(ReadOnly.allows(ReadOnly));
        assert!(!ReadOnly.allows(Write));
        // Write covers None/ReadOnly/Write, not Execute.
        assert!(Write.allows(ReadOnly));
        assert!(Write.allows(Write));
        assert!(!Write.allows(Execute));
        // A higher grant covers every lower requirement (Dangerous
        // plugin may also Write — the ladder is monotonic).
        assert!(Dangerous.allows(Write));
        assert!(Dangerous.allows(ReadOnly));
        assert!(Execute.allows(Write));
    }

    #[test]
    fn ladder_levels_are_strictly_increasing() {
        use HostcallPermission::*;
        let order = [None, ReadOnly, Write, Execute, Dangerous];
        for w in order.windows(2) {
            assert!(
                w[0].level() < w[1].level(),
                "{:?} must rank below {:?}",
                w[0],
                w[1]
            );
        }
    }

    #[test]
    fn from_requested_permission_is_one_to_one() {
        use super::RequestedPermission as R;
        assert_eq!(HostcallPermission::from(R::None), HostcallPermission::None);
        assert_eq!(
            HostcallPermission::from(R::ReadOnly),
            HostcallPermission::ReadOnly
        );
        assert_eq!(
            HostcallPermission::from(R::Write),
            HostcallPermission::Write
        );
        assert_eq!(
            HostcallPermission::from(R::Execute),
            HostcallPermission::Execute
        );
        assert_eq!(
            HostcallPermission::from(R::Dangerous),
            HostcallPermission::Dangerous
        );
    }

    #[test]
    fn cap_denied_payload_shape_is_stable_json() {
        // Operators grep `neoth wal show --type plugin_cap_denied --json
        // | jq '.hostcall, .required, .granted'`. Pin the on-disk shape.
        let bytes = build_cap_denied_payload(
            "snoop-v1",
            "emit_event",
            HostcallPermission::Write,
            HostcallPermission::ReadOnly,
        );
        let v: serde_json::Value =
            serde_json::from_slice(&bytes).expect("cap-denied payload must round-trip");
        assert_eq!(v["plugin"], "snoop-v1");
        assert_eq!(v["hostcall"], "emit_event");
        assert_eq!(v["required"], "write");
        assert_eq!(v["granted"], "read_only");
    }

    #[test]
    fn cap_denied_payload_is_deterministic() {
        // Same inputs → byte-identical (cross-node equivalence; no clock
        // in the body — the timestamp lives in the header).
        let a = build_cap_denied_payload(
            "p",
            "recall_top",
            HostcallPermission::ReadOnly,
            HostcallPermission::None,
        );
        let b = build_cap_denied_payload(
            "p",
            "recall_top",
            HostcallPermission::ReadOnly,
            HostcallPermission::None,
        );
        assert_eq!(a, b);
    }

    #[test]
    fn linker_builds_against_neoth_engine() {
        let engine = NeothEngine::new().expect("engine constructs");
        let linker = build_linker(engine.raw()).expect("linker binds");
        // Smoke: every hostcall must be discoverable by name on the
        // resulting linker. We don't instantiate a module here — that
        // requires a real .wasm fixture which lives in the next pick.
        let _ = linker;
    }

    #[test]
    fn emit_event_requires_write_permission() {
        let mapping: std::collections::HashMap<&'static str, HostcallPermission> =
            PHASE_1_HOSTCALLS.iter().copied().collect();
        assert_eq!(
            mapping.get("neoth.emit_event"),
            Some(&HostcallPermission::Write),
            "emit_event MUST stay Write — Read-only plugins cannot append WAL frames"
        );
    }

    #[test]
    fn plugin_log_redacts_api_key_pattern() {
        // SX-03 contract: the neoth.log host call must NOT emit raw
        // plugin-supplied secrets through `tracing::info!`. Direct unit
        // test on the redactor proves the pattern is recognised — the
        // closure in `build_linker` passes its borrowed `&str` through
        // exactly this function before formatting.
        let raw = "API_KEY=sk-abc123def456ghi789jkl012mno345pqr678";
        let redacted = crate::security::redact::redact_text(raw);
        assert!(
            redacted.contains("[REDACTED"),
            "expected redaction marker in {redacted:?}"
        );
        assert!(
            !redacted.contains("sk-abc123def"),
            "raw key leaked through redactor: {redacted:?}"
        );
    }

    #[test]
    fn plugin_log_preserves_safe_text() {
        // Drift guard — a benign plugin log line ("starting work")
        // must pass through unchanged so operator debugging stays
        // signal-rich.
        let raw = "starting cleanup pass on 42 entries";
        let redacted = crate::security::redact::redact_text(raw);
        assert_eq!(redacted, raw);
    }

    #[test]
    fn log_and_fuel_left_are_permission_none() {
        let mapping: std::collections::HashMap<&'static str, HostcallPermission> =
            PHASE_1_HOSTCALLS.iter().copied().collect();
        assert_eq!(mapping.get("neoth.log"), Some(&HostcallPermission::None));
        assert_eq!(
            mapping.get("neoth.fuel_left"),
            Some(&HostcallPermission::None)
        );
    }

    #[test]
    fn read_slice_bounds_checks() {
        let memory = vec![0u8; 100];
        // In-bounds.
        assert!(read_slice(&memory, 10, 20).is_some());
        // Out-of-bounds — should return None, not panic.
        assert!(read_slice(&memory, 90, 50).is_none());
        // Zero-length at the very end is still in-bounds (vacuous).
        assert!(read_slice(&memory, 100, 0).is_some());
        // Negative ptr would underflow if cast without check —
        // `read_slice` uses `as usize` which wraps negatives to huge
        // values, then `checked_add` short-circuits.
        assert!(read_slice(&memory, -1, 10).is_none());
    }

    // ── V10-04 Pick #34 voll (2026-05-19): WAL payload + writer wiring ──

    #[test]
    fn build_hostcall_payload_shape_is_stable_json() {
        // Operators grep `neoth wal show --type 0xC4 --json | jq .kind`.
        // Pin the on-disk JSON shape so a future serde rename doesn't
        // silently break their dashboards.
        let bytes = build_hostcall_payload("indexer-v1", b"file_seen", 42);
        let v: serde_json::Value =
            serde_json::from_slice(&bytes).expect("payload must round-trip through serde_json");
        assert_eq!(v["plugin"], "indexer-v1");
        assert_eq!(v["kind"], "file_seen");
        assert_eq!(v["payload_bytes"], 42);
    }

    #[test]
    fn build_hostcall_payload_clamps_non_utf8_kind_safely() {
        // A plugin passing non-UTF-8 bytes (raw protobuf, broken
        // multi-byte sequence) MUST NOT panic the daemon. The lossy
        // conversion produces a replacement-char string + valid JSON.
        let bad_kind = &[0xFF, 0xFE, 0x80, 0x41]; // invalid utf-8 lead bytes
        let bytes = build_hostcall_payload("plugin-x", bad_kind, 7);
        let v: serde_json::Value =
            serde_json::from_slice(&bytes).expect("lossy kind must still yield valid JSON");
        assert_eq!(v["plugin"], "plugin-x");
        assert_eq!(v["payload_bytes"], 7);
        let kind_str = v["kind"].as_str().expect("kind is a string");
        assert!(
            kind_str.contains('\u{FFFD}') || kind_str.contains('A'),
            "non-UTF-8 input must be lossy-decoded, not dropped: {kind_str:?}"
        );
    }

    #[test]
    fn build_hostcall_payload_empty_kind_is_valid() {
        // Zero-length kind is permitted (operator might use a flat
        // plugin where every event has the same implicit type).
        let bytes = build_hostcall_payload("p", b"", 0);
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
        assert_eq!(v["kind"], "");
        assert_eq!(v["payload_bytes"], 0);
    }

    // ── KF-09 (0xC6 PLUGIN_CAP_USED) read-capability audit payload ──────

    #[test]
    fn build_cap_used_payload_shape_is_stable_json() {
        // Operators grep `neoth wal show --type plugin_cap_used --json
        // | jq .capability`. Pin the on-disk shape.
        let bytes = build_cap_used_payload("indexer-v1", "recall_top", 0x0123456789abcdef, 3);
        let v: serde_json::Value =
            serde_json::from_slice(&bytes).expect("payload must round-trip through serde_json");
        assert_eq!(v["plugin"], "indexer-v1");
        assert_eq!(v["capability"], "recall_top");
        // prompt_hash is the {:016x} wire form recall_top queries against.
        assert_eq!(v["prompt_hash"], "0123456789abcdef");
        assert_eq!(v["hits"], 3);
    }

    #[test]
    fn build_cap_used_payload_prompt_hash_is_unsigned_016x() {
        // wasm sends u64 hashes as i64; a negative value must render as
        // the UNSIGNED 16-hex form, matching recall_count_by_text_hash's
        // `format!("{:016x}", prompt_hash as u64)`.
        let bytes = build_cap_used_payload("p", "recall_top", -1, 0);
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
        assert_eq!(v["prompt_hash"], "ffffffffffffffff");
        assert_eq!(v["hits"], 0);
    }

    #[test]
    fn build_cap_used_payload_is_deterministic() {
        // Same inputs → byte-identical (cross-node equivalence; no clock /
        // random in the body — the timestamp lives in the header).
        let a = build_cap_used_payload("plug", "recall_top", 42, 7);
        let b = build_cap_used_payload("plug", "recall_top", 42, 7);
        assert_eq!(a, b);
    }

    // ── Concern-3 (Session 24) cross-node payload determinism ─────────
    //
    // These tests pin the "what enters the WAL frame from a plugin
    // is deterministic on plugin inputs; only the clock-sampled
    // event_id is non-deterministic by design" contract. See the
    // ADR block on `build_hostcall_payload` above for the rationale.

    #[test]
    fn concern_3_same_inputs_produce_byte_identical_payloads() {
        // Pure-helper determinism pin. Two calls with the same
        // (plugin_id, kind, payload_bytes_len) MUST yield identical
        // byte vectors. Any future refactor that injects time /
        // random / HashMap iteration order would break this.
        let a = build_hostcall_payload("indexer-v1", b"file_seen", 42);
        let b = build_hostcall_payload("indexer-v1", b"file_seen", 42);
        assert_eq!(
            a, b,
            "same inputs MUST produce byte-identical payloads (cross-node equivalence anchor)",
        );
    }

    #[test]
    fn concern_3_same_payload_yields_identical_xxh3_hash_in_header() {
        // The cross-node verifier compares header.payload_hash (=
        // xxh3_64 over the payload). Two HeaderBuilder::build()
        // invocations with the same payload bytes MUST produce
        // identical payload_hash values, even though event_id and
        // hlc.physical_ns differ between calls.
        let payload = build_hostcall_payload("plugin-x", b"some_kind", 100);
        let header_a = crate::wal::HeaderBuilder::new(0xC4, &payload).build();
        let header_b = crate::wal::HeaderBuilder::new(0xC4, &payload).build();
        assert_eq!(
            header_a.payload_hash, header_b.payload_hash,
            "payload_hash is the cross-node content-equivalence anchor; \
             same payload bytes MUST hash identically",
        );
        // Sanity: the xxh3 actually ran (not a zeroed default).
        assert_ne!(header_a.payload_hash, 0);
    }

    #[test]
    fn concern_3_event_id_is_non_deterministic_across_invocations_by_design() {
        // Drift guard for the ADR decision. event_id is the per-node
        // ordering anchor — it MUST stay non-deterministic across
        // invocations so two frames with identical payload don't
        // collapse to one ordering position. A future "optimisation"
        // that derives event_id from payload_hash (or any
        // content-stable source) breaks audit semantics; this test
        // fails loudly if that happens.
        //
        // Note: the wider Concern-1 fix already makes the HLC strictly
        // monotonic via the global tick, so we look for STRICT
        // INEQUALITY (second > first) rather than just "different".
        let payload = build_hostcall_payload("plugin-y", b"x", 0);
        let header_a = crate::wal::HeaderBuilder::new(0xC4, &payload).build();
        let header_b = crate::wal::HeaderBuilder::new(0xC4, &payload).build();
        assert!(
            header_b.event_id.0 > header_a.event_id.0,
            "event_id MUST advance between invocations (drift guard for the \
             non-deterministic-by-design contract); got a={} b={}",
            header_a.event_id.0,
            header_b.event_id.0,
        );
    }

    #[test]
    fn max_constants_match_docstring() {
        // The bounds documented on the hostcall return-code table must
        // match the actual constants. Catches a copy-paste drift where
        // the docstring says 4 KiB but the constant moved.
        assert_eq!(MAX_KIND_BYTES, 128);
        assert_eq!(MAX_PAYLOAD_BYTES_PER_HOSTCALL, 4 * 1024);
    }

    #[tokio::test]
    async fn plugin_store_state_with_wal_writer_attaches_handle() {
        // The hostcall reads `caller.data().wal_writer` to decide
        // between the real-append path and the fallback log path. Pin
        // that the builder actually populates the field.
        use crate::wal::writer::spawn;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let seg = dir.path().join("000001.wal");
        let (handle, _join) = spawn(seg).expect("spawn writer");

        let state =
            crate::wasm_plugin::engine::PluginStoreState::new("indexer-v1").with_wal_writer(handle);
        assert!(
            state.wal_writer.is_some(),
            "with_wal_writer builder must populate the option"
        );
        assert_eq!(state.plugin_id, "indexer-v1");
    }

    #[test]
    fn plugin_store_state_default_has_no_wal_writer() {
        // Default construction (tests, slim daemon) leaves the writer
        // absent so the hostcall falls back to the tracing-only path.
        let state = crate::wasm_plugin::engine::PluginStoreState::new("indexer-v1");
        assert!(
            state.wal_writer.is_none(),
            "PluginStoreState::new must NOT attach a writer by default — \
             keeps the tracing-fallback path live for tests + slim daemon"
        );
    }

    // ── V10-04 Pick #34c (2026-05-19): recall_top wiring ─────────────────

    /// Build an in-memory views.db-shaped fixture so the helper can be
    /// exercised without spinning up the whole indexer pipeline.
    /// Mirrors the column subset `memory::store.rs` declares for
    /// `idx_episode` — only the fields `recall_count_by_text_hash`
    /// actually reads are populated.
    fn fixture_views_db_with_hashes(hashes: &[&str]) -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().expect("open in-memory views.db fixture");
        conn.execute_batch(
            "CREATE TABLE idx_episode (
                event_id   INTEGER PRIMARY KEY,
                event_type INTEGER NOT NULL,
                ts_ns      INTEGER NOT NULL,
                text       TEXT NOT NULL,
                text_hash  TEXT NOT NULL,
                importance REAL NOT NULL DEFAULT 0.5,
                last_access_ts INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX idx_episode_hash ON idx_episode (text_hash);",
        )
        .expect("create fixture schema");
        for (i, h) in hashes.iter().enumerate() {
            conn.execute(
                "INSERT INTO idx_episode (event_id, event_type, ts_ns, text, text_hash) \
                 VALUES (?1, 1, ?2, ?3, ?4)",
                rusqlite::params![i as i64 + 1, 1_700_000_000_000_000_000_i64, "txt", h],
            )
            .expect("insert fixture row");
        }
        conn
    }

    #[test]
    fn recall_count_returns_zero_for_unknown_hash() {
        let db = std::sync::Arc::new(std::sync::Mutex::new(fixture_views_db_with_hashes(&[
            "0000000000000001",
        ])));
        // u64 -> i64 transform: 0xDEAD_BEEF is well-within i64 positive
        // range, so the hostcall passes it through unchanged.
        let n = recall_count_by_text_hash(&db, 0xDEAD_BEEF).expect("query succeeds");
        assert_eq!(n, 0, "unknown hash must return 0 hits");
    }

    #[test]
    fn recall_count_returns_hit_count_for_matching_hash() {
        // Three rows share the same text_hash — the plugin asking
        // "how many of my prompt-hash have you seen?" gets 3 back.
        let h = format!("{:016x}", 0xCAFE_BABE_u64);
        let db = std::sync::Arc::new(std::sync::Mutex::new(fixture_views_db_with_hashes(&[
            &h, &h, &h,
        ])));
        let n = recall_count_by_text_hash(&db, 0xCAFE_BABE).expect("query succeeds");
        assert_eq!(n, 3, "three matching rows → count of 3");
    }

    #[test]
    fn recall_count_handles_negative_i64_via_u64_cast() {
        // wasm passes i64 because it has no unsigned 64-bit type at the
        // ABI boundary. A hash that as u64 is > i64::MAX arrives here
        // as a negative i64; the `as u64` cast in the helper restores
        // the original bit pattern. Pin that the wire-form match works.
        let raw: u64 = 0xFFFF_0000_DEAD_BEEF; // top bit set → negative as i64
        let as_i64 = raw as i64;
        assert!(as_i64 < 0, "fixture should produce a negative i64");

        let stored_hash = format!("{:016x}", raw);
        let db = std::sync::Arc::new(std::sync::Mutex::new(fixture_views_db_with_hashes(&[
            &stored_hash,
        ])));
        let n = recall_count_by_text_hash(&db, as_i64).expect("query succeeds");
        assert_eq!(
            n, 1,
            "negative i64 prompt_hash must still match the {:016x}-formatted row",
            raw
        );
    }

    #[test]
    fn recall_count_query_propagates_schema_error() {
        // Empty DB without the table → SELECT errors out. The helper
        // surfaces the error so the hostcall body's `match` arm logs
        // it + returns 0 to the plugin (verified at the integration
        // layer; here we just check the helper doesn't panic).
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let db = std::sync::Arc::new(std::sync::Mutex::new(conn));
        let result = recall_count_by_text_hash(&db, 1);
        assert!(
            result.is_err(),
            "missing idx_episode table must surface as Err, not silent 0"
        );
    }

    #[tokio::test]
    async fn plugin_store_state_with_recall_db_attaches_handle() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let db = std::sync::Arc::new(std::sync::Mutex::new(conn));
        let state =
            crate::wasm_plugin::engine::PluginStoreState::new("recall-plugin").with_recall_db(db);
        assert!(
            state.recall_db.is_some(),
            "with_recall_db builder must populate the option"
        );
    }

    #[test]
    fn plugin_store_state_default_has_no_recall_db() {
        let state = crate::wasm_plugin::engine::PluginStoreState::new("recall-plugin");
        assert!(
            state.recall_db.is_none(),
            "PluginStoreState::new must NOT attach a recall handle by default"
        );
    }
}
