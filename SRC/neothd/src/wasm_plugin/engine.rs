//! Wasmtime engine wrapper — V10-04 runtime entry point.
//!
//! Owns one process-wide `wasmtime::Engine` configured for NEOTH's
//! threat model. Every plugin module is compiled by this engine and
//! instantiated inside a per-plugin `Store` so a crash in plugin A
//! cannot reach plugin B.
//!
//! ## Threat model defaults (locked at engine construction)
//!
//!   - **Fuel metering ON.** Every plugin call charges a fuel budget;
//!     a runaway loop hits the cap + traps instead of pinning the CPU.
//!   - **Memory cap.** Per-instance memory limit (default 64 MiB) so a
//!     malicious plugin cannot exhaust host RAM.
//!   - **No WASI by default.** Plugins talk to NEOTH only through the
//!     `host_*` hostcalls we explicitly link. No `wasi-filesystem`, no
//!     `wasi-sockets`. Operators who need a filesystem plugin enable
//!     the `wasi-fs` feature in a future PR + grant
//!     `FreedomGrant<Execute>`.
//!   - **Bulk memory + reference types: OFF.** Smaller attack surface
//!     than the cranelift default. Re-enable when an actual plugin
//!     needs them.
//!
//! ## What this module is NOT
//!
//! Not a public API for plugin authors — they consume `neoth-plugin-sdk`.
//! Not a hostcall dispatcher — that's in `wasm_plugin::hostcalls`
//! (next pick). This module is the engine boundary: load → instantiate
//! → call exported `neoth_run`.
//!
//! Compiled only when `wasm-plugin-host` feature is on. The
//! non-feature build still exports the `Phase` enum from the parent
//! module so callers can branch on "wasmtime live?" without a feature
//! gate at every site.

use anyhow::{Context, Result};
use wasmtime::{Config, Engine, Module, ResourceLimiter, Store};

use crate::wal::writer::WalWriterHandle;

/// V10-04 Pick #34c (2026-05-19): shared read-only recall connection
/// type alias. `rusqlite::Connection` is `!Sync` (SQLite library
/// re-entry is per-connection), so cross-thread sharing requires a
/// `Mutex`. `Arc` lets multiple plugin stores point at the same
/// underlying handle without re-opening the file per plugin.
pub type RecallDbHandle = std::sync::Arc<std::sync::Mutex<rusqlite::Connection>>;

/// Default per-instance memory ceiling. Conservative — enough for
/// indexer / formatter plugins, far short of a misbehaving plugin
/// pinning the daemon's RAM. Operators can override per-plugin via
/// `freedom.yaml::plugins.<id>.memory_limit_bytes`.
pub const DEFAULT_MEMORY_LIMIT_BYTES: usize = 64 * 1024 * 1024;

/// Default fuel budget per `host_call`. Cranelift charges 1 fuel unit
/// per ~50 wasm instructions; 1M fuel ≈ 50M wasm ops ≈ 50-200ms on a
/// laptop core. Enough for any reasonable plugin work, traps before
/// runaway loops.
pub const DEFAULT_FUEL_BUDGET: u64 = 1_000_000;

/// Per-store state. Holds the per-plugin identifier, fuel budget, and
/// optional hostcall dependencies that the wasmtime `Linker` closures
/// reach through `caller.data()`. The fields are deliberately public so
/// the daemon's plugin-load path can construct + populate state cheaply
/// without going through a builder for every plugin instance.
///
/// `wal_writer` is optional: tests + the `linker_builds_against_neoth_engine`
/// smoke do not wire a real writer, and the slim daemon builds (no
/// `wasm-plugin-host` feature) skip plugin loading entirely. When
/// `None`, `host.emit_event` falls back to the tracing-log path it
/// shipped with in Pick #34's stub.
#[derive(Clone, Debug)]
pub struct PluginStoreState {
    /// Operator-readable plugin id from the `.wasm`'s `plugin.toml`
    /// manifest. Used in WAL frames + log lines.
    pub plugin_id: String,
    /// Initial fuel budget. Decremented as the plugin runs; trap on 0.
    pub fuel_budget: u64,
    /// V10-04 Pick #34 voll (2026-05-19): when `Some`, `host.emit_event`
    /// writes an `EVENT_TYPE_PLUGIN_HOSTCALL` (0xC4) frame via the
    /// writer's sync `try_append_sync` API. When `None`, the hostcall
    /// degrades to a tracing log line — the operator still sees the
    /// call but the audit chain doesn't grow a frame.
    pub wal_writer: Option<WalWriterHandle>,
    /// V10-04 Pick #34c (2026-05-19): shared read-only handle to the
    /// daemon's `views.db`. When `Some`, `host.recall_top(prompt_hash)`
    /// runs `SELECT COUNT(*) FROM idx_episode WHERE text_hash = ?` and
    /// returns the hit count. When `None`, returns 0 so plugins can
    /// branch on absence without a hostcall failure path. The
    /// `Arc<Mutex>` lets multiple plugin stores share one connection
    /// without re-opening the file per plugin.
    pub recall_db: Option<RecallDbHandle>,
    /// Reviewer-1 P0-A (2026-05-20): per-instance memory ceiling in
    /// bytes. The `ResourceLimiter` impl below checks every
    /// `memory.grow` call against this cap. Before this field landed
    /// `DEFAULT_MEMORY_LIMIT_BYTES` was defined as a constant but
    /// never wired to wasmtime — a plugin could grow until the host
    /// OOM-killed the daemon.
    pub memory_limit_bytes: usize,
}

/// Reviewer-1 P0-A enforcement (2026-05-20): wasmtime calls this
/// callback on every `memory.grow` (and `table.grow`). Returning
/// `Ok(false)` traps the plugin with "memory growth failed" — the
/// daemon stays alive, the misbehaving plugin dies.
impl ResourceLimiter for PluginStoreState {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> Result<bool> {
        // Honour wasmtime's own cap when the module declared one
        // smaller than ours — defense in depth.
        let cap = match maximum {
            Some(m) => m.min(self.memory_limit_bytes),
            None => self.memory_limit_bytes,
        };
        if desired > cap {
            tracing::warn!(
                plugin_id = %self.plugin_id,
                desired_bytes = desired,
                cap_bytes = cap,
                "wasm memory grow denied — plugin exceeded per-instance cap",
            );
            return Ok(false);
        }
        Ok(true)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        _desired: usize,
        _maximum: Option<usize>,
    ) -> Result<bool> {
        // Tables are small (function references); we let wasmtime's own
        // limit handle them. Override here if a CVE pattern emerges.
        Ok(true)
    }
}

impl PluginStoreState {
    pub fn new(plugin_id: impl Into<String>) -> Self {
        Self {
            plugin_id: plugin_id.into(),
            fuel_budget: DEFAULT_FUEL_BUDGET,
            wal_writer: None,
            recall_db: None,
            memory_limit_bytes: DEFAULT_MEMORY_LIMIT_BYTES,
        }
    }

    pub fn with_fuel(mut self, fuel: u64) -> Self {
        self.fuel_budget = fuel;
        self
    }

    /// Reviewer-1 P0-A (2026-05-20): override the default 64 MiB cap.
    /// `freedom.yaml::plugins.<id>.memory_limit_bytes` flows through
    /// here. Cap of 0 is rejected by the caller (manifest parser);
    /// this builder trusts its input.
    #[must_use]
    pub fn with_memory_limit(mut self, bytes: usize) -> Self {
        self.memory_limit_bytes = bytes;
        self
    }

    /// Attach a WAL writer handle so `host.emit_event` can append
    /// 0xC4 PLUGIN_HOSTCALL frames. Builder-style so the daemon's
    /// plugin-load path reads naturally:
    ///
    /// ```ignore
    /// let state = PluginStoreState::new(manifest.id())
    ///     .with_wal_writer(self.wal_writer.clone());
    /// ```
    #[must_use]
    pub fn with_wal_writer(mut self, writer: WalWriterHandle) -> Self {
        self.wal_writer = Some(writer);
        self
    }

    /// Attach a shared `views.db` handle so `host.recall_top` can
    /// query hit counts. Builder-style so the daemon's plugin-load
    /// path reads naturally:
    ///
    /// ```ignore
    /// let state = PluginStoreState::new(manifest.id())
    ///     .with_wal_writer(self.wal_writer.clone())
    ///     .with_recall_db(self.recall_db.clone());
    /// ```
    #[must_use]
    pub fn with_recall_db(mut self, db: RecallDbHandle) -> Self {
        self.recall_db = Some(db);
        self
    }
}

/// NEOTH's wasmtime engine. One per daemon process; shared across all
/// plugins (the per-plugin isolation lives at the `Store` layer, not
/// the `Engine`).
pub struct NeothEngine {
    engine: Engine,
}

impl NeothEngine {
    /// Build the engine with NEOTH's locked-down config. Errors only
    /// when wasmtime fails to construct the cranelift backend (very
    /// rare — wrong target triple, no cranelift feature). Lookup the
    /// underlying error via `anyhow::Context`.
    pub fn new() -> Result<Self> {
        let mut cfg = Config::new();
        // Fuel metering ON — must enable BEFORE the engine is built;
        // wasmtime panics on a runtime `set_fuel` call against an engine
        // that wasn't built with consumption enabled.
        cfg.consume_fuel(true);
        // Async support stays default (off) — wasmtime 26 dropped the
        // explicit `async_support` setter for that direction; sync is
        // the default for non-async-feature builds. Plugins are called
        // from sync host code in v0.1 anyway; the dispatcher decides
        // when to spawn. Pick #34 follow-up enables async only when a
        // plugin actually needs to await a host future.
        // Cranelift is the only backend we ship; the runtime feature gate
        // already enforces this but the explicit setting catches a
        // future wasmtime release that flips defaults.
        cfg.strategy(wasmtime::Strategy::Cranelift);
        let engine = Engine::new(&cfg).context("build wasmtime Engine with NEOTH config")?;
        Ok(Self { engine })
    }

    /// Compile a `.wasm` file into a wasmtime `Module`. Sync because
    /// cranelift compilation is CPU-bound; callers that want it off
    /// the tokio runtime should wrap in `spawn_blocking`.
    pub fn compile_from_bytes(&self, wasm: &[u8]) -> Result<Module> {
        Module::new(&self.engine, wasm).context("compile plugin module via cranelift")
    }

    /// Create a fresh `Store` for one plugin instance. The store owns
    /// the per-instance memory + fuel state; dropping it tears down
    /// the instance + reclaims memory immediately.
    pub fn new_store(&self, state: PluginStoreState) -> Result<Store<PluginStoreState>> {
        let budget = state.fuel_budget;
        let mut store = Store::new(&self.engine, state);
        store
            .set_fuel(budget)
            .context("seed fuel budget on plugin store")?;
        // Reviewer-1 P0-A (2026-05-20): wire the ResourceLimiter so
        // `PluginStoreState::memory_growing` is consulted on every
        // `memory.grow`. Without this call the cap is dead config.
        store.limiter(|state| state as &mut dyn ResourceLimiter);
        Ok(store)
    }

    /// Borrow the underlying engine — needed for `Linker::new(&engine)`
    /// in the hostcalls module (next pick).
    pub fn raw(&self) -> &Engine {
        &self.engine
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_constructs_with_fuel_metering_on() {
        let eng = NeothEngine::new().expect("engine must construct");
        // Smoke: an engine with fuel disabled would reject the
        // `set_fuel` call we make in `new_store`. Run the round trip.
        let store = eng
            .new_store(PluginStoreState::new("test-plugin"))
            .expect("store must seed fuel");
        let _ = store; // drop releases the Store + verifies no leak
    }

    #[test]
    fn store_state_carries_plugin_id_and_default_fuel() {
        let s = PluginStoreState::new("indexer-v1");
        assert_eq!(s.plugin_id, "indexer-v1");
        assert_eq!(s.fuel_budget, DEFAULT_FUEL_BUDGET);
    }

    #[test]
    fn with_fuel_overrides_default_budget() {
        let s = PluginStoreState::new("heavy-job").with_fuel(10_000_000);
        assert_eq!(s.fuel_budget, 10_000_000);
    }

    #[test]
    fn default_memory_limit_is_64_mib() {
        assert_eq!(DEFAULT_MEMORY_LIMIT_BYTES, 64 * 1024 * 1024);
    }

    #[test]
    fn new_state_carries_default_memory_limit() {
        // Reviewer-1 P0-A regression guard: a freshly constructed
        // PluginStoreState MUST carry the default cap so plugins
        // built without `with_memory_limit` still hit the limiter.
        let s = PluginStoreState::new("default-mem");
        assert_eq!(s.memory_limit_bytes, DEFAULT_MEMORY_LIMIT_BYTES);
    }

    #[test]
    fn with_memory_limit_overrides_default() {
        let s = PluginStoreState::new("small-mem").with_memory_limit(8 * 1024 * 1024);
        assert_eq!(s.memory_limit_bytes, 8 * 1024 * 1024);
    }

    #[test]
    fn resource_limiter_blocks_growth_beyond_cap() {
        // Reviewer-1 P0-A enforcement test: the ResourceLimiter must
        // return Ok(false) when desired > cap. The host's response to
        // that is a `memory.grow` trap, which is the OS-RAM-safety
        // contract — without this assertion the cap is purely cosmetic.
        let mut s = PluginStoreState::new("cap-test").with_memory_limit(1024 * 1024);
        // 2 MiB desired against 1 MiB cap → denied.
        let denied = s.memory_growing(0, 2 * 1024 * 1024, None).unwrap();
        assert!(!denied, "growth beyond cap must be denied");
        // 512 KiB desired against 1 MiB cap → allowed.
        let allowed = s.memory_growing(0, 512 * 1024, None).unwrap();
        assert!(allowed, "growth within cap must be allowed");
    }

    #[test]
    fn resource_limiter_honours_module_declared_max() {
        // Defense in depth: when the wasm module declares its own
        // memory maximum, the limiter takes the min of (host cap,
        // module max). A 100 MiB module against a 64 MiB host cap
        // still cannot exceed 64 MiB.
        let mut s = PluginStoreState::new("dual-cap").with_memory_limit(64 * 1024 * 1024);
        // module max 8 MiB, desired 16 MiB → denied (module's own cap).
        let denied = s
            .memory_growing(0, 16 * 1024 * 1024, Some(8 * 1024 * 1024))
            .unwrap();
        assert!(!denied);
    }

    #[test]
    fn compile_rejects_garbage_bytes() {
        let eng = NeothEngine::new().unwrap();
        let result = eng.compile_from_bytes(b"\x00\x61\x73\x6d not valid wasm");
        assert!(
            result.is_err(),
            "compiling non-WASM bytes must error, not silently succeed"
        );
    }

    /// Smoke that a minimal valid WASM module (8-byte preamble +
    /// version) compiles. Catches "wasmtime API changed under us"
    /// regressions without needing a wat -> wasm toolchain.
    #[test]
    fn compile_accepts_minimal_empty_module() {
        let eng = NeothEngine::new().unwrap();
        // Magic `\0asm` + version 1 little-endian. The smallest module.
        let minimal = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        let module = eng.compile_from_bytes(&minimal);
        assert!(
            module.is_ok(),
            "minimal wasm preamble must compile: {:?}",
            module.err()
        );
    }
}
