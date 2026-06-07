//! WASM plugin host — V10-04 (shipped, feature-gated).
//!
//! NEOTH plugins ship in two flavours per `SPEC_skill_plugin_system.md`:
//!
//!   1. **Compiled-in (Phase 1, today)** — Rust crates registered via
//!      `inventory!` linkage at neothd build time. Zero runtime cost,
//!      zero sandbox — every compiled-in plugin runs at host trust.
//!      Cannot be turned off without recompiling the daemon.
//!
//!   2. **WASM (Phase 2, V10-04)** — `.wasm` modules loaded by
//!      `wasmtime` at startup. Fuel-capped, memory-capped, hostcall-
//!      gated. Hot-toggle via `freedom.yaml::plugins.<id>.enabled`.
//!      Each plugin runs in its own `wasmtime::Store` so a crash in
//!      plugin A cannot corrupt plugin B's state.
//!
//! This module owns flavour 2. The wasmtime runtime is **implemented**
//! (behind the `wasm-plugin-host` Cargo feature): [`engine`] builds the
//! fuel/memory-capped `wasmtime::Engine` + per-plugin `Store`, [`dispatch`]
//! instantiates modules through a `Linker` and invokes their entry points,
//! [`hostcalls`] gates the host surface, [`discovery`] + [`manifest`] load
//! the on-disk plugin set. It also owns the operator-visible names (config
//! schema keys, WAL event codes, diagnostic strings) shared with the
//! feature-off build.
//!
//! ## Phase tracker
//!
//! [`Phase::current`] reads as the daemon's authoritative answer to
//! "is wasm-plugin loading live?". CLI surfaces (e.g. `neoth plugins
//! list`) consult this so operators see the same answer the daemon's
//! load-path takes. The phase enum is `non_exhaustive` so future
//! transitions (Phase 3 inter-plugin IPC, Phase 4 cross-node plugin
//! sync) don't break consumers that match on it today.
//!
//! ## Self-contained, in-binary
//!
//! Per the hard rules "v1.1 is the norm" + `neoth_hard_rule_self_contained.md`,
//! V10-04 ships INSIDE the neothd binary, not as a sidecar. The public
//! surface (module path + config schema + Phase enum) is stable across both
//! feature configurations, so a feature-off ("compiled-in plugins only")
//! build and a feature-on (full wasmtime host) build expose the same names —
//! `Phase::current()` is what tells them apart at runtime.
//!
//! ## Cargo feature
//!
//! The actual wasmtime dependency lands behind a `wasm-plugin-host`
//! feature so a slim daemon build (containers, embedded targets,
//! Phase-1-only operators) skips the ~15 MiB of wasmtime + its
//! transitive deps. See `Cargo.toml`.
//!
//! ## References
//!
//! - `SPEC_skill_plugin_system.md` §10 — capability API hostcalls
//! - `PLAN/PROGRESS.md` GA blocker V10-04 — milestone tracking
//! - `neoth-plugin-sdk` crate — the public SDK plugins compile against

use serde::{Deserialize, Serialize};

// V10-04 runtime — wasmtime Engine + Store wrapper. Only compiled when
// the operator opted into `wasm-plugin-host`. The non-feature build
// stays slim — the Phase enum + WAL band reservation below are
// always present so consumers (CLI, doctor) read the same surface
// regardless of feature configuration.
#[cfg(feature = "wasm-plugin-host")]
pub mod engine;

#[cfg(feature = "wasm-plugin-host")]
pub mod hostcalls;

// Pick #34 follow-up (2026-05-20): pre-flight compile + dispatch
// outcome shape. Feature-gated because Module/Arc<Module> live on
// the wasmtime side.
#[cfg(feature = "wasm-plugin-host")]
pub mod dispatch;

// Plugin manifest parser. Compiled in BOTH feature configurations so
// the slim daemon can still diagnose a malformed `plugin.toml` (`neoth
// doctor --explain plugin-<id>`) even when wasmtime isn't linked.
pub mod manifest;

// Plugin discovery — `~/.neoth/plugins/<id>/` enumeration + manifest
// + wasm bytes pre-load. Compiled in BOTH feature configurations so a
// slim daemon can still report which plugins exist on disk + their
// manifests in `neoth plugins list`, even if it can't run them.
pub mod discovery;

/// What state the WASM plugin host is in.
///
/// `current()` reports today's phase. The enum is `non_exhaustive` so
/// V11+ extensions don't break match arms in older `neothd doctor`
/// builds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Phase {
    /// Compiled-in plugins only. `wasm-plugin-host` feature is OFF or
    /// the runtime hasn't initialised yet. Operator can build plugins
    /// against `neoth-plugin-sdk` but cannot drop them in as `.wasm`.
    CompiledInOnly,

    /// Reserved for V10-04 work: wasmtime runtime initialised, modules
    /// can be loaded from `~/.neoth/plugins/*.wasm`. Not reachable
    /// from current main-line code — the variant exists so consumers
    /// (CLI, doctor, GUI) write the match arm now and the V10-04 PR
    /// only has to flip the `current()` switch.
    WasmtimeRuntimeLive,
}

impl Phase {
    /// Compile-time answer that consumers can rely on.
    ///
    /// Returns `WasmtimeRuntimeLive` when the binary was built with the
    /// `wasm-plugin-host` Cargo feature, `CompiledInOnly` otherwise.
    /// `neoth doctor` + `neoth plugins list` read this to surface the
    /// effective runtime state.
    pub const fn current() -> Self {
        #[cfg(feature = "wasm-plugin-host")]
        {
            Self::WasmtimeRuntimeLive
        }
        #[cfg(not(feature = "wasm-plugin-host"))]
        {
            Self::CompiledInOnly
        }
    }

    /// Operator-readable label (snake_case for WAL payload stability).
    pub const fn as_str(self) -> &'static str {
        match self {
            Phase::CompiledInOnly => "compiled_in_only",
            Phase::WasmtimeRuntimeLive => "wasmtime_runtime_live",
        }
    }
}

/// V10-04 design pin: the host-side WAL event codes the wasmtime
/// integration will emit. Reserved in the 0xC0..=0xCF tool band per
/// `wal/events.rs` register table — same band as MCP tool calls
/// because both are "operator authorised something to run code that
/// isn't neothd's own". Concrete `pub const EVENT_TYPE_PLUGIN_*`
/// allocations land alongside the wasmtime PR; sketched here so the
/// band reservation is auditable today.
///
/// Sketch (NOT YET EMITTED):
///   - `0xC2 PLUGIN_LOADED`        — `.wasm` parsed + linked
///   - `0xC3 PLUGIN_REJECTED`      — manifest invalid / sig mismatch
///   - `0xC4 PLUGIN_HOSTCALL`      — capability API hostcall fired
///   - `0xC5 PLUGIN_FUEL_EXHAUSTED` — wasmtime fuel budget hit
pub const RESERVED_WAL_BAND_HINT: &str =
    "0xC0..=0xCF (tool band). Concrete codes land with V10-04 implementation PR.";

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "wasm-plugin-host"))]
    #[test]
    fn current_phase_is_compiled_in_only_without_feature() {
        // Without the `wasm-plugin-host` Cargo feature the daemon
        // CANNOT load .wasm — wasmtime isn't linked. Pin that the
        // Phase reflects that reality.
        assert_eq!(Phase::current(), Phase::CompiledInOnly);
    }

    #[cfg(feature = "wasm-plugin-host")]
    #[test]
    fn current_phase_is_wasmtime_live_with_feature() {
        // With the feature on, the wasmtime engine module is compiled
        // and the daemon CAN load .wasm. Pin the matching answer.
        assert_eq!(Phase::current(), Phase::WasmtimeRuntimeLive);
    }

    #[test]
    fn phase_string_form_is_snake_case_and_stable() {
        // WAL payloads serialise this; downstream tooling greps for
        // the string. Pin the exact bytes so a future rename surfaces
        // here, not in operator audit logs.
        assert_eq!(Phase::CompiledInOnly.as_str(), "compiled_in_only");
        assert_eq!(Phase::WasmtimeRuntimeLive.as_str(), "wasmtime_runtime_live");
    }

    #[test]
    fn phase_roundtrips_through_serde_json() {
        let p = Phase::CompiledInOnly;
        let s = serde_json::to_string(&p).unwrap();
        let back: Phase = serde_json::from_str(&s).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn reserved_wal_band_hint_names_tool_band() {
        // Sanity that the operator-readable docstring still points at
        // the agreed band. Catches a copy-paste regression where the
        // hint silently drifts to a wrong band number.
        assert!(RESERVED_WAL_BAND_HINT.contains("0xC0"));
        assert!(RESERVED_WAL_BAND_HINT.contains("0xCF"));
        assert!(RESERVED_WAL_BAND_HINT.contains("V10-04"));
    }
}
