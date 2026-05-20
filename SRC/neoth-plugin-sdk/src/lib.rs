//! NEOTH plugin SDK — types plugin authors compile against.
//!
//! Scope of this crate (per SPEC_skill_plugin_system.md):
//! - `Hook` trait and `HookContext`/`HookResult` types — the entry points the
//!   host invokes when a pipeline executes.
//! - `PermissionToken<L>` typestate — proof of authority to call host tools.
//! - `PermissionLevel` sealed marker types: `None`, `ReadOnly`, `Execute`,
//!   `Dangerous`.
//!
//! **Out of scope:** wasmtime ABI, WAL event emission, the host runtime. Those
//! live in `neothd` and are not part of the plugin contract.
//!
//! **Day-15 milestone:** this crate is currently a skeleton — types and trait
//! shapes are stable, but the host wiring lives in `neothd` and is not yet
//! complete. Plugin authors should pin `neoth-plugin-sdk = "0.1.0-alpha"` and
//! expect minor breaks until 0.1.0 stable.
//!
//! Scope clarification (SPEC §6 annotation, Rust Architect review):
//! The `PermissionToken<T>` typestate enforces permission boundaries at
//! **compile time for Phase 1 (compiled-in) plugins only**. The Phase 2
//! WASM plugin host (Day-23) enforces the same boundaries at **runtime**
//! via a `hostcall_allowlist`. Both layers exist; do not assume the typestate
//! travels over the WASM ABI.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// Plugin SDK is API-surface-first: types and traits are declared now even
// when no in-tree caller exercises them yet. Plugin authors are the real
// consumers. Drop this `allow` when the SDK ships its 0.1.0 stable release.
#![allow(dead_code)]

pub mod hook;
pub mod permission;

pub use hook::{Hook, HookContext, HookOutput, HookResult, PipelineStage};
pub use permission::{
    AtLeast, Dangerous, Execute, FreedomGrant, PermissionLevel, PermissionToken,
    PermissionTokenAny, ReadOnly, UnauthorizedLevel, Write,
};
