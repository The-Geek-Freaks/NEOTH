//! NEOTH plugin SDK — types plugin authors compile against.
//!
//! Scope of this crate (per SPEC_skill_plugin_system.md):
//! - `guest` — versioned Wasmtime guest ABI, safe hostcall wrappers, and the
//!   `export_wasm_plugin!` entry-point macro.
//! - `Hook` trait and `HookContext`/`HookResult` types — the native Rust
//!   integration surface for pipeline hooks. These types do not define the
//!   Wasmtime guest ABI.
//! - `PermissionToken<L>` typestate — typed permission-level markers for
//!   compile-time API checks.
//! - `PermissionLevel` sealed marker types: `None`, `ReadOnly`, `Write`,
//!   `Execute`, `Dangerous`.
//!
//! **Out of scope:** Wasmtime engine setup, runtime authorization, WAL storage,
//! and host policy. Those live in `neothd`; this crate defines only the guest
//! side of the ABI and native integration types.
//!
//! **Status:** the Wasmtime host wiring ships in `neoth`; this SDK remains
//! `0.1.0-alpha.0` while external authors validate the public type and trait
//! shapes. Plugin authors should pin the exact alpha version and expect minor
//! breaks before 0.1.0 stable.
//!
//! Scope clarification (SPEC §6 annotation, Rust Architect review):
//! `PermissionToken<T>` catches permission-level mismatches in Rust integration
//! code. It is not an authorization boundary: Cargo consumers can select the
//! `_host` feature, and the zero-sized markers do not travel over the WASM ABI.
//! The Wasmtime sandbox, operator-approved capability state, and per-hostcall
//! allowlist in `neoth` enforce permissions at runtime.

// Guest hostcall imports require four tightly-scoped unsafe FFI calls on
// wasm32. Keep unsafe denied everywhere else; `guest::imports` locally allows
// only that audited ABI shim.
#![deny(unsafe_code)]
#![warn(missing_docs)]
// Plugin SDK is API-surface-first: types and traits are declared now even
// when no in-tree caller exercises them yet. Plugin authors are the real
// consumers. Drop this `allow` when the SDK ships its 0.1.0 stable release.
#![allow(dead_code)]

pub mod guest;
pub mod hook;
pub mod permission;

pub use hook::{Hook, HookContext, HookOutput, HookResult, PipelineStage};
pub use permission::{
    AtLeast, Dangerous, Execute, FreedomGrant, PermissionLevel, PermissionToken,
    PermissionTokenAny, ReadOnly, UnauthorizedLevel, Write,
};
