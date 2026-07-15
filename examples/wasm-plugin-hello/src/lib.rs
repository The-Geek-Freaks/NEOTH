//! Minimal versioned NEOTH WASM plugin.
//!
//! Smallest possible plugin that satisfies the NEOTH plugin ABI:
//! `export_wasm_plugin!` exports both the ABI-version probe and `neoth_run`.
//!
//! Build:
//!   cargo build --release --target wasm32-unknown-unknown \
//!     --manifest-path examples/wasm-plugin-hello/Cargo.toml
//!
//! The compiled `.wasm` exists so the Pick #34 happy-path
//! integration test can exercise the full
//!   discover → compile → instantiate → call neoth_run
//! pipeline against a real artefact (instead of the minimal-WASM
//! preamble that has no exports).

use neoth_plugin_sdk::guest::GuestHost;
use neoth_plugin_sdk::permission::None as NoPermission;

fn run(_host: GuestHost<NoPermission>) {}

neoth_plugin_sdk::export_wasm_plugin!(NoPermission, run);
