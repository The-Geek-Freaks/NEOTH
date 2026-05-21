//! Minimal NEOTH WASM plugin — `neoth_run() -> i32`.
//!
//! Smallest possible plugin that satisfies the NEOTH plugin ABI:
//! one exported function named `neoth_run`, signature `() -> i32`,
//! returning zero (the operator-defined convention for "success").
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

/// Exported entry point. `#[no_mangle]` keeps the symbol name
/// stable across rustc versions; `extern "C"` matches the
/// `Instance::get_typed_func::<(), i32>("neoth_run")` lookup the
/// host performs.
#[unsafe(no_mangle)]
pub extern "C" fn neoth_run() -> i32 {
    // Plugin convention: 0 = success, non-zero = plugin-defined
    // error code. This minimal plugin always succeeds.
    0
}
