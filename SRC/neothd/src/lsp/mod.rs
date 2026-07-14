//! GOLD-PROG-10 (OP-03) — LSP diagnostics loop triggered on every `neoth edit --apply` write.
//!
//! Provides a lightweight, standalone, headless LSP client that spawns an LSP
//! server subprocess (e.g. `rust-analyzer`), sends `textDocument/didOpen`, and
//! collects `textDocument/publishDiagnostics` notifications — surfacing them to
//! stderr inline after a `neoth edit --apply` write completes.
//!
//! Architecture:
//! - `lsp::client::LspSession` — subprocess lifecycle + JSON-RPC framing
//! - `lsp::types::LspDiagnostic` — output type mirroring `coding::cargo_check::CargoDiagnostic`
//!
//! No tower-lsp / lsp-types dependency. Uses `mcp::transport::{frame, parse_frame}`
//! (`Content-Length` framing is local to LSP; MCP uses newline-delimited JSON),
//! and `std::sync::mpsc`
//! for read-timeout in the sync context of `cli::edit::run`.
//!
//! Wire point: `cli::edit::run()` after `apply_hashline_diff` writes the file.
//! Config gate: `freedom.yaml::tokens.lsp_diagnostics_enabled` (default off).

pub mod client;
pub mod types;
