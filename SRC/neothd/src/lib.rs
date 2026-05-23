// V03-06 / D14b-5 (Session 21): split out `src/lib.rs` from `src/main.rs`
// so the criterion bench harness (which requires the library target) can
// reach the WAL writer + memory store internals via `use neothd::wal::...`
// etc. Previously the crate was bin-only; benches had no way to pull in
// the modules they wanted to measure.
//
// Convention: `src/main.rs` stays as the implicit binary target (single
// `fn main()` calling `neothd::run().await`). All module declarations +
// helper functions live here in `src/lib.rs`. Every `mod X` from the
// pre-split main.rs is now `pub mod X` here so the bench harness +
// future external consumers can import them.
//
// Test surface: `#[cfg(test)] mod tests` inside src/ files compiles as
// part of the lib target — every existing unit test keeps working
// because `crate::X::Y` paths still resolve to the lib root. The bin
// imports the lib via `use neothd::run;` and `crate::*` inside main.rs
// is now empty (the bin only contains `fn main`).

// Crate-level clippy lints. The disabled ones are stylistic / documentation
// nits where the project's chosen formatting (4-space indented continuation
// lines in doc bullets, explicit `..Default::default()` after partial
// initialisers, etc.) doesn't match clippy's default preference.
#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::field_reassign_with_default)]
// Wire-format / header structs intentionally take `&self` for `to_bytes()`
// even when `Self: Copy`, because operator-grep'ability of the call site
// matters more than the micro-savings of by-value receivers.
#![allow(clippy::wrong_self_convention)]
#![allow(clippy::should_implement_trait)]
#![allow(clippy::derive_ord_xor_partial_ord)]
// `Vec::with_capacity(n).push(x)` is intentional in payload builders where
// the capacity is the upper bound and the actual fills are conditional.
#![allow(clippy::vec_init_then_push)]
// clippy 1.95 bumped these lints to error under -D warnings. They flag
// stylistic doc-comment + minor pattern choices project-wide.
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::empty_line_after_doc_comments)]
#![allow(clippy::derivable_impls)]
#![allow(clippy::manual_pattern_char_comparison)]
// V03-06: lib/bin split flipped previously-private modules to `pub mod`,
// which means clippy now scrutinises enums with `#[doc(hidden)]` test-only
// variants under the pub-API `manual_non_exhaustive` heuristic. We use the
// hidden-variant idiom on purpose (e.g. `permissions::gate::ConfirmStrategy`)
// so external callers can't construct AlwaysAllow yet exhaustive matches in
// the crate keep working.
#![allow(clippy::manual_non_exhaustive)]
// dead_code is allowed crate-wide during the Day-2..Day-30 ramp-up.
#![allow(dead_code)]

use anyhow::Result;
use clap::Parser;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

pub mod shutdown;

pub mod adr;
pub mod channels;
pub mod cli;
pub mod cloud;
pub mod cluster;
pub mod code_map;
pub mod coding;
pub mod config;
pub mod consent;
pub mod council;
pub mod cron;
pub mod daemon;
pub mod hooks;
pub mod installers;
pub mod mcp;
pub mod media;
pub mod memory;
pub mod migrate;
pub mod models;
pub mod n8n_api;
pub mod permissions;
pub mod policy;
pub mod profile;
pub mod providers;
pub mod recall;
pub mod secret;
pub mod security;
pub mod skills;
pub mod slash;
pub mod sub_agents;
pub mod telemetry;
pub mod tools;
pub mod transport;
pub mod tweaks;
pub mod updater;
pub mod wal;
pub mod wasm_plugin;

pub const BANNER: &str = "Neoth ready. Sup.";

/// Daemon entrypoint. Called by `src/main.rs` inside `#[tokio::main]`.
/// Split from the bin so the lib target carries every module the bench
/// harness + downstream consumers need.
pub async fn run() -> Result<()> {
    // S6/S7-style hardening: tight umask before any file open.
    // Affects ~/.neoth/wal/ segment files written on Day-2+.
    #[cfg(unix)]
    unsafe {
        libc::umask(0o077);
    }

    // Windows: no umask equivalent. Warn the operator if running on a
    // user account whose default DACL grants read to other processes.
    // See OPEN_DECISIONS.md D-008.
    #[cfg(windows)]
    {
        warn!(
            "Running on Windows: NEOTH cannot enforce restrictive file permissions \
             automatically. Treat ~/.neoth/ as containing live secrets — keep the \
             machine off shared accounts and enable BitLocker for at-rest protection."
        );
    }

    init_tracing()?;
    install_panic_handler();

    info!(version = %env!("CARGO_PKG_VERSION"), "{BANNER}");

    // Parse CLI and dispatch. Subcommands own their own shutdown handling —
    // `cli::serve` listens for SIGTERM/Ctrl+C internally and drains the WAL
    // writer before returning. Short-lived subcommands (`init`, `chat`, etc.)
    // do not need a signal handler.
    let cli = cli::Cli::parse();
    cli::run(cli).await?;

    Ok(())
}

/// Initialise the global tracing subscriber.
///
/// Format selection (V03-01, 2026-05-17):
///   - `NEOTH_LOG_FORMAT=json` (or `jsonl`) → structured JSON lines on
///     stdout, one event per line. Each line is a single JSON object
///     with `timestamp`, `level`, `target`, `fields`, `span` —
///     ingestable by Loki, Datadog, Vector, jq, etc.
///   - Anything else (including unset) → human-readable compact text
///     (current default; backward compatible).
///
/// Filter selection: `NEOTH_LOG` env var per the standard
/// `tracing_subscriber::EnvFilter` syntax (`info,neothd=debug`,
/// `warn,neothd::wal=trace`, etc).
pub fn init_tracing() -> Result<()> {
    let filter = EnvFilter::try_from_env("NEOTH_LOG")
        .unwrap_or_else(|_| EnvFilter::new("info,neothd=debug"));
    let format = std::env::var("NEOTH_LOG_FORMAT")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let json_mode = matches!(format.as_str(), "json" | "jsonl" | "ndjson");
    if json_mode {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .with_thread_ids(false)
            .with_level(true)
            .json()
            .with_current_span(true)
            .with_span_list(false)
            .flatten_event(true)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .with_thread_ids(false)
            .with_level(true)
            .compact()
            .init();
    }
    Ok(())
}

pub fn install_panic_handler() {
    // Pick #34 (Session 14, architect audit-fix): panic handler now
    // ALSO appends to `~/.neoth/crash.log` so a daemon panic (OOM,
    // HLC overflow, unwind from a tokio worker) leaves operator-
    // visible forensics instead of a silent exit + clean PID-file
    // drop. Stderr still gets the line for live-console operators.
    //
    // Best-effort append: if HOME isn't resolvable or the file write
    // fails the handler MUST stay non-panicking — a panic-in-a-panic
    // would abort the process with no diagnostics at all.
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "<unknown>".to_string());
        let payload = if let Some(s) = info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "<non-string panic payload>".to_string()
        };
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let line = format!(
            "[neoth panic] ts_unix={ts} at {location}: {payload} (version={})\n",
            env!("CARGO_PKG_VERSION"),
        );
        eprintln!("{}", line.trim_end());
        // Best-effort persistence — never panic from inside the handler.
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .ok();
        if let Some(home) = home {
            let crash_path = std::path::PathBuf::from(home)
                .join(".neoth")
                .join("crash.log");
            // Create the parent dir if missing — first crash on a fresh
            // install must still land on disk.
            if let Some(parent) = crash_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            use std::io::Write;
            let _ = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&crash_path)
                .and_then(|mut f| f.write_all(line.as_bytes()));
        }
    }));
}
