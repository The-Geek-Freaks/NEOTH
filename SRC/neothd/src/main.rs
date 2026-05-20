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
// Neoth v0.1.0 -- Day 1 (banner) + Day 3 (CLI scaffolding)
// Neoth knows.
//
// Sources:  PLAN/00_DESIGN_v1.1_FINAL.md (normative spec)
//           PLAN/tool_framework_v4_1.md  (Pflegbarer Garten foundation)
//           PLAN/SPEC_onboarding.md      (neoth init wizard)
//
// Day-1 deliverable: cargo workspace, freedom.yaml, panic handler, banner.
// Day-3 deliverable: CLI subcommand scaffolding via clap 4.5 (SPEC_onboarding.md section 9).

// dead_code is allowed crate-wide during the Day-2..Day-30 ramp-up.
// Many of the WAL, plugin-SDK, and CLI surface types are public-API parking
// lots: defined now (per spec) but only wired up in later days. The allow
// keeps the build output free of noise so real regressions stand out.
//
// REMOVAL TRIGGER: drop this attribute when v0.1.0-rc1 is tagged. By that
// point every public item should either be exercised by an integration test
// or removed.
#![allow(dead_code)]

use anyhow::Result;
use clap::Parser;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

pub mod shutdown;

mod adr;
mod channels;
mod cli;
mod cluster;
mod code_map;
// V11 coding-workflow scaffold (Session 17 Pick #38, 2026-05-19).
// Hermes-adapted autonomous software engineering workflow with kanban
// task tracking + 3-hemisphere routing (Left fast worker / Right deep
// worker / Cerebellum orchestrator). Schema + data types only in
// Pick #1; decomposer + dispatcher + CLI surface land in subsequent
// picks per `PLAN/SPEC_coding_workflow.md` build order.
mod coding;
mod config;
mod consent;
mod council;
mod cron;
mod daemon;
mod hooks;
mod installers;
mod mcp;
mod media;
mod memory;
// V10-06 GA blocker — Phase-3 cutover migration registry. Encodes the
// 12 Jarvis stores as a static table so `neoth-migrate` (Phase-3 bin,
// shipped separately) and `neoth doctor --explain migrate` consult the
// same source of truth. Implementation lands behind a `migrate` feature
// in the separate binary; the registry stays small + pure data.
mod migrate;
mod models;
mod permissions;
mod policy;
mod profile;
mod providers;
mod secret;
mod security;
mod skills;
mod slash;
mod sub_agents;
mod tools;
mod transport;
mod tweaks;
mod updater;
mod wal;
// V10-04 GA blocker — stub module reserving the wasmtime plugin host
// surface (operator-visible names + WAL band + Phase enum). Full
// wasmtime integration lands behind the `wasm-plugin-host` Cargo
// feature in a follow-up PR; see module docs for the roadmap.
mod wasm_plugin;
// Phase 33b SP-6: removed 7 placeholder modules (brain, council, pipelines,
// context_engine, profile, tools, plugins). They were 1-line stubs with no
// callers. Each will return as a real module when its phase lands:
//   brain          — Phase 2 organism architecture
//   council        — Phase 30 sub-agents (R-18)
//   pipelines      — already lives in cli/ via PipelineHandler; module
//                    re-creation deferred until per-channel pipelines diverge
//   context_engine — already lives in memory/ctx.rs (R-19)
//   profile        — Phase 28b R-23 onboarding profile + ProfileClaimGuard
//   tools          — Phase 30 sub-agents tool surface
//   plugins        — Phase 33+ WASM plugin host
// `shutdown` declared above so it stays accessible from `cli::serve` for the
// drain path. Daemons (Phase 2+) call `shutdown::wait_for_signal()` inside
// their own task and own the drain ordering.

const BANNER: &str = "Neoth ready. Sup.";

#[tokio::main]
async fn main() -> Result<()> {
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
fn init_tracing() -> Result<()> {
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

fn install_panic_handler() {
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
