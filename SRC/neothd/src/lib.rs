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

/// Process-global serialization lock for tests that mutate or read the
/// real process environment (`NEOTH_HOME`, `NEOTH_NO_AUTO_CODE`, …).
/// `std::env::set_var`/`remove_var` are process-wide, so under cargo's
/// default multi-threaded test runner a setter in one module races a
/// reader in another (e.g. `cli::mode` sets `NEOTH_HOME` to a tempdir
/// while `daemon::pidfile` reads `default_pidfile()`). Both ends take
/// this lock for their whole body:
/// `let _env = crate::test_env::lock();`. The CI Windows job runs
/// `--test-threads=1` so it was always safe there; this closes the
/// Unix-job flake. Poison-tolerant — a test that panics while holding
/// the lock must not wedge every other env test.
#[cfg(test)]
pub(crate) mod test_env {
    use std::sync::{Mutex, MutexGuard, OnceLock};
    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    pub(crate) fn lock() -> MutexGuard<'static, ()> {
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

use anyhow::Result;
use clap::Parser;
// clippy::unused_imports is wrong on `warn` here -- the `warn!`
// macro at line 125 below DOES resolve through this import on
// MSVC/stable. Removing it breaks compile with
// "cannot find macro `warn` in this scope".
#[allow(unused_imports)]
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

pub mod shutdown;

pub mod adr;
pub mod bosk;
pub mod channels;
pub mod claude_plugins;
pub mod cli;
pub mod cloud;
// GOLD-SEC-16: the cluster subsystem is gated behind the `cluster` feature
// (default-ON in release, opt-out via `--no-default-features` for a slimmer
// solo-node binary).
#[cfg(feature = "cluster")]
pub mod cluster;
pub mod code_map;
pub mod coding;
pub mod config;
pub mod consent;
pub mod context;
pub mod council;
pub mod credentials;
pub mod cron;
pub mod daemon;
pub mod domain_events;
pub mod ecology;
pub mod email;
pub mod event_ledger;
pub mod feedback;
pub mod hooks;
pub mod installers;
pub mod mcp;
pub mod media;
pub mod memory;
pub mod models;
pub mod n8n_api;
pub mod os_tools;
pub mod paperless;
pub mod permissions;
pub mod pipeline;
pub mod policy;
pub mod proactive;
pub mod profile;
pub mod providers;
pub mod recall;
pub mod recipes;
pub mod recovery;
pub mod reflection;
pub mod secret;
pub mod security;
pub mod skills;
pub mod slash;
pub mod sub_agents;
pub mod telemetry;
/// Round-3 v0.4 ARCH-04 — block-layer prompt token-cap enforcement
/// + graceful degradation policy (D oldest 50% → C lowest-importance
/// 50% → Conductor truncation; never touches A/B/E). Returns the
/// per-block diff for the WAL `0x2F BUDGET_EXCEEDED` audit emit-site.
pub mod tokens;
pub mod tools;
pub mod transport;
pub mod tweaks;
pub mod updater;
pub mod wal;
pub mod wasm_plugin;
pub mod wizard;

pub const BANNER: &str = "Neoth ready. Sup.";

/// A CLI subcommand wants the process to exit with a non-zero status WITHOUT
/// being treated as a crash (e.g. `neoth monitor` found alerts, `neoth doctor`
/// found a failing check, `neoth wal verify` saw a bad signature).
///
/// GOLD-COR-01 / A-03: previously these sites called `std::process::exit(1)`
/// directly. `process::exit` terminates immediately and **skips every
/// destructor on the stack** — including the WAL writer's flush-on-Drop and
/// open DB handles — so a status-code exit could silently drop un-fsync'd audit
/// frames. Returning this marker instead lets the stack unwind normally (all
/// Drop impls run, the tokio runtime drains), and only the top-level `main`
/// frame — where nothing important is left alive — translates it back into the
/// requested exit code. Carries no operator-facing message: the subcommand has
/// already printed its human-readable status before returning this.
#[derive(Debug, Clone, Copy)]
pub struct QuietExit(pub i32);

impl std::fmt::Display for QuietExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "process exiting with status {}", self.0)
    }
}

impl std::error::Error for QuietExit {}

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

    // Suppress the startup banner when the operator is running the
    // interactive wizard (`neoth init` on a TTY). The wizard prints
    // its own welcome banner inside step1_license; layering a
    // tracing-style `INFO neothd: Neoth ready. Sup.` on top makes
    // the first impression look like a logspew dump. Other
    // subcommands keep the banner — it's a useful one-line
    // ready-to-go signal for daemon/serve flows.
    if !is_interactive_wizard_invocation() {
        info!(version = %env!("CARGO_PKG_VERSION"), "{BANNER}");
    }

    // Parse CLI and dispatch. Subcommands own their own shutdown handling —
    // `cli::serve` listens for SIGTERM/Ctrl+C internally and drains the WAL
    // writer before returning. Short-lived subcommands (`init`, `chat`, etc.)
    // do not need a signal handler.
    let cli = cli::Cli::parse();
    cli::run(cli).await?;

    Ok(())
}

/// True when `neoth init` is being invoked from a TTY without
/// `--non-interactive`. Used to silence the tracing-style startup
/// banner + step-marker info!() calls during the wizard so the
/// operator sees a clean prompt sequence instead of layered logspew.
fn is_interactive_wizard_invocation() -> bool {
    use std::io::IsTerminal;
    let mut args = std::env::args();
    let _argv0 = args.next();
    let mut saw_init = false;
    let mut non_interactive_flag = false;
    for a in args {
        if a == "init" {
            saw_init = true;
        }
        if a == "--non-interactive" {
            non_interactive_flag = true;
        }
    }
    saw_init && !non_interactive_flag && std::io::stdout().is_terminal()
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
    // Interactive wizard runs default to `warn` so the operator sees
    // a clean prompt UX. Explicit NEOTH_LOG override always wins —
    // power users get the verbose default by setting it themselves.
    // Long-lived flows (`neoth serve`, `neoth chat`, etc.) keep the
    // historical `info,neothd=debug` default.
    let default_filter = if is_interactive_wizard_invocation() {
        "warn"
    } else {
        "info,neothd=debug"
    };
    let filter =
        EnvFilter::try_from_env("NEOTH_LOG").unwrap_or_else(|_| EnvFilter::new(default_filter));
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
