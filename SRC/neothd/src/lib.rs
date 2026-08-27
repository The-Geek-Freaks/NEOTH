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

// GOLD-FEAT-10: matrix-sdk's E2EE async (`get_user_devices` et al.) nests deep
// enough that evaluating `Send` for a future that awaits it overflows rustc's
// default recursion limit (128). matrix-sdk itself raises this to 256; the
// Matrix channel adapter's handler future wraps that, so 512 gives headroom.
// Harmless for non-matrix builds — it only widens the compile-time recursion
// budget for trait/`Send` evaluation, never changes runtime behaviour.
#![recursion_limit = "512"]
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
// V03-06: lib/bin split flipped previously-private modules to `pub mod`, so
// clippy now scrutinises enums that carry hidden test-only variants under the
// pub-API `manual_non_exhaustive` heuristic. Those variants (for example
// `permissions::gate::ConfirmStrategy::AlwaysAllow`) are compiled out of
// production with `#[cfg(test)]`.
#![allow(clippy::manual_non_exhaustive)]

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

    #[cfg(windows)]
    use std::path::{Path, PathBuf};
    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    #[cfg(windows)]
    /// A Windows test directory created with its private DACL already in place.
    ///
    /// This intentionally does not try to adopt the directory into
    /// `tempfile::TempDir`: `tempfile` has no safe adoption API, and creating a
    /// normal temporary directory before hardening its ACL leaves an ambient
    /// access interval. The guard owns only the exact random directory it
    /// created, and its drop cleanup is confined to that directory.
    pub(crate) struct CanonicalTempDir {
        path: PathBuf,
        keep: bool,
    }

    #[cfg(not(windows))]
    pub(crate) type CanonicalTempDir = tempfile::TempDir;

    #[cfg(windows)]
    impl CanonicalTempDir {
        pub(crate) fn path(&self) -> &Path {
            &self.path
        }

        /// Retain the exact fixture directory after consuming its cleanup guard.
        pub(crate) fn keep(mut self) -> PathBuf {
            self.keep = true;
            self.path.clone()
        }
    }

    #[cfg(windows)]
    impl Drop for CanonicalTempDir {
        fn drop(&mut self) {
            if !self.keep {
                // This path was generated by us and created with
                // `CreateDirectoryW`; never sweep the ambient temp root.
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }
    }

    #[cfg(windows)]
    fn canonical_local_disk_parts(path: &Path) -> std::io::Result<(u8, Vec<std::ffi::OsString>)> {
        use std::path::{Component, Prefix};

        let mut components = path.components();
        let letter = match components.next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => letter,
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "canonical Windows temp root is not a local disk path",
                    ));
                }
            },
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "canonical Windows temp root has no disk prefix",
                ));
            }
        };
        if !matches!(components.next(), Some(Component::RootDir)) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "canonical Windows temp root has no root directory",
            ));
        }
        let mut descendants = Vec::new();
        for component in components {
            let Component::Normal(component) = component else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "canonical Windows temp root has a non-child component",
                ));
            };
            descendants.push(component.to_os_string());
        }
        Ok((letter.to_ascii_uppercase(), descendants))
    }

    #[cfg(windows)]
    fn ordinary_local_disk_spelling(canonical: &Path) -> std::io::Result<PathBuf> {
        let expected = canonical_local_disk_parts(canonical)?;
        let mut ordinary = PathBuf::from(format!("{}:\\", char::from(expected.0)));
        ordinary.extend(&expected.1);

        let rebound = std::fs::canonicalize(&ordinary)?;
        if canonical_local_disk_parts(&rebound)? != expected {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ordinary Windows temp root did not rebind to its canonical target",
            ));
        }
        Ok(ordinary)
    }

    pub(crate) fn lock() -> MutexGuard<'static, ()> {
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Create a fixture below the canonical OS temp root.
    ///
    /// macOS exposes its temporary directory through `/var`, which is a
    /// system symlink to `/private/var`. Security-sensitive path tests must
    /// keep rejecting caller-supplied symlink ancestors, so the test harness
    /// resolves only this trusted, already-existing root before creating its
    /// private child directory.
    #[cfg(not(windows))]
    pub(crate) fn canonical_tempdir() -> std::io::Result<CanonicalTempDir> {
        let root = std::fs::canonicalize(std::env::temp_dir())?;
        let directory = tempfile::Builder::new()
            .prefix("neoth-test-")
            .tempdir_in(root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(directory)
    }

    #[cfg(windows)]
    pub(crate) fn canonical_tempdir() -> std::io::Result<CanonicalTempDir> {
        const ATTEMPTS: usize = 32;
        let canonical_root = std::fs::canonicalize(std::env::temp_dir())?;
        let root = ordinary_local_disk_spelling(&canonical_root)?;
        for _ in 0..ATTEMPTS {
            let mut nonce = [0u8; 16];
            getrandom::getrandom(&mut nonce).map_err(|error| {
                std::io::Error::other(format!("generate private test directory nonce: {error}"))
            })?;
            let name = format!("neoth-test-{}", hex::encode(nonce));
            let path = root.join(name);
            match crate::wal::win_native::create_private_directory_new(&path) {
                Ok(()) => return Ok(CanonicalTempDir { path, keep: false }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate a unique private test directory",
        ))
    }

    #[cfg(windows)]
    #[test]
    fn canonical_tempdir_is_private_and_accepted_by_the_local_disk_boundary() {
        use std::path::{Component, Prefix};

        let directory = canonical_tempdir().expect("create private test directory");
        let mut components = directory.path().components();
        assert!(matches!(
            components.next(),
            Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_))
        ));
        assert!(matches!(components.next(), Some(Component::RootDir)));
        assert!(components.all(|component| matches!(component, Component::Normal(_))));
        crate::wal::win_native::verify_private_directory_dacl(directory.path())
            .expect("test directory has the private TokenUser DACL");
        assert!(
            crate::skills::store::open_absolute_bound_directory(
                directory.path(),
                false,
                "private test directory",
            )
            .expect("open private test directory through the local disk boundary")
            .is_some()
        );
    }
}

use anyhow::{Context, Result};
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
/// ADOPT31-W1 — typed Wayfinder handoff artifacts. This module deliberately
/// owns only goal clarification data; map ingestion, workflow execution, and
/// evidence-gate wiring land in their separately scoped ADOPT31 slices.
pub mod adw;
/// Babel-Index analytics: async observer subsystem for the delta-kosmologie
/// federation protocol.  Never blocks inference; consent-gated federation
/// requires `freedom.yaml :: babel.federate = true` AND AutonomyLevel >= Elevated.
pub mod analytics;
pub mod channels;
pub mod cli;
// GOLD-SEC-16: the cluster subsystem is gated behind the `cluster` feature
// (default-ON in release, opt-out via `--no-default-features` for a slimmer
// solo-node binary).
#[cfg(feature = "cluster")]
pub mod cluster;
pub mod code_map;
pub mod coding;
pub mod computer_use;
pub mod config;
/// GOLD-CC-01 — typed, fail-closed connector control-plane contracts.
pub mod connectors;
pub mod consent;
pub mod context;
/// GOLD-CC-02 — instance-bound encrypted connector evidence store.
pub mod context_graph;
pub mod council;
pub mod credentials;
pub mod cron;
pub mod daemon;
pub mod domain_events;
pub mod ecology;
pub mod email;
pub mod feedback;
pub mod graphify_label_broker;
pub mod graphify_publish;
pub mod graphify_runner;
pub mod graphify_transaction;
pub mod hooks;
/// GOLD-ADAPT-ODY-13 — hardware-fit model scorer (GPU-bandwidth → tok/s
/// estimate + VRAM fit + ranking), surfaced via `neoth models fit`.
pub mod hwfit;
pub mod installers;
pub mod integrations;
pub mod interface_preference;
/// GOLD-LOOP-01 — multi-round autonomous loop engine. Wraps
/// `run_mcp_dispatch_loop` with outer rounds, stop-condition verification,
/// optional self-reflect refine passes, WAL events (0x7C–0x7F), and
/// `LoopRunRecord` disk persistence (`~/.neoth/loops/`).
pub mod loop_engine;
pub mod lsp;
pub mod mcp;
pub mod media;
pub mod memory;
pub mod models;
pub mod n8n_api;
pub mod oai_serve;
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
pub mod recon;
pub mod recovery;
pub mod reflection;
pub mod secret;
pub mod secret_transfer;
pub mod security;
pub mod self_improve;
pub mod skills;
pub mod slash;
pub mod sources;
pub mod sub_agents;
pub mod telemetry;
/// GOLD-ARCH-07 — canonical overflow-defined unix-time helpers.
pub mod time;
/// Round-3 v0.4 ARCH-04 — block-layer prompt token-cap enforcement
/// + graceful degradation policy (D oldest 50% → C lowest-importance
/// 50% → Conductor truncation). Uncoupled A/B/E items remain protected; a
/// validated A+D semantic atomic group may be removed only as one unit. Returns the
/// per-block diff for the WAL `0x2F BUDGET_EXCEEDED` audit emit-site.
pub mod tokens;
pub mod tools;
pub mod transport;
pub mod tweaks;
pub mod updater;
pub mod util;
pub mod wal;
pub mod wasm_plugin;
/// GOLD-FEAT-03 — NEOTH self-wiki: render the `PLAN/` design corpus into an
/// interlinked Obsidian vault (`neoth obsidian wiki-build`).
pub mod wiki;
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

    // A prior bundle transaction may have stopped after installing companion
    // members but before its durable final state. Recover under the exact
    // executable-derived root and closed release allowlist before parsing or
    // dispatching any public command.
    updater::release_bundle::recover_running_portable_transaction()
        .context("recover interrupted NEOTH installation before startup")?;

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

    // A bare invocation is the installed product launcher: it owns the
    // exactly-once GUI/CLI choice and honours it on later launches. Keep this
    // before Clap's required-subcommand parser so `neoth` itself is useful.
    // No banner here — the launcher renders its own UI.
    if std::env::args_os().nth(1).is_none() {
        cli::run_default_invocation().await?;
        return Ok(());
    }

    // Parse CLI first: Clap handles `--version`/`--help` inside `parse()` and
    // exits, so their stdout stays byte-clean for scripts and the binary
    // contract tests. Only a real subcommand dispatch reaches the banner.
    let cli = cli::Cli::parse();

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

    // Dispatch. Subcommands own their own shutdown handling —
    // `cli::serve` listens for SIGTERM/Ctrl+C internally and drains the WAL
    // writer before returning. Short-lived subcommands (`init`, `chat`, etc.)
    // do not need a signal handler.
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
    let mut saw_any_argument = false;
    let mut non_interactive_flag = false;
    for a in args {
        saw_any_argument = true;
        if a == "init" {
            saw_init = true;
        }
        if a == "--non-interactive" {
            non_interactive_flag = true;
        }
    }
    (saw_init || !saw_any_argument) && !non_interactive_flag && std::io::stdout().is_terminal()
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
        let ts = crate::time::now_unix_secs();
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
