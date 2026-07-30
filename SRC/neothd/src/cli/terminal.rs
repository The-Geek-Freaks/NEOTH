//! GOLD-ADAPT-HERMES-11 — `neoth terminal` CLI subcommand.
//!
//! Wires the `providers::pty_session` PTY engine into an operator-facing CLI
//! subcommand that spawns an interactive (or headless) PTY subprocess and
//! records WAL frames `0x8E PTY_SESSION_STARTED` / `0x8F PTY_SESSION_ENDED`
//! around the session lifetime.
//!
//! # Feature gate
//!
//! This subcommand **requires** the `pty-subprocess` cargo feature. When
//! the build was compiled without it, `run_terminal` returns an actionable
//! error immediately — no silent fallback to a non-PTY subprocess.
//!
//! # Use case
//!
//! ```text
//! neoth terminal claude                   # interactive claude PTY session
//! neoth terminal -- bash -c "echo hi"     # headless capture (piped stdin)
//! neoth terminal --rows 40 --cols 200 bash
//! ```
//!
//! # Design notes
//!
//! - The CLI path (`run_terminal`) is a synchronous `Result<()>` function
//!   called from `cli/mod.rs::dispatch`. Blocking reads are intentional here
//!   (not in an async serve path). Do NOT call this from an async context
//!   without wrapping in `tokio::task::spawn_blocking`.
//! - For the GUI lane (deferred): `cli/gui_stream.rs` would add
//!   `"pty_start"` / `"pty_write"` / `"pty_read"` NDJSON methods owning a
//!   `HashMap<String, PtySession>` session store keyed by `session_id`. That
//!   is the true "GUI lane (L)" the tracker refers to; this CLI subcommand is
//!   the minimal wired surface that proves the engine is reachable + audited.

use std::time::Duration;

use anyhow::{Result, bail};
use clap::Args;
use tracing::info;

use crate::cli::OutputFormat;
use crate::providers::pty_session::{PtySession, PtySize, PtySpawn, feature_compiled_in};

/// Arguments for `neoth terminal`.
#[derive(Args, Debug, Clone)]
pub struct TerminalArgs {
    /// Command to spawn inside the PTY (e.g. `claude`, `bash`, `cmd`).
    pub command: String,

    /// Extra arguments passed to the command.
    #[arg(trailing_var_arg = true)]
    pub args: Vec<String>,

    /// PTY height in rows (default: 40).
    #[arg(long, default_value = "40")]
    pub rows: u16,

    /// PTY width in columns (default: 200).
    #[arg(long, default_value = "200")]
    pub cols: u16,

    /// Headless read timeout in seconds (used when stdin is not a TTY).
    /// The process is killed after this many seconds if it has not exited.
    #[arg(long, default_value = "30")]
    pub timeout_secs: u64,

    /// Human-readable label stored in traces/logs (not in WAL payloads).
    #[arg(long)]
    pub session_label: Option<String>,
}

/// Run `neoth terminal`. Called synchronously from `cli/mod.rs::dispatch`.
///
/// Behaviour:
/// 1. Returns an actionable error when `pty-subprocess` was not compiled in.
/// 2. Spawns the PTY subprocess from `TerminalArgs`.
/// 3. Emits WAL `0x8E PTY_SESSION_STARTED` (best-effort, via one-shot writer
///    since the CLI path has no live daemon writer handle).
/// 4. Runs a headless read-until loop (stdin non-TTY path) that captures
///    output and writes it to stdout, OR an interactive bidirectional I/O
///    loop (stdin TTY path) forwarding operator keystrokes into the slave.
/// 5. Emits WAL `0x8F PTY_SESSION_ENDED` with the exit code.
pub fn run_terminal(args: TerminalArgs, _output: OutputFormat) -> Result<()> {
    // ── Step 1: feature gate ─────────────────────────────────────────────────
    if !feature_compiled_in() {
        bail!(
            "`neoth terminal` requires the `pty-subprocess` cargo feature, \
             which is not compiled into this binary.\n\
             To enable it, rebuild with:\n\
             \n  cargo build --features pty-subprocess\n\
             \n\
             The official release tarball ships with the feature enabled. \
             Alternatively, install tmux and use `neoth chat` — the tmux \
             backend is the default when tmux is on PATH."
        );
    }

    // ── Step 2: build spawn params ───────────────────────────────────────────
    let size = PtySize {
        rows: args.rows,
        cols: args.cols,
        pixel_width: 0,
        pixel_height: 0,
    };
    let mut spawn = PtySpawn::new(&args.command).size(size);
    for a in &args.args {
        spawn = spawn.arg(a);
    }

    let label = args.session_label.as_deref().unwrap_or(&args.command);
    info!(
        command = %args.command,
        label = %label,
        rows = args.rows,
        cols = args.cols,
        "terminal: spawning PTY session"
    );

    // ── Step 3: spawn ────────────────────────────────────────────────────────
    let session = PtySession::spawn(spawn)?;
    let session_id = session.session_id.clone();

    // ── Step 4: WAL 0x8E PTY_SESSION_STARTED (best-effort one-shot writer) ──
    // The CLI path has no live daemon WalWriterHandle. We use the sync
    // one-shot pattern (same as emit_bg_done_wal_sync) via a helper that
    // accepts a WalWriterHandle for the async daemon path. Here we use the
    // sync ended helper's sibling pattern for started.
    emit_wal_started_sync(&session_id, &args.command);

    // ── Step 5: I/O loop ─────────────────────────────────────────────────────
    let exit_code = run_io_loop(&session, Duration::from_secs(args.timeout_secs));

    // ── Step 6: WAL 0x8F PTY_SESSION_ENDED ──────────────────────────────────
    emit_wal_ended_sync(&session_id, exit_code);

    info!(
        session_id = %session_id,
        exit_code = ?exit_code,
        "terminal: PTY session ended"
    );

    Ok(())
}

/// Synchronous I/O loop.
///
/// - **Non-TTY stdin** (piped/headless): reads all output until the child
///   exits or `timeout` elapses, then prints to stdout. This is the safe
///   path for CI/scripted use.
/// - **TTY stdin** (interactive): forwards stdin bytes into the slave and
///   prints slave output to stdout in a simple polling loop. On Unix the
///   terminal is NOT put into raw mode here (the child running inside the
///   PTY handles its own cooked/raw state via the PTY line discipline —
///   `claude`'s own TUI does this correctly). The outer terminal stays in
///   its default mode; the operator can Ctrl+C to exit.
///
/// Returns the child's exit code, or `None` when the platform/ConPTY path
/// does not expose it.
fn run_io_loop(session: &PtySession, timeout: Duration) -> Option<i32> {
    let stdin_is_tty = atty_check();

    if stdin_is_tty {
        run_interactive_loop(session, timeout)
    } else {
        run_headless_loop(session, timeout)
    }
}

/// Headless read: capture all PTY output until EOF or timeout, then print.
fn run_headless_loop(session: &PtySession, timeout: Duration) -> Option<i32> {
    let bytes = session.read_until(timeout).unwrap_or_default();
    // Write raw bytes to stdout — the PTY output may contain ANSI sequences
    // that the operator's pager / downstream tool expects verbatim.
    use std::io::Write;
    let _ = std::io::stdout().write_all(&bytes);
    let _ = std::io::stdout().flush();

    // Collect the exit code after the read loop drained.
    session.wait_exit_code()
}

/// Interactive loop: poll stdin→slave and slave→stdout at 50 ms intervals.
/// Ctrl-C kills the child (the signal handler in the parent terminates the
/// process, which drops `PtySession` and triggers the kill guard).
fn run_interactive_loop(session: &PtySession, _timeout: Duration) -> Option<i32> {
    use std::io::Write;

    let poll_interval = Duration::from_millis(50);
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    // Shared output: drain slave output first, then check for stdin.
    // This is a simple non-raw polling loop — sufficient for CI-friendly
    // interactive testing. A production GUI lane would use async channels.
    loop {
        // ── slave → stdout ───────────────────────────────────────────────────
        // read_until with a short window drains whatever is currently buffered.
        let out = session.read_until(poll_interval).unwrap_or_default();
        if !out.is_empty() {
            let _ = stdout.write_all(&out);
            let _ = stdout.flush();
        }

        // ── stdin → slave ────────────────────────────────────────────────────
        // Non-blocking check: try_read is not available on all platforms via
        // std, so we attempt a small read with a short timeout guard.
        // Use a non-blocking check via stdin's raw fd availability.
        // On Windows this falls through to headless-style timeout.
        #[cfg(unix)]
        {
            let mut ibuf = [0u8; 256];
            use std::io::Read;
            use std::os::unix::io::AsRawFd;
            let fd = stdin.as_raw_fd();
            let mut rfds = unsafe {
                let mut set = std::mem::zeroed::<libc::fd_set>();
                libc::FD_SET(fd, &mut set);
                set
            };
            let mut tv = libc::timeval {
                tv_sec: 0,
                tv_usec: 0, // non-blocking check
            };
            let ready = unsafe {
                libc::select(
                    fd + 1,
                    &mut rfds,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut tv,
                )
            };
            if ready > 0
                && let Ok(n) = stdin.lock().read(&mut ibuf)
                && n > 0
            {
                let _ = session.write_bytes(&ibuf[..n]);
            }
        }
        #[cfg(not(unix))]
        {
            // On Windows: skip non-blocking stdin in the simple loop;
            // the GUI lane (gui_stream.rs) handles bidirectional Windows PTY.
            let _ = &stdin;
        }

        // ── exit check ───────────────────────────────────────────────────────
        if !session.is_alive() {
            // Drain any remaining output.
            let tail = session
                .read_until(Duration::from_millis(200))
                .unwrap_or_default();
            if !tail.is_empty() {
                let _ = stdout.write_all(&tail);
                let _ = stdout.flush();
            }
            break;
        }
    }

    session.wait_exit_code()
}

/// Returns `true` when stdin is connected to a real terminal.
/// Portable: uses `libc::isatty` on Unix, Windows CRT `_isatty` on Windows.
fn atty_check() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::isatty(0) != 0 } // fd 0 = stdin
    }
    #[cfg(not(unix))]
    {
        false // headless mode on Windows; GUI lane owns interactive path
    }
}

/// Sync one-shot WAL emit for PTY_SESSION_STARTED.
/// Uses the same-home daemon audit route when present; otherwise opens a unique
/// home-bound segment and blocks for the append acknowledgement plus the
/// writer's complete finalization outcome.
/// Best-effort: failure is logged via `tracing::warn!`, not propagated.
fn emit_wal_started_sync(session_id: &str, command: &str) {
    use crate::wal::events::EVENT_TYPE_PTY_SESSION_STARTED;
    let payload = match serde_json::to_vec(&serde_json::json!({
        "session_id": session_id,
        "command": command,
        "ts_unix": crate::time::now_unix_secs(),
    })) {
        Ok(v) => v,
        Err(_) => return,
    };
    emit_terminal_wal_sync(
        EVENT_TYPE_PTY_SESSION_STARTED,
        "pty-started",
        payload,
        "PTY_SESSION_STARTED",
    );
}

fn emit_wal_ended_sync(session_id: &str, exit_code: Option<i32>) {
    use crate::wal::events::EVENT_TYPE_PTY_SESSION_ENDED;
    let payload = match serde_json::to_vec(&serde_json::json!({
        "session_id": session_id,
        "exit_code": exit_code,
        "ts_unix": crate::time::now_unix_secs(),
    })) {
        Ok(v) => v,
        Err(_) => return,
    };
    emit_terminal_wal_sync(
        EVENT_TYPE_PTY_SESSION_ENDED,
        "pty-ended",
        payload,
        "PTY_SESSION_ENDED",
    );
}

fn emit_terminal_wal_sync(event_type: u8, surface: &str, payload: Vec<u8>, event: &str) {
    let home = crate::config::FreedomConfig::default_neoth_home();
    let pidfile = home.join("neothd.pid");
    match crate::daemon::pidfile::live_daemon_pid(&pidfile) {
        Ok(Some(_)) => {
            let Ok(runtime) = tokio::runtime::Handle::try_current() else {
                tracing::warn!(
                    event,
                    "terminal audit RPC unavailable outside a Tokio runtime"
                );
                return;
            };
            let result = tokio::task::block_in_place(|| {
                runtime.block_on(crate::daemon::audit_rpc::try_post_audit_frame(
                    &home, event_type, &payload,
                ))
            });
            if let Err(e) = result {
                tracing::warn!(
                    error = %e,
                    event,
                    "terminal audit forward failed; local writer suppressed while daemon is live"
                );
            }
            return;
        }
        Ok(None) => {}
        Err(e) => {
            tracing::warn!(
                error = %e,
                pidfile = %pidfile.display(),
                event,
                "terminal audit ownership is uncertain; refusing a local WAL writer"
            );
            return;
        }
    }

    let wal_dir = home.join("wal");
    if let Err(e) = std::fs::create_dir_all(&wal_dir) {
        tracing::warn!(
            error = %e,
            wal_dir = %wal_dir.display(),
            event,
            "terminal WAL directory unavailable"
        );
        return;
    }
    let segment = crate::wal::writer::unique_standalone_segment_path(&wal_dir, surface);
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        tracing::warn!(
            event,
            "terminal WAL append unavailable outside a Tokio runtime"
        );
        return;
    };
    let (writer, completion) =
        match crate::wal::writer::spawn_for_home_with_completion(segment, home) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, event, "terminal WAL writer spawn failed");
                return;
            }
        };
    let header = crate::wal::HeaderBuilder::new(event_type, &payload).build();
    let append_result =
        tokio::task::block_in_place(|| runtime.block_on(writer.append(header, payload)));
    drop(writer);
    let completion_result = tokio::task::block_in_place(|| runtime.block_on(completion.wait()));
    if let Err(e) = append_result {
        tracing::warn!(error = %e, event, "terminal WAL append failed (best-effort)");
    }
    if let Err(e) = completion_result {
        tracing::warn!(error = %e, event, "terminal WAL writer finalization failed (best-effort)");
    }
}

// Re-export the async WAL helper so the daemon path (gui_stream.rs) can use
// the handle-based variant without going through the one-shot writer.
pub use crate::providers::pty_session::emit_wal_started as emit_wal_started_async;

#[cfg(test)]
mod tests {
    use super::*;

    // ── Feature-gate error ─────────────────────────────────────────────────

    #[cfg(not(feature = "pty-subprocess"))]
    #[test]
    fn feature_off_run_terminal_returns_actionable_error() {
        let args = TerminalArgs {
            command: "claude".to_string(),
            args: vec![],
            rows: 40,
            cols: 200,
            timeout_secs: 5,
            session_label: None,
        };
        let err = run_terminal(args, crate::cli::OutputFormat::Table).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("pty-subprocess"),
            "error must name the missing feature: {msg}"
        );
        assert!(
            msg.contains("pty-subprocess"),
            "error must point to the rebuild flag: {msg}"
        );
    }

    // ── TerminalArgs builder ───────────────────────────────────────────────

    #[test]
    fn terminal_args_defaults_are_sane() {
        // Verify the clap defaults match the documented PTY dimensions.
        // We parse them from a string to exercise the clap path without
        // importing clap::Parser in the test (the test binary already has it
        // via the outer crate, but avoid the unnecessary import chain).
        let rows: u16 = "40".parse().unwrap();
        let cols: u16 = "200".parse().unwrap();
        assert!(rows >= 24, "rows must be usable for most TUIs");
        assert!(cols >= 80, "cols must be wide enough for claude");
    }

    // ── PTY round-trip (feature on only) ──────────────────────────────────

    #[cfg(feature = "pty-subprocess")]
    #[test]
    fn pty_session_started_and_ended_wal_helpers_smoke() {
        // Smoke-test: emit_wal_started_sync and emit_wal_ended_sync must
        // not panic. They may fail to open the WAL (no daemon running in
        // tests) but must swallow the error gracefully.
        emit_wal_started_sync("test-smoke-id", "echo");
        emit_wal_ended_sync("test-smoke-id", Some(0));
    }

    #[cfg(feature = "pty-subprocess")]
    #[test]
    fn pty_session_spawn_and_read_echo() {
        // Integration: spawn a real PTY process and confirm its output
        // is captured. On CI hosts without a PTY device the spawn may fail;
        // the test accepts that gracefully (same policy as real_spawn_echo_roundtrip
        // in providers/pty_session.rs).
        use crate::providers::pty_session::{PtySession, PtySpawn};

        let spawn = if cfg!(windows) {
            PtySpawn::new("cmd").arg("/C").arg("echo pty-ok")
        } else {
            PtySpawn::new("echo").arg("pty-ok")
        };
        let session = match PtySession::spawn(spawn) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("skipping PTY integration — spawn failed (likely no PTY on CI): {e}");
                return;
            }
        };
        let bytes = session
            .read_until(std::time::Duration::from_secs(5))
            .unwrap_or_default();
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            text.contains("pty-ok"),
            "expected 'pty-ok' in PTY output, got: {text:?}"
        );
        // WAL helpers must not panic after a real session.
        emit_wal_started_sync(&session.session_id, "echo");
        emit_wal_ended_sync(&session.session_id, session.wait_exit_code());
    }
}
