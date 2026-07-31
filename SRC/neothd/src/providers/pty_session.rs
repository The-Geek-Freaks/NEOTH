//! B-6 Item 3f — PTY-backed subprocess session (PTY stealth).
//!
//! When tmux is unavailable (Windows-without-tmux, locked-down minimal
//! image) and the operator still wants interactive `claude` (not
//! `--print`), the subprocess needs a real PTY so the CLI does not
//! enter CI-detection mode + render its non-interactive JSON output.
//! `portable-pty` (Wez Furlong's crate, same one WezTerm ships)
//! abstracts Windows ConPTY (Win10+) + Linux pty + macOS pty behind
//! a single trait.
//!
//! Feature-gated on `pty-subprocess`. Without the feature the module
//! compiles to a stub that returns an actionable "not available in
//! this build" error so a misconfigured operator sees a clear
//! diagnostic instead of a silent fallback.
//!
//! Scope (v0.1):
//!   - Spawn an arbitrary command inside a PTY of operator-chosen size.
//!   - Write bytes into the slave (operator input).
//!   - Read bytes out (capture-style, non-streaming).
//!   - Kill the child explicitly + Drop-guarded auto-kill.
//!   - PTY resize for terminal-width-sensitive callees (`claude` reflows
//!     its UI when COLUMNS changes).
//!
//! Out of scope (v0.2):
//!   - ANSI parsing into structured screen state (see `claude_tmux`
//!     for the pane-scrape protocol that would consume this).
//!   - Bidirectional streaming via tokio channels (current API is
//!     blocking-read in a `spawn_blocking`).
//!   - The retry classifier (B-6 Item 3h) that would consume timeouts
//!     + classify pane-disappeared vs auth vs transient.

#[cfg(feature = "pty-subprocess")]
use std::io::{Read, Write};
use std::time::Duration;

use anyhow::{Result, anyhow};

/// Byte ceiling for one timed PTY read. The deadline bounds how long we wait,
/// not how much a fast child can hand us inside it.
#[cfg(feature = "pty-subprocess")]
const MAX_PTY_READ_BYTES: usize = 4 * 1024 * 1024;

/// PTY dimensions. Defaults match a sensible wide terminal so
/// `claude`'s ANSI reflow doesn't truncate lines on first paint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PtySize {
    pub rows: u16,
    pub cols: u16,
    /// Pixel dimensions — most PTY backends ignore these; included
    /// because portable-pty's wire shape requires them.
    pub pixel_width: u16,
    pub pixel_height: u16,
}

impl Default for PtySize {
    fn default() -> Self {
        Self {
            rows: 40,
            cols: 200,
            pixel_width: 0,
            pixel_height: 0,
        }
    }
}

/// Operator-supplied spawn parameters. `command` is the binary name
/// (resolved via PATH); `args` are positional CLI args; `cwd` is the
/// child's working directory. Env is the parent's scrubbed env (see
/// `claude_cli::cached_scrubbed_env`).
#[derive(Clone, Debug)]
pub struct PtySpawn {
    pub command: String,
    pub args: Vec<String>,
    pub cwd: Option<std::path::PathBuf>,
    pub size: PtySize,
}

impl PtySpawn {
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            args: Vec::new(),
            cwd: None,
            size: PtySize::default(),
        }
    }

    pub fn arg(mut self, a: impl Into<String>) -> Self {
        self.args.push(a.into());
        self
    }

    pub fn cwd(mut self, p: impl Into<std::path::PathBuf>) -> Self {
        self.cwd = Some(p.into());
        self
    }

    pub fn size(mut self, size: PtySize) -> Self {
        self.size = size;
        self
    }
}

// ── Feature-gated implementation ────────────────────────────────────

/// Generate a short session-id slug for WAL correlation.
/// Uses unix-nanos XOR a call-count so two spawns in the same nanosecond
/// stay distinct. Not cryptographic; scoped to operator-local audit.
#[cfg(feature = "pty-subprocess")]
fn new_session_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let cnt = COUNTER.fetch_add(1, Ordering::Relaxed);
    let ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let raw = (cnt.wrapping_mul(0x9e37_79b9)) ^ u64::from(ns);
    format!("pty-{raw:016x}")
}

#[cfg(feature = "pty-subprocess")]
#[allow(unused_imports)] // re-exported for v0.2 ClaudeCliAdapter wiring
pub use real::PtySession;

#[cfg(not(feature = "pty-subprocess"))]
#[allow(unused_imports)] // re-exported for v0.2 ClaudeCliAdapter wiring
pub use stub::PtySession;

#[cfg(feature = "pty-subprocess")]
mod real {
    use super::*;
    use portable_pty::{CommandBuilder, MasterPty, PtyPair, native_pty_system};
    use std::sync::{Arc, Mutex};

    /// PTY-backed subprocess. Holds the master end + the child handle.
    /// Drop kills the child + closes the master to free the pty pair
    /// kernel-side even if the operator forgot to `kill()`.
    ///
    /// `session_id` is a stable slug emitted in WAL frames 0x8E/0x8F so
    /// `neoth wal show --type pty_session_started` can correlate the start
    /// and end of a single PTY lifecycle.
    pub struct PtySession {
        master: Box<dyn MasterPty + Send>,
        child: Arc<Mutex<Box<dyn portable_pty::Child + Send + Sync>>>,
        spawn: PtySpawn,
        /// Stable identifier for WAL correlation (0x8E/0x8F frames).
        pub session_id: String,
    }

    impl PtySession {
        /// Spawn the command inside a fresh PTY. The size is committed
        /// before exec so the child reads accurate `winsize` /
        /// `ConPTY` dimensions on startup.
        pub fn spawn(spawn: PtySpawn) -> Result<Self> {
            let pty_system = native_pty_system();
            let PtyPair { master, slave } = pty_system
                .openpty(portable_pty::PtySize {
                    rows: spawn.size.rows,
                    cols: spawn.size.cols,
                    pixel_width: spawn.size.pixel_width,
                    pixel_height: spawn.size.pixel_height,
                })
                .map_err(|e| anyhow!("openpty: {e}"))?;
            let mut cmd = CommandBuilder::new(&spawn.command);
            for a in &spawn.args {
                cmd.arg(a);
            }
            if let Some(c) = &spawn.cwd {
                cmd.cwd(c);
            }
            let child = slave
                .spawn_command(cmd)
                .map_err(|e| anyhow!("spawn_command: {e}"))?;
            // Drop the slave so when the child exits the master EOFs
            // cleanly — without this the read loop blocks forever.
            drop(slave);
            Ok(Self {
                master,
                child: Arc::new(Mutex::new(child)),
                session_id: super::new_session_id(),
                spawn,
            })
        }

        /// Resize the PTY so a callee re-reflows its UI. `claude` listens
        /// for SIGWINCH (Unix) / ConPTY resize events (Windows) and
        /// repaints; useful when the operator widens the host terminal.
        pub fn resize(&self, size: PtySize) -> Result<()> {
            self.master
                .resize(portable_pty::PtySize {
                    rows: size.rows,
                    cols: size.cols,
                    pixel_width: size.pixel_width,
                    pixel_height: size.pixel_height,
                })
                .map_err(|e| anyhow!("resize: {e}"))
        }

        /// Write operator input into the slave's stdin. The trailing
        /// newline that triggers a CR-on-Enter must be supplied by the
        /// caller (the helper does NOT auto-add one).
        pub fn write_bytes(&self, bytes: &[u8]) -> Result<()> {
            let mut writer = self
                .master
                .take_writer()
                .map_err(|e| anyhow!("take_writer: {e}"))?;
            writer
                .write_all(bytes)
                .map_err(|e| anyhow!("pty write: {e}"))?;
            writer.flush().map_err(|e| anyhow!("pty flush: {e}"))?;
            Ok(())
        }

        /// Read bytes from the PTY until the child exits or `until`
        /// elapses. Returns whatever was captured so a timeout still
        /// surfaces partial output (operator-debugging value).
        pub fn read_until(&self, until: Duration) -> Result<Vec<u8>> {
            let mut reader = self
                .master
                .try_clone_reader()
                .map_err(|e| anyhow!("try_clone_reader: {e}"))?;
            let mut buf = Vec::with_capacity(8192);
            let start = std::time::Instant::now();
            let mut chunk = [0u8; 4096];
            loop {
                if start.elapsed() >= until {
                    break;
                }
                // The deadline alone is not a bound: a child that writes fast
                // enough fills memory before it expires.
                if buf.len() >= MAX_PTY_READ_BYTES {
                    break;
                }
                match reader.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        let room = MAX_PTY_READ_BYTES - buf.len();
                        buf.extend_from_slice(&chunk[..n.min(room)]);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(e) => return Err(anyhow!("pty read: {e}")),
                }
            }
            Ok(buf)
        }

        /// Best-effort kill. Idempotent. Returns Ok even when the child
        /// already exited so callers don't have to special-case
        /// double-kill in Drop paths.
        pub fn kill(&self) -> Result<()> {
            if let Ok(mut guard) = self.child.lock() {
                let _ = guard.kill();
            }
            Ok(())
        }

        /// True ⇔ the child is still running.
        pub fn is_alive(&self) -> bool {
            let Ok(mut guard) = self.child.lock() else {
                return false;
            };
            matches!(guard.try_wait(), Ok(None))
        }

        /// Wait for the child to exit and return its exit code (None only
        /// when the child mutex is poisoned or `wait()` errors).
        /// `portable_pty::ExitStatus` is platform-uniform: a signal death
        /// reports `success() == false` with code 1, otherwise the raw
        /// process exit code — no per-OS branch needed (the old
        /// std-ExitStatusExt branch predates the portable-pty type and
        /// never compiled against it).
        pub fn wait_exit_code(&self) -> Option<i32> {
            let Ok(mut guard) = self.child.lock() else {
                return None;
            };
            guard.wait().ok().map(|status| status.exit_code() as i32)
        }

        pub fn spawn_params(&self) -> &PtySpawn {
            &self.spawn
        }
    }

    impl Drop for PtySession {
        fn drop(&mut self) {
            let _ = self.kill();
        }
    }
}

#[cfg(not(feature = "pty-subprocess"))]
mod stub {
    use super::*;

    /// Stub used when the `pty-subprocess` cargo feature is off.
    /// Returns an actionable error so a misconfigured wizard surfaces
    /// the missing feature instead of silently fallback-spawning a
    /// non-PTY subprocess that would land Claude in CI-mode.
    #[derive(Debug)]
    pub struct PtySession {
        _phantom: std::marker::PhantomData<()>,
        /// Stable identifier field present in both real + stub so callers
        /// can read `session.session_id` regardless of feature gate.
        pub session_id: String,
    }

    impl PtySession {
        pub fn spawn(_spawn: PtySpawn) -> Result<Self> {
            Err(anyhow!(
                "PTY-subprocess backend not compiled in. Rebuild with \
                 `--features pty-subprocess` (or install the release \
                 tarball, which ships with the feature ON) to use the \
                 PTY-stealth subprocess path. v0.1 alternative: install \
                 tmux + use the tmux backend (the default when tmux is \
                 on PATH)."
            ))
        }
        pub fn resize(&self, _size: PtySize) -> Result<()> {
            Err(anyhow!("pty-subprocess feature off"))
        }
        pub fn write_bytes(&self, _bytes: &[u8]) -> Result<()> {
            Err(anyhow!("pty-subprocess feature off"))
        }
        pub fn read_until(&self, _until: Duration) -> Result<Vec<u8>> {
            Err(anyhow!("pty-subprocess feature off"))
        }
        pub fn kill(&self) -> Result<()> {
            Ok(())
        }
        pub fn is_alive(&self) -> bool {
            false
        }
        pub fn wait_exit_code(&self) -> Option<i32> {
            None
        }
        pub fn spawn_params(&self) -> &'static PtySpawn {
            static EMPTY: std::sync::OnceLock<PtySpawn> = std::sync::OnceLock::new();
            EMPTY.get_or_init(|| PtySpawn::new(""))
        }
    }
}

/// True ⇔ this build was compiled with the `pty-subprocess` feature.
/// Wizards inspect this to decide whether to surface the PTY backend
/// in the picker. Pure-function so the test below pins both feature
/// configurations.
pub const fn feature_compiled_in() -> bool {
    cfg!(feature = "pty-subprocess")
}

// ── WAL helpers (GOLD-ADAPT-HERMES-11) ─────────────────────────────────────
//
// These are best-effort: a WAL write failure must NEVER abort a PTY session.
// Pattern mirrors `cli::bg_session::emit_bg_done_wal_sync` exactly.

/// Emit a `0x8E PTY_SESSION_STARTED` frame via the supplied WAL writer handle
/// (async, called from `cli::terminal::run_terminal` before the I/O loop).
/// Payload: `{ session_id, command, ts_unix }`.
pub async fn emit_wal_started(
    writer: &crate::wal::writer::WalWriterHandle,
    session_id: &str,
    command: &str,
) {
    use crate::wal::events::EVENT_TYPE_PTY_SESSION_STARTED;
    let payload = match serde_json::to_vec(&serde_json::json!({
        "session_id": session_id,
        "command": command,
        "ts_unix": crate::time::now_unix_secs(),
    })) {
        Ok(v) => v,
        Err(_) => return,
    };
    let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_PTY_SESSION_STARTED, &payload).build();
    if let Err(e) = writer.append(header, payload).await {
        tracing::warn!(error = %e, "pty_session: WAL PTY_SESSION_STARTED append failed (best-effort)");
    }
}

/// Emit a `0x8F PTY_SESSION_ENDED` frame via a one-shot WAL writer
/// (sync, called from `cli::terminal::run_terminal` after the I/O loop).
/// Uses the same `spawn` + `try_append_sync` pattern as `emit_bg_done_wal_sync`.
/// Payload: `{ session_id, exit_code, ts_unix }`.
pub fn emit_wal_ended_sync(session_id: &str, exit_code: Option<i32>) {
    use crate::wal::events::EVENT_TYPE_PTY_SESSION_ENDED;
    let home = crate::config::FreedomConfig::default_neoth_home();
    let wal_dir = home.join("wal");
    if let Err(error) = std::fs::create_dir_all(&wal_dir) {
        tracing::warn!(%error, "pty_session: WAL directory unavailable for PTY_SESSION_ENDED");
        return;
    }
    let segment = crate::wal::writer::unique_standalone_segment_path(&wal_dir, "pty-ended");
    let exit_val: serde_json::Value = match exit_code {
        Some(c) => serde_json::Value::Number(c.into()),
        None => serde_json::Value::Null,
    };
    let payload = match serde_json::to_vec(&serde_json::json!({
        "session_id": session_id,
        "exit_code": exit_val,
        "ts_unix": crate::time::now_unix_secs(),
    })) {
        Ok(v) => v,
        Err(_) => return,
    };
    let (writer, _join) = match crate::wal::writer::spawn_for_home(segment, home) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "pty_session: WAL writer spawn failed for PTY_SESSION_ENDED");
            return;
        }
    };
    let header = crate::wal::HeaderBuilder::new(EVENT_TYPE_PTY_SESSION_ENDED, &payload).build();
    if let Err(e) = writer.try_append_sync(header, payload) {
        tracing::warn!(error = %e, "pty_session: PTY_SESSION_ENDED append failed (best-effort)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pty_size_default_is_wide_enough_for_claude_ui() {
        let s = PtySize::default();
        // claude's UI starts truncating at < 80 cols; 200 keeps a
        // comfortable margin for wrapped tool-output lines.
        assert!(s.cols >= 80);
        assert!(s.rows >= 24);
    }

    #[test]
    fn pty_spawn_builder_collects_args_in_order() {
        let spawn = PtySpawn::new("claude").arg("--model").arg("opus");
        assert_eq!(spawn.command, "claude");
        assert_eq!(spawn.args, vec!["--model", "opus"]);
    }

    #[test]
    fn pty_spawn_cwd_round_trip() {
        let spawn = PtySpawn::new("ls").cwd("/tmp");
        assert_eq!(spawn.cwd.as_deref(), Some(std::path::Path::new("/tmp")));
    }

    #[test]
    fn pty_spawn_default_size_is_wide() {
        let spawn = PtySpawn::new("x");
        assert_eq!(spawn.size, PtySize::default());
    }

    #[test]
    fn pty_spawn_size_override() {
        let custom = PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 640,
            pixel_height: 480,
        };
        let spawn = PtySpawn::new("x").size(custom);
        assert_eq!(spawn.size, custom);
    }

    #[test]
    fn feature_const_matches_cfg_state() {
        // Pin the feature-gate constant. Without `pty-subprocess` the
        // const is false + the stub PtySession surfaces the actionable
        // error. With the feature on, the real PtySession is exported.
        // This test passes in both configurations; the assertion is
        // that the const matches the cfg gate.
        let compiled = feature_compiled_in();
        if cfg!(feature = "pty-subprocess") {
            assert!(compiled);
        } else {
            assert!(!compiled);
        }
    }

    #[cfg(not(feature = "pty-subprocess"))]
    #[test]
    fn stub_spawn_returns_actionable_error_when_feature_off() {
        let err = PtySession::spawn(PtySpawn::new("claude")).unwrap_err();
        let msg = err.to_string();
        // Operator must see WHY the feature is unavailable + WHERE to
        // turn it on. Pin both pointers so a future error-message edit
        // can't silently drop one.
        assert!(
            msg.contains("pty-subprocess"),
            "missing feature pointer: {msg}"
        );
        assert!(
            msg.contains("tmux"),
            "missing v0.1 alternative pointer: {msg}"
        );
    }

    #[cfg(feature = "pty-subprocess")]
    #[test]
    fn real_spawn_echo_roundtrip() {
        // Live PTY test — only meaningful when the feature is on.
        // `echo hello` exits quickly so the read-until loop terminates
        // on EOF, not timeout.
        let echo_cmd = if cfg!(windows) {
            PtySpawn::new("cmd").arg("/C").arg("echo hello")
        } else {
            PtySpawn::new("echo").arg("hello")
        };
        let session = match PtySession::spawn(echo_cmd) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("skipping live PTY test — spawn failed (likely no PTY on CI): {e}");
                return;
            }
        };
        let bytes = session
            .read_until(Duration::from_secs(3))
            .unwrap_or_default();
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            text.contains("hello"),
            "expected 'hello' in PTY output, got: {text:?}"
        );
    }
}
