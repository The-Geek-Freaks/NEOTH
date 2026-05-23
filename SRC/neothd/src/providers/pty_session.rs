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
    pub struct PtySession {
        master: Box<dyn MasterPty + Send>,
        child: Arc<Mutex<Box<dyn portable_pty::Child + Send + Sync>>>,
        spawn: PtySpawn,
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
                match reader.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
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
