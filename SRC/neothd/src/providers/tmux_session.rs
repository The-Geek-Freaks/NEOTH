//! Tmux-backed warm session primitive (B-6).
//!
//! `ClaudeCliAdapter` today spawns a fresh `claude --print` subprocess per
//! `complete` call. Cold-start cost is real — model+memory load runs
//! every request. On Linux/macOS, Alex's `claude_openai_bridge.py` keeps
//! a long-lived `claude` instance inside a tmux pane and writes prompts
//! into it via `tmux send-keys`; subsequent prompts hit a warm session.
//!
//! This module ports the tmux mechanics to Rust as a reusable primitive
//! without yet wiring it into the `Provider` trait. Wiring needs
//! operator-facing config (which sessions to keep warm, TTL, fallback
//! when tmux is unavailable) and is a follow-up: ship the primitive +
//! its tests first, integrate in a later pass once the policy is decided.
//!
//! ## Platform support
//!
//! Tmux is Unix-only. On Windows the primitive's `is_available()` check
//! returns `false` and operators stay on the subprocess path — the
//! adapter degrades gracefully without operator awareness.
//!
//! ## Lifecycle
//!
//! 1. `TmuxSession::new(name, command)` runs
//!    `tmux new-session -d -s <name> -- <command>`. Detached so NEOTH
//!    can drive it without a TTY.
//! 2. `send_text(text)` writes text into the pane via
//!    `tmux send-keys -l <text>` (the `-l` flag avoids keyword
//!    interpretation; raw literal mode).
//! 3. `send_enter()` posts the newline that submits the prompt to
//!    whatever interactive program is running in the pane.
//! 4. `capture_pane()` reads the current visible content of the pane —
//!    operators use this to scrape responses. Stabilisation polling
//!    (poll-until-no-change) is the caller's responsibility — different
//!    interactive programs render at different cadences.
//! 5. `kill()` ends the session. `Drop` also calls kill best-effort so
//!    a panicking caller does not leak a long-lived process.

use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::process::Command;

use super::tmux_socket::{TmuxSocket, socket_args};

/// Default prefix used by Alex's bridge. NEOTH inherits the convention so
/// existing operator scripts that list sessions starting with `cc-` keep
/// working when both stacks share a host. Configurable via
/// `NEOTH_TMUX_PREFIX` env var (set by the daemon at boot if the operator
/// pinned one in `freedom.yaml`).
pub const DEFAULT_SESSION_PREFIX: &str = "neoth-cc";

/// Default capture-pane history limit (number of trailing lines).
/// `-1000` matches Alex's bridge default; tmux interprets `-S -<n>` as
/// "start n lines back from current".
pub const DEFAULT_CAPTURE_HISTORY_LINES: i32 = 1000;

/// One live tmux session NEOTH owns. Holding the value keeps the
/// session alive; dropping it issues a best-effort `kill-session`.
///
/// B-6 Item 4c integration (Session 22): every tmux invocation routes
/// through `tmux_cmd()` / `tmux_cmd_sync()` which splice the operator's
/// configured `-L <socket>` arg pair at the start. Default constructor
/// uses the shared per-user socket (backward-compatible); operators
/// who pinned `freedom.yaml::claude_cli.tmux.socket_name = "neoth"`
/// use `new_with_socket` to land sessions on the dedicated NEOTH
/// server.
#[derive(Debug)]
pub struct TmuxSession {
    name: String,
    socket: TmuxSocket,
    killed: bool,
}

impl TmuxSession {
    /// Build a fresh tokio Command with `tmux` + the operator's
    /// socket-name args spliced. All async sites in this module go
    /// through this helper so a future tmux verb addition can't
    /// accidentally skip the `-L` flag.
    fn tmux_cmd(&self) -> Command {
        let mut cmd = Command::new("tmux");
        for arg in socket_args(self.socket.name()) {
            cmd.arg(arg);
        }
        cmd
    }

    /// Sync variant for the Drop impl. tokio Command can't be used
    /// inside Drop (no runtime), so the fire-and-forget kill uses
    /// std::process::Command — same socket-arg splicing applied.
    fn tmux_cmd_sync(&self) -> std::process::Command {
        let mut cmd = std::process::Command::new("tmux");
        for arg in socket_args(self.socket.name()) {
            cmd.arg(arg);
        }
        cmd
    }
}

impl TmuxSession {
    /// Probe `tmux` on PATH. Cheap (~5ms on Linux); cached for the
    /// process lifetime via `OnceLock` — operators do not
    /// install/uninstall tmux mid-run.
    ///
    /// Pick #35 (Session 14, B-6 design-audit gap-fix): prior shape
    /// re-spawned `tmux -V` on every `complete()` call in the
    /// `ClaudeBackend::Auto` resolution path. On Windows without
    /// tmux this added ~5ms per chat message + a process-spawn cost.
    /// Cache flips the cost from per-call to once-per-process.
    pub async fn is_available() -> bool {
        // Cache the result via a OnceLock — first caller wins, every
        // subsequent caller reads the atomic bool. The probe runs at
        // most once per daemon lifetime.
        static AVAILABLE: tokio::sync::OnceCell<bool> = tokio::sync::OnceCell::const_new();
        *AVAILABLE
            .get_or_init(|| async {
                // `tmux -V` prints the version + exits 0. On Windows
                // the command typically fails with "not recognised".
                // Either way a non-zero exit or spawn error means
                // tmux is unusable.
                let result = Command::new("tmux")
                    .arg("-V")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .await;
                matches!(result, Ok(s) if s.success())
            })
            .await
    }

    /// Start a new detached tmux session on the shared per-user socket.
    /// Backward-compatible default — operators on
    /// `freedom.yaml::claude_cli.tmux.socket_name = ""` (the default
    /// shared socket) get the same behaviour as before B-6 4c.
    pub async fn new(name: impl Into<String>, command: &str) -> Result<Self> {
        Self::new_with_socket(name, command, TmuxSocket::shared()).await
    }

    /// B-6 Item 4c (Session 22) — start a new detached tmux session
    /// on the operator-configured socket. `TmuxSocket::shared()` ⇒
    /// shared per-user socket (no `-L` flag); `TmuxSocket::neoth()` ⇒
    /// `-L neoth` so server-scoped settings can land without polluting
    /// the operator's own tmux.
    pub async fn new_with_socket(
        name: impl Into<String>,
        command: &str,
        socket: TmuxSocket,
    ) -> Result<Self> {
        let name = name.into();
        validate_session_name(&name)?;

        // `tmux [-L <socket>] new-session -d -s <name> <command>` —
        // `-d` keeps the session detached, `-s` names it. The command
        // is passed as a single arg so tmux runs it via the system
        // shell; this matches how operators normally invoke `claude`
        // interactively.
        //
        // Note: we can't go through self.tmux_cmd() yet (no self exists)
        // so we splice the socket args inline. Every OTHER call site in
        // the impl uses self.tmux_cmd() / self.tmux_cmd_sync().
        let mut cmd = Command::new("tmux");
        for arg in socket_args(socket.name()) {
            cmd.arg(arg);
        }
        let status = cmd
            .arg("new-session")
            .arg("-d")
            .arg("-s")
            .arg(&name)
            .arg(command)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .status()
            .await
            .context("spawn `tmux new-session`")?;
        if !status.success() {
            anyhow::bail!(
                "tmux new-session -s {name} `{command}` exited with {:?}",
                status.code(),
            );
        }
        Ok(Self {
            name,
            socket,
            killed: false,
        })
    }

    /// Borrow the socket the session was created on. Exposed so the
    /// daemon's diagnostic surface (`neoth doctor`) can list
    /// "session X on socket Y" for the operator.
    pub fn socket(&self) -> &TmuxSocket {
        &self.socket
    }

    /// Session name as known to tmux. Useful for operator-facing
    /// diagnostics + the `neoth doctor` listing of warm sessions.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Write `text` into the pane as a literal string. `-l` (literal)
    /// disables tmux's keyword translation (`Enter`, `C-c`, etc) so
    /// prompts containing those tokens reach the model verbatim.
    /// Does NOT submit — pair with [`send_enter`] for an interactive
    /// CLI that needs a newline to dispatch.
    pub async fn send_text(&self, text: &str) -> Result<()> {
        let status = self
            .tmux_cmd()
            .arg("send-keys")
            .arg("-t")
            .arg(&self.name)
            .arg("-l")
            .arg(text)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .status()
            .await
            .context("spawn `tmux send-keys` for literal text")?;
        if !status.success() {
            anyhow::bail!(
                "tmux send-keys -l (session={}) exited with {:?}",
                self.name,
                status.code(),
            );
        }
        Ok(())
    }

    /// Press Enter inside the pane — submits whatever literal text was
    /// previously sent via [`send_text`]. Separate call so callers can
    /// stage multi-line input before dispatching.
    pub async fn send_enter(&self) -> Result<()> {
        let status = self
            .tmux_cmd()
            .arg("send-keys")
            .arg("-t")
            .arg(&self.name)
            .arg("Enter")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .status()
            .await
            .context("spawn `tmux send-keys Enter`")?;
        if !status.success() {
            anyhow::bail!(
                "tmux send-keys Enter (session={}) exited with {:?}",
                self.name,
                status.code(),
            );
        }
        Ok(())
    }

    /// Read the most recent `history_lines` of pane output. `tmux
    /// capture-pane -p -S -<n>` prints the pane contents to stdout.
    /// Caller is responsible for parsing / detecting the prompt
    /// stabilisation — capture is a snapshot, not a wait.
    pub async fn capture_pane(&self, history_lines: i32) -> Result<String> {
        let start = format!("-{history_lines}");
        let output = self
            .tmux_cmd()
            .arg("capture-pane")
            .arg("-p")
            .arg("-t")
            .arg(&self.name)
            .arg("-S")
            .arg(&start)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("spawn `tmux capture-pane`")?;
        if !output.status.success() {
            anyhow::bail!(
                "tmux capture-pane (session={}) exited with {:?}: {}",
                self.name,
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim(),
            );
        }
        String::from_utf8(output.stdout).context("tmux capture-pane stdout not valid UTF-8")
    }

    /// Poll `capture_pane` until the output stops changing for
    /// `stable_for` consecutive checks `poll_interval` apart, or
    /// `overall_timeout` elapses. Returns the final pane contents.
    ///
    /// Used by the adapter to wait for an interactive model to finish
    /// emitting tokens. Stabilisation is the canonical "the prompt is
    /// idle again" signal because the interactive `claude` CLI redraws
    /// its prompt cursor at the end of each response.
    pub async fn capture_until_stable(
        &self,
        history_lines: i32,
        poll_interval: Duration,
        stable_for: u32,
        overall_timeout: Duration,
    ) -> Result<String> {
        let started = std::time::Instant::now();
        let mut last = self.capture_pane(history_lines).await?;
        let mut stable_count = 0u32;
        while stable_count < stable_for {
            if started.elapsed() > overall_timeout {
                anyhow::bail!(
                    "tmux capture-pane on session {} did not stabilise within {:?}",
                    self.name,
                    overall_timeout,
                );
            }
            tokio::time::sleep(poll_interval).await;
            let now = self.capture_pane(history_lines).await?;
            if now == last {
                stable_count += 1;
            } else {
                stable_count = 0;
                last = now;
            }
        }
        Ok(last)
    }

    /// Best-effort terminate. Errors are logged but not propagated —
    /// `kill` is idempotent and the caller typically uses it on a
    /// happy path where the session might already be gone.
    pub async fn kill(&mut self) -> Result<()> {
        if self.killed {
            return Ok(());
        }
        let status = self
            .tmux_cmd()
            .arg("kill-session")
            .arg("-t")
            .arg(&self.name)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .context("spawn `tmux kill-session`")?;
        self.killed = true;
        if !status.success() {
            anyhow::bail!(
                "tmux kill-session -t {} exited with {:?}",
                self.name,
                status.code(),
            );
        }
        Ok(())
    }

    /// Check whether tmux still tracks this session. False when the
    /// session was killed externally or `kill()` already ran.
    pub async fn exists(&self) -> bool {
        let status = self
            .tmux_cmd()
            .arg("has-session")
            .arg("-t")
            .arg(&self.name)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
        matches!(status, Ok(s) if s.success())
    }
}

impl Drop for TmuxSession {
    fn drop(&mut self) {
        if self.killed {
            return;
        }
        // Fire-and-forget kill. We cannot await in Drop; spawn a
        // detached `tmux kill-session` via the synchronous std API so
        // the call still issues even when the surrounding tokio runtime
        // is being torn down. Errors are swallowed because the operator
        // already lost the session reference. Routes through
        // tmux_cmd_sync() to honour the operator's `-L <socket>` choice.
        let _ = self
            .tmux_cmd_sync()
            .arg("kill-session")
            .arg("-t")
            .arg(&self.name)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    }
}

/// Reject names that would let an operator/payload smuggle shell or
/// tmux-command metacharacters into `tmux -t <name>`. Tmux itself is
/// largely tolerant of weird names, but allowing `;` / `|` / `\n` /
/// `:` opens injection surface in `send-keys` args.
fn validate_session_name(name: &str) -> Result<()> {
    if name.is_empty() {
        anyhow::bail!("tmux session name cannot be empty");
    }
    if name.len() > 64 {
        anyhow::bail!("tmux session name too long ({} chars, max 64)", name.len());
    }
    for c in name.chars() {
        let ok = c.is_ascii_alphanumeric() || c == '-' || c == '_';
        if !ok {
            anyhow::bail!(
                "tmux session name `{name}` contains invalid char `{c}`. \
                 Allowed: ASCII alphanumeric, dash, underscore."
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // The runtime tests below skip themselves when tmux is not on PATH
    // (Windows CI, minimal CI images). Validation + name-policy tests
    // run everywhere.

    #[test]
    fn validate_session_name_accepts_clean_names() {
        assert!(validate_session_name("neoth-cc-1").is_ok());
        assert!(validate_session_name("session_42").is_ok());
        assert!(validate_session_name("a").is_ok());
    }

    #[test]
    fn validate_session_name_rejects_empty() {
        let e = validate_session_name("").unwrap_err();
        assert!(e.to_string().contains("empty"));
    }

    #[test]
    fn validate_session_name_rejects_metachars() {
        for bad in [
            "foo;rm", "foo|cat", "foo bar", "foo:bar", "foo\nbar", "foo$bar", "foo`bar",
        ] {
            let e = validate_session_name(bad).unwrap_err();
            assert!(
                e.to_string().contains("invalid char"),
                "expected reject for {bad:?}, got {e}"
            );
        }
    }

    #[test]
    fn validate_session_name_rejects_too_long() {
        let long = "a".repeat(65);
        let e = validate_session_name(&long).unwrap_err();
        assert!(e.to_string().contains("too long"));
    }

    #[test]
    fn default_session_prefix_matches_alex_bridge_convention() {
        // The `cc-` prefix is what Alex's claude_openai_bridge.py uses
        // on Jarvis. NEOTH adds `neoth-` in front so the two stacks
        // can share a host without colliding. Pinning this value keeps
        // the convention pinned across refactors.
        assert!(DEFAULT_SESSION_PREFIX.contains("cc"));
    }

    #[tokio::test]
    async fn is_available_returns_bool_without_panicking() {
        // Smoke: don't care which value, just that the check completes
        // without panicking on either Windows (no tmux) or Linux.
        let _ = TmuxSession::is_available().await;
    }

    /// Live tmux integration — only runs when tmux is on PATH.
    /// Spawns a `sleep 60` session, sends "hello", captures pane,
    /// asserts the literal text landed, then kills.
    #[tokio::test]
    async fn live_session_send_text_and_capture_roundtrip() {
        if !TmuxSession::is_available().await {
            eprintln!("tmux not available, skipping live integration test");
            return;
        }
        let name = format!("neoth-test-{}", std::process::id());
        // `cat` keeps the pane open waiting on stdin so capture-pane
        // has predictable contents after send-keys.
        let mut session = match TmuxSession::new(&name, "cat").await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("tmux new-session failed (host may not support detached sessions): {e}");
                return;
            }
        };
        session
            .send_text("hello-from-neoth")
            .await
            .expect("send_text");
        // Give tmux a tick to render the text into the pane buffer.
        tokio::time::sleep(Duration::from_millis(80)).await;
        let pane = session
            .capture_pane(DEFAULT_CAPTURE_HISTORY_LINES)
            .await
            .expect("capture_pane");
        assert!(
            pane.contains("hello-from-neoth"),
            "captured pane should contain literal text, got: {pane:?}",
        );
        session.kill().await.expect("kill");
        // After kill, `exists` should report false.
        let still = session.exists().await;
        assert!(!still, "session should be gone after kill");
    }

    #[tokio::test]
    async fn live_session_kill_is_idempotent() {
        if !TmuxSession::is_available().await {
            eprintln!("tmux not available, skipping live integration test");
            return;
        }
        let name = format!("neoth-test-idem-{}", std::process::id());
        let mut session = match TmuxSession::new(&name, "cat").await {
            Ok(s) => s,
            Err(_) => return,
        };
        session.kill().await.expect("first kill");
        // Second kill returns Ok because `killed` flag short-circuits.
        session.kill().await.expect("second kill (idempotent)");
    }

    #[tokio::test]
    async fn live_session_drop_cleans_up_without_explicit_kill() {
        if !TmuxSession::is_available().await {
            return;
        }
        let name = format!("neoth-test-drop-{}", std::process::id());
        {
            let _session = match TmuxSession::new(&name, "cat").await {
                Ok(s) => s,
                Err(_) => return,
            };
            // Drop without calling kill — the Drop impl spawns a
            // background `tmux kill-session`.
        }
        // Give the background spawn a moment to land.
        tokio::time::sleep(Duration::from_millis(150)).await;
        // Verify by asking tmux directly — `has-session` should fail.
        let status = Command::new("tmux")
            .arg("has-session")
            .arg("-t")
            .arg(&name)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
        if let Ok(s) = status {
            assert!(!s.success(), "Drop impl should have killed the session");
        }
    }

    #[tokio::test]
    async fn new_session_rejects_invalid_names_before_spawning_tmux() {
        // No tmux call happens — validation runs first. Works on
        // Windows + Linux equally because it never spawns.
        let r = TmuxSession::new("bad;name", "cat").await;
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("invalid char"));
    }

    // ── B-6 Item 4c integration tests (Session 22) ───────────────────

    #[tokio::test]
    async fn new_with_socket_rejects_invalid_names_before_spawning_tmux() {
        // Same validation path runs for the new_with_socket constructor.
        // Pin so a future refactor that splits validation doesn't
        // accidentally skip it on the new_with_socket path.
        let r = TmuxSession::new_with_socket("bad;name", "cat", TmuxSocket::neoth()).await;
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("invalid char"));
    }

    /// B-6 4c contract pin: a session constructed via the
    /// backward-compat `new()` lives on the shared per-user socket.
    /// Tmux probe-skip on Windows / no-tmux hosts — validation +
    /// field assertion run everywhere.
    #[tokio::test]
    async fn default_constructor_uses_shared_socket() {
        if !TmuxSession::is_available().await {
            return;
        }
        let s = TmuxSession::new("neoth-cc-b6-default-test", "cat")
            .await
            .expect("tmux new-session");
        assert!(s.socket().is_shared(), "new() must default to shared");
        // Drop kills the session.
        drop(s);
    }

    /// B-6 4c contract pin: `new_with_socket(TmuxSocket::neoth())`
    /// lands the session on the dedicated `-L neoth` server. Drop
    /// must kill on the SAME socket — otherwise the session would
    /// leak (kill on shared socket misses a session that lives on
    /// the dedicated socket).
    #[tokio::test]
    async fn new_with_socket_lands_session_on_dedicated_socket() {
        if !TmuxSession::is_available().await {
            return;
        }
        let s = TmuxSession::new_with_socket(
            "neoth-cc-b6-dedicated-test",
            "cat",
            TmuxSocket::neoth(),
        )
        .await
        .expect("tmux new-session -L neoth");
        assert_eq!(s.socket().name(), Some("neoth"));
        // The session MUST exist on the dedicated socket — verified
        // via exists() which routes through tmux_cmd() (same socket).
        assert!(
            s.exists().await,
            "session should be live on its own -L neoth server"
        );
        // And it must NOT show up on the shared socket (a cross-check
        // via has-session without -L would return false).
        let cross_check = Command::new("tmux")
            .arg("has-session")
            .arg("-t")
            .arg("neoth-cc-b6-dedicated-test")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
        // Cross-check returns non-success when the session lives on a
        // different socket. (Returns Ok+success only if the operator
        // happens to have a same-named session on the shared socket —
        // session name `neoth-cc-b6-dedicated-test` is unique enough
        // to make that vanishingly unlikely.)
        match cross_check {
            Ok(status) => assert!(
                !status.success(),
                "shared-socket cross-check should miss the dedicated-socket session"
            ),
            Err(_) => {
                // tmux binary missing mid-test — skip silently.
            }
        }
        // Cleanup explicit so the dedicated-socket session doesn't
        // leak between tests run in the same process.
        let mut s = s;
        let _ = s.kill().await;
    }
}
