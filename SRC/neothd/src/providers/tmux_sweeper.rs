//! Tmux session TTL sweeper (B-10).
//!
//! Companion to [`super::tmux_session::TmuxSession`]. A long-running NEOTH
//! daemon that wires the tmux backend (B-6 follow-up) will accumulate
//! warm sessions over time: one per operator / per conversation. If the
//! operator stops sending prompts to a conversation, the underlying
//! `claude` process still holds memory + a model context. Without a
//! sweeper a host with many idle sessions would slowly leak resources.
//!
//! The sweeper periodically lists every `tmux ls` entry whose name
//! starts with NEOTH's configured prefix, asks tmux for its
//! `session_activity` (timestamp of last input) via `tmux display-message
//! -p -F "#{session_activity}"`, and kills sessions whose idle time
//! exceeds the configured TTL.
//!
//! Pure tmux operation; no NEOTH state. The daemon's job is to call
//! [`sweep_once`] on a schedule (the cron module or a `tokio::spawn`
//! interval). The sweeper itself is stateless + idempotent.

use std::time::Duration;

use anyhow::{Context, Result};
use tokio::process::Command;

use super::tmux_socket::{TmuxSocket, socket_args};

/// Default operator-grade TTL: 10 minutes idle = stale. Matches Alex's
/// bridge `TMUX_IDLE_SECS=600` env default.
pub const DEFAULT_IDLE_TTL: Duration = Duration::from_secs(600);

/// One swept session — what we did and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepDecision {
    pub session_name: String,
    pub idle_secs: u64,
    pub action: SweepAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepAction {
    /// Session was killed because `idle_secs > ttl`.
    Killed,
    /// Session is below TTL; left alone.
    Kept,
    /// Session disappeared between list + kill — race we tolerate
    /// (operator could have closed it via `tmux kill-session`).
    AlreadyGone,
}

/// Run one sweep pass. Lists every session whose name starts with
/// `prefix`, computes its idle time, and kills sessions older than
/// `idle_ttl`. Returns the per-session decisions so the daemon can log
/// them.
///
/// When tmux is not installed the function returns an empty Vec — the
/// sweeper is a no-op on Windows hosts, matching the [`TmuxSession`]
/// degradation strategy.
pub async fn sweep_once(prefix: &str, idle_ttl: Duration) -> Result<Vec<SweepDecision>> {
    sweep_once_on_socket(prefix, idle_ttl, &TmuxSocket::shared()).await
}

/// B-6 Item 4c integration (Session 22) — socket-aware sweep variant.
/// Honours the operator's `freedom.yaml::claude_cli.tmux.socket_name`
/// so daemon-managed sessions on `-L neoth` get swept by their own
/// sweeper without touching sessions on the operator's shared socket.
pub async fn sweep_once_on_socket(
    prefix: &str,
    idle_ttl: Duration,
    socket: &TmuxSocket,
) -> Result<Vec<SweepDecision>> {
    if prefix.is_empty() {
        anyhow::bail!("tmux sweep: prefix must not be empty (would match every session)");
    }
    let sessions = list_neoth_sessions_on_socket(prefix, socket).await?;
    let now = current_unix_secs();
    let mut decisions = Vec::with_capacity(sessions.len());
    for (name, activity_ts) in sessions {
        let idle_secs = now.saturating_sub(activity_ts);
        if idle_secs > idle_ttl.as_secs() {
            let action = match kill_session_on_socket(&name, socket).await {
                Ok(_) => SweepAction::Killed,
                Err(_) => SweepAction::AlreadyGone,
            };
            decisions.push(SweepDecision {
                session_name: name,
                idle_secs,
                action,
            });
        } else {
            decisions.push(SweepDecision {
                session_name: name,
                idle_secs,
                action: SweepAction::Kept,
            });
        }
    }
    Ok(decisions)
}

/// `tmux ls -F '#{session_name} #{session_activity}'` — emits one line
/// per session. `session_activity` is a unix-epoch-seconds value tmux
/// updates whenever input/output happens in the pane. Backward-compat
/// wrapper around [`list_neoth_sessions_on_socket`] using the shared
/// socket.
#[allow(dead_code)]
async fn list_neoth_sessions(prefix: &str) -> Result<Vec<(String, u64)>> {
    list_neoth_sessions_on_socket(prefix, &TmuxSocket::shared()).await
}

async fn list_neoth_sessions_on_socket(
    prefix: &str,
    socket: &TmuxSocket,
) -> Result<Vec<(String, u64)>> {
    let mut cmd = Command::new("tmux");
    for arg in socket_args(socket.name()) {
        cmd.arg(arg);
    }
    let output = cmd
        .arg("ls")
        .arg("-F")
        .arg("#{session_name} #{session_activity}")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await;
    let output = match output {
        Ok(o) => o,
        Err(_) => {
            // tmux not installed → no sessions to sweep.
            return Ok(Vec::new());
        }
    };
    if !output.status.success() {
        // `tmux ls` exits 1 when there is no server running — that
        // means "no sessions", not an error worth propagating. Other
        // non-zero exits with stderr content surface as Err.
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("no server running") || stderr.is_empty() {
            return Ok(Vec::new());
        }
        anyhow::bail!("tmux ls failed: {}", stderr.trim());
    }
    let stdout = String::from_utf8(output.stdout).context("tmux ls stdout not UTF-8")?;
    Ok(parse_tmux_ls(&stdout, prefix))
}

/// Pure parser — testable without tmux on PATH. Each line shape:
/// `<name> <epoch_secs>`; we keep only entries whose name starts with
/// `prefix`.
fn parse_tmux_ls(stdout: &str, prefix: &str) -> Vec<(String, u64)> {
    stdout
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(2, ' ');
            let name = parts.next()?;
            let ts = parts.next()?.trim().parse::<u64>().ok()?;
            if name.starts_with(prefix) {
                Some((name.to_string(), ts))
            } else {
                None
            }
        })
        .collect()
}

#[allow(dead_code)]
async fn kill_session(name: &str) -> Result<()> {
    kill_session_on_socket(name, &TmuxSocket::shared()).await
}

async fn kill_session_on_socket(name: &str, socket: &TmuxSocket) -> Result<()> {
    let mut cmd = Command::new("tmux");
    for arg in socket_args(socket.name()) {
        cmd.arg(arg);
    }
    let status = cmd
        .arg("kill-session")
        .arg("-t")
        .arg(name)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .context("spawn `tmux kill-session`")?;
    if !status.success() {
        anyhow::bail!(
            "tmux kill-session -t {name} exited with {:?}",
            status.code()
        );
    }
    Ok(())
}

fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::tmux_session::{DEFAULT_SESSION_PREFIX, TmuxSession};

    #[test]
    fn parse_tmux_ls_filters_by_prefix() {
        let stdout = "neoth-cc-a 1700000000\nrandom-other 1700000050\nneoth-cc-b 1700000100\n";
        let rows = parse_tmux_ls(stdout, "neoth-cc-");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, "neoth-cc-a");
        assert_eq!(rows[0].1, 1_700_000_000);
        assert_eq!(rows[1].0, "neoth-cc-b");
        assert_eq!(rows[1].1, 1_700_000_100);
    }

    #[test]
    fn parse_tmux_ls_skips_malformed_lines() {
        let stdout = "neoth-cc-good 1700000000\nneoth-cc-bad notanumber\nneoth-cc-empty\n\n";
        let rows = parse_tmux_ls(stdout, "neoth-cc-");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "neoth-cc-good");
    }

    #[test]
    fn parse_tmux_ls_returns_empty_on_no_matches() {
        let stdout = "other-foo 1700000000\nother-bar 1700000050\n";
        let rows = parse_tmux_ls(stdout, "neoth-cc-");
        assert!(rows.is_empty());
    }

    #[test]
    fn parse_tmux_ls_handles_empty_stdout() {
        assert!(parse_tmux_ls("", "neoth-cc-").is_empty());
        assert!(parse_tmux_ls("\n\n", "neoth-cc-").is_empty());
    }

    #[tokio::test]
    async fn sweep_once_rejects_empty_prefix() {
        let err = sweep_once("", Duration::from_secs(60)).await.unwrap_err();
        assert!(err.to_string().contains("prefix must not be empty"));
    }

    #[tokio::test]
    async fn sweep_once_returns_ok_when_tmux_absent_or_no_server() {
        // On Windows / minimal CI tmux isn't available. The sweeper
        // returns Ok(empty) instead of erroring so a scheduled job
        // doesn't crash on Windows daemons.
        let decisions = sweep_once("neoth-cc-", Duration::from_secs(60)).await;
        assert!(decisions.is_ok());
    }

    /// Live integration — spawns 2 sessions, sweeps with TTL=0 so both
    /// qualify, asserts both got Killed. Skipped when tmux absent.
    #[tokio::test]
    async fn live_sweeper_kills_idle_sessions_over_ttl() {
        if !TmuxSession::is_available().await {
            eprintln!("tmux not available, skipping live sweeper test");
            return;
        }
        let pid = std::process::id();
        let name_a = format!("neoth-cc-sweep-a-{pid}");
        let name_b = format!("neoth-cc-sweep-b-{pid}");
        let session_a = match TmuxSession::new(&name_a, "cat").await {
            Ok(s) => s,
            Err(_) => return,
        };
        let session_b = match TmuxSession::new(&name_b, "cat").await {
            Ok(s) => s,
            Err(_) => return,
        };
        // TTL = 0 — every session is over-ttl regardless of activity ts.
        let decisions = sweep_once("neoth-cc-sweep-", Duration::from_secs(0))
            .await
            .expect("sweep");

        // Should have at least 2 Killed entries for our two sessions.
        let killed: Vec<_> = decisions
            .iter()
            .filter(|d| {
                d.action == SweepAction::Killed
                    && (d.session_name == name_a || d.session_name == name_b)
            })
            .collect();
        assert!(
            killed.len() >= 2,
            "expected at least 2 killed, got decisions={decisions:?}"
        );
        // Sessions should no longer exist.
        assert!(!session_a.exists().await);
        assert!(!session_b.exists().await);
        // Drop the values — their Drop impl no-ops because tmux already
        // reported the sessions gone. Suppress unused-var warning.
        drop(session_a);
        drop(session_b);
    }

    /// Live integration — TTL set high enough that fresh sessions are
    /// `Kept`, not killed. Validates the keep branch is reachable.
    #[tokio::test]
    async fn live_sweeper_keeps_fresh_sessions_below_ttl() {
        if !TmuxSession::is_available().await {
            return;
        }
        let pid = std::process::id();
        let name = format!("neoth-cc-keep-{pid}");
        let mut session = match TmuxSession::new(&name, "cat").await {
            Ok(s) => s,
            Err(_) => return,
        };
        // TTL = 1 hour — the just-created session is well below it.
        let decisions = sweep_once("neoth-cc-keep-", Duration::from_secs(3600))
            .await
            .expect("sweep");
        let kept = decisions
            .iter()
            .find(|d| d.session_name == name)
            .expect("our session should appear");
        assert_eq!(kept.action, SweepAction::Kept);
        session.kill().await.expect("teardown kill");
    }

    #[test]
    fn default_idle_ttl_matches_bridge_convention() {
        // Alex's bridge env: TMUX_IDLE_SECS=600. Pin so a refactor
        // doesn't silently drift away from operator's existing
        // expectation when the two stacks share a host.
        assert_eq!(DEFAULT_IDLE_TTL, Duration::from_secs(600));
    }

    #[test]
    fn default_session_prefix_compatible_with_sweeper() {
        // Sweeper's `prefix` arg + tmux_session::DEFAULT_SESSION_PREFIX
        // must agree by convention; if these drift, the sweeper would
        // silently miss every session NEOTH spawns.
        assert!(DEFAULT_SESSION_PREFIX.starts_with("neoth-"));
    }

    // ── B-6 Item 4c socket-aware sweep tests (Session 22) ────────────

    #[tokio::test]
    async fn sweep_on_dedicated_socket_only_sees_its_own_sessions() {
        // B-6 4c contract: a sweep run on the dedicated `-L neoth`
        // socket MUST NOT touch sessions on the shared socket. Proves
        // socket isolation end-to-end through the sweeper.
        if !TmuxSession::is_available().await {
            return;
        }
        let pid = std::process::id();
        // Spawn one session on shared, one on dedicated.
        let name_shared = format!("neoth-cc-shared-iso-{pid}");
        let name_dedicated = format!("neoth-cc-dedicated-iso-{pid}");
        let mut s_shared = match TmuxSession::new(&name_shared, "cat").await {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut s_dedicated = match TmuxSession::new_with_socket(
            &name_dedicated,
            "cat",
            TmuxSocket::neoth(),
        )
        .await
        {
            Ok(s) => s,
            Err(_) => {
                let _ = s_shared.kill().await;
                return;
            }
        };
        // Sweep on dedicated socket — should see ONLY the dedicated
        // session under the matching prefix.
        let decisions = sweep_once_on_socket(
            "neoth-cc-dedicated-iso-",
            Duration::from_secs(3600),
            &TmuxSocket::neoth(),
        )
        .await
        .expect("sweep on dedicated");
        assert!(
            decisions.iter().any(|d| d.session_name == name_dedicated),
            "dedicated-socket sweep should see dedicated-socket session"
        );
        // Now sweep on dedicated socket with the SHARED-socket prefix
        // — must NOT see the shared-socket session because it lives
        // on a different server.
        let decisions_cross = sweep_once_on_socket(
            "neoth-cc-shared-iso-",
            Duration::from_secs(3600),
            &TmuxSocket::neoth(),
        )
        .await
        .expect("sweep on dedicated (shared-prefix)");
        assert!(
            !decisions_cross.iter().any(|d| d.session_name == name_shared),
            "dedicated-socket sweep MUST NOT see shared-socket sessions"
        );
        let _ = s_shared.kill().await;
        let _ = s_dedicated.kill().await;
    }

    #[tokio::test]
    async fn sweep_once_backward_compat_uses_shared_socket() {
        // Pin: the no-socket-arg `sweep_once` defaults to shared,
        // matching pre-4c behaviour. A future refactor that flipped
        // the default to dedicated would silently stop sweeping
        // operator-side shared-socket sessions.
        if !TmuxSession::is_available().await {
            return;
        }
        let pid = std::process::id();
        let name = format!("neoth-cc-compat-{pid}");
        let mut session = match TmuxSession::new(&name, "cat").await {
            Ok(s) => s,
            Err(_) => return,
        };
        // sweep_once (no socket arg) must see the shared-socket session.
        let decisions = sweep_once("neoth-cc-compat-", Duration::from_secs(3600))
            .await
            .expect("sweep_once backward compat");
        assert!(
            decisions.iter().any(|d| d.session_name == name),
            "sweep_once must see shared-socket session by default"
        );
        let _ = session.kill().await;
    }
}
