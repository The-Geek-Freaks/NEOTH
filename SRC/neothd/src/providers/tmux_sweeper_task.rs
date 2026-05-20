//! Cron-style task that runs [`tmux_sweeper::sweep_once`] on a schedule.
//!
//! Wires the B-10 primitive into the daemon's long-running task graph
//! the same way `memory::decay_task` and `memory::gc_task` are wired:
//! `spawn(...)` returns a `JoinHandle` the daemon's drop-path awaits on
//! shutdown. The interval is operator-tunable (default 5 min) so a host
//! with many warm sessions can tighten the sweep without restart.
//!
//! On Windows or hosts without tmux the sweeper short-circuits to a
//! no-op inside `sweep_once`, so the task is safe to spawn unconditionally.

use std::time::Duration;

use anyhow::Result;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use super::tmux_session::DEFAULT_SESSION_PREFIX;
use super::tmux_sweeper::{DEFAULT_IDLE_TTL, SweepAction, sweep_once};

/// How often the sweeper task runs. 5 minutes balances "kill idle
/// sessions promptly" against "don't fork a `tmux ls` every few
/// seconds for a single-operator daemon".
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(300);

/// Spawn the periodic tmux sweeper.
///
/// `prefix` defaults to [`DEFAULT_SESSION_PREFIX`]; pass `None` to use
/// the convention. `idle_ttl` defaults to [`DEFAULT_IDLE_TTL`] (10 min).
/// `interval` defaults to [`DEFAULT_INTERVAL`].
///
/// The task runs forever; the returned handle aborts when dropped or
/// when the daemon's shutdown signal lands.
pub fn spawn(
    prefix: Option<String>,
    idle_ttl: Option<Duration>,
    interval: Option<Duration>,
) -> JoinHandle<Result<()>> {
    let prefix = prefix.unwrap_or_else(|| DEFAULT_SESSION_PREFIX.to_string());
    let idle_ttl = idle_ttl.unwrap_or(DEFAULT_IDLE_TTL);
    let interval = interval.unwrap_or(DEFAULT_INTERVAL);
    tokio::spawn(async move { run(prefix, idle_ttl, interval).await })
}

async fn run(prefix: String, idle_ttl: Duration, interval: Duration) -> Result<()> {
    info!(
        prefix = %prefix,
        idle_ttl_secs = idle_ttl.as_secs(),
        interval_secs = interval.as_secs(),
        "tmux sweeper task started",
    );
    let mut ticker = tokio::time::interval(interval);
    // Burn the first tick — `tokio::time::interval` fires immediately
    // on the initial poll, but a fresh-boot sweep would race the daemon's
    // own session creation. Skip it.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        match sweep_once(&prefix, idle_ttl).await {
            Ok(decisions) => {
                let killed = decisions
                    .iter()
                    .filter(|d| d.action == SweepAction::Killed)
                    .count();
                if killed > 0 {
                    info!(
                        killed,
                        total = decisions.len(),
                        "tmux sweeper killed idle session(s)",
                    );
                } else if !decisions.is_empty() {
                    debug!(total = decisions.len(), "tmux sweeper run — no kills",);
                }
                // No-decisions case (Windows / no tmux) stays silent.
            }
            Err(e) => {
                warn!(error = %e, "tmux sweeper run failed, will retry next tick");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_interval_is_5_minutes() {
        assert_eq!(DEFAULT_INTERVAL, Duration::from_secs(300));
    }

    #[tokio::test]
    async fn spawn_returns_handle_without_panicking() {
        // Smoke: spawn with a tiny interval, let it tick once on a
        // host without tmux (sweep_once short-circuits to Ok([])), then
        // abort + verify the handle was alive.
        let handle = spawn(
            Some("neoth-cc-test-".to_string()),
            Some(Duration::from_secs(1)),
            Some(Duration::from_millis(40)),
        );
        // Give the task a few interval cycles to prove it doesn't crash.
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(
            !handle.is_finished(),
            "sweeper task should still be running"
        );
        handle.abort();
    }
}
