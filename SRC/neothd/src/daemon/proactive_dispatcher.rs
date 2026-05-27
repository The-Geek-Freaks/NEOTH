//! Round-3 v0.4 G-01 consumer half — drains [`ProactiveQueue`] +
//! delivers items to a per-operator JSONL sidecar.
//!
//! G-01a (Session 24) shipped the bounded queue + `enqueue` /
//! `drain` / persistence. G-01-mini (Session 24) ships the
//! reflection producer. G-01 cron-wiring (Session 28 commit
//! `7acb181`) wires the producer into a 24h cron. **This module
//! closes the consumer half**: ticks every
//! [`PROACTIVE_DRAIN_INTERVAL_SECS`], pops items in priority +
//! schedule order respecting the daily-budget cap, appends each to
//! `~/.neoth/proactive_delivered.jsonl` for operator inspection.
//!
//! The JSONL sidecar is the operator-visible "delivered inbox" —
//! one JSON per line, append-only, never truncated. Operators
//! `tail -f` it during a session OR a future
//! `neoth proactive items list` CLI surface paginates the recent
//! tail. Channel-side delivery (Telegram message / Slack DM /
//! Keet / Discord) is the L follow-on once each adapter consumes
//! the sidecar.
//!
//! ## Why sidecar not channel-direct
//!
//! Channel adapters are async + per-protocol (Telegram bot API,
//! Slack Web API, etc.). Putting the channel-dispatch inside the
//! drain loop would bind every operator to running the channels
//! they care about + couple the drain cadence to the slowest
//! adapter. A sidecar JSONL is:
//!   - Always present (zero-channel operators still see their
//!     proactive items).
//!   - Append-only + crash-safe (no torn writes; each line is one
//!     drain operation).
//!   - Cheap to consume from any future adapter (channel adapter
//!     tails the file + sends each new line; tail-cursor is the
//!     adapter's local state).

use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::task::JoinHandle;
use tracing::{info, warn};

/// Default drain-tick interval — 5 minutes in seconds. Producers
/// (G-01-mini reflection cron at 24h) enqueue at much lower
/// frequency, so 5min is comfortable: at most 12 drain ticks per
/// hour, well under the queue's daily-budget cap (default 3/day).
/// Operators tune via `freedom.yaml::proactive.drain_interval_secs`
/// in the follow-on slice.
pub const PROACTIVE_DRAIN_INTERVAL_SECS: u64 = 5 * 60;

/// Per-tick drain cap — at most N items pop per tick. Caps the
/// notification storm a bursty producer could otherwise trigger.
/// The queue's own daily budget (default 3/day) is the harder
/// guarantee; this tick-cap is just a smoothing layer.
pub const PROACTIVE_PER_TICK_CAP: usize = 3;

/// JSONL sidecar filename inside `~/.neoth/`. Operators tail this
/// to see delivered items; future channel adapters subscribe to
/// the same file for at-least-once delivery semantics.
pub const PROACTIVE_DELIVERED_SIDECAR: &str = "proactive_delivered.jsonl";

/// One drain tick: load the queue, pop up to cap items, append
/// each to the sidecar, save the post-drain queue.
///
/// Pure-fn (no async) so tests can call directly. Returns the
/// number of items delivered (0 when queue empty / cap=0 / budget
/// exhausted). Errors propagate from queue load/save + sidecar
/// append.
pub fn run_proactive_drain_tick(home: &Path, now_unix: i64) -> Result<usize, String> {
    use crate::proactive::ProactiveQueue;

    let queue_path = home.join("proactive_queue.json");
    if !queue_path.exists() {
        return Ok(0);
    }
    let mut queue =
        ProactiveQueue::load_from(&queue_path).map_err(|e| format!("queue load failed: {e}"))?;
    if queue.is_empty() {
        return Ok(0);
    }
    let drained = queue.drain(now_unix, PROACTIVE_PER_TICK_CAP);
    if drained.is_empty() {
        // Either daily-budget exhausted OR cap=0 OR every item is
        // future-scheduled. Persist nothing + return.
        return Ok(0);
    }

    let sidecar_path = home.join(PROACTIVE_DELIVERED_SIDECAR);
    append_to_sidecar(&sidecar_path, &drained, now_unix)
        .map_err(|e| format!("sidecar append failed: {e}"))?;

    queue
        .save_to(&queue_path)
        .map_err(|e| format!("queue save after drain failed: {e}"))?;
    Ok(drained.len())
}

fn append_to_sidecar(
    sidecar_path: &Path,
    items: &[crate::proactive::ProactiveItem],
    now_unix: i64,
) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(sidecar_path)?;
    for item in items {
        let line = serde_json::to_string(&serde_json::json!({
            "delivered_at_unix": now_unix,
            "item": item,
        }))
        .unwrap_or_default();
        writeln!(f, "{line}")?;
    }
    f.flush()?;
    Ok(())
}

/// Spawn the daemon-side drain loop. Matches the doctor_cron /
/// reflection_cron pattern. Returns the JoinHandle the daemon's
/// shutdown path can `.abort()`.
pub fn spawn_proactive_drain_loop(home: PathBuf, interval_secs: u64) -> JoinHandle<()> {
    let interval = Duration::from_secs(interval_secs.max(30));
    tokio::spawn(async move {
        info!(
            interval_secs = interval.as_secs(),
            home = %home.display(),
            "proactive drain loop spawned (G-01 consumer half)"
        );
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            let now_unix = chrono::Utc::now().timestamp();
            match run_proactive_drain_tick(&home, now_unix) {
                Ok(0) => {
                    tracing::debug!("proactive drain tick: nothing to deliver");
                }
                Ok(n) => info!(
                    delivered = n,
                    "proactive drain tick: {n} item(s) appended to sidecar",
                ),
                Err(e) => {
                    warn!(error = %e, "proactive drain tick failed; will retry next interval")
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proactive::{ProactiveItem, ProactiveQueue};
    use tempfile::TempDir;

    fn item(key: &str, priority: i32, ts: i64) -> ProactiveItem {
        ProactiveItem {
            priority,
            dedup_key: key.to_string(),
            channel: "cli".to_string(),
            source: "test".to_string(),
            body: format!("test body {key}"),
            scheduled_for_unix: ts,
        }
    }

    #[test]
    fn drain_tick_no_queue_file_returns_zero() {
        let tmp = TempDir::new().unwrap();
        let n = run_proactive_drain_tick(tmp.path(), 1_700_000_000).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn drain_tick_empty_queue_returns_zero() {
        let tmp = TempDir::new().unwrap();
        let queue = ProactiveQueue::new();
        queue
            .save_to(&tmp.path().join("proactive_queue.json"))
            .unwrap();
        let n = run_proactive_drain_tick(tmp.path(), 1_700_000_000).unwrap();
        assert_eq!(n, 0);
        // No sidecar gets written for empty drains.
        assert!(!tmp.path().join(PROACTIVE_DELIVERED_SIDECAR).exists());
    }

    #[test]
    fn drain_tick_appends_each_drained_item_to_sidecar() {
        let tmp = TempDir::new().unwrap();
        let mut queue = ProactiveQueue::new();
        queue.enqueue(item("a", 50, 0));
        queue.enqueue(item("b", 50, 0));
        queue
            .save_to(&tmp.path().join("proactive_queue.json"))
            .unwrap();
        let n = run_proactive_drain_tick(tmp.path(), 1_700_000_000).unwrap();
        assert_eq!(n, 2);
        let sidecar = tmp.path().join(PROACTIVE_DELIVERED_SIDECAR);
        assert!(sidecar.exists());
        let body = std::fs::read_to_string(sidecar).unwrap();
        // Two lines (one per item) — JSONL format.
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2);
        // Each line is valid JSON.
        for line in &lines {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(v["delivered_at_unix"], 1_700_000_000);
            assert!(v["item"].is_object());
        }
    }

    #[test]
    fn drain_tick_persists_post_drain_queue() {
        let tmp = TempDir::new().unwrap();
        let mut queue = ProactiveQueue::new();
        queue.enqueue(item("a", 50, 0));
        queue.enqueue(item("b", 50, 0));
        let q_path = tmp.path().join("proactive_queue.json");
        queue.save_to(&q_path).unwrap();
        run_proactive_drain_tick(tmp.path(), 1_700_000_000).unwrap();
        // Reload from disk + verify both items are gone.
        let after = ProactiveQueue::load_from(&q_path).unwrap();
        assert!(after.is_empty());
    }

    #[test]
    fn drain_tick_respects_per_tick_cap() {
        // Enqueue more items than PROACTIVE_PER_TICK_CAP and verify
        // the tick only pops up to the cap. NB: the queue's daily
        // budget defaults to 3, which equals PROACTIVE_PER_TICK_CAP
        // — so the cap actually fires here only if both budgets
        // align. With cap 3 + budget 3 + 5 items enqueued, we get 3
        // out + 2 remain.
        let tmp = TempDir::new().unwrap();
        let mut queue = ProactiveQueue::new();
        for k in 0..5 {
            queue.enqueue(item(&format!("k{k}"), 50, 0));
        }
        queue
            .save_to(&tmp.path().join("proactive_queue.json"))
            .unwrap();
        let n = run_proactive_drain_tick(tmp.path(), 1_700_000_000).unwrap();
        assert_eq!(n, PROACTIVE_PER_TICK_CAP);
        let after = ProactiveQueue::load_from(&tmp.path().join("proactive_queue.json")).unwrap();
        assert_eq!(after.peek().len(), 5 - PROACTIVE_PER_TICK_CAP);
    }

    #[test]
    fn drain_tick_appends_not_truncates_sidecar() {
        let tmp = TempDir::new().unwrap();
        let sidecar = tmp.path().join(PROACTIVE_DELIVERED_SIDECAR);
        std::fs::write(&sidecar, "{\"existing\": \"line\"}\n").unwrap();
        let mut queue = ProactiveQueue::new();
        queue.enqueue(item("new", 50, 0));
        queue
            .save_to(&tmp.path().join("proactive_queue.json"))
            .unwrap();
        run_proactive_drain_tick(tmp.path(), 1_700_000_000).unwrap();
        let body = std::fs::read_to_string(&sidecar).unwrap();
        assert!(
            body.starts_with("{\"existing\": \"line\"}"),
            "existing line MUST be preserved (append-only contract)",
        );
        assert!(body.contains("\"delivered_at_unix\"") && body.contains("\"item\""));
    }

    #[test]
    fn constants_canonical() {
        assert_eq!(PROACTIVE_DRAIN_INTERVAL_SECS, 5 * 60);
        assert_eq!(PROACTIVE_PER_TICK_CAP, 3);
        assert_eq!(PROACTIVE_DELIVERED_SIDECAR, "proactive_delivered.jsonl");
    }
}
