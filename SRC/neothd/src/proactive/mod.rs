//! G-01a (Session 24) — `ProactiveQueue` shared substrate.
//!
//! A1 + A2 #11 pinned G-01a as the prerequisite for v0.5 PL-03
//! (proactive learning briefings) + OB-03 (Obsidian-as-scratchpad
//! reminders): without a SHARED dedup + rate-limit queue, every
//! proactive producer would create its own notification storm.
//! Operator gets one daily-cap-respecting drainable queue
//! regardless of how many things upstream want to nudge them.
//!
//! ## Item shape
//!
//! `ProactiveItem { priority, dedup_key, channel, source, body,
//! scheduled_for_unix }`. Higher `priority` drains first; ties
//! break on `scheduled_for_unix` (earliest first). The `dedup_key`
//! is the operator-meaningful identity: enqueueing an item whose
//! `dedup_key` matches an already-queued item is a no-op (the
//! prior item wins). Source tag + channel exist so the operator
//! can audit `who-said-what` after the fact via `neoth proactive
//! list --history`.
//!
//! ## Daily cap
//!
//! Default `max_per_day = 3`. `drain(now_unix, cap)` returns up
//! to `cap` items whose `scheduled_for_unix <= now_unix`, in
//! priority-desc order. The queue tracks recent-drain timestamps
//! in a 24h rolling window so a SECOND drain call inside the same
//! window respects the budget left from the first.
//!
//! ## Persistence
//!
//! `save_to(path)` + `load_from(path)` round-trip the queue +
//! drain-history through a JSON file (atomic .tmp + rename). The
//! daemon's bootstrap calls `load_from` to restore queued items
//! across restarts; the drain cron calls `save_to` after every
//! tick so a crash mid-tick doesn't lose state.
//!
//! ## Scope of this commit (G-01a)
//!
//! - In-memory queue + dedup + priority + daily-cap drain.
//! - Persistence helpers (save / load).
//! - Tests covering every behaviour.
//!
//! Producer-side wiring (G-01-mini reflection cron, PL-03, OB-03,
//! Self-correction loop) is the next commit set — those callers
//! consume `ProactiveQueue::enqueue`. The shared substrate
//! unblocks them.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub mod action_staging;

/// One queued proactive notification. Fields are operator-facing —
/// the CLI's `neoth proactive list` renders each verbatim, and the
/// audit trail records the full struct.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProactiveItem {
    /// Higher fires first. Operator-defined; rough convention:
    ///   - 100 = "urgent — operator asked for it"
    ///   - 50  = "useful unprompted nudge"
    ///   - 10  = "background telemetry observation"
    pub priority: i32,
    /// Operator-meaningful identity. Duplicate enqueues are no-ops.
    /// Convention: `"<producer>:<topic>:<window>"` so a daily-briefing
    /// dedup key `"reflection:morning-news:2026-05-25"` won't enqueue
    /// twice within the same day even if the cron fires multiple times.
    pub dedup_key: String,
    /// Channel target by name as recognised by `channels::Channel::name`
    /// (`telegram` / `keet` / `slack` / `cli`). Empty falls back to
    /// the operator's default channel.
    pub channel: String,
    /// Producer tag for audit. e.g. `"g_01_mini"` / `"pl_03"` /
    /// `"ob_03"` / `"self_correction"`.
    pub source: String,
    /// The notification body the operator sees. Pre-rendered;
    /// channel adapters apply their own formatting on top.
    pub body: String,
    /// Earliest unix-seconds time this item may drain. `drain` skips
    /// items whose `scheduled_for_unix > now_unix`. Default 0 =
    /// drain immediately.
    pub scheduled_for_unix: i64,
    /// GOLD-FEAT-13 — when `true`, channel routing prefers the operator's
    /// configured `failure_channel` (e.g. a coding session that ended with
    /// blocked tasks). `#[serde(default)]` so queue files written before this
    /// field deserialise as non-failure.
    #[serde(default)]
    pub is_failure: bool,
    /// JV-PRO-10 — TTL. Unix-seconds after which a still-queued item is
    /// DROPPED on the next `drain` without ever firing (a stale nudge —
    /// e.g. yesterday's news held back by the daily cap — is worse than no
    /// nudge). `0` = never expires. `#[serde(default)]` so queue files
    /// written before this field load as evergreen. Producers of
    /// time-sensitive items set it; evergreen items leave it `0`.
    #[serde(default)]
    pub expires_unix: i64,
}

/// JV-PRO-10 — items at/above this priority "early-surface": they bypass
/// `scheduled_for_unix` (drain before their scheduled time). NOTE (D53): this
/// bypasses only the SCHEDULE, not the daily cap — `take_n = cap.min(budget_left)`
/// still applies, so once the per-day budget is exhausted even an urgent item
/// drains nothing until the next day. This is the operator-urgent / signal path
/// (the upstream "DSPM signal" → surface now), matching the priority-100
/// "urgent — operator asked for it" convention above.
pub const URGENT_PRIORITY: i32 = 100;

/// Daily-cap configuration. `max_per_day = 3` is the AGENTER hard-
/// rule default for proactive messages (operator opt-in beyond
/// that via `neoth proactive config --max-per-day N`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProactiveConfig {
    pub max_per_day: usize,
}

impl Default for ProactiveConfig {
    fn default() -> Self {
        Self { max_per_day: 3 }
    }
}

/// The in-memory proactive queue. Cheaply clonable via `Arc<Mutex<_>>`
/// at the wrapper layer when shared across producers — this struct
/// itself owns its state.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProactiveQueue {
    items: Vec<ProactiveItem>,
    /// Recent drain timestamps (unix-seconds). The daily-cap check
    /// counts entries within `now - 86_400 < ts <= now`. Pruned
    /// inside `drain` to keep the vector bounded.
    drained_at: Vec<i64>,
    #[serde(default)]
    pub config: ProactiveConfig,
}

impl ProactiveQueue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: ProactiveConfig) -> Self {
        Self {
            items: Vec::new(),
            drained_at: Vec::new(),
            config,
        }
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Enqueue `item`. Returns `true` on insert, `false` when the
    /// `dedup_key` already exists in the queue (prior item wins,
    /// matches the spec).
    pub fn enqueue(&mut self, item: ProactiveItem) -> bool {
        if self.items.iter().any(|i| i.dedup_key == item.dedup_key) {
            return false;
        }
        self.items.push(item);
        true
    }

    /// Pop up to `cap` items in priority-desc order, capped by both
    /// `cap` and the remaining daily-budget (per `config.max_per_day`).
    /// Records the wall-clock of each drained item so subsequent
    /// drains within the same 24h window respect the budget.
    ///
    /// `now_unix` is injected so tests can simulate arbitrary clock
    /// positions without sleeping; production callers pass the real
    /// wall clock.
    pub fn drain(&mut self, now_unix: i64, cap: usize) -> Vec<ProactiveItem> {
        // JV-PRO-10 — drop expired items BEFORE anything else (even before
        // the budget check), so a stale nudge never fires and an exhausted
        // daily budget can't keep dead items alive on disk.
        self.items
            .retain(|i| i.expires_unix == 0 || i.expires_unix > now_unix);
        let cutoff = now_unix.saturating_sub(86_400);
        self.drained_at.retain(|t| *t > cutoff);
        let used_today = self.drained_at.len();
        let budget_left = self.config.max_per_day.saturating_sub(used_today);
        let take_n = cap.min(budget_left);
        if take_n == 0 {
            return Vec::new();
        }

        // Index-based selection so we can pull from the middle of
        // the vec without an O(n log n) sort allocation per drain.
        let mut eligible: Vec<usize> = self
            .items
            .iter()
            .enumerate()
            // JV-PRO-10 — an item drains once its schedule arrives, OR
            // immediately if it is operator-urgent (early-surface bypass).
            .filter(|(_, i)| i.scheduled_for_unix <= now_unix || i.priority >= URGENT_PRIORITY)
            .map(|(idx, _)| idx)
            .collect();
        eligible.sort_by(|a, b| {
            self.items[*b]
                .priority
                .cmp(&self.items[*a].priority)
                .then_with(|| {
                    self.items[*a]
                        .scheduled_for_unix
                        .cmp(&self.items[*b].scheduled_for_unix)
                })
        });
        eligible.truncate(take_n);

        // Remove from highest index downward so prior indices stay valid.
        eligible.sort_unstable_by(|a, b| b.cmp(a));
        let mut out: Vec<ProactiveItem> = eligible
            .into_iter()
            .map(|idx| self.items.remove(idx))
            .collect();
        // Restore priority-desc order for the caller (the index
        // removal above pulled them in descending-index, which is
        // unrelated to priority).
        out.sort_by_key(|item| std::cmp::Reverse(item.priority));
        for _ in &out {
            self.drained_at.push(now_unix);
        }
        out
    }

    /// Peek at items currently in the queue (immutable view). Useful
    /// for `neoth proactive list` without consuming the queue.
    pub fn peek(&self) -> &[ProactiveItem] {
        &self.items
    }

    /// Remaining daily budget. Returns `config.max_per_day` minus
    /// the count of drains within the last 24h. Pure read; doesn't
    /// mutate the rolling window.
    pub fn budget_left(&self, now_unix: i64) -> usize {
        let cutoff = now_unix.saturating_sub(86_400);
        let used = self.drained_at.iter().filter(|t| **t > cutoff).count();
        self.config.max_per_day.saturating_sub(used)
    }

    /// Drop every item whose `dedup_key` matches `key`. Returns the
    /// number removed. Used by `neoth proactive drop <key>` for an
    /// operator who decided a queued nudge isn't relevant anymore.
    pub fn remove_by_key(&mut self, key: &str) -> usize {
        let before = self.items.len();
        self.items.retain(|i| i.dedup_key != key);
        before - self.items.len()
    }

    /// Atomic save via `.tmp` + rename. Mode 0600 on unix; restricted
    /// DACL on Windows via the credentials helper. Mirrors the
    /// pattern used by `wizard_checkpoint::save_checkpoint`.
    pub fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create parent dir for {}", path.display()))?;
        }
        let bytes = serde_json::to_vec_pretty(self).context("serialise proactive queue")?;
        let tmp = path.with_extension("json.tmp");
        crate::config::credentials::write_mode_0600(&tmp, &bytes)
            .with_context(|| format!("write tmp {}", tmp.display()))?;
        std::fs::rename(&tmp, path)
            .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
        Ok(())
    }

    /// Read the queue from disk. Returns `Ok(Self::default())` when
    /// the file is missing OR zero-length (atomic-rename race window)
    /// so a fresh-install daemon can call this unconditionally.
    pub fn load_from(path: &Path) -> Result<Self> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
        };
        if bytes.is_empty() {
            return Ok(Self::default());
        }
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
    }

    /// Stats snapshot for the operator-facing `neoth proactive
    /// status` line. Pure-read.
    pub fn stats(&self, now_unix: i64) -> QueueStats {
        let cutoff = now_unix.saturating_sub(86_400);
        let drained_24h = self.drained_at.iter().filter(|t| **t > cutoff).count();
        let by_source: HashMap<String, usize> =
            self.items.iter().fold(HashMap::new(), |mut acc, i| {
                *acc.entry(i.source.clone()).or_insert(0) += 1;
                acc
            });
        QueueStats {
            queued: self.items.len(),
            drained_last_24h: drained_24h,
            budget_left: self.budget_left(now_unix),
            by_source,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QueueStats {
    pub queued: usize,
    pub drained_last_24h: usize,
    pub budget_left: usize,
    pub by_source: HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn item(priority: i32, key: &str, source: &str) -> ProactiveItem {
        ProactiveItem {
            priority,
            dedup_key: key.into(),
            channel: "telegram".into(),
            source: source.into(),
            body: format!("body of {key}"),
            scheduled_for_unix: 0,
            is_failure: false,
            expires_unix: 0,
        }
    }

    #[test]
    fn expired_item_is_dropped_without_firing() {
        let mut q = ProactiveQueue::new();
        // expires at t=100; draining at t=200 must drop it, not fire it.
        q.enqueue(ProactiveItem {
            expires_unix: 100,
            ..item(50, "stale-news", "hn_tech_currency")
        });
        q.enqueue(item(50, "evergreen", "x")); // expires_unix 0 = never
        let drained = q.drain(200, 10);
        assert_eq!(drained.len(), 1, "only the evergreen item should fire");
        assert_eq!(drained[0].dedup_key, "evergreen");
        assert_eq!(q.len(), 0, "expired item must be pruned from the queue too");
    }

    #[test]
    fn not_yet_expired_item_still_fires() {
        let mut q = ProactiveQueue::new();
        q.enqueue(ProactiveItem {
            expires_unix: 1000,
            ..item(50, "fresh", "x")
        });
        let drained = q.drain(500, 10);
        assert_eq!(drained.len(), 1, "item expiring later must still fire now");
    }

    #[test]
    fn urgent_item_early_surfaces_past_its_schedule() {
        let mut q = ProactiveQueue::new();
        // Scheduled far in the future, but URGENT_PRIORITY → drains now.
        q.enqueue(ProactiveItem {
            priority: URGENT_PRIORITY,
            scheduled_for_unix: 9_999,
            ..item(URGENT_PRIORITY, "urgent-signal", "x")
        });
        // A non-urgent future item must NOT early-surface.
        q.enqueue(ProactiveItem {
            scheduled_for_unix: 9_999,
            ..item(50, "later", "x")
        });
        let drained = q.drain(0, 10);
        assert_eq!(drained.len(), 1, "only the urgent item bypasses its schedule");
        assert_eq!(drained[0].dedup_key, "urgent-signal");
    }

    #[test]
    fn new_queue_is_empty_with_default_budget() {
        let q = ProactiveQueue::new();
        assert!(q.is_empty());
        assert_eq!(q.budget_left(0), 3, "default max_per_day = 3");
    }

    #[test]
    fn enqueue_dedups_on_key() {
        let mut q = ProactiveQueue::new();
        assert!(q.enqueue(item(50, "k1", "a")));
        assert!(!q.enqueue(item(99, "k1", "b")), "duplicate key must reject");
        assert_eq!(q.len(), 1);
        // The PRIOR item wins per spec — body still reflects "a".
        assert_eq!(q.peek()[0].source, "a");
    }

    #[test]
    fn drain_pops_in_priority_desc_order_and_breaks_ties_by_schedule() {
        let mut q = ProactiveQueue::new();
        q.enqueue(item(10, "low", "x"));
        q.enqueue(item(50, "mid1", "x"));
        // Same priority as mid1 but scheduled earlier — wins the tie.
        q.enqueue(ProactiveItem {
            scheduled_for_unix: -1,
            ..item(50, "mid2-earlier", "x")
        });
        q.enqueue(item(100, "urgent", "x"));

        let drained = q.drain(0, 10);
        assert_eq!(drained.len(), 3, "default max_per_day = 3");
        // Priority-desc.
        assert_eq!(drained[0].dedup_key, "urgent");
        // Tie at 50 — earlier-scheduled one wins.
        assert_eq!(drained[1].dedup_key, "mid2-earlier");
        assert_eq!(drained[2].dedup_key, "mid1");
        // `low` stays queued because the daily cap was hit.
        assert_eq!(q.len(), 1);
        assert_eq!(q.peek()[0].dedup_key, "low");
    }

    #[test]
    fn drain_respects_daily_cap_across_multiple_calls_in_same_window() {
        let mut q = ProactiveQueue::new();
        for i in 0..10 {
            q.enqueue(item(10, &format!("k{i}"), "x"));
        }
        // First drain pulls 3.
        let first = q.drain(100, 10);
        assert_eq!(first.len(), 3);
        // Second drain 30 seconds later → no budget left.
        let second = q.drain(130, 10);
        assert!(second.is_empty(), "daily cap exhausted within 24h");
        // 25 hours later → budget reset.
        let later = q.drain(100 + 86_400 + 3_600, 10);
        assert_eq!(later.len(), 3, "budget reset after 24h rolls past");
    }

    #[test]
    fn drain_skips_items_scheduled_for_future() {
        let mut q = ProactiveQueue::new();
        q.enqueue(ProactiveItem {
            scheduled_for_unix: 1000,
            ..item(99, "future", "x")
        });
        q.enqueue(item(10, "now", "x"));
        let drained = q.drain(500, 10);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].dedup_key, "now");
        // Future item still queued.
        assert_eq!(q.len(), 1);
        // Once the clock catches up, the future item drains.
        let later = q.drain(2000, 10);
        assert_eq!(later.len(), 1);
        assert_eq!(later[0].dedup_key, "future");
    }

    #[test]
    fn budget_left_reads_without_mutating_history() {
        let mut q = ProactiveQueue::new();
        assert_eq!(q.budget_left(100), 3);
        q.drained_at.push(50);
        assert_eq!(q.budget_left(100), 2);
        // Same call again — read-only.
        assert_eq!(q.budget_left(100), 2);
    }

    #[test]
    fn remove_by_key_returns_count_removed() {
        let mut q = ProactiveQueue::new();
        q.enqueue(item(10, "stale", "x"));
        q.enqueue(item(10, "fresh", "x"));
        assert_eq!(q.remove_by_key("stale"), 1);
        assert_eq!(q.len(), 1);
        assert_eq!(q.remove_by_key("missing"), 0);
    }

    #[test]
    fn save_then_load_round_trips_queue_plus_drain_history() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("proactive.json");
        let mut q = ProactiveQueue::new();
        q.enqueue(item(50, "k1", "src1"));
        q.enqueue(item(10, "k2", "src2"));
        let drained = q.drain(1000, 1);
        assert_eq!(drained.len(), 1);
        q.save_to(&path).unwrap();

        let loaded = ProactiveQueue::load_from(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.peek()[0].dedup_key, "k2");
        // Drain history preserved — same-window subsequent load
        // still respects the cap.
        assert_eq!(loaded.budget_left(1000), 2);
    }

    #[test]
    fn load_from_returns_default_for_missing_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("never-existed.json");
        let q = ProactiveQueue::load_from(&path).unwrap();
        assert!(q.is_empty());
        assert_eq!(q.budget_left(0), 3);
    }

    #[test]
    fn load_from_returns_default_for_zero_length_file() {
        // Atomic-rename race window. The daemon's startup path
        // shouldn't crash on a zero-length proactive.json.
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.json");
        std::fs::write(&path, b"").unwrap();
        let q = ProactiveQueue::load_from(&path).unwrap();
        assert!(q.is_empty());
    }

    #[test]
    fn stats_carries_per_source_breakdown_and_budget() {
        let mut q = ProactiveQueue::new();
        q.enqueue(item(10, "a", "g_01_mini"));
        q.enqueue(item(10, "b", "g_01_mini"));
        q.enqueue(item(10, "c", "pl_03"));
        q.drain(500, 1);
        let s = q.stats(500);
        assert_eq!(s.queued, 2);
        assert_eq!(s.drained_last_24h, 1);
        assert_eq!(s.budget_left, 2);
        assert_eq!(s.by_source.get("g_01_mini").copied().unwrap_or(0), 1);
        assert_eq!(s.by_source.get("pl_03").copied().unwrap_or(0), 1);
    }

    #[test]
    fn operator_can_widen_cap_via_with_config() {
        let mut q = ProactiveQueue::with_config(ProactiveConfig { max_per_day: 10 });
        for i in 0..7 {
            q.enqueue(item(10, &format!("k{i}"), "x"));
        }
        let drained = q.drain(1000, 99);
        assert_eq!(
            drained.len(),
            7,
            "with max_per_day=10 + cap=99, all 7 queued items drain",
        );
    }
}
