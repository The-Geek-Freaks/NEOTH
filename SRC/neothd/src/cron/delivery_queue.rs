//! JV-PRO-10 — Delivery-queue TTL + signal-based early-surface.
//!
//! Pure functions on a `Vec<QueuedDelivery>`. No I/O. No async.
//!
//! ## Purpose
//!
//! Cron jobs that produce proactive briefings should not deliver stale content.
//! A morning news briefing queued at 07:00 but still undelivered at 19:00 is
//! worse than no briefing at all. `expire_stale` drops items whose TTL has
//! elapsed. Conversely, `drain_for_signal` lets an operator-activity event
//! (e.g. "operator opened CLI", "operator sent a message") surface queued items
//! immediately rather than waiting for the next scheduled drain tick.
//!
//! ## Wiring note
//!
//! // neoth — The existing proactive delivery path lives in
//! // `daemon/proactive_dispatcher.rs` which drains `proactive::ProactiveQueue`
//! // (a bounded JSON-persisted queue). JV-PRO-10 wiring into that path should:
//! //
//! //   1. Add a `ttl_secs: u64` field to `proactive::ProactiveItem` (or store
//! //      it separately in `ProactiveQueue`).
//! //   2. In `run_proactive_drain_tick`, call `expire_stale` on the in-memory
//! //      item list before the priority-sort + drain-cap step.
//! //   3. In `daemon/serve_tasks.rs` (or wherever an operator-activity event
//! //      fires), call `drain_for_signal(queue, signal)` and pass the result to
//! //      the existing sidecar-append path.
//! //
//! // This module ships the pure primitives; the wiring is deferred to avoid
//! // touching the hot-lane `serve_tasks.rs` / `daemon/mod.rs` without a
//! // coordinated window.
//!
//! ## Signal matching
//!
//! `drain_for_signal` matches items where `signal` is a substring of the item's
//! `signal_filter` field. An empty `signal_filter` on an item means "no early
//! surface" — the item stays in the queue until the scheduled drain or TTL.

/// One item in the delivery queue with an associated TTL.
///
/// `payload` is opaque to this module — it is whatever the producer (cron
/// runner, G-02 surfacing tick, etc.) stores. In practice it will be the
/// JSON-serialised body of a `ProactiveItem`, but this struct deliberately
/// does not depend on that type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedDelivery {
    /// Unique ID for audit / dedup. Matches the `dedup_key` convention from
    /// `proactive::ProactiveItem`.
    pub id: String,
    /// Unix seconds when the item was enqueued.
    pub created_unix: i64,
    /// Opaque delivery payload (e.g. JSON of `ProactiveItem`).
    pub payload: String,
    /// How many seconds after `created_unix` the item is considered stale.
    /// `0` means "never expires" — the item will not be removed by `expire_stale`.
    pub ttl_secs: i64,
    /// Optional signal name that triggers early delivery. Empty string means
    /// "no early-surface": the item waits for the scheduled drain or TTL.
    ///
    /// Convention: use the same names as operator-activity events, e.g.
    /// `"cli_open"`, `"operator_message"`, `"daily_summary"`.
    pub signal_filter: String,
}

impl QueuedDelivery {
    /// True when the item has passed its TTL.
    ///
    /// Items with `ttl_secs == 0` never expire.
    pub fn is_expired(&self, now_unix: i64) -> bool {
        self.ttl_secs > 0 && (now_unix - self.created_unix) >= self.ttl_secs
    }

    /// True when `signal` (case-insensitive substring match) fires this item's
    /// early-surface filter. Items with an empty `signal_filter` never match.
    pub fn matches_signal(&self, signal: &str) -> bool {
        if self.signal_filter.is_empty() || signal.is_empty() {
            return false;
        }
        let lower_filter = self.signal_filter.to_ascii_lowercase();
        let lower_signal = signal.to_ascii_lowercase();
        lower_filter.contains(lower_signal.as_str())
            || lower_signal.contains(lower_filter.as_str())
    }
}

// ── TTL expiry ────────────────────────────────────────────────────────────────

/// Remove items from `queue` that have passed their TTL.
///
/// Returns the removed (stale) items so the caller can log or audit them.
/// The surviving items remain in `queue` in their original order.
///
/// Items with `ttl_secs == 0` are never removed by this function.
pub fn expire_stale(queue: &mut Vec<QueuedDelivery>, now_unix: i64) -> Vec<QueuedDelivery> {
    let mut stale = Vec::new();
    let mut i = 0;
    while i < queue.len() {
        if queue[i].is_expired(now_unix) {
            stale.push(queue.remove(i));
            // do not advance i: the element at position i is now the next item
        } else {
            i += 1;
        }
    }
    stale
}

// ── Signal-based early-surface ────────────────────────────────────────────────

/// Drain items from `queue` whose `signal_filter` matches `signal`.
///
/// Returns the matching items (removed from `queue`). Items that do not match
/// stay in place. The caller is responsible for delivering the returned items
/// (appending to the sidecar, sending to the channel, etc.).
///
/// Matching is case-insensitive substring: an item with `signal_filter =
/// "cli"` matches signals `"cli_open"`, `"CLI_SESSION"`, etc.
pub fn drain_for_signal(queue: &mut Vec<QueuedDelivery>, signal: &str) -> Vec<QueuedDelivery> {
    if signal.is_empty() {
        return Vec::new();
    }
    let mut matched = Vec::new();
    let mut i = 0;
    while i < queue.len() {
        if queue[i].matches_signal(signal) {
            matched.push(queue.remove(i));
        } else {
            i += 1;
        }
    }
    matched
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: &str, created: i64, ttl: i64, signal: &str) -> QueuedDelivery {
        QueuedDelivery {
            id: id.to_string(),
            created_unix: created,
            payload: format!("{{\"id\":\"{id}\"}}"),
            ttl_secs: ttl,
            signal_filter: signal.to_string(),
        }
    }

    // ── expire_stale ──────────────────────────────────────────────────────────

    #[test]
    fn expire_stale_drops_past_ttl_item() {
        let mut queue = vec![
            item("old", 1_000, 3600, ""),   // created 1h ago, ttl=3600 → expired
            item("fresh", 4_000, 3600, ""), // created near now, ttl=3600 → fresh
        ];
        let now = 4_601_i64; // "old" is 3601s old → expired; "fresh" is 601s old → ok

        let stale = expire_stale(&mut queue, now);

        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].id, "old");
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].id, "fresh");
    }

    #[test]
    fn expire_stale_keeps_fresh_items() {
        let mut queue = vec![item("a", 1_000, 7200, ""), item("b", 2_000, 7200, "")];
        let now = 3_000_i64; // both ≤ 1000s old — well within ttl

        let stale = expire_stale(&mut queue, now);

        assert!(stale.is_empty(), "no items should expire yet");
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn expire_stale_never_removes_zero_ttl() {
        let mut queue = vec![item("permanent", 0, 0, "")]; // ttl=0 → never expires
        let now = i64::MAX;
        let stale = expire_stale(&mut queue, now);
        assert!(stale.is_empty(), "ttl=0 item must never expire");
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn expire_stale_removes_multiple_stale_items() {
        let now = 10_000_i64;
        let mut queue = vec![
            item("s1", 0, 100, ""),    // 10000s old, ttl=100 → stale
            item("ok", 9_950, 100, ""), // 50s old, ttl=100 → fresh
            item("s2", 500, 200, ""),  // 9500s old, ttl=200 → stale
        ];
        let stale = expire_stale(&mut queue, now);
        assert_eq!(stale.len(), 2);
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].id, "ok");
    }

    // ── drain_for_signal ──────────────────────────────────────────────────────

    #[test]
    fn drain_for_signal_returns_matching_items() {
        let mut queue = vec![
            item("a", 0, 0, "cli_open"),
            item("b", 0, 0, "daily_summary"),
            item("c", 0, 0, "cli_session"),
        ];
        let drained = drain_for_signal(&mut queue, "cli");
        // "cli_open" and "cli_session" both contain "cli"
        assert_eq!(drained.len(), 2);
        assert!(drained.iter().any(|i| i.id == "a"));
        assert!(drained.iter().any(|i| i.id == "c"));
        // "daily_summary" remains
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].id, "b");
    }

    #[test]
    fn drain_for_signal_leaves_unmatched_items() {
        let mut queue = vec![
            item("x", 0, 0, "telegram"),
            item("y", 0, 0, ""),         // no signal_filter → never early-surfaced
        ];
        let drained = drain_for_signal(&mut queue, "cli");
        assert!(drained.is_empty(), "neither item matches 'cli'");
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn drain_for_signal_empty_signal_returns_nothing() {
        let mut queue = vec![item("z", 0, 0, "cli")];
        let drained = drain_for_signal(&mut queue, "");
        assert!(drained.is_empty(), "empty signal must not drain anything");
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn drain_for_signal_is_case_insensitive() {
        let mut queue = vec![item("u", 0, 0, "CLI_OPEN")];
        let drained = drain_for_signal(&mut queue, "cli");
        assert_eq!(drained.len(), 1, "matching should be case-insensitive");
    }

    #[test]
    fn drain_for_signal_empty_queue_returns_nothing() {
        let mut queue: Vec<QueuedDelivery> = Vec::new();
        let drained = drain_for_signal(&mut queue, "cli");
        assert!(drained.is_empty());
    }

    // ── is_expired / matches_signal unit checks ───────────────────────────────

    #[test]
    fn is_expired_exact_boundary() {
        // At exactly ttl_secs elapsed → expired.
        let it = item("e", 0, 100, "");
        assert!(it.is_expired(100));
        assert!(!it.is_expired(99));
    }

    #[test]
    fn matches_signal_empty_filter_is_false() {
        let it = item("f", 0, 0, "");
        assert!(!it.matches_signal("anything"));
    }

    #[test]
    fn matches_signal_bidirectional() {
        // item's filter is a prefix of the signal
        let it = item("g", 0, 0, "cli");
        assert!(it.matches_signal("cli_open"));
        // signal is a prefix of the item's filter
        let it2 = item("h", 0, 0, "cli_open");
        assert!(it2.matches_signal("cli"));
    }
}
