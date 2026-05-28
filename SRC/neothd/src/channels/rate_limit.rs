//! Per-channel + per-sender token bucket — Phase 33c BS-11.
//!
//! Prevents a runaway upstream (e.g. a Telegram client stuck in a retry
//! loop, or a misbehaving bot user) from filling the WAL faster than the
//! daemon can drain it. Each (channel, sender_id) pair gets its own
//! bucket; tokens refill linearly between checks.
//!
//! ## Defaults
//!
//! - 30 tokens per minute per sender (≈ 1 message every 2 seconds, with
//!   short bursts up to 30 msgs allowed)
//! - Bucket capacity = burst size = 30
//!
//! Operators can override in `freedom.yaml` once tuning is needed. The
//! daemon uses [`RateLimiter::with_defaults`] until then.
//!
//! ## Decision
//!
//! `try_consume` returns:
//!   - `Decision::Allowed` — proceed, one token consumed
//!   - `Decision::RateLimited { retry_after_ms }` — drop or queue
//!
//! The caller is expected to record the drop as a WAL audit event (we
//! don't write WAL from inside the rate limiter to keep it lock-free
//! pure-Rust).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// Default rate: 30 tokens per minute (= 0.5 tokens/sec).
pub const DEFAULT_TOKENS_PER_MINUTE: f64 = 30.0;
/// Default burst size = bucket capacity.
pub const DEFAULT_BURST: u32 = 30;

/// Outcome of a `try_consume` call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allowed,
    /// Retry in approximately this many ms. The caller can drop the
    /// message or queue it; the rate limiter doesn't care.
    RateLimited {
        retry_after_ms: u32,
    },
}

#[derive(Clone, Copy, Debug)]
struct Bucket {
    /// Current token count. Float because refill is linear in elapsed time.
    tokens: f64,
    /// Last time tokens were refilled.
    last_refill: Instant,
}

impl Bucket {
    fn new(initial: f64) -> Self {
        Self {
            tokens: initial,
            last_refill: Instant::now(),
        }
    }
}

/// Per-sender token bucket. Cheap to clone (an `Arc<Mutex<HashMap>>`
/// under the hood) so the daemon can hand it to every channel adapter
/// without re-syncing.
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, Bucket>>,
    tokens_per_sec: f64,
    capacity: f64,
}

impl RateLimiter {
    /// 30 tokens/min, burst 30.
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_TOKENS_PER_MINUTE, DEFAULT_BURST)
    }

    /// Custom rate. `tokens_per_minute` = sustained rate; `burst` = bucket
    /// capacity = max consecutive messages before throttling.
    pub fn new(tokens_per_minute: f64, burst: u32) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            tokens_per_sec: tokens_per_minute / 60.0,
            capacity: burst as f64,
        }
    }

    /// Try to consume one token for the `(channel, sender)` pair. Refills
    /// the bucket first based on elapsed time, then checks if ≥ 1 token
    /// is available. Lock-held duration is O(1) per call.
    pub fn try_consume(&self, channel: &str, sender: &str) -> Decision {
        self.try_consume_at(channel, sender, Instant::now())
    }

    /// Test seam: caller supplies the timestamp. Production callers use
    /// [`Self::try_consume`].
    ///
    /// F4-02 (A3 F-2 / A5 I-2 — Via-Negativa): this method is now a thin
    /// imperative SHELL around the stateless [`refill_and_consume`] operation.
    /// The shell does only what genuinely needs shared state — take the lock,
    /// fetch-or-create the per-key bucket, write the result back. All token
    /// math lives in the pure free function, exhaustively testable without a
    /// lock or a map.
    pub fn try_consume_at(&self, channel: &str, sender: &str, now: Instant) -> Decision {
        let key = format!("{channel}/{sender}");
        let mut guard = match self.buckets.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let bucket = guard
            .entry(key)
            .or_insert_with(|| Bucket::new(self.capacity));
        let (updated, decision) =
            refill_and_consume(*bucket, self.tokens_per_sec, self.capacity, now);
        *bucket = updated;
        decision
    }

    /// Drop everything we know about `(channel, sender)` — useful when the
    /// operator manually whitelists a sender or wants to reset the limiter
    /// state for tests.
    pub fn reset(&self, channel: &str, sender: &str) {
        let key = format!("{channel}/{sender}");
        let mut guard = match self.buckets.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.remove(&key);
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// Stateless token-bucket operation — the functional core of the limiter
/// (F4-02). Given a bucket's prior state, the limiter parameters, and the
/// current instant, returns the updated bucket plus the decision. No shared
/// state, no lock, no map: a pure transformation the [`RateLimiter`] shell
/// composes over its per-`(channel, sender)` storage.
///
/// Refill is linear in elapsed time and capped at `capacity`; a call consumes
/// one token when ≥ 1 is available, otherwise reports the wait to the next
/// whole token.
fn refill_and_consume(
    mut bucket: Bucket,
    tokens_per_sec: f64,
    capacity: f64,
    now: Instant,
) -> (Bucket, Decision) {
    let elapsed_secs = now
        .saturating_duration_since(bucket.last_refill)
        .as_secs_f64();
    bucket.tokens = (bucket.tokens + elapsed_secs * tokens_per_sec).min(capacity);
    bucket.last_refill = now;

    if bucket.tokens >= 1.0 {
        bucket.tokens -= 1.0;
        (bucket, Decision::Allowed)
    } else {
        // Time to one full token = (1 - tokens) / tokens_per_sec seconds.
        let needed = 1.0 - bucket.tokens;
        let secs = needed / tokens_per_sec.max(1e-9);
        let retry_after_ms = (secs * 1000.0).ceil() as u32;
        (bucket, Decision::RateLimited { retry_after_ms })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn fresh_sender_can_burst_up_to_capacity() {
        let rl = RateLimiter::new(60.0, 5);
        for _ in 0..5 {
            assert_eq!(rl.try_consume("tg", "alice"), Decision::Allowed);
        }
        assert!(matches!(
            rl.try_consume("tg", "alice"),
            Decision::RateLimited { .. }
        ));
    }

    #[test]
    fn refills_between_calls() {
        let rl = RateLimiter::new(60.0, 1); // 1 token/sec
        let t0 = Instant::now();
        assert_eq!(rl.try_consume_at("tg", "bob", t0), Decision::Allowed);
        assert!(matches!(
            rl.try_consume_at("tg", "bob", t0),
            Decision::RateLimited { .. }
        ));
        // 1 second later → token refilled.
        assert_eq!(
            rl.try_consume_at("tg", "bob", t0 + Duration::from_secs(1)),
            Decision::Allowed,
        );
    }

    #[test]
    fn senders_are_isolated() {
        let rl = RateLimiter::new(60.0, 1);
        let t = Instant::now();
        assert_eq!(rl.try_consume_at("tg", "alice", t), Decision::Allowed);
        // alice is throttled, bob has a full bucket.
        assert!(matches!(
            rl.try_consume_at("tg", "alice", t),
            Decision::RateLimited { .. }
        ));
        assert_eq!(rl.try_consume_at("tg", "bob", t), Decision::Allowed);
    }

    #[test]
    fn channels_are_isolated() {
        let rl = RateLimiter::new(60.0, 1);
        let t = Instant::now();
        assert_eq!(rl.try_consume_at("tg", "alice", t), Decision::Allowed);
        // Same sender, different channel → different bucket.
        assert_eq!(rl.try_consume_at("keet", "alice", t), Decision::Allowed);
    }

    #[test]
    fn rate_limited_includes_retry_after() {
        let rl = RateLimiter::new(60.0, 1); // 1 token/sec
        let t = Instant::now();
        rl.try_consume_at("tg", "alice", t);
        match rl.try_consume_at("tg", "alice", t) {
            Decision::RateLimited { retry_after_ms } => {
                // Need ~1 full token at 1/sec → retry ~1000ms.
                assert!(
                    (900..=1100).contains(&retry_after_ms),
                    "retry_after_ms = {retry_after_ms}, expected ~1000",
                );
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn refill_caps_at_capacity() {
        let rl = RateLimiter::new(60.0, 3); // 1 token/sec, capacity 3
        let t0 = Instant::now();
        // Drain to 0.
        for _ in 0..3 {
            assert_eq!(rl.try_consume_at("tg", "alice", t0), Decision::Allowed);
        }
        // 100 seconds later — bucket capped at 3, not 100.
        let t1 = t0 + Duration::from_secs(100);
        for _ in 0..3 {
            assert_eq!(rl.try_consume_at("tg", "alice", t1), Decision::Allowed);
        }
        assert!(matches!(
            rl.try_consume_at("tg", "alice", t1),
            Decision::RateLimited { .. }
        ));
    }

    #[test]
    fn reset_clears_sender_state() {
        let rl = RateLimiter::new(60.0, 1);
        let t = Instant::now();
        rl.try_consume_at("tg", "alice", t);
        // Throttled.
        assert!(matches!(
            rl.try_consume_at("tg", "alice", t),
            Decision::RateLimited { .. }
        ));
        rl.reset("tg", "alice");
        // Fresh bucket — first call passes.
        assert_eq!(rl.try_consume_at("tg", "alice", t), Decision::Allowed);
    }

    // ── F4-02: pure operation tested in isolation (no lock, no map) ─────────
    #[test]
    fn refill_and_consume_allows_when_tokens_available() {
        let t = Instant::now();
        let (next, decision) = refill_and_consume(Bucket::new(2.0), 1.0, 5.0, t);
        assert_eq!(decision, Decision::Allowed);
        assert!((next.tokens - 1.0).abs() < 1e-9, "one token consumed");
    }

    #[test]
    fn refill_and_consume_throttles_when_empty_and_reports_retry() {
        let t = Instant::now();
        // Empty bucket, 1 token/sec → next token in ~1000 ms.
        let (next, decision) = refill_and_consume(Bucket { tokens: 0.0, last_refill: t }, 1.0, 5.0, t);
        match decision {
            Decision::RateLimited { retry_after_ms } => {
                assert!((900..=1100).contains(&retry_after_ms), "got {retry_after_ms}");
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
        assert_eq!(next.tokens, 0.0, "no token consumed when throttled");
    }

    #[test]
    fn refill_and_consume_caps_refill_at_capacity() {
        let t0 = Instant::now();
        // Start empty, wait 100s at 1 tok/sec, capacity 3 → refill capped at 3,
        // then one consumed → 2 remain.
        let (next, decision) = refill_and_consume(
            Bucket { tokens: 0.0, last_refill: t0 },
            1.0,
            3.0,
            t0 + Duration::from_secs(100),
        );
        assert_eq!(decision, Decision::Allowed);
        assert!((next.tokens - 2.0).abs() < 1e-9, "refill capped at capacity: {}", next.tokens);
    }

    #[test]
    fn defaults_match_spec() {
        let rl = RateLimiter::with_defaults();
        // 30 burst, then throttled. Drain 30 then check.
        let t = Instant::now();
        for _ in 0..30 {
            assert_eq!(rl.try_consume_at("tg", "alice", t), Decision::Allowed);
        }
        assert!(matches!(
            rl.try_consume_at("tg", "alice", t),
            Decision::RateLimited { .. }
        ));
    }
}
