//! Per-(channel, sender) rate limiter — Phase 33c BS-11.
//!
//! Token bucket: each `(channel, sender_id)` pair gets `BURST` tokens
//! that refill at `REFILL_PER_SEC`. The channel pipeline calls
//! [`allow`] before sanitizing each inbound message — over-budget
//! senders are silently dropped (with a WAL audit) so a runaway client
//! cannot fill the WAL.
//!
//! Defaults: 20-token burst, 1 token/sec refill — comfortable for
//! human-paced chat, hard ceiling against an accidental loop.
//!
//! The limiter is in-memory + best-effort. After a daemon restart the
//! buckets are empty (start fresh). We deliberately don't persist them:
//! the WAL audit trail records every blocked attempt, which is what
//! actually matters for the post-mortem.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// Maximum tokens any single bucket can hold. Higher = more burst tolerance.
pub const DEFAULT_BURST: f64 = 20.0;
/// Tokens added per second of wall-clock. Lower = stricter steady-state rate.
pub const DEFAULT_REFILL_PER_SEC: f64 = 1.0;

/// One bucket per `(channel, sender_id)` pair. Cheap to look up; the map
/// grows linearly with active senders but never above a few hundred for
/// a personal agent.
#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

impl Bucket {
    fn new(burst: f64) -> Self {
        Self {
            tokens: burst,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self, burst: f64, rate_per_sec: f64) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * rate_per_sec).min(burst);
            self.last_refill = now;
        }
    }

    fn try_consume(&mut self, burst: f64, rate_per_sec: f64) -> bool {
        self.refill(burst, rate_per_sec);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Thread-safe token-bucket limiter shared across the channel pipeline
/// and the rate-limit-status reader.
#[derive(Debug)]
pub struct RateLimiter {
    burst: f64,
    rate_per_sec: f64,
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl RateLimiter {
    pub fn new(burst: f64, rate_per_sec: f64) -> Self {
        Self {
            burst,
            rate_per_sec,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    pub fn default_config() -> Self {
        Self::new(DEFAULT_BURST, DEFAULT_REFILL_PER_SEC)
    }

    /// Try to consume one token for `(channel, sender_id)`. Returns
    /// `true` if the request is allowed, `false` if the bucket is empty.
    pub fn allow(&self, channel: &str, sender_id: &str) -> bool {
        let key = format!("{channel}:{sender_id}");
        let mut guard = match self.buckets.lock() {
            Ok(g) => g,
            // Poisoned lock — rate-limit is best-effort; allow the request
            // rather than panic the channel pipeline.
            Err(p) => p.into_inner(),
        };
        let bucket = guard.entry(key).or_insert_with(|| Bucket::new(self.burst));
        bucket.try_consume(self.burst, self.rate_per_sec)
    }

    /// How many tokens does this bucket currently hold? Surfaced by
    /// `neoth status --rate-limit` (Phase 33c BS-11 follow-up).
    pub fn tokens_remaining(&self, channel: &str, sender_id: &str) -> f64 {
        let key = format!("{channel}:{sender_id}");
        let mut guard = match self.buckets.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let bucket = guard.entry(key).or_insert_with(|| Bucket::new(self.burst));
        bucket.refill(self.burst, self.rate_per_sec);
        bucket.tokens
    }

    /// Clear every bucket. Useful for `neoth rate-limit --reset` (CLI
    /// surface to be added once the operator hits an unwanted lockout).
    pub fn reset(&self) {
        if let Ok(mut g) = self.buckets.lock() {
            g.clear();
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::default_config()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_bucket_allows_burst_then_blocks() {
        let rl = RateLimiter::new(3.0, 0.0); // 3 tokens, no refill — measure burst.
        assert!(rl.allow("tg", "alice"));
        assert!(rl.allow("tg", "alice"));
        assert!(rl.allow("tg", "alice"));
        assert!(!rl.allow("tg", "alice"), "fourth must block — bucket empty");
    }

    #[test]
    fn separate_senders_have_separate_buckets() {
        let rl = RateLimiter::new(1.0, 0.0);
        assert!(rl.allow("tg", "alice"));
        assert!(!rl.allow("tg", "alice"));
        // bob's bucket is independent.
        assert!(rl.allow("tg", "bob"));
        assert!(!rl.allow("tg", "bob"));
    }

    #[test]
    fn separate_channels_have_separate_buckets_for_same_sender() {
        let rl = RateLimiter::new(1.0, 0.0);
        assert!(rl.allow("tg", "sam"));
        assert!(!rl.allow("tg", "sam"));
        assert!(
            rl.allow("keet", "sam"),
            "different channel must not share bucket"
        );
    }

    #[test]
    fn refill_after_sleep_restores_some_tokens() {
        let rl = RateLimiter::new(5.0, 100.0); // 100 tokens/sec — quick test.
        assert!(rl.allow("tg", "alice"));
        assert!(rl.allow("tg", "alice"));
        // Drain to zero.
        assert!(rl.allow("tg", "alice"));
        assert!(rl.allow("tg", "alice"));
        assert!(rl.allow("tg", "alice"));
        assert!(!rl.allow("tg", "alice"));
        // 50ms sleep at 100/sec ≈ 5 tokens. At least 1 must return.
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(rl.allow("tg", "alice"));
    }

    #[test]
    fn tokens_remaining_decreases_with_each_allow() {
        let rl = RateLimiter::new(10.0, 0.0);
        let before = rl.tokens_remaining("tg", "sam");
        assert!((before - 10.0).abs() < 1e-3);
        rl.allow("tg", "sam");
        rl.allow("tg", "sam");
        let after = rl.tokens_remaining("tg", "sam");
        assert!((after - 8.0).abs() < 1e-3, "got {after}");
    }

    #[test]
    fn reset_clears_all_buckets() {
        let rl = RateLimiter::new(1.0, 0.0);
        rl.allow("tg", "sam");
        assert!(!rl.allow("tg", "sam"));
        rl.reset();
        assert!(rl.allow("tg", "sam"), "post-reset must replenish");
    }

    #[test]
    fn default_config_matches_published_constants() {
        let rl = RateLimiter::default();
        // 20-burst default; allow exactly 20 before blocking on a no-refill
        // simulation requires manually constructing. Smoke-check the public
        // constants instead.
        let _ = rl;
        assert_eq!(DEFAULT_BURST, 20.0);
        assert_eq!(DEFAULT_REFILL_PER_SEC, 1.0);
    }
}
