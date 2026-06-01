//! SL-00(1c) — process-wide local-load gauge.
//!
//! The cluster heartbeat must advertise THIS node's real load so peers can do
//! load-aware routing. Faking the numbers would be theater, so this module is
//! the single source of truth that the request path updates and the heartbeat
//! sender reads:
//!
//! - `inflight_requests` — a live count of provider requests in flight, kept by
//!   an `AtomicU32` that the chat path bumps via the RAII [`InflightGuard`]
//!   (increment on construct, decrement on drop — exception-safe).
//! - `tokens_per_sec` — an exponentially-weighted moving average of measured
//!   output throughput, fed by [`record_completion`] after each call. Starts at
//!   `0.0` (honestly "no measurement yet"), never NaN/Inf/negative.
//! - `healthy` — `true` while the daemon is up and serving. A future slice can
//!   downgrade this from provider circuit-breaker state; today it is the
//!   truthful "this node is alive" signal, not a fabricated metric.
//!
//! All state is a private `static` so any subsystem can read/update without
//! threading a handle through every call site. Reads are lock-free.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::heartbeat::{HeartbeatBody, hash_capabilities};

// Memory ordering: both gauges use `Relaxed`. They are STANDALONE counters with
// no happens-before relationship to any other memory — updated from the request
// path (`cli/chat.rs`, an arbitrary tokio task) and read by the heartbeat sender
// (another task). A reader tolerates bounded staleness (a heartbeat carrying the
// previous tick's value is fine), so no acquire/release fence is needed.

/// Live count of in-flight provider requests. Bumped only through
/// [`InflightGuard`] so a panic/early-return can never leak a count.
static INFLIGHT: AtomicU32 = AtomicU32::new(0);

/// Current tokens/sec EWMA, stored as `f64` bits. `0.0` until the first
/// completion is recorded. Only ever written with a finite, non-negative value.
static TPS_EWMA_BITS: AtomicU64 = AtomicU64::new(0);

/// EWMA smoothing factor — weight given to the newest sample. 0.3 reacts within
/// a few requests without whipsawing on a single outlier.
const TPS_ALPHA: f64 = 0.3;

/// Sanity ceiling mirroring `heartbeat::validate_heartbeat` so a wild sample
/// (e.g. a divide-by-near-zero elapsed) can never poison the gauge or trip the
/// receiver's validation.
const TPS_SANITY_CAP: f64 = 1_000_000.0;

/// RAII in-flight marker. Construct one for the duration of a provider request;
/// dropping it (normal return, `?`, or panic unwind) decrements the count.
#[must_use = "hold the guard for the request's lifetime; dropping it early decrements the in-flight count"]
pub struct InflightGuard {
    _private: (),
}

impl InflightGuard {
    fn new() -> Self {
        INFLIGHT.fetch_add(1, Ordering::Relaxed);
        Self { _private: () }
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        // Saturating-style guard: never wrap below zero even if a guard is
        // somehow dropped twice (it can't be — no Clone — but be defensive).
        let prev = INFLIGHT.load(Ordering::Relaxed);
        if prev > 0 {
            INFLIGHT.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Mark a provider request as in flight for the lifetime of the returned guard.
pub fn inflight_guard() -> InflightGuard {
    InflightGuard::new()
}

/// Current in-flight request count (lock-free read).
pub fn inflight() -> u32 {
    INFLIGHT.load(Ordering::Relaxed)
}

/// Feed the throughput gauge a completed call: `output_tokens` produced over
/// `elapsed`. Updates the tokens/sec EWMA. Ignores degenerate samples
/// (zero/!finite elapsed, zero tokens) so the gauge stays honest.
pub fn record_completion(output_tokens: u32, elapsed: std::time::Duration) {
    let secs = elapsed.as_secs_f64();
    if output_tokens == 0 || !secs.is_finite() || secs <= 0.0 {
        return;
    }
    let sample = (output_tokens as f64 / secs).clamp(0.0, TPS_SANITY_CAP);
    let prev = tokens_per_sec();
    // First real sample seeds the average directly instead of decaying from 0.
    let next = if prev <= 0.0 {
        sample
    } else {
        TPS_ALPHA * sample + (1.0 - TPS_ALPHA) * prev
    };
    let clamped = if next.is_finite() {
        next.clamp(0.0, TPS_SANITY_CAP)
    } else {
        prev
    };
    TPS_EWMA_BITS.store(clamped.to_bits(), Ordering::Relaxed);
}

/// Current tokens/sec EWMA (lock-free read). Always finite, `>= 0.0`.
pub fn tokens_per_sec() -> f64 {
    let v = f64::from_bits(TPS_EWMA_BITS.load(Ordering::Relaxed));
    if v.is_finite() && v >= 0.0 { v } else { 0.0 }
}

/// Build the [`HeartbeatBody`] this node broadcasts: a real snapshot of local
/// load. `capabilities` is hashed into `capabilities_hash` so peers can detect
/// a change without the full list every tick.
pub fn local_load_snapshot(capabilities: &[String]) -> HeartbeatBody {
    HeartbeatBody {
        tokens_per_sec: tokens_per_sec(),
        inflight_requests: inflight(),
        // True while the daemon is up and answering. Honest current state;
        // provider-breaker-aware downgrade is a tracked follow-up.
        healthy: true,
        capabilities_hash: hash_capabilities(capabilities),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // NOTE: these tests touch process-global statics. They are written to be
    // order-independent (each asserts a relative change, not an absolute), and
    // the inflight guard is balanced within each test.

    #[test]
    fn inflight_guard_increments_and_decrements() {
        let base = inflight();
        {
            let _g = inflight_guard();
            assert_eq!(inflight(), base + 1, "guard increments");
            {
                let _g2 = inflight_guard();
                assert_eq!(inflight(), base + 2, "nested guard increments again");
            }
            assert_eq!(inflight(), base + 1, "inner guard drop decrements");
        }
        assert_eq!(inflight(), base, "outer guard drop returns to base");
    }

    #[test]
    fn record_completion_ignores_degenerate_samples() {
        let before = tokens_per_sec();
        record_completion(0, Duration::from_secs(1)); // zero tokens
        record_completion(100, Duration::from_secs(0)); // zero elapsed
        assert_eq!(
            tokens_per_sec(),
            before,
            "degenerate samples must not move the gauge"
        );
    }

    #[test]
    fn record_completion_produces_finite_nonnegative_tps() {
        // 50 tokens in 1s ⇒ ~50 tps (after EWMA blending with prior state).
        record_completion(50, Duration::from_secs(1));
        let tps = tokens_per_sec();
        assert!(tps.is_finite() && tps >= 0.0, "tps stays valid: {tps}");
        assert!(tps <= TPS_SANITY_CAP, "tps respects the sanity cap");
    }

    #[test]
    fn snapshot_is_valid_for_the_wire() {
        let body = local_load_snapshot(&["claude_cli".to_string()]);
        assert!(body.healthy);
        // The snapshot must always pass the receiver's validation.
        super::super::heartbeat::validate_heartbeat(&body)
            .expect("local snapshot must be a valid heartbeat body");
        assert_eq!(
            body.capabilities_hash,
            hash_capabilities(&["claude_cli".to_string()])
        );
    }

    #[test]
    fn absurd_throughput_is_capped_not_propagated() {
        // A pathological sample (1e9 tokens in 1ns) must clamp, not poison.
        record_completion(1_000_000_000, Duration::from_nanos(1));
        let tps = tokens_per_sec();
        assert!(tps <= TPS_SANITY_CAP, "must clamp to the sanity cap: {tps}");
        assert!(tps.is_finite());
    }
}
