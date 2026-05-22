//! Provider circuit-breaker primitive — QM-10 Phase 1 (the failover
//! wiring across every provider is Phase 2; this module ships the
//! state machine + registry that the wire-in step consumes).
//!
//! State machine:
//!
//!   Closed ──(consecutive failures ≥ threshold)──→ Open
//!   Open ──(reset_after elapsed)──→ HalfOpen
//!   HalfOpen ──(probe success)──→ Closed
//!   HalfOpen ──(probe failure)──→ Open
//!
//! Each call to `try_acquire()` returns either a `Permit` (the caller
//! MUST report the outcome via `record_success` / `record_failure`)
//! or `BreakerError::Open { retry_after }` when the breaker won't
//! admit traffic. The `HalfOpen` state allows ONE in-flight probe at
//! a time — concurrent callers get rejected as `Open` until the
//! probe settles.
//!
//! Thread-safe via `std::sync::Mutex` — every method is short-lived
//! so there's no risk of holding the lock across awaits.
//!
//! Configurable knobs (`BreakerConfig`):
//! - `failure_threshold`: consecutive failures that flip Closed → Open
//!   (default 5)
//! - `reset_after`: Open → HalfOpen cooldown (default 30s)
//! - `success_threshold`: consecutive successes in HalfOpen needed to
//!   close the breaker (default 1 — single probe is enough)
//!
//! Pure in-memory; surviving process restarts is intentionally out of
//! scope (a restarted daemon should retry every provider afresh).

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Operator-tweakable knobs. Defaults match the QM-10 spec
/// (5 failures / 30s cooldown / single probe).
#[derive(Clone, Copy, Debug)]
pub struct BreakerConfig {
    pub failure_threshold: u32,
    pub reset_after: Duration,
    pub success_threshold: u32,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            reset_after: Duration::from_secs(30),
            success_threshold: 1,
        }
    }
}

/// Breaker state machine — public so doctor/metrics callers can render
/// the current state without going through `try_acquire`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakerState {
    Closed,
    Open,
    HalfOpen,
}

impl BreakerState {
    pub fn as_str(&self) -> &'static str {
        match self {
            BreakerState::Closed => "closed",
            BreakerState::Open => "open",
            BreakerState::HalfOpen => "half_open",
        }
    }
}

/// Why `try_acquire` rejected.
#[derive(Debug)]
pub enum BreakerError {
    /// Breaker is Open and the cooldown hasn't elapsed.
    Open { retry_after: Duration },
    /// HalfOpen is already probing — only one in-flight probe allowed.
    HalfOpenBusy,
}

impl std::fmt::Display for BreakerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BreakerError::Open { retry_after } => write!(
                f,
                "circuit breaker open; retry after {:.1}s",
                retry_after.as_secs_f64()
            ),
            BreakerError::HalfOpenBusy => write!(f, "circuit breaker probing — try later"),
        }
    }
}

impl std::error::Error for BreakerError {}

/// Internal state — only constructed inside `CircuitBreaker`.
#[derive(Debug)]
struct Inner {
    state: BreakerState,
    consecutive_failures: u32,
    consecutive_successes: u32,
    opened_at: Option<Instant>,
    half_open_probe_inflight: bool,
}

impl Inner {
    fn fresh() -> Self {
        Self {
            state: BreakerState::Closed,
            consecutive_failures: 0,
            consecutive_successes: 0,
            opened_at: None,
            half_open_probe_inflight: false,
        }
    }
}

/// Per-provider breaker. Operators usually access these via
/// `BreakerRegistry::breaker_for(provider_id)`; constructing one
/// directly is fine for tests or one-off probes.
#[derive(Debug)]
pub struct CircuitBreaker {
    config: BreakerConfig,
    inner: Mutex<Inner>,
}

impl CircuitBreaker {
    pub fn new(config: BreakerConfig) -> Self {
        Self {
            config,
            inner: Mutex::new(Inner::fresh()),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(BreakerConfig::default())
    }

    pub fn config(&self) -> BreakerConfig {
        self.config
    }

    /// Current state. Reading it does NOT advance the state machine
    /// (cooldown transitions only happen on `try_acquire`).
    pub fn state(&self) -> BreakerState {
        self.lock().state
    }

    /// Snapshot for metrics / doctor output. Cheap.
    pub fn snapshot(&self) -> BreakerSnapshot {
        let g = self.lock();
        BreakerSnapshot {
            state: g.state,
            consecutive_failures: g.consecutive_failures,
            consecutive_successes: g.consecutive_successes,
            seconds_in_open: g
                .opened_at
                .map(|t| Instant::now().saturating_duration_since(t).as_secs_f64()),
        }
    }

    /// Try to admit one call. Returns a `Permit` the caller MUST
    /// settle with `record_success` / `record_failure`. Dropping the
    /// permit without calling either is a programming bug; we err on
    /// the conservative side and treat it as a failure via the
    /// `Permit::Drop` impl below.
    pub fn try_acquire(&self) -> Result<Permit<'_>, BreakerError> {
        let mut g = self.lock();
        match g.state {
            BreakerState::Closed => Ok(Permit::new(self)),
            BreakerState::HalfOpen => {
                if g.half_open_probe_inflight {
                    Err(BreakerError::HalfOpenBusy)
                } else {
                    g.half_open_probe_inflight = true;
                    Ok(Permit::new(self))
                }
            }
            BreakerState::Open => {
                let opened_at = g
                    .opened_at
                    .expect("Open state must carry an opened_at timestamp");
                let elapsed = Instant::now().saturating_duration_since(opened_at);
                if elapsed >= self.config.reset_after {
                    g.state = BreakerState::HalfOpen;
                    g.half_open_probe_inflight = true;
                    Ok(Permit::new(self))
                } else {
                    Err(BreakerError::Open {
                        retry_after: self.config.reset_after - elapsed,
                    })
                }
            }
        }
    }

    fn record_success_inner(&self) {
        let mut g = self.lock();
        g.consecutive_failures = 0;
        match g.state {
            BreakerState::Closed => {}
            BreakerState::HalfOpen => {
                g.consecutive_successes = g.consecutive_successes.saturating_add(1);
                g.half_open_probe_inflight = false;
                if g.consecutive_successes >= self.config.success_threshold {
                    g.state = BreakerState::Closed;
                    g.opened_at = None;
                    g.consecutive_successes = 0;
                }
            }
            BreakerState::Open => {
                // Shouldn't happen — Permit can only be issued from Closed
                // or HalfOpen. Reset defensively rather than panic.
                g.state = BreakerState::Closed;
                g.opened_at = None;
            }
        }
    }

    fn record_failure_inner(&self) {
        let mut g = self.lock();
        g.consecutive_successes = 0;
        match g.state {
            BreakerState::Closed => {
                g.consecutive_failures = g.consecutive_failures.saturating_add(1);
                if g.consecutive_failures >= self.config.failure_threshold {
                    g.state = BreakerState::Open;
                    g.opened_at = Some(Instant::now());
                }
            }
            BreakerState::HalfOpen => {
                g.state = BreakerState::Open;
                g.opened_at = Some(Instant::now());
                g.half_open_probe_inflight = false;
                g.consecutive_failures = g.consecutive_failures.saturating_add(1);
            }
            BreakerState::Open => {
                // Defensive — same reasoning as the Open branch in
                // record_success_inner. A Permit shouldn't exist here.
            }
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // Poisoned mutex on panic recovery: take the inner state and
        // soldier on. A breaker holding a poisoned lock means the
        // last caller panicked between try_acquire and record_*; we
        // don't want to amplify that into permanent breaker death.
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// Snapshot fields for metrics / doctor.
#[derive(Clone, Copy, Debug)]
pub struct BreakerSnapshot {
    pub state: BreakerState,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub seconds_in_open: Option<f64>,
}

/// One-shot RAII permit. Caller settles by calling `record_success`
/// or `record_failure`. Dropping the permit without settling counts
/// as a failure (conservative — a forgotten settle usually means the
/// call path errored before reaching the success arm).
#[must_use = "must call record_success() or record_failure() on a Permit"]
#[derive(Debug)]
pub struct Permit<'a> {
    breaker: &'a CircuitBreaker,
    settled: bool,
}

impl<'a> Permit<'a> {
    fn new(breaker: &'a CircuitBreaker) -> Self {
        Self {
            breaker,
            settled: false,
        }
    }

    pub fn record_success(mut self) {
        self.breaker.record_success_inner();
        self.settled = true;
    }

    pub fn record_failure(mut self) {
        self.breaker.record_failure_inner();
        self.settled = true;
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        if !self.settled {
            // Forgotten settle → conservative failure. Logging from
            // a Drop impl is risky (no async, no tracing context);
            // the test suite catches the conservative-default by
            // pinning the "drop counts as failure" contract.
            self.breaker.record_failure_inner();
        }
    }
}

/// Multi-provider registry. Lookup by provider id returns a stable
/// breaker reference; the first lookup constructs the breaker with
/// the configured defaults.
#[derive(Debug, Default)]
pub struct BreakerRegistry {
    breakers: Mutex<HashMap<String, std::sync::Arc<CircuitBreaker>>>,
    config: BreakerConfig,
}

impl BreakerRegistry {
    pub fn new(config: BreakerConfig) -> Self {
        Self {
            breakers: Mutex::new(HashMap::new()),
            config,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(BreakerConfig::default())
    }

    /// Get-or-create the breaker for `provider_id`. Returns an Arc so
    /// the breaker outlives the registry guard.
    pub fn breaker_for(&self, provider_id: &str) -> std::sync::Arc<CircuitBreaker> {
        let mut g = self.breakers.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(b) = g.get(provider_id) {
            return b.clone();
        }
        let b = std::sync::Arc::new(CircuitBreaker::new(self.config));
        g.insert(provider_id.to_string(), b.clone());
        b
    }

    /// Snapshot every registered breaker. Used by `neoth doctor` +
    /// future `/metrics` exporter.
    pub fn snapshot_all(&self) -> Vec<(String, BreakerSnapshot)> {
        let g = self.breakers.lock().unwrap_or_else(|p| p.into_inner());
        let mut out: Vec<_> = g
            .iter()
            .map(|(k, v)| (k.clone(), v.snapshot()))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn breaker_starts_closed() {
        let b = CircuitBreaker::with_defaults();
        assert_eq!(b.state(), BreakerState::Closed);
    }

    #[test]
    fn closed_breaker_admits_calls_and_resets_failures_on_success() {
        let b = CircuitBreaker::with_defaults();
        for _ in 0..3 {
            let p = b.try_acquire().expect("closed should admit");
            p.record_success();
        }
        let snap = b.snapshot();
        assert_eq!(snap.state, BreakerState::Closed);
        assert_eq!(snap.consecutive_failures, 0);
    }

    #[test]
    fn five_consecutive_failures_flip_to_open() {
        let b = CircuitBreaker::with_defaults();
        for _ in 0..4 {
            let p = b.try_acquire().expect("still closed");
            p.record_failure();
            assert_eq!(b.state(), BreakerState::Closed);
        }
        let p = b.try_acquire().expect("5th call still admitted");
        p.record_failure();
        assert_eq!(b.state(), BreakerState::Open);
    }

    #[test]
    fn open_breaker_rejects_with_retry_after() {
        let b = CircuitBreaker::new(BreakerConfig {
            failure_threshold: 1,
            reset_after: Duration::from_secs(60),
            success_threshold: 1,
        });
        b.try_acquire().unwrap().record_failure();
        assert_eq!(b.state(), BreakerState::Open);
        match b.try_acquire() {
            Err(BreakerError::Open { retry_after }) => {
                assert!(retry_after.as_secs() > 50);
                assert!(retry_after.as_secs() <= 60);
            }
            other => panic!("expected Open error, got {other:?}"),
        }
    }

    #[test]
    fn open_to_half_open_after_cooldown_then_single_probe() {
        let b = CircuitBreaker::new(BreakerConfig {
            failure_threshold: 1,
            reset_after: Duration::from_millis(10),
            success_threshold: 1,
        });
        b.try_acquire().unwrap().record_failure();
        assert_eq!(b.state(), BreakerState::Open);
        std::thread::sleep(Duration::from_millis(20));
        // First post-cooldown acquire transitions to HalfOpen and issues
        // the probe permit.
        let p = b.try_acquire().expect("cooldown elapsed → half_open admit");
        assert_eq!(b.state(), BreakerState::HalfOpen);
        // Concurrent caller during in-flight probe is rejected.
        match b.try_acquire() {
            Err(BreakerError::HalfOpenBusy) => {}
            other => panic!("expected HalfOpenBusy, got {other:?}"),
        }
        p.record_success();
        assert_eq!(b.state(), BreakerState::Closed);
    }

    #[test]
    fn half_open_probe_failure_returns_to_open() {
        let b = CircuitBreaker::new(BreakerConfig {
            failure_threshold: 1,
            reset_after: Duration::from_millis(5),
            success_threshold: 1,
        });
        b.try_acquire().unwrap().record_failure();
        std::thread::sleep(Duration::from_millis(15));
        let p = b.try_acquire().expect("probe");
        p.record_failure();
        assert_eq!(b.state(), BreakerState::Open);
    }

    #[test]
    fn permit_drop_without_settle_counts_as_failure() {
        let b = CircuitBreaker::new(BreakerConfig {
            failure_threshold: 1,
            reset_after: Duration::from_secs(60),
            success_threshold: 1,
        });
        {
            let _p = b.try_acquire().expect("closed admits");
            // Drop without settle.
        }
        assert_eq!(b.state(), BreakerState::Open);
    }

    #[test]
    fn registry_returns_same_breaker_for_same_id() {
        let r = BreakerRegistry::with_defaults();
        let a = r.breaker_for("openai");
        let b = r.breaker_for("openai");
        assert!(std::sync::Arc::ptr_eq(&a, &b));
        let c = r.breaker_for("gemini");
        assert!(!std::sync::Arc::ptr_eq(&a, &c));
    }

    #[test]
    fn registry_snapshot_all_returns_sorted_entries() {
        let r = BreakerRegistry::with_defaults();
        let _ = r.breaker_for("zeta");
        let _ = r.breaker_for("alpha");
        let _ = r.breaker_for("middle");
        let snaps = r.snapshot_all();
        assert_eq!(snaps.len(), 3);
        let ids: Vec<&str> = snaps.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(ids, vec!["alpha", "middle", "zeta"]);
    }

    #[test]
    fn snapshot_carries_seconds_in_open_when_open() {
        let b = CircuitBreaker::new(BreakerConfig {
            failure_threshold: 1,
            reset_after: Duration::from_secs(60),
            success_threshold: 1,
        });
        b.try_acquire().unwrap().record_failure();
        std::thread::sleep(Duration::from_millis(15));
        let snap = b.snapshot();
        assert_eq!(snap.state, BreakerState::Open);
        let secs = snap.seconds_in_open.expect("Open carries timestamp");
        assert!(secs >= 0.01, "seconds_in_open should be > 10ms: {secs}");
    }

    #[test]
    fn breaker_state_as_str_pinned() {
        assert_eq!(BreakerState::Closed.as_str(), "closed");
        assert_eq!(BreakerState::Open.as_str(), "open");
        assert_eq!(BreakerState::HalfOpen.as_str(), "half_open");
    }

    #[test]
    fn breaker_error_display_carries_retry_after() {
        let err = BreakerError::Open {
            retry_after: Duration::from_secs_f64(12.5),
        };
        let s = err.to_string();
        assert!(s.contains("open"));
        assert!(s.contains("12.5"));
    }
}
