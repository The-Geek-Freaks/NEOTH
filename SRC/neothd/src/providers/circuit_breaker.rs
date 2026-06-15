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
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Process-wide breaker registry. v0.1.x has no runtime sidecar
/// exposing the registry into the doctor context yet (Phase 3),
/// but the chat dispatch path consults this Lazy to keep state
/// across requests within one daemon run. Per-process scope is
/// the right v0.1 default — surviving a daemon restart is the
/// Phase 3 follow-up (persisted breaker state would tip the
/// daemon into the "open" state on boot after a transient
/// outage just before shutdown).
pub static GLOBAL: LazyLock<BreakerRegistry> = LazyLock::new(BreakerRegistry::with_defaults);

/// Owned permit — same RAII contract as `Permit<'a>` but holds an
/// `Arc<CircuitBreaker>` so it can outlive any stack frame and
/// be returned from a registry helper. Use this when the call
/// site needs the permit to live past a borrow boundary
/// (typical for the chat dispatch hot path).
#[must_use = "must call record_success() or record_failure() on an OwnedPermit"]
#[derive(Debug)]
pub struct OwnedPermit {
    breaker: std::sync::Arc<CircuitBreaker>,
    settled: bool,
}

impl OwnedPermit {
    pub fn record_success(mut self) {
        self.breaker.record_success_inner();
        self.settled = true;
    }

    pub fn record_failure(mut self) {
        self.breaker.record_failure_inner();
        self.settled = true;
    }
}

impl Drop for OwnedPermit {
    fn drop(&mut self) {
        if !self.settled {
            self.breaker.record_failure_inner();
        }
    }
}

/// Helper for the chat / dispatch hot path. Looks up the breaker
/// for `provider_id` from the global registry + tries to acquire.
/// Returns `Ok(OwnedPermit)` on admit, `Err(BreakerError)` when
/// the breaker is Open / probing. Callers settle the permit with
/// `record_success` / `record_failure` after the provider call;
/// dropping without settling counts as a failure (conservative).
pub fn acquire_for(provider_id: &str) -> Result<OwnedPermit, BreakerError> {
    let breaker_arc = GLOBAL.breaker_for(provider_id);
    // Replicate the state-machine transition logic from
    // `CircuitBreaker::try_acquire` without holding the lifetime
    // borrow — we own the Arc so the permit can live as long as
    // the caller needs.
    let mut g = breaker_arc.lock();
    match g.state {
        BreakerState::Closed => {
            drop(g);
            Ok(OwnedPermit {
                breaker: breaker_arc,
                settled: false,
            })
        }
        BreakerState::HalfOpen => {
            if g.half_open_probe_inflight {
                Err(BreakerError::HalfOpenBusy)
            } else {
                g.half_open_probe_inflight = true;
                drop(g);
                Ok(OwnedPermit {
                    breaker: breaker_arc,
                    settled: false,
                })
            }
        }
        BreakerState::Open => {
            let opened_at = g
                .opened_at
                .expect("Open state must carry an opened_at timestamp");
            let elapsed = Instant::now().saturating_duration_since(opened_at);
            if elapsed >= breaker_arc.config.reset_after {
                g.state = BreakerState::HalfOpen;
                g.half_open_probe_inflight = true;
                drop(g);
                Ok(OwnedPermit {
                    breaker: breaker_arc,
                    settled: false,
                })
            } else {
                Err(BreakerError::Open {
                    retry_after: breaker_arc.config.reset_after - elapsed,
                })
            }
        }
    }
}

/// GR-04 helper: wrap an async provider call so it observes the
/// breaker without each provider needing to re-implement the
/// `acquire_for` + `record_success`/`record_failure` boilerplate.
///
/// Pattern at every `Provider::complete` / `Provider::stream` site:
/// ```ignore
/// async fn complete(&self, req: Request) -> anyhow::Result<Completion> {
///     run_with_breaker(self.name(), async {
///         // existing body — `?` exits land as record_failure, the
///         // final Ok(..) lands as record_success.
///     }).await
/// }
/// ```
///
/// The future is polled to completion regardless of the breaker
/// outcome; only the success/failure tally and the open-circuit
/// fast-fail are added. Open-circuit rejection materialises as an
/// anyhow error whose message includes the provider id + retry-after
/// hint so operators reading the WAL audit can correlate.
pub async fn run_with_breaker<F, T>(provider_id: &str, fut: F) -> anyhow::Result<T>
where
    F: std::future::Future<Output = anyhow::Result<T>>,
{
    let permit = acquire_for(provider_id)
        .map_err(|e| anyhow::anyhow!("circuit breaker open for {provider_id}: {e}"))?;
    let result = fut.await;
    match &result {
        Ok(_) => permit.record_success(),
        Err(_) => permit.record_failure(),
    }
    result
}

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

/// QM-10 Phase 3: persistable snapshot per-breaker for cross-restart
/// continuity. Only the failure counter persists — the Open state is
/// intentionally NOT restored (a restarted daemon should retry every
/// provider afresh, per the Phase 1 design note). Operators who hit
/// a transient Open just before shutdown shouldn't see the breaker
/// still Open after a daemon restart.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct BreakerPersistedRow {
    pub provider_id: String,
    pub consecutive_failures: u32,
    pub last_seen_ts_unix: i64,
}

/// JSONL persistence layer for the breaker registry. Mirrors the
/// usage_log pattern — one row per provider, append-only with the
/// daily file naming so historical breaker behaviour is auditable.
pub mod persist {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Directory under `home` that holds the breaker state file.
    pub fn dir(home: &Path) -> std::path::PathBuf {
        home.join("breakers")
    }

    /// Single-row file — the breaker state surfaces a NOT-time-
    /// series view, just the latest counter per provider. Daily
    /// rotation isn't useful here (unlike usage_log which is
    /// per-event); operators want "what does the state look like
    /// right now" persisted across restarts.
    pub fn state_file(home: &Path) -> std::path::PathBuf {
        dir(home).join("state.jsonl")
    }

    /// Snapshot every registered breaker into the state file.
    /// Atomic write via `.tmp` + rename. Best-effort I/O — caller
    /// decides whether to warn-and-continue on error.
    pub fn snapshot_to_disk(home: &Path, registry: &BreakerRegistry) -> std::io::Result<usize> {
        fs::create_dir_all(dir(home))?;
        let now = crate::time::now_unix_i64();
        let snaps = registry.snapshot_all();
        // Only persist providers that have non-zero failure
        // history — saves disk + keeps the restore noise-free.
        let rows: Vec<BreakerPersistedRow> = snaps
            .into_iter()
            .filter(|(_, snap)| snap.consecutive_failures > 0)
            .map(|(provider_id, snap)| BreakerPersistedRow {
                provider_id,
                consecutive_failures: snap.consecutive_failures,
                last_seen_ts_unix: now,
            })
            .collect();
        let path = state_file(home);
        let tmp = path.with_extension("jsonl.tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            for row in &rows {
                let line = serde_json::to_vec(row).map_err(std::io::Error::other)?;
                f.write_all(&line)?;
                f.write_all(b"\n")?;
            }
            f.flush()?;
        }
        fs::rename(&tmp, &path)?;
        Ok(rows.len())
    }

    /// Restore failure counters into the global registry. Stale
    /// rows (older than `stale_after_secs` seconds) are skipped —
    /// a breaker that's been idle for a day shouldn't restore its
    /// pre-idle failure count.
    pub fn restore_from_disk(
        home: &Path,
        registry: &BreakerRegistry,
        stale_after_secs: i64,
    ) -> std::io::Result<usize> {
        let path = state_file(home);
        if !path.exists() {
            return Ok(0);
        }
        let body = fs::read_to_string(&path)?;
        // Fail-safe: a `now = 0` default underflows `now - last_seen_ts_unix`
        // to a large negative number, defeating the staleness skip — so EVERY
        // persisted row (even months-old) would be restored as if fresh,
        // potentially forcing healthy providers Open after a clock fault.
        // Surface the error; the caller logs it non-fatally and skips restore
        // (clean breakers are the safe default).
        let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_secs() as i64,
            Err(e) => {
                return Err(std::io::Error::other(format!(
                    "system clock is before UNIX_EPOCH ({e}); skipping breaker restore"
                )));
            }
        };
        let mut restored = 0usize;
        for line in body.lines() {
            let Ok(row) = serde_json::from_str::<BreakerPersistedRow>(line) else {
                continue;
            };
            if now - row.last_seen_ts_unix > stale_after_secs {
                continue;
            }
            let breaker = registry.breaker_for(&row.provider_id);
            // Restore only the failure counter — never the Open
            // state (per Phase 1 design note).
            let mut g = breaker.lock();
            g.consecutive_failures = row.consecutive_failures;
            drop(g);
            restored += 1;
        }
        Ok(restored)
    }
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
        let mut out: Vec<_> = g.iter().map(|(k, v)| (k.clone(), v.snapshot())).collect();
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
    fn acquire_for_admits_when_global_breaker_is_closed() {
        // Use a provider id unique to this test to avoid global
        // state collisions with other tests in the same process.
        let id = "qm10_admit_test_provider";
        let p = acquire_for(id).expect("global Closed breaker admits");
        p.record_success();
        // Repeat admit — should still pass.
        let p2 = acquire_for(id).expect("Closed admit again after success");
        p2.record_success();
    }

    #[test]
    fn acquire_for_owned_permit_drop_counts_as_failure() {
        let id = "qm10_drop_failure_test_provider";
        // Drop without settling 5 times to flip the global breaker
        // to Open for this provider id.
        for _ in 0..5 {
            let _ = acquire_for(id);
        }
        // 6th attempt should be rejected.
        match acquire_for(id) {
            Err(BreakerError::Open { retry_after }) => {
                assert!(retry_after.as_secs() > 0);
            }
            other => panic!("expected Open after 5 drops, got {other:?}"),
        }
    }

    #[test]
    fn persist_snapshot_roundtrip_restores_failure_counter() {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let r1 = BreakerRegistry::with_defaults();
        // Drive one breaker to 3 failures.
        let b = r1.breaker_for("openai");
        for _ in 0..3 {
            b.try_acquire().unwrap().record_failure();
        }
        assert_eq!(b.snapshot().consecutive_failures, 3);
        let written = persist::snapshot_to_disk(dir.path(), &r1).unwrap();
        assert_eq!(written, 1);
        // Fresh registry: restore picks up the counter.
        let r2 = BreakerRegistry::with_defaults();
        let restored = persist::restore_from_disk(dir.path(), &r2, 86_400).unwrap();
        assert_eq!(restored, 1);
        let b2 = r2.breaker_for("openai");
        assert_eq!(b2.snapshot().consecutive_failures, 3);
        // State stays Closed even though pre-snapshot was approaching
        // Open — restart-grace per Phase 1 design.
        assert_eq!(b2.snapshot().state, BreakerState::Closed);
    }

    #[test]
    fn persist_snapshot_skips_zero_failure_breakers() {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let r = BreakerRegistry::with_defaults();
        let _ = r.breaker_for("openai");
        let _ = r.breaker_for("gemini");
        let written = persist::snapshot_to_disk(dir.path(), &r).unwrap();
        assert_eq!(written, 0, "no failure history → nothing persisted");
    }

    #[test]
    fn persist_restore_missing_file_returns_zero() {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let r = BreakerRegistry::with_defaults();
        let restored = persist::restore_from_disk(dir.path(), &r, 86_400).unwrap();
        assert_eq!(restored, 0);
    }

    #[test]
    fn persist_skips_stale_rows() {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        // Write a row with last_seen_ts_unix in the deep past.
        let now = crate::time::now_unix_i64();
        let stale_row = BreakerPersistedRow {
            provider_id: "stale_provider".into(),
            consecutive_failures: 99,
            last_seen_ts_unix: now - 86_400 * 30, // 30 days old
        };
        std::fs::create_dir_all(persist::dir(dir.path())).unwrap();
        std::fs::write(
            persist::state_file(dir.path()),
            format!("{}\n", serde_json::to_string(&stale_row).unwrap()),
        )
        .unwrap();
        let r = BreakerRegistry::with_defaults();
        // stale_after = 7 days → 30-day row gets skipped.
        let restored = persist::restore_from_disk(dir.path(), &r, 7 * 86_400).unwrap();
        assert_eq!(restored, 0);
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

    // ── GR-04: run_with_breaker wrapper coverage ─────────────────────────

    /// Unique provider-id per test so the global registry's state
    /// from a previous test cannot bleed into the next.
    fn unique_provider_id(suffix: &str) -> String {
        format!(
            "gr04-test-{}-{}",
            suffix,
            crate::time::now_unix_ns_u128()
        )
    }

    #[tokio::test]
    async fn run_with_breaker_admits_ok_path_and_records_success() {
        let id = unique_provider_id("ok");
        let out = run_with_breaker(&id, async { Ok::<u32, anyhow::Error>(7) })
            .await
            .expect("Ok future should pass through");
        assert_eq!(out, 7);
        // Successful settle keeps state Closed.
        let snap = GLOBAL.snapshot_all();
        let (_id, row) = snap
            .iter()
            .find(|(k, _)| k == &id)
            .expect("breaker row exists");
        assert_eq!(row.state, BreakerState::Closed);
        assert_eq!(row.consecutive_failures, 0);
        // consecutive_successes only ticks in HalfOpen state — in Closed
        // the breaker just keeps consecutive_failures = 0. Pinning the
        // state + failures is enough to prove the success path settled.
    }

    #[tokio::test]
    async fn run_with_breaker_propagates_err_and_records_failure() {
        let id = unique_provider_id("err");
        let err = run_with_breaker(&id, async {
            Err::<(), anyhow::Error>(anyhow::anyhow!("upstream fail"))
        })
        .await
        .expect_err("Err future should surface");
        assert!(format!("{err}").contains("upstream fail"));
        // Single failure stays Closed (threshold is 5) but tally moves.
        let snap = GLOBAL.snapshot_all();
        let (_id, row) = snap.iter().find(|(k, _)| k == &id).unwrap();
        assert_eq!(row.consecutive_failures, 1);
    }

    #[tokio::test]
    async fn run_with_breaker_rejects_when_circuit_open() {
        let id = unique_provider_id("trip");
        // Trip the breaker by recording enough failures to exceed the
        // default threshold (BreakerConfig::default is 5 failures).
        for _ in 0..6 {
            let _ = run_with_breaker(&id, async {
                Err::<(), anyhow::Error>(anyhow::anyhow!("fail"))
            })
            .await;
        }
        // Next call MUST be rejected at acquire — never enters the
        // future — with a message naming the provider id.
        let err = run_with_breaker(&id, async { Ok::<(), anyhow::Error>(()) })
            .await
            .expect_err("open circuit must reject");
        let msg = format!("{err}");
        assert!(
            msg.contains("circuit breaker open"),
            "expected open-circuit reason, got: {msg}"
        );
        assert!(
            msg.contains(&id),
            "expected provider id in error, got: {msg}"
        );
    }
}
