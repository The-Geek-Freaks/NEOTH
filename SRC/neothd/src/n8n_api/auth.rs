//! Auth failure cooldown tracker for the localhost API.
//!
//! 5 consecutive failures (wrong / missing bearer) from one source
//! triggers a 60s silence window. Defends against accidental
//! operator config drift / mistyped env from spamming the WAL with
//! 0x39 audit frames. Per-source key is the socket-peer string
//! (e.g. `"127.0.0.1:54321"` minus the port — the operator owns the
//! host, so coarsely keying by `"127.0.0.1"` is fine).
//!
//! In-memory only; the cooldown evaporates on daemon restart, which
//! is the correct behaviour (process restart = operator-attested
//! "I know what I'm doing").

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::{AUTH_FAILURE_COOLDOWN_SECS, AUTH_FAILURE_STRIKE_LIMIT};

/// Per-source strike + cooldown state.
#[derive(Clone, Debug)]
struct SourceState {
    strikes: u32,
    cooldown_until: Option<Instant>,
}

impl SourceState {
    fn new() -> Self {
        Self {
            strikes: 0,
            cooldown_until: None,
        }
    }
}

/// Thread-safe in-memory tracker keyed by `source` (loopback peer
/// host without port). Methods are coarse-locked — auth latency is
/// dominated by token compare, not the HashMap touch.
#[derive(Debug, Default)]
pub struct AuthCooldown {
    state: Mutex<HashMap<String, SourceState>>,
}

impl AuthCooldown {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` when the given source is currently in cooldown
    /// and the auth middleware must short-circuit with 401.
    pub fn is_locked(&self, source: &str, now: Instant) -> bool {
        let guard = match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard
            .get(source)
            .and_then(|s| s.cooldown_until)
            .is_some_and(|until| now < until)
    }

    /// Records one failed auth attempt. When the strike count hits
    /// [`AUTH_FAILURE_STRIKE_LIMIT`] the source enters a
    /// [`AUTH_FAILURE_COOLDOWN_SECS`] silence window. Returns true
    /// when this call tripped the cooldown.
    pub fn record_failure(&self, source: &str, now: Instant) -> bool {
        let mut guard = match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let entry = guard
            .entry(source.to_string())
            .or_insert_with(SourceState::new);
        entry.strikes = entry.strikes.saturating_add(1);
        if entry.strikes >= AUTH_FAILURE_STRIKE_LIMIT {
            entry.cooldown_until = Some(now + Duration::from_secs(AUTH_FAILURE_COOLDOWN_SECS));
            entry.strikes = 0;
            true
        } else {
            false
        }
    }

    /// Clears the strike count for a source. Called on every
    /// successful auth — a single good token resets the counter so
    /// a future flurry of typos gets a fresh 5-strike budget.
    pub fn record_success(&self, source: &str) {
        let mut guard = match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(entry) = guard.get_mut(source) {
            entry.strikes = 0;
            entry.cooldown_until = None;
        }
    }

    /// Snapshot for tests — current strike count + cooldown state
    /// for `source`. `None` when the source was never seen.
    #[cfg(test)]
    pub(crate) fn peek(&self, source: &str) -> Option<(u32, bool)> {
        let guard = match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard
            .get(source)
            .map(|s| (s.strikes, s.cooldown_until.is_some()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_source_not_locked() {
        let c = AuthCooldown::new();
        assert!(!c.is_locked("127.0.0.1", Instant::now()));
    }

    #[test]
    fn under_limit_no_lock() {
        let c = AuthCooldown::new();
        let now = Instant::now();
        for _ in 0..(AUTH_FAILURE_STRIKE_LIMIT - 1) {
            let tripped = c.record_failure("src", now);
            assert!(!tripped);
        }
        assert!(!c.is_locked("src", now));
    }

    #[test]
    fn fifth_failure_trips_cooldown() {
        let c = AuthCooldown::new();
        let now = Instant::now();
        for _ in 0..(AUTH_FAILURE_STRIKE_LIMIT - 1) {
            c.record_failure("src", now);
        }
        let tripped = c.record_failure("src", now);
        assert!(tripped);
        assert!(c.is_locked("src", now));
    }

    #[test]
    fn cooldown_expires_after_60s() {
        let c = AuthCooldown::new();
        let now = Instant::now();
        for _ in 0..AUTH_FAILURE_STRIKE_LIMIT {
            c.record_failure("src", now);
        }
        assert!(c.is_locked("src", now));
        let after = now + Duration::from_secs(AUTH_FAILURE_COOLDOWN_SECS + 1);
        assert!(!c.is_locked("src", after));
    }

    #[test]
    fn success_resets_strike_count() {
        let c = AuthCooldown::new();
        let now = Instant::now();
        c.record_failure("src", now);
        c.record_failure("src", now);
        c.record_success("src");
        assert_eq!(c.peek("src"), Some((0, false)));
        // After reset, need full 5 strikes again to lock.
        for _ in 0..(AUTH_FAILURE_STRIKE_LIMIT - 1) {
            assert!(!c.record_failure("src", now));
        }
        assert!(c.record_failure("src", now));
    }

    #[test]
    fn per_source_isolation() {
        let c = AuthCooldown::new();
        let now = Instant::now();
        for _ in 0..AUTH_FAILURE_STRIKE_LIMIT {
            c.record_failure("a", now);
        }
        assert!(c.is_locked("a", now));
        assert!(!c.is_locked("b", now));
    }
}
