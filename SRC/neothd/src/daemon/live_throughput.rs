//! W162 — bounded request-local live throughput accounting.
//!
//! This module intentionally stores only millisecond bucket counts.  It never
//! sees response text, identities, tokens, WAL handles, or global state.  The
//! caller supplies only already-authorized event/token increments for one
//! request and owns all transport/presentation decisions.
//!
//! The rolling window is discrete at one-millisecond resolution.  Each bucket
//! represents the closed interval selected by `Instant::elapsed().as_millis()`;
//! the active window contains buckets `[now_ms - 999, now_ms]`.  The denominator
//! is always one second, so an early request is not spuriously inflated by a
//! shorter elapsed denominator.  Counts saturate at `u64::MAX`; saturation is
//! conservative (never wraps or fabricates a lower count) and clears normally
//! when the saturated bucket ages out.

use std::time::{Duration, Instant};

/// Fixed resolution for the exact discrete rolling window.
pub const LIVE_THROUGHPUT_BUCKET_RESOLUTION: Duration = Duration::from_millis(1);
/// Number of fixed millisecond buckets retained for one rolling second.
pub const LIVE_THROUGHPUT_BUCKET_COUNT: usize = 1_000;
const LIVE_THROUGHPUT_WINDOW_MS: u64 = LIVE_THROUGHPUT_BUCKET_COUNT as u64;

/// The unit whose per-second rate the caller is permitted to display.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiveThroughputBasis {
    /// A real nonempty visible stream event admitted to the current request.
    VisibleEvent,
    /// A provider-proven incremental output-token delta.
    TokenDelta,
}

/// Honest reasons why no current numerical rate is available.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiveThroughputUnavailable {
    /// No admitted visible event has occurred for this request.
    NoVisibleEvents,
    /// The provider offered no incremental token accounting.
    NoUsageReported,
    /// The request was cancelled before a live rate could continue.
    Cancelled,
    /// The stream ended with an error.
    StreamError,
}

/// Transient state suitable for a request-bound protocol projection.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum LiveThroughputState {
    /// A stable-one-second rolling rate in the declared basis.
    Measuring {
        basis: LiveThroughputBasis,
        per_second: f64,
    },
    /// The request is active but its once-populated rolling window is empty.
    Paused { basis: LiveThroughputBasis },
    /// No numerical rate is honest for the current lifecycle state.
    Unavailable(LiveThroughputUnavailable),
}

/// Caller error rather than a display state: callers must not mix bases,
/// resurrect a terminal request, send zero token increments, or move monotonic
/// time backwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiveThroughputError {
    BasisMismatch,
    ZeroTokenDelta,
    TimeRegression,
    Terminal,
}

/// A bounded, request-local rolling one-second counter.
#[derive(Debug)]
pub struct LiveThroughputWindow {
    basis: LiveThroughputBasis,
    anchor: Instant,
    last_now: Instant,
    last_elapsed_ms: u64,
    buckets: [u64; LIVE_THROUGHPUT_BUCKET_COUNT],
    ever_observed: bool,
    terminal: bool,
}

impl LiveThroughputWindow {
    /// Construct from an injected monotonic instant for deterministic callers
    /// and tests. The initial state is unavailable until an eligible event is
    /// observed.
    #[must_use]
    pub fn new(basis: LiveThroughputBasis, now: Instant) -> Self {
        Self {
            basis,
            anchor: now,
            last_now: now,
            last_elapsed_ms: 0,
            buckets: [0; LIVE_THROUGHPUT_BUCKET_COUNT],
            ever_observed: false,
            terminal: false,
        }
    }

    /// Construct from the current monotonic clock for production call sites.
    #[must_use]
    pub fn start(basis: LiveThroughputBasis) -> Self {
        Self::new(basis, Instant::now())
    }

    #[must_use]
    pub const fn basis(&self) -> LiveThroughputBasis {
        self.basis
    }

    /// Count one already-admitted, nonempty visible event. The caller must not
    /// pass reasoning, control, error, empty, or suppressed output here.
    pub fn observe_visible_event(
        &mut self,
        now: Instant,
    ) -> Result<LiveThroughputState, LiveThroughputError> {
        if self.basis != LiveThroughputBasis::VisibleEvent {
            return Err(LiveThroughputError::BasisMismatch);
        }
        self.record(now, 1)
    }

    /// Count one explicit provider incremental output-token delta. Final or
    /// cumulative provider usage totals are not valid input to this method.
    pub fn observe_incremental_tokens(
        &mut self,
        now: Instant,
        delta: u32,
    ) -> Result<LiveThroughputState, LiveThroughputError> {
        if self.basis != LiveThroughputBasis::TokenDelta {
            return Err(LiveThroughputError::BasisMismatch);
        }
        if delta == 0 {
            return Err(LiveThroughputError::ZeroTokenDelta);
        }
        self.record(now, u64::from(delta))
    }

    /// Advance the window without adding a unit. A once-populated empty window
    /// is paused; a never-populated window stays honestly unavailable.
    pub fn observe_idle(
        &mut self,
        now: Instant,
    ) -> Result<LiveThroughputState, LiveThroughputError> {
        self.advance(now)?;
        Ok(self.state())
    }

    /// Terminal lifecycle state clears every retained bucket and rejects later
    /// observations until `reset` establishes a new request lifetime.
    pub fn terminal(&mut self, why: LiveThroughputUnavailable) -> LiveThroughputState {
        self.buckets = [0; LIVE_THROUGHPUT_BUCKET_COUNT];
        self.terminal = true;
        LiveThroughputState::Unavailable(why)
    }

    /// Start a distinct request lifetime with the same explicit basis.
    pub fn reset(&mut self, now: Instant) {
        self.anchor = now;
        self.last_now = now;
        self.last_elapsed_ms = 0;
        self.buckets = [0; LIVE_THROUGHPUT_BUCKET_COUNT];
        self.ever_observed = false;
        self.terminal = false;
    }

    fn record(
        &mut self,
        now: Instant,
        amount: u64,
    ) -> Result<LiveThroughputState, LiveThroughputError> {
        self.advance(now)?;
        let index = bucket_index(self.last_elapsed_ms);
        self.buckets[index] = self.buckets[index].saturating_add(amount);
        self.ever_observed = true;
        Ok(self.state())
    }

    fn advance(&mut self, now: Instant) -> Result<(), LiveThroughputError> {
        if self.terminal {
            return Err(LiveThroughputError::Terminal);
        }
        if now.checked_duration_since(self.last_now).is_none() {
            return Err(LiveThroughputError::TimeRegression);
        }
        let elapsed = now
            .checked_duration_since(self.anchor)
            .ok_or(LiveThroughputError::TimeRegression)?;
        let elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        let advanced_ms = elapsed_ms.saturating_sub(self.last_elapsed_ms);

        if advanced_ms >= LIVE_THROUGHPUT_WINDOW_MS {
            self.buckets = [0; LIVE_THROUGHPUT_BUCKET_COUNT];
        } else {
            for millisecond in self.last_elapsed_ms.saturating_add(1)..=elapsed_ms {
                let index = bucket_index(millisecond);
                self.buckets[index] = 0;
            }
        }

        self.last_now = now;
        self.last_elapsed_ms = elapsed_ms;
        Ok(())
    }

    fn state(&self) -> LiveThroughputState {
        let retained_count = self
            .buckets
            .iter()
            .copied()
            .fold(0_u64, u64::saturating_add);
        if retained_count != 0 {
            // The retained count is always a rolling 1000ms discrete window,
            // so its stable denominator is exactly one second.
            return LiveThroughputState::Measuring {
                basis: self.basis,
                per_second: retained_count as f64,
            };
        }
        if self.ever_observed {
            LiveThroughputState::Paused { basis: self.basis }
        } else {
            LiveThroughputState::Unavailable(match self.basis {
                LiveThroughputBasis::VisibleEvent => LiveThroughputUnavailable::NoVisibleEvents,
                LiveThroughputBasis::TokenDelta => LiveThroughputUnavailable::NoUsageReported,
            })
        }
    }
}

const fn bucket_index(elapsed_ms: u64) -> usize {
    (elapsed_ms % LIVE_THROUGHPUT_WINDOW_MS) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(start: Instant, milliseconds: u64) -> Instant {
        start + Duration::from_millis(milliseconds)
    }

    #[test]
    fn visible_events_use_a_stable_one_second_denominator() {
        let start = Instant::now();
        let mut window = LiveThroughputWindow::new(LiveThroughputBasis::VisibleEvent, start);

        assert_eq!(
            window.observe_visible_event(start).unwrap(),
            LiveThroughputState::Measuring {
                basis: LiveThroughputBasis::VisibleEvent,
                per_second: 1.0,
            }
        );
        assert_eq!(
            window.observe_visible_event(at(start, 250)).unwrap(),
            LiveThroughputState::Measuring {
                basis: LiveThroughputBasis::VisibleEvent,
                per_second: 2.0,
            }
        );
    }

    #[test]
    fn discrete_window_expires_a_bucket_at_exactly_one_thousand_milliseconds() {
        let start = Instant::now();
        let mut window = LiveThroughputWindow::new(LiveThroughputBasis::VisibleEvent, start);
        window.observe_visible_event(start).unwrap();

        assert!(matches!(
            window.observe_idle(at(start, 999)).unwrap(),
            LiveThroughputState::Measuring {
                per_second: 1.0,
                ..
            }
        ));
        assert_eq!(
            window.observe_idle(at(start, 1_000)).unwrap(),
            LiveThroughputState::Paused {
                basis: LiveThroughputBasis::VisibleEvent,
            }
        );
    }

    #[test]
    fn fixed_buckets_preserve_high_event_rate_within_one_millisecond() {
        let start = Instant::now();
        let mut window = LiveThroughputWindow::new(LiveThroughputBasis::VisibleEvent, start);
        for _ in 0..20_000 {
            window.observe_visible_event(start).unwrap();
        }
        assert_eq!(
            window.observe_idle(start).unwrap(),
            LiveThroughputState::Measuring {
                basis: LiveThroughputBasis::VisibleEvent,
                per_second: 20_000.0,
            }
        );
    }

    #[test]
    fn token_basis_requires_positive_explicit_incremental_deltas() {
        let start = Instant::now();
        let mut window = LiveThroughputWindow::new(LiveThroughputBasis::TokenDelta, start);
        assert_eq!(
            window.observe_incremental_tokens(start, 0),
            Err(LiveThroughputError::ZeroTokenDelta)
        );
        assert_eq!(
            window.observe_visible_event(start),
            Err(LiveThroughputError::BasisMismatch)
        );
        assert_eq!(
            window.observe_incremental_tokens(start, 7).unwrap(),
            LiveThroughputState::Measuring {
                basis: LiveThroughputBasis::TokenDelta,
                per_second: 7.0,
            }
        );
    }

    #[test]
    fn time_regression_is_rejected_without_reusing_old_buckets() {
        let start = Instant::now();
        let mut window = LiveThroughputWindow::new(LiveThroughputBasis::VisibleEvent, start);
        window.observe_visible_event(at(start, 10)).unwrap();
        assert_eq!(
            window.observe_idle(at(start, 9)),
            Err(LiveThroughputError::TimeRegression)
        );
        assert!(matches!(
            window.observe_idle(at(start, 10)).unwrap(),
            LiveThroughputState::Measuring {
                per_second: 1.0,
                ..
            }
        ));
    }

    #[test]
    fn terminal_clears_state_and_reset_starts_a_distinct_lifetime() {
        let start = Instant::now();
        let mut window = LiveThroughputWindow::new(LiveThroughputBasis::VisibleEvent, start);
        window.observe_visible_event(start).unwrap();
        assert_eq!(
            window.terminal(LiveThroughputUnavailable::Cancelled),
            LiveThroughputState::Unavailable(LiveThroughputUnavailable::Cancelled)
        );
        assert_eq!(
            window.observe_idle(at(start, 1)),
            Err(LiveThroughputError::Terminal)
        );

        let next = at(start, 2_000);
        window.reset(next);
        assert_eq!(
            window.observe_idle(next).unwrap(),
            LiveThroughputState::Unavailable(LiveThroughputUnavailable::NoVisibleEvents)
        );
    }
}
