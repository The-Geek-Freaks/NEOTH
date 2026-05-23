//! B-6 Item 4e — provider-cooldown pair state machine.
//!
//! bridge.py runs paired `claude` sessions (`left` / `right`) and
//! flips between them for failover: when one side hits a transient
//! error (rate-limit, 5xx, OAuth challenge), it goes into a cooldown
//! window + the next request lands on its partner. NEOTH's
//! `inference.left` / `inference.right` / `inference.cerebellum`
//! hemisphere config already declares the slots; this module ships
//! the cooldown ORCHESTRATION layer that sits on top of any pair of
//! provider IDs.
//!
//! Scope (this commit):
//!   - Pure-fn `CooldownPair` state struct holding two provider IDs +
//!     per-side cooldown expiry timestamps.
//!   - `pick_active(now)` returns the side that should serve the
//!     next request. Picks the "cool" side when both are alive; the
//!     non-cooled side when one is cooling; bails when both are
//!     cooling.
//!   - `record_failure(side, class, now)` consults the B-6 Item 3h
//!     retry classifier to decide the cooldown window per failure
//!     class. Auth = 0s (never auto-retry); Transient = 60s; others
//!     = constant short windows from the retry decision.
//!   - `record_success(side)` clears the cooldown when a side
//!     successfully completes.
//!
//! Wiring (deferred): the dispatcher consults `pick_active` before
//! `complete()`; on error it calls `record_failure(side, class)`
//! using the retry-classifier output. v0.2 lands the wire-up.

use std::time::{Duration, Instant};

use super::claude_retry::RetryClass;

/// Which side of the pair. `Left` / `Right` matches the
/// `inference.left` / `inference.right` hemisphere convention
/// already shipped in `freedom.yaml`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PairSide {
    Left,
    Right,
}

impl PairSide {
    pub fn other(self) -> Self {
        match self {
            Self::Left => Self::Right,
            Self::Right => Self::Left,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Left => "left",
            Self::Right => "right",
        }
    }
}

/// Outcome of [`CooldownPair::pick_active`]. `Both` means neither
/// side is cooling + dispatcher may pick whichever it prefers
/// (round-robin / hash / etc.).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PickOutcome {
    /// Both sides alive — caller chooses.
    Both,
    /// Only the named side is alive.
    Single(PairSide),
    /// Both sides cooling. Caller surfaces "pair exhausted".
    None,
}

/// One operator-tunable cooldown-pair tracker. Holds per-side
/// expiry timestamps in `Option<Instant>` — None = side is alive,
/// Some(t) = side cools until t.
#[derive(Clone, Debug)]
pub struct CooldownPair {
    pub left_provider: String,
    pub right_provider: String,
    left_cooling_until: Option<Instant>,
    right_cooling_until: Option<Instant>,
}

impl CooldownPair {
    /// Construct a fresh pair — both sides alive.
    pub fn new(left: impl Into<String>, right: impl Into<String>) -> Self {
        Self {
            left_provider: left.into(),
            right_provider: right.into(),
            left_cooling_until: None,
            right_cooling_until: None,
        }
    }

    /// Which side should serve the next request. `now` injected so
    /// tests can pin timing without a sleep.
    pub fn pick_active(&self, now: Instant) -> PickOutcome {
        let left_cool = self.is_cooling(PairSide::Left, now);
        let right_cool = self.is_cooling(PairSide::Right, now);
        match (left_cool, right_cool) {
            (false, false) => PickOutcome::Both,
            (true, false) => PickOutcome::Single(PairSide::Right),
            (false, true) => PickOutcome::Single(PairSide::Left),
            (true, true) => PickOutcome::None,
        }
    }

    /// True ⇔ the named side is in its cooldown window at `now`.
    pub fn is_cooling(&self, side: PairSide, now: Instant) -> bool {
        let until = match side {
            PairSide::Left => self.left_cooling_until,
            PairSide::Right => self.right_cooling_until,
        };
        match until {
            Some(t) => t > now,
            None => false,
        }
    }

    /// Mark `side` failed with the given retry class. Sets the
    /// cooldown window per [`cooldown_for_class`].
    pub fn record_failure(&mut self, side: PairSide, class: RetryClass, now: Instant) {
        let dur = cooldown_for_class(class);
        let until = now + dur;
        match side {
            PairSide::Left => self.left_cooling_until = Some(until),
            PairSide::Right => self.right_cooling_until = Some(until),
        }
    }

    /// Clear the cooldown on `side` after a successful completion.
    pub fn record_success(&mut self, side: PairSide) {
        match side {
            PairSide::Left => self.left_cooling_until = None,
            PairSide::Right => self.right_cooling_until = None,
        }
    }

    /// Borrow the configured provider ID for `side`.
    pub fn provider_for(&self, side: PairSide) -> &str {
        match side {
            PairSide::Left => &self.left_provider,
            PairSide::Right => &self.right_provider,
        }
    }
}

/// Map a [`RetryClass`] to its cooldown window. Pinned per-class:
///   - Auth → infinite-ish (1 hour — operator must rerun `/login`).
///   - SessionCollision → 5s.
///   - EmptyStdout → 10s.
///   - Transient → 60s (longest; we want to drain rate-limit windows).
pub fn cooldown_for_class(class: RetryClass) -> Duration {
    match class {
        RetryClass::Auth => Duration::from_secs(3_600),
        RetryClass::SessionCollision => Duration::from_secs(5),
        RetryClass::EmptyStdout => Duration::from_secs(10),
        RetryClass::Transient => Duration::from_secs(60),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn fresh_pair_picks_both() {
        let p = CooldownPair::new("anthropic_a", "anthropic_b");
        assert_eq!(p.pick_active(Instant::now()), PickOutcome::Both);
    }

    #[test]
    fn pair_side_other_swaps() {
        assert_eq!(PairSide::Left.other(), PairSide::Right);
        assert_eq!(PairSide::Right.other(), PairSide::Left);
    }

    #[test]
    fn pair_side_as_str_pinned() {
        assert_eq!(PairSide::Left.as_str(), "left");
        assert_eq!(PairSide::Right.as_str(), "right");
    }

    #[test]
    fn record_failure_isolates_to_one_side() {
        let mut p = CooldownPair::new("a", "b");
        let now = Instant::now();
        p.record_failure(PairSide::Left, RetryClass::Transient, now);
        assert!(p.is_cooling(PairSide::Left, now));
        assert!(!p.is_cooling(PairSide::Right, now));
        assert_eq!(p.pick_active(now), PickOutcome::Single(PairSide::Right));
    }

    #[test]
    fn record_failure_both_sides_returns_none_outcome() {
        let mut p = CooldownPair::new("a", "b");
        let now = Instant::now();
        p.record_failure(PairSide::Left, RetryClass::Transient, now);
        p.record_failure(PairSide::Right, RetryClass::Transient, now);
        assert_eq!(p.pick_active(now), PickOutcome::None);
    }

    #[test]
    fn cooldown_expires_after_window() {
        let mut p = CooldownPair::new("a", "b");
        let t0 = Instant::now();
        p.record_failure(PairSide::Left, RetryClass::Transient, t0);
        // Just before expiry: still cooling.
        let t_before = t0 + Duration::from_secs(59);
        assert!(p.is_cooling(PairSide::Left, t_before));
        // Just after expiry: alive again.
        let t_after = t0 + Duration::from_secs(61);
        assert!(!p.is_cooling(PairSide::Left, t_after));
    }

    #[test]
    fn record_success_clears_cooldown() {
        let mut p = CooldownPair::new("a", "b");
        let now = Instant::now();
        p.record_failure(PairSide::Left, RetryClass::Transient, now);
        assert!(p.is_cooling(PairSide::Left, now));
        p.record_success(PairSide::Left);
        assert!(!p.is_cooling(PairSide::Left, now));
    }

    #[test]
    fn cooldown_per_class_matches_pinned_table() {
        assert_eq!(
            cooldown_for_class(RetryClass::Auth),
            Duration::from_secs(3_600)
        );
        assert_eq!(
            cooldown_for_class(RetryClass::SessionCollision),
            Duration::from_secs(5)
        );
        assert_eq!(
            cooldown_for_class(RetryClass::EmptyStdout),
            Duration::from_secs(10)
        );
        assert_eq!(
            cooldown_for_class(RetryClass::Transient),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn auth_failure_cools_for_full_hour() {
        let mut p = CooldownPair::new("a", "b");
        let now = Instant::now();
        p.record_failure(PairSide::Right, RetryClass::Auth, now);
        // 30min later: still cooling.
        let t30 = now + Duration::from_secs(30 * 60);
        assert!(p.is_cooling(PairSide::Right, t30));
    }

    #[test]
    fn provider_for_round_trips_ids() {
        let p = CooldownPair::new("anthropic_a", "anthropic_b");
        assert_eq!(p.provider_for(PairSide::Left), "anthropic_a");
        assert_eq!(p.provider_for(PairSide::Right), "anthropic_b");
    }
}
