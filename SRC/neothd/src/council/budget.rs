//! BudgetToken — Pick #8 F6 fractal rule (Session 14 Pick #19).
//!
//! Hard cap on LLM calls a single user message can trigger, shared
//! across the ENTIRE council recursion tree. Without a shared cap an
//! operator-misconfigured depth-3 council (`hemisphere_council_depth =
//! 3`) would fire 3⁴ = 81 leaf calls — that's a real bill on metered
//! providers. F6 binds the council to a single shared atomic counter
//! that every leaf must `charge()` against before invoking its
//! provider; the first leaf to find the counter exhausted is returned
//! as a synthetic skipped-response (same shape as a timeout) instead
//! of being dispatched.
//!
//! ## Wire shape
//!
//! ```ignore
//! use neothd::council::budget::BudgetToken;
//!
//! let budget = BudgetToken::new(15);                     // operator cap
//! match budget.charge() {
//!     Ok(used) => { /* fire LLM call; `used` is the 1-indexed leaf */ },
//!     Err(_)   => { /* synthesise skipped HemisphereResponse */ },
//! }
//! ```
//!
//! ## Why `Arc<AtomicU32>`
//!
//! The council orchestrator fires its hemispheres via
//! `FuturesUnordered` — three concurrent tasks owning the same budget.
//! A `&mut BudgetToken` cannot cross those task boundaries (each
//! future would need exclusive access). `Arc<AtomicU32>` is cheap to
//! clone, lock-free under contention, and lets every concurrent task
//! call `.charge()` without synchronisation primitives. Even an
//! adapter that overrides `ask_with_depth_budget` to recurse into
//! another `run_debate_with_depth_budget` can `.clone()` the same
//! token and the shared counter keeps tracking across the recursion.
//!
//! ## Out of scope (deferred)
//!
//! - WAL emission of `COUNCIL_BUDGET_EXHAUSTED` events — the error
//!   string surfaces in `HemisphereResponse::error` which the existing
//!   audit emission already captures.
//! - Per-provider sub-budgets (cap claude_cli at N, OpenAI at M).
//!   Today's cap is total-LLM-calls; per-provider budgets need
//!   provider-id-keyed counters, which fits cleanly as a follow-up.
//! - Daily-USD-cap integration (`CouncilConfig::daily_usd_cap` is
//!   wired in `providers/cost.rs::DailyBudget` separately).

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

/// Shared-counter cap on total LLM calls for ONE user message.
/// Cheap-cloneable: every clone references the same underlying
/// `AtomicU32`, so the cap stays shared no matter how deep the
/// recursion goes.
#[derive(Clone, Debug)]
pub struct BudgetToken {
    used: Arc<AtomicU32>,
    cap: u32,
}

/// Returned by `BudgetToken::charge` when the cap is already exhausted.
/// Carries the cap so callers can log a helpful "ran out at N/M"
/// message without re-reading the token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetExhausted {
    pub cap: u32,
}

impl std::fmt::Display for BudgetExhausted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "budget exhausted: {} LLM calls already charged against cap of {}",
            self.cap, self.cap,
        )
    }
}

impl std::error::Error for BudgetExhausted {}

impl BudgetToken {
    /// Construct a new token with the given cap. A cap of `0` means
    /// "no LLM calls allowed" — every `charge()` returns
    /// [`BudgetExhausted`] immediately.
    pub fn new(cap: u32) -> Self {
        Self {
            used: Arc::new(AtomicU32::new(0)),
            cap,
        }
    }

    /// Construct a token from an operator's [`CouncilConfig`].
    /// Convenience for production call sites that already hold a
    /// `FreedomConfig`.
    pub fn from_council(council: &crate::config::inference::CouncilConfig) -> Self {
        Self::new(council.effective_max_calls())
    }

    /// Reserve one LLM call against the cap. Returns the 1-indexed
    /// position this call took (so a cap-of-15 token's 15th successful
    /// `charge` returns `Ok(15)` and the 16th returns
    /// `Err(BudgetExhausted)`). Lock-free: a single relaxed
    /// `fetch_add`.
    ///
    /// On exhaustion the internal counter is NOT decremented — the
    /// over-budget read still cost an atomic op but the token stays
    /// in the exhausted state forever after. That is the contract:
    /// once a council pass has hit the cap, every subsequent
    /// `charge` for the same user-message must also fail so the
    /// caller doesn't accidentally race past the limit.
    pub fn charge(&self) -> Result<u32, BudgetExhausted> {
        let prior = self.used.fetch_add(1, Ordering::SeqCst);
        let used = prior.saturating_add(1);
        if used > self.cap {
            return Err(BudgetExhausted { cap: self.cap });
        }
        Ok(used)
    }

    /// Number of charges that have succeeded so far. Reads the atomic
    /// counter once; the value may be stale by the time the caller
    /// uses it (concurrent `charge` calls can race past), but the
    /// monotonicity guarantee holds — `used()` never decreases.
    pub fn used(&self) -> u32 {
        self.used.load(Ordering::SeqCst).min(self.cap)
    }

    /// Hard cap value supplied at construction. Immutable.
    pub fn cap(&self) -> u32 {
        self.cap
    }

    /// Headroom remaining. May be `0` while the next `charge` is still
    /// in flight on another task.
    pub fn remaining(&self) -> u32 {
        self.cap.saturating_sub(self.used())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charge_sequence_returns_1_indexed_positions() {
        let b = BudgetToken::new(3);
        assert_eq!(b.charge().unwrap(), 1);
        assert_eq!(b.charge().unwrap(), 2);
        assert_eq!(b.charge().unwrap(), 3);
    }

    #[test]
    fn charge_past_cap_returns_exhausted() {
        let b = BudgetToken::new(2);
        b.charge().unwrap();
        b.charge().unwrap();
        let err = b.charge().unwrap_err();
        assert_eq!(err.cap, 2);
    }

    #[test]
    fn zero_cap_is_immediately_exhausted() {
        let b = BudgetToken::new(0);
        assert!(b.charge().is_err());
    }

    #[test]
    fn used_is_saturating_at_cap() {
        // A flurry of over-budget charges must not show `used > cap`
        // to callers — the user-facing "x of y charged" surface stays
        // sane even when concurrent tasks race past the cap.
        let b = BudgetToken::new(2);
        let _ = b.charge();
        let _ = b.charge();
        let _ = b.charge();
        let _ = b.charge();
        assert_eq!(b.used(), 2, "used must saturate at cap");
    }

    #[test]
    fn clone_shares_counter() {
        let b = BudgetToken::new(3);
        let b2 = b.clone();
        assert_eq!(b.charge().unwrap(), 1);
        assert_eq!(b2.charge().unwrap(), 2);
        assert_eq!(b.charge().unwrap(), 3);
        assert!(b2.charge().is_err());
    }

    #[test]
    fn remaining_decrements_with_charges() {
        let b = BudgetToken::new(3);
        assert_eq!(b.remaining(), 3);
        b.charge().unwrap();
        assert_eq!(b.remaining(), 2);
        b.charge().unwrap();
        assert_eq!(b.remaining(), 1);
        b.charge().unwrap();
        assert_eq!(b.remaining(), 0);
        let _ = b.charge();
        assert_eq!(b.remaining(), 0);
    }

    #[test]
    fn from_council_uses_effective_max_calls() {
        use crate::config::inference::CouncilConfig;
        let cfg = CouncilConfig {
            max_calls_per_user_message: Some(7),
            ..Default::default()
        };
        let b = BudgetToken::from_council(&cfg);
        assert_eq!(b.cap(), 7);
    }

    #[test]
    fn from_council_default_matches_const() {
        use crate::config::inference::{CouncilConfig, DEFAULT_MAX_CALLS_PER_USER_MESSAGE};
        let cfg = CouncilConfig::default();
        let b = BudgetToken::from_council(&cfg);
        assert_eq!(b.cap(), DEFAULT_MAX_CALLS_PER_USER_MESSAGE);
    }

    #[test]
    fn budget_exhausted_display_includes_cap() {
        let err = BudgetExhausted { cap: 15 };
        let msg = err.to_string();
        assert!(msg.contains("15"), "got: {msg}");
        assert!(msg.contains("exhausted"), "got: {msg}");
    }

    #[tokio::test]
    async fn concurrent_charges_never_exceed_cap() {
        // Spawn 50 concurrent charge attempts against a cap of 10 —
        // exactly 10 must succeed, the remaining 40 must see
        // BudgetExhausted. Lock-free counter must not over-grant.
        let b = BudgetToken::new(10);
        let mut tasks = Vec::with_capacity(50);
        for _ in 0..50 {
            let b = b.clone();
            tasks.push(tokio::spawn(async move { b.charge().is_ok() }));
        }
        let mut ok_count = 0usize;
        for t in tasks {
            if t.await.unwrap() {
                ok_count += 1;
            }
        }
        assert_eq!(ok_count, 10, "exactly cap-many charges must succeed");
        assert_eq!(b.used(), 10);
    }
}
