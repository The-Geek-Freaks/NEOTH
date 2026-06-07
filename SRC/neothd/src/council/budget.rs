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

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use serde::{Deserialize, Serialize};

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
/// Carries both the calls actually charged and the cap so callers can
/// log a truthful "ran out at N/M" message without re-reading the token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetExhausted {
    /// LLM calls actually charged against the cap at the point of
    /// exhaustion (saturated at `cap` — the over-budget attempt that
    /// produced this error is itself NOT counted as charged). Populated
    /// from [`BudgetToken::used`] rather than reusing `cap` so the
    /// Display message reports a real count, not a duplicated cap.
    pub used: u32,
    pub cap: u32,
}

impl std::fmt::Display for BudgetExhausted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "budget exhausted: {} LLM calls already charged against cap of {}",
            self.used, self.cap,
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
            // Report the saturated successful-charge count (== cap once
            // exhausted, 0 for a cap of 0), NOT this over-budget attempt's
            // 1-indexed position, so the message reads "N of M charged".
            return Err(BudgetExhausted {
                used: self.used(),
                cap: self.cap,
            });
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

// ── KF-08 — persisted council-budget meter (backend half) ─────────────────

/// Persisted council-budget posture for `neoth council budget`. Written
/// once per user-message debate by the chat-layer wrapper
/// (`run_council_debate`) — NOT by the orchestrator hot path — and read
/// by the CLI. Distinct from the in-process [`BudgetToken`] (per-debate +
/// ephemeral): this is the last-known runtime state surviving across CLI
/// invocations + daemon restarts. A scratch file, not the WAL: it's a
/// live gauge, not an audit record (every charge already surfaces in the
/// council audit frames).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CouncilBudgetSnapshot {
    /// The shared per-message cap in force at the last debate.
    pub cap: u32,
    /// LLM calls the last debate actually consumed.
    pub used_last_msg: u32,
    /// True when the last debate hit the cap (`used >= cap`, cap > 0) —
    /// at least one leaf was denied + synthesised as skipped.
    pub exhausted_last_msg: bool,
    /// Lifetime count of debates that hit the cap. A climbing value is
    /// the operator signal that the cap is too low for their topology.
    pub exhaustions_rolling: u64,
    /// Unix seconds the snapshot was last written.
    pub updated_ts_unix: i64,
}

/// Path to the council-budget scratch file inside `home`.
pub fn budget_snapshot_path(home: &Path) -> PathBuf {
    home.join("council_budget.json")
}

/// Atomic `.tmp` + rename write of the budget snapshot (Windows-safe:
/// remove-then-rename).
pub fn save_budget_snapshot(home: &Path, snap: &CouncilBudgetSnapshot) -> std::io::Result<()> {
    let path = budget_snapshot_path(home);
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_vec_pretty(snap).map_err(std::io::Error::other)?;
    std::fs::write(&tmp, json)?;
    if path.exists() {
        let _ = std::fs::remove_file(&path);
    }
    std::fs::rename(&tmp, &path)
}

/// Load the budget snapshot. `None` for missing / zero-length / malformed
/// (the CLI then renders a config-only readout).
pub fn load_budget_snapshot(home: &Path) -> Option<CouncilBudgetSnapshot> {
    let body = std::fs::read_to_string(budget_snapshot_path(home)).ok()?;
    if body.trim().is_empty() {
        return None;
    }
    serde_json::from_str(&body).ok()
}

/// Best-effort: fold one completed debate's `(used, cap)` into the
/// persisted snapshot (load → update last-msg fields + bump the rolling
/// exhaustion counter when the cap was hit → save). Never fails the
/// debate — an I/O error logs `warn!` and drops the update.
pub fn record_budget_outcome(home: &Path, used: u32, cap: u32, now_unix: i64) {
    let mut snap = load_budget_snapshot(home).unwrap_or_default();
    let exhausted = cap > 0 && used >= cap;
    snap.cap = cap;
    snap.used_last_msg = used;
    snap.exhausted_last_msg = exhausted;
    if exhausted {
        snap.exhaustions_rolling = snap.exhaustions_rolling.saturating_add(1);
    }
    snap.updated_ts_unix = now_unix;
    if let Err(e) = save_budget_snapshot(home, &snap) {
        tracing::warn!(error = %e, "council budget snapshot write failed (non-fatal)");
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
        let err = BudgetExhausted { used: 15, cap: 15 };
        let msg = err.to_string();
        assert!(msg.contains("15"), "got: {msg}");
        assert!(msg.contains("exhausted"), "got: {msg}");
    }

    #[test]
    fn budget_exhausted_reports_used_and_cap_from_charge() {
        // COR-14: the error populated by an over-budget `charge` must
        // report the calls actually charged (== cap) AND the cap, not a
        // duplicated cap. Cap of 20 → "20 LLM calls charged against cap
        // of 20".
        let b = BudgetToken::new(20);
        for _ in 0..20 {
            b.charge().unwrap();
        }
        let err = b.charge().unwrap_err();
        assert_eq!(err.used, 20, "used must report the cap-many charges");
        assert_eq!(err.cap, 20);
        let msg = err.to_string();
        assert!(
            msg.contains("20 LLM calls already charged against cap of 20"),
            "got: {msg}"
        );
    }

    #[test]
    fn budget_exhausted_zero_cap_reports_zero_used() {
        // A cap of 0 grants nothing — the error must say "0 ... cap of 0",
        // not reuse the cap for the used count.
        let b = BudgetToken::new(0);
        let err = b.charge().unwrap_err();
        assert_eq!(err.used, 0);
        assert_eq!(err.cap, 0);
        assert!(
            err.to_string()
                .contains("0 LLM calls already charged against cap of 0"),
            "got: {err}"
        );
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

    // ── KF-08 budget snapshot ─────────────────────────────────────────

    #[test]
    fn budget_snapshot_round_trips_through_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_budget_snapshot(dir.path()).is_none());
        let snap = CouncilBudgetSnapshot {
            cap: 15,
            used_last_msg: 9,
            exhausted_last_msg: false,
            exhaustions_rolling: 3,
            updated_ts_unix: 1_700_000_000,
        };
        save_budget_snapshot(dir.path(), &snap).unwrap();
        assert_eq!(load_budget_snapshot(dir.path()).unwrap(), snap);
        // No .tmp leak after the atomic rename.
        assert!(!dir.path().join("council_budget.json.tmp").exists());
    }

    #[test]
    fn record_budget_outcome_marks_exhausted_and_increments_rolling() {
        let dir = tempfile::tempdir().unwrap();
        // First debate hits the cap → exhausted + rolling = 1.
        record_budget_outcome(dir.path(), 15, 15, 1000);
        let s = load_budget_snapshot(dir.path()).unwrap();
        assert!(s.exhausted_last_msg);
        assert_eq!(s.exhaustions_rolling, 1);
        assert_eq!(s.used_last_msg, 15);
        assert_eq!(s.cap, 15);

        // Second debate also hits → rolling = 2.
        record_budget_outcome(dir.path(), 15, 15, 1001);
        assert_eq!(
            load_budget_snapshot(dir.path())
                .unwrap()
                .exhaustions_rolling,
            2
        );

        // A debate under cap → not exhausted, rolling unchanged, last-msg
        // fields updated.
        record_budget_outcome(dir.path(), 3, 15, 1002);
        let s = load_budget_snapshot(dir.path()).unwrap();
        assert!(!s.exhausted_last_msg);
        assert_eq!(s.exhaustions_rolling, 2);
        assert_eq!(s.used_last_msg, 3);
        assert_eq!(s.updated_ts_unix, 1002);
    }

    #[test]
    fn record_budget_outcome_zero_cap_never_exhausted() {
        let dir = tempfile::tempdir().unwrap();
        record_budget_outcome(dir.path(), 0, 0, 1000);
        let s = load_budget_snapshot(dir.path()).unwrap();
        assert!(
            !s.exhausted_last_msg,
            "cap=0 must not register as exhausted"
        );
        assert_eq!(s.exhaustions_rolling, 0);
    }
}
