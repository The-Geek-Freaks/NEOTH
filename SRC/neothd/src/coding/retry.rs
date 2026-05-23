//! Pick #6 Phase 4-pre — `WorkerRetryPolicy`.
//!
//! Ported from smallcode's `governor/early_stop.js` +
//! `bin/governor.js::checkAndEnforceHardFail` (see
//! `PLAN/SMALLCODE_INTEGRATION_PLAN_2026-05-21.md`). Adds the per-
//! task state machine between `InProgress` and `Blocked` that NEOTH
//! lacks today.
//!
//! Today's gap:
//!   - Worker errors / empty outcomes → immediate Blocked
//!   - Operator has no signal whether a one-time fluke or a real
//!     stuck state
//!
//! This module:
//!   - Tracks attempts per task in an `Arc<Mutex<…>>`-friendly
//!     `HashMap<KanbanTaskId, u32>`
//!   - Picks a strategy hint based on attempt count
//!   - The dispatcher injects the hint into the task description
//!     and re-queues to `Backlog` for another go
//!   - At the ceiling (default 3 attempts), the task lands in
//!     `Blocked` with the final strategy hint preserved so the
//!     operator can diagnose
//!
//! Pure-logic surface — no IO, no SQL. The dispatcher calls
//! `record_attempt` + `should_retry` + `pick_strategy` and decides
//! the next state transition.

use std::collections::HashMap;

use crate::coding::types::KanbanTaskId;

/// Default ceiling — three attempts then Blocked.  Smallcode uses 6
/// (4 fail + 6 total in their detector), but they have a more
/// granular hint set; for NEOTH's three coarse strategies, three
/// retries is enough signal without bloating the audit chain.
pub const DEFAULT_MAX_ATTEMPTS: u32 = 3;

/// What the dispatcher tells the worker to do differently on the
/// next attempt. The strings are operator-readable so the audit
/// chain shows what was tried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetryStrategy {
    /// First retry — task split too coarse, ask worker for smaller
    /// scope. Smallcode calls this "split_file".
    SplitFile,
    /// Second retry — worker is over-correcting / oscillating.
    /// Constrain to one error per attempt. Smallcode: "one_error_at_a_time".
    OneErrorAtATime,
    /// Third + final retry — heuristics aren't working, rewrite
    /// the affected section from scratch. Smallcode: "rewrite_section".
    RewriteSection,
}

impl RetryStrategy {
    /// Pick a strategy based on which attempt we're on (1-indexed).
    /// Attempt 1 fails → SplitFile; attempt 2 fails → OneErrorAtATime;
    /// attempt 3 fails → RewriteSection. Past the ceiling the
    /// dispatcher transitions to Blocked instead of asking us.
    pub fn for_attempt(attempt_count: u32) -> Self {
        match attempt_count {
            0 | 1 => RetryStrategy::SplitFile,
            2 => RetryStrategy::OneErrorAtATime,
            _ => RetryStrategy::RewriteSection,
        }
    }

    /// Stable wire form for WAL frames + operator-facing logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            RetryStrategy::SplitFile => "split_file",
            RetryStrategy::OneErrorAtATime => "one_error_at_a_time",
            RetryStrategy::RewriteSection => "rewrite_section",
        }
    }

    /// The hint the dispatcher appends to the task description
    /// before re-queueing. Operator + worker both see it on the
    /// next attempt.
    pub const fn hint(self) -> &'static str {
        match self {
            RetryStrategy::SplitFile => {
                "[retry hint: split this task into smaller files — the previous \
                 attempt's scope was too wide]"
            }
            RetryStrategy::OneErrorAtATime => {
                "[retry hint: focus on one error at a time — the previous \
                 attempt over-corrected]"
            }
            RetryStrategy::RewriteSection => {
                "[retry hint: rewrite the affected section from scratch — \
                 heuristic patches aren't converging]"
            }
        }
    }
}

/// In-memory retry tracker. One per dispatch session — created at
/// `dispatch_session` start, dropped when the loop exits. Lives in
/// the dispatcher's stack frame; not shared across sessions.
#[derive(Debug, Default)]
pub struct WorkerRetryPolicy {
    attempts: HashMap<KanbanTaskId, u32>,
    max_attempts: u32,
}

impl WorkerRetryPolicy {
    pub fn new() -> Self {
        Self {
            attempts: HashMap::new(),
            max_attempts: DEFAULT_MAX_ATTEMPTS,
        }
    }

    /// Override the default ceiling. Operator config flows through
    /// `freedom.yaml::coding.max_worker_retries` in a follow-up
    /// commit.
    pub fn with_max_attempts(mut self, n: u32) -> Self {
        self.max_attempts = n;
        self
    }

    /// Record that a worker attempt just finished (failure or empty
    /// outcome). Returns the new attempt count for the task.
    pub fn record_attempt(&mut self, task: KanbanTaskId) -> u32 {
        let entry = self.attempts.entry(task).or_insert(0);
        *entry += 1;
        *entry
    }

    /// How many times we've tried this task. `0` when never seen.
    pub fn attempts_for(&self, task: KanbanTaskId) -> u32 {
        self.attempts.get(&task).copied().unwrap_or(0)
    }

    /// `true` while we haven't hit the ceiling. The dispatcher
    /// re-queues + injects a hint when true, transitions to Blocked
    /// when false.
    pub fn should_retry(&self, task: KanbanTaskId) -> bool {
        self.attempts_for(task) < self.max_attempts
    }

    /// The strategy hint to inject before the next attempt. Pure
    /// function of the current attempt count.
    pub fn pick_strategy(&self, task: KanbanTaskId) -> RetryStrategy {
        RetryStrategy::for_attempt(self.attempts_for(task))
    }

    /// Reset a task's attempt counter. The dispatcher calls this
    /// when a task lands in Review (the worker succeeded after a
    /// retry); future runs of the same task id start fresh.
    pub fn reset(&mut self, task: KanbanTaskId) {
        self.attempts.remove(&task);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strategy_for_attempt_walks_three_tiers() {
        assert_eq!(RetryStrategy::for_attempt(0), RetryStrategy::SplitFile);
        assert_eq!(RetryStrategy::for_attempt(1), RetryStrategy::SplitFile);
        assert_eq!(
            RetryStrategy::for_attempt(2),
            RetryStrategy::OneErrorAtATime
        );
        assert_eq!(RetryStrategy::for_attempt(3), RetryStrategy::RewriteSection);
        // Past ceiling, the dispatcher transitions to Blocked
        // instead of asking — but the function stays defined for
        // safety (returns the most-aggressive strategy).
        assert_eq!(
            RetryStrategy::for_attempt(99),
            RetryStrategy::RewriteSection
        );
    }

    #[test]
    fn strategy_wire_form_is_stable_snake_case() {
        // Pin wire form — WAL frames + audit logs grep this.
        assert_eq!(RetryStrategy::SplitFile.as_str(), "split_file");
        assert_eq!(
            RetryStrategy::OneErrorAtATime.as_str(),
            "one_error_at_a_time"
        );
        assert_eq!(RetryStrategy::RewriteSection.as_str(), "rewrite_section");
    }

    #[test]
    fn strategy_hint_is_operator_readable() {
        for s in [
            RetryStrategy::SplitFile,
            RetryStrategy::OneErrorAtATime,
            RetryStrategy::RewriteSection,
        ] {
            let h = s.hint();
            assert!(h.starts_with("[retry hint:"));
            assert!(h.ends_with(']'));
        }
    }

    #[test]
    fn policy_default_ceiling_is_three() {
        let p = WorkerRetryPolicy::new();
        assert_eq!(p.max_attempts, 3);
    }

    #[test]
    fn policy_with_max_attempts_overrides_default() {
        let p = WorkerRetryPolicy::new().with_max_attempts(5);
        assert_eq!(p.max_attempts, 5);
    }

    #[test]
    fn record_attempt_increments_per_task() {
        let mut p = WorkerRetryPolicy::new();
        let t = KanbanTaskId(42);
        assert_eq!(p.attempts_for(t), 0);
        assert_eq!(p.record_attempt(t), 1);
        assert_eq!(p.record_attempt(t), 2);
        assert_eq!(p.attempts_for(t), 2);
    }

    #[test]
    fn record_attempt_is_per_task_isolated() {
        // Two tasks must not share counters.
        let mut p = WorkerRetryPolicy::new();
        let a = KanbanTaskId(1);
        let b = KanbanTaskId(2);
        p.record_attempt(a);
        p.record_attempt(a);
        p.record_attempt(b);
        assert_eq!(p.attempts_for(a), 2);
        assert_eq!(p.attempts_for(b), 1);
    }

    #[test]
    fn should_retry_returns_true_below_ceiling() {
        let mut p = WorkerRetryPolicy::new(); // default 3
        let t = KanbanTaskId(1);
        assert!(p.should_retry(t), "fresh task should be retryable");
        p.record_attempt(t); // 1
        assert!(p.should_retry(t));
        p.record_attempt(t); // 2
        assert!(p.should_retry(t));
        p.record_attempt(t); // 3
        assert!(!p.should_retry(t), "at ceiling, no more retries");
    }

    #[test]
    fn pick_strategy_advances_with_attempts() {
        let mut p = WorkerRetryPolicy::new();
        let t = KanbanTaskId(1);
        assert_eq!(p.pick_strategy(t), RetryStrategy::SplitFile);
        p.record_attempt(t);
        assert_eq!(p.pick_strategy(t), RetryStrategy::SplitFile);
        p.record_attempt(t);
        assert_eq!(p.pick_strategy(t), RetryStrategy::OneErrorAtATime);
        p.record_attempt(t);
        assert_eq!(p.pick_strategy(t), RetryStrategy::RewriteSection);
    }

    #[test]
    fn reset_clears_attempt_history() {
        let mut p = WorkerRetryPolicy::new();
        let t = KanbanTaskId(1);
        p.record_attempt(t);
        p.record_attempt(t);
        assert_eq!(p.attempts_for(t), 2);
        p.reset(t);
        assert_eq!(p.attempts_for(t), 0);
        assert!(p.should_retry(t));
    }

    #[test]
    fn reset_unknown_task_is_no_op() {
        let mut p = WorkerRetryPolicy::new();
        p.reset(KanbanTaskId(404)); // never recorded
        // No panic, no allocation surprise.
        assert_eq!(p.attempts_for(KanbanTaskId(404)), 0);
    }

    #[test]
    fn policy_with_zero_max_attempts_never_retries() {
        // Operator override: max_attempts=0 means "first failure
        // → Blocked, no retry budget at all". Pin the boundary.
        let mut p = WorkerRetryPolicy::new().with_max_attempts(0);
        let t = KanbanTaskId(1);
        assert!(!p.should_retry(t));
        p.record_attempt(t);
        assert!(!p.should_retry(t));
    }
}
