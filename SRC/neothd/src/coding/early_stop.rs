//! QU-01 EarlyStopDetector — pure-fn detectors of degenerate worker
//! behaviour, ported from smallcode's `governor/early_stop.js`.
//!
//! Today's gap: every worker failure → silent `Blocked`. The operator
//! sees "task #N blocked" but not WHY — was the worker looping on
//! identical outputs (model wedge), did it surrender to a greeting
//! ("Sorry, I can't help with that"), or did it produce four
//! consecutive empty patches (patch spiral)? Each pathology wants a
//! different recovery (full-rewrite / model-swap / hemisphere-escalation),
//! but the dispatcher needs to know which one fired.
//!
//! ## Scope (Phase 1)
//!
//! Three pure-fn detectors over recent worker outputs + patch results:
//!
//!   - [`is_repetition_loop`] — N most recent worker replies are
//!     byte-identical (or near-identical after whitespace collapse).
//!   - [`is_refusal_or_capability_disclaimer`] — single worker reply is just a
//!     greeting / refusal / clarifying-question fall-back, with no
//!     `<patch>` block + no actual diff content. Bilingual EN/DE.
//!   - [`PatchSpiralTracker`] — counts consecutive failed-or-empty
//!     patch results per task; trips at the configured ceiling.
//!
//! Composition over inheritance: each detector is independent + pure;
//! the dispatcher composes them in its diagnosis path. Each returns
//! the verdict + an operator-readable reason string for the WAL audit
//! frame.
//!
//! ## Scope (Phase 2, deferred)
//!
//! - Cross-worker correlation (left + right both regress in the same
//!   session → likely a prompt/spec issue, not a model issue).
//! - Confidence-decay detector (worker outputs trend toward shorter +
//!   vaguer over N attempts → model is losing context).
//!
//! These need cross-attempt state the dispatcher doesn't yet thread;
//! Phase 1 keeps the substrate simple + pure.

use std::collections::HashMap;

use crate::coding::types::KanbanTaskId;

/// Minimum recent-output count before the repetition-loop detector
/// fires. Below this we don't have enough signal to call it a loop
/// (one duplicate could be honest convergence).
pub const REPETITION_LOOP_MIN_SAMPLES: usize = 3;

/// Default ceiling for [`PatchSpiralTracker`]. Smallcode uses 4
/// (matches the `patch-spiral counter (4 failures → full-rewrite)`
/// rule in the original spec). Below 4 we let the existing
/// [`crate::coding::retry::WorkerRetryPolicy`] handle the strategy
/// rotation; at 4 we declare the spiral + escalate.
pub const DEFAULT_PATCH_SPIRAL_CEILING: u32 = 4;

/// Greeting / refusal / no-work markers. Bilingual EN/DE +
/// case-folded check at match time. Each entry is the *prefix* shape
/// the detector looks for after the output has been trimmed +
/// lowercased — so "Sorry, I can't help…" matches "sorry," etc.
///
/// The list stays short on purpose: false positives are worse than
/// false negatives here. A wrongly-flagged worker output stops the
/// dispatcher cold + asks the operator to intervene; a missed
/// greeting just means one extra retry cycle the retry-policy
/// would have done anyway.
pub const GREETING_REGRESSION_MARKERS: &[&str] = &[
    "sorry, i can't",
    "sorry, i cannot",
    "i can't help with",
    "i cannot help with",
    "i'm not able to",
    "i am not able to",
    "as an ai",
    "i don't have the ability",
    // German
    "entschuldigung, ich kann",
    "es tut mir leid",
    "ich kann dir dabei nicht",
    "als ki kann ich",
    "ich bin nicht in der lage",
    "leider kann ich nicht",
];

/// Returns `true` when the last [`REPETITION_LOOP_MIN_SAMPLES`] or
/// more recent worker outputs are all identical after whitespace
/// normalisation. The detector compares the *tail* so a session
/// that began with productive variety + then wedged still gets
/// caught.
///
/// Whitespace-normalised compare: collapses any run of whitespace
/// to a single space + trims edges. A worker that re-emits the
/// same text with slightly different indentation still trips this
/// (most model wedges are exact-byte but indentation drift happens
/// when the worker re-renders a tool template).
pub fn is_repetition_loop(recent_outputs: &[&str]) -> bool {
    if recent_outputs.len() < REPETITION_LOOP_MIN_SAMPLES {
        return false;
    }
    let tail = &recent_outputs[recent_outputs.len() - REPETITION_LOOP_MIN_SAMPLES..];
    let first = collapse_ws(tail[0]);
    if first.is_empty() {
        // All-empty tail isn't a "loop" per se; the empty-patch
        // detector below catches it.
        return false;
    }
    tail.iter().all(|t| collapse_ws(t) == first)
}

/// Returns `true` when the worker output is just a greeting /
/// refusal / no-work fallback. Heuristic: lowercase + trim, check
/// whether the FIRST 200 chars match any [`GREETING_REGRESSION_MARKERS`]
/// prefix AND the output contains no `<patch>` / `diff` / code-fence
/// markers (so an output that opens with a polite preamble + then
/// delivers real work is NOT flagged).
///
/// The 200-char window keeps the check tight against long replies
/// where a greeting on line 1 is just style, not regression.
pub fn is_refusal_or_capability_disclaimer(output: &str) -> bool {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return false;
    }
    let head_lower = trimmed.chars().take(200).collect::<String>().to_lowercase();
    let matches_greeting = GREETING_REGRESSION_MARKERS
        .iter()
        .any(|m| head_lower.starts_with(m));
    if !matches_greeting {
        return false;
    }
    // Long output with real work somewhere → not a regression.
    let lower_full = trimmed.to_lowercase();
    let has_work = lower_full.contains("<patch>")
        || lower_full.contains("```diff")
        || lower_full.contains("```rust")
        || lower_full.contains("```python")
        || lower_full.contains("```typescript")
        || lower_full.contains("```javascript")
        || lower_full.contains("```ts")
        || lower_full.contains("```js")
        || lower_full.contains("--- a/")
        || lower_full.contains("+++ b/");
    !has_work
}

/// Per-task counter of consecutive failed-or-empty patch results.
/// The dispatcher calls [`PatchSpiralTracker::record`] with each
/// patch outcome; when [`PatchSpiralTracker::is_spiraling`] returns
/// true the dispatcher escalates (full-rewrite / hemisphere swap)
/// instead of running yet another retry-strategy hint.
///
/// Pure in-memory state — the dispatcher owns the tracker for the
/// session's lifetime + drops it on session-close. Cross-restart
/// persistence would force a new SQLite table for marginal value
/// (a fresh daemon boot already wipes mid-flight worker state).
#[derive(Debug, Default, Clone)]
pub struct PatchSpiralTracker {
    consecutive_failures: HashMap<KanbanTaskId, u32>,
    ceiling: u32,
}

impl PatchSpiralTracker {
    /// Construct with the canonical ceiling
    /// ([`DEFAULT_PATCH_SPIRAL_CEILING`]).
    pub fn new() -> Self {
        Self::with_ceiling(DEFAULT_PATCH_SPIRAL_CEILING)
    }

    /// Operator-tunable ceiling. Tests use this to drive the
    /// detector against a tight budget; production callers should
    /// stay on [`DEFAULT_PATCH_SPIRAL_CEILING`].
    pub fn with_ceiling(ceiling: u32) -> Self {
        Self {
            consecutive_failures: HashMap::new(),
            ceiling: ceiling.max(1),
        }
    }

    /// Record the result of one patch attempt. `applied_ok = true`
    /// resets the per-task counter (the spiral broke); `false`
    /// increments it.
    pub fn record(&mut self, task: KanbanTaskId, applied_ok: bool) {
        if applied_ok {
            self.consecutive_failures.remove(&task);
        } else {
            *self.consecutive_failures.entry(task).or_insert(0) += 1;
        }
    }

    /// Returns true once a task has accumulated `ceiling` consecutive
    /// failures.
    pub fn is_spiraling(&self, task: KanbanTaskId) -> bool {
        self.consecutive_failures.get(&task).copied().unwrap_or(0) >= self.ceiling
    }

    /// Read-only access to the current failure count for a task.
    /// Useful for the WAL audit frame so the operator sees the depth
    /// of the spiral, not just the binary verdict.
    pub fn failure_count(&self, task: KanbanTaskId) -> u32 {
        self.consecutive_failures.get(&task).copied().unwrap_or(0)
    }
}

fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── is_repetition_loop ─────────────────────────────────────────

    #[test]
    fn repetition_loop_needs_minimum_samples() {
        let outs = vec!["fix the bug", "fix the bug"];
        // Two identical samples → still below the 3-sample floor.
        assert!(!is_repetition_loop(&outs));
    }

    #[test]
    fn repetition_loop_fires_when_tail_is_identical() {
        let outs = vec!["v1", "v2", "stuck", "stuck", "stuck"];
        // Last 3 are identical → loop.
        assert!(is_repetition_loop(&outs));
    }

    #[test]
    fn repetition_loop_tolerates_whitespace_drift() {
        // Same text, different indentation — the worker is wedged
        // even though byte-equality would miss it.
        let outs = vec!["x = 1\n  y = 2", "x = 1\ny = 2", "x = 1   y = 2"];
        assert!(is_repetition_loop(&outs));
    }

    #[test]
    fn repetition_loop_ignores_productive_variety_in_tail() {
        let outs = vec!["fix one", "fix two", "fix three"];
        // All-different → not a loop.
        assert!(!is_repetition_loop(&outs));
    }

    #[test]
    fn repetition_loop_treats_all_empty_tail_as_non_loop() {
        // Empty-string repeat is technically identical but means
        // "no output", which is the patch-spiral detector's domain.
        let outs = vec!["", "", ""];
        assert!(!is_repetition_loop(&outs));
    }

    // ── is_refusal_or_capability_disclaimer ─────────────────────────────────────

    #[test]
    fn greeting_regression_fires_on_bare_refusal_en() {
        assert!(is_refusal_or_capability_disclaimer(
            "Sorry, I can't help with that request."
        ));
    }

    #[test]
    fn greeting_regression_fires_on_bare_refusal_de() {
        assert!(is_refusal_or_capability_disclaimer(
            "Es tut mir leid, das kann ich nicht."
        ));
    }

    #[test]
    fn greeting_regression_does_not_fire_on_preamble_plus_work() {
        // Polite preamble + actual patch → not a regression.
        let out = "Sorry, I can't be terse — here's the patch:\n\
                   ```diff\n+ let x = 1;\n```";
        assert!(!is_refusal_or_capability_disclaimer(out));
    }

    #[test]
    fn greeting_regression_does_not_fire_on_empty_output() {
        assert!(!is_refusal_or_capability_disclaimer(""));
    }

    #[test]
    fn greeting_regression_ignores_unrelated_preamble() {
        // Output starts with productive content, not a greeting.
        assert!(!is_refusal_or_capability_disclaimer(
            "Looking at the diff, I think the issue is in line 42."
        ));
    }

    #[test]
    fn greeting_regression_respects_200_char_head_window() {
        // Long preamble before the greeting marker → not flagged
        // (it's mid-stream apology, not a regression).
        let preamble = "Working on the implementation now. ".repeat(8);
        let out = format!("{preamble}Sorry, I can't continue.");
        assert!(!is_refusal_or_capability_disclaimer(&out));
    }

    // ── PatchSpiralTracker ─────────────────────────────────────────

    #[test]
    fn patch_spiral_increments_on_failure_resets_on_success() {
        let mut tracker = PatchSpiralTracker::new();
        let task = KanbanTaskId(1);
        tracker.record(task, false);
        tracker.record(task, false);
        assert_eq!(tracker.failure_count(task), 2);
        // Success resets the counter.
        tracker.record(task, true);
        assert_eq!(tracker.failure_count(task), 0);
    }

    #[test]
    fn patch_spiral_trips_at_ceiling() {
        let mut tracker = PatchSpiralTracker::with_ceiling(2);
        let task = KanbanTaskId(7);
        tracker.record(task, false);
        assert!(!tracker.is_spiraling(task));
        tracker.record(task, false);
        assert!(tracker.is_spiraling(task));
    }

    #[test]
    fn patch_spiral_tracks_tasks_independently() {
        let mut tracker = PatchSpiralTracker::with_ceiling(2);
        let a = KanbanTaskId(1);
        let b = KanbanTaskId(2);
        tracker.record(a, false);
        tracker.record(a, false);
        // Only A is spiraling.
        assert!(tracker.is_spiraling(a));
        assert!(!tracker.is_spiraling(b));
    }

    #[test]
    fn patch_spiral_ceiling_floor_prevents_zero() {
        // `with_ceiling(0)` would otherwise mean "spiral immediately
        // on first failure" — clamp to 1 so the tracker has at
        // least one chance to see a failure first.
        let mut tracker = PatchSpiralTracker::with_ceiling(0);
        let task = KanbanTaskId(1);
        assert!(!tracker.is_spiraling(task));
        tracker.record(task, false);
        assert!(tracker.is_spiraling(task));
    }

    #[test]
    fn default_constants_canonical() {
        assert_eq!(REPETITION_LOOP_MIN_SAMPLES, 3);
        assert_eq!(DEFAULT_PATCH_SPIRAL_CEILING, 4);
    }
}
