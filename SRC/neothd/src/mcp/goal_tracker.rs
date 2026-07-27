//! ADOPT-22 — Goal/Grind persistent nudge tracker.
//!
//! Mirrors the goose `Agent::goal` / `Agent::grind` pattern:
//!
//! - **Goal** — operator sets a desired outcome. When the dispatch loop
//!   would normally finish (no tool calls in latest response), inject one
//!   invisible nudge: "Before finishing, check whether this goal is met."
//!   Without an independent judge, the next clean exit stops the loop. With
//!   the judge enabled, negative post-nudge verdicts keep the bounded loop
//!   working until confirmation or the configured iteration/tool budget.
//!
//! - **Grind** — operator sets a relentless objective. Every clean exit
//!   injects a nudge: "Keep working, the grind goal is not yet done."
//!   The loop only terminates when `max_iterations` is reached.
//!
//! Both nudges are injected as **invisible user messages** — they appear
//! in the conversation context the LLM sees but are not surfaced to the
//! operator's UI (matched to goose's `with_visibility(false, true)` flag).
//! In NEOTH's text-prompt model we mark them with a `<!-- goal-nudge -->`
//! HTML comment so the call site can strip them from operator-facing output
//! without a separate flag.
//!
//! The tracker is pure logic — no async, no I/O. The dispatch loop owns
//! one instance per run.

/// Maximum UTF-8 payload bytes a goal/grind text may occupy before the
/// truncation marker in an injected nudge. Guards against accidental context
/// explosion when the operator sets a multi-kilobyte goal string.
pub const MAX_NUDGE_TEXT_LEN: usize = 256;

/// A goal lifecycle invariant that callers must never bypass with a direct
/// provider fallback. Each variant means the returned text cannot truthfully
/// resolve the exact configured goal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GoalIntegrityError {
    #[error(
        "loop-engine goal hash mismatch: inner dispatch outcome is not bound to the original configured goal"
    )]
    HashMismatch,
    #[error(
        "configured goal cannot be judged completely: maximum {max_bytes} UTF-8 bytes; shorten the goal or disable the independent judge"
    )]
    PromptIncomplete { max_bytes: usize },
    #[error("configured goal became unavailable because every tool dispatch in the round failed")]
    DispatchUnavailable,
}

/// Caller-supplied goal context for one dispatch-loop run.
#[derive(Debug, Clone, Default)]
pub struct GoalContext {
    /// One-shot goal: LLM must verify this is satisfied before finishing.
    /// Maps to goose `Agent::set_goal`.
    pub goal: Option<String>,
    /// Relentless grind goal: LLM keeps working every turn until `max_turns`.
    /// Maps to goose `Agent::set_grind`.
    pub grind: Option<String>,
}

impl GoalContext {
    /// Convenience: neither goal nor grind set.
    pub fn empty() -> Self {
        Self {
            goal: None,
            grind: None,
        }
    }

    /// True when neither field is set (no nudge will ever fire).
    pub fn is_empty(&self) -> bool {
        self.goal.is_none() && self.grind.is_none()
    }
}

/// Per-loop nudge state machine.
pub struct GoalTracker {
    goal: Option<String>,
    goal_hash: Option<String>,
    /// Whether the bounded prompt copy contains the complete original goal.
    /// An incomplete copy may drive nudges, but can never receive a `Met`
    /// verdict for the hash of the full goal.
    goal_prompt_complete: bool,
    grind: Option<String>,
    /// Set to `true` after the legacy one-shot goal nudge fires.
    goal_nudge_fired: bool,
    /// Independent judge confirmation. Kept separate from nudge state so the
    /// post-nudge response remains judge eligible.
    goal_met: bool,
}

impl GoalTracker {
    /// Create a tracker from a caller-supplied context.
    pub fn new(ctx: GoalContext) -> Self {
        let goal_hash = ctx.goal.as_deref().map(crate::mcp::goal_judge::goal_hash);
        let goal_prompt_complete = ctx
            .goal
            .as_ref()
            .is_some_and(|goal| goal.len() <= MAX_NUDGE_TEXT_LEN);
        Self {
            goal: ctx.goal.map(|s| truncate(s, MAX_NUDGE_TEXT_LEN)),
            goal_hash,
            goal_prompt_complete,
            grind: ctx.grind.map(|s| truncate(s, MAX_NUDGE_TEXT_LEN)),
            goal_nudge_fired: false,
            goal_met: false,
        }
    }

    /// No-op tracker when no goal context is provided.
    pub fn none() -> Self {
        Self::new(GoalContext::empty())
    }

    /// Called when the dispatch loop has a clean exit (current LLM response
    /// contained no tool calls). Returns the nudge string to append to the
    /// accumulated prompt, or `None` if the loop should genuinely stop.
    ///
    /// Logic mirrors goose agent.rs:2254-2289:
    ///
    /// 1. If `goal` is set and the nudge hasn't fired yet → fire the goal
    ///    nudge once, mark it fired, return `Some(nudge)`.
    /// 2. If `grind` is set → always return `Some(nudge)` (loop never
    ///    self-terminates while grind is active; `max_turns` is the ceiling).
    /// 3. Otherwise → return `None` (stop the loop).
    pub fn on_clean_exit(&mut self) -> Option<String> {
        if let Some(ref goal) = self.goal
            && !self.goal_met
            && !self.goal_nudge_fired
        {
            self.goal_nudge_fired = true;
            return Some(goal_nudge(goal));
        }
        if let Some(ref grind) = self.grind {
            return Some(grind_nudge(grind));
        }
        None
    }

    /// A negative independent judgement is stricter than the legacy one-shot
    /// path: keep the bounded goal active until a later judge confirms it or
    /// the dispatch budget terminates the run.
    pub fn on_judged_not_met(&mut self) -> Option<String> {
        if self.goal_met {
            return None;
        }
        let nudge = goal_nudge(self.goal.as_deref()?);
        self.goal_nudge_fired = true;
        Some(nudge)
    }

    /// True when the tracker has any active goal or grind text.
    pub fn is_active(&self) -> bool {
        self.goal.is_some() || self.grind.is_some()
    }

    /// HERMES-04 — return the bounded goal while it has not been independently
    /// confirmed. The first post-nudge response therefore remains judge
    /// eligible.
    pub fn active_goal(&self) -> Option<&str> {
        if !self.goal_met && self.goal_prompt_complete {
            self.goal.as_deref()
        } else {
            None
        }
    }

    /// True only when the judge prompt contains the complete original goal.
    /// Judge-enabled callers reject an incomplete prompt before provider
    /// dispatch; judge-disabled callers retain the bounded legacy one-shot
    /// nudge without accepting a verdict for a truncated prefix.
    pub fn goal_prompt_complete(&self) -> bool {
        self.goal_prompt_complete
    }

    /// Return the configured goal independently of whether its one-shot nudge
    /// has already fired. Budget-exhaustion audit paths use this to retain the
    /// terminal goal state after judge eligibility has ended.
    pub fn configured_goal(&self) -> Option<&str> {
        self.goal.as_deref()
    }

    /// Hash of the original, untruncated operator goal. Every lifecycle WAL
    /// outcome uses this value even though provider prompts receive a bounded
    /// copy.
    pub fn configured_goal_hash(&self) -> Option<&str> {
        self.goal_hash.as_deref()
    }

    /// HERMES-04 — mark the goal as already met so `on_clean_exit` skips the
    /// nudge on the next call. Call this when the judge confirms goal-met so the
    /// loop exits immediately without injecting a spurious nudge.
    pub fn mark_goal_met(&mut self) {
        if !self.goal_prompt_complete {
            return;
        }
        self.goal_nudge_fired = true;
        self.goal_met = true;
    }

    /// Clear both goal and grind (operator `/goal off` / `/grind off` equivalent).
    pub fn clear(&mut self) {
        self.goal = None;
        self.goal_hash = None;
        self.goal_prompt_complete = false;
        self.grind = None;
        self.goal_nudge_fired = false;
        self.goal_met = false;
    }
}

// ── nudge text builders ──────────────────────────────────────────────────────

/// The invisible goal-check nudge injected once before a clean exit.
/// The `<!-- goal-nudge -->` marker lets callers identify and strip it from
/// operator-facing output if needed.
fn goal_nudge(goal: &str) -> String {
    format!(
        "<!-- goal-nudge -->Before finishing, check whether the following goal has been \
         fully met:\n\n**Goal:** {goal}\n\nIf not, continue working toward it."
    )
}

/// The invisible grind nudge injected every turn while a grind is active.
fn grind_nudge(grind: &str) -> String {
    format!(
        "<!-- goal-nudge -->Keep working. The grind goal is not yet complete:\n\n\
         **Goal:** {grind}\n\nContinue until it is fully done."
    )
}

/// Truncate `s` to at most `max` bytes (on a char boundary) and append
/// `…` if truncation occurred.
fn truncate(s: String, max: usize) -> String {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

// ── unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ---- GoalContext helpers ------------------------------------------------

    #[test]
    fn goal_context_empty_when_both_none() {
        assert!(GoalContext::empty().is_empty());
        assert!(
            GoalContext {
                goal: None,
                grind: None
            }
            .is_empty()
        );
    }

    #[test]
    fn goal_context_not_empty_when_goal_set() {
        let ctx = GoalContext {
            goal: Some("finish".into()),
            grind: None,
        };
        assert!(!ctx.is_empty());
    }

    #[test]
    fn goal_context_not_empty_when_grind_set() {
        let ctx = GoalContext {
            goal: None,
            grind: Some("grind".into()),
        };
        assert!(!ctx.is_empty());
    }

    // ---- no goal/grind → stop immediately ----------------------------------

    #[test]
    fn no_goal_no_grind_stops_immediately() {
        let mut t = GoalTracker::none();
        assert!(t.on_clean_exit().is_none());
        assert!(t.on_clean_exit().is_none());
    }

    // ---- goal: fires once, then stops --------------------------------------

    #[test]
    fn goal_nudge_fires_exactly_once() {
        let mut t = GoalTracker::new(GoalContext {
            goal: Some("finish the report".into()),
            grind: None,
        });
        let first = t.on_clean_exit();
        assert!(first.is_some(), "goal nudge must fire on first clean exit");
        let text = first.unwrap();
        assert!(
            text.contains("finish the report"),
            "nudge must include goal text"
        );
        assert!(
            text.contains("<!-- goal-nudge -->"),
            "must have invisible marker"
        );

        let second = t.on_clean_exit();
        assert!(
            second.is_none(),
            "after goal nudge fired, next clean exit must stop the loop"
        );
        assert!(
            t.active_goal().is_some(),
            "the post-nudge response must remain independently judge eligible"
        );
        assert_eq!(
            t.configured_goal(),
            Some("finish the report"),
            "terminal budget audit must retain the configured goal"
        );
    }

    #[test]
    fn negative_judgement_keeps_goal_active_until_confirmed() {
        let mut t = GoalTracker::new(GoalContext {
            goal: Some("finish the report".into()),
            grind: None,
        });

        assert!(t.on_judged_not_met().is_some());
        assert!(t.on_judged_not_met().is_some());
        assert!(t.active_goal().is_some());

        t.mark_goal_met();
        assert!(t.active_goal().is_none());
        assert!(t.on_judged_not_met().is_none());
        assert!(t.on_clean_exit().is_none());
    }

    #[test]
    fn goal_nudge_only_fires_on_clean_exit_not_mid_loop() {
        // `on_clean_exit` is only called when no tool calls were emitted.
        // A mid-loop call (simulated by not calling it) must never fire.
        // Verified implicitly: tracker is constructed but `on_clean_exit`
        // is NOT called — goal_nudge_fired stays false, goal stays set.
        let t = GoalTracker::new(GoalContext {
            goal: Some("check later".into()),
            grind: None,
        });
        assert!(!t.goal_nudge_fired);
        assert!(t.is_active());
    }

    // ---- grind: fires every turn until max_turns ---------------------------

    #[test]
    fn grind_nudge_fires_every_clean_exit() {
        let mut t = GoalTracker::new(GoalContext {
            goal: None,
            grind: Some("build everything".into()),
        });
        for i in 0..5 {
            let nudge = t.on_clean_exit();
            assert!(nudge.is_some(), "grind nudge must fire on turn {i}");
            let text = nudge.unwrap();
            assert!(
                text.contains("build everything"),
                "nudge must include grind text at turn {i}"
            );
            assert!(
                text.contains("Keep working"),
                "grind nudge must say keep working"
            );
        }
    }

    // ---- goal fires, then grind takes over ---------------------------------

    #[test]
    fn goal_fires_first_then_grind_takes_over() {
        let mut t = GoalTracker::new(GoalContext {
            goal: Some("check this".into()),
            grind: Some("keep grinding".into()),
        });
        // First clean exit: goal nudge fires.
        let first = t.on_clean_exit().unwrap();
        assert!(first.contains("check this"), "first nudge is goal: {first}");

        // Subsequent clean exits: grind takes over.
        for i in 0..3 {
            let nudge = t.on_clean_exit().unwrap();
            assert!(
                nudge.contains("keep grinding"),
                "turn {i} must be grind nudge"
            );
        }
    }

    // ---- clear resets state ------------------------------------------------

    #[test]
    fn clear_stops_all_nudges() {
        let mut t = GoalTracker::new(GoalContext {
            goal: Some("goal".into()),
            grind: Some("grind".into()),
        });
        t.clear();
        assert!(t.on_clean_exit().is_none());
        assert!(!t.is_active());
    }

    // ---- truncation --------------------------------------------------------

    #[test]
    fn long_goal_text_is_truncated_in_nudge() {
        let long = "x".repeat(MAX_NUDGE_TEXT_LEN + 100);
        let expected_hash = crate::mcp::goal_judge::goal_hash(&long);
        let ctx = GoalContext {
            goal: Some(long.clone()),
            grind: None,
        };
        let mut t = GoalTracker::new(ctx);
        assert_eq!(
            t.configured_goal_hash(),
            Some(expected_hash.as_str()),
            "audit identity must bind the original goal, not its bounded prompt copy"
        );
        assert!(!t.goal_prompt_complete());
        assert!(
            t.active_goal().is_none(),
            "a truncated goal must never reach the independent judge"
        );
        t.mark_goal_met();
        assert!(
            !t.goal_met,
            "a truncated prefix cannot mark the complete goal as met"
        );
        assert_ne!(t.configured_goal(), Some(long.as_str()));
        let nudge = t.on_clean_exit().unwrap();
        // Nudge contains the ellipsis from truncation.
        assert!(
            nudge.contains('…'),
            "long goal must be truncated with ellipsis"
        );
    }

    #[test]
    fn short_goal_text_is_not_truncated() {
        let short = "finish the report";
        let ctx = GoalContext {
            goal: Some(short.into()),
            grind: None,
        };
        let mut t = GoalTracker::new(ctx);
        assert!(t.goal_prompt_complete());
        let nudge = t.on_clean_exit().unwrap();
        assert!(nudge.contains(short), "short goal must not be truncated");
        assert!(!nudge.contains('…'), "short goal must not have ellipsis");
    }

    #[test]
    fn oversized_utf8_goal_cannot_be_judged_as_complete() {
        let original = "🧠".repeat(65);
        assert!(original.len() > MAX_NUDGE_TEXT_LEN);
        let expected_hash = crate::mcp::goal_judge::goal_hash(&original);
        let mut tracker = GoalTracker::new(GoalContext {
            goal: Some(original),
            grind: None,
        });

        assert_eq!(tracker.configured_goal_hash(), Some(expected_hash.as_str()));
        assert!(!tracker.goal_prompt_complete());
        assert!(tracker.active_goal().is_none());
        assert!(tracker.on_judged_not_met().is_some());
        tracker.mark_goal_met();
        assert!(!tracker.goal_met);
    }

    // ---- truncate helper ---------------------------------------------------

    #[test]
    fn truncate_short_string_unchanged() {
        let s = truncate("hello".into(), 10);
        assert_eq!(s, "hello");
    }

    #[test]
    fn truncate_long_string_gets_ellipsis() {
        let s = truncate("abcdef".into(), 3);
        assert!(s.starts_with("abc"));
        assert!(s.ends_with('…'));
    }

    #[test]
    fn truncate_respects_char_boundary() {
        // "日本語" is 3 chars, each 3 bytes. max=5 → cut before second char.
        let s = truncate("日本語".into(), 5);
        assert!(s.starts_with('日'), "must include first char");
        assert!(s.ends_with('…'), "must have ellipsis");
    }
}
