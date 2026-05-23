//! P-15 — chat-flow inline profile-extraction trigger.
//!
//! The cron-driven profile extraction (P-01 aggregation task) runs
//! every N minutes against the WAL backlog. That's fine for steady-
//! state operation but misses two cases the operator notices:
//!
//!   1. **Fresh first-launch operator** writes 3 prompts in 5
//!      minutes; cron hasn't fired yet so the council has no
//!      profile claims to inject. The operator's first session
//!      feels generic.
//!   2. **Operator just told NEOTH something important** ("from now
//!      on, prefer Rust over Go") and the next prompt 30 seconds
//!      later should already act on it; cron-only means a 4-min
//!      lag where NEOTH ignores the just-stated preference.
//!
//! This module ships the **trigger gate** that the chat dispatch
//! consults BEFORE handing a prompt to the council: returns
//! `ExtractDecision::RunInline` when one of three operator-visible
//! signals fires, else `ExtractDecision::DeferToCron`.
//!
//! The three inline-fire signals (priority order, first hit wins):
//!   - **Operator-prompted preference statement** — explicit
//!     "remember that ..." / "from now on ..." / "I prefer ..."
//!     phrases at the start of the prompt.
//!   - **Cold-start grace window** — first N minutes since daemon
//!     start, run extraction inline on every prompt so the operator
//!     never sees the no-profile-yet window.
//!   - **Stale-cron window** — last cron-driven extraction was >
//!     threshold ago; one inline run catches up.

use serde::{Deserialize, Serialize};

/// Cold-start window during which every prompt triggers inline
/// extraction. Default 5 min — fits the "first 3-prompt session"
/// shape. Operator tunes via `freedom.yaml::profile.inline_extract
/// .cold_start_window_secs`.
pub const DEFAULT_COLD_START_WINDOW_SECS: i64 = 5 * 60;

/// Stale-cron threshold after which one inline run catches up.
/// Default 30 min — operators who said something 5 min ago expect
/// the next prompt to reflect it, even if cron is on a 60-min
/// cadence.
pub const DEFAULT_STALE_CRON_THRESHOLD_SECS: i64 = 30 * 60;

/// Lowercase prefixes that mark an explicit preference statement.
/// Matched at the START of the operator's prompt (after leading
/// whitespace). Drift-guarded by test.
pub const PREFERENCE_PREFIXES: &[&str] = &[
    "remember that ",
    "remember to ",
    "from now on ",
    "i prefer ",
    "i'd prefer ",
    "i would prefer ",
    "please remember ",
    "keep in mind that ",
];

/// Operator-tunable trigger thresholds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InlineExtractPolicy {
    pub cold_start_window_secs: i64,
    pub stale_cron_threshold_secs: i64,
    /// True ⇔ the explicit-preference-prefix gate is on. Operator
    /// turns off via `freedom.yaml` if they prefer the cron-only
    /// rhythm (some operators want every claim to go through the
    /// human-readable cron audit log).
    pub honour_preference_phrases: bool,
}

impl Default for InlineExtractPolicy {
    fn default() -> Self {
        Self {
            cold_start_window_secs: DEFAULT_COLD_START_WINDOW_SECS,
            stale_cron_threshold_secs: DEFAULT_STALE_CRON_THRESHOLD_SECS,
            honour_preference_phrases: true,
        }
    }
}

/// Trigger decision. Operator-visible `reason` so the WAL trace
/// shows WHICH signal fired (helpful for tuning the policy).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExtractDecision {
    RunInline { reason: &'static str },
    DeferToCron { reason: &'static str },
}

impl ExtractDecision {
    pub fn is_inline(&self) -> bool {
        matches!(self, Self::RunInline { .. })
    }
    pub fn reason(&self) -> &'static str {
        match self {
            Self::RunInline { reason } | Self::DeferToCron { reason } => reason,
        }
    }
}

/// Decide whether to run profile extraction inline for `prompt`.
/// All time inputs are unix-epoch seconds; caller resolves clock
/// state from the WAL replay + the daemon's boot time.
///
/// Priority (first match wins):
///   1. Preference phrase at prompt start (when policy enables it).
///   2. Within cold-start window from daemon boot.
///   3. Stale-cron window elapsed since last extraction.
///   4. Otherwise defer to cron.
pub fn should_extract_inline(
    prompt: &str,
    now_unix: i64,
    daemon_started_at_unix: i64,
    last_extraction_at_unix: Option<i64>,
    policy: &InlineExtractPolicy,
) -> ExtractDecision {
    if policy.honour_preference_phrases && prompt_starts_with_preference(prompt) {
        return ExtractDecision::RunInline {
            reason: "explicit preference phrase at prompt start",
        };
    }
    if now_unix - daemon_started_at_unix < policy.cold_start_window_secs {
        return ExtractDecision::RunInline {
            reason: "within cold-start window from daemon boot",
        };
    }
    if let Some(last) = last_extraction_at_unix {
        if now_unix - last >= policy.stale_cron_threshold_secs {
            return ExtractDecision::RunInline {
                reason: "stale-cron window elapsed since last extraction",
            };
        }
    } else {
        // Never extracted before + outside cold-start → still run
        // once. Operator with a daemon that's been up for hours
        // but never had a chat shouldn't be silent forever.
        return ExtractDecision::RunInline {
            reason: "no prior extraction recorded",
        };
    }
    ExtractDecision::DeferToCron {
        reason: "no inline-fire signal; cron handles it",
    }
}

/// True ⇔ `prompt` (after leading-whitespace trim) starts with one
/// of the recognised preference-statement prefixes. Case-
/// insensitive match.
fn prompt_starts_with_preference(prompt: &str) -> bool {
    let lower = prompt.trim_start().to_ascii_lowercase();
    PREFERENCE_PREFIXES.iter().any(|p| lower.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_policy() -> InlineExtractPolicy {
        InlineExtractPolicy::default()
    }

    // ── Policy defaults ─────────────────────────────────────────

    #[test]
    fn default_policy_pinned() {
        let p = base_policy();
        assert_eq!(p.cold_start_window_secs, 5 * 60);
        assert_eq!(p.stale_cron_threshold_secs, 30 * 60);
        assert!(p.honour_preference_phrases);
    }

    #[test]
    fn preference_prefixes_pinned() {
        // Drift guard — operator-visible prompts. Removing one
        // would silently change which prompts trigger inline
        // extraction.
        for required in [
            "remember that ",
            "from now on ",
            "i prefer ",
            "please remember ",
        ] {
            assert!(
                PREFERENCE_PREFIXES.contains(&required),
                "missing prefix: {required}"
            );
        }
    }

    // ── preference-phrase trigger ───────────────────────────────

    #[test]
    fn explicit_preference_fires_inline() {
        let d = should_extract_inline(
            "Remember that I prefer Rust over Go.",
            10_000,
            0,           // daemon-started long ago
            Some(9_000), // recent extraction
            &base_policy(),
        );
        assert!(d.is_inline());
        assert!(d.reason().contains("preference"));
    }

    #[test]
    fn preference_phrase_is_case_insensitive() {
        let d = should_extract_inline(
            "REMEMBER THAT I prefer Rust.",
            10_000,
            0,
            Some(9_000),
            &base_policy(),
        );
        assert!(d.is_inline());
    }

    #[test]
    fn preference_phrase_honours_leading_whitespace() {
        let d = should_extract_inline(
            "  remember that I prefer terse answers.",
            10_000,
            0,
            Some(9_000),
            &base_policy(),
        );
        assert!(d.is_inline());
    }

    #[test]
    fn preference_phrase_only_at_prompt_start() {
        // "remember that" appearing mid-sentence shouldn't fire.
        let d = should_extract_inline(
            "Just a reminder: please remember that the meeting is at 3.",
            10_000,
            0,
            Some(9_000),
            &base_policy(),
        );
        // Must defer (no inline-fire signal applies).
        assert!(!d.is_inline());
    }

    #[test]
    fn preference_disabled_by_policy_falls_through() {
        let mut p = base_policy();
        p.honour_preference_phrases = false;
        // Long-running daemon with recent extraction → defer.
        let d = should_extract_inline("Remember that I prefer X.", 10_000, 0, Some(9_000), &p);
        assert!(!d.is_inline());
    }

    // ── cold-start window ───────────────────────────────────────

    #[test]
    fn cold_start_window_fires_inline_for_fresh_daemon() {
        let now = 60; // 1 min after boot
        let d = should_extract_inline("what is 2+2", now, 0, Some(0), &base_policy());
        assert!(d.is_inline());
        assert!(d.reason().contains("cold-start"));
    }

    #[test]
    fn cold_start_window_expires_after_threshold() {
        let now = 10 * 60; // 10 min after boot (cold-start = 5min)
        let d = should_extract_inline("hi", now, 0, Some(now - 60), &base_policy());
        // Recent extraction + outside cold-start → defer.
        assert!(!d.is_inline());
    }

    // ── stale-cron trigger ──────────────────────────────────────

    #[test]
    fn stale_cron_fires_inline_when_threshold_elapsed() {
        let now = 100_000;
        let last = now - 35 * 60; // 35 min ago (threshold = 30min)
        let d = should_extract_inline("hi", now, 0, Some(last), &base_policy());
        assert!(d.is_inline());
        assert!(d.reason().contains("stale-cron"));
    }

    #[test]
    fn stale_cron_silent_when_extraction_recent() {
        let now = 100_000;
        let last = now - 5 * 60; // 5 min ago
        let d = should_extract_inline("hi", now, 0, Some(last), &base_policy());
        assert!(!d.is_inline());
    }

    #[test]
    fn no_prior_extraction_always_fires_inline_once() {
        let now = 100_000;
        let d = should_extract_inline("hi", now, 0, None, &base_policy());
        assert!(d.is_inline());
        assert!(d.reason().contains("no prior extraction"));
    }

    // ── priority order ──────────────────────────────────────────

    #[test]
    fn preference_phrase_takes_priority_over_cold_start() {
        // Within cold-start, but the reason should be preference.
        let d = should_extract_inline("Remember that I prefer X.", 60, 0, Some(0), &base_policy());
        assert!(d.is_inline());
        assert!(d.reason().contains("preference"));
    }

    #[test]
    fn cold_start_takes_priority_over_stale_cron() {
        // Within cold-start AND stale-cron — cold-start wins.
        let d = should_extract_inline(
            "hi",
            60,
            0,
            Some(60 - 60 * 60), // last extraction 60 min ago
            &base_policy(),
        );
        assert!(d.is_inline());
        assert!(d.reason().contains("cold-start"));
    }

    // ── ExtractDecision predicate ───────────────────────────────

    #[test]
    fn extract_decision_is_inline_predicate_pinned() {
        assert!(ExtractDecision::RunInline { reason: "x" }.is_inline());
        assert!(!ExtractDecision::DeferToCron { reason: "y" }.is_inline());
    }

    // ── serde round-trip on the policy ──────────────────────────

    #[test]
    fn policy_serde_round_trips() {
        let p = base_policy();
        let s = serde_yaml::to_string(&p).unwrap();
        let back: InlineExtractPolicy = serde_yaml::from_str(&s).unwrap();
        assert_eq!(back, p);
    }
}
