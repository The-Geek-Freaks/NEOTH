//! B-6 Item 3h — 4-class retry classifier for the claude-cli backend.
//!
//! Both the subprocess (`claude --print`) and tmux backends can fail
//! in qualitatively distinct ways. Treating every failure the same
//! way either retries too aggressively (auth failures spam the user)
//! or gives up too quickly (a transient network blip kills the
//! whole chat). This module classifies an observed failure into one
//! of four buckets + emits an actionable `RetryDecision` carrying
//! attempts + backoff + an operator-readable hint.
//!
//! Class taxonomy (mirrors the Konsens B-6 architecture):
//!
//!   - **Transient** — network blip, rate-limit, 5xx upstream. Safe to
//!     retry with exponential backoff. Default: 3 attempts.
//!   - **SessionCollision** — two NEOTH workers raced to claim the same
//!     warm-tmux session, or the JSONL got locked. Drop session +
//!     retry once with a fresh session.
//!   - **EmptyStdout** — the CLI returned exit 0 but no text. Almost
//!     always means the pane was mid tool-call when we polled.
//!     Retry once with a longer idle wait.
//!   - **Auth** — token expired / OAuth challenge fired / permission
//!     denied. NEVER retry; surface a "run `claude /login`" pointer.
//!
//! Inputs are operator-observable strings (stdout / stderr / error
//! message). No regex dep — pure substring + lowercase scan so the
//! classifier is allocation-light and fully deterministic.
//!
//! Wiring (deferred): `complete_tmux_uncached` + future PTY-subprocess
//! path consume `RetryDecision` to drive their loops. v0.2 lands the
//! wire-up; this commit ships the classifier surface + the contract.

use std::time::Duration;

/// One of four retry classes covering every observed claude-cli
/// failure mode. Pinned exhaustively — adding a fifth class is an
/// architecture change, not a quick fix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RetryClass {
    /// Network / rate-limit / 5xx upstream. Retry with backoff.
    Transient,
    /// Two workers raced; JSONL locked; pane disappeared mid-write.
    /// Drop session + retry once with fresh session.
    SessionCollision,
    /// Exit 0 but stdout empty. Pane mid tool-call. Retry once with
    /// longer idle wait.
    EmptyStdout,
    /// Token expired / OAuth needed / permission denied. NEVER retry.
    Auth,
}

impl RetryClass {
    /// Stable identifier for logs + WAL events.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Transient => "transient",
            Self::SessionCollision => "session_collision",
            Self::EmptyStdout => "empty_stdout",
            Self::Auth => "auth",
        }
    }
}

/// Observed failure signal — caller assembles this from whatever
/// the backend exposed (subprocess `Output` + spawn `Result` /
/// tmux `ClaudeTmuxError` + pane snapshot). Empty strings are fine;
/// classify treats absence as "no signal in this slot".
#[derive(Clone, Debug, Default)]
pub struct FailureSignal<'a> {
    /// Process exit code (None when the spawn itself failed).
    pub exit_code: Option<i32>,
    pub stdout: &'a str,
    pub stderr: &'a str,
    /// Human-readable error message from the anyhow chain (e.g.
    /// `"PaneDisappeared"`, `"connection refused"`).
    pub error_message: &'a str,
}

/// Retry strategy for one class. Caller's responsibility to honour
/// `max_attempts`; once exceeded, the original error surfaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryDecision {
    pub class: RetryClass,
    /// 0 means "never retry, surface immediately".
    pub max_attempts: u32,
    /// First-retry sleep. `Transient` doubles per attempt
    /// (exponential backoff); other classes hold constant.
    pub initial_backoff: Duration,
    /// True ⇔ the backend should drop the warm-tmux session before
    /// the next attempt. Only `SessionCollision` flips this on.
    pub reset_session: bool,
    /// Operator-readable hint for the log line + future
    /// `neoth doctor` surface.
    pub hint: &'static str,
}

/// Classify an observed failure into one of the four buckets.
/// Priority order (most specific first): Auth → SessionCollision →
/// EmptyStdout → Transient (fallback).
pub fn classify_failure(signal: &FailureSignal<'_>) -> RetryClass {
    let combined_lower = {
        let mut s = String::with_capacity(
            signal.stdout.len() + signal.stderr.len() + signal.error_message.len() + 2,
        );
        s.push_str(signal.stdout);
        s.push(' ');
        s.push_str(signal.stderr);
        s.push(' ');
        s.push_str(signal.error_message);
        s.to_lowercase()
    };

    if has_auth_signal(&combined_lower) {
        return RetryClass::Auth;
    }
    if has_session_collision_signal(&combined_lower) {
        return RetryClass::SessionCollision;
    }
    if is_empty_stdout_signal(signal) {
        return RetryClass::EmptyStdout;
    }
    RetryClass::Transient
}

/// Emit the retry strategy for a classified failure. Pure-fn so the
/// policy is testable without spawning anything.
pub fn retry_decision(class: RetryClass) -> RetryDecision {
    match class {
        RetryClass::Transient => RetryDecision {
            class,
            max_attempts: 3,
            initial_backoff: Duration::from_millis(500),
            reset_session: false,
            hint: "transient upstream failure — retrying with exponential backoff",
        },
        RetryClass::SessionCollision => RetryDecision {
            class,
            max_attempts: 1,
            initial_backoff: Duration::from_millis(250),
            reset_session: true,
            hint: "session collision — dropping warm session + retrying once on a fresh one",
        },
        RetryClass::EmptyStdout => RetryDecision {
            class,
            max_attempts: 1,
            initial_backoff: Duration::from_millis(2_000),
            reset_session: false,
            hint: "empty stdout — pane was likely mid tool-call, retrying once with a longer idle wait",
        },
        RetryClass::Auth => RetryDecision {
            class,
            max_attempts: 0,
            initial_backoff: Duration::from_millis(0),
            reset_session: false,
            hint: "auth failure — run `claude /login` and re-issue your message",
        },
    }
}

/// Compute the actual sleep duration for attempt `n` (0-indexed).
/// `Transient` doubles per attempt up to 30s cap; all other classes
/// hold the initial backoff constant.
pub fn backoff_for_attempt(decision: &RetryDecision, attempt: u32) -> Duration {
    const CAP: Duration = Duration::from_secs(30);
    if decision.class != RetryClass::Transient {
        return decision.initial_backoff;
    }
    let factor = 1u64 << attempt.min(8);
    let scaled = decision.initial_backoff.saturating_mul(factor as u32);
    if scaled > CAP {
        CAP
    } else {
        scaled
    }
}

fn has_auth_signal(s: &str) -> bool {
    [
        "invalid_api_key",
        "unauthenticated",
        "unauthorized",
        "401",
        "403",
        "permission denied",
        "oauth",
        "token expired",
        "please run `claude /login`",
        "please run claude /login",
        "not signed in",
        "no credentials",
    ]
    .iter()
    .any(|needle| s.contains(needle))
}

fn has_session_collision_signal(s: &str) -> bool {
    [
        "panedisappeared",
        "pane disappeared",
        "session not found",
        "jsonl is locked",
        "session was killed",
        "already in use",
        "session collision",
    ]
    .iter()
    .any(|needle| s.contains(needle))
}

fn is_empty_stdout_signal(signal: &FailureSignal<'_>) -> bool {
    // Exit 0 + empty stdout (after trim) is the canonical
    // "pane mid tool-call" signature.
    signal.exit_code == Some(0) && signal.stdout.trim().is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(exit: Option<i32>, stdout: &'static str, stderr: &'static str, err: &'static str) -> FailureSignal<'static> {
        FailureSignal {
            exit_code: exit,
            stdout,
            stderr,
            error_message: err,
        }
    }

    // ── classify_failure ────────────────────────────────────────

    #[test]
    fn classifies_oauth_message_as_auth() {
        let s = sig(Some(1), "", "Please run `claude /login` to authenticate", "");
        assert_eq!(classify_failure(&s), RetryClass::Auth);
    }

    #[test]
    fn classifies_401_as_auth() {
        let s = sig(Some(1), "", "HTTP 401 unauthorized from upstream", "");
        assert_eq!(classify_failure(&s), RetryClass::Auth);
    }

    #[test]
    fn classifies_pane_disappeared_as_session_collision() {
        let s = sig(None, "", "", "PaneDisappeared while reading capture-pane");
        assert_eq!(classify_failure(&s), RetryClass::SessionCollision);
    }

    #[test]
    fn classifies_session_not_found_as_session_collision() {
        let s = sig(Some(2), "", "session not found", "");
        assert_eq!(classify_failure(&s), RetryClass::SessionCollision);
    }

    #[test]
    fn classifies_exit_zero_empty_stdout_as_empty_stdout() {
        let s = sig(Some(0), "   \n  ", "", "");
        assert_eq!(classify_failure(&s), RetryClass::EmptyStdout);
    }

    #[test]
    fn classifies_unknown_failure_as_transient_fallback() {
        let s = sig(Some(1), "", "connection refused", "");
        assert_eq!(classify_failure(&s), RetryClass::Transient);
    }

    #[test]
    fn classifies_5xx_as_transient() {
        let s = sig(Some(1), "", "503 service unavailable upstream", "");
        assert_eq!(classify_failure(&s), RetryClass::Transient);
    }

    #[test]
    fn auth_signal_takes_priority_over_collision() {
        // A pane that died because the token expired should classify
        // as Auth, not SessionCollision — otherwise we'd burn a
        // retry attempt before surfacing the real problem.
        let s = sig(
            Some(1),
            "",
            "401 unauthorized",
            "PaneDisappeared during 401 response",
        );
        assert_eq!(classify_failure(&s), RetryClass::Auth);
    }

    // ── retry_decision contract ─────────────────────────────────

    #[test]
    fn auth_never_retries() {
        let d = retry_decision(RetryClass::Auth);
        assert_eq!(d.max_attempts, 0);
        assert!(!d.reset_session);
    }

    #[test]
    fn session_collision_resets_session() {
        let d = retry_decision(RetryClass::SessionCollision);
        assert!(d.reset_session);
        assert_eq!(d.max_attempts, 1);
    }

    #[test]
    fn empty_stdout_retries_once_with_longer_wait() {
        let d = retry_decision(RetryClass::EmptyStdout);
        assert_eq!(d.max_attempts, 1);
        assert!(d.initial_backoff >= Duration::from_secs(1));
    }

    #[test]
    fn transient_gets_three_attempts() {
        let d = retry_decision(RetryClass::Transient);
        assert_eq!(d.max_attempts, 3);
        assert!(!d.reset_session);
    }

    #[test]
    fn every_decision_carries_operator_readable_hint() {
        for class in [
            RetryClass::Transient,
            RetryClass::SessionCollision,
            RetryClass::EmptyStdout,
            RetryClass::Auth,
        ] {
            let d = retry_decision(class);
            assert!(!d.hint.is_empty(), "missing hint for {class:?}");
        }
    }

    // ── backoff_for_attempt ─────────────────────────────────────

    #[test]
    fn transient_backoff_doubles_per_attempt() {
        let d = retry_decision(RetryClass::Transient);
        let a0 = backoff_for_attempt(&d, 0);
        let a1 = backoff_for_attempt(&d, 1);
        let a2 = backoff_for_attempt(&d, 2);
        assert_eq!(a0, Duration::from_millis(500));
        assert_eq!(a1, Duration::from_millis(1_000));
        assert_eq!(a2, Duration::from_millis(2_000));
    }

    #[test]
    fn transient_backoff_caps_at_30s() {
        let d = retry_decision(RetryClass::Transient);
        // Attempt 8 would be 500ms * 256 = 128s; must cap at 30s.
        let big = backoff_for_attempt(&d, 8);
        assert_eq!(big, Duration::from_secs(30));
    }

    #[test]
    fn non_transient_backoff_is_constant_across_attempts() {
        for class in [
            RetryClass::SessionCollision,
            RetryClass::EmptyStdout,
            RetryClass::Auth,
        ] {
            let d = retry_decision(class);
            let a0 = backoff_for_attempt(&d, 0);
            let a3 = backoff_for_attempt(&d, 3);
            assert_eq!(a0, a3, "non-transient {class:?} must not change backoff");
        }
    }

    // ── stable wire form ────────────────────────────────────────

    #[test]
    fn class_as_str_pinned_for_wal_events() {
        // Drift guard — WAL replay relies on these strings.
        assert_eq!(RetryClass::Transient.as_str(), "transient");
        assert_eq!(RetryClass::SessionCollision.as_str(), "session_collision");
        assert_eq!(RetryClass::EmptyStdout.as_str(), "empty_stdout");
        assert_eq!(RetryClass::Auth.as_str(), "auth");
    }
}
