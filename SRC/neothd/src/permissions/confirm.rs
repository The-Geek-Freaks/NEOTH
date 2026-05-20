//! Confirmation handshake for `Decision::Confirm` outcomes — Phase 28b AU-4.
//!
//! When `permissions::evaluate` returns `Confirm(reason)`, the caller must
//! ask the operator (or a remote responder) before proceeding. Three paths:
//!
//!   - **Interactive TTY** — `dialoguer::Confirm` y/n prompt.
//!   - **Channel-driven** — post a single "approve / deny" question on the
//!     active channel, await reply (with a timeout). Defaults to deny if
//!     the operator never answers.
//!   - **Daemon-only / cron** — no human in the loop. Defer to the job's
//!     `best_effort` flag if set; otherwise fail closed.
//!
//! The integration into individual tools lands when Phase 30 sub-agents
//! wire `guarded_action` into their dispatch path. This module is the
//! reusable handshake itself.

use std::time::Duration;

use super::Decision;

/// Where the prompt is delivered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfirmMode {
    /// Operator is sitting at a TTY (`neoth` invoked interactively).
    InteractiveTty,
    /// Operator is reachable via a channel (Telegram/Keet/...). The caller
    /// supplies the reply hook via [`confirm_channel`].
    Channel,
    /// Cron / hook / sub-agent path with no human handle. Fail-closed
    /// unless the action carries an explicit `best_effort` flag.
    DaemonOnly { best_effort: bool },
}

/// Outcome of a confirmation handshake. Map back to `Decision::Allow` /
/// `Decision::Deny` for the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfirmOutcome {
    Approved,
    Denied,
    /// No reply arrived within the timeout. Treated as deny by the caller
    /// but distinguished so the WAL audit can record the reason precisely.
    TimedOut,
}

impl ConfirmOutcome {
    pub fn into_decision(self, reason: &str) -> Decision {
        match self {
            ConfirmOutcome::Approved => Decision::Allow,
            ConfirmOutcome::Denied => Decision::Deny(format!("operator denied: {reason}")),
            ConfirmOutcome::TimedOut => Decision::Deny(format!("confirm timed out: {reason}")),
        }
    }
}

/// Default channel-reply timeout. 90 seconds gives a phone-tapping operator
/// time to respond without making the daemon block forever.
pub const DEFAULT_CHANNEL_TIMEOUT: Duration = Duration::from_secs(90);

/// Interactive y/n prompt. No-op + Denied when `wizard` feature is off
/// (CI / slim daemon builds), since dialoguer isn't compiled.
pub fn confirm_interactive(reason: &str) -> ConfirmOutcome {
    #[cfg(feature = "wizard")]
    {
        match dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt(format!("Confirm: {reason}"))
            .default(false)
            .interact()
        {
            Ok(true) => ConfirmOutcome::Approved,
            Ok(false) => ConfirmOutcome::Denied,
            Err(_) => ConfirmOutcome::Denied,
        }
    }
    #[cfg(not(feature = "wizard"))]
    {
        let _ = reason;
        // No dialoguer available; fail closed.
        ConfirmOutcome::Denied
    }
}

/// Channel-driven confirm. The caller supplies a future that resolves to
/// `Some(approved)` when the operator replies, or `None` on timeout.
///
/// We accept the future as a closure rather than wiring a specific channel
/// here so the same code drives Telegram / Keet / future channels without
/// duplicating the timeout/race logic.
pub async fn confirm_channel<F>(reason: &str, ask: F, timeout: Duration) -> ConfirmOutcome
where
    F: std::future::Future<Output = Option<bool>>,
{
    let _ = reason; // Logged by caller; here only the outcome matters.
    match tokio::time::timeout(timeout, ask).await {
        Ok(Some(true)) => ConfirmOutcome::Approved,
        Ok(Some(false)) => ConfirmOutcome::Denied,
        Ok(None) => ConfirmOutcome::Denied,
        Err(_) => ConfirmOutcome::TimedOut,
    }
}

/// Daemon-only / cron path. No human to ask. Honour the job's `best_effort`
/// flag if present; otherwise fail closed.
pub fn confirm_daemon_only(best_effort: bool) -> ConfirmOutcome {
    if best_effort {
        ConfirmOutcome::Approved
    } else {
        ConfirmOutcome::Denied
    }
}

/// Resolve a `Decision::Confirm` outcome through the appropriate handshake.
/// Non-confirm decisions pass through unchanged.
///
/// This is the top-level helper the dispatch layer will call:
///
/// ```ignore
/// let decision = permissions::evaluate(&action, level);
/// let final_decision = confirm::resolve(decision, mode, &ask).await;
/// ```
pub async fn resolve<F>(decision: Decision, mode: ConfirmMode, ask: F) -> Decision
where
    F: std::future::Future<Output = Option<bool>>,
{
    let Decision::Confirm(reason) = decision else {
        return decision;
    };
    let outcome = match mode {
        ConfirmMode::InteractiveTty => confirm_interactive(&reason),
        ConfirmMode::Channel => confirm_channel(&reason, ask, DEFAULT_CHANNEL_TIMEOUT).await,
        ConfirmMode::DaemonOnly { best_effort } => confirm_daemon_only(best_effort),
    };
    outcome.into_decision(&reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_only_fails_closed_without_best_effort() {
        assert_eq!(
            confirm_daemon_only(false),
            ConfirmOutcome::Denied,
            "cron job without best_effort must fail closed",
        );
        assert_eq!(
            confirm_daemon_only(true),
            ConfirmOutcome::Approved,
            "cron job with best_effort proceeds",
        );
    }

    #[test]
    fn outcome_into_decision_keeps_reason() {
        let d = ConfirmOutcome::Denied.into_decision("rm -rf");
        match d {
            Decision::Deny(r) => assert!(r.contains("rm -rf"), "reason lost: {r}"),
            _ => panic!("expected Deny, got {d:?}"),
        }
        assert_eq!(
            ConfirmOutcome::Approved.into_decision("anything"),
            Decision::Allow,
        );
    }

    #[tokio::test]
    async fn channel_confirm_approves_when_reply_says_true() {
        let ask = async { Some(true) };
        let out = confirm_channel("x", ask, Duration::from_secs(1)).await;
        assert_eq!(out, ConfirmOutcome::Approved);
    }

    #[tokio::test]
    async fn channel_confirm_denies_when_reply_says_false() {
        let ask = async { Some(false) };
        let out = confirm_channel("x", ask, Duration::from_secs(1)).await;
        assert_eq!(out, ConfirmOutcome::Denied);
    }

    #[tokio::test]
    async fn channel_confirm_times_out() {
        // Future that never resolves → must time out within the bound.
        let ask = async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            Some(true)
        };
        let out = confirm_channel("x", ask, Duration::from_millis(20)).await;
        assert_eq!(out, ConfirmOutcome::TimedOut);
    }

    #[tokio::test]
    async fn resolve_passes_allow_through() {
        let d = resolve(
            Decision::Allow,
            ConfirmMode::DaemonOnly { best_effort: false },
            async { None },
        )
        .await;
        assert_eq!(d, Decision::Allow);
    }

    #[tokio::test]
    async fn resolve_passes_deny_through() {
        let d = resolve(
            Decision::Deny("nope".into()),
            ConfirmMode::DaemonOnly { best_effort: false },
            async { None },
        )
        .await;
        assert!(matches!(d, Decision::Deny(_)));
    }

    #[tokio::test]
    async fn resolve_confirm_in_daemon_without_best_effort_denies() {
        let d = resolve(
            Decision::Confirm("write outside home".into()),
            ConfirmMode::DaemonOnly { best_effort: false },
            async { None },
        )
        .await;
        assert!(matches!(d, Decision::Deny(_)));
    }

    #[tokio::test]
    async fn resolve_confirm_via_channel_approves() {
        let d = resolve(
            Decision::Confirm("ok?".into()),
            ConfirmMode::Channel,
            async { Some(true) },
        )
        .await;
        assert_eq!(d, Decision::Allow);
    }
}
