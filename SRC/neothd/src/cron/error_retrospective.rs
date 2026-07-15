//! JV-PRO-06 — Cron job error retrospective + classifier.
//!
//! Pure functions. No I/O. No async. Called by `runner::run_job` (or a
//! post-run analysis path) on any `RunOutcome` with `success == false`.
//!
//! ## Design
//!
//! `classify_error` maps free-form error text + an exit-kind tag to a typed
//! `ErrorCause` via keyword taxonomy. `risk_score` turns the cause + a
//! consecutive-failure count into a `[0.0, 1.0]` urgency signal that operators
//! (or a future self-heal path) use to prioritise remediation.
//! `build_retrospective` composes both into a `Retrospective` that becomes the
//! operator-visible WHY + recommendation when a cron job fails.
//!
//! ## Taxonomy
//!
//! The keyword lists are intentionally conservative: a short, explicit set is
//! easier to audit and extend than a regex corpus. Add patterns as new failure
//! modes surface in the wild.

/// Typed failure cause. The Unknown variant is the safe fallback — it never
/// hides a failure, it just means the pattern-match didn't fire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCause {
    /// The provider call hit the job's `timeout_seconds` wall.
    Timeout,
    /// The provider returned an error (HTTP 4xx/5xx, auth, quota, etc.).
    ProviderError,
    /// The provider returned successfully but the output was empty or
    /// whitespace-only (a degenerate success that is functionally a failure).
    EmptyOutput,
    /// The cron runner produced output but the downstream channel delivery
    /// rejected or failed to accept it.
    ChannelDeliveryFailed,
    /// Error text did not match any known pattern.
    Unknown,
}

impl ErrorCause {
    /// Human-readable label for WAL frames / CLI output.
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorCause::Timeout => "timeout",
            ErrorCause::ProviderError => "provider_error",
            ErrorCause::EmptyOutput => "empty_output",
            ErrorCause::ChannelDeliveryFailed => "channel_delivery_failed",
            ErrorCause::Unknown => "unknown",
        }
    }
}

// ── Keyword taxonomy ──────────────────────────────────────────────────────────

/// Substrings that indicate a timeout path. Checked case-insensitively.
const TIMEOUT_MARKERS: &[&str] = &[
    "timed out",
    "timeout",
    "time out",
    "deadline exceeded",
    "elapsed",
];

/// Substrings that indicate a provider-layer failure (HTTP, auth, rate-limit).
const PROVIDER_ERROR_MARKERS: &[&str] = &[
    "http",
    "status 4",
    "status 5",
    "401",
    "403",
    "429",
    "503",
    "provider",
    "authentication",
    "unauthorized",
    "rate limit",
    "quota",
    "connection refused",
    "connection reset",
    "no such host",
    "dns",
];

/// Substrings that indicate an empty-output path.
const EMPTY_OUTPUT_MARKERS: &[&str] = &[
    "empty output",
    "empty response",
    "no output",
    "zero bytes",
    "0 bytes",
];

/// Substrings (or exit-kind values) that indicate a channel delivery failure.
const CHANNEL_DELIVERY_MARKERS: &[&str] = &[
    "channel",
    "delivery",
    "send failed",
    "could not deliver",
    "telegram",
    "discord",
    "slack",
    "matrix",
];

/// Classify the error from a failed job run.
///
/// `err_text` is the free-form error string stored in `RunOutcome::error`.
/// `exit_kind` is a short caller-controlled tag — e.g. `"timeout"`,
/// `"provider"`, `"delivery"` — that can tip classification when the error
/// text is ambiguous. Pass an empty string when no structured tag is
/// available.
///
/// Classification order: Timeout > EmptyOutput > ProviderError >
/// ChannelDeliveryFailed > Unknown. Timeout is checked first because a
/// timed-out provider call also produces `err_text` containing "provider"
/// substrings in some adapters.
pub fn classify_error(err_text: &str, exit_kind: &str) -> ErrorCause {
    let lower = err_text.to_ascii_lowercase();
    let kind = exit_kind.to_ascii_lowercase();

    // Timeout wins if the structured tag says so, OR the error text fires.
    if kind == "timeout" || TIMEOUT_MARKERS.iter().any(|m| lower.contains(m)) {
        return ErrorCause::Timeout;
    }

    // Empty output: check structured tag first, then text.
    if kind == "empty" || EMPTY_OUTPUT_MARKERS.iter().any(|m| lower.contains(m)) {
        return ErrorCause::EmptyOutput;
    }

    // Provider error.
    if kind == "provider" || PROVIDER_ERROR_MARKERS.iter().any(|m| lower.contains(m)) {
        return ErrorCause::ProviderError;
    }

    // Channel delivery failure.
    if kind == "delivery" || CHANNEL_DELIVERY_MARKERS.iter().any(|m| lower.contains(m)) {
        return ErrorCause::ChannelDeliveryFailed;
    }

    ErrorCause::Unknown
}

// ── Risk scoring ──────────────────────────────────────────────────────────────

/// Base risk weight per cause. Reflects operator impact:
///   - Timeout / ProviderError are recoverable but indicate infrastructure
///     issues that compound over time.
///   - EmptyOutput is suspicious (might be a silent misconfiguration).
///   - ChannelDeliveryFailed means the job ran but nobody saw the result.
///   - Unknown is neutral — we don't over-punish what we don't understand.
fn base_weight(cause: &ErrorCause) -> f64 {
    match cause {
        ErrorCause::Timeout => 0.55,
        ErrorCause::ProviderError => 0.50,
        ErrorCause::EmptyOutput => 0.45,
        ErrorCause::ChannelDeliveryFailed => 0.35,
        ErrorCause::Unknown => 0.20,
    }
}

/// Score the urgency of a failure in `[0.0, 1.0]`.
///
/// The base weight is amplified by `consecutive_failures` using a logarithmic
/// curve — the first recurrence roughly doubles the score, but 10+ recurrences
/// don't push it arbitrarily high (an infinite-loop crasher should not
/// dominate the alert channel).
///
/// Formula: `clamp(base * (1.0 + ln(1 + consecutive_failures)), 0.0, 1.0)`
pub fn risk_score(cause: &ErrorCause, consecutive_failures: u32) -> f64 {
    let base = base_weight(cause);
    let amplifier = 1.0 + (1.0 + consecutive_failures as f64).ln();
    (base * amplifier).min(1.0_f64)
}

// ── Recommendation builder ────────────────────────────────────────────────────

fn recommendation_for(cause: &ErrorCause, consecutive_failures: u32) -> String {
    let recurring = consecutive_failures >= 3;
    match cause {
        ErrorCause::Timeout => {
            if recurring {
                format!(
                    "Job has timed out {consecutive_failures} consecutive times. \
                     Increase `timeout_seconds` in jobs.yaml, or reduce the \
                     prompt scope."
                )
            } else {
                "Job timed out. Check provider latency or increase \
                 `timeout_seconds` in jobs.yaml."
                    .to_string()
            }
        }
        ErrorCause::ProviderError => {
            if recurring {
                format!(
                    "Provider error repeated {consecutive_failures} times. \
                     Verify API credentials, check quota/rate-limits, or \
                     switch to a fallback provider in freedom.yaml."
                )
            } else {
                "Provider returned an error. Check credentials and \
                 rate-limit budget."
                    .to_string()
            }
        }
        ErrorCause::EmptyOutput => "Provider returned empty output. The prompt may be too vague \
             or the model may be over-constrained. Add explicit output \
             instructions to the job prompt."
            .to_string(),
        ErrorCause::ChannelDeliveryFailed => {
            "Output was generated but channel delivery failed. Check \
             channel credentials and the destination in channel_routing.yaml."
                .to_string()
        }
        ErrorCause::Unknown => {
            if recurring {
                format!(
                    "Unknown error class repeated {consecutive_failures} times. \
                     Inspect `neoth cron logs --id <job>` for the raw error text."
                )
            } else {
                "Unknown error. Inspect `neoth cron logs --id <job>` for \
                 details."
                    .to_string()
            }
        }
    }
}

// ── Retrospective ─────────────────────────────────────────────────────────────

/// Composed failure analysis emitted after a job run fails. The operator (or a
/// future self-heal path) reads `cause`, `risk`, and `recommendation` to decide
/// whether to alert, retry, or suppress.
#[derive(Debug, Clone)]
pub struct Retrospective {
    /// Classified failure reason.
    pub cause: ErrorCause,
    /// Urgency in `[0.0, 1.0]`. Rises with `consecutive_failures`.
    pub risk_score: f64,
    /// Human-readable next-action recommendation.
    pub recommendation: String,
}

/// Build a [`Retrospective`] for a failed job run.
///
/// `err_text` — the `RunOutcome::error` string (may be empty but not None for
/// a failure path).
/// `exit_kind` — structured tag from the caller; pass `""` when unavailable.
/// `consecutive_failures` — how many times THIS job has failed in a row
/// (monotonic counter the caller maintains; 0 = first failure).
pub fn build_retrospective(
    err_text: &str,
    exit_kind: &str,
    consecutive_failures: u32,
) -> Retrospective {
    let cause = classify_error(err_text, exit_kind);
    let score = risk_score(&cause, consecutive_failures);
    let recommendation = recommendation_for(&cause, consecutive_failures);
    Retrospective {
        cause,
        risk_score: score,
        recommendation,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_timeout_from_text() {
        assert_eq!(
            classify_error("timeout after 1800s", ""),
            ErrorCause::Timeout
        );
        assert_eq!(classify_error("job timed out", ""), ErrorCause::Timeout);
        assert_eq!(classify_error("deadline exceeded", ""), ErrorCause::Timeout);
    }

    #[test]
    fn classify_timeout_from_exit_kind() {
        assert_eq!(
            classify_error("something else entirely", "timeout"),
            ErrorCause::Timeout
        );
    }

    #[test]
    fn classify_provider_error() {
        assert_eq!(
            classify_error("http status 429 rate limit", ""),
            ErrorCause::ProviderError
        );
        assert_eq!(
            classify_error("authentication failed", ""),
            ErrorCause::ProviderError
        );
        assert_eq!(
            classify_error("connection refused", ""),
            ErrorCause::ProviderError
        );
    }

    #[test]
    fn classify_empty_output() {
        assert_eq!(classify_error("empty output", ""), ErrorCause::EmptyOutput);
        assert_eq!(
            classify_error("0 bytes returned", ""),
            ErrorCause::EmptyOutput
        );
        assert_eq!(
            classify_error("irrelevant text", "empty"),
            ErrorCause::EmptyOutput
        );
    }

    #[test]
    fn classify_channel_delivery() {
        assert_eq!(
            classify_error("telegram send failed: bad token", ""),
            ErrorCause::ChannelDeliveryFailed
        );
        assert_eq!(
            classify_error("irrelevant", "delivery"),
            ErrorCause::ChannelDeliveryFailed
        );
    }

    #[test]
    fn classify_unknown_fallback() {
        assert_eq!(classify_error("", ""), ErrorCause::Unknown);
        assert_eq!(classify_error("some weird crash", ""), ErrorCause::Unknown);
    }

    #[test]
    fn timeout_beats_provider_in_text() {
        // Some provider adapters include "http" in a timeout trace.
        let text = "timed out waiting for http response";
        assert_eq!(classify_error(text, ""), ErrorCause::Timeout);
    }

    #[test]
    fn risk_score_rises_with_consecutive_failures() {
        let s0 = risk_score(&ErrorCause::Timeout, 0);
        let s1 = risk_score(&ErrorCause::Timeout, 1);
        let s5 = risk_score(&ErrorCause::Timeout, 5);
        assert!(s0 < s1, "first recurrence should raise risk");
        assert!(s1 < s5, "more failures should raise risk further");
    }

    #[test]
    fn risk_score_capped_at_one() {
        let score = risk_score(&ErrorCause::Timeout, 1_000_000);
        assert!(score <= 1.0, "risk_score must be ≤ 1.0");
    }

    #[test]
    fn risk_score_unknown_lower_than_timeout() {
        let t = risk_score(&ErrorCause::Timeout, 0);
        let u = risk_score(&ErrorCause::Unknown, 0);
        assert!(
            u < t,
            "Unknown should score lower than Timeout at the same failure count"
        );
    }

    #[test]
    fn build_retrospective_composes_fields() {
        let r = build_retrospective("timed out after 1800s", "", 2);
        assert_eq!(r.cause, ErrorCause::Timeout);
        assert!(r.risk_score > 0.0);
        assert!(!r.recommendation.is_empty());
    }

    #[test]
    fn retrospective_recommendation_mentions_consecutive_failures() {
        let r = build_retrospective("timed out", "", 5);
        assert!(
            r.recommendation.contains('5'),
            "recommendation should mention the consecutive count when recurring"
        );
    }
}
