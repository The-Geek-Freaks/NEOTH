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
//! `claude_cli::plan_tmux_retry` consumes the classifier and turns each
//! decision into the live tmux retry/reset plan.

use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Stable, content-free operator receipt embedded in the existing provider
/// lifecycle terminal. The retry chain is explicit so a read-only WAL consumer
/// never guesses that two equal prompts belong to the same retry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RetryOperatorReceipt {
    pub schema: String,
    pub retry_chain_id: String,
    pub class: RetryClass,
    pub attempt: u32,
    pub provider: String,
    pub wire_model: String,
    pub disposition: RetryDisposition,
}

impl RetryOperatorReceipt {
    pub(crate) fn new(
        retry_chain_id: String,
        class: RetryClass,
        attempt: u32,
        provider: impl Into<String>,
        wire_model: impl Into<String>,
        disposition: RetryDisposition,
    ) -> Self {
        Self {
            schema: "neoth.retry-receipt.v1".to_owned(),
            retry_chain_id,
            class,
            attempt,
            provider: provider.into(),
            wire_model: wire_model.into(),
            disposition,
        }
    }
}

/// A confirmed lifecycle fact, never a prediction that a later send occurred.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RetryDisposition {
    RetryIntentClosed,
    Exhausted,
    AuthNonRetryable,
}

const RETRY_HISTORY_MAX_ENTRIES: usize = 16;
const RETRY_HISTORY_MAX_FIELD_BYTES: usize = 128;
const RETRY_HISTORY_MAX_OUTPUT_BYTES: usize = 16 * 1024;
const RETRY_HISTORY_SCAN_LIMITS: crate::wal::scan::HomeWalScanLimits =
    crate::wal::scan::HomeWalScanLimits {
        max_directory_entries: 64,
        max_segments: 32,
        max_segment_physical_bytes: 512 * 1024,
        max_total_physical_bytes: 4 * 1024 * 1024,
        max_segment_logical_bytes: 1024 * 1024,
        max_total_logical_bytes: 8 * 1024 * 1024,
    };

/// Bounded, passive Buddy projection. It reads only the authenticated WAL
/// prefix and reports a later lifecycle intent as observed, never as a raw
/// provider send.
pub(crate) fn retry_operator_history(home: &Path) -> Value {
    let mut receipts = Vec::new();
    let scan = crate::wal::scan::for_each_authenticated_prefix_frame_at_home(
        home,
        RETRY_HISTORY_SCAN_LIMITS,
        |_, frame| {
            let Ok(payload) = serde_json::from_slice::<Value>(frame.payload) else {
                return Ok(());
            };
            if frame.header.event_type == crate::wal::events::EVENT_TYPE_PROVIDER_ERROR
                && let Some(receipt) = payload
                    .get("retry_receipt")
                    .cloned()
                    .and_then(|value| serde_json::from_value::<RetryOperatorReceipt>(value).ok())
                && valid_retry_receipt(&receipt)
            {
                let session = frame.header.session_id.opaque_hex();
                receipts.retain(|entry: &RetryHistoryEntry| {
                    entry.receipt.retry_chain_id != receipt.retry_chain_id || entry.session != session
                });
                if receipts.len() == RETRY_HISTORY_MAX_ENTRIES {
                    receipts.remove(0);
                }
                receipts.push(RetryHistoryEntry {
                    receipt,
                    session,
                    follow_up_lifecycle: "not_observed",
                });
            }
            if frame.header.event_type == crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST
                && let Some(retry_chain_id) = payload.get("retry_chain_id").and_then(Value::as_str)
                && let Some(retry_attempt) = payload.get("retry_attempt").and_then(Value::as_u64)
                && let Some(entry) = receipts.iter_mut().rev().find(|entry| {
                    entry.receipt.retry_chain_id == retry_chain_id
                        && entry.session == frame.header.session_id.opaque_hex()
                        && entry.receipt.disposition == RetryDisposition::RetryIntentClosed
                        && retry_attempt == u64::from(entry.receipt.attempt).saturating_add(1)
                })
            {
                entry.follow_up_lifecycle = "observed";
            }
            Ok(())
        },
    );
    match scan {
        Ok(scan) => {
            let value = json!({
                "kind": "available",
                "authenticated_complete": scan.complete,
                "receipts": receipts.into_iter().rev().collect::<Vec<_>>(),
            });
            match serde_json::to_vec(&value) {
                Ok(encoded) if encoded.len() <= RETRY_HISTORY_MAX_OUTPUT_BYTES => value,
                _ => json!({"kind": "unavailable"}),
            }
        }
        Err(_) => json!({"kind": "unavailable"}),
    }
}

fn valid_retry_receipt(receipt: &RetryOperatorReceipt) -> bool {
    receipt.schema == "neoth.retry-receipt.v1"
        && receipt.attempt != 0
        && !receipt.retry_chain_id.is_empty()
        && !receipt.provider.is_empty()
        && !receipt.wire_model.is_empty()
        && receipt.retry_chain_id.len() <= RETRY_HISTORY_MAX_FIELD_BYTES
        && receipt.provider.len() <= RETRY_HISTORY_MAX_FIELD_BYTES
        && receipt.wire_model.len() <= RETRY_HISTORY_MAX_FIELD_BYTES
}

#[derive(Serialize)]
struct RetryHistoryEntry {
    receipt: RetryOperatorReceipt,
    session: String,
    follow_up_lifecycle: &'static str,
}

/// One of four retry classes covering every observed claude-cli
/// failure mode. Pinned exhaustively — adding a fifth class is an
/// architecture change, not a quick fix.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
    if scaled > CAP { CAP } else { scaled }
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

    async fn append_authenticated_retry_frame(
        writer: &crate::wal::writer::WalWriterHandle,
        event_type: u8,
        session: crate::wal::WalSessionContext,
        payload: Value,
    ) {
        let payload = serde_json::to_vec(&payload).expect("encode retry WAL fixture");
        writer
            .append_authenticated(
                crate::wal::HeaderBuilder::new(event_type, &payload)
                    .session_context(Some(session))
                    .build(),
                payload,
            )
            .await
            .expect("append authenticated retry WAL fixture");
    }

    fn receipt_value(
        chain: &str,
        attempt: u32,
        disposition: RetryDisposition,
    ) -> Value {
        serde_json::to_value(RetryOperatorReceipt::new(
            chain.to_owned(),
            RetryClass::Transient,
            attempt,
            "claude_cli",
            "claude-3-7-sonnet",
            disposition,
        ))
        .expect("serialize retry receipt fixture")
    }

    fn sig(
        exit: Option<i32>,
        stdout: &'static str,
        stderr: &'static str,
        err: &'static str,
    ) -> FailureSignal<'static> {
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
        let s = sig(
            Some(1),
            "",
            "Please run `claude /login` to authenticate",
            "",
        );
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

    #[test]
    fn retry_receipt_wire_is_versioned_and_content_free() {
        let receipt = RetryOperatorReceipt::new(
            "invocation-opaque-1".to_owned(),
            RetryClass::Transient,
            2,
            "claude_cli",
            "claude-3-7-sonnet",
            RetryDisposition::Exhausted,
        );
        let wire = serde_json::to_value(&receipt).expect("retry receipt serializes");
        assert_eq!(wire["schema"], "neoth.retry-receipt.v1");
        assert_eq!(wire["class"], "transient");
        assert_eq!(wire["attempt"], 2);
        assert_eq!(wire["provider"], "claude_cli");
        assert_eq!(wire["wire_model"], "claude-3-7-sonnet");
        assert_eq!(wire["disposition"], "exhausted");
        assert!(wire.get("prompt").is_none());
        assert!(wire.get("error").is_none());
    }

    #[tokio::test]
    async fn authenticated_retry_history_requires_same_session_next_attempt_and_valid_receipt() {
        let home = tempfile::tempdir().expect("test home");
        let wal = home.path().join("wal");
        let segment = wal.join("000001.wal");
        std::fs::create_dir_all(&wal).expect("create WAL directory");
        let (writer, join, ready) = crate::wal::writer::spawn_for_home_ready(
            segment.clone(),
            home.path().to_path_buf(),
        )
        .expect("spawn authenticated WAL writer");
        ready.wait().await.expect("ready authenticated WAL writer");
        let session_a = crate::wal::WalSessionContext::from_admitted_identity(
            home.path(),
            b"test\0retry-history\0session-a",
        )
        .expect("session a");
        let session_b = crate::wal::WalSessionContext::from_admitted_identity(
            home.path(),
            b"test\0retry-history\0session-b",
        )
        .expect("session b");

        // This request predates its receipt in authenticated frame order.
        append_authenticated_retry_frame(
            &writer,
            crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST,
            session_a,
            serde_json::json!({"retry_chain_id":"earlier-request", "retry_attempt":2}),
        )
        .await;

        for (chain, attempt, disposition, session) in [
            ("valid", 1, RetryDisposition::RetryIntentClosed, session_a),
            ("cross-session", 1, RetryDisposition::RetryIntentClosed, session_a),
            ("earlier-request", 1, RetryDisposition::RetryIntentClosed, session_a),
            ("wrong-attempt", 1, RetryDisposition::RetryIntentClosed, session_a),
            ("exhausted", 1, RetryDisposition::Exhausted, session_a),
            ("shared-chain", 1, RetryDisposition::RetryIntentClosed, session_a),
        ] {
            append_authenticated_retry_frame(
                &writer,
                crate::wal::events::EVENT_TYPE_PROVIDER_ERROR,
                session,
                serde_json::json!({"retry_receipt": receipt_value(chain, attempt, disposition)}),
            )
            .await;
        }
        append_authenticated_retry_frame(
            &writer,
            crate::wal::events::EVENT_TYPE_PROVIDER_ERROR,
            session_b,
            serde_json::json!({"retry_receipt": receipt_value("shared-chain", 1, RetryDisposition::RetryIntentClosed)}),
        )
        .await;
        append_authenticated_retry_frame(
            &writer,
            crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST,
            session_a,
            serde_json::json!({"retry_chain_id":"valid", "retry_attempt":2}),
        )
        .await;
        append_authenticated_retry_frame(
            &writer,
            crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST,
            session_b,
            serde_json::json!({"retry_chain_id":"shared-chain", "retry_attempt":2}),
        )
        .await;
        append_authenticated_retry_frame(
            &writer,
            crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST,
            session_b,
            serde_json::json!({"retry_chain_id":"cross-session", "retry_attempt":2}),
        )
        .await;
        append_authenticated_retry_frame(
            &writer,
            crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST,
            session_a,
            serde_json::json!({"retry_chain_id":"wrong-attempt", "retry_attempt":3}),
        )
        .await;
        append_authenticated_retry_frame(
            &writer,
            crate::wal::events::EVENT_TYPE_PROVIDER_REQUEST,
            session_a,
            serde_json::json!({"retry_chain_id":"exhausted", "retry_attempt":2}),
        )
        .await;
        append_authenticated_retry_frame(
            &writer,
            crate::wal::events::EVENT_TYPE_PROVIDER_ERROR,
            session_a,
            serde_json::json!({"retry_receipt": {"schema":"wrong", "attempt":0, "prompt":"must-not-project"}}),
        )
        .await;

        // Drain the producer before reading, then add a torn tail. The reader
        // must retain only the authenticated prefix and create no files.
        drop(writer);
        join.await.expect("writer join").expect("writer completion");
        use std::io::Write as _;
        let mut tail = std::fs::OpenOptions::new()
            .append(true)
            .open(&segment)
            .expect("open sealed test WAL for torn tail");
        tail.write_all(b"raw-error-secret")
            .expect("append truncated tail bytes");
        tail.sync_all().expect("sync truncated tail bytes");

        let history = retry_operator_history(home.path());
        let rows = history["receipts"].as_array().expect("receipt rows");
        assert_eq!(rows.len(), 7, "malformed receipts and live tails stay absent");
        let valid = rows
            .iter()
            .find(|row| row["receipt"]["retry_chain_id"] == "valid")
            .expect("valid receipt row");
        assert_eq!(valid["follow_up_lifecycle"], "observed");
        for chain in ["cross-session", "earlier-request", "wrong-attempt", "exhausted"] {
            let row = rows
                .iter()
                .find(|row| row["receipt"]["retry_chain_id"] == chain)
                .expect("expected valid receipt row");
            assert_eq!(row["follow_up_lifecycle"], "not_observed");
        }
        let shared = rows
            .iter()
            .filter(|row| row["receipt"]["retry_chain_id"] == "shared-chain")
            .collect::<Vec<_>>();
        assert_eq!(shared.len(), 2, "same retry chain is isolated by session");
        assert!(shared.iter().any(|row| row["follow_up_lifecycle"] == "observed"));
        assert!(shared.iter().any(|row| row["follow_up_lifecycle"] == "not_observed"));
        let rendered = serde_json::to_string(&history).expect("render history");
        assert!(!rendered.contains("raw-error-secret"));
        assert!(!rendered.contains("must-not-project"));
        assert_eq!(history["authenticated_complete"], false);
    }
}
