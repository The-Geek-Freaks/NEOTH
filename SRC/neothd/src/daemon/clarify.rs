//! GOLD-ADAPT-HERMES-03 — Mid-run clarification gate.
//!
//! When a worker encounters an ambiguous input it calls [`ClarificationGate::park`],
//! which:
//!
//! 1. Transitions the gate into the [`GateState::Waiting`] state.
//! 2. Surfaces a [`ClarificationRequest`] (question text + request id).
//! 3. Blocks the worker (via a tokio oneshot) until either an answer
//!    arrives via [`ClarificationGate::answer`] or the configured
//!    timeout elapses.
//!
//! On answer:
//! - The gate transitions to [`GateState::Answered`] and the parked worker
//!   receives the answer text and resumes.
//!
//! On timeout:
//! - The gate transitions to [`GateState::TimedOut`] and `park` returns
//!   `Err(ParkError::Timeout)`.
//!
//! Unambiguous inputs call [`ClarificationGate::pass_through`] and see
//! `ParkOutcome::PassThrough` — the gate stays [`GateState::Idle`].
//!
//! ## Design notes
//!
//! The gate is intentionally *single-use per run*: one `park`→`answer`
//! round-trip per logical worker run. A worker that hits a second ambiguity
//! after resumal creates a fresh `ClarificationGate`.
//!
//! Thread-safety: `ClarificationGate` is `Send + Sync` behind an
//! `Arc<ClarificationGate>` so the answering half (operator CLI / channel
//! push) can live on a different tokio task.

use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Default park timeout. Operators see a "clarification timed out" signal
/// after this period; the worker resumes with a best-effort fallback.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

/// Unique identifier for a pending clarification request. Used by the
/// answering surface to route the reply back to the correct gate.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClarificationId(pub String);

impl ClarificationId {
    /// Generate a collision-free id.
    pub fn new() -> Self {
        // Cheap collision-free id without pulling in `uuid`. A timestamp +
        // monotonically-incrementing process-global counter ensures uniqueness
        // even for two calls on the same thread in the same millisecond.
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let ts = crate::time::now_unix_i64();
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        Self(format!("clarify-{ts}-{seq:06x}"))
    }
}

impl Default for ClarificationId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ClarificationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A pending request surfaced to the operator (or test harness).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClarificationRequest {
    /// Stable id — used to route the answer back to this gate.
    pub id: ClarificationId,
    /// Free-form question text the worker surfaced.
    pub question: String,
    /// Unix timestamp when the request was created.
    pub created_at: i64,
    /// When the gate will time out if no answer arrives (unix epoch).
    pub deadline_at: i64,
}

/// The gate's lifecycle state. Transitions are one-way:
/// `Idle → Waiting → Answered | TimedOut`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateState {
    /// No pending clarification.
    Idle,
    /// Waiting for an operator answer. `ClarificationRequest` describes
    /// the question.
    Waiting(ClarificationRequest),
    /// Answer received; gate consumed.
    Answered { answer: String },
    /// Operator did not answer within the timeout.
    TimedOut,
}

/// Outcome returned to the worker by [`ClarificationGate::park`].
#[derive(Debug, PartialEq, Eq)]
pub enum ParkOutcome {
    /// An answer arrived; the worker resumes with this text.
    Answered(String),
    /// No answer arrived within the timeout; the worker may use a
    /// fallback strategy.
    TimedOut,
}

/// Outcome returned by [`ClarificationGate::pass_through`].
#[derive(Debug, PartialEq, Eq)]
pub enum PassThroughOutcome {
    /// Input was unambiguous — no gate action needed.
    PassThrough,
}

/// Error returned by [`ClarificationGate::answer`].
#[derive(Debug, PartialEq, Eq)]
pub enum AnswerError {
    /// The gate is not in `Waiting` state; the request id does not match
    /// the current pending request.
    NotWaiting,
    /// The request id does not match the pending request.
    IdMismatch {
        expected: ClarificationId,
        got: ClarificationId,
    },
}

impl std::fmt::Display for AnswerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnswerError::NotWaiting => write!(f, "clarification gate is not in Waiting state"),
            AnswerError::IdMismatch { expected, got } => {
                write!(
                    f,
                    "clarification id mismatch: expected {expected}, got {got}"
                )
            }
        }
    }
}

/// Internal slot shared between the `park` future and the `answer` call.
struct Slot {
    state: GateState,
    /// Sender half of the rendezvous channel. `Some` while parked;
    /// `None` once consumed (answered or timed-out).
    tx: Option<tokio::sync::oneshot::Sender<String>>,
}

/// Mid-run clarification gate. Wrap in `Arc<ClarificationGate>` to share
/// between the worker task and the answering surface.
pub struct ClarificationGate {
    slot: Mutex<Slot>,
    timeout: Duration,
}

impl ClarificationGate {
    /// Create a new gate. A worker parks on it; an operator (or test)
    /// answers via [`Self::answer`].
    pub fn new(timeout: Duration) -> Self {
        Self {
            slot: Mutex::new(Slot {
                state: GateState::Idle,
                tx: None,
            }),
            timeout,
        }
    }

    /// Create a gate with [`DEFAULT_TIMEOUT`].
    pub fn default_timeout() -> Self {
        Self::new(DEFAULT_TIMEOUT)
    }

    /// Current state of the gate (non-blocking snapshot for the
    /// operator-facing status surface).
    pub fn state(&self) -> GateState {
        self.slot
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .state
            .clone()
    }

    /// The current pending request, if the gate is in `Waiting` state.
    pub fn pending_request(&self) -> Option<ClarificationRequest> {
        match &self.slot.lock().unwrap_or_else(|p| p.into_inner()).state {
            GateState::Waiting(req) => Some(req.clone()),
            _ => None,
        }
    }

    /// **Worker call** — input is unambiguous. Returns immediately without
    /// changing gate state.
    pub fn pass_through(&self) -> PassThroughOutcome {
        PassThroughOutcome::PassThrough
    }

    /// **Worker call** — input is ambiguous. Parks the calling task in
    /// `Waiting` state and blocks until either the operator provides an
    /// answer or the timeout elapses.
    ///
    /// Returns `Err` when the gate is already in a non-Idle state (callers
    /// must create a fresh gate per run).
    pub async fn park(&self, question: impl Into<String>) -> Result<ParkOutcome, String> {
        let question = question.into();
        let (tx, rx) = tokio::sync::oneshot::channel();

        let request = {
            let now = crate::time::now_unix_i64();
            let timeout_secs = self.timeout.as_secs() as i64;
            let id = ClarificationId::new();
            ClarificationRequest {
                id: id.clone(),
                question: question.clone(),
                created_at: now,
                deadline_at: now + timeout_secs,
            }
        };

        {
            let mut slot = self.slot.lock().unwrap_or_else(|p| p.into_inner());
            if !matches!(slot.state, GateState::Idle) {
                return Err(format!(
                    "gate already in state {:?}; create a new gate per run",
                    slot.state
                ));
            }
            slot.state = GateState::Waiting(request.clone());
            slot.tx = Some(tx);
        }

        tracing::info!(
            id = %request.id,
            question = %question,
            deadline_at = request.deadline_at,
            "clarification gate parked — waiting for operator answer",
        );

        // Wait for answer or timeout.
        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(answer)) => {
                tracing::info!(id = %request.id, "clarification gate answered — resuming worker");
                Ok(ParkOutcome::Answered(answer))
            }
            Ok(Err(_)) => {
                // Sender was dropped without sending — treat as timeout.
                let mut slot = self.slot.lock().unwrap_or_else(|p| p.into_inner());
                slot.state = GateState::TimedOut;
                slot.tx = None;
                tracing::warn!(id = %request.id, "clarification gate sender dropped — timeout");
                Ok(ParkOutcome::TimedOut)
            }
            Err(_elapsed) => {
                let mut slot = self.slot.lock().unwrap_or_else(|p| p.into_inner());
                slot.state = GateState::TimedOut;
                slot.tx = None;
                tracing::warn!(
                    id = %request.id,
                    timeout_secs = self.timeout.as_secs(),
                    "clarification gate timed out — worker unparked with TimedOut",
                );
                Ok(ParkOutcome::TimedOut)
            }
        }
    }

    /// **Answering surface call** — provide the operator's answer to the
    /// parked worker. Returns `Err(AnswerError)` when the gate is not
    /// waiting or the id does not match.
    pub fn answer(
        &self,
        id: &ClarificationId,
        answer: impl Into<String>,
    ) -> Result<(), AnswerError> {
        let answer = answer.into();
        let mut slot = self.slot.lock().unwrap_or_else(|p| p.into_inner());
        match &slot.state {
            GateState::Waiting(req) if &req.id == id => {
                // Take the sender out of the slot before transitioning state
                // (avoids a second lock cycle).
                let tx = slot.tx.take().expect("tx must be Some while Waiting");
                slot.state = GateState::Answered {
                    answer: answer.clone(),
                };
                // Ignore the error — receiver may have been cancelled by a
                // timeout race; the state transition is authoritative.
                let _ = tx.send(answer);
                Ok(())
            }
            GateState::Waiting(req) => Err(AnswerError::IdMismatch {
                expected: req.id.clone(),
                got: id.clone(),
            }),
            _ => Err(AnswerError::NotWaiting),
        }
    }
}

impl Default for ClarificationGate {
    fn default() -> Self {
        Self::default_timeout()
    }
}

impl std::fmt::Debug for ClarificationGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.state();
        f.debug_struct("ClarificationGate")
            .field("state", &state)
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// Determine whether a worker input should trigger a clarification park.
/// Returns `true` when the input carries explicit ambiguity markers.
///
/// This is a **lightweight heuristic** — operators integrate their own
/// LLM-side ambiguity signal (e.g. a structured response field) on top;
/// this function handles the headless / integration-test path where the
/// signal is a text marker.
pub fn is_ambiguous(input: &str) -> bool {
    const MARKERS: &[&str] = &[
        "[[ambiguous]]",
        "[[clarify]]",
        "[[needs-clarification]]",
        "AMBIGUOUS:",
        "CLARIFY:",
    ];
    let lower = input.to_lowercase();
    MARKERS.iter().any(|m| lower.contains(&m.to_lowercase()))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    // ── ClarificationId ───────────────────────────────────────────────────────

    #[test]
    fn clarification_id_is_unique_per_call() {
        let a = ClarificationId::new();
        let b = ClarificationId::new();
        // Uniqueness is probabilistic; two calls in the same millisecond may
        // share the ts component but differ in thread-id hash.
        assert_ne!(a, b, "two IDs generated in sequence must differ");
    }

    #[test]
    fn clarification_id_display_contains_prefix() {
        let id = ClarificationId::new();
        assert!(
            id.to_string().starts_with("clarify-"),
            "id must carry prefix"
        );
    }

    // ── is_ambiguous ──────────────────────────────────────────────────────────

    #[test]
    fn unambiguous_input_passes_through() {
        assert!(!is_ambiguous("deploy the staging cluster"));
        assert!(!is_ambiguous("summarise the last 10 commits"));
    }

    #[test]
    fn explicit_marker_triggers_ambiguity() {
        assert!(is_ambiguous("[[ambiguous]] which cluster do you mean?"));
        assert!(is_ambiguous("[[clarify]] staging or production?"));
        assert!(is_ambiguous("[[needs-clarification]] branch unclear"));
        assert!(is_ambiguous("AMBIGUOUS: multiple targets found"));
        assert!(is_ambiguous("CLARIFY: missing argument"));
    }

    #[test]
    fn marker_detection_is_case_insensitive() {
        assert!(is_ambiguous("[[AMBIGUOUS]] uppercase marker"));
        assert!(is_ambiguous("CLARIFY: uppercase variant"));
    }

    // ── pass_through ──────────────────────────────────────────────────────────

    #[test]
    fn pass_through_returns_pass_through_variant() {
        let gate = ClarificationGate::default_timeout();
        assert_eq!(gate.pass_through(), PassThroughOutcome::PassThrough);
    }

    #[test]
    fn pass_through_leaves_gate_idle() {
        let gate = ClarificationGate::default_timeout();
        gate.pass_through();
        assert_eq!(gate.state(), GateState::Idle);
    }

    // ── park + answer ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn parked_ambiguous_input_resumes_on_answer() {
        let gate = Arc::new(ClarificationGate::new(Duration::from_secs(10)));
        let gate2 = Arc::clone(&gate);

        // Spawn the worker that parks.
        let worker = tokio::spawn(async move {
            gate2
                .park("[[ambiguous]] which environment: staging or prod?")
                .await
                .expect("park must not error")
        });

        // Give the tokio scheduler a moment so `park` reaches the oneshot wait.
        tokio::task::yield_now().await;

        // Verify the gate is now Waiting.
        let pending = gate
            .pending_request()
            .expect("gate must be in Waiting state");
        assert!(pending.question.contains("which environment"));

        // Provide the answer.
        gate.answer(&pending.id, "staging")
            .expect("answer must succeed");

        // Worker must resume with the answer.
        let outcome = worker.await.expect("worker task panicked");
        assert_eq!(outcome, ParkOutcome::Answered("staging".to_string()));
        assert!(
            matches!(gate.state(), GateState::Answered { answer } if answer == "staging"),
            "gate must be in Answered state"
        );
    }

    #[tokio::test]
    async fn parked_gate_times_out_when_no_answer() {
        // Very short timeout so the test completes quickly.
        let gate = Arc::new(ClarificationGate::new(Duration::from_millis(50)));

        let outcome = gate
            .park("[[clarify]] which branch?")
            .await
            .expect("park must not error");

        assert_eq!(outcome, ParkOutcome::TimedOut);
        assert_eq!(gate.state(), GateState::TimedOut);
    }

    #[tokio::test]
    async fn unambiguous_input_passes_through_gate_stays_idle() {
        let gate = ClarificationGate::new(Duration::from_secs(5));
        // Unambiguous: pass_through, never park.
        let input = "restart the indexer";
        assert!(!is_ambiguous(input));
        let r = gate.pass_through();
        assert_eq!(r, PassThroughOutcome::PassThrough);
        assert_eq!(gate.state(), GateState::Idle);
    }

    // ── answer error paths ────────────────────────────────────────────────────

    #[test]
    fn answer_on_idle_gate_returns_not_waiting() {
        let gate = ClarificationGate::default_timeout();
        let id = ClarificationId::new();
        let err = gate.answer(&id, "ignored").unwrap_err();
        assert_eq!(err, AnswerError::NotWaiting);
    }

    #[tokio::test]
    async fn answer_with_wrong_id_returns_id_mismatch() {
        let gate = Arc::new(ClarificationGate::new(Duration::from_secs(10)));
        let gate2 = Arc::clone(&gate);

        let worker = tokio::spawn(async move { gate2.park("[[ambiguous]] target?").await });

        tokio::task::yield_now().await;

        let pending = gate.pending_request().expect("must be Waiting");
        let wrong_id = ClarificationId("clarify-0000-000000".to_string());
        assert_ne!(wrong_id, pending.id);

        let err = gate.answer(&wrong_id, "anything").unwrap_err();
        assert!(matches!(err, AnswerError::IdMismatch { .. }));

        // Clean up — answer with the correct id so the worker task ends.
        gate.answer(&pending.id, "staging")
            .expect("correct id must work");
        let _ = worker.await;
    }

    // ── gate reuse guard ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn park_on_non_idle_gate_returns_error() {
        let gate = Arc::new(ClarificationGate::new(Duration::from_secs(10)));
        let gate2 = Arc::clone(&gate);

        // Park the gate.
        let _worker =
            tokio::spawn(async move { gate2.park("[[ambiguous]] first question?").await });
        tokio::task::yield_now().await;

        // A second park on the same gate (not allowed — create a new gate).
        let err = gate
            .park("[[ambiguous]] second question?")
            .await
            .unwrap_err();
        assert!(
            err.contains("create a new gate per run"),
            "error must guide caller: {err}"
        );

        // Resolve the worker cleanly.
        if let Some(pending) = gate.pending_request() {
            let _ = gate.answer(&pending.id, "done");
        }
    }

    // ── state snapshot ────────────────────────────────────────────────────────

    #[test]
    fn fresh_gate_is_idle() {
        let gate = ClarificationGate::default_timeout();
        assert_eq!(gate.state(), GateState::Idle);
    }

    #[test]
    fn pending_request_is_none_when_idle() {
        let gate = ClarificationGate::default_timeout();
        assert!(gate.pending_request().is_none());
    }

    // ── ClarificationRequest serde ───────────────────────────────────────────

    #[test]
    fn clarification_request_serde_roundtrip() {
        let req = ClarificationRequest {
            id: ClarificationId("clarify-1234-abcdef".to_string()),
            question: "which env?".to_string(),
            created_at: 1_700_000_000,
            deadline_at: 1_700_000_300,
        };
        let json = serde_json::to_string(&req).expect("must serialise");
        let back: ClarificationRequest = serde_json::from_str(&json).expect("must deserialise");
        assert_eq!(back.id, req.id);
        assert_eq!(back.question, req.question);
        assert_eq!(back.created_at, req.created_at);
        assert_eq!(back.deadline_at, req.deadline_at);
    }
}
