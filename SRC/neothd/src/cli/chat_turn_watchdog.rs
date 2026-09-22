//! Request-local silence deadline for one admitted chat turn.
//!
//! This type owns no task and persists no state. The caller polls its actual
//! provider or stream future through [`TurnSilenceWatchdog::race`], gives its
//! actual observer a [`TurnProgressHandle`], and records only real provider
//! progress or emitted stream frames. Poll/read timeouts are deliberately not
//! a signal.

use std::{future::Future, pin::Pin, time::Duration};

use tokio::{
    sync::watch,
    time::{Instant, Sleep},
};

use super::chat_turn_pipeline::ChatTurnCancellation;

pub(crate) const TURN_SILENCE_TIMEOUT: Duration = Duration::from_secs(120);

/// Typed shared-turn outcome for a provider that made no meaningful progress.
/// Presentation layers may show retry guidance, but this error itself makes no
/// claim that retrying an already-started external provider call is automatic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TurnSilenceTimeout;

impl std::fmt::Display for TurnSilenceTimeout {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("chat turn exceeded the 120-second meaningful-progress deadline")
    }
}

impl std::error::Error for TurnSilenceTimeout {}

/// The one terminal observation from polling an in-flight provider operation.
///
/// `Cancelled` has priority over completion and expiry when the cancellation
/// gate is already observed closed. `SilenceExpired` closes that same gate so
/// later effect boundaries retain the existing request-local cancellation
/// contract.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TurnWatchdogPoll<T> {
    Completed(T),
    Cancelled,
    SilenceExpired,
}

/// Bounded, cloneable signal edge for the actual provider-stream observer.
///
/// A watch channel retains only the newest monotonic timestamp. It cannot turn
/// a burst of stream chunks into an unbounded request-local queue. Call this
/// only after a real provider progress event or a sanitized emitted frame.
#[derive(Clone)]
pub(crate) struct TurnProgressHandle {
    signal_state: watch::Sender<SignalState>,
}

impl TurnProgressHandle {
    pub(crate) fn meaningful_signal(&self) {
        let now = Instant::now();
        self.signal_state.send_modify(|state| {
            if state.expired {
                return;
            }
            if now.saturating_duration_since(state.last_signal) >= TURN_SILENCE_TIMEOUT {
                state.expired = true;
            } else {
                state.last_signal = now;
            }
        });
    }
}

/// Latest bounded signal state. `expired` is sticky: a receiver that was not
/// scheduled while a real stream stayed silent must not let a late event revive
/// the turn merely because both the watch update and timer are now ready.
#[derive(Clone, Copy)]
struct SignalState {
    last_signal: Instant,
    expired: bool,
}

/// A monotonic, request-local deadline with no detached background task.
///
/// The sleep is held and polled by the active turn. Therefore dropping this
/// value drops the timer, and a completed turn cannot leave a timer able to
/// affect another turn.
pub(crate) struct TurnSilenceWatchdog {
    cancellation: ChatTurnCancellation,
    progress: watch::Receiver<SignalState>,
    progress_handle: TurnProgressHandle,
    deadline: Pin<Box<Sleep>>,
    disarmed: bool,
}

impl TurnSilenceWatchdog {
    pub(crate) fn new(cancellation: ChatTurnCancellation) -> Self {
        let (signal_state, progress) = watch::channel(SignalState {
            last_signal: Instant::now(),
            expired: false,
        });
        Self {
            cancellation,
            progress,
            progress_handle: TurnProgressHandle { signal_state },
            deadline: Box::pin(tokio::time::sleep(TURN_SILENCE_TIMEOUT)),
            disarmed: false,
        }
    }

    /// Give the real provider-stream observer its bounded signal edge.
    pub(crate) fn progress_handle(&self) -> TurnProgressHandle {
        self.progress_handle.clone()
    }

    fn rearm_from_latest_signal(&mut self) -> bool {
        let signal = *self.progress.borrow_and_update();
        if signal.expired {
            return false;
        }
        self.deadline
            .as_mut()
            .reset(signal.last_signal + TURN_SILENCE_TIMEOUT);
        true
    }

    fn claim_silence_expiry(&self) -> bool {
        self.cancellation.try_close()
    }

    /// Poll one real in-flight operation against cancellation and silence.
    ///
    /// `biased` gives already-observed user/shutdown cancellation priority.
    /// Actual provider/stream progress re-arms the deadline without completing
    /// this method; the active future stays pinned and remains watched until it
    /// reaches a terminal result. The expiry arm rechecks the shared gate
    /// before closing it, covering a cancellation that became visible while
    /// `select!` chose the deadline.
    pub(crate) async fn race<T>(
        &mut self,
        operation: impl Future<Output = T>,
    ) -> TurnWatchdogPoll<T> {
        self.race_inner(operation, true).await
    }

    /// Poll a nonterminal response-production stage. A completed operation
    /// leaves this request-local deadline armed so its caller can carry the
    /// same silence budget into the immediately following post-reply stage.
    pub(crate) async fn race_nonterminal<T>(
        &mut self,
        operation: impl Future<Output = T>,
    ) -> TurnWatchdogPoll<T> {
        self.race_inner(operation, false).await
    }

    async fn race_inner<T>(
        &mut self,
        operation: impl Future<Output = T>,
        disarm_on_completion: bool,
    ) -> TurnWatchdogPoll<T> {
        debug_assert!(!self.disarmed, "a disarmed chat-turn watchdog was reused");
        tokio::pin!(operation);
        let cancellation = self.cancellation.clone();
        let outcome = loop {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => break TurnWatchdogPoll::Cancelled,
                progress_changed = self.progress.changed() => {
                    debug_assert!(progress_changed.is_ok(), "watchdog retains its progress sender");
                    if !self.rearm_from_latest_signal() {
                        break if self.claim_silence_expiry() {
                            TurnWatchdogPoll::SilenceExpired
                        } else {
                            TurnWatchdogPoll::Cancelled
                        };
                    }
                }
                _ = &mut self.deadline => {
                    break if self.claim_silence_expiry() {
                        TurnWatchdogPoll::SilenceExpired
                    } else {
                        TurnWatchdogPoll::Cancelled
                    };
                }
                value = &mut operation => break TurnWatchdogPoll::Completed(value),
            }
        };
        if disarm_on_completion || !matches!(&outcome, TurnWatchdogPoll::Completed(_)) {
            self.disarm();
        }
        outcome
    }

    /// Stop this deadline before a caller takes any terminal path that does
    /// not use `race` (for example a pre-dispatch refusal).
    pub(crate) fn disarm(&mut self) {
        self.disarmed = true;
    }

    #[cfg(test)]
    fn is_disarmed(&self) -> bool {
        self.disarmed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn expires_after_a_full_silence_window_and_closes_the_shared_gate() {
        let cancellation = ChatTurnCancellation::default();
        let mut watchdog = TurnSilenceWatchdog::new(cancellation.clone());
        tokio::time::advance(TURN_SILENCE_TIMEOUT).await;

        assert_eq!(
            watchdog.race(std::future::pending::<()>()).await,
            TurnWatchdogPoll::SilenceExpired
        );
        assert!(cancellation.is_closed());
        assert!(watchdog.is_disarmed());
    }

    #[tokio::test(start_paused = true)]
    async fn repeated_real_signals_keep_one_inflight_operation_alive_past_120_seconds() {
        let cancellation = ChatTurnCancellation::default();
        let mut watchdog = TurnSilenceWatchdog::new(cancellation);
        let progress = watchdog.progress_handle();
        let (done, receiver) = tokio::sync::oneshot::channel::<&'static str>();
        let raced = tokio::spawn(async move {
            watchdog
                .race(async move { receiver.await.unwrap() })
                .await
        });
        tokio::task::yield_now().await;

        for _ in 0..3 {
            tokio::time::advance(Duration::from_secs(119)).await;
            progress.meaningful_signal();
            tokio::task::yield_now().await;
        }
        done.send("provider completed").unwrap();

        assert_eq!(
            raced.await.unwrap(),
            TurnWatchdogPoll::Completed("provider completed")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn coalesced_timely_signals_rearm_even_when_the_receiver_has_not_polled_yet() {
        let cancellation = ChatTurnCancellation::default();
        let mut watchdog = TurnSilenceWatchdog::new(cancellation);
        let progress = watchdog.progress_handle();

        for _ in 0..3 {
            tokio::time::advance(Duration::from_secs(119)).await;
            progress.meaningful_signal();
        }

        assert_eq!(
            watchdog.race(async { "provider completed" }).await,
            TurnWatchdogPoll::Completed("provider completed")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn late_signal_after_a_full_silence_window_cannot_revive_the_turn() {
        let cancellation = ChatTurnCancellation::default();
        let mut watchdog = TurnSilenceWatchdog::new(cancellation.clone());
        let progress = watchdog.progress_handle();
        tokio::time::advance(Duration::from_secs(121)).await;
        progress.meaningful_signal();

        assert_eq!(
            watchdog.race(async { "late completion" }).await,
            TurnWatchdogPoll::SilenceExpired
        );
        assert!(cancellation.is_closed());
    }

    #[tokio::test(start_paused = true)]
    async fn user_cancellation_wins_an_expiry_race() {
        let cancellation = ChatTurnCancellation::default();
        let mut watchdog = TurnSilenceWatchdog::new(cancellation.clone());
        cancellation.close();
        tokio::time::advance(TURN_SILENCE_TIMEOUT).await;

        assert_eq!(
            watchdog.race(std::future::pending::<()>()).await,
            TurnWatchdogPoll::Cancelled
        );
        assert!(watchdog.is_disarmed());
    }

    #[tokio::test(start_paused = true)]
    async fn read_polling_without_a_progress_signal_still_expires() {
        let cancellation = ChatTurnCancellation::default();
        let mut watchdog = TurnSilenceWatchdog::new(cancellation.clone());
        let raced = tokio::spawn(async move {
            watchdog
                .race(async {
                    loop {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                })
                .await
        });
        tokio::task::yield_now().await;
        tokio::time::advance(TURN_SILENCE_TIMEOUT).await;

        assert_eq!(raced.await.unwrap(), TurnWatchdogPoll::SilenceExpired);
        assert!(cancellation.is_closed());
    }

    #[tokio::test(start_paused = true)]
    async fn already_expired_deadline_beats_a_simultaneously_ready_completion() {
        let cancellation = ChatTurnCancellation::default();
        let mut watchdog = TurnSilenceWatchdog::new(cancellation.clone());
        tokio::time::advance(TURN_SILENCE_TIMEOUT).await;

        assert_eq!(
            watchdog.race(async { "late completion" }).await,
            TurnWatchdogPoll::SilenceExpired
        );
        assert!(cancellation.is_closed());
    }

    #[tokio::test(start_paused = true)]
    async fn completed_operation_disarms_without_later_cancellation() {
        let cancellation = ChatTurnCancellation::default();
        let mut watchdog = TurnSilenceWatchdog::new(cancellation.clone());

        assert_eq!(
            watchdog.race(async { 7_u8 }).await,
            TurnWatchdogPoll::Completed(7)
        );
        tokio::time::advance(TURN_SILENCE_TIMEOUT).await;
        assert!(!cancellation.is_closed());
        assert!(watchdog.is_disarmed());
    }

    #[tokio::test(start_paused = true)]
    async fn nonterminal_completion_carries_the_same_deadline_into_post_reply_work() {
        let cancellation = ChatTurnCancellation::default();
        let mut watchdog = TurnSilenceWatchdog::new(cancellation.clone());

        assert_eq!(
            watchdog.race_nonterminal(async { "provider completed" }).await,
            TurnWatchdogPoll::Completed("provider completed")
        );
        assert!(!watchdog.is_disarmed());
        tokio::time::advance(TURN_SILENCE_TIMEOUT).await;

        assert_eq!(
            watchdog.race(std::future::pending::<()>()).await,
            TurnWatchdogPoll::SilenceExpired
        );
        assert!(cancellation.is_closed());
    }

    #[tokio::test(start_paused = true)]
    async fn dropped_unpolled_watchdog_cannot_close_its_turn_later() {
        let cancellation = ChatTurnCancellation::default();
        let watchdog = TurnSilenceWatchdog::new(cancellation.clone());
        drop(watchdog);

        tokio::time::advance(TURN_SILENCE_TIMEOUT).await;
        assert!(!cancellation.is_closed());
    }
}
