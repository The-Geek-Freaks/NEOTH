//! A2 bridge-owned, authorized visible-text turn adapter.
//!
//! This module deliberately consumes the existing [`GuiChatBridge`] lifecycle
//! instead of constructing a provider request.  The bridge retains every
//! sealed preflight/decision/start/cancel capability; this adapter sees only
//! visible deltas and a typed terminal state.

use super::conversation_session::{ConversationCleanupFuture, ConversationTaskRegistry};
use super::gui_chat_bridge::{
    GuiChatBridge, GuiChatBridgeDecisionOutcome, GuiChatBridgeDecisionReceipt, GuiChatBridgeError,
    GuiChatBridgeEvent, GuiChatBridgeEventSink, GuiChatBridgePreflight,
    GuiChatBridgePreflightInput, GuiChatBridgePreflightReceipt, GuiChatBridgeResult,
    GuiChatBridgeSubscription, GuiChatBridgeTurn, GuiChatConsentDecision, GuiChatConsentPrompt,
    GuiChatSurface, GuiChatTerminalState, GuiChatTurnId,
};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};

/// A confirmation the owning surface must present verbatim.  The sealed
/// receipt cannot be converted into a provider or microphone capability.
pub(crate) struct AuthorizedTextTurnConfirmation {
    receipt: GuiChatBridgePreflightReceipt,
    pub(crate) prompt: GuiChatConsentPrompt,
    surface: GuiChatSurface,
}

/// A started bridge turn with exactly one same-session subscription.
///
/// `AuthorizedTextTurn` is owned by the conversation task. That task normally
/// calls [`Self::cancel_and_settle`] on every cancellation/error exit. If the
/// consumer drops it first, its already-running supervisor receives the sealed
/// turn through a channel and performs the same cancellation settlement.
#[must_use = "a running authorized text turn must be cancelled and settled by its conversation owner"]
pub(crate) struct AuthorizedTextTurn {
    turn: GuiChatBridgeTurn,
    subscription: GuiChatBridgeSubscription,
    next_sequence: u64,
    terminal: Option<GuiChatTerminalState>,
    owner: Arc<AuthorizedTextTurnOwner>,
}

struct DetachedTurn {
    turn: GuiChatBridgeTurn,
    subscription: GuiChatBridgeSubscription,
    next_sequence: u64,
}

enum CleanupCommand {
    Settle {
        detached: DetachedTurn,
        completion: oneshot::Sender<GuiChatBridgeResult<SettledAuthorizedTextTurn>>,
    },
    Shutdown {
        completion: oneshot::Sender<()>,
    },
}

/// This owner is the only bridge context used by both the normal and dropped
/// consumer paths. The bounded channel holds at most one dropped turn because
/// one supervisor admits one active conversation turn at a time.
struct AuthorizedTextTurnOwner {
    bridge: Arc<dyn GuiChatBridge>,
    cleanup_tx: mpsc::Sender<CleanupCommand>,
    pending: Mutex<Option<oneshot::Receiver<GuiChatBridgeResult<SettledAuthorizedTextTurn>>>>,
    active: Mutex<bool>,
}

impl AuthorizedTextTurnOwner {
    fn admit_single_turn(&self) -> GuiChatBridgeResult<()> {
        let mut active = self
            .active
            .lock()
            .expect("authorized text turn active mutex");
        if *active {
            return Err(GuiChatBridgeError::invalid(
                "authorized_text_turn_already_active",
            ));
        }
        *active = true;
        Ok(())
    }

    fn release_after_observed_terminal(&self) {
        *self
            .active
            .lock()
            .expect("authorized text turn active mutex") = false;
    }
}

/// Durable owner for all adapter turns of one conversation session. The task
/// is created before a turn can be started and retains `Arc<GuiChatBridge>`;
/// dropping a consumer handle only enqueues sealed bridge state to this owner.
/// The session must await [`Self::wait_for_dropped_turn`] before it declares
/// cancellation complete.
pub(crate) struct AuthorizedTextTurnSupervisor {
    owner: Arc<AuthorizedTextTurnOwner>,
}

impl AuthorizedTextTurnSupervisor {
    pub(crate) async fn new(
        bridge: Arc<dyn GuiChatBridge>,
        task_registry: ConversationTaskRegistry,
    ) -> GuiChatBridgeResult<Self> {
        let (cleanup_tx, mut cleanup_requests) = mpsc::channel(1);
        let owner = Arc::new(AuthorizedTextTurnOwner {
            bridge,
            cleanup_tx,
            pending: Mutex::new(None),
            active: Mutex::new(false),
        });
        let worker_owner = Arc::clone(&owner);
        let cleanup_task: ConversationCleanupFuture = Box::pin(async move {
            while let Some(command) = cleanup_requests.recv().await {
                match command {
                    CleanupCommand::Settle {
                        detached,
                        completion,
                    } => {
                        let _ =
                            completion.send(settle_detached_turn(&worker_owner, detached).await);
                    }
                    CleanupCommand::Shutdown { completion } => {
                        let _ = completion.send(());
                        break;
                    }
                }
            }
        });
        task_registry
            .spawn_cleanup(cleanup_task)
            .await
            .map_err(|_| {
                GuiChatBridgeError::invalid("authorized_text_turn_cleanup_registration_failed")
            })?;
        Ok(Self { owner })
    }

    pub(crate) async fn start(
        &self,
        input: GuiChatBridgePreflightInput,
    ) -> GuiChatBridgeResult<AuthorizedTextTurnStart> {
        start_authorized_text_turn(self, input).await
    }

    pub(crate) async fn decide(
        &self,
        confirmation: AuthorizedTextTurnConfirmation,
        decision: GuiChatConsentDecision,
    ) -> GuiChatBridgeResult<AuthorizedTextTurnStart> {
        decide_authorized_text_turn(self, confirmation, decision).await
    }

    /// Await the terminal settlement scheduled by a dropped consumer handle.
    /// A closed result channel or failed drop delivery is never a cancellation
    /// success and must remain visible to the owning conversation session.
    pub(crate) async fn wait_for_dropped_turn(
        &self,
    ) -> GuiChatBridgeResult<SettledAuthorizedTextTurn> {
        let completion = self
            .owner
            .pending
            .lock()
            .expect("authorized text turn pending mutex")
            .take()
            .ok_or_else(|| {
                GuiChatBridgeError::invalid("authorized_text_turn_cleanup_not_pending")
            })?;
        completion
            .await
            .map_err(|_| GuiChatBridgeError::invalid("authorized_text_turn_cleanup_owner_closed"))?
    }

    /// Consume a dropped-turn completion when one exists.  This is for a
    /// session teardown which cannot know whether a stage returned normally
    /// after its own settlement or dropped its consumer on an error path.
    /// It retains the strict API above for callers that require a completion.
    pub(crate) async fn wait_for_dropped_turn_if_pending(
        &self,
    ) -> GuiChatBridgeResult<Option<SettledAuthorizedTextTurn>> {
        let completion = self
            .owner
            .pending
            .lock()
            .expect("authorized text turn pending mutex")
            .take();
        let Some(completion) = completion else {
            return Ok(None);
        };
        completion
            .await
            .map_err(|_| GuiChatBridgeError::invalid("authorized_text_turn_cleanup_owner_closed"))?
            .map(Some)
    }

    /// The daemon/session root calls this only after every turn is terminal or
    /// every dropped-turn completion was awaited. It wakes an idle worker and
    /// waits for its terminal acknowledgement. The retained daemon registry
    /// then performs the actual join during `GuiChatRuntime::close_and_drain`
    /// before WAL shutdown; this adapter never owns or detaches that task.
    pub(crate) async fn shutdown_and_join(self) -> GuiChatBridgeResult<()> {
        // The retained cleanup worker owns one stable reference in addition
        // to this supervisor. Any third reference is an active consumer and
        // must keep shutdown fail-closed until its terminal is observed.
        if Arc::strong_count(&self.owner) != 2 {
            return Err(GuiChatBridgeError::invalid(
                "authorized_text_turn_shutdown_with_live_consumer",
            ));
        }
        if self
            .owner
            .pending
            .lock()
            .expect("authorized text turn pending mutex")
            .is_some()
        {
            return Err(GuiChatBridgeError::invalid(
                "authorized_text_turn_shutdown_with_unobserved_settlement",
            ));
        }
        let (completion_tx, completion_rx) = oneshot::channel();
        self.owner
            .cleanup_tx
            .send(CleanupCommand::Shutdown {
                completion: completion_tx,
            })
            .await
            .map_err(|_| {
                GuiChatBridgeError::invalid("authorized_text_turn_cleanup_owner_closed")
            })?;
        completion_rx.await.map_err(|_| {
            GuiChatBridgeError::invalid("authorized_text_turn_cleanup_owner_closed")
        })?;
        Ok(())
    }
}

/// Start outcome.  A caller must surface `ConfirmationRequired`; it may not
/// choose an allow decision on behalf of an operator.
pub(crate) enum AuthorizedTextTurnStart {
    Ready(AuthorizedTextTurn),
    ConfirmationRequired(AuthorizedTextTurnConfirmation),
    /// The real bridge rejected the sealed provider confirmation.  No turn
    /// was started and the microphone conversation may continue listening.
    Denied,
}

/// Terminal facts that the conversation owner is allowed to observe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthorizedTextTurnTerminal {
    Complete,
    Cancelled,
    Failed,
    CrashUnknown,
    Indeterminate,
}

/// Private evidence that the bridge's actual terminal after a cancel request
/// was `Cancelled`. It is deliberately non-cloneable/non-serializable and has
/// no public constructor, so WAL consumers cannot fabricate a cancellation.
pub(crate) struct CancelProof {
    turn_id_sha256: String,
}

impl CancelProof {
    pub(crate) fn turn_id_sha256(&self) -> &str {
        &self.turn_id_sha256
    }

    /// Move-only WAL handoff. No constructor or clone exists outside the
    /// observed bridge-terminal path.
    pub(crate) fn into_turn_id_sha256(self) -> String {
        self.turn_id_sha256
    }
}

/// The observed result of a cancel settlement. A raced complete/failed
/// terminal remains visible here but has no `CancelProof`; only a real
/// `Cancelled` terminal reached after bridge cancellation mints one.
pub(crate) struct SettledAuthorizedTextTurn {
    turn_id_sha256: String,
    terminal_kind: AuthorizedTextTurnTerminal,
    cancel_proof: Option<CancelProof>,
}

impl SettledAuthorizedTextTurn {
    pub(crate) fn turn_id_sha256(&self) -> &str {
        &self.turn_id_sha256
    }

    pub(crate) fn terminal_kind(&self) -> AuthorizedTextTurnTerminal {
        self.terminal_kind
    }

    pub(crate) fn cancel_proof(&self) -> Option<&CancelProof> {
        self.cancel_proof.as_ref()
    }

    /// This consuming handoff is for the microphone/WAL admission only; its
    /// constructor remains private to the actual bridge-terminal observer.
    pub(crate) fn into_cancel_proof(self) -> Option<CancelProof> {
        self.cancel_proof
    }
}

fn from_settled_bridge_terminal(
    turn_id: GuiChatTurnId,
    terminal: GuiChatTerminalState,
    cancelled_by_this_owner: bool,
) -> SettledAuthorizedTextTurn {
    let mut hasher = Sha256::new();
    hasher.update(b"neoth/a2/settled-authorized-turn/v1\0");
    hasher.update(turn_id.as_uuid().as_bytes());
    let turn_id_sha256 = hex::encode(hasher.finalize());
    let terminal_kind = terminal.into();
    let cancel_proof =
        if cancelled_by_this_owner && matches!(terminal, GuiChatTerminalState::Cancelled) {
            Some(CancelProof {
                turn_id_sha256: turn_id_sha256.clone(),
            })
        } else {
            None
        };
    SettledAuthorizedTextTurn {
        turn_id_sha256,
        terminal_kind,
        cancel_proof,
    }
}

impl From<GuiChatTerminalState> for AuthorizedTextTurnTerminal {
    fn from(value: GuiChatTerminalState) -> Self {
        match value {
            GuiChatTerminalState::Complete => Self::Complete,
            GuiChatTerminalState::Cancelled => Self::Cancelled,
            GuiChatTerminalState::Failed => Self::Failed,
            GuiChatTerminalState::CrashUnknown => Self::CrashUnknown,
            GuiChatTerminalState::Indeterminate => Self::Indeterminate,
        }
    }
}

/// The only content plane exported by this adapter.  Provider reasoning,
/// notices, recall, throughput and provider identity stay behind the bridge.
pub(crate) trait AuthorizedTextTurnSink: Send {
    fn visible_delta(&mut self, text: &str) -> Result<(), &'static str>;
    fn terminal(&mut self, terminal: AuthorizedTextTurnTerminal) -> Result<(), &'static str>;
}

/// Ask the existing bridge to preflight an already-bound GUI/daemon request.
/// `input` must come from the owning daemon surface; media code does not build
/// provider, endpoint, attachment, or credential inputs.
pub(crate) async fn start_authorized_text_turn(
    supervisor: &AuthorizedTextTurnSupervisor,
    input: GuiChatBridgePreflightInput,
) -> GuiChatBridgeResult<AuthorizedTextTurnStart> {
    let surface = input.origin_surface;
    match supervisor.owner.bridge.preflight(input).await? {
        GuiChatBridgePreflight::Ready { decision } => {
            open_authorized_text_turn(Arc::clone(&supervisor.owner), decision, surface)
                .await
                .map(AuthorizedTextTurnStart::Ready)
        }
        GuiChatBridgePreflight::ConfirmationRequired { receipt, prompt } => Ok(
            AuthorizedTextTurnStart::ConfirmationRequired(AuthorizedTextTurnConfirmation {
                receipt,
                prompt,
                surface,
            }),
        ),
    }
}

/// Continue only after the owning UI supplied the exact decision for the
/// sealed preflight.  Denial is a normal typed outcome and cannot start work.
pub(crate) async fn decide_authorized_text_turn(
    supervisor: &AuthorizedTextTurnSupervisor,
    confirmation: AuthorizedTextTurnConfirmation,
    decision: GuiChatConsentDecision,
) -> GuiChatBridgeResult<AuthorizedTextTurnStart> {
    match supervisor
        .owner
        .bridge
        .decide(confirmation.receipt, decision)
        .await?
    {
        GuiChatBridgeDecisionOutcome::Denied => Ok(AuthorizedTextTurnStart::Denied),
        GuiChatBridgeDecisionOutcome::Approved(decision) => open_authorized_text_turn(
            Arc::clone(&supervisor.owner),
            decision,
            confirmation.surface,
        )
        .await
        .map(AuthorizedTextTurnStart::Ready),
    }
}

async fn open_authorized_text_turn(
    owner: Arc<AuthorizedTextTurnOwner>,
    decision: GuiChatBridgeDecisionReceipt,
    surface: GuiChatSurface,
) -> GuiChatBridgeResult<AuthorizedTextTurn> {
    // This is deliberately immediately before `bridge.start`: no second
    // preflight/decision path can create a second provider turn for one owner.
    owner.admit_single_turn()?;
    let turn = match owner.bridge.start(decision).await {
        Ok(turn) => turn,
        Err(error) => {
            owner.release_after_observed_terminal();
            return Err(error);
        }
    };
    // `start` seals the cursor for this turn.  The later exchange response is
    // an attachment upper bound and can already be ahead of visible deltas;
    // using it here would skip speech that the owner has never received.
    let start_cursor = turn.metadata.latest_sequence;
    let subscription = match owner
        .bridge
        .exchange_same_session_attach(&turn, surface)
        .await
    {
        Ok(subscription) => subscription,
        Err(exchange_error) => {
            return settle_started_turn_after_exchange_failure(
                &owner,
                turn,
                surface,
                start_cursor,
                exchange_error,
            )
            .await;
        }
    };
    Ok(AuthorizedTextTurn {
        next_sequence: start_cursor,
        turn,
        subscription,
        terminal: None,
        owner,
    })
}

/// A successful `start` has admitted a real provider turn.  If the first
/// attach exchange fails, it must be closed through the bridge and observed to
/// a terminal state before this adapter returns.  A second exchange is only a
/// settlement attachment; it starts at the sealed start cursor so no emitted
/// visible delta is skipped.  If the bridge cannot expose that settlement, the
/// result is explicitly indeterminate rather than leaking a live turn behind
/// the original exchange error.
async fn settle_started_turn_after_exchange_failure(
    owner: &Arc<AuthorizedTextTurnOwner>,
    turn: GuiChatBridgeTurn,
    surface: GuiChatSurface,
    start_cursor: u64,
    _exchange_error: GuiChatBridgeError,
) -> GuiChatBridgeResult<AuthorizedTextTurn> {
    owner.bridge.cancel(&turn).await.map_err(|_| {
        GuiChatBridgeError::invalid("authorized_text_turn_exchange_cleanup_cancel_failed")
    })?;
    let subscription = owner
        .bridge
        .exchange_same_session_attach(&turn, surface)
        .await
        .map_err(|_| {
            GuiChatBridgeError::invalid("authorized_text_turn_exchange_cleanup_unsettled")
        })?;
    let mut settlement = SettlementForwarder {
        latest_sequence: start_cursor,
        terminal: None,
    };
    let attach_result = owner
        .bridge
        .attach(subscription, start_cursor, &mut settlement)
        .await;
    // A terminal delivered before a later transport/sink error is authoritative
    // and settles the started turn.  Otherwise the bridge could not prove
    // closure, so never hide that state behind the original exchange error.
    if settlement.terminal.is_some() {
        owner.release_after_observed_terminal();
        return Err(GuiChatBridgeError::invalid(
            "authorized_text_turn_exchange_failed_after_settlement",
        ));
    }
    attach_result.map_err(|_| {
        GuiChatBridgeError::invalid("authorized_text_turn_exchange_cleanup_unsettled")
    })?;
    Err(GuiChatBridgeError::invalid(
        "authorized_text_turn_exchange_cleanup_unsettled",
    ))
}

impl AuthorizedTextTurn {
    /// Deliver one attached bridge interval.  Only `Delta` and `Terminal`
    /// reach `sink`; the bridge owns all other provider/UI event categories.
    pub(crate) async fn attach_visible(
        &mut self,
        sink: &mut dyn AuthorizedTextTurnSink,
    ) -> GuiChatBridgeResult<()> {
        if self.terminal.is_some() {
            return Ok(());
        }
        let mut forwarder = VisibleForwarder {
            sink,
            latest_sequence: self.next_sequence,
            terminal: None,
        };
        let attach_result = self
            .owner
            .bridge
            .attach(
                self.subscription.clone(),
                self.next_sequence,
                &mut forwarder,
            )
            .await;
        // Bridge delivery is allowed to fail after forwarding frames.  Commit
        // both cursor and terminal before propagating that error, otherwise a
        // retry can replay speech already sent to the user.
        self.next_sequence = forwarder.latest_sequence;
        if self.terminal.is_none() {
            self.terminal = forwarder.terminal;
        }
        if self.terminal.is_some() {
            self.owner.release_after_observed_terminal();
        }
        attach_result
    }

    /// Request bridge cancellation and consume the same subscription until an
    /// explicit terminal arrives.  No visible output is forwarded during
    /// settlement, preventing stale text from reaching sentence batching.
    pub(crate) async fn cancel_and_settle(
        &mut self,
    ) -> GuiChatBridgeResult<SettledAuthorizedTextTurn> {
        if let Some(terminal) = self.terminal {
            return Ok(from_settled_bridge_terminal(
                self.turn.metadata.turn_id,
                terminal,
                false,
            ));
        }
        self.owner.bridge.cancel(&self.turn).await?;
        let mut settlement = SettlementForwarder {
            latest_sequence: self.next_sequence,
            terminal: None,
        };
        let attach_result = self
            .owner
            .bridge
            .attach(
                self.subscription.clone(),
                self.next_sequence,
                &mut settlement,
            )
            .await;
        self.next_sequence = settlement.latest_sequence;
        if self.terminal.is_none() {
            self.terminal = settlement.terminal;
        }
        // Preserve a terminal received before a subsequent attach error.  It
        // is stronger evidence than the later transport failure.
        if let Some(terminal) = self.terminal {
            self.owner.release_after_observed_terminal();
            return Ok(from_settled_bridge_terminal(
                self.turn.metadata.turn_id,
                terminal,
                true,
            ));
        }
        attach_result?;
        let terminal = self
            .terminal
            .ok_or_else(|| GuiChatBridgeError::invalid("authorized_text_turn_cancel_unsettled"))?;
        Ok(from_settled_bridge_terminal(
            self.turn.metadata.turn_id,
            terminal,
            true,
        ))
    }
}

impl Drop for AuthorizedTextTurn {
    fn drop(&mut self) {
        if self.terminal.is_some() {
            return;
        }
        let detached = DetachedTurn {
            turn: self.turn.clone(),
            subscription: self.subscription.clone(),
            next_sequence: self.next_sequence,
        };
        let (completion_tx, completion_rx) = oneshot::channel();
        let already_pending = {
            let mut pending = self
                .owner
                .pending
                .lock()
                .expect("authorized text turn pending mutex");
            if pending.is_some() {
                true
            } else {
                *pending = Some(completion_rx);
                false
            }
        };
        if already_pending {
            let _ = completion_tx.send(Err(GuiChatBridgeError::invalid(
                "authorized_text_turn_cleanup_delivery_failed",
            )));
            return;
        }
        // Capacity is one by the one-active-turn supervisor invariant. A full
        // or closed channel is still returned through the pending completion;
        // `Drop` never panics, aborts, or pretends that cancellation occurred.
        let command = CleanupCommand::Settle {
            detached,
            completion: completion_tx,
        };
        if let Err(error) = self.owner.cleanup_tx.try_send(command) {
            if let CleanupCommand::Settle { completion, .. } = error.into_inner() {
                let _ = completion.send(Err(GuiChatBridgeError::invalid(
                    "authorized_text_turn_cleanup_delivery_failed",
                )));
            }
        }
    }
}

async fn settle_detached_turn(
    owner: &Arc<AuthorizedTextTurnOwner>,
    detached: DetachedTurn,
) -> GuiChatBridgeResult<SettledAuthorizedTextTurn> {
    owner.bridge.cancel(&detached.turn).await?;
    let mut settlement = SettlementForwarder {
        latest_sequence: detached.next_sequence,
        terminal: None,
    };
    let attach_result = owner
        .bridge
        .attach(
            detached.subscription,
            detached.next_sequence,
            &mut settlement,
        )
        .await;
    // A bridge terminal observed before a later transport error is final.
    if let Some(terminal) = settlement.terminal {
        owner.release_after_observed_terminal();
        return Ok(from_settled_bridge_terminal(
            detached.turn.metadata.turn_id,
            terminal,
            true,
        ));
    }
    attach_result?;
    Err(GuiChatBridgeError::invalid(
        "authorized_text_turn_cancel_unsettled",
    ))
}

struct VisibleForwarder<'a> {
    sink: &'a mut dyn AuthorizedTextTurnSink,
    latest_sequence: u64,
    terminal: Option<GuiChatTerminalState>,
}

impl GuiChatBridgeEventSink for VisibleForwarder<'_> {
    fn on_event(&mut self, event: GuiChatBridgeEvent) -> GuiChatBridgeResult<()> {
        match event {
            GuiChatBridgeEvent::Delta { sequence, text, .. } => {
                self.latest_sequence = self.latest_sequence.max(sequence);
                self.sink
                    .visible_delta(&text)
                    .map_err(GuiChatBridgeError::invalid)?;
            }
            GuiChatBridgeEvent::Terminal {
                sequence, state, ..
            } => {
                self.latest_sequence = self.latest_sequence.max(sequence);
                let terminal = state.into();
                self.sink
                    .terminal(terminal)
                    .map_err(GuiChatBridgeError::invalid)?;
                self.terminal = Some(state);
            }
            event => self.latest_sequence = self.latest_sequence.max(event_sequence(&event)),
        }
        Ok(())
    }
}

struct SettlementForwarder {
    latest_sequence: u64,
    terminal: Option<GuiChatTerminalState>,
}

impl GuiChatBridgeEventSink for SettlementForwarder {
    fn on_event(&mut self, event: GuiChatBridgeEvent) -> GuiChatBridgeResult<()> {
        self.latest_sequence = self.latest_sequence.max(event_sequence(&event));
        if let GuiChatBridgeEvent::Terminal { state, .. } = event {
            self.terminal = Some(state);
        }
        Ok(())
    }
}

fn event_sequence(event: &GuiChatBridgeEvent) -> u64 {
    match event {
        GuiChatBridgeEvent::Accepted { sequence, .. }
        | GuiChatBridgeEvent::PhaseChanged { sequence, .. }
        | GuiChatBridgeEvent::Notice { sequence, .. }
        | GuiChatBridgeEvent::TurnSilenceTimeout { sequence, .. }
        | GuiChatBridgeEvent::Delta { sequence, .. }
        | GuiChatBridgeEvent::ReasoningDelta { sequence, .. }
        | GuiChatBridgeEvent::ReasoningCheckpoint { sequence, .. }
        | GuiChatBridgeEvent::ReasoningState { sequence, .. }
        | GuiChatBridgeEvent::ProviderDone { sequence, .. }
        | GuiChatBridgeEvent::CancelRequested { sequence, .. }
        | GuiChatBridgeEvent::RecallChipBatch { sequence, .. }
        | GuiChatBridgeEvent::ThroughputState { sequence, .. }
        | GuiChatBridgeEvent::Terminal { sequence, .. } => *sequence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::gui_chat_bridge::{
        GuiChatRequestId, GuiChatSubscriptionMetadata, GuiChatTurnId, GuiChatTurnMetadata,
    };
    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingSink {
        text: Vec<String>,
        terminal: Vec<AuthorizedTextTurnTerminal>,
    }

    impl AuthorizedTextTurnSink for RecordingSink {
        fn visible_delta(&mut self, text: &str) -> Result<(), &'static str> {
            self.text.push(text.to_owned());
            Ok(())
        }

        fn terminal(&mut self, terminal: AuthorizedTextTurnTerminal) -> Result<(), &'static str> {
            self.terminal.push(terminal);
            Ok(())
        }
    }

    fn turn_metadata(cursor: u64) -> GuiChatTurnMetadata {
        GuiChatTurnMetadata {
            boot_id: "a2-test-boot".into(),
            turn_id: GuiChatTurnId(uuid::Uuid::now_v7()),
            origin_surface: GuiChatSurface::Main,
            phase: crate::daemon::gui_chat_bridge::GuiChatPhase::Receiving,
            latest_sequence: cursor,
        }
    }

    fn subscription(cursor: u64) -> GuiChatSubscriptionMetadata {
        GuiChatSubscriptionMetadata {
            boot_id: "a2-test-boot".into(),
            turn_id: GuiChatTurnId(uuid::Uuid::now_v7()),
            surface: GuiChatSurface::Main,
            generation: 1,
            latest_sequence: cursor,
        }
    }

    fn turn(cursor: u64) -> GuiChatBridgeTurn {
        GuiChatBridgeTurn::from_live(turn_metadata(cursor), vec![1])
    }

    fn attached(cursor: u64) -> GuiChatBridgeSubscription {
        GuiChatBridgeSubscription::from_live(subscription(cursor), vec![2])
    }

    fn decision() -> GuiChatBridgeDecisionReceipt {
        GuiChatBridgeDecisionReceipt::from_live(vec![3])
    }

    fn input() -> GuiChatBridgePreflightInput {
        GuiChatBridgePreflightInput {
            request_id: GuiChatRequestId::new(),
            session_id: "test-session".into(),
            origin_surface: GuiChatSurface::Main,
            message: "test".into(),
            model: None,
            skill_id: None,
            incognito: false,
            reasoning_display: false,
            attachment_paths: Vec::new(),
        }
    }

    fn task_registry() -> ConversationTaskRegistry {
        ConversationTaskRegistry::default()
    }

    async fn drain_registry(registry: &ConversationTaskRegistry) {
        registry.drain().await.expect("retained registry drains");
    }

    async fn open_for_test(
        bridge: Arc<ScriptedBridge>,
    ) -> GuiChatBridgeResult<(
        ConversationTaskRegistry,
        AuthorizedTextTurnSupervisor,
        AuthorizedTextTurn,
    )> {
        let registry = task_registry();
        let supervisor = AuthorizedTextTurnSupervisor::new(bridge, registry.clone()).await?;
        let turn = open_authorized_text_turn(
            Arc::clone(&supervisor.owner),
            decision(),
            GuiChatSurface::Main,
        )
        .await?;
        Ok((registry, supervisor, turn))
    }

    fn delta(sequence: u64, text: &str) -> GuiChatBridgeEvent {
        GuiChatBridgeEvent::Delta {
            subscription: subscription(sequence),
            sequence,
            text: text.into(),
        }
    }

    fn terminal(sequence: u64, state: GuiChatTerminalState) -> GuiChatBridgeEvent {
        GuiChatBridgeEvent::Terminal {
            subscription: subscription(sequence),
            sequence,
            state,
            provider: "fixture".into(),
            model: "fixture".into(),
            response_feedback: None,
            response_feedback_unavailable: true,
        }
    }

    struct AttachScript {
        events: Vec<GuiChatBridgeEvent>,
        result: GuiChatBridgeResult<()>,
    }

    /// This is a bridge lifecycle double, not an event projection test.  It
    /// seals real bridge handles, records bridge calls and can fail only after
    /// it delivered a selected prefix of the actual attach event stream.
    struct ScriptedBridge {
        started: GuiChatBridgeTurn,
        exchanges: Mutex<VecDeque<GuiChatBridgeResult<GuiChatBridgeSubscription>>>,
        attaches: Mutex<VecDeque<AttachScript>>,
        attached_after: Mutex<Vec<u64>>,
        cancel_calls: Mutex<u32>,
        start_calls: Mutex<u32>,
        decisions: Mutex<VecDeque<GuiChatBridgeDecisionOutcome>>,
    }

    impl ScriptedBridge {
        fn new(
            start_cursor: u64,
            exchanges: Vec<GuiChatBridgeResult<GuiChatBridgeSubscription>>,
            attaches: Vec<AttachScript>,
        ) -> Self {
            Self {
                started: turn(start_cursor),
                exchanges: Mutex::new(exchanges.into()),
                attaches: Mutex::new(attaches.into()),
                attached_after: Mutex::new(Vec::new()),
                cancel_calls: Mutex::new(0),
                start_calls: Mutex::new(0),
                decisions: Mutex::new(
                    vec![GuiChatBridgeDecisionOutcome::Approved(decision())].into(),
                ),
            }
        }
    }

    #[async_trait::async_trait]
    impl GuiChatBridge for ScriptedBridge {
        async fn preflight(
            &self,
            _input: GuiChatBridgePreflightInput,
        ) -> GuiChatBridgeResult<GuiChatBridgePreflight> {
            Ok(GuiChatBridgePreflight::Ready {
                decision: decision(),
            })
        }

        async fn decide(
            &self,
            _preflight: GuiChatBridgePreflightReceipt,
            _decision: GuiChatConsentDecision,
        ) -> GuiChatBridgeResult<GuiChatBridgeDecisionOutcome> {
            self.decisions
                .lock()
                .expect("test decision mutex")
                .pop_front()
                .ok_or_else(|| GuiChatBridgeError::invalid("missing scripted decision"))
        }

        async fn start(
            &self,
            _decision: GuiChatBridgeDecisionReceipt,
        ) -> GuiChatBridgeResult<GuiChatBridgeTurn> {
            *self.start_calls.lock().expect("test start mutex") += 1;
            Ok(self.started.clone())
        }

        async fn active(&self) -> GuiChatBridgeResult<Option<GuiChatBridgeTurn>> {
            Ok(Some(self.started.clone()))
        }

        async fn exchange_same_session_attach(
            &self,
            _turn: &GuiChatBridgeTurn,
            _surface: GuiChatSurface,
        ) -> GuiChatBridgeResult<GuiChatBridgeSubscription> {
            self.exchanges
                .lock()
                .expect("test exchange mutex")
                .pop_front()
                .expect("scripted exchange")
        }

        async fn attach(
            &self,
            _subscription: GuiChatBridgeSubscription,
            after_sequence: u64,
            sink: &mut dyn GuiChatBridgeEventSink,
        ) -> GuiChatBridgeResult<()> {
            self.attached_after
                .lock()
                .expect("test attach mutex")
                .push(after_sequence);
            let script = self
                .attaches
                .lock()
                .expect("test attach script mutex")
                .pop_front()
                .expect("scripted attach");
            for event in script.events {
                sink.on_event(event)?;
            }
            script.result
        }

        async fn cancel(&self, _turn: &GuiChatBridgeTurn) -> GuiChatBridgeResult<()> {
            *self.cancel_calls.lock().expect("test cancel mutex") += 1;
            Ok(())
        }

        async fn status(
            &self,
            _turn: &GuiChatBridgeTurn,
        ) -> GuiChatBridgeResult<GuiChatTurnMetadata> {
            Ok(self.started.metadata.clone())
        }
    }

    #[test]
    fn genuine_bridge_reasoning_event_never_reaches_voice_sink() {
        let mut sink = RecordingSink::default();
        let mut forwarder = VisibleForwarder {
            sink: &mut sink,
            latest_sequence: 0,
            terminal: None,
        };
        forwarder
            .on_event(GuiChatBridgeEvent::ReasoningDelta {
                subscription: subscription(7),
                sequence: 7,
                reasoning_sequence: 1,
                delta: crate::providers::ReasoningText::new("private chain".into()),
            })
            .expect("reasoning bridge event is intentionally ignored");
        let latest_sequence = forwarder.latest_sequence;
        assert!(sink.text.is_empty());
        assert_eq!(latest_sequence, 7);
    }

    #[test]
    fn genuine_bridge_delta_and_terminal_are_forwarded_in_order() {
        let mut sink = RecordingSink::default();
        let mut forwarder = VisibleForwarder {
            sink: &mut sink,
            latest_sequence: 0,
            terminal: None,
        };
        forwarder
            .on_event(GuiChatBridgeEvent::Delta {
                subscription: subscription(3),
                sequence: 3,
                text: "spoken text".into(),
            })
            .unwrap();
        forwarder
            .on_event(GuiChatBridgeEvent::Terminal {
                subscription: subscription(4),
                sequence: 4,
                state: GuiChatTerminalState::Complete,
                provider: "fixture".into(),
                model: "fixture".into(),
                response_feedback: None,
                response_feedback_unavailable: true,
            })
            .unwrap();
        let terminal = forwarder.terminal;
        let latest_sequence = forwarder.latest_sequence;
        assert_eq!(sink.text, vec!["spoken text".to_owned()]);
        assert_eq!(sink.terminal, [AuthorizedTextTurnTerminal::Complete]);
        assert_eq!(terminal, Some(GuiChatTerminalState::Complete));
        assert_eq!(latest_sequence, 4);
    }

    #[tokio::test]
    async fn sealed_start_cursor_replays_visible_delta_before_exchange_upper_bound() {
        let bridge = Arc::new(ScriptedBridge::new(
            1,
            vec![Ok(attached(9))],
            vec![AttachScript {
                events: vec![
                    delta(2, "must not be skipped"),
                    terminal(3, GuiChatTerminalState::Complete),
                ],
                result: Ok(()),
            }],
        ));
        let (_registry, _supervisor, mut text_turn) = open_for_test(Arc::clone(&bridge))
            .await
            .expect("turn opens from sealed start cursor");
        let mut sink = RecordingSink::default();
        text_turn.attach_visible(&mut sink).await.unwrap();
        assert_eq!(*bridge.attached_after.lock().unwrap(), vec![1]);
        assert_eq!(sink.text, vec!["must not be skipped".to_owned()]);
        assert_eq!(sink.terminal, vec![AuthorizedTextTurnTerminal::Complete]);
    }

    #[tokio::test]
    async fn failed_exchange_cancels_and_observes_terminal_before_returning_error() {
        let bridge = Arc::new(ScriptedBridge::new(
            4,
            vec![
                Err(GuiChatBridgeError::invalid("first_exchange_failed")),
                Ok(attached(8)),
            ],
            vec![AttachScript {
                events: vec![terminal(5, GuiChatTerminalState::Cancelled)],
                result: Ok(()),
            }],
        ));
        let registry = task_registry();
        let supervisor = AuthorizedTextTurnSupervisor::new(bridge.clone(), registry.clone())
            .await
            .unwrap();
        let result = open_authorized_text_turn(
            Arc::clone(&supervisor.owner),
            decision(),
            GuiChatSurface::Main,
        )
        .await;
        assert!(result.is_err());
        assert_eq!(*bridge.cancel_calls.lock().unwrap(), 1);
        assert_eq!(*bridge.attached_after.lock().unwrap(), vec![4]);
        supervisor.shutdown_and_join().await.unwrap();
    }

    #[tokio::test]
    async fn partial_attach_error_commits_cursor_and_never_replays_speech() {
        let bridge = Arc::new(ScriptedBridge::new(
            1,
            vec![Ok(attached(1))],
            vec![
                AttachScript {
                    events: vec![delta(2, "once")],
                    result: Err(GuiChatBridgeError::invalid("after_delta_transport_failure")),
                },
                AttachScript {
                    events: vec![terminal(3, GuiChatTerminalState::Complete)],
                    result: Ok(()),
                },
            ],
        ));
        let (_registry, _supervisor, mut text_turn) =
            open_for_test(Arc::clone(&bridge)).await.unwrap();
        let mut sink = RecordingSink::default();
        assert!(text_turn.attach_visible(&mut sink).await.is_err());
        text_turn.attach_visible(&mut sink).await.unwrap();
        assert_eq!(*bridge.attached_after.lock().unwrap(), vec![1, 2]);
        assert_eq!(sink.text, vec!["once".to_owned()]);
        assert_eq!(sink.terminal, vec![AuthorizedTextTurnTerminal::Complete]);
    }

    #[tokio::test]
    async fn cancellation_preserves_terminal_delivered_before_later_attach_error() {
        let bridge = Arc::new(ScriptedBridge::new(
            1,
            vec![Ok(attached(1))],
            vec![AttachScript {
                events: vec![terminal(2, GuiChatTerminalState::Cancelled)],
                result: Err(GuiChatBridgeError::invalid(
                    "after_terminal_transport_failure",
                )),
            }],
        ));
        let (_registry, _supervisor, mut text_turn) =
            open_for_test(Arc::clone(&bridge)).await.unwrap();
        let settled = text_turn.cancel_and_settle().await.unwrap();
        assert_eq!(
            settled.terminal_kind(),
            AuthorizedTextTurnTerminal::Cancelled
        );
        assert!(settled.cancel_proof().is_some());
        assert_eq!(*bridge.cancel_calls.lock().unwrap(), 1);
        assert_eq!(*bridge.attached_after.lock().unwrap(), vec![1]);
    }

    #[tokio::test]
    async fn cancel_racing_a_complete_terminal_mints_no_cancel_proof() {
        let bridge = Arc::new(ScriptedBridge::new(
            1,
            vec![Ok(attached(1))],
            vec![AttachScript {
                events: vec![terminal(2, GuiChatTerminalState::Complete)],
                result: Ok(()),
            }],
        ));
        let (_registry, _supervisor, mut text_turn) =
            open_for_test(Arc::clone(&bridge)).await.unwrap();
        let settled = text_turn.cancel_and_settle().await.unwrap();
        assert_eq!(
            settled.terminal_kind(),
            AuthorizedTextTurnTerminal::Complete
        );
        assert!(settled.cancel_proof().is_none());
    }

    #[tokio::test]
    async fn normal_preobserved_cancelled_terminal_never_mints_auto_cancel_proof() {
        let bridge = Arc::new(ScriptedBridge::new(
            1,
            vec![Ok(attached(1))],
            vec![AttachScript {
                events: vec![terminal(2, GuiChatTerminalState::Cancelled)],
                result: Ok(()),
            }],
        ));
        let (_registry, _supervisor, mut text_turn) =
            open_for_test(Arc::clone(&bridge)).await.unwrap();
        let mut sink = RecordingSink::default();
        text_turn.attach_visible(&mut sink).await.unwrap();
        let settled = text_turn.cancel_and_settle().await.unwrap();
        assert_eq!(
            settled.terminal_kind(),
            AuthorizedTextTurnTerminal::Cancelled
        );
        assert!(settled.cancel_proof().is_none());
        assert_eq!(*bridge.cancel_calls.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn dropped_consumer_is_cancelled_and_settled_by_its_existing_supervisor() {
        let bridge = Arc::new(ScriptedBridge::new(
            1,
            vec![Ok(attached(1))],
            vec![AttachScript {
                events: vec![terminal(2, GuiChatTerminalState::Cancelled)],
                result: Ok(()),
            }],
        ));
        let registry = task_registry();
        let supervisor = AuthorizedTextTurnSupervisor::new(bridge.clone(), registry.clone())
            .await
            .unwrap();
        let turn = open_authorized_text_turn(
            Arc::clone(&supervisor.owner),
            decision(),
            GuiChatSurface::Main,
        )
        .await
        .unwrap();
        drop(turn);
        let settled = supervisor.wait_for_dropped_turn().await.unwrap();
        assert_eq!(
            settled.terminal_kind(),
            AuthorizedTextTurnTerminal::Cancelled
        );
        assert!(settled.cancel_proof().is_some());
        assert_eq!(*bridge.cancel_calls.lock().unwrap(), 1);
        assert_eq!(*bridge.attached_after.lock().unwrap(), vec![1]);
        supervisor.shutdown_and_join().await.unwrap();
        drain_registry(&registry).await;
    }

    #[tokio::test]
    async fn second_start_is_refused_before_any_second_bridge_start() {
        let bridge = Arc::new(ScriptedBridge::new(
            1,
            vec![Ok(attached(1))],
            vec![AttachScript {
                events: vec![terminal(2, GuiChatTerminalState::Cancelled)],
                result: Ok(()),
            }],
        ));
        let registry = task_registry();
        let supervisor = AuthorizedTextTurnSupervisor::new(bridge.clone(), registry.clone())
            .await
            .unwrap();
        let first = open_authorized_text_turn(
            Arc::clone(&supervisor.owner),
            decision(),
            GuiChatSurface::Main,
        )
        .await
        .unwrap();
        assert!(
            open_authorized_text_turn(
                Arc::clone(&supervisor.owner),
                decision(),
                GuiChatSurface::Main,
            )
            .await
            .is_err()
        );
        assert_eq!(*bridge.start_calls.lock().unwrap(), 1);
        drop(first);
        assert_eq!(
            supervisor
                .wait_for_dropped_turn()
                .await
                .unwrap()
                .terminal_kind(),
            AuthorizedTextTurnTerminal::Cancelled
        );
        supervisor.shutdown_and_join().await.unwrap();
        drain_registry(&registry).await;
    }

    #[tokio::test]
    async fn idle_supervisor_shutdown_wakes_and_joins_the_retained_daemon_registry() {
        let bridge = Arc::new(ScriptedBridge::new(1, vec![], vec![]));
        let registry = task_registry();
        let supervisor = AuthorizedTextTurnSupervisor::new(bridge, registry.clone())
            .await
            .unwrap();
        assert!(
            supervisor
                .wait_for_dropped_turn_if_pending()
                .await
                .unwrap()
                .is_none()
        );
        supervisor.shutdown_and_join().await.unwrap();
        drain_registry(&registry).await;
    }

    #[tokio::test]
    async fn actual_bridge_denial_starts_no_turn_and_a_later_start_remains_admissible() {
        let bridge = Arc::new(ScriptedBridge::new(
            1,
            vec![Ok(attached(1))],
            vec![AttachScript {
                events: vec![terminal(2, GuiChatTerminalState::Cancelled)],
                result: Ok(()),
            }],
        ));
        {
            let mut decisions = bridge.decisions.lock().unwrap();
            decisions.clear();
            decisions.push_back(GuiChatBridgeDecisionOutcome::Denied);
        }
        let registry = task_registry();
        let supervisor = AuthorizedTextTurnSupervisor::new(bridge.clone(), registry.clone())
            .await
            .unwrap();
        let confirmation = AuthorizedTextTurnConfirmation {
            receipt: GuiChatBridgePreflightReceipt::from_live(vec![7]),
            prompt: GuiChatConsentPrompt {
                request_id: GuiChatRequestId::new(),
                routes: Vec::new(),
                expires_at_unix_ms: 1,
            },
            surface: GuiChatSurface::Main,
        };
        assert!(matches!(
            supervisor
                .decide(confirmation, GuiChatConsentDecision::AllowOnce)
                .await
                .unwrap(),
            AuthorizedTextTurnStart::Denied
        ));
        assert_eq!(*bridge.start_calls.lock().unwrap(), 0);
        let turn = match supervisor.start(input()).await.unwrap() {
            AuthorizedTextTurnStart::Ready(turn) => turn,
            _ => panic!("later admitted start must create one turn"),
        };
        assert_eq!(*bridge.start_calls.lock().unwrap(), 1);
        drop(turn);
        supervisor.wait_for_dropped_turn().await.unwrap();
        supervisor.shutdown_and_join().await.unwrap();
        drain_registry(&registry).await;
    }
}
