//! Canonical lifecycle for one GUI chat stream.
//!
//! Provider/process events are the only transition authority. UI timers may
//! animate a phase, but must never advance it. Every event is bound to the
//! request that produced it so a late callback cannot mutate a newer turn.

use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChatStreamRequestId(u64);

impl ChatStreamRequestId {
    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn as_wire(self) -> String {
        self.0.to_string()
    }

    pub fn parse_wire(value: &str) -> Option<Self> {
        value
            .parse::<u64>()
            .ok()
            .filter(|value| *value != 0)
            .map(Self)
    }
}

// W41 — daemon-owned delivery identity for the GUI bridge.
//
// This deliberately lives beside the retained child-stream reducer while the
// proposal is being adopted.  It does not authorize a daemon operation or
// manufacture an attachment/consent capability.  It owns only presentation
// state: one daemon turn can have independent Main and Buddy subscriptions.
// Every accepted event is checked against boot, turn, surface, generation and
// contiguous cursor before response text reaches a Slint projection.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaemonChatTurnIdentity {
    pub boot_id: String,
    pub turn_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaemonChatTerminal {
    Complete,
    Cancelled,
    Failed,
    CrashUnknown,
    Indeterminate,
}

#[derive(Clone, PartialEq, Eq)]
pub enum DaemonChatEventKind {
    Accepted,
    PhaseWaiting,
    PhaseReceiving,
    PhaseFinalizing,
    Notice,
    Delta(String),
    ProviderDone,
    CancelRequested,
    Terminal(DaemonChatTerminal),
}

#[derive(Clone, PartialEq, Eq)]
pub struct DaemonChatEvent {
    pub identity: DaemonChatTurnIdentity,
    pub surface: ChatStreamSurface,
    pub generation: u64,
    pub sequence: u64,
    pub kind: DaemonChatEventKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaemonChatReject {
    NoSubscription,
    WrongTurn,
    WrongGeneration,
    Duplicate,
    Gap,
    InvalidTransition,
    AfterTerminal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaemonChatApply {
    Applied,
    Rejected(DaemonChatReject),
}

/// A live subscription is local sensitive state. `reply` and `preview` are
/// overwritten/zeroized when the surface detaches or receives a newer
/// subscription generation.  The daemon remains the owner of the turn.
struct DaemonChatSubscriptionState {
    identity: DaemonChatTurnIdentity,
    generation: u64,
    cursor: u64,
    phase: ChatStreamPhase,
    incognito: bool,
    cancel_requested: bool,
    provider_done: bool,
    terminal: Option<DaemonChatTerminal>,
    reply: zeroize::Zeroizing<String>,
    canonical_preview: Option<zeroize::Zeroizing<String>>,
}

impl DaemonChatSubscriptionState {
    fn zeroize(mut self) {
        use zeroize::Zeroize as _;

        self.reply.zeroize();
        if let Some(mut preview) = self.canonical_preview.take() {
            preview.zeroize();
        }
    }
}

/// Main and Buddy have deliberately separate slots.  A Buddy attachment must
/// not replace Main's cursor or generation; a close simply drops its one local
/// subscription state and never cancels the daemon-owned turn.
#[derive(Default)]
pub struct DaemonChatPresentationReducer {
    main: Option<DaemonChatSubscriptionState>,
    buddy: Option<DaemonChatSubscriptionState>,
}

impl DaemonChatPresentationReducer {
    fn slot(&self, surface: ChatStreamSurface) -> &Option<DaemonChatSubscriptionState> {
        match surface {
            ChatStreamSurface::Main => &self.main,
            ChatStreamSurface::Buddy => &self.buddy,
        }
    }

    fn slot_mut(&mut self, surface: ChatStreamSurface) -> &mut Option<DaemonChatSubscriptionState> {
        match surface {
            ChatStreamSurface::Main => &mut self.main,
            ChatStreamSurface::Buddy => &mut self.buddy,
        }
    }

    /// Install a daemon-minted subscription.  Reopen must be a new nonzero
    /// generation for the same surface; a stale generation is never allowed
    /// to re-adopt old reply text.
    pub fn attach(
        &mut self,
        surface: ChatStreamSurface,
        identity: DaemonChatTurnIdentity,
        generation: u64,
        cursor: u64,
        incognito: bool,
    ) -> Result<(), DaemonChatReject> {
        if generation == 0 || identity.boot_id.is_empty() || identity.turn_id.is_empty() {
            return Err(DaemonChatReject::InvalidTransition);
        }
        if let Some(current) = self.slot(surface)
            && current.identity == identity
            && generation <= current.generation
        {
            return Err(DaemonChatReject::WrongGeneration);
        }
        if let Some(previous) = self.slot_mut(surface).take() {
            previous.zeroize();
        }
        *self.slot_mut(surface) = Some(DaemonChatSubscriptionState {
            identity,
            generation,
            cursor,
            phase: ChatStreamPhase::Waiting,
            incognito,
            cancel_requested: false,
            provider_done: false,
            terminal: None,
            reply: zeroize::Zeroizing::new(String::new()),
            canonical_preview: None,
        });
        Ok(())
    }

    /// UI close is a detach: locally held content is destroyed and no daemon
    /// cancellation is sent.  Stop is intentionally a separate bridge call.
    pub fn detach(&mut self, surface: ChatStreamSurface) {
        if let Some(previous) = self.slot_mut(surface).take() {
            previous.zeroize();
        }
    }

    pub fn apply(&mut self, event: DaemonChatEvent) -> DaemonChatApply {
        let Some(current) = self.slot_mut(event.surface).as_mut() else {
            return DaemonChatApply::Rejected(DaemonChatReject::NoSubscription);
        };
        if current.identity != event.identity {
            return DaemonChatApply::Rejected(DaemonChatReject::WrongTurn);
        }
        if current.generation != event.generation {
            return DaemonChatApply::Rejected(DaemonChatReject::WrongGeneration);
        }
        if event.sequence <= current.cursor {
            return DaemonChatApply::Rejected(DaemonChatReject::Duplicate);
        }
        if event.sequence != current.cursor.saturating_add(1) {
            return DaemonChatApply::Rejected(DaemonChatReject::Gap);
        }
        if current.terminal.is_some() {
            return DaemonChatApply::Rejected(DaemonChatReject::AfterTerminal);
        }

        let transition = match event.kind {
            DaemonChatEventKind::Accepted | DaemonChatEventKind::Notice => true,
            DaemonChatEventKind::PhaseWaiting => current.phase == ChatStreamPhase::Waiting,
            DaemonChatEventKind::PhaseReceiving => {
                if current.cancel_requested || current.phase == ChatStreamPhase::Finalizing {
                    false
                } else {
                    current.phase = ChatStreamPhase::Receiving;
                    true
                }
            }
            DaemonChatEventKind::PhaseFinalizing | DaemonChatEventKind::ProviderDone => {
                if current.cancel_requested {
                    false
                } else {
                    current.provider_done = true;
                    current.phase = ChatStreamPhase::Finalizing;
                    true
                }
            }
            DaemonChatEventKind::CancelRequested => {
                current.cancel_requested = true;
                true
            }
            DaemonChatEventKind::Delta(text) => {
                if current.cancel_requested || current.phase == ChatStreamPhase::Finalizing {
                    false
                } else {
                    if current.phase == ChatStreamPhase::Waiting {
                        current.phase = ChatStreamPhase::Receiving;
                    }
                    current.reply.push_str(&text);
                    true
                }
            }
            DaemonChatEventKind::Terminal(terminal) => {
                let valid = match terminal {
                    DaemonChatTerminal::Complete => {
                        !current.cancel_requested
                            && current.provider_done
                            && current.phase == ChatStreamPhase::Finalizing
                    }
                    DaemonChatTerminal::Cancelled => current.cancel_requested,
                    DaemonChatTerminal::Failed
                    | DaemonChatTerminal::CrashUnknown
                    | DaemonChatTerminal::Indeterminate => true,
                };
                if valid {
                    current.phase = match terminal {
                        DaemonChatTerminal::Complete => ChatStreamPhase::Complete,
                        DaemonChatTerminal::Cancelled => ChatStreamPhase::Cancelled,
                        DaemonChatTerminal::Failed
                        | DaemonChatTerminal::CrashUnknown
                        | DaemonChatTerminal::Indeterminate => ChatStreamPhase::Failed,
                    };
                    if terminal == DaemonChatTerminal::Complete && !current.incognito {
                        current.canonical_preview =
                            Some(zeroize::Zeroizing::new(current.reply.as_str().to_owned()));
                    }
                    current.terminal = Some(terminal);
                }
                valid
            }
        };
        if !transition {
            return DaemonChatApply::Rejected(DaemonChatReject::InvalidTransition);
        }
        current.cursor = event.sequence;
        DaemonChatApply::Applied
    }

    pub fn phase(&self, surface: ChatStreamSurface) -> Option<ChatStreamPhase> {
        self.slot(surface).as_ref().map(|state| state.phase)
    }

    pub fn cursor(&self, surface: ChatStreamSurface) -> Option<u64> {
        self.slot(surface).as_ref().map(|state| state.cursor)
    }

    pub fn visible_reply(&self, surface: ChatStreamSurface) -> Option<&str> {
        self.slot(surface)
            .as_ref()
            .map(|state| state.reply.as_str())
    }

    /// This is intentionally empty until the exact current subscription has a
    /// valid daemon terminal completion. Incognito never exports a sidebar
    /// preview from the reducer.
    pub fn canonical_preview(&self, surface: ChatStreamSurface) -> Option<&str> {
        self.slot(surface)
            .as_ref()
            .and_then(|state| state.canonical_preview.as_ref())
            .map(|preview| preview.as_str())
    }
}

impl Drop for DaemonChatPresentationReducer {
    fn drop(&mut self) {
        self.detach(ChatStreamSurface::Main);
        self.detach(ChatStreamSurface::Buddy);
    }
}

#[cfg(test)]
mod daemon_chat_presentation_tests {
    use super::*;

    fn identity() -> DaemonChatTurnIdentity {
        DaemonChatTurnIdentity {
            boot_id: "boot-a".into(),
            turn_id: "turn-a".into(),
        }
    }

    fn event(sequence: u64, kind: DaemonChatEventKind) -> DaemonChatEvent {
        DaemonChatEvent {
            identity: identity(),
            surface: ChatStreamSurface::Main,
            generation: 1,
            sequence,
            kind,
        }
    }

    #[test]
    fn main_delta_terminal_creates_preview_only_after_valid_terminal() {
        let mut reducer = DaemonChatPresentationReducer::default();
        reducer
            .attach(ChatStreamSurface::Main, identity(), 1, 0, false)
            .unwrap();
        assert_eq!(
            reducer.apply(event(1, DaemonChatEventKind::Delta("hello".into()))),
            DaemonChatApply::Applied
        );
        assert!(reducer.canonical_preview(ChatStreamSurface::Main).is_none());
        assert_eq!(
            reducer.apply(event(2, DaemonChatEventKind::ProviderDone)),
            DaemonChatApply::Applied
        );
        assert_eq!(
            reducer.apply(event(
                3,
                DaemonChatEventKind::Terminal(DaemonChatTerminal::Complete)
            )),
            DaemonChatApply::Applied
        );
        assert_eq!(
            reducer.canonical_preview(ChatStreamSurface::Main),
            Some("hello")
        );
    }

    #[test]
    fn stale_generation_duplicate_and_gap_cannot_repaint_main() {
        let mut reducer = DaemonChatPresentationReducer::default();
        reducer
            .attach(ChatStreamSurface::Main, identity(), 2, 4, false)
            .unwrap();
        assert_eq!(
            reducer.apply(event(5, DaemonChatEventKind::Delta("old".into()))),
            DaemonChatApply::Rejected(DaemonChatReject::WrongGeneration)
        );
        let mut current = event(4, DaemonChatEventKind::Delta("duplicate".into()));
        current.generation = 2;
        assert_eq!(
            reducer.apply(current),
            DaemonChatApply::Rejected(DaemonChatReject::Duplicate)
        );
        let mut gap = event(6, DaemonChatEventKind::Delta("gap".into()));
        gap.generation = 2;
        assert_eq!(
            reducer.apply(gap),
            DaemonChatApply::Rejected(DaemonChatReject::Gap)
        );
        assert_eq!(reducer.visible_reply(ChatStreamSurface::Main), Some(""));
    }

    #[test]
    fn buddy_has_own_generation_and_close_only_detaches_local_content() {
        let mut reducer = DaemonChatPresentationReducer::default();
        reducer
            .attach(ChatStreamSurface::Main, identity(), 1, 0, false)
            .unwrap();
        reducer
            .attach(ChatStreamSurface::Buddy, identity(), 7, 0, false)
            .unwrap();
        let mut buddy_delta = event(1, DaemonChatEventKind::Delta("shared".into()));
        buddy_delta.surface = ChatStreamSurface::Buddy;
        buddy_delta.generation = 7;
        assert_eq!(reducer.apply(buddy_delta), DaemonChatApply::Applied);
        reducer.detach(ChatStreamSurface::Buddy);
        assert_eq!(reducer.visible_reply(ChatStreamSurface::Buddy), None);
        assert_eq!(reducer.visible_reply(ChatStreamSurface::Main), Some(""));
    }

    #[test]
    fn stop_requires_cancel_then_cancel_terminal_and_never_previews() {
        let mut reducer = DaemonChatPresentationReducer::default();
        reducer
            .attach(ChatStreamSurface::Main, identity(), 1, 0, false)
            .unwrap();
        assert_eq!(
            reducer.apply(event(1, DaemonChatEventKind::CancelRequested)),
            DaemonChatApply::Applied
        );
        assert_eq!(
            reducer.apply(event(2, DaemonChatEventKind::Delta("late".into()))),
            DaemonChatApply::Rejected(DaemonChatReject::InvalidTransition)
        );
        assert_eq!(
            reducer.apply(event(
                2,
                DaemonChatEventKind::Terminal(DaemonChatTerminal::Cancelled)
            )),
            DaemonChatApply::Applied
        );
        assert!(reducer.canonical_preview(ChatStreamSurface::Main).is_none());
    }
}

const CHAT_LAUNCH_PENDING: u8 = 0;
const CHAT_LAUNCH_COMMITTED: u8 = 1;
const CHAT_LAUNCH_CANCELLED: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatLaunchCommit {
    Committed,
    AlreadyCommitted,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatLaunchCancel {
    Cancelled,
    AlreadyCancelled,
    AlreadyCommitted,
}

/// Request-bound launch authority shared by the UI Stop path and its worker.
///
/// The successful compare-and-exchange is the single linearization point:
/// either the worker commits the launch or Stop cancels it. A cancelled launch
/// can never become committed, and neither operation needs the stream
/// controller mutex.
#[derive(Debug, Clone)]
pub struct ChatLaunchGate {
    request_id: ChatStreamRequestId,
    state: Arc<AtomicU8>,
}

impl ChatLaunchGate {
    pub fn new(request_id: ChatStreamRequestId) -> Self {
        Self {
            request_id,
            state: Arc::new(AtomicU8::new(CHAT_LAUNCH_PENDING)),
        }
    }

    pub const fn request_id(&self) -> ChatStreamRequestId {
        self.request_id
    }

    pub fn commit(&self) -> ChatLaunchCommit {
        match self.state.compare_exchange(
            CHAT_LAUNCH_PENDING,
            CHAT_LAUNCH_COMMITTED,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(CHAT_LAUNCH_PENDING) => ChatLaunchCommit::Committed,
            Err(CHAT_LAUNCH_COMMITTED) => ChatLaunchCommit::AlreadyCommitted,
            Err(CHAT_LAUNCH_CANCELLED) => ChatLaunchCommit::Cancelled,
            Ok(_) | Err(_) => unreachable!("invalid GUI chat launch gate state"),
        }
    }

    pub fn cancel_before_commit(&self) -> ChatLaunchCancel {
        match self.state.compare_exchange(
            CHAT_LAUNCH_PENDING,
            CHAT_LAUNCH_CANCELLED,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(CHAT_LAUNCH_PENDING) => ChatLaunchCancel::Cancelled,
            Err(CHAT_LAUNCH_CANCELLED) => ChatLaunchCancel::AlreadyCancelled,
            Err(CHAT_LAUNCH_COMMITTED) => ChatLaunchCancel::AlreadyCommitted,
            Ok(_) | Err(_) => unreachable!("invalid GUI chat launch gate state"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatStreamSurface {
    Main,
    Buddy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatStreamPhase {
    Waiting,
    Receiving,
    Finalizing,
    Complete,
    Cancelled,
    Failed,
}

impl ChatStreamPhase {
    #[cfg(test)]
    pub const ALL: [Self; 6] = [
        Self::Waiting,
        Self::Receiving,
        Self::Finalizing,
        Self::Complete,
        Self::Cancelled,
        Self::Failed,
    ];

    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::Waiting => "waiting",
            Self::Receiving => "receiving",
            Self::Finalizing => "finalizing",
            Self::Complete => "complete",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }

    pub const fn is_active(self) -> bool {
        matches!(self, Self::Waiting | Self::Receiving | Self::Finalizing)
    }

    pub fn is_active_wire(value: &str) -> bool {
        matches!(value, "waiting" | "receiving" | "finalizing")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChatStreamUpdate {
    pub request_id: ChatStreamRequestId,
    pub surface: ChatStreamSurface,
    pub phase: ChatStreamPhase,
    pub cancel_requested: bool,
    pub changed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatStreamBeginError {
    RequestAlreadyActive,
    RequestIdExhausted,
}

impl std::fmt::Display for ChatStreamBeginError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::RequestAlreadyActive => "a chat stream request is already active",
            Self::RequestIdExhausted => "chat stream request id space is exhausted",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChatStreamState {
    request_id: ChatStreamRequestId,
    surface: ChatStreamSurface,
    phase: ChatStreamPhase,
    cancel_requested: bool,
    dispatch_claimed: bool,
}

#[derive(Debug, Default)]
pub struct ChatStreamController {
    next_request_id: u64,
    current: Option<ChatStreamState>,
}

impl ChatStreamController {
    pub fn begin(
        &mut self,
        surface: ChatStreamSurface,
    ) -> Result<ChatStreamUpdate, ChatStreamBeginError> {
        if self.current.is_some_and(|state| state.phase.is_active()) {
            return Err(ChatStreamBeginError::RequestAlreadyActive);
        }
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or(ChatStreamBeginError::RequestIdExhausted)?;
        let phase = ChatStreamPhase::Waiting;
        let request_id = ChatStreamRequestId(self.next_request_id);
        self.current = Some(ChatStreamState {
            request_id,
            surface,
            phase,
            cancel_requested: false,
            dispatch_claimed: false,
        });
        Ok(ChatStreamUpdate {
            request_id,
            surface,
            phase,
            cancel_requested: false,
            changed: true,
        })
    }

    pub fn visible_delta(
        &mut self,
        request_id: ChatStreamRequestId,
        text: &str,
    ) -> Option<ChatStreamUpdate> {
        let state = self.current_for(request_id)?;
        if state.cancel_requested
            || !state.phase.is_active()
            || state.phase == ChatStreamPhase::Finalizing
        {
            return None;
        }
        if text.trim().is_empty() {
            return Some(Self::unchanged(state));
        }
        match state.phase {
            ChatStreamPhase::Waiting => self.transition(request_id, ChatStreamPhase::Receiving),
            ChatStreamPhase::Receiving => Some(Self::unchanged(state)),
            ChatStreamPhase::Finalizing
            | ChatStreamPhase::Complete
            | ChatStreamPhase::Cancelled
            | ChatStreamPhase::Failed => None,
        }
    }

    pub fn provider_finished(
        &mut self,
        request_id: ChatStreamRequestId,
    ) -> Option<ChatStreamUpdate> {
        let state = self.current_for(request_id)?;
        if state.cancel_requested {
            return None;
        }
        match state.phase {
            ChatStreamPhase::Waiting | ChatStreamPhase::Receiving => {
                self.transition(request_id, ChatStreamPhase::Finalizing)
            }
            ChatStreamPhase::Finalizing => Some(Self::unchanged(state)),
            ChatStreamPhase::Complete | ChatStreamPhase::Cancelled | ChatStreamPhase::Failed => {
                None
            }
        }
    }

    /// Settle the presentation after the provider/process path has completed.
    ///
    /// A successful turn can become `Complete` only after the provider emitted
    /// its authenticated completion marker and the controller entered
    /// `Finalizing`. Failure may terminate any active phase. Operator
    /// cancellation wins over a later EOF/error from the killed subprocess.
    pub fn settle(
        &mut self,
        request_id: ChatStreamRequestId,
        succeeded: bool,
    ) -> Option<ChatStreamUpdate> {
        let state = self.current_for(request_id)?;
        if state.cancel_requested {
            return self.transition(request_id, ChatStreamPhase::Cancelled);
        }
        if succeeded {
            (state.phase == ChatStreamPhase::Finalizing)
                .then(|| self.transition(request_id, ChatStreamPhase::Complete))
                .flatten()
        } else if state.phase.is_active() {
            self.transition(request_id, ChatStreamPhase::Failed)
        } else {
            None
        }
    }

    /// Record an operator cancellation without releasing the request slot.
    ///
    /// The worker/preflight owner must still reap or stop its work and call
    /// [`settle`](Self::settle). Until then a newer request cannot begin and
    /// late events from this request cannot advance the presentation.
    pub fn request_cancel(&mut self, request_id: ChatStreamRequestId) -> Option<ChatStreamUpdate> {
        let current = self.current.as_mut()?;
        if current.request_id != request_id || !current.phase.is_active() {
            return None;
        }
        let changed = !current.cancel_requested;
        current.cancel_requested = true;
        Some(ChatStreamUpdate {
            request_id,
            surface: current.surface,
            phase: current.phase,
            cancel_requested: true,
            changed,
        })
    }

    pub fn active_request(&self) -> Option<ChatStreamUpdate> {
        self.current
            .filter(|state| state.phase.is_active())
            .map(Self::unchanged)
    }

    pub fn current_request(&self) -> Option<ChatStreamUpdate> {
        self.current.map(Self::unchanged)
    }

    #[cfg(test)]
    pub fn is_active(&self, request_id: ChatStreamRequestId) -> bool {
        self.current_for(request_id)
            .is_some_and(|state| state.phase.is_active())
    }

    pub fn is_dispatchable_on(
        &self,
        request_id: ChatStreamRequestId,
        surface: ChatStreamSurface,
    ) -> bool {
        self.current_for(request_id).is_some_and(|state| {
            state.surface == surface && state.phase.is_active() && !state.cancel_requested
        })
    }

    pub fn dispatch_claimed(&self, request_id: ChatStreamRequestId) -> bool {
        self.current_for(request_id)
            .is_some_and(|state| state.dispatch_claimed)
    }

    /// Claim the one provider launch owned by this request. Slint callbacks
    /// may be delivered more than once, but only the first accepted delivery
    /// is allowed to consume consent state or spawn a paid provider process.
    pub fn claim_dispatch(
        &mut self,
        request_id: ChatStreamRequestId,
        surface: ChatStreamSurface,
    ) -> bool {
        let Some(current) = self.current.as_mut() else {
            return false;
        };
        if current.request_id != request_id
            || current.surface != surface
            || !current.phase.is_active()
            || current.cancel_requested
            || current.dispatch_claimed
        {
            return false;
        }
        current.dispatch_claimed = true;
        true
    }

    fn current_for(&self, request_id: ChatStreamRequestId) -> Option<ChatStreamState> {
        self.current.filter(|state| state.request_id == request_id)
    }

    fn transition(
        &mut self,
        request_id: ChatStreamRequestId,
        phase: ChatStreamPhase,
    ) -> Option<ChatStreamUpdate> {
        let current = self.current.as_mut()?;
        if current.request_id != request_id {
            return None;
        }
        let changed = current.phase != phase;
        current.phase = phase;
        Some(ChatStreamUpdate {
            request_id,
            surface: current.surface,
            phase,
            cancel_requested: current.cancel_requested,
            changed,
        })
    }

    const fn unchanged(state: ChatStreamState) -> ChatStreamUpdate {
        ChatStreamUpdate {
            request_id: state.request_id,
            surface: state.surface,
            phase: state.phase,
            cancel_requested: state.cancel_requested,
            changed: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_turn_crosses_all_three_visible_phases() {
        let mut controller = ChatStreamController::default();
        let waiting = controller.begin(ChatStreamSurface::Main).unwrap();
        assert_eq!(waiting.phase, ChatStreamPhase::Waiting);

        let receiving = controller
            .visible_delta(waiting.request_id, "first token")
            .unwrap();
        assert_eq!(receiving.phase, ChatStreamPhase::Receiving);

        let finalizing = controller.provider_finished(waiting.request_id).unwrap();
        assert_eq!(finalizing.phase, ChatStreamPhase::Finalizing);

        let complete = controller.settle(waiting.request_id, true).unwrap();
        assert_eq!(complete.phase, ChatStreamPhase::Complete);
        assert!(!complete.phase.is_active());
    }

    #[test]
    fn empty_or_whitespace_chunks_do_not_start_receiving() {
        let mut controller = ChatStreamController::default();
        let waiting = controller.begin(ChatStreamSurface::Main).unwrap();

        for chunk in ["", " ", "\r\n\t"] {
            let update = controller.visible_delta(waiting.request_id, chunk).unwrap();
            assert_eq!(update.phase, ChatStreamPhase::Waiting);
            assert!(!update.changed);
        }
    }

    #[test]
    fn cancellation_keeps_slot_busy_and_wins_over_late_subprocess_failure() {
        let mut controller = ChatStreamController::default();
        let waiting = controller.begin(ChatStreamSurface::Main).unwrap();
        let cancel_requested = controller.request_cancel(waiting.request_id).unwrap();
        assert_eq!(cancel_requested.request_id, waiting.request_id);
        assert_eq!(cancel_requested.phase, ChatStreamPhase::Waiting);
        assert!(cancel_requested.cancel_requested);
        assert_eq!(
            controller.begin(ChatStreamSurface::Buddy),
            Err(ChatStreamBeginError::RequestAlreadyActive)
        );

        let reaped = controller.settle(waiting.request_id, false).unwrap();
        assert_eq!(reaped.phase, ChatStreamPhase::Cancelled);
        assert!(!reaped.phase.is_active());
    }

    #[test]
    fn failure_terminates_each_active_phase() {
        for stage in 0..3 {
            let mut controller = ChatStreamController::default();
            let start = controller.begin(ChatStreamSurface::Main).unwrap();
            if stage == 1 || stage == 2 {
                controller
                    .visible_delta(start.request_id, "partial")
                    .unwrap();
            }
            if stage == 2 {
                controller.provider_finished(start.request_id).unwrap();
            }

            assert_eq!(
                controller.settle(start.request_id, false).unwrap().phase,
                ChatStreamPhase::Failed
            );
        }
    }

    #[test]
    fn overlapping_begin_and_stale_callbacks_are_rejected() {
        let mut controller = ChatStreamController::default();
        let first = controller.begin(ChatStreamSurface::Main).unwrap();
        assert_eq!(
            controller.begin(ChatStreamSurface::Buddy),
            Err(ChatStreamBeginError::RequestAlreadyActive)
        );
        controller.provider_finished(first.request_id).unwrap();
        controller.settle(first.request_id, true).unwrap();

        let second = controller.begin(ChatStreamSurface::Buddy).unwrap();
        assert_ne!(first.request_id, second.request_id);
        assert_eq!(second.surface, ChatStreamSurface::Buddy);
        assert!(
            controller
                .visible_delta(first.request_id, "late old chunk")
                .is_none()
        );
        assert!(controller.is_active(second.request_id));
    }

    #[test]
    fn request_ids_round_trip_and_reject_zero_or_malformed_values() {
        let mut controller = ChatStreamController::default();
        let request = controller.begin(ChatStreamSurface::Main).unwrap();
        assert_eq!(
            ChatStreamRequestId::parse_wire(&request.request_id.as_wire()),
            Some(request.request_id)
        );
        assert_eq!(ChatStreamRequestId::parse_wire("0"), None);
        assert_eq!(ChatStreamRequestId::parse_wire("-1"), None);
        assert_eq!(ChatStreamRequestId::parse_wire("not-an-id"), None);
    }

    #[test]
    fn cancellation_blocks_late_delta_and_completion_marker() {
        let mut controller = ChatStreamController::default();
        let request = controller.begin(ChatStreamSurface::Main).unwrap();
        controller.request_cancel(request.request_id).unwrap();
        assert!(
            controller
                .visible_delta(request.request_id, "late")
                .is_none()
        );
        assert!(controller.provider_finished(request.request_id).is_none());
    }

    #[test]
    fn provider_dispatch_can_be_claimed_once_by_the_owning_surface() {
        let mut controller = ChatStreamController::default();
        let first = controller.begin(ChatStreamSurface::Main).unwrap();
        assert!(!controller.claim_dispatch(first.request_id, ChatStreamSurface::Buddy));
        assert!(controller.claim_dispatch(first.request_id, ChatStreamSurface::Main));
        assert!(!controller.claim_dispatch(first.request_id, ChatStreamSurface::Main));

        controller.provider_finished(first.request_id).unwrap();
        controller.settle(first.request_id, true).unwrap();
        let second = controller.begin(ChatStreamSurface::Buddy).unwrap();
        controller.request_cancel(second.request_id).unwrap();
        assert!(!controller.claim_dispatch(second.request_id, ChatStreamSurface::Buddy));
    }

    #[test]
    fn dispatch_claim_state_survives_cancellation_until_worker_settles() {
        let mut controller = ChatStreamController::default();
        let request = controller.begin(ChatStreamSurface::Main).unwrap();
        assert!(!controller.dispatch_claimed(request.request_id));
        assert!(controller.claim_dispatch(request.request_id, ChatStreamSurface::Main));
        assert!(controller.dispatch_claimed(request.request_id));

        controller.request_cancel(request.request_id).unwrap();
        assert!(controller.dispatch_claimed(request.request_id));
        controller.settle(request.request_id, false).unwrap();
        assert!(controller.dispatch_claimed(request.request_id));
    }

    #[test]
    fn launch_gate_can_be_committed_exactly_once() {
        let mut controller = ChatStreamController::default();
        let request = controller.begin(ChatStreamSurface::Main).unwrap();
        let gate = ChatLaunchGate::new(request.request_id);

        assert_eq!(gate.commit(), ChatLaunchCommit::Committed);
        assert_eq!(gate.commit(), ChatLaunchCommit::AlreadyCommitted);
    }

    #[test]
    fn cancellation_before_commit_permanently_blocks_launch() {
        let mut controller = ChatStreamController::default();
        let request = controller.begin(ChatStreamSurface::Main).unwrap();
        let gate = ChatLaunchGate::new(request.request_id);

        assert_eq!(gate.cancel_before_commit(), ChatLaunchCancel::Cancelled);
        assert_eq!(gate.commit(), ChatLaunchCommit::Cancelled);
        assert_eq!(
            gate.cancel_before_commit(),
            ChatLaunchCancel::AlreadyCancelled
        );
    }

    #[test]
    fn cancellation_after_commit_cannot_revoke_the_launch() {
        let mut controller = ChatStreamController::default();
        let request = controller.begin(ChatStreamSurface::Main).unwrap();
        let gate = ChatLaunchGate::new(request.request_id);

        assert_eq!(gate.commit(), ChatLaunchCommit::Committed);
        assert_eq!(
            gate.cancel_before_commit(),
            ChatLaunchCancel::AlreadyCommitted
        );
        assert_eq!(gate.commit(), ChatLaunchCommit::AlreadyCommitted);
    }

    #[test]
    fn cloned_launch_gates_share_one_atomic_state() {
        let mut controller = ChatStreamController::default();
        let request = controller.begin(ChatStreamSurface::Buddy).unwrap();
        let original = ChatLaunchGate::new(request.request_id);
        let worker = original.clone();

        assert_eq!(worker.cancel_before_commit(), ChatLaunchCancel::Cancelled);
        assert_eq!(original.commit(), ChatLaunchCommit::Cancelled);
        assert_eq!(
            original.cancel_before_commit(),
            ChatLaunchCancel::AlreadyCancelled
        );
    }

    #[test]
    fn launch_gates_retain_request_identity_and_independent_state() {
        let mut controller = ChatStreamController::default();
        let first = controller.begin(ChatStreamSurface::Main).unwrap();
        controller.provider_finished(first.request_id).unwrap();
        controller.settle(first.request_id, true).unwrap();
        let second = controller.begin(ChatStreamSurface::Buddy).unwrap();
        let first_gate = ChatLaunchGate::new(first.request_id);
        let second_gate = ChatLaunchGate::new(second.request_id);

        assert_eq!(first_gate.request_id(), first.request_id);
        assert_eq!(second_gate.request_id(), second.request_id);
        assert_ne!(first_gate.request_id(), second_gate.request_id());
        assert_eq!(
            first_gate.cancel_before_commit(),
            ChatLaunchCancel::Cancelled
        );
        assert_eq!(second_gate.commit(), ChatLaunchCommit::Committed);
    }

    #[test]
    fn wire_vocabulary_is_complete_and_unique() {
        let mut wires = ChatStreamPhase::ALL.map(ChatStreamPhase::as_wire).to_vec();
        wires.sort_unstable();
        wires.dedup();
        assert_eq!(wires.len(), ChatStreamPhase::ALL.len());
        assert_eq!(
            ChatStreamPhase::ALL
                .iter()
                .filter(|phase| phase.is_active())
                .count(),
            3
        );
    }
}
