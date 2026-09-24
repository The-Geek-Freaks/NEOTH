//! W41 daemon-chat controller shared by Main and Buddy.
//!
//! This module is intentionally provider/child/WAL-free.  The bridge
//! factory is the sole acquisition point; all renderers consume the reducer's
//! already-bound delivery state.

use std::sync::Arc;

use slint::ComponentHandle;

use neothd::daemon::gui_chat_bridge::{
    GuiChatBridge, GuiChatBridgeDecisionOutcome, GuiChatBridgePreflight,
    GuiChatBridgePreflightInput, GuiChatBridgeResult, GuiChatBridgeSubscription, GuiChatBridgeTurn,
    GuiChatConsentDecision, GuiChatSurface,
};

use crate::chat_stream_phase::{
    ChatStreamSurface, DaemonChatEvent, DaemonChatEventKind, DaemonChatPresentationReducer,
    DaemonChatTerminal, DaemonChatTurnIdentity,
};

pub struct GuiChatBridgeController {
    bridge: Arc<dyn GuiChatBridge>,
    /// One reducer is shared with every attach worker.  Main and Buddy retain
    /// independent slots inside it; a worker never reaches the legacy child
    /// stream controller.
    reducer: Arc<std::sync::Mutex<DaemonChatPresentationReducer>>,
    session_id: String,
}

struct PendingGuiConsent {
    request_id: String,
    surface: GuiChatSurface,
    receipt: neothd::daemon::gui_chat_bridge::GuiChatBridgePreflightReceipt,
    incognito: bool,
    reasoning_display: bool,
    body: String,
    operation: GuiChatOperation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GuiChatOperation {
    id: u64,
    origin_surface: GuiChatSurface,
    delivery_surface: GuiChatSurface,
}

struct ActiveGuiChatTurn {
    operation: GuiChatOperation,
    daemon_turn_id: String,
    /// The bridge turn contains sealed cancellation authority. Keep the one
    /// opaque value behind Arc rather than requiring the core type to Clone.
    turn: Arc<GuiChatBridgeTurn>,
    incognito: bool,
    /// Captured at the attested preflight boundary. A handoff/reopen never
    /// rereads the editable next-turn selector.
    reasoning_display: bool,
}

pub(crate) struct InstalledGuiChat {
    controller: Arc<GuiChatBridgeController>,
    active: Option<ActiveGuiChatTurn>,
    active_operation: Option<GuiChatOperation>,
    next_operation_id: u64,
    pending: Option<PendingGuiConsent>,
    attachments: Arc<std::sync::Mutex<Vec<std::path::PathBuf>>>,
    throughput_projections: crate::ChatThroughputProjections,
    recall_chip_projections: crate::ChatRecallChipProjections,
    response_feedback_projections: crate::ChatResponseFeedbackProjections,
}

/// Content-free observation for the explicit packaged-chat acceptance probe.
/// It deliberately exposes neither a sealed turn handle nor any capability.
#[derive(Clone, Debug)]
pub(crate) struct PackagedChatProbeSnapshot {
    pub(crate) operation_id: u64,
    pub(crate) turn_id: String,
    pub(crate) surface: GuiChatSurface,
    pub(crate) latest_sequence: u64,
    pub(crate) phase: String,
}

/// Read the daemon's authoritative cursor for the turn currently owned by the
/// real GUI callbacks. This is package-probe-only plumbing: the normal UI
/// still receives all state through the event sink and projections.
pub(crate) async fn packaged_probe_snapshot(
    installed: &Arc<std::sync::Mutex<InstalledGuiChat>>,
) -> GuiChatBridgeResult<Option<PackagedChatProbeSnapshot>> {
    let (bridge, turn, operation) = {
        let locked = installed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(active) = locked.active.as_ref() else {
            return Ok(None);
        };
        (
            Arc::clone(&locked.controller.bridge),
            Arc::clone(&active.turn),
            active.operation,
        )
    };
    let status = bridge.status(&turn).await?;
    Ok(Some(PackagedChatProbeSnapshot {
        operation_id: operation.id,
        turn_id: status.turn_id.as_uuid().to_string(),
        surface: operation.delivery_surface,
        latest_sequence: status.latest_sequence,
        phase: format!("{:?}", status.phase),
    }))
}

impl InstalledGuiChat {
    fn begin_operation(&mut self, surface: GuiChatSurface) -> GuiChatOperation {
        self.next_operation_id = self.next_operation_id.saturating_add(1);
        let operation = GuiChatOperation {
            id: self.next_operation_id,
            origin_surface: surface,
            delivery_surface: surface,
        };
        self.active_operation = Some(operation);
        operation
    }

    /// A visible surface handoff is a fresh local projection operation for the
    /// same daemon turn. Its captured Incognito flag stays on the active turn;
    /// the editable next-turn toggle never participates in reopen.
    fn begin_reopen_operation(&mut self, surface: GuiChatSurface) -> Option<GuiChatOperation> {
        let origin_surface = self.active.as_ref()?.operation.origin_surface;
        self.next_operation_id = self.next_operation_id.saturating_add(1);
        let operation = GuiChatOperation {
            id: self.next_operation_id,
            origin_surface,
            delivery_surface: surface,
        };
        self.active
            .as_mut()
            .expect("checked active daemon turn")
            .operation = operation;
        self.active_operation = Some(operation);
        Some(operation)
    }

    fn operation_is_current(&self, operation: GuiChatOperation) -> bool {
        current_operation_matches(self.active_operation, operation)
    }

    fn active_turn_is_current(
        &self,
        operation: GuiChatOperation,
        daemon_turn_id: &str,
        surface: GuiChatSurface,
        incognito: bool,
    ) -> bool {
        self.active.as_ref().is_some_and(|active| {
            operation_matches_turn(
                self.active_operation,
                active.operation,
                &active.daemon_turn_id,
                operation,
                daemon_turn_id,
                surface,
                active.incognito,
                incognito,
            )
        })
    }

    fn settle_current_turn(
        &mut self,
        operation: GuiChatOperation,
        daemon_turn_id: &str,
        surface: GuiChatSurface,
        incognito: bool,
    ) -> bool {
        if !self.active_turn_is_current(operation, daemon_turn_id, surface, incognito) {
            return false;
        }
        self.active = None;
        self.active_operation = None;
        true
    }

    fn fail_current_operation(&mut self, operation: GuiChatOperation) -> bool {
        if !self.operation_is_current(operation) {
            return false;
        }
        self.active = None;
        self.active_operation = None;
        true
    }
}

fn current_operation_matches(
    current: Option<GuiChatOperation>,
    callback: GuiChatOperation,
) -> bool {
    current == Some(callback)
}

fn operation_matches_turn(
    current: Option<GuiChatOperation>,
    active: GuiChatOperation,
    active_daemon_turn_id: &str,
    callback: GuiChatOperation,
    callback_daemon_turn_id: &str,
    callback_surface: GuiChatSurface,
    active_incognito: bool,
    callback_incognito: bool,
) -> bool {
    current == Some(callback)
        && active == callback
        && active_daemon_turn_id == callback_daemon_turn_id
        && callback.delivery_surface == callback_surface
        && active_incognito == callback_incognito
}

const fn preview_is_publishable(incognito: bool, terminal: bool) -> bool {
    terminal && !incognito
}

fn pending_request_matches(pending_request_id: &str, decision_request_id: &str) -> bool {
    pending_request_id == decision_request_id
}

fn parse_consent_decision(decision: &str) -> Option<GuiChatConsentDecision> {
    match decision {
        "deny" => Some(GuiChatConsentDecision::Deny),
        "allow-once" => Some(GuiChatConsentDecision::AllowOnce),
        "allow-always" => Some(GuiChatConsentDecision::AllowAlways),
        _ => None,
    }
}

const fn restores_hidden_buddy_after_no_start(surface: GuiChatSurface) -> bool {
    matches!(surface, GuiChatSurface::Buddy)
}

/// The attach worker owns this sink. A rejected reducer event is returned to
/// the bridge, ending only that subscription; it never mutates another view.
pub struct BridgeSink {
    pub reducer: Arc<std::sync::Mutex<DaemonChatPresentationReducer>>,
    state: Option<Arc<std::sync::Mutex<InstalledGuiChat>>>,
    pub window: slint::Weak<crate::MainWindow>,
    pub overlay: slint::Weak<crate::MiniOverlay>,
    operation: Option<GuiChatOperation>,
    pub incognito: bool,
    throughput_projections: crate::ChatThroughputProjections,
    recall_chip_projections: crate::ChatRecallChipProjections,
    response_feedback_projections: crate::ChatResponseFeedbackProjections,
}

impl neothd::daemon::gui_chat_bridge::GuiChatBridgeEventSink for BridgeSink {
    fn on_event(
        &mut self,
        event: neothd::daemon::gui_chat_bridge::GuiChatBridgeEvent,
    ) -> GuiChatBridgeResult<()> {
        use neothd::daemon::gui_chat_bridge::{
            GuiChatBridgeError, GuiChatPhase, GuiChatTerminalState,
        };
        let recall_batch = match &event {
            neothd::daemon::gui_chat_bridge::GuiChatBridgeEvent::RecallChipBatch {
                batch, ..
            } => Some(batch.clone()),
            _ => None,
        };
        let throughput_state = match &event {
            neothd::daemon::gui_chat_bridge::GuiChatBridgeEvent::ThroughputState {
                throughput_sequence,
                state,
                ..
            } => Some((*throughput_sequence, *state)),
            _ => None,
        };
        let freeze_throughput = matches!(
            &event,
            neothd::daemon::gui_chat_bridge::GuiChatBridgeEvent::ProviderDone { .. }
        );
        let clear_throughput = matches!(
            &event,
            neothd::daemon::gui_chat_bridge::GuiChatBridgeEvent::CancelRequested { .. }
                | neothd::daemon::gui_chat_bridge::GuiChatBridgeEvent::Terminal {
                    state: GuiChatTerminalState::Cancelled
                        | GuiChatTerminalState::Failed
                        | GuiChatTerminalState::CrashUnknown
                        | GuiChatTerminalState::Indeterminate,
                    ..
                }
        );
        let freeze_recall = matches!(
            &event,
            neothd::daemon::gui_chat_bridge::GuiChatBridgeEvent::ProviderDone { .. }
        );
        let clear_recall = matches!(
            &event,
            neothd::daemon::gui_chat_bridge::GuiChatBridgeEvent::CancelRequested { .. }
                | neothd::daemon::gui_chat_bridge::GuiChatBridgeEvent::Terminal {
                    state: GuiChatTerminalState::Cancelled
                        | GuiChatTerminalState::Failed
                        | GuiChatTerminalState::CrashUnknown
                        | GuiChatTerminalState::Indeterminate,
                    ..
                }
        );
        let (metadata, sequence, kind, terminal, response_feedback, response_feedback_unavailable) =
            match event {
                neothd::daemon::gui_chat_bridge::GuiChatBridgeEvent::Accepted {
                    subscription,
                    sequence,
                } => (
                    subscription,
                    sequence,
                    DaemonChatEventKind::Accepted,
                    false,
                    None,
                    false,
                ),
                neothd::daemon::gui_chat_bridge::GuiChatBridgeEvent::PhaseChanged {
                    subscription,
                    sequence,
                    phase,
                } => (
                    subscription,
                    sequence,
                    match phase {
                        GuiChatPhase::Waiting => DaemonChatEventKind::PhaseWaiting,
                        GuiChatPhase::Receiving => DaemonChatEventKind::PhaseReceiving,
                        GuiChatPhase::Finalizing => DaemonChatEventKind::PhaseFinalizing,
                    },
                    false,
                    None,
                    false,
                ),
                neothd::daemon::gui_chat_bridge::GuiChatBridgeEvent::Notice {
                    subscription,
                    sequence,
                    ..
                } => (
                    subscription,
                    sequence,
                    DaemonChatEventKind::Notice,
                    false,
                    None,
                    false,
                ),
                neothd::daemon::gui_chat_bridge::GuiChatBridgeEvent::TurnSilenceTimeout {
                    subscription,
                    sequence,
                    timeout_seconds,
                    retryable,
                } => (
                    subscription,
                    sequence,
                    DaemonChatEventKind::TurnSilenceTimeout {
                        timeout_seconds,
                        retryable,
                    },
                    false,
                    None,
                    false,
                ),
                neothd::daemon::gui_chat_bridge::GuiChatBridgeEvent::Delta {
                    subscription,
                    sequence,
                    text,
                } => (
                    subscription,
                    sequence,
                    DaemonChatEventKind::Delta(text),
                    false,
                    None,
                    false,
                ),
                neothd::daemon::gui_chat_bridge::GuiChatBridgeEvent::ReasoningDelta {
                    subscription,
                    sequence,
                    reasoning_sequence,
                    delta,
                } => (
                    subscription,
                    sequence,
                    DaemonChatEventKind::ReasoningDelta {
                        reasoning_sequence,
                        delta,
                    },
                    false,
                    None,
                    false,
                ),
                neothd::daemon::gui_chat_bridge::GuiChatBridgeEvent::ReasoningState {
                    subscription,
                    sequence,
                    reasoning_sequence,
                    state,
                    event_count,
                    byte_count,
                } => (
                    subscription,
                    sequence,
                    DaemonChatEventKind::ReasoningState {
                        reasoning_sequence,
                        state,
                        event_count,
                        byte_count,
                    },
                    false,
                    None,
                    false,
                ),
                neothd::daemon::gui_chat_bridge::GuiChatBridgeEvent::ReasoningCheckpoint {
                    subscription,
                    sequence,
                    reasoning_sequence,
                    event_count,
                    byte_count,
                } => (
                    subscription,
                    sequence,
                    DaemonChatEventKind::ReasoningCheckpoint {
                        reasoning_sequence,
                        event_count,
                        byte_count,
                    },
                    false,
                    None,
                    false,
                ),
                neothd::daemon::gui_chat_bridge::GuiChatBridgeEvent::ProviderDone {
                    subscription,
                    sequence,
                } => (
                    subscription,
                    sequence,
                    DaemonChatEventKind::ProviderDone,
                    false,
                    None,
                    false,
                ),
                neothd::daemon::gui_chat_bridge::GuiChatBridgeEvent::CancelRequested {
                    subscription,
                    sequence,
                } => (
                    subscription,
                    sequence,
                    DaemonChatEventKind::CancelRequested,
                    false,
                    None,
                    false,
                ),
                neothd::daemon::gui_chat_bridge::GuiChatBridgeEvent::RecallChipBatch {
                    subscription,
                    sequence,
                    ..
                } => (
                    subscription,
                    sequence,
                    DaemonChatEventKind::RecallChipBatch,
                    false,
                    None,
                    false,
                ),
                neothd::daemon::gui_chat_bridge::GuiChatBridgeEvent::ThroughputState {
                    subscription,
                    sequence,
                    ..
                } => (
                    subscription,
                    sequence,
                    DaemonChatEventKind::ThroughputState,
                    false,
                    None,
                    false,
                ),
                neothd::daemon::gui_chat_bridge::GuiChatBridgeEvent::Terminal {
                    subscription,
                    sequence,
                    state,
                    response_feedback,
                    response_feedback_unavailable,
                    ..
                } => {
                    let (terminal, response_feedback, response_feedback_unavailable) = match state {
                        GuiChatTerminalState::Complete => (
                            DaemonChatTerminal::Complete,
                            response_feedback,
                            response_feedback_unavailable,
                        ),
                        GuiChatTerminalState::Cancelled => {
                            (DaemonChatTerminal::Cancelled, None, false)
                        }
                        GuiChatTerminalState::Failed => (DaemonChatTerminal::Failed, None, false),
                        GuiChatTerminalState::CrashUnknown => {
                            (DaemonChatTerminal::CrashUnknown, None, false)
                        }
                        GuiChatTerminalState::Indeterminate => {
                            (DaemonChatTerminal::Indeterminate, None, false)
                        }
                    };
                    (
                        subscription,
                        sequence,
                        DaemonChatEventKind::Terminal(terminal),
                        true,
                        response_feedback,
                        response_feedback_unavailable,
                    )
                }
            };
        let surface = match metadata.surface {
            GuiChatSurface::Main => ChatStreamSurface::Main,
            GuiChatSurface::Buddy => ChatStreamSurface::Buddy,
        };
        let identity = DaemonChatTurnIdentity {
            boot_id: metadata.boot_id,
            turn_id: metadata.turn_id.as_uuid().to_string(),
        };
        let mut reducer = self.reducer.lock().unwrap_or_else(|p| p.into_inner());
        let applied = reducer.apply(DaemonChatEvent {
            identity,
            surface,
            generation: metadata.generation,
            sequence,
            kind,
        });
        if !matches!(applied, crate::chat_stream_phase::DaemonChatApply::Applied) {
            return Err(GuiChatBridgeError::invalid(
                "stale or gapped daemon chat event",
            ));
        }
        let phase = reducer
            .phase(surface)
            .unwrap_or(crate::chat_stream_phase::ChatStreamPhase::Failed);
        let text = reducer
            .turn_silence_timeout(surface)
            .map(|(timeout_seconds, retryable)| {
                if retryable {
                    format!(
                        "No provider progress for {timeout_seconds} seconds. You can retry this chat turn."
                    )
                } else {
                    format!("No provider progress for {timeout_seconds} seconds.")
                }
            })
            .unwrap_or_else(|| reducer.visible_reply(surface).unwrap_or("").to_owned());
        let reasoning_status = reducer
            .reasoning_status(surface)
            .map(|status| status.as_wire())
            .unwrap_or("hidden");
        let reasoning_active = reducer.reasoning_active(surface).unwrap_or(false);
        let reasoning_text: slint::SharedString =
            reducer.reasoning_text(surface).unwrap_or("").into();
        let incognito = self.incognito;
        let preview = preview_is_publishable(incognito, terminal)
            .then(|| reducer.canonical_preview(surface).map(str::to_owned))
            .flatten();
        drop(reducer);
        let window = self.window.clone();
        let overlay = self.overlay.clone();
        let state = self.state.as_ref().map(Arc::clone);
        let throughput_projections = self.throughput_projections.clone();
        let recall_chip_projections = self.recall_chip_projections.clone();
        let response_feedback_projections = self.response_feedback_projections.clone();
        let operation = self.operation;
        let daemon_turn_id = metadata.turn_id.as_uuid().to_string();
        let daemon_surface = metadata.surface;
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(window) = window.upgrade() {
                let current = match (&state, operation) {
                    (Some(state), Some(operation)) => state
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .active_turn_is_current(
                            operation,
                            &daemon_turn_id,
                            daemon_surface,
                            incognito,
                        ),
                    _ => true,
                };
                if !current {
                    return;
                }
                project_daemon_turn(&window, &daemon_turn_id, phase, &text);
                project_daemon_reasoning(
                    &window,
                    overlay.upgrade().as_ref(),
                    daemon_surface,
                    reasoning_status,
                    &reasoning_text,
                    reasoning_active,
                );
                if let Some(preview) = preview
                    && !preview.is_empty()
                {
                    crate::set_local_chat_sidebar_preview(
                        &window,
                        &preview,
                        &crate::format_now_hms(),
                    );
                }
                if let Some(overlay) = overlay.upgrade() {
                    crate::project_companion_chat_stream(&overlay, phase, Some(&text));
                    if !incognito {
                        crate::sync_companion_recent_lines_from_canonical(&window, &overlay);
                    }
                }
                if let (Some((throughput_sequence, state)), Some(operation)) =
                    (throughput_state, operation)
                {
                    match crate::accept_daemon_throughput_state(
                        &throughput_projections,
                        operation.id,
                        throughput_sequence,
                        state,
                    ) {
                        Ok(snapshot) => crate::project_chat_throughput_snapshot(
                            Some(&window),
                            overlay.upgrade().as_ref(),
                            match daemon_surface {
                                GuiChatSurface::Main => ChatStreamSurface::Main,
                                GuiChatSurface::Buddy => ChatStreamSurface::Buddy,
                            },
                            snapshot,
                        ),
                        Err(_) => {
                            crate::clear_daemon_throughput_projection(
                                &throughput_projections,
                                operation.id,
                            );
                            match daemon_surface {
                                GuiChatSurface::Main => {
                                    crate::clear_main_throughput_projection(&window)
                                }
                                GuiChatSurface::Buddy => {
                                    if let Some(overlay) = overlay.upgrade() {
                                        crate::clear_buddy_throughput_projection(&overlay);
                                    }
                                }
                            }
                        }
                    }
                }
                if freeze_throughput && let Some(operation) = operation {
                    crate::provider_done_daemon_throughput_projection(
                        &throughput_projections,
                        operation.id,
                    );
                    match daemon_surface {
                        GuiChatSurface::Main => crate::clear_main_throughput_projection(&window),
                        GuiChatSurface::Buddy => {
                            if let Some(overlay) = overlay.upgrade() {
                                crate::clear_buddy_throughput_projection(&overlay);
                            }
                        }
                    }
                }
                if clear_throughput && let Some(operation) = operation {
                    crate::clear_daemon_throughput_projection(
                        &throughput_projections,
                        operation.id,
                    );
                    match daemon_surface {
                        GuiChatSurface::Main => crate::clear_main_throughput_projection(&window),
                        GuiChatSurface::Buddy => {
                            if let Some(overlay) = overlay.upgrade() {
                                crate::clear_buddy_throughput_projection(&overlay);
                            }
                        }
                    }
                }
                if let (Some(batch), Some(operation)) = (recall_batch, operation) {
                    match crate::accept_daemon_recall_chip_batch(
                        &recall_chip_projections,
                        operation.id,
                        batch,
                    ) {
                        Ok(snapshot) => crate::project_chat_recall_chip_snapshot(
                            Some(&window),
                            overlay.upgrade().as_ref(),
                            match daemon_surface {
                                GuiChatSurface::Main => ChatStreamSurface::Main,
                                GuiChatSurface::Buddy => ChatStreamSurface::Buddy,
                            },
                            &snapshot,
                        ),
                        Err(_) => {
                            crate::clear_daemon_recall_chip_projection(
                                &recall_chip_projections,
                                operation.id,
                            );
                            match daemon_surface {
                                GuiChatSurface::Main => {
                                    crate::clear_main_recall_chip_projection(&window)
                                }
                                GuiChatSurface::Buddy => {
                                    if let Some(overlay) = overlay.upgrade() {
                                        crate::clear_buddy_recall_chip_projection(&overlay);
                                    }
                                }
                            }
                        }
                    }
                }
                if freeze_recall && let Some(operation) = operation {
                    crate::provider_done_daemon_recall_chip_projection(
                        &recall_chip_projections,
                        operation.id,
                    );
                }
                if terminal
                    && phase == crate::chat_stream_phase::ChatStreamPhase::Complete
                    && let Some(operation) = operation
                {
                    crate::final_daemon_recall_chip_projection(
                        &recall_chip_projections,
                        operation.id,
                    );
                }
                if clear_recall && let Some(operation) = operation {
                    crate::clear_daemon_recall_chip_projection(
                        &recall_chip_projections,
                        operation.id,
                    );
                    match daemon_surface {
                        GuiChatSurface::Main => crate::clear_main_recall_chip_projection(&window),
                        GuiChatSurface::Buddy => {
                            if let Some(overlay) = overlay.upgrade() {
                                crate::clear_buddy_recall_chip_projection(&overlay);
                            }
                        }
                    }
                }
                // The terminal target is accepted only after the subscription
                // has passed both reducer ordering and current-turn checks.
                // It is an opaque daemon-issued pair, never reconstructed
                // from provider text or a local stream frame.
                if terminal
                    && phase == crate::chat_stream_phase::ChatStreamPhase::Complete
                    && !incognito
                    && let Some(operation) = operation
                    && (response_feedback.is_some() || response_feedback_unavailable)
                {
                    let (response_id, session_id, revision) = response_feedback
                        .map(|target| {
                            (
                                Some(target.response_id),
                                Some(target.session_id),
                                Some(target.revision),
                            )
                        })
                        .unwrap_or((None, None, None));
                    if let Ok(snapshot) = crate::accept_daemon_response_feedback_terminal(
                        &response_feedback_projections,
                        operation.id,
                        response_id,
                        session_id,
                        revision,
                        response_feedback_unavailable,
                    ) {
                        crate::project_chat_response_feedback_snapshot(
                            Some(&window),
                            overlay.upgrade().as_ref(),
                            match daemon_surface {
                                GuiChatSurface::Main => ChatStreamSurface::Main,
                                GuiChatSurface::Buddy => ChatStreamSurface::Buddy,
                            },
                            &snapshot,
                        );
                    }
                }
                if terminal && let (Some(state), Some(operation)) = (&state, operation) {
                    let settled = state
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .settle_current_turn(operation, &daemon_turn_id, daemon_surface, incognito);
                    if settled {
                        settle_projection(&window, overlay.upgrade().as_ref());
                    }
                }
            }
        });
        Ok(())
    }
}

/// Materialise the daemon-accepted turn before its first attach worker can
/// deliver a frame. The same daemon turn id owns both the operator row and the
/// assistant placeholder; no local request id remains after `start`.
fn begin_daemon_turn(
    window: &crate::MainWindow,
    daemon_turn_id: &str,
    body: &str,
    incognito: bool,
) -> bool {
    use slint::Model;

    let mut rows: Vec<crate::ChatMessage> = window.get_chat_live_messages().iter().collect();
    if rows
        .iter()
        .any(|row| row.request_id.as_str() == daemon_turn_id && row.role.as_str() == "assistant")
    {
        return false;
    }
    let timestamp = crate::format_now_hms();
    rows.push(crate::ChatMessage {
        role: "operator".into(),
        text: body.into(),
        timestamp: timestamp.clone().into(),
        request_id: daemon_turn_id.into(),
        stream_phase: crate::chat_stream_phase::ChatStreamPhase::Complete
            .as_wire()
            .into(),
        incognito,
        ..Default::default()
    });
    rows.push(crate::ChatMessage {
        role: "assistant".into(),
        text: "…".into(),
        timestamp: timestamp.into(),
        request_id: daemon_turn_id.into(),
        stream_phase: crate::chat_stream_phase::ChatStreamPhase::Waiting
            .as_wire()
            .into(),
        incognito,
        ..Default::default()
    });
    // Do not derive a sidebar preview from an active or Incognito turn. The
    // validated terminal event below is the only preview publication path.
    crate::set_live_chat_messages(window, rows);
    true
}

/// The daemon turn ID is the only transcript key after `start`. A late stream
/// callback updates only its already materialised assistant/error row.
fn project_daemon_turn(
    window: &crate::MainWindow,
    daemon_turn_id: &str,
    phase: crate::chat_stream_phase::ChatStreamPhase,
    text: &str,
) {
    use slint::Model;

    let mut rows: Vec<crate::ChatMessage> = window.get_chat_live_messages().iter().collect();
    let Some(row) = rows.iter_mut().find(|row| {
        row.request_id.as_str() == daemon_turn_id
            && matches!(row.role.as_str(), "assistant" | "error")
    }) else {
        return;
    };
    if !text.is_empty() {
        row.text = text.into();
    }
    row.stream_phase = phase.as_wire().into();
    if phase == crate::chat_stream_phase::ChatStreamPhase::Failed {
        row.role = "error".into();
    }
    crate::set_live_chat_messages(window, rows);
}

/// Reasoning has its own transient Slint projection. It never enters a
/// `ChatMessage`, companion recent-lines, preview, or clipboard path.
fn project_daemon_reasoning(
    window: &crate::MainWindow,
    overlay: Option<&crate::MiniOverlay>,
    surface: GuiChatSurface,
    status: &str,
    text: &slint::SharedString,
    active: bool,
) {
    match surface {
        GuiChatSurface::Main => {
            window.set_chat_reasoning_status(status.into());
            window.set_chat_reasoning_text(text.clone());
            window.set_chat_reasoning_active(active);
        }
        GuiChatSurface::Buddy => {
            if let Some(overlay) = overlay {
                overlay.set_reasoning_status(status.into());
                overlay.set_reasoning_text(text.clone());
                overlay.set_reasoning_active(active);
            }
        }
    }
}

/// A surface switch/failure starts with no local reasoning. Keeping status
/// hidden here avoids treating a non-replayed handoff as a completed reason.
fn clear_daemon_reasoning_projection(
    window: &crate::MainWindow,
    overlay: Option<&crate::MiniOverlay>,
) {
    window.set_chat_reasoning_status("hidden".into());
    window.set_chat_reasoning_text("".into());
    window.set_chat_reasoning_active(false);
    if let Some(overlay) = overlay {
        overlay.set_reasoning_status("hidden".into());
        overlay.set_reasoning_text("".into());
        overlay.set_reasoning_active(false);
    }
}

fn bridge_runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())
}

fn submit(
    state: Arc<std::sync::Mutex<InstalledGuiChat>>,
    window: slint::Weak<crate::MainWindow>,
    overlay: slint::Weak<crate::MiniOverlay>,
    attachment_owner: Arc<std::sync::Mutex<Vec<std::path::PathBuf>>>,
    surface: GuiChatSurface,
    text: String,
    incognito: bool,
) {
    let body = text.trim().to_owned();
    if body.is_empty() {
        return;
    }
    let Some(win) = window.upgrade() else {
        return;
    };
    if win.get_chat_send_in_flight() {
        return;
    }
    // Reasoning display is a next-turn choice. Capture before resetting the
    // selector and carry only this immutable bit through preflight/receipt.
    let reasoning_display = match surface {
        GuiChatSurface::Main => win.get_chat_reasoning_display(),
        GuiChatSurface::Buddy => overlay
            .upgrade()
            .is_some_and(|overlay| overlay.get_reasoning_display()),
    };
    clear_daemon_reasoning_projection(&win, overlay.upgrade().as_ref());
    // Incognito is an immutable request snapshot. Reset only the selector on
    // the initiating surface; the active marker is set below once this
    // operation exists.
    match surface {
        GuiChatSurface::Main => {
            win.set_chat_incognito(false);
            win.set_chat_reasoning_display(false);
        }
        GuiChatSurface::Buddy => {
            if let Some(overlay) = overlay.upgrade() {
                overlay.set_incognito(false);
                overlay.set_reasoning_display(false);
            }
        }
    }
    // Model/skill remain core-selected when their existing UI owners have no
    // explicit per-turn override. Their visible selectors are not reset here.
    let model = crate::CHAT_MODEL_OVERRIDE
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .take();
    let skill = match crate::selected_skill_id_for_request() {
        Ok(skill) => skill,
        Err(error) => {
            fail_projection(&win, overlay.upgrade().as_ref(), &error);
            return;
        }
    };
    let attachments = attachment_owner
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let operation = state
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .begin_operation(surface);
    let (throughput_projections, recall_chip_projections, response_feedback_projections) = {
        let locked = state.lock().unwrap_or_else(|p| p.into_inner());
        (
            locked.throughput_projections.clone(),
            locked.recall_chip_projections.clone(),
            locked.response_feedback_projections.clone(),
        )
    };
    crate::clear_active_daemon_throughput_projection(
        &throughput_projections,
        &win,
        overlay.upgrade().as_ref(),
    );
    crate::clear_chat_recall_chip_replacement(
        &recall_chip_projections,
        &win,
        overlay.upgrade().as_ref(),
    );
    crate::clear_chat_response_feedback_replacement(
        &response_feedback_projections,
        &win,
        overlay.upgrade().as_ref(),
    );
    win.set_chat_send_in_flight(true);
    win.set_chat_incognito_active(incognito);
    if surface == GuiChatSurface::Buddy
        && let Some(ov) = overlay.upgrade()
    {
        ov.set_send_in_flight(true);
        ov.set_incognito_active(incognito);
    }
    std::thread::spawn(move || {
        let result = (|| -> GuiChatBridgeResult<GuiChatBridgePreflight> {
            let runtime = bridge_runtime().map_err(|_| {
                neothd::daemon::gui_chat_bridge::GuiChatBridgeError::invalid(
                    "GUI runtime initialization failed",
                )
            })?;
            let controller =
                Arc::clone(&state.lock().unwrap_or_else(|p| p.into_inner()).controller);
            runtime.block_on(controller.begin(
                surface,
                neothd::daemon::gui_chat_bridge::GuiChatRequestId::new(),
                body.clone(),
                model,
                skill,
                incognito,
                reasoning_display,
                attachments,
            ))
        })();
        let _ = slint::invoke_from_event_loop(move || {
            let Some(win) = window.upgrade() else {
                return;
            };
            let current = state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .operation_is_current(operation);
            if !current {
                return;
            }
            match result {
                Ok(GuiChatBridgePreflight::Ready { decision }) => start_receipt(
                    state,
                    window,
                    overlay,
                    operation,
                    incognito,
                    reasoning_display,
                    body,
                    decision,
                ),
                Ok(GuiChatBridgePreflight::ConfirmationRequired { receipt, prompt }) => {
                    let routes = prompt
                        .routes
                        .iter()
                        .map(|route| match &route.endpoint_origin {
                            Some(origin) => format!("{} · {origin}", route.provider),
                            None => route.provider.clone(),
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                    state.lock().unwrap_or_else(|p| p.into_inner()).pending =
                        Some(PendingGuiConsent {
                            request_id: prompt.request_id.as_uuid().to_string(),
                            surface,
                            receipt,
                            incognito,
                            reasoning_display,
                            body,
                            operation,
                        });
                    win.set_chat_consent_prompt_request_id(
                        prompt.request_id.as_uuid().to_string().into(),
                    );
                    win.set_chat_consent_prompt_routes(routes.into());
                    win.set_chat_consent_prompt_busy(false);
                    win.set_chat_consent_prompt_open(true);
                    if surface == GuiChatSurface::Buddy {
                        // This callback owns the established Buddy-to-Main
                        // presentation handoff for the visible Slint modal.
                        win.invoke_buddy_chat_consent_prompt_required();
                    }
                }
                Err(error) => {
                    fail_current_projection(
                        &state,
                        operation,
                        &win,
                        overlay.upgrade().as_ref(),
                        &error.to_string(),
                    );
                }
            }
        });
    });
}

fn decide_pending(
    state: Arc<std::sync::Mutex<InstalledGuiChat>>,
    window: slint::Weak<crate::MainWindow>,
    overlay: slint::Weak<crate::MiniOverlay>,
    request_id: String,
    decision: String,
) {
    let Some(win) = window.upgrade() else {
        return;
    };
    // A malformed callback must leave the current opaque receipt in place so
    // the still-visible modal can receive its valid follow-up decision.
    let Some(choice) = parse_consent_decision(&decision) else {
        return;
    };
    let pending = {
        let mut locked = state.lock().unwrap_or_else(|p| p.into_inner());
        if !locked
            .pending
            .as_ref()
            .is_some_and(|pending| pending_request_matches(&pending.request_id, &request_id))
        {
            return;
        }
        locked.pending.take()
    };
    let Some(pending) = pending else {
        return;
    };
    win.set_chat_consent_prompt_busy(true);
    std::thread::spawn(move || {
        let result = (|| {
            let runtime = bridge_runtime().map_err(|_| {
                neothd::daemon::gui_chat_bridge::GuiChatBridgeError::invalid(
                    "GUI runtime initialization failed",
                )
            })?;
            let bridge = Arc::clone(
                &state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .controller
                    .bridge,
            );
            runtime.block_on(bridge.decide(pending.receipt, choice))
        })();
        let _ = slint::invoke_from_event_loop(move || {
            let Some(win) = window.upgrade() else {
                return;
            };
            if !state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .operation_is_current(pending.operation)
            {
                return;
            }
            win.set_chat_consent_prompt_busy(false);
            win.set_chat_consent_prompt_open(false);
            win.set_chat_consent_prompt_request_id("".into());
            match result {
                Ok(GuiChatBridgeDecisionOutcome::Approved(receipt)) => start_receipt(
                    state,
                    window,
                    overlay,
                    pending.operation,
                    pending.incognito,
                    pending.reasoning_display,
                    pending.body,
                    receipt,
                ),
                Ok(GuiChatBridgeDecisionOutcome::Denied) => {
                    if fail_current_projection(
                        &state,
                        pending.operation,
                        &win,
                        overlay.upgrade().as_ref(),
                        "Message not sent: consent denied.",
                    ) && restores_hidden_buddy_after_no_start(pending.surface)
                    {
                        // The registered Main callback hides this window and
                        // restores Buddy's retained draft and selection.
                        win.invoke_buddy_chat_send_cancelled(
                            "Message not sent: consent denied.".into(),
                        );
                    }
                }
                Err(error) => {
                    let message = error.to_string();
                    if fail_current_projection(
                        &state,
                        pending.operation,
                        &win,
                        overlay.upgrade().as_ref(),
                        &message,
                    ) && restores_hidden_buddy_after_no_start(pending.surface)
                    {
                        // A rejected/expired/indeterminate decision after the
                        // Main-modal handoff must restore the hidden Buddy
                        // draft exactly as an explicit denial does.
                        win.invoke_buddy_chat_send_cancelled(message.into());
                    }
                }
            }
        });
    });
}

fn start_receipt(
    state: Arc<std::sync::Mutex<InstalledGuiChat>>,
    window: slint::Weak<crate::MainWindow>,
    overlay: slint::Weak<crate::MiniOverlay>,
    operation: GuiChatOperation,
    incognito: bool,
    reasoning_display: bool,
    body: String,
    receipt: neothd::daemon::gui_chat_bridge::GuiChatBridgeDecisionReceipt,
) {
    std::thread::spawn(move || {
        let result = (|| {
            let runtime = bridge_runtime().map_err(|_| {
                neothd::daemon::gui_chat_bridge::GuiChatBridgeError::invalid(
                    "GUI runtime initialization failed",
                )
            })?;
            let controller =
                Arc::clone(&state.lock().unwrap_or_else(|p| p.into_inner()).controller);
            runtime.block_on(controller.start_and_attach(
                receipt,
                operation.origin_surface,
                incognito,
                reasoning_display,
            ))
        })();
        match result {
            Ok((turn, subscription)) => {
                let _ = slint::invoke_from_event_loop(move || {
                    let Some(win) = window.upgrade() else {
                        return;
                    };
                    if !state
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .operation_is_current(operation)
                    {
                        return;
                    }
                    let daemon_turn_id = turn.metadata.turn_id.as_uuid().to_string();
                    if !begin_daemon_turn(&win, &daemon_turn_id, &body, incognito) {
                        return;
                    }
                    let turn = Arc::new(turn);
                    let (
                        bridge,
                        reducer,
                        throughput_projections,
                        recall_chip_projections,
                        response_feedback_projections,
                    ) = {
                        let mut locked = state.lock().unwrap_or_else(|p| p.into_inner());
                        if !locked.operation_is_current(operation) {
                            return;
                        }
                        locked.active = Some(ActiveGuiChatTurn {
                            operation,
                            daemon_turn_id,
                            turn,
                            incognito,
                            reasoning_display,
                        });
                        locked
                            .attachments
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .clear();
                        (
                            Arc::clone(&locked.controller.bridge),
                            Arc::clone(&locked.controller.reducer),
                            locked.throughput_projections.clone(),
                            locked.recall_chip_projections.clone(),
                            locked.response_feedback_projections.clone(),
                        )
                    };
                    win.set_status_line("Daemon chat started.".into());
                    let state_for_attach = Arc::clone(&state);
                    let window_for_attach = window.clone();
                    let overlay_for_attach = overlay.clone();
                    std::thread::spawn(move || {
                        let result = attach_subscription(
                            bridge,
                            reducer,
                            throughput_projections,
                            recall_chip_projections,
                            response_feedback_projections,
                            state_for_attach,
                            operation,
                            subscription,
                            window_for_attach,
                            overlay_for_attach,
                            incognito,
                        );
                        if let Err(error) = result {
                            let _ = slint::invoke_from_event_loop(move || {
                                if let Some(win) = window.upgrade() {
                                    fail_current_projection(
                                        &state,
                                        operation,
                                        &win,
                                        overlay.upgrade().as_ref(),
                                        &error.to_string(),
                                    );
                                }
                            });
                        }
                    });
                });
            }
            Err(error) => {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(win) = window.upgrade() {
                        fail_current_projection(
                            &state,
                            operation,
                            &win,
                            overlay.upgrade().as_ref(),
                            &error.to_string(),
                        );
                    }
                });
            }
        }
    });
}

fn stop_active(
    state: Arc<std::sync::Mutex<InstalledGuiChat>>,
    window: slint::Weak<crate::MainWindow>,
) {
    std::thread::spawn(move || {
        let result = (|| {
            let runtime = bridge_runtime().map_err(|_| {
                neothd::daemon::gui_chat_bridge::GuiChatBridgeError::invalid(
                    "GUI runtime initialization failed",
                )
            })?;
            let (controller, turn, operation) = {
                let locked = state.lock().unwrap_or_else(|p| p.into_inner());
                let active = locked.active.as_ref().ok_or_else(|| {
                    neothd::daemon::gui_chat_bridge::GuiChatBridgeError::invalid(
                        "no active daemon chat",
                    )
                })?;
                (
                    Arc::clone(&locked.controller),
                    Arc::clone(&active.turn),
                    active.operation,
                )
            };
            runtime.block_on(controller.stop(&turn)).map(|_| operation)
        })();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(win) = window.upgrade() {
                match result {
                    Ok(operation)
                        if state
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .operation_is_current(operation) =>
                    {
                        win.set_status_line("Stopping daemon chat…".into())
                    }
                    Ok(_) => {}
                    Err(e) => win.set_status_line(e.to_string().into()),
                }
            }
        });
    });
}

fn settle_projection(window: &crate::MainWindow, overlay: Option<&crate::MiniOverlay>) {
    window.set_chat_send_in_flight(false);
    window.set_chat_incognito_active(false);
    window.set_chat_reasoning_text("".into());
    window.set_chat_reasoning_active(false);
    if let Some(overlay) = overlay {
        overlay.set_send_in_flight(false);
        overlay.set_incognito_active(false);
        overlay.set_reasoning_text("".into());
        overlay.set_reasoning_active(false);
    }
}

fn fail_projection(
    window: &crate::MainWindow,
    overlay: Option<&crate::MiniOverlay>,
    message: &str,
) {
    settle_projection(window, overlay);
    clear_daemon_reasoning_projection(window, overlay);
    window.set_status_line(message.into());
    if let Some(overlay) = overlay {
        overlay.set_status_text(message.into());
    }
}

fn fail_current_projection(
    state: &Arc<std::sync::Mutex<InstalledGuiChat>>,
    operation: GuiChatOperation,
    window: &crate::MainWindow,
    overlay: Option<&crate::MiniOverlay>,
    message: &str,
) -> bool {
    let failed = state
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .fail_current_operation(operation);
    if failed {
        let locked = state.lock().unwrap_or_else(|p| p.into_inner());
        crate::clear_daemon_throughput_projection(&locked.throughput_projections, operation.id);
        crate::clear_daemon_recall_chip_projection(&locked.recall_chip_projections, operation.id);
        locked.controller.close(operation.delivery_surface);
        drop(locked);
        crate::clear_main_throughput_projection(window);
        crate::clear_main_recall_chip_projection(window);
        if let Some(overlay) = overlay {
            crate::clear_buddy_throughput_projection(overlay);
            crate::clear_buddy_recall_chip_projection(overlay);
        }
        fail_projection(window, overlay, message);
        true
    } else {
        false
    }
}

#[allow(clippy::too_many_arguments)] // Sealed subscription, UI weak handles, and operation identity stay explicit.
fn attach_subscription(
    bridge: Arc<dyn GuiChatBridge>,
    reducer: Arc<std::sync::Mutex<DaemonChatPresentationReducer>>,
    throughput_projections: crate::ChatThroughputProjections,
    recall_chip_projections: crate::ChatRecallChipProjections,
    response_feedback_projections: crate::ChatResponseFeedbackProjections,
    state: Arc<std::sync::Mutex<InstalledGuiChat>>,
    operation: GuiChatOperation,
    subscription: GuiChatBridgeSubscription,
    window: slint::Weak<crate::MainWindow>,
    overlay: slint::Weak<crate::MiniOverlay>,
    incognito: bool,
) -> GuiChatBridgeResult<()> {
    let surface = match subscription.metadata.surface {
        GuiChatSurface::Main => ChatStreamSurface::Main,
        GuiChatSurface::Buddy => ChatStreamSurface::Buddy,
    };
    let cursor = reducer
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .cursor(surface)
        .ok_or_else(|| {
            neothd::daemon::gui_chat_bridge::GuiChatBridgeError::invalid(
                "detached GUI subscription",
            )
        })?;
    let mut sink = BridgeSink {
        reducer,
        state: Some(state),
        window,
        overlay,
        operation: Some(operation),
        incognito,
        throughput_projections,
        recall_chip_projections,
        response_feedback_projections,
    };
    let runtime = bridge_runtime().map_err(|_| {
        neothd::daemon::gui_chat_bridge::GuiChatBridgeError::invalid(
            "GUI runtime initialization failed",
        )
    })?;
    runtime.block_on(bridge.attach(subscription, cursor, &mut sink))
}

impl GuiChatBridgeController {
    /// Replace only the two chat transport callback families.  Existing
    /// attachment selection, model/skill selection, Incognito controls, and
    /// unrelated process actions keep their original owners.
    pub fn install(
        window: &crate::MainWindow,
        overlay: &crate::MiniOverlay,
        session_id: String,
        attachment_owner: Arc<std::sync::Mutex<Vec<std::path::PathBuf>>>,
        throughput_projections: crate::ChatThroughputProjections,
        recall_chip_projections: crate::ChatRecallChipProjections,
        response_feedback_projections: crate::ChatResponseFeedbackProjections,
    ) -> GuiChatBridgeResult<Arc<std::sync::Mutex<InstalledGuiChat>>> {
        let controller = Arc::new(Self::for_attested_current_instance(session_id)?);
        Self::install_with_controller(
            window,
            overlay,
            attachment_owner,
            throughput_projections,
            recall_chip_projections,
            response_feedback_projections,
            controller,
        )
    }

    fn install_with_controller(
        window: &crate::MainWindow,
        overlay: &crate::MiniOverlay,
        attachment_owner: Arc<std::sync::Mutex<Vec<std::path::PathBuf>>>,
        throughput_projections: crate::ChatThroughputProjections,
        recall_chip_projections: crate::ChatRecallChipProjections,
        response_feedback_projections: crate::ChatResponseFeedbackProjections,
        controller: Arc<Self>,
    ) -> GuiChatBridgeResult<Arc<std::sync::Mutex<InstalledGuiChat>>> {
        let installed = Arc::new(std::sync::Mutex::new(InstalledGuiChat {
            controller,
            active: None,
            active_operation: None,
            next_operation_id: 0,
            pending: None,
            attachments: Arc::clone(&attachment_owner),
            throughput_projections,
            recall_chip_projections,
            response_feedback_projections,
        }));

        let main = Arc::clone(&installed);
        let main_attachments = Arc::clone(&attachment_owner);
        let weak = window.as_weak();
        let overlay_weak = overlay.as_weak();
        window.on_chat_send_clicked(move |text, incognito| {
            submit(
                Arc::clone(&main),
                weak.clone(),
                overlay_weak.clone(),
                Arc::clone(&main_attachments),
                GuiChatSurface::Main,
                text.to_string(),
                incognito,
            );
        });

        let buddy = Arc::clone(&installed);
        let buddy_attachments = Arc::clone(&attachment_owner);
        let weak = window.as_weak();
        let overlay_weak = overlay.as_weak();
        overlay.on_send_clicked(move |text, incognito| {
            submit(
                Arc::clone(&buddy),
                weak.clone(),
                overlay_weak.clone(),
                Arc::clone(&buddy_attachments),
                GuiChatSurface::Buddy,
                text.to_string(),
                incognito,
            );
        });

        let stop = Arc::clone(&installed);
        let weak = window.as_weak();
        window.on_chat_stop_stream(move || stop_active(Arc::clone(&stop), weak.clone()));
        let stop = Arc::clone(&installed);
        let weak = window.as_weak();
        overlay.on_stop_stream_clicked(move || stop_active(Arc::clone(&stop), weak.clone()));

        let decide = Arc::clone(&installed);
        let weak = window.as_weak();
        let overlay_weak = overlay.as_weak();
        window.on_chat_consent_prompt_decision(move |request_id, decision| {
            decide_pending(
                Arc::clone(&decide),
                weak.clone(),
                overlay_weak.clone(),
                request_id.to_string(),
                decision.to_string(),
            );
        });
        // Restore and Hide are both Main handoffs for a live Buddy turn. They
        // persist the dragged position, detach Buddy, then attach Main with
        // the immutable active Incognito snapshot.
        let reopen = Arc::clone(&installed);
        let weak = window.as_weak();
        let overlay_weak = overlay.as_weak();
        overlay.on_restore_clicked(move || {
            if let (Some(win), Some(ov)) = (weak.upgrade(), overlay_weak.upgrade()) {
                handoff_buddy_to_main(Arc::clone(&reopen), win, ov);
            }
        });
        let detach = Arc::clone(&installed);
        let weak = window.as_weak();
        let overlay_weak = overlay.as_weak();
        overlay.on_hide_clicked(move || {
            if let (Some(win), Some(ov)) = (weak.upgrade(), overlay_weak.upgrade()) {
                handoff_buddy_to_main(Arc::clone(&detach), win, ov);
            }
        });
        Ok(installed)
    }

    #[cfg(test)]
    pub(crate) fn install_with_test_bridge(
        window: &crate::MainWindow,
        overlay: &crate::MiniOverlay,
        session_id: String,
        attachment_owner: Arc<std::sync::Mutex<Vec<std::path::PathBuf>>>,
        throughput_projections: crate::ChatThroughputProjections,
        recall_chip_projections: crate::ChatRecallChipProjections,
        response_feedback_projections: crate::ChatResponseFeedbackProjections,
        bridge: Arc<dyn GuiChatBridge>,
    ) -> GuiChatBridgeResult<Arc<std::sync::Mutex<InstalledGuiChat>>> {
        Self::install_with_controller(
            window,
            overlay,
            attachment_owner,
            throughput_projections,
            recall_chip_projections,
            response_feedback_projections,
            Arc::new(Self::new(bridge, session_id)),
        )
    }

    /// Core-only construction.  A missing or unattested daemon is a truthful
    /// UI error; this function has no GUI-side transport fallback.
    pub fn for_attested_current_instance(session_id: String) -> GuiChatBridgeResult<Self> {
        Ok(Self::new(
            neothd::daemon::gui_chat_bridge::bridge_for_attested_current_instance()?,
            session_id,
        ))
    }
    pub fn new(bridge: Arc<dyn GuiChatBridge>, session_id: String) -> Self {
        Self {
            bridge,
            reducer: Arc::new(std::sync::Mutex::new(
                DaemonChatPresentationReducer::default(),
            )),
            session_id,
        }
    }

    #[allow(clippy::too_many_arguments)] // Public typed GUI preflight boundary preserves request binding fields.
    pub async fn begin(
        &self,
        surface: GuiChatSurface,
        request_id: neothd::daemon::gui_chat_bridge::GuiChatRequestId,
        message: String,
        model: Option<String>,
        skill_id: Option<String>,
        incognito: bool,
        reasoning_display: bool,
        attachment_paths: Vec<std::path::PathBuf>,
    ) -> GuiChatBridgeResult<GuiChatBridgePreflight> {
        self.bridge
            .preflight(GuiChatBridgePreflightInput {
                request_id,
                session_id: self.session_id.clone(),
                origin_surface: surface,
                message,
                model,
                skill_id,
                incognito,
                reasoning_display,
                attachment_paths,
            })
            .await
    }

    pub async fn start_and_attach(
        &self,
        receipt: neothd::daemon::gui_chat_bridge::GuiChatBridgeDecisionReceipt,
        surface: GuiChatSurface,
        incognito: bool,
        reasoning_display: bool,
    ) -> GuiChatBridgeResult<(GuiChatBridgeTurn, GuiChatBridgeSubscription)> {
        let turn = self.bridge.start(receipt).await?;
        let subscription = self
            .bridge
            .exchange_same_session_attach(&turn, surface)
            .await?;
        self.adopt(&subscription, incognito, reasoning_display)?;
        Ok((turn, subscription))
    }

    pub async fn reopen(
        &self,
        surface: GuiChatSurface,
        incognito: bool,
        reasoning_display: bool,
    ) -> GuiChatBridgeResult<Option<(GuiChatBridgeTurn, GuiChatBridgeSubscription)>> {
        let Some(turn) = self.bridge.active().await? else {
            return Ok(None);
        };
        let subscription = self
            .bridge
            .exchange_same_session_attach(&turn, surface)
            .await?;
        self.adopt(&subscription, incognito, reasoning_display)?;
        Ok(Some((turn, subscription)))
    }

    pub async fn stop(&self, turn: &GuiChatBridgeTurn) -> GuiChatBridgeResult<()> {
        self.bridge.cancel(turn).await
    }

    pub fn close(&self, surface: GuiChatSurface) {
        self.reducer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .detach(match surface {
                GuiChatSurface::Main => crate::chat_stream_phase::ChatStreamSurface::Main,
                GuiChatSurface::Buddy => crate::chat_stream_phase::ChatStreamSurface::Buddy,
            });
    }

    fn adopt(
        &self,
        subscription: &GuiChatBridgeSubscription,
        incognito: bool,
        reasoning_display: bool,
    ) -> GuiChatBridgeResult<()> {
        let metadata = &subscription.metadata;
        let surface = match metadata.surface {
            GuiChatSurface::Main => crate::chat_stream_phase::ChatStreamSurface::Main,
            GuiChatSurface::Buddy => crate::chat_stream_phase::ChatStreamSurface::Buddy,
        };
        self.reducer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .attach(
                surface,
                DaemonChatTurnIdentity {
                    boot_id: metadata.boot_id.clone(),
                    turn_id: metadata.turn_id.as_uuid().to_string(),
                },
                metadata.generation,
                metadata.latest_sequence,
                incognito,
                reasoning_display,
            )
            .map_err(|_| {
                neothd::daemon::gui_chat_bridge::GuiChatBridgeError::invalid(
                    "invalid daemon subscription",
                )
            })
    }
}

/// Preserve the ordinary overlay lifecycle while changing only the transport
/// projection. Callback replacement would otherwise lose `save_overlay_pos`.
fn handoff_buddy_to_main(
    state: Arc<std::sync::Mutex<InstalledGuiChat>>,
    window: crate::MainWindow,
    overlay: crate::MiniOverlay,
) {
    crate::save_overlay_pos(&overlay);
    clear_daemon_reasoning_projection(&window, Some(&overlay));
    let retained_turn_options = {
        let locked = state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(operation) = locked.active_operation {
            crate::clear_daemon_throughput_projection(&locked.throughput_projections, operation.id);
            crate::clear_daemon_recall_chip_projection(
                &locked.recall_chip_projections,
                operation.id,
            );
        }
        crate::clear_main_throughput_projection(&window);
        crate::clear_buddy_throughput_projection(&overlay);
        crate::clear_main_recall_chip_projection(&window);
        crate::clear_buddy_recall_chip_projection(&overlay);
        locked.controller.close(GuiChatSurface::Buddy);
        locked
            .active
            .as_ref()
            .map(|active| (active.incognito, active.reasoning_display))
    };
    let _ = overlay.hide();
    let _ = window.show();
    if let Some((incognito, reasoning_display)) = retained_turn_options {
        reopen_surface(
            state,
            window.as_weak(),
            overlay.as_weak(),
            GuiChatSurface::Main,
            incognito,
            reasoning_display,
        );
    }
}

fn reopen_surface(
    state: Arc<std::sync::Mutex<InstalledGuiChat>>,
    window: slint::Weak<crate::MainWindow>,
    overlay: slint::Weak<crate::MiniOverlay>,
    surface: GuiChatSurface,
    incognito: bool,
    reasoning_display: bool,
) {
    let (controller, operation) = {
        let mut locked = state.lock().unwrap_or_else(|p| p.into_inner());
        let Some(operation) = locked.begin_reopen_operation(surface) else {
            return;
        };
        (Arc::clone(&locked.controller), operation)
    };
    std::thread::spawn(move || {
        let result = (|| {
            let runtime = bridge_runtime().map_err(|_| {
                neothd::daemon::gui_chat_bridge::GuiChatBridgeError::invalid(
                    "GUI runtime initialization failed",
                )
            })?;
            runtime.block_on(controller.reopen(surface, incognito, reasoning_display))
        })();
        let _ = slint::invoke_from_event_loop(move || {
            let Some(win) = window.upgrade() else {
                return;
            };
            let (turn, subscription) = match result {
                Ok(Some(pair)) => pair,
                Ok(None) => {
                    fail_current_projection(
                        &state,
                        operation,
                        &win,
                        overlay.upgrade().as_ref(),
                        "Daemon chat is no longer active.",
                    );
                    return;
                }
                Err(error) => {
                    fail_current_projection(
                        &state,
                        operation,
                        &win,
                        overlay.upgrade().as_ref(),
                        &error.to_string(),
                    );
                    return;
                }
            };
            let returned_turn_id = turn.metadata.turn_id.as_uuid().to_string();
            let (
                bridge,
                reducer,
                throughput_projections,
                recall_chip_projections,
                response_feedback_projections,
            ) = {
                let mut locked = state.lock().unwrap_or_else(|p| p.into_inner());
                if !locked.operation_is_current(operation) {
                    return;
                }
                let Some(active) = locked.active.as_mut() else {
                    return;
                };
                if active.operation != operation
                    || active.daemon_turn_id != returned_turn_id
                    || active.incognito != incognito
                    || active.reasoning_display != reasoning_display
                {
                    return;
                }
                active.turn = Arc::new(turn);
                (
                    Arc::clone(&locked.controller.bridge),
                    Arc::clone(&locked.controller.reducer),
                    locked.throughput_projections.clone(),
                    locked.recall_chip_projections.clone(),
                    locked.response_feedback_projections.clone(),
                )
            };
            std::thread::spawn(move || {
                let result = attach_subscription(
                    bridge,
                    reducer,
                    throughput_projections,
                    recall_chip_projections,
                    response_feedback_projections,
                    Arc::clone(&state),
                    operation,
                    subscription,
                    window.clone(),
                    overlay.clone(),
                    incognito,
                );
                if let Err(error) = result {
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(win) = window.upgrade() {
                            fail_current_projection(
                                &state,
                                operation,
                                &win,
                                overlay.upgrade().as_ref(),
                                &error.to_string(),
                            );
                        }
                    });
                }
            });
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_settlement_requires_the_current_request_turn_and_surface() {
        let old = GuiChatOperation {
            id: 7,
            origin_surface: GuiChatSurface::Main,
            delivery_surface: GuiChatSurface::Main,
        };
        let current = GuiChatOperation {
            id: 8,
            origin_surface: GuiChatSurface::Buddy,
            delivery_surface: GuiChatSurface::Buddy,
        };

        assert!(!operation_matches_turn(
            Some(current),
            old,
            "daemon-turn-old",
            old,
            "daemon-turn-old",
            GuiChatSurface::Main,
            false,
            false,
        ));
        assert!(!operation_matches_turn(
            Some(current),
            current,
            "daemon-turn-current",
            current,
            "daemon-turn-old",
            GuiChatSurface::Buddy,
            false,
            false,
        ));
        assert!(!operation_matches_turn(
            Some(current),
            current,
            "daemon-turn-current",
            current,
            "daemon-turn-current",
            GuiChatSurface::Main,
            false,
            false,
        ));
        assert!(operation_matches_turn(
            Some(current),
            current,
            "daemon-turn-current",
            current,
            "daemon-turn-current",
            GuiChatSurface::Buddy,
            false,
            false,
        ));
    }

    #[test]
    fn buddy_origin_restore_binds_the_new_main_delivery_surface() {
        let buddy_origin = GuiChatOperation {
            id: 9,
            origin_surface: GuiChatSurface::Buddy,
            delivery_surface: GuiChatSurface::Buddy,
        };
        let restored_main = GuiChatOperation {
            id: 10,
            origin_surface: buddy_origin.origin_surface,
            delivery_surface: GuiChatSurface::Main,
        };

        assert_eq!(restored_main.origin_surface, GuiChatSurface::Buddy);
        assert!(operation_matches_turn(
            Some(restored_main),
            restored_main,
            "daemon-turn",
            restored_main,
            "daemon-turn",
            GuiChatSurface::Main,
            true,
            true,
        ));
        assert!(!operation_matches_turn(
            Some(restored_main),
            restored_main,
            "daemon-turn",
            restored_main,
            "daemon-turn",
            GuiChatSurface::Buddy,
            true,
            true,
        ));
    }

    #[test]
    fn reopen_none_or_error_settles_only_the_current_main_handoff() {
        let detached_buddy = GuiChatOperation {
            id: 15,
            origin_surface: GuiChatSurface::Buddy,
            delivery_surface: GuiChatSurface::Buddy,
        };
        let current_main_handoff = GuiChatOperation {
            id: 16,
            origin_surface: GuiChatSurface::Buddy,
            delivery_surface: GuiChatSurface::Main,
        };

        assert!(current_operation_matches(
            Some(current_main_handoff),
            current_main_handoff
        ));
        assert!(!current_operation_matches(
            Some(current_main_handoff),
            detached_buddy
        ));
    }

    #[test]
    fn stale_consent_decision_never_matches_the_retained_challenge() {
        assert!(pending_request_matches("pending-42", "pending-42"));
        assert!(!pending_request_matches("pending-42", "delayed-41"));
    }

    #[test]
    fn malformed_consent_decision_is_rejected_before_pending_receipt_take() {
        assert!(parse_consent_decision("deny").is_some());
        assert!(parse_consent_decision("allow-once").is_some());
        assert!(parse_consent_decision("allow-always").is_some());
        assert!(parse_consent_decision("unexpected-decision").is_none());
    }

    #[test]
    fn every_buddy_modal_no_start_outcome_restores_the_hidden_surface() {
        assert!(restores_hidden_buddy_after_no_start(GuiChatSurface::Buddy));
        assert!(!restores_hidden_buddy_after_no_start(GuiChatSurface::Main));
    }

    #[test]
    fn only_terminal_non_incognito_delivery_can_publish_a_preview() {
        assert!(!preview_is_publishable(false, false));
        assert!(!preview_is_publishable(true, true));
        assert!(preview_is_publishable(false, true));
    }

    #[test]
    fn daemon_terminal_target_reaches_the_shared_action_map_only_for_the_current_turn() {
        let projections: crate::ChatResponseFeedbackProjections =
            Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let gui_subscription_session = "neothd-gui";
        let core_terminal_session = "session-w164-core";
        assert_ne!(gui_subscription_session, core_terminal_session);

        let snapshot = crate::accept_daemon_response_feedback_terminal(
            &projections,
            41,
            Some("aabbccddeeff00112233445566778899".into()),
            Some(core_terminal_session.into()),
            Some(0),
            false,
        )
        .expect("current complete terminal target");
        assert!(snapshot.available);
        let (_, target, _) = crate::begin_current_response_feedback_action(
            &projections,
            crate::chat_response_feedback::Action::Set(
                crate::chat_response_feedback::FeedbackSignal::NeedsCorrection,
            ),
        )
        .expect("daemon target reaches the shared response-feedback action map");
        assert_eq!(target.session_id(), core_terminal_session);

        let current = GuiChatOperation {
            id: 41,
            origin_surface: GuiChatSurface::Main,
            delivery_surface: GuiChatSurface::Main,
        };
        let stale = GuiChatOperation {
            id: 40,
            origin_surface: GuiChatSurface::Buddy,
            delivery_surface: GuiChatSurface::Buddy,
        };
        assert!(!operation_matches_turn(
            Some(current),
            current,
            "daemon-turn-current",
            stale,
            "daemon-turn-stale",
            GuiChatSurface::Buddy,
            false,
            false,
        ));
        // `BridgeSink::on_event` returns at this exact guard before it calls
        // `accept_daemon_response_feedback_terminal`; the newer target above
        // therefore remains the only action target.
        assert!(
            projections
                .lock()
                .expect("shared target map")
                .contains_key(&crate::daemon_response_feedback_projection_id(41))
        );

        let malformed: crate::ChatResponseFeedbackProjections =
            Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        assert!(
            crate::accept_daemon_response_feedback_terminal(
                &malformed,
                42,
                Some("aabbccddeeff00112233445566778899".into()),
                None,
                Some(0),
                false,
            )
            .is_err()
        );
        assert!(
            crate::begin_current_response_feedback_action(
                &malformed,
                crate::chat_response_feedback::Action::Remove,
            )
            .is_none()
        );
    }
}
