//! Non-public A2/A5/A7 conversation owner.
//!
//! This is intentionally a consumer, not a second provider/media framework.
//! It joins the existing capture/Silero/STT path, bridge-authorized visible
//! text, configured TTS and the concrete CPAL playback owner under one leased
//! [`AudioWorkPermit`].  A later authorized GUI surface supplies microphone and
//! provider decisions; this module never chooses either on an operator's behalf.

use super::audio::{AudioWorkPermit, acquire_audio_work_permit};
use super::conversation_scope::{CancelScope, GenerationToken};
use super::dictation::{
    LiveUtteranceAssembler, LiveUtteranceEvent, transcribe_live_utterance_with_audio_permit,
};
use super::live_capture::{CpalCaptureConfig, CpalCaptureSession, LiveCaptureEvent};
use super::lm_output_processor::LmOutputProcessor;
use super::playback::{CpalPlaybackConfig, CpalPlaybackSession, PcmS16leBlock, PlaybackEvent};
use super::tts_cloud::{TtsRunOverrides, synthesize_configured_response};
use super::tts_dispatch::TtsFormat;
use super::turn_tracker::{TurnDisposition, TurnTracker};
use crate::daemon::authorized_text_turn::{
    AuthorizedTextTurn, AuthorizedTextTurnConfirmation, AuthorizedTextTurnSink,
    AuthorizedTextTurnStart, AuthorizedTextTurnSupervisor, AuthorizedTextTurnTerminal,
};
use crate::daemon::conversation_session::ConversationTaskRegistry;
use crate::daemon::gui_chat_bridge::{
    GuiChatBridgePreflightInput, GuiChatConsentDecision, GuiChatConsentPrompt, GuiChatRequestId,
};
use crate::permissions::microphone::{
    MicConsentStore, MicDecision, MicPreflight, MicStartCapability,
};
use crate::wal::microphone_receipts::{
    MicOpenIntentAdmission, MicOpenOutcome, TurnCancelAdmission, TurnCancelCause,
};
use crate::wal::writer::WalWriterHandle;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// This value is intentionally conservative: fragments below it do not cross
/// the STT or provider boundary.  The future UI may only expose a validated
/// value; it must not lower this to zero.
pub(crate) const DEFAULT_MIN_FRAGMENT_MS: u64 = 100;

fn voiced_samples_for_fragment_ms(min_fragment_ms: u64) -> Result<usize, &'static str> {
    usize::try_from(min_fragment_ms)
        .ok()
        .and_then(|milliseconds| milliseconds.checked_mul(16))
        .ok_or("conversation_fragment_threshold_overflow")
}

fn qualifies_barge_in(already_qualified: bool, voiced_samples: usize, threshold: usize) -> bool {
    !already_qualified && voiced_samples >= threshold
}

/// A bounded projection of current response facts, owned by the A2 loop.
/// Neither a partial playback nor an incomplete/failed text turn arms it.
#[cfg(any(test, feature = "live-audio"))]
struct FollowUpWindow {
    duration: Option<Duration>,
    completed: Option<GenerationToken>,
    played: Option<GenerationToken>,
    deadline: Option<(GenerationToken, std::time::Instant)>,
}

#[cfg(any(test, feature = "live-audio"))]
impl FollowUpWindow {
    fn new(duration: Option<Duration>) -> Self {
        Self {
            duration,
            completed: None,
            played: None,
            deadline: None,
        }
    }

    fn observe_settled(
        &mut self,
        scope: &CancelScope,
        generation: &GenerationToken,
        terminal: AuthorizedTextTurnTerminal,
    ) {
        if scope.is_stale(generation) {
            return;
        }
        if terminal == AuthorizedTextTurnTerminal::Complete {
            self.completed = Some(generation.clone());
        } else {
            self.completed = None;
            self.played = None;
            self.deadline = None;
        }
    }

    fn observe_playback(&mut self, scope: &CancelScope, generation: &GenerationToken) {
        if !scope.is_stale(generation) {
            self.played = Some(generation.clone());
        }
    }

    fn reconcile(
        &mut self,
        scope: &CancelScope,
        audio_idle: bool,
        now: std::time::Instant,
    ) -> Result<bool, &'static str> {
        if self
            .completed
            .as_ref()
            .is_some_and(|token| scope.is_stale(token))
        {
            self.completed = None;
        }
        if self
            .played
            .as_ref()
            .is_some_and(|token| scope.is_stale(token))
        {
            self.played = None;
        }
        if self
            .deadline
            .as_ref()
            .is_some_and(|(token, _)| scope.is_stale(token))
        {
            self.deadline = None;
        }
        if !audio_idle {
            self.deadline = None;
            return Ok(false);
        }
        if self.deadline.is_some() {
            return Ok(false);
        }
        let Some(duration) = self.duration else {
            return Ok(false);
        };
        let (Some(completed), Some(played)) = (&self.completed, &self.played) else {
            return Ok(false);
        };
        if !completed.same_generation(played) {
            return Ok(false);
        }
        let deadline = now
            .checked_add(duration)
            .ok_or("conversation_follow_up_deadline_overflow")?;
        self.deadline = Some((completed.clone(), deadline));
        Ok(true)
    }

    fn deadline(&self, scope: &CancelScope) -> Option<std::time::Instant> {
        self.deadline
            .as_ref()
            .filter(|(token, _)| !scope.is_stale(token))
            .map(|(_, deadline)| *deadline)
    }

    fn expire(&mut self, scope: &CancelScope, now: std::time::Instant) -> bool {
        if !self.deadline(scope).is_some_and(|deadline| now >= deadline) {
            return false;
        }
        self.deadline = None;
        self.completed = None;
        self.played = None;
        true
    }
}

/// Admission is the relay observation time, not the hardware callback time.
/// One blocking relay owns the bounded queue; its clock never restamps retries.
#[derive(Debug)]
struct AdmittedCapture {
    admitted_at: std::time::Instant,
    event: LiveCaptureEvent,
}

enum A2CaptureInput {
    Event(LiveCaptureEvent),
    FollowUpExpired,
}

fn capture_precedes_expiry(admitted: &AdmittedCapture, deadline: std::time::Instant) -> bool {
    admitted.admitted_at <= deadline
        || matches!(
            &admitted.event,
            LiveCaptureEvent::Error(_) | LiveCaptureEvent::Cancelled
        )
}

fn capture_at_expiry(
    capture_rx: &mut tokio::sync::mpsc::Receiver<AdmittedCapture>,
    deadline: std::time::Instant,
) -> A2CaptureInput {
    // Inspect only the existing bounded backlog. Later noise cannot keep this
    // scan alive. Preserve eligible input and terminals queued behind late PCM.
    let buffered = capture_rx.len();
    for _ in 0..buffered {
        let Ok(admitted) = capture_rx.try_recv() else {
            break;
        };
        if capture_precedes_expiry(&admitted, deadline) {
            return A2CaptureInput::Event(admitted.event);
        }
    }
    A2CaptureInput::FollowUpExpired
}

async fn next_a2_capture(
    capture_rx: &mut tokio::sync::mpsc::Receiver<AdmittedCapture>,
    deadline: Option<std::time::Instant>,
) -> Option<A2CaptureInput> {
    let Some(limit) = deadline else {
        return capture_rx
            .recv()
            .await
            .map(|admitted| A2CaptureInput::Event(admitted.event));
    };
    let admitted = tokio::select! {
        biased;
        event = capture_rx.recv() => event?,
        _ = tokio::time::sleep_until(limit.into()) => {
            return Some(capture_at_expiry(capture_rx, limit));
        }
    };
    if capture_precedes_expiry(&admitted, limit) {
        Some(A2CaptureInput::Event(admitted.event))
    } else {
        Some(capture_at_expiry(capture_rx, limit))
    }
}

#[derive(Clone, Copy, Debug)]
enum CaptureTerminal {
    Cancelled,
    Failed,
}

async fn publish_follow_up_stop(
    event_tx: &tokio::sync::mpsc::Sender<ConversationEvent>,
    settled: Result<(), &'static str>,
    capture_terminal: Option<CaptureTerminal>,
) -> Result<(), &'static str> {
    let settled = settled.and(match capture_terminal {
        Some(CaptureTerminal::Failed) => Err("capture_terminal_error"),
        _ => Ok(()),
    });
    let event = match (settled, capture_terminal) {
        (Ok(()), Some(CaptureTerminal::Cancelled)) => ConversationEvent::Cancelled,
        (Ok(()), _) => ConversationEvent::FollowUpExpired,
        (Err(reason), _) => ConversationEvent::Failed(reason),
    };
    let published = event_tx
        .send(event)
        .await
        .map_err(|_| "a2_event_queue_closed");
    // Report a failed autonomous stop even when no further control RPC arrives,
    // and retain cleanup failure as the primary cause if the receiver also left.
    settled.and(published)
}

fn preflight_for_transcript(
    template: &GuiChatBridgePreflightInput,
    transcript: String,
) -> GuiChatBridgePreflightInput {
    let mut input = template.clone();
    input.request_id = GuiChatRequestId::new();
    input.message = transcript;
    input
}

#[derive(Clone)]
pub(crate) struct ConversationDependencies {
    pub(crate) home: PathBuf,
    pub(crate) config_digest: String,
    pub(crate) media: crate::config::features::MediaConfig,
    pub(crate) updater: crate::config::UpdaterConfig,
    pub(crate) freedom: crate::config::FreedomConfig,
    pub(crate) credentials: crate::config::credentials::Credentials,
    pub(crate) wal: WalWriterHandle,
    pub(crate) playback: CpalPlaybackConfig,
    /// Bound before `open`; only its `message` is replaced by an accepted STT
    /// transcript inside the retained owner.
    pub(crate) preflight: GuiChatBridgePreflightInput,
    pub(crate) min_fragment_ms: u64,
    pub(crate) task_registry: ConversationTaskRegistry,
}

/// Typed outcomes the later GUI maps to status.  A provider or microphone
/// decision is deliberately surfaced as a pending event rather than inferred.
pub(crate) enum ConversationEvent {
    MicrophoneConfirmationRequired,
    Listening,
    ProviderConfirmationRequired(GuiChatConsentPrompt),
    TranscriptAccepted {
        turn_id: u64,
    },
    SpeechCompleted {
        terminal: AuthorizedTextTurnTerminal,
    },
    Cancelled,
    /// Published only after normal A2 cleanup and release of its audio permit.
    FollowUpExpired,
    Failed(&'static str),
}

pub(crate) enum ConversationStart {
    ConfirmationRequired {
        challenge: crate::permissions::microphone::MicChallenge,
    },
    Capability(MicStartCapability),
}

fn opening_cancelled(scope: &CancelScope, token: &GenerationToken) -> bool {
    scope.is_stale(token)
}

/// A live capture persists across barge-in.  `capture_scope` governs device
/// lifetime; `response_scope` governs the currently spoken LLM/TTS/playback
/// generation.  Invalidating the latter never stops the microphone.
pub(crate) struct ConversationSession {
    dependencies: ConversationDependencies,
    microphone: MicConsentStore,
    capture_scope: CancelScope,
    response_scope: CancelScope,
    permit: AudioWorkPermit,
    capture: CpalCaptureSession,
    assembler: LiveUtteranceAssembler,
    supervisor: AuthorizedTextTurnSupervisor,
}

impl ConversationSession {
    /// This preflight writes nothing and opens no device.  The caller must
    /// present a returned challenge and feed the exact decision to `decide`.
    pub(crate) fn microphone_preflight(
        microphone: &mut MicConsentStore,
        config_digest: &str,
    ) -> Result<ConversationStart, &'static str> {
        match microphone
            .preflight(config_digest, now_unix())
            .map_err(|_| "microphone_preflight_failed")?
        {
            MicPreflight::Granted { capability } => Ok(ConversationStart::Capability(capability)),
            MicPreflight::ConfirmationRequired { challenge } => {
                Ok(ConversationStart::ConfirmationRequired { challenge })
            }
        }
    }

    pub(crate) fn microphone_decide(
        microphone: &mut MicConsentStore,
        challenge: crate::permissions::microphone::MicChallenge,
        decision: MicDecision,
    ) -> Result<Option<MicStartCapability>, &'static str> {
        microphone
            .decide(challenge, decision, now_unix())
            .map_err(|_| "microphone_decision_failed")
    }

    /// Open capture in the required durable order.  Failure after intent is
    /// recorded as a typed terminal before returning to the UI.
    pub(crate) async fn open(
        mut microphone: MicConsentStore,
        capability: MicStartCapability,
        dependencies: ConversationDependencies,
        supervisor: AuthorizedTextTurnSupervisor,
        capture_config: CpalCaptureConfig,
        opening_scope: CancelScope,
        opening_token: GenerationToken,
    ) -> Result<Self, (&'static str, AuthorizedTextTurnSupervisor)> {
        macro_rules! fail {
            ($reason:expr) => {
                return Err(($reason, supervisor))
            };
        }
        if dependencies.min_fragment_ms < DEFAULT_MIN_FRAGMENT_MS
            || voiced_samples_for_fragment_ms(dependencies.min_fragment_ms).is_err()
            || dependencies
                .media
                .conversation_follow_up_duration()
                .is_err()
            || dependencies.config_digest.len() != 64
        {
            fail!("invalid_conversation_capture_configuration");
        }
        let admission = match microphone.consume_for_open(
            capability,
            &dependencies.config_digest,
            now_unix(),
        ) {
            Ok(admission) => admission,
            Err(_) => fail!("microphone_capability_rejected"),
        };
        let intent = MicOpenIntentAdmission::from_consumed(admission);
        let terminal = match dependencies.wal.append_microphone_open_intent(intent).await {
            Ok(terminal) => terminal,
            Err(_) => fail!("microphone_open_intent_not_durable"),
        };

        let permit = match acquire_audio_work_permit().await {
            Ok(permit) => permit,
            Err(_) => {
                let result = match terminal.complete(
                    MicOpenOutcome::Failed,
                    Some("audio_permit_unavailable"),
                    now_unix(),
                ) {
                    Ok(result) => result,
                    Err(_) => fail!("microphone_open_terminal_invalid"),
                };
                if dependencies
                    .wal
                    .append_microphone_open_result(result)
                    .await
                    .is_err()
                {
                    fail!("microphone_open_result_not_durable");
                }
                fail!("audio_permit_unavailable");
            }
        };
        // Acquiring the sole permit may wait behind another conversation.  A
        // cancellation during that wait must settle the already durable intent
        // without constructing CPAL capture.
        if opening_cancelled(&opening_scope, &opening_token) {
            let result = match terminal.complete(
                MicOpenOutcome::Failed,
                Some("opening_cancelled_before_capture"),
                now_unix(),
            ) {
                Ok(result) => result,
                Err(_) => fail!("microphone_open_terminal_invalid"),
            };
            if dependencies
                .wal
                .append_microphone_open_result(result)
                .await
                .is_err()
            {
                fail!("microphone_open_result_not_durable");
            }
            fail!("opening_cancelled_before_capture");
        }
        // The one-slot permit may have waited for up to 120 seconds.  Authority
        // is checked again immediately before the irreversible native open;
        // revocation during that wait must produce the durable failed terminal.
        let pre_open = terminal.revalidate_device_open(&microphone);
        if pre_open.is_err() || opening_cancelled(&opening_scope, &opening_token) {
            let error = if opening_cancelled(&opening_scope, &opening_token) {
                "opening_cancelled_before_capture"
            } else {
                "microphone_authority_drift"
            };
            let result = match terminal.complete(MicOpenOutcome::Failed, Some(error), now_unix()) {
                Ok(result) => result,
                Err(_) => fail!("microphone_open_terminal_invalid"),
            };
            if dependencies
                .wal
                .append_microphone_open_result(result)
                .await
                .is_err()
            {
                fail!("microphone_open_result_not_durable");
            }
            fail!(error);
        }
        // Keep the owner-visible opening scope as the capture lifetime scope:
        // an abort issued while the native device opens reaches this owner too.
        let capture_scope = opening_scope;
        let mut capture = match CpalCaptureSession::start(
            capture_config,
            capture_scope.clone(),
            permit.clone(),
        ) {
            Ok(capture) => capture,
            Err(_) => {
                let result = match terminal.complete(
                    MicOpenOutcome::Failed,
                    Some("capture_start_failed"),
                    now_unix(),
                ) {
                    Ok(result) => result,
                    Err(_) => fail!("microphone_open_terminal_invalid"),
                };
                if dependencies
                    .wal
                    .append_microphone_open_result(result)
                    .await
                    .is_err()
                {
                    fail!("microphone_open_result_not_durable");
                }
                fail!("capture_start_failed");
            }
        };
        // CPAL construction alone is not listening.  Require its owner to
        // publish Ready before the durable opened result and UI event.
        if !matches!(
            capture.next_event(Duration::from_secs(5)),
            Ok(Some(LiveCaptureEvent::Ready { .. }))
        ) {
            capture.cancel_and_join();
            let result = match terminal.complete(
                MicOpenOutcome::Failed,
                Some("capture_ready_not_observed"),
                now_unix(),
            ) {
                Ok(result) => result,
                Err(_) => fail!("microphone_open_terminal_invalid"),
            };
            if dependencies
                .wal
                .append_microphone_open_result(result)
                .await
                .is_err()
            {
                fail!("microphone_open_result_not_durable");
            }
            fail!("capture_ready_not_observed");
        }
        let result = match terminal.complete(MicOpenOutcome::Opened, None, now_unix()) {
            Ok(result) => result,
            Err(_) => {
                capture.cancel_and_join();
                fail!("microphone_open_terminal_invalid");
            }
        };
        if dependencies
            .wal
            .append_microphone_open_result(result)
            .await
            .is_err()
        {
            capture.cancel_and_join();
            fail!("microphone_open_result_not_durable");
        }
        // A late cancellation is observable only after the concrete owner has
        // reported Ready.  Record that real open, then synchronously join it;
        // returning an error prevents a hidden live session from escaping.
        if opening_cancelled(&capture_scope, &opening_token) {
            capture.cancel_and_join();
            fail!("opening_cancelled_after_capture_ready");
        }
        let assembler = match LiveUtteranceAssembler::new(&dependencies.media) {
            Ok(assembler) => assembler,
            Err(_) => {
                capture.cancel_and_join();
                fail!("silero_vad_initialization_failed");
            }
        };
        Ok(Self {
            microphone,
            dependencies,
            capture_scope,
            response_scope: CancelScope::new(),
            permit,
            capture,
            assembler,
            supervisor,
        })
    }

    /// Consumes the successfully opened session and makes this the sole live
    /// owner.  The daemon gives the GUI only the bounded control/event ends;
    /// capture, permit, assembler, supervisor and registry cannot escape into
    /// a second sequential caller.
    #[cfg(feature = "live-audio")]
    pub(crate) async fn run(
        self,
        control_rx: tokio::sync::mpsc::Receiver<A2Control>,
        event_tx: tokio::sync::mpsc::Sender<ConversationEvent>,
    ) -> Result<(), &'static str> {
        let Self {
            dependencies,
            capture_scope,
            response_scope,
            permit,
            capture,
            assembler,
            supervisor,
            ..
        } = self;
        let registry = dependencies.task_registry.clone();
        run_a2_session(
            capture,
            capture_scope,
            response_scope,
            registry,
            control_rx,
            event_tx,
            A2SessionDependencies {
                media: dependencies.media,
                updater: dependencies.updater,
                home: dependencies.home,
                wal: dependencies.wal,
                permit,
                freedom: dependencies.freedom,
                credentials: dependencies.credentials,
                playback: dependencies.playback,
                supervisor,
                preflight: dependencies.preflight,
                assembler,
                min_fragment_ms: dependencies.min_fragment_ms,
            },
        )
        .await
    }
}

fn wait_for_playback_ready(
    playback: &mut CpalPlaybackSession,
) -> Result<super::playback::PlaybackOutputFormat, ()> {
    for _ in 0..50 {
        match playback
            .next_event(Duration::from_millis(100))
            .map_err(|_| ())?
        {
            Some(PlaybackEvent::Ready(format)) => return Ok(format),
            Some(PlaybackEvent::Cancelled | PlaybackEvent::Completed | PlaybackEvent::Error(_)) => {
                return Err(());
            }
            Some(_) | None => {}
        }
    }
    Err(())
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}

// The retained daemon task owns this select-loop.  It is deliberately a
// concrete A2 mailbox, rather than a reusable actor abstraction: capture/VAD
// events, bridge-visible text and output terminals are the only admissible
// inputs.  `biased` gives barge-in and shutdown priority over every pending
// synthesis/playback result.
#[cfg(feature = "live-audio")]
pub(crate) enum A2MailboxEvent {
    Capture(LiveCaptureEvent),
    VisibleDelta {
        generation: GenerationToken,
        text: String,
    },
    VisibleTerminal {
        generation: GenerationToken,
    },
    /// A terminal observed by the authorized bridge, including cancellation
    /// settlement.  This is the only fact that releases the prior turn gate.
    VisibleSettled {
        generation: GenerationToken,
        terminal: AuthorizedTextTurnTerminal,
    },
    SttComplete {
        generation: GenerationToken,
        transcript: Result<String, &'static str>,
    },
    TtsComplete {
        generation: GenerationToken,
        pcm: Result<super::tts_cloud::VerifiedPcmS16leResponse, &'static str>,
    },
    PlaybackComplete {
        generation: GenerationToken,
        result: Result<(), &'static str>,
    },
}

#[cfg(feature = "live-audio")]
pub(crate) enum A2Control {
    BargeIn,
    Shutdown,
    /// Only the later GUI surface can possess the sealed confirmation and its
    /// exact decision.  This loop merely forwards both to the supervisor.
    ProviderDecision(GuiChatRequestId, GuiChatConsentDecision),
}

/// Values retained by the real conversation owner.  Construction happens only
/// after microphone intent/permit/Ready in `ConversationSession::open`; this
/// path deliberately accepts the already-acquired lease instead of acquiring
/// a second one.
#[cfg(feature = "live-audio")]
pub(crate) struct A2SessionDependencies {
    pub(crate) media: crate::config::features::MediaConfig,
    pub(crate) updater: crate::config::UpdaterConfig,
    pub(crate) home: PathBuf,
    pub(crate) wal: WalWriterHandle,
    pub(crate) permit: AudioWorkPermit,
    pub(crate) freedom: crate::config::FreedomConfig,
    pub(crate) credentials: crate::config::credentials::Credentials,
    pub(crate) playback: CpalPlaybackConfig,
    pub(crate) supervisor: AuthorizedTextTurnSupervisor,
    pub(crate) preflight: GuiChatBridgePreflightInput,
    pub(crate) assembler: LiveUtteranceAssembler,
    pub(crate) min_fragment_ms: u64,
}

#[cfg(feature = "live-audio")]
struct TtsStageInputs {
    home: PathBuf,
    freedom: crate::config::FreedomConfig,
    credentials: crate::config::credentials::Credentials,
    permit: AudioWorkPermit,
}

#[cfg(feature = "live-audio")]
impl From<&A2SessionDependencies> for TtsStageInputs {
    fn from(dependencies: &A2SessionDependencies) -> Self {
        Self {
            home: dependencies.home.clone(),
            freedom: dependencies.freedom.clone(),
            credentials: dependencies.credentials.clone(),
            permit: dependencies.permit.clone(),
        }
    }
}

/// The operative retained session loop.  Capture continues while every
/// configured STT/TTS/CPAL stage is awaited through the daemon registry.
/// Every worker sends a bounded fact to `stage_rx`; a stale generation is
/// discarded before it can reach the following stage.
#[cfg(feature = "live-audio")]
pub(crate) async fn run_a2_session(
    mut capture: CpalCaptureSession,
    capture_scope: CancelScope,
    response_scope: CancelScope,
    registry: crate::daemon::conversation_session::ConversationTaskRegistry,
    mut control_rx: tokio::sync::mpsc::Receiver<A2Control>,
    event_tx: tokio::sync::mpsc::Sender<ConversationEvent>,
    mut dependencies: A2SessionDependencies,
) -> Result<(), &'static str> {
    let follow_up_duration = dependencies
        .media
        .conversation_follow_up_duration()
        .map_err(|_| "invalid_conversation_follow_up_configuration")?;
    let (capture_tx, mut capture_rx) = tokio::sync::mpsc::channel(32);
    // Terminal facts bypass PCM backpressure and are read only after relay join.
    let (capture_terminal_tx, mut capture_terminal_rx) = tokio::sync::oneshot::channel();
    let (stage_tx, mut stage_rx) = tokio::sync::mpsc::channel(8);
    let relay_scope = capture_scope.clone();
    let mut outstanding_stages = 1usize;
    registry
        .spawn_stage(async move {
            tokio::task::spawn_blocking(move || -> Result<(), &'static str> {
                let token = relay_scope
                    .snapshot()
                    .map_err(|_| "capture_scope_exhausted")?;
                loop {
                    if relay_scope.is_stale(&token) {
                        capture.cancel_and_join();
                        return Ok(());
                    }
                    match capture
                        .next_event(Duration::from_millis(50))
                        .map_err(|_| "capture_event_failed")?
                    {
                        Some(event @ LiveCaptureEvent::Frame(_))
                        | Some(event @ LiveCaptureEvent::Ready { .. }) => {
                            if capture_tx
                                .blocking_send(AdmittedCapture {
                                    admitted_at: std::time::Instant::now(),
                                    event,
                                })
                                .is_err()
                            {
                                capture.cancel_and_join();
                                return if relay_scope.is_stale(&token) {
                                    Ok(())
                                } else {
                                    Err("capture_queue_closed")
                                };
                            }
                        }
                        Some(event @ LiveCaptureEvent::Error(_))
                        | Some(event @ LiveCaptureEvent::Cancelled) => {
                            let terminal = if matches!(&event, LiveCaptureEvent::Cancelled) {
                                CaptureTerminal::Cancelled
                            } else {
                                CaptureTerminal::Failed
                            };
                            let _ = capture_terminal_tx.send(terminal);
                            // Receiver closure during expiry cleanup does not erase
                            // the terminal witness retained above.
                            if capture_tx
                                .blocking_send(AdmittedCapture {
                                    admitted_at: std::time::Instant::now(),
                                    event,
                                })
                                .is_err()
                                && !relay_scope.is_stale(&token)
                            {
                                return Err("capture_terminal_queue_closed");
                            }
                            return Ok(());
                        }
                        None => {}
                    }
                }
            })
            .await
            .map_err(|_| "capture_relay_panicked")?
        })
        .await?;

    let mut turns = TurnTracker::default();
    let barge_in_voiced_samples = voiced_samples_for_fragment_ms(dependencies.min_fragment_ms)?;
    let mut output = LmOutputProcessor::new(dependencies.freedom.media.tts.max_chars_per_request)?;
    let mut active_cancel: Option<tokio::sync::oneshot::Sender<()>> = None;
    let mut pending_confirmation: Option<(GenerationToken, AuthorizedTextTurnConfirmation)> = None;
    // A qualified barge-in may accept one transcript while the old bridge turn
    // settles, but must never start/decide the next turn before that fact.
    let mut pending_transcript: Option<(GenerationToken, String)> = None;
    let mut awaiting_turn_settlement: Option<GenerationToken> = None;
    let mut active_visible_generation: Option<GenerationToken> = None;
    // One bounded serial audio lane preserves sentence order and prevents
    // concurrent CPAL owners.  A full lane is a terminal backpressure error.
    let mut pending_audio: VecDeque<(GenerationToken, String)> = VecDeque::with_capacity(8);
    // The occupied slot belongs to a TTS or CPAL worker until that worker
    // reports completion, even when its generation has become stale.
    let mut audio_owner: Option<GenerationToken> = None;
    let mut speech_has_qualified = false;
    let mut follow_up = FollowUpWindow::new(follow_up_duration);
    let mut follow_up_expired = false;
    let loop_result: Result<(), &'static str> = async {
    event_tx.try_send(ConversationEvent::Listening).map_err(|_| "a2_event_queue_closed")?;
    loop {
        if follow_up.reconcile(&response_scope, pending_audio.is_empty() && audio_owner.is_none(), std::time::Instant::now())? {
            event_tx.try_send(ConversationEvent::Listening).map_err(|_| "a2_event_queue_closed")?;
        }
        let follow_up_deadline = follow_up.deadline(&response_scope);
        tokio::select! {
            biased;
            control = control_rx.recv() => match control {
                None | Some(A2Control::Shutdown) => break,
                Some(A2Control::BargeIn) => {
                    let _ = response_scope.invalidate();
                    if let Some(cancel) = active_cancel.take() {
                        // The visible worker sends VisibleSettled only after a
                        // real terminal/cancel_and_settle result.
                        awaiting_turn_settlement = active_visible_generation.take();
                        let _ = cancel.send(());
                    }
                    pending_confirmation = None;
                    pending_audio.clear();
                }
                Some(A2Control::ProviderDecision(request_id, decision)) => {
                    if !may_start_authorized_turn(&awaiting_turn_settlement) { return Err("provider_decision_before_previous_turn_settled"); }
                    let generation = response_scope.snapshot().map_err(|_| "response_generation_exhausted")?;
                    let Some((pending_generation, confirmation)) = pending_confirmation.take() else { return Err("provider_decision_without_pending_confirmation"); };
                    if response_scope.is_stale(&pending_generation) || !pending_generation.same_generation(&generation) || confirmation.prompt.request_id != request_id {
                        return Err("provider_decision_does_not_match_pending_confirmation");
                    }
                    match dependencies.supervisor.decide(confirmation, decision).await.map_err(|_| "authorized_provider_decision_failed")? {
                        AuthorizedTextTurnStart::Ready(turn) => {
                            output = LmOutputProcessor::new(dependencies.freedom.media.tts.max_chars_per_request)?;
                            let generation = response_scope.snapshot().map_err(|_| "response_generation_exhausted")?;
                            start_visible_stage(&registry, stage_tx.clone(), turn, response_scope.clone(), generation.clone(), dependencies.wal.clone(), &mut active_cancel).await?;
                            active_visible_generation = Some(generation);
                            outstanding_stages = outstanding_stages.saturating_add(1);
                        }
                        AuthorizedTextTurnStart::ConfirmationRequired(_) => return Err("provider_confirmation_reissued"),
                        AuthorizedTextTurnStart::Denied => {
                            event_tx.try_send(ConversationEvent::Listening).map_err(|_| "a2_event_queue_closed")?;
                        }
                    }
                }
            },
            _ = event_tx.closed() => break,
            // Drain already admitted frames at a timer tie. A late frame or
            // an empty queue ends the window; fresh noise cannot extend it.
            Some(capture_input) = next_a2_capture(&mut capture_rx, follow_up_deadline) => match capture_input {
                A2CaptureInput::FollowUpExpired => {
                    if pending_audio.is_empty() && audio_owner.is_none() && follow_up.expire(&response_scope, std::time::Instant::now()) {
                        follow_up_expired = true;
                        break;
                    }
                }
                A2CaptureInput::Event(event) => match event {
                LiveCaptureEvent::Frame(frame) => {
                    let utterances = dependencies.assembler.push_frame(&frame).map_err(|_| "silero_utterance_assembly_failed")?;
                    for utterance in utterances {
                    match utterance {
                        LiveUtteranceEvent::SpeechStarted => {
                            // A Silero speech start is one 32-ms VAD block. It
                            // is not enough to cancel an answer; only a later
                            // qualified utterance commit may barge in.
                            let _ = turns.begin_speech();
                            speech_has_qualified = false;
                        }
                        LiveUtteranceEvent::SpeechProgress { voiced_samples } => {
                            if qualifies_barge_in(speech_has_qualified, voiced_samples, barge_in_voiced_samples) {
                                speech_has_qualified = true;
                                let _ = response_scope.invalidate();
                                if let Some(cancel) = active_cancel.take() {
                                    awaiting_turn_settlement = active_visible_generation.take();
                                    let _ = cancel.send(());
                                }
                                pending_confirmation = None;
                                pending_audio.clear();
                            }
                        }
                        LiveUtteranceEvent::UtteranceReady { pcm, voiced_samples, .. } => {
                            turns.add_speech(Duration::from_millis((voiced_samples as u64).saturating_mul(1000) / 16_000));
                            turns.soft_end();
                            if let TurnDisposition::Commit { turn_id } = turns.ready(dependencies.min_fragment_ms) {
                                if !speech_has_qualified { let _ = response_scope.invalidate(); }
                                pending_audio.clear();
                                let generation = response_scope.snapshot().map_err(|_| "response_generation_exhausted")?;
                                let tx = stage_tx.clone(); let media = dependencies.media.clone(); let updater = dependencies.updater.clone();
                                let home = dependencies.home.clone(); let wal = dependencies.wal.clone(); let permit = dependencies.permit.clone(); let stage_scope = response_scope.clone();
                                registry.spawn_stage(async move {
                                    let result = transcribe_live_utterance_with_audio_permit(&pcm, 16_000, &media, &updater, &home, Some(&wal), &permit).await.map_err(|_| "configured_stt_failed");
                                    if stage_scope.is_stale(&generation) { return Ok(()); }
                                    tx.send(A2MailboxEvent::SttComplete { generation, transcript: result }).await.map_err(|_| "a2_stage_queue_closed")
                                }).await?;
                                outstanding_stages = outstanding_stages.saturating_add(1);
                                event_tx.try_send(ConversationEvent::TranscriptAccepted { turn_id }).map_err(|_| "a2_event_queue_closed")?;
                            }
                        }
                    }
                } },
                LiveCaptureEvent::Cancelled => break,
                LiveCaptureEvent::Error(_) => return Err("capture_terminal_error"),
                LiveCaptureEvent::Ready { .. } => {}
                },
            },
            Some(stage) = stage_rx.recv() => match stage {
                A2MailboxEvent::SttComplete { generation, transcript } => {
                    if response_scope.is_stale(&generation) { continue; }
                    let text = transcript?;
                    if !may_start_authorized_turn(&awaiting_turn_settlement) {
                        if pending_transcript.replace((generation, text)).is_some() {
                            return Err("multiple_transcripts_waiting_for_turn_settlement");
                        }
                        continue;
                    }
                    let input = preflight_for_transcript(&dependencies.preflight, text);
                    match dependencies.supervisor.start(input).await.map_err(|_| "authorized_provider_preflight_failed")? {
                        AuthorizedTextTurnStart::ConfirmationRequired(confirmation) => {
                            event_tx.try_send(ConversationEvent::ProviderConfirmationRequired(confirmation.prompt.clone())).map_err(|_| "a2_event_queue_closed")?;
                            pending_confirmation = Some((generation, confirmation));
                        },
                        AuthorizedTextTurnStart::Ready(turn) => {
                            output = LmOutputProcessor::new(dependencies.freedom.media.tts.max_chars_per_request)?;
                            start_visible_stage(&registry, stage_tx.clone(), turn, response_scope.clone(), generation.clone(), dependencies.wal.clone(), &mut active_cancel).await?;
                            active_visible_generation = Some(generation);
                            outstanding_stages = outstanding_stages.saturating_add(1);
                        }
                        AuthorizedTextTurnStart::Denied => {
                            event_tx.try_send(ConversationEvent::Listening).map_err(|_| "a2_event_queue_closed")?;
                        }
                    }
                }
                A2MailboxEvent::VisibleDelta { generation, text } => {
                    if response_scope.is_stale(&generation) { continue; }
                    output.push_visible_delta(&text)?;
                    while let Some(sentence_batch) = output.next_batch() {
                        if pending_audio.len() == 8 { return Err("a2_audio_lane_full"); }
                        pending_audio.push_back((generation.clone(), sentence_batch));
                        if let Some((generation, batch)) = take_next_audio_stage(
                            response_scope.clone(),
                            &mut pending_audio,
                            &mut audio_owner,
                        ) {
                            let inputs = TtsStageInputs::from(&dependencies);
                            spawn_tts_stage(
                                &registry,
                                stage_tx.clone(),
                                inputs,
                                batch,
                                generation.clone(),
                            )
                            .await?;
                            audio_owner = Some(generation);
                            outstanding_stages = outstanding_stages.saturating_add(1);
                        }
                    }
                }
                A2MailboxEvent::VisibleTerminal { generation } => { if response_scope.is_stale(&generation) { continue; } output.flush_terminal()?; while let Some(batch) = output.next_batch() {
                    if pending_audio.len() == 8 { return Err("a2_audio_lane_full"); }
                    pending_audio.push_back((generation.clone(), batch));
                    if let Some((generation, batch)) = take_next_audio_stage(
                        response_scope.clone(),
                        &mut pending_audio,
                        &mut audio_owner,
                    ) {
                        let inputs = TtsStageInputs::from(&dependencies);
                        spawn_tts_stage(
                            &registry,
                            stage_tx.clone(),
                            inputs,
                            batch,
                            generation.clone(),
                        )
                        .await?;
                        audio_owner = Some(generation);
                        outstanding_stages = outstanding_stages.saturating_add(1);
                    }
                } }
                A2MailboxEvent::TtsComplete { generation, pcm } => {
                    if !audio_owner.as_ref().is_some_and(|owner| owner.same_generation(&generation)) { continue; }
                    if response_scope.is_stale(&generation) {
                        release_audio_owner(&mut audio_owner, &generation);
                        if let Some((generation, batch)) = take_next_audio_stage(
                            response_scope.clone(),
                            &mut pending_audio,
                            &mut audio_owner,
                        ) {
                            let inputs = TtsStageInputs::from(&dependencies);
                            spawn_tts_stage(
                                &registry,
                                stage_tx.clone(),
                                inputs,
                                batch,
                                generation.clone(),
                            )
                            .await?;
                            audio_owner = Some(generation);
                            outstanding_stages = outstanding_stages.saturating_add(1);
                        }
                    } else {
                        spawn_playback_stage(&registry, stage_tx.clone(), dependencies.playback.clone(), response_scope.clone(), dependencies.permit.clone(), generation, pcm?).await?;
                        outstanding_stages = outstanding_stages.saturating_add(1);
                    }
                },
                A2MailboxEvent::PlaybackComplete { generation, result } => {
                    if !audio_owner.as_ref().is_some_and(|owner| owner.same_generation(&generation)) { continue; }
                    release_audio_owner(&mut audio_owner, &generation);
                    result?;
                    follow_up.observe_playback(&response_scope, &generation);
                    if let Some((generation, batch)) = take_next_audio_stage(
                        response_scope.clone(),
                        &mut pending_audio,
                        &mut audio_owner,
                    ) {
                        let inputs = TtsStageInputs::from(&dependencies);
                        spawn_tts_stage(
                            &registry,
                            stage_tx.clone(),
                            inputs,
                            batch,
                            generation.clone(),
                        )
                        .await?;
                        audio_owner = Some(generation);
                        outstanding_stages = outstanding_stages.saturating_add(1);
                    }
                },
                A2MailboxEvent::VisibleSettled { generation, terminal } => {
                    if active_visible_generation.as_ref().is_some_and(|active| active.same_generation(&generation)) {
                        active_visible_generation = None;
                    }
                    if awaiting_turn_settlement.as_ref().is_some_and(|waiting| waiting.same_generation(&generation)) {
                        awaiting_turn_settlement = None;
                        if let Some((pending_generation, text)) = pending_transcript.take() {
                            if !response_scope.is_stale(&pending_generation) {
                                let input = preflight_for_transcript(&dependencies.preflight, text);
                                match dependencies.supervisor.start(input).await.map_err(|_| "authorized_provider_preflight_failed")? {
                                    AuthorizedTextTurnStart::ConfirmationRequired(confirmation) => {
                                        event_tx.try_send(ConversationEvent::ProviderConfirmationRequired(confirmation.prompt.clone())).map_err(|_| "a2_event_queue_closed")?;
                                        pending_confirmation = Some((pending_generation, confirmation));
                                    }
                                    AuthorizedTextTurnStart::Ready(turn) => {
                                        output = LmOutputProcessor::new(dependencies.freedom.media.tts.max_chars_per_request)?;
                                        start_visible_stage(&registry, stage_tx.clone(), turn, response_scope.clone(), pending_generation.clone(), dependencies.wal.clone(), &mut active_cancel).await?;
                                        active_visible_generation = Some(pending_generation);
                                        outstanding_stages = outstanding_stages.saturating_add(1);
                                    }
                                    AuthorizedTextTurnStart::Denied => {
                                        event_tx.try_send(ConversationEvent::Listening).map_err(|_| "a2_event_queue_closed")?;
                                    }
                                }
                            }
                        }
                    }
                    follow_up.observe_settled(&response_scope, &generation, terminal);
                },
                A2MailboxEvent::Capture(_) => {}
            },
            stage = registry.settle_one_stage(), if outstanding_stages > 0 => {
                outstanding_stages = outstanding_stages.saturating_sub(1);
                stage?;
            },
            else => break,
        }
        // A UI decision is deliberately not inferred. The outer daemon keeps
        // the sealed confirmation and resumes with `supervisor.decide` only
        // after it receives the exact operator decision.
        let _ = &pending_confirmation;
    }
    Ok(())
    }.await;
    let _ = capture_scope.invalidate();
    let _ = response_scope.invalidate();
    if let Some(cancel) = active_cancel.take() {
        let _ = cancel.send(());
    }
    // Receivers are released before the retained workers are joined.  A relay
    // blocked on a bounded send now sees scope cancellation and exits; visible,
    // TTS and playback workers likewise settle their owned turn before joining.
    drop(capture_rx);
    drop(stage_rx);
    drop(stage_tx);
    // Continue every cleanup phase after a failure.  Dropping a live turn is
    // settled through the supervisor API, never by aborting its worker.
    let stages = registry.drain_stages().await;
    // A retained stage normally owns and settles its turn directly.  When an
    // error dropped that consumer, consume its actual supervisor completion;
    // the optional API distinguishes that case from an observed terminal.
    let dropped = dependencies
        .supervisor
        .wait_for_dropped_turn_if_pending()
        .await
        .map(|_| ())
        .map_err(|_| "authorized_dropped_turn_unsettled");
    let shutdown = dependencies
        .supervisor
        .shutdown_and_join()
        .await
        .map_err(|_| "authorized_turn_supervisor_unsettled");
    let cleanup = registry.drain_cleanup().await;
    let settled = loop_result
        .and(stages)
        .and(dropped)
        .and(shutdown)
        .and(cleanup);
    // All stage-held permit clones were joined above. Release this final
    // session dependency before projecting a successful automatic stop.
    drop(dependencies);
    if follow_up_expired || settled.is_err() {
        publish_follow_up_stop(&event_tx, settled, capture_terminal_rx.try_recv().ok()).await
    } else {
        settled
    }
}

#[cfg(feature = "live-audio")]
async fn start_visible_stage(
    registry: &crate::daemon::conversation_session::ConversationTaskRegistry,
    tx: tokio::sync::mpsc::Sender<A2MailboxEvent>,
    mut turn: AuthorizedTextTurn,
    response_scope: CancelScope,
    generation: GenerationToken,
    wal: WalWriterHandle,
    active_cancel: &mut Option<tokio::sync::oneshot::Sender<()>>,
) -> Result<(), &'static str> {
    let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel();
    *active_cancel = Some(cancel_tx);
    registry.spawn_stage(async move {
        let mut sink = StageVisibleSink { tx: tx.clone(), generation: generation.clone(), terminal: None };
        tokio::select! {
            attach = turn.attach_visible(&mut sink) => attach.map_err(|_| "authorized_visible_stream_failed")?,
            _ = &mut cancel_rx => {
                // The only cancellation settlement path; it invokes bridge.cancel,
                // attaches the same subscription and waits for the actual terminal.
                let settled = turn.cancel_and_settle().await.map_err(|_| "stale_authorized_turn_unsettled")?;
                let terminal = settled.terminal_kind();
                if settled.terminal_kind() == AuthorizedTextTurnTerminal::Cancelled {
                    let receipt = TurnCancelAdmission::from_settled_turn(settled, TurnCancelCause::Stale, now_unix()).map_err(|_| "turn_cancel_proof_rejected")?;
                    wal.append_realtime_turn_cancel(receipt).await.map_err(|_| "turn_cancel_result_not_durable")?;
                }
                sink.terminal = Some(terminal);
            }
        }
        let terminal = sink.terminal.ok_or("authorized_visible_stream_missing_terminal")?;
        if tx.send(A2MailboxEvent::VisibleTerminal { generation: generation.clone() }).await.is_err() {
            return if response_scope.is_stale(&generation) { Ok(()) } else { Err("a2_stage_queue_closed") };
        }
        if tx.send(A2MailboxEvent::VisibleSettled { generation: generation.clone(), terminal }).await.is_err() {
            return if response_scope.is_stale(&generation) { Ok(()) } else { Err("a2_stage_queue_closed") };
        }
        Ok(())
    }).await?;
    Ok(())
}

#[cfg(feature = "live-audio")]
struct StageVisibleSink {
    tx: tokio::sync::mpsc::Sender<A2MailboxEvent>,
    generation: GenerationToken,
    terminal: Option<AuthorizedTextTurnTerminal>,
}
#[cfg(feature = "live-audio")]
impl AuthorizedTextTurnSink for StageVisibleSink {
    fn visible_delta(&mut self, text: &str) -> Result<(), &'static str> {
        self.tx
            .try_send(A2MailboxEvent::VisibleDelta {
                generation: self.generation.clone(),
                text: text.to_owned(),
            })
            .map_err(|_| "a2_visible_queue_full")
    }
    fn terminal(&mut self, terminal: AuthorizedTextTurnTerminal) -> Result<(), &'static str> {
        self.terminal = Some(terminal);
        Ok(())
    }
}

#[cfg(feature = "live-audio")]
async fn spawn_tts_stage(
    registry: &crate::daemon::conversation_session::ConversationTaskRegistry,
    tx: tokio::sync::mpsc::Sender<A2MailboxEvent>,
    inputs: TtsStageInputs,
    text: String,
    generation: GenerationToken,
) -> Result<(), &'static str> {
    let TtsStageInputs {
        home,
        freedom,
        credentials,
        permit,
    } = inputs;
    let format = super::tts_cloud::configured_playback_request_format(
        freedom.media.tts.primary,
        freedom.media.tts.fallback,
    )
    .map_err(|_| "configured_tts_playback_format_unavailable")?;
    registry
        .spawn_stage(async move {
            let pcm = synthesize_configured_response(
                &home,
                &freedom,
                &credentials,
                text,
                format,
                TtsRunOverrides::default(),
            )
            .await
            .map_err(|_| "configured_tts_failed")
            .and_then(|response| {
                response
                    .into_verified_pcm_s16le(&permit)
                    .map_err(|_| "tts_pcm_not_verified")
            });
            tx.send(A2MailboxEvent::TtsComplete { generation, pcm })
                .await
                .map_err(|_| "a2_stage_queue_closed")
        })
        .await?;
    Ok(())
}

#[cfg(feature = "live-audio")]
fn take_next_audio_stage(
    response_scope: CancelScope,
    pending_audio: &mut VecDeque<(GenerationToken, String)>,
    audio_owner: &mut Option<GenerationToken>,
) -> Option<(GenerationToken, String)> {
    if audio_owner.is_some() {
        return None;
    }
    while let Some((generation, batch)) = pending_audio.pop_front() {
        if response_scope.is_stale(&generation) {
            continue;
        }
        return Some((generation, batch));
    }
    None
}

#[cfg(feature = "live-audio")]
fn may_start_authorized_turn(awaiting_turn_settlement: &Option<GenerationToken>) -> bool {
    awaiting_turn_settlement.is_none()
}

#[cfg(feature = "live-audio")]
fn release_audio_owner(audio_owner: &mut Option<GenerationToken>, generation: &GenerationToken) {
    if audio_owner
        .as_ref()
        .is_some_and(|owner| owner.same_generation(generation))
    {
        *audio_owner = None;
    }
}

#[cfg(feature = "live-audio")]
async fn spawn_playback_stage(
    registry: &crate::daemon::conversation_session::ConversationTaskRegistry,
    tx: tokio::sync::mpsc::Sender<A2MailboxEvent>,
    config: CpalPlaybackConfig,
    scope: CancelScope,
    permit: AudioWorkPermit,
    generation: GenerationToken,
    pcm: super::tts_cloud::VerifiedPcmS16leResponse,
) -> Result<(), &'static str> {
    registry
        .spawn_stage(async move {
            let result = tokio::task::spawn_blocking(move || {
                let mut playback = CpalPlaybackSession::start(config, scope, permit)
                    .map_err(|_| "playback_start_failed")?;
                let output =
                    wait_for_playback_ready(&mut playback).map_err(|_| "playback_not_ready")?;
                let source =
                    PcmS16leBlock::from_le_bytes(pcm.sample_rate_hz, pcm.channels, pcm.audio_bytes)
                        .map_err(|_| "tts_pcm_invalid")?;
                playback
                    .enqueue(
                        source
                            .resample_mono_to(output.sample_rate_hz)
                            .map_err(|_| "playback_resample_refused")?,
                    )
                    .map_err(|_| "playback_queue_failed")?;
                playback
                    .complete()
                    .map_err(|_| "playback_completion_failed")?;
                loop {
                    match playback
                        .next_event(Duration::from_millis(50))
                        .map_err(|_| "playback_terminal_failed")?
                    {
                        Some(PlaybackEvent::Completed) => return Ok(()),
                        Some(PlaybackEvent::Cancelled) => return Err("playback_cancelled"),
                        Some(PlaybackEvent::Error(_)) => return Err("playback_device_error"),
                        _ => {}
                    }
                }
            })
            .await
            .map_err(|_| "playback_owner_panicked")?;
            tx.send(A2MailboxEvent::PlaybackComplete { generation, result })
                .await
                .map_err(|_| "a2_stage_queue_closed")
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn follow_up_stop_projection_preserves_cleanup_and_delivery_failures() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        assert_eq!(publish_follow_up_stop(&tx, Ok(()), None).await, Ok(()));
        assert!(matches!(
            rx.try_recv(),
            Ok(ConversationEvent::FollowUpExpired)
        ));
        assert_eq!(
            publish_follow_up_stop(&tx, Err("fixture_cleanup_failed"), None).await,
            Err("fixture_cleanup_failed")
        );
        assert!(matches!(
            rx.try_recv(),
            Ok(ConversationEvent::Failed("fixture_cleanup_failed"))
        ));
        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
        drop(rx);
        assert_eq!(
            publish_follow_up_stop(&tx, Ok(()), None).await,
            Err("a2_event_queue_closed")
        );
        assert_eq!(
            publish_follow_up_stop(&tx, Err("fixture_cleanup_failed"), None).await,
            Err("fixture_cleanup_failed")
        );
    }

    #[tokio::test]
    async fn follow_up_stop_waits_for_terminal_queue_capacity() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        tx.send(ConversationEvent::Listening).await.unwrap();
        let publish = publish_follow_up_stop(&tx, Ok(()), None);
        tokio::pin!(publish);
        tokio::select! {
            biased;
            _ = &mut publish => panic!("terminal publication must wait for capacity"),
            _ = std::future::ready(()) => {}
        }
        assert!(matches!(
            rx.recv().await,
            Some(ConversationEvent::Listening)
        ));
        assert_eq!(publish.await, Ok(()));
        assert!(matches!(
            rx.recv().await,
            Some(ConversationEvent::FollowUpExpired)
        ));
    }

    fn admitted_frame(at: std::time::Instant) -> AdmittedCapture {
        AdmittedCapture {
            admitted_at: at,
            event: LiveCaptureEvent::Frame(super::super::live_capture::CapturedPcmFrame {
                sample_rate_hz: 16_000,
                captured_at: Duration::ZERO,
                pcm: vec![0.0; 512],
            }),
        }
    }

    #[tokio::test]
    async fn follow_up_capture_tie_drains_admitted_frames_before_expiry() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(32);
        let deadline = std::time::Instant::now();
        for _ in 0..32 {
            tx.try_send(admitted_frame(deadline)).unwrap();
        }
        // The deadline is already due, but all 32 facts were admitted at it.
        for _ in 0..32 {
            assert!(matches!(
                next_a2_capture(&mut rx, Some(deadline)).await,
                Some(A2CaptureInput::Event(LiveCaptureEvent::Frame(_)))
            ));
        }
        // No producer fact remains: timer expires without a wall-clock sleep.
        assert!(matches!(
            next_a2_capture(&mut rx, Some(deadline)).await,
            Some(A2CaptureInput::FollowUpExpired)
        ));
    }

    #[tokio::test]
    async fn follow_up_post_deadline_noise_cannot_extend_window() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(32);
        let deadline = std::time::Instant::now();
        for _ in 0..32 {
            tx.try_send(admitted_frame(deadline + Duration::from_nanos(1)))
                .unwrap();
        }
        assert!(matches!(
            next_a2_capture(&mut rx, Some(deadline)).await,
            Some(A2CaptureInput::FollowUpExpired)
        ));
        assert_eq!(rx.len(), 0);
    }

    #[tokio::test]
    async fn follow_up_capture_terminal_and_disabled_window_preserve_events() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        let deadline = std::time::Instant::now();
        tx.try_send(AdmittedCapture {
            admitted_at: deadline + Duration::from_nanos(1),
            event: LiveCaptureEvent::Cancelled,
        })
        .unwrap();
        assert!(matches!(
            next_a2_capture(&mut rx, Some(deadline)).await,
            Some(A2CaptureInput::Event(LiveCaptureEvent::Cancelled))
        ));
        tx.try_send(admitted_frame(deadline + Duration::from_secs(1)))
            .unwrap();
        assert!(matches!(
            next_a2_capture(&mut rx, None).await,
            Some(A2CaptureInput::Event(LiveCaptureEvent::Frame(_)))
        ));
        drop(tx);
        assert!(next_a2_capture(&mut rx, None).await.is_none());
    }

    #[tokio::test]
    async fn follow_up_queued_terminals_survive_late_noise_at_expiry() {
        use super::super::live_capture::LiveCaptureError;
        for terminal in [
            LiveCaptureEvent::Cancelled,
            LiveCaptureEvent::Error(LiveCaptureError::NoInputDevice),
        ] {
            let (tx, mut rx) = tokio::sync::mpsc::channel(32);
            let deadline = std::time::Instant::now();
            for _ in 0..31 {
                tx.try_send(admitted_frame(deadline + Duration::from_nanos(1)))
                    .unwrap();
            }
            tx.try_send(AdmittedCapture {
                admitted_at: deadline + Duration::from_nanos(1),
                event: terminal.clone(),
            })
            .unwrap();
            match next_a2_capture(&mut rx, Some(deadline)).await {
                Some(A2CaptureInput::Event(actual)) => assert_eq!(actual, terminal),
                _ => panic!("queued capture terminal must survive expired noise"),
            }
        }
    }

    #[tokio::test]
    async fn follow_up_cancelled_wait_retains_later_capture_input() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        {
            let waiting = next_a2_capture(&mut rx, None);
            tokio::pin!(waiting);
            tokio::select! {
                biased;
                _ = &mut waiting => panic!("empty channel unexpectedly completed"),
                _ = std::future::ready(()) => {}
            }
        }
        tx.try_send(admitted_frame(std::time::Instant::now()))
            .unwrap();
        assert!(matches!(
            next_a2_capture(&mut rx, None).await,
            Some(A2CaptureInput::Event(LiveCaptureEvent::Frame(_)))
        ));
        drop(rx);
        assert!(
            tx.send(admitted_frame(std::time::Instant::now()))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn follow_up_terminal_witness_survives_full_capture_queue_and_join() {
        for terminal in [CaptureTerminal::Cancelled, CaptureTerminal::Failed] {
            let (capture_tx, capture_rx) = tokio::sync::mpsc::channel(1);
            let (terminal_tx, mut terminal_rx) = tokio::sync::oneshot::channel();
            let deadline = std::time::Instant::now();
            capture_tx
                .try_send(admitted_frame(deadline + Duration::from_nanos(1)))
                .unwrap();
            let relay = tokio::task::spawn_blocking(move || {
                terminal_tx.send(terminal).unwrap();
                capture_tx.blocking_send(AdmittedCapture {
                    admitted_at: std::time::Instant::now(),
                    event: match terminal {
                        CaptureTerminal::Cancelled => LiveCaptureEvent::Cancelled,
                        CaptureTerminal::Failed => LiveCaptureEvent::Error(
                            super::super::live_capture::LiveCaptureError::NoInputDevice,
                        ),
                    },
                })
            });
            // The terminal witness is independent of the full PCM queue. Wait
            // for it, then perform the actual expiry cleanup's receiver drop.
            let witness = (&mut terminal_rx).await.unwrap();
            drop(capture_rx);
            assert!(relay.await.unwrap().is_err());
            let (event_tx, mut event_rx) = tokio::sync::mpsc::channel(1);
            let result = publish_follow_up_stop(&event_tx, Ok(()), Some(witness)).await;
            match terminal {
                CaptureTerminal::Cancelled => {
                    assert_eq!(result, Ok(()));
                    assert!(matches!(
                        event_rx.recv().await,
                        Some(ConversationEvent::Cancelled)
                    ));
                }
                CaptureTerminal::Failed => {
                    assert_eq!(result, Err("capture_terminal_error"));
                    assert!(matches!(
                        event_rx.recv().await,
                        Some(ConversationEvent::Failed("capture_terminal_error"))
                    ));
                }
            }
        }
    }

    #[tokio::test]
    async fn follow_up_terminal_observed_after_timer_before_join_overrides_expiry() {
        let (_capture_tx, mut capture_rx) = tokio::sync::mpsc::channel(1);
        let (terminal_tx, mut terminal_rx) = tokio::sync::oneshot::channel();
        let (continue_tx, continue_rx) = tokio::sync::oneshot::channel();
        let relay = tokio::spawn(async move {
            continue_rx.await.unwrap();
            terminal_tx.send(CaptureTerminal::Failed).unwrap();
        });
        assert!(matches!(
            next_a2_capture(&mut capture_rx, Some(std::time::Instant::now())).await,
            Some(A2CaptureInput::FollowUpExpired)
        ));
        assert!(matches!(
            terminal_rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        continue_tx.send(()).unwrap();
        relay.await.unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        assert_eq!(
            publish_follow_up_stop(&tx, Ok(()), terminal_rx.try_recv().ok()).await,
            Err("capture_terminal_error")
        );
        assert!(matches!(
            rx.recv().await,
            Some(ConversationEvent::Failed("capture_terminal_error"))
        ));
    }

    #[test]
    fn follow_up_waits_for_complete_turn_and_final_audio_in_both_orders() {
        for playback_first in [false, true] {
            let scope = CancelScope::new();
            let generation = scope.snapshot().unwrap();
            let now = std::time::Instant::now();
            let delay = Duration::from_secs(7);
            let mut window = FollowUpWindow::new(Some(delay));
            if playback_first {
                window.observe_playback(&scope, &generation);
            } else {
                window.observe_settled(&scope, &generation, AuthorizedTextTurnTerminal::Complete);
            }
            assert!(!window.reconcile(&scope, true, now).unwrap());
            if playback_first {
                window.observe_settled(&scope, &generation, AuthorizedTextTurnTerminal::Complete);
            } else {
                window.observe_playback(&scope, &generation);
            }
            // Another queued or in-flight sentence still owns the audio lane.
            assert!(!window.reconcile(&scope, false, now).unwrap());
            assert_eq!(window.deadline(&scope), None);
            assert!(window.reconcile(&scope, true, now).unwrap());
            assert_eq!(window.deadline(&scope), Some(now + delay));
            assert!(!window.expire(&scope, now + delay - Duration::from_nanos(1)));
            assert!(window.expire(&scope, now + delay));
            assert!(!window.expire(&scope, now + delay));
        }
    }

    #[test]
    fn follow_up_never_arms_after_failed_turn_without_audio_or_when_disabled() {
        let scope = CancelScope::new();
        let generation = scope.snapshot().unwrap();
        let now = std::time::Instant::now();
        for terminal in [
            AuthorizedTextTurnTerminal::Cancelled,
            AuthorizedTextTurnTerminal::Failed,
            AuthorizedTextTurnTerminal::CrashUnknown,
            AuthorizedTextTurnTerminal::Indeterminate,
        ] {
            let mut window = FollowUpWindow::new(Some(Duration::from_secs(7)));
            window.observe_playback(&scope, &generation);
            window.observe_settled(&scope, &generation, terminal);
            assert!(!window.reconcile(&scope, true, now).unwrap());
        }
        let mut empty = FollowUpWindow::new(Some(Duration::from_secs(7)));
        empty.observe_settled(&scope, &generation, AuthorizedTextTurnTerminal::Complete);
        assert!(!empty.reconcile(&scope, true, now).unwrap());
        let mut disabled = FollowUpWindow::new(None);
        disabled.observe_settled(&scope, &generation, AuthorizedTextTurnTerminal::Complete);
        disabled.observe_playback(&scope, &generation);
        assert!(!disabled.reconcile(&scope, true, now).unwrap());
    }

    #[test]
    fn follow_up_stale_or_foreign_callbacks_cannot_close_a_later_generation() {
        let scope = CancelScope::new();
        let old = scope.snapshot().unwrap();
        let now = std::time::Instant::now();
        let delay = Duration::from_secs(7);
        let mut window = FollowUpWindow::new(Some(delay));
        window.observe_settled(&scope, &old, AuthorizedTextTurnTerminal::Complete);
        window.observe_playback(&scope, &old);
        assert!(window.reconcile(&scope, true, now).unwrap());
        scope.invalidate().unwrap();
        assert!(!window.expire(&scope, now + delay));
        assert!(!window.reconcile(&scope, true, now).unwrap());
        let new = scope.snapshot().unwrap();
        let foreign = CancelScope::new().snapshot().unwrap();
        window.observe_settled(&scope, &old, AuthorizedTextTurnTerminal::Complete);
        window.observe_playback(&scope, &foreign);
        assert!(!window.reconcile(&scope, true, now).unwrap());
        window.observe_settled(&scope, &new, AuthorizedTextTurnTerminal::Complete);
        window.observe_playback(&scope, &new);
        assert!(
            window
                .reconcile(&scope, true, now + Duration::from_secs(1))
                .unwrap()
        );
        window.observe_settled(&scope, &old, AuthorizedTextTurnTerminal::Failed);
        assert!(!window.expire(&scope, now + delay));
        assert!(window.expire(&scope, now + delay + Duration::from_secs(1)));
    }

    #[test]
    fn follow_up_short_noise_and_repeated_idle_facts_do_not_extend_deadline() {
        let scope = CancelScope::new();
        let generation = scope.snapshot().unwrap();
        let now = std::time::Instant::now();
        let delay = Duration::from_secs(7);
        let mut window = FollowUpWindow::new(Some(delay));
        window.observe_settled(&scope, &generation, AuthorizedTextTurnTerminal::Complete);
        window.observe_playback(&scope, &generation);
        assert!(window.reconcile(&scope, true, now).unwrap());
        assert!(!qualifies_barge_in(
            false,
            512,
            voiced_samples_for_fragment_ms(100).unwrap()
        ));
        for seconds in 1..7 {
            window.observe_settled(&scope, &generation, AuthorizedTextTurnTerminal::Complete);
            window.observe_playback(&scope, &generation);
            assert!(
                !window
                    .reconcile(&scope, true, now + Duration::from_secs(seconds))
                    .unwrap()
            );
            assert_eq!(window.deadline(&scope), Some(now + delay));
        }
        assert!(window.expire(&scope, now + delay));
    }

    #[test]
    fn follow_up_qualified_speech_invalidates_window_but_not_capture_scope() {
        let capture = CancelScope::new();
        let capture_token = capture.snapshot().unwrap();
        let response = CancelScope::new();
        let generation = response.snapshot().unwrap();
        let now = std::time::Instant::now();
        let mut window = FollowUpWindow::new(Some(Duration::from_secs(7)));
        window.observe_settled(&response, &generation, AuthorizedTextTurnTerminal::Complete);
        window.observe_playback(&response, &generation);
        assert!(window.reconcile(&response, true, now).unwrap());
        assert!(qualifies_barge_in(
            false,
            2_048,
            voiced_samples_for_fragment_ms(100).unwrap()
        ));
        response.invalidate().unwrap();
        assert!(!window.expire(&response, now + Duration::from_secs(7)));
        assert!(!window.reconcile(&response, true, now).unwrap());
        assert!(!capture.is_stale(&capture_token));
    }

    #[test]
    fn follow_up_later_audio_cannot_expire_an_earlier_idle_window() {
        let scope = CancelScope::new();
        let generation = scope.snapshot().unwrap();
        let now = std::time::Instant::now();
        let mut window = FollowUpWindow::new(Some(Duration::from_secs(7)));
        window.observe_settled(&scope, &generation, AuthorizedTextTurnTerminal::Complete);
        window.observe_playback(&scope, &generation);
        assert!(window.reconcile(&scope, true, now).unwrap());
        assert!(
            !window
                .reconcile(&scope, false, now + Duration::from_secs(1))
                .unwrap()
        );
        assert!(!window.expire(&scope, now + Duration::from_secs(8)));
        window.observe_playback(&scope, &generation);
        assert!(
            window
                .reconcile(&scope, true, now + Duration::from_secs(9))
                .unwrap()
        );
        assert_eq!(window.deadline(&scope), Some(now + Duration::from_secs(16)));
    }

    #[tokio::test]
    async fn cancelled_opening_fake_stage_is_detected_before_native_effect() {
        let scope = CancelScope::new();
        let token = scope.snapshot().expect("fresh opening token");
        tokio::task::yield_now().await;
        scope.invalidate().expect("ordinary opening cancellation");
        assert!(opening_cancelled(&scope, &token));
    }
    #[test]
    fn response_scope_barge_in_is_independent_from_capture_scope() {
        let capture = CancelScope::new();
        let response = CancelScope::new();
        let capture_token = capture.snapshot().unwrap();
        let old_response = response.snapshot().unwrap();
        response.invalidate().unwrap();
        assert!(!capture.is_stale(&capture_token));
        assert!(response.is_stale(&old_response));
    }

    #[test]
    fn qualified_turn_is_once_and_zero_length_fragment_is_cancelled() {
        let mut turns = TurnTracker::default();
        turns.begin_speech();
        assert_eq!(turns.ready(100), TurnDisposition::CancelShortFragment);
        turns.begin_speech();
        turns.add_speech(Duration::from_millis(100));
        assert!(matches!(turns.ready(100), TurnDisposition::Commit { .. }));
        assert!(matches!(
            turns.ready(100),
            TurnDisposition::AlreadyCommitted { .. }
        ));
    }

    #[test]
    fn one_vad_block_never_invalidates_an_active_response() {
        let response = CancelScope::new();
        let active = response.snapshot().unwrap();
        let mut turns = TurnTracker::default();
        // `SpeechStarted` starts bookkeeping only; 32 ms is below the 100-ms
        // admission threshold and must leave the active response current.
        turns.begin_speech();
        turns.add_speech(Duration::from_millis(32));
        assert_eq!(turns.ready(100), TurnDisposition::CancelShortFragment);
        assert!(!response.is_stale(&active));
    }

    #[test]
    fn pending_turn_cannot_start_before_the_old_generation_has_settled() {
        let scope = CancelScope::new();
        let old = scope.snapshot().unwrap();
        let mut waiting = Some(old);
        assert!(!may_start_authorized_turn(&waiting));
        waiting = None; // only the generation-tagged VisibleSettled transition does this in the loop
        assert!(may_start_authorized_turn(&waiting));
    }

    #[test]
    fn stale_audio_completion_cannot_release_a_different_generation_owner() {
        let scope = CancelScope::new();
        let old = scope.snapshot().unwrap();
        scope.invalidate().unwrap();
        let new = scope.snapshot().unwrap();
        let mut owner = Some(old.clone());
        release_audio_owner(&mut owner, &new);
        assert!(
            owner
                .as_ref()
                .is_some_and(|current| current.same_generation(&old))
        );
        release_audio_owner(&mut owner, &old);
        assert!(owner.is_none());
    }

    #[test]
    fn four_ordered_vad_blocks_qualify_once_without_a_later_reset() {
        let threshold = voiced_samples_for_fragment_ms(100).unwrap();
        let mut qualified = false;
        for voiced_samples in [512usize, 1_024, 1_536, 2_048] {
            if qualifies_barge_in(qualified, voiced_samples, threshold) {
                qualified = true;
            }
        }
        assert!(qualified);
        assert!(!qualifies_barge_in(qualified, 2_560, threshold));
    }

    #[test]
    fn configured_250ms_does_not_qualify_at_128ms_and_noise_never_qualifies() {
        let threshold = voiced_samples_for_fragment_ms(250).unwrap();
        assert!(!qualifies_barge_in(false, 2_048, threshold));
        assert!(!qualifies_barge_in(false, 0, threshold));
    }

    #[test]
    fn transcript_preflight_gets_a_fresh_correlation_id_but_keeps_bound_route() {
        let template = GuiChatBridgePreflightInput {
            request_id: GuiChatRequestId::new(),
            session_id: "bound-session".into(),
            origin_surface: crate::daemon::gui_chat_bridge::GuiChatSurface::Main,
            message: "old".into(),
            model: Some("bound-model".into()),
            skill_id: Some("bound-skill".into()),
            incognito: true,
            reasoning_display: true,
            attachment_paths: vec![PathBuf::from("bound-path")],
        };
        let first = preflight_for_transcript(&template, "first".into());
        let second = preflight_for_transcript(&template, "second".into());
        assert_ne!(template.request_id, first.request_id);
        assert_ne!(first.request_id, second.request_id);
        assert_eq!(first.session_id, template.session_id);
        assert_eq!(first.origin_surface, template.origin_surface);
        assert_eq!(first.model, template.model);
        assert_eq!(first.skill_id, template.skill_id);
        assert_eq!(first.attachment_paths, template.attachment_paths);
    }
}
