//! Bounded native microphone capture for the W186 live-dictation path.
//!
//! This module deliberately stops at capture. It neither runs VAD/STT nor
//! publishes product-facing text. A later utterance owner consumes `Frame`
//! events while retaining the same [`AudioWorkPermit`] for its complete
//! request-controlled lifetime.
//!
//! `cpal::Stream` is kept on its dedicated owner thread. In particular, this
//! module does not rely on `Stream: Send`, which is not a portable CPAL
//! contract. The platform callback does only bounded PCM conversion and a
//! non-blocking queue offer. A second bounded, non-blocking owner-to-session
//! queue prevents a slow utterance consumer from retaining unbounded PCM. One
//! separate terminal slot preserves a cancellation/error even while either PCM
//! queue is full.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};

use crate::media::audio::AudioWorkPermit;
use crate::media::conversation_scope::{CancelScope, GenerationToken};
use crate::media::resampler::{MAX_SAMPLE_RATE_HZ, MIN_SAMPLE_RATE_HZ};

/// Maximum live PCM frames retained by one callback block.
pub(crate) const MAX_CAPTURE_CALLBACK_FRAMES: usize = 4_096;
/// Maximum blocks waiting between CPAL's real-time callback and the consumer.
pub(crate) const MAX_CAPTURE_QUEUE_BLOCKS: usize = 32;
/// The capture component never accepts an implausibly wide device input.
pub(crate) const MAX_CAPTURE_CHANNELS: u16 = 16;

/// Input bounds chosen by the live-session owner before opening a device.
#[derive(Clone, Debug)]
pub(crate) struct CpalCaptureConfig {
    /// Optional exact CPAL device name. `None` selects the platform default.
    pub requested_device_name: Option<String>,
    /// Upper limit for one device callback after conversion to mono frames.
    pub max_callback_frames: usize,
    /// Number of callback blocks that can wait without blocking the callback.
    pub queue_blocks: usize,
}

impl Default for CpalCaptureConfig {
    fn default() -> Self {
        Self {
            requested_device_name: None,
            max_callback_frames: MAX_CAPTURE_CALLBACK_FRAMES,
            queue_blocks: 8,
        }
    }
}

impl CpalCaptureConfig {
    fn validate(&self) -> Result<(), LiveCaptureError> {
        if self.max_callback_frames == 0 || self.max_callback_frames > MAX_CAPTURE_CALLBACK_FRAMES {
            return Err(LiveCaptureError::InvalidConfig {
                field: "max_callback_frames",
                detail: "must be within 1..=4096",
            });
        }
        if self.queue_blocks == 0 || self.queue_blocks > MAX_CAPTURE_QUEUE_BLOCKS {
            return Err(LiveCaptureError::InvalidConfig {
                field: "queue_blocks",
                detail: "must be within 1..=32",
            });
        }
        Ok(())
    }
}

/// A normalized bounded PCM block. `pcm` is mono IEEE-f32 at the device rate.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CapturedPcmFrame {
    pub sample_rate_hz: u32,
    /// Monotonic elapsed time measured at the native callback boundary.
    pub captured_at: Duration,
    pub pcm: Vec<f32>,
}

/// Events visible to the later VAD/utterance owner.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum LiveCaptureEvent {
    Ready {
        sample_rate_hz: u32,
        channels: u16,
    },
    Frame(CapturedPcmFrame),
    Error(LiveCaptureError),
    Cancelled,
}

impl LiveCaptureEvent {
    fn terminal(&self) -> bool {
        matches!(self, Self::Error(_) | Self::Cancelled)
    }
}

/// Stable, content-free failure classes for capture-state reporting.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum LiveCaptureError {
    #[error("invalid live capture configuration: {field} {detail}")]
    InvalidConfig { field: &'static str, detail: &'static str },
    #[error("no input device is available")]
    NoInputDevice,
    #[error("requested input device is unavailable")]
    RequestedDeviceUnavailable,
    #[error("input device enumeration failed: {0}")]
    DeviceEnumeration(String),
    #[error("input device name lookup failed: {0}")]
    DeviceName(String),
    #[error("input configuration query failed: {0}")]
    DefaultConfig(String),
    #[error("unsupported input sample format: {0}")]
    UnsupportedSampleFormat(String),
    #[error("invalid input sample rate {0} Hz")]
    InvalidSampleRate(u32),
    #[error("invalid input channel count {0}")]
    InvalidChannelCount(u16),
    #[error("input stream setup failed: {0}")]
    StreamBuild(String),
    #[error("input stream start failed: {0}")]
    StreamPlay(String),
    #[error("input device was lost or its stream failed: {0}")]
    DeviceLost(String),
    #[error("input callback delivered malformed interleaved PCM")]
    MalformedCallback,
    #[error("input callback delivered {frames} frames, above the {limit}-frame limit")]
    CallbackBlockTooLarge { frames: usize, limit: usize },
    #[error("input callback supplied a non-finite f32 sample")]
    NonFiniteSample,
    #[error("bounded capture queue overflowed")]
    QueueOverflow,
    #[error("capture owner thread terminated unexpectedly")]
    OwnerThreadTerminated,
}

/// Owns one live native capture session and the shared audio-work admission.
///
/// `start` accepts an already acquired permit. Acquiring it before calling
/// `start` is intentional: device setup, callback buffers, queue buffers, and
/// every later utterance buffer share the existing global audio budget.
pub(crate) struct CpalCaptureSession {
    events: Receiver<LiveCaptureEvent>,
    terminal_events: Receiver<LiveCaptureEvent>,
    stop: SyncSender<()>,
    owner: Option<JoinHandle<()>>,
    scope: CancelScope,
    token: GenerationToken,
    terminal_seen: bool,
    _audio_permit: AudioWorkPermit,
}

impl CpalCaptureSession {
    pub(crate) fn start(
        config: CpalCaptureConfig,
        scope: CancelScope,
        audio_permit: AudioWorkPermit,
    ) -> Result<Self, LiveCaptureError> {
        config.validate()?;
        let token = scope.snapshot().map_err(|_| LiveCaptureError::OwnerThreadTerminated)?;
        // The callback-to-owner and owner-to-session queues have the same
        // bounded block count. Terminal states use an independent one-slot
        // channel so a full PCM queue cannot hide a device loss or cancel.
        let (event_tx, events) = mpsc::sync_channel(config.queue_blocks);
        let (terminal_tx, terminal_events) = mpsc::sync_channel(1);
        let (stop, stop_rx) = mpsc::sync_channel(1);
        let owner_scope = scope.clone();
        let owner_token = token.clone();
        let owner = thread::Builder::new()
            .name("neoth-live-capture".into())
            .spawn(move || {
                run_capture_owner(
                    config,
                    owner_scope,
                    owner_token,
                    event_tx,
                    terminal_tx,
                    stop_rx,
                );
            })
            .map_err(|_| LiveCaptureError::OwnerThreadTerminated)?;

        Ok(Self {
            events,
            terminal_events,
            stop,
            owner: Some(owner),
            scope,
            token,
            terminal_seen: false,
            _audio_permit: audio_permit,
        })
    }

    /// Poll the next capture event without imposing an async runtime on CPAL.
    ///
    /// `None` means the bounded wait expired. Once a terminal event has been
    /// returned, no later event is exposed even if a platform callback races it.
    pub(crate) fn next_event(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<LiveCaptureEvent>, LiveCaptureError> {
        if self.terminal_seen {
            return Ok(None);
        }
        if let Ok(event) = self.terminal_events.try_recv() {
            self.terminal_seen = true;
            return Ok(Some(event));
        }
        let received = self.events.recv_timeout(timeout);
        self.resolve_event_wait(received)
    }

    fn resolve_event_wait(
        &mut self,
        received: Result<LiveCaptureEvent, RecvTimeoutError>,
    ) -> Result<Option<LiveCaptureEvent>, LiveCaptureError> {
        if self.terminal_seen {
            return Ok(None);
        }
        // The owner publishes its terminal before dropping the PCM sender.
        // Recheck after every wait result, including disconnect and timeout,
        // so that a device error cannot become a generic owner-exit error.
        if let Ok(terminal) = self.terminal_events.try_recv() {
            self.terminal_seen = true;
            return Ok(Some(terminal));
        }
        match received {
            Ok(event) => {
                if self.scope.is_stale(&self.token) && !event.terminal() {
                    self.terminal_seen = true;
                    return Ok(Some(LiveCaptureEvent::Cancelled));
                }
                if event.terminal() {
                    self.terminal_seen = true;
                }
                Ok(Some(event))
            }
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => {
                self.terminal_seen = true;
                Ok(Some(LiveCaptureEvent::Error(
                    LiveCaptureError::OwnerThreadTerminated,
                )))
            }
        }
    }

    /// Stop CPAL on its owning thread and join it without advancing the scope.
    pub(crate) fn cancel_and_join(&mut self) {
        // The CancelScope belongs to the caller and may already have advanced
        // to a newer operation. This session-specific stop must never
        // invalidate that newer generation; callers that mean to cancel the
        // conversation invalidate their scope separately before this call.
        let _ = self.stop.try_send(());
        if let Some(owner) = self.owner.take() {
            let _ = owner.join();
        }
        // Keep the terminal slot observable: a CLI/GUI owner may still poll
        // the resulting `Cancelled` event after its shutdown join.
    }

    /// Join a naturally completed capture session without invalidating a scope
    /// owned by the caller.
    pub(crate) fn join(&mut self) {
        if let Some(owner) = self.owner.take() {
            let _ = owner.join();
        }
    }
}

impl Drop for CpalCaptureSession {
    fn drop(&mut self) {
        // Receiving an already terminal device/format error must not cancel a
        // newer operation sharing this conversation scope merely because the
        // caller drops its completed capture handle.
        if self.terminal_seen {
            self.join();
        } else {
            self.cancel_and_join();
        }
    }
}

enum CallbackSignal {
    Frame(CapturedPcmFrame),
}

fn run_capture_owner(
    config: CpalCaptureConfig,
    scope: CancelScope,
    token: GenerationToken,
    events: SyncSender<LiveCaptureEvent>,
    terminal_events: SyncSender<LiveCaptureEvent>,
    stop: Receiver<()>,
) {
    if scope.is_stale(&token) {
        let _ = terminal_events.try_send(LiveCaptureEvent::Cancelled);
        return;
    }

    let host = cpal::default_host();
    let device = match choose_input_device(&host, config.requested_device_name.as_deref()) {
        Ok(device) => device,
        Err(error) => {
            let _ = terminal_events.try_send(LiveCaptureEvent::Error(error));
            return;
        }
    };
    let supported = match device.default_input_config() {
        Ok(config) => config,
        Err(error) => {
            let _ = terminal_events.try_send(LiveCaptureEvent::Error(LiveCaptureError::DefaultConfig(error.to_string())));
            return;
        }
    };
    let stream_config = supported.config();
    if let Err(error) = validate_device_config(stream_config.sample_rate.0, stream_config.channels) {
        let _ = terminal_events.try_send(LiveCaptureEvent::Error(error));
        return;
    }

    let (callback_tx, callback_rx) = mpsc::sync_channel(config.queue_blocks);
    let terminal = Arc::new(AtomicBool::new(false));
    let started_at = Instant::now();
    let stream = match supported.sample_format() {
        cpal::SampleFormat::F32 => build_stream::<f32>(
            &device, &stream_config, callback_tx, terminal_events.clone(), terminal.clone(), scope.clone(), token.clone(),
            stream_config.sample_rate.0, config.max_callback_frames, started_at, |sample| sample,
        ),
        cpal::SampleFormat::I16 => build_stream::<i16>(
            &device, &stream_config, callback_tx, terminal_events.clone(), terminal.clone(), scope.clone(), token.clone(),
            stream_config.sample_rate.0, config.max_callback_frames, started_at, |sample| sample as f32 / 32_768.0,
        ),
        cpal::SampleFormat::U16 => build_stream::<u16>(
            &device, &stream_config, callback_tx, terminal_events.clone(), terminal.clone(), scope.clone(), token.clone(),
            stream_config.sample_rate.0, config.max_callback_frames, started_at, |sample| (sample as f32 / u16::MAX as f32) * 2.0 - 1.0,
        ),
        format => Err(LiveCaptureError::UnsupportedSampleFormat(format!("{format:?}"))),
    };
    let stream = match stream {
        Ok(stream) => stream,
        Err(error) => {
            let _ = terminal_events.try_send(LiveCaptureEvent::Error(error));
            return;
        }
    };
    if let Err(error) = stream.play() {
        let _ = terminal_events.try_send(LiveCaptureEvent::Error(LiveCaptureError::StreamPlay(error.to_string())));
        return;
    }
    if events.try_send(LiveCaptureEvent::Ready {
        sample_rate_hz: stream_config.sample_rate.0,
        channels: stream_config.channels,
    }).is_err() {
        raise_terminal(&terminal_events, &terminal, LiveCaptureEvent::Error(LiveCaptureError::QueueOverflow));
        return;
    }

    loop {
        if scope.is_stale(&token) {
            raise_terminal(&terminal_events, &terminal, LiveCaptureEvent::Cancelled);
            break;
        }
        if stop.try_recv().is_ok() {
            raise_terminal(&terminal_events, &terminal, LiveCaptureEvent::Cancelled);
            break;
        }
        match callback_rx.recv_timeout(Duration::from_millis(20)) {
            Ok(CallbackSignal::Frame(frame)) => {
                if terminal.load(Ordering::Acquire) {
                    break;
                }
                if scope.is_stale(&token) {
                    raise_terminal(&terminal_events, &terminal, LiveCaptureEvent::Cancelled);
                    break;
                }
                if events.try_send(LiveCaptureEvent::Frame(frame)).is_err() {
                    raise_terminal(&terminal_events, &terminal, LiveCaptureEvent::Error(LiveCaptureError::QueueOverflow));
                    break;
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if terminal.load(Ordering::Acquire) {
            break;
        }
    }
    drop(stream);
}

fn choose_input_device(
    host: &cpal::Host,
    requested_name: Option<&str>,
) -> Result<cpal::Device, LiveCaptureError> {
    match requested_name {
        None => host.default_input_device().ok_or(LiveCaptureError::NoInputDevice),
        Some(requested_name) => host
            .input_devices()
            .map_err(|error| LiveCaptureError::DeviceEnumeration(error.to_string()))?
            .find_map(|device| match device.description() {
                Ok(description) if description.name() == requested_name => Some(Ok(device)),
                Ok(_) => None,
                Err(error) => Some(Err(LiveCaptureError::DeviceName(error.to_string()))),
            })
            .transpose()?
            .ok_or(LiveCaptureError::RequestedDeviceUnavailable),
    }
}

fn validate_device_config(sample_rate_hz: u32, channels: u16) -> Result<(), LiveCaptureError> {
    if !(MIN_SAMPLE_RATE_HZ..=MAX_SAMPLE_RATE_HZ).contains(&sample_rate_hz) {
        return Err(LiveCaptureError::InvalidSampleRate(sample_rate_hz));
    }
    if channels == 0 || channels > MAX_CAPTURE_CHANNELS {
        return Err(LiveCaptureError::InvalidChannelCount(channels));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_stream<T>(
    device: &cpal::Device,
    config: &cpal::StreamConfig,
    callback_tx: SyncSender<CallbackSignal>,
    terminal_events: SyncSender<LiveCaptureEvent>,
    terminal: Arc<AtomicBool>,
    scope: CancelScope,
    token: GenerationToken,
    sample_rate_hz: u32,
    max_frames: usize,
    started_at: Instant,
    convert: fn(T) -> f32,
) -> Result<cpal::Stream, LiveCaptureError>
where
    T: cpal::SizedSample + Send + 'static,
{
    let channels = config.channels as usize;
    let data_terminal_events = terminal_events.clone();
    let data_terminal = terminal.clone();
    device
        .build_input_stream(
            config,
            move |input: &[T], _| {
                if data_terminal.load(Ordering::Acquire) || scope.is_stale(&token) {
                    return;
                }
                let frame = match normalize_callback(input, channels, sample_rate_hz, max_frames, started_at.elapsed(), convert) {
                    Ok(frame) => frame,
                    Err(error) => {
                        raise_terminal(&data_terminal_events, &data_terminal, LiveCaptureEvent::Error(error));
                        return;
                    }
                };
                match callback_tx.try_send(CallbackSignal::Frame(frame)) {
                    Ok(()) | Err(TrySendError::Disconnected(_)) => {}
                    Err(TrySendError::Full(_)) => {
                        raise_terminal(&data_terminal_events, &data_terminal, LiveCaptureEvent::Error(LiveCaptureError::QueueOverflow));
                    }
                }
            },
            move |error| {
                raise_terminal(
                    &terminal_events,
                    &terminal,
                    LiveCaptureEvent::Error(LiveCaptureError::DeviceLost(error.to_string())),
                );
            },
            None,
        )
        .map_err(|error| LiveCaptureError::StreamBuild(error.to_string()))
}

fn normalize_callback<T>(
    input: &[T],
    channels: usize,
    sample_rate_hz: u32,
    max_frames: usize,
    captured_at: Duration,
    convert: fn(T) -> f32,
) -> Result<CapturedPcmFrame, LiveCaptureError>
where
    T: Copy,
{
    if channels == 0 || input.len() % channels != 0 {
        return Err(LiveCaptureError::MalformedCallback);
    }
    let frames = input.len() / channels;
    if frames > max_frames {
        return Err(LiveCaptureError::CallbackBlockTooLarge {
            frames,
            limit: max_frames,
        });
    }
    let mut pcm = Vec::with_capacity(frames);
    for frame in input.chunks_exact(channels) {
        let mut sum = 0.0_f32;
        for sample in frame {
            let normalized = convert(*sample);
            if !normalized.is_finite() {
                return Err(LiveCaptureError::NonFiniteSample);
            }
            sum += normalized;
        }
        let mono = sum / channels as f32;
        if !mono.is_finite() {
            return Err(LiveCaptureError::NonFiniteSample);
        }
        pcm.push(mono.clamp(-1.0, 1.0));
    }
    Ok(CapturedPcmFrame {
        sample_rate_hz,
        captured_at,
        pcm,
    })
}

fn raise_terminal(
    events: &SyncSender<LiveCaptureEvent>,
    terminal: &AtomicBool,
    event: LiveCaptureEvent,
) {
    if terminal
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        let _ = events.try_send(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn terminal_published_during_pcm_wait_survives_every_wait_result() {
        let audio_permit = crate::media::audio::acquire_audio_work_permit()
            .await
            .expect("audio admission");
        for received in [
            Err(RecvTimeoutError::Disconnected),
            Err(RecvTimeoutError::Timeout),
            Ok(LiveCaptureEvent::Ready {
                sample_rate_hz: 16_000,
                channels: 1,
            }),
        ] {
            let (_event_tx, events) = mpsc::sync_channel(1);
            let (terminal_tx, terminal_events) = mpsc::sync_channel(1);
            let (stop, _stop_rx) = mpsc::sync_channel(1);
            let scope = CancelScope::new();
            let token = scope.snapshot().expect("capture generation");
            let mut session = CpalCaptureSession {
                events,
                terminal_events,
                stop,
                owner: None,
                scope,
                token,
                terminal_seen: false,
                _audio_permit: audio_permit.clone(),
            };
            assert!(session.terminal_events.try_recv().is_err());
            // Reproduce publication between the initial terminal poll and
            // resolution of the PCM wait without a scheduler timing guess.
            let failure = LiveCaptureEvent::Error(LiveCaptureError::DeviceLost(
                "synthetic device loss".into(),
            ));
            terminal_tx.try_send(failure.clone()).expect("terminal slot");
            assert_eq!(session.resolve_event_wait(received).unwrap(), Some(failure));
            assert_eq!(session.next_event(Duration::ZERO).unwrap(), None);
        }
    }

    #[test]
    fn synthetic_f32_callback_downmixes_and_keeps_monotonic_timestamp() {
        let frame = normalize_callback(&[0.5_f32, -0.5, 1.0, 1.0], 2, 48_000, 8, Duration::from_millis(7), |v| v)
            .expect("bounded synthetic stereo frame");
        assert_eq!(frame.pcm, vec![0.0, 1.0]);
        assert_eq!(frame.sample_rate_hz, 48_000);
        assert_eq!(frame.captured_at, Duration::from_millis(7));
    }

    #[test]
    fn synthetic_callback_rejects_oversized_and_non_finite_input() {
        assert!(matches!(
            normalize_callback(&[0_i16; 3], 1, 16_000, 2, Duration::ZERO, |v| v as f32),
            Err(LiveCaptureError::CallbackBlockTooLarge { .. })
        ));
        assert!(matches!(
            normalize_callback(&[f32::NAN], 1, 16_000, 2, Duration::ZERO, |v| v),
            Err(LiveCaptureError::NonFiniteSample)
        ));
    }

    #[test]
    fn synthetic_terminal_is_exactly_once_for_error_races() {
        let (tx, rx) = mpsc::sync_channel(1);
        let terminal = AtomicBool::new(false);
        raise_terminal(&tx, &terminal, LiveCaptureEvent::Error(LiveCaptureError::QueueOverflow));
        raise_terminal(&tx, &terminal, LiveCaptureEvent::Error(LiveCaptureError::DeviceLost("late".into())));
        assert!(matches!(rx.recv().unwrap(), LiveCaptureEvent::Error(LiveCaptureError::QueueOverflow)));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn blocked_synthetic_consumer_cannot_retain_unbounded_pcm_or_hide_terminal() {
        let (session_tx, session_rx) = mpsc::sync_channel(1);
        let (terminal_tx, terminal_rx) = mpsc::sync_channel(1);
        let terminal = AtomicBool::new(false);
        session_tx
            .try_send(LiveCaptureEvent::Ready {
                sample_rate_hz: 16_000,
                channels: 1,
            })
            .unwrap();
        let frame = CapturedPcmFrame {
            sample_rate_hz: 16_000,
            captured_at: Duration::ZERO,
            pcm: vec![0.0; 4],
        };
        assert!(matches!(
            session_tx.try_send(LiveCaptureEvent::Frame(frame)),
            Err(TrySendError::Full(_))
        ));
        raise_terminal(
            &terminal_tx,
            &terminal,
            LiveCaptureEvent::Error(LiveCaptureError::QueueOverflow),
        );
        assert!(matches!(
            terminal_rx.try_recv(),
            Ok(LiveCaptureEvent::Error(LiveCaptureError::QueueOverflow))
        ));
        // The blocked consumer owns only the one configured session slot.
        assert!(matches!(session_rx.try_recv(), Ok(LiveCaptureEvent::Ready { .. })));
    }

    #[test]
    fn synthetic_cancel_makes_a_late_callback_token_unpublishable() {
        let scope = CancelScope::new();
        let token = scope.snapshot().unwrap();
        scope.invalidate().unwrap();
        // A fake callback carrying this snapshot is discarded before it can
        // enter the bounded queue or reach a later VAD/STT owner.
        assert!(scope.is_stale(&token));
    }
}
