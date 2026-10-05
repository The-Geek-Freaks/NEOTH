//! Concrete CPAL playback owner for the future realtime conversation session.
//!
//! This module is deliberately unavailable until `media::mod` wires it behind
//! `live-audio` and the complete authorized conversation owner consumes it.
//! CPAL's stream remains on its dedicated native owner thread; callbacks only
//! take already validated PCM from one bounded queue and fill silence when it
//! is empty. The session keeps the `AudioWorkPermit` until that thread ends.

#![cfg(feature = "live-audio")]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};

use crate::media::audio::AudioWorkPermit;
use crate::media::conversation_scope::{CancelScope, GenerationToken};
use crate::media::resampler::{MAX_SAMPLE_RATE_HZ, MIN_SAMPLE_RATE_HZ, resample_mono};

/// Maximum source channels accepted from a raw PCM TTS response.
pub(crate) const MAX_PLAYBACK_CHANNELS: u16 = 16;
/// Maximum source frames held in one enqueued PCM block.
pub(crate) const MAX_PLAYBACK_BLOCK_FRAMES: usize = 48_000;
/// Maximum blocks retained between synthesis and the native callback.
pub(crate) const MAX_PLAYBACK_QUEUE_BLOCKS: usize = 16;

/// Bounds selected by the eventual conversation owner before opening CPAL.
#[derive(Clone, Debug)]
pub(crate) struct CpalPlaybackConfig {
    /// Optional exact output device name; `None` selects the platform default.
    pub requested_device_name: Option<String>,
    /// Bounded number of complete PCM blocks that may wait for the callback.
    pub queue_blocks: usize,
}

impl Default for CpalPlaybackConfig {
    fn default() -> Self {
        Self {
            requested_device_name: None,
            queue_blocks: 8,
        }
    }
}

impl CpalPlaybackConfig {
    fn validate(&self) -> Result<(), PlaybackError> {
        if self.queue_blocks == 0 || self.queue_blocks > MAX_PLAYBACK_QUEUE_BLOCKS {
            return Err(PlaybackError::InvalidConfig {
                field: "queue_blocks",
                detail: "must be within 1..=16",
            });
        }
        Ok(())
    }
}

/// Device format the next TTS request must use. No rate conversion is hidden
/// in this owner: the future TTS dispatch extraction requests this exact PCM
/// rate, and a response with different metadata is rejected before playback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PlaybackOutputFormat {
    pub sample_rate_hz: u32,
    pub channels: u16,
}

/// Validated interleaved raw `PcmS16le` accepted by the native output queue.
///
/// The constructor deliberately takes bytes rather than `TtsResponse`: the
/// later authorized TTS response adapter must prove `TtsFormat::PcmS16le` and
/// carry the provider's sample-rate/channel metadata before it reaches here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PcmS16leBlock {
    sample_rate_hz: u32,
    channels: u16,
    samples: Vec<i16>,
}

impl PcmS16leBlock {
    pub(crate) fn from_le_bytes(
        sample_rate_hz: u32,
        channels: u16,
        bytes: Vec<u8>,
    ) -> Result<Self, PlaybackError> {
        validate_pcm_metadata(sample_rate_hz, channels)?;
        if bytes.is_empty() || !bytes.len().is_multiple_of(2) {
            return Err(PlaybackError::MalformedPcm);
        }
        let samples: Vec<i16> = bytes
            .chunks_exact(2)
            .map(|sample| i16::from_le_bytes([sample[0], sample[1]]))
            .collect();
        if !samples.len().is_multiple_of(channels as usize) {
            return Err(PlaybackError::MalformedPcm);
        }
        let frames = samples.len() / channels as usize;
        if frames == 0 || frames > MAX_PLAYBACK_BLOCK_FRAMES {
            return Err(PlaybackError::PcmBlockTooLarge {
                frames,
                limit: MAX_PLAYBACK_BLOCK_FRAMES,
            });
        }
        Ok(Self {
            sample_rate_hz,
            channels,
            samples,
        })
    }

    fn matches_output_rate(&self, output: PlaybackOutputFormat) -> bool {
        self.sample_rate_hz == output.sample_rate_hz
    }

    /// Convert a source-proven mono PCM block to the already-open device rate.
    /// Multi-channel source is not silently remixed for resampling; the later
    /// typed TTS adapter must provide mono data or reject it before this call.
    pub(crate) fn resample_mono_to(
        self,
        target_sample_rate_hz: u32,
    ) -> Result<Self, PlaybackError> {
        if self.channels != 1 {
            return Err(PlaybackError::ResampleRequiresMono);
        }
        validate_pcm_metadata(target_sample_rate_hz, self.channels)?;
        if self.sample_rate_hz == target_sample_rate_hz {
            return Ok(self);
        }
        let source: Vec<f32> = self
            .samples
            .iter()
            .map(|sample| *sample as f32 / 32_768.0)
            .collect();
        let resampled = resample_mono(&source, self.sample_rate_hz, target_sample_rate_hz)
            .map_err(|error| PlaybackError::Resample(error.to_string()))?;
        if resampled.is_empty() || resampled.len() > MAX_PLAYBACK_BLOCK_FRAMES {
            return Err(PlaybackError::PcmBlockTooLarge {
                frames: resampled.len(),
                limit: MAX_PLAYBACK_BLOCK_FRAMES,
            });
        }
        let samples = resampled
            .into_iter()
            .map(|sample| (sample.clamp(-1.0, 1.0) * 32_767.0).round() as i16)
            .collect();
        Ok(Self {
            sample_rate_hz: target_sample_rate_hz,
            channels: 1,
            samples,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PlaybackEvent {
    Ready(PlaybackOutputFormat),
    Completed,
    Error(PlaybackError),
    Cancelled,
}

impl PlaybackEvent {
    fn terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Error(_) | Self::Cancelled)
    }
}

/// Stable, content-free failure classes for the future GUI/session owner.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum PlaybackError {
    #[error("invalid playback configuration: {field} {detail}")]
    InvalidConfig {
        field: &'static str,
        detail: &'static str,
    },
    #[error("no output device is available")]
    NoOutputDevice,
    #[error("requested output device is unavailable")]
    RequestedDeviceUnavailable,
    #[error("output device enumeration failed: {0}")]
    DeviceEnumeration(String),
    #[error("output device name lookup failed: {0}")]
    DeviceName(String),
    #[error("output configuration query failed: {0}")]
    DefaultConfig(String),
    #[error("unsupported output sample format: {0}")]
    UnsupportedSampleFormat(String),
    #[error("invalid output sample rate {0} Hz")]
    InvalidSampleRate(u32),
    #[error("invalid output channel count {0}")]
    InvalidChannelCount(u16),
    #[error("output stream setup failed: {0}")]
    StreamBuild(String),
    #[error("output stream start failed: {0}")]
    StreamPlay(String),
    #[error("output device was lost or its stream failed: {0}")]
    DeviceLost(String),
    #[error("PCM bytes are not complete interleaved s16le frames")]
    MalformedPcm,
    #[error("PCM block has {frames} frames, above the {limit}-frame limit")]
    PcmBlockTooLarge { frames: usize, limit: usize },
    #[error("PCM sample rate does not match the opened output device")]
    SampleRateMismatch,
    #[error("PCM resampling requires source-proven mono input")]
    ResampleRequiresMono,
    #[error("PCM resampling failed: {0}")]
    Resample(String),
    #[error("bounded playback queue is full")]
    QueueFull,
    #[error("playback owner has already stopped")]
    OwnerStopped,
    #[error("playback completion has already been requested")]
    CompletionAlreadyRequested,
    #[error("playback owner thread terminated unexpectedly")]
    OwnerThreadTerminated,
}

/// Concrete native output-session owner. It accepts only validated raw PCM;
/// no decoder, provider call, or UI capability is exposed from this module.
pub(crate) struct CpalPlaybackSession {
    commands: SyncSender<PlaybackCommand>,
    events: Receiver<PlaybackEvent>,
    terminal_events: Receiver<PlaybackEvent>,
    stop: SyncSender<()>,
    owner: Option<JoinHandle<()>>,
    scope: CancelScope,
    token: GenerationToken,
    terminal_seen: bool,
    output_format: Option<PlaybackOutputFormat>,
    completion_requested: AtomicBool,
    _audio_permit: Option<AudioWorkPermit>,
}

impl CpalPlaybackSession {
    /// Start the dedicated CPAL owner. The owner reports `Ready(format)` before
    /// callers enqueue data; a future typed TTS adapter may request this rate or use
    /// `PcmS16leBlock::resample_mono_to` after proving its actual source format.
    pub(crate) fn start(
        config: CpalPlaybackConfig,
        scope: CancelScope,
        audio_permit: AudioWorkPermit,
    ) -> Result<Self, PlaybackError> {
        config.validate()?;
        let token = scope
            .snapshot()
            .map_err(|_| PlaybackError::OwnerThreadTerminated)?;
        let (commands, command_rx) = mpsc::sync_channel(config.queue_blocks);
        let (events_tx, events) = mpsc::sync_channel(2);
        let (terminal_tx, terminal_events) = mpsc::sync_channel(1);
        let (stop, stop_rx) = mpsc::sync_channel(1);
        let owner_scope = scope.clone();
        let owner_token = token.clone();
        let owner = thread::Builder::new()
            .name("neoth-live-playback".into())
            .spawn(move || {
                run_playback_owner(
                    config,
                    owner_scope,
                    owner_token,
                    command_rx,
                    events_tx,
                    terminal_tx,
                    stop_rx,
                );
            })
            .map_err(|_| PlaybackError::OwnerThreadTerminated)?;

        Ok(Self {
            commands,
            events,
            terminal_events,
            stop,
            owner: Some(owner),
            scope,
            token,
            terminal_seen: false,
            output_format: None,
            completion_requested: AtomicBool::new(false),
            _audio_permit: Some(audio_permit),
        })
    }

    /// Queue one complete validated PCM block without blocking a session/UI
    /// thread. The block must match the `Ready` format exactly.
    pub(crate) fn enqueue(&self, block: PcmS16leBlock) -> Result<(), PlaybackError> {
        if self.completion_requested.load(Ordering::Acquire) {
            return Err(PlaybackError::OwnerStopped);
        }
        if self
            .output_format
            .is_some_and(|expected| !block.matches_output_rate(expected))
        {
            return Err(PlaybackError::SampleRateMismatch);
        }
        match self.commands.try_send(PlaybackCommand::Block(block)) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(PlaybackError::QueueFull),
            Err(TrySendError::Disconnected(_)) => Err(PlaybackError::OwnerStopped),
        }
    }

    /// Mark the bounded source complete. Completion is published only after
    /// the CPAL callback has drained every queued sample; it never replays a
    /// prior generation's data after the scope becomes stale.
    pub(crate) fn complete(&self) -> Result<(), PlaybackError> {
        if self
            .completion_requested
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(PlaybackError::CompletionAlreadyRequested);
        }
        match self.commands.try_send(PlaybackCommand::Complete) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                self.completion_requested.store(false, Ordering::Release);
                Err(PlaybackError::QueueFull)
            }
            Err(TrySendError::Disconnected(_)) => {
                self.completion_requested.store(false, Ordering::Release);
                Err(PlaybackError::OwnerStopped)
            }
        }
    }

    pub(crate) fn output_format(&self) -> Option<PlaybackOutputFormat> {
        self.output_format
    }

    pub(crate) fn next_event(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<PlaybackEvent>, PlaybackError> {
        if self.terminal_seen {
            return Ok(None);
        }
        if let Ok(event) = self.terminal_events.try_recv() {
            self.mark_terminal_and_join();
            return Ok(Some(event));
        }
        let received = self.events.recv_timeout(timeout);
        self.resolve_event_wait(received)
    }

    fn resolve_event_wait(
        &mut self,
        received: Result<PlaybackEvent, RecvTimeoutError>,
    ) -> Result<Option<PlaybackEvent>, PlaybackError> {
        if let Ok(terminal) = self.terminal_events.try_recv() {
            self.mark_terminal_and_join();
            return Ok(Some(terminal));
        }
        match received {
            Ok(event) => {
                if let PlaybackEvent::Ready(format) = event {
                    self.output_format = Some(format);
                    return Ok(Some(PlaybackEvent::Ready(format)));
                }
                if scope_is_stale(&self.scope, &self.token) && !event.terminal() {
                    self.mark_terminal_and_join();
                    return Ok(Some(PlaybackEvent::Cancelled));
                }
                if event.terminal() {
                    self.mark_terminal_and_join();
                }
                Ok(Some(event))
            }
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => {
                self.mark_terminal_and_join();
                Ok(Some(PlaybackEvent::Error(
                    PlaybackError::OwnerThreadTerminated,
                )))
            }
        }
    }

    /// Stop CPAL on its owning thread and join it. This never invalidates a
    /// potentially newer generation owned by the conversation controller.
    pub(crate) fn cancel_and_join(&mut self) {
        let _ = self.stop.try_send(());
        self.join();
    }

    pub(crate) fn join(&mut self) {
        join_owner_and_release(&mut self.owner, &mut self._audio_permit);
    }

    fn mark_terminal_and_join(&mut self) {
        self.terminal_seen = true;
        self.join();
    }
}

impl Drop for CpalPlaybackSession {
    fn drop(&mut self) {
        if self.terminal_seen {
            self.join();
        } else {
            self.cancel_and_join();
        }
    }
}

/// Joining is the release boundary for the caller-owned shared audio lease.
/// It intentionally takes the permit only after the owner has stopped and its
/// CPAL stream has dropped. The helper remains generic solely so the same
/// shutdown ordering can be driven deterministically in a device-free test.
fn join_owner_and_release<T>(owner: &mut Option<JoinHandle<()>>, permit: &mut Option<T>) {
    if let Some(owner) = owner.take() {
        let _ = owner.join();
    }
    let _ = permit.take();
}
enum PlaybackCommand {
    Block(PcmS16leBlock),
    Complete,
}

enum CallbackEvent {
    Drained,
}

struct CallbackState {
    commands: Receiver<PlaybackCommand>,
    current: Option<PcmS16leBlock>,
    frame_offset: usize,
    complete_requested: bool,
    drained_reported: bool,
    format_mismatch: bool,
}

impl CallbackState {
    fn next_sample(
        &mut self,
        output_channel: usize,
        output_channels: usize,
        expected: PlaybackOutputFormat,
    ) -> Option<i16> {
        loop {
            if let Some(block) = self.current.as_ref() {
                let source_channels = block.channels as usize;
                let frames = block.samples.len() / source_channels;
                if self.frame_offset < frames {
                    let sample = map_channel(
                        &block.samples,
                        self.frame_offset,
                        source_channels,
                        output_channel,
                        output_channels,
                    );
                    if output_channel + 1 == output_channels {
                        self.frame_offset += 1;
                    }
                    return Some(sample);
                }
                self.current = None;
                self.frame_offset = 0;
                continue;
            }
            match self.commands.try_recv() {
                Ok(PlaybackCommand::Block(block)) => {
                    if !block.matches_output_rate(expected) {
                        self.format_mismatch = true;
                        return None;
                    }
                    self.current = Some(block);
                }
                Ok(PlaybackCommand::Complete) => {
                    self.complete_requested = true;
                    return None;
                }
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => return None,
            }
        }
    }

    fn drained(&self) -> bool {
        self.complete_requested && self.current.is_none()
    }
}

/// Shared by the owner loop and the native callback so both discard a stale
/// generation before they publish or render another PCM frame.
fn scope_is_stale(scope: &CancelScope, token: &GenerationToken) -> bool {
    scope.is_stale(token)
}
/// Exact native-callback gate: a stale generation or already terminal owner
/// fills silence instead of consuming another queued PCM frame.
fn callback_must_silence(
    terminal: &AtomicBool,
    scope: &CancelScope,
    token: &GenerationToken,
) -> bool {
    terminal.load(Ordering::Acquire) || scope_is_stale(scope, token)
}
fn run_playback_owner(
    config: CpalPlaybackConfig,
    scope: CancelScope,
    token: GenerationToken,
    commands: Receiver<PlaybackCommand>,
    events: SyncSender<PlaybackEvent>,
    terminal_events: SyncSender<PlaybackEvent>,
    stop: Receiver<()>,
) {
    if scope_is_stale(&scope, &token) {
        let _ = terminal_events.try_send(PlaybackEvent::Cancelled);
        return;
    }
    let host = cpal::default_host();
    let device = match choose_output_device(&host, config.requested_device_name.as_deref()) {
        Ok(device) => device,
        Err(error) => {
            let _ = terminal_events.try_send(PlaybackEvent::Error(error));
            return;
        }
    };
    let supported = match device.default_output_config() {
        Ok(config) => config,
        Err(error) => {
            let _ = terminal_events.try_send(PlaybackEvent::Error(PlaybackError::DefaultConfig(
                error.to_string(),
            )));
            return;
        }
    };
    let stream_config = supported.config();
    let output_format = PlaybackOutputFormat {
        sample_rate_hz: stream_config.sample_rate,
        channels: stream_config.channels,
    };
    if let Err(error) = validate_pcm_metadata(output_format.sample_rate_hz, output_format.channels)
    {
        let _ = terminal_events.try_send(PlaybackEvent::Error(error));
        return;
    }

    let (callback_events, callback_event_rx) = mpsc::sync_channel(1);
    let terminal = Arc::new(AtomicBool::new(false));
    let stream = match supported.sample_format() {
        cpal::SampleFormat::F32 => build_output_stream::<f32>(
            &device,
            stream_config,
            commands,
            callback_events,
            terminal_events.clone(),
            terminal.clone(),
            scope.clone(),
            token.clone(),
            output_format,
            0.0,
            |sample| sample as f32 / 32_768.0,
        ),
        cpal::SampleFormat::I16 => build_output_stream::<i16>(
            &device,
            stream_config,
            commands,
            callback_events,
            terminal_events.clone(),
            terminal.clone(),
            scope.clone(),
            token.clone(),
            output_format,
            0,
            |sample| sample,
        ),
        cpal::SampleFormat::U16 => build_output_stream::<u16>(
            &device,
            stream_config,
            commands,
            callback_events,
            terminal_events.clone(),
            terminal.clone(),
            scope.clone(),
            token.clone(),
            output_format,
            32_768,
            |sample| (sample as i32 + 32_768) as u16,
        ),
        format => Err(PlaybackError::UnsupportedSampleFormat(format!(
            "{format:?}"
        ))),
    };
    let stream = match stream {
        Ok(stream) => stream,
        Err(error) => {
            let _ = terminal_events.try_send(PlaybackEvent::Error(error));
            return;
        }
    };
    if let Err(error) = stream.play() {
        let _ = terminal_events.try_send(PlaybackEvent::Error(PlaybackError::StreamPlay(
            error.to_string(),
        )));
        return;
    }
    if events
        .try_send(PlaybackEvent::Ready(output_format))
        .is_err()
    {
        raise_terminal(
            &terminal_events,
            &terminal,
            PlaybackEvent::Error(PlaybackError::QueueFull),
        );
        return;
    }

    loop {
        if scope_is_stale(&scope, &token) || stop.try_recv().is_ok() {
            raise_terminal(&terminal_events, &terminal, PlaybackEvent::Cancelled);
            break;
        }
        if terminal.load(Ordering::Acquire) {
            break;
        }
        match callback_event_rx.recv_timeout(Duration::from_millis(20)) {
            Ok(CallbackEvent::Drained) => {
                raise_terminal(&terminal_events, &terminal, PlaybackEvent::Completed);
                break;
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    drop(stream);
}

fn choose_output_device(
    host: &cpal::Host,
    requested_name: Option<&str>,
) -> Result<cpal::Device, PlaybackError> {
    match requested_name {
        None => host
            .default_output_device()
            .ok_or(PlaybackError::NoOutputDevice),
        Some(requested_name) => host
            .output_devices()
            .map_err(|error| PlaybackError::DeviceEnumeration(error.to_string()))?
            .find_map(|device| match device.description() {
                Ok(description) if description.name() == requested_name => Some(Ok(device)),
                Ok(_) => None,
                Err(error) => Some(Err(PlaybackError::DeviceName(error.to_string()))),
            })
            .transpose()?
            .ok_or(PlaybackError::RequestedDeviceUnavailable),
    }
}

fn build_output_stream<T>(
    device: &cpal::Device,
    config: cpal::StreamConfig,
    commands: Receiver<PlaybackCommand>,
    callback_events: SyncSender<CallbackEvent>,
    terminal_events: SyncSender<PlaybackEvent>,
    terminal: Arc<AtomicBool>,
    scope: CancelScope,
    token: GenerationToken,
    format: PlaybackOutputFormat,
    silence: T,
    convert: fn(i16) -> T,
) -> Result<cpal::Stream, PlaybackError>
where
    T: cpal::SizedSample + Copy + Send + 'static,
{
    let callback_terminal_events = terminal_events.clone();
    let callback_terminal = terminal.clone();
    let mut state = CallbackState {
        commands,
        current: None,
        frame_offset: 0,
        complete_requested: false,
        drained_reported: false,
        format_mismatch: false,
    };
    device
        .build_output_stream(
            config,
            move |output: &mut [T], _| {
                if callback_must_silence(&callback_terminal, &scope, &token) {
                    output.fill(silence);
                    return;
                }
                for (index, sample) in output.iter_mut().enumerate() {
                    let output_channel = index % format.channels as usize;
                    let next = state.next_sample(output_channel, format.channels as usize, format);
                    if state.format_mismatch {
                        output[index..].fill(silence);
                        break;
                    }
                    *sample = next.map(convert).unwrap_or(silence);
                }
                if state.format_mismatch {
                    raise_terminal(
                        &callback_terminal_events,
                        &callback_terminal,
                        PlaybackEvent::Error(PlaybackError::SampleRateMismatch),
                    );
                    output.fill(silence);
                    return;
                }
                if state.drained() && !state.drained_reported {
                    state.drained_reported = true;
                    let _ = callback_events.try_send(CallbackEvent::Drained);
                }
            },
            move |error| {
                raise_terminal(
                    &callback_terminal_events,
                    &callback_terminal,
                    PlaybackEvent::Error(PlaybackError::DeviceLost(error.to_string())),
                );
            },
            None,
        )
        .map_err(|error| PlaybackError::StreamBuild(error.to_string()))
}

fn validate_pcm_metadata(sample_rate_hz: u32, channels: u16) -> Result<(), PlaybackError> {
    if !(MIN_SAMPLE_RATE_HZ..=MAX_SAMPLE_RATE_HZ).contains(&sample_rate_hz) {
        return Err(PlaybackError::InvalidSampleRate(sample_rate_hz));
    }
    if channels == 0 || channels > MAX_PLAYBACK_CHANNELS {
        return Err(PlaybackError::InvalidChannelCount(channels));
    }
    Ok(())
}

/// Explicit interleaved channel conversion. Mono is duplicated; downmixing to
/// mono averages all source channels; wider output repeats source channels in
/// order. No source frame is retained after its final output channel is filled.
fn map_channel(
    samples: &[i16],
    source_frame: usize,
    source_channels: usize,
    output_channel: usize,
    output_channels: usize,
) -> i16 {
    let offset = source_frame * source_channels;
    if output_channels == 1 && source_channels > 1 {
        let sum: i32 = samples[offset..offset + source_channels]
            .iter()
            .map(|sample| i32::from(*sample))
            .sum();
        return (sum / source_channels as i32) as i16;
    }
    let source_channel = if source_channels == 1 {
        0
    } else {
        output_channel % source_channels
    };
    samples[offset + source_channel]
}

fn raise_terminal(
    terminal_events: &SyncSender<PlaybackEvent>,
    terminal: &AtomicBool,
    event: PlaybackEvent,
) {
    if !terminal.swap(true, Ordering::AcqRel) {
        let _ = terminal_events.try_send(event);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::{CallbackEvent, CallbackState, PcmS16leBlock};

    #[test]
    fn callback_drains_bounded_pcm_then_reports_completion_once() {
        let (tx, rx) = mpsc::sync_channel(2);
        let (events, event_rx) = mpsc::sync_channel(1);
        tx.send(super::PlaybackCommand::Block(
            PcmS16leBlock::from_le_bytes(48_000, 1, vec![1, 0, 255, 255]).unwrap(),
        ))
        .unwrap();
        tx.send(super::PlaybackCommand::Complete).unwrap();
        let mut state = CallbackState {
            commands: rx,
            current: None,
            frame_offset: 0,
            complete_requested: false,
            drained_reported: false,
            format_mismatch: false,
        };
        let expected = super::PlaybackOutputFormat {
            sample_rate_hz: 48_000,
            channels: 1,
        };
        let first: Vec<_> = (0..4)
            .map(|n| state.next_sample(n % 2, 2, expected))
            .collect();
        assert_eq!(first, vec![Some(1), Some(1), Some(-1), Some(-1)]);
        assert!(state.next_sample(0, 2, expected).is_none());
        if state.drained() && !state.drained_reported {
            state.drained_reported = true;
            events.try_send(CallbackEvent::Drained).unwrap();
        }
        assert!(matches!(event_rx.try_recv(), Ok(CallbackEvent::Drained)));
        assert!(event_rx.try_recv().is_err());
    }

    #[test]
    fn pcm_block_rejects_misaligned_or_unknown_metadata() {
        assert!(PcmS16leBlock::from_le_bytes(0, 1, vec![0, 0]).is_err());
        assert!(PcmS16leBlock::from_le_bytes(48_000, 0, vec![0, 0]).is_err());
        assert!(PcmS16leBlock::from_le_bytes(48_000, 2, vec![0, 0]).is_err());
    }

    #[test]
    fn stale_generation_is_rejected_before_ready_or_callback_render() {
        let scope = super::CancelScope::new();
        let token = scope.snapshot().unwrap();
        scope.invalidate().unwrap();
        assert!(super::callback_must_silence(
            &std::sync::atomic::AtomicBool::new(false),
            &scope,
            &token,
        ));
    }

    #[test]
    fn callback_device_failure_publishes_exactly_one_terminal_error() {
        let (tx, rx) = mpsc::sync_channel(1);
        let terminal = std::sync::atomic::AtomicBool::new(false);
        super::raise_terminal(
            &tx,
            &terminal,
            super::PlaybackEvent::Error(super::PlaybackError::DeviceLost("lost".into())),
        );
        super::raise_terminal(
            &tx,
            &terminal,
            super::PlaybackEvent::Error(super::PlaybackError::OwnerThreadTerminated),
        );
        assert!(matches!(
            rx.try_recv(),
            Ok(super::PlaybackEvent::Error(
                super::PlaybackError::DeviceLost(_)
            ))
        ));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn join_releases_permit_slot_only_after_owner_has_ended() {
        struct LeaseWitness(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl Drop for LeaseWitness {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::Release);
            }
        }

        let worker_ended = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_flag = std::sync::Arc::clone(&worker_ended);
        let mut owner = Some(std::thread::spawn(move || {
            worker_flag.store(true, std::sync::atomic::Ordering::Release);
        }));
        let released = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut lease = Some(LeaseWitness(std::sync::Arc::clone(&released)));
        super::join_owner_and_release(&mut owner, &mut lease);
        assert!(worker_ended.load(std::sync::atomic::Ordering::Acquire));
        assert!(lease.is_none());
        assert!(released.load(std::sync::atomic::Ordering::Acquire));
    }

    #[test]
    fn source_proven_mono_pcm_can_be_resampled_before_enqueue() {
        let source = PcmS16leBlock::from_le_bytes(24_000, 1, vec![0; 512]).unwrap();
        let converted = source.resample_mono_to(48_000).unwrap();
        assert_eq!(converted.sample_rate_hz, 48_000);
        assert_eq!(converted.channels, 1);
        assert!(!converted.samples.is_empty());
    }
}
