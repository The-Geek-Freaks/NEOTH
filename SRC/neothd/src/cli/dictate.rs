//! `neoth dictate <file>` / `neoth dictate --live` — dictation surface.
//!
//! File mode decodes a selected audio file before the canonical STT path. Live
//! mode keeps one bounded native capture session, one audio-work permit, and one
//! cancellation scope while the media core performs 16-kHz Silero utterance
//! assembly. Both modes retain the existing consent, audit, provider, and
//! fallback boundary.

use anyhow::{Context, Result};
use clap::Args;
#[cfg(feature = "live-audio")]
use std::collections::VecDeque;
#[cfg(feature = "live-audio")]
use std::future::Future;
use std::path::PathBuf;
#[cfg(feature = "live-audio")]
use std::time::Duration;

use crate::cli::OutputFormat;
use crate::media::dictation::DictationError;
#[cfg(feature = "live-audio")]
use crate::media::dictation::{LiveUtteranceAssembler, LiveUtteranceEvent};

/// Capture continues while the preceding utterance is being transcribed.  The
/// short queue is deliberately an explicit loss boundary: retaining arbitrary
/// microphone audio while a provider is slow would be worse than telling the
/// operator exactly which utterance could not be queued.
#[cfg(feature = "live-audio")]
const MAX_PENDING_LIVE_UTTERANCES: usize = 2;
#[cfg(feature = "live-audio")]
const LIVE_CAPTURE_POLL: Duration = Duration::from_millis(50);

#[cfg(feature = "live-audio")]
enum LiveCapturePumpEvent {
    Capture(crate::media::live_capture::LiveCaptureEvent),
}

#[cfg(feature = "live-audio")]
enum LiveCaptureRelay {
    Sent,
    ReceiverClosed,
    Overloaded,
}

/// Owns every task started by the live CLI until the normal shutdown path has
/// joined it. If the outer CLI future is dropped, the guard still advances the
/// scope and aborts the async task; the bounded capture relay observes the
/// stale token and stops its CPAL session.
#[cfg(feature = "live-audio")]
struct LiveDictateOwnedTasks {
    scope: crate::media::conversation_scope::CancelScope,
    capture_worker: Option<tokio::task::JoinHandle<Result<()>>>,
    transcription: Option<tokio::task::JoinHandle<(u64, Option<Result<String, DictationError>>)>>,
}

#[cfg(feature = "live-audio")]
impl LiveDictateOwnedTasks {
    fn new(
        scope: crate::media::conversation_scope::CancelScope,
        capture_worker: tokio::task::JoinHandle<Result<()>>,
    ) -> Self {
        Self {
            scope,
            capture_worker: Some(capture_worker),
            transcription: None,
        }
    }

    async fn join_capture(&mut self) -> Result<()> {
        let Some(worker) = self.capture_worker.take() else {
            return Ok(());
        };
        worker
            .await
            .context("dictate: capture relay task panicked")?
    }

    /// Drain the foreground STT task during an ordinary CLI shutdown. Keeping
    /// the handle in this owner until completion also keeps any cloned WAL
    /// sender in scope until the dispatcher has finished its owned work.
    async fn drain_transcription(
        &mut self,
    ) -> Result<Option<(u64, Option<Result<String, DictationError>>)>> {
        if self.transcription.is_none() {
            return Ok(None);
        }
        let outcome = self
            .transcription
            .as_mut()
            .expect("checked owned foreground task")
            .await;
        self.transcription = None;
        Ok(Some(
            outcome.context("dictate: live transcription task panicked")?,
        ))
    }
}

#[cfg(feature = "live-audio")]
impl Drop for LiveDictateOwnedTasks {
    fn drop(&mut self) {
        let _ = self.scope.invalidate();
        if let Some(task) = self.transcription.take() {
            task.abort();
        }
        if let Some(worker) = self.capture_worker.take() {
            // `spawn_blocking` cannot be force-stopped once executing. The
            // stale scope is its stop signal; abort also prevents a queued
            // relay from starting after its owner has gone away.
            worker.abort();
        }
    }
}

#[derive(Args, Debug, Clone)]
pub struct DictateArgs {
    /// Audio file to transcribe (WAV/MP3/FLAC/Ogg/M4A — decoded to 16 kHz mono
    /// before STT). Omit this only with `--live`.
    #[arg(required_unless_present = "live", conflicts_with = "live")]
    pub file: Option<PathBuf>,

    /// Capture a microphone and transcribe completed speech utterances until
    /// Ctrl-C or the device terminates.
    #[arg(long, conflicts_with = "file")]
    pub live: bool,

    /// Exact input-device name for `--live`; the platform default is used when
    /// omitted.
    #[arg(long, requires = "live")]
    pub input_device: Option<String>,

    #[arg(skip)]
    pub output: OutputFormat,
}

pub async fn run_dictate(args: DictateArgs) -> Result<()> {
    if args.live {
        return run_live_dictate(args).await;
    }
    run_file_dictate(args).await
}

async fn run_file_dictate(args: DictateArgs) -> Result<()> {
    let config = crate::config::FreedomConfig::load_from_default_path()?;
    let media_cfg = config.media;
    let updater_cfg = config.updater;
    let neoth_home = crate::config::FreedomConfig::default_neoth_home();
    let file = args
        .file
        .clone()
        .context("dictate: audio file is required unless --live is set")?;

    let audit = open_dictate_audit(&neoth_home);
    let writer_for_stt = audit.as_ref().map(|(writer, _)| writer.clone());
    let permit = crate::media::audio::acquire_audio_work_permit()
        .await
        .context("dictate: acquire global audio worker budget")?;
    let (samples, permit) = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let samples = crate::media::audio::decode_file_to_pcm(&file, &permit)?;
        Ok((samples, permit))
    })
    .await
    .context("dictate: blocking decode task panicked")??;
    let outcome = crate::media::dictation::transcribe_utterance_with_audio_permit(
        &samples,
        crate::media::audio::TARGET_SAMPLE_RATE,
        &media_cfg,
        &updater_cfg,
        &neoth_home,
        writer_for_stt.as_ref(),
        &permit,
    )
    .await;

    drop(writer_for_stt);
    drop(permit);
    close_dictate_audit(audit).await?;
    match outcome {
        Ok(text) => match args.output {
            OutputFormat::Json | OutputFormat::Jsonl => println!(
                "{}",
                serde_json::json!({ "ok": true, "text": text, "file": args.file })
            ),
            OutputFormat::Table => println!("{text}"),
        },
        Err(DictationError::AllSilence) => match args.output {
            OutputFormat::Json | OutputFormat::Jsonl => println!(
                "{}",
                serde_json::json!({ "ok": true, "text": "", "silence": true })
            ),
            OutputFormat::Table => eprintln!("[silence — nothing transcribed]"),
        },
        Err(error) => anyhow::bail!(error),
    }
    Ok(())
}

#[cfg(not(feature = "live-audio"))]
async fn run_live_dictate(args: DictateArgs) -> Result<()> {
    let error = anyhow::anyhow!(
        "Live microphone capture is unavailable in this build. Use a NEOTH desktop release or build with the live-audio feature."
    );
    emit_live_terminal_error(args.output, &error);
    Err(error)
}

#[cfg(feature = "live-audio")]
async fn run_live_dictate(args: DictateArgs) -> Result<()> {
    let config = crate::config::FreedomConfig::load_from_default_path()?;
    let media_cfg = config.media;
    let updater_cfg = config.updater;
    let neoth_home = crate::config::FreedomConfig::default_neoth_home();
    if !media_cfg.dictation_enabled {
        anyhow::bail!(DictationError::NotEnabled);
    }

    let permit = crate::media::audio::acquire_audio_work_permit()
        .await
        .context("dictate: acquire global audio worker budget")?;
    // VAD construction allocates model state.  It is admission-bound just as
    // capture and every later STT request are.
    let mut assembler = LiveUtteranceAssembler::new(&media_cfg)
        .map_err(anyhow::Error::from)
        .context("dictate: initialize live Silero VAD")?;
    let scope = crate::media::conversation_scope::CancelScope::new();
    let token = scope
        .snapshot()
        .context("dictate: initialize live cancellation scope")?;
    let session = crate::media::live_capture::CpalCaptureSession::start(
        crate::media::live_capture::CpalCaptureConfig {
            requested_device_name: args.input_device.clone(),
            ..Default::default()
        },
        scope.clone(),
        permit.clone(),
    )
    .map_err(anyhow::Error::from)
    .context("dictate: start live microphone capture")?;
    let audit = open_dictate_audit(&neoth_home);
    let writer_for_stt = audit.as_ref().map(|(writer, _)| writer.clone());
    let (capture_tx, mut capture_rx) = tokio::sync::mpsc::channel(8);
    let capture_scope = scope.clone();
    let capture_token = token.clone();
    // `next_event` is intentionally synchronous because the CPAL stream lives
    // on a native owner thread.  One owned blocking task bridges it into this
    // async loop; it is always joined below, never detached.
    let capture_worker = tokio::task::spawn_blocking(move || {
        run_live_capture_pump(session, capture_scope, capture_token, capture_tx)
    });
    let mut owned_tasks = LiveDictateOwnedTasks::new(scope.clone(), capture_worker);
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let mut pending = VecDeque::with_capacity(MAX_PENDING_LIVE_UTTERANCES);
    let mut cancelled = false;
    let mut failure: Option<anyhow::Error> = None;

    loop {
        if scope.is_stale(&token) {
            cancelled = true;
            break;
        }
        if owned_tasks.transcription.is_none() {
            if let Some((sequence, pcm)) = pending.pop_front() {
                emit_live_event(
                    args.output,
                    serde_json::json!({ "type": "live_dictation", "state": "transcribing", "sequence": sequence }),
                );
                owned_tasks.transcription = Some(start_live_transcription(
                    sequence,
                    pcm,
                    media_cfg.clone(),
                    updater_cfg.clone(),
                    neoth_home.clone(),
                    writer_for_stt.clone(),
                    permit.clone(),
                    scope.clone(),
                    token.clone(),
                ));
            }
        }

        tokio::select! {
            signal = &mut ctrl_c => {
                if signal.is_ok() {
                    let _ = scope.invalidate();
                    cancelled = true;
                } else {
                    failure = Some(anyhow::anyhow!("dictate: Ctrl-C listener failed"));
                }
                break;
            }
            result = async {
                match owned_tasks.transcription.as_mut() {
                    Some(task) => Some(task.await),
                    None => std::future::pending().await,
                }
            } => {
                owned_tasks.transcription = None;
                if scope.is_stale(&token) {
                    cancelled = true;
                    break;
                }
                match result.expect("transcription branch only runs for an owned task") {
                    Ok((sequence, Some(Ok(text)))) => emit_live_event(args.output, serde_json::json!({ "type": "live_dictation", "state": "transcript", "sequence": sequence, "text": text })),
                    Ok((_sequence, Some(Err(DictationError::AllSilence)))) => {},
                    Ok((_sequence, Some(Err(error)))) => {
                        failure = Some(anyhow::Error::from(error).context("dictate: transcribe live utterance"));
                        break;
                    }
                    Ok((_sequence, None)) => {
                        cancelled = true;
                        break;
                    }
                    Err(error) => {
                        failure = Some(anyhow::Error::from(error).context("dictate: live transcription task panicked"));
                        break;
                    }
                }
            }
            event = capture_rx.recv() => {
                let Some(event) = event else {
                    match owned_tasks.join_capture().await {
                        Ok(()) if scope.is_stale(&token) => cancelled = true,
                        Ok(()) => failure = Some(anyhow::anyhow!("dictate: capture relay closed before terminal state")),
                        Err(error) => failure = Some(error),
                    }
                    break;
                };
                match event {
                    LiveCapturePumpEvent::Capture(crate::media::live_capture::LiveCaptureEvent::Ready { sample_rate_hz, channels }) => {
                        emit_live_event(args.output, serde_json::json!({ "type": "live_dictation", "state": "ready", "sample_rate_hz": sample_rate_hz, "channels": channels }));
                    }
                    LiveCapturePumpEvent::Capture(crate::media::live_capture::LiveCaptureEvent::Frame(frame)) => {
                        if scope.is_stale(&token) {
                            cancelled = true;
                            break;
                        }
                        let events = match assembler.push_frame(&frame) {
                            Ok(events) => events,
                            Err(error) => {
                                failure = Some(anyhow::Error::from(error).context("dictate: assemble live utterance"));
                                break;
                            }
                        };
                        for event in events {
                            if scope.is_stale(&token) {
                                cancelled = true;
                                break;
                            }
                            match event {
                                LiveUtteranceEvent::SpeechStarted => emit_live_event(args.output, serde_json::json!({ "type": "live_dictation", "state": "speech_started" })),
                                LiveUtteranceEvent::UtteranceReady { sequence, pcm } if owned_tasks.transcription.is_none() && pending.is_empty() => {
                                    if scope.is_stale(&token) {
                                        cancelled = true;
                                        break;
                                    }
                                    emit_live_event(args.output, serde_json::json!({ "type": "live_dictation", "state": "transcribing", "sequence": sequence }));
                                    owned_tasks.transcription = Some(start_live_transcription(sequence, pcm, media_cfg.clone(), updater_cfg.clone(), neoth_home.clone(), writer_for_stt.clone(), permit.clone(), scope.clone(), token.clone()));
                                }
                                LiveUtteranceEvent::UtteranceReady { sequence, pcm } if pending.len() < MAX_PENDING_LIVE_UTTERANCES => {
                                    let accepted = enqueue_live_utterance(&mut pending, sequence, pcm);
                                    debug_assert!(accepted, "guard and pending admission must agree");
                                    emit_live_event(args.output, serde_json::json!({ "type": "live_dictation", "state": "queued", "sequence": sequence, "pending": pending.len() }));
                                }
                                LiveUtteranceEvent::UtteranceReady { sequence, .. } => {
                                    emit_live_event(args.output, serde_json::json!({ "type": "live_dictation", "state": "dropped", "sequence": sequence, "reason": "transcription_backlog" }));
                                }
                            }
                        }
                    }
                    LiveCapturePumpEvent::Capture(crate::media::live_capture::LiveCaptureEvent::Cancelled) => {
                        cancelled = true;
                        break;
                    }
                    LiveCapturePumpEvent::Capture(crate::media::live_capture::LiveCaptureEvent::Error(error)) => {
                        failure = Some(anyhow::Error::from(error).context("dictate: live microphone capture failed"));
                        break;
                    }
                }
            }
        }
    }

    // A capture cancellation is a caller decision: `cancel_and_join` itself
    // deliberately does not advance the scope. Invalidate first, then drain
    // the owned foreground task before releasing its writer/permit. Aborting
    // here could detach a cloud supervisor that still owns a WAL sender.
    let _ = scope.invalidate();
    assembler.reset();
    pending.clear();
    emit_live_event(
        args.output,
        serde_json::json!({
            "type": "live_dictation",
            "state": "stopping",
            "draining_transcription": owned_tasks.transcription.is_some(),
        }),
    );
    if let Err(error) = owned_tasks.join_capture().await {
        if failure.is_none() {
            failure = Some(error);
        }
    }
    match owned_tasks.drain_transcription().await {
        Ok(Some((_sequence, Some(Err(error))))) if failure.is_none() => {
            failure = Some(
                anyhow::Error::from(error)
                    .context("dictate: transcribe live utterance while draining"),
            );
        }
        Ok(_) => {}
        Err(error) if failure.is_none() => failure = Some(error),
        Err(_) => {}
    }
    drop(writer_for_stt);
    drop(permit);
    if let Err(error) = close_dictate_audit(audit).await {
        if failure.is_none() {
            failure = Some(error);
        }
    }
    if let Some(error) = failure {
        emit_live_terminal_error(args.output, &error);
        return Err(error);
    }
    if cancelled {
        emit_live_event(
            args.output,
            serde_json::json!({ "type": "live_dictation", "state": "cancelled" }),
        );
    }
    Ok(())
}

#[cfg(feature = "live-audio")]
fn enqueue_live_utterance(
    pending: &mut VecDeque<(u64, Vec<f32>)>,
    sequence: u64,
    pcm: Vec<f32>,
) -> bool {
    if pending.len() >= MAX_PENDING_LIVE_UTTERANCES {
        return false;
    }
    pending.push_back((sequence, pcm));
    true
}

#[cfg(feature = "live-audio")]
fn run_live_capture_pump(
    mut session: crate::media::live_capture::CpalCaptureSession,
    scope: crate::media::conversation_scope::CancelScope,
    token: crate::media::conversation_scope::GenerationToken,
    sender: tokio::sync::mpsc::Sender<LiveCapturePumpEvent>,
) -> Result<()> {
    loop {
        if scope.is_stale(&token) {
            session.cancel_and_join();
            return Ok(());
        }
        let event = session
            .next_event(LIVE_CAPTURE_POLL)
            .map_err(anyhow::Error::from)
            .context("dictate: poll live microphone capture")?;
        let Some(event) = event else {
            continue;
        };
        let terminal = matches!(
            event,
            crate::media::live_capture::LiveCaptureEvent::Cancelled
                | crate::media::live_capture::LiveCaptureEvent::Error(_)
        );
        match relay_live_capture_event(&sender, &scope, LiveCapturePumpEvent::Capture(event)) {
            LiveCaptureRelay::Sent => {}
            LiveCaptureRelay::ReceiverClosed => {
                let _ = scope.invalidate();
                session.cancel_and_join();
                return Ok(());
            }
            LiveCaptureRelay::Overloaded => {
                session.cancel_and_join();
                anyhow::bail!(
                    "dictate: bounded capture relay overflowed while transcription was pending"
                );
            }
        }
        if terminal {
            session.join();
            return Ok(());
        }
    }
}

#[cfg(feature = "live-audio")]
fn relay_live_capture_event<T>(
    sender: &tokio::sync::mpsc::Sender<T>,
    scope: &crate::media::conversation_scope::CancelScope,
    event: T,
) -> LiveCaptureRelay {
    match sender.try_send(event) {
        Ok(()) => LiveCaptureRelay::Sent,
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => LiveCaptureRelay::ReceiverClosed,
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            let _ = scope.invalidate();
            LiveCaptureRelay::Overloaded
        }
    }
}

#[cfg(feature = "live-audio")]
fn start_live_transcription(
    sequence: u64,
    pcm: Vec<f32>,
    media_cfg: crate::config::features::MediaConfig,
    updater_cfg: crate::config::UpdaterConfig,
    neoth_home: PathBuf,
    writer: Option<crate::wal::writer::WalWriterHandle>,
    permit: crate::media::audio::AudioWorkPermit,
    scope: crate::media::conversation_scope::CancelScope,
    token: crate::media::conversation_scope::GenerationToken,
) -> tokio::task::JoinHandle<(u64, Option<Result<String, DictationError>>)> {
    tokio::spawn(async move {
        let result = dispatch_live_if_current(&scope, &token, || async {
            crate::media::dictation::transcribe_live_utterance_with_audio_permit(
                &pcm,
                16_000,
                &media_cfg,
                &updater_cfg,
                &neoth_home,
                writer.as_ref(),
                &permit,
            )
            .await
        })
        .await;
        (sequence, result)
    })
}

#[cfg(feature = "live-audio")]
async fn dispatch_live_if_current<T, F, Fut>(
    scope: &crate::media::conversation_scope::CancelScope,
    token: &crate::media::conversation_scope::GenerationToken,
    dispatch: F,
) -> Option<T>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = T>,
{
    if scope.is_stale(token) {
        None
    } else {
        Some(dispatch().await)
    }
}

fn emit_live_terminal_error(output: OutputFormat, error: &anyhow::Error) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!(
            "{}",
            serde_json::json!({ "type": "live_dictation", "state": "error", "error": error.to_string() })
        ),
        OutputFormat::Table => eprintln!("[live dictation: error] {error:#}"),
    }
}

fn emit_live_event(output: OutputFormat, event: serde_json::Value) {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!("{event}"),
        OutputFormat::Table => match event.get("state").and_then(serde_json::Value::as_str) {
            Some("transcript") => println!(
                "{}",
                event
                    .get("text")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
            ),
            Some(state) => eprintln!("[live dictation: {state}]"),
            None => eprintln!("[live dictation]"),
        },
    }
}

fn open_dictate_audit(
    neoth_home: &std::path::Path,
) -> Option<(
    crate::wal::writer::WalWriterHandle,
    tokio::task::JoinHandle<()>,
)> {
    let wal_dir = neoth_home.join("wal");
    match (|| -> anyhow::Result<_> {
        std::fs::create_dir_all(&wal_dir)?;
        let segment = crate::wal::writer::unique_standalone_segment_path(&wal_dir, "dictate");
        Ok(crate::wal::writer::spawn_for_home(
            segment,
            neoth_home.to_path_buf(),
        )?)
    })() {
        Ok(pair) => Some(pair),
        Err(error) => {
            tracing::warn!(%error, "dictate: WAL audit writer unavailable");
            None
        }
    }
}

async fn close_dictate_audit(
    audit: Option<(
        crate::wal::writer::WalWriterHandle,
        tokio::task::JoinHandle<()>,
    )>,
) -> Result<()> {
    if let Some((writer, join)) = audit {
        drop(writer);
        join.await.context("dictate: WAL writer task panicked")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::{Args as _, FromArgMatches as _};
    #[cfg(feature = "live-audio")]
    use std::result::Result;
    #[cfg(feature = "live-audio")]
    use std::sync::Arc;
    #[cfg(feature = "live-audio")]
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[cfg(feature = "live-audio")]
    use std::time::Duration;

    use crate::config::features::MediaConfig;
    #[cfg(feature = "live-audio")]
    use crate::media::conversation_scope::CancelScope;
    use crate::media::dictation::{DictationError, transcribe_utterance};

    use super::DictateArgs;
    #[cfg(feature = "live-audio")]
    use super::{
        LiveCaptureRelay, LiveDictateOwnedTasks, MAX_PENDING_LIVE_UTTERANCES,
        dispatch_live_if_current, enqueue_live_utterance, relay_live_capture_event,
    };

    #[cfg(feature = "live-audio")]
    struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);

    #[cfg(feature = "live-audio")]
    impl Drop for DropSignal {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    #[tokio::test]
    async fn default_config_refuses_dictation() {
        let cfg = MediaConfig::default();
        let home = tempfile::tempdir().unwrap();
        let pcm = vec![0.0f32; 3200];
        let err = transcribe_utterance(
            &pcm,
            16_000,
            &cfg,
            &crate::config::UpdaterConfig::default(),
            home.path(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, DictationError::NotEnabled));
    }

    #[test]
    fn live_parser_requires_live_for_an_explicit_device_and_rejects_a_file() {
        let command = DictateArgs::augment_args(clap::Command::new("dictate"));
        let matches = command
            .clone()
            .try_get_matches_from(["dictate", "--live", "--input-device", "USB microphone"])
            .expect("live selector is a valid CLI invocation");
        let parsed = DictateArgs::from_arg_matches(&matches).expect("decode live dictate args");
        assert!(parsed.live);
        assert_eq!(parsed.input_device.as_deref(), Some("USB microphone"));
        assert!(parsed.file.is_none());
        assert!(
            command
                .clone()
                .try_get_matches_from(["dictate", "--input-device", "USB microphone"])
                .is_err()
        );
        assert!(
            command
                .try_get_matches_from(["dictate", "--live", "recording.wav"])
                .is_err()
        );
    }

    #[cfg(not(feature = "live-audio"))]
    #[tokio::test]
    async fn live_capture_unavailable_build_refuses_before_loading_configuration() {
        let error = super::run_dictate(DictateArgs {
            file: None,
            live: true,
            input_device: Some("unopened fixture device".into()),
            output: crate::cli::OutputFormat::Table,
        })
        .await
        .expect_err("server builds cannot open a microphone");
        assert!(error.to_string().contains("unavailable in this build"));
    }

    #[test]
    #[cfg(feature = "live-audio")]
    fn bounded_pending_utterances_keep_order_and_drop_the_newest_overflow() {
        let mut pending = std::collections::VecDeque::new();
        for sequence in 1..=MAX_PENDING_LIVE_UTTERANCES as u64 {
            assert!(enqueue_live_utterance(
                &mut pending,
                sequence,
                vec![sequence as f32]
            ));
        }
        assert!(!enqueue_live_utterance(&mut pending, 99, vec![99.0]));
        let retained: Vec<_> = pending.into_iter().map(|(sequence, _)| sequence).collect();
        assert_eq!(
            retained,
            (1..=MAX_PENDING_LIVE_UTTERANCES as u64).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    #[cfg(feature = "live-audio")]
    async fn stale_scope_never_calls_the_fake_stt_dispatcher() {
        let scope = CancelScope::new();
        let token = scope.snapshot().unwrap();
        scope.invalidate().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let fake_calls = Arc::clone(&calls);

        let result = dispatch_live_if_current(&scope, &token, move || async move {
            fake_calls.fetch_add(1, Ordering::SeqCst);
            "fake transcript"
        })
        .await;

        assert_eq!(result, None);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "stale work must not reach STT dispatch"
        );
    }

    #[tokio::test]
    #[cfg(feature = "live-audio")]
    async fn full_fake_capture_relay_surfaces_through_the_owned_worker_join() {
        let scope = CancelScope::new();
        let token = scope.snapshot().unwrap();
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        sender.try_send("first fake capture event").unwrap();
        let worker_scope = scope.clone();
        let worker = tokio::spawn(async move {
            match relay_live_capture_event(&sender, &worker_scope, "overflow fake capture event") {
                LiveCaptureRelay::Overloaded => anyhow::bail!("fake relay overload"),
                LiveCaptureRelay::Sent | LiveCaptureRelay::ReceiverClosed => Ok(()),
            }
        });
        let mut owned = LiveDictateOwnedTasks::new(scope.clone(), worker);

        let error = owned.join_capture().await.unwrap_err();

        assert!(error.to_string().contains("fake relay overload"));
        assert!(
            scope.is_stale(&token),
            "overflow must invalidate the capture scope"
        );
    }

    #[tokio::test]
    #[cfg(feature = "live-audio")]
    async fn draining_fake_stt_waits_for_its_fake_wal_sender_and_returns_stale_result() {
        let scope = CancelScope::new();
        let token = scope.snapshot().unwrap();
        let capture = tokio::spawn(async { Ok(()) });
        let mut owned = LiveDictateOwnedTasks::new(scope.clone(), capture);
        let (audit_sender, mut audit_receiver) = tokio::sync::mpsc::channel::<()>(1);
        let worker_sender = audit_sender.clone();
        drop(audit_sender);
        let (started_sender, started) = tokio::sync::oneshot::channel();
        let (release_sender, release) = tokio::sync::oneshot::channel();
        owned.transcription = Some(tokio::spawn(async move {
            let _held_fake_wal_sender = worker_sender;
            let _ = started_sender.send(());
            let _ = release.await;
            (7, Some(Ok("stale fake transcript".to_owned())))
        }));

        started.await.unwrap();
        assert!(
            owned.transcription.is_some(),
            "active STT handle remains owned while draining"
        );
        assert!(matches!(
            audit_receiver.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
        scope.invalidate().unwrap();

        let drained = {
            let drain = owned.drain_transcription();
            tokio::pin!(drain);
            assert!(futures_util::poll!(&mut drain).is_pending());
            release_sender.send(()).unwrap();
            drain.await.unwrap()
        };

        match drained {
            Some((7, Some(Ok(text)))) => assert_eq!(text, "stale fake transcript"),
            _ => panic!("foreground drain must return the completed fake STT result"),
        }
        assert!(
            scope.is_stale(&token),
            "the normal controller suppresses this drained stale transcript"
        );
        assert!(owned.transcription.is_none());
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(250), audit_receiver.recv())
                .await
                .unwrap(),
            None,
            "fake WAL sender closes only after foreground STT completion"
        );
    }

    #[tokio::test]
    #[cfg(feature = "live-audio")]
    async fn outer_future_drop_guard_aborts_an_active_task_and_signals_scope() {
        let scope = CancelScope::new();
        let token = scope.snapshot().unwrap();
        let capture = tokio::spawn(async { Ok(()) });
        let (drop_sender, drop_signal) = tokio::sync::oneshot::channel();
        let transcription = tokio::spawn(async move {
            let _signal = DropSignal(Some(drop_sender));
            std::future::pending::<(u64, Option<Result<String, DictationError>>)>().await
        });
        let owned = LiveDictateOwnedTasks {
            scope: scope.clone(),
            capture_worker: Some(capture),
            transcription: Some(transcription),
        };

        drop(owned);

        assert!(
            scope.is_stale(&token),
            "drop must signal the bounded capture relay"
        );
        tokio::time::timeout(Duration::from_millis(250), drop_signal)
            .await
            .expect("outer drop must abort its active foreground task")
            .expect("foreground task cleanup signal must be delivered");
    }
}
