//! Audio backend — R-9 Phase 2.
//!
//! Pure-Rust audio decode via `symphonia` (WAV / MP3 / FLAC / Ogg / M4A →
//! 16 kHz mono f32), then the canonical STT dispatcher. Provider selection,
//! model-download consent, cloud consent, audit, post-processing, and fallback
//! are enforced once in `media::stt_provider`; this extractor has no legacy
//! transcription bypass.
//!
//! Operator-visible behaviour:
//!   - WAV / MP3 / … bytes or path → decoded f32 samples + sample-rate
//!     metadata. Returned in `Extraction.metadata` as `sample_count` +
//!     `sample_rate` + `decoded_duration_secs`.
//!   - `text` carries the transcript from the effective configured provider.
//!
//! Limitations:
//!   - Single-channel mix-down — stereo inputs are averaged to mono.
//!   - Resampling uses the shared band-limited path in `media::resampler`.

use std::io::Read;
use std::mem::size_of;
use std::path::{Path, PathBuf};

use super::{Asset, AssetKind, Extraction, ExtractionError, MediaExtractor};

/// Whisper expects 16 kHz mono. We resample on decode so downstream
/// callers never have to think about it.
pub const TARGET_SAMPLE_RATE: u32 = 16_000;
const MAX_AUDIO_DURATION_SECS: u64 = 10 * 60;
const MAX_DECODED_MONO_SAMPLES: usize = 24 * 1024 * 1024;
const MAX_RESAMPLED_AUDIO_SAMPLES: usize =
    TARGET_SAMPLE_RATE as usize * MAX_AUDIO_DURATION_SECS as usize;
const MAX_AUDIO_PACKET_FRAMES: usize = 256 * 1024;
const MAX_AUDIO_PACKET_INTERLEAVED_SAMPLES: usize = 1024 * 1024;
const MAX_AUDIO_CHANNELS: usize = 16;
const AUDIO_WORKER_CONCURRENCY: usize = 1;
const AUDIO_WORKER_QUEUE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Upper bound for request-controlled audio payload buffers retained at once.
///
/// The decoder stage can retain the caller's borrowed encoded bytes, its one
/// owned snapshot, decoded mono PCM, target-rate PCM and one interleaved
/// packet. The canonical STT stage can temporarily retain the caller's bytes,
/// three target-rate f32 buffers and two PCM16 WAV buffers. Both conservative
/// bounds remain below 256 MiB with headroom for small decoder/resampler
/// scratch buffers. Model weights are process resources, not attacker-sized
/// request payloads.
pub(crate) const AUDIO_REQUEST_CONTROLLED_MEMORY_BUDGET_BYTES: usize = 256 * 1024 * 1024;
const MAX_AUDIO_DECODE_STAGE_BYTES: usize = MAX_AUDIO_BYTES as usize * 2
    + MAX_DECODED_MONO_SAMPLES * size_of::<f32>()
    + MAX_RESAMPLED_AUDIO_SAMPLES * size_of::<f32>()
    + MAX_AUDIO_PACKET_INTERLEAVED_SAMPLES * size_of::<f32>();
const MAX_AUDIO_STT_STAGE_BYTES: usize = MAX_AUDIO_BYTES as usize
    + MAX_RESAMPLED_AUDIO_SAMPLES * size_of::<f32>() * 3
    + MAX_RESAMPLED_AUDIO_SAMPLES * size_of::<i16>() * 2;
const _: () = assert!(
    MAX_AUDIO_DECODE_STAGE_BYTES <= AUDIO_REQUEST_CONTROLLED_MEMORY_BUDGET_BYTES
        && MAX_AUDIO_STT_STAGE_BYTES <= AUDIO_REQUEST_CONTROLLED_MEMORY_BUDGET_BYTES
);

static AUDIO_WORKER_BUDGET: tokio::sync::Semaphore =
    tokio::sync::Semaphore::const_new(AUDIO_WORKER_CONCURRENCY);

/// Unforgeable proof that this request owns the process-wide audio memory
/// budget. The field is private; callers can only obtain a token by awaiting
/// [`acquire_audio_work_permit`].
struct AudioWorkLease {
    _permit: tokio::sync::SemaphorePermit<'static>,
}

#[derive(Clone)]
pub(crate) struct AudioWorkPermit {
    _lease: std::sync::Arc<AudioWorkLease>,
}

pub(crate) async fn acquire_audio_work_permit() -> Result<AudioWorkPermit, ExtractionError> {
    let permit = tokio::time::timeout(AUDIO_WORKER_QUEUE_TIMEOUT, AUDIO_WORKER_BUDGET.acquire())
        .await
        .map_err(|_| ExtractionError::Backend {
            backend: "audio",
            reason: "global audio worker queue exceeded its 120-second deadline".into(),
        })?
        .map_err(|_| ExtractionError::Backend {
            backend: "audio",
            reason: "global audio worker budget is closed".into(),
        })?;
    Ok(AudioWorkPermit {
        _lease: std::sync::Arc::new(AudioWorkLease { _permit: permit }),
    })
}

/// Close the process-wide budget after a subprocess cleanup failure. Once a
/// child can no longer be proven dead, admitting another audio request would
/// violate the single-request memory/process contract.
pub(crate) fn close_audio_work_budget() {
    AUDIO_WORKER_BUDGET.close();
}

#[derive(Clone, Copy)]
struct AudioDecodeLimits {
    duration_secs: u64,
    decoded_frames: usize,
    packet_frames: usize,
    packet_interleaved_samples: usize,
    channels: usize,
}

const AUDIO_DECODE_LIMITS: AudioDecodeLimits = AudioDecodeLimits {
    duration_secs: MAX_AUDIO_DURATION_SECS,
    decoded_frames: MAX_DECODED_MONO_SAMPLES,
    packet_frames: MAX_AUDIO_PACKET_FRAMES,
    packet_interleaved_samples: MAX_AUDIO_PACKET_INTERLEAVED_SAMPLES,
    channels: MAX_AUDIO_CHANNELS,
};

pub struct AudioExtractor;

impl AudioExtractor {
    /// Extract audio with the caller's effective runtime policy and optional
    /// WAL sink. Daemon callers must use this seam so reload state, model-
    /// download consent, and cloud audit cannot drift from the active config.
    pub(crate) async fn extract_with_context(
        &self,
        asset: &Asset,
        media_cfg: &crate::config::MediaConfig,
        updater_cfg: &crate::config::UpdaterConfig,
        neoth_home: &std::path::Path,
        wal_writer: Option<crate::wal::writer::WalWriterHandle>,
    ) -> Result<Extraction, ExtractionError> {
        if asset.kind() != AssetKind::Audio {
            return Err(ExtractionError::Unsupported {
                backend: "audio",
                got: asset.kind(),
            });
        }
        // Serialize the complete request-controlled audio lifetime, including
        // STT re-encoding/dispatch. The permit is acquired before a borrowed
        // byte payload is copied or a path is opened/statted, so concurrent
        // channel/GUI requests cannot fan out the bounded per-request memory.
        let permit = acquire_audio_work_permit().await?;
        // The extractor trait borrows `Asset`, while `spawn_blocking` requires
        // owned `'static` data. Validate an in-memory payload before making the
        // one ownership copy needed to cross that boundary. The blocking
        // decoder then consumes those bytes directly instead of cloning them a
        // second time.
        let payload = own_audio_input(asset)?;
        let media_cfg = media_cfg.clone();
        let updater_cfg = updater_cfg.clone();
        let neoth_home = neoth_home.to_path_buf();
        tokio::task::spawn_blocking(move || {
            extract_blocking_with_context(
                payload,
                &media_cfg,
                &updater_cfg,
                &neoth_home,
                wal_writer.as_ref(),
                permit,
            )
        })
        .await
        .map_err(|e| ExtractionError::Backend {
            backend: "audio",
            reason: format!("join error: {e}"),
        })?
    }
}

#[async_trait::async_trait]
impl MediaExtractor for AudioExtractor {
    fn name(&self) -> &'static str {
        "audio"
    }
    async fn extract(&self, asset: &Asset) -> Result<Extraction, ExtractionError> {
        if asset.kind() != AssetKind::Audio {
            return Err(ExtractionError::Unsupported {
                backend: "audio",
                got: asset.kind(),
            });
        }
        let config = crate::config::FreedomConfig::load_from_default_path().map_err(|error| {
            ExtractionError::Backend {
                backend: "audio",
                reason: format!("load effective STT config: {error}"),
            }
        })?;
        self.extract_with_context(
            asset,
            &config.media,
            &config.updater,
            &crate::config::FreedomConfig::default_neoth_home(),
            None,
        )
        .await
    }
}

#[derive(Debug)]
enum OwnedAudioInput {
    Bytes { data: Vec<u8>, mime: String },
    Path(PathBuf),
}

fn own_audio_input(asset: &Asset) -> Result<OwnedAudioInput, ExtractionError> {
    own_audio_input_with_limit(asset, MAX_AUDIO_BYTES)
}

fn own_audio_input_with_limit(
    asset: &Asset,
    max_bytes: u64,
) -> Result<OwnedAudioInput, ExtractionError> {
    match asset {
        Asset::Bytes { data, mime, .. } => {
            enforce_audio_byte_ceiling_with_limit(data.len() as u64, max_bytes)?;
            let mut owned = Vec::new();
            owned
                .try_reserve_exact(data.len())
                .map_err(|error| audio_allocation_error("reserve owned encoded input", error))?;
            owned.extend_from_slice(data);
            Ok(OwnedAudioInput::Bytes {
                data: owned,
                mime: mime.clone(),
            })
        }
        Asset::Path { path, .. } => Ok(OwnedAudioInput::Path(path.clone())),
    }
}

fn extract_blocking_with_context(
    input: OwnedAudioInput,
    media_cfg: &crate::config::MediaConfig,
    updater_cfg: &crate::config::UpdaterConfig,
    neoth_home: &std::path::Path,
    wal_writer: Option<&crate::wal::writer::WalWriterHandle>,
    permit: AudioWorkPermit,
) -> Result<Extraction, ExtractionError> {
    let DecodedAudio {
        samples,
        original_sample_rate,
    } = match input {
        OwnedAudioInput::Bytes { data, mime } => decode_from_bytes(data, &mime)?,
        OwnedAudioInput::Path(path) => decode_from_path(&path)?,
    };
    let duration_secs = samples.len() as f64 / TARGET_SAMPLE_RATE as f64;

    // B20: dispatch_pcm_f32 is the single production entry for ALL PCM
    // transcription — local and cloud alike. Cloud gating (cloud_stt_enabled,
    // audit sink) is enforced inside the dispatcher; we no longer gate on
    // needs_cloud here. Local engine construction is async and keyed by the
    // explicit NEOTH home, repository, and idle timeout inside the dispatcher;
    // there is no process-global legacy engine or nested mini-runtime.
    //
    // The provider is stamped by
    // dispatch_transcription (B20 review fix: metadata must name the backend
    // that ACTUALLY handled the bytes, never a hardcoded repo).
    let handle =
        tokio::runtime::Handle::try_current().map_err(|error| ExtractionError::Backend {
            backend: "audio",
            reason: format!("no Tokio runtime for canonical STT dispatch: {error}"),
        })?;
    let result = handle
        .block_on(
            crate::media::stt_provider::dispatch_pcm_f32_with_audio_permit(
                &media_cfg.stt,
                media_cfg,
                updater_cfg,
                neoth_home,
                &samples,
                TARGET_SAMPLE_RATE,
                wal_writer,
                &permit,
            ),
        )
        .map_err(|error| ExtractionError::Backend {
            backend: "audio",
            reason: format!("STT dispatch: {error}"),
        })?;
    let status = if result.text.is_empty() {
        "empty transcript"
    } else {
        "transcribed"
    };
    let text = result.text;
    let segments = result.segments;
    let speaker_labels = result.speaker_labels;
    let provider = result.provider;
    // Truthful model detail per effective provider: the candle engine is pinned
    // to the configured size-specific repo; faster-whisper uses the matching
    // SYSTRAN repo; cloud kinds are identified by the provider id itself.
    let model_detail = transcription_model_detail(&provider, media_cfg.stt.model_size);
    Ok(Extraction {
        text,
        metadata: serde_json::json!({
            "extractor": "audio",
            "sample_count": samples.len(),
            "sample_rate": TARGET_SAMPLE_RATE,
            "original_sample_rate": original_sample_rate,
            "duration_secs": duration_secs,
            "transcription_status": status,
            "transcription_provider": provider,
            "transcription_model": model_detail,
            "transcription_segments": segments,
            "speaker_labels": speaker_labels,
        }),
    })
}

fn transcription_model_detail(
    provider: &str,
    model_size: crate::media::stt_dispatch::WhisperModelSize,
) -> String {
    use crate::media::stt_dispatch::SttProvider;

    if provider == SttProvider::WhisperRsLocal.as_str() {
        crate::media::stt_provider::candle_whisper_model_id(model_size).to_string()
    } else if provider == SttProvider::FasterWhisperLocal.as_str() {
        crate::media::stt_provider::faster_whisper_model_id(model_size).to_string()
    } else if provider.is_empty() || provider == "none" {
        String::from("none")
    } else {
        provider.to_string()
    }
}

/// GOLD-ADOPT-25 — decode an audio file to 16 kHz mono f32 for the
/// `neoth dictate` CLI. Thin seam over the private symphonia decoder so
/// the dictation path reuses the ingest decode (including the 32 MiB cap
/// and WAV/MP3/FLAC/Ogg/M4A support). Blocking — call from
/// `spawn_blocking`.
pub(crate) fn decode_file_to_pcm(
    path: &Path,
    _permit: &AudioWorkPermit,
) -> anyhow::Result<Vec<f32>> {
    decode_from_path(path)
        .map(|d| d.samples)
        .map_err(|e| anyhow::anyhow!("decode {}: {e}", path.display()))
}

struct DecodedAudio {
    /// 16 kHz mono f32 samples, range [-1.0, 1.0].
    samples: Vec<f32>,
    original_sample_rate: u32,
}

/// Hard cap on audio file size read into memory. A multi-GB file (e.g. a
/// hostile or accidental email attachment) would otherwise OOM the daemon:
/// encoded bytes remain resident while the decoder materializes bounded PCM.
pub(crate) const MAX_AUDIO_BYTES: u64 = 32 * 1024 * 1024;

fn decode_from_path(path: &Path) -> Result<DecodedAudio, ExtractionError> {
    // Size-gate before reading the whole file into memory.
    let file = std::fs::File::open(path)
        .map_err(|e| ExtractionError::Io(format!("open {}: {e}", path.display())))?;
    let len = file
        .metadata()
        .map_err(|e| ExtractionError::Io(format!("stat {}: {e}", path.display())))?
        .len();
    enforce_audio_byte_ceiling(len)?;
    let capacity = usize::try_from(len).map_err(|_| ExtractionError::Backend {
        backend: "audio",
        reason: "audio input size does not fit this platform".into(),
    })?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|error| audio_allocation_error("reserve encoded file input", error))?;
    let mut bounded = file.take(MAX_AUDIO_BYTES + 1);
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let read = bounded
            .read(&mut chunk)
            .map_err(|e| ExtractionError::Io(format!("read {}: {e}", path.display())))?;
        if read == 0 {
            break;
        }
        let projected = bytes
            .len()
            .checked_add(read)
            .ok_or_else(|| ExtractionError::Backend {
                backend: "audio",
                reason: "encoded file input length overflow".into(),
            })?;
        enforce_audio_byte_ceiling(projected as u64)?;
        if projected > bytes.capacity() {
            let max_capacity =
                usize::try_from(MAX_AUDIO_BYTES).map_err(|_| ExtractionError::Backend {
                    backend: "audio",
                    reason: "audio input cap does not fit this platform".into(),
                })?;
            bytes
                .try_reserve_exact(max_capacity.saturating_sub(bytes.len()))
                .map_err(|error| audio_allocation_error("grow encoded file input", error))?;
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    enforce_audio_byte_ceiling(bytes.len() as u64)?;
    // Symphonia probes the format from the bytes; the MIME hint is just a
    // search hint, not required.
    let mime = mime_hint_from_path(path);
    decode_from_bytes(bytes, &mime)
}

fn enforce_audio_byte_ceiling(len: u64) -> Result<(), ExtractionError> {
    enforce_audio_byte_ceiling_with_limit(len, MAX_AUDIO_BYTES)
}

fn enforce_audio_byte_ceiling_with_limit(len: u64, max_bytes: u64) -> Result<(), ExtractionError> {
    if len > max_bytes {
        return Err(ExtractionError::Backend {
            backend: "audio",
            reason: format!("input {len} bytes exceeds {max_bytes}-byte cap"),
        });
    }
    Ok(())
}

fn audio_allocation_error(
    stage: &'static str,
    error: std::collections::TryReserveError,
) -> ExtractionError {
    ExtractionError::Backend {
        backend: "audio",
        reason: format!("{stage}: {error}"),
    }
}

fn mime_hint_from_path(path: &Path) -> String {
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
    match ext.to_ascii_lowercase().as_str() {
        "wav" => "audio/wav".into(),
        "mp3" => "audio/mpeg".into(),
        "flac" => "audio/flac".into(),
        "ogg" | "oga" => "audio/ogg".into(),
        "m4a" | "mp4" | "aac" => "audio/mp4".into(),
        _ => String::new(),
    }
}

fn decode_from_bytes(bytes: Vec<u8>, mime: &str) -> Result<DecodedAudio, ExtractionError> {
    use std::io::Cursor;
    use symphonia::core::audio::SampleBuffer;
    use symphonia::core::codecs::DecoderOptions;
    use symphonia::core::errors::Error as SymError;
    use symphonia::core::formats::FormatOptions;
    use symphonia::core::io::MediaSourceStream;
    use symphonia::core::meta::MetadataOptions;
    use symphonia::core::probe::Hint;

    enforce_audio_byte_ceiling(bytes.len() as u64)?;
    let cursor = Cursor::new(bytes);
    let mss = MediaSourceStream::new(Box::new(cursor), Default::default());
    let mut hint = Hint::new();
    if !mime.is_empty() {
        hint.mime_type(mime);
    }
    let probed = symphonia::default::get_probe()
        .format(
            &hint,
            mss,
            &FormatOptions::default(),
            &MetadataOptions::default(),
        )
        .map_err(|e| ExtractionError::Backend {
            backend: "audio",
            reason: format!("probe: {e}"),
        })?;
    let mut format = probed.format;
    let track = format
        .default_track()
        .ok_or_else(|| ExtractionError::Backend {
            backend: "audio",
            reason: "no default track in container".into(),
        })?;
    let track_id = track.id;
    let codec_params = track.codec_params.clone();
    // A missing/zero sample rate must NOT silently fall through to "skip
    // resampling" — that would hand Whisper raw audio at whatever rate the
    // codec actually decoded (8 kHz, 48 kHz, …) while claiming 16 kHz, yielding
    // a garbage transcript stored as if correct. Fail fast like the
    // no-default-track guard above.
    let original_sr = match codec_params.sample_rate {
        Some(sr) if sr > 0 => sr,
        _ => {
            return Err(ExtractionError::Backend {
                backend: "audio",
                reason: "codec reported no/zero sample rate; cannot resample to 16 kHz".into(),
            });
        }
    };
    validate_audio_sample_rate(original_sr)?;
    if let Some(channels) = codec_params.channels.map(|value| value.count())
        && channels > AUDIO_DECODE_LIMITS.channels
    {
        return Err(ExtractionError::Backend {
            backend: "audio",
            reason: format!(
                "codec declares {channels} channels, exceeding the {}-channel cap",
                AUDIO_DECODE_LIMITS.channels
            ),
        });
    }
    if let Some(n_frames) = codec_params.n_frames {
        let declared_frames = usize::try_from(n_frames).map_err(|_| ExtractionError::Backend {
            backend: "audio",
            reason: "declared audio frame count does not fit this platform".into(),
        })?;
        enforce_total_audio_frames(declared_frames, original_sr, AUDIO_DECODE_LIMITS)?;
    }

    let mut decoder = symphonia::default::get_codecs()
        .make(&codec_params, &DecoderOptions::default())
        .map_err(|e| ExtractionError::Backend {
            backend: "audio",
            reason: format!("codec: {e}"),
        })?;

    let mut decoded_mono: Vec<f32> = Vec::new();
    loop {
        let packet = match format.next_packet() {
            Ok(p) => p,
            Err(SymError::IoError(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(SymError::ResetRequired) => break,
            Err(e) => {
                return Err(ExtractionError::Backend {
                    backend: "audio",
                    reason: format!("packet: {e}"),
                });
            }
        };
        if packet.track_id() != track_id {
            continue;
        }
        match decoder.decode(&packet) {
            Ok(audio) => {
                let spec = *audio.spec();
                let channels = spec.channels.count();
                let frame_count = audio.frames();
                admit_audio_packet(
                    decoded_mono.len(),
                    frame_count,
                    audio.capacity(),
                    channels,
                    original_sr,
                    AUDIO_DECODE_LIMITS,
                )?;
                reserve_decoded_pcm_growth(
                    &mut decoded_mono,
                    frame_count,
                    original_sr,
                    AUDIO_DECODE_LIMITS,
                )?;

                let mut sample_buffer = SampleBuffer::<f32>::new(audio.capacity() as u64, spec);
                sample_buffer.copy_interleaved_ref(audio);
                let samples = sample_buffer.samples();
                for frame in samples.chunks_exact(channels) {
                    let mixed = frame.iter().copied().sum::<f32>() / channels as f32;
                    if !mixed.is_finite() {
                        return Err(ExtractionError::Backend {
                            backend: "audio",
                            reason: "decoded PCM contains a non-finite sample".into(),
                        });
                    }
                    decoded_mono.push(mixed);
                }
            }
            Err(SymError::DecodeError(_)) => continue,
            Err(SymError::IoError(_)) => break,
            Err(e) => {
                return Err(ExtractionError::Backend {
                    backend: "audio",
                    reason: format!("decode: {e}"),
                });
            }
        }
    }

    let predicted_target_samples =
        predicted_resampled_samples(decoded_mono.len(), original_sr, TARGET_SAMPLE_RATE)?;
    if predicted_target_samples > MAX_RESAMPLED_AUDIO_SAMPLES {
        return Err(ExtractionError::Backend {
            backend: "audio",
            reason: format!(
                "resampled audio would contain {predicted_target_samples} samples, exceeding the {MAX_RESAMPLED_AUDIO_SAMPLES}-sample cap"
            ),
        });
    }
    let resampled = if original_sr == TARGET_SAMPLE_RATE {
        decoded_mono
    } else {
        // HANDY-01 — band-limited sinc (rubato), linear fallback inside.
        super::resampler::resample_mono(&decoded_mono, original_sr, TARGET_SAMPLE_RATE).map_err(
            |error| ExtractionError::Backend {
                backend: "audio",
                reason: format!("resample: {error}"),
            },
        )?
    };
    if resampled.len() > MAX_RESAMPLED_AUDIO_SAMPLES {
        return Err(ExtractionError::Backend {
            backend: "audio",
            reason: format!(
                "resampled audio contains {} samples, exceeding the {MAX_RESAMPLED_AUDIO_SAMPLES}-sample cap",
                resampled.len()
            ),
        });
    }

    Ok(DecodedAudio {
        samples: resampled,
        original_sample_rate: original_sr,
    })
}

fn validate_audio_sample_rate(sample_rate: u32) -> Result<(), ExtractionError> {
    if !(super::resampler::MIN_SAMPLE_RATE_HZ..=super::resampler::MAX_SAMPLE_RATE_HZ)
        .contains(&sample_rate)
    {
        return Err(ExtractionError::Backend {
            backend: "audio",
            reason: format!(
                "sample rate {sample_rate} Hz is outside the supported {}..={} Hz range",
                super::resampler::MIN_SAMPLE_RATE_HZ,
                super::resampler::MAX_SAMPLE_RATE_HZ
            ),
        });
    }
    Ok(())
}

fn max_audio_frames(sample_rate: u32, limits: AudioDecodeLimits) -> Result<usize, ExtractionError> {
    let duration_frames = u64::from(sample_rate)
        .checked_mul(limits.duration_secs)
        .ok_or_else(|| ExtractionError::Backend {
            backend: "audio",
            reason: "audio duration frame budget overflow".into(),
        })?;
    let duration_frames =
        usize::try_from(duration_frames).map_err(|_| ExtractionError::Backend {
            backend: "audio",
            reason: "audio duration frame budget does not fit this platform".into(),
        })?;
    Ok(duration_frames.min(limits.decoded_frames))
}

fn enforce_total_audio_frames(
    frames: usize,
    sample_rate: u32,
    limits: AudioDecodeLimits,
) -> Result<(), ExtractionError> {
    let max_frames = max_audio_frames(sample_rate, limits)?;
    if frames > max_frames {
        return Err(ExtractionError::Backend {
            backend: "audio",
            reason: format!(
                "decoded audio would contain {frames} frames, exceeding the {max_frames}-frame / {}-second cap",
                limits.duration_secs
            ),
        });
    }
    Ok(())
}

fn reserve_decoded_pcm_growth(
    decoded: &mut Vec<f32>,
    additional_frames: usize,
    sample_rate: u32,
    limits: AudioDecodeLimits,
) -> Result<(), ExtractionError> {
    let required = decoded
        .len()
        .checked_add(additional_frames)
        .ok_or_else(|| ExtractionError::Backend {
            backend: "audio",
            reason: "decoded PCM capacity overflow".into(),
        })?;
    let hard_limit = max_audio_frames(sample_rate, limits)?;
    if required > hard_limit {
        return Err(ExtractionError::Backend {
            backend: "audio",
            reason: format!(
                "decoded PCM reserve would contain {required} frames, exceeding the {hard_limit}-frame cap"
            ),
        });
    }
    if required <= decoded.capacity() {
        return Ok(());
    }

    // Fallible geometric growth avoids one realloc-and-copy per tiny codec
    // packet while the hard frame ceiling prevents over-admission.
    const MIN_GROWTH_FRAMES: usize = 64 * 1024;
    let geometric = decoded.capacity().max(MIN_GROWTH_FRAMES).saturating_mul(2);
    let target_capacity = required.max(geometric).min(hard_limit);
    decoded
        .try_reserve_exact(target_capacity.saturating_sub(decoded.len()))
        .map_err(|error| audio_allocation_error("grow decoded PCM", error))
}

fn admit_audio_packet(
    decoded_frames: usize,
    packet_frames: usize,
    packet_capacity: usize,
    channels: usize,
    sample_rate: u32,
    limits: AudioDecodeLimits,
) -> Result<(), ExtractionError> {
    if channels == 0 || channels > limits.channels {
        return Err(ExtractionError::Backend {
            backend: "audio",
            reason: format!(
                "decoded packet has {channels} channels; expected 1..={}",
                limits.channels
            ),
        });
    }
    if packet_frames > packet_capacity || packet_capacity > limits.packet_frames {
        return Err(ExtractionError::Backend {
            backend: "audio",
            reason: format!(
                "decoded packet has {packet_frames} frames / {packet_capacity} frame capacity, exceeding the {}-frame packet cap",
                limits.packet_frames
            ),
        });
    }
    let packet_samples =
        packet_capacity
            .checked_mul(channels)
            .ok_or_else(|| ExtractionError::Backend {
                backend: "audio",
                reason: "decoded packet sample-count overflow".into(),
            })?;
    if packet_samples > limits.packet_interleaved_samples {
        return Err(ExtractionError::Backend {
            backend: "audio",
            reason: format!(
                "decoded packet needs {packet_samples} interleaved samples, exceeding the {}-sample packet cap",
                limits.packet_interleaved_samples
            ),
        });
    }
    let projected =
        decoded_frames
            .checked_add(packet_frames)
            .ok_or_else(|| ExtractionError::Backend {
                backend: "audio",
                reason: "decoded audio frame-count overflow".into(),
            })?;
    enforce_total_audio_frames(projected, sample_rate, limits)
}

fn predicted_resampled_samples(
    source_samples: usize,
    source_rate: u32,
    target_rate: u32,
) -> Result<usize, ExtractionError> {
    if source_rate == 0 || target_rate == 0 {
        return Err(ExtractionError::Backend {
            backend: "audio",
            reason: "cannot predict resampled length for a zero sample rate".into(),
        });
    }
    let numerator = (source_samples as u128)
        .checked_mul(u128::from(target_rate))
        .and_then(|value| value.checked_add(u128::from(source_rate) - 1))
        .ok_or_else(|| ExtractionError::Backend {
            backend: "audio",
            reason: "resampled sample-count overflow".into(),
        })?;
    usize::try_from(numerator / u128::from(source_rate)).map_err(|_| ExtractionError::Backend {
        backend: "audio",
        reason: "resampled sample count does not fit this platform".into(),
    })
}

/// Linear resampler — now the graceful fallback for the rubato sinc path in
/// `media::resampler` (used only when rubato rejects a degenerate ratio).
/// `pub(crate)` so the resampler module can reach it.
pub(crate) fn linear_resample(
    input: &[f32],
    src_sr: u32,
    dst_sr: u32,
) -> Result<Vec<f32>, super::resampler::ResampleError> {
    if input.is_empty() || src_sr == 0 || dst_sr == 0 {
        return Ok(Vec::new());
    }
    if src_sr == dst_sr {
        let mut cloned = Vec::new();
        cloned.try_reserve_exact(input.len()).map_err(|error| {
            super::resampler::ResampleError::Allocation {
                stage: "linear identity output",
                reason: error.to_string(),
            }
        })?;
        cloned.extend_from_slice(input);
        return Ok(cloned);
    }
    let ratio = src_sr as f64 / dst_sr as f64;
    let out_len = ((input.len() as f64) / ratio).floor() as usize;
    let mut out = Vec::new();
    out.try_reserve_exact(out_len).map_err(|error| {
        super::resampler::ResampleError::Allocation {
            stage: "linear resample output",
            reason: error.to_string(),
        }
    })?;
    for i in 0..out_len {
        let src_pos = i as f64 * ratio;
        let lo = src_pos.floor() as usize;
        let hi = (lo + 1).min(input.len() - 1);
        let frac = (src_pos - lo as f64) as f32;
        out.push(input[lo] + (input[hi] - input[lo]) * frac);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a tiny WAV file in memory — 1 second of 1 kHz tone at 16 kHz,
    /// mono PCM 16-bit. Lets us exercise the decode path without shipping
    /// a binary fixture.
    fn synth_wav_tone() -> Vec<u8> {
        let sample_rate: u32 = 16_000;
        let secs = 1u32;
        let num_samples = sample_rate * secs;
        let bits_per_sample: u16 = 16;
        let channels: u16 = 1;
        let byte_rate = sample_rate * channels as u32 * (bits_per_sample / 8) as u32;
        let block_align = channels * (bits_per_sample / 8);
        let data_bytes = num_samples * channels as u32 * (bits_per_sample / 8) as u32;
        let chunk_size = 36 + data_bytes;

        let mut buf = Vec::with_capacity(44 + data_bytes as usize);
        buf.extend_from_slice(b"RIFF");
        buf.extend_from_slice(&chunk_size.to_le_bytes());
        buf.extend_from_slice(b"WAVE");
        buf.extend_from_slice(b"fmt ");
        buf.extend_from_slice(&16u32.to_le_bytes());
        buf.extend_from_slice(&1u16.to_le_bytes()); // PCM
        buf.extend_from_slice(&channels.to_le_bytes());
        buf.extend_from_slice(&sample_rate.to_le_bytes());
        buf.extend_from_slice(&byte_rate.to_le_bytes());
        buf.extend_from_slice(&block_align.to_le_bytes());
        buf.extend_from_slice(&bits_per_sample.to_le_bytes());
        buf.extend_from_slice(b"data");
        buf.extend_from_slice(&data_bytes.to_le_bytes());
        let freq = 1000.0_f32;
        for n in 0..num_samples {
            let t = n as f32 / sample_rate as f32;
            let v = (2.0 * std::f32::consts::PI * freq * t).sin();
            let sample = (v * i16::MAX as f32) as i16;
            buf.extend_from_slice(&sample.to_le_bytes());
        }
        buf
    }

    #[tokio::test]
    async fn extract_returns_unsupported_for_non_audio() {
        let extractor = AudioExtractor;
        let home = tempfile::tempdir().unwrap();
        let asset = Asset::Bytes {
            kind: AssetKind::Image,
            mime: "image/png".into(),
            data: vec![0x89, b'P', b'N', b'G'],
        };
        let err = extractor
            .extract_with_context(
                &asset,
                &crate::config::MediaConfig::default(),
                &crate::config::UpdaterConfig::default(),
                home.path(),
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ExtractionError::Unsupported {
                backend: "audio",
                ..
            }
        ));
    }

    #[test]
    fn decode_wav_tone_to_16k_mono() {
        let out = decode_from_bytes(synth_wav_tone(), "audio/wav").expect("decode wav");
        assert_eq!(out.original_sample_rate, TARGET_SAMPLE_RATE);
        let count = out.samples.len() as u64;
        // 1s at 16 kHz mono → ~16000 samples (allow ±100 from decoder
        // framing).
        assert!(
            (15_900..=16_100).contains(&count),
            "expected ~16000 samples, got {count}"
        );
    }

    #[test]
    fn in_memory_audio_uses_the_same_byte_ceiling_as_files() {
        assert!(enforce_audio_byte_ceiling(MAX_AUDIO_BYTES).is_ok());
        let error = enforce_audio_byte_ceiling(MAX_AUDIO_BYTES + 1).unwrap_err();
        assert!(error.to_string().contains("exceeds"));
    }

    #[test]
    fn request_controlled_audio_buffers_fit_the_documented_budget() {
        assert_eq!(MAX_AUDIO_BYTES, 32 * 1024 * 1024);
        assert_eq!(MAX_AUDIO_DURATION_SECS, 10 * 60);
        const {
            assert!(MAX_AUDIO_DECODE_STAGE_BYTES <= AUDIO_REQUEST_CONTROLLED_MEMORY_BUDGET_BYTES);
            assert!(MAX_AUDIO_STT_STAGE_BYTES <= AUDIO_REQUEST_CONTROLLED_MEMORY_BUDGET_BYTES);
        }
    }

    #[test]
    fn borrowed_audio_bytes_are_rejected_before_the_single_ownership_copy() {
        let asset = Asset::Bytes {
            kind: AssetKind::Audio,
            mime: "audio/wav".into(),
            data: vec![1, 2, 3, 4],
        };
        assert!(own_audio_input_with_limit(&asset, 3).is_err());

        let owned = own_audio_input_with_limit(&asset, 4).expect("bounded input");
        match owned {
            OwnedAudioInput::Bytes { data, mime } => {
                assert_eq!(data, [1, 2, 3, 4]);
                assert_eq!(mime, "audio/wav");
            }
            OwnedAudioInput::Path(_) => panic!("bytes must remain bytes"),
        }
    }

    #[test]
    fn decoded_audio_duration_and_sample_budgets_fail_during_decode() {
        let limits = AudioDecodeLimits {
            duration_secs: 2,
            decoded_frames: 100,
            packet_frames: 10,
            packet_interleaved_samples: 20,
            channels: 4,
        };
        assert!(admit_audio_packet(15, 5, 5, 2, 10, limits).is_ok());

        let duration = admit_audio_packet(18, 3, 3, 1, 10, limits).unwrap_err();
        assert!(
            matches!(
                duration,
                ExtractionError::Backend {
                    backend: "audio",
                    ref reason
                } if reason.contains("second cap")
            ),
            "{duration:?}"
        );

        let sample_cap = enforce_total_audio_frames(
            101,
            1_000,
            AudioDecodeLimits {
                duration_secs: 10,
                ..limits
            },
        )
        .unwrap_err();
        assert!(sample_cap.to_string().contains("100-frame"));
    }

    #[test]
    fn hostile_audio_packet_shape_is_rejected_before_copy() {
        let limits = AudioDecodeLimits {
            duration_secs: 10,
            decoded_frames: 1_000,
            packet_frames: 8,
            packet_interleaved_samples: 12,
            channels: 4,
        };
        assert!(admit_audio_packet(0, 8, 9, 1, 1_000, limits).is_err());
        assert!(admit_audio_packet(0, 4, 4, 4, 1_000, limits).is_err());
        assert!(admit_audio_packet(0, 1, 1, 5, 1_000, limits).is_err());
        assert!(admit_audio_packet(usize::MAX, 1, 1, 1, 1_000, limits).is_err());
    }

    #[test]
    fn tiny_packets_use_bounded_geometric_pcm_growth() {
        let limits = AudioDecodeLimits {
            duration_secs: 10,
            decoded_frames: 100_000,
            packet_frames: 8,
            packet_interleaved_samples: 8,
            channels: 1,
        };
        let mut decoded = Vec::new();
        reserve_decoded_pcm_growth(&mut decoded, 1, 1_000, limits).unwrap();
        let first_capacity = decoded.capacity();
        assert!(first_capacity >= 1);
        for _ in 0..1_000 {
            reserve_decoded_pcm_growth(&mut decoded, 1, 1_000, limits).unwrap();
            decoded.push(0.0);
        }
        assert!(
            decoded.capacity() <= max_audio_frames(1_000, limits).unwrap(),
            "geometric growth must remain below the hard PCM cap"
        );
        assert!(
            decoded.capacity() >= first_capacity,
            "capacity cannot shrink during packet admission"
        );
    }

    #[test]
    fn resampled_length_prediction_is_ceil_bounded() {
        assert_eq!(predicted_resampled_samples(1, 48_000, 16_000).unwrap(), 1);
        assert_eq!(
            predicted_resampled_samples(48_000, 48_000, 16_000).unwrap(),
            16_000
        );
        assert!(predicted_resampled_samples(1, 0, 16_000).is_err());
    }

    #[test]
    fn absurd_audio_sample_rates_are_rejected_before_resampling() {
        assert!(validate_audio_sample_rate(super::super::resampler::MIN_SAMPLE_RATE_HZ).is_ok());
        assert!(
            validate_audio_sample_rate(super::super::resampler::MIN_SAMPLE_RATE_HZ - 1).is_err()
        );
    }

    #[test]
    fn linear_resample_upsample_doubles_length() {
        let input: Vec<f32> = (0..100).map(|i| i as f32).collect();
        let out = linear_resample(&input, 8000, 16000).unwrap();
        // Doubling sample rate → output is roughly 2× source. Linear
        // interpolation may differ by ±1 frame from the exact 2x.
        assert!(out.len() >= 199 && out.len() <= 200, "got {}", out.len());
    }

    #[test]
    fn linear_resample_downsample_halves_length() {
        let input: Vec<f32> = (0..200).map(|i| i as f32).collect();
        let out = linear_resample(&input, 16000, 8000).unwrap();
        assert!(out.len() >= 99 && out.len() <= 100, "got {}", out.len());
    }

    #[test]
    fn linear_resample_identity_returns_clone() {
        let input = vec![1.0f32, 2.0, 3.0];
        let out = linear_resample(&input, 16000, 16000).unwrap();
        assert_eq!(out, input);
    }

    #[test]
    fn mime_hint_from_path_known_extensions() {
        assert_eq!(mime_hint_from_path(Path::new("x.mp3")), "audio/mpeg");
        assert_eq!(mime_hint_from_path(Path::new("x.WAV")), "audio/wav");
        assert_eq!(mime_hint_from_path(Path::new("x.flac")), "audio/flac");
        assert_eq!(mime_hint_from_path(Path::new("x.unknown")), "");
    }

    #[test]
    fn candle_provider_metadata_uses_the_effective_model_repo() {
        use crate::media::stt_dispatch::{SttProvider, WhisperModelSize};

        let detail = transcription_model_detail(
            SttProvider::WhisperRsLocal.as_str(),
            WhisperModelSize::Small,
        );
        assert_eq!(
            detail,
            crate::media::stt_provider::candle_whisper_model_id(WhisperModelSize::Small)
        );
        assert_ne!(detail, SttProvider::WhisperRsLocal.as_str());
    }
}
