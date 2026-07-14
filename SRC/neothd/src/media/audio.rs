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

use std::path::Path;

use super::{Asset, AssetKind, Extraction, ExtractionError, MediaExtractor};

/// Whisper expects 16 kHz mono. We resample on decode so downstream
/// callers never have to think about it.
pub const TARGET_SAMPLE_RATE: u32 = 16_000;

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
        let payload = asset.clone();
        let media_cfg = media_cfg.clone();
        let updater_cfg = updater_cfg.clone();
        let neoth_home = neoth_home.to_path_buf();
        tokio::task::spawn_blocking(move || {
            extract_blocking_with_context(
                &payload,
                &media_cfg,
                &updater_cfg,
                &neoth_home,
                wal_writer.as_ref(),
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

fn extract_blocking_with_context(
    asset: &Asset,
    media_cfg: &crate::config::MediaConfig,
    updater_cfg: &crate::config::UpdaterConfig,
    neoth_home: &std::path::Path,
    wal_writer: Option<&crate::wal::writer::WalWriterHandle>,
) -> Result<Extraction, ExtractionError> {
    let DecodedAudio {
        samples,
        original_sample_rate,
    } = match asset {
        Asset::Bytes { data, mime, .. } => decode_from_bytes(data.clone(), mime)?,
        Asset::Path { path, .. } => decode_from_path(path)?,
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
        .block_on(crate::media::stt_provider::dispatch_pcm_f32(
            &media_cfg.stt,
            media_cfg,
            updater_cfg,
            neoth_home,
            &samples,
            TARGET_SAMPLE_RATE,
            wal_writer,
        ))
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
/// the dictation path reuses the ingest decode (incl. the 512 MiB cap
/// and WAV/MP3/FLAC/Ogg/M4A support). Blocking — call from
/// `spawn_blocking`.
pub(crate) fn decode_file_to_pcm(path: &Path) -> anyhow::Result<Vec<f32>> {
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
/// `fs::read` allocates the whole file and `decode_from_bytes` may clone it.
const MAX_AUDIO_BYTES: u64 = 512 * 1024 * 1024; // 512 MiB

fn decode_from_path(path: &Path) -> Result<DecodedAudio, ExtractionError> {
    // Size-gate before reading the whole file into memory.
    let len = std::fs::metadata(path)
        .map_err(|e| ExtractionError::Io(format!("stat {}: {e}", path.display())))?
        .len();
    if len > MAX_AUDIO_BYTES {
        return Err(ExtractionError::Backend {
            backend: "audio",
            reason: format!("input {len} bytes exceeds {MAX_AUDIO_BYTES}-byte cap"),
        });
    }
    let bytes = std::fs::read(path)
        .map_err(|e| ExtractionError::Io(format!("read {}: {e}", path.display(),)))?;
    // Symphonia probes the format from the bytes; the MIME hint is just a
    // search hint, not required.
    let mime = mime_hint_from_path(path);
    decode_from_bytes(bytes, &mime)
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
    let channels = codec_params.channels.map(|c| c.count()).unwrap_or(1);

    let mut decoder = symphonia::default::get_codecs()
        .make(&codec_params, &DecoderOptions::default())
        .map_err(|e| ExtractionError::Backend {
            backend: "audio",
            reason: format!("codec: {e}"),
        })?;

    let mut decoded_mono: Vec<f32> = Vec::new();
    let mut buf: Option<SampleBuffer<f32>> = None;
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
                if buf.is_none() {
                    let dur = audio.capacity() as u64;
                    buf = Some(SampleBuffer::<f32>::new(dur, spec));
                }
                if let Some(b) = buf.as_mut() {
                    b.copy_interleaved_ref(audio);
                    // Mix interleaved frames down to mono.
                    let frame_count = b.samples().len() / channels.max(1);
                    let samples = b.samples();
                    for f in 0..frame_count {
                        let mut sum = 0f32;
                        for c in 0..channels {
                            sum += samples[f * channels + c];
                        }
                        decoded_mono.push(sum / channels.max(1) as f32);
                    }
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

    Ok(DecodedAudio {
        samples: resampled,
        original_sample_rate: original_sr,
    })
}

/// Linear resampler — now the graceful fallback for the rubato sinc path in
/// `media::resampler` (used only when rubato rejects a degenerate ratio).
/// `pub(crate)` so the resampler module can reach it.
pub(crate) fn linear_resample(input: &[f32], src_sr: u32, dst_sr: u32) -> Vec<f32> {
    if input.is_empty() || src_sr == 0 || dst_sr == 0 {
        return Vec::new();
    }
    if src_sr == dst_sr {
        return input.to_vec();
    }
    let ratio = src_sr as f64 / dst_sr as f64;
    let out_len = ((input.len() as f64) / ratio).floor() as usize;
    let mut out = Vec::with_capacity(out_len);
    for i in 0..out_len {
        let src_pos = i as f64 * ratio;
        let lo = src_pos.floor() as usize;
        let hi = (lo + 1).min(input.len() - 1);
        let frac = (src_pos - lo as f64) as f32;
        out.push(input[lo] + (input[hi] - input[lo]) * frac);
    }
    out
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
    fn linear_resample_upsample_doubles_length() {
        let input: Vec<f32> = (0..100).map(|i| i as f32).collect();
        let out = linear_resample(&input, 8000, 16000);
        // Doubling sample rate → output is roughly 2× source. Linear
        // interpolation may differ by ±1 frame from the exact 2x.
        assert!(out.len() >= 199 && out.len() <= 200, "got {}", out.len());
    }

    #[test]
    fn linear_resample_downsample_halves_length() {
        let input: Vec<f32> = (0..200).map(|i| i as f32).collect();
        let out = linear_resample(&input, 16000, 8000);
        assert!(out.len() >= 99 && out.len() <= 100, "got {}", out.len());
    }

    #[test]
    fn linear_resample_identity_returns_clone() {
        let input = vec![1.0f32, 2.0, 3.0];
        let out = linear_resample(&input, 16000, 16000);
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
