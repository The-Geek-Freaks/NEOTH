//! Audio backend — R-9 Phase 2.
//!
//! Pure-Rust audio decode via `symphonia` (WAV / MP3 / FLAC / Ogg / M4A →
//! 16 kHz mono f32), then **local Whisper transcription** (DD-03 / HON-04 — the
//! doc previously claimed this was unimplemented "Phase 2b"; it IS wired):
//! [`transcribe_if_cached`] runs `providers::whisper::WhisperEngine` (candle)
//! over the decoded samples once the model artifacts (tokenizer + config +
//! safetensors) are cached. The model (`providers::whisper::DEFAULT_WHISPER_REPO`,
//! ~1.6 GiB) is NOT auto-downloaded on this path — until it is pre-fetched,
//! `text` stays empty with status `"model not cached"`.
//!
//! Operator-visible behaviour:
//!   - WAV / MP3 / … bytes or path → decoded f32 samples + sample-rate
//!     metadata. Returned in `Extraction.metadata` as `sample_count` +
//!     `sample_rate` + `decoded_duration_secs`.
//!   - `text` carries the real Whisper transcript when the model is cached;
//!     empty (status `"model not cached"`) until the operator pre-fetches it.
//!
//! Limitations:
//!   - Transcription needs the cached model (no first-call auto-download here).
//!   - Single-channel mix-down — stereo inputs are averaged to mono.
//!   - 16 kHz resample is approximate (linear interpolation, not
//!     low-pass-filtered); swap for `rubato` if quality measurably drifts.

use std::path::Path;

use super::{Asset, AssetKind, Extraction, ExtractionError, MediaExtractor};

/// Whisper expects 16 kHz mono. We resample on decode so downstream
/// callers never have to think about it.
pub const TARGET_SAMPLE_RATE: u32 = 16_000;

pub struct AudioExtractor;

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
        let payload = asset.clone();
        tokio::task::spawn_blocking(move || extract_blocking(&payload))
            .await
            .map_err(|e| ExtractionError::Backend {
                backend: "audio",
                reason: format!("join error: {e}"),
            })?
    }
}

fn extract_blocking(asset: &Asset) -> Result<Extraction, ExtractionError> {
    let DecodedAudio {
        samples,
        original_sample_rate,
    } = match asset {
        Asset::Bytes { data, mime, .. } => decode_from_bytes(data.clone(), mime)?,
        Asset::Path { path, .. } => decode_from_path(path)?,
    };
    let duration_secs = samples.len() as f64 / TARGET_SAMPLE_RATE as f64;

    // Phase 2b: real whisper transcription when the model artifacts are
    // already cached. First-call download is ~1.6 GiB (whisper-large-v3-
    // turbo); we don't trigger it from inside the extract path because
    // that would block on network. Operator runs `neothd hardware` (or
    // pairs with the wizard's installer) to pre-cache before audio
    // ingestion needs it.
    let (text, status) = transcribe_if_cached(&samples);
    Ok(Extraction {
        text,
        metadata: serde_json::json!({
            "extractor": "audio",
            "sample_count": samples.len(),
            "sample_rate": TARGET_SAMPLE_RATE,
            "original_sample_rate": original_sample_rate,
            "duration_secs": duration_secs,
            "transcription_status": status,
            "transcription_model": crate::providers::whisper::DEFAULT_WHISPER_REPO,
        }),
    })
}

/// Best-effort transcription. Returns `(text, status_string)`.
///
/// Priority order:
///   1. **faster-whisper** (JV-VOICE-02/03): probe for `faster-whisper` on
///      PATH; if present, write samples to a tmp WAV, invoke the CLI with
///      `--model tiny --compute_type int8`, and parse JSONL output. This path
///      fires WITHOUT the model-cache check — faster-whisper downloads its
///      own models on first use (into `~/.cache/huggingface/`).
///   2. **candle WhisperEngine** (existing path): fires when
///      `faster-whisper` is absent but the candle model artifacts are cached.
///   3. **model not cached**: both paths unavailable — empty text.
///
/// Pitfall: we are inside `spawn_blocking`; the faster-whisper path MUST use
/// `std::process::Command` (synchronous) to avoid nested-runtime panic.
fn transcribe_if_cached(samples: &[f32]) -> (String, &'static str) {
    // ── Path 1: faster-whisper subprocess (JV-VOICE-02/03) ─────────────────
    if let Some(exe) = crate::media::stt_provider::faster_whisper_exe() {
        if let Some((text, status)) = transcribe_via_faster_whisper(&exe, samples) {
            return (text, status);
        }
        // faster-whisper present but failed — fall through to candle path.
    }

    // ── Path 2: candle WhisperEngine (HANDY-05: shared global instance) ────
    //
    // Previously constructed a NEW engine per-call (wasting VRAM on every
    // audio-ingest). Now obtains the global `Arc<WhisperEngine>` singleton
    // via `init_global_engine_sync`, which builds it once and reuses it
    // thereafter. The idle-watcher task on the engine will free VRAM after
    // the configured idle timeout (default 120 s) between calls.
    let engine = match crate::providers::whisper::init_global_engine_sync(None) {
        Ok(e) => e,
        Err(e) => {
            tracing::debug!("whisper: engine unavailable — {e:#}");
            // Map "model not cached" vs other errors to distinct statuses.
            let status = if e.to_string().contains("not cached") {
                "model not cached"
            } else {
                "whisper engine init failed"
            };
            return (String::new(), status);
        }
    };

    // We're inside spawn_blocking; build a minimal current-thread runtime
    // to drive the async transcribe call.
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return (String::new(), "tokio runtime build failed"),
    };
    let samples_owned = samples.to_vec();
    let text = rt.block_on(async move {
        engine
            .transcribe(&samples_owned, Default::default())
            .await
            .map_err(|_| ())
    });
    match text {
        // GR-fix: the local Whisper path bypassed clean_transcript (only the cloud
        // path in stt_provider.rs ran it), contra the stt_postprocess "every
        // transcript" contract. Run it here too so both paths are consistent.
        Ok(text) => (
            crate::media::stt_postprocess::clean_transcript(&text),
            "transcribed",
        ),
        Err(()) => (String::new(), "transcription failed"),
    }
}

/// JV-VOICE-02/03 — invoke faster-whisper CLI synchronously (must be inside
/// `spawn_blocking`; uses `std::process::Command` to avoid nested-runtime
/// panic). Returns `Some((text, status))` on success or clean not-found, `None`
/// to signal "try the next path".
fn transcribe_via_faster_whisper(
    exe: &std::path::Path,
    samples: &[f32],
) -> Option<(String, &'static str)> {
    // Convert f32 PCM → minimal WAV bytes that faster-whisper can consume.
    let wav = {
        let samples_i16: Vec<i16> = samples
            .iter()
            .map(|&s| (s.clamp(-1.0, 1.0) * i16::MAX as f32) as i16)
            .collect();
        let data_len = (samples_i16.len() * 2) as u32;
        let sample_rate: u32 = TARGET_SAMPLE_RATE;
        let chunk_size = 36 + data_len;
        let mut w = Vec::with_capacity(44 + data_len as usize);
        w.extend_from_slice(b"RIFF");
        w.extend_from_slice(&chunk_size.to_le_bytes());
        w.extend_from_slice(b"WAVE");
        w.extend_from_slice(b"fmt ");
        w.extend_from_slice(&16u32.to_le_bytes());
        w.extend_from_slice(&1u16.to_le_bytes()); // PCM
        w.extend_from_slice(&1u16.to_le_bytes()); // channels
        w.extend_from_slice(&sample_rate.to_le_bytes());
        w.extend_from_slice(&(sample_rate * 2).to_le_bytes()); // byte_rate
        w.extend_from_slice(&2u16.to_le_bytes()); // block_align
        w.extend_from_slice(&16u16.to_le_bytes()); // bits_per_sample
        w.extend_from_slice(b"data");
        w.extend_from_slice(&data_len.to_le_bytes());
        for s in &samples_i16 {
            w.extend_from_slice(&s.to_le_bytes());
        }
        w
    };

    let tmp_dir = std::env::temp_dir();
    // Use a thread-local timestamp-nanosecond suffix to avoid collisions when
    // multiple audio extractions run concurrently inside spawn_blocking threads.
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let tmp_path = tmp_dir.join(format!("neoth-fw-audio-{suffix}.wav"));
    if std::fs::write(&tmp_path, &wav).is_err() {
        return None; // can't write → fall through
    }

    let result = std::process::Command::new(exe)
        .args([
            "--model",
            "tiny",
            "--device",
            "cpu",
            "--compute_type",
            "int8",
            "--output_format",
            "json",
            "--language",
            "auto",
            tmp_path.to_str().unwrap_or(""),
        ])
        .env("PYTHONIOENCODING", "utf-8")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .stdin(std::process::Stdio::null())
        .output();

    let _ = std::fs::remove_file(&tmp_path);

    let out = result.ok()?;
    if !out.status.success() {
        // faster-whisper failed — log + fall through to candle.
        let stderr = String::from_utf8_lossy(&out.stderr);
        tracing::debug!(
            "faster-whisper exited {:?} — falling back to candle: {}",
            out.status,
            stderr.trim()
        );
        return None;
    }

    let (raw_text, _segs) =
        crate::media::stt_provider::parse_faster_whisper_output(&out.stdout);
    let cleaned = crate::media::stt_postprocess::clean_transcript(&raw_text);
    Some((cleaned, "transcribed-faster-whisper"))
}

// HANDY-05: whisper_cache_dir() was previously used by `transcribe_if_cached`
// to check artifact presence before building a per-call engine. Now superseded
// by `providers::whisper::init_global_engine_sync` which performs the same
// check internally. Kept here in case the faster-whisper path ever needs to
// cross-reference the candle cache directory.
#[allow(dead_code)]
fn whisper_cache_dir() -> std::path::PathBuf {
    let home = std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .or_else(|_| std::env::var("USERPROFILE").map(std::path::PathBuf::from))
        .unwrap_or_else(|_| std::path::PathBuf::from("."));
    let flattened = crate::providers::whisper::DEFAULT_WHISPER_REPO.replace('/', "-");
    home.join(".neoth").join("models").join(flattened)
}

struct DecodedAudio {
    /// 16 kHz mono f32 samples, range [-1.0, 1.0].
    samples: Vec<f32>,
    original_sample_rate: u32,
}

fn decode_from_path(path: &Path) -> Result<DecodedAudio, ExtractionError> {
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
        super::resampler::resample_mono(&decoded_mono, original_sr, TARGET_SAMPLE_RATE)
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
        let asset = Asset::Bytes {
            kind: AssetKind::Image,
            mime: "image/png".into(),
            data: vec![0x89, b'P', b'N', b'G'],
        };
        let err = extractor.extract(&asset).await.unwrap_err();
        assert!(matches!(
            err,
            ExtractionError::Unsupported {
                backend: "audio",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn extract_decodes_wav_tone_to_16k_mono() {
        let extractor = AudioExtractor;
        let asset = Asset::Bytes {
            kind: AssetKind::Audio,
            mime: "audio/wav".into(),
            data: synth_wav_tone(),
        };
        let out = extractor.extract(&asset).await.expect("decode wav");
        assert!(out.text.is_empty(), "text deferred to Phase 2b");
        let sr = out.metadata["sample_rate"].as_u64().unwrap();
        assert_eq!(sr, TARGET_SAMPLE_RATE as u64);
        let count = out.metadata["sample_count"].as_u64().unwrap();
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
}
