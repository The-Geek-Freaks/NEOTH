//! Audio backend — R-9 Phase 2.
//!
//! Pure-Rust audio decode via `symphonia` (WAV / MP3 / FLAC / Ogg / M4A →
//! 16 kHz mono f32), then **local Whisper transcription** (DD-03 / HON-04 — the
//! doc previously claimed this was unimplemented "Phase 2b"; it IS wired):
//! [`transcribe_if_cached`] runs `providers::whisper::WhisperEngine` (candle)
//! over the decoded samples once the model artifacts (tokenizer + config +
//! safetensors) are cached.
//!
//! ## First-STT-use auto-download (GOLD-ADAPT-HANDY-04)
//!
//! When the model is absent **and** `freedom.yaml::updater.allow_huggingface_downloads`
//! is `true` (the default), the first STT call triggers an automatic download
//! of the configured Whisper model (~1.6 GiB) via `WhisperEngine::ensure_artifacts`
//! (HuggingFace Hub, resumable). `0xD7 MODEL_DOWNLOAD_START` + `0xD8 MODEL_DOWNLOAD_COMPLETE`
//! WAL frames are emitted around the fetch. If the flag is `false`, the call
//! returns `status = "model download blocked"` with an actionable hint naming
//! the flag rather than silently producing an empty transcript.
//!
//! Operator-visible behaviour:
//!   - WAV / MP3 / … bytes or path → decoded f32 samples + sample-rate
//!     metadata. Returned in `Extraction.metadata` as `sample_count` +
//!     `sample_rate` + `decoded_duration_secs`.
//!   - `text` carries the real Whisper transcript once the model is cached
//!     (auto-fetched on first use when downloads are permitted).
//!
//! Limitations:
//!   - The auto-download blocks the calling audio-extraction for the duration
//!     of the fetch (~1.6 GiB). This is intentional: the operator opted in via
//!     the default `allow_huggingface_downloads = true`.
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

    // Phase 2b + GOLD-ADAPT-HANDY-04: real whisper transcription.
    // If the model is not yet cached AND allow_huggingface_downloads is true
    // (the default), `transcribe_if_cached` triggers an auto-download on first
    // use before returning the transcript. When downloads are disabled the
    // function returns an empty text with status "model download blocked".
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

/// Best-effort transcription with first-use auto-download (GOLD-ADAPT-HANDY-04).
/// Returns `(text, status_string)`.
///
/// Priority order:
///   1. **faster-whisper** (JV-VOICE-02/03): probe for `faster-whisper` on
///      PATH; if present, write samples to a tmp WAV, invoke the CLI with
///      `--model tiny --compute_type int8`, and parse JSONL output. Gated on
///      `updater.allow_huggingface_downloads` — faster-whisper downloads its
///      own models on first use (into `~/.cache/huggingface/`), so the
///      air-gap policy applies to this path too.
///   2. **candle WhisperEngine** (existing path): fires when
///      `faster-whisper` is absent. If the model is not yet cached, triggers
///      an auto-download gated by `updater.allow_huggingface_downloads`
///      (default `true`). Emits `0xD7`/`0xD8` WAL frames around the fetch.
///   3. **blocked / unavailable**: download disabled or failed — empty text
///      with an actionable status string.
///
/// Pitfall: we are inside `spawn_blocking`; both the download and the
/// faster-whisper path MUST use synchronous or mini-runtime patterns to
/// avoid nested-runtime panic.
/// `pub(crate)` so `media::dictation` can reuse the same STT path without
/// duplicating the faster-whisper → candle priority logic.
pub(crate) fn transcribe_pcm_samples(samples: &[f32]) -> (String, &'static str) {
    transcribe_if_cached(samples)
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

fn transcribe_if_cached(samples: &[f32]) -> (String, &'static str) {
    // ── Path 1: faster-whisper subprocess (JV-VOICE-02/03) ─────────────────
    // Gated on the same `updater.allow_huggingface_downloads` policy as the
    // candle path: faster-whisper downloads its own models into
    // ~/.cache/huggingface/ on first use, so an air-gapped operator who
    // disabled HF downloads must not have this path reach out either.
    // (We can't know whether ITS cache is warm, so the gate is on the path.)
    if let Some(exe) = crate::media::stt_provider::faster_whisper_exe() {
        // FAIL-CLOSED on config-load failure (error-hunt wave s4): the
        // serde default for allow_huggingface_downloads is `true`, so
        // unwrap_or_default would silently re-open the air-gap exactly
        // when the operator's `false` couldn't be read (file locked /
        // mid-rotation). Skipping faster-whisper here only costs a
        // fallthrough to the candle path.
        let allow_hf = match crate::config::FreedomConfig::load_from_default_path() {
            Ok(c) => c.updater.allow_huggingface_downloads,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "faster-whisper gate: freedom.yaml unreadable — failing CLOSED (candle path)"
                );
                false
            }
        };
        if allow_hf {
            if let Some((text, status)) = transcribe_via_faster_whisper(&exe, samples) {
                return (text, status);
            }
            // faster-whisper present but failed — fall through to candle path.
        } else {
            tracing::info!(
                "faster-whisper skipped: updater.allow_huggingface_downloads=false — using candle path"
            );
        }
    }

    // ── Path 2: candle WhisperEngine (HANDY-05: shared global instance) ────
    //
    // Previously constructed a NEW engine per-call (wasting VRAM on every
    // audio-ingest). Now obtains the global `Arc<WhisperEngine>` singleton
    // via `init_global_engine_sync`, which builds it once and reuses it
    // thereafter. The idle-watcher task on the engine will free VRAM after
    // the configured idle timeout (default 120 s) between calls.
    //
    // GOLD-ADAPT-HANDY-04: when `init_global_engine_sync` reports "not cached",
    // attempt an auto-download before returning an empty transcript.
    let engine = match crate::providers::whisper::init_global_engine_sync(None) {
        Ok(e) => e,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("not cached") {
                // Model absent — try auto-download if the operator permits it.
                // Test builds must NEVER hit the network: the wave-4 test run
                // pulled the real 1.6GB whisper model through this hook via the
                // operator's live config. cfg!(test) is compile-time-free in prod.
                if cfg!(test) {
                    return (String::new(), "model not cached");
                }
                match maybe_auto_download_whisper() {
                    Ok(()) => {
                        // Artifacts now on disk; build the engine.
                        match crate::providers::whisper::init_global_engine_sync(None) {
                            Ok(e) => e,
                            Err(e2) => {
                                tracing::warn!("whisper: engine init after download failed — {e2:#}");
                                return (String::new(), "whisper engine init failed");
                            }
                        }
                    }
                    Err(dl_err) => {
                        tracing::info!("whisper: auto-download skipped/failed — {dl_err:#}");
                        // Return the dl_err message as status so callers/logs see
                        // whether it was a consent block or a network error.
                        let status: &'static str = if dl_err
                            .to_string()
                            .contains("allow_huggingface_downloads")
                        {
                            "model download blocked"
                        } else {
                            "model download failed"
                        };
                        return (String::new(), status);
                    }
                }
            } else {
                tracing::debug!("whisper: engine unavailable — {e:#}");
                return (String::new(), "whisper engine init failed");
            }
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

/// GOLD-ADAPT-HANDY-04 — first-STT-use auto-download for the candle Whisper model.
///
/// Called from inside `spawn_blocking` when `init_global_engine_sync` reports
/// "not cached". Uses a mini current-thread runtime (same pattern as
/// `init_global_engine_sync` itself) to drive the async download.
///
/// Gate: `freedom.yaml::updater.allow_huggingface_downloads` (default `true`).
/// WAL: emits `0xD7 MODEL_DOWNLOAD_START` + `0xD8 MODEL_DOWNLOAD_COMPLETE`
///      via `daemon::model_download_audit` (best-effort; never aborts the download).
///
/// Returns `Ok(())` when the artifacts are on disk (download completed or were
/// already present). Returns `Err` with an actionable message when the download
/// is blocked (`allow_huggingface_downloads = false`) or fails on the network.
fn maybe_auto_download_whisper() -> anyhow::Result<()> {
    use crate::providers::whisper::DEFAULT_WHISPER_REPO;

    // HF-01 consent gate — reuse UpdaterConfig::check_model_download.
    let cfg = crate::config::FreedomConfig::load_from_default_path().unwrap_or_default();
    cfg.updater
        .check_model_download(DEFAULT_WHISPER_REPO, Some("whisper"))
        .map_err(|msg| anyhow::anyhow!("{msg}"))?;

    // Build a mini runtime (we're inside spawn_blocking).
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow::anyhow!("build runtime for whisper download: {e}"))?;

    rt.block_on(async {
        let start = std::time::Instant::now();
        // 0xD7 MODEL_DOWNLOAD_START
        crate::daemon::model_download_audit::emit_start(DEFAULT_WHISPER_REPO).await;

        // `WhisperEngine::new_with_idle_secs` calls `ensure_artifacts` which
        // uses hf_hub to download tokenizer.json + config.json + model.safetensors.
        // idle_secs=Some(0) → no background idle-watcher spawned in this transient rt.
        let result =
            crate::providers::whisper::WhisperEngine::new_with_idle_secs(None, Some(0)).await;

        let duration_ms = start.elapsed().as_millis() as u64;
        match &result {
            Ok(_) => {
                let cache_path = {
                    let home = std::env::var("HOME")
                        .map(std::path::PathBuf::from)
                        .or_else(|_| {
                            std::env::var("USERPROFILE").map(std::path::PathBuf::from)
                        })
                        .unwrap_or_else(|_| std::path::PathBuf::from("."));
                    let flattened = DEFAULT_WHISPER_REPO.replace('/', "-");
                    home.join(".neoth").join("models").join(flattened)
                };
                // 0xD8 MODEL_DOWNLOAD_COMPLETE
                crate::daemon::model_download_audit::emit_complete(
                    DEFAULT_WHISPER_REPO,
                    &cache_path.to_string_lossy(),
                    duration_ms,
                )
                .await;
                tracing::info!(
                    model = DEFAULT_WHISPER_REPO,
                    duration_ms,
                    "whisper: auto-download complete"
                );
            }
            Err(e) => {
                tracing::warn!(
                    model = DEFAULT_WHISPER_REPO,
                    error = %e,
                    "whisper: auto-download failed"
                );
            }
        }
        // Drop the engine immediately — GLOBAL_WHISPER_ENGINE will be
        // populated by the subsequent `init_global_engine_sync` call in the
        // caller, which shares the same OnceLock path.
        result.map(|_| ())
    })
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
    // Process-unique suffix: pid + atomic sequence + wall-clock nanos. Nanos
    // alone collide when two spawn_blocking extractions read the same clock
    // tick (Windows timer resolution can be >=1ms) — both calls then share
    // one temp file and transcribe each other's audio.
    static FW_TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = FW_TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let tmp_path = tmp_dir.join(format!(
        "neoth-fw-audio-{}-{seq}-{nanos}.wav",
        std::process::id()
    ));
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

    // ── GOLD-ADAPT-HANDY-04: auto-download gate tests ────────────────────────

    /// When `allow_huggingface_downloads = false`, `maybe_auto_download_whisper`
    /// must return Err whose message references the config flag — not attempt
    /// any network request.
    #[test]
    fn auto_download_blocked_when_hf_downloads_disabled() {
        use crate::config::ops::UpdaterConfig;

        let mut updater = UpdaterConfig::default();
        updater.allow_huggingface_downloads = false;

        // Directly test the consent gate that `maybe_auto_download_whisper` uses.
        let result = updater.check_model_download(
            crate::providers::whisper::DEFAULT_WHISPER_REPO,
            Some("whisper"),
        );
        assert!(
            result.is_err(),
            "check_model_download must return Err when downloads disabled"
        );
        let msg = result.unwrap_err();
        assert!(
            msg.contains("allow_huggingface_downloads"),
            "error must name the config flag; got: {msg}"
        );
    }

    /// When all three artifact files exist in the cache directory,
    /// `init_global_engine_sync` returns Ok — confirming the "model present"
    /// fast path does NOT invoke `maybe_auto_download_whisper`.
    /// Uses a temp directory pointed at via the HOME override so no real
    /// ~/.neoth layout is required.
    #[test]
    fn model_present_does_not_trigger_download() {
        use crate::providers::whisper::{CONFIG_FILE, DEFAULT_WHISPER_REPO, SAFETENSORS_FILE, TOKENIZER_FILE};

        // Env-var mutation MUST hold the process-wide test-env lock — without
        // it the HOME override races parallel tests (the STT factory test saw
        // our stub tree and flipped its is_err() expectation).
        let _env = crate::test_env::lock();

        // Build a fake model directory under a temp HOME.
        let tmp = tempfile::tempdir().expect("tempdir");
        let flattened = DEFAULT_WHISPER_REPO.replace('/', "-");
        let model_dir = tmp.path().join(".neoth").join("models").join(&flattened);
        std::fs::create_dir_all(&model_dir).unwrap();

        // Touch all three sentinel files (content irrelevant — presence is the gate).
        for name in &[SAFETENSORS_FILE, TOKENIZER_FILE, CONFIG_FILE] {
            std::fs::write(model_dir.join(name), b"stub").unwrap();
        }

        // Override HOME so `default_cache_dir` resolves to our temp tree.
        // NOTE: this is process-global; tests run in isolation via `cargo test`'s
        // per-binary parallelism, but within-process test threads may race on env.
        // We scope the env mutation tightly and accept the risk for this unit test.
        let prev_home = std::env::var("HOME").ok();
        let prev_userprofile = std::env::var("USERPROFILE").ok();
        unsafe {
            std::env::set_var("HOME", tmp.path());
            std::env::set_var("USERPROFILE", tmp.path());
        }

        // `init_global_engine_sync` checks file existence before touching OnceLock.
        // With stubs present the existence check passes; it then tries to build the
        // engine (which fails because the stubs are not real weights). The test
        // asserts the error is NOT "not cached" — proving the gate did NOT trigger.
        let result = crate::providers::whisper::init_global_engine_sync(None);

        unsafe {
            match prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
            match prev_userprofile {
                Some(v) => std::env::set_var("USERPROFILE", v),
                None => std::env::remove_var("USERPROFILE"),
            }
        }

        // If somehow the global engine was already set from another test that
        // actually has the model cached, the call returns Ok — that is fine.
        if let Err(e) = result {
            let msg = e.to_string();
            assert!(
                !msg.contains("not cached"),
                "expected a load/parse error (stubs), not a cache-miss; got: {msg}"
            );
        }
    }
}
