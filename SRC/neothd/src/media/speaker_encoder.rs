//! GOLD-ADAPT-SPEAKR-02c — self-contained speaker-embedding encoder.
//!
//! Turns raw per-utterance PCM into a fixed-dim voice embedding using a
//! classical log-mel + statistics-pooling front-end (the GMM-UBM / i-vector
//! feature family): frame → Hann window → real FFT → mel filterbank (40 bins)
//! → log → per-utterance **mean + std** pooling over frames → L2-normalise.
//! Output is [`crate::media::speaker_profile::SPEAKER_EMBEDDING_DIM`] (= 80)
//! floats. It is **deterministic, needs NO model download, NO external
//! weights, and carries NO license encumbrance** — it runs offline today and
//! the matcher (SPEAKR-02 / 02b) consumes it unchanged.
//!
//! ## Tiered inference
//! The common STT path first attempts the fully implemented ECAPA-TDNN and
//! x-vector candle encoders when the operator has provisioned compatible
//! safetensors. This weight-free encoder is the always-available third tier,
//! keeping speaker re-identification functional without a model download.
//!
//! ## Quality ceiling (honest)
//! Spectral-statistics embeddings discriminate speakers far less sharply than
//! ECAPA (they capture the long-term spectral envelope, not learned speaker
//! manifolds). The match threshold + ambiguity guard in `speaker_profile`
//! keep false-merges conservative; expect more `SPEAKER_NN` splits than a
//! neural encoder would produce. Good enough to *learn + re-identify* across a
//! session, not a forensic voiceprint.

use crate::media::speaker_profile::{SPEAKER_EMBEDDING_DIM, unit_normalise};
use crate::media::stt_dispatch::{AudioFormat, TextSegment};
use realfft::RealFftPlanner;

/// Working sample rate for the front-end. Input is resampled to this.
const SAMPLE_RATE: u32 = 16_000;
/// Analysis frame: 25 ms @ 16 kHz.
const FRAME_LEN: usize = 400;
/// Hop: 10 ms @ 16 kHz.
const HOP_LEN: usize = 160;
/// FFT size (≥ FRAME_LEN, power of two for a fast transform).
const N_FFT: usize = 512;
/// Mel filterbank bands. `2 * N_MELS == SPEAKER_EMBEDDING_DIM` (mean + std).
const N_MELS: usize = 40;
const MEL_FMIN: f32 = 20.0;
const MEL_FMAX: f32 = 8_000.0;
/// Floor on samples (~0.5 s @ 16 kHz). Sub-second clips produce unstable
/// near-zero-norm embeddings that would spawn junk `SPEAKER_NN` profiles, so
/// they are dropped (return `None`) rather than encoded.
const MIN_SAMPLES: usize = 8_000;

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum SpeakerAudioError {
    #[error("{format} PCM byte length {len} is not aligned to {bytes_per_sample} bytes per sample")]
    MisalignedPcm {
        format: &'static str,
        len: usize,
        bytes_per_sample: usize,
    },
    #[error("invalid sample rate {0} Hz")]
    InvalidSampleRate(u32),
    #[error("WAV header sample rate {header_hz} Hz does not match request rate {request_hz} Hz")]
    SampleRateMismatch { header_hz: u32, request_hz: u32 },
    #[error("PCM sample at index {index} is not finite")]
    NonFiniteSample { index: usize },
    #[error("invalid mono PCM16 WAV: {0}")]
    InvalidWav(String),
    #[error(transparent)]
    Resample(#[from] crate::media::resampler::ResampleError),
}

#[derive(Debug)]
struct DecodedPcm {
    samples: Vec<f32>,
    sample_rate_hz: u32,
}

// HTK mel scale.
fn hz_to_mel(hz: f32) -> f32 {
    2595.0 * (1.0 + hz / 700.0).log10()
}
fn mel_to_hz(mel: f32) -> f32 {
    700.0 * (10.0_f32.powf(mel / 2595.0) - 1.0)
}

/// Triangular mel filterbank: `N_MELS` filters over the `N_FFT/2 + 1` real-FFT
/// bins. Cheap to build (40 × 257), recomputed per call.
fn mel_filterbank() -> Vec<Vec<f32>> {
    let n_bins = N_FFT / 2 + 1;
    let mel_min = hz_to_mel(MEL_FMIN);
    let mel_max = hz_to_mel(MEL_FMAX);
    // N_MELS+2 edge points, evenly spaced on the mel scale.
    let pts: Vec<f32> = (0..N_MELS + 2)
        .map(|i| {
            let mel = mel_min + (mel_max - mel_min) * i as f32 / (N_MELS + 1) as f32;
            mel_to_hz(mel)
        })
        .collect();
    let bin = |hz: f32| hz * N_FFT as f32 / SAMPLE_RATE as f32;
    let mut fb = vec![vec![0.0f32; n_bins]; N_MELS];
    for (m, filt) in fb.iter_mut().enumerate() {
        let left = bin(pts[m]);
        let center = bin(pts[m + 1]);
        let right = bin(pts[m + 2]);
        for (k, w) in filt.iter_mut().enumerate() {
            let kf = k as f32;
            *w = if kf >= left && kf <= center && center > left {
                (kf - left) / (center - left)
            } else if kf > center && kf <= right && right > center {
                (right - kf) / (right - center)
            } else {
                0.0
            };
        }
    }
    fb
}

/// Per-frame log-mel energies. One inner vec of length `N_MELS` per frame.
fn log_mel_frames(samples: &[f32], fb: &[Vec<f32>]) -> Vec<Vec<f32>> {
    let mut planner = RealFftPlanner::<f32>::new();
    let r2c = planner.plan_fft_forward(N_FFT);
    let window: Vec<f32> = (0..FRAME_LEN)
        .map(|n| {
            0.5 - 0.5 * (2.0 * std::f32::consts::PI * n as f32 / (FRAME_LEN as f32 - 1.0)).cos()
        })
        .collect();
    let mut indata = r2c.make_input_vec();
    let mut spectrum = r2c.make_output_vec();
    let mut frames = Vec::new();
    let mut start = 0;
    while start + FRAME_LEN <= samples.len() {
        // Window the frame into the FFT input; the FRAME_LEN..N_FFT tail is
        // zero-padded (reset each iteration).
        for v in indata.iter_mut() {
            *v = 0.0;
        }
        for (n, w) in window.iter().enumerate() {
            indata[n] = samples[start + n] * w;
        }
        if r2c.process(&mut indata, &mut spectrum).is_err() {
            break;
        }
        let mut mel = vec![0.0f32; N_MELS];
        for (m, filt) in fb.iter().enumerate() {
            let mut e = 0.0f32;
            for (k, c) in spectrum.iter().enumerate() {
                e += filt[k] * c.norm_sqr();
            }
            mel[m] = (e + 1e-10).ln();
        }
        frames.push(mel);
        start += HOP_LEN;
    }
    frames
}

/// Encode already-decoded 16 kHz mono `f32` samples into a unit-norm
/// `SPEAKER_EMBEDDING_DIM` embedding. `None` if the clip is too short or
/// yields no frames.
pub fn embed_samples(samples: &[f32]) -> Option<Vec<f32>> {
    if samples.len() < MIN_SAMPLES {
        return None;
    }
    let fb = mel_filterbank();
    let frames = log_mel_frames(samples, &fb);
    if frames.is_empty() {
        return None;
    }
    let n = frames.len() as f32;
    let mut mean = vec![0.0f32; N_MELS];
    for f in &frames {
        for (m, v) in f.iter().enumerate() {
            mean[m] += v;
        }
    }
    for v in &mut mean {
        *v /= n;
    }
    let mut var = [0.0f32; N_MELS];
    for f in &frames {
        for (m, v) in f.iter().enumerate() {
            let d = v - mean[m];
            var[m] += d * d;
        }
    }
    let mut emb = Vec::with_capacity(SPEAKER_EMBEDDING_DIM);
    emb.extend_from_slice(&mean);
    emb.extend(var.iter().map(|v| (v / n).sqrt()));
    debug_assert_eq!(emb.len(), SPEAKER_EMBEDDING_DIM);
    Some(unit_normalise(&emb))
}

fn validate_sample_rate(sample_rate_hz: u32) -> Result<(), SpeakerAudioError> {
    if (crate::media::resampler::MIN_SAMPLE_RATE_HZ..=crate::media::resampler::MAX_SAMPLE_RATE_HZ)
        .contains(&sample_rate_hz)
    {
        Ok(())
    } else {
        Err(SpeakerAudioError::InvalidSampleRate(sample_rate_hz))
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let value = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let value = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn decode_wav_s16le_mono(bytes: &[u8]) -> Result<DecodedPcm, SpeakerAudioError> {
    if bytes.len() < 12 || &bytes[..4] != b"RIFF" || &bytes[8..12] != b"WAVE" {
        return Err(SpeakerAudioError::InvalidWav(
            "missing RIFF/WAVE signature".to_string(),
        ));
    }

    let mut offset = 12usize;
    let mut format = None;
    let mut data = None;
    while offset < bytes.len() {
        let header_end = offset.checked_add(8).ok_or_else(|| {
            SpeakerAudioError::InvalidWav("chunk header offset overflow".to_string())
        })?;
        let header = bytes
            .get(offset..header_end)
            .ok_or_else(|| SpeakerAudioError::InvalidWav("truncated chunk header".to_string()))?;
        let chunk_len = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
        let chunk_end = header_end
            .checked_add(chunk_len)
            .ok_or_else(|| SpeakerAudioError::InvalidWav("chunk length overflow".to_string()))?;
        let chunk = bytes
            .get(header_end..chunk_end)
            .ok_or_else(|| SpeakerAudioError::InvalidWav("truncated chunk payload".to_string()))?;

        match &header[..4] {
            b"fmt " => {
                if chunk.len() < 16 {
                    return Err(SpeakerAudioError::InvalidWav(
                        "fmt chunk is shorter than 16 bytes".to_string(),
                    ));
                }
                let audio_format = read_u16(chunk, 0).expect("validated fmt length");
                let channels = read_u16(chunk, 2).expect("validated fmt length");
                let sample_rate_hz = read_u32(chunk, 4).expect("validated fmt length");
                let block_align = read_u16(chunk, 12).expect("validated fmt length");
                let bits_per_sample = read_u16(chunk, 14).expect("validated fmt length");
                if audio_format != 1 || channels != 1 || block_align != 2 || bits_per_sample != 16 {
                    return Err(SpeakerAudioError::InvalidWav(format!(
                        "expected PCM format=1, mono, block_align=2, 16-bit; got format={audio_format}, channels={channels}, block_align={block_align}, bits={bits_per_sample}"
                    )));
                }
                validate_sample_rate(sample_rate_hz)?;
                format = Some(sample_rate_hz);
            }
            b"data" => data = Some(chunk),
            _ => {}
        }

        offset = chunk_end.checked_add(chunk_len & 1).ok_or_else(|| {
            SpeakerAudioError::InvalidWav("chunk padding offset overflow".to_string())
        })?;
        if offset > bytes.len() {
            return Err(SpeakerAudioError::InvalidWav(
                "truncated chunk padding".to_string(),
            ));
        }
    }

    let sample_rate_hz =
        format.ok_or_else(|| SpeakerAudioError::InvalidWav("missing fmt chunk".to_string()))?;
    let data =
        data.ok_or_else(|| SpeakerAudioError::InvalidWav("missing data chunk".to_string()))?;
    if data.len() % 2 != 0 {
        return Err(SpeakerAudioError::MisalignedPcm {
            format: "WAV s16le",
            len: data.len(),
            bytes_per_sample: 2,
        });
    }
    Ok(DecodedPcm {
        samples: data
            .chunks_exact(2)
            .map(|b| i16::from_le_bytes([b[0], b[1]]) as f32 / 32768.0)
            .collect(),
        sample_rate_hz,
    })
}

/// Decode raw mono PCM or a WAV container into `f32` samples in `[-1, 1]`.
fn decode(
    bytes: &[u8],
    format: AudioFormat,
    sample_rate_hz: u32,
) -> Result<DecodedPcm, SpeakerAudioError> {
    validate_sample_rate(sample_rate_hz)?;
    match format {
        AudioFormat::PcmS16leMono => {
            if !bytes.len().is_multiple_of(2) {
                return Err(SpeakerAudioError::MisalignedPcm {
                    format: "s16le",
                    len: bytes.len(),
                    bytes_per_sample: 2,
                });
            }
            Ok(DecodedPcm {
                samples: bytes
                    .chunks_exact(2)
                    .map(|b| i16::from_le_bytes([b[0], b[1]]) as f32 / 32768.0)
                    .collect(),
                sample_rate_hz,
            })
        }
        AudioFormat::PcmF32leMono => {
            if !bytes.len().is_multiple_of(4) {
                return Err(SpeakerAudioError::MisalignedPcm {
                    format: "f32le",
                    len: bytes.len(),
                    bytes_per_sample: 4,
                });
            }
            let samples: Vec<f32> = bytes
                .chunks_exact(4)
                .map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                .collect();
            if let Some(index) = samples.iter().position(|sample| !sample.is_finite()) {
                return Err(SpeakerAudioError::NonFiniteSample { index });
            }
            Ok(DecodedPcm {
                samples,
                sample_rate_hz,
            })
        }
        AudioFormat::WavPcmS16leMono => {
            let decoded = decode_wav_s16le_mono(bytes)?;
            if decoded.sample_rate_hz != sample_rate_hz {
                return Err(SpeakerAudioError::SampleRateMismatch {
                    header_hz: decoded.sample_rate_hz,
                    request_hz: sample_rate_hz,
                });
            }
            Ok(decoded)
        }
    }
}

/// Decode and resample PCM bytes to 16 kHz mono `f32` samples.
///
/// Shared by both encoder paths (log-mel + x-vector) so callers that need
/// the raw 16 kHz buffer before segmenting don't have to inline the decode/
/// resample logic. Empty input remains a valid empty buffer; malformed or
/// mislabelled audio returns a typed error.
pub fn decode_to_f32(
    bytes: &[u8],
    format: AudioFormat,
    sample_rate_hz: u32,
) -> Result<Vec<f32>, SpeakerAudioError> {
    let decoded = decode(bytes, format, sample_rate_hz)?;
    if decoded.samples.is_empty() {
        return Ok(Vec::new());
    }
    if decoded.sample_rate_hz != SAMPLE_RATE {
        Ok(crate::media::resampler::resample_mono(
            &decoded.samples,
            decoded.sample_rate_hz,
            SAMPLE_RATE,
        )?)
    } else {
        Ok(decoded.samples)
    }
}

/// Encode each transcript segment into a speaker embedding. When `segments`
/// is empty (a provider that returns no timestamps) the whole clip is encoded
/// as one utterance. Segments that decode too short are skipped, so the result
/// may be shorter than `segments` — `label_embeddings` maps 1:1 over whatever
/// is returned.
///
/// `audio` is raw PCM at `sample_rate_hz` in `format`; it is decoded then
/// resampled to 16 kHz before windowing, so segment millisecond ranges map to
/// 16 kHz sample offsets.
pub fn embed_segments(
    audio: &[u8],
    format: AudioFormat,
    sample_rate_hz: u32,
    segments: &[TextSegment],
) -> Result<Vec<Vec<f32>>, SpeakerAudioError> {
    let samples = decode_to_f32(audio, format, sample_rate_hz)?;
    if samples.is_empty() {
        return Ok(Vec::new());
    }
    if segments.is_empty() {
        return Ok(embed_samples(&samples).into_iter().collect());
    }
    let mut out = Vec::new();
    for seg in segments {
        let s = (seg.start_ms as usize) * (SAMPLE_RATE as usize) / 1000;
        let e = (seg.end_ms as usize) * (SAMPLE_RATE as usize) / 1000;
        let s = s.min(samples.len());
        let e = e.clamp(s, samples.len());
        if let Some(v) = embed_samples(&samples[s..e]) {
            out.push(v);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media::speaker_profile::cosine_similarity;

    /// `secs` of a pure sine at `freq` Hz as s16le-mono 16 kHz bytes.
    fn sine_s16le(freq: f32, secs: f32) -> Vec<u8> {
        let n = (SAMPLE_RATE as f32 * secs) as usize;
        let mut bytes = Vec::with_capacity(n * 2);
        for i in 0..n {
            let s = (2.0 * std::f32::consts::PI * freq * i as f32 / SAMPLE_RATE as f32).sin();
            bytes.extend_from_slice(&((s * 16000.0) as i16).to_le_bytes());
        }
        bytes
    }
    fn sine_samples(freq: f32, secs: f32) -> Vec<f32> {
        let n = (SAMPLE_RATE as f32 * secs) as usize;
        (0..n)
            .map(|i| (2.0 * std::f32::consts::PI * freq * i as f32 / SAMPLE_RATE as f32).sin())
            .collect()
    }

    #[test]
    fn embedding_has_fixed_dim_and_is_unit_norm() {
        let e = embed_samples(&sine_samples(220.0, 1.0)).expect("1 s clip encodes");
        assert_eq!(e.len(), SPEAKER_EMBEDDING_DIM);
        let norm: f32 = e.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-4, "unit norm, got {norm}");
        assert!(e.iter().all(|x| x.is_finite()), "no NaN/Inf");
    }

    #[test]
    fn identical_signal_is_near_one_cosine() {
        let a = embed_samples(&sine_samples(300.0, 1.0)).unwrap();
        let b = embed_samples(&sine_samples(300.0, 1.0)).unwrap();
        assert!(cosine_similarity(&a, &b) > 0.999);
    }

    #[test]
    fn distinct_spectra_are_distinguishable() {
        let a = embed_samples(&sine_samples(200.0, 1.0)).unwrap();
        let b = embed_samples(&sine_samples(1500.0, 1.0)).unwrap();
        // Different dominant mel bands → clearly below an identity match.
        assert!(cosine_similarity(&a, &b) < 0.99);
    }

    #[test]
    fn too_short_or_empty_returns_none() {
        assert!(embed_samples(&sine_samples(300.0, 0.2)).is_none()); // < MIN_SAMPLES
        assert!(embed_samples(&[]).is_none());
    }

    #[test]
    fn segments_window_into_the_clip() {
        let audio = sine_s16le(400.0, 3.0);
        let segs = vec![
            TextSegment {
                start_ms: 0,
                end_ms: 1000,
                text: String::new(),
            },
            TextSegment {
                start_ms: 1000,
                end_ms: 2500,
                text: String::new(),
            },
        ];
        let embs = embed_segments(&audio, AudioFormat::PcmS16leMono, 16_000, &segs).unwrap();
        assert_eq!(embs.len(), 2);
        assert!(embs.iter().all(|e| e.len() == SPEAKER_EMBEDDING_DIM));
    }

    #[test]
    fn no_segments_encodes_whole_clip() {
        let embs = embed_segments(
            &sine_s16le(400.0, 1.0),
            AudioFormat::PcmS16leMono,
            16_000,
            &[],
        )
        .unwrap();
        assert_eq!(embs.len(), 1);
    }

    #[test]
    fn resamples_non_16k_input() {
        // 8 kHz input → resampled to 16 k before windowing; still encodes.
        let n = 8_000usize; // 1 s @ 8 kHz
        let mut bytes = Vec::with_capacity(n * 2);
        for i in 0..n {
            let s = (2.0 * std::f32::consts::PI * 300.0 * i as f32 / 8_000.0).sin();
            bytes.extend_from_slice(&((s * 16000.0) as i16).to_le_bytes());
        }
        let embs = embed_segments(&bytes, AudioFormat::PcmS16leMono, 8_000, &[]).unwrap();
        assert_eq!(embs.len(), 1);
        assert_eq!(embs[0].len(), SPEAKER_EMBEDDING_DIM);
    }

    #[test]
    fn f32_format_decodes() {
        let samples = sine_samples(440.0, 1.0);
        let mut bytes = Vec::with_capacity(samples.len() * 4);
        for s in &samples {
            bytes.extend_from_slice(&s.to_le_bytes());
        }
        let embs = embed_segments(&bytes, AudioFormat::PcmF32leMono, 16_000, &[]).unwrap();
        assert_eq!(embs.len(), 1);
    }

    #[test]
    fn malformed_raw_pcm_is_rejected_instead_of_truncated() {
        assert!(matches!(
            decode_to_f32(&[0, 1, 2], AudioFormat::PcmS16leMono, 16_000),
            Err(SpeakerAudioError::MisalignedPcm { .. })
        ));
        assert!(matches!(
            decode_to_f32(&[0, 1, 2], AudioFormat::PcmF32leMono, 16_000),
            Err(SpeakerAudioError::MisalignedPcm { .. })
        ));
    }

    #[test]
    fn wav_container_is_decoded_as_wav_not_raw_pcm() {
        let samples = sine_samples(440.0, 1.0);
        let wav = crate::media::stt_provider::pcm_f32_to_wav(&samples).unwrap();
        let decoded = decode_to_f32(&wav, AudioFormat::WavPcmS16leMono, 16_000).unwrap();

        assert_eq!(
            decoded.len(),
            samples.len(),
            "RIFF header must not become samples"
        );
        assert!((decoded[100] - samples[100]).abs() < 1e-3);
    }
}
