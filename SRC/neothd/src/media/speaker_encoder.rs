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
//! ## Why this and not a neural ECAPA-TDNN (the upgrade path)
//! candle-transformers 0.8 ships **zero** speaker models, so a neural encoder
//! (ECAPA-TDNN, EER 0.69%) means ~450 lines of hand-rolled candle (Res2Block /
//! SE-block / attentive-statistics-pooling) **plus** an offline SpeechBrain
//! `spkrec-ecapa-voxceleb` `.ckpt`→safetensors conversion, a SHA-pinned HF
//! artifact behind the SC-10 download gate + HF-01 audit, and a license
//! resolution (Apache-2.0 vs CC-BY-4.0 is disputed across sources). Until
//! those weights are produced + hosted, a neural module would be an inert stub
//! (model never cached). This encoder makes speaker re-id **functional now**;
//! swapping in a neural forward pass later is a drop-in behind [`embed_samples`].
//!
//! ## Quality ceiling (honest)
//! Spectral-statistics embeddings discriminate speakers far less sharply than
//! ECAPA (they capture the long-term spectral envelope, not learned speaker
//! manifolds). The match threshold + ambiguity guard in `speaker_profile`
//! keep false-merges conservative; expect more `SPEAKER_NN` splits than a
//! neural encoder would produce. Good enough to *learn + re-identify* across a
//! session, not a forensic voiceprint.

use crate::media::speaker_profile::{unit_normalise, SPEAKER_EMBEDDING_DIM};
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
        .map(|n| 0.5 - 0.5 * (2.0 * std::f32::consts::PI * n as f32 / (FRAME_LEN as f32 - 1.0)).cos())
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
    let mut var = vec![0.0f32; N_MELS];
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

/// Decode raw interleaved-but-mono PCM into `f32` samples in `[-1, 1]`.
fn decode(bytes: &[u8], format: AudioFormat) -> Vec<f32> {
    match format {
        AudioFormat::PcmS16leMono => bytes
            .chunks_exact(2)
            .map(|b| i16::from_le_bytes([b[0], b[1]]) as f32 / 32768.0)
            .collect(),
        AudioFormat::PcmF32leMono => bytes
            .chunks_exact(4)
            .map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .collect(),
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
) -> Vec<Vec<f32>> {
    let decoded = decode(audio, format);
    if decoded.is_empty() {
        return Vec::new();
    }
    let samples = if sample_rate_hz != SAMPLE_RATE {
        crate::media::resampler::resample_mono(&decoded, sample_rate_hz, SAMPLE_RATE)
    } else {
        decoded
    };
    if segments.is_empty() {
        return embed_samples(&samples).into_iter().collect();
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
    out
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
            TextSegment { start_ms: 0, end_ms: 1000, text: String::new() },
            TextSegment { start_ms: 1000, end_ms: 2500, text: String::new() },
        ];
        let embs = embed_segments(&audio, AudioFormat::PcmS16leMono, 16_000, &segs);
        assert_eq!(embs.len(), 2);
        assert!(embs.iter().all(|e| e.len() == SPEAKER_EMBEDDING_DIM));
    }

    #[test]
    fn no_segments_encodes_whole_clip() {
        let embs = embed_segments(&sine_s16le(400.0, 1.0), AudioFormat::PcmS16leMono, 16_000, &[]);
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
        let embs = embed_segments(&bytes, AudioFormat::PcmS16leMono, 8_000, &[]);
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
        let embs = embed_segments(&bytes, AudioFormat::PcmF32leMono, 16_000, &[]);
        assert_eq!(embs.len(), 1);
    }
}
