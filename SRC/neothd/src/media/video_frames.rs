//! MM-02 — video frame extraction + multimodal council request
//! primitives.
//!
//! Pure-data sampler logic + multimodal request builder. MM-02b is now wired:
//! [`super::frame_decoder`] supplies the ffmpeg-backed decoder and
//! [`super::video_dispatch`] caps frames, enforces the upload/audit policy,
//! calls the selected vision synthesizer, and records the result.
//!
//! ## Frame sampling strategies
//!
//! - `EveryNthFrame { n }` — deterministic stride. Cheap. Misses
//!   important moments between strides.
//! - `EveryNMilliseconds { ms }` — wall-clock stride. Robust to
//!   variable framerate footage.
//! - `Keyframes` — only the keyframes (`I-frames`) the decoder
//!   already exposes. Cheapest extraction, but misses fast motion
//!   between keyframes.
//! - `Adaptive { target_count }` — re-samples a clip down to
//!   approximately `target_count` frames by spreading them evenly
//!   across the duration. The recommended default for multimodal
//!   council — most providers cap input frames per request.

use serde::{Deserialize, Serialize};

/// One extracted frame. Pixel data is owned to make ownership
/// simple — multimodal providers serialize this anyway, so the
/// extra clone is the floor cost.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frame {
    /// Timestamp into the source video, milliseconds.
    pub ts_ms: u64,
    pub width: u32,
    pub height: u32,
    pub format: FrameFormat,
    pub pixels: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrameFormat {
    /// JPEG bytes (what cloud multimodal LLMs accept directly).
    #[serde(rename = "jpeg")]
    Jpeg,
    /// PNG bytes.
    #[serde(rename = "png")]
    Png,
    /// WebP bytes — smallest at quality, supported by most modern
    /// multimodal LLMs.
    #[serde(rename = "webp")]
    WebP,
    /// Raw RGB24 (caller wants to do their own encoding).
    #[serde(rename = "rgb24")]
    Rgb24,
}

impl FrameFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Jpeg => "jpeg",
            Self::Png => "png",
            Self::WebP => "webp",
            Self::Rgb24 => "rgb24",
        }
    }

    /// MIME type — multimodal providers want this in the request
    /// body alongside the base64 payload.
    pub fn mime_type(self) -> &'static str {
        match self {
            Self::Jpeg => "image/jpeg",
            Self::Png => "image/png",
            Self::WebP => "image/webp",
            Self::Rgb24 => "application/octet-stream",
        }
    }
}

/// Frame sampling strategy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SamplingStrategy {
    EveryNthFrame { n: u32 },
    EveryNMilliseconds { ms: u32 },
    Keyframes,
    Adaptive { target_count: u32 },
}

impl SamplingStrategy {
    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::EveryNthFrame { .. } => "every_nth_frame",
            Self::EveryNMilliseconds { .. } => "every_n_milliseconds",
            Self::Keyframes => "keyframes",
            Self::Adaptive { .. } => "adaptive",
        }
    }
}

/// Pick which source-frame timestamps to extract from a video of
/// known total `duration_ms` + `framerate_fps`. Pure helper —
/// returns the millisecond offsets the caller hands to the
/// decoder. Caps at `max_frames` to honour multimodal-LLM frame
/// limits regardless of strategy.
pub fn plan_frame_timestamps(
    strategy: &SamplingStrategy,
    duration_ms: u64,
    framerate_fps: f32,
    max_frames: u32,
) -> Vec<u64> {
    if duration_ms == 0 {
        return Vec::new();
    }
    let mut out = match strategy {
        SamplingStrategy::EveryNthFrame { n } => {
            let n = (*n).max(1);
            let frame_ms = (1000.0 / framerate_fps.max(1.0)) as u64;
            let mut t = 0u64;
            let mut frame_idx = 0u32;
            let mut v = Vec::new();
            while t < duration_ms {
                if frame_idx.is_multiple_of(n) {
                    v.push(t);
                }
                t += frame_ms.max(1);
                frame_idx += 1;
            }
            v
        }
        SamplingStrategy::EveryNMilliseconds { ms } => {
            let stride = (*ms).max(1) as u64;
            let mut v = Vec::new();
            let mut t = 0u64;
            while t < duration_ms {
                v.push(t);
                t += stride;
            }
            v
        }
        SamplingStrategy::Keyframes => {
            // Without a real decoder we can't know real keyframe
            // positions. Approximate by treating one frame per
            // 2 seconds — most encoders default to a ~2 s GOP.
            let mut v = Vec::new();
            let mut t = 0u64;
            while t < duration_ms {
                v.push(t);
                t += 2_000;
            }
            v
        }
        SamplingStrategy::Adaptive { target_count } => {
            let n = (*target_count).max(1) as u64;
            if n == 1 {
                vec![duration_ms / 2]
            } else {
                let step = duration_ms / (n - 1).max(1);
                (0..n).map(|i| (i * step).min(duration_ms)).collect()
            }
        }
    };
    if out.len() as u32 > max_frames {
        // Subsample evenly down to max_frames.
        let stride = out.len() as f32 / max_frames as f32;
        let kept: Vec<u64> = (0..max_frames)
            .map(|i| out[(i as f32 * stride) as usize])
            .collect();
        out = kept;
    }
    out
}

/// Multimodal council request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MultimodalRequest {
    pub prompt: String,
    pub frames: Vec<Frame>,
    /// Soft cap on the response token count. Provider-dependent
    /// hard caps still apply.
    pub max_tokens: u32,
    /// Provider-specific model id (e.g. `claude-opus-4-7`,
    /// `gpt-4o`, `gemini-1.5-pro`). Empty = use the dispatcher's
    /// default.
    #[serde(default)]
    pub model_id: String,
}

impl MultimodalRequest {
    /// Constructor that pre-validates frame count against the most
    /// common provider caps. Returns `Err` when over the cap so
    /// callers see the limit BEFORE serialising MBs of pixel data.
    pub fn new(
        prompt: impl Into<String>,
        frames: Vec<Frame>,
        max_tokens: u32,
    ) -> Result<Self, MultimodalRequestError> {
        if frames.is_empty() {
            return Err(MultimodalRequestError::NoFrames);
        }
        if frames.len() > HARD_MAX_FRAMES_PER_REQUEST {
            return Err(MultimodalRequestError::TooManyFrames {
                got: frames.len(),
                cap: HARD_MAX_FRAMES_PER_REQUEST,
            });
        }
        Ok(Self {
            prompt: prompt.into(),
            frames,
            max_tokens,
            model_id: String::new(),
        })
    }
}

/// Conservative hard cap across providers — most multimodal LLMs
/// accept ≤20 images per request. Adaptive sampling should aim well
/// under this to leave room for prompt + system messages.
pub const HARD_MAX_FRAMES_PER_REQUEST: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MultimodalRequestError {
    #[error("no frames in request — provider would reject")]
    NoFrames,
    #[error("frame count {got} exceeds hard cap {cap} — use Adaptive sampling")]
    TooManyFrames { got: usize, cap: usize },
}

/// Multimodal provider — same shape as MM-01/MM-03 dispatchers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MultimodalProvider {
    #[serde(rename = "anthropic_claude")]
    AnthropicClaude,
    #[serde(rename = "openai_gpt4o")]
    OpenAiGpt4o,
    #[serde(rename = "google_gemini")]
    GoogleGemini,
}

impl MultimodalProvider {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AnthropicClaude => "anthropic_claude",
            Self::OpenAiGpt4o => "openai_gpt4o",
            Self::GoogleGemini => "google_gemini",
        }
    }

    /// Provider's documented max frames per request. Adaptive
    /// sampling should target ≤ this.
    pub fn max_frames_per_request(self) -> u32 {
        match self {
            Self::AnthropicClaude => 20,
            Self::OpenAiGpt4o => 10,
            Self::GoogleGemini => 16,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(ts: u64) -> Frame {
        Frame {
            ts_ms: ts,
            width: 64,
            height: 64,
            format: FrameFormat::Jpeg,
            pixels: vec![0u8; 8],
        }
    }

    // ── format ────────────────────────────────────────────────────

    #[test]
    fn frame_format_as_str_pinned() {
        assert_eq!(FrameFormat::Jpeg.as_str(), "jpeg");
        assert_eq!(FrameFormat::Png.as_str(), "png");
        assert_eq!(FrameFormat::WebP.as_str(), "webp");
        assert_eq!(FrameFormat::Rgb24.as_str(), "rgb24");
    }

    #[test]
    fn frame_format_mime_pinned() {
        assert_eq!(FrameFormat::Jpeg.mime_type(), "image/jpeg");
        assert_eq!(FrameFormat::Png.mime_type(), "image/png");
        assert_eq!(FrameFormat::WebP.mime_type(), "image/webp");
        assert_eq!(FrameFormat::Rgb24.mime_type(), "application/octet-stream");
    }

    // ── strategy kind_str ─────────────────────────────────────────

    #[test]
    fn strategy_kind_str_pinned() {
        assert_eq!(
            SamplingStrategy::EveryNthFrame { n: 5 }.kind_str(),
            "every_nth_frame"
        );
        assert_eq!(
            SamplingStrategy::EveryNMilliseconds { ms: 1000 }.kind_str(),
            "every_n_milliseconds"
        );
        assert_eq!(SamplingStrategy::Keyframes.kind_str(), "keyframes");
        assert_eq!(
            SamplingStrategy::Adaptive { target_count: 8 }.kind_str(),
            "adaptive"
        );
    }

    // ── timestamp planner ─────────────────────────────────────────

    #[test]
    fn plan_zero_duration_returns_empty() {
        let s = SamplingStrategy::EveryNthFrame { n: 1 };
        assert!(plan_frame_timestamps(&s, 0, 30.0, 100).is_empty());
    }

    #[test]
    fn plan_every_n_milliseconds_uniform_grid() {
        let s = SamplingStrategy::EveryNMilliseconds { ms: 1_000 };
        let plan = plan_frame_timestamps(&s, 5_000, 30.0, 100);
        assert_eq!(plan, vec![0, 1000, 2000, 3000, 4000]);
    }

    #[test]
    fn plan_adaptive_spreads_target_count_evenly() {
        let s = SamplingStrategy::Adaptive { target_count: 5 };
        let plan = plan_frame_timestamps(&s, 10_000, 30.0, 100);
        assert_eq!(plan.len(), 5);
        assert_eq!(plan[0], 0);
        assert_eq!(*plan.last().unwrap(), 10_000);
    }

    #[test]
    fn plan_adaptive_target_one_returns_midpoint() {
        let s = SamplingStrategy::Adaptive { target_count: 1 };
        let plan = plan_frame_timestamps(&s, 10_000, 30.0, 100);
        assert_eq!(plan, vec![5_000]);
    }

    #[test]
    fn plan_keyframes_uses_2s_default_gop() {
        let s = SamplingStrategy::Keyframes;
        let plan = plan_frame_timestamps(&s, 6_000, 30.0, 100);
        assert_eq!(plan, vec![0, 2_000, 4_000]);
    }

    #[test]
    fn plan_every_nth_frame_respects_n() {
        // 30 fps → 33 ms per frame. n=10 → every 10th frame ≈ 330 ms.
        let s = SamplingStrategy::EveryNthFrame { n: 10 };
        let plan = plan_frame_timestamps(&s, 1_000, 30.0, 100);
        // 0, 330, 660, 990 (4 picks) — but with 33 ms rounding...
        assert!(plan.len() >= 3);
        assert_eq!(plan[0], 0);
    }

    #[test]
    fn plan_caps_at_max_frames_via_even_subsample() {
        let s = SamplingStrategy::EveryNMilliseconds { ms: 100 };
        // 10 s @ every 100 ms → 100 timestamps; cap at 10.
        let plan = plan_frame_timestamps(&s, 10_000, 30.0, 10);
        assert_eq!(plan.len(), 10);
        // Subsample is even — first stays at 0, last close to end.
        assert_eq!(plan[0], 0);
    }

    // ── MultimodalRequest validation ──────────────────────────────

    #[test]
    fn new_request_rejects_empty_frames() {
        let err = MultimodalRequest::new("prompt", vec![], 200).unwrap_err();
        assert_eq!(err, MultimodalRequestError::NoFrames);
    }

    #[test]
    fn new_request_rejects_overcap_frames() {
        let frames: Vec<Frame> = (0..(HARD_MAX_FRAMES_PER_REQUEST + 1))
            .map(|i| frame(i as u64 * 100))
            .collect();
        let err = MultimodalRequest::new("prompt", frames, 200).unwrap_err();
        match err {
            MultimodalRequestError::TooManyFrames { got, cap } => {
                assert_eq!(got, HARD_MAX_FRAMES_PER_REQUEST + 1);
                assert_eq!(cap, HARD_MAX_FRAMES_PER_REQUEST);
            }
            other => panic!("expected TooManyFrames, got {other:?}"),
        }
    }

    #[test]
    fn new_request_accepts_max_frames_inclusive() {
        let frames: Vec<Frame> = (0..HARD_MAX_FRAMES_PER_REQUEST)
            .map(|i| frame(i as u64 * 100))
            .collect();
        let req = MultimodalRequest::new("p", frames, 200).expect("ok at cap");
        assert_eq!(req.frames.len(), HARD_MAX_FRAMES_PER_REQUEST);
    }

    #[test]
    fn new_request_sets_empty_model_id_by_default() {
        let req = MultimodalRequest::new("p", vec![frame(0)], 200).unwrap();
        assert!(req.model_id.is_empty());
    }

    // ── provider surface ──────────────────────────────────────────

    #[test]
    fn multimodal_provider_as_str_pinned() {
        assert_eq!(
            MultimodalProvider::AnthropicClaude.as_str(),
            "anthropic_claude"
        );
        assert_eq!(MultimodalProvider::OpenAiGpt4o.as_str(), "openai_gpt4o");
        assert_eq!(MultimodalProvider::GoogleGemini.as_str(), "google_gemini");
    }

    #[test]
    fn multimodal_provider_max_frames_per_request() {
        assert_eq!(
            MultimodalProvider::AnthropicClaude.max_frames_per_request(),
            20
        );
        assert_eq!(MultimodalProvider::OpenAiGpt4o.max_frames_per_request(), 10);
        assert_eq!(
            MultimodalProvider::GoogleGemini.max_frames_per_request(),
            16
        );
    }

    // ── serde ─────────────────────────────────────────────────────

    #[test]
    fn provider_snake_case_serde() {
        let json = serde_json::to_string(&MultimodalProvider::AnthropicClaude).unwrap();
        assert_eq!(json, "\"anthropic_claude\"");
    }

    #[test]
    fn strategy_serde_kind_tag() {
        let s = SamplingStrategy::Adaptive { target_count: 8 };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"kind\":\"adaptive\""));
        assert!(json.contains("\"target_count\":8"));
    }

    #[test]
    fn frame_serde_roundtrip() {
        let f = frame(123);
        let json = serde_json::to_string(&f).unwrap();
        let back: Frame = serde_json::from_str(&json).unwrap();
        assert_eq!(back, f);
    }

    #[test]
    fn frame_format_serde_pinned_strings() {
        assert_eq!(
            serde_json::to_string(&FrameFormat::Jpeg).unwrap(),
            "\"jpeg\""
        );
        assert_eq!(
            serde_json::to_string(&FrameFormat::WebP).unwrap(),
            "\"webp\""
        );
    }
}
