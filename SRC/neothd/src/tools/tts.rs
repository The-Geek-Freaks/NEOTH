//! Text-to-speech (A-45).
//!
//! Two providers planned:
//!   - **ElevenLabs** (live in v0.1.x): cloud REST call, ~$0.003/1k
//!     chars. Operator supplies API key + voice id. Returns audio
//!     bytes the caller writes to disk / streams to the channel.
//!   - **piper-rs** (Phase 2 — local, free): pure-Rust port of the
//!     piper neural TTS. Voice files (~50 MiB each) live under
//!     `~/.neoth/models/piper/<voice>.onnx` after `neoth models pull`.
//!     Scaffold here so the Phase-2 wiring is mechanical.

use anyhow::{Context, Result};

use crate::providers::http_client;
use crate::secret::SecretString;

#[derive(Clone, Debug)]
pub enum Provider {
    ElevenLabs,
    Piper, // Phase 2 — synthesise locally
}

impl Provider {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "elevenlabs" => Some(Self::ElevenLabs),
            "piper" => Some(Self::Piper),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct TtsResult {
    pub provider: String,
    pub voice: String,
    pub bytes: usize,
    pub mime: String,
}

/// Synthesise `text` to audio. The actual bytes are written to
/// `out_path` (callers stream-to-channel by passing a tempfile or
/// `/dev/stdout`). Returns metadata about the synthesis for the
/// audit trail.
pub async fn synthesise(
    provider: Provider,
    voice: &str,
    text: &str,
    api_key: Option<&SecretString>,
    out_path: &std::path::Path,
) -> Result<TtsResult> {
    if text.trim().is_empty() {
        anyhow::bail!("tts: empty text");
    }
    match provider {
        Provider::ElevenLabs => {
            let key = api_key.ok_or_else(|| {
                anyhow::anyhow!("elevenlabs: API key required (--api-key or NEOTH_TTS_KEY)")
            })?;
            elevenlabs_speak(voice, text, key, out_path).await
        }
        Provider::Piper => {
            anyhow::bail!(
                "piper-rs synthesis deferred to Phase 2 — local TTS engine \
                 (ONNX) + voice model pull from HF Hub. Use `--provider \
                 elevenlabs` in the meantime, or wait for the Phase-2 release \
                 once the dep tree allows the ~5 MiB onnxruntime crate."
            )
        }
    }
}

async fn elevenlabs_speak(
    voice_id: &str,
    text: &str,
    api_key: &SecretString,
    out_path: &std::path::Path,
) -> Result<TtsResult> {
    let url = format!("https://api.elevenlabs.io/v1/text-to-speech/{voice_id}");
    let client = http_client::build_client()?;
    let resp = client
        .post(&url)
        .header("xi-api-key", api_key.expose())
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "text": text,
            "model_id": "eleven_multilingual_v2",
            "voice_settings": {
                "stability": 0.5,
                "similarity_boost": 0.75,
            },
        }))
        .send()
        .await
        .context("elevenlabs request")?;
    if !resp.status().is_success() {
        anyhow::bail!("elevenlabs returned {}", resp.status());
    }
    let mime = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("audio/mpeg")
        .to_string();
    let body = resp.bytes().await.context("elevenlabs body")?;
    let bytes = body.len();
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create tts out dir {}", parent.display()))?;
    }
    std::fs::write(out_path, &body).with_context(|| format!("write {}", out_path.display()))?;
    Ok(TtsResult {
        provider: "elevenlabs".to_string(),
        voice: voice_id.to_string(),
        bytes,
        mime,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_parses_known_names() {
        assert!(matches!(
            Provider::from_str("elevenlabs"),
            Some(Provider::ElevenLabs)
        ));
        assert!(matches!(Provider::from_str("piper"), Some(Provider::Piper)));
        assert!(Provider::from_str("aws-polly").is_none());
    }

    #[tokio::test]
    async fn synthesise_rejects_empty_text() {
        let tmp = tempfile::tempdir().unwrap();
        let r = synthesise(
            Provider::ElevenLabs,
            "any-voice",
            "",
            Some(&SecretString::from("dummy")),
            &tmp.path().join("out.mp3"),
        )
        .await;
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("empty"));
    }

    #[tokio::test]
    async fn piper_provider_bails_with_phase2_message() {
        let tmp = tempfile::tempdir().unwrap();
        let err = synthesise(
            Provider::Piper,
            "en_US-amy",
            "hello",
            None,
            &tmp.path().join("out.wav"),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("Phase 2"));
    }

    #[tokio::test]
    async fn elevenlabs_requires_api_key() {
        let tmp = tempfile::tempdir().unwrap();
        let err = synthesise(
            Provider::ElevenLabs,
            "any-voice",
            "hello",
            None,
            &tmp.path().join("out.mp3"),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("API key required"));
    }
}
