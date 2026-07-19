//! Deprecated compatibility facade for text-to-speech.
//!
//! Provider implementations live exclusively in `media::{tts_dispatch,
//! tts_provider,tts_cloud}`. This module preserves the older call shape while
//! delegating every execution, consent, credential, audit, and output-write
//! decision to the canonical media stack.

use anyhow::{Context, Result};

use crate::config::FreedomConfig;
use crate::media::tts_cloud::{TtsConfirmMode, TtsRunOverrides, synthesize_to_file_at};
use crate::media::tts_dispatch::{TtsFormat, TtsProvider};
use crate::secret::SecretString;

#[derive(Clone, Debug)]
pub enum Provider {
    ElevenLabs,
    Piper,
}

impl Provider {
    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "elevenlabs" | "eleven_labs" => Some(Self::ElevenLabs),
            "piper" => Some(Self::Piper),
            _ => None,
        }
    }

    fn canonical(&self) -> TtsProvider {
        match self {
            Self::ElevenLabs => TtsProvider::ElevenLabs,
            Self::Piper => TtsProvider::Piper,
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

#[deprecated(note = "use media::tts_cloud::synthesize_to_file_at")]
pub async fn synthesise(
    provider: Provider,
    voice: &str,
    text: &str,
    api_key: Option<&SecretString>,
    out_path: &std::path::Path,
) -> Result<TtsResult> {
    let home = FreedomConfig::default_neoth_home();
    let config_path = home.join("freedom.yaml");
    let (config, credentials) = crate::config::load_optional_runtime_config_pair_from_path(
        &config_path,
    )
    .with_context(|| {
        format!(
            "load coherent TTS configuration and credentials {}",
            config_path.display()
        )
    })?;
    let config = config.unwrap_or_default();
    let format = match out_path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("wav") => TtsFormat::Wav,
        Some("mp3") => TtsFormat::Mp3,
        Some("opus") => TtsFormat::Opus,
        Some("pcm") | Some("raw") => TtsFormat::PcmS16le,
        _ => anyhow::bail!("TTS output extension must be wav, mp3, opus, or pcm"),
    };
    let result = synthesize_to_file_at(
        &home,
        &config,
        &credentials,
        text.to_string(),
        format,
        out_path,
        TtsRunOverrides {
            provider: Some(provider.canonical()),
            voice: Some(voice.to_string()),
            api_key: api_key.cloned(),
            confirm_mode: TtsConfirmMode::NonInteractive,
            ..Default::default()
        },
    )
    .await
    .map_err(anyhow::Error::msg)?;
    Ok(TtsResult {
        provider: result.provider,
        voice: result.voice,
        bytes: result.bytes,
        mime: result.mime,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_parses_only_legacy_supported_names() {
        assert!(matches!(
            Provider::from_str("elevenlabs"),
            Some(Provider::ElevenLabs)
        ));
        assert!(matches!(Provider::from_str("piper"), Some(Provider::Piper)));
        assert!(Provider::from_str("coqui").is_none());
    }

    #[test]
    fn facade_contains_no_provider_transport() {
        // include_str! embeds this test module too, so the banned literals
        // must be assembled at runtime (same idiom as the sibling guard in
        // cli/tts.rs) — a contiguous literal here would match itself.
        let source = include_str!("tts.rs");
        let forbidden_http_crate = ["req", "west"].concat();
        let direct_http_host = ["api.", "elevenlabs", ".io"].concat();
        assert!(!source.contains(&forbidden_http_crate));
        assert!(!source.contains(&direct_http_host));
        assert!(source.contains("synthesize_to_file_at"));
        assert!(source.contains("confirm_mode: TtsConfirmMode::NonInteractive"));
    }
}
