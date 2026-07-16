//! Canonical `neoth tts` CLI.
//!
//! `speak` routes exclusively through `media::tts_cloud::synthesize_to_file_at`:
//! dispatcher, provider factory, cloud-consent rail, credential chain, 0xCD
//! metadata audit, fallback, format validation, and atomic output are shared
//! with every compatibility caller.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
#[cfg(test)]
use crate::config::credentials::Credentials;
use crate::media::tts_cloud::{TtsConfirmMode, TtsRunOverrides, synthesize_to_file_at};
use crate::media::tts_dispatch::{TtsFormat, TtsProvider, pick_voice_for_locale};
use crate::secret::SecretString;

#[derive(Args, Debug, Clone)]
pub struct TtsArgs {
    #[command(subcommand)]
    pub action: TtsAction,

    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum TtsAction {
    /// Synthesise speech to an audio file.
    Speak(Box<TtsSpeakArgs>),
    /// Show the effective provider and local Piper readiness without synthesis.
    Status,
}

#[derive(Args, Debug, Clone)]
pub struct TtsSpeakArgs {
    /// Text to synthesise. Use `-` to read from stdin.
    text: String,
    /// Output file. The extension is authoritative: wav, mp3, opus, pcm.
    #[arg(long, value_name = "PATH")]
    out: PathBuf,
    /// Override `media.tts.primary` for this call.
    #[arg(long)]
    provider: Option<String>,
    /// Override the configured provider-specific voice id.
    #[arg(long)]
    voice: Option<String>,
    /// Override the configured locale (for example `de-DE`).
    #[arg(long)]
    locale: Option<String>,
    /// Piper ONNX path under `~/.neoth/models/piper`.
    #[arg(long, value_name = "PATH")]
    model: Option<PathBuf>,
    /// Piper JSON config path under `~/.neoth/models/piper`.
    #[arg(long = "model-config", value_name = "PATH")]
    model_config: Option<PathBuf>,
    /// Ephemeral cloud key override. Prefer credentials.yaml/keychain or
    /// NEOTH_ELEVENLABS_TTS_KEY / NEOTH_AZURE_TTS_KEY.
    #[arg(long)]
    api_key: Option<String>,
}

pub async fn run_tts(args: TtsArgs) -> Result<()> {
    let home = FreedomConfig::default_neoth_home();
    match args.action {
        TtsAction::Speak(speak) => {
            let config_path = home.join("freedom.yaml");
            let (config, credentials) =
                crate::config::load_optional_runtime_config_pair_from_path(&config_path)
                    .with_context(|| {
                        format!(
                            "load coherent TTS config and credentials under {}",
                            home.display()
                        )
                    })?;
            let config = config.unwrap_or_default();
            let TtsSpeakArgs {
                text,
                out,
                provider,
                voice,
                locale,
                model,
                model_config,
                api_key,
            } = *speak;
            let text = resolve_text(&text).await?;
            let provider = provider.as_deref().map(parse_provider).transpose()?;
            let format = format_from_output_path(&out)?;
            let result = synthesize_to_file_at(
                &home,
                &config,
                &credentials,
                text,
                format,
                &out,
                TtsRunOverrides {
                    provider,
                    voice,
                    locale,
                    piper_model: model,
                    piper_config: model_config,
                    api_key: api_key.map(SecretString::from),
                    confirm_mode: TtsConfirmMode::InteractiveCli,
                },
            )
            .await
            .map_err(anyhow::Error::msg)?;
            match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    println!("{}", serde_json::to_string_pretty(&result)?);
                }
                OutputFormat::Table => {
                    println!(
                        "synthesised {} bytes ({}) via {} to {}",
                        result.bytes, result.mime, result.provider, result.out_path
                    );
                }
            }
        }
        TtsAction::Status => {
            let config = load_config(&home)?;
            print_status(&home, &config, args.output)?;
        }
    }
    Ok(())
}

fn load_config(home: &Path) -> Result<FreedomConfig> {
    let path = home.join("freedom.yaml");
    if !path.exists() {
        return Ok(FreedomConfig::default());
    }
    FreedomConfig::load_from_path(&path)
        .with_context(|| format!("load TTS configuration {}", path.display()))
}

fn parse_provider(value: &str) -> Result<TtsProvider> {
    TtsProvider::parse(value).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown TTS provider `{value}` — known: {}",
            TtsProvider::known_names()
        )
    })
}

pub fn format_from_output_path(path: &Path) -> Result<TtsFormat> {
    match path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("wav") => Ok(TtsFormat::Wav),
        Some("mp3") => Ok(TtsFormat::Mp3),
        Some("opus") => Ok(TtsFormat::Opus),
        Some("pcm") | Some("raw") => Ok(TtsFormat::PcmS16le),
        _ => anyhow::bail!(
            "TTS output extension must be .wav, .mp3, .opus, or .pcm; no codec is inferred"
        ),
    }
}

fn print_status(home: &Path, config: &FreedomConfig, output: OutputFormat) -> Result<()> {
    let tts = &config.media.tts;
    let piper_voice = if tts.primary == TtsProvider::Piper && !tts.voice.is_empty() {
        tts.voice.clone()
    } else {
        pick_voice_for_locale(&tts.locale, TtsProvider::Piper)
            .unwrap_or("")
            .to_string()
    };
    let piper = crate::media::tts_provider::piper_status(
        &home.join("models/piper"),
        tts.piper_model.as_deref(),
        tts.piper_config.as_deref(),
        &piper_voice,
    );
    let body = match piper {
        Ok(assets) => serde_json::json!({
            "effective_provider": tts.primary.as_str(),
            "fallback": tts.fallback.map(TtsProvider::as_str),
            "cloud_tts_enabled": config.media.cloud_tts_enabled,
            "locale": tts.locale,
            "voice": tts.voice,
            "piper": {
                "ready": true,
                "model": assets.model,
                "config": assets.config,
            }
        }),
        Err(error) => serde_json::json!({
            "effective_provider": tts.primary.as_str(),
            "fallback": tts.fallback.map(TtsProvider::as_str),
            "cloud_tts_enabled": config.media.cloud_tts_enabled,
            "locale": tts.locale,
            "voice": tts.voice,
            "piper": {
                "ready": false,
                "models_root": home.join("models/piper"),
                "error": error,
            }
        }),
    };
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        OutputFormat::Table => {
            println!("effective provider: {}", tts.primary.as_str());
            println!(
                "fallback: {}",
                tts.fallback.map(TtsProvider::as_str).unwrap_or("none")
            );
            println!(
                "cloud TTS consent: {}",
                if config.media.cloud_tts_enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            if body["piper"]["ready"].as_bool() == Some(true) {
                println!("piper: ready ({})", body["piper"]["model"]);
            } else {
                println!("piper: not ready ({})", body["piper"]["error"]);
            }
        }
    }
    Ok(())
}

async fn resolve_text(arg: &str) -> Result<String> {
    if arg == "-" {
        use tokio::io::AsyncReadExt;
        let mut buf = String::new();
        tokio::io::stdin().read_to_string(&mut buf).await?;
        return Ok(buf);
    }
    Ok(arg.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn speak_args_remain_clap_compatible_when_boxed() {
        let cli = crate::cli::Cli::try_parse_from([
            "neoth",
            "tts",
            "speak",
            "hello",
            "--out",
            "voice.wav",
            "--provider",
            "piper",
            "--voice",
            "de_DE-thorsten-high",
            "--locale",
            "de-DE",
            "--model",
            "voice.onnx",
            "--model-config",
            "voice.json",
            "--api-key",
            "ephemeral",
        ])
        .unwrap();
        let crate::cli::Commands::Tts(TtsArgs {
            action: TtsAction::Speak(speak),
            ..
        }) = cli.command
        else {
            panic!("expected tts speak command")
        };
        assert_eq!(speak.text, "hello");
        assert_eq!(speak.out, PathBuf::from("voice.wav"));
        assert_eq!(speak.provider.as_deref(), Some("piper"));
        assert_eq!(speak.voice.as_deref(), Some("de_DE-thorsten-high"));
        assert_eq!(speak.locale.as_deref(), Some("de-DE"));
        assert_eq!(speak.model.as_deref(), Some(Path::new("voice.onnx")));
        assert_eq!(speak.model_config.as_deref(), Some(Path::new("voice.json")));
        assert_eq!(speak.api_key.as_deref(), Some("ephemeral"));
    }

    #[test]
    fn unknown_and_removed_providers_fail_loud() {
        assert!(parse_provider("googlebot").is_err());
        assert!(parse_provider("coqui").is_err());
    }

    #[test]
    fn output_extension_is_authoritative() {
        assert_eq!(
            format_from_output_path(Path::new("voice.wav")).unwrap(),
            TtsFormat::Wav
        );
        assert_eq!(
            format_from_output_path(Path::new("voice.MP3")).unwrap(),
            TtsFormat::Mp3
        );
        assert!(format_from_output_path(Path::new("voice.bin")).is_err());
    }

    #[test]
    fn default_provider_is_offline() {
        let config = FreedomConfig::default();
        assert!(config.media.tts.primary.is_local());
        assert_eq!(config.media.tts.primary, TtsProvider::SystemNative);
        assert!(!config.media.cloud_tts_enabled);
    }

    #[test]
    fn cli_source_has_no_legacy_provider_or_direct_http() {
        let source = include_str!("tts.rs");
        assert!(!source.contains("tools::tts"));
        assert!(!source.contains("api.elevenlabs.io"));
        assert!(source.contains("synthesize_to_file_at"));
        assert!(source.contains("confirm_mode: TtsConfirmMode::InteractiveCli"));
    }

    #[tokio::test]
    async fn synthesis_error_leaves_existing_output_untouched() {
        let home = tempfile::tempdir().unwrap();
        let out = home.path().join("voice.mp3");
        std::fs::write(&out, b"old-audio").unwrap();
        let error = synthesize_to_file_at(
            home.path(),
            &FreedomConfig::default(),
            &Credentials::default(),
            "hello".to_string(),
            TtsFormat::Mp3,
            &out,
            TtsRunOverrides::default(),
        )
        .await
        .unwrap_err();
        assert!(error.contains("system_native cannot produce mp3"));
        assert_eq!(std::fs::read(out).unwrap(), b"old-audio");
    }
}
