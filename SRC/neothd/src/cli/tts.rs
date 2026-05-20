//! `neoth tts speak <text> --out <file>` — A-45.

use anyhow::Result;
use clap::{Args, Subcommand};
use std::path::PathBuf;

use crate::cli::OutputFormat;
use crate::secret::SecretString;
use crate::tools::tts::{self, Provider};

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
    Speak {
        /// Text to synthesise. Use `-` to read from stdin.
        text: String,
        /// Output file path. Format inferred from provider (.mp3 for
        /// ElevenLabs, .wav for piper).
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
        /// `elevenlabs` (default, live in v0.1) or `piper` (Phase 2 deferred).
        #[arg(long, default_value = "elevenlabs")]
        provider: String,
        /// Voice id for the chosen provider.
        #[arg(long, default_value = "21m00Tcm4TlvDq8ikWAM")] // ElevenLabs "Rachel"
        voice: String,
        /// API key override. Defaults to `NEOTH_TTS_KEY` env var.
        #[arg(long)]
        api_key: Option<String>,
    },
}

pub async fn run_tts(args: TtsArgs) -> Result<()> {
    match args.action {
        TtsAction::Speak {
            text,
            out,
            provider,
            voice,
            api_key,
        } => {
            let text = resolve_text(&text).await?;
            let provider = Provider::from_str(&provider).ok_or_else(|| {
                anyhow::anyhow!("unknown tts provider `{provider}` — known: elevenlabs, piper")
            })?;
            let key = api_key
                .map(SecretString::from)
                .or_else(|| std::env::var("NEOTH_TTS_KEY").ok().map(SecretString::from));
            let result = tts::synthesise(provider, &voice, &text, key.as_ref(), &out).await?;
            match args.output {
                OutputFormat::Json | OutputFormat::Jsonl => {
                    let body = serde_json::json!({
                        "result": result,
                        "out_path": out.display().to_string(),
                    });
                    println!("{}", serde_json::to_string_pretty(&body)?);
                }
                OutputFormat::Table => {
                    println!(
                        "synthesised {} bytes ({}) to {}",
                        result.bytes,
                        result.mime,
                        out.display()
                    );
                }
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

    #[tokio::test]
    async fn tts_unknown_provider_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let args = TtsArgs {
            action: TtsAction::Speak {
                text: "hi".to_string(),
                out: tmp.path().join("out.mp3"),
                provider: "googlebot".to_string(),
                voice: "v".to_string(),
                api_key: None,
            },
            output: OutputFormat::Json,
        };
        let err = run_tts(args).await.unwrap_err();
        assert!(err.to_string().contains("unknown tts provider"));
    }

    #[tokio::test]
    async fn tts_piper_bails_with_phase2() {
        let tmp = tempfile::tempdir().unwrap();
        let args = TtsArgs {
            action: TtsAction::Speak {
                text: "hi".to_string(),
                out: tmp.path().join("out.wav"),
                provider: "piper".to_string(),
                voice: "en_US-amy".to_string(),
                api_key: None,
            },
            output: OutputFormat::Json,
        };
        let err = run_tts(args).await.unwrap_err();
        assert!(err.to_string().contains("Phase 2"));
    }
}
