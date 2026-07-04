//! `neoth dictate <file>` — GOLD-ADOPT-25 dictation surface.
//!
//! Decodes an audio file to 16 kHz mono PCM (symphonia — WAV/MP3/FLAC/
//! Ogg/M4A) and runs it through `media::dictation::transcribe_utterance`:
//! the `media.dictation_enabled` consent gate, the optional SmoothedVad
//! pre-filter, and the faster-whisper → candle STT priority chain.
//!
//! Live microphone capture is deliberately out of scope (no cpal dep);
//! file-based dictation is the production caller for the pipeline until
//! a capture loop lands.

use anyhow::{Context, Result};
use clap::Args;
use std::path::PathBuf;

use crate::cli::OutputFormat;
use crate::media::dictation::DictationError;

#[derive(Args, Debug, Clone)]
pub struct DictateArgs {
    /// Audio file to transcribe (WAV/MP3/FLAC/Ogg/M4A — decoded to
    /// 16 kHz mono before STT).
    pub file: PathBuf,

    #[arg(skip)]
    pub output: OutputFormat,
}

pub async fn run_dictate(args: DictateArgs) -> Result<()> {
    let config = crate::config::FreedomConfig::load_from_default_path()?;
    let media_cfg = config.media;
    let file = args.file.clone();

    // Decode + STT are blocking (symphonia / whisper) — keep them off
    // the async reactor. The closure returns Ok(Result<String,
    // DictationError>) ON PURPOSE: DictationError is a match-handled
    // outcome below (AllSilence = clean exit), NOT a `?`-propagated
    // failure — don't "simplify" the double wrap.
    let outcome = tokio::task::spawn_blocking(move || {
        let samples = crate::media::audio::decode_file_to_pcm(&file)?;
        Ok::<_, anyhow::Error>(crate::media::dictation::transcribe_utterance(
            &samples,
            crate::media::audio::TARGET_SAMPLE_RATE,
            &media_cfg,
        ))
    })
    .await
    .context("dictate: blocking decode/STT task panicked")??;

    match outcome {
        Ok(text) => match args.output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!(
                    "{}",
                    serde_json::json!({ "ok": true, "text": text, "file": args.file })
                );
            }
            OutputFormat::Table => println!("{text}"),
        },
        // All-silence is a clean outcome, not a failure: exit 0 with an
        // empty transcript so scripted callers can distinguish it via JSON.
        Err(DictationError::AllSilence) => match args.output {
            OutputFormat::Json | OutputFormat::Jsonl => {
                println!(
                    "{}",
                    serde_json::json!({ "ok": true, "text": "", "silence": true })
                );
            }
            OutputFormat::Table => eprintln!("[silence — nothing transcribed]"),
        },
        // NotEnabled / Transcription carry actionable messages via thiserror.
        Err(e) => anyhow::bail!(e),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::config::features::MediaConfig;
    use crate::media::dictation::{transcribe_utterance, DictationError};

    /// The CLI is a thin shim; the load-bearing contract is that the
    /// default config (dictation_enabled=false) refuses before touching
    /// any STT backend.
    #[test]
    fn default_config_refuses_dictation() {
        let cfg = MediaConfig::default();
        let pcm = vec![0.0f32; 3200]; // 200 ms of silence @ 16 kHz
        let err = transcribe_utterance(&pcm, 16_000, &cfg).unwrap_err();
        assert!(matches!(err, DictationError::NotEnabled));
    }
}
