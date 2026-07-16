//! `neoth dictate <file>` — GOLD-ADOPT-25 dictation surface.
//!
//! Decodes an audio file to 16 kHz mono PCM (symphonia — WAV/MP3/FLAC/
//! Ogg/M4A) and runs it through the writer-aware canonical dictation path:
//! the `media.dictation_enabled` consent gate, the optional SmoothedVad
//! pre-filter, configured STT provider/fallback, download consent, and WAL
//! audit for cloud transcription.
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
    let updater_cfg = config.updater;
    let neoth_home = crate::config::FreedomConfig::default_neoth_home();
    let file = args.file.clone();

    // A standalone CLI process must not append to the daemon-owned active
    // segment. Use an independent timestamp-named segment and pass its writer
    // into the canonical STT boundary. If opening it fails, local STT remains
    // usable; proof-hardline cloud STT rejects the missing sink before egress.
    let audit = {
        let wal_dir = crate::config::FreedomConfig::default_wal_dir();
        let opened = (|| -> anyhow::Result<_> {
            std::fs::create_dir_all(&wal_dir)?;
            Ok(crate::wal::writer::spawn(
                wal_dir.join(format!("{:020}.wal", crate::time::now_unix_ns())),
            )?)
        })();
        match opened {
            Ok(pair) => Some(pair),
            Err(error) => {
                tracing::warn!(%error, "dictate: WAL audit writer unavailable");
                None
            }
        }
    };
    let writer_for_stt = audit.as_ref().map(|(writer, _)| writer.clone());

    // Symphonia decode is blocking; the canonical STT dispatcher is async and
    // must stay on the runtime rather than calling Handle::block_on from an
    // executor thread.
    let samples =
        tokio::task::spawn_blocking(move || crate::media::audio::decode_file_to_pcm(&file))
            .await
            .context("dictate: blocking decode task panicked")??;
    let outcome = crate::media::dictation::transcribe_utterance_with_writer(
        &samples,
        crate::media::audio::TARGET_SAMPLE_RATE,
        &media_cfg,
        &updater_cfg,
        &neoth_home,
        writer_for_stt.as_ref(),
    )
    .await;

    if let Some((writer, join)) = audit {
        drop(writer);
        join.await.context("dictate: WAL writer task panicked")?;
    }
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
    use crate::media::dictation::{DictationError, transcribe_utterance};

    /// The CLI is a thin shim; the load-bearing contract is that the
    /// default config (dictation_enabled=false) refuses before touching
    /// any STT backend.
    #[tokio::test]
    async fn default_config_refuses_dictation() {
        let cfg = MediaConfig::default();
        let home = tempfile::tempdir().unwrap();
        let pcm = vec![0.0f32; 3200]; // 200 ms of silence @ 16 kHz
        let err = transcribe_utterance(
            &pcm,
            16_000,
            &cfg,
            &crate::config::UpdaterConfig::default(),
            home.path(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, DictationError::NotEnabled));
    }
}
