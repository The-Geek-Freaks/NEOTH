//! `neoth models` — manage the local model caches under `~/.neoth/models/`.
//!
//! Three subcommands today:
//!   - `list`   — print every model NEOTH knows about + on-disk status.
//!   - `pull <name>` — download a known model's artifacts. Operators
//!     trigger this once after `neoth init` so the first media-extract
//!     run isn't blocked on a several-GiB HF download.
//!   - `prune <name>` — delete a model's cache directory. Useful when
//!     iterating on disk-strapped laptops.
//!
//! Known names: `clip` (vision Phase 2b), `whisper` (audio Phase 2b).
//! `qwen` is intentionally **not** in this list — local Qwen has its
//! own onboarding flow via `cli/init.rs::step5b_inference_topology`
//! that runs sysinfo-based hardware sizing before picking the repo.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::providers::{clip_engine, whisper};

#[derive(Args, Debug, Clone)]
pub struct ModelsArgs {
    #[command(subcommand)]
    pub action: ModelsAction,

    /// Output format. Inherited from the global `--output` flag.
    #[arg(skip)]
    pub output: OutputFormat,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ModelsAction {
    /// Print every known model + whether its artifacts are cached.
    List,
    /// Download a model's artifacts into `~/.neoth/models/<flat>/`.
    Pull {
        /// Model id. Known: `clip`, `whisper`.
        name: String,
        /// Override the HF repo (otherwise the default for the chosen
        /// name is used).
        #[arg(long)]
        repo: Option<String>,
    },
    /// Delete a model's cache directory. No-op when the directory is
    /// absent.
    Prune {
        /// Model id. Known: `clip`, `whisper`.
        name: String,
    },
}

/// Static catalogue of models NEOTH knows. Adding a new entry to this
/// list automatically surfaces it in `list` + makes `pull` accept it.
fn known_models() -> Vec<KnownModel> {
    vec![
        KnownModel {
            name: "clip",
            description: "CLIP ViT-B/32 image + text embeddings (vision Phase 2b)",
            default_repo: clip_engine::DEFAULT_CLIP_REPO,
            required_files: &[
                clip_engine::CONFIG_FILE,
                clip_engine::SAFETENSORS_FILE,
                clip_engine::TOKENIZER_FILE,
            ],
            cache_dir: clip_engine::default_cache_dir,
        },
        KnownModel {
            name: "whisper",
            description: "Whisper large-v3-turbo transcription (audio Phase 2b)",
            default_repo: whisper::DEFAULT_WHISPER_REPO,
            required_files: &[
                whisper::CONFIG_FILE,
                whisper::TOKENIZER_FILE,
                whisper::SAFETENSORS_FILE,
            ],
            cache_dir: whisper_cache_dir,
        },
    ]
}

struct KnownModel {
    name: &'static str,
    description: &'static str,
    default_repo: &'static str,
    required_files: &'static [&'static str],
    cache_dir: fn(&str) -> std::path::PathBuf,
}

/// Wrapper around the whisper engine's `default_cache_dir` so we can
/// store a `fn` pointer alongside CLIP's identical helper.
fn whisper_cache_dir(repo: &str) -> std::path::PathBuf {
    let home = std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .or_else(|_| std::env::var("USERPROFILE").map(std::path::PathBuf::from))
        .unwrap_or_else(|_| std::path::PathBuf::from("."));
    let flattened = repo.replace('/', "-");
    home.join(".neoth").join("models").join(flattened)
}

pub async fn run_models(args: ModelsArgs) -> Result<()> {
    match args.action {
        ModelsAction::List => run_list(&args.output),
        ModelsAction::Pull { name, repo } => run_pull(&name, repo.as_deref()).await,
        ModelsAction::Prune { name } => run_prune(&name),
    }
}

fn run_list(output: &OutputFormat) -> Result<()> {
    let _home = FreedomConfig::default_neoth_home();
    let rows: Vec<ListRow> = known_models()
        .into_iter()
        .map(|m| {
            let cache = (m.cache_dir)(m.default_repo);
            let cached = m.required_files.iter().all(|f| cache.join(f).exists());
            ListRow {
                name: m.name.to_string(),
                description: m.description.to_string(),
                repo: m.default_repo.to_string(),
                cache_dir: cache.display().to_string(),
                cached,
            }
        })
        .collect();
    match output {
        OutputFormat::Table => print_table(&rows),
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&rows)?);
        }
    }
    Ok(())
}

fn print_table(rows: &[ListRow]) {
    println!("NAME       STATUS   REPO                                            CACHE");
    println!("{}", "─".repeat(110));
    for r in rows {
        let status = if r.cached { "cached" } else { "missing" };
        println!(
            "{:<10} {:<8} {:<48} {}",
            r.name, status, r.repo, r.cache_dir
        );
        println!("           {}", r.description);
    }
}

#[derive(serde::Serialize)]
struct ListRow {
    name: String,
    description: String,
    repo: String,
    cache_dir: String,
    cached: bool,
}

async fn run_pull(name: &str, repo_override: Option<&str>) -> Result<()> {
    match name {
        "clip" => {
            let repo = repo_override.map(String::from);
            tracing::info!(repo = ?repo, "pulling CLIP artifacts");
            let _engine = clip_engine::ClipEngine::new(repo)
                .await
                .with_context(|| "pull CLIP artifacts")?;
            println!(
                "CLIP cached at {}",
                clip_engine::default_cache_dir(clip_engine::DEFAULT_CLIP_REPO).display()
            );
            Ok(())
        }
        "whisper" => {
            let repo = repo_override.map(String::from);
            tracing::info!(repo = ?repo, "pulling Whisper artifacts");
            let _engine = whisper::WhisperEngine::new(repo)
                .await
                .with_context(|| "pull Whisper artifacts")?;
            println!(
                "Whisper cached at {}",
                whisper_cache_dir(whisper::DEFAULT_WHISPER_REPO).display()
            );
            Ok(())
        }
        other => anyhow::bail!(
            "unknown model id '{other}'. Known: {}",
            known_models()
                .iter()
                .map(|m| m.name)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn run_prune(name: &str) -> Result<()> {
    let known = known_models();
    let model = known
        .iter()
        .find(|m| m.name == name)
        .ok_or_else(|| anyhow::anyhow!("unknown model id '{name}'"))?;
    let dir = (model.cache_dir)(model.default_repo);
    if !dir.exists() {
        println!("{} already absent at {}", name, dir.display());
        return Ok(());
    }
    std::fs::remove_dir_all(&dir).with_context(|| format!("remove_dir_all {}", dir.display()))?;
    println!("removed {}", dir.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_models_contains_clip_and_whisper() {
        let names: Vec<&'static str> = known_models().iter().map(|m| m.name).collect();
        assert!(names.contains(&"clip"));
        assert!(names.contains(&"whisper"));
    }

    #[test]
    fn known_models_have_required_files() {
        for m in known_models() {
            assert!(
                !m.required_files.is_empty(),
                "{} has no required_files",
                m.name
            );
            for f in m.required_files {
                assert!(!f.is_empty(), "{}'s required_files contains empty", m.name);
            }
        }
    }

    #[test]
    fn whisper_cache_dir_matches_engine_default() {
        // Both helpers must point at the same directory or `models pull`
        // would download into one place while extractions look in
        // another.
        let from_cli = whisper_cache_dir(whisper::DEFAULT_WHISPER_REPO);
        let s = from_cli.to_string_lossy();
        assert!(s.contains("openai-whisper-large-v3-turbo"));
        assert!(s.contains(".neoth"));
        assert!(s.contains("models"));
    }

    #[tokio::test]
    async fn pull_unknown_name_errors_with_known_list() {
        let err = run_pull("nope", None).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown model id"));
        assert!(msg.contains("clip"));
        assert!(msg.contains("whisper"));
    }

    #[test]
    fn prune_unknown_name_errors() {
        let err = run_prune("nope").unwrap_err();
        assert!(err.to_string().contains("unknown model id"));
    }

    #[test]
    fn prune_missing_dir_is_noop() {
        // Use a temp HOME so we don't trash the operator's real cache.
        let tmp = tempfile::TempDir::new().unwrap();
        // SAFETY: test-only env mutation, single-threaded by default.
        let prev_home = std::env::var("HOME").ok();
        let prev_user = std::env::var("USERPROFILE").ok();
        unsafe { std::env::set_var("HOME", tmp.path()) };
        unsafe { std::env::set_var("USERPROFILE", tmp.path()) };
        let r = run_prune("clip");
        if let Some(v) = prev_home {
            unsafe { std::env::set_var("HOME", v) };
        } else {
            unsafe { std::env::remove_var("HOME") };
        }
        if let Some(v) = prev_user {
            unsafe { std::env::set_var("USERPROFILE", v) };
        } else {
            unsafe { std::env::remove_var("USERPROFILE") };
        }
        assert!(r.is_ok());
    }
}
