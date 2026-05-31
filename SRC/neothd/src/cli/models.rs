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
use crate::wal::events::{EVENT_TYPE_MODEL_DOWNLOAD_COMPLETE, EVENT_TYPE_MODEL_DOWNLOAD_START};
use crate::wal::{make_header, spawn as wal_spawn};

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
    /// `neoth model fetch <name>` is an accepted alias for this.
    #[command(visible_alias = "fetch")]
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

/// Seconds since the unix epoch (saturating to 0 on a clock fault) for
/// the HF-01 model-download audit payloads.
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn run_pull(name: &str, repo_override: Option<&str>) -> Result<()> {
    // Resolve the known model + its target repo BEFORE any config load or
    // network, so an unknown name fails fast with the known-list.
    let model_id: String = match name {
        "clip" => repo_override
            .unwrap_or(clip_engine::DEFAULT_CLIP_REPO)
            .to_string(),
        "whisper" => repo_override
            .unwrap_or(whisper::DEFAULT_WHISPER_REPO)
            .to_string(),
        other => anyhow::bail!(
            "unknown model id '{other}'. Known: {}",
            known_models()
                .iter()
                .map(|m| m.name)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    };

    // HF-01 consent gate — refuse the fetch when the operator disabled
    // HuggingFace downloads (air-gapped / bandwidth-controlled installs).
    let cfg =
        FreedomConfig::load_from_path(&FreedomConfig::default_neoth_home().join("freedom.yaml"))
            .unwrap_or_default();
    // SC-10: a per-model policy entry overrides the global gate, so an
    // operator can block (or permit) one specific model independent of
    // the `allow_huggingface_downloads` default. The full repo string AND
    // the short model name are both accepted as policy keys (see
    // `UpdaterConfig::model_download_allowed`).
    cfg.updater
        .check_model_download(&model_id, Some(name))
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // HF-01 audit: best-effort one-shot WAL writer. Skipped when the
    // daemon is live (it owns the writer + would emit its own frames).
    let audit = {
        let pidfile = crate::daemon::pidfile::default_pidfile();
        if matches!(
            crate::daemon::pidfile::live_daemon_pid(&pidfile),
            Ok(Some(_))
        ) {
            None
        } else {
            let seg = FreedomConfig::default_wal_dir().join("000001.wal");
            if let Some(p) = seg.parent() {
                let _ = std::fs::create_dir_all(p);
            }
            wal_spawn(seg).ok()
        }
    };

    if let Some((w, _)) = &audit {
        let payload = serde_json::to_vec(&serde_json::json!({
            "model_id": model_id.as_str(),
            "ts_unix": now_unix_secs(),
        }))
        .unwrap_or_default();
        if let Err(e) = w
            .append(
                make_header(EVENT_TYPE_MODEL_DOWNLOAD_START, &payload),
                payload,
            )
            .await
        {
            tracing::warn!(error = %e, "MODEL_DOWNLOAD_START WAL emit failed (non-fatal)");
        }
    }

    let started = std::time::Instant::now();
    let cache_dir = match name {
        "clip" => {
            tracing::info!(repo = %model_id, "pulling CLIP artifacts");
            let _engine = clip_engine::ClipEngine::new(repo_override.map(String::from))
                .await
                .with_context(|| "pull CLIP artifacts")?;
            clip_engine::default_cache_dir(&model_id)
        }
        "whisper" => {
            tracing::info!(repo = %model_id, "pulling Whisper artifacts");
            let _engine = whisper::WhisperEngine::new(repo_override.map(String::from))
                .await
                .with_context(|| "pull Whisper artifacts")?;
            whisper_cache_dir(&model_id)
        }
        // `name` was validated to clip/whisper above.
        _ => unreachable!("model id validated above"),
    };

    if let Some((w, join)) = audit {
        let payload = serde_json::to_vec(&serde_json::json!({
            "model_id": model_id.as_str(),
            "cached_path": cache_dir.display().to_string(),
            "duration_ms": u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "ts_unix": now_unix_secs(),
        }))
        .unwrap_or_default();
        if let Err(e) = w
            .append(
                make_header(EVENT_TYPE_MODEL_DOWNLOAD_COMPLETE, &payload),
                payload,
            )
            .await
        {
            tracing::warn!(error = %e, "MODEL_DOWNLOAD_COMPLETE WAL emit failed (non-fatal)");
        }
        drop(w);
        let _ = join.await;
    }

    println!("{} cached at {}", name, cache_dir.display());
    Ok(())
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

    // The env lock is intentionally held across run_pull's await so no
    // concurrent test mutates NEOTH_HOME mid-call (single-threaded intent).
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn pull_blocked_when_hf_downloads_disabled() {
        // HF-01 gate: with allow_huggingface_downloads = false the pull
        // bails BEFORE any network fetch. Hermetic via NEOTH_HOME override.
        let tmp = tempfile::TempDir::new().unwrap();
        let _env = crate::test_env::lock();
        let prev = std::env::var("NEOTH_HOME").ok();
        unsafe { std::env::set_var("NEOTH_HOME", tmp.path()) };
        std::fs::write(
            tmp.path().join("freedom.yaml"),
            "updater:\n  allow_huggingface_downloads: false\n",
        )
        .unwrap();
        let r = run_pull("clip", None).await;
        if let Some(v) = prev {
            unsafe { std::env::set_var("NEOTH_HOME", v) };
        } else {
            unsafe { std::env::remove_var("NEOTH_HOME") };
        }
        let err = r.expect_err("gate should block the pull");
        assert!(err.to_string().contains("blocked"), "got: {err}");
    }

    #[test]
    fn prune_missing_dir_is_noop() {
        // Use a temp HOME so we don't trash the operator's real cache.
        let tmp = tempfile::TempDir::new().unwrap();
        // Serialize HOME/USERPROFILE mutation against every other env
        // test (see crate::test_env) — they all race on the shared
        // process env under the multi-threaded runner.
        let _env = crate::test_env::lock();
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
