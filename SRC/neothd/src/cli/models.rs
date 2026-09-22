//! `neoth models` — manage the local model caches under `~/.neoth/models/`.
//!
//! Operator-facing subcommands include:
//!   - `list` — print every managed local model + on-disk status.
//!   - `catalog` — print the live provider-model catalog used by the GUI.
//!   - `pull <name>` — download a known model's artifacts. Operators
//!     trigger this once after `neoth init` so the first media-extract
//!     run isn't blocked on a several-GiB HF download.
//!   - `prune <name>` — delete a model's cache directory. Useful when
//!     iterating on disk-strapped laptops.
//!   - `bge-m3` — inspect or explicitly operate the pinned BGE-M3 embedding
//!     artifact lifecycle. This group has no mutable repository selector.
//!   - `recommend` / `fit` — select and size local inference models.
//!
//! Known names: `clip` (vision Phase 2b), `whisper` (audio Phase 2b).
//! `whisper-candle` and `whisper-faster` explicitly select either local STT
//! backend; plain `whisper` follows the effective configured primary.
//! `qwen` is intentionally **not** in this list — local Qwen has its
//! own onboarding flow via `cli/init.rs::step5b_inference_topology`
//! that runs sysinfo-based hardware sizing before picking the repo.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand, ValueEnum};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::daemon::local_models::{LocalModelAction, LocalModelActionAck, LocalModelsSnapshot};
use crate::daemon::local_models_ipc::LocalModelsIpcClient;
use crate::installers::{gpu, ollama};
use crate::models::gguf_variants::{self, GgufVariant, VariantClass};
use crate::models::selector::{self, Quant};
use crate::providers::clip_engine;

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
    /// Daemon-owned local Ollama inventory and operation controls. This uses
    /// the private local-model IPC service; it never creates a CLI controller.
    Ollama {
        /// Select the daemon instance by its freedom.yaml path. The parent
        /// directory is the private IPC home, matching `neoth serve --config`.
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
        #[command(subcommand)]
        action: OllamaModelsAction,
    },
    /// Print every known model + whether its artifacts are cached.
    List,
    /// H18 — dump the live provider-model catalog (the wizard's model
    /// select source, `~/.neoth/models_catalog.json`) as JSON for the
    /// GUI's regenerate-with-model picker. Read-only; never-fetched or
    /// stale providers surface their fetch error so consumers degrade
    /// honestly instead of guessing model ids.
    Catalog,
    /// Operate the immutable, local-only BGE-M3 embedding artifact.
    ///
    /// The repository, revision, and manifest are fixed in the reviewed
    /// artifact module. Selection remains an explicit `embed.model=bge_m3`
    /// operator choice; this command never changes that configuration.
    BgeM3 {
        #[command(subcommand)]
        action: BgeM3ModelsAction,
    },
    /// Inspect or explicitly operate the selected local embedding model.
    /// `--config` binds this command to that exact instance home.
    Embedding {
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
        #[command(subcommand)]
        action: EmbeddingModelsAction,
    },
    /// Download a model's artifacts into `~/.neoth/models/<flat>/`.
    /// `neoth model fetch <name>` is an accepted alias for this.
    #[command(visible_alias = "fetch")]
    Pull {
        /// Model id. Known: `clip`, `whisper`, `whisper-candle`, `whisper-faster`.
        name: String,
        /// Override the HF repo for CLIP. Whisper repositories are pinned to
        /// the configured model size and reject overrides.
        #[arg(long)]
        repo: Option<String>,
    },
    /// Delete a model's cache directory. No-op when the directory is
    /// absent.
    Prune {
        /// Model id. Known: `clip`, `whisper`, `whisper-candle`, `whisper-faster`.
        name: String,
    },
    /// Recommend the best LOCAL model(s) for this machine's VRAM and print
    /// ready-to-run `ollama pull` commands (GOLD-ADOPT-10/11/13). Quantized
    /// (Q4/Q8), abliterated-first, newest/best resolved live from HuggingFace.
    Recommend {
        /// Override detected VRAM (MiB) instead of probing the GPU. Useful on
        /// headless boxes or to preview a different tier.
        #[arg(long)]
        vram: Option<u32>,
        /// Lineage to prefer. `abliterated` (default — uncensored) or
        /// `standard`.
        #[arg(long, value_enum, default_value_t = RecClass::Abliterated)]
        class: RecClass,
        /// Skip the live HuggingFace lookup; use the verified curated repos
        /// only (offline / air-gapped).
        #[arg(long)]
        offline: bool,
    },
    /// GOLD-ADAPT-ODY-13 — estimate decode throughput (tok/s) for a ladder of
    /// quantized local models on a GPU, ranked by VRAM-fit then speed.
    /// Complements `recommend` (which model) with "how fast". The estimate is
    /// memory-bandwidth-bound: `tok/s ≈ 0.55 × bandwidth / model_GB`.
    Fit {
        /// GPU name (e.g. `RTX 4090`, `A100`) — matched against a built-in
        /// bandwidth table. Provides both bandwidth + VRAM.
        #[arg(long, value_name = "NAME")]
        gpu: Option<String>,
        /// Memory bandwidth (GB/s) — required when `--gpu` isn't in the table.
        #[arg(long, value_name = "GB_S")]
        bandwidth: Option<f64>,
        /// VRAM (GB) for the fit check. Defaults to the `--gpu` table value;
        /// 0 (or omitted with a custom `--bandwidth`) ranks by speed only.
        #[arg(long, value_name = "GB")]
        vram: Option<f64>,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum OllamaModelsAction {
    /// Read the daemon's current typed local-model snapshot.
    Status,
    /// Start a pull for this exact Ollama tag selector.
    Pull { model: String },
    /// Start an update for this exact installed Ollama tag selector.
    Update { model: String },
    /// Request a verified prune for this exact Ollama tag selector.
    Prune { model: String },
    /// Request cancellation of the daemon-owned exact operation id.
    Cancel { operation_id: String },
    /// Retry the retained failed exact operation id.
    Retry { operation_id: String },
}

/// Lifecycle actions for the exact pinned BGE-M3 artifact manifest.
///
/// There intentionally are no repository, revision, filename, or hash flags:
/// each operation targets only `providers::bge_m3_artifacts`' reviewed pin.
#[derive(Subcommand, Debug, Clone)]
pub enum BgeM3ModelsAction {
    /// Show the selected embedding model and the BGE-M3 cache row.
    List,
    /// Show selected-model readiness plus the immutable BGE-M3 artifact pin.
    Status,
    /// Download and verify the exact pinned BGE-M3 manifest.
    Pull,
    /// Reconcile a pending, missing, or corrupt exact BGE-M3 generation.
    Repair,
    /// Remove only the exact owned BGE-M3 cache after lifecycle safeguards.
    Prune,
}

/// Versioned embedding-surface actions. Pull, repair, and prune are currently
/// available only for BGE-M3's reviewed artifact lifecycle.
#[derive(Subcommand, Debug, Clone)]
pub enum EmbeddingModelsAction {
    /// Cheap cache/config snapshot. It never reports a loaded runtime ready.
    List,
    /// Alias of list for GUI and operator status polling.
    Status,
    /// Persist the closed embedding-model selection and return exact readback.
    Select { model: EmbeddingModelArg },
    /// Construct and validate only the explicitly selected local adapter.
    Probe,
    /// Pull the exact pinned BGE-M3 artifacts, then return a fresh snapshot.
    Pull,
    /// Reconcile BGE-M3's exact lifecycle, then return a fresh snapshot.
    Repair,
    /// Prune the exact BGE-M3 cache, then return a fresh snapshot.
    Prune,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
pub enum EmbeddingModelArg {
    #[value(name = "qwen3_q8")]
    Qwen3Q8,
    #[value(name = "bge_m3")]
    BgeM3,
}

impl From<EmbeddingModelArg> for crate::config::embedding::EmbeddingModel {
    fn from(value: EmbeddingModelArg) -> Self {
        match value {
            EmbeddingModelArg::Qwen3Q8 => Self::Qwen3Q8,
            EmbeddingModelArg::BgeM3 => Self::BgeM3,
        }
    }
}

/// Operator-facing lineage choice for `models recommend`.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecClass {
    /// Refusal-ablated / uncensored fine-tune (operator default).
    Abliterated,
    /// Vanilla instruct GGUF.
    Standard,
}

impl From<RecClass> for VariantClass {
    fn from(c: RecClass) -> Self {
        match c {
            RecClass::Abliterated => VariantClass::Abliterated,
            RecClass::Standard => VariantClass::Standard,
        }
    }
}

const MODEL_NAMES: [&str; 4] = ["clip", "whisper", "whisper-candle", "whisper-faster"];

#[derive(Clone)]
enum ManagedModel {
    Clip {
        model_id: String,
        cache_path: std::path::PathBuf,
    },
    BgeM3(crate::providers::bge_m3_artifacts::BgeM3Artifacts),
    Whisper(crate::media::stt_provider::LocalWhisperTarget),
}

impl ManagedModel {
    fn model_id(&self) -> &str {
        match self {
            Self::Clip { model_id, .. } => model_id,
            Self::BgeM3(_) => crate::providers::bge_m3_artifacts::DEFAULT_REPO,
            Self::Whisper(target) => target.model_id(),
        }
    }

    fn cache_path(&self) -> &std::path::Path {
        match self {
            Self::Clip { cache_path, .. } => cache_path,
            Self::BgeM3(artifacts) => artifacts.cache_dir(),
            Self::Whisper(target) => target.cache_path(),
        }
    }

    fn backend(&self) -> &'static str {
        match self {
            Self::Clip { .. } => "clip",
            Self::BgeM3(_) => "bge-m3",
            Self::Whisper(target) => target.backend().as_str(),
        }
    }

    fn cache_health(&self) -> crate::media::model_manager::CacheHealth {
        match self {
            Self::Clip {
                model_id,
                cache_path,
            } => match cache_path.parent() {
                Some(models_root) => clip_engine::cache_health_at(models_root, model_id),
                None => crate::media::model_manager::CacheHealth::Corrupt {
                    path: cache_path.clone(),
                    reason: "CLIP cache path has no model root".to_string(),
                },
            },
            Self::BgeM3(artifacts) => artifacts.cache_health(),
            Self::Whisper(target) => target.cache_health(),
        }
    }

    fn verified_cache_health(
        &self,
        during_attempt: bool,
    ) -> crate::media::model_manager::CacheHealth {
        match self {
            Self::Clip {
                model_id,
                cache_path,
            } => match cache_path.parent() {
                Some(models_root) => {
                    clip_engine::verified_cache_health_at(models_root, model_id, during_attempt)
                }
                None => crate::media::model_manager::CacheHealth::Corrupt {
                    path: cache_path.clone(),
                    reason: "CLIP cache path has no model root".to_string(),
                },
            },
            Self::BgeM3(artifacts) => {
                if during_attempt {
                    crate::media::model_manager::verified_cache_health_during_install(
                        artifacts.cache_dir(),
                        crate::providers::bge_m3_artifacts::REQUIRED_ARTIFACTS,
                    )
                } else {
                    crate::providers::bge_m3_artifacts::verified_cache_health_at(
                        artifacts.cache_dir(),
                    )
                }
            }
            Self::Whisper(target) => target.verified_cache_health(during_attempt),
        }
    }

    fn policy_name(&self) -> &'static str {
        match self {
            Self::Clip { .. } => "clip",
            Self::BgeM3(_) => "bge-m3",
            Self::Whisper(_) => "whisper",
        }
    }

    fn cache_is_neoth_owned(&self) -> bool {
        match self {
            Self::Clip { .. } => true,
            Self::BgeM3(_) => true,
            Self::Whisper(target) => target.cache_is_neoth_owned(),
        }
    }
}

fn model_description(name: &str) -> &'static str {
    match name {
        "clip" => "CLIP ViT-B/32 image + text embeddings (vision Phase 2b)",
        "bge-m3" => "Pinned local BGE-M3 multilingual embedding artifacts",
        "whisper" => "Configured effective local Whisper transcription model",
        "whisper-candle" => "Explicit local Candle Whisper transcription model",
        "whisper-faster" => "Explicit local faster-whisper transcription model",
        _ => "unknown model",
    }
}

fn resolve_managed_model(
    neoth_home: &std::path::Path,
    name: &str,
    repo_override: Option<&str>,
    cfg: &FreedomConfig,
) -> Result<ManagedModel> {
    use crate::media::stt_dispatch::SttProvider;

    match name {
        "clip" => {
            let model_id = repo_override
                .unwrap_or(clip_engine::DEFAULT_CLIP_REPO)
                .to_string();
            let cache_path = clip_engine::cache_dir_at(&neoth_home.join("models"), &model_id);
            Ok(ManagedModel::Clip {
                model_id,
                cache_path,
            })
        }
        "bge-m3" => {
            if repo_override.is_some() {
                anyhow::bail!(
                    "BGE-M3 has an immutable reviewed repository and revision; use `neoth models bge-m3 pull` without overrides"
                );
            }
            Ok(ManagedModel::BgeM3(
                crate::providers::bge_m3_artifacts::BgeM3Artifacts::at_neoth_home(neoth_home),
            ))
        }
        "whisper" | "whisper-candle" | "whisper-faster" => {
            if repo_override.is_some() {
                anyhow::bail!(
                    "--repo is only supported for `clip`; Whisper repositories are pinned to \
                     `media.stt.model_size` so model management cannot drift from runtime"
                );
            }
            let backend = match name {
                "whisper" => cfg.media.stt.primary,
                "whisper-candle" => SttProvider::WhisperRsLocal,
                "whisper-faster" => SttProvider::FasterWhisperLocal,
                _ => unreachable!(),
            };
            crate::media::stt_provider::resolve_local_whisper_target(
                neoth_home,
                backend,
                cfg.media.stt.model_size,
            )
            .map(ManagedModel::Whisper)
            .map_err(|error| {
                let alias_hint = if name == "whisper" {
                    "; use `whisper-candle` or `whisper-faster` to manage an explicit local backend"
                } else {
                    ""
                };
                anyhow::anyhow!("cannot resolve model `{name}`: {error}{alias_hint}")
            })
        }
        other => anyhow::bail!(
            "unknown model id '{other}'. Known: {}",
            MODEL_NAMES.join(", ")
        ),
    }
}

pub async fn run_models(args: ModelsArgs) -> Result<()> {
    match args.action {
        ModelsAction::Ollama { config, action } => run_ollama(action, config, args.output).await,
        ModelsAction::List => run_list(&args.output),
        ModelsAction::Catalog => run_catalog(&args.output),
        ModelsAction::BgeM3 { action } => run_bge_m3(action, &args.output).await,
        ModelsAction::Embedding { config, action } => {
            run_embedding_models(action, config.as_deref(), &args.output).await
        }
        ModelsAction::Pull { name, repo } => run_pull(&name, repo.as_deref()).await,
        ModelsAction::Prune { name } => run_prune(&name),
        ModelsAction::Recommend {
            vram,
            class,
            offline,
        } => run_recommend(vram, class.into(), offline, &args.output).await,
        ModelsAction::Fit {
            gpu,
            bandwidth,
            vram,
        } => run_models_fit(gpu.as_deref(), bandwidth, vram, &args.output),
    }
}

async fn run_ollama(
    action: OllamaModelsAction,
    config: Option<PathBuf>,
    output: OutputFormat,
) -> Result<()> {
    let home = ollama_ipc_home(config.as_deref());
    let client = LocalModelsIpcClient::discover(&home).with_context(|| {
        format!(
            "local-model daemon IPC is unavailable for {}; start `neoth serve` and retry",
            home.display()
        )
    })?;

    match action {
        OllamaModelsAction::Status => {
            let snapshot = client
                .status()
                .await
                .context("read local-model daemon status")?;
            render_ollama_snapshot(&snapshot, output)
        }
        action => {
            let ack = match ollama_ipc_action(action) {
                OllamaIpcRequest::Start(action) => client.start(action).await,
                OllamaIpcRequest::Cancel(operation_id) => client.cancel(&operation_id).await,
            }
            .context("submit local-model daemon operation")?;
            render_ollama_ack(&ack, output)
        }
    }
}

/// Match `serve --config`: a custom config selects its parent instance home.
/// Without that override, preserve the ordinary `NEOTH_HOME`-aware default.
fn ollama_ipc_home(config: Option<&Path>) -> PathBuf {
    match config {
        Some(path) => path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(".")),
        None => FreedomConfig::default_neoth_home(),
    }
}

enum OllamaIpcRequest {
    Start(LocalModelAction),
    Cancel(String),
}

fn ollama_ipc_action(action: OllamaModelsAction) -> OllamaIpcRequest {
    match action {
        OllamaModelsAction::Pull { model } => {
            OllamaIpcRequest::Start(LocalModelAction::Pull { model })
        }
        OllamaModelsAction::Update { model } => {
            OllamaIpcRequest::Start(LocalModelAction::Update { model })
        }
        OllamaModelsAction::Prune { model } => {
            OllamaIpcRequest::Start(LocalModelAction::Prune { model })
        }
        OllamaModelsAction::Retry { operation_id } => {
            OllamaIpcRequest::Start(LocalModelAction::Retry {
                terminal_operation_id: operation_id,
            })
        }
        OllamaModelsAction::Cancel { operation_id } => OllamaIpcRequest::Cancel(operation_id),
        OllamaModelsAction::Status => {
            unreachable!("status is handled before IPC action conversion")
        }
    }
}

/// The JSON model snapshot is the daemon DTO without a separate CLI schema.
pub(crate) fn local_models_snapshot_wire(snapshot: &LocalModelsSnapshot) -> serde_json::Value {
    serde_json::to_value(snapshot).expect("LocalModelsSnapshot is serializable")
}

fn render_ollama_snapshot(snapshot: &LocalModelsSnapshot, output: OutputFormat) -> Result<()> {
    let wire = local_models_snapshot_wire(snapshot);
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!("{wire}"),
        OutputFormat::Table => {
            println!("local-model endpoint: {}", wire["endpoint"]);
            println!("observed_at_unix_ms: {}", wire["observed_at_unix_ms"]);
            println!("models: {}", wire["models"].as_array().map_or(0, Vec::len));
            if let Some(operation) = wire["active_operation"].as_object() {
                println!(
                    "active operation: {} ({})",
                    operation["operation_id"], operation["action"]
                );
            }
            for model in wire["models"].as_array().into_iter().flatten() {
                println!(
                    "{}  digest={}  size_bytes={}  readiness={}",
                    model["model"], model["digest"], model["size_bytes"], model["readiness"]
                );
            }
        }
    }
    Ok(())
}

fn render_ollama_ack(ack: &LocalModelActionAck, output: OutputFormat) -> Result<()> {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => println!("{}", serde_json::to_value(ack)?),
        OutputFormat::Table => {
            println!("operation accepted: {}", ack.ok);
            println!("action: {:?}", ack.action);
            if let Some(operation_id) = &ack.operation_id {
                println!("operation_id: {operation_id}");
            }
            if let Some(error) = &ack.error {
                println!("error: {:?}", error.code);
            }
            render_ollama_snapshot(&ack.snapshot, OutputFormat::Table)?;
        }
    }
    Ok(())
}

/// GOLD-ADAPT-ODY-13 — render the hardware-fit tok/s ranking.
fn run_models_fit(
    gpu: Option<&str>,
    bandwidth: Option<f64>,
    vram: Option<f64>,
    output: &crate::cli::OutputFormat,
) -> Result<()> {
    use crate::cli::OutputFormat;
    use crate::hwfit;

    // Resolve (label, bandwidth, vram) from the GPU table or explicit flags.
    let (label, bw, vr) = if let Some(name) = gpu {
        match hwfit::lookup_gpu(name) {
            Some(g) => (
                g.name.to_string(),
                bandwidth.unwrap_or(g.bandwidth_gb_s),
                vram.unwrap_or(g.vram_gb),
            ),
            None => {
                let bw = bandwidth.ok_or_else(|| {
                    anyhow::anyhow!(
                        "GPU `{name}` not in the built-in table — pass `--bandwidth <GB/s>` \
                         (and optionally `--vram <GB>`)"
                    )
                })?;
                (name.to_string(), bw, vram.unwrap_or(0.0))
            }
        }
    } else if let Some(bw) = bandwidth {
        ("custom".to_string(), bw, vram.unwrap_or(0.0))
    } else {
        // GOLD-ADAPT-ODY-13 — no --gpu/--bandwidth given → auto-detect the host
        // GPU (probe → built-in bandwidth table), so `neoth models fit` works
        // out-of-the-box. Clear error naming what was detected when it isn't in
        // the table. (The CLI scorer is ODY-13; the GUI model browser stays a
        // separate deferred item.)
        let report = crate::installers::gpu::probe_gpu();
        match report.name.as_deref().and_then(hwfit::lookup_gpu) {
            Some(g) => (
                g.name.to_string(),
                bandwidth.unwrap_or(g.bandwidth_gb_s),
                vram.unwrap_or(g.vram_gb),
            ),
            None => {
                let detected = report.name.as_deref().unwrap_or("none detected");
                anyhow::bail!(
                    "`models fit` needs a GPU: auto-detect found `{detected}` (not in the \
                     built-in table). Pass `--gpu <name>` (e.g. \"RTX 4090\") or \
                     `--bandwidth <GB/s>`."
                );
            }
        }
    };

    let candidates = hwfit::default_candidates();
    let ranked = hwfit::rank_models(vr, bw, &candidates);

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let rows: Vec<_> = ranked
                .iter()
                .map(|m| {
                    serde_json::json!({
                        "model": m.label,
                        "size_gb": m.size_gb,
                        "fits": m.fits,
                        "tok_s": (m.tok_s * 10.0).round() / 10.0,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "gpu": label,
                    "bandwidth_gb_s": bw,
                    "vram_gb": vr,
                    "models": rows,
                }))?
            );
        }
        OutputFormat::Table => {
            println!(
                "hardware fit — {label} ({bw:.0} GB/s{}):",
                if vr > 0.0 {
                    format!(", {vr:.0} GB VRAM")
                } else {
                    String::new()
                }
            );
            println!(
                "  {:<10} {:>8} {:>6} {:>10}",
                "model", "size", "fits", "~tok/s"
            );
            for m in &ranked {
                println!(
                    "  {:<10} {:>6.1}GB {:>6} {:>10.0}",
                    m.label,
                    m.size_gb,
                    if m.fits { "yes" } else { "no" },
                    m.tok_s
                );
            }
            println!(
                "  (estimate: memory-bandwidth-bound, ~0.55 efficiency; real tok/s varies by runtime)"
            );
        }
    }
    Ok(())
}

/// One recommended local-model choice: a size at a quant, resolved to a
/// concrete GGUF repo with the exact `ollama pull` command to run it.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RecCandidate {
    pub rank: usize,
    pub param_b: f32,
    pub quant: &'static str,
    pub est_vram_gb: f32,
    pub repo: String,
    pub class: &'static str,
    /// `hf.co/<repo>:<Q4_K_M|Q8_0>`.
    pub pull_ref: String,
    /// `["ollama", "pull", "<pull_ref>"]`.
    pub pull_command: Vec<String>,
}

/// Pure, deterministic recommendation core (curated repos, NO network): the
/// VRAM-fitting quantized shortlist, each resolved to its verified GGUF repo +
/// `ollama pull` command. `run_recommend` upgrades each repo to the live
/// newest/best unless `--offline`.
fn build_recommendation(vram_mib: Option<u32>, class: VariantClass) -> Vec<RecCandidate> {
    selector::quantized_shortlist(vram_mib)
        .into_iter()
        .enumerate()
        .map(|(i, opt)| {
            // GR-040 — nearest curated size for an exotic param_b (no exact
            // row → closest real model, not a silent 7B downgrade).
            let variant = gguf_variants::curated_or_nearest(opt.param_b, class);
            candidate_from(i + 1, &opt, variant)
        })
        .collect()
}

/// Assemble a [`RecCandidate`] from a shortlist option + resolved repo.
fn candidate_from(rank: usize, opt: &selector::QuantOption, variant: GgufVariant) -> RecCandidate {
    let pull_ref = variant.pull_ref(opt.quant);
    RecCandidate {
        rank,
        param_b: opt.param_b,
        quant: opt.quant.gguf_tag(),
        est_vram_gb: opt.est_vram_gb,
        class: variant.class.label(),
        repo: variant.repo,
        pull_command: ollama::pull_command(&pull_ref),
        pull_ref,
    }
}

async fn run_recommend(
    vram_override: Option<u32>,
    class: VariantClass,
    offline: bool,
    output: &OutputFormat,
) -> Result<()> {
    let vram_mib = vram_override.or_else(|| gpu::probe_gpu().vram_mib);
    // Deterministic curated base; then upgrade each to the live newest/best
    // unless offline.
    let mut candidates = build_recommendation(vram_mib, class);
    if !offline {
        for c in &mut candidates {
            let live = gguf_variants::resolve_gguf_repo(c.param_b, class).await;
            // Only adopt a live hit that actually came from the network (curated
            // fallback carries downloads == 0 and an empty timestamp); otherwise
            // keep the already-set curated repo.
            if live.downloads > 0 || !live.created_at.is_empty() {
                let quant = if c.quant == Quant::Q8.gguf_tag() {
                    Quant::Q8
                } else {
                    Quant::Q4
                };
                c.pull_ref = live.pull_ref(quant);
                c.pull_command = ollama::pull_command(&c.pull_ref);
                c.class = live.class.label();
                c.repo = live.repo;
            }
        }
    }

    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&candidates)?);
        }
        OutputFormat::Table => print_recommendation(vram_mib, &candidates),
    }
    Ok(())
}

fn print_recommendation(vram_mib: Option<u32>, candidates: &[RecCandidate]) {
    match vram_mib {
        Some(mib) => println!("Detected VRAM: {:.1} GiB", mib as f32 / 1024.0),
        None => println!("No GPU detected — sizing for a CPU/RAM operator."),
    }
    if candidates.is_empty() {
        println!("(no local model fits — use a cloud provider)");
        return;
    }
    println!(
        "Local models run QUANTIZED (Q4/Q8), abliterated-first. Pick one and run its command:\n"
    );
    for c in candidates {
        let star = if c.rank == 1 { "★" } else { " " };
        println!(
            "{star} #{}  {:>4.1}B {:<6} ~{:>4.1} GB VRAM  [{}]",
            c.rank, c.param_b, c.quant, c.est_vram_gb, c.class
        );
        println!("     {}", c.repo);
        println!("     $ {}", c.pull_command.join(" "));
    }
    println!(
        "\nThen point a hemisphere at Ollama's OpenAI-compatible endpoint:\n  {}",
        ollama::openai_compat_endpoint(ollama::DEFAULT_OLLAMA_PORT)
    );
}

fn load_models_config(neoth_home: &std::path::Path) -> Result<FreedomConfig> {
    let path = neoth_home.join("freedom.yaml");
    if !path.exists() {
        return Ok(FreedomConfig::default());
    }
    FreedomConfig::load_from_path(&path)
        .with_context(|| format!("load model configuration {}", path.display()))
}

/// `neoth models catalog` — H18. Pure read of the on-disk live catalog;
/// the daemon's refresh task keeps it current, this just surfaces it.
fn run_catalog(output: &OutputFormat) -> Result<()> {
    use crate::models::catalog::ModelsCatalog;
    let neoth_home = FreedomConfig::default_neoth_home();
    let catalog = ModelsCatalog::load_from(&ModelsCatalog::default_path(&neoth_home));
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&catalog)?);
        }
        OutputFormat::Table => {
            if catalog.providers.is_empty() {
                println!("# model catalog is empty — the daemon fills it on first provider use");
                return Ok(());
            }
            for (name, pc) in &catalog.providers {
                println!(
                    "# {name} — {} model(s){}",
                    pc.models.len(),
                    if pc.fetched_at_unix == 0 {
                        " (never fetched)"
                    } else {
                        ""
                    }
                );
                for m in &pc.models {
                    println!(
                        "  {}{}",
                        m.id,
                        if m.deprecated { "  [deprecated]" } else { "" }
                    );
                }
            }
        }
    }
    Ok(())
}

fn run_list(output: &OutputFormat) -> Result<()> {
    let neoth_home = FreedomConfig::default_neoth_home();
    let cfg = load_models_config(&neoth_home)?;
    let rows = build_list_rows(&neoth_home, &cfg)?;
    match output {
        OutputFormat::Table => print_table(&rows),
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&rows)?);
        }
    }
    Ok(())
}

fn build_list_rows(neoth_home: &std::path::Path, cfg: &FreedomConfig) -> Result<Vec<ListRow>> {
    let mut rows = MODEL_NAMES
        .iter()
        .map(
            |name| match resolve_managed_model(neoth_home, name, None, cfg) {
                Ok(model) => {
                    let health = model.cache_health();
                    Ok(ListRow {
                        name: (*name).to_string(),
                        backend: model.backend().to_string(),
                        description: model_description(name).to_string(),
                        repo: model.model_id().to_string(),
                        cache_dir: model.cache_path().display().to_string(),
                        cached: health.is_ready(),
                        health: health.label().to_string(),
                        error: matches!(
                            &health,
                            crate::media::model_manager::CacheHealth::Corrupt { .. }
                        )
                        .then(|| health.to_string()),
                    })
                }
                Err(error) if *name == "whisper" => Ok(ListRow {
                    name: (*name).to_string(),
                    backend: cfg.media.stt.primary.as_str().to_string(),
                    description: model_description(name).to_string(),
                    repo: String::new(),
                    cache_dir: String::new(),
                    cached: false,
                    health: "unavailable".to_string(),
                    error: Some(error.to_string()),
                }),
                Err(error) => Err(error),
            },
        )
        .collect::<Result<Vec<_>>>()?;
    let bge_artifacts =
        crate::providers::bge_m3_artifacts::BgeM3Artifacts::at_neoth_home(neoth_home);
    // Inventory stays cheap and artifact-only: it must never hash the
    // multi-GiB checkpoint or claim that the Candle adapter has loaded.
    let bge_health = bge_artifacts.cache_health();
    rows.push(ListRow {
        name: "bge-m3".to_string(),
        backend: "local-bge-m3".to_string(),
        description: model_description("bge-m3").to_string(),
        repo: format!(
            "{}@{}",
            crate::providers::bge_m3_artifacts::DEFAULT_REPO,
            crate::providers::bge_m3_artifacts::DEFAULT_REVISION,
        ),
        cache_dir: bge_artifacts.cache_dir().display().to_string(),
        cached: bge_health.is_ready(),
        health: if bge_health.is_ready() {
            "cached".to_string()
        } else {
            bge_health.label().to_string()
        },
        error: (!bge_health.is_ready()).then(|| bge_health.to_string()),
    });
    let tts = &cfg.media.tts;
    let voice = if tts.voice.is_empty() {
        crate::media::tts_dispatch::pick_voice_for_locale(
            &tts.locale,
            crate::media::tts_dispatch::TtsProvider::Piper,
        )
        .unwrap_or("")
        .to_string()
    } else {
        tts.voice.clone()
    };
    let piper_root = neoth_home.join("models/piper");
    let piper = crate::media::tts_provider::piper_status(
        &piper_root,
        tts.piper_model.as_deref(),
        tts.piper_config.as_deref(),
        &voice,
    );
    rows.push(match piper {
        Ok(assets) => ListRow {
            name: "piper".to_string(),
            backend: "piper-cli".to_string(),
            description: "Operator-provided local Piper ONNX voice (no automatic download)"
                .to_string(),
            repo: "operator-provided".to_string(),
            cache_dir: assets.model.display().to_string(),
            cached: true,
            health: "ready".to_string(),
            error: None,
        },
        Err(error) => ListRow {
            name: "piper".to_string(),
            backend: "piper-cli".to_string(),
            description: "Operator-provided local Piper ONNX voice (no automatic download)"
                .to_string(),
            repo: "operator-provided".to_string(),
            cache_dir: piper_root.display().to_string(),
            cached: false,
            health: "unavailable".to_string(),
            error: Some(error),
        },
    });
    Ok(rows)
}

fn print_table(rows: &[ListRow]) {
    println!(
        "NAME              STATUS   BACKEND                   REPO                         CACHE"
    );
    println!("{}", "─".repeat(130));
    for r in rows {
        println!(
            "{:<17} {:<8} {:<25} {:<28} {}",
            r.name, r.health, r.backend, r.repo, r.cache_dir
        );
        println!("                  {}", r.description);
        if let Some(error) = &r.error {
            println!("                  unavailable: {error}");
        }
    }
}

#[derive(Debug, serde::Serialize)]
struct ListRow {
    name: String,
    backend: String,
    description: String,
    repo: String,
    cache_dir: String,
    cached: bool,
    health: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

const EMBEDDING_STATUS_SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum EmbeddingArtifactState {
    Unavailable,
    Installed,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum EmbeddingReadinessState {
    Unavailable,
    Installed,
    Ready,
    ReachableButUnready,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EmbeddingActions {
    probe: bool,
    pull: bool,
    repair: bool,
    prune: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EmbeddingStatusRow {
    model: String,
    artifact_state: EmbeddingArtifactState,
    readiness_state: EmbeddingReadinessState,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    repository: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revision: Option<String>,
    actions: EmbeddingActions,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EmbeddingStatusSnapshot {
    schema_version: u8,
    observed_at_unix_ms: u64,
    selected_model: String,
    source: String,
    rows: Vec<EmbeddingStatusRow>,
}

fn embedding_observed_at_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn embedding_snapshot(home: &Path, cfg: &FreedomConfig) -> EmbeddingStatusSnapshot {
    let bge = crate::providers::bge_m3_artifacts::BgeM3Artifacts::at_neoth_home(home);
    let health = bge.cache_health();
    let bge_installed = health.is_ready();
    let bge_selected = matches!(
        cfg.embed.model,
        crate::config::embedding::EmbeddingModel::BgeM3
    );
    let (bge_repo, bge_revision) = crate::providers::local_bge_m3::pinned_model_identity();
    EmbeddingStatusSnapshot {
        schema_version: EMBEDDING_STATUS_SCHEMA_VERSION,
        observed_at_unix_ms: embedding_observed_at_unix_ms(),
        selected_model: cfg.embed.model.as_str().to_string(),
        source: "status".to_string(),
        rows: vec![
            EmbeddingStatusRow {
                model: "qwen3_q8".to_string(),
                artifact_state: EmbeddingArtifactState::Unavailable,
                readiness_state: EmbeddingReadinessState::Unavailable,
                reason: Some("not supported: Qwen has no verified read-only CLI load probe or standalone lifecycle".to_string()),
                repository: None, revision: None,
                actions: EmbeddingActions { probe: false, pull: false, repair: false, prune: false },
            },
            EmbeddingStatusRow {
                model: "bge_m3".to_string(),
                artifact_state: if bge_installed { EmbeddingArtifactState::Installed } else { EmbeddingArtifactState::Unavailable },
                readiness_state: if bge_installed { EmbeddingReadinessState::Installed } else { EmbeddingReadinessState::Unavailable },
                reason: if !bge_selected { Some("select embed.model=bge_m3 to enable BGE lifecycle actions".to_string()) } else { (!bge_installed).then(|| health.to_string()) },
                repository: Some(bge_repo.to_string()),
                revision: Some(bge_revision.to_string()),
                actions: EmbeddingActions { probe: bge_selected, pull: bge_selected, repair: bge_selected, prune: bge_selected },
            },
        ],
    }
}

fn embedding_scope(config: Option<&Path>) -> (PathBuf, PathBuf) {
    let home = ollama_ipc_home(config);
    let path = config
        .map(Path::to_path_buf)
        .unwrap_or_else(|| home.join("freedom.yaml"));
    (home, path)
}

fn render_embedding_snapshot(
    snapshot: &EmbeddingStatusSnapshot,
    output: &OutputFormat,
) -> Result<()> {
    match output {
        OutputFormat::Json | OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string(&snapshot)?)
        }
        OutputFormat::Table => {
            println!("Embedding selection: {}", snapshot.selected_model);
            for row in &snapshot.rows {
                println!(
                    "{}  artifact={:?} readiness={:?}",
                    row.model, row.artifact_state, row.readiness_state
                );
            }
        }
    }
    Ok(())
}

fn select_embedding_model(
    path: &Path,
    selected: crate::config::embedding::EmbeddingModel,
) -> Result<FreedomConfig> {
    FreedomConfig::update_at(path, |current| {
        current.embed.model = selected;
        Ok(())
    })?;
    let readback = FreedomConfig::load_from_path(path)?;
    anyhow::ensure!(
        readback.embed.model == selected,
        "embedding selection readback did not retain the requested model"
    );
    Ok(readback)
}

async fn run_embedding_models(
    action: EmbeddingModelsAction,
    config: Option<&Path>,
    output: &OutputFormat,
) -> Result<()> {
    let (home, path) = embedding_scope(config);
    let mut cfg = if config.is_some() {
        FreedomConfig::load_from_path(&path)?
    } else {
        load_models_config(&home)?
    };
    match action {
        EmbeddingModelsAction::List | EmbeddingModelsAction::Status => {
            render_embedding_snapshot(&embedding_snapshot(&home, &cfg), output)
        }
        EmbeddingModelsAction::Select { model } => {
            cfg = select_embedding_model(&path, model.into())?;
            render_embedding_snapshot(&embedding_snapshot(&home, &cfg), output)
        }
        EmbeddingModelsAction::Probe => {
            anyhow::ensure!(
                matches!(
                    cfg.embed.model,
                    crate::config::embedding::EmbeddingModel::BgeM3
                ),
                "qwen3_q8 has no verified read-only load probe; it remains unavailable until a no-download runtime probe exists"
            );
            let readiness =
                crate::providers::local_embedding_readiness_from_config_at(&cfg, &home).await;
            let readback = FreedomConfig::load_from_path(&path)?;
            anyhow::ensure!(
                readback.embed.model == cfg.embed.model
                    && readback.inference.embedding_provider == cfg.inference.embedding_provider,
                "embedding configuration changed during probe; refusing stale ready result"
            );
            let mut snapshot = embedding_snapshot(&home, &cfg);
            snapshot.source = "probe".to_string();
            let row = snapshot
                .rows
                .iter_mut()
                .find(|row| row.model == cfg.embed.model.as_str())
                .expect("closed embedding row");
            match readiness {
                crate::providers::LocalEmbeddingReadiness::Ready { .. } => {
                    row.readiness_state = EmbeddingReadinessState::Ready;
                    row.reason = None;
                }
                crate::providers::LocalEmbeddingReadiness::Unavailable { reason, .. } => {
                    row.readiness_state = EmbeddingReadinessState::ReachableButUnready;
                    row.reason = Some(reason);
                }
            }
            render_embedding_snapshot(&snapshot, output)
        }
        EmbeddingModelsAction::Pull | EmbeddingModelsAction::Repair => {
            anyhow::ensure!(
                matches!(
                    cfg.embed.model,
                    crate::config::embedding::EmbeddingModel::BgeM3
                ),
                "pull/repair are supported only when embed.model=bge_m3; Qwen has no standalone lifecycle owner"
            );
            run_pull_with_config(&home, &cfg, "bge-m3", None, true).await?;
            let cfg = FreedomConfig::load_from_path(&path)?;
            render_embedding_snapshot(&embedding_snapshot(&home, &cfg), output)
        }
        EmbeddingModelsAction::Prune => {
            anyhow::ensure!(
                matches!(
                    cfg.embed.model,
                    crate::config::embedding::EmbeddingModel::BgeM3
                ),
                "prune is supported only when embed.model=bge_m3; Qwen has no standalone lifecycle owner"
            );
            run_prune_with_config(&home, &cfg, "bge-m3", true)?;
            let cfg = FreedomConfig::load_from_path(&path)?;
            render_embedding_snapshot(&embedding_snapshot(&home, &cfg), output)
        }
    }
}

async fn run_bge_m3(action: BgeM3ModelsAction, output: &OutputFormat) -> Result<()> {
    match action {
        BgeM3ModelsAction::List | BgeM3ModelsAction::Status => {
            run_embedding_models(EmbeddingModelsAction::Status, None, output).await
        }
        BgeM3ModelsAction::Pull | BgeM3ModelsAction::Repair => run_pull("bge-m3", None).await,
        BgeM3ModelsAction::Prune => run_prune("bge-m3"),
    }
}

enum PullAuditSink {
    Wal(crate::wal::writer::WalWriterHandle),
    Daemon { home: std::path::PathBuf },
}

#[async_trait::async_trait]
impl crate::media::model_manager::ModelDownloadAuditSink for PullAuditSink {
    async fn append_model_download(&self, event_type: u8, payload: Vec<u8>) -> Result<()> {
        match self {
            Self::Wal(writer) => {
                crate::media::model_manager::ModelDownloadAuditSink::append_model_download(
                    writer, event_type, payload,
                )
                .await
            }
            Self::Daemon { home } => {
                crate::daemon::audit_rpc::try_post_audit_frame(home, event_type, &payload)
                    .await
                    .context("forward mandatory model-download audit frame to daemon")
            }
        }
    }
}

#[async_trait::async_trait]
trait WhisperPrefetcher: Send + Sync {
    async fn prefetch(
        &self,
        target: &crate::media::stt_provider::LocalWhisperTarget,
        updater_cfg: &crate::config::ops::UpdaterConfig,
        attempt: Option<&crate::media::model_manager::ModelDownloadAttempt>,
    ) -> Result<()>;
}

struct RuntimeWhisperPrefetcher;

#[async_trait::async_trait]
impl WhisperPrefetcher for RuntimeWhisperPrefetcher {
    async fn prefetch(
        &self,
        target: &crate::media::stt_provider::LocalWhisperTarget,
        updater_cfg: &crate::config::ops::UpdaterConfig,
        attempt: Option<&crate::media::model_manager::ModelDownloadAttempt>,
    ) -> Result<()> {
        crate::media::stt_provider::prefetch_local_whisper(target, updater_cfg, attempt)
            .await
            .map_err(|error| anyhow::anyhow!("prefetch Whisper model: {error}"))
    }
}

async fn execute_pull_with(
    target: &ManagedModel,
    updater_cfg: &crate::config::ops::UpdaterConfig,
    whisper_prefetcher: &dyn WhisperPrefetcher,
    attempt: Option<&crate::media::model_manager::ModelDownloadAttempt>,
) -> Result<()> {
    match target {
        ManagedModel::Clip {
            model_id,
            cache_path,
        } => {
            tracing::info!(repo = %model_id, "pulling CLIP artifacts");
            let models_root = cache_path.parent().ok_or_else(|| {
                anyhow::anyhow!(
                    "CLIP cache path has no model root: {}",
                    cache_path.display()
                )
            })?;
            let engine = match attempt {
                Some(attempt) => {
                    clip_engine::ClipEngine::prefetch_with_models_root(
                        Some(model_id.clone()),
                        models_root,
                        attempt,
                    )
                    .await
                }
                None => {
                    clip_engine::ClipEngine::open_with_models_root(
                        Some(model_id.clone()),
                        models_root,
                    )
                    .await
                }
            }
            .with_context(|| "pull CLIP artifacts")?;
            engine
                .validate_load()
                .await
                .with_context(|| "validate CLIP backend")?;
            Ok(())
        }
        ManagedModel::BgeM3(artifacts) => {
            tracing::info!(
                repo = crate::providers::bge_m3_artifacts::DEFAULT_REPO,
                revision = crate::providers::bge_m3_artifacts::DEFAULT_REVISION,
                "pulling pinned BGE-M3 artifacts"
            );
            let verified = match attempt {
                Some(attempt) => artifacts
                    .acquire_from_hf(attempt)
                    .await
                    .context("pull pinned BGE-M3 artifacts"),
                None => {
                    let artifacts = artifacts.clone();
                    tokio::task::spawn_blocking(move || artifacts.verify())
                        .await
                        .context("join pinned BGE-M3 artifact verification")?
                        .context("verify pinned BGE-M3 artifacts")
                }
            }?;
            let adapter =
                crate::providers::local_bge_m3::LocalBgeM3Adapter::open_verified(verified)
                    .context("open verified BGE-M3 adapter")?;
            adapter
                .validate_load()
                .await
                .context("validate pinned BGE-M3 adapter load")
        }
        ManagedModel::Whisper(target) => {
            tracing::info!(
                backend = target.backend().as_str(),
                repo = target.model_id(),
                "pulling Whisper artifacts"
            );
            whisper_prefetcher
                .prefetch(target, updater_cfg, attempt)
                .await
        }
    }
}

async fn run_pull(name: &str, repo_override: Option<&str>) -> Result<()> {
    run_pull_at(&FreedomConfig::default_neoth_home(), name, repo_override).await
}

async fn run_pull_at(neoth_home: &Path, name: &str, repo_override: Option<&str>) -> Result<()> {
    let cfg = load_models_config(&neoth_home)?;
    run_pull_with_config(neoth_home, &cfg, name, repo_override, false).await
}

async fn run_pull_with_config(
    neoth_home: &Path,
    cfg: &FreedomConfig,
    name: &str,
    repo_override: Option<&str>,
    quiet: bool,
) -> Result<()> {
    let target = resolve_managed_model(neoth_home, name, repo_override, cfg)?;
    let model_id = target.model_id().to_string();
    let cache_dir = target.cache_path().to_path_buf();
    let mut attempt = crate::media::model_manager::ModelDownloadAttempt::acquire(
        &cache_dir, &model_id, "explicit",
    )
    .await
    .context("acquire model-download lifecycle")?;

    let health_target = target.clone();
    let during_attempt = attempt.is_pending();
    let initial_health =
        tokio::task::spawn_blocking(move || health_target.verified_cache_health(during_attempt))
            .await
            .context("join model cache integrity check")?;
    let lifecycle_needed = attempt.is_pending() || !initial_health.is_ready();

    let mut audit_completion = None;
    let audit_sink = if lifecycle_needed {
        let pidfile = neoth_home.join("neothd.pid");
        let daemon_live = crate::daemon::pidfile::live_daemon_pid(&pidfile)
            .with_context(|| format!("inspect daemon pidfile {}", pidfile.display()))?
            .is_some();
        if daemon_live {
            Some(PullAuditSink::Daemon {
                home: neoth_home.to_path_buf(),
            })
        } else {
            let wal_dir = neoth_home.join("wal");
            std::fs::create_dir_all(&wal_dir)
                .with_context(|| format!("create model-download WAL dir {}", wal_dir.display()))?;
            let segment = crate::wal::writer::unique_standalone_segment_path(
                &wal_dir,
                "explicit-model-download",
            );
            let (writer, completion) = crate::wal::writer::spawn_for_home_with_completion(
                segment,
                neoth_home.to_path_buf(),
            )
            .context("spawn mandatory home-bound model-download WAL writer")?;
            audit_completion = Some(completion);
            Some(PullAuditSink::Wal(writer))
        }
    } else {
        None
    };

    let operation_result: Result<()> = async {
        if let Some(crate::media::model_manager::PendingModelDownloadOutcome::Failed { .. }) =
            attempt.pending_outcome()
        {
            attempt
                .replay_terminal(
                    audit_sink
                        .as_ref()
                        .context("pending failed attempt has no mandatory audit sink")?,
                )
                .await
                .context("replay pending failed MODEL_DOWNLOAD_COMPLETE")?;
        }

        let health_target = target.clone();
        let during_attempt = attempt.is_pending();
        let health = tokio::task::spawn_blocking(move || {
            health_target.verified_cache_health(during_attempt)
        })
        .await
        .context("join model cache integrity recheck")?;
        let network_needed = !health.is_ready();

        if network_needed
            && matches!(
                attempt.pending_outcome(),
                Some(crate::media::model_manager::PendingModelDownloadOutcome::Ready)
            )
        {
            let reason = format!("pending ready model generation no longer validates: {health}");
            attempt
                .finish_failed(
                    audit_sink
                        .as_ref()
                        .context("pending ready attempt has no mandatory audit sink")?,
                    &reason,
                )
                .await
                .context("correct stale pending ready outcome")?;
            anyhow::bail!("{reason}; retry the pull to start a fresh attempt");
        }

        if network_needed {
            if let Err(policy_error) = cfg
                .updater
                .check_model_download(&model_id, Some(target.policy_name()))
            {
                let message = policy_error.to_string();
                if attempt.is_pending() {
                    attempt
                        .finish_failed(
                            audit_sink
                                .as_ref()
                                .context("pending policy failure has no mandatory audit sink")?,
                            &message,
                        )
                        .await
                        .context("append policy-failed MODEL_DOWNLOAD_COMPLETE")?;
                }
                anyhow::bail!("{message}");
            }
            attempt
                .ensure_started(
                    audit_sink
                        .as_ref()
                        .context("model download has no mandatory audit sink")?,
                )
                .await
                .context("append mandatory MODEL_DOWNLOAD_START")?;
        } else if attempt.is_pending()
            && attempt.pending_outcome().is_none()
            && !attempt.network_authorized(&cache_dir, &model_id)
        {
            attempt
                .ensure_started(
                    audit_sink
                        .as_ref()
                        .context("pending model recovery has no mandatory audit sink")?,
                )
                .await
                .context("recover pending MODEL_DOWNLOAD_START")?;
        }

        let lifecycle_attempt = attempt.is_pending().then_some(&attempt);
        let pull_result = execute_pull_with(
            &target,
            &cfg.updater,
            &RuntimeWhisperPrefetcher,
            lifecycle_attempt,
        )
        .await;
        finalize_model_pull(&mut attempt, audit_sink.as_ref(), &cache_dir, pull_result).await
    }
    .await;

    drop(attempt);
    drop(audit_sink);
    let audit_shutdown = match audit_completion {
        Some(completion) => completion
            .wait()
            .await
            .context("finalize mandatory model-download WAL writer"),
        None => Ok(()),
    };
    match (operation_result, audit_shutdown) {
        (Ok(()), Ok(())) => {}
        (Err(error), Ok(())) => return Err(error),
        (Ok(()), Err(error)) => return Err(error),
        (Err(operation), Err(shutdown)) => {
            return Err(anyhow::anyhow!(
                "{operation:#}; additionally failed to close model-download audit WAL: {shutdown:#}"
            ));
        }
    }

    if !quiet {
        println!("{} cached at {}", name, cache_dir.display());
    }
    Ok(())
}

/// Complete the durable D7/D8 lifecycle after the concrete loader returns.
/// A BGE-M3 artifact may hash correctly yet still fail its real Candle load;
/// that error must take the failed D8 path and can never publish ready.
async fn finalize_model_pull(
    attempt: &mut crate::media::model_manager::ModelDownloadAttempt,
    audit_sink: Option<&PullAuditSink>,
    cache_dir: &Path,
    pull_result: Result<()>,
) -> Result<()> {
    match pull_result {
        Ok(()) => {
            if attempt.is_pending() {
                attempt
                    .finish_ready(
                        audit_sink
                            .context("completed model attempt has no mandatory audit sink")?,
                        cache_dir,
                    )
                    .await
                    .context("append mandatory ready MODEL_DOWNLOAD_COMPLETE")?;
            }
            Ok(())
        }
        Err(error) => {
            if attempt.is_pending() {
                let terminal = attempt
                    .finish_failed(
                        audit_sink.context("failed model attempt has no mandatory audit sink")?,
                        &format!("{error:#}"),
                    )
                    .await;
                if let Err(audit_error) = terminal {
                    anyhow::bail!(
                        "model pull failed: {error:#}; terminal D8 failed: {audit_error:#}"
                    );
                }
            }
            Err(error)
        }
    }
}

fn run_prune(name: &str) -> Result<()> {
    run_prune_at(&FreedomConfig::default_neoth_home(), name)
}

fn run_prune_at(neoth_home: &Path, name: &str) -> Result<()> {
    let cfg = load_models_config(neoth_home)?;
    run_prune_with_config(neoth_home, &cfg, name, false)
}

fn run_prune_with_config(
    neoth_home: &Path,
    cfg: &FreedomConfig,
    name: &str,
    quiet: bool,
) -> Result<()> {
    let target = resolve_managed_model(neoth_home, name, None, cfg)?;
    prune_target_with_output(name, &target, neoth_home, quiet)
}

fn prune_target(name: &str, target: &ManagedModel, neoth_home: &std::path::Path) -> Result<()> {
    prune_target_with_output(name, target, neoth_home, false)
}

fn prune_target_with_output(
    name: &str,
    target: &ManagedModel,
    neoth_home: &std::path::Path,
    quiet: bool,
) -> Result<()> {
    let dir = target.cache_path();
    if !target.cache_is_neoth_owned() {
        anyhow::bail!(
            "refusing to prune shared/external model cache `{}`; unset the Hugging Face cache \
             override or remove that cache with its owning tool",
            dir.display()
        );
    }
    let owned_roots = [
        neoth_home.join("models"),
        neoth_home.join("cache").join("huggingface").join("hub"),
    ];
    let Some(owned_root) = owned_roots.iter().find(|root| dir.starts_with(root)) else {
        anyhow::bail!(
            "refusing to prune shared/external model cache `{}`; NEOTH only removes caches below \
             `{}` or `{}`",
            dir.display(),
            owned_roots[0].display(),
            owned_roots[1].display()
        );
    };
    let _model_lock = crate::media::model_manager::lock_model_cache_blocking(dir)
        .with_context(|| format!("lock model cache before prune {}", dir.display()))?;
    if crate::media::model_manager::has_pending_download(dir)? {
        anyhow::bail!(
            "refusing to prune `{}` while a model-download D7/D8 attempt is pending; retry `neoth models pull {name}` to reconcile it first",
            dir.display()
        );
    }
    let metadata = match std::fs::symlink_metadata(dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if !quiet {
                println!("{} already absent at {}", name, dir.display());
            }
            return Ok(());
        }
        Err(error) => {
            return Err(error).with_context(|| format!("inspect model cache {}", dir.display()));
        }
    };
    if metadata.file_type().is_symlink() {
        anyhow::bail!(
            "refusing to prune symlinked model cache `{}`; remove the link explicitly",
            dir.display()
        );
    }
    if !metadata.is_dir() {
        anyhow::bail!(
            "refusing to prune model cache `{}` because it is not a directory",
            dir.display()
        );
    }
    let canonical_root = std::fs::canonicalize(owned_root)
        .with_context(|| format!("canonicalize owned model root {}", owned_root.display()))?;
    let canonical_dir = std::fs::canonicalize(dir)
        .with_context(|| format!("canonicalize model cache {}", dir.display()))?;
    if !canonical_dir.starts_with(&canonical_root) {
        anyhow::bail!(
            "refusing model cache path `{}` because it resolves outside owned root `{}`",
            dir.display(),
            owned_root.display()
        );
    }
    let relative = dir.strip_prefix(owned_root).with_context(|| {
        format!(
            "model cache {} is not below owned root {}",
            dir.display(),
            owned_root.display()
        )
    })?;
    let mut cursor = owned_root.to_path_buf();
    for component in std::iter::once(None).chain(relative.components().map(Some)) {
        if let Some(component) = component {
            cursor.push(component.as_os_str());
        }
        let entry = std::fs::symlink_metadata(&cursor)
            .with_context(|| format!("inspect model cache ancestor {}", cursor.display()))?;
        if entry.file_type().is_symlink() {
            anyhow::bail!(
                "refusing to prune model cache through symlinked ancestor `{}`",
                cursor.display()
            );
        }
    }
    if dir.file_name().is_none() || dir.parent().is_none() {
        anyhow::bail!("refusing unsafe model cache path `{}`", dir.display());
    }
    std::fs::remove_dir_all(dir).with_context(|| format!("remove_dir_all {}", dir.display()))?;
    if !quiet {
        println!("removed {} ({})", dir.display(), target.model_id());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Debug, Parser)]
    struct ModelsCli {
        #[command(flatten)]
        args: ModelsArgs,
    }

    struct EnvGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &std::path::Path) -> Self {
            let previous = std::env::var_os(key);
            unsafe { std::env::set_var(key, value) };
            Self { key, previous }
        }

        fn remove(key: &'static str) -> Self {
            let previous = std::env::var_os(key);
            unsafe { std::env::remove_var(key) };
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => unsafe { std::env::set_var(self.key, value) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    #[test]
    fn ollama_nested_commands_preserve_exact_selectors_and_operation_ids() {
        let pull =
            ModelsCli::try_parse_from(["models", "ollama", "pull", "qwen2.5:7b-instruct-q4_K_M"])
                .expect("ollama pull parses");
        assert!(matches!(
            ollama_ipc_action(match pull.args.action {
                ModelsAction::Ollama { action, .. } => action,
                _ => unreachable!("expected ollama action"),
            }),
            OllamaIpcRequest::Start(LocalModelAction::Pull { model }) if model == "qwen2.5:7b-instruct-q4_K_M"
        ));
        let cancel = ModelsCli::try_parse_from(["models", "ollama", "cancel", "op-01ABC"])
            .expect("ollama cancel parses");
        assert!(matches!(
            ollama_ipc_action(match cancel.args.action {
                ModelsAction::Ollama { action, .. } => action,
                _ => unreachable!("expected ollama action"),
            }),
            OllamaIpcRequest::Cancel(operation_id) if operation_id == "op-01ABC"
        ));
    }

    #[test]
    fn bge_m3_nested_commands_have_no_mutable_artifact_selectors() {
        let pull = ModelsCli::try_parse_from(["models", "bge-m3", "pull"])
            .expect("pinned BGE-M3 pull parses");
        assert!(matches!(
            pull.args.action,
            ModelsAction::BgeM3 {
                action: BgeM3ModelsAction::Pull
            }
        ));
        let repair = ModelsCli::try_parse_from(["models", "bge-m3", "repair"])
            .expect("pinned BGE-M3 repair parses");
        assert!(matches!(
            repair.args.action,
            ModelsAction::BgeM3 {
                action: BgeM3ModelsAction::Repair
            }
        ));
        assert!(
            ModelsCli::try_parse_from(["models", "bge-m3", "pull", "--repo", "other/model"])
                .is_err()
        );
        assert!(
            ModelsCli::try_parse_from(["models", "bge-m3", "pull", "--revision", "main"]).is_err()
        );
    }

    #[test]
    fn embedding_commands_bind_config_and_closed_selection() {
        let cli = ModelsCli::try_parse_from([
            "models",
            "embedding",
            "--config",
            "C:/instances/blue/freedom.yaml",
            "select",
            "bge_m3",
        ])
        .unwrap();
        assert!(matches!(
            cli.args.action,
            ModelsAction::Embedding {
                config: Some(_),
                action: EmbeddingModelsAction::Select {
                    model: EmbeddingModelArg::BgeM3
                }
            }
        ));
        assert!(
            ModelsCli::try_parse_from(["models", "embedding", "select", "remote_model"]).is_err()
        );
    }

    #[test]
    fn cheap_embedding_status_never_claims_fresh_ready() {
        let home = tempfile::tempdir().unwrap();
        let snapshot = embedding_snapshot(home.path(), &FreedomConfig::default());
        assert_eq!(snapshot.schema_version, EMBEDDING_STATUS_SCHEMA_VERSION);
        assert_eq!(snapshot.source, "status");
        assert_eq!(snapshot.rows.len(), 2);
        assert!(
            snapshot
                .rows
                .iter()
                .all(|row| !matches!(row.readiness_state, EmbeddingReadinessState::Ready))
        );
    }

    #[test]
    fn embedding_actions_follow_the_selected_model() {
        let home = tempfile::tempdir().unwrap();
        let qwen = embedding_snapshot(home.path(), &FreedomConfig::default());
        assert!(!qwen.rows[0].actions.probe);
        assert!(!qwen.rows[1].actions.pull);
        let mut bge_cfg = FreedomConfig::default();
        bge_cfg.embed.model = crate::config::embedding::EmbeddingModel::BgeM3;
        let bge = embedding_snapshot(home.path(), &bge_cfg);
        assert!(
            bge.rows[1].actions.probe
                && bge.rows[1].actions.pull
                && bge.rows[1].actions.repair
                && bge.rows[1].actions.prune
        );
    }

    #[test]
    fn embedding_select_transaction_reads_back_custom_named_config_and_preserves_other_fields() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("operator-blue.yaml");
        std::fs::write(
            &path,
            "operator_id: blue-operator\nonboarding_complete: true\n",
        )
        .unwrap();
        let readback =
            select_embedding_model(&path, crate::config::embedding::EmbeddingModel::BgeM3).unwrap();
        assert_eq!(
            readback.embed.model,
            crate::config::embedding::EmbeddingModel::BgeM3
        );
        let rendered = std::fs::read_to_string(&path).unwrap();
        assert!(rendered.contains("operator_id: blue-operator"));
        assert!(rendered.contains("onboarding_complete: true"));
        assert!(!home.path().join("freedom.yaml").exists());
    }

    #[test]
    fn embedding_status_json_is_a_single_strict_snapshot() {
        let home = tempfile::tempdir().unwrap();
        let snapshot = embedding_snapshot(home.path(), &FreedomConfig::default());
        let json = serde_json::to_string(&snapshot).unwrap();
        let decoded: EmbeddingStatusSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.schema_version, EMBEDDING_STATUS_SCHEMA_VERSION);
        assert_eq!(decoded.source, "status");
        let mut unknown = serde_json::to_value(&snapshot).unwrap();
        unknown["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<EmbeddingStatusSnapshot>(unknown).is_err());
    }

    #[tokio::test]
    async fn bge_m3_load_failure_records_failed_d8_and_never_ready() {
        let home = tempfile::tempdir().unwrap();
        let cache_dir = home.path().join("models").join("bge-m3");
        let (writer, join) = crate::wal::writer::spawn(home.path().join("attempt.wal")).unwrap();
        let sink = PullAuditSink::Wal(writer);
        let mut attempt = crate::media::model_manager::ModelDownloadAttempt::acquire(
            &cache_dir,
            crate::providers::bge_m3_artifacts::DEFAULT_REPO,
            "explicit",
        )
        .await
        .unwrap();
        attempt.ensure_started(&sink).await.unwrap();

        let error = finalize_model_pull(
            &mut attempt,
            Some(&sink),
            &cache_dir,
            Err(anyhow::anyhow!(
                "BGE-M3 adapter load rejected pinned artifacts"
            )),
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("adapter load rejected"));
        assert!(
            !crate::media::model_manager::has_pending_download(&cache_dir).unwrap(),
            "a durably accepted failed D8 clears the pending marker"
        );
        drop(attempt);
        drop(sink);
        join.await.unwrap();

        let bytes = std::fs::read(home.path().join("attempt.wal")).unwrap();
        let mut terminal_statuses = Vec::new();
        crate::wal::scan::for_each_frame(&bytes, |_, frame| {
            if frame.header.event_type == crate::wal::events::EVENT_TYPE_MODEL_DOWNLOAD_COMPLETE {
                let payload: serde_json::Value = serde_json::from_slice(frame.payload)?;
                terminal_statuses.push((
                    payload["status"].as_str().unwrap_or_default().to_string(),
                    payload["reason"].as_str().map(str::to_string),
                ));
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(terminal_statuses.len(), 1);
        assert_eq!(terminal_statuses[0].0, "failed");
        assert!(
            terminal_statuses[0]
                .1
                .as_deref()
                .is_some_and(|reason| reason.contains("adapter load rejected"))
        );
    }

    #[tokio::test]
    #[ignore = "requires a hosted runner with the hash-verified official BGE-M3 cache"]
    async fn bge_m3_retained_ready_marker_is_healthy_only_for_its_recovery_attempt() {
        struct FailComplete;

        #[async_trait::async_trait]
        impl crate::media::model_manager::ModelDownloadAuditSink for FailComplete {
            async fn append_model_download(&self, event_type: u8, _payload: Vec<u8>) -> Result<()> {
                if event_type == crate::wal::events::EVENT_TYPE_MODEL_DOWNLOAD_COMPLETE {
                    anyhow::bail!("simulate an accepted-ready cleanup interruption");
                }
                Ok(())
            }
        }

        let home = std::env::var_os("NEOTH_BGE_M3_HOSTED_NEOTH_HOME")
            .expect("hosted BGE-M3 recovery test requires its explicit NEOTH home");
        let home = PathBuf::from(home);
        let cfg = FreedomConfig::default();
        let target = resolve_managed_model(&home, "bge-m3", None, &cfg).unwrap();
        assert!(target.verified_cache_health(false).is_ready());

        let mut attempt = crate::media::model_manager::ModelDownloadAttempt::acquire(
            target.cache_path(),
            crate::providers::bge_m3_artifacts::DEFAULT_REPO,
            "explicit",
        )
        .await
        .unwrap();
        let failing = FailComplete;
        attempt.ensure_started(&failing).await.unwrap();
        assert!(
            attempt
                .finish_ready(&failing, target.cache_path())
                .await
                .is_err()
        );

        assert!(!target.verified_cache_health(false).is_ready());
        assert!(target.verified_cache_health(true).is_ready());
        assert!(!attempt.network_authorized(target.cache_path(), target.model_id()));
        execute_pull_with(
            &target,
            &cfg.updater,
            &RuntimeWhisperPrefetcher,
            Some(&attempt),
        )
        .await
        .expect("verified retained-ready cache must reload without new network authority");

        let cleanup_wal = tempfile::tempdir().unwrap();
        let (writer, join) =
            crate::wal::writer::spawn(cleanup_wal.path().join("recovery-cleanup.wal")).unwrap();
        let cleanup = PullAuditSink::Wal(writer);
        attempt.replay_terminal(&cleanup).await.unwrap();
        drop(cleanup);
        join.await.unwrap();
    }

    #[test]
    fn ollama_config_selects_the_same_spaced_parent_home_as_serve() {
        let cli = ModelsCli::try_parse_from([
            "models",
            "ollama",
            "--config",
            "C:/NEOTH Instances/blue instance/freedom.yaml",
            "status",
        ])
        .expect("ollama custom config parses");
        let config = match cli.args.action {
            ModelsAction::Ollama {
                config,
                action: OllamaModelsAction::Status,
            } => config,
            _ => unreachable!("expected Ollama status with a config override"),
        };
        assert_eq!(
            ollama_ipc_home(config.as_deref()),
            PathBuf::from("C:/NEOTH Instances/blue instance")
        );
        assert_eq!(
            ollama_ipc_home(Some(Path::new("freedom.yaml"))),
            PathBuf::from(".")
        );
    }

    #[test]
    fn known_models_include_generic_and_explicit_whisper_backends() {
        assert_eq!(
            MODEL_NAMES,
            ["clip", "whisper", "whisper-candle", "whisper-faster"]
        );
    }

    #[test]
    fn generic_and_explicit_whisper_names_resolve_backend_repo_cache_truth() {
        use crate::media::stt_dispatch::{SttProvider, WhisperModelSize};

        let dir = tempfile::tempdir().unwrap();
        let neoth_home = dir.path().join("custom-neoth-home");
        std::fs::create_dir_all(&neoth_home).unwrap();
        let process_home = dir.path().join("process-home");
        std::fs::create_dir_all(&process_home).unwrap();
        let _env = crate::test_env::lock();
        let _home = EnvGuard::set("HOME", &process_home);
        let _user = EnvGuard::set("USERPROFILE", &process_home);
        let hf_cache = dir.path().join("hf-cache");
        let _hf = EnvGuard::set("HUGGINGFACE_HUB_CACHE", &hf_cache);
        let mut cfg = FreedomConfig::default();
        cfg.media.stt.model_size = WhisperModelSize::Small;

        let clip = resolve_managed_model(&neoth_home, "clip", None, &cfg).unwrap();
        assert_eq!(
            clip.cache_path(),
            crate::providers::clip_engine::cache_dir_at(
                &neoth_home.join("models"),
                crate::providers::clip_engine::DEFAULT_CLIP_REPO,
            )
        );
        assert!(!clip.cache_path().starts_with(&process_home));

        let candle = resolve_managed_model(&neoth_home, "whisper-candle", None, &cfg).unwrap();
        assert_eq!(candle.backend(), "candle_whisper_local");
        assert_eq!(candle.model_id(), "openai/whisper-small");
        assert_eq!(
            candle.cache_path(),
            neoth_home.join("models").join("openai-whisper-small")
        );
        assert!(
            !candle.cache_path().starts_with(&process_home),
            "explicit NEOTH home must win over process HOME"
        );

        let faster = resolve_managed_model(&neoth_home, "whisper-faster", None, &cfg).unwrap();
        assert_eq!(faster.backend(), "faster_whisper_local");
        assert_eq!(faster.model_id(), "Systran/faster-whisper-small");
        assert_eq!(
            faster.cache_path(),
            hf_cache.join("models--Systran--faster-whisper-small")
        );

        cfg.media.stt.primary = SttProvider::FasterWhisperLocal;
        let generic = resolve_managed_model(&neoth_home, "whisper", None, &cfg).unwrap();
        assert_eq!(generic.backend(), "faster_whisper_local");
        assert_eq!(generic.model_id(), faster.model_id());
        assert_eq!(generic.cache_path(), faster.cache_path());

        let rows = build_list_rows(&neoth_home, &cfg).unwrap();
        let generic = rows.iter().find(|row| row.name == "whisper").unwrap();
        assert_eq!(generic.backend, "faster_whisper_local");
        assert_eq!(generic.repo, "Systran/faster-whisper-small");
        assert_eq!(generic.cache_dir, faster.cache_path().display().to_string());

        for backend in [SttProvider::OpenAiWhisperApi, SttProvider::AzureSpeech] {
            cfg.media.stt.primary = backend;
            let error = resolve_managed_model(&neoth_home, "whisper", None, &cfg)
                .err()
                .unwrap();
            let message = error.to_string();
            assert!(message.contains(backend.as_str()), "got: {message}");
            assert!(message.contains("whisper-candle"), "got: {message}");
            assert!(message.contains("whisper-faster"), "got: {message}");
        }
        let rows = build_list_rows(&neoth_home, &cfg).unwrap();
        let generic = rows.iter().find(|row| row.name == "whisper").unwrap();
        assert_eq!(generic.backend, SttProvider::AzureSpeech.as_str());
        assert!(generic.repo.is_empty());
        assert!(generic.cache_dir.is_empty());
        assert!(generic.error.as_deref().unwrap().contains("whisper-candle"));
        assert!(resolve_managed_model(&neoth_home, "whisper-candle", None, &cfg).is_ok());
        assert!(resolve_managed_model(&neoth_home, "whisper-faster", None, &cfg).is_ok());
    }

    #[test]
    fn whisper_repo_override_is_rejected_instead_of_drifting_runtime() {
        let cfg = FreedomConfig::default();
        let home = tempfile::tempdir().unwrap();
        let error = resolve_managed_model(home.path(), "whisper-candle", Some("other/repo"), &cfg)
            .err()
            .unwrap();
        assert!(error.to_string().contains("pinned"));
    }

    #[test]
    fn list_marks_structurally_corrupt_whisper_cache_as_not_cached() {
        let home = tempfile::tempdir().unwrap();
        let cache = crate::providers::whisper::materialize_structural_test_cache(
            &home.path().join("models"),
            "openai/whisper-base",
        )
        .unwrap();
        std::fs::write(cache.join("config.json"), b"not-json").unwrap();

        let rows = build_list_rows(home.path(), &FreedomConfig::default()).unwrap();
        let candle = rows
            .iter()
            .find(|row| row.name == "whisper-candle")
            .unwrap();

        assert!(!candle.cached);
        assert_eq!(candle.health, "corrupt");
        assert!(
            candle
                .error
                .as_deref()
                .is_some_and(|error| error.contains("config.json"))
        );
    }

    #[test]
    fn faster_whisper_default_cache_is_owned_by_the_explicit_neoth_home() {
        use crate::media::stt_dispatch::WhisperModelSize;

        let home = tempfile::tempdir().unwrap();
        let _env = crate::test_env::lock();
        let _hub = EnvGuard::remove("HUGGINGFACE_HUB_CACHE");
        let _hf_home = EnvGuard::remove("HF_HOME");
        let _xdg = EnvGuard::remove("XDG_CACHE_HOME");
        let mut cfg = FreedomConfig::default();
        cfg.media.stt.model_size = WhisperModelSize::Base;

        let target = resolve_managed_model(home.path(), "whisper-faster", None, &cfg).unwrap();

        assert_eq!(
            target.cache_path(),
            home.path()
                .join("cache")
                .join("huggingface")
                .join("hub")
                .join("models--Systran--faster-whisper-base")
        );
    }

    struct InjectedWhisperPrefetcher {
        calls: std::sync::Mutex<Vec<(String, String)>>,
    }

    #[async_trait::async_trait]
    impl WhisperPrefetcher for InjectedWhisperPrefetcher {
        async fn prefetch(
            &self,
            target: &crate::media::stt_provider::LocalWhisperTarget,
            _updater_cfg: &crate::config::ops::UpdaterConfig,
            _attempt: Option<&crate::media::model_manager::ModelDownloadAttempt>,
        ) -> Result<()> {
            self.calls.lock().unwrap().push((
                target.backend().as_str().to_string(),
                target.model_id().to_string(),
            ));
            Ok(())
        }
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn whisper_pull_executor_receives_the_resolved_runtime_target() {
        use crate::media::stt_dispatch::{SttProvider, WhisperModelSize};

        let dir = tempfile::tempdir().unwrap();
        let _env = crate::test_env::lock();
        let _home = EnvGuard::set("HOME", dir.path());
        let _user = EnvGuard::set("USERPROFILE", dir.path());
        let _hf = EnvGuard::set("HUGGINGFACE_HUB_CACHE", &dir.path().join("hf"));
        let mut cfg = FreedomConfig::default();
        cfg.media.stt.primary = SttProvider::FasterWhisperLocal;
        cfg.media.stt.model_size = WhisperModelSize::Medium;
        let target = resolve_managed_model(dir.path(), "whisper", None, &cfg).unwrap();
        let prefetcher = InjectedWhisperPrefetcher {
            calls: std::sync::Mutex::new(Vec::new()),
        };

        execute_pull_with(&target, &cfg.updater, &prefetcher, None)
            .await
            .unwrap();

        assert_eq!(
            *prefetcher.calls.lock().unwrap(),
            vec![(
                "faster_whisper_local".to_string(),
                "Systran/faster-whisper-medium".to_string()
            )]
        );
    }

    #[test]
    fn prune_removes_only_the_exact_resolved_repo_cache() {
        use crate::media::stt_dispatch::WhisperModelSize;

        let dir = tempfile::tempdir().unwrap();
        let _env = crate::test_env::lock();
        let _home = EnvGuard::set("HOME", dir.path());
        let _user = EnvGuard::set("USERPROFILE", dir.path());
        let _hf = EnvGuard::remove("HUGGINGFACE_HUB_CACHE");
        let _hf_home = EnvGuard::remove("HF_HOME");
        let _xdg = EnvGuard::remove("XDG_CACHE_HOME");
        let hf_cache = dir.path().join("cache").join("huggingface").join("hub");
        let mut cfg = FreedomConfig::default();
        cfg.media.stt.model_size = WhisperModelSize::Tiny;
        let target = resolve_managed_model(dir.path(), "whisper-faster", None, &cfg).unwrap();
        std::fs::create_dir_all(target.cache_path()).unwrap();
        std::fs::write(target.cache_path().join("owned"), b"target").unwrap();
        let sibling = hf_cache.join("models--Systran--faster-whisper-base");
        std::fs::create_dir_all(&sibling).unwrap();
        std::fs::write(sibling.join("keep"), b"sibling").unwrap();

        prune_target("whisper-faster", &target, dir.path()).unwrap();

        assert!(!target.cache_path().exists());
        assert!(sibling.join("keep").is_file());
    }

    #[tokio::test]
    async fn prune_refuses_unterminated_model_download_attempt() {
        let home = tempfile::tempdir().unwrap();
        let cache_path = home.path().join("models").join("clip-model");
        let target = ManagedModel::Clip {
            model_id: clip_engine::DEFAULT_CLIP_REPO.to_string(),
            cache_path: cache_path.clone(),
        };
        let (writer, join) = crate::wal::writer::spawn(home.path().join("attempt.wal")).unwrap();
        let mut attempt = crate::media::model_manager::ModelDownloadAttempt::acquire(
            &cache_path,
            clip_engine::DEFAULT_CLIP_REPO,
            "explicit",
        )
        .await
        .unwrap();
        attempt.ensure_started(&writer).await.unwrap();
        drop(attempt);

        let error = prune_target("clip", &target, home.path()).unwrap_err();
        assert!(error.to_string().contains("D7/D8 attempt is pending"));
        assert!(cache_path.exists());

        let mut attempt = crate::media::model_manager::ModelDownloadAttempt::acquire(
            &cache_path,
            clip_engine::DEFAULT_CLIP_REPO,
            "explicit",
        )
        .await
        .unwrap();
        attempt
            .finish_failed(&writer, "test cleanup")
            .await
            .unwrap();
        drop(attempt);
        drop(writer);
        join.await.unwrap();
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
    fn rec_class_maps_to_variant_class() {
        assert_eq!(
            VariantClass::from(RecClass::Abliterated),
            VariantClass::Abliterated
        );
        assert_eq!(
            VariantClass::from(RecClass::Standard),
            VariantClass::Standard
        );
    }

    #[test]
    fn recommendation_is_quantized_abliterated_with_pull_commands() {
        // 24 GiB GPU → top pick is a big model at Q4 (operator mandate), as a
        // verified abliterated GGUF, with a runnable `ollama pull` command.
        let recs = build_recommendation(Some(24 * 1024), VariantClass::Abliterated);
        assert!(!recs.is_empty());
        let top = &recs[0];
        assert_eq!(top.rank, 1);
        assert_eq!(top.param_b, 32.0);
        assert_eq!(top.quant, "Q4_K_M");
        assert_eq!(top.class, "abliterated");
        assert_eq!(
            top.repo,
            "mradermacher/Qwen2.5-32B-Instruct-abliterated-GGUF"
        );
        assert_eq!(
            top.pull_ref,
            "hf.co/mradermacher/Qwen2.5-32B-Instruct-abliterated-GGUF:Q4_K_M"
        );
        assert_eq!(top.pull_command[0], "ollama");
        assert_eq!(top.pull_command[1], "pull");
        assert_eq!(top.pull_command[2], top.pull_ref);
        // Ranks are 1-based and contiguous.
        for (i, c) in recs.iter().enumerate() {
            assert_eq!(c.rank, i + 1);
        }
    }

    #[test]
    fn recommendation_standard_class_uses_bartowski() {
        let recs = build_recommendation(Some(8 * 1024), VariantClass::Standard);
        let top = &recs[0];
        assert_eq!(top.class, "standard");
        assert!(top.repo.starts_with("bartowski/"), "got {}", top.repo);
        assert!(top.pull_ref.starts_with("hf.co/bartowski/"));
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
