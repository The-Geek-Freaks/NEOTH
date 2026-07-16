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
//! `whisper-candle` and `whisper-faster` explicitly select either local STT
//! backend; plain `whisper` follows the effective configured primary.
//! `qwen` is intentionally **not** in this list — local Qwen has its
//! own onboarding flow via `cli/init.rs::step5b_inference_topology`
//! that runs sysinfo-based hardware sizing before picking the repo.

use anyhow::{Context, Result};
use clap::{Args, Subcommand, ValueEnum};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::installers::{gpu, ollama};
use crate::models::gguf_variants::{self, GgufVariant, VariantClass};
use crate::models::selector::{self, Quant};
use crate::providers::clip_engine;
use crate::wal::spawn as wal_spawn;

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
    /// H18 — dump the live provider-model catalog (the wizard's model
    /// select source, `~/.neoth/models_catalog.json`) as JSON for the
    /// GUI's regenerate-with-model picker. Read-only; never-fetched or
    /// stale providers surface their fetch error so consumers degrade
    /// honestly instead of guessing model ids.
    Catalog,
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
static MODEL_PULL_WAL_NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[derive(Clone)]
enum ManagedModel {
    Clip {
        model_id: String,
        cache_path: std::path::PathBuf,
    },
    Whisper(crate::media::stt_provider::LocalWhisperTarget),
}

impl ManagedModel {
    fn model_id(&self) -> &str {
        match self {
            Self::Clip { model_id, .. } => model_id,
            Self::Whisper(target) => target.model_id(),
        }
    }

    fn cache_path(&self) -> &std::path::Path {
        match self {
            Self::Clip { cache_path, .. } => cache_path,
            Self::Whisper(target) => target.cache_path(),
        }
    }

    fn backend(&self) -> &'static str {
        match self {
            Self::Clip { .. } => "clip",
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
            Self::Whisper(target) => target.verified_cache_health(during_attempt),
        }
    }

    fn policy_name(&self) -> &'static str {
        match self {
            Self::Clip { .. } => "clip",
            Self::Whisper(_) => "whisper",
        }
    }

    fn cache_is_neoth_owned(&self) -> bool {
        match self {
            Self::Clip { .. } => true,
            Self::Whisper(target) => target.cache_is_neoth_owned(),
        }
    }
}

fn model_description(name: &str) -> &'static str {
    match name {
        "clip" => "CLIP ViT-B/32 image + text embeddings (vision Phase 2b)",
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
        ModelsAction::List => run_list(&args.output),
        ModelsAction::Catalog => run_catalog(&args.output),
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
    let neoth_home = FreedomConfig::default_neoth_home();
    let cfg = load_models_config(&neoth_home)?;
    let target = resolve_managed_model(&neoth_home, name, repo_override, &cfg)?;
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

    let mut audit_join = None;
    let audit_sink = if lifecycle_needed {
        let daemon_live = matches!(
            crate::daemon::pidfile::live_daemon_pid(&crate::daemon::pidfile::default_pidfile()),
            Ok(Some(_))
        );
        if daemon_live {
            Some(PullAuditSink::Daemon {
                home: neoth_home.clone(),
            })
        } else {
            let wal_dir = FreedomConfig::default_wal_dir();
            std::fs::create_dir_all(&wal_dir)
                .with_context(|| format!("create model-download WAL dir {}", wal_dir.display()))?;
            let sequence = crate::time::now_unix_ns()
                .saturating_add(u64::from(std::process::id()) << 12)
                .saturating_add(
                    MODEL_PULL_WAL_NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                );
            let (writer, join) = wal_spawn(wal_dir.join(format!("{sequence:020}.wal")))
                .context("spawn mandatory model-download WAL writer")?;
            audit_join = Some(join);
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
        match pull_result {
            Ok(()) => {
                if attempt.is_pending() {
                    attempt
                        .finish_ready(
                            audit_sink
                                .as_ref()
                                .context("completed model attempt has no mandatory audit sink")?,
                            &cache_dir,
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
                            audit_sink
                                .as_ref()
                                .context("failed model attempt has no mandatory audit sink")?,
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
    .await;

    drop(attempt);
    drop(audit_sink);
    if let Some(join) = audit_join {
        join.await
            .context("model-download WAL writer task panicked")?;
    }
    operation_result?;

    println!("{} cached at {}", name, cache_dir.display());
    Ok(())
}

fn run_prune(name: &str) -> Result<()> {
    let neoth_home = FreedomConfig::default_neoth_home();
    let cfg = load_models_config(&neoth_home)?;
    let target = resolve_managed_model(&neoth_home, name, None, &cfg)?;
    prune_target(name, &target, &neoth_home)
}

fn prune_target(name: &str, target: &ManagedModel, neoth_home: &std::path::Path) -> Result<()> {
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
            println!("{} already absent at {}", name, dir.display());
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
    println!("removed {} ({})", dir.display(), target.model_id());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            neoth_home
                .join("models")
                .join("openai-clip-vit-base-patch32")
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
        let cache = home.path().join("models").join("openai-whisper-base");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::write(cache.join("tokenizer.json"), b"{}").unwrap();
        std::fs::write(cache.join("config.json"), b"not-json").unwrap();
        std::fs::write(cache.join("model.safetensors"), b"truncated").unwrap();

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
