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
use clap::{Args, Subcommand, ValueEnum};

use crate::cli::OutputFormat;
use crate::config::FreedomConfig;
use crate::installers::{gpu, ollama};
use crate::models::gguf_variants::{self, GgufVariant, VariantClass};
use crate::models::selector::{self, Quant};
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
    crate::time::now_unix_secs()
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
    // AUDIT-RPC-01: when the daemon owns the WAL we forward the download frames
    // over the loopback channel (0xD7/0xD8 allowlisted); otherwise a one-shot
    // writer emits them directly.
    let daemon_live = matches!(
        crate::daemon::pidfile::live_daemon_pid(&crate::daemon::pidfile::default_pidfile()),
        Ok(Some(_))
    );
    let audit = if daemon_live {
        None
    } else {
        let seg = FreedomConfig::default_wal_dir().join("000001.wal");
        if let Some(p) = seg.parent() {
            let _ = std::fs::create_dir_all(p);
        }
        wal_spawn(seg).ok()
    };
    let audit_home = FreedomConfig::default_neoth_home();

    {
        let payload = serde_json::to_vec(&serde_json::json!({
            "model_id": model_id.as_str(),
            "ts_unix": now_unix_secs(),
        }))
        .unwrap_or_default();
        if let Some((w, _)) = &audit {
            if let Err(e) = w
                .append(
                    make_header(EVENT_TYPE_MODEL_DOWNLOAD_START, &payload),
                    payload,
                )
                .await
            {
                tracing::warn!(error = %e, "MODEL_DOWNLOAD_START WAL emit failed (non-fatal)");
            }
        } else if daemon_live {
            if let Err(e) = crate::daemon::audit_rpc::try_post_audit_frame(
                &audit_home,
                EVENT_TYPE_MODEL_DOWNLOAD_START,
                &payload,
            )
            .await
            {
                tracing::debug!(error = %e, "0xD7 forward skipped (daemon listener unreachable)");
            }
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

    {
        let payload = serde_json::to_vec(&serde_json::json!({
            "model_id": model_id.as_str(),
            "cached_path": cache_dir.display().to_string(),
            "duration_ms": u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "ts_unix": now_unix_secs(),
        }))
        .unwrap_or_default();
        if let Some((w, join)) = audit {
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
        } else if daemon_live {
            if let Err(e) = crate::daemon::audit_rpc::try_post_audit_frame(
                &audit_home,
                EVENT_TYPE_MODEL_DOWNLOAD_COMPLETE,
                &payload,
            )
            .await
            {
                tracing::debug!(error = %e, "0xD8 forward skipped (daemon listener unreachable)");
            }
        }
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
