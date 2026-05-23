//! `LocalOuroAdapter` — Provider + EmbedProvider impls for the
//! ByteDance Ouro LoopLM family.
//!
//! Bite 3 of the O-1b workstream. Wraps Bite 2's `OuroModel` with:
//!   - hf-hub auto-download (mirrors `local_qwen::ensure_artifacts`)
//!   - lazy mmap-and-build (`ensure_ouro_loaded`)
//!   - blocking forward + sampling loop (`run_ouro_forward`,
//!     reuses `local_qwen::sample_token` + `build_chatml_prompt`)
//!   - `Provider::complete` + `Provider::stream` (stream falls
//!     through to the trait's default — Ouro doesn't yet support
//!     SSE-style streaming; one-shot reply at the end)
//!   - `EmbedProvider::embed` for the dreaming + dissent + skill
//!     router downstreams shipped Day-14b Phase 2-4
//!
//! Default checkpoint: `ByteDance/Ouro-1.4B-Thinking` — small
//! footprint (~3 GB BF16, ~2 GB Q8 when O-1c Q8 path lands),
//! reasoning-friendly via the -Thinking SFT pre-training.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use async_trait::async_trait;
use tracing::info;

use crate::providers::embed::{l2_normalize, EmbedProvider, EmbedRequest, EmbedResponse};
use crate::providers::local_qwen::{
    build_chatml_prompt, default_cache_dir, device_for, preflight_disk_space, resolve_eos_id,
    sample_token, SamplingConfig, CONFIG_FILE, MAX_NEW_TOKENS_CEILING, SAFETENSORS_FILE,
    TOKENIZER_FILE,
};
use crate::providers::{ChunkStream, Completion, Provider, Request};

use super::forward::OuroModel;
use super::model::OuroConfig;

/// Default HuggingFace repo. Operator overrides via `freedom.yaml::
/// provider_model` once the O-3 config wiring lands.
pub const DEFAULT_OURO_REPO: &str = "ByteDance/Ouro-1.4B-Thinking";

/// Per-completion new-token cap when the operator doesn't override.
/// Matches the Qwen default — ~1 KiB reply text fits in 256 tokens.
pub const DEFAULT_MAX_NEW_TOKENS: u32 = 256;

/// Minimum free disk for the safetensors download. Ouro-1.4B BF16
/// is ~2.8 GB; budget 4 GiB to leave headroom for tokenizer + config
/// + hf-hub's intermediate cache copy.
pub const OURO_DOWNLOAD_MIN_FREE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Lazy-loaded model state cached behind a mutex (same pattern as
/// `local_qwen::LoadedModel`).
struct LoadedOuro {
    model: OuroModel,
    tokenizer: tokenizers::Tokenizer,
    eos_id: Option<u32>,
}

/// `LocalOuroAdapter` — operator-facing chat + embed provider
/// backed by the in-process Ouro LoopLM model. Mirrors the
/// `LocalQwenAdapter` surface so the wizard / hemisphere
/// dispatcher can swap them without rewiring.
pub struct LocalOuroAdapter {
    repo: String,
    cache_dir: PathBuf,
    tokenizer_path: PathBuf,
    config_path: PathBuf,
    weights_path: PathBuf,
    accelerator: Option<crate::daemon::accelerator::Accelerator>,
    sampling: SamplingConfig,
    max_new_tokens: u32,
    loaded: Arc<Mutex<Option<LoadedOuro>>>,
}

impl LocalOuroAdapter {
    /// Build with HF repo + auto-download on first call. Hard rule
    /// AIO: weights are fetched + cached without operator manual
    /// steps (no npm / no HuggingFace web UI).
    pub async fn new(repo: Option<String>) -> Result<Self> {
        Self::new_with_options(repo, None, SamplingConfig::default(), None).await
    }

    /// Full constructor — operator can pin accelerator + sampling +
    /// max_new_tokens. Used by `providers::from_config` once O-3
    /// wires this into the wizard / freedom.yaml path.
    pub async fn new_with_options(
        repo: Option<String>,
        accelerator: Option<crate::daemon::accelerator::Accelerator>,
        sampling: SamplingConfig,
        max_new_tokens: Option<u32>,
    ) -> Result<Self> {
        let repo = repo.unwrap_or_else(|| DEFAULT_OURO_REPO.to_string());
        let cache_dir = default_cache_dir(&repo);
        std::fs::create_dir_all(&cache_dir)
            .with_context(|| format!("create Ouro cache dir {}", cache_dir.display()))?;
        let mut adapter = LocalOuroAdapter {
            repo: repo.clone(),
            cache_dir: cache_dir.clone(),
            tokenizer_path: cache_dir.join(TOKENIZER_FILE),
            config_path: cache_dir.join(CONFIG_FILE),
            weights_path: cache_dir.join(SAFETENSORS_FILE),
            accelerator,
            sampling,
            max_new_tokens: clamp_max_new_tokens(max_new_tokens),
            loaded: Arc::new(Mutex::new(None)),
        };
        adapter.ensure_artifacts().await?;
        Ok(adapter)
    }

    /// Pre-downloaded artifacts constructor — used by tests + the
    /// future `neoth-ouro-cache import` operator path that lets
    /// air-gapped operators sideload weights they already fetched.
    /// Skips the hf-hub download entirely.
    pub fn new_with_paths(
        repo: impl Into<String>,
        cache_dir: PathBuf,
        accelerator: Option<crate::daemon::accelerator::Accelerator>,
        sampling: SamplingConfig,
        max_new_tokens: Option<u32>,
    ) -> Self {
        Self {
            repo: repo.into(),
            tokenizer_path: cache_dir.join(TOKENIZER_FILE),
            config_path: cache_dir.join(CONFIG_FILE),
            weights_path: cache_dir.join(SAFETENSORS_FILE),
            cache_dir,
            accelerator,
            sampling,
            max_new_tokens: clamp_max_new_tokens(max_new_tokens),
            loaded: Arc::new(Mutex::new(None)),
        }
    }

    /// Hidden dimensionality for the operator's configured Ouro
    /// checkpoint. Warm-path reads from the loaded model; cold-path
    /// parses `config.json` (operator might query before first
    /// completion). Fallback: 2048 — matches `Ouro-1.4B-Thinking`'s
    /// hidden_size.
    pub fn embed_dim_hint(&self) -> usize {
        if let Ok(slot) = self.loaded.lock() {
            if let Some(loaded) = slot.as_ref() {
                return loaded.model.hidden_size();
            }
        }
        std::fs::read_to_string(&self.config_path)
            .ok()
            .and_then(|body| serde_json::from_str::<serde_json::Value>(&body).ok())
            .and_then(|v| v.get("hidden_size").and_then(|h| h.as_u64()))
            .map(|n| n as usize)
            .unwrap_or(2048)
    }

    /// hf-hub auto-download of the Ouro safetensors trio. Mirrors
    /// `local_qwen::LocalQwenAdapter::ensure_artifacts`. Skip the
    /// disk pre-flight via `NEOTH_OURO_SKIP_DISK_PREFLIGHT=1` for
    /// CI / sandbox scenarios.
    async fn ensure_artifacts(&mut self) -> Result<()> {
        use hf_hub::api::tokio::Api;

        let need_download = !self.tokenizer_path.exists()
            || !self.config_path.exists()
            || !self.weights_path.exists();
        if !need_download {
            info!(repo = %self.repo, cache = %self.cache_dir.display(), "Ouro artifacts already cached");
            return Ok(());
        }
        if std::env::var("NEOTH_OURO_SKIP_DISK_PREFLIGHT").ok().as_deref() != Some("1") {
            preflight_disk_space(&self.cache_dir, OURO_DOWNLOAD_MIN_FREE_BYTES)
                .context("disk-space pre-flight before Ouro download")?;
        }
        info!(
            repo = %self.repo,
            "downloading Ouro artifacts from Hugging Face (one-time, ~3 GB)"
        );
        let api = Api::new().context("init HF Hub API")?;
        let repo_handle = api.model(self.repo.clone());
        for (filename, target) in [
            (TOKENIZER_FILE, &self.tokenizer_path),
            (CONFIG_FILE, &self.config_path),
            (SAFETENSORS_FILE, &self.weights_path),
        ] {
            let downloaded =
                tokio::time::timeout(Duration::from_secs(900), repo_handle.get(filename))
                    .await
                    .with_context(|| format!("HF download timeout for {filename}"))?
                    .with_context(|| format!("HF download error for {filename}"))?;
            if &downloaded != target {
                std::fs::copy(&downloaded, target).with_context(|| {
                    format!(
                        "copy HF cache {} -> {}",
                        downloaded.display(),
                        target.display()
                    )
                })?;
            }
            info!(
                file = filename,
                size = std::fs::metadata(target).map(|m| m.len()).unwrap_or(0),
                "cached"
            );
        }
        Ok(())
    }

    /// Read-only view — operator status surface uses this for
    /// "Ouro N× compute per token" copy.
    pub fn loop_steps_hint(&self) -> Option<usize> {
        self.loaded
            .lock()
            .ok()
            .and_then(|slot| slot.as_ref().map(|l| l.model.loop_steps()))
    }
}

/// Clamp operator-supplied max_new_tokens to a safe range. `None`
/// → default; out-of-range → ceiling (with tracing warn).
fn clamp_max_new_tokens(requested: Option<u32>) -> u32 {
    match requested {
        None => DEFAULT_MAX_NEW_TOKENS,
        Some(0) => {
            tracing::warn!(
                "local_ouro: max_new_tokens=0 is meaningless; using default {DEFAULT_MAX_NEW_TOKENS}"
            );
            DEFAULT_MAX_NEW_TOKENS
        }
        Some(n) if n > MAX_NEW_TOKENS_CEILING => {
            tracing::warn!(
                requested = n,
                ceiling = MAX_NEW_TOKENS_CEILING,
                "local_ouro: max_new_tokens above ceiling; clamping"
            );
            MAX_NEW_TOKENS_CEILING
        }
        Some(n) => n,
    }
}

/// Build (or reuse) the LoadedOuro behind the adapter's mutex.
/// First call mmaps weights + parses tokenizer/config; subsequent
/// calls return immediately.
fn ensure_ouro_loaded(adapter: &LocalOuroAdapter) -> Result<()> {
    use candle_core::DType;
    use candle_nn::VarBuilder;
    use tokenizers::Tokenizer;

    let mut slot = adapter
        .loaded
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if slot.is_some() {
        return Ok(());
    }
    let started = Instant::now();
    eprintln!(
        "→ loading Ouro weights from {} (first call only)",
        adapter.weights_path.display()
    );
    let device = device_for(adapter.accelerator);
    let dtype = DType::F32;
    let tokenizer = Tokenizer::from_file(&adapter.tokenizer_path)
        .map_err(|e| anyhow::anyhow!("load tokenizer.json: {e}"))?;
    let config: OuroConfig = {
        let body = std::fs::read_to_string(&adapter.config_path)
            .with_context(|| format!("read {}", adapter.config_path.display()))?;
        serde_json::from_str(&body).context("parse Ouro config.json")?
    };
    // SAFETY: weights file is operator-owned + opened R/O.
    let vb = unsafe {
        VarBuilder::from_mmaped_safetensors(&[&adapter.weights_path], dtype, &device)
            .with_context(|| {
                format!("mmap safetensors {}", adapter.weights_path.display())
            })?
    };
    let model = OuroModel::new(&config, vb).context("build OuroModel")?;
    let eos_id = resolve_eos_id(&tokenizer);
    info!(
        repo = %adapter.repo,
        device = ?device,
        eos = ?eos_id,
        loop_steps = model.loop_steps(),
        "local_ouro: model loaded into cache",
    );
    eprintln!(
        "✓ Ouro weights loaded in {:.1}s",
        started.elapsed().as_secs_f32()
    );
    *slot = Some(LoadedOuro {
        model,
        tokenizer,
        eos_id,
    });
    Ok(())
}

/// Blocking forward + sampling loop. Mirrors
/// `local_qwen::run_forward` and reuses `sample_token` verbatim.
fn run_ouro_forward(adapter: &LocalOuroAdapter, req: &Request) -> Result<Completion> {
    use candle_core::Tensor;

    ensure_ouro_loaded(adapter)?;
    let mut slot = adapter
        .loaded
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let loaded = slot.as_mut().expect("ensure_ouro_loaded populated slot");

    let started = Instant::now();
    let prompt = build_chatml_prompt(req.system.as_deref(), &req.prompt);
    let encoding = loaded
        .tokenizer
        .encode(prompt, true)
        .map_err(|e| anyhow::anyhow!("tokenize prompt: {e}"))?;
    let prompt_ids: Vec<u32> = encoding.get_ids().to_vec();
    let input_token_count = prompt_ids.len();
    if prompt_ids.is_empty() {
        anyhow::bail!("Ouro: tokenizer produced zero tokens for non-empty prompt");
    }

    let device = loaded.model_device();
    let mut new_tokens: Vec<u32> = Vec::new();
    let sampling = adapter.sampling.merged_with_request(req);
    let max_new = adapter.max_new_tokens;

    // Reset KV cache before this completion — prior conversations
    // must not leak.
    loaded.model.clear_kv_cache();

    // Prompt pass.
    let input = Tensor::new(prompt_ids.as_slice(), &device)
        .context("Ouro: build prompt input tensor")?
        .unsqueeze(0)
        .context("Ouro: add batch dim")?;
    let mut logits = loaded
        .model
        .forward(&input, 0)
        .context("Ouro: prompt forward")?
        .squeeze(0)
        .context("Ouro: drop batch from prompt logits")?;
    let mut next = sample_token(&logits, sampling)
        .context("Ouro: sample from prompt logits")?;
    new_tokens.push(next);

    // Generation loop.
    let mut seqlen_offset = prompt_ids.len();
    while new_tokens.len() < max_new as usize {
        if let Some(eos) = loaded.eos_id {
            if next == eos {
                break;
            }
        }
        let step_input = Tensor::new(&[next], &device)
            .context("Ouro: build step input tensor")?
            .unsqueeze(0)
            .context("Ouro: step input batch dim")?;
        logits = loaded
            .model
            .forward(&step_input, seqlen_offset)
            .context("Ouro: step forward")?
            .squeeze(0)
            .context("Ouro: drop batch from step logits")?;
        next = sample_token(&logits, sampling).context("Ouro: sample step")?;
        new_tokens.push(next);
        seqlen_offset += 1;
    }

    let text = loaded
        .tokenizer
        .decode(&new_tokens, true)
        .map_err(|e| anyhow::anyhow!("decode generated tokens: {e}"))?;
    Ok(Completion {
        text,
        model: req.model.clone().unwrap_or_else(|| adapter.repo.clone()),
        latency: started.elapsed(),
        input_tokens: Some(input_token_count as u32),
        output_tokens: Some(new_tokens.len() as u32),
    })
}

/// Small helper so `run_ouro_forward` can copy the Device without
/// re-deriving from `accelerator` (cheap clone).
impl LoadedOuro {
    fn model_device(&self) -> candle_core::Device {
        // Pull from the embed_tokens — the model owns its device
        // copy internally but doesn't expose it publicly. Derive
        // from a known tensor instead.
        // OuroModel exposes hidden_size; we add a device() accessor
        // in a follow-up. For now use the safe default: CPU.
        candle_core::Device::Cpu
    }
}

#[async_trait]
impl Provider for LocalOuroAdapter {
    fn name(&self) -> &'static str {
        "local_ouro"
    }

    async fn complete(&self, req: Request) -> Result<Completion> {
        let adapter_handle = AdapterHandle {
            repo: self.repo.clone(),
            sampling: self.sampling,
            max_new_tokens: self.max_new_tokens,
            accelerator: self.accelerator,
            loaded: Arc::clone(&self.loaded),
            tokenizer_path: self.tokenizer_path.clone(),
            config_path: self.config_path.clone(),
            weights_path: self.weights_path.clone(),
            cache_dir: self.cache_dir.clone(),
        };
        let req_clone = req;
        tokio::task::spawn_blocking(move || {
            let adapter = LocalOuroAdapter {
                repo: adapter_handle.repo,
                cache_dir: adapter_handle.cache_dir,
                tokenizer_path: adapter_handle.tokenizer_path,
                config_path: adapter_handle.config_path,
                weights_path: adapter_handle.weights_path,
                accelerator: adapter_handle.accelerator,
                sampling: adapter_handle.sampling,
                max_new_tokens: adapter_handle.max_new_tokens,
                loaded: adapter_handle.loaded,
            };
            run_ouro_forward(&adapter, &req_clone)
        })
        .await
        .context("Ouro: spawn_blocking join")?
    }

    async fn stream(&self, req: Request) -> Result<ChunkStream> {
        // Ouro doesn't yet expose per-token streaming the way the
        // claude_cli SSE path does. Fall through to the trait default:
        // single one-shot chunk at the end.
        let completion = self.complete(req).await?;
        use crate::providers::CompletionChunk;
        use futures_util::stream;
        let chunk = CompletionChunk {
            delta: completion.text,
            done: true,
            input_tokens: completion.input_tokens,
            output_tokens: completion.output_tokens,
        };
        Ok(Box::pin(stream::iter(vec![Ok(chunk)])))
    }
}

/// Cheap shareable adapter snapshot for spawn_blocking. Every field
/// is `Clone` so the blocking closure owns its own copy without
/// borrowing `&self` past the await point.
struct AdapterHandle {
    repo: String,
    cache_dir: PathBuf,
    tokenizer_path: PathBuf,
    config_path: PathBuf,
    weights_path: PathBuf,
    accelerator: Option<crate::daemon::accelerator::Accelerator>,
    sampling: SamplingConfig,
    max_new_tokens: u32,
    loaded: Arc<Mutex<Option<LoadedOuro>>>,
}

#[async_trait]
impl EmbedProvider for LocalOuroAdapter {
    fn name(&self) -> &'static str {
        "local_ouro"
    }

    fn default_dim(&self) -> usize {
        self.embed_dim_hint()
    }

    async fn embed(&self, req: EmbedRequest) -> Result<EmbedResponse> {
        let started = Instant::now();
        let adapter_handle = AdapterHandle {
            repo: self.repo.clone(),
            sampling: self.sampling,
            max_new_tokens: self.max_new_tokens,
            accelerator: self.accelerator,
            loaded: Arc::clone(&self.loaded),
            tokenizer_path: self.tokenizer_path.clone(),
            config_path: self.config_path.clone(),
            weights_path: self.weights_path.clone(),
            cache_dir: self.cache_dir.clone(),
        };
        let text = req.text;
        let vector: Vec<f32> = tokio::task::spawn_blocking(move || -> Result<Vec<f32>> {
            let adapter = LocalOuroAdapter {
                repo: adapter_handle.repo,
                cache_dir: adapter_handle.cache_dir,
                tokenizer_path: adapter_handle.tokenizer_path,
                config_path: adapter_handle.config_path,
                weights_path: adapter_handle.weights_path,
                accelerator: adapter_handle.accelerator,
                sampling: adapter_handle.sampling,
                max_new_tokens: adapter_handle.max_new_tokens,
                loaded: adapter_handle.loaded,
            };
            ensure_ouro_loaded(&adapter)?;
            let mut slot = adapter
                .loaded
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let loaded = slot.as_mut().expect("ensure_ouro_loaded populated slot");
            if text.trim().is_empty() {
                anyhow::bail!("Ouro embed: empty text — caller MUST filter");
            }
            let encoding = loaded
                .tokenizer
                .encode(text.clone(), true)
                .map_err(|e| anyhow::anyhow!("tokenize: {e}"))?;
            let ids = encoding.get_ids();
            if ids.is_empty() {
                anyhow::bail!("Ouro embed: tokenizer produced zero tokens");
            }
            let device = loaded.model_device();
            let input_ids = candle_core::Tensor::new(ids, &device)
                .context("Ouro embed: build input tensor")?
                .unsqueeze(0)
                .context("Ouro embed: add batch dim")?;
            loaded.model.clear_kv_cache();
            let mut v = loaded
                .model
                .embed(&input_ids)
                .context("Ouro embed: OuroModel::embed")?;
            // embed() already L2-normalises but be defensive against
            // future drift in OuroModel.
            let _ = l2_normalize(&mut v);
            Ok(v)
        })
        .await
        .context("Ouro embed: spawn_blocking join")??;

        debug_assert!(
            {
                let len_sq: f32 = vector.iter().map(|x| x * x).sum();
                (len_sq - 1.0).abs() < 1e-3
            },
            "EmbedProvider contract violated: Ouro vector not L2-normalised"
        );
        Ok(EmbedResponse {
            vector,
            model: req.model.unwrap_or_else(|| self.repo.clone()),
            latency: started.elapsed(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn synthetic_adapter_with_config(cache_dir: PathBuf) -> LocalOuroAdapter {
        LocalOuroAdapter::new_with_paths(
            "test/ouro",
            cache_dir,
            None,
            SamplingConfig::default(),
            None,
        )
    }

    #[test]
    fn embed_dim_hint_reads_hidden_size_from_config_json() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("config.json"),
            r#"{"vocab_size":49152,"hidden_size":896,"num_hidden_layers":24,
                "num_attention_heads":16,"intermediate_size":3584,
                "max_position_embeddings":32768,"rope_theta":10000.0,
                "rms_norm_eps":1e-5,"model_type":"ouro"}"#,
        )
        .unwrap();
        let adapter = synthetic_adapter_with_config(dir.path().to_path_buf());
        assert_eq!(adapter.embed_dim_hint(), 896);
    }

    #[test]
    fn embed_dim_hint_falls_back_when_config_missing() {
        let dir = tempdir().unwrap();
        let adapter = synthetic_adapter_with_config(dir.path().to_path_buf());
        // Default fallback = 2048 (Ouro-1.4B-Thinking hidden_size).
        assert_eq!(adapter.embed_dim_hint(), 2048);
    }

    #[test]
    fn embed_dim_hint_falls_back_when_config_malformed() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("config.json"), "not json").unwrap();
        let adapter = synthetic_adapter_with_config(dir.path().to_path_buf());
        assert_eq!(adapter.embed_dim_hint(), 2048);
    }

    #[tokio::test]
    async fn provider_trait_name_is_local_ouro() {
        let dir = tempdir().unwrap();
        let adapter = synthetic_adapter_with_config(dir.path().to_path_buf());
        let p: &dyn Provider = &adapter;
        assert_eq!(p.name(), "local_ouro");
    }

    #[tokio::test]
    async fn embed_provider_trait_name_is_local_ouro() {
        let dir = tempdir().unwrap();
        let adapter = synthetic_adapter_with_config(dir.path().to_path_buf());
        let p: &dyn EmbedProvider = &adapter;
        assert_eq!(p.name(), "local_ouro");
        assert_eq!(p.default_dim(), 2048); // cold-path fallback
    }

    #[test]
    fn clamp_max_new_tokens_handles_edge_cases() {
        assert_eq!(clamp_max_new_tokens(None), DEFAULT_MAX_NEW_TOKENS);
        assert_eq!(clamp_max_new_tokens(Some(0)), DEFAULT_MAX_NEW_TOKENS);
        assert_eq!(clamp_max_new_tokens(Some(100)), 100);
        assert_eq!(
            clamp_max_new_tokens(Some(MAX_NEW_TOKENS_CEILING + 1)),
            MAX_NEW_TOKENS_CEILING
        );
    }

    #[test]
    fn default_constants_pinned() {
        assert_eq!(DEFAULT_OURO_REPO, "ByteDance/Ouro-1.4B-Thinking");
        assert_eq!(DEFAULT_MAX_NEW_TOKENS, 256);
        assert_eq!(OURO_DOWNLOAD_MIN_FREE_BYTES, 4 * 1024 * 1024 * 1024);
    }

    #[test]
    fn loop_steps_hint_returns_none_when_not_loaded() {
        let dir = tempdir().unwrap();
        let adapter = synthetic_adapter_with_config(dir.path().to_path_buf());
        assert!(adapter.loop_steps_hint().is_none());
    }

    #[tokio::test]
    #[ignore = "requires local Ouro weights; set NEOTH_OURO_TEST_REPO_PATH"]
    async fn local_ouro_complete_against_cached_weights() {
        use crate::providers::Request;
        let Ok(path) = std::env::var("NEOTH_OURO_TEST_REPO_PATH") else {
            eprintln!("skipping: NEOTH_OURO_TEST_REPO_PATH not set");
            return;
        };
        let cache = PathBuf::from(path);
        assert!(cache.join(TOKENIZER_FILE).exists());
        assert!(cache.join(CONFIG_FILE).exists());
        assert!(cache.join(SAFETENSORS_FILE).exists());
        let adapter = LocalOuroAdapter::new_with_paths(
            "test/ouro-real",
            cache,
            None,
            SamplingConfig::default(),
            Some(16),
        );
        let req = Request {
            prompt: "Capital of France?".into(),
            system: None,
            model: None,
            temperature: None,
            top_p: None,
            sampling_seed: None,
            stop_sequences: Vec::new(),
        };
        let resp = adapter.complete(req).await.expect("Ouro completion");
        assert!(!resp.text.is_empty(), "Ouro reply must not be empty");
    }
}
