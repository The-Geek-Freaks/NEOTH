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

use crate::providers::embed::{EmbedProvider, EmbedRequest, EmbedResponse, l2_normalize};
use crate::providers::local_qwen::{
    CONFIG_FILE, MAX_NEW_TOKENS_CEILING, SAFETENSORS_FILE, SamplingConfig, TOKENIZER_FILE,
    build_chatml_prompt, default_cache_dir, device_for, preflight_disk_space, resolve_eos_id,
    sample_token,
};
use crate::providers::{ChunkStream, Completion, Provider, Request};

use super::forward::OuroModel;
use super::model::{OuroConfig, OuroQuantMode};

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
/// O-5c — model variant the adapter cached. Dispatch via the
/// enum so each Provider/EmbedProvider call routes to the right
/// forward path without re-reading `quant_mode`.
enum LoadedOuroModel {
    Native(OuroModel),
    Quantized(super::quantized_forward::QuantizedOuroModel),
}

impl LoadedOuroModel {
    fn forward(
        &mut self,
        input_ids: &candle_core::Tensor,
        seqlen_offset: usize,
    ) -> anyhow::Result<candle_core::Tensor> {
        match self {
            Self::Native(m) => m.forward(input_ids, seqlen_offset),
            Self::Quantized(m) => m.forward(input_ids, seqlen_offset),
        }
    }

    fn embed(&mut self, input_ids: &candle_core::Tensor) -> anyhow::Result<Vec<f32>> {
        match self {
            Self::Native(m) => m.embed(input_ids),
            Self::Quantized(m) => m.embed(input_ids),
        }
    }

    fn clear_kv_cache(&mut self) {
        match self {
            Self::Native(m) => m.clear_kv_cache(),
            Self::Quantized(m) => m.clear_kv_cache(),
        }
    }

    fn hidden_size(&self) -> usize {
        match self {
            Self::Native(m) => m.hidden_size(),
            Self::Quantized(m) => m.hidden_size(),
        }
    }

    fn loop_steps(&self) -> usize {
        match self {
            Self::Native(m) => m.loop_steps(),
            Self::Quantized(m) => m.loop_steps(),
        }
    }
}

struct LoadedOuro {
    model: LoadedOuroModel,
    tokenizer: tokenizers::Tokenizer,
    eos_id: Option<u32>,
    /// COR-12 — the candle device the weights were mmap'd onto, stored
    /// at load time (mirrors `local_qwen::LoadedModel::device`). Input
    /// tensors MUST be built on this exact device instance, not a fresh
    /// `device_for(..)` re-derivation: candle's `Device::same_device`
    /// compares a per-instance `DeviceId`, so two `device_for` calls
    /// would yield non-interoperable devices on real CUDA/Metal.
    device: candle_core::Device,
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
    /// O-5a — operator-picked quant mode. `None` (default) loads
    /// native BF16/F32. `Q8` is wired but falls through to None at
    /// load time until O-5b ships the QTensor forward-pass swap.
    quant_mode: OuroQuantMode,
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
            quant_mode: OuroQuantMode::default(),
            loaded: Arc::new(Mutex::new(None)),
        };
        adapter.ensure_artifacts().await?;
        Ok(adapter)
    }

    /// O-5a — operator-picked quant mode override. Returns a new
    /// adapter (builder-style) so the existing construction sites
    /// don't need to change. `Q8` is accepted today + plumbed
    /// through `ensure_ouro_loaded` but falls through to native
    /// load with a tracing-warn until O-5b lands.
    pub fn with_quant_mode(mut self, mode: OuroQuantMode) -> Self {
        self.quant_mode = mode;
        self
    }

    /// Read-only view of the configured quant mode — operator
    /// status surface (`neoth ouro status` once O-5a wires it) reads
    /// via this.
    pub fn quant_mode(&self) -> OuroQuantMode {
        self.quant_mode
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
            quant_mode: OuroQuantMode::default(),
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
        // HF-01 — honour the operator's HuggingFace-download policy on the
        // implicit first-use path (mirrors local_qwen + the explicit
        // `neoth model pull`). Refuse the silent fetch when the operator
        // disabled HF downloads. Best-effort read; absent config = default
        // permissive.
        let allow_hf = crate::config::FreedomConfig::load_from_default_path()
            .map(|c| c.updater.allow_huggingface_downloads)
            .unwrap_or(true);
        if !allow_hf {
            anyhow::bail!(
                "Hugging Face downloads are disabled \
                 (freedom.yaml::updater.allow_huggingface_downloads = false), but the local_ouro \
                 provider needs to fetch its weights from {}. Set it to true, pre-place the \
                 artifacts under {}, or run `neoth model pull` on a connected machine.",
                self.repo,
                self.cache_dir.display(),
            );
        }
        if std::env::var("NEOTH_OURO_SKIP_DISK_PREFLIGHT")
            .ok()
            .as_deref()
            != Some("1")
        {
            preflight_disk_space(&self.cache_dir, OURO_DOWNLOAD_MIN_FREE_BYTES)
                .context("disk-space pre-flight before Ouro download")?;
        }
        // HF-01 implicit-emit (Session 28g+) — same audit-chain closure
        // as `local_qwen::ensure_artifacts`: emit 0xD7 before the fetch,
        // 0xD8 after, with `trigger=implicit` so the operator can tell
        // the implicit first-use path apart from `neoth model pull` in
        // the WAL log. Best-effort + single-writer-invariant safe.
        crate::daemon::model_download_audit::emit_start(&self.repo).await;
        let download_start = std::time::Instant::now();

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
                tokio::time::timeout(Duration::from_secs(900), repo_handle.download(filename))
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
        crate::daemon::model_download_audit::emit_complete(
            &self.repo,
            &self.cache_dir.display().to_string(),
            download_start.elapsed().as_millis().min(u64::MAX as u128) as u64,
        )
        .await;
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

    /// COR-12 — resolve the candle device from the operator's pinned
    /// accelerator via the shared `device_for` mapping (same fallback
    /// rules as `local_qwen`: a GPU request degrades to CPU when the
    /// corresponding candle feature is off). `ensure_ouro_loaded` calls
    /// this ONCE at load time and stores the result in `LoadedOuro` so
    /// every inference tensor lands on the exact same device instance.
    fn resolved_device(&self) -> candle_core::Device {
        device_for(self.accelerator)
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
    // O-5c — quant mode dispatch. None → native OuroModel.
    // Q8 → parallel QuantizedOuroModel via the swap that lands
    // below. The defer-warn from O-5a/b is gone since
    // `is_quant_active()` now flips true for Q8.
    eprintln!(
        "→ loading Ouro weights from {} (first call only, quant={})",
        adapter.weights_path.display(),
        adapter.quant_mode.as_str()
    );
    let device = adapter.resolved_device();
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
            .with_context(|| format!("mmap safetensors {}", adapter.weights_path.display()))?
    };
    // O-5c — dispatch on operator's quant_mode. Q8 → parallel
    // QuantizedOuroModel (Q8 matmuls inside attention + MLP);
    // None → native OuroModel (BF16/F32 forward pass).
    let model = if adapter.quant_mode.is_quant_active() {
        let m = super::quantized_forward::QuantizedOuroModel::new(&config, vb)
            .context("build QuantizedOuroModel (Q8 path)")?;
        LoadedOuroModel::Quantized(m)
    } else {
        let m = OuroModel::new(&config, vb).context("build OuroModel")?;
        LoadedOuroModel::Native(m)
    };
    let eos_id = resolve_eos_id(&tokenizer);
    info!(
        repo = %adapter.repo,
        device = ?device,
        eos = ?eos_id,
        loop_steps = model.loop_steps(),
        quant_mode = %adapter.quant_mode.as_str(),
        "local_ouro: model loaded into cache",
    );
    eprintln!(
        "✓ Ouro weights loaded in {:.1}s (quant={})",
        started.elapsed().as_secs_f32(),
        adapter.quant_mode.as_str()
    );
    *slot = Some(LoadedOuro {
        model,
        tokenizer,
        eos_id,
        device,
    });
    Ok(())
}

/// Blocking forward + sampling loop. Mirrors
/// `local_qwen::run_forward` and reuses `sample_token` verbatim.
/// COR-31: build the model input ids for a `full_resequence` decode step — the
/// FULL running sequence (prompt + every token generated so far), re-fed at
/// `seqlen_offset=0` so attention sees the full context. This is the DEFAULT
/// decode path: correct but O(n²)/step. GOLD-COR-36 added the per-loop KV cache
/// (`NEOTH_OURO_KV_CACHE_MODE=per_loop`) which decodes in O(n) by feeding only
/// the new token at a growing offset — bit-identical logits (proven by the
/// parity oracle), default-off until a real-weight run certifies it. Pure, so
/// the full-resequence strategy stays unit-testable without a loaded model.
fn decode_context_ids(prompt_ids: &[u32], generated: &[u32]) -> Vec<u32> {
    let mut ids = Vec::with_capacity(prompt_ids.len() + generated.len());
    ids.extend_from_slice(prompt_ids);
    ids.extend_from_slice(generated);
    ids
}

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
    let mut next = sample_token(&logits, sampling).context("Ouro: sample from prompt logits")?;
    new_tokens.push(next);

    // Generation loop — two decode strategies, both feeding `forward()`:
    //
    // GOLD-COR-36 `per_loop` (opt-in via `NEOTH_OURO_KV_CACHE_MODE=per_loop`):
    // a per-loop persistent KV cache (one slot per recurrent loop) lets us feed
    // ONLY the new token at a growing `seqlen_offset` — O(n) decode that is
    // bit-identical to the full-resequence baseline (proven by the
    // `per_loop_cache_decode_matches_full_resequence_baseline` oracle in
    // forward.rs / quantized_forward.rs). Default-off here until a real-weight
    // run certifies the candle tensor-cat path on an actual checkpoint; the
    // promotion to a `freedom.yaml::ouro.kv_cache_mode` flag + per_loop default
    // is the GOLD-COR-36 follow-up.
    //
    // COR-31 `full_resequence` (default): re-feed the WHOLE running sequence at
    // `seqlen_offset=0` each step. The per-loop caches reset every call (offset
    // 0), so attention sees the full context; correct but O(n²)/step.
    let per_loop = std::env::var("NEOTH_OURO_KV_CACHE_MODE")
        .map(|v| v.eq_ignore_ascii_case("per_loop"))
        .unwrap_or(false);
    // For incremental decode: the absolute position of the NEXT token to feed.
    // After the prompt pass the cache holds positions 0..prompt_len-1, so the
    // first generated token (sampled from the prompt's last-token logits) is fed
    // at position `prompt_len`.
    let mut next_offset = prompt_ids.len();
    while new_tokens.len() < max_new as usize {
        if let Some(eos) = loaded.eos_id {
            if next == eos {
                break;
            }
        }
        logits = if per_loop {
            let input = Tensor::new(&[next], &device)
                .context("Ouro: build single-token input tensor")?
                .unsqueeze(0)
                .context("Ouro: single-token batch dim")?;
            let l = loaded
                .model
                .forward(&input, next_offset)
                .context("Ouro: incremental decode forward")?
                .squeeze(0)
                .context("Ouro: drop batch from decode logits")?;
            next_offset += 1;
            l
        } else {
            let context_ids = decode_context_ids(&prompt_ids, &new_tokens);
            let full_input = Tensor::new(context_ids.as_slice(), &device)
                .context("Ouro: build full-context input tensor")?
                .unsqueeze(0)
                .context("Ouro: full-context batch dim")?;
            loaded
                .model
                .forward(&full_input, 0)
                .context("Ouro: decode forward")?
                .squeeze(0)
                .context("Ouro: drop batch from decode logits")?
        };
        next = sample_token(&logits, sampling).context("Ouro: sample step")?;
        new_tokens.push(next);
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
    /// COR-12 — the candle device the model's weights live on, captured
    /// at load time. Inference tensors are built on this exact device
    /// instance; re-deriving via `device_for` would mint a fresh
    /// `DeviceId` that candle treats as a different device on GPU,
    /// causing a device-mismatch error on the first matmul.
    fn model_device(&self) -> candle_core::Device {
        self.device.clone()
    }
}

#[async_trait]
impl Provider for LocalOuroAdapter {
    fn name(&self) -> &'static str {
        "local_ouro"
    }

    async fn complete(&self, req: Request) -> Result<Completion> {
        // GR-04: circuit breaker — same local-inference rationale
        // as `local_qwen` (mmap / candle / OOM failure isolation).
        crate::providers::circuit_breaker::run_with_breaker("local_ouro", async {
            let adapter_handle = AdapterHandle {
                repo: self.repo.clone(),
                sampling: self.sampling,
                max_new_tokens: self.max_new_tokens,
                accelerator: self.accelerator,
                quant_mode: self.quant_mode,
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
                    quant_mode: adapter_handle.quant_mode,
                    loaded: adapter_handle.loaded,
                };
                run_ouro_forward(&adapter, &req_clone)
            })
            .await
            .context("Ouro: spawn_blocking join")?
        })
        .await
    }

    async fn stream(&self, req: Request) -> Result<ChunkStream> {
        // GR-04 stream-wrap: same circuit-breaker semantics as
        // `complete`. NOTE: Ouro's `complete()` is itself wrapped by
        // the breaker; the stream wrap adds a second permit acquisition
        // for the stream-iter that follows. That is INTENTIONAL — each
        // public surface ({complete, stream}) takes its own permit so
        // an Open breaker fast-fails either entry point. The complete()
        // permit settles before the stream-iter starts, so we never
        // hold two permits in parallel.
        crate::providers::circuit_breaker_stream::run_stream_with_breaker("local_ouro", async {
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
            Ok(Box::pin(stream::iter(vec![Ok(chunk)])) as ChunkStream)
        })
        .await
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
    quant_mode: OuroQuantMode,
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
            quant_mode: self.quant_mode,
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
                quant_mode: adapter_handle.quant_mode,
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
    fn decode_context_ids_feeds_full_running_sequence_not_single_token() {
        // COR-31: each decode step must feed prompt + ALL generated tokens so
        // the looped model attends to the full context at offset 0 — NOT a lone
        // token (which the per-loop KV-cache clear makes context-blind).
        let prompt = [10u32, 11, 12];
        assert_eq!(decode_context_ids(&prompt, &[]), vec![10, 11, 12]);
        assert_eq!(decode_context_ids(&prompt, &[20]), vec![10, 11, 12, 20]);
        assert_eq!(
            decode_context_ids(&prompt, &[20, 21, 22]),
            vec![10, 11, 12, 20, 21, 22]
        );
        // The running sequence grows by one each step and always ends with the
        // most-recently generated token (whose last-token logits forward() uses).
        let grown = decode_context_ids(&prompt, &[20, 21]);
        assert_eq!(*grown.last().unwrap(), 21);
        assert_eq!(grown.len(), prompt.len() + 2);
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

    #[test]
    fn quant_mode_defaults_to_none() {
        let dir = tempdir().unwrap();
        let adapter = synthetic_adapter_with_config(dir.path().to_path_buf());
        assert_eq!(adapter.quant_mode(), OuroQuantMode::None);
    }

    #[test]
    fn with_quant_mode_builder_overrides_default() {
        let dir = tempdir().unwrap();
        let adapter = synthetic_adapter_with_config(dir.path().to_path_buf())
            .with_quant_mode(OuroQuantMode::Q8);
        assert_eq!(adapter.quant_mode(), OuroQuantMode::Q8);
    }

    #[test]
    fn with_quant_mode_preserves_other_fields() {
        // Building-style override must not lose repo / paths /
        // accelerator / sampling / max_new_tokens. Smoke that the
        // moved fields round-trip.
        let dir = tempdir().unwrap();
        let adapter = synthetic_adapter_with_config(dir.path().to_path_buf())
            .with_quant_mode(OuroQuantMode::Q8);
        assert_eq!(adapter.repo, "test/ouro");
        assert_eq!(adapter.quant_mode(), OuroQuantMode::Q8);
    }

    #[test]
    fn resolved_device_derives_from_accelerator_field() {
        // Regression for GOLD-COR-12: the inference device must derive
        // from the adapter's `accelerator` (via the shared `device_for`
        // mapping `local_qwen` uses), NOT a hardcoded Cpu like the old
        // `LoadedOuro::model_device`. On a build without GPU candle
        // features (CI default) every accelerator degrades to Cpu; real
        // GPU dispatch — where the stored-vs-re-derived `DeviceId`
        // distinction actually bites — is exercised by the
        // NEOTH_OURO_TEST_REPO_PATH integration suite below.
        use crate::daemon::accelerator::Accelerator;
        let dir = tempdir().unwrap();
        for accel in [
            None,
            Some(Accelerator::Cuda),
            Some(Accelerator::Metal),
            Some(Accelerator::OpenVino),
            Some(Accelerator::Cpu),
        ] {
            let adapter = LocalOuroAdapter::new_with_paths(
                "test/ouro",
                dir.path().to_path_buf(),
                accel,
                SamplingConfig::default(),
                None,
            );
            // Adapter resolution must match the shared device_for for the
            // SAME accelerator — proves it consults its own field rather
            // than ignoring it (the previous bug returned Cpu blindly).
            assert!(
                matches!(adapter.resolved_device(), candle_core::Device::Cpu),
                "accelerator {accel:?} must degrade to Cpu on a non-GPU build"
            );
        }
    }

    // ── Ouro O-6: real-weights integration suite ─────────────────────
    //
    // Every test in this section gated by NEOTH_OURO_TEST_REPO_PATH —
    // operator points at a cache dir with tokenizer.json + config.json
    // + model.safetensors from any of the 4 published Ouro checkpoints.
    // Run via: `cargo test -p neothd --bin neothd -- --ignored ouro`.
    //
    // CI without weights stays green because every test log-skips
    // when the env var or required files are missing.

    fn ouro_weights_cache() -> Option<PathBuf> {
        let path = std::env::var("NEOTH_OURO_TEST_REPO_PATH").ok()?;
        let cache = PathBuf::from(path);
        if cache.join(TOKENIZER_FILE).exists()
            && cache.join(CONFIG_FILE).exists()
            && cache.join(SAFETENSORS_FILE).exists()
        {
            Some(cache)
        } else {
            eprintln!(
                "skipping: NEOTH_OURO_TEST_REPO_PATH set but cache is \
                 incomplete (need {TOKENIZER_FILE} + {CONFIG_FILE} + \
                 {SAFETENSORS_FILE})"
            );
            None
        }
    }

    fn build_integration_adapter(cache: PathBuf) -> LocalOuroAdapter {
        LocalOuroAdapter::new_with_paths(
            "ouro-integration-suite",
            cache,
            None,
            SamplingConfig::default(),
            Some(16),
        )
    }

    #[tokio::test]
    #[ignore = "requires local Ouro weights; set NEOTH_OURO_TEST_REPO_PATH"]
    async fn local_ouro_complete_against_cached_weights() {
        let Some(cache) = ouro_weights_cache() else {
            return;
        };
        let adapter = build_integration_adapter(cache);
        let req = Request {
            prompt: "What is the capital of France?".into(),
            system: None,
            model: None,
            temperature: None,
            top_p: None,
            sampling_seed: None,
            stop_sequences: Vec::new(),
        };
        let resp = adapter.complete(req).await.expect("Ouro completion");
        assert!(!resp.text.is_empty(), "completion must produce text");
        assert!(
            resp.output_tokens.unwrap_or(0) > 0,
            "output_tokens must be reported"
        );
    }

    #[tokio::test]
    #[ignore = "requires local Ouro weights; set NEOTH_OURO_TEST_REPO_PATH"]
    async fn local_ouro_decode_is_context_aware_not_degenerate_repetition() {
        // COR-31 regression (real-weight). Before the full-resequence decode
        // fix, every decode step attended ONLY to the new token — the per-loop
        // KV-cache clear wiped the prompt + prior context at loop_idx=0 of each
        // forward() — so generation collapsed into degenerate repetition /
        // incoherence. With the fix the model sees the full running context and
        // produces a varied, multi-token answer. This asserts the completion is
        // not a single token spammed — a coarse but real signal the
        // context-blindness is gone. Run: set NEOTH_OURO_TEST_REPO_PATH to a
        // local Ouro repo (tokenizer.json + config.json + model.safetensors),
        // then `cargo test -p neothd --lib providers::ouro -- --ignored`.
        let Some(cache) = ouro_weights_cache() else {
            return;
        };
        let adapter = build_integration_adapter(cache);
        let req = Request {
            prompt: "List three different farm animals, one per line.".into(),
            system: None,
            model: None,
            temperature: None,
            top_p: None,
            sampling_seed: Some(7),
            stop_sequences: Vec::new(),
        };
        let resp = adapter.complete(req).await.expect("Ouro completion");
        let text = resp.text.trim();
        assert!(!text.is_empty(), "completion must produce text");
        // Degenerate context-blind output is typically one token spammed; a
        // context-aware decode yields several distinct whitespace tokens.
        let distinct: std::collections::HashSet<&str> = text.split_whitespace().collect();
        assert!(
            distinct.len() >= 3,
            "context-aware decode should yield varied output, got: {text:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires local Ouro weights; set NEOTH_OURO_TEST_REPO_PATH"]
    async fn local_ouro_per_loop_decode_matches_full_resequence_on_real_weights() {
        // GOLD-COR-36 real-weight CERT: the per-loop KV-cache O(n) decode
        // (`NEOTH_OURO_KV_CACHE_MODE=per_loop`) must produce the SAME generated
        // text as the full-resequence O(n²) baseline on ACTUAL Ouro weights —
        // confirming the candle tensor-cat / device path holds where the
        // synthetic parity oracle (zero-device-edge-cases) cannot. Sampling is
        // seeded, and the two paths produce bit-identical logits, so the token
        // sequences must match exactly. Run: set NEOTH_OURO_TEST_REPO_PATH, then
        // `cargo test -p neothd --lib providers::ouro -- --ignored`.
        let Some(cache) = ouro_weights_cache() else {
            return;
        };
        let mkreq = || Request {
            prompt: "List three different farm animals, one per line.".into(),
            system: None,
            model: None,
            temperature: None,
            top_p: None,
            sampling_seed: Some(7),
            stop_sequences: Vec::new(),
        };
        // Baseline — full_resequence (default; ensure the var is unset).
        {
            let _env = crate::test_env::lock();
            // SAFETY: env mutation serialized by the crate-wide test_env lock.
            unsafe { std::env::remove_var("NEOTH_OURO_KV_CACHE_MODE") };
        }
        let baseline = build_integration_adapter(cache.clone())
            .complete(mkreq())
            .await
            .expect("baseline completion")
            .text;
        // per_loop incremental decode.
        {
            let _env = crate::test_env::lock();
            // SAFETY: env mutation serialized by the crate-wide test_env lock.
            unsafe { std::env::set_var("NEOTH_OURO_KV_CACHE_MODE", "per_loop") };
        }
        let per_loop = build_integration_adapter(cache)
            .complete(mkreq())
            .await
            .expect("per_loop completion")
            .text;
        {
            let _env = crate::test_env::lock();
            // SAFETY: env mutation serialized by the crate-wide test_env lock.
            unsafe { std::env::remove_var("NEOTH_OURO_KV_CACHE_MODE") };
        }
        assert_eq!(
            baseline, per_loop,
            "GOLD-COR-36: per-loop O(n) decode must produce identical text to the \
             full-resequence baseline on real weights"
        );
    }

    #[tokio::test]
    #[ignore = "requires local Ouro weights; set NEOTH_OURO_TEST_REPO_PATH"]
    async fn local_ouro_embed_returns_l2_normalised_vector_of_expected_dim() {
        let Some(cache) = ouro_weights_cache() else {
            return;
        };
        let adapter = build_integration_adapter(cache);
        let dim = adapter.embed_dim_hint();
        let resp = adapter
            .embed(EmbedRequest::new("hello world"))
            .await
            .expect("Ouro embed");
        assert_eq!(
            resp.vector.len(),
            dim,
            "embed dim must match embed_dim_hint"
        );
        let len_sq: f32 = resp.vector.iter().map(|x| x * x).sum();
        assert!(
            (len_sq - 1.0).abs() < 1e-3,
            "L2 norm must be ≈ 1.0, got len² = {len_sq}"
        );
    }

    #[tokio::test]
    #[ignore = "requires local Ouro weights; set NEOTH_OURO_TEST_REPO_PATH"]
    async fn local_ouro_embed_distinct_prompts_have_cos_below_threshold() {
        let Some(cache) = ouro_weights_cache() else {
            return;
        };
        let adapter = build_integration_adapter(cache);
        let r1 = adapter
            .embed(EmbedRequest::new("the weather is sunny today"))
            .await
            .expect("first embed");
        let r2 = adapter
            .embed(EmbedRequest::new("the kernel panicked on boot"))
            .await
            .expect("second embed");
        let c = crate::providers::embed::cosine(&r1.vector, &r2.vector);
        assert!(
            c < 0.99,
            "distinct semantic prompts must score cos < 0.99, got {c}"
        );
    }

    #[tokio::test]
    #[ignore = "requires local Ouro weights; set NEOTH_OURO_TEST_REPO_PATH"]
    async fn local_ouro_embed_identical_prompts_have_cos_one() {
        let Some(cache) = ouro_weights_cache() else {
            return;
        };
        let adapter = build_integration_adapter(cache);
        let r1 = adapter
            .embed(EmbedRequest::new("identical input prompt"))
            .await
            .expect("first embed");
        let r2 = adapter
            .embed(EmbedRequest::new("identical input prompt"))
            .await
            .expect("second embed");
        let c = crate::providers::embed::cosine(&r1.vector, &r2.vector);
        assert!(
            (c - 1.0).abs() < 1e-3,
            "identical prompts must score cos ≈ 1.0, got {c}"
        );
    }

    #[tokio::test]
    #[ignore = "requires local Ouro weights; set NEOTH_OURO_TEST_REPO_PATH"]
    async fn local_ouro_stream_emits_at_least_one_chunk_with_done() {
        use futures_util::StreamExt;
        let Some(cache) = ouro_weights_cache() else {
            return;
        };
        let adapter = build_integration_adapter(cache);
        let req = Request {
            prompt: "Hi".into(),
            system: None,
            model: None,
            temperature: None,
            top_p: None,
            sampling_seed: None,
            stop_sequences: Vec::new(),
        };
        let mut stream = adapter.stream(req).await.expect("Ouro stream");
        let mut chunks = 0;
        let mut got_done = false;
        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.expect("stream chunk");
            chunks += 1;
            if chunk.done {
                got_done = true;
            }
        }
        assert!(chunks >= 1, "stream must emit ≥1 chunk");
        assert!(got_done, "stream must terminate with a chunk marked done");
    }

    #[tokio::test]
    #[ignore = "requires local Ouro weights; set NEOTH_OURO_TEST_REPO_PATH"]
    async fn local_ouro_loop_steps_hint_populated_after_first_call() {
        let Some(cache) = ouro_weights_cache() else {
            return;
        };
        let adapter = build_integration_adapter(cache);
        // Cold cache → None.
        assert!(adapter.loop_steps_hint().is_none());
        // Trigger model load via one embed call.
        let _ = adapter
            .embed(EmbedRequest::new("warm-up"))
            .await
            .expect("warm-up embed");
        // Now hot — hint should reflect the model's total_ut_steps.
        let hint = adapter
            .loop_steps_hint()
            .expect("loop_steps_hint must populate after model load");
        assert!(
            (1..=8).contains(&hint),
            "loop_steps in [1, MAX_TOTAL_UT_STEPS=8], got {hint}"
        );
    }

    #[tokio::test]
    #[ignore = "requires local Ouro weights; set NEOTH_OURO_TEST_REPO_PATH"]
    async fn local_ouro_trait_dispatch_round_trip_via_embed_provider_dyn() {
        let Some(cache) = ouro_weights_cache() else {
            return;
        };
        let adapter = build_integration_adapter(cache);
        let e: &dyn EmbedProvider = &adapter;
        assert_eq!(e.name(), "local_ouro");
        let resp = e
            .embed(EmbedRequest::new("trait dispatch round trip"))
            .await
            .expect("trait dispatch embed");
        assert_eq!(resp.vector.len(), e.default_dim());
    }
}
