//! Local-only BGE-M3 dense embedding adapter.
//!
//! This module deliberately owns inference only.  The reviewed artifact
//! manifest and acquisition lifecycle live in `bge_m3_artifacts`; opening an
//! adapter requires that lifecycle to have already verified the exact pinned
//! cache.  In particular, this code never contacts Hugging Face and never
//! falls back to Qwen or a remote embedding endpoint.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{Context, Result};
use async_trait::async_trait;
use candle_core::{DType, Device, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::xlm_roberta::{Config, XLMRobertaModel};
use tokenizers::{Tokenizer, TruncationDirection, TruncationParams, TruncationStrategy};

use super::bge_m3_artifacts::{
    BGE_M3_EMBEDDING_DIMENSION, BGE_M3_MAX_TOKENS as MANIFEST_MAX_TOKENS, DEFAULT_REPO,
    DEFAULT_REVISION, VerifiedBgeM3Artifacts,
};
use super::embed::{EmbedProvider, EmbedRequest, EmbedResponse};

/// BGE-M3's reviewed dense-vector width.
pub const BGE_M3_DIM: usize = BGE_M3_EMBEDDING_DIMENSION;
/// The official BGE-M3 model supports sequences through 8192 tokens.
pub const BGE_M3_MAX_TOKENS: usize = MANIFEST_MAX_TOKENS;
/// Bump when the dense embedding path (CLS pooling + L2 normalisation) changes.
pub(crate) const BGE_M3_EMBEDDING_ALGORITHM: &str = "cls-pool-l2-v1";

/// Exact official artifact identity shared with operator surfaces.
pub const fn pinned_model_identity() -> (&'static str, &'static str) {
    (DEFAULT_REPO, DEFAULT_REVISION)
}

struct LoadedBgeM3 {
    model: XLMRobertaModel,
    tokenizer: Tokenizer,
    device: Device,
}

/// A local BGE-M3 dense embedding provider backed only by a verified cache.
///
/// `Mutex` serializes access to the Candle model.  That keeps the model and
/// tokenizer reusable without holding any async lock across the blocking
/// tensor work.
pub struct LocalBgeM3Adapter {
    cache_dir: PathBuf,
    config_path: PathBuf,
    tokenizer_path: PathBuf,
    weights_path: PathBuf,
    loaded: Arc<Mutex<Option<LoadedBgeM3>>>,
}

impl LocalBgeM3Adapter {
    /// Consume the sealed cache capability minted by the artifact verifier.
    /// New provider-factory code should use this constructor: it cannot
    /// accidentally turn an arbitrary directory into an inference source.
    pub(crate) fn open_verified(artifacts: VerifiedBgeM3Artifacts) -> Result<Self> {
        Ok(Self {
            cache_dir: artifacts.cache_dir().to_path_buf(),
            config_path: artifacts.config_path().to_path_buf(),
            tokenizer_path: artifacts.tokenizer_path().to_path_buf(),
            weights_path: artifacts.weights_path().to_path_buf(),
            loaded: Arc::new(Mutex::new(None)),
        })
    }

    /// Construct the real Candle model without producing an embedding.  The
    /// model lifecycle calls this before reporting a downloaded cache ready.
    pub async fn validate_load(&self) -> Result<()> {
        let loaded = Arc::clone(&self.loaded);
        let config_path = self.config_path.clone();
        let tokenizer_path = self.tokenizer_path.clone();
        let weights_path = self.weights_path.clone();
        tokio::task::spawn_blocking(move || {
            ensure_loaded(&loaded, &config_path, &tokenizer_path, &weights_path)
        })
        .await
        .context("join BGE-M3 Candle load")?
    }

    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }
}

fn ensure_loaded(
    loaded: &Arc<Mutex<Option<LoadedBgeM3>>>,
    config_path: &Path,
    tokenizer_path: &Path,
    weights_path: &Path,
) -> Result<()> {
    let mut slot = loaded
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if slot.is_some() {
        return Ok(());
    }

    let config: Config = serde_json::from_str(
        &std::fs::read_to_string(config_path)
            .with_context(|| format!("read BGE-M3 config {}", config_path.display()))?,
    )
    .context("parse BGE-M3 XLM-R config")?;
    if config.hidden_size != BGE_M3_DIM {
        anyhow::bail!(
            "BGE-M3 config hidden_size {} is not the reviewed {BGE_M3_DIM}",
            config.hidden_size
        );
    }
    if config.max_position_embeddings < BGE_M3_MAX_TOKENS {
        anyhow::bail!(
            "BGE-M3 config max_position_embeddings {} cannot serve {BGE_M3_MAX_TOKENS} tokens",
            config.max_position_embeddings
        );
    }

    let mut tokenizer = Tokenizer::from_file(tokenizer_path)
        .map_err(|error| anyhow::anyhow!("load BGE-M3 tokenizer.json: {error}"))?;
    // Configure truncation before `encode(..., true)`: tokenizers first
    // truncates the raw sequence and then its XLM-R post-processor adds the
    // leading CLS and trailing SEP tokens.  Truncating the finished Encoding
    // would otherwise cut the trailing SEP off a long request.
    tokenizer
        .with_truncation(Some(TruncationParams {
            max_length: BGE_M3_MAX_TOKENS,
            strategy: TruncationStrategy::LongestFirst,
            stride: 0,
            direction: TruncationDirection::Right,
        }))
        .map_err(|error| anyhow::anyhow!("configure BGE-M3 tokenizer truncation: {error}"))?;
    let device = Device::Cpu;
    // Candle's PTH loader reads PyTorch tensor storage through its native,
    // data-only checkpoint reader; it does not invoke Python or unpickle
    // executable objects.  BAAI/bge-m3 publishes the official reviewed
    // checkpoint as `pytorch_model.bin`, not a safetensors file.
    let vb = VarBuilder::from_pth(weights_path, DType::F32, &device)
        .with_context(|| format!("open BGE-M3 PyTorch weights {}", weights_path.display()))?;
    // HF XLMRobertaModel state dictionaries use `embeddings.*` and
    // `encoder.layer.*` at their root.  Passing `vb` directly is therefore
    // correct; `vb.pp("encoder")` would incorrectly double-prefix the keys.
    let model = XLMRobertaModel::new(&config, vb).context("build BGE-M3 XLM-R encoder")?;
    *slot = Some(LoadedBgeM3 {
        model,
        tokenizer,
        device,
    });
    Ok(())
}

fn normalize_bge_vector(vector: &mut [f32]) -> Result<()> {
    if vector.len() != BGE_M3_DIM {
        anyhow::bail!(
            "BGE-M3 CLS vector has dimension {}, expected {BGE_M3_DIM}",
            vector.len()
        );
    }
    if vector.iter().any(|value| !value.is_finite()) {
        anyhow::bail!("BGE-M3 CLS vector contains a non-finite value");
    }
    if !super::embed::l2_normalize(vector) {
        anyhow::bail!("BGE-M3 CLS vector is zero and cannot be normalized");
    }
    if vector.iter().any(|value| !value.is_finite()) {
        anyhow::bail!("BGE-M3 normalized vector contains a non-finite value");
    }
    Ok(())
}

fn encode_bge_input(tokenizer: &Tokenizer, text: &str) -> Result<tokenizers::Encoding> {
    let encoding = tokenizer
        .encode(text, true)
        .map_err(|error| anyhow::anyhow!("tokenize BGE-M3 input: {error}"))?;
    if encoding.get_ids().is_empty() {
        anyhow::bail!("BGE-M3 tokenizer produced no input tokens");
    }
    if encoding.get_ids().len() > BGE_M3_MAX_TOKENS {
        anyhow::bail!("BGE-M3 tokenizer exceeded its configured {BGE_M3_MAX_TOKENS}-token limit");
    }
    Ok(encoding)
}

fn embed_blocking(
    loaded: Arc<Mutex<Option<LoadedBgeM3>>>,
    config_path: PathBuf,
    tokenizer_path: PathBuf,
    weights_path: PathBuf,
    text: String,
) -> Result<Vec<f32>> {
    if text.trim().is_empty() {
        anyhow::bail!("BGE-M3 embedding input is empty");
    }
    ensure_loaded(&loaded, &config_path, &tokenizer_path, &weights_path)?;
    let slot = loaded
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let loaded = slot
        .as_ref()
        .expect("BGE-M3 loader populated its cache slot");

    let encoding = encode_bge_input(&loaded.tokenizer, &text)?;
    let input_ids = Tensor::new(encoding.get_ids(), &loaded.device)
        .context("build BGE-M3 input id tensor")?
        .unsqueeze(0)?;
    let attention_mask = Tensor::new(encoding.get_attention_mask(), &loaded.device)
        .context("build BGE-M3 attention mask")?
        .unsqueeze(0)?;
    let token_type_ids = Tensor::new(encoding.get_type_ids(), &loaded.device)
        .context("build BGE-M3 token-type tensor")?
        .unsqueeze(0)?;
    let hidden = loaded
        .model
        .forward(
            &input_ids,
            &attention_mask,
            &token_type_ids,
            None,
            None,
            None,
        )
        .context("run BGE-M3 XLM-R forward pass")?;
    // Sentence-Transformers' official `1_Pooling/config.json` selects only
    // CLS pooling.  This is intentionally not a mean pool.
    let cls = hidden
        .get_on_dim(1, 0)
        .context("select BGE-M3 CLS hidden state")?
        .squeeze(0)
        .context("remove BGE-M3 batch dimension")?;
    let mut vector = cls
        .to_dtype(DType::F32)?
        .to_vec1::<f32>()
        .context("extract BGE-M3 CLS vector")?;
    normalize_bge_vector(&mut vector)?;
    Ok(vector)
}

#[async_trait]
impl EmbedProvider for LocalBgeM3Adapter {
    fn name(&self) -> &'static str {
        "local_bge_m3"
    }

    fn default_dim(&self) -> usize {
        BGE_M3_DIM
    }

    async fn embed(&self, req: EmbedRequest) -> Result<EmbedResponse> {
        if let Some(requested) = req.model.as_deref()
            && requested != DEFAULT_REPO
            && requested != format!("{DEFAULT_REPO}@{DEFAULT_REVISION}")
        {
            anyhow::bail!(
                "BGE-M3 provider is pinned to {DEFAULT_REPO}@{DEFAULT_REVISION}; \
                 request selected incompatible model `{requested}`"
            );
        }
        let started = Instant::now();
        let loaded = Arc::clone(&self.loaded);
        let config_path = self.config_path.clone();
        let tokenizer_path = self.tokenizer_path.clone();
        let weights_path = self.weights_path.clone();
        let vector = tokio::task::spawn_blocking(move || {
            embed_blocking(loaded, config_path, tokenizer_path, weights_path, req.text)
        })
        .await
        .context("join BGE-M3 embedding task")??;
        Ok(EmbedResponse {
            vector,
            model: format!("{DEFAULT_REPO}@{DEFAULT_REVISION}"),
            latency: started.elapsed(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bge_vector_normalization_requires_exact_finite_dimension() {
        let mut valid = vec![0.0_f32; BGE_M3_DIM];
        valid[0] = 3.0;
        valid[1] = 4.0;
        normalize_bge_vector(&mut valid).unwrap();
        assert!((valid.iter().map(|value| value * value).sum::<f32>() - 1.0).abs() < 1e-6);

        let mut short = vec![1.0_f32; BGE_M3_DIM - 1];
        assert!(normalize_bge_vector(&mut short).is_err());

        let mut non_finite = vec![0.0_f32; BGE_M3_DIM];
        non_finite[0] = f32::NAN;
        assert!(normalize_bge_vector(&mut non_finite).is_err());
    }

    /// Hosted acceptance entry: the runner materializes only the immutable
    /// manifest into the supplied NEOTH home, then this test opens the native
    /// Candle PTH reader and performs one real official-model embedding.  It
    /// is ignored locally because the workstation BSOD hold forbids model
    /// parsing and runtime work.
    #[tokio::test]
    #[ignore = "requires a hosted runner with the hash-verified official BGE-M3 cache"]
    async fn hosted_official_bge_m3_smoke() {
        let home = std::env::var_os("NEOTH_BGE_M3_HOSTED_NEOTH_HOME")
            .expect("hosted smoke must provide NEOTH_BGE_M3_HOSTED_NEOTH_HOME");
        let verified =
            super::super::bge_m3_artifacts::BgeM3Artifacts::at_neoth_home(Path::new(&home))
                .verify()
                .expect("hosted BGE-M3 cache must match the immutable manifest");
        let adapter = LocalBgeM3Adapter::open_verified(verified).unwrap();
        adapter.validate_load().await.unwrap();
        let english = adapter
            .embed(EmbedRequest::new("BGE-M3 hosted smoke"))
            .await
            .unwrap();
        let english_repeat = adapter
            .embed(EmbedRequest::new("BGE-M3 hosted smoke"))
            .await
            .unwrap();
        let german = adapter
            .embed(EmbedRequest::new(
                "Ein lokaler mehrsprachiger Einbettungstest.",
            ))
            .await
            .unwrap();
        for response in [&english, &english_repeat, &german] {
            assert_eq!(response.dim(), BGE_M3_DIM);
            let length_sq: f32 = response.vector.iter().map(|value| value * value).sum();
            assert!((length_sq - 1.0).abs() < 1e-4);
        }
        assert_eq!(
            english.vector, english_repeat.vector,
            "CPU inference must be deterministic"
        );
        assert!(
            super::super::embed::cosine(&english.vector, &german.vector) < 0.99999,
            "distinct bilingual inputs must not collapse to one vector"
        );
        assert!(adapter.embed(EmbedRequest::new("   ")).await.is_err());
        assert!(
            adapter
                .embed(EmbedRequest::new("test").with_model("other-model"))
                .await
                .is_err()
        );

        // Tokenize a long input only: do not run a costly 8192-token forward
        // pass merely to prove the special-token boundary.
        let tokenizer = adapter
            .loaded
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .tokenizer
            .clone();
        let long_encoding = encode_bge_input(&tokenizer, &"multilingual ".repeat(10_000)).unwrap();
        assert!(long_encoding.get_ids().len() <= BGE_M3_MAX_TOKENS);
        let sep_id = tokenizer
            .token_to_id("</s>")
            .expect("official XLM-R SEP token");
        assert_eq!(long_encoding.get_ids().last(), Some(&sep_id));
    }
}
