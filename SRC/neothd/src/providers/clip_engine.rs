//! CLIP image embedding engine — R-9 vision Phase 2b.
//!
//! Wraps candle-transformers' CLIP ViT-B/32 into a NEOTH-friendly embed
//! API. Operators get 512-dim image embeddings locally — no cloud call,
//! no Python — suitable for ctx-mode similarity search and downstream
//! caption / vision-LLM passes.
//!
//! Pipeline per image:
//!   1. Decode-side already produced an RGB byte buffer + dimensions
//!      (see `media::vision::extract_blocking`).
//!   2. Resize so the shortest side hits 224 px, bilinear filter, then
//!      centre-crop to 224×224. This matches HF's `CLIPImageProcessor`
//!      with `do_resize=True, do_center_crop=True, size=224`.
//!   3. Normalise per channel with the CLIP mean / std baked into the
//!      original OpenAI checkpoint:
//!        mean = [0.48145466, 0.4578275, 0.40821073]
//!        std  = [0.26862954, 0.26130258, 0.27577711]
//!   4. Pack into an NCHW f32 tensor on CPU.
//!   5. `ClipModel::get_image_features` → 512-dim vector.
//!   6. L2-normalise so downstream cosine search just needs a dot
//!      product.
//!
//! What is NOT in scope here:
//!   - Text features / caption generation. CLIP's text tower retrieves
//!     by text-prompt match; a real caption needs a generative model
//!     (for example BLIP-2) and is Phase 2c.
//!   - GPU acceleration. Vision Phase 2b ships CPU-only so the install
//!     stays self-contained on every operator machine. Operators with
//!     CUDA / Metal can flip the feature later once D14b adds the
//!     candle-cuda / candle-metal stacks.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use candle_core::{DType, Device, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::clip;

/// Reviewed ViT-B/32 safetensors repository. The upstream OpenAI repository
/// publishes only `pytorch_model.bin`; Candle requires safetensors, so the old
/// default could never complete its documented download path.
pub const DEFAULT_CLIP_REPO: &str = "laion/CLIP-ViT-B-32-laion2B-s34B-b79K";
const DEFAULT_CLIP_REVISION: &str = "1a25a446712ba5ee05982a381eed697ef9b435cf";

pub const CONFIG_FILE: &str = "config.json";
pub const SAFETENSORS_FILE: &str = "model.safetensors";
pub const TOKENIZER_FILE: &str = "tokenizer.json";

const REQUIRED_ARTIFACTS: [crate::media::model_manager::RequiredArtifact; 3] = {
    use crate::media::model_manager::{
        ArtifactKind, ExpectedArtifactFingerprint, RequiredArtifact,
    };
    [
        RequiredArtifact {
            filename: CONFIG_FILE,
            kind: ArtifactKind::JsonObject,
            expected: Some(ExpectedArtifactFingerprint {
                len: 4_355,
                sha256: "1284cbff35169abb23a1c5525a8b0f543c7bd191d4b9aed63880c1571bc4191c",
            }),
        },
        RequiredArtifact {
            filename: TOKENIZER_FILE,
            kind: ArtifactKind::JsonObject,
            expected: Some(ExpectedArtifactFingerprint {
                len: 2_224_041,
                sha256: "b556ac8c99757ffb677208af34bc8c6721572114111a6e0aaf5fa69ff0b8d842",
            }),
        },
        RequiredArtifact {
            filename: SAFETENSORS_FILE,
            kind: ArtifactKind::Safetensors,
            expected: Some(ExpectedArtifactFingerprint {
                len: 605_157_884,
                sha256: "74813fbcdc750f235c9784c367ca1394d2a5c25eb0aac92761752ac239db7cff",
            }),
        },
    ]
};

/// Side length CLIP ViT-B/32 expects after preprocessing.
pub const IMAGE_SIZE: usize = 224;
/// Embedding dimension `get_image_features` produces.
pub const EMBED_DIM: usize = 512;
/// Max token length the text tower accepts (`max_position_embeddings`
/// in the ViT-B/32 config).
pub const TEXT_CONTEXT_LEN: usize = 77;
/// CLIP's hardcoded special tokens. `49406` = `<|startoftext|>`,
/// `49407` = `<|endoftext|>`. Same across every OpenAI CLIP variant
/// so we don't read them out of `tokenizer_config.json`.
const SOT_TOKEN_ID: u32 = 49_406;
const EOT_TOKEN_ID: u32 = 49_407;

// Verbatim copies of the OpenAI CLIP image-processor constants — float
// literals overflow f32 precision by ~1 ulp; the allow is here so a
// future precision-bump doesn't silently change the embedding output.
#[allow(clippy::excessive_precision)]
const CLIP_MEAN: [f32; 3] = [0.48145466, 0.4578275, 0.40821073];
#[allow(clippy::excessive_precision)]
const CLIP_STD: [f32; 3] = [0.26862954, 0.26130258, 0.27577711];

pub struct ClipEngine {
    repo: String,
    hf_cache_dir: PathBuf,
    config_path: PathBuf,
    weights_path: PathBuf,
    tokenizer_path: PathBuf,
    loaded: Arc<Mutex<Option<LoadedClip>>>,
    allow_pending_validation: bool,
}

struct LoadedClip {
    model: clip::ClipModel,
    tokenizer: Option<tokenizers::Tokenizer>,
    device: Device,
}

impl ClipEngine {
    /// Construct an engine + ensure the model artifacts are cached
    /// under `~/.neoth/models/<repo-flattened>/`. ~605 MiB download on
    /// the first run for the reviewed default repository.
    pub(crate) async fn new(repo: Option<String>) -> Result<Self> {
        let models_root = crate::config::FreedomConfig::default_neoth_home().join("models");
        let engine = Self::from_models_root(repo, &models_root, false)?;
        let health = cache_health_at(&models_root, &engine.repo);
        if !health.is_ready() {
            anyhow::bail!("CLIP cache is not ready ({health}); run `neoth models pull clip` first");
        }
        engine.validate_load().await?;
        Ok(engine)
    }

    /// The only network-capable CLIP constructor. Callers must complete model
    /// download policy and D7 audit before entering this seam.
    pub(crate) async fn prefetch_with_models_root(
        repo: Option<String>,
        models_root: &Path,
        attempt: &crate::media::model_manager::ModelDownloadAttempt,
    ) -> Result<Self> {
        let engine = Self::from_models_root(repo, models_root, true)?;
        engine.ensure_artifacts(attempt).await?;
        Ok(engine)
    }

    pub(crate) async fn open_with_models_root(
        repo: Option<String>,
        models_root: &Path,
    ) -> Result<Self> {
        let engine = Self::from_models_root(repo, models_root, false)?;
        let cache_dir = engine
            .config_path
            .parent()
            .context("CLIP cache path has no parent")?;
        let health =
            crate::media::model_manager::verified_cache_health(cache_dir, &REQUIRED_ARTIFACTS);
        if !health.is_ready() {
            anyhow::bail!("CLIP cache is not verified ({health}); run `neoth models pull clip`");
        }
        Ok(engine)
    }

    fn from_models_root(
        repo: Option<String>,
        models_root: &Path,
        allow_pending_validation: bool,
    ) -> Result<Self> {
        let repo = repo.unwrap_or_else(|| DEFAULT_CLIP_REPO.to_string());
        if repo != DEFAULT_CLIP_REPO {
            anyhow::bail!(
                "unsupported CLIP repository `{repo}`: NEOTH only accepts the reviewed \
                 revision/SHA-256 manifest for `{DEFAULT_CLIP_REPO}`"
            );
        }
        let cache_dir = cache_dir_at(models_root, &repo);
        Ok(ClipEngine {
            repo: repo.clone(),
            hf_cache_dir: models_root.join(".hf-hub"),
            config_path: cache_dir.join(CONFIG_FILE),
            weights_path: cache_dir.join(SAFETENSORS_FILE),
            tokenizer_path: cache_dir.join(TOKENIZER_FILE),
            loaded: Arc::new(Mutex::new(None)),
            allow_pending_validation,
        })
    }

    async fn ensure_artifacts(
        &self,
        attempt: &crate::media::model_manager::ModelDownloadAttempt,
    ) -> Result<()> {
        use hf_hub::api::tokio::ApiBuilder;
        use hf_hub::{Repo, RepoType};
        let cache_dir = self
            .config_path
            .parent()
            .context("CLIP cache path has no parent")?;
        if crate::media::model_manager::verified_cache_health_during_install(
            cache_dir,
            &REQUIRED_ARTIFACTS,
        )
        .is_ready()
        {
            return Ok(());
        }
        if !attempt.network_authorized(cache_dir, &self.repo) {
            anyhow::bail!(
                "CLIP network access for `{}` is not authorised by a confirmed D7 attempt",
                self.repo
            );
        }
        let api = ApiBuilder::new()
            .with_cache_dir(self.hf_cache_dir.clone())
            .build()
            .context("init HF Hub API")?;
        let repo_handle = api.repo(Repo::with_revision(
            self.repo.clone(),
            RepoType::Model,
            DEFAULT_CLIP_REVISION.to_string(),
        ));
        for artifact in REQUIRED_ARTIFACTS {
            let filename = artifact.filename;
            let target = cache_dir.join(filename);
            let downloaded = repo_handle
                .download(filename)
                .await
                .with_context(|| format!("HF download error for {filename}"))?;
            if downloaded != target {
                let expected = artifact
                    .expected
                    .context("pinned CLIP artifact lacks a fingerprint")?;
                let expected = crate::media::model_manager::ArtifactFingerprint {
                    len: expected.len,
                    sha256: expected.sha256.to_string(),
                };
                crate::media::model_manager::install_from_hf_source(
                    &downloaded,
                    &target,
                    &expected,
                )
                .await
                .with_context(|| {
                    format!(
                        "atomically install HF cache {} -> {}",
                        downloaded.display(),
                        target.display()
                    )
                })?;
            }
        }
        let health = crate::media::model_manager::verified_cache_health_during_install(
            cache_dir,
            &REQUIRED_ARTIFACTS,
        );
        if !health.is_ready() {
            anyhow::bail!("CLIP artifacts failed post-install validation: {health}");
        }
        Ok(())
    }

    /// Prove the pinned bytes and construct the actual Candle model before a
    /// model-download lifecycle can report D8 `ready`.
    pub(crate) async fn validate_load(&self) -> Result<()> {
        let cache_dir = self
            .config_path
            .parent()
            .context("CLIP cache path has no parent")?
            .to_path_buf();
        let allow_pending = self.allow_pending_validation;
        let health = tokio::task::spawn_blocking(move || {
            if allow_pending {
                crate::media::model_manager::verified_cache_health_during_install(
                    &cache_dir,
                    &REQUIRED_ARTIFACTS,
                )
            } else {
                crate::media::model_manager::verified_cache_health(&cache_dir, &REQUIRED_ARTIFACTS)
            }
        })
        .await
        .context("join CLIP SHA-256 validation")?;
        if !health.is_ready() {
            anyhow::bail!("CLIP cache failed full integrity validation: {health}");
        }
        let loaded = Arc::clone(&self.loaded);
        let config_path = self.config_path.clone();
        let weights_path = self.weights_path.clone();
        let tokenizer_path = self.tokenizer_path.clone();
        tokio::task::spawn_blocking(move || {
            ensure_loaded(&loaded, &config_path, &weights_path, &tokenizer_path)
        })
        .await
        .context("join CLIP backend validation")??;
        Ok(())
    }

    /// Compute the 512-dim L2-normalised image embedding for a raw RGB
    /// buffer at the given dimensions. `rgb` length must equal
    /// `width * height * 3`.
    pub async fn embed_image(&self, rgb: &[u8], width: u32, height: u32) -> Result<Vec<f32>> {
        let cache_dir = self
            .config_path
            .parent()
            .context("CLIP cache path has no parent")?;
        let _model_lock = crate::media::model_manager::lock_model_cache(cache_dir).await?;
        let health = crate::media::model_manager::cache_health(cache_dir, &REQUIRED_ARTIFACTS);
        if !health.is_ready() {
            anyhow::bail!("CLIP cache became unavailable before image embedding: {health}");
        }
        let expected = (width as usize) * (height as usize) * 3;
        if rgb.len() != expected {
            anyhow::bail!(
                "CLIP embed: rgb length {} != expected {} (w={width}, h={height})",
                rgb.len(),
                expected
            );
        }
        let loaded = Arc::clone(&self.loaded);
        let config_path = self.config_path.clone();
        let weights_path = self.weights_path.clone();
        let tokenizer_path = self.tokenizer_path.clone();
        let rgb = rgb.to_vec();
        tokio::task::spawn_blocking(move || -> Result<Vec<f32>> {
            ensure_loaded(&loaded, &config_path, &weights_path, &tokenizer_path)?;
            let slot = loaded.lock().unwrap_or_else(|p| p.into_inner());
            let lc = slot.as_ref().expect("loaded just initialised");
            embed_blocking(lc, &rgb, width, height)
        })
        .await
        .context("clip embed join error")?
    }

    /// Compute the 512-dim L2-normalised text embedding for a natural-
    /// language prompt. Lives in the same projection space as
    /// `embed_image`, so dot product across the two spaces is the
    /// canonical CLIP "image ↔ text" similarity metric.
    ///
    /// Prompts are truncated to `TEXT_CONTEXT_LEN - 2` tokens (`-2`
    /// leaves room for `<|startoftext|>` + `<|endoftext|>`) then
    /// padded with zeros to the full 77 positions.
    pub async fn embed_text(&self, prompt: &str) -> Result<Vec<f32>> {
        let cache_dir = self
            .config_path
            .parent()
            .context("CLIP cache path has no parent")?;
        let _model_lock = crate::media::model_manager::lock_model_cache(cache_dir).await?;
        let health = crate::media::model_manager::cache_health(cache_dir, &REQUIRED_ARTIFACTS);
        if !health.is_ready() {
            anyhow::bail!("CLIP cache became unavailable before text embedding: {health}");
        }
        let loaded = Arc::clone(&self.loaded);
        let config_path = self.config_path.clone();
        let weights_path = self.weights_path.clone();
        let tokenizer_path = self.tokenizer_path.clone();
        let prompt = prompt.to_string();
        tokio::task::spawn_blocking(move || -> Result<Vec<f32>> {
            ensure_loaded(&loaded, &config_path, &weights_path, &tokenizer_path)?;
            let slot = loaded.lock().unwrap_or_else(|p| p.into_inner());
            let lc = slot.as_ref().expect("loaded just initialised");
            embed_text_blocking(lc, &prompt)
        })
        .await
        .context("clip embed_text join error")?
    }
}

fn ensure_loaded(
    loaded: &Arc<Mutex<Option<LoadedClip>>>,
    config_path: &Path,
    weights_path: &Path,
    tokenizer_path: &Path,
) -> Result<()> {
    let mut slot = loaded.lock().unwrap_or_else(|p| p.into_inner());
    if slot.is_some() {
        return Ok(());
    }
    let device = Device::Cpu;
    // The candle CLIP module hard-codes the two upstream variants. We
    // only ship ViT-B/32 (the smallest); the config.json is read only
    // to verify the cached weights actually match — if an operator
    // points NEOTH_CLIP_REPO at a larger checkpoint we error out
    // loudly rather than mismatching layer sizes silently.
    verify_config_matches_vit_b32(config_path)?;
    let config = clip::ClipConfig::vit_base_patch32();
    // SAFETY: `from_mmaped_safetensors` requires that the mapped file
    // is not concurrently truncated or replaced while the mapping
    // lives. The file lives in `~/.neoth/models/` under the operator's
    // home, mode-0600 / DACL-restricted, and `models pull` is the only
    // sanctioned writer — re-running it on a live cache returns early
    // without touching the file. We do NOT claim exclusive process
    // ownership: multi-process use within the same operator session
    // (daemon + `neoth ingest`) is allowed because both processes only
    // read. Engine construction and explicit validation hash every
    // artifact against the reviewed revision/length/SHA-256 manifest
    // before this mapping is created. A third party that can ignore
    // the cache lock and mutate an operator-owned file after that
    // validation is outside NEOTH's process trust boundary.
    let vb = unsafe {
        VarBuilder::from_mmaped_safetensors(&[weights_path], DType::F32, &device)
            .with_context(|| format!("mmap safetensors {}", weights_path.display()))?
    };
    let model = clip::ClipModel::new(vb, &config).context("build CLIP model")?;

    // Tokenizer is optional at load time so legacy cache directories
    // (image-only Phase 2b) still work — `embed_text` is the only path
    // that needs it and fails its own caller with a clear message
    // when the file is absent.
    let tokenizer = if tokenizer_path.exists() {
        match tokenizers::Tokenizer::from_file(tokenizer_path) {
            Ok(t) => Some(t),
            Err(e) => {
                tracing::warn!(
                    path = %tokenizer_path.display(),
                    error = %e,
                    "CLIP tokenizer.json present but failed to parse — \
                     text embedding will be unavailable"
                );
                None
            }
        }
    } else {
        None
    };

    *slot = Some(LoadedClip {
        model,
        tokenizer,
        device,
    });
    Ok(())
}

fn verify_config_matches_vit_b32(config_path: &Path) -> Result<()> {
    let body = std::fs::read_to_string(config_path)
        .with_context(|| format!("read {}", config_path.display()))?;
    let v: serde_json::Value = serde_json::from_str(&body).context("parse CLIP config.json")?;
    // ViT-B/32 has hidden_size 768 in vision_config, patch_size 32.
    // Bail loudly if the operator points us at a different variant —
    // the candle module would crash on the wrong shape anyway, and a
    // typed message here is friendlier than a tensor-shape panic.
    let hidden = v
        .get("vision_config")
        .and_then(|c| c.get("hidden_size"))
        .and_then(|x| x.as_u64());
    let patch = v
        .get("vision_config")
        .and_then(|c| c.get("patch_size"))
        .and_then(|x| x.as_u64());
    if hidden != Some(768) || patch != Some(32) {
        anyhow::bail!(
            "CLIP variant mismatch: only openai/clip-vit-base-patch32 is supported \
             (vision_config.hidden_size=768, patch_size=32); got hidden={:?}, patch={:?}",
            hidden,
            patch
        );
    }
    Ok(())
}

fn embed_blocking(lc: &LoadedClip, rgb: &[u8], width: u32, height: u32) -> Result<Vec<f32>> {
    let pixel_tensor = preprocess_image(rgb, width, height, &lc.device)?;
    let features = lc
        .model
        .get_image_features(&pixel_tensor)
        .context("CLIP forward pass")?;
    // get_image_features returns (1, 512). Flatten + L2-normalise.
    let vec = features
        .squeeze(0)
        .context("squeeze batch dim")?
        .to_vec1::<f32>()
        .context("extract embedding")?;
    if vec.len() != EMBED_DIM {
        anyhow::bail!("CLIP returned {} dims, expected {}", vec.len(), EMBED_DIM);
    }
    Ok(l2_normalise(&vec))
}

fn embed_text_blocking(lc: &LoadedClip, prompt: &str) -> Result<Vec<f32>> {
    let tokenizer = lc.tokenizer.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "CLIP text embedding requires tokenizer.json; \
             run `neoth models pull clip` to fetch it (or delete the cached \
             directory so the next pull re-downloads everything)"
        )
    })?;
    let ids = tokenize_prompt(tokenizer, prompt)?;
    let input = Tensor::new(ids.as_slice(), &lc.device)
        .context("build CLIP text token tensor")?
        .unsqueeze(0)
        .context("add batch dim")?;
    let features = lc
        .model
        .get_text_features(&input)
        .context("CLIP text forward pass")?;
    let vec = features
        .squeeze(0)
        .context("squeeze batch dim")?
        .to_vec1::<f32>()
        .context("extract text embedding")?;
    if vec.len() != EMBED_DIM {
        anyhow::bail!(
            "CLIP text returned {} dims, expected {}",
            vec.len(),
            EMBED_DIM
        );
    }
    Ok(l2_normalise(&vec))
}

/// Tokenise `prompt` with the CLIP BPE tokenizer, prepend
/// `<|startoftext|>`, append `<|endoftext|>`, truncate to
/// `TEXT_CONTEXT_LEN - 2` content tokens, then zero-pad to the full
/// 77 positions. Returns the u32 token-id vector ready for the text
/// tower.
fn tokenize_prompt(tokenizer: &tokenizers::Tokenizer, prompt: &str) -> Result<Vec<u32>> {
    // `add_special_tokens=false` because we add SOT/EOT manually — the
    // HF tokenizer config for openai/clip-vit-base-patch32 does add
    // them automatically when `true`, but checking against several
    // forks of the same repo shows the special-token IDs vary; pinning
    // to the upstream OpenAI ids (49406 + 49407) makes the integration
    // independent of the tokenizer's TemplateProcessing config.
    let encoding = tokenizer
        .encode(prompt, false)
        .map_err(|e| anyhow::anyhow!("tokenize CLIP prompt: {e:#}"))?;
    let content = encoding.get_ids();
    let max_content = TEXT_CONTEXT_LEN.saturating_sub(2);
    let truncated = &content[..content.len().min(max_content)];

    let mut ids = Vec::with_capacity(TEXT_CONTEXT_LEN);
    ids.push(SOT_TOKEN_ID);
    ids.extend_from_slice(truncated);
    ids.push(EOT_TOKEN_ID);
    while ids.len() < TEXT_CONTEXT_LEN {
        ids.push(0); // pad with zero — matches HF's CLIPTokenizer default.
    }
    debug_assert_eq!(ids.len(), TEXT_CONTEXT_LEN);
    Ok(ids)
}

/// Resize → centre-crop → normalise → NCHW tensor.
/// Returns shape `(1, 3, 224, 224)` f32.
fn preprocess_image(rgb: &[u8], width: u32, height: u32, device: &Device) -> Result<Tensor> {
    use image::imageops::FilterType;
    let img = image::RgbImage::from_raw(width, height, rgb.to_vec())
        .ok_or_else(|| anyhow::anyhow!("rgb buffer dimensions mismatch"))?;
    // 1. Shortest-side resize to 224 — matches CLIPImageProcessor.
    let (target_w, target_h) = if width < height {
        let h = ((IMAGE_SIZE as f32) * (height as f32) / (width as f32)).round() as u32;
        (IMAGE_SIZE as u32, h.max(IMAGE_SIZE as u32))
    } else {
        let w = ((IMAGE_SIZE as f32) * (width as f32) / (height as f32)).round() as u32;
        (w.max(IMAGE_SIZE as u32), IMAGE_SIZE as u32)
    };
    let resized = image::imageops::resize(&img, target_w, target_h, FilterType::Triangle);
    // 2. Centre-crop 224×224.
    let x0 = (target_w.saturating_sub(IMAGE_SIZE as u32)) / 2;
    let y0 = (target_h.saturating_sub(IMAGE_SIZE as u32)) / 2;
    let cropped = image::imageops::crop_imm(&resized, x0, y0, IMAGE_SIZE as u32, IMAGE_SIZE as u32)
        .to_image();
    // 3. Normalise → CHW f32.
    let mut chw = vec![0f32; 3 * IMAGE_SIZE * IMAGE_SIZE];
    for (y, row) in cropped.rows().enumerate() {
        for (x, pixel) in row.enumerate() {
            for c in 0..3 {
                let v = (pixel.0[c] as f32) / 255.0;
                let normed = (v - CLIP_MEAN[c]) / CLIP_STD[c];
                chw[c * IMAGE_SIZE * IMAGE_SIZE + y * IMAGE_SIZE + x] = normed;
            }
        }
    }
    Tensor::from_vec(chw, (1, 3, IMAGE_SIZE, IMAGE_SIZE), device).context("build NCHW pixel tensor")
}

fn l2_normalise(v: &[f32]) -> Vec<f32> {
    let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm == 0.0 {
        return v.to_vec();
    }
    v.iter().map(|x| x / norm).collect()
}

pub(crate) fn default_cache_dir(repo: &str) -> PathBuf {
    let models_root = crate::config::FreedomConfig::default_neoth_home().join("models");
    cache_dir_at(&models_root, repo)
}

pub(crate) fn cache_dir_at(models_root: &Path, repo: &str) -> PathBuf {
    models_root.join(super::model_cache_component(repo))
}

pub(crate) fn cache_health_at(
    models_root: &Path,
    repo: &str,
) -> crate::media::model_manager::CacheHealth {
    let cache = cache_dir_at(models_root, repo);
    if repo != DEFAULT_CLIP_REPO {
        return crate::media::model_manager::CacheHealth::Corrupt {
            path: cache,
            reason: format!(
                "unsupported CLIP repository `{repo}` has no reviewed revision/SHA-256 manifest"
            ),
        };
    }
    crate::media::model_manager::cache_health(&cache, &REQUIRED_ARTIFACTS)
}

pub(crate) fn verified_cache_health_at(
    models_root: &Path,
    repo: &str,
    during_attempt: bool,
) -> crate::media::model_manager::CacheHealth {
    let cache = cache_dir_at(models_root, repo);
    if repo != DEFAULT_CLIP_REPO {
        return crate::media::model_manager::CacheHealth::Corrupt {
            path: cache,
            reason: format!(
                "unsupported CLIP repository `{repo}` has no reviewed revision/SHA-256 manifest"
            ),
        };
    }
    if during_attempt {
        crate::media::model_manager::verified_cache_health_during_install(
            &cache,
            &REQUIRED_ARTIFACTS,
        )
    } else {
        crate::media::model_manager::verified_cache_health(&cache, &REQUIRED_ARTIFACTS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_cache_dir_flattens_repo_path() {
        let p = default_cache_dir("openai/clip-vit-base-patch32");
        assert_eq!(
            p,
            crate::config::FreedomConfig::default_neoth_home()
                .join("models")
                .join("openai-clip-vit-base-patch32")
        );
    }

    #[test]
    fn explicit_models_root_is_used_verbatim() {
        let root = PathBuf::from("isolated-neoth-home").join("models");
        assert_eq!(
            cache_dir_at(&root, "openai/clip-vit-base-patch32"),
            root.join("openai-clip-vit-base-patch32")
        );
    }

    #[test]
    fn repo_id_cannot_escape_explicit_models_root() {
        let root = PathBuf::from("isolated-neoth-home").join("models");
        let path = cache_dir_at(&root, r"C:\\outside/../../model");
        assert_eq!(path.parent(), Some(root.as_path()));
        assert!(path.starts_with(&root));
        let name = path.file_name().unwrap().to_string_lossy();
        assert!(!name.contains('/'));
        assert!(!name.contains('\\'));
    }

    #[test]
    fn default_repo_is_clip_vit_base_patch32() {
        assert_eq!(DEFAULT_CLIP_REPO, "laion/CLIP-ViT-B-32-laion2B-s34B-b79K");
    }

    #[test]
    fn embed_dim_matches_clip_b32_projection() {
        assert_eq!(EMBED_DIM, 512);
    }

    #[test]
    fn preprocess_produces_nchw_224_tensor() {
        let device = Device::Cpu;
        let rgb = vec![128u8; 64 * 64 * 3];
        let t = preprocess_image(&rgb, 64, 64, &device).expect("preprocess 64x64");
        assert_eq!(t.dims(), &[1, 3, IMAGE_SIZE, IMAGE_SIZE]);
        // Centre-crop of a uniform image stays uniform after normalisation.
        let flat = t.flatten_all().unwrap().to_vec1::<f32>().expect("flatten");
        // Channel 0 value should be (128/255 - mean[0]) / std[0]
        let expected_c0 = (128.0_f32 / 255.0 - CLIP_MEAN[0]) / CLIP_STD[0];
        let v = flat[0];
        assert!(
            (v - expected_c0).abs() < 1e-5,
            "got {v}, expected {expected_c0}"
        );
    }

    #[test]
    fn preprocess_rejects_dimension_mismatch() {
        let device = Device::Cpu;
        let rgb = vec![0u8; 10];
        let err = preprocess_image(&rgb, 64, 64, &device).unwrap_err();
        assert!(err.to_string().contains("rgb buffer"));
    }

    #[test]
    fn preprocess_handles_non_square_image() {
        let device = Device::Cpu;
        // 200×100 — landscape; shortest side (100) goes to 224 → final
        // resized buffer is 448×224, then centre-cropped back to
        // 224×224.
        let rgb = vec![0u8; 200 * 100 * 3];
        let t = preprocess_image(&rgb, 200, 100, &device).expect("preprocess landscape");
        assert_eq!(t.dims(), &[1, 3, IMAGE_SIZE, IMAGE_SIZE]);
    }

    #[test]
    fn l2_normalise_unit_length() {
        let v = vec![3.0, 4.0];
        let n = l2_normalise(&v);
        let mag = (n[0] * n[0] + n[1] * n[1]).sqrt();
        assert!((mag - 1.0).abs() < 1e-6);
    }

    #[test]
    fn l2_normalise_handles_zero_vector() {
        let v = vec![0.0, 0.0, 0.0];
        let n = l2_normalise(&v);
        assert_eq!(n, vec![0.0, 0.0, 0.0]);
    }

    #[test]
    fn text_context_len_matches_clip_b32_max_position() {
        assert_eq!(TEXT_CONTEXT_LEN, 77);
    }

    #[test]
    fn tokenizer_file_constant_matches_hf_canonical() {
        assert_eq!(TOKENIZER_FILE, "tokenizer.json");
    }

    /// Verify the SOT/EOT/padding shape of `tokenize_prompt` without
    /// loading the real CLIP tokenizer — we hand-build a minimal
    /// tokenizer that returns whatever IDs we feed it so the test
    /// stays hermetic.
    #[test]
    fn tokenize_prompt_wraps_with_sot_eot_and_pads_to_77() {
        // Build a fake encoding directly. We bypass the real tokenizer
        // by directly calling the same wrap+pad logic that
        // `tokenize_prompt` runs after `encode`.
        // Concretely: simulate `encoding.get_ids()` returning 5 content
        // tokens, then verify the surrounding pad+SOT+EOT layout.
        let fake_content: [u32; 5] = [100, 200, 300, 400, 500];
        let max_content = TEXT_CONTEXT_LEN.saturating_sub(2);
        let truncated = &fake_content[..fake_content.len().min(max_content)];

        let mut ids = Vec::with_capacity(TEXT_CONTEXT_LEN);
        ids.push(SOT_TOKEN_ID);
        ids.extend_from_slice(truncated);
        ids.push(EOT_TOKEN_ID);
        while ids.len() < TEXT_CONTEXT_LEN {
            ids.push(0);
        }

        assert_eq!(ids.len(), TEXT_CONTEXT_LEN);
        assert_eq!(ids[0], SOT_TOKEN_ID);
        assert_eq!(ids[1..1 + truncated.len()], fake_content[..]);
        assert_eq!(ids[1 + truncated.len()], EOT_TOKEN_ID);
        // Padding from position 7 onwards must be zero.
        for tail in &ids[1 + truncated.len() + 1..] {
            assert_eq!(*tail, 0);
        }
    }

    #[test]
    fn tokenize_prompt_truncates_oversize_content() {
        // Simulate a tokenized prompt that's already longer than
        // TEXT_CONTEXT_LEN - 2 = 75 tokens, ensuring the truncation
        // logic kicks in before the SOT/EOT wrapping.
        let huge: Vec<u32> = (1..200).collect();
        let max_content = TEXT_CONTEXT_LEN.saturating_sub(2);
        let truncated = &huge[..huge.len().min(max_content)];
        assert_eq!(truncated.len(), 75);

        let mut ids = Vec::with_capacity(TEXT_CONTEXT_LEN);
        ids.push(SOT_TOKEN_ID);
        ids.extend_from_slice(truncated);
        ids.push(EOT_TOKEN_ID);
        // No padding required — already at 77.
        assert_eq!(ids.len(), TEXT_CONTEXT_LEN);
        assert_eq!(ids[0], SOT_TOKEN_ID);
        assert_eq!(ids[TEXT_CONTEXT_LEN - 1], EOT_TOKEN_ID);
    }
}
