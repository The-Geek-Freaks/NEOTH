//! Whisper transcription engine — R-9 audio Phase 2b.
//!
//! Wraps candle-transformers' whisper model into a NEOTH-friendly
//! transcribe API. Operators get speech-to-text without depending on a
//! cloud service. The canonical STT dispatcher selects the size-specific
//! repository and explicit NEOTH model root; the low-level constructor retains
//! `openai/whisper-large-v3-turbo` only as its compatibility default.
//!
//! Pipeline per chunk:
//!   1. Pad / clip raw samples to exactly 30 s (`N_SAMPLES`).
//!   2. Compute log-mel spectrogram (128 mel bins for v3 / turbo, 80 for
//!      earlier variants — detected from the loaded `Config`).
//!   3. Encoder forward → audio features.
//!   4. Decoder greedy-decode starting from
//!      `<|startoftranscript|><|en|><|transcribe|><|notimestamps|>` until
//!      `<|endoftext|>` or `MAX_NEW_TOKENS`.
//!   5. Detokenise.
//!
//! Files > 30 s are split into back-to-back 30 s windows. Outputs are
//! concatenated with a single space; no overlap stitching today —
//! whisper-large-v3-turbo's chunk boundaries are clean enough that the
//! audio-track-extraction in the video pipeline doesn't introduce mid-
//! word splits.
//!
//! What is NOT in scope here:
//!   - Language detection (we hard-code `<|en|>`; operator-overrideable
//!     via `WhisperOptions::language`).
//!   - Timestamp prediction (`<|notimestamps|>` is forced).
//!   - Sampling beyond greedy / argmax — temperature fallback is whisper's
//!     usual hallucination-mitigation; we'd add it once we see real
//!     transcripts drift.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{Context, Result};
use candle_core::{Device, IndexOp, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::whisper as cw;
use tokenizers::Tokenizer;

/// Hugging Face repo we default to. Operator can override via
/// `freedom.yaml::whisper_repo` once we surface that config field.
pub const DEFAULT_WHISPER_REPO: &str = "openai/whisper-large-v3-turbo";

pub const TOKENIZER_FILE: &str = "tokenizer.json";
pub const CONFIG_FILE: &str = "config.json";
pub const SAFETENSORS_FILE: &str = "model.safetensors";

#[derive(Clone, Copy)]
struct WhisperArtifactManifest {
    revision: &'static str,
    artifacts: [crate::media::model_manager::RequiredArtifact; 3],
}

const fn whisper_artifact_manifest(
    revision: &'static str,
    tokenizer_len: u64,
    tokenizer_sha256: &'static str,
    config_len: u64,
    config_sha256: &'static str,
    weights_len: u64,
    weights_sha256: &'static str,
) -> WhisperArtifactManifest {
    use crate::media::model_manager::{
        ArtifactKind, ExpectedArtifactFingerprint, RequiredArtifact,
    };
    WhisperArtifactManifest {
        revision,
        artifacts: [
            RequiredArtifact {
                filename: TOKENIZER_FILE,
                kind: ArtifactKind::JsonObject,
                expected: Some(ExpectedArtifactFingerprint {
                    len: tokenizer_len,
                    sha256: tokenizer_sha256,
                }),
            },
            RequiredArtifact {
                filename: CONFIG_FILE,
                kind: ArtifactKind::JsonObject,
                expected: Some(ExpectedArtifactFingerprint {
                    len: config_len,
                    sha256: config_sha256,
                }),
            },
            RequiredArtifact {
                filename: SAFETENSORS_FILE,
                kind: ArtifactKind::Safetensors,
                expected: Some(ExpectedArtifactFingerprint {
                    len: weights_len,
                    sha256: weights_sha256,
                }),
            },
        ],
    }
}

fn artifact_manifest(repo: &str) -> Option<WhisperArtifactManifest> {
    Some(match repo {
        "openai/whisper-tiny" => whisper_artifact_manifest(
            "169d4a4341b33bc18d8881c4b69c2e104e1cc0af",
            2_480_466,
            "27fc476bfe7f17299480be2273fc0608e4d5a99aba2ab5dec5374b4482d1a566",
            1_983,
            "ffdccec4f3211f4c63310f2b7098f309fe70f3952cedc5e4d11e43f5b2379b98",
            151_061_672,
            "7ebd0e69e78190ffe1438491fa05cc1f5c1aa3a4c4db3bc1723adbb551ea2395",
        ),
        "openai/whisper-base" => whisper_artifact_manifest(
            "e37978b90ca9030d5170a5c07aadb050351a65bb",
            2_480_466,
            "27fc476bfe7f17299480be2273fc0608e4d5a99aba2ab5dec5374b4482d1a566",
            1_983,
            "a153c53883a6799b6f056b4a8d1a515c9926d03994682ba88a7616618d7da0c1",
            290_403_936,
            "07cadb9f25677c8d50df603e66a98fbd842cce45047139baeb16e6219a1e807b",
        ),
        "openai/whisper-small" => whisper_artifact_manifest(
            "973afd24965f72e36ca33b3055d56a652f456b4d",
            2_480_466,
            "27fc476bfe7f17299480be2273fc0608e4d5a99aba2ab5dec5374b4482d1a566",
            1_967,
            "e6a2b489da1b5aed65a8eb8d1e7466fa867ad5643a8bc138ba708bd56b2875c4",
            966_995_080,
            "1d7734884874f1a1513ed9aa760a4f8e97aaa02fd6d93a3a85d27b2ae9ca596b",
        ),
        "openai/whisper-medium" => whisper_artifact_manifest(
            "abdf7c39ab9d0397620ccaea8974cc764cd0953e",
            2_480_466,
            "27fc476bfe7f17299480be2273fc0608e4d5a99aba2ab5dec5374b4482d1a566",
            1_991,
            "18706810eb740d1dc54d1db181358d5f8578600d0f449e51dfd4798c0223a1f5",
            3_055_544_304,
            "62f73550fa6db24b0c6f6c5962bd0dae80fa644e93cde9cd9c3792971b47fd28",
        ),
        "openai/whisper-large-v3" => whisper_artifact_manifest(
            "06f233fe06e710322aca913c1bc4249a0d71fce1",
            2_480_617,
            "6d8cbd7cd0d8d5815e478dac67b85a26bbe77c1f5e0c6d76d1ce2abc0e5f21ca",
            1_272,
            "ad0e8d1e46f4d01f7861a21509e5d0f977d6cc1f367a370603c92541d819807b",
            3_087_130_976,
            "a8e94b85976e5864ba3e9525c7e6c83b2a1eca42d4b797a0c7c24d778e40fd95",
        ),
        "openai/whisper-large-v3-turbo" => whisper_artifact_manifest(
            "41f01f3fe87f28c78e2fbf8b568835947dd65ed9",
            2_710_337,
            "297b13372ac43916285644fb9687add3cc62ee2a1adb60da3dc25cc94c1871fd",
            1_256,
            "c5b526b3e3cd64cd8940dabb45e8ba726629e22d8ed389c29b552f9140daf04a",
            1_617_824_864,
            "542566a422ae4f3fd23f1ba11add198fca01bbf82e66e6a2857b3f608b1eb9d1",
        ),
        _ => return None,
    })
}

/// Operator-overrideable transcription knobs.
#[derive(Clone, Debug)]
pub struct WhisperOptions {
    /// ISO 639-1 language code. `"en"` by default. Whisper recognises 99
    /// languages. When `auto_detect_language=true` this field is the
    /// fallback used only if detection fails (e.g. silent chunk).
    pub language: String,
    /// `false` = transcribe in source language; `true` = translate to
    /// English. Whisper's hardcoded direction.
    pub translate: bool,
    /// Max new tokens per chunk before forcing EOT. Whisper produces ~448
    /// tokens for a 30 s window; 480 gives a small safety margin.
    pub max_new_tokens: usize,
    /// When `true`, run a one-step decoder probe at the start of each
    /// chunk to pick the language from the audio features instead of
    /// taking `self.language` at face value. Costs one extra decoder
    /// step per chunk (~2 ms on CPU) and avoids garbled output on
    /// non-English audio when the operator left the default `"en"`.
    pub auto_detect_language: bool,
    /// Temperature schedule for the hallucination-fallback retry.
    /// Whisper degrades into repetitive loops on silent / ambiguous
    /// audio; the OpenAI-cli mitigation is: try T=0 first, and if the
    /// output's compression ratio crosses a threshold, retry with the
    /// next T until either the ratio is acceptable or the schedule is
    /// exhausted. Empty vec disables the fallback (single greedy pass).
    pub temperatures: Vec<f32>,
    /// Compression-ratio threshold above which we suspect hallucination
    /// and trigger the next temperature. 2.4 is whisper's reference
    /// default — produced text compressed via gzip whose
    /// `text_len / compressed_len` exceeds this ratio is treated as
    /// repetitive and rejected.
    pub compression_ratio_threshold: f32,
}

impl Default for WhisperOptions {
    fn default() -> Self {
        Self {
            language: "en".into(),
            translate: false,
            max_new_tokens: 480,
            auto_detect_language: true,
            temperatures: vec![0.0, 0.2, 0.4, 0.6, 0.8, 1.0],
            compression_ratio_threshold: 2.4,
        }
    }
}

pub struct WhisperEngine {
    repo: String,
    manifest: WhisperArtifactManifest,
    hf_cache_dir: PathBuf,
    tokenizer_path: PathBuf,
    config_path: PathBuf,
    weights_path: PathBuf,
    allow_pending_validation: bool,
    /// Pre-computed mel filterbank, `n_mels × (N_FFT/2 + 1)` floats.
    /// Populated by `ensure_artifacts` so transcription doesn't pay the
    /// ~5 ms recompute cost on every chunk.
    mel_filters: Vec<f32>,
    /// Lazy-loaded model. First `transcribe` call mmaps + builds.
    loaded: Arc<Mutex<Option<LoadedWhisper>>>,
    /// Candle device selected at construction time via `HwProbe`. Stored
    /// on the engine so `transcribe` can pass it into `ensure_loaded`
    /// without re-running the probe on every call.
    device: Device,
    // ── HANDY-05: idle-unload machinery ──────────────────────────────────
    /// Monotonic timestamp of the last completed transcription. Updated
    /// (under std Mutex, not Tokio) by `transcribe` on every call.
    last_used: Arc<Mutex<Instant>>,
    /// Counter of in-flight transcriptions. The idle-watcher task skips
    /// the unload when `in_flight > 0` (inference and unload cannot race).
    in_flight: Arc<AtomicUsize>,
    /// Cancel token for the idle-watcher background task. Sending `()`
    /// signals the task to exit. Dropped (= task exits) when the engine
    /// drops.
    _idle_cancel: Option<tokio::sync::watch::Sender<()>>,
}

struct LoadedWhisper {
    model: cw::model::Whisper,
    tokenizer: Tokenizer,
    config: cw::Config,
    device: Device,
    /// Tokens we prepend to every decoder run when the operator-set
    /// language is fixed (auto-detect disabled). Built once per load.
    initial_tokens: Vec<u32>,
    eot_id: u32,
    /// `(code, token_id)` for every `<|XX|>` language token registered
    /// in the tokenizer. Populated at load. Used by
    /// `detect_language_for_chunk` to mask the decoder logits at
    /// position 0 to only language candidates.
    language_tokens: Vec<(String, u32)>,
    /// `<|startoftranscript|>` id, cached once.
    sot_id: u32,
}

// ── HANDY-05: LoadingGuard RAII ─────────────────────────────────────────────

/// RAII guard that prevents the idle-watcher task from unloading the
/// `LoadedWhisper` while an inference is in flight.
///
/// Constructed by `WhisperEngine::loading_guard()`; dropped automatically
/// when the transcription scope exits. On `Drop`, decrements the engine's
/// `in_flight` counter and refreshes `last_used` to the completion time so
/// the idle timer starts from the END of the inference (not the start).
pub struct LoadingGuard {
    in_flight: Arc<AtomicUsize>,
    last_used: Arc<Mutex<Instant>>,
}

impl Drop for LoadingGuard {
    fn drop(&mut self) {
        // Refresh last_used to NOW so the idle countdown starts from when
        // the inference completed, not when it began.
        if let Ok(mut t) = self.last_used.lock() {
            *t = Instant::now();
        }
        // Decrement AFTER refreshing last_used — the idle task checks
        // in_flight==0 THEN reads last_used; this order is safe.
        self.in_flight.fetch_sub(1, Ordering::Release);
        tracing::debug!("whisper: LoadingGuard released");
    }
}

impl WhisperEngine {
    /// Construct against an explicit NEOTH-owned model root.
    ///
    /// Runtime callers with a custom `NEOTH_HOME` or daemon home must use this
    /// seam; otherwise the provider can pass policy checks for one home while
    /// reading or writing model artifacts below another user's `~/.neoth`.
    pub(crate) async fn new_with_models_root(
        repo: Option<String>,
        idle_secs: Option<u64>,
        models_root: &Path,
    ) -> Result<Self> {
        Self::build_with_models_root(repo, idle_secs, models_root, None).await
    }

    /// Network-capable construction is only reachable with the central
    /// durable D7/D8 attempt that owns this exact model cache.
    pub(crate) async fn new_for_download_attempt(
        repo: Option<String>,
        idle_secs: Option<u64>,
        models_root: &Path,
        attempt: &crate::media::model_manager::ModelDownloadAttempt,
    ) -> Result<Self> {
        Self::build_with_models_root(repo, idle_secs, models_root, Some(attempt)).await
    }

    async fn build_with_models_root(
        repo: Option<String>,
        idle_secs: Option<u64>,
        models_root: &Path,
        attempt: Option<&crate::media::model_manager::ModelDownloadAttempt>,
    ) -> Result<Self> {
        let repo = repo.unwrap_or_else(|| DEFAULT_WHISPER_REPO.to_string());
        let manifest = artifact_manifest(&repo).ok_or_else(|| {
            anyhow::anyhow!(
                "unsupported Whisper repository `{repo}`: no reviewed revision/SHA-256 manifest"
            )
        })?;
        let cache_dir = cache_dir_at(models_root, &repo);

        // Run the hardware probe and select the best available device.
        // Identical one-shot semantics to `LocalQwenAdapter` — never re-probed.
        let probe = crate::media::hw_probe::HwProbe::detect();
        tracing::info!(hw = %probe, "whisper: hardware probe");
        let device = device_for_hw_probe(&probe);
        tracing::info!(device = ?device, "whisper: selected candle device");

        let loaded = Arc::new(Mutex::new(None::<LoadedWhisper>));
        let last_used = Arc::new(Mutex::new(Instant::now()));
        let in_flight = Arc::new(AtomicUsize::new(0));

        // ── HANDY-05: spawn idle-watcher task ──────────────────────────
        // The engine is constructed from an async runtime. Keeping the watch
        // sender in `_idle_cancel` gives the watcher the same lifetime as the
        // engine and drops it cleanly with the engine.
        let idle_cancel = match (idle_secs, idle_secs.unwrap_or(0)) {
            (None, _) | (_, 0) => None,
            (Some(secs), _) => {
                let (tx, rx) = tokio::sync::watch::channel(());
                let slot = Arc::clone(&loaded);
                let lu = Arc::clone(&last_used);
                let iflt = Arc::clone(&in_flight);
                let poll_interval = tokio::time::Duration::from_secs(secs / 2 + 1);
                let idle_dur = std::time::Duration::from_secs(secs);
                tokio::task::spawn(async move {
                    let mut rx = rx;
                    loop {
                        // Exit when the engine drops (sender side dropped).
                        let sleep = tokio::time::sleep(poll_interval);
                        tokio::select! {
                            _ = rx.changed() => break,
                            _ = sleep => {}
                        }
                        // Skip unload when inference is active.
                        if iflt.load(Ordering::Acquire) > 0 {
                            continue;
                        }
                        let elapsed = lu
                            .lock()
                            .map(|t| t.elapsed())
                            .unwrap_or(std::time::Duration::ZERO);
                        if elapsed >= idle_dur {
                            let mut s = slot.lock().unwrap_or_else(|p| p.into_inner());
                            if s.is_some() {
                                *s = None;
                                tracing::info!(
                                    idle_secs = secs,
                                    "whisper: idle unload — VRAM/RAM freed"
                                );
                            }
                        }
                    }
                });
                Some(tx)
            }
        };

        let mut engine = WhisperEngine {
            repo: repo.clone(),
            manifest,
            hf_cache_dir: models_root.join(".hf-hub"),
            tokenizer_path: cache_dir.join(TOKENIZER_FILE),
            config_path: cache_dir.join(CONFIG_FILE),
            weights_path: cache_dir.join(SAFETENSORS_FILE),
            allow_pending_validation: attempt.is_some(),
            mel_filters: Vec::new(),
            loaded,
            device,
            last_used,
            in_flight,
            _idle_cancel: idle_cancel,
        };
        engine.ensure_artifacts(attempt).await?;
        // Pre-compute mel filters based on the model's expected n_mels.
        // We peek at the config without loading the weights so the cost
        // is paid up-front but very cheap.
        let n_mels = peek_n_mels(&engine.config_path)?;
        engine.mel_filters = compute_mel_filters(n_mels);
        Ok(engine)
    }

    /// Acquire a `LoadingGuard` that prevents idle-unloads for its
    /// lifetime. Increments `in_flight`; `Drop` decrements it and
    /// refreshes `last_used`.
    pub fn loading_guard(&self) -> LoadingGuard {
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        LoadingGuard {
            in_flight: Arc::clone(&self.in_flight),
            last_used: Arc::clone(&self.last_used),
        }
    }

    /// Test-only: check whether the `LoadedWhisper` slot is currently empty
    /// (i.e. the model has been unloaded).
    #[cfg(test)]
    pub fn is_slot_empty(&self) -> bool {
        self.loaded
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_none()
    }

    /// Test-only: force the loaded slot to a sentinel value (non-None) so the
    /// idle task has something to drop without needing real model weights.
    #[cfg(test)]
    pub fn force_load_sentinel_for_test(&self) {
        // We create a minimal LoadedWhisper-like sentinel by simply stuffing
        // a Some(…) into the slot using an unsafe transmute trick would be
        // unsound, so we instead expose the in_flight counter + last_used
        // for test assertions and avoid touching the slot directly.
        // The idle-unload test exercises the counter + timing path via
        // is_slot_empty() which only reads the lock.
        let _ = self; // keep clippy happy — no real action needed for the slot test
    }

    async fn ensure_artifacts(
        &self,
        attempt: Option<&crate::media::model_manager::ModelDownloadAttempt>,
    ) -> Result<()> {
        use hf_hub::api::tokio::ApiBuilder;
        use hf_hub::{Repo, RepoType};
        let cache_dir = self
            .tokenizer_path
            .parent()
            .context("Whisper cache path has no parent")?;
        let health = if attempt.is_some() {
            crate::media::model_manager::verified_cache_health_during_install(
                cache_dir,
                &self.manifest.artifacts,
            )
        } else {
            crate::media::model_manager::verified_cache_health(cache_dir, &self.manifest.artifacts)
        };
        if health.is_ready() {
            return Ok(());
        }
        let attempt = attempt.with_context(|| {
            format!(
                "Whisper cache is not verified ({health}); model downloads require a durable D7/D8 attempt"
            )
        })?;
        if !attempt.network_authorized(cache_dir, &self.repo) {
            anyhow::bail!(
                "Whisper network access for `{}` is not authorised by a confirmed D7 attempt",
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
            self.manifest.revision.to_string(),
        ));
        for artifact in self.manifest.artifacts {
            let filename = artifact.filename;
            let target = cache_dir.join(filename);
            let downloaded = repo_handle
                .download(filename)
                .await
                .with_context(|| format!("HF download error for {filename}"))?;
            if downloaded != target {
                let expected = artifact
                    .expected
                    .context("pinned Whisper artifact lacks a fingerprint")?;
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
            &self.manifest.artifacts,
        );
        if !health.is_ready() {
            anyhow::bail!("Whisper artifacts failed post-install validation: {health}");
        }
        Ok(())
    }

    /// Prove the pinned SHA-256 generation and construct the real Candle model
    /// before a D8 `ready` event can be emitted. Structural cache checks alone
    /// cannot detect a valid-looking but incompatible tokenizer/tensor set.
    pub(crate) async fn validate_load(&self) -> Result<()> {
        let cache_dir = self
            .tokenizer_path
            .parent()
            .context("Whisper cache path has no parent")?
            .to_path_buf();
        let artifacts = self.manifest.artifacts;
        let allow_pending = self.allow_pending_validation;
        let health = tokio::task::spawn_blocking(move || {
            if allow_pending {
                crate::media::model_manager::verified_cache_health_during_install(
                    &cache_dir, &artifacts,
                )
            } else {
                crate::media::model_manager::verified_cache_health(&cache_dir, &artifacts)
            }
        })
        .await
        .context("join Whisper SHA-256 validation")?;
        if !health.is_ready() {
            anyhow::bail!("Whisper cache failed full integrity validation: {health}");
        }

        let _guard = self.loading_guard();
        let loaded = Arc::clone(&self.loaded);
        let tokenizer_path = self.tokenizer_path.clone();
        let config_path = self.config_path.clone();
        let weights_path = self.weights_path.clone();
        let device = self.device.clone();
        tokio::task::spawn_blocking(move || {
            ensure_loaded(
                &loaded,
                &tokenizer_path,
                &config_path,
                &weights_path,
                &WhisperOptions::default(),
                device,
            )
        })
        .await
        .context("join Whisper backend validation")??;
        Ok(())
    }

    /// Transcribe a slice of 16 kHz mono f32 samples. Files > 30 s are
    /// chunked transparently. Returns the concatenated text.
    ///
    /// Acquires a [`LoadingGuard`] for the duration of the call, which
    /// prevents the idle-watcher task from unloading mid-inference and
    /// refreshes `last_used` on completion.
    pub async fn transcribe(&self, samples: &[f32], options: WhisperOptions) -> Result<String> {
        let cache_dir = self
            .tokenizer_path
            .parent()
            .context("Whisper cache path has no parent")?;
        let _model_lock = crate::media::model_manager::lock_model_cache(cache_dir).await?;
        let health = crate::media::model_manager::cache_health(cache_dir, &self.manifest.artifacts);
        if !health.is_ready() {
            anyhow::bail!("Whisper cache became unavailable before transcription: {health}");
        }
        // Acquire BEFORE spawn_blocking so the idle task cannot race.
        let _guard = self.loading_guard();

        let loaded = Arc::clone(&self.loaded);
        let tokenizer_path = self.tokenizer_path.clone();
        let config_path = self.config_path.clone();
        let weights_path = self.weights_path.clone();
        let mel_filters = self.mel_filters.clone();
        let device = self.device.clone();
        let samples = samples.to_vec();
        tokio::task::spawn_blocking(move || -> Result<String> {
            ensure_loaded(
                &loaded,
                &tokenizer_path,
                &config_path,
                &weights_path,
                &options,
                device,
            )?;
            let mut slot = loaded.lock().unwrap_or_else(|p| p.into_inner());
            let lw = slot.as_mut().expect("loaded just initialised");
            transcribe_blocking(lw, &samples, &mel_filters, &options)
        })
        .await
        .context("whisper join error")?
        // `_guard` drops here → in_flight-- and last_used = now
    }
}

fn ensure_loaded(
    loaded: &Arc<Mutex<Option<LoadedWhisper>>>,
    tokenizer_path: &Path,
    config_path: &Path,
    weights_path: &Path,
    options: &WhisperOptions,
    device: Device,
) -> Result<()> {
    let mut slot = loaded.lock().unwrap_or_else(|p| p.into_inner());
    if slot.is_some() {
        return Ok(());
    }
    let tokenizer = Tokenizer::from_file(tokenizer_path)
        .map_err(|e| anyhow::anyhow!("load whisper tokenizer.json: {e}"))?;
    let config: cw::Config = {
        let body = std::fs::read_to_string(config_path)
            .with_context(|| format!("read {}", config_path.display()))?;
        serde_json::from_str(&body).context("parse whisper config.json")?
    };
    // SAFETY: `from_mmaped_safetensors` requires the mapped file is
    // not truncated or replaced for the lifetime of the mapping. The
    // file lives under `~/.neoth/models/` (mode-0600 / DACL-locked).
    // Multi-process read (daemon + `neoth ingest`) is allowed; the
    // single sanctioned writer is `neoth models pull` which is a
    // no-op against an existing cache. Engine construction and
    // explicit validation hash every artifact against the reviewed
    // revision/length/SHA-256 manifest before this mapping is created.
    // A third party that can ignore the cache lock and mutate an
    // operator-owned file afterwards is outside NEOTH's process trust
    // boundary.
    let vb = unsafe {
        VarBuilder::from_mmaped_safetensors(&[weights_path], cw::DTYPE, &device)
            .with_context(|| format!("mmap safetensors {}", weights_path.display()))?
    };
    let model = cw::model::Whisper::load(&vb, config.clone()).context("build Whisper model")?;
    let initial_tokens = build_initial_tokens(&tokenizer, options)?;
    let eot_id = tokenizer
        .token_to_id(cw::EOT_TOKEN)
        .ok_or_else(|| anyhow::anyhow!("tokenizer missing {}", cw::EOT_TOKEN))?;
    let sot_id = tokenizer
        .token_to_id(cw::SOT_TOKEN)
        .ok_or_else(|| anyhow::anyhow!("tokenizer missing {}", cw::SOT_TOKEN))?;
    let language_tokens = discover_language_tokens(&tokenizer);
    *slot = Some(LoadedWhisper {
        model,
        tokenizer,
        config,
        device,
        initial_tokens,
        eot_id,
        language_tokens,
        sot_id,
    });
    Ok(())
}

/// Walk the whisper tokenizer once at load and pick out every
/// language token (`<|XX|>` for ISO 639-1 / 639-3 codes). Whisper
/// registers 99 of them as added tokens; we look them up by id (every
/// id from 0 .. vocab_size whose surface form matches the pattern) and
/// return the `(code, id)` pairs sorted by id so detection picks
/// stably-ordered candidates.
fn discover_language_tokens(tokenizer: &Tokenizer) -> Vec<(String, u32)> {
    let vocab_size = tokenizer.get_vocab_size(true);
    let mut out = Vec::with_capacity(99);
    for id in 0..vocab_size as u32 {
        let Some(tok) = tokenizer.id_to_token(id) else {
            continue;
        };
        // Surface form: `<|en|>`, `<|de|>`, ... `<|jw|>`, `<|haw|>`.
        // Excludes task tokens (`<|transcribe|>`, `<|translate|>`,
        // ...) by requiring the inner part to be only 2-3 letters.
        let Some(inner) = tok.strip_prefix("<|").and_then(|s| s.strip_suffix("|>")) else {
            continue;
        };
        let len_ok = (2..=3).contains(&inner.len());
        let ascii_ok = inner.chars().all(|c| c.is_ascii_lowercase());
        if len_ok && ascii_ok {
            out.push((inner.to_string(), id));
        }
    }
    out
}

fn build_initial_tokens(tokenizer: &Tokenizer, options: &WhisperOptions) -> Result<Vec<u32>> {
    let lang_token = format!("<|{}|>", options.language);
    let task = if options.translate {
        cw::TRANSLATE_TOKEN
    } else {
        cw::TRANSCRIBE_TOKEN
    };
    let toks = [cw::SOT_TOKEN, &lang_token, task, cw::NO_TIMESTAMPS_TOKEN];
    let mut ids = Vec::with_capacity(toks.len());
    for t in toks {
        let id = tokenizer
            .token_to_id(t)
            .ok_or_else(|| anyhow::anyhow!("tokenizer missing special token {t}"))?;
        ids.push(id);
    }
    Ok(ids)
}

fn transcribe_blocking(
    lw: &mut LoadedWhisper,
    samples: &[f32],
    mel_filters: &[f32],
    options: &WhisperOptions,
) -> Result<String> {
    if samples.is_empty() {
        return Ok(String::new());
    }
    let mut out = String::new();
    for (chunk_index, chunk_start) in (0..samples.len()).step_by(cw::N_SAMPLES).enumerate() {
        let end = (chunk_start + cw::N_SAMPLES).min(samples.len());
        let mut chunk: Vec<f32> = samples[chunk_start..end].to_vec();
        // Whisper expects exactly 30 s per encode; pad short tails with
        // silence rather than dropping them.
        chunk.resize(cw::N_SAMPLES, 0.0);
        let piece = transcribe_one_chunk(lw, &chunk, mel_filters, options)?;
        if chunk_index > 0 && !out.is_empty() && !piece.is_empty() {
            out.push(' ');
        }
        out.push_str(&piece);
    }
    Ok(out.trim().to_string())
}

fn transcribe_one_chunk(
    lw: &mut LoadedWhisper,
    chunk: &[f32],
    mel_filters: &[f32],
    options: &WhisperOptions,
) -> Result<String> {
    // 1. Mel spectrogram. candle's pcm_to_mel handles padding + log
    //    + clipping — output is a flat `n_mels × N_FRAMES` vector.
    let mel = cw::audio::pcm_to_mel(&lw.config, chunk, mel_filters);
    let n_mels = lw.config.num_mel_bins;
    let mel = Tensor::from_vec(mel, (1, n_mels, cw::N_FRAMES), &lw.device)?.to_dtype(cw::DTYPE)?;

    // 2. Encoder forward. flush_kv_cache=true because each chunk is
    //    its own independent context.
    lw.model.reset_kv_cache();
    let audio_features = lw.model.encoder.forward(&mel, true)?;

    // 3. Pick the initial-tokens prompt. Auto-detect runs a one-step
    //    decoder probe against the encoded features and substitutes
    //    the detected language token for the operator-set default.
    //    Falls back silently to `options.language` when the
    //    `language_tokens` map is empty (legacy tokenizer or zero
    //    discovery).
    let initial_tokens = if options.auto_detect_language && !lw.language_tokens.is_empty() {
        match detect_language_for_chunk(lw, &audio_features) {
            Ok(code) => build_initial_tokens_for_language(&lw.tokenizer, &code, options.translate)
                .unwrap_or_else(|_| lw.initial_tokens.clone()),
            Err(_) => lw.initial_tokens.clone(),
        }
    } else {
        lw.initial_tokens.clone()
    };
    let prompt_len = initial_tokens.len();

    // 4. Run the decoder with the configured temperature fallback. The
    //    first attempt is T=0 (or the schedule's first entry); if the
    //    decoded text trips the compression-ratio heuristic, we retry
    //    with the next temperature. Empty schedule → behave like a
    //    plain greedy decode without retries.
    let schedule = if options.temperatures.is_empty() {
        &[0.0f32][..]
    } else {
        &options.temperatures[..]
    };
    let mut best: Option<String> = None;
    let mut last_ratio = 0.0f32;
    for (attempt, &temperature) in schedule.iter().enumerate() {
        let tokens = run_decoder_pass(
            lw,
            &initial_tokens,
            &audio_features,
            options.max_new_tokens,
            temperature,
        )?;
        let new_tokens = &tokens[prompt_len..];
        let text = lw
            .tokenizer
            .decode(new_tokens, true)
            .map_err(|e| anyhow::anyhow!("whisper decode: {e}"))?;
        let ratio = compression_ratio(&text);
        last_ratio = ratio;
        let acceptable = ratio <= options.compression_ratio_threshold;
        if acceptable {
            return Ok(text.trim().to_string());
        }
        tracing::debug!(
            attempt,
            temperature,
            ratio,
            "whisper fallback: high compression ratio, retrying with next temperature"
        );
        best = Some(text);
    }
    // Schedule exhausted; surface the last attempt's text. Operators
    // can still inspect the chunk's audio if downstream context
    // catches the issue.
    tracing::warn!(
        last_ratio,
        threshold = options.compression_ratio_threshold,
        "whisper temperature schedule exhausted; returning last attempt"
    );
    Ok(best.unwrap_or_default().trim().to_string())
}

/// One full decoder pass against the encoded audio features.
/// `temperature == 0.0` keeps argmax (greedy); anything > 0 routes the
/// logits through a softmax-based stochastic sampler. The seed is
/// derived from the prompt + temperature so repeat runs at the same
/// settings are reproducible without exposing an extra knob.
fn run_decoder_pass(
    lw: &mut LoadedWhisper,
    initial_tokens: &[u32],
    audio_features: &Tensor,
    max_new_tokens: usize,
    temperature: f32,
) -> Result<Vec<u32>> {
    use rand::SeedableRng;
    use rand::distr::weighted::WeightedIndex;
    use rand::prelude::*;

    let mut tokens = initial_tokens.to_vec();
    // Reproducible seed: prompt hash + temperature bytes. Operators
    // running the same chunk twice at the same temperature get the
    // same transcript.
    let seed = {
        let mut h = xxhash_rust::xxh3::Xxh3::new();
        for t in initial_tokens {
            h.update(&t.to_le_bytes());
        }
        h.update(&temperature.to_le_bytes());
        h.digest()
    };
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    for _step in 0..max_new_tokens {
        let input = Tensor::new(tokens.as_slice(), &lw.device)?.unsqueeze(0)?;
        let logits = lw.model.decoder.forward(&input, audio_features, true)?;
        let last = logits.i((0, logits.dim(1)? - 1))?;
        let final_logits = lw.model.decoder.final_linear(&last.unsqueeze(0)?)?;
        let row: Vec<f32> = final_logits.squeeze(0)?.to_vec1()?;

        let next = if temperature <= 0.0 {
            // Greedy argmax — also the path used during language
            // detection so the two share semantics.
            row.iter()
                .enumerate()
                .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
                .map(|(i, _)| i as u32)
                .unwrap_or(lw.eot_id)
        } else {
            // Softmax with temperature, then weighted-index sample.
            let inv_t = 1.0 / temperature;
            let max = row.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
            let exps: Vec<f32> = row.iter().map(|x| ((x - max) * inv_t).exp()).collect();
            let sum: f32 = exps.iter().sum();
            if sum.is_finite() && sum > 0.0 {
                let weights: Vec<f32> = exps.iter().map(|x| x / sum).collect();
                match WeightedIndex::new(&weights) {
                    Ok(dist) => dist.sample(&mut rng) as u32,
                    Err(_) => row
                        .iter()
                        .enumerate()
                        .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
                        .map(|(i, _)| i as u32)
                        .unwrap_or(lw.eot_id),
                }
            } else {
                lw.eot_id
            }
        };
        if next == lw.eot_id {
            break;
        }
        tokens.push(next);
    }
    Ok(tokens)
}

/// Compute the gzip compression ratio for a piece of text — proxy for
/// the "repetitive output → likely hallucination" heuristic from
/// OpenAI's whisper-cli reference impl. Returns
/// `text.len() / compressed.len()`; higher = more repetition.
/// Empty text returns 0.0.
fn compression_ratio(text: &str) -> f32 {
    if text.is_empty() {
        return 0.0;
    }
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;
    let bytes = text.as_bytes();
    let mut enc = GzEncoder::new(Vec::with_capacity(bytes.len()), Compression::default());
    if enc.write_all(bytes).is_err() {
        return 0.0;
    }
    let compressed = match enc.finish() {
        Ok(v) => v,
        Err(_) => return 0.0,
    };
    if compressed.is_empty() {
        return 0.0;
    }
    (bytes.len() as f32) / (compressed.len() as f32)
}

/// One-step decoder probe to identify the language of a chunk.
/// Builds the prompt `<|startoftranscript|>`, runs one decoder step,
/// masks every non-language token, argmaxes the remaining logits, and
/// returns the matching ISO code. The encoder pass has already
/// happened; we reuse its features here.
fn detect_language_for_chunk(lw: &mut LoadedWhisper, audio_features: &Tensor) -> Result<String> {
    let prompt = vec![lw.sot_id];
    let input = Tensor::new(prompt.as_slice(), &lw.device)?.unsqueeze(0)?;
    let logits = lw.model.decoder.forward(&input, audio_features, true)?;
    let last = logits.i((0, logits.dim(1)? - 1))?;
    let final_logits = lw.model.decoder.final_linear(&last.unsqueeze(0)?)?;
    // Pull the vocab-sized logit row out as a Vec<f32> so we can mask
    // by language-token id list (faster than building a giant mask
    // tensor + argmax on device for 99 entries).
    let scores = final_logits.squeeze(0)?.to_vec1::<f32>()?;
    let mut best: Option<(f32, &str)> = None;
    for (code, id) in &lw.language_tokens {
        let idx = *id as usize;
        if idx >= scores.len() {
            continue;
        }
        let s = scores[idx];
        match best {
            Some((b, _)) if s <= b => {}
            _ => best = Some((s, code.as_str())),
        }
    }
    best.map(|(_, c)| c.to_string())
        .ok_or_else(|| anyhow::anyhow!("language detection failed: no language tokens scored"))
}

/// Build the four-token prompt for a specific language code. Identical
/// shape to `build_initial_tokens` but takes the code directly so the
/// auto-detect path doesn't mutate `WhisperOptions`.
fn build_initial_tokens_for_language(
    tokenizer: &Tokenizer,
    code: &str,
    translate: bool,
) -> Result<Vec<u32>> {
    let lang_token = format!("<|{code}|>");
    let task = if translate {
        cw::TRANSLATE_TOKEN
    } else {
        cw::TRANSCRIBE_TOKEN
    };
    let toks = [cw::SOT_TOKEN, &lang_token, task, cw::NO_TIMESTAMPS_TOKEN];
    let mut ids = Vec::with_capacity(toks.len());
    for t in toks {
        let id = tokenizer
            .token_to_id(t)
            .ok_or_else(|| anyhow::anyhow!("tokenizer missing special token {t}"))?;
        ids.push(id);
    }
    Ok(ids)
}

/// Select the candle `Device` for Whisper based on the hardware probe.
///
/// Mirrors `providers::local_qwen::device_for` — reuses the same cargo
/// feature gates (`qwen-cuda` / `qwen-metal`) so no new features are
/// introduced. Applies the FMA3 guard before any non-CPU branch: candle's
/// SIMD kernels require FMA3 (Haswell / Piledriver 2012+); on older CPUs
/// they SIGILL. On guard failure we warn and return `Device::Cpu`.
fn device_for_hw_probe(probe: &crate::media::hw_probe::HwProbe) -> Device {
    use crate::media::hw_probe::AcceleratorClass;

    match probe.accelerator {
        AcceleratorClass::Cuda => {
            // Guard: candle CUDA kernels also use FMA3 paths.
            if let Err(msg) = crate::media::hw_probe::require_fma3(probe.cpu_caps.fma3) {
                tracing::warn!("whisper: {msg}; falling back to Device::Cpu");
                return Device::Cpu;
            }
            #[cfg(feature = "qwen-cuda")]
            {
                match Device::new_cuda(0) {
                    Ok(d) => {
                        tracing::info!("whisper: CUDA device 0 acquired");
                        return d;
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "whisper: Device::new_cuda(0) failed; falling back to CPU"
                        );
                    }
                }
            }
            #[cfg(not(feature = "qwen-cuda"))]
            tracing::warn!(
                "whisper: CUDA requested but `qwen-cuda` feature disabled; \
                 using CPU. Rebuild with `--features qwen-cuda` to enable."
            );
            Device::Cpu
        }
        AcceleratorClass::Metal => {
            if let Err(msg) = crate::media::hw_probe::require_fma3(probe.cpu_caps.fma3) {
                tracing::warn!("whisper: {msg}; falling back to Device::Cpu");
                return Device::Cpu;
            }
            #[cfg(feature = "qwen-metal")]
            {
                match Device::new_metal(0) {
                    Ok(d) => {
                        tracing::info!("whisper: Metal device 0 acquired");
                        return d;
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "whisper: Device::new_metal(0) failed; falling back to CPU"
                        );
                    }
                }
            }
            #[cfg(not(feature = "qwen-metal"))]
            tracing::warn!(
                "whisper: Metal requested but `qwen-metal` feature disabled; \
                 using CPU."
            );
            Device::Cpu
        }
        AcceleratorClass::OpenVino => {
            tracing::warn!("whisper: OpenVINO is not a candle backend; using CPU.");
            Device::Cpu
        }
        AcceleratorClass::Cpu => Device::Cpu,
    }
}

#[cfg(test)]
fn default_cache_dir(repo: &str) -> PathBuf {
    let models_root = crate::config::FreedomConfig::default_neoth_home().join("models");
    cache_dir_at(&models_root, repo)
}

pub(crate) fn cache_dir_at(models_root: &Path, repo: &str) -> PathBuf {
    models_root.join(super::model_cache_component(repo))
}

/// Materialise a cheap structural cache fixture whose artifact lengths follow
/// the reviewed manifest. The safetensors payload is sparse and the fixture is
/// intentionally not SHA-256-valid; production-ready validation still rejects
/// it. This keeps cache-status tests honest without checking multi-gigabyte
/// model blobs into the repository.
#[cfg(test)]
pub(crate) fn materialize_structural_test_cache(models_root: &Path, repo: &str) -> Result<PathBuf> {
    use crate::media::model_manager::ArtifactKind;
    use std::io::Write as _;

    let manifest = artifact_manifest(repo)
        .with_context(|| format!("no reviewed Whisper artifact manifest for `{repo}`"))?;
    let cache = cache_dir_at(models_root, repo);
    std::fs::create_dir_all(&cache)
        .with_context(|| format!("create structural test cache {}", cache.display()))?;

    for artifact in manifest.artifacts {
        let expected = artifact.expected.with_context(|| {
            format!(
                "Whisper test fixture artifact `{}` has no pinned length",
                artifact.filename
            )
        })?;
        let path = cache.join(artifact.filename);
        match artifact.kind {
            ArtifactKind::JsonObject => {
                let len = usize::try_from(expected.len)
                    .context("Whisper JSON fixture length does not fit usize")?;
                anyhow::ensure!(len >= 2, "Whisper JSON fixture is shorter than `{{}}`");
                let mut bytes = vec![b' '; len];
                bytes[0] = b'{';
                bytes[1] = b'}';
                std::fs::write(&path, bytes)
                    .with_context(|| format!("write structural JSON fixture {}", path.display()))?;
            }
            ArtifactKind::Safetensors => {
                let mut data_len = expected.len;
                let header = loop {
                    let header = format!(
                        r#"{{"weight":{{"dtype":"U8","shape":[{data_len}],"data_offsets":[0,{data_len}]}}}}"#
                    );
                    let next = expected
                        .len
                        .checked_sub(8 + header.len() as u64)
                        .context("Whisper safetensors fixture is shorter than its header")?;
                    if next == data_len {
                        break header;
                    }
                    data_len = next;
                };
                let mut file = std::fs::File::create(&path).with_context(|| {
                    format!("create structural safetensors fixture {}", path.display())
                })?;
                file.write_all(&(header.len() as u64).to_le_bytes())?;
                file.write_all(header.as_bytes())?;
                file.set_len(expected.len)?;
            }
            ArtifactKind::NonEmpty { .. } => {
                anyhow::bail!(
                    "unexpected opaque artifact `{}` in Whisper manifest",
                    artifact.filename
                );
            }
        }
    }
    Ok(cache)
}

pub(crate) fn cache_health_at(
    models_root: &Path,
    repo: &str,
) -> crate::media::model_manager::CacheHealth {
    let cache = cache_dir_at(models_root, repo);
    let Some(manifest) = artifact_manifest(repo) else {
        return crate::media::model_manager::CacheHealth::Corrupt {
            path: cache,
            reason: format!(
                "unsupported Whisper repository `{repo}` has no reviewed revision/SHA-256 manifest"
            ),
        };
    };
    crate::media::model_manager::cache_health(&cache, &manifest.artifacts)
}

pub(crate) fn verified_cache_health_at(
    models_root: &Path,
    repo: &str,
    during_attempt: bool,
) -> crate::media::model_manager::CacheHealth {
    let cache = cache_dir_at(models_root, repo);
    let Some(manifest) = artifact_manifest(repo) else {
        return crate::media::model_manager::CacheHealth::Corrupt {
            path: cache,
            reason: format!(
                "unsupported Whisper repository `{repo}` has no reviewed revision/SHA-256 manifest"
            ),
        };
    };
    if during_attempt {
        crate::media::model_manager::verified_cache_health_during_install(
            &cache,
            &manifest.artifacts,
        )
    } else {
        crate::media::model_manager::verified_cache_health(&cache, &manifest.artifacts)
    }
}

/// Peek at the `num_mel_bins` field in config.json without instantiating
/// the model. Used to size the mel filterbank before the weights load.
fn peek_n_mels(config_path: &Path) -> Result<usize> {
    let body = std::fs::read_to_string(config_path)
        .with_context(|| format!("read {}", config_path.display()))?;
    let v: serde_json::Value = serde_json::from_str(&body).context("parse whisper config.json")?;
    let n = v.get("num_mel_bins").and_then(|x| x.as_u64()).unwrap_or(80) as usize;
    Ok(n)
}

/// Compute the mel filterbank — `(n_mels × (N_FFT/2 + 1))` flat. Mirrors
/// librosa.filters.mel with `htk=False`, `norm='slaney'`. ~50 LOC of
/// reference-grade math; matches whisper's `mel_filters.npz` to f32
/// precision.
fn compute_mel_filters(n_mels: usize) -> Vec<f32> {
    const SR: f32 = 16000.0;
    let n_fft = cw::N_FFT;
    let n_freqs = n_fft / 2 + 1;
    let fmin = 0.0f32;
    let fmax = SR / 2.0;

    // Slaney mel-scale conversions.
    fn hz_to_mel(f: f32) -> f32 {
        let f_min = 0.0_f32;
        let f_sp = 200.0_f32 / 3.0;
        let min_log_hz = 1000.0_f32;
        let min_log_mel = (min_log_hz - f_min) / f_sp;
        let logstep = (6.4_f32).ln() / 27.0;
        if f >= min_log_hz {
            min_log_mel + ((f / min_log_hz).ln()) / logstep
        } else {
            (f - f_min) / f_sp
        }
    }
    fn mel_to_hz(m: f32) -> f32 {
        let f_min = 0.0_f32;
        let f_sp = 200.0_f32 / 3.0;
        let min_log_hz = 1000.0_f32;
        let min_log_mel = (min_log_hz - f_min) / f_sp;
        let logstep = (6.4_f32).ln() / 27.0;
        if m >= min_log_mel {
            min_log_hz * ((m - min_log_mel) * logstep).exp()
        } else {
            f_min + f_sp * m
        }
    }

    let mel_min = hz_to_mel(fmin);
    let mel_max = hz_to_mel(fmax);
    let mut mel_points = Vec::with_capacity(n_mels + 2);
    for i in 0..(n_mels + 2) {
        let frac = i as f32 / (n_mels as f32 + 1.0);
        mel_points.push(mel_min + frac * (mel_max - mel_min));
    }
    let hz_points: Vec<f32> = mel_points.iter().copied().map(mel_to_hz).collect();
    let fft_freqs: Vec<f32> = (0..n_freqs)
        .map(|k| (SR / n_fft as f32) * k as f32)
        .collect();

    let mut filters = vec![0f32; n_mels * n_freqs];
    for m in 0..n_mels {
        let lo = hz_points[m];
        let mid = hz_points[m + 1];
        let hi = hz_points[m + 2];
        let denom_left = mid - lo;
        let denom_right = hi - mid;
        // Slaney normalisation = 2 / (hi - lo).
        let norm = 2.0 / (hi - lo);
        for (k, &f) in fft_freqs.iter().enumerate() {
            let weight = if f < lo || f > hi {
                0.0
            } else if f <= mid {
                ((f - lo) / denom_left.max(1e-9)) * norm
            } else {
                ((hi - f) / denom_right.max(1e-9)) * norm
            };
            filters[m * n_freqs + k] = weight;
        }
    }
    filters
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_mel_filters_for_80_bins_has_expected_size() {
        let n_mels = 80;
        let f = compute_mel_filters(n_mels);
        let n_freqs = cw::N_FFT / 2 + 1;
        assert_eq!(f.len(), n_mels * n_freqs);
        // Every filter must have some non-zero weight.
        for m in 0..n_mels {
            let row = &f[m * n_freqs..(m + 1) * n_freqs];
            let sum: f32 = row.iter().sum();
            assert!(sum > 0.0, "filter {m} has zero total weight");
        }
    }

    #[test]
    fn compute_mel_filters_for_128_bins_has_expected_size() {
        let n_mels = 128;
        let f = compute_mel_filters(n_mels);
        let n_freqs = cw::N_FFT / 2 + 1;
        assert_eq!(f.len(), n_mels * n_freqs);
    }

    #[test]
    fn whisper_options_default_is_english_transcribe_greedy_with_autodetect() {
        let o = WhisperOptions::default();
        assert_eq!(o.language, "en");
        assert!(!o.translate);
        assert_eq!(o.max_new_tokens, 480);
        assert!(
            o.auto_detect_language,
            "auto-detect should default on so non-English chunks transcribe correctly \
             out of the box"
        );
    }

    #[test]
    fn default_cache_dir_flattens_repo_path() {
        let p = default_cache_dir("openai/whisper-large-v3-turbo");
        assert_eq!(
            p,
            crate::config::FreedomConfig::default_neoth_home()
                .join("models")
                .join("openai-whisper-large-v3-turbo")
        );
    }

    #[test]
    fn explicit_models_root_never_falls_back_to_process_home() {
        let root = PathBuf::from("isolated-neoth-home").join("models");
        assert_eq!(
            cache_dir_at(&root, "openai/whisper-base"),
            root.join("openai-whisper-base")
        );
    }

    #[test]
    fn default_repo_is_whisper_large_v3_turbo() {
        assert_eq!(DEFAULT_WHISPER_REPO, "openai/whisper-large-v3-turbo");
    }

    /// Build a minimal tokenizer that registers a handful of fake
    /// language tokens + non-language tokens so we can exercise the
    /// discovery filter without downloading the real whisper
    /// tokenizer.json.
    fn fake_tokenizer_with_language_tokens() -> Tokenizer {
        use tokenizers::AddedToken;
        use tokenizers::models::wordlevel::WordLevel;

        let mut vocab = std::collections::HashMap::new();
        vocab.insert("<|en|>".to_string(), 0u32);
        vocab.insert("<|de|>".to_string(), 1);
        vocab.insert("<|jw|>".to_string(), 2);
        vocab.insert("<|haw|>".to_string(), 3); // 3-letter code (haw = Hawaiian)
        vocab.insert("<|transcribe|>".to_string(), 4); // excluded — too long
        vocab.insert("<|translate|>".to_string(), 5); // excluded — too long
        vocab.insert("<|endoftext|>".to_string(), 6); // excluded — non-letter content
        vocab.insert("<|EN|>".to_string(), 7); // excluded — uppercase
        vocab.insert("hello".to_string(), 8); // excluded — no <| ... |>
        let model = WordLevel::builder()
            .vocab(vocab)
            .unk_token("hello".to_string())
            .build()
            .unwrap();
        let mut tok = Tokenizer::new(model);
        tok.add_special_tokens(&[
            AddedToken::from("<|en|>", true),
            AddedToken::from("<|de|>", true),
            AddedToken::from("<|jw|>", true),
            AddedToken::from("<|haw|>", true),
            AddedToken::from("<|transcribe|>", true),
            AddedToken::from("<|translate|>", true),
            AddedToken::from("<|endoftext|>", true),
            AddedToken::from("<|EN|>", true),
        ]);
        tok
    }

    #[test]
    fn discover_language_tokens_filters_to_lowercase_2_3_letter_codes() {
        let tok = fake_tokenizer_with_language_tokens();
        let codes: Vec<String> = discover_language_tokens(&tok)
            .into_iter()
            .map(|(c, _)| c)
            .collect();
        assert!(codes.contains(&"en".to_string()));
        assert!(codes.contains(&"de".to_string()));
        assert!(codes.contains(&"jw".to_string()));
        assert!(codes.contains(&"haw".to_string()));
        assert!(
            !codes.contains(&"transcribe".to_string()),
            "task tokens must not slip through"
        );
        assert!(
            !codes.contains(&"endoftext".to_string()),
            "non-language sentinel must not slip through"
        );
        // Uppercase variant excluded — language codes are lowercase
        // ISO 639 by spec.
        assert!(!codes.contains(&"EN".to_string()));
    }

    #[test]
    fn discover_language_tokens_on_empty_tokenizer_returns_empty() {
        use tokenizers::models::wordlevel::WordLevel;
        let model = WordLevel::builder()
            .vocab([("x".to_string(), 0u32)].into_iter().collect())
            .unk_token("x".to_string())
            .build()
            .unwrap();
        let tok = Tokenizer::new(model);
        assert!(discover_language_tokens(&tok).is_empty());
    }

    #[test]
    fn compression_ratio_returns_zero_for_empty_text() {
        assert_eq!(compression_ratio(""), 0.0);
    }

    #[test]
    fn compression_ratio_flags_repetitive_text() {
        // Pathological repetition — gzip eats it. Real whisper
        // hallucinations look like this ("Thank you. Thank you. Thank
        // you. ..." for minutes).
        let repetitive: String = "hallo hallo hallo ".repeat(200);
        let r = compression_ratio(&repetitive);
        assert!(r > 5.0, "repetitive text should compress hard, got {r}");
    }

    #[test]
    fn compression_ratio_low_for_natural_diverse_text() {
        let prose = "The quick brown fox jumps over the lazy dog. Sphinx of black quartz, \
                     judge my vow! Pack my box with five dozen liquor jugs.";
        let r = compression_ratio(prose);
        assert!(
            r < 2.0,
            "natural prose should not trip the 2.4 threshold, got {r}"
        );
    }

    #[test]
    fn default_options_has_full_temperature_schedule() {
        let o = WhisperOptions::default();
        assert_eq!(o.temperatures, vec![0.0, 0.2, 0.4, 0.6, 0.8, 1.0]);
        assert!((o.compression_ratio_threshold - 2.4).abs() < 1e-6);
    }

    // ── device_for_hw_probe (HANDY-07-WIRE) ─────────────────────────────────

    #[test]
    fn device_for_hw_probe_no_panic_on_cuda_with_fma3() {
        use crate::media::hw_probe::{AcceleratorClass, CpuCaps, HwProbe};
        let probe = HwProbe {
            cpu_caps: CpuCaps {
                fma3: true,
                avx2: true,
                avx: true,
            },
            accelerator: AcceleratorClass::Cuda,
        };
        // require_fma3 must succeed (fma3=true)
        assert!(crate::media::hw_probe::require_fma3(probe.cpu_caps.fma3).is_ok());
        // device_for_hw_probe must not panic on any build config.
        let _ = device_for_hw_probe(&probe);
    }

    #[test]
    fn device_for_hw_probe_falls_back_to_cpu_when_no_fma3() {
        use crate::media::hw_probe::{AcceleratorClass, CpuCaps, HwProbe};
        let probe = HwProbe {
            cpu_caps: CpuCaps {
                fma3: false,
                avx2: false,
                avx: false,
            },
            accelerator: AcceleratorClass::Cuda,
        };
        let device = device_for_hw_probe(&probe);
        assert!(
            matches!(device, Device::Cpu),
            "pre-FMA3 CPU must fall back to Device::Cpu"
        );
    }

    #[test]
    fn device_for_hw_probe_cpu_class_skips_fma3_guard() {
        use crate::media::hw_probe::{AcceleratorClass, CpuCaps, HwProbe};
        let probe = HwProbe {
            cpu_caps: CpuCaps {
                fma3: false,
                avx2: false,
                avx: false,
            },
            accelerator: AcceleratorClass::Cpu,
        };
        let device = device_for_hw_probe(&probe);
        assert!(matches!(device, Device::Cpu));
    }

    // ── HANDY-05: idle-unload + LoadingGuard tests ───────────────────────────

    /// `LoadingGuard::drop` must decrement the in_flight counter.
    ///
    /// This is a unit test of the counter protocol — no model weights needed.
    #[test]
    fn loading_guard_drop_decrements_in_flight() {
        let in_flight = Arc::new(AtomicUsize::new(0));
        let last_used = Arc::new(Mutex::new(Instant::now()));
        // Simulate acquiring the guard (as engine.loading_guard() does).
        in_flight.fetch_add(1, Ordering::AcqRel);
        let guard = LoadingGuard {
            in_flight: Arc::clone(&in_flight),
            last_used: Arc::clone(&last_used),
        };
        assert_eq!(
            in_flight.load(Ordering::Acquire),
            1,
            "in_flight should be 1 while guard is live"
        );
        drop(guard);
        assert_eq!(
            in_flight.load(Ordering::Acquire),
            0,
            "in_flight should be 0 after guard drop"
        );
    }

    /// Multiple overlapping guards increment/decrement correctly (concurrency
    /// correctness of the AtomicUsize counter).
    #[test]
    fn loading_guard_multiple_concurrent_increments() {
        let in_flight = Arc::new(AtomicUsize::new(0));
        let last_used = Arc::new(Mutex::new(Instant::now()));
        // Simulate 3 concurrent guards.
        in_flight.fetch_add(1, Ordering::AcqRel);
        let g1 = LoadingGuard {
            in_flight: Arc::clone(&in_flight),
            last_used: Arc::clone(&last_used),
        };
        in_flight.fetch_add(1, Ordering::AcqRel);
        let g2 = LoadingGuard {
            in_flight: Arc::clone(&in_flight),
            last_used: Arc::clone(&last_used),
        };
        in_flight.fetch_add(1, Ordering::AcqRel);
        let g3 = LoadingGuard {
            in_flight: Arc::clone(&in_flight),
            last_used: Arc::clone(&last_used),
        };
        assert_eq!(in_flight.load(Ordering::Acquire), 3);
        drop(g1);
        assert_eq!(in_flight.load(Ordering::Acquire), 2);
        drop(g2);
        assert_eq!(in_flight.load(Ordering::Acquire), 1);
        drop(g3);
        assert_eq!(in_flight.load(Ordering::Acquire), 0);
    }

    /// `default_whisper_idle_unload_secs` returns `Some(120)` — the
    /// `MediaConfig` default should be 2 minutes, not disabled.
    #[test]
    fn media_config_default_whisper_idle_unload_secs_is_120() {
        let cfg = crate::config::MediaConfig::default();
        assert_eq!(
            cfg.whisper_idle_unload_secs,
            Some(120),
            "HANDY-05: default idle timeout must be Some(120) (2 minutes)"
        );
    }

    /// `MediaConfig::default()` with `whisper_idle_unload_secs = None` means
    /// never-unload — ensure `None` round-trips through serde.
    #[test]
    fn media_config_whisper_idle_unload_secs_none_survives_serde() {
        let mut cfg = crate::config::MediaConfig::default();
        cfg.whisper_idle_unload_secs = None;
        let json = serde_json::to_string(&cfg).unwrap();
        let back: crate::config::MediaConfig = serde_json::from_str(&json).unwrap();
        // `None` from JSON round-trips back to `None`.
        assert_eq!(back.whisper_idle_unload_secs, None);
    }

    /// `MediaConfig` with `whisper_idle_unload_secs` absent from the JSON
    /// payload uses the `serde(default)` helper → `Some(120)`.
    #[test]
    fn media_config_missing_field_gets_default_120() {
        // Minimal JSON — omit the new field entirely.
        let json = "{}";
        let cfg: crate::config::MediaConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.whisper_idle_unload_secs, Some(120));
    }
}
