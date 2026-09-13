//! Ouro runtime-artifact identity and integrity contract.
//!
//! The Hugging Face cache is only a transport cache.  The runtime accepts an
//! Ouro generation only after the exact three files it opens have passed the
//! shared structural validator and have been bound into a content-addressed
//! receipt.  A receipt is deliberately cheap to compare and expensive to
//! forge: it contains the configured repo, every artifact's SHA-256/length,
//! the selected quantisation path, and the resolved Candle device location.

use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use candle_core::safetensors::Load;
use sha2::{Digest, Sha256};

use crate::providers::local_qwen::{CONFIG_FILE, SAFETENSORS_FILE, TOKENIZER_FILE};

use super::model::{OuroConfig, OuroQuantMode};

const REQUIRED_ARTIFACTS: [crate::media::model_manager::RequiredArtifact; 3] = [
    crate::media::model_manager::RequiredArtifact {
        filename: TOKENIZER_FILE,
        kind: crate::media::model_manager::ArtifactKind::JsonObject,
        expected: None,
    },
    crate::media::model_manager::RequiredArtifact {
        filename: CONFIG_FILE,
        kind: crate::media::model_manager::ArtifactKind::JsonObject,
        expected: None,
    },
    crate::media::model_manager::RequiredArtifact {
        filename: SAFETENSORS_FILE,
        kind: crate::media::model_manager::ArtifactKind::Safetensors,
        expected: None,
    },
];
const WEIGHT_ARTIFACT: [crate::media::model_manager::RequiredArtifact; 1] =
    [crate::media::model_manager::RequiredArtifact {
        filename: SAFETENSORS_FILE,
        kind: crate::media::model_manager::ArtifactKind::Safetensors,
        expected: None,
    }];

const GENERATIONS_DIR: &str = ".ouro-generations";
const ACTIVE_GENERATION_FILE: &str = ".ouro-active-generation.json";
const GENERATION_PENDING_FILE: &str = ".ouro-generation.pending.json";
/// Tokenizer and config are metadata, never model-weight payloads.  Keep
/// their parsing bounded even if a cache path is replaced with a large file.
const MAX_OURO_METADATA_BYTES: u64 = 32 * 1024 * 1024;

#[derive(serde::Deserialize, serde::Serialize)]
struct ActiveGeneration {
    version: u8,
    generation: String,
}

/// Bounded readiness result shared by the CLI and future GUI surfaces.  This
/// deliberately reports structural readiness only; creating a model still
/// makes the full digest-bound [`OuroLoadReceipt`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct OuroCacheStatus {
    pub state: &'static str,
    pub detail: Option<String>,
}

/// Inspect a runtime cache without a surprise multi-gigabyte digest pass.
/// `ready` means the normal, non-pending structural contract holds; every
/// other state is `not_ready` and carries a bounded causal detail.
pub fn runtime_cache_status(cache_dir: &Path) -> OuroCacheStatus {
    let checked_dir = match active_generation_dir(cache_dir) {
        Ok(Some(generation)) => generation,
        Ok(None) => cache_dir.to_path_buf(),
        Err(error) => {
            return OuroCacheStatus {
                state: "not_ready",
                detail: Some(bounded_detail(&error)),
            };
        }
    };
    match validate_runtime_artifacts_at(&checked_dir, false) {
        Ok(()) => OuroCacheStatus {
            state: "ready",
            detail: None,
        },
        Err(error) => OuroCacheStatus {
            state: "not_ready",
            detail: Some(bounded_detail(&error)),
        },
    }
}

/// One runtime file as observed at validation time.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct OuroArtifactDigest {
    pub(crate) filename: &'static str,
    pub(crate) len: u64,
    pub(crate) sha256: String,
}

/// Immutable identity of a model load.  Do not persist this as a cache-ready
/// marker: it is a receipt for the bytes currently observed by this process.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct OuroLoadReceipt {
    pub(crate) repo: String,
    pub(crate) artifacts: Vec<OuroArtifactDigest>,
    pub(crate) quant_mode: &'static str,
    pub(crate) configured_accelerator: &'static str,
    pub(crate) resolved_accelerator: String,
}

/// A load lease binds the exact opened files to config/tokenizer parsing and
/// the safetensors mmap used by Candle. The mapped weight bytes are never
/// copied into a whole-model buffer; the lease stays in [`LoadedOuro`] for the
/// lifetime of tensors that may borrow the mapping.
pub(crate) struct OuroLoadLease {
    _tokenizer_file: File,
    _config_file: File,
    tokenizer_bytes: Vec<u8>,
    config_bytes: Vec<u8>,
    weights: Arc<BoundSafetensors>,
}

struct BoundSafetensors {
    _file: File,
    mmap: memmap2::Mmap,
}

struct LeaseBackend(Arc<BoundSafetensors>);

impl OuroLoadReceipt {
    pub(crate) fn summary(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"neoth-ouro-load-receipt-v1\0");
        hasher.update(self.repo.as_bytes());
        hasher.update(self.quant_mode.as_bytes());
        hasher.update(self.configured_accelerator.as_bytes());
        hasher.update(self.resolved_accelerator.as_bytes());
        for artifact in &self.artifacts {
            hasher.update(artifact.filename.as_bytes());
            hasher.update(artifact.len.to_be_bytes());
            hasher.update(artifact.sha256.as_bytes());
        }
        hex::encode(hasher.finalize())
    }
}

impl OuroLoadLease {
    /// Open a retained, exact-file lease for a published generation. Every
    /// loaded byte must equal the receipt made from that generation; paths are
    /// never reopened by Candle after this point.
    pub(crate) fn open(generation_dir: &Path, receipt: &OuroLoadReceipt) -> Result<Self> {
        let tokenizer_file = open_read_lease(&generation_dir.join(TOKENIZER_FILE))?;
        let config_file = open_read_lease(&generation_dir.join(CONFIG_FILE))?;
        let weights_file = open_read_lease(&generation_dir.join(SAFETENSORS_FILE))?;
        let tokenizer_bytes = read_bound_file(&tokenizer_file, TOKENIZER_FILE)?;
        let config_bytes = read_bound_file(&config_file, CONFIG_FILE)?;
        // SAFETY: the map is made from the same retained handle whose bytes
        // are receipt-checked immediately below, and it remains owned by the
        // lease for every tensor load. Windows reader-only sharing excludes
        // writes, replacement, and delete. Unix `flock` is advisory only: the
        // readonly content-addressed generation contract protects against
        // NEOTH cache writers, not a hostile process that can mutate the
        // inode despite that contract.
        let mmap = unsafe {
            memmap2::MmapOptions::new()
                .map(&weights_file)
                .context("mmap retained Ouro safetensors handle")?
        };
        let lease = Self {
            _tokenizer_file: tokenizer_file,
            _config_file: config_file,
            tokenizer_bytes,
            config_bytes,
            weights: Arc::new(BoundSafetensors {
                _file: weights_file,
                mmap,
            }),
        };
        lease.ensure_matches_receipt(receipt)?;
        // Parse the actual mapped header once at lease creation. The custom
        // backend reparses only this already-bound mmap for individual tensors.
        lease.weights.safe_tensors()?;
        Ok(lease)
    }

    pub(crate) fn tokenizer(&self) -> Result<tokenizers::Tokenizer> {
        tokenizers::Tokenizer::from_bytes(&self.tokenizer_bytes)
            .map_err(|error| anyhow::anyhow!("parse bound Ouro tokenizer.json: {error}"))
    }

    pub(crate) fn config(&self) -> Result<OuroConfig> {
        let config: OuroConfig =
            serde_json::from_slice(&self.config_bytes).context("parse bound Ouro config.json")?;
        config.validate().context("validate bound Ouro config.json")
    }

    pub(crate) fn var_builder(
        &self,
        dtype: candle_core::DType,
        device: &candle_core::Device,
    ) -> candle_nn::VarBuilder<'static> {
        candle_nn::VarBuilder::from_backend(
            Box::new(LeaseBackend(Arc::clone(&self.weights))),
            dtype,
            device.clone(),
        )
    }

    /// Rehash the retained bytes, not their filesystem paths. This catches a
    /// mutation visible through the active map while model construction runs.
    pub(crate) fn ensure_matches_receipt(&self, receipt: &OuroLoadReceipt) -> Result<()> {
        let actual = [
            digest_bytes(TOKENIZER_FILE, &self.tokenizer_bytes),
            digest_bytes(CONFIG_FILE, &self.config_bytes),
            digest_bytes(SAFETENSORS_FILE, &self.weights.mmap),
        ];
        anyhow::ensure!(
            actual.as_slice() == receipt.artifacts.as_slice(),
            "Ouro bound load lease bytes do not match the validated artifact receipt"
        );
        Ok(())
    }
}

impl BoundSafetensors {
    fn safe_tensors(&self) -> candle_core::Result<safetensors::tensor::SafeTensors<'_>> {
        Ok(safetensors::tensor::SafeTensors::deserialize(&self.mmap)?)
    }
}

impl candle_nn::var_builder::SimpleBackend for LeaseBackend {
    fn get(
        &self,
        expected_shape: candle_core::Shape,
        name: &str,
        _: candle_nn::Init,
        dtype: candle_core::DType,
        device: &candle_core::Device,
    ) -> candle_core::Result<candle_core::Tensor> {
        let tensor = self
            .0
            .safe_tensors()?
            .tensor(name)?
            .load(device)?
            .to_dtype(dtype)?;
        if tensor.shape() != &expected_shape {
            candle_core::bail!("shape mismatch for {name}");
        }
        Ok(tensor)
    }

    fn contains_tensor(&self, name: &str) -> bool {
        self.0
            .safe_tensors()
            .is_ok_and(|tensors| tensors.tensor(name).is_ok())
    }
}

/// Validate the exact tokenizer, config, and safetensors payload that Ouro
/// opens.  `during_install` is only valid while the model-download lifecycle
/// owns the generation; ordinary cache hits reject every pending marker.
pub(crate) fn validate_runtime_artifacts_at(cache_dir: &Path, during_install: bool) -> Result<()> {
    for artifact in &REQUIRED_ARTIFACTS {
        ensure_regular_artifact_path(&cache_dir.join(artifact.filename))?;
    }
    let health = if during_install {
        crate::media::model_manager::cache_health_during_install(cache_dir, &WEIGHT_ARTIFACT)
    } else {
        crate::media::model_manager::cache_health(cache_dir, &WEIGHT_ARTIFACT)
    };
    if !health.is_ready() {
        anyhow::bail!("Ouro runtime cache is not loadable: {health}");
    }

    // Bound the metadata before handing it to either JSON/tokenizer parser.
    let tokenizer_bytes = read_bounded_path(&cache_dir.join(TOKENIZER_FILE), TOKENIZER_FILE)?;
    let config_bytes = read_bounded_path(&cache_dir.join(CONFIG_FILE), CONFIG_FILE)?;
    let tokenizer = tokenizers::Tokenizer::from_bytes(&tokenizer_bytes)
        .map_err(|error| anyhow::anyhow!("load Ouro tokenizer.json: {error}"))?;
    let config: OuroConfig =
        serde_json::from_slice(&config_bytes).context("parse Ouro config.json")?;
    config.validate().context("validate Ouro config.json")?;
    validate_tokenizer_vocab(&tokenizer, config.vocab_size)?;
    Ok(())
}

fn validate_tokenizer_vocab(tokenizer: &tokenizers::Tokenizer, vocab_size: usize) -> Result<()> {
    let max_id = tokenizer.get_vocab(true).into_values().max();
    if let Some(max_id) = max_id {
        let max_id = usize::try_from(max_id).context("Ouro tokenizer id does not fit usize")?;
        if max_id >= vocab_size {
            anyhow::bail!(
                "Ouro tokenizer maximum id {max_id} is outside config vocab_size {vocab_size}"
            );
        }
    }
    Ok(())
}

/// Revalidate and fingerprint the current runtime inputs into a load receipt.
/// This is called before every warm-cache reuse, so a same-path overwrite,
/// configuration swap, pending lifecycle marker, or quant/device change cannot
/// reuse a previously loaded native/Q8 model.
pub(crate) fn receipt_for(
    repo: &str,
    cache_dir: &Path,
    quant_mode: OuroQuantMode,
    configured_accelerator: &'static str,
    resolved_accelerator: String,
) -> Result<OuroLoadReceipt> {
    validate_runtime_artifacts_at(cache_dir, false)?;
    let artifacts = REQUIRED_ARTIFACTS
        .iter()
        .map(|artifact| fingerprint(cache_dir.join(artifact.filename), artifact.filename))
        .collect::<Result<Vec<_>>>()?;
    Ok(OuroLoadReceipt {
        repo: repo.to_string(),
        artifacts,
        quant_mode: quant_mode.as_str(),
        configured_accelerator,
        resolved_accelerator,
    })
}

/// Resolve the immutable content-addressed generation for this cache, or move
/// a fully validated canonical trio into one.  Callers that already own the
/// shared model-cache lock must use [`resolve_or_promote_generation_locked`].
pub(crate) fn resolve_or_promote_generation(cache_dir: &Path) -> Result<PathBuf> {
    let _guard = crate::media::model_manager::lock_model_cache_blocking(cache_dir)
        .context("lock Ouro cache to resolve immutable generation")?;
    resolve_or_promote_generation_locked(cache_dir)
}

/// Resolve only an already-published generation. This may repair one durable
/// promotion journal or adopt one exact orphan generation while holding the
/// shared model-cache lock. It never downloads or promotes mutable paths.
pub(crate) fn resolve_existing_generation(cache_dir: &Path) -> Result<Option<PathBuf>> {
    let _guard = crate::media::model_manager::lock_model_cache_blocking(cache_dir)
        .context("lock Ouro cache to inspect immutable generation")?;
    resolve_existing_generation_locked(cache_dir)
}

/// Same as [`resolve_or_promote_generation`] while the caller owns the shared
/// model-cache lock.  The active pointer is committed last, so an interrupted
/// promotion cannot be observed as ready.  Files are renamed on the same
/// volume; this creates no second multi-gigabyte model copy.
pub(crate) fn resolve_or_promote_generation_locked(cache_dir: &Path) -> Result<PathBuf> {
    if let Some(active) = resolve_existing_generation_locked(cache_dir)? {
        return Ok(active);
    }
    let digests = runtime_artifact_digests(cache_dir)?;
    let generation = artifact_generation_id(&digests);
    let generations_root = cache_dir.join(GENERATIONS_DIR);
    std::fs::create_dir_all(&generations_root)
        .with_context(|| format!("create Ouro generation root {}", generations_root.display()))?;
    ensure_real_directory(&generations_root, "Ouro immutable generation root")?;
    crate::util::atomic_write::sync_parent_directory_required(&generations_root)
        .context("durably create Ouro generation root")?;
    let generation_dir = generations_root.join(&generation);
    let pending = cache_dir.join(GENERATION_PENDING_FILE);
    let pending_record = ActiveGeneration {
        version: 1,
        generation: generation.clone(),
    };
    publish_generation_record(&pending, &pending_record, "promotion marker")?;
    std::fs::create_dir_all(&generation_dir)
        .with_context(|| format!("create Ouro generation {}", generation_dir.display()))?;
    ensure_real_directory(&generation_dir, "Ouro immutable generation")?;
    crate::util::atomic_write::sync_parent_directory_required(&generation_dir)
        .context("durably create Ouro generation directory")?;
    for artifact in &REQUIRED_ARTIFACTS {
        let source = cache_dir.join(artifact.filename);
        let destination = generation_dir.join(artifact.filename);
        if destination.exists() {
            anyhow::ensure!(
                source.exists(),
                "Ouro generation collision leaves mutable source beside immutable destination"
            );
            continue;
        }
        ensure_regular_artifact_path(&source)?;
        std::fs::rename(&source, &destination).with_context(|| {
            format!(
                "publish Ouro artifact into immutable generation {} -> {}",
                source.display(),
                destination.display()
            )
        })?;
        crate::util::atomic_write::sync_parent_directory_required(&source).with_context(|| {
            format!("durably remove mutable Ouro artifact {}", source.display())
        })?;
        crate::util::atomic_write::sync_parent_directory_required(&destination).with_context(
            || {
                format!(
                    "durably publish Ouro artifact into generation {}",
                    destination.display()
                )
            },
        )?;
    }
    // Re-read after rename and bind the directory name to its actual bytes
    // before publishing the pointer.  A changed generation is never active.
    let published = runtime_artifact_digests(&generation_dir)?;
    anyhow::ensure!(
        artifact_generation_id(&published) == generation,
        "Ouro generation content changed during promotion"
    );
    for artifact in &REQUIRED_ARTIFACTS {
        let path = generation_dir.join(artifact.filename);
        make_artifact_readonly(&path)?;
        crate::util::atomic_write::sync_parent_directory_required(&path)
            .with_context(|| format!("durably commit Ouro generation mode {}", path.display()))?;
    }
    let active = ActiveGeneration {
        version: 1,
        generation,
    };
    publish_generation_record(
        &cache_dir.join(ACTIVE_GENERATION_FILE),
        &active,
        "active generation pointer",
    )?;
    crate::util::atomic_write::durable_remove_file(&pending).with_context(|| {
        format!(
            "clear Ouro generation promotion marker {}",
            pending.display()
        )
    })?;
    Ok(generation_dir)
}

pub(crate) fn active_generation_dir(cache_dir: &Path) -> Result<Option<PathBuf>> {
    ensure_no_pending_generation(cache_dir)?;
    let pointer = cache_dir.join(ACTIVE_GENERATION_FILE);
    let Some(active) = read_generation_record(&pointer, "active generation")? else {
        return Ok(None);
    };
    let generation_dir = verify_generation_dir(cache_dir, &active.generation)?;
    Ok(Some(generation_dir))
}

/// Recover only an unambiguous, fully verified generation. A missing pointer
/// or journal is not permission to fetch again when generation evidence is
/// still present: incomplete and ambiguous directories remain visible errors.
fn resolve_existing_generation_locked(cache_dir: &Path) -> Result<Option<PathBuf>> {
    let pending = cache_dir.join(GENERATION_PENDING_FILE);
    if let Some(record) = read_generation_record(&pending, "promotion marker")? {
        let generation_dir = verify_generation_dir(cache_dir, &record.generation).with_context(|| {
            format!(
                "Ouro promotion marker cannot be recovered without exact immutable generation {}",
                record.generation
            )
        })?;
        publish_generation_record(
            &cache_dir.join(ACTIVE_GENERATION_FILE),
            &record,
            "recovered active generation pointer",
        )?;
        crate::util::atomic_write::durable_remove_file(&pending)
            .context("durably clear recovered Ouro promotion marker")?;
        return Ok(Some(generation_dir));
    }
    if let Some(active) = active_generation_dir(cache_dir)? {
        return Ok(Some(active));
    }

    let generations = cache_dir.join(GENERATIONS_DIR);
    match std::fs::symlink_metadata(&generations) {
        Ok(metadata) => {
            anyhow::ensure!(
                !metadata_is_link_like(&metadata) && metadata.is_dir(),
                "Ouro immutable generation root must be a real directory, not a symlink or reparse point: {}",
                generations.display()
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "stat Ouro immutable generation root without following links {}",
                    generations.display()
                )
            });
        }
    }
    let entries = std::fs::read_dir(&generations)
        .with_context(|| format!("read Ouro generations {}", generations.display()))?;
    let mut orphan = None;
    for entry in entries {
        let entry = entry.context("enumerate Ouro generation")?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("inspect Ouro generation entry {}", entry.path().display()))?;
        anyhow::ensure!(
            file_type.is_dir() && !file_type.is_symlink(),
            "unexpected non-directory Ouro generation entry: {}",
            entry.path().display()
        );
        let name = entry.file_name().to_string_lossy().into_owned();
        validate_generation_id(&name)?;
        let generation_dir = verify_generation_dir(cache_dir, &name).with_context(|| {
            format!(
                "orphan Ouro generation is incomplete or corrupt: {}",
                entry.path().display()
            )
        })?;
        anyhow::ensure!(
            orphan.is_none(),
            "multiple orphan Ouro generations exist; refusing implicit cache selection"
        );
        orphan = Some((name, generation_dir));
    }
    let Some((generation, generation_dir)) = orphan else {
        return Ok(None);
    };
    let record = ActiveGeneration {
        version: 1,
        generation,
    };
    publish_generation_record(
        &cache_dir.join(ACTIVE_GENERATION_FILE),
        &record,
        "recovered orphan active generation pointer",
    )?;
    Ok(Some(generation_dir))
}

fn verify_generation_dir(cache_dir: &Path, generation: &str) -> Result<PathBuf> {
    validate_generation_id(generation)?;
    let generations_root = cache_dir.join(GENERATIONS_DIR);
    ensure_real_directory(&generations_root, "Ouro immutable generation root")?;
    let generation_dir = generations_root.join(generation);
    ensure_real_directory(&generation_dir, "Ouro immutable generation")?;
    for artifact in &REQUIRED_ARTIFACTS {
        let path = generation_dir.join(artifact.filename);
        let metadata = ensure_regular_artifact_path(&path)?;
        anyhow::ensure!(
            metadata.permissions().readonly(),
            "Ouro active generation artifact is not readonly: {}",
            path.display()
        );
    }
    let digests = runtime_artifact_digests(&generation_dir)?;
    anyhow::ensure!(
        artifact_generation_id(&digests) == generation,
        "Ouro active generation content does not match its content-addressed identifier"
    );
    Ok(generation_dir)
}

fn ensure_no_pending_generation(cache_dir: &Path) -> Result<()> {
    let pending = cache_dir.join(GENERATION_PENDING_FILE);
    anyhow::ensure!(
        !pending.exists(),
        "Ouro generation promotion is incomplete; repair the cache before retrying: {}",
        pending.display()
    );
    Ok(())
}

fn read_generation_record(path: &Path, label: &str) -> Result<Option<ActiveGeneration>> {
    let body = match std::fs::read(path) {
        Ok(body) => body,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("read Ouro {label} {}", path.display()));
        }
    };
    let record: ActiveGeneration = serde_json::from_slice(&body)
        .with_context(|| format!("parse Ouro {label} {}", path.display()))?;
    anyhow::ensure!(record.version == 1, "unsupported Ouro {label} version");
    validate_generation_id(&record.generation)?;
    Ok(Some(record))
}

fn validate_generation_id(generation: &str) -> Result<()> {
    anyhow::ensure!(
        generation.len() == 64 && generation.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid Ouro active generation identifier"
    );
    Ok(())
}

fn publish_generation_record(path: &Path, record: &ActiveGeneration, label: &str) -> Result<()> {
    let body = serde_json::to_vec(record).with_context(|| format!("serialize Ouro {label}"))?;
    crate::util::atomic_write::atomic_write_private(path, &body)
        .with_context(|| format!("atomically publish Ouro {label} {}", path.display()))?;
    crate::util::atomic_write::sync_parent_directory_required(path)
        .with_context(|| format!("durably publish Ouro {label} {}", path.display()))?;
    Ok(())
}

fn runtime_artifact_digests(cache_dir: &Path) -> Result<Vec<OuroArtifactDigest>> {
    validate_runtime_artifacts_at(cache_dir, false)?;
    REQUIRED_ARTIFACTS
        .iter()
        .map(|artifact| fingerprint(cache_dir.join(artifact.filename), artifact.filename))
        .collect()
}

fn artifact_generation_id(artifacts: &[OuroArtifactDigest]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"neoth-ouro-artifact-generation-v1\0");
    for artifact in artifacts {
        hasher.update(artifact.filename.as_bytes());
        hasher.update(artifact.len.to_be_bytes());
        hasher.update(artifact.sha256.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn fingerprint(path: impl AsRef<Path>, filename: &'static str) -> Result<OuroArtifactDigest> {
    let path = path.as_ref();
    let mut file = open_read_lease(path)
        .with_context(|| format!("open Ouro artifact for SHA-256 {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut len = 0_u64;
    let mut buffer = [0_u8; 256 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("read Ouro artifact for SHA-256 {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        len = len
            .checked_add(read as u64)
            .context("Ouro artifact length overflow")?;
    }
    Ok(OuroArtifactDigest {
        filename,
        len,
        sha256: hex::encode(hasher.finalize()),
    })
}

fn digest_bytes(filename: &'static str, bytes: &[u8]) -> OuroArtifactDigest {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    OuroArtifactDigest {
        filename,
        len: bytes.len() as u64,
        sha256: hex::encode(hasher.finalize()),
    }
}

fn open_read_lease(path: &Path) -> Result<File> {
    ensure_regular_artifact_path(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        // Permit only readers. Windows enforces this against every later open,
        // so replacement, delete, and writes cannot race a live Ouro lease.
        // Opening the reparse point itself lets the handle check reject a
        // junction/symlink race instead of following it.
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        options
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .with_context(|| format!("open retained Ouro read lease {}", path.display()))?;
    ensure_regular_artifact_metadata(
        &file
            .metadata()
            .with_context(|| format!("stat opened Ouro read lease {}", path.display()))?,
        path,
    )?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;
        // Unix locks are advisory; the content-addressed readonly generation
        // is the immutability boundary. This lock still makes all NEOTH model
        // writers fail closed while the process retains the mapped inode.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) };
        if result != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("lock retained Ouro read lease {}", path.display()));
        }
    }
    Ok(file)
}

fn read_bound_file(file: &File, filename: &'static str) -> Result<Vec<u8>> {
    let mut file = file
        .try_clone()
        .with_context(|| format!("clone retained Ouro handle for {filename}"))?;
    file.rewind()
        .with_context(|| format!("rewind retained Ouro handle for {filename}"))?;
    read_bounded_stream(&mut file, filename)
}

fn read_bounded_path(path: &Path, filename: &'static str) -> Result<Vec<u8>> {
    let mut file = open_read_lease(path)
        .with_context(|| format!("open Ouro metadata {} for bounded read", path.display()))?;
    read_bounded_stream(&mut file, filename)
}

fn ensure_regular_artifact_path(path: &Path) -> Result<Metadata> {
    let metadata = std::fs::symlink_metadata(path).with_context(|| {
        format!(
            "stat Ouro artifact without following links {}",
            path.display()
        )
    })?;
    ensure_regular_artifact_metadata(&metadata, path)?;
    Ok(metadata)
}

fn ensure_real_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("stat {label} without following links {}", path.display()))?;
    anyhow::ensure!(
        !metadata_is_link_like(&metadata) && metadata.is_dir(),
        "{label} must be a real directory, not a symlink or reparse point: {}",
        path.display()
    );
    Ok(())
}

fn ensure_regular_artifact_metadata(metadata: &Metadata, path: &Path) -> Result<()> {
    anyhow::ensure!(
        !metadata_is_link_like(metadata) && metadata.is_file(),
        "Ouro artifact must be a regular file, not a symlink or reparse point: {}",
        path.display()
    );
    Ok(())
}

fn metadata_is_link_like(metadata: &Metadata) -> bool {
    if metadata.is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(not(windows))]
fn make_artifact_readonly(path: &Path) -> Result<()> {
    let file = open_read_lease(path)?;
    let mut permissions = file
        .metadata()
        .with_context(|| format!("stat published Ouro generation {}", path.display()))?
        .permissions();
    permissions.set_readonly(true);
    file.set_permissions(permissions)
        .with_context(|| format!("make Ouro generation readonly {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("durably make Ouro generation readonly {}", path.display()))?;
    Ok(())
}

#[cfg(windows)]
fn make_artifact_readonly(path: &Path) -> Result<()> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
        FILE_WRITE_ATTRIBUTES,
    };

    ensure_regular_artifact_path(path)?;
    // A retry can reach this point after the readonly attribute succeeded but
    // the later pointer/journal transition did not. Re-verify it with the
    // retained nofollow/reparse-safe reader; do not ask for write access to an
    // already-staged readonly artifact.
    let read_lease = open_read_lease(path)?;
    if read_lease
        .metadata()
        .with_context(|| format!("stat staged Ouro generation {}", path.display()))?
        .permissions()
        .readonly()
    {
        return Ok(());
    }
    drop(read_lease);

    let mut options = OpenOptions::new();
    options.read(true).write(true);
    options
        .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_WRITE_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options
        .open(path)
        .with_context(|| format!("open Ouro artifact to make readonly {}", path.display()))?;
    ensure_regular_artifact_metadata(
        &file
            .metadata()
            .with_context(|| format!("stat opened Ouro artifact {}", path.display()))?,
        path,
    )?;
    let mut permissions = file
        .metadata()
        .with_context(|| format!("stat published Ouro generation {}", path.display()))?
        .permissions();
    if permissions.readonly() {
        return Ok(());
    }
    file.sync_all().with_context(|| {
        format!(
            "durably flush Ouro artifact before readonly {}",
            path.display()
        )
    })?;
    permissions.set_readonly(true);
    file.set_permissions(permissions)
        .with_context(|| format!("make Ouro generation readonly {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("durably make Ouro generation readonly {}", path.display()))?;
    Ok(())
}

fn read_bounded_stream(file: &mut File, filename: &'static str) -> Result<Vec<u8>> {
    read_bounded_stream_with_limit(file, filename, MAX_OURO_METADATA_BYTES)
}

fn read_bounded_stream_with_limit(
    file: &mut File,
    filename: &'static str,
    limit: u64,
) -> Result<Vec<u8>> {
    let declared_len = file
        .metadata()
        .with_context(|| format!("stat Ouro metadata {filename}"))?
        .len();
    anyhow::ensure!(
        declared_len <= limit,
        "Ouro metadata {filename} exceeds {} byte limit",
        limit
    );
    let mut bytes = Vec::with_capacity(usize::try_from(declared_len).unwrap_or(0));
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read bounded Ouro metadata {filename}"))?;
    anyhow::ensure!(
        bytes.len() as u64 <= limit,
        "Ouro metadata {filename} grew beyond {} byte limit while reading",
        limit
    );
    Ok(bytes)
}

fn bounded_detail(error: &anyhow::Error) -> String {
    const MAX_CHARS: usize = 240;
    let detail = error.to_string();
    let mut bounded: String = detail.chars().take(MAX_CHARS).collect();
    if detail.chars().nth(MAX_CHARS).is_some() {
        bounded.push('…');
    }
    bounded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_fixture(dir: &Path) {
        tokenizers::Tokenizer::new(tokenizers::models::bpe::BPE::default())
            .save(dir.join(TOKENIZER_FILE), false)
            .expect("write tokenizer fixture");
        std::fs::write(
            dir.join(CONFIG_FILE),
            r#"{"vocab_size":32,"hidden_size":32,"intermediate_size":64,"num_hidden_layers":1,"num_attention_heads":1,"max_position_embeddings":32,"rope_theta":10000.0,"rms_norm_eps":0.00001,"model_type":"ouro"}"#,
        )
        .expect("write config fixture");
        let header = br#"{"tensor":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}"#;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(header.len() as u64).to_le_bytes());
        bytes.extend_from_slice(header);
        bytes.extend_from_slice(&[0_u8; 4]);
        std::fs::write(dir.join(SAFETENSORS_FILE), bytes).expect("write safetensors fixture");
    }

    fn write_tokenizer_with_id(dir: &Path, id: u32) {
        let vocab = [("outside".to_string(), id)].into_iter().collect();
        let model = tokenizers::models::bpe::BPE::builder()
            .vocab_and_merges(vocab, Vec::new())
            .build()
            .expect("build tokenizer fixture model");
        tokenizers::Tokenizer::new(model)
            .save(dir.join(TOKENIZER_FILE), false)
            .expect("write tokenizer fixture");
    }

    #[test]
    fn receipt_rejects_corrupt_or_pending_cache() {
        let dir = tempfile::tempdir().unwrap();
        write_fixture(dir.path());
        let receipt = receipt_for(
            "test/ouro",
            dir.path(),
            OuroQuantMode::Q8,
            "cpu",
            "Cpu".into(),
        )
        .expect("valid fixture receipt");
        assert_eq!(receipt.quant_mode, "q8");
        assert_eq!(receipt.artifacts.len(), 3);

        std::fs::write(dir.path().join("model.safetensors"), b"short").unwrap();
        let error = receipt_for(
            "test/ouro",
            dir.path(),
            OuroQuantMode::Q8,
            "cpu",
            "Cpu".into(),
        )
        .expect_err("truncated safetensors must never be ready");
        assert!(error.to_string().contains("not loadable"));

        write_fixture(dir.path());
        let mut pending = dir.path().as_os_str().to_os_string();
        pending.push(".download.pending.json");
        std::fs::write(pending, b"{}").unwrap();
        assert!(
            receipt_for(
                "test/ouro",
                dir.path(),
                OuroQuantMode::Q8,
                "cpu",
                "Cpu".into()
            )
            .is_err()
        );
    }

    #[test]
    fn receipt_changes_for_artifact_quant_or_resolved_accelerator() {
        let dir = tempfile::tempdir().unwrap();
        write_fixture(dir.path());
        let native = receipt_for(
            "test/ouro",
            dir.path(),
            OuroQuantMode::None,
            "cpu",
            "Cpu".into(),
        )
        .unwrap();
        let q8 = receipt_for(
            "test/ouro",
            dir.path(),
            OuroQuantMode::Q8,
            "cpu",
            "Cpu".into(),
        )
        .unwrap();
        assert_ne!(native, q8, "Q8 may not reuse a native loaded model");
        assert_ne!(native.summary(), q8.summary());

        std::fs::write(dir.path().join(CONFIG_FILE),
            r#"{"vocab_size":32,"hidden_size":32,"intermediate_size":64,"num_hidden_layers":1,"num_attention_heads":1,"max_position_embeddings":64,"rope_theta":10000.0,"rms_norm_eps":0.00001,"model_type":"ouro"}"#).unwrap();
        let mutated = receipt_for(
            "test/ouro",
            dir.path(),
            OuroQuantMode::None,
            "cpu",
            "Cpu".into(),
        )
        .unwrap();
        assert_ne!(
            native, mutated,
            "changed runtime bytes invalidate the receipt"
        );
        let other_device = receipt_for(
            "test/ouro",
            dir.path(),
            OuroQuantMode::None,
            "cuda",
            "Cuda(0)".into(),
        )
        .unwrap();
        assert_ne!(
            mutated, other_device,
            "resolved accelerator is load identity"
        );
    }

    #[test]
    fn public_cache_status_is_bounded_and_never_calls_corrupt_ready() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(CONFIG_FILE), "x".repeat(300)).unwrap();
        let status = runtime_cache_status(dir.path());
        assert_eq!(status.state, "not_ready");
        assert!(status.detail.unwrap().chars().count() <= 241);

        let bounded = bounded_detail(&anyhow::anyhow!("{}", "x".repeat(300)));
        assert_eq!(bounded.chars().count(), 241);
        assert!(bounded.ends_with('…'));

        write_fixture(dir.path());
        let status = runtime_cache_status(dir.path());
        assert_eq!(status.state, "ready");
        assert!(status.detail.is_none());
    }

    #[test]
    fn tokenizer_ids_must_fit_the_ouro_config_vocab() {
        let dir = tempfile::tempdir().unwrap();
        write_fixture(dir.path());
        write_tokenizer_with_id(dir.path(), 32);
        let error = validate_runtime_artifacts_at(dir.path(), false)
            .expect_err("id equal to vocab_size is outside the embedding table");
        assert!(error.to_string().contains("maximum id 32"));

        write_tokenizer_with_id(dir.path(), 31);
        validate_runtime_artifacts_at(dir.path(), false)
            .expect("largest valid token id remains inside config vocab_size");
    }

    #[test]
    fn metadata_stream_cap_rejects_oversize_before_parser_input() {
        let dir = tempfile::tempdir().unwrap();
        let metadata = dir.path().join(CONFIG_FILE);
        std::fs::write(&metadata, b"0123456789abcdef!").unwrap();
        let mut file = File::open(&metadata).unwrap();
        let error = read_bounded_stream_with_limit(&mut file, CONFIG_FILE, 16)
            .expect_err("streamed metadata beyond its cap must not reach a parser");
        assert!(error.to_string().contains("exceeds 16 byte limit"));
    }

    #[test]
    fn load_lease_rejects_a_path_swap_after_receipt_creation() {
        let dir = tempfile::tempdir().unwrap();
        write_fixture(dir.path());
        let receipt = receipt_for(
            "test/ouro",
            dir.path(),
            OuroQuantMode::None,
            "cpu",
            "Cpu".into(),
        )
        .unwrap();
        // Preserve safetensors structure and length while changing the bytes a
        // path-based mmap would otherwise reopen after the old hash.
        let weights = dir.path().join(SAFETENSORS_FILE);
        let mut bytes = std::fs::read(&weights).unwrap();
        *bytes.last_mut().unwrap() = 9;
        std::fs::write(weights, bytes).unwrap();
        assert!(OuroLoadLease::open(dir.path(), &receipt).is_err());
    }

    #[test]
    fn immutable_generation_rejects_tamper_and_incomplete_promotion() {
        let dir = tempfile::tempdir().unwrap();
        write_fixture(dir.path());
        let generation = resolve_or_promote_generation(dir.path()).unwrap();
        assert!(!dir.path().join(SAFETENSORS_FILE).exists());
        assert_eq!(
            active_generation_dir(dir.path()).unwrap(),
            Some(generation.clone())
        );

        // A content-addressed name is verified on every resolve, not trusted.
        let weights = generation.join(SAFETENSORS_FILE);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mut permissions = std::fs::metadata(&weights).unwrap().permissions();
            permissions.set_mode(permissions.mode() | 0o200);
            std::fs::set_permissions(&weights, permissions).unwrap();
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt as _;
            use std::os::windows::fs::MetadataExt as _;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY, SetFileAttributesW,
            };
            let attributes =
                std::fs::metadata(&weights).unwrap().file_attributes() & !FILE_ATTRIBUTE_READONLY;
            let attributes = if attributes == 0 {
                FILE_ATTRIBUTE_NORMAL
            } else {
                attributes
            };
            let path: Vec<u16> = weights.as_os_str().encode_wide().chain(Some(0)).collect();
            // SAFETY: this test owns the regular fixture and the terminated path
            // stays alive for the synchronous Windows attribute update.
            assert_ne!(unsafe { SetFileAttributesW(path.as_ptr(), attributes) }, 0);
        }
        let mut bytes = std::fs::read(&weights).unwrap();
        *bytes.last_mut().unwrap() = 11;
        std::fs::write(&weights, bytes).unwrap();
        assert!(active_generation_dir(dir.path()).is_err());

        let interrupted = tempfile::tempdir().unwrap();
        write_fixture(interrupted.path());
        std::fs::write(
            interrupted.path().join(GENERATION_PENDING_FILE),
            br#"{"version":1,"generation":"0000000000000000000000000000000000000000000000000000000000000000"}"#,
        )
        .unwrap();
        assert!(resolve_or_promote_generation(interrupted.path()).is_err());
        assert!(interrupted.path().join(SAFETENSORS_FILE).exists());
    }

    #[test]
    fn immutable_generation_recovers_one_verified_orphan_without_download() {
        let dir = tempfile::tempdir().unwrap();
        write_fixture(dir.path());
        let generation = resolve_or_promote_generation(dir.path()).unwrap();
        let pointer = dir.path().join(ACTIVE_GENERATION_FILE);
        crate::util::atomic_write::durable_remove_file(&pointer).unwrap();

        let recovered = resolve_existing_generation(dir.path())
            .expect("one exact orphan is recoverable")
            .expect("generation remains available");
        assert_eq!(recovered, generation);
        assert_eq!(active_generation_dir(dir.path()).unwrap(), Some(generation));
        assert!(
            !dir.path().join(SAFETENSORS_FILE).exists(),
            "recovery must not recreate mutable canonical artifacts"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_promotion_and_readonly_retry_preserve_artifact_bytes() {
        let dir = tempfile::tempdir().unwrap();
        write_fixture(dir.path());
        let generation = resolve_or_promote_generation(dir.path()).unwrap();
        for artifact in &REQUIRED_ARTIFACTS {
            let path = generation.join(artifact.filename);
            let expected = std::fs::read(&path).unwrap();
            make_artifact_readonly(&path).expect("retry accepts readonly staged artifact");
            assert_eq!(std::fs::read(&path).unwrap(), expected);
            assert!(std::fs::metadata(&path).unwrap().permissions().readonly());
        }
    }

    #[cfg(unix)]
    #[test]
    fn orphan_generation_rejects_artifact_symlink_before_external_digest() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        write_fixture(dir.path());
        let generation = resolve_or_promote_generation(dir.path()).unwrap();
        crate::util::atomic_write::durable_remove_file(&dir.path().join(ACTIVE_GENERATION_FILE))
            .unwrap();
        let weights = generation.join(SAFETENSORS_FILE);
        std::fs::remove_file(&weights).unwrap();
        let external = dir.path().join("external.safetensors");
        std::fs::write(&external, b"external bytes must never be digested").unwrap();
        symlink(&external, &weights).unwrap();

        let link_metadata = std::fs::symlink_metadata(&weights).unwrap();
        assert!(
            link_metadata.file_type().is_symlink(),
            "fixture must replace the retained artifact with a symlink"
        );
        let direct_error = ensure_regular_artifact_path(&weights)
            .expect_err("the no-follow artifact boundary must reject the symlink before a digest");
        assert!(
            direct_error.to_string().contains("regular file"),
            "unexpected direct no-follow error: {direct_error:#}"
        );

        let error = resolve_existing_generation(dir.path())
            .expect_err("orphan artifact symlink must not be adopted");
        assert!(
            error
                .chain()
                .any(|cause| cause.to_string().contains("regular file")),
            "orphan adoption must preserve its rejected-artifact cause: {error:#}"
        );
    }
}
