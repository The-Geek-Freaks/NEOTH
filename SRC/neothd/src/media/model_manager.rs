//! Canonical model-artifact installation and cache validation.
//!
//! `hf-hub` remains the only network downloader. It owns HTTP range resume,
//! its blob lock, and the atomic commit into the Hugging Face cache. This
//! module owns the second boundary NEOTH needs: materialising a downloaded HF
//! blob into a runtime cache without ever exposing a partial final file.

use std::io::{Read, Seek};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const COPY_BUFFER_BYTES: usize = 256 * 1024;
const MAX_SAFETENSORS_HEADER_BYTES: u64 = 100_000_000;
const INSTALLING_MARKER: &str = ".neoth-installing";
const DOWNLOAD_PENDING_SUFFIX: &str = "download.pending.json";
const MODEL_LOCK_RETRY: std::time::Duration = std::time::Duration::from_millis(50);
static SIDECAR_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static DOWNLOAD_ATTEMPT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

type ProcessModelLocks = std::collections::HashMap<PathBuf, Weak<tokio::sync::Mutex<()>>>;

static PROCESS_MODEL_LOCKS: OnceLock<std::sync::Mutex<ProcessModelLocks>> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CacheHealth {
    Ready,
    Missing { path: PathBuf },
    Corrupt { path: PathBuf, reason: String },
}

impl CacheHealth {
    pub(crate) const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready)
    }

    pub(crate) const fn label(&self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Missing { .. } => "missing",
            Self::Corrupt { .. } => "corrupt",
        }
    }
}

impl std::fmt::Display for CacheHealth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ready => formatter.write_str("ready"),
            Self::Missing { path } => write!(formatter, "missing `{}`", path.display()),
            Self::Corrupt { path, reason } => {
                write!(formatter, "corrupt `{}`: {reason}", path.display())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArtifactKind {
    JsonObject,
    Safetensors,
    NonEmpty { minimum_bytes: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RequiredArtifact {
    pub(crate) filename: &'static str,
    pub(crate) kind: ArtifactKind,
    /// Immutable upstream fingerprint for the pinned model revision. Cache
    /// status uses the length as a cheap corruption check; download commit and
    /// backend-ready validation verify the full SHA-256.
    pub(crate) expected: Option<ExpectedArtifactFingerprint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExpectedArtifactFingerprint {
    pub(crate) len: u64,
    pub(crate) sha256: &'static str,
}

impl ExpectedArtifactFingerprint {
    fn to_owned(self) -> ArtifactFingerprint {
        ArtifactFingerprint {
            len: self.len,
            sha256: self.sha256.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArtifactFingerprint {
    pub(crate) len: u64,
    pub(crate) sha256: String,
}

/// Validate every required runtime artifact without reading model weights into
/// memory. JSON files must contain an object, safetensors must have a valid
/// header whose declared tensor span exactly matches the file length, and
/// opaque backend files must meet their explicit minimum size.
pub(crate) fn cache_health(root: &Path, required: &[RequiredArtifact]) -> CacheHealth {
    cache_health_inner(root, required, false)
}

/// Validate a generation while its durable download lifecycle owns the model
/// lock. Callers outside [`ModelDownloadAttempt`] must use [`cache_health`].
pub(crate) fn cache_health_during_install(
    root: &Path,
    required: &[RequiredArtifact],
) -> CacheHealth {
    cache_health_inner(root, required, true)
}

fn cache_health_inner(
    root: &Path,
    required: &[RequiredArtifact],
    allow_installing: bool,
) -> CacheHealth {
    let pending = pending_path(root);
    if !allow_installing && pending.exists() {
        return CacheHealth::Corrupt {
            path: pending,
            reason: "model download has an unterminated D7/D8 lifecycle; retry the pull to recover"
                .to_string(),
        };
    }
    if !root.is_dir() {
        return CacheHealth::Missing {
            path: root.to_path_buf(),
        };
    }
    let installing = root.join(INSTALLING_MARKER);
    if !allow_installing && installing.exists() {
        return CacheHealth::Corrupt {
            path: installing,
            reason: "model generation is incomplete; retry the pull to recover".to_string(),
        };
    }

    for artifact in required {
        let path = root.join(artifact.filename);
        if !path.is_file() {
            return CacheHealth::Missing { path };
        }
        if let Err(error) = validate_artifact(&path, artifact.kind) {
            return CacheHealth::Corrupt {
                path,
                reason: format!("{error:#}"),
            };
        }
        if let Some(expected) = artifact.expected {
            let actual_len = match std::fs::metadata(&path) {
                Ok(metadata) => metadata.len(),
                Err(error) => {
                    return CacheHealth::Corrupt {
                        path,
                        reason: format!("cannot stat artifact: {error}"),
                    };
                }
            };
            if actual_len != expected.len {
                return CacheHealth::Corrupt {
                    path,
                    reason: format!(
                        "artifact length mismatch: expected {}, found {actual_len}",
                        expected.len
                    ),
                };
            }
        }
    }
    CacheHealth::Ready
}

/// Audit destination for the central D7/D8 lifecycle. WAL-backed runtime
/// callers use the blanket implementation below; the CLI also implements this
/// for its daemon-RPC sink.
#[async_trait::async_trait]
pub(crate) trait ModelDownloadAuditSink: Send + Sync {
    async fn append_model_download(&self, event_type: u8, payload: Vec<u8>) -> Result<()>;
}

#[async_trait::async_trait]
impl ModelDownloadAuditSink for crate::wal::writer::WalWriterHandle {
    async fn append_model_download(&self, event_type: u8, payload: Vec<u8>) -> Result<()> {
        let header = crate::wal::make_header(event_type, &payload);
        self.append(header, payload)
            .await
            .map(|_| ())
            .context("append model-download audit event")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PendingModelDownloadOutcome {
    Ready,
    Failed { reason: String },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PendingModelDownload {
    version: u8,
    model_id: String,
    attempt_id: String,
    #[serde(default)]
    attempt_sha256: String,
    trigger: String,
    started_unix_ns: u64,
    d7_emitted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    outcome: Option<PendingOutcomeRecord>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum PendingOutcomeRecord {
    Ready {
        cached_path: String,
        duration_ms: u64,
    },
    Failed {
        reason: String,
        duration_ms: u64,
    },
}

/// Process-global plus OS-wide exclusive model lock. The process tier prevents
/// duplicate first-use work across independently-created provider instances;
/// the file tier covers CLI/daemon and multi-process races. Unlike the generic
/// config lock, this intentionally waits for long model loads/downloads.
pub(crate) struct ModelCacheGuard {
    _process: tokio::sync::OwnedMutexGuard<()>,
    _os: std::fs::File,
}

/// Durable, replayable D7/D8 transaction for one model cache. The pending
/// record is written before D7, marked network-authorised only after D7 is
/// durably accepted, and retained until a terminal D8 is durably accepted.
/// A crash may duplicate an event on replay, but the stable `attempt_id` makes
/// that at-least-once delivery unambiguous and never permits unaudited network.
pub(crate) struct ModelDownloadAttempt {
    root: PathBuf,
    model_id: String,
    trigger: String,
    pending: Option<PendingModelDownload>,
    _guard: ModelCacheGuard,
}

/// Unforgeable capability for one exact, durably-audited network attempt.
/// Network-capable model loaders accept this value instead of a boolean so a
/// caller cannot accidentally continue after a failed D7 append.
#[derive(Debug)]
pub(crate) struct ModelDownloadPermit {
    root: PathBuf,
    model_id: String,
    attempt_id: String,
    attempt_sha256: String,
}

impl ModelDownloadPermit {
    /// Refuse reuse for another cache, model, attempt, or a tampered binding.
    pub(crate) fn require(&self, root: &Path, model_id: &str) -> Result<()> {
        let expected = model_download_attempt_sha256(root, model_id, &self.attempt_id);
        if self.root != root || self.model_id != model_id || self.attempt_sha256 != expected {
            bail!(
                "model-download permit {} is not valid for `{model_id}` at {}",
                self.attempt_id,
                root.display()
            );
        }
        Ok(())
    }
}

impl ModelDownloadAttempt {
    pub(crate) async fn acquire(root: &Path, model_id: &str, trigger: &str) -> Result<Self> {
        let guard = lock_model_cache(root).await?;
        let mut pending = read_pending(root)?;
        let mut migrated = false;
        if let Some(pending) = pending.as_mut() {
            if pending.model_id != model_id {
                bail!(
                    "model cache {} has pending attempt {} for `{}`, not `{model_id}`",
                    root.display(),
                    pending.attempt_id,
                    pending.model_id
                );
            }
            if !matches!(pending.version, 1 | 2) {
                bail!(
                    "unsupported model-download pending version {} for attempt {}",
                    pending.version,
                    pending.attempt_id
                );
            }
            let expected = model_download_attempt_sha256(root, model_id, &pending.attempt_id);
            if pending.attempt_sha256.is_empty() {
                pending.version = 2;
                pending.attempt_sha256 = expected;
                migrated = true;
            } else if pending.attempt_sha256 != expected {
                bail!(
                    "model-download pending attempt {} has an invalid cache/model binding",
                    pending.attempt_id
                );
            }
        }
        let attempt = Self {
            root: root.to_path_buf(),
            model_id: model_id.to_string(),
            trigger: trigger.to_string(),
            pending,
            _guard: guard,
        };
        if migrated {
            attempt.persist()?;
        }
        Ok(attempt)
    }

    pub(crate) fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    #[cfg(test)]
    pub(crate) fn attempt_id(&self) -> Option<&str> {
        self.pending
            .as_ref()
            .map(|pending| pending.attempt_id.as_str())
    }

    pub(crate) fn pending_outcome(&self) -> Option<PendingModelDownloadOutcome> {
        match self.pending.as_ref()?.outcome.as_ref()? {
            PendingOutcomeRecord::Ready { .. } => Some(PendingModelDownloadOutcome::Ready),
            PendingOutcomeRecord::Failed { reason, .. } => {
                Some(PendingModelDownloadOutcome::Failed {
                    reason: reason.clone(),
                })
            }
        }
    }

    pub(crate) fn network_authorized(&self, root: &Path, model_id: &str) -> bool {
        root == self.root
            && model_id == self.model_id
            && self.pending.as_ref().is_some_and(|pending| {
                pending.attempt_sha256
                    == model_download_attempt_sha256(root, model_id, &pending.attempt_id)
            })
            && matches!(
                self.pending.as_ref(),
                Some(PendingModelDownload {
                    d7_emitted: true,
                    outcome: None,
                    ..
                })
            )
    }

    /// Durably append D7 and mint a capability bound to this exact attempt.
    /// No permit exists on any error path.
    pub(crate) async fn authorize_network(
        &mut self,
        sink: &dyn ModelDownloadAuditSink,
    ) -> Result<ModelDownloadPermit> {
        self.ensure_started(sink).await?;
        let pending = self
            .pending
            .as_ref()
            .context("D7 produced no pending attempt")?;
        if !self.network_authorized(&self.root, &self.model_id) {
            bail!(
                "model-download attempt {} was not durably authorized",
                pending.attempt_id
            );
        }
        Ok(ModelDownloadPermit {
            root: self.root.clone(),
            model_id: self.model_id.clone(),
            attempt_id: pending.attempt_id.clone(),
            attempt_sha256: pending.attempt_sha256.clone(),
        })
    }

    /// Ensure D7 exists and create/refresh the install marker. This is the
    /// only transition that authorises a network-capable model loader.
    pub(crate) async fn ensure_started(&mut self, sink: &dyn ModelDownloadAuditSink) -> Result<()> {
        if self.pending.is_none() {
            let sequence = DOWNLOAD_ATTEMPT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let attempt_id = format!(
                "{:016x}-{:08x}-{:016x}",
                crate::time::now_unix_ns(),
                std::process::id(),
                sequence
            );
            self.pending = Some(PendingModelDownload {
                version: 2,
                model_id: self.model_id.clone(),
                attempt_sha256: model_download_attempt_sha256(
                    &self.root,
                    &self.model_id,
                    &attempt_id,
                ),
                attempt_id,
                trigger: self.trigger.clone(),
                started_unix_ns: crate::time::now_unix_ns(),
                d7_emitted: false,
                outcome: None,
            });
            self.persist()?;
        }
        let pending = self.pending.as_ref().expect("pending created above");
        if pending.outcome.is_some() {
            bail!(
                "model download attempt {} already has a terminal outcome awaiting D8 replay",
                pending.attempt_id
            );
        }
        if !pending.d7_emitted {
            let payload = serde_json::to_vec(&serde_json::json!({
                "attempt_id": pending.attempt_id,
                "attempt_sha256": pending.attempt_sha256,
                "model_id": pending.model_id,
                "status": "started",
                "ts_unix": pending.started_unix_ns / 1_000_000_000,
                "trigger": pending.trigger,
            }))
            .context("serialize MODEL_DOWNLOAD_START payload")?;
            sink.append_model_download(
                crate::wal::events::EVENT_TYPE_MODEL_DOWNLOAD_START,
                payload,
            )
            .await?;
            self.pending.as_mut().expect("pending exists").d7_emitted = true;
            self.persist()?;
        }
        self.write_installing_marker()?;
        Ok(())
    }

    pub(crate) async fn finish_ready(
        &mut self,
        sink: &dyn ModelDownloadAuditSink,
        cached_path: &Path,
    ) -> Result<()> {
        self.require_started()?;
        let duration_ms = self.duration_ms();
        self.pending
            .as_mut()
            .expect("pending checked above")
            .outcome = Some(PendingOutcomeRecord::Ready {
            cached_path: cached_path.to_string_lossy().into_owned(),
            duration_ms,
        });
        self.persist()?;
        self.replay_terminal(sink).await.map(|_| ())
    }

    pub(crate) async fn finish_failed(
        &mut self,
        sink: &dyn ModelDownloadAuditSink,
        reason: &str,
    ) -> Result<()> {
        self.require_started()?;
        let duration_ms = self.duration_ms();
        self.pending
            .as_mut()
            .expect("pending checked above")
            .outcome = Some(PendingOutcomeRecord::Failed {
            reason: reason.chars().take(512).collect(),
            duration_ms,
        });
        self.persist()?;
        self.replay_terminal(sink).await.map(|_| ())
    }

    pub(crate) async fn replay_terminal(
        &mut self,
        sink: &dyn ModelDownloadAuditSink,
    ) -> Result<PendingModelDownloadOutcome> {
        let pending = self
            .pending
            .as_ref()
            .context("no pending model-download attempt")?;
        if !pending.d7_emitted {
            bail!(
                "pending model-download attempt {} has no confirmed D7",
                pending.attempt_id
            );
        }
        let outcome = pending
            .outcome
            .as_ref()
            .context("pending model-download attempt has no terminal outcome")?;
        let (view, payload) = match outcome {
            PendingOutcomeRecord::Ready {
                cached_path,
                duration_ms,
            } => (
                PendingModelDownloadOutcome::Ready,
                serde_json::json!({
                    "attempt_id": pending.attempt_id,
                    "attempt_sha256": pending.attempt_sha256,
                    "model_id": pending.model_id,
                    "cached_path": cached_path,
                    "duration_ms": duration_ms,
                    "status": "ready",
                    "ts_unix": crate::time::now_unix_secs(),
                    "trigger": pending.trigger,
                }),
            ),
            PendingOutcomeRecord::Failed {
                reason,
                duration_ms,
            } => (
                PendingModelDownloadOutcome::Failed {
                    reason: reason.clone(),
                },
                serde_json::json!({
                    "attempt_id": pending.attempt_id,
                    "attempt_sha256": pending.attempt_sha256,
                    "model_id": pending.model_id,
                    "duration_ms": duration_ms,
                    "reason": reason,
                    "status": "failed",
                    "ts_unix": crate::time::now_unix_secs(),
                    "trigger": pending.trigger,
                }),
            ),
        };
        let payload =
            serde_json::to_vec(&payload).context("serialize MODEL_DOWNLOAD_COMPLETE payload")?;
        sink.append_model_download(
            crate::wal::events::EVENT_TYPE_MODEL_DOWNLOAD_COMPLETE,
            payload,
        )
        .await?;

        // Clear the marker first. If cleanup crashes between the two removes,
        // the still-durable pending record forces an idempotent D8 replay.
        remove_if_exists(&self.root.join(INSTALLING_MARKER), "model install marker")?;
        remove_if_exists(&pending_path(&self.root), "model download pending state")?;
        self.pending = None;
        Ok(view)
    }

    fn require_started(&self) -> Result<()> {
        match self.pending.as_ref() {
            Some(pending) if pending.d7_emitted => Ok(()),
            Some(pending) => bail!(
                "model download attempt {} cannot finish before D7 succeeds",
                pending.attempt_id
            ),
            None => bail!("model download cannot finish without a pending attempt"),
        }
    }

    fn duration_ms(&self) -> u64 {
        self.pending
            .as_ref()
            .map(|pending| {
                crate::time::now_unix_ns().saturating_sub(pending.started_unix_ns) / 1_000_000
            })
            .unwrap_or(0)
    }

    fn persist(&self) -> Result<()> {
        let pending = self
            .pending
            .as_ref()
            .context("no pending state to persist")?;
        let path = pending_path(&self.root);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create model pending directory {}", parent.display()))?;
        }
        let body = serde_json::to_vec_pretty(pending)
            .context("serialize durable model-download pending state")?;
        crate::util::atomic_write::atomic_write(&path, &body)
            .with_context(|| format!("write model pending state {}", path.display()))?;
        sync_parent_directory(&path);
        Ok(())
    }

    fn write_installing_marker(&self) -> Result<()> {
        let pending = self.pending.as_ref().context("no pending model attempt")?;
        std::fs::create_dir_all(&self.root)
            .with_context(|| format!("create model cache directory {}", self.root.display()))?;
        let marker = self.root.join(INSTALLING_MARKER);
        let body = format!(
            "attempt_id={}\npid={}\nstarted_unix={}\n",
            pending.attempt_id,
            std::process::id(),
            pending.started_unix_ns / 1_000_000_000
        );
        crate::util::atomic_write::atomic_write(&marker, body.as_bytes())
            .with_context(|| format!("write model install marker {}", marker.display()))?;
        sync_parent_directory(&marker);
        Ok(())
    }
}

pub(crate) fn has_pending_download(root: &Path) -> Result<bool> {
    Ok(read_pending(root)?.is_some())
}

pub(crate) async fn lock_model_cache(root: &Path) -> Result<ModelCacheGuard> {
    let root = lock_key(root)?;
    let process = process_model_mutex(&root).lock_owned().await;
    let os = lock_model_os(&root).await?;
    Ok(ModelCacheGuard {
        _process: process,
        _os: os,
    })
}

pub(crate) fn lock_model_cache_blocking(root: &Path) -> Result<ModelCacheGuard> {
    let root = lock_key(root)?;
    let mutex = process_model_mutex(&root);
    let process = loop {
        match Arc::clone(&mutex).try_lock_owned() {
            Ok(guard) => break guard,
            Err(_) => std::thread::sleep(MODEL_LOCK_RETRY),
        }
    };
    let lock_path = sibling_path(&root, "install.lock");
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create model lock directory {}", parent.display()))?;
    }
    let os = loop {
        match crate::util::locked_file::try_lock_file_once(&lock_path, "model generation")? {
            Some(file) => break file,
            None => std::thread::sleep(MODEL_LOCK_RETRY),
        }
    };
    Ok(ModelCacheGuard {
        _process: process,
        _os: os,
    })
}

async fn lock_model_os(root: &Path) -> Result<std::fs::File> {
    let lock_path = sibling_path(root, "install.lock");
    if let Some(parent) = lock_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create model lock directory {}", parent.display()))?;
    }
    loop {
        match crate::util::locked_file::try_lock_file_once(&lock_path, "model generation")? {
            Some(file) => return Ok(file),
            None => tokio::time::sleep(MODEL_LOCK_RETRY).await,
        }
    }
}

fn process_model_mutex(root: &Path) -> Arc<tokio::sync::Mutex<()>> {
    let locks =
        PROCESS_MODEL_LOCKS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut locks = locks
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    locks.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = locks.get(root).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    locks.insert(root.to_path_buf(), Arc::downgrade(&lock));
    lock
}

fn lock_key(root: &Path) -> Result<PathBuf> {
    if root.is_absolute() {
        Ok(root.to_path_buf())
    } else {
        Ok(std::env::current_dir()
            .context("resolve current directory for model lock")?
            .join(root))
    }
}

fn pending_path(root: &Path) -> PathBuf {
    sibling_path(root, DOWNLOAD_PENDING_SUFFIX)
}

fn model_download_attempt_sha256(root: &Path, model_id: &str, attempt_id: &str) -> String {
    let root = root.to_string_lossy();
    let mut hasher = Sha256::new();
    hasher.update(b"neoth-model-download-attempt-v1\0");
    for value in [root.as_bytes(), model_id.as_bytes(), attempt_id.as_bytes()] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }
    hex::encode(hasher.finalize())
}

fn read_pending(root: &Path) -> Result<Option<PendingModelDownload>> {
    let path = pending_path(root);
    let body = match std::fs::read(&path) {
        Ok(body) => body,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("read model pending state {}", path.display()));
        }
    };
    let pending = serde_json::from_slice(&body)
        .with_context(|| format!("parse model pending state {}", path.display()))?;
    Ok(Some(pending))
}

fn remove_if_exists(path: &Path, what: &str) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {
            sync_parent_directory(path);
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("clear {what} {}", path.display())),
    }
}

/// Full integrity validation for a pinned model generation. This is
/// intentionally separate from [`cache_health`]: status/doctor surfaces must
/// not hash multi-gigabyte weights, while a download completion or first model
/// load must prove every byte against the reviewed upstream manifest.
pub(crate) fn verified_cache_health(root: &Path, required: &[RequiredArtifact]) -> CacheHealth {
    verified_cache_health_inner(root, required, false)
}

pub(crate) fn verified_cache_health_during_install(
    root: &Path,
    required: &[RequiredArtifact],
) -> CacheHealth {
    verified_cache_health_inner(root, required, true)
}

fn verified_cache_health_inner(
    root: &Path,
    required: &[RequiredArtifact],
    allow_installing: bool,
) -> CacheHealth {
    let health = cache_health_inner(root, required, allow_installing);
    if !health.is_ready() {
        return health;
    }
    for artifact in required {
        let Some(expected) = artifact.expected else {
            return CacheHealth::Corrupt {
                path: root.join(artifact.filename),
                reason: "artifact has no pinned SHA-256 manifest entry".to_string(),
            };
        };
        let path = root.join(artifact.filename);
        match fingerprint_file_sync(&path) {
            Ok(actual) if actual == expected.to_owned() => {}
            Ok(actual) => {
                return CacheHealth::Corrupt {
                    path,
                    reason: format!(
                        "artifact fingerprint mismatch: expected {:?}, found {actual:?}",
                        expected.to_owned()
                    ),
                };
            }
            Err(error) => {
                return CacheHealth::Corrupt {
                    path,
                    reason: format!("{error:#}"),
                };
            }
        }
    }
    CacheHealth::Ready
}

fn validate_artifact(path: &Path, kind: ArtifactKind) -> Result<()> {
    match kind {
        ArtifactKind::JsonObject => {
            let reader = std::io::BufReader::new(
                std::fs::File::open(path)
                    .with_context(|| format!("open JSON artifact {}", path.display()))?,
            );
            let value: serde_json::Value = serde_json::from_reader(reader)
                .with_context(|| format!("parse JSON artifact {}", path.display()))?;
            if !value.is_object() {
                bail!("top-level JSON value is not an object");
            }
            Ok(())
        }
        ArtifactKind::Safetensors => validate_safetensors(path),
        ArtifactKind::NonEmpty { minimum_bytes } => {
            let len = std::fs::metadata(path)
                .with_context(|| format!("stat artifact {}", path.display()))?
                .len();
            if len < minimum_bytes {
                bail!("expected at least {minimum_bytes} bytes, found {len}");
            }
            Ok(())
        }
    }
}

fn validate_safetensors(path: &Path) -> Result<()> {
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("open safetensors artifact {}", path.display()))?;
    let file_len = file
        .metadata()
        .with_context(|| format!("stat safetensors artifact {}", path.display()))?
        .len();
    let mut length_bytes = [0_u8; 8];
    file.read_exact(&mut length_bytes)
        .with_context(|| format!("read safetensors header length from {}", path.display()))?;
    let header_len = u64::from_le_bytes(length_bytes);
    if header_len == 0 || header_len > MAX_SAFETENSORS_HEADER_BYTES {
        bail!("invalid safetensors header length {header_len}");
    }
    let header_len_usize = usize::try_from(header_len).context("safetensors header too large")?;
    let mut header = vec![0_u8; header_len_usize];
    file.read_exact(&mut header)
        .with_context(|| format!("read safetensors header from {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_slice(&header)
        .with_context(|| format!("parse safetensors header from {}", path.display()))?;
    let tensors = value
        .as_object()
        .context("safetensors header is not a JSON object")?;
    let mut spans = Vec::new();
    let mut tensor_count = 0_usize;
    for (name, tensor) in tensors {
        if name == "__metadata__" {
            continue;
        }
        let tensor = tensor
            .as_object()
            .with_context(|| format!("tensor `{name}` metadata is not an object"))?;
        let offsets = tensor
            .get("data_offsets")
            .and_then(serde_json::Value::as_array)
            .with_context(|| format!("tensor `{name}` has no data_offsets"))?;
        if offsets.len() != 2 {
            bail!("tensor `{name}` data_offsets must have two values");
        }
        let start = offsets[0]
            .as_u64()
            .with_context(|| format!("tensor `{name}` start offset is invalid"))?;
        let end = offsets[1]
            .as_u64()
            .with_context(|| format!("tensor `{name}` end offset is invalid"))?;
        if start > end {
            bail!("tensor `{name}` has reversed offsets");
        }
        spans.push((start, end, name.as_str()));
        tensor_count += 1;
    }
    if tensor_count == 0 {
        bail!("safetensors header contains no tensors");
    }
    // JSON object iteration order is not a safetensors invariant. Validate the
    // byte ranges after sorting by their declared start offset so a valid file
    // cannot be rejected solely because its serializer reordered keys.
    // Sorting by end as well keeps valid zero-length tensors before a
    // non-empty tensor that starts at the same byte offset.
    spans.sort_unstable_by_key(|(start, end, _)| (*start, *end));
    let mut data_end = 0_u64;
    for (start, end, name) in spans {
        if start != data_end {
            let issue = if start < data_end { "overlap" } else { "gap" };
            bail!("tensor `{name}` has a data {issue}: expected offset {data_end}, found {start}");
        }
        data_end = end;
    }
    let expected_len = 8_u64
        .checked_add(header_len)
        .and_then(|prefix| prefix.checked_add(data_end))
        .context("safetensors declared length overflow")?;
    if expected_len != file_len {
        bail!("declared length {expected_len} does not match file length {file_len}");
    }
    // Assert that the header read left the cursor exactly at the data section.
    let cursor = file
        .stream_position()
        .with_context(|| format!("read cursor for {}", path.display()))?;
    if cursor != 8 + header_len {
        bail!("safetensors header cursor mismatch");
    }
    Ok(())
}

/// Materialise an artifact already committed by `hf-hub` into NEOTH's runtime
/// cache. The final path is never opened for writing. Bytes are streamed into a
/// unique sibling part file, flushed and synced, re-read for SHA-256/length
/// equality, and only then atomically renamed into place.
pub(crate) async fn install_from_hf_source(
    source: &Path,
    destination: &Path,
    expected: &ArtifactFingerprint,
) -> Result<ArtifactFingerprint> {
    let (part, source_fingerprint) = copy_to_unique_part(source, destination).await?;
    if source_fingerprint != *expected {
        if part != source {
            let _ = tokio::fs::remove_file(&part).await;
        }
        bail!(
            "upstream model artifact fingerprint mismatch for {}: expected {:?}, got {:?}",
            source.display(),
            expected,
            source_fingerprint
        );
    }
    commit_verified_part(&part, destination, &source_fingerprint).await?;
    Ok(source_fingerprint)
}

async fn copy_to_unique_part(
    source: &Path,
    destination: &Path,
) -> Result<(PathBuf, ArtifactFingerprint)> {
    if source == destination {
        return Ok((source.to_path_buf(), fingerprint_file(source).await?));
    }
    let parent = destination
        .parent()
        .with_context(|| format!("model destination has no parent: {}", destination.display()))?;
    tokio::fs::create_dir_all(parent)
        .await
        .with_context(|| format!("create model cache directory {}", parent.display()))?;

    let part = unique_sidecar_path(destination, "part");
    let mut input = tokio::fs::File::open(source)
        .await
        .with_context(|| format!("open HF artifact {}", source.display()))?;
    let mut output = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&part)
        .await
        .with_context(|| format!("create model part {}", part.display()))?;
    let mut hasher = Sha256::new();
    let mut len = 0_u64;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let copy_result: Result<()> = async {
        loop {
            let read = input
                .read(&mut buffer)
                .await
                .with_context(|| format!("read HF artifact {}", source.display()))?;
            if read == 0 {
                break;
            }
            output
                .write_all(&buffer[..read])
                .await
                .with_context(|| format!("write model part {}", part.display()))?;
            hasher.update(&buffer[..read]);
            len = len
                .checked_add(read as u64)
                .context("model artifact length overflow")?;
        }
        output
            .flush()
            .await
            .with_context(|| format!("flush model part {}", part.display()))?;
        output
            .sync_all()
            .await
            .with_context(|| format!("sync model part {}", part.display()))?;
        Ok(())
    }
    .await;
    drop(output);
    if let Err(error) = copy_result {
        let _ = tokio::fs::remove_file(&part).await;
        return Err(error);
    }

    let expected = ArtifactFingerprint {
        len,
        sha256: hex::encode(hasher.finalize()),
    };
    let on_disk = match fingerprint_file(&part).await {
        Ok(fingerprint) => fingerprint,
        Err(error) => {
            let _ = tokio::fs::remove_file(&part).await;
            return Err(error);
        }
    };
    if on_disk != expected {
        let _ = tokio::fs::remove_file(&part).await;
        bail!(
            "model part verification failed for {}: expected {:?}, got {:?}",
            part.display(),
            expected,
            on_disk
        );
    }
    Ok((part, expected))
}

async fn commit_verified_part(
    part: &Path,
    destination: &Path,
    expected: &ArtifactFingerprint,
) -> Result<()> {
    if part == destination {
        return verify_fingerprint(destination, expected).await;
    }
    if verify_fingerprint(destination, expected).await.is_ok() {
        let _ = tokio::fs::remove_file(part).await;
        return Ok(());
    }

    let quarantine = if destination.exists() {
        let quarantine = unique_sidecar_path(destination, "corrupt");
        match tokio::fs::rename(destination, &quarantine).await {
            Ok(()) => Some(quarantine),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                if verify_fingerprint(destination, expected).await.is_ok() {
                    let _ = tokio::fs::remove_file(part).await;
                    return Ok(());
                }
                return Err(error).with_context(|| {
                    format!(
                        "quarantine corrupt model artifact {}",
                        destination.display()
                    )
                });
            }
        }
    } else {
        None
    };

    match tokio::fs::rename(part, destination).await {
        Ok(()) => {
            verify_fingerprint(destination, expected).await?;
            sync_parent_directory(destination);
            if let Some(quarantine) = quarantine {
                let _ = tokio::fs::remove_file(quarantine).await;
            }
            Ok(())
        }
        Err(commit_error) => {
            if verify_fingerprint(destination, expected).await.is_ok() {
                let _ = tokio::fs::remove_file(part).await;
                if let Some(quarantine) = quarantine {
                    let _ = tokio::fs::remove_file(quarantine).await;
                }
                return Ok(());
            }
            if let Some(quarantine) = quarantine
                && !destination.exists()
            {
                let _ = tokio::fs::rename(&quarantine, destination).await;
            }
            Err(commit_error).with_context(|| {
                format!(
                    "atomically install model artifact {} -> {}",
                    part.display(),
                    destination.display()
                )
            })
        }
    }
}

async fn verify_fingerprint(path: &Path, expected: &ArtifactFingerprint) -> Result<()> {
    let actual = fingerprint_file(path).await?;
    if actual != *expected {
        bail!(
            "artifact fingerprint mismatch for {}: expected {:?}, got {:?}",
            path.display(),
            expected,
            actual
        );
    }
    Ok(())
}

async fn fingerprint_file(path: &Path) -> Result<ArtifactFingerprint> {
    let mut file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("open artifact for SHA-256 {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut len = 0_u64;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = file
            .read(&mut buffer)
            .await
            .with_context(|| format!("read artifact for SHA-256 {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        len = len
            .checked_add(read as u64)
            .context("model artifact length overflow")?;
    }
    Ok(ArtifactFingerprint {
        len,
        sha256: hex::encode(hasher.finalize()),
    })
}

fn fingerprint_file_sync(path: &Path) -> Result<ArtifactFingerprint> {
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("open artifact for SHA-256 {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut len = 0_u64;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("read artifact for SHA-256 {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        len = len
            .checked_add(read as u64)
            .context("model artifact length overflow")?;
    }
    Ok(ArtifactFingerprint {
        len,
        sha256: hex::encode(hasher.finalize()),
    })
}

fn unique_sidecar_path(destination: &Path, kind: &str) -> PathBuf {
    let sequence = SIDECAR_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut path = destination.as_os_str().to_os_string();
    path.push(format!(".{kind}.{}.{}", std::process::id(), sequence));
    PathBuf::from(path)
}

fn sibling_path(path: &Path, suffix: &str) -> PathBuf {
    let mut sibling = path.as_os_str().to_os_string();
    sibling.push(format!(".{suffix}"));
    PathBuf::from(sibling)
}

fn sync_parent_directory(path: &Path) {
    #[cfg(unix)]
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        && let Ok(directory) = std::fs::File::open(parent)
    {
        let _ = directory.sync_all();
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecordingAuditSink {
        events: std::sync::Mutex<Vec<(u8, serde_json::Value)>>,
        fail_next: std::sync::Mutex<Option<u8>>,
    }

    impl RecordingAuditSink {
        fn fail_once(event_type: u8) -> Self {
            Self {
                events: std::sync::Mutex::new(Vec::new()),
                fail_next: std::sync::Mutex::new(Some(event_type)),
            }
        }
    }

    #[async_trait::async_trait]
    impl ModelDownloadAuditSink for RecordingAuditSink {
        async fn append_model_download(&self, event_type: u8, payload: Vec<u8>) -> Result<()> {
            let mut fail_next = self.fail_next.lock().unwrap();
            if *fail_next == Some(event_type) {
                *fail_next = None;
                anyhow::bail!("injected audit failure");
            }
            drop(fail_next);
            self.events
                .lock()
                .unwrap()
                .push((event_type, serde_json::from_slice(&payload).unwrap()));
            Ok(())
        }
    }

    fn write_minimal_safetensors(path: &Path) {
        let header = br#"{"tensor":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}"#;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(header.len() as u64).to_le_bytes());
        bytes.extend_from_slice(header);
        bytes.extend_from_slice(&[0_u8; 4]);
        std::fs::write(path, bytes).unwrap();
    }

    #[test]
    fn cache_health_rejects_truncated_safetensors_and_bad_json() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.json"), b"{}").unwrap();
        write_minimal_safetensors(&dir.path().join("model.safetensors"));
        let required = [
            RequiredArtifact {
                filename: "config.json",
                kind: ArtifactKind::JsonObject,
                expected: None,
            },
            RequiredArtifact {
                filename: "model.safetensors",
                kind: ArtifactKind::Safetensors,
                expected: None,
            },
        ];
        assert_eq!(cache_health(dir.path(), &required), CacheHealth::Ready);

        let weights = dir.path().join("model.safetensors");
        let len = std::fs::metadata(&weights).unwrap().len();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&weights)
            .unwrap()
            .set_len(len - 1)
            .unwrap();
        assert!(matches!(
            cache_health(dir.path(), &required),
            CacheHealth::Corrupt { path, .. } if path == weights
        ));

        write_minimal_safetensors(&weights);
        std::fs::write(dir.path().join("config.json"), b"not-json").unwrap();
        assert!(matches!(
            cache_health(dir.path(), &required),
            CacheHealth::Corrupt { path, .. } if path.ends_with("config.json")
        ));
    }

    #[tokio::test]
    async fn part_is_verified_before_final_path_becomes_visible() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.bin");
        let destination = dir.path().join("runtime").join("model.bin");
        std::fs::write(&source, b"verified model bytes").unwrap();

        let (part, fingerprint) = copy_to_unique_part(&source, &destination).await.unwrap();
        assert!(part.is_file());
        assert!(!destination.exists());

        commit_verified_part(&part, &destination, &fingerprint)
            .await
            .unwrap();
        assert_eq!(std::fs::read(destination).unwrap(), b"verified model bytes");
    }

    #[tokio::test]
    async fn corrupt_destination_is_atomically_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.bin");
        let destination = dir.path().join("model.bin");
        std::fs::write(&source, b"complete source").unwrap();
        std::fs::write(&destination, b"truncated").unwrap();

        let expected = fingerprint_file(&source).await.unwrap();
        let fingerprint = install_from_hf_source(&source, &destination, &expected)
            .await
            .unwrap();
        assert_eq!(fingerprint.len, 15);
        assert_eq!(std::fs::read(destination).unwrap(), b"complete source");
    }

    #[tokio::test]
    async fn concurrent_installers_accept_the_same_verified_winner() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.bin");
        let destination = dir.path().join("model.bin");
        std::fs::write(&source, vec![0xA5; COPY_BUFFER_BYTES + 17]).unwrap();

        let expected = fingerprint_file(&source).await.unwrap();
        let (left, right) = tokio::join!(
            install_from_hf_source(&source, &destination, &expected),
            install_from_hf_source(&source, &destination, &expected)
        );
        assert_eq!(left.unwrap(), right.unwrap());
        assert_eq!(
            fingerprint_file(&destination).await.unwrap(),
            fingerprint_file(&source).await.unwrap()
        );
        let sidecars: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".part."))
            .collect();
        assert!(sidecars.is_empty(), "part files leaked: {sidecars:?}");
    }

    #[tokio::test]
    async fn d7_failure_never_authorizes_network_and_retry_reuses_attempt_id() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("model");
        let failing =
            RecordingAuditSink::fail_once(crate::wal::events::EVENT_TYPE_MODEL_DOWNLOAD_START);
        let mut attempt = ModelDownloadAttempt::acquire(&root, "repo/model", "implicit")
            .await
            .unwrap();
        assert!(attempt.ensure_started(&failing).await.is_err());
        let attempt_id = attempt.attempt_id().unwrap().to_string();
        assert!(!attempt.network_authorized(&root, "repo/model"));
        assert!(!root.join(INSTALLING_MARKER).exists());
        assert!(has_pending_download(&root).unwrap());
        drop(attempt);

        let sink = RecordingAuditSink::default();
        let mut retry = ModelDownloadAttempt::acquire(&root, "repo/model", "implicit")
            .await
            .unwrap();
        assert_eq!(retry.attempt_id(), Some(attempt_id.as_str()));
        retry.ensure_started(&sink).await.unwrap();
        assert!(retry.network_authorized(&root, "repo/model"));
        retry
            .finish_failed(&sink, "injected download error")
            .await
            .unwrap();
        assert!(!has_pending_download(&root).unwrap());
        assert!(!root.join(INSTALLING_MARKER).exists());
    }

    #[tokio::test]
    async fn network_permit_is_bound_to_attempt_model_root_and_persisted_hash() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("model");
        let sink = RecordingAuditSink::default();
        let mut attempt = ModelDownloadAttempt::acquire(&root, "repo/model", "implicit")
            .await
            .unwrap();
        let permit = attempt.authorize_network(&sink).await.unwrap();
        permit.require(&root, "repo/model").unwrap();
        assert!(permit.require(&root, "repo/other").is_err());
        assert!(
            permit
                .require(&dir.path().join("other"), "repo/model")
                .is_err()
        );

        let pending_file = pending_path(&root);
        drop(permit);
        drop(attempt);
        let mut pending: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&pending_file).unwrap()).unwrap();
        pending["attempt_sha256"] = serde_json::Value::String("00".repeat(32));
        std::fs::write(&pending_file, serde_json::to_vec(&pending).unwrap()).unwrap();
        assert!(
            ModelDownloadAttempt::acquire(&root, "repo/model", "implicit")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn failed_d8_keeps_pending_and_validated_cache_replays_without_download() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("model");
        let start_sink = RecordingAuditSink::default();
        let mut attempt = ModelDownloadAttempt::acquire(&root, "repo/model", "explicit")
            .await
            .unwrap();
        attempt.ensure_started(&start_sink).await.unwrap();
        let attempt_id = attempt.attempt_id().unwrap().to_string();

        let failing =
            RecordingAuditSink::fail_once(crate::wal::events::EVENT_TYPE_MODEL_DOWNLOAD_COMPLETE);
        assert!(attempt.finish_ready(&failing, &root).await.is_err());
        assert!(has_pending_download(&root).unwrap());
        assert!(root.join(INSTALLING_MARKER).exists());
        assert!(matches!(
            cache_health(&root, &[]),
            CacheHealth::Corrupt { .. }
        ));
        assert!(cache_health_during_install(&root, &[]).is_ready());
        drop(attempt);

        let replay_sink = RecordingAuditSink::default();
        let mut retry = ModelDownloadAttempt::acquire(&root, "repo/model", "explicit")
            .await
            .unwrap();
        assert_eq!(retry.attempt_id(), Some(attempt_id.as_str()));
        assert_eq!(
            retry.pending_outcome(),
            Some(PendingModelDownloadOutcome::Ready)
        );
        retry.replay_terminal(&replay_sink).await.unwrap();
        assert!(!has_pending_download(&root).unwrap());
        assert!(!root.join(INSTALLING_MARKER).exists());
        let events = replay_sink.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].1["attempt_id"], attempt_id);
        assert_eq!(events[0].1["status"], "ready");
    }

    #[tokio::test]
    async fn model_lock_serializes_provider_instances_for_the_same_cache() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("model");
        let first = ModelDownloadAttempt::acquire(&root, "repo/model", "implicit")
            .await
            .unwrap();
        let (acquired_tx, mut acquired_rx) = tokio::sync::oneshot::channel();
        let second_root = root.clone();
        let second = tokio::spawn(async move {
            let guard = ModelDownloadAttempt::acquire(&second_root, "repo/model", "implicit")
                .await
                .unwrap();
            let _ = acquired_tx.send(());
            guard
        });
        tokio::task::yield_now().await;
        assert!(acquired_rx.try_recv().is_err());
        drop(first);
        tokio::time::timeout(std::time::Duration::from_secs(1), &mut acquired_rx)
            .await
            .expect("second model instance never acquired shared lock")
            .unwrap();
        drop(second.await.unwrap());
    }
}
