//! On-disk model catalog at `~/.neoth/models_catalog.json`.
//!
//! The catalog is plain JSON (not a SQLite view) because:
//!   - It is small (low hundreds of KB at the absolute most)
//!   - It is human-readable, so operators can hand-inspect what NEOTH
//!     thinks is current without firing a SQL query
//!   - Provider refreshes merge through a locked read-modify-write transaction,
//!     so concurrent CLI/daemon writers cannot lose one another's updates
//!
//! Lifecycle:
//!   - **Load**: lazy on first read. Missing file → empty catalog
//!     (every provider reports `is_fresh() == false` so a refresh
//!     fires).
//!   - **Save**: private atomic replacement through the shared hardened writer.
//!   - **Freshness**: a per-provider `fetched_at_unix` + global TTL
//!     (default 24h). Stale slots are not deleted — the catalog
//!     keeps them around so `neoth models list --stale` can show the
//!     operator what's missing, and so a transient API outage
//!     doesn't wipe the operator's wizard select options.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Operator-defined short-form aliases for model ids.
///
/// Lives in `freedom.yaml` under `models.aliases: { "fast": "gpt-5.5", ... }`.
/// Aliases resolve BEFORE catalog validation so the alias itself never appears
/// in the catalog — only the real model id does. Aliases never shadow real model
/// ids: if an operator sets `alias = "gpt-5.5"` the alias is dead but harmless.
pub type ModelAliasMap = BTreeMap<String, String>;

/// Wire-format version. Bump when a non-backwards-compatible change
/// lands in the on-disk shape; older catalogs are then dropped on
/// load with a warn log.
pub const CATALOG_VERSION: u32 = 2;

/// Default freshness window — 24 hours. Operators with constrained
/// quota can dial this up via `freedom.yaml::models.ttl_secs`; the
/// catalog tolerates arbitrarily long TTLs.
pub const DEFAULT_TTL_SECS: u64 = 24 * 60 * 60;

/// Filename of the on-disk catalog inside `~/.neoth/`.
pub const CATALOG_FILE: &str = "models_catalog.json";

/// Sibling epoch rotated by [`ModelsCatalog::clear_at`]. In-flight refreshes
/// bind their CAS lease to this opaque value, so a completion from before a
/// clear can never publish into the post-clear generation.
const CLEAR_EPOCH_EXTENSION: &str = "clear_epoch";

/// Hard limits for the operator-readable cache. They apply both after parsing
/// untrusted disk state and immediately before atomic publication.
pub const MAX_CATALOG_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_CATALOG_PROVIDERS: usize = 16;
pub const MAX_MODELS_PER_PROVIDER: usize = 4096;
pub const MAX_PROVIDER_ID_CHARS: usize = 64;
pub const MAX_MODEL_ID_CHARS: usize = 512;
pub const MAX_MODEL_DISPLAY_CHARS: usize = 256;
pub const MAX_MODEL_SUMMARY_CHARS: usize = 200;
pub const MAX_CATALOG_ERROR_CHARS: usize = 512;

/// Same-process tier of the catalog read-modify-write lock. Always acquired
/// before the sibling OS lock so local writers park instead of spinning.
static CATALOG_UPDATE_LOCK: Mutex<()> = Mutex::new(());

const MIGRATABLE_CATALOG_VERSION: u32 = 1;

/// Where this provider catalog was sourced from. Surfaced in
/// `neoth models show` so operators know whether the entry came
/// from a live CLI exec (most authoritative) or a REST list-models
/// call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceOrigin {
    /// `claude --models` / `gemini --models` / similar CLI-pull. Most
    /// trusted: the OAuth CLI has its own auth + service-side
    /// resolution.
    Cli,
    /// Provider REST `/v1/models` (or equivalent) endpoint. Needs an
    /// API key in [`crate::config::credentials`] / `freedom.yaml`.
    Api,
    /// Fallback hand-curated baseline shipped with NEOTH so the
    /// wizard always has SOMETHING to render in air-gapped /
    /// no-network setups. Bumped manually when the operator-facing
    /// defaults rot too far ahead of a discovery run.
    #[default]
    Bundled,
}

/// One model entry inside a provider catalog. Minimal field set —
/// the wizard only needs name + id + a one-line operator-readable
/// description.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelEntry {
    /// API model identifier — exactly what NEOTH writes into
    /// `freedom.yaml::provider_model`. Example:
    /// `anthropic.claude-opus-4-7`, `gpt-5.5`,
    /// `gemini-3.1-pro-preview`.
    pub id: String,
    /// Operator-readable label. May coincide with `id` for providers
    /// that don't surface a separate display name.
    #[serde(default)]
    pub display_name: Option<String>,
    /// One-line description as returned by the provider (capability
    /// tier, special flags, etc.). Truncated to 200 chars on
    /// insertion so a verbose provider doesn't bloat the catalog.
    #[serde(default)]
    pub summary: Option<String>,
    /// Whether the provider flagged this model as deprecated /
    /// scheduled for sunset. NEOTH hides deprecated entries from
    /// the wizard's primary select but still surfaces them under
    /// `neoth models list --include-deprecated`.
    #[serde(default)]
    pub deprecated: bool,
}

impl ModelEntry {
    /// Convenience constructor used by [`sources`] implementations.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            display_name: None,
            summary: None,
            deprecated: false,
        }
    }

    pub fn with_display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = Some(name.into());
        self
    }

    pub fn with_summary(mut self, summary: impl Into<String>) -> Self {
        let raw = summary.into();
        // Clamp to 200 chars to keep the catalog small. UTF-8 safe via
        // char_indices.
        let clamped = if raw.chars().count() > MAX_MODEL_SUMMARY_CHARS {
            let cut = raw
                .char_indices()
                .nth(MAX_MODEL_SUMMARY_CHARS - 1)
                .map(|(i, _)| i)
                .unwrap_or(raw.len());
            format!("{}…", &raw[..cut])
        } else {
            raw
        };
        self.summary = Some(clamped);
        self
    }

    pub fn marked_deprecated(mut self) -> Self {
        self.deprecated = true;
        self
    }
}

/// All known models for one provider, plus the metadata needed to
/// decide whether a refresh fire.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderCatalog {
    /// Unix-seconds of the last successful fetch. `0` (the default)
    /// flags the entry as "never fetched"; `is_fresh()` always
    /// returns false in that state.
    #[serde(default)]
    pub fetched_at_unix: u64,
    /// Hash of the credential/endpoint/provider binding for which this entry
    /// was fetched. An entry without a binding hash is legacy/unbound and must
    /// not satisfy binding-aware freshness checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_hash: Option<String>,
    /// Where the entries came from — surfaced in
    /// `neoth models show <provider>`.
    #[serde(default = "default_source_origin")]
    pub source: SourceOrigin,
    /// Listed models, ordered by the provider's preference. The
    /// wizard renders the first non-deprecated entry as the
    /// default-selection.
    #[serde(default)]
    pub models: Vec<ModelEntry>,
    /// Error string from the most recent fetch attempt, or `None`
    /// when the last attempt succeeded. Surfaced by
    /// `neoth models show` so the operator sees WHY a provider is
    /// stale.
    #[serde(default)]
    pub last_error: Option<String>,
    /// Durable compare-and-swap lease for one in-flight network refresh.
    /// A later attempt replaces this token before it starts fetching, so an
    /// older slow response can never overwrite the newer provider state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_attempt: Option<CatalogRefreshAttempt>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogRefreshAttempt {
    pub token: String,
    pub binding_hash: String,
    /// `None` is accepted only for an in-flight v2 catalog written by an older
    /// NEOTH binary. New attempts always persist the current clear epoch and
    /// completion CAS requires an exact match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clear_epoch: Option<String>,
}

fn default_source_origin() -> SourceOrigin {
    SourceOrigin::Bundled
}

impl ProviderCatalog {
    /// True when the entry was fetched within `ttl_secs` of `now`.
    pub fn is_fresh(&self, now_unix: u64, ttl_secs: u64) -> bool {
        // A recent successful timestamp does not make a later failed refresh
        // fresh. `record_error` deliberately preserves prior models and their
        // timestamp for availability, so last_error is the authoritative
        // signal that stale-only discovery must retry.
        if self.fetched_at_unix == 0 || self.last_error.is_some() {
            return false;
        }
        now_unix.saturating_sub(self.fetched_at_unix) < ttl_secs
    }

    /// True only when the entry is fresh AND belongs to the exact current
    /// provider binding. Legacy entries without a binding hash are stale here.
    pub fn is_fresh_for_binding(&self, now_unix: u64, ttl_secs: u64, binding_hash: &str) -> bool {
        self.refresh_attempt.is_none()
            && self.binding_hash.as_deref() == Some(binding_hash)
            && self.is_fresh(now_unix, ttl_secs)
    }

    /// Pick the first non-deprecated model as the recommended
    /// default. Returns `None` when the catalog is empty or every
    /// entry is deprecated.
    pub fn recommended_default(&self) -> Option<&ModelEntry> {
        self.models.iter().find(|m| !m.deprecated)
    }
}

/// Top-level on-disk shape. Keyed by NEOTH's `ProviderKind` snake_case
/// string ("openai_api", "gemini_api", "aws_bedrock", "claude_cli",
/// etc.) so callers in `cli::init` / `cli::catalog` can index by the
/// same identifier the rest of the daemon already uses.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModelsCatalog {
    /// Schema-version pin. Future incompatible changes bump this and
    /// older catalogs get dropped on load.
    #[serde(default = "default_catalog_version")]
    pub version: u32,
    /// Monotone committed read-modify-write generation. Direct in-memory
    /// construction starts at zero; every successful [`Self::update_at`]
    /// transaction increments the previously persisted value exactly once.
    #[serde(default)]
    pub generation: u64,
    /// Operator override for the freshness window (seconds). `None`
    /// → use [`DEFAULT_TTL_SECS`].
    #[serde(default)]
    pub ttl_secs: Option<u64>,
    /// Per-provider catalogs. Keyed by provider name string.
    #[serde(default)]
    pub providers: BTreeMap<String, ProviderCatalog>,
    /// The local path the catalog was loaded from. Skipped from
    /// serde so the file itself never embeds its own location.
    #[serde(skip)]
    path: Option<PathBuf>,
}

/// Receipt for one durable catalog transaction. The hash is lowercase SHA-256
/// of the exact pretty-JSON bytes atomically published by that transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogCommit<T> {
    pub value: T,
    pub generation: u64,
    pub content_hash: String,
}

/// Result of a conditional catalog transaction. `changed=false` means the
/// mutation was deliberately discarded and no catalog bytes or generation
/// were changed. The optional snapshot identifies the exact current file; both
/// fields are `None` only when the catalog is intentionally absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CatalogConditionalCommit<T> {
    pub value: T,
    pub generation: Option<u64>,
    pub content_hash: Option<String>,
    pub changed: bool,
}

pub(crate) enum CatalogMutation<T> {
    Commit(T),
    Unchanged(T),
}

/// One strict catalog parsed from exactly one successful file read. The hash
/// covers those raw bytes, not a re-serialization which could hide formatting
/// changes or race a subsequent atomic replacement.
#[derive(Clone, Debug)]
pub struct CatalogSnapshot {
    pub catalog: ModelsCatalog,
    pub content_hash: String,
}

#[derive(Deserialize)]
struct CatalogHeader {
    version: u32,
}

fn default_catalog_version() -> u32 {
    CATALOG_VERSION
}

/// Manual Default so a fresh in-memory catalog stamps the current
/// schema version. Derived `Default` would emit `version: 0`, which
/// `load_from` would then reject as a schema mismatch on the next
/// round-trip.
impl Default for ModelsCatalog {
    fn default() -> Self {
        Self {
            version: CATALOG_VERSION,
            generation: 0,
            ttl_secs: None,
            providers: BTreeMap::new(),
            path: None,
        }
    }
}

impl ModelsCatalog {
    /// Construct an in-memory catalog with no on-disk backing —
    /// useful for unit tests that want full isolation.
    pub fn in_memory() -> Self {
        Self::default()
    }

    /// Resolve the default on-disk path below the NEOTH state directory.
    ///
    /// `neoth_home` is the same path returned by
    /// [`crate::config::FreedomConfig::default_neoth_home`] (normally
    /// `~/.neoth`). Keeping that contract explicit prevents callers from
    /// accidentally producing `~/.neoth/.neoth/models_catalog.json`.
    pub fn default_path(neoth_home: &Path) -> PathBuf {
        neoth_home.join(CATALOG_FILE)
    }

    /// Load from disk. Missing file → empty catalog (NOT an error).
    /// Malformed JSON → warn-log + empty catalog. Wrong schema
    /// version → warn-log + empty catalog. The operator's wizard
    /// path keeps running with bundled defaults until the next
    /// refresh restocks the catalog.
    pub fn load_from(path: &Path) -> Self {
        let mut catalog: Self = match std::fs::read(path) {
            Ok(bytes) if bytes.len() > MAX_CATALOG_BYTES => {
                tracing::warn!(
                    path = %path.display(),
                    bytes = bytes.len(),
                    "models_catalog.json exceeds size limit — starting empty"
                );
                Self::default()
            }
            Ok(bytes) => match serde_json::from_slice::<Self>(&bytes) {
                Ok(parsed) if parsed.version == CATALOG_VERSION => parsed,
                Ok(parsed) => {
                    tracing::warn!(
                        path = %path.display(),
                        loaded_version = parsed.version,
                        expected_version = CATALOG_VERSION,
                        "models_catalog.json schema mismatch — starting empty"
                    );
                    Self::default()
                }
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "models_catalog.json malformed — starting empty"
                    );
                    Self::default()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "models_catalog.json unreadable — starting empty"
                );
                Self::default()
            }
        };
        catalog.path = Some(path.to_path_buf());
        if catalog.version == 0 {
            catalog.version = CATALOG_VERSION;
        }
        if let Err(error) = catalog.validate_semantics() {
            tracing::warn!(
                path = %path.display(),
                error = %error,
                "models_catalog.json violates semantic contract — starting empty"
            );
            catalog = Self::default().with_path(path.to_path_buf());
        }
        catalog
    }

    /// Strictly load one on-disk catalog.
    ///
    /// `Ok(None)` means the file genuinely does not exist. Every other I/O
    /// error, malformed payload, missing/invalid version header, or unsupported
    /// schema version is an error. This distinction is required by locked
    /// read-modify-write callers: corrupt state must never be replaced as if it
    /// were a fresh install.
    pub fn load_snapshot_strict_from(path: &Path) -> Result<Option<CatalogSnapshot>> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| format!("read {}", path.display()));
            }
        };
        anyhow::ensure!(
            bytes.len() <= MAX_CATALOG_BYTES,
            "models catalog at {} exceeds {} bytes",
            path.display(),
            MAX_CATALOG_BYTES
        );

        let header: CatalogHeader = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse catalog header at {}", path.display()))?;
        if header.version != CATALOG_VERSION {
            anyhow::bail!(
                "unsupported models catalog version {} in {}; expected {}",
                header.version,
                path.display(),
                CATALOG_VERSION
            );
        }

        let mut catalog: Self = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse models catalog at {}", path.display()))?;
        catalog.path = Some(path.to_path_buf());
        catalog.validate_semantics()?;
        Ok(Some(CatalogSnapshot {
            catalog,
            content_hash: Self::hash_serialized(&bytes),
        }))
    }

    /// Compatibility projection for callers which do not need the raw-byte
    /// receipt. New readback/security-sensitive callers should use
    /// [`Self::load_snapshot_strict_from`].
    pub fn load_strict_from(path: &Path) -> Result<Option<Self>> {
        Ok(Self::load_snapshot_strict_from(path)?.map(|snapshot| snapshot.catalog))
    }

    /// Load the current generation for a locked update. A fully parseable v1
    /// cache is the sole migration exception: its provider/model data survives,
    /// while every binding is cleared so discovery must revalidate it. Missing
    /// state starts fresh; malformed, unreadable, and all other versions fail.
    fn load_for_update(path: &Path) -> Result<Self> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default().with_path(path.to_path_buf()));
            }
            Err(error) => {
                return Err(error).with_context(|| format!("read {}", path.display()));
            }
        };
        anyhow::ensure!(
            bytes.len() <= MAX_CATALOG_BYTES,
            "models catalog at {} exceeds {} bytes",
            path.display(),
            MAX_CATALOG_BYTES
        );
        let header: CatalogHeader = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse catalog header at {}", path.display()))?;
        if header.version != CATALOG_VERSION && header.version != MIGRATABLE_CATALOG_VERSION {
            anyhow::bail!(
                "unsupported models catalog version {} in {}; expected {} (or migratable v{})",
                header.version,
                path.display(),
                CATALOG_VERSION,
                MIGRATABLE_CATALOG_VERSION
            );
        }

        let mut catalog: Self = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse models catalog at {}", path.display()))?;
        if header.version == MIGRATABLE_CATALOG_VERSION {
            catalog.version = CATALOG_VERSION;
            catalog.generation = 0;
            for provider in catalog.providers.values_mut() {
                provider.binding_hash = None;
            }
        }
        catalog.path = Some(path.to_path_buf());
        catalog.validate_semantics()?;
        Ok(catalog)
    }

    /// Bind a path so a later [`Self::save`] knows where to write.
    /// Used by tests that want to round-trip through tempdirs.
    pub fn with_path(mut self, path: PathBuf) -> Self {
        self.path = Some(path);
        self
    }

    /// Persist one whole-catalog replacement through the same locked,
    /// generation-incrementing transaction as provider refreshes. No-op when
    /// the catalog has no path (in-memory mode). This is primarily useful for
    /// isolated construction/tests; production discovery should merge with
    /// [`Self::update_at`] instead of replacing unrelated providers.
    pub fn save(&self) -> Result<()> {
        let Some(path) = self.path.as_ref() else {
            return Ok(());
        };
        let replacement = self.clone();
        Self::update_at(path, move |catalog| {
            *catalog = replacement;
            Ok(())
        })?;
        Ok(())
    }

    fn serialized_body(&self) -> Result<Vec<u8>> {
        serde_json::to_vec_pretty(self).context("serialize models_catalog.json")
    }

    fn write_serialized(path: &Path, body: &[u8]) -> Result<()> {
        crate::util::atomic_write::atomic_write_private(path, body)
            .with_context(|| format!("atomically write models catalog at {}", path.display()))
    }

    fn hash_serialized(body: &[u8]) -> String {
        hex::encode(Sha256::digest(body))
    }

    /// SHA-256 of the exact JSON representation used by [`Self::save`] and
    /// [`Self::update_at`]. This avoids a second file read when callers already
    /// hold a strict catalog snapshot.
    pub(crate) fn content_hash(&self) -> Result<String> {
        Ok(Self::hash_serialized(&self.serialized_body()?))
    }

    /// Validate the complete semantic cache contract. This is deliberately in
    /// the storage core so every strict reader and every publisher gets the
    /// same bounds instead of relying on CLI-only validation.
    pub fn validate_semantics(&self) -> Result<()> {
        anyhow::ensure!(
            self.version == CATALOG_VERSION,
            "models catalog schema version is not {}",
            CATALOG_VERSION
        );
        anyhow::ensure!(
            self.providers.len() <= MAX_CATALOG_PROVIDERS,
            "models catalog contains too many providers"
        );
        for (provider, entry) in &self.providers {
            validate_identifier(provider, MAX_PROVIDER_ID_CHARS, "provider id")?;
            anyhow::ensure!(
                provider
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'),
                "models catalog provider id contains unsupported characters"
            );
            anyhow::ensure!(
                entry.models.len() <= MAX_MODELS_PER_PROVIDER,
                "models catalog provider `{provider}` contains too many models"
            );
            if !entry.models.is_empty() {
                anyhow::ensure!(
                    entry.fetched_at_unix > 0,
                    "models catalog provider `{provider}` has models without a fetch timestamp"
                );
            }
            if let Some(binding_hash) = entry.binding_hash.as_deref() {
                validate_sha256(binding_hash, "provider binding hash")?;
            }
            if let Some(attempt) = entry.refresh_attempt.as_ref() {
                validate_sha256(&attempt.token, "provider refresh token")?;
                validate_sha256(&attempt.binding_hash, "provider refresh binding hash")?;
                if let Some(clear_epoch) = attempt.clear_epoch.as_deref() {
                    validate_sha256(clear_epoch, "provider refresh clear epoch")?;
                }
            }
            if let Some(error) = entry.last_error.as_deref() {
                validate_identifier(error, MAX_CATALOG_ERROR_CHARS, "provider error")?;
            }
            let mut model_ids = std::collections::HashSet::with_capacity(entry.models.len());
            for model in &entry.models {
                validate_identifier(&model.id, MAX_MODEL_ID_CHARS, "model id")?;
                anyhow::ensure!(
                    model_ids.insert(model.id.as_str()),
                    "models catalog provider `{provider}` repeats model id `{}`",
                    model.id
                );
                if let Some(display_name) = model.display_name.as_deref() {
                    validate_identifier(
                        display_name,
                        MAX_MODEL_DISPLAY_CHARS,
                        "model display name",
                    )?;
                }
                if let Some(summary) = model.summary.as_deref() {
                    validate_identifier(summary, MAX_MODEL_SUMMARY_CHARS, "model summary")?;
                }
            }
        }
        Ok(())
    }

    /// Cross-process-safe read-modify-write for one catalog file.
    ///
    /// The process mutex is acquired first, followed by a stable sibling file
    /// lock. The newest catalog is then loaded fail-closed while both locks are
    /// held; the only compatibility path is the explicit v1-to-v2 cache
    /// migration described by [`Self::load_for_update`]. Callers must perform
    /// network discovery before entering this transaction and use `mutation`
    /// only to merge already-fetched results. Missing state starts from
    /// generation zero; invalid existing state fails without invoking
    /// `mutation` or replacing any bytes.
    pub fn update_at<T>(
        path: &Path,
        mutation: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<CatalogCommit<T>> {
        Self::update_at_with_clear_epoch(path, |catalog, _clear_epoch| mutation(catalog))
    }

    /// Always-committing catalog transaction which also exposes the current
    /// clear epoch while the process + OS catalog locks are held. Refresh
    /// reservations use this boundary so the lease and epoch are one atomic
    /// generation.
    pub(crate) fn update_at_with_clear_epoch<T>(
        path: &Path,
        mutation: impl FnOnce(&mut Self, &str) -> Result<T>,
    ) -> Result<CatalogCommit<T>> {
        let result = Self::update_at_inner(path, |catalog, clear_epoch| {
            mutation(catalog, clear_epoch).map(CatalogMutation::Commit)
        })?;
        let (Some(generation), Some(content_hash)) = (result.generation, result.content_hash)
        else {
            unreachable!("an always-committing catalog transaction returned no snapshot")
        };
        debug_assert!(result.changed);
        Ok(CatalogCommit {
            value: result.value,
            generation,
            content_hash,
        })
    }

    /// Conditional catalog transaction for CAS completion. Returning
    /// [`CatalogMutation::Unchanged`] preserves the exact current bytes and
    /// generation (or deliberate absence) while still returning the mutation's
    /// typed outcome.
    pub(crate) fn update_at_if_changed_with_clear_epoch<T>(
        path: &Path,
        mutation: impl FnOnce(&mut Self, &str) -> Result<CatalogMutation<T>>,
    ) -> Result<CatalogConditionalCommit<T>> {
        Self::update_at_inner(path, mutation)
    }

    fn update_at_inner<T>(
        path: &Path,
        mutation: impl FnOnce(&mut Self, &str) -> Result<CatalogMutation<T>>,
    ) -> Result<CatalogConditionalCommit<T>> {
        let _process_guard = CATALOG_UPDATE_LOCK
            .lock()
            .map_err(|_| anyhow::anyhow!("models catalog process lock was poisoned"))?;
        let lock_path = path.with_extension("lock");
        let _file_guard =
            crate::util::locked_file::lock_file_blocking(&lock_path, "models catalog")?;

        let clear_epoch = Self::load_or_init_clear_epoch_locked(path)?;
        let mut catalog = Self::load_for_update(path)?;
        // Preserve the generation of the locked on-disk value. A mutation may
        // replace the whole catalog, but it must not be able to reset or skip
        // the publication sequence by supplying its own generation.
        let current_generation = catalog.generation;
        let mutation = mutation(&mut catalog, &clear_epoch)?;
        let result = match mutation {
            CatalogMutation::Commit(result) => result,
            CatalogMutation::Unchanged(result) => {
                let snapshot = Self::load_snapshot_strict_from(path)?;
                return Ok(CatalogConditionalCommit {
                    value: result,
                    generation: snapshot
                        .as_ref()
                        .map(|snapshot| snapshot.catalog.generation),
                    content_hash: snapshot.map(|snapshot| snapshot.content_hash),
                    changed: false,
                });
            }
        };
        let next_generation = current_generation
            .checked_add(1)
            .context("models catalog generation overflow")?;
        // A public mutation can replace the whole value through `*catalog = …`.
        // Rebind storage invariants after it returns so the commit cannot turn
        // into an accidental in-memory no-op or redirect itself elsewhere.
        catalog.path = Some(path.to_path_buf());
        catalog.version = CATALOG_VERSION;
        catalog.generation = next_generation;
        catalog.validate_semantics()?;
        let body = catalog.serialized_body()?;
        anyhow::ensure!(
            body.len() <= MAX_CATALOG_BYTES,
            "models catalog publication exceeds {} bytes",
            MAX_CATALOG_BYTES
        );
        let content_hash = Self::hash_serialized(&body);
        Self::write_serialized(path, &body)?;
        Ok(CatalogConditionalCommit {
            value: result,
            generation: Some(catalog.generation),
            content_hash: Some(content_hash),
            changed: true,
        })
    }

    /// Read-only access to one provider's catalog.
    pub fn provider(&self, name: &str) -> Option<&ProviderCatalog> {
        self.providers.get(name)
    }

    /// Remove the catalog while holding the exact same process/file lock pair
    /// as writers. A concurrent refresh therefore publishes wholly before or
    /// wholly after the clear, never into an uncoordinated deletion race.
    pub fn clear_at(path: &Path) -> Result<bool> {
        let _process_guard = CATALOG_UPDATE_LOCK
            .lock()
            .map_err(|_| anyhow::anyhow!("models catalog process lock was poisoned"))?;
        let lock_path = path.with_extension("lock");
        let _file_guard =
            crate::util::locked_file::lock_file_blocking(&lock_path, "models catalog")?;
        let existed = path
            .try_exists()
            .with_context(|| format!("check catalog before clear at {}", path.display()))?;
        // Commit the epoch before deletion. A crash between the two operations
        // may leave the old catalog visible, but it cannot let a pre-clear
        // network completion publish; the next clear remains idempotent.
        Self::rotate_clear_epoch_locked(path)?;
        crate::util::atomic_write::durable_remove_file(path)
            .with_context(|| format!("clear {}", path.display()))?;
        Ok(existed)
    }

    fn clear_epoch_path(path: &Path) -> PathBuf {
        path.with_extension(CLEAR_EPOCH_EXTENSION)
    }

    fn load_or_init_clear_epoch_locked(path: &Path) -> Result<String> {
        let epoch_path = Self::clear_epoch_path(path);
        match std::fs::read_to_string(&epoch_path) {
            Ok(epoch) => {
                let epoch = epoch.trim();
                validate_sha256(epoch, "clear epoch")?;
                Ok(epoch.to_string())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let epoch = mint_clear_epoch()?;
                crate::util::atomic_write::atomic_write_private(&epoch_path, epoch.as_bytes())
                    .with_context(|| {
                        format!(
                            "initialize models catalog clear epoch at {}",
                            epoch_path.display()
                        )
                    })?;
                Ok(epoch)
            }
            Err(error) => Err(error).with_context(|| {
                format!(
                    "read models catalog clear epoch at {}",
                    epoch_path.display()
                )
            }),
        }
    }

    fn rotate_clear_epoch_locked(path: &Path) -> Result<String> {
        let epoch_path = Self::clear_epoch_path(path);
        let epoch = mint_clear_epoch()?;
        crate::util::atomic_write::atomic_write_private(&epoch_path, epoch.as_bytes())
            .with_context(|| {
                format!(
                    "rotate models catalog clear epoch at {}",
                    epoch_path.display()
                )
            })?;
        Ok(epoch)
    }

    /// Insert or replace one provider's catalog. Stamps `fetched_at_unix`
    /// with `now` and clears any prior `last_error`. Callers that want
    /// to record a fetch FAILURE should use [`Self::record_error`]
    /// instead.
    pub fn upsert(
        &mut self,
        name: impl Into<String>,
        source: SourceOrigin,
        models: Vec<ModelEntry>,
    ) {
        let name = name.into();
        self.providers.insert(
            name,
            ProviderCatalog {
                fetched_at_unix: now_unix(),
                binding_hash: None,
                source,
                models,
                last_error: None,
                refresh_attempt: None,
            },
        );
    }

    /// Insert or replace one provider's catalog and bind the successful fetch
    /// to the exact credential/endpoint/provider configuration that produced
    /// it. Binding-aware discovery must use this instead of [`Self::upsert`].
    pub fn upsert_bound(
        &mut self,
        name: impl Into<String>,
        source: SourceOrigin,
        models: Vec<ModelEntry>,
        binding_hash: impl Into<String>,
    ) {
        let name = name.into();
        self.providers.insert(
            name,
            ProviderCatalog {
                fetched_at_unix: now_unix(),
                binding_hash: Some(binding_hash.into()),
                source,
                models,
                last_error: None,
                refresh_attempt: None,
            },
        );
    }

    /// Record a failed fetch — leaves prior models intact (so the
    /// operator's wizard select still has options) but stamps the
    /// `last_error` field for telemetry.
    pub fn record_error(&mut self, name: impl Into<String>, error: impl Into<String>) {
        let name = name.into();
        let entry = self.providers.entry(name).or_default();
        entry.last_error = Some(error.into());
        entry.refresh_attempt = None;
    }

    /// Effective TTL: operator override OR [`DEFAULT_TTL_SECS`].
    pub fn effective_ttl_secs(&self) -> u64 {
        self.ttl_secs.unwrap_or(DEFAULT_TTL_SECS)
    }

    /// Enumerate provider names that have NOT been refreshed within
    /// the TTL window. Used by the cron task + `neoth models refresh
    /// --stale-only`.
    pub fn stale_providers(&self, now_unix: u64) -> Vec<String> {
        let ttl = self.effective_ttl_secs();
        let mut stale: Vec<String> = self
            .providers
            .iter()
            .filter(|(_, pc)| !pc.is_fresh(now_unix, ttl))
            .map(|(name, _)| name.clone())
            .collect();
        stale.sort();
        stale
    }
}

fn validate_sha256(value: &str, field: &str) -> Result<()> {
    anyhow::ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "models catalog {field} is not lowercase SHA-256"
    );
    Ok(())
}

fn mint_clear_epoch() -> Result<String> {
    let mut epoch = [0u8; 32];
    getrandom::getrandom(&mut epoch).context("mint models catalog clear epoch")?;
    Ok(hex::encode(epoch))
}

fn validate_identifier(value: &str, max_chars: usize, field: &str) -> Result<()> {
    validate_text(value, max_chars, field)?;
    anyhow::ensure!(
        value.trim() == value,
        "models catalog {field} is not trimmed"
    );
    Ok(())
}

fn validate_text(value: &str, max_chars: usize, field: &str) -> Result<()> {
    anyhow::ensure!(!value.is_empty(), "models catalog {field} is empty");
    anyhow::ensure!(
        value.chars().count() <= max_chars,
        "models catalog {field} exceeds {max_chars} characters"
    );
    anyhow::ensure!(
        !value.chars().any(char::is_control),
        "models catalog {field} contains control characters"
    );
    Ok(())
}

/// Wall-clock unix seconds. Wraps `SystemTime` for ergonomics + test
/// stubbing. Aligned with `crate::providers::quota::now_unix`.
pub fn now_unix() -> u64 {
    crate::time::now_unix_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest as _;
    use tempfile::tempdir;

    fn entry(id: &str) -> ModelEntry {
        ModelEntry::new(id)
    }

    fn binding(seed: &str) -> String {
        hex::encode(sha2::Sha256::digest(seed.as_bytes()))
    }

    #[test]
    fn empty_catalog_round_trips_to_disk() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        let cat = ModelsCatalog::default().with_path(path.clone());
        cat.save().unwrap();

        let reloaded = ModelsCatalog::load_from(&path);
        assert_eq!(reloaded.version, CATALOG_VERSION);
        assert!(reloaded.providers.is_empty());
    }

    #[test]
    fn upsert_then_load_returns_same_provider_entries() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        let mut cat = ModelsCatalog::load_from(&path);
        cat.upsert(
            "anthropic_api",
            SourceOrigin::Api,
            vec![
                entry("claude-opus-4-7"),
                entry("claude-sonnet-4-6"),
                entry("claude-haiku-4-5-20251001"),
            ],
        );
        cat.save().unwrap();

        let reloaded = ModelsCatalog::load_from(&path);
        let provider = reloaded.provider("anthropic_api").unwrap();
        assert_eq!(provider.models.len(), 3);
        assert_eq!(provider.source, SourceOrigin::Api);
        assert_eq!(provider.models[0].id, "claude-opus-4-7");
    }

    #[test]
    fn missing_file_loads_empty_not_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("does_not_exist.json");
        let cat = ModelsCatalog::load_from(&path);
        assert!(cat.providers.is_empty());
        assert_eq!(cat.version, CATALOG_VERSION);
    }

    #[test]
    fn strict_loader_distinguishes_missing_from_invalid_state() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        assert!(ModelsCatalog::load_strict_from(&path).unwrap().is_none());

        std::fs::write(&path, b"{ not valid json").unwrap();
        assert!(
            ModelsCatalog::load_strict_from(&path).is_err(),
            "malformed state must fail instead of looking missing"
        );
    }

    #[test]
    fn strict_snapshot_hashes_the_exact_bytes_read() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        let raw = b"{\"version\":2,\"generation\":7,\"ttl_secs\":null,\"providers\":{}}\n";
        std::fs::write(&path, raw).unwrap();

        let snapshot = ModelsCatalog::load_snapshot_strict_from(&path)
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.catalog.generation, 7);
        assert_eq!(
            snapshot.content_hash,
            hex::encode(sha2::Sha256::digest(raw))
        );
        assert_ne!(
            snapshot.content_hash,
            snapshot.catalog.content_hash().unwrap(),
            "raw-byte receipt must not silently canonicalize formatting"
        );
    }

    #[test]
    fn semantic_validation_rejects_unbounded_and_control_text_before_publish() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        let error = ModelsCatalog::update_at(&path, |catalog| {
            let mut model = ModelEntry::new("model\ncontrol");
            model.display_name = Some("display".repeat(MAX_MODEL_DISPLAY_CHARS + 1));
            catalog.upsert_bound(
                "openai_api",
                SourceOrigin::Api,
                vec![model],
                binding("openai"),
            );
            Ok(())
        })
        .unwrap_err();
        assert!(
            error.to_string().contains("model id contains control")
                || error.to_string().contains("display name exceeds")
        );
        assert!(!path.exists(), "invalid state must never be published");

        let mut catalog = ModelsCatalog::default();
        catalog.providers.insert(
            "openai_api".into(),
            ProviderCatalog {
                last_error: Some("error\rcontrol".into()),
                ..Default::default()
            },
        );
        assert!(catalog.validate_semantics().is_err());

        let mut too_many_models = ModelsCatalog::default();
        too_many_models.providers.insert(
            "openai_api".into(),
            ProviderCatalog {
                fetched_at_unix: 1,
                models: (0..=MAX_MODELS_PER_PROVIDER)
                    .map(|index| ModelEntry::new(format!("model-{index}")))
                    .collect(),
                ..Default::default()
            },
        );
        assert!(too_many_models.validate_semantics().is_err());
    }

    #[test]
    fn malformed_json_loads_empty_not_panic() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        std::fs::write(&path, b"{ not valid json").unwrap();
        let cat = ModelsCatalog::load_from(&path);
        assert!(cat.providers.is_empty());
    }

    #[test]
    fn wrong_schema_version_loads_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        // Schema version 999 — far in the future.
        std::fs::write(&path, br#"{"version":999,"ttl_secs":null,"providers":{}}"#).unwrap();
        let cat = ModelsCatalog::load_from(&path);
        // Loaded as empty so the operator's wizard still works with bundled defaults.
        assert!(cat.providers.is_empty());
    }

    #[test]
    fn strict_loader_rejects_v1_catalog() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        std::fs::write(&path, br#"{"version":1,"ttl_secs":null,"providers":{}}"#).unwrap();

        let error = ModelsCatalog::load_strict_from(&path).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsupported models catalog version 1"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn update_migrates_complete_v1_and_hashes_exact_committed_bytes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        std::fs::write(
            &path,
            br#"{
                "version": 1,
                "ttl_secs": 3600,
                "providers": {
                    "anthropic_api": {
                        "fetched_at_unix": 1000000,
                        "source": "api",
                        "models": [{"id": "claude-opus-4-7"}],
                        "last_error": null
                    }
                }
            }"#,
        )
        .unwrap();

        let commit = ModelsCatalog::update_at(&path, |catalog| {
            let migrated = catalog.provider("anthropic_api").unwrap();
            assert_eq!(migrated.models[0].id, "claude-opus-4-7");
            assert!(migrated.binding_hash.is_none());
            catalog.upsert_bound(
                "openai_api",
                SourceOrigin::Api,
                vec![entry("gpt-5.5")],
                binding("openai"),
            );
            Ok("merged")
        })
        .unwrap();

        let actual = std::fs::read(&path).unwrap();
        let actual_hash = hex::encode(sha2::Sha256::digest(&actual));
        assert_eq!(commit.value, "merged");
        assert_eq!(commit.generation, 1);
        assert_eq!(commit.content_hash, actual_hash);

        let catalog = ModelsCatalog::load_strict_from(&path).unwrap().unwrap();
        assert_eq!(catalog.version, CATALOG_VERSION);
        assert_eq!(catalog.generation, 1);
        assert_eq!(catalog.ttl_secs, Some(3600));
        assert_eq!(catalog.content_hash().unwrap(), actual_hash);
        assert!(catalog.providers.contains_key("anthropic_api"));
        assert!(catalog.providers.contains_key("openai_api"));
        assert!(
            catalog
                .provider("anthropic_api")
                .unwrap()
                .binding_hash
                .is_none()
        );
    }

    #[test]
    fn is_fresh_uses_ttl_window() {
        let mut pc = ProviderCatalog::default();
        pc.fetched_at_unix = 1_000_000;
        assert!(pc.is_fresh(1_000_500, 1000), "within window");
        assert!(!pc.is_fresh(1_001_001, 1000), "just past window");
        assert!(!pc.is_fresh(2_000_000, 1000), "far past window");
    }

    #[test]
    fn binding_mismatch_is_stale_even_inside_ttl() {
        let pc = ProviderCatalog {
            fetched_at_unix: 1_000_000,
            binding_hash: Some("binding-a".into()),
            ..Default::default()
        };

        assert!(pc.is_fresh_for_binding(1_000_001, 1_000, "binding-a"));
        assert!(!pc.is_fresh_for_binding(1_000_001, 1_000, "binding-b"));

        let unbound = ProviderCatalog {
            fetched_at_unix: 1_000_000,
            ..Default::default()
        };
        assert!(!unbound.is_fresh_for_binding(1_000_001, 1_000, "binding-a"));
    }

    #[test]
    fn never_fetched_is_never_fresh() {
        let pc = ProviderCatalog::default();
        // fetched_at_unix == 0; even with a generous TTL must return false.
        assert!(!pc.is_fresh(u64::MAX, u64::MAX));
    }

    #[test]
    fn cached_error_is_never_fresh_even_with_recent_success_timestamp() {
        let pc = ProviderCatalog {
            fetched_at_unix: 1_000_000,
            last_error: Some("last refresh failed".into()),
            ..Default::default()
        };
        assert!(!pc.is_fresh(1_000_001, 1_000));
    }

    #[test]
    fn recommended_default_skips_deprecated_entries() {
        let mut pc = ProviderCatalog::default();
        pc.models = vec![
            entry("gpt-5.1").marked_deprecated(),
            entry("gpt-5.4"),
            entry("gpt-5.5"),
        ];
        let recommended = pc.recommended_default().unwrap();
        assert_eq!(recommended.id, "gpt-5.4");
    }

    #[test]
    fn recommended_default_none_when_all_deprecated() {
        let mut pc = ProviderCatalog::default();
        pc.models = vec![
            entry("gpt-4o").marked_deprecated(),
            entry("gpt-4-turbo").marked_deprecated(),
        ];
        assert!(pc.recommended_default().is_none());
    }

    #[test]
    fn upsert_stamps_fetched_at_unix() {
        let mut cat = ModelsCatalog::default();
        cat.upsert("openai_api", SourceOrigin::Api, vec![entry("gpt-5.5")]);
        let p = cat.provider("openai_api").unwrap();
        assert!(p.fetched_at_unix > 0, "must stamp fetch time");
        assert!(p.last_error.is_none(), "happy path clears prior error");
    }

    #[test]
    fn bound_upsert_records_binding_hash() {
        let mut cat = ModelsCatalog::default();
        cat.upsert_bound(
            "openai_api",
            SourceOrigin::Api,
            vec![entry("gpt-5.5")],
            "binding-a",
        );
        let provider = cat.provider("openai_api").unwrap();
        assert_eq!(provider.binding_hash.as_deref(), Some("binding-a"));
    }

    #[test]
    fn serialized_disjoint_updates_preserve_both_and_advance_generation() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));

        let mut workers = Vec::new();
        for (provider, model, binding) in [
            ("anthropic_api", "claude-opus-4-7", binding("anthropic")),
            ("openai_api", "gpt-5.5", binding("openai")),
        ] {
            let path = path.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                ModelsCatalog::update_at(&path, |catalog| {
                    catalog.upsert_bound(provider, SourceOrigin::Api, vec![entry(model)], binding);
                    Ok(())
                })
            }));
        }

        barrier.wait();
        for worker in workers {
            worker.join().unwrap().unwrap();
        }

        let catalog = ModelsCatalog::load_strict_from(&path).unwrap().unwrap();
        assert_eq!(catalog.generation, 2);
        assert!(catalog.providers.contains_key("anthropic_api"));
        assert!(catalog.providers.contains_key("openai_api"));
    }

    #[test]
    fn transaction_rebinds_storage_after_whole_catalog_replacement() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");

        ModelsCatalog::update_at(&path, |catalog| {
            *catalog = ModelsCatalog::default();
            catalog.upsert("openai_api", SourceOrigin::Api, vec![entry("gpt-5.5")]);
            Ok(())
        })
        .unwrap();

        let catalog = ModelsCatalog::load_strict_from(&path).unwrap().unwrap();
        assert_eq!(catalog.generation, 1);
        assert!(catalog.providers.contains_key("openai_api"));
    }

    #[test]
    fn save_atomically_overwrites_existing_catalog() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("models_catalog.json");

        let mut first = ModelsCatalog::default().with_path(path.clone());
        first.upsert(
            "anthropic_api",
            SourceOrigin::Api,
            vec![entry("claude-opus-4-7")],
        );
        first.save().unwrap();

        let mut second = ModelsCatalog::default().with_path(path.clone());
        second.upsert("openai_api", SourceOrigin::Api, vec![entry("gpt-5.5")]);
        second.save().unwrap();

        let reloaded = ModelsCatalog::load_strict_from(&path).unwrap().unwrap();
        assert!(!reloaded.providers.contains_key("anthropic_api"));
        assert!(reloaded.providers.contains_key("openai_api"));
    }

    #[test]
    fn record_error_preserves_existing_models() {
        let mut cat = ModelsCatalog::default();
        cat.upsert("openai_api", SourceOrigin::Api, vec![entry("gpt-5.5")]);
        cat.record_error("openai_api", "rate limited");
        let p = cat.provider("openai_api").unwrap();
        assert_eq!(p.models.len(), 1, "models from prior success preserved");
        assert_eq!(p.last_error.as_deref(), Some("rate limited"));
    }

    #[test]
    fn record_error_on_unknown_provider_creates_empty_entry() {
        let mut cat = ModelsCatalog::default();
        cat.record_error("never_seen", "401 unauthorized");
        let p = cat.provider("never_seen").unwrap();
        assert!(p.models.is_empty());
        assert_eq!(p.last_error.as_deref(), Some("401 unauthorized"));
    }

    #[test]
    fn stale_providers_lists_only_unfresh() {
        let mut cat = ModelsCatalog::default();
        cat.ttl_secs = Some(1000);

        let mut fresh = ProviderCatalog::default();
        fresh.fetched_at_unix = 1_000_000;
        let mut stale = ProviderCatalog::default();
        stale.fetched_at_unix = 1; // ancient
        let never = ProviderCatalog::default(); // fetched_at_unix == 0

        cat.providers.insert("fresh_p".into(), fresh);
        cat.providers.insert("stale_p".into(), stale);
        cat.providers.insert("never_p".into(), never);

        let list = cat.stale_providers(1_000_500);
        assert_eq!(list, vec!["never_p".to_string(), "stale_p".to_string()]);
    }

    #[test]
    fn effective_ttl_falls_back_to_default_when_unset() {
        let cat = ModelsCatalog::default();
        assert_eq!(cat.effective_ttl_secs(), DEFAULT_TTL_SECS);
    }

    #[test]
    fn effective_ttl_honours_operator_override() {
        let mut cat = ModelsCatalog::default();
        cat.ttl_secs = Some(3600);
        assert_eq!(cat.effective_ttl_secs(), 3600);
    }

    #[test]
    fn with_summary_clamps_long_strings() {
        let long = "x".repeat(500);
        let entry = ModelEntry::new("test-id").with_summary(&long);
        let summary = entry.summary.unwrap();
        // The truncation marker is included in the 200-character cap.
        assert!(summary.chars().count() <= MAX_MODEL_SUMMARY_CHARS);
        assert!(summary.ends_with('…'));
    }

    #[test]
    fn with_summary_passes_through_short_strings() {
        let entry = ModelEntry::new("id").with_summary("short");
        assert_eq!(entry.summary.as_deref(), Some("short"));
    }

    #[test]
    fn default_path_uses_the_supplied_neoth_home_exactly_once() {
        let neoth_home = Path::new("/tmp/fake_home/.neoth");
        let path = ModelsCatalog::default_path(neoth_home);
        assert_eq!(path, neoth_home.join("models_catalog.json"));
        assert!(!path.ends_with(".neoth/.neoth/models_catalog.json"));
    }
}
// NOTE: with_aliases / resolve_alias / aliases field were removed (FIX-4b).
// Alias resolution lives solely in config::FreedomConfig::resolve_model_alias
// (plain first-match HashMap lookup). Tests for that contract live in
// config/inline_tests.rs.
